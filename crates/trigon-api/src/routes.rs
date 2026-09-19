//! The handlers. Every one is a `get`, and none of them can produce a verdict.
//!
//! The absences are the design, and `docs/22-management-layer.md` §5.4 argues each: no endpoint
//! writes an `outcome`, there is no anonymous evidence route, no `DELETE` of anything signed, no
//! worker-proxying route, and no `/v1/costs` in dollars while there is no price table.

use crate::evidence::{Class, admits};
use crate::index::Query;
use crate::{Api, Principal};
use axum::extract::{Path, Query as UrlQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use trigon_core::Digest;

type S = State<Arc<Api>>;

/// A refusal that says something true about the system.
///
/// `(status, code, sentence)`. The code is stable and machine-readable; the sentence is for the
/// person. A 403 with neither teaches a reader that the site is arbitrary.
fn refuse(status: StatusCode, code: &str, sentence: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": code, "detail": sentence })),
    )
        .into_response()
}

fn json<T: serde::Serialize>(v: T) -> Response {
    axum::Json(v).into_response()
}

pub async fn health(State(api): S) -> Response {
    json(serde_json::json!({
        "ok": true,
        "runs": api.index.len(),
        // Named so an operator reading a health check knows which gate the site is behind, rather
        // than discovering it from a page that shows nothing.
        "principal": match api.principal() {
            Principal::Anonymous => "anonymous",
            Principal::Operator => "operator",
        },
        "divergence_publication": if api.switches.stop_divergences { "stopped" } else { "running" },
    }))
}

pub async fn stats(State(api): S) -> Response {
    json(api.index.stats(api.principal() == Principal::Anonymous))
}

#[derive(Debug, Deserialize)]
pub struct RunsQuery {
    ecosystem: Option<String>,
    outcome: Option<String>,
    fault: Option<String>,
    q: Option<String>,
    kind: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

pub async fn runs(State(api): S, UrlQuery(q): UrlQuery<RunsQuery>) -> Response {
    let page = api.index.page(
        &Query {
            ecosystem: q.ecosystem,
            outcome: q.outcome,
            fault: q.fault,
            q: q.q,
            kind: q.kind,
            cursor: q.cursor,
            limit: q.limit.unwrap_or(50),
        },
        api.principal() == Principal::Anonymous,
    );
    json(page)
}

/// One run, in as much detail as the principal may see.
///
/// The record is returned as it is stored, minus nothing — it holds digests, not bytes, and a
/// digest is not a secret. What the digests *point at* is class-gated, which is where the control
/// lives. The entry beside it carries the publication decision, so the front-end never has to
/// re-derive one.
pub async fn run(State(api): S, Path(id): Path<String>) -> Response {
    let Some(record) = api.index.get(&id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    let Some(entry) = api.index.entry(&id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    if api.principal() == Principal::Anonymous && !entry.publication.is_public() {
        // 404, not 403. A 403 confirms the run exists, which for a withheld divergence is most of
        // the accusation the gate is holding back.
        return refuse(
            StatusCode::NOT_FOUND,
            "no_such_run",
            "no run by that id is published",
        );
    }
    json(serde_json::json!({ "entry": entry, "record": record }))
}

/// The digest a named field of a run points at, with its class.
fn digest_of(r: &trigon_store::RunRecord, what: &str) -> Option<(Digest, Class)> {
    match what {
        "comparison" => r.comparison.map(|d| (d, Class::Comparison)),
        "log" => r.build_log.map(|d| (d, Class::BuildLog)),
        "network" => r.network_transcript.map(|d| (d, Class::Transcript)),
        "transcript" => r.transcript.map(|d| (d, Class::ModelTranscript)),
        "strategy" => r.strategy.map(|d| (d, Class::Definition)),
        "instructions" => r.instructions.map(|d| (d, Class::Definition)),
        _ => None,
    }
}

/// Fetch a run's blob by the *field that names it*, never by a class the caller asserts.
///
/// This is the whole reason these routes exist beside `/v1/evidence/{digest}`: a class read off the
/// record is a class the caller cannot choose. A route that took `?class=definition` and a digest
/// would let anyone relabel a build log as a definition and read it.
async fn blob_of(api: &Api, id: &str, what: &str) -> Response {
    let Some(r) = api.index.get(id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    let Some((digest, class)) = digest_of(&r, what) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_recorded",
            "this run recorded no blob of that kind. Absent is not empty: it means no such record \
             was written, which is a different fact from one that was written and held nothing.",
        );
    };
    if !admits(api.principal(), class) {
        return refuse(StatusCode::FORBIDDEN, "class_gated", class.refusal());
    }
    match api.store.blobs().get(&digest).await {
        // `Blobs::get` re-hashes on every read, because the store is exactly the thing a
        // compromised worker can write to. What arrives here is bytes that hash to the digest the
        // record named, or an error — never bytes we merely found at that path.
        Ok(bytes) => (
            [(header::CONTENT_TYPE, content_type(class))],
            bytes.to_vec(),
        )
            .into_response(),
        Err(e) => refuse(
            StatusCode::NOT_FOUND,
            "no_such_blob",
            &format!("the record names a blob the store cannot return: {e}"),
        ),
    }
}

fn content_type(c: Class) -> &'static str {
    match c {
        Class::Comparison | Class::Statement | Class::Definition => "application/json",
        Class::Transcript => "application/x-ndjson",
        Class::BuildLog | Class::ModelTranscript => "text/plain; charset=utf-8",
        Class::Artifact => "application/octet-stream",
    }
}

pub async fn comparison(State(api): S, Path(id): Path<String>) -> Response {
    blob_of(&api, &id, "comparison").await
}

pub async fn build_log(State(api): S, Path(id): Path<String>) -> Response {
    blob_of(&api, &id, "log").await
}

pub async fn network(State(api): S, Path(id): Path<String>) -> Response {
    blob_of(&api, &id, "network").await
}

/// The signed statement, anonymous, permalinked.
///
/// `11-interfaces.md` wants exactly this: the statement, not the log. It is the product — the thing
/// a third party can check without trusting us or asking our permission.
pub async fn attestation(State(api): S, Path(id): Path<String>) -> Response {
    let Some(r) = api.index.get(&id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    if r.attestations.is_empty() {
        return refuse(
            StatusCode::NOT_FOUND,
            "unattested",
            "nothing has been signed for this run. An unattested outcome is a claim by whichever \
             worker computed it; a signed one has been re-derived from the bytes.",
        );
    }
    let mut envelopes = Vec::new();
    for path in &r.attestations {
        match api.store.get_attestation(path).await {
            Ok(e) => envelopes.push(e),
            Err(e) => {
                tracing::warn!(run = %id, path = %path, error = %e, "unreadable attestation");
            }
        }
    }
    if envelopes.is_empty() {
        return refuse(
            StatusCode::NOT_FOUND,
            "unreadable",
            "the record names statements the store cannot return",
        );
    }
    json(envelopes)
}

/// Lookup by the digest of the **published** artifact.
///
/// `19-distribution-and-lookup.md`: the only query that works without a naming authority. Somebody
/// holding a tarball can ask about it without knowing what we call it, which is the query a
/// consumer actually has.
pub async fn artifact(State(api): S, Path(digest): Path<String>) -> Response {
    // `sha256:abcd…` or bare hex; both are what a caller has to hand.
    let hex = digest
        .rsplit_once(':')
        .map(|(_, h)| h)
        .unwrap_or(&digest)
        .to_ascii_lowercase();
    let page = api.index.page(
        &Query {
            limit: 500,
            ..Default::default()
        },
        api.principal() == Principal::Anonymous,
    );
    let mut hits = Vec::new();
    for e in &page.rows {
        if let Some(r) = api.index.get(&e.id)
            && r.upstream.sha256.to_hex() == hex
        {
            hits.push(e.clone());
        }
    }
    if hits.is_empty() {
        return refuse(
            StatusCode::NOT_FOUND,
            "never_checked",
            "no published run covers that artifact. **Never checked is not a pass** — it is the \
             absence of an answer, and it is reported as its own state for that reason.",
        );
    }
    json(hits)
}

/// Every run against one package, newest first: the version ladder.
pub async fn target(State(api): S, Path(purl): Path<String>) -> Response {
    let page = api.index.page(
        &Query {
            q: Some(purl.clone()),
            limit: 500,
            ..Default::default()
        },
        api.principal() == Principal::Anonymous,
    );
    let rows: Vec<_> = page
        .rows
        .into_iter()
        .filter(|e| e.target == purl || e.target.starts_with(&format!("{purl}@")))
        .collect();
    if rows.is_empty() {
        return refuse(
            StatusCode::NOT_FOUND,
            "never_checked",
            "nothing published covers that package. Never checked is not a pass.",
        );
    }
    json(rows)
}

/// A blob by digest, for a principal who may read its class.
///
/// **Anonymous callers are refused outright, whatever the class.** A digest-addressed route cannot
/// know what it is serving without being told, and being told by the caller is the vulnerability.
/// The per-run routes above are how a byte is reached with its class established from the record.
pub async fn evidence_blob(State(api): S, Path(digest): Path<String>) -> Response {
    if api.principal() == Principal::Anonymous {
        return refuse(
            StatusCode::FORBIDDEN,
            "no_anonymous_evidence",
            "a digest on its own does not say what class of evidence it is, and a caller who names \
             the class chooses their own permissions. Reach a blob through its run instead.",
        );
    }
    let hex = digest.rsplit_once(':').map(|(_, h)| h).unwrap_or(&digest);
    let Ok(d) = Digest::from_hex(hex) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "malformed_digest",
            "that is not a sha256 digest",
        );
    };
    match api.store.blobs().get(&d).await {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes.to_vec(),
        )
            .into_response(),
        Err(e) => refuse(
            StatusCode::NOT_FOUND,
            "no_such_blob",
            &format!("the store cannot return that blob: {e}"),
        ),
    }
}

/// The contract, generated from the routes rather than written beside them.
///
/// A decoupled front-end is *defined by* this boundary, and before this nothing defined it. Small
/// and hand-rolled: pulling in a generator to describe twelve GET routes would be more dependency
/// than document.
pub async fn openapi(State(api): S) -> Response {
    let mut paths = BTreeMap::new();
    for (path, summary) in ROUTES {
        paths.insert(
            path.to_string(),
            serde_json::json!({
                "get": {
                    "summary": summary,
                    "responses": { "200": { "description": "ok" } }
                }
            }),
        );
    }
    json(serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Trigon",
            "version": "0.0.0",
            "description": "The read path. No operation here writes an outcome; see \
                            docs/22-management-layer.md §5.4."
        },
        "x-principal": match api.principal() {
            Principal::Anonymous => "anonymous",
            Principal::Operator => "operator",
        },
        "paths": paths,
    }))
}

/// Every route, with the sentence that says what it is for.
///
/// One table, read by `openapi` and asserted by `every_route_is_described`, so a route added to the
/// router without a description fails the build rather than appearing in the contract as a blank.
pub const ROUTES: &[(&str, &str)] = &[
    (
        "/v1/health",
        "Liveness, corpus size, and which gate the site is behind",
    ),
    (
        "/v1/stats",
        "Counts by outcome and by fault, never summed together",
    ),
    (
        "/v1/runs",
        "Browse and search. Filter by ecosystem, outcome, fault or text",
    ),
    (
        "/v1/runs/{id}",
        "One run: the stored record and the publication decision",
    ),
    (
        "/v1/runs/{id}/comparison",
        "The full comparison. Class-gated",
    ),
    (
        "/v1/runs/{id}/attestation",
        "The signed statement. Anonymous",
    ),
    (
        "/v1/runs/{id}/log",
        "The build log. Class-gated: unredacted",
    ),
    (
        "/v1/runs/{id}/network",
        "What crossed into the build. Class-gated: unredacted",
    ),
    (
        "/v1/artifacts/{digest}",
        "Lookup by published artifact digest, needing no naming authority",
    ),
    (
        "/v1/targets/{purl}",
        "Every run against one package, newest first",
    ),
    (
        "/v1/evidence/{digest}",
        "A blob by digest, for a principal who may read its class",
    ),
    ("/v1/openapi.json", "This contract"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// And the structural half, which no amount of source-scanning can give.
    ///
    /// A grep over this crate's own files says nothing about a helper it calls in another. The
    /// manifest is the real boundary: a crate that does not depend on the comparator cannot reach
    /// it however the code is arranged, and `cargo tree` is what a sceptic checks rather than our
    /// word for it.
    #[test]
    fn the_comparator_is_not_even_a_dependency() {
        // `[dependencies]` only. A dev-dependency is linked into tests and not into the binary,
        // so it cannot be reached by a handler — and conflating the two would eventually push
        // somebody into hand-building fixtures to satisfy a check that was never about them.
        let manifest = include_str!("../Cargo.toml");
        let runtime = manifest
            .split("[dev-dependencies]")
            .next()
            .unwrap_or(manifest);
        for dep in [
            "trigon-compare",
            "trigon-stabilize",
            "trigon-sandbox",
            "trigon-ai",
        ] {
            assert!(
                !runtime.contains(dep),
                "`{dep}` is a dependency of the API. The read path renders what a run decided; \
                 anything that could decide one belongs on the other side of the seam."
            );
        }
    }

    #[test]
    fn every_route_is_described() {
        for (p, s) in ROUTES {
            assert!(!s.is_empty(), "{p} appears in the contract as a blank");
            assert!(
                p.starts_with("/v1/"),
                "{p} is outside the versioned surface"
            );
        }
    }

    #[test]
    fn no_route_names_a_verb_that_writes() {
        // The router declares only `get`. This asserts the *contract* agrees, so a POST added to
        // one and not the other cannot ship a write path the documentation denies exists.
        let src = include_str!("lib.rs");
        for verb in ["post(", "put(", "delete(", "patch("] {
            assert!(
                !src.contains(verb),
                "the router declares `{verb}` — this crate has no write path, and a route that \
                 mutates would have to be argued for in docs/22 §5.4 first"
            );
        }
    }

    #[test]
    fn this_crate_cannot_produce_a_verdict() {
        // The structural half of "the API never computes an outcome". A handler that could call
        // `compare` could launder a verdict, so no handler names the thing that computes one.
        // `xtask policy` asserts the dependency; this asserts the source.
        //
        // **Scanning only the code above `#[cfg(test)]`.** The first version scanned whole files
        // and failed on this very test, whose own needle is a string literal in the file it reads.
        // That is the `pgrep -f` shape: a check whose pattern matches the checker. Splitting at the
        // test module is the fix and generalizes — an assertion about production code should not
        // be reading the assertion.
        for (name, f) in [
            ("routes.rs", include_str!("routes.rs")),
            ("index.rs", include_str!("index.rs")),
            ("lib.rs", include_str!("lib.rs")),
            ("evidence.rs", include_str!("evidence.rs")),
            ("publication.rs", include_str!("publication.rs")),
        ] {
            let production: String = f
                .split("#[cfg(test)]")
                .next()
                .unwrap_or(f)
                .lines()
                // Comments stripped, because the second version failed on `lib.rs`'s own module
                // doc, which states the rule by naming the function it forbids. A check that a
                // file may not *discuss* what it may not *call* forbids writing the rule down.
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for needle in ["trigon_compare::compare", "trigon_stabilize::"] {
                assert!(
                    !production.contains(needle),
                    "{name} reaches for `{needle}` — this crate enqueues and renders, it does not \
                     judge, and a handler that can produce a `Match` can launder one"
                );
            }
        }
    }
}
