//! The handlers. Every one is a `get`, and none of them can produce a verdict.
//!
//! The absences are the design, and `docs/22-management-layer.md` §5.4 argues each: no endpoint
//! writes an `outcome`, there is no anonymous evidence route, no `DELETE` of anything signed, no
//! worker-proxying route, and no `/v1/costs` in dollars while there is no price table.

use crate::evidence::{Class, admits};
use crate::index::Query;
use crate::publication::Publication;
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
pub(crate) fn refuse(status: StatusCode, code: &str, sentence: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": code, "detail": sentence })),
    )
        .into_response()
}

pub(crate) fn json<T: serde::Serialize>(v: T) -> Response {
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
        Class::Comparison | Class::Statement | Class::Definition | Class::Diff => {
            "application/json"
        }
        Class::Transcript => "application/x-ndjson",
        Class::BuildLog | Class::ModelTranscript => "text/plain; charset=utf-8",
        Class::Artifact => "application/octet-stream",
    }
}

pub async fn comparison(State(api): S, Path(id): Path<String>) -> Response {
    blob_of(&api, &id, "comparison").await
}

#[derive(Debug, Deserialize)]
pub struct MemberQuery {
    /// The member's name, exactly as the comparison gave it — including the `outer!inner` form a
    /// nested archive produces.
    path: String,
    /// `upstream` or `rebuild`. Only for the raw route; a diff needs both.
    #[serde(default)]
    side: Option<String>,
    /// Byte offset to show in the hex view, for paging through a file that differs throughout.
    /// Absent means the difference-centred regions, which is the right default and useless once a
    /// reader wants byte 300,000.
    #[serde(default)]
    offset: Option<u64>,
}

/// Fetch a stored artifact's bytes, or say why not.
///
/// `pub(crate)` because the document handler boots a member panel with it. **One implementation,
/// two callers** — a second copy here would be a second set of size caps and a second answer to
/// "was this artifact kept", which is the shape this tree keeps finding.
pub(crate) async fn artifact_bytes(
    api: &Api,
    r: &trigon_store::RunRecord,
    side: &str,
) -> Result<(Vec<u8>, String), Response> {
    let Some((digest, name)) = crate::member::side_digest(r, side) else {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "no_such_side",
            "there are two sides, `upstream` and `rebuild`, and a run that produced no artifact \
             has only the first.",
        ));
    };
    // **Refused from the record, before a byte is read.** The size cap lives in `member::read`,
    // which runs *after* the whole artifact has been fetched and copied — so an over-cap artifact
    // cost 608 MiB of resident memory and then a 404 saying it was too large to read. The record
    // already knows how big it is.
    //
    // This is an optimisation and not the guarantee: a record can carry a wrong `bytes`, and the
    // check inside `read` is what actually holds. But for a record this tool wrote, it turns the
    // common refusal from half a gigabyte into nothing.
    let declared = match side {
        "upstream" => r.upstream.bytes,
        _ => r.rebuild.as_ref().map(|a| a.bytes).unwrap_or(0),
    };
    if declared > crate::member::MAX_ARTIFACT as u64 {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "too_large",
            &format!(
                "that artifact is {declared} bytes and this will not parse anything that large to \
                 reach one member of it. The whole artifact is still downloadable."
            ),
        ));
    }
    let stored = match side {
        "upstream" => r.upstream.stored,
        _ => r.rebuild.as_ref().is_some_and(|a| a.stored),
    };
    if !stored {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "not_kept",
            "that artifact's bytes were not kept. Retention drops them on a match and keeps them \
             on a divergence, so the copies that could answer this question are the ones where \
             somebody would ask it.",
        ));
    }
    match api.store.blobs().get(&digest).await {
        Ok(b) => Ok((b.to_vec(), name)),
        Err(e) => Err(refuse(
            StatusCode::NOT_FOUND,
            "no_such_blob",
            &format!("the record names an artifact the store cannot return: {e}"),
        )),
    }
}

/// Both sides' copies of one member, and what stopped either from being there.
#[derive(Debug, Default)]
pub(crate) struct Pair {
    pub upstream: Option<Vec<u8>>,
    pub rebuild: Option<Vec<u8>>,
    /// Whether the run's *artifacts* were kept at all, per side.
    ///
    /// **The distinction a reader needs and the first version lost.** Retention drops artifact
    /// bytes on a clean match and keeps them on a divergence, so "we never kept the bytes" is the
    /// normal state for most of a corpus — and it is not "neither artifact holds a member by that
    /// name", which is what the caller said when both sides came back empty. One of those is about
    /// the package and the other is about our retention policy.
    pub kept: (bool, bool),
    /// Things that went wrong, as against things that are simply absent.
    pub problems: Vec<String>,
}

impl Pair {
    pub fn found_nothing(&self) -> bool {
        self.upstream.is_none() && self.rebuild.is_none()
    }

    pub fn nothing_was_kept(&self) -> bool {
        !self.kept.0 && !self.kept.1
    }
}

/// What one side's artifact calls a member the comparison named after stabilization.
///
/// `None` unless a renaming pass ran, which is the overwhelmingly common case and costs one
/// `Option` check. The blob is only fetched when a member was not found under the comparison's own
/// name for it.
async fn raw_name_for(
    api: &Api,
    r: &trigon_store::RunRecord,
    path: &str,
    side: &str,
) -> Option<String> {
    let digest = r.comparison?;
    let bytes = api.store.blobs().get(&digest).await.ok()?;
    crate::comparison::raw_name(&bytes, path, side)
}

/// Read one member from both sides.
pub(crate) async fn member_pair(
    api: &Api,
    r: &trigon_store::RunRecord,
    path: &str,
) -> Result<Pair, Response> {
    let mut pair = Pair::default();
    let mut problems = Vec::new();
    let mut out: [Option<Vec<u8>>; 2] = [None, None];

    for (i, side) in ["upstream", "rebuild"].into_iter().enumerate() {
        // Whether this side is *supposed* to have bytes. A run with no rebuild artifact, or one
        // whose artifacts retention dropped on a clean match, is not a failure — and neither is a
        // member that only one side has, which is the whole reason this route exists.
        let expected = match side {
            "upstream" => r.upstream.stored,
            _ => r.rebuild.as_ref().is_some_and(|a| a.stored),
        };
        if i == 0 {
            pair.kept.0 = expected;
        } else {
            pair.kept.1 = expected;
        }
        if !expected {
            continue;
        }
        match artifact_bytes(api, r, side).await {
            Ok((bytes, name)) => match crate::member::read(bytes.clone(), &name, path) {
                Ok(b) => out[i] = Some(b),
                // Not there under the name the *comparison* uses. That name is the stabilized one,
                // and two passes rename, so for a handful of `nupkg` members the artifact spells it
                // differently — `lib/portable-net45%2Bwin8…` against the canonical
                // `lib/portable-net45+win8…`. The comparison recorded both; ask it, and try again
                // under the name the bytes are actually under.
                //
                // Only on a miss, because loading the comparison blob is not free and this is a
                // handful of members of one ecosystem. Measured before this existed: 5 of 23
                // members on one real NuGet divergence page were dead links.
                Err(e) if e.contains("holds no member") => {
                    if let Some(raw) = raw_name_for(api, r, path, side).await
                        && let Ok(b) = crate::member::read(bytes, &name, &raw)
                    {
                        out[i] = Some(b);
                    }
                }
                Err(e) => problems.push(format!("{side}: {e}")),
            },
            // The record says these bytes were kept and the store will not return them. That is
            // our fault and it is said out loud, because the alternative is a page that reports a
            // deleted file where there is a broken store.
            Err(_) => problems.push(format!(
                "{side}: the record says this artifact was kept and the store would not return it"
            )),
        }
    }
    let [up, rb] = out;
    pair.upstream = up;
    pair.rebuild = rb;
    pair.problems = problems;
    Ok(pair)
}

/// `GET /v1/runs/{id}/member?path=…` — what differs inside one member.
///
/// The question the comparison cannot answer. It says *that* `lib/net20/Newtonsoft.Json.dll`
/// differs and what kind of difference it is; this says what the difference is, as a line diff
/// where the bytes are text and as a hex view centred on the differing runs where they are not.
///
/// **Class-gated**, unlike the rendered comparison. A census and a member list are claims about an
/// artifact; this is the artifact's content, and `12-security.md` §5's rule covers it: we hold
/// somebody else's bytes to check them, not to redistribute them. The bound that makes the census
/// anonymous does not apply — a diff of a file that differs everywhere is the file.
pub async fn member(
    State(api): S,
    Path(id): Path<String>,
    UrlQuery(q): UrlQuery<MemberQuery>,
) -> Response {
    let Some(r) = api.index.get(&id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    // Held for the whole read. See `Api::member_reads`: one of these costs twice an artifact, and
    // the number in flight is what decides whether that is a lot of memory or a fatal amount.
    let _permit = api.member_reads.clone().acquire_owned().await;
    if !admits(api.principal(), Class::Artifact) {
        return refuse(
            StatusCode::FORBIDDEN,
            "class_gated",
            Class::Artifact.refusal(),
        );
    }
    let pair = match member_pair(&api, &r, &q.path).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if pair.found_nothing() {
        // Three different answers, and they were one message. A reader told "neither artifact holds
        // a member by that name" about a run whose bytes were dropped on a clean match would go
        // looking for a member that is there.
        return if pair.nothing_was_kept() {
            refuse(
                StatusCode::NOT_FOUND,
                "not_kept",
                "this run's artifacts were not kept, so there are no member bytes to read. \
                 Retention drops them on a match and keeps them on a divergence — the copies that \
                 could answer this are the ones where somebody would ask.",
            )
        } else if pair.problems.is_empty() {
            refuse(
                StatusCode::NOT_FOUND,
                "no_such_member",
                "neither artifact holds a member by that name.",
            )
        } else {
            refuse(
                StatusCode::NOT_FOUND,
                "unreadable_member",
                &format!(
                    "that member could not be read. {}",
                    pair.problems.join("; ")
                ),
            )
        };
    }
    let mut view = crate::member::view(&q.path, pair.upstream, pair.rebuild, q.offset);
    if !pair.problems.is_empty() {
        view.unavailable = Some(pair.problems.join("; "));
    }
    json(view)
}

/// `GET /v1/runs/{id}/member/raw?path=…&side=…` — one member's bytes, to read or to save.
///
/// The whole file rather than a diff of it, because a member present on one side only has no diff
/// and is still the thing somebody needs to look at. Served as an attachment with the member's own
/// base name, and always as `application/octet-stream`: these are bytes from an artifact we did not
/// write, and a browser that decided to render them because the name ends in `.html` would be
/// executing somebody else's content on this origin.
pub async fn member_raw(
    State(api): S,
    Path(id): Path<String>,
    UrlQuery(q): UrlQuery<MemberQuery>,
) -> Response {
    let Some(r) = api.index.get(&id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    let _permit = api.member_reads.clone().acquire_owned().await;
    if !admits(api.principal(), Class::Artifact) {
        return refuse(
            StatusCode::FORBIDDEN,
            "class_gated",
            Class::Artifact.refusal(),
        );
    }
    let side = q.side.as_deref().unwrap_or("upstream");
    if side != "upstream" && side != "rebuild" {
        return refuse(
            StatusCode::BAD_REQUEST,
            "no_such_side",
            "`side` is `upstream` or `rebuild`",
        );
    }
    let (bytes, name) = match artifact_bytes(&api, &r, side).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    // Same fallback as `member_pair`: the comparison names members after stabilization, and two
    // passes rename. Without this the download link beside a renamed member 404s while the diff
    // above it renders.
    let mut read = crate::member::read(bytes.clone(), &name, &q.path);
    if read.as_ref().is_err_and(|e| e.contains("holds no member"))
        && let Some(raw) = raw_name_for(&api, &r, &q.path, side).await
    {
        read = crate::member::read(bytes, &name, &raw);
    }
    match read {
        Ok(body) => {
            // The base name only, quoted, with anything a header cannot carry removed. A member
            // path is attacker-controlled and this header is parsed by the browser.
            let base: String = q
                .path
                .rsplit(['/', '!'])
                .next()
                .unwrap_or("member")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                .take(80)
                .collect();
            let base = if base.is_empty() {
                "member".into()
            } else {
                base
            };
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{side}-{base}\""),
                    ),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                ],
                body,
            )
                .into_response()
        }
        Err(e) => refuse(StatusCode::NOT_FOUND, "no_such_member", &e),
    }
}

/// The comparison, rendered: the ladder, the ledger, the census and a bounded member list.
///
/// The page a reader wants, as against `/comparison`, which is the same facts as three thousand
/// lines of JSON. Both exist on purpose — the raw blob is what a third party re-derives a verdict
/// from, and no rendering replaces that.
///
/// Anonymous, unlike the blob. See [`Class::Diff`]: the control on a difference summary is its
/// bound, not its secrecy, and the same member paths already reach a signed statement served to
/// anybody.
pub async fn diff(State(api): S, Path(id): Path<String>) -> Response {
    let Some(r) = api.index.get(&id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    if api.principal() == Principal::Anonymous
        && !api
            .index
            .entry(&id)
            .is_some_and(|e| e.publication.is_public())
    {
        // 404, matching `/v1/runs/{id}`: a 403 confirms the run exists, which for a withheld
        // divergence is most of the accusation the gate is holding back.
        return refuse(
            StatusCode::NOT_FOUND,
            "no_such_run",
            "no run by that id is published",
        );
    }
    let Some(digest) = r.comparison else {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_recorded",
            "this run reached no comparison, so there is nothing to render. A run that produced no \
             verdict says why on its own page.",
        );
    };
    let bytes = match api.store.blobs().get(&digest).await {
        Ok(b) => b,
        Err(e) => {
            return refuse(
                StatusCode::NOT_FOUND,
                "no_such_blob",
                &format!("the record names a comparison the store cannot return: {e}"),
            );
        }
    };
    // `None`: the set's membership is not in the record, so nothing here can tell a pass that found
    // nothing from one that was never configured. See `comparison::View::silent`.
    match crate::comparison::render(&bytes, None) {
        Some(view) => json(view),
        None => refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unreadable_comparison",
            "the stored comparison is not one this build can read. That is our fault rather than \
             the run's, and the raw blob is still served, so nothing is lost but the rendering.",
        ),
    }
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
///
/// **Anonymous, for a run the gate published.** Attestations are written at attest time, before
/// anything knows whether a second attempt will agree, so a first-attempt divergence is signed and
/// on disk while `decide` still says `Withheld { AwaitingConfirmation }`. Every other route on that
/// run refuses an anonymous reader — the record 404s, the comparison and the log are class-gated —
/// and this one served 13 KB of signed statement asserting the divergence. Observed against a real
/// run in a real store, not reasoned about: see `seam_public_surface.rs`.
///
/// `Void` is refused too, and that is not over-caution. Safeguard 2 says such a run is shown *as a
/// void and never as a divergence*; a signed statement asserting one is that divergence in its most
/// quotable form, and it would contradict the page it sits behind.
pub async fn attestation(State(api): S, Path(id): Path<String>) -> Response {
    let Some(r) = api.index.get(&id) else {
        return refuse(StatusCode::NOT_FOUND, "no_such_run", "no run by that id");
    };
    if api.principal() == Principal::Anonymous {
        let published = api
            .index
            .entry(&id)
            .is_some_and(|e| e.publication == Publication::Published);
        if !published {
            // 404 rather than 403, for the reason `run` gives: confirming the run exists is most
            // of the accusation the gate is holding back.
            return refuse(
                StatusCode::NOT_FOUND,
                "no_such_run",
                "no run by that id has a published statement",
            );
        }
    }
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
    for (path, verb, summary) in ROUTES {
        paths.insert(
            path.to_string(),
            serde_json::json!({
                (*verb): {
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
/// The public surface, as a contract: path, HTTP verb, and what it is for.
///
/// **The verb is in the table.** It was not, and every entry was rendered into the OpenAPI
/// document as a `get` — so the first route that was not one made the contract describe something
/// the router does not have. A contract that has to be true of the router is not the place to
/// assume a shape.
pub const ROUTES: &[(&str, &str, &str)] = &[
    (
        "/v1/health",
        "get",
        "Liveness, corpus size, and which gate the site is behind",
    ),
    (
        "/v1/stats",
        "get",
        "Counts by outcome and by fault, never summed together",
    ),
    (
        "/v1/runs",
        "post",
        "Browse and search. Filter by ecosystem, outcome, fault or text",
    ),
    (
        "/v1/runs/{id}",
        "get",
        "One run: the stored record and the publication decision",
    ),
    (
        "/v1/runs/{id}/diff",
        "get",
        "The comparison rendered: ladder, ledger, census, members. Anonymous, bounded",
    ),
    (
        "/v1/runs/{id}/comparison",
        "get",
        "The full comparison, as stored. Class-gated",
    ),
    (
        "/v1/runs/{id}/member",
        "get",
        "What differs inside one member: a line diff, a hex diff, or both. Class-gated",
    ),
    (
        "/v1/runs/{id}/member/raw",
        "get",
        "One member's bytes, from one side, to read or to save. Class-gated",
    ),
    (
        "/v1/runs/{id}/attestation",
        "get",
        "The signed statement. Anonymous",
    ),
    (
        "/v1/runs/{id}/log",
        "get",
        "The build log. Class-gated: unredacted",
    ),
    (
        "/v1/runs/{id}/network",
        "get",
        "What crossed into the build. Class-gated: unredacted",
    ),
    (
        "/v1/check",
        "post",
        "A lockfile or SBOM in, a verdict table out, with an explicit never-checked row",
    ),
    (
        "/v1/clusters",
        "get",
        "Failed runs grouped by failure signature, biggest first. Class-gated",
    ),
    (
        "/v1/fleet",
        "get",
        "Queue depth, who holds a lease, and the corpus's two denominators",
    ),
    (
        "/v1/artifacts/{digest}",
        "get",
        "Lookup by published artifact digest, needing no naming authority",
    ),
    (
        "/v1/targets/{purl}",
        "get",
        "Every run against one package, newest first",
    ),
    (
        "/v1/evidence/{digest}",
        "get",
        "A blob by digest, for a principal who may read its class",
    ),
    ("/v1/openapi.json", "get", "This contract"),
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
        for (p, _verb, s) in ROUTES {
            assert!(!s.is_empty(), "{p} appears in the contract as a blank");
            assert!(
                p.starts_with("/v1/"),
                "{p} is outside the versioned surface"
            );
        }
    }

    #[test]
    fn nothing_deletes_and_nothing_replaces() {
        // **The rule is narrower than "no writes", and it was always the rule.** The first version
        // of this test banned every verb but `get`, which was a fair proxy while there was no
        // write path at all; `POST /v1/runs` enqueues a job and expresses no verdict, so the proxy
        // expired and the rule did not.
        //
        // What stays forbidden: `DELETE`, because supersession is an appended statement and
        // nothing signed is ever removed; and `PUT`/`PATCH`, because every write this API has is a
        // request for work rather than an edit to a record.
        let src = include_str!("lib.rs");
        for verb in ["delete(", "put(", "patch("] {
            assert!(
                !src.contains(verb),
                "the router declares `{verb}`. Nothing here edits or removes a record — a \
                 divergence is superseded by appending, never by replacing — so a route that did \
                 would have to be argued for in docs/22 §5.4 first"
            );
        }
        // And the `POST` routes are these two and no others, so a third cannot appear without
        // this line changing. Named rather than counted: a count says a route appeared, and what
        // a reader needs to know is *which*.
        //
        // Neither writes. `/v1/runs` enqueues a job — a request for work, not a verdict. `/v1/check`
        // reads: it takes a lockfile in the body because a lockfile does not fit in a query string,
        // stores nothing, and returns verdicts that were already in the index. A `POST` that is a
        // read is a shape this rule has to allow for, or the next one gets argued into being a
        // `GET` with a 40,000-package query string.
        let posts: std::collections::BTreeSet<&str> = ["/v1/runs", "/v1/check"].into_iter().collect();
        assert_eq!(
            src.matches("post(").count(),
            posts.len(),
            "a POST route appeared that this test does not know about. If it writes, it needs an \
             argument in docs/22 §5.4; if it reads, add it here and say why it takes a body."
        );
        for p in &posts {
            assert!(
                src.contains(&format!("\"{p}\"")),
                "{p} is listed here as a POST route and the router does not declare it"
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
