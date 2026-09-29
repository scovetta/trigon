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
        "kill_switches": api.kill_switches(),
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
/// The record is returned as it is stored — it holds digests, not bytes, and a digest is not a
/// secret. What the digests *point at* is class-gated, which is where the control lives. The entry
/// beside it carries the publication decision, so the front-end never has to re-derive one.
///
/// **Minus a void run's outcome, for an anonymous reader, and everything else that says it.**
/// Safeguard 2 shows such a run as a void and never as a divergence, and both halves of this answer
/// carry the outcome — the record in several other words too — so both are passed through
/// [`crate::index::Entry::shown`] and [`crate::index::record_shown`]. The row stays, with its
/// reason, so the reader is told why there is no verdict rather than shown a gap.
pub async fn run(State(api): S, Path(id): Path<String>) -> Response {
    let Some((record, entry)) = run_for(&api, &id) else {
        return no_such_run(&api);
    };
    let public = api.principal() == Principal::Anonymous;
    let published = published_view(&record);
    let record = crate::index::record_shown(record, entry.publication, public);
    json(serde_json::json!({
        "entry": entry.shown(public),
        "record": record,
        "published": published,
    }))
}

/// Where a run's record was published (`docs/19` §10 phase 6), from `RunRecord.published`, or
/// `None` where it has not been: the repository, the commit that logged it, the record's digest
/// and the path of its file there, and its leaf. The run page shows it as a panel of its own, and
/// the record says the same in its own field; this is it in a form a reader can go and fetch.
///
/// Nothing here is withheld from an anonymous reader of a run they may see: the record is
/// already public, in the repository it names, and a run the gate withholds is refused before
/// this is asked.
pub(crate) fn published_view(r: &trigon_store::RunRecord) -> Option<serde_json::Value> {
    let p = r.published.as_ref()?;
    Some(serde_json::json!({
        "repository": p.repository,
        "commit": p.commit,
        "record": format!("sha256:{}", p.record.to_hex()),
        "path": trigon_attest::evidence::record_path(&p.record),
        "leaf": p.leaf,
        "log": p.log.as_deref().unwrap_or("log"),
    }))
}

/// The run by that id and its row, if this reader may know there is one. Every per-run route asks
/// this first, and answers [`no_such_run`] where it says `None`.
///
/// **For an anonymous reader a withheld run is absent, and is refused in the same bytes.** 404, not
/// 403, because a 403 confirms the run exists, which for a withheld divergence is most of the
/// accusation the gate is holding back. The routes each had their own version of that, and they
/// disagreed with it: `/v1/runs/{id}` and its diff said "no run by that id" to an absent id and "no
/// run by that id is published" to a withheld one, and the class-gated routes answered a withheld
/// run with their class's 403 and an absent one with a 404. Run ids are a timestamp and eight hex
/// digits of the published artifact's digest, which anyone holding the artifact has, so each
/// difference was a test for whether a given package had a run held back.
///
/// A void is published, so it is returned, and each route shows it as one.
fn run_for(api: &Api, id: &str) -> Option<(trigon_store::RunRecord, crate::index::Entry)> {
    let public = api.principal() == Principal::Anonymous;
    let (r, e) = (api.index.get(id)?, api.index.entry(id)?);
    (!public || e.publication.is_public()).then_some((r, e))
}

/// The one refusal of a run [`run_for`] did not return, whether it is absent or withheld.
fn no_such_run(api: &Api) -> Response {
    let sentence = match api.principal() {
        Principal::Anonymous => "no run by that id is published",
        Principal::Operator => "no run by that id",
    };
    refuse(StatusCode::NOT_FOUND, "no_such_run", sentence)
}

/// The refusal of anything that would show a void run to an anonymous reader as more than a void.
fn published_as_void(because: crate::Withheld) -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        "published_as_void",
        &format!(
            "this run is published as void, not as a verdict: {} A void carries no comparison \
             outcome and no difference data, because it is evidence of nothing about the package.",
            because.sentence()
        ),
    )
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
    let Some((r, _)) = run_for(api, id) else {
        return no_such_run(api);
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
    let Some((_, name)) = crate::member::side_digest(r, side) else {
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
    let artifact = match side {
        "upstream" => Some((&r.upstream, "published artifact")),
        _ => r.rebuild.as_ref().map(|a| (a, "rebuilt artifact")),
    };
    let not_kept = || {
        refuse(
            StatusCode::NOT_FOUND,
            "not_kept",
            "that artifact's bytes were not kept. Retention drops them on a match and keeps them \
             on a divergence, so the copies that could answer this question are the ones where \
             somebody would ask it.",
        )
    };
    let Some((a, what)) = artifact else {
        return Err(not_kept());
    };
    // Read by the record's word only where the store bears it out: bytes it says are kept and
    // the store has lost are missing, and said so, never served as absent by policy.
    match api.store.artifact(&r.id, what, a).await {
        Ok(Some(b)) => Ok((b.to_vec(), name)),
        Ok(None) => Err(not_kept()),
        Err(e @ trigon_store::StoreError::Missing { .. }) => {
            Err(refuse(StatusCode::NOT_FOUND, "missing", &e.to_string()))
        }
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
    let Some((r, _)) = run_for(&api, &id) else {
        return no_such_run(&api);
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
    // **A managed assembly is decompiled here too, not only for the model.** For a `.dll` the
    // text view is empty and the reader gets a hex window; the injected decompiler (from
    // `trigon serve`, see [`crate::Decompiler`]) turns both sides into C#, and the text view
    // becomes the diff of that. The predicate for "is this an assembly" lives with the decompiler
    // in the binary, so the hook is asked about every member and answers `None` for the ones it
    // does not handle — a cheap rejection, no container. Only where both sides are present, since
    // a diff needs both.
    let decompiled = match (&pair.upstream, &pair.rebuild) {
        (Some(up), Some(rb)) if trigon_core::is_managed_assembly(&q.path) => {
            // **The store first, which needs no container.** A divergent run pre-computes the C#
            // for its differing assemblies and stores it keyed by the assembly's digest, so a read
            // replica over a bucket — no podman — serves the source diff from bytes. Only on a
            // miss (an old run, a member the run did not reach) does the live decompiler run, and
            // only where the binary supplied one.
            let (ad, bd) = (trigon_store::digest_of(up), trigon_store::digest_of(rb));
            let cached = match (
                api.store.get_decompiled(&ad).await,
                api.store.get_decompiled(&bd).await,
            ) {
                (Ok(Some(a)), Ok(Some(b))) => Some((a, b)),
                _ => None,
            };
            match (cached, &api.decompiler) {
                (Some(pair), _) => Some(pair),
                (None, Some(dec)) => {
                    let (dec, path, up, rb) = (dec.clone(), q.path.clone(), up.clone(), rb.clone());
                    // Off the async runtime: the live decompiler blocks on a container.
                    tokio::task::spawn_blocking(move || dec(&path, &up, &rb))
                        .await
                        .ok()
                        .flatten()
                }
                (None, None) => None,
            }
        }
        _ => None,
    };
    let mut view = crate::member::view(&q.path, pair.upstream, pair.rebuild, q.offset);
    if let Some((up_cs, rb_cs)) = decompiled {
        // The C# diff replaces the (absent) text view; the hex view stays, so a reader can still
        // see the bytes. `decompiled` marks it so the page says the diff is a reading of the
        // assembly and not the assembly.
        let cs = crate::member::view(
            &q.path,
            Some(up_cs.into_bytes()),
            Some(rb_cs.into_bytes()),
            None,
        );
        view.text = cs.text;
        view.decompiled = true;
    }
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
    let Some((r, _)) = run_for(&api, &id) else {
        return no_such_run(&api);
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
///
/// **Not for a void run**, whose view is its outcome and a census of what differed: the divergence
/// in more detail than the verdict the run page no longer shows. `docs/19` §4.3 says a void
/// carries no comparison outcome and no difference data, and the refusal says why in those terms.
pub async fn diff(State(api): S, Path(id): Path<String>) -> Response {
    let Some((r, entry)) = run_for(&api, &id) else {
        return no_such_run(&api);
    };
    // `run_for` has already refused a withheld run, as it refuses an absent one.
    if api.principal() == Principal::Anonymous
        && let Publication::Void { because } = entry.publication
    {
        return published_as_void(because);
    }
    let Some(digest) = r.comparison else {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_recorded",
            "this run reached no comparison, so there is nothing to render. A run that produced no \
             verdict says why on its own page.",
        );
    };
    // Rendered from the re-derivation where `trigon rederive` wrote one that agrees with the
    // recorded comparison; `comparison` (the raw evidence route) always serves the recorded one.
    let bytes = match crate::comparison::bytes_for_view(&api.store, &digest).await {
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

/// The network transcript, summarized: totals, routes, what the guard could check, the hosts, and
/// the largest exchanges.
///
/// Gated exactly as the raw transcript is, because it carries the same unredacted URLs: the class
/// is read off the record, never asserted by the caller, and a principal refused the transcript is
/// refused its summary with the same sentence.
pub async fn network_summary(State(api): S, Path(id): Path<String>) -> Response {
    let Some((r, _)) = run_for(&api, &id) else {
        return no_such_run(&api);
    };
    let Some((digest, class)) = digest_of(&r, "network") else {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_recorded",
            "this run recorded no network transcript. Absent is not empty: no transcript was \
             written, which is a different fact from one that was written and held nothing.",
        );
    };
    if !admits(api.principal(), class) {
        return refuse(StatusCode::FORBIDDEN, "class_gated", class.refusal());
    }
    match api.store.blobs().get(&digest).await {
        Ok(bytes) => json(crate::network::summarize(&bytes)),
        Err(e) => refuse(
            StatusCode::NOT_FOUND,
            "no_such_blob",
            &format!("the record names a transcript the store cannot return: {e}"),
        ),
    }
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
/// **A void run serves its `void/v1` and nothing else.** Safeguard 2 says such a run is shown *as a
/// void and never as a divergence*, and a verdict envelope signed for it — which `trigon attest`
/// signed for an open-egress run until `docs/19` §10 phase 2 — is that divergence in its most
/// quotable form, contradicting the page it sits behind. So an anonymous reader of a void run is
/// served only statements whose predicate is `void/v1`, which carry no outcome and no difference
/// data, and one with no such statement is refused.
pub async fn attestation(State(api): S, Path(id): Path<String>) -> Response {
    let Some((r, entry)) = run_for(&api, &id) else {
        return no_such_run(&api);
    };
    // A withheld run was refused above, as an absent one is, so what reaches here unpublished is a
    // void; the arm for a withheld one is there so this cannot come to serve one if that changes.
    let void = match (api.principal(), entry.publication) {
        (Principal::Anonymous, Publication::Void { because }) => Some(because),
        (Principal::Anonymous, Publication::Withheld { .. }) => return no_such_run(&api),
        _ => None,
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
            Ok(e) if void.is_none() || is_void(&e) => envelopes.push(e),
            // A void run's other statements, which for a run attested before voids were signed
            // are its verdicts. Chosen by the predicate the envelope carries, never by the name it
            // is filed under: the name is the store's, and the statement is what a reader is
            // handed.
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(run = %id, path = %path, error = %e, "unreadable attestation");
            }
        }
    }
    if let Some(because) = void
        && envelopes.is_empty()
    {
        return refuse(
            StatusCode::NOT_FOUND,
            "no_void_statement",
            &format!(
                "this run is published as void, and no void statement has been signed for it: {} \
                 `trigon attest` signs one, and signs nothing else for a void run.",
                because.sentence()
            ),
        );
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

/// Whether an envelope's statement is a `void/v1`. One that does not decode is not.
fn is_void(e: &trigon_attest::Envelope) -> bool {
    let Ok(payload) = e.decoded_payload() else {
        return false;
    };
    serde_json::from_slice::<trigon_attest::Statement>(&payload)
        .is_ok_and(|st| st.predicate_type == trigon_attest::VOID)
}

/// Lookup by the digest of the **published** artifact.
///
/// `19-distribution-and-lookup.md`: the only query that works without a naming authority. Somebody
/// holding a tarball can ask about it without knowing what we call it, which is the query a
/// consumer actually has.
///
/// **The algorithm is the one asked for**: `sha256:<hex>`, `sha512:<hex>` or `sha1:<hex>` — npm's
/// lockfile holds a sha512 and nothing else — each matched against the digest of that algorithm
/// the run computed over the published bytes, as a subject carries them (`docs/19` §5). A bare
/// digest is read by its length. It used to discard the algorithm and compare whatever hex it was
/// given with the sha256, so a sha512 or a sha1 matched nothing; and it searched the newest 500
/// rows, so an older run of the artifact read as never checked. Every run is searched now.
///
/// Its rows are [`crate::index::Index::for_artifact`]'s, which hands an anonymous reader a void
/// row without its outcome, as it does for `/v1/runs` and `/v1/targets/{purl}`, and no withheld
/// row at all.
pub async fn artifact(State(api): S, Path(digest): Path<String>) -> Response {
    let (algorithm, hex) = match digest.split_once(':') {
        Some((a, h)) => (a.to_ascii_lowercase(), h.to_ascii_lowercase()),
        None => {
            let hex = digest.to_ascii_lowercase();
            let algorithm = match hex.len() {
                128 => "sha512",
                40 => "sha1",
                _ => "sha256",
            };
            (algorithm.to_string(), hex)
        }
    };
    let len = match algorithm.as_str() {
        "sha256" => 64,
        "sha512" => 128,
        "sha1" => 40,
        _ => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "unknown_algorithm",
                "a published artifact is looked up by `sha256:<hex>`, `sha512:<hex>` or \
                 `sha1:<hex>`: the digests a run computes over it",
            );
        }
    };
    if hex.len() != len || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "malformed_digest",
            &format!("a {algorithm} digest is {len} hex digits"),
        );
    }
    let hits = api
        .index
        .for_artifact(&algorithm, &hex, api.principal() == Principal::Anonymous);
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

/// Every run against one package, newest first: the version ladder. Every run, not a page of them:
/// see [`crate::index::Index::for_target`].
pub async fn target(State(api): S, Path(purl): Path<String>) -> Response {
    let rows = api
        .index
        .for_target(&purl, api.principal() == Principal::Anonymous);
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
    // Gathered per path, because a path can carry more than one verb: `/v1/runs` is browsed with
    // `GET` and asked of with `POST`. One operation per path is what let the table list it once,
    // as the verb it is not browsed with.
    let mut paths: BTreeMap<&str, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();
    for (path, verb, summary) in ROUTES {
        paths.entry(path).or_default().insert(
            verb.to_string(),
            serde_json::json!({
                "summary": summary,
                "responses": { "200": { "description": "ok" } }
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
///
/// **And every route is in the table**, which `the_table_lists_every_route_the_router_mounts`
/// holds against `lib.rs`. `/v1/me`, `/v1/queue` and `/v1/jobs/{id}/events` were mounted and
/// missing, and `/v1/runs` was listed once, as `post`, with the description of its `get`. A sweep
/// over "every anonymous route" is built from this table, so a route missing here is a route no
/// sweep visits — and the job events route was publishing withheld divergences past one.
pub const ROUTES: &[(&str, &str, &str)] = &[
    (
        "/v1/health",
        "get",
        "Liveness, corpus size, which gate the site is behind, and both kill-switches: this \
         server's, and the evidence repository's",
    ),
    (
        "/v1/stats",
        "get",
        "Counts by outcome and by fault, never summed together",
    ),
    (
        "/v1/runs",
        "get",
        "Browse and search. Filter by ecosystem, outcome, fault or text",
    ),
    (
        "/v1/runs",
        "post",
        "Ask for a rebuild of a package URL. Needs a principal with a quota, and names nothing else",
    ),
    (
        "/v1/runs/{id}",
        "get",
        "One run: the stored record, the publication decision, and where its record was published",
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
        "The signed statements. Anonymous; a void run's `void/v1` alone",
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
        "/v1/runs/{id}/network/summary",
        "get",
        "The network transcript summarized: routes, hosts, guard coverage, largest exchanges. Class-gated like the transcript",
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
        "Queue depth, how many hold a lease and how soon each lapses (worker names to an operator only), and the corpus's two denominators",
    ),
    (
        "/v1/artifacts/{digest}",
        "get",
        "Lookup by published artifact digest — sha256, sha512 or sha1 — needing no naming authority",
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
    (
        "/v1/me",
        "get",
        "What the presented credential may do, or that there is none",
    ),
    (
        "/v1/queue",
        "get",
        "What is waiting and what is running. Names targets, never outcomes",
    ),
    (
        "/v1/jobs/{id}/events",
        "get",
        "Where one job has got to. Its notes are for an operator",
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

    /// The table and the router are the same set of routes, verb for verb.
    ///
    /// Read off `lib.rs`, because axum will not list a router's routes. The two routes that serve
    /// the page are outside the versioned surface and are left out on purpose; everything under
    /// `/v1/` the router mounts has to be in the contract, or a sweep built from the contract does
    /// not visit it.
    #[test]
    fn the_table_lists_every_route_the_router_mounts() {
        use std::collections::BTreeSet;
        let src = include_str!("lib.rs");
        let mounted: BTreeSet<(String, String)> = src
            .split(".route(")
            .skip(1)
            .filter_map(|call| {
                // `"/v1/queue", get(request::queue_state))`: the path, then the handler's verb,
                // which is the last segment of whatever comes before its first parenthesis.
                let mut parts = call.splitn(3, '"');
                let path = parts.nth(1)?;
                let rest = parts.next()?.trim_start_matches([',', ' ', '\n']);
                let verb = rest.split('(').next()?.rsplit("::").next()?;
                Some((path.to_string(), verb.to_string()))
            })
            .filter(|(path, _)| path.starts_with("/v1/"))
            .collect();
        assert!(
            mounted.len() > 20,
            "the scan found {} routes in lib.rs, so it is reading the wrong thing",
            mounted.len()
        );
        let table: BTreeSet<(String, String)> = ROUTES
            .iter()
            .map(|(p, v, _)| (p.to_string(), v.to_string()))
            .collect();
        let unlisted: Vec<_> = mounted.difference(&table).collect();
        let unmounted: Vec<_> = table.difference(&mounted).collect();
        assert!(
            unlisted.is_empty() && unmounted.is_empty(),
            "the router mounts {unlisted:?}, which the contract does not list, and the contract \
             lists {unmounted:?}, which the router does not mount"
        );
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
        let posts: std::collections::BTreeSet<&str> =
            ["/v1/runs", "/v1/check"].into_iter().collect();
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

    /// A class is read off the field of the record that names the blob, and each field names the
    /// class the evidence table was written for. The per-run routes rest on this: a mapping that
    /// filed a build log or a model exchange under an anonymous class would serve it to anybody.
    #[test]
    fn each_field_a_route_names_is_read_with_its_own_class() {
        let d = |n: u8| Digest::from_bytes([n; 32]);
        let mut r = trigon_store::RunRecord::new(
            "1700000001-aa",
            "pkg:npm/a@1",
            trigon_store::ArtifactRef {
                name: "a.tgz".into(),
                sha256: d(0),
                bytes: 1,
                stored: true,
            },
            trigon_store::Environment {
                base_image: "x@sha256:0".into(),
                derived_image: None,
                egress: "mirror".into(),
                isolation: "podman".into(),
                attestable: true,
                registry_moment: None,
                pin: None,
                guard_manifest: None,
                guarded_members: None,
            },
            "2026-01-01T00:00:00Z",
        );
        for what in [
            "comparison",
            "log",
            "network",
            "transcript",
            "strategy",
            "instructions",
        ] {
            assert_eq!(digest_of(&r, what), None, "`{what}` was never recorded");
        }
        r.comparison = Some(d(1));
        r.build_log = Some(d(2));
        r.network_transcript = Some(d(3));
        r.transcript = Some(d(4));
        r.strategy = Some(d(5));
        r.instructions = Some(d(6));
        assert_eq!(digest_of(&r, "comparison"), Some((d(1), Class::Comparison)));
        assert_eq!(digest_of(&r, "log"), Some((d(2), Class::BuildLog)));
        assert_eq!(digest_of(&r, "network"), Some((d(3), Class::Transcript)));
        assert_eq!(
            digest_of(&r, "transcript"),
            Some((d(4), Class::ModelTranscript))
        );
        assert_eq!(digest_of(&r, "strategy"), Some((d(5), Class::Definition)));
        assert_eq!(
            digest_of(&r, "instructions"),
            Some((d(6), Class::Definition))
        );
        // A field the caller names that the record does not have is nothing, never a guess.
        assert_eq!(digest_of(&r, "upstream"), None);
    }

    /// Every class is served as data. Bytes from an artifact or a log that a browser rendered as a
    /// page would run somebody else's content on this origin.
    #[test]
    fn no_class_is_served_as_something_a_browser_renders_as_a_page() {
        for c in Class::ALL {
            let t = content_type(c);
            assert!(
                !t.contains("html") && !t.contains("javascript") && !t.contains("svg"),
                "{c:?} is served as {t}"
            );
        }
        assert_eq!(content_type(Class::Artifact), "application/octet-stream");
        assert_eq!(content_type(Class::BuildLog), "text/plain; charset=utf-8");
        assert_eq!(
            content_type(Class::ModelTranscript),
            "text/plain; charset=utf-8"
        );
        assert_eq!(content_type(Class::Transcript), "application/x-ndjson");
    }
}
