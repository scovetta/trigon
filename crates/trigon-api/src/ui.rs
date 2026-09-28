//! Serving the front-end.
//!
//! The site is a separate deployable: static files that talk to nothing but the JSON API. It is
//! *also* compiled into this binary, and `docs/22-management-layer.md` §9 is the argument for why
//! that is one front-end rather than two — `11-interfaces.md` wanted it embedded "so `trigon serve`
//! gives the full UI with no separate deployment step", and this plan wants it decoupled so a
//! public site can ship on its own. Drifting rather than deciding produces an embedded UI that
//! silently rots. The decision: **the API is the only contract, and the embedded build is the same
//! front-end.** These are the same bytes you would put behind a CDN.
//!
//! No bundler, no `node_modules`, no build step. Plain ES modules, which every browser this would
//! be served to has had for years. That is a deliberate reading of the same "boring technology"
//! rule that picked Postgres over a search service: a toolchain is a dependency, a dependency is a
//! supply chain, and this project's whole subject is supply chains.

use crate::evidence::{Class, admits};
use crate::publication::Publication;
use crate::{Api, Principal};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::sync::Arc;

/// Every file the site is made of, with its media type.
///
/// A table rather than a directory walk, so what ships is a list somebody wrote down. A static
/// server that serves whatever is in a folder is a static server that serves whatever ends up in
/// that folder.
const ASSETS: &[(&str, &str, &str)] = &[
    (
        "index.html",
        "text/html; charset=utf-8",
        include_str!("../ui/index.html"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_str!("../ui/app.js"),
    ),
    (
        "app.css",
        "text/css; charset=utf-8",
        include_str!("../ui/app.css"),
    ),
];

/// The document, with what the requested route needs already in it.
///
/// **A page's first painted frame is what a link preview, a screenshot and a reader on a slow
/// connection all get**, and an SPA that fetches its own data paints "Loading…" into every one of
/// them. Firefox's headless screenshot fires at `load`, so the first attempt at a picture of this
/// site was a picture of that word — and the second, after this was added for the browse view, was
/// a picture of it again on a *permalink*, which is the URL people actually share.
///
/// The fix keeps the file deployable on its own: the document carries a `<!--BOOT-->` marker, these
/// handlers replace it with a JSON island, and the script uses the island when it is there and
/// fetches when it is not. A CDN copy still works; a served copy paints something true immediately.
/// What the document can be asked to arrive with.
///
/// **A query rather than a fragment.** The member used to live in `#member=…`, which is correct for
/// in-page state and useless for booting: a fragment is never sent to the server, so the one thing
/// a deep link most needs rendered was the one thing the document could not carry. Moving it to the
/// query keeps the page the run's — clearing it returns a reader where they were — and lets the
/// server fill it.
#[derive(Debug, Default, Deserialize)]
pub struct DocQuery {
    #[serde(default)]
    pub member: Option<String>,
    /// `text` or `hex`. Absent lets the bytes decide, which is the right default.
    #[serde(default)]
    pub view: Option<String>,
    #[serde(default)]
    pub offset: Option<u64>,
}

pub async fn index_html(State(api): State<Arc<Api>>, uri: Uri) -> Response {
    document(&api, None, query_of(&uri)).await
}

/// The document's query, read one field at a time.
///
/// Parsed from the `Uri` rather than extracted, so a stray parameter costs a *boot* rather than the
/// page: `Query<T>` as an extractor rejects the request, and a document that 400s because somebody
/// appended `?utm_source=` is a document nobody can share.
///
/// **Field by field, because deserializing the struct is all-or-nothing.** The first version did
/// `Query::<DocQuery>::try_from_uri(uri).unwrap_or_default()`, so `?member=x&offset=abc` failed to
/// deserialize `offset` and threw away `member` with it — the deep link booted nothing, and the
/// reason was a parameter that has nothing to do with which member was asked for. A bad `offset`
/// now costs the offset.
fn query_of(uri: &Uri) -> DocQuery {
    // A `Vec<(String, String)>` cannot fail on a value, because every value is a string. The
    // percent-decoding and `+` handling still come from the same place as before.
    let pairs = Query::<Vec<(String, String)>>::try_from_uri(uri)
        .map(|Query(v)| v)
        .unwrap_or_default();
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == k)
            .map(|(_, v)| v.clone())
    };
    DocQuery {
        member: get("member").filter(|s| !s.is_empty()),
        view: get("view").filter(|s| !s.is_empty()),
        // An unreadable offset is no offset, which is the difference-centred default. Silently the
        // right thing, and it no longer takes the member with it.
        offset: get("offset").and_then(|s| s.parse().ok()),
    }
}

pub async fn asset(State(api): State<Arc<Api>>, Path(path): Path<String>, uri: Uri) -> Response {
    // Everything unknown falls back to the document, because the front-end owns its own routes:
    // `/runs/1700-abc` is a page, not a file, and a reader who pastes a permalink must land on it
    // rather than on a 404 that tells them the link they were given is broken.
    match ASSETS.iter().find(|(n, ..)| *n == path) {
        Some(_) => serve(&path),
        None if path.starts_with("v1/") => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "no_such_route"})),
        )
            .into_response(),
        None => document(&api, Some(&path), query_of(&uri)).await,
    }
}

/// `path` is the front-end route being entered directly, `runs/<id>` for a permalink.
async fn document(api: &Api, path: Option<&str>, q: DocQuery) -> Response {
    let public = api.principal() == Principal::Anonymous;
    // Every route a reader can arrive on directly gets a first frame with content in it. A route
    // missing from here still works — the script falls through to a fetch — but it paints the word
    // "Loading" into every preview of itself, which is how this was noticed twice.
    let boot = match path {
        Some(p) if p.starts_with("runs/") => run_boot(api, &p[5..], public, &q).await,
        Some("queue") => queue_boot(api, public).await,
        // A job page is a live view by definition: its content is what has happened in the last
        // few seconds, so there is nothing worth freezing into the document.
        Some(_) => serde_json::json!({ "health": health_boot(api, public) }),
        None => browse_boot(api, public),
    };
    let Some((_, mime, body)) = ASSETS.iter().find(|(n, ..)| *n == "index.html") else {
        return (StatusCode::NOT_FOUND, "no document").into_response();
    };
    // The angle brackets are escaped because a corpus holding a package called `</script>` must not
    // be able to break out of the island it sits inside. `a_package_name_cannot_close_the_island`
    // asserts it against a record named exactly that.
    let island = format!(
        "<script type=\"application/json\" id=\"boot\">{}</script>",
        serde_json::to_string(&boot)
            .unwrap_or_else(|_| "null".into())
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
    );
    with_headers(mime, body.replace("<!--BOOT-->", &island))
}

fn health_boot(api: &Api, public: bool) -> serde_json::Value {
    serde_json::json!({
        "runs": api.index.len(),
        "principal": if public { "anonymous" } else { "operator" },
        "divergence_publication": if api.switches.stop_divergences { "stopped" } else { "running" },
        "kill_switches": api.kill_switches(),
    })
}

/// The queue's depth and what is in flight.
///
/// Anonymous, and it names targets. A deliberate call: the queue says what we are *about to look
/// at*, which is not a finding about anybody, and it is the thing a visitor who has just asked for
/// a rebuild most wants to see. Nothing here says whether a package reproduced.
async fn queue_boot(api: &Api, public: bool) -> serde_json::Value {
    let health = health_boot(api, public);
    let Some(q) = api.queue.as_ref() else {
        return serde_json::json!({
            "health": health,
            "queue": { "depth": null, "detail": "this instance reads a corpus and has no queue." },
        });
    };
    let (Ok(depth), Ok(flight)) = (q.depth().await, q.in_flight(50).await) else {
        // A queue that cannot be read leaves the frame without it, and the script's own fetch
        // surfaces the error. A boot island is an optimisation; it must never be the only way a
        // page can report that something is wrong.
        return serde_json::json!({ "health": health });
    };
    serde_json::json!({
        "health": health,
        "queue": {
            "depth": depth.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
            "in_flight": flight
                .into_iter()
                .map(|(job, target, state, attempt)| serde_json::json!({
                    "job": job, "target": target, "state": state, "attempt": attempt,
                }))
                .collect::<Vec<_>>(),
        },
    })
}

fn browse_boot(api: &Api, public: bool) -> serde_json::Value {
    serde_json::json!({
        // The first page of rows as well as the summary. Without them the frame carries true
        // numbers above an empty table, which is a worse first impression than either half alone.
        "runs": api.index.page(
            &crate::index::Query {
                limit: 50,
                ..Default::default()
            },
            public,
        ),
        "stats": api.index.stats(public),
        "health": health_boot(api, public),
    })
}

/// One run, already resolved — and gated exactly as `GET /v1/runs/{id}` gates it.
///
/// The publication gate is asked here as well, rather than trusted to the fetch that would
/// otherwise follow. Injecting a withheld run into the document and relying on the front-end not to
/// draw it would put the accusation in the page source, which is the one place a gate cannot reach.
///
/// A void run is booted as the routes show it to the same reader: without its outcome, and without
/// the rendered comparison, which `GET /v1/runs/{id}/diff` refuses an anonymous reader of a void.
async fn run_boot(api: &Api, id: &str, public: bool, q: &DocQuery) -> serde_json::Value {
    let (Some(entry), Some(record)) = (api.index.entry(id), api.index.get(id)) else {
        return serde_json::json!({ "health": health_boot(api, public) });
    };
    if public && !entry.publication.is_public() {
        return serde_json::json!({ "health": health_boot(api, public) });
    }
    let diff = match entry.publication {
        Publication::Void { .. } if public => serde_json::Value::Null,
        _ => diff_boot(api, &record).await,
    };
    let member = member_boot(api, &record, q).await;
    let publication = entry.publication;
    serde_json::json!({
        "health": health_boot(api, public),
        "run": {
            "entry": entry.shown(public),
            "record": crate::index::record_shown(record, publication, public),
        },
        "diff": diff,
        "member": member,
    })
}

/// How large a rendered comparison may be before the document stops carrying it.
///
/// A comparison is bounded at 500 members, and a big one serializes to something like a hundred
/// kilobytes. That is worth sending for a page whose whole content it is, and not worth sending on
/// every run page regardless — so it is capped, and past the cap the script fetches it, which is
/// what it did before this existed. The number is a judgement, not a measurement.
const MAX_BOOTED_DIFF: usize = 192 << 10;

/// The rendered comparison, so a run page's first frame is the page.
///
/// Booted *because* the member panel is: the panel is drawn inside the member table, which this
/// produces, so booting one without the other saves a request and still leaves a reader watching a
/// placeholder. A deep link that paints everything is the thing being asked for; half of it is not
/// obviously better than none.
async fn diff_boot(api: &Api, record: &trigon_store::RunRecord) -> serde_json::Value {
    let Some(digest) = record.comparison else {
        return serde_json::Value::Null;
    };
    // The re-derivation where one exists and agrees, so a run judged before per-field attribution
    // and the pass-by-pass progression were recorded can still show both.
    let Ok(bytes) = crate::comparison::bytes_for_view(&api.store, &digest).await else {
        return serde_json::Value::Null;
    };
    let Some(view) = crate::comparison::render(&bytes, None) else {
        return serde_json::Value::Null;
    };
    let value = serde_json::to_value(&view).unwrap_or(serde_json::Value::Null);
    // Measured after rendering rather than guessed from the member count, because the members are
    // not the only thing that varies — a comparison with ten thousand notes is large too.
    if serde_json::to_string(&value)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
        > MAX_BOOTED_DIFF
    {
        return serde_json::Value::Null;
    }
    value
}

/// The member panel a deep link asked for, where this principal may see it.
///
/// **The gate is asked here and not delegated to the script.** A member's bytes are
/// `Class::Artifact`: somebody else's content, which `12-security.md` §5 says we hold to check and
/// not to redistribute. Putting it in the document and trusting the front-end not to draw it would
/// put the content in `view-source:`, which is the one place a front-end cannot gate — the same
/// reasoning that made `run_boot` re-ask the publication gate.
///
/// `null` for an anonymous reader, and that is not a failure: the script falls through to
/// `/v1/runs/{id}/member`, which refuses with a sentence saying a principal is needed. A reader
/// signed in with a bearer token also lands here, because the browser sends a token on an XHR and
/// not on a document request — identity cannot be booted, which is the same limit `/v1/me` has.
async fn member_boot(
    api: &Api,
    record: &trigon_store::RunRecord,
    q: &DocQuery,
) -> serde_json::Value {
    let Some(path) = q.member.as_deref() else {
        return serde_json::Value::Null;
    };
    if !admits(api.principal(), Class::Artifact) {
        return serde_json::Value::Null;
    }
    // The document path reads a member too, so it takes the same permit. Booting was the change
    // that made this reachable from a plain page load rather than only from an explicit fetch.
    let _permit = api.member_reads.clone().acquire_owned().await;
    let Ok(pair) = crate::routes::member_pair(api, record, path).await else {
        return serde_json::Value::Null;
    };
    if pair.found_nothing() {
        // Nothing to draw. The script asks and gets a refusal that says *which* of the three
        // reasons it is — better than a document that boots an empty panel and leaves a reader
        // wondering whether the member is missing or the page is broken.
        return serde_json::Value::Null;
    }
    let mut view = crate::member::view(path, pair.upstream, pair.rebuild, q.offset);
    if !pair.problems.is_empty() {
        view.unavailable = Some(pair.problems.join("; "));
    }
    serde_json::json!({
        "view": q.view,
        "member": view,
    })
}

fn serve(name: &str) -> Response {
    let Some((_, mime, body)) = ASSETS.iter().find(|(n, ..)| *n == name) else {
        return (StatusCode::NOT_FOUND, "no such asset").into_response();
    };
    with_headers(mime, (*body).to_string())
}

fn with_headers(mime: &str, body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, mime.to_string()),
            // The page reads only its own API and loads nothing from anywhere else. Stated to the
            // browser as well as in this comment, because a site whose subject is supply-chain
            // integrity should not be one script tag away from executing somebody else's code.
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; \
                 connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
                    .to_string(),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_loads_nothing_from_anywhere_else() {
        // A CDN font, an analytics snippet or a charting library from a third party would each be
        // an external dependency on the one page whose subject is external dependencies.
        //
        // **A URL is not a fetch.** The first version banned the substring `http://` and failed on
        // `xmlns="http://www.w3.org/2000/svg"` in the favicon — an XML namespace, which names a
        // vocabulary and loads nothing. So the check is on the attributes that actually retrieve
        // something, which is the property meant all along.
        for (name, _, body) in ASSETS {
            for attr in ["src=", "href=", "url("] {
                for (i, _) in body.match_indices(attr) {
                    let tail = &body[i + attr.len()..];
                    let value = tail.trim_start_matches(['"', '\'']);
                    assert!(
                        !value.starts_with("http://")
                            && !value.starts_with("https://")
                            && !value.starts_with("//"),
                        "{name} retrieves something off-origin: {attr}{}",
                        &value[..value.len().min(60)]
                    );
                }
            }
            assert!(
                !body.contains("integrity="),
                "{name} carries a subresource-integrity hash, which only a third-party asset needs"
            );
        }
    }

    #[test]
    fn every_asset_the_document_names_is_one_this_binary_carries() {
        let html = ASSETS.iter().find(|(n, ..)| *n == "index.html").unwrap().2;
        for (name, ..) in ASSETS {
            if *name == "index.html" {
                continue;
            }
            assert!(
                html.contains(name),
                "{name} ships and nothing references it"
            );
        }
        // And the other direction: nothing referenced that does not ship.
        for token in ["app.js", "app.css"] {
            assert!(
                ASSETS.iter().any(|(n, ..)| n == &token),
                "the document names {token} and the binary does not carry it"
            );
        }
    }
}
