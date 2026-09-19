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

use crate::{Api, Principal};
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
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
pub async fn index_html(State(api): State<Arc<Api>>) -> Response {
    document(&api, None)
}

pub async fn asset(State(api): State<Arc<Api>>, Path(path): Path<String>) -> Response {
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
        None => document(&api, Some(&path)),
    }
}

/// `path` is the front-end route being entered directly, `runs/<id>` for a permalink.
fn document(api: &Api, path: Option<&str>) -> Response {
    let public = api.principal() == Principal::Anonymous;
    let boot = match path.and_then(|p| p.strip_prefix("runs/")) {
        Some(id) => run_boot(api, id, public),
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
fn run_boot(api: &Api, id: &str, public: bool) -> serde_json::Value {
    let (Some(entry), Some(record)) = (api.index.entry(id), api.index.get(id)) else {
        return serde_json::json!({ "health": health_boot(api, public) });
    };
    if public && !entry.publication.is_public() {
        return serde_json::json!({ "health": health_boot(api, public) });
    }
    serde_json::json!({
        "health": health_boot(api, public),
        "run": { "entry": entry, "record": record },
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
