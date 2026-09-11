//! The server.
//!
//! One handler for everything, because the routing that matters is not by path but by the platform
//! in the credentials: the same mirror serves npm and PyPI and the client says which by how it
//! addressed it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::error::MirrorError;
use crate::moment::{Filter, Platform};

/// How the mirror was used, for the run record.
///
/// A rebuild that claims a pinned dependency graph should be able to show that the pin did
/// something. Zero filtered requests against a package with floating ranges means the build never
/// asked the mirror, and the claim is empty.
#[derive(Debug, Default)]
pub struct Stats {
    pub index_requests: AtomicU64,
    pub versions_withheld: AtomicU64,
    pub passthrough_requests: AtomicU64,
    pub rejected_requests: AtomicU64,
}

pub struct Mirror {
    client: reqwest::Client,
    stats: Arc<Stats>,
    guard: Arc<crate::guard::Guard>,
}

/// A running mirror.
pub struct MirrorHandle {
    pub addr: SocketAddr,
    stats: Arc<Stats>,
    guard: Arc<crate::guard::Guard>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    joined: tokio::task::JoinHandle<()>,
}

impl MirrorHandle {
    /// The host:port a build should be pointed at.
    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// What the guard caught, if anything. A non-empty list makes the run `Void`.
    pub fn trips(&self) -> Vec<crate::Trip> {
        self.guard.trips()
    }

    /// Stop serving and wait for in-flight requests.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.joined.await;
    }
}

impl Mirror {
    pub fn new() -> Result<Self, MirrorError> {
        Ok(Mirror {
            client: reqwest::Client::builder()
                .user_agent(concat!("trigon-mirror/", env!("CARGO_PKG_VERSION")))
                // Redirects are followed here. A client behind an enforced egress boundary cannot
                // follow one itself: the destination is exactly what the boundary forbids.
                .redirect(reqwest::redirect::Policy::limited(5))
                .build()?,
            stats: Arc::new(Stats::default()),
            guard: Arc::new(crate::guard::Guard::default()),
        })
    }

    /// Refuse this run's own artifact, and watch for it arriving by any other route.
    pub fn with_guard(mut self, manifest: crate::GuardManifest) -> Self {
        self.guard = Arc::new(crate::guard::Guard::new(manifest));
        self
    }

    /// Bind and serve until the handle is dropped or shut down.
    ///
    /// Binds to all interfaces rather than loopback, because the thing that needs to reach it is a
    /// container on another network namespace.
    pub async fn serve(self, port: u16) -> Result<MirrorHandle, MirrorError> {
        let stats = self.stats.clone();
        let guard = self.guard.clone();
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(Arc::new(self));

        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| MirrorError::Bind {
                port,
                detail: e.to_string(),
            })?;
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let joined = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        tracing::info!(%addr, "time-filtering mirror listening");
        Ok(MirrorHandle {
            addr,
            stats,
            guard,
            shutdown: tx,
            joined,
        })
    }
}

async fn handle(State(mirror): State<Arc<Mirror>>, req: Request) -> Response {
    match serve_one(&mirror, req).await {
        Ok(r) => r,
        Err(e) => {
            mirror
                .stats
                .rejected_requests
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!("{e}");
            (
                StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_GATEWAY),
                e.to_string(),
            )
                .into_response()
        }
    }
}

async fn serve_one(mirror: &Mirror, req: Request) -> Result<Response, MirrorError> {
    let path_now = req.uri().path().to_string();
    let query_now = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();

    // Artifact URLs carry the filter in the path rather than in credentials, and are handled before
    // the auth check. npm forwards the registry's credentials to the packument request and not to
    // the tarball request, so a rewritten URL relying on them comes back here unfiltered and is
    // refused: the symptom is `400 Bad Request` on a tarball after the index resolved fine.
    if let Some(rest) = path_now.strip_prefix("/-artifact/") {
        return artifact(mirror, rest, &query_now).await;
    }

    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(MirrorError::NoFilter)?;
    let filter = Filter::from_authorization(auth)?;
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let accept = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // How the client addressed us, which is what artifact URLs get rewritten to. Taken from the
    // request rather than configured, because the mirror does not otherwise know its own name and
    // guessing wrong produces a packument full of URLs that resolve to nothing.
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    match filter.platform {
        Platform::Npm => npm_request(mirror, &filter, &path, &query, &host).await,
        Platform::PyPI => pypi_request(mirror, &filter, &path, &query, &accept, &host).await,
    }
}

/// npm: a bare path is a packument, anything under `/-/` is a tarball.
async fn npm_request(
    mirror: &Mirror,
    filter: &Filter,
    path: &str,
    query: &str,
    host: &str,
) -> Result<Response, MirrorError> {
    let url = format!("{}{path}{query}", filter.platform.upstream());

    // Tarballs are immutable, so there is nothing to filter. They are still proxied rather than
    // redirected: under an enforced egress tier the mirror is the build's only route out, and a
    // redirect to a host the build cannot reach is the same as no answer at all.
    if path.contains("/-/") {
        mirror
            .stats
            .passthrough_requests
            .fetch_add(1, Ordering::Relaxed);
        return proxy(mirror, &url, filter).await;
    }

    let resp = fetch(mirror, &url, filter, &[]).await?;
    let mut doc: serde_json::Value = resp.json().await?;
    let removed = crate::npm::filter_packument(&mut doc, &filter.moment);
    rewrite_npm_tarballs(&mut doc, &authority(filter, host));

    mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
    mirror
        .stats
        .versions_withheld
        .fetch_add(removed as u64, Ordering::Relaxed);
    tracing::debug!(
        path,
        moment = filter.moment,
        removed,
        "filtered a packument"
    );

    Ok(json_response(&doc, "application/json"))
}

/// PyPI: `/simple/{project}/` is the index, everything else passes through.
async fn pypi_request(
    mirror: &Mirror,
    filter: &Filter,
    path: &str,
    query: &str,
    accept: &str,
    host: &str,
) -> Result<Response, MirrorError> {
    let url = format!("{}{path}{query}", filter.platform.upstream());
    let is_simple =
        path.starts_with("/simple/") && path.trim_end_matches('/').matches('/').count() >= 2;
    if !is_simple {
        mirror
            .stats
            .passthrough_requests
            .fetch_add(1, Ordering::Relaxed);
        return proxy(mirror, &url, filter).await;
    }

    // Always ask upstream for JSON, whatever the client wanted. The HTML simple API carries no
    // upload times, so proxying it would pass every file through and quietly do nothing.
    let resp = fetch(
        mirror,
        &url,
        filter,
        &[(header::ACCEPT, "application/vnd.pypi.simple.v1+json")],
    )
    .await?;
    let mut doc: serde_json::Value = resp.json().await?;
    let removed = crate::pypi::filter_simple(&mut doc, &filter.moment);
    rewrite_pypi_files(&mut doc, &authority(filter, host));

    mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
    mirror
        .stats
        .versions_withheld
        .fetch_add(removed as u64, Ordering::Relaxed);
    tracing::debug!(
        path,
        moment = filter.moment,
        removed,
        "filtered a simple index"
    );

    if accept.contains("json") {
        return Ok(json_response(&doc, "application/vnd.pypi.simple.v1+json"));
    }
    let project = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let html = crate::pypi::render_html(&doc, project);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.pypi.simple.v1+html")],
        html,
    )
        .into_response())
}

async fn fetch(
    mirror: &Mirror,
    url: &str,
    filter: &Filter,
    headers: &[(header::HeaderName, &str)],
) -> Result<reqwest::Response, MirrorError> {
    let mut req = mirror.client.get(url);
    for (k, v) in headers {
        req = req.header(k, *v);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(MirrorError::Upstream {
            platform: filter.platform.as_str().into(),
            status: resp.status().as_u16(),
        });
    }
    Ok(resp)
}

/// Serve an artifact addressed as `/-artifact/{platform}/{moment}/{host}/{path}`.
///
/// The platform and moment are carried for the log and the refusal, not to filter: an artifact's
/// bytes are immutable, so there is nothing to filter. What matters is that the build can fetch it
/// at all, which under an enforced egress tier means through here.
async fn artifact(mirror: &Mirror, rest: &str, query: &str) -> Result<Response, MirrorError> {
    let mut parts = rest.splitn(3, '/');
    let (Some(platform), Some(moment), Some(target)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(MirrorError::NoFilter);
    };
    let platform = Platform::parse(platform).ok_or_else(|| MirrorError::UnknownPlatform {
        found: platform.to_string(),
    })?;
    let filter = Filter {
        platform,
        moment: moment.to_string(),
    };
    mirror
        .stats
        .passthrough_requests
        .fetch_add(1, Ordering::Relaxed);
    proxy(mirror, &format!("https://{target}{query}"), &filter).await
}

/// The prefix a rewritten artifact URL is built from.
///
/// The credentials are carried into every rewritten URL rather than left for the client to supply.
/// A package manager sends its index credentials to the index host and not always beyond it, and a
/// URL that arrives here without the filter cannot be served: this mirror refuses an unfiltered
/// request rather than answering with the index as it is today.
fn authority(filter: &Filter, host: &str) -> String {
    format!(
        "{host}/-artifact/{}/{}",
        filter.platform.as_str(),
        filter.moment
    )
}

/// Point every artifact URL at this mirror.
///
/// Without this a build behind an enforced egress boundary resolves a version successfully and then
/// cannot fetch it: the packument's `dist.tarball` is an absolute upstream URL, and upstream is
/// exactly what the boundary forbids. The path is preserved so the rewritten URL comes back here
/// and is proxied to the same place.
fn rewrite_npm_tarballs(doc: &mut serde_json::Value, host: &str) {
    if host.is_empty() {
        return;
    }
    let Some(versions) = doc.get_mut("versions").and_then(|v| v.as_object_mut()) else {
        return;
    };
    for version in versions.values_mut() {
        let Some(tarball) = version
            .get_mut("dist")
            .and_then(|d| d.get_mut("tarball"))
            .and_then(|t| t.as_str().map(str::to_owned))
        else {
            continue;
        };
        // The upstream host rides in the path, so the mirror knows where to fetch from without
        // assuming an artifact lives on the index's own domain.
        if let Some((_, rest)) = tarball.split_once("://") {
            version["dist"]["tarball"] = serde_json::Value::String(format!("http://{host}/{rest}"));
        }
    }
}

/// The same for PyPI, where files live on a separate CDN host.
///
/// The upstream host is carried in the path, because unlike npm the files are not served from the
/// index's own domain and dropping it would leave nothing to proxy to.
fn rewrite_pypi_files(doc: &mut serde_json::Value, host: &str) {
    if host.is_empty() {
        return;
    }
    let Some(files) = doc.get_mut("files").and_then(|f| f.as_array_mut()) else {
        return;
    };
    for file in files {
        let Some(url) = file.get("url").and_then(|u| u.as_str().map(str::to_owned)) else {
            continue;
        };
        if let Some((_, rest)) = url.split_once("://") {
            file["url"] = serde_json::Value::String(format!("http://{host}/{rest}"));
        }
    }
}

/// Stream an upstream response through, headers and all.
async fn proxy(mirror: &Mirror, url: &str, filter: &Filter) -> Result<Response, MirrorError> {
    // The cheapest control there is: at mirror-only egress this is the only reachable host, so a
    // build that asks for its own published artifact gets nothing. Refused before the request is
    // made, so the bytes never leave the registry.
    if mirror.guard.refuses(url) {
        mirror.guard.record_refusal(url);
        return Err(MirrorError::Refused {
            url: url.to_string(),
        });
    }
    let resp = mirror.client.get(url).send().await?;
    // Redirects are followed here rather than handed back: the client may have no route to where
    // they point, which is the whole reason this proxies instead of redirecting.
    let resp = if resp.status().is_redirection() {
        match resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
        {
            Some(next) => {
                let next = next.to_string();
                mirror.client.get(&next).send().await?
            }
            None => resp,
        }
    } else {
        resp
    };
    if !resp.status().is_success() {
        return Err(MirrorError::Upstream {
            platform: filter.platform.as_str().into(),
            status: resp.status().as_u16(),
        });
    }
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    // Streamed, not buffered: an artifact can be gigabytes and the mirror serves a whole fleet.
    // The guard hashes as the bytes go past rather than holding them.
    let stream = guarded_stream(resp.bytes_stream(), mirror.guard.clone(), url.to_string());
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type)],
        Body::from_stream(stream),
    )
        .into_response())
}

/// Pass a body through, hashing it, and check it once it has finished.
///
/// The body is also collected when it is small enough to decompose, because the case worth
/// catching is not the artifact arriving under its own name but one of its members arriving inside
/// something unrelated. Above that size only the whole-body hash applies, which is stated in
/// `guard.rs` rather than left as a silent limit.
fn guarded_stream<S>(
    inner: S,
    guard: Arc<crate::guard::Guard>,
    url: String,
) -> impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
where
    S: futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    use sha2::Digest as _;
    struct State<S> {
        inner: S,
        hasher: sha2::Sha256,
        body: Option<Vec<u8>>,
        guard: Arc<crate::guard::Guard>,
        url: String,
    }
    let armed = guard.is_armed();
    let state = State {
        inner,
        hasher: sha2::Sha256::new(),
        body: armed.then(Vec::new),
        guard,
        url,
    };
    futures::stream::unfold(Some(state), move |s| async move {
        let mut s = s?;
        match futures::StreamExt::next(&mut s.inner).await {
            Some(Ok(chunk)) => {
                if armed {
                    s.hasher.update(&chunk);
                    // Stop collecting once it is too big to decompose; the hash continues.
                    if let Some(b) = &mut s.body {
                        if b.len() + chunk.len() <= crate::guard::MAX_DECOMPOSE_BYTES {
                            b.extend_from_slice(&chunk);
                        } else {
                            s.body = None;
                        }
                    }
                }
                Some((Ok(chunk), Some(s)))
            }
            // An error mid-stream means we never saw the whole body, so there is nothing to check.
            Some(Err(e)) => Some((Err(e), None)),
            None => {
                if armed {
                    let digest = trigon_core::Digest::from_bytes(s.hasher.finalize().into());
                    s.guard.observe(&s.url, digest, s.body.as_deref());
                }
                None
            }
        }
    })
}

fn json_response(doc: &serde_json::Value, content_type: &'static str) -> Response {
    let body = serde_json::to_vec(doc).unwrap_or_default();
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    (StatusCode::OK, headers, Body::from(body)).into_response()
}
