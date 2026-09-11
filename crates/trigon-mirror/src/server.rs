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
}

/// A running mirror.
pub struct MirrorHandle {
    pub addr: SocketAddr,
    stats: Arc<Stats>,
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
                // No automatic redirect following. PyPI redirects file URLs to a CDN, and a mirror
                // that followed them would proxy the bytes through itself for no reason; the
                // client can follow its own.
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            stats: Arc::new(Stats::default()),
        })
    }

    /// Bind and serve until the handle is dropped or shut down.
    ///
    /// Binds to all interfaces rather than loopback, because the thing that needs to reach it is a
    /// container on another network namespace.
    pub async fn serve(self, port: u16) -> Result<MirrorHandle, MirrorError> {
        let stats = self.stats.clone();
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

    match filter.platform {
        Platform::Npm => npm_request(mirror, &filter, &path, &query).await,
        Platform::PyPI => pypi_request(mirror, &filter, &path, &query, &accept).await,
    }
}

/// npm: a bare path is a packument, anything under `/-/` is a tarball.
async fn npm_request(
    mirror: &Mirror,
    filter: &Filter,
    path: &str,
    query: &str,
) -> Result<Response, MirrorError> {
    let url = format!("{}{path}{query}", filter.platform.upstream());

    // Tarballs are immutable, so there is nothing to filter and no reason to buffer them. A
    // redirect keeps the bytes off this process entirely.
    if path.contains("/-/") {
        mirror
            .stats
            .passthrough_requests
            .fetch_add(1, Ordering::Relaxed);
        return Ok(redirect(&url));
    }

    let resp = fetch(mirror, &url, filter, &[]).await?;
    let mut doc: serde_json::Value = resp.json().await?;
    let removed = crate::npm::filter_packument(&mut doc, &filter.moment);

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
) -> Result<Response, MirrorError> {
    let url = format!("{}{path}{query}", filter.platform.upstream());
    let is_simple =
        path.starts_with("/simple/") && path.trim_end_matches('/').matches('/').count() >= 2;
    if !is_simple {
        mirror
            .stats
            .passthrough_requests
            .fetch_add(1, Ordering::Relaxed);
        return Ok(redirect(&url));
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

fn json_response(doc: &serde_json::Value, content_type: &'static str) -> Response {
    let body = serde_json::to_vec(doc).unwrap_or_default();
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    (StatusCode::OK, headers, Body::from(body)).into_response()
}

fn redirect(url: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url)], Body::empty()).into_response()
}
