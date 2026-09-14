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
    pub toolchain_requests: AtomicU64,
    pub rejected_requests: AtomicU64,
}

/// Hosts the toolchain route will fetch from.
///
/// Short and hand-maintained on purpose. At `mirror-only` egress this proxy is the build's only
/// route out, so every entry here is a place a build can be told to download an executable from —
/// which is why it is a compiled-in list rather than a flag. The entries are toolchain
/// distributions whose URLs name an exact version, so what comes back is a function of the URL and
/// not of the day.
///
/// Adding one is cheap and deliberate. What it must never become is a wildcard: the moment the
/// build picks the host, `mirror-only` means nothing.
pub const TOOLCHAIN_HOSTS: &[&str] = &["nodejs.org", "unofficial-builds.nodejs.org"];

/// Hosts the artifact route will fetch from.
///
/// The route exists so a build behind the boundary can fetch a dependency whose URL the index gave
/// it, and these are exactly the hosts this mirror itself rewrites index URLs into — see
/// `rewrite_npm_tarballs` and `rewrite_pypi_files`. Anything else was not offered by an index we
/// served.
///
/// It had no allowlist at all, and the consequence was measured rather than reasoned about:
/// `GET /-artifact/npm/<moment>/example.com/` returned **200 with example.com's home page**, while
/// the toolchain route returned 403 for the same host. The route also sits before the credential
/// check, so it needed none. At `mirror-only` egress this mirror is the build's only route out, so
/// that made the tier a general HTTP proxy to the internet wearing the name of a boundary — a
/// larger hole than the one it was found while closing.
pub const ARTIFACT_HOSTS: &[&str] = &["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"];

/// Whether the artifact route will proxy to this host.
///
/// Exact match, for the same reason the toolchain list is: a suffix rule written the obvious way
/// accepts `registry.npmjs.org.evil.example`.
/// How many `Location` hops a proxied response may take.
///
/// Bounded because an unbounded chain is a free denial of service against a worker, and because a
/// legitimate one is short: `crates.io/.../download` is a single hop to `static.crates.io`.
const MAX_REDIRECTS: usize = 5;

/// Which allowlist applies on a given route.
///
/// One function, so the check that runs on the first URL and the check that runs on every redirect
/// after it are the same check. They were not: the routes checked their own host inline and the
/// redirect path checked nothing, which made the allowlist a statement about where a build asked to
/// go rather than about where its bytes came from.
fn host_allowed(route: &str, host: &str) -> bool {
    match route {
        "toolchain" => toolchain_host_allowed(host),
        // `artifact` is a dependency under its own name; `passthrough` is an index host serving
        // something no filter applied to. Both fetch bytes from a registry, so both take the
        // artifact list. An unknown route is refused rather than waved through: a route added
        // without a rule here must fail closed.
        "artifact" | "passthrough" => artifact_host_allowed(host),
        _ => false,
    }
}

pub fn artifact_host_allowed(host: &str) -> bool {
    ARTIFACT_HOSTS.contains(&host)
}

/// Whether the toolchain route will proxy to this host.
///
/// Exact match, not a suffix match: `nodejs.org.evil.example` ends with nothing in the list, but a
/// suffix rule written the obvious way would have accepted `evil-nodejs.org`.
pub fn toolchain_host_allowed(host: &str) -> bool {
    TOOLCHAIN_HOSTS.contains(&host)
}

/// Evidence that a registry pin bound something.
///
/// A run that says it resolved against the index as of some instant is making a claim, and until
/// this existed nothing checked it. The failure it exists to catch is silent by construction: pip
/// ignores an untrusted plain-HTTP index after one warning and resolves against the live one, so
/// the build gets today's packages while every log line says it was pinned. The only trace was this
/// counter sitting at zero, which reads exactly like a build that happened not to need anything.
///
/// Zero is genuinely ambiguous — a package with no dependencies asks for nothing — so this reports
/// rather than judges, and the caller decides. See `docs/16-findings.md` §1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Observed {
    /// Index documents served through the time filter. Non-zero is proof the pin bound something.
    pub index_requests: u64,
    /// Versions removed because they did not exist yet at the pinned moment.
    pub versions_withheld: u64,
    pub artifact_requests: u64,
    /// Toolchain downloads proxied through the allowlist. Separate from artifacts because they are
    /// a different claim: an artifact request is the build fetching a dependency, a toolchain
    /// request is the build fetching the thing that will run.
    #[serde(default)]
    pub toolchain_requests: u64,
    /// Requests the mirror turned away, most often for arriving with no filter at all — a client
    /// that dropped the credentials carrying the moment. Distinct from silence: somebody asked and
    /// was refused, which is a different thing to investigate.
    pub rejected: u64,
}

impl Observed {
    /// Derive the same counters from a network transcript.
    ///
    /// **The second of two ways to compute one thing, and the reason there is a test asserting they
    /// agree.** The first is [`Mirror::observed`], reading atomics the request path bumps. That one
    /// cannot leave the island: under an enforced tier the mirror runs inside the build's network
    /// namespace, the host has no route to it, and the counter that caught the `PIP_TRUSTED_HOST`
    /// finding read `null` on exactly the tier where it is the claim. The transcript does leave,
    /// through the container log, so this reads the same facts off it.
    ///
    /// Every field here is a count of rows rather than a number carried out of the container, which
    /// is what makes it checkable: a reader holding the transcript can redo this arithmetic.
    pub fn from_transcript(exchanges: &[crate::Exchange], refusals: u64) -> Observed {
        let count = |r: &str| exchanges.iter().filter(|e| e.route == r).count() as u64;
        Observed {
            index_requests: count("index"),
            // Only index documents carry a `withheld`, and `None` there means "not an index
            // response" rather than zero — so summing the `Some`s is the whole of it.
            versions_withheld: exchanges.iter().filter_map(|e| e.withheld).sum(),
            // Both routes are the build fetching a file rather than resolving against an index,
            // which is the distinction this counter draws. `passthrough` is an index host serving
            // something no filter applied to; `artifact` is a dependency under its own name.
            artifact_requests: count("artifact") + count("passthrough"),
            toolchain_requests: count("toolchain"),
            rejected: refusals,
        }
    }

    /// Whether anything was served through the time filter.
    ///
    /// Not the same question as "is the pin correct": a build that asked once and got what it
    /// wanted proves the configuration reached the client, which is the part that was silently
    /// failing.
    pub fn pin_bound(&self) -> bool {
        self.index_requests > 0
    }

    /// Whether the mirror was contacted at all, by any route.
    ///
    /// Separates "the pin did not apply" from "the build never came here", which want different
    /// investigations: the first is a configuration that did not reach the client, the second is a
    /// build that resolved nothing or resolved it somewhere else.
    pub fn contacted(&self) -> bool {
        self.index_requests + self.artifact_requests + self.toolchain_requests + self.rejected > 0
    }
}

pub struct Mirror {
    /// For index documents, which we parse. Transparent decompression is wanted here.
    client: reqwest::Client,
    /// For artifact bodies, which we must not touch.
    ///
    /// A separate client with `no_gzip`, because reqwest's `gzip` feature decompresses any response
    /// carrying `Content-Encoding: gzip` and hands back the plaintext. Registries serve `.tgz`
    /// files that way, so the proxy was gunzipping a tarball once and forwarding the result under
    /// the original content type: npm reported `zlib: invalid stored block lengths` and the build
    /// failed in a way that read as the package's fault.
    ///
    /// Worse, and the reason this is a correctness bug rather than a compatibility one: the
    /// artifact guard hashes the bytes as they go past. Decompressed bytes are not the artifact,
    /// so the digest never matches the one we are guarding against — the single most important
    /// control in the design was checking a transformed body. See `docs/12-security.md` §2.
    passthrough: reqwest::Client,
    stats: Arc<Stats>,
    guard: Arc<crate::guard::Guard>,
    seen: Arc<Seen>,
}

/// What this mirror served, kept in memory beside the counters that count it.
///
/// Two ways to answer one question is the shape of bug this project keeps finding, so this exists
/// mainly so a test can assert the two agree: [`Mirror::observed`] reads the atomics the request
/// path bumps, [`Observed::from_transcript`] reads the rows, and for the same traffic they must
/// produce the same `Observed`. Only the second can leave the island, which is why the second has
/// to be right.
///
/// The counters remain the source of truth for `observed()` because they are exact and unbounded;
/// the rows are capped, since a long-running `trigon mirror` would otherwise grow without limit.
/// Passing the cap drops rows and is visible as `truncated`, never as a smaller count.
#[derive(Debug, Default)]
pub struct Seen {
    exchanges: std::sync::Mutex<Vec<crate::Exchange>>,
    refusals: std::sync::Mutex<Vec<crate::Refusal>>,
    truncated: AtomicU64,
}

/// Rows retained in memory before this stops keeping them. One run's build fetches a few hundred.
const MAX_RETAINED: usize = 10_000;

impl Seen {
    /// Write one exchange to the transcript and keep a copy.
    ///
    /// One function, so the line that leaves the container and the row a test inspects are the same
    /// object. Split across two call sites they would be two things that had to agree.
    fn exchange(&self, e: crate::Exchange) {
        e.emit();
        if let Ok(mut v) = self.exchanges.lock() {
            if v.len() < MAX_RETAINED {
                v.push(e);
            } else {
                self.truncated.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn refusal(&self, r: crate::Refusal) {
        r.emit();
        if let Ok(mut v) = self.refusals.lock() {
            if v.len() < MAX_RETAINED {
                v.push(r);
            } else {
                self.truncated.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn exchanges(&self) -> Vec<crate::Exchange> {
        self.exchanges.lock().map(|v| v.clone()).unwrap_or_default()
    }

    pub fn refusals(&self) -> Vec<crate::Refusal> {
        self.refusals.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// Rows dropped for exceeding [`MAX_RETAINED`]. Non-zero means `exchanges()` is a sample and
    /// `Observed::from_transcript` over it would undercount — which the counters would not.
    pub fn truncated(&self) -> u64 {
        self.truncated.load(Ordering::Relaxed)
    }
}

/// A running mirror.
pub struct MirrorHandle {
    pub addr: SocketAddr,
    stats: Arc<Stats>,
    guard: Arc<crate::guard::Guard>,
    seen: Arc<Seen>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    joined: tokio::task::JoinHandle<()>,
}

impl MirrorHandle {
    /// The host:port a build should be pointed at.
    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// What this mirror served, row by row. See [`Seen`] for why this exists beside the counters.
    pub fn seen(&self) -> &Seen {
        &self.seen
    }

    /// What the mirror actually did, as plain numbers a caller can act on.
    pub fn observed(&self) -> Observed {
        Observed {
            index_requests: self.stats.index_requests.load(Ordering::Relaxed),
            versions_withheld: self.stats.versions_withheld.load(Ordering::Relaxed),
            artifact_requests: self.stats.passthrough_requests.load(Ordering::Relaxed),
            toolchain_requests: self.stats.toolchain_requests.load(Ordering::Relaxed),
            rejected: self.stats.rejected_requests.load(Ordering::Relaxed),
        }
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
            passthrough: reqwest::Client::builder()
                .user_agent(concat!("trigon-mirror/", env!("CARGO_PKG_VERSION")))
                // **No automatic redirects.** This used to be `limited(5)`, which meant reqwest
                // followed a `Location` to any host on the internet without asking, and a second
                // hand-rolled hop in `proxy` did the same. The host allowlist — the entire content
                // of `mirror-only` on this route — was therefore checked on the first URL and on
                // nothing after it. An allowlisted host that answers `302 cdn.evil.example` puts
                // arbitrary bytes into a build that is supposed to have no route out.
                //
                // Redirects still have to work: `crates.io/api/v1/crates/{n}/{v}/download` is a
                // 302 to `static.crates.io`, so the first crates.io request exercises this. They
                // are followed in `proxy`, one hop at a time, with the allowlist re-checked on
                // every one.
                .redirect(reqwest::redirect::Policy::none())
                .no_gzip()
                .build()?,
            stats: Arc::new(Stats::default()),
            guard: Arc::new(crate::guard::Guard::default()),
            seen: Arc::new(Seen::default()),
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
        let seen = self.seen.clone();
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
            seen,
            shutdown: tx,
            joined,
        })
    }
}

async fn handle(State(mirror): State<Arc<Mirror>>, req: Request) -> Response {
    // Taken before the request is consumed, so a refusal can say what was asked for.
    let path = req.uri().path().to_string();
    match serve_one(&mirror, req).await {
        Ok(r) => r,
        Err(e) => {
            mirror
                .stats
                .rejected_requests
                .fetch_add(1, Ordering::Relaxed);
            // Out through the log beside the transcript, because the counter beside it cannot
            // leave the island — and "somebody asked and was refused" reads nothing like silence.
            mirror.seen.refusal(crate::Refusal {
                path: path.clone(),
                status: e.status(),
                reason: e.to_string(),
            });
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

    // Toolchains, likewise before the auth check and for a stronger reason: there is nothing to
    // filter by date. A pinned toolchain URL names its own version, so the bytes are a function of
    // the URL. Without this route a build at `mirror-only` egress cannot install the toolchain that
    // produced the package at all — the deps phase runs inside the island, and the only host in
    // there is this one. See `docs/16-findings.md`.
    if let Some(rest) = path_now.strip_prefix("/-toolchain/") {
        return toolchain(mirror, rest, &query_now).await;
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
        return proxy(mirror, &url, filter, "artifact").await;
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

    Ok(json_response(
        &mirror.seen,
        &url,
        &doc,
        "application/json",
        removed as u64,
    ))
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
        // `passthrough`, not `artifact`: anything on the index host that is not a filtered
        // simple page comes through here, and calling all of it a dependency download would put a
        // wrong label on a signed record to avoid adding a word.
        return proxy(mirror, &url, filter, "passthrough").await;
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
        return Ok(json_response(
            &mirror.seen,
            &url,
            &doc,
            "application/vnd.pypi.simple.v1+json",
            removed as u64,
        ));
    }
    let project = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let html = crate::pypi::render_html(&doc, project);
    transcribe_generated(&mirror.seen, &url, html.as_bytes(), removed as u64);
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
    // The host, before anything else. `target` is `<host>/<path>`, and without this check the
    // route proxied any host on the internet to a build that is supposed to have no route out.
    let host = target.split('/').next().unwrap_or_default();
    if !artifact_host_allowed(host) {
        return Err(MirrorError::HostNotAllowed {
            host: host.to_string(),
            route: "artifact",
        });
    }
    let filter = Filter {
        platform,
        moment: moment.to_string(),
    };
    mirror
        .stats
        .passthrough_requests
        .fetch_add(1, Ordering::Relaxed);
    proxy(
        mirror,
        &format!("https://{target}{query}"),
        &filter,
        "artifact",
    )
    .await
}

/// Proxy a toolchain download, from an allowlisted host only.
///
/// `/-toolchain/<host>/<path>`. No filter and no credentials: the URL names an exact version, so
/// there is no moment to pin it to and nothing a date filter could remove. The guard still applies,
/// because "the artifact arrived dressed as a toolchain" is exactly the route it exists to close.
async fn toolchain(mirror: &Mirror, rest: &str, query: &str) -> Result<Response, MirrorError> {
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if !toolchain_host_allowed(host) {
        return Err(MirrorError::HostNotAllowed {
            host: host.to_string(),
            route: "toolchain",
        });
    }
    mirror
        .stats
        .toolchain_requests
        .fetch_add(1, Ordering::Relaxed);
    // The filter is carried for the log line the proxy writes, and filters nothing here.
    let filter = Filter {
        platform: Platform::Npm,
        moment: String::new(),
    };
    proxy(
        mirror,
        &format!("https://{host}/{path}{query}"),
        &filter,
        "toolchain",
    )
    .await
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
async fn proxy(
    mirror: &Mirror,
    url: &str,
    filter: &Filter,
    route: &'static str,
) -> Result<Response, MirrorError> {
    // The cheapest control there is: at mirror-only egress this is the only reachable host, so a
    // build that asks for its own published artifact gets nothing. Refused before the request is
    // made, so the bytes never leave the registry.
    if mirror.guard.refuses(url) {
        mirror.guard.record_refusal(url);
        return Err(MirrorError::Refused {
            url: url.to_string(),
        });
    }
    let resp = mirror.passthrough.get(url).send().await?;
    // Redirects are followed here rather than passed on, because a client behind an enforced egress
    // boundary cannot follow one itself: the destination is exactly the host it has no route to.
    //
    // **Every hop is re-checked against the allowlist.** The first URL was checked by the route
    // that built it; nothing checked the second, and reqwest was quietly following five more on
    // its own. That made the allowlist a check on where a build *asked* to go rather than on where
    // its bytes *came from*, which is the opposite of what it is for.
    let mut resp = resp;
    for _ in 0..MAX_REDIRECTS {
        if !resp.status().is_redirection() {
            break;
        }
        let Some(next) = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        else {
            break;
        };
        // Relative `Location` headers are resolved against the URL that produced them, so a
        // redirect within an allowlisted host keeps working without naming itself again.
        let next = match reqwest::Url::parse(&next) {
            Ok(u) => u,
            Err(_) => resp
                .url()
                .join(&next)
                .map_err(|_| MirrorError::BadRedirect {
                    found: next.clone(),
                })?,
        };
        let host = next.host_str().unwrap_or_default().to_string();
        if !host_allowed(route, &host) {
            return Err(MirrorError::HostNotAllowed { host, route });
        }
        resp = mirror.passthrough.get(next).send().await?;
    }
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
    // Forwarded because the body is now passed through undecoded. Without it a client receiving a
    // `Content-Encoding: gzip` body has no way to know, and the corruption simply moves from our
    // side to theirs.
    let content_encoding = resp
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Streamed, not buffered: an artifact can be gigabytes and the mirror serves a whole fleet.
    // The guard hashes as the bytes go past rather than holding them.
    let stream = guarded_stream(
        resp.bytes_stream(),
        mirror.guard.clone(),
        mirror.seen.clone(),
        url.to_string(),
        route,
    );
    let mut out = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type)],
        Body::from_stream(stream),
    )
        .into_response();
    if let Some(enc) = content_encoding
        && let Ok(v) = header::HeaderValue::from_str(&enc)
    {
        out.headers_mut().insert(header::CONTENT_ENCODING, v);
    }
    Ok(out)
}

/// Pass a body through, hashing it, checking it, and transcribing it.
///
/// The body is also collected when it is small enough to decompose, because the case worth
/// catching is not the artifact arriving under its own name but one of its members arriving inside
/// something unrelated. Above that size only the whole-body hash applies, which is stated in
/// `guard.rs` rather than left as a silent limit.
///
/// **Hashing is unconditional.** It used to run only when the guard was armed, which was right
/// while the hash existed solely to feed the guard. It is also the transcript's digest, and a run
/// with no guard manifest still downloads things — gating it would have given every unarmed run a
/// transcript full of the digest of nothing, which is worse than no transcript. What stays
/// conditional is *collecting* the body, which is the expensive half.
fn guarded_stream<S>(
    inner: S,
    guard: Arc<crate::guard::Guard>,
    seen: Arc<Seen>,
    url: String,
    route: &'static str,
) -> impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
where
    S: futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    use sha2::Digest as _;
    struct State<S> {
        inner: S,
        hasher: sha2::Sha256,
        body: Option<Vec<u8>>,
        /// Set when the body was dropped for being too large, as opposed to never collected.
        /// `observe` cannot tell those apart from a `None`, and they mean opposite things.
        oversized: bool,
        bytes: u64,
        guard: Arc<crate::guard::Guard>,
        seen: Arc<Seen>,
        url: String,
        route: &'static str,
        /// Set once the body has been read to the end and its row written.
        ///
        /// Without it a client that hangs up mid-response produced **no row at all**: the stream is
        /// dropped, the `None` arm never runs, and bytes cross into the build with nothing saying
        /// they did. That breaks the transcript's one claim — that it lists everything that crossed
        /// — and it breaks it in the direction that flatters us.
        finished: bool,
    }

    /// The row for a response that never finished.
    ///
    /// A partial body cannot be checked and must not be recorded as a whole one, so it is written
    /// with [`Checked::Partial`](crate::Checked) and the digest of the prefix that arrived. The
    /// guard is deliberately not consulted: a truncated archive does not open, and a prefix digest
    /// matching the artifact is not a thing that happens.
    impl<S> Drop for State<S> {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            let digest =
                trigon_core::Digest::from_bytes(std::mem::take(&mut self.hasher).finalize().into());
            self.seen.exchange(crate::Exchange::new(
                self.route,
                &self.url,
                digest.to_hex(),
                self.bytes,
                crate::Checked::Partial,
            ));
        }
    }
    // Keeping the bytes only when something will look at them.
    let keep_body = guard.wants_body();
    let state = State {
        inner,
        hasher: sha2::Sha256::new(),
        body: keep_body.then(Vec::new),
        oversized: false,
        bytes: 0,
        guard,
        seen,
        url,
        route,
        finished: false,
    };
    futures::stream::unfold(Some(state), move |s| async move {
        let mut s = s?;
        match futures::StreamExt::next(&mut s.inner).await {
            Some(Ok(chunk)) => {
                s.hasher.update(&chunk);
                s.bytes += chunk.len() as u64;
                // Stop collecting once it is too big to decompose; the hash continues.
                if let Some(b) = &mut s.body {
                    if b.len() + chunk.len() <= crate::guard::MAX_DECOMPOSE_BYTES {
                        b.extend_from_slice(&chunk);
                    } else {
                        s.body = None;
                        s.oversized = true;
                    }
                }
                Some((Ok(chunk), Some(s)))
            }
            // An error mid-stream means we never saw the whole body, so there is nothing to check
            // and nothing honest to transcribe: a partial body recorded under a whole body's URL
            // and digest is the one line a reader must never be handed.
            Some(Err(e)) => Some((Err(e), None)),
            None => {
                // `take`, not a move: `State` implements `Drop` now, so it cannot be
                // destructured. The `finished` flag below is what stops `Drop` writing a second row.
                let digest = trigon_core::Digest::from_bytes(
                    std::mem::take(&mut s.hasher).finalize().into(),
                );
                let checked = if s.oversized {
                    s.guard.observe_oversized(&s.url, digest)
                } else {
                    s.guard.observe(&s.url, digest, s.body.as_deref())
                };
                s.seen.exchange(crate::Exchange::new(
                    s.route,
                    &s.url,
                    digest.to_hex(),
                    s.bytes,
                    checked,
                ));
                // Before the state is dropped, so `Drop` does not write a second, partial row for
                // a body that finished perfectly well.
                s.finished = true;
                None
            }
        }
    })
}

/// Transcribe a body the mirror composed itself.
///
/// A filtered index is not proxied — it is rebuilt here from an upstream document with versions
/// removed — so the guard never sees it and [`guarded_stream`] never runs over it. It is still the
/// most consequential thing the build received, because every version it resolved came out of it,
/// so it belongs in the transcript with `Checked::Generated` saying plainly that no guard applied.
fn transcribe_generated(seen: &Seen, url: &str, body: &[u8], withheld: u64) {
    use sha2::Digest as _;
    let digest = trigon_core::Digest::from_bytes(sha2::Sha256::digest(body).into());
    seen.exchange(
        crate::Exchange::new(
            "index",
            url,
            digest.to_hex(),
            body.len() as u64,
            crate::Checked::Generated,
        )
        // Always recorded on an index response, including when it is zero. Zero withheld is
        // evidence the filter ran and found nothing to remove; absent would say it was never an
        // index document at all.
        .withholding(withheld),
    );
}

/// Serve a document the mirror composed, and transcribe exactly the bytes served.
///
/// The serialization happens once and both the response and the digest come out of it. Hashing a
/// second serialization would be hashing something the build never saw, which is the same class of
/// mistake as recording a partial body.
fn json_response(
    seen: &Seen,
    url: &str,
    doc: &serde_json::Value,
    content_type: &'static str,
    withheld: u64,
) -> Response {
    let body = serde_json::to_vec(doc).unwrap_or_default();
    transcribe_generated(seen, url, &body, withheld);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    (StatusCode::OK, headers, Body::from(body)).into_response()
}

#[cfg(test)]
mod allowlist_tests {
    use super::*;

    #[test]
    fn every_route_is_checked_against_its_own_list_and_an_unknown_route_fails_closed() {
        // This function exists because the check that ran on the URL a build asked for and the
        // check that ran on the `Location` it was redirected to were not the same check — the
        // second did not exist, and reqwest was following up to five hops on its own. The
        // allowlist is the entire content of `mirror-only` on these routes, so it was a statement
        // about where a build *asked* to go rather than about where its bytes *came from*.
        assert!(host_allowed("artifact", "registry.npmjs.org"));
        assert!(host_allowed("passthrough", "pypi.org"));
        assert!(host_allowed("toolchain", "nodejs.org"));

        // The lists do not bleed into each other: a toolchain host is not somewhere the artifact
        // route may fetch from, and vice versa. That separation is the reason there are two lists.
        assert!(!host_allowed("artifact", "nodejs.org"));
        assert!(!host_allowed("toolchain", "registry.npmjs.org"));

        // Nothing is allowed anywhere.
        assert!(!host_allowed("artifact", "cdn.evil.example"));
        assert!(!host_allowed("toolchain", "cdn.evil.example"));
        assert!(!host_allowed("artifact", ""));

        // And a route nobody taught it about is refused rather than waved through. A route added
        // without a rule here must fail closed: the alternative is a new route that proxies
        // anything, discovered later.
        assert!(!host_allowed("index", "registry.npmjs.org"));
        assert!(!host_allowed("something-new", "registry.npmjs.org"));
    }
}
