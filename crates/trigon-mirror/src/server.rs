//! The server.
//!
//! One handler for everything, because the routing that matters is not by path but by the platform
//! in the credentials: the same mirror serves npm and PyPI and the client says which by how it
//! addressed it.

use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use trigon_politeness as politeness;

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
pub const TOOLCHAIN_HOSTS: &[&str] = &[
    "nodejs.org",
    "unofficial-builds.nodejs.org",
    // rustup-init and every Rust toolchain. `static.rust-lang.org` is the only host rustup fetches
    // from when `RUSTUP_DIST_SERVER` points at it, and its URLs name an exact release — the
    // property this list requires.
    "static.rust-lang.org",
    // io.js, for the year before it merged back into Node at 4.0.0. `_nodeVersion` values of 1.x,
    // 2.x and 3.x name releases that only ever existed here — nodejs.org has no v1, v2 or v3 — and
    // the URLs name an exact version, which is the property this list requires.
    "iojs.org",
];

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
pub const ARTIFACT_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    // NuGet serves its registration metadata and its `.nupkg` bytes from the one host.
    "api.nuget.org",
    // Where crates.io's `config.json` points `dl` at, and the only host a `.crate` comes from.
    // The index itself is fetched by the mirror rather than proxied — it is filtered, not passed
    // through — so `index.crates.io` is deliberately not here.
    "static.crates.io",
];

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

/// Claim the address a mirror will serve on, before the mirror exists.
///
/// The guard manifest is narrowed by the source tree, the source tree is a function of the
/// strategy's location, and a strategy has to be told where the mirror *will be* before it can be
/// chosen. Reserving the address breaks that cycle without starting a mirror whose manifest is not
/// final — a mirror serving with a wider guard than the run settled on is a control reporting one
/// posture while holding another.
///
/// A held listener rather than a remembered port number: releasing a port and re-binding it later
/// is a race, and the losing side of that race is a run that cannot start its mirror at all.
pub async fn reserve(port: u16) -> Result<tokio::net::TcpListener, MirrorError> {
    tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| MirrorError::Bind {
            port,
            detail: e.to_string(),
        })
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
    /// Where the mirror got a body, when it did not get it from the network.
    ///
    /// `None` is the default and the whole of the behaviour before this existed. A mirror with no
    /// cache fetches everything, every time, which is honest and is 39 GB per sweep.
    cache: Option<Arc<crate::cache::Cache>>,
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
    /// Tarball paths this mirror offered in a **filtered** packument, as npm would compose them.
    ///
    /// The bare-tarball route serves only these. Without it that route would proxy any npm tarball
    /// on request — including a version published long after the moment the run is pinned to — and
    /// `seam_controls_fail_closed.rs` says in as many words that a tarball "which needs no
    /// filtering, is refused rather than proxied unfiltered". That test is the specification, and a
    /// route that made it fail would have been a control being edited to match the code that broke
    /// it.
    ///
    /// With it, the filter still decides: a build can fetch exactly what the index it was served
    /// offered, and nothing else. A package never indexed in this run is refused as before.
    offered: std::sync::Mutex<std::collections::BTreeSet<String>>,
    /// The moment an index request filtered to, remembered for the requests that carry no
    /// credentials.
    ///
    /// The filter rides in the credentials and npm forwards them for a packument and not for a
    /// tarball it composed itself, so a bare tarball arrives with no moment at all. One mirror
    /// serves one build against one moment, so the moment the index used is the moment that
    /// applies — and `note_moment` refuses to change it rather than quietly taking the last one,
    /// because two moments in one run is a bug worth seeing.
    moment: std::sync::Mutex<Option<String>>,
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

    /// Remember the moment the index filtered to, the first time one is seen.
    fn note_moment(&self, moment: &str) {
        if moment.is_empty() {
            return;
        }
        if let Ok(mut m) = self.moment.lock() {
            match m.as_deref() {
                None => *m = Some(moment.to_string()),
                Some(first) if first != moment => tracing::warn!(
                    first,
                    now = moment,
                    "two moments in one run; the first is the one a credential-less request uses"
                ),
                Some(_) => {}
            }
        }
    }

    /// The moment this run is pinned to, if any index request has said.
    fn moment(&self) -> Option<String> {
        self.moment.lock().ok().and_then(|m| m.clone())
    }

    /// Record a tarball path the filtered index just offered.
    fn offer(&self, path: &str) {
        if let Ok(mut o) = self.offered.lock() {
            o.insert(path.to_string());
        }
    }

    /// Whether a bare tarball request asks for something the filtered index offered.
    fn was_offered(&self, path: &str) -> bool {
        self.offered
            .lock()
            .map(|o| o.contains(path))
            .unwrap_or(false)
    }
}

/// A running mirror.
pub struct MirrorHandle {
    pub addr: SocketAddr,
    stats: Arc<Stats>,
    guard: Arc<crate::guard::Guard>,
    seen: Arc<Seen>,
    cache: Option<Arc<crate::cache::Cache>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    joined: tokio::task::JoinHandle<()>,
}

impl MirrorHandle {
    /// The host:port a build should be pointed at.
    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// The package and version this run is about, as the guard was told it.
    ///
    /// Exposed so the void decision can tell a member arriving inside one of the package's *own*
    /// other releases from one arriving inside somebody else's package. See
    /// [`crate::guard::voiding`].
    pub fn withheld(&self) -> Option<&crate::guard::Withheld> {
        self.guard.withheld()
    }

    /// What this mirror served, row by row. See [`Seen`] for why this exists beside the counters.
    pub fn seen(&self) -> &Seen {
        &self.seen
    }

    /// What the cache did, where one was configured.
    pub fn cache_stats(&self) -> Option<crate::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
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

    /// The trips where something arrived: the artifact, or a guarded member of it.
    ///
    /// Whether they void the run is decided against what the build produced — see
    /// [`crate::voiding`].
    pub fn arrived(&self) -> Vec<crate::Trip> {
        self.guard.arrived()
    }

    /// Times the build asked for its own artifact and was turned away. Not a void — nothing
    /// arrived. See `REFUSED_ARTIFACT_MARKER`.
    pub fn refused(&self) -> Vec<crate::Trip> {
        self.guard.refused()
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
                // **The same string every other route declares.** This said
                // `trigon-mirror/0.0.0` with no contact URL while carrying every byte a build
                // fetches, so the traffic that mattered was the traffic nobody could trace back
                // to a person. An anonymous crawler is the thing registries block first.
                .user_agent(politeness::user_agent())
                // Redirects are followed here. A client behind an enforced egress boundary cannot
                // follow one itself: the destination is exactly what the boundary forbids.
                .redirect(reqwest::redirect::Policy::limited(5))
                .build()?,
            passthrough: reqwest::Client::builder()
                .user_agent(politeness::user_agent())
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
            cache: None,
        })
    }

    /// Serve from a cache on disk, rooted at `root`, with index entries scoped to `scope`.
    ///
    /// Behind the mirror rather than in front of it: the guard still runs first, the bytes still go
    /// through the same hashing stream, and the transcript is byte for byte what it would have
    /// been. See [`ADR-0013`](../../../docs/adr/0013-a-cache-supplies-bytes-never-decisions.md).
    pub fn with_cache(
        mut self,
        root: std::path::PathBuf,
        scope: String,
        max_bytes: Option<u64>,
    ) -> Result<Self, MirrorError> {
        // **The cache directory is also where the rate limiter's slots live.** It is the one thing
        // every mirror container in a sweep already shares — a bind mount from the host — and the
        // limiter needs exactly that: somewhere two processes can queue in one line. Without it
        // "process-global" means per-target, because the mirror is per-target, and a sweep at N
        // lanes keeps N copies of the declared floor.
        trigon_politeness::share_with(root.clone());
        let cache = crate::cache::Cache::open(root, scope).map_err(MirrorError::Cache)?;
        if let Some(max) = max_bytes {
            match cache.prune(max) {
                Ok(0) => {}
                Ok(freed) => tracing::info!(freed, "pruned the cache to its ceiling"),
                // Never fatal. A cache that cannot be pruned is a disk to look at, not a reason to
                // refuse to serve a build.
                Err(e) => tracing::warn!("could not prune the cache: {e}"),
            }
        }
        self.cache = Some(Arc::new(cache));
        Ok(self)
    }

    /// What the cache did, for the run record.
    pub fn cache_stats(&self) -> Option<crate::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
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
        let listener = reserve(port).await?;
        self.serve_on(listener).await
    }

    /// Serve on an address that was reserved before the mirror was armed.
    ///
    /// See [`reserve`] for why the two are separable.
    pub async fn serve_on(
        self,
        listener: tokio::net::TcpListener,
    ) -> Result<MirrorHandle, MirrorError> {
        let stats = self.stats.clone();
        let guard = self.guard.clone();
        let seen = self.seen.clone();
        let cache = self.cache.clone();
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(Arc::new(self));

        let addr = listener.local_addr().map_err(|e| MirrorError::Bind {
            port: 0,
            detail: e.to_string(),
        })?;
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
            cache,
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

    // **A bare npm tarball, unfiltered, because npm composes this URL itself.** The `-artifact`
    // route above exists for the `dist.tarball` values this mirror rewrites, and npm 11 does not
    // use them: it takes the path off the upstream tarball URL and re-bases it onto the configured
    // registry, producing `http://timewarp:8129/yocto-queue/-/yocto-queue-0.1.0.tgz` — and drops
    // the credentials on the way, because modern npm does not forward URL userinfo to a tarball
    // request it built itself.
    //
    // `moment.rs` states the assumption this breaks: "Credentials in a URL are the one component
    // every client already forwards." That was true when it was written and is no longer true of
    // npm. The M1 corpus is what found it — 34 of 197 targets, every one reported as the package
    // failing when the mirror was refusing our own request.
    //
    // **Only what the filtered index already offered.** The first version of this served any npm
    // tarball on request, which reversed a deliberate decision: `seam_controls_fail_closed.rs` says
    // a tarball "which needs no filtering, is refused rather than proxied unfiltered", and it fails
    // when that stops being true. Editing the test to match would have been the control eroding to
    // fit the code that broke it — so instead the route serves exactly the paths
    // `rewrite_npm_tarballs` handed out for this run's moment, and refuses everything else. A
    // version published after the pin is still unreachable, which is the property the filter exists
    // for.
    //
    // The upstream is **hardcoded** to the npm registry rather than read from the path, so this
    // route reaches exactly one host, and the guard still hashes every byte.
    if is_npm_tarball(&path_now) {
        // **Offered, or provably offerable.** The offered set covers a build that resolved through
        // the index: every packument this mirror filtered handed out its surviving tarballs and
        // remembered them. A build that resolves from a **lockfile** asks for none of those
        // packuments — npm reads `resolved` straight out of `package-lock.json`, re-bases it onto
        // the configured registry and fetches — so nothing ever offered the path and every such
        // build was refused. That was 23 of 150 targets on the npm corpus, all reported as the
        // package failing.
        //
        // Serving any tarball on request is the hole this gate was added to close, so the answer
        // is to *answer the question the gate was standing in for*: ask the index whether this
        // exact version survives the filter, and serve it only if it does. Same property, arrived
        // at by asking rather than by remembering.
        let offerable =
            mirror.seen.was_offered(&path_now) || filtered_index_offers(mirror, &path_now).await;
        if offerable {
            mirror
                .stats
                .passthrough_requests
                .fetch_add(1, Ordering::Relaxed);
            let url = format!("{}{path_now}{query_now}", Platform::Npm.upstream());
            let filter = Filter {
                platform: Platform::Npm,
                moment: String::new(),
            };
            return proxy(mirror, &url, &filter, "artifact").await;
        }
    }

    // NuGet, before the auth check for the same reason the artifact route is: the filter travels
    // in the path. `dotnet restore` is configured with a `--source` URL and sends no credentials to
    // it, so a moment carried in userinfo would be dropped exactly as npm drops it on a tarball
    // request — the failure `moment.rs` records as its broken assumption.
    if let Some(rest) = path_now.strip_prefix("/-nuget/") {
        // The authority the client reached us on, so the documents we serve point back at the same
        // place. Taken from the request rather than from configuration: the mirror is addressed by
        // a container alias inside the network island (`timewarp:PORT`) and by `127.0.0.1` from the
        // host, and a document that named the wrong one would resolve for one caller and not the
        // other.
        let via = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        return nuget_route(mirror, rest, &path_now, &via).await;
    }

    // Cargo, before the auth check for the reason NuGet is: the moment travels in the path.
    // A sparse registry is configured as a bare URL in `config.toml` and Cargo sends no
    // credentials to it, so a moment in userinfo would be dropped exactly as npm drops it on a
    // tarball request.
    if let Some(rest) = path_now.strip_prefix("/-cargo/") {
        let via = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        return cargo_route(mirror, rest, &path_now, &via).await;
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
        // **Named rather than waved through.** This match is reached only by a request whose
        // filter came out of *credentials*, and NuGet's never does: `dotnet restore` is handed a
        // `--source` URL and sends no userinfo with it, so the moment travels in the path and
        // `/-nuget/` is answered before the auth check. A NuGet filter arriving here means
        // something built one from credentials, which is a bug rather than a request to serve.
        // Cargo lands here for the same reason, and is refused for the same reason: a sparse
        // registry is a bare URL in `config.toml` that Cargo sends no credentials to, so its
        // moment travels in the path and `/-cargo/` is answered before the auth check.
        Platform::NuGet | Platform::Cargo => Err(MirrorError::NoFilter),
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

    mirror.seen.note_moment(&filter.moment);
    let (body, _) = fetch_index(mirror, &url, filter, &[]).await?;
    let mut doc: serde_json::Value = serde_json::from_slice(&body).map_err(upstream_json("npm"))?;
    let removed = crate::npm::filter_packument(&mut doc, &filter.moment);
    let withheld = match mirror.guard.withheld() {
        Some(w) => crate::npm::withhold_version(&mut doc, w),
        None => 0,
    };
    rewrite_npm_tarballs(&mut doc, &authority(filter, host), &mirror.seen);

    mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
    mirror
        .stats
        .versions_withheld
        .fetch_add(removed as u64, Ordering::Relaxed);
    tracing::debug!(
        path,
        moment = filter.moment,
        removed,
        withheld,
        "filtered a packument"
    );
    if withheld > 0 {
        tracing::info!(
            path,
            "the version under test was withheld from this index, so a resolver picks another \
             rather than being offered one it will then be refused"
        );
    }

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
    let (body, _) = fetch_index(
        mirror,
        &url,
        filter,
        &[(header::ACCEPT, "application/vnd.pypi.simple.v1+json")],
    )
    .await?;
    let mut doc: serde_json::Value =
        serde_json::from_slice(&body).map_err(upstream_json("pypi"))?;
    let removed = crate::pypi::filter_simple(&mut doc, &filter.moment);
    let withheld = match mirror.guard.withheld() {
        Some(w) => crate::pypi::withhold_version(&mut doc, w),
        None => 0,
    };
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
        withheld,
        "filtered a simple index"
    );
    if withheld > 0 {
        tracing::info!(
            path,
            "the version under test was withheld from this index, so a resolver picks another \
             rather than being offered one it will then be refused"
        );
    }

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

/// How many times a 429 is waited out before the build is told the host refused.
///
/// Small: the build is blocked on this request, and a mirror that silently waits five minutes is
/// indistinguishable from a hang. Past this the refusal is reported, and `Fault::Upstream` keeps it
/// off the package's record.
const MAX_THROTTLE_RETRIES: u32 = 2;

/// One outbound request: paced, counted, and willing to wait when a host asks it to.
///
/// **Every byte a build fetches at an enforced tier goes through here**, and until now none of it
/// was paced, counted or backed off. A 186-run npm sweep put 143,362 requests through this
/// function's callers, which is the measurement in `docs/20-m4-plan.md` §2 — so this is the route
/// the rate limiting was missing from, while the careful client sat on the metadata route.
///
/// Takes a builder rather than a request because a retry needs a second one, and a `RequestBuilder`
/// is consumed by `send`.
async fn outbound(
    url: &str,
    route: politeness::Route,
    build: impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, MirrorError> {
    let host = politeness::host_of(url);
    let mut attempt = 0;
    loop {
        // Waits out a backoff another lane earned, too: `throttled` below pushes this host's slot
        // out for the whole process, and this is where that is paid.
        politeness::pace(&host, route).await;
        politeness::note_request(&host);
        // One line per request that actually goes on the wire, including a retry and each hop of a
        // redirect: the host is counting what upstream saw, not what we intended.
        crate::guard::Asked {
            host: host.clone(),
            cached: false,
            index_fetched_at: None,
        }
        .emit();
        let resp = match build().send().await {
            Ok(r) => r,
            Err(e) => {
                politeness::note_failure(&host);
                return Err(e.into());
            }
        };
        if resp.status().as_u16() != 429 {
            return Ok(resp);
        }
        // What the server asked for. Guessing our own backoff against a host that told us what it
        // wanted is how throttling becomes a ban.
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(std::time::Duration::from_secs);
        politeness::throttled(&host, retry_after);
        let gave_up = attempt >= MAX_THROTTLE_RETRIES;
        // Out through the log, where the host process can read it. The counter this just bumped
        // dies with the container.
        crate::guard::Throttled {
            host: host.clone(),
            retry_after_s: retry_after.map(|d| d.as_secs()),
            gave_up,
        }
        .emit();
        if gave_up {
            politeness::note_failure(&host);
            tracing::warn!(url, "upstream is still rate limiting; giving up");
            return Ok(resp);
        }
        tracing::warn!(url, attempt, ?retry_after, "rate limited; waiting");
        attempt += 1;
    }
}

/// A document upstream sent that we cannot parse. Theirs, and a 502, the way a bad body always was
/// when `reqwest` did the parsing.
fn upstream_json(platform: &'static str) -> impl Fn(serde_json::Error) -> MirrorError {
    move |e| {
        tracing::warn!("{platform} sent an index document that will not parse: {e}");
        MirrorError::Upstream {
            platform: platform.into(),
            status: 502,
        }
    }
}

/// An upstream index document, from disk where we have it and from the network otherwise.
///
/// **The bytes are cached; the decision never is.** What comes back here is the document as the
/// registry published it, and the time filter runs on it afterwards on every request — so a cached
/// document resolved at a different moment still gets that moment's filter. The cache supplies
/// bytes, never an answer.
///
/// The second return says whether the bytes came from disk. `Cache::get` already emits the marker
/// the host counts, so nothing has to thread this through the response helpers — it is here for a
/// caller that wants to log or branch on it, and every caller today ignores it.
async fn fetch_index(
    mirror: &Mirror,
    url: &str,
    filter: &Filter,
    headers: &[(header::HeaderName, &str)],
) -> Result<(Vec<u8>, bool), MirrorError> {
    if let Some(cache) = &mirror.cache
        && let Some(entry) = cache.get(crate::Tier::Index, url)
    {
        tracing::debug!(url, fetched_at = entry.fetched_at, "index from cache");
        return Ok((entry.body, true));
    }
    // An index document: assembled per request and the expensive kind for a registry to serve.
    let resp = outbound(url, politeness::Route::Index, || {
        let mut req = mirror.client.get(url);
        for (k, v) in headers {
            req = req.header(k, *v);
        }
        req
    })
    .await?;
    // The client follows redirects itself, and hands back only the ones it could not: no
    // `Location`, or one it cannot resolve. Answered as `proxy` answers them, and for its reason.
    if resp.status().is_redirection() {
        return Err(unfollowed(&resp));
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
        .unwrap_or("application/json")
        .to_string();
    let body = resp.bytes().await?.to_vec();
    if let Some(cache) = &mirror.cache {
        cache.note_miss();
        // Best effort. A cache that cannot be written is a slower sweep, never a wrong one, so a
        // failure here is logged and the body is served.
        if let Err(e) = cache.put(
            crate::Tier::Index,
            url,
            &body,
            &content_type,
            crate::now_unix(),
        ) {
            tracing::warn!(url, "could not cache an index document: {e}");
        }
    }
    Ok((body, false))
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
/// A NuGet V3 feed, filtered to a moment.
///
/// Addressed as `/-nuget/{moment}/...` so every request says what it is filtered to, the way
/// `/-artifact/{platform}/{moment}/...` does. Three shapes:
///
/// * `{moment}/index.json` — the service index, pointing the client back here.
/// * `{moment}/reg/{id}/index.json` — the registration, filtered. **Every page resolved and
///   inlined**, so the client never holds a URL this mirror would have to serve separately and a
///   remote page cannot slip past the filter unread.
/// * `{moment}/flat/{id}/index.json` — the version list, *derived* from the filtered registration.
/// * `{moment}/flat/{id}/{version}/{file}` — the `.nupkg`, proxied under the guard.
async fn nuget_route(
    mirror: &Mirror,
    rest: &str,
    path: &str,
    via: &str,
) -> Result<Response, MirrorError> {
    let (raw, tail) = rest.split_once('/').ok_or(MirrorError::NoFilter)?;
    if raw.is_empty() {
        return Err(MirrorError::NoFilter);
    }
    // **Normalized, for the reason the Cargo route gives.** A moment in the path has been through
    // nothing, and `published_by` normalizes the timestamp it compares and not the moment — so
    // `yesterday` was a moment every registry timestamp sorts before, and the registration came
    // back with every version in it under a URL claiming a filter. Refused instead, as
    // `normalize` refuses on every other route.
    let moment = &crate::moment::normalize(raw)?;
    let filter = Filter {
        platform: Platform::NuGet,
        moment: moment.clone(),
    };
    // The authority this mirror is reachable at, so the documents it serves point back at it —
    // with the moment normalized, as the Cargo and artifact routes write it, so every URL served
    // and every transcript row names the moment the filter applied rather than the client's
    // spelling of it: an offset or a fraction `normalize` drops is not in them. A client follows
    // an `@id` as written and never compares it with the URL it first asked for.
    let base = format!("http://{via}/-nuget/{moment}");

    if tail == "index.json" {
        mirror.seen.note_moment(moment);
        mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
        // Through `json_response`, not `axum::Json`: it transcribes the exact bytes served as an
        // `index` exchange. A counter alone is invisible to the pin evidence, which is built from
        // the transcript — the first working run reported `it was contacted but served no index
        // document` while having served three, because the route bumped a counter and recorded
        // nothing.
        return Ok(json_response(
            &mirror.seen,
            &format!("{base}/index.json"),
            &crate::nuget::service_index(&base),
            "application/json",
            0,
        ));
    }

    if let Some(p) = tail.strip_prefix("reg/") {
        let id = p
            .strip_suffix("/index.json")
            .ok_or_else(|| MirrorError::NotFound {
                path: path.to_string(),
            })?;
        let (pages, removed, withheld) = nuget_pages(mirror, id, &filter, &base).await?;
        mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
        mirror
            .stats
            .versions_withheld
            .fetch_add(removed as u64, Ordering::Relaxed);
        tracing::debug!(id, moment, removed, withheld, "filtered a registration");
        let count: usize = pages
            .iter()
            .map(|p| p.get("items").and_then(Value::as_array).map_or(0, Vec::len))
            .sum();
        let url = format!("{base}/reg/{}/index.json", crate::nuget::normalized(id));
        return Ok(json_response(
            &mirror.seen,
            &url,
            &serde_json::json!({
                "@id": url,
                "count": pages.len(),
                "totalVersions": count,
                "items": pages,
            }),
            "application/json",
            removed as u64,
        ));
    }

    if let Some(p) = tail.strip_prefix("flat/") {
        // `{id}/index.json` is the version list; anything else is a file to proxy.
        if let Some(id) = p.strip_suffix("/index.json") {
            let (pages, removed, _) = nuget_pages(mirror, id, &filter, &base).await?;
            mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
            mirror
                .stats
                .versions_withheld
                .fetch_add(removed as u64, Ordering::Relaxed);
            // **Derived, never proxied.** The upstream version list carries no dates, so a mirror
            // that forwarded it would answer with every version and report that it had filtered.
            return Ok(json_response(
                &mirror.seen,
                &format!("{base}/flat/{}/index.json", crate::nuget::normalized(id)),
                &serde_json::json!({ "versions": crate::nuget::versions(&pages) }),
                "application/json",
                removed as u64,
            ));
        }
        // The bytes. Through `proxy`, so the guard hashes them and the target's own artifact is
        // refused exactly as it is on every other route.
        mirror
            .stats
            .passthrough_requests
            .fetch_add(1, Ordering::Relaxed);
        let url = format!("{}/{p}", crate::nuget::FLAT_BASE);
        return proxy(mirror, &url, &filter, "artifact").await;
    }

    Err(MirrorError::NotFound {
        path: path.to_string(),
    })
}

/// Every registration page for a package, resolved, filtered and pointed back at this mirror.
///
/// Returns the pages, how many leaves the moment removed, and how many the withheld target did.
///
/// **Remote pages are fetched here and nowhere else.** A registration index either carries its
/// leaves inline or carries an `@id` to fetch them from, and which one depends on how many versions
/// the package has: `newtonsoft.json` is wholly inline, `system.text.json` has three pages and none
/// of them are. Filtering only what arrived inline would pass every version of the second kind
/// through while reporting that it had filtered — so the fetch happens before the filter, and the
/// result is inlined so the client never asks for a page separately.
/// Serve the crates.io sparse index at `/-cargo/{moment}/...`, filtered to that instant.
///
/// Two documents and nothing else. `config.json` is generated here so `dl` points back at this
/// mirror; every other path is an index document fetched from `index.crates.io` and filtered by
/// `pubtime`. The index is **not proxied** — it is rebuilt — which is why `index.crates.io` is
/// absent from `ARTIFACT_HOSTS`: there is no route on which a build can ask us for it unfiltered.
async fn cargo_route(
    mirror: &Mirror,
    rest: &str,
    path: &str,
    via: &str,
) -> Result<Response, MirrorError> {
    let (moment, tail) = rest.split_once('/').ok_or(MirrorError::NoFilter)?;
    if moment.is_empty() || tail.is_empty() {
        return Err(MirrorError::NoFilter);
    }
    // **Normalized here, not taken as written.** A moment that arrives in credentials goes through
    // `Filter::from_authorization`, which normalizes it; one that arrives in the path has had
    // nothing done to it. `published_by` normalizes the *timestamp* it is comparing and not the
    // moment it compares against, so an un-normalized `...:04.251Z` would be compared against
    // normalized `...:04` — string comparison that happens to work in one direction and silently
    // shifts the boundary in the other. Refusing a moment we cannot parse is the same choice
    // `normalize` documents for every other route.
    let moment = &crate::moment::normalize(moment)?;
    let filter = Filter {
        platform: Platform::Cargo,
        moment: moment.clone(),
    };

    if tail == "config.json" {
        mirror.seen.note_moment(moment);
        mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
        let artifact_base = format!("http://{via}/-artifact/cargo/{moment}");
        return Ok(json_response(
            &mirror.seen,
            &format!("http://{via}/-cargo/{moment}/config.json"),
            &crate::cargo::config_json(&artifact_base),
            "application/json",
            0,
        ));
    }

    // Anything else is an index path. Cargo derives it from the crate name, so it is
    // `1/x`, `2/xy`, `3/x/xyz` or `ab/cd/abcdef` and never contains `..` — but the check is on the
    // path we are about to build rather than on that reasoning, because the reasoning is about
    // Cargo and the request is from whatever is on the other end of the socket.
    if tail.contains("..") || tail.starts_with('/') {
        return Err(MirrorError::NotFound {
            path: path.to_string(),
        });
    }
    mirror.seen.note_moment(moment);
    let url = format!("{}/{tail}", crate::cargo::INDEX_BASE);
    let (raw, _) = fetch_index(mirror, &url, &filter, &[]).await?;
    let body = String::from_utf8_lossy(&raw).into_owned();
    let (filtered, withheld, unyanked) = crate::cargo::filter_index(&body, moment);
    mirror.stats.index_requests.fetch_add(1, Ordering::Relaxed);
    mirror
        .stats
        .versions_withheld
        .fetch_add(withheld, Ordering::Relaxed);
    tracing::debug!(
        tail,
        moment,
        withheld,
        unyanked,
        "filtered a crates.io index document"
    );

    // Every version postdates the pin, so at that moment the crate did not exist. A 404 is what
    // Cargo already reports well; an empty 200 is a document claiming the crate exists with no
    // versions, which surfaces several layers from the cause.
    if crate::cargo::is_empty(&filtered) {
        return Err(MirrorError::NotFound {
            path: path.to_string(),
        });
    }

    let served = format!("http://{via}/-cargo/{moment}/{tail}");
    Ok(text_response(
        &mirror.seen,
        &served,
        filtered.into_bytes(),
        "text/plain; charset=utf-8",
        withheld,
    ))
}

async fn nuget_pages(
    mirror: &Mirror,
    id: &str,
    filter: &Filter,
    base: &str,
) -> Result<(Vec<Value>, usize, usize), MirrorError> {
    let id = crate::nuget::normalized(id);
    mirror.seen.note_moment(&filter.moment);
    let url = format!("{}/{id}/index.json", crate::nuget::REGISTRATION_BASE);
    let (body, _) = fetch_index(mirror, &url, filter, &[]).await?;
    let index: Value = serde_json::from_slice(&body).map_err(upstream_json("nuget"))?;

    let mut pages: Vec<Value> = index
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let (mut removed, mut withheld) = (0usize, 0usize);
    for page in pages.iter_mut() {
        if !crate::nuget::page_is_inline(page)
            && let Some(u) = crate::nuget::page_url(page)
        {
            // Only upstream's own registration base. A page `@id` pointing anywhere else is a
            // document we do not understand, and following it would make this route a proxy to
            // whatever a feed chose to name.
            let u = u.to_string();
            if u.starts_with(crate::nuget::REGISTRATION_BASE) {
                match fetch_index(mirror, &u, filter, &[]).await {
                    Ok((page_body, _)) => match serde_json::from_slice::<Value>(&page_body) {
                        Ok(full) => *page = full,
                        Err(e) => {
                            return Err(MirrorError::Upstream {
                                platform: "nuget".into(),
                                status: 502,
                            })
                            .inspect_err(|_| tracing::warn!("registration page {u}: {e}"));
                        }
                    },
                    Err(e) => return Err(e),
                }
            }
        }
        // A page that is still not inline after that resolved to nothing we can read. Refused
        // rather than served empty: an empty page is indistinguishable from a filtered one, and
        // this route's whole job is to be distinguishable.
        if !crate::nuget::page_is_inline(page) {
            return Err(MirrorError::Upstream {
                platform: "nuget".into(),
                status: 502,
            });
        }
        removed += crate::nuget::filter_page(page, &filter.moment);
        if let Some(w) = mirror.guard.withheld() {
            withheld += crate::nuget::withhold_version(page, w);
        }
        crate::nuget::rewrite_urls(page, base);
    }
    if withheld > 0 {
        tracing::info!(
            id,
            "the version under test was withheld from this registration, so a resolver picks \
             another rather than being offered one it will then be refused"
        );
    }
    Ok((pages, removed, withheld))
}

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
/// Whether a path is npm's tarball shape: `/{name}/-/{file}.tgz`, scoped or not.
///
/// `/-/` is npm's own separator between a package name and its tarballs and appears in no other
/// route here — a packument is `/{name}` or `/@scope%2fname`, neither of which contains it. Both the
/// separator and the extension are required, so a package that merely has `-` in its name does not
/// match.
fn is_npm_tarball(path: &str) -> bool {
    path.contains("/-/") && path.ends_with(".tgz")
}

/// The package and version a bare npm tarball path names.
///
/// `/yocto-queue/-/yocto-queue-0.1.0.tgz` is `("yocto-queue", "0.1.0")`, and
/// `/@babel/core/-/core-7.28.5.tgz` is `("@babel/core", "7.28.5")` — the filename repeats only the
/// *last* segment of a scoped name, which is why the version cannot be taken by trimming the whole
/// package name off the front.
fn npm_tarball_coords(path: &str) -> Option<(String, String)> {
    let (name, file) = path.trim_start_matches('/').split_once("/-/")?;
    let stem = file.strip_suffix(".tgz")?;
    let last = name.rsplit('/').next()?;
    let version = stem.strip_prefix(last)?.strip_prefix('-')?;
    (!name.is_empty() && !version.is_empty()).then(|| (name.to_string(), version.to_string()))
}

/// Whether the filtered index would have offered this exact tarball.
///
/// Fetches the packument, applies the same time filter and the same withhold the index route
/// applies, and asks whether the version is still there. A version published after the pinned
/// moment is not, and neither is the artifact under test — so the two properties this route must
/// not lose are decided by the same code that decides them everywhere else, rather than by a second
/// implementation that can drift.
///
/// Answering `false` on any failure to ask: an upstream that will not tell us is not permission.
async fn filtered_index_offers(mirror: &Mirror, path: &str) -> bool {
    let Some((name, version)) = npm_tarball_coords(path) else {
        return false;
    };
    // No index request has been filtered yet, so there is no moment to filter against and this
    // route must not become a way to fetch anything at all.
    let Some(moment) = mirror.seen.moment() else {
        tracing::info!(%name, "refused: nothing has pinned a moment in this run yet");
        return false;
    };
    let filter = Filter {
        platform: Platform::Npm,
        moment,
    };
    let url = format!("{}/{name}", Platform::Npm.upstream());
    let Ok((body, _cached)) = fetch_index(mirror, &url, &filter, &[]).await else {
        tracing::debug!(%name, "could not ask the index about a lockfile tarball");
        return false;
    };
    let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return false;
    };
    crate::npm::filter_packument(&mut doc, &filter.moment);
    if let Some(w) = mirror.guard.withheld() {
        crate::npm::withhold_version(&mut doc, w);
    }
    let offers = doc
        .get("versions")
        .and_then(|v| v.as_object())
        .is_some_and(|v| v.contains_key(&version));
    match offers {
        // Remembered, so a repeat costs no upstream round trip and the account of what this mirror
        // offered stays complete.
        true => mirror.seen.offer(path),
        false => tracing::info!(
            %name, %version,
            "refused: the index at this moment does not offer that version"
        ),
    }
    offers
}

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
fn rewrite_npm_tarballs(doc: &mut serde_json::Value, host: &str, seen: &Seen) {
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
            // What npm will ask for if it re-bases this onto the registry root instead of using the
            // URL below — everything after the upstream host. Remembered so the bare-tarball route
            // can serve exactly what this filtered document offered and refuse anything else.
            if let Some(slash) = rest.find('/') {
                seen.offer(&rest[slash..]);
            }
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

    // **After the guard, never before it.** An artifact this run is trying to reproduce must be
    // refused whether or not we happen to have it on disk — a cache that answered first would turn
    // the one control that separates a verdict from a tautology into a control on cold requests.
    //
    // Only the immutable routes. `passthrough` is whatever an index host served that no filter
    // applied to, which is not something to keep and call permanent.
    if let (Some(cache), true) = (&mirror.cache, matches!(route, "artifact" | "toolchain"))
        && let Some(entry) = cache.get(crate::Tier::Bytes, url)
    {
        // Through the same hashing stream as the network path, so the transcript row, the digest
        // and everything the guard does are byte for byte what they would have been. The cache
        // supplies bytes and changes nothing else about the evidence.
        let body = entry.body;
        let stream = guarded_stream(
            futures::stream::iter([Ok(bytes::Bytes::from(body))]),
            mirror.guard.clone(),
            mirror.seen.clone(),
            url.to_string(),
            route,
        );
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, entry.content_type)],
            Body::from_stream(stream),
        )
            .into_response());
    }
    if let (Some(cache), true) = (&mirror.cache, matches!(route, "artifact" | "toolchain")) {
        cache.note_miss();
    }

    // Whatever the proxy is carrying. `artifact` and `toolchain` are immutable objects at
    // immutable URLs; `passthrough` is something on an index host that no filter applied to, which
    // is closer to an index than to a tarball and is paced as one.
    let kind = match route {
        "artifact" | "toolchain" => politeness::Route::Bytes,
        _ => politeness::Route::Index,
    };
    let resp = outbound(url, kind, || mirror.passthrough.get(url)).await?;
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
        // Each hop is its own request to its own host, so each one is paced and counted against
        // that host rather than against the one that redirected us.
        resp = outbound(next.as_str(), kind, || mirror.passthrough.get(next.clone())).await?;
    }
    // **A redirect the loop did not follow is not an answer.** It ends holding one when upstream
    // names nowhere to go, or is still redirecting after the last hop, and this used to hand that
    // on as a bare 3xx. The build cannot follow it any more than it could the others, and pip and
    // npm do not take a 3xx for a failure: they read the refusal text as the document or the
    // tarball and fail further on, over something else — where a 502 is a failure they retry.
    if resp.status().is_redirection() {
        return Err(unfollowed(&resp));
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
    // The guard hashes as the bytes go past rather than holding them, and the cache is filled the
    // same way — a temporary file that is renamed into place only if the body reaches its end, so a
    // download the client abandons leaves nothing a later read could mistake for a whole one.
    //
    // **Content-encoded bodies are not cached.** What goes past here is undecoded, and the entry
    // would have to carry the encoding to be replayable; serving a `Content-Encoding: gzip` body
    // without that header is the corruption this proxy already learned about the hard way.
    let writer = match (&mirror.cache, matches!(route, "artifact" | "toolchain")) {
        (Some(cache), true) if content_encoding.is_none() => cache.writer(crate::Tier::Bytes, url),
        _ => None,
    };
    let stream = guarded_stream(
        resp.bytes_stream(),
        mirror.guard.clone(),
        mirror.seen.clone(),
        url.to_string(),
        route,
    );
    // Boxed because `unfold` produces a stream that is not `Unpin` and this one polls it by
    // reference. One allocation per response, against a body that is measured in megabytes.
    let stream = caching_stream(
        Box::pin(stream),
        writer,
        content_type.clone(),
        mirror.cache.clone(),
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

/// A redirect upstream answered that this mirror did not follow, named by its `Location` or by
/// the want of one.
fn unfollowed(resp: &reqwest::Response) -> MirrorError {
    MirrorError::BadRedirect {
        found: resp
            .headers()
            .get(header::LOCATION)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_else(|| "no Location header".into()),
    }
}

/// Fill a cache entry from a body as it passes, completing it only where the body completes.
///
/// A separate wrapper rather than another job for `guarded_stream`, which already hashes, guards,
/// transcribes and tracks whether the body finished. The one rule this has to keep is the same one:
/// a partial body must never become a whole entry, so the rename happens in the `None` arm and
/// nowhere else, and the writer's `Drop` removes the temporary file on every other path.
fn caching_stream<S>(
    inner: S,
    writer: Option<crate::cache::CacheWriter>,
    content_type: String,
    cache: Option<Arc<crate::cache::Cache>>,
) -> impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>
where
    S: futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    struct State<S> {
        inner: S,
        writer: Option<crate::cache::CacheWriter>,
        content_type: String,
        cache: Option<Arc<crate::cache::Cache>>,
    }
    futures::stream::unfold(
        Some(State {
            inner,
            writer,
            content_type,
            cache,
        }),
        |s| async move {
            let mut s = s?;
            match futures::StreamExt::next(&mut s.inner).await {
                Some(Ok(chunk)) => {
                    if let Some(w) = &mut s.writer {
                        w.write(&chunk);
                    }
                    Some((Ok(chunk), Some(s)))
                }
                // Mid-stream error: the entry is abandoned by dropping the writer, which removes its
                // temporary file. Half an artifact under a whole artifact's URL is the one thing this
                // must never leave behind.
                Some(Err(e)) => Some((Err(e), None)),
                None => {
                    if let Some(w) = s.writer.take()
                        && w.finish(&s.content_type, crate::now_unix())
                        && let Some(c) = &s.cache
                    {
                        c.note_write();
                    }
                    None
                }
            }
        },
    )
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
/// Serve a body this mirror composed, as text rather than JSON.
///
/// The sparse index is newline-delimited JSON, which is not a JSON document — round-tripping it
/// through `serde_json::Value` would reorder keys and reserialize numbers, changing bytes Cargo
/// checksums nothing about but that this mirror transcribes. It goes out as it was assembled.
fn text_response(
    seen: &Seen,
    url: &str,
    body: Vec<u8>,
    content_type: &'static str,
    withheld: u64,
) -> Response {
    transcribe_generated(seen, url, &body, withheld);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    (StatusCode::OK, headers, Body::from(body)).into_response()
}

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
        // io.js, which served majors 1 to 3 before the merge. Without this the toolchain route
        // refuses the only host those versions were ever published from, and the refusal reads as
        // the mirror being broken rather than as a host nobody added.
        assert!(host_allowed("toolchain", "iojs.org"));
        // And it is a toolchain host, not an artifact one: the lists do not bleed.
        assert!(!host_allowed("artifact", "iojs.org"));

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

#[cfg(test)]
mod npm_tarball_route_tests {
    use super::is_npm_tarball;

    #[test]
    fn the_shape_npm_actually_asks_for_is_recognised() {
        // The exact URL from the M1 corpus run, minus the host.
        assert!(is_npm_tarball("/yocto-queue/-/yocto-queue-0.1.0.tgz"));
        assert!(is_npm_tarball("/@babel/core/-/core-7.28.5.tgz"));
    }

    #[test]
    fn the_shape_alone_does_not_open_the_route() {
        // The shape test says what *could* be served; `Seen::was_offered` says what *is*. Both are
        // required, and this is the half that keeps the pin meaningful: a tarball nobody was
        // offered — a version published after the moment, say — matches the shape and is still
        // refused.
        let seen = super::Seen::default();
        assert!(!seen.was_offered("/left-pad/-/left-pad-1.3.0.tgz"));
        seen.offer("/left-pad/-/left-pad-1.3.0.tgz");
        assert!(seen.was_offered("/left-pad/-/left-pad-1.3.0.tgz"));
        assert!(
            !seen.was_offered("/left-pad/-/left-pad-99.0.0.tgz"),
            "a different version of an offered package is still not offered"
        );
    }

    #[test]
    fn a_packument_is_not_a_tarball() {
        // The routes must not overlap: a packument has to keep reaching the filtered path, or the
        // registry pin stops applying and every floating range resolves against today.
        assert!(!is_npm_tarball("/yocto-queue"));
        assert!(!is_npm_tarball("/@babel%2fcore"));
        assert!(!is_npm_tarball("/simple/packaging/"));
        // A name containing the separator's characters is not the separator.
        assert!(!is_npm_tarball("/some-package-name"));
        // Both halves are required.
        assert!(!is_npm_tarball("/yocto-queue/-/yocto-queue-0.1.0.tar.gz"));
        assert!(!is_npm_tarball("/yocto-queue-0.1.0.tgz"));
    }
}

#[cfg(test)]
mod lockfile_tarball_tests {
    use super::npm_tarball_coords;

    #[test]
    fn a_bare_tarball_path_names_its_package_and_version() {
        // The shape npm composes for itself when it resolves from a lockfile: it reads `resolved`
        // out of `package-lock.json`, re-bases the path onto the configured registry, and drops the
        // credentials — so nothing about the request says which package or which moment.
        for (path, name, version) in [
            (
                "/yocto-queue/-/yocto-queue-0.1.0.tgz",
                "yocto-queue",
                "0.1.0",
            ),
            (
                "/xmlhttprequest-ssl/-/xmlhttprequest-ssl-2.1.1.tgz",
                "xmlhttprequest-ssl",
                "2.1.1",
            ),
            // A scoped name repeats only its *last* segment in the filename, so the version cannot
            // be taken by trimming the whole package name off the front.
            ("/@babel/core/-/core-7.28.5.tgz", "@babel/core", "7.28.5"),
            // Prereleases and build metadata are part of the version, not separators.
            ("/pkg/-/pkg-1.0.0-rc.1.tgz", "pkg", "1.0.0-rc.1"),
            // A name that itself contains a dash, which is most of them.
            (
                "/zod-to-json-schema/-/zod-to-json-schema-3.24.5.tgz",
                "zod-to-json-schema",
                "3.24.5",
            ),
        ] {
            assert_eq!(
                npm_tarball_coords(path),
                Some((name.to_string(), version.to_string())),
                "{path}"
            );
        }
    }

    #[test]
    fn anything_that_is_not_a_tarball_path_names_nothing() {
        // Refusing to parse is refusing to serve: `filtered_index_offers` answers `false` on `None`
        // rather than guessing a package name out of an unfamiliar shape.
        for path in [
            "/yocto-queue",            // a packument, not a tarball
            "/-/all",                  // no package name
            "/pkg/-/pkg-1.0.0.tar.gz", // not a .tgz
            "/pkg/-/other-1.0.0.tgz",  // the filename does not belong to the package
            "/pkg/-/pkg.tgz",          // no version
        ] {
            assert_eq!(npm_tarball_coords(path), None, "{path}");
        }
    }
}

#[cfg(test)]
mod outbound_politeness {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    /// An upstream that says 429 the first `refusals` times and then answers.
    ///
    /// Hand-rolled over a `TcpListener` because the thing under test is what our client does with
    /// a status and a header, and standing up a framework to produce three bytes of status line
    /// would put more code in the fixture than in the control.
    fn upstream_that_throttles(refusals: usize) -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut served = 0;
            for stream in listener.incoming().take(refusals + 1) {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let body = if served < refusals {
                    // One second, so the test waits a real interval rather than a guessed one.
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                };
                let _ = s.write_all(body.as_bytes());
                let _ = s.flush();
                served += 1;
            }
            served
        });
        (format!("http://127.0.0.1:{port}/thing"), handle)
    }

    #[tokio::test]
    async fn a_429_is_waited_out_rather_than_handed_to_the_build_as_a_failure() {
        // The mirror had no 429 path at all: a rate-limited registry became
        // `MirrorError::Upstream` and the build failed, on a run whose only problem was our own
        // request rate. The build cannot retry — it has no route out except this proxy — so
        // waiting is this process's job.
        let client = reqwest::Client::new();
        let (url, server) = upstream_that_throttles(2);

        let started = std::time::Instant::now();
        let resp = super::outbound(&url, trigon_politeness::Route::Index, || client.get(&url))
            .await
            .expect("the third attempt answers");

        assert_eq!(resp.status(), 200, "the wait should have been worth it");
        assert_eq!(server.join().unwrap(), 3, "two refusals and one answer");
        // Two `Retry-After: 1` waits. Honouring the header is the difference between being
        // throttled and being banned, so this asserts the delay happened rather than that the
        // status was read.
        assert!(
            started.elapsed() >= std::time::Duration::from_secs(2),
            "it answered in {:?}, which is faster than the two seconds upstream asked for",
            started.elapsed()
        );

        // And it is counted, on the route that carries the bytes. Three requests, because a
        // retried request is a request the host saw. Keyed by host *and port*: that is the
        // endpoint a rate limit applies to.
        let host = trigon_politeness::host_of(&url);
        let traffic = trigon_politeness::traffic();
        let t = traffic
            .get(&host)
            .unwrap_or_else(|| panic!("nothing counted for {host}: {traffic:?}"));
        assert_eq!(t.requests, 3, "{t:?}");
        assert_eq!(t.throttled, 2, "{t:?}");
        assert_eq!(t.failed, 0, "it answered in the end: {t:?}");
    }

    #[test]
    fn a_throttle_leaves_the_island_through_the_log() {
        // A counter cannot leave: the mirror runs inside the build's network namespace and the
        // host process has no route to it. The transcript cannot carry this either — it lists
        // bodies that crossed and a 429 has none — so without the marker a rate-limited run would
        // record `0 throttled`, which is the claim that nobody stopped us.
        let t = crate::guard::Throttled {
            host: "registry.npmjs.org".into(),
            retry_after_s: Some(30),
            gave_up: false,
        };
        let logs = format!("some build noise\n{}\nmore noise\n", t.line());
        assert_eq!(crate::guard::Throttled::parse_log(&logs).unwrap(), vec![t]);
        // And a log with none says none, rather than failing to parse.
        assert!(
            crate::guard::Throttled::parse_log("nothing here")
                .unwrap()
                .is_empty()
        );
    }
}

/// `proxy` against an upstream on loopback: every hop, every status, every way a body can end.
///
/// The routes that build a URL all name a real registry, so the served tests cannot reach these
/// paths without the network. `proxy` itself takes the URL it is given — the route has already
/// checked the first hop — so a loopback upstream exercises exactly the code a registry would, and
/// the allowlist on every *later* hop is the thing under test.
#[cfg(test)]
mod proxy_tests {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    use sha2::Digest as _;

    use super::{Filter, Mirror, MirrorError, Platform, proxy};

    /// An upstream that answers one connection per canned response, then stops listening, and
    /// hands back the request line of each connection it answered.
    ///
    /// Every response closes its connection, so a second request cannot quietly ride a pooled one:
    /// once the answers run out, asking again is a refused connection rather than a stale answer.
    fn upstream(responses: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut asked = Vec::new();
            for response in responses {
                let Ok((mut s, _)) = listener.accept() else {
                    break;
                };
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&head);
                asked.push(line.lines().next().unwrap_or_default().to_string());
                let _ = s.write_all(&response);
                let _ = s.flush();
            }
            asked
        });
        (base, handle)
    }

    fn answer(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
        for h in headers {
            out.push_str(h);
            out.push_str("\r\n");
        }
        if !headers.iter().any(|h| h.starts_with("Content-Length")) {
            out.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        out.push_str("\r\n");
        let mut out = out.into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn npm() -> Filter {
        Filter {
            platform: Platform::Npm,
            moment: String::new(),
        }
    }

    /// A mirror with a cache, built directly rather than through `with_cache` so this binary's
    /// rate limiter is not pointed at a directory the test is about to delete.
    fn caching(name: &str) -> (Mirror, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("trigon-proxy-cache-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cache = crate::cache::Cache::open(root.clone(), "scope".into()).unwrap();
        let m = Mirror {
            cache: Some(Arc::new(cache)),
            ..Mirror::new().unwrap()
        };
        (m, root)
    }

    async fn body(r: axum::response::Response) -> Result<Vec<u8>, axum::Error> {
        axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .map(|b| b.to_vec())
    }

    fn hex(bytes: &[u8]) -> String {
        format!("{:x}", sha2::Sha256::digest(bytes))
    }

    #[tokio::test]
    async fn a_redirect_off_the_routes_own_allowlist_is_refused_and_never_followed() {
        // The allowlist is the entire content of `mirror-only` on these routes, and it used to be
        // checked on the URL a build asked for and on nothing after it: reqwest followed up to five
        // hops on its own. An allowlisted host that answers `302 cdn.evil.example` then put
        // arbitrary bytes into a build that is supposed to have no route out.
        for (route, location, host) in [
            (
                "artifact",
                "https://cdn.evil.example/payload.tgz",
                "cdn.evil.example",
            ),
            // The lists do not bleed into each other, on a later hop any more than on the first.
            (
                "toolchain",
                "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "registry.npmjs.org",
            ),
            (
                "passthrough",
                "https://nodejs.org/dist/v20.0.0/node.tar.gz",
                "nodejs.org",
            ),
            // A relative `Location` is resolved against the URL that sent it and checked again, so
            // staying on the same host is no way round the list.
            ("artifact", "/elsewhere/payload.tgz", "127.0.0.1"),
        ] {
            let (base, asked) = upstream(vec![answer(
                "302 Found",
                &[&format!("Location: {location}")],
                b"",
            )]);
            let m = Mirror::new().unwrap();
            let e = proxy(&m, &format!("{base}/start"), &npm(), route)
                .await
                .expect_err("a redirect off the allowlist must not be followed");
            match &e {
                MirrorError::HostNotAllowed { host: h, route: r } => {
                    assert_eq!((h.as_str(), *r), (host, route), "{e}")
                }
                other => panic!("{route} -> {location}: {other:?}"),
            }
            assert_eq!(e.status(), 403);
            assert_eq!(asked.join().unwrap(), ["GET /start HTTP/1.1"], "{route}");
            assert!(
                m.seen.exchanges().is_empty(),
                "nothing crossed, so nothing is transcribed"
            );
        }
    }

    #[tokio::test]
    async fn a_redirect_to_somewhere_that_cannot_be_named_is_refused() {
        // A destination we cannot name is a destination we cannot put on an allowlist.
        let (base, asked) = upstream(vec![answer("301 Moved", &["Location: http://["], b"")]);
        let m = Mirror::new().unwrap();
        let e = proxy(&m, &format!("{base}/start"), &npm(), "artifact")
            .await
            .expect_err("an unresolvable Location");
        assert!(
            matches!(&e, MirrorError::BadRedirect { found } if found == "http://["),
            "{e:?}"
        );
        assert_eq!(e.status(), 502);
        assert_eq!(asked.join().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_redirect_that_names_nowhere_is_upstreams_failure_and_never_handed_on() {
        // The build cannot follow a redirect itself — at `mirror-only` the destination is a host it
        // has no route to — and a bare 3xx handed on is no failure to pip or npm: they read the
        // refusal text as the document or the tarball, and fail further on over something else.
        let (base, asked) = upstream(vec![answer("302 Found", &[], b"")]);
        let m = Mirror::new().unwrap();
        let e = proxy(&m, &format!("{base}/start"), &npm(), "artifact")
            .await
            .expect_err("a redirect with nowhere to go");
        assert!(
            matches!(&e, MirrorError::BadRedirect { found } if found == "no Location header"),
            "{e:?}"
        );
        assert_eq!(e.status(), 502);
        assert_eq!(
            trigon_core::Classify::fault(&e),
            trigon_core::Fault::Upstream
        );
        assert_eq!(asked.join().unwrap(), ["GET /start HTTP/1.1"]);
        assert!(m.seen.exchanges().is_empty(), "nothing crossed");
    }

    #[tokio::test]
    async fn a_redirect_still_going_after_the_last_hop_is_upstreams_failure() {
        // Every hop on an allowlisted host, so it is the hop limit that stops it and not the list.
        // The name is resolved here rather than by DNS, so nothing leaves this machine.
        let hops: Vec<Vec<u8>> = (1..=super::MAX_REDIRECTS + 1)
            .map(|n| answer("302 Found", &[&format!("Location: /hop{n}")], b""))
            .collect();
        let (base, asked) = upstream(hops);
        let port = base.rsplit(':').next().unwrap();
        let m = Mirror {
            passthrough: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .resolve("static.crates.io", ([127, 0, 0, 1], 0).into())
                .no_proxy()
                .build()
                .unwrap(),
            ..Mirror::new().unwrap()
        };
        let url = format!("http://static.crates.io:{port}/start");
        let e = proxy(&m, &url, &npm(), "artifact")
            .await
            .expect_err("a redirect that never arrives");
        let last = format!("/hop{}", super::MAX_REDIRECTS + 1);
        assert!(
            matches!(&e, MirrorError::BadRedirect { found } if *found == last),
            "{e:?}"
        );
        assert_eq!(e.status(), 502);
        let asked = asked.join().unwrap();
        assert_eq!(
            asked.len(),
            super::MAX_REDIRECTS + 1,
            "the first request and one per hop, and no hop past the last: {asked:?}"
        );
        assert!(m.seen.exchanges().is_empty(), "nothing crossed");
    }

    #[tokio::test]
    async fn an_index_redirect_the_client_could_not_follow_is_upstreams_failure() {
        // The index client follows redirects itself and hands back the ones it cannot: no
        // `Location`, or one it cannot resolve. Either is the same failure `proxy` answers.
        for (location, found) in [(None, "no Location header"), (Some("http://["), "http://[")] {
            let headers: Vec<String> = location
                .map(|l| format!("Location: {l}"))
                .into_iter()
                .collect();
            let headers: Vec<&str> = headers.iter().map(String::as_str).collect();
            let (base, asked) = upstream(vec![answer("302 Found", &headers, b"")]);
            let url = format!("{base}/demo-pkg");
            let (m, root) = caching("index-redirect");
            let e = super::fetch_index(&m, &url, &npm(), &[])
                .await
                .expect_err("a redirect is not a document");
            assert!(
                matches!(&e, MirrorError::BadRedirect { found: f } if f == found),
                "{location:?}: {e:?}"
            );
            assert_eq!(e.status(), 502);
            assert_eq!(asked.join().unwrap().len(), 1);
            assert!(
                m.cache
                    .as_ref()
                    .unwrap()
                    .get(crate::Tier::Index, &url)
                    .is_none()
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[tokio::test]
    async fn an_upstream_error_status_is_reported_as_upstreams_and_carries_its_status() {
        let (base, _) = upstream(vec![answer("404 Not Found", &[], b"no such tarball")]);
        let m = Mirror::new().unwrap();
        let e = proxy(&m, &format!("{base}/x.tgz"), &npm(), "artifact")
            .await
            .expect_err("a 404 is not a body to serve");
        assert!(
            matches!(&e, MirrorError::Upstream { platform, status: 404 } if platform == "npm"),
            "{e:?}"
        );
        assert_eq!(e.status(), 404);
        assert_eq!(
            trigon_core::Classify::fault(&e),
            trigon_core::Fault::Upstream,
            "the registry's answer, never the package's record"
        );
    }

    #[tokio::test]
    async fn a_host_that_cannot_be_reached_is_a_transport_failure_charged_upstream() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let url = format!("http://127.0.0.1:{port}/x.tgz");
        let m = Mirror::new().unwrap();
        let e = proxy(&m, &url, &npm(), "artifact")
            .await
            .expect_err("nothing is listening");
        assert!(matches!(e, MirrorError::Transport(_)), "{e:?}");
        assert_eq!(e.status(), 502);
        assert_eq!(
            trigon_core::Classify::fault(&e),
            trigon_core::Fault::Upstream
        );
        let t = trigon_politeness::traffic()
            .remove(&trigon_politeness::host_of(&url))
            .expect("the attempt is counted against the host");
        assert_eq!((t.requests, t.failed), (1, 1), "{t:?}");
    }

    #[tokio::test]
    async fn a_host_that_keeps_throttling_is_given_up_on_and_the_refusal_is_upstreams() {
        // Waited out twice, then reported: the build is blocked on this request, and a mirror that
        // waits for ever is indistinguishable from a hang.
        let throttle = answer("429 Too Many Requests", &["Retry-After: 0"], b"slow down");
        let (base, asked) = upstream(vec![throttle.clone(), throttle.clone(), throttle]);
        let url = format!("{base}/x.tgz");
        let m = Mirror::new().unwrap();
        let e = proxy(&m, &url, &npm(), "artifact")
            .await
            .expect_err("still throttled after every retry");
        assert!(
            matches!(e, MirrorError::Upstream { status: 429, .. }),
            "{e:?}"
        );
        assert_eq!(
            asked.join().unwrap().len(),
            3,
            "one request and two retries"
        );
        let t = trigon_politeness::traffic()
            .remove(&trigon_politeness::host_of(&url))
            .expect("counted");
        assert_eq!((t.requests, t.throttled, t.failed), (3, 3, 1), "{t:?}");
    }

    #[tokio::test]
    async fn a_body_is_streamed_through_hashed_and_transcribed_as_it_was_served() {
        let (base, _) = upstream(vec![answer(
            "200 OK",
            &["Content-Type: text/plain"],
            b"hello",
        )]);
        let url = format!("{base}/greeting.txt");
        let m = Mirror::new().unwrap();
        let r = proxy(&m, &url, &npm(), "toolchain").await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()[axum::http::header::CONTENT_TYPE], "text/plain");
        assert_eq!(body(r).await.unwrap(), b"hello");

        let rows = m.seen.exchanges();
        assert_eq!(rows.len(), 1, "{rows:?}");
        let row = &rows[0];
        assert_eq!(
            (row.route.as_str(), row.url.as_str()),
            ("toolchain", url.as_str())
        );
        assert_eq!(
            (row.sha256.as_str(), row.bytes),
            (hex(b"hello").as_str(), 5)
        );
        // No manifest on this mirror, and the row says so rather than claiming a check.
        assert_eq!(row.checked, crate::Checked::Unarmed);
    }

    #[tokio::test]
    async fn an_artifact_fetched_once_is_cached_and_the_second_request_asks_nobody() {
        // The offline twin of `a_second_request_for_one_artifact_asks_nobody`: the body streamed to
        // the client is also written, and the second request serves the same bytes from disk —
        // through the same hashing stream, so it is a transcript row either way.
        let (base, asked) = upstream(vec![answer(
            "200 OK",
            &["Content-Type: application/gzip"],
            b"tarball bytes",
        )]);
        let url = format!("{base}/pkg/-/pkg-1.0.0.tgz");
        let (m, root) = caching("second-asks-nobody");

        let first = proxy(&m, &url, &npm(), "artifact").await.unwrap();
        assert_eq!(body(first).await.unwrap(), b"tarball bytes");
        let second = proxy(&m, &url, &npm(), "artifact").await.unwrap();
        assert_eq!(
            second.headers()[axum::http::header::CONTENT_TYPE],
            "application/gzip",
            "the cached entry replays its content type"
        );
        assert_eq!(body(second).await.unwrap(), b"tarball bytes");

        assert_eq!(
            asked.join().unwrap().len(),
            1,
            "the second request went upstream"
        );
        let stats = m.cache_stats().unwrap();
        assert_eq!(
            (stats.hits, stats.misses, stats.written, stats.rejected),
            (1, 1, 1, 0),
            "{stats:?}"
        );
        let rows = m.seen.exchanges();
        assert_eq!(
            rows.len(),
            2,
            "a served body is a row whether or not we fetched it"
        );
        assert_eq!(rows[0].sha256, rows[1].sha256);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_content_encoded_body_is_forwarded_undecoded_with_its_encoding_and_never_cached() {
        // Decoded bytes are not the artifact: the guard would hash a transformed body, and a client
        // handed gzip without the header has no way to know. And an entry would have to carry the
        // encoding to be replayable, so none is written.
        let gz = b"\x1f\x8b\x08\x00 not really deflate".to_vec();
        let (base, _) = upstream(vec![answer(
            "200 OK",
            &[
                "Content-Type: application/octet-stream",
                "Content-Encoding: gzip",
            ],
            &gz,
        )]);
        let url = format!("{base}/pkg.tgz");
        let (m, root) = caching("encoded");

        let r = proxy(&m, &url, &npm(), "artifact").await.unwrap();
        assert_eq!(r.headers()[axum::http::header::CONTENT_ENCODING], "gzip");
        assert_eq!(
            body(r).await.unwrap(),
            gz,
            "the body was decoded on the way through"
        );
        assert_eq!(m.seen.exchanges()[0].sha256, hex(&gz));

        let cache = m.cache.as_ref().unwrap();
        assert_eq!(cache.stats().written, 0);
        assert!(cache.get(crate::Tier::Bytes, &url).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_passthrough_body_is_served_but_never_kept_as_permanent() {
        // `passthrough` is whatever an index host served that no filter applied to, which is not
        // something to keep and call immutable.
        let (base, _) = upstream(vec![answer("200 OK", &[], b"an index host's page")]);
        let url = format!("{base}/stats/");
        let (m, root) = caching("passthrough");

        let r = proxy(&m, &url, &npm(), "passthrough").await.unwrap();
        assert_eq!(body(r).await.unwrap(), b"an index host's page");
        let cache = m.cache.as_ref().unwrap();
        assert_eq!(
            cache.stats(),
            crate::CacheStats::default(),
            "the cache was touched"
        );
        assert!(cache.get(crate::Tier::Bytes, &url).is_none());
        assert_eq!(m.seen.exchanges()[0].route, "passthrough");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_index_fetched_from_upstream_is_cached_with_when_it_was_fetched() {
        // The bytes are cached and the decision never is, so what goes on disk is the document as
        // the registry sent it, with the instant it was fetched — and the next read asks nobody.
        let doc = br#"{"name":"demo","files":[]}"#;
        let (base, asked) = upstream(vec![answer(
            "200 OK",
            &["Content-Type: application/vnd.pypi.simple.v1+json"],
            doc,
        )]);
        let url = format!("{base}/simple/demo/");
        let (m, root) = caching("index");
        let pypi = Filter {
            platform: Platform::PyPI,
            moment: "2020-01-01T00:00:00".into(),
        };
        let accept = [(
            axum::http::header::ACCEPT,
            "application/vnd.pypi.simple.v1+json",
        )];
        let before = crate::now_unix();

        let (body, cached) = super::fetch_index(&m, &url, &pypi, &accept).await.unwrap();
        assert_eq!((body.as_slice(), cached), (&doc[..], false));
        let (again, cached) = super::fetch_index(&m, &url, &pypi, &accept).await.unwrap();
        assert_eq!((again.as_slice(), cached), (&doc[..], true));

        let asked = asked.join().unwrap();
        assert_eq!(
            asked,
            ["GET /simple/demo/ HTTP/1.1"],
            "the second read went upstream"
        );
        let cache = m.cache.as_ref().unwrap();
        let entry = cache.get(crate::Tier::Index, &url).expect("an index entry");
        assert_eq!(entry.content_type, "application/vnd.pypi.simple.v1+json");
        assert!(
            entry.fetched_at >= before,
            "{} < {before}",
            entry.fetched_at
        );
        let stats = cache.stats();
        assert_eq!((stats.misses, stats.written), (1, 1), "{stats:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn the_headers_an_index_request_needs_go_upstream_with_it() {
        // What this holds is `fetch_index`'s half: the headers its caller hands it reach upstream,
        // with our User-Agent beside them. That `pypi_request` hands it JSON's `Accept` whatever
        // the client asked for — the HTML form carries no upload times, so a mirror that fetched it
        // would pass every file through and quietly do nothing — is *not* held here or anywhere
        // offline: the route's upstream is compiled in, and the cache it could be served from is
        // keyed by URL alone, so no test without a network sees which `Accept` went out.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/simple/demo/", listener.local_addr().unwrap());
        let head = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut chunk).unwrap();
                head.extend_from_slice(&chunk[..n]);
            }
            let _ = s.write_all(&answer("200 OK", &[], b"{}"));
            String::from_utf8_lossy(&head).to_ascii_lowercase()
        });
        let m = Mirror::new().unwrap();
        let accept = [(
            axum::http::header::ACCEPT,
            "application/vnd.pypi.simple.v1+json",
        )];
        super::fetch_index(&m, &url, &npm(), &accept).await.unwrap();
        let head = head.join().unwrap();
        assert!(
            head.contains("accept: application/vnd.pypi.simple.v1+json"),
            "{head}"
        );
        assert!(
            head.contains("user-agent: trigon/"),
            "an anonymous crawler: {head}"
        );
    }

    #[tokio::test]
    async fn an_index_is_served_even_when_the_cache_cannot_keep_it() {
        // Best effort, by design: a cache that cannot be written is a slower sweep, never a wrong
        // one, and never a reason to refuse the build the document it asked for.
        let (base, _) = upstream(vec![answer("200 OK", &[], br#"{"name":"demo"}"#)]);
        let url = format!("{base}/demo");
        let (m, root) = caching("index-unwritable");
        std::fs::write(root.join("index"), b"a file where the tier directory goes").unwrap();

        let (body, cached) = super::fetch_index(&m, &url, &npm(), &[]).await.unwrap();
        assert_eq!(
            (body.as_slice(), cached),
            (&br#"{"name":"demo"}"#[..], false)
        );
        let stats = m.cache.as_ref().unwrap().stats();
        assert_eq!((stats.misses, stats.written), (1, 0), "{stats:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_index_upstream_will_not_serve_is_its_failure_and_is_not_cached() {
        let (base, _) = upstream(vec![answer("503 Service Unavailable", &[], b"down")]);
        let url = format!("{base}/demo-pkg");
        let (m, root) = caching("index-refused");
        let e = super::fetch_index(&m, &url, &npm(), &[])
            .await
            .expect_err("a 503 is not a document");
        assert!(
            matches!(&e, MirrorError::Upstream { platform, status: 503 } if platform == "npm"),
            "{e:?}"
        );
        assert!(
            m.cache
                .as_ref()
                .unwrap()
                .get(crate::Tier::Index, &url)
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_body_too_large_to_open_is_still_hashed_whole_and_says_it_was_not_opened() {
        // The member check is what catches the target's files inside something else, and the size
        // that suppresses it is chosen by the thing under test. So the skip is recorded, and the
        // whole-body hash — which never needed the bytes kept — still catches the artifact itself.
        const CHUNK: usize = 1 << 20;
        let chunks = crate::guard::MAX_DECOMPOSE_BYTES / CHUNK + 1;
        let block = vec![0x5a_u8; CHUNK];
        let whole = {
            let mut h = sha2::Sha256::new();
            for _ in 0..chunks {
                h.update(&block);
            }
            trigon_core::Digest::from_bytes(h.finalize().into())
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/huge.tgz", listener.local_addr().unwrap());
        let served = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut chunk = [0u8; 1024];
            let _ = s.read(&mut chunk);
            let head = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                chunks * CHUNK
            );
            s.write_all(head.as_bytes()).unwrap();
            for _ in 0..chunks {
                s.write_all(&block).unwrap();
            }
        });
        // Members to look for, so the stream starts out collecting the body.
        let m = Mirror {
            guard: Arc::new(crate::Guard::new(crate::GuardManifest {
                artifact: Some(whole),
                members: [trigon_core::Digest::from_bytes([3; 32])]
                    .into_iter()
                    .collect(),
                ..Default::default()
            })),
            ..Mirror::new().unwrap()
        };

        let r = proxy(&m, &url, &npm(), "artifact").await.unwrap();
        let mut stream = r.into_body().into_data_stream();
        let mut total = 0;
        while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
            total += chunk.unwrap().len();
        }
        served.join().unwrap();
        assert_eq!(total, chunks * CHUNK);

        assert_eq!(m.guard.undecomposed(), std::slice::from_ref(&url));
        let trips = m.guard.trips();
        assert_eq!(trips.len(), 1, "{trips:?}");
        assert_eq!(trips[0].matched, crate::GuardMatch::WholeArtifact);
        let row = &m.seen.exchanges()[0];
        assert_eq!(row.checked, crate::Checked::Hashed, "{row:?}");
        assert_eq!(row.sha256, whole.to_hex());
    }

    #[tokio::test]
    async fn a_body_cut_short_is_transcribed_as_partial_and_never_cached_as_whole() {
        // Half an artifact under a whole artifact's URL and digest is the one line a reader must
        // never be handed — and the one entry a cache must never keep.
        let (base, _) = upstream(vec![answer(
            "200 OK",
            &["Content-Length: 100"],
            b"0123456789",
        )]);
        let url = format!("{base}/big.tgz");
        let (m, root) = caching("partial");

        let r = proxy(&m, &url, &npm(), "artifact").await.unwrap();
        assert!(body(r).await.is_err(), "the client must see the body fail");

        let rows = m.seen.exchanges();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].checked, crate::Checked::Partial, "{rows:?}");
        assert!(rows[0].bytes < 100, "recorded as whole: {rows:?}");
        assert_eq!(
            rows[0].sha256,
            hex(&b"0123456789"[..rows[0].bytes as usize]),
            "the digest is of the prefix that crossed"
        );

        let cache = m.cache.as_ref().unwrap();
        assert!(cache.get(crate::Tier::Bytes, &url).is_none());
        assert_eq!(cache.stats().written, 0);
        let leftovers: Vec<_> = std::fs::read_dir(root.join("tmp")).unwrap().collect();
        assert!(
            leftovers.is_empty(),
            "an abandoned write left {leftovers:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// What the mirror keeps in memory beside its counters, and where it stops keeping it.
#[cfg(test)]
mod seen_tests {
    use super::{MAX_RETAINED, Seen};

    #[test]
    fn past_the_cap_rows_are_counted_as_dropped_rather_than_silently_lost() {
        // A long-running `trigon mirror` would otherwise grow without limit. Passing the cap drops
        // rows, and it has to be visible as `truncated`, never as a smaller count — a transcript
        // that is a sample and says nothing reads as a build that fetched less.
        let seen = Seen::default();
        let row = || {
            crate::Exchange::new(
                "artifact",
                "https://x/y",
                String::new(),
                1,
                crate::Checked::Hashed,
            )
        };
        for _ in 0..MAX_RETAINED {
            seen.exchange(row());
        }
        assert_eq!(seen.truncated(), 0, "nothing is dropped up to the cap");
        seen.exchange(row());
        let refusal = || crate::Refusal {
            path: "/x".into(),
            status: 400,
            reason: "no filter".into(),
        };
        seen.refusal(refusal());
        assert_eq!(seen.exchanges().len(), MAX_RETAINED);
        assert_eq!(seen.refusals().len(), 1, "each list has its own cap");
        assert_eq!(seen.truncated(), 1);

        for _ in 1..MAX_RETAINED {
            seen.refusal(refusal());
        }
        assert_eq!(seen.truncated(), 1);
        seen.refusal(refusal());
        assert_eq!(seen.refusals().len(), MAX_RETAINED);
        assert_eq!(
            seen.truncated(),
            2,
            "a dropped refusal is counted like a dropped row"
        );
    }

    #[test]
    fn the_first_moment_a_run_pins_is_the_one_a_credential_less_request_uses() {
        // One mirror serves one build against one moment. A second moment is a bug worth seeing,
        // and quietly taking the latest would move the pin under a build halfway through it.
        let seen = Seen::default();
        seen.note_moment("");
        assert_eq!(seen.moment(), None, "an empty moment pins nothing");
        seen.note_moment("2020-01-01T00:00:00");
        seen.note_moment("2020-01-01T00:00:00");
        seen.note_moment("2024-06-01T00:00:00");
        assert_eq!(seen.moment().as_deref(), Some("2020-01-01T00:00:00"));
    }

    #[test]
    fn a_document_that_says_nothing_about_where_it_was_reached_keeps_its_upstream_urls() {
        // The authority is taken from how the client addressed us. With none, there is nothing to
        // rewrite onto, and a guessed one is a packument full of URLs that resolve to nothing — so
        // the document is left alone and nothing is recorded as offered.
        let seen = Seen::default();
        let npm = || {
            serde_json::json!({ "versions": { "1.0.0": { "dist": {
                "tarball": "https://registry.npmjs.org/a/-/a-1.0.0.tgz" } } } })
        };
        let mut doc = npm();
        super::rewrite_npm_tarballs(&mut doc, "", &seen);
        assert_eq!(doc, npm());
        assert!(!seen.was_offered("/a/-/a-1.0.0.tgz"));

        let pypi = || {
            serde_json::json!({
                "files": [{ "url": "https://files.pythonhosted.org/p/a.whl" }],
            })
        };
        let mut doc = pypi();
        super::rewrite_pypi_files(&mut doc, "");
        assert_eq!(doc, pypi());
    }

    #[test]
    fn only_absolute_artifact_urls_are_pointed_back_and_offered() {
        // A version with no tarball, or one that is not an absolute URL, has nothing to proxy to.
        // Offering it anyway would open the bare-tarball route to a path nobody filtered.
        let seen = Seen::default();
        let mut doc = serde_json::json!({ "versions": {
            "1.0.0": { "dist": { "tarball": "https://registry.npmjs.org/a/-/a-1.0.0.tgz" } },
            "1.1.0": { "dist": {} },
            "1.2.0": { "dist": { "tarball": "a-1.2.0.tgz" } },
            "1.3.0": {},
        } });
        super::rewrite_npm_tarballs(&mut doc, "mirror:8129/-artifact/npm/m", &seen);
        assert_eq!(
            doc["versions"]["1.0.0"]["dist"]["tarball"],
            "http://mirror:8129/-artifact/npm/m/registry.npmjs.org/a/-/a-1.0.0.tgz"
        );
        assert_eq!(doc["versions"]["1.2.0"]["dist"]["tarball"], "a-1.2.0.tgz");
        assert!(seen.was_offered("/a/-/a-1.0.0.tgz"));
        assert!(!seen.was_offered("a-1.2.0.tgz") && !seen.was_offered("/a-1.2.0.tgz"));

        let mut doc = serde_json::json!({ "files": [
            { "url": "https://files.pythonhosted.org/p/a-1.0.whl" },
            { "filename": "no-url.whl" },
            { "url": "relative/a-1.1.whl" },
        ] });
        super::rewrite_pypi_files(&mut doc, "mirror:8129/-artifact/pypi/m");
        assert_eq!(
            doc["files"][0]["url"],
            "http://mirror:8129/-artifact/pypi/m/files.pythonhosted.org/p/a-1.0.whl"
        );
        assert_eq!(doc["files"][2]["url"], "relative/a-1.1.whl");
        // And a document with no list at all is not given one.
        let mut empty = serde_json::json!({ "name": "a" });
        super::rewrite_pypi_files(&mut empty, "mirror:8129/-artifact/pypi/m");
        super::rewrite_npm_tarballs(&mut empty, "mirror:8129/-artifact/npm/m", &seen);
        assert_eq!(empty, serde_json::json!({ "name": "a" }));
    }
}
