//! The read path a decoupled front-end talks to.
//!
//! See [`docs/22-management-layer.md`] for why this exists and what it may never do. Two rules from
//! there are structural in this crate rather than aspirational:
//!
//! - **Nothing here produces a [`trigon_core::Match`].** There is no import of `trigon_stabilize`,
//!   no call to `trigon_compare::compare`, and no handler that writes an outcome. The API cannot
//!   express a verdict, so it cannot launder one. `xtask policy` asserts the absence.
//! - **Nothing anonymous returns a byte that was not class-gated first.** Build logs and network
//!   transcripts are unredacted — D14 is disclaimed and security-critical, and until this crate the
//!   only mitigation was that `trigon watch` binds to loopback. A public site is precisely the
//!   removal of that mitigation, so [`evidence`] is a precondition of the first public byte rather
//!   than a later stage.
//!
//! [`docs/22-management-layer.md`]: ../../../docs/22-management-layer.md

pub mod comparison;
pub mod evidence;
pub mod fleet;
pub mod index;
pub mod member;
pub mod network;
pub mod publication;
pub mod recover;
pub mod request;
pub mod routes;
pub mod serve;
pub mod ui;

pub use index::Index;
pub use publication::{Attempt, Confirmation, NotCold, Publication, Switches, Withheld};
pub use serve::{Config, run};

use std::sync::Arc;

/// Who is asking.
///
/// Two of the five principals `docs/22` §6 names, because the other three need an identity provider
/// and this crate has no write path to protect. The split that matters is already here: an
/// anonymous reader sees published verdicts and never bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    /// The public internet. Published verdicts, statements, digests and rollups.
    Anonymous,
    /// Whoever can reach the bind address. The local, loopback, operator case — the same trust
    /// model `trigon watch` has, and for the same reason: a work directory and a store both hold
    /// bytes that have not been redacted.
    Operator,
}

/// Turns two managed-assembly member byte-strings into their decompiled C#, or `None`.
///
/// **Injected, so this crate never mentions the decompiler.** ILSpy runs in a container, which is
/// the binary's world and not the serving layer's — so `trigon serve` hands this in and a
/// deployment without it (or without podman) simply serves the hex view, exactly as before. The
/// same rule the opinion path is under: a decompilation is a reading aid, never a verdict, and the
/// member route treats a `None` here as "no C# available", never as "the sources match".
pub type Decompiler =
    Arc<dyn Fn(&str, &[u8], &[u8]) -> Option<(String, String)> + Send + Sync>;

/// The evidence repository's kill-switch, as `trigon serve` reads it (`docs/19` §3).
///
/// **Beside `--stop-divergences`, never in place of it, and each stops only what it says.** The
/// repository's `kill-switch` file stops what `trigon publish` publishes; `serve`'s own switch
/// stops what this server shows. Neither is read as the other: a site whose repository switch is
/// set still shows what its own gate releases, and one whose own switch is set says so whatever
/// the repository's is.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RepositorySwitch {
    pub state: SwitchState,
    /// The repository `trigon publish` writes to, as configured. Shown to an operator only: a
    /// local path names a directory of the host's.
    pub repository: String,
    /// When what was read was fetched, RFC 3339; `None` where that is not known.
    pub as_of: Option<String>,
    /// How it was read, or why it could not be: shown to an operator only, for the same reason.
    pub detail: String,
}

/// What the evidence repository's kill-switch was found to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchState {
    /// The file is there: `trigon publish` publishes no divergence.
    Set,
    /// It is not.
    Clear,
    /// Nothing could be read — no working clone, or none that has fetched — which is never
    /// reported as clear.
    Unknown,
}

/// Reads the evidence repository's kill-switch.
///
/// **Injected, as the decompiler is**: the repository and the publisher's working clone are the
/// binary's to find, with `git`, and this crate only reports what it is handed. `Api` asks the
/// one it holds on every `/v1/health` and every page, so that one must answer at once: `serve`
/// wraps the binary's in [`cached_switch`], which reads it only off the request path.
pub type RepositorySwitchReader = Arc<dyn Fn() -> RepositorySwitch + Send + Sync>;

/// How often `serve` reads the evidence repository's kill-switch again. It changes only when
/// `trigon publish` fetches, hours or days apart, so a page this far behind it misses nothing.
pub const SWITCH_EVERY: std::time::Duration = std::time::Duration::from_secs(10);

/// `read`, asked off the request path: once now and then every `every`, each time on a blocking
/// thread, one read at a time. The reader returned hands every caller the last answer and asks
/// nothing itself, and the timer stops once it is dropped. Call it inside a tokio runtime.
///
/// **The binary's reader runs `git`**, several processes a read. Asked by each request, as
/// `/v1/health` and every page's first frame ask, a reader polling a `--public` server could fork
/// `git` at will and hold a runtime worker through each; and a spawn that failed under that load
/// is one more read that finds nothing.
pub async fn cached_switch(
    read: RepositorySwitchReader,
    every: std::time::Duration,
) -> RepositorySwitchReader {
    let last = Arc::new(std::sync::RwLock::new(ask(&read, None).await));
    let held = Arc::downgrade(&last);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let Some(last) = held.upgrade() else {
                return;
            };
            let before = last
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let now = ask(&read, Some(&before)).await;
            *last
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = now;
        }
    });
    Arc::new(move || {
        last.read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    })
}

/// One read of the switch, on a blocking thread. A reader that panicked has read nothing, which is
/// `unknown`, never the answer before it.
async fn ask(read: &RepositorySwitchReader, before: Option<&RepositorySwitch>) -> RepositorySwitch {
    let r = read.clone();
    tokio::task::spawn_blocking(move || r())
        .await
        .unwrap_or_else(|e| RepositorySwitch {
            state: SwitchState::Unknown,
            repository: before.map(|b| b.repository.clone()).unwrap_or_default(),
            as_of: None,
            detail: format!("reading it failed: {e}"),
        })
}

/// Everything a handler can reach.
pub struct Api {
    pub store: Arc<trigon_store::Store>,
    /// Decompiles a managed assembly to C# for the member view, where the binary supplied one.
    /// `None` on a reader with no such tool, and on every path but `trigon serve`.
    pub decompiler: Option<Decompiler>,
    /// The queue, where one is configured.
    ///
    /// `None` is a reader over a corpus in object storage and nothing else — the shape stage 1
    /// shipped, which needs no database at all. Every write route answers "this instance has no
    /// queue" rather than pretending, because an instance that silently accepted requests it could
    /// not queue would be worse than one that says so.
    pub queue: Option<trigon_store::Queue>,
    pub index: index::Index,
    pub switches: Switches,
    /// How many member reads may be in flight at once.
    ///
    /// **Peak memory for one member request is twice the artifact**, because both sides are fetched
    /// and parsed to compare one file inside them. Measured: 409 MiB for a 200 MiB-per-side
    /// artifact, and `MAX_ARTIFACT` allows 256 MiB — so an unbounded number of concurrent requests
    /// is an unbounded amount of memory, and the way that ends is the process being killed. Which
    /// is what a reader would report as the server crashing.
    ///
    /// Four, so the worst case is about two gigabytes rather than however many requests arrive. A
    /// request that waits is slow; a process that is killed takes everybody's page with it.
    pub member_reads: Arc<tokio::sync::Semaphore>,
    /// What an unauthenticated caller counts as.
    ///
    /// `Anonymous` is what `--public` selects and is the mode the class gating and the publication
    /// gate are written for. `Operator` is the default, because the default bind is loopback and a
    /// person reading their own store should not have to authenticate to themselves.
    pub unauthenticated: Principal,
    /// The evidence repository's kill-switch, where a publish repository is configured; `None`
    /// where none is.
    pub repository_switch: Option<RepositorySwitchReader>,
}

/// How many member reads may be in flight at once, by default.
///
/// Named rather than spelled `Semaphore::new(4)` at each construction, so the number that bounds
/// the server's peak memory is stated once and has somewhere to carry its reasoning — and so a test
/// building an `Api` gets the production bound rather than whatever it happened to type.
pub fn default_member_permits() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(4))
}

impl Api {
    pub fn principal(&self) -> Principal {
        self.unauthenticated
    }

    /// Both kill-switches, for `/v1/health` and the page it feeds: this server's own, and the
    /// evidence repository's, each with what it stops (`docs/19` §3). The repository's is `null`
    /// where no publish repository is configured, and `unknown`, never `clear`, where it could not
    /// be read; where it is and what was read are for an operator only.
    pub fn kill_switches(&self) -> serde_json::Value {
        let operator = self.principal() == Principal::Operator;
        let repository = self.repository_switch.as_ref().map(|read| {
            let r = read();
            let mut o = serde_json::json!({
                "state": r.state,
                "as_of": r.as_of,
                "stops": "what `trigon publish` publishes: while the evidence repository holds \
                          its `kill-switch` file, no divergence is published to it",
            });
            if operator {
                o["repository"] = r.repository.into();
                o["detail"] = r.detail.into();
            }
            o
        });
        serde_json::json!({
            "serve": {
                "set": self.switches.stop_divergences,
                "stops": "what this server shows: while it is set, no divergence is shown to an \
                          anonymous reader (`trigon serve --stop-divergences`)",
            },
            "repository": repository,
        })
    }
}

/// How much body `POST /v1/check` will buffer, one byte above the cap the handler enforces.
///
/// The extra byte is the whole point: at exactly `MAX_LOCKFILE + 1` the request still reaches the
/// handler, which refuses it by its own rule and says what the cap is and how far over the body
/// went. Without it the framework refuses first, and its rejection is plain text with no `error`
/// code — a client that reads `error` to decide what to tell the user gets nothing.
///
/// Anything beyond this is still stopped here, which is what a transport limit is for: the handler
/// cannot decline a body that has already been buffered into memory to be measured.
const BODY_LIMIT: axum::extract::DefaultBodyLimit =
    axum::extract::DefaultBodyLimit::max(fleet::MAX_LOCKFILE + 1);

/// The routes.
///
/// One of them is a `POST`, and it enqueues. The rule this crate keeps is not "no writes" — that
/// was a proxy for it, true while there was no write path — but **no route can express a verdict**,
/// which is enforced by the crate not depending on anything that computes one.
pub fn router(api: Arc<Api>) -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/v1/health", get(routes::health))
        .route("/v1/stats", get(routes::stats))
        .route("/v1/runs", get(routes::runs))
        .route("/v1/runs/{id}", get(routes::run))
        // The rendered comparison, and the bytes it was rendered from. Both, deliberately: a page
        // is what a reader wants and the blob is what a third party re-derives a verdict from.
        .route("/v1/runs/{id}/diff", get(routes::diff))
        .route("/v1/runs/{id}/comparison", get(routes::comparison))
        // What differs inside one member, and the member itself. Both class-gated: a census is a
        // claim about an artifact, and these are its content.
        .route("/v1/runs/{id}/member", get(routes::member))
        .route("/v1/runs/{id}/member/raw", get(routes::member_raw))
        .route("/v1/runs/{id}/attestation", get(routes::attestation))
        .route("/v1/runs/{id}/log", get(routes::build_log))
        .route("/v1/runs/{id}/network", get(routes::network))
        .route("/v1/runs/{id}/network/summary", get(routes::network_summary))
        .route("/v1/artifacts/{digest}", get(routes::artifact))
        .route("/v1/targets/{purl}", get(routes::target))
        .route("/v1/evidence/{digest}", get(routes::evidence_blob))
        .route("/v1/openapi.json", get(routes::openapi))
        .route("/v1/me", get(request::me))
        .route("/v1/queue", get(request::queue_state))
        // The three views docs/11-interfaces.md §3 asks for that the corpus browser lacked.
        .route(
            "/v1/check",
            axum::routing::post(fleet::check).layer(BODY_LIMIT),
        )
        .route("/v1/clusters", get(fleet::clusters))
        .route("/v1/fleet", get(fleet::fleet))
        .route("/v1/jobs/{id}/events", get(request::job_events))
        // The one write route. It enqueues a job; it cannot express an outcome, so it cannot
        // launder one. See `request`'s module documentation and `docs/22` §5.4.
        .route("/v1/runs", axum::routing::post(request::request_run))
        .route("/", get(ui::index_html))
        .route("/{*path}", get(ui::asset))
        // Last, so it wraps every route above. A handler that panics answers with a 500 that says
        // what broke, rather than dropping the socket and leaving a browser to report that the
        // network failed — which is what a reader saw the first time one did.
        .layer(axum::middleware::from_fn(recover::catch_panics))
        .with_state(api)
}
