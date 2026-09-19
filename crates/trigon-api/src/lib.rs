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
pub mod index;
pub mod member;
pub mod publication;
pub mod recover;
pub mod request;
pub mod routes;
pub mod serve;
pub mod ui;

pub use index::Index;
pub use publication::{Publication, Switches, Withheld};
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

/// Everything a handler can reach.
pub struct Api {
    pub store: Arc<trigon_store::Store>,
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
}

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
        .route("/v1/artifacts/{digest}", get(routes::artifact))
        .route("/v1/targets/{purl}", get(routes::target))
        .route("/v1/evidence/{digest}", get(routes::evidence_blob))
        .route("/v1/openapi.json", get(routes::openapi))
        .route("/v1/me", get(request::me))
        .route("/v1/queue", get(request::queue_state))
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
