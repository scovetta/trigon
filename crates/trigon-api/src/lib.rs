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

pub mod evidence;
pub mod index;
pub mod publication;
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
    pub index: index::Index,
    pub switches: Switches,
    /// What an unauthenticated caller counts as.
    ///
    /// `Anonymous` is what `--public` selects and is the mode the class gating and the publication
    /// gate are written for. `Operator` is the default, because the default bind is loopback and a
    /// person reading their own store should not have to authenticate to themselves.
    pub unauthenticated: Principal,
}

impl Api {
    pub fn principal(&self) -> Principal {
        self.unauthenticated
    }
}

/// The routes, and nothing else.
///
/// Every one is a `get`. That is not a coincidence to be maintained by attention: this crate has no
/// handler that takes a body, and `no_route_mutates_anything` asserts the router agrees.
pub fn router(api: Arc<Api>) -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/v1/health", get(routes::health))
        .route("/v1/stats", get(routes::stats))
        .route("/v1/runs", get(routes::runs))
        .route("/v1/runs/{id}", get(routes::run))
        .route("/v1/runs/{id}/comparison", get(routes::comparison))
        .route("/v1/runs/{id}/attestation", get(routes::attestation))
        .route("/v1/runs/{id}/log", get(routes::build_log))
        .route("/v1/runs/{id}/network", get(routes::network))
        .route("/v1/artifacts/{digest}", get(routes::artifact))
        .route("/v1/targets/{purl}", get(routes::target))
        .route("/v1/evidence/{digest}", get(routes::evidence_blob))
        .route("/v1/openapi.json", get(routes::openapi))
        .route("/", get(ui::index_html))
        .route("/{*path}", get(ui::asset))
        .with_state(api)
}
