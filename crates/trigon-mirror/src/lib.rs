//! The time-filtering registry mirror.
//!
//! Rebuilding a package two years after publication resolves *today's* transitive dependencies.
//! That is not a small source of divergence: it makes **any package whose build resolves a floating
//! range irreproducible by construction**, and it does so silently, because the build succeeds and
//! produces something that is simply not what was published.
//!
//! The mirror answers a package manager's index requests with the index as it stood at a named
//! instant. Everything else, tarballs and wheels, passes through untouched: registries are
//! append-only for artifact bytes, so a file that existed then has the same content now.
//!
//! It is also what makes `EgressTier::MirrorOnly` mean anything. A build allowed to reach only this
//! is a build that cannot reach the artifact it is supposed to be reproducing.

mod error;
mod guard;
mod moment;
mod npm;
mod pypi;
mod server;

pub use error::MirrorError;
pub use guard::{
    Checked, EXCHANGE_MARKER, Exchange, Guard, GuardManifest, GuardMatch, TRIP_MARKER, Trip,
};
pub use moment::{Filter, Platform, normalize, published_by, url_for};
pub use npm::filter_packument;
pub use pypi::{filter_simple, render_html};
pub use server::{
    ARTIFACT_HOSTS, Mirror, MirrorHandle, Observed, TOOLCHAIN_HOSTS, artifact_host_allowed,
    toolchain_host_allowed,
};
