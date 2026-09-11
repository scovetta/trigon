//! Running a build in isolation.
//!
//! The build container executes the package's own build scripts, so it is treated as hostile
//! throughout. The controls that matter are not sandbox-escape defences: they are that the build
//! worker cannot reach the upstream artifact, by network or by blob store, because a build that can
//! download the artifact it is supposed to be reproducing will reproduce it perfectly every time.
//! See `docs/12-security.md` §2.

mod dockerfile;
mod error;
mod model;
mod network;
mod podman;
mod runner;

pub use dockerfile::{BuildContext, render as render_context};
pub use error::SandboxError;
pub use model::{
    BuildEvent, BuildOutcome, BuildPlan, EgressTier, IsolationClass, Limits, ObservabilityTier,
    OciPlan, Phase, RunOpts, RunnerCaps,
};
pub use network::Island;
pub use podman::{PodmanRunner, failing_phase as failing_phase_for_test};
pub use runner::{BuildHandle, BuildRunner, route};
