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
mod store_lock;

pub use dockerfile::install_command;
pub use dockerfile::{BuildContext, render as render_context};
pub use error::SandboxError;
pub use model::{
    BuildEvent, BuildOutcome, BuildPlan, EgressTier, EventSink, IsolationClass, Limits,
    ObservabilityTier, OciPlan, Phase, RunOpts, RunnerCaps,
};
pub use network::{Island, MirrorLog, owner_is_gone};
pub use podman::{PodmanRunner, failing_phase as failing_phase_for_test};
pub use runner::{BuildHandle, BuildRunner, route};

/// A bind-mount source podman will read as a path rather than as a volume name.
///
/// podman decides between "bind mount this directory" and "create a named volume" by whether the
/// source starts with `/`. A relative `--work demo/work` therefore became a *named volume* called
/// `demo/work/guard.json`, which podman refuses because a volume name must match
/// `[a-zA-Z0-9][a-zA-Z0-9_.-]*` — so every enforced-tier run started from a relative path died in
/// setup with a message about volume names, three steps from the cause.
///
/// `canonicalize` rather than `absolutize`: it also resolves `..` and symlinks, and the path is
/// about to be handed to another process that does not share our working directory.
pub(crate) fn mount_source(p: &std::path::Path) -> String {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .display()
        .to_string()
}
