use thiserror::Error;
use trigon_core::{Classify, Fault};

use crate::model::EgressTier;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("no runner accepts this plan: {0}")]
    Unroutable(String),

    #[error(
        "this runner cannot enforce {requested} egress (it enforces: {available}). \
         Refusing rather than downgrading: a verdict labelled with a tier that was never enforced \
         is worse than no verdict."
    )]
    EgressUnenforceable {
        requested: EgressTier,
        available: String,
    },

    #[error("the runner does not offer privileged execution, and the plan requires it")]
    PrivilegedUnavailable,

    #[error("base image `{0}` is not pinned by digest. A tag makes the run unreproducible.")]
    ImageNotPinned(String),

    /// A reference that can only be local, and is not there.
    ///
    /// Checked before the build rather than discovered inside it. `localhost/base@sha256:<stale>`
    /// has the shape of a pinned image, so it cleared the pin check and podman then spent six
    /// seconds trying to reach a registry called `localhost` — reported, after all that, as the
    /// package failing its dependency phase.
    #[error(
        "base image `{0}` is not in the local image store, and a `localhost/` or bare `sha256:` \
         reference can never be pulled from anywhere. Build it (`trigon base-image`) or pass the \
         digest of one that is there — `podman images --no-trunc` lists them."
    )]
    ImageNotInStore(String),

    #[error("{tool} is not available: {detail}")]
    ToolMissing { tool: String, detail: String },

    #[error("the build exceeded its {0:?} wall-clock limit and was killed")]
    Timeout(std::time::Duration),

    #[error("{phase}: {detail}")]
    Failed { phase: String, detail: String },

    /// The container runtime refused before any instruction of ours ran.
    ///
    /// An image that is not in the local store, a registry it cannot reach, a storage error.
    /// podman exits 125 for this and for nothing else, and its message names the cause exactly —
    /// so both are carried rather than collapsed into "the build failed".
    ///
    /// **Distinct from [`SandboxError::Failed`] because the two answer different questions.**
    /// `Failed` is a step of ours that did not work; this is the runtime declining to start one.
    /// Both are `Fault::Infra`, and neither is the package.
    #[error(
        "the container runtime could not start the build (exit {code}), so nothing about the \
         package was tested:\n{detail}"
    )]
    RuntimeRefused { code: i32, detail: String },

    #[error(
        "this strategy needs the system package(s) {packages}, and `{tier}` egress gives the image \
         build no network to install them. Build a base image that carries them and pass it with \
         `--image`:\n\n    FROM {base_image}\n    RUN {install}\n\nThat is what `docs/08` §3 \
         means by base images per ecosystem and toolchain family; it is also the only way an \
         enforced tier can mean what it says, because a phase that installs packages is a phase \
         that reaches the internet."
    )]
    SystemDepsUnavailable {
        tier: crate::EgressTier,
        packages: String,
        base_image: String,
        install: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Classify for SandboxError {
    fn fault(&self) -> Fault {
        match self {
            // Ours: the fleet is misconfigured, a tool is missing, a step of ours did not work,
            // or the runtime declined to start at all.
            //
            // **`Failed` moved here from `Fault::Build`.** Its `phase` field names one of *our*
            // steps, not one of the package's, and every one of the twelve sites that construct it
            // is infrastructure: copying the checkout into the build context, resolving the
            // mirror's address on the island, setting up the network namespace. Charging those to
            // the package is what `docs/03` says `Fault` exists to prevent — it is the difference
            // between "this package does not build" and "our base image has no CA bundle".
            SandboxError::ToolMissing { .. }
            | SandboxError::Io(_)
            | SandboxError::Failed { .. }
            | SandboxError::RuntimeRefused { .. } => Fault::Infra,
            // The plan asked for something we decline to provide.
            SandboxError::Unroutable(_)
            | SandboxError::EgressUnenforceable { .. }
            | SandboxError::PrivilegedUnavailable
            | SandboxError::ImageNotPinned(_)
            | SandboxError::ImageNotInStore(_)
            // A tier that cannot install packages and a strategy that needs them: a policy of
            // ours, not a broken package and not broken infrastructure.
            | SandboxError::SystemDepsUnavailable { .. } => Fault::Policy,
            // The package's own build did this. A wall-clock kill of a build that is running is
            // the package taking too long; a timeout that expires while the runtime is still
            // pulling an image is ours, and telling the two apart needs the log rather than the
            // type. Recorded in `docs/17-backlog.md` rather than guessed at here.
            SandboxError::Timeout(_) => Fault::Build,
        }
    }
}
