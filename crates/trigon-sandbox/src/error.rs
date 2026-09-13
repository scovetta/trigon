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

    #[error("{tool} is not available: {detail}")]
    ToolMissing { tool: String, detail: String },

    #[error("the build exceeded its {0:?} wall-clock limit and was killed")]
    Timeout(std::time::Duration),

    #[error("{phase}: {detail}")]
    Failed { phase: String, detail: String },

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
            // Ours: the fleet is misconfigured or a tool is missing.
            SandboxError::ToolMissing { .. } | SandboxError::Io(_) => Fault::Infra,
            // The plan asked for something we decline to provide.
            SandboxError::Unroutable(_)
            | SandboxError::EgressUnenforceable { .. }
            | SandboxError::PrivilegedUnavailable
            | SandboxError::ImageNotPinned(_)
            // A tier that cannot install packages and a strategy that needs them: a policy of
            // ours, not a broken package and not broken infrastructure.
            | SandboxError::SystemDepsUnavailable { .. } => Fault::Policy,
            // The package's own build did this.
            SandboxError::Timeout(_) | SandboxError::Failed { .. } => Fault::Build,
        }
    }
}
