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
            | SandboxError::ImageNotPinned(_) => Fault::Policy,
            // The package's own build did this.
            SandboxError::Timeout(_) | SandboxError::Failed { .. } => Fault::Build,
        }
    }
}
