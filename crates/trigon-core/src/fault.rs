use serde::{Deserialize, Serialize};

/// Whose fault an error is.
///
/// Load-bearing rather than tidy: without it, every benchmark denominator counts infrastructure
/// faults as unreproducible packages. See `docs/02-domain-model.md` §4.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// Ours. Stays out of the reproduction rate.
    Infra,
    /// The registry's, or the network's.
    Upstream,
    /// The package's build.
    Build,
    /// A policy said no: egress tier, unpinned image, unregistered tool.
    Policy,
    /// Ours, and someone should look now.
    Bug,
}

pub trait Classify {
    fn fault(&self) -> Fault;
}

impl Fault {
    /// Whether a run that ended this way should be retried unchanged.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Fault::Infra | Fault::Upstream)
    }

    /// Whether this error says anything about the package.
    pub const fn is_about_the_package(self) -> bool {
        matches!(self, Fault::Build)
    }
}
