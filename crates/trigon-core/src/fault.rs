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

    /// Whether retrying this exact run could reach a different answer.
    ///
    /// Defaults to the fault class, which is right for most errors. An error that knows better
    /// overrides it, because the class cannot always tell: a 503 from a registry and a malformed
    /// published artifact are both `Upstream`, and only the first is worth trying again. Retrying
    /// the second burns a worker slot to reach the same conclusion, and at fleet scale it does so
    /// on every sweep.
    fn is_retryable(&self) -> bool {
        self.fault().is_retryable()
    }
}

impl Fault {
    /// Whether a run that ended this way is, by class alone, worth retrying unchanged.
    ///
    /// A default rather than a verdict. `Upstream` covers both a registry that was briefly down
    /// and an artifact that will never parse, so an error that can tell them apart overrides
    /// [`Classify::is_retryable`].
    pub const fn is_retryable(self) -> bool {
        matches!(self, Fault::Infra | Fault::Upstream)
    }

    /// Whether this error says anything about the package.
    pub const fn is_about_the_package(self) -> bool {
        matches!(self, Fault::Build)
    }
}
