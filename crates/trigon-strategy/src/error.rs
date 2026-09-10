use thiserror::Error;
use trigon_core::{Classify, Fault};

#[derive(Debug, Error)]
pub enum StrategyError {
    #[error("not valid YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    /// The message carries a path into the document, which is the point of the dependency.
    #[error("{path}: {message}")]
    Field { path: String, message: String },

    #[error(
        "missing `kind`. Every strategy document declares one of: location_hint, flow, manual, prebuilt"
    )]
    MissingKind,

    #[error(
        "schema {found} is newer than this build understands (highest known: {known}). \
         Upgrade trigon rather than editing the document."
    )]
    SchemaTooNew { found: u32, known: u32 },

    #[error("template: {0}")]
    Template(String),

    #[error("{0}")]
    Invalid(String),
}

impl Classify for StrategyError {
    fn fault(&self) -> Fault {
        match self {
            // A malformed document is a fault in the definitions repo or in whatever produced it,
            // never in the package under test.
            StrategyError::Yaml(_)
            | StrategyError::Field { .. }
            | StrategyError::MissingKind
            | StrategyError::Template(_)
            | StrategyError::Invalid(_) => Fault::Policy,
            StrategyError::SchemaTooNew { .. } => Fault::Infra,
        }
    }
}
