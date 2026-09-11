//! The definitions rung: a human wrote this one down.
//!
//! Above every heuristic, because a definition exists precisely where inference failed. The layout
//! is the prior art's, `{ecosystem}/{package}/{version}/{artifact}/build.yaml`, so an existing
//! checkout works unmodified and ours can grow alongside it.
//!
//! A definition that fails to parse is a loud error rather than a silent fallthrough. Falling
//! through would run a heuristic against a target somebody had already established needs
//! something else, and report the resulting divergence as a fact about the package.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use trigon_core::Confidence;

use crate::error::RegistryError;
use crate::infer::{Candidate, Derivation, StrategyInferrer};
use crate::model::ResolvedTarget;

pub struct DefinitionsInferrer {
    root: PathBuf,
}

impl DefinitionsInferrer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DefinitionsInferrer { root: root.into() }
    }

    /// The conventional location, honouring `TRIGON_DEFINITIONS`.
    pub fn from_env() -> Option<Self> {
        let p = std::env::var("TRIGON_DEFINITIONS").ok()?;
        let path = Path::new(&p);
        path.is_dir().then(|| DefinitionsInferrer::new(path))
    }
}

#[async_trait]
impl StrategyInferrer for DefinitionsInferrer {
    fn name(&self) -> &'static str {
        "definitions"
    }

    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        let r = &target.reference;
        let mut out = Vec::new();

        for artifact in &target.artifacts {
            let path = self
                .root
                .join(r.ecosystem.purl_type())
                .join(r.registry_name())
                .join(&r.version)
                .join(artifact.id.as_str())
                .join("build.yaml");
            if !path.is_file() {
                continue;
            }
            let src = std::fs::read_to_string(&path)?;

            // Ours first, then the prior art's shape. Both are text files called build.yaml and the
            // difference is which key is at the top.
            let imported = trigon_strategy::from_yaml(&src)
                .map(|strategy| (strategy, Vec::new()))
                .or_else(|_| {
                    trigon_strategy::import(&src).map(|i| (i.strategy, i.custom_stabilizers))
                })
                .map_err(|e| RegistryError::Malformed {
                    ecosystem: r.ecosystem.to_string(),
                    what: path.display().to_string(),
                    detail: e.to_string(),
                })?;

            let (strategy, custom) = imported;
            let mut assumptions = Vec::new();
            for cs in &custom {
                // Surfaced, never silently dropped. The definition says the comparison needs this,
                // so a run without it reports a divergence its author already explained.
                assumptions.push(format!(
                    "this definition carries a `{}` custom stabilizer that is not executed yet: {}",
                    cs.kind,
                    cs.reason.lines().next().unwrap_or("").trim()
                ));
            }

            tracing::info!(path = %path.display(), "using a checked-in definition");
            out.push(Candidate {
                strategy,
                derivation: Derivation::Definition,
                confidence: Confidence::Certain,
                discovery: trigon_core::SourceDiscovery::Definition,
                assumptions,
            });
        }
        Ok(out)
    }
}
