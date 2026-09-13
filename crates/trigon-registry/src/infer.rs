//! Turning what a registry told us into a strategy.
//!
//! The engine holds an ordered list of inferrers and takes the first candidate that validates. No
//! branch anywhere asks whether a candidate came from a heuristic or a model: the ordering *is* the
//! policy. That is what keeps the AI out of the judgement half by construction rather than by
//! discipline, and it is why the model rungs, when they exist, implement this same trait.
//!
//! Every rung here is free and deterministic. `docs/04-strategies.md` §6 puts a definitions entry
//! above a heuristic and both above any model call, because a rung that costs nothing and is right
//! most of the time is worth more than a clever one that costs money every time.

use async_trait::async_trait;
use trigon_core::{Confidence, SourceDiscovery};
use trigon_strategy::Strategy;

use crate::error::RegistryError;
use crate::model::ResolvedTarget;

/// A strategy, and how much to believe it.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub strategy: Strategy,
    /// Which rung produced this. Recorded in the attestation, because how a strategy was derived
    /// predicts a false result better than anything else we have.
    pub derivation: Derivation,
    pub confidence: Confidence,
    /// Which rung found the commit this strategy checks out.
    ///
    /// Carried separately from the strategy because the strategy only holds the answer. A
    /// registry-recorded commit and a fuzzy tag match are both a forty-character string, and a
    /// divergence means something different under each.
    pub discovery: SourceDiscovery,
    /// What this rung had to assume. Printed, so a divergence can be read against the guesses that
    /// produced it rather than treated as a fact about the package.
    pub assumptions: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Derivation {
    /// A human wrote it down for this exact artifact.
    Definition,
    /// Derived from the release workflow.
    CiDerived,
    /// Derived from registry metadata and source layout.
    Heuristic,
    ModelAssisted,
}

/// The one spelling, because this reaches a signed statement.
///
/// It was written two ways from two branches of one `if` in `trigon rebuild`: the first candidate's
/// derivation went through `format!("{:?}", d).to_lowercase()`, giving `modelassisted` and
/// `ciderived`, while a repaired run wrote the literal `model_assisted`. So the same run recorded a
/// different `derivation.method` depending on whether it needed a repair, and a consumer filtering
/// on "no model touched this" — which `docs/09-attestations.md` §2.1 makes their job — had two
/// strings to know about and was told about one.
impl std::fmt::Display for Derivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Derivation::Definition => "definition",
            Derivation::CiDerived => "ci_derived",
            Derivation::Heuristic => "heuristic",
            Derivation::ModelAssisted => "model_assisted",
        })
    }
}

#[async_trait]
pub trait StrategyInferrer: Send + Sync {
    fn name(&self) -> &'static str;

    /// Propose strategies for this target, best first.
    ///
    /// An empty vector means "this rung has nothing to say", which is not an error: most rungs are
    /// silent for most targets, and that is how the ladder is supposed to work.
    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError>;
}

/// Run the ladder and return the first candidate anything produced.
pub async fn infer(
    rungs: &[Box<dyn StrategyInferrer>],
    target: &ResolvedTarget,
) -> Result<Option<Candidate>, RegistryError> {
    for rung in rungs {
        match rung.infer(target).await {
            Ok(candidates) if !candidates.is_empty() => {
                tracing::info!(
                    rung = rung.name(),
                    derivation = ?candidates[0].derivation,
                    "inferred a strategy"
                );
                return Ok(candidates.into_iter().next());
            }
            Ok(_) => tracing::debug!(rung = rung.name(), "nothing to say"),
            // A rung that fails is not fatal: the next one may still know. The engine only fails
            // when every rung has been asked and none produced anything.
            Err(e) => tracing::warn!(rung = rung.name(), "{e}"),
        }
    }
    Ok(None)
}

/// How a `SourceDiscovery` rung should be believed.
pub(crate) fn confidence_of(how: SourceDiscovery) -> Confidence {
    match how {
        SourceDiscovery::RegistryCommit
        | SourceDiscovery::PublishedProvenance
        | SourceDiscovery::Definition => Confidence::Certain,
        SourceDiscovery::TreeHashMatch | SourceDiscovery::ExactTag => Confidence::Strong,
        _ => Confidence::Weak,
    }
}
