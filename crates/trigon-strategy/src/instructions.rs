//! What a rendered strategy is: three scripts and the environment they need.
//!
//! This is the far side of the seam. A strategy is data and rendering is pure, so `Instructions`
//! are the only thing an executor ever sees, and the attestation records them verbatim. A verifier
//! then needs no template engine of ours, and an attestation written today stays readable after the
//! DSL changes underneath it. See `docs/04-strategies.md` §1.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::StrategyError;
use crate::model::Location;

/// A shell fragment, already rendered. Never a template.
pub type Script = String;

/// What the build needs from the environment it runs in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirements {
    /// System packages hoisted into the image, so the build phase itself reaches no package
    /// manager. `BTreeSet` because this is hashed into the plan and set iteration order would
    /// otherwise make the digest depend on insertion order.
    pub system_deps: BTreeSet<String>,
    /// Almost never true, and a runner that does not advertise the capability rejects the plan
    /// rather than quietly dropping the request.
    pub privileged: bool,
}

/// Where the source came from, as a fact rather than a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProvenance {
    pub repo: String,
    /// The resolved commit. A tag or branch here would make the instructions unreproducible.
    pub commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdir: Option<String>,
}

impl From<&Location> for SourceProvenance {
    fn from(l: &Location) -> Self {
        SourceProvenance {
            repo: l.repo.clone(),
            commit: l.git_ref.clone(),
            subdir: l.subdir.clone(),
        }
    }
}

/// A strategy, rendered. The executor consumes this and never re-renders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instructions {
    pub location: SourceProvenance,
    /// Fetch and prepare the working tree.
    pub source: Script,
    /// Toolchain and dependencies. Runs at image-build time where the runner supports it.
    pub deps: Script,
    /// Produce the artifact.
    pub build: Script,
    /// Where the artifact lands, relative to the working tree.
    pub output_path: String,
    pub requires: Requirements,
}

impl Instructions {
    /// Whether this plan would actually build something.
    ///
    /// Separate from `render` on purpose: rendering is a pure function and `trigon strategy render`
    /// exists to *look at* what a strategy produces, including a deps-only fragment. Refusing to
    /// render one would break the inspection command. What must be refused is **executing** a plan
    /// whose build phase is empty, because the executor runs it, produces nothing, and the run ends
    /// as "the build succeeded and left no artifact" — which reports that the recipe ran and failed
    /// to produce, rather than that the recipe does not build anything.
    ///
    /// The shape that survives review is the second one: every build step carries an `if:`, and on
    /// this run every condition is false. The document reads like a build and the render is silence.
    pub fn executable(&self) -> Result<(), StrategyError> {
        if self.build.trim().is_empty() {
            return Err(StrategyError::Invalid(
                "this strategy renders an empty build phase, so running it would produce nothing \
                 and report that the build succeeded. Either it declares no build steps, or every \
                 step it declares was skipped by its own `if:` on this run."
                    .into(),
            ));
        }
        Ok(())
    }
}
