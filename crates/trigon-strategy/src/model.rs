//! The strategy schema.
//!
//! Four variants, and the intent is that it stays four. The prior art carries thirteen, among them
//! `pypi_pure_wheel_build`, `npm_pack_build` and `maven_build`, and every one is a pre-canned flow
//! wearing a type. Here those are named flow templates in the definitions repo, so adding an
//! ecosystem is YAML plus a `Registry` implementation rather than a change to this enum. See
//! `docs/04-strategies.md` §2.1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The schema version every strategy document declares.
///
/// The prior art has no version field. Adding one costs a line and buys the ability to change the
/// format later without invalidating every document ever written.
pub const CURRENT_SCHEMA: u32 = 1;

/// What to do to reproduce an artifact.
///
/// Internally tagged on `kind`, never `untagged`. `untagged` reports "data did not match any
/// variant" with no span, no field and no inner error, which is the message a build-repair loop
/// would have to work from. It also picks the wrong variant in silence when two variants share a
/// shape, and `LocationHint` is a subset of `FlowStrategy` here, so that is live rather than
/// theoretical. See `docs/04-strategies.md` §2.2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Strategy {
    /// Repo and ref only. Seeds inference and cannot render instructions.
    LocationHint(LocationHint),
    /// The normal case: ordered steps over a named-tool registry.
    Flow(FlowStrategy),
    /// Raw scripts, which is what a model emits. Accepted, and recorded at a lower trust tier.
    Manual(ManualStrategy),
    /// The artifact is copied from a declared, pinned upstream build. Needs a human approval record.
    Prebuilt(PrebuiltStrategy),
}

impl Strategy {
    /// Whether this strategy can produce executable instructions at all.
    ///
    /// A `LocationHint` cannot, and the engine has to know that without matching on the variant
    /// everywhere it holds one.
    pub fn is_executable(&self) -> bool {
        !matches!(self, Strategy::LocationHint(_))
    }

    pub fn location(&self) -> Option<&Location> {
        match self {
            Strategy::LocationHint(h) => Some(&h.location),
            Strategy::Flow(f) => Some(&f.location),
            Strategy::Manual(m) => Some(&m.location),
            Strategy::Prebuilt(_) => None,
        }
    }
}

/// Where the source lives.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub repo: String,
    /// A resolved commit. Not a tag or a branch: those move, and a strategy that names one is not
    /// a description of a reproducible build.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// Path within the repository, when the package is not at its root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdir: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocationHint {
    pub location: Location,
    /// How the location was arrived at, for triage. Free text, never load-bearing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The normal case: four ordered phases of steps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStrategy {
    pub location: Location,
    /// Fetching and preparing the working tree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub src: Vec<Step>,
    /// Toolchain and dependency installation. Runs at image-build time where the runner supports
    /// it, which is what makes layer caching worth anything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<Step>,
    /// The build itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub build: Vec<Step>,
    /// Where the built artifact lands, relative to the working tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
    /// The exact filename to collect, when `output_dir` holds more than one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
}

/// Raw scripts. What an agent emits before anything has been lifted into a tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualStrategy {
    pub location: Location,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub deps: String,
    pub build: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
}

/// The artifact is taken from a declared upstream build rather than produced here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrebuiltStrategy {
    /// Where the bytes come from. Pinned, because the whole claim rests on it.
    pub url: String,
    /// The digest the fetched bytes must have.
    pub sha256: String,
    /// Who approved this and why. Required: a prebuilt strategy asserts something we did not
    /// verify, so it does not get to be anonymous.
    pub approved_by: String,
    pub reason: String,
}

/// One step of a phase.
///
/// `try_from` rather than `flatten`, because internal tagging on the outer enum buffers through
/// serde's `Content` and `flatten` does not compose with that. The conversion is also where
/// exactly-one-of is enforced, phrased in terms of the YAML someone wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(into = "StepRaw")]
pub struct Step {
    pub body: StepBody,
    /// System packages this step needs present. Hoisted into the image rather than installed
    /// mid-build, so the build phase does not reach the network.
    pub needs: Vec<String>,
    /// Render-time condition. The step is dropped when this renders empty or `false`.
    pub when: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepBody {
    /// A shell fragment, as a template.
    Runs(String),
    /// A named tool from the registry, with its parameters.
    Uses {
        tool: String,
        with: BTreeMap<String, String>,
    },
}

/// The wire shape of a step, before exactly-one-of is enforced.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRaw {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<String>,
    /// `BTreeMap`, not `HashMap`: rendering order feeds the strategy digest, and a hash map makes
    /// that digest vary between runs of the same binary. See `docs/04-strategies.md` §3.2 (2).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub with: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    #[serde(rename = "if", default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
}

impl TryFrom<StepRaw> for Step {
    type Error = String;

    fn try_from(r: StepRaw) -> Result<Self, Self::Error> {
        let body = match (r.runs, r.uses) {
            (Some(_), Some(_)) => {
                return Err("provide exactly one of `runs` or `uses`, not both".into());
            }
            (None, None) => return Err("provide exactly one of `runs` or `uses`".into()),
            (Some(runs), None) => {
                if !r.with.is_empty() {
                    return Err(
                        "`with` belongs to `uses`; a `runs` step takes no parameters".into(),
                    );
                }
                StepBody::Runs(runs)
            }
            // **`uses: runs` means a `runs` step.** A model writes it repeatedly — four of eight
            // recorded answers for one package — as
            //
            // ```yaml
            // - uses: runs
            //   with:
            //     script: |
            //       NODE_ENV=development browserify …
            // ```
            //
            // and it is unambiguous: `runs` is a step kind and can never be a registered tool, so
            // there is no other thing this could mean. Refusing it cost a correct repair on every
            // run that produced it, with an error naming nineteen tools the model was not asking
            // for.
            //
            // Accepted here rather than prompted away, because a schema a reader can get wrong in
            // one obvious direction is better read than re-explained.
            (None, Some(uses)) if uses == "runs" => {
                let mut with = r.with;
                // The parameter it puts the script under. One of these and no other; two would be
                // a step saying two different things.
                let named: Vec<&str> = ["script", "run", "cmd", "command"]
                    .into_iter()
                    .filter(|k| with.contains_key(*k))
                    .collect();
                match named.as_slice() {
                    [one] => StepBody::Runs(with.remove(*one).expect("just found")),
                    [] => {
                        return Err(
                            "`uses: runs` is read as a `runs` step, and it carries no script. \
                             Give it one under `script`, or write `runs:` directly."
                                .into(),
                        );
                    }
                    many => {
                        return Err(format!(
                            "`uses: runs` carries {} scripts ({}). A step runs one thing.",
                            many.len(),
                            many.join(", ")
                        ));
                    }
                }
            }
            (None, Some(uses)) => StepBody::Uses {
                tool: uses,
                with: r.with,
            },
        };
        Ok(Step {
            body,
            needs: r.needs,
            when: r.when,
        })
    }
}

impl From<Step> for StepRaw {
    fn from(s: Step) -> Self {
        let (runs, uses, with) = match s.body {
            StepBody::Runs(r) => (Some(r), None, BTreeMap::new()),
            StepBody::Uses { tool, with } => (None, Some(tool), with),
        };
        StepRaw {
            runs,
            uses,
            with,
            needs: s.needs,
            when: s.when,
        }
    }
}

impl<'de> Deserialize<'de> for Step {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = StepRaw::deserialize(d)?;
        Step::try_from(raw).map_err(serde::de::Error::custom)
    }
}
