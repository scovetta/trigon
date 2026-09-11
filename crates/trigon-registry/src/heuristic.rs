//! The heuristic rung: registry metadata into a strategy, with no model and no money.
//!
//! This is the rung that carries the volume. A definitions entry covers roughly a thousandth of
//! targets and a model costs per call, so a free deterministic rung that is right most of the time
//! is worth more than either.
//!
//! What "right most of the time" means differs sharply by ecosystem, and the difference is
//! structural rather than a matter of effort. npm records the commit it published from *and* the
//! Node and npm versions the publisher used, so an npm strategy is close to a transcription. PyPI
//! records a project URL, so a PyPI strategy has to guess the commit from a tag and the build
//! requirements from nothing at all.

use async_trait::async_trait;
use std::collections::BTreeMap;
use trigon_core::Confidence;
use trigon_strategy::{FlowStrategy, Location, Step, StepBody, Strategy};

use crate::client::Client;
use crate::error::RegistryError;
use crate::infer::{Candidate, Derivation, StrategyInferrer, confidence_of};
use crate::model::ResolvedTarget;
use crate::tags;

fn uses(tool: &str, with: BTreeMap<String, String>) -> Step {
    Step {
        body: StepBody::Uses {
            tool: tool.into(),
            with,
        },
        needs: Vec::new(),
        when: None,
    }
}

/// npm, where the registry already knows almost everything.
pub struct NpmInferrer {
    client: Client,
    mirror: Option<String>,
}

impl NpmInferrer {
    pub fn new(client: Client) -> Self {
        NpmInferrer {
            client,
            mirror: None,
        }
    }

    /// Pin the registry moment against a time-filtering mirror.
    ///
    /// Without one the strategy must not pin a moment at all. Emitting `registry_time` with no
    /// mirror renders a registry URL pointing at a host that does not resolve, and the build fails
    /// in a way that reads like the package's fault.
    pub fn with_mirror(mut self, mirror: Option<String>) -> Self {
        self.mirror = mirror;
        self
    }
}

#[async_trait]
impl StrategyInferrer for NpmInferrer {
    fn name(&self) -> &'static str {
        "npm-heuristic"
    }

    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        let Some(source) = &target.source else {
            return Ok(Vec::new());
        };
        if source.commit.is_empty() {
            return Ok(Vec::new());
        }
        let _ = &self.client;

        let mut assumptions = Vec::new();

        // `_nodeVersion` and `_npmVersion` are what the publishing client reported, so this is not
        // an inference at all: it is the toolchain that produced the artifact, recorded by the
        // registry at publish time. Where they are absent the rung declines rather than picking a
        // current release, because a modern npm packs a tarball a 2018 npm would not have.
        let node = evidence_value(target, "npm:_nodeVersion");
        let npm = evidence_value(target, "npm:_npmVersion");
        let (Some(node), Some(npm)) = (node, npm) else {
            tracing::debug!(
                "no _nodeVersion/_npmVersion recorded; declining rather than guessing a toolchain"
            );
            return Ok(Vec::new());
        };

        let mut deps = BTreeMap::from([
            ("node_version".to_string(), node),
            ("npm_version".to_string(), npm),
        ]);
        match (&target.intrinsics.publish_time, &self.mirror) {
            (Some(t), Some(_)) => {
                deps.insert("registry_time".into(), t.clone());
            }
            // The reproducibility-critical caveat, stated rather than hidden. Any package with a
            // floating dependency range resolves differently today than it did at publish time, so
            // a rebuild without a mirror answers a weaker question than it looks like it answers.
            (Some(t), None) => assumptions.push(format!(
                "no registry mirror configured, so dependencies resolve against today's npm \
                 rather than against {t}"
            )),
            (None, _) => assumptions.push(
                "no publish time recorded, so dependencies resolve against today's registry".into(),
            ),
        }

        // `npm pack` runs prepare and prepack itself, so the plain build covers a package with
        // publish scripts as well. Where it does not, the divergence says so and a definitions
        // entry is the answer; guessing at a script to run first would build something the
        // publisher did not.
        let build = BTreeMap::from([("npm_version".to_string(), deps["npm_version"].clone())]);

        let strategy = Strategy::Flow(FlowStrategy {
            location: Location {
                repo: source.repo_url.clone(),
                git_ref: source.commit.clone(),
                subdir: source.subdir.clone(),
            },
            src: vec![uses("git-checkout", BTreeMap::new())],
            deps: vec![uses("npm/deps/custom", deps)],
            build: vec![uses("npm/build/pack", build)],
            // The tarball, not the directory. `npm pack` writes `<name>-<version>.tgz` into the
            // package directory, and naming the directory copies the whole working tree: a
            // "successful" build that collects a source checkout and nothing to compare.
            output_dir: None,
            output_path: Some(match &source.subdir {
                Some(d) => format!("{}/*.tgz", d.trim_end_matches('/')),
                None => "*.tgz".into(),
            }),
        });

        Ok(vec![Candidate {
            strategy,
            derivation: Derivation::Heuristic,
            confidence: confidence_of(source.how),
            discovery: source.how,
            assumptions,
        }])
    }
}

/// PyPI, where the registry knows the repository and nothing else.
pub struct PyPiInferrer {
    client: Client,
    mirror: Option<String>,
}

impl PyPiInferrer {
    pub fn new(client: Client) -> Self {
        PyPiInferrer {
            client,
            mirror: None,
        }
    }

    /// See [`NpmInferrer::with_mirror`].
    pub fn with_mirror(mut self, mirror: Option<String>) -> Self {
        self.mirror = mirror;
        self
    }
}

#[async_trait]
impl StrategyInferrer for PyPiInferrer {
    fn name(&self) -> &'static str {
        "pypi-heuristic"
    }

    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        let Some(source) = &target.source else {
            return Ok(Vec::new());
        };

        let mut assumptions = Vec::new();

        // PyPI records no commit, so one has to be found. A tag is the cheap rung and it is right
        // for most projects that tag releases at all.
        let (commit, how) = if source.commit.is_empty() {
            match tags::resolve_version_tag(
                &self.client,
                &source.repo_url,
                &target.reference.version,
            )
            .await
            {
                Some((sha, tag, how)) => {
                    assumptions.push(format!(
                        "the commit comes from tag `{tag}`, not the registry"
                    ));
                    (sha, how)
                }
                None => {
                    tracing::debug!(
                        repo = source.repo_url,
                        "no tag matches this version; a stronger rung is needed"
                    );
                    return Ok(Vec::new());
                }
            }
        } else {
            (source.commit.clone(), source.how)
        };

        let mut deps = BTreeMap::from([("venv".to_string(), "/deps".to_string())]);
        match (&target.intrinsics.publish_time, &self.mirror) {
            (Some(t), Some(_)) => {
                deps.insert("registry_time".into(), t.clone());
            }
            (Some(t), None) => assumptions.push(format!(
                "no registry mirror configured, so dependencies resolve against today's PyPI \
                 rather than against {t}"
            )),
            (None, _) => assumptions.push(
                "no publish time recorded, so dependencies resolve against today's index".into(),
            ),
        }
        // Nothing in PyPI's metadata says what the build needed. The frontend reads pyproject.toml
        // and installs the declared backend itself, which is right for a modern project and wrong
        // for one that expected a specific setuptools. That is the common case, and where it is
        // wrong the divergence is in METADATA or RECORD and legible.
        assumptions.push(
            "build requirements come from the project's own declaration, resolved by the build \
             frontend rather than pinned here"
                .into(),
        );

        let strategy = Strategy::Flow(FlowStrategy {
            location: Location {
                repo: source.repo_url.clone(),
                git_ref: commit,
                subdir: source.subdir.clone(),
            },
            src: vec![uses("git-checkout", BTreeMap::new())],
            deps: vec![uses("pypi/deps/basic", deps)],
            build: vec![uses(
                "pypi/build/wheel",
                BTreeMap::from([
                    ("locator".to_string(), "/deps/bin/".to_string()),
                    // This rung pins no build requirements, so the frontend has to resolve them
                    // from the project's own declaration. With `-n` it does not install a declared
                    // requirement, it checks for it and stops.
                    ("no_isolation".to_string(), "false".to_string()),
                ]),
            )],
            output_dir: Some(match &source.subdir {
                Some(d) => format!("{}/dist", d.trim_end_matches('/')),
                None => "dist".into(),
            }),
            output_path: None,
        });

        Ok(vec![Candidate {
            strategy,
            derivation: Derivation::Heuristic,
            // Never better than Weak: a tag match plus assumed build requirements is a reasonable
            // opening guess, not a description of how the artifact was built.
            confidence: Confidence::Weak,
            discovery: how,
            assumptions,
        }])
    }
}

fn evidence_value(target: &ResolvedTarget, source: &str) -> Option<String> {
    target
        .intrinsics
        .evidence
        .iter()
        .find_map(|e| match &e.claim {
            trigon_core::Claim::ToolchainExact { version, .. } if e.source == source => {
                Some(version.clone())
            }
            _ => None,
        })
}
