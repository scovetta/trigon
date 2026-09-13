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

/// The build this package declares that its packaging tool will not run, from the evidence the
/// resolver recorded.
fn unrun_build(target: &ResolvedTarget) -> Option<(String, String)> {
    target
        .intrinsics
        .evidence
        .iter()
        .find_map(|e| match &e.claim {
            trigon_core::Claim::UnrunScript { name, command } => {
                Some((name.clone(), command.clone()))
            }
            _ => None,
        })
}

/// Whether a command is one program with literal arguments.
///
/// `bundt` and `rollup -c` qualify; `premove dist && pnpm build-bundle` does not. The point is not
/// that a shell pipeline is unsafe to run — the build already runs whatever the package says, in a
/// container with an enforced egress boundary — but that a pipeline reaches for tools and paths
/// this rung has checked nothing about. A rung that cannot tell what it is about to run should not
/// be the one deciding to run it; that is the Builder's job, and the divergence that says so is
/// how it gets there.
fn bare_program(command: &str) -> bool {
    !command.is_empty()
        && command
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " @._/,:+-".contains(c))
}

fn plural(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

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
    sources: Option<std::sync::Arc<crate::SourceCache>>,
}

impl NpmInferrer {
    pub fn new(client: Client) -> Self {
        NpmInferrer {
            client,
            mirror: None,
            sources: None,
        }
    }

    /// Let the rung read the repository, for the one question registry metadata cannot answer.
    ///
    /// Without it the rung is exactly what it was: metadata in, strategy out, no disk. With it, a
    /// package that declares a build nothing runs gets one depth-1 checkout so the rung can ask
    /// whether the repository already contains what the manifest promises. That question decides
    /// between a recipe that builds and one that does not, and getting it wrong in either direction
    /// costs a target — so it is asked of the repository rather than assumed.
    pub fn with_sources(mut self, sources: Option<std::sync::Arc<crate::SourceCache>>) -> Self {
        self.sources = sources;
        self
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

        // `npm pack` runs prepare and prepack itself, so the plain recipe covers a package with
        // publish scripts. What it does not cover is a package whose build hangs off a name npm
        // never runs — `build`, most often — and which publishes the output.
        //
        // Two conditions, and both have to hold. The registry document has to say a build exists
        // that nothing will run (`Claim::UnrunScript`, which is where the narrow test lives), and
        // the repository has to be missing something its own manifest promises. The second is what
        // keeps the rule off a package that declares a build *and commits its output*: running that
        // build regenerates files the repository already holds correctly, under whatever today's
        // floating ranges resolve to, which is a divergence manufactured by the fix.
        let mut build = BTreeMap::from([("npm_version".to_string(), deps["npm_version"].clone())]);
        let mut build_tool = "npm/build/pack";
        if let Some((script, command)) = unrun_build(target)
            && bare_program(&command)
            && let Some(sources) = self.sources.clone()
        {
            let (repo, commit) = (source.repo_url.clone(), source.commit.clone());
            // On a blocking thread: the checkout shells out to git, and a rung runs inside the
            // runtime that drives a sweep.
            let read = tokio::task::spawn_blocking(move || {
                let c = sources.checkout(&repo, &commit)?;
                let manifest = c.read(&["package.json"], 1 << 20);
                let files = c.files(20_000)?;
                Ok::<_, RegistryError>((manifest, files))
            })
            .await;

            match read {
                Ok(Ok((manifest, files))) => {
                    let parsed = manifest
                        .first()
                        .and_then(|(_, text)| serde_json::from_str::<serde_json::Value>(text).ok());
                    let missing = parsed
                        .map(|m| crate::shortfall(&m, &files))
                        .unwrap_or_default();
                    if !missing.is_empty() {
                        build_tool = "npm/build/custom";
                        build.insert("command".into(), script.clone());
                        assumptions.push(format!(
                            "the manifest promises {} the repository does not contain ({}), and \
                             `npm pack` runs no script that would build {}, so `npm run {script}` \
                             is run first",
                            plural(missing.len(), "file"),
                            missing
                                .iter()
                                .take(4)
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", "),
                            if missing.len() == 1 { "it" } else { "them" },
                        ));
                        assumptions.push(format!(
                            "`{command}` is the publisher's own build command, and this assumes it \
                             is what they ran: nothing records that it is"
                        ));
                    }
                }
                // A repository we cannot read leaves the plain recipe in place. A rung that failed
                // here would turn a package with a force-pushed commit from a build failure into no
                // strategy at all, which moves a verdict for a reason that has nothing to do with
                // the package.
                Ok(Err(e)) => tracing::debug!("no build inference: {e}"),
                Err(e) => tracing::debug!("the checkout task did not finish: {e}"),
            }
        }

        let strategy = Strategy::Flow(FlowStrategy {
            location: Location {
                repo: source.repo_url.clone(),
                git_ref: source.commit.clone(),
                subdir: source.subdir.clone(),
            },
            src: vec![uses("git-checkout", BTreeMap::new())],
            deps: vec![uses("npm/deps/custom", deps)],
            build: vec![uses(build_tool, build)],
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
                    // Named as mutable, not merely as "from a tag". A tag can be moved or deleted
                    // after a release — `pad-left 2.1.0` in the corpus is a package whose recorded
                    // commit was force-pushed away — so this is the commit the tag points at
                    // today, which is a good approximation and not the same claim as a commit the
                    // registry recorded at publish time.
                    assumptions.push(format!(
                        "the commit comes from tag `{tag}` rather than from the registry, and a \
                         tag is mutable: this is where it points today, not necessarily what was \
                         published"
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
        // The published wheel says which backend built it, in its own `Generator:` field. Nothing
        // in PyPI's *metadata* does, which is what this rung used to assume — and the difference
        // was nine of ten divergences in the M1 corpus, every one of them confined to `WHEEL`,
        // `METADATA` and the `RECORD` that follows from them, with every source file identical.
        //
        // Unpinned, the frontend resolves the project's declaration against the index and installs
        // whatever is current; the publisher used whatever was current then. Two lines differ and
        // the wheel diverges.
        let backend = build_backend_pin(target);
        match &backend {
            Some(pin) => {
                deps.insert("build_backend".into(), pin.clone());
            }
            None => assumptions.push(
                "the published artifact names no build backend, so build requirements come from \
                 the project's own declaration resolved by the frontend"
                    .into(),
            ),
        }

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
                    (
                        "constraints".to_string(),
                        backend
                            .as_ref()
                            .map(|_| "/deps/constraints.txt".to_string())
                            .unwrap_or_default(),
                    ),
                    // Isolation stays on. `-n` makes the frontend *check* for each declared build
                    // requirement rather than install it, so anything the project needs beyond the
                    // backend goes missing — `attrs` wants `hatch-vcs` and `hatch-fancy-pypi-readme`
                    // and stops with "Unmet dependencies". The backend version is pinned by a
                    // constraint instead, which binds the environment the frontend builds without
                    // taking over what goes into it.
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

/// `name==version` for the backend the published wheel says built it.
///
/// A deterministic read from the artifact under test, not a guess: `crate::wheel::generator_evidence`
/// puts it in the intrinsics at fetch time and this turns it into something pip can install.
pub(crate) fn build_backend_pin(target: &ResolvedTarget) -> Option<String> {
    target
        .intrinsics
        .evidence
        .iter()
        .find_map(|e| match &e.claim {
            trigon_core::Claim::ToolchainExact { tool, version }
                if e.source == "wheel:Generator" =>
            {
                Some(format!("{tool}=={version}"))
            }
            _ => None,
        })
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
