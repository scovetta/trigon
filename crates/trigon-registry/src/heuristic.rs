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
use trigon_strategy::{FlowStrategy, Location, Step, StepBody, Strategy, VENV};

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
        let _ = &self.client;

        let mut assumptions = Vec::new();

        // **npm usually records a commit, and a monorepo usually does not.** `gitHead` is written
        // by the publishing client, and the tools that publish workspaces — lerna, changesets,
        // `pnpm publish` — mostly do not write it: `@babel/core` and `@vue/reactivity` both carry
        // `repository.directory` and no `gitHead` at all. This rung used to decline outright, so
        // every such package came back `no-strategy` in a second, which reads as "we cannot infer a
        // recipe" when the truth is "the registry did not record which commit".
        //
        // The tag is the same cheap rung PyPI has always used, and it costs one `ls-remote` now
        // that it no longer goes through the GitHub API.
        let (commit, how) = if source.commit.is_empty() {
            match tags::resolve_version_tag(
                &source.repo_url,
                &target.reference.version,
                &target.reference.name,
            )
            .await
            {
                Some((sha, tag, how)) => {
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
                        "npm recorded no gitHead and no tag matches this version"
                    );
                    return Ok(Vec::new());
                }
            }
        } else {
            (source.commit.clone(), source.how)
        };

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
        // The registry moment travels to the build phase as well as the deps phase. Both call
        // `npm/npx`, and npx downloads the pinned npm before it runs anything — so a build phase
        // without it goes to the default registry and dies at an enforced tier exactly as the deps
        // phase did, one phase later.
        let mut build = BTreeMap::from([
            ("npm_version".to_string(), deps["npm_version"].clone()),
            (
                "registry_time".to_string(),
                deps.get("registry_time").cloned().unwrap_or_default(),
            ),
        ]);
        let mut build_tool = "npm/build/pack";
        if let Some((script, command)) = unrun_build(target)
            && bare_program(&command)
            && let Some(sources) = self.sources.clone()
        {
            let (repo, commit) = (source.repo_url.clone(), commit.clone());
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
                // The resolved commit, which is the registry's where it recorded one and the
                // version's tag where it did not. Using `source.commit` here would put an empty
                // ref in the strategy for exactly the packages this fallback exists for.
                git_ref: commit.clone(),
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
            // How the commit was *actually* found, not how the registry would have found one. A
            // tag is `Confidence::Strong` where a recorded commit is `Certain`, and a reader has to
            // be able to tell which they are looking at.
            confidence: confidence_of(how),
            discovery: how,
            assumptions,
        }])
    }
}

/// PyPI, where the registry knows the repository and nothing else.
///
/// **Holds no HTTP client.** It used to, for the GitHub API tag lookup; that now goes over git
/// protocol, and a field nothing reads is the dead configuration `docs/16-findings.md` §3.15 is
/// about. The resolver it calls talks to a forge through a subprocess, which is paced by nothing
/// here — one `ls-remote` per target.
#[derive(Default)]
pub struct PyPiInferrer {
    mirror: Option<String>,
    sources: Option<std::sync::Arc<crate::SourceCache>>,
}

impl PyPiInferrer {
    pub fn new() -> Self {
        PyPiInferrer::default()
    }

    /// See [`NpmInferrer::with_mirror`].
    pub fn with_mirror(mut self, mirror: Option<String>) -> Self {
        self.mirror = mirror;
        self
    }

    /// Let the rung read the repository, to find out where in it the project lives.
    ///
    /// npm declares this: `repository.directory` is a field, and a PyPI `tree/<ref>/<path>` link
    /// carries it in passing. Neither exists for a project that simply is not at the root of its
    /// repository — `stub42/pytz` keeps its `setup.py` under `src/`, so a checkout at the tag it
    /// released from has no Python project where the recipe looked, and the build failed with
    /// "Source /src does not appear to be a Python project". Nothing in any metadata says where it
    /// is; the repository does.
    pub fn with_sources(mut self, sources: Option<std::sync::Arc<crate::SourceCache>>) -> Self {
        self.sources = sources;
        self
    }
}

/// Where the Python project is in a repository, given everything the repository contains.
///
/// `None` means the root, which is the answer for almost every package and costs nothing to say.
/// Otherwise the one directory holding a `pyproject.toml` or a `setup.py`, or — where several do —
/// the one named after the package.
///
/// Depth 1 only. A project two directories down exists, and finding it would mean ranking
/// candidates from a whole monorepo; the shapes this is for are `src/`, `python/`, and a
/// repository holding two or three siblings.
///
/// Several candidates and no name match yields `None` rather than a guess: building at the root
/// fails with a message that names the problem, and building in the wrong sibling produces a
/// divergence that says nothing about the package.
pub(crate) fn project_root(files: &[String], package: &str) -> Option<String> {
    const MANIFESTS: [&str; 2] = ["pyproject.toml", "setup.py"];
    if files.iter().any(|f| MANIFESTS.contains(&f.as_str())) {
        return None;
    }
    let mut dirs: Vec<&str> = Vec::new();
    for f in files {
        let Some((dir, base)) = f.rsplit_once('/') else {
            continue;
        };
        if dir.contains('/') || !MANIFESTS.contains(&base) {
            continue;
        }
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    match dirs.as_slice() {
        [] => None,
        [one] => Some((*one).to_string()),
        several => {
            let squash = |s: &str| -> String {
                s.chars()
                    .filter(char::is_ascii_alphanumeric)
                    .map(|c| c.to_ascii_lowercase())
                    .collect()
            };
            let wanted = squash(package);
            several
                .iter()
                .find(|d| squash(d) == wanted)
                .map(|d| (*d).to_string())
        }
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
                &source.repo_url,
                &target.reference.version,
                &target.reference.name,
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

        // Where in the repository the project is. A declared subdirectory wins — npm has a field
        // for it and a PyPI `tree/<ref>/<path>` link says it in passing — and where nothing
        // declares one, the repository is asked. `stub42/pytz` keeps its `setup.py` under `src/`,
        // and the build failed with "Source /src does not appear to be a Python project", which
        // reads as a broken checkout rather than as a layout.
        let mut subdir = source.subdir.clone();
        if subdir.is_none()
            && let Some(sources) = self.sources.clone()
        {
            let (repo, at) = (source.repo_url.clone(), commit.clone());
            // On a blocking thread: the checkout shells out to git, and a rung runs inside the
            // runtime that drives a sweep.
            let listed = tokio::task::spawn_blocking(move || {
                sources.checkout(&repo, &at).and_then(|c| c.files(20_000))
            })
            .await;
            match listed {
                Ok(Ok(files)) => {
                    if let Some(found) = project_root(&files, &target.reference.registry_name()) {
                        assumptions.push(format!(
                            "the repository has no Python project at its root; `{found}/` is the \
                             one directory that does, and the build runs there"
                        ));
                        subdir = Some(found);
                    }
                }
                // Not fatal. The recipe built at the root is what this rung produced before this
                // check existed, and a failure to read the repository must not turn a target that
                // resolves into one that does not.
                Ok(Err(e)) => {
                    tracing::debug!(repo = source.repo_url, "could not list the repository: {e}");
                }
                Err(e) => tracing::debug!(repo = source.repo_url, "listing panicked: {e}"),
            }
        }

        // See `VENV`: the path is a constant because four places have to agree on it.
        // `/trigon/deps`, not `/deps`. The root directory of a Debian image is mode 0555, and root
        // writes there only through `CAP_DAC_OVERRIDE` — which the sandbox drops, deliberately and
        // by name. So `python3 -m venv /deps` is `Permission denied` for root, and only at an
        // enforced tier: `defer_deps` moves the deps phase out of the image build and into the
        // container run, so the same recipe worked at `--egress open` with full capabilities and
        // failed at `mirror-only` with none. A build that succeeds at one tier and fails at another
        // for a reason that has nothing to do with the package, reported as the package's fault.
        //
        // `/trigon` is ours and already in the image — the phase scripts are copied there — so it
        // exists at run time, is owned by root at 0755, and needs no capability to write to.
        // `/tmp` would also work today and is the worse choice: it is world-writable, and a tmpfs
        // mounted over it (which `docs/12-security.md` §5 wants) would empty it between the image
        // build and the run without anything saying so.
        let mut deps = BTreeMap::from([("venv".to_string(), VENV.to_string())]);
        // A build must not consume the artifact it is reproducing. Ordinarily nothing tries — but
        // a package that is part of the machinery that builds packages does, because the frontend
        // needs it: rebuilding `packaging` or `pyproject-hooks` makes pip ask for the very version
        // under test, the mirror refuses it, and the build dies. Excluding that one version lets
        // the resolver take the release before it, which is the right thing for a build tool to
        // build itself with.
        deps.insert(
            "exclude_self".into(),
            format!(
                "{}!={}",
                target.reference.registry_name(),
                target.reference.version
            ),
        );
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
                subdir: subdir.clone(),
            },
            src: vec![uses("git-checkout", BTreeMap::new())],
            deps: vec![uses("pypi/deps/basic", deps)],
            build: vec![uses(
                "pypi/build/wheel",
                BTreeMap::from([
                    // **Build what will be compared, not what is usual.** `preferred()` picks the
                    // sdist for a package whose only wheels are platform-specific — correctly,
                    // because such a wheel is built on one machine and does not reproduce on
                    // another — and a wheel built here would then be compared against it. The
                    // comparator took its format from the upstream name and called the sdist a
                    // malformed gzip.
                    (
                        "kind".to_string(),
                        match target.about.as_ref().map(|a| a.kind()) {
                            Some(trigon_core::ArtifactKind::Sdist) => "sdist".to_string(),
                            _ => "wheel".to_string(),
                        },
                    ),
                    // Both derived from `VENV` rather than written out, so the venv the deps
                    // phase creates and the one the build phase looks in cannot come apart. They
                    // were three literals agreeing by eye.
                    ("locator".to_string(), format!("{VENV}/bin/")),
                    // Always set now, not only where a backend was read: the constraints file
                    // also carries the exclusion of the artifact under test, so it is written on
                    // every PyPI build and the build phase has to be pointed at it either way.
                    ("constraints".to_string(), format!("{VENV}/constraints.txt")),
                    // Isolation stays on. `-n` makes the frontend *check* for each declared build
                    // requirement rather than install it, so anything the project needs beyond the
                    // backend goes missing — `attrs` wants `hatch-vcs` and `hatch-fancy-pypi-readme`
                    // and stops with "Unmet dependencies". The backend version is pinned by a
                    // constraint instead, which binds the environment the frontend builds without
                    // taking over what goes into it.
                    ("no_isolation".to_string(), "false".to_string()),
                ]),
            )],
            output_dir: Some(match &subdir {
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

#[cfg(test)]
mod project_root_tests {
    use super::project_root;

    /// What `git ls-files` returns for `stub42/pytz` at the tag it released 2026.1 from, trimmed.
    const PYTZ: &[&str] = &[
        "LICENSE.txt",
        "Makefile",
        "README.md",
        "conf.py",
        "gen_tzinfo.py",
        "src/pytz/__init__.py",
        "src/setup.py",
        "test_zdump.py",
        "tz/africa",
    ];

    fn owned(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn a_project_that_is_not_at_the_root_of_its_repository_is_found() {
        // Nothing in any metadata says where it is: npm's `repository.directory` and a PyPI
        // `tree/<ref>/<path>` link both cover a project that *declares* a subdirectory, and this
        // one simply is not at the root. The build failed with "Source /src does not appear to be
        // a Python project", which reads as a broken checkout.
        assert_eq!(project_root(&owned(PYTZ), "pytz").as_deref(), Some("src"));
    }

    #[test]
    fn the_ordinary_layout_costs_nothing_to_say() {
        // Almost every package. `None` means the root, and the rung behaves exactly as before.
        let flat = owned(&["pyproject.toml", "src/thing/__init__.py", "tests/test.py"]);
        assert_eq!(project_root(&flat, "thing"), None);
        // A root `setup.py` beside a subdirectory that also has one: the root wins, because the
        // root is where the project is and the subdirectory is something it vendors.
        let both = owned(&["setup.py", "vendor/setup.py"]);
        assert_eq!(project_root(&both, "thing"), None);
    }

    #[test]
    fn several_candidates_are_decided_by_the_package_name_or_not_at_all() {
        let siblings = owned(&[
            "google-auth/pyproject.toml",
            "google-cloud-storage/pyproject.toml",
            "README.md",
        ]);
        assert_eq!(
            project_root(&siblings, "google-auth").as_deref(),
            Some("google-auth")
        );
        // Normalized, so `google_auth` in the tree matches `google-auth` on the index.
        let underscored = owned(&["google_auth/setup.py", "other/setup.py"]);
        assert_eq!(
            project_root(&underscored, "google-auth").as_deref(),
            Some("google_auth")
        );
        // And where the name decides nothing, neither does this. Building at the root fails with
        // a message that names the problem; building in the wrong sibling produces a divergence
        // that says nothing about the package.
        assert_eq!(project_root(&siblings, "unrelated"), None);
    }

    #[test]
    fn depth_one_only() {
        // A project two directories down exists, and finding it would mean ranking candidates from
        // a whole monorepo. Stated as a limit rather than discovered as a silent miss.
        let deep = owned(&["packages/python/google-auth/pyproject.toml"]);
        assert_eq!(project_root(&deep, "google-auth"), None);
    }
}
