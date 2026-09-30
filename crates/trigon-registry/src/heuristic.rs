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
use trigon_core::{Confidence, SourceDiscovery};
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
///
/// The CI rung applies the same check to the script a release workflow runs, since it displaces
/// this rung's candidate.
pub(crate) fn bare_program(command: &str) -> bool {
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

/// A step whose every parameter is a literal: handed to the tool as written, never rendered.
///
/// **What this rung passes a tool is data.** A Node or npm version, a publish time, a backend pin,
/// a script name, a crate's name, the version the feed served — each was read from a registry
/// document, the published artifact or the repository, or put together from what was, and a `with`
/// value is a template: text from any of them carrying `{{`, `{%` or `{#` would be evaluated, and
/// the package under test would be writing part of its own recipe. The values this code chooses
/// itself — a path, a flag — are not templates either, so nothing here is.
fn uses(tool: &str, literal: BTreeMap<String, String>) -> Step {
    Step {
        body: StepBody::Uses {
            tool: tool.into(),
            with: BTreeMap::new(),
        },
        needs: Vec::new(),
        when: None,
        literal,
    }
}

/// The commit to build, or one sentence saying why there is none.
///
/// **One function for the decision and the explanation**, because they are the same question asked
/// twice: `infer` needs the commit and `why_not` needs the reason, and two implementations of
/// "why did this decline" drift the moment one of them is edited. The reason is the `Err`.
///
/// Costs one `ls-remote` on the decline path, which by definition is a target nothing is about to
/// build.
async fn commit_for(
    target: &ResolvedTarget,
    registry_recorded_it: bool,
) -> Result<(String, SourceDiscovery, Option<String>), String> {
    let Some(source) = &target.source else {
        return Err("the registry declared no repository for this package".into());
    };
    if !source.commit.is_empty() {
        return Ok((source.commit.clone(), source.how, None));
    }
    match tags::resolve_version_tag(
        &source.repo_url,
        &target.reference.version,
        &target.reference.name,
    )
    .await
    {
        Some((sha, tag, how)) => Ok((sha, how, Some(tag))),
        None => Err(format!(
            "{} declares `{}` and no tag there matches version {}",
            match registry_recorded_it {
                true => "npm recorded no `gitHead`; the package",
                false => "the package",
            },
            source.repo_url,
            target.reference.version
        )),
    }
}

/// The sentence a mutable tag deserves beside a verdict built on it.
/// The opening shared by every rung that has to *find* a commit.
///
/// PyPI, crates.io and NuGet all reach for a tag, because none of their registries records a
/// commit of its own. npm does not share this: it publishes `gitHead`, so its rung asks a
/// different question and keeps its own opening.
///
/// `None` means there is nothing to infer from — no declared repository, or no commit findable —
/// which is the one empty candidate list all three callers already returned for either case.
///
/// The tag assumption travels with the commit because it is a fact about *how* the commit was
/// found: a tag can be moved or deleted after a release, so this is where it points today rather
/// than what the registry recorded at publish time.
async fn found_commit(
    target: &ResolvedTarget,
) -> Option<(
    &trigon_core::SourceProvenance,
    String,
    SourceDiscovery,
    Vec<String>,
)> {
    let source = target.source.as_ref()?;
    let (commit, how, tag) = commit_for(target, false).await.ok()?;
    let assumptions = tag.map(|t| vec![from_a_tag(&t)]).unwrap_or_default();
    Some((source, commit, how, assumptions))
}

fn from_a_tag(tag: &str) -> String {
    format!(
        "the commit comes from tag `{tag}` rather than from the registry, and a tag is mutable: \
         this is where it points today, not necessarily what was published"
    )
}

/// npm, where the registry already knows almost everything.
pub struct NpmInferrer {
    client: Client,
    mirror: Option<String>,
    sources: Option<std::sync::Arc<crate::SourceCache>>,
}

/// Whether a version string recorded by the registry is a plain `x.y.z`.
///
/// Exactly three all-numeric components, and the gate on two different fields for two different
/// reasons.
///
/// `_nodeVersion`: `8.0.0-pre` fails on the third component, which is what a Node built from
/// `master` reports before 8.0.0 is cut, and no distribution host ever carried it. io.js versions
/// like `1.6.4` pass, because they are real releases — `npm/install-node` routes majors 1 to 3 to
/// iojs.org and fetches the publisher's own binary.
///
/// `_npmVersion`: the field is whatever the publishing client put there, and a publishing client is
/// not always npm. `framer-motion@12.36.0` records
/// `lerna/4.0.0/node@v22.14.0+arm64 (darwin)` — a user-agent string. That reached
/// `npm install -g npm@…` unquoted and the parenthesis ended the deps phase with
/// `Syntax error: "(" unexpected`, filed as `unknown` and charged to the package. A value that is
/// not a version cannot be installed, so there is nothing to salvage and the rung declines.
///
/// The CI rung gates both fields on it too, since it displaces this rung's candidate.
pub(crate) fn is_plain_version(version: &str) -> bool {
    let numeric =
        |p: Option<&str>| p.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    let mut parts = version.split('.');
    numeric(parts.next())
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_none()
}

/// Sort key for a plain `x.y.z`, so "highest" means highest *number* and not longest string.
fn node_order(version: &str) -> (u64, u64, u64) {
    let mut p = version.split('.').map(|x| x.parse::<u64>().unwrap_or(0));
    (
        p.next().unwrap_or(0),
        p.next().unwrap_or(0),
        p.next().unwrap_or(0),
    )
}

/// The highest Node release published at or before `instant`.
///
/// **Highest by number, not newest by date, and the difference decides whether the build runs.**
/// Node maintains several lines at once, so the most recent *release event* before an instant is
/// often an old LTS patch: on 2017-03-21 Node shipped both 4.8.1 and 7.7.4. Measured on
/// `isexe@2.0.0`, whose recorded npm is 4.4.2 — under 4.8.1 the deps phase dies installing that
/// npm, under 7.7.4 the package reproduces with every member identical. Picking by date would have
/// chosen the one that cannot run the toolchain the registry recorded.
///
/// Filtered to releases that actually ship `linux-x64`, because that is the file
/// `npm/install-node` asks for and a release without it would 404 exactly as the pre-release does.
///
/// Fetched rather than computed: Node's releases are irregular, so there is no train to derive them
/// from the way `cargo_current_at` derives Cargo's. Only reached when the recorded version is
/// unfetchable, which across the npm corpus is one target in 197.
async fn highest_node_release_at(client: &Client, instant: &str) -> Option<String> {
    // `index.json` dates are `YYYY-MM-DD`; a publish instant is RFC 3339 and starts with one.
    let day = instant.get(..10)?;
    let body = client
        .get("https://nodejs.org/dist/index.json", "npm")
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let index: Vec<serde_json::Value> = serde_json::from_str(&body).ok()?;
    highest_release_in(&index, day)
}

/// The choice [`highest_node_release_at`] makes, apart from the fetch, over `index.json`'s entries.
fn highest_release_in(index: &[serde_json::Value], day: &str) -> Option<String> {
    index
        .iter()
        .filter(|e| e["date"].as_str().is_some_and(|d| d <= day))
        .filter(|e| {
            e["files"]
                .as_array()
                .is_some_and(|f| f.iter().any(|x| x.as_str() == Some("linux-x64")))
        })
        .filter_map(|e| e["version"].as_str()?.strip_prefix('v'))
        .filter(|v| is_plain_version(v))
        .max_by_key(|v| node_order(v))
        .map(str::to_string)
}

/// Whether a Cargo release understands a `sparse+http://` registry.
///
/// Sparse registries were stabilized in **1.68.0**. Below that the scheme prefix is not recognized
/// and Cargo resolves `sparse+http` as a hostname, so the check is on the pinned toolchain rather
/// than on the error it would otherwise produce.
///
/// A version that will not parse is treated as **not** speaking sparse: the consequence of being
/// wrong in that direction is a stated assumption and a run at open egress, and in the other
/// direction it is a libgit2 DNS error several layers from the cause.
fn speaks_sparse(version: &str) -> bool {
    let mut parts = version.split(['.', '-', '+']);
    let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
        return false;
    };
    match (major.parse::<u32>(), minor.parse::<u32>()) {
        (Ok(major), Ok(minor)) => (major, minor) >= (1, 68),
        _ => false,
    }
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
        let Ok((commit, how, tag)) = commit_for(target, true).await else {
            // The reason is `why_not`'s, which asks the same function.
            return Ok(Vec::new());
        };
        if let Some(tag) = tag {
            assumptions.push(from_a_tag(&tag));
        }

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
        // **`_npmVersion` is whatever the publishing client wrote, and it is not always a version.**
        // Unlike `_nodeVersion` there is no substitution to make: a user-agent string names no npm
        // release, and the publisher's actual npm is not recoverable from it. Declining says that;
        // passing it on produced a shell syntax error inside our own deps script and reported the
        // package as broken.
        if !is_plain_version(&npm) {
            tracing::debug!(
                npm,
                "the registry recorded a publishing client rather than an npm version; declining"
            );
            return Ok(Vec::new());
        }

        // **A `_nodeVersion` no host serves, replaced by the nearest one that does.** The publisher
        // used a Node built from master — `isexe@2.0.0` records `8.0.0-pre` — and nodejs.org never
        // published it, so the toolchain fetch 404s at every egress tier. Declining would be honest
        // and would lose the target; substituting silently would answer a different question from
        // the one asked. So it substitutes and says so, which is what `assumptions` is for.
        //
        // The npm that packs the tarball is still the recorded one, and that is the half that
        // shapes the artifact: `npm pack`'s manifest rewrite is npm's behaviour, not Node's.
        let node = if is_plain_version(&node) {
            node
        } else {
            let Some(publish) = target.intrinsics.publish_time.as_deref() else {
                tracing::debug!(
                    node,
                    "an unfetchable _nodeVersion and no publish time to resolve it against"
                );
                return Ok(Vec::new());
            };
            let Some(nearest) = highest_node_release_at(&self.client, publish).await else {
                tracing::debug!(
                    node,
                    "could not resolve a Node release at the publish instant"
                );
                return Ok(Vec::new());
            };
            assumptions.push(format!(
                "the registry records Node {node} for this publish, which is a build from master \
                 rather than a release and exists on no distribution host; this builds with \
                 {nearest}, the highest Node released at or before the publish instant. The npm \
                 that packs the tarball is still the one the registry recorded, and for a package \
                 with no build step that is what shapes the artifact — but a package whose build \
                 runs under Node could differ, and this run cannot tell you it did not"
            ));
            nearest
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
        // **The script name is what reaches a shell; the command body never does.** The tool runs
        // `npm run <script>`, so validating the command rejected every composite build — `&&` is
        // not in the allowlist, and `npm run clean && npm run compile` is the commonest shape in
        // this ecosystem. The name is still publisher-controlled and still checked, which is the
        // part that matters.
        if let Some((script, command)) = unrun_build(target)
            && bare_program(&script)
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

    /// Why this rung said nothing. Asks [`commit_for`], which is what `infer` asked.
    ///
    /// The commit is the only thing this rung declines over that a reader cannot see for
    /// themselves; a missing `_nodeVersion` is named too, because "npm did not record the
    /// toolchain" and "we could not find the commit" send a reader to different places.
    async fn why_not(&self, target: &ResolvedTarget) -> Option<String> {
        if let Err(why) = commit_for(target, true).await {
            return Some(why);
        }
        let toolchain = evidence_value(target, "npm:_nodeVersion")
            .zip(evidence_value(target, "npm:_npmVersion"));
        toolchain.is_none().then(|| {
            "the registry recorded no `_nodeVersion`/`_npmVersion`, and a modern npm packs a \
             tarball a 2018 npm would not have"
                .to_string()
        })
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
        // PyPI records no commit, so one has to be found. A tag is the cheap rung and it is right
        // for most projects that tag releases at all — see [`found_commit`] for what that costs in
        // certainty.
        let Some((source, commit, how, mut assumptions)) = found_commit(target).await else {
            return Ok(Vec::new());
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

        let mut deps = pypi_deps(target);
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
            build: vec![uses("pypi/build/wheel", pypi_build(target))],
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

    /// Why this rung said nothing. Asks [`commit_for`], which is what `infer` asked.
    async fn why_not(&self, target: &ResolvedTarget) -> Option<String> {
        commit_for(target, false).await.err()
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

/// What `pypi/deps/basic` is given on every PyPI build, whichever rung lowered the recipe.
///
/// One construction for this rung and the CI rung (`ci/lower.rs`), because two drifted: the CI
/// lowering was written beside this one, and when the exclusion and the always-written constraints
/// file arrived here it kept the shape from before them. The CI rung sits above this one and
/// displaces its candidate, so a recipe from it put the artifact under test back within reach of
/// its own build.
pub(crate) fn pypi_deps(target: &ResolvedTarget) -> BTreeMap<String, String> {
    // See `VENV`: the path is a constant because four places have to agree on it.
    // `/trigon/deps`, not `/deps`. The root directory of a Debian image is mode 0555, and root
    // writes there only through `CAP_DAC_OVERRIDE` — which the sandbox drops, deliberately and by
    // name. So `python3 -m venv /deps` is `Permission denied` for root, and only at an enforced
    // tier: `defer_deps` moves the deps phase out of the image build and into the container run, so
    // the same recipe worked at `--egress open` with full capabilities and failed at `mirror-only`
    // with none. A build that succeeds at one tier and fails at another for a reason that has
    // nothing to do with the package, reported as the package's fault.
    //
    // `/trigon` is ours and already in the image — the phase scripts are copied there — so it
    // exists at run time, is owned by root at 0755, and needs no capability to write to. `/tmp`
    // would also work today and is the worse choice: it is world-writable, and a tmpfs mounted over
    // it (which `docs/12-security.md` §5 wants) would empty it between the image build and the run
    // without anything saying so.
    let mut deps = BTreeMap::from([("venv".to_string(), VENV.to_string())]);
    // A build must not consume the artifact it is reproducing. Ordinarily nothing tries — but a
    // package that is part of the machinery that builds packages does, because the frontend needs
    // it: rebuilding `packaging` or `pyproject-hooks` makes pip ask for the very version under
    // test, the mirror refuses it, and the build dies. Excluding that one version lets the resolver
    // take the release before it, which is the right thing for a build tool to build itself with.
    deps.insert(
        "exclude_self".into(),
        format!(
            "{}!={}",
            target.reference.registry_name(),
            target.reference.version
        ),
    );
    deps
}

/// What `pypi/build/wheel` is given on every PyPI build, whichever rung lowered the recipe. See
/// [`pypi_deps`] for why the two rungs share it.
pub(crate) fn pypi_build(target: &ResolvedTarget) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("kind".to_string(), pypi_kind(target).to_string()),
        // Both derived from `VENV` rather than written out, so the venv the deps phase creates and
        // the one the build phase looks in cannot come apart. They were three literals agreeing by
        // eye.
        ("locator".to_string(), format!("{VENV}/bin/")),
        // Always set now, not only where a backend was read: the constraints file also carries the
        // exclusion of the artifact under test, so it is written on every PyPI build and the build
        // phase has to be pointed at it either way.
        ("constraints".to_string(), format!("{VENV}/constraints.txt")),
        // Isolation stays on. `-n` makes the frontend *check* for each declared build requirement
        // rather than install it, so anything the project needs beyond the backend goes missing —
        // `attrs` wants `hatch-vcs` and `hatch-fancy-pypi-readme` and stops with "Unmet
        // dependencies". The backend version is pinned by a constraint instead, which binds the
        // environment the frontend builds without taking over what goes into it.
        ("no_isolation".to_string(), "false".to_string()),
    ])
}

/// Which distribution a PyPI recipe builds: `sdist` or `wheel`, as `pypi/build/wheel`'s `kind`.
///
/// **Build what will be compared, not what is usual.** `preferred()` picks the sdist for a package
/// whose only wheels are platform-specific — correctly, because such a wheel is built on one
/// machine and does not reproduce on another — and a wheel built here would then be compared
/// against it. The comparator took its format from the upstream name and called the sdist a
/// malformed gzip. A wheel where nothing has chosen yet.
pub(crate) fn pypi_kind(target: &ResolvedTarget) -> &'static str {
    match target.about.as_ref().map(|a| a.kind()) {
        Some(trigon_core::ArtifactKind::Sdist) => "sdist",
        _ => "wheel",
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

/// crates.io, where the registry records more about the build than any other and the artifact is
/// harder to reproduce than any other.
///
/// The recipe is one command. What makes this ecosystem difficult is not the recipe but the
/// **toolchain window**: `cargo package` rewrites `Cargo.toml` on the way into the tarball and the
/// rewrite rules changed across Cargo releases, so the manifest inside the published `.crate` is a
/// fingerprint of the Cargo that made it. This rung does not read that fingerprint. It pins what
/// the registry stated — the `edition` floor, carried as a `ToolchainRange` by the resolver — and
/// says so, because a window this rung guessed at is a window nobody can check.
#[derive(Default)]
pub struct CratesIoInferrer {
    mirror: Option<String>,
}

impl CratesIoInferrer {
    pub fn new() -> Self {
        CratesIoInferrer::default()
    }

    /// See [`NpmInferrer::with_mirror`].
    pub fn with_mirror(mut self, mirror: Option<String>) -> Self {
        self.mirror = mirror;
        self
    }
}

#[async_trait]
impl StrategyInferrer for CratesIoInferrer {
    fn name(&self) -> &'static str {
        "cargo-heuristic"
    }

    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        // `.cargo_vcs_info.json` inside the published `.crate` gives the commit exactly, and the
        // run reads it before inference — so unlike PyPI this rung usually has one already and the
        // tag ladder is the fallback rather than the rule.
        let Some((source, commit, how, mut assumptions)) = found_commit(target).await else {
            return Ok(Vec::new());
        };

        // The toolchain, from the edition floor the resolver recorded. A floor is not a version, so
        // this says which it is: the lowest Cargo that could have packaged this edition, which is
        // right for a crate published soon after an edition landed and wrong by years for one
        // published later.
        let rust = trigon_core::resolve_toolchain("cargo", &target.intrinsics.evidence);
        let pinned = match &rust {
            trigon_core::ToolchainResolution::Pinned { version } => Some(version.clone()),
            // **A floor is not an estimate.** `edition = "2018"` puts Cargo at 1.31 or newer, and
            // building a crate published in 2025 with Cargo 1.31 is wrong by seven years and
            // thirty-odd releases — it fails outright, because `cargo package -p` did not exist
            // then. The publish date is the better evidence and it is already here.
            trigon_core::ToolchainResolution::Window { lo, .. } => {
                let floor = lo.clone();
                match target
                    .intrinsics
                    .publish_time
                    .as_deref()
                    .and_then(cargo_current_at)
                {
                    Some(v) => {
                        assumptions.push(format!(
                            "the crate's edition puts Cargo at {} or newer, and this builds with \
                             {v} — the release current when the crate was published, computed from \
                             Cargo's six-week train. The manifest rewrite inside the published \
                             `.crate` is a tighter fingerprint and this rung does not read it, so \
                             a crate packaged on an older or a nightly toolchain will diverge in \
                             `Cargo.toml` and nowhere else",
                            floor.as_deref().unwrap_or("any version")
                        ));
                        Some(v)
                    }
                    // A floor alone. Said as a floor rather than dressed up as a version.
                    None => floor.map(|lo| {
                        assumptions.push(format!(
                            "no publish time, so this builds with {lo} — the *oldest* Cargo that \
                             could have packaged this edition rather than an estimate of the one \
                             that did"
                        ));
                        lo
                    }),
                }
            }
            _ => None,
        };
        let Some(rust_version) = pinned else {
            tracing::debug!("no toolchain evidence for this crate; declining rather than guessing");
            return Ok(Vec::new());
        };

        let rust_for_steps = rust_version.clone();
        let mut deps = BTreeMap::from([("rust_version".to_string(), rust_version)]);
        let mut deps_steps: Vec<Step> = Vec::new();
        if let Some(m) = &self.mirror {
            // **The host is part of the path.** The mirror's toolchain route is
            // `/-toolchain/<host>/<path>`, so a base without the host makes the mirror read
            // `rustup` as the upstream host and refuse it — and `wget -q` reported that as
            // nothing at all.
            deps.insert(
                "toolchain_base".into(),
                format!("http://{m}/-toolchain/static.rust-lang.org"),
            );
        } else {
            assumptions.push(
                "no mirror configured, so the toolchain is fetched from static.rust-lang.org \
                 directly"
                    .into(),
            );
        }

        deps_steps.push(uses("cargo/install-rust", deps));

        // **Cargo has to be pointed at the mirror as well as told where its toolchain lives.**
        // `cargo package` resolves the dependency graph in order to write the `Cargo.lock` that
        // goes inside the `.crate`, so it reaches `index.crates.io` even with `--no-verify` and
        // even for a crate whose dependencies it will never compile. Without this step that fetch
        // has nowhere to go at `mirror-only` and the build dies in libcurl — which is what
        // `pkg:cargo/hashbrown@0.17.1` did, reported as `unknown`.
        if let Some(m) = &self.mirror {
            match target.intrinsics.publish_time.as_deref() {
                // **Only a Cargo that speaks the sparse protocol.** It landed in 1.68; an older one
                // reads `sparse+http://host/` as a URL whose *host* is `sparse+http` and dies in
                // libgit2 with `failed to resolve address for sparse+http`, which reads as DNS
                // rather than as a protocol it does not have. `rand@0.8.5` pins 1.58.0 and did
                // exactly that. The alternative for those is a git index, which this mirror does
                // not serve — so the run says what it cannot do instead of failing obscurely.
                Some(t) if speaks_sparse(&rust_for_steps) => {
                    deps_steps.push(uses(
                        "cargo/setup-registry",
                        BTreeMap::from([
                            ("registry_time".to_string(), t.to_string()),
                            ("index_base".to_string(), format!("http://{m}/-cargo")),
                        ]),
                    ));
                    // Stated on every run that resolves through the mirror, because it cannot be
                    // known per-run whether it mattered: crates.io publishes no yank timestamp, in
                    // the index or the API, so "was this version yanked that day" is unanswerable.
                    assumptions.push(
                        "dependencies resolve against the crates.io index as it stood at the \
                         publish instant, except for yank state, which crates.io never timestamps \
                         — a version yanked since is offered as live, because treating today's \
                         yanks as facts about that day made Cargo resolve an older dependency than \
                         the publisher did and the lockfile differ because of it"
                            .into(),
                    );
                }
                Some(_) => assumptions.push(format!(
                    "this crate pins Cargo {rust_for_steps}, which predates the sparse registry \
                     protocol Cargo gained in 1.68 — the mirror serves no git index, so dependency \
                     resolution cannot be pinned to the publish instant and this needs \
                     `--egress open` to build at all"
                )),
                // No instant to pin to, so the index is not configured at all rather than
                // configured to *now*. A mirror serving today's index under a moment nobody chose
                // resolves a dependency graph that never existed, and does it silently; a build
                // that cannot reach the index says so in the log.
                None => assumptions.push(
                    "no publish time for this crate, so the index is not pinned and dependency \
                     resolution is not reproducible — this needs `--egress open` to build at all"
                        .into(),
                ),
            }
        }

        let strategy = Strategy::Flow(FlowStrategy {
            location: Location {
                repo: source.repo_url.clone(),
                git_ref: commit,
                subdir: source.subdir.clone(),
            },
            src: vec![uses("git-checkout", BTreeMap::new())],
            deps: deps_steps,
            build: vec![uses(
                "cargo/build/package",
                // The crate's own name, which selects it out of a workspace. Always passed rather
                // than only where a workspace is suspected: `-p serde` in a single-package
                // repository names the one package there is, and guessing which shape a repository
                // has before checking it out is the guess this avoids.
                {
                    let mut b =
                        BTreeMap::from([("package".to_string(), target.reference.name.clone())]);
                    // The build phase needs it too, not only the deps phase: a repository with a
                    // `rust-toolchain.toml` turns `cargo` into a rustup proxy that installs
                    // components on demand, and it does that here.
                    if let Some(m) = &self.mirror {
                        b.insert(
                            "toolchain_base".to_string(),
                            format!("http://{m}/-toolchain/static.rust-lang.org"),
                        );
                    }
                    b
                },
            )],
            // Relative to the checkout, which is what `output_dir` means. `cargo package` writes
            // into `<target-dir>/package/`, and the tool's target directory is `target` for the
            // reason its own docs give.
            output_dir: Some("target/package".into()),
            output_path: None,
        });

        Ok(vec![Candidate {
            strategy,
            derivation: Derivation::Heuristic,
            confidence: confidence_of(how).max(Confidence::Weak),
            discovery: how,
            assumptions,
        }])
    }

    async fn why_not(&self, target: &ResolvedTarget) -> Option<String> {
        if let Err(why) = commit_for(target, false).await {
            return Some(why);
        }
        match trigon_core::resolve_toolchain("cargo", &target.intrinsics.evidence) {
            trigon_core::ToolchainResolution::Pinned { .. }
            | trigon_core::ToolchainResolution::Window { lo: Some(_), .. } => None,
            _ => Some(
                "crates.io declared no edition for this version, so there is no floor for the \
                 Cargo that packaged it and any version this rung picked would be a guess"
                    .into(),
            ),
        }
    }
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

/// The Cargo release current on a given day.
///
/// Arithmetic rather than a table, because Rust has shipped on a **six-week train** since 1.0 on
/// 2015-05-15 and has not missed one. `docs/03-ecosystems.md` calls toolchain-window inference the
/// game for this ecosystem; this is the cheap opening move, accurate to within a release, and it
/// beats the edition floor by years for any crate published long after its edition landed.
///
/// What it is not: the fingerprint. The published `.crate` carries a `Cargo.toml` that Cargo
/// rewrote, and the rewrite rules changed across releases — pretty arrays from 1.60, a header
/// comment from 1.55 — so the artifact itself pins the window far tighter than a date does.
/// Reading it is the real answer and is recorded in `docs/17-backlog.md` rather than done here.
///
/// A date before 1.0 gives `None`: crates.io predates the six-week train and nothing here can say
/// what packaged something from 2014.
fn cargo_current_at(rfc3339: &str) -> Option<String> {
    let days = days_since_epoch(rfc3339)?;
    const RUST_1_0: i64 = 16_570; // 2015-05-15
    const TRAIN: i64 = 42;
    let elapsed = days.checked_sub(RUST_1_0).filter(|d| *d >= 0)?;
    Some(format!("1.{}.0", elapsed / TRAIN))
}

/// Days from 1970-01-01 for the `YYYY-MM-DD` at the head of an RFC 3339 instant.
///
/// Only the date, because the train is six weeks wide and an hour cannot change the answer.
fn days_since_epoch(rfc3339: &str) -> Option<i64> {
    let d = rfc3339.get(..10)?;
    let mut it = d.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let day: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    // Howard Hinnant's days-from-civil, which is exact for the whole proleptic Gregorian calendar
    // and needs no leap-year special cases at the call site.
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod cargo_train_tests {
    use super::{cargo_current_at, days_since_epoch};

    #[test]
    fn the_epoch_and_the_train_line_up_with_real_releases() {
        // Anchors taken from Rust's own release history. Within one release is the accuracy this
        // claims, and the assumption text says so.
        for (date, want) in [
            ("2015-05-15T00:00:00Z", "1.0.0"),
            ("2021-10-21T00:00:00Z", "1.56.0"), // edition 2021 landed here
            ("2025-02-20T00:00:00Z", "1.85.0"), // edition 2024 landed here
        ] {
            let got = cargo_current_at(date).unwrap();
            let n = |v: &str| v.split('.').nth(1).unwrap().parse::<i64>().unwrap();
            assert!(
                (n(&got) - n(want)).abs() <= 1,
                "{date}: got {got}, expected about {want}"
            );
        }
    }

    #[test]
    fn a_date_before_the_train_is_not_a_guess() {
        // crates.io predates 1.0, and nothing here can say what packaged something from 2014.
        assert_eq!(cargo_current_at("2014-01-01T00:00:00Z"), None);
        assert_eq!(cargo_current_at("not-a-date"), None);
        assert_eq!(cargo_current_at(""), None);
    }

    #[test]
    fn the_civil_calendar_conversion_is_exact() {
        assert_eq!(days_since_epoch("1970-01-01T00:00:00Z"), Some(0));
        // A leap day, and the day after a century that is not a leap year.
        assert_eq!(days_since_epoch("2000-02-29T00:00:00Z"), Some(11016));
        assert_eq!(days_since_epoch("1900-03-01T00:00:00Z"), Some(-25508));
        assert_eq!(days_since_epoch("2026-09-16T10:00:00Z"), Some(20712));
    }
}

// --- nuget ---------------------------------------------------------------------------------------

/// The `.csproj` that builds a given package, out of a repository listing.
///
/// .NET repositories put the project somewhere by convention rather than by declaration: usually
/// `src/<PackageId>/<PackageId>.csproj`, sometimes `<PackageId>/<PackageId>.csproj`, sometimes at
/// the root. Nothing in the `.nuspec` says which, so the file name is the evidence — a project
/// whose name matches the package id, preferring the shallowest.
///
/// Matched on a squashed form, because a package id and a directory name disagree about separators
/// far more often than about letters: `Microsoft.Extensions.Logging` lives in
/// `src/Microsoft.Extensions.Logging/`, but plenty of projects publish `Foo.Bar` out of `FooBar/`.
pub(crate) fn nuget_project(files: &[String], package: &str) -> Option<String> {
    let squash = |s: &str| -> String {
        s.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    let wanted = squash(package);

    let mut best: Option<(usize, String)> = None;
    for f in files {
        let Some(stem) = f.strip_suffix(".csproj") else {
            continue;
        };
        let base = stem.rsplit_once('/').map(|(_, b)| b).unwrap_or(stem);
        if squash(base) != wanted {
            continue;
        }
        // The directory holding it, which is what the tools take as `dir`.
        let dir = f.rsplit_once('/').map(|(d, _)| d.to_string());
        let depth = dir
            .as_deref()
            .map(|d| d.matches('/').count() + 1)
            .unwrap_or(0);
        let candidate = dir.unwrap_or_else(|| ".".to_string());
        // **Ties are refused rather than broken.** Two projects of the same name at the same depth
        // — `src/Foo/Foo.csproj` and `test/Foo/Foo.csproj` is a real shape — means the evidence
        // does not identify one, and picking either would be a guess wearing a heuristic's name.
        match &best {
            Some((d, existing)) if *d == depth && existing != &candidate => return None,
            Some((d, _)) if *d <= depth => {}
            _ => best = Some((depth, candidate)),
        }
    }
    best.map(|(_, d)| d)
}

/// The project that *declares* this package id, from the `.csproj` files themselves.
///
/// Better evidence than the file name, and needed because the two disagree often: `Humanizer.Core`
/// is built from `src/Humanizer/Humanizer.csproj`, and `System.Text.Json` from a directory that
/// matches only by accident of convention. A `.csproj` carrying `<PackageId>` says outright what it
/// publishes, and nothing else in a repository does.
///
/// Takes `(path, contents)` rather than reading, so the matching is testable without a checkout.
pub(crate) fn nuget_project_by_id(projects: &[(String, String)], package: &str) -> Option<String> {
    let wanted = package.to_ascii_lowercase();
    let mut found: Option<String> = None;
    for (path, body) in projects {
        let Some(start) = body.find("<PackageId>") else {
            continue;
        };
        let rest = &body[start + "<PackageId>".len()..];
        let Some(end) = rest.find("</PackageId>") else {
            continue;
        };
        let declared = rest[..end].trim();
        // An MSBuild property reference — `<PackageId>$(AssemblyName).Core</PackageId>` — is not an
        // answer. Evaluating it needs MSBuild, and guessing at it would be worse than falling
        // through to the name match.
        if declared.contains('$') || declared.to_ascii_lowercase() != wanted {
            continue;
        }
        let dir = path
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_else(|| ".".to_string());
        match &found {
            // Two projects claiming the same package id is a repository we do not understand, and
            // picking one would be a guess. Refused, as the name matcher refuses a tie.
            Some(existing) if existing != &dir => return None,
            _ => found = Some(dir),
        }
    }
    found
}

/// NuGet, where the packaging is deterministic and the toolchain is the whole question.
///
/// The `.nuspec` inside a published package can carry `<repository commit="…">`, and where it does
/// this rung has the commit exactly. NuGet only began recording it around 2018, so for anything
/// older the tag ladder is the rule rather than the fallback — the reverse of crates.io.
#[derive(Default)]
pub struct NuGetInferrer {
    mirror: Option<String>,
    sources: Option<std::sync::Arc<crate::SourceCache>>,
}

impl NuGetInferrer {
    pub fn new() -> Self {
        NuGetInferrer::default()
    }

    /// See [`NpmInferrer::with_mirror`].
    pub fn with_mirror(mut self, mirror: Option<String>) -> Self {
        self.mirror = mirror;
        self
    }

    pub fn with_sources(mut self, sources: Option<std::sync::Arc<crate::SourceCache>>) -> Self {
        self.sources = sources;
        self
    }
}

#[async_trait]
impl StrategyInferrer for NuGetInferrer {
    fn name(&self) -> &'static str {
        "nuget-heuristic"
    }

    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        let Some((source, commit, how, mut assumptions)) = found_commit(target).await else {
            return Ok(Vec::new());
        };

        // Where the project is. Declared subdirectory first; otherwise the repository is asked,
        // exactly as the PyPI rung does for a `setup.py` that is not at the root.
        let mut subdir = source.subdir.clone();
        if subdir.is_none()
            && let Some(sources) = self.sources.clone()
        {
            let (repo, at) = (source.repo_url.clone(), commit.clone());
            let listed = tokio::task::spawn_blocking(move || {
                let c = sources.checkout(&repo, &at)?;
                let files = c.files(20_000)?;
                // Bounded on both axes. A repository with hundreds of projects is a monorepo whose
                // answer is not going to be found by reading all of them, and a `.csproj` is a
                // small file — one that is not is not a project file.
                let paths: Vec<&str> = files
                    .iter()
                    .filter(|f| f.ends_with(".csproj"))
                    .take(64)
                    .map(String::as_str)
                    .collect();
                let projects = c.read(&paths, 256 * 1024);
                Ok::<_, crate::RegistryError>((files, projects))
            })
            .await;
            match listed {
                Ok(Ok((files, projects))) => {
                    // Declared first, guessed second. A `.csproj` that says `<PackageId>` is
                    // evidence; a directory whose name happens to match is a convention.
                    if let Some(found) = nuget_project_by_id(&projects, &target.reference.name) {
                        assumptions.push(format!(
                            "`{found}` holds the `.csproj` that declares \
                             `<PackageId>{}</PackageId>`, and the build runs there",
                            target.reference.name
                        ));
                        subdir = Some(found);
                    } else if let Some(found) = nuget_project(&files, &target.reference.name) {
                        assumptions.push(format!(
                            "no `.csproj` declares this package id, so the build runs in \
                             `{found}` — the one project *named* for the package, which is a \
                             convention rather than a declaration"
                        ));
                        subdir = Some(found);
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!(repo = source.repo_url, "could not list the repository: {e}");
                }
                Err(e) => tracing::debug!("listing the repository panicked: {e}"),
            }
        }

        // **The assumption this rung cannot discharge.** A `.nupkg` records which tool packed it —
        // `NuGet.Build.Tasks.Pack, Version=4.5.0.4, …;Microsoft Windows NT 10.0` for
        // Newtonsoft.Json 11.0.1 — and that is the only toolchain evidence NuGet publishes.
        // It names the *packer*, not the compiler, and the compiler is what decides the IL. So
        // unlike crates.io there is no version to derive, and the SDK in the image is what builds.
        // Said plainly, because a `divergent` verdict caused by an SDK mismatch is otherwise
        // indistinguishable from one caused by the source.
        assumptions.push(
            "NuGet publishes no compiler version, so this builds with whatever .NET SDK the base \
             image carries. Roslyn compiles deterministically, so a matching SDK reproduces the \
             assembly byte for byte and a different one diverges throughout — a divergence here is \
             as likely to be the toolchain as the source"
                .into(),
        );

        // The feed, pointed at the mirror where one is running. The moment travels in the path
        // rather than in credentials: `dotnet restore` is handed a `--source` URL and sends no
        // userinfo with it, so a moment carried the npm way would be silently dropped.
        let mut restore = BTreeMap::new();
        match (&target.intrinsics.publish_time, &self.mirror) {
            (Some(t), Some(m)) => {
                restore.insert(
                    "source".to_string(),
                    format!("http://{m}/-nuget/{t}/index.json"),
                );
            }
            // A mirror with no publish time to pin it to would serve an unfiltered feed under a
            // name that claims filtering. Refused rather than pinned to nothing.
            (None, Some(_)) => {
                assumptions.push(
                    "the feed declared no publish time for this version, so there is no moment to \
                     pin the index to and dependencies resolve against today's feed"
                        .into(),
                );
            }
            (_, None) => assumptions.push(
                "no mirror is in front of this build, so `dotnet restore` resolves against the \
                 live feed rather than against it as it stood when this version was published. A \
                 dependency published since then can reach this build, and nothing would notice"
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
            deps: vec![uses("nuget/restore", restore)],
            build: vec![uses(
                "nuget/build/pack",
                BTreeMap::from([(
                    // The version the feed served. .NET projects routinely carry a placeholder in
                    // the committed `.csproj` and have CI stamp the real one at publish, so a
                    // checkout at the release tag would otherwise pack `1.0.0`.
                    "version".to_string(),
                    target.reference.version.clone(),
                )]),
            )],
            // **Not joined with the subdir**, which is the mistake that cost a working build:
            // `dotnet pack -o <relative>` resolves against the working directory, and that is the
            // checkout root however deep the project is. Polly packed to `/src/trigon-pack` while
            // collection looked in `/src/src/Polly/trigon-pack`, so a build that had succeeded
            // reported as a failure to find its own output.
            output_dir: Some("trigon-pack".into()),
            // **`*.nupkg`, not the whole directory.** `dotnet pack` writes a symbols package beside
            // the package — `Polly.8.2.0.snupkg` next to `Polly.8.2.0.nupkg` — and collecting the
            // directory handed the comparison the symbols one. It compared cleanly and reported
            // `divergent` with every `lib/*/Polly.dll` "only in upstream" and a `.pdb` in its
            // place: a real verdict about the wrong file, which is worse than a failure.
            //
            // `.snupkg` does not end in `.nupkg`, so this glob separates them exactly.
            output_path: Some("trigon-pack/*.nupkg".into()),
        });

        Ok(vec![Candidate {
            strategy,
            derivation: Derivation::Heuristic,
            confidence: confidence_of(how).max(Confidence::Weak),
            discovery: how,
            assumptions,
        }])
    }

    async fn why_not(&self, target: &ResolvedTarget) -> Option<String> {
        if let Err(why) = commit_for(target, false).await {
            return Some(why);
        }
        None
    }
}

#[cfg(test)]
mod nuget_project_tests {
    use super::nuget_project;

    fn owned(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn the_conventional_layout_is_found() {
        let files = owned(&[
            "README.md",
            "Newtonsoft.Json.sln",
            "Src/Newtonsoft.Json/Newtonsoft.Json.csproj",
            "Src/Newtonsoft.Json.Tests/Newtonsoft.Json.Tests.csproj",
        ]);
        assert_eq!(
            nuget_project(&files, "Newtonsoft.Json").as_deref(),
            Some("Src/Newtonsoft.Json")
        );
    }

    #[test]
    fn a_project_at_the_root_reports_the_root() {
        let files = owned(&["Foo.csproj", "Class1.cs"]);
        assert_eq!(nuget_project(&files, "Foo").as_deref(), Some("."));
    }

    #[test]
    fn separators_do_not_have_to_agree() {
        // `Foo.Bar` published out of `FooBar/`, which is common enough to be worth matching.
        let files = owned(&["src/FooBar/FooBar.csproj"]);
        assert_eq!(
            nuget_project(&files, "Foo.Bar").as_deref(),
            Some("src/FooBar")
        );
    }

    #[test]
    fn a_tie_is_refused_rather_than_broken() {
        // The same name at the same depth in two trees. Nothing here identifies which one ships,
        // and picking the alphabetically-first would be a guess wearing a heuristic's name.
        let files = owned(&["src/Foo/Foo.csproj", "test/Foo/Foo.csproj"]);
        assert_eq!(nuget_project(&files, "Foo"), None);
    }

    #[test]
    fn a_shallower_project_wins_over_a_deeper_one() {
        let files = owned(&["src/Foo/Foo.csproj", "samples/deep/nested/Foo/Foo.csproj"]);
        assert_eq!(nuget_project(&files, "Foo").as_deref(), Some("src/Foo"));
    }

    #[test]
    fn a_repository_with_no_matching_project_says_so() {
        let files = owned(&["src/Other/Other.csproj"]);
        assert_eq!(nuget_project(&files, "Foo"), None);
    }
}

#[cfg(test)]
mod nuget_package_id_tests {
    use super::nuget_project_by_id;

    fn project(path: &str, id: Option<&str>) -> (String, String) {
        let body = match id {
            Some(i) => format!("<Project Sdk=\"Microsoft.NET.Sdk\">\n<PropertyGroup>\n<PackageId>{i}</PackageId>\n</PropertyGroup>\n</Project>\n"),
            None => "<Project Sdk=\"Microsoft.NET.Sdk\">\n<PropertyGroup>\n<TargetFramework>net8.0</TargetFramework>\n</PropertyGroup>\n</Project>\n".to_string(),
        };
        (path.to_string(), body)
    }

    #[test]
    fn a_declared_package_id_beats_the_directory_name() {
        // The case the name matcher gets wrong: `Humanizer.Core` really is built from
        // `src/Humanizer/`, and only the project file says so.
        let projects = vec![
            project("src/Humanizer/Humanizer.csproj", Some("Humanizer.Core")),
            project("src/Humanizer.Tests/Humanizer.Tests.csproj", None),
        ];
        assert_eq!(
            nuget_project_by_id(&projects, "Humanizer.Core").as_deref(),
            Some("src/Humanizer")
        );
    }

    #[test]
    fn an_msbuild_property_is_not_an_answer() {
        // `<PackageId>$(AssemblyName).Core</PackageId>` needs MSBuild to evaluate. Falling through
        // to the name match is honest; pretending to have read it is not.
        let projects = vec![project("src/Foo/Foo.csproj", Some("$(AssemblyName).Core"))];
        assert_eq!(nuget_project_by_id(&projects, "Foo.Core"), None);
    }

    #[test]
    fn two_projects_claiming_one_package_id_is_refused() {
        let projects = vec![
            project("src/A/A.csproj", Some("Shared.Id")),
            project("src/B/B.csproj", Some("Shared.Id")),
        ];
        assert_eq!(nuget_project_by_id(&projects, "Shared.Id"), None);
    }

    #[test]
    fn a_project_with_no_package_id_is_skipped_rather_than_matched() {
        let projects = vec![project("src/Foo/Foo.csproj", None)];
        assert_eq!(nuget_project_by_id(&projects, "Foo"), None);
    }

    #[test]
    fn case_does_not_have_to_agree() {
        // NuGet ids are case-insensitive, and the feed and the project file disagree routinely.
        let projects = vec![project("src/Foo/Foo.csproj", Some("Foo.Bar"))];
        assert_eq!(
            nuget_project_by_id(&projects, "foo.bar").as_deref(),
            Some("src/Foo")
        );
    }
}

#[cfg(test)]
mod node_substitution_tests {
    use super::{highest_release_in, is_plain_version, node_order};

    /// What counts as a version a toolchain host will serve.
    ///
    /// `isexe@2.0.0` records `8.0.0-pre` — the string a Node built from master reports before 8.0.0
    /// is cut. Nothing ever distributed it, so the fetch 404s at every egress tier.
    /// A publishing client is not a version, and it must not reach a shell.
    ///
    /// `framer-motion@12.36.0` records `_npmVersion: "lerna/4.0.0/node@v22.14.0+arm64 (darwin)"`.
    /// Spliced unquoted into `npm install -g npm@…` the parenthesis ended the deps phase with
    /// `Syntax error: "(" unexpected`, which classified as `unknown` — `Fault::Build` — and charged
    /// a shell bug of ours to the package.
    #[test]
    fn a_publishing_client_string_is_not_a_version() {
        for ua in [
            "lerna/4.0.0/node@v22.14.0+arm64 (darwin)",
            "npm/10.9.2 node/v22.14.0 linux x64 workspaces/false",
            "yarn/1.22.19",
            // The shape that makes this worth a rung check rather than only quoting.
            "1.2.3; curl evil | sh",
            "$(id)",
            "`id`",
            "1.2.3'",
        ] {
            assert!(
                !is_plain_version(ua),
                "{ua} must not be treated as a version"
            );
        }
        for real in ["4.4.2", "10.9.2", "2.8.3"] {
            assert!(is_plain_version(real), "{real} is a version");
        }
    }

    #[test]
    fn a_pre_release_is_not_fetchable_and_a_real_release_is() {
        assert!(!is_plain_version("8.0.0-pre"), "the case this exists for");
        for odd in [
            "8.0.0-nightly20170323ee19e2923a",
            "8.0.0-rc.1",
            "v8.0.0",
            "8.0",
            "8",
            "",
        ] {
            assert!(!is_plain_version(odd), "{odd} is not an x.y.z release");
        }

        // io.js versions are real releases and must NOT be substituted: `npm/install-node` routes
        // majors 1 to 3 to iojs.org and fetches the publisher's own binary. Substituting one would
        // trade an exact toolchain for a nearby guess, which is strictly worse.
        for real in [
            "1.6.4", "2.5.0", "3.3.1", "0.12.7", "4.8.1", "7.7.4", "22.14.0",
        ] {
            assert!(is_plain_version(real), "{real} is a release we can fetch");
        }
    }

    /// "Highest" means highest number, and on the day that matters it disagrees with "newest".
    ///
    /// Node ships several lines at once. On 2017-03-21 it released both 4.8.1 and 7.7.4; ordering by
    /// date picks 4.8.1, under which `isexe@2.0.0`'s recorded npm 4.4.2 fails to install at all,
    /// while 7.7.4 reproduces the package with every member identical.
    #[test]
    fn highest_is_by_number_not_by_string_or_date() {
        let mut releases = ["4.8.1", "7.7.4", "0.12.18", "6.10.1"];
        releases.sort_by_key(|v| node_order(v));
        assert_eq!(releases.last(), Some(&"7.7.4"));

        // The trap a string comparison walks into: "10.0.0" < "9.0.0" lexically.
        let mut two_digit = ["9.11.2", "10.0.0"];
        two_digit.sort_by_key(|v| node_order(v));
        assert_eq!(
            two_digit.last(),
            Some(&"10.0.0"),
            "10 is above 9, not below it"
        );

        assert!(node_order("7.7.4") > node_order("4.8.1"));
        assert!(node_order("8.0.0") > node_order("7.7.4"));
    }

    #[test]
    fn the_substitute_is_the_highest_linux_release_out_by_the_publish_day() {
        // Entries shaped as `nodejs.org/dist/index.json` writes them. On 2017-03-21 Node released
        // both 4.8.1 and 7.7.4, and `isexe@2.0.0` reproduces only under the second.
        let entry = |version: &str, date: &str, files: &[&str]| serde_json::json!({ "version": version, "date": date, "files": files });
        let index = [
            entry("v7.8.0", "2017-03-29", &["linux-x64", "osx-x64-tar"]),
            entry("v7.7.4", "2017-03-21", &["linux-x64", "win-x64-exe"]),
            entry("v4.8.1", "2017-03-21", &["linux-x64"]),
            entry("v6.10.1", "2017-03-21", &["linux-x64"]),
            entry("v6.9.5", "2017-01-31", &["linux-x64"]),
            // Higher, earlier, and useless here: nothing `npm/install-node` could fetch.
            entry("v7.9.9", "2017-03-01", &["win-x64-exe"]),
            entry("v7.10.0-rc.1", "2017-03-01", &["linux-x64"]),
            serde_json::json!({ "version": "v7.11.0", "files": ["linux-x64"] }),
            serde_json::json!({ "version": 7, "date": "2017-03-01", "files": ["linux-x64"] }),
            serde_json::json!({ "version": "7.12.0", "date": "2017-03-01", "files": ["linux-x64"] }),
        ];
        assert_eq!(
            highest_release_in(&index, "2017-03-21").as_deref(),
            Some("7.7.4")
        );
        // By number: 6.10.1 is above 6.9.5 although it sorts below it as a string.
        assert_eq!(
            highest_release_in(&index[2..], "2017-03-21").as_deref(),
            Some("6.10.1")
        );
        // Nothing out yet is nothing, not the earliest release there is.
        assert_eq!(highest_release_in(&index, "2016-01-01"), None);
        assert_eq!(highest_release_in(&[], "2017-03-21"), None);
    }
}
