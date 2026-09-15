//! A `CiRecipe` to the two things `docs/06` §4 says it produces: a strategy candidate and a set of
//! `Evidence`.
//!
//! The order matters and it is the opposite of what the names suggest. Evidence is collected
//! **first and unconditionally**, before any of the refusals below can fire, because §4's closing
//! claim is that the second output often beats the first: a workflow we cannot lower faithfully
//! still tells us the Python version, and that alone can turn a failing heuristic strategy into a
//! passing one. A decline that also threw the evidence away would keep the honest half of this rung
//! and discard the useful one.

use std::collections::BTreeMap;

use trigon_core::{Claim, Confidence, Evidence, RegistryMoment, SourceDiscovery};
use trigon_strategy::{FlowStrategy, Location, Step, StepBody, Strategy};

use super::cmd::{self, Cmd};
use super::recipe::{
    BuildPublishLink, CiRecipe, CiStep, Decline, RunnerSpec, StepPhase, ToolPin, VersionSpec,
};
use crate::infer::{Candidate, Derivation, confidence_of};
use crate::model::ResolvedTarget;

/// Everything one recipe produced.
pub struct Lowering {
    pub candidate: Option<Candidate>,
    pub evidence: Vec<Evidence>,
    pub notes: Vec<String>,
    pub decline: Option<Decline>,
    /// The `Claim::PlatformIs` for a macOS or Windows runner rides in `evidence`; this says the
    /// rung *recognised* the case rather than merely failing to find a Linux one.
    pub out_of_scope: Option<super::recipe::OutOfScope>,
}

pub struct LowerCtx<'a> {
    pub target: &'a ResolvedTarget,
    pub repo: &'a str,
    pub commit: &'a str,
    pub discovery: SourceDiscovery,
    pub mirror: Option<&'a str>,
    pub aux_files: &'a BTreeMap<String, String>,
}

pub fn lower(recipe: &CiRecipe, ctx: &LowerCtx<'_>) -> Lowering {
    let mut out = Lowering {
        candidate: None,
        evidence: Vec::new(),
        notes: Vec::new(),
        decline: None,
        out_of_scope: recipe.runner.out_of_scope().cloned(),
    };
    let source = format!("ci:{}", recipe.source.path());

    // ---- Evidence, unconditionally. ----------------------------------------------------------
    for pin in &recipe.toolchains {
        if let Some(e) = toolchain_evidence(pin) {
            out.evidence.push(e);
        }
    }
    if let Some(platform) = recipe.runner.platform() {
        out.evidence.push(Evidence::new(
            Claim::PlatformIs {
                platform: platform.into(),
            },
            Confidence::Strong,
            source.clone(),
        ));
    }
    if let Some(dir) = &recipe.working_directory
        && dir != "."
    {
        out.evidence.push(Evidence::new(
            Claim::SubdirIs { path: dir.clone() },
            Confidence::Strong,
            source.clone(),
        ));
    }

    let build = analyse(recipe);

    // A build that fetches from somewhere other than the ecosystem's own index needs the network,
    // and the egress tier is downstream of knowing that.
    if !build.network.is_empty() {
        out.evidence.push(Evidence::new(
            Claim::RequiresNetwork { required: true },
            Confidence::Strong,
            source.clone(),
        ));
        out.notes.push(format!(
            "the build fetches from outside the registry: {}",
            build.network.join("; ")
        ));
    }
    // `npm ci` resolves nothing — the lockfile is the answer — so this is the one registry moment
    // we can state at `Certain`, because the digest is of bytes already in hand from the checkout.
    if build.frozen_install
        && let Some(text) = ctx.aux_files.get("package-lock.json")
    {
        out.evidence.push(Evidence::new(
            Claim::RegistryMomentIs {
                moment: RegistryMoment::Lockfile {
                    digest: digest_of(text),
                },
            },
            Confidence::Certain,
            source.clone(),
        ));
    }
    for (name, value) in &build.github_env {
        out.notes.push(format!(
            "the build exports `{name}={value}` for every later step, and nothing in `FlowStrategy` \
             carries it"
        ));
    }

    // ---- The refusals. -----------------------------------------------------------------------
    if let Some(reason) = refuse(recipe, &build, ctx) {
        out.decline = Some(reason);
        return out;
    }

    // ---- The candidate. ----------------------------------------------------------------------
    let mut assumptions = Vec::new();
    if let Some(approx) = recipe.runner.approximation() {
        assumptions.push(approx.why.clone());
    }
    if let RunnerSpec::Container { image, digest } = &recipe.runner {
        assumptions.push(match digest {
            Some(d) => format!(
                "the workflow ran in `{image}`, already pinned by digest ({d}); this is the one \
                 runner statement that is not an approximation"
            ),
            None => format!(
                "the workflow ran in `{image}`, a tag rather than a digest: it resolves to \
                 whatever that tag points at today, not to what the publisher's run resolved it to"
            ),
        });
    }
    if let Some(depth) = &recipe.checkout.fetch_depth
        && depth == "0"
    {
        // Deliberately an assumption rather than a decline, and the difference was settled by
        // reading our own tool rather than by reasoning about it. `SourceCache` fetches depth 1, so
        // a first draft of this rule declined every project using `hatch-vcs` or `setuptools-scm`.
        // But `SourceCache` is the *host-side* read, and the build container runs
        // `crates/trigon-strategy/tools/git-checkout.yaml`, which does a plain `git clone` with no
        // depth at all: the history is there. What remains is narrower and is what this says —
        // the version those backends derive comes from `git describe`, so it is right only if the
        // commit we check out is the tagged one.
        assumptions.push(
            "the workflow checks out the full history, so the build may derive its version from \
             the git tag; our checkout clones fully, but the version will only match if this \
             commit is the one the release tag points at"
                .into(),
        );
    }
    if let Some(git_ref) = &recipe.checkout.git_ref
        && !git_ref.is_empty()
        && git_ref != ctx.commit
    {
        assumptions.push(format!(
            "the workflow checked out `{git_ref}` rather than the commit this run pins \
             ({}), and the two are only the same if the reference resolved there",
            &ctx.commit[..ctx.commit.len().min(12)]
        ));
    }
    if !recipe.unmodelled.is_empty() {
        assumptions.push(format!(
            "the build runs {} this rung does not interpret ({}), and an unmodelled step is where \
             the next inference failure comes from",
            plural(recipe.unmodelled.len(), "step"),
            recipe
                .unmodelled
                .iter()
                .map(|u| u.action.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !build.system_deps.is_empty() {
        assumptions.push(format!(
            "the workflow installs system packages ({}); they are carried onto the build step's \
             `needs`, which is the closest `FlowStrategy` gets to an apt invocation",
            build.system_deps.join(", ")
        ));
    }

    let lowered = match ctx.target.reference.ecosystem {
        trigon_core::Ecosystem::PyPI => {
            lower_pypi(recipe, &build, ctx, &mut assumptions, &mut out.notes)
        }
        trigon_core::Ecosystem::Npm => {
            lower_npm(recipe, &build, ctx, &mut assumptions, &mut out.notes)
        }
        // The rung is only wired for the two ecosystems with a registry client. A third would be a
        // `lower_*` function and nothing else here.
        _ => Err(Decline::NothingTheHeuristicLacks {
            because: "this ecosystem has no CI lowering yet".into(),
        }),
    };

    match lowered {
        Ok(strategy) => {
            out.candidate = Some(Candidate {
                strategy,
                derivation: Derivation::CiDerived,
                confidence: confidence(recipe, ctx),
                discovery: ctx.discovery,
                assumptions,
            });
        }
        Err(reason) => out.decline = Some(reason),
    }
    out
}

/// What the build job's `run:` steps add up to.
struct BuildAnalysis {
    /// The commands that produce the artifact, in order.
    builds: Vec<Cmd>,
    /// Fragments with no lowering. The input to `Decline::NoToolForBuildCommand`.
    unknown: Vec<String>,
    /// Commands that rewrote the working tree before the build read it.
    mutations: Vec<String>,
    system_deps: Vec<String>,
    network: Vec<String>,
    github_env: Vec<(String, String)>,
    frozen_install: bool,
    package_manager: Option<&'static str>,
    /// A step that computes the version at run time, which no checkout can reproduce.
    computed_version: Option<String>,
}

fn analyse(recipe: &CiRecipe) -> BuildAnalysis {
    let mut a = BuildAnalysis {
        builds: Vec::new(),
        unknown: Vec::new(),
        mutations: Vec::new(),
        system_deps: Vec::new(),
        network: Vec::new(),
        github_env: Vec::new(),
        frozen_install: false,
        package_manager: None,
        computed_version: None,
    };

    for (i, step) in recipe.steps.iter().enumerate() {
        let CiStep::Runs { script, .. } = step else {
            continue;
        };
        let is_publish = recipe.publish_job == recipe.build_job && i == recipe.publishes.step_index;

        // A version written into the package immediately before publishing exists nowhere in the
        // repository. `vercel/ms` builds `${BASE}-nightly.$(date +%Y%m%d%H%M)` and publishes it, so
        // the version on the registry cannot be produced from any commit. Checked on the publish
        // step too — that is where it lives.
        for marker in ["npm version ", "pnpm version ", "yarn version "] {
            if script.contains(marker) && script.contains("--no-git-tag-version") {
                a.computed_version = Some(marker.trim().to_string());
            }
        }
        if is_publish {
            continue;
        }

        for c in cmd::classify_script(script) {
            match c {
                c if c.is_build() => a.builds.push(c),
                Cmd::NpmInstall { frozen } => a.frozen_install |= frozen,
                Cmd::SystemDeps(names) => a.system_deps.extend(names),
                Cmd::Network(f) => a.network.push(f),
                Cmd::GithubEnv { name, value } => a.github_env.push((name, value)),
                Cmd::PackageManager(m) => a.package_manager = Some(m),
                Cmd::Unknown(f) => a.unknown.push(f),
                Cmd::MutatesTree(f) => a.mutations.push(f),
                Cmd::PyDeps(_) | Cmd::Publish(_) | Cmd::Incidental => {}
                // Already collected by the `is_build` arm above; listed rather than wildcarded so
                // a new `Cmd` variant is a compile error here instead of a silent omission.
                Cmd::PyBuild { .. } | Cmd::UvBuild { .. } | Cmd::NpmPack | Cmd::NpmRun(_) => {}
            }
        }
    }
    a
}

/// Every reason this recipe does not become a candidate, in the order they are worth reporting.
fn refuse(recipe: &CiRecipe, build: &BuildAnalysis, ctx: &LowerCtx<'_>) -> Option<Decline> {
    if let Some(o) = recipe.runner.out_of_scope() {
        return Some(Decline::RunnerOutOfScope(o.clone()));
    }
    // Before the package-manager check: even with a pnpm tool, a version computed from `date` is
    // not in the repository and no rebuild can produce it. This is the stronger statement, so it is
    // the one worth reporting.
    if let Some(step) = &build.computed_version {
        return Some(Decline::VersionComputedAtPublishTime { step: step.clone() });
    }
    if let Some(manager) = build.package_manager {
        return Some(Decline::PackageManagerUnsupported {
            manager: manager.into(),
        });
    }
    if !recipe.secrets_in_build.is_empty() {
        return Some(Decline::SecretInBuild {
            names: recipe.secrets_in_build.clone(),
        });
    }
    // Before the unknown-fragment checks below, because it is the more specific statement: we read
    // the command and know what it did, rather than failing to read it.
    if let Some(command) = build.mutations.first() {
        return Some(Decline::BuildRewritesTheTree {
            command: command.clone(),
        });
    }
    if !build.unknown.is_empty() && build.builds.is_empty() {
        // The last one, not the first. A release job installs its tooling before it builds, so the
        // earliest unrecognised fragment is usually `pipx install nox[pbs]` and the last is the
        // build itself — `nox --no-install -R -s release_build` for `pypa/packaging`, which is the
        // command a reader needs to see.
        return Some(Decline::NoToolForBuildCommand {
            command: build.unknown.last().cloned().unwrap_or_default(),
        });
    }
    if build.builds.is_empty() {
        if let Some(u) = recipe
            .unmodelled
            .iter()
            .find(|u| u.phase == StepPhase::Build)
        {
            return Some(Decline::BuildIsOneUnmodelledStep {
                action: u.action.clone(),
            });
        }
        // Only for PyPI. On npm a job that installs and then runs `npm publish` is a *complete*
        // description rather than an empty one: `npm publish` runs `prepare` and `prepack` itself,
        // which is precisely the heuristic's `npm pack` recipe. Saying "this job runs no build"
        // there would be false, and `lower_npm` has the accurate answer.
        if ctx.target.reference.ecosystem == trigon_core::Ecosystem::PyPI {
            return Some(Decline::BuildJobRunsNoBuild {
                job: recipe.build_job.clone(),
            });
        }
    }
    // A recognised build *and* fragments we could not read means the recipe is incomplete rather
    // than wrong, and an incomplete build is a rebuild that silently skips a step. Its own decline
    // rather than `NoToolForBuildCommand`, whose message — "`…` is the build, and no tool in the
    // registry lowers it" — is false about a run that found the build and lowered it.
    if !build.unknown.is_empty() {
        return Some(Decline::RecipeIncomplete {
            command: build.unknown.last().cloned().unwrap_or_default(),
        });
    }
    if !build.builds.is_empty() && recipe.checkout.path.as_deref().is_some_and(|p| p != ".") {
        return Some(Decline::UnresolvedExpression {
            field: "actions/checkout path",
            raw: recipe.checkout.path.clone().unwrap_or_default(),
        });
    }
    None
}

fn lower_pypi(
    recipe: &CiRecipe,
    build: &BuildAnalysis,
    ctx: &LowerCtx<'_>,
    assumptions: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Result<Strategy, Decline> {
    let (outdir, dir, frontend_python) = match build.builds.first() {
        Some(Cmd::PyBuild { outdir, dir, .. }) => (outdir.clone(), dir.clone(), None),
        Some(Cmd::UvBuild {
            outdir,
            dir,
            python,
            ..
        }) => {
            // A real semantic difference, stated rather than buried. `uv build` and
            // `python -m build` are both PEP 517 frontends driving the same backend, and the
            // backend is what writes the wheel — which is why this is an approximation worth making
            // rather than a decline. What differs is the environment the frontend assembles, and
            // `pypi/deps/basic` pins the backend by constraint precisely so that environment is not
            // left to whichever frontend ran.
            assumptions.push(
                "the workflow built with `uv build`; this recipe runs `python -m build`, a \
                 different PEP 517 frontend driving the same backend"
                    .into(),
            );
            (outdir.clone(), dir.clone(), python.clone())
        }
        _ => {
            return Err(Decline::NoToolForBuildCommand {
                command: "(no Python build frontend)".into(),
            });
        }
    };

    let mut deps = BTreeMap::from([("venv".to_string(), trigon_strategy::VENV.to_string())]);

    // The interpreter, from the workflow if it pinned one and from `uv build --python` otherwise.
    let python = recipe
        .toolchains
        .iter()
        .find(|p| p.tool == "python")
        .and_then(usable_version)
        .or_else(|| {
            frontend_python
                .as_deref()
                .and_then(|p| match VersionSpec::classify(p, 2) {
                    VersionSpec::Pinned(v) => Some(v),
                    VersionSpec::Series { lo, .. } => Some(lo),
                    VersionSpec::Unknown { .. } => None,
                })
        });
    match &python {
        Some(v) => {
            deps.insert("python_version".into(), v.clone());
        }
        None => assumptions.push(
            "the workflow pins no interpreter version this rung can use, so the build runs on \
             whichever Python the image carries"
                .into(),
        ),
    }

    match (&ctx.target.intrinsics.publish_time, ctx.mirror) {
        (Some(t), Some(_)) => {
            deps.insert("registry_time".into(), t.clone());
        }
        (Some(t), None) => assumptions.push(format!(
            "no registry mirror configured, so dependencies resolve against today's PyPI rather \
             than against {t}"
        )),
        (None, _) => assumptions
            .push("no publish time recorded, so dependencies resolve against today's index".into()),
    }

    // The backend the published wheel says built it. A read from the artifact under test rather
    // than from the workflow: `uv build` and `python -m build` are frontends and name no backend,
    // and the wheel's own `Generator:` field states it at `Certain`.
    let backend = crate::heuristic::build_backend_pin(ctx.target);
    match &backend {
        Some(pin) => {
            deps.insert("build_backend".into(), pin.clone());
        }
        None => notes.push(
            "the published artifact names no build backend, so the frontend resolves the \
             project's own declaration"
                .into(),
        ),
    }

    let subdir = subdir_of(recipe, ctx);
    let project_dir = dir.filter(|d| d != ".");
    let output = outdir.unwrap_or_else(|| "dist".into());

    Ok(Strategy::Flow(FlowStrategy {
        location: Location {
            repo: ctx.repo.to_string(),
            git_ref: ctx.commit.to_string(),
            subdir: subdir.clone(),
        },
        src: vec![uses("git-checkout", BTreeMap::new(), Vec::new())],
        deps: vec![uses("pypi/deps/basic", deps, Vec::new())],
        build: vec![uses(
            "pypi/build/wheel",
            BTreeMap::from([
                (
                    "locator".to_string(),
                    format!("{}/bin/", trigon_strategy::VENV),
                ),
                (
                    "constraints".to_string(),
                    backend
                        .as_ref()
                        .map(|_| format!("{}/constraints.txt", trigon_strategy::VENV))
                        .unwrap_or_default(),
                ),
                // Isolation stays on for the same reason it does in the heuristic: `-n` makes the
                // frontend check for each declared build requirement rather than install it, and a
                // project needing anything beyond the backend stops with "Unmet dependencies".
                ("no_isolation".to_string(), "false".to_string()),
                ("dir".to_string(), project_dir.unwrap_or_default()),
            ]),
            build.system_deps.clone(),
        )],
        output_dir: Some(match &subdir {
            Some(d) => format!("{}/{output}", d.trim_end_matches('/')),
            None => output,
        }),
        output_path: None,
    }))
}

fn lower_npm(
    recipe: &CiRecipe,
    build: &BuildAnalysis,
    ctx: &LowerCtx<'_>,
    assumptions: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Result<Strategy, Decline> {
    // The displacement rule, and the reason this rung is quiet on npm. `CiDerived` sits above
    // `Heuristic` and `infer()` takes the first non-empty rung, so a candidate here *replaces* one
    // the heuristic would have produced. For npm the heuristic's inputs are strictly better:
    // `_nodeVersion` and `_npmVersion` are what the publishing client reported at publish time and
    // enter at `Confidence::Certain`, where a workflow's `node-version: 24` is an intent recorded
    // before the fact. So the rung produces a candidate only where it knows something the registry
    // does not — the build command the publisher actually ran — and hands back evidence otherwise.
    let node = registry_toolchain(ctx.target, "npm:_nodeVersion");
    let npm = registry_toolchain(ctx.target, "npm:_npmVersion");
    let (Some(node), Some(npm)) = (node, npm) else {
        return Err(Decline::NothingTheHeuristicLacks {
            because:
                "the registry recorded no publishing toolchain, and a workflow's node-version \
                      is a series rather than the build it produced"
                    .into(),
        });
    };

    let script = build.builds.iter().find_map(|c| match c {
        Cmd::NpmRun(s) => Some(s.clone()),
        _ => None,
    });
    let Some(script) = script else {
        return Err(Decline::NothingTheHeuristicLacks {
            because:
                "the release ran no build script beyond what `npm pack` runs itself, which is \
                      exactly the heuristic's recipe"
                    .into(),
        });
    };

    let mut deps = BTreeMap::from([
        ("node_version".to_string(), node),
        ("npm_version".to_string(), npm.clone()),
    ]);
    match (&ctx.target.intrinsics.publish_time, ctx.mirror) {
        (Some(t), Some(_)) => {
            deps.insert("registry_time".into(), t.clone());
        }
        (Some(t), None) => assumptions.push(format!(
            "no registry mirror configured, so dependencies resolve against today's npm rather \
             than against {t}"
        )),
        (None, _) => assumptions.push(
            "no publish time recorded, so dependencies resolve against today's registry".into(),
        ),
    }

    assumptions.push(format!(
        "the release workflow ran `npm run {script}` before publishing, and `npm pack` does not \
         run it, so the recipe runs it first"
    ));
    if let Some(pin) = recipe.toolchains.iter().find(|p| p.tool == "node") {
        notes.push(format!(
            "the workflow asked for node {:?} and the registry recorded the version that actually \
             published; the registry's is used and the workflow's is left as a constraint",
            pin.spec
        ));
    }

    let subdir = subdir_of(recipe, ctx);
    Ok(Strategy::Flow(FlowStrategy {
        location: Location {
            repo: ctx.repo.to_string(),
            git_ref: ctx.commit.to_string(),
            subdir: subdir.clone(),
        },
        src: vec![uses("git-checkout", BTreeMap::new(), Vec::new())],
        deps: vec![uses("npm/deps/custom", deps, Vec::new())],
        build: vec![uses(
            "npm/build/custom",
            BTreeMap::from([
                ("npm_version".to_string(), npm),
                ("command".to_string(), script),
            ]),
            build.system_deps.clone(),
        )],
        // The tarball, not the directory: naming the directory collects the whole working tree.
        output_dir: None,
        output_path: Some(match &subdir {
            Some(d) => format!("{}/*.tgz", d.trim_end_matches('/')),
            None => "*.tgz".into(),
        }),
    }))
}

/// Where in the repository the package lives.
///
/// The registry's own answer first — it is a statement about the published package rather than
/// about a job — then the workflow's `working-directory:`, which is the only thing that knows about
/// a monorepo whose registry metadata records no `repository.directory`.
fn subdir_of(recipe: &CiRecipe, ctx: &LowerCtx<'_>) -> Option<String> {
    ctx.target
        .source
        .as_ref()
        .and_then(|s| s.subdir.clone())
        .or_else(|| recipe.working_directory.clone().filter(|d| d != "."))
}

/// How much to believe a CI-derived candidate.
///
/// Capped by how the commit was found, then lowered again by what the workflow left unsaid. Never
/// `Certain`: the workflow is intent, we did not observe the run, and the file at this commit is
/// not provably the file that ran.
fn confidence(recipe: &CiRecipe, ctx: &LowerCtx<'_>) -> Confidence {
    // `Confidence` orders Certain < Strong < Weak, so the *worse* of two is the larger one.
    let mut c = confidence_of(ctx.discovery).max(Confidence::Strong);
    if !recipe.unmodelled.is_empty() {
        c = c.max(Confidence::Weak);
    }
    if recipe
        .runner
        .approximation()
        .is_some_and(|a| a.confidence == Confidence::Weak)
    {
        c = c.max(Confidence::Weak);
    }
    c
}

/// A version string we are willing to hand to a tool, or nothing.
fn usable_version(pin: &ToolPin) -> Option<String> {
    match &pin.spec {
        VersionSpec::Pinned(v) => Some(v.clone()),
        // The low end of the series. `pypi/setup-venv` passes it to `uv venv --python`, which
        // accepts a series and resolves it to the newest matching interpreter — the same thing
        // `actions/setup-python` does with the same string.
        VersionSpec::Series { lo, .. } => Some(lo.clone()),
        VersionSpec::Unknown { .. } => None,
    }
}

/// Turn a workflow's version field into a claim, at the strength the field supports.
///
/// The `Series` case is the load-bearing one. `resolve_toolchain` intersects every claim about a
/// tool, and an exact claim that disagrees with another exact claim is a `Contradiction`, which
/// `needs_help()` reports as a reason to escalate to a model. npm records `_nodeVersion: 18.17.1`
/// at `Certain`; a CI `ToolchainExact { node, 18 }` would contradict it and buy a paid call to
/// adjudicate a disagreement that does not exist. `ToolchainRange { 18, 19 }` intersects to
/// `Pinned { 18.17.1 }` instead, which is both the right answer and free.
fn toolchain_evidence(pin: &ToolPin) -> Option<Evidence> {
    let claim = match &pin.spec {
        VersionSpec::Pinned(v) => Claim::ToolchainExact {
            tool: pin.tool.clone(),
            version: v.clone(),
        },
        VersionSpec::Series { lo, hi } => Claim::ToolchainRange {
            tool: pin.tool.clone(),
            lo: Some(lo.clone()),
            hi: Some(hi.clone()),
        },
        // No claim at all. A wildcard, a float, an unresolved expression or a `requires-python`
        // floor each say less than nothing about which version ran, and a claim built from one
        // would carry CI's authority behind a guess.
        VersionSpec::Unknown { .. } => return None,
    };
    // Never `Certain`. `Certain` is reserved for what the registry stated or what the bytes say,
    // and a workflow is a description of an intended build.
    Some(Evidence::new(claim, Confidence::Strong, pin.from.clone()))
}

fn registry_toolchain(target: &ResolvedTarget, source: &str) -> Option<String> {
    target
        .intrinsics
        .evidence
        .iter()
        .find_map(|e| match &e.claim {
            Claim::ToolchainExact { version, .. } if e.source == source => Some(version.clone()),
            _ => None,
        })
}

fn digest_of(text: &str) -> trigon_core::Digest {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(text.as_bytes());
    trigon_core::Digest::from_bytes(h.finalize().into())
}

fn uses(tool: &str, with: BTreeMap<String, String>, needs: Vec<String>) -> Step {
    Step {
        body: StepBody::Uses {
            tool: tool.into(),
            with,
        },
        needs,
        when: None,
    }
}

fn plural(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// What two equally-ranked recipes disagree about, if anything.
///
/// A tie is only a problem when the two would lower differently. Two cells of a matrix that vary
/// something we never read are interchangeable and picking either is correct; two jobs that pin
/// different Python versions are not, and choosing one attaches a verdict to a coin flip.
pub fn disagreement(a: &CiRecipe, b: &CiRecipe) -> Option<&'static str> {
    if runner_key(a) != runner_key(b) {
        return Some("the runner");
    }
    if toolchain_key(a) != toolchain_key(b) {
        return Some("the toolchain");
    }
    if build_key(a) != build_key(b) {
        return Some("the build command");
    }
    if a.working_directory != b.working_directory {
        return Some("the working directory");
    }
    if link_key(&a.link) != link_key(&b.link) {
        return Some("which job built the artifact");
    }
    None
}

fn runner_key(r: &CiRecipe) -> String {
    match &r.runner {
        RunnerSpec::LinuxLabel { label, .. } => format!("linux:{label}"),
        RunnerSpec::Container { image, .. } => format!("container:{image}"),
        RunnerSpec::OutOfScope(o) => format!("out:{o}"),
    }
}

fn toolchain_key(r: &CiRecipe) -> Vec<String> {
    let mut v: Vec<String> = r
        .toolchains
        .iter()
        .map(|p| format!("{}={:?}", p.tool, p.spec))
        .collect();
    v.sort();
    v
}

fn build_key(r: &CiRecipe) -> Vec<String> {
    r.steps
        .iter()
        .map(|s| match s {
            CiStep::Runs { script, .. } => script.clone(),
            CiStep::Uses { action, .. } => action.clone(),
        })
        .collect()
}

fn link_key(l: &BuildPublishLink) -> String {
    match l {
        BuildPublishLink::SameJob => "same".into(),
        BuildPublishLink::Artifact { name } => format!("artifact:{name}"),
        BuildPublishLink::ArtifactId { producer } => format!("producer:{producer}"),
    }
}
