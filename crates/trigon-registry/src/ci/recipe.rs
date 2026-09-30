//! What a release workflow says, normalized away from GitHub Actions' shape.
//!
//! `docs/06-ci-awareness.md` §3 sketches one `CiRecipe` with one `job`. Reading real release
//! workflows says that shape is wrong, and it is wrong in the one place that decides whether the
//! rung works at all. §3.1 asserts "the job that publishes is the one that describes the build";
//! for every modern PyPI release workflow in `tests/fixtures/workflows/` that is false. `attrs`,
//! `flask`, `certifi`, `platformdirs` and `packaging` all publish from a job whose entire body is
//! `actions/download-artifact` followed by `pypa/gh-action-pypi-publish`. There is no build step
//! in it. Following the publish job alone would produce a recipe that builds nothing and a
//! candidate that collects an empty `dist/`.
//!
//! So a recipe names **two** jobs joined by a [`BuildPublishLink`]: the job that published, which
//! is what identifies the release, and the job that built, which is what we lower. They are
//! frequently the same job (`six` is), and where they are not the edge between them is an artifact
//! name or an artifact id that has to be resolved rather than guessed.

use std::collections::BTreeMap;

use trigon_core::Confidence;

/// Which file this came out of, pinned to the commit we read it at.
///
/// The commit is not decoration. A workflow is only evidence about *this* release if it is the
/// workflow that existed at the commit the artifact was built from; reading `HEAD`'s workflow to
/// explain a 2021 publish reads a file that did not exist then. The rung refuses to run without a
/// pinned commit for exactly this reason (see [`Decline::NoPinnedCommit`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CiSource {
    GithubActions {
        path: String,
        commit: String,
    },
    /// Not implemented in v1. Present because `docs/06` §6 makes the point that `CiRecipe` is a
    /// common denominator rather than a GitHub Actions shape, and a variant nobody can construct
    /// is a cheaper way to hold that line than a comment.
    GitLabCi {
        path: String,
    },
}

impl CiSource {
    pub fn path(&self) -> &str {
        match self {
            CiSource::GithubActions { path, .. } | CiSource::GitLabCi { path } => path,
        }
    }
}

/// What made the workflow run, ranked.
///
/// The ordering is the first term of job selection and it is the cheapest discriminator available:
/// a workflow triggered by `release: published` is a release workflow, and one triggered by a
/// branch push is usually CI. `escalade`'s `on: [push, pull_request]` is the case this keeps out —
/// its only job is a seven-cell Node test matrix, and ranking it as a build would pin Node 20 for a
/// package published from a laptop.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TriggerKind {
    BranchPush,
    PullRequest,
    Schedule,
    Other(String),
    Call,
    Dispatch,
    TagPush,
    ReleasePublished,
}

impl TriggerKind {
    /// Higher is a stronger claim to being the release path. Used as the first rank term.
    pub fn rank(&self) -> u8 {
        match self {
            TriggerKind::ReleasePublished => 5,
            TriggerKind::TagPush => 4,
            TriggerKind::Dispatch | TriggerKind::Call => 3,
            TriggerKind::Schedule | TriggerKind::PullRequest => 1,
            TriggerKind::BranchPush => 1,
            TriggerKind::Other(_) => 0,
        }
    }
}

/// The step that made the artifact public, and which registry it reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishStep {
    /// The literal marker we matched, kept verbatim so a report can show what we recognised rather
    /// than an enum name nobody can check.
    pub marker: String,
    /// `npm` or `pypi`. A job that publishes to the *other* ecosystem is not this target's release.
    pub ecosystem: &'static str,
    /// Index of the step inside the publishing job's step list.
    pub step_index: usize,
    /// Strength, as the second rank term. A dedicated publish action outranks a `run:` line that
    /// happens to contain the words.
    pub strength: u8,
}

/// How the build job's output reaches the publish job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildPublishLink {
    /// One job does both. `six` and `vercel/ms`.
    SameJob,
    /// `actions/upload-artifact` in one job, `actions/download-artifact` in the other, matched on
    /// the artifact name after expression resolution. `platformdirs` names it through a
    /// workflow-level `env:` entry, `certifi` writes it literally.
    Artifact { name: String },
    /// `download-artifact` with `artifact-ids: ${{ needs.<job>.outputs.<x> }}`, which names the
    /// producing job directly and skips the name match entirely. `flask` does this.
    ArtifactId { producer: String },
}

/// Where a step sat, so an unmodelled one can be reported with the phase it would have affected.
///
/// An unmodelled step in the publish phase costs nothing — we are not going to publish. One in the
/// build phase is where the next inference failure comes from, which is `docs/06` §3.2's whole
/// argument for recording them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepPhase {
    Src,
    Deps,
    Build,
    Publish,
}

/// A step, after `${{ }}` resolution and after the allowlist has had its look.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CiStep {
    Uses {
        /// The name before `@`, never the ref. See [`crate::ci::actions`] for why matching on the
        /// name is the only thing that works and what it costs.
        action: String,
        action_ref: String,
        with: BTreeMap<String, String>,
    },
    Runs {
        script: String,
        /// `secrets.*` names referenced anywhere in this step. A token in the publish step is
        /// expected; one in a build step means the build reads something we do not have and cannot
        /// know the effect of.
        secrets: Vec<String>,
        working_directory: Option<String>,
    },
}

/// A `uses:` we declined to interpret, pinned by whatever the workflow pinned it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmodelledStep {
    pub action: String,
    pub action_ref: String,
    pub phase: StepPhase,
}

/// A toolchain the workflow asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolPin {
    /// `python`, `node`, `uv`, `rust`, … — the same vocabulary `Claim::ToolchainExact` uses, so
    /// `resolve_toolchain` can intersect a CI claim with a registry one.
    pub tool: String,
    pub spec: VersionSpec,
    /// The action or file the version was read off, for the evidence `source` string.
    pub from: String,
}

/// A version field, classified by how much of it is actually pinned.
///
/// The distinction between `Pinned` and `Series` is the single most consequential rule in this
/// module, and getting it backwards costs money rather than correctness. npm records
/// `_nodeVersion: 18.17.1` at `Confidence::Certain`. A workflow saying `node-version: 18` is a
/// *weaker* statement about the same fact. Emitting it as `ToolchainExact { node, 18 }` makes
/// `resolve_toolchain` return `Contradiction`, which `ToolchainResolution::needs_help` reports as
/// an escalation signal, and a paid model gets called to adjudicate a disagreement that does not
/// exist. Emitting it as `ToolchainRange { lo: 18, hi: 19 }` intersects with the registry's exact
/// version and resolves to `Pinned { 18.17.1 }`, which is the right answer and costs nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionSpec {
    /// Every component is literal: `3.11.7`, `18.17.1`.
    Pinned(String),
    /// A prefix: `3.11` means `[3.11, 3.12)`, `24` means `[24, 25)`.
    Series { lo: String, hi: String },
    /// We read a version field and could not make a claim from it. `raw` is kept so a note can
    /// quote it; guessing here is how a workflow gets blamed for a divergence it did not cause.
    Unknown { raw: String, why: WhyUnknown },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhyUnknown {
    /// `3.x`, `*`, `lts/*`, `latest`.
    Wildcard,
    /// The killer. `python-version: 3.10` unquoted is a YAML **float**, and every YAML 1.2 parser
    /// including `serde_yaml_ng` reads it as `3.1`. Reading a version through a parsed number would
    /// claim Python 3.1 — a release from 2006 — with CI authority behind it. Verified against
    /// `serde_yaml_ng` 0.10 rather than assumed: `python-version: 3.10` parses to `Number(3.1)`,
    /// and `Number::to_string` gives `"3.1"`. Version fields therefore accept a YAML string or an
    /// integer and never a float.
    UnquotedFloat,
    /// A `${{ }}` we could not resolve.
    Expression,
    /// `>=3.9` and friends. A floor is not a pin, and `pyproject.toml`'s `requires-python` — which
    /// is what `actions/setup-python`'s `python-version-file` reads for `flask` — is exactly this.
    RangeSpec,
    /// A `python-version-file:` naming a file the checkout does not have.
    FileMissing,
    /// A sequence of versions rather than one.
    Multiple,
}

impl VersionSpec {
    /// Classify a literal version string. The caller has already refused floats.
    ///
    /// `lts/*`, `latest`, `*` and anything with an `x` or a comparison operator produce `Unknown`.
    /// A dotted run of integers produces `Pinned` when it looks complete for its tool and `Series`
    /// otherwise — "complete" meaning three components for a semver toolchain and two for Python,
    /// which is handled by the caller passing `full_components`.
    pub fn classify(raw: &str, full_components: usize) -> VersionSpec {
        let t = raw.trim();
        if t.is_empty() {
            return VersionSpec::Unknown {
                raw: raw.to_string(),
                why: WhyUnknown::Wildcard,
            };
        }
        if t.contains("${{") {
            return VersionSpec::Unknown {
                raw: raw.to_string(),
                why: WhyUnknown::Expression,
            };
        }
        if t.starts_with(['>', '<', '=', '~', '^']) || t.contains(',') || t.contains(' ') {
            return VersionSpec::Unknown {
                raw: raw.to_string(),
                why: WhyUnknown::RangeSpec,
            };
        }
        let parts: Vec<&str> = t.split('.').collect();
        if !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return VersionSpec::Unknown {
                raw: raw.to_string(),
                why: WhyUnknown::Wildcard,
            };
        }
        if parts.len() >= full_components {
            return VersionSpec::Pinned(t.to_string());
        }
        // A prefix. The upper bound is the last stated component plus one, which is what
        // `actions/setup-node` and `actions/setup-python` both mean by a partial version: the
        // newest release matching the prefix.
        let mut hi_parts: Vec<String> = parts.iter().map(|p| (*p).to_string()).collect();
        let last = hi_parts.len() - 1;
        let bumped = parts[last].parse::<u64>().ok().map(|n| n.saturating_add(1));
        match bumped {
            Some(n) => {
                hi_parts[last] = n.to_string();
                VersionSpec::Series {
                    lo: t.to_string(),
                    hi: hi_parts.join("."),
                }
            }
            None => VersionSpec::Unknown {
                raw: raw.to_string(),
                why: WhyUnknown::Wildcard,
            },
        }
    }
}

/// A runner label we could not map onto a Linux x86 container, with the reason preserved.
///
/// Each case is its own variant rather than one "unsupported" string because the reason survives
/// into the report and they mean different things: `MacOs` says the artifact is platform-specific
/// and a Linux rebuild would produce a stream of divergences that say nothing about the package,
/// while `UnknownLabel` says our table is behind and someone should extend it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutOfScope {
    MacOs(String),
    Windows(String),
    SelfHosted,
    /// `pyca/cryptography` has `ubuntu-24.04-arm` and `ubuntu-24.04-ppc64le` cells. Mapping those
    /// onto an amd64 base image produces a rebuild of a different architecture reported as a
    /// rebuild of this one.
    NonX86(String),
    UnknownLabel(String),
}

impl std::fmt::Display for OutOfScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutOfScope::MacOs(l) => write!(f, "`{l}` is a macOS runner"),
            OutOfScope::Windows(l) => write!(f, "`{l}` is a Windows runner"),
            OutOfScope::SelfHosted => f.write_str("the job runs on a self-hosted runner"),
            OutOfScope::NonX86(l) => write!(f, "`{l}` is a Linux runner that is not x86-64"),
            OutOfScope::UnknownLabel(l) => {
                write!(f, "`{l}` is a runner label this build does not recognise")
            }
        }
    }
}

/// A base image we would use to approximate a runner, **labelled as an approximation**.
///
/// Never a `Claim`. `docs/06` §2 and ADR-0009 both insist the `runs-on`-to-base-image mapping is
/// recorded as an approximation and never as an equality claim, and no `Claim` variant asserts a
/// base image — inventing one would make an approximation look like a fact the moment it reached an
/// attestation. So this rides on the reading and on the candidate's assumption list, which is
/// printed next to any divergence it might explain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseImageApprox {
    pub image: String,
    pub from_label: String,
    pub confidence: Confidence,
    pub why: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunnerSpec {
    /// A Linux x86-64 label we can approximate.
    LinuxLabel {
        label: String,
        approx: Option<BaseImageApprox>,
    },
    /// `container:`. The best case: a digest here is not an approximation at all.
    Container {
        image: String,
        digest: Option<String>,
    },
    OutOfScope(OutOfScope),
}

/// What `actions/checkout` was asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckoutSpec {
    /// `0` means the whole history. Recorded, and deliberately **not** a decline — see the note in
    /// `lower.rs`, which checked what our own `git-checkout` tool actually does before deciding.
    pub fetch_depth: Option<String>,
    pub submodules: Option<String>,
    /// `ref:`, cross-checked against the commit we are reading at.
    pub git_ref: Option<String>,
    /// `path:` other than `.` means the tree is not at the root of the workspace, which changes
    /// every relative path in the job.
    pub path: Option<String>,
}

/// The rank of one candidate recipe, as an ordered tuple so a tie is detectable.
///
/// A tuple rather than a single score: with a score, two recipes that disagree about everything can
/// land on the same number by accident and the rung silently picks whichever sorted first. With a
/// tuple, "these two are equally good" is a comparison that comes out `Equal`, and the rung can
/// decline instead of guessing. Fields are in priority order because `Ord` derives lexicographically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct JobRank {
    pub trigger: u8,
    pub publish_marker: u8,
    pub artifact_name_match: u8,
    pub platform_match: u8,
}

/// One workflow job pair, normalized. The thing `lower.rs` turns into a strategy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiRecipe {
    pub source: CiSource,
    pub publish_job: String,
    pub build_job: String,
    pub link: BuildPublishLink,
    pub trigger: TriggerKind,
    pub publishes: PublishStep,
    pub runner: RunnerSpec,
    /// The matrix cell this recipe is about. Empty for a job with no matrix.
    pub matrix_cell: BTreeMap<String, String>,
    pub toolchains: Vec<ToolPin>,
    /// Workflow `env` < job `env` < step `env`, already merged, literals only.
    pub env: BTreeMap<String, String>,
    pub working_directory: Option<String>,
    pub checkout: CheckoutSpec,
    /// The build job's steps, in order.
    pub steps: Vec<CiStep>,
    pub unmodelled: Vec<UnmodelledStep>,
    /// `secrets.*` referenced by a step in the build job that is not the publish step.
    pub secrets_in_build: Vec<String>,
    /// Artifacts the *build* job downloaded from another job. Bytes a rebuild will not produce.
    pub consumed_artifacts: Vec<String>,
    /// Steps in the publish job, before the publish step, that we cannot account for. Empty when
    /// the publish job is the build job, where the same steps are already in `steps`.
    pub touched_after_build: Vec<String>,
    pub rank: JobRank,
}

impl CiRecipe {
    /// A stable name for this recipe in a message, including the matrix cell.
    ///
    /// Two recipes for the same job differing only by matrix cell have to be distinguishable in a
    /// tie message, or the message reads "these two jobs tie" while naming the same job twice.
    pub fn label(&self) -> String {
        let cell: Vec<String> = self
            .matrix_cell
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        if cell.is_empty() {
            format!("{}:{}", self.source.path(), self.build_job)
        } else {
            format!(
                "{}:{} [{}]",
                self.source.path(),
                self.build_job,
                cell.join(",")
            )
        }
    }
}

/// Why the rung produced no candidate.
///
/// Exhaustive and specific, because "the CI rung had nothing to say" is the single most common
/// outcome and an unlabelled silence is indistinguishable from a bug. Every variant is a sentence a
/// person can act on, and several of them (`BuildIsOneUnmodelledStep`, `NoToolForBuildCommand`) are
/// the honest answer to a workflow we read perfectly well and cannot execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decline {
    /// No commit, so there is no "the workflow at the time of this release" to read.
    NoPinnedCommit,
    /// The repository could not be read. Not an error: a rung that failed here would turn a package
    /// with a force-pushed commit into no strategy at all.
    SourceUnreadable {
        detail: String,
    },
    NoWorkflows,
    NoQualifyingJob {
        jobs_seen: usize,
    },
    /// The top two recipes rank equal and disagree about something we would lower. Declining is the
    /// only honest move: picking one would attach a verdict to a coin flip.
    RecipesTie {
        top: Vec<String>,
        disagree_on: &'static str,
    },
    /// A publish job whose build we could not find: the artifact name resolved to nothing, or the
    /// producing job is not reachable through `needs:`.
    BuildJobUnreachable {
        publish_job: String,
        artifact: String,
    },
    /// The build job runs nothing this rung recognises as producing an artifact, and there is no
    /// unmodelled action to blame it on either. Usually a job selected for a publish marker that
    /// turned out to only tag a release.
    BuildJobRunsNoBuild {
        job: String,
    },
    /// Every build command in the job writes only the other Python distribution: `python -m build
    /// --wheel` in a run about the sdist, or `--sdist` in one about a wheel. The workflow never
    /// built the artifact under test, so it cannot say how that was built, and a recipe lowered
    /// from it would displace the heuristic's with a build nobody ran. `built` and `wanted` are
    /// `pypi/build/wheel`'s names for the two, `wheel` and `sdist`.
    WorkflowBuildsAnotherKind {
        built: &'static str,
        wanted: &'static str,
    },
    /// The build is one action we are not willing to guess at. `attrs` is exactly this:
    /// `hynek/build-and-inspect-python-package` *is* the build, and ADR-0009 says we flag rather
    /// than execute an unknown action to find out what it does.
    BuildIsOneUnmodelledStep {
        action: String,
    },
    /// A load-bearing field is behind an expression we could not resolve, and a rendered strategy
    /// must never contain a literal `${{ }}`.
    UnresolvedExpression {
        field: &'static str,
        raw: String,
    },
    /// A build step reads a secret. A token in the publish step is expected and ignored; a secret
    /// reaching a build command means the build consumes something we do not have, and we cannot
    /// know whether it changes the output.
    SecretInBuild {
        names: Vec<String>,
    },
    /// The build job downloaded an artifact another job produced, so its inputs are bytes rather
    /// than source. A rebuild from the checkout alone is a different build, and one that matched
    /// anyway would be matching for the wrong reason.
    BuildConsumesAnotherJobsOutput {
        artifact: String,
    },
    /// Something happened to the artifact in the publish job, between the download and the upload.
    /// Whatever the build produced, that is not what reached the registry.
    ArtifactChangedAfterTheBuild {
        step: String,
    },
    /// The published version is computed at publish time rather than read from the tree.
    /// `vercel/ms` derives a nightly version from `date`, so the version it published exists
    /// nowhere in the repository and no checkout can reproduce it.
    VersionComputedAtPublishTime {
        step: String,
    },
    /// A build command with no tool and no safe lowering: `nox --no-install -R -s release_build`
    /// (`pypa/packaging`), `pnpm run ci-publish` (`vitejs/vite`), any package script.
    NoToolForBuildCommand {
        command: String,
    },
    /// The build was recognised and lowered, and the job also does something this rung cannot
    /// read. Distinct from [`Decline::NoToolForBuildCommand`], which says there was no build to
    /// lower: saying that about a run that found one sends a reader to the wrong step.
    RecipeIncomplete {
        command: String,
    },
    /// A command rewrote the working tree between the checkout and the build. The recipe would
    /// describe a build of the tree as checked out, which is not the tree that was built.
    BuildRewritesTheTree {
        command: String,
    },
    /// `trigon-strategy` ships no pnpm or yarn tool, and `npm/build/pack` is not the same recipe.
    PackageManagerUnsupported {
        manager: String,
    },
    RunnerOutOfScope(OutOfScope),
    /// A value the lowering would hand a tool fails the check the heuristic applies to it: an
    /// `_npmVersion` that names a publishing client rather than an npm release, a `_nodeVersion` no
    /// host serves, a script name that is more than a name. This rung displaces the heuristic's
    /// candidate, so passing such a value on here would undo that check for every package whose
    /// release runs a script.
    UnfitValue {
        what: &'static str,
        value: String,
        because: &'static str,
    },
    /// The rung read the workflow, learned things, and has nothing the heuristic below does not
    /// already know better. See `mod.rs` for why this is the npm default rather than an edge case.
    NothingTheHeuristicLacks {
        because: String,
    },
}

impl std::fmt::Display for Decline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decline::NoPinnedCommit => f.write_str(
                "no commit is pinned for this release, and a workflow read at HEAD is not the \
                 workflow that built it",
            ),
            Decline::SourceUnreadable { detail } => {
                write!(f, "the repository could not be read: {detail}")
            }
            Decline::NoWorkflows => {
                f.write_str("the repository has no `.github/workflows` files at this commit")
            }
            Decline::NoQualifyingJob { jobs_seen } => write!(
                f,
                "none of the {jobs_seen} job(s) carries a publish marker for this ecosystem, so \
                 nothing here describes how the artifact was released"
            ),
            Decline::RecipesTie { top, disagree_on } => write!(
                f,
                "{} rank equally and disagree on {disagree_on}, so choosing one would attach a \
                 verdict to a coin flip",
                top.join(" and ")
            ),
            Decline::BuildJobUnreachable {
                publish_job,
                artifact,
            } => write!(
                f,
                "`{publish_job}` publishes an artifact (`{artifact}`) that no reachable job \
                 uploads, so the build it published is not in this file"
            ),
            Decline::BuildJobRunsNoBuild { job } => write!(
                f,
                "`{job}` was selected as the job that built this release and runs no step this \
                 rung recognises as a build"
            ),
            Decline::WorkflowBuildsAnotherKind { built, wanted } => write!(
                f,
                "every build command in the job builds only the {built}, and this run needs the \
                 {wanted}, so the workflow never built what a recipe from it would build"
            ),
            Decline::BuildIsOneUnmodelledStep { action } => write!(
                f,
                "the build is a single unallowlisted action, `{action}`; we flag an unknown action \
                 rather than execute it to find out what it does"
            ),
            Decline::UnresolvedExpression { field, raw } => write!(
                f,
                "`{field}` is `{raw}`, an expression this resolver cannot evaluate, and a strategy \
                 must never render containing a literal `${{{{ }}}}`"
            ),
            Decline::SecretInBuild { names } => write!(
                f,
                "the build reads {}, so it consumes something we do not have and cannot know the \
                 effect of",
                names
                    .iter()
                    .map(|n| format!("`secrets.{n}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Decline::BuildConsumesAnotherJobsOutput { artifact } => write!(
                f,
                "the build job downloads `{artifact}` from another job, so its inputs are bytes \
                 this rebuild does not produce and a recipe built from the checkout alone is \
                 about a different build"
            ),
            Decline::ArtifactChangedAfterTheBuild { step } => write!(
                f,
                "`{step}` runs in the publish job between the build's output and the upload, so \
                 what reached the registry is not what the build produced"
            ),
            Decline::VersionComputedAtPublishTime { step } => write!(
                f,
                "`{step}` computes the published version at run time, so the version that reached \
                 the registry exists nowhere in the repository"
            ),
            Decline::NoToolForBuildCommand { command } => write!(
                f,
                "`{command}` is the build, and no tool in the registry lowers it"
            ),
            Decline::RecipeIncomplete { command } => write!(
                f,
                "the build was read and lowered, and `{command}` alongside it was not, so the \
                 recipe describes part of this job rather than all of it"
            ),
            Decline::BuildRewritesTheTree { command } => write!(
                f,
                "`{command}` rewrites the working tree before the build reads it, so a recipe \
                 built from the checkout alone is about a different tree"
            ),
            Decline::PackageManagerUnsupported { manager } => write!(
                f,
                "the release used {manager}, and this build ships no {manager} tool; `npm pack` \
                 would be a different recipe rather than an approximation of this one"
            ),
            Decline::RunnerOutOfScope(o) => write!(f, "{o}"),
            Decline::UnfitValue {
                what,
                value,
                because,
            } => write!(f, "{what} is `{value}`, {because}"),
            Decline::NothingTheHeuristicLacks { because } => write!(
                f,
                "the workflow adds nothing to what the registry already recorded: {because}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_field_becomes_a_pin_a_series_or_an_honest_unknown() {
        let unknown = |raw: &str, why| VersionSpec::Unknown {
            raw: raw.to_string(),
            why,
        };
        for (raw, full, want) in [
            ("3.11.7", 2, VersionSpec::Pinned("3.11.7".into())),
            ("3.12", 2, VersionSpec::Pinned("3.12".into())),
            (" 18.17.1 ", 3, VersionSpec::Pinned("18.17.1".into())),
            (
                "3",
                2,
                VersionSpec::Series {
                    lo: "3".into(),
                    hi: "4".into(),
                },
            ),
            (
                "24",
                3,
                VersionSpec::Series {
                    lo: "24".into(),
                    hi: "25".into(),
                },
            ),
            (
                "18.9",
                3,
                VersionSpec::Series {
                    lo: "18.9".into(),
                    hi: "18.10".into(),
                },
            ),
            ("", 2, unknown("", WhyUnknown::Wildcard)),
            ("3.x", 2, unknown("3.x", WhyUnknown::Wildcard)),
            ("lts/*", 3, unknown("lts/*", WhyUnknown::Wildcard)),
            ("latest", 3, unknown("latest", WhyUnknown::Wildcard)),
            ("3..11", 2, unknown("3..11", WhyUnknown::Wildcard)),
            (
                "${{ matrix.python }}",
                2,
                unknown("${{ matrix.python }}", WhyUnknown::Expression),
            ),
            (">=3.9", 2, unknown(">=3.9", WhyUnknown::RangeSpec)),
            ("~=3.9", 2, unknown("~=3.9", WhyUnknown::RangeSpec)),
            ("^18", 3, unknown("^18", WhyUnknown::RangeSpec)),
            ("3.9, <4", 2, unknown("3.9, <4", WhyUnknown::RangeSpec)),
            ("3.9 3.10", 2, unknown("3.9 3.10", WhyUnknown::RangeSpec)),
            // A component too large to bump names no series.
            (
                "99999999999999999999",
                3,
                unknown("99999999999999999999", WhyUnknown::Wildcard),
            ),
        ] {
            assert_eq!(VersionSpec::classify(raw, full), want, "{raw:?}");
        }
    }

    #[test]
    fn a_release_trigger_outranks_a_tag_which_outranks_everything_else() {
        let ranked = |t: TriggerKind| t.rank();
        assert!(ranked(TriggerKind::ReleasePublished) > ranked(TriggerKind::TagPush));
        assert!(ranked(TriggerKind::TagPush) > ranked(TriggerKind::Dispatch));
        assert_eq!(
            ranked(TriggerKind::Dispatch),
            ranked(TriggerKind::Call),
            "two ways a human starts a release"
        );
        assert!(ranked(TriggerKind::Dispatch) > ranked(TriggerKind::BranchPush));
        assert_eq!(
            ranked(TriggerKind::BranchPush),
            ranked(TriggerKind::PullRequest)
        );
        assert!(ranked(TriggerKind::Schedule) > ranked(TriggerKind::Other("gollum".into())));
    }

    #[test]
    fn every_decline_names_what_it_is_about() {
        // The decline is the only explanation a `no-strategy` verdict carries, so each one has to
        // carry its subject: the command, the job, the secret, the runner.
        for (d, subject) in [
            (Decline::NoPinnedCommit, "no commit is pinned"),
            (
                Decline::SourceUnreadable {
                    detail: "git fetch failed".into(),
                },
                "git fetch failed",
            ),
            (Decline::NoWorkflows, "`.github/workflows`"),
            (
                Decline::NoQualifyingJob { jobs_seen: 7 },
                "none of the 7 job(s)",
            ),
            (
                Decline::RecipesTie {
                    top: vec!["a.yml:build".into(), "b.yml:build".into()],
                    disagree_on: "the toolchain",
                },
                "a.yml:build and b.yml:build rank equally and disagree on the toolchain",
            ),
            (
                Decline::BuildJobUnreachable {
                    publish_job: "publish".into(),
                    artifact: "dist".into(),
                },
                "`publish` publishes an artifact (`dist`)",
            ),
            (
                Decline::BuildJobRunsNoBuild { job: "tag".into() },
                "`tag` was selected",
            ),
            (
                Decline::WorkflowBuildsAnotherKind {
                    built: "wheel",
                    wanted: "sdist",
                },
                "builds only the wheel, and this run needs the sdist",
            ),
            (
                Decline::BuildIsOneUnmodelledStep {
                    action: "hynek/build-and-inspect-python-package".into(),
                },
                "`hynek/build-and-inspect-python-package`",
            ),
            (
                Decline::UnresolvedExpression {
                    field: "working-directory",
                    raw: "${{ matrix.dir }}".into(),
                },
                "`working-directory` is `${{ matrix.dir }}`",
            ),
            (
                Decline::SecretInBuild {
                    names: vec!["A".into(), "B".into()],
                },
                "reads `secrets.A`, `secrets.B`",
            ),
            (
                Decline::BuildConsumesAnotherJobsOutput {
                    artifact: "wheels".into(),
                },
                "downloads `wheels` from another job",
            ),
            (
                Decline::ArtifactChangedAfterTheBuild {
                    step: "sign".into(),
                },
                "`sign` runs in the publish job",
            ),
            (
                Decline::VersionComputedAtPublishTime {
                    step: "npm version".into(),
                },
                "`npm version` computes the published version",
            ),
            (
                Decline::NoToolForBuildCommand {
                    command: "nox -s build".into(),
                },
                "`nox -s build` is the build",
            ),
            (
                Decline::RecipeIncomplete {
                    command: "make docs".into(),
                },
                "`make docs` alongside it",
            ),
            (
                Decline::BuildRewritesTheTree {
                    command: "sed -i x f".into(),
                },
                "`sed -i x f` rewrites the working tree",
            ),
            (
                Decline::PackageManagerUnsupported {
                    manager: "pnpm".into(),
                },
                "ships no pnpm tool",
            ),
            (
                Decline::RunnerOutOfScope(OutOfScope::NonX86("ubuntu-24.04-arm".into())),
                "`ubuntu-24.04-arm` is a Linux runner that is not x86-64",
            ),
            (
                Decline::UnfitValue {
                    what: "the registry's `_npmVersion`",
                    value: "lerna/4.0.0".into(),
                    because: "which names no npm release",
                },
                "the registry's `_npmVersion` is `lerna/4.0.0`, which names no npm release",
            ),
            (
                Decline::NothingTheHeuristicLacks {
                    because: "npm recorded it".into(),
                },
                "adds nothing to what the registry already recorded: npm recorded it",
            ),
        ] {
            let text = d.to_string();
            assert!(text.contains(subject), "{d:?}: {text}");
        }
        // The literal it refuses to render is spelled as Actions spells it.
        let text = Decline::UnresolvedExpression {
            field: "f",
            raw: "r".into(),
        }
        .to_string();
        assert!(text.ends_with("a literal `${{ }}`"), "{text}");
        for (o, subject) in [
            (
                OutOfScope::MacOs("macos-14".into()),
                "`macos-14` is a macOS runner",
            ),
            (
                OutOfScope::Windows("windows-2022".into()),
                "`windows-2022` is a Windows runner",
            ),
            (
                OutOfScope::SelfHosted,
                "the job runs on a self-hosted runner",
            ),
            (
                OutOfScope::UnknownLabel("x".into()),
                "`x` is a runner label this build does not recognise",
            ),
        ] {
            assert_eq!(o.to_string(), subject);
        }
    }
}
