//! The CI-derived rung: read the release workflow, lower it, and say what it taught us either way.
//!
//! `docs/06-ci-awareness.md` opens with the argument for this rung and it is the right one: a CI
//! workflow built most packages published after roughly 2023, that workflow sits in the repository,
//! and it names the toolchain, the build command, the environment, the working directory and the
//! publish step. It costs one file read, and it moves targets from "needs a model" to "needs no
//! model", which is where the cost savings in `docs/10-scale.md` come from.
//!
//! # Why this rung has a second entry point
//!
//! `StrategyInferrer::infer` returns `Vec<Candidate>`, and a rung that declines returns an empty
//! one. That is the correct shape for a ladder — but everything the rung learned goes with it, and
//! `docs/06` §4 is explicit that the *evidence* half often beats the candidate half: a workflow we
//! cannot lower faithfully still tells us the Python version, and that alone can turn a failing
//! heuristic strategy into a passing one. There is nowhere in `Vec<Candidate>` to put that, and
//! hanging it on a `Candidate` loses it in exactly the case that matters.
//!
//! So the real API is [`CiInferrer::read`], which returns a [`CiReading`] carrying evidence, notes,
//! the decline and the base-image approximation beside the optional candidate. The
//! `StrategyInferrer` impl is three lines over it, so the rung slots into the ladder unchanged
//! while a caller that wants the rest can ask for it. [`CiReading::seed`] folds the evidence into
//! `ResolvedTarget::intrinsics`, where the heuristic rung below already reads it — `evidence_value`
//! and `build_backend_pin` are looking at that field today — so the rung below improves without
//! knowing this one exists.
//!
//! # What it will not do
//!
//! ADR-0009 and `docs/06` §2 rule out emulating runners: runner images mutate and resist pinning,
//! and emulating them would leave *our own* results irreproducible. We extract intent and lower it
//! to a container plan. The `runs-on` mapping is recorded as an approximation and never as an
//! equality claim, an unallowlisted action is flagged rather than executed to find out what it
//! does, and macOS and Windows report out of scope rather than failing.

pub mod actions;
mod cmd;
mod lower;
mod parse;
pub mod recipe;
pub mod runner;
mod select;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use trigon_core::{Ecosystem, Evidence};

use crate::error::RegistryError;
use crate::infer::{Candidate, StrategyInferrer};
use crate::model::ResolvedTarget;
use crate::source::SourceCache;
use crate::tags;

pub use recipe::{
    BaseImageApprox, BuildPublishLink, CheckoutSpec, CiRecipe, CiSource, CiStep, Decline, JobRank,
    OutOfScope, PublishStep, RunnerSpec, StepPhase, ToolPin, TriggerKind, UnmodelledStep,
    VersionSpec, WhyUnknown,
};

/// How many workflow files we will read, and how large one may be.
///
/// A `.github/workflows` directory is a place a package controls, and a rung that read all of it
/// unbounded would be a memory cost per target in a sweep. Forty files is more than any release
/// repository in the corpus has; half a megabyte is ten times the largest workflow in it
/// (`pyca/cryptography`'s wheel builder, at 15 KB).
const MAX_WORKFLOWS: usize = 40;
const MAX_WORKFLOW_BYTES: usize = 512 * 1024;

/// Files beside the workflows that a workflow can point at.
///
/// Read in the same pass rather than on demand: the checkout is already open, a second blocking
/// round trip per target is the kind of cost `docs/10-scale.md` warns about, and the set is small
/// and fixed.
const AUX_FILES: &[&str] = &[
    ".python-version",
    ".nvmrc",
    ".node-version",
    "pyproject.toml",
    "package-lock.json",
    "uv.lock",
];
const MAX_AUX_BYTES: usize = 8 * 1024 * 1024;

/// Everything one read of a repository's workflows produced.
///
/// The candidate is one field of seven on purpose. A reading that declines is the common case and
/// is not a failure: it has usually learned the interpreter version, the platform and the working
/// directory on its way to deciding it cannot lower the build, and all three are worth more to the
/// rung below than a candidate this rung was not sure of.
#[derive(Debug, Default)]
pub struct CiReading {
    /// Candidate recipes, best first. Empty when no job qualified.
    pub ranked: Vec<CiRecipe>,
    /// Claims about how the artifact was built. Survives a decline; this is the point.
    pub evidence: Vec<Evidence>,
    /// Things a person should know that no `Claim` variant can carry.
    pub notes: Vec<String>,
    pub candidate: Option<Candidate>,
    /// `Some` exactly when `candidate` is `None`.
    pub declined: Option<Decline>,
    /// Set when the only job that could have built this artifact runs somewhere we do not build.
    /// Reported rather than failed: `docs/06` §3.3 says attempting macOS and Windows would produce
    /// a stream of divergences that say nothing about the packages involved.
    pub out_of_scope: Option<OutOfScope>,
    /// The `runs-on`-to-base-image mapping, labelled as the approximation it is.
    ///
    /// It lands here and in the candidate's assumption list and nowhere else, because there is
    /// nowhere else for it to land: `FlowStrategy` has no base-image field, and `OciPlan`'s is
    /// filled from the `--image` argument. Flagged rather than papered over — a consumer that wants
    /// to act on it reads this field.
    pub base_image: Option<BaseImageApprox>,
}

impl CiReading {
    /// Fold this reading's evidence into a target, for the rungs below.
    ///
    /// Additive and idempotent: an identical claim from an identical source is not appended twice,
    /// so calling this before each rung is safe. It deliberately does not *replace* anything —
    /// `resolve_toolchain` exists to intersect disagreeing claims and report a contradiction, and
    /// silently dropping one side of a disagreement here would hide the signal that function is
    /// built to produce.
    pub fn seed(&self, target: &mut ResolvedTarget) {
        for e in &self.evidence {
            if !target.intrinsics.evidence.contains(e) {
                target.intrinsics.evidence.push(e.clone());
            }
        }
    }

    /// One line saying what happened, for a log or a report.
    pub fn summary(&self) -> String {
        match (&self.candidate, &self.declined) {
            (Some(_), _) => format!(
                "a candidate from {}",
                self.ranked
                    .first()
                    .map(CiRecipe::label)
                    .unwrap_or_else(|| "a workflow".into())
            ),
            (None, Some(d)) => format!("no candidate: {d}"),
            (None, None) => "no candidate and no stated reason, which is a bug".into(),
        }
    }
}

/// The CI rung.
///
/// Holds a `Client` for the same reason `PyPiInferrer` does: PyPI records no commit, so one has to
/// be resolved from a tag before there is a workflow to read. Without that the rung would decline
/// on almost every PyPI target, which is most of what `docs/06` is about.
pub struct CiInferrer {
    sources: Arc<SourceCache>,
    mirror: Option<String>,
    /// One entry, keyed by what was read.
    ///
    /// `read()` and `infer()` are two calls about the same target and a caller doing the documented
    /// thing — seed the rungs below, then run the ladder — makes both. Parsing forty workflow files
    /// twice per target is the sort of cost that only shows up at sweep scale, and one entry is all
    /// the locality there is: the engine finishes a target before it starts the next.
    memo: Mutex<Option<(String, Arc<CiReading>)>>,
}

impl CiInferrer {
    pub fn new(sources: Arc<SourceCache>) -> Self {
        CiInferrer {
            sources,
            mirror: None,
            memo: Mutex::new(None),
        }
    }

    /// Pin the registry moment against a time-filtering mirror. See [`crate::NpmInferrer`].
    pub fn with_mirror(mut self, mirror: Option<String>) -> Self {
        self.mirror = mirror;
        self
    }

    /// Read this target's release workflow and say everything it taught us.
    ///
    /// Never an error for a repository we could not read or a workflow we could not parse: those
    /// are declines. It errors only where the caller passed something structurally impossible.
    pub async fn read(&self, target: &ResolvedTarget) -> Result<Arc<CiReading>, RegistryError> {
        let key = memo_key(target);
        if let Some((k, cached)) = self.memo.lock().ok().and_then(|m| m.clone())
            && k == key
        {
            return Ok(cached);
        }
        let reading = Arc::new(self.read_uncached(target).await?);
        if let Ok(mut m) = self.memo.lock() {
            *m = Some((key, reading.clone()));
        }
        Ok(reading)
    }

    async fn read_uncached(&self, target: &ResolvedTarget) -> Result<CiReading, RegistryError> {
        let Some(ecosystem) = ecosystem_tag(target.reference.ecosystem) else {
            return Ok(declined(Decline::NothingTheHeuristicLacks {
                because: "this ecosystem has no CI lowering yet".into(),
            }));
        };
        let Some(source) = &target.source else {
            return Ok(declined(Decline::NoPinnedCommit));
        };

        // The commit. A workflow is evidence about *this* release only if it is the workflow that
        // existed when the release was built, so reading `HEAD` is reading the wrong file. npm
        // records the commit; PyPI does not, and the tag rung is the same one the heuristic uses.
        let (commit, how) = if !source.commit.is_empty() {
            (source.commit.clone(), source.how)
        } else {
            match tags::resolve_version_tag(
                &source.repo_url,
                &target.reference.version,
                &target.reference.name,
            )
            .await
            {
                Some((sha, _tag, how)) => (sha, how),
                None => return Ok(declined(Decline::NoPinnedCommit)),
            }
        };

        // On a blocking thread: the checkout shells out to git, and a rung runs inside the runtime
        // that drives a sweep.
        let sources = self.sources.clone();
        let repo = source.repo_url.clone();
        let at = commit.clone();
        let read = tokio::task::spawn_blocking(move || {
            let c = sources.checkout(&repo, &at)?;
            let files = c.files(20_000)?;
            let workflow_paths: Vec<String> = files
                .iter()
                .filter(|f| is_workflow(f))
                .take(MAX_WORKFLOWS)
                .cloned()
                .collect();
            let borrowed: Vec<&str> = workflow_paths.iter().map(String::as_str).collect();
            let workflows = c.read(&borrowed, MAX_WORKFLOW_BYTES);
            let aux: BTreeMap<String, String> =
                c.read(AUX_FILES, MAX_AUX_BYTES).into_iter().collect();
            Ok::<_, RegistryError>((workflows, aux))
        })
        .await;

        let (raw_workflows, aux_files) = match read {
            Ok(Ok(v)) => v,
            // A repository we cannot read is a decline, not an error. A rung that failed here would
            // turn a package with a force-pushed commit into no strategy at all, which moves a
            // verdict for a reason that has nothing to do with the package.
            Ok(Err(e)) => {
                return Ok(declined(Decline::SourceUnreadable {
                    detail: e.to_string(),
                }));
            }
            Err(e) => {
                return Ok(declined(Decline::SourceUnreadable {
                    detail: format!("the checkout task did not finish: {e}"),
                }));
            }
        };
        if raw_workflows.is_empty() {
            return Ok(declined(Decline::NoWorkflows));
        }

        let parsed: Vec<parse::Workflow> = raw_workflows
            .iter()
            .filter_map(|(path, text)| parse::parse_workflow(path, text))
            .collect();

        let selection = select::select(
            &parsed,
            &select::SelectionCtx {
                ecosystem,
                publish_time: target.intrinsics.publish_time.as_deref(),
                commit: &commit,
                aux_files: &aux_files,
            },
        );

        let mut reading = CiReading {
            notes: selection.notes,
            ..CiReading::default()
        };
        let Some(best) = selection.recipes.first() else {
            reading.declined = Some(Decline::NoQualifyingJob {
                jobs_seen: selection.jobs_seen,
            });
            reading.ranked = selection.recipes;
            return Ok(reading);
        };

        // A tie is checked before anything is lowered, because it invalidates the choice rather
        // than the lowering. Two recipes that rank equal and would lower the same way are
        // interchangeable and either is correct; two that would lower differently mean the ranking
        // did not decide anything, and picking the one that sorted first attaches a verdict to
        // `git ls-files` ordering.
        let tie = selection
            .recipes
            .get(1)
            .filter(|second| second.rank == best.rank)
            .and_then(|second| lower::disagreement(best, second).map(|what| (second, what)));

        let lowered = lower::lower(
            best,
            &lower::LowerCtx {
                target,
                repo: &source.repo_url,
                commit: &commit,
                discovery: how,
                mirror: self.mirror.as_deref(),
                aux_files: &aux_files,
            },
        );

        reading.evidence = lowered.evidence;
        reading.notes.extend(lowered.notes);
        reading.out_of_scope = lowered.out_of_scope;
        reading.base_image = best.runner.approximation().cloned();

        match tie {
            Some((second, disagree_on)) => {
                reading.declined = Some(Decline::RecipesTie {
                    top: vec![best.label(), second.label()],
                    disagree_on,
                });
            }
            None => {
                reading.candidate = lowered.candidate;
                reading.declined = lowered.decline;
            }
        }
        // Only the top recipe's evidence, and `docs/06` §3.1's "the rest become Evidence" is
        // deliberately not implemented as written. Two jobs in one file routinely pin different
        // interpreters — a test matrix beside a release job — and emitting both would hand
        // `resolve_toolchain` a `Contradiction`, whose documented meaning is "escalate to a model".
        // That would spend budget on our own ranking rather than on the package. The losing
        // recipes stay in `ranked` where a report can show them.
        reading.ranked = selection.recipes;

        if reading.candidate.is_none() && reading.declined.is_none() {
            reading.declined = Some(Decline::NoQualifyingJob {
                jobs_seen: selection.jobs_seen,
            });
        }
        Ok(reading)
    }
}

#[async_trait]
impl StrategyInferrer for CiInferrer {
    fn name(&self) -> &'static str {
        "ci-derived"
    }

    /// The ladder's view of this rung: a candidate, or silence.
    ///
    /// Everything else the read produced is reachable through [`CiInferrer::read`], which this
    /// shares a memo with, so a caller that asks for both parses once.
    async fn infer(&self, target: &ResolvedTarget) -> Result<Vec<Candidate>, RegistryError> {
        let reading = self.read(target).await?;
        if let Some(d) = &reading.declined {
            tracing::debug!(rung = "ci-derived", "{d}");
        }
        Ok(reading.candidate.clone().into_iter().collect())
    }
}

fn declined(d: Decline) -> CiReading {
    CiReading {
        declined: Some(d),
        ..CiReading::default()
    }
}

/// `.github/workflows/*.yml` and `*.yaml`, and nothing nested below that.
///
/// Actions itself only reads that one directory, so a file one level deeper is not a workflow
/// however much it looks like one — reusable-workflow fragments under
/// `.github/workflows/shared/` would otherwise be ranked as release jobs in their own right.
fn is_workflow(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(".github/workflows/") else {
        return false;
    };
    !rest.contains('/') && (rest.ends_with(".yml") || rest.ends_with(".yaml"))
}

fn ecosystem_tag(e: Ecosystem) -> Option<&'static str> {
    match e {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("pypi"),
        _ => None,
    }
}

fn memo_key(target: &ResolvedTarget) -> String {
    let (repo, commit) = target
        .source
        .as_ref()
        .map(|s| (s.repo_url.as_str(), s.commit.as_str()))
        .unwrap_or(("", ""));
    format!(
        "{}|{}|{}|{repo}|{commit}",
        target.reference.ecosystem.purl_type(),
        target.reference.registry_name(),
        target.reference.version
    )
}
