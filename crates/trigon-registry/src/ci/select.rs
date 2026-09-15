//! Which job published, which job built, and how confident we are that they are the right pair.
//!
//! `docs/06` §3.1 gives one ranking over one set of jobs. The fixtures say it needs to be two
//! searches joined by an edge, and the reason is structural rather than incidental: trusted
//! publishing moved the upload into a job with `id-token: write` and nothing else, so the release
//! step and the build step now live in different jobs by design. `attrs`, `certifi`, `flask`,
//! `platformdirs` and `packaging` are all shaped that way; `six` is the older single-job shape and
//! still works because `SameJob` is just the degenerate edge.
//!
//! Selection deliberately does not decline. It produces ranked recipes and lets `lower.rs` refuse
//! them, because a recipe we cannot lower is still evidence — `docs/06` §4's whole point is that a
//! workflow we cannot execute still tells us the Python version.

use std::collections::{BTreeMap, BTreeSet};

use super::actions::{self, Known};
use super::cmd::{self, Cmd};
use super::parse::{ExprCtx, Job, RawStep, Workflow, needs_output_producer, resolve, secrets_in};
use super::recipe::{
    BuildPublishLink, CheckoutSpec, CiRecipe, CiSource, CiStep, JobRank, PublishStep, StepPhase,
    ToolPin, TriggerKind, UnmodelledStep, VersionSpec, WhyUnknown,
};
use super::runner;

/// How many recipes we will build before stopping. A matrix job crossed with a matrix publish job
/// is multiplicative, and nothing downstream looks past the first few.
const MAX_RECIPES: usize = 64;

pub struct SelectionCtx<'a> {
    /// `npm` or `pypi`. A job that publishes to the other one is not this target's release.
    pub ecosystem: &'static str,
    pub publish_time: Option<&'a str>,
    pub commit: &'a str,
    /// Files read out of the checkout beside the workflows, for `python-version-file` and friends.
    pub aux_files: &'a BTreeMap<String, String>,
}

#[derive(Default)]
pub struct Selection {
    /// Best first.
    pub recipes: Vec<CiRecipe>,
    pub notes: Vec<String>,
    pub jobs_seen: usize,
    /// A job that carried a publish marker and whose build we could not reach, with what it asked
    /// for. Set so a decline can say that rather than "no job carries a publish marker", which is
    /// false of the run that produced it and sends a reader to the wrong part of the file.
    pub unlinked: Option<(String, String)>,
}

/// A publish step we matched, before it becomes a `PublishStep`.
struct Marker {
    text: String,
    strength: u8,
    /// A TestPyPI upload is not this target's release. `attrs` has a `release-test-pypi` job whose
    /// publish step is otherwise identical to the real one, and selecting it would describe an
    /// in-dev build of a version that never reached pypi.org.
    test_index: bool,
    /// Set when the release used a package manager `trigon-strategy` ships no tool for.
    manager: Option<&'static str>,
}

pub fn select(workflows: &[Workflow], ctx: &SelectionCtx<'_>) -> Selection {
    let mut out = Selection::default();

    for wf in workflows {
        let trigger = wf
            .triggers
            .iter()
            .max_by_key(|t| t.rank())
            .cloned()
            .unwrap_or(TriggerKind::Other("none".into()));

        out.jobs_seen += wf.jobs.len();

        for pub_job in &wf.jobs {
            for pub_cell in &pub_job.cells {
                let env = merged_env(&wf.env, &pub_job.env);
                let ectx = ExprCtx {
                    env: &env,
                    matrix: pub_cell,
                    inputs: &wf.input_defaults,
                };

                let Some((step_index, marker)) = find_publish(pub_job, ctx.ecosystem, &ectx) else {
                    continue;
                };
                if marker.test_index {
                    out.notes.push(format!(
                        "`{}` in `{}` publishes to the test index, so it is not this release",
                        pub_job.id,
                        wf.title()
                    ));
                    continue;
                }
                if let Some(manager) = marker.manager {
                    out.notes.push(format!(
                        "`{}` in `{}` released with {manager}; the recipe below is recorded for \
                         its evidence and is not lowered",
                        pub_job.id,
                        wf.title()
                    ));
                }

                let (build_job, link) = match find_build(wf, pub_job, step_index, &ectx) {
                    Some(found) => found,
                    None => {
                        out.notes.push(format!(
                            "`{}` in `{}` publishes something no reachable job builds",
                            pub_job.id,
                            wf.title()
                        ));
                        out.unlinked.get_or_insert_with(|| {
                            (pub_job.id.clone(), wanted_artifact(pub_job, &ectx))
                        });
                        continue;
                    }
                };

                for build_cell in &build_job.cells {
                    if out.recipes.len() >= MAX_RECIPES {
                        break;
                    }
                    let (recipe, mut notes) = assemble(
                        wf,
                        &trigger,
                        pub_job,
                        step_index,
                        &marker,
                        build_job,
                        build_cell,
                        link.clone(),
                        ctx,
                    );
                    out.notes.append(&mut notes);
                    out.recipes.push(recipe);
                }
            }
        }
    }

    // Descending rank, then a total order on identity so the result is the same on every run of the
    // same binary. A sort that left ties in input order would make the chosen recipe depend on
    // `git ls-files` ordering, which is not something a verdict should rest on.
    out.recipes.sort_by(|a, b| {
        b.rank
            .cmp(&a.rank)
            .then_with(|| a.source.path().cmp(b.source.path()))
            .then_with(|| a.label().cmp(&b.label()))
    });
    out
}

fn merged_env(
    workflow: &BTreeMap<String, String>,
    job: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = workflow.clone();
    env.extend(job.clone());
    env
}

/// The first step in this job that published to our ecosystem's real index.
fn find_publish(job: &Job, ecosystem: &str, ectx: &ExprCtx<'_>) -> Option<(usize, Marker)> {
    for (i, step) in job.steps.iter().enumerate() {
        if let Some(m) = publish_marker(step, ecosystem, ectx) {
            return Some((i, m));
        }
    }
    None
}

fn publish_marker(step: &RawStep, ecosystem: &str, ectx: &ExprCtx<'_>) -> Option<Marker> {
    if let Some((action, _)) = step.action() {
        match (actions::classify(&action), ecosystem) {
            (Some(Known::PyPiPublish), "pypi") => {
                let url = step
                    .with
                    .get("repository-url")
                    .or_else(|| step.with.get("repository_url"))
                    .and_then(|s| s.text())
                    .unwrap_or_default();
                return Some(Marker {
                    text: action,
                    strength: 3,
                    test_index: url.contains("test.pypi.org"),
                    manager: None,
                });
            }
            (Some(Known::NpmPublish), "npm") => {
                return Some(Marker {
                    text: action,
                    strength: 3,
                    test_index: false,
                    manager: None,
                });
            }
            _ => return None,
        }
    }

    let run = step.run.as_deref()?;
    // Resolution failure is not fatal here: we are pattern-matching for a marker, not lowering.
    let script = resolve(run, ectx).unwrap_or_else(|_| run.to_string());

    if ecosystem == "pypi" {
        let publishes = cmd::classify_script(&script)
            .into_iter()
            .any(|c| matches!(&c, Cmd::Publish(f) if f.contains("twine") || f.contains("uv ")));
        if publishes {
            // Only the step's declared `env:` mapping, never the script body. `benjaminp/six`
            // exports `TWINE_REPOSITORY=testpypi` *inside* a shell conditional that also exports
            // `pypi`, so a scan of the text would disqualify a job that publishes to the real
            // index on a tag push. A declared `env:` entry is unconditional and is the only form
            // that can be read as a fact.
            let test = step
                .env
                .get("TWINE_REPOSITORY")
                .is_some_and(|v| v.eq_ignore_ascii_case("testpypi"))
                || step
                    .env
                    .get("TWINE_REPOSITORY_URL")
                    .is_some_and(|v| v.contains("test.pypi.org"));
            return Some(Marker {
                text: "twine upload".into(),
                strength: 2,
                test_index: test,
                manager: None,
            });
        }
    }

    if ecosystem == "npm" {
        // Longest first, and it matters: "pnpm publish" *contains* "npm publish", so the obvious
        // ordering reads a pnpm release as an npm one and loses the reason the rung declines.
        for (needle, manager) in [
            ("yarn npm publish", Some("yarn")),
            ("pnpm publish", Some("pnpm")),
            ("yarn publish", Some("yarn")),
            ("npm publish", None),
        ] {
            if script.contains(needle) {
                return Some(Marker {
                    text: needle.into(),
                    strength: 2,
                    test_index: false,
                    manager,
                });
            }
        }
    }
    None
}

/// The job that built what the publish job uploaded.
fn find_build<'a>(
    wf: &'a Workflow,
    pub_job: &'a Job,
    publish_step: usize,
    ectx: &ExprCtx<'_>,
) -> Option<(&'a Job, BuildPublishLink)> {
    // What separates the two shapes is `actions/download-artifact`, not the presence of a build
    // command. A trusted-publishing job exists to hold `id-token: write` and does exactly two
    // things: download what another job built, and upload it. Anything else — `six` installing and
    // building in the same job, `vercel/ms` running `pnpm build` before publishing — is its own
    // build job, and treating it otherwise loses the recipe entirely.
    //
    // A job doing substantive work of its own wins even when it also downloads, because then the
    // artifact it published is the one it just built.
    let downloads = pub_job.steps.iter().any(|s| {
        s.action()
            .is_some_and(|(a, _)| actions::classify(&a) == Some(Known::DownloadArtifact))
    });
    let does_own_work = pub_job
        .steps
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != publish_step)
        .any(|(_, s)| {
            s.run.as_deref().is_some_and(|r| {
                cmd::classify_script(r).iter().any(|c| {
                    !matches!(
                        c,
                        Cmd::Incidental
                            | Cmd::PyDeps(_)
                            | Cmd::Publish(_)
                            | Cmd::GithubEnv { .. }
                            | Cmd::Network(_)
                    )
                })
            })
        });
    if does_own_work || !downloads {
        return Some((pub_job, BuildPublishLink::SameJob));
    }

    let reachable = needs_closure(wf, &pub_job.id);

    for step in &pub_job.steps {
        let Some((action, _)) = step.action() else {
            continue;
        };
        if actions::classify(&action) != Some(Known::DownloadArtifact) {
            continue;
        }

        // `artifact-ids: ${{ needs.<job>.outputs.<x> }}` names the producer outright. `flask` does
        // this, and it is exact where a name match is a guess: no artifact name appears anywhere in
        // the file, so nothing else in this function would find the edge.
        if let Some(ids) = step.with.get("artifact-ids").and_then(|s| s.text())
            && let Some((producer, output)) = needs_output_producer(&ids)
            && let Some(job) = wf.jobs.iter().find(|j| j.id == producer)
            && reachable.contains(&producer)
            // The producing job has to actually declare the output the expression names. Without
            // this the edge would be believed on the strength of a job id alone, and an expression
            // referring to an output nobody defines resolves to the empty string at run time —
            // meaning the real workflow downloaded nothing and the recipe would describe a build
            // that never reached the publish step.
            && job.outputs.contains_key(&output)
        {
            return Some((job, BuildPublishLink::ArtifactId { producer }));
        }

        // Otherwise match the artifact name against an upload in a job we depend on. `name:` is a
        // literal and `pattern:` is a glob, and conflating them was how every matrix release lost
        // its edge: a job collecting `dist-*` was looked up as an upload literally called `dist-*`.
        let (raw, glob) = match step.with.get("name").and_then(|s| s.text()) {
            Some(n) => (n, false),
            None => match step.with.get("pattern").and_then(|s| s.text()) {
                Some(p) => (p, true),
                None => continue,
            },
        };
        let Ok(wanted) = resolve(&raw, ectx) else {
            continue;
        };
        for job in &wf.jobs {
            if !reachable.contains(&job.id) {
                continue;
            }
            // The *uploaded* name, not the glob that asked for it: `dist-*` is what the publish
            // job typed, and `dist-ubuntu-22.04` is the artifact the edge is actually about.
            if let Some(name) = uploads_artifact(wf, job, &wanted, glob) {
                return Some((job, BuildPublishLink::Artifact { name }));
            }
        }
        let name = wanted;

        // No `actions/upload-artifact` matched, and that is not always a broken workflow: an
        // unallowlisted action can upload too. `python-attrs/attrs` uploads through
        // `hynek/build-and-inspect-python-package`, so the name `Packages` appears exactly once in
        // the file and nothing we recognise produced it. Where the publish job depends on exactly
        // one other job, `needs:` names the producer as surely as an upload would — and following
        // it is what turns `attrs` from "we could not find the build" into the far more useful
        // "the build is one action we decline to execute".
        let others: Vec<&Job> = wf
            .jobs
            .iter()
            .filter(|j| j.id != pub_job.id && reachable.contains(&j.id))
            .collect();
        if let [only] = others.as_slice() {
            return Some((*only, BuildPublishLink::Artifact { name }));
        }
    }
    None
}

/// Steps in the publish job that could have changed the artifact before it was uploaded.
///
/// Everything before the publish step that is not a step we can account for. What is accounted
/// for is narrow on purpose: the artifact actions (which carry the edge), the checkout, caching,
/// toolchain setup, an inert action, and a `run:` whose every fragment is incidental. Anything
/// else had the bytes and our reach to them ends here.
fn touches_the_artifact(pub_job: &Job, publish_step: usize) -> Vec<String> {
    let mut out = Vec::new();
    for step in pub_job.steps.iter().take(publish_step) {
        if let Some((action, _)) = step.action() {
            let accounted = matches!(
                actions::classify(&action),
                Some(
                    Known::Checkout
                        | Known::Cache
                        | Known::UploadArtifact
                        | Known::DownloadArtifact
                        | Known::SetupPython
                        | Known::SetupNode
                        | Known::SetupUv
                        | Known::OtherToolchain(_)
                )
            ) || actions::is_inert(&action);
            if !accounted {
                out.push(action);
            }
            continue;
        }
        if let Some(run) = step.run.as_deref() {
            // The publish job's scripts are read with the same classifier as the build's, and the
            // same rule: a fragment we cannot read is one we cannot call harmless.
            for c in cmd::classify_script(run) {
                match c {
                    // Installing the publish tooling cannot rewrite what is already in `dist/`,
                    // and a release job that pins `twine` before uploading is the common shape.
                    Cmd::Incidental | Cmd::Publish(_) | Cmd::PyDeps(_) | Cmd::SystemDeps(_) => {}
                    other => {
                        out.push(format!("{}: {other:?}", step.label()));
                        break;
                    }
                }
            }
        }
    }
    out
}

/// What a publish job's `download-artifact` steps asked for, for a decline to name.
///
/// The first `name:` or `pattern:` it carries, unresolved expressions and all — this is a message
/// for a person, and `${{ env.dists }}` is more use to them than an empty string.
fn wanted_artifact(job: &Job, ectx: &ExprCtx<'_>) -> String {
    for step in &job.steps {
        let Some((action, _)) = step.action() else {
            continue;
        };
        if actions::classify(&action) != Some(Known::DownloadArtifact) {
            continue;
        }
        if let Some(raw) = step
            .with
            .get("name")
            .or_else(|| step.with.get("pattern"))
            .and_then(|s| s.text())
        {
            return resolve(&raw, ectx).unwrap_or(raw);
        }
    }
    "(unnamed)".into()
}

/// Whether this job uploads an artifact under this name, resolved in the producing job's own scope.
///
/// The producer's scope matters: `platformdirs` writes the name once as a workflow-level `env`
/// entry and refers to it as `${{ env.dists-artifact-name }}` from both jobs, so resolving the
/// upload's name in the *consumer's* scope would work by accident there and fail wherever the two
/// jobs differ.
fn uploads_artifact(wf: &Workflow, job: &Job, wanted: &str, glob: bool) -> Option<String> {
    let env = merged_env(&wf.env, &job.env);
    for cell in &job.cells {
        let ectx = ExprCtx {
            env: &env,
            matrix: cell,
            inputs: &wf.input_defaults,
        };
        for step in &job.steps {
            let Some((action, _)) = step.action() else {
                continue;
            };
            if actions::classify(&action) != Some(Known::UploadArtifact) {
                continue;
            }
            let raw = step
                .with
                .get("name")
                .and_then(|s| s.text())
                // An `upload-artifact` with no `name:` uploads as `artifact`, which is the default
                // a consumer downloading by that name is relying on.
                .unwrap_or_else(|| "artifact".into());
            let Ok(name) = resolve(&raw, &ectx) else {
                continue;
            };
            let hit = match glob {
                true => glob_matches(wanted, &name),
                false => name == wanted,
            };
            if hit {
                return Some(name);
            }
        }
    }
    None
}

/// `actions/download-artifact`'s `pattern:`, which is minimatch, reduced to the part workflows use.
///
/// `*` matches any run of characters and `?` matches one. Nothing else: minimatch also has brace
/// expansion and character classes, and a pattern using them matches nothing here rather than
/// matching something approximate. A wrong build job is worse than an unresolved edge.
fn glob_matches(pattern: &str, name: &str) -> bool {
    fn go(p: &[u8], n: &[u8]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some(b'*') => (0..=n.len()).any(|i| go(&p[1..], &n[i..])),
            Some(b'?') => !n.is_empty() && go(&p[1..], &n[1..]),
            Some(c) => n.first() == Some(c) && go(&p[1..], &n[1..]),
        }
    }
    // Anything minimatch can do that this cannot, it must not pretend to do.
    if pattern.contains(['{', '[', '!', '+', '(']) {
        return false;
    }
    go(pattern.as_bytes(), name.as_bytes())
}

/// Every job this one depends on, transitively, including itself.
fn needs_closure(wf: &Workflow, start: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start.to_string()];
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(job) = wf.jobs.iter().find(|j| j.id == id) {
            stack.extend(job.needs.iter().cloned());
        }
    }
    seen
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    wf: &Workflow,
    trigger: &TriggerKind,
    pub_job: &Job,
    publish_step: usize,
    marker: &Marker,
    build_job: &Job,
    build_cell: &BTreeMap<String, String>,
    link: BuildPublishLink,
    ctx: &SelectionCtx<'_>,
) -> (CiRecipe, Vec<String>) {
    let mut notes = Vec::new();
    let env = merged_env(&wf.env, &build_job.env);
    let ectx = ExprCtx {
        env: &env,
        matrix: build_cell,
        inputs: &wf.input_defaults,
    };

    // The runner. `container:` wins where it exists: it is the one form that can already be
    // digest-pinned, which makes it a statement rather than an approximation.
    //
    // **But the host still decides scope.** `container:` used to be taken before `runs_on` was
    // consulted at all, so a job on `windows-latest` or a self-hosted machine that also declared a
    // container slipped past the out-of-scope check entirely — and ADR-0009's rule is that those
    // report `Unsupported` rather than a verdict. A container on an unsupported host is still an
    // unsupported host: the image says what userspace the build sees, not what kernel or
    // architecture it runs on, and `windows-latest` running a Linux image is not a thing.
    // `[self-hosted, linux, x64]` is a label *set*, and the self-hosted member is the one that
    // decides: the others describe a machine we know nothing else about.
    let host_label = {
        let labels: Vec<String> = build_job
            .runs_on
            .iter()
            .map(|l| resolve(l, &ectx).unwrap_or_else(|_| l.clone()))
            .collect();
        labels
            .iter()
            .find(|l| l.to_ascii_lowercase().starts_with("self-hosted"))
            .or_else(|| labels.first())
            .cloned()
            .unwrap_or_default()
    };
    let host_spec =
        (!host_label.is_empty()).then(|| runner::map_label(&host_label, ctx.publish_time));
    let host_out_of_scope = host_spec
        .as_ref()
        .is_some_and(|s| s.out_of_scope().is_some());

    let spec = match &build_job.container {
        // A failed resolution falls back to the *original* text, never to the expression that
        // defeated it: `resolve` returns the offending `${{ … }}` as its error, and substituting
        // that for the whole field would report `${{ matrix.os }}` as the image name.
        // **The host still decides scope.** `container:` was taken before `runs_on` was consulted
        // at all, so a job on `windows-latest` or a self-hosted machine that also declared a
        // container slipped past the out-of-scope check — and ADR-0009's rule is that those report
        // `Unsupported` rather than a verdict. An image says what userspace the build sees, not
        // what kernel or architecture it runs on, and `windows-latest` running a Linux image is not
        // a thing. So where the host is out of scope, the host's answer wins and the container is
        // not consulted.
        Some(_) if host_out_of_scope => host_spec.expect("checked by host_out_of_scope"),
        Some(image) => match resolve(image, &ectx) {
            Ok(i) => runner::map_container(&i),
            Err(_) => runner::map_label(image, ctx.publish_time),
        },
        None => host_spec
            .clone()
            .unwrap_or_else(|| runner::map_label("", ctx.publish_time)),
    };

    let mut toolchains = Vec::new();
    let mut consumed = Vec::new();
    let mut unmodelled = Vec::new();
    let mut steps = Vec::new();
    let mut checkout = CheckoutSpec::default();
    let mut secrets_in_build = BTreeSet::new();
    let mut working_directory = build_job.defaults_working_directory.clone();

    let same_job_publish = std::ptr::eq(pub_job, build_job);
    // **What the publish job does to the artifact, when it is not the build job.** The loop below
    // walks the *build* job, so in the two-job shape the publish job's own steps were never
    // classified at all — and everything it does between downloading the build's output and
    // uploading it happens to the bytes that reached the registry. A step that repacks, signs or
    // strips `dist/` makes the published artifact different from the built one, and the recipe
    // would have said the build explained it. That is not a confidence question: the published
    // artifact is what a verdict is about.
    let touched_after_build = match same_job_publish {
        true => Vec::new(),
        false => touches_the_artifact(pub_job, publish_step),
    };
    // Where the publish step lands in `recipe.steps`, which is not where it sat in the job: a step
    // with neither `uses:` nor `run:` is dropped on the way, and an index that addressed the job's
    // list would then point at the wrong step. Downstream uses this to tell "a token in the publish
    // step", which is expected, from "a secret in the build", which is a decline.
    let mut publish_step_position = publish_step;

    for (i, step) in build_job.steps.iter().enumerate() {
        let is_publish_step = same_job_publish && i == publish_step;
        if is_publish_step {
            publish_step_position = steps.len();
        }
        let phase = phase_of(step, is_publish_step);

        if let Some((action, action_ref)) = step.action() {
            let known = actions::classify(&action);
            let with: BTreeMap<String, String> = step
                .with
                .iter()
                .filter_map(|(k, v)| v.text().map(|t| (k.clone(), t)))
                .collect();

            match known {
                Some(Known::Checkout) => {
                    checkout = CheckoutSpec {
                        fetch_depth: with.get("fetch-depth").cloned(),
                        submodules: with.get("submodules").cloned(),
                        git_ref: with.get("ref").cloned(),
                        path: with.get("path").cloned(),
                    };
                }
                Some(Known::SetupPython) => {
                    toolchains.extend(python_pin(step, &ectx, ctx, &mut notes));
                }
                Some(Known::SetupNode) => {
                    toolchains.extend(node_pin(step, &ectx, ctx, &mut notes));
                }
                Some(Known::SetupUv) => {
                    if let Some(pin) = version_pin(step, "version", "uv", 3, &ectx, &mut notes) {
                        toolchains.push(pin);
                    }
                    if let Some(pin) =
                        version_pin(step, "python-version", "python", 2, &ectx, &mut notes)
                    {
                        toolchains.push(pin);
                    }
                }
                Some(Known::SetupPnpm) => {
                    notes.push(format!(
                        "`{}` in `{}` sets up pnpm; this build ships no pnpm tool",
                        build_job.id,
                        wf.title()
                    ));
                }
                Some(Known::OtherToolchain(tool)) => {
                    // Evidence only. No registry client exists for these ecosystems, so a pin here
                    // can never produce a candidate — but it can still narrow one, and it costs a
                    // line to keep.
                    for field in ["version", "toolchain", "distribution", "ruby-version"] {
                        if let Some(pin) = version_pin(step, field, tool, 3, &ectx, &mut notes) {
                            toolchains.push(pin);
                            break;
                        }
                    }
                }
                Some(Known::CiBuildWheel) => {
                    notes.push(
                        "the build runs `pypa/cibuildwheel`, whose manylinux image is a real \
                         container pin that `FlowStrategy` has nowhere to put"
                            .into(),
                    );
                    unmodelled.push(UnmodelledStep {
                        action: action.clone(),
                        action_ref: action_ref.clone(),
                        phase,
                    });
                }
                // **A download into the build job is an input to the build.** This sat with
                // `actions/cache` on the list of steps that provably do not matter, on the
                // reasoning that the artifact actions carry the edge between jobs rather than
                // building anything. That is true of the *publish* job, and this loop walks the
                // *build* job: bytes another job produced are reaching the tree before the build
                // reads it, and a recipe that drops the step describes a build from source alone.
                // It is the shape `docs/12-security.md` §1.1 is about — a rebuild that matches
                // because it was handed the answer.
                Some(Known::DownloadArtifact) => {
                    consumed.push(
                        with.get("name")
                            .or_else(|| with.get("pattern"))
                            .cloned()
                            .unwrap_or_else(|| "artifact".into()),
                    );
                }
                // Caching cannot change output, and the remaining artifact and publish actions
                // carry the edge rather than building anything. Neither is unmodelled: recording
                // them would depress a candidate's confidence for steps that provably do not
                // matter.
                Some(
                    Known::Cache
                    | Known::UploadArtifact
                    | Known::PyPiPublish
                    | Known::NpmPublish
                    | Known::GithubRelease,
                ) => {}
                None if actions::is_inert(&action) => {}
                None => unmodelled.push(UnmodelledStep {
                    action: action.clone(),
                    action_ref: action_ref.clone(),
                    phase,
                }),
            }

            steps.push(CiStep::Uses {
                action,
                action_ref,
                with,
            });
            continue;
        }

        let Some(run) = step.run.as_deref() else {
            continue;
        };
        // A build step behind a condition we cannot evaluate may not have run at all. Recorded
        // rather than acted on: `certifi` guards its *publish* step with
        // `if: github.event_name == 'push'`, which is fine, and a guard on a build step is the case
        // worth seeing in a report next to a divergence.
        if !is_publish_step
            && let Some(cond) = &step.if_expr
            && resolve(cond, &ectx).is_err()
        {
            notes.push(format!(
                "`{}` runs only when `{cond}` holds, which this rung cannot evaluate, so the \
                 recipe assumes it ran",
                step.label()
            ));
        }
        let script = resolve(run, &ectx).unwrap_or_else(|_| run.to_string());
        let mut found = secrets_in(run);
        for v in step.env.values() {
            found.extend(secrets_in(v));
        }
        if !is_publish_step {
            secrets_in_build.extend(found.iter().cloned());
        }
        if working_directory.is_none() && step.working_directory.is_some() {
            working_directory = step.working_directory.clone();
        }
        steps.push(CiStep::Runs {
            script,
            secrets: found.into_iter().collect(),
            working_directory: step.working_directory.clone(),
        });
    }

    let rank = JobRank {
        trigger: trigger.rank(),
        publish_marker: marker.strength,
        // An exact edge outranks a name match, which outranks "the same job did both" only because
        // the first two prove the publish job consumed *this* build's output.
        artifact_name_match: match &link {
            BuildPublishLink::ArtifactId { .. } => 2,
            BuildPublishLink::Artifact { .. } => 1,
            BuildPublishLink::SameJob => 1,
        },
        platform_match: u8::from(spec.out_of_scope().is_none()),
    };

    let recipe = CiRecipe {
        source: CiSource::GithubActions {
            path: wf.path.clone(),
            commit: ctx.commit.to_string(),
        },
        publish_job: pub_job.id.clone(),
        build_job: build_job.id.clone(),
        link,
        trigger: trigger.clone(),
        publishes: PublishStep {
            marker: marker.text.clone(),
            ecosystem: ctx.ecosystem,
            step_index: publish_step_position,
            strength: marker.strength,
        },
        runner: spec,
        matrix_cell: build_cell.clone(),
        toolchains,
        env,
        working_directory,
        checkout,
        steps,
        unmodelled,
        secrets_in_build: secrets_in_build.into_iter().collect(),
        consumed_artifacts: consumed,
        touched_after_build,
        rank,
    };
    (recipe, notes)
}

fn phase_of(step: &RawStep, is_publish_step: bool) -> StepPhase {
    if is_publish_step {
        return StepPhase::Publish;
    }
    match step.action().as_ref().map(|(a, _)| actions::classify(a)) {
        Some(Some(Known::Checkout)) => StepPhase::Src,
        Some(Some(
            Known::SetupPython | Known::SetupNode | Known::SetupUv | Known::OtherToolchain(_),
        )) => StepPhase::Deps,
        Some(Some(Known::PyPiPublish | Known::NpmPublish | Known::GithubRelease)) => {
            StepPhase::Publish
        }
        _ => StepPhase::Build,
    }
}

/// `actions/setup-python`, including `python-version-file`.
fn python_pin(
    step: &RawStep,
    ectx: &ExprCtx<'_>,
    ctx: &SelectionCtx<'_>,
    notes: &mut Vec<String>,
) -> Option<ToolPin> {
    if let Some(pin) = version_pin(step, "python-version", "python", 2, ectx, notes) {
        return Some(pin);
    }
    let file = step.with.get("python-version-file")?.text()?;
    Some(version_from_file(&file, "python", 2, ctx, notes))
}

fn node_pin(
    step: &RawStep,
    ectx: &ExprCtx<'_>,
    ctx: &SelectionCtx<'_>,
    notes: &mut Vec<String>,
) -> Option<ToolPin> {
    if let Some(pin) = version_pin(step, "node-version", "node", 3, ectx, notes) {
        return Some(pin);
    }
    let file = step.with.get("node-version-file")?.text()?;
    Some(version_from_file(&file, "node", 3, ctx, notes))
}

/// Read a version out of one `with:` field.
///
/// `full_components` is how many dotted components make a complete pin for this tool: three for a
/// semver toolchain, two for Python, whose releases are `3.11.7` but whose series is `3.11` and
/// where `3.11` in a workflow means "the newest 3.11.x the runner has".
fn version_pin(
    step: &RawStep,
    field: &str,
    tool: &str,
    full_components: usize,
    ectx: &ExprCtx<'_>,
    notes: &mut Vec<String>,
) -> Option<ToolPin> {
    let raw = step.with.get(field)?;
    let from = format!(
        "ci:{}:{field}",
        step.action().map(|(a, _)| a).unwrap_or_default()
    );
    let text = match raw.version_text() {
        Ok(Some(t)) => t,
        // The float case, stated rather than swallowed. A reader seeing no Python claim on a
        // workflow that plainly names one deserves to know why.
        Err(written) => {
            notes.push(format!(
                "`{field}: {written}` is an unquoted YAML float and parses to a different version \
                 than it reads as, so no {tool} claim is made from it"
            ));
            return Some(ToolPin {
                tool: tool.into(),
                spec: VersionSpec::Unknown {
                    raw: written,
                    why: WhyUnknown::UnquotedFloat,
                },
                from,
            });
        }
        Ok(None) => {
            return Some(ToolPin {
                tool: tool.into(),
                spec: VersionSpec::Unknown {
                    raw: format!("{raw:?}"),
                    why: WhyUnknown::Multiple,
                },
                from,
            });
        }
    };
    let resolved = match resolve(&text, ectx) {
        Ok(r) => r,
        Err(expr) => {
            return Some(ToolPin {
                tool: tool.into(),
                spec: VersionSpec::Unknown {
                    raw: expr,
                    why: WhyUnknown::Expression,
                },
                from,
            });
        }
    };
    Some(ToolPin {
        tool: tool.into(),
        spec: VersionSpec::classify(&resolved, full_components),
        from,
    })
}

/// `python-version-file:` / `node-version-file:`, read out of the checkout.
///
/// `.python-version` and `.nvmrc` hold a bare version and are a real pin. `pyproject.toml` is not:
/// `actions/setup-python` reads `requires-python` from it, which is a floor rather than a version,
/// and `flask` points its release workflow at exactly that. Emitting an exact claim from a floor
/// would be the most confident wrong statement this module could make.
fn version_from_file(
    file: &str,
    tool: &str,
    full_components: usize,
    ctx: &SelectionCtx<'_>,
    notes: &mut Vec<String>,
) -> ToolPin {
    let from = format!("ci:{file}");
    let Some(text) = ctx.aux_files.get(file) else {
        return ToolPin {
            tool: tool.into(),
            spec: VersionSpec::Unknown {
                raw: file.into(),
                why: WhyUnknown::FileMissing,
            },
            from,
        };
    };
    if file.ends_with(".toml") {
        notes.push(format!(
            "the workflow reads the {tool} version from `{file}`, which states a supported range \
             rather than the version the build ran on"
        ));
        let floor = text
            .lines()
            .find(|l| l.trim_start().starts_with("requires-python"))
            .unwrap_or("")
            .trim()
            .to_string();
        return ToolPin {
            tool: tool.into(),
            spec: VersionSpec::Unknown {
                raw: floor,
                why: WhyUnknown::RangeSpec,
            },
            from,
        };
    }
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("");
    ToolPin {
        tool: tool.into(),
        spec: VersionSpec::classify(first, full_components),
        from,
    }
}
