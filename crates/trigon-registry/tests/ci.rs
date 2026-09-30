//! The CI-derived rung, against real release workflows and no network.
//!
//! Every fixture under `tests/fixtures/workflows/` is a verbatim copy of a file that published a
//! package, named by repository, path and commit in its own header. That is the point of them: the
//! claims this module makes about what a workflow *means* are checked against workflows that exist
//! rather than against the chapter, and where the two disagree the file wins. Three of the rules in
//! `src/ci/` exist only because a fixture contradicted the specification — the publish job is
//! usually not the build job, an unquoted version is a float, and a `-latest` label inside a
//! rollout window resolves to nothing.
//!
//! The repository is made on the spot with `git`, so the suite needs nothing but a local git.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use trigon_core::{
    ArtifactId, Claim, Confidence, Ecosystem, Evidence, Intrinsics, SourceDiscovery,
    SourceProvenance, TargetRef, ToolchainResolution, resolve_toolchain,
};
use trigon_registry::ci::recipe::{BuildPublishLink, Decline, OutOfScope};
use trigon_registry::{
    ArtifactMeta, CiInferrer, CiReading, Derivation, ResolvedTarget, StrategyInferrer,
};
use trigon_strategy::{StepBody, Strategy};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/workflows");

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// A directory of this test's own, removed when the test is done with it.
fn tmpdir(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("trigon-ci-{name}-"))
        .tempdir()
        .unwrap()
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// One workflow file to plant in the repository: where it goes, and what is in it.
enum Wf {
    /// A vendored fixture, by basename.
    Fixture(&'static str),
    /// A file written for one test, when the point is a shape no real workflow in the corpus has.
    Inline(&'static str, &'static str),
}

/// A repository at a pinned commit holding these workflows and these extra files. The directory
/// holding it goes when the first element is dropped, so a test keeps it for as long as it reads.
fn repo(
    name: &str,
    workflows: &[Wf],
    extra: &[(&str, &str)],
) -> (tempfile::TempDir, String, String) {
    let root = tmpdir(name);
    let repo = root.path().join("origin");
    std::fs::create_dir_all(repo.join(".github").join("workflows")).unwrap();
    for w in workflows {
        let (file, text) = match w {
            Wf::Fixture(basename) => (
                format!("{basename}.yml"),
                std::fs::read_to_string(format!("{FIXTURES}/{basename}.yml"))
                    .unwrap_or_else(|e| panic!("{basename}: {e}")),
            ),
            Wf::Inline(file, text) => ((*file).to_string(), (*text).to_string()),
        };
        std::fs::write(repo.join(".github").join("workflows").join(file), text).unwrap();
    }
    for (path, text) in extra {
        let p = repo.join(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, text).unwrap();
    }
    git(&repo, &["init", "--quiet", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "--quiet", "-m", "release"]);
    let out = Command::new("git")
        .current_dir(&repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let commit = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (root, repo.to_string_lossy().into_owned(), commit)
}

fn target(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    url: &str,
    commit: &str,
) -> ResolvedTarget {
    ResolvedTarget {
        reference: TargetRef::new(ecosystem, name, version),
        artifacts: vec![ArtifactMeta {
            id: ArtifactId::new(format!("{name}-{version}-py3-none-any.whl")),
            url: String::new(),
            declared: Vec::new(),
            declared_note: None,
            size: None,
        }],
        intrinsics: Intrinsics {
            // Settled well inside the 22.04 window, so a `-latest` label resolves.
            publish_time: Some("2024-03-01T00:00:00Z".into()),
            declared_repo: Some(url.into()),
            registry_moment: None,
            evidence: Vec::new(),
        },
        source: Some(SourceProvenance {
            repo_url: url.into(),
            declared_url: None,
            commit: commit.into(),
            ref_name: None,
            subdir: None,
            how: SourceDiscovery::RegistryCommit,
        }),
        about: None,
    }
}

/// The rung, pointed at a cache under this test's own directory.
fn rung(root: &tempfile::TempDir) -> CiInferrer {
    let sources = Arc::new(
        trigon_registry::SourceCache::new(root.path().join("cache")).trusting_local_paths(),
    );
    CiInferrer::new(sources)
}

async fn read_pypi(name: &str, workflows: &[Wf], extra: &[(&str, &str)]) -> Arc<CiReading> {
    let (root, url, commit) = repo(name, workflows, extra);
    let t = target(Ecosystem::PyPI, name, "1.2.3", &url, &commit);
    rung(&root).read(&t).await.unwrap()
}

async fn read_npm(name: &str, workflows: &[Wf], toolchain: bool) -> Arc<CiReading> {
    read_npm_recorded(name, workflows, toolchain.then_some(("24.1.0", "11.3.0"))).await
}

/// [`read_npm`], with the `_nodeVersion` and `_npmVersion` the registry recorded, if any.
async fn read_npm_recorded(
    name: &str,
    workflows: &[Wf],
    recorded: Option<(&str, &str)>,
) -> Arc<CiReading> {
    let (root, url, commit) = repo(name, workflows, &[]);
    let mut t = target(Ecosystem::Npm, name, "1.2.3", &url, &commit);
    if let Some((node, npm)) = recorded {
        for (tool, version, source) in [
            ("node", node, "npm:_nodeVersion"),
            ("npm", npm, "npm:_npmVersion"),
        ] {
            t.intrinsics.evidence.push(Evidence::new(
                Claim::ToolchainExact {
                    tool: tool.into(),
                    version: version.into(),
                },
                Confidence::Certain,
                source,
            ));
        }
    }
    rung(&root).read(&t).await.unwrap()
}

fn params(strategy: &Strategy, phase: &str) -> BTreeMap<String, String> {
    let Strategy::Flow(f) = strategy else {
        panic!("expected a flow strategy")
    };
    let steps = match phase {
        "deps" => &f.deps,
        "build" => &f.build,
        _ => &f.src,
    };
    // A workflow is the repository's text, so every parameter lowered from one is a literal and
    // none a template the repository could steer.
    match &steps[0].body {
        StepBody::Uses { with, .. } => {
            assert!(
                with.is_empty(),
                "a lowered parameter is a template: {with:?}"
            );
            steps[0].literal.clone()
        }
        other => panic!("expected a tool step, got {other:?}"),
    }
}

fn tool(strategy: &Strategy, phase: &str) -> String {
    let Strategy::Flow(f) = strategy else {
        panic!("expected a flow strategy")
    };
    let steps = match phase {
        "deps" => &f.deps,
        "build" => &f.build,
        _ => &f.src,
    };
    match &steps[0].body {
        StepBody::Uses { tool, .. } => tool.clone(),
        other => panic!("expected a tool step, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Job selection: the correction the fixtures forced
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_job_that_publishes_is_not_the_job_that_builds() {
    // `docs/06-ci-awareness.md` §3.1 says "the job that publishes is the one that describes the
    // build". Against `certifi/python-certifi` that is false, and it is false the same way for
    // `attrs`, `flask`, `platformdirs` and `packaging`: trusted publishing moved the upload into a
    // job holding `id-token: write` and nothing else. Its entire body is `download-artifact` plus
    // `gh-action-pypi-publish`. A rung that followed the publish job alone would lower a recipe
    // that builds nothing and collects an empty `dist/`.
    let r = read_pypi("certifi", &[Wf::Fixture("certifi-release")], &[]).await;
    let best = r.ranked.first().expect("a recipe");
    assert_eq!(best.publish_job, "pypi");
    assert_eq!(best.build_job, "build");
    assert_eq!(
        best.link,
        BuildPublishLink::Artifact {
            name: "certifi-dists".into()
        },
        "the edge between them is the artifact name, and it has to be followed rather than assumed"
    );

    let c = r.candidate.as_ref().expect("a candidate: {r:?}");
    assert_eq!(c.derivation, Derivation::CiDerived);
    assert_eq!(tool(&c.strategy, "build"), "pypi/build/wheel");
}

#[tokio::test]
async fn an_artifact_id_expression_names_the_producing_job_outright() {
    // `pallets/flask` joins its jobs with `artifact-ids: ${{ needs.build.outputs.artifact-id }}`.
    // No artifact *name* appears anywhere in that file, so a name-matching edge finds nothing and
    // the rung would decline on a workflow it can read perfectly well. The expression itself is the
    // edge, and it is exact where a name match is a guess.
    let r = read_pypi(
        "flask",
        &[Wf::Fixture("flask-publish")],
        &[(
            "pyproject.toml",
            "[project]\nrequires-python = \">=3.10\"\n",
        )],
    )
    .await;
    let best = r.ranked.first().expect("a recipe");
    assert_eq!(best.publish_job, "publish-pypi");
    assert_eq!(
        best.link,
        BuildPublishLink::ArtifactId {
            producer: "build".into()
        }
    );

    // `create-release` also consumes the build's output and also looks like a release job. It is
    // not a PyPI publish, so it never qualifies: a GitHub release proves nothing about what reached
    // the index.
    assert!(
        r.ranked.iter().all(|x| x.publish_job != "create-release"),
        "a GitHub release is not a PyPI publish"
    );

    let c = r.candidate.as_ref().expect("a candidate");
    assert!(
        c.assumptions.iter().any(|a| a.contains("uv build")),
        "the frontend swap is stated rather than hidden: {:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn a_workflow_level_env_entry_resolves_the_artifact_name() {
    // `tox-dev/platformdirs` writes the artifact name once as a workflow-level `env` entry and
    // refers to it as `${{ env.dists-artifact-name }}` from both jobs. Without expression
    // resolution across scopes the edge is two different literal strings and the rung declines.
    let r = read_pypi("platformdirs", &[Wf::Fixture("platformdirs-release")], &[]).await;
    let best = r.ranked.first().expect("a recipe");
    assert_eq!(best.build_job, "build");
    assert_eq!(
        best.link,
        BuildPublishLink::Artifact {
            name: "python-package-distributions".into()
        }
    );

    let c = r.candidate.as_ref().expect("a candidate");
    // `runs-on: ubuntu-24.04` names a release outright, so the approximation is Strong rather than
    // the Weak a `-latest` label earns.
    let approx = r.base_image.as_ref().expect("an approximation");
    assert_eq!(approx.image, "docker.io/library/ubuntu:24.04");
    assert_eq!(approx.confidence, Confidence::Strong);
    assert!(
        approx.why.contains("approximation"),
        "and it says so: {}",
        approx.why
    );

    // `uv build --python 3.14 … --out-dir dist` — the interpreter and the output directory both
    // come off the command line rather than off a setup action.
    assert_eq!(
        params(&c.strategy, "deps")
            .get("python_version")
            .map(String::as_str),
        Some("3.14")
    );
    let Strategy::Flow(f) = &c.strategy else {
        panic!()
    };
    assert_eq!(f.output_dir.as_deref(), Some("dist"));
}

// ---------------------------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_test_index_upload_is_not_this_release() {
    // `python-attrs/attrs` has two publish jobs whose steps are otherwise identical; one carries
    // `repository-url: https://test.pypi.org/legacy/`. Selecting it would describe an in-dev build
    // of a version that never reached pypi.org.
    let r = read_pypi("attrs", &[Wf::Fixture("attrs-pypi-package")], &[]).await;
    assert!(
        r.ranked.iter().all(|x| x.publish_job == "release-pypi"),
        "the TestPyPI job was selected: {:?}",
        r.ranked
            .iter()
            .map(|x| x.publish_job.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        r.notes.iter().any(|n| n.contains("test index")),
        "and the rejection is said out loud: {:?}",
        r.notes
    );
}

#[tokio::test]
async fn a_build_that_is_one_unallowlisted_action_is_flagged_rather_than_executed() {
    // Also `attrs`. Its build job is `actions/checkout` followed by
    // `hynek/build-and-inspect-python-package`, which *is* the build. ADR-0009 says we flag an
    // unknown action rather than execute it to find out what it does, so this is the honest answer
    // to a workflow we parsed completely.
    let r = read_pypi("attrs-build", &[Wf::Fixture("attrs-pypi-package")], &[]).await;
    assert!(r.candidate.is_none());
    match r.declined.as_ref().expect("a stated reason") {
        Decline::BuildIsOneUnmodelledStep { action } => {
            assert_eq!(action, "hynek/build-and-inspect-python-package");
        }
        other => panic!("expected the unmodelled-action decline, got {other:?}"),
    }
    assert!(
        r.declined
            .as_ref()
            .unwrap()
            .to_string()
            .contains("rather than execute it"),
        "the message says why: {}",
        r.declined.as_ref().unwrap()
    );
}

#[tokio::test]
async fn a_build_command_with_no_tool_declines_and_names_the_command() {
    // `pypa/packaging` builds with `nox --no-install -R -s release_build`. Nothing in the tool
    // registry lowers that, and the useful output is the command itself: the *last* unrecognised
    // fragment, not the first, because a release job installs its tooling before it builds and the
    // first unknown would be `pipx install nox[pbs]`.
    let r = read_pypi("packaging", &[Wf::Fixture("packaging-publish")], &[]).await;
    assert!(r.candidate.is_none());
    match r.declined.as_ref().expect("a stated reason") {
        Decline::NoToolForBuildCommand { command } => {
            assert!(
                command.contains("nox --no-install -R -s release_build"),
                "named the wrong fragment: {command}"
            );
        }
        other => panic!("expected NoToolForBuildCommand, got {other:?}"),
    }
}

#[tokio::test]
async fn a_test_only_workflow_qualifies_no_job() {
    // `lukeed/escalade` is published from a laptop; its only workflow is a seven-cell Node test
    // matrix on `on: [push, pull_request]`. A fallback to "the job that looks most like a build"
    // would pin Node 20 from that matrix and attach it to a release it had nothing to do with,
    // which is exactly why there is no fallback.
    let r = read_npm("escalade", &[Wf::Fixture("escalade-ci")], true).await;
    assert!(r.candidate.is_none());
    assert!(
        matches!(r.declined, Some(Decline::NoQualifyingJob { jobs_seen: 1 })),
        "{:?}",
        r.declined
    );
}

#[tokio::test]
async fn a_version_computed_at_publish_time_cannot_be_reproduced() {
    // `vercel/ms` derives `${BASE}-nightly.$(date +%Y%m%d%H%M)` and publishes it, so the version
    // that reached the registry exists nowhere in the repository and no checkout produces it. This
    // is reported ahead of the pnpm decline because it is the stronger statement: even with a pnpm
    // tool, there is nothing to rebuild.
    let r = read_npm("ms", &[Wf::Fixture("ms-release")], true).await;
    assert!(r.candidate.is_none());
    assert!(
        matches!(
            r.declined,
            Some(Decline::VersionComputedAtPublishTime { .. })
        ),
        "{:?}",
        r.declined
    );
    assert!(
        r.notes.iter().any(|n| n.contains("pnpm")),
        "and the package manager is still recorded: {:?}",
        r.notes
    );
}

const PNPM_RELEASE: &str = r#"
name: Release
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
      - run: pnpm publish --access public
"#;

#[tokio::test]
async fn a_package_manager_with_no_tool_is_a_decline_with_a_reason() {
    // `trigon-strategy` ships fourteen builtin tools and none of them is pnpm. `npm/build/pack`
    // would be a different recipe rather than an approximation of this one, so the rung says so
    // instead of substituting it.
    let r = read_npm("pnpm", &[Wf::Inline("release.yml", PNPM_RELEASE)], true).await;
    assert!(r.candidate.is_none());
    match r.declined.as_ref().expect("a stated reason") {
        Decline::PackageManagerUnsupported { manager } => assert_eq!(manager, "pnpm"),
        other => panic!("expected PackageManagerUnsupported, got {other:?}"),
    }
}

const SECRET_IN_BUILD: &str = r#"
name: Release
on:
  push:
    tags: ["*"]
jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install build
      - name: Build with source maps
        run: SENTRY_AUTH_TOKEN=${{ secrets.SENTRY_AUTH_TOKEN }} python -m build
      - run: python -m twine upload dist/*
        env:
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
"#;

#[tokio::test]
async fn a_secret_in_the_build_is_a_decline_and_a_token_in_the_publish_step_is_not() {
    // The distinction is the whole rule. Every release workflow hands a token to its publish step
    // and that tells us nothing; a secret reaching a *build* command means the build consumes
    // something we do not have, and we cannot know whether it changes the output.
    let r = read_pypi("secret", &[Wf::Inline("release.yml", SECRET_IN_BUILD)], &[]).await;
    match r.declined.as_ref().expect("a stated reason") {
        Decline::SecretInBuild { names } => {
            assert_eq!(names, &vec!["SENTRY_AUTH_TOKEN".to_string()]);
            assert!(
                !names.iter().any(|n| n == "PYPI_TOKEN"),
                "the publish token is expected and must not count: {names:?}"
            );
        }
        other => panic!("expected SecretInBuild, got {other:?}"),
    }

    // `benjaminp/six` hands `secrets.PYPI_UPLOAD_TOKEN` to its publish step inside the same job
    // that builds, and still produces a candidate.
    let ok = read_pypi("six-token", &[Wf::Fixture("six-publish")], &[]).await;
    assert!(
        ok.candidate.is_some(),
        "a token in the publish step is not a reason to decline: {:?}",
        ok.declined
    );
}

/// A release that writes its version into the package with `echo` before it builds.
const VERSION_BY_ECHO: &str = r#"
name: Release
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install build
      - run: echo "__version__ = '${GITHUB_REF_NAME#v}'" > src/widget/_version.py
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn a_version_written_into_the_package_by_echo_is_a_rewrite_and_not_an_echo() {
    // Read as an `echo`, the step was incidental and the recipe built the tree as checked out: a
    // package without the version the release wrote into it.
    let r = read_pypi(
        "echo-version",
        &[Wf::Inline("release.yml", VERSION_BY_ECHO)],
        &[],
    )
    .await;
    assert!(r.candidate.is_none());
    assert_eq!(
        r.declined,
        Some(Decline::BuildRewritesTheTree {
            command: "echo \"__version__ = '${GITHUB_REF_NAME#v}'\" > src/widget/_version.py"
                .into()
        })
    );

    // The same `echo` into the runner's output file writes nothing the build reads.
    let to_output = VERSION_BY_ECHO.replace("> src/widget/_version.py", ">> \"$GITHUB_OUTPUT\"");
    let to_output: &'static str = Box::leak(to_output.into_boxed_str());
    let r = read_pypi("echo-output", &[Wf::Inline("release.yml", to_output)], &[]).await;
    assert!(r.candidate.is_some(), "{:?}", r.declined);
}

// ---------------------------------------------------------------------------------------------
// The single-job shape, and the interpreter
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_older_single_job_shape_still_lowers() {
    // `benjaminp/six` builds and publishes from one job, which is what `docs/06` §3.1 assumed
    // everywhere. `SameJob` is the degenerate edge rather than a separate path, so the older shape
    // needs no special case.
    let r = read_pypi("six", &[Wf::Fixture("six-publish")], &[]).await;
    let best = r.ranked.first().expect("a recipe");
    assert_eq!(best.link, BuildPublishLink::SameJob);
    assert_eq!(best.publish_job, best.build_job);

    let c = r.candidate.as_ref().expect("a candidate");
    assert_eq!(
        params(&c.strategy, "deps")
            .get("python_version")
            .map(String::as_str),
        Some("3.13"),
        "quoted, two components, and that is a complete Python version"
    );
    assert_eq!(tool(&c.strategy, "deps"), "pypi/deps/basic");
    // Never `Certain`: a workflow is intent, and we did not observe the run.
    assert_ne!(c.confidence, Confidence::Certain);
}

#[tokio::test]
async fn a_six_upload_targeting_the_test_index_is_read_from_the_declared_env_only() {
    // `six`'s publish step exports `TWINE_REPOSITORY=testpypi` *inside* a shell conditional that
    // also exports `pypi`. Scanning the script text for "testpypi" would disqualify a job that
    // publishes to the real index on a tag push, so only a declared `env:` mapping — which is
    // unconditional and can be read as a fact — is allowed to disqualify one.
    let r = read_pypi("six-env", &[Wf::Fixture("six-publish")], &[]).await;
    assert!(r.candidate.is_some(), "{:?}", r.declined);
    assert!(
        !r.notes.iter().any(|n| n.contains("test index")),
        "the conditional export must not read as a TestPyPI job: {:?}",
        r.notes
    );
}

const UNQUOTED_VERSION: &str = r#"
name: Release
on:
  push:
    tags: ["*"]
jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: 3.10
      - run: python -m build
      - run: twine upload dist/*
"#;

#[tokio::test]
async fn an_unquoted_version_is_a_yaml_float_and_makes_no_claim() {
    // The bug this rule exists for: `python-version: 3.10` unquoted parses as the float `3.1` in
    // every YAML 1.2 parser, `serde_yaml_ng` included. A version read through a parsed number would
    // claim Python 3.1 — a release from 2006 — with CI authority behind it.
    let r = read_pypi("float", &[Wf::Inline("release.yml", UNQUOTED_VERSION)], &[]).await;
    assert!(
        !r.evidence.iter().any(|e| matches!(
            &e.claim,
            Claim::ToolchainExact { tool, version } if tool == "python" && version.starts_with("3.1")
        )),
        "a float was believed: {:?}",
        r.evidence
    );
    assert!(
        r.notes.iter().any(|n| n.contains("float")),
        "and the reader is told why there is no Python claim: {:?}",
        r.notes
    );
    // The rest of the workflow still lowers; one unusable field is not a reason to lose the build.
    let c = r.candidate.as_ref().expect("a candidate");
    assert!(
        !params(&c.strategy, "deps").contains_key("python_version"),
        "and no interpreter is pinned from it"
    );
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("pins no interpreter")),
        "{:?}",
        c.assumptions
    );
}

const NODE_SERIES: &str = r#"
name: Release
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - run: npm ci
      - run: npm run build
      - run: npm publish --provenance
"#;

#[tokio::test]
async fn a_partial_version_is_a_range_so_it_narrows_the_registry_rather_than_fighting_it() {
    // The rule that keeps this rung out of a fight it should lose, and the easiest one to get
    // backwards. npm records `_nodeVersion: 24.1.0` at `Certain` — the version the publishing
    // client reported. A CI `ToolchainExact { node, 24 }` would make `resolve_toolchain` return
    // `Contradiction`, whose documented meaning is "escalate to a model", and a paid call would
    // adjudicate a disagreement that does not exist. As a range it intersects to the registry's own
    // answer, for free.
    let r = read_npm("series", &[Wf::Inline("release.yml", NODE_SERIES)], true).await;
    let range = r
        .evidence
        .iter()
        .find(|e| matches!(&e.claim, Claim::ToolchainRange { tool, .. } if tool == "node"))
        .expect("a node range");
    assert_eq!(
        range.claim,
        Claim::ToolchainRange {
            tool: "node".into(),
            lo: Some("24".into()),
            hi: Some("25".into())
        }
    );
    assert_eq!(range.confidence, Confidence::Strong, "never Certain");

    let registry = Evidence::new(
        Claim::ToolchainExact {
            tool: "node".into(),
            version: "24.1.0".into(),
        },
        Confidence::Certain,
        "npm:_nodeVersion",
    );
    assert_eq!(
        resolve_toolchain("node", &[registry, range.clone()]),
        ToolchainResolution::Pinned {
            version: "24.1.0".into()
        },
        "the two have to compose rather than contradict"
    );
}

/// **What the heuristic checks, this rung checks too.** It displaces the heuristic's candidate, so
/// a value the heuristic declines or replaces and this rung passes on is the check undone for every
/// package whose release workflow runs a script. Each of these reached the build unchecked: the
/// script name inside `TRIGON_NPM_CMD='… npm run <name> …'`, where its own `'` ends the quoting
/// and `$(id)` runs; a publishing client's user-agent as `npm install -g "npm@<it>"`, where npm's
/// spec parser reads it, and the build failure is charged to the package; a Node built from master
/// as a download that 404s. Each is declined by name, and the evidence still gets out.
#[tokio::test]
async fn the_values_the_heuristic_checks_are_checked_before_they_are_lowered() {
    let crafted: &'static str = NODE_SERIES
        .replace("npm run build", r#"npm run "x'$(id)'""#)
        .leak();
    for (name, workflow, recorded, what, value) in [
        (
            "npm-script",
            crafted,
            ("24.1.0", "11.3.0"),
            "the script the release runs",
            "x'$(id)'",
        ),
        (
            "npm-agent",
            NODE_SERIES,
            ("22.14.0", "lerna/4.0.0/node@v22.14.0+arm64 (darwin)"),
            "the registry's `_npmVersion`",
            "lerna/4.0.0/node@v22.14.0+arm64 (darwin)",
        ),
        (
            "npm-agent-spaces",
            NODE_SERIES,
            ("18.17.1", "npm/9.6.7 node/v18.17.1 linux x64"),
            "the registry's `_npmVersion`",
            "npm/9.6.7 node/v18.17.1 linux x64",
        ),
        (
            "npm-alias",
            NODE_SERIES,
            ("18.17.1", "npm:evil@1.0.0"),
            "the registry's `_npmVersion`",
            "npm:evil@1.0.0",
        ),
        (
            "npm-master",
            NODE_SERIES,
            ("8.0.0-pre", "4.4.2"),
            "the registry's `_nodeVersion`",
            "8.0.0-pre",
        ),
    ] {
        let r =
            read_npm_recorded(name, &[Wf::Inline("release.yml", workflow)], Some(recorded)).await;
        assert!(r.candidate.is_none(), "{name}: {:?}", r.candidate);
        let Some(Decline::UnfitValue {
            what: got_what,
            value: got_value,
            ..
        }) = &r.declined
        else {
            panic!("{name}: {:?}", r.declined)
        };
        assert_eq!((*got_what, got_value.as_str()), (what, value), "{name}");
        assert!(
            r.evidence
                .iter()
                .any(|e| matches!(&e.claim, Claim::ToolchainRange { tool, .. } if tool == "node")),
            "{name}: the evidence still gets out: {:?}",
            r.evidence
        );
    }

    // A Node the heuristic can replace is left to it, and the reason says so.
    let r = read_npm_recorded(
        "npm-master-says",
        &[Wf::Inline("release.yml", NODE_SERIES)],
        Some(("8.0.0-pre", "4.4.2")),
    )
    .await;
    let why = r
        .declined
        .as_ref()
        .map(Decline::to_string)
        .unwrap_or_default();
    assert!(why.contains("the heuristic"), "{why}");
}

#[tokio::test]
async fn an_npm_release_produces_a_candidate_only_where_it_knows_more_than_the_registry() {
    // The displacement rule. `CiDerived` sits above `Heuristic` and `infer()` takes the first
    // non-empty rung, so a candidate here *replaces* one the heuristic would have produced — and
    // for npm the heuristic's inputs are strictly better, because `_nodeVersion` and `_npmVersion`
    // are what the publishing client reported rather than what a workflow intended. So the rung
    // speaks up only where it knows something the registry does not: the build script `npm pack`
    // will not run by itself.
    let with_build = read_npm("npm-build", &[Wf::Inline("release.yml", NODE_SERIES)], true).await;
    let c = with_build.candidate.as_ref().expect("a candidate");
    assert_eq!(tool(&c.strategy, "build"), "npm/build/custom");
    assert_eq!(
        params(&c.strategy, "build")
            .get("command")
            .map(String::as_str),
        Some("build")
    );
    assert_eq!(
        params(&c.strategy, "deps")
            .get("node_version")
            .map(String::as_str),
        Some("24.1.0"),
        "the registry's exact version wins over the workflow's series"
    );

    // The same workflow with no build script has nothing the heuristic lacks.
    let plain = NODE_SERIES.replace("      - run: npm run build\n", "");
    let leaked: &'static str = Box::leak(plain.into_boxed_str());
    let without = read_npm("npm-plain", &[Wf::Inline("release.yml", leaked)], true).await;
    assert!(without.candidate.is_none());
    assert!(
        matches!(
            without.declined,
            Some(Decline::NothingTheHeuristicLacks { .. })
        ),
        "{:?}",
        without.declined
    );

    // And with no recorded publishing toolchain there is no exact Node to build with either: a
    // workflow's `node-version: 24` names a series, and `npm/install-node` fetches one tarball.
    let no_registry = read_npm("npm-bare", &[Wf::Inline("release.yml", NODE_SERIES)], false).await;
    assert!(no_registry.candidate.is_none());
    assert!(
        no_registry
            .evidence
            .iter()
            .any(|e| matches!(&e.claim, Claim::ToolchainRange { tool, .. } if tool == "node")),
        "but the evidence still gets out: {:?}",
        no_registry.evidence
    );
}

// ---------------------------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------------------------

const MACOS_RELEASE: &str = r#"
name: Release
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m build
      - run: twine upload dist/*
"#;

#[tokio::test]
async fn a_macos_runner_is_out_of_scope_rather_than_a_failure() {
    // `docs/06` §3.3: attempting macOS would produce a stream of divergences that say nothing about
    // the packages involved. The `Claim::PlatformIs` is how that reaches a verdict — through the
    // intersection, with no new plumbing — because a `StrategyInferrer` cannot stop the ladder.
    let r = read_pypi("macos", &[Wf::Inline("release.yml", MACOS_RELEASE)], &[]).await;
    assert!(r.candidate.is_none());
    assert!(
        matches!(r.out_of_scope, Some(OutOfScope::MacOs(_))),
        "{:?}",
        r.out_of_scope
    );
    assert!(
        matches!(r.declined, Some(Decline::RunnerOutOfScope(_))),
        "{:?}",
        r.declined
    );
    assert!(
        r.evidence.iter().any(|e| e.claim
            == Claim::PlatformIs {
                platform: "macos".into()
            }),
        "the platform still reaches the intersection: {:?}",
        r.evidence
    );
    assert!(r.base_image.is_none(), "and nothing is approximated");
}

#[tokio::test]
async fn ubuntu_latest_inside_a_rollout_window_resolves_to_nothing() {
    // GitHub moves `-latest` to a percentage of runners over weeks. During the window the label
    // genuinely was both releases, so a publish time inside one yields no mapping at all rather
    // than a coin flip: a rebuild that picks one is describing a machine that may never have run.
    let (root, url, commit) = repo("rollout", &[Wf::Fixture("six-publish")], &[]);

    let mut settled = target(Ecosystem::PyPI, "six", "1.17.0", &url, &commit);
    settled.intrinsics.publish_time = Some("2024-03-01T00:00:00Z".into());
    let r = rung(&root).read(&settled).await.unwrap();
    let approx = r.base_image.as_ref().expect("a settled label resolves");
    assert_eq!(approx.image, "docker.io/library/ubuntu:22.04");
    assert_eq!(
        approx.confidence,
        Confidence::Weak,
        "a label-history lookup is a heuristic and is recorded as one"
    );

    let mut mid = target(Ecosystem::PyPI, "six", "1.17.0", &url, &commit);
    mid.intrinsics.publish_time = Some("2024-12-20T00:00:00Z".into());
    let during = rung(&root).read(&mid).await.unwrap();
    assert!(
        during.base_image.is_none(),
        "a publish inside the 24.04 rollout resolved anyway: {:?}",
        during.base_image
    );
    assert!(
        during.candidate.is_some(),
        "and the candidate survives — the mapping is an assumption, not a precondition"
    );
}

// ---------------------------------------------------------------------------------------------
// The seam: evidence outliving the decline
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_evidence_survives_a_decline_and_seeds_the_rung_below() {
    // `docs/06` §4's closing claim, and the reason this rung has a second entry point at all: a
    // workflow we cannot lower faithfully still tells us the Python version, and that alone can
    // turn a failing heuristic strategy into a passing one. `StrategyInferrer::infer` returns
    // `Vec<Candidate>`, which has nowhere to put that — so a rung that declines through the trait
    // alone throws away everything it learned.
    let (root, url, commit) = repo("seed", &[Wf::Fixture("attrs-pypi-package")], &[]);
    let mut t = target(Ecosystem::PyPI, "attrs", "25.4.0", &url, &commit);

    let rung = rung(&root);
    let reading = rung.read(&t).await.unwrap();
    assert!(reading.candidate.is_none(), "attrs declines");
    assert!(
        reading.evidence.iter().any(|e| e.claim
            == Claim::PlatformIs {
                platform: "linux/amd64".into()
            }),
        "and still learned the platform: {:?}",
        reading.evidence
    );

    let before = t.intrinsics.evidence.len();
    reading.seed(&mut t);
    assert!(t.intrinsics.evidence.len() > before);
    // Idempotent, so seeding before each rung is safe.
    reading.seed(&mut t);
    let after = t.intrinsics.evidence.len();
    reading.seed(&mut t);
    assert_eq!(t.intrinsics.evidence.len(), after);

    // The trait sees only the silence, which is what the ladder wants.
    assert!(rung.infer(&t).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_repository_with_no_workflows_declines_rather_than_erroring() {
    // Most rungs are silent for most targets, and that is how a ladder is supposed to work. A rung
    // that errored here would be logged as a failure on every package published from a laptop.
    let (root, url, commit) = repo("bare", &[], &[("README.md", "nothing here\n")]);
    let t = target(Ecosystem::PyPI, "bare", "1.0", &url, &commit);
    let r = rung(&root).read(&t).await.unwrap();
    assert!(
        matches!(r.declined, Some(Decline::NoWorkflows)),
        "{:?}",
        r.declined
    );
    assert!(r.summary().contains("no candidate"));
}

#[tokio::test]
async fn a_target_with_no_commit_will_not_read_head() {
    // Reading `HEAD`'s workflow to explain a 2021 publish reads a file that did not exist then. The
    // rung would rather say nothing.
    let (root, url, commit) = repo("nocommit", &[Wf::Fixture("six-publish")], &[]);
    let mut t = target(Ecosystem::PyPI, "six", "1.17.0", &url, &commit);
    t.source = None;
    let r = rung(&root).read(&t).await.unwrap();
    assert!(
        matches!(r.declined, Some(Decline::NoPinnedCommit)),
        "{:?}",
        r.declined
    );
}

const OTHER_RELEASE: &str = r#"
name: Other
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.9"
      - run: python -m build
      - run: twine upload dist/*
"#;

#[tokio::test]
async fn two_equally_ranked_recipes_that_disagree_are_a_decline_rather_than_a_coin_flip() {
    // Two release workflows, the same trigger, the same publish marker, different interpreters.
    // The ranking did not decide anything, and taking the one that sorted first would attach a
    // verdict to `git ls-files` ordering.
    let r = read_pypi(
        "tie",
        &[
            Wf::Inline("a-release.yml", OTHER_RELEASE),
            Wf::Inline("b-release.yml", OTHER_RELEASE.replace("3.9", "3.12").leak()),
        ],
        &[],
    )
    .await;
    match r.declined.as_ref().expect("a stated reason") {
        Decline::RecipesTie { top, disagree_on } => {
            assert_eq!(top.len(), 2);
            assert_eq!(*disagree_on, "the toolchain");
        }
        other => panic!("expected RecipesTie, got {other:?}"),
    }
    assert!(r.candidate.is_none());
}

#[tokio::test]
async fn only_the_workflows_directory_itself_is_read() {
    // Actions reads exactly one directory. A reusable-workflow fragment one level deeper is not a
    // workflow however much it looks like one, and ranking it as a release job in its own right
    // would let a file nobody triggers describe a build.
    let r = read_pypi(
        "nested",
        &[Wf::Inline("noop.yml", "name: noop\non: [push]\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo hi\n")],
        &[(".github/workflows/shared/release.yml", OTHER_RELEASE)],
    )
    .await;
    assert!(
        matches!(r.declined, Some(Decline::NoQualifyingJob { jobs_seen: 1 })),
        "the nested file was read: {:?}",
        r.declined
    );
}

// ---------------------------------------------------------------------------------------------
// The candidate has to be executable, not merely well-typed
// ---------------------------------------------------------------------------------------------

/// A release that builds a directory whose name the repository chose to look like a template.
const TEMPLATE_IN_A_DIRECTORY: &str = r#"
name: Release
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install build
      - run: python -m build pkg{{7*7}}{%if%}{#
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn what_a_workflow_says_reaches_the_build_as_written_and_is_never_evaluated() {
    // The directory is the repository's text, lowered into a tool parameter. As a template it
    // built `pkg49`, or failed the render on `{% if %}`, so the repository under test chose what
    // the recipe built; as a literal it is the directory the workflow named.
    let r = read_pypi(
        "template-dir",
        &[Wf::Inline("release.yml", TEMPLATE_IN_A_DIRECTORY)],
        &[],
    )
    .await;
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    assert_eq!(params(&c.strategy, "build")["dir"], "pkg{{7*7}}{%if%}{#");

    let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
    let rendered = trigon_strategy::render(&c.strategy, &Default::default(), &tools)
        .unwrap_or_else(|e| panic!("the lowered strategy does not render: {e}"));
    assert!(
        rendered
            .build
            .ends_with("-m build --wheel pkg{{7*7}}{%if%}{#"),
        "{}",
        rendered.build
    );
}

#[tokio::test]
async fn a_ci_derived_candidate_renders_against_the_builtin_tools() {
    // The check a type cannot make. A `Strategy` naming a tool nobody registered, or passing a
    // parameter a tool does not declare, is a perfectly valid value of the type and a build that
    // does less than it was asked to — which `trigon-strategy`'s own module docs call out as a
    // false pass rather than a failure. So the rung's output is rendered here, the same way the
    // engine renders it, and the script is read back.
    let r = read_pypi("render", &[Wf::Fixture("six-publish")], &[]).await;
    let c = r.candidate.as_ref().expect("a candidate");

    let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
    let cx = trigon_strategy::Context {
        location: trigon_strategy::LocationCtx {
            repo: "https://github.com/benjaminp/six".into(),
            git_ref: "0".repeat(40),
            subdir: String::new(),
        },
        target: trigon_strategy::TargetCtx {
            ecosystem: "pypi".into(),
            name: "six".into(),
            version: "1.17.0".into(),
            artifact: "six-1.17.0-py2.py3-none-any.whl".into(),
        },
        ..Default::default()
    };
    let rendered = trigon_strategy::render(&c.strategy, &cx, &tools)
        .unwrap_or_else(|e| panic!("the CI rung emitted a strategy that will not render: {e}"));

    let script = format!("{:?}", rendered);
    assert!(
        !script.contains("${{"),
        "a rendered strategy must never carry a literal Actions expression: {script}"
    );
    assert!(
        script.contains("--python 3.13"),
        "the interpreter the workflow pinned has to reach the build: {script}"
    );
    assert!(
        script.contains("python3 -m build"),
        "and so does the build itself: {script}"
    );
}

#[tokio::test]
async fn the_reading_is_parsed_once_per_target() {
    // `read()` and `infer()` are two calls about one target, and the documented way to use this
    // rung makes both: seed the rungs below, then run the ladder. Parsing forty workflow files
    // twice per target is a cost that only shows up at sweep scale.
    let (root, url, commit) = repo("memo", &[Wf::Fixture("six-publish")], &[]);
    let t = target(Ecosystem::PyPI, "six", "1.17.0", &url, &commit);
    let rung = rung(&root);

    let first = rung.read(&t).await.unwrap();
    let second = rung.read(&t).await.unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "the second read reparsed the repository"
    );
    assert_eq!(rung.infer(&t).await.unwrap().len(), 1);
}

// ---------------------------------------------------------------------------------------------
// B11: the eight defects two verification passes named, each with the shape that demonstrates it
// ---------------------------------------------------------------------------------------------

/// The check-then-upload shape, which is what the packaging guide tells people to write.
const CHECK_THEN_UPLOAD: &str = r#"
name: release
on:
  push:
    tags: ["v*"]
jobs:
  release:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m build
      - run: twine check dist/*
      - run: twine upload dist/*
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
"#;

#[tokio::test]
async fn twine_check_is_not_the_publish_step() {
    // `twine` was classified as a publish whatever its subcommand, so on the shape above the
    // *check* became "the publish step". Two things follow, and the second is the serious one.
    //
    // The recipe's steps are everything in the job that is not the publish step, so `twine upload`
    // — the real one — lands among them. A rebuild lowered from that recipe uploads to PyPI.
    // The first is that `TWINE_PASSWORD` is then a secret read by a *build* step, which is a
    // decline, so the rung refuses a workflow it can read perfectly well.
    let r = read_pypi(
        "checked",
        &[Wf::Inline("release.yml", CHECK_THEN_UPLOAD)],
        &[("pyproject.toml", "[project]\nname = \"checked\"\n")],
    )
    .await;
    let best = r.ranked.first().expect("a recipe: {r:?}");
    assert!(
        best.secrets_in_build.is_empty(),
        "the upload step's token was attributed to the build: {:?}",
        best.secrets_in_build
    );

    let c = r.candidate.as_ref().unwrap_or_else(|| {
        panic!("declined a readable workflow: {:?}", r.declined);
    });
    let Strategy::Flow(f) = &c.strategy else {
        panic!("expected a flow strategy")
    };
    let rendered = format!("{:?}", f.build);
    assert!(
        !rendered.contains("twine upload"),
        "the rebuild would publish to PyPI: {rendered}"
    );
}

/// A build preceded by an in-place rewrite of the tree it is about to build.
const SED_THEN_BUILD: &str = r#"
name: release
on:
  push:
    tags: ["v*"]
jobs:
  release:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: sed -i "s/0.0.0/${GITHUB_REF_NAME#v}/" src/checked/__init__.py
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn an_in_place_rewrite_of_the_tree_is_not_incidental() {
    // `sed` sat in `cmd::INCIDENTAL` — the list of commands that provably do not affect build
    // output — and `sed -i` is the one invocation for which that is false. The recipe came out
    // describing a build of the tree as checked out, which is not the tree that was built, and
    // nothing said so.
    //
    // The rung has no way to *model* the rewrite, so this is a decline rather than a lowering.
    // What it must not be is silence.
    let r = read_pypi(
        "sedded",
        &[Wf::Inline("release.yml", SED_THEN_BUILD)],
        &[("pyproject.toml", "[project]\nname = \"sedded\"\n")],
    )
    .await;
    let d = r.declined.as_ref().unwrap_or_else(|| {
        panic!("lowered a recipe that omits the rewrite: {:?}", r.candidate);
    });
    let said = d.to_string();
    assert!(
        said.contains("sed -i"),
        "the decline has to name the command a reader would go looking for: {said}"
    );
}

#[tokio::test]
async fn a_decline_does_not_assert_what_is_not_true_of_its_own_run() {
    // Two messages said things the run contradicted, and a decline that misdescribes itself sends
    // whoever reads it to the wrong part of the workflow.
    //
    // Here a build *was* recognised — `python -m build` is right there — so
    // "`…` is the build, and no tool in the registry lowers it" is false about this run. The
    // recipe is incomplete, which is a different statement and the true one.
    let r = read_pypi(
        "sedded2",
        &[Wf::Inline("release.yml", SED_THEN_BUILD)],
        &[("pyproject.toml", "[project]\nname = \"sedded2\"\n")],
    )
    .await;
    let said = r.declined.as_ref().expect("a decline").to_string();
    assert!(
        !said.contains("is the build, and no tool"),
        "a build was recognised, and the decline says there was none: {said}"
    );
}

/// A matrix build fanning wheels out under per-platform names, collected with a glob.
const FAN_IN_WITH_A_GLOB: &str = r#"
name: release
on:
  push:
    tags: ["v*"]
jobs:
  sdist:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - run: echo nothing to see here
      - uses: actions/upload-artifact@v4
        with:
          name: notes
          path: NOTES
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dist-ubuntu-22.04
          path: dist/
  publish:
    needs: [build, sdist]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: dist-*
          merge-multiple: true
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn a_publish_job_that_fans_in_with_a_glob_keeps_its_build_edge() {
    // `pattern:` is a minimatch glob and was compared as a literal artifact name, so a publish job
    // collecting `dist-*` matched an upload named `dist-*` and nothing else. Every matrix release —
    // which is most of the ones that publish wheels — lost the edge to the job that built them and
    // the rung declined for a reason that was not true of the file.
    let r = read_pypi(
        "fanned",
        &[Wf::Inline("release.yml", FAN_IN_WITH_A_GLOB)],
        &[("pyproject.toml", "[project]\nname = \"fanned\"\n")],
    )
    .await;
    let best = r.ranked.first().unwrap_or_else(|| {
        panic!("no recipe, declined: {:?}", r.declined);
    });
    assert_eq!(best.publish_job, "publish");
    assert_eq!(
        best.build_job, "build",
        "the glob has to reach the job that uploaded a name it matches, and not the other job \
         this one also depends on"
    );
    assert_eq!(
        best.link,
        BuildPublishLink::Artifact {
            name: "dist-ubuntu-22.04".into()
        },
        "the edge records the artifact that was uploaded, not the glob that asked for it"
    );
}

/// A build that starts by downloading bytes another job produced.
const BUILD_CONSUMES_AN_ARTIFACT: &str = r#"
name: release
on:
  push:
    tags: ["v*"]
jobs:
  compile:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - run: make libthing.so
      - uses: actions/upload-artifact@v4
        with:
          name: native
          path: libthing.so
  build:
    needs: [compile]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          name: native
          path: src/consumer/
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn a_build_fed_by_another_jobs_bytes_is_not_reproducible_from_source() {
    // `actions/download-artifact` sat with `actions/cache` on the list of steps that "provably do
    // not matter", on the reasoning that the artifact actions carry the edge between jobs rather
    // than building anything. That is true of the *publish* job. In the *build* job it is the
    // opposite: the build's inputs include bytes this rebuild will never produce, and a recipe that
    // drops the step describes a build from source alone. That is the shape `docs/12-security.md`
    // §1.1 is about — a rebuild that matches because it was handed the answer.
    let r = read_pypi(
        "fed",
        &[Wf::Inline("release.yml", BUILD_CONSUMES_AN_ARTIFACT)],
        &[("pyproject.toml", "[project]\nname = \"fed\"\n")],
    )
    .await;
    let said = r
        .declined
        .as_ref()
        .unwrap_or_else(|| {
            panic!(
                "lowered a recipe that drops the download: {:?}",
                r.candidate
            )
        })
        .to_string();
    assert!(
        said.contains("native"),
        "the decline has to name the artifact the build consumed: {said}"
    );
}

#[tokio::test]
async fn failing_to_resolve_a_label_does_not_make_the_candidate_more_confident() {
    // The inversion. Resolving `ubuntu-latest` to a release produces a `Weak` approximation, and
    // `confidence()` lowers the candidate to match. Failing to resolve it produced *no*
    // approximation, nothing to lower against, and a `Strong` candidate — so the run that knew
    // less was the more confident one.
    //
    // Both of these are the same file and the same commit. The only difference is a publish time
    // inside GitHub's 24.04 rollout window, where the label genuinely was both releases.
    let (root, url, commit) = repo("inversion", &[Wf::Fixture("six-publish")], &[]);

    let mut settled = target(Ecosystem::PyPI, "six", "1.17.0", &url, &commit);
    settled.intrinsics.publish_time = Some("2024-03-01T00:00:00Z".into());
    let resolved = rung(&root).read(&settled).await.unwrap();

    let mut mid = target(Ecosystem::PyPI, "six", "1.17.0", &url, &commit);
    mid.intrinsics.publish_time = Some("2024-12-20T00:00:00Z".into());
    let unresolved = rung(&root).read(&mid).await.unwrap();

    let known = resolved.candidate.as_ref().expect("a candidate").confidence;
    let unknown = unresolved
        .candidate
        .as_ref()
        .expect("a candidate")
        .confidence;
    // `Confidence` orders Certain < Strong < Weak, so "no better than" is `>=`.
    assert!(
        unknown >= known,
        "not knowing which release the label meant produced the more confident candidate: \
         resolved={known:?} unresolved={unknown:?}"
    );
}

/// A release whose reproducibility lever is set where the rung parsed it and then forgot it.
const ENV_AT_THE_TOP: &str = r#"
name: release
on:
  push:
    tags: ["v*"]
env:
  SOURCE_DATE_EPOCH: "1700000000"
jobs:
  release:
    runs-on: ubuntu-22.04
    env:
      SETUPTOOLS_SCM_PRETEND_VERSION: "1.2.3"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn environment_the_workflow_set_and_the_recipe_drops_is_said_out_loud() {
    // `CiRecipe::env` was assembled — workflow `env` under job `env`, merged, literals only — and
    // then read by nothing. A build that ran with `SOURCE_DATE_EPOCH` set and a rebuild that runs
    // without it are two different builds, and the single most consequential variable in Python
    // packaging reproducibility disappeared between the parse and the recipe with nothing said.
    //
    // A `GITHUB_ENV` export already gets a note saying `FlowStrategy` has nowhere to carry it.
    // A declared `env:` is the same fact arriving by a different route and gets the same note.
    let r = read_pypi(
        "enved",
        &[Wf::Inline("release.yml", ENV_AT_THE_TOP)],
        &[("pyproject.toml", "[project]\nname = \"enved\"\n")],
    )
    .await;
    let said = r.notes.join("\n");
    for name in ["SOURCE_DATE_EPOCH", "SETUPTOOLS_SCM_PRETEND_VERSION"] {
        assert!(
            said.contains(name),
            "`{name}` was parsed and dropped in silence:\n{said}"
        );
    }

    // And it reaches the candidate, because a note lives in a report and an assumption is what a
    // reader of the attestation gets.
    let c = r.candidate.as_ref().unwrap_or_else(|| {
        panic!("declined: {:?}", r.declined);
    });
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("SOURCE_DATE_EPOCH")),
        "the assumption list does not mention it: {:?}",
        c.assumptions
    );
}

/// A publish job that does something to the artifact between downloading it and uploading it.
const SIGNED_BETWEEN_BUILD_AND_PUBLISH: &str = r#"
name: release
on:
  push:
    tags: ["v*"]
jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dists
          path: dist/
  publish:
    needs: [build]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dists
          path: dist/
      - uses: example/rewrap-wheels@v2
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn what_the_publish_job_does_to_the_artifact_is_not_invisible() {
    // The recipe is assembled by walking the *build* job's steps, so when the publish job is a
    // different job its own steps were never classified at all. Everything between the download
    // and the upload happened to the bytes that were published, and the rung saw none of it: a
    // step that repacks, signs, strips or otherwise rewrites `dist/` left the artifact on the
    // registry different from the one the build produced, and the recipe said the build explained
    // it.
    //
    // The published artifact is what a verdict is *about*, so this is not a confidence question.
    let r = read_pypi(
        "rewrapped",
        &[Wf::Inline("release.yml", SIGNED_BETWEEN_BUILD_AND_PUBLISH)],
        &[("pyproject.toml", "[project]\nname = \"rewrapped\"\n")],
    )
    .await;
    let said = r
        .declined
        .as_ref()
        .unwrap_or_else(|| {
            panic!(
                "lowered a recipe blind to the publish job: {:?}",
                r.candidate
            )
        })
        .to_string();
    assert!(
        said.contains("example/rewrap-wheels"),
        "the decline has to name the step that touched the artifact: {said}"
    );
}

#[tokio::test]
async fn an_ordinary_publish_job_is_not_made_suspicious_by_this() {
    // The counterpart, and the reason the rule is about steps *between* the download and the
    // publish rather than about the publish job having steps at all. `certifi` is the shape every
    // trusted-publishing release has: download, publish, nothing else.
    let r = read_pypi("certifi-still", &[Wf::Fixture("certifi-release")], &[]).await;
    assert!(
        r.candidate.is_some(),
        "an ordinary publish job now declines: {:?}",
        r.declined
    );
}

// ---------------------------------------------------------------------------------------------
// What the recipe builds, and the fields a workflow pins it with
// ---------------------------------------------------------------------------------------------

/// A single-job release that lowers: checkout, an interpreter, a build, the trusted publisher.
const PLAIN_RELEASE: &str = r#"
name: Release
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install build
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn the_ci_recipe_builds_the_kind_of_artifact_the_run_is_about() {
    // A package with only platform wheels is verified against its sdist, and the caller says so
    // through `about`. The build tool defaults to a wheel, and the heuristic learned to pass the
    // kind; the CI lowering did not, so its recipe built a wheel and the run compared a wheel
    // against an sdist — which the comparator reports as a malformed gzip.
    let (root, url, commit) = repo("kind", &[Wf::Inline("release.yml", PLAIN_RELEASE)], &[]);
    let mut t = target(Ecosystem::PyPI, "kind", "1.2.3", &url, &commit);
    t.about = Some(ArtifactId::new("kind-1.2.3.tar.gz"));
    let r = rung(&root).read(&t).await.unwrap();
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    assert_eq!(params(&c.strategy, "build")["kind"], "sdist");

    // And a wheel under test, or nothing chosen yet, builds a wheel.
    for about in [Some("kind-1.2.3-py3-none-any.whl"), None] {
        let (root, url, commit) = repo(
            &format!("kind-{}", about.is_some()),
            &[Wf::Inline("release.yml", PLAIN_RELEASE)],
            &[],
        );
        let mut t = target(Ecosystem::PyPI, "kind", "1.2.3", &url, &commit);
        t.about = about.map(ArtifactId::new);
        let r = rung(&root).read(&t).await.unwrap();
        let c = r.candidate.as_ref().expect("a candidate");
        assert_eq!(params(&c.strategy, "build")["kind"], "wheel", "{about:?}");
    }
}

#[tokio::test]
async fn a_workflow_that_built_only_the_other_kind_declines_and_still_gives_its_evidence() {
    // `python -m build --wheel` in a run about the sdist never built the artifact under test, so
    // the workflow cannot say how that was built. A recipe from it builds an sdist nobody built
    // and displaces the heuristic's candidate with it. The interpreter it pinned is still true.
    let python = Claim::ToolchainExact {
        tool: "python".into(),
        version: "3.12".into(),
    };
    for (name, command, about, built, wanted) in [
        (
            "wheel-only",
            "python -m build --wheel",
            Some("kind-1.2.3.tar.gz"),
            "wheel",
            "sdist",
        ),
        (
            "sdist-only",
            "python -m build -s",
            Some("kind-1.2.3-py3-none-any.whl"),
            "sdist",
            "wheel",
        ),
        // Nothing chosen yet: the recipe would build a wheel, so the workflow has to have.
        (
            "sdist-only-unchosen",
            "python -m build --sdist",
            None,
            "sdist",
            "wheel",
        ),
        (
            "uv-wheel-only",
            "uv build --wheel",
            Some("kind-1.2.3.tar.gz"),
            "wheel",
            "sdist",
        ),
    ] {
        let text = PLAIN_RELEASE.replace(
            "      - run: python -m build\n",
            &format!("      - run: {command}\n"),
        );
        let (root, url, commit) = repo(name, &[Wf::Inline("release.yml", text.leak())], &[]);
        let mut t = target(Ecosystem::PyPI, "kind", "1.2.3", &url, &commit);
        t.about = about.map(ArtifactId::new);
        let r = rung(&root).read(&t).await.unwrap();
        assert!(r.candidate.is_none(), "{name}");
        assert_eq!(
            r.declined,
            Some(Decline::WorkflowBuildsAnotherKind { built, wanted }),
            "{name}"
        );
        assert!(
            r.evidence.iter().any(|e| e.claim == python),
            "{name}: {:?}",
            r.evidence
        );
    }

    // A job that builds both kinds, in one command or across two, built the one the run compares.
    for (name, command) in [
        ("both-flags", "python -m build --sdist --wheel"),
        (
            "both-commands",
            "python -m build --wheel\n      - run: python -m build --sdist",
        ),
    ] {
        let text = PLAIN_RELEASE.replace(
            "      - run: python -m build\n",
            &format!("      - run: {command}\n"),
        );
        let (root, url, commit) = repo(name, &[Wf::Inline("release.yml", text.leak())], &[]);
        let mut t = target(Ecosystem::PyPI, "kind", "1.2.3", &url, &commit);
        t.about = Some(ArtifactId::new("kind-1.2.3.tar.gz"));
        let r = rung(&root).read(&t).await.unwrap();
        let c = r
            .candidate
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: {:?}", r.declined));
        assert_eq!(params(&c.strategy, "build")["kind"], "sdist", "{name}");
    }
}

const UV_RELEASE: &str = r#"
name: Release
on:
  push:
    tags: ["v*"]
jobs:
  release:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
        with:
          version: "0.4.20"
      - run: uv build --python 3.11 --sdist --wheel
        working-directory: python
      - run: uv publish
"#;

#[tokio::test]
async fn a_uv_release_pins_uv_and_takes_the_interpreter_from_the_frontend() {
    let r = read_pypi("uv", &[Wf::Inline("release.yml", UV_RELEASE)], &[]).await;
    let best = r.ranked.first().expect("a recipe");
    assert_eq!(best.working_directory.as_deref(), Some("python"));
    assert!(
        r.evidence.iter().any(|e| e.claim
            == Claim::ToolchainExact {
                tool: "uv".into(),
                version: "0.4.20".into()
            }
            && e.confidence == Confidence::Strong),
        "{:?}",
        r.evidence
    );
    assert!(
        r.evidence.iter().any(|e| e.claim
            == Claim::SubdirIs {
                path: "python".into()
            }),
        "{:?}",
        r.evidence
    );

    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    // `setup-uv` named no interpreter, and `uv build --python 3.11` did.
    assert_eq!(params(&c.strategy, "deps")["python_version"], "3.11");
    // The step's working directory is where the project is, and where its output lands.
    let Strategy::Flow(f) = &c.strategy else {
        unreachable!()
    };
    assert_eq!(f.location.subdir.as_deref(), Some("python"));
    assert_eq!(f.output_dir.as_deref(), Some("python/dist"));
    // A different frontend driving the same backend is an approximation, and said to be one.
    assert!(
        c.assumptions.iter().any(|a| a.contains("`uv build`")),
        "{:?}",
        c.assumptions
    );
}

/// `actions/setup-python` pointed at a file, which is only a pin when the file holds a version.
fn version_file_release(file: &str) -> String {
    format!(
        "on:\n  push:\n    tags: ['*']\njobs:\n  release:\n    runs-on: ubuntu-22.04\n    steps:\n      \
         - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          \
         python-version-file: {file}\n      - run: python -m build\n      \
         - uses: pypa/gh-action-pypi-publish@release/v1\n"
    )
}

#[tokio::test]
async fn a_version_file_is_a_pin_where_it_holds_a_version_and_nothing_where_it_is_missing() {
    let text = version_file_release(".python-version");
    let wf = text.leak();
    let r = read_pypi(
        "pyversion",
        &[Wf::Inline("release.yml", wf)],
        &[(".python-version", "# the interpreter\n3.11.7\n")],
    )
    .await;
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    assert_eq!(params(&c.strategy, "deps")["python_version"], "3.11.7");
    assert!(
        r.evidence.iter().any(|e| e.source == "ci:.python-version"),
        "{:?}",
        r.evidence
    );

    // The same workflow, and no such file at this commit: no claim, and the recipe says it is
    // building on whatever interpreter the image carries.
    let r = read_pypi("pyversion-missing", &[Wf::Inline("release.yml", wf)], &[]).await;
    let pin = &r.ranked[0].toolchains[0];
    assert_eq!(
        pin.spec,
        trigon_registry::ci::VersionSpec::Unknown {
            raw: ".python-version".into(),
            why: trigon_registry::ci::WhyUnknown::FileMissing
        }
    );
    assert!(!r.evidence.iter().any(|e| matches!(
        &e.claim,
        Claim::ToolchainExact { tool, .. } | Claim::ToolchainRange { tool, .. } if tool == "python"
    )));
    let c = r.candidate.as_ref().expect("a candidate without a pin");
    assert!(!params(&c.strategy, "deps").contains_key("python_version"));
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("pins no interpreter version")),
        "{:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn an_interpreter_the_workflow_does_not_name_as_one_version_makes_no_claim() {
    // An expression this resolver cannot evaluate, and a list: each is a statement about several
    // possible interpreters, and a claim built from one would carry CI's authority behind a guess.
    for (name, field, why) in [
        (
            "py-expr",
            "python-version: ${{ vars.PYTHON }}",
            trigon_registry::ci::WhyUnknown::Expression,
        ),
        (
            "py-list",
            "python-version: ['3.11', '3.12']",
            trigon_registry::ci::WhyUnknown::Multiple,
        ),
    ] {
        let text = PLAIN_RELEASE.replace("python-version: \"3.12\"", field);
        let wf = text.leak();
        let r = read_pypi(name, &[Wf::Inline("release.yml", wf)], &[]).await;
        let pin = &r.ranked[0].toolchains[0];
        assert!(
            matches!(&pin.spec, trigon_registry::ci::VersionSpec::Unknown { why: w, .. } if *w == why),
            "{field}: {:?}",
            pin.spec
        );
        assert!(
            !r.evidence.iter().any(
                |e| matches!(&e.claim, Claim::ToolchainExact { tool, .. } if tool == "python")
            ),
            "{field}: {:?}",
            r.evidence
        );
    }
}

#[tokio::test]
async fn a_container_is_a_statement_about_userspace_and_not_about_the_host() {
    // On a Windows host the job is out of scope whatever image it names: the image says what
    // userspace the build sees, not what kernel runs it.
    let text = PLAIN_RELEASE.replace(
        "runs-on: ubuntu-22.04",
        "runs-on: windows-latest\n    container: python:3.12",
    );
    let wf = text.leak();
    let r = read_pypi("container-windows", &[Wf::Inline("release.yml", wf)], &[]).await;
    assert!(
        matches!(
            &r.declined,
            Some(Decline::RunnerOutOfScope(OutOfScope::Windows(l))) if l == "windows-latest"
        ),
        "{:?}",
        r.declined
    );
    assert!(r.out_of_scope.is_some());

    // On a Linux host, a digest-pinned image is the one runner statement that is not an
    // approximation, and a tag is said to be a tag.
    for (image, says) in [
        (
            "python:3.12@sha256:0123abcd",
            "already pinned by digest (sha256:0123abcd)",
        ),
        ("python:3.12", "a tag rather than a digest"),
    ] {
        let text = PLAIN_RELEASE.replace(
            "runs-on: ubuntu-22.04",
            &format!("runs-on: ubuntu-22.04\n    container: {{ image: \"{image}\" }}"),
        );
        let wf = text.leak();
        let r = read_pypi(
            &format!("container-{}", image.len()),
            &[Wf::Inline("release.yml", wf)],
            &[],
        )
        .await;
        let c = r
            .candidate
            .as_ref()
            .unwrap_or_else(|| panic!("{:?}", r.declined));
        assert!(
            c.assumptions.iter().any(|a| a.contains(says)),
            "{image}: {:?}",
            c.assumptions
        );
        assert_eq!(r.base_image, None, "a container is not an approximation");
    }

    // An image behind an expression the resolver cannot evaluate is not an image; the rung
    // declines and names what it could not read, rather than guessing at a container.
    let text = PLAIN_RELEASE.replace(
        "runs-on: ubuntu-22.04",
        "runs-on: ubuntu-22.04\n    container: ${{ vars.IMAGE }}",
    );
    let wf = text.leak();
    let r = read_pypi("container-expr", &[Wf::Inline("release.yml", wf)], &[]).await;
    assert!(r.candidate.is_none(), "{:?}", r.candidate);
    let said = r.declined.as_ref().expect("a decline").to_string();
    assert!(said.contains("vars.IMAGE"), "{said}");
}

const UNREACHABLE_BUILD: &str = r#"
name: Release
on:
  release:
    types: [published]
jobs:
  build-a:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - run: python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dist-a
          path: dist/
  build-b:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - run: python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dist-b
          path: dist/
  publish:
    needs: [build-a, build-b]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: wheels
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;

#[tokio::test]
async fn a_publish_job_whose_build_is_not_in_the_file_says_which_artifact_it_wanted() {
    // The job carries a publish marker, so "no job publishes" would be false about this run and
    // would send a reader to the wrong half of the file. What failed is the edge back to a build.
    let r = read_pypi(
        "unreachable",
        &[Wf::Inline("release.yml", UNREACHABLE_BUILD)],
        &[],
    )
    .await;
    assert_eq!(
        r.declined,
        Some(Decline::BuildJobUnreachable {
            publish_job: "publish".into(),
            artifact: "wheels".into(),
        })
    );
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("publishes something no reachable job builds")),
        "{:?}",
        r.notes
    );
    assert!(r.ranked.is_empty());
}

#[tokio::test]
async fn a_build_step_behind_a_condition_the_rung_cannot_evaluate_is_noted() {
    // It may not have run at all. The recipe assumes it did, and says so beside the verdict.
    let text = PLAIN_RELEASE.replace(
        "      - run: python -m build\n",
        "      - run: python -m build\n        if: ${{ github.event_name == 'release' }}\n",
    );
    let wf = text.leak();
    let r = read_pypi("guarded", &[Wf::Inline("release.yml", wf)], &[]).await;
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("which this rung cannot evaluate, so the recipe assumes it ran")),
        "{:?}",
        r.notes
    );
    assert!(r.candidate.is_some(), "{:?}", r.declined);
}

#[tokio::test]
async fn a_cibuildwheel_build_is_one_unmodelled_step_and_says_why() {
    let text = PLAIN_RELEASE
        .replace("      - run: python -m pip install build\n", "")
        .replace(
            "      - run: python -m build\n",
            "      - uses: pypa/cibuildwheel@v2.16\n",
        );
    let wf = text.leak();
    let r = read_pypi("cibw", &[Wf::Inline("release.yml", wf)], &[]).await;
    assert_eq!(
        r.declined,
        Some(Decline::BuildIsOneUnmodelledStep {
            action: "pypa/cibuildwheel".into()
        })
    );
    assert!(
        r.notes.iter().any(|n| n.contains("manylinux")),
        "{:?}",
        r.notes
    );
    // The evidence survives the decline: the interpreter is still known.
    assert!(
        r.evidence.iter().any(|e| e.claim
            == Claim::ToolchainExact {
                tool: "python".into(),
                version: "3.12".into()
            }),
        "{:?}",
        r.evidence
    );
}

const NPM_ACTION_RELEASE: &str = r#"
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version-file: .nvmrc
      - run: npm ci
      - run: npm run build
      - uses: JS-DevTools/npm-publish@v3
"#;

#[tokio::test]
async fn an_npm_release_through_the_publish_action_is_read_with_its_lockfile() {
    let (root, url, commit) = repo(
        "npm-action",
        &[Wf::Inline("publish.yml", NPM_ACTION_RELEASE)],
        &[
            (".nvmrc", "20.11.1\n"),
            ("package-lock.json", "{\"lockfileVersion\": 3}\n"),
        ],
    );
    let mut t = target(Ecosystem::Npm, "npm-action", "1.2.3", &url, &commit);
    for (tool, version, source) in [
        ("node", "20.11.1", "npm:_nodeVersion"),
        ("npm", "10.2.4", "npm:_npmVersion"),
    ] {
        t.intrinsics.evidence.push(Evidence::new(
            Claim::ToolchainExact {
                tool: tool.into(),
                version: version.into(),
            },
            Confidence::Certain,
            source,
        ));
    }
    let r = rung(&root).read(&t).await.unwrap();
    // `npm ci` resolves nothing: the lockfile is the answer, so the moment is the lockfile's
    // digest and it is the one registry moment this rung can state as certain.
    assert!(
        r.evidence.iter().any(|e| matches!(
            &e.claim,
            Claim::RegistryMomentIs {
                moment: trigon_core::RegistryMoment::Lockfile { .. }
            }
        ) && e.confidence == Confidence::Certain),
        "{:?}",
        r.evidence
    );
    assert!(
        r.evidence.iter().any(|e| e.source == "ci:.nvmrc"),
        "{:?}",
        r.evidence
    );
    // The release ran a build `npm pack` would not, which is the one thing it knows that the
    // registry does not.
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    assert_eq!(tool(&c.strategy, "build"), "npm/build/custom");
    assert_eq!(params(&c.strategy, "build")["command"], "build");
    assert_eq!(params(&c.strategy, "deps")["node_version"], "20.11.1");
    assert!(
        r.notes.iter().any(|n| n.contains("the registry's is used")),
        "{:?}",
        r.notes
    );
}

#[tokio::test]
async fn a_node_version_written_with_a_v_is_that_pin_and_an_lts_alias_is_none() {
    // `v20.11.1` is what `node -v > .nvmrc` writes, and nvm and `actions/setup-node` both read it
    // as 20.11.1. Read as it is spelled, it made no claim at all, and was called a wildcard.
    let in_the_workflow: &'static str = NPM_ACTION_RELEASE
        .replace("node-version-file: .nvmrc", "node-version: v20.11.1")
        .leak();
    let lockfile = ("package-lock.json", "{\"lockfileVersion\": 3}\n");
    for (name, wf, extra, source) in [
        (
            "nvmrc-v",
            NPM_ACTION_RELEASE,
            vec![(".nvmrc", "v20.11.1\n"), lockfile],
            "ci:.nvmrc",
        ),
        (
            "node-version-v",
            in_the_workflow,
            vec![lockfile],
            "ci:actions/setup-node:node-version",
        ),
    ] {
        let (root, url, commit) = repo(name, &[Wf::Inline("publish.yml", wf)], &extra);
        let t = target(Ecosystem::Npm, name, "1.2.3", &url, &commit);
        let r = rung(&root).read(&t).await.unwrap();
        assert!(
            r.evidence.iter().any(|e| e.source == source
                && e.claim
                    == Claim::ToolchainExact {
                        tool: "node".into(),
                        version: "20.11.1".into()
                    }),
            "{name}: {:?}",
            r.evidence
        );
    }

    // An LTS alias names whatever release its line had reached on the day it was read, which is
    // no pin: it stays unknown, and makes no claim.
    let (root, url, commit) = repo(
        "nvmrc-lts",
        &[Wf::Inline("publish.yml", NPM_ACTION_RELEASE)],
        &[(".nvmrc", "lts/iron\n"), lockfile],
    );
    let t = target(Ecosystem::Npm, "nvmrc-lts", "1.2.3", &url, &commit);
    let r = rung(&root).read(&t).await.unwrap();
    assert_eq!(
        r.ranked[0].toolchains[0].spec,
        trigon_registry::ci::VersionSpec::Unknown {
            raw: "lts/iron".into(),
            why: trigon_registry::ci::WhyUnknown::Wildcard
        }
    );
    assert!(
        !r.evidence.iter().any(|e| e.source == "ci:.nvmrc"),
        "{:?}",
        r.evidence
    );
}

// ---------------------------------------------------------------------------------------------
// The rung, seen from the ladder
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_rung_explains_itself_through_the_ladder_and_its_summary() {
    // A candidate: the ladder asks nothing further, and the summary names the recipe.
    let (root, url, commit) = repo(
        "ladder-yes",
        &[Wf::Inline("release.yml", PLAIN_RELEASE)],
        &[],
    );
    let t = target(Ecosystem::PyPI, "ladder-yes", "1.2.3", &url, &commit);
    let r = rung(&root);
    assert_eq!(r.name(), "ci-derived");
    let got = r.infer(&t).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].derivation, Derivation::CiDerived);
    assert_eq!(r.why_not(&t).await, None);
    let summary = r.read(&t).await.unwrap().summary();
    assert_eq!(
        summary,
        "a candidate from .github/workflows/release.yml:release"
    );

    // A decline: the ladder gets the decline's own sentence as the reason, which is the only
    // explanation a `no-strategy` verdict carries.
    let (root, url, commit) = repo("ladder-no", &[Wf::Fixture("attrs-pypi-package")], &[]);
    let t = target(Ecosystem::PyPI, "attrs", "1.2.3", &url, &commit);
    let r = rung(&root);
    assert!(r.infer(&t).await.unwrap().is_empty());
    let why = r.why_not(&t).await.expect("a reason");
    let reading = r.read(&t).await.unwrap();
    assert_eq!(
        Some(why.clone()),
        reading.declined.as_ref().map(Decline::to_string)
    );
    assert_eq!(reading.summary(), format!("no candidate: {why}"));
}

#[tokio::test]
async fn a_target_the_rung_cannot_read_declines_for_that_reason() {
    let (root, url, commit) = repo(
        "unreadable",
        &[Wf::Inline("release.yml", PLAIN_RELEASE)],
        &[],
    );

    // An ecosystem with no lowering is said to be one, rather than read and misdescribed.
    let t = target(Ecosystem::CratesIo, "unreadable", "1.2.3", &url, &commit);
    let r = rung(&root).read(&t).await.unwrap();
    assert!(
        matches!(&r.declined, Some(Decline::NothingTheHeuristicLacks { because })
            if because.contains("no CI lowering yet")),
        "{:?}",
        r.declined
    );

    // A repository the tag rung does not ask about, and no commit: the workflow at `HEAD` is not
    // the one that built this release. Nothing is fetched to find that out.
    let mut t = target(
        Ecosystem::PyPI,
        "unreadable",
        "1.2.3",
        "https://codeberg.org/o/unreadable",
        "",
    );
    t.source.as_mut().unwrap().how = SourceDiscovery::RegistryMetadata;
    let r = rung(&root).read(&t).await.unwrap();
    assert_eq!(r.declined, Some(Decline::NoPinnedCommit));

    // A commit the repository does not have — force-pushed away — is a decline, not an error that
    // would turn the target into no strategy at all.
    let t = target(
        Ecosystem::PyPI,
        "unreadable",
        "1.2.3",
        &url,
        &"0".repeat(40),
    );
    let r = rung(&root).read(&t).await.unwrap();
    assert!(
        matches!(&r.declined, Some(Decline::SourceUnreadable { detail }) if !detail.is_empty()),
        "{:?}",
        r.declined
    );
    assert!(r.evidence.is_empty());
}

// ---------------------------------------------------------------------------------------------
// What a lowering carries beside the recipe
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_build_that_fetches_and_installs_system_packages_says_both() {
    // A fetch from outside the registry is a fact the egress tier depends on; a system package is
    // something `FlowStrategy` can carry on the build step's `needs`, and says it did.
    let text = PLAIN_RELEASE.replace(
        "      - run: python -m build\n",
        "      - run: |\n          sudo apt-get install -y libffi-dev\n          \
         curl -sSL https://example.invalid/vendor.tgz -o vendor.tgz\n          \
         python -m build\n",
    );
    let r = read_pypi("fetches", &[Wf::Inline("release.yml", text.leak())], &[]).await;
    assert!(
        r.evidence
            .iter()
            .any(|e| e.claim == Claim::RequiresNetwork { required: true }),
        "{:?}",
        r.evidence
    );
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("fetches from outside the registry")
                && n.contains("example.invalid")),
        "{:?}",
        r.notes
    );
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    let Strategy::Flow(f) = &c.strategy else {
        unreachable!()
    };
    assert_eq!(f.build[0].needs, ["libffi-dev"]);
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("installs system packages (libffi-dev)")),
        "{:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn how_the_workflow_checked_out_is_stated_where_it_matters_and_refused_where_it_breaks() {
    // A named ref other than the pinned commit, and the full history a VCS-versioned build reads
    // its version from: both are assumptions about the verdict, not reasons to refuse it.
    let text = PLAIN_RELEASE.replace(
        "      - uses: actions/checkout@v4\n",
        "      - uses: actions/checkout@v4\n        with:\n          ref: main\n          \
         fetch-depth: 0\n",
    );
    let r = read_pypi(
        "checkout-ref",
        &[Wf::Inline("release.yml", text.leak())],
        &[],
    )
    .await;
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("checked out `main` rather than the commit this run pins")),
        "{:?}",
        c.assumptions
    );
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("checks out the full history")),
        "{:?}",
        c.assumptions
    );

    // A checkout into a subdirectory moves the tree the build runs in, and no field of the
    // recipe can say where; the rung declines rather than build in the wrong place.
    let text = PLAIN_RELEASE.replace(
        "      - uses: actions/checkout@v4\n",
        "      - uses: actions/checkout@v4\n        with:\n          path: src\n",
    );
    let r = read_pypi(
        "checkout-path",
        &[Wf::Inline("release.yml", text.leak())],
        &[],
    )
    .await;
    assert_eq!(
        r.declined,
        Some(Decline::UnresolvedExpression {
            field: "actions/checkout path",
            raw: "src".into()
        })
    );
}

#[tokio::test]
async fn the_registry_moment_and_the_backend_the_wheel_names_reach_the_recipe() {
    let (root, url, commit) = repo("moment", &[Wf::Inline("release.yml", PLAIN_RELEASE)], &[]);
    let mut t = target(Ecosystem::PyPI, "moment", "1.2.3", &url, &commit);
    t.intrinsics.evidence.push(Evidence::new(
        Claim::ToolchainExact {
            tool: "hatchling".into(),
            version: "1.21.0".into(),
        },
        Confidence::Certain,
        "wheel:Generator",
    ));
    let r = rung(&root)
        .with_mirror(Some("mirror:8080".into()))
        .read(&t)
        .await
        .unwrap();
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    let deps = params(&c.strategy, "deps");
    assert_eq!(deps["registry_time"], "2024-03-01T00:00:00Z");
    assert_eq!(deps["build_backend"], "hatchling==1.21.0");
    // The constraint file that pins the backend is where the build looks.
    assert!(
        params(&c.strategy, "build")["constraints"].ends_with("/constraints.txt"),
        "{:?}",
        params(&c.strategy, "build")
    );
    assert!(
        !c.assumptions
            .iter()
            .any(|a| a.contains("no registry mirror"))
    );

    // With no publish time there is no moment to pin, and the recipe says it resolves today.
    let (root, url, commit) = repo(
        "no-moment",
        &[Wf::Inline("release.yml", PLAIN_RELEASE)],
        &[],
    );
    let mut t = target(Ecosystem::PyPI, "no-moment", "1.2.3", &url, &commit);
    t.intrinsics.publish_time = None;
    let r = rung(&root)
        .with_mirror(Some("mirror:8080".into()))
        .read(&t)
        .await
        .unwrap();
    let c = r.candidate.as_ref().expect("a candidate");
    assert!(!params(&c.strategy, "deps").contains_key("registry_time"));
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("no publish time recorded")),
        "{:?}",
        c.assumptions
    );
    // No backend was read, and the build is still pointed at the constraints file: it carries the
    // exclusion of the artifact under test, which every PyPI recipe is given.
    assert_eq!(
        params(&c.strategy, "build")["constraints"],
        format!("{}/constraints.txt", trigon_strategy::VENV)
    );
}

#[tokio::test]
async fn a_ci_recipe_keeps_the_artifact_under_test_out_of_its_own_build_as_the_heuristic_does() {
    // A package that is part of the machinery that builds packages — `packaging`,
    // `pyproject-hooks` — makes pip ask for the very version under test when the frontend is
    // installed. The heuristic excludes it and always points the build at the constraints file
    // that carries the exclusion; the CI lowering kept the shape from before that, with no
    // exclusion and no constraints unless a backend was read. It sits above the heuristic and
    // displaces its candidate, so its recipe undid the fix for every package it answered.
    let r = read_pypi("kind", &[Wf::Inline("release.yml", PLAIN_RELEASE)], &[]).await;
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    let deps = params(&c.strategy, "deps");
    assert!(!deps.contains_key("build_backend"), "the premise: {deps:?}");
    assert_eq!(deps["exclude_self"], "kind!=1.2.3");
    assert_eq!(
        params(&c.strategy, "build")["constraints"],
        "/trigon/deps/constraints.txt"
    );
}

#[tokio::test]
async fn an_action_the_rung_does_not_read_lowers_the_candidate_and_is_named() {
    // An unmodelled step is where the next inference failure comes from; hiding it is the worst
    // option available, so the candidate is weaker and says which step it could not read.
    let text = PLAIN_RELEASE.replace(
        "      - run: python -m build\n",
        "      - uses: example/prepare-sources@v1\n      - run: python -m build\n",
    );
    let r = read_pypi("unmodelled", &[Wf::Inline("release.yml", text.leak())], &[]).await;
    let c = r
        .candidate
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", r.declined));
    assert_eq!(c.confidence, Confidence::Weak);
    assert!(
        c.assumptions
            .iter()
            .any(|a| a.contains("1 step this rung does not interpret (example/prepare-sources)")),
        "{:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn a_release_job_that_builds_nothing_says_so() {
    // Selected for its publish marker, and running no step that produces an artifact. On PyPI
    // that is a job that tags a release, not a description of a build.
    let text = PLAIN_RELEASE
        .replace("      - run: python -m pip install build\n", "")
        .replace(
            "      - run: python -m build\n",
            "      - run: echo publishing\n",
        );
    let r = read_pypi(
        "builds-nothing",
        &[Wf::Inline("release.yml", text.leak())],
        &[],
    )
    .await;
    assert_eq!(
        r.declined,
        Some(Decline::BuildJobRunsNoBuild {
            job: "release".into()
        })
    );
}

const NPM_PUBLISH_ONLY: &str = r#"
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm publish --provenance
"#;

#[tokio::test]
async fn an_npm_release_that_only_publishes_leaves_the_heuristic_to_answer() {
    // `npm publish` runs `prepare` and `prepack` itself, which is the heuristic's own recipe. A
    // CI candidate here would only displace a better-informed one.
    let r = read_npm(
        "publish-only",
        &[Wf::Inline("publish.yml", NPM_PUBLISH_ONLY)],
        true,
    )
    .await;
    assert!(r.candidate.is_none());
    assert!(
        matches!(&r.declined, Some(Decline::NothingTheHeuristicLacks { because })
            if because.contains("no build script beyond what `npm pack` runs")),
        "{:?}",
        r.declined
    );
    // The workflow's `node-version: 20` is a series, carried as a range that intersects with the
    // registry's exact version rather than contradicting it.
    assert!(
        r.evidence.iter().any(|e| e.claim
            == Claim::ToolchainRange {
                tool: "node".into(),
                lo: Some("20".into()),
                hi: Some("21".into())
            }),
        "{:?}",
        r.evidence
    );
}

#[tokio::test]
async fn equally_ranked_recipes_are_a_tie_whatever_they_disagree_about() {
    // The runner, the build command, the directory: each is a different build, and the ranking
    // did not decide between them.
    for (name, from, to, disagree) in [
        (
            "tie-runner",
            "runs-on: ubuntu-24.04",
            "runs-on: ubuntu-22.04",
            "the runner",
        ),
        (
            "tie-build",
            "- run: python -m build",
            "- run: python -m build --wheel",
            "the build command",
        ),
        (
            "tie-dir",
            "- run: python -m build",
            "- run: python -m build\n        working-directory: pkg",
            "the working directory",
        ),
    ] {
        let r = read_pypi(
            name,
            &[
                Wf::Inline("a-release.yml", OTHER_RELEASE),
                Wf::Inline("b-release.yml", OTHER_RELEASE.replace(from, to).leak()),
            ],
            &[],
        )
        .await;
        match r.declined.as_ref() {
            Some(Decline::RecipesTie { disagree_on, .. }) => {
                assert_eq!(*disagree_on, disagree, "{name}")
            }
            other => panic!("{name}: expected a tie, got {other:?}"),
        }
    }

    // Two identical release workflows are interchangeable, and either is correct.
    let r = read_pypi(
        "tie-none",
        &[
            Wf::Inline("a-release.yml", OTHER_RELEASE),
            Wf::Inline("b-release.yml", OTHER_RELEASE),
        ],
        &[],
    )
    .await;
    assert!(r.candidate.is_some(), "{:?}", r.declined);
}
