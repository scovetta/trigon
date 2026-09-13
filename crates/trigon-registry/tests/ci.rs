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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use trigon_core::{
    ArtifactId, Claim, Confidence, Ecosystem, Evidence, Intrinsics, SourceDiscovery,
    SourceProvenance, TargetRef, ToolchainResolution, resolve_toolchain,
};
use trigon_registry::ci::recipe::{BuildPublishLink, Decline, OutOfScope};
use trigon_registry::{
    ArtifactMeta, CiInferrer, CiReading, Client, ClientConfig, Derivation, ResolvedTarget,
    StrategyInferrer,
};
use trigon_strategy::{StepBody, Strategy};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/workflows");

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-ci-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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

/// A repository at a pinned commit holding these workflows and these extra files.
fn repo(name: &str, workflows: &[Wf], extra: &[(&str, &str)]) -> (PathBuf, String, String) {
    let root = tmpdir(name);
    let repo = root.join("origin");
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
            declared_sha256: None,
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
            commit: commit.into(),
            ref_name: None,
            subdir: None,
            how: SourceDiscovery::RegistryCommit,
        }),
    }
}

/// The rung, pointed at a cache under this test's own directory.
fn rung(root: &Path) -> CiInferrer {
    let sources =
        Arc::new(trigon_registry::SourceCache::new(root.join("cache")).trusting_local_paths());
    CiInferrer::new(Client::new(ClientConfig::default()).unwrap(), sources)
}

async fn read_pypi(name: &str, workflows: &[Wf], extra: &[(&str, &str)]) -> Arc<CiReading> {
    let (root, url, commit) = repo(name, workflows, extra);
    let t = target(Ecosystem::PyPI, name, "1.2.3", &url, &commit);
    rung(&root).read(&t).await.unwrap()
}

async fn read_npm(name: &str, workflows: &[Wf], toolchain: bool) -> Arc<CiReading> {
    let (root, url, commit) = repo(name, workflows, &[]);
    let mut t = target(Ecosystem::Npm, name, "1.2.3", &url, &commit);
    if toolchain {
        for (tool, version, source) in [
            ("node", "24.1.0", "npm:_nodeVersion"),
            ("npm", "11.3.0", "npm:_npmVersion"),
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
    match &steps[0].body {
        StepBody::Uses { with, .. } => with.clone(),
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
