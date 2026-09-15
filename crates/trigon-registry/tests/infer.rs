//! The inference ladder, without a network.

use std::collections::BTreeMap;

use trigon_core::{
    ArtifactId, Claim, Confidence, Ecosystem, Evidence, Intrinsics, SourceDiscovery,
    SourceProvenance, TargetRef,
};
use trigon_registry::{
    ArtifactMeta, Client, ClientConfig, Derivation, NpmInferrer, PyPiInferrer, ResolvedTarget,
    StrategyInferrer,
};
use trigon_strategy::{StepBody, Strategy};

fn client() -> Client {
    Client::new(ClientConfig::default()).unwrap()
}

fn npm_target(with_toolchain: bool) -> ResolvedTarget {
    let mut evidence = vec![Evidence::new(
        Claim::RepoIs {
            url: "https://github.com/stevemao/left-pad".into(),
        },
        Confidence::Strong,
        "npm:package.json:repository",
    )];
    if with_toolchain {
        for (tool, version, source) in [
            ("node", "9.2.1", "npm:_nodeVersion"),
            ("npm", "5.5.1", "npm:_npmVersion"),
        ] {
            evidence.push(Evidence::new(
                Claim::ToolchainExact {
                    tool: tool.into(),
                    version: version.into(),
                },
                Confidence::Certain,
                source,
            ));
        }
    }
    ResolvedTarget {
        reference: TargetRef::new(Ecosystem::Npm, "left-pad", "1.3.0"),
        artifacts: vec![ArtifactMeta {
            id: ArtifactId::new("left-pad-1.3.0.tgz"),
            url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into(),
            declared_sha256: None,
            size: None,
        }],
        intrinsics: Intrinsics {
            publish_time: Some("2018-04-09T01:10:45.796Z".into()),
            declared_repo: Some("https://github.com/stevemao/left-pad".into()),
            registry_moment: None,
            evidence,
        },
        source: Some(SourceProvenance {
            repo_url: "https://github.com/stevemao/left-pad".into(),
            commit: "ff8e7ba8b4122829cf66125ca8445cac7f073bce".into(),
            ref_name: None,
            subdir: None,
            how: SourceDiscovery::RegistryCommit,
        }),
        about: None,
    }
}

fn tool_params(strategy: &Strategy, phase: &str) -> BTreeMap<String, String> {
    let Strategy::Flow(f) = strategy else {
        panic!("expected a flow")
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

#[tokio::test]
async fn npm_inference_transcribes_the_publishers_toolchain() {
    // Not an inference at all. npm records _nodeVersion and _npmVersion at publish time, so this
    // is the toolchain that produced the artifact rather than a guess at one.
    let c = NpmInferrer::new(client())
        .infer(&npm_target(true))
        .await
        .unwrap();
    let candidate = &c[0];
    assert_eq!(candidate.derivation, Derivation::Heuristic);
    assert_eq!(candidate.discovery, SourceDiscovery::RegistryCommit);
    assert_eq!(candidate.confidence, Confidence::Certain);

    let deps = tool_params(&candidate.strategy, "deps");
    assert_eq!(deps.get("node_version").map(String::as_str), Some("9.2.1"));
    assert_eq!(deps.get("npm_version").map(String::as_str), Some("5.5.1"));

    let loc = candidate.strategy.location().unwrap();
    assert_eq!(loc.git_ref, "ff8e7ba8b4122829cf66125ca8445cac7f073bce");
}

#[tokio::test]
async fn without_a_recorded_toolchain_the_rung_declines() {
    // Picking a current Node would build with a packer the publisher never ran: a 2026 npm packs
    // a tarball a 2018 npm would not have, and the divergence would read as the package's fault.
    let c = NpmInferrer::new(client())
        .infer(&npm_target(false))
        .await
        .unwrap();
    assert!(c.is_empty(), "declining beats guessing a toolchain");
}

#[tokio::test]
async fn a_registry_moment_is_pinned_only_when_a_mirror_exists() {
    // Emitting registry_time with no mirror renders a URL pointing at a host that does not
    // resolve, and the build fails in a way that reads like the package's fault.
    let without = NpmInferrer::new(client())
        .infer(&npm_target(true))
        .await
        .unwrap();
    assert!(!tool_params(&without[0].strategy, "deps").contains_key("registry_time"));
    assert!(
        without[0]
            .assumptions
            .iter()
            .any(|a| a.contains("today's npm")),
        "and the caveat is stated: {:?}",
        without[0].assumptions
    );

    let with = NpmInferrer::new(client())
        .with_mirror(Some("timewarp".into()))
        .infer(&npm_target(true))
        .await
        .unwrap();
    assert_eq!(
        tool_params(&with[0].strategy, "deps")
            .get("registry_time")
            .map(String::as_str),
        Some("2018-04-09T01:10:45.796Z")
    );
    assert!(with[0].assumptions.is_empty());
}

#[tokio::test]
async fn the_output_is_the_tarball_not_the_working_tree() {
    // `npm pack` writes <name>-<version>.tgz into the package directory. Naming the directory
    // collects the whole checkout, which is a "successful" build with nothing to compare.
    let c = NpmInferrer::new(client())
        .infer(&npm_target(true))
        .await
        .unwrap();
    let Strategy::Flow(f) = &c[0].strategy else {
        panic!()
    };
    assert_eq!(f.output_path.as_deref(), Some("*.tgz"));
    assert_eq!(f.output_dir, None);
}

#[tokio::test]
async fn a_target_with_no_source_yields_nothing_rather_than_an_error() {
    // Most rungs are silent for most targets; that is how a ladder works.
    let mut t = npm_target(true);
    t.source = None;
    assert!(
        NpmInferrer::new(client())
            .infer(&t)
            .await
            .unwrap()
            .is_empty()
    );
}

fn with_artifacts(names: &[&str]) -> ResolvedTarget {
    let mut t = npm_target(true);
    t.reference = TargetRef::new(Ecosystem::PyPI, "demo", "1.0");
    t.artifacts = names
        .iter()
        .map(|n| ArtifactMeta {
            id: ArtifactId::new(*n),
            url: format!("https://files/{n}"),
            declared_sha256: None,
            size: None,
        })
        .collect();
    t
}

#[test]
fn a_release_with_several_artifacts_still_has_an_obvious_one() {
    // Every PyPI release publishes an sdist and at least one wheel, so requiring exactly one
    // artifact meant every PyPI target failed before it built anything.
    let t = with_artifacts(&["six-1.17.0-py2.py3-none-any.whl", "six-1.17.0.tar.gz"]);
    assert_eq!(
        t.pick(None).unwrap().id.as_str(),
        "six-1.17.0-py2.py3-none-any.whl",
        "the pure wheel is what almost everything installs"
    );
}

#[test]
fn a_sole_sdist_is_chosen_when_there_is_no_pure_wheel() {
    let t = with_artifacts(&["thing-1.0.tar.gz"]);
    assert_eq!(t.pick(None).unwrap().id.as_str(), "thing-1.0.tar.gz");
}

#[test]
fn several_platform_wheels_stay_ambiguous() {
    // These are built on different machines and do not reproduce alike, so picking one would
    // attach a verdict to whichever the registry happened to list first.
    let t = with_artifacts(&[
        "x-1.0-cp39-abi3-manylinux_2_28_x86_64.whl",
        "x-1.0-cp39-abi3-macosx_11_0_arm64.whl",
        "x-1.0.tar.gz",
    ]);
    // The lone sdist is still unambiguous, and is the artifact that carries the source.
    assert_eq!(t.pick(None).unwrap().id.as_str(), "x-1.0.tar.gz");

    let no_sdist = with_artifacts(&[
        "x-1.0-cp39-abi3-manylinux_2_28_x86_64.whl",
        "x-1.0-cp39-abi3-macosx_11_0_arm64.whl",
    ]);
    let e = no_sdist.pick(None).unwrap_err().to_string();
    assert!(e.contains("manylinux"), "the error lists what exists: {e}");
}

// ---------------------------------------------------------------------------
// The PyPI heuristic.
//
// Untested until now, and it is the rung that changed most: the build-backend pin, the constraint
// file, and the isolation setting are all decisions made here, and all three were wrong at some
// point today in ways that produced a plausible strategy rather than an error.

fn pypi_target(generator: Option<(&str, &str)>) -> ResolvedTarget {
    let mut evidence = vec![Evidence::new(
        Claim::RepoIs {
            url: "https://github.com/python-trio/sniffio".into(),
        },
        Confidence::Strong,
        "pypi:project_urls",
    )];
    // Exactly the shape `wheel::generator_evidence` produces, including the source string the
    // heuristic keys on: a pin derived from some other evidence would be a different claim.
    if let Some((tool, version)) = generator {
        evidence.push(Evidence::new(
            Claim::ToolchainExact {
                tool: tool.into(),
                version: version.into(),
            },
            Confidence::Certain,
            "wheel:Generator",
        ));
    }
    ResolvedTarget {
        reference: TargetRef::new(Ecosystem::PyPI, "sniffio", "1.3.1"),
        artifacts: vec![ArtifactMeta {
            id: ArtifactId::new("sniffio-1.3.1-py3-none-any.whl"),
            url: "https://files.pythonhosted.org/sniffio-1.3.1-py3-none-any.whl".into(),
            declared_sha256: None,
            size: None,
        }],
        intrinsics: Intrinsics {
            publish_time: Some("2024-02-25T23:20:01.196159Z".into()),
            declared_repo: Some("https://github.com/python-trio/sniffio".into()),
            registry_moment: None,
            evidence,
        },
        source: Some(SourceProvenance {
            repo_url: "https://github.com/python-trio/sniffio".into(),
            commit: "ae020e13b98d276a6558ffc25e82509fd4c288f0".into(),
            ref_name: Some("v1.3.1".into()),
            subdir: None,
            how: SourceDiscovery::ExactTag,
        }),
        about: None,
    }
}

async fn pypi_strategy(generator: Option<(&str, &str)>) -> (Strategy, Vec<String>) {
    let c = PyPiInferrer::new()
        .with_mirror(Some("timewarp:8129".into()))
        .infer(&pypi_target(generator))
        .await
        .unwrap();
    let one = c
        .into_iter()
        .next()
        .expect("the pypi rung produced nothing");
    (one.strategy, one.assumptions)
}

#[tokio::test]
async fn the_backend_the_wheel_names_is_pinned() {
    // The fix that moved PyPI from 33% to 80%. The published wheel records what built it in its own
    // `.dist-info/WHEEL`; unpinned, the frontend resolves the project's declaration against today's
    // index and the wheel diverges in METADATA, WHEEL and the RECORD that follows.
    let (s, assumptions) = pypi_strategy(Some(("hatchling", "1.29.0"))).await;
    let deps = tool_params(&s, "deps");
    assert_eq!(
        deps.get("build_backend").map(String::as_str),
        Some("hatchling==1.29.0")
    );
    assert!(
        !assumptions.iter().any(|a| a.contains("build backend")),
        "a pinned backend is not an assumption: {assumptions:?}"
    );
}

#[tokio::test]
async fn a_pin_travels_to_the_build_phase_as_a_constraint() {
    // The environment that matters is the isolated one the frontend builds, and pre-installing the
    // backend does nothing for it. The constraint file is how a version is pinned inside an
    // environment somebody else populates, so it has to reach the build step.
    let (s, _) = pypi_strategy(Some(("setuptools", "75.6.0"))).await;
    assert_eq!(
        tool_params(&s, "build")
            .get("constraints")
            .map(String::as_str),
        Some(format!("{}/constraints.txt", trigon_strategy::VENV).as_str())
    );
    // **Always pointed at, pinned backend or not.** The file used to exist only where a backend had
    // been read, and it now also carries the exclusion of the artifact under test — which is what
    // lets a package that is part of the machinery that builds packages resolve its frontend to the
    // release before itself instead of asking the mirror for the very thing under test.
    let (unpinned, _) = pypi_strategy(None).await;
    assert_eq!(
        tool_params(&unpinned, "build")
            .get("constraints")
            .map(String::as_str),
        Some(format!("{}/constraints.txt", trigon_strategy::VENV).as_str()),
        "the constraints file is written on every PyPI build, because it carries the \
         self-exclusion even where no backend was pinned"
    );

    // And the exclusion itself reaches the deps step, naming the exact version under test.
    assert_eq!(
        tool_params(&unpinned, "deps")
            .get("exclude_self")
            .map(String::as_str),
        Some("sniffio!=1.3.1"),
        "a build must not resolve to the artifact it is reproducing"
    );
}

#[tokio::test]
async fn isolation_stays_on_whether_or_not_a_backend_is_pinned() {
    // `-n` makes the frontend *check* for each declared build requirement rather than install it,
    // so anything the project needs beyond the backend goes missing — `attrs` wants `hatch-vcs` and
    // `hatch-fancy-pypi-readme` and stops with "Unmet dependencies". Coupling this to the pin was
    // wrong and produced a build failure that looked like the package's.
    for generator in [Some(("hatchling", "1.29.0")), None] {
        let (s, _) = pypi_strategy(generator).await;
        assert_eq!(
            tool_params(&s, "build")
                .get("no_isolation")
                .map(String::as_str),
            Some("false"),
            "isolation must stay on for {generator:?}"
        );
    }
}

#[tokio::test]
async fn an_artifact_that_names_no_backend_says_so_rather_than_guessing() {
    // An sdist, or a wheel assembled by hand. The absence is ordinary and belongs in the
    // assumptions, where it reaches the attestation, rather than being silently papered over.
    let (s, assumptions) = pypi_strategy(None).await;
    assert!(!tool_params(&s, "deps").contains_key("build_backend"));
    assert!(
        assumptions
            .iter()
            .any(|a| a.contains("names no build backend")),
        "{assumptions:?}"
    );
}

#[tokio::test]
async fn the_registry_moment_reaches_the_deps_phase() {
    // Without it every package with a floating range is unreproducible by construction. The pin
    // silently not applying is the bug class that dominated M1, so the strategy carrying it is
    // worth asserting even though the mirror enforces it separately.
    let (s, _) = pypi_strategy(Some(("flit_core", "3.12.0"))).await;
    assert_eq!(
        tool_params(&s, "deps")
            .get("registry_time")
            .map(String::as_str),
        Some("2024-02-25T23:20:01.196159Z")
    );
}

#[tokio::test]
async fn a_declared_build_changes_nothing_without_a_repository_to_check_it_against() {
    // The second condition is not optional. A package that declares a build nothing runs may still
    // commit its output, and running the build there regenerates files the repository already holds
    // correctly — under whatever today's floating ranges resolve to. With no source cache the rung
    // cannot ask, so it does not act: the strategy is the one it has always emitted.
    let mut target = npm_target(true);
    target.intrinsics.evidence.push(Evidence::new(
        Claim::UnrunScript {
            name: "build".into(),
            command: "bundt".into(),
        },
        Confidence::Certain,
        "npm:scripts",
    ));

    let got = NpmInferrer::new(Client::new(ClientConfig::default()).unwrap())
        .infer(&target)
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    let Strategy::Flow(f) = &got[0].strategy else {
        panic!("expected a flow")
    };
    let StepBody::Uses { tool, with } = &f.build[0].body else {
        panic!("expected a tool")
    };
    assert_eq!(tool, "npm/build/pack", "no repository, no build step");
    assert!(!with.contains_key("command"));
    assert!(
        !got[0].assumptions.iter().any(|a| a.contains("npm run")),
        "nothing was assumed, because nothing was done: {:?}",
        got[0].assumptions
    );
}
