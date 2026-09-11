//! The inference ladder, without a network.

use std::collections::BTreeMap;

use trigon_core::{
    ArtifactId, Claim, Confidence, Ecosystem, Evidence, Intrinsics, SourceDiscovery,
    SourceProvenance, TargetRef,
};
use trigon_registry::{
    ArtifactMeta, Client, ClientConfig, Derivation, NpmInferrer, ResolvedTarget, StrategyInferrer,
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
