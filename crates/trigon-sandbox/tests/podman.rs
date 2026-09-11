//! A real container build.
//!
//! Skipped when podman is unavailable or the pinned base image is not in the local store, so the
//! suite still runs in an environment without either. The image is pinned by digest because the
//! runner refuses anything else, which is exactly the property under test.

use std::collections::BTreeSet;

use trigon_sandbox::{
    BuildPlan, BuildRunner, EgressTier, Limits, OciPlan, Phase, PodmanRunner, RunOpts,
};

const ALPINE: &str = "docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";

async fn usable(r: &PodmanRunner) -> bool {
    if r.health().await.is_err() {
        eprintln!("skipped: podman is not available");
        return false;
    }
    let out = std::process::Command::new("podman")
        .args(["image", "exists", ALPINE])
        .status();
    match out {
        Ok(s) if s.success() => true,
        _ => {
            eprintln!("skipped: {ALPINE} is not in the local image store");
            false
        }
    }
}

fn opts(run_id: &str) -> RunOpts {
    RunOpts {
        run_id: run_id.into(),
        limits: Limits {
            wall_clock: std::time::Duration::from_secs(180),
            ..Default::default()
        },
        retain: false,
    }
}

fn workdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join("trigon-sandbox-tests");
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test]
async fn a_build_runs_and_its_artifact_is_collected() {
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }

    // Deny-all egress, so this proves the offline path end to end: no network at any point after
    // the image exists.
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "mkdir -p pkg && echo 'hello from source' > pkg/a.txt".into(),
        deps: "echo 'deps ran' > pkg/b.txt".into(),
        build: "mkdir -p dist && cat pkg/a.txt pkg/b.txt > dist/out.txt".into(),
        output_path: "dist/out.txt".into(),
        egress: EgressTier::DenyAll,
        privileged: false,
        extra_hosts: Default::default(),
    });

    let h = r.start(&plan, &opts("collect-ok")).await.expect("starts");
    let outcome = h.wait().await.expect("completes");

    assert!(
        outcome.succeeded(),
        "exit {}\n{}",
        outcome.exit_code,
        outcome.log_tail
    );
    let artifact = outcome.artifact.expect("an artifact was collected");
    let text = std::fs::read_to_string(&artifact).unwrap();
    assert_eq!(
        text, "hello from source\ndeps ran\n",
        "the phases ran in order"
    );

    assert_eq!(outcome.egress, EgressTier::DenyAll);
    assert!(
        !outcome.attestable,
        "a local unproxied run is not full-trust"
    );
    assert!(outcome.failed_in.is_none());

    // Timings are per phase and present, not zeroed.
    let phases: Vec<Phase> = outcome.timings.iter().map(|(p, _)| *p).collect();
    assert_eq!(phases, vec![Phase::Deps, Phase::Build]);
    assert!(outcome.timings.iter().all(|(_, d)| d.is_some()));
}

#[tokio::test]
async fn deny_all_egress_really_denies() {
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    // The control the whole design rests on. A build that can reach the network can fetch the
    // artifact it is meant to be reproducing, and will then reproduce it perfectly every time.
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "true".into(),
        build: "wget -T 5 -O - http://example.com >/dev/null".into(),
        output_path: ".".into(),
        egress: EgressTier::DenyAll,
        privileged: false,
        extra_hosts: Default::default(),
    });
    let h = r.start(&plan, &opts("deny-all")).await.unwrap();
    let outcome = h.wait().await.unwrap();
    assert!(
        !outcome.succeeded(),
        "the build reached the network under deny-all egress:\n{}",
        outcome.log_tail
    );
    assert_eq!(outcome.failed_in, Some(Phase::Build));
}

#[tokio::test]
async fn a_failing_build_still_reports_its_phase_and_logs() {
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    // Failed builds carry information. Losing the log here is losing the only evidence of why.
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "true".into(),
        build: "echo 'about to fail' && exit 3".into(),
        output_path: ".".into(),
        egress: EgressTier::DenyAll,
        privileged: false,
        extra_hosts: Default::default(),
    });
    let h = r.start(&plan, &opts("fails")).await.unwrap();
    let outcome = h.wait().await.unwrap();

    assert_eq!(outcome.exit_code, 3);
    assert_eq!(outcome.failed_in, Some(Phase::Build));
    assert!(
        outcome.log_tail.contains("about to fail"),
        "{}",
        outcome.log_tail
    );
}

#[tokio::test]
async fn a_failure_in_the_deps_phase_is_attributed_to_deps() {
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    // Which phase failed is the difference between "our infrastructure" and "this package".
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "echo 'deps blew up' && exit 1".into(),
        build: "true".into(),
        output_path: ".".into(),
        egress: EgressTier::DenyAll,
        privileged: false,
        extra_hosts: Default::default(),
    });
    let h = r.start(&plan, &opts("deps-fail")).await.unwrap();
    let outcome = h.wait().await.unwrap();
    assert!(!outcome.succeeded());
    assert_eq!(outcome.failed_in, Some(Phase::Deps));
    assert!(
        outcome.log_tail.contains("deps blew up"),
        "{}",
        outcome.log_tail
    );
}
