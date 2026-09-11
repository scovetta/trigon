//! A real container build.
//!
//! Skipped when podman is unavailable or the pinned base image is not in the local store, so the
//! suite still runs in an environment without either. The image is pinned by digest because the
//! runner refuses anything else, which is exactly the property under test.

use std::collections::BTreeSet;
use std::path::Path;

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
        mirror_port: 8129,
        guard: None,
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

const MIRROR_IMAGE: &str = "localhost/trigon-mirror:latest";

fn mirror_image_available() -> bool {
    let ok = std::process::Command::new("podman")
        .args(["image", "exists", MIRROR_IMAGE])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipped: build {MIRROR_IMAGE} with `trigon mirror-image`");
    }
    ok
}

#[tokio::test]
async fn mirror_only_egress_blocks_everything_but_the_mirror() {
    let r = PodmanRunner::new(workdir()).with_mirror_image(Some(MIRROR_IMAGE.into()));
    if !usable(&r).await || !mirror_image_available() {
        return;
    }

    // The control the whole design rests on. A build that can reach the network can fetch the
    // artifact it is supposed to be reproducing, and will then reproduce it perfectly, past every
    // clean re-run. Enforcement has to be a kernel boundary rather than a configured one: setting
    // HTTP_PROXY and hoping is not a control, because the build runs the package's own scripts and
    // those scripts are free to ignore it.
    //
    // Under mirror-only the build's only interface is an internal network whose sole route out is
    // the mirror container, so there is nothing to opt out of.
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "true".into(),
        // Two addresses that are reachable from any ordinary network, by IP so that a blocked
        // resolver is not mistaken for a blocked route.
        build: "nc -w 3 -z 1.1.1.1 443 && echo REACHED-CLOUDFLARE\n\
                nc -w 3 -z 151.101.0.223 443 && echo REACHED-NPM\n\
                echo probes-finished"
            .into(),
        output_path: ".".into(),
        egress: EgressTier::MirrorOnly,
        privileged: false,
        extra_hosts: Default::default(),
    });

    let h = r
        .start(&plan, &opts("egress-enforced"))
        .await
        .expect("starts");
    let outcome = h.wait().await.expect("completes");

    assert!(
        !outcome.log_tail.contains("REACHED-"),
        "the build reached the internet under mirror-only egress:\n{}",
        outcome.log_tail
    );
    assert!(
        outcome.log_tail.contains("probes-finished") || !outcome.succeeded(),
        "the probes should have run and failed, not been skipped:\n{}",
        outcome.log_tail
    );
    assert_eq!(outcome.egress, EgressTier::MirrorOnly);
    // The boundary holds, and it is still not enough to sign: with no network transcript we cannot
    // say what the build fetched from the mirror itself.
    assert!(!outcome.attestable);
}

#[tokio::test]
async fn the_same_probes_succeed_under_open_egress() {
    // Without this the test above proves nothing: a build that cannot reach anything because the
    // probe is broken looks exactly like one held back by the boundary.
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "true".into(),
        build: "nc -w 5 -z 1.1.1.1 443 && echo REACHED-CLOUDFLARE".into(),
        output_path: ".".into(),
        egress: EgressTier::Open,
        privileged: false,
        extra_hosts: Default::default(),
    });
    let h = r.start(&plan, &opts("egress-open")).await.unwrap();
    let outcome = h.wait().await.unwrap();
    assert!(
        outcome.log_tail.contains("REACHED-CLOUDFLARE"),
        "the probe itself must work, or the enforcement test is vacuous:\n{}",
        outcome.log_tail
    );
}

#[tokio::test]
async fn a_failed_build_leaves_nothing_behind() {
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    // Cleanup used to sit at the end of the happy path, so only successful builds tidied up. A
    // failing build is the common case for exactly the packages a sweep spends its time on, and
    // this machine had accumulated nineteen context directories and a 602 MB image before anyone
    // looked.
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "echo 'deps will fail' && exit 1".into(),
        build: "true".into(),
        output_path: ".".into(),
        egress: EgressTier::DenyAll,
        privileged: false,
        extra_hosts: Default::default(),
    });

    let run_id = "leftovers";
    let h = r.start(&plan, &opts(run_id)).await.unwrap();
    let outcome = h.wait().await.unwrap();
    assert!(!outcome.succeeded());

    let ctx = std::env::temp_dir().join(format!("trigon-ctx-{run_id}"));
    assert!(
        !ctx.exists(),
        "the build context outlived the failed build: {}",
        ctx.display()
    );
    // This run's own tag, not a count of every trigon-build image. A count is shared state, and
    // sibling tests create and delete those images: the first version of this assertion passed
    // alone and failed under `cargo test`, which is a flaky test rather than a finding.
    assert!(
        !image_exists(&format!("trigon-build:{run_id}")),
        "a failed build left its image behind"
    );
}

#[tokio::test]
async fn a_retained_build_keeps_its_image() {
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    // The other half: `retain` exists so an agent can exec into the container and a human can pull
    // the image, and a guard that removed it regardless would make the flag a lie.
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "true".into(),
        build: "mkdir -p dist && echo hi > dist/out.txt".into(),
        output_path: "dist/out.txt".into(),
        egress: EgressTier::DenyAll,
        privileged: false,
        extra_hosts: Default::default(),
    });
    let run_id = "retained";
    let mut o = opts(run_id);
    o.retain = true;
    let h = r.start(&plan, &o).await.unwrap();
    assert!(h.wait().await.unwrap().succeeded());

    let tag = format!("trigon-build:{run_id}");
    assert!(image_exists(&tag), "retain must keep the image");
    let _ = std::process::Command::new("podman")
        .args(["rmi", "--force", &tag])
        .status();
}

fn image_exists(tag: &str) -> bool {
    std::process::Command::new("podman")
        .args(["image", "exists", tag])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn a_build_prunes_leftovers_from_runs_that_were_killed() {
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    // `Leftovers` covers every path a process returns by; it cannot cover one that does not return.
    // A wall-clock timeout or a fatal signal skips Drop, and three contexts and three 600 MB images
    // were found sitting here from runs a SIGPIPE bug had killed.
    //
    // Pid 1 is alive, so its context must survive: a prune that disturbed a concurrent run would be
    // worse than the leak.
    let dead = std::env::temp_dir().join("trigon-ctx-deadbeef1234-4294967290");
    let live = std::env::temp_dir().join("trigon-ctx-deadbeef1234-1");
    for d in [&dead, &live] {
        std::fs::create_dir_all(d).unwrap();
        // Backdated past the age floor, which exists because process ids get reused.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let _ = filetime_set(d, old);
    }

    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "true".into(),
        build: "mkdir -p dist && echo hi > dist/out.txt".into(),
        output_path: "dist/out.txt".into(),
        egress: EgressTier::DenyAll,
        privileged: false,
        extra_hosts: Default::default(),
    });
    let h = r.start(&plan, &opts("prunes")).await.unwrap();
    let _ = h.wait().await.unwrap();

    assert!(
        !dead.exists(),
        "a context whose process is gone should have been removed"
    );
    assert!(
        live.exists(),
        "a context whose process is alive must be left alone"
    );
    let _ = std::fs::remove_dir_all(&live);
}

/// Backdate a directory so the age floor does not protect it.
fn filetime_set(path: &Path, when: std::time::SystemTime) -> std::io::Result<()> {
    let secs = when
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .as_secs();
    let status = std::process::Command::new("touch")
        .args(["-d", &format!("@{secs}")])
        .arg(path)
        .status()?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| std::io::Error::other("touch failed"))
}
