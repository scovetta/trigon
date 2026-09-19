//! A real container build.
//!
//! Skipped when podman is unavailable or the pinned base image is not in the local store, so the
//! suite still runs in an environment without either. The image is pinned by digest because the
//! runner refuses anything else, which is exactly the property under test.

use std::collections::BTreeSet;
use std::path::Path;

use trigon_sandbox::{
    BuildEvent, BuildPlan, BuildRunner, EgressTier, Limits, OciPlan, Phase, PodmanRunner, RunOpts,
};

const ALPINE: &str = "docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";

/// Serialize every case that touches the container store.
///
/// These tests share one machine-global resource: podman's local image store. Running two builds
/// against it at once is not a thing the suite is testing, and it is a thing podman is unhappy
/// about — a build reusing cached layers while a sibling's image is removed fails with
/// `getting top layer info: layer not known`, and the case that reports it is whichever one
/// happened to be building.
///
/// The product's own guards against this live in `prune_stale_leftovers` and `Leftovers::drop`:
/// an age floor, a dead-process check, and no `--force`. They narrow the window and do not close
/// it, because one process cannot see another's builds. That is recorded in `docs/17-backlog.md`;
/// here, the answer is to stop racing.
async fn store() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// A skip the caller was supposed to have prevented.
///
/// Every gate below is a thing *the environment* controls — podman is installed or it is not, the
/// image was pulled or it was not, `TRIGON_LIVE` was set or it was not. A gate like that reports
/// `ok` when it declines to run, so a CI job that forgets one of them is green and says nothing,
/// which is how thirteen container tests came to skip on every pull request for the life of the
/// repository.
///
/// `TRIGON_TESTS_MUST_RUN=1` is the job asserting it did its setup: under it a gate of this kind
/// is a failure, not a skip. Conditions the job does *not* control — an upstream host being
/// unreachable — stay skips, and say so where they are written.
#[track_caller]
fn refuse_to_skip(why: &str) {
    if std::env::var("TRIGON_TESTS_MUST_RUN").as_deref() == Ok("1") {
        panic!("TRIGON_TESTS_MUST_RUN=1 but this test skipped: {why}");
    }
    eprintln!("skipped: {why}");
}

async fn usable(r: &PodmanRunner) -> bool {
    if r.health().await.is_err() {
        refuse_to_skip("podman is not available");
        return false;
    }
    let out = std::process::Command::new("podman")
        .args(["image", "exists", ALPINE])
        .status();
    match out {
        Ok(s) if s.success() => true,
        _ => {
            refuse_to_skip(&format!("{ALPINE} is not in the local image store"));
            false
        }
    }
}

fn opts(run_id: &str) -> RunOpts {
    RunOpts {
        // Unique per process so two runs of the suite do not share an image tag — `no_cache`
        // below is what actually forces the phases to execute, and this keeps their *names* from
        // colliding while they do.
        run_id: format!("{run_id}-{}", std::process::id()),
        limits: Limits {
            wall_clock: std::time::Duration::from_secs(180),
            ..Default::default()
        },
        retain: false,
        mirror_port: 8129,
        guard: None,
        cache: None,
        on_event: None,
        // **Every test in this file asserts about what a build did**, and a cached layer means it
        // did nothing: the probe that proves a phase could not reach the internet is satisfied by a
        // phase that never ran, and its silence proves nothing. The egress test says exactly that
        // and fails rather than passing on it.
        //
        // A unique run id was the first attempt and fixed the wrong layer — the tag differs, and
        // podman caches by content regardless. Only this actually rebuilds.
        no_cache: true,
    }
}

fn workdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join("trigon-sandbox-tests");
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test]
async fn a_build_runs_and_its_artifact_is_collected() {
    let _store = store().await;
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
        source_tree: None,
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
    // `deny-all` accounts for egress completely without a proxy: `--network none` on both the image
    // build and the run means the build has no interface, so "nothing crossed" is enforced by the
    // kernel rather than observed. An *empty* account, not an absent one — flattening the two is
    // how "we never looked" comes to read as "we looked and it was clean".
    assert_eq!(outcome.transcript.as_deref(), Some(&[][..]));
    assert!(
        outcome.attestable,
        "a run that reached nothing can say so, and that is the whole claim"
    );
    assert!(outcome.failed_in.is_none());

    // Timings are per phase and present, not zeroed.
    let phases: Vec<Phase> = outcome.timings.iter().map(|(p, _)| *p).collect();
    assert_eq!(phases, vec![Phase::Deps, Phase::Build]);
    assert!(outcome.timings.iter().all(|(_, d)| d.is_some()));
}

#[tokio::test]
async fn deny_all_egress_really_denies() {
    let _store = store().await;
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
        source_tree: None,
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
    let _store = store().await;
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
        source_tree: None,
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
    let _store = store().await;
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
        source_tree: None,
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
        refuse_to_skip(&format!("build {MIRROR_IMAGE} with `trigon mirror-image`"));
    }
    ok
}

#[tokio::test]
async fn mirror_only_egress_blocks_everything_but_the_mirror() {
    let _store = store().await;
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
        source_tree: None,
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
    // The boundary holds *and* the run can now say what went through it. The mirror hashed every
    // body it served all along — that is how the artifact guard works — and threw all of it away
    // unless the hash matched; the transcript is those discarded observations, read back out of the
    // container log the same way a guard trip is.
    let transcript = outcome
        .transcript
        .as_ref()
        .expect("mirror-only accounts for egress completely");
    assert!(
        outcome.attestable,
        "a boundary that holds and is observed is exactly what `attestable` means"
    );
    // The probes are refused rather than served, so nothing should be listed. What is under test is
    // that the list exists and is the complete account: an empty transcript here says the mirror
    // served nothing, which is a claim, and it is checkable against the probe output above.
    assert!(
        transcript
            .iter()
            .all(|e| ["index", "artifact", "toolchain", "passthrough"].contains(&e.route.as_str())),
        "every entry names one of the three routes: {transcript:?}"
    );
}

#[tokio::test]
async fn a_mirror_only_build_transcribes_what_it_fetched() {
    let _store = store().await;
    let r = PodmanRunner::new(workdir()).with_mirror_image(Some(MIRROR_IMAGE.into()));
    if !usable(&r).await || !mirror_image_available() {
        return;
    }

    // The test above proves the boundary holds. This one proves we can say what went through it,
    // which is the other half and the one that was missing: an enforced tier whose traffic nobody
    // records answers "did the build fetch something it should not have?" with a shrug.
    //
    // The toolchain route, because it needs no registry pin and names an exact file — so the digest
    // in the transcript is checkable against the same URL fetched any other way.
    let url = "http://mirror:8129/-toolchain/nodejs.org/dist/v20.11.0/SHASUMS256.txt";
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        // At run time, not image-build time: the image build has no network at any enforced tier,
        // and the island is where the mirror is reachable.
        deps: "true".into(),
        build: format!("wget -q -O /tmp/sums {url} && echo fetched-ok"),
        output_path: ".".into(),
        egress: EgressTier::MirrorOnly,
        privileged: false,
        extra_hosts: [("mirror".to_string(), "mirror".to_string())]
            .into_iter()
            .collect(),
        source_tree: None,
    });

    let h = r.start(&plan, &opts("transcribed")).await.expect("starts");
    let outcome = h.wait().await.expect("completes");
    if !outcome.log_tail.contains("fetched-ok") {
        // Upstream is not ours to depend on. A skip that says why beats a red suite that means
        // nothing, and the assertion below would otherwise pass vacuously on an empty transcript.
        eprintln!(
            "skipped: nodejs.org was not reachable through the mirror:\n{}",
            outcome.log_tail
        );
        return;
    }

    let transcript = outcome.transcript.expect("mirror-only records one");
    let fetched = transcript
        .iter()
        .find(|e| e.url.contains("SHASUMS256.txt"))
        .unwrap_or_else(|| panic!("the fetch is not in the transcript: {transcript:?}"));
    assert_eq!(
        fetched.route, "toolchain",
        "the route is a claim of its own: a toolchain is the one thing a build fetches that then runs"
    );
    assert_eq!(fetched.sha256.len(), 64, "{fetched:?}");
    assert!(fetched.bytes > 0, "{fetched:?}");
    assert!(outcome.attestable);
}

#[tokio::test]
async fn the_same_probes_succeed_under_open_egress() {
    let _store = store().await;
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
        source_tree: None,
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
    let _store = store().await;
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
        source_tree: None,
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
    let _store = store().await;
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
        source_tree: None,
    });
    let mut o = opts("retained");
    o.retain = true;
    let h = r.start(&plan, &o).await.unwrap();
    assert!(h.wait().await.unwrap().succeeded());

    // From the run id the runner was actually given, not from the string handed to `opts` — those
    // stopped being the same thing when run ids became unique per process, and a test that rebuilds
    // a tag by its own arithmetic is a second implementation of the runner's naming.
    let tag = format!("trigon-build:{}", o.run_id);
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
    let _store = store().await;
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
        source_tree: None,
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

#[tokio::test]
async fn a_watcher_is_told_which_phase_is_running_while_it_runs() {
    // `events()` is a snapshot: the whole history once the build is over, and nothing at all while
    // it is the thing you want to watch. A page that says "on left-pad for 40s" and cannot say
    // which phase is a page that cannot tell a slow dependency install from a hung build.
    let _store = store().await;
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let seen = seen.clone();
        std::sync::Arc::new(move |e: &BuildEvent| {
            if let BuildEvent::PhaseStart(p) = e {
                seen.lock().unwrap().push(*p);
            }
        })
    };

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
        source_tree: None,
    });
    let mut o = opts("phases");
    o.on_event = Some(sink);
    let h = r.start(&plan, &o).await.unwrap();
    let outcome = h.wait().await.unwrap();
    assert_eq!(outcome.exit_code, 0);

    // Told as they happened, in order, and not only at the end.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen, vec![Phase::Deps, Phase::Build], "{seen:?}");
}

#[tokio::test]
async fn no_phase_of_an_enforced_run_reaches_the_internet() {
    // The test `mirror_only_egress_blocks_everything_but_the_mirror` is the one that let B7 exist:
    // it puts `source: "true"`, `deps: "true"` and every probe inside `build:`, and the build phase
    // was the one phase already inside the boundary. Setup and source are image-build layers, and
    // rootless `podman build` cannot join the island — so with no network flag at all they had
    // ordinary networking at every tier but `deny-all`. This one probes every phase.
    let _store = store().await;
    let r = PodmanRunner::new(workdir()).with_mirror_image(Some(MIRROR_IMAGE.into()));
    if !usable(&r).await || !mirror_image_available() {
        return;
    }

    // `|| echo blocked` rather than `&& echo REACHED` alone: under `set -eu` a bare failing
    // AND-list exits the phase, so the absence of REACHED would be satisfied by a phase that never
    // ran. Both halves are asserted.
    let probe =
        |tag: &str| format!("nc -w 3 -z 1.1.1.1 443 && echo REACHED-{tag} || echo blocked-{tag}\n");
    let plan = BuildPlan::Oci(OciPlan {
        base_image: ALPINE.into(),
        // Empty on purpose: an enforced tier refuses a plan that needs packages, because with no
        // network in the image build there is nothing to install them with.
        system_deps: BTreeSet::new(),
        source: probe("SOURCE"),
        deps: probe("DEPS"),
        build: format!("{}mkdir -p dist && echo hi > dist/out.txt", probe("BUILD")),
        output_path: "dist/out.txt".into(),
        egress: EgressTier::MirrorOnly,
        privileged: false,
        extra_hosts: Default::default(),
        source_tree: None,
    });

    let h = r.start(&plan, &opts("allphases")).await.unwrap();
    let outcome = h.wait().await.unwrap();
    let log = &outcome.log_tail;

    assert!(
        !log.contains("REACHED-"),
        "a phase reached the internet at mirror-only:\n{log}"
    );
    for tag in ["SOURCE", "DEPS", "BUILD"] {
        assert!(
            log.contains(&format!("blocked-{tag}")),
            "the {tag} phase did not run, so its silence proves nothing:\n{log}"
        );
    }
}

#[tokio::test]
async fn an_enforced_tier_verifies_its_base_image_instead_of_installing() {
    // The image build has no network at an enforced tier — that is what makes the tier mean what
    // it says — so the setup phase cannot install. It checks instead, from the package manager's
    // own on-disk database, and names what is missing.
    //
    // The first design refused the run before it started. That was wrong for a reason worth
    // keeping: a pre-flight refusal cannot know what a base image contains, so it refuses every
    // strategy that declares a package even when the image carries all of them. The check knows.
    let _store = store().await;
    let r = PodmanRunner::new(workdir());
    if !usable(&r).await {
        return;
    }
    let plan = |egress| {
        BuildPlan::Oci(OciPlan {
            base_image: ALPINE.into(),
            // Alpine has `busybox` and does not have `libatomic`, so one of each.
            system_deps: ["busybox", "libatomic"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            source: "true".into(),
            deps: "true".into(),
            build: "mkdir -p dist && echo hi > dist/out.txt".into(),
            output_path: "dist/out.txt".into(),
            egress,
            privileged: false,
            extra_hosts: Default::default(),
            source_tree: None,
        })
    };

    let h = r
        .start(&plan(EgressTier::DenyAll), &opts("verify"))
        .await
        .unwrap();
    let outcome = h.wait().await.unwrap();
    assert_ne!(
        outcome.exit_code, 0,
        "a missing package must stop the build"
    );
    let log = &outcome.log_tail;
    assert!(log.contains("this base image is missing"), "{log}");
    assert!(log.contains("libatomic"), "the missing one is named: {log}");
    assert!(
        log.contains("trigon base-image"),
        "and the way to fix it is printed: {log}"
    );
    assert!(
        !log.contains("busybox"),
        "a package that is present must not be reported missing: {log}"
    );
}

/// The third leg of `docs/12-security.md` row 6, which that table already claims is covered.
///
/// The row reads: *"The build worker cannot reach the upstream artifact — Three integration tests:
/// the mirror refuses its URL, an egress fetch of it voids the run, **a blob-store read from
/// inside the sandbox is denied**"*, and is marked **yes**. The first two exist
/// (`trigon-mirror/tests/server.rs::the_mirror_refuses_the_runs_own_artifact` and the
/// `seam_*_fail_closed` suites). The third did not.
///
/// It matters more than it looks. §12.6 is about the hole the other two do not cover:
///
/// ```text
/// GET <cas>/blobs/sha256/<upstream_digest>   →   cp to the output path
/// ```
///
/// That request never goes to a registry, so the mirror never sees it and the egress guard never
/// hashes it. A build that can reach the blob store can read the artifact it is supposed to be
/// reproducing, out of our own storage, and reproduce it perfectly past every clean re-run.
///
/// The control is structural rather than configured: at `mirror-only` the build's only interface
/// is a podman `--internal` network whose sole route out is the mirror container, so a host-side
/// service has no route to it at all. This asserts that, against a real listener on this machine
/// standing in for the blob store.
///
/// **Paired with the open-egress case on purpose.** A probe that cannot reach anything proves
/// nothing about the boundary, so the same listener, on the same address, must be reached when the
/// tier permits it. Asserted on the host side — a connection really arrived — rather than on the
/// probe's own exit code.
#[tokio::test]
async fn a_blob_store_read_from_inside_the_sandbox_is_denied() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let _store = store().await;
    let r = PodmanRunner::new(workdir()).with_mirror_image(Some(MIRROR_IMAGE.into()));
    if !usable(&r).await || !mirror_image_available() {
        return;
    }

    // The address a container on an ordinary network can reach this machine on. Found by asking
    // the routing table which local address it would use to leave, rather than guessing at
    // podman's gateway, which differs between rootless and rootful.
    let Some(host_ip) = ({
        std::net::UdpSocket::bind("0.0.0.0:0")
            .ok()
            .and_then(|s| s.connect("1.1.1.1:80").ok().map(|()| s))
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.ip().to_string())
    }) else {
        refuse_to_skip("this machine has no outbound route, so there is no address to probe");
        return;
    };

    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind a stand-in blob store");
    let port = listener.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stream.is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    // By IP and port, so a blocked resolver is not mistaken for a blocked route — the same
    // reasoning as `mirror_only_egress_blocks_everything_but_the_mirror`.
    let probe = format!(
        "nc -w 3 -z {host_ip} {port} && echo REACHED-BLOBSTORE\n\
         echo probe-finished\n"
    );

    let plan = |egress| {
        BuildPlan::Oci(OciPlan {
            base_image: ALPINE.into(),
            system_deps: BTreeSet::new(),
            source: "true".into(),
            deps: "true".into(),
            build: probe.clone(),
            output_path: ".".into(),
            egress,
            privileged: false,
            extra_hosts: Default::default(),
            source_tree: None,
        })
    };

    // 1. The control. Same listener, same address, a tier that permits it.
    let open = r
        .start(&plan(EgressTier::Open), &opts("blobstore-open"))
        .await
        .expect("starts")
        .wait()
        .await
        .expect("completes");
    assert!(
        open.log_tail.contains("probe-finished"),
        "the probe did not run under open egress, so it proves nothing below:\n{}",
        open.log_tail
    );
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "nothing reached the stand-in blob store at {host_ip}:{port} even under open egress. The \
         probe is broken, not the boundary — this test would otherwise pass for the wrong reason."
    );

    let reached_when_allowed = hits.load(Ordering::SeqCst);

    // 2. The boundary.
    let closed = r
        .start(&plan(EgressTier::MirrorOnly), &opts("blobstore-denied"))
        .await
        .expect("starts")
        .wait()
        .await
        .expect("completes");

    assert!(
        !closed.log_tail.contains("REACHED-BLOBSTORE"),
        "the build reached a host-side blob store under mirror-only egress. That request never \
         goes to a registry, so the mirror never sees it and the artifact guard never hashes \
         it:\n{}",
        closed.log_tail
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        reached_when_allowed,
        "a connection arrived at the stand-in blob store while the build was at mirror-only"
    );
    assert!(
        closed.log_tail.contains("probe-finished") || !closed.succeeded(),
        "the probe should have run and failed, not been skipped:\n{}",
        closed.log_tail
    );
}
