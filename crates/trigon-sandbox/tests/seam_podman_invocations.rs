//! What the runner asks of the container runtime, and what it makes of the answers.
//!
//! `tests/podman.rs` runs real containers and skips wherever podman or its pinned image is missing,
//! which is every CI job that has not set them up. So the flags that *are* the egress policy — the
//! `--network none` on an image build at `deny-all`, the island the build runs on at
//! `mirror-only`, the capabilities it is denied — and the reading of the mirror's log that decides
//! whether a run can be attested, were covered only where a container runtime happened to be.
//!
//! None of that needs a container. The runner and the island take the runtime as a path, so every
//! test here hands them a stand-in: a shell script that writes down each invocation and answers
//! from files its test put beside it. What is asserted is the conversation — which arguments went
//! out, and what the runner concluded from what came back — which is the half of the boundary this
//! crate owns. Whether podman then enforces those flags is `tests/podman.rs`'s question.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use trigon_core::{Classify, Fault};
use trigon_mirror::{Asked, Checked, Exchange, GuardMatch, Observed, Refusal, Throttled, Trip};
use trigon_sandbox::{
    BuildEvent, BuildOutcome, BuildPlan, BuildRunner, DEPS_DONE, EgressTier, Island,
    IsolationClass, OciPlan, Phase, PodmanRunner, RunOpts, SandboxError,
};

// ---------------------------------------------------------------------------------------------
// The egress tiers, as flags.
// ---------------------------------------------------------------------------------------------

/// At `deny-all` neither the image build nor the run has a network, and the run is accounted for.
///
/// The image build had no network flag at all once, so every phase rendered as a layer ran with
/// ordinary rootless networking whatever tier was asked for — a `src:` step could fetch the
/// published artifact on a run recorded as enforced. `--network none` on both is what makes
/// "nothing crossed" something the kernel enforces rather than something a proxy observed, which is
/// why the account is complete, and empty, with no mirror at all.
#[tokio::test]
async fn deny_all_gives_the_image_build_and_the_run_no_network_and_an_empty_complete_account() {
    let fake = Fake::new("deny-all");
    fake.set(
        "build.out",
        "STEP 1/7: FROM alpine\n/trigon/setup.sh\n/trigon/deps.sh\n",
    )
    .set("run.out", "compiling\n")
    .set("run.err", "a warning on stderr\n")
    .set("artifacts", "demo-1.0.0.tgz\n");
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut opts = opts("deny-all");
    let sink = events.clone();
    opts.on_event = Some(Arc::new(move |e: &BuildEvent| {
        sink.lock().unwrap().push(e.clone())
    }));

    let out = run(&fake.runner(), plan(EgressTier::DenyAll), &opts)
        .await
        .expect("the build ran");

    let build = fake.one("build");
    assert!(build.contains("--network none"), "{build}");
    assert!(
        build.contains(&format!("--tag trigon-build:{}", opts.run_id)),
        "{build}"
    );
    let run = fake.one("run --rm");
    for flag in [
        "--network none",
        "--cap-drop all",
        "--security-opt no-new-privileges",
        "--cpus 2",
        "--memory 4g",
        "--pids-limit 2048",
    ] {
        assert!(run.contains(flag), "the build ran without `{flag}`: {run}");
    }
    let out_dir = std::fs::canonicalize(fake.work().join(&opts.run_id)).unwrap();
    assert!(
        run.ends_with(&format!(
            "--volume {}:/out:Z trigon-build:{}",
            out_dir.display(),
            opts.run_id
        )),
        "{run}"
    );

    assert!(out.succeeded());
    assert_eq!(out.artifact, Some(out_dir.join("demo-1.0.0.tgz")));
    assert_eq!(out.egress, EgressTier::DenyAll);
    assert_eq!(out.isolation, IsolationClass::UserNs);
    assert_eq!(
        out.transcript,
        Some(vec![]),
        "no interface is a complete account"
    );
    assert!(out.attestable);
    assert_eq!(
        out.pin, None,
        "no mirror ran, so there is no pin evidence to derive"
    );
    assert_eq!(out.failed_in, None);
    let phases: Vec<Phase> = out.timings.iter().map(|(p, _)| *p).collect();
    assert_eq!(phases, [Phase::Deps, Phase::Build]);
    assert!(out.timings.iter().all(|(_, d)| d.is_some()));
    // Both streams reach the log a person and a classifier read.
    assert!(out.log_tail.contains("compiling"), "{}", out.log_tail);
    assert!(
        out.log_tail.contains("a warning on stderr"),
        "{}",
        out.log_tail
    );

    let events = events.lock().unwrap().clone();
    assert_eq!(events.first(), Some(&BuildEvent::PhaseStart(Phase::Deps)));
    assert_eq!(events.last(), Some(&BuildEvent::Exit(0)));
    assert!(events.contains(&BuildEvent::Stdout("compiling".into())));
    assert!(events.contains(&BuildEvent::Stderr("a warning on stderr".into())));
    let started_build = events
        .iter()
        .position(|e| *e == BuildEvent::PhaseStart(Phase::Build))
        .expect("the build phase was announced");
    let ended_deps = events
        .iter()
        .position(|e| {
            matches!(
                e,
                BuildEvent::PhaseEnd {
                    phase: Phase::Deps,
                    ..
                }
            )
        })
        .expect("the image build's phase ended");
    assert!(ended_deps < started_build, "{events:?}");

    assert!(
        !std::env::temp_dir()
            .join(format!("trigon-ctx-{}", opts.run_id))
            .exists(),
        "the build context outlived the run"
    );
}

/// At `open` there is no boundary, so no flag and no account.
#[tokio::test]
async fn open_egress_passes_no_network_flag_and_is_never_attestable() {
    let fake = Fake::new("open");
    fake.set("build.out", "/trigon/deps.sh\n")
        .set("artifacts", "demo-1.0.0.tgz\n");
    let out = run(&fake.runner(), plan(EgressTier::Open), &opts("open"))
        .await
        .expect("the build ran");

    assert!(!fake.one("build").contains("--network"));
    assert!(!fake.one("run --rm").contains("--network"));
    // Still no capabilities: the tier is about the network, not about what the build may do.
    assert!(fake.one("run --rm").contains("--cap-drop all"));
    assert_eq!(out.transcript, None);
    assert!(
        !out.attestable,
        "a build that could reach anything is not accounted for"
    );
}

/// At `mirror-only` the build runs on an island whose only other member is the mirror, and what
/// crossed is read out of the mirror's own log — both streams, in one read.
///
/// The mirror sits inside the island and the host has no route to it, so its log is the only way
/// its account gets out. The trip line goes to stderr here on purpose: the reader once took stdout
/// only while the trip went to stderr, and the most important control in the system reported
/// nothing on the only tier that enforces it.
#[tokio::test]
async fn mirror_only_runs_the_build_on_the_island_and_takes_its_account_from_the_mirror_log() {
    let fake = Fake::new("mirror-only");
    let o = opts("mirror-only");
    let net = format!("trigon-{}", o.run_id);
    let (exchange, trip, refusal, asked, throttled) = mirror_records();
    let refused = format!(
        "{} https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
        trigon_mirror::REFUSED_ARTIFACT_MARKER
    );
    fake.set("logs.1.out", "time-filtering mirror listening\n")
        .set(
            "logs.2.out",
            &[
                "time-filtering mirror listening",
                &exchange.line(),
                &refusal.line(),
                &asked.line(),
                &throttled.line(),
                &refused,
                "",
            ]
            .join("\n"),
        )
        .set("logs.2.err", &format!("{}\n", trip.line()))
        .set("ip.out", "10.89.0.7\n")
        .set("build.out", "/trigon/setup.sh\n/trigon/source.sh\n")
        .set(
            "run.out",
            &format!("/trigon/deps.sh\n{DEPS_DONE}\nbuilding\n"),
        )
        .set("artifacts", "demo-1.0.0.tgz\n");
    let guard = fake.dir.join("guard.json");
    std::fs::write(&guard, "{}").unwrap();
    let cache = fake.dir.join("cache");
    let opts = RunOpts {
        guard: Some(guard.clone()),
        cache: Some((cache.clone(), "sweep-1".into())),
        ..o
    };
    let mut p = plan(EgressTier::MirrorOnly);
    p.extra_hosts = BTreeMap::from([("timewarp".to_string(), "mirror".to_string())]);

    let out = run(&fake.mirrored(), p, &opts)
        .await
        .expect("the build ran");

    assert!(fake.has(&format!("network create --internal {net}")));
    let mirror = fake.one("run --detach");
    let guard = std::fs::canonicalize(&guard).unwrap();
    let cache = std::fs::canonicalize(&cache).expect("the cache directory was made for podman");
    assert!(
        mirror.starts_with(&format!("run --detach --name {net}-mirror ")),
        "{mirror}"
    );
    assert_eq!(
        flag_values(&mirror, "--network"),
        [net.as_str(), "podman"],
        "the mirror is on the island and the default network, and nothing else is: {mirror}"
    );
    // The mounts by what they are, not by how they are spelled: the SELinux label on the shared
    // cache is an open question (`docs/17-backlog.md`), and nothing here is about it.
    let volumes: Vec<Vec<&str>> = flag_values(&mirror, "--volume")
        .into_iter()
        .map(|v| v.splitn(3, ':').collect())
        .collect();
    assert_eq!(volumes.len(), 2, "{mirror}");
    let guard_src = guard.display().to_string();
    assert_eq!(
        volumes[0][..2],
        [guard_src.as_str(), "/guard.json"],
        "{mirror}"
    );
    assert!(
        volumes[0]
            .get(2)
            .is_some_and(|o| o.split(',').any(|o| o == "ro")),
        "the mirror has no business writing to the manifest it enforces: {mirror}"
    );
    let cache_src = cache.display().to_string();
    assert_eq!(volumes[1][..2], [cache_src.as_str(), "/cache"], "{mirror}");
    assert!(
        mirror.ends_with(
            " localhost/trigon-mirror:latest mirror --port 8129 --guard /guard.json --cache /cache \
             --cache-scope sweep-1"
        ),
        "{mirror}"
    );
    // The image build has no network even here — rootless `podman build` cannot join the island —
    // and the name the strategy uses for the mirror is mapped to its address on the island.
    let build = fake.one("build");
    assert!(build.contains("--network none"), "{build}");
    assert!(build.contains("--add-host timewarp:10.89.0.7"), "{build}");
    let run = fake.one("run --rm");
    assert!(run.contains(&format!("--network {net} ")), "{run}");
    assert!(!run.contains("--network none"), "{run}");
    assert!(run.contains("--add-host timewarp:10.89.0.7"), "{run}");
    // And the island is gone afterwards.
    for teardown in [
        format!("stop --time 2 {net}-mirror"),
        format!("rm --force {net}-mirror"),
        format!("network rm --force {net}"),
    ] {
        assert!(
            fake.has(&teardown),
            "`{teardown}` never ran: {:?}",
            fake.calls()
        );
    }

    assert!(out.succeeded());
    assert_eq!(
        out.failed_in, None,
        "the deps marker was printed, so deps finished"
    );
    assert_eq!(out.transcript, Some(vec![exchange.clone()]));
    assert!(out.attestable);
    assert_eq!(out.guard_arrived, vec![trip]);
    assert_eq!(out.refused_artifact, vec![refused]);
    assert_eq!(out.throttled, vec![throttled]);
    assert_eq!(out.asked, vec![asked]);
    assert_eq!(
        out.pin,
        Some(Observed::from_transcript(&[exchange], 1)),
        "the pin evidence is derived from the rows the log carried"
    );
}

/// A mirror log line that cannot be read fails the run, and the island is still torn down.
///
/// "We could not tell" and "nothing happened" are different answers, and only one leaves the run
/// evidence of anything. Each record type has its own line, and a torn one of any of them is an
/// error naming what is now unknown — never an empty list that reads as a clean run.
#[tokio::test]
async fn an_unreadable_mirror_log_line_fails_the_run_and_still_tears_the_island_down() {
    for (marker, unknown) in [
        (
            trigon_mirror::TRIP_MARKER,
            "reached the build is unknown rather than no",
        ),
        (
            trigon_mirror::EXCHANGE_MARKER,
            "what the build downloaded is unknown rather than empty",
        ),
        (
            trigon_mirror::ASKED_MARKER,
            "is unknown rather than nothing",
        ),
        (
            trigon_mirror::THROTTLE_MARKER,
            "rate limited us is unknown rather than no",
        ),
        (
            trigon_mirror::REFUSAL_MARKER,
            "turned away is unknown rather than no",
        ),
    ] {
        let fake = Fake::new(&format!("torn-{}", marker.to_ascii_lowercase()));
        let opts = opts(&format!("torn-{}", marker.to_ascii_lowercase()));
        fake.set("logs.1.out", "listening\n")
            .set(
                "logs.2.out",
                &format!("listening\n{marker} {{\"url\": \"https://x/y\n"),
            )
            .set("ip.out", "10.89.0.7\n")
            .set("build.out", "/trigon/setup.sh\n");

        let e = run(&fake.mirrored(), plan(EgressTier::MirrorOnly), &opts)
            .await
            .expect_err("a torn record is not an empty one");
        assert!(
            matches!(
                &e,
                SandboxError::Failed { phase, detail }
                    if phase == "build" && detail.contains(unknown)
            ),
            "{marker}: {e}"
        );
        assert!(
            fake.has(&format!("network rm --force trigon-{}", opts.run_id)),
            "{marker}: a failed read left the island behind"
        );
    }
}

/// A mirror log that cannot be read at all is an error, not an empty account.
#[tokio::test]
async fn a_mirror_log_that_cannot_be_read_is_an_error_rather_than_an_empty_account() {
    let fake = Fake::new("logs-gone");
    let opts = opts("logs-gone");
    fake.set("logs.1.out", "listening\n")
        .set("logs.2.code", "125")
        .set("logs.2.err", "Error: no container with name or ID found\n")
        .set("ip.out", "10.89.0.7\n")
        .set("build.out", "/trigon/setup.sh\n");

    let e = run(&fake.mirrored(), plan(EgressTier::MirrorOnly), &opts)
        .await
        .expect_err("an unreadable log is not a quiet one");
    assert!(
        matches!(&e, SandboxError::Failed { phase, detail }
            if phase == "collect" && detail.contains("no container with name or ID found")),
        "{e}"
    );
    assert_eq!(e.fault(), Fault::Infra);
    assert!(fake.has(&format!("network rm --force trigon-{}", opts.run_id)));
}

/// An image build that fails at an enforced tier still reads the mirror, and still tears it down.
///
/// The image build has no network at any enforced tier, so the honest answer is the mirror's
/// account — here, one it served nothing into — rather than no account at all.
#[tokio::test]
async fn a_failed_image_build_at_mirror_only_is_still_accounted_for_and_torn_down() {
    let fake = Fake::new("mirror-build-fails");
    let opts = opts("mirror-build-fails");
    fake.set("logs.1.out", "listening\n")
        .set("logs.2.out", "listening\n")
        .set("ip.out", "10.89.0.7\n")
        .set(
            "build.out",
            "/trigon/setup.sh\nE: Unable to locate package libfoo-dev\n",
        )
        .set("build.code", "100");

    let out = run(&fake.mirrored(), plan(EgressTier::MirrorOnly), &opts)
        .await
        .expect("a phase of the package's ran, so this is an outcome");
    assert_eq!((out.exit_code, out.failed_in), (100, Some(Phase::Setup)));
    assert_eq!(out.transcript, Some(vec![]));
    assert_eq!(out.pin, Some(Observed::default()));
    assert!(
        fake.calls().iter().all(|c| !c.starts_with("run --rm")),
        "the build ran anyway"
    );
    assert!(fake.has(&format!("network rm --force trigon-{}", opts.run_id)));
}

// ---------------------------------------------------------------------------------------------
// The island on its own.
// ---------------------------------------------------------------------------------------------

/// A mirror that dies at startup is reported with what it said, not waited on until a timeout.
///
/// `podman run --detach` returns when the container starts, not when the process in it listens,
/// and a container that already exited will never listen. Polling on is how a crash at startup
/// came to be reported as a thirty-second timeout, which sent an afternoon looking at the wrong
/// thing.
#[tokio::test]
async fn a_mirror_that_exits_at_startup_is_reported_with_what_it_said() {
    let fake = Fake::new("mirror-exits");
    fake.set(
        "logs.out",
        "trigon 0.0.0\nerror: unexpected argument '--cache-scope' found\n\nUsage: trigon mirror\n",
    )
    .set("state.out", "exited\n");

    let e = no_island(island(&fake, "mirror-exits").await, "it never listened");
    let SandboxError::Failed { phase, detail } = &e else {
        panic!("{e:?}")
    };
    assert_eq!(phase, "setup");
    assert!(
        detail.starts_with("the mirror container is exited: "),
        "{detail}"
    );
    assert!(
        detail.contains("unexpected argument '--cache-scope' found / Usage: trigon mirror"),
        "the tail of what it said, one line per line: {detail}"
    );
    assert_eq!(e.fault(), Fault::Infra, "ours, never the package's");
}

/// A mirror container that disappears before listening says how that happens.
#[tokio::test]
async fn a_mirror_container_that_disappears_before_listening_says_how_that_happens() {
    let fake = Fake::new("mirror-gone");
    fake.set("logs.out", "")
        .set("state.code", "125")
        .set("state.err", "Error: no such container\n");

    let e = no_island(island(&fake, "mirror-gone").await, "it never listened");
    let detail = e.to_string();
    assert!(
        detail.contains("disappeared before it started listening"),
        "{detail}"
    );
    assert!(
        detail.contains("rebuild it with `trigon mirror-image`"),
        "{detail}"
    );
}

/// A mirror container that will not start names the image and how to build one.
#[tokio::test]
async fn a_mirror_container_that_will_not_start_names_the_image_and_how_to_build_one() {
    let fake = Fake::new("mirror-no-image");
    fake.set("detach.code", "125").set(
        "detach.err",
        "Error: localhost/trigon-mirror:latest: image not known\n",
    );

    let e = no_island(island(&fake, "mirror-no-image").await, "nothing started");
    let detail = e.to_string();
    assert!(
        detail
            .contains("could not start the mirror container from `localhost/trigon-mirror:latest`"),
        "{detail}"
    );
    assert!(
        detail.contains("image not known"),
        "podman's own reason: {detail}"
    );
    assert!(detail.contains("trigon mirror-image"), "{detail}");
}

/// The island names its mirror by a stable host and finds its address by network name.
///
/// An address rather than the container name for the image build, because `podman build` does not
/// join podman's DNS the way `podman run` does. The network name contains dashes, which a Go
/// template reads as subtraction under dot access, so it is looked up with `index` — and an empty
/// answer is no address rather than an empty one.
#[tokio::test]
async fn the_mirror_is_found_by_network_name_and_an_empty_answer_is_no_address() {
    let fake = Fake::new("mirror-ip");
    fake.set("logs.out", "listening\n")
        .set("ip.out", "10.89.0.9\n");
    let run_id = format!("mirror-ip-{}", std::process::id());
    let i = island(&fake, "mirror-ip").await.expect("it listened");

    assert_eq!(i.network(), format!("trigon-{run_id}"));
    assert_eq!(i.mirror_host, Some(format!("trigon-{run_id}-mirror:8129")));
    assert_eq!(i.mirror_ip().await.as_deref(), Some("10.89.0.9"));
    assert!(
        fake.has(&format!(
            "inspect --format \
             {{{{(index .NetworkSettings.Networks \"trigon-{run_id}\").IPAddress}}}} \
             trigon-{run_id}-mirror"
        )),
        "{:?}",
        fake.calls()
    );
    fake.set("ip.out", "\n");
    assert_eq!(i.mirror_ip().await, None);

    // No guard and no cache: neither mount is invented.
    let mirror = fake.one("run --detach");
    assert!(
        !mirror.contains("--volume") && !mirror.contains("--guard"),
        "{mirror}"
    );
    i.destroy().await;
    assert!(fake.has(&format!("network rm --force trigon-{run_id}")));
}

/// The sweep for abandoned islands never touches one whose owner is still running.
///
/// It runs at the start of every run, on a machine where another run — the owner's own `trigon
/// serve`, or a sibling lane of this very process — may be mid-build. Removing a live island takes
/// the only route out from under a build, and it happened: `reading the mirror's log: no container
/// with name or ID found`, on an island nobody had abandoned.
///
/// In a private temp dir, so the image-store lock the sweep needs is free: a dead owner's island
/// listed beside the live one is removed, mirror and network, which is what shows the sweep ran
/// and could have removed the live one too — rather than having been turned away by a lock some
/// other build on the machine held.
#[tokio::test]
async fn the_orphan_sweep_never_touches_an_island_whose_owner_is_alive() {
    if !in_a_private_temp_dir("the_orphan_sweep_never_touches_an_island_whose_owner_is_alive") {
        return;
    }
    let fake = Fake::new("orphans");
    let live = format!("trigon-somebody-else-{}", std::process::id());
    fake.set(
        "networks.out",
        &format!("{live}\n{ABANDONED}\ntrigon-no-pid-here\npodman\nsomebody-elses-network\n"),
    )
    .set("logs.out", "listening\n");
    let i = island(&fake, "orphans").await.expect("it listened");

    let calls = fake.calls();
    for removal in [
        format!("rm --force {ABANDONED}-mirror"),
        format!("network rm --force {ABANDONED}"),
    ] {
        assert!(
            calls.contains(&removal),
            "the abandoned island was left behind, `{removal}` never ran: {calls:?}"
        );
    }
    for name in [
        live.as_str(),
        "trigon-no-pid-here",
        "somebody-elses-network",
        "podman",
    ] {
        let container = format!("{name}-mirror");
        let removed = calls.iter().any(|c| {
            (c.starts_with("rm ") || c.starts_with("network rm "))
                && c.split(' ').any(|w| w == name || w == container)
        });
        assert!(!removed, "the sweep removed {name}: {calls:?}");
    }
    i.destroy().await;
}

/// An abandoned island is left for a later sweep while a build holds the image store.
///
/// `rm --force` and `network rm --force` mutate the store a build is reading, so the sweep takes
/// the lock for them and, when a build has it, leaves the orphan rather than waiting or racing.
#[tokio::test]
async fn an_abandoned_island_is_left_for_later_while_a_build_holds_the_image_store() {
    if !in_a_private_temp_dir(
        "an_abandoned_island_is_left_for_later_while_a_build_holds_the_image_store",
    ) {
        return;
    }
    let fake = Fake::new("orphans-busy");
    fake.set("networks.out", &format!("{ABANDONED}\n"))
        .set("logs.out", "listening\n");
    let held = hold_the_image_store_as_a_build();
    let i = island(&fake, "orphans-busy").await.expect("it listened");
    drop(held);

    assert!(
        fake.has("network ls --format {{.Name}}"),
        "the sweep never looked: {:?}",
        fake.calls()
    );
    assert!(
        !fake
            .calls()
            .iter()
            .any(|c| c.split(' ').any(|w| w.starts_with(ABANDONED))),
        "removed from under a build reading the store: {:?}",
        fake.calls()
    );
    i.destroy().await;
}

// ---------------------------------------------------------------------------------------------
// Whose failure it was.
// ---------------------------------------------------------------------------------------------

/// A runtime that refuses before any phase ran is our error, carrying what the runtime said.
///
/// `STEP 1/11: FROM` and a registry the runtime cannot reach used to become a `build-failed:deps`
/// verdict against the package. Nothing of the package's ran; the runtime's own diagnosis is one
/// line among its progress chatter, and that line is what gets reported.
#[tokio::test]
async fn a_runtime_that_refuses_before_any_phase_is_ours_and_says_what_the_runtime_said() {
    let fake = Fake::new("refused");
    fake.set(
        "build.out",
        "STEP 1/11: FROM localhost/trigon-base@sha256:7cddd\n\
         time=\"2026-01-01T00:00:00Z\" level=warning msg=\"Failed, retrying in 1s ... (1/3)\"\n\
         Error: creating build container: pinging container registry localhost: connection \
         refused\n",
    )
    .set("build.code", "125");

    let e = run(&fake.runner(), plan(EgressTier::DenyAll), &opts("refused"))
        .await
        .expect_err("nothing of ours ran, so there is no outcome to report");
    let SandboxError::RuntimeRefused { code, detail } = &e else {
        panic!("{e:?}")
    };
    assert_eq!(*code, 125);
    assert!(
        detail.contains("pinging container registry localhost"),
        "{detail}"
    );
    assert!(
        !detail.contains("STEP 1/11"),
        "progress chatter is not the diagnosis: {detail}"
    );
    assert!(!detail.contains("retrying"), "{detail}");
    assert_eq!(e.fault(), Fault::Infra);
    assert!(fake.calls().iter().all(|c| !c.starts_with("run --rm")));

    // And a runtime that said nothing at all is reported as having said nothing, not as a blank.
    let quiet = Fake::new("refused-quietly");
    quiet.set("build.code", "125");
    let e = run(
        &quiet.runner(),
        plan(EgressTier::DenyAll),
        &opts("refused-quietly"),
    )
    .await
    .expect_err("still nothing of ours ran");
    assert!(
        e.to_string().ends_with("the runtime printed nothing"),
        "{e}"
    );
}

/// An image build that fails in one of the package's phases is an outcome naming that phase, and
/// nothing after it runs.
#[tokio::test]
async fn an_image_build_that_fails_in_a_phase_names_that_phase_and_runs_nothing_after_it() {
    let fake = Fake::new("source-fails");
    fake.set(
        "build.out",
        "STEP 3/9: RUN /bin/sh /trigon/setup.sh\nSTEP 4/9: RUN /bin/sh /trigon/source.sh\n\
         fatal: reference is not a tree: cafebabe\n",
    )
    .set("build.code", "128");

    let out = run(
        &fake.runner(),
        plan(EgressTier::DenyAll),
        &opts("source-fails"),
    )
    .await
    .expect("the package's own phase failed, which is an outcome");
    assert_eq!((out.exit_code, out.failed_in), (128, Some(Phase::Source)));
    let phases: Vec<Phase> = out.timings.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        phases,
        [Phase::Source],
        "a timing for the phase that ran, and no other"
    );
    assert_eq!(out.artifact, None);
    assert!(fake.calls().iter().all(|c| !c.starts_with("run --rm")));
    // `--network none` held for the image build, so nothing crossed; that is still an account.
    assert_eq!(out.transcript, Some(vec![]));
}

/// With deps deferred into the run, a failure before the deps marker is a deps failure, and one
/// after it is the build's.
///
/// It used to ask whether the deps script had been *invoked*, which is true of every run that
/// reached the container — so every failure at an enforced tier was reported as a deps failure,
/// and sent a reader to the wrong half of the log.
#[tokio::test]
async fn with_deps_deferred_the_marker_decides_which_phase_a_failure_was_in() {
    for (output, want) in [
        (
            "/trigon/deps.sh\nnpm ERR! 404 Not Found\n".to_string(),
            Phase::Deps,
        ),
        (
            format!("/trigon/deps.sh\n{DEPS_DONE}\nerror TS2307: Cannot find module\n"),
            Phase::Build,
        ),
    ] {
        let name = format!("deferred-{want:?}").to_ascii_lowercase();
        let fake = Fake::new(&name);
        fake.set("logs.out", "listening\n")
            .set("ip.out", "10.89.0.7\n")
            .set("build.out", "/trigon/setup.sh\n")
            .set("run.out", &output)
            .set("run.code", "1");
        let out = run(&fake.mirrored(), plan(EgressTier::MirrorOnly), &opts(&name))
            .await
            .expect("an outcome");
        assert_eq!((out.exit_code, out.failed_in), (1, Some(want)), "{output}");
    }
}

/// The failure a build named is kept even when the log it was named in is compressed away.
///
/// The signature is the repair cache key and the cluster id. Classified from a compressed tail,
/// the same failure keyed two ways depending on how much the build printed after it.
///
/// So the naming line has to be one compression really drops. It is an error line, which the
/// compressor keeps first — but among error lines the later one wins, so it is followed by a few
/// thousand distinct later ones that no rule names: more of them than the budget holds, and none
/// alike, so collapsing repeats cannot make room for it.
#[tokio::test]
async fn the_failure_a_build_named_survives_the_log_being_compressed() {
    let fake = Fake::new("signature");
    fake.set("build.out", "/trigon/deps.sh\n")
        .set("run.out", "sh: 1: yarn: not found\n")
        .set("run.chatter", "4000")
        .set("run.code", "127");
    let out = run(
        &fake.runner(),
        plan(EgressTier::DenyAll),
        &opts("signature"),
    )
    .await
    .expect("an outcome");
    assert!(
        !out.log_tail.contains("yarn: not found"),
        "the naming line survived compression, so this proves nothing: {}",
        out.log_tail.chars().take(400).collect::<String>()
    );
    // The design this replaced, classifying the compressed tail, gets it wrong on this log.
    assert_ne!(
        trigon_core::classify(&out.log_tail).code,
        "npm/unsupported-package-manager"
    );
    let sig = out.signature.expect("the failure was named as it passed");
    assert_eq!(sig.code, "npm/unsupported-package-manager");
}

/// A build that is still running at its wall-clock limit is killed, and it is the build's time.
///
/// Killed, not merely reported: a `Timeout` returned while the process lives on frees the worker
/// slot and leaves the build running beside whatever takes it next.
#[tokio::test(start_paused = true)]
async fn a_build_still_running_at_its_wall_clock_limit_is_killed() {
    let fake = Fake::new("hangs");
    fake.set("build.hang", "");
    let o = opts("hangs");
    let limit = o.limits.wall_clock;
    let e = run(&fake.runner(), plan(EgressTier::DenyAll), &o)
        .await
        .expect_err("a hung build must not hold a worker until somebody notices");
    assert!(matches!(e, SandboxError::Timeout(d) if d == limit), "{e:?}");
    assert_eq!(e.fault(), Fault::Build);
    assert_killed(&fake, "build");
}

/// What a build prints after closing one of its streams still reaches the log.
///
/// The reader stops watching both streams when the first one ends, so whatever the other still
/// holds has to be drained — and the line a build prints last, on stderr after its stdout is gone,
/// is usually the error.
#[tokio::test]
async fn a_line_written_after_the_other_stream_closed_still_reaches_the_log() {
    for (file, line, event) in [
        (
            "run.late-err",
            "error: the real cause",
            BuildEvent::Stderr("error: the real cause".into()),
        ),
        (
            "run.late-out",
            "the last word on stdout",
            BuildEvent::Stdout("the last word on stdout".into()),
        ),
    ] {
        let name = format!("drain-{}", file.trim_start_matches("run."));
        let fake = Fake::new(&name);
        fake.set("build.out", "/trigon/deps.sh\n")
            .set("run.out", "first\n")
            .set(file, &format!("{line}\n"));
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let mut opts = opts(&name);
        opts.on_event = Some(Arc::new(move |e: &BuildEvent| {
            sink.lock().unwrap().push(e.clone())
        }));
        let out = run(&fake.runner(), plan(EgressTier::DenyAll), &opts)
            .await
            .expect("the build ran");
        assert!(out.log_tail.contains(line), "{file}: {}", out.log_tail);
        assert!(events.lock().unwrap().contains(&event), "{file}");
    }
}

/// The wall-clock limit holds for the whole run, not only while both streams are open.
///
/// A process that closes its output and goes on running is still running. The limit is not
/// optional — a hung build otherwise holds a worker slot until a human notices, and at fleet scale
/// nobody notices — so it cannot be something a build opts out of by closing a stream.
///
/// A real clock and a short limit, because what is under test is a deadline against a process that
/// is genuinely still there. Each stand-in closes its streams at once, long before the limit; if it
/// were slow to, the limit would still have to hold, so the assertion does not depend on timing.
#[tokio::test]
async fn a_build_that_closes_its_output_and_hangs_is_still_killed_at_its_limit() {
    for (name, file) in [
        ("linger-err", "run.late-err"),
        ("linger-out", "run.late-out"),
        ("linger-mute", "run.mute"),
    ] {
        let fake = Fake::new(name);
        fake.set("build.out", "/trigon/deps.sh\n")
            .set(file, "still here\n")
            .set("run.linger", "");
        let mut o = opts(name);
        o.limits.wall_clock = std::time::Duration::from_secs(1);
        let ran = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            run(&fake.runner(), plan(EgressTier::DenyAll), &o),
        )
        .await
        .unwrap_or_else(|_| panic!("{name}: the build outlived its wall-clock limit twentyfold"));
        let e = ran.expect_err("a hung build is not an outcome");
        assert!(
            matches!(e, SandboxError::Timeout(d) if d == o.limits.wall_clock),
            "{name}: {e:?}"
        );
        assert_killed(&fake, "run");
    }
}

/// Only what a dead run left, and only once it has sat idle, is swept before a build.
///
/// Process ids are reused, and deleting a live run's build context because an unrelated process
/// inherited its number would be worse than the leak — so both conditions are required.
///
/// In a private temp dir, because the sweep walks the whole of it: planted in the host's own, the
/// probes would sit among every other run's contexts, and the sweep would be deleting there.
#[tokio::test]
async fn only_a_dead_runs_idle_build_context_is_swept_before_a_build() {
    if !in_a_private_temp_dir("only_a_dead_runs_idle_build_context_is_swept_before_a_build") {
        return;
    }
    let tmp = std::env::temp_dir();
    let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    // A run id ends in the pid that made it. No process has these two, and this one has the last.
    let me = std::process::id();
    let make = |run_id: &str, idle: bool| {
        let dir = tmp.join(format!("trigon-ctx-{run_id}"));
        std::fs::create_dir_all(&dir).unwrap();
        if idle {
            std::fs::File::open(&dir)
                .unwrap()
                .set_modified(hour_ago)
                .unwrap();
        }
        dir
    };
    let stale = make(&format!("sweep-probe-{me}-stale-4000000000"), true);
    let fresh = make(&format!("sweep-probe-{me}-fresh-4000000001"), false);
    let live = make(&format!("sweep-probe-{me}-live-{me}"), true);
    // No pid to ask about: left alone, because the safe direction to err is "alive".
    let unowned = make(&format!("sweep-probe-{me}-no-pid"), true);

    let fake = Fake::new("sweep");
    fake.set("build.out", "/trigon/deps.sh\n");
    run(&fake.runner(), plan(EgressTier::DenyAll), &opts("sweep"))
        .await
        .expect("the build ran");

    assert!(
        !stale.exists(),
        "a dead run's idle context survived the sweep"
    );
    assert!(live.exists(), "a live run's context was swept");
    assert!(
        fresh.exists(),
        "a context idle for less than the floor was swept"
    );
    assert!(unowned.exists(), "a context naming no process was swept");
    for dir in [stale, fresh, live, unowned] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A mirror that is slow to bind is waited for, rather than reported as broken.
///
/// `podman run --detach` returns before the process inside is listening, and the image build
/// begins straight after: the race used to show up as `ECONNREFUSED` from a package manager, which
/// reads as a broken mirror rather than one that was not up yet.
#[tokio::test(start_paused = true)]
async fn a_mirror_that_is_slow_to_start_is_waited_for() {
    let fake = Fake::new("slow-mirror");
    fake.set("logs.1.out", "starting\n")
        .set("logs.2.out", "starting\n")
        .set("logs.3.out", "starting\ntime-filtering mirror listening\n")
        .set("state.out", "running\n");
    let i = island(&fake, "slow-mirror").await;
    let i = match i {
        Ok(i) => i,
        Err(e) => panic!("a mirror that was merely slow was reported as failed: {e}"),
    };
    let asked = fake
        .calls()
        .iter()
        .filter(|c| c.starts_with("logs"))
        .count();
    assert_eq!(asked, 3, "it asked until the mirror said it was listening");
    i.destroy().await;
}

/// A sweep that cannot list networks does not stop the run it was only tidying up before.
#[tokio::test]
async fn a_sweep_that_cannot_list_networks_does_not_stop_the_run() {
    let fake = Fake::new("no-network-list");
    fake.set("networks.code", "125")
        .set("networks.err", "Error: cannot connect\n")
        .set("logs.out", "listening\n");
    let i = island(&fake, "no-network-list").await;
    assert!(i.is_ok(), "the island failed on a best-effort sweep");
    assert!(fake.calls().iter().any(|c| c.starts_with("network create")));
}

// ---------------------------------------------------------------------------------------------
// Addresses, sources and artifacts.
// ---------------------------------------------------------------------------------------------

/// `host-gateway` is resolved before the image build, because `podman build` rejects the keyword.
///
/// `podman run` understands it, so the run keeps it; the image build — where a package manager
/// actually talks to a mirror on the host — needs the address this machine's rootless networking
/// hands out, which is asked for rather than assumed.
#[tokio::test]
async fn host_gateway_is_resolved_for_the_image_build_and_left_to_podman_for_the_run() {
    let fake = Fake::new("gateway");
    fake.set("probe.out", "10.0.2.2        trigon-probe\n")
        .set("build.out", "/trigon/deps.sh\n");
    let mut p = plan(EgressTier::Open);
    p.extra_hosts = BTreeMap::from([("registry".to_string(), "host-gateway".to_string())]);
    run(&fake.runner(), p, &opts("gateway"))
        .await
        .expect("the build ran");

    let probe = fake.one("run --rm --add-host trigon-probe:host-gateway");
    assert!(
        probe.ends_with(&format!("{IMAGE} getent hosts trigon-probe")),
        "{probe}"
    );
    assert!(fake.one("build").contains("--add-host registry:10.0.2.2"));
    let run = fake
        .calls()
        .into_iter()
        .find(|c| c.starts_with("run --rm") && !c.contains("trigon-probe"))
        .expect("the build ran");
    assert!(run.contains("--add-host registry:host-gateway"), "{run}");
}

/// A host that cannot be resolved, or a mirror alias with no island, stops the run before the
/// build.
#[tokio::test]
async fn a_host_mapping_that_cannot_be_resolved_stops_the_run_before_the_build() {
    let fake = Fake::new("gateway-fails");
    fake.set("probe.code", "1");
    let mut p = plan(EgressTier::Open);
    p.extra_hosts = BTreeMap::from([("registry".to_string(), "host-gateway".to_string())]);
    let e = run(&fake.runner(), p, &opts("gateway-fails"))
        .await
        .expect_err("an unresolvable mapping");
    assert!(
        e.to_string()
            .contains("could not work out how `registry` should reach the host"),
        "{e}"
    );
    assert!(!fake.calls().iter().any(|c| c.starts_with("build")));

    // `mirror` names the island's mirror, and a tier with no island has none to name.
    let fake = Fake::new("mirror-alias");
    let mut p = plan(EgressTier::DenyAll);
    p.extra_hosts = BTreeMap::from([("timewarp".to_string(), "mirror".to_string())]);
    let e = run(&fake.runner(), p, &opts("mirror-alias"))
        .await
        .expect_err("an alias for a mirror that does not exist");
    assert!(
        e.to_string()
            .contains("the mirror container has no address"),
        "{e}"
    );
    assert_eq!(e.fault(), Fault::Infra);
    assert!(!fake.calls().iter().any(|c| c.starts_with("build")));
}

/// The checkout the host fetched is copied into the build context, `.git` included, and one that
/// cannot be copied stops the run as ours.
#[tokio::test]
async fn a_checkout_is_copied_into_the_context_and_one_that_cannot_be_copied_stops_the_run() {
    let fake = Fake::new("checkout");
    fake.set("build.out", "/trigon/deps.sh\n");
    let tree = fake.dir.join("checkout");
    std::fs::create_dir_all(tree.join(".git")).unwrap();
    std::fs::write(tree.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(tree.join("package.json"), "{}").unwrap();
    let mut p = plan(EgressTier::DenyAll);
    p.source_tree = Some(tree);
    run(&fake.runner(), p, &opts("checkout"))
        .await
        .expect("the build ran");
    let copied = std::fs::read_to_string(fake.dir.join("ctx-src")).expect("the context was listed");
    let copied: BTreeSet<&str> = copied.lines().collect();
    assert_eq!(copied, BTreeSet::from([".git", "package.json"]));

    let mut p = plan(EgressTier::DenyAll);
    p.source_tree = Some(fake.dir.join("no-such-checkout"));
    let e = run(&fake.runner(), p, &opts("no-checkout"))
        .await
        .expect_err("a checkout that is not there");
    assert!(
        matches!(&e, SandboxError::Failed { phase, .. } if phase == "source"),
        "{e:?}"
    );
    assert_eq!(e.fault(), Fault::Infra);
}

/// Only a single regular file at the output path is an artifact.
///
/// Three files means the strategy's `output_path` does not identify an artifact, and picking one
/// would attach a verdict to whichever the filesystem listed first. A symlink is the build pointing
/// at a path on *our* filesystem, and is never collected.
#[tokio::test]
async fn only_a_single_regular_file_at_the_output_path_is_collected() {
    for (name, artifacts, links) in [
        ("two-files", "a.tgz\nb.tgz\n", ""),
        ("a-link", "", "passwd.tgz\n"),
        ("nothing", "", ""),
    ] {
        let fake = Fake::new(name);
        fake.set("build.out", "/trigon/deps.sh\n")
            .set("artifacts", artifacts)
            .set("links", links);
        let out = run(&fake.runner(), plan(EgressTier::DenyAll), &opts(name))
            .await
            .expect("the build ran");
        assert!(out.succeeded());
        assert_eq!(out.artifact, None, "{name}");
    }
}

// ---------------------------------------------------------------------------------------------
// What a run leaves in the image store, and when it may be taken out.
//
// Every removal here takes the machine-wide image-store lock and skips itself when a build holds
// it, so each test runs in a process of its own with a private temp dir, where the lock is free
// unless the test itself holds it.
// ---------------------------------------------------------------------------------------------

/// A run's image is removed however the run ends, unless the caller asked to keep it.
///
/// A guard rather than a line at the end of the happy path: a failed build used to keep its image
/// for ever, and a failing build is the common case for the packages a sweep spends its time on.
/// Never forced, so an image another build still depends on survives.
#[tokio::test]
async fn a_runs_image_is_removed_however_the_run_ends_unless_it_was_to_be_kept() {
    if !in_a_private_temp_dir(
        "a_runs_image_is_removed_however_the_run_ends_unless_it_was_to_be_kept",
    ) {
        return;
    }
    let fake = Fake::new("leftovers");
    fake.set("build.out", "/trigon/deps.sh\n");
    let built = opts("built");
    run(&fake.runner(), plan(EgressTier::DenyAll), &built)
        .await
        .expect("the build ran");
    assert!(
        fake.has(&format!("rmi trigon-build:{}", built.run_id)),
        "{:?}",
        fake.calls()
    );

    fake.set("build.code", "1");
    let failed = opts("failed");
    let out = run(&fake.runner(), plan(EgressTier::DenyAll), &failed)
        .await
        .expect("a failure in the package's phase is an outcome");
    assert_eq!(out.failed_in, Some(Phase::Deps));
    assert!(
        fake.has(&format!("rmi trigon-build:{}", failed.run_id)),
        "a failed build kept its image: {:?}",
        fake.calls()
    );

    let mut kept = opts("kept");
    kept.retain = true;
    let _ = run(&fake.runner(), plan(EgressTier::DenyAll), &kept).await;
    let calls = fake.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("rmi") && c.contains(&kept.run_id)),
        "an image the caller asked to keep was removed: {calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("rmi") && c.contains("--force")),
        "{calls:?}"
    );
}

/// An image the store was too busy to remove is removed once it is quiet, and nothing waits.
///
/// Skipping a removal while a build reads the store is the point — a removal must never block a
/// build — but skipping and *forgetting* grew the store without limit under a sweep, which holds
/// the lock almost continuously. The image is remembered, and taken by whichever comes first: an
/// explicit drain once the store is quiet, or the next run that gets the lock for its own image.
#[tokio::test]
async fn an_image_the_store_was_too_busy_to_remove_is_removed_once_it_is_quiet() {
    if !in_a_private_temp_dir(
        "an_image_the_store_was_too_busy_to_remove_is_removed_once_it_is_quiet",
    ) {
        return;
    }
    let fake = Fake::new("deferred");
    fake.set("build.out", "/trigon/deps.sh\n");
    let removals = |run_id: &str| {
        let rmi = format!("rmi trigon-build:{run_id}");
        fake.calls().iter().filter(|c| **c == rmi).count()
    };

    let held = hold_the_image_store_as_a_build();
    let first = opts("busy-first");
    run(&fake.runner(), plan(EgressTier::DenyAll), &first)
        .await
        .expect("the build ran");
    assert_eq!(removals(&first.run_id), 0, "removed from under a build");
    // Draining never waits for the store either.
    trigon_sandbox::reap_deferred(&fake.path());
    assert_eq!(removals(&first.run_id), 0, "removed from under a build");
    drop(held);
    trigon_sandbox::reap_deferred(&fake.path());
    assert_eq!(removals(&first.run_id), 1, "{:?}", fake.calls());
    // And a drained backlog is empty: nothing is removed twice.
    trigon_sandbox::reap_deferred(&fake.path());
    assert_eq!(removals(&first.run_id), 1, "{:?}", fake.calls());

    let held = hold_the_image_store_as_a_build();
    let second = opts("busy-second");
    run(&fake.runner(), plan(EgressTier::DenyAll), &second)
        .await
        .expect("the build ran");
    drop(held);
    let third = opts("quiet-third");
    run(&fake.runner(), plan(EgressTier::DenyAll), &third)
        .await
        .expect("the build ran");
    assert_eq!(
        (removals(&second.run_id), removals(&third.run_id)),
        (1, 1),
        "the run that got the lock takes the backlog with its own image: {:?}",
        fake.calls()
    );
}

/// The stale-image sweep removes only an old build image whose run is gone.
///
/// Keyed on the pid a run id ends in, and asked of podman only past the age floor, because the
/// images of concurrent runs share layers. Once per process: it reaches into the shared store, so
/// the second run in a process does not ask again.
#[tokio::test]
async fn the_stale_image_sweep_removes_only_an_old_build_image_whose_run_is_gone() {
    if !in_a_private_temp_dir(
        "the_stale_image_sweep_removes_only_an_old_build_image_whose_run_is_gone",
    ) {
        return;
    }
    let me = std::process::id();
    let fake = Fake::new("stale-images");
    fake.set("build.out", "/trigon/deps.sh\n").set(
        "images.out",
        &format!(
            "localhost/trigon-build:fake-gone-4000000000\n\
             localhost/trigon-build:fake-alive-{me}\n\
             localhost/trigon-build:no-pid-here\n\
             docker.io/library/alpine:latest\n\
             localhost/trigon-mirror:latest\n"
        ),
    );
    run(&fake.runner(), plan(EgressTier::DenyAll), &opts("sweeps"))
        .await
        .expect("the build ran");
    run(&fake.runner(), plan(EgressTier::DenyAll), &opts("again"))
        .await
        .expect("the build ran");

    let calls = fake.calls();
    let listed: Vec<&String> = calls.iter().filter(|c| c.starts_with("images")).collect();
    assert_eq!(
        listed,
        ["images --filter until=10m --format {{.Repository}}:{{.Tag}}"],
        "asked once, and only for images past the age floor: {calls:?}"
    );
    assert!(
        calls.contains(&"rmi localhost/trigon-build:fake-gone-4000000000".to_string()),
        "{calls:?}"
    );
    for survivor in [
        format!("fake-alive-{me}"),
        "no-pid-here".into(),
        "alpine:latest".into(),
        "trigon-mirror".into(),
    ] {
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("rmi") && c.contains(&survivor)),
            "the sweep removed {survivor}: {calls:?}"
        );
    }
}

/// The stale-image sweep takes nothing out of a store a build is reading.
#[tokio::test]
async fn the_stale_image_sweep_takes_nothing_while_a_build_reads_the_store() {
    if !in_a_private_temp_dir("the_stale_image_sweep_takes_nothing_while_a_build_reads_the_store") {
        return;
    }
    let fake = Fake::new("stale-images-busy");
    fake.set("build.out", "/trigon/deps.sh\n").set(
        "images.out",
        "localhost/trigon-build:fake-gone-4000000000\n",
    );
    let held = hold_the_image_store_as_a_build();
    run(&fake.runner(), plan(EgressTier::DenyAll), &opts("busy"))
        .await
        .expect("the build ran");
    drop(held);
    let calls = fake.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("images") || c.contains("fake-gone-4000000000")),
        "{calls:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The runtime itself.
// ---------------------------------------------------------------------------------------------

/// A runtime that is missing, or answers `--version` with an error, is a missing tool — ours.
#[tokio::test]
async fn a_runtime_that_is_missing_or_broken_is_reported_as_a_missing_tool() {
    let missing = PodmanRunner::new(std::env::temp_dir()).with_binary("/nonexistent/podman");
    let e = missing.health().await.expect_err("there is nothing to run");
    assert!(
        matches!(&e, SandboxError::ToolMissing { tool, .. } if tool == "/nonexistent/podman"),
        "{e:?}"
    );
    assert_eq!(e.fault(), Fault::Infra);

    let fake = Fake::new("health");
    fake.set("version.code", "125")
        .set("version.err", "cannot connect to the Podman socket\n");
    let e = fake.runner().health().await.expect_err("a broken runtime");
    assert!(
        matches!(&e, SandboxError::ToolMissing { detail, .. }
            if detail == "cannot connect to the Podman socket"),
        "{e:?}"
    );
    fake.set("version.code", "0");
    assert!(fake.runner().health().await.is_ok());
}

/// A base image that is not in the store is pulled by digest, and a pull that fails says why.
///
/// `docs/19` D8: "re-pulled" is written only where the pull happened. The branch that first takes
/// an image *out* of the store needs the machine-wide store lock, so it is asserted in a private
/// temp dir, by the test after this one.
#[test]
fn an_absent_base_image_is_pulled_by_digest_and_a_failed_pull_is_not_reported_as_one() {
    let image = format!("docker.io/library/debian@sha256:{}", "c".repeat(64));
    let fake = Fake::new("repull");
    fake.set("image.code", "1");
    trigon_sandbox::repull(&fake.path(), &image).expect("pulled");
    assert!(fake.has(&format!("image exists {image}")));
    assert!(fake.has(&format!("pull --quiet {image}")));
    assert!(!fake.calls().iter().any(|c| c.starts_with("image rm")));

    fake.set("pull.code", "125").set(
        "pull.err",
        "Trying to pull docker.io/library/debian...\n\
         Error: initializing source: manifest unknown\n",
    );
    let e = trigon_sandbox::repull(&fake.path(), &image).expect_err("the pull failed");
    assert!(e.starts_with("pulling it again failed: "), "{e}");
    assert!(e.contains("manifest unknown"), "podman's reason: {e}");
}

/// A base image already in the store is taken out, seen to be gone, and only then pulled again —
/// and an attempt that cannot take it out says so rather than claiming a re-pull.
///
/// `docs/19` D8: a confirming attempt's image must have come from the registry for that attempt,
/// not from whatever the store has held since the first. Never forced, so an image in use stays.
#[test]
fn a_present_base_image_is_taken_out_before_it_is_pulled_and_one_that_stays_is_not_repulled() {
    if !in_a_private_temp_dir(
        "a_present_base_image_is_taken_out_before_it_is_pulled_and_one_that_stays_is_not_repulled",
    ) {
        return;
    }
    let image = format!("docker.io/library/debian@sha256:{}", "c".repeat(64));
    let fake = Fake::new("repull-present");
    fake.set("image.code", "0");
    trigon_sandbox::repull(&fake.path(), &image).expect("taken out and pulled again");
    assert_eq!(
        fake.calls(),
        [
            format!("image exists {image}"),
            format!("image rm {image}"),
            format!("image exists {image}"),
            format!("pull --quiet {image}"),
        ]
    );

    let in_use = Fake::new("repull-in-use");
    in_use.set("image.code", "0").set("image-rm.code", "2").set(
        "image-rm.err",
        "Error: image used by 3f1c: image is in use by a container\n",
    );
    let e = trigon_sandbox::repull(&in_use.path(), &image).expect_err("it could not be removed");
    assert!(
        e.starts_with(
            "podman would not remove it (Error: image used by 3f1c: image is in use by a \
             container)"
        ),
        "{e}"
    );
    assert!(
        !in_use.calls().iter().any(|c| c.starts_with("pull")),
        "pulled on top of an image that never left: {:?}",
        in_use.calls()
    );

    let sticky = Fake::new("repull-sticky");
    sticky.set("image.code", "0").set("image.sticky", "");
    let e = trigon_sandbox::repull(&sticky.path(), &image).expect_err("it never left the store");
    assert!(
        e.contains("still in the image store after it was removed"),
        "{e}"
    );
    assert!(!sticky.calls().iter().any(|c| c.starts_with("pull")));
    assert!(
        !sticky
            .calls()
            .iter()
            .any(|c| c.starts_with("image rm") && c.contains("--force")),
        "{:?}",
        sticky.calls()
    );
}

// ---------------------------------------------------------------------------------------------
// The stand-in.
// ---------------------------------------------------------------------------------------------

const IMAGE: &str = concat!(
    "docker.io/library/alpine@sha256:",
    "c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
);

/// A container runtime that writes down what it was asked and answers from files beside it.
///
/// For each command `NAME` it prints `NAME.out` and `NAME.err` and exits with `NAME.code`, all
/// optional. `logs` answers from `logs.N.*` on its Nth call where one exists, so a log can say
/// "listening" to the readiness probe and something else to the reader after the build. A process
/// told to hang writes its pid to `NAME.pid` first, so a test can see whether it was killed. The
/// image store has one bit of state: `image rm` takes the image out, so a later `image exists`
/// answers no — unless `image-rm.code` makes the removal fail, or `image.sticky` says the image is
/// still there under another name.
const SCRIPT: &str = r#"#!/bin/sh
D="$(dirname "$0")"
printf '%s\n' "$*" >> "$D/calls"
emit() {
  [ -f "$D/$1.out" ] && cat "$D/$1.out"
  [ -f "$D/$1.err" ] && cat "$D/$1.err" >&2
  # Distinct error lines no failure rule names, so neither a classifier nor dedup absorbs them.
  [ -f "$D/$1.chatter" ] && seq -f 'FAILED self-check %05g of the widget, which stayed quiet' \
    1 "$(cat "$D/$1.chatter")"
  # One stream closed while the process goes on writing to the other, or goes on running.
  [ -f "$D/$1.late-err" ] && { exec 1>&-; cat "$D/$1.late-err" >&2; }
  [ -f "$D/$1.late-out" ] && { exec 2>&-; cat "$D/$1.late-out"; }
  [ -f "$D/$1.mute" ] && exec 1>&- 2>&-
  [ -f "$D/$1.linger" ] && { echo $$ > "$D/$1.pid"; exec sleep 600; }
  [ -f "$D/$1.code" ] && exit "$(cat "$D/$1.code")"
  exit 0
}
case "$1" in
  --version) emit version ;;
  image)
    if [ "$2" = rm ]; then
      [ -f "$D/image-rm.code" ] || [ -f "$D/image.sticky" ] || echo 1 > "$D/image.code"
      emit image-rm
    fi
    emit image ;;
  images) emit images ;;
  pull) emit pull ;;
  network) [ "$2" = ls ] && emit networks; exit 0 ;;
  build)
    prev=""; ctx=""
    for a; do
      [ "$prev" = "--file" ] && ctx="$(dirname "$a")"
      prev="$a"
    done
    [ -d "$ctx/src" ] && ls -A "$ctx/src" > "$D/ctx-src"
    [ -f "$D/build.hang" ] && { echo $$ > "$D/build.pid"; exec sleep 600; }
    emit build ;;
  run)
    case "$*" in
      *--detach*) emit detach ;;
      *trigon-probe:host-gateway*) emit probe ;;
    esac
    prev=""; out=""
    for a; do
      if [ "$prev" = "--volume" ]; then
        case "$a" in *:/out:Z) out="${a%:/out:Z}" ;; esac
      fi
      prev="$a"
    done
    if [ -n "$out" ]; then
      [ -f "$D/artifacts" ] && while read -r f; do
        [ -n "$f" ] && echo "built $f" > "$out/$f"
      done < "$D/artifacts"
      [ -f "$D/links" ] && while read -r f; do
        [ -n "$f" ] && ln -s /etc/passwd "$out/$f"
      done < "$D/links"
    fi
    emit run ;;
  logs)
    n=$(( $(cat "$D/logs.n" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$D/logs.n"
    for f in "$D/logs.$n.out" "$D/logs.$n.err" "$D/logs.$n.code"; do
      [ -f "$f" ] && emit "logs.$n"
    done
    emit logs ;;
  inspect)
    case "$*" in
      *State.Status*) [ -f "$D/state.out" ] || echo running; emit state ;;
      *IPAddress*) emit ip ;;
    esac
    exit 0 ;;
esac
exit 0
"#;

struct Fake {
    dir: PathBuf,
}

impl Fake {
    fn new(name: &str) -> Fake {
        let dir =
            std::env::temp_dir().join(format!("trigon-fake-podman-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("podman");
        std::fs::write(&bin, SCRIPT).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        settle(&bin);
        let _ = std::fs::remove_file(dir.join("calls"));
        Fake { dir }
    }

    fn set(&self, file: &str, content: &str) -> &Fake {
        std::fs::write(self.dir.join(file), content).unwrap();
        self
    }

    fn path(&self) -> String {
        self.dir.join("podman").display().to_string()
    }

    fn work(&self) -> PathBuf {
        self.dir.join("work")
    }

    fn runner(&self) -> PodmanRunner {
        PodmanRunner::new(self.work()).with_binary(self.path())
    }

    fn mirrored(&self) -> PodmanRunner {
        self.runner()
            .with_mirror_image(Some("localhost/trigon-mirror:latest".into()))
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn has(&self, call: &str) -> bool {
        self.calls().iter().any(|c| c == call)
    }

    /// The one invocation starting with `prefix`, which there must be exactly one of.
    fn one(&self, prefix: &str) -> String {
        let matching: Vec<String> = self
            .calls()
            .into_iter()
            .filter(|c| c.starts_with(prefix))
            .collect();
        assert_eq!(matching.len(), 1, "`{prefix}`: {:?}", self.calls());
        matching.into_iter().next().unwrap()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Run the stand-in once, so no later spawn of it can fail with `ETXTBSY`.
///
/// A script is written and then executed while sibling tests are forking: a child forked while the
/// file was open for writing holds that descriptor until it execs, and executing the script in that
/// window fails with "text file busy". Once one execution has succeeded after the write was closed,
/// no process can still hold it open for writing, so every later one succeeds.
fn settle(bin: &Path) {
    for _ in 0..10_000 {
        match std::process::Command::new(bin).arg("--version").output() {
            Ok(_) => return,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => std::thread::yield_now(),
            Err(e) => panic!("the stand-in will not run: {e}"),
        }
    }
    panic!("the stand-in stayed busy");
}

/// Assert that the stand-in's `name` invocation has stopped running: that the runner killed it.
///
/// Found two ways, because the kill can land before the script has said who it is: by its command
/// line, which names the stand-in until it becomes `sleep`, and by the pid it writes just before
/// it does. Looked for in that order, so a script that execs between the two looks is still found
/// by the second. Each is then waited on through a pidfd, which becomes readable when the process
/// ends — an event, not a sleep — with a bound, so a survivor fails the test rather than hanging
/// it.
fn assert_killed(fake: &Fake, name: &str) {
    let stand_in = fake.path();
    let mut pids: BTreeSet<i32> = std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|c| String::from_utf8_lossy(&c).contains(&stand_in))
        })
        .collect();
    if let Some(pid) = std::fs::read_to_string(fake.dir.join(format!("{name}.pid")))
        .ok()
        .and_then(|s| s.trim().parse().ok())
    {
        pids.insert(pid);
    }
    for pid in pids {
        // SAFETY: `pidfd_open` takes a pid and flags, and returns a new descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
        if fd < 0 {
            // Gone already, reaped and all.
            continue;
        }
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid `pollfd`, whose descriptor is ours until the `close` below.
        let n = unsafe { libc::poll(&mut ready, 1, 10_000) };
        // SAFETY: closing the descriptor `pidfd_open` gave us, once.
        unsafe { libc::close(fd) };
        assert_eq!(
            n, 1,
            "`{name}` (pid {pid}) was still running ten seconds after the build was given up on"
        );
    }
}

fn plan(egress: EgressTier) -> OciPlan {
    OciPlan {
        base_image: IMAGE.into(),
        system_deps: BTreeSet::new(),
        source: "true".into(),
        deps: "true".into(),
        build: "true".into(),
        output_path: "dist/*".into(),
        egress,
        privileged: false,
        extra_hosts: BTreeMap::new(),
        source_tree: None,
    }
}

/// A run id ending in this process's pid, which is what marks its leftovers as a live run's.
fn opts(name: &str) -> RunOpts {
    RunOpts {
        run_id: format!("fake-{name}-{}", std::process::id()),
        ..Default::default()
    }
}

async fn run(
    runner: &PodmanRunner,
    plan: OciPlan,
    opts: &RunOpts,
) -> Result<BuildOutcome, SandboxError> {
    runner
        .start(&BuildPlan::Oci(plan), opts)
        .await?
        .wait()
        .await
}

/// Every value a flag was given in one invocation, in order.
fn flag_values<'a>(call: &'a str, flag: &str) -> Vec<&'a str> {
    let words: Vec<&str> = call.split(' ').collect();
    words
        .windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1])
        .collect()
}

/// An island whose owner is gone: no process has this pid, which is past any `pid_max`.
const ABANDONED: &str = "trigon-x-4000000000";

/// Set in a child started by [`in_a_private_temp_dir`], and nowhere else.
const PRIVATE: &str = "TRIGON_SEAM_PODMAN_PRIVATE_TMPDIR";

/// Run the calling test again, alone, in a process whose temp dir is private.
///
/// Two things the runner finds through `std::env::temp_dir()` are machine-wide: the lock over
/// podman's image store, which every removal takes and skips itself without, and the directory the
/// stale-context sweep walks. A test that asserts what a removal does when the store is quiet
/// cannot share that lock with every other build on the machine, and one that plants stale
/// contexts must not plant them in the host's own temp dir. `temp_dir` reads `TMPDIR`, so a child
/// given a private one has a private lock and a private sweep root — passed with `Command::env`,
/// never set in this process, where every sibling test would see it.
///
/// `true` in the child, which goes on to run the scenario; `false` in the parent, which has already
/// checked that the child ran it and passed.
fn in_a_private_temp_dir(test: &str) -> bool {
    if std::env::var_os(PRIVATE).is_some() {
        return true;
    }
    let tmp = std::env::temp_dir().join(format!(
        "trigon-seam-private-tmp-{test}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--test-threads=1"])
        .env(PRIVATE, "1")
        .env("TMPDIR", &tmp)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "{test}, alone in a private temp dir: {said}"
    );
    assert!(
        said.contains("1 passed"),
        "{test}: the child ran nothing: {said}"
    );
    false
}

/// Hold the image-store lock the way a build does, shared, until the file is dropped.
///
/// The path is the one `store_lock` computes, written out again because it is private to the
/// crate. If the two drift, the store is quiet when a test says it is busy and the removal it
/// expects to be skipped happens — a failure, not a pass on a lock nobody held.
fn hold_the_image_store_as_a_build() -> std::fs::File {
    use std::os::fd::AsRawFd as _;
    assert!(
        std::env::var_os(PRIVATE).is_some(),
        "the machine's own image store is never held by a test"
    );
    // SAFETY: `getuid` reads a process property and cannot fail.
    let uid = unsafe { libc::getuid() };
    let at = std::env::temp_dir().join(format!("trigon-image-store-{uid}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(at)
        .unwrap();
    // SAFETY: the descriptor is owned by `file` and outlives the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    file
}

/// The error an island failed to come up with. `Island` is not `Debug`, so not `expect_err`.
fn no_island(r: Result<Island, SandboxError>, why: &str) -> SandboxError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("an island came up: {why}"),
    }
}

async fn island(fake: &Fake, name: &str) -> Result<Island, SandboxError> {
    let run_id = format!("{name}-{}", std::process::id());
    Island::create(
        &fake.path(),
        &run_id,
        "localhost/trigon-mirror:latest",
        8129,
        None,
        None,
    )
    .await
}

/// One of each record the mirror writes, as it writes them.
fn mirror_records() -> (Exchange, Trip, Refusal, Asked, Throttled) {
    (
        Exchange::new(
            "index",
            "https://registry.npmjs.org/demo",
            "aa".repeat(32),
            4096,
            Checked::Generated,
        )
        .withholding(2),
        Trip {
            url: "https://cdn.evil.example/demo-1.0.0.tgz".into(),
            matched: GuardMatch::WholeArtifact,
        },
        Refusal {
            path: "/left-pad".into(),
            status: 400,
            reason: "no time filter on this request".into(),
        },
        Asked {
            host: "registry.npmjs.org".into(),
            cached: true,
            index_fetched_at: Some(1_700_000_000),
        },
        Throttled {
            host: "registry.npmjs.org".into(),
            retry_after_s: Some(3),
            gave_up: false,
        },
    )
}
