//! What the runner will and will not agree to, and what the container pattern renders to.
//!
//! No container runtime needed: rendering is pure and routing is a decision about capabilities.

use std::collections::BTreeSet;

use trigon_core::{Classify, Fault};
use trigon_sandbox::{
    BuildPlan, BuildRunner, EgressTier, ObservabilityTier, OciPlan, PodmanRunner, RunOpts,
    SandboxError, render_context, route,
};

const PINNED: &str = "docker.io/library/python@sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999";

fn plan(egress: EgressTier) -> BuildPlan {
    BuildPlan::Oci(OciPlan {
        base_image: PINNED.into(),
        system_deps: BTreeSet::from(["git".to_string(), "curl".to_string()]),
        source: "git clone https://github.com/a/b .\ngit checkout --force 'cafebabe'".into(),
        deps: "python3 -m venv /deps\n/deps/bin/pip install build".into(),
        build: "/deps/bin/python3 -m build --wheel -n".into(),
        output_path: "dist/*".into(),
        egress,
        privileged: false,
        extra_hosts: Default::default(),
        source_tree: None,
    })
}

#[test]
fn the_context_runs_deps_at_image_build_time_and_writes_the_build() {
    let BuildPlan::Oci(p) = plan(EgressTier::DenyAll);
    let c = render_context(&p, false);
    println!(
        "{}\n---\n{:#?}",
        c.dockerfile,
        c.files.keys().collect::<Vec<_>>()
    );

    assert!(
        c.dockerfile.contains(&format!("FROM {PINNED}")),
        "pinned by digest"
    );

    // Each phase is a COPY plus a RUN, which is what buys layer caching across sibling versions and
    // per-phase timings from layer metadata.
    assert!(
        c.files["setup.sh"].contains("dpkg -s"),
        "an enforced tier checks rather than installs"
    );
    assert!(c.files["source.sh"].contains("git checkout --force 'cafebabe'"));
    assert!(c.files["deps.sh"].contains("python3 -m venv /deps"));

    // The build is WRITTEN, not run: everything above is cacheable, and only this happens fresh
    // under the runtime's isolation.
    let deps_at = c.dockerfile.find("RUN /bin/sh /trigon/deps.sh").unwrap();
    let build_at = c
        .dockerfile
        .find("COPY build.sh /build")
        .expect("the build is copied, not run");
    assert!(
        deps_at < build_at,
        "deps must be a layer before the build script is written"
    );
    assert!(
        !c.dockerfile.contains("RUN /bin/sh /build"),
        "the build must not run at image time"
    );
    assert!(c.dockerfile.contains(r#"ENTRYPOINT ["/bin/sh", "/build"]"#));

    // Unquoted, because output_path is usually a glob and quoting it would look for a file with an
    // asterisk in its name.
    assert!(c.files["build.sh"].contains("cp -r /src/dist/* /out/"));
    assert!(
        c.files["build.sh"].starts_with("set -eux"),
        "fail on the first error"
    );
}

#[test]
fn a_script_is_a_file_rather_than_a_heredoc() {
    // Podman 4.x builds with imagebuilder, which does not implement BuildKit heredocs: it parses
    // the body as Dockerfile instructions, so the first line of a build script becomes an unknown
    // instruction. Requiring BuildKit would make "runs on a laptop with podman" false. As a bonus
    // there is no shell quoting to get wrong, which this checks.
    let BuildPlan::Oci(mut p) = plan(EgressTier::DenyAll);
    p.build = "echo $HOME > marker".into();
    let c = render_context(&p, false);
    assert!(
        !c.dockerfile.contains("<<"),
        "no heredocs: {}",
        c.dockerfile
    );
    assert!(
        c.files["build.sh"].contains("echo $HOME > marker"),
        "passed through verbatim"
    );
}

#[test]
fn every_phase_script_stops_at_the_first_error() {
    // Without -e a failing command mid-phase leaves the build running against a half-prepared tree
    // and the failure surfaces somewhere else entirely.
    let BuildPlan::Oci(p) = plan(EgressTier::DenyAll);
    let c = render_context(&p, false);
    for (name, body) in &c.files {
        assert!(body.starts_with("set -e"), "{name} must set -e: {body}");
    }
}

#[test]
fn an_empty_phase_emits_no_layer() {
    let BuildPlan::Oci(mut p) = plan(EgressTier::DenyAll);
    p.deps = "  \n ".into();
    p.system_deps = BTreeSet::new();
    let c = render_context(&p, false);
    assert!(
        !c.dockerfile.contains("# deps"),
        "an empty phase is not an empty layer"
    );
    assert!(!c.files.contains_key("deps.sh"));
    assert!(!c.dockerfile.contains("# setup"));
    assert!(c.dockerfile.contains("# source"));
}

#[test]
fn the_package_manager_follows_the_base_image() {
    let BuildPlan::Oci(mut p) = plan(EgressTier::Open);
    p.base_image = "docker.io/library/alpine@sha256:abc".into();
    assert!(render_context(&p, false).files["setup.sh"].contains("apk add --no-cache"));
    p.base_image = "docker.io/library/fedora@sha256:abc".into();
    assert!(render_context(&p, false).files["setup.sh"].contains("dnf install -y"));
}

#[test]
fn an_enforced_tier_checks_its_base_image_instead_of_installing_into_it() {
    // The image build has no network at an enforced tier, so the setup phase cannot install. It
    // asks the package manager's own database instead, and the query follows the distribution the
    // same way the install command does.
    let BuildPlan::Oci(mut p) = plan(EgressTier::DenyAll);
    let setup = render_context(&p, false).files["setup.sh"].clone();
    assert!(setup.contains("dpkg -s"), "{setup}");
    assert!(
        !setup.contains("apt-get install"),
        "nothing is installed: {setup}"
    );
    // And it says what to do about a package that is absent, because "missing curl" is not an
    // instruction.
    assert!(setup.contains("trigon base-image"), "{setup}");
    // **With the real reference, not a placeholder.** This printed the literal `<this image>`, so
    // the one command a reader needs at the moment they need it was the one thing they had to
    // assemble by hand — from a digest that had scrolled off the top of the same output.
    assert!(
        setup.contains(&format!("--from {}", p.base_image)),
        "the fix names the image it is about: {setup}"
    );
    assert!(
        !setup.contains("<this image>"),
        "a placeholder is not an instruction: {setup}"
    );

    p.base_image = "docker.io/library/alpine@sha256:abc".into();
    assert!(render_context(&p, false).files["setup.sh"].contains("apk info -e"));

    // `open` still installs: it is the tier with a network, and it is where the corpus runs.
    let BuildPlan::Oci(open) = plan(EgressTier::Open);
    assert!(render_context(&open, false).files["setup.sh"].contains("apt-get install"));
}

#[test]
fn a_supplied_checkout_is_copied_in_rather_than_cloned() {
    // The source phase is an image-build layer and rootless `podman build` cannot join the island,
    // so a phase that needs the repository can only run inside the boundary if the repository is
    // already there.
    let BuildPlan::Oci(mut p) = plan(EgressTier::MirrorOnly);
    assert!(
        render_context(&p, false)
            .dockerfile
            .contains("RUN mkdir -p /src /out")
    );
    assert!(
        !render_context(&p, false)
            .dockerfile
            .contains("COPY src /src")
    );

    p.source_tree = Some(std::path::PathBuf::from("/somewhere/checkout"));
    let d = render_context(&p, false).dockerfile;
    assert!(d.contains("COPY src /src"), "{d}");
    assert!(!d.contains("RUN mkdir -p /src /out"), "{d}");
}

#[test]
fn rendering_is_deterministic() {
    let BuildPlan::Oci(p) = plan(EgressTier::DenyAll);
    assert_eq!(render_context(&p, false), render_context(&p, false));
}

#[tokio::test]
async fn a_runner_refuses_an_egress_tier_it_cannot_enforce() {
    // The point of the whole abstraction. There is no allowlisting proxy yet, so mirror-only
    // cannot be enforced, and a runner that accepted the plan anyway would produce a verdict
    // labelled with a tier nothing applied.
    let r = PodmanRunner::new(std::env::temp_dir());
    assert!(!r.accepts(&plan(EgressTier::MirrorOnly)));
    assert!(r.accepts(&plan(EgressTier::DenyAll)));
    assert!(r.accepts(&plan(EgressTier::Open)));

    let e = match r
        .start(&plan(EgressTier::MirrorOnly), &RunOpts::default())
        .await
    {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a tier the runner cannot enforce must not start"),
    };
    assert!(e.contains("cannot enforce mirror-only"), "{e}");
    assert!(
        e.contains("deny-all, open"),
        "it must say what it does offer: {e}"
    );
}

#[tokio::test]
async fn an_unpinned_base_image_is_refused() {
    let r = PodmanRunner::new(std::env::temp_dir());
    let BuildPlan::Oci(mut p) = plan(EgressTier::DenyAll);
    p.base_image = "docker.io/library/python:3.11".into();
    let e = match r.start(&BuildPlan::Oci(p), &RunOpts::default()).await {
        Err(e) => e.to_string(),
        Ok(_) => panic!("an unpinned image must not start"),
    };
    assert!(e.contains("not pinned by digest"), "{e}");
    assert!(e.contains("unreproducible"), "{e}");
}

#[test]
fn routing_says_what_was_on_offer_when_nothing_matches() {
    let runners: Vec<Box<dyn BuildRunner>> =
        vec![Box::new(PodmanRunner::new(std::env::temp_dir()))];
    let e = match route(&runners, &plan(EgressTier::MirrorOnly)) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("nothing should have accepted this"),
    };
    assert!(e.contains("mirror-only"), "what was wanted: {e}");
    assert!(
        e.contains("podman [deny-all, open]"),
        "what was offered: {e}"
    );
}

#[test]
fn a_runner_with_no_mirror_records_no_network_transcript() {
    // The mirror is what makes the transcript: it is the build's only route out under
    // `mirror-only`, and it writes down every body it serves. With no image to run one from there
    // is nothing observing the boundary, and advertising `network` observability would be a claim
    // about a proxy that does not exist.
    let bare = PodmanRunner::new(std::env::temp_dir());
    assert_eq!(bare.caps().observability, ObservabilityTier::None);
    assert!(!bare.caps().exec);

    let equipped = PodmanRunner::new(std::env::temp_dir())
        .with_mirror_image(Some("localhost/trigon-mirror:latest".into()));
    assert_eq!(equipped.caps().observability, ObservabilityTier::Network);
}

#[tokio::test]
async fn mirror_only_is_offered_only_when_a_mirror_image_exists() {
    // The enforcement is an internal network whose only route out is the mirror container. Without
    // an image to run that container from there is no route and no enforcement, so the tier is not
    // advertised and a plan asking for it is refused rather than run with ordinary networking and
    // labelled as though something had been enforced.
    let bare = PodmanRunner::new(std::env::temp_dir());
    assert!(!bare.accepts(&plan(EgressTier::MirrorOnly)));

    let equipped = PodmanRunner::new(std::env::temp_dir())
        .with_mirror_image(Some("localhost/trigon-mirror:latest".into()));
    assert!(equipped.accepts(&plan(EgressTier::MirrorOnly)));
    assert!(
        equipped
            .caps()
            .egress_modes
            .contains(&EgressTier::MirrorOnly),
        "{:?}",
        equipped.caps().egress_modes
    );

    // And the tier that can be enforced is also the tier that can be observed: the same mirror
    // container is both the only route out and the thing that writes down what went through it.
    assert_eq!(equipped.caps().observability, ObservabilityTier::Network);
}

#[tokio::test]
async fn git_and_mirror_is_still_refused() {
    // It needs the allowlisting proxy, which does not exist. Advertising a tier we cannot enforce
    // is the one thing this abstraction is for.
    let r = PodmanRunner::new(std::env::temp_dir())
        .with_mirror_image(Some("localhost/trigon-mirror:latest".into()));
    assert!(!r.accepts(&plan(EgressTier::GitAndMirror)));
    let e = match r
        .start(&plan(EgressTier::GitAndMirror), &RunOpts::default())
        .await
    {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a tier the runner cannot enforce must not start"),
    };
    assert!(e.contains("cannot enforce git-and-mirror"), "{e}");
    assert!(e.contains("mirror-only"), "it says what it does offer: {e}");
}

#[test]
fn an_image_build_failure_names_the_phase_that_died() {
    // Setup, source and deps are all image-build-time layers, and calling every one of them a
    // dependency failure is the difference between "this package does not build" and "our base
    // image has no CA bundle", which is a real thing that happened.
    use trigon_sandbox::failing_phase_for_test as failing_phase;
    let log = "STEP 4/11: COPY source.sh /trigon/source.sh\n\
               STEP 5/11: RUN /bin/sh /trigon/source.sh\n\
               fatal: unable to access 'https://github.com/a/b/': \
               server certificate verification failed\n";
    assert_eq!(failing_phase(log), Some(trigon_sandbox::Phase::Source));

    let deps = "RUN /bin/sh /trigon/source.sh\nok\nRUN /bin/sh /trigon/deps.sh\nboom\n";
    assert_eq!(failing_phase(deps), Some(trigon_sandbox::Phase::Deps));

    assert_eq!(failing_phase("nothing to see"), None);
}

#[test]
fn a_logical_system_dep_renders_for_the_base_image() {
    // A strategy names what it needs, not what a distribution calls it: one that named Debian
    // packages would only build on Debian. `python3 -m venv` needs ensurepip, which Debian ships
    // separately as python3-venv and which no other family has as its own package.
    // At `open`, which is the tier that installs. An enforced tier has no network in the image
    // build, so its setup phase checks instead — covered below.
    let BuildPlan::Oci(mut p) = plan(EgressTier::Open);
    p.system_deps = BTreeSet::from(["python3".to_string(), "git".to_string()]);

    p.base_image = "docker.io/library/debian@sha256:abc".into();
    let setup = render_context(&p, false).files["setup.sh"].clone();
    assert!(setup.contains("python3-venv"), "{setup}");
    assert!(setup.contains("git"), "{setup}");

    p.base_image = "docker.io/library/alpine@sha256:abc".into();
    let setup = render_context(&p, false).files["setup.sh"].clone();
    assert!(setup.contains("apk add"), "{setup}");
    assert!(
        !setup.contains("python3-venv"),
        "there is no such package outside Debian: {setup}"
    );
}

#[test]
fn an_island_whose_process_is_gone_is_collectable_even_while_its_mirror_runs() {
    // `prune_orphans` skipped every *running* container, and a killed-parent orphan is only ever
    // running: a process felled by a wall-clock timeout, a Ctrl-C or an OOM leaves its mirror up,
    // not exited. So the sweep collected only islands that had already tidied themselves, and the
    // leak it exists for survived every later run — one was found at seven hours with that code in
    // place, which is what this test is named after.
    //
    // The predicate is what decides it. Errs toward *alive*, because the failure that matters is
    // one Trigon deleting the network out from under another's running build.
    use trigon_sandbox::owner_is_gone;

    // Our own pid: alive, so its island is never collected however long it has been up.
    let mine = format!("trigon-abc123def456-{}", std::process::id());
    assert!(
        !owner_is_gone(&mine),
        "a live run's island must be left alone"
    );

    // A pid that cannot exist. `/proc` has no entry, so the island is collectable.
    assert!(
        owner_is_gone("trigon-abc123def456-4294967294"),
        "an island whose process is gone is nobody's"
    );

    // A name with no parseable pid is treated as owned rather than guessed at. Somebody may have
    // created it by hand, and a sweeper that removes what it does not understand is worse than one
    // that leaks.
    for odd in [
        "trigon-no-pid-here",
        "trigon-",
        "trigon-abc123def456-notanumber",
    ] {
        assert!(!owner_is_gone(odd), "`{odd}` should be left alone");
    }
}

#[test]
fn the_deferred_build_marks_where_deps_ended() {
    // With deps deferred both phases run in one container and one log, and the attribution asked
    // whether the deps script had been *invoked* — true of every run that got that far. So at an
    // enforced tier every failure was reported as a deps failure: `stub42/pytz` installed its build
    // frontend successfully, failed in `python -m build`, and the record said `build-failed:deps`.
    //
    // The marker is printed between the two under `set -e`, which is what makes its absence mean
    // "deps exited non-zero" rather than "we did not look".
    let BuildPlan::Oci(p) = plan(EgressTier::MirrorOnly);
    let c = render_context(&p, true);
    let build = c.files.get("build.sh").expect("a build script");
    let deps_at = build
        .find("/trigon/deps.sh")
        .expect("the deferred deps invocation");
    let marker_at = build
        .find(trigon_sandbox::DEPS_DONE)
        .expect("the phase marker");
    assert!(
        deps_at < marker_at,
        "the marker has to come after the deps script, or it says nothing: {build}"
    );
    assert!(
        build.starts_with("set -eux"),
        "without `set -e` the marker is printed whether deps succeeded or not: {build}"
    );
}

#[test]
fn a_build_that_runs_its_deps_as_a_layer_needs_no_marker() {
    // Not deferred: the deps phase is an image layer and its failure is a build-image failure, so
    // there is nothing for the run's log to disambiguate.
    let BuildPlan::Oci(p) = plan(EgressTier::DenyAll);
    let c = render_context(&p, false);
    let build = c.files.get("build.sh").expect("a build script");
    assert!(!build.contains(trigon_sandbox::DEPS_DONE), "{build}");
}

#[tokio::test]
async fn a_reference_that_can_only_be_local_and_is_not_there_is_refused_before_the_build() {
    // `is_pinned` checks the *shape* of the string, so `localhost/base@sha256:<stale>` cleared it
    // and podman then spent six seconds discovering it cannot reach a registry called `localhost`.
    // Reported, after all that, as the package failing its dependency phase.
    let r = PodmanRunner::new(std::env::temp_dir());
    let BuildPlan::Oci(mut p) = plan(EgressTier::DenyAll);
    p.base_image =
        "localhost/trigon-base@sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .into();
    let err = r
        .start(&BuildPlan::Oci(p), &RunOpts::default())
        .await
        .err()
        .expect("a reference naming nothing is not a pinned image");
    assert!(
        matches!(err, SandboxError::ImageNotInStore(_)),
        "got {err:?}"
    );
    // Ours or the operator's, never the package's.
    assert_eq!(err.fault(), Fault::Policy);
}

#[test]
fn a_build_that_died_before_any_phase_ran_reports_no_phase() {
    // `failing_phase(&log).unwrap_or(Phase::Deps)` invented a phase, a timing row for it, and a
    // `build-failed:deps` verdict for a run where podman never got past `STEP 1/11: FROM`. At
    // `mirror-only` the invention names the one phase that provably cannot have run there, because
    // `defer_deps` keeps the deps script out of the image entirely.
    let died_at_from = "STEP 1/11: FROM localhost/trigon-base@sha256:7cddd\n\
         Error: creating build container: initializing source docker://localhost/trigon-base: \
         pinging container registry localhost: connection refused";
    assert_eq!(
        trigon_sandbox::failing_phase_for_test(died_at_from),
        None,
        "nothing of ours ran, and `None` is the answer rather than a default"
    );
}

#[test]
fn our_own_steps_are_not_the_packages_fault() {
    // Every site that constructs `Failed` is infrastructure — copying the checkout into the build
    // context, resolving the mirror's address on the island, setting up the network namespace —
    // and its `phase` field names one of *our* steps, not one of the package's. It was classified
    // `Fault::Build`, which is what `docs/03` says `Fault` exists to prevent.
    let ours = SandboxError::Failed {
        phase: "setup".into(),
        detail: "the mirror container has no address on the build's network".into(),
    };
    assert_eq!(ours.fault(), Fault::Infra);

    let refused = SandboxError::RuntimeRefused {
        code: 125,
        detail: "pinging container registry localhost: connection refused".into(),
    };
    assert_eq!(refused.fault(), Fault::Infra);
    // And it says what the runtime said, rather than "unknown".
    assert!(refused.to_string().contains("pinging container registry"));
}

#[test]
fn a_bare_image_id_is_pinned_and_a_tag_is_not() {
    // **Two copies of this rule disagreed, and the disagreement was user-visible.** `base-image`
    // had its own, requiring `@` — while `env/base-image-incomplete` builds its suggested fix
    // command out of whatever `--image` the run used, which for a locally built base is a bare
    // `sha256:<id>`. So Trigon printed a command and then refused to run it.
    for pinned in [
        "sha256:de0f04bb2bdd83d6c2a6ab8a72737852df73e3a2a4e85750434a61a88ca5a3c4",
        // `podman images --no-trunc` prints the hex without the prefix.
        "de0f04bb2bdd83d6c2a6ab8a72737852df73e3a2a4e85750434a61a88ca5a3c4",
        "docker.io/library/debian@sha256:160466e67bb85a4099d9d9c2356b4a6a64747b281a22c1",
    ] {
        assert!(trigon_sandbox::is_pinned(pinned), "{pinned}");
    }
    for moving in [
        "debian:bookworm-slim",
        "localhost/trigon-base:latest",
        "debian",
        // Hex, and the wrong length for an id — a truncated paste rather than a reference.
        "sha256:de0f04bb",
        "",
    ] {
        assert!(!trigon_sandbox::is_pinned(moving), "{moving}");
    }
}

#[test]
fn a_localhost_digest_reference_names_something_podman_cannot_fetch() {
    // **Pinned is not the same as resolvable, and the gap is one podman reports as a network
    // error.** `localhost/name@sha256:…` has the shape of a pinned image, so it passes `is_pinned`;
    // podman then reads `localhost` as a registry hostname and tries to pull over HTTPS from a
    // registry nobody is running. The operator sees `connection refused` about an image sitting on
    // their own disk, and this is the third time that confusion has cost somebody a round trip.
    let r = "localhost/trigon-mirror@sha256:efd6eb2cf0ff249f1908363d7952024abecf1526d8585a4789ea2ca8f588bfaa";
    assert!(trigon_sandbox::is_pinned(r), "it is pinned");
    let err = trigon_sandbox::resolvable(r, false).expect_err("and unfetchable");
    assert!(err.contains("registry hostname"), "{err}");
    // The message has to carry the reference that does work, not just refuse the one that does not.
    assert!(err.contains("sha256:efd6eb2cf0ff249f"), "{err}");

    // Present locally: nothing to complain about, whatever the shape.
    assert!(trigon_sandbox::resolvable(r, true).is_ok());

    // A bare id that is not there says so plainly, and does not explain registries at a reference
    // that names none.
    let absent = trigon_sandbox::resolvable(&format!("sha256:{}", "a".repeat(64)), false)
        .expect_err("a bare id we do not have");
    assert!(absent.contains("is in the local store"), "{absent}");
    assert!(!absent.contains("registry hostname"), "{absent}");

    // A real registry reference is podman's business to resolve, not ours to pre-judge.
    assert!(
        trigon_sandbox::resolvable(
            "docker.io/library/debian@sha256:160466e67bb85a4099d9d9c2356b4a6a64747b2",
            false
        )
        .is_ok()
    );
}

/// A confirming attempt pulls its base image again only where a registry can serve it by digest,
/// and says why not everywhere else, so "re-pulled" is never written about an image that was not.
#[test]
fn only_a_registry_image_pinned_by_digest_can_be_pulled_again() {
    let hex = "a".repeat(64);
    assert!(trigon_sandbox::repullable(&format!("docker.io/library/debian@sha256:{hex}")).is_ok());
    for (image, why) in [
        ("docker.io/library/debian:bookworm", "digest"),
        (
            &*format!("localhost/trigon-base@sha256:{hex}"),
            "only in this machine",
        ),
        (&*format!("sha256:{hex}"), "digest"),
        (&*format!("debian@sha256:{hex}"), "only in this machine"),
        (
            "docker.io/library/debian@sha256:abc",
            "only in this machine",
        ),
    ] {
        let e = trigon_sandbox::repullable(image).unwrap_err();
        assert!(e.contains(why), "{image}: {e}");
    }
}

/// And a pull that could not happen is an error, never a quiet success: with no podman to run,
/// the answer is that it was not pulled.
#[test]
fn a_pull_that_could_not_run_is_not_reported_as_one() {
    let image = format!("docker.io/library/debian@sha256:{}", "b".repeat(64));
    let e = trigon_sandbox::repull("/nonexistent/podman", &image).unwrap_err();
    assert!(e.contains("could not be run"), "{e}");
    let e = trigon_sandbox::repull("/nonexistent/podman", "localhost/x@sha256:00").unwrap_err();
    assert!(e.contains("only in this machine"), "{e}");
}
