//! What the runner will and will not agree to, and what the container pattern renders to.
//!
//! No container runtime needed: rendering is pure and routing is a decision about capabilities.

use std::collections::BTreeSet;

use trigon_sandbox::{
    BuildPlan, BuildRunner, EgressTier, OciPlan, PodmanRunner, RunOpts, render_context, route,
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
    })
}

#[test]
fn the_context_runs_deps_at_image_build_time_and_writes_the_build() {
    let BuildPlan::Oci(p) = plan(EgressTier::DenyAll);
    let c = render_context(&p);
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
    assert!(c.files["setup.sh"].contains("apt-get install -y --no-install-recommends curl git"));
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
    let c = render_context(&p);
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
    let c = render_context(&p);
    for (name, body) in &c.files {
        assert!(body.starts_with("set -e"), "{name} must set -e: {body}");
    }
}

#[test]
fn an_empty_phase_emits_no_layer() {
    let BuildPlan::Oci(mut p) = plan(EgressTier::DenyAll);
    p.deps = "  \n ".into();
    p.system_deps = BTreeSet::new();
    let c = render_context(&p);
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
    let mut p = match plan(EgressTier::DenyAll) {
        BuildPlan::Oci(p) => p,
    };
    p.base_image = "docker.io/library/alpine@sha256:abc".into();
    assert!(render_context(&p).files["setup.sh"].contains("apk add --no-cache"));
    p.base_image = "docker.io/library/fedora@sha256:abc".into();
    assert!(render_context(&p).files["setup.sh"].contains("dnf install -y"));
}

#[test]
fn rendering_is_deterministic() {
    let BuildPlan::Oci(p) = plan(EgressTier::DenyAll);
    assert_eq!(render_context(&p), render_context(&p));
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
fn a_local_podman_run_is_not_attestable_at_full_trust() {
    // Unproxied, with no network transcript. Good enough to build and compare; not good enough to
    // sign a claim that nothing was fetched.
    assert!(!PodmanRunner::new(std::env::temp_dir()).caps().attestable);
    assert!(!PodmanRunner::new(std::env::temp_dir()).caps().exec);
}
