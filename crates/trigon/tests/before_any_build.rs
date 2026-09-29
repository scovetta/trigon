//! What the commands that build refuse or print before anything is built, pulled or fetched: the
//! Containerfile `base-image --print` renders from its arguments alone, a guard manifest the mirror
//! cannot read, an egress tier that does not exist, and a confirmation of a run that cannot be
//! repeated.
//!
//! `podman` on the `PATH` of every command here is a stand-in that writes down that it was run and
//! fails, so a refusal that reached a container would show.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Pinned, by the sandbox's own rule, which is all `--print` asks of it.
const FROM: &str = concat!(
    "docker.io/library/debian@sha256:",
    "2dd7f3b0a5c1e4d6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1"
);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

/// A directory with `home/` and `shim/` under it, `shim/podman` recording every call.
fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-before-build-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("home")).unwrap();
    std::fs::create_dir_all(d.join("shim")).unwrap();
    let podman = d.join("shim/podman");
    std::fs::write(
        &podman,
        format!(
            "#!/bin/sh\necho \"podman $*\" >> '{}'\nexit 125\n",
            d.join("podman.log").display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&podman, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    d
}

fn trigon(d: &Path, args: &[&std::ffi::OsStr]) -> Output {
    let path = std::env::join_paths(std::iter::once(d.join("shim")).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let mut c = Command::new(bin());
    c.current_dir(d)
        .env("PATH", path)
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"))
        .env("XDG_CACHE_HOME", d.join("home/.cache"))
        .env("TMPDIR", d)
        .env("NO_COLOR", "1")
        .args(args);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.output().unwrap()
}

fn os(args: &[&str]) -> Vec<std::ffi::OsString> {
    args.iter().map(std::ffi::OsString::from).collect()
}

fn run(d: &Path, args: &[std::ffi::OsString]) -> Output {
    let refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
    trigon(d, &refs)
}

fn podman_calls(d: &Path) -> String {
    std::fs::read_to_string(d.join("podman.log")).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// base-image --print
// ---------------------------------------------------------------------------------------------

/// `--print` is a function of its arguments: it renders the Containerfile from two strings, and
/// pulls nothing, builds nothing and asks the local image store nothing — so it can be previewed
/// for an image that is not here yet.
#[test]
fn base_image_print_renders_from_the_arguments_alone() {
    let d = dir("print");
    let out = run(
        &d,
        &os(&[
            "base-image",
            "--from",
            FROM,
            "--packages",
            "wget,git",
            "--packages",
            "git",
            "--print",
        ]),
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(podman_calls(&d), "", "--print ran podman");

    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], format!("FROM {FROM}"));
    // The labels are an index `--image auto` reads without starting a container: what the image
    // carries, sorted and once each, and what it was built from.
    assert!(
        lines.contains(&"LABEL org.trigon.packages=\"git wget\""),
        "{text}"
    );
    assert!(
        lines.contains(&format!("LABEL org.trigon.parent=\"{FROM}\"").as_str()),
        "{text}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("LABEL org.trigon.family=\"")),
        "{text}"
    );
    let install = lines
        .iter()
        .find(|l| l.starts_with("RUN "))
        .unwrap_or_else(|| panic!("nothing is installed:\n{text}"));
    assert!(
        install.contains("git") && install.contains("wget"),
        "{text}"
    );
    assert!(!text.contains("pcl"), "{text}");
}

/// With no packages named, the image carries the default set, which is what the npm and PyPI
/// corpora between them need.
#[test]
fn base_image_print_defaults_to_the_union_the_builtin_tools_ask_for() {
    let d = dir("defaults");
    let out = run(&d, &os(&["base-image", "--from", FROM, "--print"]));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    let label = text
        .lines()
        .find_map(|l| l.strip_prefix("LABEL org.trigon.packages=\""))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap_or_else(|| panic!("no packages label:\n{text}"));
    let packages: Vec<&str> = label.split(' ').collect();
    for wanted in ["git", "python3", "ca-certificates"] {
        assert!(packages.contains(&wanted), "{wanted} is missing: {label}");
    }
    let mut sorted = packages.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(packages, sorted, "the label is sorted and has no repeats");
}

/// The PCL reference assemblies are one pinned file, unpacked with `dpkg-deb -x` — no maintainer
/// script from a third-party repository, nothing written to the package database — and checked to
/// have landed where the build tool looks.
#[test]
fn base_image_print_unpacks_the_pcl_assemblies_rather_than_installing_them() {
    let d = dir("pcl");
    let out = run(
        &d,
        &os(&[
            "base-image",
            "--from",
            FROM,
            "--pcl-reference-assemblies",
            "--print",
        ]),
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains(
            "wget -O /tmp/pcl.deb https://download.mono-project.com/repo/ubuntu/pool/main/r/\
             referenceassemblies-pcl/\
             referenceassemblies-pcl_2014.04.14-1xamarin7+ubuntu2004b1_all.deb"
        ),
        "{text}"
    );
    assert!(
        text.contains("dpkg-deb -x /tmp/pcl.deb /opt/pcl-reference-assemblies"),
        "{text}"
    );
    assert!(!text.contains("dpkg -i"), "{text}");
    assert!(
        text.contains(
            "test -d /opt/pcl-reference-assemblies/usr/lib/mono/xbuild-frameworks/.NETPortable"
        ),
        "{text}"
    );
    assert_eq!(podman_calls(&d), "");
}

/// A tag resolves to different bytes on different days, so `--from` is refused unless pinned —
/// before anything is printed or built.
#[test]
fn base_image_refuses_a_parent_that_is_not_pinned() {
    let d = dir("unpinned");
    for print in [true, false] {
        let mut args = os(&["base-image", "--from", "docker.io/library/debian:bookworm"]);
        if print {
            args.push("--print".into());
        }
        let out = run(&d, &args);
        assert!(!out.status.success(), "print={print}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("pin `--from` by digest or by image id"),
            "{err}"
        );
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("FROM "),
            "print={print}"
        );
    }
    assert_eq!(podman_calls(&d), "");
}

// ---------------------------------------------------------------------------------------------
// The mirror's guard, and the build's tier
// ---------------------------------------------------------------------------------------------

/// A guard manifest the mirror cannot read stops it before it listens: a mirror serving with no
/// guard, or half of one, would be the control failing open.
#[test]
fn a_mirror_whose_guard_cannot_be_read_does_not_start() {
    let d = dir("guard");
    let broken = d.join("guard.json");
    std::fs::write(&broken, "[1, 2").unwrap();
    let out = run(
        &d,
        &[
            "mirror".into(),
            "--port".into(),
            "0".into(),
            "--guard".into(),
            broken.clone().into(),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!("parsing {}", broken.display())),
        "{err}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("listening"));

    let missing = d.join("no-such-guard.json");
    let out = run(
        &d,
        &[
            "mirror".into(),
            "--port".into(),
            "0".into(),
            "--guard".into(),
            missing.clone().into(),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!("reading {}", missing.display())),
        "{err}"
    );
}

/// A tier that does not exist is refused by name, with the ones that do, before a strategy is
/// rendered or a container asked for.
#[test]
fn a_build_at_an_egress_tier_that_does_not_exist_is_refused() {
    let d = dir("egress");
    let strategy = d.join("strategy.yaml");
    std::fs::write(
        &strategy,
        "schema: 1\nkind: flow\nlocation:\n  repo: https://github.com/owner/demo\n  ref: \
         ff8e7ba8b4122829cf66125ca8445cac7f073bce\nsrc:\n- uses: git-checkout\nbuild:\n- runs: npm \
         pack\noutput_path: '*.tgz'\n",
    )
    .unwrap();
    let out = run(
        &d,
        &[
            "build".into(),
            strategy.into(),
            "--image".into(),
            FROM.into(),
            "--egress".into(),
            "sideways".into(),
            "--out".into(),
            d.join("out").into(),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(
            "unknown egress tier `sideways`; one of: deny-all, mirror-only, git-and-mirror, open"
        ),
        "{err}"
    );
    assert_eq!(podman_calls(&d), "");
}

/// `rebuild` and `sweep` refuse a tier that does not exist as they read their arguments, naming
/// the ones that do — before a registry is asked for the package or a strategy chosen, where the
/// build used to be the first to refuse it. `mirror` is the one a help text once offered.
#[test]
fn a_rebuild_or_sweep_at_an_egress_tier_that_does_not_exist_is_refused_before_anything_runs() {
    let d = dir("rebuild-egress");
    let targets = d.join("targets.txt");
    std::fs::write(&targets, "pkg:npm/left-pad@1.3.0\n").unwrap();
    for args in [
        os(&[
            "rebuild",
            "pkg:npm/left-pad@1.3.0",
            "--image",
            FROM,
            "--egress",
            "mirror",
        ]),
        [
            os(&["sweep"]),
            vec![targets.clone().into()],
            os(&["--image", FROM, "--egress", "mirror"]),
        ]
        .concat(),
    ] {
        let out = run(&d, &args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains("'mirror'"), "{args:?}: {err}");
        for tier in ["deny-all", "mirror-only", "git-and-mirror", "open"] {
            assert!(err.contains(tier), "{args:?}: {tier}: {err}");
        }
        assert_eq!(podman_calls(&d), "", "{args:?}");
    }
}

/// A recipe whose build phase renders empty would run, produce nothing, and report a build that
/// succeeded and left no artifact — blaming the run for the recipe. It is refused before a
/// container is asked for.
#[test]
fn a_recipe_that_builds_nothing_is_refused_before_a_container_is_asked_for() {
    let d = dir("empty-build");
    let strategy = d.join("strategy.yaml");
    std::fs::write(
        &strategy,
        "schema: 1\nkind: flow\nlocation:\n  repo: https://github.com/owner/demo\n  ref: \
         ff8e7ba8b4122829cf66125ca8445cac7f073bce\nsrc:\n- uses: git-checkout\noutput_path: \
         out.tgz\n",
    )
    .unwrap();
    let source = d.join("checkout");
    std::fs::create_dir_all(&source).unwrap();
    for egress in ["open", "deny-all"] {
        let out = run(
            &d,
            &[
                "build".into(),
                strategy.clone().into(),
                "--image".into(),
                FROM.into(),
                "--egress".into(),
                egress.into(),
                "--source".into(),
                source.clone().into(),
                "--out".into(),
                d.join("out").into(),
            ],
        );
        assert!(!out.status.success(), "{egress}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("renders an empty build phase"),
            "{egress}: {err}"
        );
        assert_eq!(podman_calls(&d), "", "{egress}");
    }
}

/// A build with no usable container runtime says so, before it starts anything, and leaves no
/// artifact behind it — at an enforced tier with the operator's checkout, which fetches nothing on
/// the host, as at `open`.
#[test]
fn a_build_without_a_usable_runtime_says_so_and_leaves_nothing() {
    let d = dir("no-runtime");
    let strategy = d.join("strategy.yaml");
    std::fs::write(
        &strategy,
        "schema: 1\nkind: flow\nlocation:\n  repo: https://github.com/owner/demo\n  ref: \
         ff8e7ba8b4122829cf66125ca8445cac7f073bce\nsrc:\n- uses: git-checkout\nbuild:\n- runs: npm \
         pack\noutput_path: '*.tgz'\n",
    )
    .unwrap();
    let source = d.join("checkout");
    std::fs::create_dir_all(&source).unwrap();
    for egress in ["open", "mirror-only", "git-and-mirror", "deny-all"] {
        let out_dir = d.join(format!("out-{egress}"));
        let out = run(
            &d,
            &[
                "build".into(),
                strategy.clone().into(),
                "--image".into(),
                FROM.into(),
                "--egress".into(),
                egress.into(),
                "--source".into(),
                source.clone().into(),
                "--out".into(),
                out_dir.clone().into(),
            ],
        );
        assert!(!out.status.success(), "{egress}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("podman is not usable"), "{egress}: {err}");
        let left: Vec<_> = std::fs::read_dir(&out_dir)
            .map(|r| r.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "{egress}: {left:?}");
    }
    // It asked the runtime, and asked it nothing to build.
    let calls = podman_calls(&d);
    assert!(!calls.is_empty());
    for line in calls.lines() {
        assert!(
            !line.starts_with("podman build") && !line.starts_with("podman run"),
            "{calls}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// rebuild --confirm
// ---------------------------------------------------------------------------------------------

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A run that compared at `--egress open`, which the gate calls void.
fn void_run(store: &Path, id: &str) {
    use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};
    let store = Store::local(store).unwrap();
    let mut r = RunRecord::new(
        id,
        "pkg:npm/left-pad@1.3.0",
        ArtifactRef {
            name: "left-pad-1.3.0.tgz".into(),
            sha256: trigon_core::Digest::from_bytes([7u8; 32]),
            bytes: 3619,
            stored: false,
        },
        Environment {
            base_image: FROM.into(),
            derived_image: None,
            egress: "open".into(),
            isolation: String::new(),
            guard_manifest: None,
            guarded_members: None,
            attestable: false,
            registry_moment: None,
            pin: None,
        },
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = Some("exact".into());
    rt().block_on(store.put_run(&r)).unwrap();
}

/// A confirmation of a run that cannot be repeated is refused before a registry is asked anything
/// and before a work directory says a run happened: the refusal is a fact about the record, and
/// no attempt was made.
#[test]
fn a_confirmation_of_a_run_that_cannot_be_repeated_is_refused_before_anything_runs() {
    let d = dir("confirm");
    let store = d.join("store");
    let id = "1789005000-cafecafe";
    void_run(&store, id);
    let work = d.join("work");
    let out = run(
        &d,
        &[
            "rebuild".into(),
            "--confirm".into(),
            id.into(),
            "--store".into(),
            store.clone().into(),
            "--work".into(),
            work.clone().into(),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!("run `{id}` is void (open_egress)")),
        "{err}"
    );
    assert!(!work.exists(), "a work directory says a run happened");
    assert_eq!(podman_calls(&d), "");

    let out = run(
        &d,
        &[
            "rebuild".into(),
            "--confirm".into(),
            "1789005001-00000000".into(),
            "--store".into(),
            store.into(),
            "--work".into(),
            work.clone().into(),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("which --confirm names"), "{err}");
    assert!(!work.exists());
}
