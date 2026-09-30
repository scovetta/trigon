//! `scripts/evidence-e2e.sh`'s arguments, and what it refuses before it touches anything.
//!
//! The script rebuilds under podman and needs the network, so no test runs it through. These run
//! it only as far as its argument handling, with `TRIGON` naming no binary and `--dir` inside a
//! scratch directory: a script that went further would stop at the missing binary, having written
//! nothing.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/evidence-e2e.sh")
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-e2e-script-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The script with `args`, its run directory under `dir`, and no trigon to run.
fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new("bash")
        .arg(script())
        .args(args)
        .arg("--dir")
        .arg(dir.join("run"))
        .env("TRIGON", dir.join("no-trigon-here"))
        .output()
        .expect("bash runs")
}

#[test]
fn without_a_package_it_prints_usage_naming_an_example_and_exits_64() {
    // Which package is rebuilt and published is the caller's to say: there is no default to fall
    // back on, so a run without one stops at the arguments, before any directory is made.
    let d = scratch("no-purl");
    for args in [&[][..], &["--egress", "deny-all"][..]] {
        let out = run(&d, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {stderr}");
        assert!(
            stderr.contains("usage: scripts/evidence-e2e.sh PURL"),
            "{args:?}: {stderr}"
        );
        assert!(
            stderr.contains("pkg:npm/wrappy@1.0.2"),
            "{args:?}: {stderr}"
        );
        assert!(
            !d.join("run").exists(),
            "{args:?}: it refused, and made its directory anyway"
        );
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn help_says_the_package_is_required_and_offers_no_default() {
    let d = scratch("help");
    let out = run(&d, &["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("# Usage: scripts/evidence-e2e.sh PURL [--egress"),
        "{stdout}"
    );
    assert!(stdout.contains("required"), "{stdout}");
    assert!(stdout.contains("pkg:npm/wrappy@1.0.2"), "{stdout}");
    assert!(!stdout.contains("default pkg:"), "{stdout}");
    std::fs::remove_dir_all(&d).unwrap();
}
