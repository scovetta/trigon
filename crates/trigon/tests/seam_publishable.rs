//! `docs/19` §10 phase 3 through the binary, where it can be reached with no network and no
//! podman: `trigon rebuild --confirm` refuses a run it cannot repeat before it asks a registry
//! anything, `rebuild --attest` needs the store it signs from, and `trigon serve` reads the
//! confirmation settings from `evidence.toml` and starts with the defaults when there is none.
//!
//! What a confirmation records and what the gate makes of it are asserted beside the code that
//! does each: `crates/trigon/src/main.rs` (`a_run_is_made_publishable`) and
//! `crates/trigon-api/tests/seam_confirmation.rs`.

use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

/// A directory with `store/`, `home/` and `project/` under it.
fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-publishable-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["store", "home", "project"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    d
}

/// `trigon` in `d/project`, with `d/home` as HOME and nothing from this process's `TRIGON_*`, so a
/// developer's own `evidence.toml` changes nothing here.
fn trigon(d: &Path) -> Command {
    let mut c = Command::new(bin());
    c.current_dir(d.join("project"))
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A run that reached a verdict and kept no strategy blob: every run recorded before `docs/19`
/// §10 phase 2.
fn run_without_a_strategy(d: &Path) -> String {
    let store = Store::local(&d.join("store")).unwrap();
    let mut r = RunRecord::new(
        "1789000000-aaaaaaaa",
        "pkg:npm/left-pad@1.3.0",
        ArtifactRef {
            name: "left-pad-1.3.0.tgz".into(),
            sha256: trigon_core::Digest::from_bytes([7u8; 32]),
            bytes: 1,
            stored: false,
        },
        Environment {
            base_image: "docker.io/library/node@sha256:aa".into(),
            derived_image: None,
            egress: "mirror-only".into(),
            isolation: "user_ns".into(),
            attestable: true,
            registry_moment: None,
            pin: None,
            guard_manifest: None,
            guarded_members: None,
        },
        "2026-09-01T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = Some("exact".into());
    r.non_builtin_stabilizer = Some(false);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(store.put_run(&r))
        .unwrap();
    r.id
}

#[test]
fn a_run_with_no_strategy_blob_is_refused_before_anything_is_fetched() {
    let d = dir("no-strategy");
    let id = run_without_a_strategy(&d);
    let store = d.join("store");
    let work = d.join("work");
    let out = trigon(&d)
        .args(["rebuild", "--confirm", &id, "--store"])
        .arg(&store)
        .arg("--work")
        .arg(&work)
        .output()
        .unwrap();
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(said.contains("kept no strategy blob"), "{said}");
    assert!(
        !work.join("run.json").exists(),
        "a refused confirmation leaves no report of a run that did not happen"
    );
}

#[test]
fn a_confirmation_takes_its_target_image_and_tier_from_the_run_and_needs_the_store() {
    let d = dir("confirm-flags");
    for (args, says) in [
        (
            &["rebuild", "--confirm", "1789000000-aaaaaaaa"][..],
            "--store",
        ),
        (
            &[
                "rebuild",
                "--confirm",
                "1789000000-aaaaaaaa",
                "--store",
                "s",
                "--image",
                "docker.io/library/node@sha256:aa",
            ][..],
            "--image",
        ),
        (
            &[
                "rebuild",
                "--confirm",
                "1789000000-aaaaaaaa",
                "--store",
                "s",
                "--egress",
                "open",
            ][..],
            "--egress",
        ),
        (
            &[
                "rebuild",
                "pkg:npm/left-pad@1.3.0",
                "--confirm",
                "1789000000-aaaaaaaa",
                "--store",
                "s",
            ][..],
            "--confirm",
        ),
        (
            &[
                "rebuild",
                "--confirm",
                "1789000000-aaaaaaaa",
                "--store",
                "s",
                "--model",
                "replay:t.json",
            ][..],
            "--model",
        ),
        // And a rebuild that is not a confirmation still names what it rebuilds and on what.
        (&["rebuild", "--image", "x@sha256:aa"][..], "<PURL>"),
        (&["rebuild", "pkg:npm/left-pad@1.3.0"][..], "--image"),
    ] {
        let out = trigon(&d).args(args).output().unwrap();
        let said = text(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {said}");
        assert!(said.contains(says), "{args:?}: {said}");
    }
}

#[test]
fn rebuild_attest_signs_from_a_store_and_says_it_needs_one() {
    let d = dir("attest-needs-store");
    let out = trigon(&d)
        .args([
            "rebuild",
            "pkg:npm/left-pad@1.3.0",
            "--image",
            "x@sha256:aa",
            "--attest",
            "claim.json",
        ])
        .output()
        .unwrap();
    let said = text(&out);
    assert_eq!(out.status.code(), Some(2), "{said}");
    assert!(said.contains("--store"), "{said}");
}

/// Start `trigon serve` on an empty store, bound to a port the system picks, and return what it
/// printed up to the line saying what a confirmation is — then stop it.
fn serve_says(d: &Path) -> Result<String, String> {
    let mut child = trigon(d)
        .arg("serve")
        .arg(d.join("store"))
        .args(["--bind", "127.0.0.1:0", "--refresh-seconds", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("a confirmation is") {
                break;
            }
        }
        let _ = tx.send(seen);
    });
    let got = rx.recv_timeout(Duration::from_secs(60));
    // Ours to stop: it was started above, and it serves until it is.
    let _ = child.kill();
    let status = child.wait().unwrap();
    match got {
        Ok(seen) if seen.contains("a confirmation is") => Ok(seen),
        _ => {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                use std::io::Read as _;
                let _ = e.read_to_string(&mut err);
            }
            Err(format!("{status}: {err}"))
        }
    }
}

#[test]
fn serve_starts_with_no_configuration_and_holds_to_the_defaults() {
    let d = dir("serve-defaults");
    let said = serve_says(&d).expect("serve did not start with no configuration file");
    assert!(
        said.contains("begun 3600s or more after the first, on another machine\n"),
        "{said}"
    );
}

#[test]
fn serve_reads_the_confirmation_settings_from_the_configuration() {
    let d = dir("serve-configured");
    let path = d.join("home/.config/trigon/evidence.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "[publish]\nsame_host_confirmation = true\nconfirmation_interval = \"2h\"\n",
    )
    .unwrap();
    let said = serve_says(&d).expect("serve did not start");
    assert!(
        said.contains(
            "begun 7200s or more after the first, on another machine, or on the same one cold \
             with its image re-pulled"
        ),
        "{said}"
    );

    // And one it cannot read stops it, as it stops every command that reads it.
    std::fs::write(&path, "[publish]\nsame_host_confirmaton = true\n").unwrap();
    let out = trigon(&d)
        .arg("serve")
        .arg(d.join("store"))
        .args(["--bind", "127.0.0.1:0", "--refresh-seconds", "0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert!(
        text(&out).contains("same_host_confirmaton"),
        "{}",
        text(&out)
    );
}
