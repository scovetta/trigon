//! `scripts/build-set-module.sh`, as far as what it hands cargo: the flags that make the module
//! reproducible wherever the checkout is, and the commit the module names.
//!
//! A fake `cargo` stands in for the real one and records what it was given, so nothing is compiled
//! here and nothing touches the network. The script building the module for real, and the module
//! naming the commit the script gave it, is `parity.rs`'s test of that commit, which CI's
//! `wasm-parity` job runs; the reproducibility of its bytes is `docs/16-findings.md` §3.109.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/build-set-module.sh")
}

/// Records the environment cargo would read its flags and the commit from, and writes a module
/// where cargo would put one.
const FAKE_CARGO: &str = r#"#!/usr/bin/env bash
set -eu
out="$FAKE_CARGO_OUT"
mkdir -p "$out"
record() { if [ -n "${!1+set}" ]; then printf '%s' "${!1}" > "$out/$2"; fi; }
record CARGO_ENCODED_RUSTFLAGS encoded
record RUSTFLAGS rustflags
record TRIGON_SET_MODULE_COMMIT commit
m="${CARGO_TARGET_DIR:-$PWD/target}/wasm32-unknown-unknown/release"
mkdir -p "$m"
printf 'not really a module' > "$m/trigon_stabilize_wasm.wasm"
"#;

struct Scratch {
    root: PathBuf,
    /// A copy of the script at `<checkout>/scripts/`, where the checkout's path has a space in it.
    checkout: PathBuf,
    cargo_home: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "trigon-set-module-script-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let checkout = root.join("a checkout");
        let cargo_home = root.join("cargo home");
        std::fs::create_dir_all(checkout.join("scripts")).unwrap();
        std::fs::create_dir_all(&cargo_home).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::copy(script(), checkout.join("scripts/build-set-module.sh")).unwrap();
        let cargo = root.join("bin/cargo");
        std::fs::write(&cargo, FAKE_CARGO).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        Scratch {
            checkout: checkout.canonicalize().unwrap(),
            cargo_home: cargo_home.canonicalize().unwrap(),
            root,
        }
    }

    /// The script, with flags and a commit in the environment that it must not pass on.
    fn run(&self) -> Output {
        let path = format!(
            "{}:{}",
            self.root.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let _ = std::fs::remove_dir_all(self.root.join("out"));
        Command::new("bash")
            .arg(self.checkout.join("scripts/build-set-module.sh"))
            .env("PATH", path)
            .env("CARGO_HOME", &self.cargo_home)
            .env("CARGO_TARGET_DIR", self.root.join("target dir"))
            .env("FAKE_CARGO_OUT", self.root.join("out"))
            .env("RUSTFLAGS", "--cfg leaked")
            .env("CARGO_ENCODED_RUSTFLAGS", "--cfg\x1fleaked")
            .env("TRIGON_SET_MODULE_COMMIT", "f".repeat(40))
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .expect("bash runs")
    }

    /// The flags rustc would be given, read as cargo reads them: `CARGO_ENCODED_RUSTFLAGS` split
    /// on 0x1f where it is set, and otherwise `RUSTFLAGS` split on whitespace.
    fn flags(&self) -> Vec<String> {
        let out = self.root.join("out");
        match std::fs::read_to_string(out.join("encoded")) {
            Ok(e) if e.is_empty() => Vec::new(),
            Ok(e) => e.split('\x1f').map(String::from).collect(),
            Err(_) => std::fs::read_to_string(out.join("rustflags"))
                .unwrap_or_default()
                .split_whitespace()
                .map(String::from)
                .collect(),
        }
    }

    fn commit(&self) -> Option<String> {
        std::fs::read_to_string(self.root.join("out/commit")).ok()
    }

    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.checkout)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.org"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}: {out:?}");
    }
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every path is remapped as one flag, a checkout and a `CARGO_HOME` with a space in their paths
/// included: cargo splits `RUSTFLAGS` on whitespace, and a path passed that way came apart into two
/// flags that named neither path, and the module carried the path it was built at. Nothing from the
/// environment is passed on, flags or commit.
#[test]
fn every_path_is_one_flag_and_nothing_in_the_environment_is_passed_on() {
    let s = Scratch::new("flags");
    let said = ok(&s.run());
    let flags = s.flags();
    assert_eq!(
        flags[..2],
        [
            format!("--remap-path-prefix={}=/trigon", s.checkout.display()),
            format!("--remap-path-prefix={}=/cargo", s.cargo_home.display()),
        ],
        "{flags:?}"
    );
    assert!(
        flags.iter().all(|f| f.starts_with("--remap-path-prefix=")),
        "{flags:?}"
    );
    assert!(said.contains("module  "), "{said}");
    assert!(said.contains("sha256  "), "{said}");

    // Not a git checkout: the module names no commit, and the one in the environment is not it.
    assert_eq!(s.commit().as_deref(), Some(""));
    assert!(
        said.contains(&format!(
            "commit  none: {} is not the top of a git checkout",
            s.checkout.display()
        )),
        "{said}"
    );
    std::fs::remove_dir_all(&s.root).unwrap();
}

/// In a git checkout the module names its commit, and `.dirty` after it once the tree has changes
/// the commit does not, as the binary's own version does.
#[test]
fn the_module_names_the_commit_of_the_checkout_and_whether_it_was_clean() {
    let s = Scratch::new("commit");
    s.git(&["init", "-q"]);
    s.git(&["add", "scripts"]);
    s.git(&["commit", "-q", "-m", "the script"]);
    let head = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&s.checkout)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    assert_eq!(head.len(), 40);

    // The fake cargo's module lands outside the checkout, so the tree stays clean.
    let said = ok(&s.run());
    assert_eq!(s.commit().as_deref(), Some(head.as_str()));
    assert!(said.contains(&format!("commit  {head}\n")), "{said}");

    std::fs::write(s.checkout.join("uncommitted"), "a change").unwrap();
    let said = ok(&s.run());
    assert_eq!(s.commit(), Some(format!("{head}.dirty")));
    assert!(said.contains(&format!("commit  {head}.dirty\n")), "{said}");
    std::fs::remove_dir_all(&s.root).unwrap();
}
