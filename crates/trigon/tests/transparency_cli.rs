//! Checking a log entry from the command line, offline.
//!
//! The fixtures are a real `rekor.sigstage.dev` entry (index 56042173) and the bundle it is about,
//! both produced by `trigon attest --rekor` in one run. A hand-made pair could not test the thing
//! that matters — that the log entry and the bundle really do correspond — because the
//! correspondence is a hash the log computed.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn check(bundle: &str, entry: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(bin())
        .arg("verify-attestation")
        .arg(fixture(bundle))
        .arg("--transparency")
        .arg(entry)
        .args(extra)
        .output()
        .unwrap()
}

fn tmp(name: &str, body: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-tlog-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

fn entry_json() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(fixture("logged-entry.json")).unwrap()).unwrap()
}

#[test]
fn a_real_entry_checks_out_against_the_bundle_it_is_about() {
    let out = check("logged-bundle.json", &fixture("logged-entry.json"), &[]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("rekor.sigstage.dev index 56042173"),
        "the log and index are the address of the entry; they have to be shown:\n{text}"
    );
    // The date, not just the raw instant: the timestamp is the whole reason the entry exists, and
    // an operator reading `1789568827` learns nothing from it.
    assert!(text.contains("2026-09-16T"), "{text}");
    assert!(
        text.contains("the entry is about this bundle"),
        "a verifying timestamp on an unrelated entry is not the claim anyone wants:\n{text}"
    );
}

#[test]
fn no_key_had_to_be_supplied_or_fetched() {
    // The key is selected by `logID`, which *is* the SHA-256 of that key — so the compiled-in table
    // is an index rather than an authority, and a wrong row cannot be chosen for this entry. The
    // alternative, fetching the key from the log under test, asks it to vouch for itself.
    let out = check("logged-bundle.json", &fixture("logged-entry.json"), &[]);
    assert!(out.status.success());
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("--log-key"),
        "a known log should not be asking for its own key"
    );
}

#[test]
fn an_entry_about_another_statement_is_refused_rather_than_reported() {
    // The failure mode worth naming: the SET on this entry verifies perfectly. Something really was
    // logged at that instant — just not this. Reporting "logged ✓" here would be the worst kind of
    // wrong, because every individual check passed.
    let out = check("other-bundle.json", &fixture("logged-entry.json"), &[]);
    assert!(!out.status.success(), "an unrelated entry was accepted");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("about a different statement") && err.contains("timestamp is real"),
        "the error has to say the timestamp is real and simply not about this:\n{err}"
    );
}

#[test]
fn a_tampered_timestamp_does_not_verify() {
    let mut e = entry_json();
    e["integrated_time"] = serde_json::json!(1_700_000_000);
    let path = tmp("tampered.json", &e.to_string());
    let out = check("logged-bundle.json", &path, &[]);
    assert!(!out.status.success(), "a rewritten instant was accepted");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("when this entry existed"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_unknown_log_says_what_to_pass_and_warns_against_the_easy_way() {
    let mut e = entry_json();
    e["log_id"] = serde_json::json!("00".repeat(32));
    let path = tmp("unknown-log.json", &e.to_string());
    let out = check("logged-bundle.json", &path, &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--log-key"), "{err}");
    assert!(
        err.contains("rather than fetching it from the log whose signature you are checking"),
        "the obvious fix — fetch the key from the log — is the wrong one, and the message is where \
         to say so:\n{err}"
    );
}

#[test]
fn a_run_record_is_not_a_log_entry_and_the_error_says_how_to_get_one() {
    // The mistake an operator makes first: `--transparency <run>.json`, because the entry lives
    // inside the record. Worth a message that names the jq rather than "invalid JSON".
    let path = tmp(
        "run.json",
        r#"{"id":"run-1","target":"pkg:npm/x@1","state":"done"}"#,
    );
    let out = check("logged-bundle.json", &path, &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("jq .transparency"),
        "the error should hand over the command:\n{err}"
    );
}
