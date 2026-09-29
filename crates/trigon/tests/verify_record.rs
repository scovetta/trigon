//! `trigon verify-attestation --record <file> --evidence <dir>`, from the command line a person
//! types (`docs/19` §6): the network-free verifier's record form, its sources of keys and
//! checkpoints, what it prints, and the exit codes a CI job reads.
//!
//! Against the golden evidence repository of `crates/trigon-attest/testdata/evidence/`, which
//! `crates/trigon-attest/tests/evidence_repo/golden.rs` describes record by record, copies of it
//! damaged the ways a repository is, and small repositories that test's own builder writes from
//! the same fixed keys, for what the golden one does not hold.

// The writer the golden repository is built by, from the crate whose tests own it: one writer, so
// that a repository built here is laid out, signed and logged exactly as the golden one is.
#[allow(dead_code)]
#[path = "../../trigon-attest/tests/evidence_log/common.rs"]
mod common;
#[allow(dead_code)]
#[path = "../../trigon-attest/tests/evidence_repo/build.rs"]
mod build;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::json;
use trigon_attest::log::{
    Checkpoint, Leaf, LogEndLeaf, LogSigner, RecordLeaf, SignedCheckpoint, Successor,
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../trigon-attest/testdata/evidence")
}

fn repo() -> PathBuf {
    fixture().join("repo")
}

/// A fresh directory of this test's own.
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-record-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn copy_dir(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap() {
        let p = e.unwrap().path();
        let dest = to.join(p.file_name().unwrap());
        if p.is_dir() {
            std::fs::create_dir_all(&dest).unwrap();
            copy_dir(&p, &dest);
        } else {
            std::fs::copy(&p, &dest).unwrap();
        }
    }
}

/// The golden record `name`'s digest, in hex.
fn digest(name: &str) -> String {
    let names: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture().join("records.json")).unwrap()).unwrap();
    names[name]["record"].as_str().unwrap()[7..].to_string()
}

/// The golden record `name`'s file in the repository at `root`.
fn record(root: &Path, name: &str) -> PathBuf {
    let d = digest(name);
    root.join(format!("records/{}/{}/{d}.json", &d[..2], &d[2..4]))
}

/// The golden source's keys, as flags.
fn keys() -> Vec<String> {
    let vkey = std::fs::read_to_string(repo().join("keys/log.vkey")).unwrap();
    vec![
        "--log-vkey".into(),
        vkey.trim().into(),
        "--attestation-key".into(),
        repo().join("keys/attestation.pub").to_str().unwrap().into(),
    ]
}

fn verify(args: &[&str]) -> Output {
    Command::new(bin())
        .arg("verify-attestation")
        .args(args)
        .output()
        .unwrap()
}

/// `verify-attestation --record <name's file> --evidence <root>` with the golden keys, and `more`.
fn check(root: &Path, name: &str, more: &[&str]) -> Output {
    let rec = record(root, name);
    let mut args = vec![
        "--record",
        rec.to_str().unwrap(),
        "--evidence",
        root.to_str().unwrap(),
    ];
    let keys = keys();
    args.extend(keys.iter().map(String::as_str));
    args.extend(more);
    verify(&args)
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_published_verdict_verifies_from_the_directory_and_re_derives_from_its_artifacts() {
    let a = fixture().join("artifacts");
    let out = check(
        &repo(),
        "a2",
        &[
            "--rerun-comparison",
            "--upstream",
            a.join("demo-a-1.0.0.tar").to_str().unwrap(),
            "--rebuild",
            a.join("rebuilt-demo-a-1.0.0.tar").to_str().unwrap(),
        ],
    );
    let said = text(&out);
    assert_eq!(out.status.code(), Some(0), "{said}");
    for line in [
        "example.com/trigon-evidence, 15 leaves, then example.com/trigon-evidence/1, 3 leaves",
        "at leaf 8 of example.com/trigon-evidence",
        "claims    normalized",
        "supersedes sha256:",
        "current   yes",
        "answer    normalized",
        "the claim holds",
        "the published comparison report agrees",
        // A release asset is never in the repository, and is never counted as checked.
        "rebuiltArtifact sha256:",
        "a release asset, not in the repository: unchecked",
        // Nothing was given to hold the log to, and the output says so rather than staying quiet.
        "no --checkpoint",
    ] {
        assert!(said.contains(line), "{line}\n{said}");
    }
}

#[test]
fn every_state_exits_with_the_code_docs_19_6_gives_it() {
    for (name, code, says) in [
        ("a2", 0, "answer    normalized"),
        ("e", 0, "answer    exact"),
        ("k", 0, "at leaf 1 of example.com/trigon-evidence/1"),
        ("b", 1, "answer    divergent"),
        // The withdrawal, and the verdict it withdrew, which is superseded and shown so.
        ("w", 2, "answer    withdrawn"),
        ("d0", 2, "current   no: superseded by"),
        ("c", 3, "answer    void"),
        // Superseded, and verified: what the source says of the artifact is its successor's.
        ("a1", 0, "(set_changed)"),
        ("g", 4, "the key change at leaf 9"),
        ("h", 4, "neither this source's pinned attestation key"),
        ("i", 4, "disagrees with its leaf"),
        ("j", 4, "unlogged"),
    ] {
        let out = check(&repo(), name, &[]);
        let said = text(&out);
        assert_eq!(out.status.code(), Some(code), "{name}: {said}");
        assert!(said.contains(says), "{name}: {says}\n{said}");
    }
}

#[test]
fn a_record_with_one_byte_flipped_fails_verification_with_exit_4() {
    let root = scratch("flipped");
    copy_dir(&repo(), &root);
    let path = record(&root, "e");
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() / 3;
    bytes[at] ^= 0x20;
    std::fs::write(&path, &bytes).unwrap();
    let out = check(&root, "e", &[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("FAILED") || text(&out).contains("NO"));
}

#[test]
fn a_record_whose_evidence_is_not_what_it_signs_fails_and_one_absent_is_unchecked() {
    let root = scratch("evidence");
    copy_dir(&repo(), &root);
    // Every evidence file gone, as from a default clone: unchecked, and the record verifies.
    std::fs::remove_dir_all(root.join("evidence")).unwrap();
    let out = check(&root, "e", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("not in this directory: unchecked"));
    // One there and altered: the record fails.
    copy_dir(&repo().join("evidence"), &{
        std::fs::create_dir_all(root.join("evidence")).unwrap();
        root.join("evidence")
    });
    let json = check(&root, "e", &["--output", "json"]);
    let doc: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let comparison = doc["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "comparison")
        .unwrap()["digest"]
        .as_str()
        .unwrap()[7..]
        .to_string();
    std::fs::write(
        root.join(format!(
            "evidence/sha256/{}/{}/{comparison}",
            &comparison[..2],
            &comparison[2..4]
        )),
        b"not the report",
    )
    .unwrap();
    let out = check(&root, "e", &[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("is not the bytes its statement signs"));
}

/// Carry-over from `docs/19` phase 4a: two trees under one log key, side by side in one
/// repository, is an equivocation. The source is refused with both signed notes, and exits 4.
#[test]
fn two_trees_under_one_log_key_are_an_equivocation_and_exit_4() {
    let root = scratch("equivocation");
    copy_dir(&repo(), &root);
    let key = LogSigner::from_seed("example.com/trigon-evidence", [1; 32]).unwrap();
    let fork = SignedCheckpoint::sign(
        &Checkpoint {
            origin: "example.com/trigon-evidence".into(),
            size: 15,
            root: [7; 32],
        },
        &key,
    )
    .unwrap();
    std::fs::create_dir_all(root.join("log/5")).unwrap();
    std::fs::write(root.join("log/5/checkpoint"), fork.to_string()).unwrap();
    let out = check(&root, "e", &[]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(4), "{said}");
    assert!(said.contains("equivocation"), "{said}");
    // Both signed notes, each by its signature line: the report indents a cause's lines.
    let signature = |note: &str| note.lines().last().unwrap().to_string();
    let real = std::fs::read_to_string(repo().join("log/checkpoint")).unwrap();
    for note in [fork.to_string(), real] {
        assert!(
            said.contains(&signature(&note)),
            "both signed notes: {said}"
        );
    }
    // Whose it is: the source's, never trigon's.
    assert!(said.contains("the evidence source's"), "{said}");

    // And a JSON reader gets a document, with both notes, though no record was read.
    let out = check(&root, "e", &["--output", "json"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", text(&out)));
    assert_eq!(doc["exit"], 4);
    assert_eq!(doc["stopped"], "equivocation");
    let notes: Vec<&str> = doc["signedNotes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["note"].as_str().unwrap())
        .collect();
    assert!(notes.contains(&fork.to_string().as_str()), "{doc}");

    // And a checkpoint given as accepted that the log does not extend is refused the same way.
    let forked = root.join("fork.checkpoint");
    std::fs::write(&forked, fork.to_string()).unwrap();
    let out = check(&repo(), "e", &["--checkpoint", forked.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(
        text(&out).contains("keep both signed notes"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_checkpoint_the_log_extends_is_accepted_and_one_it_is_behind_is_a_rollback() {
    let cp = fixture().join("checkpoints/9.checkpoint");
    let out = check(&repo(), "e", &["--checkpoint", cp.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("held to the checkpoint of 9 leaves"));

    // A clone rolled back behind the checkpoint: the repository as it was at 9 leaves, held to
    // the checkpoint of 14 — refused.
    let root = scratch("rollback");
    copy_dir(&repo(), &root);
    std::fs::copy(
        fixture().join("checkpoints/9.checkpoint"),
        root.join("log/checkpoint"),
    )
    .unwrap();
    std::fs::remove_dir_all(root.join("log/1")).unwrap();
    let later = fixture().join("checkpoints/14.checkpoint");
    let out = check(&root, "a1", &["--checkpoint", later.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("fewer than the 14"), "{}", text(&out));
}

/// `--source <name>`: the keys from `evidence.toml`, and the checkpoint from the state directory,
/// or the source's initial one, or none, each said.
#[test]
fn a_source_is_read_from_the_configuration_and_its_state_directory() {
    let d = scratch("source");
    let config = d.join("evidence.toml");
    let vkey = std::fs::read_to_string(repo().join("keys/log.vkey")).unwrap();
    let initial = fixture().join("checkpoints/7.checkpoint");
    std::fs::write(
        &config,
        format!(
            "[[source]]\nname = \"golden\"\nurls = [\"{}\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\ncheckpoint = \"{}\"\n",
            repo().display(),
            vkey.trim(),
            repo().join("keys/attestation.pub").display(),
            initial.display()
        ),
    )
    .unwrap();
    let state = d.join("state");
    let run = |name: &str| {
        let rec = record(&repo(), "b");
        Command::new(bin())
            .current_dir(&d)
            .env("TRIGON_EVIDENCE_CONFIG", &config)
            .env("TRIGON_EVIDENCE_STATE", &state)
            .env_remove("TRIGON_EVIDENCE_REPO")
            .args(["verify-attestation", "--record"])
            .arg(&rec)
            .arg("--evidence")
            .arg(repo())
            .args(["--source", name])
            .output()
            .unwrap()
    };
    // No state yet: the initial checkpoint the source configures, and the missing state file
    // said, never passed over (§6.1).
    let out = run("golden");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("held to the checkpoint of 7 leaves"),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).contains(&format!("from {}", config.display())),
        "{}",
        text(&out)
    );
    let missing = format!(
        "{} is not there — so its log is held only to the initial checkpoint",
        state.join("golden/checkpoint").display()
    );
    assert!(text(&out).contains(&missing), "{}", text(&out));
    // The state directory's, once a sync has accepted one; names compare ignoring ASCII case.
    std::fs::create_dir_all(state.join("golden")).unwrap();
    std::fs::copy(
        fixture().join("checkpoints/14.checkpoint"),
        state.join("golden/checkpoint"),
    )
    .unwrap();
    let out = run("Golden");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("held to the checkpoint of 14 leaves"),
        "{}",
        text(&out)
    );
    assert!(!text(&out).contains("is not there"), "{}", text(&out));
    // A state file that is not a checkpoint: a damaged local input, which the source is never
    // blamed for: 5, naming the file.
    std::fs::write(state.join("golden/checkpoint"), "not a checkpoint\n").unwrap();
    let out = run("golden");
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert!(
        text(&out).contains(&format!(
            "{} is not a checkpoint",
            state.join("golden/checkpoint").display()
        )),
        "{}",
        text(&out)
    );
    assert!(!text(&out).contains("evidence source's"), "{}", text(&out));
    // A state checkpoint the log does not extend: refused, 4.
    let key = LogSigner::from_seed("example.com/trigon-evidence", [1; 32]).unwrap();
    let fork = SignedCheckpoint::sign(
        &Checkpoint {
            origin: "example.com/trigon-evidence".into(),
            size: 14,
            root: [3; 32],
        },
        &key,
    )
    .unwrap();
    std::fs::write(state.join("golden/checkpoint"), fork.to_string()).unwrap();
    let out = run("golden");
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    // No such source: the tool could not check at all, 5.
    let out = run("nowhere");
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert!(
        text(&out).contains("the sources configured are golden"),
        "{}",
        text(&out)
    );
}

#[test]
fn arguments_that_cannot_be_checked_exit_5() {
    let rec = record(&repo(), "b");
    let rec = rec.to_str().unwrap();
    let r = repo();
    let r = r.to_str().unwrap();
    let keys = keys();
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let a = fixture().join("artifacts/demo-a-1.0.0.tar");
    let a = a.to_str().unwrap();
    let unlogged = record(&repo(), "j");
    let unlogged = unlogged.to_str().unwrap();
    let not_a_checkpoint = fixture().join("records.json");
    let not_a_checkpoint = not_a_checkpoint.to_str().unwrap();
    let joined = format!("--record={rec}");
    for (args, says) in [
        // What `clap` refuses exits 5 in this form too, not the 2 §6 gives "never checked".
        (
            [
                vec!["--record", rec, "--evidence", r, "--upstream", a],
                keys.clone(),
            ]
            .concat(),
            "--rerun-comparison",
        ),
        (
            [
                vec!["--record", rec, "--evidence", r, "--rebuild", a],
                keys.clone(),
            ]
            .concat(),
            "--rerun-comparison",
        ),
        (
            [vec!["--record", rec, "--evidence", r, "--bogus"], keys.clone()].concat(),
            "--bogus",
        ),
        (
            [vec![joined.as_str(), "--evidence", r, "--bogus"], keys.clone()].concat(),
            "--bogus",
        ),
        (
            [
                vec!["--record", rec, "--evidence", r, "--stabilizers", a],
                keys.clone(),
            ]
            .concat(),
            "--stabilizers",
        ),
        // `--rerun-comparison`'s arguments are checked before the record is, so a record that
        // fails verification does not turn a bad one into a 4 (§6: 5 before 4).
        (
            [
                vec!["--record", unlogged, "--evidence", r, "--rerun-comparison"],
                keys.clone(),
            ]
            .concat(),
            "needs both --upstream",
        ),
        (
            [
                vec!["--record", rec, "--evidence", r, "--rerun-comparison"],
                keys.clone(),
            ]
            .concat(),
            "needs both --upstream",
        ),
        (
            [
                vec![
                    "--record",
                    unlogged,
                    "--evidence",
                    r,
                    "--rerun-comparison",
                    "--upstream",
                    "/nonexistent",
                    "--rebuild",
                    a,
                ],
                keys.clone(),
            ]
            .concat(),
            "--upstream /nonexistent",
        ),
        // A checkpoint that is not one is a bad argument, not the source failing verification.
        (
            [
                vec![
                    "--record",
                    rec,
                    "--evidence",
                    r,
                    "--checkpoint",
                    not_a_checkpoint,
                ],
                keys.clone(),
            ]
            .concat(),
            "is not a checkpoint",
        ),
        (vec!["--record", rec], "--evidence"),
        (vec!["--record", rec, "--evidence", r], "--source"),
        (
            [
                vec!["--record", rec, "--evidence", "/nonexistent"],
                keys.clone(),
            ]
            .concat(),
            "not a directory",
        ),
        (
            [
                vec!["--record", rec, "--evidence", r, "--source", "x"],
                keys.clone(),
            ]
            .concat(),
            "--source",
        ),
        (
            [
                vec!["--record", rec, "--evidence", r, "--public-key", "00"],
                keys.clone(),
            ]
            .concat(),
            "--public-key",
        ),
        (
            [
                vec!["b.json", "--record", rec, "--evidence", r],
                keys.clone(),
            ]
            .concat(),
            "not both",
        ),
        (vec!["b.json", "--evidence", r], "--record"),
        (vec![], "--record <file> --evidence <dir>"),
        (
            vec![
                "--record",
                rec,
                "--evidence",
                r,
                "--log-vkey",
                "nonsense",
                "--attestation-key",
                "00",
            ],
            "--log-vkey",
        ),
    ] {
        let out = verify(&args);
        assert_eq!(out.status.code(), Some(5), "{args:?}: {}", text(&out));
        assert!(
            text(&out).contains(says),
            "{args:?}: {says}\n{}",
            text(&out)
        );
    }
    // `--rerun-comparison` of a void, which makes no comparison claim, is a check not made.
    let out = check(
        &repo(),
        "c",
        &["--rerun-comparison", "--upstream", a, "--rebuild", a],
    );
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    // And re-deriving from the wrong file is a mistake, not a refutation.
    let out = check(
        &repo(),
        "b",
        &["--rerun-comparison", "--upstream", a, "--rebuild", a],
    );
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert!(
        text(&out).contains("not the one this statement is about"),
        "{}",
        text(&out)
    );
}

#[test]
fn the_json_report_carries_the_record_its_answer_and_its_exit_code() {
    let out = check(&repo(), "d0", &["--output", "json"]);
    assert_eq!(out.status.code(), Some(2));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["exit"], 2);
    assert_eq!(doc["verified"], true);
    assert_eq!(doc["answer"], "withdrawn");
    assert_eq!(doc["claims"], "exact");
    assert_eq!(
        doc["supersededBy"][0]["record"],
        format!("sha256:{}", digest("w"))
    );
    assert_eq!(doc["leaf"]["index"], 3);

    let out = check(&repo(), "j", &["--output", "json"]);
    assert_eq!(out.status.code(), Some(4));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["verified"], false);
    assert_eq!(doc["failure"]["kind"], "unlogged");
}

/// Carry-over from phase 4a: a bundle whose signature does not verify is the evidence's fault,
/// never "a bug in trigon", and the bundle form is otherwise unchanged.
#[test]
fn a_bundle_whose_signature_does_not_verify_is_the_evidences_fault() {
    let d = scratch("bundle");
    let a = fixture().join("artifacts/demo-a-1.0.0.tar");
    let b = fixture().join("artifacts/rebuilt-demo-a-1.0.0.tar");
    let key = d.join("k.key");
    let made = Command::new(bin())
        .args(["keygen", "--out"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", text(&made));
    let bundle = d.join("b.json");
    let made = Command::new(bin())
        .arg("verify")
        .arg(&a)
        .arg(&b)
        .arg("--attest")
        .arg(&bundle)
        .arg("--key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", text(&made));
    let other = "0".repeat(63) + "1";
    let out = verify(&[bundle.to_str().unwrap(), "--public-key", &other]);
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("no signature on this bundle verifies"),
        "{said}"
    );
    assert!(
        said.contains("the evidence's: it failed verification"),
        "{said}"
    );
    assert!(!said.contains("bug in trigon"), "{said}");
}

/// `docs/19` §4.2: every client that shows a record renders its set, when and which Trigon, the
/// egress tier and `attestable`, the derivation method, and for a verdict the command that would
/// falsify it and where to dispute it; §8, never an outcome without the last two. As signed, in
/// both forms, and absent shown as absent.
#[test]
fn a_record_is_shown_with_every_field_docs_19_4_2_has_a_client_render() {
    let subject = std::fs::read_to_string(fixture().join("records.json")).unwrap();
    let names: serde_json::Value = serde_json::from_str(&subject).unwrap();
    let subject = names["b"]["subject"].as_str().unwrap();

    // A divergence.
    let out = check(&repo(), "b", &[]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(1), "{said}");
    for line in [
        "claims    divergent",
        "set       tar, sha256:",
        "run       1789000000-bbbbbbbb, 2026-09-27T00:00:00Z to 2026-09-27T00:02:00Z",
        "trigon    built by 0.0.0+git.1111111111111111111111111111111111111111, signed by \
         0.0.0+git.2222222222222222222222222222222222222222",
        "egress    mirror-only, attestable",
        "derived   heuristic",
        &format!(
            "falsify   trigon verify-attestation --lookup sha256:{subject} --predicate \
             https://trigon.dev/divergence/v2 --origin example.com/trigon-evidence \
             --rerun-comparison --upstream <file>"
        ),
        "dispute   https://example.com/trigon-evidence/issues",
    ] {
        assert!(said.contains(line), "{line}\n{said}");
    }
    let out = check(&repo(), "b", &["--output", "json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["stabilizerSet"]["id"], "tar");
    assert_eq!(doc["run"]["id"], "1789000000-bbbbbbbb");
    assert_eq!(doc["run"]["finishedOn"], "2026-09-27T00:02:00Z");
    assert_eq!(
        doc["trigonVersion"]["builder"],
        "0.0.0+git.1111111111111111111111111111111111111111"
    );
    assert_eq!(doc["egressTier"], "mirror-only");
    assert_eq!(doc["attestable"], true);
    assert_eq!(doc["derivation"], "heuristic");
    assert_eq!(doc["falsifyingCommand"]["argv"][3], format!("sha256:{subject}"));
    assert_eq!(
        doc["disputePointer"],
        json!({"kind": "url", "url": "https://example.com/trigon-evidence/issues"})
    );

    // A void: its reason and its run, no set where its guard stopped the build before any
    // comparison, and no command to falsify, since it makes no claim.
    let out = check(&repo(), "c", &[]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(3), "{said}");
    for line in [
        "claims    void, because guard_tripped",
        "set       none: the run reached no comparison",
        "run       1789000000-cccccccc, 2026-09-27T00:00:00Z to 2026-09-27T00:02:00Z",
        "trigon    built by 0.0.0+git.1111",
        "egress    mirror-only, attestable",
    ] {
        assert!(said.contains(line), "{line}\n{said}");
    }
    assert!(!said.contains("falsify"), "{said}");
    let out = check(&repo(), "c", &["--output", "json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["because"], "guard_tripped");
    assert_eq!(doc["run"]["id"], "1789000000-cccccccc");
    assert_eq!(doc["stabilizerSet"], serde_json::Value::Null);
    assert_eq!(doc["falsifyingCommand"], serde_json::Value::Null);

    // An equivalence signed with no derivation and no dispute pointer, which only a divergence
    // must carry: each said to be absent, never shown as a value.
    let p = build::pairs();
    let k3 = common::attestation_key(3);
    let without = |fields: &'static [&'static str]| {
        build::resigned(
            &build::verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, common::T0),
            &k3,
            common::T0,
            None,
            move |i, st| {
                if i == 0 {
                    let o = st.predicate.as_object_mut().unwrap();
                    for field in fields {
                        o.remove(*field);
                    }
                }
            },
        )
    };
    let bare = without(&["derivation", "disputePointer"]);
    let root = scratch("bare");
    build::small(&root, &[&bare]);
    let out = check_made(&root, &bare, &[]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(0), "{said}");
    for line in [
        "derived   not recorded: the statement names no derivation method",
        "dispute   none signed",
    ] {
        assert!(said.contains(line), "{line}\n{said}");
    }

    // A verdict with no command that would falsify it is never rendered: it fails verification,
    // exit 4, since a client never renders an outcome it cannot show with one (docs/19 §8).
    let bare = without(&["falsifyingCommand"]);
    let root = scratch("no-command");
    build::small(&root, &[&bare]);
    let out = check_made(&root, &bare, &[]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(4), "{said}");
    assert!(said.contains("signs no falsifying command"), "{said}");
}

/// `verify-attestation --record <m's file> --evidence <root>`, with the keys `build.rs` signs
/// and logs with, and `more`.
fn check_made(root: &Path, m: &build::Made, more: &[&str]) -> Output {
    let rec = root.join(trigon_attest::evidence::record_path(&m.digest));
    let vkey = common::log_key().vkey().to_string();
    let key = common::attestation_key(3).public_hex();
    let mut args = vec![
        "--record",
        rec.to_str().unwrap(),
        "--evidence",
        root.to_str().unwrap(),
        "--log-vkey",
        &vkey,
        "--attestation-key",
        &key,
    ];
    args.extend(more);
    verify(&args)
}

/// `pair`'s two artifacts, written where `--upstream` and `--rebuild` can read them.
fn artifacts(dir: &Path, pair: &build::Pair) -> (String, String) {
    let (u, r) = (dir.join("upstream.tar"), dir.join("rebuilt.tar"));
    std::fs::write(&u, &pair.upstream).unwrap();
    std::fs::write(&r, &pair.rebuilt).unwrap();
    (u.display().to_string(), r.display().to_string())
}

/// The record form's central guarantee: a logged, verified verdict whose claim the bytes refute
/// exits 4, however it is refuted — what it says the comparison found, a stabilized digest, a
/// subject digest, or the comparison report it signs beside it.
#[test]
fn a_claim_rerun_comparison_refutes_exits_4() {
    let p = build::pairs();
    let k3 = common::attestation_key(3);
    let honest = build::verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, common::T0);
    let dir = scratch("refuted");
    let (u, r) = artifacts(&dir, &p["b"]);
    let rerun = ["--rerun-comparison", "--upstream", &u, "--rebuild", &r];

    // The honest one holds, so each refusal below is about its lie.
    let root = dir.join("honest");
    build::small(&root, &[&honest]);
    let out = check_made(&root, &honest, &rerun);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("the claim holds"), "{}", text(&out));

    // A report whose member digest is not the bytes', signed as the verdict's evidence: it matches
    // the digest the verdict signs, and disagrees with re-deriving.
    let mut report: serde_json::Value = serde_json::from_slice(&honest.evidence[1]).unwrap();
    assert!(report["diff"]["files"][0]["rebuild_digest"].is_string());
    report["diff"]["files"][0]["rebuild_digest"] = "0".repeat(64).into();
    let lying = serde_json::to_vec(&report).unwrap();
    let signs = build::sha256(&lying).to_hex();
    let mut evidence = honest.evidence.clone();
    evidence[1] = lying;

    type Edit = Box<dyn Fn(usize, &mut trigon_attest::Statement)>;
    type Evidence = Option<Vec<Vec<u8>>>;
    let lies: [(&str, Evidence, Edit, &str); 4] = [
        (
            "differences",
            None,
            Box::new(|i, st| {
                if i == 0 {
                    st.predicate["differences"] = json!(["mode@package/index.js"]);
                }
            }),
            "the claim does NOT hold",
        ),
        (
            "stabilized",
            None,
            Box::new(|i, st| {
                if i == 0 {
                    st.predicate["stabilized"]["upstream"]["sha256"] = "0".repeat(64).into();
                }
            }),
            "the claim does NOT hold: the statement claims",
        ),
        (
            "subject",
            None,
            // The verdict's subject and its observation's, so that the record verifies and only
            // the bytes refute it.
            Box::new(|i, st| {
                if i != 1 {
                    st.subject[0]
                        .digest
                        .insert("sha512".into(), "ab".repeat(64));
                }
            }),
            "its digests were not all computed over one file",
        ),
        (
            "report",
            Some(evidence),
            Box::new(move |i, st| {
                if i == 0 {
                    st.predicate["evidence"]["comparison"]["sha256"] = signs.clone().into();
                }
            }),
            "the published comparison report does NOT agree",
        ),
    ];
    for (what, evidence, edit, says) in lies {
        let m = build::resigned(&honest, &k3, common::T0, evidence, edit);
        let root = dir.join(what);
        build::small(&root, &[&m]);
        // Verified as a record: what refutes it is the bytes, and only under --rerun-comparison.
        let out = check_made(&root, &m, &[]);
        assert_eq!(out.status.code(), Some(1), "{what}: {}", text(&out));
        let out = check_made(&root, &m, &rerun);
        let said = text(&out);
        assert_eq!(out.status.code(), Some(4), "{what}: {said}");
        assert!(said.contains(says), "{what}: {says}\n{said}");
        assert!(said.contains("verified under"), "{what}: {said}");
        // And the JSON reader gets the whole report, with the refutation in it.
        let mut json = rerun.to_vec();
        json.extend(["--output", "json"]);
        let out = check_made(&root, &m, &json);
        assert_eq!(out.status.code(), Some(4), "{what}: {}", text(&out));
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{what}: {e}: {}", text(&out)));
        assert_eq!(doc["exit"], 4, "{what}");
        assert_eq!(doc["verified"], true, "{what}");
        let refuted =
            doc["rederived"]["holds"] == false || doc["report"]["agrees"] == false;
        assert!(refuted, "{what}: {doc}");
    }
}

/// A record logged a second time after its withdrawal would, judged leaf by leaf, answer again,
/// with no fork: it fails verification, and the command exits 4.
#[test]
fn a_record_logged_twice_fails_verification_and_exits_4() {
    let p = build::pairs();
    let k3 = common::attestation_key(3);
    let d0 = build::verdict(&p["d"], &k3, "1789000000-dddddddd", None, common::T0);
    let w = build::withdrawal(&d0, &k3, common::T0 + 60);
    let again = build::Made {
        leaf: RecordLeaf {
            time: common::T0 + 120,
            ..d0.leaf.clone()
        },
        ..d0.clone()
    };
    let root = scratch("twice");
    build::small(&root, &[&d0, &w, &again]);
    let out = check_made(&root, &d0, &[]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(4), "{said}");
    assert!(said.contains("at 2 leaves — leaf 0 of log 0, leaf 2 of log 0"), "{said}");
    assert!(!said.contains("answer    exact"), "{said}");
    // The withdrawal verifies, and what the source says of the artifact is still a failure.
    let out = check_made(&root, &w, &["--output", "json"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["verified"], true);
    assert!(
        doc["answer"].as_str().unwrap().contains("failed verification"),
        "{doc}"
    );
}

/// A log that continues in a repository the directory does not hold may hold, past what is here,
/// the withdrawal of the very record checked: never answered as current, and 4, as a source that
/// cannot say what it says now. A checkpoint given for that log, or any other the directory does
/// not hold, is said to be unchecked, never one the log is held to.
#[test]
fn a_log_that_continues_elsewhere_answers_unknown_and_exits_4() {
    let p = build::pairs();
    let k3 = common::attestation_key(3);
    let a = build::verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, common::T0);
    let root = scratch("continues");
    let mut log = common::Writer::init(&root.join("log"), common::log_key());
    log.append(&[
        Leaf::Record(a.leaf.clone()),
        Leaf::LogEnd(LogEndLeaf {
            time: common::T0 + 60,
            successor: Successor {
                origin: common::SUCCESSOR.into(),
                log_key: common::successor_key().vkey().to_string(),
                urls: vec!["https://example.org/next.git".into()],
                dir: "log".into(),
            },
        }),
    ]);
    a.write(&root);

    let out = check_made(&root, &a, &[]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(4), "{said}");
    for line in [
        "record    sha256:",
        "current   unknown",
        "answer    unknown — the log continues as `example.com/trigon-evidence/1` at \
         https://example.org/next.git",
    ] {
        assert!(said.contains(line), "{line}\n{said}");
    }
    assert!(!said.contains("current   yes"), "{said}");

    // A checkpoint of the successor, as a client that followed it would hold, and one of a log
    // with nothing to do with this one: neither is checked here, and neither is said to be.
    let sign = |signer: &LogSigner, size| {
        SignedCheckpoint::sign(
            &Checkpoint {
                origin: signer.name().to_string(),
                size,
                root: [5; 32],
            },
            signer,
        )
        .unwrap()
        .to_string()
    };
    let unrelated = LogSigner::from_seed("example.net/unrelated", [6; 32]).unwrap();
    for (name, note, says) in [
        (
            "successor.checkpoint",
            sign(&common::successor_key(), 50),
            "the log this repository's chain continues into in another repository",
        ),
        (
            "unrelated.checkpoint",
            sign(&unrelated, 3),
            "which is no log this directory holds",
        ),
    ] {
        let cp = root.join(name);
        std::fs::write(&cp, note).unwrap();
        let out = check_made(&root, &a, &["--checkpoint", cp.to_str().unwrap()]);
        let said = text(&out);
        assert_eq!(out.status.code(), Some(4), "{name}: {said}");
        assert!(said.contains(says), "{name}: {said}");
        assert!(said.contains("it was not checked here"), "{name}: {said}");
        assert!(!said.contains("held to the checkpoint"), "{name}: {said}");
        assert!(!said.contains("current   yes"), "{name}: {said}");
    }
}

/// A JSON reader gets a document on every exit but `clap`'s refusals, naming what stopped the check
/// before any record was read (`docs/19` §6): arguments that cannot be checked, 5, whether the
/// command line or the check refused them; a log whose checkpoint another key of its name signed,
/// 4, as the source failing verification; one whose leaves are not there, 4, as a log that cannot
/// be read, which says nothing of the source's honesty; and a log behind the checkpoint it is held
/// to, 4, with both signed notes, as §8 has a client keep them.
#[test]
fn a_json_reader_is_told_what_stopped_the_check() {
    let stopped = |out: &Output, code: i32| -> serde_json::Value {
        assert_eq!(out.status.code(), Some(code), "{}", text(out));
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{e}: {}", text(out)));
        assert_eq!(doc["exit"], code, "{doc}");
        assert!(doc["error"].is_string(), "{doc}");
        doc
    };
    // No keys to check it against: the tool could not check at all.
    let rec = record(&repo(), "e");
    let out = verify(&[
        "--record",
        rec.to_str().unwrap(),
        "--evidence",
        repo().to_str().unwrap(),
        "--output",
        "json",
    ]);
    let doc = stopped(&out, 5);
    assert_eq!(doc["stopped"], "cannot-check", "{doc}");
    assert!(doc["error"].as_str().unwrap().contains("--source"), "{doc}");
    assert_eq!(doc["signedNotes"], serde_json::Value::Null, "{doc}");
    // So are arguments refused once they are read, whatever refuses them: a bundle's key given to
    // the record form, a bundle beside a record, and, in the network-free verifier, `--lookup`.
    let root = repo();
    let (rec, r) = (rec.to_str().unwrap(), root.to_str().unwrap());
    let subject = format!("sha256:{}", "0".repeat(64));
    let mut refused = vec![
        (
            vec!["--record", rec, "--evidence", r, "--public-key", "00"],
            "--public-key",
        ),
        (vec!["b.json", "--record", rec, "--evidence", r], "not both"),
    ];
    if cfg!(not(feature = "build")) {
        refused.push((vec!["--lookup", &subject], "network-free verifier"));
    }
    for (args, says) in refused {
        let doc = stopped(&verify(&[&args[..], &["--output", "json"]].concat()), 5);
        assert_eq!(doc["stopped"], "cannot-check", "{args:?}: {doc}");
        assert!(
            doc["error"].as_str().unwrap().contains(says),
            "{args:?}: {doc}"
        );
    }
    // Only what `clap` refuses, before `--output` is read, prints no document: still 5.
    let out = verify(&["--record", rec, "--bogus", "--output", "json"]);
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert!(out.stdout.is_empty(), "{}", text(&out));

    // The checkpoint signed again by another key under the log's own name.
    let root = scratch("json-other-key");
    copy_dir(&repo(), &root);
    let note = std::fs::read(root.join("log/checkpoint")).unwrap();
    let cp = Checkpoint::parse(
        trigon_attest::log::SignedNote::parse(&note)
            .unwrap()
            .text(),
    )
    .unwrap();
    let other = LogSigner::from_seed("example.com/trigon-evidence", [9; 32]).unwrap();
    std::fs::write(
        root.join("log/checkpoint"),
        SignedCheckpoint::sign(&cp, &other).unwrap().to_string(),
    )
    .unwrap();
    let doc = stopped(&check(&root, "e", &["--output", "json"]), 4);
    assert_eq!(doc["stopped"], "log-failed-verification", "{doc}");
    // And in text, the source's fault, never trigon's.
    let said = text(&check(&root, "e", &[]));
    assert!(said.contains("the evidence source's"), "{said}");

    // The checkpoint as signed, and the leaves it signs not there to be read.
    std::fs::copy(repo().join("log/checkpoint"), root.join("log/checkpoint")).unwrap();
    std::fs::remove_file(root.join("log/tile/entries/000.p/15")).unwrap();
    let doc = stopped(&check(&root, "e", &["--output", "json"]), 4);
    assert_eq!(doc["stopped"], "log-unreadable", "{doc}");

    // Rolled back behind the checkpoint given as accepted: both notes, the accepted first.
    let root = scratch("json-rollback");
    copy_dir(&repo(), &root);
    let behind = fixture().join("checkpoints/9.checkpoint");
    std::fs::copy(&behind, root.join("log/checkpoint")).unwrap();
    std::fs::remove_dir_all(root.join("log/1")).unwrap();
    let later = fixture().join("checkpoints/14.checkpoint");
    let doc = stopped(
        &check(
            &root,
            "a1",
            &["--checkpoint", later.to_str().unwrap(), "--output", "json"],
        ),
        4,
    );
    assert_eq!(doc["stopped"], "inconsistent", "{doc}");
    let notes = doc["signedNotes"].as_array().unwrap();
    assert_eq!(notes.len(), 2, "{doc}");
    assert_eq!(
        notes[0]["accepted"],
        std::fs::read_to_string(&later).unwrap(),
        "{doc}"
    );
    assert!(notes[1]["offered"].is_string(), "{doc}");
}

/// The source form reads its keys and checkpoint from the configuration and the state, so keys
/// given beside `--source` are refused whether or not a directory is given; and each file
/// `--rerun-comparison` reads must be a file. Both before anything is verified: 5.
#[test]
fn the_source_form_and_the_rerun_files_take_only_what_they_read() {
    let rec = record(&repo(), "b");
    let keys = keys();
    let mut args = vec!["--record", rec.to_str().unwrap(), "--source", "golden"];
    args.extend(keys.iter().map(String::as_str));
    let out = verify(&args);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(5), "{said}");
    assert!(
        said.contains("--source takes the source's keys and checkpoint from its configuration"),
        "{said}"
    );

    let dir = fixture().join("artifacts");
    let a = dir.join("demo-a-1.0.0.tar");
    let out = check(
        &repo(),
        "a2",
        &[
            "--rerun-comparison",
            "--upstream",
            dir.to_str().unwrap(),
            "--rebuild",
            a.to_str().unwrap(),
        ],
    );
    let said = text(&out);
    assert_eq!(out.status.code(), Some(5), "{said}");
    assert!(said.contains("is not a file"), "{said}");
}

/// Re-deriving holds the published comparison report to the claim only where the report can be
/// read. From a directory without the evidence, as a default clone is, the claim is re-derived,
/// and the report is said to be unchecked — never agreeing, and never failing — so the record
/// answers as it does.
#[test]
fn a_report_the_directory_does_not_hold_is_unchecked_and_never_agrees() {
    let root = scratch("no-report");
    copy_dir(&repo(), &root);
    std::fs::remove_dir_all(root.join("evidence")).unwrap();
    let a = fixture().join("artifacts");
    let rerun = [
        "--rerun-comparison",
        "--upstream",
        &a.join("demo-a-1.0.0.tar").display().to_string(),
        "--rebuild",
        &a.join("rebuilt-demo-a-1.0.0.tar").display().to_string(),
    ]
    .map(String::from);
    let rerun: Vec<&str> = rerun.iter().map(String::as_str).collect();
    let out = check(&root, "a2", &rerun);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(said.contains("the claim holds"), "{said}");
    assert!(said.contains("report    unchecked: sha256:"), "{said}");
    assert!(said.contains("not in this directory: unchecked"), "{said}");
    assert!(!said.contains("agrees with the re-derivation"), "{said}");

    let mut json = rerun.clone();
    json.extend(["--output", "json"]);
    let out = check(&root, "a2", &json);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["report"]["agrees"], serde_json::Value::Null, "{doc}");
    assert!(
        doc["report"]["unchecked"]
            .as_str()
            .unwrap()
            .contains("not in this directory"),
        "{doc}"
    );
    assert_eq!(doc["rederived"]["holds"], true, "{doc}");
}

/// What the source says of the artifact now, where the log continues in a repository the
/// directory does not hold, is `unknown` to a JSON reader too, with why, and never the record's
/// own answer; and 4.
#[test]
fn a_json_reader_is_told_unknown_where_the_log_continues_elsewhere() {
    let p = build::pairs();
    let k3 = common::attestation_key(3);
    let a = build::verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, common::T0);
    let root = scratch("continues-json");
    let mut log = common::Writer::init(&root.join("log"), common::log_key());
    log.append(&[
        Leaf::Record(a.leaf.clone()),
        Leaf::LogEnd(LogEndLeaf {
            time: common::T0 + 60,
            successor: Successor {
                origin: common::SUCCESSOR.into(),
                log_key: common::successor_key().vkey().to_string(),
                urls: vec!["https://example.org/next.git".into()],
                dir: "log".into(),
            },
        }),
    ]);
    a.write(&root);
    let out = check_made(&root, &a, &["--output", "json"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["exit"], 4, "{doc}");
    assert_eq!(doc["verified"], true, "{doc}");
    assert_eq!(doc["answer"], "unknown", "{doc}");
    assert!(
        doc["unknown"]
            .as_str()
            .unwrap()
            .contains("the log continues as `example.com/trigon-evidence/1`"),
        "{doc}"
    );
}

/// `docs/19` §4.2: a field a statement does not sign is shown as absent, never as a value, and
/// `attestable: false` as not attestable: a verdict signed with no run, no egress tier and no
/// building Trigon, and one with no signer named and no `attestable`.
#[test]
fn a_field_a_verdict_does_not_sign_is_shown_as_absent() {
    let p = build::pairs();
    let k3 = common::attestation_key(3);
    let honest = build::verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, common::T0);
    type Edit = Box<dyn Fn(usize, &mut trigon_attest::Statement)>;
    let cases: [(&str, Edit, &[&str]); 2] = [
        (
            "unsigned",
            Box::new(|i, st| {
                if i == 0 {
                    let o = st.predicate.as_object_mut().unwrap();
                    o.remove("run");
                    o.remove("egressTier");
                    o.insert("attestable".into(), json!(false));
                    o["trigonVersion"].as_object_mut().unwrap().remove("builder");
                }
            }),
            &[
                "run       none signed",
                "trigon    built by a Trigon the run did not record, signed by 0.0.0+git.2222",
                "egress    no tier signed, not attestable",
            ],
        ),
        (
            "no-signer",
            Box::new(|i, st| {
                if i == 0 {
                    let o = st.predicate.as_object_mut().unwrap();
                    o.remove("attestable");
                    o["trigonVersion"].as_object_mut().unwrap().remove("attestor");
                }
            }),
            &[
                "trigon    built by 0.0.0+git.1111111111111111111111111111111111111111; the \
                 signer is not named",
                "egress    mirror-only, `attestable` not signed",
            ],
        ),
    ];
    for (name, edit, lines) in cases {
        let m = build::resigned(&honest, &k3, common::T0, None, edit);
        let root = scratch(&format!("absent-{name}"));
        build::small(&root, &[&m]);
        let out = check_made(&root, &m, &[]);
        let said = text(&out);
        assert_eq!(out.status.code(), Some(0), "{name}: {said}");
        for line in lines {
            assert!(said.contains(line), "{name}: {line}\n{said}");
        }
    }
}

/// Re-deriving holds the published comparison report the verdict signs to the claim: a report
/// that is the bytes the verdict signs and no comparison at all fails the record, exit 4, as the
/// evidence failing verification, never as a report left unchecked; and a verdict that names no
/// report has none to hold, which is said, and the record answers as it does.
#[test]
fn a_signed_report_that_is_no_comparison_fails_the_record() {
    let p = build::pairs();
    let k3 = common::attestation_key(3);
    let honest = build::verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, common::T0);
    let dir = scratch("no-comparison");
    let (u, r) = artifacts(&dir, &p["a"]);
    let rerun = ["--rerun-comparison", "--upstream", &u, "--rebuild", &r];
    let garbage = b"no comparison report at all".to_vec();
    let signs = build::sha256(&garbage).to_hex();
    let mut evidence = honest.evidence.clone();
    evidence[1] = garbage;
    let m = build::resigned(&honest, &k3, common::T0, Some(evidence), move |i, st| {
        if i == 0 {
            st.predicate["evidence"]["comparison"]["sha256"] = signs.clone().into();
        }
    });
    let root = dir.join("garbage");
    build::small(&root, &[&m]);
    // As a record, the report is the bytes it signs, and it verifies.
    let out = check_made(&root, &m, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = check_made(&root, &m, &rerun);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(4), "{said}");
    assert!(said.contains("the claim holds"), "{said}");
    assert!(said.contains("report    FAILED verification: "), "{said}");
    let mut json = rerun.to_vec();
    json.extend(["--output", "json"]);
    let out = check_made(&root, &m, &json);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["report"]["agrees"], false, "{doc}");
    assert!(doc["report"]["failed"].is_string(), "{doc}");

    // A verdict that signs no report.
    let m = build::resigned(&honest, &k3, common::T0, None, |i, st| {
        if i == 0 {
            st.predicate["evidence"]
                .as_object_mut()
                .unwrap()
                .remove("comparison");
        }
    });
    let root = dir.join("none");
    build::small(&root, &[&m]);
    let out = check_made(&root, &m, &rerun);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(said.contains("the claim holds"), "{said}");
    assert!(said.contains("report    unchecked: the verdict names none"), "{said}");
}

/// A checkpoint given as last accepted that is of no log the directory's chain reaches, where the
/// chain continues nowhere else, is never passed over: what is here is behind what was accepted,
/// and the source is refused, exit 4, with both signed notes.
#[test]
fn a_checkpoint_of_no_log_the_chain_reaches_is_refused_as_a_rollback() {
    let d = scratch("unrelated-checkpoint");
    let unrelated = LogSigner::from_seed("example.net/unrelated", [6; 32]).unwrap();
    let cp = d.join("unrelated.checkpoint");
    std::fs::write(
        &cp,
        SignedCheckpoint::sign(
            &Checkpoint {
                origin: "example.net/unrelated".into(),
                size: 3,
                root: [5; 32],
            },
            &unrelated,
        )
        .unwrap()
        .to_string(),
    )
    .unwrap();
    let out = check(&repo(), "e", &["--checkpoint", cp.to_str().unwrap()]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(4), "{said}");
    assert!(
        said.contains(
            "the checkpoint last accepted is for `example.net/unrelated`, and no log this \
             repository's chain reaches has that origin"
        ),
        "{said}"
    );
    assert!(!said.contains("answer    exact"), "{said}");
    let out = check(
        &repo(),
        "e",
        &["--checkpoint", cp.to_str().unwrap(), "--output", "json"],
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["stopped"], "inconsistent", "{doc}");
}
