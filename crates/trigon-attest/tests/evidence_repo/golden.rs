//! The golden evidence repository, `testdata/evidence/`: that the writer writes it byte for byte,
//! and that a client verifies it and finds in it what it is said to hold.
//!
//! What it holds, so a reader of `testdata/evidence/` knows what to look for. The keys are
//! `common.rs`'s: log key 1 for `example.com/trigon-evidence`, 2 for its successor
//! `example.com/trigon-evidence/1`, attestation keys 3 (pinned) and 4 (changed to), release key 5,
//! and key 9, which the source never had.
//!
//! - `repo/log/`, fifteen leaves over four publications:
//!   0 `a1`, a `normalized` verdict about demo-a; 1 `b`, a `divergent` one about demo-b; 2 `c`, a
//!   void about demo-c; 3 `d0`, an `exact` verdict about demo-d; 4 `f`, a verdict about demo-f
//!   whose record file is gone — deleted; 5 `i`, a verdict whose leaf logs `exact` where its
//!   statement signs `normalized`; 6 `h`, a verdict signed by key 9; 7 a heartbeat; 8 `a2`, a
//!   verdict superseding `a1` (`set_changed`); 9 the change from key 3 to key 4; 10 `w`, the
//!   withdrawal of `d0`, under key 4; 11 `g`, a verdict signed by key 3 after it was retired; 12 a
//!   client release; 13 `e`, an `exact` verdict under key 4; 14 the log-end naming `log/1`.
//! - `repo/log/1/`: the log-continuation, 1 `k`, a verdict under key 4, and a heartbeat.
//! - `repo/records/`: every record file but `f`'s, and `j`'s, a signed verdict no leaf names.
//! - `repo/evidence/`: every verdict's set manifest, comparison report, strategy and guard
//!   manifest, and the void's guard manifest; rebuilt artifacts are release assets, not here.
//! - `repo/index/`: every index file the log implies, `f`'s, `g`'s, `h`'s and `i`'s included.
//! - `records.json`: each record by name, with its digest, subject, purl and leaf.
//! - `artifacts/`: the published and rebuilt artifacts of demo-a, demo-b and demo-e, for
//!   re-deriving their verdicts.
//! - `checkpoints/`: every checkpoint `log/` had, named by its size.

use serde_json::{Value, json};
use trigon_attest::log::{Leaf, verify_source};
use trigon_attest::{AttestationKey, evidence::Repository};

use crate::build::{Golden, golden, repo, testdata};
use crate::common::{attestation_key, log_key, tree_of};

fn rewriting() -> bool {
    std::env::var_os("TRIGON_WRITE_GOLDEN").is_some_and(|v| v == "1")
}

/// Everything under `testdata/evidence/` the writer produces, by path.
fn written(g: &Golden, built: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out: std::collections::BTreeMap<String, Vec<u8>> = tree_of(built)
        .into_iter()
        .map(|(p, b)| (format!("repo/{p}"), b))
        .collect();
    let mut names = serde_json::Map::new();
    for (name, (m, at)) in &g.records {
        let st = m.statement();
        names.insert(
            (*name).to_string(),
            json!({
                "record": format!("sha256:{}", m.digest.to_hex()),
                "predicateType": st.predicate_type,
                "outcome": st.predicate.get("outcome"),
                "subject": st.subject[0].digest["sha256"],
                "purl": st.predicate["purl"],
                "log": at.map(|(log, _)| log),
                "leaf": at.map(|(_, leaf)| leaf),
            }),
        );
    }
    let mut text = serde_json::to_string_pretty(&Value::Object(names)).unwrap();
    text.push('\n');
    out.insert("records.json".into(), text.into_bytes());
    for (name, bytes) in &g.artifacts {
        out.insert(format!("artifacts/{name}"), bytes.clone());
    }
    for c in &g.checkpoints {
        out.insert(
            format!("checkpoints/{}.checkpoint", c.size()),
            c.to_string().into_bytes(),
        );
    }
    out
}

#[test]
fn the_golden_evidence_is_what_the_writer_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let g = golden(tmp.path());
    let got = written(&g, tmp.path());
    if rewriting() {
        let _ = std::fs::remove_dir_all(testdata());
        for (path, bytes) in &got {
            crate::build::write(&testdata(), path, bytes);
        }
    }
    let want = tree_of(&testdata());
    assert_eq!(
        want.keys().collect::<Vec<_>>(),
        got.keys().collect::<Vec<_>>(),
        "the files the writer writes are not the golden evidence's; if the change is deliberate, \
         TRIGON_WRITE_GOLDEN=1 rewrites it"
    );
    for (path, bytes) in &got {
        assert!(want[path] == *bytes, "{path} differs from the golden file");
    }
}

#[test]
fn the_golden_repository_verifies_and_holds_every_leaf_kind() {
    let source = verify_source(&repo(), &log_key().vkey(), None).unwrap();
    let dirs: Vec<&str> = source.logs.iter().map(|c| c.dir.as_str()).collect();
    assert_eq!(dirs, ["log", "log/1"]);
    assert!(source.refused.is_empty() && source.unnamed.is_empty());
    assert_eq!(
        (source.logs[0].log.size(), source.logs[1].log.size()),
        (15, 3)
    );
    let mut kinds: Vec<&str> = source
        .logs
        .iter()
        .flat_map(|c| c.log.leaves().map(|(_, l)| l.kind()))
        .collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(
        kinds,
        [
            "heartbeat",
            "key-change",
            "log-continuation",
            "log-end",
            "record",
            "release"
        ]
    );
}

/// `records.json` says where each record's leaf is, and the log agrees.
#[test]
fn every_golden_record_is_at_the_leaf_records_json_names() {
    let source = verify_source(&repo(), &log_key().vkey(), None).unwrap();
    let names = crate::build::names();
    assert_eq!(names.len(), 13);
    for (name, r) in &names {
        let record = r["record"].as_str().unwrap();
        match (r["log"].as_u64(), r["leaf"].as_u64()) {
            (Some(log), Some(leaf)) => {
                let Some(Leaf::Record(l)) = source.logs[log as usize].log.leaf(leaf) else {
                    panic!("{name}: leaf {leaf} of log {log} is not a record leaf");
                };
                assert_eq!(format!("sha256:{}", l.record.to_hex()), record, "{name}");
            }
            _ => assert_eq!(name, "j", "only `j` is unlogged"),
        }
    }
}

/// The records of every type — verdict, void, withdrawal, superseding verdict — verify, and the
/// ones built to fail do not.
#[test]
fn the_golden_records_verify_but_the_three_built_to_fail() {
    let k3 = AttestationKey::from(attestation_key(3).public_key());
    let r = Repository::open(&repo(), &log_key().vkey(), &k3, None).unwrap();
    for (name, want) in [
        ("a1", true),
        ("a2", true),
        ("b", true),
        ("c", true),
        ("d0", true),
        ("w", true),
        ("e", true),
        ("k", true),
        ("g", false),
        ("h", false),
        ("i", false),
        ("j", false),
    ] {
        let bytes = r
            .read_record(&crate::build::digest(name))
            .unwrap()
            .unwrap_or_else(|| panic!("{name}'s record file is in the repository"));
        let got = r.verify_record(&bytes);
        assert_eq!(got.is_ok(), want, "{name}: {:?}", got.err());
    }
    assert!(r.read_record(&crate::build::digest("f")).unwrap().is_none());
}
