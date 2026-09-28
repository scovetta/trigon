//! Leaves: one golden file per kind, read strictly, and every rule on every field.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};
use trigon_attest::log::leaf::{KINDS, MAX_TIME};
use trigon_attest::log::{
    KeyChangeLeaf, Leaf, LeafOutcome, LogContinuationLeaf, LogEndLeaf, LogError, RecordLeaf,
    ReleaseLeaf, SignedNote, Successor,
};
use trigon_attest::{
    AttestationKey, DIVERGENCE, DIVERGENCE_V2, EQUIVALENCE_V2, SupersedeReason, VOID, WITHDRAWAL,
};
use trigon_core::purl::{PURL_CANON, canonicalize_under};

use crate::common::{
    ORIGIN, SUCCESSOR, T0, attestation_key, log_key, record_leaf, sha256, successor_key,
};

fn golden(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("testdata/log/leaves/{name}.json"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

const GOLDEN: [(&str, &str); 10] = [
    ("record", "record"),
    ("record-divergent", "record"),
    ("record-void", "record"),
    ("record-supersedes", "record"),
    ("record-withdrawal", "record"),
    ("heartbeat", "heartbeat"),
    ("key-change", "key-change"),
    ("release", "release"),
    ("log-end", "log-end"),
    ("log-continuation", "log-continuation"),
];

#[test]
fn every_kind_has_a_golden_leaf_that_reads_back_to_its_own_bytes() {
    let mut seen: Vec<&str> = Vec::new();
    for (name, kind) in GOLDEN {
        let bytes = golden(name);
        let leaf = Leaf::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(leaf.kind(), kind, "{name}");
        assert_eq!(leaf.encode().unwrap(), bytes, "{name}");
        seen.push(kind);
    }
    seen.sort();
    seen.dedup();
    let mut kinds = KINDS.to_vec();
    kinds.sort();
    assert_eq!(seen, kinds, "a kind has no golden leaf");
}

/// The shape a reader in another language is held to: the record leaf, spelled out.
#[test]
fn a_record_leaf_is_canonical_json_with_these_fields() {
    let v: Value = serde_json::from_slice(&golden("record")).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "keyId",
            "kind",
            "outcome",
            "predicateType",
            "purl",
            "purlCanon",
            "record",
            "stabilizerSet",
            "subject",
            "time"
        ]
    );
    assert_eq!(v["kind"], "record");
    assert_eq!(v["outcome"], "normalized");
    assert!(v["record"].as_str().unwrap().starts_with("sha256:"));
    let w: Value = serde_json::from_slice(&golden("record-withdrawal")).unwrap();
    assert!(w.get("outcome").is_none() && w.get("stabilizerSet").is_none());
    assert_eq!(w["reason"], "withdrawn");
    let text = String::from_utf8(golden("record")).unwrap();
    assert!(!text.contains(' ') && !text.contains('\n'), "{text}");
}

fn canonical(v: &Value) -> Vec<u8> {
    trigon_core::jcs::canonicalize(v).unwrap().into_bytes()
}

fn refused(bytes: &[u8]) -> String {
    match Leaf::decode(bytes) {
        Err(e @ LogError::Malformed(_)) => e.to_string(),
        other => panic!(
            "{}: expected a refusal, got {other:?}",
            String::from_utf8_lossy(bytes)
        ),
    }
}

#[test]
fn an_unknown_kind_is_refused_by_name() {
    let e = refused(br#"{"kind":"note","time":1}"#);
    assert!(e.contains("`note`") && e.contains("update it"), "{e}");
    assert!(refused(br#"{"time":1}"#).contains("no `kind`"));
    assert!(refused(br#"{"kind":1,"time":1}"#).contains("not a string"));
    assert!(refused(b"[1]").contains("not a JSON object"));
    assert!(refused(b"{").contains("not JSON"));
}

#[test]
fn an_unknown_field_is_refused_in_every_kind_and_every_object() {
    for (name, _) in GOLDEN {
        let mut v: Value = serde_json::from_slice(&golden(name)).unwrap();
        v["extra"] = json!(1);
        let e = refused(&canonical(&v));
        assert!(e.contains("unknown field `extra`"), "{name}: {e}");
    }
    // Inside the nested objects too.
    let mut v: Value = serde_json::from_slice(&golden("key-change")).unwrap();
    v["old"]["extra"] = json!(1);
    assert!(refused(&canonical(&v)).contains("unknown field `extra`"));
    let mut v: Value = serde_json::from_slice(&golden("log-end")).unwrap();
    v["successor"]["extra"] = json!(1);
    assert!(refused(&canonical(&v)).contains("unknown field `extra`"));
}

#[test]
fn a_leaf_not_in_canonical_form_is_refused() {
    let bytes = golden("record");
    let text = String::from_utf8(bytes.clone()).unwrap();
    let spaced = text.replacen(",", ", ", 1);
    // Keys out of order: the same object, written with `time` first.
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let mut reordered = format!("{{\"time\":{}", v["time"]);
    for (k, val) in v.as_object().unwrap() {
        if k != "time" {
            reordered.push_str(&format!(",{}:{}", json!(k), val));
        }
    }
    reordered.push('}');
    let duplicated = text.replacen("{", &format!("{{\"time\":{},", v["time"]), 1);
    let escaped = text.replacen("normalized", "normali\\u007aed", 1);
    for (bad, what) in [
        (spaced, "a space"),
        (reordered, "keys out of order"),
        (duplicated, "a key given twice"),
        (escaped, "an escape where none is needed"),
        (format!("{text}\n"), "a trailing newline"),
    ] {
        let e = refused(bad.as_bytes());
        assert!(e.contains("not in canonical form"), "{what}: {e}");
    }
    // Not a time at all: serde says what it expected, not which field, so the type is the tell.
    let negative = text.replacen("\"time\":", "\"time\":-", 1);
    assert!(refused(negative.as_bytes()).contains("expected u64"));
    let float = text.replacen(&v["time"].to_string(), "1.5", 1);
    assert!(refused(float.as_bytes()).contains("expected u64"));
}

fn record() -> RecordLeaf {
    record_leaf(T0, 1, &attestation_key(3))
}

fn record_refused(r: RecordLeaf) -> String {
    let e = Leaf::Record(r.clone()).encode().unwrap_err().to_string();
    // A reader refuses what the writer refuses: the same leaf, written past the writer's checks.
    let mut v = serde_json::to_value(&r).unwrap();
    v["kind"] = json!("record");
    assert_eq!(refused(&canonical(&v)), e);
    e
}

#[test]
fn every_rule_on_a_record_leaf_is_checked_by_writer_and_reader() {
    let mut cases: Vec<(RecordLeaf, &str)> = Vec::new();
    let mut r = record();
    r.subject.remove("sha256");
    cases.push((r, "no sha256"));
    let mut r = record();
    r.subject.insert("sha384".into(), "00".repeat(48));
    cases.push((r, "`sha384`"));
    let mut r = record();
    let upper = r.subject["sha256"].to_uppercase();
    r.subject.insert("sha256".into(), upper);
    cases.push((r, "lowercase hex"));
    let mut r = record();
    r.subject.insert("sha1".into(), "ab".repeat(19));
    cases.push((r, "40 lowercase hex"));
    cases.push((
        RecordLeaf {
            purl: "pkg:NPM/left-pad@1.3.1".into(),
            ..record()
        },
        "not canonical",
    ));
    cases.push((
        RecordLeaf {
            purl: "not a purl".into(),
            ..record()
        },
        "is not one",
    ));
    // A rule this build does not have, before the first or after the newest, is one it cannot
    // check the purl under.
    cases.push((
        RecordLeaf {
            purl_canon: PURL_CANON + 1,
            ..record()
        },
        "written by a newer Trigon",
    ));
    cases.push((
        RecordLeaf {
            purl_canon: 0,
            ..record()
        },
        "rule 0",
    ));
    cases.push((
        RecordLeaf {
            predicate_type: DIVERGENCE.into(),
            outcome: Some(LeafOutcome::Divergent),
            ..record()
        },
        "not one `publish` logs",
    ));
    cases.push((
        RecordLeaf {
            outcome: Some(LeafOutcome::Divergent),
            ..record()
        },
        "`divergent` is not one",
    ));
    cases.push((
        RecordLeaf {
            outcome: Some(LeafOutcome::Void),
            ..record()
        },
        "`void` is not one",
    ));
    cases.push((
        RecordLeaf {
            predicate_type: DIVERGENCE_V2.into(),
            outcome: None,
            ..record()
        },
        "no outcome",
    ));
    cases.push((
        RecordLeaf {
            predicate_type: VOID.into(),
            outcome: Some(LeafOutcome::Normalized),
            ..record()
        },
        "`normalized` is not one",
    ));
    cases.push((
        RecordLeaf {
            stabilizer_set: None,
            ..record()
        },
        "no stabilizer set",
    ));
    let withdrawal = RecordLeaf {
        predicate_type: WITHDRAWAL.into(),
        outcome: None,
        stabilizer_set: None,
        supersedes: Some(sha256("record 0")),
        reason: Some(SupersedeReason::Withdrawn),
        ..record()
    };
    cases.push((
        RecordLeaf {
            outcome: Some(LeafOutcome::Normalized),
            ..withdrawal.clone()
        },
        "`normalized` is not one",
    ));
    cases.push((
        RecordLeaf {
            stabilizer_set: Some(sha256("set")),
            ..withdrawal.clone()
        },
        "a withdrawal names none",
    ));
    cases.push((
        RecordLeaf {
            supersedes: None,
            reason: None,
            ..withdrawal.clone()
        },
        "names the record it supersedes",
    ));
    cases.push((
        RecordLeaf {
            reason: None,
            ..withdrawal.clone()
        },
        "without the other",
    ));
    cases.push((
        RecordLeaf {
            supersedes: Some(sha256("r")),
            ..record()
        },
        "without the other",
    ));
    cases.push((
        RecordLeaf {
            key_id: "abc".into(),
            ..record()
        },
        "16 lowercase hex",
    ));
    cases.push((
        RecordLeaf {
            key_id: "ABCDEF0123456789".into(),
            ..record()
        },
        "16 lowercase hex",
    ));
    cases.push((
        RecordLeaf {
            time: MAX_TIME + 1,
            ..record()
        },
        "largest integer",
    ));
    for (r, says) in cases {
        let e = record_refused(r.clone());
        assert!(e.contains(says), "{r:?}: {e}");
    }
    // The ones that are fine: a withdrawal as it should be, a void with a set and without, and
    // the latest time there is.
    for ok in [
        withdrawal,
        RecordLeaf {
            predicate_type: VOID.into(),
            outcome: Some(LeafOutcome::Void),
            ..record()
        },
        RecordLeaf {
            predicate_type: VOID.into(),
            outcome: Some(LeafOutcome::Void),
            stabilizer_set: None,
            ..record()
        },
        RecordLeaf {
            time: MAX_TIME,
            ..record()
        },
    ] {
        let bytes = Leaf::Record(ok.clone()).encode().unwrap();
        assert_eq!(Leaf::decode(&bytes).unwrap(), Leaf::Record(ok));
    }
}

/// A leaf is never rewritten, so a record leaf logged under an earlier canonicalisation rule must
/// still read once the rule moves on: every rule this build has is checked as the rule it was, and
/// a leaf under one decodes.
#[test]
fn a_record_leaf_under_any_rule_this_build_has_reads() {
    for rule in 1..=PURL_CANON {
        let r = RecordLeaf {
            purl_canon: rule,
            purl: canonicalize_under(rule, "pkg:npm/left-pad@1.3.1")
                .unwrap()
                .to_string(),
            ..record()
        };
        let bytes = Leaf::Record(r.clone()).encode().unwrap();
        assert_eq!(Leaf::decode(&bytes).unwrap(), Leaf::Record(r));
    }
    // And the purl is canonical under its own rule, which says so when it is not.
    let e = record_refused(RecordLeaf {
        purl: "pkg:NPM/left-pad@1.3.1".into(),
        ..record()
    });
    assert!(e.contains("not canonical under rule 1"), "{e}");
}

/// serde quotes an unknown field or variant as it was written, and a leaf is anyone's bytes: a
/// refusal escapes it, so no control character reaches a terminal.
#[test]
fn a_refusal_of_a_leaf_carries_none_of_its_control_characters() {
    let mut record: Value = serde_json::from_slice(&golden("record")).unwrap();
    record["outcome"] = json!("\u{1b}]0;owned\u{7}\u{9b}2J");
    let mut heartbeat = json!({"kind": "heartbeat", "time": 1});
    heartbeat["\u{1b}[2J\u{7f}"] = json!(1);
    for bytes in [
        canonical(&record),
        canonical(&heartbeat),
        b"{\"kind\":\"heartbeat\",\"time\":1,\"\x1b[2J\"".to_vec(),
    ] {
        let e = refused(&bytes);
        assert!(!e.chars().any(char::is_control), "{e:?}");
    }
    let e = refused(&canonical(&record));
    assert!(e.contains(r"\u{1b}]0;owned\u{7}\u{9b}2J"), "{e}");
}

#[test]
fn a_digest_a_leaf_writes_as_sha256_colon_hex_is_read_only_so() {
    let bytes = golden("record");
    let text = String::from_utf8(bytes).unwrap();
    let hex = sha256("record 1").to_hex();
    for bad in [
        text.replacen(&format!("sha256:{hex}"), &hex, 1),
        text.replacen(&format!("sha256:{hex}"), &format!("SHA256:{hex}"), 1),
        text.replacen(
            &format!("sha256:{hex}"),
            &format!("sha256:{}", hex.to_uppercase()),
            1,
        ),
        text.replacen(
            &format!("sha256:{hex}"),
            &format!("sha256:{}", &hex[1..]),
            1,
        ),
    ] {
        assert!(
            refused(bad.as_bytes()).contains("64 lowercase hex"),
            "{bad}"
        );
    }
}

#[test]
fn a_key_change_is_signed_by_both_keys_over_its_log() {
    let (k3, k4) = (attestation_key(3), attestation_key(4));
    let change = KeyChangeLeaf::sign(ORIGIN, T0, &k3, &k4).unwrap();
    change.verify(ORIGIN).unwrap();
    assert_eq!(
        change.old_key().unwrap(),
        AttestationKey::from(k3.public_key())
    );
    assert_eq!(
        change.new_key().unwrap(),
        AttestationKey::from(k4.public_key())
    );
    let message = String::from_utf8(KeyChangeLeaf::message(
        ORIGIN,
        T0,
        &change.old_key().unwrap(),
        &change.new_key().unwrap(),
    ))
    .unwrap();
    assert_eq!(
        message,
        format!(
            "trigon.dev/key-change/v1\n{ORIGIN}\n{T0}\n{}\n{}\n",
            change.old.public_key, change.new.public_key
        )
    );

    // Replayed into another log, or moved in time, neither signature holds.
    assert!(matches!(
        change.verify(SUCCESSOR),
        Err(LogError::Rotation(_))
    ));
    let moved = KeyChangeLeaf {
        time: T0 + 1,
        ..change.clone()
    };
    assert!(moved.verify(ORIGIN).is_err());
    // One key signing for both is not a change both made.
    let mut one = change.clone();
    one.new.signature = one.old.signature.clone();
    let e = one.verify(ORIGIN).unwrap_err().to_string();
    assert!(e.contains("new key"), "{e}");

    // Its fields.
    let refuse = |c: KeyChangeLeaf, says: &str| {
        let e = Leaf::KeyChange(c).encode().unwrap_err().to_string();
        assert!(e.contains(says), "{e}");
    };
    let mut c = change.clone();
    c.old.key_id = "0000000000000000".into();
    refuse(c, "old key's id");
    let mut c = change.clone();
    c.new.public_key = c.new.public_key.to_uppercase();
    refuse(c, "64 lowercase hex");
    let mut c = change.clone();
    c.new.signature = "AAAA".into();
    refuse(c, "new key's signature");
    let mut c = change.clone();
    c.new = c.old.clone();
    refuse(c, "one key");
    assert!(KeyChangeLeaf::sign(ORIGIN, T0, &k3, &k3).is_err());
}

fn artifacts() -> BTreeMap<String, BTreeMap<String, String>> {
    BTreeMap::from([(
        "trigon-check-0.1.0.tgz".to_string(),
        BTreeMap::from([("sha256".to_string(), sha256("tgz").to_hex())]),
    )])
}

#[test]
fn a_release_is_signed_by_the_release_key() {
    let key = attestation_key(5);
    let pinned = AttestationKey::from(key.public_key());
    let r = ReleaseLeaf::sign(ORIGIN, T0, "trigon-check", "0.1.0", artifacts(), &key).unwrap();
    r.verify(ORIGIN, &pinned).unwrap();

    let other = AttestationKey::from(attestation_key(6).public_key());
    assert!(matches!(
        r.verify(ORIGIN, &other),
        Err(LogError::Unverified(_))
    ));
    assert!(matches!(
        r.verify(SUCCESSOR, &pinned),
        Err(LogError::BadSignature(_))
    ));
    let mut tampered = r.clone();
    tampered
        .artifacts
        .get_mut("trigon-check-0.1.0.tgz")
        .unwrap()
        .insert("sha256".into(), sha256("other").to_hex());
    assert!(matches!(
        tampered.verify(ORIGIN, &pinned),
        Err(LogError::BadSignature(_))
    ));

    for (change, says) in [
        (
            Box::new(|r: &mut ReleaseLeaf| r.artifacts.clear()) as Box<dyn Fn(&mut ReleaseLeaf)>,
            "no released file",
        ),
        (
            Box::new(|r: &mut ReleaseLeaf| {
                let d = r.artifacts.values().next().unwrap().clone();
                r.artifacts.insert("dir/file.tgz".into(), d);
            }),
            "not a file name",
        ),
        (
            Box::new(|r: &mut ReleaseLeaf| {
                let d = r.artifacts.values().next().unwrap().clone();
                r.artifacts.insert("..".into(), d);
            }),
            "not a file name",
        ),
        (
            Box::new(|r: &mut ReleaseLeaf| {
                r.artifacts
                    .values_mut()
                    .next()
                    .unwrap()
                    .insert("sha1".into(), "ab".repeat(20));
            }),
            "sha1",
        ),
        (
            Box::new(|r: &mut ReleaseLeaf| r.version = "0.1 .0".into()),
            "version",
        ),
        (
            Box::new(|r: &mut ReleaseLeaf| r.name = String::new()),
            "name",
        ),
        (
            Box::new(|r: &mut ReleaseLeaf| r.signature = "AAAA".into()),
            "signature",
        ),
    ] {
        let mut bad = r.clone();
        change(&mut bad);
        let e = Leaf::Release(bad).encode().unwrap_err().to_string();
        assert!(e.contains(says), "{e}");
    }
}

fn successor() -> Successor {
    Successor {
        origin: SUCCESSOR.into(),
        log_key: successor_key().vkey().to_string(),
        urls: Vec::new(),
        dir: "log/1".into(),
    }
}

#[test]
fn a_log_end_names_its_successor_whole() {
    let ok = |s: Successor| {
        let leaf = Leaf::LogEnd(LogEndLeaf {
            time: T0,
            successor: s,
        });
        let bytes = leaf.encode().unwrap();
        assert_eq!(Leaf::decode(&bytes).unwrap(), leaf);
    };
    let bad = |s: Successor, says: &str| {
        let e = Leaf::LogEnd(LogEndLeaf {
            time: T0,
            successor: s,
        })
        .encode()
        .unwrap_err()
        .to_string();
        assert!(e.contains(says), "{e}");
    };
    ok(successor());
    let elsewhere = |urls: &[&str], dir: &str| Successor {
        urls: urls.iter().map(|u| u.to_string()).collect(),
        dir: dir.into(),
        ..successor()
    };
    ok(elsewhere(
        &[
            "https://github.com/owner/trigon-evidence-2.git",
            "git@codeberg.org:owner/trigon-evidence-2.git",
        ],
        "log",
    ));
    ok(elsewhere(&["https://github.com/owner/r.git"], "log/3"));

    bad(
        Successor {
            origin: "example.com/other".into(),
            ..successor()
        },
        "a log key's name is its log's origin",
    );
    bad(
        Successor {
            log_key: "not a key".into(),
            ..successor()
        },
        "not a C2SP verifier key",
    );
    bad(
        elsewhere(&["file:///srv/r.git"], "log"),
        "a path on some machine",
    );
    bad(elsewhere(&["/srv/r.git"], "log"), "a path on some machine");
    bad(
        elsewhere(&["https://user:token@github.com/o/r.git"], "log"),
        "not a repository location",
    );
    bad(
        elsewhere(
            &["https://github.com/o/r.git", "https://github.com/o/r.git"],
            "log",
        ),
        "twice",
    );
    for dir in [
        "log", "log/0", "log/01", "logs/1", "log/1/", "log/one", "../log/1", "/log/1",
    ] {
        bad(
            Successor {
                dir: dir.into(),
                ..successor()
            },
            "is not `log/<n>`",
        );
    }
}

#[test]
fn a_log_continuation_carries_a_checkpoint_signed_twice() {
    let body = format!("{ORIGIN}\n5\n{}\n", "A".repeat(43) + "=");
    let once = SignedNote::sign(&body, &log_key()).unwrap();
    let twice = once.cosign(&successor_key()).unwrap();
    let leaf = |note: String| {
        Leaf::LogContinuation(LogContinuationLeaf {
            time: T0,
            checkpoint: note,
        })
    };
    let bytes = leaf(twice.to_string()).encode().unwrap();
    let Leaf::LogContinuation(c) = Leaf::decode(&bytes).unwrap() else {
        unreachable!()
    };
    assert_eq!(c.old_checkpoint().unwrap().size, 5);
    assert_eq!(c.note().unwrap(), twice);

    let e = leaf(once.to_string()).encode().unwrap_err().to_string();
    assert!(e.contains("carries one signature"), "{e}");
    let not_a_checkpoint = SignedNote::sign("hello\n", &log_key())
        .unwrap()
        .cosign(&successor_key())
        .unwrap();
    let e = leaf(not_a_checkpoint.to_string())
        .encode()
        .unwrap_err()
        .to_string();
    assert!(e.contains("not a checkpoint"), "{e}");
    let e = leaf("no note".into()).encode().unwrap_err().to_string();
    assert!(e.contains("not a signed note"), "{e}");
}

#[test]
fn a_leaf_too_long_for_an_entry_bundle_is_refused() {
    let key = attestation_key(5);
    let mut many = BTreeMap::new();
    for i in 0..1000 {
        many.insert(
            format!("file-{i:04}.tgz"),
            BTreeMap::from([("sha256".to_string(), sha256(&i.to_string()).to_hex())]),
        );
    }
    let r = ReleaseLeaf::sign(ORIGIN, T0, "trigon-check", "0.1.0", many, &key).unwrap();
    let e = Leaf::Release(r).encode().unwrap_err().to_string();
    assert!(e.contains("at most 65535"), "{e}");
}

/// The equality of the golden records with what `publish` would log is phase 4b's to check; here,
/// only that the kinds a record leaf may be are the four predicates `publish` logs.
#[test]
fn a_record_leaf_is_for_the_four_predicates_publish_logs() {
    for (predicate, outcome, set) in [
        (EQUIVALENCE_V2, Some(LeafOutcome::Exact), true),
        (
            EQUIVALENCE_V2,
            Some(LeafOutcome::NormalizedWithCaveats),
            true,
        ),
        (DIVERGENCE_V2, Some(LeafOutcome::Divergent), true),
        (VOID, Some(LeafOutcome::Void), false),
    ] {
        let r = RecordLeaf {
            predicate_type: predicate.into(),
            outcome,
            stabilizer_set: set.then(|| sha256("set")),
            ..record()
        };
        Leaf::Record(r).encode().unwrap();
    }
}
