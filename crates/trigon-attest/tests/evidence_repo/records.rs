//! A record checked against its leaf (`docs/19` §4.1, §4.2, §8): every check, and every way a
//! record fails one, each with its reason.

use trigon_attest::evidence::{
    EvidenceState, Key, RecordFailure, RecordKind, check_record, record_leaf,
};
use trigon_attest::log::{DirFiles, LeafPos};
use trigon_attest::{
    LocalKey, Record, Signer as _, Statement, SupersedeReason, Supersession, sign_statement,
};
use trigon_core::Match;

use crate::build::{
    Clock, Made, Pair, copy, digest, leaf_for, open, open_golden, pairs, repo, resigned, sha256,
    small, verdict, void, withdrawal,
};
use crate::common::{T0, attestation_key};

fn failure(r: &trigon_attest::evidence::Repository, name: &str) -> RecordFailure {
    let bytes = r.read_record(&digest(name)).unwrap().unwrap();
    r.verify_record(&bytes).unwrap_err()
}

/// `m`'s record file with statement `at` edited by `edit` and signed again with `key`, assembled
/// again: the bytes alone, for a test whose leaf `record_leaf` would refuse to write.
fn edited_bytes(m: &Made, key: &LocalKey, at: usize, edit: impl Fn(&mut Statement)) -> Vec<u8> {
    let mut record = Record::from_slice(&m.bytes).unwrap();
    let mut st: Statement =
        serde_json::from_slice(&record.statements[at].decoded_payload().unwrap()).unwrap();
    edit(&mut st);
    record.statements[at] = sign_statement(&st, key).unwrap();
    Record::assemble(record.statements)
        .unwrap()
        .encode()
        .unwrap()
}

/// `m`, logged alone in a repository of its own, and verified there.
fn verify_alone(m: &Made) -> Result<trigon_attest::evidence::VerifiedRecord, RecordFailure> {
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[m]);
    open(tmp.path()).verify_record(&m.bytes)
}

#[test]
fn a_verdict_a_void_a_withdrawal_and_a_superseding_verdict_each_verify() {
    let r = open_golden();
    for (name, kind, pos) in [
        ("a1", RecordKind::Verdict(Match::Normalized), (0, 0)),
        ("b", RecordKind::Verdict(Match::Divergent), (0, 1)),
        ("c", RecordKind::Void, (0, 2)),
        ("d0", RecordKind::Verdict(Match::Exact), (0, 3)),
        ("a2", RecordKind::Verdict(Match::Normalized), (0, 8)),
        ("w", RecordKind::Withdrawal, (0, 10)),
        ("e", RecordKind::Verdict(Match::Exact), (0, 13)),
        ("k", RecordKind::Verdict(Match::Normalized), (1, 1)),
    ] {
        let bytes = r.read_record(&digest(name)).unwrap().unwrap();
        let v = r.verify_record(&bytes).unwrap();
        assert_eq!(v.kind(), kind, "{name}");
        assert_eq!(
            v.pos,
            LeafPos {
                log: pos.0,
                index: pos.1
            },
            "{name}"
        );
        assert_eq!(v.digest, digest(name));
    }
    // Before the key change the pinned key signs; after it, the key it changed to.
    let key_of = |name: &str| {
        let bytes = r.read_record(&digest(name)).unwrap().unwrap();
        r.verify_record(&bytes).unwrap().key.key_id()
    };
    assert_eq!(key_of("a2"), attestation_key(3).key_id());
    assert_eq!(key_of("w"), attestation_key(4).key_id());
    assert_eq!(key_of("k"), attestation_key(4).key_id());
    // The superseding verdict and the withdrawal name what they supersede, and why.
    let bytes = r.read_record(&digest("a2")).unwrap().unwrap();
    assert_eq!(
        r.verify_record(&bytes).unwrap().supersedes(),
        Some((digest("a1"), SupersedeReason::SetChanged))
    );
    let bytes = r.read_record(&digest("w")).unwrap().unwrap();
    assert_eq!(
        r.verify_record(&bytes).unwrap().supersedes(),
        Some((digest("d0"), SupersedeReason::Withdrawn))
    );
}

#[test]
fn every_evidence_file_is_checked_and_one_absent_is_unchecked_never_passed() {
    let r = open_golden();
    let bytes = r.read_record(&digest("a2")).unwrap().unwrap();
    let v = r.verify_record(&bytes).unwrap();
    let states: Vec<(&str, &EvidenceState)> = v
        .evidence
        .iter()
        .map(|e| (e.name.as_str(), &e.state))
        .collect();
    assert_eq!(
        states,
        [
            ("comparison", &EvidenceState::Matches),
            ("guardManifest", &EvidenceState::Matches),
            ("rebuiltArtifact", &EvidenceState::ReleaseAsset),
            ("stabilizerSetManifest", &EvidenceState::Matches),
            ("strategy", &EvidenceState::Matches),
        ]
    );
    // A release asset is not in the repository, so it is never counted as checked.
    assert_eq!(v.unchecked().count(), 1);

    // Absent, as from a default clone, which leaves `evidence/` out: unchecked, and the record
    // still verifies, since what it signs is what matters and the file is only its evidence.
    let tmp = tempfile::tempdir().unwrap();
    copy(&repo(), tmp.path());
    let comparison = v.evidence.iter().find(|e| e.name == "comparison").unwrap();
    let path = trigon_attest::evidence::evidence_path(&comparison.digest);
    std::fs::remove_file(tmp.path().join(&path)).unwrap();
    let t = open(tmp.path());
    let v = t.verify_record(&bytes).unwrap();
    let state = &v
        .evidence
        .iter()
        .find(|e| e.name == "comparison")
        .unwrap()
        .state;
    assert_eq!(state, &EvidenceState::Absent);
    assert!(!state.checked());
    assert_eq!(v.unchecked().count(), 2);

    // Present and not the bytes the statement signs: the record fails.
    std::fs::write(tmp.path().join(&path), b"another report").unwrap();
    let e = t.verify_record(&bytes).unwrap_err();
    assert!(matches!(e, RecordFailure::Evidence(_)), "{e}");
    assert!(e.to_string().contains(&path), "{e}");
}

#[test]
fn a_record_file_with_one_byte_flipped_fails_verification() {
    let tmp = tempfile::tempdir().unwrap();
    copy(&repo(), tmp.path());
    let path = trigon_attest::evidence::record_path(&digest("b"));
    let mut bytes = std::fs::read(tmp.path().join(&path)).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0x01;
    std::fs::write(tmp.path().join(&path), &bytes).unwrap();
    let r = open(tmp.path());

    // Handed in whole, it is a record no leaf names.
    let e = r.verify_record(&bytes).unwrap_err();
    assert!(matches!(e, RecordFailure::Unlogged { .. }), "{e}");
    // Found through its leaf, it is not the record the leaf names.
    let found = r.lookup(&Key::parse("pkg:npm/demo-b@1.0.0").unwrap());
    let [f] = found.found.as_slice() else {
        panic!("{found:?}")
    };
    let trigon_attest::evidence::RecordState::Failed(e) = &f.state else {
        panic!("{:?}", f.state)
    };
    assert!(
        matches!(e, RecordFailure::NotItsLeaf { leaf, .. } if *leaf == digest("b")),
        "{e}"
    );
    assert_eq!(
        found
            .answer(Match::NormalizedWithCaveats)
            .exit_code(Match::Exact),
        4
    );
}

#[test]
fn an_unlogged_record_fails_verification() {
    let e = failure(&open_golden(), "j");
    assert_eq!(
        e,
        RecordFailure::Unlogged {
            record: digest("j")
        }
    );
    assert!(e.to_string().contains("unlogged"), "{e}");
}

#[test]
fn a_record_signed_by_a_key_the_source_never_had_fails_verification() {
    let e = failure(&open_golden(), "h");
    assert!(matches!(e, RecordFailure::Signature(_)), "{e}");
    assert!(
        e.to_string().contains("neither this source's pinned"),
        "{e}"
    );
}

#[test]
fn a_record_signed_by_a_key_retired_before_its_leaf_fails_verification() {
    let e = failure(&open_golden(), "g");
    assert!(matches!(e, RecordFailure::Signature(_)), "{e}");
    assert!(e.to_string().contains("key change at leaf 9"), "{e}");
}

#[test]
fn a_record_whose_statement_disagrees_with_its_leaf_fails_verification() {
    let e = failure(&open_golden(), "i");
    assert!(matches!(e, RecordFailure::Leaf(_)), "{e}");
    assert!(e.to_string().contains("the outcome"), "{e}");

    // And on every other field §8 names: each leaf changed in one field, and logged.
    let p = pairs();
    let k3 = attestation_key(3);
    let base = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let superseding = verdict(
        &p["a"],
        &k3,
        "1789000100-aaaaaaa2",
        Some(Supersession {
            record: base.digest,
            reason: SupersedeReason::SetChanged,
        }),
        T0 + 60,
    );
    type Edit = fn(&mut trigon_attest::log::RecordLeaf);
    let edits: [(&str, &Made, Edit); 7] = [
        ("the subject", &base, |l| {
            l.subject.insert("sha512".into(), "0".repeat(128));
        }),
        ("the subject", &base, |l| {
            l.subject.remove("sha1");
        }),
        ("the purl", &base, |l| {
            l.purl = "pkg:npm/demo-b@1.0.0".into()
        }),
        ("the stabilizer-set digest", &base, |l| {
            l.stabilizer_set = Some(sha256(b"another set"))
        }),
        ("the predicate type", &base, |l| {
            l.predicate_type = trigon_attest::DIVERGENCE_V2.into();
            l.outcome = Some(trigon_attest::log::LeafOutcome::Divergent);
        }),
        ("the record it supersedes", &superseding, |l| {
            l.supersedes = Some(sha256(b"another record"))
        }),
        ("the reason", &superseding, |l| {
            l.reason = Some(SupersedeReason::PipelineBug)
        }),
    ];
    for (what, m, edit) in edits {
        let mut m = m.clone();
        edit(&mut m.leaf);
        let tmp = tempfile::tempdir().unwrap();
        small(tmp.path(), &[&m]);
        let r = open(tmp.path());
        let e = r.verify_record(&m.bytes).unwrap_err();
        assert!(matches!(e, RecordFailure::Leaf(_)), "{what}: {e}");
        assert!(e.to_string().contains(what), "{what}: {e}");
    }

    // The purl's rule, which a leaf can only log as 1, the one rule there is: a statement that
    // signs another, or signs 1 as a string, disagrees with it.
    for rule in [serde_json::json!(2), serde_json::json!("1")] {
        let bytes = edited_bytes(&base, &k3, 0, |st| st.predicate["purlCanon"] = rule.clone());
        let m = Made {
            leaf: trigon_attest::log::RecordLeaf {
                record: sha256(&bytes),
                ..base.leaf.clone()
            },
            digest: sha256(&bytes),
            bytes,
            evidence: base.evidence.clone(),
        };
        let e = verify_alone(&m).unwrap_err();
        assert!(matches!(e, RecordFailure::Leaf(_)), "{rule}: {e}");
        assert!(
            e.to_string().contains("the purl's canonicalisation rule"),
            "{rule}: {e}"
        );
    }
}

/// The writer's half: `record_leaf` never gives a leaf `check_record` would refuse the record
/// against. A statement that signs `supersedes` without its `sha256:`, or a digest in capitals,
/// would be logged as the leaf writes it and fail at every client for good; it is refused before.
#[test]
fn record_leaf_refuses_a_statement_whose_leaf_every_client_would_refuse() {
    let p = pairs();
    let k3 = attestation_key(3);
    let base = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let w = withdrawal(&base, &k3, T0 + 60);
    let hex = base.digest.to_hex();
    for (what, m, at, field, value) in [
        ("bare hex", &w, 0, "/supersedes", hex.clone()),
        (
            "capitals",
            &w,
            0,
            "/supersedes",
            format!("sha256:{}", hex.to_uppercase()),
        ),
        (
            "a set digest in capitals",
            &base,
            0,
            "/stabilizerSet/digest/sha256",
            base.statement().predicate["stabilizerSet"]["digest"]["sha256"]
                .as_str()
                .unwrap()
                .to_uppercase(),
        ),
    ] {
        let bytes = edited_bytes(m, &k3, at, |st| {
            *st.predicate.pointer_mut(field).unwrap() = value.clone().into()
        });
        let e = record_leaf(&bytes, &k3.key_id(), T0 + 120).unwrap_err();
        assert!(
            e.to_string().contains("would disagree with the leaf"),
            "{what}: {e}"
        );
    }
    // And the record as it is signed gives a leaf it verifies against.
    let leaf = record_leaf(&w.bytes, &k3.key_id(), T0 + 60).unwrap();
    assert_eq!(leaf, w.leaf);
}

#[test]
fn an_envelope_not_signed_by_the_key_its_leaf_names_fails_verification() {
    // The verdict is signed by key 3, as its leaf says, and its `rebuild` by key 9.
    let pair = &pairs()["a"];
    let (k3, k9) = (attestation_key(3), attestation_key(9));
    let signed = verdict(pair, &k3, "1789000000-aaaaaaa1", None, T0);
    let mut record = Record::from_slice(&signed.bytes).unwrap();
    let rebuild: trigon_attest::Statement =
        serde_json::from_slice(&record.statements[1].decoded_payload().unwrap()).unwrap();
    assert_eq!(rebuild.predicate_type, trigon_attest::REBUILD);
    record.statements[1] = sign_statement(&rebuild, &k9).unwrap();
    let bytes = record.encode().unwrap();
    let m = Made {
        leaf: leaf_for(&bytes, &k3, T0),
        digest: sha256(&bytes),
        bytes,
        evidence: signed.evidence.clone(),
    };
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&m]);
    let e = open(tmp.path()).verify_record(&m.bytes).unwrap_err();
    assert!(matches!(e, RecordFailure::Signature(_)), "{e}");
    assert!(e.to_string().contains("rebuild/v1"), "{e}");

    // And one carrying no signature at all.
    let mut record = Record::from_slice(&signed.bytes).unwrap();
    record.statements[2].signatures.clear();
    let bytes = record.encode().unwrap();
    let m = Made {
        leaf: leaf_for(&bytes, &k3, T0),
        digest: sha256(&bytes),
        bytes,
        evidence: Vec::new(),
    };
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&m]);
    let e = open(tmp.path()).verify_record(&m.bytes).unwrap_err();
    assert!(e.to_string().contains("buildobservation/v1"), "{e}");
}

#[test]
fn an_unsigned_map_that_disagrees_with_the_signed_statement_fails_verification() {
    let pair = &pairs()["a"];
    let k3 = attestation_key(3);
    let m = verdict(pair, &k3, "1789000000-aaaaaaa1", None, T0);
    type Edit = fn(&mut Record);
    let edits: [(&str, Edit); 4] = [
        ("purl", |r| r.subject.purl = "pkg:npm/demo-b@1.0.0".into()),
        ("unsigned subject", |r| {
            r.subject.digests.insert("sha256".into(), "0".repeat(64));
        }),
        ("evidence map", |r| {
            r.evidence
                .insert("comparison".into(), format!("sha256:{}", "0".repeat(64)));
        }),
        ("evidence map", |r| {
            r.evidence.remove("strategy");
        }),
    ];
    for (what, edit) in edits {
        let mut record = Record::from_slice(&m.bytes).unwrap();
        edit(&mut record);
        let bytes = record.encode().unwrap();
        let edited = Made {
            leaf: leaf_for(&bytes, &k3, T0),
            digest: sha256(&bytes),
            bytes,
            evidence: m.evidence.clone(),
        };
        let tmp = tempfile::tempdir().unwrap();
        small(tmp.path(), &[&edited]);
        let e = open(tmp.path()).verify_record(&edited.bytes).unwrap_err();
        assert!(matches!(e, RecordFailure::Map(_)), "{what}: {e}");
        assert!(e.to_string().contains(what), "{what}: {e}");
    }
}

#[test]
fn a_void_or_a_withdrawal_carries_its_one_statement_alone() {
    let p = pairs();
    let k3 = attestation_key(3);
    let v = void(&p["c"], &k3, "1789000000-cccccccc", T0);
    let other = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let mut record = Record::from_slice(&v.bytes).unwrap();
    record
        .statements
        .push(Record::from_slice(&other.bytes).unwrap().statements[2].clone());
    let bytes = record.encode().unwrap();
    let m = Made {
        leaf: leaf_for(&bytes, &k3, T0),
        digest: sha256(&bytes),
        bytes,
        evidence: v.evidence,
    };
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&m]);
    let e = open(tmp.path()).verify_record(&m.bytes).unwrap_err();
    assert!(matches!(e, RecordFailure::Statements(_)), "{e}");

    // A verdict whose build observation is about another artifact is refused too.
    let b = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, T0);
    let mut record = Record::from_slice(&other.bytes).unwrap();
    record.statements[2] = Record::from_slice(&b.bytes).unwrap().statements[2].clone();
    let bytes = record.encode().unwrap();
    let m = Made {
        leaf: leaf_for(&bytes, &k3, T0),
        digest: sha256(&bytes),
        bytes,
        evidence: other.evidence.clone(),
    };
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&m]);
    let e = open(tmp.path()).verify_record(&m.bytes).unwrap_err();
    assert!(e.to_string().contains("build observation"), "{e}");

    // A withdrawal is one statement, as the golden one is.
    let w = withdrawal(&other, &k3, T0);
    assert_eq!(Record::from_slice(&w.bytes).unwrap().statements.len(), 1);
}

/// A verdict's `rebuild` and `buildobservation` are about its run: each check of `accompanies`,
/// broken one at a time, and the record fails with why. Statement 1 is the rebuild, 2 the
/// observation.
#[test]
fn what_accompanies_a_verdict_is_about_its_run() {
    let p = pairs();
    let k3 = attestation_key(3);
    let m = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    assert!(verify_alone(&m).is_ok());
    type Edit = fn(&mut Statement);
    let edits: [(usize, &str, Edit); 6] = [
        (1, "rebuilt artifact", |st| {
            st.subject[0].digest.insert("sha256".into(), "0".repeat(64));
        }),
        (1, "of the run `another-run`", |st| {
            st.predicate["runDetails"]["metadata"]["invocationId"] = "another-run".into()
        }),
        (1, "names the stabilizer set", |st| {
            st.predicate["stabilizerSet"]["digest"]["sha256"] = "0".repeat(64).into()
        }),
        (2, "egress tier `open`", |st| {
            st.predicate["egressTier"] = "open".into()
        }),
        (2, "guard was armed with the manifest", |st| {
            st.predicate["artifactHashCheck"]["guardManifest"]["sha256"] = "0".repeat(64).into()
        }),
        (2, "the artifact guard tripped", |st| {
            st.predicate["artifactHashCheck"]["matched"] = true.into()
        }),
    ];
    for (at, says, edit) in edits {
        let edited = resigned(&m, &k3, T0, None, |i, st| {
            if i == at {
                edit(st)
            }
        });
        let e = verify_alone(&edited).unwrap_err();
        assert!(matches!(e, RecordFailure::Statements(_)), "{says}: {e}");
        assert!(e.to_string().contains(says), "{says}: {e}");
    }

    // A second observation of the run, the same one twice: a run has one.
    let mut record = Record::from_slice(&m.bytes).unwrap();
    record.statements.push(record.statements[2].clone());
    let bytes = Record::assemble(record.statements)
        .unwrap()
        .encode()
        .unwrap();
    let twice = Made {
        leaf: leaf_for(&bytes, &k3, T0),
        digest: sha256(&bytes),
        bytes,
        evidence: m.evidence.clone(),
    };
    let e = verify_alone(&twice).unwrap_err();
    assert!(matches!(e, RecordFailure::Statements(_)), "{e}");
    assert!(e.to_string().contains("two `"), "{e}");
}

#[test]
fn a_record_is_accepted_only_under_a_key_its_signed_subject_is() {
    let r = open_golden();
    let bytes = r.read_record(&digest("a2")).unwrap().unwrap();
    let (pos, leaf) = r
        .record_leaves()
        .find(|(_, l)| l.record == digest("a2"))
        .unwrap();
    let check = |key: &str| {
        check_record(
            &bytes,
            Some((pos, leaf)),
            r.keys(),
            &DirFiles::new(repo()),
            Some(&Key::parse(key).unwrap()),
        )
    };
    let subject = &leaf.subject;
    for key in [
        format!("sha256:{}", subject["sha256"]),
        format!("sha512:{}", subject["sha512"]),
        format!("sha1:{}", subject["sha1"]),
        // Accepted only if its signed purl canonicalises to the key.
        "pkg:npm/demo-a@1.0.0".to_string(),
        "PKG:NPM/Demo-A@1.0.0".to_string(),
        "pkg:npm/demo-a".to_string(),
    ] {
        check(&key).unwrap_or_else(|e| panic!("{key}: {e}"));
    }
    for key in [
        format!("sha256:{}", "0".repeat(64)),
        format!("sha1:{}", "0".repeat(40)),
        "pkg:npm/demo-a@1.0.1".to_string(),
        "pkg:npm/demo-b@1.0.0".to_string(),
        "pkg:npm/demo-b".to_string(),
    ] {
        let e = check(&key).unwrap_err();
        assert!(matches!(e, RecordFailure::WrongKey(_)), "{key}: {e}");
    }

    // A file whose sha256 is the subject's and whose other digests are not: the signed subject
    // names every digest, and every one is held to the file.
    let Key::File(mut d) = Key::of_bytes(&pairs()["a"].upstream) else {
        unreachable!()
    };
    check_record(
        &bytes,
        Some((pos, leaf)),
        r.keys(),
        &DirFiles::new(repo()),
        Some(&Key::File(d.clone())),
    )
    .unwrap();
    d.insert("sha512".into(), "0".repeat(128));
    let e = check_record(
        &bytes,
        Some((pos, leaf)),
        r.keys(),
        &DirFiles::new(repo()),
        Some(&Key::File(d)),
    )
    .unwrap_err();
    assert!(matches!(e, RecordFailure::WrongKey(_)), "{e}");
}

#[test]
fn a_file_that_is_not_a_record_fails_verification_as_unreadable() {
    let k3 = attestation_key(3);
    for bytes in [
        b"not json".to_vec(),
        br#"{"schema":"trigon.record/v2","subject":{"purl":"","digests":{}},"statements":[]}"#
            .to_vec(),
        br#"{"schema":"trigon.record/v1","subject":{"purl":"","digests":{}},"statements":[]}"#
            .to_vec(),
    ] {
        let mut clock = Clock(T0);
        let leaf = trigon_attest::log::RecordLeaf {
            record: sha256(&bytes),
            ..verdict(
                &Pair::new("demo-a", b"a\n", b"a\n", false),
                &k3,
                "1789000000-aaaaaaa1",
                None,
                clock.tick(),
            )
            .leaf
        };
        let m = Made {
            bytes: bytes.clone(),
            digest: sha256(&bytes),
            leaf,
            evidence: Vec::new(),
        };
        let tmp = tempfile::tempdir().unwrap();
        small(tmp.path(), &[&m]);
        let e = open(tmp.path()).verify_record(&bytes).unwrap_err();
        assert!(matches!(e, RecordFailure::Unreadable(_)), "{e}");
    }
}
