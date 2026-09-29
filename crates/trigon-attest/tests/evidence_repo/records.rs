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
use crate::common::{ORIGIN, T0, attestation_key};

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
            ORIGIN,
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
        ORIGIN,
        r.keys(),
        &DirFiles::new(repo()),
        Some(&Key::File(d.clone())),
    )
    .unwrap();
    d.insert("sha512".into(), "0".repeat(128));
    let e = check_record(
        &bytes,
        Some((pos, leaf)),
        ORIGIN,
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

/// `docs/19` §4.2 item 6 and §8: a client never renders an outcome it cannot show with the command
/// that would falsify it and, for a divergence, where to dispute it. So a logged verdict without
/// its falsifying command fails verification, and so does one whose command would resolve
/// elsewhere — another log's origin, another subject, another predicate type, another program —
/// and a divergence without its dispute pointer. An equivalence need not say where to dispute it,
/// and a void and a withdrawal carry neither (`a_verdict_a_void_a_withdrawal_and_a_superseding_
/// verdict_each_verify`).
#[test]
fn a_verdict_without_what_answers_it_fails_verification() {
    let p = pairs();
    let k3 = attestation_key(3);
    let eq = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let div = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, T0);
    let drop = |field: &'static str| {
        move |st: &mut Statement| {
            st.predicate.as_object_mut().unwrap().remove(field);
        }
    };
    // The falsifying command's argv, edited by `f`.
    fn argv(f: impl Fn(&mut Vec<String>)) -> impl Fn(&mut Statement) {
        move |st: &mut Statement| {
            let mut argv: Vec<String> =
                serde_json::from_value(st.predicate["falsifyingCommand"]["argv"].clone()).unwrap();
            f(&mut argv);
            st.predicate["falsifyingCommand"]["argv"] = serde_json::json!(argv);
        }
    }
    fn set(flag: &'static str, to: &'static str) -> impl Fn(&mut Vec<String>) {
        move |argv: &mut Vec<String>| {
            let at = argv.iter().position(|a| a == flag).unwrap();
            argv[at + 1] = to.into();
        }
    }
    type Edit = Box<dyn Fn(&mut Statement)>;
    let cases: Vec<(&Made, &str, Edit)> = vec![
        (
            &eq,
            "signs no falsifying command",
            Box::new(drop("falsifyingCommand")),
        ),
        (
            &div,
            "signs no falsifying command",
            Box::new(drop("falsifyingCommand")),
        ),
        (
            &div,
            "signs no dispute pointer",
            Box::new(drop("disputePointer")),
        ),
        (
            &eq,
            "naming the log `example.com/elsewhere`, and it is logged in \
             `example.com/trigon-evidence`",
            Box::new(argv(set("--origin", "example.com/elsewhere"))),
        ),
        (
            &div,
            "naming the log `example.com/elsewhere`",
            Box::new(argv(set("--origin", "example.com/elsewhere"))),
        ),
        (
            &eq,
            "whose `--lookup` is `sha256:0000",
            Box::new(argv(set(
                "--lookup",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ))),
        ),
        (
            &eq,
            "whose `--predicate` is `https://trigon.dev/divergence/v2`",
            Box::new(argv(set("--predicate", "https://trigon.dev/divergence/v2"))),
        ),
        (
            &eq,
            "without `--origin`",
            Box::new(argv(|a| {
                let at = a.iter().position(|x| x == "--origin").unwrap();
                a.drain(at..at + 2);
            })),
        ),
        (
            &eq,
            "gives `--origin` 2 times",
            Box::new(argv(|a| {
                a.extend(["--origin".to_string(), "example.com/trigon-evidence".into()])
            })),
        ),
        (
            &eq,
            "is not `trigon verify-attestation`",
            Box::new(argv(|a| a[0] = "sh".into())),
        ),
        (
            &div,
            "not an `https://` URL",
            Box::new(|st: &mut Statement| {
                st.predicate["disputePointer"]["url"] = "http://example.com/issues".into();
            }),
        ),
        (
            &eq,
            "not an `https://` URL",
            Box::new(|st: &mut Statement| {
                st.predicate["disputePointer"] =
                    serde_json::json!({"kind": "email", "address": "x@example.com"});
            }),
        ),
    ];
    for (m, says, edit) in &cases {
        let edited = resigned(m, &k3, T0, None, |i, st| {
            if i == 0 {
                edit(st)
            }
        });
        let e = verify_alone(&edited).unwrap_err();
        assert!(matches!(e, RecordFailure::Recourse(_)), "{says}: {e}");
        assert_eq!(e.kind(), "no-recourse");
        assert!(e.to_string().contains(says), "{says}: {e}");
    }

    // An equivalence is no accusation, and need not say where to dispute it.
    let without = resigned(&eq, &k3, T0, None, |i, st| {
        if i == 0 {
            drop("disputePointer")(st)
        }
    });
    verify_alone(&without).unwrap();
    verify_alone(&eq).unwrap();
    verify_alone(&div).unwrap();
}

/// `bytes`, logged under `like`'s leaf with only the record digest changed: for a record file
/// `record_leaf` would refuse to write a leaf for, or one whose leaf is beside the point.
fn logged_as(bytes: Vec<u8>, like: &Made) -> Made {
    Made {
        leaf: trigon_attest::log::RecordLeaf {
            record: sha256(&bytes),
            ..like.leaf.clone()
        },
        digest: sha256(&bytes),
        bytes,
        evidence: like.evidence.clone(),
    }
}

/// `m`'s record file with statement `at` replaced by `st`, signed with `key`, and the file encoded
/// as it stands rather than assembled again: a record `Record::assemble` would refuse to write.
fn with_statement(m: &Made, at: usize, st: &Statement, key: &LocalKey) -> Vec<u8> {
    let mut record = Record::from_slice(&m.bytes).unwrap();
    record.statements[at] = sign_statement(st, key).unwrap();
    record.encode().unwrap()
}

/// Each failure has a short name of its own, which `--output json` carries for a machine to sort
/// by.
#[test]
fn every_way_a_record_fails_has_a_name_of_its_own() {
    let d = sha256(b"a record");
    let at = LeafPos { log: 0, index: 1 };
    let why = || "why".to_string();
    let names: Vec<&str> = [
        RecordFailure::Unlogged { record: d },
        RecordFailure::LoggedTwice {
            record: d,
            leaves: vec![at, at],
        },
        RecordFailure::NotItsLeaf { leaf: d, file: d },
        RecordFailure::Unreadable(why()),
        RecordFailure::Signature(why()),
        RecordFailure::Leaf(why()),
        RecordFailure::Statements(why()),
        RecordFailure::Recourse(why()),
        RecordFailure::Map(why()),
        RecordFailure::Evidence(why()),
        RecordFailure::WrongKey(why()),
    ]
    .iter()
    .map(RecordFailure::kind)
    .collect();
    assert_eq!(
        names,
        [
            "unlogged",
            "logged-twice",
            "not-its-leaf",
            "unreadable",
            "signature",
            "disagrees-with-leaf",
            "statements",
            "no-recourse",
            "unsigned-map",
            "evidence",
            "wrong-key",
        ]
    );
}

/// An envelope a record holds is an in-toto statement, or the record is unreadable: another payload
/// type, or a payload that is not a statement, is refused before any signature is trusted.
#[test]
fn an_envelope_that_is_not_an_in_toto_statement_makes_its_record_unreadable() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);

    let mut record = Record::from_slice(&m.bytes).unwrap();
    record.statements[1].payload_type = "application/json".into();
    let e = verify_alone(&logged_as(record.encode().unwrap(), &m)).unwrap_err();
    assert!(matches!(e, RecordFailure::Unreadable(_)), "{e}");
    assert!(e.to_string().contains("`application/json`"), "{e}");

    let mut record = Record::from_slice(&m.bytes).unwrap();
    record.statements[1] = trigon_attest::Envelope::new(br#"{"not":"a statement"}"#, Vec::new());
    let e = record.statement().unwrap_err();
    assert!(e.to_string().contains("not an in-toto statement"), "{e}");
    let e = verify_alone(&logged_as(record.encode().unwrap(), &m)).unwrap_err();
    assert!(matches!(e, RecordFailure::Unreadable(_)), "{e}");
    assert!(e.to_string().contains("not an in-toto statement"), "{e}");
}

/// A record is one result about one artifact. A statement naming two subjects is refused by the
/// writer, which will not assemble or log it, and by every reader, however it came to be logged.
#[test]
fn a_statement_about_two_subjects_is_neither_written_nor_accepted() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let mut st = m.statement();
    st.subject.push(pairs()["b"].subject());
    let bytes = with_statement(&m, 0, &st, &k3);

    let e = record_leaf(&bytes, &k3.key_id(), T0).unwrap_err();
    assert!(e.to_string().contains("names 2 subjects"), "{e}");
    let statements = Record::from_slice(&bytes).unwrap().statements;
    let e = Record::assemble(statements).unwrap_err();
    assert!(e.to_string().contains("names 2"), "{e}");

    let e = verify_alone(&logged_as(bytes, &m)).unwrap_err();
    assert!(matches!(e, RecordFailure::Leaf(_)), "{e}");
    assert!(e.to_string().contains("names 2 subjects"), "{e}");
}

/// A record holds one result: two verdicts in one file is no record, and a writer will not
/// assemble a statement that signs no purl, since no client could find it by one.
#[test]
fn a_record_is_one_result_that_can_be_found() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let mut record = Record::from_slice(&m.bytes).unwrap();
    record.statements.push(record.statements[0].clone());
    let e = record.statement().unwrap_err();
    assert!(e.to_string().contains("holds 2 verdict"), "{e}");
    let e = verify_alone(&logged_as(record.encode().unwrap(), &m)).unwrap_err();
    assert!(matches!(e, RecordFailure::Unreadable(_)), "{e}");

    let mut st = m.statement();
    st.predicate.as_object_mut().unwrap().remove("purl");
    let bytes = with_statement(&m, 0, &st, &k3);
    let statements = Record::from_slice(&bytes).unwrap().statements;
    let e = Record::assemble(statements).unwrap_err();
    assert!(e.to_string().contains("signs no purl"), "{e}");
}

/// A statement signs each piece of evidence as `{"sha256": <64 lowercase hex>}` under its
/// `evidence`. Anything else is not a digest this build can check, and is refused rather than read
/// past — by the writer assembling the record, and by a reader comparing the map against it.
#[test]
fn evidence_signed_as_anything_but_a_sha256_is_refused_not_read_past() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let hex = m.statement().predicate["evidence"]["comparison"]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    for (what, evidence) in [
        ("not an object", serde_json::json!("sha256:0")),
        (
            "capitals",
            serde_json::json!({ "comparison": { "sha256": hex.to_uppercase() } }),
        ),
        (
            "too short",
            serde_json::json!({ "comparison": { "sha256": &hex[..63] } }),
        ),
        (
            "a second digest",
            serde_json::json!({ "comparison": { "sha256": hex, "sha512": "00" } }),
        ),
        ("a bare string", serde_json::json!({ "comparison": hex })),
    ] {
        let mut st = m.statement();
        st.predicate["evidence"] = evidence;
        let bytes = with_statement(&m, 0, &st, &k3);
        let statements = Record::from_slice(&bytes).unwrap().statements;
        let e = Record::assemble(statements).unwrap_err();
        assert!(e.to_string().contains("signs"), "{what}: {e}");
        let e = verify_alone(&logged_as(bytes, &m)).unwrap_err();
        assert!(matches!(e, RecordFailure::Unreadable(_)), "{what}: {e}");
    }
}

/// A statement of a kind this build does not read, signed by the source's key, is read past: a
/// later writer may add one, and a reader that refused it would refuse every record after it.
#[test]
fn a_signed_statement_of_a_kind_this_build_does_not_read_is_read_past() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let mut record = Record::from_slice(&m.bytes).unwrap();
    let mut later: Statement =
        serde_json::from_slice(&record.statements[1].decoded_payload().unwrap()).unwrap();
    later.predicate_type = "https://example.com/a-later-kind/v1".into();
    record.statements.push(sign_statement(&later, &k3).unwrap());
    let bytes = Record::assemble(record.statements)
        .unwrap()
        .encode()
        .unwrap();
    let with = Made {
        leaf: leaf_for(&bytes, &k3, T0),
        digest: sha256(&bytes),
        bytes,
        evidence: m.evidence.clone(),
    };
    let v = verify_alone(&with).unwrap();
    assert_eq!(v.kind(), RecordKind::Verdict(Match::Normalized));
    assert_eq!(v.record.statements.len(), 4);
}

/// What accompanies a verdict is compared as signed, and a value that is not a string is shown as
/// its JSON, never as though it were absent.
#[test]
fn a_rebuild_of_another_run_is_refused_whatever_its_run_is_written_as() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let edited = resigned(&m, &k3, T0, None, |i, st| {
        if i == 1 {
            st.predicate["runDetails"]["metadata"]["invocationId"] = 7.into()
        }
    });
    let e = verify_alone(&edited).unwrap_err();
    assert!(matches!(e, RecordFailure::Statements(_)), "{e}");
    assert!(
        e.to_string()
            .contains("of the run `7`, and its verdict of the run `1789000000-aaaaaaa1`"),
        "{e}"
    );
}

/// A falsifying command is an argv a client runs without parsing a shell line: one signed as
/// anything else is no recourse.
#[test]
fn a_falsifying_command_that_is_not_an_argv_is_no_recourse() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let edited = resigned(&m, &k3, T0, None, |i, st| {
        if i == 0 {
            st.predicate["falsifyingCommand"] =
                "trigon verify-attestation --lookup sha256:00".into()
        }
    });
    let e = verify_alone(&edited).unwrap_err();
    assert!(matches!(e, RecordFailure::Recourse(_)), "{e}");
    assert!(e.to_string().contains("that is not an argv"), "{e}");
}

/// An unsigned map left empty disagrees with a statement that signs a subject and evidence: it is
/// said as naming nothing, never passed as naming what the statement does.
#[test]
fn an_unsigned_map_emptied_disagrees_with_what_is_signed() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    for (says, edit) in [
        (
            "its unsigned subject names no digest",
            (|r: &mut Record| r.subject.digests.clear()) as fn(&mut Record),
        ),
        ("its unsigned evidence map names nothing", |r| {
            r.evidence.clear()
        }),
    ] {
        let mut record = Record::from_slice(&m.bytes).unwrap();
        edit(&mut record);
        let e = verify_alone(&logged_as(record.encode().unwrap(), &m)).unwrap_err();
        assert!(matches!(e, RecordFailure::Map(_)), "{says}: {e}");
        assert!(e.to_string().contains(says), "{says}: {e}");
    }
}

/// Evidence that is there and cannot be read is unchecked, with why, and never passed: the record
/// still verifies on what it signs, as with evidence a clone left out.
#[test]
fn evidence_that_cannot_be_read_is_unchecked_and_never_passed() {
    let tmp = tempfile::tempdir().unwrap();
    copy(&repo(), tmp.path());
    let r = open(tmp.path());
    let bytes = r.read_record(&digest("a2")).unwrap().unwrap();
    let v = r.verify_record(&bytes).unwrap();
    let comparison = v.evidence.iter().find(|e| e.name == "comparison").unwrap();
    let path = tmp
        .path()
        .join(trigon_attest::evidence::evidence_path(&comparison.digest));
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let v = r.verify_record(&bytes).unwrap();
    let state = &v
        .evidence
        .iter()
        .find(|e| e.name == "comparison")
        .unwrap()
        .state;
    assert!(
        matches!(state, EvidenceState::Unreadable(why) if why.contains("not a regular file")),
        "{state:?}"
    );
    assert!(!state.checked());
    assert_eq!(v.unchecked().count(), 2);
}

/// Found under a key the signed subject does not carry, or under a purl or a package that is not
/// one under the rule the record was signed under, a record is refused as found under the wrong
/// key: never accepted for a key it is not about.
#[test]
fn a_record_is_never_accepted_under_a_key_it_does_not_carry() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    // The verdict and its observation about a subject with no sha1.
    let without = resigned(&m, &k3, T0, None, |i, st| {
        if i != 1 {
            st.subject[0].digest.remove("sha1");
        }
    });
    let sha1 = m.leaf.subject["sha1"].clone();
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&without, &m]);
    let r = open(tmp.path());
    let check = |made: &Made, key: Key| {
        let (pos, leaf) = r
            .record_leaves()
            .find(|(_, l)| l.record == made.digest)
            .unwrap();
        check_record(
            &made.bytes,
            Some((pos, leaf)),
            ORIGIN,
            r.keys(),
            r.files(),
            Some(&key),
        )
    };
    let e = check(
        &without,
        Key::Digest {
            algorithm: "sha1",
            hex: sha1.clone(),
        },
    )
    .unwrap_err();
    assert!(matches!(e, RecordFailure::WrongKey(_)), "{e}");
    assert!(e.to_string().contains("names no sha1"), "{e}");

    // A purl or a package that is none under the record's rule matches no leaf, and is refused
    // where a record is checked against it all the same.
    for key in [
        Key::Purl("not a purl".into()),
        Key::Package("not a purl".into()),
    ] {
        assert!(!key.matches(&m.leaf), "{key}");
        let e = check(&m, key.clone()).unwrap_err();
        assert!(matches!(e, RecordFailure::WrongKey(_)), "{key}: {e}");
    }
}

/// An observation that signs no egress tier, where its verdict's run signs one, is not an
/// observation of that run: refused, and its absence said as none.
#[test]
fn an_observation_that_signs_no_egress_tier_is_not_of_its_verdicts_run() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let edited = resigned(&m, &k3, T0, None, |i, st| {
        if i == 2 {
            st.predicate.as_object_mut().unwrap().remove("egressTier");
        }
    });
    let e = verify_alone(&edited).unwrap_err();
    assert!(matches!(e, RecordFailure::Statements(_)), "{e}");
    assert!(
        e.to_string()
            .contains("under the egress tier none, and its verdict's run under `mirror-only`"),
        "{e}"
    );
}

/// Evidence read through another reader than the repository's own directory — a partial clone's
/// objects — is held to its signed digest all the same: the bytes signed are returned, other bytes
/// fail, and a file not there is unchecked.
#[test]
fn evidence_read_through_another_reader_is_held_to_its_signed_digest() {
    use trigon_attest::evidence::read_evidence_from;
    let r = open_golden();
    let bytes = r.read_record(&digest("a2")).unwrap().unwrap();
    let v = r.verify_record(&bytes).unwrap();
    let report = v.evidence.iter().find(|e| e.name == "comparison").unwrap();
    let (state, read) = read_evidence_from(r.files(), report).unwrap();
    assert_eq!(state, EvidenceState::Matches);
    assert_eq!(sha256(&read.unwrap()), report.digest);

    let tmp = tempfile::tempdir().unwrap();
    let elsewhere = DirFiles::new(tmp.path());
    assert_eq!(
        read_evidence_from(&elsewhere, report).unwrap(),
        (EvidenceState::Absent, None)
    );
    let path = trigon_attest::evidence::evidence_path(&report.digest);
    crate::build::write(tmp.path(), &path, b"another report");
    let e = read_evidence_from(&elsewhere, report).unwrap_err();
    assert!(matches!(e, RecordFailure::Evidence(_)), "{e}");
    let asset = v
        .evidence
        .iter()
        .find(|e| e.name == "rebuiltArtifact")
        .unwrap();
    assert_eq!(
        read_evidence_from(&elsewhere, asset).unwrap(),
        (EvidenceState::ReleaseAsset, None)
    );
}

/// A falsifying command too short to be `trigon verify-attestation` is no recourse, said as what it
/// is and never read past its end; and the command alone, with no flag after it, resolves no
/// record.
#[test]
fn a_falsifying_command_too_short_to_resolve_a_record_is_no_recourse() {
    let k3 = attestation_key(3);
    let m = verdict(&pairs()["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let cases: [(&[&str], &str); 3] = [
        (&[], "is not `trigon verify-attestation`: ``"),
        (&["trigon"], "is not `trigon verify-attestation`: `trigon`"),
        (&["trigon", "verify-attestation"], "without `--lookup`"),
    ];
    for (argv, says) in cases {
        let edited = resigned(&m, &k3, T0, None, |i, st| {
            if i == 0 {
                st.predicate["falsifyingCommand"]["argv"] = serde_json::json!(argv);
            }
        });
        let e = verify_alone(&edited).unwrap_err();
        assert!(matches!(e, RecordFailure::Recourse(_)), "{argv:?}: {e}");
        assert!(e.to_string().contains(says), "{argv:?}: {e}");
    }
}

/// A void or a withdrawal is one statement alone, whatever a second one is: even a statement of a
/// kind this build reads past beside a verdict, signed by the source's key, makes it no void and no
/// withdrawal.
#[test]
fn a_void_or_a_withdrawal_with_any_second_statement_is_refused() {
    let p = pairs();
    let k3 = attestation_key(3);
    let v = void(&p["c"], &k3, "1789000000-cccccccc", T0);
    let of = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let w = withdrawal(&of, &k3, T0 + 60);
    for m in [&v, &w] {
        verify_alone(m).unwrap();
        let mut record = Record::from_slice(&m.bytes).unwrap();
        let mut later = m.statement();
        later.predicate_type = "https://example.com/a-later-kind/v1".into();
        record.statements.push(sign_statement(&later, &k3).unwrap());
        let e = verify_alone(&logged_as(record.encode().unwrap(), m)).unwrap_err();
        assert!(matches!(e, RecordFailure::Statements(_)), "{e}");
        assert!(
            e.to_string()
                .contains("holds one statement, and this one holds 2"),
            "{e}"
        );
    }
}

/// A dispute pointer is somewhere a reader can open: `https://` and a place after it. The scheme
/// alone points nowhere, and is no recourse.
#[test]
fn a_dispute_pointer_that_is_the_scheme_alone_is_no_recourse() {
    let k3 = attestation_key(3);
    let div = verdict(&pairs()["b"], &k3, "1789000000-bbbbbbbb", None, T0);
    for (url, verifies) in [("https://", false), ("https://x", true)] {
        let edited = resigned(&div, &k3, T0, None, |i, st| {
            if i == 0 {
                st.predicate["disputePointer"]["url"] = url.into();
            }
        });
        match verify_alone(&edited) {
            Ok(_) => assert!(verifies, "{url}"),
            Err(e) => {
                assert!(!verifies, "{url}: {e}");
                assert!(matches!(e, RecordFailure::Recourse(_)), "{url}: {e}");
                assert!(
                    e.to_string().contains("not an `https://` URL"),
                    "{url}: {e}"
                );
            }
        }
    }
}
