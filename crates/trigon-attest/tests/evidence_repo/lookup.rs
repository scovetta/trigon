//! Lookup over the verified leaves, and supersession (`docs/19` §3, §4.2, §5, §6).

use base64::Engine as _;
use trigon_attest::evidence::{Answer, Key, RecordFailure, RecordState};
use trigon_attest::{SupersedeReason, Supersession};
use trigon_core::Match;

use crate::build::{
    Pair, copy, digest, open, open_golden, pairs, repo, small, verdict, withdrawal,
};
use crate::common::{T0, attestation_key};

const FLOOR: Match = Match::NormalizedWithCaveats;

fn answer(r: &trigon_attest::evidence::Repository, key: &str) -> Answer {
    r.lookup(&Key::parse(key).unwrap()).answer(FLOOR)
}

/// Every state `docs/19` §4.2 has a client tell apart, from one repository, with the exit code
/// §6 gives each.
#[test]
fn every_state_is_told_apart_and_has_its_exit_code() {
    let r = open_golden();
    let failed = |a: Answer| match a {
        Answer::Failed(why) => why,
        other => panic!("expected a failure, got {other}"),
    };
    for (key, want, code) in [
        (
            "pkg:npm/demo-a@1.0.0",
            Answer::Outcome(Match::Normalized),
            0,
        ),
        ("pkg:npm/demo-b@1.0.0", Answer::Outcome(Match::Divergent), 1),
        ("pkg:npm/demo-c@1.0.0", Answer::Void, 3),
        ("pkg:npm/demo-d@1.0.0", Answer::Withdrawn, 2),
        ("pkg:npm/demo-e@1.0.0", Answer::Outcome(Match::Exact), 0),
        ("pkg:npm/demo-f@1.0.0", Answer::Deleted, 4),
        // In the successor log.
        (
            "pkg:npm/demo-k@1.0.0",
            Answer::Outcome(Match::Normalized),
            0,
        ),
        // Signed, and never logged: a lookup reads the log, so it never sees it.
        ("pkg:npm/demo-j@1.0.0", Answer::NeverChecked, 2),
        ("pkg:npm/nothing@1.0.0", Answer::NeverChecked, 2),
    ] {
        let got = answer(&r, key);
        assert_eq!(got, want, "{key}");
        assert_eq!(got.exit_code(FLOOR), code, "{key}");
    }
    assert!(matches!(
        failed(answer(&r, "pkg:npm/demo-g@1.0.0")),
        RecordFailure::Signature(_)
    ));
    assert!(matches!(
        failed(answer(&r, "pkg:npm/demo-h@1.0.0")),
        RecordFailure::Signature(_)
    ));
    assert!(matches!(
        failed(answer(&r, "pkg:npm/demo-i@1.0.0")),
        RecordFailure::Leaf(_)
    ));
    assert_eq!(
        answer(&r, "pkg:npm/demo-g@1.0.0").exit_code(FLOOR),
        4,
        "failed verification exits 4, never as never checked"
    );
    // An outcome below the floor is 3, and `--min` moves the floor.
    assert_eq!(
        answer(&r, "pkg:npm/demo-a@1.0.0").exit_code(Match::Exact),
        3
    );
}

#[test]
fn a_key_is_resolved_from_the_leaves_by_every_digest_and_purl_the_subject_carries() {
    let r = open_golden();
    let pair = &pairs()["e"];
    let key = Key::of_bytes(&pair.upstream);
    let Key::File(d) = &key else { unreachable!() };
    let sri = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD
            .encode(<sha2::Sha512 as sha2::Digest>::digest(&pair.upstream))
    );
    for k in [
        format!("sha256:{}", d["sha256"]),
        format!("sha512:{}", d["sha512"]),
        format!("sha1:{}", d["sha1"]),
        format!("sha256:{}", d["sha256"].to_uppercase()),
        sri,
        "pkg:npm/demo-e@1.0.0".into(),
        "pkg:npm/Demo-E@1.0.0".into(),
        "pkg:npm/demo-e".into(),
    ] {
        let found = r.lookup(&Key::parse(&k).unwrap());
        assert_eq!(found.found.len(), 1, "{k}");
        assert_eq!(found.found[0].leaf.record, digest("e"), "{k}");
        assert_eq!(found.answer(FLOOR), Answer::Outcome(Match::Exact), "{k}");
    }
    let found = r.lookup(&key);
    assert_eq!(found.answer(FLOOR), Answer::Outcome(Match::Exact));

    // A package key finds every version, which is one here, and another package finds nothing.
    assert!(
        r.lookup(&Key::parse("pkg:npm/demo").unwrap())
            .found
            .is_empty()
    );
    assert!(
        r.lookup(&Key::parse("pkg:pypi/demo-e@1.0.0").unwrap())
            .found
            .is_empty()
    );
}

#[test]
fn keys_that_are_not_keys_are_refused_with_what_a_key_is() {
    for bad in [
        "sha256:abc",
        "sha512:zz",
        "sha1-AAAA",
        "sha384-AAAA",
        "md5:d41d8cd98f00b204e9800998ecf8427e",
        "left-pad@1.3.0",
        "pkg:",
        "",
    ] {
        let e = Key::parse(bad).unwrap_err().to_string();
        assert!(!e.is_empty(), "{bad}");
    }
    let e = Key::parse("sha256:abc").unwrap_err().to_string();
    assert!(e.contains("64 hex digits"), "{e}");
    let e = Key::parse("left-pad@1.3.0").unwrap_err().to_string();
    assert!(e.contains("sha512-<base64>") && e.contains("purl"), "{e}");
}

#[test]
fn a_superseded_record_is_returned_marked_and_never_hidden() {
    let r = open_golden();
    let found = r.lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    let records: Vec<_> = found.found.iter().map(|f| f.leaf.record).collect();
    assert_eq!(records, [digest("a1"), digest("a2")]);
    let (a1, a2) = (&found.found[0], &found.found[1]);
    assert!(!a1.is_current() && a2.is_current());
    assert_eq!(a1.superseded_by.len(), 1);
    let by = &a1.superseded_by[0];
    assert_eq!(
        (by.record, by.pos.index, a1.pos.index, by.reason),
        (digest("a2"), 8, 0, SupersedeReason::SetChanged)
    );
    assert!(matches!(a1.state, RecordState::Verified(_)));

    // Withdrawn: the verdict is superseded by the withdrawal, and both are returned.
    let found = r.lookup(&Key::parse("pkg:npm/demo-d@1.0.0").unwrap());
    assert_eq!(found.found.len(), 2);
    assert_eq!(
        found.found[0].superseded_by[0].reason,
        SupersedeReason::Withdrawn
    );
    assert_eq!(found.answer(FLOOR), Answer::Withdrawn);
}

/// §3: dropped only by a verified, logged record, signed by a key trusted for it, that names it,
/// has a later leaf, and has the same subject digests and canonical purl. Each clause, broken.
#[test]
fn supersession_takes_every_clause_of_docs_19_3() {
    let p = pairs();
    let (k3, k9) = (attestation_key(3), attestation_key(9));
    let first = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0 + 60);
    let names = |r: SupersedeReason| {
        Some(Supersession {
            record: first.digest,
            reason: r,
        })
    };

    // A later leaf, the same subject and purl, verified: superseded.
    let later = verdict(
        &p["a"],
        &k3,
        "1789000100-aaaaaaa2",
        names(SupersedeReason::SetChanged),
        T0 + 120,
    );
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&first, &later]);
    let found = open(tmp.path()).lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    assert_eq!(found.found[0].superseded_by.len(), 1);

    // An earlier leaf naming it: not superseded, and two current records.
    let earlier = verdict(
        &p["a"],
        &k3,
        "1789000100-aaaaaaa2",
        names(SupersedeReason::SetChanged),
        T0,
    );
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&earlier, &first]);
    let found = open(tmp.path()).lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    assert_eq!(found.current().count(), 2);

    // Signed by a key the source does not trust: it fails, and supersedes nothing.
    let stranger = verdict(
        &p["a"],
        &k9,
        "1789000100-aaaaaaa2",
        names(SupersedeReason::SetChanged),
        T0 + 120,
    );
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&first, &stranger]);
    let found = open(tmp.path()).lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    assert!(found.found[0].is_current());
    assert!(matches!(found.answer(FLOOR), Answer::Failed(_)));

    // The same bytes under another package: the same subject digests, another purl.
    let renamed = Pair {
        name: "demo-other".into(),
        ..p["a"].clone()
    };
    let other = verdict(
        &renamed,
        &k3,
        "1789000100-aaaaaaa2",
        names(SupersedeReason::SetChanged),
        T0 + 120,
    );
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&first, &other]);
    let found = open(tmp.path())
        .lookup(&Key::parse(&format!("sha256:{}", first.leaf.subject["sha256"])).unwrap());
    assert_eq!(found.found.len(), 2);
    assert!(found.found.iter().all(|f| f.is_current()), "{found:?}");

    // Another artifact under the same purl: another subject.
    let rebuilt_again = Pair {
        upstream: crate::build::tar(1, b"A\n"),
        ..p["a"].clone()
    };
    let another = verdict(
        &rebuilt_again,
        &k3,
        "1789000100-aaaaaaa2",
        names(SupersedeReason::SetChanged),
        T0 + 120,
    );
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&first, &another]);
    let found = open(tmp.path()).lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    assert_eq!(found.current().count(), 2);
    // Two subjects under one purl, each with its own answer.
    assert_eq!(found.subjects().len(), 2);
}

/// A record logged a second time after the withdrawal of it would, judged leaf by leaf, be current
/// again: its second leaf is later than the withdrawal's. Anyone holding the log key alone can do
/// that in the one public history, with no fork, so a record at two leaves fails verification at
/// both, and the subject answers failed, never the verdict.
#[test]
fn a_record_logged_again_after_its_withdrawal_fails_and_never_answers_again() {
    let p = pairs();
    let k3 = attestation_key(3);
    let d0 = verdict(&p["d"], &k3, "1789000000-dddddddd", None, T0);
    let w = withdrawal(&d0, &k3, T0 + 60);
    let again = crate::build::Made {
        leaf: trigon_attest::log::RecordLeaf {
            time: T0 + 120,
            ..d0.leaf.clone()
        },
        ..d0.clone()
    };
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&d0, &w, &again]);
    let r = open(tmp.path());

    let found = r.lookup(&Key::parse("pkg:npm/demo-d@1.0.0").unwrap());
    let states: Vec<_> = found
        .found
        .iter()
        .map(|f| (f.pos.index, matches!(f.state, RecordState::Verified(_))))
        .collect();
    assert_eq!(states, [(0, false), (1, true), (2, false)]);
    for f in [&found.found[0], &found.found[2]] {
        let RecordState::Failed(RecordFailure::LoggedTwice { record, leaves }) = &f.state else {
            panic!("{:?}", f.state)
        };
        assert_eq!(*record, d0.digest);
        assert_eq!(leaves.iter().map(|l| l.index).collect::<Vec<_>>(), [0, 2]);
    }
    let a = found.answer(FLOOR);
    assert!(
        matches!(a, Answer::Failed(RecordFailure::LoggedTwice { .. })),
        "{a}"
    );
    assert_eq!(a.exit_code(FLOOR), 4);

    // Handed in whole, the same.
    let e = r.verify_record(&d0.bytes).unwrap_err();
    assert!(matches!(e, RecordFailure::LoggedTwice { .. }), "{e}");
    assert!(
        e.to_string().contains("leaf 0 of log 0, leaf 2 of log 0"),
        "{e}"
    );
    // The withdrawal, logged once, still verifies.
    assert!(r.verify_record(&w.bytes).is_ok());
}

#[test]
fn two_current_records_for_one_subject_are_both_returned_and_the_more_severe_answers() {
    let p = pairs();
    let k3 = attestation_key(3);
    let normalized = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    // The same published artifact, rebuilt into something else: a divergence about one subject.
    let diverged = Pair {
        rebuilt: crate::build::tar(2, b"A\n"),
        ..p["a"].clone()
    };
    let divergent = verdict(&diverged, &k3, "1789000100-aaaaaaa2", None, T0 + 60);
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&normalized, &divergent]);
    let found = open(tmp.path()).lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    assert_eq!(found.current().count(), 2);
    assert_eq!(found.subjects().len(), 1);
    assert_eq!(found.answer(FLOOR), Answer::Outcome(Match::Divergent));
    assert_eq!(found.answer(FLOOR).exit_code(FLOOR), 1);

    // And a withdrawal beside a current verdict it does not name leaves the verdict answering.
    let w = withdrawal(&divergent, &k3, T0 + 120);
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&normalized, &divergent, &w]);
    let found = open(tmp.path()).lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    assert_eq!(found.answer(FLOOR), Answer::Outcome(Match::Normalized));
}

#[test]
fn a_verdict_capped_below_normalized_answers_as_one() {
    // `normalized_with_caveats` from the tar profile's passes alone is not reachable, so the
    // statement is edited before it is signed: lookup reads what is signed and logged, and does
    // not re-derive it.
    let pair = &pairs()["a"];
    let k3 = attestation_key(3);
    let m = verdict(pair, &k3, "1789000000-aaaaaaa1", None, T0);
    let mut record = trigon_attest::Record::from_slice(&m.bytes).unwrap();
    let mut st = m.statement();
    st.predicate["outcome"] = "normalized_with_caveats".into();
    record.statements[0] = trigon_attest::sign_statement(&st, &k3).unwrap();
    let bytes = record.encode().unwrap();
    let m = crate::build::Made {
        leaf: crate::build::leaf_for(&bytes, &k3, T0),
        digest: crate::build::sha256(&bytes),
        bytes,
        evidence: m.evidence,
    };
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&m]);
    let a = answer(&open(tmp.path()), "pkg:npm/demo-a@1.0.0");
    assert_eq!(a, Answer::Outcome(Match::NormalizedWithCaveats));
    assert_eq!(a.exit_code(Match::NormalizedWithCaveats), 0);
    assert_eq!(a.exit_code(Match::Normalized), 3);
}

#[test]
fn a_record_file_deleted_is_deleted_whatever_its_leaf_says() {
    let tmp = tempfile::tempdir().unwrap();
    copy(&repo(), tmp.path());
    std::fs::remove_file(
        tmp.path()
            .join(trigon_attest::evidence::record_path(&digest("b"))),
    )
    .unwrap();
    let r = open(tmp.path());
    let found = r.lookup(&Key::parse("pkg:npm/demo-b@1.0.0").unwrap());
    assert!(matches!(found.found[0].state, RecordState::Deleted));
    assert_eq!(found.answer(FLOOR), Answer::Deleted);
    assert_eq!(found.answer(FLOOR).exit_code(FLOOR), 4);

    // The superseding record gone: the one it superseded is current again, and the subject is
    // still deleted, since a deletion is evidence whatever else is there.
    std::fs::remove_file(
        tmp.path()
            .join(trigon_attest::evidence::record_path(&digest("a2"))),
    )
    .unwrap();
    let found = r.lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    assert!(found.found[0].is_current());
    assert_eq!(found.answer(FLOOR), Answer::Deleted);
}

#[test]
fn a_record_whose_index_entries_are_removed_or_altered_is_still_found() {
    let tmp = tempfile::tempdir().unwrap();
    copy(&repo(), tmp.path());
    // Every index file, gone.
    std::fs::remove_dir_all(tmp.path().join("index")).unwrap();
    let r = open(tmp.path());
    assert_eq!(
        answer(&r, "pkg:npm/demo-e@1.0.0"),
        Answer::Outcome(Match::Exact)
    );
    // And an index that lies — naming the divergence under demo-e's keys — changes nothing.
    let e = pairs()["e"].clone();
    for key in Key::parse("pkg:npm/demo-e@1.0.0").unwrap().index_keys() {
        let file = trigon_attest::evidence::IndexFile {
            key: key.name(),
            records: vec![trigon_attest::evidence::IndexEntry {
                record: digest("b"),
                leaf: 1,
                log: None,
            }],
        };
        crate::build::write(tmp.path(), &key.path(), &file.encode().unwrap());
    }
    assert_eq!(
        answer(&r, "pkg:npm/demo-e@1.0.0"),
        Answer::Outcome(Match::Exact)
    );
    assert_eq!(
        r.lookup(&Key::of_bytes(&e.upstream)).answer(FLOOR),
        Answer::Outcome(Match::Exact)
    );
}
