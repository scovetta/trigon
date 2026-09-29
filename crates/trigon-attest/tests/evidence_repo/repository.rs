//! A repository opened, and a source's chain read as one across the repositories it goes on in
//! (`docs/19` §6.1, §8): each log's records and evidence read from the repository that holds the
//! log, what a later repository sets aside said with it, and a repository that is not the chain's
//! next refused.

use std::path::{Path, PathBuf};

use trigon_attest::evidence::{
    Answer, EvidenceState, Key, RECORD_LIMIT, RecordFailure, RecordState, Repository,
    evidence_path, record_path,
};
use trigon_attest::log::{
    Leaf, LeafPos, LogContinuationLeaf, LogEndLeaf, LogError, LogSigner, RefusedLog, Successor,
    VerifiedSource, verify_continuation, verify_source,
};
use trigon_core::Match;

use crate::build::{Made, open, pairs, pinned, sha256, small, verdict, verdict_in};
use crate::common::{ORIGIN, SUCCESSOR, T0, Writer, attestation_key, log_key, successor_key};

const FLOOR: Match = Match::NormalizedWithCaveats;

/// A log-end naming a successor at `log` in another repository.
fn ends_elsewhere(time: u64, origin: &str, key: &LogSigner) -> Leaf {
    Leaf::LogEnd(LogEndLeaf {
        time,
        successor: Successor {
            origin: origin.into(),
            log_key: key.vkey().to_string(),
            urls: vec!["https://example.com/owner/trigon-evidence-2.git".into()],
            dir: "log".into(),
        },
    })
}

/// The log-continuation of the log `old` has written, signed by its key and `next`.
fn continuing(old: &Writer, time: u64, next: &LogSigner) -> Leaf {
    Leaf::LogContinuation(LogContinuationLeaf {
        time,
        checkpoint: old.checkpoint().note().cosign(next).unwrap().to_string(),
    })
}

/// `here`, whose log holds `a` and ends naming a successor in another repository, and `there`,
/// which holds that successor: its continuation, then `k`. Returns both records and the
/// successor's writer.
fn two(here: &Path, there: &Path) -> (Made, Made, Writer) {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let k = verdict_in(
        SUCCESSOR,
        &p["k"],
        &k3,
        "1789000300-kkkkkkkk",
        None,
        T0 + 180,
    );
    let mut old = Writer::init(&here.join("log"), log_key());
    old.append(&[
        Leaf::Record(a.leaf.clone()),
        ends_elsewhere(T0 + 60, SUCCESSOR, &successor_key()),
    ]);
    a.write(here);
    let mut next = Writer::init(&there.join("log"), successor_key());
    next.append(&[
        continuing(&old, T0 + 120, &successor_key()),
        Leaf::Record(k.leaf.clone()),
    ]);
    k.write(there);
    (a, k, next)
}

/// The chain from `here` into `there`, verified part by part as a sync verifies it.
fn parts(here: &Path, there: &Path) -> Vec<(PathBuf, VerifiedSource)> {
    let head = verify_source(here, &log_key().vkey(), None).unwrap();
    let tail = verify_continuation(&head.logs[0].log, there).unwrap();
    vec![(here.to_path_buf(), head), (there.to_path_buf(), tail)]
}

#[test]
fn each_logs_records_and_evidence_are_read_from_the_repository_that_holds_it() {
    let (here, there) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, k, _) = two(here.path(), there.path());
    let r = Repository::chain(parts(here.path(), there.path()), &pinned(), None).unwrap();
    assert_eq!(r.root(), here.path());
    assert_eq!(r.roots().collect::<Vec<_>>(), [here.path(), there.path()]);
    assert_eq!(r.logs().len(), 2);

    let va = r.verify_record(&a.bytes).unwrap();
    assert_eq!(va.pos, LeafPos { log: 0, index: 0 });
    assert_eq!(r.root_of(va.pos), here.path());
    let vk = r.verify_record(&k.bytes).unwrap();
    assert_eq!(vk.pos, LeafPos { log: 1, index: 1 });
    assert_eq!(r.root_of(vk.pos), there.path());
    assert_eq!(
        r.read_record(&k.digest).unwrap().as_deref(),
        Some(k.bytes.as_slice())
    );
    assert_eq!(
        r.lookup(&Key::parse("pkg:npm/demo-k@1.0.0").unwrap())
            .answer(FLOOR),
        Answer::Outcome(Match::Normalized)
    );

    // `k`'s comparison report is only in the repository that holds its log, and is found there.
    let report = vk.evidence.iter().find(|e| e.name == "comparison").unwrap();
    assert_eq!(report.state, EvidenceState::Matches);
    assert!(!here.path().join(evidence_path(&report.digest)).exists());
    let bytes = r.read_evidence(&report.digest).unwrap().unwrap();
    assert_eq!(sha256(&bytes), report.digest);
    assert_eq!(r.read_evidence(&sha256(b"no such evidence")).unwrap(), None);

    // The files of the repository the chain starts in are that repository's alone.
    let files = r.files();
    assert!(
        files
            .read(&record_path(&a.digest), RECORD_LIMIT)
            .unwrap()
            .is_some()
    );
    assert!(
        files
            .read(&record_path(&k.digest), RECORD_LIMIT)
            .unwrap()
            .is_none()
    );
}

/// A directory means something only inside its repository, so what a later repository of the chain
/// sets aside — a `log/<n>` no log-end names, a directory refused — is said with that repository.
#[test]
fn what_a_later_repository_sets_aside_is_said_with_that_repository() {
    let (here, there) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    two(here.path(), there.path());
    let mut stray = Writer::init(&there.path().join("log/3"), successor_key());
    stray.append(&[crate::common::heartbeat(T0)]);
    let mut parts = parts(here.path(), there.path());
    parts[1].1.refused.push(RefusedLog {
        dir: "log/7".into(),
        why: "planted".into(),
    });
    let r = Repository::chain(parts, &pinned(), None).unwrap();
    let in_there = |d: &str| format!("{d} in {}", there.path().display());
    assert_eq!(r.source().unnamed, [in_there("log/3")]);
    assert_eq!(
        r.source().refused,
        [RefusedLog {
            dir: in_there("log/7"),
            why: "planted".into()
        }]
    );
}

/// A repository is the chain's next only where the log before it names a successor elsewhere and
/// it begins with that successor; and a chain never returns to a log it has passed through,
/// across repositories as within one.
#[test]
fn a_repository_that_is_not_the_chains_next_is_refused() {
    let (here, there) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (_, _, mut next) = two(here.path(), there.path());
    let good = parts(here.path(), there.path());

    // Nothing at all.
    let e = Repository::chain(Vec::new(), &pinned(), None).unwrap_err();
    assert!(matches!(e, LogError::Malformed(_)), "{e}");

    // A first repository that names no successor elsewhere.
    let plain = tempfile::tempdir().unwrap();
    let mut w = Writer::init(&plain.path().join("log"), log_key());
    w.append(&[crate::common::heartbeat(T0)]);
    let alone = verify_source(plain.path(), &log_key().vkey(), None).unwrap();
    let e = Repository::chain(
        vec![(plain.path().to_path_buf(), alone.clone()), good[1].clone()],
        &pinned(),
        None,
    )
    .unwrap_err();
    assert!(
        e.to_string().contains("names no successor elsewhere"),
        "{e}"
    );

    // A second that does not begin with the successor named.
    let e = Repository::chain(
        vec![good[0].clone(), (plain.path().to_path_buf(), alone)],
        &pinned(),
        None,
    )
    .unwrap_err();
    assert!(e.to_string().contains("does not begin with it"), "{e}");

    // The successor ends naming a third repository whose log is the first log's origin again.
    let again = || LogSigner::from_seed(ORIGIN, [23; 32]).unwrap();
    next.append(&[ends_elsewhere(T0 + 240, ORIGIN, &again())]);
    let third = tempfile::tempdir().unwrap();
    let mut back = Writer::init(&third.path().join("log"), again());
    back.append(&[continuing(&next, T0 + 300, &again())]);
    let mut parts = parts(here.path(), there.path());
    let tail = verify_continuation(&parts[1].1.logs[0].log, third.path()).unwrap();
    parts.push((third.path().to_path_buf(), tail));
    let e = Repository::chain(parts, &pinned(), None).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("appears twice"), "{e}");
}

/// A record file that is there and cannot be read as one — a directory in its place — is not
/// verified, so never passed: it fails, and the key it is found by answers as failed.
#[test]
fn a_record_file_that_cannot_be_read_fails_and_is_never_passed() {
    let a = verdict(
        &pairs()["a"],
        &attestation_key(3),
        "1789000000-aaaaaaa1",
        None,
        T0,
    );
    let tmp = tempfile::tempdir().unwrap();
    small(tmp.path(), &[&a]);
    let path = tmp.path().join(record_path(&a.digest));
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let found = open(tmp.path()).lookup(&Key::parse("pkg:npm/demo-a@1.0.0").unwrap());
    let [f] = found.found.as_slice() else {
        panic!("{found:?}")
    };
    let RecordState::Failed(RecordFailure::Unreadable(why)) = &f.state else {
        panic!("{:?}", f.state)
    };
    assert!(why.contains("could not be read as a record file"), "{why}");
    assert!(matches!(found.answer(FLOOR), Answer::Failed(_)));
    assert_eq!(found.answer(FLOOR).exit_code(FLOOR), 4);
}
