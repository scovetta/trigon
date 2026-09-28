//! Rotation (`docs/19` §8): an attestation key changed by a key-change leaf, and a log ended by a
//! log-end leaf and continued by its successor — each followed only when it verifies, and a
//! successor nothing names refused.

use std::path::Path;

use trigon_attest::AttestationKey;
use trigon_attest::log::{
    DirFiles, KeyChange, KeyChangeLeaf, KeyHistory, Leaf, LeafPos, LogContinuationLeaf, LogEndLeaf,
    LogError, LogSigner, SignedCheckpoint, SignedNote, Successor, follow, verify_log,
    verify_source,
};

use crate::common::{
    ORIGIN, SUCCESSOR, T0, Writer, attestation_key, heartbeat, heartbeats, log_key, record,
    successor_key,
};

/// The successor every test log names unless it says otherwise: `log/1` in the same repository.
pub fn named() -> Successor {
    Successor {
        origin: SUCCESSOR.into(),
        log_key: successor_key().vkey().to_string(),
        urls: Vec::new(),
        dir: "log/1".into(),
    }
}

pub fn log_end(time: u64) -> Leaf {
    Leaf::LogEnd(LogEndLeaf {
        time,
        successor: named(),
    })
}

/// A log-continuation well formed and holding nothing in particular, for tests of where one may
/// stand.
pub fn continuation(time: u64) -> Leaf {
    let body = format!("{ORIGIN}\n1\n{}=\n", "A".repeat(43));
    let note = SignedNote::sign(&body, &log_key())
        .unwrap()
        .cosign(&successor_key())
        .unwrap();
    Leaf::LogContinuation(LogContinuationLeaf {
        time,
        checkpoint: note.to_string(),
    })
}

/// The first log, at `log/`: `leaves`, then a log-end at `end`.
pub fn ended(repo: &Path, leaves: &[Leaf], end: Leaf) -> Writer {
    let mut w = Writer::init(&repo.join("log"), log_key());
    if !leaves.is_empty() {
        w.append(leaves);
    }
    w.append(&[end]);
    w
}

/// The old log's checkpoint as it stands, signed by `signers` in order.
pub fn continuation_of(old: &Writer, time: u64, signers: &[LogSigner]) -> Leaf {
    let body = old.checkpoint().checkpoint().body();
    let mut note = SignedNote::sign(&body, &signers[0]).unwrap();
    for s in &signers[1..] {
        note = note.cosign(s).unwrap();
    }
    Leaf::LogContinuation(LogContinuationLeaf {
        time,
        checkpoint: note.to_string(),
    })
}

/// A successor at `dir`, signed by `signer`, whose leaves are `leaves`.
pub fn successor_at(repo: &Path, dir: &str, signer: LogSigner, leaves: &[Leaf]) -> Writer {
    let mut w = Writer::init(&repo.join(dir), signer);
    if !leaves.is_empty() {
        w.append(leaves);
    }
    w
}

fn key(n: u8) -> AttestationKey {
    AttestationKey::from(attestation_key(n).public_key())
}

fn at(log: usize, index: u64) -> LeafPos {
    LeafPos { log, index }
}

/// A one-log source with these leaves.
fn one_log(leaves: &[Leaf]) -> (tempfile::TempDir, trigon_attest::log::VerifiedSource) {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(&tmp.path().join("log"), log_key());
    w.append(leaves);
    let source = verify_source(tmp.path(), &log_key().vkey(), None).unwrap();
    (tmp, source)
}

#[test]
fn a_key_change_signed_by_both_keys_advances_the_history() {
    let (k3, k4) = (attestation_key(3), attestation_key(4));
    let (_tmp, source) = one_log(&[
        record(T0, 0, &k3),
        Leaf::KeyChange(KeyChangeLeaf::sign(ORIGIN, T0 + 1, &k3, &k4).unwrap()),
        record(T0 + 2, 2, &k4),
        record(T0 + 3, 3, &k3),
    ]);
    let (history, skipped) = KeyHistory::from_source(key(3), &source).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(history.current(), &key(4));
    assert_eq!(history.epochs().len(), 2);
    assert_eq!(history.epochs()[0].until, Some(at(0, 1)));
    assert_eq!(history.epochs()[1].from, Some(at(0, 1)));

    assert_eq!(
        history.key_for(&key(3).key_id(), at(0, 0)).unwrap(),
        &key(3)
    );
    assert_eq!(
        history.key_for(&key(4).key_id(), at(0, 2)).unwrap(),
        &key(4)
    );
    // From the change on, the old key's records are refused, and the new key's before it too.
    let e = history.key_for(&key(3).key_id(), at(0, 3)).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("leaf 1 of log 0"), "{e}");
    let e = history.key_for(&key(4).key_id(), at(0, 0)).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    // A key the source never had.
    let e = history.key_for(&key(9).key_id(), at(0, 2)).unwrap_err();
    assert!(matches!(e, LogError::Unverified(_)), "{e}");
}

#[test]
fn a_key_change_the_current_key_did_not_sign_is_refused() {
    // A leaf naming the current key as its old one, signed by some other key in its place: what a
    // stolen log key without the attestation key could write.
    let mut forged =
        KeyChangeLeaf::sign(ORIGIN, T0, &attestation_key(9), &attestation_key(4)).unwrap();
    forged.old.public_key = key(3).to_hex();
    forged.old.key_id = key(3).key_id();
    let (_tmp, source) = one_log(&[Leaf::KeyChange(forged)]);
    let e = KeyHistory::from_source(key(3), &source).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("old key"), "{e}");
}

#[test]
fn a_key_change_signed_for_another_log_is_refused() {
    let change = KeyChangeLeaf::sign(
        "example.com/other",
        T0,
        &attestation_key(3),
        &attestation_key(4),
    )
    .unwrap();
    let (_tmp, source) = one_log(&[Leaf::KeyChange(change)]);
    assert!(matches!(
        KeyHistory::from_source(key(3), &source),
        Err(LogError::Rotation(_))
    ));
}

#[test]
fn a_key_change_from_a_key_already_retired_changes_nothing() {
    let (k3, k4, k5) = (attestation_key(3), attestation_key(4), attestation_key(5));
    let (_tmp, source) = one_log(&[
        Leaf::KeyChange(KeyChangeLeaf::sign(ORIGIN, T0, &k3, &k4).unwrap()),
        Leaf::KeyChange(KeyChangeLeaf::sign(ORIGIN, T0 + 1, &k3, &k5).unwrap()),
    ]);
    let (history, skipped) = KeyHistory::from_source(key(3), &source).unwrap();
    assert_eq!(history.current(), &key(4));
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].0, at(0, 1));
    assert!(skipped[0].1.contains("current key is"), "{}", skipped[0].1);
    assert!(history.key_for(&key(5).key_id(), at(0, 2)).is_err());
}

/// A client pinned after a rotation sees the change that led to its pin, changes nothing, and
/// accepts only its pin.
#[test]
fn a_client_pinned_after_a_rotation_starts_from_its_pin() {
    let (k3, k4) = (attestation_key(3), attestation_key(4));
    let (_tmp, source) = one_log(&[
        record(T0, 0, &k3),
        Leaf::KeyChange(KeyChangeLeaf::sign(ORIGIN, T0 + 1, &k3, &k4).unwrap()),
        record(T0 + 2, 2, &k4),
    ]);
    let (history, skipped) = KeyHistory::from_source(key(4), &source).unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(history.current(), &key(4));
    assert_eq!(
        history.key_for(&key(4).key_id(), at(0, 2)).unwrap(),
        &key(4)
    );
    assert!(matches!(
        history.key_for(&key(3).key_id(), at(0, 0)),
        Err(LogError::Unverified(_))
    ));
}

#[test]
fn key_changes_are_followed_in_the_order_the_log_holds_them() {
    let (k3, k4) = (attestation_key(3), attestation_key(4));
    let mut history = KeyHistory::new(key(3));
    let change = KeyChangeLeaf::sign(ORIGIN, T0, &k3, &k4).unwrap();
    assert_eq!(
        history.follow(at(0, 5), ORIGIN, &change).unwrap(),
        KeyChange::Followed { to: key(4) }
    );
    let back = KeyChangeLeaf::sign(ORIGIN, T0, &k4, &k3).unwrap();
    assert!(history.follow(at(0, 4), ORIGIN, &back).is_err());
    // A key may be changed back, and then covers the leaves after that change as well.
    history.follow(at(0, 9), ORIGIN, &back).unwrap();
    assert_eq!(
        history.key_for(&key(3).key_id(), at(0, 3)).unwrap(),
        &key(3)
    );
    assert!(history.key_for(&key(3).key_id(), at(0, 7)).is_err());
    assert_eq!(
        history.key_for(&key(3).key_id(), at(0, 10)).unwrap(),
        &key(3)
    );
}

#[test]
fn a_log_end_and_its_continuation_are_followed_into_the_successor() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    let old = ended(repo, &heartbeats(T0, 300), log_end(T0 + 300 * 60));
    let (k3, k4) = (attestation_key(3), attestation_key(4));
    successor_at(
        repo,
        "log/1",
        successor_key(),
        &[
            continuation_of(&old, T0 + 301 * 60, &[log_key(), successor_key()]),
            record(T0 + 302 * 60, 1, &k3),
            Leaf::KeyChange(KeyChangeLeaf::sign(SUCCESSOR, T0 + 303 * 60, &k3, &k4).unwrap()),
        ],
    );
    let source = verify_source(repo, &log_key().vkey(), None).unwrap();
    let dirs: Vec<&str> = source.logs.iter().map(|c| c.dir.as_str()).collect();
    assert_eq!(dirs, ["log", "log/1"]);
    assert_eq!(source.logs[1].log.origin(), SUCCESSOR);
    assert!(source.unnamed.is_empty() && source.continues_at.is_none());

    // A key change in the successor is signed over the successor's origin, and followed there.
    let (history, _) = KeyHistory::from_source(key(3), &source).unwrap();
    assert_eq!(history.current(), &key(4));
    assert_eq!(
        history.key_for(&key(3).key_id(), at(1, 1)).unwrap(),
        &key(3)
    );
    assert!(history.key_for(&key(3).key_id(), at(1, 3)).is_err());
}

/// §8: a successor that is not named by the old log's `log-end` is refused.
#[test]
fn a_successor_no_log_end_names_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    let mut old = Writer::init(&repo.join("log"), log_key());
    old.append(&heartbeats(T0, 3));
    let next = successor_at(
        repo,
        "log/1",
        successor_key(),
        &[continuation_of(
            &old,
            T0 + 1000,
            &[log_key(), successor_key()],
        )],
    );
    let source = verify_source(repo, &log_key().vkey(), None).unwrap();
    assert_eq!(source.logs.len(), 1);
    assert_eq!(source.unnamed, ["log/1"]);

    let prev = verify_log(&old.files(), &log_key().vkey(), None).unwrap();
    let e = follow(&prev, &next.files(), None).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("names no successor"), "{e}");
}

#[test]
fn a_successor_signed_by_another_key_than_the_one_named_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    let old = ended(repo, &[], log_end(T0));
    let impostor = LogSigner::from_seed(SUCCESSOR, [77; 32]).unwrap();
    let cont = continuation_of(&old, T0 + 1, &[log_key(), impostor.clone_for_test()]);
    successor_at(repo, "log/1", impostor, &[cont]);
    let e = verify_source(repo, &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("not the successor"), "{e}");
}

/// Both keys, or it is not followed: the old key vouches for the checkpoint, and the new one for
/// taking over from it.
#[test]
fn a_continuation_is_followed_only_when_both_log_keys_signed_it() {
    let witness = LogSigner::from_seed("example.com/witness", [55; 32]).unwrap();
    for (signers, says) in [
        (
            vec![log_key(), witness.clone_for_test()],
            "not signed by the new log key",
        ),
        (
            vec![successor_key(), witness.clone_for_test()],
            "not signed by the old log key",
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let old = ended(tmp.path(), &heartbeats(T0, 2), log_end(T0 + 120));
        let cont = continuation_of(&old, T0 + 180, &signers);
        successor_at(tmp.path(), "log/1", successor_key(), &[cont]);
        let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
        assert!(matches!(e, LogError::Rotation(_)), "{e}");
        assert!(e.to_string().contains(says), "{says}: {e}");
    }
    // A third signature, by a witness, is read past.
    let tmp = tempfile::tempdir().unwrap();
    let old = ended(tmp.path(), &heartbeats(T0, 2), log_end(T0 + 120));
    let cont = continuation_of(&old, T0 + 180, &[log_key(), witness, successor_key()]);
    successor_at(tmp.path(), "log/1", successor_key(), &[cont]);
    verify_source(tmp.path(), &log_key().vkey(), None).unwrap();
}

#[test]
fn a_continuation_must_hold_the_old_logs_final_checkpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    let mut old = Writer::init(&repo.join("log"), log_key());
    old.append(&heartbeats(T0, 4));
    // The checkpoint before the log-end, signed by both: a real checkpoint, and not the final one.
    let earlier = continuation_of(&old, T0 + 1000, &[log_key(), successor_key()]);
    old.append(&[log_end(T0 + 999)]);
    successor_at(repo, "log/1", successor_key(), &[earlier]);
    let e = verify_source(repo, &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("holds a checkpoint"), "{e}");
}

#[test]
fn a_successor_must_begin_with_its_continuation() {
    for leaves in [vec![heartbeat(T0 + 60)], vec![]] {
        let tmp = tempfile::tempdir().unwrap();
        ended(tmp.path(), &[], log_end(T0));
        successor_at(tmp.path(), "log/1", successor_key(), &leaves);
        let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
        assert!(
            e.to_string()
                .contains("does not begin with a log-continuation"),
            "{e}"
        );
    }
    // Nor is a successor followed that is not there at all.
    let tmp = tempfile::tempdir().unwrap();
    ended(tmp.path(), &[], log_end(T0));
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    assert!(
        matches!(e, LogError::Missing { ref path } if path.contains("log/1")),
        "{e}"
    );
}

#[test]
fn a_continuation_logged_before_the_log_end_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let old = ended(tmp.path(), &[], log_end(T0 + 600));
    let cont = continuation_of(&old, T0, &[log_key(), successor_key()]);
    successor_at(tmp.path(), "log/1", successor_key(), &[cont]);
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Rule(_)), "{e}");
}

#[test]
fn a_successor_with_the_old_logs_origin_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let same = LogSigner::from_seed(ORIGIN, [66; 32]).unwrap();
    let end = Leaf::LogEnd(LogEndLeaf {
        time: T0,
        successor: Successor {
            origin: ORIGIN.into(),
            log_key: same.vkey().to_string(),
            ..named()
        },
    });
    let old = ended(tmp.path(), &[], end);
    let prev = verify_log(&old.files(), &log_key().vkey(), None).unwrap();
    let e = follow(&prev, &DirFiles::new(tmp.path().join("log/1")), None).unwrap_err();
    assert!(e.to_string().contains("with its own origin"), "{e}");
}

#[test]
fn a_log_end_naming_a_directory_already_in_the_chain_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let old = ended(tmp.path(), &[], log_end(T0));
    let second = LogSigner::from_seed("example.com/trigon-evidence/2", [12; 32]).unwrap();
    let mut next = successor_at(
        tmp.path(),
        "log/1",
        successor_key(),
        &[continuation_of(&old, T0 + 1, &[log_key(), successor_key()])],
    );
    next.append(&[Leaf::LogEnd(LogEndLeaf {
        time: T0 + 2,
        successor: Successor {
            origin: second.name().into(),
            log_key: second.vkey().to_string(),
            urls: Vec::new(),
            dir: "log/1".into(),
        },
    })]);
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    assert!(
        e.to_string().contains("holds an earlier log of the chain"),
        "{e}"
    );
}

#[test]
fn a_successor_in_another_repository_is_left_for_the_caller_to_follow() {
    let (here, there) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let end = Leaf::LogEnd(LogEndLeaf {
        time: T0,
        successor: Successor {
            urls: vec!["https://example.com/owner/trigon-evidence-2.git".into()],
            dir: "log".into(),
            ..named()
        },
    });
    let old = ended(here.path(), &heartbeats(T0 - 600, 5), end);
    let next = successor_at(
        there.path(),
        "log",
        successor_key(),
        &[
            continuation_of(&old, T0 + 60, &[log_key(), successor_key()]),
            heartbeat(T0 + 120),
        ],
    );
    let accepted = next.checkpoint().to_string();

    let source = verify_source(here.path(), &log_key().vkey(), Some(accepted.as_bytes())).unwrap();
    assert_eq!(source.logs.len(), 1);
    let s = source.continues_at.as_ref().unwrap();
    assert_eq!(s.urls, ["https://example.com/owner/trigon-evidence-2.git"]);
    assert!(
        !source.accepted_checked,
        "the accepted checkpoint is the successor's"
    );

    let accepted =
        trigon_attest::log::SignedCheckpoint::open(accepted.as_bytes(), &s.vkey().unwrap())
            .unwrap();
    let followed = follow(&source.logs[0].log, &next.files(), Some(&accepted)).unwrap();
    assert_eq!(followed.origin(), SUCCESSOR);
}

#[test]
fn the_checkpoint_last_accepted_is_held_against_the_log_of_its_origin() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    let old = ended(repo, &heartbeats(T0, 3), log_end(T0 + 180));
    let mut next = successor_at(
        repo,
        "log/1",
        successor_key(),
        &[continuation_of(
            &old,
            T0 + 240,
            &[log_key(), successor_key()],
        )],
    );
    let early = next.checkpoint().to_string();
    next.append(&[heartbeat(T0 + 300)]);
    let pin = log_key().vkey();

    // The successor's earlier checkpoint, and the old log's final one, are both extended.
    let s = verify_source(repo, &pin, Some(early.as_bytes())).unwrap();
    assert!(s.accepted_checked);
    let s = verify_source(repo, &pin, Some(old.checkpoint().to_string().as_bytes())).unwrap();
    assert!(s.accepted_checked);

    // One the successor never had is an equivocation.
    let tmp2 = tempfile::tempdir().unwrap();
    let mut fork = Writer::init(tmp2.path(), successor_key());
    fork.append(&[
        continuation_of(&old, T0 + 240, &[log_key(), successor_key()]),
        heartbeat(T0 + 301),
    ]);
    let forked = fork.checkpoint().to_string();
    let e = verify_source(repo, &pin, Some(forked.as_bytes())).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");

    // One of a log this repository's chain never reaches means the repository is behind.
    let later = LogSigner::from_seed("example.com/trigon-evidence/2", [13; 32]).unwrap();
    let tmp3 = tempfile::tempdir().unwrap();
    let beyond = Writer::init(tmp3.path(), later).checkpoint().to_string();
    let e = verify_source(repo, &pin, Some(beyond.as_bytes())).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");
    assert!(e.to_string().contains("behind what was accepted"), "{e}");
}

#[test]
fn a_client_pinned_to_the_successor_starts_at_its_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let old = ended(tmp.path(), &heartbeats(T0, 2), log_end(T0 + 120));
    successor_at(
        tmp.path(),
        "log/1",
        successor_key(),
        &[continuation_of(
            &old,
            T0 + 180,
            &[log_key(), successor_key()],
        )],
    );
    let source = verify_source(tmp.path(), &successor_key().vkey(), None).unwrap();
    let dirs: Vec<&str> = source.logs.iter().map(|c| c.dir.as_str()).collect();
    assert_eq!(dirs, ["log/1"]);
    assert!(source.unnamed.is_empty());

    // A key no log here is signed by finds nothing to start at.
    let stranger = LogSigner::from_seed("example.com/nowhere", [14; 32]).unwrap();
    let e = verify_source(tmp.path(), &stranger.vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Unverified(_)), "{e}");
    assert!(e.to_string().contains("no log in"), "{e}");
}

/// Whoever holds the push credential can plant a directory beside the log a client is pinned to.
/// The chain starts at the newest checkpoint the pinned key opens, whichever directory holds it,
/// and every other directory claiming that log is reported and set aside: planting one never
/// stops the source, and never moves it onto an older state (`docs/16` §3.98).
#[test]
fn a_planted_directory_does_not_move_or_stop_a_client_pinned_to_a_successor() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    let end = Leaf::LogEnd(LogEndLeaf {
        time: T0 + 120,
        successor: Successor {
            dir: "log/2".into(),
            ..named()
        },
    });
    let old = ended(repo, &heartbeats(T0, 2), end);
    let mut next = successor_at(
        repo,
        "log/2",
        successor_key(),
        &[continuation_of(
            &old,
            T0 + 180,
            &[log_key(), successor_key()],
        )],
    );
    let early = next.checkpoint();
    next.append(&[heartbeat(T0 + 240)]);
    let newest = next.checkpoint();
    let pin = successor_key().vkey();
    let starts_at_log_2 = |accepted: Option<&[u8]>| {
        let s = verify_source(repo, &pin, accepted).unwrap();
        let dirs: Vec<&str> = s.logs.iter().map(|c| c.dir.as_str()).collect();
        assert_eq!(dirs, ["log/2"]);
        assert_eq!(s.logs[0].log.size(), 2);
        assert!(s.unnamed.is_empty(), "{:?}", s.unnamed);
        s.refused
    };
    assert!(starts_at_log_2(None).is_empty());
    let planted = repo.join("log/1");
    let plant = |files: &[(&str, &[u8])]| {
        let _ = std::fs::remove_dir_all(&planted);
        for (path, bytes) in files {
            let p = planted.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
    };

    // A checkpoint that names the successor and is signed by nobody.
    let empty = trigon_attest::log::Checkpoint::empty(SUCCESSOR).body();
    plant(&[(
        "checkpoint",
        format!("{empty}\n\u{2014} x AAAAAAA=\n").as_bytes(),
    )]);
    let refused = starts_at_log_2(None);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].dir, "log/1");
    assert!(refused[0].why.contains("does not open"), "{:?}", refused);

    // The successor's own older state, genuinely signed, with every file it needs: the chain
    // still starts at the newest, and the older copy is reported as one.
    let mut files: Vec<(String, Vec<u8>)> =
        crate::common::tree_of(&next.root).into_iter().collect();
    for (path, bytes) in &mut files {
        if path == "checkpoint" {
            *bytes = early.to_string().into_bytes();
        }
    }
    let files: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    plant(&files);
    let refused = starts_at_log_2(None);
    assert!(
        refused[0].why.contains("older checkpoint") && refused[0].why.contains("extends"),
        "{refused:?}"
    );
    starts_at_log_2(Some(newest.to_string().as_bytes()));

    // A copy of the newest checkpoint and nothing else, numbered before the real one: tried
    // first, found wanting, and the real one verified in its place.
    plant(&[("checkpoint", newest.to_string().as_bytes())]);
    let refused = starts_at_log_2(Some(early.to_string().as_bytes()));
    assert!(refused[0].why.contains("is missing"), "{refused:?}");

    // A checkpoint of the log that the newest does not extend is signed by its key, and nobody
    // without the log key can plant one: two trees under one key is an equivocation, and the
    // source is refused with both signed notes (`docs/19` §6.1, §8), not merely set aside.
    let fork = SignedCheckpoint::sign(
        &trigon_attest::log::Checkpoint {
            origin: SUCCESSOR.into(),
            size: 1,
            root: [7; 32],
        },
        &successor_key(),
    )
    .unwrap();
    plant(&[("checkpoint", fork.to_string().as_bytes())]);
    let e = verify_source(repo, &pin, None).unwrap_err();
    let LogError::Equivocation {
        first_dir,
        first,
        second_dir,
        second,
        ..
    } = &e
    else {
        panic!("expected an equivocation, got {e}");
    };
    assert_eq!(
        (first_dir.as_str(), second_dir.as_str()),
        ("log/2", "log/1")
    );
    assert_eq!(first, &newest.to_string());
    assert_eq!(second, &fork.to_string());
    assert!(e.fails_verification());
    let said = e.to_string();
    assert!(
        said.contains("equivocation") && said.contains("does not extend"),
        "{said}"
    );

    // And two checkpoints of one size with two roots, each in its own directory.
    let twin = SignedCheckpoint::sign(
        &trigon_attest::log::Checkpoint {
            origin: SUCCESSOR.into(),
            size: newest.size(),
            root: [9; 32],
        },
        &successor_key(),
    )
    .unwrap();
    plant(&[("checkpoint", twin.to_string().as_bytes())]);
    let e = verify_source(repo, &pin, None).unwrap_err();
    assert!(matches!(e, LogError::Equivocation { .. }), "{e}");
    assert!(e.to_string().contains(&twin.to_string()), "{e}");

    // A client pinned to the first log still follows the chain, and the planted directory,
    // which no log-end names, is refused as a successor.
    let s = verify_source(repo, &log_key().vkey(), None).unwrap();
    let dirs: Vec<&str> = s.logs.iter().map(|c| c.dir.as_str()).collect();
    assert_eq!(dirs, ["log", "log/2"]);
    assert_eq!(s.unnamed, ["log/1"]);

    // Where nothing opens, the first directory claiming the log says why, as it would alone.
    std::fs::remove_dir_all(repo.join("log/2")).unwrap();
    plant(&[(
        "checkpoint",
        format!("{empty}\n\u{2014} x AAAAAAA=\n").as_bytes(),
    )]);
    let e = verify_source(repo, &pin, None).unwrap_err();
    assert!(matches!(e, LogError::Unverified(_)), "{e}");
    assert!(e.to_string().contains("no signature by"), "{e}");
}

/// A `LogSigner` holds a secret and is not `Clone`; tests that need one twice make it twice.
trait CloneForTest {
    fn clone_for_test(&self) -> LogSigner;
}

impl CloneForTest for LogSigner {
    fn clone_for_test(&self) -> LogSigner {
        LogSigner::from_skey(&self.to_skey()).unwrap()
    }
}
