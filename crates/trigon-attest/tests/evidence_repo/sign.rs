//! What `trigon log sign` holds a tree to before the log key signs it (`docs/19` §8, §10 phase 5
//! step 5): a tree that extends a checkpoint the key itself opens, rewriting nothing signed, whose
//! every new leaf names a record every client would accept, with its evidence beside it — and
//! nothing past the size it is told to sign.

use std::path::Path;

use trigon_attest::evidence::{Repository, Unsignable, check_to_sign, record_path};
use trigon_attest::log::{Leaf, LogError, LogSigner, SignedCheckpoint, verify_log};

use crate::build::{Made, pairs, pinned, verdict, void, write};
use crate::common::{
    T0, Writer, attestation_key, err, heartbeat, heartbeats, log_key, successor_key,
};

/// A repository whose log holds `base`'s leaves under a signed checkpoint, then `more` appended
/// beneath that same checkpoint, with the record files of `files`: the tree `publish` hands `log
/// sign`. Returns the new tree's size.
fn unsigned(root: &Path, base: &[&Made], more: &[Leaf], files: &[&Made]) -> u64 {
    write(
        root,
        "keys/log.vkey",
        format!("{}\n", log_key().vkey()).as_bytes(),
    );
    write(
        root,
        "keys/attestation.pub",
        attestation_key(3).public_pem().as_bytes(),
    );
    let mut log = Writer::init(&root.join("log"), log_key());
    let leaves: Vec<Leaf> = base.iter().map(|m| Leaf::Record(m.leaf.clone())).collect();
    log.append(&leaves);
    for m in base {
        m.write(root);
    }
    let signed = log.read("checkpoint");
    log.append(more);
    log.write("checkpoint", &signed);
    for m in files {
        m.write(root);
    }
    log.tree.size()
}

fn check(root: &Path, size: u64) -> Result<trigon_attest::log::Extension, Unsignable> {
    check_to_sign(root, "log", &log_key().vkey(), size, &pinned(), None, None)
}

#[test]
fn a_tree_whose_new_leaves_it_has_checked_is_signed_and_verifies() {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let b = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, T0 + 60);
    let c = void(&p["c"], &k3, "1789000000-cccccccc", T0 + 60);
    let tmp = tempfile::tempdir().unwrap();
    let more = [
        Leaf::Record(b.leaf.clone()),
        Leaf::Record(c.leaf.clone()),
        heartbeat(T0 + 120),
    ];
    let size = unsigned(tmp.path(), &[&a], &more, &[&b, &c]);
    let ext = check(tmp.path(), size).unwrap();
    assert_eq!(ext.base().size(), 1);
    assert_eq!(ext.size(), 4);
    assert_eq!(ext.new_leaves().count(), 3);
    let body = ext.checkpoint().body();
    assert!(
        body.starts_with("example.com/trigon-evidence\n4\n"),
        "{body}"
    );

    // Signed only by the key the base opened under.
    let e = err(ext.sign(&successor_key()));
    assert!(e.contains("signed by its own key"), "{e}");
    let signed = ext.sign(&log_key()).unwrap();
    write(tmp.path(), "log/checkpoint", signed.to_string().as_bytes());
    let repo = Repository::open(tmp.path(), &log_key().vkey(), &pinned(), None).unwrap();
    let bytes = repo.read_record(&b.digest).unwrap().unwrap();
    repo.verify_record(&bytes).unwrap();
}

#[test]
fn a_tree_that_rewrites_what_was_signed_is_not_an_extension() {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let d = verdict(&p["d"], &k3, "1789000000-dddddddd", None, T0);
    let b = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, T0 + 60);
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &[Leaf::Record(b.leaf.clone())], &[&b]);
    // The new bundle, with the signed leaf replaced: the tiles are written to match, so only the
    // signed root can tell.
    let mut w = Writer::init(&tmp.path().join("scratch"), log_key());
    w.append(&[Leaf::Record(d.leaf.clone()), Leaf::Record(b.leaf.clone())]);
    for path in ["tile/entries/000.p/2", "tile/0/000.p/2"] {
        write(tmp.path(), &format!("log/{path}"), &w.read(path));
    }
    d.write(tmp.path());
    let e = err(check(tmp.path(), size));
    assert!(e.contains("rewrites what was signed"), "{e}");
    assert!(matches!(
        check(tmp.path(), size),
        Err(Unsignable::Log(LogError::Mismatch(_)))
    ));

    // And a log only grows.
    let e = err(check(tmp.path(), 0));
    assert!(e.contains("only grows"), "{e}");
}

#[test]
fn a_checkpoint_the_key_does_not_open_is_not_extended() {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &heartbeats(T0 + 60, 1), &[]);
    let other = LogSigner::from_seed("example.com/trigon-evidence", [7; 32]).unwrap();
    let e = check_to_sign(
        tmp.path(),
        "log",
        &other.vkey(),
        size,
        &pinned(),
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(e, Unsignable::Log(LogError::Unverified(_))), "{e}");
    // No checkpoint at all is no base to extend, never an empty log to begin afresh.
    std::fs::remove_file(tmp.path().join("log/checkpoint")).unwrap();
    let e = check(tmp.path(), size).unwrap_err();
    assert!(
        matches!(e, Unsignable::Log(LogError::Missing { .. })),
        "{e}"
    );
}

#[test]
fn a_new_leaf_is_signed_only_for_a_record_every_client_would_accept() {
    let p = pairs();
    let (k3, stranger) = (attestation_key(3), attestation_key(9));
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let b = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, T0 + 60);
    let h = verdict(&p["h"], &stranger, "1789000000-88888888", None, T0 + 60);

    let case = |more: &[Leaf], files: &[&Made], edit: &dyn Fn(&Path)| {
        let tmp = tempfile::tempdir().unwrap();
        let size = unsigned(tmp.path(), &[&a], more, files);
        edit(tmp.path());
        err(check(tmp.path(), size))
    };
    let none = |_: &Path| {};

    // A record file that is not there.
    let e = case(&[Leaf::Record(b.leaf.clone())], &[], &none);
    assert!(
        e.contains("leaf 1") && e.contains("has no `records/"),
        "{e}"
    );
    // A record signed by a key the source never had.
    let e = case(&[Leaf::Record(h.leaf.clone())], &[&h], &none);
    assert!(e.contains("fails the check every client makes"), "{e}");
    // A record logged again.
    let e = case(&[Leaf::Record(a.leaf.clone())], &[], &none);
    assert!(e.contains("again, which leaf 0 logs"), "{e}");
    // A record whose evidence is not beside it.
    let e = case(&[Leaf::Record(b.leaf.clone())], &[&b], &|root| {
        let manifest =
            trigon_attest::evidence::evidence_path(&crate::build::sha256(&b.evidence[0]));
        std::fs::remove_file(root.join(manifest)).unwrap();
    });
    assert!(e.contains("evidence") && e.contains("is absent"), "{e}");
    // A record file that is other bytes than its leaf names.
    let e = case(&[Leaf::Record(b.leaf.clone())], &[&b], &|root| {
        std::fs::write(root.join(record_path(&b.digest)), b"{}").unwrap();
    });
    assert!(e.contains("fails the check every client makes"), "{e}");
}

/// A log-end naming the successor [`successor_key`] in `log/1`, logged at `time`.
fn log_end(time: u64) -> Leaf {
    Leaf::LogEnd(trigon_attest::log::LogEndLeaf {
        time,
        successor: trigon_attest::log::Successor {
            origin: successor_key().name().into(),
            log_key: successor_key().vkey().to_string(),
            urls: Vec::new(),
            dir: "log/1".into(),
        },
    })
}

/// A log is ended only by a `log sign` that holds the successor's key as well as the log's — both
/// keys present — and the one it holds is the one the log-end names; a successor's key given for
/// a tree that does not end naming it cosigns nothing. A release leaf is still no command's.
#[test]
fn a_log_end_is_signed_only_with_the_successor_key_it_names() {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &[log_end(T0 + 60)], &[]);
    let with = |successor: Option<&LogSigner>| {
        check_to_sign(
            tmp.path(),
            "log",
            &log_key().vkey(),
            size,
            &pinned(),
            None,
            successor.map(|s| s.vkey()).as_ref(),
        )
    };
    let e = err(with(None));
    assert!(e.contains("holds the successor's log key too"), "{e}");
    let stranger = LogSigner::from_seed("example.com/elsewhere", [9; 32]).unwrap();
    let e = err(with(Some(&stranger)));
    assert!(e.contains("does not end with a log-end naming it"), "{e}");
    let ext = with(Some(&successor_key())).unwrap();
    assert_eq!(ext.size(), 2);

    // Given for a tree that does not end the log, it is refused: it would cosign a checkpoint no
    // successor continues from.
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &heartbeats(T0 + 60, 2), &[]);
    let e = err(check_to_sign(
        tmp.path(),
        "log",
        &log_key().vkey(),
        size,
        &pinned(),
        None,
        Some(&successor_key().vkey()),
    ));
    assert!(e.contains("does not end with a log-end naming it"), "{e}");
    // A heartbeat needs nothing beside it.
    check(tmp.path(), size).unwrap();

    // A release leaf is signed by no command of this build.
    let release = trigon_attest::log::ReleaseLeaf::sign(
        crate::common::ORIGIN,
        T0 + 60,
        "trigon-check",
        "0.1.0",
        std::collections::BTreeMap::from([(
            "trigon-check.tgz".to_string(),
            std::collections::BTreeMap::from([(
                "sha256".to_string(),
                crate::build::sha256(b"x").to_hex(),
            )]),
        )]),
        &attestation_key(5),
    )
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &[Leaf::Release(release)], &[]);
    let e = err(check(tmp.path(), size));
    assert!(
        e.contains("release leaf, which no command of this build writes"),
        "{e}"
    );
}

/// A key change is signed only from the key current at it, by both keys: one from any other key
/// is what a stolen log key would write, and is refused.
#[test]
fn a_key_change_is_signed_only_from_the_current_key() {
    let p = pairs();
    let (k3, k4, k5) = (attestation_key(3), attestation_key(4), attestation_key(5));
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let change = |from: &trigon_attest::LocalKey, to: &trigon_attest::LocalKey| {
        Leaf::KeyChange(
            trigon_attest::log::KeyChangeLeaf::sign(crate::common::ORIGIN, T0 + 60, from, to)
                .unwrap(),
        )
    };
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &[change(&k3, &k4)], &[]);
    check(tmp.path(), size).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &[change(&k4, &k5)], &[]);
    let e = err(check(tmp.path(), size));
    assert!(
        e.contains("key change from a key that is not the current one"),
        "{e}"
    );
}

/// The repository a succession leaves before its successor is signed: `log/` ended by a log-end
/// naming [`successor_key`] at `log/1`, its final checkpoint signed by both log keys, and `log/1`
/// holding `first` — the log-continuation, or whatever a test puts in its place — with no
/// checkpoint. Returns the final checkpoint.
fn succeeded(root: &Path, first: impl FnOnce(&SignedCheckpoint) -> Vec<Leaf>) -> SignedCheckpoint {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    write(
        root,
        "keys/log.vkey",
        format!("{}\n", log_key().vkey()).as_bytes(),
    );
    write(root, "keys/attestation.pub", k3.public_pem().as_bytes());
    a.write(root);
    let mut log = Writer::init(&root.join("log"), log_key());
    log.append(&[Leaf::Record(a.leaf.clone()), log_end(T0 + 60)]);
    let last = log.checkpoint();
    let cosigned = last.note().cosign(&successor_key()).unwrap().to_string();
    log.write("checkpoint", cosigned.as_bytes());
    let mut next = Writer::init(&root.join("log/1"), successor_key());
    next.append(&first(&last));
    std::fs::remove_file(root.join("log/1/checkpoint")).unwrap();
    SignedCheckpoint::open(cosigned.as_bytes(), &log_key().vkey()).unwrap()
}

fn continuation(time: u64, of: &SignedCheckpoint) -> Leaf {
    Leaf::LogContinuation(trigon_attest::log::LogContinuationLeaf {
        time,
        checkpoint: of.note().cosign(&successor_key()).unwrap().to_string(),
    })
}

/// A successor is begun, under its own key, only as the one its predecessor's log-end names, from
/// the predecessor's final checkpoint signed by both keys; and what is signed is what every client
/// follows.
#[test]
fn a_successor_is_begun_only_as_the_one_its_predecessor_names() {
    use trigon_attest::evidence::check_to_begin;
    use trigon_attest::log::{DirFiles, find_predecessor};

    let tmp = tempfile::tempdir().unwrap();
    let last = succeeded(tmp.path(), |last| vec![continuation(T0 + 60, last)]);
    let pred = find_predecessor(tmp.path(), &log_key().vkey(), &successor_key().vkey()).unwrap();
    assert_eq!(pred.size(), 2);
    let begun = check_to_begin(
        tmp.path(),
        "log/1",
        &successor_key().vkey(),
        1,
        &pred,
        Some(&last),
    )
    .unwrap();
    let files = DirFiles::in_repository(tmp.path(), "log/1");
    // Only by its own key.
    assert!(err(begun.sign(&log_key(), &files)).contains("the key given to begin it"));
    let signed = begun.sign(&successor_key(), &files).unwrap();
    assert_eq!(signed.size(), 1);
    write(
        tmp.path(),
        "log/1/checkpoint",
        signed.to_string().as_bytes(),
    );
    let repo = Repository::open(tmp.path(), &log_key().vkey(), &pinned(), None).unwrap();
    assert_eq!(repo.source().logs.len(), 2);
    assert_eq!(repo.source().logs[1].dir, "log/1");

    // Begun once: a checkpoint there already is a log, extended from then on.
    let e = err(check_to_begin(
        tmp.path(),
        "log/1",
        &successor_key().vkey(),
        1,
        &pred,
        None,
    ));
    assert!(e.contains("already holds a checkpoint"), "{e}");

    // A key the log-end does not name is not its successor, however the tree was written.
    let stranger = LogSigner::from_seed("example.com/trigon-evidence/2", [8; 32]).unwrap();
    let e = err(find_predecessor(
        tmp.path(),
        &log_key().vkey(),
        &stranger.vkey(),
    ));
    assert!(e.contains("ends naming the log key"), "{e}");
    let e = err(check_to_begin(
        tmp.path(),
        "log/2",
        &stranger.vkey(),
        1,
        &pred,
        None,
    ));
    assert!(e.contains("a successor it does not name is refused"), "{e}");

    // A continuation holding a checkpoint other than the final one is not a continuation of it.
    let tmp = tempfile::tempdir().unwrap();
    succeeded(tmp.path(), |_| {
        let mut other = Writer::init(&tmp.path().join("elsewhere"), log_key());
        other.append(&heartbeats(T0, 2));
        vec![continuation(T0 + 60, &other.checkpoint())]
    });
    let pred = find_predecessor(tmp.path(), &log_key().vkey(), &successor_key().vkey()).unwrap();
    let e = err(check_to_begin(
        tmp.path(),
        "log/1",
        &successor_key().vkey(),
        1,
        &pred,
        None,
    ));
    assert!(e.contains("final checkpoint is of 2 leaves"), "{e}");

    // Nor one logged before the log-end, nor a first tree of more than the continuation.
    let tmp = tempfile::tempdir().unwrap();
    succeeded(tmp.path(), |last| vec![continuation(T0, last)]);
    let pred = find_predecessor(tmp.path(), &log_key().vkey(), &successor_key().vkey()).unwrap();
    let e = err(check_to_begin(
        tmp.path(),
        "log/1",
        &successor_key().vkey(),
        1,
        &pred,
        None,
    ));
    assert!(
        e.contains("before `example.com/trigon-evidence`'s log-end"),
        "{e}"
    );
    let tmp = tempfile::tempdir().unwrap();
    succeeded(tmp.path(), |last| {
        vec![continuation(T0 + 60, last), heartbeat(T0 + 120)]
    });
    let pred = find_predecessor(tmp.path(), &log_key().vkey(), &successor_key().vkey()).unwrap();
    let e = err(check_to_begin(
        tmp.path(),
        "log/1",
        &successor_key().vkey(),
        2,
        &pred,
        None,
    ));
    assert!(e.contains("log-continuation leaf alone"), "{e}");

    // And never from a predecessor behind what this host published of it.
    let tmp = tempfile::tempdir().unwrap();
    succeeded(tmp.path(), |last| vec![continuation(T0 + 60, last)]);
    let pred = find_predecessor(tmp.path(), &log_key().vkey(), &successor_key().vkey()).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let mut elsewhere = Writer::init(scratch.path(), log_key());
    elsewhere.append(&heartbeats(T0, 3));
    let e = err(check_to_begin(
        tmp.path(),
        "log/1",
        &successor_key().vkey(),
        1,
        &pred,
        Some(&elsewhere.checkpoint()),
    ));
    assert!(
        e.contains("does not extend the checkpoint of 3 leaves"),
        "{e}"
    );
}

/// A repository rolled back holds an older checkpoint the key opens as well as it opens the newest,
/// so a tree extending it is held to the newest checkpoint published too: a second root for a size
/// already published is never signed, and neither is a tree shorter than what was published.
#[test]
fn a_tree_that_does_not_extend_what_was_published_is_not_signed() {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let b = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, T0 + 60);
    let tmp = tempfile::tempdir().unwrap();
    // The repository as a rollback leaves it: `a` under a checkpoint of 1, with a heartbeat after.
    let size = unsigned(tmp.path(), &[&a], &heartbeats(T0 + 60, 1), &[]);
    let with = |published: &SignedCheckpoint| {
        check_to_sign(
            tmp.path(),
            "log",
            &log_key().vkey(),
            size,
            &pinned(),
            Some(published),
            None,
        )
    };
    // What was published before the rollback: `a`, then `b`.
    let scratch = tempfile::tempdir().unwrap();
    let mut real = Writer::init(scratch.path(), log_key());
    real.append(&[Leaf::Record(a.leaf.clone())]);
    let one = real.checkpoint();
    real.append(&[Leaf::Record(b.leaf.clone())]);
    let two = real.checkpoint();
    real.append(&heartbeats(T0 + 120, 1));
    let three = real.checkpoint();

    // Extending the published checkpoint of 1 is signed.
    with(&one).unwrap();
    // A second root for 2 is not, and it says which two.
    let e = with(&two).unwrap_err();
    assert!(
        matches!(e, Unsignable::Log(LogError::Inconsistent { .. })),
        "{e}"
    );
    let e = e.to_string();
    assert!(
        e.contains("the first 2 leaves of the tree offered hash to"),
        "{e}"
    );
    assert!(e.contains("published before signs"), "{e}");
    // Nor a tree shorter than what was published.
    let e = err(with(&three));
    assert!(e.contains("fewer than the 3"), "{e}");
    // A published checkpoint of another log, or not signed by this key, is no basis at all.
    let other = LogSigner::from_seed("example.com/elsewhere", [7; 32]).unwrap();
    let elsewhere = SignedCheckpoint::sign(
        &trigon_attest::log::Checkpoint::empty("example.com/elsewhere"),
        &other,
    )
    .unwrap();
    assert!(err(with(&elsewhere)).contains("this log is `example.com/trigon-evidence`"));
    let forged = LogSigner::from_seed("example.com/trigon-evidence", [7; 32]).unwrap();
    let forged = SignedCheckpoint::sign(one.checkpoint(), &forged).unwrap();
    assert!(matches!(
        with(&forged),
        Err(Unsignable::Log(LogError::Unverified(_)))
    ));
}

/// Files planted past the size `log sign` is told to sign are never read, so never signed: a
/// wider bundle holding a leaf nobody checked changes nothing, and the tree signed verifies.
#[test]
fn nothing_past_the_size_to_sign_is_read_or_signed() {
    let p = pairs();
    let k3 = attestation_key(3);
    let a = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, T0);
    let b = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, T0 + 60);
    let tmp = tempfile::tempdir().unwrap();
    let size = unsigned(tmp.path(), &[&a], &[Leaf::Record(b.leaf.clone())], &[&b]);
    // A bundle and a tile of three, with a third leaf that names a record nobody wrote.
    write(tmp.path(), "log/tile/entries/000.p/3", b"\x00\x02{}");
    write(tmp.path(), "log/tile/0/000.p/3", &[0u8; 96]);
    let ext = check(tmp.path(), size).unwrap();
    let signed = ext.sign(&log_key()).unwrap();
    assert_eq!(signed.size(), 2);
    write(tmp.path(), "log/checkpoint", signed.to_string().as_bytes());
    let log = verify_log(
        &trigon_attest::log::DirFiles::in_repository(tmp.path(), "log"),
        &log_key().vkey(),
        None,
    )
    .unwrap();
    assert_eq!(log.size(), 2);
    // Told to sign the planted size, it reads the planted leaf, and refuses it.
    assert!(check(tmp.path(), 3).is_err());
}
