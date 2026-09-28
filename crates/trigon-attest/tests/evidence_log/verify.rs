//! A log verified from its files, as every client verifies one on every sync (`docs/19` §6, §8):
//! what passes, what is refused, and what is never read.

use trigon_attest::log::tiles::encode_bundle;
use trigon_attest::log::{
    KeyChangeLeaf, Leaf, LogContinuationLeaf, LogEndLeaf, LogError, LogSigner, SignedCheckpoint,
    SignedNote, Successor, open_checkpoint, prove_inclusion_from_tiles,
    verify_extension_from_tiles, verify_log,
};

use crate::common::{
    ORIGIN, SUCCESSOR, T0, Writer, attestation_key, heartbeat, heartbeats, log_key, record,
    successor_key, tree_of,
};

/// A log of `n` leaves, grown in the given steps, in a directory of its own.
fn log_of(steps: &[u64]) -> (tempfile::TempDir, Writer, Vec<SignedCheckpoint>) {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(&tmp.path().join("log"), log_key());
    let mut checkpoints = vec![w.checkpoint()];
    let key = attestation_key(3);
    let mut t = T0;
    for &step in steps {
        let leaves: Vec<Leaf> = (0..step)
            .map(|i| {
                t += 60;
                if i % 3 == 0 {
                    record(t, t as u32, &key)
                } else {
                    heartbeat(t)
                }
            })
            .collect();
        w.append(&leaves);
        checkpoints.push(w.checkpoint());
    }
    (tmp, w, checkpoints)
}

#[test]
fn a_log_verifies_and_every_leaf_comes_back_with_its_index() {
    let (_tmp, w, _) = log_of(&[1, 200, 99, 300]);
    let log = verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    assert_eq!(log.size(), 600);
    assert_eq!(log.origin(), ORIGIN);
    assert_eq!(log.tree().root(), *log.checkpoint().root());
    let leaves: Vec<(u64, &Leaf)> = log.leaves().collect();
    assert_eq!(leaves.len(), 600);
    for (i, (index, leaf)) in leaves.iter().enumerate() {
        assert_eq!(*index, i as u64);
        assert_eq!(leaf.encode().unwrap(), w.entries[i]);
        assert_eq!(log.entry(*index).unwrap(), w.entries[i]);
    }
    assert_eq!(log.newest_time(), Some(T0 + 600 * 60));
    assert!(log.log_end().is_none());
}

#[test]
fn a_log_with_no_leaves_verifies_from_its_checkpoint_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let w = Writer::init(tmp.path(), log_key());
    assert_eq!(
        tree_of(tmp.path()).len(),
        1,
        "a checkpoint and nothing else"
    );
    let log = verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    assert_eq!(log.size(), 0);
    assert_eq!(log.leaves().count(), 0);
    assert_eq!(log.newest_time(), None);
}

#[test]
fn a_checkpoint_not_signed_by_the_pinned_key_is_refused() {
    let (_tmp, w, _) = log_of(&[5]);
    // Another key under the log's name.
    let impostor = LogSigner::from_seed(ORIGIN, [42; 32]).unwrap();
    let e = verify_log(&w.files(), &impostor.vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Unverified(_)), "{e}");

    // The pinned key's checkpoint, with its size changed.
    let note = String::from_utf8(w.read("checkpoint")).unwrap();
    w.write("checkpoint", note.replacen("\n5\n", "\n4\n", 1).as_bytes());
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::BadSignature(_)), "{e}");

    // No checkpoint at all.
    std::fs::remove_file(w.root.join("checkpoint")).unwrap();
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(
        matches!(e, LogError::Missing { ref path } if path.ends_with("checkpoint")),
        "{e}"
    );
}

#[test]
fn a_leaf_changed_after_the_checkpoint_was_signed_is_found() {
    let (_tmp, w, _) = log_of(&[10]);
    // Rewrite the partial bundle with one heartbeat a second later: still a valid leaf, still in
    // canonical form, and not the one the checkpoint signed.
    let mut entries = w.entries.clone();
    let Leaf::Heartbeat(h) = Leaf::decode(&entries[4]).unwrap() else {
        panic!("leaf 4 is a heartbeat");
    };
    entries[4] = heartbeat(h.time + 1).encode().unwrap();
    w.write("tile/entries/000.p/10", &encode_bundle(&entries).unwrap());
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Mismatch(_)), "{e}");
    assert!(
        e.to_string()
            .contains("not the leaves the checkpoint was signed over"),
        "{e}"
    );
}

/// A leaf the log key signed and this build cannot read refuses the log, and says where it is.
#[test]
fn a_leaf_that_does_not_decode_is_refused_with_where_it_is() {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(tmp.path(), log_key());
    w.append_raw(vec![
        heartbeat(T0).encode().unwrap(),
        br#"{"extra":true,"kind":"heartbeat","time":1790467201}"#.to_vec(),
        heartbeat(T0 + 2).encode().unwrap(),
    ]);
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Malformed(_)), "{e}");
    let e = e.to_string();
    assert!(
        e.contains("leaf 1") && e.contains("tile/entries/000.p/3"),
        "{e}"
    );
    assert!(e.contains("unknown field `extra`"), "{e}");
}

/// A bundle altered after its checkpoint was signed is a mismatch, whatever its leaves say: until
/// the root is checked, a leaf that breaks a rule of the log, or that this build cannot read, is
/// no more the log key's than the alteration is, and blaming the signer — or telling the user to
/// update Trigon — would accuse whoever did not do it (`docs/19` §8).
#[test]
fn a_bundle_altered_after_signing_is_a_mismatch_whatever_its_leaves_say() {
    let altered: [(&str, Vec<u8>); 5] = [
        (
            "a time before the leaf's before it",
            heartbeat(1).encode().unwrap(),
        ),
        (
            "a log-end that is not last",
            crate::rotation::log_end(T0 + 10_000).encode().unwrap(),
        ),
        (
            "a log-continuation that is not first",
            crate::rotation::continuation(T0 + 10_000).encode().unwrap(),
        ),
        (
            "a kind this build does not know",
            br#"{"kind":"future","time":1800000000}"#.to_vec(),
        ),
        (
            "a field no leaf has",
            br#"{"extra":1,"kind":"heartbeat","time":1800000000}"#.to_vec(),
        ),
    ];
    for (what, leaf) in altered {
        let (_tmp, w, _) = log_of(&[5]);
        let mut entries = w.entries.clone();
        entries[2] = leaf;
        w.write("tile/entries/000.p/5", &encode_bundle(&entries).unwrap());
        let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
        assert!(matches!(e, LogError::Mismatch(_)), "{what}: {e}");
        assert!(
            e.to_string()
                .contains("not the leaves the checkpoint was signed over"),
            "{what}: {e}"
        );
    }
}

#[test]
fn a_tile_that_does_not_hold_the_leaves_hashes_is_refused() {
    // Every level: a partial of level 0, a full tile of level 0, and a partial of level 1, which
    // a reader proving inclusion from the tiles would read as much as the others.
    for path in ["tile/0/001.p/44", "tile/0/000", "tile/1/000.p/1"] {
        let (_tmp, w, _) = log_of(&[300]);
        let mut tile = w.read(path);
        tile[0] ^= 1;
        w.write(path, &tile);
        let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
        assert!(matches!(e, LogError::Mismatch(_)), "{path}: {e}");
        assert!(e.to_string().contains(path), "{path}: {e}");

        // One of the wrong length is not a tile.
        w.write(path, &tile[..tile.len() - 1]);
        let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
        assert!(matches!(e, LogError::Malformed(_)), "{path}: {e}");
    }
}

#[test]
fn a_file_the_checkpoints_tree_needs_is_reported_missing() {
    for path in [
        "tile/entries/000",
        "tile/entries/001.p/44",
        "tile/0/000",
        "tile/1/000.p/1",
    ] {
        let (_tmp, w, _) = log_of(&[300]);
        std::fs::remove_file(w.root.join(path)).unwrap();
        let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
        assert!(
            matches!(e, LogError::Missing { path: ref p } if p.ends_with(path)),
            "{path}: {e}"
        );
    }
}

#[test]
fn leaf_times_never_go_backwards() {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(tmp.path(), log_key());
    // Equal times are fine.
    w.append(&[heartbeat(T0), heartbeat(T0), heartbeat(T0 + 1)]);
    verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    w.append(&[heartbeat(T0)]);
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Rule(_)), "{e}");
    assert!(e.to_string().contains("leaf 3 was logged at"), "{e}");
}

/// `docs/19` §8: whoever holds the push credential can plant files in `log/` beyond the
/// checkpoint, and none of them is read as part of the log.
#[test]
fn nothing_beyond_the_checkpoints_size_is_part_of_the_log() {
    let (_tmp, w, _) = log_of(&[180]);
    let mut more = w.entries.clone();
    more.extend(
        heartbeats(T0 + 10_000_000, 76)
            .iter()
            .map(|l| l.encode().unwrap()),
    );
    let whole = encode_bundle(&more).unwrap();
    // A full bundle and a wider partial beside the checkpoint's, a bundle past its end, and tiles
    // likewise, all with leaves or hashes the checkpoint never signed.
    w.write("tile/entries/000", &whole);
    w.write(
        "tile/entries/000.p/200",
        &encode_bundle(&more[..200]).unwrap(),
    );
    w.write("tile/entries/001.p/5", &encode_bundle(&more[..5]).unwrap());
    w.write("tile/0/000", &[0xee; 256 * 32]);
    w.write("tile/0/000.p/200", &[0xee; 200 * 32]);
    w.write("tile/1/000.p/1", &[0xee; 32]);
    let log = verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    assert_eq!(log.size(), 180);
    assert_eq!(log.leaves().count(), 180);
    assert!(log.entry(180).is_none());

    // But the bundle the checkpoint does name, with a leaf more than its name says, is not the one
    // the publication wrote.
    w.write(
        "tile/entries/000.p/180",
        &encode_bundle(&more[..181]).unwrap(),
    );
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(e.to_string().contains("more than the 180 leaves"), "{e}");
}

#[test]
fn a_log_end_must_be_last_and_a_log_continuation_first() {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(tmp.path(), log_key());
    let end = crate::rotation::log_end(T0);
    w.append(&[end.clone(), heartbeat(T0 + 1)]);
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(
        matches!(e, LogError::Rule(_)) && e.to_string().contains("leaf 0 is a log-end"),
        "{e}"
    );

    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(tmp.path(), log_key());
    w.append(&[heartbeat(T0), crate::rotation::continuation(T0 + 1)]);
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(
        e.to_string().contains("leaf 1 is a log-continuation"),
        "{e}"
    );
}

#[test]
fn a_log_extends_the_checkpoint_last_accepted_or_is_refused_with_both_notes() {
    let (_tmp, w, history) = log_of(&[3, 250, 10, 1]);
    let pin = log_key().vkey();
    // Every checkpoint it has had is one it extends.
    for accepted in &history {
        verify_log(&w.files(), &pin, Some(accepted)).unwrap();
    }

    // A rewrite: the same log with leaf 50 changed, re-signed. Its checkpoint of 100 leaves is not
    // a prefix of the real one.
    let (_other, mut rewritten, _) = log_of(&[]);
    let mut entries = w.entries[..100].to_vec();
    entries[50] = heartbeat(T0 + 50 * 60 + 30).encode().unwrap();
    rewritten.append_raw(entries);
    let forked = rewritten.checkpoint();
    let e = verify_log(&w.files(), &pin, Some(&forked)).unwrap_err();
    let LogError::Inconsistent {
        ref accepted,
        ref offered,
        ..
    } = e
    else {
        panic!("expected an equivocation, got {e}");
    };
    assert_eq!(*accepted, forked.to_string());
    assert_eq!(*offered, w.checkpoint().to_string());
    let shown = e.to_string();
    assert!(
        shown.contains(&forked.to_string()) && shown.contains(offered),
        "{shown}"
    );
    assert!(shown.contains("first 100 leaves"), "{shown}");

    // A rollback: the log is behind what was accepted.
    let (_tmp2, behind, _) = log_of(&[3]);
    let e = verify_log(&behind.files(), &pin, Some(history.last().unwrap())).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");
    assert!(e.to_string().contains("fewer than the 264"), "{e}");

    // The same size and another root is an equivocation too.
    let (_tmp3, same, _) = log_of(&[3, 250, 10, 1]);
    let mut entries = same.entries.clone();
    entries[263] = heartbeat(T0 + 999_999).encode().unwrap();
    let (_tmp4, mut other, _) = log_of(&[]);
    other.append_raw(entries);
    let e = verify_log(&w.files(), &pin, Some(&other.checkpoint())).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");

    // A checkpoint of another log is not one this log is held to; nor is one whose note does not
    // verify under the log's key.
    let stranger = LogSigner::from_seed("example.com/other", [8; 32]).unwrap();
    let theirs = crate::common::Writer::init(&_tmp.path().join("other"), stranger).checkpoint();
    let e = verify_log(&w.files(), &pin, Some(&theirs)).unwrap_err();
    assert!(
        e.to_string().contains("given as last accepted is for"),
        "{e}"
    );
}

#[test]
fn a_checkpoint_extends_the_accepted_one_by_its_tiles_alone() {
    let (tmp, w, history) = log_of(&[1, 254, 1, 700, 3]);
    // Only the tiles and the checkpoint: every entry bundle gone.
    std::fs::remove_dir_all(w.root.join("tile/entries")).unwrap();
    let pin = log_key().vkey();
    for accepted in &history {
        let cp = verify_extension_from_tiles(&w.files(), &pin, accepted).unwrap();
        assert_eq!(cp.size(), 959);
    }

    // A rewritten log's checkpoint cannot be proven a prefix of this one, and the tiles, which
    // lead to the root this log's checkpoint signs, prove that it is not: two trees under one key.
    let (_other, mut rewritten, _) = log_of(&[]);
    let mut entries = w.entries[..256].to_vec();
    entries[0] = heartbeat(T0 - 1).encode().unwrap();
    rewritten.append_raw(entries);
    let e = verify_extension_from_tiles(&w.files(), &pin, &rewritten.checkpoint()).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");
    assert!(e.to_string().contains("as its tiles prove"), "{e}");

    // So is a checkpoint of the same size with another root, which needs no tiles to disagree.
    let (_tmp3, mut same, _) = log_of(&[]);
    let mut entries = w.entries.clone();
    entries[958] = heartbeat(T0 + 999_999).encode().unwrap();
    same.append_raw(entries);
    let e = verify_extension_from_tiles(&w.files(), &pin, &same.checkpoint()).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");
    assert!(e.to_string().contains("for as many"), "{e}");

    // A damaged tile is not an equivocation: the tiles are not the tree the checkpoint signs, and
    // say nothing about the log key — against a genuine checkpoint, and against a rewritten one
    // alike, since damaged tiles cannot show that either.
    let (_tmp4, mut short, _) = log_of(&[]);
    let mut entries = w.entries[..100].to_vec();
    entries[0] = heartbeat(T0 - 1).encode().unwrap();
    short.append_raw(entries);
    let mut tile = w.read("tile/0/000");
    tile[100] ^= 1;
    w.write("tile/0/000", &tile);
    for accepted in [&history[1], &short.checkpoint()] {
        let e = verify_extension_from_tiles(&w.files(), &pin, accepted).unwrap_err();
        assert!(matches!(e, LogError::Mismatch(_)), "{e}");
        assert!(
            e.to_string()
                .contains("are not the tree its checkpoint signs"),
            "{e}"
        );
    }
    // A proof that does not read the damaged tile is untouched by it: from 256 leaves it reads the
    // level-1 hash above that tile, which still leads to the signed root, so the rewrite of 256
    // leaves is still proven one, and every genuine checkpoint from there still extends.
    let e = verify_extension_from_tiles(&w.files(), &pin, &rewritten.checkpoint()).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");
    for accepted in &history[3..] {
        verify_extension_from_tiles(&w.files(), &pin, accepted).unwrap();
    }

    // A rollback needs no proof to refuse.
    let (_tmp2, behind, _) = log_of(&[2]);
    let e =
        verify_extension_from_tiles(&behind.files(), &pin, history.last().unwrap()).unwrap_err();
    assert!(e.to_string().contains("fewer than"), "{e}");
    drop(tmp);
}

#[test]
fn a_leaf_is_proven_included_from_the_tiles_alone() {
    let (_tmp, w, _) = log_of(&[600]);
    let cp = open_checkpoint(&w.files(), &log_key().vkey()).unwrap();
    std::fs::remove_dir_all(w.root.join("tile/entries")).unwrap();
    for i in [0u64, 1, 255, 256, 511, 512, 599] {
        prove_inclusion_from_tiles(&w.files(), &cp, i, &w.entries[i as usize]).unwrap();
    }
    let e = prove_inclusion_from_tiles(&w.files(), &cp, 3, &w.entries[4]).unwrap_err();
    assert!(matches!(e, LogError::Mismatch(_)), "{e}");
    assert!(prove_inclusion_from_tiles(&w.files(), &cp, 600, &w.entries[0]).is_err());
}

#[cfg(unix)]
#[test]
fn a_file_that_leads_out_of_the_log_is_not_read() {
    let (tmp, w, _) = log_of(&[3]);
    let outside = tmp.path().join("outside");
    std::fs::write(&outside, w.read("tile/entries/000.p/3")).unwrap();
    std::fs::remove_file(w.root.join("tile/entries/000.p/3")).unwrap();
    std::os::unix::fs::symlink(&outside, w.root.join("tile/entries/000.p/3")).unwrap();
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(
        e.to_string().contains("leads through a symbolic link"),
        "{e}"
    );

    // A link that stays inside the log is only a file.
    std::fs::remove_file(w.root.join("tile/entries/000.p/3")).unwrap();
    std::fs::write(w.root.join("bundle"), std::fs::read(&outside).unwrap()).unwrap();
    std::os::unix::fs::symlink(w.root.join("bundle"), w.root.join("tile/entries/000.p/3")).unwrap();
    verify_log(&w.files(), &log_key().vkey(), None).unwrap();

    // A directory where a file should be is not one.
    std::fs::remove_file(w.root.join("tile/entries/000.p/3")).unwrap();
    std::fs::create_dir(w.root.join("tile/entries/000.p/3")).unwrap();
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(e.to_string().contains("not a regular file"), "{e}");
}

/// A repository's log directory that is itself a link out of the repository reads nothing: the
/// bound is the repository, not the directory.
#[cfg(unix)]
#[test]
fn a_log_directory_that_is_a_link_out_of_the_repository_is_not_read() {
    let (outside, w, _) = log_of(&[3]);
    let repo = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(&w.root, repo.path().join("log")).unwrap();
    let e = trigon_attest::log::verify_source(repo.path(), &log_key().vkey(), None).unwrap_err();
    assert!(
        e.to_string().contains("leads through a symbolic link"),
        "{e}"
    );
    // The same directory, given as a log's own, reads as one.
    verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    drop(outside);
}

#[test]
fn a_file_longer_than_its_kind_can_be_is_refused_unread() {
    let (_tmp, w, _) = log_of(&[3]);
    let mut note = w.read("checkpoint");
    note.extend(std::iter::repeat_n(b'x', 70 * 1024));
    w.write("checkpoint", &note);
    let e = verify_log(&w.files(), &log_key().vkey(), None).unwrap_err();
    assert!(
        e.to_string()
            .contains("no file at that path can be more than"),
        "{e}"
    );
}

#[test]
fn a_verified_log_plans_its_next_append_and_refuses_one_that_breaks_its_rules() {
    let (_tmp, mut w, _) = log_of(&[250]);
    let log = verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    let next = heartbeats(T0 + 250 * 60, 10);
    let planned = log.plan_append(&next).unwrap();
    // What the verified log plans is what the writer writes.
    assert_eq!(planned, w.append(&next));
    let grown = verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    assert_eq!(grown.size(), 260);

    let e = grown.plan_append(&[heartbeat(T0)]).unwrap_err();
    assert!(matches!(e, LogError::Rule(_)), "{e}");
    let e = grown
        .plan_append(&[
            crate::rotation::log_end(T0 + 10_000_000),
            heartbeat(T0 + 10_000_001),
        ])
        .unwrap_err();
    assert!(e.to_string().contains("not the log's last leaf"), "{e}");
    let e = grown
        .plan_append(&[crate::rotation::continuation(T0 + 10_000_000)])
        .unwrap_err();
    assert!(e.to_string().contains("log-continuation"), "{e}");

    w.append(&[crate::rotation::log_end(T0 + 10_000_000)]);
    let ended = verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    assert!(ended.log_end().is_some());
    let e = ended
        .plan_append(&[heartbeat(T0 + 10_000_001)])
        .unwrap_err();
    assert!(e.to_string().contains("nothing is appended"), "{e}");
}

/// The writer is held to what the readers apply, as far as a log can know it: a leaf every reader
/// refuses, once logged, breaks the source for good, since the log is append-only and nothing is
/// appended after a log-end.
#[test]
fn a_verified_log_does_not_plan_a_leaf_every_reader_would_refuse() {
    let (_tmp, w, _) = log_of(&[3]);
    let log = verify_log(&w.files(), &log_key().vkey(), None).unwrap();
    let t = T0 + 10_000;
    let (k3, k4) = (attestation_key(3), attestation_key(4));

    // A key change signed over another log's origin, which `KeyHistory` refuses here: the mistake
    // of signing a successor's change with the repository's first origin, or the reverse.
    let elsewhere = Leaf::KeyChange(KeyChangeLeaf::sign(SUCCESSOR, t, &k3, &k4).unwrap());
    let e = log.plan_append(&[elsewhere]).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(
        e.to_string().contains("would be refused by every reader"),
        "{e}"
    );
    let here = Leaf::KeyChange(KeyChangeLeaf::sign(ORIGIN, t, &k3, &k4).unwrap());
    log.plan_append(&[here]).unwrap();

    // A log-end naming a successor with this log's own origin, which `follow` refuses.
    let same = LogSigner::from_seed(ORIGIN, [66; 32]).unwrap();
    let end = Leaf::LogEnd(LogEndLeaf {
        time: t,
        successor: Successor {
            origin: ORIGIN.into(),
            log_key: same.vkey().to_string(),
            ..crate::rotation::named()
        },
    });
    let e = log.plan_append(&[end]).unwrap_err();
    assert!(e.to_string().contains("this log's own origin"), "{e}");
    log.plan_append(&[crate::rotation::log_end(t)]).unwrap();

    // A log-continuation this log's key did not sign, or that holds this log's own checkpoint.
    let tmp = tempfile::tempdir().unwrap();
    let next = Writer::init(tmp.path(), successor_key());
    let successor = verify_log(&next.files(), &successor_key().vkey(), None).unwrap();
    successor
        .plan_append(&[crate::rotation::continuation(t)])
        .unwrap();
    let continuation = |body: &str, first: &LogSigner, second: &LogSigner| {
        let note = SignedNote::sign(body, first)
            .unwrap()
            .cosign(second)
            .unwrap();
        Leaf::LogContinuation(LogContinuationLeaf {
            time: t,
            checkpoint: note.to_string(),
        })
    };
    let root = format!("{}=", "A".repeat(43));
    let third = LogSigner::from_seed("example.com/third", [9; 32]).unwrap();
    let unsigned = continuation(&format!("{ORIGIN}\n1\n{root}\n"), &log_key(), &third);
    let e = successor.plan_append(&[unsigned]).unwrap_err();
    assert!(
        e.to_string().contains("not signed by this log's key"),
        "{e}"
    );
    let own = continuation(
        &format!("{SUCCESSOR}\n1\n{root}\n"),
        &successor_key(),
        &log_key(),
    );
    let e = successor.plan_append(&[own]).unwrap_err();
    assert!(
        e.to_string().contains("holding a checkpoint of this log"),
        "{e}"
    );
}

/// What a refusal says reaches a terminal, and a leaf is anyone's bytes: its unknown field's name
/// is escaped, as every other string from a clone is.
#[test]
fn a_refusal_never_carries_a_leafs_control_characters() {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(tmp.path(), log_key());
    w.append_raw(vec![
        heartbeat(T0).encode().unwrap(),
        r#"{"\u001b]0;owned\u0007\u001b[2J\u009b":1,"kind":"heartbeat","time":1790467201}"#
            .as_bytes()
            .to_vec(),
    ]);
    let e = verify_log(&w.files(), &log_key().vkey(), None)
        .unwrap_err()
        .to_string();
    assert!(!e.chars().any(char::is_control), "{e:?}");
    assert!(e.contains(r"\u{1b}]0;owned\u{7}"), "{e}");
}

/// The notes an equivocation shows are escaped, since a signature line by a key nobody pinned is
/// read past unverified and its name may hold control characters; the notes it keeps are the
/// bytes as read, for evidence.
#[test]
fn the_notes_a_refusal_shows_are_escaped_and_kept_as_read() {
    let (_tmp, w, history) = log_of(&[3, 2]);
    // A rollback to the genuine first checkpoint, with a line by a key nobody pinned.
    let planted = format!(
        "{}\u{2014} x\u{7f}\u{9b}2J\u{9d}0;t\u{9c} AAAAAAAAAAAA\n",
        history[1]
    );
    w.write("checkpoint", planted.as_bytes());
    let e = verify_log(&w.files(), &log_key().vkey(), Some(&history[2])).unwrap_err();
    let LogError::Inconsistent { ref offered, .. } = e else {
        panic!("expected a rollback, got {e}");
    };
    assert_eq!(*offered, planted);
    let shown = e.to_string();
    assert!(
        !shown.chars().any(|c| c.is_control() && c != '\n'),
        "{shown:?}"
    );
    assert!(shown.contains(r"x\u{7f}\u{9b}2J"), "{shown}");
    assert!(shown.contains(&history[2].to_string()), "{shown}");
}
