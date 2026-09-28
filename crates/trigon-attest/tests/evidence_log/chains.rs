//! A source's chain across repositories, and copies of one chain held to one another (`docs/19`
//! §6.1, §8): a successor another repository holds is followed there and on through its own
//! successors; the checkpoint last accepted is held to whichever log of the whole chain it is of;
//! and two mirrors of a source are one chain or an equivocation.

use std::cmp::Ordering;
use std::path::Path;

use trigon_attest::log::{
    Leaf, LogEndLeaf, LogError, Successor, VerifiedLog, check_accepted, compare_chains, same_log,
    verify_continuation, verify_source,
};

use crate::common::{SUCCESSOR, T0, Writer, heartbeat, heartbeats, log_key, successor_key};
use crate::rotation::{continuation_of, ended, named, successor_at};

/// A log-end naming the successor at `log` in another repository.
fn end_elsewhere(time: u64) -> Leaf {
    Leaf::LogEnd(LogEndLeaf {
        time,
        successor: Successor {
            urls: vec!["https://example.com/owner/trigon-evidence-2.git".into()],
            dir: "log".into(),
            ..named()
        },
    })
}

fn logs(source: &trigon_attest::log::VerifiedSource) -> Vec<&VerifiedLog> {
    source.logs.iter().map(|c| &c.log).collect()
}

/// A first repository whose log ends naming a successor in a second, which the second begins.
fn two_repositories(here: &Path, there: &Path) -> (Writer, Writer) {
    let old = ended(here, &heartbeats(T0, 3), end_elsewhere(T0 + 180));
    let next = successor_at(
        there,
        "log",
        successor_key(),
        &[
            continuation_of(&old, T0 + 240, &[log_key(), successor_key()]),
            heartbeat(T0 + 300),
        ],
    );
    (old, next)
}

#[test]
fn a_successor_in_another_repository_is_followed_there() {
    let (here, there) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (_, next) = two_repositories(here.path(), there.path());
    let head = verify_source(here.path(), &log_key().vkey(), None).unwrap();
    let prev = &head.logs[0].log;
    let tail = verify_continuation(prev, there.path()).unwrap();
    assert_eq!(tail.logs.len(), 1);
    assert_eq!(tail.logs[0].dir, "log");
    assert_eq!(tail.logs[0].log.origin(), SUCCESSOR);
    assert_eq!(tail.logs[0].log.size(), next.tree.size());
    assert!(tail.continues_at.is_none());

    // Not a repository the log-end names: the successor's files under another key.
    let elsewhere = tempfile::tempdir().unwrap();
    let impostor = || trigon_attest::log::LogSigner::from_seed(SUCCESSOR, [9; 32]).unwrap();
    let mut w = Writer::init(&elsewhere.path().join("log"), impostor());
    let old = Writer {
        root: here.path().join("log"),
        signer: log_key(),
        tree: head.logs[0].log.tree().clone(),
        entries: Vec::new(),
    };
    w.append(&[continuation_of(&old, T0 + 240, &[log_key(), impostor()])]);
    let e = verify_continuation(prev, elsewhere.path()).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("is not the successor"), "{e}");

    // A log that names no successor elsewhere is followed with its own repository, not here.
    let same = tempfile::tempdir().unwrap();
    let mut plain = Writer::init(&same.path().join("log"), log_key());
    plain.append(&heartbeats(T0, 2));
    let alone = verify_source(same.path(), &log_key().vkey(), None).unwrap();
    let e = verify_continuation(&alone.logs[0].log, there.path()).unwrap_err();
    assert!(e.to_string().contains("no log-end"), "{e}");
}

#[test]
fn the_checkpoint_last_accepted_is_held_to_the_whole_chain() {
    let (here, there) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (old, mut next) = two_repositories(here.path(), there.path());
    let head = verify_source(here.path(), &log_key().vkey(), None).unwrap();
    let tail = verify_continuation(&head.logs[0].log, there.path()).unwrap();
    let chain: Vec<&VerifiedLog> = logs(&head).into_iter().chain(logs(&tail)).collect();

    // The successor's checkpoint, and the old log's final one, are both extended.
    let accepted = next.checkpoint().to_string();
    assert!(check_accepted(&chain, false, accepted.as_bytes()).unwrap());
    let final_old = old.checkpoint().to_string();
    assert!(check_accepted(&chain, false, final_old.as_bytes()).unwrap());

    // Accepted further on than the successor now serves: a rollback, refused with both notes.
    next.append(&[heartbeat(T0 + 360)]);
    let further = next.checkpoint().to_string();
    let e = check_accepted(&chain, false, further.as_bytes()).unwrap_err();
    assert!(matches!(e, LogError::Inconsistent { .. }), "{e}");
    assert!(e.to_string().contains("fewer than the 3"), "{e}");

    // Of a log the chain has not reached: unchecked where the chain goes on unfollowed, and
    // behind what was accepted where it does not.
    assert!(!check_accepted(&logs(&head), true, accepted.as_bytes()).unwrap());
    let e = check_accepted(&logs(&head), false, accepted.as_bytes()).unwrap_err();
    assert!(e.to_string().contains("behind what was accepted"), "{e}");
}

#[test]
fn copies_of_one_chain_are_one_chain_or_an_equivocation() {
    let a = tempfile::tempdir().unwrap();
    let mut wa = Writer::init(&a.path().join("log"), log_key());
    wa.append(&heartbeats(T0, 4));
    let b = tempfile::tempdir().unwrap();
    let mut wb = Writer::init(&b.path().join("log"), log_key());
    wb.append(&heartbeats(T0, 4));
    let c = tempfile::tempdir().unwrap();
    let mut wc = Writer::init(&c.path().join("log"), log_key());
    wc.append(&heartbeats(T0, 2));
    let verified = |p: &Path| verify_source(p, &log_key().vkey(), None).unwrap();
    let (sa, sb, sc) = (verified(a.path()), verified(b.path()), verified(c.path()));

    // In agreement, and one lagging.
    assert_eq!(
        compare_chains(&logs(&sa), &logs(&sb)).unwrap(),
        Ordering::Equal
    );
    assert_eq!(
        compare_chains(&logs(&sc), &logs(&sa)).unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare_chains(&logs(&sa), &logs(&sc)).unwrap(),
        Ordering::Greater
    );
    same_log(&sa.logs[0].log, &sc.logs[0].log).unwrap();

    // Another log of the same size under the same key: an equivocation.
    let d = tempfile::tempdir().unwrap();
    let mut wd = Writer::init(&d.path().join("log"), log_key());
    wd.append(&heartbeats(T0 + 1, 4));
    let sd = verified(d.path());
    let e = compare_chains(&logs(&sa), &logs(&sd)).unwrap_err();
    assert!(e.why.contains("one signs the root"), "{}", e.why);
    // And one whose first leaves are not the larger's.
    let e = compare_chains(&logs(&sc), &logs(&sd)).unwrap_err();
    assert!(e.why.contains("not a prefix"), "{}", e.why);

    // A copy past a succession is ahead of one that has not reached it, and still one chain.
    let here = tempfile::tempdir().unwrap();
    let old = ended(
        here.path(),
        &heartbeats(T0, 3),
        crate::rotation::log_end(T0 + 180),
    );
    successor_at(
        here.path(),
        "log/1",
        successor_key(),
        &[continuation_of(
            &old,
            T0 + 240,
            &[log_key(), successor_key()],
        )],
    );
    let before = tempfile::tempdir().unwrap();
    let mut wbefore = Writer::init(&before.path().join("log"), log_key());
    wbefore.append(&heartbeats(T0, 3));
    let (past, notyet) = (verified(here.path()), verified(before.path()));
    assert_eq!(
        compare_chains(&logs(&past), &logs(&notyet)).unwrap(),
        Ordering::Greater
    );
    // Two chains that share no log are not copies of one.
    let other = || trigon_attest::log::LogSigner::from_seed("example.com/other", [7; 32]).unwrap();
    let e_dir = tempfile::tempdir().unwrap();
    let mut we = Writer::init(&e_dir.path().join("log"), other());
    we.append(&heartbeats(T0, 1));
    let se = verify_source(e_dir.path(), &other().vkey(), None).unwrap();
    let e = compare_chains(&logs(&sa), &logs(&se)).unwrap_err();
    assert!(e.why.contains("share no log"), "{}", e.why);
}
