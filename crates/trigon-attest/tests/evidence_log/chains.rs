//! A source's chain across repositories, and copies of one chain held to one another (`docs/19`
//! §6.1, §8): a successor another repository holds is followed there and on through its own
//! successors; the checkpoint last accepted is held to whichever log of the whole chain it is of;
//! and two mirrors of a source are one chain or an equivocation.

use std::cmp::Ordering;
use std::path::Path;

use trigon_attest::log::{
    Leaf, LogEndLeaf, LogError, Successor, VerifiedLog, check_accepted, compare_chains,
    holds_no_log, same_log, verify_continuation, verify_source,
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

/// Copies of two logs are not copies of one, whatever their roots: two origins are two logs.
#[test]
fn copies_of_two_origins_are_never_one_log() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut wa = Writer::init(&a.path().join("log"), log_key());
    wa.append(&heartbeats(T0, 2));
    let mut wb = Writer::init(&b.path().join("log"), successor_key());
    wb.append(&heartbeats(T0, 2));
    let la = trigon_attest::log::verify_log(&wa.files(), &log_key().vkey(), None).unwrap();
    let lb = trigon_attest::log::verify_log(&wb.files(), &successor_key().vkey(), None).unwrap();
    let e = same_log(&la, &lb).unwrap_err();
    assert!(
        e.contains(&format!(
            "one copy is of `{}` and the other of `{SUCCESSOR}`",
            crate::common::ORIGIN
        )),
        "{e}"
    );
}

/// A succession never returns to an earlier log: a successor whose origin is one the chain has
/// already passed through is refused, though the log-end naming it is signed and its
/// continuation holds the final checkpoint it should.
#[test]
fn a_chain_that_returns_to_an_earlier_origin_is_refused() {
    use trigon_attest::log::LogSigner;
    let tmp = tempfile::tempdir().unwrap();
    let old = ended(
        tmp.path(),
        &heartbeats(T0, 2),
        crate::rotation::log_end(T0 + 120),
    );
    // The first log's origin again, under a key of its own.
    let again = || LogSigner::from_seed(crate::common::ORIGIN, [21; 32]).unwrap();
    let mut next = successor_at(
        tmp.path(),
        "log/1",
        successor_key(),
        &[continuation_of(
            &old,
            T0 + 180,
            &[log_key(), successor_key()],
        )],
    );
    next.append(&[Leaf::LogEnd(LogEndLeaf {
        time: T0 + 240,
        successor: Successor {
            origin: crate::common::ORIGIN.into(),
            log_key: again().vkey().to_string(),
            urls: Vec::new(),
            dir: "log/2".into(),
        },
    })]);
    successor_at(
        tmp.path(),
        "log/2",
        again(),
        &[continuation_of(
            &next,
            T0 + 300,
            &[successor_key(), again()],
        )],
    );
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(e.to_string().contains("appears twice"), "{e}");
}

/// A successor in the log's own repository is followed with that repository's own logs, never as
/// a repository of its own.
#[test]
fn a_successor_in_the_same_repository_is_not_followed_as_another() {
    let tmp = tempfile::tempdir().unwrap();
    let old = ended(
        tmp.path(),
        &heartbeats(T0, 2),
        crate::rotation::log_end(T0 + 120),
    );
    let prev = trigon_attest::log::verify_log(&old.files(), &log_key().vkey(), None).unwrap();
    let e = verify_continuation(&prev, tmp.path()).unwrap_err();
    assert!(matches!(e, LogError::Rotation(_)), "{e}");
    assert!(
        e.to_string().contains("in its own repository, at `log/1`"),
        "{e}"
    );
}

/// A directory with no log in it is no source, and says what it looked for. With no checkpoint
/// anywhere it cannot be read, and is not failing verification: a mistyped URL, or a repository
/// nothing has been published to, says nothing and so cannot be lying. `holds_no_log`, asked with
/// no key before trusting one on first use, says so of exactly the same directories.
#[test]
fn a_repository_with_no_log_is_refused_saying_what_it_lacks() {
    let tmp = tempfile::tempdir().unwrap();
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::NoLog(_)), "{e}");
    assert!(!e.fails_verification(), "{e}");
    assert!(e.to_string().contains("it has no `log/checkpoint`"), "{e}");
    assert!(holds_no_log(tmp.path()));
    // A numbered directory with no checkpoint in it is no log either.
    std::fs::create_dir_all(tmp.path().join("log/1/tile")).unwrap();
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    assert!(matches!(e, LogError::NoLog(_)), "{e}");
    assert!(holds_no_log(tmp.path()));
    std::fs::remove_dir_all(tmp.path().join("log")).unwrap();

    // A checkpoint in a numbered directory alone is a log, whoever's it is.
    let mut other = Writer::init(&tmp.path().join("log/1"), successor_key());
    other.append(&heartbeats(T0, 1));
    assert!(!holds_no_log(tmp.path()));
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    assert!(!matches!(e, LogError::NoLog(_)), "{e}");
    std::fs::remove_dir_all(tmp.path().join("log")).unwrap();

    // Where there are logs and none is the pinned one's, each is said as what it is.
    std::fs::create_dir_all(tmp.path().join("log")).unwrap();
    std::fs::write(tmp.path().join("log/checkpoint"), b"not a note\n").unwrap();
    assert!(!holds_no_log(tmp.path()));
    let mut other = Writer::init(&tmp.path().join("log/1"), successor_key());
    other.append(&heartbeats(T0, 1));
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    // A checkpoint that is there is held to the key: this fails verification, as before.
    assert!(matches!(e, LogError::Unverified(_)), "{e}");
    assert!(e.fails_verification(), "{e}");
    let said = e.to_string();
    assert!(said.contains("`log` has no readable checkpoint"), "{said}");
    assert!(
        said.contains(&format!("`log/1` is `{SUCCESSOR}`")),
        "{said}"
    );
}

/// Only `log/<n>`, numbered without a leading zero, may hold a successor: a numbered directory with
/// no checkpoint is named as one no log-end names and is never read, and one that is not a number
/// is not a log directory at all.
// Linux: a file name that is not UTF-8 is one the filesystem takes.
#[cfg(target_os = "linux")]
#[test]
fn only_numbered_directories_are_successors_and_one_without_a_checkpoint_is_not_read() {
    use std::os::unix::ffi::OsStrExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(&tmp.path().join("log"), log_key());
    w.append(&heartbeats(T0, 2));
    for dir in ["3", "07", "x1"] {
        w.write(&format!("{dir}/tile/0/000"), b"not a tile");
    }
    let name = std::ffi::OsStr::from_bytes(b"\xff9");
    std::fs::create_dir_all(tmp.path().join("log").join(name)).unwrap();
    let source = verify_source(tmp.path(), &log_key().vkey(), None).unwrap();
    assert_eq!(source.logs.len(), 1);
    assert_eq!(source.unnamed, ["log/3"]);
    assert!(source.refused.is_empty(), "{:?}", source.refused);
}

/// Two directories holding the newest checkpoint are one signed tree, and the chain starts at the
/// first whose files verify: the other is set aside, said as a copy, and never read as a
/// successor.
#[test]
fn a_second_copy_of_the_newest_checkpoint_is_set_aside_as_a_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::init(&tmp.path().join("log"), log_key());
    w.append(&heartbeats(T0, 3));
    for (path, bytes) in crate::common::tree_of(&w.root) {
        if !path.starts_with("4/") {
            w.write(&format!("4/{path}"), &bytes);
        }
    }
    let source = verify_source(tmp.path(), &log_key().vkey(), None).unwrap();
    let dirs: Vec<&str> = source.logs.iter().map(|c| c.dir.as_str()).collect();
    assert_eq!(dirs, ["log"]);
    assert_eq!(source.refused.len(), 1);
    assert_eq!(source.refused[0].dir, "log/4");
    assert!(
        source.refused[0]
            .why
            .contains("holds a copy of the checkpoint in `log`"),
        "{:?}",
        source.refused
    );
    assert!(source.unnamed.is_empty(), "{:?}", source.unnamed);
}

/// A repository whose `log` is not a directory holds no log, and is refused naming it rather than
/// read as one with no successors.
#[test]
fn a_repository_whose_log_is_not_a_directory_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("log"), b"not a directory").unwrap();
    let e = verify_source(tmp.path(), &log_key().vkey(), None).unwrap_err();
    let log = tmp.path().join("log").display().to_string();
    assert!(e.to_string().contains(&log), "{e}");
}

/// Two chains that share no log are said by each one's origins, in order, so a reader sees which
/// logs each copy holds.
#[test]
fn chains_that_share_no_log_are_said_by_their_origins() {
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
    let chain = verify_source(here.path(), &log_key().vkey(), None).unwrap();
    let other = || trigon_attest::log::LogSigner::from_seed("example.com/other", [7; 32]).unwrap();
    let there = tempfile::tempdir().unwrap();
    let mut w = Writer::init(&there.path().join("log"), other());
    w.append(&heartbeats(T0, 1));
    let alone = verify_source(there.path(), &other().vkey(), None).unwrap();
    let e = compare_chains(&logs(&chain), &logs(&alone)).unwrap_err();
    assert_eq!((e.first, e.second), (0, 0));
    let said = format!(
        "one copy's chain is `{} \u{2192} {SUCCESSOR}` and the other's `example.com/other`",
        crate::common::ORIGIN
    );
    assert!(e.why.contains(&said), "{}", e.why);
}

/// Followed into another repository, the chain goes on through that repository's own successors,
/// and a numbered directory there that no log-end names is said as unnamed, never read.
#[test]
fn a_chain_followed_elsewhere_names_the_directories_there_it_does_not_reach() {
    let (here, there) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let old = ended(here.path(), &heartbeats(T0, 3), end_elsewhere(T0 + 180));
    let third = || {
        trigon_attest::log::LogSigner::from_seed("example.com/trigon-evidence/2", [12; 32]).unwrap()
    };
    let next = successor_at(
        there.path(),
        "log",
        successor_key(),
        &[
            continuation_of(&old, T0 + 240, &[log_key(), successor_key()]),
            Leaf::LogEnd(LogEndLeaf {
                time: T0 + 300,
                successor: Successor {
                    origin: third().name().into(),
                    log_key: third().vkey().to_string(),
                    urls: Vec::new(),
                    dir: "log/1".into(),
                },
            }),
        ],
    );
    successor_at(
        there.path(),
        "log/1",
        third(),
        &[continuation_of(
            &next,
            T0 + 360,
            &[successor_key(), third()],
        )],
    );
    std::fs::create_dir_all(there.path().join("log/5")).unwrap();
    let head = verify_source(here.path(), &log_key().vkey(), None).unwrap();
    let tail = verify_continuation(&head.logs[0].log, there.path()).unwrap();
    let dirs: Vec<&str> = tail.logs.iter().map(|c| c.dir.as_str()).collect();
    assert_eq!(dirs, ["log", "log/1"]);
    assert_eq!(tail.unnamed, ["log/5"]);
    assert!(tail.continues_at.is_none());
}
