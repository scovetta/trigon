//! What `trigon log sign` holds a tree to before the log key signs its checkpoint (`docs/19` §8,
//! §10 phase 5 step 5).
//!
//! The log key is the secret whose misuse no client can detect alone: a checkpoint it signs over
//! a tree that differs from the real log after the newest checkpoint a client holds is a fork that
//! client cannot see (`docs/19` §8). So the step that holds it trusts nothing `publish` hands it.
//! It reads the new tree from disk, and it signs only where:
//!
//! 1. the checkpoint the tree extends opens under the log key itself, and the new tree's first
//!    leaves hash to its root ([`verify_extension`]); and they hash to the root of the newest
//!    checkpoint of the log published from this host, where the caller keeps one
//!    ([`Extension::check_extends`]), since a repository rolled back holds an older checkpoint the
//!    key opens just as well: nothing signed is rewritten;
//! 2. every leaf decodes, sits where a leaf of its kind may and is no earlier than the one before
//!    it, and every tile of the new tree holds its leaves' hashes;
//! 3. every new record leaf names a record file in the tree, logged at no other leaf, whose
//!    envelopes verify under the attestation key current at that leaf and which passes every
//!    check a client makes of it ([`check_record`]), with every piece of evidence it names beside
//!    it but the rebuilt artifact, which is a release asset;
//! 4. every other new leaf is a heartbeat, a key change from the current key signed by both keys
//!    over this log, or a log-end, which is signed only where the successor's log key is in hand
//!    too and is the one it names ([`check_to_sign`]'s `successor`): the final checkpoint a
//!    successor continues from is cosigned by that key, and a log ended in favour of a key nobody
//!    holds is a log nobody can continue. A release leaf is written by no command of this build,
//!    and a log-continuation only ever begins a successor ([`check_to_begin`]); either is refused
//!    rather than signed on `publish`'s word.
//!
//! Nothing past the size it is told to sign is read, so a bundle or a tile planted beyond it by
//! whoever can push is never signed.
//!
//! [`check_to_begin`] is the same step for a successor's first tree, which has no checkpoint of
//! its own to extend: it holds the log-continuation leaf alone, and is signed only where that leaf
//! holds the final checkpoint of the log whose log-end names this key, signed by both keys, as
//! [`follow`] requires of every client.
//!
//! [`follow`]: crate::log::follow

use std::collections::BTreeMap;
use std::path::Path;

use trigon_core::Digest;

use super::check::{EvidenceState, check_record};
use super::paths::{evidence_path, record_path};
use super::repository::RECORD_LIMIT;
use crate::AttestationKey;
use crate::LogVkey;
use crate::log::{
    Beginning, DirFiles, Extension, KeyChange, KeyHistory, Leaf, LeafPos, LogError, LogFiles,
    SignedCheckpoint, VerifiedLog, verify_beginning, verify_extension,
};

/// Why `trigon log sign` will not sign a tree.
#[derive(Debug, thiserror::Error)]
pub enum Unsignable {
    /// The tree is not an extension of the checkpoint it holds, or its files are not a log.
    #[error(transparent)]
    Log(#[from] LogError),
    /// A new leaf names what the log key must not vouch for.
    #[error("leaf {index} of `{origin}` is not signed: {why}")]
    Leaf {
        index: u64,
        origin: String,
        why: String,
    },
}

/// Check the tree of `size` leaves in the log `dir` of the repository at `repo` for signing under
/// the log key `vkey`: every rule of the module's documentation.
///
/// `current` is the attestation key current at the checkpoint the tree extends: the repository's
/// `keys/attestation.pub`, or a key its operator names. A key change among the new leaves moves it,
/// and a record after that change is held to the new key. `published` is the newest checkpoint of
/// the log known to have been published, which the new tree must extend as well as its own base.
///
/// `successor` is the log key of the successor the tree's last leaf, a log-end, names: in hand
/// because the step signing the final checkpoint holds that key too, and cosigns it with it. A
/// new log-end is refused without it, or with another key than the one it names; and one given
/// where the tree does not end with a log-end naming it is refused, so that a successor key is
/// never used to cosign anything but a final checkpoint.
pub fn check_to_sign(
    repo: &Path,
    dir: &str,
    vkey: &LogVkey,
    size: u64,
    current: &AttestationKey,
    published: Option<&SignedCheckpoint>,
    successor: Option<&LogVkey>,
) -> Result<Extension, Unsignable> {
    let ext = verify_extension(&DirFiles::in_repository(repo, dir), vkey, size)?;
    if let Some(p) = published {
        ext.check_extends(p)?;
    }
    let origin = ext.origin().to_string();
    let refuse = |index: u64, why: String| Unsignable::Leaf {
        index,
        origin: origin.clone(),
        why,
    };
    if let Some(s) = successor {
        let names = |l: &Leaf| matches!(l, Leaf::LogEnd(e) if e.successor.log_key == s.to_string());
        match ext.leaves().last() {
            Some((_, l)) if names(l) => {}
            last => {
                return Err(refuse(
                    last.map_or(size, |(i, _)| i),
                    format!(
                        "a successor's log key, {s}, was given, and the tree does not end with a \
                         log-end naming it; a successor's key cosigns only the final checkpoint \
                         of the log that names it"
                    ),
                ));
            }
        }
    }
    // Every file a record names is read inside the repository and nowhere else, as a client reads
    // it: a record or an evidence file that is a link out of the tree reads nothing.
    let files = DirFiles::new(repo);
    let mut keys = KeyHistory::new(current.clone());
    let mut logged: BTreeMap<Digest, u64> = BTreeMap::new();
    let base = ext.base().size();
    for (index, leaf) in ext.leaves() {
        // One log, so the chain's first: the positions are compared only with each other.
        let pos = LeafPos { log: 0, index };
        let new = index >= base;
        match leaf {
            Leaf::Record(r) => {
                if let Some(first) = logged.insert(r.record, index)
                    && new
                {
                    return Err(refuse(
                        index,
                        format!(
                            "it logs the record sha256:{} again, which leaf {first} logs; a record \
                             is logged once, and one logged again after what withdraws it would \
                             read as current again",
                            r.record.to_hex()
                        ),
                    ));
                }
                if !new {
                    continue;
                }
                let path = record_path(&r.record);
                let bytes = files
                    .read(&path, RECORD_LIMIT)
                    .map_err(|e| refuse(index, format!("its record `{path}` cannot be read: {e}")))?
                    .ok_or_else(|| {
                        refuse(
                            index,
                            format!(
                                "it names the record sha256:{}, and the tree has no `{path}`: the \
                                 log key signs no leaf whose record it has not checked",
                                r.record.to_hex()
                            ),
                        )
                    })?;
                let v = check_record(&bytes, Some((pos, r)), &origin, &keys, &files, None)
                    .map_err(|e| {
                        refuse(
                            index,
                            format!(
                                "its record `{path}` fails the check every client makes, so every \
                                 client would refuse it: {e}"
                            ),
                        )
                    })?;
                let missing = v.evidence.iter().find(|e| {
                    !matches!(
                        e.state,
                        EvidenceState::Matches | EvidenceState::ReleaseAsset
                    )
                });
                if let Some(e) = missing {
                    let state = match &e.state {
                        EvidenceState::Unreadable(why) => format!("unreadable ({why})"),
                        _ => "absent".to_string(),
                    };
                    return Err(refuse(
                        index,
                        format!(
                            "its record's `{}` evidence, `{}`, is {state}; a record is logged with \
                             the evidence it names beside it, or a reader could never re-derive it",
                            e.name,
                            evidence_path(&e.digest)
                        ),
                    ));
                }
            }
            // Followed in order, the base's too, so that a record is held to the key current at
            // its own leaf.
            Leaf::KeyChange(c) => {
                if let KeyChange::NotCurrent { why } = keys.follow(pos, &origin, c)?
                    && new
                {
                    return Err(refuse(
                        index,
                        format!("it is a key change from a key that is not the current one: {why}"),
                    ));
                }
            }
            Leaf::Heartbeat(_) => {}
            // Both keys present, and the one given is the one named: `trigon log sign` cosigns the
            // final checkpoint with it, which is what the successor's log-continuation holds.
            Leaf::LogEnd(end) if new => {
                let named = &end.successor;
                match successor {
                    Some(s) if s.to_string() == named.log_key => {}
                    Some(s) => {
                        return Err(refuse(
                            index,
                            format!(
                                "it is a log-end naming the successor `{}` under the log key {}, \
                                 and the successor's key given is {s}",
                                named.origin, named.log_key
                            ),
                        ));
                    }
                    None => {
                        return Err(refuse(
                            index,
                            format!(
                                "it is a log-end naming the successor `{}`, and a log is ended \
                                 only by a `trigon log sign` that holds the successor's log key \
                                 too (--successor-key), to cosign the final checkpoint the \
                                 successor continues from: a log ended in favour of a key nobody \
                                 has shown is held is a log nobody may be able to continue",
                                named.origin
                            ),
                        ));
                    }
                }
            }
            Leaf::LogContinuation(_) if new => {
                return Err(refuse(
                    index,
                    "it is a log-continuation, which begins a successor and is signed only as \
                     that log's first tree (`trigon log sign --continuing`), never appended to a \
                     log with a checkpoint of its own"
                        .into(),
                ));
            }
            Leaf::Release(_) if new => {
                return Err(refuse(
                    index,
                    "it is a release leaf, which no command of this build writes; the log key \
                     signs one only once a command that checks it does (docs/19 §10 phase 9)"
                        .into(),
                ));
            }
            Leaf::Release(_) | Leaf::LogEnd(_) | Leaf::LogContinuation(_) => {}
        }
    }
    Ok(ext)
}

/// Check the first tree of a successor log, at `dir` in the repository at `repo`, for signing
/// under its own log key `vkey`: the tree `trigon log succeed` writes, of `size` leaves, which is
/// one — the log-continuation alone, since everything after it is published into the log like
/// into any other.
///
/// `predecessor` is the log whose log-end names this one, verified by the caller from where it is
/// (`find_predecessor`); `published` the newest checkpoint of it known to have been published,
/// which it must extend, so that a successor is never begun from a predecessor rolled back. The
/// continuation must hold the predecessor's final checkpoint signed by both log keys, and the
/// checkpoint [`Beginning::sign`] makes is held to [`follow`] before it is returned: what every
/// client asks of a succession is asked here first, with the client's own code.
///
/// [`follow`]: crate::log::follow
pub fn check_to_begin(
    repo: &Path,
    dir: &str,
    vkey: &LogVkey,
    size: u64,
    predecessor: &VerifiedLog,
    published: Option<&SignedCheckpoint>,
) -> Result<Beginning, Unsignable> {
    if let Some(p) = published {
        let extends = p.origin() == predecessor.origin()
            && p.size() <= predecessor.size()
            && predecessor.tree().root_at(p.size()).ok().as_ref() == Some(p.root());
        if !extends {
            return Err(Unsignable::Log(LogError::Rotation(format!(
                "the log `{}` this would continue has {} leaves, and does not extend the \
                 checkpoint of {} leaves of it published from this host: a successor is begun \
                 only from the log as it was published",
                predecessor.origin(),
                predecessor.size(),
                p.size()
            ))));
        }
    }
    Ok(verify_beginning(
        &DirFiles::in_repository(repo, dir),
        vkey,
        size,
        predecessor,
    )?)
}
