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
//! 4. every other new leaf is a heartbeat, or a key change from the current key signed by both
//!    keys over this log. A release, log-end or log-continuation leaf is written by no command of
//!    this build, and is refused rather than signed on `publish`'s word.
//!
//! Nothing past the size it is told to sign is read, so a bundle or a tile planted beyond it by
//! whoever can push is never signed.

use std::collections::BTreeMap;
use std::path::Path;

use trigon_core::Digest;

use super::check::{EvidenceState, check_record};
use super::paths::{evidence_path, record_path};
use super::repository::RECORD_LIMIT;
use crate::AttestationKey;
use crate::LogVkey;
use crate::log::{
    DirFiles, Extension, KeyChange, KeyHistory, Leaf, LeafPos, LogError, LogFiles,
    SignedCheckpoint, verify_extension,
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
pub fn check_to_sign(
    repo: &Path,
    dir: &str,
    vkey: &LogVkey,
    size: u64,
    current: &AttestationKey,
    published: Option<&SignedCheckpoint>,
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
            Leaf::Release(_) | Leaf::LogEnd(_) | Leaf::LogContinuation(_) if new => {
                return Err(refuse(
                    index,
                    format!(
                        "it is a {} leaf, which no command of this build writes; the log key signs \
                         one only once a command that checks it does",
                        leaf.kind()
                    ),
                ));
            }
            Leaf::Release(_) | Leaf::LogEnd(_) | Leaf::LogContinuation(_) => {}
        }
    }
    Ok(ext)
}
