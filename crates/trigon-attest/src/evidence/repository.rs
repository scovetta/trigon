//! An evidence repository, opened: its log verified under a source's pinned keys, and its records
//! read through that log (`docs/19` §2.3, §6, §6.1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use trigon_core::Digest;

use super::check::{
    EvidenceFile, EvidenceState, RecordFailure, VerifiedRecord, check_record, read_evidence,
};
use super::lookup::{Found, Key, Lookup, RecordState};
use super::paths::{evidence_path, record_path};
use crate::log::{
    DirFiles, KeyHistory, Leaf, LeafPos, LogError, LogFiles, RecordLeaf, VerifiedSource,
    verify_source,
};
use crate::record::Record;
use crate::{AttestationKey, LogVkey};

/// The longest record file read. A record is its statements and some digests, 7 to 15 KB
/// (`docs/19` §7); one far past that is not one this build wrote, and is refused unread.
pub const RECORD_LIMIT: u64 = 4 << 20;

/// The longest evidence file read: GitHub refuses a file over 100 MiB, so no repository it serves
/// holds a longer one. The largest comparison report in the local store is 5.94 MB.
pub const EVIDENCE_LIMIT: u64 = 100 << 20;

/// A directory with the `docs/19` §2.3 layout — a clone, or any copy of one — whose log has been
/// verified under one source's pinned keys, and whose attestation keys have been followed through
/// its key-change leaves.
///
/// Keys never cross sources (`docs/19` §6.1): everything asked of a `Repository` is answered from
/// its own log and checked against its own keys.
#[derive(Debug)]
pub struct Repository {
    root: PathBuf,
    files: DirFiles,
    source: VerifiedSource,
    keys: KeyHistory,
    skipped: Vec<(LeafPos, String)>,
    /// Every record the log holds at more than one leaf, with those leaves in order: none of them
    /// is verified ([`RecordFailure::LoggedTwice`]).
    twice: BTreeMap<Digest, Vec<LeafPos>>,
}

impl Repository {
    /// Verify the repository at `root`: its chain of logs under the pinned log key, against the
    /// checkpoint last accepted where there is one ([`verify_source`]), and its attestation keys
    /// from the pinned one through every key change the log holds ([`KeyHistory`]).
    pub fn open(
        root: &Path,
        log_key: &LogVkey,
        attestation_key: &AttestationKey,
        accepted: Option<&[u8]>,
    ) -> Result<Repository, LogError> {
        let source = verify_source(root, log_key, accepted)?;
        let (keys, skipped) = KeyHistory::from_source(attestation_key.clone(), &source)?;
        let mut repo = Repository {
            root: root.to_path_buf(),
            // Every file is read inside the repository and nowhere else, as the log's are: a
            // record or an evidence file that is a link out of it reads nothing.
            files: DirFiles::new(root),
            source,
            keys,
            skipped,
            twice: BTreeMap::new(),
        };
        // Over the whole chain, whatever key a lookup asks for: a record logged again is the same
        // record under every key it is found by.
        let mut at: BTreeMap<Digest, Vec<LeafPos>> = BTreeMap::new();
        for (pos, leaf) in repo.record_leaves() {
            at.entry(leaf.record).or_default().push(pos);
        }
        at.retain(|_, leaves| leaves.len() > 1);
        repo.twice = at;
        Ok(repo)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The verified chain of logs, with whatever was set aside in choosing where it starts.
    pub fn source(&self) -> &VerifiedSource {
        &self.source
    }

    /// The attestation keys the source has had, from the pinned one.
    pub fn keys(&self) -> &KeyHistory {
        &self.keys
    }

    /// Key changes from a key that was not current, which changed nothing, with where each was.
    pub fn skipped_key_changes(&self) -> &[(LeafPos, String)] {
        &self.skipped
    }

    /// The origin of the log a leaf is in.
    pub fn origin(&self, pos: LeafPos) -> &str {
        self.source.logs[pos.log].log.origin()
    }

    /// Every record leaf of the chain, in the order the source logged them.
    pub fn record_leaves(&self) -> impl Iterator<Item = (LeafPos, &RecordLeaf)> {
        self.source.logs.iter().enumerate().flat_map(|(log, c)| {
            c.log.leaves().filter_map(move |(index, leaf)| match leaf {
                Leaf::Record(r) => Some((LeafPos { log, index }, r)),
                _ => None,
            })
        })
    }

    /// When the newest leaf of the chain was logged: what the frozen clock of `docs/19` §6 reads.
    pub fn newest_time(&self) -> Option<u64> {
        self.source
            .logs
            .iter()
            .rev()
            .find_map(|c| c.log.newest_time())
    }

    /// A record file by its digest, from `records/`, or `None` where there is none.
    pub fn read_record(&self, record: &Digest) -> Result<Option<Vec<u8>>, LogError> {
        self.files.read(&record_path(record), super::RECORD_LIMIT)
    }

    /// An evidence file by its digest, from `evidence/sha256/`, or `None` where there is none.
    /// Not checked against the digest here; a record's evidence is, by [`check_record`], and
    /// anything read to be judged is read by [`Self::read_evidence_checked`].
    pub fn read_evidence(&self, digest: &Digest) -> Result<Option<Vec<u8>>, LogError> {
        self.files
            .read(&evidence_path(digest), super::EVIDENCE_LIMIT)
    }

    /// A verified record's piece of evidence, read again to be judged — a comparison report held
    /// to a re-derivation, say — and held to its signed digest again, since the file checked when
    /// the record was verified may be other bytes now: a writer between the two reads, or a mount
    /// that serves one thing and then another. What is found of it now, and its bytes where they
    /// are the bytes signed; other bytes fail, as they would have at [`check_record`].
    pub fn read_evidence_checked(
        &self,
        e: &EvidenceFile,
    ) -> Result<(EvidenceState, Option<Vec<u8>>), RecordFailure> {
        read_evidence(&self.files, &e.name, &e.digest)
    }

    /// The files of the repository, by their paths in it.
    pub fn files(&self) -> &dyn LogFiles {
        &self.files
    }

    /// Verify a record file handed in whole, as `verify-attestation --record` does: its leaf is
    /// the one the log holds for its digest; a record the log holds no leaf for is unlogged, and
    /// one it holds at two is logged twice, which fails.
    pub fn verify_record(&self, bytes: &[u8]) -> Result<VerifiedRecord, RecordFailure> {
        let digest = Record::digest_of(bytes);
        if let Some(leaves) = self.twice.get(&digest) {
            return Err(RecordFailure::LoggedTwice {
                record: digest,
                leaves: leaves.clone(),
            });
        }
        let leaf = self.record_leaves().find(|(_, l)| l.record == digest);
        let origin = leaf.map_or("", |(pos, _)| self.origin(pos));
        check_record(bytes, leaf, origin, &self.keys, &self.files, None)
    }

    /// Every record the log holds for `key`, each read from `records/` and verified, a missing one
    /// `deleted`, one logged at two leaves failed at both, and every supersession applied. Never
    /// reads `index/`.
    pub fn lookup(&self, key: &Key) -> Lookup {
        let mut found = Vec::new();
        for (pos, leaf) in self.record_leaves().filter(|(_, l)| key.matches(l)) {
            let state = match (self.twice.get(&leaf.record), self.read_record(&leaf.record)) {
                // Whatever its file: a record at two leaves has no one place in the log to be
                // judged at, so whether a later record supersedes it has no answer, and a
                // deletion of it is the lesser finding.
                (Some(leaves), _) => RecordState::Failed(RecordFailure::LoggedTwice {
                    record: leaf.record,
                    leaves: leaves.clone(),
                }),
                (None, Ok(None)) => RecordState::Deleted,
                (None, Ok(Some(bytes))) => {
                    match check_record(
                        &bytes,
                        Some((pos, leaf)),
                        self.origin(pos),
                        &self.keys,
                        &self.files,
                        Some(key),
                    ) {
                        Ok(r) => RecordState::Verified(Box::new(r)),
                        Err(why) => RecordState::Failed(why),
                    }
                }
                // There, and not readable as a record: a link out of the repository, something that
                // is not a file, one too long to be a record. Not verified, so never passed.
                (None, Err(e)) => RecordState::Failed(RecordFailure::Unreadable(format!(
                    "`{}` could not be read as a record file: {e}",
                    record_path(&leaf.record)
                ))),
            };
            found.push(Found {
                pos,
                leaf: leaf.clone(),
                state,
                superseded_by: Vec::new(),
            });
        }
        Lookup::resolve(key.clone(), found)
    }
}
