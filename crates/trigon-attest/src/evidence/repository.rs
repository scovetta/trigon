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
use crate::location::printable;
use crate::log::{
    DirFiles, KeyHistory, Leaf, LeafPos, LogError, LogFiles, RecordLeaf, RefusedLog, VerifiedLog,
    VerifiedSource, check_accepted, verify_source,
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
/// its key-change leaves; or a source's whole chain of logs, where it goes on from one such
/// repository into another, each log's records read from the repository that holds the log.
///
/// Keys never cross sources (`docs/19` §6.1): everything asked of a `Repository` is answered from
/// its own log and checked against its own keys.
#[derive(Debug)]
pub struct Repository {
    /// Every repository the chain is in, in the order it reaches them: one, unless the chain goes
    /// on in another repository and that repository was followed ([`Self::chain`]).
    parts: Vec<Part>,
    /// For each log of the chain, the part it is in.
    part_of: Vec<usize>,
    source: VerifiedSource,
    keys: KeyHistory,
    skipped: Vec<(LeafPos, String)>,
    /// Every record the log holds at more than one leaf, with those leaves in order: none of them
    /// is verified ([`RecordFailure::LoggedTwice`]).
    twice: BTreeMap<Digest, Vec<LeafPos>>,
}

/// One repository of a chain: where it is, and its files.
#[derive(Debug)]
struct Part {
    root: PathBuf,
    // Every file is read inside the repository and nowhere else, as the log's are: a record or an
    // evidence file that is a link out of it reads nothing.
    files: DirFiles,
}

impl Repository {
    /// Verify the repository at `root`: its chain of logs under the pinned log key, against the
    /// checkpoint last accepted where there is one ([`verify_source`]), and its attestation keys
    /// from the pinned one through every key change the log holds ([`KeyHistory`]).
    ///
    /// A chain that goes on in another repository is verified as far as this one holds it, and
    /// [`VerifiedSource::continues_at`] says where it goes: [`Self::chain`] follows it there.
    pub fn open(
        root: &Path,
        log_key: &LogVkey,
        attestation_key: &AttestationKey,
        accepted: Option<&[u8]>,
    ) -> Result<Repository, LogError> {
        let source = verify_source(root, log_key, accepted)?;
        Self::assemble(vec![(root.to_path_buf(), source)], attestation_key)
    }

    /// A source's chain across repositories (`docs/19` §6.1, §8): `parts` in the order the chain
    /// reaches them, the first verified from the source's pinned log key by [`verify_source`], and
    /// each after it by [`crate::log::verify_continuation`] from the last log of the one before,
    /// which must have named it. Its attestation keys are followed from the pinned one through
    /// every key change of the whole chain, and `accepted`, the checkpoint last accepted for the
    /// source, is held to whichever log of the whole chain it is of ([`check_accepted`]).
    pub fn chain(
        parts: Vec<(PathBuf, VerifiedSource)>,
        attestation_key: &AttestationKey,
        accepted: Option<&[u8]>,
    ) -> Result<Repository, LogError> {
        for pair in parts.windows(2) {
            let (before, after) = (&pair[0].1, &pair[1].1);
            let named = before.continues_at.as_ref().ok_or_else(|| {
                LogError::Rotation(
                    "a repository was followed as the chain's next, and the one before it names \
                     no successor elsewhere"
                        .into(),
                )
            })?;
            let first = after.logs.first().map(|c| &c.log);
            if first
                .is_none_or(|l| l.origin() != named.origin || l.vkey().to_string() != named.log_key)
            {
                return Err(LogError::Rotation(format!(
                    "the repository followed as `{}`'s successor does not begin with it",
                    printable(&named.origin)
                )));
            }
        }
        let mut repo = Self::assemble(parts, attestation_key)?;
        let mut seen: Vec<&str> = Vec::new();
        for c in &repo.source.logs {
            if seen.contains(&c.log.origin()) {
                return Err(LogError::Rotation(format!(
                    "`{}` appears twice in this source's chain of logs; a succession never \
                     returns to an earlier log",
                    c.log.origin()
                )));
            }
            seen.push(c.log.origin());
        }
        repo.source.accepted_checked = match accepted {
            Some(note) => check_accepted(&repo.logs(), repo.source.continues_at.is_some(), note)?,
            None => true,
        };
        Ok(repo)
    }

    /// The parts put together, with the keys followed over all of them and the records the chain
    /// logs twice found.
    fn assemble(
        parts: Vec<(PathBuf, VerifiedSource)>,
        attestation_key: &AttestationKey,
    ) -> Result<Repository, LogError> {
        let mut whole: Option<VerifiedSource> = None;
        let mut part_of = Vec::new();
        let mut places = Vec::new();
        for (n, (root, source)) in parts.into_iter().enumerate() {
            part_of.extend(std::iter::repeat_n(n, source.logs.len()));
            // A directory that only means something inside its repository is said with it, past
            // the first.
            let at = |d: &str| match n {
                0 => d.to_string(),
                _ => format!("{d} in {}", root.display()),
            };
            match &mut whole {
                None => whole = Some(source),
                Some(w) => {
                    w.logs.extend(source.logs);
                    w.continues_at = source.continues_at;
                    w.unnamed.extend(source.unnamed.iter().map(|d| at(d)));
                    w.refused
                        .extend(source.refused.into_iter().map(|r| RefusedLog {
                            dir: at(&r.dir),
                            why: r.why,
                        }));
                    w.accepted_checked |= source.accepted_checked;
                }
            }
            places.push(Part {
                files: DirFiles::new(&root),
                root,
            });
        }
        let source = whole.ok_or_else(|| {
            LogError::Malformed("a chain of logs was asked for with no repository in it".into())
        })?;
        let (keys, skipped) = KeyHistory::from_source(attestation_key.clone(), &source)?;
        let mut repo = Repository {
            parts: places,
            part_of,
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

    /// The repository the chain starts in.
    pub fn root(&self) -> &Path {
        &self.parts[0].root
    }

    /// Every repository the chain is in, in the order it reaches them.
    pub fn roots(&self) -> impl Iterator<Item = &Path> {
        self.parts.iter().map(|p| p.root.as_path())
    }

    /// The repository that holds the log a leaf is in.
    pub fn root_of(&self, pos: LeafPos) -> &Path {
        &self.parts[self.part_of[pos.log]].root
    }

    /// Every log of the chain, in order.
    pub fn logs(&self) -> Vec<&VerifiedLog> {
        self.source.logs.iter().map(|c| &c.log).collect()
    }

    /// The chain's logs up to and including its `n`-th, by repository, as [`Self::chain`] takes
    /// them: what a writer publishing into a repository the chain goes on in stands on. The last
    /// part ends at that log, and goes on where its log-end names, if it has one.
    pub fn parts_through(&self, n: usize) -> Vec<(PathBuf, VerifiedSource)> {
        let mut out: Vec<(PathBuf, VerifiedSource)> = Vec::new();
        for (i, c) in self.source.logs.iter().enumerate().take(n + 1) {
            let root = &self.parts[self.part_of[i]].root;
            let begins = i == 0 || self.part_of[i] != self.part_of[i - 1];
            if begins {
                out.push((
                    root.clone(),
                    VerifiedSource {
                        logs: Vec::new(),
                        continues_at: None,
                        unnamed: Vec::new(),
                        refused: Vec::new(),
                        accepted_checked: false,
                    },
                ));
            }
            let (_, part) = out.last_mut().expect("a part was begun");
            part.logs.push(c.clone());
            part.continues_at = c
                .log
                .log_end()
                .map(|e| e.successor.clone())
                .filter(|s| !s.in_this_repository());
        }
        out
    }

    /// The files of the repository that holds the log a leaf is in.
    fn files_of(&self, pos: LeafPos) -> &DirFiles {
        &self.parts[self.part_of[pos.log]].files
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

    /// A record file by its digest, from `records/` of the repository holding the log that logs
    /// it — the first repository of the chain for a record no leaf names — or `None` where there
    /// is none.
    pub fn read_record(&self, record: &Digest) -> Result<Option<Vec<u8>>, LogError> {
        let files = match self.record_leaves().find(|(_, l)| l.record == *record) {
            Some((pos, _)) => self.files_of(pos),
            None => &self.parts[0].files,
        };
        files.read(&record_path(record), super::RECORD_LIMIT)
    }

    /// An evidence file by its digest, from `evidence/sha256/` of the first repository of the
    /// chain that has it, or `None` where none does. Not checked against the digest here; a
    /// record's evidence is, by [`check_record`], and anything read to be judged is read by
    /// [`Self::read_evidence_checked`].
    pub fn read_evidence(&self, digest: &Digest) -> Result<Option<Vec<u8>>, LogError> {
        for p in &self.parts {
            if let Some(bytes) = p
                .files
                .read(&evidence_path(digest), super::EVIDENCE_LIMIT)?
            {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// A verified record's piece of evidence, read again to be judged — a comparison report held
    /// to a re-derivation, say — and held to its signed digest again, since the file checked when
    /// the record was verified may be other bytes now: a writer between the two reads, or a mount
    /// that serves one thing and then another. What is found of it now, and its bytes where they
    /// are the bytes signed; other bytes fail, as they would have at [`check_record`]. Read from
    /// the repository that holds the record's log, `pos` being its leaf, as it was when verified.
    pub fn read_evidence_checked(
        &self,
        pos: LeafPos,
        e: &EvidenceFile,
    ) -> Result<(EvidenceState, Option<Vec<u8>>), RecordFailure> {
        read_evidence(self.files_of(pos), &e.name, &e.digest)
    }

    /// The files of the repository the chain starts in, by their paths in it.
    pub fn files(&self) -> &dyn LogFiles {
        &self.parts[0].files
    }

    /// Verify a record file handed in whole, as `verify-attestation --record` does: its leaf is
    /// the one the log holds for its digest; a record the log holds no leaf for is unlogged, and
    /// one it holds at two is logged twice, which fails.
    pub fn verify_record(&self, bytes: &[u8]) -> Result<VerifiedRecord, RecordFailure> {
        self.verify_record_reading(bytes, None)
    }

    /// [`Self::verify_record`], with the evidence the record names read from `evidence` where one
    /// is given, rather than from the directory of the repository that holds its log: what
    /// `verify-attestation --lookup` reads a partial clone's `evidence/` through, which is in
    /// git's objects and not in its working tree.
    pub fn verify_record_reading(
        &self,
        bytes: &[u8],
        evidence: Option<&dyn LogFiles>,
    ) -> Result<VerifiedRecord, RecordFailure> {
        let digest = Record::digest_of(bytes);
        if let Some(leaves) = self.twice.get(&digest) {
            return Err(RecordFailure::LoggedTwice {
                record: digest,
                leaves: leaves.clone(),
            });
        }
        let leaf = self.record_leaves().find(|(_, l)| l.record == digest);
        let origin = leaf.map_or("", |(pos, _)| self.origin(pos));
        let own: &dyn LogFiles = leaf.map_or(&self.parts[0].files, |(pos, _)| self.files_of(pos));
        check_record(bytes, leaf, origin, &self.keys, evidence.unwrap_or(own), None)
    }

    /// Every record the log holds for `key`, each read from `records/` and verified, a missing one
    /// `deleted`, one logged at two leaves failed at both, and every supersession applied. Never
    /// reads `index/`.
    pub fn lookup(&self, key: &Key) -> Lookup {
        let mut found = Vec::new();
        for (pos, leaf) in self.record_leaves().filter(|(_, l)| key.matches(l)) {
            let file = self
                .files_of(pos)
                .read(&record_path(&leaf.record), super::RECORD_LIMIT);
            let state = match (self.twice.get(&leaf.record), file) {
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
                        self.files_of(pos),
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
