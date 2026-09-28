//! An evidence repository read as a client reads one (`docs/19` §4, §5, §6, §8): records verified
//! against the log, lookup over the verified leaves, and where every file of the repository is.
//!
//! [`crate::log`] makes the log checkable; this makes the records it logs checkable, and finds
//! them. Pure, as the log is: no network, and no filesystem beyond the directory it is given, so
//! the network-free verifier links it and a clone is checked with no socket open.
//!
//! - [`paths`]: record, evidence and index paths, and the index file, derived from each key a
//!   record is found by — the functions `publish` writes with and every reader reads with;
//! - [`check_record`]: one record file against its leaf, the key current at that leaf, and the
//!   evidence files beside it;
//! - [`Key`], [`Lookup`]: resolving a digest, a purl, a package or a file to the records the log
//!   holds for it, never through `index/`, with every supersession the log records applied;
//! - [`Repository`]: a directory with the `docs/19` §2.3 layout, its log verified under a source's
//!   pinned keys, which the rest is asked through — or a source's whole chain, across every
//!   repository it has gone on in;
//! - [`Standing`], [`exit_code`]: whether a source can answer now, by the two clocks of `docs/19`
//!   §6, and what several sources' answers about one package come to;
//! - [`check_to_sign`]: what `trigon log sign` holds a new tree to before the log key signs it —
//!   the writer's side, checked with the reader's code — and [`check_to_begin`], the same for a
//!   successor's first tree.
//!
//! **The log wins, and the disagreement is shown** (`docs/19` §8). A record file no leaf names is
//! unlogged and fails verification, and one the log holds at two leaves fails at both; a leaf
//! whose file is missing is deleted, whatever its outcome; a record whose signed statement
//! disagrees with its leaf fails. None of these is ever answered as "never checked", because each
//! may be an attack.

mod check;
mod lookup;
pub mod paths;
mod repository;
mod sign;
mod standing;

pub use check::{
    EvidenceFile, EvidenceState, RecordFailure, RecordKind, VerifiedRecord, check_record,
    read_evidence_from, record_leaf,
};
pub use lookup::{Answer, Found, Key, Lookup, RecordState, SupersededBy, risk_name};
pub use paths::{
    IndexEntry, IndexFile, IndexKey, evidence_path, index_files, index_files_after, record_path,
};
pub use repository::{EVIDENCE_LIMIT, RECORD_LIMIT, Repository};
pub use sign::{Unsignable, check_to_begin, check_to_sign};
pub use standing::{Said, Standing, ago, exit_code, first_that_wins};
