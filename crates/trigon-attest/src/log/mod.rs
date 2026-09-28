//! The evidence log, as pure code (`docs/19` §2.3, §8; `docs/09-attestations.md` §2.10).
//!
//! An append-only log that we sign, with one small leaf per published record, an RFC 6962 Merkle
//! tree over the leaves, and its root signed as a checkpoint. Its job is to make it impossible for
//! us to quietly change our minds, and every client recomputes it whole. The formats are the C2SP
//! ones the witness network takes, from the first leaf, so nothing about the log changes when
//! witnesses cosign it (`docs/19` §10 phase 7b):
//!
//! - [`note`]: C2SP signed notes, Ed25519 keys, and the log key in Go's private-key format;
//! - [`checkpoint`]: C2SP tlog-checkpoint — origin, size, root, and no extension lines;
//! - [`merkle`]: RFC 6962 hashing, roots, and inclusion and consistency proofs (RFC 9162);
//! - [`tiles`]: C2SP tlog-tiles — tile and entry-bundle paths, framing, what a tree of a size has,
//!   what an append writes, and reading a proof's hashes from tiles;
//! - [`leaf`]: the six leaf kinds, canonical JSON, decoded strictly;
//! - [`verify`]: a log verified from its files, a repository's chain of logs, a chain followed
//!   into another repository, and copies of one chain held to being one;
//! - [`rotation`]: following attestation-key changes.
//!
//! No network, no runtime, and no filesystem beyond reading the directory it is given: the
//! network-free verifier links this, and a clone is verified with no socket open.

pub mod checkpoint;
mod error;
pub mod files;
pub mod leaf;
pub mod merkle;
pub mod note;
pub mod rotation;
pub mod tiles;
pub mod verify;

pub use checkpoint::{Checkpoint, SignedCheckpoint};
pub use error::LogError;
pub use files::{DirFiles, LogFiles, Staged};
pub use leaf::{
    HeartbeatLeaf, KeyChangeKey, KeyChangeLeaf, Leaf, LeafOutcome, LogContinuationLeaf, LogEndLeaf,
    RecordLeaf, ReleaseLeaf, Successor,
};
pub use merkle::{Hash, Tree};
pub use note::{LogSigner, SignedNote};
pub use rotation::{KeyChange, KeyEpoch, KeyHistory, LeafPos};
pub use tiles::{Append, Bundle, Tile, TileHashes, plan_append};
pub use verify::{
    Beginning, ChainedLog, Disagreement, Extension, RefusedLog, VerifiedLog, VerifiedSource,
    check_accepted, compare_chains, find_predecessor, follow, open_checkpoint,
    prove_inclusion_from_tiles, same_log, verify_beginning, verify_continuation, verify_extension,
    verify_extension_from_tiles, verify_log, verify_source,
};
