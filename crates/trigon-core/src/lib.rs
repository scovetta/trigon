//! Pure types shared across Trigon.
//!
//! This crate declares **no cargo features** and depends on nothing that can perform I/O.
//! The dependency-policy test in `xtask` enforces both. See `docs/01-architecture.md` §2.2.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod digest;
mod fault;
mod format;
mod note;
mod outcome;
mod path;
mod target;

pub use digest::{Digest, MultiDigest, ParseDigestError, Sha512};
pub use fault::{Classify, Fault};
pub use format::Format;
pub use note::{Note, NoteCode};
pub use outcome::{Match, ProfileId, Provenance, RiskTier, StabilizerId};
pub use path::EntryPath;
pub use target::{ArtifactId, ArtifactKind, Ecosystem, PurlError, Target, TargetRef};
