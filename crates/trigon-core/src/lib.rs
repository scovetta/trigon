//! Pure types shared across Trigon.
//!
//! This crate declares **no cargo features** and depends on nothing that can perform I/O.
//! The dependency-policy test in `xtask` enforces both. See `docs/01-architecture.md` §2.2.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod digest;
mod evidence;
mod failure;
mod fault;
mod format;
pub mod jcs;
mod logs;
mod note;
mod outcome;
mod path;
mod target;

pub use digest::{Digest, MultiDigest, ParseDigestError, Sha512};
pub use evidence::{
    Claim, Confidence, Evidence, Intrinsics, RegistryMoment, SourceDiscovery, SourceProvenance,
    ToolchainResolution, resolve_toolchain,
};
pub use failure::{FailureSignature, classify, classify_line};
pub use fault::{Classify, Fault, Phase};
pub use format::{Format, UnknownFormat};
pub use logs::{Compressed, compress};
pub use note::{Note, NoteCode};
pub use outcome::{Match, ProfileId, Provenance, RiskTier, StabilizerId};
pub use path::EntryPath;
pub use target::{ArtifactId, ArtifactKind, Ecosystem, PurlError, Target, TargetRef};
