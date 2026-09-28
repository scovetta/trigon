//! Pure types shared across Trigon.
//!
//! This crate declares **no cargo features** and depends on nothing that can perform I/O.
//! The dependency-policy test in `xtask` enforces both. See `docs/01-architecture.md` §2.2.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod declared;
mod digest;
mod evidence;
mod failure;
mod fault;
mod format;
pub mod jcs;
mod lockfile;
mod logs;
mod note;
mod opinion;
mod outcome;
mod path;
pub mod purl;
mod target;

pub use declared::{CheckResult, DeclaredDigest, DigestCheck};
pub use digest::{Digest, MultiDigest, ParseDigestError, Sha1, Sha512};
pub use evidence::{
    Claim, Confidence, Evidence, Intrinsics, RegistryMoment, SourceDiscovery, SourceProvenance,
    ToolchainResolution, resolve_toolchain,
};
pub use failure::{FailureSignature, classify, classify_line};
pub use fault::{Classify, Fault, Phase};
pub use format::{Format, UnknownFormat};
pub use lockfile::{Kind, LockfileError, Package, Status, parse as parse_lockfile, read as read_lockfile};
pub use logs::{Compressed, compress, strip_controls};
pub use note::{Note, NoteCode};
pub use opinion::{DiffOpinion, DiffVerdict};

/// Whether a member name is a .NET managed assembly worth trying to decompile.
///
/// One place, because two ask: the binary's decompiler gates on it, and the serve member view
/// gates its cache probe on it so a `.txt` member does not cost two object-store lookups on the
/// way to a hex view. By extension, and best effort past it — a native `.dll` reaches the
/// decompiler, produces nothing, and falls back, which costs one attempt and never a wrong answer.
pub fn is_managed_assembly(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".dll") || lower.ends_with(".exe")
}
pub use outcome::{
    Match, ProfileId, Provenance, RiskTier, StabilizerId, caps_normalized, ceiling_of,
};
pub use path::EntryPath;
pub use target::{ArtifactId, ArtifactKind, Ecosystem, PurlError, Target, TargetRef};
