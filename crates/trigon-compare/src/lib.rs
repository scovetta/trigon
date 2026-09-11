//! One-pass comparison of two artifacts.
//!
//! Six digests per comparison, three per side: the bytes as published, the decompressed container
//! before any stabilizer, and the stabilized re-serialization. The container digest is what answers
//! "same tar, different gzip framing", the most common near-miss for `.crate`, `.tgz` and `.gem`,
//! and it costs one more hasher on a stream that is already flowing.
//!
//! See `docs/05-archive-and-normalization.md` §4.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod diff;

pub use diff::{DiffReport, FileDiff, FileStatus};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512 as Sha512Hasher};
use trigon_archive::{ArchiveError, Limits, parse, serialize};
use trigon_core::{
    Digest, Format, Match, MultiDigest, Note, ProfileId, Provenance, RiskTier, Sha512,
};
use trigon_stabilize::{Applied, StabilizerSet, apply};

#[derive(Debug, thiserror::Error)]
pub enum CompareError {
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("the two sides were stabilized under different sets: {0} and {1}")]
    SetMismatch(ProfileId, ProfileId),
}

impl trigon_core::Classify for CompareError {
    fn fault(&self) -> trigon_core::Fault {
        match self {
            // Delegate rather than restate. A malformed artifact is the artifact's fault whether
            // the parser was reached through a comparison or directly, and duplicating the mapping
            // here is how the two answers drift apart.
            CompareError::Archive(e) => e.fault(),
            // Comparing across stabilizer sets is a caller error: the two digests answer different
            // questions, so the comparison was never going to mean anything.
            CompareError::SetMismatch(..) => trigon_core::Fault::Bug,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            CompareError::Archive(e) => e.is_retryable(),
            CompareError::SetMismatch(..) => false,
        }
    }
}

/// What one artifact looks like at each of the three forms we digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary {
    pub format: Format,
    pub bytes: u64,
    pub raw: MultiDigest,
    /// Present only for a format with an outer codec.
    pub container: Option<MultiDigest>,
    pub stabilized: MultiDigest,
    pub applied: Vec<Applied>,
    pub notes: Vec<Note>,
    pub set: (ProfileId, Digest),
}

/// Parse, stabilize and digest one artifact.
pub fn summarize(
    bytes: Vec<u8>,
    format: Format,
    set: &StabilizerSet,
    limits: &Limits,
) -> Result<(Summary, trigon_archive::Archive), CompareError> {
    let raw = multi_digest(&bytes, true);
    let n = bytes.len() as u64;

    let mut notes = Vec::new();
    let mut parsed = parse(bytes, format, limits, &mut notes)?;
    let container = parsed.container.as_deref().map(|c| multi_digest(c, false));

    let applied = apply(set, &mut parsed.archive);
    // `store_only`: the stabilized stream never passes through a deflate encoder, so no encoder's
    // behaviour can reach a signed digest.
    let stabilized_bytes = serialize(&parsed.archive, true)?;
    let stabilized = multi_digest(&stabilized_bytes, false);

    Ok((
        Summary {
            format,
            bytes: n,
            raw,
            container,
            stabilized,
            applied,
            notes,
            set: (set.id.clone(), set.digest()),
        },
        parsed.archive,
    ))
}

fn multi_digest(bytes: &[u8], with_sha512: bool) -> MultiDigest {
    let sha256 = Digest::from_bytes(Sha256::digest(bytes).into());
    // SHA-512 rides along on raw artifact digests only: those are what a third party cross-checks
    // against a registry, and registries publish both. Doubling the others would double the hashing
    // cost of the hottest loop in the system for a value nobody else publishes.
    let sha512 = with_sha512.then(|| Sha512(Sha512Hasher::digest(bytes).into()));
    MultiDigest { sha256, sha512 }
}

/// The result of comparing two artifacts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Comparison {
    pub outcome: Match,
    pub upstream: Summary,
    pub rebuild: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffReport>,
}

impl Comparison {
    /// "Same tar, different gzip framing". `None` when the format has no outer codec.
    pub fn container_bit_identical(&self) -> Option<bool> {
        Some(self.upstream.container.as_ref()?.sha256 == self.rebuild.container.as_ref()?.sha256)
    }

    /// Every stabilizer that fired on either side.
    pub fn applied(&self) -> Vec<&Applied> {
        self.upstream
            .applied
            .iter()
            .chain(&self.rebuild.applied)
            .collect()
    }

    /// Whether the outcome was capped below `Normalized` by provenance or risk, and why.
    pub fn cap_reason(&self) -> Option<String> {
        self.applied()
            .into_iter()
            .find(|a| a.provenance != Provenance::Builtin || a.risk > RiskTier::Metadata)
            .map(|a| format!("{} is {:?} at {:?} risk", a.id, a.provenance, a.risk))
    }
}

/// Compare two summaries.
///
/// The provenance cap lives here and nowhere else: `Match::Normalized` is unreachable when any
/// applied stabilizer carries non-`Builtin` provenance or a risk tier above `Metadata`. Anything a
/// model touched reaches at most `NormalizedWithCaveats`. See `docs/00-overview.md` §3.1.
pub fn compare(
    upstream: Summary,
    rebuild: Summary,
    upstream_archive: Option<&trigon_archive::Archive>,
    rebuild_archive: Option<&trigon_archive::Archive>,
) -> Result<Comparison, CompareError> {
    if upstream.set.1 != rebuild.set.1 {
        return Err(CompareError::SetMismatch(
            upstream.set.0.clone(),
            rebuild.set.0.clone(),
        ));
    }

    let outcome = if upstream.raw.sha256 == rebuild.raw.sha256 {
        Match::Exact
    } else if upstream.stabilized.sha256 == rebuild.stabilized.sha256 {
        let clean = upstream
            .applied
            .iter()
            .chain(&rebuild.applied)
            .all(|a| a.provenance == Provenance::Builtin && a.risk <= RiskTier::Metadata);
        if clean {
            Match::Normalized
        } else {
            Match::NormalizedWithCaveats
        }
    } else {
        Match::Divergent
    };

    // A diff report is produced on every run, including a success: it is what makes a verdict
    // auditable, and it is what the UI renders.
    let diff = match (upstream_archive, rebuild_archive) {
        (Some(u), Some(r)) => Some(diff::report(u, r)),
        _ => None,
    };

    // One event carrying the verdict and the digests it rests on. This is the line a fleet
    // aggregates, so it names the outcome as a string rather than an ordinal: a downstream filter
    // written against an integer breaks the moment an outcome is inserted.
    tracing::info!(
        outcome = %outcome,
        upstream_stabilized = %upstream.stabilized.sha256,
        rebuild_stabilized = %rebuild.stabilized.sha256,
        applied = upstream.applied.len(),
        differs = diff.as_ref().map(|d| d.differs).unwrap_or(0),
        "compared"
    );
    Ok(Comparison {
        outcome,
        upstream,
        rebuild,
        diff,
    })
}

/// Convenience: summarize both sides under one set and compare them.
pub fn compare_bytes(
    upstream: Vec<u8>,
    rebuild: Vec<u8>,
    format: Format,
    set: &StabilizerSet,
    limits: &Limits,
) -> Result<Comparison, CompareError> {
    let (us, ua) = summarize(upstream, format, set, limits)?;
    let (rs, ra) = summarize(rebuild, format, set, limits)?;
    compare(us, rs, Some(&ua), Some(&ra))
}
