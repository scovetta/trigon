use std::fmt;

use serde::{Deserialize, Serialize};

/// How far two artifacts agree.
///
/// Serialized as a **string**, never as an ordinal. A downstream policy engine that writes
/// `rung <= 3` traps you into never inserting a rung. See `docs/05-archive-and-normalization.md` §4.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    /// Stabilized digests differ.
    Divergent,
    /// Stabilized digests equal, and at least one applied stabilizer is `Content` or `Lossy`, or
    /// carries `Human` or `Model` provenance.
    NormalizedWithCaveats,
    /// Stabilized digests equal, every applied stabilizer `Builtin` at `Metadata` risk or below.
    Normalized,
    /// Raw digests equal. No transform was needed.
    Exact,
}

impl Match {
    /// Ordering exists for policy convenience. The wire format stays a string.
    pub fn is_at_least(self, floor: Match) -> bool {
        self >= floor
    }

    pub const fn is_reproduced(self) -> bool {
        !matches!(self, Match::Divergent)
    }
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Match::Exact => "exact",
            Match::Normalized => "normalized",
            Match::NormalizedWithCaveats => "normalized_with_caveats",
            Match::Divergent => "divergent",
        })
    }
}

/// What a stabilizer is allowed to disturb.
///
/// `Structural` covers reordering and reframing, **and** dropping integrity metadata computed over
/// content we are rebuilding: a `checksums.yaml.gz` or a `.sig` cannot differ while the content
/// matches, and neither is content a consumer reads. See `docs/05-archive-and-normalization.md` §3.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Structural,
    Metadata,
    Content,
    Lossy,
}

/// Who wrote a stabilizer.
///
/// Load-bearing: the provenance cap in `docs/00-overview.md` §3.1 makes `Match::Normalized`
/// unreachable when anything other than `Builtin` fired.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Provenance {
    Builtin,
    Human { reviewer: String },
    Model { model_id: String, run_id: String },
}

impl Provenance {
    pub const fn is_builtin(&self) -> bool {
        matches!(self, Provenance::Builtin)
    }
}

/// A stable stabilizer name. Appears verbatim in every attestation, so it never changes.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StabilizerId(pub String);

impl StabilizerId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StabilizerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a stabilizer set, such as `npm-tarball` or `wheel`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(pub String);

impl ProfileId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_outranks_normalized() {
        assert!(Match::Exact.is_at_least(Match::Normalized));
        assert!(!Match::NormalizedWithCaveats.is_at_least(Match::Normalized));
        assert!(Match::NormalizedWithCaveats.is_at_least(Match::Divergent));
    }

    #[test]
    fn serializes_as_a_string() {
        let j = serde_json::to_string(&Match::NormalizedWithCaveats).unwrap();
        assert_eq!(j, "\"normalized_with_caveats\"");
    }

    #[test]
    fn risk_tiers_are_ordered_for_the_cap() {
        assert!(RiskTier::Metadata <= RiskTier::Metadata);
        assert!(RiskTier::Content > RiskTier::Metadata);
        assert!(RiskTier::Structural < RiskTier::Metadata);
    }
}
