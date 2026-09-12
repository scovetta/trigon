//! What one run leaves behind.
//!
//! The record is deliberately a description of *facts about a build*, not a log of what our code
//! did. Everything in it is either a digest or a small scalar, and every large thing it refers to
//! lives in the blob store under its own hash. That keeps the manifest small enough to read, and it
//! is what lets the attestor work from the record alone: it fetches what it needs by hash, checks
//! the hash, and never has to trust the process that wrote any of it.
//!
//! This is also the source for the `rebuild/v1` and `buildobservation/v1` predicates
//! (`docs/09-attestations.md` §2), which is why fields like the base image, the egress tier and the
//! achieved isolation are here rather than in a log line: a predicate assembled from prose is a
//! predicate nobody can regenerate.

use serde::{Deserialize, Serialize};
use trigon_core::{Digest, FailureSignature};

/// How far a run got. The five persisted states of `docs/03` §1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Inferring,
    Building,
    Judging,
    Done,
}

/// One artifact, by name and by what it hashes to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub name: String,
    pub sha256: Digest,
    pub bytes: u64,
    /// Whether the bytes are still in the blob store.
    ///
    /// Stated rather than discovered, so a consumer can tell "pruned after a match" from "never
    /// stored" — and so `--rerun-comparison` can say which of those it is up against instead of
    /// reporting a missing blob.
    #[serde(default = "yes")]
    pub stored: bool,
}

fn yes() -> bool {
    true
}

/// The environment a build ran in, as the attestation has to describe it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Pinned by digest. A tag would make the record unreproducible by anyone else.
    pub base_image: String,
    pub egress: String,
    pub isolation: String,
    /// Whether this run may be attested at full trust.
    ///
    /// False where the runner enforced no mirror and recorded no network transcript: such a run
    /// cannot claim the build fetched nothing it should not have, and saying so here keeps that
    /// out of the signed statement rather than leaving it to be inferred.
    pub attestable: bool,
    /// The instant the dependency index was pinned to, where one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_moment: Option<String>,
    /// Evidence that the pin above bound anything.
    ///
    /// A `registry_moment` on its own is a claim about how the build was configured, not about how
    /// it resolved. The two came apart silently for weeks: pip ignores an untrusted plain-HTTP
    /// index after a single warning and resolves against the live one, so every run recorded a pin
    /// it did not have. Recording the evidence beside the claim is what makes the difference
    /// visible to anyone reading the statement rather than only to whoever ran it.
    ///
    /// `None` where no mirror was configured, which is a third state and not a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<PinEvidence>,
}

/// What the mirror saw, recorded beside the moment the build claimed to be pinned to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinEvidence {
    /// Non-zero is proof the configuration reached the client.
    pub index_requests: u64,
    pub versions_withheld: u64,
    pub artifact_requests: u64,
    /// Requests refused, most often for arriving without the filter. Distinct from silence.
    pub rejected: u64,
}

impl PinEvidence {
    /// Whether anything was served through the time filter.
    pub fn bound(&self) -> bool {
        self.index_requests > 0
    }
}

/// Everything one run produced, with the large parts left in the blob store.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: String,
    /// The package URL this run is about.
    pub target: String,
    pub state: RunState,
    /// `exact`, `normalized`, `normalized_with_caveats`, `divergent`, or absent. A string, never an
    /// ordinal, for the same reason the wire format is: a consumer filtering on an integer breaks
    /// the moment an outcome is inserted between two existing ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Not a pass and not a failure. Present when the artifact under test reached the build over
    /// the network, which makes whatever it produced evidence of nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_trips: Vec<String>,

    pub started: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,

    pub environment: Environment,
    /// Canonical JSON of the strategy, and its digest. The digest is what a cache key is built from
    /// and what the attestation names; the blob is what a person reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_digest: Option<String>,
    /// How the strategy was arrived at: `definition`, `heuristic`, `ci_derived`, `model_assisted`.
    /// A provenance fact beside the claim, never inside it (`docs/09` §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<String>,
    /// The rendered scripts the executor actually ran. Rendering happens once, at resolution time,
    /// so what ran is a stored artifact rather than something to be re-derived from a template and
    /// a context that may no longer exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<Digest>,

    pub upstream: ArtifactRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild: Option<ArtifactRef>,

    /// The full `Comparison`, which carries both sides' three digests, every stabilizer that fired
    /// with its risk and provenance, and the difference codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_log: Option<Digest>,

    /// Per-phase durations in seconds. `None` means *no data*, never zero: a timing we failed to
    /// read is not a phase that took no time, and averaging the two produces a number that quietly
    /// understates every build.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timings: Vec<(String, Option<f64>)>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureSignature>,

    /// Set once a statement has been signed for this run. Read by the prune path, which must not
    /// discard the bytes a signature is about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<String>,
}

impl RunRecord {
    /// A minimal record for a run that has just started.
    pub fn new(
        id: impl Into<String>,
        target: impl Into<String>,
        upstream: ArtifactRef,
        environment: Environment,
        started: impl Into<String>,
    ) -> Self {
        RunRecord {
            id: id.into(),
            target: target.into(),
            state: RunState::Building,
            outcome: None,
            guard_trips: Vec::new(),
            started: started.into(),
            finished: None,
            environment,
            strategy: None,
            strategy_digest: None,
            derivation: None,
            instructions: None,
            upstream,
            rebuild: None,
            comparison: None,
            build_log: None,
            timings: Vec::new(),
            failure: None,
            attestations: Vec::new(),
        }
    }

    /// Whether this run is evidence about the package reproducing.
    ///
    /// A tripped guard is not, whatever the outcome says: the artifact under test reached the build
    /// over the network, so a perfect match proves only that the build downloaded it. This is the
    /// one question a consumer of the record must not get wrong, so it is a method rather than a
    /// convention about reading two fields together.
    pub fn is_evidence(&self) -> bool {
        self.guard_trips.is_empty() && self.outcome.is_some()
    }
}
