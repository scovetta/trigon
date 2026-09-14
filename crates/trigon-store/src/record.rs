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
    /// Whether this run can account for everything that crossed into the build.
    ///
    /// True exactly when `network_transcript` is present. A run without one cannot claim the build
    /// fetched nothing it should not have, and saying so here keeps that out of the signed
    /// statement rather than leaving it to be inferred.
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
    /// Toolchain downloads proxied through the mirror's allowlist. Recorded because a toolchain is
    /// the one thing a build fetches that then *runs*, and a reader of this record should not have
    /// to infer it from the artifact count.
    #[serde(default)]
    pub toolchain_requests: u64,
    /// Requests refused, most often for arriving without the filter. Distinct from silence.
    pub rejected: u64,
}

impl PinEvidence {
    /// Whether anything was served through the time filter.
    pub fn bound(&self) -> bool {
        self.index_requests > 0
    }
}

/// What one run cost, in the units `docs/03-pipeline-and-run-record.md` §3 asks for.
///
/// Every field is optional and **`None` means no data, never zero** — the same convention the phase
/// timings keep, and for the same reason. A run that asked no model and a run whose token counts we
/// failed to read are different facts; averaging the second as zero understates every figure built
/// on top of it, and the figures built on top of it are what decide where money goes.
///
/// The unit that matters downstream is `$` per *verdict gained*, not per target
/// ([`07-ai.md`](../docs/07-ai.md) §5). That division needs a denominator this record cannot see,
/// so what is stored here is the numerator and nothing else: no prices, no model-price table, no
/// currency. A price table baked into a run record is wrong within a quarter and quietly rewrites
/// history when it changes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Costs {
    /// Wall-clock seconds spent waiting on a model. `None` where none was asked.
    ///
    /// Measured around the provider call alone, so it is comparable with `build_seconds`: a rung
    /// that reads a repository and then asks a question must not bill the reading as inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference_seconds: Option<f64>,
    /// One entry per model used, and **never summed across them**. Adding token counts from models
    /// with different prices produces a number that means nothing; the prior art panics rather than
    /// allow it, and this keeps them apart instead. Empty where no model was asked anything, which
    /// `docs/07-ai.md` §6 wants to be the healthy majority of a corpus.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<Tokens>,
    /// Wall-clock seconds inside the sandbox, summed over the phases we have a timing for.
    ///
    /// `None` where no phase was timed. Phases whose timing we failed to read are left out rather
    /// than counted as zero, so this is a floor on the true figure and never an overstatement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_seconds: Option<f64>,
    /// Bytes that crossed the network into the build, from the network transcript.
    ///
    /// `None` where there is no transcript, `Some(0)` where there is one and nothing crossed. That
    /// distinction is the whole point of the field: `docs/10-scale.md` §1 puts dependency bytes
    /// first among the things that break at fleet scale — ~22 TB per cold 100k sweep — and a
    /// denominator that cannot tell "fetched nothing" from "was not measured" is not a measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_bytes: Option<u64>,
    /// Bytes this run added to the blob store in total: both artifacts, the log, the comparison,
    /// both transcripts. The budget `docs/10-scale.md` §1 sets is ~3 MB per run and ~270 GB per
    /// sweep, and this is the figure it is set against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_bytes: Option<u64>,
    /// The two halves of `blob_bytes` worth separating, because they are governed by different
    /// rules. Artifact bytes are what the retention policy drops on a match and keeps on a
    /// divergence (`docs/09-attestations.md` §6); log bytes are what the compression budget is set
    /// against. Both are subsets of `blob_bytes`, never additions to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_bytes: Option<u64>,
}

/// What the model calls cost, in tokens.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub input: u64,
    /// **A subset of `input`, not an addition.** Adding the two double-counts every cached token
    /// and makes a well-cached run look more expensive than a cold one — which inverts the sign of
    /// the one lever `docs/07-ai.md` §5 cares most about, since cache-read rate is an SLO.
    pub cached_input: u64,
    pub output: u64,
    /// The pinned model id. Without it a token count is not comparable to anything: the same count
    /// is two orders of magnitude apart in price between a local 0.5B and a frontier model.
    pub model: String,
    /// How many times a model was asked. The numerator of the model-invocation rate, which
    /// `docs/07-ai.md` §6 wants trending down.
    pub calls: u32,
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

    /// The model exchange this run's strategy came out of, when one did: JSON of a
    /// `trigon_ai::Transcript`, stored as an ordinary blob.
    ///
    /// Stored beside `derivation` rather than inside the signed statement, which is the rule from
    /// [`09`](../docs/09-attestations.md) §4: AI is a provenance fact next to the claim, never part
    /// of it. Worth keeping even where nobody intends to replay — a run that says
    /// `derivation: model_assisted` with no transcript is an assertion, and one with a transcript
    /// is a record. What a replay of it proves is narrow and stated where the type is defined: the
    /// provenance of the derivation, not the reproducibility of the result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<Digest>,

    /// Everything that crossed the network into the build, as JSON Lines — one
    /// `trigon_mirror::Exchange` per line, in the order the mirror finished serving them. Tier 1
    /// of `docs/08-execution.md` §7, and the body of the `buildobservation/v1` predicate.
    ///
    /// **Present and empty is not the same as absent.** A stored blob of zero bytes says the
    /// build's egress was completely accounted for and nothing crossed — which at `deny-all` is
    /// what having no network interface means. Absent says no complete account exists. Collapsing
    /// the two would turn "we never looked" into "we looked and it was clean", which is the exact
    /// reading this field exists to make impossible; `attestable` is derived from which of the two
    /// it is, so the distinction is load-bearing rather than decorative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_transcript: Option<Digest>,

    /// What this run cost. `None` on a record written before costs were measured, which is a third
    /// state and not a free run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub costs: Option<Costs>,

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
            transcript: None,
            network_transcript: None,
            costs: None,
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
