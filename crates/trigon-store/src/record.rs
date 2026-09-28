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
use trigon_core::{Digest, DigestCheck, FailureSignature, Sha1, Sha512};

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
    /// The digest of the guard manifest the mirror was armed with, where it was armed.
    ///
    /// The manifest itself is stored as a blob under this digest by every run recorded since
    /// `docs/19` §10 phase 2, so the digest names bytes a reader can fetch; it used to be left in
    /// the work directory and lost with it.
    ///
    /// **`None` means nobody looked, and that is why it is recorded rather than inferred.** The
    /// signed `artifactHashCheck` block derives `performed` from this field being present, so a
    /// record that omits it says the artifact guard never ran — which is what nineteen signed
    /// statements said about runs where it had. The predicate renderer was right and tested both
    /// ways; nothing asserted that a real run supplied the input, and it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_manifest: Option<String>,
    /// What this run built its base image from, where it built one.
    ///
    /// **`None` means this run derived nothing** — the operator named an image, or one already on
    /// the machine carried what the strategy needed. It is not "no image".
    ///
    /// This exists because `--image derive` spends network *outside* the boundary the rest of the
    /// record accounts for. At `mirror-only` the run's whole claim is that `network_transcript`
    /// is a complete account of what crossed into the build; an image `apt-get`-ed into existence
    /// ninety seconds earlier is bytes that account never saw. Recording it is what keeps the
    /// claim true — and what lets [`crate::publication`]'s gate withhold rather than publish a
    /// divergence, which is an accusation, from a run with an undisclosed step in it.
    ///
    /// Modelled on `non_builtin_stabilizer` below: a typed fact the run path writes down because
    /// the publication gate needs it and cannot compute it from anything else it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_image: Option<DerivedImage>,
    /// How many of the artifact's members the guard was watching for.
    ///
    /// Zero is a real answer and not the same as `None`: every member was too small, too common,
    /// or also present in the source, so the guard watched the artifact alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guarded_members: Option<u64>,
}

/// A base image this run built, and what went into it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedImage {
    /// The image it was built on, pinned.
    pub parent: String,
    /// What was installed onto the parent, sorted. The reader's answer to "why do these bytes
    /// differ from a stock distribution image".
    pub packages: Vec<String>,
    /// Whether **these bytes** were built by this run.
    ///
    /// `false` is a hit on the content-addressed tag: an earlier run derived the same parent and
    /// package set, and this one reused it. It does **not** say no network was spent — it says
    /// not by this run, and the earlier one may have recorded nothing at all. Anyone who needs
    /// the difference has `parent` and `packages` here, which are the tag's whole input.
    pub built_here: bool,
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

/// Every digest of the published bytes beyond `upstream.sha256`: what the run computed over them,
/// and what the registry declared and whether the bytes agreed.
///
/// **Computed, then declared, and never one standing in for the other.** `sha512` and `sha1` are
/// hashed from the bytes as they were fetched, and are what a statement's subject carries: a
/// consumer holding an npm lockfile has the sha512 and nothing else, and a subject that lacks it is
/// unfindable (`docs/19` §5). `declared` is what the registry claimed, which the fetch checked and
/// would have refused on a mismatch. Kept on the run rather than recomputed at attest time because
/// a run that reached no verdict does not keep the bytes, and its statement still needs a subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamDigests {
    pub sha512: Sha512,
    /// Only where the ecosystem publishes one, which is npm's `dist.shasum`: a lookup key there and
    /// nowhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<Sha1>,
    /// One entry per digest the registry declared, with the field it came from and what checking
    /// it found: `matched`, or `unchecked` for an algorithm this build cannot compute.
    ///
    /// **Written even when empty.** An empty list is a finding — the registry declared nothing —
    /// and `note` says so; a missing key would read as a record from before this field existed.
    #[serde(default)]
    pub declared: Vec<DigestCheck>,
    /// Why `declared` is empty, or which of it went unchecked, in words. `None` when every
    /// declaration was checked and held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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

/// One, so `attempt` can be `u32` rather than `Option<u32>`. See the field.
fn one() -> u32 {
    1
}

/// Everything one run produced, with the large parts left in the blob store.
///
/// Deliberately without `deny_unknown_fields`: a store holds run files written by every earlier
/// version, some carrying keys this struct has since dropped, and each must still read.
/// `tests/old_run_files.rs` holds one such file.
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
    /// Times the build asked for its own published artifact and the mirror refused it.
    ///
    /// **Deliberately not `guard_trips`.** Nothing arrived, so the run is not `Void` and stays
    /// evidence about the package — `is_evidence` keys on `guard_trips` and must keep doing so.
    /// Recorded because it is worth knowing the build asked, and because it usually explains
    /// whatever failed next: a package that is part of the machinery that builds packages makes
    /// the build ask for itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_artifact: Vec<String>,

    pub started: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,

    /// Which attempt at this exact piece of work this is, counting from 1.
    ///
    /// [ADR-0010]'s first safeguard is **two agreeing attempts before anything publishes**,
    /// divergences and matches alike, on different workers at different times — because one attempt
    /// cannot tell a deterministic recipe from a lucky one, and the risk that dominates is ambient
    /// nondeterminism rather than malice. Nothing could express that: every record looked like a
    /// first and only attempt, so the safeguard was enforced by nothing and
    /// `12-security.md`'s invariant 12 says so in that word.
    ///
    /// Defaulted to 1 rather than made optional. A record written before this field existed *was* a
    /// single attempt, so 1 is the fact and not a filler — and it is the value that leaves the gate
    /// correctly withholding, which an `Option` treated as "unknown, probably fine" would not.
    ///
    /// [ADR-0010]: ../../../docs/adr/0010-publish-divergences.md
    #[serde(default = "one")]
    pub attempt: u32,
    /// What makes two attempts attempts *at the same thing*.
    ///
    /// The target, the strategy digest and the stabilizer set: change any of them and the second
    /// run is a different question, not a confirmation of the first. `None` on a record written
    /// before the field existed, which the gate reads as unconfirmable rather than as confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_key: Option<String>,

    pub environment: Environment,
    /// The blob holding the strategy that ran, as canonical JSON (`trigon_core::jcs`): the digest
    /// of a file a reader can fetch, and what a published record binds its strategy evidence by
    /// (`docs/19` §4.2 item 7).
    ///
    /// **Not `strategy_digest`**, and the two must not be confused. This is the sha256 of the
    /// file's bytes; that one is a domain-separated hash over the canonical strategy *and every
    /// tool it reaches*, which is what a cache key needs and is the digest of no file. The field
    /// was declared long before anything wrote it — none of 371 stored runs had it — so `None`
    /// means a run recorded before `docs/19` §10 phase 2, or one that never chose a strategy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Digest>,
    /// `strategyDigest`: what a cache key is built from and what the `rebuild` statement's
    /// `internalParameters` names. See `strategy` above for why it is not a file digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_digest: Option<String>,
    /// The Trigon that ran the build: the crate version, and the git revision too if a build ever
    /// embeds one. None does today, so this is the version alone.
    ///
    /// Recorded because the only version signed anywhere was the *attestor's*, in `rebuild`, and a
    /// run attested by a later binary claimed that binary had built it (`docs/19` §4.2 item 3).
    /// `None` on a record written before the run kept it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigon_version: Option<String>,
    /// How the strategy was arrived at: `definition`, `heuristic`, `ci_derived`, `model_assisted`.
    /// A provenance fact beside the claim, never inside it (`docs/09` §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<String>,
    /// The repository, commit and subdirectory the artifact was rebuilt from, and which rung found
    /// the commit.
    ///
    /// A verdict is a statement about a published artifact **and a source**, and only the first
    /// half was recorded: the source lived inside the strategy blob, which the attestation does not
    /// even list among its byproducts, and how the commit was found lived on a terminal line.
    /// `SourceDiscovery::FuzzyTag` and `SourceDiscovery::RegistryCommit` are very different claims
    /// and were indistinguishable in every stored record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<trigon_core::SourceProvenance>,
    /// The rendered scripts the executor actually ran. Rendering happens once, at resolution time,
    /// so what ran is a stored artifact rather than something to be re-derived from a template and
    /// a context that may no longer exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<Digest>,

    pub upstream: ArtifactRef,
    /// The published artifact's other digests, and what its registry declared. See
    /// [`UpstreamDigests`].
    ///
    /// `None` on a record written before the fetch kept them, and on one whose fetch never
    /// finished, which are both "not known" and never "nothing declared": that is an empty
    /// `declared` with a note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_digests: Option<UpstreamDigests>,
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

    /// How a run ended when it ended **without a verdict**: `no-strategy`, `build-failed`,
    /// `void`, `failed`.
    ///
    /// Not `outcome`, which is what a *comparison* produced and must stay one of the four matches
    /// ([ADR-0002]). Not `failure` either: a `no-strategy` is a scope statement and not a failure,
    /// so it has no signature, and filing it under one would put "we do not build this ecosystem
    /// yet" in the same column as "this package does not build".
    ///
    /// Without it, every run that reached no verdict was indistinguishable from every other, and a
    /// corpus page could only report them as `unclassified` — which is the word for a failure whose
    /// cause nobody has named, not for one that was named and then dropped on the way to the store.
    ///
    /// `None` exactly where `outcome` is `Some`.
    ///
    /// [ADR-0002]: ../../../docs/adr/0002-four-match-outcomes.md
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,

    /// Why each rung that could have produced a strategy did not.
    ///
    /// The single most useful thing about a `no-strategy`, and it lived only in the work directory.
    /// A corpus with three thousand of these and no reasons is a corpus that can say the rate and
    /// not what to build next.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declines: Vec<String>,

    /// What the strategy had to assume to be usable at all, in the rung's own words.
    ///
    /// Carried because a verdict reached under three assumptions is a different claim from one
    /// reached under none, and the assumptions were visible on a terminal and nowhere else.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assumptions: Vec<String>,

    /// How much the derivation trusts itself: `strong`, `weak`. A provenance fact beside the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,

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
    /// Statements this run named in the per-target layout, set aside when it was attested again
    /// under its own id ([`crate::Store::record_attestations`]).
    ///
    /// Kept so the history is not lost, and **served by nothing**. A per-target path was shared by
    /// every run of the target, so what it holds now is whichever run attested last — 40 of the
    /// 93 in the local store were shared when this was measured — and neither a build observation
    /// nor an equivalence statement says which run it is about. Left in `attestations`, a re-attest
    /// went on serving another run's statements, possibly a withheld divergence, as this run's.
    /// Empty on every run that was never attested under both layouts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_target_attestations: Vec<String>,
    /// Whether any stabilizer that actually fired carried non-`Builtin` provenance.
    ///
    /// ADR-0010 safeguard 2's provenance clause needs this, and the fact lives in the comparison
    /// blob — which the publication gate's index does not fetch, and should not have to for every
    /// run on every refresh. So the run path, which has the `Comparison` in hand, writes the one
    /// bit down here.
    ///
    /// `None` is a record written before this field existed, and means **not known**, never "no".
    /// The gate treats it as an unevaluated safeguard rather than a cleared one.
    #[serde(default)]
    pub non_builtin_stabilizer: Option<bool>,

    /// What a model made of the diff, where one was configured and there was a diff to read.
    ///
    /// **An opinion, never a verdict** — the full rule is on [`trigon_core::DiffOpinion`]. The
    /// comparison outcome does not read it, the publication gate does not read it (`trigon-api`
    /// has the test), and it enters no signed statement. It exists for the reader triaging a
    /// corpus of divergences: "likely a banner timestamp" and "likely different logic" deserve
    /// different afternoons.
    ///
    /// `None` means no model, nothing to show, or the ask failed — never "the diff is fine".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_opinion: Option<trigon_core::DiffOpinion>,
}

impl RunRecord {
    /// What this run says about the package, in the vocabulary a lockfile check reports.
    ///
    /// **A guard trip outranks the comparison.** A build that reached the published artifact over
    /// the network may have reproduced it by copying it, so whatever the comparison concluded is
    /// not evidence — the run is unsupported, not divergent, and calling it divergent would be an
    /// accusation nobody established.
    ///
    /// Returns the reason alongside, because "we could not run this" is only useful with the
    /// because.
    pub fn status(&self) -> (trigon_core::Status, Option<String>) {
        use trigon_core::Status;
        if !self.guard_trips.is_empty() {
            return (
                Status::Unsupported,
                Some(format!(
                    "the build reached the published artifact over the network ({} trip(s)), so \
                     nothing it produced is evidence about the package",
                    self.guard_trips.len()
                )),
            );
        }
        match self.outcome.as_deref() {
            Some("exact") => (Status::Reproduced, Some("byte for byte".into())),
            Some("normalized") => (
                Status::Reproduced,
                Some("identical after stabilization".into()),
            ),
            Some("normalized_with_caveats") => (
                Status::Caveats,
                Some("identical after a stabilizer that is a judgement call".into()),
            ),
            Some("divergent") => (
                Status::Divergent,
                self.failure
                    .as_ref()
                    .map(|f| f.key())
                    .or_else(|| Some("the rebuild differs from what was published".into())),
            ),
            Some(other) => (Status::Unsupported, Some(other.to_string())),
            None => (
                Status::Unsupported,
                Some(
                    self.failure
                        .as_ref()
                        .map(|f| f.key())
                        .unwrap_or_else(|| "the run reached no verdict".into()),
                ),
            ),
        }
    }
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
            refused_artifact: Vec::new(),
            started: started.into(),
            finished: None,
            attempt: 1,
            cache_key: None,
            environment,
            strategy: None,
            strategy_digest: None,
            trigon_version: None,
            derivation: None,
            source: None,
            instructions: None,
            upstream,
            upstream_digests: None,
            rebuild: None,
            comparison: None,
            build_log: None,
            timings: Vec::new(),
            failure: None,
            terminal: None,
            declines: Vec::new(),
            assumptions: Vec::new(),
            confidence: None,
            transcript: None,
            network_transcript: None,
            costs: None,
            attestations: Vec::new(),
            per_target_attestations: Vec::new(),
            non_builtin_stabilizer: None,
            diff_opinion: None,
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
