# 02. Domain model

Everything here lives in `trigon-core`: pure types, `serde` and `thiserror` only, zero cargo
features. A type in this document that needs a network client to construct belongs in another crate.

## 1. Identifying things

```rust
/// A package coordinate. Wraps a PURL but keeps the parsed parts hot.
pub struct TargetRef {
    pub ecosystem: EcosystemId,
    pub namespace: Option<String>,   // npm scope, maven group, nuget is None
    pub name: String,
    pub version: Version,            // ecosystem-specific ordering, see §6
    pub qualifiers: BTreeMap<String, String>,
}

/// A specific artifact of a specific version. This is what a run is about.
pub struct Target {
    pub reference: TargetRef,
    pub artifact: ArtifactId,        // "left-pad-1.3.0.tgz", "cryptography-42.0.5-cp39-abi3-manylinux…whl"
}

pub struct ArtifactId(String);

pub enum ArtifactKind { Sdist, Wheel, Tarball, Crate, Gem, Nupkg, Jar, ReleaseAsset, SourceArchive }
```

`pkg:github/owner/repo@v1.2.3` is an ordinary target whose artifact is a release asset or the
source archive itself. The type system gives GitHub no special case.

```rust
pub struct SourceProvenance {
    pub repo_url: String,            // canonicalized
    pub commit: Oid,                 // always a resolved SHA, never a ref name
    pub ref_name: Option<String>,    // the tag or branch it came from, for humans
    pub subdir: Option<Utf8PathBuf>, // monorepo package directory
    pub how: SourceDiscovery,        // which rung of the ladder found it
}

pub enum SourceDiscovery {
    RegistryMetadata,        // package.json repository, .nuspec, project_urls
    PublishedProvenance,     // npm/PyPI/NuGet trusted-publishing attestation
    ExactTag, PrefixedTag, FuzzyTag,
    ManifestHistory,         // first commit where the manifest version changed
    TreeHashMatch,           // scored against the published sdist, see 07-ai.md §2
    Definition,              // a human said so
    ModelAssisted,
}
```

We record `SourceDiscovery` because it predicts a false result better than anything else we have.
A `TreeHashMatch` is strong evidence. A `FuzzyTag` on a repo with 4,000 tags is a coin flip.

## 2. Evidence, not decisions

The most consequential modelling choice in this document. The prior art derives the Cargo
toolchain version by clamping in sequence: start from the Rust release current a week before
publication, raise to the declared MSRV, apply an edition floor, apply a `Cargo.lock` version-header
floor, then narrow using structural fingerprints of the packaged manifest. Those steps are a set of
independent interval constraints wearing an imperative costume.

We model them as constraints:

```rust
pub struct Evidence {
    pub claim: Claim,
    pub confidence: Confidence,      // Certain | Strong | Weak
    pub source: &'static str,        // "cargo-manifest:pretty-arrays", "wheel:Generator", "gemspec:rubygems_version"
}

pub enum Claim {
    ToolchainRange { tool: ToolId, lo: Option<Version>, hi: Option<Version> },
    ToolchainExact { tool: ToolId, version: Version },
    BuildBackend(BackendId),                 // setuptools | flit | hatch | poetry | maturin …
    RegistryMomentIs(RegistryMoment),
    RepoIs(String),
    SubdirIs(Utf8PathBuf),
    PlatformIs(Platform),
    RequiresNetwork(bool),
}

pub struct Intrinsics {
    pub publish_time: Option<OffsetDateTime>,
    pub declared_repo: Option<String>,
    pub registry_moment: Option<RegistryMoment>,
    pub evidence: Vec<Evidence>,
}

pub enum RegistryMoment {
    Lockfile { digest: Digest },     // the build resolves nothing; see 08 §4.0
    Timestamp(OffsetDateTime),
    GitCommit(Oid),                  // crates.io-index commit satisfying the lockfile
}
```

Intersecting them is a pure function in `trigon-core`:

```rust
pub fn resolve_toolchain(tool: ToolId, ev: &[Evidence]) -> ToolchainResolution;

pub enum ToolchainResolution {
    Pinned(Version),
    Window { lo: Version, hi: Version, width: usize },
    Contradiction { conflicting: Vec<Evidence> },   // ← the signal to invoke a model
    Unconstrained,                                  // ← also the signal to invoke a model
}
```

Three payoffs:

1. **`Contradiction` and `Unconstrained` are the signals that escalate to a model.** Without the
   type, that escalation decision stays a heuristic somebody tunes by hand.
2. Every constraint gets its own unit test against a corpus. Whether the pretty-array fingerprint
   implies Cargo 1.60 or later becomes a test over 2,000 real crates rather than a belief.
3. The evidence list drops into the attestation as a byproduct, so a reader can see why we chose the
   toolchain we chose.

The prior art's equivalent of `RegistryMoment` is a URL string that downstream code sniffs for the
substrings `cargosparse` and `cargogitarchive`. An enum costs nothing and cannot be misread.

## 3. Strategy

[`04-strategies.md`](04-strategies.md) covers this in full. The shape:

```rust
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Strategy {
    LocationHint(LocationHint),   // repo and ref only. Seeds inference, cannot build.
    Flow(FlowStrategy),           // the normal case
    Manual(ManualStrategy),       // raw scripts. What a model emits. Lower trust tier.
    Prebuilt(PrebuiltStrategy),   // artifact copied from a declared, pinned upstream build
}

pub struct Instructions {
    pub location: SourceProvenance,
    pub source: Script,
    pub deps: Script,
    pub build: Script,
    pub output_path: Utf8PathBuf,
    pub requires: Requirements,
}

pub struct Requirements {
    pub system_deps: Vec<SystemDep>,
    pub privileged: bool,
    pub egress: EgressTier,
    pub platform: Platform,
}
```

`Strategy` is data. `Instructions` is a strategy rendered for one target and environment. The
executor consumes `Instructions` and never re-renders.

## 4. Verdicts

```rust
pub enum Verdict {
    Reproduced  { outcome: Match },
    Divergent   { differences: DifferenceSummary },
    Void        { reason: VoidReason },
    BuildFailed { phase: Phase, class: FailureClass },
    Unsupported { reason: UnsupportedReason },
    Error       { phase: Phase, retryable: bool },
}

pub enum Match { Exact, Normalized, NormalizedWithCaveats, Divergent }

pub enum VoidReason {
    /// The upstream artifact, or a substantial member of it, reached the sandbox.
    /// See 12-security.md §2 for the matching rules and the false-positive filters.
    UpstreamArtifactReachedSandbox { via: GuardChannel, matched: GuardMatch },
    EgressPolicyViolated { host: String },
    ObservabilityGapDuringBuild,
    CleanRunsDisagreed { runs: Vec<RunId> },
    OperatorVoided { note: String },
}

pub enum GuardChannel { Egress { host: String }, BlobStore, Mirror }

pub enum GuardMatch {
    WholeArtifact,
    Member { path: EntryPath, bytes: u64 },
}

pub enum UnsupportedReason {
    PlatformSpecificBinary { platform: Platform },   // a manylinux wheel we cannot host
    NoSourceDistribution,
    SourceUnavailable { repo: String, how: SourceLoss },
    ProprietaryToolchain { tool: String },
    RequiresSecret { name: String },
    EcosystemNotImplemented(EcosystemId),
    ArtifactTooLarge { bytes: u64 },
    NotSelected { policy: SelectionPolicyId },       // see §8.1
}

pub enum SourceLoss { RepoDeleted, RepoPrivate, RefMissing, HostUnreachable }

pub enum FailureClass {
    MissingToolchain, ToolchainVersionMismatch, LockfileMismatch,
    NetworkDenied, DependencyResolutionFailed,
    OutOfMemory, Timeout, NativeBuildFailed, TestFailure, Unclassified,
}
```

Four distinctions this taxonomy preserves:

- **`Divergent` is a finding. `Error` is an operational metric.** Conflate them and fleet numbers
  stop meaning anything. The prior art keeps this split. OSSGadget collapses everything into a
  boolean plus a hard-coded score table.
- **`Unsupported` states scope.** Its rate tells us where the roadmap should go next.
- **`Void` sits outside pass and fail.** A run where the upstream artifact reached the sandbox
  proves nothing in either direction, and neither does a pair of attempts that disagreed. `Void`
  anchors the security model ([`12-security.md`](12-security.md)), and it never publishes as a
  divergence.
- **`FailureClass` is the caching key for build repair** ([`07-ai.md`](07-ai.md) §3). A normalized
  failure signature covering thousands of packages costs one model call.

Every error type also implements `Classify`:

```rust
pub enum Fault { Infra, Upstream, Build, Policy, Bug }
pub trait Classify { fn fault(&self) -> Fault; }
```

`Fault::Infra` stays out of the reproduction rate. `Fault::Bug` pages someone.

## 5. Comparison

```rust
pub struct Comparison {
    pub outcome: Match,
    pub upstream: MultiDigest,
    pub rebuild: MultiDigest,
    pub upstream_stabilized: MultiDigest,
    pub rebuild_stabilized: MultiDigest,
    /// Digest of the decompressed container stream, taken before any stabilizer runs.
    /// Present only for a compressed container (.tgz, .crate, .gem). Six digests per
    /// comparison, three per side, all from one pass. See 05 §4.2.
    pub upstream_container: Option<MultiDigest>,
    pub rebuild_container: Option<MultiDigest>,
    pub stabilizer_set: (ProfileId, Digest),
    pub applied: Vec<AppliedStabilizer>,
    pub notes: Vec<Note>,
}

impl Comparison {
    /// "same tar, different gzip framing": the most common near-miss for .crate/.tgz/.gem.
    pub fn container_bit_identical(&self) -> Option<bool> {
        Some(self.upstream_container.as_ref()? == self.rebuild_container.as_ref()?)
    }
}

pub struct AppliedStabilizer {
    pub id: StabilizerId,
    pub risk: RiskTier,
    pub provenance: Provenance,
    pub entries_touched: u32,
    pub bytes_changed: u64,
}

pub struct Note { pub code: NoteCode, pub path: Option<EntryPath>, pub detail: String }

pub enum NoteCode {
    NestedParseFailed, RecursionLimitReached, SpilledToDisk,
    DuplicateEntryPath,                // count; sort ties break on parse order
    MalformedEntry,                    // e.g. a symlink carrying a body
    UnknownEntryKind,                  // unrecognized tar typeflag, passed through
    LongNameReencoded,                 // GNU long name in, PAX long name out
    MemberOnlyInUpstream, MemberOnlyInRebuild, MemberContentDiffers,
    ExecutableContentDiffers,          // never benign
    CustomStabilizerTouchedExecutable, // flagged in the UI and the attestation
}

/// SHA-256 always. SHA-512 alongside it on the two raw artifact digests only,
/// because those are the values a third party cross-checks against a registry,
/// and registries publish both. Container and stabilized digests are SHA-256
/// alone: they are ours, nobody else publishes them, and doubling them doubles
/// the hashing cost of the hottest loop in the system.
pub struct MultiDigest { pub sha256: Digest, pub sha512: Option<Sha512> }

pub enum RiskTier { Structural, Metadata, Content, Lossy }
pub enum Provenance { Builtin, Human { reviewer: String }, Model { model_id: String, run_id: RunId } }
```

`entries_touched` and `bytes_changed` cost nothing, since they fall out of the dirty bits the
walker already sets, and they are the triage numbers people reach for. "`wheel-record-v2` touched
412 entries" is a diagnosis. A pass rate is a statistic.

The invariant from [`00-overview.md`](00-overview.md) §3.1 becomes a function over this struct:

```rust
impl Comparison {
    pub fn provenance_capped(&self) -> Match {
        let clean = self.applied.iter()
            .all(|a| a.provenance == Provenance::Builtin && a.risk <= RiskTier::Metadata);
        match (self.outcome, clean) {
            (Match::Normalized, false) => Match::NormalizedWithCaveats,
            (other, _) => other,
        }
    }
}
```

`Match` carries an ordering for policy convenience and **serializes as a string**. Ordinals in wire
formats trap you: a downstream policy engine writes `rung <= 3`, and from then on you cannot insert a
rung.

```rust
impl Match { pub fn is_at_least(self, floor: Match) -> bool { /* … */ } }
```

## 6. Versions

No single version algebra covers the six ecosystems. `semver` is Cargo-flavoured and rejects valid
npm and PyPI versions. `pep440_rs` handles Python and nothing else. RubyGems and NuGet have no usable
Rust crate.

```rust
pub trait VersionOrd {
    fn parse(&self, s: &str) -> Result<Version, VersionError>;
    fn cmp(&self, a: &Version, b: &Version) -> Ordering;
    fn is_prerelease(&self, v: &Version) -> bool;
    fn satisfies(&self, v: &Version, range: &str) -> Result<bool, VersionError>;
}
```

We ship four implementations: Cargo semver, PEP 440, node-semver, and hand-rolled RubyGems (about
200 lines) plus NuGet range parsing. The `cmp_version` template filter in
[`04-strategies.md`](04-strategies.md) **dispatches by ecosystem**. Write it as one function and the
bug surfaces on the packages you care about least.

> **As built: none of this exists.** There is no `VersionOrd` trait and no `cmp_version` filter, in
> code or in the definitions. The workspace holds exactly one version comparator — a private
> dot-separated `Vec<u64>` parse in `trigon-core/src/evidence.rs`, used only by `resolve_toolchain`
> — because nothing outside that function compares versions at all. The per-ecosystem dispatch
> above is a design claim about RubyGems and NuGet, and the first ecosystem that needs it is the
> first one that will write it. Recorded rather than deleted: the reasoning still holds, and a
> reader should not have to grep to find out which half is real.

## 7. Runs, phases, timings, costs

```rust
pub struct Run {
    pub id: RunId,
    pub cache_key: CacheKey,         // what may be reused: 01-architecture.md §1.1
    pub attempt: Attempt,            // what makes this run distinct from its siblings
    pub target: Target,
    pub sweep: Option<SweepId>,
    pub state: RunState,             // Queued | Inferring | Building | Judging | Done
    pub verdict: Option<Verdict>,
    pub strategy: Option<Strategy>,
    pub derivation: Derivation,
    pub source: Option<SourceProvenance>,
    pub environment: EnvironmentDescriptor,
    pub timings: Timings,
    pub costs: Costs,
    pub events: Vec<RunEvent>,       // append-only, blob-backed beyond a threshold
}

/// Two runs of the same recipe share a CacheKey and differ in Attempt. Deduplication
/// keys on CacheKey; the confirmation policy in 07 §3 counts Attempts.
pub struct Attempt {
    pub ordinal: u8,                 // 0 = first, 1 = confirmation, …
    pub purpose: AttemptPurpose,
    pub worker: WorkerId,
    pub started: OffsetDateTime,
}

pub enum AttemptPurpose { Initial, Confirmation, OperatorRequested, EvalReplay }

pub enum Derivation { Cached, Definitions { repo_ref: Oid }, CiDerived, Heuristic, ModelAssisted { transcript: Digest } }
```

### 7.1 Timings, nullable on purpose

```rust
pub struct Timings {
    pub setup:  Option<Duration>,
    pub source: Option<Duration>,
    pub deps:   Option<Duration>,
    pub build:  Option<Duration>,
    pub judge:  Option<Duration>,
    pub failed_in: Option<Phase>,
}
```

`None` means **no data**, never zero. A zero-valued duration for a phase that never ran poisons
every percentile you compute, and you will not notice, because the numbers still look plausible.
`failed_in` lets us drop a failed phase's partial span from clean-duration estimates. That span is a
lower bound under timeout or kill, so it never measures completion. An absent `failed_in` also fails
to prove that every phase finished.

### 7.2 Costs

```rust
pub struct Costs {
    pub inference_seconds: Option<f64>,
    pub tokens: Vec<Tokens>,          // one per model used; never summed across models
    pub build_seconds: Option<f64>,
    pub egress_bytes: Option<u64>,
    pub blob_bytes: Option<u64>,      // everything this run wrote
    pub artifact_bytes: Option<u64>,  // a subset of blob_bytes
    pub log_bytes: Option<u64>,       // ditto
}

pub struct Tokens {
    pub input: u64, pub cached_input: u64, pub output: u64,
    pub model: String, pub calls: u32,
}
```

`cached_input` is a **subset** of `input`, matching the prior art's schema so their published cost
data stays comparable with ours. `tokens` holds a vector rather than a sum, because adding token
counts across models with different prices produces a number that means nothing. The prior art panics
rather than allow it, and we follow them.

**Every field is `Option`, and `None` means no data — never zero.** The same rule the phase timings
keep, for the same reason: a run that asked no model and a run whose token counts we failed to read
are different facts, and averaging the second as zero understates every figure built on top of it.
The figures built on top of it are what decide where money goes.

Three of these are measured rather than estimated, and it is worth saying by what:

- `inference_seconds` is timed **around the provider call alone**, inside the counting wrapper, so
  it is comparable with `build_seconds`. A rung that reads a repository and then asks a question
  must not bill the reading as inference.
- `build_seconds` sums only the phases we have a reading for, dropping the rest instead of counting
  them as zero, so it is a floor and never an overstatement.
- `egress_bytes` comes straight off the **network transcript** ([`08`](08-execution.md) §7.2). Before
  that existed this number could only be guessed at, and `None` versus `Some(0)` carries the same
  distinction the transcript does: no account, versus a complete account of nothing.

`container_bytes` is not recorded: nothing measures image-layer growth per run, and a field nobody
fills is worse than a field that is not there.

**What is deliberately absent: prices.** No currency, no per-model rate table, no dollar figure. The
unit that matters is `$` per *verdict gained* rather than per target ([`07-ai.md`](07-ai.md) §5), and
that division needs a denominator a single run cannot see. A price table baked into a run record is
wrong within a quarter and silently rewrites history when it is corrected, so the record stores the
numerator and the reporting layer does the arithmetic.

We track repository-level cost separately, because a handful of monorepos dominate clone expense
and thousands of targets share them:

```rust
pub struct RepoMetrics { pub uri: String, pub bytes: u64, pub commits: u64, pub head: Oid, pub measured_at: OffsetDateTime }
```

### 7.3 Environment descriptor

Everything that could change a verdict, enumerated. Whatever we leave off this list becomes a
hidden input, and a hidden input flips a verdict one day for no visible reason.

```rust
pub struct EnvironmentDescriptor {
    pub base_image: ImageDigest,
    pub runner: RunnerId,
    pub isolation: IsolationClass,     // Container | UserNs | Gvisor | Kata | Vm
    pub egress: EgressTier,
    pub observability: ObservabilityTier,
    pub registry_moment: Option<RegistryMoment>,
    pub source_date_epoch: Option<i64>,
    pub locale: String,
    pub timezone: String,
    pub umask: u32,
    pub arch: Arch,
    pub kernel: Option<String>,
    pub toolchains: BTreeMap<ToolId, Version>,
}
```

## 8. Sweeps and package sets

```rust
pub struct Sweep {
    pub id: SweepId,
    pub package_set: PackageSetRef,   // name + canonical content hash
    pub priority: Tier,               // Interactive | Regression | Bulk
    pub budget: Budget,               // { usd_cap, token_cap, build_seconds_cap }
    pub egress_ceiling: EgressTier,
    pub created: OffsetDateTime,
}

pub struct PackageSet { pub metadata: PackageSetMeta, pub packages: Vec<PackageEntry> }
impl PackageSet {
    /// Canonical: sorted "ecosystem|name|version" joined by "|", then SHA-256.
    pub fn content_hash(&self) -> Digest;
}
```

We record the content hash on **every** run. Without it you cannot tell an improvement from a
corpus edit, so "reproduction rate went up" means nothing. The prior art does this, and copying it
costs a hash.

### 8.1 From packages to artifacts

A package set counts **packages**. A run verifies **one artifact**. The expansion between them
decides the size of a sweep, and it is large: `cryptography@42.0.5` publishes an sdist plus roughly
twenty wheels, and a naive expansion of a 100k-package set produces several hundred thousand runs.
Every figure in [`10-scale.md`](10-scale.md) counts artifacts for this reason.

```rust
pub struct SelectionPolicy {
    pub id: SelectionPolicyId,       // named, versioned, recorded on the sweep
    pub rules: Vec<SelectionRule>,
}

pub enum SelectionRule {
    AlwaysSourceDistribution,        // sdist, .crate, source .gem: cheapest and most informative
    PlatformMatched { hostable: Vec<Platform> },   // manylinux we can run; skip macOS and Windows
    PureArtifactsOnly,               // py3-none-any and equivalents
    FirstOfEachAbi,                  // one wheel per abi tag rather than every cp3x variant
    All,                             // opt-in, for a small corpus
}
```

The default policy for a bulk sweep is `AlwaysSourceDistribution + PureArtifactsOnly +
PlatformMatched { hostable }`. Artifacts the policy skips produce no runs. They record
`Unsupported { NotSelected { policy } }` against the target, so the coverage denominator stays
honest and the UI shows *not checked* rather than a blank cell.

The policy id travels on the sweep and into every attestation's target block, so two sweeps run under
different expansion policies stay comparable.
