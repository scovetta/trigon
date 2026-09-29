# 01. Architecture

## 1. The pipeline

The pipeline has thirteen conceptual steps and **five persisted states**. Thirteen persisted
transitions multiplied by hundreds of thousands of artifacts multiplied by retries costs a great many
database writes and buys nothing.

```
Queued ──▶ Inferring ──▶ Building ──▶ Judging ──▶ Done
```

The fine-grained steps are **events on the run**. They double as the `Phase` enum used for
per-phase timings and for `failed_in`:

| Phase | What happens | Deterministic? |
|---|---|---|
| `Resolve` | Registry metadata to artifact URL, digest, declared repo, publish time, intrinsics | yes |
| `Decompose` | Fetch the upstream artifact, enumerate its members, emit the **guard manifest** (§1.2) | yes |
| `LocateSource` | Metadata, then provenance, then the tag ladder, then tree-hash match, then a model | AI-assisted |
| `InferStrategy` | Cache, then definitions, then CI-derived, then heuristic, then a model | AI-assisted |
| `Materialize` | Narrow git fetch at a pinned commit into the source cache | yes |
| `Build` | Container execution under a declared egress tier | bounded |
| `Extract` | Locate the produced artifact in the workspace | yes |
| `Stabilize` | Normalize both sides identically | yes |
| `Compare` | One pass, six digests, structured notes | yes |
| `Explain` | Classify remaining differences (deterministic rules, model fallback) | AI-assisted, advisory |
| `Attest` | Build in-toto statements, sign in a separate process | yes |
| `Publish` | Object store and metadata store, then an evidence repository with a log we sign ([`19`](19-distribution-and-lookup.md); planned) | yes |

```
                    ┌──────────────┐
   sweep planner ──▶│    Queued    │
                    └──────┬───────┘
                           │ lease (infer worker, network+AI, no build rights)
                    ┌──────▼───────┐
                    │  Inferring   │  Resolve · Decompose · LocateSource · InferStrategy · Materialize
                    └──────┬───────┘
                           │ strategy (data) + pinned source + guard manifest (digests only)
                    ┌──────▼───────┐
                    │   Building   │  Build · Extract      (build worker: egress-restricted,
                    └──────┬───────┘                        WRITE-ONLY blob access, cannot read
                           │ write-only, run-scoped        the upstream artifact from anywhere)
                    ┌──────▼───────┐
                    │   Judging    │  Stabilize · Compare · Explain   (cheap worker; reads both sides)
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │     Done     │  Attest · Publish     (separate attestor process, holds keys)
                    └──────────────┘
```

The worker split is a security control. **Judging runs on a different worker from building**,
because judging reads the upstream artifact and the build worker has to be unable to reach it. See
[`12-security.md`](12-security.md).

Two access rules make that separation real, and both are easy to lose in implementation:

- The build worker's blob-store credential is **write-only and scoped to `runs/<run-id>/`**. A
  read-write credential would let a build fetch the upstream artifact from *our own* content-addressed
  store by its digest, which travels with every target. That path never crosses the egress proxy, so
  the network guard would never see it.
- The **guard manifest carries digests, never bytes.** The infer worker holds the upstream artifact
  during `Decompose` and hands the build worker a set of hashes.

### 1.1 Idempotency

```
cache_key = H( target
             , upstream_artifact_digest
             , strategy_digest
             , base_image_digest
             , stabilizer_set_digest
             , comparator_digest )
```

The cache key says **what may be reused**. Re-enqueuing a target whose cache key already has a
terminal verdict is a no-op returning that verdict, and that is what makes repeated sweeps
affordable.

The cache key does **not** identify a run. Confirmation runs ([`07-ai.md`](07-ai.md) §3) execute the
same recipe on a different worker at a different time, so they share a cache key by construction. Run
identity is `(cache_key, Attempt)`, where `Attempt` carries an ordinal, a purpose, a worker and a
start time ([`02-domain-model.md`](02-domain-model.md) §7). Deduplication keys on the cache key and
respects the confirmation policy: a target that needs two agreeing attempts is not satisfied by one
cached attempt.

Concretely, the scheduler admits a new attempt when the cache key has no terminal verdict, or when it
has fewer agreeing attempts than the publication policy requires, or when an operator asked.

**As built** ([`19`](19-distribution-and-lookup.md) §10 phase 3), the key a run records is
`trigon_store::cache_key` over the target — its canonical purl and the artifact's name — the
strategy digest and the stabilizer-set digest, built by the run once it knows them, worker and CLI
alike. The upstream artifact's digest is held to instead where two attempts are compared: they agree
only on one agreement digest (`Comparison::agreement`), which covers the published artifact's raw
digest as well as both sides' stabilized digests, so attempts against different upstream bytes
disagree rather than confirm each other — even bytes the set makes one, such as a republished
tarball whose timestamps alone changed — and `rebuild --confirm` refuses a registry that now serves
other bytes before it builds. The base image and comparator digests are not in it.

A queue job's own key names the request — the target's canonical purl, `trigon_store::request_key`
— because nothing that enqueues knows the strategy. So **re-asking for a target is deduplicated by
the target alone**, whatever set or strategy it would now be judged under: a first attempt that is
on the queue, or done, answers a new request for it, and the scheduler does not yet admit a new
attempt because the set or the strategy changed. Whether the request key should carry something
that changes when they do is open ([`16`](16-findings.md) §3.97).

Two details matter:

- **`upstream_artifact_digest` belongs in the key.** crates.io is immutable. npm dist-tags and CDN
  content are not, and PyPI yank-and-reupload happens. Leave the digest out and you serve a cached "match" against a different upstream.
- **`stabilizer_set_digest` and `comparator_digest` are content digests.** A hand-bumped integer is a
  promise someone forgets to keep, and an out-of-band registry edit would then reuse cache entries
  that no longer apply.

### 1.2 The guard manifest

`Decompose` runs on the infer worker, between `Resolve` and `LocateSource`. It fetches the upstream
artifact once, enumerates its members, and emits a manifest that the sandbox's egress proxy and the
mirror both load before the build starts:

```rust
pub struct GuardManifest {
    pub artifact_digest: Digest,
    pub artifact_url: Url,               // the mirror refuses to serve this URL for this run
    pub guarded_members: Vec<GuardedMember>,   // filtered; see 12-security.md §2
}

pub struct GuardedMember { pub digest: Digest, pub path: EntryPath, pub bytes: u64 }
```

Three properties of that manifest matter:

- It exists **before** the build, which is why `Decompose` is its own phase rather than something the
  judge worker does after the fact.
- It carries **digests and paths, never bytes**, so handing it to a component adjacent to a hostile
  sandbox leaks nothing the attacker does not already hold.
- `guarded_members` is a **filtered** subset, not every member. The filters live in
  [`12-security.md`](12-security.md) §2, and without them the guard fires on every build that
  downloads an archive containing an empty file.

## 2. The crate graph

Eleven crates. Rust crate splits cost link time, force trait definitions downward, and create
`dyn` indirection at seams that would otherwise be plain calls. The one thing a crate boundary buys
over a module is **machine-checkable dependency policy**, so we split where we want to enforce a
policy and nowhere else.

```
                          trigon-core
                    (pure; serde + thiserror; ZERO cargo features)
                        /       |        \
          trigon-archive   trigon-strategy   trigon-attest
                 |          (minijinja)      (in-toto / DSSE / Signer)
         trigon-stabilize        |                  |
                 |               |                  |
          trigon-compare         |                  |
                  \              |                  |
 ══════════════════ JUDGEMENT ═══╪══ SEARCH ════════╪══════════════════
                   \             |                  |
    trigon-registry   trigon-ai   trigon-sandbox   trigon-store
          \______________|________|_________________/
                         |
                   trigon-engine
                         |
                      trigon (bin)
```

Everything above the line stays synchronous, with no tokio, no reqwest, and zero cargo features.

| Crate | Contents | Async? |
|---|---|---|
| `trigon-core` | PURL, `Target`, `Verdict`, `Match`, `Fault`, `Provenance`, `RiskTier`, the `Evidence` and `Claim` algebra | no |
| `trigon-archive` | mutable recursive archive model; hand-written tar/zip/gzip writers | no |
| `trigon-stabilize` | stabilizer registry, profiles, set digests | no |
| `trigon-compare` | one-pass multi-digest comparison, structural diff, diff report model | no |
| `trigon-strategy` | strategy schema, flow DSL, minijinja rendering to `Instructions` | no |
| `trigon-attest` | in-toto v1 + SLSA v1 statements, DSSE, JCS canonicalization, `Signer` | mixed |
| `trigon-registry` | per-ecosystem registry clients, source discovery, CI parsing, git cache | yes |
| `trigon-sandbox` | `BuildRunner`/`BuildHandle`, OCI and k8s adapters, egress proxy, observability | yes |
| `trigon-store` | `object_store` blobs, Postgres metadata, and the queue | yes |
| `trigon-ai` | `LlmProvider`, the Builder agent, budgets, transcripts, replay | yes |
| `trigon-politeness` | what we ask of an upstream host, and how fast: the process-wide limiter, the per-host counters, the one User-Agent | yes |
| `trigon-engine` | the state machine over the traits above | yes |
| `trigon` | One binary: `serve`, `work`, `verify`, `check`, `run`, `sweep`, `bench` | yes |

### 2.1 Why these boundaries and not others

**Merged, with reasons:**

- Registry, source discovery and CI parsing become **`trigon-registry`**. All three go read the
  internet about a package. They share an HTTP client, a cache, a rate limiter, and per-ecosystem
  inference logic. Splitting them means three trait objects to answer one question.
- Queue and store become **`trigon-store`**. `enqueue` and `record_state` have to happen in one
  `sqlx::Transaction`, a transactional outbox. Across a crate boundary both crates need `sqlx`
  anyway, so the boundary buys nothing and costs us the transaction.
- Worker, API, CLI and bench become **one binary with subcommands**. Four binaries mean four full
  dependency-tree links, and Rust does not link like Go.

**Split out, with reasons:**

- **`trigon-archive`** sits apart from `trigon-stabilize`. It churns at a different rate, it is the
  crate to fuzz in isolation, and `trigon-compare` walks archives to produce diffs without needing
  stabilizer rules.
- **`trigon-attest`** depends on `trigon-core`, `trigon-archive`, `trigon-compare` and
  `trigon-stabilize` — every crate above the line and nothing below it — so we can build `trigon verify` from
  `core + archive + stabilize + compare + attest` and nothing else.

### 2.2 The dependency policy, and how it is enforced

Four mechanisms, in descending order of value.

**(1) Provenance-capped outcomes.** This catches the failure mode we have: model-authored *data*
rather than model-calling *code*.

```rust
// trigon-compare
debug_assert!(
    outcome != Match::Normalized
    || applied.iter().all(|s| s.provenance == Provenance::Builtin && s.risk <= RiskTier::Metadata)
);
```

It is enforced exhaustively rather than by sampling: `trigon-compare/tests/seam_provenance_cap.rs`
enumerates every `RiskTier × Provenance × side` point, which is a proof over the domain where a
proptest would be evidence about the same points and strictly weaker. It makes a stronger and more
legible claim than any dependency graph, and it is what the attestation reports.

**(2) Ban the runtime rather than the crate.** Forbidding `tokio`, `reqwest` and `hyper` from
`trigon-stabilize`'s transitive tree cuts sharper than forbidding `trigon-ai`, because you cannot
call a model without one of them. `cargo-deny` expresses the direct case:

```toml
[[bans.deny]]
name = "reqwest"
wrappers = ["trigon-registry", "trigon-ai", "trigon-sandbox", "trigon-store", "trigon-engine", "trigon"]
```

`wrappers` constrains direct dependents only, so this rule needs the next one behind it.

**(3) An `xtask` policy test over the resolved graph.** This one does the enforcing. It shells
`cargo metadata --all-features --format-version 1`, builds the resolved dependency graph, and asserts
a declarative table:

```
forbid_transitive: trigon-stabilize -> { trigon-ai, tokio, reqwest, hyper, rustls, async-compression }
forbid_transitive: trigon-compare   -> { trigon-ai, tokio, reqwest }
forbid_transitive: trigon-strategy  -> { trigon-ai, trigon-registry, reqwest }
forbid_transitive: trigon-attest    -> { trigon-ai }
require_no_features: { trigon-core, trigon-archive, trigon-stabilize, trigon-compare }
allow_only:          trigon-engine  -> <explicit list>
```

`require_no_features` carries the weight. Judgement-half crates have zero cargo features, so
feature unification has nothing to leak in through. Run the whole thing under
`cargo-hack --feature-powerset` for the crates that do have features.

**(4) The claim a user can check.** Ship `trigon verify` built `--no-default-features`,
containing `core + archive + stabilize + compare + attest` and nothing else. It re-downloads both
artifacts and recomputes the outcome. Handing someone a 4 MB binary with no network client and no
model code that reproduces our verdict beats any diagram in a README.

## 3. Trait catalogue

### 3.1 Async and error conventions

**Async.** AFIT is stable, lacks `dyn` compatibility, and carries no `Send` bound. `trait_variant`
fixes `Send` and leaves `dyn` alone. The rule:

- Dyn-dispatched with a millisecond or more of I/O per call gets `#[async_trait]`. The box allocation
  is noise next to starting a container. That covers `Registry`, `BuildRunner`, `LlmProvider`,
  `Signer` and `Queue`.
- Pure and hot gets a sync trait, where `dyn` costs nothing worth counting. That covers `Stabilizer`,
  `Comparator` and `EcosystemSpec`.

**Errors.** No global `TrigonError`. Each crate gets `thiserror` enums, each dyn-safe trait owns
one concrete error enum with an `Other(#[source] anyhow::Error)` escape hatch, and nothing else
`anyhow`-shaped appears in a library signature. Every error maps into a classification that lives in
`trigon-core`:

```rust
pub enum Fault { Infra, Upstream, Build, Policy, Bug }
pub trait Classify { fn fault(&self) -> Fault; }
```

This generalizes the prior art's split between `FAILURE` and `ERROR`. Without it, every benchmark
denominator counts infrastructure faults as unreproducible packages.

### 3.2 The ecosystem seam, split three ways

A single `Ecosystem` trait bundling `resolve` (async, network) with `stabilizer_profile` (pure)
would force `trigon-stabilize` to depend on a crate that needs `reqwest` and `tokio`. The headline
invariant would die at the first trait we wrote. So we split it into three traits in three crates:

```rust
// trigon-core. Pure, sync, dyn-safe, depended on by everyone.
// NOT BUILT. See `docs/03-ecosystems.md` §7.2: no such trait exists. The dependency severance it
// describes is real and is achieved by `resolve_profile` naming a profile **id**; this shape was
// never written, and two source comments still cite it as though it had been.
pub trait EcosystemSpec: Send + Sync + 'static {
    fn id(&self) -> EcosystemId;
    fn artifact_kinds(&self) -> &'static [ArtifactKind];
    fn archive_format(&self, a: &ArtifactId) -> ArchiveFormat;

    /// Returns an identifier. That one word severs the dependency: the profile
    /// resolves against a registry that lives in trigon-stabilize.
    fn stabilizer_profile(&self, a: &ArtifactId) -> ProfileId;
}
```

```rust
// trigon-registry. Async, dyn-safe.
#[async_trait]
pub trait Registry: Send + Sync + 'static {
    fn id(&self) -> EcosystemId;
    async fn resolve(&self, t: &TargetRef) -> Result<ResolvedTarget, RegistryError>;
    async fn fetch_artifact(&self, a: &ArtifactId, sink: &mut dyn BlobSink)
        -> Result<ArtifactMeta, RegistryError>;
    async fn intrinsics(&self, r: &ResolvedTarget) -> Result<Intrinsics, RegistryError>;
    async fn enumerate_versions(&self, p: &PackageRef) -> Result<Vec<Version>, RegistryError>;
}
```

```rust
// trigon-registry AND trigon-ai both implement this.
#[async_trait]
pub trait StrategyInferrer: Send + Sync {
    fn id(&self) -> &'static str;
    async fn infer(&self, cx: &InferenceContext<'_>) -> Result<Vec<Candidate>, InferError>;
}

pub struct Candidate {
    pub strategy: Strategy,
    pub rationale: String,
    pub confidence: f32,
    pub provenance: Provenance,
}
```

Heuristic and model inferrers implement the **same** trait. The engine holds one ordered
`Vec<Arc<dyn StrategyInferrer>>` and contains no branch on whether a candidate came from a model,
which is what makes the escalation ladder in [`07-ai.md`](07-ai.md) configuration rather than control
flow.

### 3.3 `BuildRunner` and `BuildHandle`

```rust
#[async_trait]
pub trait BuildRunner: Send + Sync + 'static {
    fn caps(&self) -> RunnerCaps;                  // privileged? exec? egress modes; concurrency
    fn accepts(&self, p: &BuildPlan) -> bool;
    async fn start(&self, p: &BuildPlan, o: &RunOpts) -> Result<Box<dyn BuildHandle>, SandboxError>;
    async fn health(&self) -> RunnerHealth;
}

#[async_trait]
pub trait BuildHandle: Send + Sync {
    fn id(&self) -> &BuildId;
    fn events(&self) -> BoxStream<'static, BuildEvent>;
    async fn wait(self: Box<Self>) -> Result<BuildOutcome, SandboxError>;
    async fn cancel(&self) -> Result<(), SandboxError>;
    /// Only when caps().exec. Exploration environments only, never verification.
    async fn exec(&self, cmd: &[String]) -> Result<ExecOutput, SandboxError>;
}

pub enum BuildPlan { Oci(OciPlan), K8sJob(JobPlan), CloudBuild(GcbPlan) }

pub enum BuildEvent {
    PhaseStart(Phase), Stdout(Bytes), Stderr(Bytes), PhaseEnd(Phase, Duration), Exit(i32),
}
```

Three departures from the prior art's `Planner[T]`, `Executor` and `Handle`:

- **`BuildPlan` is a concrete enum rather than `any`.** The engine holds a heterogeneous
  `Vec<Box<dyn BuildRunner>>` and dispatches on `accepts()`. Go's generic `Planner[T]` cannot express
  that without reflection.
- **`events()` returns a stream rather than an `io.Reader`.** Phase timings, the bounded log tail the
  agent reads, and the blob-store tee all want the same data with structure. Teeing a single
  `AsyncRead` three ways in Rust hurts; a broadcast stream costs a few lines, and the log tail becomes
  a bounded ring buffer over events.
- **`wait(self: Box<Self>)` consumes the handle**, so a double wait fails to compile.

### 3.4 `Stabilizer`

```rust
// trigon-stabilize. Sync, no tokio, no reqwest, no features.
pub trait Stabilizer: Send + Sync + 'static {
    fn id(&self) -> StabilizerId;        // stable string; appears in the attestation
    fn stage(&self) -> Stage;            // Default = 0, Patch = 10, Finalize = 100
    fn risk(&self) -> RiskTier;          // Structural | Metadata | Content | Lossy
    fn provenance(&self) -> Provenance;  // Builtin | Human { reviewer } | Model { model_id, run_id }
    fn applies(&self, cx: &Cx) -> bool;

    fn on_archive(&self, _a: &mut Archive, _cx: &Cx) {}
    fn on_entry(&self, _e: &mut Entry, _cx: &Cx) {}
}

pub struct StabilizerSet { pub id: ProfileId, pub members: Vec<Arc<dyn Stabilizer>> }
impl StabilizerSet {
    /// Over sorted (id, stage, risk, provenance). Part of the run key.
    pub fn digest(&self) -> Digest { /* ... */ }
}
```

Four choices, each replacing machinery the prior art needed because Go lacks sum types:

- **Constraints fold into `applies()`.** The apparatus of `Constraint`, `Any`,
  `WithFns(map[Format]Fn)` and type-switch-on-function-kind collapses to two defaulted methods.
- **Both hooks carry defaults**, so one stabilizer can act at archive and entry level. The Go
  walker's `if archiveFn { … } else { for each entry { … } }` structure rules that out.
- **`risk()` and `provenance()` live on the trait**, so we derive the attestation predicate
  mechanically rather than from a side table someone forgets to update.
- **No `Result`.** Stabilizers are total. A parse failure falls back to the original bytes and emits
  a structured note. The prior art already works this way by convention, and making it a type-level
  guarantee rules out half-stabilized states. A fuzz target asserts that `apply` never panics.

### 3.5 The rest

| Trait | Crate | Shape | Detail |
|---|---|---|---|
| `Comparator` | `trigon-compare` | sync, dyn | per-format member comparison |
| `SourceFetcher` | `trigon-registry` | async, dyn | narrow fetch + source cache |
| `CiParser` | `trigon-registry` | sync, dyn | see [`06`](06-ci-awareness.md) |
| `LlmProvider` | `trigon-ai` | async, dyn | see [`07`](07-ai.md) §7 |
| `Queue` | `trigon-store` | async, dyn | own SQL; see [`10`](10-scale.md) §3 |
| `MetaStore` | `trigon-store` | async, dyn | Postgres, or SQLite locally |
| `Signer` | `trigon-attest` | async, dyn | see [`09`](09-attestations.md) §3 |

```rust
// trigon-compare. Sync, dyn-safe, no I/O.
pub trait Comparator: Send + Sync + 'static {
    fn id(&self) -> ComparatorId;
    fn applies(&self, kind: ContentKind, path: &EntryPath) -> bool;
    /// Compares two archive members. Total: an unparseable member compares by bytes.
    fn compare(&self, upstream: &[u8], rebuild: &[u8]) -> MemberComparison;
}

// trigon-registry
#[async_trait]
pub trait SourceFetcher: Send + Sync + 'static {
    /// Narrow fetch (blob:none, single-branch) at a pinned commit, via the shared cache.
    async fn materialize(&self, p: &SourceProvenance) -> Result<SourceTree, SourceError>;
    async fn metrics(&self, repo: &str) -> Result<RepoMetrics, SourceError>;
}

pub trait CiParser: Send + Sync + 'static {
    fn detects(&self, tree: &SourceTree) -> bool;          // .github/workflows, .gitlab-ci.yml, …
    fn parse(&self, tree: &SourceTree, t: &Target) -> Result<Vec<CiRecipe>, CiError>;
}

// trigon-store. Queue and MetaStore share a connection pool so enqueue and
// state writes land in ONE transaction (the outbox; see ADR-0005).
#[async_trait]
pub trait Queue: Send + Sync + 'static {
    async fn enqueue(&self, tx: &mut Tx<'_>, jobs: &[Job]) -> Result<usize, StoreError>;
    async fn lease(&self, c: &LeaseCriteria, n: usize) -> Result<Vec<Lease>, StoreError>;
    async fn heartbeat(&self, l: &LeaseId) -> Result<(), StoreError>;   // NOT on the queue table
    async fn complete(&self, tx: &mut Tx<'_>, l: LeaseId) -> Result<(), StoreError>;
    async fn abandon(&self, l: LeaseId, retryable: bool) -> Result<(), StoreError>;
}

#[async_trait]
pub trait MetaStore: Send + Sync + 'static {
    async fn begin(&self) -> Result<Tx<'_>, StoreError>;
    async fn upsert_run(&self, tx: &mut Tx<'_>, r: &Run) -> Result<(), StoreError>;
    async fn find_by_cache_key(&self, k: &CacheKey) -> Result<Vec<Run>, StoreError>;  // all attempts
    async fn record_verdict(&self, tx: &mut Tx<'_>, id: RunId, v: &Verdict) -> Result<(), StoreError>;
}
```

`Queue::heartbeat` stays off the queue table. Writing progress to the hot path would amplify
writes there ([`10-scale.md`](10-scale.md) §3).

Blob storage gets **no Trigon trait**. `object_store::ObjectStore` from arrow-rs already covers S3,
GCS, Azure, local filesystem and memory behind one mature interface. Wrapping it would add a layer
and subtract nothing.

`trigon plugins` lists every registered implementation of every seam, with its provenance and
version. That listing is what makes the extension story checkable rather than aspirational.

## 4. Out-of-tree extension (v2)

Deferred, with the shape decided so that v1 leaves room for it.

- **The WASM component model (`wasmtime` plus `wit-bindgen`) takes `Stabilizer` first.** A stabilizer
  makes an ideal WASM guest: untrusted, pure, total, deterministic, with no network and no
  filesystem. It is also the extension point most likely to attract outside contributions, and the
  one where sandboxing earns its keep, because a stabilizer participates in the signed digest.
- **`Comparator` and `EcosystemSpec::heuristic_strategies` follow**, being equally pure.
- **`BuildRunner` gets an out-of-process gRPC seam** rather than WASM, since it orchestrates I/O.
- **`Registry` stays in-tree.** It needs network, credentials, and rate-limit coordination, none of
  which cross a WASM boundary comfortably today.

## 5. Configuration

One `trigon.toml`, which `figment` assembles from file, environment, and CLI in that order.
`models.toml` sits apart because it changes on a different cadence, and it is the file an operator
edits to move a role between providers.

```toml
[storage]
blobs = "s3://trigon-blobs"          # or "file:///var/lib/trigon/blobs"
meta  = "postgres://…"               # or "sqlite:///var/lib/trigon/trigon.db"

[sandbox]
runner       = "podman"              # podman | docker | k8s | cloudbuild
default_egress = "mirror-only"
observability  = "tier1"             # tier0 | tier1 | tier2 | tier3

[mirrors]
npm   = "http://mirror.internal:8081/npm"
pypi  = "http://mirror.internal:8081/pypi"
images = "registry.internal/trigon"

[definitions]
repo = "https://github.com/trigon-dev/trigon-definitions"
ref  = "refs/heads/main"             # resolved to a SHA at startup; the SHA goes in the attestation

[limits]
build_timeout       = "45m"
max_artifact_bytes  = "4GiB"
recursion_limit     = 4
```

Any value that can affect a verdict, including the stabilizer set, the base image, the egress tier
and the definitions ref, resolves at startup, gets recorded on each run, and reappears in the
attestation. A configuration change that could alter a verdict therefore changes the run key.
