# 13. Roadmap

## 1. Sequencing principle

**Build the judgement half first, alone, with no AI and no sandbox.**

Section 3 gives the reasoning: the stabilized digest is a pure function of a hand-written
serialization stack, and it is the value we sign. We can replace everything else in the system, and
not that. So it gets built first, tested hardest, and frozen earliest.

The second principle is **depth before breadth**: npm and PyPI to a high standard before adding
ecosystems. Going breadth-first would exercise the extension seam harder and leave every ecosystem
mediocre for longer, and a rebuild verifier that is mediocre everywhere helps nobody.

## 2. Milestones

### M0. The judgement half (2 to 3 weeks)

**Crates:** `trigon-core`, `trigon-archive`, `trigon-stabilize`, `trigon-compare`, and a `trigon
verify` binary.

Compare two local artifacts and produce a verdict plus a diff report, with no builds, no AI, no
queue, and no network beyond fetching an artifact by URL.

**Exit criteria:**

- [ ] **The M0 corpus exists**, 3,000 to 5,000 artifacts pinned by digest across the five
      ecosystems, with a fetch script and a manifest ([`15-corpora.md`](15-corpora.md)). This sits on
      the critical path, because the headline criterion below depends on it.
      **Partly. 58 artifacts, selected rarest-stratum-first from a scan of 526.** Three strata that
      section calls the point (duplicate paths, non-regular entries, non-UTF-8 names) turned up zero
      instances in 526 artifacts and are covered by hand-built fixtures rather than by the corpus.
      Closing this is a longer scan, not new code.
- [x] **Differential corpus test against the Go implementation passes.** The harness is the prior
      art's own `cmd/stabilize`, which is `go install`-able and takes `--enable-passes` and
      `--disable-passes`, so a mismatch localizes to one stabilizer rather than to the pipeline. The
      criterion is **stabilized-digest equality except a checked-in deviation list**, because the
      deviations are intentional ([`05`](05-archive-and-normalization.md) §6). An unexplained
      difference fails the build.
      **34 of 58 byte-identical, 24 covered by a listed deviation, 0 unexplained.** Attribution is
      by difference code rather than by filename, so a new artifact differing for a new reason stays
      unexplained however many of its siblings are exempt.
- [x] **The deviation list exists as a reviewed file**, each row carrying a test and a sentence.
- [x] **Regold works**, with a review artifact showing how many digests moved and which stabilizer
      moved them. Without it, the first stabilizer change deletes the corpus test.
      `xtask golden --write --reason` and a golden file per corpus.
- [x] `stabilize(stabilize(x)) == stabilize(x)` holds as a proptest.
- [x] `parse(write(a)) == a` holds as a proptest.
- [x] Byte-identical output across runs and across threads.
- [x] `cargo-fuzz` clean on `parse` and on `parse -> stabilize -> write -> parse`, with limits
      respected. About 62,000 runs seeded from the corpus, no crashes and no property violations
      ([`fuzz/README.md`](../fuzz/README.md)). The useful version of this runs for hours on a
      schedule rather than five minutes by hand.
- [x] The `xtask` dependency-policy test is in CI and fails a deliberate violation. Two negative
      tests hand the checker rules that must fail, so it cannot pass by finding nothing.
- [x] `trigon verify` builds with `--no-default-features` and links no network client or model code.
      The `build` feature is on by default and gates `trigon-sandbox` and `tokio`; without it the
      binary resolves 125 crates against 175 and none of them is a runtime or a network client.
      Enforced by the `xtask` policy check, which resolves that build separately rather than walking
      the default graph, and by the `verifier` CI job.

This milestone retires the project's risk, so over-invest in it.

### M1. First rebuilds (3 to 4 weeks)

**Adds:** `trigon-strategy`, `trigon-sandbox` (Podman only), the time-filtered registry, and
`trigon run --strategy build.yaml`.

The time-filtered registry is in and serves npm and PyPI. Real `pip` and real `npm` resolve through
it, and a rebuild of `left-pad@1.3.0` with `--timewarp auto` withheld 1,048 versions across 70 index
requests and still matched. What remains before a run at that tier can be *signed* is enforcement:
the runner still offers `open` egress rather than `mirror-only`, because nothing yet stops a build
reaching past the mirror.

**Exit criteria:**

M1 needs **two** corpora, and conflating them was a mistake in an earlier draft.

- [~] **The DSL corpus: the prior art's `definitions/`, imported verbatim.** 53 files, and the
      distribution matters: 51 PyPI, 1 npm, 1 maven. These are overrides written for packages where
      *inference failed*, so they are the pathological tail. They exercise the flow DSL, the template
      engine, the named-tool registry and `custom_stabilizers` harder than anything we would write,
      and they say nothing about the common path. Executing them validates the DSL. Nothing more.
      **All 53 import; 51 render to scripts, 1 is location-only, 1 is maven and refused by name.**
      Rendering is not executing: there is no sandbox yet, so what this currently validates is the
      schema, the lowering, the tool registry and the template engine. The `custom_stabilizers` on
      four of them are carried and printed, not applied, so those four cannot match until they are.
- [~] **The common-path corpus: 400 targets sampled by prevalence**, 200 npm and 200 PyPI, stratified
      by build system rather than by popularity alone ([`15-corpora.md`](15-corpora.md) §3). This is
      what a reproduction rate can be quoted from, and it is the number M1 reports.
      **Both corpora exist and 300 of the 400 have been run** — 150 from each, sampled
      proportionally across the strata rather than taken from the head, because the strata are
      contiguous in the files and a head-150 contains no TypeScript, monorepo, poetry or
      native-extension target at all.

      | | compared | reproduced | |
      |---|---:|---:|---|
      | npm | 85 of 150 | 64 | 75% |
      | PyPI | 122 of 150 | 103 | 84% |

      **Neither is yet the number M1 reports, and the npm one is not a fact about npm.** 48 of
      npm's 62 failures were ours: 23 `trigon/mirror-refused-unfiltered` (since fixed — a build
      resolving from a lockfile asked for no packument, so the mirror's offered-set gate refused
      every tarball), 13 more across `net/unreachable`, `env/missing-tool` and what was then called
      `trigon/mirror-corrupted-artifact` — npm 7.0 through 8.2 corrupting the tarballs it fetches
      concurrently, since fixed by serializing that range. PyPI is the honest half: 9 failures ours,
      8 the packages'.

      What M1 needs before quoting a rate is the remaining 100 targets, a re-run on current code,
      and the per-stratum breakdown — an aggregate that hides a bad native-extension or monorepo
      rate is what the stratification exists to prevent.
- [x] `trigon rebuild pkg:npm/left-pad@1.3.0` works on a laptop with Podman and no cloud account.
      Resolve, infer, fetch, build, compare, in one command. Reported `normalized`, with all ten
      members identical, against what npm published in 2018.
- [~] npm and PyPI end-to-end with heuristic and CI-derived strategies only, **with no AI involved**.
      **npm, yes.** The registry records the commit it published from and the Node and npm versions
      the publisher used, so npm inference is a transcription rather than a guess. **PyPI is
      weaker**: no commit is recorded, so the rung resolves a tag and assumes the build requirements,
      and it declines when no tag matches. No CI-derived rung yet, which is what would supply the
      toolchain PyPI does not record.
- [ ] The `smoke` benchmark corpus (~50 targets) is green and runs in under ten minutes.
- [x] Per-phase timings and costs recorded, with `None` meaning "no data". `Costs` carries
      `inference_seconds` (timed around the provider call alone, so it is comparable with
      `build_seconds`), tokens per model and never summed across them, `build_seconds` summing only
      the phases that were read, `egress_bytes` straight off the network transcript, and the blob
      totals. Every field is `Option` and `None` is no data rather than zero. No prices: `$` per
      *verdict gained* needs a denominator one run cannot see, and a rate table baked into a record
      rewrites history when it is corrected.

**The artifact-hash check is in**, ahead of its milestone, because the egress work made it cheap:
everything a build fetches now crosses one process. Both controls from
[`12-security.md`](12-security.md) §2 are live and tested against the real registry. The run outcome
`Void` exists and is reported, and all four member filters are in. The one that is not automatic is
also-in-source: it needs a checkout, which `--source` supplies and which a sweep has no per-target
equivalent of until the source cache exists. Without it the guard is wider than designed, which errs
toward voiding an honest run rather than missing a forged one.

### M2. Attestations (2 weeks) — complete

**Adds:** `trigon-attest`, `trigon-store`.

`trigon-store` is scoped here to what makes the attestor separable: content-addressed blobs and run
records, in the layout [`09`](09-attestations.md) §7 already specifies. The Postgres tables of
[`10`](10-scale.md) §4 — `runs`, `verdicts`, `rollups` — exist to make a *fleet* legible, and none of
them is needed to sign a statement; building that schema before there is a fleet to put in it means
maintaining one whose shape is a guess. It arrives with M4.

**Exit criteria:**

- [x] `equivalence/v1`, `divergence/v1`, `rebuild/v1` and `buildobservation/v1` emitted,
      DSSE-wrapped over RFC 8785 canonical bytes. A conformant SLSA Provenance v1 statement remains:
      `rebuild/v1` already carries the SLSA shape but not the predicate type, and claiming
      conformance is worth doing only against the conformance suite.
- [x] Signing works unsigned and with a local ed25519 key, with `trigon keygen` to make one.
- [x] ~~Statements publish to a Rekor transparency log, and the log's signed entry timestamp
      verifies offline in the `--no-default-features` verifier.~~ Built, measured against staging,
      and removed by [ADR-0014](adr/0014-git-evidence-store-without-rekor.md): Rekor could not hold
      what a published record has to carry, served divergences where we cannot correct them, and
      its successor cannot take our signatures ([`16`](16-findings.md) §3.92). Publishing is now
      [`19-distribution-and-lookup.md`](19-distribution-and-lookup.md), an evidence repository with
      a log of our own, and is planned rather than built.
- [ ] A certificate chain to a pinned root — [B21](17-backlog.md) steps 4-5 — or key epochs sealed
      in the evidence log instead, as docs/19 D6 decides. Either bounds a stolen key, which nothing
      does today. **Sigstore keyless is not planned**;
      [ADR-0011](adr/0011-keyed-signing-under-a-trusted-root.md) has the reasoning.
- [x] The attestor runs as a separate process and **re-derives the claim before signing**.
      `trigon attest` reads a store written by `trigon rebuild --store`, fetches every blob **by
      hash and checks it against that hash**, recomputes the claim from the artifact bytes, and
      refuses in three cases: a record that disagrees with the comparison it points at, a
      re-derivation that does not hold, and a blob whose content no longer matches its address. A
      void run — which it used to refuse outright — is signed as `void/v1` and nothing else, never
      as a verdict ([`19`](19-distribution-and-lookup.md) §4.3). It runs no build and opens no
      socket.
- [x] **`trigon verify-attestation --rerun-comparison`** re-derives the claim from the bundle and
      two files, with no network and no trust in the producer — including from a checkout that
      shares no state with the producer. `scripts/cross-machine-verify.sh` runs it: a fresh clone, a
      separate target directory, a `--no-default-features` build whose tree contains no runtime and
      no network client, four files handed over, and the network taken away with `unshare -rn`. It
      also requires an overstated outcome, an edited payload and a substituted artifact each to be
      caught, and each for its own reason — a verifier that printed "the claim holds"
      unconditionally would pass the positive case alone.
- [x] `trigon verify` refuses to compare across differing stabilizer-set digests
      (`AttestError::SetMismatch`), and re-derivation checks the **raw** digests as well as the
      stabilized ones — two artifacts that stabilize alike are the normal case, so the stabilized
      check alone would accept a substituted artifact as proof of the claim.
- [x] **Stabilizer sets publish as content-addressed artifacts**, and `--rerun-comparison` loads the
      set named in the attestation rather than the one in the binary ([`09`](09-attestations.md)
      §7.1). Two forms: a self-verifying JSON manifest that says what a set *was*, and a WebAssembly
      module that *runs* it. A parity test asserts the module and the native build produce identical
      bytes and identical set digests for every profile.

      Shipped as a **core module** rather than a component, and an archived set can reach
      `NormalizedWithCaveats` but not `Normalized`, because the provenance cap cannot be confirmed
      from bytes alone. Both are recorded in [`16-findings.md`](16-findings.md) §4b.

### M3. The AI subsystem (4 weeks)

**Adds:** `trigon-ai`, holding Resolver, Builder and Explainer, with budgets, generalizing caches,
transcripts, replay, and the three-tier eval harness.

**Sequencing note, from implementation.** The crate begins with the parts that are *deterministic*,
before any provider or prompt exists, because they are what decides whether the subsystem costs
thousands of dollars or hundreds of thousands for the same work — and because each of them is a unit
test rather than an evaluation run:

- `trigon_core::FailureSignature` names a failure so that every run sharing the cause shares the
  name. It is simultaneously the repair cache key, the admission-control input and the cluster id;
  key the cache on the target instead and every sibling misses.
- `trigon_core::compress` cuts a build log to what a model needs to read — the largest single cost
  lever in §4.2, worth about 7× on its own.
- `trigon_ai::RepairLoop` decides whether to spend anything at all: stop on a repeated signature
  rather than an iteration count, escalate on progress rather than frustration, and refuse a
  signature nobody has ever repaired.

Only then the provider abstraction and the Builder, because a Builder without these is the
$168,000 configuration.

**Exit criteria:**

- [x] The deterministic half: failure signatures, log compression, and the repair-loop policy, each
      testable with no provider configured.
- [x] The provider seam and the Builder, with a replay provider that makes no call. The prompt is a
      list of parts with a cache breakpoint rather than a string, because cache-read rate is an SLO
      whose failure is invisible: the calls succeed and the bill is several times larger.
- [ ] A live provider. Anthropic and one OpenAI-compatible endpoint.
- [ ] The deterministic rungs that lower the model-invocation rate before any model is configured.
      Two are already done and measured — pinning the build backend a wheel names, and removing a
      system package that was breaking every npm build — and together they moved PyPI from 33% to
      80% and npm from 13 of 20 to 15 of 20 reaching a comparison, with no model involved
      ([`16-findings.md`](16-findings.md) §2).
- [ ] Measurable lift on the `regression` corpus versus M1's heuristics-only baseline.
- [ ] **Model-invocation rate trends down** across the milestone as the flywheel produces rules.
- [ ] At least one repair promoted into a merged corpus-wide rule, with its impact preview.
- [ ] Replay reproduces a recorded run with zero model calls.
- [ ] Both the Anthropic and OpenAI-compatible providers work; a fully local configuration
      (Ollama or vLLM) completes the `smoke` corpus.
- [ ] The `trivial-deterministic` label shows **zero** model invocations.

### M4. Fleet (4 weeks)

**Adds:** the queue, worker classes, the API, the embedded UI, Kubernetes manifests, the dependency
mirror, and the git cache. The mirror arrived early — M3's egress boundary needed it — so what is
left here is the queue and what sits on it.

[`20-m4-plan.md`](20-m4-plan.md) holds the plan: each criterion below checked against the code, the
measured cost of the 5,000-target sweep, and the order. Two of its findings change what is written
here — the fetch cache is a precondition of the first criterion rather than an optimisation, and the
rate limiting the third criterion asks for exists on a client that carries 0.2% of the traffic.

**Exit criteria:**

- [ ] **A 5,000-target npm and PyPI sweep completes within its declared budget**, and we publish
      the measured numbers: reproduction rate, cost, wall clock, model-invocation rate.
- [ ] The three worker classes are enforced, including a test that the build worker cannot fetch the
      upstream artifact.
- [ ] Per-host rate limiting with global backoff propagation; a declared `User-Agent` with a contact
      URL; the registries have been contacted before the sweep runs.
- [ ] The UI ships the lockfile check, failure clusters, run, diff, cost, and fleet-health views.
- [ ] `trigon check ./package-lock.json --format sarif` works in a CI workflow.
- [ ] **Continuous ingestion runs for npm and PyPI** ([`10`](10-scale.md) §5), with a recorded cursor
      per feed and a catch-up path. After M4 the steady state is ingestion, and a sweep is what we
      run when the selection policy or the stabilizer set changes.

### M5. Breadth and public instance (6 weeks)

**Adds:** crates.io, RubyGems, GitHub, then NuGet. Tier-1 observability. The public instance.

**Exit criteria:**

- [ ] Per-ecosystem reproduction rates measured and published, including the honest ones.
- [ ] **RubyGems verification exists**, the first independent rebuild verification infrastructure
      that ecosystem has had.
- [x] The network transcript and the artifact-hash guard are live on every run. Tier 1 only
      ([`08`](08-execution.md) §7.2); the guard has been live since M2.
- [ ] Divergence publication is live, with all five safeguards from
      [`09-attestations.md`](09-attestations.md) §5 enforced, including the false-mismatch
      kill-switch.
- [ ] The provenance-contradiction feed is live.

### Beyond

Multi-tenancy. WASM-sandboxed stabilizers. Maven, Go and Debian. Tier 2 and 3 observability through
Tetragon or Falco. The Ask view as a sidecar to failure clusters.

## 3. The single biggest technical risk

**The stabilized digest is a pure function of our hand-written Rust serialization stack, and it is
the value we sign.**

```
stabilized = SHA256( our_writer( our_stabilizers( our_parser( bytes ) ) ) )
```

Consequences:

- A change to any writer, or a parse edge case, changes **every** stabilized digest. Caches
  invalidate, attestations stop reproducing for anyone on a different Trigon build, and third-party
  verification, which is the point of the exercise, fails.
- We borrow the prior art's digests **once**, as a bootstrap check in M0, and its **verdicts**
  thereafter. Once our deviation list exists, their digests stop being ground truth and ours start.
- Bugs come out **self-consistent**. Both sides get the same wrong treatment, so errors surface as
  false negatives, where two artifacts should have matched and did not, rather than as crashes.
  Meanwhile over-aggressive membership deletion is a false-**positive** vector.

**Retired by:** M0 in full, plus freezing the migration story on day one. Attestations record the
full stabilizer set, meaning member ids and the set digest. `trigon verify` refuses to compare across
differing set digests and re-derives instead. We persist both raw and stabilized digests, so a set
change leaves every old result open to re-evaluation.

### 3.1 Runner-up risks

| Risk | Mitigation |
|---|---|
| **Structured output across providers**, where local models are unreliable | `ModelCaps`-gated text-first fallback; the structured surface is exactly one type ([`07`](07-ai.md) §7) |
| **Upstream rate limiting / abuse flags** | Mirrors, narrow git fetch, per-host buckets, declared identity, and talking to registries before the first sweep ([`10`](10-scale.md) §2) |
| **False-mismatch rate**, given automatic divergence publication | Two agreeing attempts, the `Void` rules, the SLO kill-switch ([`09`](09-attestations.md) §5) |
| **Scope creep across six ecosystems** | Depth-first; `Unsupported` is a respectable outcome |
| **The guard voiding legitimate builds** | Member-level comparison with size, stock-content and also-in-source filters, plus invariant 11 in [`12`](12-security.md) §10: replay 500 known-good builds and assert zero `Void` |
| **Cold-sweep cost being quoted warm** | The sizing table in [`10`](10-scale.md) §1 carries three columns, and the cold column is the one to quote when asked what a first pass costs |
| **The archive writers taking longer than budgeted** | They are M0's whole content. If they slip, everything slips, which is why they go first. |

## 4. Cut or deferred

The reasoning goes here so it outlasts the people who did the deciding.

**1. eBPF syscall tracing, cut.** Highest effort, lowest early value, most hostile to portability.
It fails to compose with gVisor, which intercepts syscalls in userspace, or with Kata, which needs
the probe in the guest kernel. It breaks on every managed Kubernetes that "runs in any cloud"
implies. It needs privilege we otherwise avoid. And it generates the blob volume that blows the
storage budget. **Tier 1, the network transcript, answers the question people ask.** Revisit it by
consuming Tetragon or Falco events when a named user asks for syscalls by name. ([ADR-0007](adr/0007-observability-tiers.md))

**2. Three of the four proposed agents, cut.** We keep one real agent in the Builder, one
deterministic resolver, and one deterministic classifier, each with a model fallback. That halves the
prompt surface, the eval surface, the budget plumbing, and the failure modes. Nothing is lost,
because the cut agents were doing lookup and classification rather than search.
([ADR-0006](adr/0006-one-agent-not-four.md))

**3. The pluggable-everything matrix, deferred.** Keep the traits and build one implementation of
each in v1. Every adapter becomes a permanent cell in the test matrix, so a user has to ask for one
by name. ([ADR-0008](adr/0008-one-implementation-per-seam.md))

**3a. The WASM host, promoted from v2 into M2.** Not as an extension mechanism, which stays deferred,
but as the delivery format for stabilizer sets. A verifier three years out needs the code that
produced a digest, and naming the set digest without shipping the implementation leaves
`--rerun-comparison` unable to verify anything ([`09`](09-attestations.md) §7.1).

**4. The six-rung comparison ladder, cut** in favour of four outcomes.
([ADR-0002](adr/0002-four-match-outcomes.md))

**5. The Ask view, deferred**, and constrained to emitting queries rather than prose.

**6. Maven, Go and Debian, deferred.** The seam supports them.

## 5. Team shape

M0 takes one person who is good at binary formats and property testing, working alone. It resists
parallelizing, and forcing it would cost more than it saved.

M1 through M4 split into three streams: **ecosystems and strategies**, meaning breadth of `Registry`
implementations and flow templates; **infrastructure**, meaning sandbox, queue, workers and mirrors;
and **AI plus evaluation**. The judgement half stays with whoever built M0, because the invariants in
[`12-security.md`](12-security.md) §10 need an owner who knows why each one exists.
