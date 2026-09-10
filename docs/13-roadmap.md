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
- [ ] **Differential corpus test against the Go implementation passes.** The harness is the prior
      art's own `cmd/stabilize`, which is `go install`-able and takes `--enable-passes` and
      `--disable-passes`, so a mismatch localizes to one stabilizer rather than to the pipeline. The
      criterion is **stabilized-digest equality except a checked-in deviation list**, because six
      deviations are intentional ([`05`](05-archive-and-normalization.md) §6). An unexplained
      difference fails the build.
- [ ] **The deviation list exists as a reviewed file**, each row carrying a test and a sentence.
- [ ] **`trigon bench regold` works**, with a review artifact showing how many digests moved and
      which stabilizer moved them. Without it, the first stabilizer change deletes the corpus test.
- [ ] `stabilize(stabilize(x)) == stabilize(x)` holds as a proptest.
- [ ] `parse(write(a)) == a` holds as a proptest.
- [ ] Byte-identical output across 100 runs and across threads.
- [ ] `cargo-fuzz` clean on `parse` and on `parse → stabilize → write → parse`, with limits respected.
- [ ] The `xtask` dependency-policy test is in CI and fails a deliberate violation.
- [ ] `trigon verify` builds with `--no-default-features` and links no network client or model code.

This milestone retires the project's risk, so over-invest in it.

### M1. First rebuilds (3 to 4 weeks)

**Adds:** `trigon-strategy`, `trigon-sandbox` (Podman only), the time-filtered registry, and
`trigon run --strategy build.yaml`.

**Exit criteria:**

M1 needs **two** corpora, and conflating them was a mistake in an earlier draft.

- [ ] **The DSL corpus: the prior art's `definitions/`, imported verbatim.** 53 files, and the
      distribution matters: 51 PyPI, 1 npm, 1 maven. These are overrides written for packages where
      *inference failed*, so they are the pathological tail. They exercise the flow DSL, the template
      engine, the named-tool registry and `custom_stabilizers` harder than anything we would write,
      and they say nothing about the common path. Executing them validates the DSL. Nothing more.
- [ ] **The common-path corpus: 400 targets sampled by prevalence**, 200 npm and 200 PyPI, stratified
      by build system rather than by popularity alone ([`15-corpora.md`](15-corpora.md) §3). This is
      what a reproduction rate can be quoted from, and it is the number M1 reports.
- [ ] `trigon verify pkg:npm/left-pad@1.3.0` works on a laptop with Podman and no cloud account.
- [ ] npm and PyPI end-to-end with heuristic and CI-derived strategies only, **with no AI involved**.
- [ ] The `smoke` benchmark corpus (~50 targets) is green and runs in under ten minutes.
- [ ] Per-phase timings and costs recorded, with `None` meaning "no data".

### M2. Attestations (2 weeks)

**Adds:** `trigon-attest`, `trigon-store`.

**Exit criteria:**

- [ ] All four predicates emitted, plus a conformant SLSA Provenance v1 statement.
- [ ] Signing works unsigned, with a local key, and with sigstore keyless including Rekor v2.
- [ ] The attestor runs as a separate process and **re-derives the claim before signing**.
- [ ] **`trigon verify-attestation --rerun-comparison` succeeds against a bundle produced on a
      different machine**, from a checkout that shares no state with the producer.
- [ ] `trigon verify` refuses to compare across differing stabilizer-set digests.
- [ ] **Stabilizer sets publish as content-addressed WASM components**, and
      `--rerun-comparison` loads the set named in the attestation rather than the one in the binary
      ([`09`](09-attestations.md) §7.1). A CI test asserts the WASM and native builds produce
      identical digests over the M0 corpus.

### M3. The AI subsystem (4 weeks)

**Adds:** `trigon-ai`, holding Resolver, Builder and Explainer, with budgets, generalizing caches,
transcripts, replay, and the three-tier eval harness.

**Exit criteria:**

- [ ] Measurable lift on the `regression` corpus versus M1's heuristics-only baseline.
- [ ] **Model-invocation rate trends down** across the milestone as the flywheel produces rules.
- [ ] At least one repair promoted into a merged corpus-wide rule, with its impact preview.
- [ ] Replay reproduces a recorded run with zero model calls.
- [ ] Both the Anthropic and OpenAI-compatible providers work; a fully local configuration
      (Ollama or vLLM) completes the `smoke` corpus.
- [ ] The `trivial-deterministic` label shows **zero** model invocations.

### M4. Fleet (4 weeks)

**Adds:** the queue, worker classes, the API, the embedded UI, Kubernetes manifests, the dependency
mirror, and the git cache.

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
- [ ] The network transcript and the artifact-hash guard are live on every run.
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
