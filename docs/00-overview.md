# 00. Overview

## 1. The problem

Package registries distribute **artifacts**. Humans audit **source**. Almost nothing checks that the
two correspond.

A published npm tarball, PyPI wheel, gem, crate, or nupkg is a blob that a publisher uploaded. The
registry does not build it. The registry does not check it against a repository. npm will accept an
arbitrary tarball with no connection to any commit at all. Everything downstream, from SCA scanners
to SBOMs to code review, reads the *source* and then trusts that the *artifact* matches it.

Attackers have exploited that gap repeatedly. In `event-stream`, `ua-parser-js`, the `xz` backdoor,
and the 2024 to 2026 run of npm publish-token compromises, the malicious code sat in the artifact and
not in the repository anyone was reading.

### Trusted publishing helps and does not close it

Between 2023 and 2025 every major registry shipped OIDC trusted publishing: PyPI in April 2023,
RubyGems in December 2023, npm in July 2025, crates.io in July 2025, NuGet in September 2025. PyPI
added PEP 740 attestations, which are in-toto v1 statements signed through Sigstore. npm and GitHub
ship SLSA provenance.

Trigon consumes all of it (see [`06-ci-awareness.md`](06-ci-awareness.md)). Note what it proves:
*workflow W in repo R at commit C produced this artifact*. It does not prove the artifact
corresponds to the source at commit C. A compromised workflow, a compromised action, a malicious
build script, or a maintainer with a backdoor in their build tooling all produce valid provenance.
Provenance says **where** an artifact came from. Rebuild verification says **what it is**.

The two complement each other, and a rebuild that contradicts existing provenance is one of the
highest-signal outputs this system can produce.

### The reproducibility ground has shifted in our favour

Ecosystem-level reproducibility improved sharply between 2023 and 2026. Numbers and citations are in
[`03-ecosystems.md`](03-ecosystems.md):

- **RubyGems** went from 0% to about 99.9% when 3.6.7 started defaulting `SOURCE_DATE_EPOCH` and
  sorting gemspec metadata. No independent rebuild verification infrastructure exists for it.
- **PyPI** goes from about 12% to about 98% with `SOURCE_DATE_EPOCH` plus umask fixes. Timestamps
  alone account for 87.7% of failures.
- **crates.io** reproduces well by design since `trim-paths` became the release default.
- **npm** reproduces at about 100% at the tarball level and 0% linked to source.
- **NuGet** has trusted publishing and almost no reproducibility infrastructure.

For most ecosystems the *normalization* problem is now tractable, and the remaining hard problem is
finding the source and reconstructing the build. That is a search problem, and search is what modern
models are good at.

## 2. Prior art

We read two systems in full before writing this design. This section is the evidence behind most of
the decisions in the rest of the document set.

### 2.1 google/oss-rebuild (Go)

The strongest existing design by a wide margin, in production for npm, PyPI and crates.io, with
Maven, Debian, RubyGems and OCI in-tree.

**Ideas Trigon takes:**

| Idea | Detail | Where it lands |
|---|---|---|
| The `Strategy → Instructions` seam | `GenerateFor(Target, BuildEnv) -> Instructions{Location, Source, Deps, Build, OutputPath, Requires}`. Strategies are *data*, rendering to shell is pure, and executors consume rendered scripts without interpreting them. | [`04`](04-strategies.md) |
| The `flow` step DSL | `Step{Runs(template) \| Uses(tool), With, Needs}` plus a composable named-tool registry. One substrate serves typed strategies and hand-authored YAML. | [`04`](04-strategies.md) |
| Stabilization over bitwise equality | Ordered, constraint-guarded pure passes over a mutable archive model, with `StageDefault(0) / StagePatch(10) / StageFinalize(100)`. Finalize exists for invariants that depend on all prior passes, and wheel `RECORD` regeneration is the canonical case. | [`05`](05-archive-and-normalization.md) |
| Two digests in one pass | A `TeeReader` feeds a raw hasher while the stabilized stream feeds a second hasher. About 40 lines, and it gives exact-versus-stabilized for free. | [`05`](05-archive-and-normalization.md) |
| **Timewarp** | An in-container registry proxy that filters npm, PyPI and RubyGems responses to the state at the target's publish timestamp. Without it, any package whose build resolves a floating dependency range cannot be reproduced at all. | [`08`](08-execution.md) |
| Index-commit pinning | For Cargo, pin a `crates.io-index` git commit satisfying the lockfile. A timestamp lacks the precision, so this is a correctness fix and not an optimization. | [`08`](08-execution.md) |
| Cargo toolchain fingerprinting | Cargo rewrites `Cargo.toml` at package time, and the rewriting rules changed across releases. Structural fingerprinting of the packaged manifest pins the toolchain window far tighter than release dates or the declared MSRV. | [`03`](03-ecosystems.md) |
| Build container shape | The Dockerfile runs setup, source and deps at *image build* time, and the build itself is `docker run` of a written `/build` script. That yields layer caching, clean phase-timing boundaries, and a retained container an agent can `exec` into. | [`08`](08-execution.md) |
| Exploration is not verification | Their agent iterates on a scratch VM, and only a locally verified success reaches the trusted builder. Only the trusted builder's output is attestable. | [`07`](07-ai.md) |
| Honest verdict taxonomy | `FAILURE` (built, no match) sits apart from `ERROR` (infra fault). Per-phase timings are nullable, where `nil` means "no data" and never zero, plus a `FailedIn` phase so failed spans stay out of duration statistics. | [`02`](02-domain-model.md) |
| Definitions governance | Overrides at `{eco}/{pkg}/{ver}/{artifact}/build.yaml`. Custom stabilizers require a **mandatory non-empty prose `reason:`**, validated at load. | [`04`](04-strategies.md) |
| Prevalence-ordered work | A `signals` package scores packages by normalized dependency-graph prevalence. At 100k targets this decides whether the money goes to packages people import or to packages nobody imports. | [`10`](10-scale.md) |
| Cost accounting | Per-attempt inference seconds, `Tokens{Input, CachedInput, Output, Model}`, builder seconds, log and container and artifact bytes, plus repo metrics keyed per *repository*, because many packages share one. | [`02`](02-domain-model.md), [`10`](10-scale.md) |
| Reproducible benchmarking | Versioned package sets with a canonical content hash recorded on every run, so a result traces to an exact corpus revision. | [`07`](07-ai.md) |

**What Trigon leaves:**

- **GCP coupling.** Cloud Build, Cloud Tasks, Cloud Run Jobs, Firestore and GCS carry load rather
  than sitting behind adapters. Running your own instance means running theirs.
- **AI as a bolt-on.** Their agent is a three-call Diagnose, Implement, Clean cycle producing raw
  bash, reached only after normal inference fails. Useful, and not a design centre.
- **KMS-only signing with no transparency log.** The "log" is a public GCS bucket.
- **Positive results only.** A failed rebuild produces little durable, publishable output.
- **No management UI** beyond a server-rendered dashboard and an operator TUI.
- **`StrategyOneOf` as a struct of nullable pointers.** A Go workaround for missing sum types. Rust
  gets a tagged enum (see [ADR-0003](adr/0003-strategy-representation.md)).
- **The stabilizer dispatch machinery.** About 200 lines of `Constraint`, `WithFns(map[Format]Fn)`
  and type-switch-on-function-kind that exists because Go cannot dispatch on a node enum. In Rust it
  collapses to two defaulted trait methods.
- **Recursion as a stabilizer.** Their gem inner-archive stabilizer implements nested-archive
  recursion as a stabilizer and swallows the error, so a malformed `data.tar.gz` produces a
  different stabilized digest with no signal. Trigon makes recursion structural (see
  [`05`](05-archive-and-normalization.md)).

Two facts worth holding onto when planning: their largest published benchmark covers about 5,000
package-versions, and `definitions/` holds **53 files**. Nobody has demonstrated this at 100k, and
manual overrides form a 0.1% long tail rather than a rung of the escalation ladder that carries
volume.

### 2.2 microsoft/OSSGadget `oss-reproducible` (C#)

A warning, with two good ideas inside it.

**The good ideas:** ranked strategies (`PackageMatchesSourceStrategy` at High priority, then
`AutoBuildProducesSamePackage` and `PackageContainedInSourceStrategy` at Medium, then
`OryxBuildStrategy` at Low), stopping at the first pass; and per-ecosystem `autobuild.sh` scripts in
Docker with a `prebuild` / `build` / `postbuild` override hook resolved per package, which is a good
escape-hatch shape. Each strategy also runs on a throwaway copy of the inputs, so one strategy
mutating the source tree cannot pollute the next.

**The comparison is the problem, and comparison is the entire point of the tool.** It compares files
with `File.ReadAllText` plus a line diff with `ignoreWhiteSpace: true`. That is text only: no
hashing, no binary comparison, no archive-level comparison of members, timestamps, or modes.
"Normalization" means shelling out to a container to run prettier on `.js` and `.ts`, and it compares
every other file type raw. It matches paths between package and source with a fuzzy *suffix*
heuristic. It handles metadata with a global regex ignore list that drops all `.md`, `.txt`, `.rst`
and changelog files. The reproducibility "score" is a hard-coded table keyed on strategy class name,
with a `@TODO Refactor this into the individual strategy objects` comment above it.

Coverage tells the same story. `cargo` and `gem` ship build scripts but have no source-repository
discovery, so they never run. `nuget` has discovery but no build script. And the CLI's
`--diff-technique` flag gets dropped when the tool constructs per-strategy options, so it does
nothing.

**What Trigon takes:** ranked strategies with a per-package override hook. Comparison has to be
typed, format-aware, and rigorous, never a text diff with an ignore list.

## 3. The thesis

Rebuild verification is a search problem wrapped in an equivalence problem. Models handle search
well. They have no place in the equivalence.

- **The search half**, meaning source discovery, strategy inference, and build repair, runs
  nondeterministically, under budget, cached, and replayable. Its output is a *candidate strategy*,
  which is data.
- **The judgement half**, meaning execute, normalize, compare, runs deterministically with no model
  in reach, and a third party can reproduce it holding only the attestation and the two artifacts.

### 3.1 The invariant, stated so it survives contact with reality

The naive form of this rule says the judgement half must not depend on the AI crate. True, and weak.
Nobody was ever going to call a model from inside a comparator. The failure modes that exist are
**data**:

1. A **model-authored stabilizer** participates in the stabilized digest without anyone noticing.
2. A **model-authored build script fetches the upstream artifact** and re-emits it, so the rebuild
   matches byte for byte.
3. Cargo **feature unification** enables an HTTP feature in a crate that was supposed to be pure.

So the invariant is **provenance-capped outcomes**:

**`Match::Normalized` is unreachable if any *applied* stabilizer has non-`Builtin` provenance or a
risk tier above `Metadata`. Anything a model touched reaches at most
`Match::NormalizedWithCaveats`.**

One line, testable as a unit test and as a property, and reported in the attestation predicate. The
crate dependency graph in [`01-architecture.md`](01-architecture.md) keeps honest code honest. The
controls that stop an attacker are this invariant, egress denial, the artifact-hash check in
[`12-security.md`](12-security.md), and a `trigon verify` binary built with `--no-default-features`
that contains no network client and no model code.

### 3.2 What we are willing to sign

A verifier who has never heard of a language model has to be able to check the claim in a Trigon
attestation:

**Recipe R, executed in fully described environment E, produced artifact A whose stabilized form
under versioned stabilizer set S equals the stabilized form of published artifact P.**

Every noun there is deterministic. Whether a model helped derive R sits beside the claim as a
provenance fact and never inside it. See [`09-attestations.md`](09-attestations.md).

## 4. Goals

1. **Verify semantically, not bitwise.** Bit-for-bit purism fails on real ecosystems. Normalize known
   classes of benign nondeterminism, name every normalization applied, and let consumers set their
   own risk threshold.
2. **Six ecosystems behind one seam.** npm, PyPI, crates.io, RubyGems, NuGet, GitHub. Adding a
   seventh means YAML plus one trait implementation, and no engine change.
3. **Local and cloud from the same binary.** `trigon verify pkg:npm/left-pad@1.3.0` has to work on a
   laptop with Docker and no cloud account. The same code scales to a fleet.
4. **AI-native where AI helps.** Heavy use of models for source discovery, strategy inference, and
   build repair, with budgets, caching that generalizes across versions, and a flywheel that promotes
   each repair into a reusable rule.
5. **Attest both outcomes.** A divergence carries at least as much value as a match, and gets its own
   signed, structured, falsifiable document.
6. **Third-party verifiable.** `trigon verify-attestation --rerun-comparison` has to let someone who
   distrusts us re-derive the equivalence claim from the attestation and the two artifacts.
7. **Honest at scale.** Design the interfaces for 100k, prove the system at 5k, publish the number we
   measured.

## 5. Non-goals

- **Bit-for-bit purism.** See goal 1.
- **Emulating GitHub Actions runners.** Runner images mutate and resist pinning, so emulating them
  would make our own results irreproducible. We extract intent and lower it to our own container plan.
- **Malware scanning.** Trigon answers whether an artifact matches a source. Whether the source is
  malicious is a different product. Build observability ([`08`](08-execution.md)) gives forensic
  context rather than detection.
- **Replacing trusted publishing.** We consume it.
- **Maven, Go, or Debian in v1.** The seam supports them. The effort does not fit.
- **A general CI system.** We reconstruct builds for verification, not for release.

## 6. Glossary

| Term | Meaning |
|---|---|
| **Target** | A package coordinate plus a specific artifact, addressed as a PURL plus artifact filename. GitHub projects use `pkg:github/owner/repo@ref`. |
| **Upstream artifact** | The published bytes fetched from the registry or release. |
| **Source provenance** | A resolved `{repo_url, commit_sha, subdir, ref_name}`, meaning the claimed origin. |
| **Strategy** | A versioned, content-addressed, declarative recipe turning source into an artifact. Data rather than code. |
| **Instructions** | A strategy rendered for a specific target and environment: source, deps and build scripts, output path, requirements. |
| **Stabilizer** | A pure, total transform removing one known class of benign nondeterminism from an artifact. |
| **Stabilizer set** | An ordered, named, content-digested collection of stabilizers. Named in every attestation. |
| **Match** | `Exact` \| `Normalized` \| `NormalizedWithCaveats` \| `Divergent`. |
| **Verdict** | The outcome of a run: `Reproduced` \| `Divergent` \| `Void` \| `BuildFailed` \| `Unsupported` \| `Error`. |
| **Void** | A run that proves nothing, for example because the upstream artifact entered the sandbox over the network. |
| **Run** | One execution of the pipeline over one target, content-addressed and replayable. |
| **Sweep** | A planned fan-out of runs over a package set, with a shared budget and priority. |
| **Egress tier** | `deny-all` \| `mirror-only` \| `git+mirror` \| `open`. A signed attestation field. |
| **Derivation** | How a strategy was obtained: `definitions` \| `heuristic` \| `ci_derived` \| `model_assisted`. |
