# ADR-0001. Rust, and a judgement half that cannot call a model

**Status:** accepted

## Decision

Implement in Rust, and split the workspace so that the crates performing execution, normalization and
comparison have no way to depend on the AI crate, on tokio, or on an HTTP client. A policy test over
the resolved dependency graph enforces that in CI.

On top of that, and mattering more, cap outcomes by provenance:

**`Match::Normalized` is unreachable if any applied stabilizer has non-`Builtin` provenance or a risk
tier above `Metadata`.**

## Rust, and what it costs

- The archive writers have to produce **byte-exact** output. A language with predictable memory
  layout and no hidden allocation makes that tractable, and the type system lets us express the
  total, panic-free stabilizer contract.
- A single static binary with no runtime is what makes "runs on a laptop, scales to a fleet"
  credible.
- Sum types and exhaustive matching remove about 200 lines of dispatch machinery that the Go prior
  art carries to work around their absence.
- crates.io is one of the target ecosystems, and dogfooding matters.

The costs are real, and we accept them. The LLM client ecosystem is young, so we write about 600
lines ourselves. Git tooling is the weakest spot in the stack. And no usable in-toto crate or
complete sigstore crate exists, so we hand-write about 350 lines.

## The dependency split is not the control

The naive framing says the judgement half must not depend on `trigon-ai`. True, and weak. Nobody was
going to call a model from inside a comparator. The failure modes that exist are **data**:

1. A model-authored **stabilizer** participating in the signed digest.
2. A model-authored **build script** fetching the upstream artifact and re-emitting it.
3. Cargo **feature unification** enabling HTTP in a crate that was supposed to be pure.

The provenance cap addresses (1) and takes both a unit test and a property test. The artifact-hash
guard in `12-security.md` §2 addresses (2). `require_no_features` on judgement-half crates addresses
(3), leaving unification nothing to leak through.

So the dependency graph keeps honest code honest, and we describe it that way rather than as a
security boundary.

## The claim a sceptic can check

`trigon verify`, built `--no-default-features`, contains `core + archive + stabilize + compare +
attest` and nothing else. No network client, no model code. It reproduces our verdict from an
attestation and two artifacts. That binary beats the diagram.

## Alternatives considered

- **Go**, matching the prior art. It would let us reuse their stabilizers directly, which tempts.
  But their digests only transfer as *verdicts* anyway, since we have to own the writers to own the
  signed value, and the dispatch machinery Go forces costs us every time we touch it.
- **A single crate with module-level discipline.** Rejected. A module boundary is not
  machine-checkable, and the point is a claim someone else can verify.
