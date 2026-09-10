# ADR-0002. Four match outcomes rather than a six-rung ladder

**Status:** accepted, reversing an earlier draft

## Decision

```rust
pub enum Match { Exact, Normalized, NormalizedWithCaveats, Divergent }
```

Serialized as **strings**, never as ordinals.

## Context

An earlier draft proposed six rungs: `Identical`, `ContainerNormalized`, `ContentIdentical`,
`ContentNormalized`, `SemanticallyEqual`, `Annotated`. It looked more informative on paper and does
not survive the implementation.

## Reasoning

**One pipeline run cannot separate the middle rungs.** Telling `ContainerNormalized` from
`ContentNormalized` means running the pipeline several times with different stabilizer subsets,
tripling the cost of the most-executed code path, or partitioning stabilizers into container and
content. That partition breaks on `wheel-record`, a *content* stabilizer that exists because
*membership*, a container property, changed. The categories do not sit at right angles.

**`SemanticallyEqual` cannot be defended in a signed statement.** For a compiled shared object it
asserts compiler-output equivalence, which nobody can back. Everything you would file there amounts
to "we chose to ignore a difference", which `NormalizedWithCaveats` already says.

**Ordinals in wire formats trap you.** A downstream policy engine writes `rung <= 3`, and from then
on you cannot insert a rung without breaking it.

## The information the ladder promised

A differently shaped answer rather than a coarser one. The `Comparison` record carries:

- six digests: raw, decompressed container, and stabilized, on both sides;
- `container_bit_identical`, which captures "same tar, different gzip framing", the most common
  near-miss for `.crate`, `.tgz` and `.gem`;
- `applied`: every stabilizer that fired, with risk tier, provenance, `entries_touched` and
  `bytes_changed`;
- structured `notes`.

That carries more information than a rung number, at no extra cost, because `applied` falls out of
the dirty bits the walker already sets.

## The bonus

`NormalizedWithCaveats` gives the provenance cap from ADR-0001 somewhere to land. Normalization
authored by a model or a human cannot present as a clean `Normalized`, and a consumer sets their own
floor through `Match::is_at_least()` in the library while the wire format stays a string.
