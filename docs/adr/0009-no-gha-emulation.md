# ADR-0009. Read GitHub Actions, do not emulate runners

**Status:** accepted

## Decision

Parse `.github/workflows/*.yml` into a normalized `CiRecipe` and **lower it to our own container
plan**, pinned by digest. Do not execute workflows in runner images, `act`-style.

## Reasoning

**Runner images mutate and resist pinning.** `ubuntu-24.04` moves and `ubuntu-latest` moves faster.
Emulating them would leave *our own* results irreproducible, which defeats the purpose of the system.
A verifier who cannot re-derive our result has nothing.

**We need intent rather than fidelity.** The workflow tells us the toolchain version, the build
command, the environment variables, the working directory and the publish step, which is what a
strategy needs. Reproducing `actions/cache` behaviour faithfully buys nothing, because caching cannot
change output.

**Emulation is a large ongoing surface.** Every action is arbitrary JavaScript or a container, and
keeping up with the ecosystem is a project of its own.

## The approach instead

- Select candidate jobs by trigger and by the presence of a publish step, matched against a table of
  per-ecosystem publish markers.
- Expand `uses:` for a **curated allowlist** of well-known setup actions.
- Map `runs-on` to one of our digest-pinned base images. The attestation records that mapping as an
  **approximation**, labelled that way, and never as an equality claim.
- Record whatever we could not interpret as `UnmodelledStep`, which lowers the candidate's confidence
  and shows up in the UI. An unmodelled step is where the next inference failure comes from, so
  hiding it would be the worst available option.
- Emit both a strategy candidate **and** a set of `Evidence`. The second output often beats the
  first: a workflow we cannot lower faithfully still tells us the Python version, and that alone can
  turn a failing heuristic strategy into a passing one.

## Trusted-publishing provenance is an input

Where npm, PyPI, NuGet or GitHub publish provenance, we consume it. It hands us repository, commit
and workflow path, which is the largest single reduction in model invocation available. We verify its
signature ourselves, and its claims enter as `Evidence` rather than as facts.

**A rebuild that contradicts published provenance is the highest-signal output this system
produces**, so the presence of provenance never short-circuits a verdict. Provenance says where an
artifact came from, and we say what it is.

macOS and Windows runners report `Unsupported` rather than failing. Attempting them would produce a
stream of divergences that say nothing about the packages involved.
