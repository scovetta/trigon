# Trigon

**Semantic rebuild verification for open-source packages.**

Trigon takes a published package artifact, finds the source it claims to come from, rebuilds it in a
controlled environment, and decides whether the rebuild and the published artifact are the same
thing. It signs a statement either way, and that statement is checkable by someone who does not
trust us.

Registries distribute artifacts. People audit source. Almost nothing checks that the two correspond,
and that gap is where build-time supply-chain attacks live.

## Status

M0 and M1 are complete, M2 is complete but for one criterion, and M3 has begun. The design lives in
[`docs/`](docs/) and was written before any code; [`docs/16-findings.md`](docs/16-findings.md)
records where building it proved the design wrong.

| Milestone | | |
|---|---|---|
| **M0** the judgement half | done | differential against the reference implementation: 34 match, 24 deviate by a declared entry, **0 unexplained** |
| **M1** first rebuilds | done | npm and PyPI rebuild end to end, under an enforced egress tier, against a time-filtered index |
| **M2** attestations | 5 of 6 | signed statements, re-derivable cross-machine; stabilizer sets as WASM components remain |
| **M3** the search half | begun | the deterministic parts first — failure signatures, log compression, the repair-loop policy, the Builder |

Measured on the M1 smoke corpora, at `--egress open`:

| | reproduce | reach a comparison |
|---|---|---|
| npm | 14 of 15 (93%) | 15 of 20 |
| PyPI | 12 of 15 (80%) | 15 of 17 |

PyPI was 5 of 15 that morning. The lift came from three deterministic fixes and no model at all;
[`docs/16-findings.md`](docs/16-findings.md) §2 has the arithmetic.

## What it does

```
$ trigon verify upstream.tgz rebuild.tgz
✔ normalized

  format         tar+gzip
  stabilizer set npm-tarball (562ce45ae605…)

               upstream           rebuild
  raw          950a7c15ff8f…      b1934117b05e…      ≠
  container    bddb6178d296…      ef8d6b3d2ff6…      ≠
  stabilized   23065039367b…      23065039367b…      =

  applied
    gzip-meta                metadata        1 entries
    tar-entry-order          structural      3 entries
    tar-mode                 metadata        3 entries
    tar-owners               metadata        3 entries
    tar-time                 metadata        3 entries

  members  3 identical, 0 differ, 0 upstream-only, 0 rebuild-only
```

Those two tarballs were built eight years apart, by different users, with different umasks, in a
different member order, at different gzip levels. They stabilize to the same digest. Change one byte
of `index.js` and the verdict is `divergent`, the member is named, and the exit code is 1.

Rebuilding a real package, from the registry:

```
$ trigon rebuild pkg:npm/left-pad@1.3.0 --image debian@sha256:8820… --timewarp auto --store ./store
  artifact   left-pad-1.3.0.tgz
  published  sha256 870c0fe1096223a5
  guarding   the artifact and 10 of its members
  mirror     inside the build's network island, which is its only route out
  source     https://github.com/stevemao/left-pad @ ff8e7ba8b41228…
  strategy   Heuristic, commit found by RegistryCommit, confidence Certain
  ✔ normalized
```

Then signing it, from a **separate process that runs no build**:

```
$ trigon attest --store ./store --key k.bin
rederived normalized under tar-gzip@4598411b636d — signing
  attestations/npm/left-pad/1.3.0/left-pad-1.3.0.tgz/equivalence.intoto.json
  attestations/npm/left-pad/1.3.0/left-pad-1.3.0.tgz/rebuild.intoto.json
  attestations/npm/left-pad/1.3.0/left-pad-1.3.0.tgz/buildobservation.intoto.json
```

And checking it, as somebody who does not trust us:

```
$ trigon verify-attestation bundle.json --rerun-comparison \
      --upstream upstream.tgz --rebuild rebuild.tgz --public-key <hex>
signature verified
rederived normalized under tar-gzip@4598411b636d — the claim holds
```

`scripts/cross-machine-verify.sh` runs that last step the hard way: a fresh clone, a separate target
directory, a `--no-default-features` build whose dependency tree contains no async runtime and no
network client, four files handed over, and the network removed with `unshare -rn`. It also requires
an overstated outcome, an edited payload and a substituted artifact each to be caught, for three
different reasons — a verifier that printed "the claim holds" unconditionally would pass the
positive case on its own.

## The two halves

The system is one idea: **rebuild verification is a search problem wrapped in an equivalence
problem.** Search is where a model helps. Equivalence is where it must never be trusted.

```
                         trigon-core
                    /         |        \
      trigon-archive    trigon-strategy   trigon-attest
             |                                  |
      trigon-stabilize                          |
             |                                  |
      trigon-compare                            |
              \____________ _______ ___________/
   ================= JUDGEMENT / SEARCH LINE =================
    trigon-registry   trigon-ai   trigon-sandbox   trigon-store
                             |
                        trigon (bin)
```

Everything above the line is synchronous, declares no cargo features, and cannot reach `tokio`,
`reqwest` or `trigon-ai`. Everything below it is budgeted and replayable. `trigon-ai` is forbidden
from naming `trigon-compare`, `trigon-stabilize` or `trigon-archive` — the invariant read from the
other side, because a crate that cannot name a function cannot call it.

`cargo run -p xtask -- policy` enforces all of it and fails the build on a violation. The claim a
sceptic can check without reading any of this is `cargo tree` on the verifier build.

## Layout

```
crates/trigon-core        digests, paths, formats, outcomes, risk tiers, evidence,
                          failure signatures, log compression, RFC 8785 canonicalization
crates/trigon-archive     the mutable archive model; hand-written tar, zip and gzip writers
crates/trigon-stabilize   the stabilizer catalogue and its profiles
crates/trigon-compare     one pass, six digests, the provenance cap, the difference signature
crates/trigon-strategy    the strategy schema, the flow DSL, the tool registry, rendering
crates/trigon-attest      in-toto statements, DSSE, signing, re-derivation
crates/trigon-registry    registry clients, source discovery, strategy inference
crates/trigon-sandbox     the build runner, egress islands, isolation
crates/trigon-mirror      the time-filtered index and the artifact guard
crates/trigon-store       content-addressed blobs and run records
crates/trigon-ai          the provider seam, the Builder, budgets and admission control
crates/trigon             the binary
xtask                     dependency policy, corpora, golden digests, the differential
docs/                     the design, and what implementing it changed
corpora/                  frozen corpora and declared deviations (manifests only)
scripts/                  the cross-machine verification check
```

## Build and check

```
cargo test --workspace                      # 390 tests
cargo run -p xtask -- policy                # the dependency policy
cargo run -p xtask -- differential          # against the reference implementation
scripts/cross-machine-verify.sh             # the claim a third party can check
```

Rust 1.85 or later, edition 2024. Rebuilds additionally need `podman`; nothing else has
prerequisites, and `trigon verify` has none at all.

## Reading the design

Start with [`docs/00-overview.md`](docs/00-overview.md) for the thesis, then
[`docs/05-archive-and-normalization.md`](docs/05-archive-and-normalization.md) for the part that is
hard, then [`docs/12-security.md`](docs/12-security.md) for the attack that shapes everything else.
[`docs/16-findings.md`](docs/16-findings.md) is what the design got wrong, measured.

## License

Apache-2.0.
