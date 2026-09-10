# Trigon

**Semantic rebuild verification for open-source packages.**

Trigon takes a published package artifact, finds the source it claims to come from, rebuilds it in a
controlled environment, and decides whether the rebuild and the published artifact are the same
thing. It signs an attestation either way.

Registries distribute artifacts. People audit source. Almost nothing checks that the two correspond,
and that gap is where build-time supply-chain attacks live.

## Status: M0, in progress

The design is complete and lives in [`docs/`](docs/). The code is at milestone M0, which builds the
**judgement half** and nothing else: no builds, no sandbox, no AI, no queue. The reason is in
[`docs/13-roadmap.md`](docs/13-roadmap.md) §3, and it is that the stabilized digest is a pure
function of a hand-written serialization stack and it is the value we sign. Everything else is
replaceable. That is not.

What works today:

```
$ trigon verify upstream.tgz rebuild.tgz --profile npm-tarball
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

## Layout

```
crates/trigon-core        pure types: digests, paths, formats, outcomes, risk tiers
crates/trigon-archive     the mutable archive model; hand-written tar, zip and gzip writers
crates/trigon-stabilize   the stabilizer catalogue and its profiles
crates/trigon-compare     one pass, six digests, the provenance cap, the diff report
crates/trigon             the binary
xtask                     dependency policy, corpora, golden digests
docs/                     the design
corpora/                  frozen test corpora (manifests only; artifacts are fetched)
```

Everything above `trigon-registry` in the graph is synchronous, declares no cargo features, and
cannot reach tokio, reqwest or the AI crate. `cargo run -p xtask -- policy` enforces that, and it
fails the build on a violation.

## Build

```
cargo test --workspace          # 45 tests, including 200-case property tests
cargo run -p xtask -- policy    # the dependency policy
cargo run -p trigon -- stabilizers --profile gem
```

Rust 1.85 or later (edition 2024). No other prerequisites.

## Reading the design

Start with [`docs/00-overview.md`](docs/00-overview.md) for the thesis, then
[`docs/05-archive-and-normalization.md`](docs/05-archive-and-normalization.md) for the part that is
hard, then [`docs/12-security.md`](docs/12-security.md) for the attack that shapes everything.

## License

Apache-2.0.
