# Trigon

**Semantic rebuild verification for open-source packages.**

Trigon takes a published package artifact, finds the source it claims to come from, rebuilds it in a
controlled environment, and decides whether the rebuild and the published artifact are the same
thing. It signs a statement either way, and that statement is checkable by someone who does not
trust us.

Registries distribute artifacts. People audit source. Almost nothing checks that the two correspond,
and that gap is where build-time supply-chain attacks live.

## Status

M0, M1 and M2 are complete, and M3 has begun. The design lives in
[`docs/`](docs/) and was written before any code; [`docs/16-findings.md`](docs/16-findings.md)
records where building it proved the design wrong.

| Milestone | | |
|---|---|---|
| **M0** the judgement half | done | differential against the reference implementation: 34 match, 24 deviate by a declared entry, **0 unexplained** |
| **M1** first rebuilds | done | npm and PyPI rebuild end to end, under an enforced egress tier, against a time-filtered index |
| **M2** attestations | done | signed statements, re-derivable cross-machine and through an archived stabilizer set run under `wasmtime` |
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

## Verify a package end to end

Two real targets, start to finish. Both need `podman` and take a few minutes each, most of it
pulling the base image the first time.

### An npm package

```
$ trigon rebuild pkg:npm/left-pad@1.3.0 \
      --image docker.io/library/debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 \
      --work ./work --egress open --timewarp auto

  artifact   left-pad-1.3.0.tgz
  published  sha256 870c0fe1096223a5
  guarding   the artifact and 10 of its members
  source     https://github.com/stevemao/left-pad @ ff8e7ba8b41228…
  strategy   Heuristic, commit found by RegistryCommit, confidence Certain

  mirror     69 index request(s), 1044 version(s) withheld across them

✔ normalized

  format         tar+gzip
  stabilizer set tar-gzip (4598411b636d…)

               upstream           rebuild
  raw          870c0fe10962…      0ebf94afb7c6…      ≠
  container    2bc27360d33b…      b7142014cce1…      ≠
  stabilized   f0a01941419d…      f0a01941419d…      =

  members  10 identical, 0 differ, 0 upstream-only, 0 rebuild-only
```

`normalized` rather than `exact`: the two tarballs differ in mtimes, file modes and member order,
all of which the stabilizers remove, and in nothing else.

The `mirror` line is the evidence that the dependency index really was pinned to the publish date.
The count is across all 69 packuments the build fetched, not left-pad's own — left-pad has published
nothing since 2018, so none of its fifteen versions were withheld. The thousand-odd come from its
devDependency tree, where `mocha` alone accounts for 111 versions that did not exist in April 2018
and `glob` for 73.

### A PyPI package

```
$ trigon rebuild pkg:pypi/chardet@7.6.0 \
      --image docker.io/library/python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b \
      --work ./work-py --egress open --timewarp auto

  mirror     10 index request(s), 12 version(s) withheld across them

✔ exact

  format         zip
  stabilizer set wheel (58632c3c627d…)

               upstream           rebuild
  raw          4076d795897c…      4076d795897c…      =
  stabilized   aafb77c84b42…      aafb77c84b42…      =

  members  41 identical, 0 differ, 0 upstream-only, 0 rebuild-only
```

`exact` is the strongest outcome there is: the rebuilt wheel is byte-for-byte the published one,
before any stabilizer ran.

### Signing it, and checking the signature

`--store` records the run so a **separate process** can sign it. That separation is the point: the
process that ran the build could record any outcome it liked, so the attestor re-derives the claim
from the artifact bytes before it signs anything.

```
$ head -c 32 /dev/urandom > key.bin          # a development key; see docs/09 for the real options
$ trigon rebuild pkg:pypi/chardet@7.6.0 --image <as above> --work ./work-py \
      --egress open --timewarp auto --store ./store
$ trigon runs --store ./store
1789215251-4076d795  pkg:pypi/chardet@7.6.0    exact    unattested

$ trigon attest --store ./store --key key.bin
target    pkg:pypi/chardet@7.6.0
rederived exact under wheel@58632c3c627d — signing

  attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/equivalence.intoto.json
  attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/rebuild.intoto.json
  attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/buildobservation.intoto.json

signed with key 8238c7031caabae5
```

`rederived exact … — signing` is the load-bearing line. The attestor did not take the run record's
word for the outcome: it fetched both artifacts from the store **by hash**, checked each against the
hash it asked for, recomputed the comparison, and would have refused to sign had the answer differed.

Anyone holding the two artifacts can now check that claim without trusting us, and without a
network:

```
$ trigon verify-attestation \
      ./store/attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/equivalence.intoto.json \
      --rerun-comparison \
      --upstream ./work-py/chardet-7.6.0-py3-none-any.whl \
      --rebuild ./work-py/rebuild/*/chardet-7.6.0-py3-none-any.whl \
      --public-key <hex printed when the key signed>

subject   chardet-7.6.0-py3-none-any.whl (4076d795897ce45239825956a1334e134322ecc4bfe84dbb12acd5390de0fbc1)
predicate https://trigon.dev/equivalence/v1
claims    exact
signature verified
rederived exact under wheel@58632c3c627d — the claim holds
```

Drop `--public-key` and it still re-derives; it just says the signature was present and unchecked,
because "unsigned" and "signed by someone you do not trust" are different answers. Edit the payload
and the signature fails. Edit the claimed outcome and **the bytes refute it even with no key at
all** — which is the property that makes an attestation from a rebuilder worth anything.

### Comparing two files you already have

No registry, no container, no network:

```
$ trigon verify upstream.tgz rebuild.tgz
```

This is the whole judgement half, and it is the part with no prerequisites at all.

### A note on `--egress open`

`open` lets the build reach the internet, which is the quick way to try this. It is also the weaker
claim, and the attestation says so: `attestable: false`, because a run with no enforced mirror
cannot show the build fetched nothing it should not have. `--egress mirror-only` puts the build on a
network whose only route out is the time-filtered mirror, and needs that mirror's image built first:

```
$ trigon mirror-image          # compiles trigon in a container; several minutes
$ trigon rebuild pkg:npm/left-pad@1.3.0 --image <as above> --work ./work \
      --egress mirror-only --timewarp auto
…
✔ normalized
```

The image is built from this workspace's source, so it goes stale when the mirror changes. `rebuild`
compares the two and says so before the build starts rather than after it fails inside the island.

At that tier the deps phase runs *inside* the island, so everything it fetches comes through the
mirror — including the toolchain. Node is downloaded over the mirror's `/-toolchain/` route, which
proxies a short compiled-in allowlist of distribution hosts and refuses everything else. A base
image that already carries the right toolchain skips the hop entirely.

### Asking a model

Off unless you name a provider. The ladder tries a checked-in definition, then the ecosystem
heuristic, and only then — if `--model` says so — asks a model for a strategy:

```
$ trigon rebuild pkg:npm/some-package@1.0.0 --model ollama:qwen2.5:0.5b …
$ trigon rebuild …  --model anthropic:claude-opus-5      # $ANTHROPIC_API_KEY
$ trigon rebuild …  --model openai:gpt-5                 # $OPENAI_API_KEY
$ trigon rebuild …  --model openrouter:<model>           # $OPENROUTER_API_KEY
$ trigon rebuild …  --model copilot:auto                 # the Copilot CLI, signed in
$ trigon rebuild …  --model compatible:http://host/v1#m  # vLLM, llama.cpp, a gateway
$ trigon rebuild …  --model replay:run.transcript.json   # a recording; opens no socket
```

Keys are read from the environment, never the command line. A model rung needs the repository, so
it fetches the pinned commit to a local cache first; it declines where there is no source, no
commit, or an answer that will not parse, and the ladder moves on.

When a build fails — or succeeds and produces something that is not the published artifact — the
recipe, the failure and the compressed log go back to the model for another attempt, bounded: six
iterations, a token budget, a wall clock, and a stop as soon as two attempts fail the same way.

A model-derived recipe is recorded as `derivation: model_assisted` **beside** the claim, never
inside it, so a consumer can filter on "no model touched this". It does not change the match
outcome: the provenance cap is about *stabilizers*, and a model-authored one can only ever reach
`normalized_with_caveats`. What keeps a model-written recipe honest is the artifact guard — a build
that downloads its own published output is `Void` however it was derived.

`copilot` is an agent with a shell on your machine, and it is configured here so the model sees no
tools at all. Read the module documentation in `trigon-ai/src/copilot.rs` before using it.

The artifact guard runs either way. If the package's own published bytes — or any of its member
files — arrive over the network, the run is `Void`: not a pass and not a failure, because a build
that downloads its own output reproduces it perfectly and proves nothing.

## Watching a sweep

`trigon sweep` prints its summary once, at the end, into the terminal that launched it. `trigon
watch` reads the same work directory from somewhere else, while the sweep is still running:

```
$ trigon sweep corpora/m1-npm-smoke.txt --image <digest> --work ./sweeps/npm …
$ trigon watch ./sweeps/npm --targets corpora/m1-npm-smoke.txt     # in another terminal
watching on http://127.0.0.1:8099  (read-only; ctrl-c to stop)
```

The board, the two rates with their denominators printed, and the failure clusters ranked by size —
then a cluster page that says whether forty red rows are one problem or three, and a run page with
the log and what the ladder decided.

It never talks to the sweep. It reads the files the sweep already writes, so it survives the sweep's
death: every completed result stays on the page, the silence is labelled with its age, and the
target that was in flight is reported as unknown rather than converted into a failure. Read-only —
there is no write path, and a cluster hands you the `trigon rebuild` line to paste.

Loopback by default, because a work directory holds artifacts fetched from registries and build logs
that may carry credentials. [`docs/18`](docs/18-management-ui.md) has the plan it is being built to.

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
crates/trigon-stabilize-wasm  a stabilizer set archived as a WebAssembly module, and its host
crates/trigon             the binary
xtask                     dependency policy, corpora, golden digests, the differential
docs/                     the design, and what implementing it changed
corpora/                  frozen corpora and declared deviations (manifests only)
scripts/                  the cross-machine verification check
```

## Build and check

```
cargo test --workspace                      # 400 tests
cargo run -p xtask -- policy                # the dependency policy
cargo run -p xtask -- differential          # against the reference implementation
scripts/cross-machine-verify.sh             # the claim a third party can check

# The archived stabilizer set, which needs a second target and is not in the default run:
cargo build -p trigon-stabilize-wasm --target wasm32-unknown-unknown --release
cargo test  -p trigon-stabilize-wasm --features host
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
