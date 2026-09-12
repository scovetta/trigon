# 16. What building it changed

The rest of `docs/` was written before any code existed. This is what implementing it taught, with
the measurements, and it is deliberately separate: the design documents describe the system as it is
meant to be, and rewriting them to match every discovery would erase the record of which beliefs
were wrong and how they were found out.

Three kinds of entry appear here. A **correction** is a place the design said something false. A
**gap** is something it did not anticipate at all. A **measurement** is a number that replaces an
estimate. Where a design document has been amended, it says so.

---

## 1. The bug class that dominated

Almost every real defect found during M1 and M2 had the same shape:

> **Configuration that looks applied and is not, with the failure surfacing somewhere that
> implicates the package instead of us.**

Six instances, none of which the design anticipated:

| What | How it looked | What it was |
|---|---|---|
| `PIP_TRUSTED_HOST` absent | builds resolved against today's index while every log line said "pinned" | pip warns once about an untrusted plain-HTTP index, then resolves as though none were configured |
| `export` in the deps phase | the mirror pinned dependency installation and not the build | phases are separate scripts; the variable is gone by the next one |
| tool-level `needs` | `env/toolchain-crashed` on two npm targets | a tool whose steps all skip still contributes its needs, so Debian's Node came in and a pinned Node 10 loaded its modules and aborted |
| `reqwest`'s `gzip` feature | npm reported corrupt tarballs | the proxy transparently gunzipped artifacts, and the guard hashed the decompressed bytes |
| `build.log` in the collect directory | 26 targets reported `error:upstream` | the artifact collector picked the newest file, which was the log |
| `npm` calling `setuid` | a build that worked at image-build time failed at run time | our run-time isolation denies it, and npm crashes inside its own error handler |

The common property is not that each was subtle. It is that **each failed silently in a direction
that blamed something else.** Four of the six produced a number that looked like a package problem:
a low reproduction rate, a build failure, a corrupt artifact, an upstream error.

Two lessons, both now reflected in the code:

**Anything that claims to be applied should be observable.** The mirror's request counter is what
eventually exposed the pip finding — `0 index request(s)` had been printed on every PyPI run for
weeks and reads exactly like a build that happened not to need anything. A counter nobody checks is
better than no counter, but a build that *asserts* its pin took effect would have caught it on the
first run. This is unbuilt and it is the most valuable thing on the list.

**The taxonomy has to be able to blame us.** `trigon/mirror-corrupted-artifact` exists so that our
own corruption is counted as ours. Before it, the same symptom was charged to `has-flag` in the
reproduction rate. `Fault::Bug` and `Fault::Infra` are not decoration: without them a reproduction
rate silently becomes a measure of our own reliability wearing the costume of a claim about
packages.

---

## 2. Measured rates, and what moved them

All figures on the M1 smoke corpora at `--egress open`, against the baseline established before any
of the work below.

One measurement note, because it changes how much the numbers are worth. The npm figures come from a
full sweep. The final PyPI figure comes from **re-comparing the stored artifact pairs** from the
preceding sweep with the new stabilizer in place, rather than from rebuilding all seventeen targets
again: the comparison is the real one and runs over the same bytes, but the builds are not fresh, so
it does not re-test build-time nondeterminism. The 73% figure that precedes it is a full sweep.

### 2.1 PyPI: 33% → 80%

| | reproduce | reach comparison |
|---|---|---|
| baseline | 5 of 15 (33%) | 15 of 17 |
| after three fixes (full sweep) | 11 of 15 (73%) | 15 of 17 |
| after `wheel-metadata-eol` (re-comparison) | 12 of 15 (80%) | 15 of 17 |

Six targets flipped, no regressions. Three fixes, in the order they were found, each exposed by the
one before it:

1. **Pin the build backend the wheel names.** The heuristic said "nothing in PyPI's metadata says
   what the build needed", which is true of the metadata and false of the artifact: every wheel
   carries `Generator:` in its own `.dist-info/WHEEL`. Reading it is an algorithm, not a search —
   the same argument [`07`](07-ai.md) §2.1 makes for tree-hash scoring over prompting. Nine of ten
   divergences were confined to `WHEEL`, `METADATA` and the `RECORD` that follows from them, with
   every source file byte-identical.

2. **Make the mirror actually apply.** See §1. The backend pin was the probe that found it: the
   first thing to ask the mirror for a package *after* the index was configured.

3. **A pin is a constraint, not an install.** The environment that matters is the isolated one a
   PEP 517 frontend builds. Pre-installing the backend does nothing for it, and disabling isolation
   to compensate strands every other declared build requirement — `attrs` needs `hatch-vcs` and
   `hatch-fancy-pypi-readme` and stops with "Unmet dependencies". `PIP_CONSTRAINT` pins a version
   inside an environment somebody else populates.

A fourth, `wheel-metadata-eol`, flipped one more (§4).

### 2.2 npm: 92% → 93%, and 13 of 20 → 15 of 20

The rate barely moved because it was already high; what moved was how many targets *reached* a
comparison. Removing Debian's `npm` and setting `npm_config_unsafe_perm` took two targets from
`build-failed` to reproducing.

### 2.3 What the remaining failures are

Every failure in both corpora is now named, and the clusters are the diagnosis:

| cluster | what to do |
|---|---|
| `env/missing-shared-library:libatomic.so.1` | fixed: declared as a dependency, with the distro map handling Debian's soname suffix |
| `git/commit-not-in-repo` | nothing to repair — npm's recorded `gitHead` was force-pushed away |
| `trigon/mirror-corrupted-artifact` | **open**, ours, intermittent; see §5 |
| `iniconfig` divergence | setuptools-scm embeds the git commit; the publisher built without git metadata |
| `py-cpuinfo` divergence | `bdist_wheel` names the *wheel* package, so setuptools' version is not recorded anywhere |

The last two are limits of the evidence rather than bugs. They are worth stating as such: a system
that reports them as failures without saying why teaches its operators to ignore failures.

---

## 3. Corrections to the design

### 3.1 `Signer` and `LlmProvider` are synchronous

[`09`](09-attestations.md) §3 specifies `#[async_trait] Signer` and [`07`](07-ai.md) §7 specifies the
same for `LlmProvider`. Both are synchronous in the implementation, for one reason each:

- The **verifier build** links `trigon-attest` and must contain no async runtime. That is the claim
  `xtask policy` enforces and the one a sceptic can check with `cargo tree`. An async method would
  drag `tokio` across the judgement line for the benefit of signers that do not exist yet.
- The **replay provider** makes no call at all, and a test harness should not have to hold a runtime
  to use it. A synchronous trait is callable from an async context by whoever owns the runtime; the
  reverse needs an executor everywhere.

Network implementations block in their own client or live behind an async façade in a crate below
the line. Both documents now record the deviation.

### 3.2 Internal tagging plus `serde_path_to_error` does not work

[`04`](04-strategies.md) §2.2 specifies parsing a strategy by internal tag and reporting errors
through `serde_path_to_error`. Internal tagging buffers through serde's `Content`, which loses the
path — the two are incompatible. The parser reads `schema` and `kind` manually and then deserializes
the payload directly, which preserves the path and is what the repair loop depends on.

### 3.3 A tool's `needs` are collected even when its steps are skipped

[`04`](04-strategies.md) treats `needs` as "what this tool requires". The implementation collects
tool-level `needs` whether or not any step survives its condition, which made a conditional tool
contribute a system package to every build that referenced it. Step-level `needs` behave as
documented. The fix is to put a need on the step that uses it; the two npm tools that got this wrong
now do.

### 3.4 `trigon-store` is not a database yet

[`10`](10-scale.md) §4 specifies Postgres tables for `runs`, `verdicts` and `rollups`. None of them
is needed to sign a statement, and building a schema before there is a fleet to put in it means
maintaining one whose shape is a guess. M2's store is the content-addressed layout
[`09`](09-attestations.md) §7 already specifies — blobs, run records, attestations — over
`object_store`, so cloud backends are a cargo feature rather than code. The tables arrive with M4.

### 3.5 The capability taxonomy was missing the label the Builder is most for

[`07`](07-ai.md) §6.2 lists `trivial-deterministic`, `needs-source-discovery`, the four
`needs-repair-*` labels, and `known-unreproducible`. Labelling the two smoke corpora turned up a
target none of them fits: `escalade 3.2.0` publishes `dist/index.js` and `dist/index.mjs`, which
`npm pack` alone never produces. Nothing is being *repaired* — the first attempt is not wrong, it is
absent. A recipe has to be inferred from the repository or its CI.

Filing it under the nearest `needs-repair-*` label would have hidden the most common thing the
Builder actually does, and the whole point of labelling by capability is that a model firing on the
wrong class is visible. The taxonomy gains `needs-build-inference`, between source discovery and
repair.

### 3.6 `mirror-only` egress has to carry the toolchain too

[`08`](08-execution.md) describes the tiers as a statement about *dependency* traffic, and the tools
were written to match: `npm/install-node` fetched `https://nodejs.org/dist/...` directly, with a
comment noting that this fails at `mirror-only`. It does, and it fails late. Rootless `podman build`
cannot join a named network, so at that tier the deps phase is deferred into the container — inside
the island, where the mirror is the only reachable host. The image builds, the source checks out,
and then the first phase that needs the network dies at `Network is unreachable` in a way that reads
as a broken sandbox rather than as a strategy naming a host it cannot reach.

The tier is not wrong; the seam was missing. The mirror now serves `/-toolchain/<host>/<path>`
against a compiled-in allowlist (`nodejs.org`, `unofficial-builds.nodejs.org`), and templates write
the URL through a `toolchain_url()` function that yields the upstream URL when no mirror is
configured. No time filter: a toolchain URL names its exact version, so the bytes are a function of
the URL and there is nothing for a date to remove. The guard still runs on the body, because "the
artifact arrived dressed as a toolchain" is exactly the route it exists to close.

The allowlist is the load-bearing part and is deliberately compiled in. At `mirror-only` the mirror
is the build's only route out, so any host reachable through it is a host a strategy can be told to
download an executable from; a wildcard here would quietly restore `open` egress under a different
path. Matching is exact rather than by suffix — the obvious `ends_with` rule accepts
`evil-nodejs.org`.

Two more came out of running it to the end, both from the same root cause — a phase that used to run
as an image layer now runs inside the container:

- **`tar` cannot preserve ownership there.** The official Node tarballs record uid/gid 500. As an
  image layer the user namespace maps a wide range and tar is happy; inside the container the range
  is narrow, so tar fails on every entry and exits non-zero. The phase after a 40-second download
  dies with 700 lines of `Cannot change ownership`, and the fix is `--no-same-owner` — file
  ownership inside a toolchain is not part of what we reproduce.
- **The mirror image goes stale silently.** It is compiled from this workspace, so an image built
  before a mirror change serves the old routes. What the operator sees is a `400` from inside the
  island and a strategy that looks wrong; what it is, is an old binary. `rebuild` now compares a
  digest of `trigon-mirror`'s source against a label on the image and warns before the build starts.
  Scoped to that one crate deliberately: a digest over the workspace would fire on every commit, and
  a warning that always fires is not a warning.

Beside them, a message that was actively misleading: a run at `mirror-only` reported *"this runner
enforces no mirror"* because the local runner is never attestable at full trust. Two different
reasons — no boundary, versus a boundary with no network transcript — and only the second is true
there.

With all of it in place, `left-pad 1.3.0` reproduces `normalized` at `mirror-only` on a stock Debian
image.

---

## 4. A stabilizer the reference does not have

`wheel-metadata-eol` normalizes CRLF to LF in the four files a wheel builder *generates*. A publisher
on Windows gets `\r\n` in `METADATA` because the tool opened the file in text mode; we cannot
reproduce Windows text-mode I/O from a Linux builder, so normalizing is the only route to a match.

It is worth recording how it was reviewed, because the process is the point:

- **Impact preview before merge.** Across the M1 PyPI corpus: one flip (`sniffio`), no other verdict
  moved. Two of 58 M0 artifacts carry CRLF metadata, one of them named `feagi_bv_windows`.
- **The differential refused it** until it was declared. `0 unexplained` became `2 unexplained`,
  which is the test doing its job: a pass the reference implementation lacks cannot go green without
  a prose reason in `corpora/deviations.toml`.
- **The scope is the whole argument**, so it is tested from both sides. A `.py` file keeps its CRLF —
  the author's choice, part of what is under test. A hand-written `dist-info/LICENSE` keeps its CRLF,
  because `dist-info/` is not a licence to rewrite everything inside it. A lone `\r` is content.

This is the first stabilizer added on evidence from a live corpus rather than from the reference
implementation's catalogue, and the review path in [`05`](05-archive-and-normalization.md) §6 worked
as written.

---

## 4b. A core module where the design says component

`docs/09-attestations.md` §7.1 specifies stabilizer sets shipping as **WASM components**, instantiated
under `wasmtime`. What ships is a **core module** for `wasm32-unknown-unknown`, with a four-function
ABI over a byte buffer.

The component model means `wasm32-wasip2`, WIT definitions and `cargo-component`. A core module gets
the whole benefit of the criterion — an archived set that *executes*, so a claim made under a set the
verifier's binary does not carry is checkable rather than merely describable — with a host that needs
no WASI implementation at all, and a toolchain that is one `rustup target add`. What it gives up is a
typed interface for guests written in other languages, which begins to matter when somebody writes
one.

Two things about it are worth knowing before relying on it.

**Host and guest share a crate.** The ABI — a packed `(ptr << 32) | len` return, an append-only
format numbering — has one definition rather than two that drift. Two crates agreeing on a calling
convention by comment is two things to keep in step.

**An archived set can reach `NormalizedWithCaveats` and never `Normalized`.** The provenance cap
needs each applied stabilizer's risk tier and provenance, and a module that returns bytes cannot
supply them. The ABI could be extended to report an `applied` list, and then the cap would rest on
what the module says about itself — which is exactly the wrong place for it. So the archived path
claims the weaker outcome on the weaker evidence, and a `Normalized` claim re-derived through its
archived set reports `NormalizedWithCaveats` and reads as refuted. That is a real limitation rather
than a rounding error: it is honest, and it is not yet good enough for a verifier checking an old
`Normalized` claim. Revisit if the interface ever becomes typed.

`wasmtime` is behind a feature and on the verifier's forbidden list: 100 crates by default, 142 with
`--features wasm`. The small tree is the claim a sceptic checks instead of trusting us, and a
verifier who only checks claims made under their own set should not pay for a runtime they never
use.

---

## 5. Open

**An archived `Normalized` claim re-derives as `NormalizedWithCaveats`.** See §4b: the provenance cap
cannot be confirmed from bytes alone.

**`trigon/mirror-corrupted-artifact`.** Intermittent; npm retries and then fails with
`Z_DATA_ERROR`. Ruled out so far: transparent gzip decompression (fixed, and a serial fetch through
the mirror is byte-identical to the registry's); concurrency (twelve parallel fetches, all
identical); packument integrity mismatch (the declared sha512 matches the served bytes exactly). It
is correctly classified as ours with nothing to repair, so it does not contaminate any reproduction
rate, but it is unexplained.

**Two clean re-runs before publishing a divergence.** [`10.3`](00-overview.md) requires it and
nothing implements it yet.

**The corpora are smoke sets.** Twenty npm and seventeen PyPI targets, not sampled by prevalence.
Every percentage here is a signal about the pipeline, not an estimate of an ecosystem, and
[`15`](15-corpora.md) §2 says what a real corpus needs.
