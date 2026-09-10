# 15. Corpora

Five corpora, four of them frozen, all of them addressed by content hash. Every result Trigon quotes
names the corpus it came from and that corpus's hash, because otherwise "reproduction rate went up"
cannot be told apart from "somebody edited the corpus".

| Corpus | Size | Built in | Used by | Model calls |
|---|---:|---|---|---:|
| `m0` | 3,000 to 5,000 artifacts | M0 | differential test against the Go stabilizer | 0 |
| `smoke` | ~50 targets | M1 | every pull request, replay only | 0 |
| `dsl` | 53 targets | M1 | flow-DSL coverage, imported from the prior art | 0 |
| `common-path` | 400 targets | M1 | the reproduction rate M1 reports | 0 |
| `regression` | ~500 targets | M3 | nightly, live | yes |
| `sweep-sample` | ~5,000 targets | M4 | weekly | yes |

## 1. The manifest format

One file per corpus, in `corpora/<name>.toml`, checked in. Digests make the corpus a fixed object
rather than a query that returns different rows each week.

```toml
schema = 1
name = "m0"
description = "Differential-test corpus for the archive and stabilizer stack."
created = "2026-09-14"

# Sampling is recorded, not just the result, so the corpus can be regenerated
# and the regeneration argued with.
[provenance]
method = "stratified-by-format-and-size"
source = "ecosystem download counts, 2026-09-01 snapshot"
seed = 20260901
script = "xtask/corpus/build-m0.rs"

[[artifact]]
purl = "pkg:npm/left-pad@1.3.0"
file = "left-pad-1.3.0.tgz"
url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
sha256 = "e9f1a3b0…"
bytes = 2412
format = "tar+gzip"
# Why this one is in the corpus. Freeform, and it earns its place at review time.
tags = ["tiny", "no-nested", "pure"]

[[artifact]]
purl = "pkg:gem/rails@7.1.3"
file = "rails-7.1.3.gem"
url = "https://rubygems.org/downloads/rails-7.1.3.gem"
sha256 = "4b2d…"
bytes = 8_617_984
format = "tar"
tags = ["nested:2", "yaml-metadata", "signed"]
```

`corpus_hash` is SHA-256 over the sorted `sha256` values joined by newline. It covers the artifacts
and nothing else, so editing a description or a tag leaves the hash alone while adding or removing an
artifact moves it. Every run records it.

## 2. The M0 corpus

The one on the critical path. Its job is to exercise every branch of the archive and stabilizer code
against a reference implementation, which means it is stratified by **structure**, not by popularity.

| Stratum | Target count | Why |
|---|---:|---|
| tar+gzip, small (<1 MB) | 800 | The common npm and crates case |
| tar+gzip, large (>50 MB) | 100 | Copy-on-write and spill paths |
| zip, small | 800 | Wheels, nupkgs, jars |
| zip64 | 50 | The 4 GB and 65,535-entry boundaries |
| Nested (`.gem`) | 400 | Two layers, YAML metadata, the recursion the prior art gets wrong |
| Non-UTF-8 paths | 100 | `EntryPath` as bytes rather than `String` |
| **Duplicate entry paths** | 100 | The sort tiebreaker in [`05`](05-archive-and-normalization.md) §2.2 (6) |
| **Long names (>100 bytes)** | 150 | PAX versus GNU, the first thing to diverge |
| **Non-regular entries** | 150 | Symlinks, hardlinks, directories, devices, FIFOs |
| Data descriptors, stored entries | 100 | zip general-purpose bit-flag handling |
| Empty archives, single-member | 50 | Degenerate cases |
| Deliberately malformed | 200 | Truncated, bad CRC, bad checksum, recursion bombs |

The last four strata are the point. A corpus sampled by download count would be 95% small pure-Python
wheels and would exercise none of them, and every one of them is somewhere our writer and Go's writer
can disagree.

**Finding them.** The rare strata are the work. Popularity sampling produces the first two rows for
free; the rest come from a scan that reads headers only:

```
xtask corpus scan --ecosystem npm --limit 50000 \
      --want duplicate-paths,long-names,non-regular,non-utf8 \
      --out candidates.jsonl
```

The scanner streams each artifact, parses it with the production parser, records which strata it
satisfies, and discards the bytes. It never keeps an artifact it does not need. Expect to scan tens
of thousands of artifacts to fill the 100-target duplicate-path stratum, which is why this runs once
and the result is frozen.

**Where this actually stands.** A first scan of 526 artifacts across npm, PyPI, crates.io and
RubyGems produced `corpora/m0.toml`, 58 artifacts selected rarest stratum first:

| Stratum | Found in 526 | Selected |
|---|---:|---:|
| plain | 316 | 8 |
| empty-members | 88 | 8 |
| tiny | 84 | 8 |
| nested-archives | 35 | 8 |
| long-names | 17 | 8 |
| many-members | 8 | 8 |
| large | 5 | 5 |
| stored-entries | 3 | 3 |
| pax-records | 1 | 1 |
| zip64 | 1 | 1 |
| **duplicate-paths** | **0** | 0 |
| **non-regular-entries** | **0** | 0 |
| **non-utf8-paths** | **0** | 0 |

The three empty rows are the ones the table above calls the point, and 526 artifacts did not turn up
a single instance of any of them. That is the predicted result rather than a surprise, and it is why
the target counts assume a scan two orders of magnitude larger. Until that scan runs, those three
strata are covered by hand-built fixtures in the unit tests and by nothing in the corpus, which is
the honest description of the current state: the differential is far stronger than it was at five
artifacts and it still does not exercise duplicate paths, symlinks or non-UTF-8 names against the
reference.

Two enumeration notes worth keeping. npm's `_changes` replicate feed returns mostly deletions, so
the search API is the usable enumerator and it carries the version inline, which saves a packument
fetch per candidate. And a published artifact our parser rejects is a finding rather than scan noise,
so the scanner reports fetch failures and parse failures separately.

**Malformed inputs are synthesized, not found.** `xtask corpus synth` mutates known-good artifacts
under a recorded seed: truncate at a header boundary, corrupt a CRC, nest an archive five deep, point
a hardlink at a member that does not exist. The mutation script is checked in and the outputs are
addressed by digest like everything else.

## 3. The M1 corpora

`dsl` is the prior art's `definitions/` directory imported verbatim. 53 targets, of which 51 are
PyPI. It exercises the flow DSL, the named-tool registry and `custom_stabilizers`, and it tells us
nothing about the common path, because every file in it exists because inference failed on that
package.

`common-path` is 400 targets, 200 npm and 200 PyPI, stratified by build system rather than by
popularity:

| npm | | PyPI | |
|---|---:|---|---:|
| No lifecycle script (`npm/pack`) | 90 | flit or hatch | 50 |
| `prepare` or `prepack` present | 60 | setuptools, `pyproject.toml` | 60 |
| TypeScript build | 30 | setuptools, `setup.py` only | 40 |
| Monorepo subdirectory | 20 | poetry | 30 |
| | | maturin or a native extension | 20 |

Sampled by prevalence within each stratum, so the targets are packages people import while the
distribution reflects the work the builder has to do. This is the corpus M1 quotes a reproduction
rate from, and the stratum breakdown is reported alongside the headline number, because an aggregate
that hides a 20% rate on native extensions is not a number anyone can act on.

## 4. Fetching, politely

The fetch script is boring and the politeness is not optional. A corpus build downloads thousands of
artifacts from registries that owe us nothing.

```
xtask corpus fetch --manifest corpora/m0.toml --dest ~/.cache/trigon/corpora/m0
```

- A declared `User-Agent`: `trigon-corpus/0.1 (+https://github.com/…; contact@…)`.
- One request at a time per host by default, `--concurrency` capped at 4, with jitter.
- `Retry-After` honoured, and a 429 or 503 backs the whole fetch off rather than the one worker.
- Every response verified against the manifest digest before it lands. A mismatch is a hard failure,
  because it means the registry served something other than what the corpus pins.
- Resumable, so an interrupted fetch does not re-download what it already has.

Fetched artifacts live in a cache directory outside the repository and are **never checked in**. The
manifest plus the fetch script is what version control holds. Where an artifact disappears from a
registry, the manifest entry stays, the fetch reports it, and the corpus hash is unchanged: a corpus
is a statement about what we tested, and rewriting it to match what is currently downloadable would
defeat that.

A mirror of the M0 corpus lives in our own object store for CI, populated once from the manifest, so
continuous integration never touches a public registry.

## 5. Changing a corpus

Adding or removing an artifact moves `corpus_hash`, which makes every prior result incomparable to
every later one. That is correct and it is also expensive, so corpora change on a stated cadence
rather than whenever someone finds an interesting package.

- `m0` freezes at the end of M0 and changes only to add a stratum, which happens when a bug escapes
  it. Each addition is a pull request explaining what got through.
- `smoke` and `regression` grow when a failure class appears often enough to deserve a permanent
  guard, which is the same review that promotes a repair into a rule
  ([`07-ai.md`](07-ai.md) §5).
- `common-path` is resampled once a year, and both versions are kept and quoted separately for a
  release, because a resample is not an improvement.

Digest changes inside a corpus are a different matter and are handled by
`trigon bench regold` ([`05-archive-and-normalization.md`](05-archive-and-normalization.md) §6). That
covers the expected outputs. This section covers the inputs.
