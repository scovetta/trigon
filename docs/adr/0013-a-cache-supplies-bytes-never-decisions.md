# ADR-0013. A cache supplies bytes, never decisions

**Status:** accepted

## Decision

Cache upstream fetches **between the mirror and the registry, never between the build and the
mirror**, in three tiers that are governed by different rules because they carry different things:

| tier | keyed by | lifetime | verified |
|---|---|---|---|
| toolchain | sha256 of the tarball | permanent | digest, on every read |
| artifact | upstream URL | permanent | digest the registry published, on every read |
| index | upstream URL + the instant it was fetched | bounded, and recorded in the run | not verifiable — see below |

The rule is [ADR-0012](0012-base-images-supply-bytes-not-decisions.md)'s, applied to a second
component:

> A cache may supply **bytes** the evidence does not pin. It may never supply a **decision** the
> evidence does pin — and where it must, the run says so.

A `.crate`, a `.tgz`, a wheel and a Node tarball are bytes: immutable by registry policy, named by a
URL that already contains the version, and carrying a digest the registry published. Serving one
from disk instead of from the network cannot change any answer, and re-checking the digest on every
read makes that a property rather than a hope.

A packument is a decision. It is the document that determines which versions exist, and therefore
which versions a build resolves. That is the tier this ADR spends its words on.

## What prompted it

The question was whether to stop re-fetching the same bytes every run. The measurement, from one
186-run npm sweep at `mirror-only`:

| route | fetches | bytes | distinct URLs | if each were fetched once |
|---|---:|---:|---:|---:|
| index | 57,219 | **25.70 GB** | 4,962 | **1.52 GB** |
| toolchain | 181 | 8.66 GB | ~30 | ~0.20 GB |
| artifact | 85,962 | 4.87 GB | 14,138 | 2.40 GB |
| | **143,362** | **39.23 GB** | | **~4.1 GB** |

Two things in that table are not what anyone predicted.

**Indices are two thirds of the traffic, and 94% of that is redundant.** Tarballs — the obvious
thing to cache — are the smallest of the three routes. One document, `registry.npmjs.org/npm` at
22.3 MB, was fetched 309 times for 6.89 GB: **18% of the entire sweep's egress for a single
packument**, fetched every time only because `npx --package=npm@X` resolves npm before it runs
anything.

**Only 8% of index fetches repeat within a single run.** So a per-run memo is worth almost nothing
and the entire prize is across runs — which is exactly the axis where staleness becomes a
correctness question rather than a performance one.

## Why the cache goes behind the mirror, not in front of it

The mirror is where the evidence is made. `guard.refuses(url)` rejects a build fetching its own
published artifact *before* the request is issued; `guarded_stream` hashes every body as it passes
and writes the row that `rebuild/network.jsonl` is made of; the time filter runs on every index
request. A cache that answered the build directly would sit in front of all three, and the
transcript's one claim — that it lists everything that crossed — would become false.

Behind the mirror, none of that changes. The guard still runs first, the bytes still flow through
the same hashing stream, and the transcript is byte-for-byte what it would have been. The cache
becomes an answer to "where did the mirror get this", which is a question the run record can hold,
rather than to "what did the build receive", which is a question it must never be vague about.

## The objection this has to answer

ADR-0012 already rejected a mirror-side cache, in as many words: *"a cache inside `trigon-mirror` is
invisible to the attestation and sits beside the guard that enforces 'the build must not fetch its
own published artifact'. A store whose entries are verified by hash on every use is a different
proposition from one that is trusted because it is warm."*

That objection is correct and this ADR does not overturn it — it takes the escape clause the last
sentence already names. The toolchain and artifact tiers are verified by hash on every use, so they
are the "different proposition" 0012 allowed for. They are not trusted because they are warm; they
are trusted because the digest matches, and a cache entry that fails that check is a cache miss.

The index tier has no such escape. There is no published digest for "the packument as it stood",
so nothing can re-derive whether a cached one was right. This ADR therefore does **not** claim the
index tier is safe by construction. It claims something weaker and checkable:

**Because every index request is filtered to an instant already in the past, a stale snapshot and a
live fetch can differ in exactly one way.** Versions published after the snapshot are excluded by
the filter regardless. What remains is a version *unpublished* between the snapshot and now — and
for that case the older snapshot is arguably the more faithful document, since it is closer to what
the publisher's own resolver saw.

"Arguably" is not "provably", so the tier carries two obligations rather than an argument:

- **The snapshot's fetch instant goes in the run's pin evidence.** Without it, "resolved against the
  index as it stood at moment M" quietly becomes "resolved against our copy of it from day D", and
  nothing in the record distinguishes them. A reader must not have to know this ADR exists to find
  that out.
- **A control fetches live and compares.** It re-runs the filter against a fresh upstream document
  and compares the digest of the filtered result to the digest the cached path produced. This
  codebase's most repeated defect is a control that fails open and reports success
  ([`16-findings.md`](../16-findings.md) passim); a cache with no such check is a silent correctness
  dependency on a document nobody looks at any more. `--no-cache` must therefore be a supported
  path and not a debugging flag that has rotted.

## Alternatives

**Cache nothing, as today.** Honest and expensive: 39 GB and 143,000 requests per sweep, most of it
re-fetching one of 4,962 documents. The cost is not only ours — it is 309 requests to npm's CDN for
one 22 MB file that did not change between any two of them.

**Cache artifacts only.** The safe subset, and it collects the *smallest* slice: 2.4 GB of 39 GB.
Choosing it would mean the measurement above was taken and then ignored.

**Cache indices per sweep rather than permanently.** Captures nearly all of the 25.7 GB, because the
309 fetches of the npm packument all happened within hours of each other, and bounds staleness to a
single invocation by construction. This is the conservative form of the index tier and is what it
should ship as; the bounded lifetime in the table above is that, not a TTL picked by taste.

**Pre-seed from a snapshot of the registry.** Solves the wrong problem — the cost is repetition
within our own workload, not cold start — and it would make us responsible for the completeness of
a mirror of crates.io or npm, which is a different project.

## What this costs, stated plainly

- **A disk cache introduces eviction, concurrent writers and partial writes**, none of which the
  mirror has today. That is the bug class that produced `trigon/client-corrupted-download` — a
  partially-written entry served as whole is precisely the failure that took three investigations to
  attribute. Every entry must be written to a temporary path and renamed, and read back through the
  same digest check as the network path.
- **The index tier weakens a claim we currently make strictly.** Today the mirror provably filtered a
  document it fetched moments earlier. After this, it filtered a document it fetched at a recorded
  earlier instant. That is a real reduction and the run record has to carry it rather than round it
  off.
- **The numbers are npm-shaped.** PyPI's simple-index pages are far smaller and Cargo's sparse index
  is a line per version, so the index tier's payoff elsewhere will be a fraction of 25.7 GB. The
  artifact and toolchain tiers generalise; the index tier's prize is an npm fact.
- **It makes a fast path the default and the slow path the test.** Whenever that happens the slow
  path stops being exercised, which is the mechanism by which `--no-cache` would rot. The control
  above is the only thing standing against it, so it has to run on a schedule rather than on request.
