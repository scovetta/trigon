# ADR-0004. Hand-written archive writers, with copy-on-write bodies

**Status:** accepted

## Decision

Use ecosystem crates for archive **readers**: `tar`, `zip`, `flate2`. **Hand-write all three
writers.** Model archive entry bodies as copy-on-write over an `mmap`, materializing on mutation.
Put nested-archive recursion in the archive model as **structure**, not in a stabilizer.

## The writers have to be ours

| Format | Why the crate falls short |
|---|---|
| tar | `tar::Header` is a `[u8; 512]` newtype with no first-class PAX-record emission. Stabilization depends on **forcing PAX format** so that a normalized timestamp field survives at all. Left alone, the writer may emit USTAR and drop the field, and the two sides could then differ over whether the field is representable. |
| zip | The crate cannot set general-purpose bit flags, creator or reader version, or zeroed CRC and size fields. Stabilization zeroes all of them. |
| gzip | `GzHeader` does not expose XFL and FEXTRA reliably. |

About 800 to 1000 lines, two weeks including fuzzing. **Byte-exact output is the product, so this is
the wrong place to economize.**

## One finding makes it tractable

**The stabilized form contains no compressed data.** Stabilizers set zip `Method = Store` and gzip
`Compression = none`, so the stabilized stream never reaches a deflate encoder. The usual worry about
porting from Go, that `compress/flate` and `miniz_oxide` emit different bytes for the same input,
never arises. A stored-only zip writer emits a local file header, the name, the raw bytes, a central
directory header, and an end-of-central-directory record, plus zip64 where needed. No compressor
fidelity required.

## Copy-on-write

The prior art buffers whole archives in memory and documents the choice as intentional, because tar
is single-pass and sorting needs the whole list. The reasoning holds and the conclusion goes too far.

**Sorting needs the entry *list* buffered, not the entry *bodies*.**

With `Body::Original { src: Arc<SourceMap>, off, len }` backed by `memmap2`, sorting touches only
`Vec<Entry>` and zeroing timestamps touches only headers, so a 2 GB wheel stabilizes at close to zero
heap. Without it, that wheel across two sides in raw and stabilized form comes to roughly 8 GB and
OOM-kills a worker. An OOM kill looks like a build failure in the metrics, which is where this bug
hides. Bounded spill through `SpooledTempFile` handles the large entries that do get mutated.

## Recursion belongs in the model

The prior art implements gem inner-archive recursion **as a stabilizer**, and swallows the error. A
malformed `data.tar.gz` produces a different stabilized digest with no signal at all, which is a
correctness bug in a signed value.

Making nesting a `Body::Nested` variant, decided at parse time and walked by the walker, means a
parse failure keeps the body inline and emits `NoteCode::NestedParseFailed`. The run reports that it
could not see inside rather than changing its answer without telling anyone.

## Limits the prior art lacks

We decompress attacker-controlled bytes. `RecursionLimit` at 4, `MaxInlineBytes` at 8 MiB per entry,
`MaxInlineTotal` at 256 MiB, `TotalExpandedBytes` at 4 GiB, `MaxEntries` at one million. Breaching a
limit produces a note or an `Unsupported` verdict, and never a silent truncation.

## De-risking it

M0, in full. A differential corpus test asserting stabilized-digest equality against the Go
implementation over 3,000 to 5,000 real artifacts, proptests for idempotence and round-trip, and
fuzzing. See `13-roadmap.md` §3.
