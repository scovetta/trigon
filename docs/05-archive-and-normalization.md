# 05. Archive model, stabilization, and comparison

The heart of the system, the hardest thing in it to build, and the part we sign. A bug here is a
bug in a cryptographic claim.

## 1. Why stabilization rather than bit-for-bit

Bit-for-bit reproducibility suits a distribution that controls its own toolchain. It suits nobody
verifying artifacts other people built, in environments we do not control, with toolchains that were
current years ago.

So we **normalize known classes of benign nondeterminism from both artifacts identically, then
compare.**

```
equivalent(rebuild, upstream)  ⟺  stabilize(rebuild) == stabilize(upstream)
```

Three rules keep that honest, and they come before any of the machinery:

1. **Both sides get the identical transform.** A stabilizer is `Fn(&mut Archive)`. Nothing lets it
   condition on the comparison or on which side it is processing, because it takes no parameter it
   could cheat with.
2. **The attestation names every applied stabilizer**, with its risk tier and provenance. A consumer
   who rejects a particular normalization can see that it fired and throw the result out.
3. **A content digest versions the stabilizer set**, and that digest sits in the run key and in every
   attestation. Change the set and you invalidate caches and make old and new results
   non-comparable, both of which are what should happen.

The caveat belongs in the text rather than a footnote. Executing code can condition on any
observable difference, so normalizing a difference away leaves room for an attacker who makes their
payload depend on, say, an archive timestamp. We judge that building such a payload takes contrived
logic that static analysis catches more readily, while normalizing benign variation buys large and
immediate coverage. Risk tiers exist for the people who disagree: they can demand `Match::Exact`, or
`Match::Normalized` with `risk <= Structural`.

## 2. The archive model

### 2.1 What the ecosystem gives us, and what we write ourselves

| Need | Crate | Verdict |
|---|---|---|
| tar **read** | `tar` | **Use it.** PAX and GNU long-name parsing is battle-tested. |
| tar **write** | none | **Hand-roll (~400 lines).** `tar::Header` is a `[u8; 512]` newtype with no first-class PAX-record emission, and we depend on forcing PAX format so that a timestamp field survives at all. Header checksum, name and prefix split, the PAX `"%d %s=%s\n"` length fixpoint, ordered records, and the long-name rule below. |
| zip **read** | none | **Hand-roll (~250 lines).** Started out delegating to the `zip` crate, and that crate hides the four fields stabilization has to control: version-made-by, version-needed, general-purpose flags, and internal attributes. Walking the central directory ourselves costs 250 lines and gives every field. The crate stays a dev-dependency, where it cross-checks our output the way an external implementation should. |
| zip **write** | none | **Hand-roll (~300 lines).** The crate cannot set general-purpose bit flags, creator/reader version, or zeroed CRC and size fields, and stabilization needs all three. |
| gzip read | `flate2` (`MultiGzDecoder`) | Use it; supplement with a small header reader, since `GzHeader` does not expose XFL and FEXTRA reliably. |
| gzip write | `flate2::GzBuilder` at `Compression::none()` | Workable. Verify the XFL byte, and hand-roll if it comes out wrong. The container runs about 100 lines, and stored-deflate framing is a few more. |
| CRC32 | `crc32fast` | Fine. |
| `ar` (for `.deb`, later) | none | Hand-roll (~60 lines). No maintained crate worth the dependency. |
| `async-compression` | none | **Do not use.** Stabilization is synchronous and CPU-bound, and this crate would drag tokio into `trigon-stabilize` and break the dependency invariant. |

**One finding makes all of this tractable: the stabilized form contains no compressed data.**
Stabilizers set zip `Method = Store` and gzip `Compression = none`, so the stabilized byte stream
never reaches a deflate encoder. The usual worry about porting from Go, that `compress/flate` and
`miniz_oxide` emit different bytes for the same input, never arises. A stored-only zip writer emits a
local file header, the name, the raw bytes, a central directory header, and an
end-of-central-directory record, plus zip64 where needed. No compressor fidelity required.

**Long names take PAX, always.** A path over 100 bytes, or a linkname over 100 bytes, needs an
extension record, and tar has three ways to carry one: a GNU `L`-typeflag entry, a PAX `path=` /
`linkpath=` record, or the ustar `prefix` field, which holds 155 bytes and joins to the name with a
`/`. The third is the trap. It works only when a `/` falls in the right place, so whether a name is
representable depends on where its slashes are rather than on how long it is, and two paths of the
same length end up framed differently.

Our writer emits **PAX for every long name and long linkname**, with no GNU fallback and no use of
the `prefix` field, which stays NUL on every header we write. PAX records are ordered
lexicographically by keyword. We already force PAX for timestamps, so this costs nothing and removes
a whole class of ambiguity. The rule is a stabilizer-independent property of the writer: it applies
whether or not `tar-time` ran.

Where the input used a GNU long name or a prefix split, the output uses PAX, so the stabilized form
differs from the input encoding by design. Each such entry carries a `LongNameReencoded` note. A
writer pinned to the PAX format behaves the same way, so this agrees with the reference rather than
deviating from it.

Budget about 800 to 1000 lines and two weeks including fuzzing. **Byte-exact output is the product,
so this is the wrong place to economize.**

### 2.2 The types

```rust
pub struct Archive {
    pub format: Format,
    pub entries: Vec<Entry>,
    pub trailer: Trailer,
}

pub enum Trailer { Zip { comment: Vec<u8> }, Gzip(GzipHeader), Tar, None }

pub struct Entry {
    pub path: EntryPath,   // BYTES, see below
    pub ordinal: u32,      // position as parsed; the sort tiebreaker, see (6)
    pub kind: EntryKind,   // what this entry IS, see (7)
    pub meta: Meta,        // format-agnostic: size, mtime, mode
    pub raw:  RawMeta,     // format-specific, preserved verbatim
    pub body: Body,
    dirty: bool,           // set by the walker; drives `entries_touched`
}

pub enum EntryKind {
    Regular,
    Directory,
    Symlink   { target: Vec<u8> },
    Hardlink  { target: Vec<u8> },
    CharDevice { major: u32, minor: u32 },
    BlockDevice { major: u32, minor: u32 },
    Fifo,
    Other(u8),             // an unrecognized tar typeflag, preserved verbatim
}

pub enum RawMeta {
    Zip(ZipRaw),   // creator_version, reader_version, flags, method, crc, extra, comment, external_attrs
    Tar(TarRaw),   // typeflag, linkname, uid, gid, uname, gname, devmajor, devminor, pax: Vec<(String,String)>, format
}

pub enum Body {
    Original { src: Arc<SourceMap>, off: u64, len: u64 },  // mmap'd; never touched
    Inline(Bytes),                                          // materialized on first mutation
    Spilled { file: Arc<SpillFile>, off: u64, len: u64 },
    Nested(Box<Archive>),                                   // recursion lives HERE
}
```

Seven choices worth defending:

**(1) Copy-on-write bodies.** Most entries never change. Sorting touches `Vec<Entry>` and zeroing
timestamps touches headers. With `Body::Original` backed by `memmap2`, stabilizing a 2 GB wheel costs
close to zero heap, because entries stream from the mapping into the writer. `fn body_mut()` promotes
`Original` to `Inline` on first mutation.

That answers the question of whether full in-memory buffering scales. The prior art buffers
everything and documents the choice as intentional, because tar is single-pass and sorting needs the
whole list. **Sorting needs the entry *list* buffered, not the entry *bodies*.** Without
copy-on-write, a 2 GB wheel across two sides in raw and stabilized form comes to roughly 8 GB and
OOM-kills a worker. An OOM kill looks like a build failure in your metrics, which is where this bug
hides.

**(2) `Meta` and `RawMeta` stay separate rather than becoming a union.** Format-agnostic
stabilizers, meaning sort entries, zero timestamps and normalize modes, operate on `Meta`.
Format-specific ones match on `RawMeta`. That split is what lets one `Stabilizer` trait serve both
zip and tar, and it removes the need for the prior art's `WithFns(map[Format]Fn)` dispatch table.

**(3) `EntryPath` holds bytes rather than a `String` or a `PathBuf`.** Real npm tarballs contain
non-UTF-8 paths, zip carries an explicit non-UTF-8 flag, and `PathBuf` would bring Windows path
semantics into a format that has none. Sorting over raw bytes also matches Go's `strings.Compare`,
which the differential test in §6 depends on.

**(4) `Body::Nested` makes recursion structural.** The parser decides nesting and the walker walks
it, so no stabilizer is involved. That fixes a real bug in the prior art, where gem inner-archive
recursion lives *as* a stabilizer and swallows its error: a malformed `data.tar.gz` yields a
different stabilized digest with no signal at all. In Trigon a nested parse failure leaves the body unparsed, wherever it already lived, and emits `NoteCode::NestedParseFailed`. The bytes still reach the digest untouched, and the run reports that it could not see inside rather than changing its answer without telling anyone.

**(4a) Descending is not licence to rewrite.** A `.gem` member like `data.tar.gz` is framing the
format defines. A `banner.json.gz` inside an npm tarball is a file the package ships. The parser
cannot tell them apart, because both are gzip members of an outer tar, and treating the second like
the first rewrites a deliverable: re-serializing it stores what was deflated and drops the header
fields the file legitimately carries. One npm tarball in the corpus grew a 4,887-byte member to
66,090 that way.

Two rules keep the distinction. `Body::Nested` carries the bytes it was parsed from alongside the
parsed inner archive, and an inner archive nothing changed writes those bytes back rather than a
re-serialization. And the container passes, the ones that act on the trailer, apply at depth 0 or
where the **profile** says the nesting is structural, which for gems is exactly `data.tar.gz`,
`metadata.gz` and `checksums.yaml.gz`. Entry passes still apply at every depth, so the tar inside a
gem's `data.tar.gz` is normalized as usual.

A pass that hashes members must then ask for `Entry::stabilized_bytes` rather than
`Entry::body_bytes`, because a nested archive has no bytes of its own until it is written. The
alternative, skipping the members it cannot read, is silent membership deletion, and membership
deletion is how a stabilizer turns a real difference into a false match.

**(5) Limits, which the prior art lacks.** We decompress attacker-controlled bytes:

| Limit | Default | On breach |
|---|---|---|
| `RecursionLimit` | 4 | stop descending; `NoteCode::RecursionLimitReached` |
| `MaxInlineBytes` (per entry) | 8 MiB | spill to `SpooledTempFile`; `NoteCode::SpilledToDisk` |
| `MaxInlineTotal` (per archive) | 256 MiB | spill |
| `TotalExpandedBytes` | 4 GiB | abort with `Unsupported { ArtifactTooLarge }` |
| `MaxEntries` | 1,000,000 | abort |

**(6) `ordinal` makes the sort total.** Both tar and zip permit **duplicate entry paths**, and real
archives contain them: a tar built by appending, a zip with a stale local header, a wheel repacked by
a tool that did not deduplicate. Sorting by path bytes alone is not a total order over a multiset, so
two runs over the same input can emit two byte sequences and the digest becomes a coin flip. That is
the exact failure class this whole crate exists to prevent, and it arrives on the first archive with
a duplicate.

The sort key is `(path_bytes, ordinal)`, where `ordinal` is parse position. Ties break by original
order, which is stable, reproducible, and identical on both sides of a comparison.

Duplicates also get a note. An archive whose members are not uniquely named is worth flagging even
when it stabilizes cleanly:

```rust
NoteCode::DuplicateEntryPath   // path, and how many times it appears
```

Members compare positionally within a duplicate group during `Compare`, so upstream's second
`lib/index.js` compares against the rebuild's second `lib/index.js`.

**(7) `EntryKind` decides which stabilizers apply.** The catalogue says "mode → 0777" and
"owners → 0", which is right for a regular file and wrong or meaningless for everything else. tar
carries symlinks, hardlinks, directories, FIFOs, and character and block devices, and each needs a
stated rule rather than whatever the writer happens to do:

| Kind | mode | owners | body | linkname | Notes |
|---|---|---|---|---|---|
| `Regular` | → 0777 | → 0 | preserved | n/a | |
| `Directory` | → 0777 | → 0 | must be empty | n/a | Presence is **preserved**, never synthesized or dropped. Writers disagree about emitting directory entries, and inventing them would change membership. |
| `Symlink` | → 0777 | → 0 | must be empty | preserved verbatim | The mode on a symlink is not meaningful on any platform we target, and normalizing it costs nothing. The target is content. |
| `Hardlink` | → 0777 | → 0 | must be empty | preserved verbatim | The target names another member, so normalizing it would break the reference. |
| `CharDevice`, `BlockDevice` | → 0777 | → 0 | must be empty | n/a | `tar-device` zeroes major and minor. A device node in a package artifact is worth a note of its own. |
| `Fifo` | → 0777 | → 0 | must be empty | n/a | |
| `Other(flag)` | untouched | untouched | preserved | n/a | An unrecognized typeflag is passed through byte for byte and noted. Guessing is worse than declining. |

Two rules fall out of that table and belong in the writer rather than in a stabilizer. An entry whose
kind requires an empty body carries `size = 0` on the wire regardless of what the parser found, and a
parser that finds a non-empty body on such an entry emits `NoteCode::MalformedEntry` and preserves
the bytes rather than discarding them.

### 2.3 The walker

```rust
pub fn walk(a: &mut Archive, cx: &mut Cx, f: &mut dyn FnMut(Node<'_>, &Cx));

pub struct Cx { levels: SmallVec<[Level; 4]>, entry: Option<EntryPath> }
pub struct Level { format: Format, archive_path: Option<EntryPath>, depth: usize }
```

`Cx` mirrors the prior art's stabilization context, so its constraint vocabulary of "at depth 0",
"at minimum depth 1" and "only inside `metadata.gz`" ports into `Stabilizer::applies()` unchanged.

## 3. Stabilizers

```rust
pub trait Stabilizer: Send + Sync + 'static {
    fn id(&self) -> StabilizerId;
    fn stage(&self) -> Stage;            // Default = 0, Patch = 10, Finalize = 100
    fn risk(&self) -> RiskTier;
    fn provenance(&self) -> Provenance;
    fn applies(&self, cx: &Cx) -> bool;
    fn on_archive(&self, _a: &mut Archive, _cx: &Cx) -> Touched { Touched::NONE }
    fn on_entry(&self, _e: &mut Entry, _cx: &Cx) -> Touched { Touched::NONE }
}

/// What one pass changed.
pub struct Touched { pub entries: u32, pub bytes: u64 }
```

**Stages.** `Default` does ordinary normalization. `Patch` runs custom stabilizers supplied by the
definitions repo. `Finalize` handles invariants that depend on every prior pass, and wheel `RECORD`
regeneration is the canonical case: earlier stabilizers change archive membership, `exclude_path`
above all, and `RECORD` is a manifest *of* membership.

**Risk tiers**, which drive the outcome cap:

| Tier | Meaning | Examples |
|---|---|---|
| `Structural` | Reorders or reframes without changing any file's content, **or drops integrity metadata computed over content we are rebuilding** | entry ordering, compression method, gzip framing, checksum and signature exclusion |
| `Metadata` | Rewrites fields that are not the distributed content | timestamps, modes, uid/gid, archive comments |
| `Content` | Rewrites bytes inside a distributed file | line endings, `RECORD` regeneration, PE timestamp and MVID, `.pyc` header |
| `Lossy` | Removes distributed content, or information we cannot re-derive | dropping a source file, dropping documentation |

The placement of signature and checksum exclusion took a second pass. Treating them as `Lossy` caps
every gem, every signed nupkg and every signed jar at `NormalizedWithCaveats`, which strips the clean
tier from an entire ecosystem for no gain in honesty. A `checksums.yaml.gz` is a hash *of* the
members we are rebuilding, and a `.sig` is a signature *over* those members made with a key we will
never hold. Neither is distributed content, and neither can differ while the content matches. They
belong with entry ordering.

`Lossy` keeps its teeth for the case it was written for: a stabilizer that removes something a
consumer would have received. `wheel-direct-url` stays `Lossy`, because `direct_url.json` is a file
the installer reads.

**Totality.** Stabilizers return no error. A parse failure inside one falls back to the original
bytes and emits a note, which leaves no half-stabilized state to reason about. A fuzz target asserts
that `apply` never panics.

They do return `Touched`. `entries_touched` and `bytes_changed` reach the attestation, and a signed
number should not rest on every pass author remembering to set a flag. `applied` then reports only
the passes that changed something, so a pass that was configured and did nothing stays out of the
predicate.

**Sets and digests:**

```rust
pub struct StabilizerSet { pub id: ProfileId, pub members: Vec<Arc<dyn Stabilizer>> }
impl StabilizerSet {
    /// SHA-256 over sorted (id, stage, risk, provenance) tuples.
    pub fn digest(&self) -> Digest;
}
```

The digest enters the run key and the attestation. A hand-bumped version integer would be a
promise someone forgets to keep.

### 3.1 Catalogue

**tar**

| id | Transform | Risk |
|---|---|---|
| `tar-entry-order` | sort entries by `(path bytes, ordinal)` | Structural |
| `tar-time` | mtime and atime → epoch, ctime zeroed, format forced to PAX | Metadata |
| `tar-mode` | mode → 0777, every kind (§2.2 (7)) | Metadata |
| `tar-owners` | uid and gid → 0, uname and gname → "" | Metadata |
| `tar-xattrs` | drop extended attributes and the PAX records carrying them | Metadata |
| `tar-device` | devmajor and devminor → 0 | Metadata |

We force PAX format on purpose. Left alone, the writer may emit USTAR and drop the field, so the two
sides could differ over whether a timestamp is representable at all. `linkname` on a symlink or
hardlink is content and no stabilizer touches it.

**zip**

| id | Transform | Risk |
|---|---|---|
| `zip-entry-order` | sort by `(path bytes, ordinal)` | Structural |
| `zip-time` | modified date/time → 0 | Metadata |
| `zip-compression` | method → `Store` | Structural |
| `zip-data-descriptor` | clear flag bit 3; zero CRC and compressed/uncompressed sizes in the header | Structural |
| `zip-encoding` | clear the non-UTF-8 flag | Metadata |
| `zip-versions` | creator and reader version → 0; external attributes → 0 | Metadata |
| `zip-misc` | drop comments and extra fields; clear remaining flags | Metadata |

**gzip**

| id | Transform | Risk |
|---|---|---|
| `gzip-compression` | level → none | Structural |
| `gzip-name` | clear the embedded filename | Metadata |
| `gzip-time` | mtime → **unset**, not epoch | Metadata |
| `gzip-misc` | clear comment and extra; OS byte → 255 (unknown) | Metadata |

`gzip-time` writes 0, which is how gzip spells "no timestamp available": the field is always
present and zero is its unset value. Our model carries `Option<u32>` so that reading 0 gives back
`None` rather than a date in 1970, and both encode to the same byte.

**wheel** (zip set, plus)

| id | Transform | Risk | Stage |
|---|---|---|---|
| `wheel-record` | recompute `RECORD` from actual members: `path,sha256=<urlsafe-b64>,<size>`, sorted, PEP 376 CSV quoting, `RECORD,,` last | Content | **Finalize** |
| `wheel-generator` | normalize the `Generator:` line in `WHEEL` | Metadata | Default |
| `wheel-direct-url` | drop `direct_url.json` | Lossy | Default |
| `pyc-header` | zero the timestamp/hash field in `.pyc` headers | Content | Default |

**crate** (tar + gzip sets, plus)

| id | Transform | Risk |
|---|---|---|
| `cargo-vcs-hash` | replace `git.sha1` in `.cargo_vcs_info.json` with a fixed placeholder | Content |

Drop this one stabilizer and no crate rebuild ever compares, because the commit hash embeds the
exact checkout.

**npm tarball** (tar + gzip sets, plus)

| id | Transform | Risk |
|---|---|---|
| `npm-prefix` | normalize the `package/` path prefix | Structural |
| `npm-install-fields` | drop `_resolved`, `_integrity`, `_from` from `package.json` | Metadata |

**gem** (tar + gzip sets, plus)

| id | Transform | Risk |
|---|---|---|
| `gem-metadata-yaml-normalize` | canonical key ordering in `metadata.gz` | Content |
| `gem-metadata-date` | normalize the spec date | Metadata |
| `gem-metadata-rubygems-version` | normalize `rubygems_version` | Metadata |
| `gem-metadata-cert-chain` | empty the certificate chain | Structural |
| `gem-exclude-checksums` | drop `checksums.yaml.gz` | Structural |
| `gem-exclude-signatures` | drop `*.sig` members | Structural |

Nested descent into `data.tar.gz` and `metadata.gz` lives in the archive model as structure.

**nupkg** (zip set, plus)

| id | Transform | Risk |
|---|---|---|
| `nupkg-opc-ordering` | element ordering in `_rels/.rels` and `[Content_Types].xml` | Structural |
| `nuspec-normalize` | element ordering and insignificant whitespace in the `.nuspec` | Metadata |
| `nupkg-exclude-signature` | drop `.signature.p7s` | Structural |
| `pe-deterministic` | zero the PE header timestamp; normalize assembly MVID | **Content** |
| `pdb-normalize` | normalize embedded portable PDB identifiers | **Content** |

**jar** (zip set, plus)

| id | Transform | Risk |
|---|---|---|
| `jar-build-metadata` | delete ~70 `MANIFEST.MF` build attributes (`Build-Jdk`, `Built-By`, `Created-By`, `Bnd-LastModified`, `SCM-Git-*`, `Jenkins-Build-Number`, `Os-*`, `Java-*`, `DSTAMP`/`TSTAMP`, `SHA-256-Digest`, …) | Metadata |
| `jar-attribute-order` | sort comma-separated OSGi attribute values | Structural |
| `jar-git-properties` | empty `git.properties` / `git.json` | Metadata |
| `jar-signature` | strip signature entries | Structural |

Manifest handling needs a correct parse and serialize round-trip, including the 72-byte
line-continuation rule.

## 4. Comparison: four outcomes

```rust
pub enum Match { Exact, Normalized, NormalizedWithCaveats, Divergent }
```

| Outcome | Meaning |
|---|---|
| `Exact` | Raw digests equal. No transform was needed. |
| `Normalized` | Stabilized digests equal, **and every applied stabilizer is `Builtin` with `risk <= Metadata`**. |
| `NormalizedWithCaveats` | Stabilized digests equal, but at least one applied stabilizer is `Content`/`Lossy` or has `Human`/`Model` provenance. |
| `Divergent` | Stabilized digests differ. |

### 4.1 Why not a six-rung ladder

An earlier draft proposed six rungs: `ContainerNormalized`, `ContentIdentical`,
`ContentNormalized`, `SemanticallyEqual`, `Annotated` and the rest. We cut it, for three reasons:

- **One pipeline run cannot separate the middle rungs.** Distinguishing them means running the
  pipeline three times with different stabilizer subsets, tripling the cost of the most-executed code
  path, or partitioning stabilizers into container and content. That partition breaks on
  `wheel-record`, a *content* stabilizer that exists because *membership* changed. The categories do
  not sit at right angles to each other.
- **`SemanticallyEqual` cannot be defended in a signed statement.** For a compiled shared object it
  would assert compiler-output equivalence, which nobody can back. Everything you would want to file
  there says "we chose to ignore a difference", which is what `NormalizedWithCaveats` says already.
- **Ordinals in wire formats trap you.** A downstream policy engine writes `rung <= 3`, and from then
  on no rung can be inserted.

All four outcomes come out of **one** pipeline run at no extra cost over a binary scheme, because
`applied` falls out of the dirty bits the walker already sets.

### 4.2 One pass, six digests

```rust
let raw_h  = Sha256::new();   // the bytes as published
let cont_h = Sha256::new();   // the decompressed container, before any stabilizer
let stab_h = Sha256::new();   // the stabilized re-serialization

// Three tees down one pipeline: raw bytes on the way in, the decompressed
// container as it leaves the outer codec, the stabilized stream on the way out.
let summary = summarize(
    reader.tee(&mut raw_h),
    &set,
    Taps { container: &mut cont_h, stabilized: &mut stab_h },
)?;
```

About thirty lines in Rust. Run it over both artifacts and the comparison becomes three digest
comparisons per side, six digests in one pass over each artifact.

The container digest is what `container_bit_identical` reads. Knowing that the tar matched while the
gzip framing differed needs a digest taken between the outer codec and the stabilizers, and it costs
one more hasher on a stream that is already flowing. It is `None` for an uncompressed container.

### 4.3 The comparison record

```rust
pub struct Comparison {
    pub outcome: Match,
    pub upstream: MultiDigest, pub rebuild: MultiDigest,
    pub upstream_stabilized: MultiDigest, pub rebuild_stabilized: MultiDigest,
    pub upstream_container: Option<MultiDigest>,   // decompressed, pre-stabilizer
    pub rebuild_container: Option<MultiDigest>,
    pub stabilizer_set: (ProfileId, Digest),
    pub applied: Vec<AppliedStabilizer>,   // id, risk, provenance, entries_touched, bytes_changed
    pub notes: Vec<Note>,
}
```

`container_bit_identical()` earns its place. "Same tar, different gzip framing" is the most common
near-miss for `.crate`, `.tgz` and `.gem`, and it deserves its own signal without deserving its own
outcome. It derives from the container digests rather than being stored, so it cannot drift out of
agreement with them.

`entries_touched` costs nothing and is the triage number people reach for.

### 4.4 The provenance cap

```rust
impl Comparison {
    pub fn provenance_capped(&self) -> Match {
        let clean = self.applied.iter()
            .all(|a| a.provenance == Provenance::Builtin && a.risk <= RiskTier::Metadata);
        match (self.outcome, clean) {
            (Match::Normalized, false) => Match::NormalizedWithCaveats,
            (other, _) => other,
        }
    }
}
```

That makes [`00-overview.md`](00-overview.md) §3.1 executable: a model-influenced normalization
cannot present as a clean `Normalized`.

It is enforced exhaustively rather than by sampling. `trigon-compare/tests/seam_provenance_cap.rs`
enumerates every `RiskTier × Provenance × side` point, which is a proof over the domain where a
proptest would be evidence about the same points and strictly weaker — and its classification helper
is a `match` with no wildcard arm, so a new `RiskTier` or `Provenance` variant fails to compile
rather than silently passing.

## 5. The diff report

We produce one on **every** run, including successes. It makes a verdict auditable, and the UI
renders it.

```rust
pub struct DiffReport {
    pub summary: DifferenceSummary,          // counts by class
    pub tree: Vec<FileDiff>,
    pub applied: Vec<AppliedStabilizer>,
    pub classification: Vec<ClassifiedDifference>,   // deterministic rules first
    pub explanation: Option<AdvisoryExplanation>,    // model-authored, labelled, never signed
}

pub struct FileDiff {
    pub path: EntryPath,
    pub status: FileStatus,      // Identical | NormalizedEqual | Differs | OnlyUpstream | OnlyRebuild
    pub kind: ContentKind,       // Executable | Source | Metadata | Documentation | Binary
    pub hunks: Option<Vec<Hunk>>,
}
```

**File classification gates leniency.** Documentation and metadata files get generous
normalization. Anything classified `Executable` gets the strictest available comparator, and a custom
stabilizer that normalizes it away raises `NoteCode::CustomStabilizerTouchedExecutable`.

Text hunks come from `imara-diff`. Structural diffs run over our own `Archive` model, which is why
we have the model rather than shelling out to `diffoscope`. Where a human-readable rendering of a
binary member helps, `diffoscope` can enrich the report as an option, and stays off the verdict
path.

The **deterministic classifier** runs before we consult a model, over a near-closed taxonomy:
timestamps, entry ordering, permissions and umask, embedded absolute paths, compression level, line
endings, build-id and UUID and MVID, embedded version metadata, locale-dependent formatting, and map
iteration order. About ten classes cover most real mismatches. The model handles `Unknown`, and its
output stays advisory, unsigned and labelled. See [`07-ai.md`](07-ai.md) §2 and
[`09-attestations.md`](09-attestations.md) §4.

## 6. Testing, which is what de-risks the project

The stabilized digest is a pure function of our hand-written serialization stack, and it is the
value we sign. That makes it the project's largest technical risk
([`13-roadmap.md`](13-roadmap.md) §3), and testing retires it in M0, before anything else exists.

**(1) Differential corpus test against the Go implementation.** The prior art ships the harness
already:

```
go install github.com/google/oss-rebuild/cmd/stabilize@latest
stabilize --infile x.gem --outfile out --ecosystem rubygems \
          --enable-passes tar-time --disable-passes all
```

Per-pass `--enable-passes` and `--disable-passes` are what make this test worth building. Running the
whole pipeline tells you a digest differs; running one pass at a time tells you **which stabilizer**
differs, which turns a day of bisecting into a table. The corpus runs both ways: whole-pipeline for
every artifact, per-pass for anything that mismatches.

Pull the corpus described in [`15-corpora.md`](15-corpora.md), 3,000 to 5,000 real artifacts across
npm, PyPI, crates.io, RubyGems and NuGet, and compare stabilized digests for every one. This turns
"does my PAX writer match theirs?" from a guess into a CI signal, and nothing else in the project
returns as much.

The exit criterion is **equality except a checked-in deviation list**, and it cannot be plain
equality. The list lives at `corpora/deviations.toml`.

**Attribution is by what the difference is, not by which file it turned up in.** Each mismatch is
reduced to a set of codes naming the fields that differ, and a deviation declares the codes it
explains:

```
body@*/.cargo_vcs_info.json          the bytes of a member
entry:zip.creator_version@*          a central-directory field
entry:tar.pax.SCHILY.ino@pkg/x       one PAX keyword, named individually
member-only-in-reference@pkg/x       membership
container:gzip.os                    the outer gzip header
```

An artifact is explained when every code it produced is claimed by some deviation. The first version
of this test keyed exemptions on filenames, which does not survive a real corpus: a filename list
grows with every artifact and is trivial to extend without thinking, so a genuine bug in one wheel
hides the moment some other wheel is exempt. A pattern cannot hide one. When the corpus grew from 5
artifacts to 58, the filename scheme would have marked 26 mismatches "known"; the signature scheme
marked 3 of them as new and they were all real bugs.

Two further rules. A **stale exemption fails the build**: a deviation that explained nothing anywhere
in the corpus was either closed by a fix nobody recorded or is written in patterns that no longer
match, and both are places a regression can hide. And a mismatch that produces **no codes at all**
fails too, rather than passing: the signature is computed over parsed archives, so a difference in
something the parser does not represent is invisible to it. That is a gap in the test, and the run
says so instead of going green.

The report groups uncovered codes by class with counts and example paths, which is what makes a
mismatch readable: `entry:zip.creator_version 33 members` and `body 8 members` in the same wheel are
two different findings, and the second one is the bug.

**The same vocabulary is the divergence attestation's**, which is why `signature` lives in
`trigon-compare` rather than beside the differential test that first needed it. A published
divergence is a public claim about someone else's package, and "these two files differ" is an
accusation a maintainer cannot act on; `entry:zip.method` on four named members is something they
can go and reproduce. `DiffReport::codes` carries them, on a divergence only — naming every field
that differs means walking both archives a second time, and on a match there is nothing to name.
Two implementations of this would drift, and the published one is signed.

The first run on a five-artifact corpus found three real bugs. Scaling to 58 artifacts selected by
structure ([`15-corpora.md`](15-corpora.md) §2) found four more. All seven were fixed:

| Bug | What was wrong |
|---|---|
| PAX header mode | We wrote 0o644 into a PAX extended-header entry; the reference builds those minimally with mode 0. |
| PAX header device fields | We octal-formatted devmajor and devminor; the reference leaves them NUL. |
| Stored-deflate framing | We let `flate2` frame the no-compression case, which sets BFINAL on the last data block. The reference appends an empty final block. Twenty lines of our own stored-deflate writer fixed it, and made the claim that the stabilized stream never reaches a deflate encoder literally true rather than nearly true. |
| PAX records survived stabilization | `tar-xattrs` stripped only `SCHILY.xattr.*`. Real npm tarballs carry `SCHILY.ino` and `SCHILY.dev` (inode and device numbers from the packing machine) and a `NODETAR.*` record per field of the packed `package.json`. Keeping any of them made the stabilized digest a function of where the package was built. The keyword set is open, so the pass now clears the map. |
| Nested archives were rewritten | Descending into a `.gz` a package ships is for seeing inside it, not licence to rewrite it. Every nested archive was re-serialized store-only, which decompressed one 4,887-byte npm member to 66,090. `Body::Nested` now keeps the bytes it was parsed from and writes them back unless a pass changed something inside (§2.2 (4a)). |
| A truncated tar name could end in `/` | A name too long for the 100-byte field is truncated, and a truncation landing just after a separator makes a regular file read as a directory to anything that infers the kind from the name. The trailing slash is now dropped and the NUL terminates the field. |
| `wheel-record` dropped members it could not read | A `.gz` inside a wheel parses as a nested archive and has no bytes of its own, so `RECORD` regeneration skipped it. That is silent membership deletion presented as a normalization, and membership deletion is how a stabilizer turns a real difference into a false match. Members now contribute `Entry::stabilized_bytes`, and a member that genuinely cannot be read leaves `RECORD` untouched rather than producing a manifest of an archive that does not exist. |

After those, **34 of 58 artifacts are byte-identical to the reference** and the other 24 are covered
by the deviations below. Every npm tarball in the corpus matches exactly.

The deviations that remain are decisions rather than defects:

| Deviation | Why ours differs |
|---|---|
| `zip-writer-defaults` | The reference's stabilized wheel carries version-made-by 20, the data-descriptor flag, a 0x5455 extended-timestamp extra field, and a DOS date of 31 December 2097, which is what a zero `time.Time` degrades to. None of that is asked for by its stabilizers; all of it is Go's `archive/zip` writer. We zero it. |
| `cargo-vcs-surgical` | The reference round-trips `.cargo_vcs_info.json` through a JSON serializer, compacting 94 bytes to 76. We replace the 40 hex characters and touch nothing else, so `bytes_changed: 40` means it. |
| `nested-parse-errors` | Their gem recursion swallows a parse error; ours emits a note (§2.2 (4)). |
| `duplicate-path-ordering` | Our sort key is `(path, ordinal)`; theirs is path alone (§2.2 (6)). |
| `long-names-always-pax` | We never use the ustar `prefix` field, so a long name always takes a PAX `path` record and the framing does not depend on where the slashes fall (§2.1). A writer pinned to PAX does the same, so the digests agree. |
| `gem-metadata-yaml` | We normalize the three gemspec fields that carry build noise, and match the reference's substitutions exactly. Its fourth pass re-serializes the whole document through a YAML writer, re-indenting every list; we decline for the `cargo-vcs-surgical` reason. |
| `pyc-source-mtime` | A timestamp-validated `.pyc` embeds the mtime of the `.py` it was compiled from, so identical source from two checkouts produces different bytes. The reference has no `.pyc` pass; we zero those four bytes and nothing else, leaving the flags word that says how to read the rest and the source size that cannot differ while the source matches. |

Every entry carries a test and a sentence. An unexplained difference fails the build, and the list is
a deliverable of M0 rather than a by-product.

**(1a) Golden digests, and how to change them.** The corpus test and the `smoke` eval tier
([`07-ai.md`](07-ai.md) §6) both compare against recorded digests, so **any stabilizer change fails
the entire corpus by construction**. That is correct behaviour and it needs a workflow, or the first
person to hit it will delete the test.

```
trigon bench regold --corpus m0 --reason "add gzip-misc OS byte normalization"
```

`regold` re-runs the corpus, writes the new digests, and emits a review artifact: how many digests
moved, grouped by ecosystem and by which stabilizer touched them, with a sample diff per group. The
pull request carries that artifact, the new `stabilizer_set_digest`, and the reason. A digest that
moves without a stabilizer change in the same commit is a bug, and `regold` refuses to run.

**(2) Property tests.**
- `stabilize(stabilize(x)) == stabilize(x)`. **Idempotence is a requirement**, and repairing it is
  what `StageFinalize` exists for. Make it a test rather than a convention.
- `parse(write(a)) == a` for any archive.
- `write(parse(x)) == x` for an already-stabilized `x`.
- Byte-identical output across 100 runs and across threads.

**(3) Fuzzing.** `cargo-fuzz` on `parse`, and on the round trip
`parse → stabilize → write → parse`. Assert no panics, and that limits are respected.

**(4) Freeze the migration story on day one.** Attestations record the full stabilizer set, meaning
member ids plus the set digest. `trigon verify` **refuses** to compare across differing set digests
and re-derives instead. We persist both raw and stabilized digests, so a set change leaves every old
result open to re-evaluation.
