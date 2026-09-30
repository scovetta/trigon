# Stabilizers and profiles

Trigon ships ten stabilizer profiles and thirty-three passes. This page documents each one as
`crates/trigon-stabilize` defines it and as `trigon stabilizers` prints it in the build of
2026-09-29. [`05-archive-and-normalization.md`](05-archive-and-normalization.md) gives the design:
why Trigon normalizes instead of demanding bit-for-bit output, how Trigon chose the tiers, and how
one pass over an artifact yields six digests.

`crates/trigon-stabilize/tests/stabilizers_doc.rs` holds this page to the code. It fails when:

- the first sentence above miscounts the profiles or passes the registry has;
- a profile has no row in the §2 summary giving its pass count and the first sixteen hex digits of
  its set digest, or no section giving its full set digest and a pass table that lists its passes in
  the order they run, with their tiers and stages;
- the §1.4 cap table lists for a profile other passes than the ones that cap;
- a pass has no entry in §3 whose opening paragraph gives its tier, stage and profiles as the code
  has them;
- a retired id has no entry marked superseded, or a `-vN` pass replaced an id the test's list of
  retired ids does not name;
- the page documents a profile the registry lacks, or a pass it lacks that the list does not name as
  retired.

The test checks nothing else on the page: not the §1.1 selection table, which the binary crate
decides, and not the digests in §4, which record the sets on either side of each rename.

1. [Stabilizers, profiles and the verdict](#1-stabilizers-profiles-and-the-verdict)
2. [Profiles](#2-profiles)
3. [Passes](#3-passes)
4. [Archived sets, and renaming a pass](#4-archived-sets-and-renaming-a-pass)
5. [Ids from the design catalogue](#5-ids-from-the-design-catalogue)

---

## 1. Stabilizers, profiles and the verdict

A **stabilizer**, or pass, is a transform over a parsed archive that removes one known class of
benign nondeterminism: a timestamp, an entry order, a signature made with a key no rebuilder holds.
Trigon applies the same passes to the published artifact and to the rebuild, and compares what comes
out. Three properties hold by construction (`crates/trigon-stabilize/src/lib.rs`):

- A pass takes no parameter that could tell it which side of a comparison it is on.
- Each pass carries its own id, risk tier, stage and provenance, and the verdict reads them off the
  pass rather than off a table kept beside it.
- A pass returns no error. A member it cannot read or parse keeps its bytes, and the pass reports no
  change for it. A pass has nowhere to leave a note, so it declines silently: in `applied`, a member
  a pass could not read looks like one it had nothing to do to.

A member that is not valid UTF-8 is one that a pass which edits text cannot parse. The seven such
passes (`cargo-vcs-hash-v2`, `npm-install-fields-v2`, the three `gem-metadata-*-v2` passes,
`nupkg-repository-branch-v2` and `nupkg-readme-markers-v2`) leave it exactly as it is. Their first
versions decoded it lossily, replacing each invalid sequence with U+FFFD and writing the replacement
back, so two gems whose gemspecs differed in one such byte, 0xFF against 0xFE, matched as a clean
`normalized` (§4).

A **profile** is a named set of passes, one per artifact shape. Its **set digest** is SHA-256 over
one row per pass, `id|stage|risk|provenance`, sorted. The digest covers which passes run and each
one's stage, tier and provenance, and not their code (§4). Every comparison records the profile id
and its set digest, and the verdict a statement signs carries both.

### 1.1 Profile selection

`resolve_profile` in `crates/trigon/src/main.rs` picks the profile from the file name of the
published artifact. An explicit `--profile <id>` on `trigon verify` or `trigon stabilize` overrides
it. Otherwise three pieces of code decide. `BY_EXTENSION`, in the same file, maps four extensions to
their own profiles. Any other name gets the fallback profile for its container format:
`Format::from_file_name` in `crates/trigon-core/src/format.rs` infers the format from the extension
unless `--format` gives it, and `default_for` in `crates/trigon-stabilize/src/profiles.rs` maps the
format to a profile. Both match an extension in any case.

| File name ends in | Decided by | Format | Profile |
|---|---|---|---|
| `.whl` | `BY_EXTENSION` | zip | `wheel` |
| `.crate` | `BY_EXTENSION` | tar+gzip | `crate` |
| `.gem` | `BY_EXTENSION` | tar | `gem` |
| `.nupkg` | `BY_EXTENSION` | zip | `nupkg` |
| `.tgz`, `.tar.gz` | format fallback | tar+gzip | `tar-gzip` |
| `.tar` | format fallback | tar | `tar` |
| `.zip`, `.jar`, `.egg` | format fallback | zip | `zip` |
| `.gz`, other than `.tar.gz` | format fallback | gzip | `gzip` |
| anything else | `--format` | none: the command stops and asks for `--format` | the fallback for the format given; `--format raw` gives `raw` |

**Nothing selects `npm-tarball`.** An npm package is a `.tgz`, and `.tgz` stays with `tar-gzip`,
because a great deal else shares the extension and the name alone does not say which file is npm's.
Every npm comparison in the store carries the `tar-gzip` digest, and `npm-install-fields-v2` has
never run on an artifact Trigon verified, nor had the id before it. Routing `.tgz` to `npm-tarball`
would change the set digest every npm statement carries, so [`16-findings.md`](16-findings.md) §3.28
records the gap and leaves routing to a decision about verdicts. `--profile npm-tarball` reaches the
profile by hand.

`trigon stabilizers --list-profiles` prints this selection with each profile's digest and the passes
that can cap it; `trigon stabilizers --profile <id>` prints one profile's passes in the order they
run. `trigon stabilize` also takes `--enable-passes` and `--disable-passes`, which narrow the set to
localize a digest mismatch to one pass. Each takes a comma-separated list of pass ids, or `all` or
`none`; `--enable-passes` defaults to `all` and `--disable-passes` to `none`. A narrowed set has a
digest of its own.

### 1.2 Scope and run order

The parser descends into a member only when its name ends `.gz`: a gem's `data.tar.gz`, a `.tar.gz`
or `.gz` file a package ships. It walks the inflated bytes as a tar only if they carry the ustar
magic, and otherwise holds them as a single gzip member. It stops three levels below the top
(`Limits::recursion` in `crates/trigon-archive/src/limits.rs`) and records a note where it stopped.
Any other archive a package carries (a `.zip`, a `.jar`, a plain `.tar`) is one opaque member,
compared as its bytes.

A gzip file is a series of members, and the readers packages are installed with disagree about
them: gunzip, Node and Python inflate every member, RubyGems and Cargo the first alone. The parser
reads every member and refuses a file whose members after the first hold data, since it has no one
content to compare (`gzip::read` in `crates/trigon-archive/src/gzip.rs`). Nested, such a file stays
in its archive as the bytes it is, with a note; as the artifact itself, it reaches no verdict. Read
as every member's content, a gem whose `data.tar.gz` put its last entry in a second member matched
an honest build of all of them, though RubyGems installs it without that entry
([`16-findings.md`](16-findings.md) §3.106).

`apply` walks the parsed archive depth first. It stabilizes a nested archive with the whole set
before the archive that holds it, so a parent's passes see the bytes the child will serialize to. At
each level every pass asks its context (`Cx`: the format, the nesting depth, and the path the
archive was found at) whether it applies there. A pass runs only in the profiles that carry it, so a
`.tar.gz` inside a wheel or a `.nupkg` gets none of the tar passes.

Within one level the passes run by stage, then by id in byte order. `StabilizerSet::new` sorts them,
so the order a profile lists its passes in `profiles.rs` decides nothing. The tables in §2 and the
output of `trigon stabilizers` show the order the passes run in.

After the passes, the serializer writes the stabilized artifact uncompressed: zip members stored,
the outer gzip stream at level none. It writes each tar entry in PAX form, a name or link target too
long for the ustar header in a PAX record as the bytes it is, and every record a pass left as the
bytes it arrived as. It writes a nested archive the same way once a pass has marked
it changed, by changing one of its members, its gzip header or its order. Two passes mark a nested
archive whether or not they changed anything, so that its bytes do not depend on whether it needed
them: [`gzip-meta-v2`](#gzip-meta-v2) marks a gzip layer the gem format defines, and
[`tar-entry-order-v2`](#tar-entry-order-v2) marks every nested tar, whose entries the tar passes
normalize at any depth.

A nested archive that nothing normalizes goes back as the bytes it arrived as, compressed stream and
gzip header included (`flatten` in `crates/trigon-archive/src/parse.rs`): a `.gz` of anything but a
tar that a package ships, and an archive inside a wheel, a `.nupkg` or a zip, whose profiles carry
no tar or gzip pass. Its compression level therefore reaches the stabilized digest: two wheels that
ship one `pkg/data.gz` compressed at levels 1 and 9 are `divergent`, and so are two `.tgz` files
that ship one `banner.json.gz` that way. That is a limit Trigon keeps on purpose. Such a file is a
deliverable, and its compressed bytes are what the package delivers, as its gzip header is
([`05`](05-archive-and-normalization.md) §2.2 (4a)). Everywhere else the serializer decides the
compression, and no pass is needed for it.

### 1.3 Stages

| Stage | Runs | Builtin passes at this stage |
|---|---|---|
| `default` | first | every pass but one |
| `patch` | after `default` | none. Trigon reserves the stage for custom stabilizers from the definitions repository ([`04-strategies.md`](04-strategies.md) §5.2). The registry reads a definition that carries one today, such as `exclude_path`, and the run records it as an assumption: "not executed yet". |
| `finalize` | last | `wheel-record-v3`, which has to see membership after every other pass |

### 1.4 Risk tiers and the verdict

Each pass carries one of four tiers, ordered from least to most intrusive (`RiskTier` in
`trigon-core`):

| Tier | A pass at this tier | Examples in this build |
|---|---|---|
| `structural` | reorders, renames or reframes without changing what a consumer reads, or drops integrity metadata computed over the content being rebuilt | entry order, the `.psmdcp` name, signature and checksum exclusion |
| `metadata` | rewrites fields that are not the distributed content | timestamps, modes, owners, the packing tool's name, an assembly's MVID |
| `content` | rewrites bytes inside a distributed file | line endings, `RECORD` regeneration, a `.pyc` mtime, a crate's commit hash |
| `lossy` | removes distributed content, or information that cannot be re-derived | dropping `direct_url.json`, reducing an assembly to its code |

A pass reports what it changed (`Touched`: entries and bytes). The comparison keeps as `applied`
only the passes that changed something on either side, each with its tier and provenance, and the
verdict follows from the digests and from `applied`:

| Outcome | Condition |
|---|---|
| `exact` | the raw digests are equal; no pass is consulted |
| `normalized` | the stabilized digests are equal, and every pass in `applied` is builtin at `metadata` or below |
| `normalized_with_caveats` | the stabilized digests are equal, and a pass in `applied` is `content` or `lossy`, or was written by a person or a model rather than compiled in |
| `divergent` | the stabilized digests differ |

The verdict reads the cap off the passes that fired. A profile that carries a `content` pass caps
nothing on a run where that pass found nothing to do. The passes that can hold a match at
`normalized_with_caveats`:

| Profile | Passes that cap |
|---|---|
| `crate` | `cargo-vcs-hash-v2` (content) |
| `wheel` | `pyc-header-v2` (content), `wheel-direct-url` (lossy), `wheel-metadata-eol` (content), `wheel-record-v3` (content) |
| `nupkg` | `dotnet-il-canonical-v3` (lossy), `nupkg-readme-markers-v2` (content), `nupkg-text-eol` (content) |

No pass in the other profiles caps a match. Three of the passes above fire on most artifacts of
their kind:

- `cargo-vcs-hash-v2` fires on every crate whose `.cargo_vcs_info.json` holds a forty-hex `"sha1"`
  value, which `cargo package` writes when it packages from a git checkout.
- `wheel-record-v3` fires whenever the regenerated `RECORD` differs from the published one: when an
  earlier pass changed a member, or when the published file is not already in the form the pass
  writes.
- `dotnet-il-canonical-v3` fires on every `.dll` or `.exe` in a `.nupkg` that it can read, whether
  or not the identity pass left a difference behind.

A `.nupkg` holding a managed assembly the IL pass reads therefore reaches `normalized_with_caveats`
at best unless its bytes are `exact`. Crates and wheels usually cap, though not always. A crate
without `.cargo_vcs_info.json`, or whose file holds no forty-hex `"sha1"` value or is not valid
UTF-8, never fires `cargo-vcs-hash-v2`. A wheel whose `RECORD` is already in the pass's form, or
that has no `.dist-info` of its own at its root, and which gives the other wheel passes nothing to
change, can match as a clean `normalized`: two wheels that differ only in their zip timestamps do.

---

## 2. Profiles

| Profile | Selected by | Passes | Set digest |
|---|---|---|---|
| [`tar`](#tar) | `.tar`, and any tar `BY_EXTENSION` does not name | 6 | `a1b74ac55ad44a81…` |
| [`tar-gzip`](#tar-gzip) | `.tgz`, `.tar.gz`, and any tar+gzip `BY_EXTENSION` does not name | 7 | `cadb3a863443a703…` |
| [`zip`](#zip) | `.zip`, `.jar`, `.egg`, and any zip `BY_EXTENSION` does not name | 5 | `5f1e6bc5c9a6b035…` |
| [`gzip`](#gzip) | `.gz`, other than `.tar.gz` | 1 | `e7b47b1ed937032a…` |
| [`npm-tarball`](#npm-tarball) | nothing; `--profile` only | 8 | `8b992c8410f03e2b…` |
| [`crate`](#crate) | `.crate` | 8 | `5ac2049396f6a166…` |
| [`gem`](#gem) | `.gem` | 12 | `b7f07d65a95c41bf…` |
| [`wheel`](#wheel) | `.whl` | 9 | `188d208b5a9e7525…` |
| [`nupkg`](#nupkg) | `.nupkg` | 15 | `d7edf6128800bb92…` |
| [`raw`](#raw) | `--format raw` | 0 | `e3b0c44298fc1c14…` |

§3 describes a pass shared between profiles once, and each table links to it.

### `tar`

Selected by `.tar`, and by any artifact in tar format whose name `BY_EXTENSION` does not list.

Set digest `a1b74ac55ad44a81202463100fd1da2b19acf435d4bcdbb156938fdd329d63a4`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`tar-device`](#tar-device) | metadata | default | device major and minor numbers |
| 2 | [`tar-entry-order-v2`](#tar-entry-order-v2) | structural | default | the order of entries |
| 3 | [`tar-mode`](#tar-mode) | metadata | default | permission bits, to `0777` |
| 4 | [`tar-owners`](#tar-owners) | metadata | default | uid, gid, user and group names |
| 5 | [`tar-time`](#tar-time) | metadata | default | mtime, atime and ctime |
| 6 | [`tar-xattrs`](#tar-xattrs) | metadata | default | every surviving PAX record |

### `tar-gzip`

Selected by `.tgz` and `.tar.gz`, and by any tar+gzip artifact `BY_EXTENSION` does not list, which
includes every npm package (§1.1). It runs the `tar` passes and `gzip-meta-v2`.

Set digest `cadb3a863443a703bcfb7bd35e08581cee2a2d54c78b661bd2c43e483120bdbb`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`gzip-meta-v2`](#gzip-meta-v2) | metadata | default | the gzip header |
| 2 | [`tar-device`](#tar-device) | metadata | default | device numbers |
| 3 | [`tar-entry-order-v2`](#tar-entry-order-v2) | structural | default | entry order |
| 4 | [`tar-mode`](#tar-mode) | metadata | default | permission bits |
| 5 | [`tar-owners`](#tar-owners) | metadata | default | ownership |
| 6 | [`tar-time`](#tar-time) | metadata | default | timestamps |
| 7 | [`tar-xattrs`](#tar-xattrs) | metadata | default | PAX records |

### `zip`

Selected by `.zip`, `.jar` and `.egg`, and by any zip `BY_EXTENSION` does not list.

Set digest `5f1e6bc5c9a6b035cf3d60a4068da097ab9656fab3fc1cad57259dca0eb5cdfb`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`zip-compression`](#zip-compression) | structural | default | the method field, and the archive comment |
| 2 | [`zip-entry-order`](#zip-entry-order) | structural | default | the order of entries |
| 3 | [`zip-misc`](#zip-misc) | metadata | default | extra fields, entry comments, flags, internal attributes |
| 4 | [`zip-time`](#zip-time) | metadata | default | DOS date and time |
| 5 | [`zip-versions`](#zip-versions) | metadata | default | version fields, and permission bits in the external attributes |

### `gzip`

Selected by a name ending `.gz` but not `.tar.gz`.

Set digest `e7b47b1ed937032a2ede2fc71c06fd96d38cb83627882c1068c8db1109c3069e`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`gzip-meta-v2`](#gzip-meta-v2) | metadata | default | the gzip header |

### `npm-tarball`

Selected by nothing (§1.1); only `--profile npm-tarball` reaches it. It runs the `tar-gzip` passes
and `npm-install-fields-v2`.

Set digest `8b992c8410f03e2b6cf47420e262f5a71d276d0cd88f330512c9ffed30cf4862`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`gzip-meta-v2`](#gzip-meta-v2) | metadata | default | the gzip header |
| 2 | [`npm-install-fields-v2`](#npm-install-fields-v2) | metadata | default | install-time fields in `package.json` |
| 3 | [`tar-device`](#tar-device) | metadata | default | device numbers |
| 4 | [`tar-entry-order-v2`](#tar-entry-order-v2) | structural | default | entry order |
| 5 | [`tar-mode`](#tar-mode) | metadata | default | permission bits |
| 6 | [`tar-owners`](#tar-owners) | metadata | default | ownership |
| 7 | [`tar-time`](#tar-time) | metadata | default | timestamps |
| 8 | [`tar-xattrs`](#tar-xattrs) | metadata | default | PAX records |

### `crate`

Selected by `.crate`. It runs the `tar-gzip` passes and `cargo-vcs-hash-v2`, which caps.

Set digest `5ac2049396f6a16622340f14df01e8b6380352ca58471277d22a37e8b29f6125`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`cargo-vcs-hash-v2`](#cargo-vcs-hash-v2) | content | default | the commit hash in `.cargo_vcs_info.json` |
| 2 | [`gzip-meta-v2`](#gzip-meta-v2) | metadata | default | the gzip header |
| 3 | [`tar-device`](#tar-device) | metadata | default | device numbers |
| 4 | [`tar-entry-order-v2`](#tar-entry-order-v2) | structural | default | entry order |
| 5 | [`tar-mode`](#tar-mode) | metadata | default | permission bits |
| 6 | [`tar-owners`](#tar-owners) | metadata | default | ownership |
| 7 | [`tar-time`](#tar-time) | metadata | default | timestamps |
| 8 | [`tar-xattrs`](#tar-xattrs) | metadata | default | PAX records |

### `gem`

Selected by `.gem`. A `.gem` is a plain tar, the envelope, holding `metadata.gz` (the gemspec as
YAML), `data.tar.gz` (the payload), `checksums.yaml.gz`, and a `.sig` beside each member when the
gem is signed. The parser descends into all three gzipped members, so the set runs on the envelope
(depth 0), on `metadata.gz`, `data.tar.gz` and `checksums.yaml.gz` (depth 1), and on any `.gz` the
payload ships (depth 2 and below, §1.2). It runs on `checksums.yaml.gz`, `gzip-meta-v2` included,
before `gem-exclude-checksums` drops that member from the envelope.

Set digest `b7f07d65a95c41bf229fda11aecdca57d830d89cd5d330102d769e2196ef22b3`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`gem-exclude-checksums`](#gem-exclude-checksums) | structural | default | `checksums.yaml.gz`, dropped from the envelope |
| 2 | [`gem-exclude-signatures`](#gem-exclude-signatures) | structural | default | `*.sig`, dropped from the envelope |
| 3 | [`gem-metadata-cert-chain-v2`](#gem-metadata-cert-chain-v2) | structural | default | the gemspec's `cert_chain`, emptied |
| 4 | [`gem-metadata-date-v2`](#gem-metadata-date-v2) | metadata | default | the gemspec's `date` |
| 5 | [`gem-metadata-rubygems-version-v2`](#gem-metadata-rubygems-version-v2) | metadata | default | the gemspec's `rubygems_version` |
| 6 | [`gzip-meta-v2`](#gzip-meta-v2) | metadata | default | the gzip headers of `data.tar.gz`, `metadata.gz`, `checksums.yaml.gz` |
| 7 | [`tar-device`](#tar-device) | metadata | default | device numbers |
| 8 | [`tar-entry-order-v2`](#tar-entry-order-v2) | structural | default | entry order |
| 9 | [`tar-mode`](#tar-mode) | metadata | default | permission bits |
| 10 | [`tar-owners`](#tar-owners) | metadata | default | ownership |
| 11 | [`tar-time`](#tar-time) | metadata | default | timestamps |
| 12 | [`tar-xattrs`](#tar-xattrs) | metadata | default | PAX records |

No pass in the set is above `metadata`, so a gem can reach a clean `normalized`.

### `wheel`

Selected by `.whl`. It runs the `zip` passes and four wheel passes, one of them at `finalize`.

Set digest `188d208b5a9e7525ba23e7dc1eae0a81830f2f8d70abf3e688f58b499dc2e23f`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`pyc-header-v2`](#pyc-header-v2) | content | default | the source mtime in a `.pyc` header |
| 2 | [`wheel-direct-url`](#wheel-direct-url) | lossy | default | `direct_url.json`, dropped |
| 3 | [`wheel-metadata-eol`](#wheel-metadata-eol) | content | default | CRLF in four generated `.dist-info` files |
| 4 | [`zip-compression`](#zip-compression) | structural | default | the method field, and the archive comment |
| 5 | [`zip-entry-order`](#zip-entry-order) | structural | default | entry order |
| 6 | [`zip-misc`](#zip-misc) | metadata | default | extras, comments, flags |
| 7 | [`zip-time`](#zip-time) | metadata | default | DOS date and time |
| 8 | [`zip-versions`](#zip-versions) | metadata | default | version fields and permission bits |
| 9 | [`wheel-record-v3`](#wheel-record-v3) | content | finalize | `RECORD`, regenerated from the members |

`wheel-record-v3` runs last so the manifest it writes describes the wheel after every other pass.

### `nupkg`

Selected by `.nupkg`. A `.nupkg` is an OPC package: a zip carrying a `.nuspec`, the payload under
`lib/`, a relationships part and a core-properties part. The profile runs the `zip` passes, eight
packaging passes, and two passes over managed assemblies.

Set digest `d7edf6128800bb925975c4ed1831b5a3ca38d7079aa613b143aa3e9a94ac38ab`.

| # | Pass | Tier | Stage | Normalizes |
|---|---|---|---|---|
| 1 | [`dotnet-assembly-identity-v2`](#dotnet-assembly-identity-v2) | metadata | default | an assembly's timestamps, checksum, signature, debug data and MVID, zeroed in place |
| 2 | [`dotnet-il-canonical-v3`](#dotnet-il-canonical-v3) | lossy | default | an assembly, replaced by the canonical form of its code |
| 3 | [`nupkg-doc-member-order-v2`](#nupkg-doc-member-order-v2) | structural | default | the order of `<member>` elements in XML documentation |
| 4 | [`nupkg-packager-version`](#nupkg-packager-version) | metadata | default | `<lastModifiedBy>` in the core-properties part |
| 5 | [`nupkg-packaging-names`](#nupkg-packaging-names) | structural | default | the core-properties part's GUID name, and relationship ids |
| 6 | [`nupkg-portable-folder-name`](#nupkg-portable-folder-name) | structural | default | the spelling of a `lib/portable…` folder |
| 7 | [`nupkg-readme-markers-v2`](#nupkg-readme-markers-v2) | content | default | NuGetizer's include markers and whitespace in Markdown |
| 8 | [`nupkg-repository-branch-v2`](#nupkg-repository-branch-v2) | metadata | default | the `branch` attribute of `<repository>` |
| 9 | [`nupkg-signature`](#nupkg-signature) | structural | default | `.signature.p7s`, dropped |
| 10 | [`nupkg-text-eol`](#nupkg-text-eol) | content | default | CRLF in text members |
| 11 | [`zip-compression`](#zip-compression) | structural | default | the method field, and the archive comment |
| 12 | [`zip-entry-order`](#zip-entry-order) | structural | default | entry order |
| 13 | [`zip-misc`](#zip-misc) | metadata | default | extras, comments, flags |
| 14 | [`zip-time`](#zip-time) | metadata | default | DOS date and time |
| 15 | [`zip-versions`](#zip-versions) | metadata | default | version fields and permission bits |

The ids decide the order, with two consequences:

- Both renaming passes, `nupkg-packaging-names` and `nupkg-portable-folder-name`, sort before
  `zip-entry-order`, so the entry sort sees the canonical names. A rename after the sort would leave
  the order depending on which spelling arrived. The position a pass is listed at in `profiles.rs`
  decides nothing; the ids keep the order.
- The two .NET passes run first. `dotnet-assembly-identity-v2` zeroes the fixed-location build
  identity, then `dotnet-il-canonical-v3` replaces each assembly it can read with its canonical
  form. The first acts only where the second reads the same form from the zeroed bytes as from the
  published ones, so nothing it zeroes reaches a `nupkg` digest.

### `raw`

Selected by `--format raw`: opaque bytes, compared whole and never walked. The profile has no
passes, so the set digest is the SHA-256 of empty input, and a `raw` artifact can be `exact` or
`divergent` and nothing between.

Set digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

---

## 3. Passes

The entries group every pass `trigon stabilizers` lists by family, and each id a rename retired
keeps an entry of its own. An entry opens with the pass's tier, stage and profiles. It then gives
the change byte for byte, the reason the difference is not the package's, what the pass could hide
and so what its tier means for the verdict, and the cases where the pass is limited or declines.

Every pass matches a member's name as bytes, case-sensitively, except the two .NET passes, which
match `.dll` and `.exe` in any case.

### Tar passes

In the profiles that carry them, the six tar passes apply to every tar and tar+gzip archive at every
depth: the artifact itself, a gem's `data.tar.gz`, and a `.tar.gz` the package ships inside itself.
Each pass that reads a tar entry's own header fields leaves alone an entry that carries another
format's metadata; `tar-mode` reads only the format-neutral mode.

An entry with a typeflag the parser does not recognize keeps its typeflag, its body and its mode,
as [`05`](05-archive-and-normalization.md) §2.2 (7) gives the rule. `tar-time`, `tar-owners`,
`tar-xattrs` and `tar-device` change it as they change any other entry.

#### `tar-entry-order-v2`

`structural` tier, `default` stage. Profiles: `tar`, `tar-gzip`, `npm-tarball`, `crate`, `gem`.

**Changes.** Sorts the entries by path bytes, and breaks a tie between duplicate paths by the order
the parser read them. The pass reports an archive whose order it moved and marks the archive
changed, so a nested one is written again in the new order (§1.2). It marks every nested tar
changed besides, sorted or not, and does not report that: the serializer then writes the tar again,
and its bytes, compressed stream included, do not depend on whether it arrived already in the form
the tar passes leave. The outermost archive is written again anyway, and the pass neither touches
nor reports one already in order.

**Rationale.** A tar writer lists files in whatever order it walked the directory, and the order
carries no meaning for a package.

**Risk.** Membership and every member's bytes are unchanged. Duplicates keep their relative order,
so an extractor that lets a later duplicate overwrite an earlier one sees the same file win on both
sides. A `.tar.gz` a package ships inside itself is written again uncompressed under the gzip header
it arrived with, so the level it was compressed at does not show.

#### `tar-entry-order`

Superseded by `tar-entry-order-v2`. `structural` tier, `default` stage. Profiles: `tar`,
`tar-gzip`, `npm-tarball`, `crate`, `gem`, until the rename.

The same sort. It marked nothing changed, so in a nested tar where no other pass changed anything
the serializer wrote the archive back as it arrived, unsorted: two `.tgz` files that shipped one
`.tar.gz`, its entries in two orders and nothing else to normalize, were `divergent`, though
`applied` listed the pass. The last sets that carried it hash to `c294a4d0c8a7…` (`tar`),
`4598411b636d…` (`tar-gzip`), `562ce45ae605…` (`npm-tarball`), `fcd80dd27bb9…` (`crate`) and
`cc5a0b733412…` (`gem`).

#### `tar-time`

`metadata` tier, `default` stage. Profiles: `tar`, `tar-gzip`, `npm-tarball`, `crate`, `gem`.

**Changes.** Sets each entry's mtime and atime to 0 (the epoch), clears its ctime, and drops any
`mtime`, `atime` and `ctime` PAX records. Ustar has no atime field, so the writer emits atime as a
PAX record, and the serializer writes every stabilized tar entry in PAX form. Forcing PAX keeps the
two sides from disagreeing about whether a timestamp is representable.

**Rationale.** A build stamps each file with the moment it ran. The instant is not reproducible and
says nothing about the package.

**Risk.** A difference only in a timestamp does not show. Code that reads its own file times at run
time could behave differently between the two; [`05`](05-archive-and-normalization.md) §1 records
why Trigon accepts that.

#### `tar-mode`

`metadata` tier, `default` stage. Profiles: `tar`, `tar-gzip`, `npm-tarball`, `crate`, `gem`.

**Changes.** Sets the mode of every entry to `0777`: regular files, directories, symlinks,
hardlinks, devices and FIFOs alike. An entry with a typeflag the parser does not recognize keeps its
mode.

**Rationale.** The packing machine's umask and tooling decide the permission bits.
[`05`](05-archive-and-normalization.md) §2.2 (7) gives the rule for each kind of entry.

**Risk.** The executable bit goes with the noise, and so do the setuid, setgid and sticky bits. A
file that is executable on one side only, or setuid on one side only, compares equal, and at
`metadata` tier the verdict can still be a clean `normalized`.

#### `tar-owners`

`metadata` tier, `default` stage. Profiles: `tar`, `tar-gzip`, `npm-tarball`, `crate`, `gem`.

**Changes.** Sets uid and gid to 0 and empties the user and group names, on every entry, including
one with an unrecognized typeflag, whose mode `tar-mode` leaves alone.

**Rationale.** The account that packed the archive is a property of the machine.

**Risk.** A difference in ownership does not show.

#### `tar-xattrs`

`metadata` tier, `default` stage. Profiles: `tar`, `tar-gzip`, `npm-tarball`, `crate`, `gem`.

**Changes.** Drops every PAX extended-header record that survives parsing, whatever its keyword. The
reader has already lifted `path`, `linkpath`, `size`, `mtime`, `atime` and `ctime` into typed
fields, and the writer regenerates them, so a long name survives, byte for byte.

**Rationale.** The keyword set is open, and what turns up in real tarballs is host state. node-tar
writes `SCHILY.ino`, `SCHILY.dev` and `SCHILY.nlink` (inode, device and link count on the packing
machine) and a `NODETAR.*` record for each field of the packed `package.json`. `SCHILY.xattr.*`
records carry extended attributes such as SELinux labels. Keeping any of them makes the stabilized
digest depend on where the package was packed.

**Risk.** The pass removes more than its id says. A record that grants something on extraction does
not show either: the pass drops `SCHILY.xattr.security.capability`, a Linux file capability, as it
drops an inode number. At `metadata` tier the pass cannot cap a verdict.

#### `tar-device`

`metadata` tier, `default` stage. Profiles: `tar`, `tar-gzip`, `npm-tarball`, `crate`, `gem`.

**Changes.** Sets the device major and minor numbers to 0 on every entry, in the header fields and
in the entry kind of a character or block device. The node type stays.

**Rationale.** A device number belongs to the machine that created the node.

**Risk.** A device entry still shows as a device of its kind. Two nodes that point at different
devices compare equal.

### Zip passes

The five zip passes apply to the zip artifact itself. The parser does not descend into a zip or a
`.jar` a package carries (§1.2), so the comparison treats those as opaque bytes. Each pass that
reads a zip entry's own header fields leaves alone an entry that carries another format's metadata.

#### `zip-entry-order`

`structural` tier, `default` stage. Profiles: `zip`, `wheel`, `nupkg`.

**Changes.** Sorts the entries by path bytes, and breaks a tie between duplicate paths by the order
the parser read them. The pass neither touches nor reports an archive already in that order.

**Rationale.** The order of a zip's central directory is the writer's choice.

**Risk.** Membership and every member's bytes are unchanged.

#### `zip-time`

`metadata` tier, `default` stage. Profiles: `zip`, `wheel`, `nupkg`.

**Changes.** Sets each entry's DOS date and time to zero and drops its parsed modification time. The
extended-timestamp and Unix extra fields, which carry times too, go with `zip-misc`.

**Rationale.** The date a zip records for a member is when the build ran.

**Risk.** A difference only in a timestamp does not show.

#### `zip-versions`

`metadata` tier, `default` stage. Profiles: `zip`, `wheel`, `nupkg`.

**Changes.** Sets "version made by" and "version needed to extract" to 0, and replaces the external
attributes with the entry's file type alone: the Unix symlink type (`0120000`, in the high 16 bits)
for a symlink, and 0 for everything else. Permission bits and DOS attributes go. The type comes from
the parser's reading of the entry, so a zip that records no Unix mode agrees with one that records
`0100644`.

**Rationale.** The version fields name the tool and host that wrote the zip. The permission bits
come from the packing machine's umask.

**Risk.** An executable bit on one side only does not show. The file type does: an earlier version
zeroed the whole field, and a member that was a symlink to `/etc/passwd` compared equal to a regular
file holding that text ([`16-findings.md`](16-findings.md) §3.55). The fix kept the id (§4).

#### `zip-misc`

`metadata` tier, `default` stage. Profiles: `zip`, `wheel`, `nupkg`.

**Changes.** Empties each entry's extra field and entry comment, and zeroes its general-purpose
flags and internal attributes.

**Rationale.** Writers differ in which extras they add (extended timestamps, Unix uid and gid, zip64
sizes, alignment padding), in whether they set the data-descriptor and UTF-8 flags, and in whether
they mark text members in the internal attributes. None of it changes a member's bytes.

**Risk.** A comment on an entry does not show, and neither does the UTF-8 flag, which decides how a
reader decodes a non-ASCII name. The name's bytes still compare.

#### `zip-compression`

`structural` tier, `default` stage. Profiles: `zip`, `wheel`, `nupkg`.

**Changes.** Sets each entry's compression method field to 0 (stored), and empties the archive
comment in the end-of-central-directory record. The serializer writes every member stored, so the
zip's own compressed bytes never reach the digest (§1.2).

**Rationale.** The compressor and its level are the writer's choice. The uncompressed bytes are the
content.

**Risk.** The archive comment does not show.

### Gzip pass

#### `gzip-meta-v2`

`metadata` tier, `default` stage. Profiles: `tar-gzip`, `gzip`, `npm-tarball`, `crate`, `gem`.

**Changes.** Clears the gzip header's MTIME, FNAME, FCOMMENT and FEXTRA fields and sets OS to 255
(unknown). An MTIME of 0 is how gzip spells "no timestamp", so an absent time and a zero one write
the same bytes. The serializer sets XFL to match the level it writes at. The pass reports a header
it changed. It marks a nested layer changed whether or not its header was, and does not report
that, so the serializer writes the layer again uncompressed (§1.2) and the level it was compressed
at does not reach the digest.

**Scope.** The outermost gzip layer of a tar+gzip or gzip artifact, and the gzip layer of three
members the gem format defines: `data.tar.gz`, `metadata.gz` and `checksums.yaml.gz`, found by exact
path one level down. A `.gz` file a package ships, such as an npm package's `banner.json.gz`, keeps
its header: there the header is bytes the package delivers. It keeps its compressed bytes too,
unless it is a tar, which [`tar-entry-order-v2`](#tar-entry-order-v2) has written again (§1.2).

**Rationale.** The header records when and on which system the compressor ran, and the name of the
file it compressed. The compression level is the compressor's choice, and in a layer the format
defines it frames the content rather than being it.

**Risk.** The pass hides nothing a consumer reads after decompression. The exact-path rule does not
ask which profile is running, so in `tar-gzip`, `crate` or `npm-tarball` a member of the outer
archive named exactly `data.tar.gz`, `metadata.gz` or `checksums.yaml.gz` counts as framing too.

#### `gzip-meta`

Superseded by `gzip-meta-v2`. `metadata` tier, `default` stage. Profiles: `tar-gzip`, `gzip`,
`npm-tarball`, `crate`, `gem`, until the rename.

The same header. It marked a nested layer changed only when its header was, so a layer the gem
format defines, its header already clear and nothing inside it changed, went out as it arrived: two
gems that differed only in the compression level of `data.tar.gz` or `metadata.gz` were
`divergent`. The last sets that carried it hash to `4598411b636d…` (`tar-gzip`), `ef4835dee29e…`
(`gzip`), `562ce45ae605…` (`npm-tarball`), `fcd80dd27bb9…` (`crate`) and `cc5a0b733412…` (`gem`).

### Crate pass

#### `cargo-vcs-hash-v2`

`content` tier, `default` stage. Profile: `crate`.

**Changes.** In a tar entry whose path ends in `.cargo_vcs_info.json`, finds the first occurrence of
the text `"sha1"` and replaces the first quoted string after the colon that follows it with forty
`x` characters, provided that string is forty hex digits. The rest of the file, `path_in_vcs` and
`dirty` included, stays byte for byte. The pass reports 40 bytes changed.

**Rationale.** `cargo package` records the commit it packaged from. The commit names a checkout
rather than the files in it: a rebuild from another commit with the same tree records another hash.

**Risk.** The comparison stops checking the one pointer a crate carries back to its source. A crate
that names one commit and was built from another compares equal when the files match. The pass
rewrites a file the crate ships, so it is `content`, and every crate it touches caps at
`normalized_with_caveats`.

**Limits.** The pass matches text and does not parse the JSON. The first `"sha1"` in the file picks
the value, whether it appears as a key or inside a value. The pass leaves alone a value that is not
forty hex digits, any later `"sha1"`, a file it cannot read, and one that is not valid UTF-8 (§1).

#### `cargo-vcs-hash`

Superseded by `cargo-vcs-hash-v2`. `content` tier, `default` stage. Profile: `crate`, until the
rename.

The same rewrite, of text it decoded lossily: a file that was not valid UTF-8 came out with U+FFFD
for each invalid sequence, so two that differed only inside one compared equal (§1). The last
`crate` set that carried it hashes to `fcd80dd27bb9…`.

### npm pass

#### `npm-install-fields-v2`

`metadata` tier, `default` stage. Profile: `npm-tarball`.

**Changes.** In every tar entry named `package.json`, in any directory (bundled dependencies
included), drops each line whose text after leading whitespace begins with `"_resolved"`,
`"_integrity"`, `"_from"` or `"_id"`. If the first line kept after one or more dropped lines opens
with `}`, ignoring indentation, the pass also removes the comma that ends the last non-blank line
kept before them, so the object stays valid JSON; a blank line between them keeps the comma. A
rewritten `package.json` has its line endings made LF and ends with a newline.

**Rationale.** An installing npm client writes these fields: `_resolved` holds the URL it fetched,
`_integrity` the hash it checked, `_from` the spec it resolved, and `_id` the name and version it
installed. They describe an install.

**Risk.** A package that uses one of these keys in a `package.json` for its own data loses it from
the comparison.

**Limits.** The pass works on lines of text, leaves a file that is not valid UTF-8 as it is (§1),
and does not parse the JSON. It changes nothing in a `package.json` written on one line, drops a
nested key of the same name, and drops only the first line of a value that spans several. Nothing
selects `npm-tarball`, so the pass has never run on a verified artifact (§1.1).

#### `npm-install-fields`

Superseded by `npm-install-fields-v2`. `metadata` tier, `default` stage. Profile: `npm-tarball`,
until the rename.

The same edit, of text it decoded lossily (§1). Nothing selects `npm-tarball`, so no record names
it; the pass took a new id all the same (§4). The last `npm-tarball` set that carried it hashes to
`562ce45ae605…`.

### Gem passes

#### `gem-exclude-checksums`

`structural` tier, `default` stage. Profile: `gem`.

**Changes.** Removes members whose file name is `checksums.yaml.gz` from the gem's envelope, the
outermost tar. It never looks inside `data.tar.gz`.

**Rationale.** The file holds hashes of `metadata.gz` and `data.tar.gz` as stored, compressed. It
therefore differs whenever their gzip framing differs, framing that `gzip-meta-v2` and
re-serialization normalize. It depends only on those members' bytes, so it adds nothing to the
comparison of the members themselves, and a consumer does not read it as content.

**Risk.** The pass hides nothing beyond the file itself: every member it hashes still compares.
[`05`](05-archive-and-normalization.md) §3 gives the reason the pass sits at `structural` and not
`lossy`.

**Limits.** Depth 0 only. An earlier version applied to every tar and fired inside `data.tar.gz` too
([`16-findings.md`](16-findings.md) §3.55); the fix kept the id (§4).

#### `gem-exclude-signatures`

`structural` tier, `default` stage. Profile: `gem`.

**Changes.** Removes members whose path ends in `.sig` from the gem's envelope, the outermost tar.

**Rationale.** The publisher signs a gem with a private key, over members the rebuild reproduces.

**Risk.** The comparison says nothing about whether the published gem was signed, or by whom.

**Limits.** Depth 0 only. An earlier version applied to every tar, fired inside `data.tar.gz` too,
and deleted a gem's own `lib/trusted-cert.sig` from both sides, so two gems that differed only in
that file compared equal ([`16-findings.md`](16-findings.md) §3.55). The fix kept the id (§4).

#### `gem-metadata-date-v2`

`metadata` tier, `default` stage. Profile: `gem`.

**Changes.** Replaces each line of the gemspec that begins `date:` with
`date: 1980-01-02 00:00:00.000000000 Z`. A rewritten gemspec also has its line endings made LF and
ends with a newline. The pass leaves a gemspec that is not valid UTF-8 as it is (§1).

**Rationale.** The gemspec records when `gem build` ran.

**Risk.** A difference in the date does not show.

**Limits.** The three gemspec passes apply to every member of any archive found at a path ending in
`metadata.gz`, at any depth, so the passes rewrite a gzip file the gem ships inside `data.tar.gz`
under such a name the same way. Only lines that begin at column 0 match. The passes leave a YAML
file in the payload alone unless it sits in an archive whose name ends `metadata.gz`.

#### `gem-metadata-date`

Superseded by `gem-metadata-date-v2`. `metadata` tier, `default` stage. Profile: `gem`, until the
rename.

The same line, in a gemspec it decoded lossily: one that was not valid UTF-8 came out with U+FFFD
for each invalid sequence, and two gems whose gemspecs differed in one such byte, 0xFF against 0xFE,
matched as a clean `normalized` (§1). The last `gem` set that carried it hashes to `cc5a0b733412…`.

#### `gem-metadata-rubygems-version-v2`

`metadata` tier, `default` stage. Profile: `gem`.

**Changes.** Replaces each gemspec line that begins `rubygems_version:` with
`rubygems_version: 0.0.0`, under the same rules as `gem-metadata-date-v2`.

**Rationale.** The RubyGems version that packaged the gem is a property of the build host.

**Risk.** A difference in the packaging tool's version does not show.

#### `gem-metadata-rubygems-version`

Superseded by `gem-metadata-rubygems-version-v2`. `metadata` tier, `default` stage. Profile: `gem`,
until the rename.

The same line, in a gemspec it decoded lossily, as `gem-metadata-date` did. The last `gem` set that
carried it hashes to `cc5a0b733412…`.

#### `gem-metadata-cert-chain-v2`

`structural` tier, `default` stage. Profile: `gem`.

**Changes.** Replaces the gemspec's `cert_chain:` line and the block after it (the lines that begin
with a space or a dash) with `cert_chain: []`, under the same rules as `gem-metadata-date-v2`. The
pass leaves a chain that is already `[]` alone, and an unsigned gem has none to drop.

**Rationale.** The chain certifies the key that signed the gem, over members the rebuild reproduces:
the argument that puts signature exclusion at `structural`.

**Risk.** The signer's identity does not show.

#### `gem-metadata-cert-chain`

Superseded by `gem-metadata-cert-chain-v2`. `structural` tier, `default` stage. Profile: `gem`,
until the rename.

The same block, in a gemspec it decoded lossily, as `gem-metadata-date` did. The last `gem` set that
carried it hashes to `cc5a0b733412…`.

### Wheel passes

#### `wheel-direct-url`

`lossy` tier, `default` stage. Profile: `wheel`.

**Changes.** Removes every member whose file name is `direct_url.json`, in any directory.

**Rationale.** pip writes `direct_url.json` into an installed distribution to record the URL or path
it installed from. It describes an install.

**Risk.** The pass removes a file a consumer would receive, which is what `lossy` is for: a wheel
that carries one caps at `normalized_with_caveats`, and the match holds whatever the file said. The
pass matches the name in any directory, not only in `.dist-info/`, so a package's own file of that
name goes too.

#### `pyc-header-v2`

`content` tier, `default` stage. Profile: `wheel`.

**Changes.** In a `.pyc` member, zeroes the source mtime where the header its magic number names
puts it. The magic is a two-byte number and `\r\n`:

| Magic | Writer | Header | Source mtime |
|---|---|---|---|
| 20121 to 62211, each by name | CPython 1.5 to 2.7 | 8 bytes: magic, mtime | bytes 4 to 8 |
| 3000 to 3209 | CPython 3.0 to 3.2, and 3.3's first alphas | 8 bytes: magic, mtime | bytes 4 to 8 |
| 3210 to 3391 | CPython 3.3 to 3.6, and 3.7's first alphas | 12 bytes: magic, mtime, source size | bytes 4 to 8 |
| 3392 to 3999 | CPython 3.7 onward (PEP 552) | 16 bytes: magic, flags, then mtime and size, or a hash | bytes 8 to 12, when the flags are 0 |

The magic number, the flags word, the source size and everything after the header stay. The pass
leaves alone a hash-based `.pyc` (flags 1 or 3), a flags word PEP 552 does not define, a magic it
does not recognize, and a file shorter than the header its magic names.

**Rationale.** A timestamp-validated `.pyc` records the mtime of the `.py` it was compiled from, for
cache invalidation, and the bytecode does not depend on it. The source size and a source hash both
follow from the source: zeroing them would remove a signal and normalize nothing. The reference
implementation has no `.pyc` pass, so this one is a listed deviation (`corpora/deviations.toml`,
`pyc-source-mtime`).

**Risk.** A difference in the recorded mtime does not show. The pass edits a shipped file, so it is
`content`.

**Limits.** Python 3's magic numbers are read by range, since CPython numbers them upward and 3.14's
are in the 3600s: a number in a range that no CPython release wrote is read as that range's header.
Python 2's are listed one by one, so one that `python -U` wrote, a number higher, is left alone.

#### `pyc-header`

Superseded by `pyc-header-v2`. `content` tier, `default` stage. Profile: `wheel`, until the rename.

It did not read the magic number, and took every header for PEP 552's: in a `.pyc` of at least 16
bytes whose second word had bit 0 clear, it zeroed bytes 8 to 12. Before 3.7 that word is the mtime
itself, so the pass zeroed the source size (3.3 to 3.6) or the first bytes of the code object
(Python 2) when the mtime was even, and nothing when it was odd. The last `wheel` set that carried
it hashes to `738725964c4a…`, the same set as `wheel-record-v2`'s.

#### `wheel-metadata-eol`

`content` tier, `default` stage. Profile: `wheel`.

**Changes.** Removes each carriage return that immediately precedes a line feed in four generated
files, which the pass matches by path suffix: `.dist-info/METADATA`, `.dist-info/WHEEL`,
`.dist-info/entry_points.txt` and `.dist-info/top_level.txt`. A lone carriage return stays.

**Rationale.** A wheel builder on Windows writes these files in text mode and gets CRLF; on Linux it
writes LF. `sniffio 1.3.1` matched in every member except these once Trigon pinned its build
backend.

**Risk.** A line-ending difference in those four files does not show. The pass leaves alone package
source, a licence and every other file in `.dist-info/`, whose line endings are the author's. The
suffix match reaches past the wheel's own metadata: a package that vendors a distribution with its
`.dist-info` directory, as setuptools does under `setuptools/_vendor/`, has those four files
rewritten in the vendored copy too.

#### `wheel-record-v3`

`content` tier, `finalize` stage. Profile: `wheel`.

**Changes.** Replaces the wheel's own `RECORD`, the one in the `.dist-info` directory at the root of
the archive, with a manifest of the members as they stand after every other pass: one row per other
member, `path,sha256=<digest>,<size>`, the digest URL-safe base64 without padding over the member's
stabilized bytes; rows sorted; a path quoted only where CSV needs it; `RECORD`'s own row last with
an empty digest and size. The pass does not report a `RECORD` already in that form.

A `.dist-info` directory below the root belongs to a distribution the wheel vendors, as setuptools
vendors under `setuptools/_vendor/`, and its `RECORD` is a member like any other. A wheel whose root
holds no `.dist-info` directory, or more than one, has no `RECORD` that is its own by the format
(pip refuses to install one with two), and the pass leaves every `RECORD` in it as it arrived.

**Stage.** The only builtin pass at `finalize`. Earlier passes change membership
(`wheel-direct-url`) and member bytes (`pyc-header-v2`, `wheel-metadata-eol`), and `RECORD`
describes both.

**Rationale.** As published, `RECORD` describes the wheel before stabilization.

**Risk.** The pass discards the published `RECORD` on both sides. A wheel whose `RECORD` lists a
wrong hash, a missing member or an extra one compares equal to a correct wheel with the same
members.

**Limits.** If the pass cannot read a member's bytes, it leaves `RECORD` as it arrived and writes no
manifest without that member. The digests are over each member's stabilized bytes, which for a
member no pass changed are its bytes as shipped. A published `RECORD` that is correct, sorted as the
pass sorts and written with LF line endings is therefore already in the pass's form, and the pass
leaves it alone and does not report it.

#### `wheel-record-v2`

Superseded by `wheel-record-v3`. `content` tier, `finalize` stage. Profile: `wheel`, until the
rename.

It replaced the first member whose path ended `.dist-info/RECORD`, in path order once
`zip-entry-order` had sorted the members. In a wheel that vendors a distribution whose
`.dist-info` directory sorts before its own, as `aaa/_vendor/dep-1.0.dist-info/` sorts before
`zzz-1.0.dist-info/`, it regenerated the vendored `RECORD` and compared the wheel's own as
published. The last `wheel` set that carried it hashes to `738725964c4a…`.

#### `wheel-record`

Superseded by `wheel-record-v2`. `content` tier, `finalize` stage. Profile: `wheel`, until the
rename.

It wrote the same `RECORD`. It is an archive pass, which names no member when it reports work, so a
comparison's field edits carried no `body` edit on `RECORD`; when the comparison began recording
that edit, the pass took a new id (§4). The last `wheel` set that carried it hashes to
`58632c3c627d…`, and a statement made under that set re-derives under its archived module.

### NuGet packaging passes

A `.nupkg` published from Windows and a rebuild on Linux differ first in packaging bookkeeping. The
payload compiles deterministically: Roslyn's deterministic build is on by default for SDK projects,
and two packs of one source produced byte-identical assemblies. These passes remove the bookkeeping.

#### `nupkg-signature`

`structural` tier, `default` stage. Profile: `nupkg`.

**Changes.** Removes the member at the exact path `.signature.p7s`, at the root of the package. A
file of that name in a subdirectory, or spelled in another case, stays.

**Rationale.** `.signature.p7s` holds the package signature: the repository signature nuget.org adds
after upload, over the bytes it received, and the author's signature where there is one. Both are
made with keys no rebuilder holds, and nothing anyone builds carries one.

**Risk.** The comparison says nothing about the signature: whether the package was signed, and by
whom. Every other member still compares. The pass sits at `structural`, beside the gem signature
passes.

#### `nupkg-packaging-names`

`structural` tier, `default` stage. Profile: `nupkg`.

**Changes.** The pass acts only on a zip that has a root `_rels/.rels` part, which is what makes it
an OPC package. It renames any member `package/services/metadata/core-properties/<name>.psmdcp` to
`package/services/metadata/core-properties/core.psmdcp`, and rewrites `_rels/.rels`: each
`Target="…psmdcp"` becomes that canonical path, and each `Id="…"` becomes `R0`, `R1` and so on, in
the order they appear. A renamed member keeps its original name, so a report can point at the bytes
as published.

**Rationale.** `dotnet pack` names the core-properties part after a fresh GUID on every run
(`55d4e0b4ecfa412baa282881ce747f48.psmdcp` and `4f28fcb5c9304310a279a6ce74f94f55.psmdcp`, two packs
minutes apart), and writes random relationship ids beside it, whose case differs between NuGet 4.5
and 7.0 (`R192ff84775f641df` against `R2BEFEA914E60C8DE`).

**Risk.** The part's name and the relationship ids stop showing; the part's contents still compare.
A zip without `_rels/.rels` (a wheel, a jar) never has a member renamed on the strength of a suffix.

**Limits.** The `_rels/.rels` rewrite works on bytes and rewrites every `Id="` it meets, which in a
relationships part is every relationship. The pass leaves a `_rels/.rels` it cannot read as it is.

#### `nupkg-packager-version`

`metadata` tier, `default` stage. Profile: `nupkg`.

**Changes.** In the core-properties part (`package/services/metadata/core-properties/*.psmdcp`),
empties the text of the first `<lastModifiedBy>` element.

**Rationale.** NuGet records the packing tool, its version and the operating system there. For the
published Newtonsoft.Json 11.0.1 it reads
`NuGet.Build.Tasks.Pack, Version=4.5.0.4, …;Microsoft Windows NT 10.0.16299.0;.NET Framework 4.5`.

**Risk.** The tool and machine that packed the package do not show. A `<lastModifiedBy>` in any
other member is content and stays.

**Limits.** The pass matches the literal text `<lastModifiedBy>`, so it leaves alone a prefixed
`<cp:lastModifiedBy>` and an element that carries attributes.

#### `nupkg-portable-folder-name`

`structural` tier, `default` stage. Profile: `nupkg`.

**Changes.** Renames the target-framework folder of a payload path `lib/<framework>/…` when
`<framework>` begins `portable`: drops the digits immediately after `portable`, then decodes each
`%2B` (either case) to `+`. `lib/portable-net45%2Bwin8%2Bwp8%2Bwpa81/` and
`lib/portable45-net45+win8+wp8+wpa81/` both become `lib/portable-net45+win8+wp8+wpa81/`. A renamed
member keeps its original name.

**Rationale.** NuGet's spelling of a PCL profile changed. The 2018 client percent-encoded the `+`; a
modern client writes the profile's .NET version after `portable`. The components and their order are
the same on both sides. Without the pass, a rebuild that reproduced both of Newtonsoft.Json's PCL
assemblies reported four members only upstream and four only in the rebuild.

**Risk.** Only the spelling of the folder name goes; the members still compare. The pass reorders no
monikers, touches no folder outside `lib/`, and leaves alone a name that does not begin `portable`.

#### `nupkg-text-eol`

`content` tier, `default` stage. Profile: `nupkg`.

**Changes.** Removes each carriage return that immediately precedes a line feed, in members whose
name ends `.nuspec`, `.rels`, `.psmdcp`, `.xml`, `.md` or `.txt`, anywhere in the package. The pass
selects members by extension and does not sniff content, so it does not rewrite a `.dll` or `.exe`.

**Rationale.** NuGet writes text members with the line endings of the machine that packed them. On
Newtonsoft.Json 11.0.1, nine of twenty-three members match once this runs and differ without it.

**Risk.** These are bytes a consumer receives, a `.txt` or `.xml` the package ships as content among
them, so the pass is `content` and a match that needs it is `normalized_with_caveats`.

**Limits.** The extensions match case-sensitively, so `LICENSE.TXT` and `README.MD` keep their line
endings. A `.md` member reaches this pass after `nupkg-readme-markers-v2`, which strips trailing
carriage returns from every Markdown file it rewrites. `applied` therefore credits a CRLF Markdown
file to that pass, and this one finds nothing left in it.

#### `nupkg-doc-member-order-v2`

`structural` tier, `default` stage. Profile: `nupkg`.

**Changes.** In a member under `lib/` whose name ends `.xml`, sorts the `<member …>` blocks inside
`<members>` by their `name` attribute, in byte order. Each block moves whole, with its text and the
whitespace after it. The file needs a `<members>` element, a `</members>` after it, and at least two
members; the pass leaves any other shape alone. The pass reports the rewritten file's length as the
bytes it changed.

**Rationale.** Roslyn writes the elements in the host's collation order, and Windows and ICU
disagree about where `.` sorts. On Newtonsoft.Json 11.0.1 one twenty-one-line block moves, in four
of the nine documentation files.

**Risk.** Only the order goes; each member's documentation text still compares.

**Limits.** The pass cuts blocks at the literal text `<member `, so documentation text containing
that string splits a block. The pass cuts both sides the same way.

#### `nupkg-doc-member-order`

Superseded by `nupkg-doc-member-order-v2`. `structural` tier, `default` stage. Profile: `nupkg`,
until the rename.

The same sort. It reported the rewrite as zero bytes, so `applied` signed `bytesChanged: 0` for a
body it had rewritten, and no field edit named the member it had reconciled. Counting the bytes
changes what a statement signs, so the pass took a new id (§4). The last `nupkg` set that carried it
hashes to `266ab529cd64…`.

#### `nupkg-repository-branch-v2`

`metadata` tier, `default` stage. Profile: `nupkg`.

**Changes.** In a member whose name ends `.nuspec`, removes the `branch` attribute, and the
whitespace before it, from the first `<repository …>` element. The pass reads the tag attribute by
attribute, stepping over each value, in either quote, to its closing quote, so a ` branch="` inside
another attribute's value is text and stays. The `commit` attribute and every other attribute stay,
and a `branch` attribute on any other element stays.

**Rationale.** The branch names the ref the publisher built from. A publisher building from the
release tag writes `branch="v4.20.72"`; Trigon checks the commit out detached, so its build writes
no branch. The commit is the identity, and the pass keeps it.

**Risk.** A difference in the recorded branch does not show.

**Limits.** The pass works on text, and leaves a `.nuspec` that is not valid UTF-8 as it is (§1).
It looks only at the first `<repository` in the file, and leaves the file as it is when that one is
inside a comment, when its tag does not close, when an attribute in it is not `name="value"` or
`name='value'`, and when it names `branch` twice.

#### `nupkg-repository-branch`

Superseded by `nupkg-repository-branch-v2`. `metadata` tier, `default` stage. Profile: `nupkg`,
until the rename.

The same attribute, in text it decoded lossily (§1), found by a search for ` branch="` inside the
tag. The search found one inside another attribute's value as readily: in
`url="https://example.com/r branch=" commit="…"` it cut from inside the URL through the opening
quote of `commit`, and the nuspec matched one with another URL and no commit as a clean `normalized`
([`16-findings.md`](16-findings.md) §3.106). The last `nupkg` set that carried it hashes to
`e473a7e21721…`.

#### `nupkg-readme-markers-v2`

`content` tier, `default` stage. Profile: `nupkg`.

**Changes.** In every member whose name ends `.md`: removes each line that holds only a single-token
HTML comment (`<!-- include foo -->`, `<!-- foo -->`), trims trailing whitespace from every line,
collapses each run of blank lines to one, drops leading blank lines, and ends the file with a single
newline. The pass does not report a file it leaves unchanged, and leaves one that is not valid UTF-8
as it is (§1).

**Rationale.** NuGetizer assembles a readme from `<!-- include … -->` directives and leaves the
markers in. Trigon's NuGet build neutralizes remote includes so the pack stays offline
([`16-findings.md`](16-findings.md) §3.86). That leaves three lines different from the publisher's
networked build: the neutralized include directive, a marker whose pairing shifted with it, and a
trailing blank line. The included text reproduces.

**Risk.** The pass rewrites more than NuGetizer's markers. It applies to every Markdown file in the
package, and trimming trailing whitespace removes Markdown's two-space hard line break, which
changes how the file renders. A one-word comment line goes wherever it appears. The pass is
`content`, so a match that needs it caps.

#### `nupkg-readme-markers`

Superseded by `nupkg-readme-markers-v2`. `content` tier, `default` stage. Profile: `nupkg`, until
the rename.

The same rewrite, of text it decoded lossily (§1). The last `nupkg` set that carried it hashes to
`e473a7e21721…`.

### .NET assembly passes

Both passes act on members whose name ends `.dll` or `.exe`, in any case and in any directory of the
package, and read the PE by hand: no decompiler or metadata crate for the verifier to link and a
sceptic to audit. Every offset they read is one the publisher wrote, so the passes bound-check every
read, and no offset arithmetic can overflow on the 32-bit WebAssembly build of an archived set.

#### `dotnet-assembly-identity-v2`

`metadata` tier, `default` stage. Profile: `nupkg`.

**Changes.** Walks the PE, optional, CLI and metadata headers and zeroes, in place:

- the COFF header's TimeDateStamp and the optional header's CheckSum;
- the strong-name signature the CLI header points at;
- the debug data directory's own RVA and size, each debug directory entry's TimeDateStamp, and the
  data each entry names: the CodeView record (the PDB's GUID, age and path), a PDB checksum, an
  embedded portable PDB;
- the whole `#GUID` heap, which holds the module's MVID.

It zeroes a region only once it is shown to be what its header calls it, and otherwise leaves the
whole assembly as it arrived (Declines). The member keeps its length and every offset. The pass
leaves an assembly with nothing but zeros in those regions on its original bytes and does not report
it. A compiler writes a non-zero MVID into `#GUID`, in a deterministic build too, so in practice the
pass reports every managed assembly it does not decline.

**Rationale.** None of it is code, and none of it is reproducible by a rebuilder: a signature made
with a key the rebuilder does not have, a per-compilation GUID, build stamps, and a record of where
the build wrote a `.pdb` the package does not ship. On castle.core's net6.0 assembly, with its
version reconstructed, the first version of the pass took a 485-byte difference to 217
([`16-findings.md`](16-findings.md) §3.81).

**Tier.** The signature alone would be `structural`, and the stamps and GUIDs are `metadata` like
the archive timestamps. A pass carries the higher of what it does, so `metadata`, and alone it caps
nothing. In the `nupkg` profile nothing it zeroes reaches a digest. It acts only where
`dotnet-il-canonical-v3` reads the same canonical form from the zeroed bytes as from the published
ones, and that pass, which runs next, replaces the assembly with the form, so a match there is
`normalized_with_caveats` whatever this pass did. The checks below stand between its zeroing and a
digest only in a set narrowed without the IL pass, which `trigon stabilize --disable-passes` makes
and under which no verdict is reached.

**What counts as identity.** Every region but the timestamp, the checksum and the debug directory's
slot is named by a pointer the publisher wrote, and a pointer can name code as readily as a
signature. So the pass first delimits everything the assembly holds (`occupied`, in
`crates/trigon-stabilize/src/ilcanon.rs`), finding each structure where the runtime reads it:
through the section that maps its address, or, below `SizeOfHeaders` where no section does, in the
headers, which the loader maps at the image's base. It holds:

- the headers;
- each PE data directory but the debug directory, the certificate table by its file offset, and
  what the import and resource directories point at: each import descriptor, the name of the DLL it
  imports from, its lookup and address tables, and each import's hint and name; each resource
  directory table, name, data entry and the data it names;
- the CLI header and the directories it names: managed resources, the code manager table, the VTable
  fixups and the slots each names, the export address table jumps;
- the metadata root, its stream directory, and every stream but `#GUID`; every table's rows;
- every method body with its exception sections;
- the data each FieldRVA row names, as long as its field's type says, or to the end of what the
  loader maps there when the type has no size the pass can read. A primitive has a size, and so has
  a value type a ClassLayout row sizes whole: a `ClassSize` that is not 0, of a type with no fields,
  which no second row names. A `ClassSize` of 0 is no `.size` at all, and a type with fields is as
  long as they lay out when that is longer (ECMA-335 §II.22.8, §II.10.7);
- sixteen bytes from the entry point, the startup stub.

Then:

- the strong-name signature, the debug directory, each debug entry's data and the `#GUID` heap each
  lie wholly in the file, clear of the headers, of everything the assembly holds, and of one
  another. Every debug entry's data is placed before any of it is read, and two that overlap decline
  the assembly there, so reading the records costs the file's length at most;
- each debug entry is one of four types, laid out as that type is: a CodeView record (`RSDS`, a GUID
  and an age, then a path whose NUL is followed by nothing but zeros), a PDB checksum (`SHA256`,
  `SHA384` or `SHA512`, a NUL, and a digest exactly that hash's length), an embedded portable PDB
  (`MPDB`, a non-zero inflated size, then data), or a Reproducible entry that names no data at all;
  where an entry gives both an address and a file offset, they name the same bytes;
- the `#GUID` heap lies after the stream directory, inside the metadata the CLI header states, and
  is a whole number of GUIDs, and every heap index in every row names an entry inside its own heap,
  so nothing but a GUID column reads `#GUID`;
- the assembly has a canonical form ([`dotnet-il-canonical-v3`](#dotnet-il-canonical-v3)), and with
  every region zeroed it reads to the same one.

**Declines.** The pass leaves the whole assembly untouched, and zeroes none of it, when:

- it is not a managed PE: no `MZ` or `PE\0\0` signature, an optional header neither PE32 nor PE32+,
  no CLI header (a native image), headers cut short;
- it carries native code, which has no extent the metadata states: the CLI header's ILONLY flag is
  clear (a mixed-mode C++/CLI assembly), its NATIVE_ENTRYPOINT flag is set, or it names a
  ManagedNativeHeader (ReadyToRun);
- it has a data directory that points at native code or at tables of its own, which no managed
  compiler writes: exports, exception data, TLS, load configuration, bound or delay imports;
- what it holds cannot be delimited: a CLI header, metadata root or method body at an address no
  section maps; a directory, FieldRVA row or entry point at an address no section maps, past
  `SizeOfHeaders`; imports or resources that run past what the loader maps there, or name one
  structure over and over past the file's length; a method whose body is native code or neither
  tiny nor fat, two sections that claim one address, no table stream or no `#Strings` or `#Blob`
  heap, a table ECMA-335 does not define, a stream listed twice, rows that run past the metadata;
- any one region fails a check above: a debug entry of another type (such as the POGO and VC feature
  records a C++ linker writes), a record that is not laid out as its type or runs on past its end,
  an entry whose data is not in the file or runs past its end, two entries whose data overlap, a
  debug directory that is not a whole number of entries or lies in no section, a strong-name
  signature that runs past the end of the file or over anything the assembly holds, a `#GUID` heap
  over the metadata root or the stream directory, past the metadata the CLI header states, or over
  another stream;
- `dotnet-il-canonical-v3` would decline it (a form past four times the assembly, say), or the
  zeroed assembly reads to another form.

A debug directory slot with an address and no size, or a size and no address, names nothing: the
pass leaves the slot and zeroes the rest.

**Risk.** A difference in any of those regions does not show. The checks cannot tell a record of the
right shape in slack space the assembly does not use from one the compiler wrote, and zeroing slack
hides nothing the runtime reads. Before them, an entry could name any range of the file after its
first byte, code included (the superseded entry below).

**Limits.** The residual the pass cannot reach is layout. If two builds write PDB paths of different
lengths, the debug entries and the data after them sit at different offsets, and zeroing aligns only
regions at the same offset ([`17-backlog.md`](17-backlog.md) B46). `dotnet-il-canonical-v3` handles
that case. In the `nupkg` profile that pass replaces every assembly this one zeroes, with a form the
zeroing did not change, so this pass shows in `applied` and never in the digest.

#### `dotnet-assembly-identity`

Superseded by `dotnet-assembly-identity-v2`. `metadata` tier, `default` stage. Profile: `nupkg`,
until the rename.

It zeroed the same regions, found by the same walk, and checked none of them: whatever range each
debug entry named, the strong-name signature wherever the CLI header put it, and every `#GUID` heap
the stream directory listed. It skipped a region that ran past the end of the file and zeroed the
rest, and it zeroed the other regions of an assembly whose metadata it could not read. An entry
could name any range of the file after its first byte, code included: two one-member packages whose
assemblies differed in 220 bytes of code, each with an entry naming the whole file, stabilized to
the same bytes, `dotnet-il-canonical-v2` could read neither and declined, and the verdict was a
clean `normalized`. An entry naming the `#US` heap made two assemblies that differed only in a
string literal match as `normalized_with_caveats`. The last `nupkg` set that carried it hashes to
`e473a7e21721…`.

#### `dotnet-il-canonical-v3`

`lossy` tier, `default` stage. Profile: `nupkg`.

**Changes.** Replaces each managed assembly it can read whole with the canonical form of its code:
what the code is, resolved through the metadata heaps to values, and nothing about where the
compiler put it. The form, every number little-endian:

1. `0x06`, the MethodDef row count as a `u32`, then one record per method in table order: its name
   and its signature, each behind a `u32` length; its ImplFlags and Flags as the row holds them; its
   ParamList as a `u32`; a byte, `0` for a method with no body and `1` for one with a body; and for
   a body, its header and its IL, each behind a length, then the total length of its extra-data
   (exception-handling) sections and the sections themselves.
2. Each kept table in id order: the id as a byte, the row count as a `u32`, then each row column by
   column. A `#Strings` or `#Blob` index is written as the string or blob it names, behind its
   length; a table or coded index as a `u32`; any other column as the integer it holds.
3. `0x70`, the token type of a string literal, and the whole `#US` heap behind its length.

Lengths frame every field, because an IL body or a signature can hold any byte: framed by
separators, a call moved from a body into its signature, or a method folded into the body before it,
would read back as the original program.

The kept tables:

| Kept because | Tables |
|---|---|
| an IL token or a signature can name them | TypeRef, TypeDef, Field, MemberRef, StandAloneSig, ModuleRef, TypeSpec, MethodSpec, and AssemblyRef, where a TypeRef resolves |
| they decide how the code runs, though no token names them | Param, Constant, FieldMarshal, InterfaceImpl, MethodImpl, ImplMap (P/Invoke), ClassLayout, FieldLayout, NestedClass, GenericParam, GenericParamConstraint, EventMap, Event, PropertyMap, Property, MethodSemantics, ExportedType |
| the uncompressed (`#-`) layout routes ownership through them | FieldPtr, MethodPtr, ParamPtr, EventPtr, PropertyPtr |

A token is a row number or a `#US` offset, and the form holds whatever it names at that position. A
body that calls another method, catches another type or loads another literal under an unchanged
token therefore still differs, and so does a changed flag, signature, P/Invoke target, override or
implemented interface.

**Rationale.** Builds of one source can differ throughout an assembly without differing in code.
`moq@4.20.72`'s four assemblies decompile to identical C#, and their method IL is byte for byte
equal, yet about 56 KB of each 312 KB differs: the embedded PDB, SourceLink's repository URL, the
order a source generator's documents landed in, and heap offsets that shift when one string upstream
changes length ([`16-findings.md`](16-findings.md) §3.87). A pass that zeroes bytes in place cannot
align offsets that moved. With this pass, `moq@4.20.72` compares `normalized_with_caveats`.

**Risk.** The form drops these, and a difference only in them reads as a caveated match:

- manifest resources, and with them any data or code the assembly loads from them at run time;
- custom attributes and security declarations (CustomAttribute, DeclSecurity), which code driven by
  reflection reads;
- the data a field is initialized from (FieldRVA), such as a static array's initial bytes;
- the Module and Assembly rows (the assembly's own name, version and public key), the File and
  ManifestResource rows, and the processor, OS and edit-and-continue tables;
- the metadata's own encoding: the version string in the metadata root, the fields of the `#~`
  header, any `#Strings` or `#Blob` entry that no method or kept row names, and every other stream,
  such as `#Pdb`;
- the `#GUID` heap, and everything outside the metadata and the method bodies: the PE and CLI
  headers (the entry-point token among them), Win32 resources, the strong-name signature and the
  debug data.

`lossy` is the tier for that. A match through this pass is `normalized_with_caveats`: the code
matched, and nothing checked the rest. The pass fires on every assembly it reads, whether or not a
layout residual remains, so a `.nupkg` holding a readable managed assembly reaches a clean verdict
only as `exact` ([`16-findings.md`](16-findings.md) §3.89).

**Declines.** The pass leaves the member as `dotnet-assembly-identity-v2` left it when it cannot
read the assembly whole, as the runtime reads it:

- not a managed PE: no `MZ` or `PE\0\0`, neither PE32 nor PE32+, no CLI header, no `BSJB` metadata
  root, or a header cut short;
- a CLI header, metadata root or method body at an RVA no section maps;
- no `#~` or `#-` table stream, or no `#Strings` or `#Blob` heap (an assembly without `#US` reads
  with an empty one);
- two sections that claim one address;
- a row, `#Blob` entry, `#US` heap, method body or extra-data section that runs past the bytes the
  file backs of its section: past `SizeOfRawData` the loader maps zeros, and the pass never reads
  the file bytes there;
- a method body whose header is neither tiny nor fat;
- a method with a body whose code type is not IL (native, OPTIL or runtime), such as the native code
  of a mixed-mode C++/CLI assembly;
- an image whose CLI header says it carries native code no method need name: ILONLY clear (a
  mixed-mode C++/CLI assembly), NATIVE_ENTRYPOINT set (a native entry point the loader runs), or a
  ManagedNativeHeader (ReadyToRun's precompiled methods, which the runtime runs in place of their
  IL). None of that code is in the form, so read past, two images of one IL and different native
  code shared a form;
- a form that would exceed four times the assembly's size;
- a field too long for its `u32` length.

A `#Strings` entry that runs past those bytes does not decline the assembly. The form cuts the entry
where the backed bytes end, and reads an offset past them as an empty string, as the runtime reads
the zeros the loader maps there.

A cross-check of `-v2` against `System.Reflection.Metadata` over 6,707 PE files from a local NuGet
cache and SDK found that the form read 6,659 and agreed with the reference on every method and kept
row, apart from two places the reference normalizes a value the form keeps raw. Ten of the 48 it
declined are the mixed-mode `System.EnterpriseServices.Wrapper.dll` files, and the other 38 carry no
metadata. The largest form was 2.2 times its assembly. Scanned again for `-v3`, the same cache and
SDK hold 6,356 managed assemblies once links are resolved, and 414 of them declare native code in
their CLI header, which `-v3` leaves as they are: the SDK's 394 ReadyToRun assemblies, the ten
`System.EnterpriseServices.Wrapper.dll` files, and ten mixed-mode .NET Framework assemblies from
reference packages (two copies each of `System.Data.dll`, `System.Data.OracleClient.dll`,
`System.Transactions.dll`, `CustomMarshalers.dll` and `ISymWrapper.dll`), which `-v2` read.

**Limits.** The form is positional. Two builds that number the same rows differently, such as
another compiler version or a type a generator added, still differ, and the form cannot tell a
renumbering from a real change. Newtonsoft.Json 11.0.1 rebuilt with a current SDK stays `divergent`
for both reasons: 92% of its matched methods are identical but for token numbering, and 7.7% are
lowered differently ([`03-ecosystems.md`](03-ecosystems.md) §5.0.2). The form is not a PE, so a
second run declines it and stabilization stays idempotent.

#### `dotnet-il-canonical-v2`

Superseded by `dotnet-il-canonical-v3`. `lossy` tier, `default` stage. Profile: `nupkg`, until the
rename.

The same form. It declined an assembly with a method whose body was native, and read the rest of an
image that carried native code no method named: a ReadyToRun image, whose precompiled methods the
runtime runs in place of their IL, and a mixed-mode image with a native entry point. Two images of
one IL and different native code shared a form and matched as `normalized_with_caveats`
([`16-findings.md`](16-findings.md) §3.106). The last `nupkg` set that carried it hashes to
`e473a7e21721…`, the same set as `nupkg-repository-branch`'s.

#### `dotnet-il-canonical`

Superseded by `dotnet-il-canonical-v2`. `lossy` tier, `default` stage. Profile: `nupkg`, until the
rename.

It kept each method's name, signature and IL, and nothing the IL's tokens named. A changed string
literal of the same length, a MemberRef renamed or moved to another type under the same token, a
method's flags, the fat header's MaxStack and locals, a catch clause's type, a P/Invoke's entry
point, an explicit override and an implemented interface all compared equal, so a changed program
could read as a caveated match. It also read bodies and heaps past `SizeOfRawData`, where the
runtime sees zeros. The new form under the old id would have re-derived old records differently
under the digest they were signed with, so the form took a new id (§4). The last `nupkg` set that
carried it hashes to `266ab529cd64…`, the same set as `nupkg-doc-member-order`'s.

---

## 4. Archived sets, and renaming a pass

A statement names the profile and its set digest. The digest covers each pass's id, stage, tier and
provenance, and not its code ([`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) §4.2,
item 2). Two practices follow from that.

**An archived set lets a verifier re-derive a claim under the set that made it.** `trigon verify`
refuses to compare across differing set digests: it re-derives under today's set and labels the
result a new claim. Checking the old claim itself needs the code that made it, so
`trigon-stabilize-wasm` compiles the stabilizer registry of one commit, every profile in it, into a
WebAssembly core module. `scripts/build-set-module.sh` builds it reproducibly. Every published
verdict names its module by sha256, `trigon attest` names one only once it has reproduced the run,
and `trigon publish` puts it in `evidence/` beside the record
([`09-attestations.md`](09-attestations.md) §7.1). `verify-attestation`, where its binary does not
carry the set a verdict names, runs the module the record carries, once the module's sha256 is the
one the verdict signs; it also asks the module for the digest of the profile the statement names,
and refuses one that answers with another. `--stabilizers` runs a module given on the command line:

```
scripts/build-set-module.sh
trigon verify-attestation --rerun-comparison --stabilizers set.wasm …
```

The full build runs modules; the verifier build needs `--features wasm`.
`crates/trigon-stabilize-wasm/tests/parity.rs` checks that a module reports the native digest of
every profile and stabilizes sample artifacts to the native bytes. A published set manifest
(`SetManifest`, as JSON) lists the members exactly as the digest covers them and recomputes to the
digest it claims, so a reader without the module still learns what the set was. A module returns
stabilized bytes and no `applied` list, so a claim re-derived through one reaches
`normalized_with_caveats` at best, and a `normalized` claim re-derived so is reported *consistent*,
neither held nor refuted ([`16-findings.md`](16-findings.md) §4b).

**Since 62781a8, a pass whose behaviour changes takes a new id.** Under an unchanged id, a change to
what a pass writes or reports keeps the set digest, and today's code would re-derive an old record
differently under the digest it was signed with, so an honest record would read as refuted.
[`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) D9 (§11.1) decides that the digest
keeps covering ids and not code, and that each set is archived as a WASM module in `evidence/`. So
a changed pass takes a new id with a `-vN` suffix: the new id moves the set digest, and a record
made under the old one goes to its archived set, where the code that made it re-derives it. Three
passes took new ids in 62781a8:

| Old id | New id | What changed | Set digest, before and after |
|---|---|---|---|
| `wheel-record` | `wheel-record-v2` | nothing in the `RECORD` written; the rewrite is now recorded as a `body` edit on `RECORD` | `wheel`: `58632c3c627d…`, then `738725964c4a…` |
| `nupkg-doc-member-order` | `nupkg-doc-member-order-v2` | the bytes it rewrites are counted, where v1 signed `bytesChanged: 0` | `nupkg`: `266ab529cd64…`, then `e473a7e21721…`, with the row below |
| `dotnet-il-canonical` | `dotnet-il-canonical-v2` | a new form: flags, whole bodies, every row a token names, the declarations, `#US` | the same change of the `nupkg` digest |

The earlier `wheel` digest is the one `crates/trigon-attest/tests/renamed_pass.rs` pins as published
([`16-findings.md`](16-findings.md) §3.91); the test rebuilds that set from today's by giving the
RECORD pass and `pyc-header-v2` the ids they had then. This page computes the earlier `nupkg` digest
from that set's rows before the renames, by the method `StabilizerSet::digest` uses; no test pins
it, unlike `wheel`'s.

Twelve more passes took new ids when writing this page from the code found defects in them, and a
thirteenth when a review of those fixes found `dotnet-il-canonical-v2` reading past native code
([`16-findings.md`](16-findings.md) §3.106). Several of the defects were false matches, the failure
the project exists to avoid:

| Old id | New id | What changed |
|---|---|---|
| `dotnet-assembly-identity` | `dotnet-assembly-identity-v2` | zeroes a region only once it is shown to be identity, and leaves the assembly whole otherwise, where a debug entry could name code |
| `cargo-vcs-hash`, `npm-install-fields`, `gem-metadata-date`, `gem-metadata-rubygems-version`, `gem-metadata-cert-chain`, `nupkg-repository-branch`, `nupkg-readme-markers` | each with `-v2` | leave a member that is not valid UTF-8 as it is, where they decoded it lossily and two members differing only in an invalid byte matched |
| `pyc-header` | `pyc-header-v2` | reads the magic number and zeroes the mtime where that header puts it, where it read every header as 3.7's |
| `wheel-record-v2` | `wheel-record-v3` | regenerates the wheel's own `RECORD`, where it took the first in path order |
| `tar-entry-order` | `tar-entry-order-v2` | marks an archive it sorted changed, and writes every nested tar again |
| `gzip-meta` | `gzip-meta-v2` | writes a gzip layer the gem format defines again, whatever its header |
| `dotnet-il-canonical-v2` | `dotnet-il-canonical-v3` | leaves an image whose CLI header declares native code as it is, where it read past ReadyToRun code and a native entry point |

Every profile but `zip` and `raw` carries one of them:

| Profile | Set digest before | Set digest after |
|---|---|---|
| `tar` | `c294a4d0c8a7…` | `a1b74ac55ad4…` |
| `tar-gzip` | `4598411b636d…` | `cadb3a863443…` |
| `gzip` | `ef4835dee29e…` | `e7b47b1ed937…` |
| `npm-tarball` | `562ce45ae605…` | `8b992c8410f0…` |
| `crate` | `fcd80dd27bb9…` | `5ac2049396f6…` |
| `gem` | `cc5a0b733412…` | `b7f07d65a95c…` |
| `wheel` | `738725964c4a…` | `188d208b5a9e…` |
| `nupkg` | `e473a7e21721…` | `d7edf6128800…` |

The digests before are the ones this page recorded, recomputed from each set's rows; the digests
after are the registry's.

Two fixes of the same round changed the parser and the serializer, which no pass id covers
(§1.2): a gzip file whose members after the first hold data is refused where it was read as every
member's content, and a tar name, link target or PAX record is written as the bytes it is where it
was decoded lossily. Each changes what some artifact stabilizes to in a profile that walks a tar or
a gzip layer, and every such profile took a new set digest in the table above, so no record made
before them re-derives under a digest it was signed with. `zip` and `raw`, whose digests did not
move, write a nested tar or gzip file back as the bytes it arrived as, before and after.

Some changes kept their ids. Before 62781a8, `gem-exclude-signatures` and `gem-exclude-checksums`
narrowed to the gem's envelope and `zip-versions` began keeping the file type
([`16-findings.md`](16-findings.md) §3.55), each under its old id, so §3 describes their earlier
versions under the current ids. The same commit changed the output of `npm-install-fields`, which
now removes the comma a dropped last property leaves behind, under the same id: nothing selects
`npm-tarball`, so no record names the pass and none re-derives differently (§1.1). The pass has
taken a new id since, for the UTF-8 fix, though the same reasoning held: a rule followed without
exceptions is one nobody has to remember the exceptions to.

Each retired id keeps an entry in §3, marked superseded, so a reader holding an old statement can
look up what its `applied` list meant. The completeness test keeps a list of retired ids, requires
an entry for each, and requires the list to name every id a `-vN` pass replaced.

---

## 5. Ids from the design catalogue

[`05-archive-and-normalization.md`](05-archive-and-normalization.md) §3.1 lists the passes as first
designed. Each id there that has an entry in §3 shipped under that id, and several have taken a
`-vN` id since (§4). The others map to this build as follows:

| Design id | In this build |
|---|---|
| `gzip-name`, `gzip-time`, `gzip-misc` | [`gzip-meta-v2`](#gzip-meta-v2) |
| `gzip-compression` | no pass: the serializer writes gzip at level none, and `gzip-meta-v2` and `tar-entry-order-v2` see that it writes a nested layer again (§1.2) |
| `zip-data-descriptor` | no pass: `zip-misc` zeroes the flags, and the zip writer never writes a data descriptor and computes each CRC and size from the member's bytes |
| `zip-encoding` | no pass of its own: `zip-misc` zeroes the UTF-8 flag with the other flags |
| `pe-deterministic`, `pdb-normalize` | [`dotnet-assembly-identity-v2`](#dotnet-assembly-identity-v2), at `metadata` rather than `content`, with [`dotnet-il-canonical-v3`](#dotnet-il-canonical-v3) after it |
| `nupkg-exclude-signature` | [`nupkg-signature`](#nupkg-signature) |
| `nuspec-normalize` | not built; a `.nuspec` gets [`nupkg-text-eol`](#nupkg-text-eol) and [`nupkg-repository-branch-v2`](#nupkg-repository-branch-v2) |
| `nupkg-opc-ordering` | not built; [`nupkg-packaging-names`](#nupkg-packaging-names) renumbers the relationship ids in `_rels/.rels` and reorders nothing |
| `wheel-generator`, `npm-prefix`, `gem-metadata-yaml-normalize` | not built |
| `jar-build-metadata`, `jar-attribute-order`, `jar-git-properties`, `jar-signature` | not built; a `.jar` gets the `zip` profile (§1.1) |

The design lists none of `wheel-metadata-eol`, the NuGet packaging passes other than the signature
pass, or `dotnet-il-canonical-v3`; §3 documents each.
