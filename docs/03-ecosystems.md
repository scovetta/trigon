# 03. Ecosystems

Each chapter follows the same structure, so adding one is a fill-in-the-blanks exercise:
**resolution, source discovery, toolchain evidence, build, output, nondeterminism, stabilizer
profile, expected outcome**. A chapter that needs a special case in the engine, rather than in its
own `Registry` implementation and stabilizer profile, tells us the seam in
[`01-architecture.md`](01-architecture.md) is wrong.

## 0. The landscape in 2026

| Ecosystem | Reproducibility state | Hard part for us | Priority |
|---|---|---|---|
| **npm** | ~100% at tarball level (package managers hard-code archive metadata); **no source linkage whatsoever** | Source discovery and build inference | **M1** |
| **PyPI** | ~12% → ~98% with `SOURCE_DATE_EPOCH` + umask fixes; timestamps are 87.7% of failures | Native-extension wheels | **M1** |
| **crates.io** | Highly reproducible by design since `trim-paths` became the release default | Toolchain-window inference; build scripts and proc macros | M5 |
| **RubyGems** | 0% → 99.9% since 3.6.7 defaults `SOURCE_DATE_EPOCH` and sorts gemspec metadata. **No independent verification infrastructure exists anywhere.** | Native extensions | M5 |
| **NuGet** | Trusted publishing since Sept 2025; **almost no reproducibility infrastructure** | We are partly inventing this ecosystem's story | M5 |
| **GitHub** | Not applicable. The artifact is a release asset or source archive | Everything comes from the release workflow | M5 |

Sources: the reproducible-builds project's per-ecosystem reporting through 2026, PEP 740 and the
PyPI Integrity API, RubyGems 3.6.7 release notes, Rust RFC 3127 (`trim-paths`), and the
"Reproducible Builds in Language Package Managers" survey (Nesbitt, Feb 2026).

Two framing consequences to state up front:

- **npm needs a different pitch.** With near-total tarball-level reproducibility and zero source
  linkage, asking whether an npm package rebuilds gets you a yes every time. The npm question is
  **whether the published tarball corresponds to the claimed source**, which is source attribution.
  Present it any other way and npm users see a wall of green and shrug.
- **RubyGems and NuGet offer the cheapest differentiation**, because nobody is doing either. They sit
  after npm and PyPI because we chose depth first, and for no other reason.

---

## 1. npm

### Resolution
`GET https://registry.npmjs.org/{name}` → version document. Artifact at
`{registry}/{@scope/}{name}/-/{name}-{version}.tgz`, with `dist.integrity` and `dist.shasum` giving
the expected digest before download. Scoped names URL-encode `@` as `%40`.

### Source discovery
1. `repository.url` on the **version** document, canonicalized. The packument root drifts from it.
2. **`_npmUser` + npm provenance attestation** where present: gives repo, commit, and workflow
   directly. Free and authoritative; always try this first when it exists.
3. `gitHead`, where npm records the publish-time git HEAD in the version document. This is the most
   useful npm-specific field, and it holds up even when the tags are a mess.
4. Tag ladder: exact, `v`-prefixed, fuzzy version-in-tag.
5. **Manifest history**: walk commits touching `package.json`, take the first commit where the
   version differs from all parents.
6. Tree-hash scoring against the published tarball (see [`07-ai.md`](07-ai.md) §2).

Monorepo subdirectory detection tries `package.json`, then `packages/{name}/package.json`, then a
grep for `"name": "{pkg}"` across `*/package.json`. We **validate** every candidate by re-reading
`package.json` at that commit and checking name and version. A candidate matching the name but not
the version still works, paired with an `npm version --no-git-tag-version` step.

### Toolchain evidence
`_npmVersion` and `_nodeVersion` in the version document are `Claim::ToolchainExact` with `Strong`
confidence. Known-bad npm versions are remapped (`< 5` → 5.0.4; 5.4 and 5.5 → 5.6.0 for Node 9
compatibility). Node version selection prefers musl builds because our base image is Alpine.

### Build
Two flow templates:
- **`npm/pack`**, for packages with no `prepare`, `prepack` or `build` script in `package.json`.
  It runs `npm pack` and nothing else, and it covers most of npm.
- **`npm/custom`**, which installs Node and npm at pinned versions, runs `npm install` against the
  time-filtered registry, runs the lifecycle script, drops `node_modules` where the script needs it,
  then runs `npm pack`.

### Output and stabilizer profile
`{name}-{version}.tgz`, tar+gzip. Profile: tar set + gzip set + `npm-tarball`, which normalizes the
`package/` prefix and drops `_resolved` / `_integrity` / `_from` fields injected by the installing
client.

### Nondeterminism
Mostly **dependency drift**. A floating `^` or `~` range resolves to different versions today than
it did at publish time, so npm needs the time-filtered registry
([`08-execution.md`](08-execution.md) §4). After that come lifecycle scripts that embed a build
timestamp or a git SHA.

### Expected outcome
`Exact` or `Normalized` for most of npm once we pin the dependency state. When an npm package
diverges the cause sits in the source rather than the build, which is the signal npm users need.

---

## 2. PyPI

### Resolution
`GET https://pypi.org/pypi/{name}/{version}/json` → `urls[]`. `packagetype` is `sdist` or
`bdist_wheel`. `digests.sha256` gives the expected digest. PEP 740 attestations, when present, are
fetched from the Integrity API.

### Source discovery
1. **PEP 740 attestation** → repo, workflow, commit. Authoritative when present.
2. `info.project_urls`, keys normalized to lowercase-without-spaces, in preference order:
   `source`, `sourcecode`, `repository`, `project`, `github`.
3. `info.home_page`, if it points at a known forge.
4. Repository URLs scraped from the long description.
5. Tag ladder, manifest history over `pyproject.toml` / `setup.py`, tree-hash scoring.

### Toolchain evidence, where npm has none and PyPI has plenty
Open the **upstream wheel** and read `*.dist-info/WHEEL` and `METADATA`:

- `Generator: bdist_wheel (0.37.1)` → `Claim::ToolchainExact { setuptools-ish backend }`, `Certain`.
- `Root-Is-Purelib`, `Tag:` lines → platform and ABI constraints.
- `Requires-Python` → interpreter range.
- `pyproject.toml`'s `[build-system] requires` → backend and its version constraints.

We then derive the interpreter version from the intersection. That evidence is stronger than any
other ecosystem offers, and it explains why PyPI has a high ceiling despite a low baseline.

### Build
- **`pypi/wheel`** runs `uv venv --seed --python {X}` (or `python3 -m venv` when the version is
  unpinned), installs `build` from the real index, points `PIP_INDEX_URL` at the time-filtered
  mirror, installs the pinned backend requirements, then runs `python -m build --wheel -n`. Output
  lands in `dist/`.
- **`pypi/sdist`** takes the same shape with `--sdist`.

We set `SOURCE_DATE_EPOCH` to the publish timestamp and set `umask 022`. Between them those two
lines account for most of PyPI's historical irreproducibility.

### Output and stabilizer profile
A `.whl` (zip) or a `.tar.gz` (sdist). The wheel profile is the zip set plus `wheel-record` at
**`StageFinalize`** plus `pyc-header`. `RECORD` regeneration runs last, because earlier stabilizers
change archive membership (any `exclude_path` in particular) and `RECORD` is a manifest of
membership.

`RECORD` regeneration recomputes each line as `path,sha256=<urlsafe-b64-unpadded>,<size>`, sorts
lexicographically, applies PEP 376 CSV quoting, and writes the `RECORD,,` self-line last.

### Nondeterminism
Timestamps account for 87.7% of historical failures. Then umask-dependent file modes, `.pyc` header
timestamps, `RECORD` ordering, and `direct_url.json`. Build backends differ sharply. `flit` and
`hatch` reproduce out of the box, `setuptools` needs help, and a bespoke `setup.py` puts a package in
the long tail.

### Expected outcome
`Normalized` for pure-Python wheels at a high rate. Platform-specific binary wheels built by
`cibuildwheel` across manylinux images form the hard tail. We rebuild the ones whose manylinux image
we can pin and run. The rest report `Unsupported { PlatformSpecificBinary }`, which states scope
rather than failure.

---

## 3. crates.io

The most sophisticated inference of the six, and the one with the best trick.

### Resolution
Metadata from `https://crates.io/api/v1/crates/{name}/{version}`; artifact from
`https://static.crates.io/crates/{name}/{version}/download`. The registry index is a git repository
(or the sparse HTTP protocol), which matters below.

### Source discovery
`.cargo_vcs_info.json` **inside the published `.crate`** carries `git.sha1`, the exact commit. No
other ecosystem hands us the source that directly, and no heuristic is involved. Failing that, use
`repository` in `Cargo.toml`, then the tag ladder, then `Cargo.toml` history, resolving
`version.workspace = true` inheritance through the workspace root.

### Toolchain evidence by manifest structural fingerprinting
Cargo **rewrites** `Cargo.toml` when it packages a crate, and the rewriting rules changed across
releases. The packaged manifest therefore leaks the packaging toolchain version far tighter than
release dates or the declared MSRV:

| Observation | Claim |
|---|---|
| `debug = true` appears denormalized (not `debug = 2`) | Cargo `< 1.71` |
| Arrays rendered multi-line ("pretty") | Cargo `>= 1.60` |
| Header comment mentions `to registry (e.g., crates.io) dependencies.` | Cargo `>= 1.55` |
| `doc-scrape-examples` key present | Cargo `>= 1.67` |
| `edition = "2021"` / `"2024"` | `>= 1.56` / `>= 1.85` |
| `resolver = "2"` | `>= 1.51` |
| `Cargo.lock` `version = 3` / `version = 4` | `>= 1.47` / `>= 1.78` |
| declared `rust-version` | `>= that` |
| publish time | baseline: the release current ~7 days earlier |

Each row is one `Evidence` with its own `source` string, and their intersection is a
`ToolchainResolution`. This needs **format-preserving TOML parsing** through `toml_edit`, because
plain `toml` discards the information the trick depends on.

We reject Rust versions with no musl build, since the base image is Alpine.

### Registry pinning by index commit
Cargo skips the time filter. We resolve a `crates.io-index` **git commit** that satisfies every
version in the target's `Cargo.lock`, then serve the registry from that commit, either as a local
registry replacement (`[source.crates-io] replace-with`) or over the sparse protocol for Rust 1.68
and later. A timestamp lacks the precision, so this is a correctness fix.

### Build
`cargo package --no-verify` (with `--exclude-lockfile` where supported), `CARGO_TARGET_DIR=$PWD/target`,
output in `target/package/{name}-{version}.crate`.

### Output and stabilizer profile
tar and gzip. The profile is the tar set plus the gzip set plus `cargo-vcs-hash`, which replaces
`git.sha1` in `.cargo_vcs_info.json` with a fixed placeholder. Drop that one stabilizer and no crate
rebuild ever compares, because the commit hash embeds the exact checkout.

### Nondeterminism
Build scripts (`build.rs`) and procedural macros execute arbitrary code at build time, and they are
the main gap. The `cc` crate brings back C-toolchain variability. Since RFC 3127, `trim-paths`
handles path remapping in release profiles.

### Expected outcome
`Normalized` at a high rate for pure-Rust crates. Crates whose build scripts embed environment data
form the tail.

---

## 4. RubyGems

The cheapest large win available, and nobody is doing it.

### Resolution
`https://rubygems.org/api/v1/versions/{name}.json` for the version list;
`https://rubygems.org/downloads/{name}-{version}.gem` for the artifact. `sha` in the version entry
gives the expected digest.

### Source discovery
The gemspec's `metadata` hash carries `source_code_uri`, `homepage_uri`, `bug_tracker_uri`,
`changelog_uri`. RubyGems trusted publishing (since Dec 2023) provides repo and workflow where used.
Then the tag ladder and `*.gemspec` history.

The prior art ships a gem build script and no source discovery for gems, so this chapter is
greenfield rather than a port.

### Toolchain evidence
The gem's `metadata.gz` carries a serialized `Gem::Specification` including `rubygems_version`,
which gives a `Claim::ToolchainExact` at `Certain` confidence. `required_ruby_version` gives an
interpreter range. `SOURCE_DATE_EPOCH` behaviour depends on the version: RubyGems **3.6.7 and later**
defaults it to `315619200` (1980-01-01) and sorts gemspec metadata fields, and earlier versions do
neither. That one change explains the jump from 0% to 99.9%.

### Build
`gem build {name}.gemspec --output /out/{artifact}`, with the Ruby version pinned from the evidence
and `SOURCE_DATE_EPOCH` set to match what the publishing RubyGems version would have used. Bundler is
used only when a `Gemfile.lock` is present and the gemspec depends on it.

### Output and stabilizer profile
A `.gem` is a **tar containing three gzipped members**: `data.tar.gz`, `metadata.gz`, and
`checksums.yaml.gz`. The stabilizer profile therefore exercises the nested-archive machinery harder
than any other ecosystem:

- outer tar set + gzip set,
- **recursion into `data.tar.gz`**, which lives in the archive model as structure rather than as a
  stabilizer. See [`05`](05-archive-and-normalization.md), and note the prior art's swallowed-error
  bug here.
- `gem-metadata-yaml-normalize`, for canonical YAML key ordering in `metadata.gz`,
- `gem-metadata-date`, `gem-metadata-rubygems-version`, `gem-metadata-cert-chain`,
- `gem-exclude-checksums` and `gem-exclude-signatures`, both **`RiskTier::Structural`**. They remove
  archive members, and those members are a hash of, and a signature over, the content we are
  rebuilding. Neither can differ while the content matches, and neither is content a consumer reads,
  so they sit with entry ordering rather than capping the outcome. See
  [`05`](05-archive-and-normalization.md) §3 for the reasoning.

### Nondeterminism
Before 3.6.7, timestamps caused 97.1% of failures. Now the causes are native extensions compiled
against host system libraries, and gemspec fields computed at build time. Using `git ls-files` for
the file list is common, and it makes the manifest depend on working-tree state.

### Expected outcome
`Normalized` at a high rate for pure-Ruby gems built by RubyGems 3.6.7 and later. Older gems need
`SOURCE_DATE_EPOCH` emulation, and gems whose gemspec computes its file list with `git ls-files` land
at `NormalizedWithCaveats` or `Divergent` depending on how the working tree differed.

---

## 5. NuGet

NuGet has trusted publishing and almost no reproducibility infrastructure, so parts of this chapter
are design rather than port. That is why it goes last.

### Resolution
The v3 service index at `https://api.nuget.org/v3/index.json` → `PackageBaseAddress` →
`{id-lower}/{version-lower}/{id-lower}.{version-lower}.nupkg`. Also fetch `.nuspec` and, when
present, the `.snupkg` symbol package.

### Source discovery
Better than most, when the publisher did the right thing:

1. `.nuspec` `<repository type="git" url="…" commit="…"/>` gives **repo and commit directly**.
2. **SourceLink** data embedded in the PDB, in the package or in the `.snupkg`, maps every source
   file to a repository URL at a specific commit. No other ecosystem gives per-file source provenance
   this strong. Extract it even when (1) is present, because it also identifies the *subdirectory*
   and validates the commit.
3. NuGet trusted publishing metadata.
4. Tag ladder.

A repository that has been deleted, renamed without a redirect, or made private is common for older
packages, and it is a scope statement rather than a failure. Those targets report
`Unsupported { SourceUnavailable }` with the loss classified, and the UI shows them apart from
packages we tried and could not reproduce.

### Toolchain evidence
- `.nuspec` `<dependencies>` target frameworks → SDK range.
- The assembly's `TargetFrameworkAttribute` → framework version.
- **Deterministic-build markers.** `<Deterministic>true</Deterministic>` is the SDK default, and
  `ContinuousIntegrationBuild=true` normalizes stored file paths. The PDB's path strings show whether
  the publisher set the second one, which decides whether a byte-level match is available at all.
- Compiler version is recorded in the PDB.

### Build
`dotnet pack -c Release` with `ContinuousIntegrationBuild=true`,
`DeterministicSourcePaths=true`, `PathMap` set to match the observed paths, and
`SOURCE_DATE_EPOCH` honoured where the SDK supports it. Restore runs against the time-filtered
mirror.

### Output and stabilizer profile
A `.nupkg` is a zip, in the OPC packaging form. The profile is the zip set plus:
- `nupkg-opc-ordering`, for `_rels/.rels` and `[Content_Types].xml` element ordering,
- `nuspec-normalize`, for element ordering and whitespace in the `.nuspec`,
- `nupkg-exclude-signature`, which drops `.signature.p7s`. It is `RiskTier::Structural`, because the
  signature covers content we are rebuilding and cannot differ while that content matches.
- `pe-deterministic`, which zeroes the PE header timestamp (a content hash under deterministic
  builds) and normalizes the **MVID** in the assembly's module table,
- `pdb-normalize`, for embedded portable PDBs.

The PE and PDB stabilizers carry `RiskTier::Content`, because they rewrite bytes inside executable
images. A NuGet match that needs them reports `NormalizedWithCaveats`, and we leave it there.
Signature exclusion is `Structural` for the same reason it is on gems, so a deterministic build with
no PE rewriting can still reach a clean `Normalized`.

### Nondeterminism
Publishers who leave `ContinuousIntegrationBuild` unset, absolute source paths baked into PDBs,
MVIDs, signature files, and `dotnet pack` output that depends on the exact SDK patch version more
than most toolchains do.

### Expected outcome
Lower than the other five, and reported that way. The near-term win for NuGet is **source
attribution through SourceLink**, which works even where a byte-level rebuild does not.

---

## 6. GitHub projects

GitHub is not a package registry, so the shape differs. The artifact is a release asset or the
source archive, and the release workflow holds most of the build recipe.

### Resolution
`pkg:github/{owner}/{repo}@{ref}`. We enumerate artifacts from the GitHub Releases API and fetch
source archives at `/archive/refs/tags/{tag}.tar.gz`. **GitHub's generated source archives drift over
time**, since the compression parameters have changed, so we compare a source-archive target at the
tree level after container normalization rather than at the byte level, and record a note saying so.

### Source discovery
The repository *is* the source. Two things still need resolving: the **commit** behind the tag,
where annotated tags resolve through the tag object, and the subdirectory for a monorepo.

### Toolchain and build
Both come from the release workflow. See [`06-ci-awareness.md`](06-ci-awareness.md). CI parsing
does more work here than anywhere else: the strategy candidate is close to the extracted `CiRecipe`,
and a GitHub build-provenance attestation, where one exists, supplies repo, commit, workflow path and
runner.

### Output and stabilizer profile
Whatever the release publishes. Format sniffing selects the profile: tar, zip, gzip, or `raw` for a
single binary. A raw binary leaves us with format-specific stabilizers only, meaning
`pe-deterministic` and ELF `build-id` normalization, both `RiskTier::Content`.

### Expected outcome
Variable. Release assets built inside a pinned container reproduce well. Assets built on
`macos-latest` or `windows-latest` runners sit beyond what we can host, and report
`Unsupported { PlatformSpecificBinary }`.

---

## 7. Adding a seventh ecosystem

The checklist, which doubles as the test of whether the seam holds:

1. Implement `EcosystemSpec` in `trigon-core`: identity, artifact kinds, archive format, and the
   stabilizer profile **id**. About 40 lines, no I/O.
2. Implement `Registry` in `trigon-registry`: resolve, fetch, enumerate, intrinsics. The ecosystem's
   knowledge lives here.
3. Add a stabilizer profile in `trigon-stabilize`, usually a composition of the tar, zip and gzip
   sets plus two or three format-specific stabilizers.
4. Add flow templates in the definitions repo under `_tools/{ecosystem}/`. **No Rust changes.**
5. Add a base image to `trigon-images`, pinned by digest.
6. Add a benchmark corpus and label it by required capability.
7. Add a chapter here.

Steps 1 through 3 are code. Steps 4 through 7 are data and content. A new ecosystem that requires
touching `trigon-engine` has found a bug in the architecture rather than an awkward ecosystem.
