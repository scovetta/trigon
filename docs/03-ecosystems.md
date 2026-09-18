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
| **crates.io** | Highly reproducible by design since `trim-paths` became the release default | Toolchain-window inference; build scripts and proc macros | **resolves, builds, compares** |
| **RubyGems** | 0% → 99.9% since 3.6.7 defaults `SOURCE_DATE_EPOCH` and sorts gemspec metadata. **No independent verification infrastructure exists anywhere.** | Native extensions | M5 |
| **NuGet** | Trusted publishing since Sept 2025; **almost no reproducibility infrastructure** | We are partly inventing this ecosystem's story | **resolves, builds, compares and attests at `mirror-only`** |
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
4. The **package-level** record, where the release's own names no forge. A release's metadata is a
   snapshot of what the project declared on the day it was published, and what projects declare
   improves over time: `pytz` 2026.1 names a `Download` link and a docs `Homepage`, and `pytz`
   today names `Source: https://github.com/stub42/pytz`. We verify old versions, so we keep meeting
   the record that says least. Recorded under its own evidence source, because it is a guess about
   continuity rather than a contemporary statement.
5. Repository URLs scraped from the long description.
6. Tag ladder, manifest history over `pyproject.toml` / `setup.py`, tree-hash scoring.

**Every one of these is a URL a human typed**, and a large minority of them point at a *view* of a
repository rather than at the repository: `…/python-engineio/issues`, `…/msal/releases`,
`…/lark/tarball/master`. Trimming a view off the end is not cosmetic — on a 50-target sample it
was the difference between ten targets resolving and ten reporting `no-strategy`.

The same URLs are also the only place PyPI can say what npm says in `repository.directory`. A
`…/google-cloud-python/tree/main/packages/google-auth` link carries the subdirectory in passing,
and reading the repository out of it while discarding the path is how a monorepo member comes to
build at the wrong root. `blob/` links are excluded: they name a file, not a directory.

**And where nothing declares a subdirectory, the repository is asked.** A project that simply is
not at the root of its repository — `stub42/pytz` keeps its `setup.py` under `src/` — has no field
anywhere to say so. One directory at depth 1 holding a `pyproject.toml` or `setup.py` is the
answer; several, and the package name decides; neither, and we build at the root and fail with a
message that names the problem, which beats building in the wrong sibling and reporting a
divergence that says nothing about the package.

### The tag ladder
An exact tag, then `v`-prefixed, then the same two with a calendar version zero-padded back
(PEP 440 normalizes the zero out of `2026.07.22`), then a tag whose *prefix* strips to leave the
version exactly: `python-ecdsa-0.19.2`, `RELEASE_3.2.9`, `azure-storage-blob_12.28.0`. Prefix
only — stripping a suffix too would make `1.2.3-rc1` match `1.2.3`, a different release. Where
several tags match, the package name breaks the tie and nothing else does; where it does not, the
rung yields no commit, because a wrong commit is worse than none.

All of it is answered from one `git ls-remote`, so the whole ladder costs one request.

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

> **Built, and reproducing at the enforced tier.** `pkg:cargo/serde@1.0.219` resolves, reads its
> commit out of `.cargo_vcs_info.json` as `PublishedProvenance`, installs a pinned toolchain,
> packages the workspace member and compares **`exact` at `--egress mirror-only`** — including
> `Cargo.lock`, which was the one file of twenty-eight that used to differ. `hashbrown@0.17.1` does
> the same across 50 members.
>
> The lockfile stopped differing because the mirror now serves the crates.io sparse index filtered
> to the publish instant, so `cargo package` resolves the graph the publisher resolved rather than
> today's. [`17-backlog.md`](17-backlog.md) B19 has what that closed and the one thing it did not;
> B20 is the toolchain window, and the trick below is B20 and is not implemented.

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

### Registry pinning by publication time
**Planned as an index commit, built as a time filter, because the index started carrying the
timestamp.** The argument for a commit was that resolution is a function of a git commit and
commits are not evenly spaced in time, so an hour could not name one. The sparse index now carries
a `pubtime` on every line — present on all 56 versions of `hashbrown` and all 316 of `serde`, back
to 2014, in the RFC 3339 UTC form the mirror already compares lexically — so the instant is a
property of the document and the npm and PyPI shape applies after all.

The mirror serves the index at `/-cargo/{moment}/`, dropping every line published after the moment,
and rewrites `config.json`'s `dl` to its own artifact route. Cargo is pointed at it with
`[source.crates-io] replace-with`, which is source *replacement* rather than a second registry on
purpose: the lockfile then records `registry+https://github.com/rust-lang/crates.io-index` exactly
as the publisher's did, and the lockfile ships inside the `.crate`.

**Yank state is the one field with no history, and the mirror clears it.** A line's `yanked` flag
is its state today; crates.io timestamps a yank nowhere, neither in the index nor in the API. Both
available answers are therefore wrong somewhere, and keeping today's flag is the worse one:
`bitflags@2.6.0` resolved `bytemuck` 1.14.0 instead of the 1.16.1 in its published lockfile, purely
because 1.15.x and 1.16.x have been yanked since. The flag is cleared on every surviving line and
the run says so in its assumptions. The residual error — a version already yanked at the pin being
offered as live — is rarer, because Cargo takes the newest satisfying version and a long-yanked one
is normally superseded by one it would pick anyway.

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

### 5.0 What is built, and what a `.nupkg` actually differs by

Measured rather than reasoned about: two `dotnet pack` runs over identical source, and
`newtonsoft.json.11.0.1.nupkg` as the gallery serves it.

**The good news is the payload.** The compiled assembly was byte-identical across two packs minutes
apart. Roslyn's deterministic compilation is on by default for SDK-style projects, so the part of
this ecosystem that looked hardest is already solved upstream. What is left is packaging
bookkeeping, and the `nupkg` stabilizer profile is exactly that list:

| Pass | Risk | What it is for |
|---|---|---|
| `nupkg-signature` | structural | `.signature.p7s`, which nuget.org attaches *after* the author packs. Present on every published package and on nothing anyone builds. |
| `nupkg-packaging-names` | structural | The core-properties part is named after a **fresh GUID every pack**, and `_rels/.rels` carries that name as a `Target` — plus relationship `Id` attributes that are themselves random and differ in case between NuGet 4.5 and 7.0. |
| `nupkg-packager-version` | metadata | `<lastModifiedBy>`, which for Newtonsoft.Json 11.0.1 reads `NuGet.Build.Tasks.Pack, Version=4.5.0.4, …;Microsoft Windows NT 10.0.16299.0`. It names a Windows machine in 2018. |

With those, two independent packs of one source reconcile to `normalized` with every member
identical.

### 5.0.1 The mirror serves a V3 feed

`dotnet pack` cannot run without `dotnet restore`, so unlike crates.io — where
`cargo package --no-verify` resolves nothing — NuGet has no way to sidestep the index. The mirror
serves one at `/-nuget/<moment>/`: a service index, a registration filtered by `published`, and a
flat container whose version list is **derived** from that filtered registration rather than
proxied, because upstream's own version list carries no dates and so cannot be filtered at all.

Four things this cost that were not obvious from the specification:

- **Registration pages may be remote.** A page either carries its leaves inline or an `@id` to
  fetch them from, and which one depends on how many versions a package has. `newtonsoft.json` is
  wholly inline; `system.text.json` has three pages and *none* of them are. A filter reading only
  what arrived inline is correct on the first and silently passes everything on the second.
- **`1900-01-01` means unlisted, not published in 1900.** Filtering Newtonsoft.Json to mid-2018
  removed every listed release after the moment and left `13.0.4-beta1` standing, because delisted
  packages carry that sentinel and it precedes every moment there is.
- **`--source` does not override `packageSourceMapping`.** A repository that configures one — Polly
  does — answers `NU1100 … the following source(s) were not considered` and never contacts the
  mirror. The restore tool writes a `NuGet.config` with `<clear />` in every section and passes
  `--configfile`.
- **NuGet 6.11 refuses plain HTTP sources** rather than warning as older versions did, with
  `NU1301` and nothing reaching the mirror at all. The generated config sets
  `allowInsecureConnections="true"`, which is right here: the mirror is the only host inside the
  build's network island.

**The toolchain's own packages are exempt from the date filter**, by the same reasoning as the
`-toolchain` route. SDK 8.0.423 demands `Microsoft.NETCore.App.Ref 6.0.36`, a targeting pack
released a year after Polly 8.2.0 was published; that version is a function of the SDK in the image,
not of anything the project asked for, so dating it asks the wrong question and leaves a constraint
nothing can satisfy. The exemption is a short list of Microsoft-owned id prefixes and is tested for
not leaking to ordinary packages.

Measured on `Polly@8.2.0` at `--egress mirror-only`: 28 index requests, **441 versions withheld**,
`attestable: true`, and a signed divergence statement.

### 5.0.2 What a NuGet divergence is actually made of

Dissected on `Newtonsoft.Json@11.0.1`, which rebuilds all nine of its frameworks and still compares
`divergent`. Of twenty-three members, **thirteen are normalization and ten are not**, and the ten
split into two very different things.

**Line endings are the biggest single lever in this ecosystem.** NuGet writes a package's text
members with the line endings of the machine that packed it, so a package published from Windows —
which is most of them, historically — differs from any Linux rebuild in its `.nuspec`, `.rels`,
`.psmdcp`, `[Content_Types].xml`, `.md` and every generated `.xml` doc. `nupkg-text-eol` is
`Content` risk and the cap is meant to bite: a package that matches only after its line endings are
rewritten has not been reproduced byte for byte, and `NormalizedWithCaveats` is the honest ceiling.

`nupkg-doc-member-order` is the other: Roslyn emits `<member>` elements in the host's collation
order, and Windows and ICU disagree about where `.` sorts. One block moves, in four of the nine doc
files, with no content difference.

**The nine assemblies are a six-year compiler gap, and that is not normalization's business.** The
publisher built with .NET SDK 2.1.4xx / Roslyn 2.6; a current image carries SDK 8.0 / Roslyn 4.11,
and the project sets `<LangVersion>latest</LangVersion>`. Measured across 33,367 matched method
pairs: 92% are identical modulo metadata-token renumbering and 7.7% are genuinely different
lowering — Roslyn rewrote the async state machines. Two compiler-injected types shift every token in
the file, so the longest identical aligned run in a 658 KB assembly is 136 bytes. This is the
toolchain question of §5.1 in its most concrete form, and nothing but the original SDK closes it.

**And one ceiling that no toolchain reaches: the published assemblies are strong-name signed** with
a key that is not in the repository. `build.ps1` runs with `$signAssemblies=$true` against
`newtonsoft.snk`, which also defines a `SIGNED` constant that changes the `InternalsVisibleTo`
attributes the source compiles. Newtonsoft.Json 11.0.1 therefore **cannot** be byte-reproduced by
anyone without the publisher's private key, at any SDK version. That is a fact about the package
rather than about Trigon, and it is the kind of fact a rebuilder exists to establish.

The nuspec's four remaining differences are the packer's vintage — NuGet 4.5.0.4 emitted `<owners>`
and `<requireLicenseAcceptance>false>` where 6.11 omits both, wrote `.NETPortable0.0-Profile259`
where 6.11 writes `.NETPortable4.5-`, and our package carries a `repository commit=` the published
one lacks. **Deliberately not normalized.** Those are elements a consumer can observe, and the last
is more provenance than the original had; a pass that erased them would be the tool deciding that a
manifest difference does not count.

### 5.1 The toolchain, which is the open question

**NuGet publishes no compiler version.** The only toolchain evidence in a package is the packer
named above, and the packer is not the compiler. So unlike crates.io — where the `Cargo.toml`
rewrite inside a `.crate` is a fingerprint of the Cargo that made it — there is nothing here to
infer from, and a build uses whatever SDK the base image carries.

That is stated in the run's assumptions, because it changes how a verdict should be read: Roslyn is
deterministic *given a version*, so a matching SDK reproduces the assembly exactly and a different
one diverges throughout. A `divergent` NuGet verdict is as likely to be the toolchain as the source
until that is pinned.

Measured on `Polly@8.2.0` against SDK 8.0.423: the assemblies are **97% byte-identical** and differ
in length — consistent with a near-miss on compiler version rather than with different code.

### 5.2 Two strata, and only one of them is tractable

- **Plain `dotnet pack` from an SDK-style project** builds and compares. The project is located by
  reading `<PackageId>` out of the `.csproj` files, falling back to a directory named for the
  package — in that order, because `Humanizer.Core` really is built from `src/Humanizer/` and only
  the project file says so.
- **Hand-written `.nuspec` packed by a build script** does not. Humanizer keeps 40-odd
  `NuSpecs/*.nuspec` and packs them from a Cake script; nothing `dotnet pack` does reproduces that.

**An earlier draft of this section said .NET Framework and PCL targets "need reference assemblies
that do not exist on Linux". That was wrong, and measurably so.** Newtonsoft.Json 11.0.1 targets
nine frameworks — `net20`, `net35`, `net40`, `net45`, three `netstandard`s and two `portable-*`
profiles — and all nine build and pack on Linux under `dotnet pack`:

- **`net20` through `net48` need nothing at all.** The SDK adds
  `Microsoft.NETFramework.ReferenceAssemblies` implicitly, so those targets build out of the box.
- **The `MSB4057` failure that looked like "PCL is unsupported" was a different thing entirely.**
  The project overrides `<LanguageTargets>` to `Microsoft.Portable.CSharp.targets`, a file the SDK
  does not ship on Linux. That import fails quietly, the inner project never imports
  `NuGet.targets`, and the outer restore's call into `_GetRestoreSettingsPerFramework` lands on a
  project with no such target. MSBuild reports it against a PCL framework, which is a bystander.
  `nuget/restore` now passes `-p:LanguageTargets=<sdk>/Microsoft.CSharp.targets` — the SDK's own
  default for C#, so a no-op for any project that does not override it — and restore succeeds for
  all nine.
- **PCL profiles need reference assemblies that no NuGet package ships**, which is the one true part
  of the old claim. They are about a megabyte, in Mono's `referenceassemblies-pcl`, and
  `trigon base-image --pcl-reference-assemblies` vendors them. `nuget/build/pack` then writes a
  `Directory.Build.props` wiring them up for `portable-*` targets only — never unconditionally,
  because `net20`-`net48` get theirs through the same property and an unguarded override breaks
  the four targets that work for free.

Two spellings of one framework had to be reconciled before the comparison meant anything. The 2018
client wrote `lib/portable-net45%2Bwin8%2Bwp8%2Bwpa81`; a modern one writes
`lib/portable45-net45+win8+wp8+wpa81`. Same profile, same component order, different convention —
so `nupkg-portable-folder-name` normalizes it, and without that a rebuild that reproduced both PCL
assemblies exactly reported four members only in upstream and four only in the rebuild.

### 5.3 What a Polly rebuild found

Worth recording because it is the kind of thing this tool exists to surface rather than a defect in
it: `Polly.nuspec` differs by exactly one line, `<copyright>Copyright (c) 2023` against
`(c) 2026`. Polly computes its copyright year from the build clock. That is a package-side
reproducibility defect, and `--timewarp` is the answer to it — once [B23](17-backlog.md) lets a
NuGet build run with a mirror in front of it at all.


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

### 7.1 The checklist as designed

1. Implement `EcosystemSpec` in `trigon-core`: identity, artifact kinds, archive format, and the
   stabilizer profile **id**. About 40 lines, no I/O.
2. Implement `Registry` in `trigon-registry`: resolve, fetch, enumerate, intrinsics. The ecosystem's
   knowledge lives here.
3. Add a stabilizer profile in `trigon-stabilize`, usually a composition of the tar, zip and gzip
   sets plus two or three format-specific stabilizers.
4. Add flow templates under `_tools/{ecosystem}/`. **No Rust changes.**
5. Add a base image, pinned by digest.
6. Add a benchmark corpus and label it by required capability.
7. Add a chapter here.

Steps 1 through 3 are code. Steps 4 through 7 are data and content. A new ecosystem that requires
touching the engine has found a bug in the architecture rather than an awkward ecosystem.

### 7.2 The checklist as built

The list above was written before any of it existed, and a census of the code against it
(`docs/16-findings.md` §3.18) found **three of its seven steps name things that were never
written**. Recorded here rather than quietly corrected, because a checklist that sends a reader
looking for a type that does not exist is worse than no checklist.

- **`EcosystemSpec` does not exist.** No trait, no impl, nothing. It is cited as live in
  `trigon-core/src/format.rs:8`, `trigon-stabilize/src/profiles.rs:3` and in
  [`01-architecture.md`](01-architecture.md), which prints a full `pub trait` block for it. The real
  selector is `resolve_profile` in `crates/trigon/src/main.rs` — a filename-extension chain in the
  CLI binary, not a trait in core. The *dependency severance* those comments describe is real; the
  mechanism named for it is not.
- **There is no `trigon-images` crate and no `trigon-engine` crate.** Base images come from
  `trigon base-image`; the engine is the `rebuild` module of the binary.
- **"No Rust changes" for step 4 is false.** `BUILTIN_TOOLS` in `trigon-strategy/src/tool.rs` is a
  compiled-in `include_str!` array, and `ToolRegistry::add` — the public method whose doc comment
  describes a definitions repo overriding a builtin — has no callers anywhere. A YAML file dropped
  into `tools/` is invisible until that array is edited. A source-text seam test does at least make
  the omission fail rather than ship.

What adding crates.io actually costs, counted: **14 work items, 10 touching engine files, 8 of them
genuine edits** once the two pure allowlist additions are subtracted. The seam is narrow rather than
broken — every one of those edits is additive and most are three lines — but it is not the "one
`Registry` impl plus some YAML" the roadmap claims.

### 7.3 Where the seam holds, and where it leaks

**It holds completely in the judgement half.** For crates.io the stabilizer and archive diff is
*empty*: `.crate` sniffs to `tar+gzip`, the filename selects the `crate` profile, `cargo-vcs-hash`
is implemented and tested, and nineteen `pkg:cargo/` targets already run through the golden
differential corpus. Nothing below the judgement line needs touching to add crates.io — which is
the half that was hardest to get right and the half a wrong answer would be most expensive in.

**It leaks in the acquisition half**, and one of those leaks was silent. `ladder()` matched `Npm`,
`PyPI` and `_ => {}`, so an ecosystem with no rung produced a `no-strategy` verdict indistinguishable
from a package whose recipe genuinely could not be inferred — a statement about Trigon rendered as a
statement about the package. `for_ecosystem` gets the same situation right: it refuses by name and
lists what it serves. The ladder now says so too.

**The compiler is a real seam guard in exactly one subsystem.** Every `match Platform` in the mirror
is exhaustive, so adding a platform cannot compile until its upstream URL, display name and request
handler are all written. `Ecosystem` gets the weakest treatment of the three: `purl_type` is
exhaustive, but the decisions that gate whether a rebuild happens at all used catch-alls.
