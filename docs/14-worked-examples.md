# 14. Worked examples

Four targets traced end to end, to check that no stage of the design gets hand-waved. Each example
names a strategy source, a stabilizer profile, and an expected outcome. Where a step stays uncertain,
the text says so rather than smoothing it over.

---

## 1. `pkg:npm/left-pad@1.3.0`, the trivial case

| Phase | What happens |
|---|---|
| **Resolve** | `GET registry.npmjs.org/left-pad` → version doc. Artifact `left-pad-1.3.0.tgz`, `dist.integrity` gives the expected digest. `publish_time = 2018-11-22T17:00:04Z`. |
| **Intrinsics** | `_npmVersion: 6.4.1` → `Claim::ToolchainExact{npm, 6.4.1}`, `Strong`. `_nodeVersion: 8.12.0` → same for node. No published provenance (predates it). |
| **LocateSource** | Rung 1: `repository.url` on the version document → `github.com/stringandstring/left-pad`. Rung 3: `gitHead` present → commit directly. Validated by reading `package.json` at that commit: name and version both match. `SourceDiscovery::RegistryMetadata`. **No model call.** |
| **InferStrategy** | Ladder rung 1 (cached strategy for `left-pad`, any version) on a warm system. Cold: rung 4, heuristic. `package.json` has no `prepare`, `prepack` or `build` script → flow template **`npm/pack`**. `Derivation::Heuristic`. **No model call.** |
| **Materialize** | Narrow fetch (`--filter=blob:none --single-branch`) at the pinned commit into the source cache. |
| **Build** | Base image `trigon/base-node@sha256:…` with node 8.12.0 and npm 6.4.1. Egress `MirrorOnly`; `RegistryMoment::Timestamp(2018-11-22T17:00:04Z)`. `npm pack`. Sub-10-second build. |
| **Extract** | `left-pad-1.3.0.tgz` at the workspace root. |
| **Stabilize** | Profile **`npm-tarball`**, chosen with `--profile npm-tarball`: the `.tgz` name alone selects `tar-gzip` ([`stabilizers.md`](stabilizers.md) §1.1). Tar set + gzip set + `npm-install-fields-v2`. All `Builtin`, all `risk <= Metadata`. |
| **Compare** | Raw digests differ (gzip framing). Stabilized digests equal. `container_bit_identical = false`. |
| **Verdict** | **`Reproduced { Normalized }`.** Provenance cap clean: all applied stabilizers `Builtin`, max risk `Metadata`. |
| **Attest** | `rebuild/v1` + SLSA provenance + `equivalence/v1` + `buildobservation/v1` (tier 1, artifact-hash check performed, not matched). |

**Cost:** one narrow clone, one sub-10-second build, no model calls. The economics in
[`07-ai.md`](07-ai.md) §4 depend on this shape being the common case.

---

## 2. `pkg:pypi/cryptography@42.0.5`, the hard case

A `cibuildwheel`-built binary wheel with a Rust extension. This example shows where the design says
**`Unsupported`** rather than pretending.

| Phase | What happens |
|---|---|
| **Resolve** | `GET pypi.org/pypi/cryptography/42.0.5/json` → many `urls[]` entries. **A target is one artifact**, so `cryptography-42.0.5-cp39-abi3-manylinux_2_28_x86_64.whl` and the sdist are separate targets with separate verdicts. |
| **Intrinsics** | PEP 740 attestation present → repo, workflow path, commit, publisher identity. Wheel `WHEEL` file: `Generator: bdist_wheel (0.42.0)`; `Tag: cp39-abi3-manylinux_2_28_x86_64`; `Requires-Python: >=3.7`. `pyproject.toml` `[build-system] requires = ["maturin>=1,<2"]` → `Claim::BuildBackend(maturin)`. |
| **LocateSource** | Rung 2: the PEP 740 attestation gives repo **and** commit. `SourceDiscovery::PublishedProvenance`. **No model call.** |
| **InferStrategy** | Rung 3: **CI-derived**. `.github/workflows/wheel-builder.yml` is named directly by the attestation, so no job-selection heuristics needed. `pypa/cibuildwheel` is on the action allowlist → manylinux image, build selectors, `before-build` commands. Rust toolchain from `dtolnay/rust-toolchain`. |
| **Runner mapping** | The matrix cell for `manylinux_2_28_x86_64` maps to a digest-pinned manylinux image. **This is the pivot point.** If we can pin and run that exact image, proceed. If the workflow used `macos-14` for this artifact, the verdict is `Unsupported { PlatformSpecificBinary }` and no build runs. |
| **Build** | manylinux container, pinned Rust toolchain, `SOURCE_DATE_EPOCH` set, `umask 022`, egress `MirrorOnly` with `PIP_INDEX_URL` pointed at the time-filtered mirror. `python -m build --wheel -n`. Minutes, not seconds. |
| **Repair loop, if needed** | Likely failure: a Rust toolchain window that is wide or contradictory. `ToolchainResolution::Unconstrained` is the **typed** signal to escalate ([`02-domain-model.md`](02-domain-model.md) §2). Builder gets the compressed log, the evidence list, and the CI recipe; emits a patched strategy. Failure signature is normalized and cached, so the next Rust-extension wheel with the same signature costs nothing. |
| **Clean re-runs** | Two, on different workers. |
| **Stabilize** | Profile **`wheel`**: zip set + `wheel-direct-url` (`Lossy`) + `pyc-header-v2` (`Content`) + `wheel-metadata-eol` (`Content`) + **`wheel-record-v3` at `StageFinalize`**. `RECORD` regeneration must run last because `wheel-direct-url` changed membership. |
| **Compare** | The `.so` is the crux. If the Rust toolchain, LLVM version and linker flags all matched, the `.so` is byte-identical after normalization and the outcome is `NormalizedWithCaveats` when a `Content` or `Lossy` pass changed something, as `wheel-record-v3` does whenever the published `RECORD` is not already in its form, and `Normalized` when none did ([`stabilizers.md`](stabilizers.md) §1.4). If the `.so` differs, the note reads `ExecutableContentDiffers`, which is **never benign**, and the outcome is `Divergent`. |
| **Verdict** | **`Reproduced { NormalizedWithCaveats }`** on a good day; **`Divergent`** with an executable-content note otherwise; **`Unsupported`** if the platform could not be hosted. |

**What this example shows:** `Unsupported` is a first-class outcome that states scope. The
toolchain-evidence intersection produces a *typed* escalation signal rather than a heuristic one. And
`StageFinalize` exists for a concrete reason.

---

## 3. `pkg:gem/rails@7.1.3`, nested archives and an epoch

RubyGems exercises the nested-archive machinery harder than anything else, and no independent
verification infrastructure exists for it today.

| Phase | What happens |
|---|---|
| **Resolve** | `api.rubygems.org/api/v1/versions/rails.json`; artifact `rails-7.1.3.gem`; `sha` gives the expected digest. |
| **Intrinsics** | Parse `metadata.gz` from the published gem: `rubygems_version: 3.5.6` → `Claim::ToolchainExact`, `Certain`. `required_ruby_version: >= 2.7.0`. Because 3.5.6 is **below 3.6.7**, the automatic `SOURCE_DATE_EPOCH` default and gemspec metadata sorting were **not** in effect, so we emulate the older behaviour. |
| **LocateSource** | gemspec `metadata.source_code_uri` → `github.com/rails/rails`. `rails` is a monorepo, so subdirectory detection matters: the `rails` gem is the root gemspec, but `activesupport` and friends are subdirectories. Tag ladder: `v7.1.3` exact. |
| **InferStrategy** | Rung 4, heuristic: a `.gemspec` at the resolved subdirectory → flow template **`gem/build`**, with Ruby pinned from `required_ruby_version` intersected with the release current at publish time. |
| **Build** | `gem build rails.gemspec --output /out/rails-7.1.3.gem`, `SOURCE_DATE_EPOCH` set to the publish timestamp (not 315619200, because the publishing RubyGems predates that default). |
| **Likely failure** | The gemspec's file list is commonly computed with `git ls-files`, which makes the manifest depend on working-tree state. A dirty or differently-pruned checkout produces a different member list. This is a known failure class with a cached repair. |
| **Stabilize** | Profile **`gem`**. Outer tar set + gzip set; **structural recursion** into `data.tar.gz` and `metadata.gz` (a `Body::Nested` rather than a stabilizer, see [ADR-0004](adr/0004-own-the-archive-writers.md)); `gem-metadata-date-v2` and `gem-metadata-rubygems-version-v2` (`Metadata`), `gem-metadata-cert-chain-v2` (`Structural`), `gem-exclude-checksums` (`Structural`), `gem-exclude-signatures` (`Structural`). |
| **Compare** | Every applied stabilizer is `Builtin` at `Structural` or `Metadata` risk, so the provenance cap stays quiet. Checksum and signature exclusion sit at `Structural` because both are integrity metadata over content we are rebuilding ([`05`](05-archive-and-normalization.md) §3). |
| **Verdict** | **`Reproduced { Normalized }`**, which matters: an earlier draft put checksum and signature exclusion at `Lossy` and thereby denied every gem a clean tier. The gemspec `git ls-files` failure class is what pushes a gem to caveats or divergence. |

**What this example shows:** risk tiers doing real work and, in the checksum case, needing a second
pass to get right. Recursion lives in the archive model as structure. And an entire ecosystem's
ceiling turns on where one stabilizer sits in a four-value enum.

---

## 4. `pkg:nuget/Newtonsoft.Json@13.0.3`, deterministic builds and a signed package

| Phase | What happens |
|---|---|
| **Resolve** | v3 service index → `PackageBaseAddress` → `newtonsoft.json.13.0.3.nupkg`. Fetch the `.nuspec` and the `.snupkg` if published. |
| **Intrinsics** | `.nuspec` `<repository type="git" url="…" commit="…"/>` → **repo and commit directly**. SourceLink data in the PDB maps every source file to a repository URL at a commit, which also identifies the subdirectory and cross-validates the commit. PDB path strings reveal whether `ContinuousIntegrationBuild` was set: if absolute developer paths appear, a byte-level match is **not achievable** and we should say so before building. Compiler version from the PDB. |
| **LocateSource** | Rung 1, from the `.nuspec`. `SourceDiscovery::RegistryMetadata`, cross-checked against SourceLink. **No model call.** |
| **InferStrategy** | Rung 3 or 4: `dotnet pack -c Release` with `ContinuousIntegrationBuild=true`, `DeterministicSourcePaths=true`, and `PathMap` set to match the paths observed in the PDB. SDK version from the evidence intersection. Restore against the time-filtered mirror. |
| **Build** | .NET SDK container pinned by digest. `MirrorOnly` egress. |
| **Stabilize** | Profile **`nupkg`**: zip set + `nupkg-opc-ordering` (`Structural`) + `nuspec-normalize` (`Metadata`) + `nupkg-exclude-signature` (**`Structural`**, because the signature covers content we are rebuilding and cannot differ while that content matches) + `pe-deterministic` (**`Content`**, zeroing the PE header timestamp, which under deterministic builds is a content hash rather than a time, and normalizing the assembly MVID) + `pdb-normalize` (`Content`). |
| **Compare** | Under a deterministic build with matching SDK and `PathMap`, the IL matches and the remaining differences are the MVID and the signature, both handled. |
| **Verdict** | **`Reproduced { NormalizedWithCaveats }`**, because `pe-deterministic` is `Content`. Signature exclusion no longer costs anything, so the caveat rests on the one thing that earns it: we rewrote bytes inside an executable image to reach the comparison. |
| **If `ContinuousIntegrationBuild` was never set** | Absolute source paths are baked into the PDB and cannot be reproduced. The verdict is `Divergent` with a `pdb-paths` rule id, and **that is a useful finding**, because it tells the publisher what to change. |

**What this example shows:** SourceLink gives NuGet strong source provenance even where a
byte-level rebuild is out of reach. `Content`-tier stabilizers on executable images cap the outcome
where it belongs. And a divergence can carry actionable advice rather than an accusation.

---

## 5. What these examples check

| Design claim | Checked by |
|---|---|
| The extension seam holds, so a new ecosystem needs no engine change | All four run the same phases, differing in `Registry`, stabilizer profile, and flow templates |
| Toolchain evidence is a set of constraints, not a procedure | Example 2's `Unconstrained` escalation; example 3's version-dependent `SOURCE_DATE_EPOCH` |
| Risk tiers do real work | Examples 2, 3 and 4 all land at `NormalizedWithCaveats` for concrete, stated reasons |
| `Unsupported` is a scope statement | Example 2's macOS branch |
| Most targets never touch a model | Examples 1, 3 and 4 need zero model calls; example 2 needs one only on a genuine toolchain contradiction |
| `StageFinalize` is necessary | Example 2's `wheel-record-v3` after a membership change |
| Recursion is structural | Example 3's `data.tar.gz` |
| Divergences can be actionable | Example 4's `pdb-paths` finding |
