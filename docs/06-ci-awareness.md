# 06. CI/CD awareness

## 1. The best build instructions are already in the repo

A CI workflow built most packages published after roughly 2023, that workflow sits **in the
repository**, and a machine can read it. It names the toolchain, the build command, the environment
variables, the working directory, and the publish step. Nothing else available comes close as a
source of build instructions, and it costs one file read.

Reading it well moves targets from "needs a model" to "needs no model", which is where most of the
cost savings in [`10-scale.md`](10-scale.md) come from.

## 2. What we do not do

**We do not emulate GitHub Actions runners.** The `act`-style approach of pulling a runner image
and executing the workflow fails as a primary path, because runner images **mutate and resist
pinning**. `ubuntu-24.04` moves, and `ubuntu-latest` moves faster. Emulating them would leave *our
own* results irreproducible, which defeats the purpose.

We **extract intent and lower it to our own container plan**, pinned by digest. The attestation
records the mapping from `runs-on` to one of our base images as an **approximation**, labelled that
way, and never as an equality claim.

We also decline to execute an unknown action to find out what it does. We flag it instead.

## 3. Parsing: workflows to `CiRecipe`

```rust
pub struct CiRecipe {
    pub source: CiSource,                  // GitHubActions { path, sha } | GitLabCi { path }
    pub job: String,
    pub trigger: TriggerKind,
    pub publishes: Option<PublishStep>,
    pub runner: RunnerSpec,                // runs-on, container:, matrix cell
    pub toolchains: Vec<(ToolId, Version)>,
    pub env: BTreeMap<String, String>,
    pub working_directory: Option<Utf8PathBuf>,
    pub steps: Vec<CiStep>,
    pub unmodelled: Vec<UnmodelledStep>,   // honest record of what we could not interpret
}
```

### 3.1 Job selection

Candidate jobs are those that plausibly built the artifact:

1. **Trigger**: `release: published`, `push: tags/v*`, `workflow_dispatch`, `workflow_call`.
2. **A publish step**, the strongest signal, matched against a table:

| Ecosystem | Publish markers |
|---|---|
| npm | `npm publish`, `pnpm publish`, `yarn npm publish`, `JS-DevTools/npm-publish` |
| PyPI | `twine upload`, `pypa/gh-action-pypi-publish`, `uv publish` |
| crates.io | `cargo publish`, `katyo/publish-crates` |
| RubyGems | `gem push`, `rubygems/release-gem` |
| NuGet | `dotnet nuget push`, `nuget push` |
| GitHub | `softprops/action-gh-release`, `actions/upload-artifact`, `gh release upload` |

3. **Artifact-name correlation**, meaning a job that produces a file whose name matches the target
   artifact.
4. **Matrix expansion**, selecting the cell whose platform matches the target's platform tags. A
   wheel's `manylinux_2_28_x86_64` tag selects the matching matrix cell.

Where several jobs qualify we rank all of them. The top-ranked job becomes the strategy candidate and
the rest become `Evidence`.

### 3.2 Action expansion

We expand `uses:` steps for a curated **allowlist** only, because interpreting arbitrary JavaScript
actions is a project of its own:

| Action | Extracted |
|---|---|
| `actions/checkout` | `fetch-depth`, `submodules`, `ref` |
| `actions/setup-node` | Node version, registry URL, cache |
| `actions/setup-python` | Python version, architecture |
| `actions/setup-dotnet` | .NET SDK version |
| `ruby/setup-ruby` | Ruby version, bundler |
| `dtolnay/rust-toolchain`, `actions-rs/toolchain` | Rust channel/version, components, targets |
| `actions/setup-java` | JDK distribution and version |
| `actions/cache`, `Swatinem/rust-cache` | Ignored on purpose. Caching cannot change output. |
| `pypa/cibuildwheel` | manylinux image, build selectors, before-build commands |
| `docker/build-push-action` | Dockerfile path, build args |

Everything else gets **pinned by SHA, recorded, and reported as `UnmodelledStep`**. A strategy
derived from a recipe with unmodelled steps still works, carries lower confidence, and shows up in
the UI, because an unmodelled step is where the next inference failure comes from.

Whatever a step reads from `secrets.*` sits beyond our reach, and that tells us something: a build
that needs a secret cannot be reproduced, and it should reach `Unsupported` rather than burn repair
budget.

### 3.3 Runner mapping

```
ubuntu-24.04  → trigon/base-ubuntu-24.04@sha256:…    (approximation, labelled)
ubuntu-22.04  → trigon/base-ubuntu-22.04@sha256:…
ubuntu-latest → resolved to the label current at the target's publish time, then as above
container: X  → X, if it is digest-pinnable; otherwise resolved and pinned by us
macos-*       → Unsupported { PlatformSpecificBinary }
windows-*     → Unsupported { PlatformSpecificBinary }
self-hosted   → Unsupported
```

Resolving `ubuntu-latest` means checking the publish timestamp against GitHub's published label
history. That is a heuristic, and we record it as `Confidence::Weak`.

macOS and Windows report `Unsupported` rather than failing. Attempting them would produce a stream of
divergences that say nothing about the packages involved.

## 4. From `CiRecipe` to a strategy

The recipe produces **two** things:

1. A **strategy candidate**, the `CiDerived` rung of the ladder in
   [`04-strategies.md`](04-strategies.md) §6. Steps map to flow steps. A `uses:` maps to one of our
   tools where the semantics match, so `actions/setup-python` becomes `pypi/setup-venv`, and to
   `runs:` otherwise.
2. A set of **`Evidence`**: `Claim::ToolchainExact { python, 3.11 }` at `Confidence::Strong`,
   `Claim::PlatformIs(...)`, and `Claim::RequiresNetwork(true)` when a step fetches from a
   non-registry host. Evidence flows into the intersection described in
   [`02-domain-model.md`](02-domain-model.md) §2 even when we reject the strategy candidate.

The second output often beats the first. A workflow we cannot lower faithfully still tells us the
Python version, and that alone can turn a failing heuristic strategy into a passing one.

## 5. Ingesting published provenance

Where a registry or forge already publishes provenance, we consume it. One API call buys a lot.

| Source | What it gives |
|---|---|
| **npm provenance** (SLSA, Sigstore) | repo, commit, workflow path, runner environment |
| **PyPI PEP 740 attestations** (Integrity API) | Sigstore-signed in-toto statement; publisher identity, repo, workflow |
| **GitHub build provenance** (`actions/attest-build-provenance`) | subject digest, repo, commit, workflow, runner |
| **NuGet trusted publishing** | publisher identity and workflow |
| **`.nuspec` `<repository commit=…>`** and **SourceLink** | repo and commit, per file |

Three uses, in increasing order of interest:

1. **Source discovery.** A provenance statement hands us repo and commit, which is the most
   expensive thing the Resolver would otherwise have to derive. Nothing else cuts model invocation
   this much.
2. **Strategy seeding.** The workflow path in the provenance names the workflow to parse, so the
   job-selection heuristics sit idle.
3. **Cross-checking.** We verify the provenance signature ourselves, then compare its claims against
   what we found. **A rebuild that contradicts existing provenance is the highest-signal output this
   system produces**, and it gets its own alert class and its own view
   ([`11-interfaces.md`](11-interfaces.md) §4).

Provenance is an **input, never a conclusion**. It says where an artifact came from, and we say
what it is. A valid provenance statement attached to a backdoored artifact is the case this system
exists to catch, so the presence of provenance never short-circuits a verdict.

### 5.1 Trust handling for ingested provenance

An attacker can influence a provenance document the same way they influence registry metadata: a
compromised publishing workflow produces genuine signatures over false claims. So:

- We **verify** signatures, and a failed verification becomes a finding of its own.
- Claims extracted from provenance enter as `Evidence` carrying a `source` string, rather than as
  facts.
- Provenance-supplied text, meaning workflow paths and repository URLs, enters any model prompt as
  untrusted input. See [`12-security.md`](12-security.md) §4.

## 6. GitLab CI and others

`.gitlab-ci.yml` takes the same shape. Job selection uses `rules` and `only` plus publish-step
matching. `image:` maps to a base image, and it usually pins by digest already, which beats GitHub.
`before_script` and `script` map to steps, and `extends` and `include` resolve under a depth limit.

Azure Pipelines, CircleCI and Jenkins sit outside v1. The `CiParser` trait lets someone add them
without engine changes, and `CiRecipe` is shaped as a common denominator rather than a GitHub Actions
shape with other systems bolted on.
