# 04. Strategies

## 1. The seam

The single load-bearing abstraction, taken directly from the prior art:

```
Strategy  ──render(target, env)──▶  Instructions  ──lower──▶  BuildPlan  ──▶  Sandbox
 (data)                             (scripts)                 (container)
```

- A **strategy** is versioned, content-addressed, declarative data. Never code.
- Rendering is a **pure function** of `(strategy, target, environment)`.
- **Instructions** hold three shell scripts plus an output path and a requirements block.
- The executor consumes `Instructions` and **never re-renders**.

```rust
pub struct Instructions {
    pub location: SourceProvenance,
    pub source: Script,       // clone/checkout at a pinned commit
    pub deps: Script,         // toolchain + dependencies
    pub build: Script,        // produce the artifact
    pub output_path: Utf8PathBuf,
    pub requires: Requirements,   // { system_deps, privileged, egress, platform }
}
```

Pure, one-shot rendering is what makes a strategy attestable. The attestation records the
**rendered instructions**, so a verifier needs no template engine of ours, and old attestations need
no schema migration.

## 2. The strategy enum: four variants

```rust
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Strategy {
    LocationHint(LocationHint),
    Flow(FlowStrategy),
    Manual(ManualStrategy),
    Prebuilt(PrebuiltStrategy),
}
```

| Variant | Purpose | Trust |
|---|---|---|
| `LocationHint` | Repo and ref only. Seeds inference, and **cannot** render `Instructions`. | n/a |
| `Flow` | The normal case. Ordered steps over a named-tool registry. | full |
| `Manual` | Raw `deps` and `build` scripts. What a model emits. | **Lower tier, recorded as such in the attestation** |
| `Prebuilt` | The artifact is copied from a declared, pinned upstream build. | Requires a human approval record, see §7 |

### 2.1 Why the per-ecosystem variants are deleted

The prior art carries thirteen strategy variants, among them `pypi_pure_wheel_build`,
`npm_pack_build`, `cratesio_cargo_package`, `maven_build` and `gem_build`. Every one is a pre-canned
flow strategy wearing a type. In Trigon they become **named flow templates in the definitions repo**
under `_tools/{ecosystem}/` rather than Rust types.

Three consequences, all good:

1. **Adding an ecosystem takes YAML plus one `Registry` implementation**, with no change to the enum.
   That is what "easily extensible" has to mean in practice.
2. **The enum stays at four variants**, which keeps schema migration tractable.
3. **A model has one output shape to learn.**

### 2.2 Internally tagged, never `untagged`

The most consequential serde decision in the design, so here is the reasoning in full:

- `#[serde(untagged)]` produces "data did not match any variant of untagged enum Strategy", with no
  span, no field name, and no inner error. Models emit this format and humans hand-edit it, so that
  message disqualifies the option. **The build-repair loop can only be as good as this error.**
- `untagged` picks the wrong variant without complaint when two variants share a shape.
  `LocationHint` is a subset of `FlowStrategy` here, so that bug is live rather than theoretical.
- `untagged` fails to compose with `deny_unknown_fields`.
- `tag = "kind"` costs one line of YAML.

Internal tagging buffers through serde's private `Content` type, which breaks `flatten` with
non-self-describing formats and loses YAML span information. So deserialization runs **two passes**:

> **Revised in implementation.** Internal tagging and `serde_path_to_error` are incompatible: the
> tagged deserializer buffers through serde's `Content` and the path is lost. The parser reads
> `schema` and `kind` manually and then deserializes the payload directly, which keeps the path the
> repair loop depends on. See [`16-findings.md`](16-findings.md) §3.2.


```rust
let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(src)?;
let schema = doc.get("schema").and_then(Value::as_u64).unwrap_or(1);
let kind   = doc.get("kind").and_then(Value::as_str).ok_or(MissingKind)?;
let de     = serde_yaml_ng::Deserializer::from_str(src);
let s: Strategy = serde_path_to_error::deserialize(de)?;   // ← the good error message
```

That yields `flow.deps[2].with.pythonVersion: invalid type: integer, expected string`, which goes
**verbatim** into the repair prompt. Line for line, `serde_path_to_error` returns more than any other
dependency in the design.

`Step` uses `#[serde(try_from = "StepRaw")]` rather than `flatten`, which internal tagging rules
out:

```rust
pub struct Step { pub body: StepBody, pub needs: Vec<SystemDep> }
pub enum StepBody { Runs(Template), Uses { tool: ToolId, with: BTreeMap<String, String> } }

struct StepRaw { runs: Option<String>, uses: Option<ToolId>,
                 with: BTreeMap<String, String>, needs: Vec<SystemDep> }
```

`TryFrom` enforces exactly-one-of and yields "step 2 of `deps`: provide exactly one of `runs` or
`uses`", phrased in terms of the YAML a human wrote.

## 3. The flow DSL

```yaml
schema: 1
kind: flow
location:
  repo: https://github.com/psf/requests-toolbelt
  ref: da0306dcbb4e0e8dbe1ac6d1e0d8c4f6a1a3b2c1
src:
  - uses: git-checkout
  # The published wheel was built from a working tree that still contained
  # appengine.py, deleted two commits earlier. Restore it.
  - runs: git checkout '{{ location.ref }}^' -- requests_toolbelt/adapters/appengine.py
deps:
  - uses: pypi/setup-venv
    with: { python: "3.9", backend: "setuptools==62.6.0", wheel: "0.37.1" }
  - uses: pypi/setup-registry
    with: { moment: "{{ intrinsics.publish_time }}" }
build:
  - runs: python -m build --wheel -n
output_dir: dist
```

That example is real. It takes the shape of an override in the prior art's definitions directory,
and the six-line comment explaining *why* is the point. **That directory holds the institutional
memory of a project like this**, and it exists because strategies are data with a reviewable text
form. Trigon needs the same property.

### 3.1 Tools

A tool is a named, composable, parameterized fragment. Tools live in the definitions repo under
`_tools/`, load at startup, and hash into `strategy_digest`.

```yaml
# _tools/pypi/setup-venv.yaml
id: pypi/setup-venv
params:
  python:  { type: string, required: true }
  backend: { type: string, required: false }
  wheel:   { type: string, required: false }
needs: [ca-certificates]
steps:
  - runs: |
      uv venv --seed --python {{ with.python }} /venv
      . /venv/bin/activate
  - runs: pip install --no-index --find-links /wheels "{{ with.backend }}" "wheel=={{ with.wheel }}"
    if: "{{ with.backend }}"
```

Tools may reference other tools, forming a small composition graph that resolves at load time. A
cycle is a load error rather than a runtime hang, and an unknown `uses:` fails validation rather than
rendering to nothing.

### 3.2 Template rules

`minijinja`, with four settings that depart from the defaults. Each one blocks a class of silent
wrongness:

1. **`UndefinedBehavior::Strict`.** A typo'd `{{ targt.version }}` has to be a hard error. Go
   templates render `<no value>`, minijinja's default renders empty, and either produces
   `pip install ==` and a mystifying failure. This upgrade over the prior art costs one line.
2. **`BTreeMap` only in the context.** Go's `text/template` sorts map keys when ranging, and
   minijinja preserves insertion order, so a `HashMap` in the context makes rendering, and therefore
   `strategy_digest`, vary between runs. The dependency-policy test bans `HashMap` in
   `trigon-strategy`.
3. **A closed context type.** Strings, integers, booleans, lists, and maps. No floats, whose
   formatting varies, and no time values, since a template that can read a clock introduces
   nondeterminism.
4. **Render once, at strategy-resolution time.** We store the rendered script as a byproduct blob.
   That blob is what the executor runs and what the attestation records.

**Filters**, ported from the prior art: `to_json` and `from_json`, both BTreeMap-backed with
insertion-order preservation off; `indent`; `regex_replace` over the `regex` crate, where the prior
art's patterns transfer almost verbatim, though `$` and `\z` anchoring differ from RE2 and need
tests; and `cmp_version`, which **dispatches by ecosystem** rather than living as one function. See
[`02-domain-model.md`](02-domain-model.md) §6.

The full context:

```
location  { repo, ref, subdir }
target    { ecosystem, namespace, name, version, artifact }
env       { registry_moment, source_date_epoch, arch, platform, mirror_urls }
intrinsics{ publish_time, toolchains, backend, evidence_summary }
with      { …tool parameters… }
```

A template can reach nothing else. No filesystem access, no environment-variable lookup, no
clock.

## 4. Versioning and the digest

Every strategy document begins `schema: 1`. The prior art carries no version field, and we decline
to inherit that problem.

- Parse as `{ schema: u32, #[serde(flatten)] rest: Value }`, dispatch to `v1::Strategy`, then
  `From`-chain forward to the current version. **We keep every historical version's structs.**
- **`strategy_digest` covers an RFC 8785 (JCS) canonical serialization of the migrated-to-latest
  value rather than the YAML bytes.** Cover the bytes instead and editing a comment invalidates the
  cache for every target using that strategy, which at 100k targets is an expensive typo.
- Tool definitions hash into the digest, so changing a tool invalidates every strategy that uses
  it.

## 5. The definitions repository

A separate repository, `trigon-definitions`, sparse-cloned and **pinned to a resolved SHA at
startup**. That SHA goes into every attestation, so a verifier can see which overrides were in
effect.

```
_tools/{ecosystem}/{tool}.yaml
{ecosystem}/{package}/{version}/{artifact}/build.yaml
```

The paths match the asset store's layout. Namespaced packages encode their separator, giving
`npm/@polymer~app-route/…` and `nuget/Newtonsoft.Json/…`.

A definition may hold a **full strategy**, or a **`LocationHint`** that seeds inference rather than
replacing it. The hint is the common case, because most human intervention says "you found the wrong
repo" rather than "you built it wrong".

### 5.1 Governance

We take these rules wholesale from the prior art, because they separate a maintainable long tail
from an unfalsifiable pile of special cases:

- **A custom stabilizer requires a non-empty prose `reason:`**, validated at load time. It is a
  field, and its absence is a parse error, so nobody can leave it as a comment they meant to write.
- **Overrides carry the inferred-versus-corrected diff as a comment**, generated by
  `trigon strategy annotate-diff`, so a reviewer sees what inference got wrong. That artifact serves
  as review aid, eval corpus, and few-shot data at once ([`07-ai.md`](07-ai.md) §5).
- **Two-party review** for anything touching stabilizers, one reviewer for a `LocationHint`.
- **A definition is provenance.** The repo URL and resolved ref appear in the attestation, so a
  verifier can see that a human overrode inference and read why.

Here is the comment discipline these rules protect, from a real override in the prior art.
setuptools between 58.5.3 and 62.0.0 writes `PKG-INFO` with three trailing newlines, 62.6.0 strips to
one, and Python 3.9's email parser preserves them where 3.10 strips them. Both the setuptools pin and
the interpreter pin are needed, and the comment says so. No inference engine recovers that reasoning.
A human wrote it down once, and it stays.

### 5.2 Bounded custom stabilizers

Custom stabilizers are **declarative and bounded**. Two forms only:

```yaml
custom_stabilizers:
  - replace_pattern:
      paths: ["*/METADATA"]
      pattern: "\r\n"
      replace: "\n"
    reason: |
      Upstream wheel was built on Windows; setuptools wrote CRLF line endings
      into METADATA. Content is otherwise identical.
  - exclude_path:
      paths: ["*/direct_url.json"]
    reason: pip records the local build path; not part of the distributed content.
```

They may zero or rewrite a metadata field. They **may not** delete or rewrite executable content.
When a custom stabilizer alters more than a configured byte threshold, or touches a file classified
as executable, the run is flagged in the UI **and** in the attestation with the `NoteCode`
`CustomStabilizerTouchedExecutable`. Custom stabilizers carry `Provenance::Human { reviewer }`, so
they cap the outcome at `NormalizedWithCaveats`.

The threat is direct. A malicious pull request adding a stabilizer that normalizes away a
backdoored file would make a real mismatch vanish. The mandatory `reason:` is a social control, and
the bounds and the flag are the technical ones.

## 6. Strategy selection

The engine holds one ordered `Vec<Arc<dyn StrategyInferrer>>` and takes the first candidate that
validates. No branch anywhere in the engine asks whether a candidate came from a model. The ordering
*is* the policy, and the ordering is configuration:

| Rung | Inferrer | Cost | Typical hit rate |
|---|---|---|---|
| 1 | **Cached strategy** for this package (any version) | free | high, after warm-up |
| 2 | **Definitions repo** entry for this exact target | free | ~0.1% |
| 3 | **CI-derived** from the release workflow | free | substantial and growing |
| 4 | **Heuristic** from source layout, lockfiles, and intrinsics | free | the bulk |
| 5 | **Model**, cheap tier | cheap | The remainder |
| 6 | **Model**, strong tier | expensive | Only on evidence of progress |

Rungs 1 through 4 make no model call, which is what makes the economics in
[`07-ai.md`](07-ai.md) §4 work. A candidate from any rung passes schema validation, tool resolution,
and the requirements check in §7 before we accept it.

## 7. Validation before execution

We reject a rendered strategy, rather than repairing it or warning about it, when it:

- requests an **egress tier above the sweep's ceiling**,
- references a **base image without a digest**, or an unregistered tool,
- declares `privileged: true` where the runner does not advertise that capability,
- arrives as a `Prebuilt` strategy with no human approval record, or
- fails schema validation or template rendering.

Schema validation is a real control with a hard limit: **validating a string that contains bash is
validating a string.** We prefer the step DSL and record `Manual` at a lower trust tier, and the
environment is what decides what a build can *do*. That means deny-all egress except the mirror, a
filesystem allowlist, and the artifact-hash check in [`12-security.md`](12-security.md) §2. Neither
mechanism stands alone, and treating the schema as a security boundary would be the more dangerous of
the two mistakes.

## 8. Promotion

We accept `Manual` strategies, execute them, attest them at a lower trust tier, and **flag them in
the UI as unpromoted**. A recurring manual strategy is a work item rather than a steady state.
Promoting one means:

- lifting the pattern into a **flow template** in `_tools/`, where it generalizes across packages;
- writing a **definitions entry**, where it belongs to one package;
- adding a **heuristic** to the relevant `Registry` implementation, where the signal was there and we
  missed it.

Each promotion runs against the whole corpus before merge. That is the flywheel described in
[`07-ai.md`](07-ai.md) §5, and it stops the system paying for the same insight ten thousand times.


---

> **Revised in implementation.** A tool's `needs` are collected whether or not any of its steps
> survive their conditions, so a conditional tool contributes its system packages to every build that
> references it. Put a need on the step that uses it. Two npm tools got this wrong and the symptom
> was a pinned Node aborting under modules belonging to a Node nobody asked for —
> [`16-findings.md`](16-findings.md) §3.3.
