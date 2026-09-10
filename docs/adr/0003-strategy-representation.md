# ADR-0003. Strategy representation

**Status:** accepted

## Decisions

1. `Strategy` is a **serde internally tagged enum with four variants**: `LocationHint`, `Flow`,
   `Manual`, `Prebuilt`.
2. The prior art's thirteen ecosystem-specific strategy variants become **named flow templates in
   the definitions repository** rather than Rust types.
3. `strategy_digest` covers an **RFC 8785 (JCS) canonical serialization of the migrated-to-latest
   value**, not the YAML bytes.
4. Templates use `minijinja` with `UndefinedBehavior::Strict`, a `BTreeMap`-only context, no floats,
   no time values, and **one render per strategy**.

## Internal tagging, not `untagged`

The most consequential serde decision in the design.

- `#[serde(untagged)]` produces "data did not match any variant of untagged enum Strategy", with no
  span, no field name, and no inner error. Models emit this format and humans hand-edit it, so that
  message rules the option out. **The build-repair loop can only be as good as this error.**
- `untagged` picks the wrong variant without complaining when two variants share a shape.
  `LocationHint` is a subset of `FlowStrategy` here, so that bug is live.
- `untagged` fails to compose with `deny_unknown_fields`.
- `tag = "kind"` costs one line of YAML.

Internal tagging buffers through serde's private `Content` type and loses spans, so deserialization
runs two passes and routes through **`serde_path_to_error`**. That yields
`flow.deps[2].with.pythonVersion: invalid type: integer, expected string`, which goes verbatim into
the repair prompt. Line for line, that crate returns more than any other dependency here.

## Deleting the ecosystem variants

Every one of the prior art's `pypi_pure_wheel_build`, `npm_pack_build`, `cratesio_cargo_package` and
the rest is a pre-canned flow strategy wearing a type. Turning them into templates means:

- adding an ecosystem takes YAML plus one `Registry` implementation, with **no** change to the enum,
  which is what "easily extensible" has to mean in practice;
- the enum stays at four variants, keeping schema migration tractable;
- a model has one output shape to learn.

## The digest covers canonical JSON, not source bytes

Cover the bytes and editing a comment invalidates the cache for every target using that strategy. At
100k targets, that is an expensive typo. Tool definitions hash in too, so changing a tool invalidates
every strategy that uses it.

## The template settings that depart from the defaults

Each one blocks a class of silent wrongness.

- **Strict undefined.** A typo'd `{{ targt.version }}` has to be a hard error. Go templates render
  `<no value>`, minijinja's default renders empty, and either produces `pip install ==` and a
  mystifying failure. This upgrade over the prior art costs one line.
- **`BTreeMap` only.** Go sorts map keys when ranging and minijinja preserves insertion order, so a
  `HashMap` in the context makes rendering, and therefore `strategy_digest`, vary between runs.
- **No floats, no time values.** Float formatting varies, and a template that can read a clock
  introduces nondeterminism.
- **Render once.** The rendered script is the byproduct the attestation records, so a verifier needs
  no template engine of ours and old attestations need no migration.
