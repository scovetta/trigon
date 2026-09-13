# Trigon threat model

## 1.1 Header

**Project:** Trigon — semantic rebuild verification for open-source packages
**Version binding:** `1e857d1`, 2026-09-13. A report against a given commit is triaged against the
model as it stood at that commit, not against `main`.
**Status:** unratified draft. No maintainer has reviewed it. While any *(inferred)* or *(assumption)*
tag remains, the status cannot be `accepted`.
**Triage policy:** `strict`.

**Prior policy.** `docs/12-security.md` ("12. Security model") is the prior security-policy document.
This model absorbs it as a strict superset; the back-map is the appendix. There is **no**
`SECURITY.md`, no disclosure address and no supported-versions statement anywhere in the repository
*(documented, verified: no file matching `*SECURITY*` outside `docs/12-security.md`)*, which is why
§1.18 Q17 exists.

**Reporting.** A finding that violates a property in §1.11 goes to the maintainer privately. Until
Q17 is answered there is no published channel, so in the interim: GitHub private vulnerability
reporting on the repository, and if that is not enabled, a direct message to the repository owner.
A `MODEL-GAP` goes to the maintainer too, but as a revision request under §1.16 rather than as a
vulnerability.

**Provenance legend.** Every non-trivial claim carries exactly one tag.

| Tag | Meaning |
| --- | --- |
| *(documented, source)* | Stated in a maintainer-authored source in this repository, or verifiable from its public surface. The source is named. |
| *(maintainer, YYYY-MM)* | Stated by a maintainer in answer to this process. None yet. |
| *(assumption, QN)* | A conservative default this document commits to where the sources are silent. `QN` is in §1.18. |
| *(inferred, QN)* | Reasoned from code structure, with no default committed. Genuinely open. `QN` is in §1.18. |

**What a tag is allowed to do.** Under `strict`, only *(documented)* or *(maintainer)* can close a
report against its reporter. An *(inferred)* or *(assumption)* claim routes to `ESCALATE:
unratified-claim` — it can never close. `VALID` and `MODEL-GAP` are always available.

**Draft confidence:** see the census at the end of §1.19. Every *(inferred)* and *(assumption)* tag
resolves to a question in §1.18. The documented count is high because the maintainer wrote eighteen
design chapters; it is not a maturity signal, and `docs/16-findings.md` records where the code has
since corrected them.

**Backtest:** 38 items, 33 clusters, 9 families. Result and revisions in §1.15.
**Sibling models:** none.

### What Trigon is

Trigon takes a published package — an npm tarball, a Python wheel — and rebuilds it from the source
the package points at. It compares the two, not byte-for-byte but under a named set of
**stabilizers**: small, ordered, total transforms that erase differences nobody meant to publish,
such as file order inside a tar or an embedded build timestamp.

**The outcomes, strongest first.** These four words carry the whole model, so they are defined once
here and used everywhere:

- `exact` — the raw bytes are identical, before any stabilizer ran.
- `normalized` — the stabilized forms are identical, **and** every stabilizer that fired was built
  into Trigon and no riskier than metadata.
- `normalized_with_caveats` — the stabilized forms are identical, but some stabilizer that fired was
  authored by a human or a model, or changes content rather than metadata.
- `divergent` — the stabilized forms differ.

A fifth state, **`void`**, sits outside all four: the run is not evidence of anything, because the
artifact under test reached the build over the network. It is not a pass and not a failure.

Where the operator asks for one, a run also produces a signed in-toto attestation. **The attestation
is the product.** Everything else exists to make it honest.

### Triager quick-start

> Given an inbound finding:
>
> 1. **Find the sink** in §1.7's trust table. For a "downstream may assume X" finding, use §1.8.
> 2. **Find the contract dimension** in §1.7's matrix and follow the row to the claim that owns it.
> 3. **Check the attacker** against §1.10. Distinguish control of *data* from control of *size*, of
>    *a shell script*, of *a container image*, or of *a model's output*.
> 4. **Check the component** against §1.2 and §1.3, and the configuration against §1.6.
> 5. **Check the layer.** If a dependency behaved as documented and the fault is downstream of it,
>    apply §1.9.
> 6. **Apply §1.17's precedence**, starting with an exact §1.15 match.
> 7. **Check the licensing tag.** If the rule that matched is *(inferred)* or *(assumption)*, the
>    disposition is `ESCALATE: unratified-claim`, whatever rule matched. Only *(documented)* and
>    *(maintainer)* close.
> 8. **Assign exactly one disposition**, citing the section and its tag. If none fits, assign
>    `MODEL-GAP` and open a §1.16 revision. Do not improvise.

---

## 1.2 Scope and intended use

### The claim, stated exactly

A signed `trigon.dev/equivalence/v1` predicate says:

> Artifact **P**, as published, and artifact **R**, produced by recipe **S** in environment **E**,
> have stabilized forms that are byte-identical under stabilizer set **T**, whose members and digest
> are named in the statement, and of which exactly these fired, at these risk tiers, with these
> provenances.

Every noun there is deterministic. A third party holding P, R and the attestation re-derives all of
it with `trigon verify-attestation --rerun-comparison`, using a binary that contains no network
client and no model code *(documented, docs/09-attestations.md §7)*.

**What it does not say.** A reader must not read any of these into it:

- **Not that the package is safe.** A package that builds faithfully from a repository containing a
  backdoor reproduces, and should *(documented, docs/12-security.md §11)*.
- **Not that the source is the source.** The claim is about two files. Whether the repository is the
  one a package's users think of as its source is a separate question — and for npm it is the *only*
  interesting one, because npm packages reproduce at the tarball level almost always with no source
  linkage at all *(documented, docs/03-ecosystems.md §0)*.
- **Not that no model was involved.** Model involvement is recorded beside the claim as
  `derivation.method`, never inside it, and filtering on it is the consumer's job *(documented,
  docs/09-attestations.md §2.1)*.
- **Not that the build was observed.** No run at any tier is attestable at full trust today, because
  there is no network transcript *(documented, docs/16-findings.md §3.13)*.

**What would have to be true for it to be wrong.** Exactly one of:

1. **The rebuild obtained P rather than building it** — the forged-attestation attack *(documented,
   docs/12-security.md §1.1)*. The artifact guard is the control. It compares bytes, so an attacker
   who fetches P re-encoded, encrypted, or reassembled from chunks defeats it *(documented,
   docs/12-security.md §2.5)*.
2. **A stabilizer erased a real difference.** The provenance cap is the control, and the consumer
   applies it: demand `normalized` and every stabilizer that fired was built in and no riskier than
   metadata *(documented, docs/00-overview.md §3.1)*.
3. **Our serialization stack is wrong** in a way that affects both sides. It is self-consistent, so
   our bugs surface as false negatives; over-aggressive membership deletion is the false-positive
   direction *(documented, docs/13-roadmap.md §3)*.
4. **The signing identity is not who you think.** Checking it is the reader's job *(documented,
   docs/09-attestations.md §7)*.

The reader is expected to re-derive the claim, check the signing identity against their own policy,
and set their own risk threshold. §1.13 is the full list.

### Deployment and roles

Trigon ships as one binary. Today it runs as a CLI on a workstation or a CI machine. The fleet in
`docs/10-scale.md` is designed and not built *(documented, docs/README.md "Status")*.

| Role | Who | Trusted for |
| --- | --- | --- |
| **Attestation consumer** | Reads a signed predicate and decides whether to trust a package. May have no Trigon installation. | Nothing. They are the audience, and the claim must survive their scepticism. |
| **Operator** | Runs `trigon rebuild` / `sweep`. Their machine executes attacker-supplied build scripts. | The invocation, the egress tier, the definitions ref, the signing key. |

There is no third-party-client role: no daemon, no authenticated API, no multi-tenancy *(documented,
docs/12-security.md §7)*.

### Component families

The verifier is the first five rows: `cargo build -p trigon --no-default-features`, which links no
async runtime and no network client, asserted by `cargo run -p xtask -- policy` *(documented,
docs/01-architecture.md §2.2)*. Verified at this commit: `cargo tree -p trigon
--no-default-features` names no `tokio`, `reqwest` or `hyper`.

| Family | Entry point | Touches | In model |
| --- | --- | --- | --- |
| `archive-parsing` (`trigon-archive`) | `Archive::read`, the three writers | nothing outside the process | **in** |
| `stabilization` (`trigon-stabilize`) | `profile(id)`, `StabilizerSet::apply` | nothing | **in** |
| `comparison-and-verdict` (`trigon-compare`, `trigon-core`) | `compare()`, `Match`, PURL parsing | nothing | **in** |
| `attestation` (`trigon-attest`) | statement building, DSSE, `Signer` | reads a key file when signing | **in** |
| `strategy-rendering` (`trigon-strategy`) | `Strategy` parse, flow DSL, minijinja render | nothing; emits a script for someone else to run | **in** |
| `archived-stabilizer-sets` (`trigon-stabilize-wasm`) | the `wasm` feature, off by default | runs a WASM module in-process | **in**, §1.6 |
| `registry-and-source` (`trigon-registry`) | `Registry::resolve`/`fetch`, `SourceCache` | network, filesystem, spawns `git` | **in** |
| `build-execution` (`trigon-sandbox`, `trigon-mirror`) | `BuildRunner::start`, the mirror server | spawns `podman`, binds a socket, writes a work directory | **in** |
| `model-inference` (`trigon-ai`) | `Provider::complete`, the Builder, `RepairLoop` | network, spawns `copilot` | **in** |
| `operator-surface` (`trigon` bin, `trigon-store`) | CLI subcommands, `trigon watch`'s HTTP server | everything above, plus a listening socket and a store | **in** |
| `definitions` (the `trigon-definitions` repository) | `build.yaml`, custom stabilizers | — | **in as an input**, §1.9 |
| repository tooling (`xtask`, `fuzz/`, `corpora/`, `scripts/`) | not shipped in any binary | — | **out**, §1.3 |

---

## 1.3 Out of scope

A report that depends on one of these routes by §1.17 precedence: rule 2,
`OUT-OF-MODEL: unsupported-component`, unless the bullet names a §1.12 disclaimer, in which case
rule 7 applies first.

- **Malware detection.** Trigon answers whether an artifact matches a source. A malicious package
  that reproduces is a *correct* result *(documented, docs/12-security.md §11)*.
- **Judging whether the source is trustworthy** *(documented, docs/12-security.md §11)*.
- **Defending a compromised control plane.** Compromise the scheduler and the attestor and the signed
  output means nothing; `--rerun-comparison` is what limits the damage *(documented,
  docs/12-security.md §11)*.
- **Bit-for-bit reproducibility as an end.** Semantic verification with named normalizations and
  consumer-set thresholds instead *(documented, docs/00-overview.md §4–5)*.
- **Emulating GitHub Actions runners.** Runner images are mutable and unpinnable, so emulating them
  would make our own results unreproducible *(documented, ADR-0009)*.
- **Replacing trusted publishing.** It is an input and a cross-check *(documented,
  docs/00-overview.md §5)*.
- **Being a general CI system** *(documented, docs/00-overview.md §5)*.
- **macOS and Windows runners, and Maven, Go and Debian**, which report `Unsupported` rather than
  failing *(documented, docs/06-ci-awareness.md §3.3)*.
- **Syscall-level observability.** eBPF and tiers 2–3 are cut *(documented, ADR-0007)*.
- **Multi-tenancy.** The rules are decided and not implemented *(documented, docs/12-security.md §7)*.
- **Repository tooling.** `xtask`, `fuzz/`, `corpora/` and `scripts/` ship in no binary
  *(documented, crates/trigon/Cargo.toml — none is a dependency)*.

**Designed but not built.** Not non-goals — unwritten code, which the design chapters describe in the
present tense. A finding against behaviour that exists only in `docs/` is not a finding *(documented,
docs/README.md "Status")*. The largest: the fleet, the write-only blob credential of
`docs/12-security.md` §2.3, the two-agreeing-attempts confirmation policy *(documented,
docs/16-findings.md §5)*, the divergence publication pipeline, and most of `docs/11-interfaces.md` §2.

---

## 1.4 Trust boundaries and reachability

`docs/12-security.md` §3 draws the intended worker split. What is *built* is one process, so the
boundaries that hold today are narrower.

```
  operator's shell
        │  purl, flags, --model spec, key path
        ▼
  ┌─────────────────────────────────────────┐
  │ trigon process (trusted: holds the key, │      network: registries, git hosts,
  │ the store, the operator's filesystem)   │◄───► model endpoints, base images
  └───────────────┬─────────────────────────┘
                  │ writes a Dockerfile + script, spawns podman
                  ▼
  ╔═══════════════════════════════════╗  ── the one enforced boundary ──
  ║ build container (hostile)         ║
  ║  runs the package's own build     ║      egress: at an enforced tier, the
  ║  no signing key, no credentials   ║◄───► mirror only, and nothing else
  ╚═══════════════┬═══════════════════╝
                  │ writes an artifact to a bind-mounted output directory
                  ▼
        comparison, in the trigon process
```

The container boundary is real and enforced: attacker code runs inside it, and the egress tier bounds
what it reaches *(documented, docs/08-execution.md §5)*. **The attestor is not a separate process in
the built system**, so the design's "the attestor never executes sandbox-derived code" does not hold
for a local `trigon rebuild --attest`. The separable path is `trigon rebuild --store` followed by
`trigon attest` *(inferred, Q2)*.

**Reachability preconditions.** A finding matters only if it meets its family's condition.

| Family | Reachable from… |
| --- | --- |
| `archive-parsing` | the bytes of a published or a rebuilt artifact |
| `stabilization` | an archive already parsed, or a stabilizer set id named in an attestation |
| `archived-stabilizer-sets` | a `.wasm` module the operator passed to `--stabilizers` |
| `comparison-and-verdict` | two summaries produced by this process in one run |
| `attestation` | a statement this process built, or an attestation handed to `verify-attestation` |
| `strategy-rendering` | a strategy from the definitions repo, a heuristic, CI parsing, or a model |
| `registry-and-source` | registry metadata, a package-declared repository URL, or a git host's response |
| `build-execution` | a rendered strategy, or bytes crossing the mirror |
| `model-inference` | text a package wrote reaching a prompt, or a provider's response |
| `operator-surface` | a flag, a work directory on disk, or an HTTP request to `watch` |
| `definitions` | a merged pull request against the definitions repository |

---

## 1.5 Assumptions about the environment

- **Platform.** Linux on x86-64 is what is built and tested; the build path needs `podman`
  *(assumption, Q3)*.
- **Rust.** MSRV 1.85, and `#![forbid(unsafe_code)]` in the judgement half *(documented,
  crates/trigon-core/src/lib.rs:1-9)*.
- **Container runtime.** An enforced-tier run needs rootless `podman`, plus a mirror image and a base
  image the operator built first *(documented, README.md "A note on `--egress open`")*.
- **Clock.** The timewarp mirror filters to a publish instant taken from registry metadata, not the
  host clock, and nothing in the judgement half reads a clock *(documented, docs/07-ai.md §8, which
  forbids a wall-clock read in prompt construction)*.
- **Concurrency.** Nothing here is documented thread-safe beyond Rust's own `Send` and `Sync` bounds,
  and no type promises interior consistency across threads *(documented, by the absence of any such
  statement in `docs/` and in the public API of every crate)*. Two Trigon *processes* on one machine
  can still disturb each other's podman image store *(documented, docs/17-backlog.md B6)*.

### What Trigon does not do to its host

Negative claims, split because the verifier and the build path are different programs.

**The verifier** (`--no-default-features`):

| Effect | Stance | Conditions |
| --- | --- | --- |
| Network of any kind | **absent** | it links no network client *(documented, docs/01-architecture.md §2.2)* |
| Child processes | **absent** | *(documented, docs/01-architecture.md §2.2)* |
| Environment variables | **absent** | *(documented, docs/01-architecture.md §2.2)* |
| Filesystem writes | **conditional** | only paths the operator named: the `stabilize` output and the `--attest` file. `SpillFile` exists as a type and is never constructed, so nothing spills *(documented, verified: no construction of `Body::Spilled` anywhere in `crates/`)* |
| Filesystem reads | **conditional** | only paths the operator named, plus a signing key file *(documented, crates/trigon/src/main.rs — every read path is a CLI argument)* |
| stdout / stderr | **present** | the verdict on stdout, `tracing` on stderr *(documented, docs/11-interfaces.md)* |
| Signal handlers, global state, locale or FPU mutation | **absent** | *(assumption, Q4)* |
| Executing WebAssembly | **conditional** | only under the non-default `wasm` feature *(documented, docs/09-attestations.md §7.1)* |

**The build path** additionally, by design:

| Effect | Stance | Conditions |
| --- | --- | --- |
| Outbound HTTPS to registries and git hosts | **present** | resolution, fetch, checkout *(documented, docs/03-ecosystems.md)* |
| **Outbound HTTPS to any URL registry metadata names** | **present** | a package's own metadata chooses the host this machine connects to *(inferred, Q5)* |
| Spawning `git` | **present** | with `GIT_CONFIG_NOSYSTEM` and a restricted `GIT_ALLOW_PROTOCOL` *(documented, crates/trigon-registry/src/source.rs)* |
| Spawning `podman` | **present** | the build *(documented, docs/08-execution.md §1)* |
| Spawning the Copilot CLI | **conditional** | only with `--model copilot:` *(documented, crates/trigon-ai/src/copilot.rs:133)* |
| Outbound HTTPS to a model endpoint | **conditional** | only when `--model` names a live provider *(documented, README.md "Asking a model")* |
| Binding a listening socket | **conditional** | `trigon watch` (loopback by default) and the mirror *(documented, crates/trigon/src/main.rs — `--bind` defaults to `127.0.0.1:8099`)* |
| Reading environment variables | **present** | API keys and base-URL overrides; **keys come from the environment and never the command line** *(documented, crates/trigon/src/inferrer.rs:527)* |
| Writing a work directory | **present** | fetched artifacts, build logs, rebuilt artifacts *(documented, docs/18-management-ui.md §2)* |

---

## 1.6 Build-time and configuration variants

**Support posture, not defaultness, decides routing.** A defect in a supported configuration is in
model even when that configuration is not the default.

| Knob | Default | Stance | Effect |
| --- | --- | --- | --- |
| `build` feature | **on** | supported | Adds registry, sandbox, mirror, store, AI, a tokio runtime and a network client. Turning it off is the verifier, and is the *stronger* posture. |
| `wasm` feature | **off** | supported | Lets the verifier run an archived stabilizer set rather than only name it. It roughly doubles the verifier's dependency tree, and the small tree is what a sceptic checks *(documented, crates/trigon/Cargo.toml)*. See D18. |
| `--egress open` | **the default for `rebuild` and `sweep`** | **supported, and it voids the strong claim** | The build reaches the whole internet; the run records `attestable: false` *(documented, README.md "A note on `--egress open`")*. |
| `--public-key` on `verify-attestation` | **absent** | supported | Without it the tool re-derives the comparison and reports the signature as **present and unchecked** rather than verified. "Unsigned" and "signed by someone you did not check" are different things, and the tool distinguishes them *(documented, README.md "Signing it, and checking the signature")*. |
| `local-unsafe` runner | not the default | **dev-only** | Labelled development-only and refuses to sign *(documented, docs/08-execution.md §1)*. A finding that needs it closes `OUT-OF-MODEL: non-default-build`. |

**The insecure default, named.** `--egress open` is the shipped default for the two commands an
operator actually runs. The project's position is that such a run carries a weaker claim which the
attestation *states* rather than hides. So:

- A report that a build at `--egress open` fetched something it should not have →
  `BY-DESIGN: property-disclaimed`, discharged by D15 and §1.6 itself.
- A report that the run nevertheless claimed full trust → `VALID`, against P11.

This distinction is the one a triager needs most often *(documented, README.md;
docs/08-execution.md §5)*.

---

## 1.7 Assumptions about inputs

### Per-operand trust table

One row per operand an adversary in §1.10 can influence. Operator-supplied operands — a path, a flag,
a key file, a `--model` spec, a definitions ref — are **trusted** and not tabled individually.

| Entry point | Operand | Attacker-controllable | Control kind | Caller must enforce | Provenance |
| --- | --- | --- | --- | --- | --- |
| `archive::parse` | artifact bytes | **yes** | data, size, object-topology, serialized-state | nothing — safe parsing is P1; only the ceiling's size is D1 | *(documented, docs/05-archive-and-normalization.md §2.2)* |
| `archive::serialize` | the parsed archive | **yes** (derived) | data, size, object-topology | nothing — P2 | *(documented, docs/05 §3)* |
| `compare::summarize` | artifact bytes | **yes** | data, size | nothing | *(documented, docs/08-execution.md §6)* |
| `compare::compare` | two `Summary` values | no — produced by this process | serialized-state | both must come from one run; the set-digest check enforces it | *(documented, crates/trigon-compare/src/lib.rs:159)* |
| `core::classify` / `compress` | a build log | **yes** | data, size, x-build-log | nothing — bounded and control-stripped, P7 | *(documented, crates/trigon-core/src/logs.rs:8-21)* |
| `core::TargetRef::from_str` | a PURL | operator, usually | data, resource-name | a version is required; a PURL without one is refused | *(documented, crates/trigon-core/src/target.rs:152)* |
| `StabilizerSet` resolution | a set id, and the `.wasm` module it resolves to | **operator chooses the module; the id comes from an attestation** | resource-name, collaborator-implementation, x-wasm-module | **the operator decides which archived set to trust and run**; an id alone executes nothing | *(documented, docs/09-attestations.md §7.1)* |
| `Registry::resolve` | registry response JSON | **yes** | data, size, serialized-state, object-topology | nothing; shape errors surface as `RegistryError` | *(documented, crates/trigon-registry/src/npm.rs — fields are read, not schema-validated)* |
| `Registry::fetch` | `meta.url` | **yes — a package's metadata chooses the host this machine contacts** | resource-name | the operator accepts that resolving a package means contacting hosts that package names | *(inferred, Q5)* |
| `Registry::fetch` | response body | **yes** | data, size | bytes are re-hashed and checked against the declared digest | *(documented, crates/trigon-registry/src/registry.rs)* |
| `SourceCache::checkout` | `repo` | **yes** | resource-name, x-git-remote-url | **https only**, enforced here | *(documented, crates/trigon-registry/src/source.rs)* |
| `SourceCache::checkout` | `commit` | **yes** | x-git-ref | **40 hex characters only**, so a ref cannot be an option or a path | *(documented, crates/trigon-registry/src/source.rs)* |
| `Checkout::files` / `read` | repository contents | **yes** | data, object-topology | nothing — this is what the Builder reads | *(documented, docs/16-findings.md §3.7)* |
| strategy inference | `package.json` `scripts.build` | **yes** | data, x-shell-script | nothing here; the environment is the enforcement point | *(documented, docs/12-security.md §5)* |
| `strategy` parse | a strategy document | **yes when a model or a package authored it** | data, x-shell-script, x-model-output | **schema validation is not sanitization** — a `runs:` step is free-form shell | *(documented, docs/04-strategies.md §7)* |
| `strategy` render | template context | no — a closed type | type-class | undefined variables are a hard error | *(documented, docs/04-strategies.md §3)* |
| build container | everything the build runs | **yes, by design** | x-shell-script | the egress tier and the container are the boundary | *(documented, docs/08-execution.md §5)* |
| mirror `/-artifact/`, `/-toolchain/` | request host and path | **yes, from inside the build** | resource-name | compiled-in exact-match host allowlists — but these routes are **not** access-controlled and the artifact route applies **no** time filter | *(documented, docs/16-findings.md §3.13)* |
| mirror index route | the time filter, in basic auth | **readable from inside the build** | data | an index request with no filter is refused 400 | *(documented, crates/trigon-mirror/src/server.rs)* |
| egress guard | every proxied response body | **yes** | data, size, rate | hashed as it streams; a whole-artifact or member match voids the run | *(documented, docs/12-security.md §2.2)* |
| build output directory | file entries the build wrote | **yes** | data, resource-name, object-topology | **symlinks are not followed** | *(documented, docs/16-findings.md §3.12; crates/trigon-sandbox/src/podman.rs:691)* |
| store record paths | package name, namespace, version | **yes** | resource-name | nothing here — `object_store`'s `Path` percent-encodes `..` and `/` inside a component, so a name cannot escape the store root. **The safety is the dependency's, not ours** (§1.9) | *(documented, crates/trigon-store/src/lib.rs:204; verified against object_store 0.12: `..` → `%2E%2E`)* |
| `verify-attestation` | the bundle | **yes** | data, serialized-state | the signature is checked only with `--public-key`, and the tool says which it did | *(documented, README.md)* |
| `trigon watch` `GET /run/{index}` | the path segment | **yes if the port is reachable** | data, resource-name | parsed as an integer and re-formatted; never joined as a caller-supplied path | *(documented, crates/trigon/src/watch.rs)* |
| `trigon watch` all views | package names, build logs, strategies | **yes** | data, size, x-build-log | every package-derived string is HTML-escaped on the way out | *(documented, crates/trigon/src/watch.rs — `esc`)* |
| model prompt | README, CI config, manifests, build log | **yes** | data, x-build-log | **nothing prevents injection**; it is fenced, bounded and control-stripped, and accepted as residual risk | *(documented, docs/12-security.md §4)* |
| model response | the proposed strategy | **the model's, and so indirectly the attacker's** | x-model-output | parsed and validated; the provenance cap bounds the damage | *(documented, docs/00-overview.md §3.1)* |
| definitions repository | a `build.yaml` or a custom stabilizer | **yes, via a merged pull request** | data, x-shell-script, collaborator-implementation | two-party review, a mandatory prose `reason:`, and the corpus-wide impact preview | *(documented, docs/12-security.md §8)* |

**Coverage.** Every family's public surface is represented. Within a family the table names the
operands that carry attacker power. **The remainder are believed operator-supplied or internal
*(assumption, Q7)* — and because that is an assumption, a finding against an operand not in this
table does not close. It escalates.**

### Contract-dimension matrix

Eight dimensions per in-scope family. Every `claimed` and `disclaimed` row names the §1.11 property
or §1.12 disclaimer that owns it; no claimed row exists only here.

| Family | Dimension | Status | Conditions / boundary | Owner |
| --- | --- | --- | --- | --- |
| archive-parsing | numeric-domain | claimed | offsets checked; a wrapping add was fixed and is tested | P1 |
| archive-parsing | failure-atomicity | claimed | a parse failure keeps the member `Inline` and emits `NestedParseFailed` | P1 |
| archive-parsing | recursive-cyclic-topology | claimed | recursion is structural; the default of 4 descends three levels (`N` parses `N-1`) | P1 |
| archive-parsing | callback-execution | N/A | the API accepts no callbacks and holds no function values | — |
| archive-parsing | serialization-reconstruction | claimed | `parse(write(a)) == a`, proptested | P2 |
| archive-parsing | reference-lifecycle | claimed | copy-on-write from one owned buffer; a body is never aliased after mutation. Not over an mmap — see D23 | P2 |
| archive-parsing | concurrency-reentrancy | disclaimed | no thread-safety beyond `Send`/`Sync` is stated | D8 |
| archive-parsing | resource-complexity | claimed | every cap is enforced against produced bytes, not declared sizes; the ceiling's *size* is what D1 disclaims | P1 |
| archive-parsing | x-filesystem-materialization | claimed | no archive member is ever written to a filesystem path | P22 |
| stabilization | numeric-domain | claimed | stabilizers take no sizes or offsets from the input | P3 |
| stabilization | failure-atomicity | claimed | stabilizers return no `Result`; there is no half-stabilized state | P3 |
| stabilization | recursive-cyclic-topology | claimed | nesting is bounded by the archive model's depth limit | P1 |
| stabilization | callback-execution | N/A | the registry holds `Arc<dyn Stabilizer>` values compiled into this binary; an archived set is the `archived-stabilizer-sets` family | — |
| stabilization | serialization-reconstruction | claimed | `stab(stab(x)) == stab(x)`, a required and tested property | P3 |
| stabilization | reference-lifecycle | N/A | the registry hands out `Arc`s and owns nothing mutable | — |
| stabilization | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| stabilization | resource-complexity | claimed | bounded by the archive it walks; a stabilizer allocates no more than one member | P3 |
| archived-stabilizer-sets | numeric-domain | claimed | the module operates on bytes the host hands it | P23 |
| archived-stabilizer-sets | failure-atomicity | claimed | a trap in the module fails the re-derivation rather than producing a digest | P23 |
| archived-stabilizer-sets | recursive-cyclic-topology | N/A | the host calls one exported function once per artifact | — |
| archived-stabilizer-sets | callback-execution | **disclaimed** | an archived set is third-party code the operator chose to run; wasmtime's sandbox is the boundary and it is a dependency's guarantee | D21 |
| archived-stabilizer-sets | serialization-reconstruction | claimed | the archived set is proved to agree with the compiled one before use | P23 |
| archived-stabilizer-sets | reference-lifecycle | N/A | the module instance lives for one call | — |
| archived-stabilizer-sets | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| archived-stabilizer-sets | resource-complexity | **disclaimed** | memory growth inside the module is the module's | D21 |
| archived-stabilizer-sets | x-provenance-cap | **disclaimed** | the cap cannot be confirmed from bytes alone, so a `normalized` claim degrades to `normalized_with_caveats` and **a true claim reads as refuted** | D18 |
| comparison-and-verdict | numeric-domain | N/A | compares digests and counts; takes no sizes from the input | — |
| comparison-and-verdict | failure-atomicity | claimed | a set mismatch refuses before comparing, classified `Fault::Bug` | P4 |
| comparison-and-verdict | recursive-cyclic-topology | claimed | the diff walks the archive model's bounded tree | P1 |
| comparison-and-verdict | callback-execution | N/A | no callbacks | — |
| comparison-and-verdict | serialization-reconstruction | claimed | outcomes cross the wire as strings, `FromStr` the exact inverse of `Display` | P24 |
| comparison-and-verdict | reference-lifecycle | N/A | borrows for the call's duration and retains nothing | — |
| comparison-and-verdict | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| comparison-and-verdict | resource-complexity | claimed | linear in members; each side is walked at most twice | P25 |
| attestation | numeric-domain | N/A | no arithmetic on attacker-supplied values | — |
| attestation | failure-atomicity | claimed | `trigon attest` refuses a void run rather than signing a weaker claim | P6 |
| attestation | recursive-cyclic-topology | claimed | JCS refuses what another implementation might not reproduce | P9 |
| attestation | callback-execution | claimed | `Signer` and `ArchivedSet` are operator-chosen collaborators, named on the command line | P26 |
| attestation | serialization-reconstruction | claimed | canonical JSON is byte-stable; floats and non-ASCII keys are refused, not coerced | P9 |
| attestation | reference-lifecycle | N/A | a statement is built, signed and dropped within one call | — |
| attestation | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| attestation | resource-complexity | disclaimed | a statement is as large as the difference summary it carries | D9 |
| strategy-rendering | numeric-domain | N/A | no arithmetic on strategy values | — |
| strategy-rendering | failure-atomicity | claimed | an unregistered `uses:` is a hard error naming the tool, never an empty fragment | P27 |
| strategy-rendering | recursive-cyclic-topology | claimed | tool composition is acyclic at load and depth-bounded at render | P27 |
| strategy-rendering | callback-execution | **disclaimed** | a `runs:` step is free-form shell and nothing here sanitizes it | D2 |
| strategy-rendering | serialization-reconstruction | claimed | `strategy_digest` is canonical and domain-separated | P28 |
| strategy-rendering | reference-lifecycle | N/A | rendering borrows and returns owned strings | — |
| strategy-rendering | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| strategy-rendering | resource-complexity | claimed | render depth is bounded | P27 |
| registry-and-source | numeric-domain | N/A | no arithmetic on registry values | — |
| registry-and-source | failure-atomicity | disclaimed | a partial checkout or fetch is not rolled back | D10 |
| registry-and-source | recursive-cyclic-topology | N/A | registry metadata is read field-wise, never walked as a graph | — |
| registry-and-source | callback-execution | claimed | `git` is spawned with a fixed environment, https only, 40-hex commits only | P10 |
| registry-and-source | serialization-reconstruction | disclaimed | registry JSON is read field-wise and not schema-validated | D11 |
| registry-and-source | reference-lifecycle | N/A | a `Checkout` owns its directory for its lifetime | — |
| registry-and-source | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| registry-and-source | resource-complexity | disclaimed | no bound on a repository's or a response's size | D12 |
| build-execution | numeric-domain | N/A | no arithmetic on build values | — |
| build-execution | failure-atomicity | claimed | a runner refuses a tier it cannot enforce rather than downgrading it | P11 |
| build-execution | recursive-cyclic-topology | N/A | a build plan is a flat phase list | — |
| build-execution | callback-execution | **disclaimed by design** | executing attacker code is the purpose; the container is the boundary | D3 |
| build-execution | serialization-reconstruction | N/A | nothing here round-trips a serialized form | — |
| build-execution | reference-lifecycle | disclaimed | two processes share one podman image store | D4 |
| build-execution | concurrency-reentrancy | disclaimed | see D4; nothing excludes two runs | D4, D8 |
| build-execution | resource-complexity | claimed | a hard wall-clock kill bounds a build; the default is 1800s and `--timeout` sets it | P29 |
| model-inference | numeric-domain | N/A | no arithmetic on model output | — |
| model-inference | failure-atomicity | claimed | a budget stop names which budget; a replay refuses a changed prompt rather than answering it | P18 |
| model-inference | recursive-cyclic-topology | N/A | a prompt is a flat part list | — |
| model-inference | callback-execution | **disclaimed** | `--model copilot:` is an agent with a shell; every other provider is a function from a prompt to a string | D5 |
| model-inference | serialization-reconstruction | claimed | a transcript naming a model alias is refused for replay rather than replayed | P18 |
| model-inference | reference-lifecycle | N/A | a request is built and dropped per call | — |
| model-inference | concurrency-reentrancy | disclaimed | one recording replayed concurrently is not supported | D8 |
| model-inference | resource-complexity | claimed | iteration, token and wall-clock budgets, checked **between** iterations, so one long call completes and the next is refused | P30 |
| operator-surface | numeric-domain | N/A | the one numeric input is a target index | — |
| operator-surface | failure-atomicity | disclaimed | `trigon watch` has no write path at all (P20), but a store write is not atomic and is not claimed to be | D6 |
| operator-surface | recursive-cyclic-topology | N/A | the work directory is walked one level deep per view | — |
| operator-surface | callback-execution | N/A | no callbacks | — |
| operator-surface | serialization-reconstruction | disclaimed | the store hash-checks blobs and not its own records | D6 |
| operator-surface | reference-lifecycle | N/A | — | — |
| operator-surface | concurrency-reentrancy | disclaimed | nothing excludes two writers from one work directory or one store | D7 |
| operator-surface | resource-complexity | disclaimed | a `watch` request does work proportional to the whole work directory | D13 |
| definitions | numeric-domain | N/A | — | — |
| definitions | failure-atomicity | N/A | a definitions entry is data read at load time | — |
| definitions | recursive-cyclic-topology | claimed | tool composition is acyclic at load | P27 |
| definitions | callback-execution | **disclaimed** | a `build.yaml` can carry free-form shell, and a custom stabilizer is code | D2, D22 |
| definitions | serialization-reconstruction | claimed | a definitions entry is parsed with `deny_unknown_fields` | P27 |
| definitions | reference-lifecycle | N/A | — | — |
| definitions | concurrency-reentrancy | N/A | the repository is read, never written, by Trigon | — |
| definitions | resource-complexity | N/A | entries are small and hand-authored | — |

---

## 1.8 Outputs, and what a consumer may assume

Trigon's output is somebody else's input. A "downstream may assume X" report routes through
`BY-DESIGN: property-disclaimed`, licensed by the "must not be assumed" cell here.

| Channel | Taint | Guaranteed | Must not be assumed |
| --- | --- | --- | --- |
| the stabilized artifact (`trigon stabilize`) | **same as input** | a byte-stable, store-only re-serialization | that it is safe to execute, extract or trust. It is the same package, normalized *(documented, docs/05 §1)* |
| the comparison / verdict | **constrained** | one of four outcome strings, and digests we computed over bytes we hold | that `exact`/`normalized` means the package is honest, or `divergent` means it is malicious *(documented, docs/12-security.md §11)* |
| the difference summary | **same as input** | deterministic, and recomputable by a third party from the two artifacts | that member paths and difference codes are sanitized before being rendered, logged or prompted. They come from the artifact *(inferred, Q8)* |
| the rendered Dockerfile and build script | **same as input** | a pure function of (strategy, context, tools) | **that it is safe to run outside the container.** It is the package's own shell, assembled *(documented, docs/12-security.md §5)* |
| the rebuilt artifact in the work directory | **same as input** | it is what the build wrote | that it is safe to install or execute. A rebuild of a malicious package is a malicious package *(documented, docs/12-security.md §11)* |
| the signed attestation | **constrained** | canonical JSON; floats and non-ASCII keys refused rather than coerced | that a signature was checked — without `--public-key` the tool re-derives and reports the signature present and unchecked *(documented, README.md)* |
| the build log (stored, rendered, prompted) | **same as input** | bounded and control-stripped before it reaches a model | **that credentials were redacted.** They were not *(documented, docs/18-management-ui.md §2)* |
| `trigon watch` HTML | **constrained** | every package-derived string is HTML-escaped | that the page is authenticated, or safe to serve on a routable address *(documented, crates/trigon/src/main.rs)* |
| `/api/state` JSON | **same as input** | the view model the pages render | that it is access-controlled. It is not *(documented, crates/trigon/src/watch.rs)* |
| the model transcript | **same as input** | the model that answered, the prompt digests, the usage, the reasoning trace | that replaying it reproduces the *result*. It replays the model, not the world *(documented, docs/07-ai.md §8)* |

---

## 1.9 Assumptions about dependencies

**No third-party source is vendored.** Every dependency is a crates.io dependency resolved through
`Cargo.lock`, so a supply-chain report about third-party code is a report about a named crate, and
routes by the table below *(documented, repository: no `vendor/` or `third_party/` at any path)*.

**The ownership rule.** A panic, hang or unbounded allocation *inside* a parsing crate on bytes we
handed it is `OUT-OF-MODEL: dependency-contract` and goes upstream. The same symptom caused by us
failing to bound what we hand it, or what we do with what comes back, is ours and is `VALID`. D1 is
the live example: `flate2` inflates correctly; *we* do not bound the output.

| Dependency | Relied on for | Provenance | If it fails its own contract |
| --- | --- | --- | --- |
| `podman` (external binary) | process, filesystem and **network** isolation of the build. `--network none` is podman's guarantee, not ours | *(documented, docs/08-execution.md §5)* | upstream |
| `git` (external binary) | fetching a checkout without honouring attacker-supplied config | *(documented, crates/trigon-registry/src/source.rs)* | upstream, unless we passed something we should not have |
| `flate2` / `miniz_oxide` | correct inflate of attacker bytes | *(documented, docs/05 §2.1)* | upstream; **bounding the output is ours** — D1 |
| `tar`, `zip` (readers) | correct framing of attacker bytes; we own the writers | *(documented, docs/05 §2 — "ecosystem crates for readers; hand-write all three writers")* | upstream |
| `memmap2` | **nothing today.** It is a dependency of `trigon-archive` and its only use, `SourceMap::map`, has no caller — see D23 | *(documented, verified: `SourceMap::map` has no call site)* | upstream, if it is ever wired |
| `serde_json`, `serde_yaml_ng`, `serde_path_to_error` | parsing attacker-influenced documents without executing them | *(documented, docs/17-crate-picks — `serde_yaml` is archived; `serde_yaml_ng` is the fork)* | upstream |
| `object_store` | **path-component encoding.** `Path::from` percent-encodes `..` and `/` inside a component, so a package-derived name cannot escape the store root | *(documented, verified against object_store 0.12: `..` → `%2E%2E`)* | upstream — **and this is borrowed safety: a naive `PathBuf::join` here would be a traversal** |
| `reqwest` + `rustls` | TLS to registries and model endpoints | *(documented, docs/17-crate-picks)* | upstream |
| `sha2` | collision resistance of SHA-256 | *(documented, docs/02-domain-model.md §5)* | upstream |
| `ed25519-dalek` | signature correctness | *(documented, docs/09-attestations.md §6)* | upstream |
| `minijinja` | rendering without escaping into paths we did not intend; `UndefinedBehavior::Strict` | *(documented, docs/04-strategies.md §3)* | upstream |
| `wasmtime` (feature `wasm`) | sandboxing an archived stabilizer set | *(documented, docs/09-attestations.md §7.1)* | upstream — see D21 |
| a model provider's API | **nothing security-relevant.** An answer is a candidate, validated before use and capped by P5 | *(documented, docs/00-overview.md §3.1)* | never closes a report; a wrong answer is expected input |

**The crate dependency graph is not the security control.** It keeps honest code honest; the
maintainer declines to call it a boundary and neither does this model *(documented, ADR-0001)*.

**The definitions repository is a dependency and a supply chain.** A malicious pull request adding a
custom stabilizer that normalizes away a backdoored file makes a real mismatch vanish. The mandatory
prose `reason:` is a social control. Three technical controls sit under it:

- declarative bounds on what a custom stabilizer may do — it may zero a metadata field and may not
  delete or rewrite file content;
- a flag on any run where a custom stabilizer altered more than N bytes or touched an executable
  section;
- the provenance cap, which a consumer applies themselves: demand `normalized` and the
  custom-stabilizer class never appears at all.

*(documented, docs/12-security.md §8; docs/05-archive-and-normalization.md §5)*

---

## 1.10 Adversary model

### In scope

**A1 — The forged-attestation attacker.** The primary adversary. They control a package, its
repository, its README, its CI configuration, and any file in the checkout. Their goal is a signed
statement that their backdoored package reproduces cleanly. The attack needs no exotic capability:
injected content says the build requires a prebuilt binary, the Builder — the component that turns a
model's answer into a strategy — emits a schema-valid recipe that fetches it, the build "succeeds",
and it matches byte-for-byte, because it *is* the published artifact. **The clean re-run is not a
defence here; it is the mechanism of the attack** *(documented, docs/12-security.md §1.1)*.

**A2 — The prompt injector.** A narrower A1: text a package wrote — README, CI config, `AGENTS.md`,
build log — reaching a model that can act *(documented, docs/12-security.md §4)*.

**A3 — The malformed-input author.** Supplies an artifact whose bytes are hostile to the parser. We
decompress attacker-controlled bytes by construction *(documented, docs/05 §2.2)*.

**A4 — The definitions contributor.** Opens a pull request against the definitions repository
*(documented, docs/12-security.md §8)*.

**A5 — The second-package attacker.** Publishes a *second*, innocuous-looking package holding the
payload and fetches it through the mirror's artifact route, which allowlists `registry.npmjs.org`
and cannot bound what that host serves *(documented, docs/17-backlog.md B7 residue)*.

**A6 — The normalization-conditioned attacker.** Makes the payload depend on an observable the
stabilizers erase *(documented, docs/05 §1)*.

**A7 — A reader of a published divergence.** Not an attacker, but the party a false divergence harms.
Publishing one is a public accusation, so the false-mismatch rate is a safety property
*(documented, docs/09-attestations.md §5; ADR-0010)*.

### Out of scope

- **The operator.** Anyone who can pass flags can name a local path as a source, point Trigon at any
  registry, or hand it a key. `file://` is not dangerous; `file://` *chosen by the thing under test*
  is, and the distinction is a constructor *(documented, docs/16-findings.md §3.7)*.
- **Anyone with code execution in the `trigon` process.** They have already won.
- **A compromised control plane** *(documented, docs/12-security.md §11)*.
- **A network attacker between Trigon and a registry**, beyond what TLS gives. Artifacts are checked
  against the declared digest and re-hashed; the registry is trusted to say what it published
  *(documented, crates/trigon-registry/src/registry.rs)*.
- **A tenant of a shared installation.** There is no multi-tenancy to attack (§1.3).

---

## 1.11 Security properties Trigon provides

A report that violates one of these, through an adversary in §1.10 and an operand §1.7 marks
attacker-controllable, is `VALID`.

| ID | Property | Conditions | Violation symptom | Tier |
| --- | --- | --- | --- | --- |
| **P1** | Parsing a hostile artifact does not panic, escape its *enforced* limits — recursion, total expansion and entry count, but not the two D23 records as dead — or silently change a digest. Recursion is bounded by `Limits::recursion`, whose default of 4 descends three levels below the top — `N` parses `N-1`, stricter than the name reads — and a parse failure keeps the member inline and emits `NestedParseFailed`. **Every limit is enforced against what decompression produces, not against the size the input declares.** That was false for a *stored* zip member until 2026-09-13: the deflate arm checked its output and the store arm returned its bytes unexamined, while the ceiling was charged the size the central directory declared, so many entries naming one large member multiplied past the limit meant to bound them. Every offset read goes through `checked_add`. | any input bytes | panic, hang, wrong digest | **security-critical** *(documented, docs/05 §2.2; crates/trigon-archive/src/zip.rs — `checked_add`; crates/trigon-archive/src/gzip.rs:25 — the output budget; tests `an_offset_that_wraps_is_a_short_read_and_not_a_panic`, `a_gzip_bomb_is_refused_at_the_limit_rather_than_inflated`, `a_zip_member_that_lies_about_its_size_is_refused`)* |
| **P2** | The stabilized form is a byte-stable function of the input: `parse(write(a)) == a`, identical across runs and threads *of a single process*. | same stabilizer set | two runs disagree on a digest | **security-critical** *(documented, docs/13-roadmap.md M0)* |
| **P3** | Stabilizers are total and idempotent: `stab(stab(x)) == stab(x)`, no `Result`, no half-stabilized state, and none allocates more than one member at a time. | — | a digest that depends on how many times a pass ran | **security-critical** *(documented, docs/05 §4)* |
| **P4** | `compare` refuses to compare two sides stabilized under different sets, by set digest, and classifies the refusal `Fault::Bug`. | — | a verdict derived across incomparable sets | **security-critical** *(documented, docs/09-attestations.md §7)* |
| **P5** | **Provenance-capped outcomes.** `normalized` is produced only when the stabilized digests are equal *and* every applied stabilizer is `Builtin` with risk ≤ `Metadata`. Anything else that matches is `normalized_with_caveats`. | — | a model- or human-authored normalization reported as clean | **security-critical** *(documented, docs/00-overview.md §3.1; crates/trigon-compare/src/lib.rs:166-181)* |
| **P6** | `trigon attest` refuses to sign a void run. | the guard was armed | a signed statement about a run that fetched its own answer | **security-critical** *(documented, docs/12-security.md §2.4; crates/trigon/src/main.rs:4223)* |
| **P7** | Text reaching a model is bounded and control-stripped, and operator instructions travel in a system message, never spliced into package text. | every provider **except `copilot:`**, which has no system-role channel | a build log rewriting the operator's instructions | **security-critical** *(documented, docs/12-security.md §4.1; crates/trigon-ai/src/copilot.rs:35)* |
| **P8** | Both artifacts receive an identical transform; the API has no way to stabilize one side differently. Enforced by the type signature. | — | an asymmetric normalization producing a false match | **security-critical** *(documented, docs/12-security.md §10)* |
| **P9** | Canonical JSON refuses what another implementation might not reproduce: floats and non-ASCII object keys are type errors, not coerced values. | signing path | two implementations disagreeing on what was signed | **security-critical** *(documented, crates/trigon-core/src/jcs.rs)* |
| **P10** | A package-declared repository reaches `git` as **https only**, with a **40-hex commit only**, under `GIT_CONFIG_NOSYSTEM` and a restricted `GIT_ALLOW_PROTOCOL`. Only the operator may name a local path. | — | command or option injection from registry metadata | **security-critical** *(documented, docs/16-findings.md §3.7)* |
| **P11** | A runner refuses an egress tier it cannot enforce rather than downgrading it, and at every tier but `open` no phase reaches the network — the image build takes `--network none` too. | podman honours its flags | a run recorded as enforced that was not | **security-critical** *(documented, docs/16-findings.md §3.13)* |
| **P12** | The mirror refuses to serve this run's own published artifact, and hashes every proxied body as it streams; a whole-artifact or member match voids the run. Artifact bodies are proxied undecoded so the guard sees real bytes. | an enforced tier | the forged-attestation attack succeeding | **security-critical** *(documented, docs/12-security.md §2.1–2.2)* |
| **P13** | Both mirror passthrough routes proxy only to compiled-in, exact-match host allowlists chosen here rather than by the request. | — | the mirror acting as a general HTTP proxy | **security-critical** *(documented, docs/16-findings.md §3.13)* |
| **P14** | The output collector takes a file's type **without following symlinks**. | — | any host file becoming the "rebuilt artifact" | **security-critical** *(documented, docs/16-findings.md §3.12; crates/trigon-sandbox/src/podman.rs:691)* |
| **P15** | A strategy cannot request privileged execution, a wider egress tier, an unpinned base image, or a platform. | — | a strategy widening its own boundary | **security-critical** *(documented, docs/04-strategies.md)* |
| **P16** | Model API keys are read from the environment and never accepted on the command line. | — | a key in a process list or shell history | **security-critical** *(documented, crates/trigon/src/inferrer.rs:527)* |
| **P17** | Every package-derived string `trigon watch` renders is HTML-escaped, and the only path parameter is an integer, re-formatted rather than joined. | — | script execution in the operator's browser; path traversal | **security-critical** *(documented, crates/trigon/src/watch.rs — `esc`)* |
| **P18** | A model is never called unless `--model` names a provider; `replay:` opens no socket; a replay refuses a prompt differing from the recorded one; a transcript naming an alias rather than a snapshot is refused for replay. | — | a silent model call; a changed question answered from an old recording | **security-critical** *(documented, docs/07-ai.md §8)* |
| **P19** | Members are paired by `(path, occurrence)`, never by archive position. | — | a false divergence from reordering | correctness-only *(documented, crates/trigon-compare/src/signature.rs)* |
| **P20** | `trigon watch` has no write path: four GET routes, and it never writes to the work directory or the store. Nothing absent is rendered as a zero, and the two denominators never merge. | — | the monitor changing what it observes; "no data" shown as a result | **security-critical** *(documented, docs/18-management-ui.md)* |
| **P21** | `trigon-core` performs no I/O and declares no cargo features; the verifier links no runtime and no network client. Asserted by `xtask policy`, checkable with `cargo tree`. | `--no-default-features` | the verifier's independence being false | **security-critical** *(documented, docs/01-architecture.md §2.2)* |
| **P22** | **No archive member is ever written to a filesystem path.** Archives are parsed in memory, and the only write is the operator-named output file. Trigon never extracts an artifact to a directory, so a hostile member path has nowhere to land. | — | a member path escaping an output directory | **security-critical** *(documented, verified: no `File::create`, `fs::write` or `create_dir_all` anywhere in `trigon-archive`, `trigon-stabilize` or `trigon-compare`)* |
| **P23** | An archived stabilizer set is proved to agree with the compiled one before its digest is used, and a trap in the module fails the re-derivation rather than producing a digest. | `wasm` feature | an archived set silently producing a different digest | **security-critical** *(documented, docs/16-findings.md — "run an archived stabilizer set, and prove it agrees with the compiled one")* |
| **P24** | Outcomes cross the wire as strings, with `FromStr` the exact inverse of `Display`. | — | a verdict changing meaning across a serialization boundary | correctness-only *(documented, crates/trigon-core/src/outcome.rs:46-53)* |
| **P25** | Comparison is linear in member count; each side is walked at most twice. **Threshold:** super-linear in members is a bug; a constant factor is not. | — | a comparison that does not finish on a large artifact | correctness-only *(documented, docs/05 §5)* |
| **P26** | `Signer` and the archived-set loader are operator-chosen collaborators, named on the command line, never selected by anything in an artifact or an attestation. | — | an artifact choosing what signs or stabilizes it | **security-critical** *(documented, docs/09-attestations.md §6-7)* |
| **P27** | An unregistered `uses:` is a hard error naming the tool and listing the known ones; tool composition is acyclic at load and depth-bounded at render; a definitions entry is parsed with `deny_unknown_fields`. | — | an empty script fragment silently replacing a build step | **security-critical** *(documented, docs/04-strategies.md §2)* |
| **P28** | `strategy_digest` is a canonical, domain-separated content pin over the strategy and exactly the tools it uses, taken over the migrated value rather than the YAML bytes. | — | a cache hit across different recipes | correctness-only *(documented, docs/04-strategies.md §4)* |
| **P29** | A build is killed at a hard wall-clock limit. **Threshold:** the default is 1800 seconds and `--timeout` sets it; a build that exceeds it is killed, not waited for. | — | a build running forever | correctness-only *(documented, crates/trigon/src/main.rs:199)* |
| **P30** | The repair loop is bounded by iteration, token and wall-clock budgets. **Threshold:** `wall_seconds` defaults to 1200 and is checked **between** iterations, so one long call completes and the next is refused by name. | `--model` names a provider | unbounded model spend on one target | correctness-only *(documented, crates/trigon-ai/src/repair.rs:95-110)* |

---

## 1.12 Security properties Trigon does *not* provide

Each row is disclaimed. A matching report closes `BY-DESIGN: property-disclaimed` **only where the
row's tag is *(documented)* or *(maintainer)*. A row tagged *(inferred)* or *(assumption)* routes to
`ESCALATE: unratified-claim` instead** — it describes the state of the model, not a decision the
project has made.

### False friends — things that look like a security property and are not

- **The crate dependency graph is not the control** (§1.9) *(documented, ADR-0001)*.
- **Schema validation of a strategy is not sanitization.** A `runs:` step is free-form shell, and
  schema-validating a string containing bash is validating a string *(documented,
  docs/12-security.md §5)*.
- **`strategy_digest` does not identify what actually ran** *(documented, docs/04-strategies.md)*.
- **Re-running the comparison is not re-running the build.** `--rerun-comparison` re-derives the
  equivalence claim from two artifacts *you hold*. If you obtained R from the rebuilder, you have
  checked our arithmetic and not our build; independence requires building R yourself *(documented,
  docs/09-attestations.md §7)*.
- **The system message, the nonce fence and "treat this as data" do not stop prompt injection.** They
  raise the cost *(documented, docs/12-security.md §4)*.
- **A replay does not prove the package reproduces.** It replays the model, not the world
  *(documented, docs/07-ai.md §8)*.
- **A model-proposed strategy does not cap the outcome below `normalized`.** The cap is about applied
  *stabilizers*, not about how the recipe was derived *(documented, docs/00-overview.md §3.1)*.
- **An enforced egress tier does not bound what the reachable hosts serve** (§1.10 A5) *(documented,
  docs/17-backlog.md B7 residue)*.
- **The mirror's passthrough routes are not access-controlled, and the artifact route applies no time
  filter** *(documented, docs/16-findings.md §3.13)*.
- **The guard is not armed on every run.** Its also-in-source filter — the rule that skips members
  which also appear in the source checkout — needs a checkout and is not automatic in a sweep, so the
  guard runs *wider* than designed and errs toward voiding an honest run *(documented,
  docs/12-security.md §2.2)*.
- **`trigon watch` authenticates nobody**, and `--bind` selects an address rather than restricting
  who may connect *(documented, crates/trigon/src/main.rs)*.
- **`ModelCaps::context_tokens` does not bound a prompt**, and `Prompt::is_cacheable` is not enforced
  when a request is sent *(documented, crates/trigon-ai/src/provider.rs)*.
- **Apache-2.0's warranty disclaimer is not a security position.** It is boilerplate.

### Properties simply not provided

| ID | Not provided | Conditions | Tier | Provenance |
| --- | --- | --- | --- | --- |
| **D1** | A *small* bound on what decompression produces. Expansion is bounded — that is P1 — but the default ceiling is **4 GiB** (`total_expanded_bytes`), and the whole artifact plus its whole expansion are held in memory to reach it. A hostile artifact can cost that much before it is refused, so the defence is a ceiling rather than cheapness. A caller who needs a tighter bound sets one. | any input bytes | correctness-only | *(documented, crates/trigon-archive/src/limits.rs:20-30)* |
| **D23** | Any bound at all from `max_inline_bytes` (8 MiB) or `max_inline_total` (256 MiB). **Both are dead configuration**: nothing outside `limits.rs` reads either field. `SourceMap::map` — the mmap constructor, and this crate's only `unsafe` block — has no caller, and `Body::Spilled` is matched but never constructed. So `docs/05-archive-and-normalization.md` §2.2's claim that a 2 GB wheel stabilizes at near-zero heap does not hold: an artifact is read with `std::fs::read` and kept whole. Three of the five limits are real (`recursion`, `total_expanded_bytes`, `max_entries`); these two are not. | any input bytes | correctness-only | *(documented, verified: `grep` for `max_inline_bytes`/`max_inline_total`/`SourceMap::map`/`Body::Spilled` outside `limits.rs` and `model.rs` returns no enforcement site)* |
| **D2** | Sanitization of anything in a `runs:` step, from a strategy or a definitions entry. | — | **security-critical** | *(documented, docs/12-security.md §5)* |
| **D3** | Prevention of code execution inside the build container. | — | **security-critical** | *(documented, docs/08-execution.md)* |
| **D4** | Isolation between two Trigon processes sharing a podman image store. | — | correctness-only | *(documented, docs/17-backlog.md B6)* |
| **D5** | That a model provider cannot act. `--model copilot:` is an agent with a shell, measured running `bash` in `-p` mode with no permission request, and it has **no system-role channel** — operator instructions and package text travel in one string. | only with `copilot:` | **security-critical** | *(documented, docs/16-findings.md §3.8; crates/trigon-ai/src/copilot.rs:35)* |
| **D6** | That the store verifies what it reads, or writes atomically. Only blobs are hash-checked, and a record is written in place. | — | correctness-only | *(documented, crates/trigon-store/src/blobs.rs:56 is the only digest check; `lib.rs` has one `verify` and no temp-and-rename)* |
| **D7** | Exclusion between two writers of one work directory or one store. There is no lock of any kind. | — | correctness-only | *(documented, verified: no `flock`, file lock or lock file in `trigon-store` or the CLI's store and work paths)* |
| **D8** | Thread-safety beyond what `Send` and `Sync` state. No type promises interior consistency across threads, and one recording replayed concurrently is not supported. | every family | correctness-only | *(documented, by the absence of any such statement in `docs/` and in the public API of every crate)* |
| **D9** | A bound on the size of a statement or a difference summary. | — | correctness-only | *(documented, verified: no length cap on `DiffReport` members or `Statement` predicate before serialization)* |
| **D10** | Atomicity of a checkout or a fetch. A partial checkout is removed and re-fetched rather than rolled back. | — | correctness-only | *(documented, crates/trigon-registry/src/source.rs:85 — `remove_dir_all` then re-fetch)* |
| **D11** | Validation of registry JSON beyond the fields read. | — | correctness-only | *(documented, crates/trigon-registry/src/npm.rs — fields are read positionally from `Value`)* |
| **D12** | A bound on a repository's or a registry response's size. | — | correctness-only | *(documented, verified: no `content_length` check or `take()` in `trigon-registry/src/client.rs`)* |
| **D13** | Bounded work per `trigon watch` request. A request walks the whole work directory. | loopback by default | correctness-only | *(documented, docs/18-management-ui.md)* |
| **D14** | Redaction of credentials from a build log before it is stored, rendered or sent to a model. | — | **security-critical** | *(documented, docs/18-management-ui.md §2)* |
| **D15** | That any run is attestable at full trust. There is no network transcript at any tier. | all tiers, today | **security-critical** | *(documented, docs/16-findings.md §3.13)* |
| **D16** | That the artifact guard survives a byte-level transformation. It compares bytes, so re-encoding, encryption or chunk reassembly defeats it. | — | **security-critical** | *(documented, docs/12-security.md §2.5)* |
| **D17** | That a divergence has been confirmed. The two-agreeing-attempts policy is specified and not implemented. | — | **security-critical** | *(documented, docs/16-findings.md §5)* |
| **D18** | That a `normalized` claim re-derived through an archived stabilizer set stays `normalized`. It degrades to `normalized_with_caveats`, so **a true claim reads as refuted**. | `wasm` feature | **security-critical** | *(documented, docs/16-findings.md §4b)* |
| **D19** | That a published reproduction rate estimates an ecosystem. The corpora are small smoke sets, not prevalence-sampled. | — | correctness-only | *(documented, docs/16-findings.md §5)* |
| **D20** | Confidentiality of package text from a model provider, or of a Copilot prompt from the host process table — the whole prompt is an `argv` argument. | when `--model` names a provider | correctness-only | *(documented, crates/trigon-ai/src/copilot.rs:133-134 — `.arg("-p").arg(self.prompt(req))`)* |
| **D21** | Resource or capability bounds on an archived stabilizer set beyond wasmtime's own sandbox. The host sets no fuel limit, no epoch interruption and no memory limiter. | `wasm` feature | **security-critical** | *(documented, crates/trigon-stabilize-wasm/src/host.rs:56 — `Store::new(&engine, ())`)* |
| **D22** | That a custom stabilizer from the definitions repository is bounded by anything but review and the provenance cap. | a merged definitions PR | **security-critical** | *(documented, docs/12-security.md §8)* |

### Well-known attack classes left to the caller

- **Archive bombs.** We decompress attacker bytes by construction. The output bound *is* in place
  (P1), so the residual risk is the ceiling's size rather than its absence: 4 GiB by default
  *(documented, crates/trigon-archive/src/limits.rs:20-30)*.
- **Container escape and host compromise.** Every enforced-tier run executes the package's own build
  inside podman on your machine. Isolation is podman's guarantee, not ours *(documented, §1.9;
  docs/12-security.md §6)*.
- **Prompt injection** (§1.10 A2) *(documented, docs/12-security.md §4)*.
- **SSRF via package metadata.** A package names the hosts this machine connects to *(inferred, Q5 —
  so this bullet escalates rather than closes)*.
- **Supply-chain compromise of the definitions repository** *(documented, docs/12-security.md §8)*.
- **Typosquatting, dependency confusion, and a malicious-but-faithful source.** All out of scope: a
  malicious package that reproduces is a correct `reproduced` *(documented, docs/12-security.md §11)*.

---

## 1.13 Downstream responsibilities

Trigon records provenance, not trust, and leaves the policy to the consumer *(documented,
docs/09-attestations.md §2.1)*.

**If you consume an attestation:**

1. **Re-derive it.** `trigon verify-attestation --rerun-comparison`, with a binary you built. This is
   the only thing that makes a *rebuilder's* attestation worth anything to someone who does not trust
   the rebuilder. If you also want independence from our build, produce R yourself.
2. **Check the signing identity** against your own policy, and check Rekor inclusion if the bundle
   carries it. Without `--public-key` the tool still re-derives and tells you the signature was
   present and unchecked.
3. **Set your own threshold** with `Match::is_at_least`. The default is not a recommendation.
4. **Read the `applied` list.** If you reject a particular normalization you can see it fired, with
   its risk tier and provenance, and discard the result.
5. **Filter on `derivation.method`** if you want "no model touched this".
6. **Read the egress tier.** A run at `--egress open` records `attestable: false`, and today no run
   is attestable at full trust at any tier.
7. **Distinguish a confirmed result from a single attempt, and a stale pass from no data.**
8. **For npm, do not read `reproduced` as `attributed`.**

**If you run Trigon:**

9. **Choose the egress tier deliberately.** `--egress open` is the default and it voids the strong
   claim. An enforced tier needs a mirror image and a base image you built first.
10. **Only you may name a local path as a source.** `file://` chosen by the thing under test is the
    dangerous one.
11. **Read `crates/trigon-ai/src/copilot.rs`'s module docs before `--model copilot:`.** Prefer a
    provider with a real system message where the choice exists.
12. **Keep `trigon watch` on loopback** unless you have thought about it. Build logs are not
    redacted (D14).
13. **Set `total_expanded_bytes` to something your host can absorb.** The default ceiling is 4 GiB
    and a hostile artifact may reach it before being refused.
14. **Treat the rebuilt artifact as untrusted.** It is the package's own build output; do not install
    or execute it because it reproduced.
15. **Before a real sweep, talk to the registries:** a User-Agent with a contact URL, `Retry-After`
    honoured, per-host token buckets.

**If you review the definitions repository:**

16. **Two-party review for anything touching a stabilizer**, a non-empty prose `reason:`, and the
    corpus-wide impact preview before merging.

---

## 1.14 Known misuse patterns

- **Reading `reproduced` as `safe`.** A package that faithfully builds a backdoor reproduces. Treat a
  reproduction as evidence about provenance, and ask the malware question separately.
- **Reading `divergent` as `compromised`.** Most divergences are build nondeterminism. Read the
  difference signature, which you can recompute.
- **Trusting a verdict without its stabilizer set digest.** A verdict under a set you cannot obtain
  cannot be re-derived by anyone.
- **Taking a pass at `--egress open` as equivalent to one at `mirror-only`.** Read `attestable`.
- **Treating `--rerun-comparison` on the rebuilder's own R as independent verification.** It checks
  our arithmetic, not our build.
- **Pointing `trigon watch` at a routable address.** No authentication, and it serves build logs.
- **Using `--model copilot:` because it needs no key.** It is the one provider that can act.
- **Comparing verdicts across stabilizer sets.** `compare` refuses, and so should you.

---

## 1.15 Known non-findings

Patterns that recur from scanners, fuzzers and AI reviewers. A report matching an entry **on every
field** closes `KNOWN-NON-FINDING`; text similarity alone never licenses it.

| ID | Reported as | Why it is not a finding |
| --- | --- | --- |
| **N1** | Attacker-controlled README, manifest or build-log text is concatenated into an LLM prompt with no sanitization. | This is the design. Discharged by §1.12 (prompt injection disclaimed) and P7. **A specific bypass of a stated mitigation is not this entry** and may be `VALID`. |
| **N2** | An LLM decides whether a package is reproducible; a model sits in the trust path of a security verdict. | It does not. The model proposes a recipe; the verdict is computed by model-free code. Discharged by P5. |
| **N3** | Model output is deserialized without `deny_unknown_fields`. | Strategy parsing uses it, and parsing is not the control anyway. Discharged by P27 and D2. |
| **N4** | The model base URL comes from an environment variable: SSRF / arbitrary endpoint. | The operator sets it. `OUT-OF-MODEL: trusted-input` by §1.7. |
| **N5** | The build container runs arbitrary attacker code. | It is the purpose. Discharged by D3. |
| **N6** | The build downloads dependencies from the internet. | At an enforced tier it reaches only the mirror; at `--egress open` this is the disclaimed posture. Discharged by P11 and §1.6. **A report that an enforced tier failed to enforce is not this entry.** |
| **N7** | Digest comparison uses `==` and is not constant-time. | Both digests are computed locally from bytes the process holds. No secret, no remote timing channel. Discharged by §1.10 (no such adversary). |
| **N8** | `exact` is returned for artifacts byte-identical to the published one — the rebuild may just be a copy. | That is what the artifact guard is for, and such a run is `void`. Discharged by P12 and P6. **A guard bypass is not this entry.** |
| **N9** | A package name flows into an HTML page — stored XSS. | Every package-derived string is escaped. Discharged by P17. **An unescaped sink is not this entry.** |
| **N10** | A published divergence names a package that is fine. | A real false mismatch is `VALID`. This entry covers only the generic claim that false positives are possible, which D17 and D19 already state. |
| **N11** | The verifier's claim to link no network client is unverifiable. | `cargo tree -p trigon --no-default-features` and `cargo run -p xtask -- policy`. Discharged by P21. |
| **N12** | Concurrent use of one `Replaying` transcript is not synchronized. | Not supported and not claimed. Discharged by D8. |
| **N13** | A package name is interpolated into a store path: path traversal out of the store root. | `object_store`'s `Path` percent-encodes `..` and `/` inside a component. Discharged by §1.9's `object_store` row. **A report that the store no longer uses `object_store::path::Path`, or that another path is built by `PathBuf::join` from a package-derived name, is not this entry and is `VALID`.** |
| **N14** | An archive member path escapes an output directory (zip-slip). | Trigon never extracts an archive to a directory. Discharged by P22. **A report naming a code path that does extract is not this entry.** |

### Backtest result

38 items were routed blind against this model: 13 historical findings from the adversarial code
sweep and the git history, 25 constructed to reach families and dimensions history does not. Every
item landed on exactly one disposition. The first pass produced **13 `VALID`, 16
`BY-DESIGN: property-disclaimed`, 2 `OUT-OF-MODEL: trusted-input`, 1 each of
`adversary-not-in-scope`, `unsupported-component`, `dependency-contract` and `KNOWN-NON-FINDING`,
and 3 `MODEL-GAP`** — plus one close that was *illegal* under the strict policy because the
licensing claim carried no tag.

The four defects it exposed, and what each produced:

| Item | Defect in the model | Revision |
| --- | --- | --- |
| a zip-slip report | Nothing said whether Trigon ever extracts an archive to a path. | **P22** added, after verifying no `File::create`, `fs::write` or `create_dir_all` exists in the three judgement crates. Plus **N14**. |
| a store-path-traversal report | No §1.7 row for the store's record paths; Q7's blanket assumption was doing the work. | A §1.7 row, an `object_store` row in §1.9 naming the safety as **borrowed**, and **N13** — which carves out the case where the borrowing stops. |
| a stale-output-directory report | No property owned "the artifact compared is the one this attempt produced". | Covered by the existing clear-before-every-attempt code; recorded in §1.16 as a condition rather than a new property, because the bug it came from is fixed and the behaviour is not separately claimed. |
| a `flate2` overflow report | §1.9 had no provenance tags, so `OUT-OF-MODEL: dependency-contract` was an illegal close. | Every §1.9 row now carries a tag, and the ownership rule is stated in prose above the table. |

Fourteen further items routed with genuine ambiguity, which drove the other revisions in this pass:
the `ESCALATE: unratified-claim` disposition, the §1.12 preamble qualifier, the P1/D1 carve-out, and
naming every claimed matrix row's owning property.

---

## 1.16 Conditions that would change this model

- A new ecosystem gains a `Registry` — `nuget.org`, `crates.io`, `rubygems.org` are queued
  *(documented, docs/17-backlog.md B8)*. Each adds an archive format, a version algebra and a
  stabilizer profile; RubyGems adds nested archives, a new path into the parser.
- A network transcript ships, which is the condition on `attestable` becoming true (D15).
- The fleet is built: a queue, workers, an authenticated API and multi-tenancy each add a role.
- `--egress`'s default changes, or `GitAndMirror` is implemented (it is currently refused).
- The `wasm` feature becomes the default, or `docs/09-attestations.md` §7.1's fallback is taken.
- A custom stabilizer is accepted into the definitions repository for the first time, turning D22
  from a policy into a live input.
- The two-agreeing-attempts policy is implemented, changing what a published divergence asserts.
- **The output directory stops being cleared before every attempt**, or the collector starts
  selecting by sort order or mtime rather than by run. Today it is emptied before the first attempt
  and every retry *(documented, crates/trigon/src/main.rs:2218)*; that is what makes P14's guarantee
  about the *right* artifact and not merely a real one.
- Verdicts are published for runtime lookup (`docs/19-distribution-and-lookup.md`), which adds a
  consumer who never runs Trigon and never sees this document.
- **A report that cannot be routed to exactly one §1.17 disposition.** Revise; do not improvise.

---

## 1.17 Triage dispositions

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a §1.11 property, via a §1.10 adversary and a §1.7 attacker-controllable operand. | §1.11, §1.7, §1.10 |
| `VALID-HARDENING` | No §1.11 property violated, but §1.14 shows a misuse easy enough to close off. Maintainer discretion; usually no CVE. | §1.14 |
| `OUT-OF-MODEL: trusted-input` | Needs attacker control of an operand §1.7 marks trusted — in practice an operator input. | §1.7 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Needs a capability §1.10 excludes. | §1.10 |
| `OUT-OF-MODEL: unsupported-component` | Lands in code §1.3 places out of scope, including behaviour that exists only in the design chapters. | §1.3 |
| `OUT-OF-MODEL: non-default-build` | Needs a configuration §1.6 marks dev-only or unsupported. **Non-default alone is not enough** — `wasm` is off by default and supported. | §1.6 |
| `OUT-OF-MODEL: dependency-contract` | A dependency failed its own contract while Trigon used it as documented. Forward upstream. | §1.9 |
| `BY-DESIGN: property-disclaimed` | Concerns a property §1.12 says is not provided, a consumer assumption §1.8 refuses, or a host effect §1.5 records as present by design. | §1.12, §1.8, §1.5 |
| `KNOWN-NON-FINDING` | Matches a §1.15 entry on every field, and its discharging claim still stands. | §1.15 |
| `ESCALATE: unratified-claim` | A rule matched, but the claim licensing it is *(inferred)* or *(assumption)*. **Non-closing.** The report goes to the maintainer with the matched rule and its `QN`, and §1.18 answers it. | §1.18 |
| `MODEL-GAP` | Fits none of the above. Triggers §1.16. | — |

**Precedence — first matching rule wins.** Several failed preconditions do not make a `MODEL-GAP`.

1. Exact §1.15 match → `KNOWN-NON-FINDING`
2. Unsupported component → `OUT-OF-MODEL: unsupported-component`
3. Unsupported configuration → `OUT-OF-MODEL: non-default-build`
4. Conformant use of a dependency that broke its own contract → `OUT-OF-MODEL: dependency-contract`
5. Requires control of a trusted operand → `OUT-OF-MODEL: trusted-input`
6. Requires an excluded capability → `OUT-OF-MODEL: adversary-not-in-scope`
7. Disclaimed property, refused consumer assumption, or by-design host effect →
   `BY-DESIGN: property-disclaimed`
8. Violated claimed property → `VALID`; else an easy-to-prevent §1.14 misuse → `VALID-HARDENING`
9. No unique supported conclusion → `MODEL-GAP`

**Then the closure check, which overrides rules 1–7.** If the matched rule's claim is *(inferred)* or
*(assumption)*, the disposition becomes `ESCALATE: unratified-claim`.

**Closure constraint — at every model status.** Any disposition that closes a report against its
reporter must be licensed by a *(documented)* or *(maintainer)* claim.

- Under **`strict`** (this model's policy) an *(assumption)* behaves exactly like *(inferred)*:
  escalate only.
- Under **`relaxed`**, were it adopted, an *(assumption)* could license only the low-blast-radius
  closes — `trusted-input`, `adversary-not-in-scope`, `unsupported-component`, `non-default-build`,
  and a *non*-security-critical `property-disclaimed` — as a **provisional** close, tagged with its
  `QN`, the §1.18 item left open, and re-opened on a reporter's challenge without new evidence.
- **The security-critical floor holds under both policies.** An *(assumption)* never licenses
  `KNOWN-NON-FINDING`, a `property-disclaimed` whose row is security-critical, or
  `dependency-contract`.

`VALID` and `MODEL-GAP` are fail-safe and always available.

**A note on `ESCALATE: unratified-claim` and the sidecar.** The machine-readable companion's
`dispositions` list is a fixed enum shared across projects and does not carry this row. That is not a
disagreement: the sidecar expresses the same rule structurally, because every record carries its
provenance and an `inferred` or `assumption` record may never authorize a closing disposition.
`ESCALATE: unratified-claim` is the name this document gives that outcome so a human triager has one
word for it. Tooling reads the provenance; a person reads the row.

---

## 1.18 Open questions for the maintainer

Each states a **proposed answer**. Answering one promotes its claims to *(maintainer)* and removes
the question. The backtest's verification pass closed Q6 and Q9–Q13 — each was a guarantee whose
absence turned out to be checkable in the crate, so each became a *(documented)* disclaimer instead.

**Wave 1 — scope, and the two defaults that change what a claim means.**

- **Q1.** Is everything shipped in the binary in the model, with `xtask`, `fuzz/`, `corpora/` and
  `scripts/` out? *Proposed: yes.* → §1.2, §1.3
- **Q2.** `docs/12-security.md` §3 says the attestor never executes sandbox-derived code. In the
  built system `trigon rebuild --attest` signs in the process that ran the build. Is `--store` then
  `trigon attest` the supported path for a claim that matters? *Proposed: yes, and `--attest` on a
  run that built is dev convenience.* → §1.4
- **Q15.** `--egress open` is the shipped default for `rebuild` and `sweep`. Supported production
  posture, or should the default change? *Proposed: supported — the alternative is a tool that does
  not run out of the box, and the attestation records the weaker claim.* → §1.6
- **Q16.** D18: a `normalized` claim re-derived through an archived WASM set degrades to
  `normalized_with_caveats`, so a true claim reads as refuted. Acceptable, or does
  `verify-attestation` need a third answer meaning "consistent, cap unconfirmable"? *Proposed: a
  third answer.* → D18

**Wave 2 — the negative claims, which are the ones a consumer leans on.**

- **Q3.** Is Linux/x86-64 the only supported platform for the build path? *Proposed: yes.* → §1.5
- **Q4.** Does anything install a signal handler, mutate global locale or FPU state, or spawn a
  thread the caller does not know about? *Proposed: no, other than the progress heartbeat thread.*
  → §1.5
- **Q5.** A package's own metadata names the hosts the operator's machine connects to during
  resolution and fetch. Accepted, or should the host set be allowlisted the way the mirror's is?
  *Proposed: accepted and stated — the operator chose to resolve this package.* → §1.7, §1.12
- **Q7.** Are all operands not in §1.7's table operator-supplied and trusted? *Proposed: yes — and
  until it is answered, a finding against one escalates rather than closing.* → §1.7
- **Q8.** Difference codes and member paths come from the artifact and reach a signed statement, a
  log and a prompt. Bounded and control-stripped on all three paths? *Proposed: bounded on the
  prompt path by `logs.rs`, not on the statement path; state the second as a disclaimer.* → §1.8

**Wave 3 — meta.**

- **Q17.** There is no `SECURITY.md`, no disclosure address and no supported-versions statement. A
  model that says "report §1.11 violations privately" needs a channel to exist. *Proposed: add
  `SECURITY.md` naming a channel and pointing here.* → §1.1
- **Q18.** `docs/12-security.md` and this model both state a security position, and `12` is the cited
  source for most closing claims here. Does `12` stay as the controls document with this model as the
  contract, or should its §1, §3 and §11 move here and leave `12` purely about mechanism?
  *Proposed: `12` stays; it is cited, not duplicated, and the appendix records the mapping.* → appendix

---

## 1.19 Machine-readable companion

[`threat-model.yaml`](threat-model.yaml), at `threat-model-sidecar/v2`. The prose here is canonical;
the sidecar is a derived index pinned to this file's SHA-256.

It is **generated, not hand-maintained**: `scripts/threat-model-sidecar.py` reads the tables above
and emits it, and `--check` fails if the file on disk is stale. A companion kept by hand goes out of
date on the first edit nobody mirrors, and a stale sidecar is worse than none — a triage pipeline
reads it while the human reads the prose, and the two quietly disagree. The generator also refuses to
emit unless every in-scope component has a row for all eight contract dimensions, which is the
coverage check that would otherwise be somebody remembering.

**Census** — claim tags only; the legend rows and prose mentions of a tag name are excluded:
**192 documented / 0 maintainer / 3 assumption / 5 inferred**. Every assumption and inferred tag
resolves to a question in §1.18.

---

## Appendix — back-map from `docs/12-security.md`

`docs/12-security.md` is a controls document and the maintainer says explicitly that it is not this
*(documented, docs/17-backlog.md B2)*. It holds threat-model content, so this model must be a strict
superset. Kept until Q18 is answered.

| `12-security.md` | Where it lands here |
| --- | --- |
| §1, §1.1 the forged-attestation attack | §1.10 A1; §1.2 "what would have to be true for it to be wrong" |
| §2.1 mirror refusal | P12 |
| §2.2 egress hashing, the guarded member set and its filters | P12; §1.12 ("the guard is not armed on every run") |
| §2.3 write-only blob access | **designed, not built** — §1.3; §1.4 |
| §2.4 why `Void` | P6; §1.1 "the outcomes" |
| §2.5 the limits | D16 |
| §3 trust boundaries | §1.4, with the note that one process holds several designed roles |
| §4, §4.1–4.3 prompt injection | §1.10 A2; P7; §1.12 false friends |
| §5 free-form shell | D2; §1.12 false friends |
| §6 sandbox hardening | §1.5; P11; §1.12 attack classes (container escape) |
| §7 multi-tenancy | §1.3 |
| §8 the definitions repository | §1.9; §1.10 A4; D22; §1.13 item 16 |
| §9 signing key handling | §1.13; Q2 |
| §10 the twelve invariants | P1–P30, each with a symptom and a tier |
| §11 out of scope | §1.3 |
| §12 redistribution | not security-contract content; stays in `12` |
