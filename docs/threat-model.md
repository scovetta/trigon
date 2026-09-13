# Trigon threat model

**Project:** Trigon — semantic rebuild verification for open-source packages
**Version binding:** `ad422a8`, 2026-09-13. A report against a given commit is triaged against the
model as it stood at that commit, not against `main`.
**Status:** unratified draft. No maintainer has reviewed it.
**Triage policy:** `strict`.
**Author:** generated from the repository and its design chapters; see §1.18 for what is unratified.

**Provenance legend.** Every non-trivial claim below carries exactly one tag.

| Tag | Meaning |
| --- | --- |
| *(documented, source)* | Stated in a maintainer-authored source in this repository. The source is named. |
| *(maintainer, YYYY-MM)* | Stated by a maintainer in answer to a question from this process. None yet. |
| *(assumption, QN)* | A conservative default this document commits to where the sources are silent. `QN` is an open question in §1.18. |
| *(inferred, QN)* | Reasoned from code structure, with no default committed. Genuinely open. `QN` is in §1.18. |

**What a tag is allowed to do.** Under `strict`, only a *(documented)* or *(maintainer)* claim can
close a report against its reporter. An *(inferred)* or *(assumption)* claim can escalate a report to
the maintainer and can never close one. `VALID` and `MODEL-GAP` are always available.

**Reporting.** A finding that violates a property in §1.11 goes to the project's disclosure channel.
A finding that lands in §1.3 or §1.12 is closed citing this document.

**Draft confidence:** 144 documented / 0 maintainer / 5 assumption / 13 inferred. Every inferred and
assumption tag resolves to a question in §1.18. The high documented count is not a sign of maturity —
it reflects eighteen design chapters written by the maintainer, and `docs/16-findings.md` records
where the code has since corrected them.
**Backtest:** 38 items across 33 clusters and 9 component families — 13 historical findings from the
adversarial code sweep and the git history, 25 constructed to cover families and contract dimensions
history does not reach. Result recorded below the table in §1.15's companion note.
**Sibling models:** none. This is the only threat model for this repository. No `SECURITY.md` exists,
so there is no prior policy to absorb and no back-map appendix *(documented, repository: no
`SECURITY.md` at any path)*.

## What Trigon is

Trigon takes a published package — an npm tarball, a Python wheel — and tries to rebuild it from the
source the package points at. It then compares the two artifacts, not byte-for-byte but under a named
set of *stabilizers*: small, ordered, total transforms that erase differences nobody meant to publish,
such as file order inside a tar or an embedded build timestamp. The answer is one of four outcomes,
and where the operator asked for one, a signed in-toto attestation carrying the digests, the recipe,
the environment, and exactly which stabilizers fired.

The product is the attestation. Everything else exists to make it honest.

---

## Triager quick-start

> Given an inbound finding:
>
> 1. **Find the sink.** Look it up in the §1.7 input-trust table. For a "downstream may assume X"
>    finding, use the §1.8 output statement instead.
> 2. **Find the contract dimension.** For state corruption, overflow, recursion, callbacks,
>    serialization, lifecycle, concurrency, or resource use, follow the component's row in the §1.7
>    matrix to the claim that owns it.
> 3. **Check the attacker.** Does the finding need a capability §1.10 grants? Distinguish control of
>    *data* from control of *size*, *a shell script*, *a container image*, or *a model's output*.
> 4. **Check the component.** Is it in §1.2's table, or in §1.3? Does it need a configuration §1.6
>    marks unsupported?
> 5. **Check the layer.** If the root cause is in a dependency behaving as documented, apply §1.9.
> 6. **Apply §1.17's precedence**, starting with an exact §1.15 match.
> 7. **Assign exactly one disposition**, citing the section and its provenance tag. If none fits,
>    assign `MODEL-GAP` and open a §1.16 revision. Do not improvise a disposition.

---

## 1.2 Scope and intended use

### The claim, stated exactly

This is the centre of the model. A signed `trigon.dev/equivalence/v1` predicate says:

> Artifact **P**, as published, and artifact **R**, produced by recipe **S** in environment **E**,
> have stabilized forms that are byte-identical under stabilizer set **T**, whose members and digest
> are named in the statement, and of which exactly these fired, at these risk tiers, with these
> provenances.

Every noun in that sentence is deterministic. A third party holding P, R and the attestation can
re-derive the whole of it with `trigon verify-attestation --rerun-comparison` and a binary that
contains no network client and no model code *(documented, docs/09-attestations.md §7;
README.md "The two halves")*.

**What it does not say**, and what a reader must not read into it:

- **Not that the package is safe.** A package that builds faithfully from a repository containing a
  backdoor reproduces, and should *(documented, docs/12-security.md §11)*.
- **Not that the source is the source.** The equivalence claim is about two files. Whether the
  repository it built from is the one the package's users think of as its source is a separate
  question, and for npm it is the *only* interesting question — npm packages are close to 100%
  reproducible at the tarball level with no source linkage at all *(documented,
  docs/03-ecosystems.md §0)*.
- **Not that a model was absent.** Model involvement is recorded beside the claim as
  `derivation.method`, never inside it. A consumer who wants "no model touched this" has to filter on
  that field themselves *(documented, docs/09-attestations.md §2.1)*.
- **Not that the build was observed.** No run at any tier is attestable at full trust today, because
  there is still no network transcript *(documented, docs/16-findings.md §3.13; docs/17-backlog.md
  B7)*.

**What would have to be true for the claim to be wrong.** Exactly one of these:

1. The rebuild obtained P, or a member of P, rather than building it — the forged-attestation attack
   *(documented, docs/12-security.md §1.1)*. The artifact guard is the control, and it compares
   bytes, so an attacker who fetches P re-encoded, encrypted, or reassembled from chunks defeats it
   *(documented, docs/12-security.md §2.5)*.
2. A stabilizer erased a real difference. The provenance cap is the control a consumer applies:
   demand `Match::Normalized` and every stabilizer that fired was built in and no riskier than
   metadata *(documented, docs/00-overview.md §3.1)*.
3. Our own serialization stack is wrong in a way that affects both sides. It is self-consistent, so
   our bugs surface as false negatives; over-aggressive membership deletion is the false-positive
   direction *(documented, docs/13-roadmap.md §3)*.
4. The signing identity is not who you think. Checking it is the reader's job, not ours
   *(documented, docs/09-attestations.md §7 steps 2–3)*.

**What the reader is expected to check themselves** is §1.13.

### Deployment and roles

Trigon ships as one binary. Today it runs as a CLI on a workstation or a CI machine; the fleet
deployment described in `docs/10-scale.md` is designed and not built *(documented, docs/README.md
"Status")*.

Two roles, and they own different threats:

| Role | Who | Trusted for |
| --- | --- | --- |
| **Attestation consumer** | Reads a signed predicate and decides whether to trust a package. Holds no Trigon installation necessarily. | Nothing. They are the audience, and the claim must survive their scepticism. |
| **Operator** | Runs `trigon rebuild` / `sweep`. Their machine executes attacker-supplied build scripts. | The invocation, the egress tier, the definitions ref, the signing key. An operator who chooses `--egress open` has chosen a weaker claim and the attestation says so. |

There is no third-party-client role yet: no daemon, no authenticated API, no multi-tenancy
*(documented, docs/12-security.md §7 — "Multi-tenancy is not implemented")*.

### Component families

The verifier — the first five rows — is what a sceptic checks. It is built by
`cargo build -p trigon --no-default-features`, links no async runtime and no network client, and
`cargo run -p xtask -- policy` asserts that mechanically *(documented, README.md "The two halves";
docs/01-architecture.md §2.2)*. Verified for this commit: `cargo tree -p trigon
--no-default-features` names no `tokio`, `reqwest` or `hyper`.

| Family | Entry point | Touches | In model |
| --- | --- | --- | --- |
| `archive-parsing` (`trigon-archive`) | `Archive::read`, the three writers | nothing outside the process, except a spill file above 8 MiB | **in** |
| `stabilization` (`trigon-stabilize`) | `profile(id)`, `StabilizerSet::apply` | nothing | **in** |
| `comparison-and-verdict` (`trigon-compare`, `trigon-core`) | `compare()`, `Match`, PURL parsing | nothing | **in** |
| `attestation` (`trigon-attest`) | statement building, DSSE, `Signer` | reads a key file when signing | **in** |
| `strategy-rendering` (`trigon-strategy`) | `Strategy` parse, flow DSL, minijinja render | nothing; emits a script for someone else to run | **in** |
| `registry-and-source` (`trigon-registry`) | `Registry::resolve`/`fetch`, `SourceCache` | network (registries, git hosts), filesystem, spawns `git` | **in** |
| `build-execution` (`trigon-sandbox`, `trigon-mirror`) | `BuildRunner::start`, the mirror server | spawns `podman`, binds a socket, writes a work directory | **in** |
| `model-inference` (`trigon-ai`) | `Provider::complete`, the Builder, `RepairLoop` | network (model endpoints), spawns `copilot` | **in** |
| `operator-surface` (`trigon` bin, `trigon-store`) | CLI subcommands, `trigon watch`'s HTTP server | everything above, plus a listening socket and a store directory | **in** |
| `archived stabilizer sets` (`trigon-stabilize-wasm`) | `wasm` feature, off by default | runs a WASM module | **in**, see §1.6 |
| the `trigon-definitions` repository | `build.yaml`, custom stabilizers | — | **in as an input**, §1.9 |

Everything in this repository is in the model. There is no `contrib/`, no `examples/` directory of
shipped-but-unsupported code, and no vendored third-party source *(inferred, Q1)*.

---

## 1.3 Out of scope

These are non-goals. A report that depends on one of them closes as
`OUT-OF-MODEL: unsupported-component` or `BY-DESIGN: property-disclaimed`.

- **Malware detection.** Trigon answers whether an artifact matches a source. Whether the source is
  malicious is a different question, and a malicious package that reproduces is a *correct* result
  *(documented, docs/12-security.md §11)*.
- **Judging whether the source is trustworthy** *(documented, docs/12-security.md §11)*.
- **Defending a compromised control plane.** Compromise the scheduler and the attestor and the
  signed output means nothing. `--rerun-comparison` is what limits the damage, because an independent
  party re-derives the equivalence claim without trusting us *(documented, docs/12-security.md §11)*.
- **Bit-for-bit reproducibility as an end.** Semantic verification with named normalizations and
  consumer-set risk thresholds instead *(documented, docs/00-overview.md §4–5)*.
- **Emulating GitHub Actions runners.** Runner images are mutable and unpinnable, so emulating them
  would make our own results unreproducible. We extract intent and lower it to a digest-pinned
  container plan, recorded as an approximation and never as an equality claim *(documented,
  docs/06-ci-awareness.md §2; ADR-0009)*.
- **Replacing trusted publishing.** It is an input and a cross-check, never a conclusion
  *(documented, docs/00-overview.md §5)*.
- **Being a general CI system.** We reconstruct builds for verification, not for release
  *(documented, docs/00-overview.md §5)*.
- **macOS and Windows runners**, and **Maven, Go and Debian**, which report `Unsupported` rather than
  failing *(documented, docs/06-ci-awareness.md §3.3; docs/00-overview.md §5)*.
- **Syscall-level observability.** eBPF and observability tiers 2 and 3 are cut; Tier 1 is the
  network transcript and nothing above it ships *(documented, ADR-0007; docs/08-execution.md §7)*.
- **Multi-tenancy.** The rules are decided and not implemented, so a finding that requires two
  tenants sharing an installation is out of model until they are *(documented,
  docs/12-security.md §7)*.

**Designed but not built.** These are not non-goals; they are unwritten code, and the design chapters
describe them in the present tense. A finding against behaviour that exists only in `docs/` is not a
finding *(documented, docs/README.md "Status" — the design documents "describe the system as intended
rather than as built")*. The largest instances: the fleet (queue, workers, API), the
two-agreeing-attempts confirmation policy *(documented, docs/16-findings.md §5)*, the divergence
publication pipeline, and most of the CLI surface in `docs/11-interfaces.md` §2.

---

## 1.4 Trust boundaries and reachability

`docs/12-security.md` §3 draws the intended worker split. What is *built* is one process, so the
boundaries that hold today are narrower and worth stating separately.

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
  ╔═══════════════════════════════════╗  ── trust boundary ──
  ║ build container (hostile)         ║
  ║  runs the package's own build      ║      egress: at an enforced tier, the
  ║  no signing key, no credentials    ║◄───► mirror only, and nothing else
  ╚═══════════════┬═══════════════════╝
                  │ writes an artifact to a bind-mounted output directory
                  ▼
        comparison, in the trigon process
```

The one boundary that is real and enforced today is the container's: attacker code runs inside it and
the egress tier bounds what it can reach *(documented, docs/08-execution.md §5;
docs/16-findings.md §3.13)*. **The attestor is not a separate process in the built system**, so the
design's "the attestor never executes sandbox-derived code" does not hold as stated for a local
`trigon rebuild --attest`; `trigon attest` against a store is the separable path *(inferred, Q2)*.

**Reachability preconditions.** A finding in a family matters only if it meets that family's
condition. This is the second question a triager asks, after "which sink".

| Family | A finding matters only if it is reachable from… |
| --- | --- |
| `archive-parsing` | the bytes of a published artifact, or of a rebuilt one |
| `stabilization` | an archive already parsed, or a stabilizer set id named in an attestation |
| `comparison-and-verdict` | two summaries produced by this process in one run |
| `attestation` | a statement this process built, or an attestation file handed to `verify-attestation` |
| `strategy-rendering` | a strategy document from the definitions repo, a heuristic, CI parsing, or a model |
| `registry-and-source` | registry metadata, a repository URL a package declares, or a git host's response |
| `build-execution` | a strategy that has been rendered, or bytes crossing the mirror |
| `model-inference` | text a package wrote reaching a prompt, or a provider's response |
| `operator-surface` | a flag the operator passed, a work directory on disk, or an HTTP request to `watch` |

---

## 1.5 Assumptions about the environment

- **Platform.** Linux on x86-64 is what is built and tested. macOS and Windows are not supported
  targets for the build path, which needs `podman` *(assumption, Q3)*.
- **Rust.** MSRV 1.85. `#![forbid(unsafe_code)]` is declared in the judgement half *(documented,
  crates/trigon-core/src/lib.rs)*.
- **Container runtime.** An enforced-tier run needs rootless `podman` on `PATH`, plus a mirror image
  and a base image the operator built beforehand with `trigon mirror-image` and `trigon base-image`
  *(documented, README.md "A note on `--egress open`")*.
- **Clock.** The timewarp mirror filters a registry index to a publish instant taken from registry
  metadata, not from the host clock. Nothing in the judgement half reads a clock *(documented,
  docs/08-execution.md §4; docs/07-ai.md §8 forbids wall-clock reads in prompt construction)*.
- **Concurrency.** Nothing in this project is documented thread-safe beyond what Rust's own `Send`
  and `Sync` bounds state, and no type here promises interior consistency across threads. Callers get
  what the type system gives them and nothing more *(documented, by the absence of any such statement
  in `docs/` and in the public API)*. Two Trigon *processes* on one machine can still disturb each
  other's `podman` image store; this is narrowed, not closed *(documented, docs/17-backlog.md B6)*.

### What Trigon does not do to its host

These are negative claims, and they are the ones an integrator most needs and least often gets. They
are split, because the verifier and the build path are different programs.

**The verifier** (`--no-default-features`: `archive-parsing`, `stabilization`,
`comparison-and-verdict`, `attestation`, `strategy-rendering`):

| Effect | Stance | Conditions |
| --- | --- | --- |
| Network of any kind | **absent** | it links no network client, and `xtask policy` asserts it *(documented, docs/01-architecture.md §2.2)* |
| Child processes | **absent** | *(documented, docs/01-architecture.md §2.2)* |
| Environment variables | **absent** | *(documented, docs/01-architecture.md §2.2)* |
| Filesystem writes | **conditional** | only paths the operator named: the `stabilize` output, the `--attest` file, a spill file above 8 MiB *(documented, docs/05-archive-and-normalization.md §2.2)* |
| Filesystem reads | **conditional** | only paths the operator named, plus a signing key file *(documented)* |
| stdout / stderr | **present** | the verdict on stdout, `tracing` on stderr *(documented)* |
| Signal handlers, global state, locale or FPU mutation | **absent** | *(assumption, Q4)* |
| Executing WebAssembly | **conditional** | only under the non-default `wasm` feature, §1.6 *(documented, docs/09-attestations.md §7.1)* |

**The build path** additionally, and by design:

| Effect | Stance | Conditions |
| --- | --- | --- |
| Outbound HTTPS to registries and git hosts | **present** | resolution, artifact fetch, source checkout *(documented, docs/03-ecosystems.md)* |
| **Outbound HTTPS to any URL registry metadata names** | **present** | a package's own metadata chooses the host the operator's machine connects to *(inferred, Q5)* |
| Spawning `git` | **present** | with `GIT_CONFIG_NOSYSTEM` and a restricted `GIT_ALLOW_PROTOCOL` *(documented, crates/trigon-registry/src/source.rs)* |
| Spawning `podman` | **present** | the build itself *(documented, docs/08-execution.md §1)* |
| Spawning the configured model CLI | **conditional** | only with `--model copilot:…` *(documented, docs/16-findings.md §3.8)* |
| Outbound HTTPS to a model endpoint | **conditional** | only when `--model` names a live provider *(documented, README.md "Asking a model")* |
| Binding a listening socket | **conditional** | `trigon watch` (loopback by default) and the mirror *(documented, crates/trigon/src/main.rs — `--bind` defaults to `127.0.0.1:8099`)* |
| Reading environment variables | **present** | API keys and `OLLAMA_HOST`/`ANTHROPIC_BASE_URL`; **keys come from the environment and never from the command line, so a key does not reach a process list or a shell history** *(documented, crates/trigon/src/inferrer.rs)* |
| Writing a work directory | **present** | fetched artifacts, build logs, rebuilt artifacts *(documented, docs/18-management-ui.md §2)* |

---

## 1.6 Build-time and configuration variants

Two cargo features and one flag change which properties hold. **Support posture, not defaultness,
decides routing**: a defect in a supported configuration is in model even when that configuration is
not the default.

| Knob | Default | Stance | Effect on the model |
| --- | --- | --- | --- |
| `build` feature | **on** | supported | Adds `registry`, `sandbox`, `mirror`, `store`, `ai`, a tokio runtime and a network client. Turning it *off* is the verifier, and is the stronger posture, not a weaker one. |
| `wasm` feature | **off** | supported | Lets the verifier *run* an archived stabilizer set rather than only name it. It roughly doubles the verifier's dependency tree, and the small tree is what a sceptic checks *(documented, crates/trigon/Cargo.toml)*. A claim re-derived through an archived set can reach `NormalizedWithCaveats` and never `Normalized`, because the provenance cap cannot be confirmed from bytes alone — **so a `Normalized` claim re-derived this way reads as refuted when it is not** *(documented, docs/16-findings.md §4b)*. |
| `--egress open` | **the default for `rebuild` and `sweep`** | **supported, and it voids the strong claim** | The build reaches the whole internet. The run records `attestable: false`, and the README says so *(documented, README.md "A note on `--egress open`")*. |
| `local-unsafe` runner | not the default | **dev-only** | Labelled development-only and refuses to sign *(documented, docs/08-execution.md §1)*. A finding that needs it closes `OUT-OF-MODEL: non-default-build`. |

**The insecure default, named.** `--egress open` is the shipped default for the two commands an
operator actually runs. It is a supported production posture in the sense that it is what you get
without thinking, and the project's position is that such a run carries a weaker claim which the
attestation states rather than hides. So a report that a build at `--egress open` fetched something
it should not have is **not** `non-default-build`; it is `BY-DESIGN: property-disclaimed`, discharged
by §1.12's statement that the guard and the egress boundary are not in force at that tier. A report
that the run nevertheless claimed full trust *is* `VALID`. This distinction is the one a triager will
need most often *(documented, README.md; docs/08-execution.md §5)*.

---

## 1.9 Assumptions about dependencies

Trigon is not zero-dependency. The runtime dependencies whose failure would be a security event,
and where such a failure is triaged:

| Dependency | Relied on for | If it fails its own contract |
| --- | --- | --- |
| `podman` (external binary) | process, filesystem and **network** isolation of the build. `--network none` at enforced tiers is a podman guarantee, not ours. | upstream — `OUT-OF-MODEL: dependency-contract` |
| `git` (external binary) | fetching a checkout without honouring attacker-supplied config; we set `GIT_CONFIG_NOSYSTEM` and restrict `GIT_ALLOW_PROTOCOL` | upstream, unless we passed something we should not have, which is ours |
| `flate2` / `miniz_oxide` | correct, bounded inflate of attacker bytes | upstream — but note §1.12: bounding the *output* is ours and is currently unfixed |
| `reqwest` + `rustls` | TLS to registries and model endpoints | upstream |
| `sha2` | collision resistance of SHA-256 | upstream |
| `ed25519-dalek` | signature correctness | upstream |
| `minijinja` | rendering a template without escaping into code paths we did not intend | upstream |
| `wasmtime` (feature `wasm`) | sandboxing an archived stabilizer set | upstream |
| a model provider's API | nothing security-relevant. A model's answer is a *candidate*, validated before use, and capped by §1.11's provenance rule | never closes a report here; a wrong answer is expected input |

**The crate dependency graph is not the security control.** It keeps honest code honest. The
maintainer declines to describe it as a boundary, and this model does not either *(documented,
ADR-0001; docs/00-overview.md §3.1)*. The controls are the provenance cap, the egress boundary, the
artifact guard, and a verifier a third party can build and check.

**The definitions repository is a dependency and a supply chain.** A malicious pull request adding a
custom stabilizer that normalizes away a backdoored file makes a real mismatch vanish. The mandatory
prose `reason:` is a social control; the technical ones are the declarative bounds on what a custom
stabilizer may do, the flag when one alters more than N bytes or touches an executable section, and —
the one a consumer applies themselves — the provenance cap, which means a consumer demanding
`Normalized` never sees the custom-stabilizer class at all *(documented, docs/12-security.md §8)*.

---

## 1.10 Adversary model

### In scope

**A1 — The forged-attestation attacker.** The primary adversary, and the one the design is shaped
around. They control a package, its repository, its README, its CI configuration, and any file in the
checkout. Their goal is a signed statement that their backdoored package reproduces cleanly. The
attack needs no exotic capability: injected content says the build requires a prebuilt binary, the
Builder emits a schema-valid strategy that fetches it, the build "succeeds", and it matches
byte-for-byte — because it *is* the published artifact. **The clean re-run is not a defence here; it
is the mechanism of the attack** *(documented, docs/12-security.md §1.1)*.

**A2 — The prompt injector.** A special case of A1 with a narrower target: text a package wrote —
README, CI config, `AGENTS.md`, build log — reaching a model that can act. Prompt injection is an
accepted and mitigated threat, not a solved one, and the project says so *(documented,
docs/12-security.md §4)*.

**A3 — The malformed-input author.** Supplies a published artifact whose bytes are hostile to the
parser. Trigon decompresses attacker-controlled bytes by construction and there is no zip-bomb
defence to inherit *(documented, docs/05-archive-and-normalization.md §2.2)*.

**A4 — The definitions contributor.** Opens a pull request against the definitions repository
*(documented, docs/12-security.md §8)*.

**A5 — The second-package attacker.** Publishes a *second*, innocuous-looking package holding the
payload, and fetches it through the mirror's artifact route, which allowlists `registry.npmjs.org`
and cannot bound what that host serves *(documented, docs/17-backlog.md B7 residue)*.

**A6 — The normalization-conditioned attacker.** Makes the payload depend on an observable the
stabilizers erase, so the stabilized digests match while the artifacts differ where it counts. Judged
an accepted residual risk, with risk tiers offered to consumers who disagree *(documented,
docs/05-archive-and-normalization.md §1)*.

**A7 — A reader of a published divergence.** Not an attacker on the system, but the party a false
divergence harms. Publishing a divergence is a public accusation about someone else's package, so the
false-mismatch rate is a safety property and not only a quality metric *(documented,
docs/09-attestations.md §5; ADR-0010)*.

### Out of scope

- **The operator.** Anyone who can pass flags to `trigon` can name a local path as a source, point it
  at any registry, or hand it a key. `file://` is not dangerous; `file://` *chosen by the thing under
  test* is, and the distinction is a constructor *(documented, docs/16-findings.md §3.7)*. A report
  that needs operator control of an operator input closes `OUT-OF-MODEL: trusted-input`.
- **Anyone with code execution in the `trigon` process.** They have already won.
- **A compromised control plane** *(documented, docs/12-security.md §11)*.
- **A network attacker between Trigon and a registry**, beyond what TLS gives. Artifacts are verified
  against the digest the registry declared *and* re-hashed, so served bytes are checked; the registry
  itself is trusted to say what it published *(documented, crates/trigon-registry/src/registry.rs)*.
- **A tenant of a shared installation.** There is no multi-tenancy to attack yet (§1.3).

---

## 1.16 Conditions that would change this model

- A new ecosystem gains a `Registry` — `nuget.org`, `crates.io`, `rubygems.org` are queued
  *(documented, docs/17-backlog.md B8)*. Each adds an archive format, a version algebra, and a
  stabilizer profile, and RubyGems adds nested archives, which is a new reachability path into the
  parser.
- A network transcript ships, because it is the condition on `attestable` becoming true at any tier
  *(documented, docs/17-backlog.md B7)*.
- The fleet is built: a queue, workers, an authenticated API, and multi-tenancy each add a role this
  model does not have.
- `--egress`'s default changes, or `GitAndMirror` is implemented (it is currently refused).
- The `wasm` feature becomes the default, or the fallback in `docs/09-attestations.md` §7.1 — naming
  a Trigon release version in every attestation — is taken instead.
- A custom stabilizer is accepted into the definitions repository for the first time, which turns
  §1.9's definitions row from a policy into a live input.
- The two-agreeing-attempts confirmation policy is implemented, which changes what a published
  divergence asserts.
- **A report that cannot be routed to exactly one §1.17 disposition.** That is itself a trigger:
  revise this document rather than make an ad-hoc call.

---

## 1.17 Triage dispositions

The closed set. Assign exactly one.

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a property in §1.11, reachable by an adversary in §1.10 through an input §1.7 marks attacker-controllable. | §1.11, §1.7, §1.10 |
| `VALID-HARDENING` | No §1.11 property is violated, but §1.14 shows the API makes a misuse easy enough to be worth closing off. Maintainer discretion; usually no CVE. | §1.14 |
| `OUT-OF-MODEL: trusted-input` | Needs attacker control of an input §1.7 marks trusted — in practice, an operator input. | §1.7 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Needs a capability §1.10 excludes. | §1.10 |
| `OUT-OF-MODEL: unsupported-component` | Lands in code §1.3 places out of scope, including behaviour that exists only in the design chapters. | §1.3 |
| `OUT-OF-MODEL: non-default-build` | Needs a configuration §1.6 marks dev-only or unsupported. **Non-default alone is not enough** — the `wasm` feature is off by default and supported. | §1.6 |
| `OUT-OF-MODEL: dependency-contract` | Root cause is a dependency failing its own contract while Trigon used it as documented. Forward upstream. | §1.9 |
| `BY-DESIGN: property-disclaimed` | Concerns a property §1.12 says is not provided. | §1.12 |
| `KNOWN-NON-FINDING` | Matches a §1.15 entry on every field, and the claim that discharges it still stands. | §1.15 |
| `MODEL-GAP` | Fits none of the above. Triggers §1.16. | — |

**Precedence — first matching rule wins.** Several failed preconditions do not make a `MODEL-GAP`;
this order resolves them.

1. Exact §1.15 match → `KNOWN-NON-FINDING`
2. Unsupported component → `OUT-OF-MODEL: unsupported-component`
3. Unsupported configuration → `OUT-OF-MODEL: non-default-build`
4. Conformant use of a dependency that broke its own contract → `OUT-OF-MODEL: dependency-contract`
5. Requires control of a trusted input → `OUT-OF-MODEL: trusted-input`
6. Requires an excluded capability → `OUT-OF-MODEL: adversary-not-in-scope`
7. Disclaimed property → `BY-DESIGN: property-disclaimed`
8. Violated claimed property → `VALID`; else an easy-to-prevent §1.14 misuse → `VALID-HARDENING`
9. No unique supported conclusion → `MODEL-GAP`

**Closure constraint.** Any disposition that closes a report against its reporter —
`OUT-OF-MODEL: *`, `BY-DESIGN: *`, `KNOWN-NON-FINDING` — must be licensed by a *(documented)* or
*(maintainer)* claim. Under this model's `strict` policy, an *(inferred)* or *(assumption)* claim can
only escalate the report to the maintainer. `VALID` and `MODEL-GAP` are always available. While any
*(inferred)* or *(assumption)* tag remains, the status stays `unratified draft` rather than
`accepted`.

---

## 1.7 Assumptions about inputs

### Per-operand trust table

One row per operand that an adversary in §1.10 can influence. Operator-supplied operands — a path, a
flag, a key file, a `--model` spec, a definitions ref — are **trusted** throughout and are not
tabled individually; a report that needs operator control of one closes
`OUT-OF-MODEL: trusted-input`.

`Control kind` distinguishes what the attacker holds. `data` and `size` are not the same power, and
`x-shell-script`, `x-model-output` and `x-build-log` are much more power than either.

| Entry point | Operand | Attacker-controllable | Control kind | Caller must enforce | Provenance |
| --- | --- | --- | --- | --- | --- |
| `archive::parse` | artifact bytes | **yes** | data, size, object-topology, serialized-state | nothing — safe parsing is a claimed property, §1.11 P1, **except** the two unfixed limits in §1.12 | *(documented, docs/05-archive-and-normalization.md §2.2)* |
| `archive::serialize` | the parsed archive | **yes** (derived) | data, size, object-topology | nothing — byte-stability is P2 | *(documented, docs/05 §3)* |
| `compare::summarize` | artifact bytes | **yes** | data, size | nothing | *(documented, docs/08-execution.md §6)* |
| `compare::compare` | two `Summary` values | no — produced by this process | serialized-state | both must come from one run; the set-digest check enforces it | *(documented, crates/trigon-compare/src/lib.rs:159)* |
| `core::classify` / `core::compress` | a build log | **yes** | data, size, x-build-log | nothing — bounded and control-stripped, P7 | *(documented, crates/trigon-core/src/logs.rs)* |
| `core::TargetRef::from_str` | a PURL string | operator, usually | data, resource-name | a version is required and a PURL without one is refused | *(documented, crates/trigon-core/src/target.rs:152)* |
| `Registry::resolve` | registry response JSON | **yes** | data, size, serialized-state, object-topology | nothing claimed; shape errors surface as `RegistryError` | *(inferred, Q6)* |
| `Registry::fetch` | `meta.url` | **yes — the package's own metadata chooses the host this machine connects to** | resource-name | **the operator accepts that resolving a package means contacting hosts that package names** | *(inferred, Q5)* |
| `Registry::fetch` | response body | **yes** | data, size | bytes are re-hashed and checked against the declared digest | *(documented, crates/trigon-registry/src/registry.rs)* |
| `SourceCache::checkout` | `repo` | **yes** | resource-name, x-git-remote-url | **https only**, enforced here; `GIT_ALLOW_PROTOCOL` and `GIT_CONFIG_NOSYSTEM` are set | *(documented, crates/trigon-registry/src/source.rs)* |
| `SourceCache::checkout` | `commit` | **yes** | x-git-ref | **40 hex characters only**, so a ref cannot be an option or a path | *(documented, crates/trigon-registry/src/source.rs)* |
| `Checkout::files` / `read` | repository contents | **yes** | data, object-topology | nothing — this is the material the Builder reads | *(documented, docs/16-findings.md §3.7)* |
| strategy inference ladder | `package.json` `scripts.build` | **yes** | data, x-shell-script | nothing at this layer; the environment is the enforcement point | *(documented, docs/12-security.md §5)* |
| `strategy` parse | a strategy document | **yes when a model or a package authored it** | data, x-shell-script, x-model-output | **schema validation is not sanitization** — a `runs:` step is free-form shell | *(documented, docs/04-strategies.md §7; docs/12-security.md §5)* |
| `strategy` render | template context | no — a closed type | type-class | undefined variables are a hard error | *(documented, docs/04-strategies.md §3)* |
| build container | everything the build runs | **yes, by design** | x-shell-script | the egress tier and the container are the boundary | *(documented, docs/08-execution.md §5)* |
| mirror `/-artifact/`, `/-toolchain/` | request host and path | **yes, from inside the build** | resource-name | compiled-in exact-match host allowlists; **these routes sit before the credential check and are not access-controlled** | *(documented, docs/16-findings.md §3.13)* |
| mirror index route | the time filter, in basic auth | **readable from inside the build** | data | an index request with no filter is refused 400 | *(documented, crates/trigon-mirror/src/server.rs)* |
| egress guard | every proxied response body | **yes** | data, size, rate | hashed as it streams; a whole-artifact or member match voids the run | *(documented, docs/12-security.md §2.2)* |
| build output directory | file entries the build wrote | **yes** | data, resource-name, object-topology | **symlinks are not followed**; the type is taken without dereferencing | *(documented, docs/16-findings.md §3.12)* |
| `verify-attestation` | the bundle | **yes** | data, serialized-state | signature is checked only if `--public-key` is given, and the tool says which it did | *(documented, README.md "Signing it, and checking the signature")* |
| `verify-attestation` | `--stabilizers` manifest | operator | collaborator-implementation | naming an archived set the operator chose to trust | *(documented, docs/09-attestations.md §7.1)* |
| `trigon watch` `GET /run/{index}` | the path segment | **yes if the port is reachable** | data, resource-name | parsed as an integer and re-formatted; it is never joined as a caller-supplied path | *(documented, crates/trigon/src/watch.rs)* |
| `trigon watch` all views | package names, build logs, strategies | **yes** | data, size, x-build-log | every package-derived string is HTML-escaped on the way out | *(documented, crates/trigon/src/watch.rs — `esc`)* |
| model prompt | README, CI config, manifests, build log | **yes** | data, x-build-log | **nothing prevents injection**; it is fenced, bounded, control-stripped and accepted as a residual risk | *(documented, docs/12-security.md §4)* |
| model response | the proposed strategy | **the model's, and therefore indirectly the attacker's** | x-model-output | parsed and validated; the provenance cap is what bounds the damage | *(documented, docs/00-overview.md §3.1)* |

**Coverage.** Every family's public surface is represented. Within a family the table names the
operands that carry attacker power, not every parameter; the remainder are operator-supplied or
internal and are *(assumption, Q7)* trusted.

### Contract-dimension matrix

Eight dimensions per in-scope family. `claimed` and `disclaimed` rows route to §1.11 or §1.12.

| Family | Dimension | Status | Conditions / boundary |
| --- | --- | --- | --- |
| archive-parsing | numeric-domain | **claimed** | offsets are checked; a wrapping add was fixed and is tested → P1 |
| archive-parsing | failure-atomicity | **claimed** | a parse failure leaves the member `Inline` and emits `NestedParseFailed`; it never silently changes a digest → P1 |
| archive-parsing | recursive-cyclic-topology | **claimed** | recursion is structural and depth-limited to 4 → P1 |
| archive-parsing | callback-execution | N/A | the API accepts no callbacks |
| archive-parsing | serialization-reconstruction | **claimed** | `parse(write(a)) == a`, proptested → P2 |
| archive-parsing | reference-lifecycle | **claimed** | copy-on-write over an mmap; a body is never aliased after mutation → P2 |
| archive-parsing | concurrency-reentrancy | **disclaimed** | no thread-safety beyond `Send`/`Sync` is stated anywhere → D8 |
| archive-parsing | resource-complexity | **disclaimed, partially** | inline and total-expansion caps exist; **the inflate itself is not bounded by what it produces** → D1 |
| stabilization | numeric-domain | **claimed** | stabilizers are total and take no sizes from the input |
| stabilization | failure-atomicity | **claimed** | stabilizers return no `Result`; there is no half-stabilized state → P3 |
| stabilization | recursive-cyclic-topology | **claimed** | nesting is bounded by the archive model's limit |
| stabilization | callback-execution | **claimed under the `wasm` feature only** | an archived set is a WASM module, sandboxed by wasmtime → §1.6 |
| stabilization | serialization-reconstruction | **claimed** | `stab(stab(x)) == stab(x)` is a required, tested property → P3 |
| stabilization | reference-lifecycle | N/A | the registry hands out `Arc`s and owns nothing mutable |
| stabilization | concurrency-reentrancy | **disclaimed** | no statement is made → D8 |
| stabilization | resource-complexity | **claimed** | bounded by the archive it walks |
| comparison-and-verdict | numeric-domain | N/A | compares digests and counts, takes no sizes from input |
| comparison-and-verdict | failure-atomicity | **claimed** | a set mismatch refuses before comparing, classified `Fault::Bug` → P4 |
| comparison-and-verdict | recursive-cyclic-topology | **claimed** | the diff walks the archive model's bounded tree |
| comparison-and-verdict | callback-execution | N/A | no callbacks |
| comparison-and-verdict | serialization-reconstruction | **claimed** | outcomes cross the wire as strings with `FromStr` the exact inverse of `Display` → P5 |
| comparison-and-verdict | reference-lifecycle | N/A | borrows for the call's duration |
| comparison-and-verdict | concurrency-reentrancy | **disclaimed** | → D8 |
| comparison-and-verdict | resource-complexity | **claimed** | linear in members; the diff walks each side at most twice |
| attestation | numeric-domain | N/A | no arithmetic on attacker values |
| attestation | failure-atomicity | **claimed** | `trigon attest` refuses a void run outright rather than signing a weaker claim → P6 |
| attestation | recursive-cyclic-topology | **claimed** | JCS refuses what it cannot promise another implementation reproduces → P9 |
| attestation | callback-execution | **claimed** | the `Signer` and `ArchivedSet` seams are operator-chosen collaborators |
| attestation | serialization-reconstruction | **claimed** | canonical JSON is byte-stable; floats and non-ASCII keys are refused, not coerced → P9 |
| attestation | reference-lifecycle | N/A | — |
| attestation | concurrency-reentrancy | **disclaimed** | → D8 |
| attestation | resource-complexity | **disclaimed** | a statement is as large as the difference summary it carries → D9 |
| strategy-rendering | numeric-domain | N/A | — |
| strategy-rendering | failure-atomicity | **claimed** | an unregistered `uses:` is a hard error naming the tool, never an empty fragment |
| strategy-rendering | recursive-cyclic-topology | **claimed** | tool composition is acyclic at load and depth-bounded at render |
| strategy-rendering | callback-execution | **disclaimed** | a `runs:` step is free-form shell and nothing here sanitizes it → D2 |
| strategy-rendering | serialization-reconstruction | **claimed** | `strategy_digest` is canonical and domain-separated |
| strategy-rendering | reference-lifecycle | N/A | — |
| strategy-rendering | concurrency-reentrancy | **disclaimed** | → D8 |
| strategy-rendering | resource-complexity | **claimed** | render depth is bounded |
| registry-and-source | numeric-domain | N/A | — |
| registry-and-source | failure-atomicity | **disclaimed** | a partial checkout or a partial fetch is not rolled back → D10 |
| registry-and-source | recursive-cyclic-topology | N/A | — |
| registry-and-source | callback-execution | **claimed** | `git` is spawned with a fixed environment, https only, 40-hex commits only → P10 |
| registry-and-source | serialization-reconstruction | **disclaimed** | registry JSON shape is not validated beyond what is read → D11 |
| registry-and-source | reference-lifecycle | N/A | — |
| registry-and-source | concurrency-reentrancy | **disclaimed** | → D8 |
| registry-and-source | resource-complexity | **disclaimed** | no bound on a repository's or a response's size → D12 |
| build-execution | numeric-domain | N/A | — |
| build-execution | failure-atomicity | **claimed** | a runner refuses a tier it cannot enforce rather than downgrading it → P11 |
| build-execution | recursive-cyclic-topology | N/A | — |
| build-execution | callback-execution | **disclaimed by design** | executing attacker code is the purpose; the container is the boundary → D3 |
| build-execution | serialization-reconstruction | N/A | — |
| build-execution | reference-lifecycle | **disclaimed** | two processes share one podman image store → D4 |
| build-execution | concurrency-reentrancy | **disclaimed** | → D4, D8 |
| build-execution | resource-complexity | **claimed** | a hard wall-clock kill bounds a build |
| model-inference | numeric-domain | N/A | — |
| model-inference | failure-atomicity | **claimed** | a budget stop names which budget; a replay refuses a changed prompt rather than answering it |
| model-inference | recursive-cyclic-topology | N/A | — |
| model-inference | callback-execution | **disclaimed** | with `--model copilot:` the provider is an agent with a shell; every other provider is a function from a prompt to a string → D5 |
| model-inference | serialization-reconstruction | **claimed** | a transcript naming a model alias is refused for replay rather than replayed |
| model-inference | reference-lifecycle | N/A | — |
| model-inference | concurrency-reentrancy | **disclaimed** | → D8 |
| model-inference | resource-complexity | **claimed** | iteration, token and wall-clock budgets, checked between iterations |
| operator-surface | numeric-domain | N/A | — |
| operator-surface | failure-atomicity | **claimed** | `trigon watch` has no write path at all |
| operator-surface | recursive-cyclic-topology | N/A | — |
| operator-surface | callback-execution | N/A | — |
| operator-surface | serialization-reconstruction | **disclaimed** | the store hash-checks blobs and not its own records → D6 |
| operator-surface | reference-lifecycle | N/A | — |
| operator-surface | concurrency-reentrancy | **disclaimed** | nothing excludes two writers from one work directory or one store → D7 |
| operator-surface | resource-complexity | **disclaimed** | a `watch` request does unbounded work in the size of the work directory → D13 |

---

## 1.8 Outputs, and what a consumer may assume about them

Trigon's output is somebody else's input, so each channel needs a taint statement.

| Channel | Taint | Guaranteed | Must not be assumed |
| --- | --- | --- | --- |
| the stabilized artifact (`trigon stabilize`) | **same as input** | it is a byte-stable re-serialization of the input, store-only, with no compression | that it is safe to execute, extract or trust. It is the same package, normalized. |
| the comparison / verdict | **constrained** | the outcome is one of four strings; the digests are computed by us over bytes we hold | that `exact` or `normalized` means the package is honest, or that `divergent` means it is malicious *(documented, docs/12-security.md §11)* |
| the difference summary | **same as input** | it is deterministic, and a divergence's codes are computable by a third party from the two artifacts | that member paths and difference codes are sanitized before being rendered, logged, or put in a prompt. They come from the artifact. *(inferred, Q8)* |
| the signed attestation | **constrained** | the statement is canonical JSON; floats and non-ASCII object keys are refused rather than coerced | that a signature was checked. `verify-attestation` without `--public-key` re-derives and says the signature was present and unchecked — **"unsigned" and "signed by someone you did not check" are different things and the tool distinguishes them** *(documented, README.md)* |
| the build log (stored, rendered, prompted) | **same as input** | it is bounded and stripped of control characters before it reaches a model | **that credentials have been redacted out of it.** They have not *(documented, docs/17-backlog.md; docs/18-management-ui.md §2)* |
| `trigon watch` HTML | **constrained** | every package-derived string is HTML-escaped | that the page is authenticated, or that serving it is safe on a routable address |
| `/api/state` JSON | **same as input** | it is the view model the pages render | that it is access-controlled. It is not. |
| the model transcript | **same as input** | it records the model that answered, the prompt digests, the usage, and now the reasoning trace | that replaying it reproduces the *result*. It replays the model, not the world *(documented, docs/07-ai.md §8)* |

---

## 1.11 Security properties Trigon provides

Each has a violation symptom and a tier. A report that violates one of these, through an adversary in
§1.10 and an operand §1.7 marks attacker-controllable, is `VALID`.

| ID | Property | Conditions | Violation symptom | Tier |
| --- | --- | --- | --- | --- |
| **P1** | Parsing a hostile artifact does not panic, escape its limits, or silently change a digest. Recursion is depth-limited to 4; a parse failure keeps the member inline and emits `NestedParseFailed`. | any input bytes | panic, hang, wrong digest | **security-critical** *(documented, docs/05 §2.2)* |
| **P2** | The stabilized form is a byte-stable function of the input: `parse(write(a)) == a`, and identical across runs and threads. | same stabilizer set | two runs disagree on a digest | **security-critical** *(documented, docs/13-roadmap.md M0)* |
| **P3** | Stabilizers are total and idempotent: `stab(stab(x)) == stab(x)`, no `Result`, no half-stabilized state. | — | a digest that depends on how many times a pass ran | **security-critical** *(documented, docs/05 §4)* |
| **P4** | `compare` refuses to compare two sides stabilized under different sets, by set digest, and classifies the refusal `Fault::Bug`. | — | a verdict derived across incomparable sets | **security-critical** *(documented, docs/09-attestations.md §7)* |
| **P5** | **Provenance-capped outcomes.** `Match::Normalized` is produced only when the stabilized digests are equal *and* every applied stabilizer is `Builtin` with risk ≤ `Metadata`. Anything else that matches is `NormalizedWithCaveats`. | — | a model- or human-authored normalization reported as clean | **security-critical** *(documented, docs/00-overview.md §3.1; enforced at crates/trigon-compare/src/lib.rs:166–181)* |
| **P6** | `trigon attest` refuses to sign a void run — one where the artifact under test reached the build over the network. | the guard was armed | a signed statement about a run that fetched its own answer | **security-critical** *(documented, docs/12-security.md §2.4)* |
| **P7** | Text that reaches a model is bounded and stripped of control characters, and operator instructions travel in a system message, never spliced into package text. | every provider **except `copilot:`** | a build log rewriting the operator's instructions | **security-critical** *(documented, docs/12-security.md §4.1)* |
| **P8** | Both artifacts receive an identical transform; the comparison API has no way to stabilize one side differently from the other. Enforced by the type signature. | — | an asymmetric normalization producing a false match | **security-critical** *(documented, docs/12-security.md §10)* |
| **P9** | Canonical JSON refuses what it cannot promise another implementation reproduces — floats and non-ASCII object keys are type errors, not coerced values. | signing path | two implementations disagreeing on what was signed | **security-critical** *(documented, crates/trigon-core/src/jcs.rs)* |
| **P10** | A package-declared repository reaches `git` as **https only**, with a **40-hex commit only**, under `GIT_CONFIG_NOSYSTEM` and a restricted `GIT_ALLOW_PROTOCOL`. Only the operator may name a local path. | — | command or option injection from registry metadata | **security-critical** *(documented, docs/16-findings.md §3.7)* |
| **P11** | A runner refuses an egress tier it cannot enforce rather than downgrading it, and at every tier but `Open` no phase of the build reaches the network — the image build runs `--network none` too. | podman honours its flags | a run recorded as enforced that was not | **security-critical** *(documented, docs/16-findings.md §3.13)* |
| **P12** | The mirror refuses to serve this run's own published artifact, and hashes every proxied body as it streams; a whole-artifact or member match voids the run. Artifact bodies are proxied undecoded so the guard sees real bytes. | an enforced tier | the forged-attestation attack succeeding | **security-critical** *(documented, docs/12-security.md §2.1–2.2)* |
| **P13** | Both mirror passthrough routes proxy only to compiled-in, exact-match host allowlists chosen here rather than by the request. | — | the mirror acting as a general HTTP proxy | **security-critical** *(documented, docs/16-findings.md §3.13)* |
| **P14** | The output collector takes a file's type **without following symlinks**. | — | any host file becoming the "rebuilt artifact" | **security-critical** *(documented, docs/16-findings.md §3.12)* |
| **P15** | A strategy cannot request privileged execution, a wider egress tier, an unpinned base image, or a platform. | — | a strategy widening its own boundary | **security-critical** *(documented, docs/04-strategies.md)* |
| **P16** | Model API keys are read from the environment and never accepted on the command line. | — | a key in a process list or shell history | **security-critical** *(documented, crates/trigon/src/inferrer.rs)* |
| **P17** | Every package-derived string rendered by `trigon watch` is HTML-escaped, and the only path parameter is an integer, re-formatted rather than joined. | — | script execution in the operator's browser; path traversal | **security-critical** *(documented, crates/trigon/src/watch.rs)* |
| **P18** | A model is never called unless `--model` names a provider, and `replay:` opens no socket. A replay refuses a prompt that differs from the recorded one rather than answering it. | — | a silent model call; a changed question answered from an old recording | **security-critical** *(documented, docs/07-ai.md §8)* |
| **P19** | Members are paired by `(path, occurrence)`, never by archive position. | — | a false divergence from reordering | correctness-only *(documented, crates/trigon-compare/src/signature.rs)* |
| **P20** | Nothing absent is rendered as a zero, and the two denominators never merge. | `trigon watch` | "no data" displayed as a result | correctness-only *(documented, docs/18-management-ui.md)* |
| **P21** | `trigon-core` performs no I/O and declares no cargo features; the verifier links no runtime and no network client, asserted by `xtask policy` and checkable with `cargo tree`. | `--no-default-features` | the verifier's independence being false | **security-critical** *(documented, docs/01-architecture.md §2.2)* |

---

## 1.12 Security properties Trigon does *not* provide

The most useful section for anyone deciding what they now own. Each is disclaimed, so a matching
report closes `BY-DESIGN: property-disclaimed`.

### False friends — things that look like a security property and are not

These are the ones that get misread, so they are listed first.

- **The crate dependency graph is not the control.** It keeps honest code honest. The maintainer
  declines to call it a boundary and neither does this document *(documented, ADR-0001)*.
- **Schema validation of a strategy is not sanitization.** A `runs:` step is free-form shell.
  Schema-validating a string that contains bash is validating a string; the step DSL is hygiene
  *(documented, docs/12-security.md §5)*.
- **`strategy_digest` does not identify what actually ran** *(documented, docs/04-strategies.md)*.
- **The system message, the nonce fence and "treat this as data" do not stop prompt injection.** They
  raise the cost. Prompt injection is accepted and mitigated, not solved *(documented,
  docs/12-security.md §4)*.
- **A replay does not prove the package reproduces.** It replays the model, not the world
  *(documented, docs/07-ai.md §8)*.
- **A model-proposed strategy does not cap the outcome below `Normalized`.** The cap is about applied
  *stabilizers*, not about how the recipe was derived. A model-derived recipe that reproduces exactly
  reports `exact` *(documented, docs/00-overview.md §3.1)*.
- **An enforced egress tier does not bound what the reachable hosts serve.** `registry.npmjs.org`
  serves anything anyone published *(documented, docs/17-backlog.md B7 residue)*.
- **The mirror's passthrough routes are not access-controlled**, and **the artifact route applies no
  time filter** *(documented, docs/16-findings.md §3.13)*.
- **The guard is not armed on every run.** Its also-in-source filter needs a checkout and is not
  automatic in a sweep, so the guard is wider than designed — it errs toward voiding an honest run
  *(documented, docs/12-security.md §2.2)*.
- **`trigon watch` authenticates nobody.** No token, no OIDC, no TLS, no CORS policy. `--bind`
  selects an address and restricts nothing *(documented, crates/trigon/src/main.rs)*.
- **`ModelCaps::context_tokens` does not bound a prompt**, and `Prompt::is_cacheable` is not enforced
  when a request is sent *(documented, crates/trigon-ai/src/provider.rs)*.
- **Apache-2.0's warranty disclaimer is not a security position.** It is boilerplate and grants
  nothing here.

### Properties simply not provided

| ID | Not provided | Why / conditions | Tier |
| --- | --- | --- | --- |
| **D1** | A bound on what decompression *produces*. `total_expanded_bytes` is checked against the size the input declares, not against what it emits, so a 200 KB member can expand to 200 MB in our process. A 42-byte zip panics the parser on an unchecked `u64` add. | known, unfixed, filed as B5 | **security-critical** *(documented, docs/16-findings.md §3.12)* |
| **D2** | Sanitization of anything in a `runs:` step. | the environment is the enforcement point, not the string | **security-critical** *(documented, docs/12-security.md §5)* |
| **D3** | Prevention of arbitrary code execution inside the build container. | it is the purpose | **security-critical** *(documented, docs/08-execution.md)* |
| **D4** | Isolation between two Trigon processes sharing a podman image store. | narrowed, not closed | correctness-only *(documented, docs/17-backlog.md B6)* |
| **D5** | That a model provider cannot act. With `--model copilot:` the provider is an agent with a shell on the operator's machine, and in `-p` mode the CLI was measured running `bash` with no permission request. The tool filter is the control; **the Copilot provider also has no system-role channel at all**, so operator instructions and package text travel in the same text. | only with `copilot:`; read the module docs before using it | **security-critical** *(documented, docs/16-findings.md §3.8)* |
| **D6** | That the store verifies what it reads. Only blobs are hash-checked. | — | correctness-only *(inferred, Q9)* |
| **D7** | Exclusion between two writers of one work directory or one store. | — | correctness-only *(assumption, Q10)* |
| **D8** | Thread-safety beyond what `Send` and `Sync` state. No type here promises interior consistency across threads. | every family | correctness-only *(documented, by the absence of any such claim)* |
| **D9** | A bound on the size of a statement, or of a difference summary. | — | correctness-only *(inferred, Q11)* |
| **D10** | Atomicity of a checkout or a fetch. A partial one is not rolled back. | — | correctness-only *(inferred, Q12)* |
| **D11** | Validation of registry JSON beyond the fields read. | — | correctness-only *(inferred, Q6)* |
| **D12** | A bound on a repository's or a registry response's size. | — | correctness-only *(inferred, Q13)* |
| **D13** | Bounded work per `trigon watch` request. A request walks the whole work directory. | loopback by default | correctness-only *(documented, docs/18-management-ui.md)* |
| **D14** | Redaction of credentials from a build log before it is stored, rendered, or sent to a model. | — | **security-critical** *(documented, docs/18-management-ui.md §2)* |
| **D15** | That any run is attestable at full trust. No network transcript exists at any tier. | all tiers, today | **security-critical** *(documented, docs/16-findings.md §3.13)* |
| **D16** | That the artifact guard survives a byte-level transformation. It compares bytes, so re-encoding, encryption or chunk reassembly defeats it. | — | **security-critical** *(documented, docs/12-security.md §2.5)* |
| **D17** | That a divergence has been confirmed. The two-agreeing-attempts policy is specified and not implemented. | — | **security-critical** *(documented, docs/16-findings.md §5)* |
| **D18** | That a `Normalized` claim re-derived through an archived (WASM) stabilizer set stays `Normalized`. It degrades to `NormalizedWithCaveats`, so **a true claim can read as refuted**. | `wasm` feature | **security-critical** *(documented, docs/16-findings.md §4b)* |
| **D19** | That a published reproduction rate estimates an ecosystem. The corpora are small smoke sets, not prevalence-sampled. | — | correctness-only *(documented, docs/16-findings.md §5)* |
| **D20** | Confidentiality of package text from a model provider, or of a Copilot prompt from the host process table. | when `--model` names a provider | correctness-only *(inferred, Q14)* |

### Well-known attack classes left to the caller

- **Archive bombs.** We decompress attacker bytes by construction, and D1 says the output bound is
  not in place. Run the parser where an OOM is survivable.
- **Prompt injection.** Mitigated, not solved (§1.10 A2).
- **SSRF via package metadata.** A package names the hosts this machine connects to (§1.7).
- **Supply-chain compromise of the definitions repository** (§1.9).
- **Typosquatting, dependency confusion, malicious-but-faithful source.** All out of scope: a
  malicious package that reproduces is a correct `reproduced` (§1.3).

---

## 1.13 Downstream responsibilities

What the reader has to do. Trigon records provenance, not trust, and leaves the policy to the
consumer *(documented, docs/09-attestations.md §2.1)*.

**If you consume an attestation:**

1. **Re-derive it.** `trigon verify-attestation --rerun-comparison`, holding the attestation and both
   artifacts, with a binary you built. This is the only thing that makes a *rebuilder's* attestation
   worth anything to someone who does not trust the rebuilder.
2. **Check the signing identity** against your own policy, and check Rekor inclusion if the bundle
   carries it. Dropping `--public-key` still re-derives, and the tool tells you the signature was
   present and unchecked — decide what that means to you.
3. **Set your own threshold.** Demand `Match::Exact`, or `Normalized` with risk ≤ `Structural`, via
   `Match::is_at_least`. The default is not a recommendation.
4. **Read the `applied` list.** If you reject a particular normalization, you can see that it fired,
   with its risk tier and provenance, and throw the result out.
5. **Filter on `derivation.method`** if you want "no model touched this".
6. **Read the egress tier.** A run at `--egress open` records `attestable: false`, and today no run
   is attestable at full trust at any tier.
7. **Distinguish a confirmed result from a single attempt, and a stale pass from no data.**
8. **For npm, do not read `reproduced` as `attributed`.** npm packages reproduce at the tarball level
   almost always, with no source linkage at all.

**If you run Trigon:**

9. **Build the mirror and base images first** (`trigon mirror-image`, `trigon base-image --from
   <pinned>`) or an enforced tier will not work.
10. **Choose the egress tier deliberately.** `--egress open` is the default and it voids the strong
    claim.
11. **Only you may name a local path as a source.** `file://` is not dangerous; `file://` chosen by
    the thing under test is.
12. **Read `crates/trigon-ai/src/copilot.rs`'s module docs before using `--model copilot:`.** Prefer
    a provider with a real system message where the choice exists.
13. **Keep `trigon watch` on loopback** unless you have thought about it. The work directory holds
    registry artifacts and build logs, and build logs are not redacted (D14).
14. **Before a real sweep, talk to the registries**: declare a User-Agent with a contact URL, honour
    `Retry-After`, and run per-host token buckets.
15. **Read `docs/16-findings.md`.** The design chapters describe the system as intended; where the
    two disagree, `16` records which is right.

**If you review the definitions repository:**

16. **Two-party review for anything touching a stabilizer**, a non-empty prose `reason:`, and the
    corpus-wide impact preview before merging.

---

## 1.14 Known misuse patterns

- **Reading `reproduced` as `safe`.** A package that faithfully builds a backdoor reproduces. What to
  do instead: treat a reproduction as evidence about *provenance*, and run the malware question
  separately.
- **Reading `divergent` as `compromised`.** Most divergences are build nondeterminism. What to do
  instead: read the difference signature, which is deterministic and reproducible by you.
- **Trusting a verdict without its stabilizer set digest.** A verdict under a set you cannot obtain
  cannot be re-derived by anyone. What to do instead: keep the set id and digest with the verdict.
- **Taking a pass at `--egress open` as equivalent to one at `mirror-only`.** What to do instead:
  read `attestable` and the tier.
- **Pointing `trigon watch` at a routable address.** It has no authentication and serves build logs.
- **Passing an API key on the command line.** Trigon refuses; the environment is the channel.
- **Using `--model copilot:` because it needs no key.** It is the one provider that can act, and it
  has no system-role separation.
- **Comparing verdicts across stabilizer sets.** `compare` refuses, and so should you.

---

## 1.15 Known non-findings

These recur from scanners, fuzzers and AI reviewers. Each cites what discharges it. A report matching
an entry **on every field** closes `KNOWN-NON-FINDING`; text similarity alone never licenses it.

| ID | Reported as | Why it is not a finding |
| --- | --- | --- |
| **N1** | "Attacker-controlled README / manifest / build-log text is concatenated into an LLM prompt with no sanitization." | This is the design. Package text is data in a prompt by construction; §1.10 A2 and D-list note the mitigations and that they are mitigations. Discharged by §1.12 (prompt injection disclaimed) and P7 (bounded, control-stripped, system-role separated). A report that finds a *specific bypass of a stated mitigation* is not this entry and may be `VALID`. |
| **N2** | "An LLM decides whether a package is reproducible; a model sits in the trust path of a security verdict." | It does not. The model proposes a recipe; the verdict is computed by model-free code, and the provenance cap bounds what a model-touched normalization can reach. Discharged by P5 and §1.2's claim statement. |
| **N3** | "The strategy is `serde_json::from_str`'d from model output without `deny_unknown_fields`." | Strategy parsing is `deny_unknown_fields`, and in any case parsing is not the control — the environment is. Discharged by §1.12 D2. |
| **N4** | "The model base URL comes from an environment variable: SSRF / arbitrary endpoint." | The operator sets it. Operator inputs are trusted; `OUT-OF-MODEL: trusted-input` by §1.7. |
| **N5** | "The build container runs arbitrary attacker code." | It is the purpose. Discharged by D3. |
| **N6** | "The build downloads dependencies from the internet." | At an enforced tier it reaches only the mirror; at `--egress open` this is the disclaimed posture. Discharged by P11 and §1.6. |
| **N7** | "Digest comparison uses `==` and is not constant-time." | The digests being compared are both computed locally from bytes the process already holds. There is no secret and no remote timing channel. Discharged by §1.10 (no such adversary). |
| **N8** | "`Match::Exact` is returned for artifacts that are byte-identical to the published one — the rebuild may just be a copy." | That is exactly what the artifact guard is for, and a run where the artifact arrived over the network is `Void`, not `exact`. Discharged by P12 and P6. A report showing the guard can be *bypassed* is not this entry. |
| **N9** | "A package name flows into an HTML page — stored XSS." | Every package-derived string is escaped. Discharged by P17. A report showing an unescaped sink is not this entry. |
| **N10** | "A published divergence names a package that is actually fine." | A real false mismatch is `VALID` and the most expensive error class in the product. This entry covers only the *generic* claim that false positives are possible, which §1.12 D17 and D19 already state. |
| **N11** | "The verifier's claim to link no network client is unverifiable." | `cargo tree -p trigon --no-default-features` and `cargo run -p xtask -- policy`. Discharged by P21. |
| **N12** | "Concurrent use of one `Replaying` transcript is not synchronized." | Not supported, and no claim is made. Discharged by D8. |

---

## 1.18 Open questions for the maintainer

Each states a **proposed answer**, not "please clarify". Answering one promotes its claims from
*(inferred)* or *(assumption)* to *(maintainer)* and removes the question.

**Wave 1 — scope and the insecure default.**

- **Q1.** Is everything in the repository in the model — no `contrib/`, no unsupported examples, no
  vendored source? *Proposed: yes.* → §1.2
- **Q2.** `docs/12-security.md` §3 says the attestor never executes sandbox-derived code. In the
  built system, `trigon rebuild --attest` signs in the process that ran the build. Is the separable
  path (`trigon rebuild --store` then `trigon attest`) the supported one for a claim that matters?
  *Proposed: yes, and `--attest` on a run that built is dev convenience.* → §1.4, §1.6
- **Q3.** Is Linux/x86-64 the only supported platform for the build path? *Proposed: yes.* → §1.5
- **Q4.** Does anything install a signal handler, mutate global locale or FPU state, or spawn a
  thread the caller does not know about? *Proposed: no, other than the progress heartbeat thread.*
  → §1.5
- **Q5.** A package's own metadata names the hosts the operator's machine connects to during
  resolution and fetch. Is that accepted, or should the host set be allowlisted the way the mirror's
  is? *Proposed: accepted, and stated rather than fixed — the operator chose to resolve this
  package.* → §1.7

**Wave 2 — inputs and bounds.**

- **Q6.** Is registry JSON validated beyond the fields read, or is a malformed response simply a
  `RegistryError`? *Proposed: the latter; no schema validation is claimed.* → §1.7, D11
- **Q7.** Are all non-tabled operands operator-supplied and trusted? *Proposed: yes.* → §1.7
- **Q8.** Difference codes and member paths come from the artifact and reach a signed statement, a
  log and a prompt. Are they bounded and control-stripped on those paths? *Proposed: bounded on the
  prompt path by `logs.rs`, not on the statement path; state it as a disclaimer.* → §1.8
- **Q9.** Does the store verify anything it reads besides blob hashes? *Proposed: no.* → D6
- **Q10.** Is anything meant to exclude two writers from one work directory or one store? *Proposed:
  no, and the operator owns it.* → D7
- **Q11.** Is there a bound on a statement's or a difference summary's size? *Proposed: no.* → D9
- **Q12.** Is a partial checkout or fetch rolled back? *Proposed: no; the cache is keyed by commit so
  a partial entry is re-fetched.* → D10
- **Q13.** Is there a bound on a repository's or a registry response's size? *Proposed: no.* → D12
- **Q14.** Is package text confidential from a model provider, and does the Copilot prompt stay off
  the host process table? *Proposed: no to the first, unverified for the second — disclaim both.*
  → D20

**Wave 3 — the two that change what a claim means.**

- **Q15.** `--egress open` is the shipped default for `rebuild` and `sweep`. Is that a supported
  production posture (so a fetch at that tier is `BY-DESIGN`), or should the default change?
  *Proposed: supported, because the alternative is a tool that does not run out of the box, and the
  attestation records the weaker claim.* → §1.6
- **Q16.** D18: a `Normalized` claim re-derived through an archived WASM set degrades to
  `NormalizedWithCaveats`, so a true claim reads as refuted. Is that acceptable, or does
  `verify-attestation` need a third answer meaning "consistent, cap unconfirmable"? *Proposed: a
  third answer.* → D18

**Meta.**

- **Q17.** There is no `SECURITY.md`, no disclosure address, and no supported-versions statement. A
  threat model that says "report §1.11 violations through the disclosure channel" needs one to exist.
  *Proposed: add `SECURITY.md` pointing here.* → §1.1

---

## Appendix — back-map from `docs/12-security.md`

`docs/12-security.md` is a controls document, and the maintainer says explicitly that it is not this
*(documented, docs/17-backlog.md B2)*. It nonetheless holds threat-model content, so this model must
be a strict superset of it. Kept until the maintainer approves removal.

| `12-security.md` | Where it lands here |
| --- | --- |
| §1, §1.1 the forged-attestation attack | §1.10 A1; §1.2 "what would have to be true for the claim to be wrong" |
| §2.1 mirror refusal | P12 |
| §2.2 egress hashing, the guarded member set and its filters | P12; §1.12 (the guard is wider than designed) |
| §2.3 write-only blob access | **designed, not built** — §1.3 "designed but not built"; §1.4 |
| §2.4 why `Void` | P6 |
| §2.5 the limits | D16 |
| §3 trust boundaries | §1.4, with the note that one process holds several of the designed roles |
| §4, §4.1–4.3 prompt injection | §1.10 A2; P7; §1.12 false friends |
| §5 free-form shell | D2; §1.12 false friends |
| §6 sandbox hardening | §1.5; P11 |
| §7 multi-tenancy | §1.3 (out of scope until built) |
| §8 the definitions repository | §1.9; §1.10 A4; §1.13 item 16 |
| §9 signing key handling | §1.13; Q2 |
| §10 the twelve invariants | P1–P21, each with a symptom and a tier |
| §11 out of scope | §1.3 |
| §12 redistribution | not security-contract content; left in `12` |
