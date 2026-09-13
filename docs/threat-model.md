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

**Draft confidence:** _filled at publication._
**Backtest:** _filled at publication._
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
