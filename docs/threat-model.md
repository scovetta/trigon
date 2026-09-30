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
| *(maintainer, YYYY-MM)* | Stated by a maintainer in answer to this process. So far D18, which answered Q16 with a third answer (docs/09-attestations.md §7.1). |
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
artifact under test reached the build over the network, the build had the whole network, or a
stabilizer a person or a model wrote did the matching — the three clauses of the publication gate's
safeguard 2. It is not a pass and not a failure, and it is signed as `void/v1`, never as a
verdict, by `trigon attest` and by `trigon rebuild --attest`, which signs through the same code: no
path signs a verdict for a run the gate voids (P6; docs/16-findings.md §3.97). `trigon verify
--attest` signs a v1 claim about two local files with no run behind them, which is not publishable.

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
- **Not that the build was observed beyond its network.** A run at `mirror-only` or `deny-all`
  records a network transcript — every response that crossed into the build, with its digest — and
  `attestable: true` says that account is complete. It says nothing about what the build did with
  those bytes: Tier 2 and Tier 3 are not implemented *(documented, docs/08-execution.md §7.3)*.

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
| `attestation` (`trigon-attest`) | statement building, DSSE, `Signer`; the evidence log and its records verified from a directory (`log`, `evidence`), which `verify-attestation --record` reaches, and a source's chain followed across repositories; what `trigon log sign` holds a tree to before the log key signs it (`evidence::check_to_sign`); the evidence configuration and a source's state (`config`, `state`) | reads a key file when signing; reads an evidence repository's files, `evidence.toml`, a source's state checkpoint and the keys a source trusting on first use recorded when verifying a record; under `trigon log sign`, reads the log key and writes the tree's `log/checkpoint`; writes `evidence.toml` for `trigon evidence add` and `remove`, and a source's state for `trigon evidence sync` | **in** |
| `strategy-rendering` (`trigon-strategy`) | `Strategy` parse, flow DSL, minijinja render | nothing; emits a script for someone else to run | **in** |
| `archived-stabilizer-sets` (`trigon-stabilize-wasm`) | the `wasm` feature: on in the full build, off in the verifier (`--no-default-features`) unless `--features wasm` | runs a WASM module in-process | **in**, §1.6 |
| `registry-and-source` (`trigon-registry`) | `Registry::resolve`/`fetch`, `SourceCache` | network, filesystem, spawns `git` | **in** |
| `build-execution` (`trigon-sandbox`, `trigon-mirror`) | `BuildRunner::start`, the mirror server | spawns `podman`, binds a socket, writes a work directory | **in** |
| `model-inference` (`trigon-ai`) | `Provider::complete`, the Builder, `RepairLoop` | network, spawns `copilot` | **in** |
| `operator-surface` (`trigon` bin, `trigon-store`) | CLI subcommands, `trigon watch`'s HTTP server, `trigon publish` and `trigon log init`, which write an evidence repository, `trigon evidence`, which syncs the evidence sources a client trusts, and `trigon runs export` and `import`, which move runs between stores | everything above, plus a listening socket and a store; spawns `git` and `trigon log sign`; pushes to an evidence repository; clones evidence repositories into the cache and keeps each source's state | **in** |
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
docs/16-findings.md §5)*, the standalone client of docs/19 §10 phase 9 and the witnessing of phase
7b *(documented, docs/19-distribution-and-lookup.md, status and §10)*, and most of
`docs/11-interfaces.md` §2.
Reading an evidence repository is built: the log, the records it logs, lookup over its leaves and
the index paths, in `trigon_attest::log` and `trigon_attest::evidence`, reached by the network-free
verifier's `verify-attestation --record`, and held to P31–P33. So is writing one: `trigon log
init`, `trigon log sign` and `trigon publish` for runs, withdrawals and heartbeats, with rebuilt
artifacts as release assets and the divergence feed where they are configured, held to P34, P35,
P36 and P38; and
rotation, `trigon log key-change` and `trigon log succeed`, held to P37. So is syncing one: `trigon
evidence add`, `list`, `remove` and `sync` — a source's clones and state, its mirrors held to one
another, a chain followed into another repository, trust on first use, and the two freshness
clocks — held to P39–P41. And so is answering from one: `trigon lookup`, `trigon check` against
evidence sources, `verify-attestation --lookup`, the record form reading a source's own clones, and
`--remote`, held to P43–P45 *(documented, docs/19-distribution-and-lookup.md status and §10 phases
4–6; docs/16-findings.md §3.98, §3.99, §3.100, §3.101, §3.102, §3.103)*.

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
for a local `trigon rebuild --attest`, which runs `trigon attest`'s signing code in the process that
ran the build. It signs what `trigon attest` would; where it signs is the difference. The separable
path is `trigon rebuild --store` followed by `trigon attest` *(inferred, Q2)*.

**Reachability preconditions.** A finding matters only if it meets its family's condition.

| Family | Reachable from… |
| --- | --- |
| `archive-parsing` | the bytes of a published or a rebuilt artifact |
| `stabilization` | an archive already parsed, or a stabilizer set id named in an attestation |
| `archived-stabilizer-sets` | a `.wasm` module the operator passed to `--stabilizers` or to `attest --stabilizer-module` (or named as `[publish] stabilizer_module`), or the module a verified record's evidence carries, run only when its sha256 is the `stabilizerSetModule` its signed verdict names and the binary does not carry the verdict's set |
| `comparison-and-verdict` | two summaries produced by this process in one run |
| `attestation` | a statement this process built, an attestation handed to `verify-attestation`, a record file and an evidence directory handed to `verify-attestation --record`, which whoever can push to that repository wrote (A8, A9), or a tree handed to `trigon log sign`, which `publish` wrote over a clone of such a repository |
| `strategy-rendering` | a strategy from the definitions repo, a heuristic, CI parsing, or a model |
| `registry-and-source` | registry metadata, a package-declared repository URL, or a git host's response |
| `build-execution` | a rendered strategy, or bytes crossing the mirror |
| `model-inference` | text a package wrote reaching a prompt, or a provider's response |
| `operator-surface` | a flag, a work directory on disk, an HTTP request to `watch`, the evidence repository `trigon publish` fetches, or those `trigon evidence sync` clones — every location of every source, and every successor a log-end names — which whoever can push to them wrote, or serves (A8, A9); or a project's `.trigon/evidence.toml`, chosen by the thing under test; or a file handed to `trigon runs import`, which whoever made it wrote |
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
| Environment variables | **conditional** | only `verify-attestation --record`: under `--source <name>`, the evidence configuration's — `TRIGON_EVIDENCE_CONFIG`, `TRIGON_EVIDENCE_STATE`, `TRIGON_EVIDENCE_REPO` and the keys beside it, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `HOME` — and `HOME` to expand `~/` in `--attestation-key`, as `trigon log sign --attestation-key` does too; and `trigon log sign`'s `XDG_STATE_HOME` and `HOME`, for the host's state directory *(documented, crates/trigon-attest/src/config.rs — `Env::from_process`; crates/trigon/src/verify_record.rs; crates/trigon/src/evidence_log.rs)* |
| Filesystem writes | **conditional** | only paths the operator named: the `stabilize` output, the `--attest` file, the key file `keygen` or `log keygen` makes — created `0600`, never over a file already there — and under `trigon log sign`, the named tree's `log/checkpoint`, replaced by a rename from a file made new beside it, and with `--init` its `keys/log.vkey`, and with `--continuing` a successor's first checkpoint at the `--log` it names; and the newest checkpoint of the log it has built on, in the host's state directory (`$XDG_STATE_HOME/trigon/publish/`). `SpillFile` exists as a type and is never constructed, so nothing spills *(documented, verified: no construction of `Body::Spilled` anywhere in `crates/`; crates/trigon/src/evidence_log.rs)* |
| Filesystem reads | **conditional** | only paths the operator named, plus a signing key file; and under `verify-attestation --record`, the files of the evidence directory it names — checkpoints, tiles, entry bundles, records and evidence, each inside the directory once links are followed, a regular file, and no longer than its kind can be — and under `--source`, `evidence.toml`, the working directory's `.trigon/evidence.toml`, the source's state checkpoint, and for a source trusting on first use the keys its first sync recorded (`<state>/<name>/keys`); and under `trigon log sign`, the log key file — with `--successor-key`, the successor's too — the newest checkpoint of its log kept in the host's state directory, and the files of the tree it names, and with `--continuing` of the tree whose chain it continues, read the same way; and under `trigon log public-key` and `trigon log key-change-leaf`, the key files named *(documented, crates/trigon/src/main.rs — every other read path is a CLI argument; crates/trigon-attest/src/log/files.rs; crates/trigon-attest/src/evidence/repository.rs; crates/trigon-attest/src/config.rs; crates/trigon-attest/src/evidence/sign.rs)* |
| stdout / stderr | **present** | the verdict on stdout, `tracing` on stderr *(documented, docs/11-interfaces.md)* |
| Signal handlers, global state, locale or FPU mutation | **absent** | *(assumption, Q4)* |
| Executing WebAssembly | **conditional** | only under the non-default `wasm` feature *(documented, docs/09-attestations.md §7.1)* |

**The build path** additionally, by design:

| Effect | Stance | Conditions |
| --- | --- | --- |
| Outbound HTTPS to registries and git hosts | **present** | resolution, fetch, checkout *(documented, docs/03-ecosystems.md)* |
| **Outbound HTTPS to any URL registry metadata names** | **present** | a package's own metadata chooses the host this machine connects to *(inferred, Q5)* |
| Spawning `git` | **present** | for a package's source, with `GIT_CONFIG_NOSYSTEM` and a restricted `GIT_ALLOW_PROTOCOL` *(documented, crates/trigon-registry/src/source.rs)*; for `trigon publish` and `trigon log init`, with the operator's own git configuration, where its credential helper is, `GIT_TERMINAL_PROMPT=0`, and `GIT_DIR` and its kin removed, so it writes its own clone and no other. Nothing in that configuration changes what is committed or read: `core.autocrlf` and the operator's attributes file are switched off, commits and pushes are never signed, a publication's files are staged as blobs of exactly their bytes rather than by `git add`, and a repository is looked for in the directory named and never above it (`GIT_CEILING_DIRECTORIES`) *(documented, crates/trigon/src/publish/git.rs)* |
| **Pushing to an evidence repository** | **conditional** | only `trigon publish`, `trigon log init`, `trigon log key-change` and `trigon log succeed`: one commit, pushed without force to the repository `--repo`, `TRIGON_PUBLISH_REPO` or `[publish] repo` names, over whatever transport that location names. A publication's signed checkpoint leaves the host only in that push; a push that loses is discarded, never forced (P34, D26). `log succeed --url` first clones the repository its first URL names into the temporary directory and asks it `git push --dry-run`, which sends nothing, and then, only once the old log's end is pushed, pushes a second commit there, the successor's first (P37) *(documented, crates/trigon/src/publish/mod.rs; docs/19-distribution-and-lookup.md §10 phase 5)* |
| **Fetching evidence repositories** | **conditional** | only `trigon evidence sync`; `trigon lookup`, `trigon check` without `--store`, and `verify-attestation --lookup`, each of which syncs every source it asks that is stale, once, before it answers anything, and says so — none under `--offline` or `--remote`, and no request per package after it; and `trigon publish` of runs or a withdrawal into a repository whose chain begins by continuing a log elsewhere, which syncs the configured source that reaches that log — and, where none serves, every configured source it did not just sync, however fresh; a dry run syncs none: `git clone` and `git fetch` of every location of every source synced, and of every location a log-end names for a successor in another repository, over whatever transport each names, with `git` run as `publish` runs it — never prompting, ssh in batch mode, no repository looked for above the clone, no credential on argv or in what is printed. A remote is cloned `--depth 1 --filter=blob:none --sparse` and set to check out `keys`, `log` and `records`, and a local path in full; a sync is a `fetch` of the branch and `reset --hard FETCH_HEAD`, never a pull. The branch is the repository's to name: it is refused unless `git` would make a branch of the name, and is fetched as `refs/heads/<branch>` after `--`, so no name is ever an option. A project's source is followed to a successor elsewhere only at an HTTPS location. Nothing is pushed (P39) *(documented, crates/trigon/src/evidence/sync.rs; docs/19-distribution-and-lookup.md §6)* |
| Writing the evidence cache | **conditional** | only what syncs a source: one clone per location at `<cache>/<name>/<sha256 of the location>/`, `<cache>` being `TRIGON_EVIDENCE_CACHE` or `$XDG_CACHE_HOME/trigon/evidence`, each with a `.git/info/attributes` that unsets every attribute that could make a checked-out file other than its blob. A clone is made beside where it goes, under a name beginning with a dot, marked unaccepted in its git directory, and only then moved into place; the mark comes off when the sync is accepted, and a clone still marked, or what a killed clone left, is made again. A clone a refused sync made is removed and one it moved is put back; a sync accepted removes, from the cache and never from the state, the clone of every location its source no longer names — no URL of it, and no successor location its chain reaches — and says which; `trigon evidence remove` removes a source's (P39) *(documented, crates/trigon/src/evidence/sync.rs — `forget_unconfigured`; crates/trigon/tests/lookup.rs — `a_sync_removes_the_clone_of_a_location_no_longer_configured`)* |
| **Fetching an evidence file on demand** | **conditional** | only `verify-attestation --lookup`: each evidence file the resolved record names is read from its clone's working tree where it is there, and otherwise from its objects, `git cat-file` at `HEAD` in the clone, run as `publish` runs `git` and only in a clone a sync accepted; where the clone is partial and does not hold the blob, `git` fetches it from the clone's remote, which names the record to that host. Whether it held the blob is asked first with lazy fetching off, and the report says which files were fetched and from where. Nothing is written but git's objects in the clone (P45, D35) *(documented, crates/trigon/src/evidence/rerun.rs — `GitFiles`; crates/trigon/src/publish/git.rs — `blobs_fetching`, `blobs_held`; docs/19-distribution-and-lookup.md §6, §7)* |
| **Outbound HTTPS for `--remote`** | **conditional** | only `trigon lookup --remote` and `trigon check --remote`: GETs, with no credential, from `https://raw.githubusercontent.com/<owner>/<repo>/HEAD/`, or the base `TRIGON_EVIDENCE_RAW_BASE` names (HTTPS, or plain HTTP to loopback only, and no user or password), of each source's `log/checkpoint`, the entry bundle and hash tiles of its last leaf, the checkpoint, first leaf and last leaf of each successor its chain reaches on github.com, the index file for each key asked, each record it lists, and the entry bundles and hash tiles that prove each record's leaf; a redirect is followed only to HTTPS. Every request after the first names the key asked about to GitHub. No git runs, no clone is made, and no state is written; a source with no `https://github.com/<owner>/<repo>` URL is refused before any request, exit 5, and so, with nothing requested, is one whose last sync was refused; each report says the three caveats of docs/19 §6 (P44, D36) *(documented, crates/trigon/src/evidence/remote.rs; crates/trigon/tests/lookup.rs — `remote_proves_inclusion_and_refuses_what_it_cannot_prove`, `remote_answers_unknown_for_what_it_cannot_read_and_holds_to_the_state`)* |
| Writing the evidence state directory | **conditional** | only what syncs a source: `<state>/<name>/`, `<state>` being `TRIGON_EVIDENCE_STATE` or `$XDG_STATE_HOME/trigon/evidence` — the checkpoint last accepted, the key history, the record of the last sync, and a lock two syncs of one source take turns on. The checkpoint and the key history are written only once everything is verified, each file whole by rename, and once the checkpoint is, the clones it was read from are kept whatever happens to the record of the sync; a sync that fails records only that it failed. `trigon evidence remove` removes a source's (P39) *(documented, crates/trigon-attest/src/state.rs; crates/trigon/src/evidence/sync.rs)* |
| Writing `evidence.toml` | **conditional** | only `trigon evidence add` and `remove`: the user's file, or the file `--config` or `TRIGON_EVIDENCE_CONFIG` names — made where it is not there — rewritten whole by rename beside the file a symlinked path leads to, the link kept, its permissions, comments and order kept, and only once the file as it would be loads under every rule; never a project's file *(documented, crates/trigon-attest/src/config.rs — `add_source`, `remove_source`)* |
| Reading a git credential | **conditional** | **never by Trigon.** The `git` that `publish` runs reads the operator's own — an SSH key, a credential helper, `GIT_ASKPASS` — and a missing one fails rather than prompts: `GIT_TERMINAL_PROMPT=0` for `git`'s own, and ssh runs with `BatchMode=yes`, added to a configured command that runs `ssh`, so neither a passphrase nor a host key is asked for. A program the operator configures to answer — a helper, an askpass, an ssh wrapper that is not `ssh` — runs as configured. A location carrying a credential is refused when it is parsed, so none is on argv, and what `git` prints is shown with any URL's user part replaced by `***` *(documented, crates/trigon-attest/src/location.rs; crates/trigon/src/publish/git.rs — `scrub`)* |
| **Outbound HTTPS to GitHub's REST API** | **conditional** | only `trigon publish` of runs with `[publish] rebuilt_artifacts = "github-release"`: to `https://api.github.com`, or the server `TRIGON_GITHUB_API` names (HTTPS, or HTTP to loopback only), and to the upload URL it names on GitHub's upload host or that server — listing the repository's releases and their assets, creating a release `rebuilt-YYYY-MM` or the next of its series, uploading each rebuilt artifact as `sha256-<hex>`, and removing an asset of that name GitHub left unfinished or reports no digest for, to upload it again — before the commit that names them. Redirects are not followed (P36) *(documented, crates/trigon/src/publish/release.rs)* |
| **Outbound HTTPS to GitHub's REST API, anonymously** | **conditional** | only `verify-attestation --lookup --rerun-comparison` given no `--rebuild`, for a verdict that signs its rebuilt artifact's sha256 and is not exact, where a repository that holds the resolved record's leaf — the source's own, or the successor's its chain went on in, and then every other source's that holds the record, but never one a project's `.trigon/evidence.toml` added where the record was resolved in the user's own — has a location on github.com, HTTPS or SSH; whatever this host's own `[publish] rebuilt_artifacts`, which governs only what `publish` uploads. Listing each such repository's releases, and the assets of the releases of its `rebuilt-YYYY-MM` series for the month the record was logged in and the months either side, where `publish` puts the asset, and of no other release, from `https://api.github.com` or the server `TRIGON_GITHUB_API` names (HTTPS, or HTTP to loopback only), with no token; and downloading the finished asset `sha256-<hex>` the verdict names from the download URL GitHub gives, HTTPS only — or, where that server is on loopback, loopback — redirects followed to the same, streamed into a new `0600` file, created exclusively, in a directory made `0700` for it under a name of 128 random bits in the temporary directory, refused past GitHub's 2 GiB, hashed as it is written and held to the verdict's digest, and removed with its directory when the command ends; a download that fails goes on to the next release that holds the asset. A download names the artifact, and so the record, to GitHub, and says so whether or not it was had (P45, D35). An exact verdict, a repository with no github.com location, and `--rebuild <file>` given make no request; GitHub refusing or unreachable is a check not made, exit 5 *(documented, crates/trigon/src/evidence/rerun.rs — `rebuilt_asset`, `wanted`, `candidates`, `fetch_asset`, `Download`, `a_download_is_made_where_no_other_user_can_reach_it`, `plain_http_is_followed_to_this_machine_alone`, `an_exact_verdicts_rebuilt_artifact_is_the_upstream_file_and_any_others_its_signed_asset`; crates/trigon/tests/lookup.rs — `the_rebuilt_artifact_is_found_by_the_record_and_its_source_alone`, `the_rebuilt_artifact_is_looked_for_only_where_publish_puts_it`, `the_rebuilt_artifact_is_not_had_where_github_cannot_be_asked`, `the_rebuilt_artifact_is_asked_of_the_repositories_that_hold_the_record`, `an_exact_verdict_re_derives_from_the_upstream_file_alone_and_never_asks_github`, `the_falsifying_command_re_derives_a_published_verdict`, `the_falsifying_command_across_a_succession_and_for_a_void`)* |
| **Reading a GitHub token** | **conditional** | only then: `GITHUB_TOKEN`, else `GH_TOKEN`, from the environment and nowhere else — never argv, never a file — and missing, the publication is refused before anything is written. It is sent only as the `Authorization` header, only to the API and to an upload URL on GitHub's upload host or the overridden API's own origin, and is in no URL, message or `Debug` print (P38, D28) *(documented, crates/trigon/src/publish/release.rs — `Token`, `may_carry_token`)* |
| Spawning `trigon log sign` | **conditional** | `publish`, `log init`, `log key-change` and `log succeed` run it as a child of the same binary — `log succeed` twice, with `--successor-key` to sign the final checkpoint and cosign it, and with `--continuing` to begin the successor; it, and not they, opens a log key. `log succeed` names the successor by `trigon log public-key`, a child too, and `log key-change` has `trigon log key-change-leaf`, a child that opens no socket, open the two attestation keys and sign the leaf — or, in a dry run, `trigon public-key`, a child that signs nothing, read their public halves — so the process that fetches and pushes opens neither kind of key (P35, P37) *(documented, crates/trigon/src/publish/mod.rs — `sign`, `key_change_leaf`, `public_key_of`)* |
| Spawning `podman` | **present** | the build *(documented, docs/08-execution.md §1)* |
| Spawning the Copilot CLI | **conditional** | only with `--model copilot:` *(documented, crates/trigon-ai/src/copilot.rs:177)* |
| Outbound HTTPS to a model endpoint | **conditional** | only when `--model` names a live provider *(documented, README.md "Asking a model")* |
| Binding a listening socket | **conditional** | `trigon watch` (loopback by default) and the mirror *(documented, crates/trigon/src/main.rs — `--bind` defaults to `127.0.0.1:8099`)* |
| Reading environment variables | **present** | API keys and base-URL overrides; **keys come from the environment and never the command line** *(documented, crates/trigon/src/inferrer.rs:527)* |
| Writing a work directory | **present** | fetched artifacts, build logs, rebuilt artifacts *(documented, docs/18-management-ui.md §2)* |
| Writing `<store>/publish/` | **conditional** | only `trigon publish`, `log key-change` and `log succeed`: the working clone of each repository they publish to, and the store's lock; and in a working tree published into in place, a lock file in its git directory *(documented, crates/trigon/src/publish/mod.rs; docs/19-distribution-and-lookup.md §2.4)* |
| Dropping a rebuilt artifact from the store | **conditional** | `trigon attest --prune`, as it always has, and `trigon publish --prune`, for each run it published, once the publication is pushed and recorded on the run; a divergence keeps its bytes. Where a publish repository is configured with `rebuilt_artifacts = "github-release"`, `attest --prune` refuses, before signing anything, a run not yet published whose publication would upload its artifact — not an exact rebuild, not one the gate calls void, and not the second of an agreeing pair whose first is published. The bytes are deleted only where no other run's record names them as kept — as its published artifact, or as the rebuild of the other attempt of an agreeing pair, which rebuilt the same bytes into one blob — and otherwise only this run's reference is dropped. Asking who names the bytes and deleting them hold `<store>/blobs.lock` alone, made where it is not there, which a run writing bytes it names as kept holds shared from before its `put` until its record is written (P42) *(documented, crates/trigon/src/publish/mod.rs — `prune_published`; crates/trigon/src/main.rs — `refuse_prune_before_publication`; crates/trigon-store/src/lib.rs — `prune_rebuild`)* |
| Writing a store from a file another machine made | **conditional** | only `trigon runs import`: the blobs, set manifests, statements and records the file carries, once all of it is checked, under the store's own names, never a statement over another (P47). `trigon runs export` writes the one file `--out` names and reads the store without writing to it *(documented, crates/trigon/src/transfer.rs)* |
| `trigon serve` reading the publisher's working clone | **conditional** | where a publish repository is configured: `git rev-parse` and `git ls-tree` in `<store>/publish/<…>/clone`, read-only, and the commit and time `publish` records in its `.git/trigon-fetched` once a fetch succeeds, to report the repository's kill-switch — on starting and every ten seconds after, on a blocking thread, never for a request; with no clone, or no record of a fetch that succeeded, the report is `unknown` *(documented, crates/trigon/src/publish/switch.rs; crates/trigon-api/src/lib.rs — `cached_switch`)* |
| Writing `$XDG_STATE_HOME/trigon/publish/` | **conditional** | only `trigon publish`, `log key-change`, `log succeed` and `trigon log sign`: the host's lock, which keeps one `publish` at a time on the host whatever store it runs from, and the newest checkpoint of each log the host has published or verified, named by the log's origin, which every later publication and signature there must extend (P34, P35) *(documented, crates/trigon/src/evidence_log.rs — `NewestPublished`; docs/19-distribution-and-lookup.md §2.4)* |

---

## 1.6 Build-time and configuration variants

**Support posture, not defaultness, decides routing.** A defect in a supported configuration is in
model even when that configuration is not the default.

| Knob | Default | Stance | Effect |
| --- | --- | --- | --- |
| `build` feature | **on** | supported | Adds registry, sandbox, mirror, store, AI, a tokio runtime and a network client. Turning it off is the verifier, and is the *stronger* posture. |
| `wasm` feature | **on in the full build** (`build` enables it); **off in the verifier** unless `--features wasm` | supported | Runs an archived stabilizer set rather than only naming it: `attest` runs the module it names in a verdict, and `verify-attestation` the one a verdict under a set the binary does not carry names. It roughly doubles the verifier's dependency tree, and the small tree is what a sceptic checks, so the verifier stays without it and says which build runs one *(documented, crates/trigon/Cargo.toml; docs/09-attestations.md §7.1)*. See D18, D39. |
| `--egress open` | **the default for `rebuild` and `sweep`** | **supported, and it voids the strong claim** | The build reaches the whole internet; the run records `attestable: false` *(documented, README.md "A note on `--egress open`")*. |
| `--public-key` on `verify-attestation` | **absent** | supported | Without it the tool re-derives the comparison and reports the signature as **present and unchecked** rather than verified. "Unsigned" and "signed by someone you did not check" are different things, and the tool distinguishes them *(documented, README.md "Signing it, and checking the signature")*. |
| `local-unsafe` runner | not the default | **dev-only** | Labelled development-only and refuses to sign *(documented, docs/08-execution.md §1)*. A finding that needs it closes `OUT-OF-MODEL: non-default-build`. |
| `[publish] same_host_confirmation` | **off** | supported | The publication gate counts a confirmation made on the machine that made the first attempt, where nothing warm could supply it and its base image was pulled again by digest. It tests nothing that machine holds constant (D37) *(documented, docs/19-distribution-and-lookup.md §2.4, D8)*. |
| `[publish] same_host_local_images` | **off** | supported | Read only beside `same_host_confirmation`: such a confirmation may run on a local base image — one no registry digest names, as those built on that machine — pinned by its full content id, which no registry serves again for it (D38). Set alone it changes nothing, and the commands that read it say so in a note *(documented, docs/19-distribution-and-lookup.md §2.4, D8; docs/16-findings.md §3.105)*. |

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
| `StabilizerSet` resolution | a set id, and the `.wasm` module it resolves to | **the id and the module's sha256 come from a signed verdict; the module's bytes from `--stabilizers` or the record's evidence** | resource-name, collaborator-implementation, x-wasm-module | a module is run only when its sha256 is the `stabilizerSetModule` the signed verdict names, or, for a statement that names none, when the operator passes it; that binding, and not the set digest the module reports of itself, is what makes it trustworthy (P23, D39); an id alone executes nothing | *(documented, docs/09-attestations.md §7.1; crates/trigon-attest/src/verify.rs — `check_set_module`)* |
| `Registry::resolve` | registry response JSON | **yes** | data, size, serialized-state, object-topology | nothing; shape errors surface as `RegistryError` | *(documented, crates/trigon-registry/src/npm.rs — fields are read, not schema-validated)* |
| `Registry::fetch` | `meta.url` | **yes — a package's metadata chooses the host this machine contacts** | resource-name | the operator accepts that resolving a package means contacting hosts that package names | *(inferred, Q5)* |
| `Registry::fetch` | response body | **yes** | data, size | hashed as it streams and checked against **every** digest the registry declares that this build can compute, and refused on the first mismatch: npm's whole `integrity` string and its `shasum`, PyPI's `digests`, crates.io's `checksum`, and NuGet's catalog `packageHash`. PyPI's `blake2b_256` is recorded as declared and unchecked; a NuGet version whose catalog carries no hash is recorded as declaring nothing, and a catalog that cannot be read refuses the download. The run records each declaration and what checking it found (`RunRecord.upstream_digests`) | *(documented, crates/trigon-registry/src/declared.rs; docs/16-findings.md §3.95)* |
| `SourceCache::checkout` | `repo` | **yes** | resource-name, x-git-remote-url | **https only**, enforced here | *(documented, crates/trigon-registry/src/source.rs)* |
| `SourceCache::checkout` | `commit` | **yes** | x-git-ref | **40 hex characters only**, so a ref cannot be an option or a path | *(documented, crates/trigon-registry/src/source.rs)* |
| `Checkout::files` / `read` | repository contents | **yes** | data, object-topology | nothing — this is what the Builder reads | *(documented, docs/16-findings.md §3.7)* |
| strategy inference | `package.json` `scripts.build` | **yes** | data, x-shell-script | nothing here; the environment is the enforcement point | *(documented, docs/12-security.md §5)* |
| strategy inference | npm's `_nodeVersion` and `_npmVersion`, and the script a release workflow runs as `npm run <name>` | **yes** | data, resource-name, x-shell-script | lowered into a tool only as a plain `x.y.z` and a bare name (`is_plain_version`, `bare_program`), on the heuristic rung and on the CI rung that displaces it; otherwise the rung declines by name, and a `_nodeVersion` built from master is left to the heuristic, which replaces it with the nearest release and says so | *(documented, docs/16-findings.md §3.104; crates/trigon-registry/tests/ci.rs — `the_values_the_heuristic_checks_are_checked_before_they_are_lowered`)* |
| `strategy` parse | a strategy document | **yes when a model or a package authored it** | data, x-shell-script, x-model-output | **schema validation is not sanitization** — a `runs:` step is free-form shell | *(documented, docs/04-strategies.md §7)* |
| `strategy` render | template context | no — a closed type | type-class | undefined variables are a hard error | *(documented, docs/04-strategies.md §3)* |
| `strategy` render | a value a rung read from outside the strategy: a .NET version stamp or copyright, a `package.json` script body, a registry's versions and publish time, a wheel's `Generator:`, a workflow's directory and script | **yes** | data, x-template-source | nothing — it is carried as the step's `literal` and never parsed as a template (P46) | *(documented, docs/04-strategies.md §3.3; docs/16-findings.md §3.104)* |
| build container | everything the build runs | **yes, by design** | x-shell-script | the egress tier and the container are the boundary | *(documented, docs/08-execution.md §5)* |
| mirror `/-artifact/`, `/-toolchain/` | request host and path | **yes, from inside the build** | resource-name | compiled-in exact-match host allowlists — but these routes are **not** access-controlled and the artifact route applies **no** time filter | *(documented, docs/16-findings.md §3.13)* |
| mirror index route | the time filter, in basic auth | **readable from inside the build** | data | an index request with no filter is refused 400 | *(documented, crates/trigon-mirror/src/server.rs)* |
| egress guard | every proxied response body | **yes** | data, size, rate | hashed as it streams; a whole-artifact or member match voids the run | *(documented, docs/12-security.md §2.2)* |
| build output directory | file entries the build wrote | **yes** | data, resource-name, object-topology | **symlinks are not followed** | *(documented, docs/16-findings.md §3.12; crates/trigon-sandbox/src/podman.rs:691)* |
| store record paths | package name, namespace, version | **yes** | resource-name | nothing here — `object_store`'s `Path` percent-encodes `..` and `/` inside a component, so a name cannot escape the store root. **The safety is the dependency's, not ours** (§1.9) | *(documented, crates/trigon-store/src/lib.rs:204; verified against object_store 0.12: `..` → `%2E%2E`)* |
| `trigon runs import` | the file: its manifest, run records, blobs, statements and stabilizer-set manifests | **yes — whoever made it, and anything that held it on the way** | data, size, object-topology, resource-name, serialized-state | nothing for the file — P47: it is read within the ceiling an artifact may expand to and never decompressed, every entry a regular file at a path an export writes, every blob held to its name, every record to its file name, every file a record names carried, and nothing written until all of it is checked. **The records' claims — host id, start time, cache state, image pin — are the maker's word, trusted as a store's co-writer's are, and so is what `rebuild --confirm` of an imported run repeats: the strategy the file carries, the source it fetches and the commands it runs, on the base image and at the egress tier the record names (D40)** | *(documented, crates/trigon/src/transfer.rs — tests `an_import_is_checked_whole_before_anything_is_written`, `a_run_already_here_is_left_alone_or_refused_and_nothing_else_is_written`, `a_run_filed_here_after_the_import_looked_is_never_written_over`, `a_failed_import_leaves_no_record_naming_blobs_that_are_not_there`)* |
| `verify-attestation` | the bundle | **yes** | data, serialized-state | the signature is checked only with `--public-key`, and the tool says which it did | *(documented, README.md)* |
| `verify-attestation --record` | the record file | **yes** — anyone's bytes until it is checked | data, serialized-state | nothing — P31: its sha256 must be a verified leaf's, and one leaf's only, every envelope must verify under the key its source had at that leaf, its statement must agree with the leaf, its unsigned map with its statement, and every evidence file present with its digest; a record no leaf names is unlogged and fails, and so does one the log holds twice | *(documented, docs/19-distribution-and-lookup.md §4.1, §8; crates/trigon-attest/tests/evidence_repo/records.rs)* |
| `verify-attestation --record` | the evidence directory: `log/`, `records/`, `evidence/`, `index/` | **yes — whoever can push to the repository, or serves a copy of it (A8, A9)** | data, size, object-topology, resource-name | nothing — P32, P33: the log is verified whole under the pinned log key, and against the checkpoint last accepted, before a record is read; every file is read inside the directory, as a regular file of at most its kind's length; `index/` is never read; a leaf whose record file is missing is deleted | *(documented, docs/19-distribution-and-lookup.md §6, §8; crates/trigon-attest/src/log/files.rs; crates/trigon-attest/tests/evidence_repo/)* |
| `trigon publish` | the evidence repository it fetches: `keys/`, `log/`, `records/`, `evidence/`, `index/`, `feed/`, `kill-switch`, `README.md` | **yes — whoever can push to it, or serves it (A8, A9)** | data, size, object-topology, resource-name | nothing — P34: the chain of logs `keys/log.vkey` begins must end, in this repository, at `[publish] origin`'s log; the feed and the README's account of rotations are regenerated from the log, never edited; a branch that names git attributes is refused before it is checked out; the log is verified whole under it, and against the newest checkpoint of the log this host has published or verified, whatever store or spelling of the location, before anything is built on it; nothing past the checkpoint is read; a file at a path a publication writes is replaced, never written through, and a link where it writes a directory, or planted as `index`, is refused; its `.gitignore` changes nothing committed; where the repository's chain begins by continuing a log in another repository, the chain before it is read through a configured source, verified as `evidence sync` verifies one, and followed into this repository's first log | *(documented, docs/19-distribution-and-lookup.md §2.4, §8, §10 phase 5; crates/trigon/tests/publish.rs)* |
| `trigon log sign` | the tree it is handed | **yes — `publish` wrote it over such a clone** | data, size, object-topology | nothing — P35: it signs only a tree extending a checkpoint its own key opens and the newest checkpoint of the log published from this host, whose every new leaf names a record every client would accept, is a heartbeat, a key change from the current key signed by both, or a log-end naming the key `--successor-key` holds, and reads nothing past the size it is told to sign; the checkpoint it writes is renamed over the old from a file made new, never written through a link | *(documented, crates/trigon-attest/src/evidence/sign.rs; crates/trigon-attest/tests/evidence_repo/sign.rs)* |
| `trigon log sign --continuing` | the tree holding the log it continues, and the successor's first tree | **yes — `log succeed` wrote both over clones of repositories whoever can push writes** | data, size, object-topology | nothing — P37: a successor is begun only as the log a verified chain's log-end names by its key, from a log-continuation holding that log's final checkpoint signed by both log keys and logged no earlier than the log-end, extending what this host published of the old log, and held to `follow` before it is signed | *(documented, crates/trigon-attest/src/evidence/sign.rs — `check_to_begin`; crates/trigon-attest/tests/evidence_repo/sign.rs — `a_successor_is_begun_only_as_the_one_its_predecessor_names`)* |
| `trigon evidence sync` | the repositories it clones — every location of a source, and every successor location a log-end names: `keys/`, `log/`, `records/` | **yes — whoever can push to them, or serves them (A8, A9)** | data, size, object-topology, resource-name | nothing — P39, P40: every clone is verified whole under the source's keys before anything from it is accepted, and every location is held to every other; the chain is held to the checkpoint last accepted; a clone's files are read inside it, as regular files of at most their kind's length, and exactly as their blobs, whatever attributes the tree names; the default branch a clone takes from the repository is refused unless `git` would make a branch of the name, and reaches `git` only as `refs/heads/<branch>` after `--`, never as an option | *(documented, docs/19-distribution-and-lookup.md §6, §6.1, §8; crates/trigon/tests/evidence.rs — `a_repositorys_own_attributes_never_change_what_is_verified`, `a_branch_named_as_an_option_is_never_fetched`)* |
| `trigon evidence sync`, trusting on first use | `keys/log.vkey` and `keys/attestation.pub` of the first location reached that holds a log, on the source's first sync; one serving no log at all is passed over, with a note | **yes — whoever serves that location at first contact** | data | the operator, who chose trust on first use: nothing checks the keys against anything else. They are recorded in the state directory, pin every later sync, and every answer from the source says it rests on them (D33) | *(documented, docs/19-distribution-and-lookup.md §2.4, §6.1; crates/trigon/tests/evidence.rs — `trust_on_first_use_is_recorded_once_and_every_answer_says_it_rests_on_it`, `trust_on_first_use_reads_its_keys_from_the_first_location_holding_a_log`)* |
| `trigon lookup`, `trigon check`, `verify-attestation --lookup` | a source's clones, as a sync left them: `keys/`, `log/`, `records/` | **yes — whoever can push to the repository, or serves it (A8, A9)** | data, size, object-topology, resource-name | nothing — P43: every answer is read from the chain P39–P41 verified, opened again from the clones against the checkpoint last accepted before anything is answered, never from `index/`; each record is held to its leaf and its source's keys at that leaf, and a record at a leaf of one source's log is never judged under another's keys | *(documented, docs/19-distribution-and-lookup.md §6, §6.1, §8; crates/trigon/tests/lookup.rs)* |
| `trigon check` | the lockfile or SBOM | **yes — chosen by whoever controls the project**: in CI on a pull request, by its author | data, size, resource-name | nothing that makes it an answer: each package is looked up by every digest it declares that a record is filed under, and by its purl only where no digest finds one; a purl whose records are all about another artifact than every digest declared is never checked, not answered; a package with neither is never checked, never left out; a file that will not parse is exit 5, and one named as a kind this does not read is refused by its name; nothing in it is fetched — `resolved` is kept and said, never followed | *(documented, crates/trigon-core/src/lockfile.rs; crates/trigon/src/evidence/check.rs; crates/trigon/tests/lookup.rs — `check_holds_answers_to_the_threshold_and_refuses_what_it_cannot_read`)* |
| `trigon lookup --remote`, `trigon check --remote` | the files served under the raw base: the checkpoint, tiles, entry bundles, index files and records | **yes — GitHub, whoever can push to the repository, and anything between (A8, A9)** | data, size, resource-name | nothing — P44: the checkpoint is opened under the pinned key and held to the checkpoint last accepted by a consistency proof from the tiles; a successor is followed only where its first leaf, proven, is the log-continuation its predecessor's log-end requires; every record's leaf is read from its entry bundle and proven included from the hash tiles against the signed root, and one that does not prove fails verification, while one whose proof or record cannot be read — not served, refused, rate-limited, or listed past the checkpoint read — leaves the source unknown for that question; an index file served for another key, or naming a leaf that is not the record's, lists nothing that is answered; every file is read up to its kind's length | *(documented, docs/19-distribution-and-lookup.md §6; crates/trigon/tests/lookup.rs — `remote_proves_inclusion_and_refuses_what_it_cannot_prove`, `remote_answers_unknown_for_what_it_cannot_read_and_holds_to_the_state`, `remote_follows_a_succession_only_through_its_continuation`)* |
| `verify-attestation --lookup` | the evidence files fetched on demand, the rebuilt artifact downloaded from a release asset, and the log keys the configured sources give the origin asked for | **yes — whoever can push to the repository, or holds a token that writes its releases (A8); and, for a source a project's `.trigon/evidence.toml` adds, the thing under test** | data, size, resource-name | nothing — P45: each evidence file is held to the digest the signed statement names, and one that is other bytes fails the record; the release asset — looked for only in the `rebuilt-YYYY-MM` releases, of the record's month and the months either side, of the repositories that hold the record, never by the consumer's own setting, and never in the repository of a source a project's `.trigon/evidence.toml` added where the record was resolved in the user's own — is held to the rebuilt artifact's digest the verdict signs as it is written, and one that is other bytes is refused: exit 4 in the repository of the source the record was resolved in, and in another source's a check not made, exit 5, since those bytes are that repository's and not the record's; a project's source that gives the origin to a key of its own is set aside where the user's own sources hold it, and sources that give it to two keys otherwise are refused as ambiguous | *(documented, crates/trigon/tests/lookup.rs — `the_falsifying_command_re_derives_a_published_verdict`, `the_falsifying_command_is_answered_in_its_origins_log_alone`, `the_rebuilt_artifact_is_found_by_the_record_and_its_source_alone`, `the_rebuilt_artifact_is_asked_of_the_repositories_that_hold_the_record`)* |
| `trigon publish` of rebuilt artifacts | GitHub's answers: the releases and assets it lists, the upload URL a release names, an uploaded asset's state, size and digest | **yes — GitHub, and whoever holds a token with contents-write on the repository (A8)** | data, resource-name | nothing — P36, P38: an asset of an artifact's name is taken for it only where GitHub reports its digest and its size and digest are the artifact's, one of another size or digest is refused, and one GitHub reports no digest for is uploaded again in its place; no asset is put in a draft release; the token is sent to an upload URL only on GitHub's upload host, or the overridden API's own origin, no redirect is followed, and a refusal that quotes the token back has it taken out; nothing GitHub says reaches the log or a record, which names the asset by the digest its verdict signs | *(documented, crates/trigon/src/publish/release.rs — `the_token_goes_only_to_the_apis_upload_host`, `the_token_is_in_no_print_and_no_refusal`; crates/trigon/tests/publish.rs — `a_rebuilt_artifact_is_a_release_asset_uploaded_before_its_record_is_committed`, `an_asset_is_reused_on_retry_and_a_full_release_continues_its_series`, `an_asset_of_the_artifacts_name_is_taken_for_it_only_when_it_is_it`, `the_token_goes_to_no_other_host_and_no_asset_into_a_draft`)* |
| `trigon serve` | the `kill-switch` of the publish repository, as the publisher's working clone last fetched it | **yes — whoever can push to the repository (A8)** | data | nothing: it is reported as set wherever git lists anything of that name, clear only where it lists nothing, and unknown where nothing could be read, with when the fetch that succeeded began; it gates nothing `serve` shows, which only `--stop-divergences` does; where it is read from is shown to an operator only; and it is read on a timer, never for a request | *(documented, docs/19-distribution-and-lookup.md §3; crates/trigon-api/tests/seam_kill_switches.rs; crates/trigon/tests/publish.rs — `serve_reports_the_repositorys_kill_switch_beside_its_own`, `serve_reports_the_switch_as_of_the_last_fetch_that_succeeded`)* |
| `trigon watch` `GET /run/{index}` | the path segment | **yes if the port is reachable** | data, resource-name | parsed as an integer and re-formatted; never joined as a caller-supplied path | *(documented, crates/trigon/src/watch.rs)* |
| `trigon watch` all views | package names, build logs, strategies | **yes** | data, size, x-build-log | every package-derived string is HTML-escaped on the way out | *(documented, crates/trigon/src/watch.rs — `esc`)* |
| model prompt | README, CI config, manifests, build log | **yes** | data, x-build-log | **nothing prevents injection**; it is fenced, bounded and control-stripped, and accepted as residual risk | *(documented, docs/12-security.md §4)* |
| model response | the proposed strategy | **the model's, and so indirectly the attacker's** | x-model-output | parsed and validated; the provenance cap bounds the damage | *(documented, docs/00-overview.md §3.1)* |
| definitions repository | a `build.yaml` or a custom stabilizer | **yes, via a merged pull request** | data, x-shell-script, collaborator-implementation | two-party review, a mandatory prose `reason:`, and the corpus-wide impact preview | *(documented, docs/12-security.md §8)* |
| evidence sources — the configuration (`trigon_attest::config`) and `trigon evidence` | a project's `.trigon/evidence.toml`, read from the working directory | **yes — chosen by the thing under test**: in CI on a pull request, by the pull request's author | data, resource-name, x-git-remote-url | nothing; Trigon holds the file to less than the user's own configuration. It may only add `[[source]]` entries, each under a new name, with both keys and an initial checkpoint pinned and HTTPS URLs only, and any file it names — a PEM key, the checkpoint — must be inside the working directory once symlinks are followed, as must the file itself, which is also a regular file of at most 64 KiB; a file that tries anything else is refused whole, with the rule it broke and its strings escaped, and a parse error gives a line and column without quoting the file; and every answer from such a source names the file that added it. It can add a claim and cannot change what any other source answers. A source it adds is synced like any other, and the log-end its pinned key signs is followed only to HTTPS locations, a successor at any other refused, so the file never chooses where the client connects, or with which of the user's credentials; `evidence sync`, `evidence list` and the standing every command asking it reads name the file, and `evidence remove` leaves it to the project | *(documented, docs/19-distribution-and-lookup.md §2.4, §8; crates/trigon-attest/tests/evidence_config.rs — `a_project_file_that_breaks_a_rule_is_refused_whole_with_the_rule`, `a_project_file_that_links_outside_the_project_is_not_read`; crates/trigon/tests/evidence.rs — `a_projects_file_is_held_to_its_rules_and_its_sources_name_it`, `a_projects_source_follows_its_successor_over_https_only`)* |

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
| archive-parsing | resource-complexity | claimed | every cap is enforced against produced bytes, not declared sizes, and gzip members, which cost time and no bytes, are counted across the artifact; the ceiling's *size* is what D1 disclaims | P1 |
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
| archived-stabilizer-sets | callback-execution | **disclaimed** | an archived set is code the operator chose to run, or the one a signed verdict names by digest; wasmtime's sandbox is the boundary and it is a dependency's guarantee | D21 |
| archived-stabilizer-sets | serialization-reconstruction | claimed | the archived set is proved to agree with the compiled one: by the parity test, and by `attest`, which names a module only once it reproduces the run's stabilized digests; a verifier runs only the module whose sha256 the verdict signs | P23 |
| archived-stabilizer-sets | reference-lifecycle | N/A | the module instance lives for one call | — |
| archived-stabilizer-sets | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| archived-stabilizer-sets | resource-complexity | **disclaimed** | memory growth inside the module is the module's | D21 |
| archived-stabilizer-sets | x-provenance-cap | **disclaimed** | the cap cannot be confirmed from bytes alone: a `normalized` claim re-derives as `normalized_with_caveats` and is reported *consistent*, neither held nor refuted, and its tier is not re-derived | D18 |
| comparison-and-verdict | numeric-domain | N/A | compares digests and counts; takes no sizes from the input | — |
| comparison-and-verdict | failure-atomicity | claimed | a set mismatch refuses before comparing, classified `Fault::Bug` | P4 |
| comparison-and-verdict | recursive-cyclic-topology | claimed | the diff walks the archive model's bounded tree | P1 |
| comparison-and-verdict | callback-execution | N/A | no callbacks | — |
| comparison-and-verdict | serialization-reconstruction | claimed | outcomes cross the wire as strings, `FromStr` the exact inverse of `Display` | P24 |
| comparison-and-verdict | reference-lifecycle | N/A | borrows for the call's duration and retains nothing | — |
| comparison-and-verdict | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| comparison-and-verdict | resource-complexity | claimed | linear in members; each side is walked at most twice | P25 |
| attestation | numeric-domain | N/A | no arithmetic on attacker-supplied values | — |
| attestation | failure-atomicity | claimed | no path signs a void run as anything but `void/v1`: `trigon attest` and `rebuild --attest` share the code | P6 |
| attestation | recursive-cyclic-topology | claimed | JCS refuses what another implementation might not reproduce | P9 |
| attestation | callback-execution | claimed | `Signer` and `ArchivedSet` are operator-chosen collaborators, named on the command line | P26 |
| attestation | serialization-reconstruction | claimed | canonical JSON is byte-stable; floats, integers beyond ±(2^53 − 1) and non-ASCII keys are refused, not coerced | P9 |
| attestation | reference-lifecycle | N/A | a statement is built, signed and dropped within one call | — |
| attestation | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| attestation | resource-complexity | disclaimed | a statement is as large as the difference summary it carries | D9 |
| attestation | x-record-verification | claimed | a record is shown verified only when its leaf, the key its source had at that leaf, its statement, its unsigned map and every evidence file present all check | P31 |
| attestation | x-log-inclusion | claimed | an answer comes only from a record the verified log holds, found from its leaves and never from `index/` | P32 |
| attestation | x-log-consistency | claimed | the log is verified whole under the pinned key, and against the checkpoint last accepted; two trees under one key is refused | P33 |
| attestation | x-log-signing | claimed | the log key signs only a tree extending a checkpoint it opens itself, whose new leaves name records every client would accept | P35 |
| attestation | x-rotation | claimed | a key change is logged only from the current key, signed by both; a log ends only where the step signing holds the successor's key, and a successor is begun only as the log its predecessor's log-end names | P37 |
| strategy-rendering | numeric-domain | N/A | no arithmetic on strategy values | — |
| strategy-rendering | failure-atomicity | claimed | an unregistered `uses:` is a hard error naming the tool, never an empty fragment | P27 |
| strategy-rendering | recursive-cyclic-topology | claimed | tool composition is acyclic at load and depth-bounded at render | P27 |
| strategy-rendering | callback-execution | **disclaimed** | a `runs:` step is free-form shell and nothing here sanitizes it | D2 |
| strategy-rendering | serialization-reconstruction | claimed | `strategy_digest` is canonical and domain-separated | P28 |
| strategy-rendering | reference-lifecycle | N/A | rendering borrows and returns owned strings | — |
| strategy-rendering | concurrency-reentrancy | disclaimed | no statement is made | D8 |
| strategy-rendering | resource-complexity | claimed | render depth is bounded | P27 |
| strategy-rendering | x-template-source | claimed | a value a rung read from the package, its registry document or its repository is the step's `literal`, handed on as written and never parsed as a template | P46 |
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
| operator-surface | x-publication | claimed | `publish` builds only on a remote log it has verified, writes nothing the gate withholds, and pushes one commit, never forced | P34 |
| operator-surface | x-release-assets | claimed | a rebuilt artifact is found or uploaded, by the digest its verdict signs, before the commit that names it | P36 |
| operator-surface | x-credential | claimed | the GitHub token is read from the environment and sent only to GitHub, in a header | P38 |
| operator-surface | x-evidence-sync | claimed | a source is accepted only verified whole and against the checkpoint last accepted, its state written only then; a refused sync keeps every clone and the state as they were | P39 |
| operator-surface | x-mirrors | claimed | every location of a source is one log with every other, or the sync is refused as an equivocation | P40 |
| operator-surface | x-freshness | claimed | a stale source is synced first or answers unknown, a frozen one answers unknown, a refused one is exit 4 for every package | P41 |
| operator-surface | x-evidence-lookup | claimed | every answer is from a verified chain's leaves, per source and never merged, every §4.2 state told apart with its §6 exit code, and a record judged only under its own source's keys | P43 |
| operator-surface | x-remote | claimed | every record `--remote` answers from has its leaf proven included in a checkpoint held to the one last accepted, a successor is followed only through its log-continuation, one whose leaf does not prove fails verification, and one it cannot read is unknown | P44 |
| operator-surface | x-falsifying-command | claimed | `--lookup` resolves only in the source of the origin it names, never in a project's source that gives the origin to another key than the user's own, weighs every source it asks, and holds every file it fetches to the digest signed for it | P45 |
| operator-surface | x-store-retention | claimed | pruning deletes bytes only where no other record names them as kept, and bytes a record says are kept and the store lost are reported missing | P42 |
| operator-surface | x-run-import | claimed | an import writes nothing until the whole file is checked, nothing no record in it names, no statement over another, and each record after the blobs it names | P47 |
| operator-surface | x-run-import-claims | disclaimed | an imported record's host id, start time, cache state and image pin are its maker's, and the gate's same-host rule compares them as they came; `rebuild --confirm` of it repeats the strategy, base image and egress tier it names | D40 |
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
| the signed attestation | **constrained** | canonical JSON; floats, integers beyond ±(2^53 − 1) and non-ASCII keys refused rather than coerced | that a signature was checked — without `--public-key` the tool re-derives and reports the signature present and unchecked *(documented, README.md)* |
| the `verify-attestation --record` report | **constrained** | each state of docs/19 §4.2 told apart, from a log verified whole, with its §6 exit code; every §4.2 field shown as signed — set, run, versions, egress tier and `attestable`, derivation, and for a verdict the falsifying command and dispute pointer — and absent shown as absent; evidence absent from the directory, or a release asset, and whatever of a comparison report it was not held to, listed as unchecked; *unknown*, exit 4, where the log continues in a repository the directory does not hold; the checkpoint of the log it read, as the `checkpoint <origin> <size> <root>` line every report prints, and as `checkpoint` in JSON | that an unchecked evidence file was checked; that the answer is current — it is the log as the directory holds it, checked against the checkpoint given or against none, with no freshness clock (D25); or that a record verified in one source says anything in another *(documented, docs/19-distribution-and-lookup.md §4.2, §6, §6.1)* |
| a publication to an evidence repository (`trigon publish`) | **constrained** | one commit, pushed without force, holding records `check_record` accepts at the leaves they are logged at, the evidence they name, tiles and bundles that extend the checkpoint the remote held, a checkpoint `trigon log sign` signed, and index files derived from the log | that the commit's author vouches for anything — it is `trigon publish`, whoever ran it, and a client never treats who committed a file as who signed it; or that `index/` is authoritative: the log is *(documented, docs/19-distribution-and-lookup.md §2.3, §8)* |
| a `trigon runs export` file | **same as input** — it carries the runs' artifacts and the exporting store's records | an uncompressed tar of regular files, the same bytes for the same runs, every blob named by its sha256, and one `trigon runs import` accepts | that anything in it is true because it is there: its records' claims are the exporting store's (D40), its artifacts are packages' own builds, and once it leaves the machine it is anyone's bytes, which `import` checks again (P47) *(documented, crates/trigon/src/transfer.rs)* |
| `trigon evidence sync` and `evidence list` | **constrained** | each source's standing by the two clocks — fresh; usable from its clone after a failed sync, until it is stale; unknown when stale or never synced; frozen; refused — from clones verified as P39 verifies them; the file that added it; whether its keys rest on first use; the checkpoint accepted, which it answers from, as the `checkpoint <origin> <size> <root>` line every report prints, and as `checkpoint` in `list`'s JSON; a refusal printed with both signed notes, exit 4 | that a fresh source is current: within `stale_after` and `frozen_after` a newer checkpoint withheld is not detected (D32); that keys trusted on first use are the log's (D33); that a source can answer at all (D34); or that `list` fetched anything — it touches no network *(documented, docs/19-distribution-and-lookup.md §6, §6.1)* |
| `trigon lookup` and `trigon check` reports | **constrained** | per source, never merged: its name, the file that added it, the keys it rests on where first use chose them, the checkpoint it answered from — the one accepted, or under `--remote` the one fetched and verified — as one `checkpoint <origin> <size> <root>` line, the same in every report, and as `checkpoint` in JSON and SARIF; every record with the §4.2 fields as signed, a superseded one struck through with the reason and both leaves, a deleted one without its outcome, a failed one with why; sources that disagree said to; sha1 alone said to be collision-broken; §6's exit code, and the same detail in JSON and SARIF | that an answer is current beyond what D32 bounds, or that two users whose checkpoint lines match have seen everything logged — only that they were shown one tree at that size; that a package never checked is safe, or that one is `exact` because a *different* source says so; that `--remote` saw every supersession (D36); that a record's evidence was checked — `lookup` and `check` read none of it, and say which files went unchecked *(documented, docs/19-distribution-and-lookup.md §4.2, §6, §6.1)* |
| `verify-attestation --lookup` report | **constrained** | the `--record` report of the current record, resolved in the source of `--origin`, with the evidence files it fetched and from where, and the release asset it downloaded; every other source it asked, with what it says and its checkpoint (`otherSources`); where no record is current, what every source it asked says, each with its checkpoint (`sources`) | that the rebuilt artifact was built independently — a release asset is the publisher's own bytes, so re-deriving from it checks the arithmetic, not the build (§1.12); or that a record not current in the source was checked *(documented, docs/19-distribution-and-lookup.md §4.2 item 6, §6)* |
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

A8 and A9 are adversaries of the evidence store ADR-0014 decides and
`docs/19-distribution-and-lookup.md` designs. What reads an evidence repository is built, as the
network-free verifier's `verify-attestation --record`, and holds a record and its log to P31–P33
against both. What writes one is built too, `trigon publish`, `trigon log sign`, `trigon log
key-change` and `trigon log succeed`, and holds to P34–P38 against a repository A8's push
credential, A8's GitHub token or A9 has touched. What syncs one is built as well, `trigon
evidence`, and holds a source to P39–P41 against both; and what answers from it — `lookup`, `check`,
`verify-attestation --lookup`, `--remote` — holds to P43–P45. What the standalone client of docs/19
§10 phase 9 would do exists only in `docs/`, and a finding that needs it routes by §1.3.

**A8 — The operator of an evidence repository a client trusts.** Whoever holds a configured
source's keys or its push credential: its operator — us, for our own repository — or a thief. What
each holding can do differs, and the client is built around the difference *(documented,
docs/19-distribution-and-lookup.md §8; ADR-0014 "What this costs")*:

- **A stolen attestation key** alone produces records no client accepts, because a client requires
  every record's leaf in the log it verified.
- **A stolen log key** signs, for any one client, a tree that extends the newest checkpoint that
  client holds and differs from the real log after it: a fork the client cannot detect alone, which
  can omit a withdrawal or a supersession. It cannot forge a record. With both keys, the holder can
  publish anything clients accept.
- **A stolen push credential** can delete and withhold files, add or remove the kill-switch, write
  feed entries nobody signed, which the next publication of a divergence or `--reconcile`
  regenerates from the log (D29), and plant files beyond the checkpoint. It cannot make a client
  accept a record, and it cannot make `publish` build on a log that does not verify or `log sign`
  sign a leaf it did not check (P34, P35).
- **A stolen GitHub token** with contents-write on the repository — the one `rebuilt_artifacts =
  "github-release"` uploads with — can do what the push credential can, and replace or delete a
  release asset. A record names its rebuilt artifact by the digest its verdict signs and no release,
  so an asset replaced is a file a reader holds to that digest, and one deleted is unavailable, not
  forged (P36, D28).
- **Silent retraction or equivocation** by the operator itself: rewriting the repository's history,
  deleting a record, or serving different clients different logs. Every client recomputes the whole
  log, so a rewrite is provable by anyone holding an older checkpoint, and a record whose leaf is
  logged and whose file is gone reads as deleted. Nothing *prevents* either until witnesses cosign
  (docs/19 §10 phase 7b), and nothing bounds a stolen key in time (D24).

**A9 — A host or mirror serving a stale or split view.** GitHub, a mirror, or anything between them
and a client, holding no key. It can serve an old but consistent clone, withhold a newer
checkpoint, or serve different clients different histories; it cannot sign a checkpoint or a record.
A source whose newest leaf is older than `frozen_after` answers unknown, so an old state cannot turn
a withdrawal back into a verdict; a client that syncs several mirrors of one source requires their
checkpoints to be consistent and reports a mismatch as an equivocation (P40, P41); two users who
paste each other the `checkpoint <origin> <size> <root>` line every report prints under a source
see a split view served to one of them, where both hold one size (P49); and a client with no state
of its own, such as a fresh CI runner, detects a rollback only back to the checkpoint it was
configured with (D34) *(documented, docs/19-distribution-and-lookup.md §6, §6.1, §7, §8, D11)*.

### Out of scope

- **The operator** — whoever passes the flags. Anyone who can pass flags can name a local path as a
  source, point Trigon at any registry, or hand it a key. `file://` is not dangerous; `file://`
  *chosen by the thing under test* is, and the distinction is a constructor *(documented,
  docs/16-findings.md §3.7)*. The same line runs through evidence sources: the ones the operator
  configures are trusted as far as the keys pinned for them, and a project's `.trigon/evidence.toml`
  is input chosen by the thing under test (§1.7); a source the operator configures to trust on first
  use rests on whatever its repository served at first contact (D33) *(documented,
  docs/19-distribution-and-lookup.md §2.4, §8)*. This is not A8: an evidence repository's operator
  is not the person running Trigon.
- **Whoever made a file handed to `trigon runs import`, as to what its records claim.** The
  operator chose to import it, which trusts its maker as a store's co-writer is trusted: the
  machine, the time, the caches and the image pin a record names are the maker's word, and so are
  the strategy, base image and egress tier `rebuild --confirm` of it repeats (D40). The file
  itself is input anyone who held it could have changed, and is checked whole before anything is
  written (P47, §1.7) *(documented, docs/19-distribution-and-lookup.md D8)*.
- **Anyone with code execution in the `trigon` process.** They have already won.
- **A compromised control plane** *(documented, docs/12-security.md §11)*.
- **A network attacker between Trigon and a registry**, beyond what TLS gives. An artifact from
  npm, PyPI, crates.io or NuGet is hashed as it streams and checked against every digest its
  registry declares that this build can compute, and a mismatch refuses it; PyPI's `blake2b_256` is
  recorded unchecked, and a NuGet version whose catalog declares no hash is recorded as declaring
  none (§1.7). The registry is trusted to say what it published *(documented,
  crates/trigon-registry/src/declared.rs; docs/16-findings.md §3.95)*.
- **A tenant of a shared installation.** There is no multi-tenancy to attack (§1.3).

---

## 1.11 Security properties Trigon provides

A report that violates one of these, through an adversary in §1.10 and an operand §1.7 marks
attacker-controllable, is `VALID`.

| ID | Property | Conditions | Violation symptom | Tier |
| --- | --- | --- | --- | --- |
| **P1** | Parsing a hostile artifact does not panic, escape its *enforced* limits — recursion, total expansion, entry count and gzip member count, but not the two D23 records as dead — or silently change a digest. Recursion is bounded by `Limits::recursion`, whose default of 4 descends three levels below the top — `N` parses `N-1`, stricter than the name reads — and a parse failure keeps the member inline and emits `NestedParseFailed`. **Every limit is enforced against what decompression produces, not against the size the input declares.** That was false for a *stored* zip member until 2026-09-13: the deflate arm checked its output and the store arm returned its bytes unexamined, while the ceiling was charged the size the central directory declared, so many entries naming one large member multiplied past the limit meant to bound them. Every offset read goes through `checked_add`. A gzip file is read as gunzip reads it: every member, each held to its own CRC-32 and ISIZE, and any bytes after the last member kept and compared (`container:gzip.trailing`) rather than dropped. That was false until 2026-09-29: the reader inflated the first member and took the file's last eight bytes as its trailer, so a second member whose CRC was forged to the first's was skipped, and a `.tgz` carrying extra tar entries in it matched an honest rebuild without them. The members one artifact reads are counted against `Limits::max_entries` across every nested `.gz`, because an empty one costs time and no bytes. A tar ends where every reader agrees it does: a lone zero block with more of the archive after it, which node-tar reads past and the `tar` crate does not, is refused, and bytes after two zero blocks that are not padding are kept and compared (`container:tar.trailing`). Until 2026-09-29 the reader stopped at the first zero block and dropped what followed, so entries after a lone one, which npm installs, matched an honest rebuild without them. | any input bytes | panic, hang, wrong digest | **security-critical** *(documented, docs/05 §2.2; crates/trigon-archive/src/zip.rs — `checked_add`; crates/trigon-archive/src/gzip.rs:25 — the output budget; tests `an_offset_that_wraps_is_a_short_read_and_not_a_panic`, `a_gzip_bomb_is_refused_at_the_limit_rather_than_inflated`, `a_zip_member_that_lies_about_its_size_is_refused`, `a_second_gzip_member_is_part_of_the_artifact_and_never_skipped`, `bytes_after_the_last_gzip_member_are_a_named_difference_and_not_a_match`, `one_artifact_shares_one_member_count_across_every_gz_it_holds`, `a_lone_zero_block_ahead_of_more_entries_is_refused_rather_than_read_as_the_end`, `bytes_after_the_tar_end_of_archive_marker_are_a_named_difference_and_not_a_match`)* |
| **P2** | The stabilized form is a byte-stable function of the input: `parse(write(a)) == a`, identical across runs and threads *of a single process*. A value the writer has no spelling for that reads back as itself is refused rather than written as another: a tar device number past seven octal digits, which lost its high digits until 2026-09-29, gzip trailing bytes that begin with the magic, and tar trailing bytes that are all zero. | same stabilizer set | two runs disagree on a digest | **security-critical** *(documented, docs/13-roadmap.md M0; tests `a_device_number_too_wide_for_its_field_is_refused_rather_than_truncated`, `trailing_bytes_that_would_read_back_as_a_member_are_refused_by_the_writer`, `trailing_bytes_that_are_all_zero_are_refused_by_the_writer`)* |
| **P3** | Stabilizers are total and idempotent: `stab(stab(x)) == stab(x)`, no `Result`, no half-stabilized state, and none allocates more than one member at a time. | — | a digest that depends on how many times a pass ran | **security-critical** *(documented, docs/05 §4)* |
| **P4** | `compare` refuses to compare two sides stabilized under different sets, by set digest, and classifies the refusal `Fault::Bug`. | — | a verdict derived across incomparable sets | **security-critical** *(documented, docs/09-attestations.md §7)* |
| **P5** | **Provenance-capped outcomes.** `normalized` is produced only when the stabilized digests are equal *and* every applied stabilizer is `Builtin` with risk ≤ `Metadata`. Anything else that matches is `normalized_with_caveats`. | — | a model- or human-authored normalization reported as clean | **security-critical** *(documented, docs/00-overview.md §3.1; crates/trigon-compare/src/lib.rs:166-181)* |
| **P6** | No path signs a verdict for a void run; it is signed as `void/v1` and only that, by `trigon attest` and by `trigon rebuild --attest`, which signs through the same code (`sign_run`). A void run is one the publication gate calls void (`trigon_api::publication::voided`, which is `decide`'s own answer): its guard tripped, whether or not it reached an outcome, or it reached an outcome at `open` egress or with a stabilizer a person or a model wrote. `void/v1` carries the reason and the facts that establish it, and no comparison outcome, difference data, comparison report or rebuilt-artifact digest. `trigon verify --attest` signs `equivalence/v1` or `divergence/v1` about two local files with no run behind them, which is a comparison claim and not publishable. | the run was recorded, and the facts that void it are on its record | a signed `equivalence` or `divergence` about a run that fetched its own answer or had the whole network; a `void/v1` that says which way the comparison went | **security-critical** *(documented, docs/19-distribution-and-lookup.md §4.3; docs/16-findings.md §3.96, §3.97; crates/trigon/tests/seam_attest_v2.rs — `a_guard_tripped_run_yields_void_v1_and_never_a_verdict`, `an_open_egress_run_yields_void_too`, `a_run_a_hand_written_stabilizer_applied_to_is_signed_as_void_and_only_void`, `a_verdict_is_not_signed_for_a_record_that_hides_a_hand_written_stabilizer`; crates/trigon/src/main.rs — `rebuild_attest_at_open_egress_signs_void_and_never_a_verdict`)* |
| **P7** | Text reaching a model is bounded and control-stripped, and operator instructions travel in a system message, never spliced into package text. | every provider **except `copilot:`**, which has no system-role channel | a build log rewriting the operator's instructions | **security-critical** *(documented, docs/12-security.md §4.1; crates/trigon-ai/src/copilot.rs:35)* |
| **P8** | Both artifacts receive an identical transform; the API has no way to stabilize one side differently. Enforced by the type signature. | — | an asymmetric normalization producing a false match | **security-critical** *(documented, docs/12-security.md §10)* |
| **P9** | Canonical JSON refuses what another implementation might not reproduce: floats, integers beyond ±(2^53 − 1) and non-ASCII object keys are type errors, not coerced values. | signing path | two implementations disagreeing on what was signed | **security-critical** *(documented, crates/trigon-core/src/jcs.rs)* |
| **P10** | A package-declared repository reaches `git` as **https only**, with a **40-hex commit only**, under `GIT_CONFIG_NOSYSTEM` and a restricted `GIT_ALLOW_PROTOCOL`. Only the operator may name a local path. | — | command or option injection from registry metadata | **security-critical** *(documented, docs/16-findings.md §3.7)* |
| **P11** | A runner refuses an egress tier it cannot enforce rather than downgrading it, and at every tier but `open` no phase of the run reaches the network — the image build takes `--network none` too, and so does the probe that asks an image what it carries. The one exception is `--image derive`, which builds a base image with network before the build: it is opt-in, never reached by `auto`, recorded on the run as `environment.derived_image`, and withholds any accusation drawn from it. | podman honours its flags | a run recorded as enforced that was not; a derivation that happened and was not recorded | **security-critical** *(documented, docs/16-findings.md §3.13, §3.69)* |
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
| **P23** | An archived stabilizer set is proved to agree with the compiled one before its digest is used, and a trap in the module fails the re-derivation rather than producing a digest. `trigon attest` names a module in a verdict only once it reports the run's set digest and stabilizes both stored artifacts to the stabilized digests the run recorded. `verify-attestation` runs a module only when the sha256 of its bytes is the `stabilizerSetModule` the signed verdict names — the module a record carries, or one given with `--stabilizers` — and refuses any other before it runs: the signed digest, not the set digest a module reports of itself, binds a module to a claim. That binding holds where the verdict signs a module. A statement that signs none — a v1 bundle, or a verdict signed before modules were — binds none: a module given with `--stabilizers` for it is run, held only to the set digest it reports of itself and to the stabilized digests the statement signs, and the output says so. | `wasm` feature | an archived set silently producing a different digest; a substituted module making a claim re-derive | **security-critical** *(documented, docs/16-findings.md — "run an archived stabilizer set, and prove it agrees with the compiled one"; docs/09-attestations.md §7.1)* |
| **P24** | Outcomes cross the wire as strings, with `FromStr` the exact inverse of `Display`. | — | a verdict changing meaning across a serialization boundary | correctness-only *(documented, crates/trigon-core/src/outcome.rs:46-53)* |
| **P25** | Comparison is linear in member count; each side is walked at most twice. **Threshold:** super-linear in members is a bug; a constant factor is not. | — | a comparison that does not finish on a large artifact | correctness-only *(documented, docs/05 §5)* |
| **P26** | `Signer` is an operator-chosen collaborator, named on the command line, never selected by anything in an artifact or an attestation. The archived-set loader runs a module named on the command line or in `[publish] stabilizer_module`, or the one a verified record's signed verdict names by sha256 where the binary does not carry its set; never one an artifact or an unsigned part of a record selects. | — | an artifact choosing what signs or stabilizes it | **security-critical** *(documented, docs/09-attestations.md §6-7)* |
| **P27** | An unregistered `uses:` is a hard error naming the tool and listing the known ones; tool composition is acyclic at load and depth-bounded at render; a definitions entry is parsed with `deny_unknown_fields`. | — | an empty script fragment silently replacing a build step | **security-critical** *(documented, docs/04-strategies.md §2)* |
| **P28** | `strategy_digest` is a canonical, domain-separated content pin over the strategy and exactly the tools it uses, taken over the migrated value rather than the YAML bytes. | — | a cache hit across different recipes | correctness-only *(documented, docs/04-strategies.md §4)* |
| **P29** | A build is killed at a hard wall-clock limit. **Threshold:** the default is 1800 seconds and `--timeout` sets it; a build that exceeds it is killed, not waited for. | — | a build running forever | correctness-only *(documented, crates/trigon/src/main.rs:199)* |
| **P31** | **A published record is shown as verified only when all of it checks** (`verify-attestation --record`, `trigon_attest::evidence::check_record`). Its sha256 is the `record` of a leaf of the verified log — a record no leaf names is *unlogged* and fails, and one the log holds at two leaves is *logged twice* and fails at both, since a record logged again after what withdraws it would otherwise read as current again; the leaf's key id names the attestation key its source had at that leaf, the pinned key or one a `key-change` leaf signed by both keys moved to, so a record signed by a key the source never had, or by one retired before its leaf, fails; every envelope carries a signature by that key that verifies; the signed statement agrees with its leaf on subject digests, purl, predicate type, outcome, set digest, `supersedes` and `reason`; a void or a withdrawal is one statement, a verdict carries the command that would falsify it — `trigon verify-attestation` naming its own subject and predicate type and the origin of the log it is logged in — and a divergence the `https://` pointer to where it is disputed, since a client never renders an outcome it cannot show with them, a verdict's `rebuild` is of its run, under its set, and about the rebuilt artifact it names, and its `buildobservation` is about its subject, under its egress tier and guard manifest, with no guard tripped — `buildobservation` names no run, so one of another attempt at the same artifact under the same tier and guard is not told apart; the unsigned `subject` and `evidence` map agree with the statement; the signed subject is the key it was found under, a purl key its signed purl canonicalised; and every evidence file present is the bytes its statement names, one absent is reported unchecked and never passed. Each failure is reported with its reason and exits 4, never as never checked. Under `--rerun-comparison`, a claim the bytes refute exits 4 with the record's whole report: what it says the comparison found, a stabilized digest, a subject digest the artifact its sha256 names does not have, or a published comparison report that disagrees with the re-derivation, member by member — read again and held to its signed digest again before it is judged. | the source's keys are the operator's pins (§1.10) | a record shown verified that its leaf, its key, its map or its evidence contradicts; a failure reported as never checked | **security-critical** *(documented, docs/19-distribution-and-lookup.md §4.1, §4.2, §8; docs/16-findings.md §3.99; crates/trigon-attest/tests/evidence_repo/records.rs — `a_record_whose_statement_disagrees_with_its_leaf_fails_verification`, `a_record_signed_by_a_key_retired_before_its_leaf_fails_verification`, `a_record_signed_by_a_key_the_source_never_had_fails_verification`, `an_unlogged_record_fails_verification`, `an_unsigned_map_that_disagrees_with_the_signed_statement_fails_verification`, `every_evidence_file_is_checked_and_one_absent_is_unchecked_never_passed`, `what_accompanies_a_verdict_is_about_its_run`, `record_leaf_refuses_a_statement_whose_leaf_every_client_would_refuse`, `a_verdict_without_what_answers_it_fails_verification`; lookup.rs — `a_record_logged_again_after_its_withdrawal_fails_and_never_answers_again`; rerun.rs — `a_published_report_is_held_member_by_member_and_by_its_field_edits`; crates/trigon/tests/verify_record.rs — `a_claim_rerun_comparison_refutes_exits_4`, `a_record_logged_twice_fails_verification_and_exits_4`)* |
| **P32** | **Nothing is answered from a record the verified log does not hold, and nothing the log holds is hidden.** A key — a sha256, sha512 or sha1 digest, an integrity string, a purl with or without its version, a file — is resolved from the verified leaves, never from `index/`, so a missing, altered or planted index file changes no answer. A leaf whose record file is missing is *deleted*, whatever its outcome, and exits 4. A record is superseded only by a verified, logged record, signed by the key its source had at its own later leaf, that names it and has the same subject digests and canonical purl; a superseded record is returned marked, and two current records for one subject are both returned and the more severe answers. Where the log continues in a repository the directory does not hold, what the source says now is *unknown* and exits 4: a record is never shown as current when a withdrawal of it may be logged where the directory does not reach. | P33 holds for the log | a verdict answered that no leaf logs; a deletion answered as never checked or as its outcome; a supersession applied that §3's rules refuse, or a record hidden | **security-critical** *(documented, docs/19-distribution-and-lookup.md §3, §5, §6, §8; crates/trigon-attest/tests/evidence_repo/lookup.rs — `a_record_whose_index_entries_are_removed_or_altered_is_still_found`, `a_record_file_deleted_is_deleted_whatever_its_leaf_says`, `supersession_takes_every_clause_of_docs_19_3`, `a_record_logged_again_after_its_withdrawal_fails_and_never_answers_again`; crates/trigon/tests/verify_record.rs — `a_log_that_continues_elsewhere_answers_unknown_and_exits_4`)* |
| **P33** | **The log is verified whole, and held to what was accepted before, before any record is read.** The checkpoint must verify under the pinned log key and name its origin; every leaf is rehashed and the root compared with the signed one; leaf times never go backwards; every tile holds the leaves' hashes; a successor is followed only through a `log-end` and a `log-continuation` signed by both keys. A checkpoint that does not extend the one given as last accepted — a rollback, a rewrite, a fork — is refused with both signed notes; two checkpoints under one log key whose trees are not one tree, found side by side in one repository, are an equivocation, refused with both notes; either exits 4, and prints both notes in its JSON document too. A checkpoint given that the log was not held to — one of a log the directory does not hold — is said to be unchecked, never one the log is held to; one that is not a checkpoint at all, given or in the state directory, exits 5 and is never blamed on the source; and a source whose state holds no checkpoint says so when its initial one stands in. | the checkpoint last accepted is given, from `--checkpoint` or the source's state or initial checkpoint — without one, D25 | a log whose files are not its signed tree accepted; a checkpoint that does not extend the accepted one, or a second tree under the key, accepted or set aside | **security-critical** *(documented, docs/19-distribution-and-lookup.md §6, §6.1, §8; docs/16-findings.md §3.98, §3.99; crates/trigon-attest/tests/evidence_log/verify.rs; crates/trigon-attest/tests/evidence_log/rotation.rs — `a_planted_directory_does_not_move_or_stop_a_client_pinned_to_a_successor`; crates/trigon/tests/verify_record.rs — `two_trees_under_one_log_key_are_an_equivocation_and_exit_4`, `a_log_that_continues_elsewhere_answers_unknown_and_exits_4`, `a_source_is_read_from_the_configuration_and_its_state_directory`)* |
| **P34** | **`trigon publish` builds only on a remote log it has verified, and publishes only what the gate releases, as one commit pushed without force.** Before anything is written: the repository's chain of logs, from the one its `keys/log.vkey` names and through every succession in the repository, must end at `[publish] origin`'s log, which a publication appends to, and one that ended in favour of a successor elsewhere is published into only to begin that successor (P37); the chain is verified whole under that key and against the newest checkpoint of the log this host has published or verified, kept by the log's origin in the host's state directory, so a remote rolled back or rewritten behind that is refused from any store and however the location is spelled (D27 for a host with none); a branch that names git attributes is refused before it is checked out, since a filter or a line-end conversion would make the files read other than the blobs clients clone; nothing past the checkpoint is read, so files planted in `log/` beyond it are ignored and overwritten, and a file at a path a publication writes is replaced, never written through. Each run is asked of `publication::decide` through the index `trigon serve` builds, with the repository's `kill-switch` as safeguard 5: a withheld run is refused; a void run is published only as `void/v1`; a divergence is refused while `divergences = "refuse"`, and under `"feed"` is published with its entry in `feed/divergences.atom`, which the commit that logs a divergence, or a record superseding one, regenerates from the log whole, its records read with `check_record`, as `--reconcile` does; a record not signed by the attestation key the log has now — after a key change, the new one — is refused, with the key it needs; a run already published, the second of two agreeing attempts whose first is, a record for an artifact with a current record it does not supersede, a verdict without its falsifying command naming `[publish] origin` or without the dispute pointer `[publish] disputes` names, and a verdict naming no stabilizer-set module (P48), are refused; and every record is checked with `check_record` at the leaf it will have. Every refusal is listed, and nothing is written. What is published is asked of the whole chain of logs: where the repository begins by continuing a log in another repository, the chain before it is read through a configured evidence source whose chain reaches that log from the chain's first log — synced first where it is stale, and verified as P39 verifies one — and followed into this repository's first log, so an artifact with a current record in the ended repository has one here, and a withdrawal may be of a record logged there; a source pinned partway through the succession, whose first log continues another, is passed over, since it reads part of the chain; where none serves, every source not just synced is synced again, however fresh, and looked at once more; a dry run syncs none, and reads each from its clone; with no source that reaches it, runs and withdrawals are refused, saying how to add one. Where rebuilt artifacts are published, each is found or uploaded before anything is written (P36). With `--prune`, a run's rebuilt artifact is dropped from the store only once its publication is pushed and recorded. The publication is one commit holding exactly the bytes written and signed, staged as blobs and never by `git add`, and read back before it is pushed: its parent, every path it changes and every blob must be the publication's, so no `.gitignore`, excludes file, attribute, hook or pre-staged change makes the remote hold other than what `log sign` checked; neither commit nor push is signed with the operator's key. It is pushed without force; a rejected push whose remote has moved discards the commit and the checkpoint signed for it and builds again, and one whose remote is at the commit just pushed is published; a publisher killed at any step leaves the remote as it was or with the whole publication, and a run whose record is logged is completed, never logged twice, with the commit whose checkpoint first covered its leaf, in the log of the chain that holds it — after a succession, the ended one; one logged in an earlier repository of the chain is refused as published. A working clone is used only where it is a repository of its own, never the checkout around the store. One `publish` runs at a time on a host, whatever store it runs from, and one at a time in a store; a second is refused, never left waiting. | the remote is reached, and the operator's store and statements are the operator's (§1.10 out of scope) | a publication built on a log that does not verify or that a rollback rewound; a withheld run, or a void as a verdict, published; two records for one run; a partial publication visible | **security-critical** *(documented, docs/19-distribution-and-lookup.md §2.2, §3, §10 phase 5; docs/16-findings.md §3.100; crates/trigon/tests/publish.rs — `a_run_publishes_in_one_commit_and_a_fresh_clone_verifies_it`, `a_withheld_run_is_refused_and_a_void_run_publishes_only_as_void`, `a_verdict_without_its_falsifying_command_or_for_a_current_artifact_is_refused`, `two_publishers_leave_one_linear_history_and_one_root_per_size`, `a_publisher_killed_between_steps_leaves_the_old_state_or_the_new`, `files_planted_in_the_log_beyond_the_checkpoint_are_never_signed`, `a_remote_rolled_back_behind_what_this_host_published_is_refused`, `what_a_publication_writes_is_committed_whatever_git_is_told_to_ignore`, `a_branch_that_names_git_attributes_is_refused_before_it_is_checked_out`, `the_operators_git_configuration_changes_nothing_that_is_committed`, `a_working_clone_without_its_git_directory_is_made_again_and_never_the_checkout_around_it`, `one_publish_runs_at_a_time_on_a_host_whatever_store_it_runs_from`, `a_push_the_remote_took_is_published_even_when_the_connection_goes_before_it_answers`, `reconcile_never_reads_through_a_link_planted_as_index`, `a_run_completed_after_its_record_file_was_removed_names_the_commit_that_logged_it`, `a_divergence_is_published_with_its_feed_entry_in_the_same_commit`, `the_kill_switch_withholds_a_divergence_the_feed_would_publish`, `a_run_logged_before_a_succession_is_completed_against_its_own_log`, `a_key_change_is_followed_and_publish_then_expects_the_new_key`, `a_rebuilt_artifact_is_pruned_only_once_its_run_is_published`, `publishing_into_a_successor_elsewhere_reads_the_whole_chain`, `publishing_into_a_successor_elsewhere_reads_the_chain_from_its_first_log`; docs/16-findings.md §3.101, §3.102)* |
| **P35** | **The log key signs only a tree it has checked, and only `trigon log sign` holds it.** `publish` never opens the key file; it runs `trigon log sign`, a child process of the same binary that opens no socket, which reads the new tree from disk and signs its checkpoint only where the checkpoint the tree extends opens under the log key itself; the tree's first leaves hash to that checkpoint's root, and to the root of the newest checkpoint of the log this host has published, kept by its origin in the host's state directory, so nothing this host has published is rewritten however `publish` was run (D27 for a host with none); every leaf decodes, sits where its kind may, and is no earlier than the one before it; every tile holds its leaves' hashes; and every new leaf is a heartbeat, a key change from the key current at it signed by both keys, a log-end — signed only where `--successor-key` holds the log key it names, the final checkpoint then cosigned by that key and written with both signatures — or names a record file in the tree, logged at no other leaf, that passes `check_record` under the attestation key current at it, with every evidence file it names beside it. A release leaf is refused, since no command of this build writes one, and a log-continuation is signed only as a successor's first tree, under P37. Nothing past the size it is told to sign is read. A checkpoint of size 0 is signed only with `--init`, in a tree with no log and no `keys/log.vkey`, and never for a log this host has published. | the tree's `keys/attestation.pub`, or `--attestation-key`, names the attestation key current at the checkpoint the tree extends; for a successor's tree, the chain `keys/log.vkey` begins is followed from it | the log key signing a leaf nobody checked, a rewrite of what it signed, or a second tree begun over a log | **security-critical** *(documented, docs/19-distribution-and-lookup.md §8, §10 phase 5 step 5; crates/trigon-attest/tests/evidence_repo/sign.rs — `a_tree_that_does_not_extend_what_was_published_is_not_signed`, `a_log_end_is_signed_only_with_the_successor_key_it_names`, `a_key_change_is_signed_only_from_the_current_key`; crates/trigon/tests/publish.rs — `log_sign_is_its_own_step_and_what_it_refuses_is_never_committed`, `a_remote_rolled_back_behind_what_this_host_published_is_refused`, `the_repository_named_each_way_publishes`)* |
| **P36** | **A rebuilt artifact is a release asset uploaded before its record, named by the digest its verdict signs.** With `rebuilt_artifacts = "github-release"`, `publish` refuses, before anything is read or written, a location that is not a repository on github.com and a run with no token in `GITHUB_TOKEN` or `GH_TOKEN`; and at step 2, a verdict whose run's rebuilt artifact is not the one its verdict signs, or is not under GitHub's 2 GiB. At step 3, before anything that names an asset is written, each artifact — every verdict's but an exact one's, which is the published artifact itself — is found as `sha256-<hex>` in this month's or last month's `rebuilt-YYYY-MM` series, and taken for it only where GitHub reports its digest and its size and digest are the artifact's; one of another size or digest is refused; one GitHub left unfinished, or reports no digest for — whose size alone cannot tell it from another artifact's — is removed, once the store has yielded the bytes to put in its place, and uploaded again; any other is uploaded from the store, whose bytes are checked against the digest as they are read, to the first release of the month's series with room under 1,000 assets, or a new one, and never to a draft release, which only the repository's writers can see. An upload that fails leaves nothing committed; an asset uploaded for a publication that then fails is harmless, and reused by the next attempt. | `rebuilt_artifacts = "github-release"`; the API is GitHub's, or the one the operator names | a record naming an asset nobody uploaded; an asset of another artifact taken for it | **security-critical** *(documented, docs/19-distribution-and-lookup.md §2.3, §10 phase 5 step 3; crates/trigon/src/publish/release.rs — `a_github_location_names_its_repository_and_no_other_does`; crates/trigon/tests/publish.rs — `a_rebuilt_artifact_is_a_release_asset_uploaded_before_its_record_is_committed`, `an_asset_is_reused_on_retry_and_a_full_release_continues_its_series`, `an_asset_of_the_artifacts_name_is_taken_for_it_only_when_it_is_it`, `the_token_goes_to_no_other_host_and_no_asset_into_a_draft`)* |
| **P37** | **A rotation is logged only as every client follows it, and the processes that fetch and push hold no key.** `trigon log key-change` logs a key-change leaf only from the attestation key the log has now, to one it has never had, signed by both over the log's origin and the leaf's time; the leaf is signed by `trigon log key-change-leaf`, a child that opens no socket, and held by the parent to everything it asked for; a dry run signs nothing, and shows the leaf with its signatures empty. From that leaf on, `publish` publishes only records signed by the new key, and a fresh verification from the keys a client pinned follows the change: records before it verify under the old key, records after it under the new, and `keys/attestation.pub` stays the key the chain starts at. `trigon log succeed` logs a log-end naming the successor's origin, log key and place, which `log sign` signs only holding the successor's log key as well — named to `succeed` by `trigon log public-key`, a child — and cosigns the final checkpoint with; the successor's first tree is its log-continuation alone, holding that note, and `log sign --continuing` signs it only as the log a verified chain's log-end names, extending what this host published of the old log, and only after `follow` accepts the pair. In the same repository both are one commit; in another, the log-end is written only once the repository its first URL names has been cloned and found to be another than this one, holding no log or the start of one and no git attributes, and taking a push, so a log never ends naming a place no successor can be begun; the successor is begun there only once the old log's end is pushed, from the final checkpoint published, with the old repository's `kill-switch` where it is set, and a second `log succeed` finishes a succession stopped between: stopped there, the ended log refuses publication and says where it goes on, and a client syncing it finds no successor to follow, so its sync fails and it answers from what it holds until it is stale. A successor no log-end names is refused by every client and by `log sign`. After a succession, `publish` publishes into the successor, and refuses the ended log's origin with where publishing goes on. | the operator runs the rotation, holding the keys it takes | a record signed by a retired key accepted; a succession clients do not follow, or one they follow to a log nobody named; a key opened by the process that pushes | **security-critical** *(documented, docs/19-distribution-and-lookup.md §8, §10 phase 5; ADR-0014 Decision 8; crates/trigon-attest/tests/evidence_repo/sign.rs — `a_successor_is_begun_only_as_the_one_its_predecessor_names`; crates/trigon/tests/publish.rs — `a_key_change_is_followed_and_publish_then_expects_the_new_key`, `a_succession_is_followed_and_publish_continues_into_the_successor`, `a_successor_the_log_end_does_not_name_is_refused`, `a_succession_into_another_repository_is_begun_there_after_the_end_is_pushed`, `a_log_is_ended_only_naming_a_place_its_successor_can_be_begun`, `a_run_logged_before_a_succession_is_completed_against_its_own_log`; crates/trigon/tests/evidence.rs — `a_succession_into_another_repository_is_followed_on_sync`)* |
| **P38** | **The GitHub token that uploads rebuilt artifacts is read from the environment and sent only to GitHub.** It is `GITHUB_TOKEN`, else `GH_TOKEN`, and never read from argv or a file; without one, a publication that would upload is refused before anything is written. It is held in a type whose `Debug` prints `***`, sent only as the `Authorization` header, only to the API — `https://api.github.com`, or under `TRIGON_GITHUB_API` a server that must be HTTPS or on loopback — and to an upload URL on GitHub's upload host or, under `TRIGON_GITHUB_API`, that server's own origin; no redirect is followed; and no URL, message or error quotes it, even where the server quoted it back. `log key-change`, `log succeed`, `--heartbeat`, `--withdrawal`, `--reconcile` and a dry run read no token. | `rebuilt_artifacts = "github-release"` | the token on argv or in a message, or sent to another host | **security-critical** *(documented, docs/19-distribution-and-lookup.md §2.4, §10 phase 5; crates/trigon/src/publish/release.rs — `the_token_is_in_no_print_and_no_refusal`, `the_api_is_https_or_loopback_and_names_no_user`, `the_token_goes_only_to_the_apis_upload_host`; crates/trigon/tests/publish.rs — `a_rebuilt_artifact_is_a_release_asset_uploaded_before_its_record_is_committed`, `the_token_goes_to_no_other_host_and_no_asset_into_a_draft`)* |
| **P39** | **A source is accepted only once all of it verifies, and its state is written only then.** `trigon evidence sync` fetches every location of a source — cloning one it has no clone of, shallow, partial and sparse for a remote and in full for a local path, and otherwise a `fetch` of the branch and `reset --hard FETCH_HEAD` — and verifies each clone whole with the phase 4 code: the checkpoint under the source's log key, the root recomputed from every leaf, times that never go back, every tile, and every key change and succession followed, a successor in another repository cloned from the locations its log-end names and followed there as part of the same source. The whole chain is then held to the checkpoint last accepted, kept in `<state>/<name>/checkpoint`: one it does not extend — a rewrite, a fork — and one with more leaves than it has — a rollback, served or in a clone on disk — are refused with both signed notes, exit 4. The key history is recomputed from the log, and one kept in `<state>/<name>/keys` that disagrees is reported, the log winning. Only then are the key history, the checkpoint and the record of the sync written, each whole by rename, and a new clone kept; a refused sync puts back every clone it moved, removes every one it made, and leaves the state as it was, so the source is answered from nothing new and every command asking it exits 4 until a sync of it works. A source that has synced before — a clone of it is kept, or a sync of it worked — whose checkpoint, or whose keys trusted on first use, are gone is refused, never given a new state silently, until `--accept-state-loss <name>` says the loss is known, and the verifier's record form refuses a lost checkpoint too; only what was lost then starts over, so keys first read that survive a lost checkpoint still pin the source, and a checkpoint that survives lost keys must open under the keys read again. A clone is made under a name beginning with a dot, marked unaccepted, and only then moved into place, the mark coming off when a sync is accepted: a sync stopped anywhere leaves nothing that reads as one that finished, and a marked clone is made again, never fetched into. Once the checkpoint is written, the clones it was read from are kept whatever happens to the record of the sync. Each clone's `.git/info/attributes` unsets every attribute that changes a checked-out file's bytes, and each is reset clean, so the files verified are the blobs; the branch a clone takes from the repository reaches `git` only as a branch name `git` would make, after `--`. Two syncs of one source take turns, and a read of it waits for a sync. | the source's keys are the operator's pins, or those trust on first use recorded (D33) | a clone accepted that does not verify, or does not extend what was accepted; the state moved by a sync that was refused; a lost state made again silently | **security-critical** *(documented, docs/19-distribution-and-lookup.md §6, §6.1, §8; docs/16-findings.md §3.102; crates/trigon/tests/evidence.rs — `a_source_syncs_from_a_file_url_a_bare_path_and_a_relative_path`, `a_checkpoint_that_does_not_extend_the_accepted_one_is_refused_and_the_clone_kept`, `a_rollback_behind_the_accepted_checkpoint_is_refused_served_or_on_disk`, `a_key_change_and_a_succession_are_followed_on_sync`, `a_succession_into_another_repository_is_followed_on_sync`, `a_lost_state_is_reported_and_accepted_only_when_asked`, `a_sync_stopped_before_it_was_accepted_is_made_again_and_a_later_loss_refused`, `accepting_a_lost_state_keeps_what_survives_of_it`, `a_branch_named_as_an_option_is_never_fetched`, `a_repositorys_own_attributes_never_change_what_is_verified`, `full_history_keeps_the_history_and_says_when_it_was_rewritten`; crates/trigon/src/evidence/mod.rs — `a_sync_whose_record_cannot_be_written_keeps_the_clones_it_accepted`; crates/trigon-attest/tests/evidence_log/chains.rs)* |
| **P40** | **The locations of a source are one log, or the source is refused.** Every URL of a source — one log and its mirrors — and every location a log-end names for a successor is fetched and verified by itself, and then every copy is held to every other, over every log of the chain both hold: at the same size their roots are one root, and at different sizes the smaller's root is the root of the larger's first leaves, recomputed from the larger's own tree. Two that are not one log are an equivocation, refused with both signed notes, exit 4, and nothing either served is accepted. The largest answers; a smaller one is said to be lagging, and one that could not be reached or read is said, the others answering. One that serves a repository with no log at all — no checkpoint anywhere, which is what a mistyped URL or a mirror not yet pushed to serves — is one that could not be read, said with its URL, since it says nothing and so cannot be lying; a source whose every location is like that could not be synced, and is not refused for it: like one not reached, it answers from its clone until the clone is stale, and is unknown once it is stale or if it never synced. A checkpoint that is there and does not open under the key still refuses the source. | at least one location of the source is reached | two copies of one log that disagree, accepted; a smaller one answering over the larger; a log that is there and does not verify set aside rather than refusing the source | **security-critical** *(documented, docs/19-distribution-and-lookup.md §6.1, §8; crates/trigon/tests/evidence.rs — `mirrors_in_agreement_lagging_and_equivocating`, `a_location_with_no_log_is_set_aside_and_the_others_answer`; crates/trigon-attest/tests/evidence_log/chains.rs — `copies_of_one_chain_are_one_chain_or_an_equivocation`, `a_repository_with_no_log_is_refused_saying_what_it_lacks`)* |
| **P41** | **A source answers only while it is fresh, and every answer says what it rests on.** Its standing is read from two clocks: stale when its last successful sync is older than `stale_after`, and frozen when its newest leaf is older than `frozen_after` or it has no leaf, a log's checkpoint of size 0 being the oldest consistent state there is. A command that needs a source syncs a stale one first and says so; under `--offline`, or where that sync fails, a stale source answers unknown. A frozen one answers unknown whatever the sync did. After a failed sync, a source that is not yet stale answers from its clone and says when it goes stale; one whose last sync was refused answers nothing. Of several, a package takes the most severe answer any source gave that is not unknown, and is never checked only where no source that answered holds a record for it; an unknown source counts only where it is required, and is then exit 4; a refused one is 4 whatever else is said; none able to answer is 4, and none configured 5. Failure is per source: one whose state cannot be read answers unknown, saying why, and the others answer as they are. Every answer names its source and the file that added it, and one trusting on first use says the keys it rests on and where and when they were read — `verify-attestation --record --source` too, which reads a source's recorded keys rather than refusing it. | the host's clock | a stale or frozen source answered from; a refused source forgotten; an unknown required source not failing a check; an answer from a project's source, or one trusting on first use, that does not say so | **security-critical** *(documented, docs/19-distribution-and-lookup.md §2.4, §6, §6.1; crates/trigon-attest/src/evidence/standing.rs — its tests; crates/trigon/src/evidence/mod.rs — `a_command_that_needs_a_source_syncs_a_stale_one_first_and_says_so`, `what_a_source_says_is_weighed_by_how_it_stands`; crates/trigon/tests/evidence.rs — `stale_from_the_last_sync_and_frozen_from_the_newest_leaf`, `trust_on_first_use_is_recorded_once_and_every_answer_says_it_rests_on_it`, `a_projects_file_is_held_to_its_rules_and_its_sources_name_it`, `a_source_whose_state_cannot_be_read_is_unknown_and_the_others_answer`)* |
| **P42** | **A rebuilt artifact's bytes go only when no run still names them, and bytes gone are said to be missing.** `Store::prune_rebuild`, which `attest --prune` and `publish --prune` run, drops a run's reference to its rebuilt artifact, and deletes the blob only where no other run's record names it as kept — the rebuild of the other attempt of an agreeing pair, which rebuilt the same bytes into one blob, or any run's published artifact — and never where it is this run's published artifact too; a record that cannot be read refuses the prune. It asks and deletes alone, on the store's `blobs.lock`, which a run writing bytes it names as kept — `record_run` — holds shared from before its `put` until its record is written, so a run written meanwhile that names the same bytes is counted, never robbed of them. Every reader that took `stored: true` at its word asks the store: the attestor, `trigon rederive`, `serve`'s member routes and run rows, and `watch`'s run page report bytes a record says are kept and the store has lost as missing, never as there and never as pruned on purpose. | — | a record saying `stored: true` over bytes another run's prune deleted; bytes that are gone reported as there, or as retention's choice | correctness-only *(documented, docs/16-findings.md §3.102; crates/trigon-store/tests/store.rs — `bytes_two_runs_share_are_kept_until_neither_names_them`, `a_prune_waits_for_a_writer_naming_the_bytes_and_keeps_them`, `bytes_a_record_says_are_kept_and_the_store_lost_are_missing_never_present`; crates/trigon-api/tests/seam_member_bytes.rs — `bytes_the_record_says_are_kept_and_the_store_lost_are_reported_missing`; crates/trigon/tests/evidence.rs — `pruning_one_of_an_agreeing_pair_keeps_the_bytes_the_other_names`)* |
| **P43** | **Every answer about an artifact or a package comes from a verified chain's leaves, per source, and never from anything the log does not vouch for.** `trigon lookup`, `trigon check` and `verify-attestation --lookup` make each source they ask ready once — a stale one synced first and said to be, none under `--offline` — and open it from its clones with P39–P41's verification against the checkpoint last accepted; a key is resolved from the verified leaves and never from `index/`, every record held to its leaf and to its own source's attestation key at that leaf (P31, P32), so a record signed with one source's key found in another's repository fails there. Each source answers for itself and is never merged: its name, the file that added it, the keys it rests on, the checkpoint it answered from; a record found by sha1 alone says sha1 is collision-broken; two sources whose claims differ are said to disagree. A package takes the most severe answer any source gave that is not unknown — a divergence from any source fails a check — and is never checked only where no source that answered holds a record for it; an unknown source counts only where required (`required = true`, `--require`, `TRIGON_EVIDENCE_REPO`). `check` looks a package up by every digest its lockfile declares first, and by its purl only where no digest found a record about the artifact it pins; a record answers for a package only where its digests are that artifact's — of one artifact's digests (npm's `integrity`, an SBOM's `checksums`) the strongest the record carries decides, so a record found by sha1 whose sha512 is another's answers nothing, and of a requirement's `--hash`es, which are alternatives, any one matching is enough — and a purl whose records are all about another artifact is never checked, while one it cannot compare with what the lockfile declares answers and says so. Two entries of one name and version with different digests are two packages; an SBOM's packages are all kept, and a purl with no version is the version its `versionInfo` gives. `--require` of a source `--source` leaves out is refused, exit 5. `--min` is an outcome floor through `Match::is_at_least`, and `--max-risk` caps the riskiest stabilizer a normalized verdict signs as applied, an exact one meeting any cap; each below is exit 3. Exit codes are docs/19 §6's, the first of 5, 4, 1, 3, 2 winning, and anything that stops a command before it answers is 5. `--record --source` with no `--evidence` reads the source's clones the same way, in either build, and follows its chain into every repository it has gone on in. | P39–P41 hold for each source | an answer from `index/` or from a source's unverified files; one source's key accepting another's record; a divergence masked by another source's match; a package dropped, or a stale source answering; a record found by sha1 alone not saying so; a record about another artifact answering for the one pinned, or one artifact's record answering for another of its name and version | **security-critical** *(documented, docs/19-distribution-and-lookup.md §4.2, §5, §6, §6.1; docs/16-findings.md §3.103; crates/trigon/tests/lookup.rs — `a_lockfile_is_checked_after_one_sync_and_nothing_is_fetched_again`, `stale_and_unreachable_or_frozen_is_unknown`, `a_deleted_record_a_changed_byte_and_a_missing_index_entry`, `a_superseded_record_is_shown_superseded_and_a_withdrawn_one_withdrawn`, `a_source_answers_however_it_was_configured`, `two_sources_are_answered_each_and_never_merged`, `the_record_form_reads_a_sources_clones_across_repositories`, `check_holds_answers_to_the_threshold_and_refuses_what_it_cannot_read`, `check_answers_for_the_artifact_the_lockfile_pins`, `lookup_takes_every_form_of_key`; crates/trigon/src/evidence/lookup.rs — `a_leaf_is_about_the_pinned_artifact_by_the_strongest_digest_it_can_be_compared_with`; crates/trigon-attest/tests/evidence_repo/lookup.rs — `a_verdict_is_held_to_the_risk_it_was_reached_through`, `of_two_current_verdicts_one_above_the_risk_cap_answers_whatever_their_order`)* |
| **P44** | **`--remote` answers only from records whose leaves it has proven included in a checkpoint held to what was accepted.** A source whose last sync was refused answers nothing. For each other, the checkpoint served under the raw base is opened under its pinned log key — or, past a succession, the key the proven log-end before it names, followed only where the successor's first leaf, proven, is the log-continuation holding its predecessor's final checkpoint under both keys (`log::check_continuation`, as a sync's `follow`) — and, where the source's state holds a checkpoint last accepted, held to it by a consistency proof built from the served tiles against both signed roots, a served log behind it refused; the log's last leaf is read from its entry bundle and proven included, which says how recent the log is — a frozen source answers unknown — and where it goes on. The index file for each key names candidates only: each record's leaf is read from its entry bundle, proven included from the hash tiles against the signed root, and must be a record leaf naming that record and filed under the key; one whose proof does not lead to the signed root, or whose leaf is not the record listed, fails verification, exit 4, one proven to be another's is not answered, and one whose proof or record cannot be read — not served, refused, rate-limited, or listed past the checkpoint read, as a publish landing between two requests leaves it — leaves the source unknown for that question. Each record is then held to its leaf under the source's keys — the key history its last sync recorded where that starts at the keys pinned now, or the pinned key alone, which the report says — with its evidence unchecked. Only a source with an `https://github.com/<owner>/<repo>` URL is asked; the base is HTTPS, or loopback; and every report says what `--remote` costs. | the raw base serves what GitHub holds, or is the operator's own | a record answered whose leaf was not proven; a served checkpoint behind the accepted one accepted; a record answered for a key its proven leaf is not filed under; a successor not bound to its predecessor followed; a refused source answering; a record under a key the user re-pinned away from accepted | **security-critical** *(documented, docs/19-distribution-and-lookup.md §6; crates/trigon/src/evidence/remote.rs — `the_raw_base_is_https_or_loopback_and_names_no_user`; crates/trigon/tests/lookup.rs — `remote_proves_inclusion_and_refuses_what_it_cannot_prove`, `remote_answers_unknown_for_what_it_cannot_read_and_holds_to_the_state`, `remote_follows_a_succession_only_through_its_continuation`)* |
| **P45** | **A falsifying command is answered only where it was signed to be, from files held to what was signed.** `verify-attestation --lookup sha256:<subject> --origin <origin>` resolves the current record — and `--predicate`'s type where given — only in a configured source whose chain holds a log of that origin, synced first where it is stale, and syncs no source of another origin; a client with none says so, exit 4, and resolves nothing elsewhere. Sources that give the origin to logs of different keys are not all asked: a source a project's `.trigon/evidence.toml` added is set aside, and said to be, where the user's own sources or the environment's hold the origin under one key, and otherwise the command is refused as ambiguous, exit 5; without `--origin`, current records in more than one source are refused as ambiguous, exit 5. Every source asked is weighed as `lookup` weighs it, so one refused, or required and unknown, or saying withdrawn, is printed and counted beside the record checked. A subject with no current verdict or void is reported with its source's answer and code, a withdrawal among them. The record is checked exactly as `--record` checks one (P31, P32), each evidence file it names read from the clone's working tree or objects — fetched from the clone's remote where the clone is partial, and said — and held to its signed digest, other bytes failing the record, exit 4. The rebuilt artifact is `--rebuild <file>` where given, and nothing is fetched for it; where none is given, it is found by the record and its sources alone, never by the client's own `[publish] rebuilt_artifacts`: the release asset `sha256-<hex>` of the digest the verdict signs, in the `rebuilt-YYYY-MM` releases of the month the record was logged in and the months either side, of the GitHub repository that holds the record's leaf in the source it was resolved in — by an HTTPS or an SSH location — and then of every other source's that holds it, never one a project's `.trigon/evidence.toml` added where the record was resolved in the user's own; downloaded without a token into a new file in a directory made for it that only the user can enter, and held to that digest as it is written, other bytes refused: exit 4 in the resolving source's repository, and in another's a check not made, exit 5. An exact verdict, whose rebuilt artifact is the upstream artifact and is never published, asks nothing, and takes the upstream file as its rebuilt artifact, held to the digest the verdict signs, so its signed command runs as written; a record no repository of which is on github.com asks nothing either; there, where no repository asked holds the asset, where GitHub refuses or cannot be reached, or where the verdict signs no rebuilt artifact, the check is not made, exit 5, and `--rebuild <file>` is asked for, no other artifact guessed at. The claim is then re-derived and the published comparison report held to it (P31); a void has no claim to re-derive, and is reported as the void it is, exit 3. A record current in two sources of one origin — one log configured twice — is checked once. | the source's clone was accepted by a sync (P39) | a falsifying command answered from another source, or from a project's source that gives the origin to a key of its own; an evidence file or a release asset of other bytes used; a release asset looked for outside the repositories that hold the record and their series, or in a project's source's repository where the user's own resolved the record, or an artifact guessed at where it has none; GitHub failing or refusing reported as the record failing; a withdrawn artifact reported as a verdict; a source asked and then dropped from the answer | **security-critical** *(documented, docs/19-distribution-and-lookup.md §4.2 item 6, §6; crates/trigon/tests/lookup.rs — `the_falsifying_command_re_derives_a_published_verdict`, `the_falsifying_command_is_answered_in_its_origins_log_alone`, `the_falsifying_command_weighs_every_source_it_asks`, `the_falsifying_command_across_a_succession_and_for_a_void`, `the_rebuilt_artifact_is_found_by_the_record_and_its_source_alone`, `the_rebuilt_artifact_is_looked_for_only_where_publish_puts_it`, `the_rebuilt_artifact_is_not_had_where_github_cannot_be_asked`, `the_rebuilt_artifact_is_asked_of_the_repositories_that_hold_the_record`, `an_exact_verdict_re_derives_from_the_upstream_file_alone_and_never_asks_github`)* |
| **P46** | **Nothing a rung read from outside the strategy is template source.** A step's `runs`, `if` and `with` values are templates; what a rung copies from the package under test, its registry document or its repository goes in the step's `literal` map instead, which the renderer hands to the tool as the parameter of that name exactly as written, or prints where a template reads it as `{{ literal.<name> }}`, and never parses. That covers the .NET rung's version stamps and copyright, read from the published assembly; the yarn rung's expansion of a `package.json` script; and every parameter the heuristic and CI rungs pass, none of which is a template. A tool's own steps never see their caller's literals, and a name given both in `with` and in `literal` is refused when the document is parsed and when a step built in code is rendered. A .NET stamp then reaches `dotnet` MSBuild-escaped — `;`, `,`, `%`, `"` and `@` as `%XX` — so the property MSBuild sets is the text the assembly holds. It is a statement about the template engine and not the shell: a literal a tool prints into a `runs` fragment is shell the build runs, which D2 disclaims. | a strategy a rung wrote; a strategy an author or a model wrote keeps its templates, and what a package can make a model write is P7's boundary, not this | the package under test evaluating a template in its own build recipe: a stamp, a directory or a pin built as another value, a render the package fails, a recipe conditioned on the rebuilder's host | **security-critical** *(documented, docs/04-strategies.md §3.3; docs/16-findings.md §3.104; crates/trigon-strategy/tests/literals.rs — `a_copyright_reaches_the_dotnet_invocation_byte_for_byte_and_is_never_evaluated`, `a_literal_is_passed_as_written_where_the_same_text_in_with_is_rendered`, `a_parameter_given_both_ways_is_refused_when_parsed_and_when_rendered`, `a_tool_receives_a_literal_as_a_parameter_and_never_sees_its_callers_literals`; crates/trigon-strategy/src/yarn.rs — `a_script_body_reaches_the_build_as_written_and_is_never_evaluated`; crates/trigon-registry/tests/infer.rs — `the_backend_the_wheel_names_reaches_the_build_as_written_and_is_never_evaluated`; crates/trigon-registry/tests/ci.rs — `what_a_workflow_says_reaches_the_build_as_written_and_is_never_evaluated`)* |
| **P47** | **An import writes nothing it has not checked, and nothing no record names.** `trigon runs import` reads a regular file within `Limits::total_expanded_bytes` and never decompresses it: a compressed one is refused. It is read with the tar reader artifacts are read with, under the same limits, and refused whole unless every entry is a regular file — no link, directory or device, no PAX record but a long name, nothing the reader noted, nothing after the end of the archive — at a path an export writes, matched as a whole string, so no `..` and no leading `/`; every blob hashes to its name; every JSON document is at most a published record's length and parses; every run record's id is its file's and one the store addresses, and every file it names is carried, each statement in the store's statement layout under the run or its published artifact; and every entry is named by a run in the file. Against the store, a run already there as the file has it is left alone, one there that differs is refused, and so is a statement at a path that holds another: a statement is never written over (`Store::put_statement`). Only then is anything written — the blobs, the set manifests, the statements, and each record last, under the lock a prune takes turns on — so a failed import leaves blobs no record names, never a record naming a blob that is not there. That lock is shared between writers, so each statement and each record is written as a create, never over another: a record another writer files under the id after the import looked is refused (`Store::create_run`, `StoreError::RunTaken`) and left as it is. `trigon runs export` holds the file it makes to the same checks before it writes it. | `trigon runs import` | a file written outside the store's layout; a link followed; a blob stored under a name it does not hash to; a record naming a blob the import did not write; a statement or a record written over | **security-critical** *(documented, crates/trigon/src/transfer.rs; crates/trigon-store/src/lib.rs — `is_statement_path`, `put_statement`, `create_run`; tests `an_import_is_checked_whole_before_anything_is_written`, `a_statement_that_differs_where_the_run_names_it_refuses_the_import`, `a_run_filed_here_after_the_import_looked_is_never_written_over`, `a_run_imported_is_created_and_never_written_over_another`, `a_failed_import_leaves_no_record_naming_blobs_that_are_not_there`, `a_run_whose_statement_has_a_long_name_or_an_epoch_moves_whole`, `a_statement_filed_where_its_run_names_it_is_never_written_over_another`, `every_path_a_statement_is_filed_at_is_one_an_import_files_it_at`)* |
| **P48** | **Every verdict `trigon publish` publishes names the stabilizer-set module that re-derives it, and the repository holds that module.** `publish` refuses, before anything is written, a verdict whose statement signs no `evidence.stabilizerSetModule`, saying how to build and name one; it writes the module `attest` kept in the store into `evidence/sha256/…` with the record's other evidence, one file however many records name it, and the record's evidence map names it as the statement signs it, which `check_record` holds the file and the map to. `attest` names a module only once it reports the run's set digest and stabilizes both stored artifacts to the digests the run recorded, and signs the sha256 of the bytes it ran (P23). A void and a withdrawal make no claim to re-derive, and name none. | `trigon publish` of a verdict | a published verdict nobody can re-derive once no binary carries its set; a record naming a module the repository does not hold, or holds as other bytes | **security-critical** *(documented, docs/19-distribution-and-lookup.md §4.1, D9; docs/09-attestations.md §7.1; docs/16-findings.md §3.109; crates/trigon/tests/publish.rs — `a_verdict_naming_no_module_is_refused_and_a_module_is_published_once`, `a_verdict_under_a_set_the_verifier_lacks_re_derives_through_the_module_it_published`; crates/trigon/tests/seam_attest_refusals.rs — `a_verdict_names_the_module_that_reproduced_it_and_the_store_keeps_its_bytes`)* |
| **P49** | **Every report that answers from a source names the checkpoint it answered from, root included, on one line that is the same in every report.** `trigon lookup`, `trigon check`, both forms of `verify-attestation`, `evidence sync` and `evidence list` print under each source `checkpoint <origin> <size> <root>`, the root spelled as the checkpoint's note spells it, and carry it in JSON, and in `check`'s SARIF, as `checkpoint`, `{origin, size, root}`. It is the checkpoint of the last log of the chain the answer was read from: the one the last sync accepted, which the state holds byte for byte, or under `--remote` the one fetched and verified; `verify-attestation --lookup` names every other source it asked, and its checkpoint, in `otherSources`, and in its text each under a `source` line of its own after the record's report, one per source even where two share a checkpoint; and where it finds no current record, every source it asked, each under its source in the text and in its stop's `sources`. A frozen source, whose checkpoint was read and verified, prints it too. A source that answers from no checkpoint, its clones not opened, prints no line, never one it did not answer from. Two users whose lines for one origin at one size differ were shown two trees under one key, a split view (A9). | the checkpoint verified as P33 and P39–P41, or P44 under `--remote`, verify it | a line naming a checkpoint other than the one the answer came from, or a root spelled differently in two reports; a source that answers with no line | **security-critical** *(documented, docs/19-distribution-and-lookup.md §6, §8, D11; docs/16-findings.md §3.110; crates/trigon/tests/lookup.rs — `every_report_prints_the_checkpoint_it_answered_from`, `remote_prints_the_checkpoint_it_fetched`, `remote_answers_unknown_for_a_frozen_log`; crates/trigon/tests/evidence.rs — `sync_and_list_print_the_checkpoint_accepted`, `a_key_change_and_a_succession_are_followed_on_sync`)* |
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
| **D15** | That `attestable` means full trust. It means one thing: the egress boundary was enforced and the run can say what crossed it. It is not a claim about the sandbox class, the base image or the strategy. | all tiers | **security-critical** | *(documented, docs/08-execution.md §7.3)* |
| **D15b** | Observability above Tier 1. The transcript says what crossed the network, never what the build did with it — no syscalls, no file access, no process tree. | all tiers | correctness-only | *(documented, docs/08-execution.md §7, Tier 2 and 3 are unimplemented by decision)* |
| **D15c** | That the registry pin served the *right* index. `environment.pin` now says the filter ran and how many versions it removed, at every tier; it does not check that what was served matches what the registry held at that moment. | all tiers | correctness-only | *(documented, docs/16-findings.md §3.17)* |
| **D16** | That the artifact guard survives a byte-level transformation. It compares bytes, so re-encoding, encryption or chunk reassembly defeats it. | — | **security-critical** | *(documented, docs/12-security.md §2.5)* |
| **D17** | That a divergence has been confirmed. The two-agreeing-attempts policy is specified and not implemented. | — | **security-critical** | *(documented, docs/16-findings.md §5)* |
| **D18** | That a `normalized` claim re-derived through an archived stabilizer set is shown to be `normalized`. A module returns stabilized bytes and nothing about which passes fired, so equal stabilized forms re-derive as `normalized_with_caveats` at most; `verify-attestation` reports the claim *consistent* — neither held nor refuted — and exits 0, since §6's 0 is a verdict at or above `normalized_with_caveats`, which is re-derived. The claim's tier is not re-derived, and the re-derived outcome is never promoted. | `wasm` feature | **security-critical** | *(maintainer, 2026-09)* |
| **D19** | That a published reproduction rate estimates an ecosystem. The corpora are small smoke sets, not prevalence-sampled. | — | correctness-only | *(documented, docs/16-findings.md §5)* |
| **D20** | Confidentiality of package text from a model provider, or of a Copilot prompt from the host process table — the whole prompt is an `argv` argument. | when `--model` names a provider | correctness-only | *(documented, crates/trigon-ai/src/copilot.rs:179-180 — `.arg("-p").arg(&prompt)`)* |
| **D21** | Resource or capability bounds on an archived stabilizer set beyond wasmtime's own sandbox. The host sets no fuel limit, no epoch interruption and no memory limiter below the 4 GiB a `wasm32` module can address; it makes an instance of the module for each artifact, so a module that loops never returns, and one that exhausts its memory fails the re-derivation (P23). The full build runs a module without the user naming one: `verify-attestation --lookup`, the command every verdict signs as its falsifying command, and `--record … --evidence` run the module a record's signed verdict names wherever the binary does not carry the verdict's set, and `attest` runs the module it is given before it names it. | `wasm` feature | **security-critical** | *(documented, crates/trigon-stabilize-wasm/src/host.rs:228 — `Store::new(module.engine(), ())`; docs/09-attestations.md §7.1)* |
| **D22** | That a custom stabilizer from the definitions repository is bounded by anything but review and the provenance cap. | a merged definitions PR | **security-critical** | *(documented, docs/12-security.md §8)* |
| **D25** | That a record verified with `verify-attestation --record` is the source's current word. It is checked against the log the directory holds and the checkpoint it is given: with none, a rewrite or a fork signed by the log key is not detected, and even with one a newer checkpoint withheld — a supersession or a withdrawal the directory does not hold — is not, since the record form judges no freshness; staleness and the frozen clock are `evidence sync`'s and `lookup`'s (docs/19 §10 phase 6), and nothing prevents a split view until witnesses cosign. What the directory itself shows is not disclaimed: a log that continues in a repository it does not hold answers *unknown* (P32). | `verify-attestation --record` | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §6, §7, §8)* |
| **D26** | That a checkpoint signed for a push that loses never leaves the host. A push rejected because the remote had already moved is refused before any object is sent, and the commit and its checkpoint are discarded in the losing clone (P34). A push that loses in the instant between the server advertising its refs and updating them has already sent its objects, the signed checkpoint among them, and a server may keep them unreachable — GitHub serves an unreachable commit by its id — which is a second root for one size under the log key, visible to whoever asks for that object. One publishing host makes the race impossible: `publish` takes a lock in the host's state directory as well as the store's, so two on one host never overlap, whatever stores they run from. A second host — or a second user of one, whose state directory is their own — makes this window possible, though narrow. | more than one host publishing to one repository | **security-critical** | *(documented, ADR-0014 "Why git, and not an OCI registry"; docs/19-distribution-and-lookup.md §2.2, D5)* |
| **D27** | That a publisher with no memory of the log detects a repository rolled back. The newest checkpoint of a log a host has published is kept in that host's state directory, and `publish` and `log sign` hold every tree to it (P34, P35). A host that has never published the log, or whose state directory is gone — an ephemeral CI runner — builds on whatever checkpoint the repository holds: on one rolled back by whoever can push, the log key signs a second root for a size it signed before, which every client holding the newer checkpoint refuses as an equivocation. The ruleset `log init` prints is what forbids the rollback; a runner that keeps `$XDG_STATE_HOME/trigon/publish/` between runs is held to it. | a publisher whose state directory does not hold the log's newest checkpoint | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §2.4, §8)* |
| **D28** | That a release asset is still the artifact its record names, or is there at all. GitHub, and whoever holds a token with contents-write on the repository — which can push to it as well — can replace or delete an asset, or the release that holds it; the log commits to an artifact's digest, which its verdict signs, and to nothing about where it is. A reader must hold what it fetches to that digest: `--rerun-comparison` re-derives from the bytes it is given, so an asset that is not the artifact fails the re-derivation rather than passing it. And the token is a credential with the push credential's reach, in the environment of every `publish` that uploads. | `rebuilt_artifacts = "github-release"` | correctness-only | *(documented, docs/19-distribution-and-lookup.md §2.3, §4.1, §8)* |
| **D29** | That anyone is told of a divergence. Under `divergences = "feed"` a divergence is published with its entry in `feed/divergences.atom`, in the same commit, and nobody is notified: ADR-0010 safeguard 4 becomes "published at publish time", as docs/19 D7 proposes. The feed holds the 200 most recent divergences, and the log every one. Between publications, whoever can push can edit it; the next publication of a divergence, or `--reconcile`, regenerates it from the log, and no client trusts a word of it. | `divergences = "feed"` | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §3, D7)* |
| **D30** | That the repository's kill-switch `trigon serve` reports is current. It is read from the publisher's working clone as of that clone's last fetch that succeeded, and says when that fetch began; a fetch that fails changes neither, so a time that stops moving is the sign the remote is not being read. The repository may have changed since, and a store with no clone, or no record of a fetch that succeeded, reports `unknown`. It stops what `trigon publish` publishes and nothing `serve` shows, which only `--stop-divergences` stops. | a publish repository configured | correctness-only | *(documented, docs/19-distribution-and-lookup.md §3)* |
| **D32** | That an answer is current. A source answers from its clone until its last successful sync is `stale_after` old — a day by default — and is frozen only once its newest leaf is `frozen_after` old — fourteen days: within those, a host or a mirror that withholds a newer checkpoint, holding a withdrawal or a supersession, is not detected, since what it serves is consistent, and a split view served alike to every location a client syncs is not either (A9). The newest leaf's time is the log's own word, which the holder of the log key sets (A8), and the heartbeat that keeps an honest log from freezing needs a scheduled job (docs/19 D5). Witnesses, which cosign with a time of their own (docs/19 §10 phase 7b), are what would bound it. Every report says, for every source, the checkpoint its answer came from, root included, as one `checkpoint <origin> <size> <root>` line two users can compare, and `lookup` and `check` say where it synced first that it did; none says that nothing newer exists, and `--offline` answers from the clone as it is until it is stale. | a synced source | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §6, §7, §8)* |
| **D33** | That keys trusted on first use are the log's. A source configured with `trust_on_first_use`, or by `TRIGON_EVIDENCE_TOFU=1`, pins a key it does not configure by reading the repository's `keys/` from the first location reached that holds a log on its first sync: whoever serves that location then — the repository's operator, a thief of its push credential, or anyone between (A8, A9) — chooses the keys, and every later sync is held to them, a log under other keys refused. They are recorded in the state directory, and every answer from the source says it rests on them and where and when they were read; a state that has lost them is refused until `--accept-state-loss`, which reads `keys/` again as a first contact does, and holds them to the checkpoint kept where it survives; a state that lost only its checkpoint keeps the keys. An initial checkpoint pins such a log only under the keys read. | `trust_on_first_use` | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §2.4, §6.1)* |
| **D34** | That a source, or a record in it, is available. Whoever serves a repository can withhold it: a source that cannot be reached answers from its clone until it is stale and then answers unknown, which fails a check only where the source is required; a successor elsewhere that cannot be reached fails the sync; a record whose leaf is logged and whose file is gone reads as deleted, and nothing here restores it. And a client with no state of its own — a fresh CI runner, or a state lost and accepted as lost with `--accept-state-loss` — holds a log only to the initial checkpoint it is configured with, or to nothing but itself, so a rollback behind that is not detected until the state directory is kept from one run to the next. A runner that keeps the cache and not the state directory has lost its state, as far as a sync can tell, and is refused until `--accept-state-loss`: the two are kept together. For `lookup` and `check`, an unreachable source that is not required leaves only its own answers missing, and the report names it; a package no reachable source holds a record for reads never checked, which is the truth from where the client stands and not a statement that nobody checked it. | a synced source | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §4.2, §6, §6.1, §8)* |
| **D35** | That the evidence behind a record can be had when it is needed. A record names its evidence by digest and the log commits only to the record: whoever can push can delete an evidence file or leave it unserved, and whoever writes the repository's releases can delete a rebuilt artifact's asset (D28). `verify-attestation --lookup` then reports the file unchecked, or cannot find the asset and asks for `--rebuild <file>` — never a pass — but the claim cannot be re-derived from what is gone, and a clone of a partial repository holds only what it fetched. Fetching evidence on demand, and downloading the asset, name the record to the host that serves them, which a clone's reads never do (docs/19 §7). And a rebuilt artifact downloaded from the publisher's releases is the publisher's own bytes: re-deriving from it checks the arithmetic and not the build (§1.12). | `verify-attestation --lookup` | correctness-only | *(documented, docs/19-distribution-and-lookup.md §4.1, §6, §7)* |
| **D36** | That `--remote` is private, unlimited, or complete. It tells GitHub, and anything that can read the connection's metadata, which key — which package — was asked about, per question; it is rate-limited for an unauthenticated client, so a large lockfile fails partway and those packages answer unknown, as does a key whose index file lists a record logged after the checkpoint it read — each file is read at whatever commit the host serves then — until it is asked again; and it reads the index file for the key and not the log, so a record the index leaves out — a withdrawal, a supersession, a record under another digest — is not seen, and an index a host serves stale or edited can omit one, turning a withdrawal back into the verdict it withdrew for that reader. It proves the inclusion of every record it answers from (P44), and holds nothing but the checkpoint and its last leaf to the log beyond them. It follows key changes only as far as the last sync recorded them, and not at all where the pins changed since, so a record under a key changed since fails verification there; and a succession into a repository that is not on github.com is not followed, and that source answers unknown. Each report says the first three. | `--remote` | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §6, §7)* |
| **D37** | That two agreeing attempts on one machine are independent of what it holds constant. With `[publish] same_host_confirmation` set — off by default — the gate counts a confirmation on that machine when nothing warm could supply it and its base image was pulled again by digest. It catches a floating dependency or a lucky fetch, never what the machine holds constant: its kernel, CPU and image store. | `same_host_confirmation` set | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §2.4, D8; docs/16-findings.md §3.97)* |
| **D38** | That a same-host confirmation's base image was checked against a registry. `[publish] same_host_local_images` — off by default, read only beside `same_host_confirmation` — accepts a cold confirmation on a local base image pinned by its content id — one no registry digest names, as those built on the machine — which no registry serves again: both attempts run on what the image store holds under that id, so bytes damaged or rewritten there go uncaught (D37). A registry's image not pulled again — one a run named by its content id included, which `rebuild --confirm` asks podman's `RepoDigests` about and pulls again by a registry digest — and any warm cache, the image an earlier run derived among them, are refused whatever is set. | `same_host_confirmation` and `same_host_local_images` both set | **security-critical** | *(documented, docs/19-distribution-and-lookup.md §2.4, D8; docs/16-findings.md §3.105; crates/trigon-api/src/publication.rs — `not_cold`; crates/trigon/src/main.rs — `image_pin`)* |
| **D39** | That the stabilizer-set module a verdict names is honest. Its sha256, signed into the verdict, binds it to the signer's claim, and nothing else can be substituted for it; but a signer who signs a false verdict can name a module that makes it re-derive — one that reports the right set digest and stabilizes any two artifacts to what the verdict signs. `attest` checks a module against the native set before naming it, which binds an honest attestor and not a dishonest one. Rebuilding the module from source with `scripts/build-set-module.sh`, which builds it reproducibly, and comparing digests is how a verifier checks it. The module names the commit it was built from (`trigon_source_commit`), which `verify-attestation` prints: the module's own word, carried in the bytes the verdict signs, and a module that named another commit than its own fails that rebuild; one built from uncommitted changes names `<commit>.dirty` and cannot be rebuilt at all, which `attest` says and does not refuse. | a verdict re-derived through its module | **security-critical** | *(documented, docs/09-attestations.md §7.1)* |
| **D40** | That an imported run was made where, when and how its record says. `trigon runs import` checks the file (P47) and not the claims: each record keeps the host id, start time, cache state and image pin the exporting machine wrote, and gains nothing about the importing one. The publication gate's same-host rule compares the host ids the records carry, so a record that names another machine counts as one however it was made, and a confirmation's interval and coldness are read from what it says. The records also decide what a confirmation of an imported run does: `rebuild --confirm` repeats the strategy the file carries — the source it fetches and the commands it runs — on the base image and at the egress tier the record names, and refuses `--image` and `--egress` beside it, so the file's maker chooses what the confirming machine pulls and runs, not only what the gate reads, and a confirmation repeats whatever the first attempt named rather than choosing anew. Importing a run trusts whoever made the file as far as sharing a store with them would (D7): whoever can write an export a store imports can release a pair the gate would withhold. | `trigon runs import` | **security-critical** | *(documented, docs/19-distribution-and-lookup.md D8; crates/trigon/src/transfer.rs; crates/trigon/tests/publish.rs — `attempts_made_in_two_stores_and_imported_into_one_are_published_there`)* |
| **D24** | Any bound on a stolen signing key. A statement carries no third-party time, so a key stolen today signs statements that verify like those it signed before the theft. The external log check once meant to bound this was never enforced, and went with the log. docs/19 D6 chooses the bound: key epochs sealed in the evidence log, or a certificate chain checked against witnessed or time-stamped time. | a key the operator holds | **security-critical** | *(documented, ADR-0014 "What this costs"; docs/19-distribution-and-lookup.md §8, §10 phase 7a)* |

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
2. **Check the signing identity** against your own policy with `--public-key <hex>`
   (`trigon public-key <keyfile>` prints it). Without it the tool still re-derives and tells you the
   signature was present and unchecked, which is a different answer from unsigned.

   A verified signature says which key signed, never when. Nothing bounds what a stolen key can sign
   (D24), so a signature is evidence about the key and not about the time.
3. **Set your own threshold** with `Match::is_at_least`. The default is not a recommendation.
4. **Read the `applied` list.** If you reject a particular normalization you can see it fired, with
   its risk tier and provenance, and discard the result.
5. **Filter on `derivation.method`** if you want "no model touched this".
6. **Read the egress tier, and read `attestable` as exactly what it says.** A run at
   `--egress open` records `attestable: false` and carries no transcript. A run at `mirror-only` or
   `deny-all` records `attestable: true` and a transcript you can fetch by hash and read — which is
   a claim about egress being accounted for, and not a claim about anything else.
7. **Distinguish a confirmed result from a single attempt, and a stale pass from no data.**
8. **For npm, do not read `reproduced` as `attributed`.**
9. **Hold a published record's log to a checkpoint you already hold.** `verify-attestation
   --record` detects a rollback, a rewrite or a fork only back to the checkpoint it is given —
   `--checkpoint`, or the source's state or initial checkpoint under `--source` — and says when it
   was given none (P33, D25). Keep the checkpoint from your last check, and compare it with somebody
   else's.

**If you run Trigon:**

10. **Choose the egress tier deliberately.** `--egress open` is the default and it voids the strong
    claim. An enforced tier needs a mirror image and a base image you built first.
11. **Only you may name a local path as a source.** `file://` chosen by the thing under test is the
    dangerous one.
12. **Read `crates/trigon-ai/src/copilot.rs`'s module docs before `--model copilot:`.** Prefer a
    provider with a real system message where the choice exists.
13. **Keep `trigon watch` on loopback** unless you have thought about it. Build logs are not
    redacted (D14).
14. **Set `total_expanded_bytes` to something your host can absorb.** The default ceiling is 4 GiB
    and a hostile artifact may reach it before being refused.
15. **Treat the rebuilt artifact as untrusted.** It is the package's own build output; do not
    install or execute it because it reproduced.
16. **Before a real sweep, talk to the registries:** a User-Agent with a contact URL, `Retry-After`
    honoured, per-host token buckets.
17. **Publish to an evidence repository from one host, and give the push credential nothing
    else.** The host's lock keeps one `publish` at a time on it, whatever store it runs from; a
    second host publishing to the same repository can lose a push in a window that sends its signed
    checkpoint anyway (D26). Keep the host's state directory, `$XDG_STATE_HOME/trigon/publish/`,
    from one run to the next — it is what holds the log key to what was published (D27) — keep
    `[publish] log_key` where only `trigon log sign` reads it (P35), set the ruleset `trigon log
    init` prints, and use a push credential scoped to the one repository. Where rebuilt artifacts
    are published, give the GitHub token contents-write on that repository alone, with an expiry,
    and put it only in the environment of the `publish` that uploads (P38, D28). Rotate with
    `trigon log key-change` and `trigon log succeed`, never by editing `keys/`, and keep an old log
    key after a succession (P37).
18. **Import runs only from machines you would let write to your store.** `trigon runs import`
    checks the file and takes each record's claims as they came (P47, D40): a confirmation imported
    from a machine you do not control is one you cannot vouch for, and the gate counts it all the
    same.

**If you review the definitions repository:**

19. **Two-party review for anything touching a stabilizer**, a non-empty prose `reason:`, and the
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
- **Importing somebody else's export to confirm a run.** The gate counts the machine id an imported
  record names, whatever machine made it (D40). Confirm on a machine you control.

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
- Observability rises above Tier 1 (D15b) — that widens what a run can assert beyond its network.
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
- The standalone client of the evidence store is built (`docs/19-distribution-and-lookup.md` §10
  phase 9, under ADR-0014), or witnessing (phase 7b) or a bound on a stolen key (phase 7a). The
  first adds a consumer who never runs Trigon and never sees this document, and each phase adds its
  properties, side effects and disclaimers here (phase 8), as phase 4 added P31–P33 and D25, the
  writer P34–P38 and D26–D30, syncing P39–P42 and D32–D34, and answering from the clones and over
  HTTPS P43–P45 and D35–D36.
- **D4 or D7 is decided**, and `rebuilt_artifacts` or `divergences` changes its default: P36, P38,
  D28 and D29 then describe every publication rather than a configured one.
- **`same_host_confirmation` or `same_host_local_images` changes its default** (docs/19 D8): D37,
  and with the second D38, then describe every confirmation made on one machine rather than a
  configured one.
- **Runs reach a store by any way but a file the operator hands `trigon runs import`**, a store
  pulled from on a schedule or a queue filled by other machines' workers, or **an import starts
  checking what a record claims**, as a signature by the machine that made the run would let it:
  P47 then describes input nobody chose file by file, and D40 narrows to what the check leaves
  unproved.
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
| `OUT-OF-MODEL: non-default-build` | Needs a configuration §1.6 marks dev-only or unsupported. **Non-default alone is not enough** — `[publish] same_host_confirmation` is off by default and supported, and so is the verifier built `--features wasm`. | §1.6 |
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
  built system `trigon rebuild --attest` signs in the process that ran the build — what `trigon
  attest` signs, through the same code, since docs/19 §10 phase 3. Is `--store` then
  `trigon attest` the supported path for a claim that matters? *Proposed: yes, and `--attest` on a
  run that built is dev convenience.* → §1.4
- **Q15.** `--egress open` is the shipped default for `rebuild` and `sweep`. Supported production
  posture, or should the default change? *Proposed: supported — the alternative is a tool that does
  not run out of the box, and the attestation records the weaker claim.* → §1.6

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
**277 documented / 1 maintainer / 3 assumption / 5 inferred**. Every assumption and inferred tag
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
| §8 the definitions repository | §1.9; §1.10 A4; D22; §1.13 item 19 |
| §9 signing key handling | §1.13; Q2 |
| §10 the twelve invariants | P1–P30, each with a symptom and a tier |
| §11 out of scope | §1.3 |
| §12 redistribution | not security-contract content; stays in `12` |
