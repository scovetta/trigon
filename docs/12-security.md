# 12. Security model

## 1. The threat that matters

Trigon executes untrusted code by design, since rebuilding a package means running that package's
own build scripts. Sandbox escape is a real concern, and §6 handles it. A different threat defines
this system:

**An attacker causes Trigon to sign an attestation stating that their backdoored package reproduces
cleanly from source.**

Everything else in this document comes second.

### 1.1 The attack, concretely

Using only capabilities the design otherwise grants:

1. `evil@1.2.3` ships a backdoored tarball. Its repository, README, CI configuration and a helpfully
   named `BUILD.md` are **all attacker-controlled**, and all of them are read by the Resolver and the
   Builder.
2. Injected content explains that this project's build requires downloading a prebuilt binary from
   `https://cdn.evil.example/evil-1.2.3.tgz`, because of a licensing constraint.
3. The Builder emits a **syntactically valid, schema-passing** strategy that does what the text
   asked for.
4. It builds. It matches **byte-for-byte**, which it would, since it *is* the published artifact.
5. It passes the confirmation attempt, and it passes every attempt after that.
6. We sign `rebuild/v1` and `equivalence/v1`. A backdoor has been laundered into a reproducibility
   claim, with a signature.

**The confirmation attempt does the attacker's work here.** A design leaning on "we ran it twice and
got the same answer" has, in this scenario, run a perfect forgery twice.

## 2. The controls that defeat it

Three controls, in order of how much work each does.

### 2.1 The mirror refuses to serve the target to its own build

The cheapest control, and the one to reach for first. `Decompose`
([`01-architecture.md`](01-architecture.md) §1.2) records the upstream artifact's URL in the guard
manifest, and the mirror declines that URL for the duration of that run. At `MirrorOnly` egress the
mirror is the only reachable host, so a build that asks for its own published artifact gets nothing.

That closes the case where the attacker points at the registry. It does nothing about a fetch from
`cdn.evil.example`, which is what 2.2 is for.

### 2.2 Hash what crosses the proxy, against a filtered member set

**Hash every response body that crosses the proxy into the sandbox. When the target artifact, or a
guarded member of it, arrives from the network, the run is `Void`.**

```rust
// trigon-observe, in the egress path
pub struct ArtifactGuard {
    artifact_digest: Digest,
    guarded: HashMap<Digest, GuardedMember>,   // from the guard manifest
}

impl ArtifactGuard {
    /// `body` is the raw response. `members` is its decomposed contents when the
    /// response is itself an archive, empty otherwise.
    fn observe(&self, body: &[u8], members: &[(EntryPath, Digest)]) -> Option<VoidReason> {
        if sha256(body) == self.artifact_digest {
            return Some(VoidReason::UpstreamArtifactReachedSandbox {
                via: GuardChannel::Egress { host: self.host() },
                matched: GuardMatch::WholeArtifact,
            });
        }
        for (path, d) in members {
            if let Some(m) = self.guarded.get(d) {
                return Some(VoidReason::UpstreamArtifactReachedSandbox {
                    via: GuardChannel::Egress { host: self.host() },
                    matched: GuardMatch::Member { path: m.path.clone(), bytes: m.bytes },
                });
            }
        }
        None
    }
}
```

Two details separate this from the version that voids every legitimate build.

**Compare at member level, not response-body level.** A build downloads dependency archives, and
what matters is whether a *member* of one of those archives is a member of the target artifact.
Hashing the whole response body would miss exactly that, and hashing every member without the
filters below would fire constantly.

**`guarded_members` is filtered at `Decompose` time.** A naive member set contains every empty file,
`__init__.py`, `.gitkeep`, and stock LICENSE text in the artifact. Every empty file in the world
hashes the same, so an unfiltered guard voids any build that downloads an archive containing one. The
filters:

| Filter | Rule | Why |
|---|---|---|
| Minimum size | Drop members under 4 KiB | Small files collide across unrelated packages as a matter of course |
| Stock content | Drop members matching a maintained list of common licence texts and generated stubs | Same reason, for files above the size threshold |
| Also-in-source | Drop members byte-identical to a file in the resolved source tree | A vendored file the build legitimately re-fetches is not evidence of anything |
| Executable weighting | Never drop a member classified `Executable`, whatever its size | These are what an attacker wants to smuggle |

A member the filters drop is still compared during `Compare`. Filtering narrows what triggers a
`Void`, and it changes nothing about the verdict.

### 2.3 Write-only blob access from the sandbox

The network is not the only path to the upstream artifact. Our own content-addressed store holds it,
the target carries `upstream_artifact_digest`, and a read-capable credential inside the sandbox turns
the whole attack into one request:

```
GET <cas>/blobs/sha256/<upstream_digest>   →   cp to the output path
```

That request never crosses the egress proxy, so 2.2 never sees it.

So the build worker's blob credential is **write-only, scoped to `runs/<run-id>/`**, and the blob
store host is on the egress deny list rather than treated as infrastructure. The judge worker reads
both sides; the build worker writes one side and reads nothing. Where a blob store cannot express
write-only access, the sandbox writes through a sidecar that holds the credential and exposes an
append-only endpoint.

The same reasoning covers the source cache, the strategy cache, and the log store. Any component
holding upstream bytes is unreachable from the sandbox; any component the sandbox can reach holds
digests.

### 2.4 Why `Void` rather than a failure

`Void` sits outside pass and fail, so tripping the guard gains an attacker nothing. They cannot turn
it into a false divergence against a rival package either, because tripping it requires controlling
the build, which requires controlling the package.

`Void` also has a legitimate cause worth naming: a package whose build fetches something
byte-identical to a substantial member of its own artifact. Self-referential builds do this, and so
does a package that depends on an older version of itself. Those runs report
`Void { UpstreamArtifactReachedSandbox }` with the matched member named, they route to review rather
than to publication, and a reviewer can pin an exemption in the definitions repo with a mandatory
`reason:`, exactly as a custom stabilizer works.

### 2.5 The limits

The guard compares bytes, so an attacker who fetches the artifact re-encoded, encrypted, or
reassembled from chunks defeats it. Four things raise that cost:

- `MirrorOnly` egress makes an arbitrary-host fetch a policy violation on its own.
- A fetch from a non-registry host shows up in the network transcript and marks the run for review.
- 2.1 and 2.3 close the two paths that need no attacker infrastructure at all.
- Fetching a large opaque blob and copying it to the output path with no compilation in between has a
  detectable shape. That is a detection rule rather than a hard control.

None of these closes the gap. The guard shuts down the cheap versions of the attack, and the
expensive versions become visible rather than impossible.

## 3. Trust boundaries

```
┌──────────────────────────────────────────────────────────────────────────┐
│ CONTROL PLANE (trusted)                                                  │
│   scheduler, API, UI, definitions loader                                 │
│   no untrusted code execution                                            │
└──────────────┬───────────────────────────────────────────────────────────┘
               │ jobs (data)
┌──────────────▼───────────────┐  ┌──────────────────────────────────────┐
│ INFER WORKER (semi-trusted)  │  │ BUILD WORKER (hostile)               │
│  reads attacker text         │  │  executes attacker code              │
│  holds model credentials     │  │  NO credentials, NO metadata endpoint│
│  holds upstream bytes        │  │  NO signing keys                     │
│  emits the guard manifest    │  │  egress: mirror only                 │
│  NO build execution          │  │  blob access: WRITE-ONLY, run-scoped │
│  NO signing keys             │  │  CANNOT REACH THE UPSTREAM ARTIFACT  │
└──────────────┬───────────────┘  └──────────────┬───────────────────────┘
               │ strategy + guard                 │ writes blobs, reads none
               │ manifest (digests)               │
               └──────────────┬───────────────────┘
                              ▼
              ┌───────────────────────────────┐
              │ JUDGE WORKER (semi-trusted)   │
              │  reads both artifacts         │
              │  NO container execution       │
              └───────────────┬───────────────┘
                              │ comparison + blobs
              ┌───────────────▼───────────────┐
              │ ATTESTOR (trusted, holds keys)│
              │  never executes sandbox output│
              │  RE-DERIVES before signing    │
              └───────────────────────────────┘
```

The build worker's inability to reach the upstream artifact is a structural control, and it takes
three separate access rules to hold: mirror refusal (§2.1), egress hashing (§2.2), and write-only
blob access (§2.3). The egress policy alone gives you the first two and leaves the third open.

## 4. Prompt injection

Package source, README files, CI configuration, registry metadata, published provenance and build
logs all arrive as **attacker-controlled text reaching a model that holds tools.** We accept and
mitigate this threat rather than claiming to have solved it.

### 4.1 Mitigations

| Mitigation | What it buys |
|---|---|
| Tools stay **read-mostly and workspace-scoped** | An injection cannot reach other runs or the control plane |
| `run_in_container` exists **only in the exploration environment** | That sandbox already runs the package's own build scripts, so an injection gains nothing it did not already have *there* |
| Model output parses into a **typed, validated `Strategy`** | It never splices into a shell command as free text |
| **Schema validation rejects** wider egress, unpinned images and unregistered tools | Code enforces the policy rather than model judgement |
| **The artifact-hash check** (§2) | Closes the one attack that survives everything else |
| Untrusted content arrives **nonce-delimited**, with control characters stripped and lengths capped | Forged framing gets much harder to inject |
| **Tool results and model text stay unforgeably distinguishable in the transcript** | A build log printing fake tool-result JSON cannot rewrite history during replay |
| Operator instructions travel in a **system-role message**, never spliced into user text | A real operator channel exists, so injected text cannot impersonate one |
| Model snapshot ids stay **pinned**, with sampling parameters recorded | An injection cannot hide behind provider drift |

### 4.2 Where the "it's already hostile" argument holds, and where it does not

**It holds** for host integrity and confidentiality. The sandbox already executes attacker-authored
code, and an injected model adding more attacker code crosses no new boundary there.

**It fails** for integrity of the verdict, which is the product. The threat is §1.1 rather than
escape. So the argument answers one question, and §2 answers the other.

### 4.3 The structural backstop

A fully successful injection produces a **candidate strategy** and nothing more. That strategy
then has to reproduce the artifact twice, on different workers, in an environment with no `exec` and
restricted egress, under the artifact-hash guard. The attacker's remaining path runs through building
a recipe that reproduces. Absent §1.1, that means the package builds from its source.

## 5. Free-form shell: an honest accounting

The design prefers a restricted step DSL and records `Manual` raw-script strategies at a lower
trust tier. Calling that a security control would be comfortable and wrong.

> **Schema-validating a string that contains bash is validating a string.**

So we do both halves, and say which one carries the weight:

- **(a) The environment is the enforcement point.** Deny-all-but-mirror egress, filesystem allowlist,
  no credentials, the artifact-hash guard, and a build worker that cannot reach the upstream artifact.
  **This is the control.**
- **(b) The step DSL is the preferred representation**, `Manual` records at a lower trust tier, and
  a recurring manual strategy becomes a work item ([`04-strategies.md`](04-strategies.md) §8).
  **That is hygiene. It improves reviewability rather than security.**

Treating (b) as a boundary on its own would be the more dangerous of the two available mistakes.

## 6. Sandbox hardening

We treat the build container as hostile.

- No credentials, no cloud metadata endpoint (blocked at the network layer rather than unset), no
  signing keys, no access to the control plane.
- Non-root; dropped capabilities; seccomp and AppArmor profiles; read-only root filesystem with a
  tmpfs workspace as the only writable path.
- CPU, memory, PID and disk quotas; hard wall-clock kill; output size caps.
- `privileged: true` requires the runner to advertise the capability, is rare, and is recorded in the
  attestation.
- gVisor or Kata runtime classes where the cluster offers them. **They do not compose with host
  eBPF** ([`08-execution.md`](08-execution.md) §7), which is a real constraint, and making
  observability a tier resolves it.

## 7. Multi-tenancy

Implementation waits for v2. The rules get decided now, because retrofitting them costs far more
later.

- **Key shared caches by trust origin.** Public definitions are trusted, and tenant-inferred
  strategies stay tenant-scoped. A shared strategy cache is a feature and a **poisoning vector**,
  because a malicious tenant could otherwise train a bad strategy into everyone's cache.
- **Promotion to the shared cache** requires a clean re-run in a neutral environment plus review.
- **Build workers run single-tenant with full teardown.** That conflicts with warm caching, and the
  resolution is to cache **immutable, hash-addressed content** such as images, source objects and
  dependency bytes, and to cache no **state**.
- Blob paths and database rows are tenant-scoped; the run key includes the tenant for
  tenant-inferred strategies.

## 8. The definitions repository is itself a supply chain

A malicious pull request adding a custom stabilizer that normalizes away a backdoored file makes a
real mismatch vanish. That attacks the product's core claim head-on.

Controls, in layers:

- **Social:** two-party review for anything touching stabilizers, plus the **mandatory non-empty
  prose `reason:`** field, which leaves an unjustifiable change visibly unjustified.
- **Technical bounds:** custom stabilizers are declarative and may zero or rewrite a *metadata* field
  only. They **may not** delete or rewrite executable content.
- **Detection:** any run in which a custom stabilizer altered more than a threshold of bytes, or
  touched a file classified `Executable`, is flagged in the UI **and** in the attestation with
  `NoteCode::CustomStabilizerTouchedExecutable`.
- **Provenance cap:** a custom stabilizer carries `Provenance::Human`, so using one caps the outcome
  at `NormalizedWithCaveats`. A consumer demanding `Normalized` never sees the class at all.
- **Impact preview:** the corpus-wide preview ([`11-interfaces.md`](11-interfaces.md) §4) shows a
  reviewer how many verdicts a proposed stabilizer would flip, in both directions.

## 9. Signing key handling

- **Keys never enter a worker that has executed sandbox output.** The attestor runs as a separate
  process in a separate pod.
- **The attestor re-derives the equivalence claim before signing**, running the same comparison a
  client runs with `--rerun-comparison`. It costs one stabilize-and-compare pass over local blobs,
  and nothing cheaper defends against a compromised judge worker.
- Under **sigstore keyless** the workload identity is the crown jewel, so tokens stay run-scoped with
  minute-scale TTLs and verification pins the identity policy.
- Under **KMS**, only the attestor's service account holds the signing role, and key usage audits
  independently of Trigon's own logs.

## 10. Invariants and the tests that enforce them

| # | Invariant | Enforced by |
|---|---|---|
| 1 | The judgement half cannot call a model | `xtask` policy test over `cargo metadata --all-features`; `cargo-deny` bans; `require_no_features` on judgement crates ([`01`](01-architecture.md) §2.2) |
| 2 | `Match::Normalized` implies every applied stabilizer is `Builtin` with `risk <= Metadata` | runtime check, unit test, and proptest over arbitrary stabilizer sets |
| 3 | Stabilizers are total and never panic | fuzz target over `parse → stabilize → write → parse` |
| 4 | Stabilization is idempotent | proptest: `stabilize(stabilize(x)) == stabilize(x)` |
| 5 | Both artifacts receive an identical transform | The type signature. A stabilizer takes no side parameter. |
| 6 | The build worker cannot reach the upstream artifact | Three integration tests: the mirror refuses its URL, an egress fetch of it voids the run, and a blob-store read from inside the sandbox is denied |
| 7 | A model-authored strategy cannot raise the egress tier | validation test over generated strategies |
| 8 | Signing never occurs in a process that executed sandbox output | deployment test asserting the attestor's image contains no runner code |
| 9 | Identical inputs produce identical verdicts | flake test: three runs of the `smoke` corpus; any flip is a **P0 bug in the deterministic layer** |
| 10 | A `Void` run is never published as a divergence | unit test over the publication path |
| 11 | The guard does not fire on stock content | Corpus test: replay 500 known-good builds against the guard and assert zero `Void` |
| 12 | Two attempts that disagree publish nothing | unit test over the confirmation policy |

Invariants 2, 6 and 10 carry the security weight. Invariant 11 is what stops the guard from being
switched off in frustration six weeks in. Invariant 9 is the one an unrelated change breaks without
anybody noticing, which is why it runs on every pull request.

## 11. Out of scope

- **Malware detection.** Trigon answers whether an artifact matches a source. Whether the source is
  malicious is a different question. Build observability gives forensic context rather than
  detection.
- **Verifying that the source is trustworthy.** A package that builds faithfully from a repository
  containing a backdoor reproduces, and should. That is a correct result and a different problem.
- **Defending a compromised control plane.** Compromise the scheduler and the attestor and the
  signed output means nothing. `--rerun-comparison` limits the damage, because an independent party
  re-derives the equivalence claim without trusting us.

## 12. Redistribution

We keep bytes on divergence, because they are the evidence. Those bytes are someone else's published
artifact and someone else's rebuilt output, so a public instance is redistributing them. Two rules
keep that defensible: divergence evidence is served from an authenticated endpoint rather than the
public bucket, and the retention window is bounded (90 days by default) with the digests kept
permanently. A maintainer disputing a finding gets access; a scraper does not.
