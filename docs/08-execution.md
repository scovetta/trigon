# 08. Execution and sandboxing

## 1. The runner abstraction

```rust
#[async_trait]
pub trait BuildRunner: Send + Sync + 'static {
    fn caps(&self) -> RunnerCaps;
    fn accepts(&self, p: &BuildPlan) -> bool;
    async fn start(&self, p: &BuildPlan, o: &RunOpts) -> Result<Box<dyn BuildHandle>, SandboxError>;
    async fn health(&self) -> RunnerHealth;
}

pub struct RunnerCaps {
    pub isolation: IsolationClass,        // Container | UserNs | Gvisor | Kata | Vm
    pub privileged: bool,
    pub exec: bool,                       // exploration environments only
    pub egress_modes: Vec<EgressTier>,
    pub observability: ObservabilityTier,
    pub max_concurrency: usize,
}
```

| Adapter | Where it is used | Isolation |
|---|---|---|
| `podman` | local default (rootless) | UserNs |
| `docker` | local alternative | Container |
| `k8s-job` | **fleet default**, with a gVisor or Kata runtime class where the cluster offers one | Gvisor / Kata / Container |
| `cloudbuild` | GCP-native deployments | Vm |
| `codebuild` | AWS-native deployments | Vm |
| `local-unsafe` | Development only, labelled as such, refuses to sign | Process |

v1 builds `podman` and `k8s-job`. The rest stay documented seams. Every adapter becomes a permanent
cell in the test matrix, so a user has to ask for one by name before we write it
([ADR-0008](adr/0008-one-implementation-per-seam.md)).

## 2. The container pattern

Taken from the prior art, because it is right:

```dockerfile
# syntax=docker/dockerfile:1.10
FROM {{ base_image_digest }}

RUN <<'EOF' | sh          # setup: install system deps, fetch the mirror CA if needed
{{ setup }}
EOF

RUN <<'EOF' | sh          # source: mkdir /src && cd /src && <rendered source script>
{{ source }}
EOF

RUN <<'EOF' | sh          # deps:   toolchain + dependencies against the pinned registry
{{ deps }}
EOF

RUN <<'EOF' >/build       # build:  WRITTEN, NOT RUN
set -eux
{{ build }}
mkdir -p /out && cp "/src/{{ output_path }}" /out/
EOF

WORKDIR /src
ENTRYPOINT ["/bin/sh", "/build"]
```

**Setup, source and deps run at image-build time; the build itself is `docker run` of the written
`/build` script.** Three payoffs:

1. **Layer caching** across sibling versions of a package, which often separates a 20-second build
   from a 200-second one.
2. **Clean phase boundaries** for timing. Each `RUN` is a layer, and layer metadata gives per-phase
   durations without instrumenting anything.
3. **A retained container and image**, which an exploration-environment agent can `exec` into and a
   human can pull when triaging.

We recover timings from container inspection and image history, on a best-effort basis. A flaky
inspect never fails an otherwise good rebuild, so it runs without `set -e`, and its absence yields
`None` rather than zero ([`02-domain-model.md`](02-domain-model.md) §7.1).

A sentinel exit code passes through so that a *failed* build still reaches artifact and log
collection. Failed builds carry information.

## 3. Images

- **Every base image pins by digest**, and that digest sits in the run key and in the attestation.
- We build base images ourselves from a `trigon-images` repository, one per ecosystem and toolchain
  family, each reproducible and attested. Dogfooding is the point.
- **Keep the distinct-digest count near thirty**, so worker nodes hold them all warm. Image pull
  bandwidth breaks early at fleet scale ([`10-scale.md`](10-scale.md) §2).
- **Mirror every base image into our own registry.** Anonymous Docker Hub pull limits end a sweep in
  its first minute.
- `DetectOs(base_image)` selects the package-manager commands (apk/apt/dnf) so that a strategy's
  `system_deps` render for whichever base the strategy picked.

## 4. Dependency-state pinning

Rebuilding `foo@1.2.3` two years after publication resolves *today's* transitive dependencies. That
is a large, invisible source of divergence, and left alone it makes **any package whose build
resolves a floating range irreproducible by construction.** Expect mass "was reproducible, now isn't"
flapping, and weeks spent blaming your own diff logic.

Three mechanisms, cheapest first.

### 4.0 A committed lockfile, where one exists

A build that resolves against a committed `package-lock.json`, `Cargo.lock`, `poetry.lock`, `uv.lock`
or `Gemfile.lock` has already pinned every transitive version, and the time filter adds nothing. The
strategy records `RegistryMoment::Lockfile { digest }` and the mirror serves ordinary responses.

Worth stating because the alternative is an afternoon spent debugging a mirror problem that does not
exist. Check for the lockfile first, and reach for §4.1 when there is none or when the lockfile does
not cover the build's own tooling.

### 4.1 Time-filtered registry (npm, PyPI, RubyGems, NuGet)

An in-sandbox proxy filters registry responses to versions that existed at the target's publish
timestamp. The build is pointed at it by configuration, not interception:

```
PIP_INDEX_URL=http://pypi:2024-09-13T10:31:26Z@mirror.internal:8081/simple
npm --registry "http://npm:2024-09-13T10:31:26Z@mirror.internal:8081"
```

The timestamp travels in the URL userinfo, which means **plain HTTP to a host we control**. That is
why the common path needs no MITM at all (§6).

**Plain HTTP is not enough for pip, and its refusal is silent.** `PIP_INDEX_URL` alone gets a single
warning — *"the repository located at timewarp is not a trusted or secure host and is being
ignored"* — after which pip resolves as though no index were configured. Every build then installs
from the live index while every log line says it was pinned, and the only symptom is the mirror
reporting **zero requests**, which looks exactly like a build that happened not to need anything.
`PIP_TRUSTED_HOST` must be exported alongside it, carrying the bare `host:port` with no scheme and
no credentials:

```
PIP_INDEX_URL=http://pypi:2024-09-13T10:31:26Z@mirror.internal:8081/simple
PIP_TRUSTED_HOST=mirror.internal:8081
```

This cost real measurements. The PyPI numbers in the M1 smoke corpus were gathered without the time
pin they claimed to have, and the discrepancy only surfaced when a *pinned build backend* became the
first thing to ask the mirror for a package after the index was configured. Anything that verifies
the pin is working — a non-zero request count, a withheld-version count — is worth more than the
configuration that sets it up.

### 4.2 Index-commit pinning (crates.io, and any git-indexed registry)

Resolve a `crates.io-index` commit that satisfies the target's `Cargo.lock`, and serve the registry
from that commit, either as a local registry replacement or over the sparse protocol. A timestamp
lacks the precision, so this is a correctness fix rather than an optimization, and it generalizes to
any index-backed registry.

Either way the pin, whether `RegistryMoment::Timestamp` or `RegistryMoment::GitCommit`, goes into the
strategy and therefore into the attestation, so a third party can reproduce the same dependency
state.

### 4.3 The dependency mirror

Separate from the time filter, and needed as much at scale: a co-located pull-through cache
per ecosystem.

The mirror also enforces the first artifact-hash control. It loads the run's guard manifest
([`01-architecture.md`](01-architecture.md) §1.2) and **refuses to serve the target artifact's own
URL for the duration of that run** ([`12-security.md`](12-security.md) §2.1). At `MirrorOnly` egress
the mirror is the only reachable host, so that one rule closes the registry path to the forgery
attack before any hashing happens.

 Roughly 250 MB of dependency traffic per build across tens of thousands of builds
comes to tens of terabytes per sweep. Ingress usually costs nothing. **Getting rate-limited or
abuse-flagged costs a lot.** The mirror cuts unique bytes by an order of magnitude and keeps us a
good citizen.

## 5. Egress tiers

```rust
pub enum EgressTier { DenyAll, MirrorOnly, GitAndMirror, Open }
```

| Tier | Reachable | Use |
|---|---|---|
| `DenyAll` | Nothing | Vendored builds, and the strongest claim available |
| `MirrorOnly` | Our registry mirror and image registry | **The default** |
| `GitAndMirror` | The above plus allowlisted git hosts | Builds that fetch git dependencies |
| `Open` | Anything, fully logged | Last resort, and it **downgrades the trust tier** |

The strategy **declares** the tier, the network configuration **enforces** it, and the attestation
**records** it as a required signed field. A pass at `Open` egress gets a *different verdict name in
the UI* rather than a footnote. Give it a footnote and everything drifts to `Open` within six
months.

Enforcement runs as a network namespace with a veth pair whose default route points at an
allowlisting proxy. Every request logs host, path, method, response digest, and byte count.

**Rootless podman gets there by a different route,** because creating a veth into the host namespace
needs privileges a rootless user does not have. What it does have is an **internal network**, which
netavark firewalls off from the internet *and* from the host. The build joins one and nothing else,
and the mirror runs as a container on both that network and an ordinary one, so it is the island's
only route out. Measured rather than assumed:

| Container is on | Reaches internet | Reaches host |
|---|---|---|
| default network | yes | yes, via `host-gateway` |
| internal only | no | no |
| internal **and** default | yes | **no** |

The last row is why the mirror is a container rather than a host process: once a container touches
an internal network, host access is blocked on all of its interfaces, so a relay forwarding to a
mirror on the host cannot work.

Two consequences worth stating plainly. Rootless `podman build` **cannot join a named network** at
all, refusing with "cannot use networks as rootless", so at this tier the deps phase moves out of
the image and into the container run: deps stops being a cached layer, which is the trade for an
enforceable boundary on a laptop and goes away wherever the builder can join a network. And the
mirror must **proxy artifact bytes rather than redirect to them**, because the build has no route to
where a redirect points.

## 6. Do we need MITM?

Mostly no, and recognizing that cuts a lot of scope.

The time-filtered registry is a host we control, addressed over **plain HTTP** by configuration, so
the common path needs only:

- a network namespace,
- an allowlisting **CONNECT** proxy for HTTPS to permitted hosts,
- the plain-HTTP mirror endpoint the build is configured to use.

Full MITM with an ephemeral CA arrives only for package managers that configuration cannot
redirect. When we need it:

- **Mount the certificate, never the key.** Keep the proxy in a separate namespace and under a
  separate UID.
- **Prefer netns isolation with a veth default route** over `iptables` DNAT scoped by
  `-m owner --uid-owner`. That second option is a Docker-daemon-shaped workaround, and it leaves an
  unmonitored egress hole for anything running as the proxy's UID.
- Expect a **per-ecosystem CA-injection matrix**. Go module verification and some Node and Rust
  tooling bundle their own trust stores, and chasing the resulting phantom failures costs real time.
- **Redact credentials.** The proxy sees plaintext, and the UI shows network transcripts to users.

## 7. Observability tiers

Observability comes in **tiers that degrade gracefully**, and the attestation records the tier we
achieved.

| Tier | Mechanism | Availability |
|---|---|---|
| **0** | none | everywhere |
| **1** | **network transcript via the proxy** | **everywhere** |
| 2 | runtime trace points (gVisor's own, or a runtime hook) | some runtimes |
| 3 | eBPF process/file/network tracing, or a Tetragon/Falco event stream | self-managed nodes only |

**Ship Tier 1 in v1 and nothing else.** This reverses an earlier design decision, so here is the
reasoning:

- eBPF **conflicts with the isolation choices**. gVisor intercepts syscalls in userspace and does not
  surface them to host eBPF the way the naive design assumed, and Kata needs the probe inside the
  guest kernel. gVisor and eBPF do not compose.
- It **breaks on managed Kubernetes**, including Autopilot, Fargate, Cloud Run and ACI, which is the
  "runs in any cloud" requirement it was meant to serve.
- It requires **privilege we otherwise avoid**.
- It generates the **blob volume that blows the storage budget**. Raw event streams at fleet scale
  run 50 to 500 TB, against roughly 500 KB for an aggregated graph per run.
- Tier 1 already answers the question people ask: **what did this build download?**

When Tier 3 arrives it should consume Tetragon or Falco events rather than hand-written eBPF
programs. Writing our own is a six-month project sitting at right angles to the thesis.

### 7.1 What the network transcript is for

- Spotting **hidden remote dependencies**, meaning a build fetching from a non-registry host.
- Spotting **unpinned downloads**. A `curl … | sh` shows up in a transcript and looks alarming there.
- Feeding detection rules and the provenance-contradiction feed.
- Carrying **the artifact-hash check** ([`12-security.md`](12-security.md) §2.2). The proxy
  decomposes each fetched archive and compares its members against the run's guard manifest, so this
  path needs an archive reader as well as a hasher. It shares `trigon-archive` with the judgement
  half for that.

That is why a **failed** rebuild still produces something worth keeping, and it departs from the
prior art's emphasis on successes.

### 7.2 How Tier 1 is implemented

Almost all of it already existed. The mirror hashes **every** body as it streams past, because that
is how the artifact guard works — and then kept the hash only when it matched the run's guard
manifest. Every clean observation, which is to say every ordinary download, was computed and dropped
on the floor. The transcript is those discarded observations written down.

One line per response body served, behind the fixed prefix `NET-EXCHANGE`:

```json
{"route":"artifact","url":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
 "sha256":"e1c6…","bytes":2361,"checked":"opened"}
```

- **`route`** is `index`, `artifact`, `toolchain` or `passthrough`, because each is a different
  claim: an index response is the registry pin working, an artifact is a dependency, a toolchain is
  the one thing a build fetches that then *runs*, and a passthrough is something on an index host
  that no filter applied to.
- **`sha256`** is over the bytes as served, undecoded — the same digest the guard compares. A reader
  can therefore check the guard's verdict rather than take it.
- **`checked`** says how far the guard got: `opened` (every member compared against the manifest),
  `hashed` (whole-body digest only — too large to open, not an archive, or a manifest with no
  members), `generated` (a body the mirror composed itself, so no guard applies), `unarmed` (no
  manifest on this run), or `partial` (the body never finished). Without this field, "opened and
  clean" and "never opened" read identically, and they are the difference between a check and the
  appearance of one.

A `partial` row is the one worth explaining. A row is written when a body finishes, so a client that
hangs up mid-response used to produce **no row at all** — and bytes crossed into the build with
nothing saying they had. A build that aborted every download at ninety-nine per cent would have
pulled gigabytes and left an empty, `attestable: true` account behind it. The row is now written
when the stream is dropped, carrying the bytes that actually crossed and the digest of *that prefix*
rather than of the resource, because a partial body recorded as a whole one is the single most
misleading line a transcript could carry.

Index rows carry one field more: **`withheld`**, the number of versions the time filter removed from
that document before serving it. `None` on anything that is not a filtered index, which is not the
same as `Some(0)` — zero withheld is evidence the pin applied and found nothing to remove, while a
dependency tarball is not evidence about the pin at all. A second marker, `NET-REFUSED`, records
requests the mirror turned away, with the path, the status and the reason: a refusal serves no body,
so it has no digest and no place in the transcript, but "somebody asked and was refused" is a
different thing to investigate than silence.

Between them those two carry the whole of `PinEvidence` out of the island, which is what closes
[`17-backlog.md`](17-backlog.md) B7b. `Observed::from_transcript` counts the rows; the counters on
the `Mirror` object cannot leave, so a test drives real traffic through a mirror and asserts the two
produce the same answer.

**The channel out is the container log**, the same one guard trips use. The mirror sits inside the
build's network island and the host has no route to it — that is the point of the island — so the
host reads both streams with `podman logs` and filters on the marker. Two properties make this safe
rather than merely convenient: only the mirror writes to that log, so the build cannot forge a line
into it the way it can into its own output; and a marker line the host cannot parse is an **error**,
not a skipped line, because a truncated transcript and a clean short one must not look alike.

The lines are written to **stdout**, not through `tracing`. Trips go through `tracing::error!` and
survive the default `warn` filter; an `info!` line would not, and the mirror container is started
with no `-v` and no `RUST_LOG`. A record that appears only when somebody set an environment variable
is the "configuration that looks applied and isn't" failure again — and this one decides whether a
run is attestable.

### 7.3 What "attestable" now means

A run is attestable exactly when a **complete account** of what crossed into the build exists. Not
"the tier we asked for", and not "the runner we have": it is derived from the transcript and nothing
else, in one function with one match, so the tiers cannot come apart from the claim.

| Tier | Account | Why |
|---|---|---|
| `deny-all` | complete, and empty | `--network none` on the image build *and* the run: the build has no interface, so "nothing crossed" is enforced by the kernel rather than observed |
| `mirror-only` | complete, and listed | the mirror is the only route out, and it writes down every body it serves |
| `open` | none | there is no boundary to account for, which is the entire content of the tier |

**Present and empty is not the same as absent.** An empty transcript says the build's egress was
completely accounted for and nothing came through — which at `deny-all` is what having no network
interface *means*. An absent one says no account exists. The store keeps them apart by writing an
empty blob in the first case and no blob in the second, and `attestable` is derived from which of
the two it is. Collapsing them would turn "we never looked" into "we looked and it was clean", which
is the reading the whole design exists to make impossible.

What it does **not** assert: that the sandbox class, the base image or the strategy are good enough
to sign. Those are separate claims made elsewhere. Reading this one as "full trust" is how a control
starts reporting success it has not earned.

## 8. Sandbox hardening

We treat the build container as hostile, since it executes the package's own build scripts by
design.

- **No credentials, no cloud metadata endpoint, no signing keys.** A separate attestor process does
  the signing (§9).
- **Write-only blob access, scoped to `runs/<run-id>/`.** A read-capable credential would let the
  build fetch the upstream artifact out of our own content-addressed store by its digest, bypassing
  the egress guard ([`12-security.md`](12-security.md) §2.3). Where the blob store cannot
  express write-only access, the sandbox writes through a sidecar that holds the credential and
  exposes an append-only endpoint. The blob-store host sits on the egress deny list.
- Non-root, seccomp and AppArmor profiles, read-only root filesystem with a tmpfs workspace, dropped
  capabilities.
- CPU, memory, PID and disk quotas; a hard wall-clock kill.
- `privileged: true` requires the runner to advertise the capability and is recorded in the
  attestation.
- Every mount is explicit; the workspace is the only writable path.

**Worker classes** ([`01-architecture.md`](01-architecture.md) §1):

| Class | Egress | Blob access | Rights |
|---|---|---|---|
| `infer` | network and model providers | read and write | Holds upstream bytes during `Decompose`, emits the guard manifest. No build execution. |
| `build` | **mirror only, and the mirror refuses the target's URL** | **write-only, `runs/<run-id>/`** | Container execution. Reads nothing that holds upstream bytes. |
| `judge` | blob store and registry | read and write | Reads both artifacts. No container execution. |

The build worker's inability to reach the upstream artifact is what makes forging a match hard, and
it takes all three columns of that table to hold. Egress alone leaves the blob store open.

## 9. Signing sits outside all of this

The sandbox writes outputs to a content-addressed store. A **separate attestor process**, in a
different pod, never executing sandbox-derived code, reads by hash, re-derives the equivalence claim
on its own, and signs only then. Under sigstore keyless the workload identity is the crown jewel, so
tokens stay run-scoped with minute-scale TTLs. See [`09-attestations.md`](09-attestations.md) §3.
