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
