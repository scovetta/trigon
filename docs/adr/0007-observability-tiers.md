# ADR-0007. Observability as a tier, shipping the network transcript only

**Status:** accepted, reversing an earlier draft

## Decision

Observability comes in **tiers that degrade gracefully**, and the attestation records the tier we
achieved.

| Tier | Mechanism | Availability |
|---|---|---|
| 0 | none | everywhere |
| **1** | **network transcript through the egress proxy** | **everywhere** |
| 2 | runtime trace points | some runtimes |
| 3 | eBPF, or a Tetragon or Falco event stream | self-managed nodes only |

**Ship Tier 1 in v1 and nothing else.**

## Cutting eBPF

An earlier draft made eBPF, through `aya`, a core differentiator. It is the wrong first investment.

- **It conflicts with the isolation choices.** gVisor intercepts syscalls in userspace and does not
  surface them to host eBPF the way the naive design assumed. Kata needs the probe inside the guest
  kernel. gVisor and eBPF do not compose.
- **It breaks on managed Kubernetes**, including Autopilot, Fargate, Cloud Run and ACI, which is the
  "runs in any cloud" requirement it was meant to serve.
- **It requires privilege** we otherwise avoid, on the one workload we have declared hostile.
- **It generates the blob volume that blows the storage budget.** Raw event streams at fleet scale
  run 50 to 500 TB, against roughly 500 KB for an aggregated graph per run. The prior art aggregates
  into a syscall graph rather than persisting events, and uses Tetragon rather than hand-written
  eBPF.

## Tier 1 is enough to start

The network transcript answers the question people ask: **what did this build download?** It spots
hidden remote dependencies, unpinned downloads, and `curl | sh` patterns, and it feeds the
provenance-contradiction feed.

It also carries **the artifact-hash guard** (`12-security.md` §2), the most important security
control in the system, which lives in the egress path and would exist even at Tier 0 if the proxy did
nothing else.

## Tier 3, later

Consume Tetragon or Falco events rather than writing eBPF programs. Writing our own is a six-month
project sitting at right angles to the thesis, and a named user asking for syscall data should
justify it.
