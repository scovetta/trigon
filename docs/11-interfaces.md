# 11. Interfaces

## 1. Personas first

Build a UI before choosing a persona and you end up with a beautiful dashboard nobody opens. The
prior art shows why. Its operator tool is a forty-package terminal IDE with tmux integration, and its
web dashboard runs 228 lines. Read that as **a web UI built for yourself losing to a TUI**, rather
than as web mattering less.

| # | Persona | Wants | Served by |
|---|---|---|---|
| 1 | **The Trigon team and the reproducibility community**, 90% of year-one usage | Triage throughput: *"500 failed, cluster them, show me the 12 root causes, let me fix one and re-run 40"* | **CLI and the failure-cluster view** |
| 2 | **Registry and ecosystem operators** | A fleet number that goes up, and a regression alarm: *"RubyGems 3.6.9 broke reproducibility for 4,000 gems"* | **Web: fleet + target views** |
| 3 | **Enterprise consumers and compliance**, the ones who pay | *"For the 3,000 packages in my lockfile: which are verified, which diverge, which have never been checked"* | **Web: the lockfile check** |
| 4 | **Incident responders**, rare and high-drama | *"Is this version compromised, and what is in the tarball that is not in the source?"* | **Run and diff views, permalinks** |

So: **web for personas 2 and 3, and a very good CLI for personas 1 and 4.**

## 2. CLI

One binary, subcommands. **What follows is the intended surface; the built subset is smaller and its
spellings differ in places.** `trigon --help` is authoritative, and today it carries:

```
trigon verify <upstream> <rebuild> [--attest F] [--key K] [--store D]
trigon verify-attestation <bundle> --rerun-comparison --upstream A --rebuild B [--public-key HEX]
trigon verify-attestation --record F --evidence D (--source N | --log-vkey K --attestation-key K) \
    [--checkpoint C] [--rerun-comparison --upstream A --rebuild B]
trigon rebuild <purl> --image <pinned> [--egress TIER] [--timewarp auto] [--store D] [--attest F]
trigon rebuild --confirm <run> --store D
trigon sweep <targets> --image <pinned> [--store D]
trigon attest [--store D] [<run>] [--key K] [--prune]
trigon runs [--store D]
trigon stabilize | stabilizers [--list-profiles] | strategy render|tools | mirror | mirror-image | resolve | fetch | build
```

Three differences from the intended surface are decisions rather than gaps.
`trigon attest` reads a **store**, not a run id on a control plane, because the attestor is a
separate process that reads blobs by hash ([`09`](09-attestations.md) §6). `verify` takes two
artifact paths rather than a PURL, because the judgement half has no registry client by
construction. And there is no `serve`, `work` or `ingest` yet: those are M4.

The intended surface. **Aspirational, not a changelog** — much of this is unbuilt, and the
attestation lines in particular have been overtaken: what exists today is `trigon keygen` /
`public-key` for keys, `trigon attest --key <file> [--prune]`, and
`trigon verify-attestation [--public-key <hex>] [--rerun-comparison] [--output text|json]`, whose
JSON no longer has the `transparency` key it carried while a transparency-log check existed
([ADR-0014](adr/0014-git-evidence-store-without-rekor.md) removed the check). Publishing is
`trigon publish`, and looking a verdict up is `trigon lookup` and `trigon check` against evidence
repositories, all designed in [`19`](19-distribution-and-lookup.md) and not built.
`--sign kms://` and `--identity` below are the shape a fleet wants, and belong to
[B21](17-backlog.md) steps 4-5. [`09-attestations.md`](09-attestations.md) §3 is the current
account; `trigon --help` is the authority.

```
# The front door. Starts from something the user already has.
trigon check ./package-lock.json
trigon check ./requirements.txt --format sarif
trigon check --sbom ./sbom.spdx.json

# Single targets.
trigon verify pkg:npm/left-pad@1.3.0
trigon verify pkg:pypi/cryptography@42.0.5 --explain
trigon verify ./dist/my-1.0.0.whl --source ./repo@abc123f      # bring your own artifact and source

# Understanding a result.
trigon explain <run-id>                    # rendered diff report + build timeline + network summary
trigon logs <run-id> [--phase build]
trigon transcript <run-id>                 # the AI transcript, if any

# Strategies.
trigon strategy show <target>
trigon strategy test <target> --strategy ./build.yaml
trigon strategy annotate-diff <run-id>     # generates the inferred-vs-corrected diff for a PR
trigon strategy pin <target> --to ./build.yaml

# Attestations.
trigon attest <run-id> --sign kms://...
trigon verify-attestation ./trigon.intoto.jsonl --identity <policy> --rerun-comparison

# Running the thing. The first four exist; the rest of this block is still design.
trigon serve <store> [--public] [--queue sqlite://…|postgres://…]
                                           # the corpus as a website, and its API
trigon worker <queue> --image auto --work ./w --store ./s
                                           # one worker; run as many as you like
trigon enqueue <queue> <purl>...           # put targets on the queue
trigon grant <queue> <id> --scopes request # issue a credential, printed once
trigon sweep create --ecosystem npm --top 100000 --budget '$500' --tier bulk \
                    --selection bulk-default        # packages to artifacts; see 02 §8.1
trigon sweep status <sweep-id>
trigon sweep estimate --ecosystem npm --top 100000 --selection all   # artifacts, builds, cost
trigon ingest run --ecosystem npm,pypi              # tail the change feeds; see 10 §5
trigon ingest status                                # cursor position and lag per feed
trigon bench run regression --corpus npm-top-1k

# Introspection.
trigon plugins                             # every registered implementation of every seam
trigon stabilizers --profile wheel         # the set, with risk tiers and provenance
```

Design rules. Every command that produces a verdict emits `--format json` or `--format sarif`.
Every long-running command streams structured progress. Nothing requires a cloud account.

Running `trigon verify` on a laptop with Podman and no network beyond the registries tests the whole
"runs locally" claim, and it is an M1 exit criterion.

## 3. HTTP API

> **Superseded for the fleet case by [`22-management-layer.md`](22-management-layer.md) §5.**
> The twenty endpoints below are the original sketch. The management-layer plan cuts them to the
> surface a decoupled front-end actually needs, and each absence there is argued: no endpoint may
> write an `outcome`, there is no anonymous evidence route, no worker-proxying route, and no
> `/v1/costs` while there is no price table. Read this section for the shape and that one for the
> contract.

`axum`, OpenAPI 3.1, JSON. Token auth plus OIDC, with an optional read-only public mode.

```
GET    /v1/targets/{purl}
GET    /v1/targets/{purl}/versions              # the sampled version ladder
POST   /v1/runs                                 # request a verification
GET    /v1/runs/{id}
GET    /v1/runs/{id}/events                     # SSE: live phases, log lines, network events
GET    /v1/runs/{id}/diff
GET    /v1/runs/{id}/attestation
POST   /v1/check                                # lockfile / SBOM → verdict table
GET    /v1/clusters                             # failure clusters, ranked
POST   /v1/clusters/{id}/rerun
GET    /v1/sweeps        POST /v1/sweeps        GET /v1/sweeps/{id}
GET    /v1/strategies/{digest}
POST   /v1/strategies/preview                   # corpus-wide impact of a proposed stabilizer
GET    /v1/contradictions                       # rebuilds that contradict published provenance
GET    /v1/costs
GET    /v1/ingest                               # per-feed cursor, lag, admitted/skipped counts
POST   /v1/ingest/replay                        # replay a feed from a cursor after an outage
POST   /v1/query                                # saved, shareable, editable queries
GET    /v1/health  /v1/metrics
```

`POST /v1/query` returns a **query** rather than prose. See §4's note on the Ask view.

## 4. Web UI

> **Amended by [`22-management-layer.md`](22-management-layer.md) §9.** "Embedded, so there is no
> separate deployment step" and "decoupled, so a public site can be deployed on its own" are in
> direct contradiction, and drifting rather than deciding produces an embedded UI that silently
> rots. The decision: the API is the only contract, and the embedded build is the *same* front-end
> vendored for local mode.

TypeScript, React and Vite, embedded in the binary with `rust-embed`, so `trigon serve` gives the
full UI with no separate deployment step.

### The hero: lockfile / SBOM check

**Paste a lockfile, an SBOM, or a repository URL. Get a verdict table with an explicit
*never checked* column.**

No other view starts from something the user already has. The rest assume they care about a package
we happen to have scanned. This one serves persona 3 head-on and persona 1 in passing.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  package-lock.json · 1,284 packages                        [Re-check] [⇩]   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✔ Reproduced        912   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░  71%     │
│  ◐ With caveats      141   ▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  11%     │
│  ✖ Divergent           4   ▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   0.3%   │
│  ⊘ Unsupported        63   ▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   5%     │
│  ? Never checked     164   ▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  13%     │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✖  node-ipc          10.1.1   divergent · 3 files · executable content     │
│  ✖  event-stream       3.3.6   divergent · 1 file  · source not in repo     │
│  ◐  esbuild           0.21.5   caveats  · platform binary, lossy stabilizer │
│  ?  internal-utils     2.0.0   never checked · private registry             │
└─────────────────────────────────────────────────────────────────────────────┘
```

*Never checked* is a row of its own rather than a gap. A blank cell reads as green, and reading as
green is the one mistake this view cannot afford. Artifacts the selection policy skipped land there
too, labelled with the policy that skipped them, so the denominator stays honest
([`02-domain-model.md`](02-domain-model.md) §8.1).

### Failure clusters, the operator's home screen

The first draft of this design left this view out, and it may be the most important one for
persona 1.

Group failed runs by **normalized failure signature**, and show count, trend, first-seen, and
affected ecosystems. One click opens a definitions pull request for the cluster, one re-runs it, one
sends it to the Builder.

That is what turns 500 failures into 12 tickets, and it is the surface where somebody operates the
repair-to-rule flywheel ([`07-ai.md`](07-ai.md) §5).

### Diff → stabilizer, with corpus-wide impact preview

From a divergence: propose a stabilizer, then **test it against the whole corpus before proposing
it**:

```
Proposed: jar-build-metadata + "Bnd-LastModified"
Impact:   would flip 340 targets to Reproduced
          would flip   2 targets to Divergent   ← inspect these first
          risk tier: metadata · provenance: human(you)
[ Preview the 2 regressions ]   [ Open PR with reason: ]
```

That preview is what makes accepting a stabilizer safe. Without it, every stabilizer is a leap of
faith, and we sign stabilizers.

### Target view with a sampled version ladder

A version-by-outcome grid makes "reproducible since RubyGems 3.6.7" legible at a glance, which is
the story worth telling, and no other tool produces that artifact.

Filling it exhaustively multiplies target count by 10 to 50 times, so we **sample**: latest,
latest-per-minor, the first release after each toolchain bump, and any version with a known
divergence. Unsampled cells render as **not checked**, and never as blank.

```
rails         7.0  7.0.4 7.0.8  7.1  7.1.2 7.1.3  7.2  7.2.1
              ·    ✔     ✔      ·    ✔     ✔      ·    ◐
              └ not sampled                              └ caveats: native ext
```

### Provenance-contradiction feed

A rebuild that contradicts published trusted-publishing provenance is the most newsworthy output
this system produces. It gets an alarm-shaped view of its own rather than a filter on a table.

### Run view

Timeline (resolve → source → strategy → build → judge), build log, **network transcript**, the
strategy that was used with its derivation, the environment descriptor, and the AI transcript when
one exists. Every element links to the blob that backs it.

### Diff view

The rendered diff report: a file tree with per-file status and content kind, side-by-side member
diffs, which stabilizers fired and what they touched, and the Explainer's annotations, marked
**advisory, unsigned, model-generated**.

### Cost view

Spend per sweep, per ecosystem and per role, tokens by role, cache-hit rates, and dollars per
verdict gained. What you cannot see here, you discover on an invoice.

### Fleet health

Queue depth by tier and size class, oldest job age, worker saturation by class, lease expiries,
**upstream rate-limit backoff state**, and **ingestion lag per feed**. The backoff state has to ship
before the first real sweep, because upstream reputation breaks first
([`10-scale.md`](10-scale.md) §2). Ingestion lag matters as soon as feeds are live: a stalled cursor
looks exactly like a quiet week on the registry.

### Freshness

Every target row shows when we last checked, against which stabilizer set digest, at which egress
and trust tier, and whether the result is **confirmed** or a single unconfirmed attempt
([`07-ai.md`](07-ai.md) §3). **A stale pass is worse than no data**, because it looks like data, and
an unconfirmed pass is worse than a stale one, because it looks confirmed.

### Run permalinks

An unauthenticated permalink per run, carrying the attestation and a copy-pasteable
`trigon verify-attestation --rerun-comparison` line. That link is the distribution mechanism, the
thing someone pastes into an issue thread.

### The Ask view, deferred and constrained

Natural-language querying waits, and when we build it, it sits as a **sidecar to the
failure-cluster view**, answering "ask about these 340 runs" rather than greeting a visitor. The
prior art built this, inside a TUI, for an operator already deep in a triage flow. That placement is
the tell. It helps someone who would rather not write SQL right now, and it does nothing for a
first-time visitor.

One hard requirement: **it emits a saved, shareable, editable query rather than prose.** If it cannot
show you the query it ran, cut it.

## 5. Output formats

| Format | Use |
|---|---|
| JSON | the API and `--format json` |
| SARIF | `trigon check` in CI, so results land in code-scanning UIs |
| in-toto JSONL | attestation bundles |
| CycloneDX / SPDX annotation | attach verdicts to an existing SBOM |
| HTML | the rendered diff report, standalone and self-contained |

`trigon check --format sarif` in a pull-request workflow is the lowest-friction adoption path
available, and it costs one serializer.
