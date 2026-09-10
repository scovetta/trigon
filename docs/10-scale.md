# 10. Scale, cost, and operations

## 1. Sizing

A naive calculation says 100k packages, 70% cached, 30k builds at a 90-second median, 50 workers,
therefore 15 hours. The arithmetic holds and **every input is wrong.**

**Wrong input 1: packages are not artifacts.** A package set counts packages, and a run verifies one
artifact. `cryptography@42.0.5` publishes an sdist plus roughly twenty wheels. The default selection
policy ([`02-domain-model.md`](02-domain-model.md) §8.1) keeps the source distribution, the pure
artifacts, and the platform-matched wheels we can host, which lands around **1.6 artifacts per
package** across npm and PyPI and closer to 1.05 for crates.io and RubyGems. Take `All` instead and
the same set produces three to five times the work.

**Wrong input 2: a median is not a mean.** Build durations are heavy-tailed. The prior art carries
`SizeHint{SHRIMP, JUMBO}` and `ExecutionHint{FAST, EXTENDED}` because that tail exists and needs
routing of its own. A 90-second median implies a mean several times larger, and a 5% tail sitting at
a 30-minute timeout contributes as many core-seconds as the whole naive estimate.

**Wrong input 3: builds are not artifacts.** The repair loop multiplies builds, and the confirmation
policy adds a second attempt to **everything we publish**, not to repairs alone
([`07-ai.md`](07-ai.md) §3).

| | Naive | Warm sweep | Cold sweep |
|---|---:|---:|---:|
| Packages | 100,000 | 100,000 | 100,000 |
| Artifacts (default selection) | 100,000 | ~160,000 | ~160,000 |
| Artifacts needing a build | 30,000 | ~24,000 | ~112,000 |
| Confirmation attempts | 0 | ~22,000 | ~95,000 |
| Repair attempts | 0 | ~4,000 | ~48,000 |
| **Build executions** | **30,000** | **~50,000** | **~255,000** |
| Mean duration | 90 s | 240 s | 420 s |
| Core-seconds | 2.7 M | 12 M | 107 M |
| Build slots for a 15-hour sweep | 50 | ~225 | ~1,980 |
| Wall clock on 50 slots | 15 h | ~67 h | ~25 days |

The warm column assumes 85% of artifacts hit the run-key cache and skip both attempts, and that
confirmation runs against warm image and dependency caches at roughly half the cold mean. The cold
column assumes no cache at all and a 43% first-attempt failure rate.

**Fifty build workers is off by four times warm and forty times cold.** Say "a couple of thousand
build slots" or say "a month", and pick one. Claiming a same-day cold sweep on a small fleet is
claiming neither.

The cold number is the argument for prevalence ordering (§6) and for proving the system at 5k before
quoting 100k. It is also the argument for the `unconfirmed` tier: an exploratory sweep that publishes
nothing can run single-attempt and halve that column.

### 1.1 Where the money goes

Compute is not the bill. At spot pricing for a 4 vCPU, 16 GB instance, 255k builds averaging 420 s
lands in the mid five figures. The constraints sit elsewhere, and they scale with build count rather
than with package count.

| Resource | Cold 100k sweep | Mitigation |
|---|---|---|
| **Dependency bytes** | ~250 MB mean per build × 255k ≈ **60 TB** | Co-located pull-through mirror per ecosystem → 1–3 TB unique. **Mandatory above ~1k targets.** |
| **Image pulls** | up to 130 TB uncached | Mirror every base image; pin by digest; keep distinct digests under ~30 so nodes stay warm. |
| **Git clones** | 25 to 40k distinct repos, ~8 TB naive. Clones scale with *packages*, not builds, so this column does not move. | `--filter=blob:none --single-branch` fetch-by-commit (5–20× reduction); a repo-URI-keyed cache serving a tar of `.git`; per-host token buckets. |
| **Blob storage** | ~3 MB/run, ~760 GB/sweep | Budget per run: log under 2 MB gzipped, network transcript under 100 KB, AI transcript under 200 KB. **On a match, store the rebuilt artifact's digests rather than the artifact.** Keep bytes on divergence. |
| **Cross-AZ egress** | 60 TB at the per-GB rate | Keep mirrors zonal and co-resident with workers. |

**All in: low tens of thousands of dollars for a cold 100k-package sweep, and weeks rather than days
on a fleet of a few hundred slots.** A warm re-sweep of the same set costs a small fraction of that,
which is the number worth optimizing for, because after the first pass every sweep is warm.

Two anti-patterns are easy to fall into, so they get names:

- **Do not clone into memory.** The prior art's agent-side clone uses an in-memory filesystem and
  storage backend. On a large monorepo that is a memory bomb, and monorepos are the repos thousands
  of packages share.
- **Do not persist raw syscall events.** A build issuing ten million syscalls produces gigabyte-scale
  raw streams, and at 255k builds that reaches hundreds of terabytes. Aggregate, or collect nothing
  ([`08-execution.md`](08-execution.md) §7).

## 2. What breaks first

Ranked by how soon it happens and how much the recovery hurts.

1. **Upstream reputation, rather than capacity.** GitHub clone volume, Docker Hub pull limits, npm
   and PyPI abuse detection. Nobody slows you down. They **block** you, and unblocking is a human
   process measured in days. That needs per-**host** *and* per-**egress-IP** token buckets, a stable
   declared `User-Agent` with a contact URL, `Retry-After` honoured with backoff across the fleet
   rather than per worker, and **a conversation with the registries before the first real sweep.**
2. **Image pull bandwidth and node disk churn.**
3. **The duration tail.** One 45-minute JUMBO target squats a slot while ten-second npm targets queue
   behind it. **Size-class queues** fix that. More workers do not.
4. **Blob and object count**, where the retention rules above go unenforced.
5. **Postgres**, a distant fifth.

### 2.1 Prove it at 5k

The prior art's largest published benchmark covers roughly 5,000 package-versions. Nobody has
demonstrated this at 100k. **Design the interfaces for 100k, prove the system at 5k, and publish the
number we measured.** Claim 100k before running it and we lose the credibility the project runs
on.

## 3. The queue

**Write it: roughly 200 lines of SQL.**

```sql
CREATE TABLE job (
  id            BIGSERIAL PRIMARY KEY,
  cache_key     BYTEA NOT NULL,               -- what may be reused; NOT unique
  attempt       SMALLINT NOT NULL,            -- 0 initial, 1 confirmation, …
  UNIQUE (cache_key, attempt),
  tier          SMALLINT NOT NULL,            -- 0 interactive, 1 regression, 2 bulk
  size_class    SMALLINT NOT NULL,            -- 0 small, 1 large
  ecosystem     TEXT NOT NULL,
  sweep_id      UUID,
  payload_ref   BYTEA NOT NULL,               -- content hash; the payload lives in blob storage
  visible_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts      SMALLINT NOT NULL DEFAULT 0,
  leased_by     TEXT,
  leased_until  TIMESTAMPTZ
);
CREATE INDEX job_ready ON job (tier, size_class, visible_at)
  WHERE leased_by IS NULL;
```

Leasing is `SELECT … FOR UPDATE SKIP LOCKED` with a visibility timeout and an attempt counter.

**Why not `pgmq`:** it is a Postgres *extension*, and most managed Postgres offerings decline to
install it, which conflicts with running anywhere. Rolling our own also lets `enqueue` share a
transaction with the run-state write, giving a **transactional outbox**, which is why the queue lives
in `trigon-store` rather than in a crate of its own.

At 90k jobs spread over days the average rate sits well under one message per second, so **something
else breaks first**. Three caveats are real:

- **Long visibility timeouts.** A 45-minute build needs a 45-plus-minute lease, and a
  dead-tuple-heavy archive table needs per-table autovacuum tuning or it bloats.
- **Keep heartbeats and progress off the queue.** Use a separate table, or you amplify writes on the
  hot path.
- **KEDA polling** at one-second intervals across many scalers creates pointless connection load.
  Poll every 10 to 15 seconds, through pgbouncer, with a connection cap.

**Hard rule: Postgres holds pointers and small scalars. Every payload over 8 KB goes to blob storage,
addressed by content hash.** At this scale the `runs` table carries the risk rather than the queue,
and only where payloads sit inline.

## 4. Metadata schema

```
targets     (id, ecosystem, namespace, name, version, artifact, upstream_digest, publish_time,
             prevalence_score)          -- one row per artifact ever seen
packages    (id, ecosystem, namespace, name, repo_url, repo_confidence, strategy_family)
runs        (id, cache_key, attempt, target_id, sweep_id, state, verdict, outcome, derivation,
             strategy_digest, stabilizer_set_digest, environment_ref, timings, costs,
             created, finished)         -- PARTITIONED BY RANGE (created), monthly
verdicts    (run_id, target_id, outcome, published, attestation_ref)  -- append-only
strategies  (digest, kind, canonical_json_ref, first_seen, derivation, trust_tier)
sweeps      (id, package_set_name, package_set_hash, tier, budget, spent, created)
repos       (uri, bytes, commits, head, measured_at)
ai_calls    (id, run_id, role, model, prompt_version, cache_hit, tokens, cost, transcript_ref)
failure_sigs(hash, class, first_seen, count, repair_strategy_digest, promoted_rule)
rollups     (day, ecosystem, outcome, count, cost)   -- so the fleet view never scans partitions
```

We partition `runs` monthly and keep `verdicts` append-only. `rollups` exists because a fleet
dashboard that scans partitions stops working at the moment it becomes interesting.

`failure_sigs` houses the flywheel ([`07-ai.md`](07-ai.md) §5). It turns "this failure signature
has come up 340 times and one repair fixes all of them" into a query rather than an intuition.

SQLite for single-binary local mode, with the same schema minus partitioning.

## 5. Continuous ingestion

Sweeps are the wrong steady state. A sweep is how the corpus gets populated once; after that, the
interesting target is the version published forty minutes ago, and catching it costs a fraction of
re-sweeping.

Each ecosystem publishes a change feed, and the ingester tails it:

| Ecosystem | Feed | Latency |
|---|---|---|
| PyPI | RSS at `/rss/updates.xml`, plus the XML-RPC `changelog_since_serial` for gaps | minutes |
| npm | the CouchDB `_changes` replication feed | seconds |
| crates.io | new commits to the `crates.io-index` git repository | minutes |
| RubyGems | `/api/v1/activity/just_updated.json`, polled | minutes |
| NuGet | the v3 catalog, which is an append-only page chain | minutes |
| GitHub | release webhooks for watched repositories, `/releases` polling otherwise | seconds to minutes |

The ingester turns a feed entry into a target, applies the selection policy
([`02-domain-model.md`](02-domain-model.md) §8.1), and enqueues at the `bulk` tier with a per-package
prevalence score. Three properties make it cheap:

- **The strategy cache is already warm** for a package whose earlier versions we verified, so a new
  version skips inference and goes straight to a build.
- **A gap in the feed is recoverable.** Every ingester records a cursor, and every ecosystem exposes
  a way to replay from one. A missed hour costs a catch-up, not a re-sweep.
- **Regression detection falls out of it.** A package that reproduced at `Normalized` for forty
  versions and diverges at the forty-first is the alarm the target view was built for
  ([`11-interfaces.md`](11-interfaces.md) §4), and it only fires if we look at the forty-first
  version on the day it lands.

Ingestion carries its own budget, separate from any sweep, so a burst of npm publishes cannot consume
a sweep's allocation. Feeds are attacker-influenceable in the sense that anyone can publish a package
and spend our compute, which is what the prevalence threshold and the per-publisher rate limit are
for.

## 6. Scheduling

**Prevalence order.** Cold sweeps run in descending order of normalized dependency-graph
prevalence per ecosystem. At 100k targets that decides whether the money goes to packages people
import. We compute the scores offline and join them at enqueue time.

**Priority tiers**, with strict ordering and fair-share within a tier:

| Tier | Source | Behaviour |
|---|---|---|
| `interactive` | `trigon verify`, a UI request | Preempts, small budget, low latency |
| `regression` | Nightly benchmark runs | A fixed daily slot |
| `bulk` | Sweeps | Fills remaining capacity |

**Fair-share across ecosystems** within a tier, so one slow ecosystem cannot starve the others.

**Size-class queues.** Predicted duration routes a target to the small or large queue, using
previous runs of the same package, repository size, and ecosystem. That addresses failure mode 3 in
§2, and it costs far less than provisioning for the tail.

**Cost-aware admission control.** A sweep declares a budget and the scheduler enforces it. A sweep
about to exceed its budget stops enqueuing rather than overspending without saying so. Spend shows up per
sweep, per ecosystem, and per role in the cost view ([`11-interfaces.md`](11-interfaces.md) §4).

## 7. Caching is the scale strategy

| Cache | Key | Effect |
|---|---|---|
| **Run key** | The full idempotency hash | Re-sweeps cost close to nothing |
| **Strategy** | (ecosystem, package) and strategy family | siblings reuse; see [`07-ai.md`](07-ai.md) §4.1 |
| **AI** | role-specific generalizing keys | the difference between a $4k and a $168k cold sweep |
| **Source** | repo URI + commit | 5–20× reduction with narrow fetch |
| **Image** | digest | node-local, kept warm |
| **Dependency mirror** | per ecosystem | 10× reduction in registry traffic; also politeness |
| **Failure signature** | normalized signature | repairs reused without a model call |

One caching rule matters for multi-tenancy ([`12-security.md`](12-security.md) §7): **cache
immutable, hash-addressed content, and never state.** A shared mutable cache across a trust boundary
is a poisoning vector.

## 8. Workers and autoscaling

Three classes ([`08-execution.md`](08-execution.md) §8): `infer` (cheap, network- and model-heavy,
high concurrency), `build` (expensive, isolated, egress-restricted, low concurrency), `judge` (cheap,
fetches the upstream artifact, no container execution).

Separating them keeps cost sane. Inference caches and shares, builds carry the real spend, and
judging needs a network capability the build worker has to lack.

- **Leases with heartbeats.** A crashed worker's lease expires and the job is redelivered.
- **Poison jobs** go to a dead-letter queue after N attempts, with the failure classified, so an
  infra fault stops looking like an unreproducible package.
- **Graceful drain** on shutdown: finish or checkpoint the current run, do not lease more.
- **KEDA on queue depth per tier and size class** in Kubernetes; the same signal drives
  `trigon serve --workers N` locally.
- **Backpressure from upstream rate limits reaches the scheduler**, beyond the worker that hit it.
  One worker discovering a rate limit slows the fleet.

## 9. Observability of the system itself

`tracing` with OpenTelemetry export; Prometheus metrics.

Metrics that matter to an operator, distinct from the product metrics in
[`07-ai.md`](07-ai.md) §6.3:

```
trigon_queue_depth{tier,size_class}
trigon_run_duration_seconds{phase,ecosystem}          # histogram
trigon_verdict_total{outcome,ecosystem}
trigon_upstream_backoff_seconds{host}                 # the early-warning signal for §2 failure 1
trigon_mirror_hit_ratio{ecosystem}
trigon_ai_cache_hit_ratio{role}                       # SLO: > 0.7
trigon_spend_usd{sweep,role}
trigon_worker_saturation{class}
trigon_lease_expiry_total{class}                      # crashes hiding as slowness
```

Every run carries a trace id that appears in the UI, the logs, and the run manifest, so an operator
moving between them never correlates by timestamp.
