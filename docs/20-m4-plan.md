# 20. Planning M4

[`13-roadmap.md`](13-roadmap.md) states M4 as six exit criteria and four weeks.
[`10-scale.md`](10-scale.md) already carries the design — the queue, the metadata schema, continuous
ingestion, scheduling, caching, worker classes. Neither says what is built, what order to build the
rest in, or what the headline sweep actually costs. This is that.

## 1. What exists, criterion by criterion

Verified against the code rather than against the roadmap.

| Exit criterion | State | What is actually there |
|---|---|---|
| A 5,000-target sweep within budget | **partial** | `trigon sweep` runs a corpus at N lanes and has run 197 npm + 200 PyPI. It loses targets to [`B6`][b6] at concurrency 3, and §2 shows the request volume is mis-sized. |
| Three worker classes enforced | **none** | No queue, no worker split. `trigon-engine` appears in [`01-architecture.md`](01-architecture.md)'s crate table and **is not a crate**. The write-only blob credential that makes the build/judge split real is specified and implemented nowhere. |
| Per-host rate limiting, backoff, `User-Agent` | **built, minus the fleet half** | Was on the wrong client entirely: see §3. Now `trigon-politeness`, one process-wide limiter and one counter table behind every route, with the contact-URL `User-Agent` enforced by `xtask policy`. Backoff across *workers* needs the queue, which is Stage B. |
| UI: lockfile, clusters, run, diff, cost, fleet health | **partial** | `watch.rs` serves board, cluster, run, network, compare, `/api/state`. No lockfile, cost or fleet-health view. Overlaps the watch redesign — see §5. |
| `trigon check --format sarif` | **none** | No `check` subcommand and no `sarif` anywhere in the tree. |
| Continuous ingestion with a per-feed cursor | **none** | No `ingest`, no cursor. |

Two of six are untouched, three are part-built, and the two that look closest — the sweep and the
rate limiting — are the two §2 and §3 show are not what they appear.

## 2. The headline criterion, measured

Projected from the 186-run npm sweep measured in [`B25`][b25] — mean 56.2 s per target, 39.23 GB
of egress, 143,362 fetches — scaled to 5,000 targets:

| | Projected |
|---|---:|
| Egress | **1.05 TB** |
| Requests | **3,853,817** |
| of those, to `registry.npmjs.org` | **3,848,952** |
| CPU time | 78 hours serial |
| Wall clock at 16 lanes | 4.9 hours |

The wall clock is comfortable and **it is not the constraint**. Nearly every one of those requests
goes to a single host. Divided by the wall clock, that is **219 requests per second sustained
against `registry.npmjs.org` for five hours** — from one User-Agent, with nothing in the path that
would slow down if they asked (§3). That is the shape of traffic a registry blocks, and unblocking
is a human process measured in days.

Only 19,130 of the 143,362 fetches are distinct: **86.7% are repeats**, and one document —
`registry.npmjs.org/npm`, 22.3 MB, fetched 309 times — is 18% of the sweep's bytes by itself.
Serving the repeats from a cache puts the same sweep at **~514,000 requests and ~29 req/s**. That
figure is an upper bound: it scales distinct URLs linearly with targets, and overlap between targets
only grows as the corpus does.

So:

> **[`B25`][b25] is a precondition of M4's headline criterion, not an optimisation of it.**

It is also what makes criterion 3 answerable. The number to put in the mail to npm and PyPI is
~514k requests at ~29/s, not 3.9M at 219/s — the first is a description of a research tool and the
second is a description of an incident.

Two caveats on the projection. It is npm-shaped: PyPI's index pages are far smaller, so the egress
figure is an over-estimate and the request count is not. And it assumes today's per-target cost,
where the repair loop and the confirmation policy both multiply builds
([`10-scale.md`](10-scale.md) §1) and neither was exercised by the measured sweep.

## 3. The rate limiting is on the client that does not carry the traffic

This is the finding that most changes the plan, and it is the project's own recurring defect class:
a control that is real, is tested, and is not in the path.

`trigon-registry::Client` is careful. It sets a `User-Agent` naming the tool with a contact URL, it
spaces requests to the same host by `min_interval` (100 ms), it retries only transient statuses, and
it honours `Retry-After` (`crates/trigon-registry/src/client.rs:36-48`, `:244`). Its module doc
opens by saying upstream reputation is what breaks first at scale. All true.

The mirror is not that client. `trigon-mirror` builds two bare `reqwest::Client`s
(`crates/trigon-mirror/src/server.rs:429-449`) with:

- a `User-Agent` of `trigon-mirror/<version>` — **no contact URL**, so the traffic that matters is
  the traffic nobody can trace back to a person;
- **no request spacing** of any kind;
- **no `Retry-After` handling** and no 429 path.

And the mirror is where the volume is. Every one of a build's fetches at `mirror-only` goes through
it, and `network_exchanges` in a run record is the length of the mirror transcript
(`crates/trigon/src/main.rs:3282`) — so the 143,362 figure in §2 *is* the unpaced traffic, measured,
and the careful client's inference-time traffic is not in it at all.

**And the paced route is not paced across a sweep.** `Client`'s per-host spacing lives in a field
on the `Client`, and a sweep constructs a fresh one per target — the type's own doc comment says
so, about the traffic counter it had to make a process-global `static` for exactly this reason. So
even on the route that is paced, the floor resets at every target and the pacing is per-lane, not
per-process. N lanes means N times the declared rate, and a rate limit that multiplies by
concurrency is not a rate limit.

**The traffic that is counted is the traffic that is not paced, and the traffic that is paced is
not counted.** `HostTraffic` is printed to the sweep's stdout (`main.rs:5312`) and reaches no run
record and no report; `network_exchanges` is persisted per run and covers only the mirror. Nothing
joins them, so no artefact this system produces states what it asked of any host. Criterion 3's
"registries have been contacted" needs a number we do not currently keep.

**Items 1 to 3 are done** — `trigon-politeness`, and the per-host table in `run.json`. What is
below is how it was stated before the work; item 4 is still to do and item 2's fleet half waits on
the queue.

Four things, in this order:

1. ~~**Move the politeness to where the bytes are.**~~ **Done.** The mirror's outbound fetch is the one place all
   egress converges; it is the natural home for spacing, `Retry-After`, and the contact-URL
   `User-Agent`. A test should assert the mirror's UA contains the contact URL, the same way the
   egress tests assert the guard runs before the fetch.
2. **Make the limiter process-global, then fleet-global.** Process-global is a `static` and closes
   the per-lane multiplication today. Fleet-global is the criterion's "global backoff propagation"
   and belongs with the queue in Stage B: one worker seeing a 429 has learned something every other
   worker needs, and the queue is the only thing that can tell them.
3. **Record what was asked of each host in the run record**, beside `network_exchanges`. One number
   per host per run, summable across a sweep. Without it the first criterion's "declared budget"
   has nothing to check itself against.
4. **Then write to the registries**, with the cached numbers from §2 and a `User-Agent` that
   resolves to a page describing the project.

Doing (4) before (1) to (3) would mean describing traffic we cannot produce and cannot show.

## 4. Sequencing

**Stage A — preconditions. Not M4 work; M4 cannot be honest without them.**

1. ~~**[`B6`][b6], the container-store race.**~~ **Closed**, and it was closed before this plan was
   written — the backlog heading said otherwise and the body did not. A `flock` on a per-uid file
   covers lanes and separate processes alike, and `prune_orphans` no longer force-removes a
   container whose owner is alive. Re-verified at four lanes on four npm targets: four of four
   reproduced, no race in any log. The rule naming it stays, because a control whose near-misses
   are invisible cannot be told from one that never fires.
2. ~~**[`B25`][b25], the fetch cache.**~~ **Built**, as two tiers: bytes (permanent, digest-checked
   on every read) and index (scoped to one invocation, with the snapshot instant in the run
   record). The live-comparison control the ADR asks for is not, and is the one thing left.
   Originally stated as: §2. [`B24`][b24] is its toolchain tier and lands first; the
   artifact tier is digest-verified and safe; the index tier is the one carrying a correctness
   question, and [`ADR-0013`](adr/0013-a-cache-supplies-bytes-never-decisions.md) has the rule.
3. **§3 items 1 to 3**: the limiter on the mirror, the limiter made process-global, and the count
   in the run record. All small, and the sweep in criterion 1 should not be running at 219 req/s
   while we wait for the queue to be able to carry the fourth.
4. ~~**Classification honesty.**~~ **Done, against better evidence than the item asked for.** The
   fourteen `unknown`s it referred to were from a work directory that no longer exists, so instead:
   125 targets drawn uniformly at random from npm, PyPI and NuGet. Five `unknown`s, two causes,
   three new rules — `src/refused-url`, `src/fetch-failed`, `env/no-ssh-client` — and one fix to
   the evidence itself, because npm's four-line trailer was being recorded as the whole account of
   a failure. Re-classified from the logs on disk the sweep has **no unknowns** and nothing in
   `Fault::Build`. See [`16`](16-findings.md) §3.30, which also has the rates.

**Stage B — the queue and the worker classes.** The largest single piece, and the one with a written
design already ([`10-scale.md`](10-scale.md) §3, §8;
[`ADR-0005`](adr/0005-own-the-queue.md)). Build the state machine as `trigon-engine`, the crate the
architecture already names. Write the enforcement test the criterion asks for — *the build worker
cannot fetch the upstream artifact* — **first**: it is the one control that separates a verdict from
a tautology, and of the two rules specified for it the guard manifest carrying digests is built and
the write-only blob credential is not. Fleet-global backoff — the criterion's word is
"propagation", and the queue is the only thing that can carry it — rides along here.

**Stage C — continuous ingestion.** [`10-scale.md`](10-scale.md) §5. After M4 the steady state is
ingestion, and a sweep becomes what runs when the selection policy or the stabilizer set changes.
This is what makes M4 an operating mode rather than an event. Needs the cursor and the catch-up
path; nothing else in M4 blocks it.

**Stage D — the interfaces.** `trigon check --format sarif` is small, self-contained, and the only
criterion a user outside this project touches directly. The UI views are §5.

Stage A is days. Stage B dominates the four weeks. C and D parallelise against B.

## 5. What the criteria should say instead

Three of the six are worth restating before anything is built against them.

**"Within its declared budget" needs a declared budget.** §2 supplies one: ≤1.1 TB egress, ≤600k
registry requests, ≤40 req/s to any single host, ≤8 h wall clock at 16 lanes, and a model-invocation
rate that trends down. A criterion with no number cannot be failed.

**"Per-host rate limiting" should say which host and which client.** As written it is satisfied by
the code that exists, on the route that does not matter. It should read: *every outbound request,
including the mirror's, is paced and backs off; the process asserts it in a test; the declared
`User-Agent` carries a contact URL on every route; and the run record states what was asked of each
host, so the budget in the first criterion can be checked against something other than a console
line that scrolled past.*

**"The UI ships six views" predates the watch redesign.** That redesign's grounding found the sweep
board, the cluster page and the liveness apparatus are dead code against the data this repo produces
today — every work directory on this machine holds a single run. M4 is what finally produces
sweep-shaped data, so the board becomes real exactly when M4 lands. Fleet health and cost belong
here; run, diff and cluster belong to the redesign and should not be built twice.

## 6. Risks

**The rate limit is the whole design.** If the cache misses more than measured — a cold corpus, a
selection policy with a longer tail — the sweep quietly returns to hundreds of requests per second
against one registry. The budget should be enforced by the scheduler, which stops the sweep when it
is exceeded, rather than checked afterwards in a report nobody reads until the block arrives.

**Five thousand targets multiplies every classifier gap.** Fourteen unknowns in 197 is a number a
person can read in an afternoon; the same rate over 5,000 is 350, and nobody reads those. The
`unknown` rate decides whether the published number means anything, and it should be an exit
criterion in its own right.

**A fleet number will be quoted.** Every number this project has measured has moved once someone
looked closely — the npm rate, the coverage figure, the non-compared split, and the rate limiting in
§3. A 5,000-target rate will be repeated far more widely than it is re-derived, so the sweep that
produces it should write its inputs into the repository as a fixture rather than leave them in a
temporary directory.

[b6]: 17-backlog.md#b6-two-trigon-runs-on-one-machine-can-disturb-each-others-container-store--open-and-its-title-said-otherwise
[b25]: 17-backlog.md#b25-the-fetch-cache-behind-the-mirror-in-three-tiers
[b24]: 17-backlog.md#b24-a-content-addressed-toolchain-store-mounted-rather-than-layered
