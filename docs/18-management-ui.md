# A management UI

> "So we can monitor what's going on."

That is the brief, and it is narrower than the twelve views [`11`](11-interfaces.md) §4 specifies.
Those are mostly about publishing results to people who do not run this; this is about a person
watching a sweep they started, from another terminal, while it is still running. Eight of the twelve
also have no data source in the code today.

---

## 1. The finding that decides the architecture

**The store is structurally blind to every run this UI is about.**

`record_run` has one call site, and it sits past the early return that unwraps the comparison. Every
`Void`, every build failure, every `no-strategy`, every infrastructure error returns before it. That
is deliberate and right for an attestor — [`09`](09-attestations.md) §4's property is that no
statement can be written about a run that is evidence of nothing, and it is a property of the
control flow rather than a check somebody remembered.

It is fatal for a monitor. A page rooted in `runs/` reports a 100% reproduction rate on a sweep where
nothing built.

So the root is **the sweep's work directory**, and the store is an optional detail pane hanging off
a row. Writing a `RunRecord` for every terminal outcome is the right long-term fix and is listed
under instrumentation — but it is a change to what the attestor sees, and it should not be made in a
hurry to get a web page.

## 2. The shape

```
   trigon sweep ──writes──▶  <work>/results.tsv         trigon watch <work>
                             <work>/status.json    ◀──reads──   (a second process,
                             <work>/NNN/…                        on this machine or not)
```

**The monitor never talks to the sweep.** It reads the files the sweep already writes in order to
survive its own death. That inversion is the whole design, and the test of it is the moment the
sweep crashes: every completed result stays on screen, the silence is labelled with its exact age,
and the target that was in flight is reported as unknown rather than converted into a failure.

An HTTP server inside `trigon sweep` fails that test — the socket closes exactly when the operator
most needs to know what happened — and puts a listening socket and a second async runtime inside a
process running untrusted builds.

**Named `watch`, not `serve`.** [`11`](11-interfaces.md) §2 reserves `serve` for API plus UI plus
workers. A read-only viewer taking that name promises three things it does not do.

**Server-rendered HTML from the existing binary.** A `watch` module behind the existing `build`
feature; `axum` is already a workspace dependency and already compiled for the mirror. Rust string
templates, one inline `<style>`, no bundler and no node toolchain for eight tables where nothing is
interactive. It must stay behind `build`: `--no-default-features` produces the verifier, whose claim
is that it links no async runtime and no network client.

Loopback by default, the bound address printed on every page, an explicit `--bind` to leave it. A
sweep work directory holds artifacts fetched from registries and build logs that may carry
credentials. The only path parameter anywhere is the three-digit target index, parsed as an integer
and re-formatted before it touches the filesystem.

## 3. The views

| # | View | The question it answers |
|---|---|---|
| 1 | **Sweep state** — a strip on every page | Is this live, finished, or from a process that died — and how many targets were never attempted? |
| 2 | **The board** | What is it doing now, and what has it found? |
| 3 | **Two rates, denominators printed** | Did the packages reproduce, and — separately — did our infrastructure work? |
| 4 | **Failure clusters** | These forty red rows are how many actual problems, and which do I fix first? |
| 5 | **A cluster** | Is this one thing or three wearing one name, and which run do I open? |
| 6 | **A run** | What happened to this target, and is the evidence still on disk? |
| 7 | **Pin evidence** (store only) | Did the time-filtered index bind, or did this quietly resolve against today's registry? |
| 8 | **Upstream pressure** | Are we being throttled — is it slow because of us or because of them? |

Views 1–6 read `results.tsv` and `<work>/NNN/`. View 7 needs `--store`. View 8 needs counters that do
not exist yet, and appears on the page before they do, saying so.

**Three rules hold on every view**, and each is a bug this project has already shipped:

- **Nothing absent is ever rendered as a zero.** "No results yet — 0 of 212 attempted", never "0%
  reproduced". A sweep with no comparison prints `summarize`'s own sentence and no percentage.
- **The two denominators never merge.** A package that did not reproduce and a build our own
  infrastructure could not run are different findings; one bucket holding both is a number about our
  reliability wearing a reproduction rate's costume. There is no single "failed" count anywhere on
  the page, at any size.
- **Every panel states what it shows when empty, when stale, and when the producer has died.** The
  header carries `results.tsv`'s mtime and its age; an unparseable `status.json` keeps showing the
  previous state with its age rather than going blank.

## 4. What the engine must start writing

Each of these is small, and each is named with the view that is impossible without it.

| Write | Without it |
|---|---|
| ~~`<work>/sweep.json`~~ **done** — the targets file and the sha256 of its bytes, image, egress, timewarp, model, version, pid, and the per-target timeout | View 1 has no denominator, and two sweeps cannot be told to be of the same corpus |
| ~~`<work>/status.json`~~ **done** — atomic, a 10-second heartbeat, and an immediate write when a target starts | View 1 is impossible; liveness falls back to inferring from file appearance, which already misreads a repair loop as going backwards |
| A phase signal into `status.json` — `BuildEvent::PhaseStart/PhaseEnd` are already emitted and thrown away | No `stuck` state, which is the one that pages a human |
| ~~`<work>/NNN/run.json` on **every** terminal outcome~~ **done** — carrying the failure signature as classified at the time, so it cannot drift from a moved rule table | View 6 was four "not measured" lines |
| Throttle counters in `trigon-registry` | View 8 — and [`11`](11-interfaces.md) §4 says backoff state ships before the first real sweep, because upstream reputation breaks first |
| Three trailing columns on `results.tsv` for tokens | Model spend is invisible; written as empty strings where no model ran, so "no model" never renders as zero |

Deferred, and the highest-value one once there is a fleet: **a `RunRecord` on every terminal
outcome.** The fields already exist. Nothing moves from one work directory to a corpus over time
until that is true.

## 5. Build order

Each step is independently useful and none pays off only if the next three land.

1. **One day, no engine change.** `trigon watch <work-dir>` serving the board, the two rates and the
   ranked clusters off `results.tsv` and the build logs. This is `summarize` made readable from
   another terminal, on another machine, while the sweep is still running, by somebody who is not
   the person who launched it. It works against sweeps already on disk.
2. **Still no engine change.** The triage loop: cluster → deduplicated evidence lines with counts →
   member table → run page with prev/next and "7 of 41". The only path from 500 red rows to 12
   tickets *and back*.
3. ~~`sweep.json` and `status.json`, and a `GET /api/state`.~~ **Done.** The strip says running /
   finished / stopped / unresponsive / stuck, and `stuck` is measured against the per-target timeout
   the sweep itself declared rather than a threshold the page invented. Driven by killing a sweep
   mid-target: the page says `stopped`, keeps every completed result, reports the in-flight target
   as having no outcome — *which is not the same as failing* — and stops refreshing itself.
4. ~~The phase signal, and with it the `stuck` state.~~ **Done.** `BuildEvent::PhaseStart` already
   existed and was thrown away — `events()` returns a snapshot, which is the whole history once the
   build is over and nothing at all while it is the thing you want to watch. `RunOpts` gained a
   sink, and `run_one` marks the phases the sandbox cannot see: resolve, fetch, strategy, judge. The
   phase carries its own clock, because a target twenty minutes in is healthy if nineteen of them
   were `deps`.
5. ~~`failure.json` and `run.json` on every outcome.~~ **Done**, as *one* file: two of them invites
   the question of which is authoritative when they disagree, and they would — the signature is
   classified where the log is in hand and everything else is known at the end. `run_one` became a
   thin wrapper so "on every terminal outcome" is a property of the control flow rather than a line
   to remember at each of eight returns. Timings come back through the event sink that step 4 added,
   `None` still meaning no data.
6. ~~Store-backed panes, gated on `--store`.~~ **Done.** The digest chain, the environment, the
   guard trips and whether the pin bound — and a missing record says *why* (the store keeps only
   runs that reached a comparison) rather than rendering an empty pane. The join is O(runs) and the
   page prints what it cost, so the moment it stops being fine is visible rather than felt.
7. ~~Cross-sweep: the impact preview.~~ **Done.** `trigon watch --baseline <other work dir>` names
   the flips in both directions, keeps "stopped producing evidence" separate from "regressed"
   because an infrastructure fault is ours, and refuses when the two targets-file digests differ —
   a comparison across different lists is a number about the lists.

## 6. What this is not, and the one risk that matters

Not the lockfile check, the version ladder, the provenance-contradiction feed, or Ask — all
consumer-facing, all without a data source. Not fleet health: six panels and no queue, no worker, no
lease, no ingester; `RunState::Queued` is an enum variant with no producer. Not a cost view in
dollars: `Budget` is iterations, tokens and wall seconds, there is no price table, and multiplying
by a rate we typed in would put an invented number on the one view whose purpose is that you do not
discover the cost on an invoice. Not Postgres — a schema built before there is a fleet is a schema
whose shape is a guess. **No write path at all**: a cluster hands you the `trigon rebuild` line to
paste.

> [`11`](11-interfaces.md) §1: *"a web UI built for yourself will lose to a TUI every time."*

That warning is about this page. The honest answer is to make it falsifiable rather than argue with
it: steps 1 and 2 are a few hundred lines of string templates with no new dependency. **If, during
the next full sweep, the board is only ever opened by the person who started that sweep, delete
it** — and build the TUI over the same reader, which will already exist.
