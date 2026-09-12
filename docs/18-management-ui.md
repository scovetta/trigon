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
| `<work>/sweep.json` once at start — targets file and the sha256 of its bytes, image digest, egress, timewarp, model, version, pid | View 1 has no denominator, and two sweeps cannot be told to be of the same corpus |
| `<work>/status.json`, atomically, on every phase transition and a 10-second heartbeat | View 1 is impossible; liveness falls back to inferring from file appearance, which already misreads a repair loop as going backwards |
| A phase signal into `status.json` — `BuildEvent::PhaseStart/PhaseEnd` are already emitted and thrown away | No `stuck` state, which is the one that pages a human |
| `<work>/NNN/failure.json` — the `FailureSignature` at classification time | Clusters are re-derived under whatever the rule table says today rather than what it said then |
| `<work>/NNN/run.json` on **every** terminal outcome, not only past a comparison | View 6 is four "not measured" lines; the void table cannot split by reason |
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
3. `sweep.json` and `status.json`, and a `GET /api/state` returning the view model as one object.
4. The phase signal, and with it the `stuck` state.
5. `failure.json` and `run.json` on every outcome — also the files you attach to a bug report.
6. Store-backed panes, gated on `--store`: the digest chain, every applied stabilizer with its risk
   and provenance, the cap, the diff codes — and pin evidence, which [`16`](16-findings.md) §1 calls
   the most valuable unbuilt thing on the list.
7. Cross-sweep: the impact preview over `trigon_ai::flips` and `score`, which needs no
   instrumentation at all. Refuses to compare two sweeps whose targets-file digests differ.

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
