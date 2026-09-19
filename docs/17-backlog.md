# Backlog

Work that is agreed and not yet done. Each entry says what "done" means, because a backlog whose
items cannot be finished is a list of anxieties.

Ordered by when it was raised, not by priority; the roadmap in [`13`](13-roadmap.md) says what the
current milestone is.

---

## B1. Security sweep over the whole codebase

Not the design's threat model — the *code*. Every place we run a subprocess, parse
attacker-controlled bytes, join a path, or hand a string to a shell, read with an attacker in mind.

The system executes untrusted code by design, so the interesting findings are the ones where
untrusted input reaches something that was written as though it were ours: a package's repository
URL on a `git` command line, a build log in a prompt, an archive member path joined to an output
directory, a strategy's template rendering into a shell script.

**Done when:** every finding is either fixed or written down with a reason it is acceptable, and
each one has a test that would catch the regression.

**First pass done.** Seventeen reviewers over every crate and the front end, each finding re-read by
a second agent told to refute it. The ones that were reproduced are fixed, with tests, in
[`16-findings.md`](16-findings.md) §3.48–§3.56; the rest are listed in
[B29](#b29-what-the-whole-tree-review-found-and-did-not-fix) and are leads rather than facts. This
entry stays open: a sweep is not done when a list exists, it is done when the list is empty.

## B2. ~~A threat model for Trigon~~ — closed, as an unratified draft

[`threat-model.md`](threat-model.md) and its generated companion
[`threat-model.yaml`](threat-model.yaml). 192 documented claims, 3 assumptions and 5 inferences, each
of the last eight resolving to a question in §1.18. A 38-item corpus — 13 real findings from the
adversarial sweep and the git history, 25 built to reach families and contract dimensions history
does not — routed blind to exactly one disposition each.

**What the backtest was actually for.** Not to confirm the model: to break it. It found four defects
and each produced a revision — a zip-slip report that nothing in the model answered (now P22, after
verifying no judgement-half crate writes a file at all); a store-path report whose safety turned out
to be **borrowed from `object_store`**, which percent-encodes `..`, and is now named as borrowed
rather than claimed; a `flate2` report whose close was *illegal* because §1.9 carried no provenance
tags; and fourteen ambiguous routings that produced the `ESCALATE: unratified-claim` outcome for the
case the disposition set had no word for — a rule matches, but the claim licensing it is unratified.

**What remains, and it is the point of leaving it open:** it is a *draft*. Only a maintainer can
promote an assumption to a decision, and until §1.18 is answered the model can escalate a report and
must not close one on those eight claims. Q17 is the sharpest: there is no `SECURITY.md`, no
disclosure address and no supported-versions statement, so a document that says "report this
privately" currently names no channel.

## B3. Documentation that is accurate and reads for a user

Two separate problems. **Accurate:** the docs were written before the code and the code has since
corrected them — [`16`](16-findings.md) records the corrections, but the original chapters still
say the original thing in places. A reader who starts at `04` and believes it is misled.

**User-friendly:** the `README` is the only document written for somebody who wants to *use* this,
and the seventeen design chapters are written for somebody building it. At minimum a user needs:
install, verify one package, read the verdict, understand what the verdict does not say.

**Done when:** every claim in `00`–`15` is either true of the code or marked as a design intent not
yet built, and a person who has never seen this repository can verify a package from the README
alone.

**One pass done, and what it found is the argument for the rest.** An audit of the claims that today's
changes touched turned up three corrections, and the worst was not a stale detail:

- **[`12`](12-security.md) §10 listed twelve invariants and the tests that enforce them, and five of
  those tests did not exist.** Not "were weaker than described" — did not exist. No flake test, no
  known-good corpus replay against the guard, no confirmation policy, no attestor deployment test.
  The table now carries a status column and says plainly that verdicts are not checked for stability
  across identical runs, the guard's false-positive rate is unmeasured, and every attestation is
  signed off a single run. A table of controls that names imaginary enforcement is the same defect
  as a control that fails open and reports success.
- **[`16`](16-findings.md) documented a state that had been reverted**, describing the mirror as
  serving tarballs unfiltered and calling that free — which was version one of the E400 fix, undone
  the same session as a security regression.
- **Three chapters described the provenance cap as "a runtime check, a unit test, and a proptest"**;
  there is no runtime check, `proptest` is not a dependency of that crate, and the real enforcement
  is an exhaustive enumeration, which is stronger. The wording undersold it and misdescribed it at
  the same time.

The pattern is that **the dangerous staleness is in the claims about controls**, not in the
architecture prose. A reader who believes `04` is misled about a design; a reader who believes `12`
§10 is misled about what is checked.

## B4. ~~Test coverage worth the name~~ — measured, with two findings

Measured, per crate, with the judgement half at a stated bar and the deliberate gaps named. Written
up in [`16`](16-findings.md) §3.19.

```
cargo llvm-cov --workspace --no-fail-fast --summary-only \
  --ignore-filename-regex '(/tests?/|/xtask/)'
```

The leading `/` matters: `'tests?/'` without it silently excludes all of `trigon-attest`, because
`attest/` contains `test/`.

Measured twice, because the gap between them is the honest measure of "needs the network" versus
"untested" — add `TRIGON_LIVE=1` for the second.

| | offline | live |
|---|---|---|
| **Judgement half** — `core`, `archive`, `stabilize`, `compare`, `attest` | **88.4%** | **88.4%** |
| `trigon-mirror` | 77.7% | 86.3% |
| Workspace | 69.0% | 71.4% |

The judgement half moving by **0.0%** is the result worth keeping: the half that decides a verdict is
covered entirely by tests that open no socket, which is the architecture's central claim measured
rather than asserted.

Measuring it found two things that were not about coverage: the regex above, and that
`trigon-stabilize-wasm`'s parity test — a milestone criterion — had never run in this workspace and
reported `ok. 0 passed` while not running. It passes. CI now builds the wasm target and asserts the
two tests actually ran.

**What is left, and it is the harder half:** coverage says which lines ran, not whether the corpora
still exercise what they claim to. That is a different measurement and it belongs with
[`15`](15-corpora.md) §2.

## B9. Talk to Copilot through its SDK rather than its CLI

We spawn `copilot -p … --output-format json` and parse the JSONL. That works and is verified against
the real CLI, and it has a real cost I understated when I chose it: **the event shape is not an API.**
`assistant.message`, and especially
`session.usage_checkpoint.promptCacheBreakState[0].models[<model>].prompt_tokens`, are internals
that can move without notice, and when they do this provider returns an empty answer or zero tokens
rather than an error.

The reason I gave — the crate needs Rust 1.94 against our 1.85 — is weaker than I made it sound.
`rust-version` is per package, the dependency would be optional, and the verifier
(`--no-default-features`) does not link `trigon-ai` at all, so the claim that matters keeps its
floor. `default-features = false` also drops the embedded CLI binary, which was the other objection.

The reason that is real: **the control that makes this provider safe is that the model never sees a
tool**, and the SDK does not expose the flag that does it. `SessionConfig::with_tools` registers
*local* tools and the docs say the CLI may still advertise its own; `deny_all_permissions` denies
requests, which is a weaker posture — and in `-p` mode the CLI was measured running `bash` without
raising a permission request at all.

What changes the answer: `ClientOptions` has `prefix_args` and `extra_args`, so
`--available-tools=<inert>` can be passed through the SDK. That gets the typed protocol *and* the
filter, which is the combination worth having.

**Done when:** the provider uses the SDK behind an optional `copilot` feature, the tool filter is
passed through and **proved** by the existing live test — the one that asks it to run a shell command
and requires `NOTOOLS` back — and the MSRV bump is confined to that feature.

## B5. A bug sweep

**The parser half is closed.** The two defects §3.12 recorded — an unchecked `u64` add and an
inflate bounded by declared rather than produced size — were fixed in `bound what an archive can
expand to, and stop an offset wrapping`, with three tests. §3.12 went on saying they were open for a
day afterwards, and `docs/threat-model.md` inherited the stale claim as a security-critical
disclaimer; both are corrected, and the lesson is written up in §3.12.

What remains is the sweep itself. Not a review of the last change: a sweep of the whole thing,
looking for the classes this project keeps producing — configuration that looks applied and is not,
an error that reads as the package's fault when it is ours, a silent zero where there is no data, a
cache key that is not a function of everything it depends on, **and a document that describes a
defect it no longer has**.

**Done when:** every confirmed bug is fixed or filed with a failing test, and the sweep's negative
result is recorded so the next one starts from here rather than from nothing.

## B6. ~~Two Trigon runs on one machine can disturb each other's container store~~ — closed, and its title has now been wrong in both directions

Found by an intermittent sandbox test that passed in isolation. Podman's local image store is
machine-global, and this system reaches into it in two places: `Leftovers::drop` removes a run's own
image when it finishes, and `prune_stale_leftovers` removes what dead runs left behind. A concurrent
build reuses those images' layers as its build cache, so removing one fails the other with
`getting top layer info: layer not known` — reported as our sandbox being broken rather than as one
run deleting another's cache.

Narrowed, not closed: the stale sweep now runs once per process, only on images idle for ten
minutes whose process is gone, and neither path passes `--force`, so podman declines while anything
still depends on an image. What remains is the cross-process window — one Trigon cannot see
another's builds — which matters for a sweep run beside an interactive rebuild, and will matter more
with fleet concurrency.

The tests no longer race because they serialize on a lock; that is not a fix for the product.

**Now measured, and it is not only cross-process.** `trigon sweep --concurrency 3` over the
seventeen-target PyPI corpus lost two targets inside a *single* process: one to
`checking if cached image exists from a previous build: getting top layer info: layer not known`,
which is the error above verbatim, and one to `reading the mirror's log: no container with name or
ID found`. The argument that said intra-process lanes were safe — distinct run ids give distinct
image tags, so no lane removes another's top layer — is wrong, and one run of the corpus said so.

**And a third instance, in the npm corpus.** `send@1.2.1` failed with that same
`getting top layer info: layer not known`, and classified as `unknown` — so it was counted against
the package. That makes three measured occurrences across two ecosystems, which is what moved this
item's heading back to open: the body has said "narrowed, not closed" since the second one, while
the heading said closed, and a reader scanning headings would have believed the heading.

Whoever takes this should start by making it *nameable*: an unclassified podman-store error is
indistinguishable from a package that will not build, so it lands in `Fault::Build` and depresses
the reproduction rate by an amount nobody can see. A rule for the two strings above costs minutes
and turns a silent loss into a counted one, ahead of any real fix to the store handling.

That makes this a prerequisite rather than a nice-to-have. Both faults arrive labelled as the
package's failure, and a reproduction rate that contains infrastructure faults is not a rate. The
sweep therefore refuses `--concurrency` above 1 until this closes, with the reason and the measured
cost in the refusal.

**Closed by a lock, and by a sweep that was asking the wrong question.**

`crates/trigon-sandbox/src/store_lock.rs` holds `flock` on a per-uid file: a build takes it
**shared**, every removal takes it **exclusive with `try`**. A removal that cannot have it skips
itself, because a stale image costs disk and a blocked one costs the run, and the sweeps were always
best effort. It is a file lock rather than a process mutex, so it covers two Trigon processes as
well as lanes inside one — the half nothing in-process could reach — and it lives on a descriptor,
so `kill -9` releases it and no stale lock survives. Per-run storage was the alternative and is
worse: it gives up layer sharing and re-pulls a base image per target, which at 400 targets is tens
of gigabytes to avoid a lock.

The second fault was not podman's. `prune_orphans` spared a container only when it was `running`
**and** owned, so a container whose owner was alive and which had not finished starting yet was
force-removed — by a sibling lane in the same process, sharing its pid, moments after it was
created. Ownership is the whole question; a container whose owner is alive is not an orphan whatever
state it is in, and its owner removes it in `destroy`.

**The first version of the lock was a worse bug than the race**, and its own tests found it:
`shared()` blocked, so a removal that hung would have stopped every build on the machine for ever
with no diagnostic. Three test binaries wedged against each other and it read as a hang. It now
waits five seconds and builds anyway — a `podman rmi` finishes in well under a second, so a longer
wait means the holder is stuck rather than busy, and giving up restores the pre-lock behaviour where
waiting restores nothing.

**A skipped removal is deferred, not dropped**, which the first version got wrong. Skipping is
correct — a removal must never block a build — but a sweep holds the lock almost continuously and
`prune_images` runs once per process and only for pids that are gone, so nothing was collected until
the sweep ended: seventeen build images at ~240 MB each after one four-lane run, and 400 targets
would be near a hundred gigabytes. That would have failed the M1 corpus on the machine rather than
in the verdicts. Deferred tags are now remembered and taken whenever the store is next quiet — a
run that does get the lock drains the backlog inline, and a sweep reaps explicitly at the end when
no lane is left holding anything. Measured on a four-target sweep: 3 deferred, 3 reaped, leftover
build images 17 to 2.

That first sentence was false when it was written, and the measurement above did not catch it. The
drain was a call to `reap_deferred` from inside `Leftovers::drop`, which already held the lock —
and `flock` treats two opens in one process as two holders, so the inner `try_exclusive` always
lost and returned. Only the end-of-sweep reap ever ran, which is what "17 to 2" actually measured.
Found by the test audit, not by the test.

**Measured**, the seventeen-target PyPI corpus at `mirror-only`:

| | 1 lane | 4 lanes |
|---|---|---|
| outcome, every target | — | **identical** |
| reproduce | 14 of 16 (88%) | 14 of 16 (88%) |
| wall clock | 711s | **291s** |

2.4× rather than 4×, because per-target time rises 42s to 55s under contention — the lanes compete
for CPU and IO, not for the lock. The comparison is per target and not only in aggregate: two
different sets of failures can sum to the same table.

**Re-verified before M4 stage A moved on.** Four npm targets at `--concurrency 4`, `mirror-only`:
four of four reproduced, 122s wall clock, and not one `env/container-store-race` in any log. The
rule that names the race is still in the table and still `Fault::Infra`, which is where it belongs
whether or not the race fires again — a control whose near-misses are invisible cannot be told from
one that never fires.

The heading said **open** while the body described a lock, an ownership fix, a deferred-removal
backlog and a measured four-lane run. It said **closed** for a while when the body said "narrowed,
not closed". Both times the body was right and a reader scanning headings was not, which is the
only reason this paragraph exists.

## B7. ~~The image build is outside the egress boundary at `mirror-only`~~ — closed

Closed, and recorded in [`16`](16-findings.md) §3.13. The image build takes `--network none` at
every enforced tier, the source arrives as a checkout fetched on the host and copied in, and the
setup phase verifies the base image rather than installing into it. Proven by a probe that printed
`REACHED-SOURCE` before and `blocked-SOURCE` after.

**Its residue, which is a different claim:** the mirror's allowlists bound *which* hosts a build can
reach through it, never *what* those hosts serve. `registry.npmjs.org` will serve any package
anybody published, so an attacker who controls one package can publish a second one holding their
payload and fetch it through the artifact route at any path. The guard is the control for that, not
the tier. That residue is still open.

**The transcript half is done.** Tier 1 records the route, URL, response digest, byte count and how
far the guard got for everything crossing the mirror, and `attestable` is now derived from whether a
complete account exists rather than being the literal `false` it was in two places. See
[`08`](08-execution.md) §7.2 and §7.3.

## B7b. ~~The pin evidence is blank on the tier that needs it most~~ — closed

Closed, and recorded in [`16`](16-findings.md) §3.17. `PinEvidence` is the counter that exposed the
`PIP_TRUSTED_HOST` finding ([`16`](16-findings.md) §1), and it read `null` on every `mirror-only`
run: the counters live on the `Mirror` object, an enforced tier puts that object inside the build's
network island, and the host has no route to it. The one control that says "the pin actually bound
something" was present at `open`, where a build can ignore the mirror entirely, and absent at
`mirror-only`, where it is the claim.

It is derived from the transcript now, which does get out. `versions_withheld` moved onto the index
row itself — it was always a per-response fact — and refusals get their own marker line, because a
refusal serves no body and does not belong in a list whose every other row has a digest. Both of
those had previously been countable only from inside.

**Its residue, which is a different claim:** none of this says the *values* the filter served were
correct, only that it ran and what it removed. And `Seen` retains at most 10,000 rows, so a mirror
serving a very long build reports `truncated > 0` and its rows become a sample — the counters stay
exact, which is why `observed()` still reads them.

## B12. ~~A VCS-versioned project needs its tags~~ — closed

Closed, and recorded in [`16`](16-findings.md) §3.21. `chardet 7.4.3` now reproduces **`exact`** at
`mirror-only` — identical raw digests, thirty-five of thirty-five members identical — where it had
been `divergent` with every `dist-info` member named `chardet-0.1.dev1+g8f404a5a9`.

`hatch-vcs`, `setuptools-scm` and every sibling take the package version from `git describe`, and
the host checkout was `git fetch --depth 1 origin <commit>`, which carries no tags. The fix asks the
remote which tags name the commit — `ls-remote` is one round trip that transfers no objects — and
fetches only those: chardet has seventy-three tags and one of them is the answer.

**Its residue, which is the honest part:** a commit that no tag names still builds as a development
version, because that is what the build system computes and we cannot tell a genuinely untagged
commit from a release whose tag we failed to fetch. `Checkout::tags` carries the empty list out and
`rebuild` warns, so the difference that follows is attributed to the checkout rather than to the
package. Turning that warning into a refusal needs a way to know a project is VCS-versioned before
building it, which is a `pyproject.toml` read the inferrer does not do yet.

## B24. A content-addressed toolchain store, mounted rather than layered

[ADR-0012](adr/0012-base-images-supply-bytes-not-decisions.md) says a base image may supply bytes
and never decisions, which leaves every build paying to fetch its own toolchain. This is how to stop
paying without putting the decision back in the image.

Keep unpacked toolchains on the worker at `/var/lib/trigon/toolchains/<sha256-of-tarball>/`, mounted
read-only into the build, and have `npm/install-node` (and the Cargo and .NET equivalents) look there
**by hash** before reaching the network. The identity of the toolchain then travels as a hash in the
run record rather than as a layer in an image digest — so two runs using the same Node are
comparable even if the images differ, which is the opposite of what a per-version image does.

Measured on the M1 npm corpus, which is what makes this worth doing rather than assuming:

- **4.1% of wall time** is toolchain install: 457s of ~11,000s across 197 targets.
- **8.66 GB of toolchain egress**, of which only **4.41 GB is distinct content** — the rest is the
  same 102 tarballs fetched again. (Total corpus egress is 39.2 GB; toolchains are 22% of it.)
- **102 distinct Node versions** — the reason an image axis cannot work and a hash-keyed store can:
  the store holds 102 entries at ~50 MB without creating 102 environments.

**The cheapest win is not the toolchain at all.** `registry.npmjs.org/npm` is a 22.3 MB packument
fetched **309 times — 6.89 GB, 17.6% of all corpus traffic**, because `npx --package=npm@X` asks for
it on nearly every target. Caching one document by digest changes no fidelity whatsoever and is
worth doing first, independently of the rest.

**Host-side, not mirror-side, and that is the design's load-bearing detail.** A cache inside
`trigon-mirror` would be invisible to the attestation — not in the run key, not in
`Environment`, not in `externalParameters` — and would sit beside `guard.rs`, the code enforcing
that a build cannot fetch its own published artifact. Mutable state that silently defines the
environment, next to the component whose whole job is to be a boundary, is the wrong first cache. A
host-side store whose every entry is verified **by hash on use** is a different proposition: it can
only ever hand back the bytes that were asked for, and a corrupted or tampered entry fails the check
rather than forging an environment.

The mechanism exists already: `crates/trigon-sandbox/src/podman.rs` assembles a `--volume` for
`/out`, and at `mirror-only` the deps phase runs inside `podman run`, which is exactly where a second
read-only mount lands. `rebuild/network.jsonl` already records each toolchain download with
`"checked":"hashed"`, so the keys are being computed today and thrown away.

**Done when:** a second sweep of the same corpus fetches no toolchain it fetched the first time, the
run record names the toolchain by hash, and a deliberately corrupted store entry fails the build
rather than being used — that last one is the test, because a cache that cannot be caught serving
the wrong bytes is the thing this design exists to avoid.

## B27. ~~A `_nodeVersion` we cannot fetch, and what to build instead~~ — closed

`env/toolchain-unavailable` now names this honestly and stops there. What it does *not* do is
decide which toolchain to build with, because that is a fidelity question rather than an
implementation detail. Two corpus targets, and they are not the same problem:

| target | `_nodeVersion` | why the URL 404s |
|---|---|---|
| `isexe@2.0.0` | `8.0.0-pre` | the string a Node built from master reports before 8.0.0 is cut; nodejs.org never published it |
| `delayed-stream@1.0.0` | `1.6.4` | **io.js** — a real release, but only ever at `iojs.org/dist`, under an `iojs-` filename |

Measured, not assumed: every distinct `_nodeVersion` in the npm corpus (117 of them) was probed
against `nodejs.org/dist`, and exactly these two 404. A further five targets record no
`_nodeVersion` at all, which the rung already declines on. So this is 2 of 197, not a systemic gap —
worth fixing correctly rather than urgently.

**~~io.js is the easy half~~ — done.** `npm/install-node` routes majors 1, 2 and 3 to
`iojs.org/dist` under the `iojs-` filename, and `iojs.org` is on `TOOLCHAIN_HOSTS`. Not a
substitution: iojs.org still serves that exact binary, so the build gets the toolchain the publisher
ran. `delayed-stream@1.0.0` went from `build-failed:deps` to **`normalized`**, 6 of 6 members
identical, with the transcript recording
`https://iojs.org/dist/v1.6.4/iojs-v1.6.4-linux-x64.tar.gz` at 8,224,933 bytes.

Node 0.x stays on nodejs.org and so does everything from 4.0.0 on, so the selection names three
majors rather than a range. It is a shell `case` for the reason `npm/npx.yaml` gives — `1.*` catches
`1.6.4` and leaves `10.9.2` alone, where a prefix test would not — and a test runs that `case` under
a real `sh` across both boundaries. `libc: musl` is deliberately not wired up: unofficial-builds
carries no io.js, so an Alpine image asking for one gets `env/toolchain-unavailable`, which is true.

**The pre-release half is a real choice, and the options are not equal.**

- **Decline it.** Consistent with what the rung already does when `_nodeVersion` is absent, and with
  ADR-0012's line that we may supply bytes and never decisions. Costs the target.
- **The nightly the publisher actually used.** It existed: the Wayback snapshot of nodejs.org's
  nightly index taken 2017-03-25 lists `v8.0.0-nightly20170323ee19e2923a` — isexe's own publish date
  — alongside near-daily v8.0.0 nightlies through March 2017. The live index is pruned to two
  entries for that month, so those builds are *gone now*, not never there. Any scheme resting on
  them depends on an archive, which is a different reliability claim from nodejs.org/dist.
- **The nearest release, under a stated assumption.** Note that "nearest" has two defensible answers
  and they differ: on 2017-03-21 Node shipped both **v4.8.1** (newest by date) and **v7.7.4**
  (highest by number). A rule has to pick one and say which, in the run's assumptions, next to the
  toolchain-window line the cargo rung already writes.
- **The same major.** `8.0.0` for `8.0.0-pre` reads closest to the string and is the furthest from
  the truth in time — released 2017-05-30, two months *after* publication.

**Measured.** The question was whether Node's version reaches the packed bytes. For `isexe@2.0.0`
it does not, and the substitution reproduces: built from the pinned commit with its recorded npm
4.4.2 under **Node 7.7.4**, the artifact compares **`normalized` against the published tarball, 8 of
8 members identical** (stabilized `5862967ffd0b…`). The package has no dependencies and no
`prepare`/`prepack` script, so the only thing that could have differed is npm's manifest rewrite,
and npm is pinned from `_npmVersion` either way.

**The choice of "nearest" is load-bearing, and two of the three candidates do not even build.** Same
strategy, same npm, only the Node version varying:

| Node | chosen by | outcome |
|---|---|---|
| 4.8.1 | newest release **by date** at the publish moment | deps failed — `Cannot find module '@npmcorp/copy'` installing npm 4.4.2 |
| **7.7.4** | **highest version number** at or before the publish moment | **`normalized`, 8 of 8 members identical** |
| 8.0.0 | same major as the `8.0.0-pre` string | deps failed, exit 255 |

So "nearest release" resolved by date picks a toolchain that cannot run the pinned npm, and the
same-major reading picks one released two months after publication that also cannot. Highest
version number at or before the publish instant is the only one of the three that works here, and
that is a measurement rather than a preference. Both failures classify as `unknown`, which is a
separate gap worth a rule.

Caveat on the strength of this: `isexe@2.0.0` is the whole population of the pre-release case in
this corpus — 1 of 1, not 1 of many — so the substitution is validated for the only target that
needs it, and the *rule* remains an extrapolation to targets not yet seen.

**Closed.** Both targets reproduce, by different mechanisms, and the difference is the point:

- `delayed-stream@1.0.0` → **`normalized`** on the publisher's own binary, fetched from iojs.org.
  No assumption, because nothing was substituted.
- `isexe@2.0.0` → **`normalized`**, 8 of 8 members identical, attested and signed — built on Node
  7.7.4 where the registry recorded `8.0.0-pre`, and the run says so:

  > the registry records Node 8.0.0-pre for this publish, which is a build from master rather than
  > a release and exists on no distribution host; this builds with 7.7.4, the highest Node released
  > at or before the publish instant. The npm that packs the tarball is still the one the registry
  > recorded, and for a package with no build step that is what shapes the artifact — but a package
  > whose build runs under Node could differ, and this run cannot tell you it did not

The substitution fires only when the recorded version is not a plain `x.y.z`, so io.js versions are
never substituted — trading an exact toolchain for a nearby one would be strictly worse. It resolves
by fetching `nodejs.org/dist/index.json`, filtered to releases that ship `linux-x64`, because Node's
releases are irregular and there is no train to compute them from the way `cargo_current_at`
computes Cargo's. One target in 197 reaches that fetch.

**What stays open, smaller:** both of the Node versions the measurement rejected failed as
`unknown` — `4.8.1` with `Cannot find module '@npmcorp/copy'` while installing npm 4.4.2, `8.0.0`
with a bare exit 255. Neither is reachable now that the rule picks by version number, but `unknown`
is the bucket that hides our own bugs among the packages', and an old npm failing to install over
itself is a nameable class.

## B26. The repair loop has no provider that reliably finishes a repair-sized turn

`--model copilot` is the only provider that needs no API key, which makes it the one a contributor
reaches for first. It does not reliably finish a repair. Measured across four real repairs of
`ts-node@10.9.2` and `xstate@4.38.3`: three turns ended inside the model's reasoning with no answer
at all, and the ones that did produce text produced 704 and 130 characters before the stream
stopped — enough to parse into a strategy, not enough to be a whole one. The CLI's own log records
each as `Timed out dispose: PromptMode.stdout`. The same prompt, replayed by hand, answered in full.

[§3.27](16-findings.md#327-four-things-wrong-on-the-path-nothing-had-walked) has what was fixed
around it: answers are no longer discarded when the consolidated event never arrives, an empty turn
is retried once, and a short answer can no longer replace a good verdict. None of that makes the
turn finish.

Three things would, in increasing order of effort:

- **Ask for less.** The repair prompt carries the previous strategy, the failure, up to 200
  repository paths and a compressed build log, and asks for a whole strategy document back. A
  repair is usually a change to one or two steps, and a diff-shaped answer would be a fraction of
  the output — which is the half that is running out.
- **Say when an answer was short.** `stop_reason` is now `truncated_stream` on a reassembled
  answer and nothing reads it. The repair loop could re-ask on that alone, before the parser has to
  discover the answer is half a document.
- **Have a provider in CI that finishes.** Everything above is guesswork until one run of the
  corpus goes through the loop end to end. That needs a key, so it is a decision rather than a task.

**Done when:** one corpus target fails deterministically, is repaired by a model, and rebuilds — and
the corpus says how often a repair helps at all, which no number anywhere currently says.

## B28. ~~One floor for every route, and the routes are not alike~~ — closed

`trigon-politeness` spaces every request to a host by 100 ms. That number came from
`trigon-registry::ClientConfig`, where it governed **metadata** requests — resolving a package,
asking a forge about a tag — and where it is plainly right.

It now also governs every artifact and toolchain fetch, because those are what the mirror proxies
and the mirror is where the limiter went. A build installing eight hundred dependencies therefore
pays eighty seconds of pure spacing on tarballs alone, before anything is downloaded or unpacked.
Measured in the 125-target random sweep: targets with a large dependency tree went from tens of
seconds to minutes, and the spacing is the difference.

The two routes are not alike. An index document is a decision and the thing a registry most wants
us to ask for gently. A `.tgz` at an immutable URL is a CDN object, served by infrastructure built
for exactly this, and the cache collapses the repeats anyway — the measured 86.7% of them.

**The shape of the answer**, not yet chosen: a per-route floor rather than a per-host one, with the
index route keeping 100 ms and the artifact and toolchain routes taking something much smaller or
nothing. What must not happen is picking the number by how fast it makes a sweep feel, which is how
a rate limit becomes decorative.

Related, and larger: the limiter was **process-global while the mirror is per-target**, so across a
sweep at N lanes the declared floor multiplied by N. **Also closed**, by the lock file this entry
predicted: `politeness::share_with` points the limiter at a directory, `reserve_shared` claims the
next slot under `flock` in a file holding a wall-clock microsecond, and the mirror is handed the
fetch cache's root — the one directory every mirror container in a sweep already shares. Wall clock
rather than `Instant`, because two processes cannot compare theirs; that is the whole difficulty.

A slot file that cannot be used sends the caller back to the in-memory queue rather than returning
"go now", because a limiter that fails open is a control that reports success while doing nothing.
The host is hashed into the filename: it comes from a URL a package's metadata chose, and a path
assembled from one is a traversal.

**Built:** `Route::Index` keeps the 100 ms the careful client always declared; `Route::Bytes` — an
artifact or a toolchain at an immutable URL — takes 20 ms. One queue per host either way, because a
registry counts requests and not categories, and two budgets would mean the declared rate is their
sum. The numbers are conservative rather than tuned: picking them by how fast they make a sweep feel
is how a rate limit becomes decorative.

Across a fleet it is still the queue, which is M4 stage B.

## B25. ~~The fetch cache behind the mirror, in three tiers~~ — two of three built

[ADR-0013](adr/0013-a-cache-supplies-bytes-never-decisions.md) decides the shape; this is the work.
[B24](#b24-a-content-addressed-toolchain-store-mounted-rather-than-layered) is its toolchain tier
and lands first — the two should not be built as one thing, because only one of them has a
correctness question.

Measured on one 186-run npm sweep at `mirror-only`: **39.23 GB of egress across 143,362 fetches,
of which ~4.1 GB is distinct.** The split is the surprise and it decides the order of work:

| route | fetches | bytes | distinct | once each |
|---|---:|---:|---:|---:|
| index | 57,219 | **25.70 GB** | 4,962 | **1.52 GB** |
| toolchain | 181 | 8.66 GB | ~30 | ~0.20 GB |
| artifact | 85,962 | 4.87 GB | 14,138 | 2.40 GB |

**Built, as two tiers rather than three.** `trigon-mirror`'s `cache.rs`, reached by
`trigon rebuild --cache <dir>` and `trigon sweep --cache <dir>`, mounted into the per-target mirror
container as a read-write volume because the mirror runs inside the build's network island and a
cache that died with it would collect only the 8% of repeats that happen inside one target.

- **Bytes** (artifacts and toolchains): permanent, shared by every run on the machine, digest
  re-checked on every read with a mismatch treated as a miss and the entry removed. B24's separate
  toolchain store is now redundant with this and should be closed rather than built.
- **Index**: scoped to one invocation — one sweep, or one standalone rebuild, which means a single
  rebuild shares nothing with anybody. The scope is a path component, so bounding staleness needs no
  TTL and no clock.

The obligations ADR-0013 attaches to the index tier are both in: `run.json` carries a `fetch_cache`
block with the hit and fetch counts and **the instant the oldest index document it resolved against
was fetched**, and `trigon watch` renders it in those words. What is *not* built is the ADR's
live-comparison control — re-fetch, re-filter, compare digests — and `--no-cache` is the absence of
`--cache` rather than a path that is exercised.

**Tier 1 — toolchains.** B24, host-side, keyed by tarball sha256.

**Tier 2 — artifacts.** Keyed by upstream URL, verified against the digest the registry published
on **every** read, permanent. A `.tgz`, a wheel, a `.nupkg` and a `.crate` are immutable and already
hashed on the way past by `guarded_stream`, so the check costs nothing that is not already paid. An
entry failing it is a miss, never a warning. 4.87 GB → 2.40 GB, 86k requests → 14k.

**Tier 3 — indices, and the only part with a correctness question.** 94% of index traffic is
redundant, and one document — `registry.npmjs.org/npm`, 22.3 MB, 309 fetches, 6.89 GB — is 18% of
the whole sweep. But a packument decides which versions exist, so:

- Scope the entry to a single sweep invocation rather than giving it a TTL. The 309 fetches happen
  within hours of each other, so this collects nearly all of the prize while bounding staleness by
  construction instead of by a number someone picked.
- Record the **instant the snapshot was fetched** in the run's pin evidence, beside `rejected`. A
  reader must be able to tell "filtered a document fetched seconds ago" from "filtered a document
  fetched on Tuesday" without knowing the ADR exists.
- Ship the live-comparison control with the tier, not after it: re-fetch upstream, re-filter, and
  compare the digest of the filtered result against what the cached path produced. A cache whose
  slow path is only a debugging flag is a cache whose slow path has rotted.

**The bug class to design against is the one we just paid for.** `trigon/client-corrupted-download`
took three investigations because a partially-delivered body read as a whole one. A disk cache adds
eviction, concurrent writers and partial writes to a component that has none of them today: write to
a temporary path and rename, and read every entry back through the same digest check as the network
path, or this reintroduces that failure with our name properly on it this time.

Not a route the build can reach, and not in front of the guard: `guard.refuses(url)` runs before the
fetch and `guarded_stream` writes the transcript row, and both must keep running exactly as they do
now. The cache answers "where did the mirror get this", never "what did the build receive".

## B21. Keyed signing under a trusted root, and the Rekor client

[ADR-0011](adr/0011-keyed-signing-under-a-trusted-root.md) settles the design and staging has
confirmed the part that could not be settled on paper: **Rekor accepts an ed25519 key under a
self-issued certificate**, so "their log, our CA" works.

Five pieces, in the order they unblock each other. **1-3 are built**; 4 and 5 are not.

1. ~~**`dsse::Signature` gains a certificate chain.**~~ Built. `Signature.chain` is a `Vec<String>`
   of PEM, leaf first, and `is_chained()`/`leaf()` read it. The envelope is versioned by
   `payloadType`, so old bundles keep verifying against a pinned key.
2. ~~**A `Rekor` client**~~ Built, as `mod rekor` in the binary — above the judgement line, behind
   `#[cfg(feature = "build")]`, reached by `trigon attest --rekor <URL>`. One POST to
   `/api/v1/log/entries` with an `intoto` **v0.0.1** entry (not v0.0.2: the envelope goes in as a
   serialized JSON *string*, with the certificate as a sibling `spec.publicKey`), storing the
   returned `logIndex`, UUID, `logID` and `signedEntryTimestamp` on the run as
   `RunRecord.transparency`. A duplicate returns `409` carrying the existing UUID, which we fetch
   and store, so a retry after a timeout is safe.
3. ~~**SET verification**~~ Built, in `trigon-attest::transparency` — **below** the judgement line,
   so the `--no-default-features` verifier can check a SET without linking a network client. The
   canonicalization is the part that is not guessable: the signature covers RFC 8785 JCS of exactly
   `{body, integratedTime, logID, logIndex}`, with `body` verbatim as the log returned it.

   Proven against live staging rather than a hand-built fixture.
   `crates/trigon-attest/tests/transparency_live_entry.rs` checks two real `rekor.sigstage.dev`
   entries offline, against the log's pinned key: index **56040866**, posted by hand to settle
   whether Rekor accepts our envelope shape at all, and index **56041854**, which
   `trigon attest --rekor` produced end to end. The negatives are there too — production's key
   against a staging entry, and a re-encoded `body` — and the unit tests in `transparency.rs` cover
   a well-formed-but-wrong signature separately from bytes that are not a signature, because those
   fail differently and only one of them is interesting.

   What this still does not do is the thing it exists for: nothing yet checks the returned time
   against a certificate's validity window, because there are no certificates until 4 and 5. The
   time is verified and stored; it is not yet load-bearing.
4. **Chain validation to a pinned root** in `verify-attestation`, replacing `--public-key <hex>`
   with `--root <pem>` defaulting to the root compiled into the verifier.
5. **The CA itself** — an offline root, an intermediate in a KMS, short-lived leaves. Operational
   work rather than code, and the piece keyless would have avoided entirely.

**Done when:** a statement signed under a real chain verifies in the `--no-default-features`
verifier, with the Rekor SET checked against the leaf's validity window, and the corresponding
negative tests fail — a signature outside the window, a chain to the wrong root, a SET that does not
verify.

## B19. ~~Cargo needs an index commit, not a timestamp~~ — mostly closed, one part outlived it

`pkg:cargo/serde@1.0.219` used to rebuild at `--egress open` and diverge on exactly one of
twenty-eight files, `Cargo.lock`, because the lockfile was today's dependency resolution rather than
the publisher's. It now reproduces **`exact` at `--egress mirror-only`**, lockfile included, as does
`hashbrown@0.17.1` across 50 members.

**The premise expired.** This item argued that a timestamp "isn't precise enough" because the index
was a git repository whose commits are not evenly spaced in time. The sparse index now carries a
`pubtime` on every line — all 56 versions of `hashbrown`, all 316 of `serde`, back to 2014, in the
RFC 3339 UTC form [`moment.rs`](../crates/trigon-mirror/src/moment.rs) already compares lexically.
The instant became a property of the document, so the npm and PyPI shape applied after all and the
git-commit machinery was never needed. `RegistryMoment::GitCommit` still has nothing producing one.

Both halves of the old "done when" are met except one clause: the attestation records the **moment**
it resolved against, not an index commit. That is now the right thing to record, because the moment
is what the filter used.

**Yank state has no history anywhere, so it is a choice rather than a lookup.** A line's `yanked`
flag is its state *today*. The sparse index does not record when a version was yanked and neither
does the API — `/api/v1/crates/{name}/versions` returns `yanked` and `yank_message` and no
timestamp — so the state at the pinned instant cannot be reconstructed from anything crates.io
publishes.

Both answers are wrong somewhere. Keeping today's flag was measurably the worse one:
`bitflags@2.6.0` requires `bytemuck = "1.12"` and its published lockfile names 1.16.1, but every
1.15.x and 1.16.x has been yanked since, so Cargo resolved 1.14.0 and the crate diverged on
`Cargo.lock` — two of ten crates in a sweep failed exactly that way, each blamed on the package for
a fact about our own afternoon. The mirror now clears the flag on every surviving line, and the
cargo rung states it as an assumption on every run that resolves through the mirror.

The residual error runs the other way: a version already yanked *at* the pin is offered as live.
That is much rarer, because Cargo takes the newest version satisfying a requirement and a
long-yanked one is normally superseded by something it would pick instead. The remaining work is to
notice when it bites — a resolved version that was yanked before the pin is not distinguishable
today from one yanked after it.

## B20. The toolchain window is the game for Cargo and we compute a date instead

`cargo/build/package` picks the Cargo release current when the crate was published, computed from
the six-week train rather than a table. That is the cheap opening move and accurate to within one
release, and it beats the edition floor by years — building `serde` 1.0.219 with edition 2018's
floor of 1.31 fails outright, because `cargo package -p` did not exist then.

It is not the fingerprint. The published `.crate` carries a `Cargo.toml` that **Cargo rewrote**, and
the rewrite rules changed across releases — pretty-printed arrays from 1.60, a header comment from
1.55, `debug = true` denormalized before 1.71, `doc-scrape-examples` from 1.67. The manifest inside
the artifact therefore pins the window far tighter than any date can, and
[`03-ecosystems.md`](03-ecosystems.md) calls reading it the game for this ecosystem.

Everything needed is already here: `toml_edit` is a named dependency for exactly this (a
format-preserving parse, because plain `toml` discards the information the trick depends on), and
`Claim::ToolchainRange` intersects with the edition floor and the publish date through
`resolve_toolchain` without any of the three knowing about the others.

**The corpus now says how often.** A ten-crate sweep at `mirror-only`, after the index filter and
the `--allow-dirty` fix landed: five reproduce `exact` (`itoa`, `bitflags`, `clap`, `tokio`, plus
`hashbrown` and `serde` alongside), and **every remaining divergence is this item**, in two shapes:

- **`Cargo.toml`** — `anyhow@1.0.86`, `regex@1.10.5`, `syn@2.0.66`. The published manifest carries
  `build = false`, `autobins = false`, `autoexamples = false`, `autobenches = false` and an explicit
  `[lib]` table that ours does not, which is a *newer* Cargo than the date estimate picked. The
  divergence is one file and it is the rewrite.
- **`Cargo.lock` format** — `serde_derive@1.0.219`. The published lockfile is v1
  (`"unicode-ident 1.0.18 (registry+…)"`, no `checksum` fields, no `version =` line) and ours is v3.
  Same cause, different surface: the lockfile format a `cargo package` writes is a property of the
  Cargo that wrote it, so it is a second fingerprint pointing at the same window — and a cheaper one
  to read than the manifest, since the format version is a single line.

So the estimate is wrong in the *old* direction for recent crates and the manifest says so. Note
also that `libc@0.2.155` declines outright — crates.io declares no edition for it, so there is no
floor and the rung refuses to guess. A fingerprint read from the artifact would give that crate an
answer where the edition gives none, which makes this item the fix for a `no-strategy` as well as
for the divergences.

**Done when:** a crate whose manifest fingerprint contradicts its publish date resolves to the
fingerprint's window, and the three named above reproduce `exact`.

## B18. The npm strata that build anything reproduce at 12% and 25%

The 300-target common-path run, per stratum:

| npm | compared | reproduced | |
|---|---:|---:|---|
| no lifecycle script | 54 of 69 | 46 | 85% |
| `prepare`/`prepack` | 19 of 46 | 16 | 84% |
| TypeScript build | 8 of 23 | 1 | **12%** |
| monorepo member | 4 of 13 | 1 | **25%** |

**The reach is the worse half.** Only 8 of 23 TypeScript targets and 4 of 13 monorepo members get as
far as a comparison at all, so those rates are computed over a third of each stratum. "TypeScript
reproduces at 12%" honestly reads "one of the eight we could measure".

This is the number [`15-corpora.md`](15-corpora.md) §3 predicted in the abstract — "an aggregate
that hides a 20% rate on native extensions is not a number anyone can act on" — and the aggregate
hiding it is npm's 75%.

PyPI is the contrast that makes it a finding about npm rather than about rebuilding: flit/hatchling
and poetry-core are at 100% with every target reaching a comparison, and even the native-extension
stratum is at 57%.

**Measured again, and the first numbers were substantially about us.** 13 of the 35 failures were
`trigon/mirror-refused-unfiltered`, fixed separately. What remained had one dominant cause and it
was not the one assumed: 13 of 16 divergences were *"every shared file byte-identical, compiled
output missing entirely"* — the rung did not know a build existed.

| | as filed | now |
|---|---:|---:|
| reached a comparison | 12 of 35 | **22 of 35** |
| reproduced | 2 | **10** |
| divergent | 10 | 12 |

Three fixes, each measured:

- **`prepublishOnly` was on the list of hooks `npm pack` runs.** It is not, and never has been —
  verified against npm 11.16.0 with a package declaring all four hooks, which packs the output of
  `prepack` and `prepare` and nothing else. The rule was deliberately conservative ("holds under
  every npm version"), which is right for `prepublish` and backwards for this one.
- **The rung validated the command body, which never reaches a shell.** `npm run <script>` is what
  executes, so `&&` in a composite build gated out every package with one — the commonest shape in
  this ecosystem. The script *name* is validated instead, which is the string that is run.
- **A member arriving inside another release of the package itself no longer voids.** Running the
  publisher's build installs devDependencies, and something in that tree routinely depends on an
  older release of the package being rebuilt. Introduced by the first fix and found by measuring it.

**What is left, and it is the monorepo stratum's own cause.** Of 13 remaining failures, 4 are
`npm/workspace-protocol` — the published tarball was built with the whole monorepo on disk and we
build the member alone, so `workspace:*` resolves against nothing. That is B22 rather than more of
this entry.

**Done when:** B22 lands and the monorepo stratum is re-measured. The TypeScript stratum's cause is
fixed.

## B22. A monorepo member has to be built from the workspace root

`npm/workspace-protocol`, four targets in the hard strata and the largest remaining cluster in them.
`repository.directory` tells us which member a package is, and the recipe checks that subdirectory
out and builds there — but the published tarball was produced by a `npm pack` run with the *whole*
workspace present, so `workspace:*` dependency specifiers resolved against sibling packages that our
checkout has and our build cannot see.

The shape of the answer is known and is not the current one: install from the workspace root, then
pack the member. `npm pack -w <member>` and `pnpm --filter` both express it; which one applies is a
function of the lockfile the repository carries, which the rung already reads for other reasons.

**Done when:** the four targets build, and the monorepo stratum's reproduction rate is measured
rather than inferred from one target.

## B17. What an unnamed failure should cost a package

`FailureSignature::unknown` is `Fault::Build`, so a failure no rule in the table claims lands in the
numerator of the published reproduction rate. `crates/trigon-core/tests/seam_fault_classification.rs`
pins that deliberately and calls it "a tripwire on a known asymmetry rather than a statement that it
is fine".

The reading it rests on is that `classify` only ever runs on a build log, so a build did run and did
fail. That was **false** while the container runtime's own output reached it: an image absent from
the local store produced a registry error, matched no rule, and charged the package — which is how
`--image localhost/trigon-base@sha256:<stale>` came to report `the build failed in deps: unknown`.

Two changes have narrowed it since. A runtime refusal before any of our scripts run now returns
`SandboxError::RuntimeRefused` and never reaches `classify`; and the table has rules for the runtime
failures that *do* produce a log — `env/image-unavailable`, `env/runtime-refused`, and the lowercase
spellings of no-space, out-of-memory and permission-denied that only the container forms emit.

**Still open, and a question about what the published rate means rather than a defect.** The residue
is empirically mostly ours — the tripwire's own comment lists a mirror answering 400 to a toolchain
fetch, a missing `npx` under dash, and three npm-corpus failures that were all ours — and every one
of those cost a package until somebody noticed the cluster and wrote a rule. Against that: a genuine
package failure with no rule would stop counting against the package, and `Fault` has no variant
meaning "we do not know", so either answer overstates something.

**Decide when:** the corpus is large enough to measure what fraction of the residue turns out to be
ours once rules are written for it. Flipping it silently would move every number this project has
published.

Related: `SandboxError::Timeout` is `Fault::Build`, which is right for a build that ran too long and
wrong for a wall clock that expired while the runtime was still pulling an image. Telling the two
apart needs the log rather than the type.

## B15. A clean re-run must not be a cache hit

[`09-attestations.md`](09-attestations.md) §5 requires two independent re-runs before a divergence
is published, on the reasoning that one re-run cannot tell a deterministic recipe from a lucky one.
Podman caches build layers by content, so a second build of the same strategy reuses the first one's
— including the file timestamps baked into them — and produces a byte-identical artifact. That is
not a second opinion; it is the first one replayed.

Found by the end-to-end test that exists to prove two builds differ and still normalize. It began
failing when B6's deferred image removal let those layers survive between runs, which means the
hazard was always there and was previously masked by images being deleted promptly.

`RunOpts::no_cache` exists and is wired (`TRIGON_NO_BUILD_CACHE`), defaulting to off because the
caching is worth having — the deps layer is shared across sibling versions of a package.

**Done when:** the re-run path sets it, and a test asserts that two re-runs of one target produce
artifacts with different raw digests and the same stabilized one. Until then, nothing in this system
performs a clean re-run at all, so the requirement is unmet for a reason older than this entry.

## B16. System libraries are the one input a rebuild does not pin

A rebuild pins the registry index to the package's publish moment, pins the toolchain by version,
and then links against whatever `libssl` or `libffi` the base image happened to carry on the day
somebody last built it. Every other input is a function of the target; this one is a function of our
own housekeeping.

`snapshot.debian.org` serves a Debian archive as of a timestamp, which is the same mechanism
[`trigon-mirror`](../crates/trigon-mirror/src/moment.rs) already applies to a registry index — so
the shape of the answer is known and it is the one this project already uses twice.

**Not urgent, and worth writing down rather than losing.** Nothing today claims system-library
reproducibility, and the corpus has not shown a divergence traced to one. What makes it worth
keeping is that the claim gets *stronger* elsewhere over time, and this is where the honesty runs
out first.

**What it is not.** A design pass over four independent proposals landed on host-side base-image
repair from a header-to-package table, and the measurement it recommended taking first — a histogram
of what the failing targets actually need — said do neither. Four targets, four different packages,
no repetition: `ffi.h`, `yaml.h`, a Rust toolchain, `meson`. A table and a repair loop both need a
repeating tail to pay for themselves. `trigon base-image --packages` already lets an operator extend
the image for their own corpus, and the piece that was genuinely missing was the diagnosis telling
them what to add, which `cc/missing-header:<h>` and `env/missing-tool` now do.

**Declined, with the measurement it asked for.** The condition was: run the full 200-target PyPI
corpus and either the tail repeats, in which case build the table, or it does not, in which case
record that and close. All 200 have now been run. Across every PyPI target run — 217 distinct,
including the 17 outside the corpus — the entire tail is four targets:

| target | wanted |
|---|---|
| `pkg:pypi/cffi@2.0.0` | `ffi.h` |
| `pkg:pypi/msgpack@1.1.2` | `_cmsgpack.c` |
| `pkg:pypi/bcrypt@5.0.0` | a Rust toolchain |
| `pkg:pypi/numpy@2.4.6` | `meson` |

Four targets, four different subjects, no subject appearing twice. The 50 targets added last —
none of which had been run before — contributed none. The 40-target sample was not too small; it
was the whole of it. A header-to-package table and a repair loop both need a repeating tail to
pay for themselves, and there is no repetition to amortize against.

What stays: `trigon base-image --packages` for an operator extending the image to their own
corpus, and the diagnosis that tells them what to add. Of the two, the diagnosis was the piece
genuinely missing, and `cc/missing-header:<h>` and `env/missing-tool:<t>` name the subject
exactly — `ffi.h`, not "the build failed".

What is *not* declined is the paragraph above about `snapshot.debian.org`: pinning system
libraries is a different question from installing them, this entry's title is about the former,
and it remains unanswered. It is recorded in [`12-security.md`](12-security.md) as a limit of the
claim rather than as work.

## B8. The three ecosystems after npm and PyPI

`nuget.org`, `crates.io` and `rubygems.org`. [`03`](03-ecosystems.md) has a chapter on each and
[`13`](13-roadmap.md) puts them in M5; what makes them worth naming here is that they are the test of
the extension seam. Adding one should be a `Registry` implementation plus some YAML tools, with no
change to the engine — and if any of them needs a special case in the ladder, the seam is wrong and
that is the finding.

Each is a different kind of interesting, and they are not equally hard:

- **crates.io** is highly reproducible by design and the game is toolchain-window inference: Cargo
  rewrites `Cargo.toml` at package time and the rules changed across releases, which pins the
  toolchain far tighter than a release date. It also needs a registry moment that is a **git commit
  in the index**, not a timestamp — `RegistryMoment` is already an enum for exactly this and nothing
  has exercised the other arm.
- **RubyGems** went from 0% to 99.9% reproducible since 3.6.7 and **nobody verifies it
  independently**. Cheapest large win and the clearest differentiation. Needs nested archives
  (`data.tar.gz`, `metadata.gz`, `checksums.yaml.gz`), which the archive model supports and no
  corpus has yet driven.
- **NuGet** has trusted publishing and essentially no reproducibility infrastructure, so we would be
  partly inventing the ecosystem's story. Sequenced last, and honestly caveated when published.

They share one thing the current code does not have: a version algebra each (`semver` is
Cargo-flavoured; RubyGems and NuGet have no usable Rust crate, so both are hand-rolled). The
`VersionOrd` trait that was supposed to hold them was never written — see
[`02`](02-domain-model.md) §6.

**The stabilizer half is already done for two of the three.** `crate` (tar+gzip + `cargo-vcs-hash`)
and `gem` (tar+gzip + five gem passes) both exist, are listed in `all_profiles()`, have dedicated
tests, and — for cargo — nineteen targets already run through the golden differential corpus. Only
NuGet has no profile, and `main.rs` records that a `.nupkg` arm was deliberately *removed* because
it named one that did not exist. So the judgement half needs nothing for crates.io.

### What the census found

A six-subsystem read of the code against this item's own claim, with an adversarial verify pass over
each report, is written up in [`16`](16-findings.md) §3.18. In short: **the seam holds where it was
hardest to build and leaks where it was cheapest.** Adding crates.io is 14 work items, 10 in engine
files, 8 genuine edits. The ladder leak — `_ => {}`, a `no-strategy` verdict indistinguishable from
a package we could not infer — is closed, along with two live bugs the census turned up on the way
(the mirror's allowlist skipped every redirect hop; `same_artifact` would have voided every
crates.io run).

### What is left for crates.io, in order

1. `CratesIoRegistry` in `trigon-registry`, plus the `for_ecosystem` arm and its `supported:` string
   (a source-text seam test asserts those two agree). `ArtifactMeta.id` must be synthesized as
   `{name}-{version}.crate` — the npm trick of taking the URL's last segment yields the literal
   `download`, and the id selects the stabilizer profile, the definitions path and the store key.
2. `CargoInferrer` beside `NpmInferrer`/`PyPiInferrer`, and the `ladder()` arm.
3. `tools/cargo/*.yaml` plus their `BUILTIN_TOOLS` lines, and widening `inferrer::supported` in the
   same commit — a model asked to propose from a vocabulary that does not exist spends tokens to
   learn nothing.
4. The mirror: `Platform::Cargo`, a sparse-index filter, `static.crates.io` and `index.crates.io` on
   `ARTIFACT_HOSTS`, `static.rust-lang.org` on `TOOLCHAIN_HOSTS`. This is the genuinely novel piece
   and the one blocking `mirror-only`: a sparse-index line carries **no publication timestamp**, and
   `published_by` fails closed, so a naive port of the npm filter would withhold every version of
   every crate. The index commit, not a date, is the moment — and `Filter.moment` is a `String`
   validated to exactly 19 characters of `YYYY-MM-DDTHH:MM:SS`, so a 40-hex oid is a 400 today.
5. Only then the toolchain-window fingerprint, which is the interesting part and needs `toml_edit`.

**Two things to know before starting (4):** `resolve_toolchain` — the intersection function the
whole evidence design is built around — already exists, is generic, and its tests are written
entirely in Cargo's vocabulary; its only callers are inside the unwired CI rung. And every crates.io
verdict will cap at `normalized_with_caveats`, because `cargo-vcs-hash` is `RiskTier::Content` and
the provenance cap fires on anything above `Metadata`. That is correct behaviour and it will need
explaining beside any published rate, or the pass needs a different tier.

**Done when:** each has a `Registry`, a stabilizer profile, a labelled smoke corpus, and a published
rate — and the engine diff for the second and third is empty.

## B10. Publish verdicts somewhere a consumer can find them, and give them a command to ask

[`19`](19-distribution-and-lookup.md) is the design. Two things have to be decided before anything is
signed for publication, because both are baked into a signed statement and expensive to retrofit:

- **`Subject.digest` must carry every digest the ecosystem publishes**, not sha256 alone. npm gives
  sha1 and usually sha512 and never sha256, so a consumer holding an npm lockfile cannot look up our
  records without downloading each tarball. Fixing it after the corpus is signed means re-signing it.
- **Divergences go to the record store and only their digests to the transparency log.** An
  append-only accusation cannot be retracted, and the false-mismatch rate is a tracked, non-zero
  number with a publication kill-switch ([`09`](09-attestations.md) §5). The log keeps us honest
  about having claimed something; the store lets us supersede it.

**Done when:** the subject carries the ecosystem's own digests, a record schema exists with the six
fields [`19`](19-distribution-and-lookup.md) §4 requires, and a lookup client that is not Trigon can
answer a lockfile from a downloadable index without a network call per dependency.

## B11. Wire the CI-derived rung into the ladder, once it declines correctly

`crates/trigon-registry/src/ci/` exists and is **not wired**: nothing calls it, so it cannot yet
produce a candidate. That is the right state for it, because two independent verification passes
came back `needs-work` and a CI rung that emits a confident wrong candidate is worse than no rung —
it displaces the heuristic that would have worked.

Fixed already: `actions/github-script` was on the "cannot affect build output" list while running
arbitrary JavaScript with `exec`, and that list was prefix-matched so anyone naming an action after
an inert one inherited its silence; and `container:` overrode `runs-on`, so a Windows or self-hosted
job that also declared a container escaped the out-of-scope rule ADR-0009 requires.

**All eight fixed, each with a test that fails without the fix.** What each was, and what it is
now:

- `twine check` matched as a publish marker, so on the standard check-then-upload shape the *check*
  became the publish step — which put the real upload's token in `secrets_in_build` (a decline on a
  readable workflow) and put `twine upload` itself into the recipe's steps, so a rebuild lowered
  from it would publish to PyPI. Only `upload` publishes now.
- `actions/download-artifact` in the *build* job was grouped with cache markers as "provably does
  not matter". True of the publish job; in the build job it means the build's inputs are bytes this
  rebuild will not produce, which is the forged-attestation shape of [`12`](12-security.md) §1.1.
  `Decline::BuildConsumesAnotherJobsOutput`.
- `download-artifact`'s `pattern:` was compared as a literal name, so every publish job fanning
  wheels in with a glob lost its build edge. It is a glob now (`*` and `?` only; anything else
  matches nothing rather than something approximate), and the edge records the artifact that was
  *uploaded*.
- `sed` was in `cmd::INCIDENTAL`, so `sed -i` rewriting the tree before the build disappeared and
  the candidate came out `Strong`. `Cmd::MutatesTree` now, separate from `Unknown` because the two
  claim different things; `git`'s tree-writing subcommands moved with it.
- Two decline messages asserted things untrue of the run that produced them. `NoQualifyingJob`
  became `BuildJobUnreachable` where a job qualified and the edge did not resolve;
  `NoToolForBuildCommand` became `RecipeIncomplete` where a build *was* recognised and lowered.
- Confidence inverted around `ubuntu-latest`: failing to resolve the label produced no
  approximation, nothing to lower against, and a `Strong` candidate — the run that knew less was
  the more confident one. A label with no approximation is now at least as uncertain as one with a
  weak approximation.
- Workflow- and job-level `env:` was parsed and read by nothing, so a workflow setting
  `SOURCE_DATE_EPOCH` in its header looked identical to one that did not. It gets the note a
  `GITHUB_ENV` export already got, plus an assumption, because a note lives in a report and an
  assumption reaches the attestation.
- The publish job's own steps were never classified when it was not the build job, so anything it
  did to the artifact between download and upload was invisible.
  `Decline::ArtifactChangedAfterTheBuild`.

**Still not wired, and the remaining condition is the reason.** Both verification angles have to
come back `sound` against the fixed rung before `ladder()` in `crates/trigon/src/main.rs` calls it —
between the heuristic and the model, per [`01`](01-architecture.md) §3. The eight above were found
by exactly that exercise, which is the argument for running it again rather than for trusting that
the list is now empty.

## B13. A commit the forge will not serve needs the tag as a fallback

npm records `gitHead` at publish time and nothing keeps it reachable afterwards. `pad-left@2.1.0`
names `89347534…`, GitHub answers `upload-pack: not our ref`, and no fetch recovers it: the commit
is not reachable from any ref in that repository today. The same repository *does* have a `2.1.0`
tag, pointing at `817d93e8…`.

Closed already: the failure is now named. It used to cluster as `net/unreachable` — the host
checkout failed at `debug` level, the in-container clone then died on the DNS an enforced tier
denies it, and the run was filed beside genuine hidden-network-dependency findings. It is now
`src/commit-not-on-the-forge`, `Fault::Upstream`, raised before the build starts rather than a
minute later somewhere else.

**What is left is a decision, not a repair.** Falling back to the version's tag would verify the
target — but against a *different commit* than the one the registry recorded, which is a different
claim. The type system already carries it: `SourceDiscovery::ExactTag` is `Confidence::Strong` where
`RegistryCommit` is `Certain`. So the mechanism is cheap and the question is whether a rebuild
against the tag, clearly labelled as such, is worth publishing.

Worth noting what the fallback would *not* be allowed to do: silently replace the commit and report
`RegistryCommit`. The whole value of the rung is that a reader can tell which one they are looking
at.

**Done when:** either the fallback exists, records `ExactTag`, and a test asserts the discovery
field is not the registry's; or this is written down as declined with the reason.


## B14. ~~Build the guard manifest after the strategy, so the source filter applies~~ — closed

`GuardManifest::for_artifact_with_source` drops members byte-identical to a file in the source tree
— "a file the artifact ships and the repository also contains is not evidence of anything: the build
is entitled to fetch it." It is used only when an operator passes `--source`. Every other run builds
the manifest with `for_artifact`, unfiltered.

That costs the two bootstrap targets. `packaging@26.3` and `pyproject-hooks@1.2.0` build at the
enforced tier and then void: pip installs the adjacent release, a file unchanged between the two
releases is byte-identical in both, and the build produces that same file honestly from the
checkout — so the digest that arrived is also in the output, which is exactly what
[`16`](16-findings.md) §3.23's void rule asks about. Every member that trips is a source file.

**Why it is not a two-line change.** The manifest is built from the published bytes before a
strategy is chosen, and the source tree is a function of the strategy's location. The filter cannot
move to the decision instead, where the tree *is* in hand, because it carries an exemption that
needs the member's path: an executable the repository also contains is the case most worth guarding,
since a build fetching a prebuilt binary is [`12`](12-security.md) §1.1. And the manifest cannot
simply be built later without moving the host mirror, which is armed with it before the strategy is
chosen because `ladder()` needs the mirror's port.

**Closed.** The cycle was broken by separating *reserving* the mirror's address from arming and
serving it: `trigon_mirror::reserve` returns a held listener, the ladder runs against an address that
exists but serves nothing, the checkout happens, the manifest is built narrow, and only then does the
mirror serve on that listener. A held listener rather than a remembered port, because releasing and
re-binding is a race. The inferrers made it possible — they read the mirror only to decide whether to
pin a registry moment and make no request through it, so a reservation is enough to run the ladder.

`checkout_and_guard` returns both together, so there is no longer a point in the run where a manifest
exists and the checkout does not: the ordering is the invariant and the signature carries it.

Measured: `packaging@26.3` guards **0 of 29 members** — every one is a file the repository also
contains — and reproduces `normalized_with_caveats`, 29 identical, 0 differing. `pyproject-hooks@1.2.0`
likewise. Both were `void`.

---

## B29. What the whole-tree review found and did not fix

The sweep [B1](#b1-security-sweep-over-the-whole-codebase) asks for: seventeen reviewers over every
crate and the front-end, each finding independently re-read by a second agent told to refute it.
117 claims, 108 survived, and this is what is left after the ones fixed on the spot.

**Read these as leads, not as facts.** A 92% survival rate is too high for the verification to have
been as adversarial as intended, and four claims the verifiers *did* refute were things already
fixed while they were reading — so the tree moved under them. Every item below has a file and a
line and a stated mechanism; none has been reproduced by a human or by a test. The ones that were
reproduced were fixed, and are in [`16-findings.md`](16-findings.md) §3.48–§3.56 instead.

**Done when:** each item below is either reproduced and fixed with a test that would catch the
regression, or written off with a reason — and the ones written off say why, because an item
deleted without a reason comes back as a rediscovery.

### `trigon`

- **high** — `guard_manifest`/`guarded_members` are set on every run, so a signed build observation says the artifact-hash check was performed on runs where no guard was ever armed  
  `trigon/src/main.rs:3820`
- **high** — An accepted divergence repair drops the comparison it already has, so a failed next build reports `build-failed` instead of `divergent`  
  `trigon/src/main.rs:4053`
- **high** — `--public-key` is silently ignored when the bundle carries no signature, and `verify-attestation` still exits 0  
  `trigon/src/main.rs:7683`
- **medium** — A comparison that could not be stored is recorded as a non-evidence run whose `terminal` field is a verdict string  
  `trigon/src/main.rs:4933`
- **medium** — A failed read of the published artifact silently substitutes an empty guard manifest for the whole run  
  `trigon/src/main.rs:5271`
- **medium** — `sweep::one` labels every orchestration error `Fault::Policy`, including the sweep's own infrastructure failures  
  `trigon/src/main.rs:6711`
- **medium** — member_diffs joins the two member lists with a linear scan per member (O(n²))  
  `trigon/src/watch.rs:2390`
- **medium** — chain_ribbon byte-slices source.commit at index 8, panicking in the request handler  
  `trigon/src/watch.rs:3620`
- **medium** — worker.rs re-derives retryability from the fault class, discarding Classify::is_retryable  
  `trigon/src/worker.rs:162`
- **low** — The attestor stores a log entry without checking it is about our statement  
  `trigon/src/main.rs:8244`
- **low** — `check_log_entry` byte-slices a `uuid` the SET does not cover  
  `trigon/src/main.rs:7591`
- **low** — "the entry is about this bundle" is asserted from the payload hash alone  
  `trigon/src/main.rs:7573`
- **low** — Every production `rebuild/v1` statement omits the stabilizer set  
  `trigon/src/main.rs:8426`
- **low** — `sweep::completed` accepts a row whose seconds field does not parse, unlike the file's other two readers  
  `trigon/src/main.rs:6826`
- **low** — `capping_passes` hand-copies the provenance cap instead of calling `trigon_core::caps_normalized`, and its test writes the predicate a third time  
  `trigon/src/main.rs:2683`
- **low** — checkout_dir hashes the raw repo/commit while SourceCache keys on the normalized form  
  `trigon/src/provenance.rs:112`
- **low** — index_checkout gives up at MAX_FILES but reports the truncated walk as a completed search  
  `trigon/src/provenance.rs:171`
- **low** — The checkout index memo is an unbounded, never-evicted static cache in a long-lived server  
  `trigon/src/provenance.rs:296`
- **low** — join() attributes every line-ending match to nupkg-text-eol regardless of format or stabilizer set  
  `trigon/src/provenance.rs:275`
- **low** — The stabilizer ledger drops every member a pass removed, contradicting the comment above the join  
  `trigon/src/watch.rs:2381`

### `trigon-mirror`

- **high** — `from_a_toolchain` matches the npm toolchain path as a bare prefix, so every package whose name begins with `npm` is exempt from voiding  
  `trigon-mirror/src/guard.rs:482`
- **high** — `same_artifact`'s two-segment fallback reduces a crates.io URL to `{version}/download`, so any dependency at the same version as the target is refused  
  `trigon-mirror/src/guard.rs:1109`
- **high** — `another_release_of` treats any filename `<project><sep><digit>…` as another release, so an attacker-named carrier package is exempt from voiding  
  `trigon-mirror/src/guard.rs:459`
- **high** — `MAX_DECOMPOSE_BYTES` caps compressed input while the decompression it gates inflates into one 4 GiB allocation, synchronously on a runtime thread  
  `trigon-mirror/src/guard.rs:977`
- **high** — Guard's toolchain exemption matches `/npm` as a path prefix, so every npm package named `npm*` is exempt from the member-void check  
  `trigon-mirror/src/guard.rs:482`
- **medium** — A cache hit reads the whole artifact into memory and SHA-256s it synchronously on the tokio runtime  
  `trigon-mirror/src/cache.rs:158`
- **medium** — The toolchain host list exists twice and the two copies disagree, so a legitimate io.js or musl-Node toolchain fetch voids the run  
  `trigon-mirror/src/guard.rs:469`
- **medium** — The guard's private toolchain host list disagrees with the mirror's real one: `iojs.org` and `unofficial-builds.nodejs.org` are proxied but not exempt, `www.python.org` is exempt but never proxied  
  `trigon-mirror/src/guard.rs:469`
- **medium** — `guard::another_release_of` does a raw byte prefix where `pypi::is_version_of` normalizes per PEP 503, so it fails on every hyphenated PyPI project  
  `trigon-mirror/src/guard.rs:456`
- **medium** — The /-artifact route proxies arbitrary paths on the index hosts and caches them as permanent immutable bytes  
  `trigon-mirror/src/server.rs:1050`
- **medium** — The bare-npm-tarball gate falls through instead of refusing, so a client sending Authorization gets any tarball unfiltered  
  `trigon-mirror/src/server.rs:647`
- **medium** — The NuGet flat route has no dot-segment check, so /-nuget/{m}/flat/../... proxies arbitrary api.nuget.org paths  
  `trigon-mirror/src/server.rs:1181`
- **medium** — nuget_route uses the path moment verbatim, so an unparseable moment is accepted and the filter silently no-ops  
  `trigon-mirror/src/server.rs:1096`
- **low** — `normalize` deletes a UTC offset instead of applying it, and accepts the same instant written two ways with two different answers  
  `trigon-mirror/src/moment.rs:107`
- **low** — Proxy counters bump before the proxy runs, so observed() and from_transcript() disagree whenever it fails  
  `trigon-mirror/src/server.rs:1063`
- **low** — The index client follows Location to any host, with no allowlist check and one pacer/transcript record per chain  
  `trigon-mirror/src/server.rs:450`
- **low** — cargo_route never applies the withhold, so the version under test stays in the sparse index and the build dies on the guard  
  `trigon-mirror/src/server.rs:1255`
- **low** — The index client still follows redirects automatically, so index fetches skip the host allowlist the passthrough client was fixed to enforce  
  `trigon-mirror/src/server.rs:450`

### `trigon-registry`

- **high** — npm build-script name from a workflow reaches `sh -c` unquoted; the guard the heuristic rung applies to the same parameter is absent  
  `trigon-registry/src/ci/lower.rs:604`
- **high** — The project directory parsed out of the workflow's build command reaches `python3 -m build` completely unquoted  
  `trigon-registry/src/ci/lower.rs:512`
- **high** — `working-directory` is never `${{ }}`-resolved and never validated before becoming `Location.subdir` and `Claim::SubdirIs`  
  `trigon-registry/src/ci/select.rs:753`
- **medium** — `curl`/`wget` that writes a file into the working tree is classified `Network` rather than `MutatesTree`, so the recipe silently drops the fetch  
  `trigon-registry/src/ci/cmd.rs:227`
- **medium** — `lower_npm` reads `_npmVersion`/`_nodeVersion` without the `is_plain_version` gate the heuristic rung applies to the same two fields  
  `trigon-registry/src/ci/lower.rs:538`
- **medium** — `Decline::PackageManagerUnsupported` cannot fire when the pnpm/yarn command is the publish step, and the `Marker::manager` that did detect it is discarded  
  `trigon-registry/src/ci/lower.rs:285`
- **medium** — `expand_matrix` reserves the full uncapped cross product before the cap that exists to prevent it  
  `trigon-registry/src/ci/parse.rs:407`
- **medium** — `glob_matches` is an unmemoized backtracking matcher over an attacker-supplied pattern, run on the runtime thread  
  `trigon-registry/src/ci/select.rs:486`
- **medium** — Retry-After parsed unclamped: overflow panic in politeness::throttled, and a process-wide stall on a merely large value  
  `trigon-registry/src/client.rs:142`
- **medium** — npm build-shortfall check ignores source.subdir: wrong manifest, and promises compared against a differently-rooted file list  
  `trigon-registry/src/heuristic.rs:402`
- **medium** — catalog_entry uses `?` inside its page loop: one unreadable page discards the publish moment for every later page  
  `trigon-registry/src/nuget.rs:94`
- **medium** — SourceCache::checkout has no locking: concurrent lanes delete each other's in-progress checkouts  
  `trigon-registry/src/source.rs:105`
- **low** — fetch_verified enforces no size bound and checks the digest only after the whole body is written  
  `trigon-registry/src/npm.rs:446`
- **low** — Two private looks_like_a_forge implementations with lists that differ in both directions  
  `trigon-registry/src/pypi.rs:329`
- **low** — Checkout::files truncates silently and three callers use the truncated list as an existence oracle  
  `trigon-registry/src/source.rs:287`

### `trigon-api`

- **high** — setFilter deletes the cursor it was asked to set, so "next page →" cannot advance past the first 50 rows  
  `trigon-api/ui/app.js:359`
- **medium** — `/v1/artifacts/{digest}` searches only the 500 newest runs  
  `trigon-api/src/routes.rs:641`
- **medium** — `/v1/runs/{id}/diff` parses an unbounded comparison blob, anonymously, with no concurrency permit  
  `trigon-api/src/routes.rs:537`
- **medium** — JOB_POLL is never cleared on navigation, so a job page keeps polling /v1/jobs/{id}/events for the life of the tab  
  `trigon-api/ui/app.js:591`
- **low** — hunks() emits the same context line in two hunks and produces overlapping hunk ranges when changes are 4 or 5 lines apart  
  `trigon-api/src/member.rs:587`
- **low** — differing_runs over-counts by one when a trailing length difference abuts a differing run  
  `trigon-api/src/member.rs:688`
- **low** — `member_pair` discards the real refusal from `artifact_bytes` and blames the store  
  `trigon-api/src/routes.rs:343`
- **low** — /targets/… and /artifacts/… await a fetch before their first paint and get no boot island  
  `trigon-api/ui/app.js:659`
- **low** — Overlapping hex regions produce a negative "… not shown …" gap label and a dump row drawn twice  
  `trigon-api/ui/app.js:1118`
- **low** — A non-JSON error body is reported as statusText, empty over HTTP/2, so the reason a request failed is dropped  
  `trigon-api/ui/app.js:83`
- **low** — No navigation generation token: a view whose fetch resolves late paints over the view the reader navigated to  
  `trigon-api/ui/app.js:161`

### `trigon-sandbox`

- **high** — Resource ceilings and hardening flags are applied only to `podman run`, never to `podman build`, so the deps phase that executes package install scripts is unbounded  
  `trigon-sandbox/src/podman.rs:466`
- **high** — The network island and its mirror container leak on every early return after `Island::create`, including the wall-clock timeout, and the build container is never stopped  
  `trigon-sandbox/src/podman.rs:548`
- **high** — `PodmanBuild::events` accumulates every build output line in host memory and nothing ever reads it  
  `trigon-sandbox/src/podman.rs:280`
- **medium** — `render()` emits a package-manager install for `plan.system_deps` without consulting `admission()`, so a `Decision` name is installed at the default egress tier  
  `trigon-sandbox/src/dockerfile.rs:429`
- **medium** — `failing_phase` matches podman's `COPY` step announcement, so under `defer_deps` a script that was only copied is reported as the phase that failed  
  `trigon-sandbox/src/podman.rs:929`
- **medium** — The wall-clock ceiling is per podman invocation rather than per build, and `resolve_host_gateway` has no timeout at all  
  `trigon-sandbox/src/podman.rs:271`
- **low** — The shared fetch cache is bind-mounted `:Z`, so concurrent mirror containers relabel it out from under each other on SELinux hosts  
  `trigon-sandbox/src/network.rs:164`
- **low** — `StoreLock::shared()` spins on `std::thread::sleep` for up to five seconds inside an async task  
  `trigon-sandbox/src/store_lock.rs:118`

### `trigon-ai`

- **high** — Copilot's stdout/stderr pipes are never drained until the child exits, so a large answer deadlocks until the 600s deadline  
  `trigon-ai/src/copilot.rs:183`
- **high** — OpenAI-compatible provider never inspects `finish_reason`, so truncation is misreported as `Malformed` (or silently accepted) while Anthropic raises `Truncated`  
  `trigon-ai/src/http.rs:307`
- **medium** — `strip_fence` only strips a fence at byte 0, so a "prose, then ```yaml block```" answer is discarded  
  `trigon-ai/src/builder.rs:250`
- **low** — Copilot's injection fence encloses our own prelude, tool vocabulary and operator constraints, labelling them as package-written text  
  `trigon-ai/src/copilot.rs:92`
- **low** — The whole prompt is one argv entry, so a repository with large manifests makes the Copilot provider fail to spawn  
  `trigon-ai/src/copilot.rs:154`
- **low** — The Copilot agent's working directory is a fixed shared-temp path, never emptied and created through symlinks  
  `trigon-ai/src/copilot.rs:70`
- **low** — A replayed transcript with a short `prompt_sha256` panics instead of reporting a mismatch  
  `trigon-ai/src/transcript.rs:238`

### `trigon-store`

- **high** — A dead job permanently blocks every later enqueue of that target, and POST /v1/runs reports it as already answered  
  `trigon-store/src/queue.rs:243`
- **high** — request_rebuild's INSERT has no ON CONFLICT although enqueue's does, so a double-click returns 500 on Postgres  
  `trigon-store/src/queue.rs:954`
- **medium** — Daily quota is a non-locking COUNT under READ COMMITTED, so a concurrent burst overruns it on Postgres  
  `trigon-store/src/queue.rs:946`
- **medium** — An expired lease is not counted as a failure, so max_failures cannot bound a job that kills its worker  
  `trigon-store/src/queue.rs:301`
- **medium** — Daily quota is a `SELECT COUNT(*)` then an `INSERT` in one READ COMMITTED transaction  
  `trigon-store/src/queue.rs:919`
- **medium** — `POST /v1/runs` races itself into a unique-constraint violation reported as "the queue could not be reached"  
  `trigon-store/src/queue.rs:955`

### `trigon-core`

- **medium** — `FailureSignature::subject` is unbounded while `evidence` is clipped to 300, so build output controls the size of the string embedded in the repair prompt and the run record  
  `trigon-core/src/failure.rs:1354`
- **medium** — Two divergent `strip_controls` implementations; the logs.rs copy breaks on `is_ascii_alphabetic` instead of the CSI final-byte range and eats real text  
  `trigon-core/src/logs.rs:312`
- **low** — `normalize_subject` unconditionally strips every directory component, so `env/cannot-write-path` merges distinct paths into one cluster — contradicting the rule's own comment  
  `trigon-core/src/failure.rs:1434`
- **low** — `normalize_subject` strips only `==`, so `env/needs-the-package-under-test` keys one cluster per version specifier  
  `trigon-core/src/failure.rs:1435`
- **low** — The JCS canonicalizer emits integers outside ±2^53 verbatim instead of in RFC 8785 ES6 `Number::toString` form  
  `trigon-core/src/jcs.rs:57`

### `trigon-archive`

- **high** — Tar long names, link targets and PAX values are written through String::from_utf8_lossy, so two archives with different non-UTF-8 long member names serialize to byte-identical stabilized output  
  `trigon-archive/src/tar.rs:252`
- **medium** — A legal multi-member gzip stream is rejected as "malformed gzip: crc32 mismatch", accusing a well-formed artifact of corruption  
  `trigon-archive/src/gzip.rs:110`
- **medium** — flatten copies every member body into a fresh heap Vec, so serialize peaks at roughly 4x the payload and 2x the stated expansion ceiling  
  `trigon-archive/src/parse.rs:336`
- **low** — A STORED zip member's declared uncompressed size is never checked against its body, so Entry::meta.size is an attacker-chosen number unrelated to the bytes  
  `trigon-archive/src/zip.rs:348`

### `trigon-attest`

- **high** — Archived-set re-derivation reports every `normalized` claim as refuted  
  `trigon-attest/src/verify.rs:199`
- **low** — Non-ASCII `stabilizerSet.digest.sha256` panics the verifier on a byte slice  
  `trigon-attest/src/verify.rs:137`

### `trigon-stabilize`

- **medium** — npm-install-fields drops any line whose first token is a dropped key, at any nesting depth  
  `trigon-stabilize/src/passes.rs:381`
- **low** — npm-install-fields rewrites line endings only on the side that carried a dropped key  
  `trigon-stabilize/src/passes.rs:388`

### `trigon-compare`

- **medium** — A nested single-member gzip is keyed by its FNAME header, producing false member-only codes and membership notes  
  `trigon-compare/src/diff.rs:167`

### `trigon-engine`

- **high** — The confirming second attempt is enqueued outside the outbox transaction, so a crash between finish and confirm withholds that target for ever  
  `trigon-engine/src/lib.rs:238`
