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
| **Judgement half** — `core`, `archive`, `stabilize`, `compare`, `attest` | **89.3%** | **89.3%** |
| `trigon-mirror` | 73.6% | 90.7% |
| Workspace | 69.6% | 72.8% |

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

## B6. ~~Two Trigon runs on one machine can disturb each other's container store~~ — closed

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
