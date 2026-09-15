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

## B6. Two Trigon runs on one machine can disturb each other's container store

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

**Done when:** two concurrent runs on one machine cannot fail each other, by a mechanism that does
not depend on timing — a store lock, per-run storage, or not removing images from the build path at
all — and `--concurrency 4` over the PyPI smoke corpus produces the same outcome for every target as
`--concurrency 1`.

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

**Outstanding, each with a probe that demonstrates it:**

- `twine check` matches as a publish marker, so on the standard check-then-upload shape the wrong
  step becomes "the publish step".
- `actions/download-artifact` in the *build* job is grouped with cache and publish markers as
  "provably does not matter" — but a build whose inputs are bytes fetched from an earlier job is
  the forged-attestation shape of [`12`](12-security.md) §1.1, not an irrelevance.
- `download-artifact`'s `pattern:` is compared as a literal name, so every publish job that fans in
  wheels with a glob loses its build edge.
- `sed` is in `cmd::INCIDENTAL`, so `sed -i` rewriting the tree immediately before the build
  disappears and the candidate comes out `Strong`.
- Two decline messages assert things that are not true of the run that produced them
  (`NoQualifyingJob` where a job qualified but its build edge could not be followed;
  `NoToolForBuildCommand` where a build *was* recognised).
- **Confidence inverts around `ubuntu-latest`**: failing to resolve which release the label meant
  yields a *more* confident candidate than resolving it. Not knowing should never raise confidence.
- Workflow- and job-level `env:` is parsed and never read, with no note that it was dropped.
- The publish job's own `uses:` steps are never classified when it is not the build job.

**Done when:** every item above has a test that fails without the fix, both verification angles come
back `sound`, and only then does `ladder()` in `crates/trigon/src/main.rs` call it — between the
heuristic and the model, per [`01`](01-architecture.md) §3.

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
