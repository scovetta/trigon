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

## B4. Test coverage worth the name

Coverage measured rather than asserted. The suite is large and grew by accretion; what matters is
whether the parts that would be expensive to get wrong are covered — the writers, the guard, the
provenance cap, the egress boundary, the attestation round-trip — and whether the corpora still
exercise what they claim to.

**Done when:** a coverage number exists per crate, the judgement half is at a stated bar, and every
gap that is deliberate is named as deliberate.

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

Not a review of the last change: a sweep of the whole thing, looking for the classes this project
keeps producing — configuration that looks applied and is not, an error that reads as the package's
fault when it is ours, a silent zero where there is no data, a cache key that is not a function of
everything it depends on.

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

**Done when:** two concurrent runs on one machine cannot fail each other, by a mechanism that does
not depend on timing — a store lock, per-run storage, or not removing images from the build path at
all.

## B7. ~~The image build is outside the egress boundary at `mirror-only`~~ — closed

Closed, and recorded in [`16`](16-findings.md) §3.13. The image build takes `--network none` at
every enforced tier, the source arrives as a checkout fetched on the host and copied in, and the
setup phase verifies the base image rather than installing into it. Proven by a probe that printed
`REACHED-SOURCE` before and `blocked-SOURCE` after.

**Its residue, which is a different claim:** the mirror's allowlists bound *which* hosts a build can
reach through it, never *what* those hosts serve. `registry.npmjs.org` will serve any package
anybody published, so an attacker who controls one package can publish a second one holding their
payload and fetch it through the artifact route at any path. The guard is the control for that, not
the tier. And there is still no network transcript, so no run is attestable at full trust at any
tier.

**Done when:** a Tier-1 network transcript records host, path, method, response digest and byte
count for everything crossing the mirror, and `attestable` can become true for a run that has one.

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

Two things they share that the current code does not have: a version algebra each (`semver` is
Cargo-flavoured; RubyGems and NuGet have no usable Rust crate, so both are hand-rolled), and a
stabilizer profile each.

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
