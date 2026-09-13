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

## B2. A threat model for Trigon

The implicit security contract between this project and the people who depend on its verdicts:
what it assumes, what it guarantees, what it explicitly does not, and which misuses are out of
scope. [`12`](12-security.md) is a controls document and is not this.

The interesting questions are the ones a consumer of an attestation has to answer: what does a
signed `equivalence` predicate actually claim, what would have to be true for it to be wrong, and
what is the reader expected to check themselves.

**Done when:** `docs/threat-model.md` exists as prose with a machine-readable companion, every
non-trivial claim is marked as documented / maintainer-stated / inferred, and it routes a corpus of
real findings to exactly one disposition each.

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
