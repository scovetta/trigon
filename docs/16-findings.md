# 16. What building it changed

The rest of `docs/` was written before any code existed. This is what implementing it taught, with
the measurements, and it is deliberately separate: the design documents describe the system as it is
meant to be, and rewriting them to match every discovery would erase the record of which beliefs
were wrong and how they were found out.

Three kinds of entry appear here. A **correction** is a place the design said something false. A
**gap** is something it did not anticipate at all. A **measurement** is a number that replaces an
estimate. Where a design document has been amended, it says so.

---

## 1. The bug class that dominated

Almost every real defect found during M1 and M2 had the same shape:

> **Configuration that looks applied and is not, with the failure surfacing somewhere that
> implicates the package instead of us.**

Six instances, none of which the design anticipated:

| What | How it looked | What it was |
|---|---|---|
| `PIP_TRUSTED_HOST` absent | builds resolved against today's index while every log line said "pinned" | pip warns once about an untrusted plain-HTTP index, then resolves as though none were configured |
| `export` in the deps phase | the mirror pinned dependency installation and not the build | phases are separate scripts; the variable is gone by the next one |
| tool-level `needs` | `env/toolchain-crashed` on two npm targets | a tool whose steps all skip still contributes its needs, so Debian's Node came in and a pinned Node 10 loaded its modules and aborted |
| `reqwest`'s `gzip` feature | npm reported corrupt tarballs | the proxy transparently gunzipped artifacts, and the guard hashed the decompressed bytes |
| `build.log` in the collect directory | 26 targets reported `error:upstream` | the artifact collector picked the newest file, which was the log |
| `npm` calling `setuid` | a build that worked at image-build time failed at run time | our run-time isolation denies it, and npm crashes inside its own error handler |

The common property is not that each was subtle. It is that **each failed silently in a direction
that blamed something else.** Four of the six produced a number that looked like a package problem:
a low reproduction rate, a build failure, a corrupt artifact, an upstream error.

Two lessons, both now reflected in the code:

**Anything that claims to be applied should be observable.** The mirror's request counter is what
eventually exposed the pip finding — `0 index request(s)` had been printed on every PyPI run for
weeks and reads exactly like a build that happened not to need anything. A counter nobody checks is
better than no counter, but a build that *asserts* its pin took effect would have caught it on the
first run. This is unbuilt and it is the most valuable thing on the list.

**The taxonomy has to be able to blame us.** `trigon/client-corrupted-download` exists so that a
corrupt download is counted against us rather than the package. Before it, the same symptom was
charged to `has-flag` in the reproduction rate. Its first name said `mirror`, which sent three
investigations to the wrong component before [§3.26](#326-the-corruption-was-named-after-the-wrong-component)
found npm doing it — a rule that blames us has to be right about *which* part of us. `Fault::Bug` and `Fault::Infra` are not decoration: without them a reproduction
rate silently becomes a measure of our own reliability wearing the costume of a claim about
packages.

---

## 2. Measured rates, and what moved them

All figures on the M1 smoke corpora at `--egress open`, against the baseline established before any
of the work below.

One measurement note, because it changes how much the numbers are worth. The npm figures come from a
full sweep. The final PyPI figure comes from **re-comparing the stored artifact pairs** from the
preceding sweep with the new stabilizer in place, rather than from rebuilding all seventeen targets
again: the comparison is the real one and runs over the same bytes, but the builds are not fresh, so
it does not re-test build-time nondeterminism. The 73% figure that precedes it is a full sweep.

### 2.1 PyPI: 33% → 80%

| | reproduce | reach comparison |
|---|---|---|
| baseline | 5 of 15 (33%) | 15 of 17 |
| after three fixes (full sweep) | 11 of 15 (73%) | 15 of 17 |
| after `wheel-metadata-eol` (re-comparison) | 12 of 15 (80%) | 15 of 17 |

Six targets flipped, no regressions. Three fixes, in the order they were found, each exposed by the
one before it:

1. **Pin the build backend the wheel names.** The heuristic said "nothing in PyPI's metadata says
   what the build needed", which is true of the metadata and false of the artifact: every wheel
   carries `Generator:` in its own `.dist-info/WHEEL`. Reading it is an algorithm, not a search —
   the same argument [`07`](07-ai.md) §2.1 makes for tree-hash scoring over prompting. Nine of ten
   divergences were confined to `WHEEL`, `METADATA` and the `RECORD` that follows from them, with
   every source file byte-identical.

2. **Make the mirror actually apply.** See §1. The backend pin was the probe that found it: the
   first thing to ask the mirror for a package *after* the index was configured.

3. **A pin is a constraint, not an install.** The environment that matters is the isolated one a
   PEP 517 frontend builds. Pre-installing the backend does nothing for it, and disabling isolation
   to compensate strands every other declared build requirement — `attrs` needs `hatch-vcs` and
   `hatch-fancy-pypi-readme` and stops with "Unmet dependencies". `PIP_CONSTRAINT` pins a version
   inside an environment somebody else populates.

A fourth, `wheel-metadata-eol`, flipped one more (§4).

### 2.2 npm: 92% → 93%, and 13 of 20 → 15 of 20

The rate barely moved because it was already high; what moved was how many targets *reached* a
comparison. Removing Debian's `npm` and setting `npm_config_unsafe_perm` took two targets from
`build-failed` to reproducing.

### 2.3 What the remaining failures are

Every failure in both corpora is now named, and the clusters are the diagnosis:

| cluster | what to do |
|---|---|
| `env/missing-shared-library:libatomic.so.1` | fixed: declared as a dependency, with the distro map handling Debian's soname suffix |
| `git/commit-not-in-repo` | nothing to repair — npm's recorded `gitHead` was force-pushed away |
| `trigon/client-corrupted-download` | fixed: npm 7.0–8.2 corrupts concurrent fetches; that range is serialized ([§3.26](#326-the-corruption-was-named-after-the-wrong-component)) |
| `iniconfig` divergence | setuptools-scm embeds the git commit; the publisher built without git metadata |
| `py-cpuinfo` divergence | `bdist_wheel` names the *wheel* package, so setuptools' version is not recorded anywhere |

The last two are limits of the evidence rather than bugs. They are worth stating as such: a system
that reports them as failures without saying why teaches its operators to ignore failures.

---

## 3. Corrections to the design

### 3.1 `Signer` and `LlmProvider` are synchronous

[`09`](09-attestations.md) §3 specifies `#[async_trait] Signer` and [`07`](07-ai.md) §7 specifies the
same for `LlmProvider`. Both are synchronous in the implementation, for one reason each:

- The **verifier build** links `trigon-attest` and must contain no async runtime. That is the claim
  `xtask policy` enforces and the one a sceptic can check with `cargo tree`. An async method would
  drag `tokio` across the judgement line for the benefit of signers that do not exist yet.
- The **replay provider** makes no call at all, and a test harness should not have to hold a runtime
  to use it. A synchronous trait is callable from an async context by whoever owns the runtime; the
  reverse needs an executor everywhere.

Network implementations block in their own client or live behind an async façade in a crate below
the line. Both documents now record the deviation.

### 3.2 Internal tagging plus `serde_path_to_error` does not work

[`04`](04-strategies.md) §2.2 specifies parsing a strategy by internal tag and reporting errors
through `serde_path_to_error`. Internal tagging buffers through serde's `Content`, which loses the
path — the two are incompatible. The parser reads `schema` and `kind` manually and then deserializes
the payload directly, which preserves the path and is what the repair loop depends on.

### 3.3 A tool's `needs` are collected even when its steps are skipped

[`04`](04-strategies.md) treats `needs` as "what this tool requires". The implementation collects
tool-level `needs` whether or not any step survives its condition, which made a conditional tool
contribute a system package to every build that referenced it. Step-level `needs` behave as
documented. The fix is to put a need on the step that uses it; the two npm tools that got this wrong
now do.

### 3.4 `trigon-store` is not a database yet

[`10`](10-scale.md) §4 specifies Postgres tables for `runs`, `verdicts` and `rollups`. None of them
is needed to sign a statement, and building a schema before there is a fleet to put in it means
maintaining one whose shape is a guess. M2's store is the content-addressed layout
[`09`](09-attestations.md) §7 already specifies — blobs, run records, attestations — over
`object_store`, so cloud backends are a cargo feature rather than code. The tables arrive with M4.

### 3.5 The capability taxonomy was missing the label the Builder is most for

[`07`](07-ai.md) §6.2 lists `trivial-deterministic`, `needs-source-discovery`, the four
`needs-repair-*` labels, and `known-unreproducible`. Labelling the two smoke corpora turned up a
target none of them fits: `escalade 3.2.0` publishes `dist/index.js` and `dist/index.mjs`, which
`npm pack` alone never produces. Nothing is being *repaired* — the first attempt is not wrong, it is
absent. A recipe has to be inferred from the repository or its CI.

Filing it under the nearest `needs-repair-*` label would have hidden the most common thing the
Builder actually does, and the whole point of labelling by capability is that a model firing on the
wrong class is visible. The taxonomy gains `needs-build-inference`, between source discovery and
repair.

### 3.6 `mirror-only` egress has to carry the toolchain too

[`08`](08-execution.md) describes the tiers as a statement about *dependency* traffic, and the tools
were written to match: `npm/install-node` fetched `https://nodejs.org/dist/...` directly, with a
comment noting that this fails at `mirror-only`. It does, and it fails late. Rootless `podman build`
cannot join a named network, so at that tier the deps phase is deferred into the container — inside
the island, where the mirror is the only reachable host. The image builds, the source checks out,
and then the first phase that needs the network dies at `Network is unreachable` in a way that reads
as a broken sandbox rather than as a strategy naming a host it cannot reach.

The tier is not wrong; the seam was missing. The mirror now serves `/-toolchain/<host>/<path>`
against a compiled-in allowlist (`nodejs.org`, `unofficial-builds.nodejs.org`), and templates write
the URL through a `toolchain_url()` function that yields the upstream URL when no mirror is
configured. No time filter: a toolchain URL names its exact version, so the bytes are a function of
the URL and there is nothing for a date to remove. The guard still runs on the body, because "the
artifact arrived dressed as a toolchain" is exactly the route it exists to close.

The allowlist is the load-bearing part and is deliberately compiled in. At `mirror-only` the mirror
is the build's only route out, so any host reachable through it is a host a strategy can be told to
download an executable from; a wildcard here would quietly restore `open` egress under a different
path. Matching is exact rather than by suffix — the obvious `ends_with` rule accepts
`evil-nodejs.org`.

Two more came out of running it to the end, both from the same root cause — a phase that used to run
as an image layer now runs inside the container:

- **`tar` cannot preserve ownership there.** The official Node tarballs record uid/gid 500. As an
  image layer the user namespace maps a wide range and tar is happy; inside the container the range
  is narrow, so tar fails on every entry and exits non-zero. The phase after a 40-second download
  dies with 700 lines of `Cannot change ownership`, and the fix is `--no-same-owner` — file
  ownership inside a toolchain is not part of what we reproduce.
- **The mirror image goes stale silently.** It is compiled from this workspace, so an image built
  before a mirror change serves the old routes. What the operator sees is a `400` from inside the
  island and a strategy that looks wrong; what it is, is an old binary. `rebuild` now compares a
  digest of `trigon-mirror`'s source against a label on the image and warns before the build starts.
  Scoped to that one crate deliberately: a digest over the workspace would fire on every commit, and
  a warning that always fires is not a warning.

Beside them, a message that was actively misleading: a run at `mirror-only` reported *"this runner
enforces no mirror"* because the local runner is never attestable at full trust. Two different
reasons — no boundary, versus a boundary with no network transcript — and only the second is true
there.

With all of it in place, `left-pad 1.3.0` reproduces `normalized` at `mirror-only` on a stock Debian
image.

### 3.7 The Builder needs the repository, and the repository was only ever inside the container

[`07`](07-ai.md) §4 has the Builder answering from a file list and the manifests. Nothing in the run
path could supply either: the heuristic rungs answer from registry metadata alone, and the only
checkout that exists is the one the build container makes and takes away with it. A model rung
without the repository can do nothing but guess, which is strictly worse than the heuristic it sits
behind — so the rung needed a pinned checkout on the host before it needed a provider.

That moves a `git fetch` from inside the island to the host, over a URL that came from package
metadata. The controls are in `trigon-registry/src/source.rs` and each exists for a specific reason:

- **`https` only, and no leading `-`.** git reads a leading dash as an option wherever it appears,
  so `--upload-pack=…` in a repository field is a command on the operator's machine. The scheme
  restriction rules out `ssh` (a credential agent), `file` (the local filesystem) and `ext` (an
  arbitrary command).
- **A full commit id, never a ref.** A rung that reads "the repository at `main`" reads whatever
  `main` says today, and a file that arrived after the release would be read as evidence about it.
- **`GIT_ALLOW_PROTOCOL`,** which holds where the URL check cannot see: a redirect, a submodule, an
  `insteadOf` that survived. It is load-bearing rather than decorative — it refused the test fixture
  until the trusted case said otherwise.
- **A local path only where the *operator* named it,** never where a package did. `file://` is not
  dangerous; `file://` chosen by the thing under test is. That distinction is a constructor
  (`trusting_local_paths`) rather than a guess inside the check.

The rung itself declines more often than it answers: no repository, no commit, an answer that does
not parse — the ladder moves on and the target ends as `no-strategy`, which is a statement about the
run rather than an error of ours in a sweep's denominator. It is last on the ladder, it runs only
when `--model` names a provider, and the candidate it returns is `Weak` whatever the model said
about its own confidence.

### 3.8 The Copilot CLI runs shell commands in non-interactive mode, unasked

Adding GitHub Copilot as a provider turned up something worth stating plainly, because it changes
what a provider *is*. Every other provider here is a function from a prompt to a string. Copilot is
an agent with `bash`, `apply_patch` and `rg` on the machine that invokes it — and in `-p`
non-interactive mode it uses them without asking. Measured, not assumed: asked to run `id` with no
permission flags at all, it did, and printed the operator's uid and group list.

The prompt the Builder sends is full of text a package controls: its file names, its manifests, its
build log. [`12`](12-security.md) §4 already calls that the highest-risk injection channel in the
system. Pointing it at a shell on the verifying machine turns a README into a command.

`--available-tools` is the control, and it is an allowlist: everything not named is filtered out
before the model sees it, so it does not rot when a new tool ships. Two details are easy to get
wrong and both were found by testing:

- **An empty value means "no filter", not "no tools".** With `--available-tools=` the model called
  `bash` and the call ran. The flag has to name something; the provider names the most inert tool on
  offer, which fetches Copilot's own documentation.
- **`--deny-tool='*'` is not a thing.** It is rejected as an invalid rule, which is the good
  failure; a denylist of the seventeen current tools would have been the bad one.

Three more flags are part of the posture rather than tidiness: `--no-custom-instructions`, because
`AGENTS.md` is loaded from the working directory and a package's checkout can contain one — that is
instruction injection with no prompt required; `--no-remote --no-remote-export`, because the default
exports the session, and therefore somebody else's package, to GitHub's web and mobile surfaces; and
`--no-auto-update`, because a provider that replaces its own binary part-way through a sweep makes
the sweep's results unattributable. The CLI also runs in an empty directory, so there is nothing
around it to read.

What cannot be fixed from here: `-p` takes one string, so there is no system-role channel. The
operator's instructions and the package's data travel in the same text, which is precisely the
separation §4 asks for. The provider uses the best substitute available — the package-derived half
is wrapped in a nonce-delimited block, the nonce derived from the prompt rather than a clock so
replay and caching still work — and the code says it is a substitute. Where the choice exists,
prefer a provider with a real system message.

We talk to the CLI rather than to `github-copilot-sdk`, which is itself a JSON-RPC client that
spawns this same binary. Three reasons: the crate requires Rust 1.94 and the workspace is on 1.85;
it embeds a CLI executable in the dependency tree; and this codebase already reaches `podman` and
`git` the same way.

### 3.9 The repair loop, and two things running it found

Wiring `RepairLoop` into `rebuild` turns the build into a loop: a failure the build itself reported
carries a signature, and where `--model` names a provider the Builder is asked for a new recipe with
the previous one, that signature, and the **compressed** log — compressed at the call site rather
than inside the provider, so the caller who chose the budget can see what it is spending.

Driven against a deliberately broken recipe, the loop did what `docs/07-ai.md` §4.5 says it should:
two attempts, then *"two attempts failed the same way, so the model is restating rather than
searching"* — stopping four iterations before the cap. Which stop rule fired is printed, because a
budget that is too small, a gap in our rule table, and admission control working as intended are
three different things to do about it.

Two bugs, both found only by running it:

- **The digest pin was being sent as the model name.** Pinning an Ollama tag to its digest is right
  for the transcript and wrong on the wire: `qwen2.5:0.5b@a8b0c5157701` comes back
  `invalid model name`, which reads as a broken provider rather than as us having appended
  something. The digest is stripped on the way out and put back on the way in.
- **`npx: not found` did not classify.** The rule table knew bash's `command not found`; `/bin/sh`
  on a Debian image is dash, which says `npx: not found`. Every missing tool under dash was
  clustering as `unknown` — the bucket that hides our own bugs.

### 3.10 Divergence repair, and a false accusation it found

The loop now also triggers on a **divergence** — the build succeeded and produced something that is
not what was published. It is the more interesting half and it is a genuinely different question, so
it is a separate field on the task and a separate prompt rather than a build failure with a
synthetic code. A model shown a recipe and told to fix it looks for the error; here there is none,
and saying so explicitly is the difference between "add a missing dependency" and "this package has
a build step". The prompt also states the artifact-guard rule where the model can act on it rather
than only enforcing it afterwards: *do not add steps that fetch the published artifact*.

Admission control is the same, over a signature built from the difference **codes** rather than the
file names — `docs/07-ai.md` §4.2 keys repair caching on a normalized signature, and a key carrying
`dist/index.js` matches one package while `member-only-in-reference` is a class that recurs across
thousands. The brief the model reads does name the files, because that is the evidence.

Run against `escalade 3.2.0`, the corpus's one `needs-build-inference` target, it fired on
`divergence:member-only-in-ours,member-only-in-reference` — and that key exposed a bug in
`signature()` worth more than the feature:

> **Members were keyed by `Entry::ordinal`, which is the entry's position in the archive, not the
> occurrence of that path.** The comment said occurrence; the code said position. So whenever the
> two archives differ in length — which is every divergence with an added or removed member — every
> member after the first difference looked unmatched. `escalade`'s `package.json` was reported as
> present *only in the rebuild* **and** *only in the published artifact*, while the member diff
> correctly called it identical.

These codes go into the signed divergence predicate, which is a public claim about somebody else's
package; a false one is the error class [`09`](09-attestations.md) §10.3 gates tightest. Keyed by
occurrence, as `diff::report` already did, the same comparison names exactly the seven files that
really are only in the published artifact.

### 3.11 The first promoted rule, and what investigating it corrected

The flywheel's other half: a repair turned into a rule that holds corpus-wide. The target was
`escalade 3.2.0`, and investigating it properly corrected three things I had believed.

**The registry knows about the build, and the resolver was throwing it away.** An npm version
document carries `scripts`; `NpmRegistry::resolve` read four fields and discarded the rest. So the
one deterministic signal that separates "this package publishes what it builds" from "this package
publishes what it commits" was never available to any rung. It is now a `Claim::UnrunScript`, and
the predicate behind it is narrow on purpose: a `build` script, no `prepare`/`prepack`/`prepublish`/
`prepublishOnly` declared **at all** — so the claim holds under every npm version and there is no
lifecycle boundary to get wrong — no install hooks, and a command whose first token the package
itself declares as a dependency, so nothing acting on the claim opens a socket the dependency phase
did not.

**`npm pack`'s lifecycle is version-dependent, and the npm 6 documentation is wrong.** Measured
across eleven majors: npm ≤3 runs only `prepublish`; npm 4 runs `prepublish` and `prepare`; npm 5–6
run those plus `prepack` and `postpack`; npm ≥7 run `prepack`, `prepare` and `postpack` and never
`prepublish`. The npm 6 docs list only `prepack` and `postpack` for pack, and npm 6.14.18
demonstrably also runs the other two. A table taken from the documentation would misread every
package published by npm 5 or 6 — which the corpus contains.

**A rule that runs the declared build is not safe on its own.** `axios` commits its `dist/`,
byte-identical to what it publishes, and its build begins `gulp clear` — which empties that
directory and regenerates it under whatever its floating ranges resolve to today. Running the build
there manufactures the divergence it was meant to fix. So the rule has a second condition, read from
the repository rather than from the artifact: the manifest has to promise a file the repository does
not contain. A package that commits its output has an empty shortfall and is left exactly as it was.

Read from the repository and never from the published artifact, deliberately. A shortfall computed
as "published members minus repository tree" gives the same seven paths for escalade and is fitting
the recipe to the answer key — the reasoning `corpora/m1-npm-smoke.labels.json` already rules out
for labels.

Measured on the npm smoke corpus: the claim fires on **exactly one of twenty** targets. The other
nineteen declare no build script, never reach the second condition, never clone, and render an
unchanged strategy. escalade goes from seven missing members to one.

**And the seventh needed a definition, which is what definitions are for.** `bundt 1.1.1` hardcodes
the `.d.ts` extension, so `sync/index.d.mts` is not a file any version of it can emit. The
publisher's recipe is `build.ts` at the repository root — a script no `package.json` entry invokes,
which runs `npm run build` and copies four declaration files out of `src/`. We do not run it: it is
TypeScript and the pinned Node 20.10.0 cannot execute a `.ts` file. `definitions/` writes those four
copies out verbatim and in its order, rather than the one that happens to close the divergence.
`escalade 3.2.0` then reproduces **exact** — identical raw digests, eleven of eleven members.

That split is the design's governance model working rather than a compromise: a rule that holds
across a class, and a definition for the long tail, each with its reasoning written where somebody
will read it.

**What it deliberately leaves unfixed**, from the same investigation: build scripts that are shell
pipelines (roughly 15% of popular npm — `vite`, `dayjs`, `tailwindcss`), packages whose build tool
is not one of their own dependencies (`chokidar` builds with `tsc`, which comes from `typescript`),
`prepublishOnly` builds that `npm publish` runs and `npm pack` never does, and packages pinned to
npm ≤4 that declare a hook that vintage does not run. Those stay the Builder's job. Class (c) — a
build not reachable from a pack-run hook — is around 46% of `corpora/candidates.jsonl` and 16–33% of
a dependency-weighted install closure, so what is left unfixed is most of the class; what is fixed
is the part that can be fixed without guessing.

One thing the corpus lost: it no longer contains a target that defeats a deterministic read. The
`needs-build-inference` rate will now read as a Builder win it is not, and the corpus wants a target
that genuinely requires one.

### 3.12 What an adversarial sweep of the code found

Ten lenses over the whole workspace, every finding refuted by two independent skeptics before it
counted. Twenty-one survived; thirteen were high. Three of them were controls this design rests on
not working, and all three had the same shape: **a control that fails open, and reports success
while doing it.**

**The artifact guard never fired at `mirror-only`.** `Island::guard_trips` read the mirror
container's *stdout*; the mirror writes its trip through `tracing`, which writes to *stderr*. The
single most important control in the system — the one that makes a build downloading its own
published artifact `Void` rather than a perfect reproduction — returned an empty list on the only
tier that enforces it, and an unreadable log returned the same empty list as a quiet one. Three
lenses found it independently, which is itself the finding: it was reachable from the subprocess
surface, from the guard, and from "absent read as zero".

**A symlink in the output directory made any host file the rebuilt artifact.** The collector used
`Path::is_file`, which follows links. The published artifact sits two levels above the output
directory under a name the package knows, so `ln -s ../../evil-1.2.3.tgz /out/zzz.tgz` hands back
the published bytes, compares them against themselves, and signs `Exact`. No network needed — this
is `docs/12-security.md` §1.1 reached with one symlink. Both collectors now take the type without
following the link.

**The image build was outside the egress boundary at every tier.** `podman build` was invoked with
no network flag, so setup, source, and deps-unless-deferred ran with ordinary networking whatever
tier was asked for — and the run was recorded as enforced. `deny-all` is now closed with
`--network none`; `mirror-only` cannot be closed the same way, and is written up as B7.

Two more worth naming because they are the project's own recurring shapes:

- **The output directory was not cleared before the first attempt**, so a `--work` directory reused
  across targets could hand the *previous* run's artifact to the comparison. `newest_file` takes the
  last path in sort order, which has nothing to do with which run produced it.
- **`attestable` was derived from the `--egress` flag rather than from the runner**, so a local
  podman run — which records no network transcript and is never attestable at full trust — was
  stamped `attestable: true` in the store, and the CLI told the operator "the egress boundary held"
  for a run three of whose phases were outside it.

The parser findings were their own cluster, and they were closed the next day — see the commit
`bound what an archive can expand to, and stop an offset wrapping`. Every offset read now goes
through `checked_add`, and every expansion limit is enforced against what decompression *produces*
rather than against a size the input declares. Three tests hold the line:
`an_offset_that_wraps_is_a_short_read_and_not_a_panic`,
`a_gzip_bomb_is_refused_at_the_limit_rather_than_inflated`, and
`a_zip_member_that_lies_about_its_size_is_refused`.

**This paragraph said "not yet fixed" for a day after they were fixed, and that is the finding worth
keeping.** `docs/threat-model.md` was written from this document and inherited the stale claim as a
*security-critical disclaimer* — D1, saying Trigon does not bound what decompression produces, when
it does. An under-claim is safer than an over-claim, but not harmless: a disclaimer routes a matching
report to `BY-DESIGN: property-disclaimed` and closes it, so a real unbounded-inflate report would
have been dismissed by citing a hole that no longer existed.

The backtest did not catch it, and could not have. Two of its thirty-eight corpus items were drawn
from *this paragraph*, so they asserted exactly what the model asserted and agreed with it. **A
backtest corpus derived from the documents under test can only confirm their errors.** The corpus
needs at least one leg that comes from the code — a claim checked by running something — and this
one did not have it.

Thirty findings were refuted by the verification pass, which is the part worth keeping: the same
structure that surfaced the guard bug also threw away half of what was claimed.

### 3.13 Closing the tier we recommend, and the larger hole found while closing it

B7 was that the image build had no network flag at `mirror-only`, so setup and source — both image
layers — ran with ordinary networking at the tier the README recommends. Proven rather than argued:
a probe in the source phase printed `REACHED-SOURCE` against 1.1.1.1:443, and prints `blocked-SOURCE`
after.

**The larger hole was `/-artifact/`.** The route had no host allowlist at all, while `/-toolchain/`
had one, and it sits before the credential check so it needed none. Measured:
`GET /-artifact/npm/<moment>/example.com/` returned **200 with example.com's home page**. At
`mirror-only` the mirror is the build's only route out, so that made the boundary a general HTTP
proxy to the internet wearing the name of a control. It now carries the same compiled-in exact-match
allowlist the toolchain route has, holding the three hosts this mirror itself rewrites index URLs
into.

**Why not proxy git.** The obvious fix was to teach the mirror to proxy a clone so the source phase
could be deferred into the island like deps. It works — a 217-line proxy cloned from GitHub, GitLab
and Codeberg — and it was the wrong change. It would have turned on only at `GitAndMirror`, making
`mirror-only` unbuildable for every strategy that checks out source and moving everyone to a *wider*
tier; it changes `strategy_digest` for every such strategy, re-running every cached verdict; and it
puts ten correctness rules in the build's only route out, one of which is the same class as the gzip
bug in §1 — git gzips an upload-pack body above 1024 bytes, so a proxy that mishandles it passes a
`left-pad` smoke test and fails on every real repository.

**What was done instead.** The pinned checkout is an input, not a fetch. At every tier but `open`
the host fetches the commit with the `SourceCache` that already existed and copies it into the build
context; the strategy renders with `has_repo`, so `git-checkout` collapses to the
`git checkout --force <sha>` that verifies the copy landed on the right commit. The strategy digest
is unchanged — `has_repo` drops a line from a rendered script and is not part of what is hashed — so
no cached verdict re-runs. `podman build` then takes `--network none` at every enforced tier.

**The setup phase verifies instead of installing.** With no network there is no `apt-get`, and the
first design refused any strategy declaring a package before the run started. That was wrong for a
reason worth keeping: a pre-flight refusal cannot know what a base image contains, so it refuses
even when the image carries everything. Every package manager can answer "is this installed" from
its own on-disk database, so at an enforced tier the setup phase becomes that check, names the
packages that are actually missing, and prints the `trigon base-image` line that fixes it.
`command -v` would not do — `ca-certificates` and `libatomic1` provide no binary.

`left-pad 1.3.0` reproduces `normalized` at `mirror-only` against a base image built by
`trigon base-image`, with every phase inside the boundary.

**What still escapes, stated because a tier must not claim more than it enforces:** the mirror will
still GET from five allowlisted hosts, which serve whatever is published on them — the tier bounds
which hosts, never what they serve, and the artifact guard is the control for that. The artifact
route applies no time filter. The source is fetched on the host with no boundary and no transcript,
bounded only by `SourceCache`'s hardening. And no run at any tier is attestable, because there is
still no network transcript: what changed is the reason, not the answer. *(That last clause is no
longer true — see §3.16.)*

### 3.14 A 27B model on a CPU is not slow, it is out of reach

`qwen3.8:latest` is 27.3B parameters at Q4_K_M with a 262144-token context, and it answers
correctly. It is also unusable here, and the reason is worth writing down because it is not the one
you reach for first.

The host has no GPU. `/api/ps` reports `size_vram: 0`, so every token is computed on eight CPU
cores. Output generation runs at **0.4–0.5 tok/s**. That sounds survivable. The number that is not
survivable is prompt processing: **0.8 tok/s at 22 tokens, and 0.8 tok/s at 476**. It does not
improve with batch size on this hardware, which is the assumption that would have saved it — on a
GPU, prompt eval is where the parallelism is.

A Builder prompt for a modest npm target — 120 repository files, two small manifests, two lines of
evidence — measures 4919 characters, about 1230 tokens. At 0.8 tok/s the model spends **25 minutes
reading the question** before it writes anything. A repair iteration adds the previous strategy and a
compressed log; `repo_files` is capped at 200 rather than 120. Two to four thousand tokens is the
realistic range, so 40 to 80 minutes.

**The first thing that broke was ours.** The provider's HTTP timeout was a flat 600 seconds, so a
real Builder call against this model failed mid-prompt — not slowly, but as a transport error that
reads like a broken endpoint. Ten minutes is a correct bound for a hosted endpoint and the wrong one
for a model on this machine, and one constant was serving both. The deadline is now per request and
per flavour: an hour for Ollama, ten minutes for everything hosted, and `with_timeout` for a
`compatible:` URL whose speed the flavour does not predict. An hour rather than no bound, because a
server that has genuinely hung should still end the run.

What stops a sensible run is the caller's budget, not the transport. `Budget::wall_seconds` defaults
to twenty minutes and is checked *between* iterations, so a single long call completes and the
*next* one is refused with `BudgetExhausted { what: "wall clock" }`. On this hardware that means one
attempt per target and no repair, which is the honest outcome rather than a hidden one.

Turning thinking off is a real saving and does not rescue it. It cuts output tokens by roughly 8×
(52 to 6 on `{"ok":true}`) and wall clock from 150s to 27s on a trivial prompt, but it changes
nothing about the 25 minutes spent reading. The knob is worth having for any CPU-hosted thinking
model; it is not what makes this one usable.

Three things came out of the attempt that outlive it, and they are in the commit rather than here:
the reasoning trace is recorded instead of discarded, `reasoning_effort: "none"` is the one
suppression knob that reaches through `/v1/chat/completions`, and Ollama does report prefix-cache
hits, which we had assumed it did not.

**And the answer was good.** With the deadline raised, one real Builder prompt for
`pkg:npm/escalade@3.2.0` ran end to end: 672 prompt tokens in, 155 out, **1483 seconds**. What came
back parses as a `Strategy`, names only registered tools with their required parameters, and renders
to a build script:

```yaml
schema: 1
kind: flow
location: { repo: https://github.com/lukeed/escalade, ref: fa5be167 }
src:   [{ uses: git-checkout }]
deps:  [{ uses: npm/deps/custom, with: { node_version: "20", npm_version: "10",
                                         registry_time: "2024-01-26T00:00:00Z" } }]
build: [{ uses: npm/build/pack, with: { npm_version: "10" } }]
output_path: "escalade-3.2.0.tgz"
```

It would not have built, and the reason is worth keeping because it is a *model* error rather than a
speed one: the versions are major-only. The rendered script compares `node --version` against `v20`,
which never matches a real `v20.11.1`, and then fetches
`/-toolchain/nodejs.org/dist/v20/node-v20-linux-x64.tar.gz`, which is not how nodejs.org names a
release. So the first attempt fails at the toolchain fetch, and the repair loop exists for exactly
this. On this hardware it would not get one: `Budget::wall_seconds` is twenty minutes and the first
call took twenty-five.

**What this says about local inference generally.** The ladder is designed so the model is the last
rung and everything above it is free, and `docs/07-ai.md` §6 treats a falling model-invocation rate
as the goal. That design tolerates a slow model far better than a fleet would, which is why the
right response to the measurement was to give the local path a deadline it can meet rather than to
declare the model unusable. It still is not the configuration to reach for: a 27B model on CPU wants
a GPU, and the cheap local option is a small model — `qwen2.5:0.5b` is 397 MB and answers in seconds
— asked to do search rather than reasoning. The fast path is a hosted model, and that is what the
budgets in `docs/07-ai.md` §5 are sized for.

### 3.15 Two of the five archive limits are dead configuration

`Limits` has five fields. Three are enforced: `recursion` (parse.rs:158), `total_expanded_bytes`
(eight sites) and `max_entries` (zip.rs:99). **`max_inline_bytes` and `max_inline_total` are read
nowhere outside `limits.rs`.**

They have nothing to gate, because the machinery they were written for does not run.
`SourceMap::map` — the mmap constructor, and this crate's only `unsafe` block — has no caller.
`Body::Spilled` is matched in three places and constructed in none. An artifact arrives through
`std::fs::read` and is kept whole, so `docs/05-archive-and-normalization.md` §2.2's claim that a 2 GB
wheel stabilizes at near-zero heap is a description of a design rather than of this code. The 80 MB
wheel in the M0 corpus is fine; a 2 GB one would cost 2 GB.

`Body::Original` — the copy-on-write half — *is* real, and is constructed in `tar.rs:150`. So the
finding is narrower than "COW is unimplemented": the borrow-from-the-source-buffer part works, and
the never-hold-the-whole-file part does not.

**Why this is the same bug again.** §1 named the class as configuration that looks applied and is
not, and this is the purest instance yet: two limits with plausible defaults, a doc chapter
describing what they bound, and no code reading either. It also reached the threat model, which
claimed the verifier "writes a spill file above 8 MiB" as a host side effect and cited `SpillFile`
for it. That is an over-claim in the safe direction — we said we might write a file we never write —
but §1.5's whole value is that its negative claims are exact, and an inexact one there is worth no
more than a guess. Corrected, and recorded as D23.

The right fix is not to delete the fields. The design wants mmap and spilling, `docs/05` explains
why, and a fleet stabilizing large wheels will need them. What is wrong is shipping the knobs for
machinery that is not there, so until it is, the limits say so.

---

### 3.16 The transcript was already being computed, and thrown away

`attestable` was the literal `false` in two places in `podman.rs`, and the stated reason was that
the runner records no network transcript. Finding out what it would take to record one turned up an
answer the code had been sitting on the whole time.

**The mirror hashes every body as it streams past.** It has to: that is how the artifact guard
works. `guarded_stream` knows the URL, computes the SHA-256, counts the bytes, and decomposes
archives small enough to open — and then `Guard::observe` kept the result only when it *matched* the
run's guard manifest. Every clean observation, which is to say every ordinary download on every
honest run, was computed and dropped on the floor. Tier 1 was three fields and a `println!` away
and had been for months.

Four things worth writing down from doing it:

- **`Guard::observe` now returns how far it got** rather than the caller reconstructing it. Every
  reason the member check stops early — too large, not an archive, an archive that would not open, a
  manifest with no members — lives inside that function. A caller inferring `opened` from a size
  limit would call a body checked that was never opened, which is precisely the difference between a
  check and the appearance of one. The first draft of this change made exactly that mistake.
- **The hash became unconditional.** It used to run only when the guard was armed, which was right
  while its only consumer was the guard. Left as it was, every unarmed run would have produced a
  transcript full of the digest of nothing — worse than no transcript. What stays conditional is
  *collecting the body*, which is the expensive half.
- **The lines go to stdout, not through `tracing`.** Trips use `tracing::error!` and clear the
  default `warn` filter; an `info!` line does not, and the mirror container starts with no `-v` and
  no `RUST_LOG`. A record that appears only when somebody set an environment variable is the
  project's own recurring bug — configuration that looks applied and isn't — attached this time to
  the field that decides whether a run is attestable.
- **`RunnerCaps::attestable` was deleted, not updated.** Its only two readers built a *fresh,
  mirror-less* `PodmanRunner` to ask, so a run performed by a mirror-equipped runner was recorded
  with the mirror-less one's answer. It advertised "could some run here be attested" and was read as
  "was this one". That is the recurring shape again: two things that had to agree, with nothing
  asserting they did. Whether a run may be attested is a fact about that run, and it now lives on
  `BuildOutcome`, derived in one function from one match.

**A bug this change introduced, found by running it.** The transcript is written next to the build
log, in the directory `newest_file` walks looking for the rebuilt artifact — and that walk excluded
exactly one filename, `build.log`, hard-coded at the walk. So the first live `mirror-only` rebuild
after the change judged its own network transcript as the tarball it had just built, and reported
`malformed gzip: not a gzip member` about an artifact that was perfectly well-formed. Inside an hour
of writing the paragraph above about two things that had to agree with nothing asserting they did.

The fix is both halves, because only one of them is the mechanism: the caller now takes the artifact
path the *runner* collected — the runner mounted the directory, it has never had to guess — and the
walk, which remains for builds whose output lands in a subdirectory, consults a single `OURS` list
declared beside the code that writes those files. A test writes every name in that list into an
output directory and asserts nothing is offered as the artifact, so the list cannot drift from the
writers again.

**And `deny-all` is attestable too**, which was not the expected result. Its account of egress is
complete and empty: `--network none` on both the image build and the run means the build has no
interface, so "nothing crossed" is enforced by the kernel rather than observed by a proxy. Leaving
the stricter tier marked less trustworthy than the looser one would have been backwards. What keeps
this honest is that present-and-empty and absent are kept apart all the way down — an empty blob in
the store, no blob, and `attestable` derived from which — so "we never looked" cannot become "we
looked and it was clean".

### 3.17 The control that was blank on the tier that recommends itself

`PinEvidence` is the answer to "did the registry pin bind anything?", and it is the counter that
eventually exposed §1's `PIP_TRUSTED_HOST` finding after weeks of reading zero. On every
`mirror-only` run it read `null`.

The reason is the same shape as §3.16 and arrives from the opposite direction. The counters live on
the `Mirror` object. Under an enforced tier that object runs *inside the build's network island*,
and the host has no route to it — which is the definition of the island rather than a bug. So the
control was present at `open`, where a build can bypass the mirror entirely and the evidence is
nearly worthless, and absent at `mirror-only`, where it is the claim being made.

Three things came out of fixing it:

- **`versions_withheld` was never a counter.** It is computed per index document, by the filter that
  removes the versions, and then added to a running total. Moving it onto the index row put it where
  it always belonged, and the transcript carries it out for free.
- **Refusals needed their own marker.** A refusal serves no body, so it has no digest and no byte
  count, and forcing it into the transcript would have put a row of nulls beside every real one.
  It is also the more interesting half: `rejected` collapsed "no filter", "host not on the
  allowlist" and "upstream returned 500" into one number, and the row now says which.
- **Two ways to compute one thing, so something asserts they agree.** `Mirror::observed()` reads
  atomics the request path bumps; `Observed::from_transcript` counts rows. The first cannot leave
  the island, which is why the second exists, and a test drives real traffic through a mirror and
  asserts both produce the same `Observed`. That test is the point — without it this is the
  project's most reliable bug shape reintroduced deliberately.

One thing it does *not* fix, stated because a control must not claim more than it checks: this says
the filter ran and what it removed. It says nothing about whether what it served was right.

### 3.18 A census of the extension seam, before extending it

B8 says adding an ecosystem "should be a `Registry` implementation plus some YAML tools, with no
change to the engine — and if any of them needs a special case in the ladder, the seam is wrong and
that is the finding." Before writing the crates.io client, six agents read the six subsystems a new
ecosystem has to touch and a second pass tried to refute each report. The finding is that the seam
holds where it was hardest to build and leaks where it was cheapest — and that one of the leaks was
silent.

**It holds completely in the judgement half.** For crates.io the stabilizer and archive diff is
*empty*. `.crate` sniffs to `tar+gzip`, the filename selects the `crate` profile, `cargo-vcs-hash`
is implemented and tested, and nineteen `pkg:cargo/` targets already run through the golden
differential corpus against the reference implementation. Nothing below the judgement line needs
touching, which is the half a wrong answer would have been most expensive in.

**It leaks in the acquisition half, and the ladder leaked silently.** `ladder()` matched `Npm`,
`PyPI`, and `_ => {}`. A crates.io target would have resolved, fetched, built a ladder with no
heuristic rung and no model rung — `inferrer::supported` was a `matches!` that also answered `false`
without saying so — and reported `no-strategy`, which is exactly what a package whose recipe we
genuinely could not infer reports. A statement about Trigon rendered as a statement about the
package. `for_ecosystem` gets the identical situation right two hundred lines earlier: it refuses by
name and lists what it serves. Both catch-alls now do too, and `supported` is exhaustive so the next
variant fails to compile rather than answering `false`.

**Two live bugs it turned up that have nothing to do with crates.io:**

- **The mirror's host allowlist was checked on the first hop only.** The passthrough client was
  built with `redirect::Policy::limited(5)`, so reqwest followed up to five `Location` headers to
  any host on the internet, and a hand-rolled sixth hop checked nothing either. At `mirror-only` the
  allowlist is the entire content of the tier — every host reachable through the proxy is a host the
  build can be told to fetch from — so this made it a statement about where a build *asked* to go
  rather than about where its bytes *came from*. An allowlisted host answering
  `302 cdn.evil.example` put arbitrary bytes into a sandbox with no other route out. Redirects are
  now followed one hop at a time with the same check on every one, through a single `host_allowed`
  that both the routes and the loop call.
- **`same_artifact` compared the last path segment.** That works for npm and PyPI, whose artifact
  URLs end in a filename. A crates.io download URL ends in the literal word `download` for every
  crate ever published, so the first dependency a crates.io build fetched would have matched the
  run's own `refuse_url`, been refused, and recorded as a trip — every crates.io run `Void`, every
  time, from a control firing on traffic it was never meant to see. A segment that names nothing now
  falls back to comparing one deeper.

**Three types the docs describe were never written**: `EcosystemSpec`, cited as live in two source
comments and printed as a full trait block in `01-architecture.md`; `VersionOrd` and its
ecosystem-dispatching `cmp_version` filter; and the crates `trigon-images` and `trigon-engine`. The
checklist in `03-ecosystems.md` §7 — "which doubles as the test of whether the seam holds" — sent a
reader looking for three of them. It now has a §7.2 saying which half is real.

**And the honest count**: adding crates.io is 14 work items, 10 in engine files, 8 of those genuine
edits once the two allowlist additions are subtracted. Narrow rather than broken — every edit is
additive and most are three lines — but not "one `Registry` impl plus some YAML".

### 3.19 A coverage number, and the two things measuring it found

B4 asks for a coverage number per crate, the judgement half at a stated bar, and every deliberate
gap named as deliberate. Measuring it turned up two things that were not about coverage.

**The first was mine.** The obvious invocation —
`cargo llvm-cov --ignore-filename-regex '(tests?/|xtask/)'` — silently excludes the whole of
`trigon-attest`, because `at**test/**` contains `test/`. The crate that builds and signs every
attestation was absent from the report and nothing said so; the total looked slightly better for it.
The regex needs path boundaries: `'(/tests?/|/xtask/)'`. Exactly the bug class this file is full of,
committed while writing the section about it.

**The second was a green tick standing in for an unchecked claim.** `trigon-stabilize-wasm` measured
0%, and the reason is not neglect: its only test file is `#![cfg(feature = "host")]`, the feature is
off by default, and the parity test inside needs a `wasm32-unknown-unknown` module that nothing in
the workspace builds. So `cargo test -p trigon-stabilize-wasm` printed `test result: ok. 0 passed`
— which is what that file's own doc comment says a skipped parity test must never be:

> Skipping loudly rather than silently: a parity test that quietly passes when it did not run is
> worse than no parity test, because it is a green tick standing in for an unchecked claim.

The claim it guards is that an archived stabilizer set produces the same bytes as the compiled one,
which `docs/13-roadmap.md` makes a milestone criterion — it is the whole reason an archived set is
worth anything. Built and run by hand, **it passes**. It had simply never run here. CI now builds
the target and greps for the two test names, so a run that finds no module fails rather than exiting
zero.

**The numbers**, lines covered, measured twice — once offline and once with `TRIGON_LIVE=1`, because
the difference between them is the honest measure of "needs the network" versus "untested":

| | offline | live |
|---|---|---|
| **Judgement half** (`core`, `archive`, `stabilize`, `compare`, `attest`) | **88.4%** | **88.4%** |
| `trigon-mirror` | 77.7% | 86.3% |
| `trigon-ai` | 80.8% | 86.7% |
| `trigon-registry` | 72.7% | 76.4% |
| `trigon-sandbox` | 76.3% | 76.3% |
| `trigon` (CLI + UI) | 39.2% | 40.1% |
| Workspace | 69.0% | 71.4% |

**The judgement half moves by 0.0%.** That is worth more than the number beside it. It is the
central architectural claim — that the half which decides a verdict is deterministic and reaches no
network — measured rather than asserted: every line of it that is covered at all is covered by a
test that opens no socket. Not equal to one decimal: **4817 of 5452 lines in both runs**, the same
count, and the same figure per crate. The crates that move are exactly the ones that are supposed
to: the mirror gains nine points and `trigon-ai` six.

**Two of these rows are not stable to the line, and the workspace total is.** Two independent
measurements agreed exactly on the workspace figure (16105 of 23354 lines) and on judgement, mirror,
`ai` and registry, and disagreed on `trigon-sandbox` and `trigon`. `trigon-sandbox` is the unstable
one: 810 in four separate datasets and 826 in a fifth, drifting by 11 lines between two runs of the
same tree in `podman.rs` and `network.rs`, which is container timing deciding which lines execute.

The two rows do **not** trade off against each other, and the arithmetic that first suggested they
might — 810 + 2517 against 826 + 2501, both 3327 — is a coincidence of one pair of runs. Across a
different pair the binary's coverage is byte-identical at 2572 of 6413 while the sandbox moves; across
ours the reverse, the sandbox fixed at 810 while the binary climbs 2517 to 2572 because live tests
reach more of the CLI. Nothing is conserved; one crate is simply noisy.

So a per-crate figure for those two is a sample rather than a value, and a re-derivation that differs
there has not found a mistake. Quote the workspace total and the judgement half.

Measured over 901 tests. The live run of that measurement had one failing test,
`copilot_answers_through_its_cli_and_sees_no_tools`, and it cost no coverage: the panic is an
assertion *after* the provider returned a fully constructed response, the harness caught the unwind,
the other tests in that binary ran, and the profdata was written whole. The lines it did not reach
are in the test file, which `--ignore-filename-regex` excludes — the report has no row for it. Both
columns are readings, not floors. `cargo llvm-cov` does skip report generation on a non-zero test
exit; `cargo llvm-cov report` recovers it from the same profdata. Concurrent coverage runs share
`target/llvm-cov-target` and delete each other's test binaries at startup, and cargo-llvm-cov 0.9.1
has no `--target-dir` — set `CARGO_TARGET_DIR` and check stderr for `never executed` before
trusting any figure here.

The judgement half is the half that matters: it is what the verifier binary contains, what a third
party re-derives a verdict with, and the only part whose bugs are silent — a divergence is
self-consistent, so both sides get the same wrong treatment and the failure surfaces as a false
negative rather than a crash.

The deliberate gaps, named:

- **`trigon/src/watch.rs` and most of `main.rs`** are the CLI and the embedded web UI. Their logic
  is unit-tested; the uncovered remainder is argument plumbing and HTML string-building whose
  failure mode is visible rather than silent.
- **`trigon-stabilize-wasm/src/host.rs`** does not appear in the report at all, being behind the
  same `host` feature. Its coverage is real but measured only in the run CI now performs.
- **The `TRIGON_LIVE=1` delta** is the honest measure of "needs the network" versus "untested", and
  it is why the number above is quoted with the flag set rather than without.

### 3.20 Four defects behind one user's first failed run

A reader followed the README — `--egress mirror-only` against a stock Debian image — and reported
what came back. The build failed for the right reason and said so clearly:

```
this base image is missing: ca-certificates git libatomic1 wget
an enforced egress tier gives the image build no network, so the packages a
strategy needs have to be in the image already. Build one with:
    trigon base-image --from <this image> --packages ca-certificates git libatomic1 wget

  failure   unknown
```

**`unknown`, directly under our own paragraph saying exactly what was wrong.** The setup phase
writes that line; nothing in the failure taxonomy claimed it. So a run that diagnosed itself
perfectly reported that it had no idea — and the failure could not cluster, could not key the repair
cache, and could not be recognised by the flywheel the next thousand times it happened. It is also
the *first* failure a new reader hits, because that command is what the README suggests trying.
Named `env/base-image-incomplete`, `Fault::Policy` — the tier is doing what it was asked — and
unrepairable, since no strategy change helps. One cluster rather than one per combination of
missing packages: the operator action is identical whichever is absent.

Three more in the same fifteen lines:

- **`Deps 1.9s` for a build that died in `Setup`.** `failing_phase(&log)` already knew, and was
  read *after* the timing row had been pushed as `Deps`. So one line said `phase=Setup` and another
  two below it said `Deps`. Read once now, used for both.
- **"what crossed is unknown rather than nothing", about a phase that provably had no interface.**
  The early return tore the island down without reading it. The image build has `--network none` at
  every enforced tier, so the honest answer was an *empty* account, not no account — the pessimistic
  mirror of the mistake this file is otherwise full of. It reads the log before destroying now, and
  the run reports `0 responses crossed into the build`.
- **The stale-mirror check never fires for an installed binary.** This is the one worth the most.
  `warn_if_stale` computed the expected digest by walking up from the *current directory* to find
  the workspace, and returned silently when it could not. The reader saw the warning only because
  they happened to run from `target/debug`, which is inside the checkout; from anywhere else it is
  silent, and anywhere else is where an installed Trigon is always run. A control that fails open
  and says nothing while doing it — guarding against precisely the confusing in-container failure
  this reader then hit.

  It is also the wrong question. "Is this image older than the mirror code *this binary* speaks" is
  a fact about the binary, so the digest is baked in by `build.rs` now. The hashing rule lives in
  one file that `build.rs` and the binary both `include!`, because two copies would either never
  match — warning on every run — or match by luck and never warn.

### 3.21 The same tier asymmetry twice in one day

`chardet 7.4.3` at `mirror-only` produced a wheel whose every `dist-info` member was named
`chardet-0.1.dev1+g8f404a5a9`. Twenty-nine of its thirty-five members were byte-identical; the
verdict was `divergent`. A public accusation about a package whose only fault was how we cloned it.

`hatch-vcs` takes the package version from `git describe`. The host checkout is
`git fetch --depth 1 origin <commit>`, which carries no tags, so `describe` had nothing to describe
from.

**And it was tier-dependent, which is why nobody saw it.** At `--egress open` the source phase runs
`git clone` inside the container, and a clone fetches every tag, so the version came out right. Only
an enforced tier — where the host fetches instead and copies the tree in — was wrong. Same recipe,
same commit, two artifacts. That is the second such asymmetry found in a day: the venv path in §3.20
was the first, and both were invisible for the same reason, which is that the corpus runs at `open`.

The fix asks the remote which tags name the commit rather than fetching all of them: `ls-remote
--tags` is a single round trip that transfers no objects, chardet has seventy-three tags, and one of
them is the answer. Annotated tags list twice — once as the tag object, once as the commit under
`^{}` — and it is the second line that matches.

**The fix did not work the first time, and the reason is worth keeping.** A cached checkout is
reused, and one made before tags were fetched has none; reading them on the cache hit was not
enough, so the fix applied only to repositories nobody had built yet — which did not include the one
it was written for. It backfills now.

With tags, `chardet 7.4.3` reproduces **`exact`**: identical raw digests, thirty-five of thirty-five
members identical, at `mirror-only` with a complete network transcript behind it.

### 3.22 The PyPI corpus at the enforced tier, and a control reporting a win as a loss

The venv fix and the tag fix were each found by one package, so the obvious question was whether
there were more. Running the seventeen-target M1 PyPI smoke corpus at `mirror-only` — the first time
it had been run at an enforced tier at all — says no, and finds something else.

| | reproduce | reached a comparison |
|---|---|---|
| `mirror-only` | **9 of 11 (82%)** | 11 of 17 |
| `open` (prior baseline) | 12 of 15 (80%) | 15 of 17 |

**The rate holds at the enforced tier**, and three of the nine are now `exact` rather than
normalized: `chardet`, `filelock`, `platformdirs`. The six `normalized_with_caveats` are not a
weaker result — `wheel-record` is `RiskTier::Content` and the provenance cap fires above
`Metadata`, so every wheel that is not bit-identical caps there by construction.

What dropped is the denominator, and the largest cause is a control returning the wrong verdict.

**Three targets voided, and not one was a real catch.** `packaging`, `toml` and `pyproject-hooks`,
all `GuardMatch::RefusedUrl` — the build asked the mirror for its own published artifact and the
mirror refused it. Every one of those packages is part of the machinery that builds packages:
`python -m build` needs `packaging` and `pyproject-hooks`, so rebuilding one makes the build ask for
it, the mirror says no, the build dies, and the run is voided.

The guard trips three ways and they are not equally serious:

| trip | what happened | evidence of nothing? |
|---|---|---|
| `WholeArtifact` | the artifact arrived | **yes** — it could have been copied to the output |
| `Member` | a guarded file of it arrived | **yes** |
| `RefusedUrl` | the build asked and was **refused** | **no** — nothing arrived |

All three produced the same `Void`. The third is the control *working*, recorded as a failed run.

It is also safe to separate, because `refuse_url` is not what catches an attempt. It knows exactly
one URL; the whole-body hash runs on every response by every route, so a build fetching the same
bytes from anywhere else trips `WholeArtifact` instead. The refusal is a convenience and the hash is
the control. A build that is refused and *still* produces a matching artifact built it from source,
which is the thing we are trying to reward.

So a refusal no longer voids. It is recorded — on the run, in the record, and in
`buildobservation/v1` under `refusedOwnArtifact` rather than `violations` — and the run's real
outcome stands, which for a build that needed the package it was refused is a build failure that now
has an explanation attached. Voiding there would have meant `setuptools`, `wheel`, `tomli`,
`flit-core` and `hatchling` could never be verified at an enforced tier: the packages everything
else depends on.

**Re-run after the change**, the same seventeen targets: every outcome identical except the three,
which moved from `void` to `build-failed:deps` and now carry a named cluster each —
`env/needs-the-package-under-test:packaging>=24.0`, `:pyproject_hooks`, `:toml`, each marked
"nothing to repair". The rate is unchanged at 9 of 11 (82%), which is the right result: the change
was to a verdict, not to a build, and it moved exactly the runs it should have and nothing else.

**After fixing what the sweep surfaced**, the same seventeen targets: **12 of 14 compared
reproduced (86%)**, 14 of 17 reaching a comparison, no `no-strategy` and no `build-failed:source`.
`certifi`, `tomli` and `toml` all recovered.

The three that remain are worth separating, because two of them are the same problem at different
depths. `zipp` is the tier working: its backend calls `urlopen` to fetch licence text, so the build
reaches the open internet and is blocked — a finding about the package, recorded as
`net/build-fetches-directly` with nothing to repair. `packaging` and `pyproject-hooks` now *build*,
which the self-exclusion constraint bought, and then void: pip resolved the adjacent release, and
adjacent releases of the same package share byte-identical files, so a guarded member of the version
under test arrives inside a version that is not it.

That last one is sharper than it first looked, and it is why the constraint fixed `toml` and not the
other two. It is not "the build cannot run" any more. It is that **rebuilding a package whose
adjacent release is nearly identical will always trip the member guard**, because the guard compares
bytes and cannot tell a file of 26.3 from a byte-identical file of 26.2. Closing it means deciding
that a member arriving inside a *different version of the same package* is not a catch — a
bootstrapping policy rather than a code change, and not one to make by loosening a control.

[§3.23](#323-the-bootstrap-wall-and-a-control-asking-the-wrong-question) closes the first half and
narrows the second, without loosening anything: the version under test is withheld from the index so
the resolver never asks for it, and the void decision moves to where the rebuilt artifact is in hand.
`packaging` and `pyproject-hooks` then build — and still void, because for a package that rebuilds
itself the member genuinely does come back out. What is left is named there.

**Two more defects the sweep surfaced, both tier-independent:** `tomli`'s source discovery produced
`https://github.com/hukkin/tomli/blob/master/CHANGELOG.md/` as a repository URL, because
`canonicalize_repo` does not strip a `/blob/…` file path off what PyPI's metadata supplies; and
`zipp` reached the mirror for its index and then failed on something else that has not been run
down yet. `certifi` is `no-strategy` because no tag matches `2026.7.22`, which is the resolver
declining to guess and is correct.

### 3.23 The bootstrap wall, and a control asking the wrong question

Five of the eight targets that reached no comparison at the enforced tier were one bug, and §3.22
left it open deliberately: rebuilding a package that is part of the machinery that builds packages
makes the build ask for the package under test. `python -m build` needs `packaging` and
`pyproject-hooks`; npm's own installer needs `object-assign`, `strip-ansi` and `repeat-string`.

It closes in two pieces, and neither of them loosens a control.

**Refuse in the index, not at the download.** The guard knows the target's artifact URL and refuses
it. That is right and it stays. What was wrong is what the *index* said first: the mirror listed the
version, so pip resolved `packaging>=24.0` to the target, asked for the file, and was denied. A
resolver that has been told a version exists and is then refused the file does not look for another
one — it fails.

A version that was never offered is a different thing. `packaging 26.3` is simply not in the index,
so pip takes `26.2`. The target's bytes still never cross, by exactly the control that stopped them
before; the resolver routes around the hole instead of dying in it.

Both filters already had the shape. `filter_packument` and `filter_simple` drop versions by publish
time, and the npm one already recomputed `dist-tags.latest` afterwards — written because a tag naming
a removed version makes every install fail on a version that is not there. Withholding the target
reaches that hazard the same way, so the recompute moved into a function both call, and `modified`
went with it for the same reason.

The counts stay apart. `versions_withheld` is the evidence that the registry pin applied, and folding
a policy removal into it would make an index where only the target was dropped report `withheld=1`
and read as the pin doing work it did not do.

**PyPI already had a version of this and npm did not**, which is the argument for doing it here. The
`pypi/deps-basic` recipe takes an `exclude_self` parameter and writes `name!=version` into a pip
constraints file, for exactly this reason and in almost these words. It works, and it is per-recipe:
every strategy that could hit the wall has to remember to ask for it, in every ecosystem, and the
npm recipes did not. Withholding the version from the index is the same rule one layer down, where
it applies to every run, every ecosystem and every recipe including the ones nobody has written yet.
So the PyPI corpus does not move — the constraint was already carrying it — and the npm corpus is
where the measurement shows up.

**Then ask the guard the question it can answer.** With the build running, the second half of §3.22
lands: pip installs the adjacent release, and adjacent releases of one package share byte-identical
files, so a guarded member of the version under test arrives inside a version that is not it. The run
voids. The most important control in the design, firing on a dependency doing nothing unusual.

The fix is not an exemption. It is that **the question was being asked in the wrong place**. A member
*arriving* was never the harm; the harm is a member arriving and **coming back out in the rebuilt
artifact** — bytes fetched rather than built, re-emitted as though they had been, which is
[`12`](12-security.md) §1.1 exactly. That question needs the build's output, which the mirror does
not have and the judgement half does.

So the mirror reports what arrived and the decision moves after the build:

| trip | voids when |
|---|---|
| `WholeArtifact` | always — there is no honest reason for the published artifact to arrive whole |
| `Member` | the digest that arrived is also in the rebuilt artifact |
| `RefusedUrl` | never — nothing arrived (§3.22) |

Three things follow, each an improvement rather than a cost. The decision is a pure function of two
digest sets, so a third party can re-derive it from the attestation instead of taking a network
proxy's word for it. A build that produced no artifact voids nothing — nothing was smuggled out of a
build with no output, and the run is already `BuildFailed`. And the near-misses are kept and shown:
a control whose near-misses are invisible cannot be told from one that never fires.

The runner no longer decides either. It reports `guard_arrived` and the caller calls
`trigon_mirror::voiding` once, because the caller is what resolves the rebuilt artifact — `collect`
finds the single file at the output path, and the caller also walks for builds whose output lands in
a subdirectory. Two answers to that question, with nothing asserting they agreed, is the shape of
bug this project keeps finding.

**Three more defects found on the way, none of them the one being fixed.**

*The marker in the prose.* Carrying the decision out of the island meant the trip line had to carry
the digest, so `GUARD-TRIPPED` became JSON like the two markers beside it, and its reader refuses an
unreadable line rather than skipping it. It then refused immediately — because the `tracing` message
*next to* the record also contained the marker, so the reader saw a sentence where it expected an
object and reported that whether the artifact reached the build was unknown. The strictest possible
answer, produced by a log line. A record is now the marker, a space and a JSON object; prose that
mentions the marker is a different kind of line, not a damaged record. Everything from `{` onwards
stays strict, because a record that was written and cannot be read is the thing the strictness is
for.

*The port that only existed with `--timewarp`.* At an enforced tier the island mirror is the build's
only route out, so `toolchain_url` rewrites every toolchain download through it. The host it wrote
carried the mirror's port only when `--timewarp` had also been passed; without it the name fell
through to a bare `timewarp` and every toolchain download died on `Connection refused` — the mirror
listening on 8129, the rendered URL saying port 80. Two ways to know where the mirror is,
disagreeing. It is now one function with three tests, and the enforced tier names the port whatever
else was asked for.

**Measured, both corpora at `mirror-only`.**

| | before | after |
|---|---|---|
| npm, reach a comparison | 15 of 20 | **18 of 20** |
| npm, reproduce | 14 of 15 (93%) | **16 of 18 (89%)** |
| PyPI, reach a comparison | 14 of 17 | 14 of 17 |
| PyPI, reproduce | 12 of 14 (86%) | 12 of 14 (86%) |

The npm *percentage* fell and that is the change working. `object-assign` and `strip-ansi` now
reproduce `normalized` with every member identical, and `repeat-string` reaches a comparison and
diverges on two of four members — three packages that previously could not build at all. The
denominator grew from 15 to 18 and the numerator from 14 to 16. A rate computed over the targets we
managed to build is not a rate; it is a statement about which targets we excluded.

Both npm failures that remain are now named with nothing to repair, where before one of them was a
DNS error about the wrong thing: `src/commit-not-on-the-forge` and what was then called
`trigon/mirror-corrupted-artifact` ([§3.26](#326-the-corruption-was-named-after-the-wrong-component)).

**What this did not close, and what did.** (Closed in
[§3.24](#324-the-filter-was-tested-the-ordering-that-reaches-it-was-not); left here as it stood,
because the reasoning that follows is what pointed at the fix.) `packaging@26.3` and
`pyproject-hooks@1.2.0` now build — and still void. The member that arrived inside the adjacent release *is* in the rebuilt artifact,
because a file unchanged between two releases of one package is byte-identical in both and the build
produces it honestly from the checkout. The guard is answering its question correctly; the question
is not sufficient on its own for a package that rebuilds itself.

The rule that finishes it is already written and already stated:
`GuardManifest::for_artifact_with_source` drops members byte-identical to a file in the source tree,
because "a file the artifact ships and the repository also contains is not evidence of anything: the
build is entitled to fetch it". Every member that trips here is such a file. It is not applied
because the manifest is built from the published bytes *before* a strategy is chosen, and the source
tree is a function of the strategy's location.

It cannot simply move to the decision either, where the source tree is in hand: the filter carries a
deliberate exemption — an executable the repository also contains is exactly the case worth guarding,
since a build fetching a prebuilt binary is §1.1 — and that exemption keys on the artifact member's
*path*, which only the manifest has. So the manifest has to be built later, after the strategy,
which in turn is what a non-enforced run's host mirror is armed with before the strategy is chosen,
for its port. Untangling that is a change to the order of the most security-sensitive path in the
system and belongs in its own commit, not the tail of this one. Written down as B14 in [`17`](17-backlog.md).

*A commit the forge will not serve.* `pad-left@2.1.0` filed as `net/unreachable` on every corpus run,
beside genuine hidden-network-dependency findings. The real cause is that npm's recorded `gitHead`
names `89347534…`, which GitHub answers with `upload-pack: not our ref` — the commit is not
reachable from any ref in that repository today. The host checkout failed at `debug` level, the
in-container clone then died on the DNS an enforced tier denies it, and the *symptom* got the name.
It is now `src/commit-not-on-the-forge`, `Fault::Upstream`, and the reason is carried onto the
build's own failure rather than logged and dropped.

Carried, not raised: the first version of this refused the run outright when the checkout failed,
which broke a strategy whose source phase generates its own tree and needs no clone at all. The
end-to-end test in `crates/trigon/tests/cli.rs` is exactly that shape and caught it. The fallback was
never the problem — the silence was.

### 3.24 The filter was tested; the ordering that reaches it was not

[§3.23](#323-the-bootstrap-wall-and-a-control-asking-the-wrong-question) left `packaging` and
`pyproject-hooks` building and still voiding, and named the rule that would finish it. The rule was
already written, already tested, and unreachable.

`GuardManifest::for_artifact_with_source` drops members byte-identical to a file in the source tree,
because "a file the artifact ships and the repository also contains is not evidence of anything: the
build is entitled to fetch it". A unit test covers it. Nothing covered whether an ordinary run ever
got there — and it did not, because the manifest was built from the published bytes before a
strategy existed, and the tree is a function of the strategy's location. The filter had a test; the
path to the filter had none. That is this project's signature defect, found again in its own
security control.

**The cycle was the mirror.** The manifest needs the strategy; the strategy has to be told where the
mirror will be before it can be chosen; the mirror is armed with the manifest. Reserving the address
breaks it: `trigon_mirror::reserve` hands back a *held* listener, the ladder runs against an address
that exists and serves nothing, the checkout happens, the manifest is built narrow, and only then
does the mirror serve on that listener. A held listener rather than a remembered port number,
because releasing a port and re-binding it later is a race whose loser cannot start its mirror at
all.

What made it legal is a property of the inferrers worth writing down: they read the mirror only to
decide whether to pin a registry moment, and make **no request through it**. A reservation is
therefore enough to run the ladder, and nothing is served under a manifest that is not final.

`checkout_and_guard` returns the tree and the manifest together, so there is no longer a point in a
run where a manifest exists and the checkout does not — the ordering lives in a signature rather
than in line order. Its third test is the one that matters: the tree handed to the build is the tree
the guard exempted from. A different one would make the exemption a statement about other bytes,
with nothing downstream able to tell.

| PyPI, `mirror-only` | before | after |
|---|---|---|
| reach a comparison | 14 of 17 | **16 of 17** |
| reproduce | 12 of 14 (86%) | **14 of 16 (88%)** |
| `void` | 2 | **0** |

`packaging@26.3` guards **0 of 29 members** — every one is a file the repository also contains — and
reproduces with 29 identical and 0 differing. The only PyPI target left short is `zipp`, whose build
opens a socket, which is a finding about the package.

**Two things found while fixing it, neither of them the fix.**

*A sweep that lied about why a target failed.* A 400-target corpus is eight hours of strictly serial
sweeping, so the loop became a bounded thread pool with `--concurrency`. Its first real run over the
seventeen PyPI targets lost two of them to `getting top layer info: layer not known` — B6's error
verbatim — and to a mirror container read after another lane removed it. The argument that said
intra-process lanes were safe (distinct run ids give distinct image tags, so no lane removes
another's top layer) was wrong, and one run of the corpus said so. Both faults arrive labelled as
the *package's* failure, which is the one thing a reproduction rate must never contain, so the flag
refuses above one lane and states what it measured. B6 stopped being a background item and became
the gate in front of the M1 corpus.

*A red pipeline nobody could see.* `RUSTFLAGS: -D warnings` plus `cargo build -p trigon
--no-default-features` fails on two dead functions, and had been failing since before this work —
which falsifies an M0 exit criterion recorded as met. The fix is two `#[cfg]` attributes; the
finding is why it hid. `verifier_builds()`, the dependency-policy check whose entire purpose is to
catch this, ran **without** `RUSTFLAGS`. It was checking a different build from the one that has to
compile, and reporting success. A control checking something adjacent to the thing it claims to
check — the same shape as the `GUARD-TRIPPED` marker in §3.23 and the `tests?/` regex in §3.19,
three times in one codebase.

### 3.25 The corpus, and what one stratum was hiding

> **Superseded as a measurement, kept as a finding.** Every figure in this section is from the first
> full run of the corpus. The corpus has since been re-run at `0ff8aa1` and the numbers moved a
> long way — npm's TypeScript stratum from 12% to 43%, PyPI's reach from 68% to 81% — so quote the
> README for what is true now, and read this for what the first run *found*. The finding is not the
> rate; it is that an aggregate hid a stratum, and that is still true at every rate since.

The M1 common-path corpus ran for the first time: 197 npm and 200 PyPI, stratified by build system.
Every rate published before it came from the 37-target smoke corpora, which are almost entirely one
stratum — the easiest — and it shows.

| | smoke | common-path |
|---|---|---|
| npm, reach a comparison | 18 of 20 (90%) | **115 of 197 (58%)** |
| npm, reproduce | 16 of 18 (89%) | **84 of 115 (73%)** |
| PyPI, reach a comparison | 16 of 17 (94%) | **136 of 200 (68%)** |
| PyPI, reproduce | 14 of 16 (88%) | **119 of 136 (88%)** |

The reproduction rates held; **reaching a comparison did not**, and that is the number the smoke
corpora were flattering. PyPI reproduces at 88% on both, which is a real result. npm falls from 89%
to 73% because the denominator grew by targets that are harder.

Then the tail of each corpus was run alone — the strata added last and never measured before:

| tail 40 | reach a comparison | reproduce |
|---|---|---|
| npm, TypeScript + monorepo | 15 of 40 | **3 of 15 (20%)** |
| PyPI, poetry + native | 17 of 40 | 16 of 17 (94%) |

[`15-corpora.md`](15-corpora.md) §3 argued for stratification with a hypothetical: "an aggregate
that hides a 20% rate on native extensions is not a number anyone can act on." It is not
hypothetical. npm's monorepo and TypeScript strata reproduced at **20%** here, against an aggregate
of 73% over the whole corpus.

The re-run bears the argument out a second time rather than retiring it: those two strata are now
43% and 33% against an aggregate of 75%, so the spread narrowed and the aggregate still hides it.

**Confirmed at four times the sample.** 300 targets — 150 from each corpus, sampled proportionally
across the strata because they are contiguous in the files and a head-150 contains no TypeScript,
monorepo, poetry or native target at all:

| npm | compared | reproduced | | PyPI | compared | reproduced | |
|---|---:|---:|---|---|---:|---:|---|
| no lifecycle script | 54 of 69 | 46 | 85% | flit / hatchling | 38 of 38 | 38 | **100%** |
| `prepare`/`prepack` | 19 of 46 | 16 | 84% | setuptools + pyproject | 34 of 45 | 26 | 76% |
| TypeScript build | 8 of 23 | 1 | **12%** | setuptools + `setup.py` | 23 of 30 | 15 | 65% |
| monorepo member | 4 of 13 | 1 | **25%** | poetry-core | 20 of 22 | 20 | **100%** |
| | | | | maturin / C extension | 7 of 15 | 4 | 57% |

The aggregate for npm is 75% and it is a number about almost nothing: two strata at 85% and 84%
carry it, and the two that do real work sit at 12% and 25%. **The reach is worse than the rate.**
Only 8 of 23 TypeScript targets and 4 of 13 monorepo members get as far as a comparison, so the
percentages above are computed over the third of each stratum that survived — the honest reading of
"TypeScript reproduces at 12%" is "one of the eight we could measure".

PyPI inverts the expectation twice over. The two *modern* build systems are at 100% with every
target reaching a comparison, and the weakest stratum is `setup.py` at 65% rather than the native
extensions at 57% — which are themselves better than either npm stratum that builds anything.

**The first run measured a defect of ours rather than the packages.** 34 of 197 npm targets failed
`E400`, which is this mirror refusing a request for want of the time filter. npm 11 does not use the
`dist.tarball` we rewrite: it takes the path off the upstream URL, re-bases it onto the configured
registry, and **drops the credentials doing it**. `moment.rs` states the assumption that breaks —
"Credentials in a URL are the one component every client already forwards" — which was true when it
was written and is no longer true of npm.

The first fix served that shape **unfiltered**, on the reasoning that it "costs nothing the filter
was protecting: an artifact's bytes are immutable, so there is no moment to filter them by".
Re-running the corpus moved reaching a comparison from 94 to 115 and the `unknown` cluster from 50
to 23 — and the reasoning was wrong. The filter is not protecting the *bytes*; it is protecting
*which versions exist*. A route that serves any tarball on request hands a build a version published
after the pin, which is the one property the time filter exists for, and it reversed an explicit
case in `seam_controls_fail_closed.rs` — a tarball "which needs no filtering, is refused rather than
proxied unfiltered". Editing that test to match would have been the control eroding to fit the code
that broke it.

**So it was narrowed to what a filtered packument had already offered**, remembered per run. That
held the property and broke a different build shape: npm resolving from a **lockfile** asks for no
packument at all. It reads `resolved` out of `package-lock.json`, re-bases the path onto the
configured registry and fetches, so nothing ever offered the path. 23 of 150 npm targets on the
300-target corpus, every one reported as the package failing.

**The third version asks rather than remembers.** An unoffered tarball sends the mirror to that
package's packument, applies the same time filter and the same withhold the index route applies, and
serves the tarball only if that exact version survives. The property is decided by the same code
that decides it everywhere else rather than by a second implementation that can drift, and the
fail-closed control passes unedited.

It needed one piece of state, and the need is itself the finding: **the filter rides in credentials
and npm drops them on a request it composed itself**, so a bare tarball arrives saying nothing about
which moment applies. `Seen` now remembers the moment an index request filtered to, refusing to
change it rather than taking the last one — two moments in one run is a bug worth seeing. A build
that has fetched no packument at all has no moment, and is refused.

Three versions of one route, and the shape of the mistake was the same each time: a control was
judged against the build in front of it rather than against the property it holds.

**What the remaining unknowns were.** Not one mystery, four causes, each now named from its own log
line: `npm/workspace-protocol` (4), `net/dependency-from-a-forge` (4), `npm/refuses-npm` (2),
`net/prebuilt-binary-download` (1). The first is a finding about *us* — the tarball was built with
the whole monorepo and we build the member alone — and it is the same root cause as the PyPI pilot's
largest cluster, ten targets failing on our own message, `Source /src does not appear to be a Python
project`. `SourceProvenance::subdir` is plumbed through the resolvers, the strategy context and the
output paths, and both registries hardcode it to `None`; npm's packument has carried the answer all
along in `repository.directory`.

**Three bugs of ours the corpus surfaced by being debugged**, none of which 728 tests caught:

- The sweep wrote `results.tsv` in *completion* order while sorting only the in-memory rows, so the
  file's order depended on how many lanes were free. Lining a row up against its work directory —
  which is indexed by corpus position — read a different package, and the first analysis of the
  `unknown` cluster was of the wrong targets.
- The infrastructure breaker keyed on `Outcome::cluster()`, and `NoStrategy` has none, so every one
  took the reset arm. The PyPI run produced 37 consecutive `no-strategy`; the breaker was blind to
  that run's largest failure mode.
- `break` in the collector stopped the reporting and not the lanes: workers ignore a failed send and
  take the next target. A breaker built to save seven hours would have saved none of them.

### 3.26 The corruption was named after the wrong component

`trigon/mirror-corrupted-artifact` had been open since M1, and the mirror was innocent. Six of the
197 npm targets carried it — `is-glob@4.0.3`, `glob-parent@6.0.2`, `ansi-colors@4.1.3`,
`path-exists@5.0.0`, `bytes@3.1.2`, `on-finished@2.4.1` — each dying inside `npm install` with
`zlib: invalid distance too far back`, `incorrect data check`, `invalid block type`, and, in one
verbose run, 19,472 `TAR_ENTRY_INVALID` lines. §5 said the measurement nobody had taken was the
bytes on the *outgoing* side. That is the one that settled it.

**What exonerated the mirror.** Its own transcript already held the answer: every artifact row for a
failing run was `Checked::Hashed` and none was `Partial`, and the digests are the registry's.
`source-map-0.6.1.tgz` recorded sha256 `bdbca10d17ff5a58…` at 199,644 bytes and
`esquery-1.4.0.tgz` `6e5add1c721480e6…` at 160,592 — byte for byte what `registry.npmjs.org`
serves today. Forty artifacts, forty at a time, three rounds, from inside the run's own network
island: 120 requests, all verified. Then the outgoing measurement: a second server, written in
Python, buffering each body whole behind a `Content-Length` and logging a completed write for every
one of 112 requests — no truncation, no write error, no `Range` request anywhere — reproduced the
same corruption. One client explains two unrelated server implementations failing alike; nothing
about the servers does.

**What it actually is.** npm 7.0 through 8.2 splices the tarballs it fetches concurrently. The
correlation across the sweep is total: all six failures pinned an npm in that range, and none of the
other 60 distinct npm versions in the corpus, spanning 2.8.3 to 11.13.0, failed this way. Bisecting
against one mirror, in one sitting, on one Node: 7.0.15 corrupted 20 tarballs, 7.24.1 eight, 8.2.0
four, and 8.3.0 and 8.3.1 none. The Node version is not the variable — the six failures span Node
14.18.0, 16.2.0, 16.13.1 and 17.0.0 — and neither is the time filter, since 8.3.0 comes back clean
through the same mirror at the same moment. The errors are decompression
failures partway into a body that began as valid gzip, with no integrity failure anywhere in the
log, which is what a spliced stream looks like from the inside.

**Why it survived those releases.** It does not fire against `registry.npmjs.org`: npm 8.1.2 pulls
`mocha@7.2.0` clean from the real registry over HTTPS and over plain HTTP alike. That CDN's timing
misses the window; a mirror that resolves each request upstream lands in it. Nothing we can serve
avoids it. Against a 14-tarball baseline, adding `Content-Length` moved it to 7, `Connection: close`
to 15 or 11 depending on framing, and a warm in-memory cache serving at full speed to 6 — counts
that wander because it is a race, and none of them zero. Taking npm's own concurrency away is the
only thing that does: `maxsockets=1` gives zero in the repro, at every affected version tried.

So `tools/npm/npx.yaml` exports `npm_config_maxsockets=1` for npm 7.0 through 8.2 and nothing else,
on both of its branches. The guard is a shell `case` rather than a template comparison because the
boundary is the part that is easy to get wrong — `8.1.*` must catch `8.1.2` and must not catch
`8.10.0` — and the test runs that `case` under a real `sh` instead of grepping for a string the
rendered script contains either way.

**The re-run.** The six targets again, same base image, same `mirror-only` egress: `is-glob@4.0.3`,
`glob-parent@6.0.2`, `path-exists@5.0.0`, `bytes@3.1.2` and `on-finished@2.4.1` reproduce `exact`,
and `ansi-colors@4.1.3` reaches a comparison and diverges. Six results that were a statement about
us are now six statements about packages, which is the only thing this was ever costing.

It is a race and not a switch, and the re-run says so: `glob-parent` still logged one
`seems to be corrupted`, retried, and got it right. Five of the six saw none at all and none reached
`Z_DATA_ERROR`. Serializing turns a build that dies into a fetch that occasionally retries — worth
stating plainly, because a fix described as elimination would be wrong the first time someone sees
that warning again.

**What the name cost.** For as long as the code said `mirror`, every reader who met it started at
the mirror, and successive investigations did exactly that — the ruling-out recorded in §5 is all
mirror-side. The rule is now
`trigon/client-corrupted-download`, which is what the evidence supports: a build could not read
something it downloaded, and the reason is not yet attributed by the name. It stays `Fault::Bug`
and stays ours — we chose the pin — but it no longer accuses a component that was reading and
serving the right bytes the whole time.

### 3.27 Four things wrong on the path nothing had walked

Asked for a package that fails to build and then builds after a model repairs the recipe, the
honest answer turned out to be that the repair path had never been run end to end against a live
provider. Four faults, in the order they blocked each other — each one hidden behind the one before.

**The rule that chose the target was wrong about every target.** `npm/peer-conflict` matched bare
`ERESOLVE`, which npm prints as a **warning on installs that succeed**, and `classify` scans
backwards for the last line any rule claims. So it caught every unnamed npm failure in the corpus.
Counted rather than estimated: **0 of the 197 build logs contain `npm ERR! code ERESOLVE`, and 7
contain only the warning.** The rule had a 100% false-positive rate and had never once named the
thing it is called after. `ts-node@10.9.2` dies on `unzip is required to install dprint`; it was
filed as a peer conflict, and a repair loop reading that file would have gone looking for a
dependency conflict that does not exist.

This had been diagnosed once before. The comment on `npm/workspace-unbuilt-sibling` in
[`failure.rs`](../crates/trigon-core/src/failure.rs) records it exactly — "with no rule for this one
the scan ran past it to `npm WARN ERESOLVE` ... so a workspace link error was reported as
`npm/peer-conflict`, and the repair loop spent a model call fixing a peer conflict that was never
the failure" — and the fix was to name that one new symptom. Naming symptoms treats instances; requiring `npm ERR! code ERESOLVE` treats the cause, and
an unnamed failure now falls through to `unknown`, which is the honest bucket.

**The second target was a class the system had already ruled out and then paid to ask about.** With
the misattribution gone, `ts-node` classified as `env/missing-tool:unzip` — `repairable: true`, so
the loop spent a call. The model answered correctly and completely:

> adding `needs: [unzip]` would fail with `env/base-image-incomplete`. None of the registered npm
> tools can suppress that lifecycle script, exclude the lint-only dependency, or build dprint from
> source. Emitting a recipe would therefore be knowingly non-runnable.

Which is what `builder.rs`'s own preamble tells it: the image is fixed before the recipe is read.
The distinction that survives is between a tool **our recipe** reached for and a tool the
**package's own install script** demands. The first is avoidable — `env/missing-tool:npx` was fixed
by a strategy that stops calling npx — and stays repairable. The second is not, and now says so.

**The provider was discarding answers it had already received.** The Copilot CLI streams an answer
as `assistant.message_delta` chunks and only then emits the `assistant.message` holding all of it.
A turn cut short after the model began writing therefore has the answer on the wire and no event
carrying it. Three of four real repairs failed this way, reported as "no assistant message among 65
events" — which reads like a wire-format change rather than a truncation, and sent this
investigation looking at the parser twice before looking at the stream.

Reassembly keys on whether the message the turn was **last writing** ever got its consolidated
event, not on whether any message did: one turn can carry several, and an earlier completed one
sits in the stream looking like an answer. Taking it would answer an older question confidently.
A test pins that trap and caught the first implementation of this walking straight into it.
Where a turn stops before any text at all, that is now `EmptyTurn` — distinct from `Malformed`,
which says an answer arrived and could not be read, and from `Truncated`, which says a budget *we*
set was too small — classified `Fault::Infra`, retryable, with one retry inside the provider.

**And then the repair cost the run the answer it already had.** With answers no longer discarded,
the loop got a proposal: a recipe that rendered an **empty build phase**. `usable()` exists to stop
exactly this before a proposal replaces a working strategy, and it renders — but
`Instructions::executable` is deliberately *not* part of `render`, because `trigon strategy render`
has to be able to show a deps-only fragment. So the guard checked one of the two things the
executor checks. The proposal passed, replaced the strategy, and the next iteration died on an
error carrying no signature.

`report.failure` is assigned from each iteration's error, so that error assigned `None` over the
`npm/workspace-unbuilt-sibling:xstate` the run had genuinely found. The record read
`outcome: error:infra, failure: None` — a real verdict about a recipe, replaced by a suggestion for
improving it, which the comment at the call site says in as many words must never happen. The guard
now asks for both, and the failure is set and never cleared.

**What the exercise was worth.** No package was repaired. What the attempt found is four defects on
a path that every `--model` run takes, three of them invisible from the outside: a rule that was
wrong about everything it named, a class of spend that could never pay off, a provider that dropped
good answers, and a guard that let a bad one destroy a good verdict. A demo would have shown one
package building. This showed why none of them could.

### 3.28 A profile that exists, and nothing selects

`trigon stabilizers` lists the passes in one profile and needs you to know its name. There was no
way to see the set, so nothing ever asked the question a listing asks by existing: **does anything
reach this one?**

`npm-tarball` does not. The selector matches on extension — `.whl`, `.crate`, `.gem`, `.nupkg` — and
an npm tarball is `.tgz`, which matches nothing, so it falls to `default_for(TarGz)` and gets plain
`tar-gzip`. Checked against the store rather than by reading: every npm comparison blob carries
`["tar-gzip", "4598411b…"]`. `npm-install-fields` has never run on anything this tool has verified,
and [`03`](03-ecosystems.md) §1 said for months that it had.

This is the `nupkg` finding in reverse. There, the selector named a profile that did not exist and
the lookup failed into the plain zip set, so the table claimed a NuGet-specific normalization the
system could not perform. Here the profile exists and the selector cannot reach it. One table now
serves both the selector and the listing, so a profile nothing selects is printed as such:

```
Nothing selects one profile: npm-tarball. An artifact of that shape gets the fallback for its
format, so these passes never run and the normalization they describe does not happen.
```

**Left unfixed on purpose.** Routing `.tgz` to `npm-tarball` changes the set digest every npm
statement carries, so the statements written before the change stop matching the ones after it, and
`npm-install-fields` starts firing on artifacts whose verdicts are already published. That is a
decision about verdicts. A test pins the list of unselected profiles at exactly `["npm-tarball"]`,
so the list shrinks deliberately and never grows by accident.

---

### 3.29 The image could be labelled from source it was not built from

`trigon mirror-image` labels the image it builds with a digest of the workspace, and
`warn_if_stale` compares that label against the running binary's. The warning fires on every
command that uses the mirror, and it has been right every time it fired.

It could have been wrong in the direction that matters. The Containerfile mounts a cache at
`/src/target` — without it a one-line change recompiles ~180 dependency crates against musl, which
is most of why this image goes stale and stays stale — and `COPY . .` writes the context's files
with normalized timestamps. Cargo decides whether to recompile from those timestamps. So a crate of
**ours** whose source changed could look unchanged to cargo and be served from the cached rlib of an
earlier build, while the label was computed from the current tree.

Found the loud way, three times in a row: the build failed on `note_remote`, a function that was in
the tree and not in the compiled library. The quiet way is the same mechanism with the arms
reversed — a removed function, a changed constant, a rule deleted from the failure table — producing
an image that carries older behaviour, labelled as current, with the staleness check comparing
labels and saying so. `--egress mirror-only` is enforced by that image; a mirror serving the routes
it was built with is the failure mode the warning exists for, and this would have made the warning
lie.

The fix is one line before the build: `find crates -name '*.rs' -exec touch {} +`. It invalidates
our seven crates and leaves the dependency rlibs cached, which is the split the cache mount was
there for in the first place.

**The shape, again.** Two things that had to agree — what the label describes and what the binary
contains — with nothing asserting they did. The label was derived from the context and the binary
from cargo's opinion of the context, and the two have different definitions of "changed".

---

### 3.30 What the tool does with a corpus nobody chose

Every rate this project has published came from a corpus assembled on purpose: targets picked
because they record a `gitHead`, stratified by build system, chosen to exercise a path. That is the
right way to measure a pipeline and the wrong way to find out what the pipeline meets. So: 125
targets drawn uniformly at random — 50 npm, 50 PyPI, 25 NuGet — at `mirror-only`, four lanes.

| | reproduced | divergent | build-failed | no-strategy | ours | total |
|---|---:|---:|---:|---:|---:|---:|
| npm | 3 | 4 | 5 | 37 | 1 | 50 |
| pypi | 0 | 0 | 10 | 38 | 2 | 50 |
| nuget | 0 | 0 | 21 | 4 | 0 | 25 |
| **all** | **3** | **4** | **36** | **79** | **3** | **125** |

**Seven of 125 reached a comparison at all.** Three of those seven reproduced. Both numbers are
about the corpus rather than about the tool, and that is the finding: **63% of a random sample
declares no repository**, so there is nothing to build from and nothing to compare. The reproduction
rate of a random package is not a number this tool can produce, because the question does not arise
for two thirds of them.

The decline reasons, which reach the record because `declines` now has a reader:

```
  30  npm-heuristic: the registry declared no repository for this package
  16  pypi-heuristic: the registry declared no repository for this package
   3  nuget-heuristic: the registry declared no repository for this package
   8  … the package declares X and no tag there matches version Y
```

**Three quarters of the build failures are one missing tool.** `env/missing-tool:dotnet` took 21
targets and `env/base-image-incomplete` another 10 — 31 of 36. NuGet is 21 of its 25 targets, which
is `docs/21-base-image-automation.md`'s premise with a number attached: the base image is chosen
before the strategy is known, and a corpus that is not npm-and-PyPI-shaped finds that out
immediately.

**Five `unknown`s, and `unknown` is `Fault::Build`.** All five were charged to packages and none was
about one. Two causes, and neither was what the build logs suggested at a glance:

- `src/refused-url` — `ssh://git@gitlab.com/…`, which we decline to hand to `git` because an ssh
  client in a build is a credential channel. `Fault::Policy`.
- `src/fetch-failed` — `git fetch` failed on the host before anything built. `Fault::Upstream` and
  retryable; two of the three were `github.com`, which is ordinarily reachable.
- `env/no-ssh-client` — the one that reached a container: `npm install` cloning a `git@github.com:`
  *dependency*. The dependency is the package's choice; the reason the run produced nothing is ours.

The first attempt at these rules matched `cannot run ssh` and `Could not resolve host` — the strings
in the build logs. Four of the five runs never reached a container, and `classify` had been handed
**our own error message** instead. The rules were written against text that was never classified.
Reading what the record actually holds, rather than what the logs nearby happen to contain, is the
lesson; the tests carry the recorded evidence verbatim.

**And one of the five had no evidence at all.** npm prints four lines after a failure telling you
where to report it, so `last_interesting` — the last line long enough to be interesting — returned
`npm ERR!     /src/npm-debug.log`. That string was the recorded evidence, the cluster key, and what
a model would have been shown, for a failure whose cause was six lines above and had a rule. Trailers
are now skipped.

Re-classified from the logs on disk, the sweep has **no unknowns**: 21 `env/missing-tool`, 10
`env/base-image-incomplete`, 3 `net/unreachable`, 2 `env/no-ssh-client`. Not one is `Fault::Build`.

**Two things the sweep broke that were not about packages.** The wall detector stopped the first
attempt after ten targets, because ten `no-strategy` in a row is a wall on a curated corpus and the
answer on a random one; it is now `--wall <n>`. And the run that looked like a hang was one target
paying the cold-cache cost for all 125 — 239 fetches, 95 MB, including the 22 MB `npm` packument
ADR-0013 named as 18% of a sweep's egress. Every target after it read those off disk: **27% of all
bodies served came from cache**, against 3,537 bodies and 9,354 upstream requests for the whole run.

---

## 4. A stabilizer the reference does not have

`wheel-metadata-eol` normalizes CRLF to LF in the four files a wheel builder *generates*. A publisher
on Windows gets `\r\n` in `METADATA` because the tool opened the file in text mode; we cannot
reproduce Windows text-mode I/O from a Linux builder, so normalizing is the only route to a match.

It is worth recording how it was reviewed, because the process is the point:

- **Impact preview before merge.** Across the M1 PyPI corpus: one flip (`sniffio`), no other verdict
  moved. Two of 58 M0 artifacts carry CRLF metadata, one of them named `feagi_bv_windows`.
- **The differential refused it** until it was declared. `0 unexplained` became `2 unexplained`,
  which is the test doing its job: a pass the reference implementation lacks cannot go green without
  a prose reason in `corpora/deviations.toml`.
- **The scope is the whole argument**, so it is tested from both sides. A `.py` file keeps its CRLF —
  the author's choice, part of what is under test. A hand-written `dist-info/LICENSE` keeps its CRLF,
  because `dist-info/` is not a licence to rewrite everything inside it. A lone `\r` is content.

This is the first stabilizer added on evidence from a live corpus rather than from the reference
implementation's catalogue, and the review path in [`05`](05-archive-and-normalization.md) §6 worked
as written.

---

## 4b. A core module where the design says component

`docs/09-attestations.md` §7.1 specifies stabilizer sets shipping as **WASM components**, instantiated
under `wasmtime`. What ships is a **core module** for `wasm32-unknown-unknown`, with a four-function
ABI over a byte buffer.

The component model means `wasm32-wasip2`, WIT definitions and `cargo-component`. A core module gets
the whole benefit of the criterion — an archived set that *executes*, so a claim made under a set the
verifier's binary does not carry is checkable rather than merely describable — with a host that needs
no WASI implementation at all, and a toolchain that is one `rustup target add`. What it gives up is a
typed interface for guests written in other languages, which begins to matter when somebody writes
one.

Two things about it are worth knowing before relying on it.

**Host and guest share a crate.** The ABI — a packed `(ptr << 32) | len` return, an append-only
format numbering — has one definition rather than two that drift. Two crates agreeing on a calling
convention by comment is two things to keep in step.

**An archived set can reach `NormalizedWithCaveats` and never `Normalized`.** The provenance cap
needs each applied stabilizer's risk tier and provenance, and a module that returns bytes cannot
supply them. The ABI could be extended to report an `applied` list, and then the cap would rest on
what the module says about itself — which is exactly the wrong place for it. So the archived path
claims the weaker outcome on the weaker evidence, and a `Normalized` claim re-derived through its
archived set reports `NormalizedWithCaveats` and reads as refuted. That is a real limitation rather
than a rounding error: it is honest, and it is not yet good enough for a verifier checking an old
`Normalized` claim. Revisit if the interface ever becomes typed.

`wasmtime` is behind a feature and on the verifier's forbidden list: 100 crates by default, 142 with
`--features wasm`. The small tree is the claim a sceptic checks instead of trusting us, and a
verifier who only checks claims made under their own set should not pay for a runtime they never
use.

---

## 5. Open

**An archived `Normalized` claim re-derives as `NormalizedWithCaveats`.** See §4b: the provenance cap
cannot be confirmed from bytes alone.

**Closed: `trigon/mirror-corrupted-artifact`.** Left here as a signpost, because this is where it
sat open across three investigations that each began at the mirror. It was never the mirror: npm 7.0
through 8.2 splices the tarballs it fetches concurrently, the rule is now
`trigon/client-corrupted-download`, and the affected range is serialized. See
[§3.26](#326-the-corruption-was-named-after-the-wrong-component).

**Two clean re-runs before publishing a divergence.** [`10.3`](00-overview.md) requires it and
nothing implements it yet.

**The corpora are smoke sets.** Twenty npm and seventeen PyPI targets, not sampled by prevalence.
Every percentage here is a signal about the pipeline, not an estimate of an ecosystem, and
[`15`](15-corpora.md) §2 says what a real corpus needs.

### 3.31 A page that judged under a set the run never used

**Correction.** `trigon watch`'s `/compare` derived the stabilizer set from the artifact's
**format**. A run does not: `resolve_profile` reads the file name first — `.whl`, `.crate`, `.gem`,
`.nupkg` — and falls through to the format only when none matches. A `.nupkg` is a zip, so the
page's digest ladder, member table and note list were all computed under the `zip` set while the
verdict printed beside them had been computed under `nupkg`: six passes short, among them
`nupkg-text-eol`, which decides members on exactly these packages.

Measured on `Newtonsoft.Json@11.0.1`: the page said **29 members, 18 differing**; the record said
**23 and 10**.

Found within a minute of the chain ribbon existing, because the ribbon prints the set and the set
it printed disagreed with the run's own stored record — the third instance this tree has recorded
of *two things that had to agree, with nothing asserting they did*. The assertion now exists, over
the CLI's own extension table, so a kind added there is covered without anybody remembering.

### 3.32 A corpus that could not hold a failure

**Gap, found by building the thing that reads it.** `record_run` had one call site, past the early
return that unwraps the comparison. So a `no-strategy`, a build failure, a tripped guard and an
infrastructure error all left the store untouched, and nothing noticed for as long as the only
reader was a person who already knew.

Pointing the new corpus browser at this machine's store said it out loud: **32 runs, 32 of them
evidence, zero failures** — on a project whose last random sweep reached comparison 7 times in 125.
A browse page over that store reports a reproduction rate of one.

Three fields were needed, not one. `outcome` is what a *comparison* produced and must stay one of
the four matches; `failure` is a signature, and a `no-strategy` is a scope statement with no failure
in it. Without a third field — `terminal` — every run that reached no verdict was indistinguishable
from every other, and the page could only file them as `unclassified`, which is the word for a
cause nobody named rather than one that was named and dropped on the way to the store.

### 3.33 The safeguard enforced by nothing, and what it cost to enforce it

**Correction, and a measurement.** [`ADR-0010`](adr/0010-publish-divergences.md)'s first safeguard
is two agreeing attempts before anything publishes, divergences and matches alike.
[`12-security.md`](12-security.md) records invariant 12's enforcement as the word **nothing**, and
that was accurate: no component in the system had ever asked the same question twice.

The publication gate went in first and immediately withheld the entire corpus — 32 runs, every one
`awaiting_confirmation`. That is the correct answer to a single-attempt corpus and a useless
website, and it is what made the rest of the work concrete rather than theoretical.

What closed it: `attempt` and `cache_key` on the record, so two runs can be shown to be attempts at
the same work; and a worker loop that enqueues a second, independent attempt after a verdict, at
`Regression` tier and delayed, because the risk the safeguard exists against is ambient
nondeterminism and two runs back to back on a warm cache sample the same moment twice.

Measured end to end: `left-pad@1.3.0` built by worker `w1`, confirmed by worker `w2`, and shown to
an anonymous reader as **published** — the first result this project has released under the ADR's
safeguards rather than in spite of their absence.

### 3.34 Five bugs that only running it found

**Gap.** Each of these compiled, passed the existing tests, and was wrong.

- **A page's own Content-Security-Policy broke its bar chart.** `style-src 'self'` blocks the
  `style` *attribute*, so four proportional bars were written, silently dropped by the browser, and
  drawn at the track's full width. The page looked finished until somebody compared the bar lengths
  to the numbers beside them. CSP does not govern CSSOM, so the fix was to assign each property
  rather than to add `'unsafe-inline'`.
- **A permalink painted the word "Loading"** into every preview of itself, three times, each with a
  different cause: no boot island at all, then an island that covered only the browse view, then a
  view that awaited `/v1/me` — an identity that depends on a token the server never saw and so
  cannot be booted at all.
- **Two concurrent SQLite leases deadlocked** with `database is locked`. A deferred transaction
  that becomes a writer cannot wait. The lease became one `UPDATE … RETURNING`, which is atomic in
  both backends and takes `FOR UPDATE SKIP LOCKED` in the Postgres subquery.
- **`RETURNING` does not preserve the subquery's `ORDER BY`.** The tier decided which rows were
  taken and not what order a worker received them in, so a bulk sweep job could be built ahead of
  an interactive one held at the same moment.
- **A worker acknowledged infrastructure failures as completed work.** `run_one` returns `Ok` for
  every terminal outcome including the ones that say *we* could not test this package, so one
  worker on a broken machine would have drained a queue without building anything.

And one that is the same shape as §3.31 and §3.28: **five copies of the mirror-image default**, of
which the newest drifted to a tag that does not exist. It surfaced as a connection refused to
`localhost:443`, which says nothing about the mistake. Two commands that must build identically
cannot have two defaults; a literal repeated five times is four opportunities for exactly this.

### 3.35 Two tests that were wrong in the way the code was right

**Gap.** Worth recording because both were written *as* guards and both guarded the wrong thing.

A test asserting this crate cannot reach the comparator scanned its own source for the forbidden
name — and the needle was a string literal in the file doing the scanning. The `pgrep -f` shape,
in a test. Then, fixed to skip the test module, it failed on `lib.rs`'s module documentation, which
states the rule by naming the function it forbids: a check that a file may not *discuss* what it may
not *call* forbids writing the rule down. The durable version is the manifest, where a crate that
does not depend on the comparator cannot reach it however the code is arranged.

A host-budget test asserted durations and failed by five milliseconds — twice, once to a real bug
and once to the database round trips themselves. A reservation is absolute, so a caller arriving
late is correctly told to wait less. The invariant has no timing in it at all: each reservation
advances the stored floor by exactly one interval.

### 3.36 A rule that had to move down rather than be written twice

**Correction.** `caps_normalized` — *does this pass hold the verdict below `normalized`* — lived in
`trigon-compare`, which was right while the comparator was the only thing that asked. Then a page
wanted to show a reader which passes had cost them a clean verdict, and `trigon-api` deliberately
does not depend on the comparator: a crate that cannot reach it cannot produce a `Match`, whatever
its handlers do, and a test asserts the absence.

That left two bad options — link the comparator into a read-only HTTP surface, or write
`provenance != Builtin || risk > Metadata` a second time — and one good one. The rule is about
`RiskTier` and `Provenance`, both of which are `trigon-core` types, so it belongs beside them.
`trigon-compare` now projects onto it.

**Moving a seam down is how ADR-0008 survives a second caller.** The alternative, and the thing the
first instinct reaches for, is to duplicate the predicate and promise to keep the copies in step —
which is the defect §3.31 and §3.28 are both instances of.

### 3.37 The evidence classes gated the wrong property

**Correction.** The class table refused a comparison to an anonymous reader on the grounds that it
"lists member paths taken from the artifact under test". That reasoning treats the paths as secret,
and they are not: the same paths reach a signed `divergence/v1` statement, which is served to
anybody who asks.

What is actually dangerous about the stored blob is its **size**. D9 disclaims any bound on the size
of a difference summary, so one anonymous request against a pathological artifact is an amplifier.
The control is the bound.

So the rendered view — counts, the digest ladder, the stabilizer ledger, and a member list capped
at 500 with the remainder stated — is anonymous, and the unbounded blob stays gated. Getting this
wrong in the cautious direction had a cost that is easy to miss: a public site that shows a verdict
and cannot say what it is about is missing most of the product.

### 3.38 Four first frames, and the rule that was missing

**Gap.** An SPA that fetches its own data paints "Loading" into every link preview, screenshot and
slow connection. This page did it four times: the browse view, a permalink, the queue, and the run
page again the moment a comparison fetch was added in front of `replaceChildren`.

Each fix was correct and local. None generalised, and the fourth instance landed *after* the third
was documented. The bug is not in any view — it is that `await` before a paint is one keyword, reads
as ordinary, and is invisible until somebody looks at a rendered screenshot.

What closed it was not a fifth fix but a named helper and a stated rule: **paint first, fetch
second.** A view puts up a slot, hands `fillLater` the promise, and carries on. Worth recording
because the pattern generalises past this page: *a defect that recurs after being fixed and written
down is a defect whose fix was an instance rather than a rule.*

### 3.39 A hex view that showed the wrong 8 KB, and a cap that reported nothing

**Gap, in two parts, both found by pointing the thing at a real DLL.**

The first version dumped the first 8 KB of each copy. On `lib/net20/Newtonsoft.Json.dll` — 513 KB,
identical PE header — that is two screens of bytes that agree and none of the difference, which
starts at offset 0x88. A hex view has to find the differing runs first and show a window around
each; starting at zero is only right for a file that differs at zero.

The second is worse because it looked fine. With the runs found and coalesced, the byte budget went
to whichever region asked for it first. That DLL's 37,039 differing runs coalesce into two regions,
the second spanning nearly the whole file, so it took the entire budget and was silently truncated
to fit — and `regions_omitted` reported **zero**, truthfully, because no *region* had been dropped.
The page showed 1 KB of a 470 KB difference and said nothing was missing.

Two changes. `differing_bytes` beside `shown_bytes`, so the numbers carry the denominator: *469,719
bytes differ, across 37,039 runs; showing 1,264.* And no region may take more than its share of the
budget, so four separate differences get four windows instead of one.

**The rule worth keeping:** a cap that counts only the units it happens to iterate over is a cap
that lies about every other unit. `regions_omitted` counted regions; the thing being truncated was
bytes.

### 3.40 A `.tgz` is not a nested archive

**Correction, caught by a vacuity check.** The comparison names a member inside a nested archive
`outer!inner/path`, and `trigon-api` has to resolve that name without linking the comparator — two
walks of one tree, so a test builds a nested archive and demands every name the comparison produced
resolves in the other walk.

The first fixture was a gzipped tar. That produces no `!` at all: gzip is the *container* of
`Format::TarGz`, not a member of it, so its entries are named plainly. The test would have passed
while asserting nothing about the case it exists for.

It failed instead, on the line that exists for exactly this: *"the fixture is not nested any more,
so this test asserts nothing"*. Real nesting needs an archive inside an archive — a `.gem`, whose
members are themselves gzipped tars.

**Worth recording because the vacuity check is the cheap half.** A test that builds its own fixture
can stop testing what it claims to without failing, and the assertion that the fixture still has the
property under test costs one line.

### 3.41 A fragment is the wrong place for anything a server should render

**Correction.** The open member lived in `#member=…`. That is the natural home for in-page state and
exactly the wrong home for a link somebody sends: **a fragment is never transmitted to the server**,
so the one thing a deep link most wants rendered was the one thing the document could not carry.

Moving it to `?member=…` let the run document boot the panel. Two consequences worth stating:

**The gate has to be asked at document-render time.** A member's bytes are `Class::Artifact`.
Putting them in the page for a reader who may not fetch them would move the content from a route
that refuses to a page source that cannot — the same reasoning that already made the publication
gate re-run while filling the island. An anonymous reader gets `"member": null`; so does a reader
signed in with a bearer token, because a browser sends a token on an XHR and not on a document
request. Identity cannot be booted, which is the limit `/v1/me` has had since it existed.

**Booting half of it is not obviously better than none.** The member panel is drawn *inside* the
member table, which the rendered comparison produces — so booting the member alone saved a request
and still left a reader watching a placeholder. Both are booted, the comparison bounded at 192 KB
and measured after rendering rather than guessed from a member count.

Measured: a deep link to a member diff now makes **no requests at all**. 19.8 KB of document
carrying the verdict, the ladder, the census, the ledger, 23 members and the open diff.

And the test that had to exist first. Until this, the boot island held package names and counts. It
now holds the bytes of a file somebody else published — the most attacker-controlled thing on the
page — so a member whose content is `</script><script>…` would be executing on this origin before
the first paint. `a_members_content_cannot_close_the_island` asserts it isn't.

### 3.42 Three reasons a file has no bytes, reported as one

**Gap, found by pointing the new route at a run that reproduced.** "This member has no bytes" has
three causes and they were one message:

- **Retention dropped the artifacts.** Bytes are kept on a divergence and dropped on a match, so
  this is the normal state for most of a corpus.
- **The artifacts are there and the member is not.** A fact about the package.
- **The member would not read.** A fault.

The route said *"neither artifact holds a member by that name"* for all three. A reader told that
about a clean match — where the bytes were simply never kept — would go looking for a member that
is there.

The fix is a `Pair` that carries `kept` per side rather than collapsing "not kept" into "not
found", and three refusals with three codes. **The shape is the one this document keeps recording:**
two states that a reader must distinguish, merged at the point where the code found it convenient
to treat them alike.

### 3.43 A dropped connection and a dead server are the same thing to a browser

**Gap, reported as a crash.** A user saw *"Not shown. NetworkError when attempting to fetch
resource"* on a member diff and reported that `serve` had crashed. It had not: a stray cleanup had
killed the process out from under the page.

The report was still worth having, because **there was no way to tell**. A panic in an axum handler
unwinds out of the connection task, hyper drops the socket, and the browser reports a transport
error — identical to what it reports for a server that is not listening. Neither the page nor the
log tells a reader which they are looking at, so the one useful report — *what broke* — cannot be
given.

Two changes, both about making a bug legible rather than about any particular bug:

**A `catch_panics` layer.** A panicking handler answers `500` carrying the panic's own message,
logged with the route that reached it. The front-end already renders a refusal's `detail`, so the
next occurrence arrives as *"this request hit a bug in the server: index out of bounds…"* against a
named address.

**The index lock recovers from poison.** Every reader was `.read().unwrap()`. `std::sync` poisons a
lock when a thread panics holding it and every later `unwrap` panics too — so one bug under the
write lock in `refresh` would have made every subsequent request fail for the life of the process,
which is a crash by any useful definition. Poison is the right default for data whose invariants a
panic may have broken; an index is a cache rebuilt from the store on the next refresh, so it
recovers and warns.

And a bug in the handler for bugs, caught only because its test asserted on the *message* rather
than the status: `&payload` on a `Box<dyn Any + Send>` unsizes the **box** to `&dyn Any`, so the
downcasts found a `Box` and every panic reported "the panic carried no message". The status was
right the whole time.

### 3.44 A test that had no timing in it, and flaked on timing

**Correction, third time on one test.** `the_fleet_reserves_slots_rather_than_racing_for_them` has
now been wrong about time three ways. The first two measured how long a caller was told to wait and
failed by five milliseconds — once to a real bug and once to the round trips themselves. §3.34
records the fix: assert the *stored floor*, which has no timing in it.

It flaked anyway, once, on a loaded machine: it expected the floor to advance by exactly one
interval and got 76 ms where it expected 50.

**That failure was the test being wrong about the code.** `reserve_host` computes
`max(stored_floor, now) + interval`. When more wall clock passes between two calls than the interval
itself, the stored floor has *lapsed*, `now` wins, and the new floor lands further than one step
away. That is correct — a reservation must not hand out a slot in the past — and the exact-step
property only ever held while reservations arrived faster than the interval. A 50 ms interval on a
contended machine does not.

The exact step is now asserted at a ten-second interval, which no scheduling delay reaches. What
holds unconditionally is asserted separately: the floor only moves forwards, and a reservation
always leaves it in the future. Between them that is what a rate limit needs.

**The lesson is not "avoid timing in tests".** It is that "I removed the timing" is a claim worth
re-checking: the third version genuinely read no clock, and still encoded an assumption about how
much time would pass between two of its own statements.

### 3.45 A cap that is checked after the thing it caps has been loaded

**Gap, and a measurement.** An adversarial audit of the member-diff routes asked what one request
costs in memory. Measured, on this machine:

| artifact, per side | status | peak RSS |
|---|---|---|
| 200 MiB | 200 | **409 MiB** |
| 300 MiB (over `MAX_ARTIFACT`) | 404 | **608 MiB** |

Two things in that table.

**A member request costs twice the artifact.** It fetches and parses *both* copies to compare one
file inside them, which is inherent — you cannot diff one side. With `MAX_ARTIFACT` at 256 MiB that
is half a gigabyte per request, and nothing bounded how many ran at once. Unbounded concurrency over
an unbounded multiplier is how a process gets killed, and a killed process is what a reader calls a
crash. Member reads now hold one of four permits.

**The over-cap row is the sharper finding.** That request was *refused* — and it still cost 608 MiB
first, because the size check lived inside `member::read`, which runs after the whole artifact has
been fetched from the blob store and copied into a `Vec`. The record has carried the artifact's size
all along. Refusing from the record turns the common refusal from half a gigabyte into nothing.

The post-load check stays, because a record can carry a wrong size and only the bytes settle it.
The pre-check is an optimisation; the permit is the guarantee.

**The shape:** a limit enforced at the point where the expensive thing is *used* rather than where
it is *acquired* does not limit the expense. It only limits the answer.

### 3.46 The conversion protected everything except the hot path

**Correction, found by an audit rather than by the change's own review.** When every index reader
was converted from `.read().unwrap()` to a helper that recovers from lock poison (§3.43), one was
missed: `entry()`. `rustfmt` had split its call across four lines, and the edit that fixed the
others matched the single-line form.

`entry()` is called by every run page and every diff route. So the conversion protected the
accessors nobody would have noticed and left the one that would have taken the site down.

Three independent reviewers flagged it. What none of them needed was cleverness — a `grep` would
have found it, which is exactly why the guard is now a `grep`:
`no_accessor_takes_the_lock_without_recovering_from_poison` strips whitespace from the module's own
source and asserts the lock is taken in the two helpers and nowhere else.

The first version of that guard normalised runs of whitespace to single spaces, and therefore
matched `self.inner\n.write()` but not `self.inner.read()`. **A check for a formatting-dependent
mistake that is itself formatting-dependent is not a check.**

### 3.47 One bad query parameter discarded the deep link

**Gap, in code three commits old.** `?member=x&offset=abc` booted nothing. Deserializing the
document's query into a struct is all-or-nothing, so an unreadable `offset` failed the whole parse
and `unwrap_or_default()` threw away the `member` beside it. A reader whose link did nothing would
have had no way to connect that to a parameter with no bearing on which member they asked for — and
`?utm_source=` pasted on by a link shortener would have done the same.

The query is read one field at a time now, from a `Vec<(String, String)>` that cannot fail on a
value. A bad `offset` costs the offset.

**The shape:** a parse that binds several independent fields together makes every field as fragile
as the most fragile one. It is the "two things merged where the code found it convenient" pattern
again, in the request parser rather than in a record.

### 3.48 The input was capped; the output was not

**Real, and measured before it was believed.** A reviewer claimed the text diff could produce an
enormous response. `MAX_TEXT` caps a member at 2 MiB, so the claim looked like it had already been
answered. It had not: the cap bounds the *bytes read in*, and the diff's size is set by the *number
of lines* those bytes contain.

The worst case is two MiB of bare newlines against two MiB of `x\n` — a file of nothing but line
breaks, which is the most lines two MiB can hold. Both middles are past `MAX_ALIGN`, so the view
takes the unaligned path and reports the whole middle as removed and re-added: 2,097,152 removals
plus 1,048,576 additions. Measured:

| | before | after |
| --- | --- | --- |
| line structs | 3,145,728 | 2,000 |
| JSON body | 86 MB | 61 KB |
| serialize | 3.52 s | 2.4 ms |
| four at once, peak RSS | 1064 MB | — |

The 86 MB number is the interesting one, because of how it fails. It is not a crash. The server
builds the body, spends three and a half seconds serializing it, and sends all of it. What the
reader sees is a page that sits there and eventually gives up — which is indistinguishable, from the
browser's side, from the server having died. This tree had already chased that exact symptom once
([3.43](#343-a-dropped-connection-and-a-dead-server-are-the-same-thing-to-a-browser)), and the
answer there was to make a bug arrive as a sentence. A response that is merely too big to be useful
arrives as no sentence at all.

`MAX_DIFF_LINES` bounds the rendered diff at two thousand lines across every hunk, and both
constructions that skip `hunks()` — the one-sided "this file is new" view and the wholly-replaced
middle — are bounded on the same budget and asserted separately, because a bound that lives in one
of three constructors is not a bound.

What is dropped is counted and stated: `lines_shown + lines_omitted` equals every changed line, and
the test asserts that identity rather than either number, so it survives a change to the limit. The
count is taken from the ops the budget did not reach rather than from what the emit loop skipped —
those differ, and only the first is the number a reader is missing.

**The shape:** this is [3.45](#345-a-cap-that-is-checked-after-the-thing-it-caps-has-been-loaded)
pointed the other way. There, a limit sat downstream of the expense it was meant to prevent. Here a
limit sits upstream of an expense that is *not proportional to it* — two MiB of prose and two MiB of
newlines cost the same to read and differ by three orders of magnitude to render. A cap only caps
what it is measured in. Ask what the expensive structure is counted in, and cap that.

### 3.49 One sentinel, four refusals, and the wrong one printed

**Real, and found by running a test against a module four days old.** The stabilizer-parity suite
compares the archived WebAssembly stabilizer set against the compiled one. It failed with:

> the module refused: it could not parse the artifact under that profile

The artifact was a well-formed archive. The real cause was that `nupkg` had been added to the
native profile list on the 17th and the module on disk was built on the 14th, so it did not
implement that profile at all.

The guest returns `0` for an unknown profile, for profile bytes that are not UTF-8, for an
artifact it cannot parse, and for a result it cannot serialize. The host's `read()` turned every
one of those into the sentence above. A verifier who reads it goes and looks at the package, which
is the one thing that was fine.

This is [3.42](#342-three-reasons-a-file-has-no-bytes-reported-as-one) in a second crate: several
reasons a call produced nothing, reported as whichever one somebody wrote down first.

The ABI is archival — `format_from_u32`'s comment already says it may only be appended to, because
a module written today is read by a host built later — so the guest cannot start returning richer
sentinels without orphaning every module already in existence. The fix is therefore entirely on the
host:

- `digest()` no longer routes its zero through `read()`. For `trigon_set_digest` a zero has exactly
  one meaning the host cannot already rule out — the host built the profile string from a `&str`,
  so it is UTF-8 — and that meaning is "this module does not implement that profile". It says so,
  and names the profile.
- `stabilize()`'s zero is genuinely ambiguous, so on a zero it asks `trigon_set_digest` about the
  same profile. That question is answerable on its own, and answering it separates the two cases.
- `read()`'s remaining message no longer claims to know why, only what: the module refused *these
  bytes*, under a profile it does implement.

`check()` inherits the first of these, which matters most: `check` is the control that stops a
verifier running one stabilizer set while believing they ran another, and "your module predates
this profile" and "your module implements a different set" have different remedies.

**Also worth saying: the parity test could not have caught this in CI.** The `wasm-parity` job
builds the module from the same checkout it tests against, so it compares a fresh wasm build to a
fresh native build. That is a real check — two compilation targets can diverge — but it is not the
claim the crate exists for, which is that *an old archived set still answers correctly*. Nothing
tests an old module against a newer host. The drift was only visible because a stale artifact
happened to be sitting in `target/`.

**The shape:** a sentinel value carries no room for a reason, so the reason gets supplied by
whoever writes the error string, once, for the case they had in mind. If a function can fail four
ways and returns one `0`, the caller that must explain the failure has to re-derive which one — and
the place to do that is the caller, because the ABI is the thing that cannot change.

### 3.50 A 19.5 MB file that costs 8.2 GB to look inside

**Real, measured, and two separate defects wearing one symptom.** `GET /v1/runs/{id}/member` on a
run whose artifact is a `.tar.gz` held, at peak, **8213 MB of resident memory for a 19.5 MB
request**, and returned `200`. Four of those are permitted concurrently.

**First half — the container was held twice.** `Parsed::container` exists so a caller can digest the
decompressed container; `trigon-compare` is the only one that ever does, and it hashes the bytes and
drops them. It was a `Vec<u8>` *cloned out of the same buffer the tar reader had just been handed*:

```rust
let (header, inner) = gzip::read(&bytes, limits.total_expanded_bytes)?;
let mut a = tar::read(Arc::new(SourceMap::owned(inner.clone())), limits, notes)?;
…
Ok(Parsed { archive: a, container: Some(inner) })
```

`tar::read` does not copy member bodies — they are `Body::Original { src, off, len }`, windows onto
the `SourceMap`. So the `clone()` was the entire cost, and it was exactly 1.0x the decompressed
artifact, alive for as long as the `Parsed`. The `Gzip` arm did the same thing twice over, once for
the container and once for `Body::Inline(inner.clone())`.

`container` is now the same `Arc<SourceMap>` the reader holds, and the bare-gzip member is a window
onto it. Measured on the same input: **2064 MB → 1039 MB**, 2.006x the expanded size down to 1.01x.

The regression test asserts `Arc::ptr_eq` between the container and an entry's body rather than a
memory threshold, because "these are one allocation" is the actual claim and an RSS bound is a
flaky restatement of it.

**Second half — the cap was measured in the wrong unit, again.** That 1.01x is still 1.01x *of the
expanded size*, and nothing bounded the expansion. `MAX_ARTIFACT` refuses a stored blob over 256
MiB; the expansion ceiling was `Limits::default().total_expanded_bytes`, 4 GiB. Those are not the
same number and a gzip stream is where the difference lives: 19.5 MB of zeros reaches the ceiling
without approaching the cap.

`Limits::default()` is the right budget for a rebuild — one at a time, on a machine bought for it.
It is the wrong budget for an HTTP handler that permits four concurrent readers. Serving now uses
its own `total_expanded_bytes` of 1 GiB, which still opens every artifact anyone has pointed this
at and bounds the process at four of them.

This is [3.48](#348-the-input-was-capped-the-output-was-not) in a third place, and the general
statement is worth keeping: **a cap constrains the quantity it is measured in and no other.** Bytes
on disk do not bound bytes in memory; bytes in bound lines rendered; compressed does not bound
expanded.

**And the refusal named the wrong cause.** Tripping the limit came back as "the artifact would not
parse", which is what this file has now recorded four times under different names
([3.42](#342-three-reasons-a-file-has-no-bytes-reported-as-one),
[3.47](#347-one-bad-query-parameter-discarded-the-deep-link),
[3.49](#349-one-sentinel-four-refusals-and-the-wrong-one-printed)). The artifact parses fine. It is
just bigger than a web request will open. It says that now, and says the download still works.

`names()` had no size check at all. It has no caller outside tests, which is precisely the condition
under which it would acquire one.

### 3.51 The profile with the documented hazard was the one nothing tested

**Gap.** `stabilize(stabilize(x)) == stabilize(x)` is what a signed digest rests on. Every test of
it in the tree ran the `tar` profile — `tests/passes.rs`, `tests/properties.rs` — and the `stabilize`
fuzz target had its own hardcoded list of four more. Between them: `tar`, `gem`, `npm-tarball`,
`crate`, `wheel`.

Not covered: `zip`, `tar-gzip`, `gzip`, and `nupkg`. `nupkg` is the one that matters. It has seven
passes, and `profiles.rs` documents an ordering hazard in its own construction:

> **Before the zip set.** This renames entries, and `zip-entry-order` sorts them; a rename
> afterwards would leave the sort stale and the digest dependent on the order the two spellings
> happened to arrive in.

A hazard a comment warns about, in the only profile no idempotence test ran. It is in fact
idempotent — the fixture that exercises the rename, two spellings of one target framework
canonicalizing to the same name, passes. The claim was true. Nothing had checked it.

This is the second time this exact omission has happened here. `all_profiles()` once omitted
`wheel`, and its doc comment already says why that was not cosmetic.

So the new tests do not carry a list. They iterate `all_profiles()`, and a fourth test asserts the
fuzz target's table covers it too — by reading its source, since the fuzz crate is not a workspace
member and nothing can link it. A profile added tomorrow either gets a fixture or fails the suite.

**The shape:** an enumeration with a hand-written list of cases beside it will drift, and the drift
is invisible because the tests that exist all pass. Drive the cases off the enumeration.
