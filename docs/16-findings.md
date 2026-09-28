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

### 3.52 The page named members the artifacts had never heard of

**Real, observed on a live server against a real divergence, and the worst instance of the
recurring defect this file keeps recording.** On the Newtonsoft.Json 11.0.1 NuGet comparison —
published against a `dotnet pack` of its own source — **5 of the 23 members listed on the page were
dead links**. Clicking one gave:

```json
{"detail":"neither artifact holds a member by that name.","error":"no_such_member"}
```

The artifacts were fine. The name was ours.

**The mechanism.** `trigon-compare` names members from the **stabilized** archives, which is
correct and necessary: `lib/portable-net45%2Bwin8%2Bwp8%2Bwpa81/x.dll` on the published side and
`lib/portable45-net45+win8+wp8+wpa81/x.dll` on the rebuilt side are the same file, and only the
canonical name `lib/portable-net45+win8+wp8+wpa81/x.dll` says so. `trigon-api::member::read` walks
the **raw** artifact, where that canonical name has never existed on either side.

Two passes rename, both in `nupkg`: `nupkg-portable-folder-name` and `nupkg-packaging-names`. Four
dead links came from the first and one from the second — and the second is the instructive one,
because the `.psmdcp` part is named after a per-pack GUID:

```
canonical  package/services/metadata/core-properties/core.psmdcp
upstream   package/services/metadata/core-properties/096d3ae4d1ce45b083321775ef909fbc.psmdcp
rebuild    package/services/metadata/core-properties/4717a6a29ddb447e9aadfb4762f08a31.psmdcp
```

There is no single "real" name to fall back to. Each side has its own, and that is why the record
is per side rather than one field.

**Why it could not be fixed in the API.** The obvious repair — stabilize before walking — is
forbidden: `the_comparator_is_not_even_a_dependency` asserts that `trigon-stabilize` and
`trigon-compare` are not runtime dependencies of `trigon-api`, because the read path renders what a
run decided and must not be able to decide one. Re-implementing the canonicalization in the API
would be a *second copy of the renaming rule*, which is the same ADR-0008 defect one layer down.

So the seam moved down, which is how ADR-0008 conflicts have been resolved here twice before.
`Entry` gained `renamed_from`, set through a new `Entry::rename_to` rather than by assigning
`e.path`; `trigon-compare`'s `walk` carries a raw prefix beside the stabilized one, so a renamed
*container* also fixes up everything inside it; and `FileDiff` records `upstream_raw_path` /
`rebuild_raw_path`, present only where they differ. The API asks for them **only when a member was
not found under the comparison's own name**, so the common path costs nothing and the comparison
blob does not grow for the ecosystems where no pass renames.

Measured end to end, through the real server, on the real artifacts: **5 dead links of 23 → 0 of
23**, with both raw downloads and the hex view resolving.

**Two things this had that should have caught it.** The first is a test named
`a_nested_member_resolves_by_the_name_the_comparison_gave_it`, written for exactly this seam. It
passes, and always did: its fixture is a nested tar, and no pass renames a tar member. The second
is a manual sweep of every member of every run in the store, run earlier in the same session, which
reported no failures — against a store whose runs were all npm and PyPI at the time.

**The shape:** two implementations of one seam again, and the test guarding it was written against
the one input where the two implementations happen to agree. A seam test needs a fixture that
*exercises the difference*, not one that merely crosses the seam. Where a transformation exists,
the fixture has to be one the transformation changes.

### 3.53 Every long build was done six times

**Real, and the loop already said so.** `Progress::phase` renews a job's lease, so the lease lives
exactly as long as a worker keeps calling it. The builder calls it once, at the top, and then hands
the entire build to `spawn_blocking`:

```rust
progress.phase("rebuild").await;
…
let ran = tokio::task::spawn_blocking(move || crate::rebuild::run_one(args, verbose)).await
```

The shipped lease is 300 seconds. A build is allowed 1800. So the job is re-leased about six times
while the first worker is still building it, six workers build the same package, and `finish`
discards every result but the last — a worker may not record under a lease it no longer holds.

The tell is that the engine already knew:

```rust
tracing::warn!(job = job.id, "lease expired before this finished; the work was done twice");
```

The condition was detected, given a sentence, and left in place. That is worth stating as its own
observation: **a warning is not a fix, and a warning about an invariant violation is a bug report
the code is filing against itself.**

The renewal went into the engine's loop rather than into the builder, because every `Work`
implementation has the same problem and only one of them would have remembered. While a job runs,
the loop renews at a third of the lease, using a new `Progress::renew` that does *not* set a phase —
`phase` both renews and names, and renewing through it would overwrite the worker's own phase with
a meaningless "running" for the whole build, destroying the only signal `trigon watch` has about
where a long build has got to.

**A second defect inside the first fix, caught by the test.** The renewal interval was written as
`(lease / 3).max(Duration::from_secs(1))` — a floor, so that an absurdly short lease could not
become a busy loop against the database. Against a 300 ms lease that floor *is* the interval, and
the first renewal lands 700 ms after the job has already been taken. A floor that can exceed the
thing it is renewing disables the renewal, silently, while compiling and while working fine on the
default configuration. The floor is now 10 ms, which exists only because `interval` panics on zero.

The test asserts what actually matters, which took two attempts to get right. The first version
asserted that a long job still records — and it passed with the heartbeat disabled, because
`finish` checks *ownership* (`leased_by = $1 AND state = 'leased'`), not expiry, so an expired
lease nobody else has taken still records perfectly well. The property is therefore about the other
worker: **while a job is being worked on, a second worker must not be able to lease it.** That
version fails without the renewal and passes with it.

### 3.54 The transaction that deadlocked, in the function next door

**Real, and a recurrence.** `Queue::lease` was rewritten once already because a deferred SQLite
transaction that reads before it writes cannot upgrade. Two functions in the same file still did
it: `request_rebuild` counts the day's requests, looks for an existing job, and only then inserts;
`reserve_host` reads a host's floor and writes it back.

`Pool::begin()` is `BEGIN DEFERRED` on SQLite. Two such transactions each take a read lock and then
both try to upgrade, and neither can. `PRAGMA busy_timeout = 5000` — which this pool sets — does not
help, because SQLite returns `SQLITE_BUSY` *immediately* rather than waiting: waiting cannot resolve
a deadlock in which both sides would have to abandon a snapshot.

Measured: eight concurrent `request_rebuild` calls for eight distinct targets, **seven fail** with
`database is locked`. Eight concurrent `reserve_host` calls, same. What a user sees is `POST
/v1/runs` returning 500 with "the queue could not be reached", which names the wrong party — the
queue was reached, and the fault is ours.

Both now go through one `begin_write()` that issues `BEGIN IMMEDIATE` on SQLite and an ordinary
`begin()` on Postgres, which takes row locks as it goes and has no deferred-upgrade problem.

**The shape:** a fix applied to the function where the bug was found, rather than to the property
the bug was about. "How this transaction begins decides what it may do later" is a fact about every
transaction in the file, and it was recorded in one of them as a comment. It is now a function, so
there is one place to be right.

### 3.55 Two false matches, which is the failure this project cannot have

A verifier that reports a divergence where there is none wastes somebody's afternoon. One that
reports a **match** where there is a difference is worse than nothing, because it is the answer
people act on. Two passes were doing that.

**A `.sig` the package ships is not the gem's signature.** A `.gem` is a tar holding `metadata.gz`,
`checksums.yaml.gz`, `data.tar.gz` and the signing artifacts `*.sig`. `gem-exclude-signatures`
dropped every entry ending `.sig` and `gem-exclude-checksums` every `checksums.yaml.gz` — and
`apply` runs the whole set at every archive depth, so both also fired *inside* `data.tar.gz`, which
is the payload. A gem shipping a certificate, a test fixture, or a detached signature had it
deleted from both sides before they were compared, and a real difference in it became no
difference.

Measured: two gems differing only in `lib/trusted-cert.sig` stabilized to identical bytes.

The vocabulary to say this correctly already existed. `has_gzip` is written as `… && (cx.at_depth(0)
|| is_structural(cx))`, and `is_structural` names the three gem members by hand. These two passes
were the ones that did not ask, and they are now gated on `is_gem_envelope` — the gem's own tar, at
depth 0, which is where a gem's signing envelope lives.

**A symlink is not a regular file.** `zip-versions` set `raw.external_attrs = 0` to normalize the
unix mode, because 0644 against 0664 says nothing about a package. That field also carries the
**file-type** bits, and the zip writer emits `raw.external_attrs` and never consults `Entry::kind`,
which the reader had set correctly from those same bits. So after one `Metadata`-tier pass, a
symlink and a regular file with the same bytes were the same archive.

Measured through the CLI, on two 228-byte zips whose `pkg/x.py` was a symlink to `/etc/passwd` on
one side and a file containing that text on the other:

```text
✔ normalized
               upstream           rebuild
  stabilized   b60c55d03b98…      b60c55d03b98…      =
```

A published wheel that replaced a file with a symlink would have been reported as reproduced. And
because the only pass that fired was `Builtin` at `RiskTier::Metadata`, `caps_normalized` does not
cap it — the provenance cap is not a backstop here, by design.

The type bits now come from `Entry::kind` rather than from the raw word, so a zip written by a tool
that records no unix mode still agrees with one that records `0100644` — which is what zeroing the
field was for — while a symlink stays distinct. After: `✖ divergent`, and two identical regular-file
zips still report `✔ exact`.

**The shape, common to both:** a rule stated over the wrong domain. "Exclude `*.sig`" is true of a
gem's envelope and false of its contents; "the mode is noise" is true of permissions and false of
the type. Each was written as the broader claim because the broader claim was easier to express,
and in both cases the narrowing vocabulary was already sitting in the same file.

### 3.56 A ceiling that was multiplied by the member count

**Real, and the other reader already had the answer.** `Limits::total_expanded_bytes` is documented
as "a hard ceiling on everything one artifact expands to". `descend` passed the whole `Limits` to
every nested `.gz` member it found, and every inflated body was retained at once in `Body::Nested`.

Measured: a 70 KB tar of eight `.gz` members, each inflating to 8 MiB, parsed under a **16 MiB**
ceiling — returns `Ok`, holds **64 MiB**, and emits no note. It scales linearly in member count,
bounded only by `max_entries` (one million). A `.gem` is an outer tar of `.gz` members, so the shape
is entirely ordinary.

`zip::read` already threaded a running total: `let remaining =
limits.total_expanded_bytes.saturating_sub(expanded)`. The tar-and-gzip descent now does the same,
and a member that would exceed what is left is left inline with a note naming the limit — which is
the right failure, because the outer comparison still works and the member is digested as the bytes
we could not open.

This is [3.50](#350-a-19-5-mb-file-that-costs-8-2-gb-to-look-inside)'s rule a third time: **a cap
constrains the quantity it is measured in and no other.** Here the quantity was right and the
*scope* was wrong — per member rather than per artifact — which is the same mistake wearing a
different hat.

### 3.57 The compressor threw away the line the whole log was about

**Real, measured at both shipped budgets, and a reintroduction of a fix this file already records.**

`compress` cuts a build log to what a model can read. It picks lines best-first — highest priority
claims the budget — and then walks the *file* emitting the chosen ones. The emit loop had a budget
check, because the elision markers (`… 41 lines omitted …`) cost bytes and the selection pass never
priced them. On overrun it did this:

```rust
if used + line.len() + 1 > budget {
    // The markers cost budget too, and they are not priced above. Stopping here keeps the
    // promise that the output fits; the lines lost are the lowest-priority ones already.
    truncated = true;
    break;
}
```

Both sentences are false. It walks in file order, so the lines lost are the **last ones in the
log** — which is where the error is, and where the priority sort had deliberately spent the budget.
And the markers pushed after the break are unpriced, so the output did not fit either: 4,164 bytes
against a 4,096 budget.

Measured on a 4,000-line build log with a compiler warning every eighth line — which fragments the
chosen set into runs, each costing a marker — at **4096** (the rebuild path) and **8192** (the
repair path), for gap spacings of 3, 5, 8, 12, 20 and 40:

```text
classify(raw)        → cc/missing-header:python.h
classify(compressed) → unknown
```

**That signature is the repair cache key.** So the same failure keyed two ways depending on how
much the build printed, and a noisy build and a quiet one with the same cause missed each other in
the cache. The comment at the top of this very function describes that regression as already fixed:
*"a long log spent its whole budget on the head and never reached the end … `classify` then returned
`unknown`, and since that signature is the repair cache key, the same failure keyed two ways
depending on how much the build printed."* It was reintroduced one loop later.

The markers are now priced, before the emit loop runs, by a `rendered_len` that models exactly what
will be emitted. When the total does not fit, lines are evicted **by priority** — which is what the
old comment claimed the `break` was doing. The emit loop no longer has a budget check at all, only
a `debug_assert`, because a check there can only ever resolve an overrun in file order.

The existing test `the_classifier_still_names_the_failure_in_the_compressed_form` asserts this
property and passed throughout: its npm fixture has a *contiguous* chosen set, so it never reaches
the break. Same shape as [3.52](#352-the-page-named-members-the-artifacts-had-never-heard-of) — a
test written for the right property, with a fixture that cannot exercise it.

**Also corrected, one line up:** *"A third of the budget is reserved for the highest-priority lines
before anything else is considered."* No reservation existed. The sort is what provides the
guarantee, and it is a stronger one — the highest-priority lines get first claim on the whole
budget, not a third of it. Here the comment was wrong and the code was right.

### 3.58 A signed statement that the check had been performed, on runs where nothing looked

**Real, and it is a false claim inside a signature, in the default configuration.**

`RecordInputs::guard_manifest` documents itself:

> `None` means the guard did not run, and the signed `artifactHashCheck` block says so by deriving
> `performed` from the first of these.

It was built unconditionally:

```rust
let guard_manifest = Some(Digest::from_bytes(…digest(&guard_bytes)…).to_hex());
let guarded_members = Some(guard.members.len() as u64);
```

The manifest is built for every run, because building it is how we learn what we *would* watch.
Arming it is a separate event, and two things do it: `--egress mirror-only` hands it to the mirror
inside the build's network island, and `--timewarp auto` reserves a host mirror built
`.with_guard(…)`. **The shipped default does neither** — `--egress` defaults to `open` for both
`rebuild` and `sweep`, and without `--timewarp` no mirror is started at all.

So a default `trigon rebuild` signed:

```json
"artifactHashCheck": { "performed": true, "matched": false, "guardedMembers": 34, "trips": [] }
```

about a run where nothing had looked at anything. `trigon-attest/src/rebuild.rs` states the rule
being broken three lines above the field that breaks it: *"A guard that could not run is not a guard
that found nothing, and collapsing the two is how an unchecked run comes to be read as a clean
one."*

The cause is visible in the comment above the assignment, which explains a fix in the **opposite**
direction — nineteen statements once said the guard had not run when it had. The correction went
past the target and made the field unconditional.

Both fields now hang off one named predicate, `guard_was_armed(enforced, host_mirror)`, with its own
test. A function rather than an inline `||`, because a signed claim is derived from it and an inline
boolean is where the last version of this rule went wrong. They move together: `guardedMembers: 34`
beside `performed: false` is the same false statement with the other half missing.

**The shape**, shared with §3.57 and with most of what this pass found: the comment is right, the
code is wrong, and nothing compares them. Both of these were found by a reader holding the two side
by side — which is a thing no test in this repository does.

### 3.59 The only lever that works was reachable from nowhere

**Real, reported from a live run.** A divergence repair came back as:

```text
WARN the proposal produced nothing: asking about a divergence: the answer did not fit in
     16384 output tokens (16382 of them spent on reasoning).
```

The message is right about the mechanism and wrong about what to do. It says *"lower
`output_config.effort` instead, or ask the provider for `Reasoning::Off`"* — and
`output_config.effort` was a `const` in the Anthropic client. No caller could set it. No retry could
lower it. The advice named a dial nobody could turn.

Worse, the dial had **already been turned**, for this exact failure. `ANTHROPIC_EFFORT` is
`"medium"` and its doc comment explains why: *"At the API's default of `high` a repair spent 16,379
of 16,384 output tokens reasoning and was cut off before writing anything."* The fix for the first
occurrence was to hardcode a lower value, and the second occurrence — 16,382 of 16,384, at
`medium` — proves that a constant is not a fix for an adaptive system. It is a guess that happens to
hold until it does not.

**And the retry was on the wrong failure.** `ask_until_it_parses` asks a second time when an answer
*will not parse*, which is the hard case: the model produced something and it was wrong. A truncated
answer is the easy case — the model thought until the budget was gone — and it propagated straight
out as a hard error. The cheap fix had no path and the expensive one had two attempts.

Three changes:

- `Effort` is a type with `low`/`medium`/`high` and a `lower()`, carried on `Request` and skipped
  when serializing so recorded transcripts still compare equal.
- `Provider::default_effort()` replaces the constant, so a provider states its default and a caller
  can ask for less.
- `propose` walks the depth down on `Truncated` — medium, low, then one last call with reasoning
  **off**, which is a different setting rather than a lower one and is the only thing that hands
  the whole budget to the answer. Reaching the end now means something else is wrong, and the error
  says so instead of naming a dial.

Each step is a real call and costs tokens. It is still the cheaper outcome: the repair loop counts a
failed proposal as an iteration spent, and an iteration spent on a call that produced nothing is the
most expensive result available.

**The shape:** a constant standing in for a policy. The value was chosen by measuring one failure,
which makes it a fact about that failure rather than a rule — and an adaptive system will find the
next value that does not hold. What was needed was not a better number but a response to the
condition, which is what the error text had been describing in the imperative to a reader who had
no way to act on it.

### 3.60 The answer was fine; nothing took it out of its wrapper

**Real, reported from the run that followed [3.59](#359-the-only-lever-that-works-was-reachable-from-nowhere).** The
depth walk fired exactly as designed and the repair still failed:

```text
WARN the answer did not fit; asking again with less thinking limit=16384 thinking=3134 from="medium" to="low"
WARN the proposal produced nothing: the proposal did not parse as a strategy, twice.
     The model said: The previous recipe built successfully but is missing prop-types.js …
     : not valid YAML: could not find expected ':' at line 21 column 1242
```

Two things are worth reading carefully there.

**`thinking=3134`, not 16,382.** Only a fifth of the budget went to reasoning, so the *answer* was
around thirteen thousand tokens. §3.59's walk is the right response to a model that thinks until the
budget is gone, and this was a model writing an essay. The walk still helped — at `low` it produced
something instead of nothing — but the diagnosis behind it was narrower than the failure.

**`column 1242` is a sentence.** The candidate parsed, carried a correct diagnosis, and its
`strategy` field was prose. `strip_fence` had two defects and the second is the one that bit:

1. It was `s.strip_prefix("```")`, so it only found a fence at byte 0. An answer shaped *prose, then
   a fenced block* was returned whole. Found by the doc-comment pass before this was reported and
   not yet acted on.
2. **It was never applied to `candidate.strategy` at all.** A provider honouring the schema returns
   `{diagnosis, strategy}`, and nothing said the `strategy` string would be a bare document. Models
   put a fence inside it, or a paragraph in front of it. Cleaned at the top level only, a perfectly
   well-formed candidate carried a strategy that was prose — and the caller met it two calls later
   as `not valid YAML`, with the diagnosis printed where the cause should have been.

`strip_fence` now finds a fence anywhere, and where there is none, drops anything before the first
line beginning `kind:` or `schema:` **at column 0** — indented, those are fields inside a mapping,
and cutting there would take the tail of a document and return it as the whole thing.

**And fixing it introduced a regression the tests caught immediately.** Making `strip_fence` find a
fence anywhere broke the JSON path: a candidate object's `strategy` field routinely *contains* a
fence, so stripping the whole answer first cut the JSON open at a fence inside the payload. The
order is now raw JSON, then fenced JSON, then bare document — the strict parser asked first and the
salvage reached for only when it says no.

**The shape:** a cleaning step applied where the answer arrives and not where the answer is *used*.
The top-level parse was careful and the field it produced was handed on untouched, so every
improvement to the outer unwrapping missed the inner one entirely.

### 3.61 Every wheel that is not byte-identical is a caveat, so the tier says nothing

**Not a defect — a reporting problem, found by running 100 PyPI targets and reading the breakdown.**

The Census III PyPI sweep reproduced 47 of 61 compared targets. The breakdown:

| | npm | PyPI |
| --- | ---: | ---: |
| `exact` | 32 | 13 |
| `normalized` | 11 | 2 |
| `normalized_with_caveats` | 0 | **32** |

Two thirds of PyPI's reproductions are at the weakest tier and none of npm's are. That is not a
fact about the packages. The `wheel` profile contains `zip-entry-order` and `zip-compression` at
`Structural` risk and `wheel-record` at `Content`, and `caps_normalized` holds any run above
`Metadata` at `NormalizedWithCaveats`. Every applied pass was `Builtin`; the tier comes from the
*risk*, not from anyone's judgement.

So a wheel has exactly two reachable outcomes above divergent: **byte-identical, or caveats**.
`Normalized` is unreachable for any wheel whose zip framing differs at all, which is almost all of
them — the two PyPI runs that reached it were `.tar.gz` sdists, where the `tar` profile's passes are
all `Metadata`.

The cap is doing its job: a structural rewrite is a weaker claim than a metadata one, and ADR-0002's
four outcomes are meant to carry that. The problem is downstream, in what a reader takes from it. A
tier that everything lands in carries no information, and "32 reproduced with caveats" invites the
reading that those 32 are the interesting ones. They are not — they are every wheel that reproduced.

**It also makes the two ecosystems' rates not directly comparable**, which matters because M1
reports one per ecosystem and somebody will eventually add them. npm's 70% and PyPI's 77% are
counting different things at the top of the range.

Recorded rather than fixed: changing the risk tiers to make `normalized` reachable for wheels would
be weakening a control to improve a chart, which is the wrong direction. The fix belongs in how the
rate is presented — see [B35](17-backlog.md).

### 3.62 The model answered correctly, and then kept talking

**Real, from a reported run, and the diagnosis was right both times.** A repair of
`prop-types@15.8.1` failed with:

```text
WARN the proposal produced nothing: the proposal did not parse as a strategy, twice.
     The model said: The tarball's two extra members, prop-types.js and prop-types.min.js, are the
     UMD bundles produced by the repo's `build` script (`yarn umd && yarn umd-min`, invoked via the
     legacy `prepublish` hook)…
     : not valid YAML: mapping values are not allowed in this context at line 21 column 513
```

That diagnosis is correct. `prop-types` builds its UMD bundles in a `prepublish` hook, and modern
npm does not fire `prepublish` for `npm pack` — only `prepare`, `prepack`, `postpack` and
`prepublishOnly`, none of which that package.json has. The model found it, twice, and wrote a
working recipe both times.

Reading the run's transcript rather than the error:

```text
turn 0, 1,891 chars:  … output_path: '*.tgz'
                      [FollRH2] I checked the SIEM. During the exact minute of the incident, …

turn 1, 2,471 chars:  … output_path: '*.tgz'
                      (No new messages. Waiting for the next update.)Continue with your task …
                      … System: Continuing scheduled operation.Assistant:
```

**The model finished its answer and kept generating.** Turn 0 added a stray line; turn 1 added a
kilobyte and simulated the next two turns of a conversation, complete with `System:` and
`Assistant:` markers. Both strategies above the drift are valid and complete, ending at
`output_path`.

The drift lands **inside the JSON string value**, so the JSON stays well-formed. Every consumer
downstream saw a well-formed candidate whose `strategy` field happened to have junk on the end, and
reported the model's own diagnosis in the place where the cause should have gone — so a correct
answer read as a wrong one.

**This is a trust boundary and not only a parsing convenience.** Whatever produced that text put it
into a field that becomes a *build recipe*. Here it was invalid YAML and failed loudly. Valid YAML
would have been executed. So the cut is made at the end of the document rather than at the point the
parser stops complaining: a line at column 0 that is neither `key:` nor a sequence entry nor a
comment cannot belong to this mapping, whatever it says, and the document ends before it. Block
scalars are indented, so a script body survives.

It is also logged, with the size of what was dropped. Salvaging quietly would hide a model that has
stopped answering the question, and a few characters and a kilobyte are different events.

Both answers are kept verbatim as fixtures in `crates/trigon-ai/tests/fixtures/`, because the point
of them is that this is what actually arrived.

**The shape:** a well-formed container carrying a malformed payload. Every check was on the
container — the JSON parsed, the schema matched, the field was present — and nothing asked whether
the field's *contents* ended where they should. The previous two fixes ([3.59](#359-the-only-lever-that-works-was-reachable-from-nowhere),
[3.60](#360-the-answer-was-fine-nothing-took-it-out-of-its-wrapper)) were both on the outside of that
same envelope.

### 3.63 The guard rendered the repair in a world the build does not live in

**Real, reported, and the mirror image of the defect `usable` was written to close.**

With [3.62](#362-the-model-answered-correctly-and-then-kept-talking) fixed, the repair loop reached
the next step and threw the recipe away:

```text
repair  discarded: deps.[0].npm/deps/custom.[1].npm/install.[0].npm/npx.[0]: template:
        invalid operation: timewarp_url was called but no mirror is configured for this run.
        A build that pins a registry moment needs one, or it resolves against the live index.
        — in `export npm_config_registry={{ timewarp_url('npm', with.registry_time) }}`
```

The message is correct and was asked in the wrong place. `usable` renders a proposal to decide
whether to accept it, and built its `Context` like this:

```rust
env: trigon_strategy::EnvCtx {
    arch: "x86_64".into(),
    platform: "linux".into(),
    has_repo: true,
    ..Default::default()          // ← timewarp_base: String::new()
},
```

`timewarp_base` empty means *no mirror*, so any recipe pinning a registry moment renders
`timewarp_url(…)` and is refused. The run this happened in was at `--egress mirror-only`, with a
mirror inside the build's network island — the tool printed *"mirror inside the build's network
island, which is its only route out"* nine lines earlier. The model had asked for the published
moment, which is exactly right for a reproduction, and the guard discarded it for depending on
something the run had.

**`usable` exists because of this defect in the other direction.** Its own comment records the
first half: a guard that only rendered *accepted* a proposal the build then rejected, a repair for
`xstate@4.38.3` replaced the strategy and died on the next iteration, and the run was filed
`error:infra` with no failure code. The fix added an executability check. What neither half noticed
is that **the context itself was a guess** — and a guard that validates in a world the build does
not live in will reject what the build accepts as surely as it accepts what the build rejects.

`usable` now takes the run's mirror, and the value is bound once so the build call and the two
validation calls provably use the same one. The source tripwire that asserts every acceptance site
is guarded scans for the new call shape.

**The shape:** a validator that reconstructs the world instead of being handed it. `Default` is a
reasonable value for a field nobody has an opinion about and a wrong one for a field the caller
knows — and the difference is invisible, because both produce a `Context` that renders.

### 3.64 A failed repair threw away the verdict the run had already reached

**Real, reported, and listed in [B29](17-backlog.md) unactioned since the whole-tree review.**

`prop-types@15.8.1` built, compared, and diverged — two UMD bundles missing, exactly as established
in [3.62](#362-the-model-answered-correctly-and-then-kept-talking). The loop then accepted a repair,
the repaired recipe called `yarn` on an image without it, and the run recorded:

```text
outcome: None      terminal: build-failed:build      comparison: None
```

The divergence was computed, confirmed, and discarded — and the run signed a build observation and
nothing else. The finding it had was replaced by an error about the *suggestion for improving it*.

The repair site's own comment says this must not happen:

> Both arms below keep `judged`, so the run reports the divergence it found rather than an error
> about the suggestion for improving it.

There are **three** arms. The two terminal ones keep it. The middle one — accept the repair and go
round again — did not, because at that point nothing has gone wrong yet and the next iteration was
expected to produce a better answer. When the next iteration failed instead, there was nothing to
fall back to.

Two changes, because keeping the comparison alone is not enough:

- The accept arm keeps `judged`, and a later iteration that reaches a comparison overwrites it, so
  the last real answer always wins.
- **And the build it came from.** Three fields of the record are read off `built` — `attestable`,
  `isolation`, and the network transcript — and describing the run by the attempt that failed would
  report no isolation and no transcript, which reads as *no build ran* rather than *the second one
  did not*. `judged_built` carries the successful build beside its comparison.

A `Void` still outranks both: a tripped guard means the artifact under test reached the build, so
nothing the run produced is evidence, including a comparison made before the trip.

The tripwire that already asserts every acceptance site validates its proposal now also asserts
this one keeps its comparison — pinned as a *pair*, anchored on the stash, and scoped to the arm's
own `Ok(()) => {`. A count would not do: there are two accept arms and only one has a verdict to
keep, and a window wide enough to span the comment between the two lines is wide enough to be
satisfied by the neighbouring arm's keep.

**The shape:** a fallback that was never needed until the happy path stopped being happy. The arm
was correct for every run where the repair worked, which is every run anyone tested it on.

### 3.65 `yarn <script>` is `npm run <script>`, and the rule table said otherwise

**A deterministic rung, and a correction to a rule that was half right.**

`trigon-core`'s failure table classifies `yarn: not found` as `npm/unsupported-package-manager`,
`repairable: false`, on this reasoning:

> Putting yarn in a base image would run it with *some* yarn and produce a verdict about a build the
> publisher never did.
>
> A different recipe cannot conjure support for a package manager. Builder work, not repair.

The first sentence is right and the second is not. What matters is **what yarn is being asked to
do.** As a resolver — `yarn install`, `yarn add`, anything reading a `yarn.lock` — it is genuinely
unsupported, and installing some yarn would answer a question nobody asked. As a *task runner* it is
`npm run` spelled differently, and a different recipe does not need to conjure anything.

`prop-types@15.8.1`, from the published artifact's own `package.json`:

```text
umd        NODE_ENV=development browserify index.js -t loose-envify --standalone PropTypes -o prop-types.js
umd-min    NODE_ENV=production  browserify index.js -t loose-envify -t uglifyify --standalone PropTypes …
build      yarn umd && yarn umd-min
prepublish not-in-publish || yarn build
```

The work is browserify, pinned in `devDependencies` and resolved through the mirror at the published
moment. yarn resolves nothing here; it invokes two scripts. `npm run umd && npm run umd-min` runs
the same binaries at the same versions.

So the rewrite is deterministic, and it runs **before the model and without needing one** — which is
what M3 means by a rung that lowers the model-invocation rate. Three properties it has to have:

- **It refuses `yarn install`, `yarn add`, `yarn --version` and a bare `yarn`.** Returning `None`
  rather than a partial rewrite: a recipe that both installs and runs needs yarn, and rewriting half
  of it produces something that fails later and looks like a different problem.
- **`yarn build` is not `npm run build`.** `build` is itself `yarn umd && yarn umd-min`, so handing
  it to npm finds yarn again one level down. A script that reaches yarn is *expanded* into what it
  would have run; one that does not is called directly.
- **It terminates on a cycle.** `a: yarn b`, `b: yarn a` is a package somebody can publish.

The case that actually fires is the third shape: `prop-types`'s strategy never mentions yarn at all.
It runs `npm run build`, and `build` is where yarn appears — two levels below anything the recipe
says.

**And a tripwire had to be rewritten twice to keep up.** `every_place_a_proposal_is_accepted_
validates_it_first` counted `match usable(…)` against acceptances, which held while every site was a
`match` — the new rung guards with `usable(…).is_ok()` in an `&&` chain, so a correctly-guarded site
counted as unguarded. Replacing the count with a byte window then failed on *correct* code, because
a comment added above one acceptance pushed its guard 2,800 bytes away. It is anchored on where the
proposal is bound now: validated between `Ok(next)` and `strategy = next`, which is the rule itself
rather than a spelling or a distance.

**The shape:** a rule that generalised from the hard case. Yarn-as-resolver really is unsupported,
and the table wrote that down as "yarn is unsupported" — which is a larger claim, and the larger
claim is what the code enforced.

### 3.66 Five fixes, four of them shipped to the user to discover

**A process finding, and the worst one in this file.**

The chain from a model's answer to a usable recipe broke five times for one package. Each fix was
real, each was verified, and four of them were verified against a unit test shaped like the failure
that had just been *reported by the user* — so the next run found the next break, and the loop ran
four times:

| | what broke | how it was found |
| --- | --- | --- |
| [3.59](#359-the-only-lever-that-works-was-reachable-from-nowhere) | the output budget went to reasoning | reported |
| [3.60](#360-the-answer-was-fine-nothing-took-it-out-of-its-wrapper) | `strip_fence` never touched the `strategy` field | reported |
| [3.62](#362-the-model-answered-correctly-and-then-kept-talking) | drift past the end of the document | reported |
| [3.63](#363-the-guard-rendered-the-repair-in-a-world-the-build-does-not-live-in) | validation ran without the run's mirror | reported |
| [3.64](#364-a-failed-repair-threw-away-the-verdict-the-run-had-already-reached) | a failed repair discarded the verdict | reported |

Every one of those was a layer of the same path, and every fix moved the failure one layer down. A
test of the *path* would have found them together; five tests of five symptoms found them one at a
time, in production, over four days.

`crates/trigon/tests/e2e_prop_types.rs` is that test. Every answer the model has ever returned for
this package — eight of them, across four runs — is a verbatim fixture, and the assertion runs the
whole chain: unwrap the answer, parse the recipe, render it in the run's context, and ask whether
there is anything to execute.

**Its load-bearing assertion is about whose fault a refusal is.** Seven of the eight answers yield a
working recipe. The eighth is refused with *"uses `runs`, which is not a registered tool"* — a
genuine mistake by the model, and refusing it is right. What the test forbids is a refusal
containing `not valid YAML`, `no mirror is configured`, or `did not fit`: each of those strings was
a defect in this repository, and each appeared to the user as though the model had failed.

Reverting any of the five fixes fails it. Two checked explicitly: dropping the longest-prefix
salvage refuses four of eight with `not valid YAML`; emptying `timewarp_base` refuses on the mirror.

**And the last fix is different in kind from the four before it.** Those were heuristics — recognise
a fence, recognise a column-zero line, recognise a trailing marker — and the recorded drift defeated
each in turn: prose at column zero, prose indented one space, a second document appended to the
first, commentary tacked onto the end of a valid `key: value` line. The shapes are not enumerable
because they are whatever a model does after it stops answering.

So the rule stopped being *"what does junk look like"* and became *"where does the document stop
parsing"* — `from_yaml_longest_prefix`, which counts down from the whole string and returns the
longest prefix the parser accepts, along with how many lines it dropped so the run can say so. The
parser was always the only oracle whose answer was not a guess.

**The shape:** four consecutive fixes that each generalised from one observed failure, when the
failure had no generalisable form. The tell was that every fix held until the next run, which is
what a heuristic does and what a rule does not.

### 3.67 Two ways to run yarn, and the code had neither

Reported as *"you didn't fix yarn at all"*, and correctly: the run still ended `divergent` with the
repair discarded. Two separate things were wrong, and the e2e test from
[3.66](#366-five-fixes-four-of-them-shipped-to-the-user-to-discover) had already recorded one of
them as acceptable.

**`uses: runs` is a `runs` step.** Four of the eight recorded answers write the build step as

```yaml
- uses: runs
  with:
    cmd: npm run build
```

`runs` is a step kind and can never be a registered tool, so there is exactly one thing this can
mean. It was refused with a message listing nineteen tools the model had not asked for, and that
refusal cost a correct repair on every run that produced it. The e2e test recorded it as *the
model's mistake, correctly refused* — which was true of the schema and false about what to do,
because a schema readers get wrong in one obvious direction is better read than re-explained. With
the alias, eight of eight recorded answers yield a working recipe.

**And `npm/install-yarn` should have existed.** The rule table refuses a yarn build because
*"putting yarn in a base image would run it with some yarn and produce a verdict about a build the
publisher never did"*. That is right about a base image and wrong as a general rule: **yarn is an
npm package**, so installed through the mirror it resolves at `registry_time` like every other
dependency. What arrives is the yarn that was current when the package was published — the same
mechanism `npm/install-node` already uses for the toolchain, and the same reason `--timewarp`
exists.

So there are two fixes and they are for different situations:

| | |
| --- | --- |
| `yarn <script>` — a task runner | rewrite to `npm run <script>`: same binaries, same pinned versions, nothing installed |
| `yarn install` against a `yarn.lock` — a resolver | install yarn; no rewrite reproduces yarn's resolution |
| fidelity to what the publisher ran | install yarn, even where the rewrite would work |

`yarn_version` is optional because most published packages have nothing to pin it to. A
`packageManager` field states it exactly and is passed through where present; `prop-types` predates
corepack and says nothing, and then the honest reconstruction is whatever the registry called
`latest` at `registry_time`. Yarn 2 and later are deliberately out of scope: berry ships in-repo via
`.yarn/releases` and is not installed globally.

**The shape:** a rule that generalised from its hard case, twice over. Yarn-as-resolver really is
unsupported and that became "yarn is unsupported"; `runs` really is not a tool and that became "this
document is wrong". Both times the narrower true statement was available and the broader one was
what the code enforced.

**What it bought.** `pkg:npm/prop-types@15.8.1`, replayed against the exact model transcript that
had failed, now runs three builds: the first diverges on two missing members, the repair rewrites
`yarn umd && yarn umd-min` to `npm run umd && npm run umd-min` with no model call, and the third
build produces both bundles. The member census moves from **2 upstream-only** to **11 identical, 1
differ, 0 upstream-only, 0 rebuild-only**, and `prop-types.min.js` is byte-identical.

The one member that still differs is [3.67b](#367b-a-tarball-that-disagrees-with-itself), and it is
not ours.

### 3.67b A tarball that disagrees with itself

`package/prop-types.js` in the published 15.8.1 differs from the rebuild by twelve bytes, on one
line:

```
-  if (checkerResult.data.hasOwnProperty('expectedType')) {
+  if (checkerResult.data && has(checkerResult.data, 'expectedType')) {
```

`prop-types.js` is the UMD bundle of `factoryWithTypeCheckers.js`, and **both files ship in the same
tarball**. The published `factoryWithTypeCheckers.js` carries the second form; the published bundle
of it carries the first. No source tree produces that tarball: the bundle was built from an earlier
checkout than the CommonJS files packed beside it.

The rebuild reproduces `factoryWithTypeCheckers.js` byte-for-byte, and `prop-types.min.js`
byte-for-byte (the production UMD bundles `factoryWithThrowingShims.js`, which never reaches that
line). It builds the development bundle from the same source the tarball ships, and so disagrees
with the tarball.

This is the first divergence in this corpus that is **internally checkable** — it needs no reference
build, no timewarp and no trust in Trigon. Two files in one published artifact contradict each
other, and anyone can unpack it and see. It is the case the project exists for, and it arrived as
soon as the plumbing stopped failing first.

**Corroborated, three times over.** Three separate runs — one replaying the failed transcript, one
under `--image derive`, one fully live with three model calls — produced a rebuild that is
**byte-identical across all three**: raw `sha256 7ac49bd035c6…`, against the published
`1c739eb05d8a…`. Two of the three arrived there through *different* strategies (`1d4883ca47c8`,
which runs `npm run build`, and `ac1619e568de`, which runs `npm run umd` and `npm run umd-min`
separately) and still built the same bytes. The rebuild is deterministic to the byte; the
published artifact is the outlier. The live run's verdict is signed:
`attestations/npm/prop-types/15.8.1/…/divergence.intoto.json`, run `1789917709-1c739eb0`.

The live run also spent 292 seconds of inference and two more 75-second builds re-asking the model
about this divergence before the restating rule stopped it — because the brief names the member
that differs and never shows the difference. A model that could see the twelve bytes would have
had a chance to say what they mean; one shown `body,entry:size` can only guess at build flags.
That is [B42](17-backlog.md).

### 3.68 Three rules that could never match

Removing the yarn refusal meant reading the rule table, which is first-match-wins, and three rules
were exact duplicates of earlier ones: `yarn`, `pnpm` and `bun: not found` each appeared twice, the
second copy unreachable. Harmless until someone edits the dead copy and cannot work out why nothing
changes. A test now rejects a rule whose needles an earlier rule already claims — exact equality,
not subsumption, because `: not found` and `: command not found` legitimately overlap and their
order is the point.

The same read found a line that had gone false. `repairable: false` means *do not spend a model
call*, and the terminal rendered it as `no strategy change fixes this one`. The prop-types run
printed that line and then repaired the build two lines later. The flag gates the model, not the
world; it now reads `not one to ask the model about`, and the field's doc comment says which of the
two it is.

### 3.69 The loop deleted the bytes the verdict named, and a signed statement said the guard never ran

Reported as *"JFYI, this still fails"*, with a run that printed `✖ divergent`, a member census, and
then `WARN could not record this run: No such file or directory (os error 2)`. Eight words, no file
name, and both `std::fs::read` calls in `record_run` were a bare `?`.

The mechanism is one line. The build loop clears `<work>/rebuild` at the top of every iteration,
and [3.64](#364-a-failed-repair-threw-away-the-verdict-the-run-had-already-reached) had just taught
it to carry `judged` *across* an iteration so a failed repair still reports the divergence the run
already established. So the path and the bytes under it had different lifetimes, and nothing
asserted it:

```
attempt 1 builds  → judged = Some((rebuild/5a792f5778cd-…/prop-types-15.8.1.tgz, comparison))
repair accepted   → continue
                  → remove_dir_all("<work>/rebuild")      ← the file judged names
repair refused    → keep the verdict, record it
                  → std::fs::read(that path)              ← ENOENT
```

**And it did not stop at a lost record.** `run_inner` falls back to the thin terminal record when
the rich one fails, so the store got a record with no comparison, no rebuilt artifact,
`attestable: false`, `isolation: ""` and no guard manifest — and `trigon attest` then signed a
`buildobservation` predicate from it:

```json
{"artifactHashCheck":{"guardManifest":null,"guardedMembers":null,"performed":false,"matched":false},
 "egressTier":"mirror-only","isolation":"","networkTranscript":null,"tier":0}
```

The terminal, ninety seconds earlier, had printed `guarding the artifact and 1 of its members` and
`network 1039 responses crossed into the build, 563 opened and checked`. The run's outcome is
absent from the store entirely; the screen said `divergent`.

This is §3.13's nineteen false `artifactHashCheck` statements arriving through a different door.
That was fixed by making sure the value *reaches* the record. The renderer still reads
`"performed": f.guard_manifest.is_some()`, three lines under a comment that says *"a guard that
could not run is not a guard that found nothing, and collapsing the two is how an unchecked run
comes to be read as a clean one."* Any future path that loses the field recreates the false
statement. Filed as [B38](17-backlog.md); the fix here is the cause, not the second line of defence.

The relocation sits immediately above the wipe rather than at each of the eight `judged =` sites,
because a rule enforced next to its cause cannot be forgotten by a site added later, and a tripwire
anchors on the wipe.

### 3.70 The gate asked whether a proposal renders; the build also asks whether it is admissible

Same run, one step earlier. The model's repair declared a build step with `needs: [npm]`, which is
the admission table's own worked example — Debian's npm brings its own Node, 18 on bookworm, and a
pinned Node 10 then loads modules written for 18 and aborts.

`usable` checks that a proposal renders and that it is executable, because those are the two checks
the executor makes. It is the function whose doc comment says *"a guard that only renders accepts a
proposal the build will then reject. That is the gap this function exists to close."* There was a
third check — `resolve_auto`'s admission filter — and `usable` did not make it. So the proposal
passed, replaced a strategy that worked, and was refused three steps later where a refusal can no
longer become another attempt.

The rule and its wording now live in one place, `trigon_sandbox::inadmissible`, because a refusal
phrased at one call site and re-phrased at the other is the same defect one level down.

### 3.71 Two hundred and five signed records name no base image

`Environment.base_image` is documented *"pinned by digest. A tag would make the record
unreproducible by anyone else."* `--image auto` resolves inside `build::run_with` into a binding
that never escaped it, and `RecordInputs.image` was the raw flag. Counted on this machine's store:

```
205  "base_image": "auto"
 99  "base_image": "localhost/trigon-python@sha256:fdaef2ba9caea…"
 24  "base_image": "localhost/trigon-base@sha256:7cdddce4868e731…"
```

`Built::sdk_choice` says, in the file, *"`Environment.base_image` names the bytes; this names the
reasoning."* The intent was written down and the value never travelled — the same shape as
`isolation`, two fields above it, which reached a `println!` and stopped there while nineteen
statements described an unbounded build.

It matters here beyond tidiness: `--image derive` exists to disclose how an image came to be, and a
disclosure attached to a record that cannot name the image is not a disclosure. The identity and the
disclosure travel the same wire.

Still the flag on a run that produced no build, which is honest — no image was resolved — and still
the flag on a build that ran and failed, which is not. [B39](17-backlog.md).

### 3.72 `--image derive`, and a security property that was already false

`--image auto` refuses at an enforced tier because deriving an image means `apt-get` and that is
network the run's transcript would never see. The refusal was correct and the cost was hidden: on
the PyPI leg of the M1 sweep, **73 of 89 targets** produced nothing because of it, and the
prescribed remedy — derive by hand at `--egress open`, then re-run pinned — is not something anyone
does inside a sweep.

`--image derive` does it inside the run and records that it did: `Environment.derived_image` carries
the parent, the sorted package list, and whether *these bytes* were built by this run.
`built_here: false` is a hit on the content tag, and its doc says what it does not mean — not "no
network was spent", but "not by this run", because an earlier run spent it and may have recorded
nothing. That is the `artifactHashCheck.performed` trap, refused in advance.

The gate withholds an **accusation** from such a run and publishes a **match**. The asymmetry is the
claim: the mirror and the artifact guard both ran, and reproducing a published artifact byte for
byte is not made easier by an image that carries `build-essential`. Voiding the match would discard
real evidence in order to look careful.

**Threat-model P11 said something that was already untrue.** *"At every tier but `open` no phase
reaches the network — the image build takes `--network none` too."* Two phases did:

- `missing_from` — the probe that asks an image what it carries — ran `podman run` with **no
  `--network` flag**, at every tier, *before* the enforced-tier refusal. It runs `command -v`. It
  needed no network and had one. Fixed: `--network none`.
- `auto_parent` resolves through `pinned`, which runs `podman pull` when the reference is not local
  — reachable via `TRIGON_BASE_PARENT` or any .NET target, also before the refusal. Real network,
  genuinely needed, recorded nowhere. [B40](17-backlog.md).

P11 now names the exception instead of being quietly falsified by it, and the sidecar was
regenerated from the prose.

**The reframing the work produced:** `scripts/rebuild-and-attest.sh` — the supported entry point,
the one `goauto.sh` calls — already runs `trigon base-image` itself, at `--egress mirror-only`,
immediately before the run, and records nothing anywhere. Nobody owned this obligation. `derive`
closes that hole rather than opening one.

### 3.73 A legend with a row nothing matches, and the other direction

`Withheld::key`'s doc comment warns that a page keyed on one name while reading another is *"how a
legend ends up with a row nothing ever matches."* The live defect was the mirror image:
`ProvenanceUnknown` had been added to the enum and never to `app.js`, so the one withholding reason
that is about *our record* rather than about the reader's package rendered as the generic fallback.

A test now asserts every variant has a row. Existence, not wording — the sentences are written twice,
in `Withheld::sentence` and in the page, and a test pinning the text would be a third copy. The
duplication is [B41](17-backlog.md).

### 3.74 The record could say two members differ, and not whether it matters

Asked for directly: *"when we perform a diff, if a model is available, let's ask the model its
opinion about the diff — whether it's likely substantive or semantically equivalent."*

A run that ends divergent now renders its differing members — through `trigon_api::member`'s
`read` and `view`, the same bounded diff the management UI serves, because a second diff
implementation is how the page and the prompt would come to disagree — and asks the configured
model for a reading: `substantive`, `equivalent`, or `unclear`. The rendering is capped in bytes
(§3.62's rule: a prompt is billed in bytes, and a line cap lets one long line blow the window),
control-stripped at the request boundary with the same `strip_controls` the log compressor uses
(threat-model P7), and every hedge the diff machinery makes travels to the model in words —
`truncated`, `unaligned`, lines omitted — because an opinion formed on a partial diff must not
read as one formed on the whole.

**The rule that shaped everything: an opinion, never a verdict.** ADR-0013 gives caches the rule
"bytes, never decisions"; models get "opinions, never verdicts". The outcome is final before the
question is asked. The publication gate does not read the field, and `trigon-api` now asserts
that in both directions — `equivalent` must not soften a divergence out of publication and
`substantive` must not harden one in. No signed statement carries it. The record carries it with
the model's name and the condition it was formed under (`members_shown` of `members_differing`),
which is the `artifactHashCheck.performed` lesson applied in advance: a reading of 3 of 300
members is a different claim from a reading of 3 of 3.

`unclear` is load-bearing. A classifier forced to two answers turns "I was shown a truncated
diff" into one of them, and the parse refuses to guess a verdict out of prose for the same
reason: pulling the word "equivalent" out of a paragraph would be this code deciding and the
model taking the blame.

This closes half of [B42](17-backlog.md): the bounded member-diff renderer now exists. The other
half — reusing it in the *repair* brief so the model proposing a fix can see what it is fixing —
remains open.


### 3.74b What the adversarial pass caught in §3.74's first cut

Twelve confirmed findings inside one reviewed commit, five of them the tree's own recurring
shapes:

- **§3.62 readmitted through the door that cites it.** The renderer's byte budget checked before
  each push, so one two-megabyte minified-bundle line landed whole at budget-minus-one — a
  forty-fold overshoot, in a function whose doc comment quotes the rule it broke. The line is now
  cut at a char boundary, and the test uses one huge line rather than many small ones.
- **A false claim handed to the model.** A `Differs` member with one unreadable side rendered as
  "only in the published artifact" — and the rubric explicitly reads one-sidedness as
  substantive. Same shape for duplicate member paths, where `member::read` returns the first
  occurrence and the census counts them: an empty diff under a header that says "differs". Both
  now render as hedges naming what could not be shown.
- **The census and the bytes come from different moments.** The comparison runs after
  normalization; the rendered members are raw. The preamble now says so and names the applied
  passes; showing stabilized bytes is [B43](17-backlog.md).
- **The one-implementation claim was false when written.** The commit's comment declared
  `strip_controls` "the one implementation" while a second, disagreeing private copy sat in
  `failure.rs` — and the copy on the model wire was the weaker one (it read only a letter as
  ending a CSI sequence; `ESC[4~` kept eating text). One implementation now, the stricter one.
- **The reverse of P7.** The model's `reason` is composed while reading package text and lands in
  the operator's terminal one line above trusted framing; serde decodes `\u001b` into a real
  escape byte. Scrubbed and flattened to one line at the single point every path passes.

Plus: run.json counted the opinion call while its token fields excluded it (the calls-versus-
tokens mismatch the cost block's own comment warns about, pointed the other way); the thin
terminal record dropped a paid-for opinion; the gate-indifference test asserted only the
softening direction (every baseline it used already published, so `if substantive then publish`
would have passed it); `unclear`'s wire word was pinned against nothing; and the truncation retry
asked at the provider's *default* effort — on a provider that ignores `Reasoning::Off` but
honours effort, a retry that thinks harder than the call that was too big.

### 3.75 Why `castle.core@5.1.1` did not build: two properties a solution build supplies and a project build does not

Reported as a build failure: `dotnet pack` on `src/Castle.Core/Castle.Core.csproj` ended
`NU5026: The file '.../bin/Release/net462/Castle.Core.dll' to be packed was not found on disk`,
naming the first target framework it looked for as though the compile had failed. It had not — it
never ran. Two independent causes, reproduced in the .NET 6 SDK image against the real checkout and
fixed together in `nuget/build/pack`.

**A false lead first, ruled out.** The generated script injects
`-p:LanguageTargets=<sdk>/Microsoft.CSharp.targets` unconditionally, and it was the obvious suspect
— a global property override on a cross-targeting build. Removing it changed nothing: the minimal
`netstandard2.0;net6.0` project packs with or without it, and so does Castle.Core once the two
real causes are fixed. The override is innocent here, and the PCL stratum it exists for (`docs/03-ecosystems.md` §"MSB4057") still needs it. Worth
the two builds it took to clear, because a plausible cause left unrefuted is where the next hour
goes.

**Cause 1 — `GeneratePackageOnBuild=true` makes `dotnet pack` build nothing.** The project sets it,
which unhooks the `Pack` target from `Build`: the package is meant to fall out of a build, so an
explicit `dotnet pack` runs `Pack` against a `bin/` nothing compiled and fails NU5026. Confirmed by
the full output — `dotnet pack` goes straight to the error with no `Determining projects`, no
compile, no per-TFM output — while a plain `dotnet build` produces all four DLLs (net462 included:
the cross-targeting build is fine). Microsoft's own guidance is that the setting and an explicit
`pack` do not combine. Fix: `-p:GeneratePackageOnBuild=false`, a no-op for projects that never set
it.

**Cause 2 — `$(SolutionDir)` is empty without a solution.** With cause 1 fixed, the build produces
the DLLs and then pack dies `Could not find a part of the path '.../src/Castle.Core/docs/images'`.
`common.props` names the package icon `$(SolutionDir)docs/images/castle-logo.png`, and
`$(SolutionDir)` is set only by a solution build. Building the `.csproj` directly leaves it empty,
so the path resolves under the *project* directory rather than the repository root where
`docs/images/` actually is. Fix: reconstruct what a solution build would have set by finding the
nearest `.sln` walking up from the project — `Castle.Core.sln` sits at the checkout root — and
falling back to the checkout root.

With both, the trigon-generated build script produces `Castle.Core.nupkg` from the real source,
offline, exit 0.

**The shape:** neither is a defect in the tree's logic; both are facts about a project that assumes
it is built the way its CI builds it — through a solution, with a version injected — and trigon
builds the one thing the verdict is about, the project. The reconstruction has to supply what the
solution would have. The third such fact is the version, and it is not yet supplied — see
[B44](17-backlog.md): the package still comes out `0.0.0` because the project derives its version
from a custom `BuildVersion` property that `-p:Version` does not reach, so this reproduces the
*build* and not yet the *bytes*.

### 3.76 Why `castle.core@5.1.1` still diverges once it builds, peeled apart

With [3.75](#375-why-castlecore511-did-not-build-two-properties-a-solution-build-supplies-and-a-project-build-does-not)'s two fixes it builds, and the outcome is a divergence — the layer 3.75 predicted. The diff-opinion ask ([3.74](#374-the-record-could-say-two-members-differ-and-not-whether-it-matters)) read it correctly on the first live run: *"version 0.0.0 instead of 5.1.1, differing copyright year, extra PDB files, binary differences in all DLLs."* Reproduced against the real source in the .NET 6 SDK image, it is three causes stacked, and they come apart cleanly:

**1. A second package nobody asked to compare against.** `common.props` sets
`<IncludeSymbols>true</IncludeSymbols>`, so pack writes `Castle.Core.<v>.nupkg` **and**
`Castle.Core.<v>.symbols.nupkg`. `output_path: trigon-pack/*.nupkg` matches both — the run's
`collected no single artifact` warning — and the symbols copy carries the four `.pdb` the main
package does not, which is where `onlyrebuild lib/*/Castle.Core.pdb` came from. The published
artifact is the main package; the symbols one is a separate feed. Fixed in the tool with
`-p:IncludeSymbols=false`, a no-op where it was never set: pack now emits exactly one package.

**2. Two values the publisher's CI set, that a checkout does not carry.** `<BuildVersion>` defaults
to `0.0.0` (the CI overrode it from `APPVEYOR_BUILD_VERSION`), and `PackageVersion`, `VersionPrefix`,
`FileVersion` and `AssemblyVersion` all derive from it — so `-p:Version=5.1.1` is ignored and the
package comes out `0.0.0`. And `<CurrentYear>$([System.DateTime]::Now.ToString("yyyy"))</CurrentYear>`
reads the build machine's clock into the `<Copyright>` string, so the rebuild says 2026 where the
publish said 2022. Reconstructing both — `-p:BuildVersion=5.1.1`, `-p:CurrentYear=2022` from the
registry publish date — makes the four DLLs **the exact same size as published**, byte-for-byte on
length. This is [B44](17-backlog.md): the values are reconstructable (the version from the purl, the
year from `registry_time`), but the *property names* are the project's own and Trigon cannot guess
them; the faithful source is the published assembly's own version fields.

**3. What is left is the compiler.** With version, year, symbols and `ContinuousIntegrationBuild`
all matched, each DLL still differs — **3,690 of 385,024 bytes on the net6.0 assembly, scattered
from offset 137 to the end, at identical size.** Not a localized MVID or timestamp; the spread and
the equal length are the fingerprint of a different Roslyn. The build used SDK 6.0.428 (2024); the
package was compiled 2022-12-30 with whatever 6.0.4xx was current then. This is exactly what the
strategy's own assumption line warns: *"a divergence here is as likely to be the toolchain as the
source."* The `.NET 6`-by-major SDK selection is too coarse — byte reproduction needs the SDK build
current at `registry_time`, which is [B45](17-backlog.md).

**The shape, three times over:** a project builds the way its CI builds it — through a solution,
with a version and a year injected, with a compiler pinned by the calendar — and Trigon builds the
project. Each layer is Trigon being handed less than the CI had and having to reconstruct the rest;
1 it can do from the project, 2 from the publish metadata, 3 only from a historical toolchain index.

### 3.77 Decompiling the assembly, so the diff is C# and not bytes

Asked directly: *"could we use ilspy to decompile the DLLs to show the differences as source code?"* Yes,
and it turns out to be the sharpest tool yet for the compiled-language case.

For an executable member a byte diff says only "these differ", which is true and useless — and the
diff-opinion model ([3.74](#374-the-record-could-say-two-members-differ-and-not-whether-it-matters))
read `castle.core`'s four differing DLLs as *substantive* precisely because "binary differences in
all DLLs" looks substantive. `ilspycmd`, run in a container, turns each side back into C#, and the
diff of *that* is legible. Measured on `castle.core@5.1.1`'s net6.0 assembly: the two copies differ
by **3,690 scattered bytes at identical size**, and decompile to C# that differs by **sixteen
lines, every one an assembly attribute** — copyright year, `AssemblyFileVersion` 5.1.1 vs 0.0.0,
`AssemblyVersion` 5.0.0.0 vs 0.0.0.0, the framework display name. With the version and year
reconstructed ([3.76](#376-why-castlecore511-still-diverges-once-it-builds-peeled-apart)) it is
**one line**. All 25,820 lines of code are identical. ILSpy normalises the compiler codegen that
[B45](17-backlog.md) is about, so what is left in the diff is the difference that is really there.

**Display only, the rule the opinion is already under.** ADR-0013 gives caches "bytes, never
decisions"; a decompiler gets "readable form, never a decision". The C# never reaches the comparison
outcome, the publication gate or a signed statement — it is produced after the verdict is final,
from bytes re-read off disk, and flows only into the opinion prompt. An adversarial pass confirmed
that boundary holds and turned up two things worth fixing, both about not overclaiming or not
trusting the input:

- **The reassurance was too strong.** The header first told the model "an empty diff means identical
  source compiled differently". ILSpy hides most codegen but not all, and past a 2 MiB truncation an
  empty diff means "identical prefix", not "identical source". It now says the decompiler found no
  source-level difference, that this is *likely* the toolchain, and that the census is what decides
  — a hypothesis about *why* the bytes differ, never a second opinion about *whether* they do.
- **The bytes are the publisher's, so the container is bounded.** The decompile runs on the
  divergent path, right where an accusation is recorded, and the sandbox's build timeout does not
  reach it. A crafted assembly could have hung `ilspycmd` and stalled the run; the decompile now
  runs under `--memory`, `--pids-limit` and a `timeout`, and a side that fails or times out falls
  back to the byte diff rather than a truncated one.

The image (`localhost/trigon-ilspy`, `ilspycmd` pinned) is built once and reused; `--network none`
on every decompile; both sides always go through the one pinned tool, so a difference in the C# is a
difference in the assemblies and not in the decompiler. Best effort throughout — a machine with no
podman loses the reading, not the run.

### 3.78 The decompiled diff, in `trigon serve` as well as in the model's prompt

[3.77](#377-decompiling-the-assembly-so-the-diff-is-c-and-not-bytes) put the decompiled C# in front
of the opinion model but not in front of a person: `trigon serve`'s member view still opened a
`.dll` as a hex window. The gap was real — a reader browsing a divergence saw exactly what the model
used to, "these bytes differ", and nothing to act on.

The member route now serves the C# diff for a managed assembly, and the same one the opinion reads:
open `lib/net6.0/Castle.Core.dll` on a divergent `castle.core` run and the text view is

```
- [assembly: TargetFramework(".NETCoreApp,Version=v6.0", FrameworkDisplayName = ".NET 6.0")]
+ [assembly: TargetFramework(".NETCoreApp,Version=v6.0", FrameworkDisplayName = "")]
- [assembly: AssemblyCopyright("Copyright (c) 2004-2022 Castle Project …")]
+ [assembly: AssemblyCopyright("Copyright (c) 2004-2026 Castle Project …")]
- [assembly: AssemblyFileVersion("5.1.1")]
+ [assembly: AssemblyFileVersion("0.0.0")]
- [assembly: AssemblyVersion("5.0.0.0")]
+ [assembly: AssemblyVersion("0.0.0.0")]
```

with every other line identical — the hex view is still a click away for the bytes themselves.

**Injected, so the serving crate never learns what ILSpy is.** `trigon-api` cannot run a container —
that is the binary's world, and a public read surface with a podman dependency is the wrong shape.
So the decompiler arrives as a hook: `trigon serve` hands `Api` a closure, `trigon-api` asks it about
every member and gets `None` for the ones it does not handle, and a deployment without podman serves
the hex view exactly as before. The predicate for "is this an assembly" lives once, with the
decompiler in the binary. The class gate that already covers member bytes covers this — a
decompilation is the member's content in another form — and `decompiled: true` on the view is what
makes the page say the diff is a reading of the assembly, not the assembly.

### 3.79 The reproduction recipe is in the CI config, not the build scripts

Asked, of `castle.core`: *"there are build scripts in the repository, are we using them? should we?"*
No, and no — and the reason is the same one [3.76](#376-why-castlecore511-still-diverges-once-it-builds-peeled-apart)
and B44/B45 keep circling.

`build.sh` is not a recipe for the package. It runs `dotnet build --configuration Release` over the
whole solution and then the **test suites** — net462 through mono, netcoreapp3.1 and net6.0 — and
fails if any test fails. It needs mono or docker, builds the test projects as well as the library,
never runs `dotnet pack`, and **sets no version**: it would produce `0.0.0` exactly as Trigon's
direct `dotnet pack` does. Running it would cost minutes of test execution and a mono toolchain to
reconstruct one library, and reconstruct it no more faithfully. Trigon's targeted pack of the one
project under verification is the right shape.

The recipe is one directory up, in the CI config the build script never reads:

- `appveyor.yml` line 46: `Update-AppveyorBuild -Version ($env:APPVEYOR_REPO_TAG_NAME).TrimStart("v")`
  — the package version is **the git tag minus its `v`**, `v5.1.1` → `5.1.1`, set into
  `APPVEYOR_BUILD_VERSION`, which `common.props` reads into `BuildVersion`, from which every version
  attribute derives. This is exactly the tag Trigon's strategy already found (`PrefixedTag`), so the
  version B44 cannot inject is sitting in a fact Trigon already holds.
- `.github/workflows/build.yml` names the SDKs the CI installs (2.1, 3.1, 6.0, 7.0) — the toolchain
  index B45 wants, stated by the project itself.

So the answer to "should we use the build scripts" is the sharper form of B44/B45: **not the build
scripts, but the CI configuration.** For NuGet, Trigon infers a heuristic strategy and does not read
the CI config the way its GitHub-Actions rung does for other ecosystems; doing so would close the
version gap (set `APPVEYOR_BUILD_VERSION`, or the property the config threads a version through) and
inform the SDK choice. Filed against B44 and B45 rather than built here, because reading a CI config
for its version and toolchain scheme is inference and belongs with the model rung, not a hardcoded
reading of one project's `appveyor.yml`.

### 3.80 Pre-computing the decompilation, and horizontal scroll for long lines

Two asks after [3.78](#378-the-decompiled-diff-in-trigon-serve-as-well-as-in-the-models-prompt) put
the C# diff in `trigon serve`.

**Pre-compute it — yes, and here is why.** The member view decompiled at serve time, which needs
podman on the serving machine and a container per view. That is wrong for the surface `trigon-api`
targets: a read replica over a bucket has no podman and no reason to. So the run, which has both,
now does it once. `record_run`, on a divergence, decompiles each *differing* managed-assembly member
— the interesting few — and stores the C# keyed by the assembly's own digest. `trigon serve` reads
the store first and falls back to a live decompile only on a miss. Measured: a member that used to
cost a ~5-second container returns in **47 ms**, and a divergent `castle.core` run with **no model
at all** leaves eight `decompiled/sha256/*.cs` in the store — the pre-compute is a property of the
run, not of the opinion.

Content-addressed by the assembly, so a re-run of the same target and two sides that share bytes
resolve to one object; best effort, so a machine without podman records the run and leaves the
reader the hex view; and a reading aid, so nothing reads it to decide an outcome. It runs **after** the record
is persisted and every container call it makes is wall-clock bounded, so a cold image build that
stalls on the network costs the aid, never the divergence finding it decorates — a review of this
change caught that the pre-compute had sat on the critical path to `put_run`. The store key is
sharded two characters like the blob store, and the "is this an assembly" predicate is one function
in `trigon-core` that both the decompiler and the serve cache-probe read, so a `.txt` member costs
no store lookup. The cost is real
and bounded: a decompile per differing assembly on a divergent compiled-language run, the minority
of a corpus, and skipped where the digest is already cached. The one case it does not cover is a
model-less divergence served from a podman-free replica where the run itself could not decompile —
there the reader still gets hex, and an eager sweep-time pass would be the fix if it matters.

**Horizontal scroll.** A decompiled line can be long — an `InternalsVisibleTo` with a full public
key runs past 500 characters — and the diff rows are flex at the container width, so a long line was
clipped rather than scrolled. Each row is now `width: max-content` with `min-width: 100%`, so the
widest line sets the scroll region and the container's `overflow-x` becomes a real horizontal
scrollbar while a short line still fills the width for its highlight.

### 3.81 A stabilizer for a .NET assembly's build and signing identity

Asked, of castle.core: the DLL differences look like cosmetic version numbers filled in at release
— can a stabilizer handle them? Investigating it changed the answer.

**The version numbers are not the cosmetic part; they are reconstructable, and better reconstructed
than normalized** (they are consumer-meaningful — `AssemblyVersion` is a binding identity). Building
with the target version, year and copyright — read from the published assembly and passed as
*standard* global MSBuild properties, no project-specific names — makes the rebuild decompile
**byte-identical** to the published DLL. Under an era-appropriate SDK (7.0.101) that took castle's
net6.0 assembly from a 3,690-byte divergence to **485 bytes**.

Those 485 bytes are the genuinely cosmetic, genuinely *un*reproducible part, and they are what the
stabilizer handles:

- the **strong-name signature** — an RSA signature over the assembly, made with a private key we do
  not have. This is exactly `nupkg-signature`'s case one level in: a `.sig` over content we rebuild.
- the **MVID** — a per-compilation GUID the runtime never reads for behaviour.
- the **PE timestamp and checksum**, and the **debug directory** — PDB GUID, checksum, path and
  build timestamps, for a `.pdb` the package does not even ship.

`dotnet-assembly-identity` walks the PE and CLI headers and zeroes exactly those regions in place,
so it names nothing a consumer runs and moves no offsets. `Metadata` risk — the signature alone is
`Structural`, the rest is `Metadata` like the archive timestamps — so a match reached through it is
`Normalized`, not caveated: what is zeroed is bookkeeping, not behaviour. Measured on castle:
485 → 217 bytes.

**The residual 217 is structural, and a stabilizer cannot reach it.** The debug entries' pointer
fields and the trailing PDB data sit at *different offsets* in the two files, because the PDB path
is a different length — the build *environment* (the source path map, the exact SDK patch), not a
field with a fixed home. Zeroing aligns same-offset regions; it cannot align different ones. So the
last mile is reconstruction of the build environment ([B45](17-backlog.md)) — matching
`DeterministicSourcePaths` and the SDK current at `registry_time` — not another stabilizer. Filed as
[B46](17-backlog.md).

The shape, again: three layers, each handed less than the CI had. The code reconstructs from the
project. The version reconstructs from the published assembly. The signature and build GUIDs cannot
be reconstructed at all and are normalized instead — and the debug *layout* needs the build
environment, which is the frontier.

### 3.82 Version reconstruction: build the assembly with the version the feed served

Piece two of the castle.core work, and the honest primary fix for the version stamps
[3.81](#381-a-stabilizer-for-a-net-assemblys-build-and-signing-identity) declined to normalize:
they are consumer-meaningful, so the assembly is built *with* the published version rather than
having the difference erased.

A deterministic repair rung, the shape of the yarn rung and running in the same place — before any
model, whether or not one is configured. On a divergence in which a managed assembly differs, it
reads that assembly's version stamps back out of the published package (`AssemblyVersion`,
`AssemblyFileVersion`, `AssemblyInformationalVersion`, copyright — parsed from a decompilation of
one differing member) and sets them on the `nuget/build/pack` step as standard MSBuild properties.
A value passed on the command line is a global property that overrides whatever the project derived
it from, whatever the intermediate was named — so `castle.core`'s `<BuildVersion>`-from-CI
indirection, which defeated `-p:Version`, is beside the point. `-p:PackageVersion` goes with them,
so the package version reconstructs too and the nupkg is no longer named `0.0.0`.

Proven end to end: `castle.core@5.1.1` rebuilt with no model at all now carries the published
`AssemblyVersion 5.0.0.0`, `AssemblyFileVersion 5.1.1`, `AssemblyInformationalVersion 5.1.1` and
`Copyright … 2004-2022` where a default build wrote `0.0.0`/`0.0.0.0`/`2026`, and the package is
`Castle.Core.5.1.1.nupkg`. The rung fires once — `changes_anything` and a no-op-returning transform
guard it against looping — and keeps the divergence it found before going round, so a re-run that
fails still reports it.

**What this does and does not close.** The version reconstruction makes the assemblies decompile
identically to the published ones; combined with `dotnet-assembly-identity` it removes the version
and the signing/build identity. What remains for a full `castle.core` match is the toolchain: under
an era-appropriate SDK the residual is the structural debug layout ([B46](17-backlog.md)); under the
`.NET 6`-by-target SDK that `--image auto` selects today it is compiler codegen throughout
([B45](17-backlog.md)). Two of the three layers are now built; the third is the SDK-by-publish-date
frontier.

### 3.83 SDK by publish date: build with the toolchain the CI had, not the one the target names

Piece three of the castle.core work, and the layer [3.82](#382-version-reconstruction-build-the-assembly-with-the-version-the-feed-served)
named as the frontier. `dotnet::choose` selected the SDK by the project's declared target-framework
major, capped at the newest that had shipped by the publish date — a `net6.0` target became the .NET
6 SDK. That is the wrong toolchain: a package is built with whatever SDK its CI had installed, which
is the newest one that existed when it published, and the declared target is a *floor* that SDK
clears rather than the SDK itself. castle.core proves it directly — its `appveyor.yml` builds on the
"Visual Studio 2022"/"Ubuntu" images, whose December-2022 SDK was .NET 7.0.101, and building under
.NET 7 gets its decompiled code byte-identical where .NET 6 diverges throughout ([B45](17-backlog.md)).

So the choice is inverted. The publish instant now leads — `choose` builds with the newest SDK that
existed at `registry_time` — and the declared target only pulls the choice *up*, when a project
targets something newer than any SDK that had shipped (a preview, or a publish instant that is not
when the bytes were made). Above both sits a `global.json`: when the repository pins an SDK, that is
the publisher naming the toolchain outright, and it wins over target and date alike. The resolution
is read from the same two roots the project file is (the host checkout, else the source cache) by
walking up from the project directory to the checkout boundary — no further, so a `global.json`
above the boundary, which the package never carried, is never read.

For castle.core, `choose` now returns .NET 7 for a 2022-12-30 publish, and the assumption line says
why: *the newest SDK that existed when the package was published; the declared .NET 6 target is a
floor that SDK clears.* What remains is patch precision — the image is the rolling `sdk:7.0` tag, not
the exact `7.0.101` — which for castle's code does not matter (the decompiled bytes are stable across
a major's patches) and leaves only the structural debug layout ([B46](17-backlog.md)). All three
layers of the castle.core reconstruction are now built.

**The regression this trades against.** Preferring the newest SDK can only turn a match into a
divergence, never a divergence into a false match — a wrong toolchain produces different bytes, which
the comparison catches, not agreeing ones. The exposure is a package genuinely built with an older
SDK than the newest-at-publish and pinning it *without* a `global.json` — chiefly one published in
the weeks just after a new major, before the ecosystem's CI images rolled forward. That case now
diverges where it may have matched; the principled repair is an escalation rung that, on a .NET
codegen divergence, retries under the floor SDK, and is the natural next step past this one.

### 3.84 Colour and sections in the human-readable output

The verdict and the build report were correct and hard to skim: one weight, one colour, labels and values and prose all the same grey. A `style` module now paints them, under three rules that keep the colour honest — colour follows the terminal (a result piped to a file or a program is plain, the same principle the log subscriber already applies to stderr); `NO_COLOR` set to anything non-empty wins, per <https://no-color.org>, with `CLICOLOR_FORCE` to override back on for a pager; and colour is only ever an accent, never the message, so every distinction it draws is also in the words and the symbols and the plain output says exactly what the coloured one does.

The module is zero-dependency — a hand-rolled SGR wrapper, in keeping with the verifier's small-tree ethos — and not gated behind the `build` feature, because the verifier prints a verdict too and it should read as well as a build's does. Widths are computed on the plain text with the colour wrapped around the result, since an escape sequence has bytes but no width; pad first, paint second, or the columns drift by the length of the codes. What it paints: the verdict green/yellow/red to its outcome, the digest rows' `=`/`≠` green and red, a non-zero differ count red, noteworthy codes yellow, section titles bold, field labels and explanatory asides dim, and identifiers cyan. The same vocabulary carries across `verify`, the build run, `resolve`, and the `stabilizers` listings, so the whole tool reads as one report rather than a dozen ad-hoc formats.

**Extended to the whole rebuild run.** The first pass painted the verdict and the verbose build block; the bulk of what a `rebuild` prints is the run narration itself — `artifact`, `published`, `source`, `strategy`, `guarding`, `image`, `repair`, `mirror` — one `  label   value` line at a time, deliberately on stdout rather than through `tracing` (so a `no-strategy` run's reasons are not lost at the default log level). A `note(label, value)` helper now renders each in the shared vocabulary: a dim label in a fixed column, the value styled by its role — identifiers and digests cyan, assumptions and asides dim, a repair that succeeded green, one that stopped or was discarded yellow, a `no-strategy` outcome yellow. Resolve through strategy through repair through verdict now reads as a single coloured report, and piped it is byte-for-byte the layout it always was.

**Contrast, one column, and overflow.** A first look at the painted output read as washed out — the labels and asides leaned on SGR `2` (faint), which is the lowest-contrast code a terminal has and which several render nearly invisible, so most of the run was grey on grey. The palette is now built from bright colours and weight: labels are **bold bright blue**, identifiers **bright cyan**, headings **bold bright white**, and asides a real **grey** (bright black) rather than faint — every line carries colour and none of it disappears. Risk tiers are painted by how much latitude a pass took (structural and metadata cool, content and lossy warm), so the `applied` and profile tables say at a glance which passes could hold only a caveated match. Two structural fixes came with it: every `label   value` line pads its label to one tool-wide width (`style::LABEL`), so values line up down a single edge across the resolve narration, the build stats, the verdict and the listings — where before each section chose its own width and the columns stepped in and out; and a full hex object name (a 40-char commit, a 64-char image id) is shortened to twelve for display, because at full length it wrapped the terminal and threw the next line back to the margin.

### 3.85 Wrapping, one column everywhere, and an audit of the whole surface

Using the coloured output on a real NuGet rebuild turned up three faults the first passes had left: long explanations (`assuming`, the SDK rationale, the tag-mutability caveat) ran off the right edge and wrapped ragged back to the margin; a few lines still used their own label width and stepped out of the column; and identifiers with an *embedded* digest — `mcr.microsoft.com/dotnet/sdk@sha256:<64hex>` — overflowed because the shortener only fired on a whole-string hash.

The fix has three parts. A `style::wrap(text, indent)` folds a long value to the terminal width with a hanging indent, so an explanation flows *under* its value column instead of back to the margin; the width comes from `TIOCGWINSZ` (behind the `libc` the crate already links) or an explicit `COLUMNS`, and is `None` when stdout is piped — so a redirected run stays byte-for-byte the single lines it always was, and only a terminal (or a reader who sets `COLUMNS`) wraps. `short_ref` now shortens *every* long hex run inside a reference, so the digest after `@sha256:` collapses while the readable `mcr.microsoft.com/dotnet/sdk` part stays. And the label column is one tool-wide `field(label, value)` helper (`style::LABEL`), so the resolve narration, the build stats, the verdict, `resolve`, the `stabilizers` listings, `check`, `worker` and the grant/enqueue/keygen commands all read down one edge.

To stop finding one missed line at a time, a six-way parallel audit read the entire output surface and returned 59 sites — unstyled lines, wrong widths, overflow-prone values, tracing that read out of place — which this closes in one pass. The pre-run banner (`image`/`egress`/`store`/`work`) moved out of `rebuild-and-attest.sh`, where it was plain and a column narrower, into `trigon rebuild` itself, so a direct run shows it too and one place owns the colour and the `NO_COLOR` rule; the script's remaining headings now guard their bold on a TTY and `NO_COLOR` the same way the binary does.

### 3.86 Why `moq@4.20.72` did not build, and the hermetic rung that lets it

`moq@4.20.72` failed to build at all under `mirror-only`: three attempts, each `net/unreachable`, no verdict. The error named NuGetizer — `NuGetizer.Shared.targets(326,5): error : Network is unreachable (raw.githubusercontent.com:443)` — and the first guess was the referenced `TypeNameFormatter.Sources` package's legacy `<iconUrl>`. It was not: a diagnostic pack with `-v diag` showed the fetch is NuGetizer resolving a **readme `<!-- include URL -->` directive**. Moq's `readme.md` carries `<!-- include https://raw.githubusercontent.com/devlooped/sponsors/main/footer.md -->`, and NuGetizer inlines the target at pack time. A local include resolves from the checkout; a remote one is a network fetch, and the build's island has no route to it, so `dotnet pack` dies before it writes a package. (SourceLink also names `raw.githubusercontent.com`, but only as embedded PDB metadata — it makes no request; the icon download is a red herring, since Moq ships its own `<icon>` and the published nuspec carries no `iconUrl`.)

The rung, in `nuget/build/pack`: before packing, neutralise **only remote** `<!-- include http(s)://… -->` directives in the checkout's markdown, leaving local includes to resolve as they do. The pack then stays offline and produces a package. The remote target is a moving branch (`…/main/…`) whose content — a sponsor list refreshed at release time and absent from the checkout — is not reproducible even for the publisher and is not the package's own source, so there is nothing to reproduce; neutralising it is the honest hermetic choice, not a loss.

Proven end to end: `moq@4.20.72` now **builds** and reaches a comparison rather than failing. It is `divergent`, and the residual is now legible: the four `Moq.dll` targets differ throughout (the SDK/Roslyn toolchain frontier, [B45](17-backlog.md)); `Moq.nuspec` differs; and `readme.md` differs by exactly three lines once EOL is normalised — the neutralised remote-include directive, a marker whose pairing shifted with it, and a trailing blank — while the sponsor avatars and links, which come from a *local* include, reproduce byte for byte. A build that never ran became a divergence a reader can see and attribute.

### 3.87 `moq@4.20.72`'s DLL divergence is embedded debug provenance, not code or toolchain

With the readme build fixed ([3.86](#386)), `moq@4.20.72` is `divergent` with four `Moq.dll` targets differing throughout (~56 KB of ~312 KB, "never benign"). Peeled apart, it is none of the usual suspects:

- **Not the code.** ILSpy-decompiled C# of the published and rebuilt `net6.0` `Moq.dll` is byte-identical (11,520 lines, empty diff). The differing bytes concentrate entirely in the tail (offsets ~229–312 KB); the IL/metadata region differs by ~33 bytes (MVID, timestamp, strong-name signature).
- **Not the SDK patch.** Building with `sdk:8.0.400` (the patch current at the 2024-09-07 publish) gives 56,301 differing bytes — the same as `8.0.423` (56,252). The patch is not the variable.
- **Not non-determinism.** Two identical `8.0.400` builds are byte-for-byte equal (0 differing bytes). The build is deterministic; the difference vs published is a genuine *input*.

The tail is the **embedded PDB** — Moq builds `DebugType=embedded`, so the portable PDB rides inside the DLL. Extracting and comparing both PDBs, the inputs that differ are all git provenance that SourceLink embeds, none of it functional:

- **SourceLink URL** — published `https://raw.githubusercontent.com/devlooped/moq/<sha>/*`, rebuilt `…/moq/moq/<sha>/*`. Moq's GitHub org was renamed `moq` → `devlooped`; trigon resolved and cloned the package's recorded `github.com/moq/moq` (which still redirects), so its `origin` — and thus SourceLink — carries the old name while the publisher's build carried the new one. The nuspec `<repository url>` is `moq/moq` in *both*, so this is SourceLink's remote resolution specifically.
- **nuspec `branch`** — the published `<repository>` carries `branch="v4.20.72"`; the rebuilt one omits it, because trigon checks out a detached commit rather than the tag ref the publisher built from.
- A source-generator document (`IFluentInterface.g.cs`) ordered one position differently, and the PDB id/size that cascade from all of the above.

So the assembly is **code-identical and divergent only in embedded debug provenance** — the SourceLink map and the git ref, which say where the source lives, not what it is. That is normalizable (a `Content`/`Lossy`-tier concern: debug info is not the functional artifact), and is the natural next extension of `dotnet-assembly-identity` — normalize the embedded PDB's SourceLink/provenance the way it already normalizes the signing identity — rather than a toolchain or source problem. Reconstructing the exact git state cannot close it: the publisher's own nuspec (`moq/moq`) and PDB (`devlooped/moq`) disagree, so no single remote value matches both.

### 3.88 `--theme`: the reader picks the palette

The colour work settled one palette; different readers want different ones, so `--theme` (global, so it reaches the run narration `--output` never did) selects it: `auto` (the default — colour on a terminal), `textnocolor` (always plain, for a clean pipe), `textcolor` (the base palette forced on even into a pipe), `neon` (the palette one step brighter), and `bbs` (neon plus the flourishes — a block-prefixed heading and a reverse-video verdict badge). `NO_COLOR` still overrides all of them. The theme is chosen once at startup and read by the `style` palette functions, so every call site is unchanged; the palette is a table swapped by theme, and BBS's difference from neon is flourish, not colour. It is orthogonal to `--output text|json` — a theme never touches the machine-readable output.

### 3.89 `dotnet-il-canonical`: compare a managed assembly by its code, not its layout

[3.87](#387) established that `moq@4.20.72`'s four assemblies are code-identical (their method IL is byte-for-byte equal) and diverge only in metadata and debug *layout* that a byte-zeroing pass cannot align. So a new stabilizer stops trying to align it and reads past it.

`dotnet-il-canonical` walks the assembly's own ECMA-335 tables — by hand, no decompiler or metadata crate for the verifier to link and a sceptic to re-audit, the same stance `passes.rs` already takes to a PE — and emits, per method, its name, its signature (resolved through the `#Strings`/`#Blob` heaps to values, not the offsets that shifted) and its IL body. Two assemblies built from the same source reduce to the same bytes; a changed body, a new method or a changed signature still shows. It is **lossy** — it drops resources, custom attributes and field data — so a match it makes is `normalized_with_caveats`, the honest tier for "the code is the same and we did not check the rest", never a clean `normalized`. It runs last in the nupkg set, after `dotnet-assembly-identity` has taken the fixed-location identity; an assembly it cannot read whole is left exactly as it was, and one whose code genuinely differs (castle.core's stale SDK-6 rebuild, say) still diverges — it does not manufacture a match.

Two smaller residuals closed with it, both build provenance rather than code: `nupkg-repository-branch` drops the `<repository branch="…">` git ref (a tag the publisher built from, nameless in trigon's detached checkout), and `nupkg-readme-markers` strips NuGetizer's `<!-- include … -->` marker comments and the whitespace neutralising a remote include ([3.86](#386)) left spelled differently than the publisher's networked build. With all three, `moq@4.20.72` — build-failed three weeks ago, `divergent` last week — is now **`normalized_with_caveats`**: its stabilised digest matches, and the caveat says plainly that the match is of the code, normalised of everything the compiler wrote around it.

**The trade.** Every managed assembly now compares by code, so a `.nupkg` that once rebuilt byte-clean under `dotnet-assembly-identity` alone reads `normalized_with_caveats` rather than `normalized`. That is honest for a compiled artifact — one always carries an embedded PDB and a build stamp it can rarely reproduce exactly — and it turns the common case, a `divergent` that was really code-identical, into a caveated match a reader can trust. The cost is that a difference only in resources or attributes now reads as a caveat too, which the Lossy tier exists to say out loud.

### 3.90 `trigon serve` shows what the stabilizers did, and how a member was reconciled

A normalized verdict is only as trustworthy as a reader's ability to see what earned it. The corpus browser stated *that* passes fired; it now shows *what* each did and, where the record allows, *how* it erased a specific member's divergence.

**Each pass in the ledger unfolds a description.** Every stabilizer id gets two lines — what it does, and why doing it is safe — keyed by the id the ledger already prints, so a reader can tell what `dotnet-il-canonical` or `zip-time` changed without leaving the page or reading `passes.rs`. A pass with no entry simply shows none.

**A reconciled member opens.** The comparison blob records, per member, the rule codes that diverged *before any pass ran* (`body`, `entry:mode`, `entry:size`, `entry:zip.crc32`) and that the member is now byte-identical. A member that is `identical` *with* such a code on record is the interesting case — it differed and a pass put it right — so it is now openable, to a "differed → reconciled by" flow: the codes that diverged, each glossed in a sentence, beside the passes that erased them. Across the corpus this is the common metadata-reconciliation story — Newtonsoft.Json@11.0.1 reconciles 13 of 23 members this way, their archive entries renormalized while their bytes never moved.

**Attribution is by family, because that is what the blob supports.** The record says a pass fired and that a member's difference is gone, not which pass touched which field. So an `entry:*` difference is credited to the archive-framing passes that fired (`zip-*`, `tar-*`, `gzip-*`), a `body` difference to the content passes for a file of that kind (a `.dll` to `dotnet-il-canonical`/`dotnet-assembly-identity`, a `.nuspec` to the nupkg identity passes, and so on) — always intersected with the ledger, so the list names passes that ran, never passes that merely could. Claiming a precise field→pass mapping the blob does not hold would be a fabrication; naming the family that fired is the honest reflection.

**Moq is the exception the ledger already covers.** `dotnet-il-canonical` replaces each DLL's body with its canonical form *upstream* of the comparator ([3.89](#389)), so the comparator sees no `body@` divergence and records no per-member code — every one of `moq@4.20.72`'s ten members projects as untouched-identical. Its transform is therefore invisible at the member level and visible only in the ledger, where the pass shows its description, the entries and bytes it changed, and the `caps` badge that holds the verdict at `normalized_with_caveats`. The two views are complementary: the member view carries the metadata-reconciliation story, the pass view carries the code-canonicalization one.

### 3.91 Which pass changed which field of which member — attribution from ground truth

[3.90](#390) attributed a member's reconciliation by family: an `entry:*` difference, so *some* archive-framing pass did it. That is a guess, and building the serve UI on it surfaced two deeper facts. First, the difference `codes` a comparison stores are what stabilization *left*, not what it *erased* — measured directly: a member whose only differing fields are ones the passes normalize (mtime, uid) carries no code at all. So the "reconciled member" the UI drew was reading residuals, not reconciliations. Second, the blob recorded which passes fired but not what each one touched, so no precise attribution was possible from it.

Both are fixed at the source. `apply_traced` fingerprints every entry before and after each pass — exactly the fields `signature` compares, metadata only, so a 2 GB wheel's bodies are never read — and records each field that moved and the pass that moved it; a body rewrite is taken from the pass's own `Touched::bytes` rather than by hashing. The comparison merges both sides' edits and stores them beside its codes, keyed by `(field, path)`. The join is exact: a field a pass wrote that left no surviving code was **reconciled** by it; a field that still has a code was **touched but not resolved**; a code with no edit is a difference **nothing addressed**.

This makes the transform legible member by member, and closes the two gaps [3.90](#390) could not. A `.dll` whose body a pass rewrote shows that work *even when it ends byte-identical* — Moq's assemblies, reconciled by `dotnet-il-canonical`, left no code and so were invisible at the member level before; now the member opens to `body ✓ dotnet-il-canonical`. And where the code survives, the residual names the pass that tried: Newtonsoft.Json@11.0.1's DLLs read `body ↳ dotnet-assembly-identity, dotnet-il-canonical` — compared by IL and divergent anyway, which is the honest statement that the divergence is a real source-level change (its stale-SDK rebuild), not packaging. Of the run's 23 members, 13 now read fully reconciled, each field joined to the exact pass behind it.

**A comparator wart this exposed, and where it is handled.** `signature` compares the stabilized archive *in memory*, where three fields are stale shadows of what the writer will emit: an entry's `size` and `zip.crc32` are recomputed from the body on every write (`trigon_archive::zip`), and a zip's `meta.mode` is a parse-time shadow of `external_attrs`, which is what the writer actually stores. So a member the passes made byte-identical can still carry `entry:size`, `entry:zip.crc32` and `entry:mode` codes that cannot reach the output. These are filtered from the *projection* — `size` and `crc32` always (redundant with `body@`), `mode` when `external_attrs` was reconciled — so the UI does not report "still differs" on a member that is byte-for-byte identical. The stored blob keeps every code, and the real fix (not emitting a difference for a field the writer recomputes) belongs in `signature` itself, where it changes the published divergence signature and so is deferred to a change that can version it — see B47.

### 3.92 What a review of the publication design measured, and why Rekor is being removed

`docs/19` was reviewed against the code, against Rekor, GHCR and the OCI specifications, and for
internal consistency. Every finding went to an independent verifier that tried to refute it: 55
findings, 54 survived (34 as stated, 20 with a correction). The ones that decided
[ADR-0014](adr/0014-git-evidence-store-without-rekor.md), all measured between 2026-09-17 and
2026-09-23:

- **A Rekor entry commits hashes and no field of the statement.** The committed body of an `intoto`
  v0.0.1 entry is the envelope hash, the payload hash and the verification key or certificate
  (staging index 56040866, decoded, commits a whole self-signed certificate; `Canonicalize()` in
  Rekor's source). The previous `docs/19` §2.2's log entry "carrying" the outcome and set digest,
  and the "full statement" row of its §3 table, could not have been built with any entry type that
  takes an in-toto statement.
- **Rekor v1 serves the full statement anyway.** Its uncommitted attestation store keeps a decoded
  payload of 100 KiB or less and serves it: staging entry 56042318 returns a whole `equivalence/v1`,
  whose sha256 equals the committed payload hash. `attest --rekor` never consulted
  `publication::decide`, so a divergence published that way would have sat in full in storage we
  cannot correct.
- **The index claim in `docs/09` §3 and the previous `docs/19` §2.1 was wrong.** Querying Rekor's
  index by the artifact's sha256 returns our entries (the chardet wheel returns two). The earlier
  `[]` came from a fixture whose subject digest was a placeholder. Querying by the public key does
  return `[]`, but because the search and the index spell the key's hash differently, not because of
  Fulcio.
- **Rekor v2 cannot take our statements.** GA 2025-10-10; `intoto` dropped, `dsse` dropped in
  rekor-tiles v2.3.0 (2026-06-10), no attestation storage, no Signed Entry Timestamp, no search, and
  `hashedrekord` rejects pure Ed25519, which is what Trigon signs with. The public instance keeps
  Rekor v1 as its default log "for the foreseeable future".
- **ADR-0011's time bound was never live.** `within_validity`, the check that would compare the
  log's time with a certificate window, is called only from tests, and no certificate chain exists
  to check against.
- **GHCR has no OCI 1.1 referrers API.** `GET /v2/<name>/referrers/<digest>` returns 404 even for
  manifests that exist. The spec's fallback, a `sha256-<hex>` tag naming an image index, works there
  and is what GitHub's own attest action uses, and concurrent writers to one such tag drop entries
  (miracum/.github#212). cosign and oras have no mode for attaching to a subject outside the
  registry, which the previous `docs/19` §2.1 said they had.
- **Nothing in the local store is publishable.** `decide` requires two agreeing attempts counted by
  cache key, and 0 of 370 runs have one, because only worker jobs set it.
- **Signed history is being overwritten.** Attestations are stored per target, so a later `attest`
  overwrites an earlier one: 40 of 93 attestation paths are shared by more than one run.
- **`POST /v1/check` leaks withheld verdicts.** It is anonymous and answers from
  `Index::newest_for`, which ignores publication, so it reports a withheld divergence as divergent;
  its doc comment says the opposite. Confirmed by reading `fleet.rs` and `index.rs`; the fix is
  phase 0 of the build plan in `docs/19` §10.
- **npm downloads are not verified against the registry.** The fetcher reads only a `sha256-`
  integrity string and npm publishes sha512 and sha1, so `declared_sha256` is always absent. The
  code says so rather than pretending, and the fix belongs with multi-digest subjects (`docs/19`
  §5).

`docs/19` was rewritten from these, and its build plan (§10) is ordered by them: close the gate
bypass, accept the decisions, remove Rekor, change what the statements carry before anything is
published, make a run publishable at all, and only then build the store.

A second review of the git design, against GitHub's documentation, the C2SP specifications and `git`
2.43 itself, changed it in these places:

- **The checkpoint's time line would never have become third-party.** C2SP tlog-checkpoint calls
  extension lines not recommended, an Ed25519 cosignature makes no statement about them, and an
  ML-DSA-44 cosignature does not cover them. The time moved into every leaf, with a weekly heartbeat
  leaf, and a source whose newest leaf is too old now answers unknown, because a host serving an old
  but consistent log could otherwise turn a withdrawal back into a verdict.
- **A sparse checkout alone still downloads every blob.** Measured: only `--filter=blob:none` keeps
  `evidence/` out of a clone. A depth-1 clone cannot fast-forward, so a sync is a depth-1 fetch and
  a hard reset, and a shallow clone is a copy of the log, not of the history.
- **Two hex characters of fan-out would have put some 4,000 files in a directory** at a million
  records. GitHub recommends at most 3,000, and its file browser lists 1,000. It is four everywhere.
- **Classic branch protection exempts admins by default**, so the repository uses a ruleset with an
  empty bypass list; a write deploy key never expires, so a fine-grained or GitHub App token is the
  narrower credential; a release holds at most 1,000 assets; and unauthenticated clones are
  rate-limited like any other request.
- **The index was a way to hide a record.** Clients now resolve keys from the verified leaves, which
  carry every digest and the purl, and read `index/` only for `--remote`, which proves inclusion
  from the tiles.
- **`publish` would have signed leaves it did not write.** A holder of the push credential could
  plant leaves beyond the checkpoint for our next publication to sign. `publish` now builds only on
  the leaves a verified checkpoint covers, and `log sign` checks every new leaf against a record it
  can verify.

### 3.93 The anonymous surface asks the gate before it says `divergent`

`POST /v1/check` answered anonymous callers from `Index::newest_for`, which does not consult
publication, so a withheld divergence reached anyone as `divergent` ([3.92](#392)). Filtering on
"public" would not have fixed it: `Publication::is_public` is true for a `Void` run, and an
open-egress divergence still carries the outcome `divergent`. `GET /v1/runs`, `/v1/runs/{id}`,
`/v1/targets/{purl}` and `/v1/artifacts/{digest}` serialized that outcome to anybody, and so did
the record beside the entry, the rendered diff, the run page's boot island, `?outcome=divergent`
(which listed the row even with the word removed) and the `/v1/stats` counts.

`docs/19` §10 phase 0 closes it. An anonymous check answers only from runs the gate calls
`Published`; a `Void` run is `unsupported`, with the gate's reason; a `Withheld` run is absent, so
the newest older run the gate releases answers, or `never checked`. An operator is answered from
the whole store, ungated, as `trigon check` answers from a local one, and the handler's doc comment
now says both. An anonymous reader of a void run gets the row with its reason and without its
outcome, not counted as evidence; the record with nothing the comparison decided on it; and a
`published_as_void` refusal in place of the rendered diff. The serve UI draws that row as `void`,
with the reason.

The first version was checked against `trigon serve --public` with no queue, and said no anonymous
route returned `divergent`. Review found that wrong, and found more:

- **`GET /v1/jobs/{id}/events` served the worker's `outcome` note**, the comparison's label, written
  for every attempt before the gate runs, and `/v1/queue` hands out job ids. The route was missing
  from `routes::ROUTES`, which the seam sweep is built from, as were `/v1/queue`, `/v1/me` and
  `GET /v1/runs`. An anonymous reader now gets phases and times and no notes, and a test holds the
  table to the router.
- **The void's record said the verdict in other words**: `rebuild` (its digest is `upstream`'s on
  `exact`, and a prune keeps only a divergence's bytes), `transparency` (the verdict statement's log
  entry), `costs` and `transcript` (the rebuild's and the comparison's bytes, and a model asked only
  about a divergence). `record_shown` now names every field, so a new one does not compile until it
  is classified.
- **A withheld row was matched on its real outcome**, so `?q=<package>&outcome=divergent` answered
  `"withheld":1` where `outcome=exact` answered 0. It is matched without one, and still counted.
- The `non_builtin_stabilizer` sentence told a reader of a package that matched that it would
  otherwise have been a divergence; the per-run routes refused a withheld id and an absent one
  differently; and the `void` bar filtered to nothing.

Confirmed by `crates/trigon-api/tests/seam_publication_gate.rs`: a test per done-when item; a sweep
of every route in the contract, over a sqlite queue holding the worker's notes; and §4.3 in its
strongest form, that a void which matched and one which diverged, and a withheld match and a
withheld divergence, get byte-identical answers to every anonymous request (the comparison's
digest, kept on purpose, held equal). Each fix was reverted in turn to see a test fail.

**Also closed: withheld counts by reason.** `/v1/stats` and `/v1/fleet` counted withheld runs by
reason, and `kill_switch`, `image_derived_outside_boundary` and `provenance_unknown` are given only
to a confirmed divergence, so `by_withheld` published how many there were, and on a small corpus one
held-back package and its reason key were the accusation. An anonymous reader now gets one total,
`withheld`; a total is safe because every outcome can be awaiting confirmation. The operator view is
unchanged. `an_anonymous_reader_gets_one_withheld_total_and_no_reason_that_only_a_divergence_has`
holds it.

### 3.94 Rekor and Sigstore removed, with the decisions accepted first

`docs/19` §10 phases 0b and 1, on 2026-09-27.

**The decisions came first, because the removal takes out a path an accepted ADR mandated.**
[ADR-0014](adr/0014-git-evidence-store-without-rekor.md) is accepted. ADR-0011 says it is partly
superseded, names the parts, and carries a short note at each so a reader of its body is not misled.
ADR-0010 is amended, with an Amendments section ahead of its Decision: publishing is an explicit
`trigon publish`; correction is by supersession; disagreeing attempts are withheld rather than void;
safeguard 1 covers verdicts only; safeguard 4 is whatever D7 decides, and divergences are refused
until then; and same-host confirmation stays a setting, `same_host_confirmation`, default `false`,
because D8 has not accepted it. ADR-0008 gains the evidence store row, and its Signer row now says
what exists, a local file key. Backlog B10 points at `docs/19` and takes its phases as its
done-when; B21 is the chain alone, done when a statement under a real chain verifies in the verifier
and the negatives fail, with the time check deferred to phase 7a and dropped if D6 chooses key
epochs; and B29's three items about the log client are written off with the code they were about.

The threat model keeps the operator — whoever passes the flags — out of scope, and gains A8, the
operator of an evidence repository a client trusts, and A9, a host or mirror serving a stale or
split view, both marked as adversaries of a store not yet built. A project's `.trigon/evidence.toml`
is a §1.7 row, input chosen by the thing under test. The one transparency-log passage, §1.13's
`--transparency` paragraph, is gone, and what it disclaimed is now D24: nothing bounds a stolen
signing key. The sidecar generator's adversary list gained A8 and A9 and `docs/threat-model.yaml`
was regenerated from the prose. **The prose census had drifted before this change**: it said 192
documented tags, and the generator counted 195 at `d85ed4b`. It says 201 now, which is what the
generator counts.

**What was removed.** `trigon-attest`'s `transparency` module and everything it exported
(`LogEntry`, `intoto_entry`, `known_log`, `log_key_id`, `payload_id`, `utc_rfc3339`,
`within_validity`), and `p256`, which took ten crates out of `Cargo.lock`. The binary's log client
and its tests, including the `TRIGON_LIVE` fetch from staging; the attest flag that logged a
statement and its dry run; `verify-attestation`'s entry check, its log-key flag and the matching
key of `--output json`; `RunRecord.transparency`, with the arm of `record_shown` that hid it from an
anonymous reader of a void (phase 0's test lost it from the fields it checks are gone); the fifth
column of `trigon runs`; the log options of `scripts/rebuild-and-attest.sh`, and the verify line it
printed for them; six fixtures and two test files; and the two dry-run tests in
`crates/trigon/tests/keys_and_dry_run.rs`. The prose followed: `README.md`, `docs/00`, `01`, `09`,
`11`, `13` and `using-trigon.md`. `docs/09` §2's `buildobservation` row was wrong on its own
account, and now says its subject is the upstream artifact and that every attested run emits one.
`crates/trigon` keeps `reqwest`, which nothing in it calls now, for phases 5 and 6; its manifest
says so.

**What the greps show.** `git grep -i -e rekor -e sigstore -- crates scripts xtask` is empty, and
so is `git grep -e '--rekor' -e '--transparency' -- README.md docs ':!docs/16-findings.md'
':!docs/adr' ':!docs/19-distribution-and-lookup.md'`. `transparency` survives in `crates/` in one
file, `crates/trigon-store/tests/old_run_files.rs`.

**The archive.** One stored run, `1789588410-870c0fe1`, carried a `transparency` value, staging
index 56044745, which its next rewrite drops. The file is copied byte for byte to
`crates/trigon-store/tests/fixtures/run-1789588410-870c0fe1.json.gz`. It is gzipped because its
`log` field names the removed log, and the first grep above has to come back empty over `crates/`;
the test checks the decompressed bytes against the stored file's sha256, `d8e29e04…`, so the
archive cannot quietly stop being that file. It reads the file through `Store::get_run`, as `trigon
runs`, `attest` and `serve` do, and then writes it back: the key is gone and every other value is
unchanged. `RunRecord`'s doc comment now says why it has no `deny_unknown_fields`.

**Two small things found on the way.** The SPKI PEM test in `signer.rs` said it checked the
hand-built DER "against a parser that did not write it", `p256`'s, and parsed nothing; it now reads
the PEM back with `ed25519-dalek`'s own SPKI decoder and compares keys. And nothing pinned the keys
of `verify-attestation --output json`, so the one removed here could have gone, or another come,
without a test noticing; `verify_attestation_json_carries_exactly_the_keys_its_help_names` pins the
five that remain, and `runs_prints_the_id_first_and_the_target_second` now fails on a fifth column.

### 3.95 Every digest in the subject, every declaration checked, and what a run threw away

`docs/19` §10 phase 2, first half, on 2026-09-27. The statements' predicates are unchanged; the
second half moves them to v2.

**What was measured first.** The npm fetcher checked nothing: it read only a `sha256-` integrity
string, npm sends sha512 and sha1, and the one field the fetch compared against was empty for
every npm package. PyPI's md5 and blake2b_256 were never read, and a crates.io `checksum` that was
not a sha256 was dropped, which reads the same as none. NuGet's registration `catalogEntry` carries
no hash; the catalog leaf it names by `@id` does, as a base64 sha512 `packageHash`, and for
Newtonsoft.Json 13.0.3 and 3.5.8 (published 2011) it is the sha512 of the bytes the flat container
serves. In the local store, 0 of 371 runs had `strategy`; 167 carried a guard manifest digest and
none had the manifest in the store; and 40 of 93 attestation paths were shared by more than one
run, so each of those runs' records names a statement a later run wrote over.

**What changed.**

- `Subject::with_digests` carries sha256 and sha512, and sha1 where the ecosystem publishes one
  (`Ecosystem::publishes_sha1`, npm alone); `Subject::of_bytes` computes all three. The attestor
  computes the upstream subject from the blob it fetched by hash and checks it against what the
  run recorded; `equivalence_for` refuses a subject the comparison is not about; and `rederive`
  checks every digest a subject names, so a statement signed with sha256 alone verifies as before.
  The rebuilt artifact's subject is sha256 and sha512.
- Every fetcher hands its declarations to one verifier (`trigon-registry/src/declared.rs`) that
  checks each one this build can compute and refuses on the first that does not hold, naming the
  algorithm, the field and both values. npm's `integrity` and `shasum`, PyPI's whole `digests`
  object, crates.io's `checksum`, and NuGet's `packageHash` from the catalog leaf. A refused or
  broken download is deleted rather than left under the artifact's name. Declarations all of
  algorithms this build cannot compute are recorded as a download checked against nothing.
- `RunRecord.upstream_digests` holds the upstream's sha512 and sha1, computed at fetch, and one
  entry per declaration with its source field and `matched` or `unchecked`. Nothing declared is an
  empty list and a note. The record also keeps the strategy as a blob of its canonical JSON
  (`RunRecord.strategy`, distinct from `strategy_digest`), the guard manifest as a blob under the
  digest it already carried, and `trigon_version`. `rebuild`'s `strategy.json` byproduct now names
  the blob, and is left out for a run that stored none.
- Statements are filed at `…/<artifact>/<run-id>/<predicate>.intoto.json`, created only if the
  name is free. One that differs from what is there is written beside it as `.2`, `.3`, and the run
  record lists every path; the same bytes again are the same statement. Readers go by the paths a
  record names, so runs attested before this still read. A run attested again names only what is
  filed under it and sets its per-target paths aside in `per_target_attestations`, which nothing
  serves, since another run may have written over any of them.

**Found on the way.** The build loop kept the build of a divergence while a repair ran, so that a
repair that failed would not lose it, and never let go of it: a repair that went on to reproduce was
recorded with the divergent attempt's isolation, transcript and attestability, and every run's
strategy digest described the last attempt even where the verdict came from an earlier one. The
stash is now cleared when an attempt reaches its own comparison, whether the comparison succeeds or
fails, and carries the strategy beside the build. `record_terminal` wrote `guard_manifest: None`
for every run it recorded, so a void — the one run whose story is the guard — said the guard had
not been armed. And the digest length error said "expected 64 hex characters" for a sha512 too.

**What this does not do.** blake2b_256 is recorded and not checked, because nothing in the
workspace implements it and adding a crate for it is a dependency decision. `trigon_version` is the
crate version alone, since no build embeds a git revision. The 40 overwritten per-target paths
cannot be repaired: each still reads, as whichever run attested last, and only `rebuild`'s
`invocationId` says which run that was.

Tests: `crates/trigon-registry/tests/declared_digests.rs` runs each fetcher against a registry on
loopback, the npm case pinned to left-pad 1.3.0's real version document and tarball; subjects and
their verification are in `crates/trigon-attest/tests/rederive.rs`; the store's layout in
`crates/trigon-store/tests/store.rs`, the old run file in `old_run_files.rs`, the route in
`crates/trigon-api/tests/seam_attestation_layouts.rs`, the attestor end to end in
`crates/trigon/tests/seam_attest_per_run.rs`, and what `record_run` and `record_terminal` keep in
`record_keeps_what_the_run_threw_away` in `crates/trigon/src/main.rs`, beside
`an_attempt_that_reaches_a_comparison_lets_go_of_the_one_before`, which pins the stash's order.

**What review found in it.** Six defects, each now with a test that fails without its fix.

- The NuGet fetcher read an unreadable catalog as an empty one. A registration or leaf that
  answered 503, or 429 past the retries, came back as "no catalog entry for this version", so the
  download went ahead checked against nothing and the run recorded that NuGet had declared nothing.
  It now refuses the resolve (`RegistryError::CatalogUnreadable`, retried where the failure was
  transient), and "no catalog entry" is recorded only for an index that was read and does not list
  the version (`declared_digests.rs`, against a catalog on loopback whose documents fail).
- A repair whose comparison failed was recorded with the strategy and build of the divergent
  attempt before it, whose own comparison had worked: the stash was cleared on success only.
- The attestor wrote back the copy of the record it had read before signing, so a second attestor
  finishing in between dropped the first's paths. `Store::record_attestations` merges into the
  record as it is now, under a conditional write where the backend has one; the local filesystem
  has none, and a window of one read and one write remains there.
- Appending without ever removing kept a run's per-target paths beside its per-run ones, so a
  re-attested run went on being served whatever a later run had written over them, possibly a
  withheld divergence. Those paths are now set aside, as above.
- The attestor signed the `strategy.json` byproduct's digest as the record gave it. It now fetches
  the blob by hash, requires it to be the strategy's canonical JSON, and recomputes
  `strategy_digest` from it, before any statement is filed. A binary whose definition of a tool the
  strategy reaches has changed since the build refuses an honest record too; the attestor cannot
  tell that from an altered one.
- `trigon fetch --out` unlinked whatever `--out` named on any error, `/dev/null` included. It now
  stages a regular file beside the target and renames it into place on success, and writes in
  place, never removing, anything that is not a regular file.

Two checks had no test: a declared sha384, which the fetch hashes only on demand, and
`equivalence_for`'s sha512 comparison, the only check `rebuild --attest` and `verify --attest` make
before signing. Both do now.

### 3.96 What a published statement signs: v2 verdicts, void and withdrawal, and the configuration

`docs/19` §10 phase 2, second half, on 2026-09-27. Everything here is signed, so it lands before the
first publication; `publish` itself is phase 5.

**What changed.**

- **`equivalence/v2` and `divergence/v2`**, signed by `trigon attest`, carry every `docs/19` §4.2
  field: the outcome and the stabilizer set as v1 had them, the run's id and times, the Trigon that
  built it (`RunRecord.trigon_version`) and the one signing, the egress tier and `attestable`, the
  derivation method where one was recorded, the evidence digests — the set manifest's file, the
  comparison report, the rebuilt artifact, the strategy blob and the guard manifest — the canonical
  purl with `purlCanon`, and, when `[publish] origin` and `disputes` are both set, the falsifying
  command as argv and a typed dispute pointer. A v2 verdict is a v1 verdict with fields added, so
  `rederive` reads both with one path. Field by field in `docs/09` §2.5.
- **`void/v1`** is what `attest` signs, and all it signs, for a run the publication gate calls void:
  the gate's reason (`because`), the guard's trips and manifest, any stabilizer a person or a model
  wrote, the egress tier, and no outcome, difference data, comparison report or rebuilt-artifact
  digest. The attestor asks `trigon_api::publication::voided`, which is `decide`'s own answer, so
  it and `serve` cannot disagree about which runs are void. `GET /v1/runs/{id}/attestation` serves
  an anonymous reader of a void run its `void/v1` and nothing else, and refuses one whose only
  statements are verdicts.
- **`withdrawal/v1`** (`attest --withdraw <record> --reason <code>`) names the record by sha256 and
  a reason from the closed list, with the record's own subject and purl and no verdict; it is filed
  at `withdrawals/sha256/<record>/`. **`attest <run> --supersedes <record> --reason <code>`** signs
  `supersedes` and `reason` into the run's verdict or void, and refuses a record about another
  artifact or purl, since a client would never apply it. `<record>` is a path to a record file,
  whose types, `trigon.record/v1`, are in `trigon_attest::Record` with nothing but reading.
- **`rebuild/v1`** names its stabilizer set, additively, and signs `derivation.method` only where
  the run recorded one.
- **The canonical purl, version 1** (`trigon_core::purl`), with its vectors in
  `crates/trigon-core/testdata/purl-canon-v1.json`, which every writer and reader of the `purl1` and
  `pkg1` keys is held to.
- **The configuration of `docs/19` §2.4** (`trigon_attest::config`), in the crate the verifier
  already links, so phase 4's `verify-attestation --source` reads the same code: the user's file or
  `TRIGON_EVIDENCE_CONFIG`'s, the project's file under its rules, the environment, locations
  classified by transport, C2SP log keys parsed and their key hash recomputed, attestation keys as
  hex or PEM, and the error a command that needs a source and has none gives. A configuration error
  exits 5.
- **The building version names its build.** `build.rs` embeds `0.0.0+git.<rev>`, `.dirty` for a
  tree with changes the commit does not have, `+git.unknown` outside a checkout; `--version` prints
  it, runs record it, and statements sign it. `0.0.0` alone identified nothing.

**Found on the way.**

- **The gate withheld the very runs it voids.** `decide` read the outcome first and withheld a run
  with none as `no_outcome`, and a tripped guard ends the build, so every real void run — no
  comparison, no outcome — was withheld rather than shown as a void, and `attest` would have had no
  void to sign. A guard trip is now the first clause, outcome or not; open egress and a
  non-builtin stabilizer still void only a run that reached an outcome, since a build that failed
  at open egress is a failed build. `voided_agrees_with_decide_whatever_it_cannot_see` holds the
  attestor's question to the gate's answer over every combination.
- **An open-egress run was signed as a verdict.** The attestor refused a tripped guard and nothing
  else, so at `trigon rebuild`'s default `--egress open` every run was signed as `equivalence/v1`
  or `divergence/v1`, and only the API's gate kept the divergence from an anonymous reader. None of
  the 371 runs in the local store is affected — all are `mirror-only`, none tripped a guard, none
  applied a non-builtin pass — but the README's own signing walkthrough ran at `open`, and now says
  that such a run is signed as a void.
- **`rebuild/v1` signed `heuristic` for a run that recorded no derivation**, and its
  `stabilizer_set` was declared and never passed, so no statement named the set.
- **`build.rs` baked in the workspace root at compile time.** Cargo reuses a compiled build script
  across a moved tree, so a copy of the source without `.git` was stamped with the original
  checkout's commit. It reads `CARGO_MANIFEST_DIR` at run time now, and a build from such a copy
  says `+git.unknown`.

**Decisions made here that the owner may want to revisit.**

- PyPI names are normalised as PEP 503 says (runs of `-_.` become one `-`), stricter than the purl
  specification's `_`-only rule, because PyPI resolves all those spellings to one project. Case is
  folded only for the types the purl specification says are case-insensitive, so NuGet ids, Go
  module paths and Maven coordinates keep their case, and `pkg1` keeps a purl's qualifiers, as "the
  canonical purl without its version" reads.
- A project's file may name files — its checkpoint, a PEM key — only inside the working directory,
  once symlinks are followed, and its refusals print its strings with control characters escaped.
  `docs/19` §2.4 did not say this; without it, a pull request's `.trigon/evidence.toml` could have
  Trigon read any file on a CI runner as a "key".
- A location with a colon before its first slash is SSH where the part before the colon is
  `user@host`, a dotted name or a bracketed IPv6 address, and refused otherwise, with the advice to
  write `./`, `file://` or `ssh://alias/…`. A URL with a password, an `https://`, `http://` or
  `git://` URL with any user name (added in review, below), a git remote helper (`ext::` runs a
  command) and any scheme but the five listed are refused.
- `[[source]]` gained `trust_on_first_use`, the file form of `evidence add --trust-on-first-use`,
  which the project rule "cannot turn on trust on first use" presupposes.

**What this does not do.**

- Nothing verifies a record file's signatures or checks its unsigned parts against them; that is
  phase 4, and phase 6 resolves `<record>` by digest in a clone.
- No command needs a source yet, so the no-source refusal and its exit 5 have no caller outside
  their tests; phase 6 is the first.
- `trigon rebuild --attest` and `trigon verify --attest` still write v1 bundles, the first in the
  process that ran the build. `rebuild --attest` at `--egress open` therefore still signs a verdict
  for a run the gate calls void: P6 as reworded covers `trigon attest`, and whether the in-process
  path should sign a void, refuse, or go now that `attest` exists is a decision for the owner.
- `rebuild/v1` signs `derivation.transcript` as `null` even where the run kept the model exchange:
  24 of the 75 attested runs in the local store have a transcript digest nobody signed. Left as it
  was, since changing it is outside this phase.
- The build script re-runs on every build, because its `rerun-if-changed` paths for the mirror
  (`crates/trigon-mirror`) are relative to the workspace and cargo reads them relative to the
  package, so the file is "missing" every time. That also keeps the version's dirty flag current;
  corrected, the flag would be as of the last change to `HEAD`, a ref or the index.

Tests: `crates/trigon/tests/seam_attest_v2.rs` is the done-when through the binary — one assertion
per §4.2 field, the v1 fixtures signed at `255d2f5` verifying, a guard-tripped run with and without
a comparison and an open-egress run each yielding `void/v1` alone, the falsifying command and
dispute pointer absent and present, supersession, withdrawal, and a bad configuration exiting 5.
The same fields at the library in `crates/trigon-attest/tests/verdicts.rs`; the configuration in
`evidence_config.rs` and locations in `locations.rs` beside it; the purl vectors in
`crates/trigon-core/tests/purl_canon.rs`; the route in
`crates/trigon-api/tests/seam_void_statement.rs` and the gate's new order in `publication.rs`; the
withdrawal's filing in `crates/trigon-store/tests/store.rs`; and the build version in
`build_version_tests` in `crates/trigon/src/main.rs`.

**What review found in it.** Nine defects, each now with a test that fails without its fix; two
things no test checked; a doc comment moved off its function; and two questions that are the
owner's.

- **A record could hide the stabilizer that voids it.** `attest` chose between void and verdict
  from the record's `non_builtin_stabilizer` alone and checked it against nothing, with the
  comparison in hand. A record saying `false`, or nothing (written before the bit existed), beside
  a comparison in which a hand-written pass applied got a verdict, which the gate, reading the same
  bit, would publish. It now refuses a record whose bit disagrees with `AuthoredPass::of` its
  comparison, as it refuses one whose outcome does
  (`a_verdict_is_not_signed_for_a_record_that_hides_a_hand_written_stabilizer`).
- **The void whose facts come from the comparison had never been signed in a test**, only refused,
  so a regression in `AuthoredPass::of` — counting built-in passes, dropping the dedupe — passed
  everything (`a_run_a_hand_written_stabilizer_applied_to_is_signed_as_void_and_only_void`).
- **`voided` and the index disagreed** for every run without a cache key, which is every run the
  CLI records. `index::corroboration` returned `Corroboration::default()` there, dropping the
  record's provenance bit, so `serve` withheld as awaiting confirmation a run `attest` signed as
  void. The bit is a fact about the record and is carried whatever the attempts; the new test
  `the_index_voids_exactly_the_runs_the_attestor_calls_void` compares the two through the index,
  where `voided_agrees_with_decide_whatever_it_cannot_see` built the corroboration by hand.
- **A project's `.trigon/evidence.toml` was read through symlinks**, with no size or type check,
  and toml's error quotes the offending line: a link to a runner's secrets file, or to
  `/proc/self/environ`, printed it into the CI log, and one to `/dev/zero` read without end. The
  file is held to the rule the files it names are — inside the project once links are followed —
  and must be a regular file of at most 64 KiB; a parse error gives its line and column and toml's
  description, escaped, and not the line.
- **Some refusals still printed a project's control characters**: a name refused as a name, a log
  key, a PEM's path. Each is escaped where the message is written, and `project_file` escapes what
  `source_from` says once more.
- **Source names were unique only case-sensitively**, and a name is a directory: on macOS's default
  filesystem a project's `Trigon` would have shared the user's `trigon`'s checkpoint and key
  history once phase 6 writes them. Names, and the reserved `env`, are compared ignoring ASCII case.
- **`https://<token>@github.com/…` was accepted**, which is how GitHub takes a token, and would have
  been printed wherever the location is named. Any user name in an `https://`, `http://` or
  `git://` URL is refused, with how to tell a credential helper the user instead; an SSH user
  stays. Every refusal of a URL shows its user part as `***`, which the password refusal did not.
- **The canonical purl was not a fixed point** for an encoded dot segment. `.` and `..` were dropped
  before decoding, so `#%2E%2E/a` became `#../a`, which canonicalises to `#a`: two keys for one
  purl, and a record its own writer produced that phase 4's check would refuse. Segments are
  dropped by what they decode to, the vectors pin it, and a sweep over awkward spellings holds the
  fixed point beyond them.
- **Lowercasing was Unicode's**, so `%E2%84%AAeras` (KELVIN SIGN) canonicalised to `keras`, and
  full and simple case mapping disagree across languages (`İ`). It is ASCII only now, which changes
  no name any of these registries accepts; vectors pin both characters.
- **The build script's `git status` took the index lock** on every build, so a `git commit` at the
  moment an editor's background `cargo check` ran could fail on it. It runs with
  `GIT_OPTIONAL_LOCKS=0` (`asking_whether_the_tree_is_dirty_writes_nothing`). And nothing checked
  that the binary embeds a revision: every assertion passed for `+git.unknown`. Built from a
  checkout with git to ask, `this_binary_names_the_revision_it_was_built_from` requires forty hex
  digits.
- The withdrawal test was inserted between `unattested`'s doc comment and the function, and took
  the comment. It is back where it belongs.

For the owner:

- **`trigon rebuild --attest` still signs a v1 verdict for a run the gate calls void** — at
  `--egress open`, its default, or for a hand-written stabilizer — as this entry says above. What
  review added is that the code and the docs said otherwise: its comment said every void returned
  before it, and `docs/09` and the threat model said without qualification that a void is never
  signed as a verdict. The comment, the flag's help, `docs/09` §2 and §2.5, and threat model §1.1
  now say what it does. Whether it refuses, signs `void/v1`, or goes is threat model Q2.
- **`pkg1` keeps qualifiers**, so a purl with a qualifier that names one version — `file_name`,
  `checksum`, `download_url` — has a `pkg1` key per version, where `docs/19` §2.3 says the key is
  "every version". Dropping every qualifier would merge a package across `repository_url`s, the
  merge that keeping case exists to avoid; dropping only the version-bearing ones is a list that
  becomes protocol. The vectors are protocol too, so this is decided before the first record is
  published.

### 3.97 A run can be published: keys from what it ran, agreement on what it found, a confirmation

`docs/19` §10 phase 3 (backlog B31), and three things phase 2 left, on 2026-09-28. Nothing
publishes yet — that is phase 5 — but a run can now reach `Published` in the gate `serve` asks and
`publish` will ask, and before this none could.

**What changed.**

- **One function builds every cache key**, `trigon_store::cache_key`: the canonical purl, the
  artifact's name, the strategy digest and the stabilizer-set digest, as canonical JSON, hashed and
  prefixed `ck1:`. The run builds it where it writes its record, from what the record holds —
  `record_run` from the comparison's set, `record_terminal` from the set the artifact would be
  judged under — so a worker, `rebuild` and `sweep` key alike, and a run with no strategy has no
  key rather than part of one. The worker no longer copies its job's key onto the record.
- **A job's key names the request.** `trigon enqueue` and `POST /v1/runs` key a first attempt on
  `trigon_store::request_key`, the canonical purl, because nothing that enqueues knows the strategy
  a worker will infer. The engine queues a confirmation under the first attempt's record key, names
  that run in the payload as `confirm`, and delays it by the configured `confirmation_interval`
  (`trigon worker` reads it), where it used five minutes against an interval of an hour.
- **Attempts agree on what they found.** `RunRecord::agreement` is `Comparison::agreement`, a digest
  over the outcome, the set, the published artifact's raw digest and both sides' stabilized digests.
  The index counts two attempts at a key as agreeing only where both carry one and it is one digest,
  as disagreeing where the outcomes differ or the digests do, and neither where a record carries
  none. A void attempt is left out of both counts. `corroboration_is_counted_as_its_doc_says` holds
  `index::build` to `Corroboration`'s doc.
- **Each attempt records where, how and when it ran**: `RunRecord::host`, an HMAC-SHA256 of
  `/etc/machine-id` (or D-Bus's `/var/lib/dbus/machine-id`) under a key of Trigon's own, or of the
  hostname where there is neither, prefixed with which; `RunRecord::cache`, the caches the attempt
  let supply it (`build-layers`, `fetch`, `sources`, `derived-image`; empty is cold) and whether its
  base image was re-pulled; and `started`, which is now when the attempt began on every path.
- **`trigon rebuild --confirm <run>`** repeats a stored run: its target and artifact, the strategy
  from its blob, its set, the image and tier it ran on, with no model, no ladder and no repair. It
  builds with `--no-cache`, checks the source out into a directory of its own emptied first, uses
  no fetch cache, and removes the base image from the store and pulls it again by digest
  (`trigon_sandbox::repull`), recording what of that happened. It refuses, before any registry is
  asked, a run with no verdict, a void run, one with no strategy blob, one whose strategy digest
  these tools do not reproduce, one judged under a set this binary does not carry as it was, one
  not keyed as runs are now keyed, and one that does not record its source; after the fetch, it
  refuses a registry that now serves other bytes. A worker's second attempt is the same code.
- **`decide` holds a pair to the operator's settings** (`Switches::confirmation`, from `[publish]`
  wherever the gate runs): some pair of agreeing attempts must record a machine and a start, the
  later must begin at least `confirmation_interval` after the earlier, and they must be on two
  machines, or on one where `same_host_confirmation` is set and the later was cold and re-pulled.
  Four new reasons say which fell short — `confirmation_unrecorded`, `attempts_too_close`,
  `same_host`, `confirmation_not_cold` — the nearest pair's, and an anonymous reader still sees one
  withheld total. `trigon serve` reads the settings, prints them, and starts with the defaults when
  there is no `evidence.toml`; `attest` asks `voided`, which no setting can change, and a test now
  says so.
- **`rebuild --attest` signs through `trigon attest`'s code** (`attestor::sign_run`): it needs
  `--store`, signs the recorded run whatever it ended as, files every statement under it, and writes
  the verdict or the void to its path. At `--egress open`, its default, it signed every run as a
  verdict. P6 holds without a qualification now: no path signs a verdict for a run the gate voids.
  `verify --attest` still signs `equivalence/v1` about two local files, and its help, `docs/09` and
  the threat model say that is not publishable.
- **`rebuild/v1` signs `derivation.transcript`** as `{"sha256": …}` where the run kept a model
  exchange, and `null` only where it kept none. 24 of the 75 attested runs in the local store kept
  one that no statement named.
- **`pkg1` is the package.** The versionless form is `pkg:<type>/<namespace>/<name>` with the
  `repository_url` qualifier where there is one, and no version, subpath or other qualifier, so a
  `file_name` or a `checksum` no longer gives each version its own key. The vectors changed with it;
  this is still `purlCanon` 1, since nothing has been published under it.

**Found on the way.**

- **The compared path wrote the moment it recorded as `started`**, which is when the run ended. A
  terminal run wrote when it began. The gate subtracts two of these, so the field is now the start
  on both paths, and the gate reads it only beside a recorded host, which no older run has.
- **Every worker confirmation would have been withheld.** The engine delayed it five minutes and the
  default interval is an hour; the delay is the configured interval now.
- **A void attempt could confirm a clean one**: an open-egress run at the key of a `mirror-only`
  run was counted as agreeing with it. A void is evidence of nothing, so it is counted neither way.
- **The agreement digest names the verdict**: it hashes the outcome and two digests a reader holding
  the published artifact can compute, so four guesses find the outcome. `record_shown` drops it for
  an anonymous reader of a void, beside the outcome.
- **The attestor now refuses a record whose agreement digest is not its comparison's**, as it
  refuses one whose outcome is not: the gate counts attempts by that digest.
- **No stored run can be confirmed.** All 371 runs in the local store carry no cache key and no
  strategy blob, so `--confirm` refuses each; a publishable pair starts with a new rebuild.

**Decisions made here that the owner may want to revisit.**

- **"Comparison digest" is read as a digest of what the comparison found, not of the report.** The
  report names the rebuilt artifact's raw bytes, and six honest builds of `Newtonsoft.Json@11.0.1`
  gave six raw artifacts and one stabilized digest (B31), so a report digest would never let a
  `normalized` run be confirmed.
- **A deliberate pair is `--confirm`, not a `--cache-key` flag** as B31's done-when put it: a key a
  person types is the invented key the old comment warned about, and `--confirm` gets the same pair
  with the key computed.
- **"Target" in the key includes the artifact's name**, which is what `trigon_core::Target` means,
  so an sdist and a wheel of one version are two questions.
- **Re-pulled means removed, seen gone and pulled by digest**, never forced. An image that exists
  only on this machine — anything under `localhost/`, a derived image, a bare id — cannot be pulled
  again, so a run on one can be confirmed only from another machine.
- **"Warm" lists the caches an attempt let answer**, not the ones that did; a consulted cache that
  missed leaves the same bytes behind as one that was not consulted, and only the first is a fact
  the run can state.
- **The host id is in the run record, and no anonymous reader is shown it.** From a machine id it
  reveals nothing; from a hostname it can be checked against a guess, since the key is in the
  source. A key of each installation's own was considered and not taken: two installations on one
  machine — two users, or a container beside its host — would record two ids for it, which is the
  one mistake the gate must not be able to make.
- **Only machine ids tell machines apart.** Two different ids where either came from a hostname are
  held to the same-host rule, so a fleet whose workers all lack a machine id — containers, most
  often — publishes only with `same_host_confirmation` on and cold confirmations.
- **Any pair that confirms is enough**, and where none does the reason is the nearest pair's.

**What this does not do.**

- Nothing runs two real builds: `repull` is tested only where it refuses, and B15's test of two
  clean re-runs needs podman and a registry.
- Re-enqueueing a target after a change of set or strategy is still one job: a request is keyed on
  the target, and a first attempt that exists answers it.
- `publish` (phase 5) is where a confirmed run is published, and it is not built.

**What review found in it.** Eight defects, each now with a test that fails without its fix;
three things no test checked; and one question that is the owner's.

- **A confirmation could run on the machine that made the first attempt**, and with
  `same_host_confirmation` off, the default, the gate then withheld the pair as `same_host` for
  good: `Queue::lease` chose by kind, visibility and tier, nothing in the job said which machine to
  avoid, and nothing asks a third time. A fleet lost the one confirmation of every target whose
  first machine happened to be idle first. The engine now queues a confirmation to avoid the host
  the first attempt recorded (the `job_avoid` table, written in the job's own transaction; a table
  rather than a column, so `migrate` gives an older queue it), `Queue::lease_on` leases no job to a
  worker on a host it avoids, and `trigon worker` names its host and reads D8. With D8 on, any
  machine may take it. A fleet of one machine confirms nothing with D8 off, which `trigon worker`
  says when it starts and the job's events say while it waits
  (`a_confirmation_is_made_on_another_machine`,
  `one_machine_confirms_itself_where_the_operator_accepts_it`,
  `a_job_is_never_leased_on_the_machine_it_avoids`).
- **A confirmation of a run on a derived image recorded that it derived nothing and was cold.** The
  build is handed the recorded image by id, and treats an id as an image the operator named, so
  `derived_image` was `None` and `derived-image` was not listed. The gate withholds an accusation on
  a derived image by reading the record under decision, so a confirmation made on another machine
  would have published the divergence the first attempt is withheld for. `--confirm` carries the
  image over with `built_here: false`, the build's report is corrected from it, and it is listed as
  reused (`a_confirmation_of_a_run_on_a_derived_image_says_it_ran_on_one`).
- **The engine queued a confirmation for every void verdict**, which `--confirm` refuses, and the
  worker called every refusal retryable, so each was leased, refused and backed off until dead — one
  dead job per void verdict. `Work::unconfirmable` is asked first, and the worker answers from
  `publication::voided`; and `--confirm`'s refusals are a type of their own (`Unrepeatable`) that
  the worker marks not retryable, since every worker running this Trigon gives them again
  (`a_void_verdict_is_not_asked_again`, `a_run_a_confirmation_cannot_repeat_goes_dead_at_once`).
- **Two different host ids were two machines, whatever they were derived from.** A container has a
  hostname of its own and no machine id, so two workers in containers on one machine, or a run on
  the machine beside one in a container on it, counted as a confirmation from elsewhere with D8 off.
  Only two ids both derived from machine ids are two machines now; any other pair of different ids
  is held to the same-host rule (`ids_derived_from_hostnames_do_not_show_two_machines`). The host id
  also reads D-Bus's machine id where systemd's is absent, so fewer machines fall back to a
  hostname.
- **The host id was served to anonymous readers**, on every published and void run. Under a key in
  the source, one derived from a hostname can be checked against a guess, which is the leak it
  exists to prevent, and the gate never needed a reader to have it. `record_shown` removes it for
  every anonymous reader (`no_anonymous_reader_is_told_which_machine_a_run_ran_on`).
- **The agreement digest did not bind the published artifact's bytes**, so two attempts against two
  artifacts under one name that the set makes one — a tarball republished with new timestamps —
  confirmed each other, and `docs/01` said they could not. It hashes the upstream's raw digest now;
  two honest attempts fetch the same bytes
  (`the_agreement_digest_ignores_raw_bytes_and_keeps_what_was_found`).
- **`--confirm` discarded the error from emptying its source cache**, and `create_dir_all` succeeds
  on a directory that is still there, so a checkout that would not go was copied while the record
  said nothing supplied the source. It refuses now
  (`a_source_cache_that_will_not_empty_is_refused`).
- **Requests keyed canonically missed the jobs a queue made before**, which were keyed on the target
  as typed, so `pkg:npm/@babel/core@7.24.0` was queued, built and charged a second time.
  `request_rebuild`, `job_for` and `trigon enqueue` look under both
  (`a_request_finds_the_job_a_queue_keyed_on_the_target_as_typed`,
  `enqueue_finds_a_job_keyed_on_the_target_as_typed`).
- **Nothing tested that a void attempt neither confirms nor contradicts**: removing the filter left
  every test passing, because the test that named it grouped the attempts with its own copy of the
  filter. `build` and the test now share `attempts_by_key`, and
  `a_void_attempt_neither_confirms_nor_contradicts_another_at_its_key` goes through `build`.
- **Nothing tested what an attempt says it could reuse**, the fact the same-host rule rests on: the
  one test read back its own fixture. The mapping is `Reuse`, one value that gives both the record
  and the build's `--no-cache`, and each input has an assertion
  (`what_an_attempt_could_reuse_is_stated_from_how_it_was_set_up`).
- **The test cited for `rebuild --attest` never went through `rebuild`'s code**; it called `trigon
  attest`'s. `run_inner` now signs through `attest_what_was_recorded`, which the test calls.

For the owner:

- **Re-asking for a target is deduplicated by the target alone**, whatever set or strategy it would
  now be judged under, as `docs/01` now says: a first attempt on the queue, or done, answers the
  request, where `docs/01` §1.1 has the scheduler admit a new attempt when the key has no terminal
  verdict. Nothing that enqueues knows the strategy; a request key could carry the digest of every
  set and tool this binary has, so that a change of either starts new first attempts — for every
  target at once, on each such release, and decided by whichever binary enqueues. That trade is a
  scheduling policy, and it is not made here.

### 3.98 The evidence log as pure code: notes, checkpoints, proofs, tiles, leaves, rotation

`docs/19` §10 phase 4, first half, on 2026-09-28: the log's formats and its verification, in
`trigon_attest::log`, with no network and no filesystem beyond the directory it is given. Nothing
writes an evidence repository with it yet (phase 5), and nothing reads one: records verified
against the log, lookup, index paths and `verify-attestation --record` are the second half.
`docs/09` §2.10 has the formats as built.

**What changed.**

- **C2SP signed notes and the log key.** Notes are read as Go's `golang.org/x/mod/sumdb/note`
  reads them, a line by a key not pinned read past; the log key's private half is Go's
  `PRIVATE+KEY+<name>+<hash>+<keydata>`, its hash recomputed, and never quoted in a refusal.
  Signing Go's example text with Go's example key gives Go's signature line byte for byte.
- **C2SP checkpoints**: three lines and no extension lines when written, extension lines read past
  when read, the origin required to be the key's name, and size 0 signing SHA-256 of nothing.
- **RFC 6962 trees and RFC 9162 proofs**, generated and verified, over a tree held in memory as the
  rows tiles hold, or over tiles read from files, with one generator for both.
- **C2SP tiles**: paths, which tiles and bundles a tree of a size has, uint16 framing, what an
  append writes and which `.p` directories it makes obsolete, and a reader that opens the tiles of
  its checkpoint's size and nothing beside them.
- **Every leaf kind of §2.3**, typed, canonical JSON, decoded strictly: unknown kind, unknown
  field, broken rule or non-canonical bytes refused, the writer held to the same rules.
- **`verify_log`**, **`verify_source`** and **`KeyHistory`**: a log verified whole from its files,
  consistency with the checkpoint last accepted by the recomputed tree and, for a reader with only
  tiles, by proof; a repository's chain of logs followed through log-end and log-continuation; and
  attestation-key changes followed from the pinned key. A clone is written by whoever can push, so
  it is read defensively: no file through a link out of the repository, a log directory that is
  such a link included, nothing but regular files, and nothing longer than its format allows.
- **Golden files** in `crates/trigon-attest/testdata/log/`: Go's note vectors, the RFC 6962 vectors,
  one leaf of each kind, and a repository of two logs — the first grown by five publications until
  it ends, its successor by two — with the proofs between the first's checkpoints. 110 tests in
  `tests/evidence_log/`, property tests among them.

**Checked against implementations that are not this one.** The repository was opened with Go's
`note` and `tlog` (v0.40.0, from the module cache, offline): both checkpoints open; the roots
`tlog` computes from the entry bundles are the signed ones; every tile, and every older partial
still on disk, is `tlog`'s tile data at height 8; the consistency proofs pass `tlog.CheckTree` and
the inclusion proofs `tlog.CheckRecord`; the continuation opens under both keys; and C2SP's tile
paths are Go's with the height left out. The RFC 6962 vectors were computed in Python from the RFC,
and their roots are the certificate-transparency constants. Python also verified the key-change and
release signatures over the messages as `docs/09` writes them, and found every golden leaf equal
to its own canonical JSON.

**Found on the way.**

- **The signed-note vector this phase was specified with is not Go's.** Its line, `— PeterNeumann
  yvTSo2EF…BwA=`, begins with the key hash `caf4d2a3`, where PeterNeumann's key hashes to
  `c74f20a3`, and its 64 signature bytes do not verify under that key over the text, with or
  without its final newline. Go's own tests and example have `x08go/ZJku…JnAM=`, which starts with
  `c74f20a3`, verifies, and is exactly what signing the text with Go's example private key gives,
  since Ed25519 is deterministic. The tests pin Go's line, and pin the other as refused: it names
  another key, so a note carrying only it is not signed by PeterNeumann, and given PeterNeumann's
  hash its bytes fail.
- **An inclusion proof binds the tree's size only by its shape.** Leaf 3's audit path in a tree of 7
  leaves also verifies as leaf 3 of a tree of 5, 6 or 8 against the same root, because the paths
  have one shape. That is RFC 9162, not a defect, and it means a client must check every proof
  against the size of the signed checkpoint and never a size that came with the proof; the tests
  say so where they found it.
- **Go's reader is laxer than it needs to be in one place.** It verifies the first line by a known
  key and skips any later line by the same key, so a note with a good line and a bad one by the
  pinned key opens. Ed25519 is deterministic, so an honest signer writes one line; here every line
  naming the pinned key must verify.

**Decisions made here that the owner may want to revisit.** Everything below is signed into the
tree once phase 5 publishes, so it is cheap to change now and expensive later.

- **What each leaf holds, field by field** (`docs/09` §2.10). The record leaf is §2.3's example,
  with `subject` requiring sha256, digests written `sha256:<hex>`, and only the four predicates
  `publish` logs; a void's `stabilizerSet` is optional, since a build the guard stopped compared
  under no set, as `void/v1` has it — `docs/19` §2.3 and §4.1 said a void's leaf always has one,
  and now give it one only where its run compared.
- **The key-change message**: `trigon.dev/key-change/v1`, the origin, the time, the old and new
  keys in hex, a line each. Binding the origin stops a change being replayed into another source
  that shares the key; binding the time stops it being moved within the log.
- **The release leaf** — `name`, `version`, `artifacts` by file name with sha256 and optional
  sha512, `keyId`, `signature` over `trigon.dev/release/v1`, the origin, the time and the canonical
  JSON of the rest — fixed now so phase 9 has a format to write, and not written by anything yet.
- **A log-end's successor** is `origin`, `logKey`, `urls` and `dir`; an empty `urls` means this
  repository, so every mirror of it serves the successor too, and `dir` is `log/<n>`, or `log` in
  another repository. A successor elsewhere is returned for the caller to clone and `follow`, since
  this crate opens no socket.
- **Times are at most 2^53 − 1**, the largest integer a JavaScript reader holds exactly.
- **A key change from a key that is not current is read past and reported**, not refused: a client
  pinned after a rotation sees the change that led to its pin that way. One from the current key
  that does not verify under both keys refuses the source, since that is what a stolen log key
  without the attestation key would write. A new key covers the leaves after its change, not the
  change itself or anything before it.
- **A `log/<n>` that no log-end names is reported as refused**, and the source still answers from
  the logs that are named, rather than failing whole: whoever holds the push credential could
  otherwise stop a source by planting a directory.
- **Where a chain starts is the newest checkpoint the pinned key opens**, and the first directory
  holding it whose files verify; every other directory claiming that log is reported in
  `VerifiedSource::refused` and set aside. That includes a checkpoint signed by the log's key that
  the newest tree does not extend — two trees under one key, which only the log key can make — so
  such a fork found among a repository's directories is reported, not a refusal of the source. A
  client's own accepted checkpoint is what refuses a fork (§8); making this one refuse too is a
  choice for the owner.
- **A client pinned to a successor's key starts at that log**, and does not read the logs before
  it.
- **`verify_log` checks every tile against the leaves**, which §6 does not list: a client with the
  leaves does not need the tiles, but a `--remote` reader proves inclusion from them, and a full
  monitor should catch tiles that would mislead it.
- **A reader of tiles opens only the tiles of its checkpoint's size.** tlog-tiles lets a client
  read a full tile in place of a partial; this one does not, so nothing a later publication or a
  planted file put beside the partial is read. Phase 6's `--remote` may want the full tile as a
  fallback when a partial disappears between fetching the checkpoint and the tile.
- **A private key file is read whatever its permissions.** Refusing a world-readable key is a
  policy for `trigon log sign` to set in phase 5.

**What this does not do.**

- Verify a record against its leaf, look a key up, apply supersessions, derive index paths, or give
  the network-free verifier `--record`: the second half of phase 4, built on this.
- Add the threat model's properties for inclusion and consistency verification (`docs/19` phase 8):
  no command uses this code yet, so there is no shipped property to state, and they belong with the
  record verification that makes them one. The deferral is recorded in `docs/19`'s status table
  and in the threat model's §1.3, which routes a finding against the library there until then.
- Keep a verified log small at scale: every leaf is held decoded, about a kilobyte each, so a
  million leaves is on the order of a gigabyte in memory. Leaves are not also kept as bytes, since
  a canonical leaf writes back to the bytes it was read from; streaming the rest is for when D2's
  numbers say it is needed.

**What review found in it.** Fourteen findings: eleven defects, each now with a test that fails
without its fix; two places where the documents disagreed; and a gap in the tests.

- **A bundle altered after signing was blamed on the log key.** `verify_log` decoded each leaf and
  applied the log's rules before it compared the root, so a bundle rewritten by whoever can push
  read as the signed log breaking its own rules (`Rule`), or as a leaf from a newer Trigon ("update
  it"). The root is compared first now, and a leaf refused only once the checkpoint signs it
  (`a_bundle_altered_after_signing_is_a_mismatch_whatever_its_leaves_say`).
- **A damaged tile was reported as an equivocation.** `verify_extension_from_tiles` called every
  failed consistency proof `Inconsistent`, whose text accuses the operator and offers two
  consistent notes as evidence. A failed proof is an equivocation now only when its hashes lead to
  the new signed root, which authenticates them; tiles that do not are a `Mismatch`
  (`a_checkpoint_extends_the_accepted_one_by_its_tiles_alone`).
- **A planted directory could stop a client pinned to a successor**, or move it onto an older
  state: the chain started at the first directory whose checkpoint merely said the pinned origin.
  It starts where the pinned key opens the newest checkpoint now, as the decision above says
  (`a_planted_directory_does_not_move_or_stop_a_client_pinned_to_a_successor`).
- **The writer accepted leaves every reader refuses.** `VerifiedLog::plan_append` did not check a
  key change's signatures over its own log's origin, a log-end's successor origin, or a
  continuation's signature by its own key, and the free `plan_append` did not check its tail
  against the tree; each would have broken the log for good
  (`a_verified_log_does_not_plan_a_leaf_every_reader_would_refuse`,
  `an_append_whose_tail_is_not_the_trees_leaves_is_refused`).
- **A record leaf under an earlier `purlCanon` would have stopped decoding** the day the rule
  moved to 2, refusing every existing log. It is checked under its own rule, by the new
  `trigon_core::purl::canonicalize_under`, which keeps each rule this build has had
  (`every_rule_this_build_has_had_is_still_the_rule_it_was`,
  `a_record_leaf_under_any_rule_this_build_has_reads`).
- **Refusals carried raw control characters** from unsigned input: serde's text quoting an
  unknown field or variant, a signature line's name, and the notes an equivocation shows, which it
  now keeps as read and shows escaped (`a_refusal_never_carries_a_leafs_control_characters`,
  `the_notes_a_refusal_shows_are_escaped_and_kept_as_read`,
  `a_refusal_of_a_leaf_carries_none_of_its_control_characters`).
- **A signer could be made under a name no verifier key can carry**, with DEL or a C1 control in
  it, and `vkey()` then panicked; signer and verifier key share one rule now, and the signer holds
  its verifier key (`a_signer_is_made_only_under_a_name_its_verifier_key_can_carry`, and a property
  test that every signer's key reads back).
- **A bare seed's first byte was shown** in the refusal of a key file missing its type byte. The
  length is checked first and the type byte never shown
  (`a_bare_seed_is_refused_without_showing_a_byte_of_it`).
- **`prove_inclusion_from_tiles` took an unsigned checkpoint**, so nothing kept a caller from
  proving against a root nobody signed. It takes a `SignedCheckpoint`.
- **`trigon`'s fault report called a log that fails verification "a bug in trigon"**. It names
  the evidence source now, as having failed verification, and one whose log could not be read as
  the source's too (`a_log_that_fails_verification_is_the_sources_fault_and_not_trigons`).
- **The documents**: `docs/19` said a void's leaf always carries a set digest, which `void/v1` does
  not always have; and the threat model's inclusion and consistency properties, which phase 8
  gives phase 4, were deferred in this entry only. `docs/19` §2.3, §4.1 and its status table, and
  the threat model's §1.3, now say both.
- **No test tampered with a tile above level 0 or read a proof from level 2.** `verify_log` is now
  held to a full level-0 tile and a level-1 partial, and a tree of 65,836 leaves to the proofs its
  level-2 tile gives (`a_tile_that_does_not_hold_the_leaves_hashes_is_refused`,
  `hashes_read_from_tiles_are_the_trees_past_level_two`).

### 3.99 Records checked against the log, lookup over its leaves, and the verifier's record form

`docs/19` §10 phase 4, second half, on 2026-09-28: what reads an evidence repository, as pure code
in `trigon_attest::evidence`, and the network-free verifier's `verify-attestation --record <file>
--evidence <dir>`, the first command to reach `trigon_attest::log`. Nothing writes a repository yet
(phase 5), and nothing clones, syncs or answers a lockfile from one (phase 6). `docs/09` §2.8,
§2.11 and §7 have it as built.

**What changed.**

- **A record checked against its leaf** (`check_record`): its sha256 is a verified leaf's `record`,
  or it is *unlogged*, and one leaf's only, or it is *logged twice*; its leaf's key id names the
  attestation key the source had at that leaf, by `KeyHistory`, and every envelope carries a
  signature by that key that verifies; the signed statement agrees with the leaf on subject
  digests, purl and its rule, predicate type, outcome, set digest, `supersedes` and `reason`; a void
  or a withdrawal is one statement; a verdict's `rebuild` is of its run (`invocationId` is the
  verdict's `run.id`), under its set, and about the rebuilt artifact it names, and its
  `buildobservation` is about its subject, under its egress tier and the guard manifest it names as
  evidence, with no guard tripped; the unsigned `subject` and `evidence` map agree with the
  statement; the signed subject is the key it was found under, and a purl key is the signed purl
  canonicalised under the rule it was signed under; and every evidence file present is the bytes
  the statement names, one absent reported unchecked, never passed. Each failure is a typed
  `RecordFailure` with its reason.
- **Lookup over the verified leaves** (`Key`, `Lookup`, `Answer`): a sha256, sha512 or sha1 digest,
  an SRI string such as npm's `integrity`, a purl with or without its version, or a file hashed as
  it is read; never `index/`. A leaf whose file is missing is `deleted`. Supersession exactly as §3
  says, the superseded record returned marked with the reason and both leaves; two current records
  for one subject both returned, the more severe answering. The answers are the §4.2 states, each
  with §6's exit code: never checked, withdrawn, deleted, failed verification with its reason, each
  outcome, and void.
- **Where everything is** (`evidence::paths`): records, evidence, and the index under `sha256`,
  `sha512`, `sha1`, `purl1` and `pkg1`, each with the four-hex fan-out and the digest whole, held to
  the shared purl vectors; the index file, and the whole index derived from a verified log, for
  phase 5's writer and `--reconcile`. `Record::assemble`, `Record::encode` and `record_leaf` are
  the writer's other halves; `record_leaf` holds the leaf it builds to the comparison
  `check_record` makes before it returns it.
- **`--rerun-comparison` checks what a verdict says the comparison found**: its `differences`,
  `applied` and `members`, re-derived by the one function that builds a verdict and compared
  whole, where before only the outcome and the stabilized digests were. A subject whose sha256 is
  the artifact's and whose sha512 or sha1 is not is a new `AttestError::SubjectRefuted`: a signed
  claim refuted, not the wrong file. With a record, the published comparison report is read again,
  held to its digest again, and held to the same re-derivation field by field, then member by
  member — status, kind, digests and sizes — and by its field edits where it carries any; its
  progression, its notes and the members' raw paths are reported unchecked, never passed. Through
  an archived set, which gives digests and no report, all of that is reported unchecked.
- **`verify-attestation --record <file> --evidence <dir>`**, in both builds: the source's keys and
  checkpoint from `--source <name>` — `evidence.toml`, then the state directory's
  `<name>/checkpoint`, then the source's initial checkpoint — or from `--log-vkey`,
  `--attestation-key` and `--checkpoint`; the log verified whole and held to that checkpoint; the
  record, shown with every §4.2 field — set, run, both versions, egress tier and `attestable`,
  derivation, and for a verdict the falsifying command and dispute pointer, absent shown as
  absent; what the source says of its artifact now, or *unknown*, exit 4, where the log continues
  in a repository the directory does not hold; and `--rerun-comparison`. A bundle is checked as it
  was. `xtask policy` passes: the verifier still links no network client.
- **Carried over from phase 4a.** Two trees under one log key found side by side in one repository
  — the same size with two roots, or an older checkpoint the newest does not extend — refuse the
  source as `LogError::Equivocation`, with both signed notes, and the record form exits 4; 4a had
  only listed them among the directories set aside. And a signature that does not verify, a claim
  that does not re-derive and damaged evidence are labelled the evidence's fault
  (`AttestError::fails_verification`, a new `AttestError::Evidence`), where `trigon` said "a bug in
  trigon; please report it" for a refuted claim and, for a bundle whose signature failed, said
  nothing about whose fault it was, since that error was untyped. `Fault::Bug` stays their class,
  so they are never retried, and stays trigon's own for its own errors.
- **Golden files** in `crates/trigon-attest/testdata/evidence/`: a repository of two logs — every
  leaf kind — holding verdicts `exact`, `normalized` and `divergent`, a void, a superseding verdict,
  a withdrawal, a deleted record, an unlogged one, and three built to fail: signed by a key the
  source never had, by one retired before its leaf, and one whose leaf disagrees with its statement;
  with their evidence, the index the log implies, every checkpoint the first log had, and the
  artifacts three verdicts re-derive from. Its build observations name the guard manifest their
  verdicts name as evidence, as the attestor signs both from one run. 40 tests in
  `tests/evidence_repo/` and 14 in `crates/trigon/tests/verify_record.rs`, which builds the
  repositories the golden one does not hold with `tests/evidence_repo/build.rs` itself.

**Decisions made here that the owner may want to revisit.**

- **The record form's exit code is what the source says of the record's artifact now**, not the
  record's own outcome: a verified verdict that a withdrawal superseded exits 2, and a record of an
  artifact another record of which is deleted exits 4. A record handed in is checked first, and its
  own failure exits 4 whatever else is there.
- **A claim `--rerun-comparison` refutes exits 4**, as failed verification: a signed statement that
  the bytes contradict is the loudest thing a record can be. The wrong artifact, a set this build
  does not carry, or a void handed to `--rerun-comparison` exit 5: a check not made is not a check
  failed.
- **Bad arguments to the record form exit 5, as §6 says**, those `clap` refuses included: `main`
  parses with `try_parse`, and when `verify-attestation` was given `--record` a `clap` error exits
  5, since `clap`'s 2 is the code §6 gives "never checked". Everywhere else, the bundle form
  included, `clap`'s errors exit 2 as they did. `--rerun-comparison`'s arguments — both files,
  readable, and none of its files without it — are checked before the record, so a bad one exits
  5 whatever the record is; a checkpoint, given or in the state directory, that is not one exits 5
  and is never blamed on the source.
- **A record file is its canonical JSON**, so a record's name is a function of what it holds.
- **An index entry names its log** — `"log": "log/1"` — where its leaf is in a successor, since a
  leaf index alone names a leaf of one log; and an index file's `key` is `<kind>:<value>`, the
  canonical purl in the clear, so a reader can check the file is at the path its key derives.
- **A verdict record's other statements are held to its run**, each at most once: its `rebuild`
  by its invocation id, its set and the rebuilt artifact it names, and its `buildobservation` by
  its subject, egress tier and guard manifest, and refused if it says the guard tripped, since a
  run whose guard tripped is void. `buildobservation` names no run, so an observation of another
  attempt at the same artifact, under the same tier and guard, is not told apart; the `rebuild` is
  what ties a verdict to its run. A statement of a kind this build does not read has its signature
  checked and is read past, so a later writer can add one. A void or a withdrawal is refused with
  any second statement, as §4.1 says.
- **A record the log holds at two leaves fails verification at both**, and its subject answers
  failed, exit 4. Judged leaf by leaf, a record logged again after the withdrawal of it had a leaf
  later than the withdrawal's and read as current again: anyone with the log key alone could undo
  a withdrawal in the one public history, with no fork, which §8 says only a fork or a split view
  does. Resolving supersession by the record's first leaf would also have held; refusing is louder,
  and costs an honest publisher nothing, since a record is logged once.
- **A source whose log continues in a repository the directory does not hold answers *unknown***,
  exit 4, and never shows the record as current: a withdrawal of it may be logged there. A
  checkpoint given for a log the directory does not hold is said to be unchecked, and not refused,
  since it may be for a log past the successor the directory names.
- **A published comparison report is held to what the same bytes under the same set give back**:
  every member and the field edits, besides what a verdict signs, and not its progression, notes or
  the members' raw paths, which a later build may word differently or a report written before them
  lacks. Those are listed as unchecked, and so are field edits a report does not carry.
- **The state directory holds the last accepted checkpoint as `<name>/checkpoint`**, the signed
  note as accepted. Phase 6 writes it; the verifier only reads it, and says when it is not there,
  including when the source's initial checkpoint stands in for it.
- **A source that trusts on first use is refused by the record form**, which reads no repository's
  `keys/`: its keys are settled by a first sync, which phase 6 records.
- **Record files are read up to 4 MiB, evidence files up to 100 MiB** (GitHub's own ceiling), each
  inside the directory once links are followed and as a regular file, as the log's are. An evidence
  file that cannot be read is unchecked, not failed; one that is there and is other bytes fails.

**What this does not do.**

- Judge freshness. The record form answers from the log the directory holds, against the checkpoint
  it is given or none, and says which; `unknown`, and the stale and frozen clocks, are phase 6's,
  and the threat model disclaims them for this form as D25.
- Follow a successor log in another repository: one the chain continues into is reported, what
  the source says now is *unknown*, exit 4, and a record logged there is not seen.
- Decide whether a verified verdict that signs no falsifying command or dispute pointer should
  fail verification. §4.2 says every record carries them, and §8 that a client never renders an
  outcome it cannot show with them; the record form shows each as absent, loudly, and still renders
  the outcome. Refusing them is a rule for `publish` (phase 5) and a decision for the owner.
- Read or write the key history the state directory will keep (§8): the history is recomputed from
  the log every time, which is the same answer while the chain is in one repository.
- Anything over the network: `--remote`, `evidence sync`, `lookup` and `check` from sources are
  phase 6, and publishing is phase 5.

**Found on the way.**

- **The threat model's census disagreed with its sidecar**: the prose said 201 documented claims
  and `threat-model.yaml`, generated from it, counted 202. Regenerated with this phase's
  properties, both say 209.

**Found in review, and fixed.**

- **The record form rendered an outcome without the fields §4.2 has every client render**: no set,
  run, versions, egress tier, derivation, falsifying command or dispute pointer, in text or JSON.
- **A record logged a second time after its withdrawal answered again**, exit 0: supersession was
  applied leaf by leaf (above).
- **A log continuing in another repository still answered "current yes"**, exit 0, even when the
  checkpoint given was the successor's; and a checkpoint of any origin was said to hold the log.
- **Some bad arguments still exited 2**: `--upstream` or `--rebuild` without
  `--rerun-comparison`, and an unknown flag, all through `clap`; and this entry said otherwise.
- **A `--checkpoint`, or a state file, that is not a checkpoint exited 4**, blamed on the source.
- **`--rerun-comparison`'s arguments were checked only for a record that verified**, so the same
  missing `--upstream` exited 5 or 4 by the record.
- **A subject whose sha512 or sha1 lies, beside a sha256 that holds, exited 5** as the wrong file,
  where it is a signed claim refuted.
- **The comparison report was held only to what the verdict signs**, and printed as agreeing: its
  members and field edits were never compared. And it was read a second time to be judged without
  its digest checked again.
- **`record_leaf` gave leaves `check_record` refuses for ever**: a `supersedes` without `sha256:`,
  or hex in capitals, parsed leniently and logged as the log writes it.
- **"About its run" was said of `rebuild` and `buildobservation` and checked by artifact alone**,
  and three of `accompanies`' branches had no test.
- **A missing state file went unsaid when an initial checkpoint stood in**, which §6.1 forbids.
- **`--output json` wrote nothing** when the check stopped before a record: an equivocation, a log
  that fails, a claim refuted outright. It now prints a document on every exit, and a refuted
  claim is folded into the full report.
- **`trigon attest` refused a claim whose outcome held and whose `applied` did not as "the run
  recorded `normalized` and the bytes give `normalized`"**: the refusal names the fields now.
- **No test held a refuted claim to exit 4**: setting it to never refute passed every test.

### 3.100 `trigon publish`: one verified commit, and a log key only `trigon log sign` holds

`docs/19` §10 phase 5, first half, on 2026-09-28: the evidence repository's writer. `trigon log
keygen`, `log init` and `log sign`, and `trigon publish` for runs, withdrawals and heartbeats, with
`--dry-run` and `--reconcile`. The second half — rebuilt artifacts as release assets, the
divergence feed, `log key-change` and `log succeed`, `--prune`, `serve`'s report of the repository's
kill-switch, and the spike against a scratch GitHub repository — is phase 5b, and each of its
settings is refused here rather than half-honoured.

**What changed.**

- **`trigon log keygen --origin <o> --out <file>`**: an Ed25519 log key in Go's private-key
  format, named by the origin, written `0600` and never over a file already there, with the
  verifier key a client pins printed whole. The origin is held to `[publish] origin`'s rule
  (`config::check_origin`).
- **`trigon log sign --tree <dir> --size <n> --key <file>`**: the one step that holds the log key.
  It reads the tree from disk and signs its checkpoint only where the checkpoint the tree extends
  opens under the key itself, the new tree's first leaves hash to its root, every leaf decodes and
  keeps its place and time, every tile holds its leaves' hashes, and every new leaf is a heartbeat,
  a key change signed by both keys, or names a record file in the tree, logged at no other leaf,
  that passes `check_record` under the attestation key the tree names, with every evidence file it
  names beside it (`trigon_attest::evidence::check_to_sign`, over the new
  `log::verify_extension`). A release, log-end or log-continuation leaf is refused: no command of
  this build writes one. Nothing past `--size` is read. `--init` writes `keys/log.vkey` and the
  empty checkpoint, and only in a tree with neither.
- **`trigon log init --origin <o> --repo <location> --attestation-key <key>`**: the first commit —
  `keys/`, the README (origin, both keys, "once per publication, and at least every `[publish]
  heartbeat`", and `[publish] disputes`), and the checkpoint of size 0 that `log sign --init`
  signs. A repository with `log/` or `keys/` is refused. It prints the `gh api` call that sets a
  ruleset forbidding force-pushes and deletion with an empty bypass list, naming the repository
  where the origin or the location is on GitHub, and never runs it.
- **`trigon publish [RUN…] [--repo] [--withdrawal <envelope>] [--heartbeat] [--dry-run]
  [--reconcile]`**, steps 1 to 7 as §10 phase 5 lists them (step 3 is D4's). The repository is
  `--repo`, `TRIGON_PUBLISH_REPO` or `[publish] repo`; a working clone is kept at
  `<store>/publish/<sha256 of the location as git is given it>/clone`, beside the newest checkpoint
  verified there, and `<store>/publish/lock` keeps one `publish` at a time, refusing a second with
  the first's pid, start and repository. A local working tree is published into in place, with a
  lock in its git directory, and refused unless clean and on `[publish] branch`. Step 1 resets the
  clone to the remote and verifies its log whole under `keys/log.vkey`, whose origin must be
  `[publish] origin`, and against the stored checkpoint. Step 2 asks `decide` through
  `trigon_api::Index` with the repository's `kill-switch`, and refuses every run it must at once:
  withheld; a divergence under `divergences = "refuse"`; already published; the second of an
  agreeing pair whose first is (the new `Index::agreeing`); a verdict or void for an artifact with
  a current record it does not supersede; a verdict without its falsifying command naming
  `[publish] origin` or the dispute pointer `[publish] disputes` names; and a record every client
  would refuse, checked with `check_record` at the leaf it will have, against the evidence it
  stages (`log::Staged`). Step 4 writes records and evidence deduplicated, one leaf each at a time
  never earlier than the newest, the tiles and bundles `plan_append` gives and the partials it
  makes obsolete removed, and each index file of every new record's keys derived from the log whole
  (`evidence::index_files_after`). Step 5 runs `trigon log sign` as a child process and holds its
  checkpoint to the one planned. Step 6 commits once and pushes without force. Step 7 records
  `RunRecord.published` — repository, commit, record, leaf, and the log where it is not the first —
  through `Store::record_published`, merged into the record as it is now, as attestations are.
- **The forms without runs.** `--withdrawal` publishes a `withdrawal/v1` of a record the log holds
  and nothing supersedes yet, of the same subject and purl, with an entry in every index file of its
  keys. `--heartbeat` logs a heartbeat leaf when the newest is older than `[publish] heartbeat`, or
  none, on a log with no leaves, and otherwise says why and writes nothing. `--reconcile` writes
  every index file the log implies and removes every other under `index/`, in one commit, or says
  there is nothing to reconcile. `--dry-run` reads a clone of its own, prints every file and leaf
  and the checkpoint body, unsigned, and runs no `log sign`; the repository, the working clone and
  the store's runs are left byte-identical.
- **Carried over from phase 4b, decided by the lead.** `check_record` takes the origin of the log a
  leaf is in, and fails a logged v2 verdict without its falsifying command, one whose command is not
  `trigon verify-attestation` naming its own subject, its own predicate type and that origin, and a
  divergence without an `https://` dispute pointer, as a new `RecordFailure::Recourse` (kind
  `no-recourse`); a verdict that carries a dispute pointer it need not is held to the same. The
  golden repository is regenerated: `k`, in the successor log, now names the successor's origin.
  `verify-attestation --record`'s test of a verdict with no command, which pinned it rendering with
  "falsify none signed", now expects exit 4.

**Decided here, and why.**

- **`log keygen` and `log sign` are in the verifier build too**, as `keygen` is: neither opens a
  socket, and D5's option of a log key held apart wants a binary that can sign where nothing else
  runs. `log init` and `publish` are the build half's.
- **`log sign` takes `--size` and `--log`** beside the `--tree` and `--key` §10 names, so that what
  it signs is exactly a size it was told, and a wider bundle planted beside the new one is never
  read. It takes the attestation key from the tree's `keys/attestation.pub`, or `--attestation-key`;
  a push credential that swaps the file stops publishing, since every honest record then fails, and
  gets no record of its own signed, since only `publish` writes new leaves.
- **A lost race is decided by asking the remote**, not by reading `git`'s wording: a rejected push
  whose remote branch has moved from the commit the publication was built on is a lost race, and
  any other failure is an error. `git` says `[rejected] (fetch first)` for one refused before the
  pack is sent and `[remote rejected] (failed to update ref)` for one refused after it.
- **A publication is committed as `trigon publish <publish@trigon.invalid>`**, not as the
  operator: who committed a file is never who signed it (§8), and the operator's address would
  otherwise enter a public history with every publication. `--no-verify`, so no pre-commit hook of
  a tree published into changes what `log sign` checked. `git` keeps the operator's own
  configuration, where the credential helper is, with `GIT_TERMINAL_PROMPT=0`, and `GIT_DIR` and
  its kin removed, which a `publish` run from a git hook needs.
- **A void, like a verdict, must supersede a current record for its artifact.** §3 said "a
  verdict"; a void published beside a current verdict is a second current record, which a client
  can only show beside the first, and §3 now says so.
- **At publish, a verdict needs both the falsifying command and the dispute pointer, equal to
  `[publish] origin` and `disputes`**, as §2.4 says; a client requires the pointer only on a
  divergence, as §4.2 item 6 does.
- **A withdrawal of a record already superseded is refused**, naming the record that supersedes it:
  it would be a second current record, and it is that one that should be withdrawn.
- **`TRIGON_PUBLISH_DIE_AT=written|signed|committed|pushed`** stops `publish` there as a kill would,
  with nothing cleaned up, for the tests of a killed publisher. It is in every build: a kill can
  stop `publish` at any of those points anyway.

**What this does not do.**

- Phase 5b, above. `rebuilt_artifacts = "github-release"` is refused rather than publishing records
  that name assets nobody uploaded, and `divergences = "feed"` still refuses divergences.
- Push to HTTPS or SSH in a test: nothing here reaches GitHub. That a location reaches `git` exactly
  as configured is a unit test; the spike of §10 phase 5 is where a real push is measured.
- Make the race of D26 impossible. A push that loses between the server advertising its refs and
  updating them has sent its objects, the signed checkpoint among them: measured against a local
  bare repository, whose object store kept the losing commit, unreachable, after `[remote
  rejected] (failed to update ref)`. One publishing host under the lock is what makes the race
  impossible, as ADR-0014 says. The test of two racing publishers has the second publish from a
  `post-commit` hook in the first's clone, with a state directory of its own as a second host has,
  so the first is refused before its pack is sent, and checks every object the remote holds.
- `attest --prune`'s refusal of an unpublished run, which waits on D4.

**Found on the way.**

- **`index_files` could derive the index only from a verified log**, and the writer needs the index
  of a tree whose checkpoint is not signed yet; `index_files_after` is the same derivation with the
  new leaves appended.
- **Nothing could write `keys/attestation.pub`** from a public key: only a private `LocalKey`
  wrote SPKI PEM. `AttestationKey::to_pem` shares its writer.
- **A test built on the golden repository pinned a record rendering an outcome without its
  falsifying command**, the behaviour §8 forbids and this phase removes.

**What review found in it.** Eighteen findings, of twelve defects — several found more than once —
and a test that could not see what it was named for. Each defect now has a test that fails without
its fix.

- **A `.gitignore` could make `publish` push a signed checkpoint without its leaves.**
  `git add --all` staged the publication, and follows the tree's `.gitignore`, the operator's
  excludes and every filter or line-end conversion an attribute names; nothing checked that the
  commit held what `log sign` checked. A `.gitignore` naming `tile/`, which whoever can push may
  commit, left the remote with a signed checkpoint and no bundle, and the next run's `clean -x`
  deleted the only copy: the log could never verify again. `log init` could push `keys/` without
  `log/checkpoint`. The commit is now made from exactly the bytes written —
  `hash-object --no-filters` and `update-index`, never `git add` — and read back before the push:
  its parent, every path it changes and every blob must be the publication's, each blob's id
  computed here from the bytes rather than taken from `git`. A branch that names git attributes is
  refused before it is checked out, so no filter the operator's configuration defines ever runs on
  it; `core.autocrlf` and the operator's attributes file are switched off for every run; and a
  working tree published into must hold nothing git ignores where a publication reads and writes,
  and is discarded there, ignored files included, when a publication fails
  (`what_a_publication_writes_is_committed_whatever_git_is_told_to_ignore`,
  `a_branch_that_names_git_attributes_is_refused_before_it_is_checked_out`,
  `a_commit_holds_exactly_what_was_written_whatever_the_tree_ignores`).
- **The operator's `commit.gpgSign` signed, or stopped, every publication**: a public commit signed
  with the operator's own key, which the fixed committer is there to keep out of the history, or a
  passphrase prompt, or `gpg failed to sign the data`. `push.gpgSign` would fail every push to a
  server without signed pushes. Commits are made `--no-gpg-sign` and pushes `--no-signed`
  (`the_operators_git_configuration_changes_nothing_that_is_committed`).
- **ssh could wait on a terminal nobody watches.** `GIT_TERMINAL_PROMPT=0` stops `git`'s own prompt,
  not ssh's passphrase or host-key question, and a scheduled `publish --heartbeat` from a session
  with a terminal held its lock while ssh waited. ssh runs with `BatchMode=yes` now, added to a
  configured `ssh` command too; a command that is not `ssh` runs as configured, and the documents
  say so (`ssh_is_told_never_to_ask`).
- **A working clone whose `.git` was gone was taken for the repository around the store.**
  `git -C <clone> rev-parse` looked up through the parents, found the checkout the store sat in —
  the owner's own sits in this repository — and `publish` rewrote its `origin`, reset its branch to
  the evidence commit and discarded its uncommitted work. A clone is used only where its git
  directory is its own, and every `git` run in a directory looks for a repository there and no
  further up
  (`a_working_clone_without_its_git_directory_is_made_again_and_never_the_checkout_around_it`,
  `a_directory_without_a_repository_of_its_own_is_never_taken_for_the_one_around_it`).
- **A remote rolled back could make the log key sign a second root for a size it had published.**
  The newest checkpoint verified was kept per store and per spelling of the location, and `log sign`
  accepted any checkpoint in the tree its key opened, so a fresh store, or `file://` for a path,
  built on the rolled-back log and signed. It is kept by the log's origin in the host's state
  directory now, and `log sign` holds every tree to it as well as to the tree's own base (below)
  (`a_remote_rolled_back_behind_what_this_host_published_is_refused`,
  `a_tree_that_does_not_extend_what_was_published_is_not_signed`).
- **`log sign` wrote its checkpoint through a link.** The file it renamed from was opened with a
  plain write at a predictable name, which follows a link planted there, and `log init` wrote the
  README the same way. Both are made new now, never opened, and renamed over the old
  (`a_file_is_replaced_and_never_written_through_a_link`).
- **One `publish` per host was one per store.** Two stores on one host raced into D26's window. A
  lock in the host's state directory keeps one `publish` at a time on it, whatever store it runs
  from, beside the store's (`one_publish_runs_at_a_time_on_a_host_whatever_store_it_runs_from`).
- **Any branch ending in the publish branch's name was read as it.** `ls-remote` matches a pattern
  against a ref's end, so `refs/heads/a/refs/heads/main`, which anyone who can push can make, turned
  every push failure into a lost race, five times over, with the real error unsaid. Only the exact
  ref is read (`the_remote_head_is_the_branch_named_and_no_other_ending_in_its_name`).
- **A push the remote took was taken for a lost one** when the connection went before the remote
  answered: `publish` said it discarded what was published, and a withdrawal then refused itself as
  already logged. A remote at the commit just pushed is a publication
  (`a_push_the_remote_took_is_published_even_when_the_connection_goes_before_it_answers`).
- **`--reconcile` walked a directory of the host's** through an `index` planted as a link, and a dry
  run listed its files. The start of the walk is held to be a directory of the tree's own
  (`reconcile_never_reads_through_a_link_planted_as_index`).
- **A run completed after its record file was removed named the branch's tip** as the commit that
  logged it. The commit is now the first whose checkpoint, opened under the log's key, covers the
  leaf, and the missing file is said
  (`a_run_completed_after_its_record_file_was_removed_names_the_commit_that_logged_it`).
- **The ruleset `log init` prints protected the default branch**, whatever `[publish] branch` is. It
  names the branch the log is on (`the_ruleset_protects_the_branch_the_log_is_on`).
- **The test of files planted in `log/` could not see the leaf it planted**: its heartbeat's time
  broke the order rule, and it counted record leaves only. The heartbeat is a valid one now, and the
  test asserts the log's size and that no heartbeat was signed.

**Decided in review, and why.**

- **What `log sign` holds a tree to is the newest checkpoint *published*, never the newest
  *signed*.** A checkpoint signed for a push that loses, or one a kill stops, never leaves the host;
  holding the key to it would refuse every tree after a crash between signing and pushing, and stop
  the log for good. So the host keeps what it has verified on the repository and what it has pushed,
  `publish` moves it forward at step 1 and after the push, and `log sign` moves it forward to the
  base of every tree it signs. It is kept by origin, not by vkey, so that a second key under one
  origin is refused rather than given a memory of its own. And `log sign --init` refuses a log the
  host has published: the same key beginning a second repository's log signs a second root for every
  size. `the_repository_named_each_way_publishes` now begins each repository as a log of its own,
  since four logs under one key and one origin were four roots for size 1.
- **The host's state directory is `$XDG_STATE_HOME/trigon/publish/`**, the store's `publish/`
  keeping only the working clone and its lock; `docs/19` §2.4 said the checkpoint was kept in the
  store, and says where it is now, and why.
- **A branch with attributes is refused, not neutralised.** Recent `git` can read attributes from
  another tree, `--attr-source`, which an empty tree would neutralise, and older `git` cannot;
  `info/attributes` applies either way. A refusal is the same on every version, and the branch is
  checked before it is checked out.
- **D27, new**: a host with no memory of the log — a fresh CI runner — is held only to what the
  repository holds, and on one rolled back its log key signs a second root. The ruleset is what
  forbids the rollback, and keeping the state directory between runs is what catches one.

### 3.101 The rest of `trigon publish`: release assets, the feed, rotation, pruning, and the switch

`docs/19` §10 phase 5, second half, on 2026-09-28. Everything phase 5a refused rather than
half-honoured is built: `rebuilt_artifacts = "github-release"`, `divergences = "feed"`, a log that
has ended, and the release, log-end and log-continuation leaves `log sign` would not sign. The
spike is written and has **not** been run.

**What changed.**

- **Rebuilt artifacts as release assets** (`crates/trigon/src/publish/release.rs`). Step 3 finds or
  uploads each verdict's rebuilt artifact as the asset `sha256-<hex>` of the digest the verdict
  signs, in the month's release `rebuilt-YYYY-MM`, continued as `.2`, `.3` once a release holds
  1,000 assets, before anything that names it is written. An asset of the name already in this
  month's or last month's series is reused only where GitHub reports its digest and its size and
  digest are the artifact's, and refused where either is another's; one GitHub left unfinished, or
  reports no digest for, is removed and uploaded again from the store, once the store has yielded
  the bytes to put in its place. No asset goes into a draft release. An exact rebuild, the published
  artifact itself, is not uploaded, and a void has none. Refused before anything is written: a
  location that is not a github.com repository, a missing token, an artifact not under 2 GiB, and a
  run whose stored rebuilt artifact is not the one its verdict signs. GitHub's REST API over the
  `reqwest` client the crate already links, with the shared User-Agent; the token comes from
  `GITHUB_TOKEN` or `GH_TOKEN` only, prints as `***`, rides only in the `Authorization` header, and
  goes only to the API and to an upload URL on GitHub's upload host — or, under `TRIGON_GITHUB_API`,
  which must be HTTPS or loopback, to that server's own origin. No redirect is followed, and a
  refusal that quotes the token back has it taken out. A dry run says where each asset would go and
  uploads nothing, token or not.
- **The divergence feed** (`publish/feed.rs`). Under `divergences = "feed"` a divergence is
  published, and `feed/divergences.atom` is regenerated from the log whole in the same commit — and
  in the commit of any record superseding a divergence, and by `--reconcile`, which also removes
  anything else under `feed/`. The most recent 200 divergences, newest first; each entry's id is
  its record's digest as an RFC 6920 `ni:` URI, it links the record file and the dispute pointer
  the record signs, carries the falsifying command, and says so where its record is superseded,
  missing or failing verification. Written by hand, escaped for XML with the characters XML cannot
  carry replaced, and tested by parsing it with `roxmltree`, a dev-dependency that knows nothing of
  how it was written. `log init`'s README states the count.
- **`trigon log key-change --key <current> --new-key <new>`** logs a key-change leaf through
  publish's steps 1 and 4 to 6. The leaf is signed by `trigon log key-change-leaf`, a hidden child
  that opens no socket, as `attest` is, and held by the parent to the origin, time and keys it asked
  for; the parent refuses a `--key` that is not the key the log has now, and a new key the log has
  retired. From that leaf on, `publish` refuses a record not signed by the current key, with the key
  it needs, and says after the change how to switch: `trigon attest --key <new key>`; nothing in
  `evidence.toml` names the signing key, and `keys/attestation.pub` stays the key the chain starts
  at. `--dry-run` signs nothing: the keys' public halves come from `trigon public-key`, a child, and
  the leaf is shown with its signatures empty.
- **`trigon log succeed --origin <o> --log-key <file> [--url <location>]… [--dir <dir>]`** logs a
  log-end naming the successor's origin, log key, URLs and directory — the next free `log/<n>` by
  default — and begins the successor with its log-continuation. `publish` learns the successor's
  key from `trigon log public-key <file>`, new and in both builds, run as a child; `log sign
  --successor-key` signs the final checkpoint and cosigns it with the successor's key, which is
  written as the old log's `checkpoint` with both signatures; `publish` writes the continuation,
  holding that note and logged at the log-end's time, and `log sign --continuing <tree>` signs the
  successor's first checkpoint. In the same repository all of it is one commit. With `--url`, the
  repository at the first URL is cloned and looked at before the log-end is written — refused with
  nothing written where it is the evidence repository itself, cannot be reached, holds `keys/`,
  `log/` or the successor's directory, names git attributes, or would not take a push, which `git
  push --dry-run` asks — then the old log's end is pushed and the successor begun as that
  repository's first commit, carrying the old repository's `kill-switch` where it is set. A
  publisher stopped between (`TRIGON_PUBLISH_DIE_AT=ended`) leaves an ended log that refuses every
  publication, and the same `log succeed` run again begins the successor from the final checkpoint
  published. Both rotations regenerate the README's account of key changes and successors from the
  log.
- **`log sign`** accepts the new leaves under the rules phase 4a's rotation code applies
  (`trigon_attest::evidence::check_to_sign`, which now takes the successor's key, and the new
  `check_to_begin`, over `log::verify_beginning` and `log::find_predecessor`): a log-end only with
  the successor's key in hand and equal to the one named, and a successor key never for a tree that
  does not end naming it; a successor's first tree only as its log-continuation alone, holding the
  predecessor's final checkpoint signed by both keys, logged no earlier than the log-end, from a
  predecessor extending what this host published of it, and only once `follow` — the client's own
  code — accepts the pair over the checkpoint staged before it is written. For a successor's later
  trees it follows the whole chain's key changes from `keys/attestation.pub`. A release leaf is
  still refused.
- **`publish` into a chain.** The chain of logs `keys/log.vkey` begins must end, in the repository,
  at `[publish] origin`'s log, which a publication appends to; `RunRecord.published.log` names
  `log/<n>`. Publishing under the ended log's origin is refused with where publishing goes on.
- **Pruning.** `publish --prune` prunes the rebuilt artifact of each run it published or completed,
  with the store's own prune, after step 7. `attest --prune` refuses, before signing anything, a
  run not yet published where a publish repository is configured with `rebuilt_artifacts =
  "github-release"` and a publication would upload its artifact — one the gate withholds now
  included, since a confirmation can release it — and prunes as it always did an exact rebuild, a
  void run, the second of an agreeing pair whose first is published, and anything anywhere else.
- **`trigon serve`** reports the repository's kill-switch beside `--stop-divergences`
  (`publish/switch.rs`, injected into `trigon-api` as the decompiler is): read with `git ls-tree`
  from the commit the working clone's last fetch that succeeded brought the branch to, as of when
  that fetch began, both of which `publish` records in the clone's git directory
  (`trigon-fetched`) only once a fetch succeeds; from the branch itself for a working tree
  published into. Set wherever git lists anything named `kill-switch`, as `publish` counts it;
  clear only where it lists nothing; and `unknown`, never clear, with no clone, no record of a
  fetch, or a tree git cannot read. `serve` reads it on starting and every ten seconds after, on a
  blocking thread, and hands every request the last reading (`trigon_api::cached_switch`).
  `/v1/health` and the page's boot island carry `kill_switches`, each with what it stops; an
  anonymous reader is told the state and when, not the repository or the clone's path. The header
  shows both. `serve` now prints the address it bound, so `--bind 127.0.0.1:0` says which port.
- **The spike** is `scripts/evidence-spike.sh`: with `TRIGON_LIVE=1`, against a scratch repository
  its user names, it grows synthetic records shaped as §7 sizes them to each of 10⁴ and 10⁵,
  timing each growth push, the consumer's partial shallow sparse clone at each size, and that
  clone's fetch after a publication-sized push at that size; times further publication-sized
  pushes of a few hundred files, paced under GitHub's six pushes a minute, with the largest
  clone's fetch after each; makes unauthenticated git reads of the public URL above GitHub's
  advice of about 15 a second — `ls-remote`s and shallow blobless fetches into empty repositories —
  and records what each answered; uploads small assets and one large one to a release and times
  listing them, and with `--probe-asset-limit` tries a 1,001st; and records the repository's size
  and the API's rate limits. Before anything is pushed it refuses a push or clone URL that does
  not name the repository, a branch other than `main`, a release it did not make, and a `main`
  holding anything but its own `SPIKE.md`, `keys/`, `log/`, `records/` and `index/`. It never
  force-pushes or deletes, and keeps its token off every command line. Its record
  generator was run offline (8 KB records, 200-byte index files, bundles and tiles in tlog-tiles
  paths); **the spike itself has not been run**: it needs a GitHub repository this environment
  must not create. Its results belong here, and in D2, when it is.

**Decided here, and why.**

- **`keys/` stays the keys the chain starts at.** Every client pins them, and follows each change
  from them; rewriting `keys/attestation.pub` on a key change would have `publish`'s own
  verification refuse every record signed before it, and rewriting `keys/log.vkey` on a succession
  would start its chain at the successor and hide the old log's records from the supersession
  check. The README, regenerated from the log, names the keys after each rotation.
- **The final checkpoint carries the successor's cosignature in the old log's `checkpoint` file
  too.** It makes the continuation reproducible from what was published, which is what lets a
  succession into another repository be finished after a stop between its two pushes without the
  old key signing anything twice; a reader of the old log ignores the second line, as it ignores a
  witness's.
- **The processes that push hold no key.** `publish` never opened the log key; now neither
  `log succeed`, which asks `log public-key` for the successor's verifier key, nor `log key-change`,
  which has a socketless child sign the leaf with both attestation keys. Only `attest`,
  `key-change-leaf` and `log sign` open a key, and none of them opens a socket.
- **An asset is found across two months of releases, not every release.** A retry is minutes
  after the attempt it retries; a duplicate asset in a later month's release is harmless, since no
  record names a release, and listing every release's every asset on every publication would grow
  without bound.
- **A token is required whenever the mode is on and runs are published**, even when every run named
  turns out to be void: the refusal is before anything is read, which is where a missing credential
  is cheapest to hear about.
- **An exact rebuild is not uploaded.** Its bytes are the published artifact's, which docs/19 §4.1
  says is not ours to redistribute and which every reader of the record already holds.

**What this does not do.**

- **Run the spike.** Above; `docs/19`'s status table says so too.
- **Notify anyone of a divergence.** The feed is published; safeguard 4 becomes "published at
  publish time", as D7 proposes, and D29 says what that is and is not.
- **See across repositories.** A successor in another repository is published into on its own
  chain, so a verdict for an artifact with a current record in the old repository is not refused
  there as a second current record (D31); following a chain across repositories is phase 6's.
- **Run a live test against GitHub in CI.** `live_an_asset_is_uploaded_to_github_and_reused` runs
  only with `TRIGON_LIVE=1` and `TRIGON_LIVE_GITHUB_REPO`, and skips otherwise; every other test of
  the release path speaks to a server on `127.0.0.1:0` that serves the five endpoints used, and to
  a git repository reached by a GitHub URL through `url.<local>.insteadOf`, with
  `GIT_ALLOW_PROTOCOL=file` so that nothing could reach the network if the rewrite failed.

**Found on the way.**

- **A test world inherited the developer's GitHub token.** `World::command` removed every
  `TRIGON_*` and nothing else, so a `GITHUB_TOKEN` in the shell running the tests would have reached
  a publish with no `TRIGON_GITHUB_API` — `api.github.com`. It removes `GITHUB_TOKEN` and `GH_TOKEN`
  now, and every test git is let reach files only.
- **An operator's mistake read as the evidence source's fault.** A key-change signed with one key
  twice surfaced as a `LogError`, which the fault report labels "the evidence source's: its log
  could not be read". The child says what it is, in the operator's words, and so does `succeed` of
  a `--dir` no log-end can name.
- **`serve` printed the address it was asked for**, `127.0.0.1:0`, not the one it bound.

**Found in review, and fixed.**

- **`serve` stamped an old switch with a new time.** The report was as of `FETCH_HEAD`'s time, and
  a fetch that fails rewrites `FETCH_HEAD` too: with the remote unreachable and a daily heartbeat
  failing, a switch set meanwhile read "clear, as of today". The time and the commit are now
  recorded by `publish` only after a fetch succeeds.
- **"Clear" meant "git said no".** `cat-file -e` failing for any reason — a spawn that failed, an
  unreadable object, a `kill-switch` committed as a submodule entry whose commit the clone does not
  hold, which `publish` counts as set — read as clear. It is `ls-tree` now, and only an empty
  listing is clear.
- **Every request forked `git`.** `/v1/health` and every page read the switch on the request path,
  four `git` processes blocking a runtime worker, for anonymous readers too. Read on a timer now.
- **A log could be ended naming a place no successor could be begun.** `log succeed --url` pushed
  the log-end before looking at the URL; naming the evidence repository itself, or any repository
  with a log, ended the log for good with nowhere to go, and every later `log succeed` refused the
  same way. Looked at first now, with nothing written on a refusal.
- **A succession elsewhere cleared the kill-switch.** The successor's first commit carried no
  `kill-switch`, so switching `[publish] repo` to it published divergences again although nobody
  had cleared safeguard 5. It is carried over now.
- **A run completed after a succession was completed against the wrong log.** Its leaf was looked
  for in the last log's history under the last log's key; it is looked for in the log of the chain
  that holds it, which `published.log` now names.
- **An asset was reused on its size alone where GitHub reported no digest**, and a failed release
  creation could fall back on a draft of the same tag, uploading into a release the public cannot
  see. The first is uploaded again, and the second refused.
- **`log key-change --dry-run` signed the leaf with both keys and printed it**, though its help said
  it signs nothing; a preview left in a CI log was a hand-over anyone holding the log key could
  append.
- **`attest --prune` refused for ever** a run no publication would upload an artifact for, such as
  the second of an agreeing pair whose first is published.
- **Nothing tested the checks the release path's security rests on**: the kill-switch stopping a
  divergence the feed would publish, an asset of the artifact's name that is not the artifact, one
  left unfinished, an upload URL on another host, a server quoting the token back, and the API
  base's own rules. Each has a test now that fails when the check is removed.
- **The spike measured less than it said, and guarded less.** The fetch was timed at the largest
  size only, git reads were not probed at all, and the guard took any repository with a `SPIKE.md`
  and never checked that the repository the API wrote releases to was the one it had read.
