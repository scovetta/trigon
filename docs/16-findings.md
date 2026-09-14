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

**The taxonomy has to be able to blame us.** `trigon/mirror-corrupted-artifact` exists so that our
own corruption is counted as ours. Before it, the same symptom was charged to `has-flag` in the
reproduction rate. `Fault::Bug` and `Fault::Infra` are not decoration: without them a reproduction
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
| `trigon/mirror-corrupted-artifact` | **open**, ours, intermittent; see §5 |
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
and the host has no route to it — which is not a bug, it is the definition of the island. So the
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
| **Judgement half** (`core`, `archive`, `stabilize`, `compare`, `attest`) | **89.3%** | **89.3%** |
| `trigon-mirror` | 73.6% | 90.7% |
| `trigon-ai` | 80.9% | 87.3% |
| `trigon-registry` | 71.4% | 76.3% |
| `trigon-sandbox` | 78.0% | 78.7% |
| `trigon` (CLI + UI) | 40.4% | 41.4% |
| Workspace | 69.6% | 72.8% |

**The judgement half moves by 0.0%.** That is worth more than the number beside it. It is the
central architectural claim — that the half which decides a verdict is deterministic and reaches no
network — measured rather than asserted: every line of it that is covered at all is covered by a
test that opens no socket. The crates that move are exactly the ones that are supposed to: the
mirror gains 17 points, `npm.rs` and `client.rs` roughly double.

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
DNS error about the wrong thing: `src/commit-not-on-the-forge` and
`trigon/mirror-corrupted-artifact`.

**What this does not close, and what would.** `packaging@26.3` and `pyproject-hooks@1.2.0` now build
— and still void. The member that arrived inside the adjacent release *is* in the rebuilt artifact,
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

**`trigon/mirror-corrupted-artifact`.** Intermittent; npm retries and then fails with
`Z_DATA_ERROR`. Ruled out so far: transparent gzip decompression (fixed, and a serial fetch through
the mirror is byte-identical to the registry's); concurrency (twelve parallel fetches, all
identical); packument integrity mismatch (the declared sha512 matches the served bytes exactly); and
a mislabelled transfer encoding — `registry.npmjs.org` sends no `Content-Encoding` on a tarball with
or without `Accept-Encoding: gzip`, so the header the proxy forwards cannot be it. Re-measured on
`has-flag@5.0.1`: the transcript records `typescript-4.3.5.tgz` at 10,627,908 bytes and sha256
`c7be550da858…`, which is what the registry serves, and both fetches recorded `Checked::Hashed`
rather than `Partial` — so the body was read whole and the client consumed it whole. It is correctly
classified as ours with nothing to repair, so it does not contaminate any reproduction rate, but it
is unexplained.

The next measurement is the one nothing has taken: the bytes on the **outgoing** side. Everything
ruled out so far is about what the mirror *obtained*; capturing what the container receives and
diffing it against the transcript digest is what separates "the streaming response is at fault" from
"npm is rejecting a body that is exactly what was published".

**Two clean re-runs before publishing a divergence.** [`10.3`](00-overview.md) requires it and
nothing implements it yet.

**The corpora are smoke sets.** Twenty npm and seventeen PyPI targets, not sampled by prevalence.
Every percentage here is a signal about the pipeline, not an estimate of an ecosystem, and
[`15`](15-corpora.md) §2 says what a real corpus needs.
