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

The parser findings are their own cluster and are not yet fixed: a 42-byte zip panics the archive
parser through an unchecked `u64` addition, and neither `gzip::read` nor `zip::read_member` bounds
the inflate — `total_expanded_bytes` is checked against a size the input declares rather than
against what it produces, so a 200 KB member expands to 200 MB inside our own process. Those are
`docs/17-backlog.md` B5's remaining work.

Thirty findings were refuted by the verification pass, which is the part worth keeping: the same
structure that surfaced the guard bug also threw away half of what was claimed.

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

**`trigon/mirror-corrupted-artifact`.** Intermittent; npm retries and then fails with
`Z_DATA_ERROR`. Ruled out so far: transparent gzip decompression (fixed, and a serial fetch through
the mirror is byte-identical to the registry's); concurrency (twelve parallel fetches, all
identical); packument integrity mismatch (the declared sha512 matches the served bytes exactly). It
is correctly classified as ours with nothing to repair, so it does not contaminate any reproduction
rate, but it is unexplained.

**Two clean re-runs before publishing a divergence.** [`10.3`](00-overview.md) requires it and
nothing implements it yet.

**The corpora are smoke sets.** Twenty npm and seventeen PyPI targets, not sampled by prevalence.
Every percentage here is a signal about the pipeline, not an estimate of an ecosystem, and
[`15`](15-corpora.md) §2 says what a real corpus needs.
