# Automatic base image derivation, and `--image auto`

A plan. Nothing here is built yet.

Two asks: install a tool the build needs when the base image does not carry it, and let `--image
auto` choose an image instead of making the operator name a digest. They are the same mechanism
seen from two ends, and the hard part in both is not the installing. It is deciding what may be
installed at all.

## What is already here

More than it looks like from the outside.

`Requirements::system_deps` is a `BTreeSet<String>` of neutral package names, and it is populated at
**render time** (`render.rs:96`) — before any container starts. `expand(dep, family)`
(`dockerfile.rs:157`) turns a neutral name into that distribution's packages: `python3` becomes
`python3 python3-venv` on Debian, `cc` becomes `build-essential` or `build-base` or `gcc gcc-c++
make`, `pkg-config` becomes `pkgconf` on Fedora. `install_command` and `verify_command` share that
expansion, so an image carries exactly what the setup phase would have installed rather than an
operator's guess at the package names.

`verify_command` runs inside the plan's own Containerfile, probes each expanded name with `dpkg -s`
or `rpm -q` or `apk info -e`, and on a miss prints the remedy:

```
this base image is missing: openssh-client
an enforced egress tier gives the image build no network, so the packages a
strategy needs have to be in the image already. Build one with:
    trigon base-image --from sha256:… --packages openssh-client
```

That is a complete, correct, copy-pasteable fix. **Nothing acts on it.** The whole of this plan is
the distance between printing that line and running it safely.

## Three gaps, measured

### 1. The check only sees what a strategy declares

`verify_command` is handed `plan.deps`, which is the union of the `needs:` lists on the steps that
actually run. The entire declared vocabulary across every strategy in the tree is seven names:
`git`, `wget`, `ca-certificates`, `python3`, `uv`, `libatomic`, `npm`.

Every `env/missing-tool` failure in two npm sweeps names a tool that appears in none of them:

| tool | sweep-npm | sw2-npm |
|---|---|---|
| `ssh` | 7 | 0 |
| `npx` | 3 | 3 |
| `pnpm` | 2 | 3 |
| `yarn` | 2 | 3 |
| `just` | 1 | 1 |

And `env/base-image-incomplete` fired **zero** times in either sweep. That reads like the check
working. It is the check having nothing to say: the declarations were too thin for it to catch
anything, so it passed, and the build died a phase later with a message about a missing binary
instead of a message about an incomplete image.

This is the shape that keeps recurring here — a control that fails open and reports success. The
control is sound. Its input is incomplete, and nothing asserted that its input was complete.

### 2. The image can drift from the list, and nothing notices

`ssh` is in `DEFAULT_PACKAGES` today. It was added by hand in `328af2f` (2026-09-15), whose comment
records why: "Eight npm targets on the full corpus failed `ssh: not found`, all of them in the
strata with real dependency trees."

So the feedback loop already exists and already works — the table above is the proof, seven
failures before and none after. It runs at human speed, through a hand-edited constant, and it took
a corpus sweep plus someone reading it to close one package.

Worse, nothing connects a built image back to the list it was built from. There is no label, no
manifest, no recorded package set. `is_pinned` checks the *shape* of a reference — an `@` or a
64-hex id — not its contents. An image built the day before `328af2f` is as pinned, and as
acceptable to every check in the codebase, as one built after. The only thing that can tell them
apart is starting a container and probing, which only happens for names some strategy declared,
which brings us back to gap 1.

### 3. Most of what is missing must not be installed

Of the failures above, `ssh` is a library-grade dependency and the rest are package managers. The
`DEFAULT_PACKAGES` doc comment already rules on them, on the record:

> `yarn` and `just` are absent for the same reason as `npm`: a package whose build requires another
> package manager is a finding about that package, and installing every one of them makes the image
> the union of every ecosystem's opinions.

So an auto-installer built the obvious way — take what was missing, install it, retry — would
"fix" nine of the ten measured failures by discarding the finding each one represents. It would
raise the reproduction rate and lower what the number means. That is the single largest risk in
this feature, and it is why the plan below spends most of its length on a classifier and almost
none on an installer.

## The principle

ADR-0012 says a base image may supply **bytes** the evidence does not pin, and may never supply a
**decision** the evidence does pin. An automatic mechanism inherits that line exactly:

> Automation may add bytes. It may never add a decision.

`ssh` is bytes: npm shells out to it to fetch a `git+ssh://` dependency, and the dependency
resolved is the same either way. `yarn` is a decision: which resolver builds the tree changes the
tree. The classifier is the feature. The installer is a call to code that already exists.

## Part 0 — make the image say what it carries

Prerequisite for everything else, and small on its own.

At `base-image` build time, write labels:

```
org.trigon.packages = ca-certificates cc git libatomic pkg-config python3 python3-dev ssh wget
org.trigon.parent   = sha256:…
org.trigon.family   = debian
org.trigon.versions = <dpkg-query -W output, or its digest>
```

Neutral names in `packages`, because that is the vocabulary `needs:` and `system_deps` speak;
expansion is a function of the family, which is also on the label. `versions` is discussed under
*the admitted gap* below.

The label is an **index, not an authority**. `verify_command` keeps its probe, and the probe
remains the thing that decides. A label can be wrong — someone can build an image by hand with the
same label — and a selection mechanism that trusted it would be a second control that fails open.
The label exists so selection does not have to start a container, and so `podman inspect` can
answer "is this image current?" — which today nothing can.

## Part 1 — learn the needs the declarations missed

The classifier already extracts the missing tool's name. `Capture::WordBefore(": not found")`
produces `env/missing-tool:ssh`, and that capture is in every run record on disk. The demand signal
that took a human and a corpus sweep to read in `328af2f` is already structured data.

Add a proposing mode:

```
trigon base-image --from <digest> --learn work/          # or a sweep directory
```

It reads the run records, collects every `env/missing-tool:*` capture, runs each name through the
policy table, and prints two lists: packages it would add, and packages it refuses to add with the
reason. It installs nothing on its own. `--learn` proposes; a human still runs the build.

That is deliberately short of automation. The step from "propose" to "apply" is one flag, and it
should not be taken until the policy table has been exercised against a corpus and the refusals
read correctly.

## Part 2 — the policy table

A const table beside `expand()` in `dockerfile.rs`, since it shares that vocabulary. Three verdicts:

- **`Bytes`** — may be added automatically. `ca-certificates`, `git`, `wget`, `ssh`, `cc`,
  `pkg-config`, `libatomic`, `python3-dev`. Candidates on the same reasoning, currently absent and
  named as real gaps in the `DEFAULT_PACKAGES` comment: `meson`, `ninja`. They build; they do not
  resolve.
- **`Decision`** — never added automatically, at any tier, with or without a flag. `npm`, `yarn`,
  `pnpm`, `node`, `rustc`, `cargo`, `dotnet-sdk`, `go`. Each entry carries its reason as a string,
  and the refusal prints it. `just` belongs here too and is the interesting case: it is a task
  runner rather than a resolver, but its recipes *are* the build, so installing it decides what
  runs.
- **`Unknown`** — refuse, and say the name has no verdict. New entries land here by default; that
  is the fail-closed side, and it is the one that matters.

Pin it with a test: every name appearing in an `expand()` match arm, and every name appearing in a
`needs:` list in the strategy tree, must have a verdict. A name with no verdict fails the build
rather than defaulting to permissive.

### The latent hazard this activates

`npx.yaml`'s own comment forbids it in bold:

> **Do not add `needs: [npm]` back at tool level.** Debian's `npm` package pulls in its own Node —
> 18 on bookworm — plus a tree under `/usr/share/nodejs` that a system-wide `NODE_PATH` puts ahead
> of everything. A pinned Node 10 then loads modules written for 18 and aborts with SIGABRT […]
> `env/toolchain-crashed` on the M1 corpus was this, not vintage.

`needs: [npm]` nonetheless appears at `npx.yaml:146`, `version-override.yaml:25` and
`setup-registry.yaml:6`. Today that is latent: the declaration only drives a *check*, the images
happen to carry npm, and the check passes. An auto-installer makes it live — the mechanism would
install Debian's npm, drag in Node 18, and reproduce precisely the crash that comment documents.

So the policy table must land **before** any apply path, and a `Decision` verdict reached through a
`needs:` list should be a hard refusal quoting the reason. Reconciling those three declarations
against the comment is a prerequisite and is small work; it is also worth doing on its own merits,
since a declaration that contradicts its file's own documentation is the "two things that had to
agree, with nothing asserting they did" pattern again.

## Part 3 — `--image auto`

`auto` resolves to a digest, deterministically:

1. **Compute the required set.** Strategy `needs:` ∪ the ecosystem floor (`DEFAULT_PACKAGES`).
   Available at render time from `system_deps`, before a container starts — so this is a pre-flight,
   not a retry-on-failure.
2. **Classify.** Any `Decision` or `Unknown` in the set → refuse now, with the existing message and
   the table's reason. Do not derive, do not run.
3. **Select.** Find a local image whose `org.trigon.packages` is a superset of the required set,
   whose `org.trigon.parent` is the configured distro base, and whose family matches. Hit → use its
   digest.
4. **Derive on miss.** `base-image --from <pinned parent> --packages <required>`, tagged by content
   — `localhost/trigon-base:<hash of family + sorted names + parent digest>` — and resolved to the
   built image's digest.
5. **Record.** `Environment.base_image` gets the derived digest, as today. Add
   `base_image_parent` and `base_image_packages` so a reader of the record, or of the signed
   predicate, can see what was added to what and why the image differs from a stock distro.

Explicit `--image` and `auto` then become one mechanism with two entry points: explicit names the
parent, `auto` takes the parent from configuration. An explicit image that turns out to be short
can be *offered* the same derivation rather than only being refused.

### What `auto` must not do

- **Must not choose the parent by ecosystem.** "npm target, so the Node image" is a decision, and
  ADR-0012 forbids it. The parent is a distribution, chosen by configuration, identical across
  ecosystems. `auto` is intelligent about *packages*, never about *toolchains*.
- **Must not resolve to a tag, and must not resolve to a `localhost/...@sha256:` reference
  either.** Step 4 yields the bare 64-hex image id. `is_pinned` accepts both forms because it
  checks the *shape* of a string, but podman reads the `localhost/` prefix as a registry hostname
  and tries to pull over HTTPS from a registry nobody is running — so the operator gets
  `connection refused` about an image sitting on their own disk
  (`plan.rs:514`, which notes this had already cost somebody three round trips). A mechanism that
  derives images and hands their references onward is exactly where that would become routine.
- **Must not derive inside an enforced boundary.** Derivation is `apt-get`; that is network.
  At `mirror-only` or tighter, `auto` may select (steps 1–3) but may only derive behind an explicit
  opt-in, and the run record must say an image was built outside the measured boundary. Silently
  spending network that the egress accounting does not see is B7's shape, and B7 was closed by
  moving the image build *inside* the boundary — so this needs to be reasoned about rather than
  bolted on.

## The admitted gap

`apt-get install` is not reproducible. The same command on two days installs different bytes, and
a content-addressed tag computed from the package *names* will collide across two genuinely
different images. ADR-0012 already admits this for hand-built images. `auto` makes it routine, so
it has to be recorded rather than hidden — which is what `org.trigon.versions` is for. Capturing
`dpkg-query -W` at build time does not make the image reproducible. It makes two disagreeing images
comparable, which is the difference between an unknown and a known.

B24 (a content-addressed toolchain store) is the real fix, and ADR-0013's "a cache supplies bytes,
never decisions" is the same line drawn one layer down. This plan is the bridge: it should not
invent a second mechanism that B24 would have to unwind.

## Staging

- **S0** — labels at build time; the every-name-has-a-verdict test; reconcile the three stale
  `needs: [npm]` declarations. No behaviour change.
- **S1** — the policy table and the refusal path; `--learn` proposing from a corpus.
- **S2** — `--image auto`: select from labels, derive on miss, record parent and packages.
- **S3** — the egress-tier interaction and the version manifest.

## What success looks like

Re-run the npm and PyPI corpora with `--image auto`. Success is **not** a higher reproduction rate.

- Zero `env/missing-tool` naming a package classified `Bytes`.
- Every remaining `env/missing-tool` naming a `Decision`, reported with the table's reason rather
  than as a bare missing binary — so it reads as a finding about the package, which is what it is.
- The `yarn`, `pnpm` and `just` targets still failing.

If auto-derivation makes those last ones pass, the classifier has a hole and the number has gotten
worse by going up.
