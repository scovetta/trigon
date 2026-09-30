# Trigon in ten minutes

**Trigon checks that a published package was built from its source.** It downloads the package,
finds the source it claims to come from, rebuilds it in a sealed container, and compares the two.
It reports in one word how far they agree, and signs that answer so anyone can check it without
trusting us.

The links on this page lead to the chapters with the detail.

---

## The question it answers

Package registries ship **artifacts**: a `.tgz` on npm, a wheel on PyPI, a `.crate`, a `.nupkg`.
Reviewers read **source**: the repository on GitHub. Almost nothing checks that the two
correspond, and attackers use that gap at build time. A compromised build machine or a malicious
publisher can ship something the source never contained.

Trigon closes the gap one package at a time. It asks one question:

> **Does this published artifact correspond to that source?**

It does **not** ask whether the package is safe. A package that builds a backdoor from its own
source *reproduces*, and that is the correct answer. Trigon tells you the artifact is what the
source makes; you still judge whether the source is any good.

---

## Five ideas

**1. Rebuild it in a box.** Trigon finds the source at the right commit, works out a **recipe** (a
*strategy*: install these dependencies, run this build), and runs it in a `podman` container. The
recipe is data, not a script, so Trigon can store, compare and replay it.

**2. The mirror is the only way out.** During the build, the container can reach one thing: a
**mirror** of the package registry *as it stood when the package was published*. A dependency
therefore resolves to the version the publisher got, not today's. The mirror hashes and records
everything it serves. If the build tries to download the artifact it is being compared against,
Trigon marks the run **void**, since such a run proves nothing. This setup, the `mirror-only`
egress tier, makes a verdict worth signing.

**3. Stabilizers remove harmless noise.** Two honest builds of the same source rarely match byte for
byte: timestamps differ, files come out in a different order, compression settings vary.
Each **stabilizer** removes one known kind of harmless difference, the same way on both sides, and
reports what it changed and how risky that change is. If you do not accept a particular stabilizer,
you can see that it fired.

**4. One word for the answer.** The comparison ends in one of four outcomes, strongest first:

| outcome | means |
|---|---|
| `exact` | byte-for-byte identical, no stabilizer needed |
| `normalized` | identical after low-risk, built-in stabilizers (timestamps, ordering, file modes) |
| `normalized_with_caveats` | identical, but only after a stabilizer that changes content or that a person or a model wrote; read what fired |
| `divergent` | different, and Trigon names which files |

One answer sits outside the four: **`void`**, meaning "we looked, and could not tell". A run is
void when, for example, the build could reach the open internet or reached the artifact it was
being compared against.

**5. Evidence anyone can check.** Trigon signs its answer as a standard in-toto statement. Anyone
holding the two artifacts can re-run the comparison with a small verifier build that has no
network access. Trigon publishes answers to an **evidence repository** (an ordinary git repository
with an append-only, signed log), which a consumer clones and queries locally. Checking a
thousand-package lockfile then costs one download and tells nobody which packages you use.

---

## How it works

```mermaid
flowchart LR
    pkg(["a package<br/>pkg:npm/wrappy@1.0.2"])

    subgraph search["Search half — may use the network (and a model, if you ask)"]
        direction TB
        find["Find it<br/>registry metadata, the published artifact,<br/>its source repository and commit"]
        recipe["Work out a recipe<br/>checked-in definitions, ecosystem rules,<br/>the project's own CI"]
        build["Build it<br/>in a container whose only route out<br/>is the time-travelling mirror"]
        find --> recipe --> build
    end

    subgraph judge["Judgement half — no network, no model, ever"]
        direction TB
        stab["Stabilize both sides<br/>the same way"]
        cmp["Compare<br/>exact · normalized · … · divergent"]
        stab --> cmp
    end

    subgraph evidence["Evidence"]
        direction TB
        sign["Sign<br/>re-derived from stored bytes"]
        pub["Publish<br/>to a git repository with a signed log"]
        look["Look up<br/>clone, verify, answer locally"]
        sign --> pub --> look
    end

    pkg --> find
    build -->|"the rebuilt artifact"| stab
    find -->|"the published artifact"| stab
    cmp --> sign
```

**The design splits search from judgement.** Finding the source, guessing the recipe and repairing
a failed build are a *search*, which can be messy and may use the network or a language model.
Deciding whether two artifacts are the same is a *judgement*, which must be exact and repeatable.
Trigon keeps the two apart and enforces the split:

- The **search half** (registry clients, source discovery, recipe inference, the sandbox, the
  mirror, the optional model) lives in its own crates and may be as clever as it likes.
- The **judgement half** (archive readers, stabilizers, the comparison, signing and verification)
  links no network client, no async runtime and no model code. `cargo run -p xtask -- policy` fails
  the build if that changes. The **verifier build**, made with
  `cargo build -p trigon --no-default-features`, contains only this half. You hand it to someone who
  wants to check a claim without trusting our build machinery.

**Signing is a separate step on purpose.** `trigon rebuild` ran a stranger's build scripts, so
Trigon does not give it the key. `trigon attest` reads the stored bytes back and re-derives the
verdict before it signs.

**Trigon never publishes a verdict on one build.** It publishes only after a second, independent
attempt agrees, either on another machine or on the same machine starting cold (no build cache,
fresh checkout). A published divergence is a public claim about somebody else's package, so it
carries the command that would disprove it and a place to dispute it.

### Where things live

| | what it holds | made by |
|---|---|---|
| a **work directory** (`--work`) | the checkout, build log, both artifacts of one run | `trigon rebuild` |
| a **store** (`--store`) | every run's record, artifacts and comparison, content-addressed | `trigon rebuild --store` |
| an **evidence repository** | published records, their evidence, and the signed log | `trigon log init`, `trigon publish` |
| `evidence.toml` | where you publish, and which evidence repositories you trust | you, or `trigon evidence add` |

[`01-architecture.md`](01-architecture.md) has the crate map, the full pipeline and the trust
boundaries; [`00-overview.md`](00-overview.md) has the reasoning behind the split.

---

## Using it

Build it once:

```
cargo build --release -p trigon          # the full tool: target/release/trigon
```

Comparing artifacts needs only Rust (the version in `rust-toolchain.toml`). Rebuilding a package
also needs `podman`.

### 1. Compare two files you already have

This needs no network, containers or setup.

```
$ trigon verify wrappy-1.0.2.tgz rebuilt-wrappy-1.0.2.tgz
✔ normalized

  format       tar+gzip
  stabilizers  tar-gzip (4598411b636d…)

               upstream           rebuild
  raw          aff3730d91b7…      c38236deb36f…      ≠
  container    fa8a7ca19526…      ad6fa9a8d33f…      ≠
  stabilized   441b279b8b59…      441b279b8b59…      =

  applied
    gzip-meta-v2             metadata        1 entries
    tar-entry-order-v2       structural      4 entries
    tar-mode                 metadata        4 entries
    tar-owners               metadata        4 entries
    tar-time                 metadata        4 entries

  members  4 identical, 0 differ, 0 upstream-only, 0 rebuild-only
```

In this output the raw files differ (`≠`), and after stabilizing they are identical (`=`). The
`applied` list shows why: the stabilizers changed the gzip header, the order of files in the
tarball, and their modes, owners and timestamps, but nothing inside any file. Read that list for
the detail behind the verdict: each stabilizer that fired, how risky it is, and how many files it
touched. The exit code is 1 for `divergent` and 0 otherwise, so it drops into a script.

### 2. Rebuild a package from its source

Build the two helper images once, one to build in and one to run the mirror:

```
trigon base-image --from docker.io/library/debian:bookworm-slim
trigon mirror-image
```

Then rebuild, behind the mirror, pinned to the moment the package was published:

```
trigon rebuild pkg:npm/wrappy@1.0.2 --image auto --egress mirror-only --timewarp auto \
    --work ./work --store ./store
```

It prints each step (where the source is, which recipe it chose, what the mirror served) and ends
with the same verdict as `trigon verify`. `--store` keeps the run so you can sign it:

```
trigon keygen --out signing.key
trigon runs --store ./store                                  # the run's id is first on its line
trigon attest <run-id> --store ./store --key signing.key
```

### 3. Check your dependencies against published evidence

Point Trigon at an evidence repository you trust (an HTTPS or SSH git URL, or a local path), with
the two public keys its README lists:

```
trigon evidence add example https://github.com/<owner>/trigon-evidence.git \
    --log-key '<the log key>' --attestation-key <the attestation key>
trigon evidence sync
trigon check package-lock.json            # or requirements.txt, or an SPDX SBOM
trigon lookup pkg:npm/wrappy@1.0.2        # one package, with every detail of its record
```

`check` lists every package with its answer. A package nobody has checked shows **never checked**,
which does not count as a pass. The exit code is designed for CI: `0` everything passed, `1` a
divergence, `2` something never checked or withdrawn, `3` a void or a result below your `--min`,
`4` a record that failed verification or a source that could not answer, `5` Trigon itself failed.

### Try the whole loop

`scripts/evidence-e2e.sh` runs the whole loop on one machine in a few minutes, for the package you
name. It creates keys and a local evidence repository, rebuilds the package behind the mirror,
confirms it with a second cold build, publishes the verdict, then checks it the way a consumer
would, including two checks that must fail. It keeps everything it makes in `work/evidence-e2e/`
for you to look through. The package has no default. `pkg:npm/wrappy@1.0.2` is small and
reproduces behind the mirror, so start with that.

```
cargo build -p trigon && scripts/evidence-e2e.sh pkg:npm/wrappy@1.0.2
```

---

## Words you will meet

| word | meaning |
|---|---|
| **artifact** | the file a registry serves: a tarball, wheel, crate, nupkg |
| **purl** | a package's address, such as `pkg:npm/wrappy@1.0.2` or `pkg:pypi/requests@2.31.0` |
| **strategy** | the recipe for building an artifact from its source; data, not a script |
| **egress tier** | what a build may reach: `open` (anything), `mirror-only` (only the mirror), `deny-all` (nothing) |
| **timewarp** | pinning the mirror to the instant the package was published |
| **stabilizer** / **set** | one transform that removes one kind of harmless difference / the named, digested collection used for a comparison |
| **run** | one rebuild of one package, recorded with everything needed to replay it |
| **attestation** | a signed statement of a run's verdict (in-toto, DSSE) |
| **evidence repository** | a git repository of published records and the signed log that makes them tamper-evident |
| **void** | a run that proves nothing, and says why |

The full glossary is in [`00-overview.md`](00-overview.md) §6.

---

## What to read next

- **To use it day to day:** [`using-trigon.md`](using-trigon.md), which covers every task with
  real output and has the section *What a verdict does not tell you*.
- **To trust (or doubt) a verdict:** [`threat-model.md`](threat-model.md), on what Trigon assumes,
  guarantees and disclaims.
- **To publish verdicts or consume them:**
  [`19-distribution-and-lookup.md`](19-distribution-and-lookup.md).
- **To understand the design:** [`00-overview.md`](00-overview.md), then
  [`01-architecture.md`](01-architecture.md) and
  [`05-archive-and-normalization.md`](05-archive-and-normalization.md).
- **To see where the design was wrong:** [`16-findings.md`](16-findings.md).
