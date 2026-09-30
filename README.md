# Trigon

**Semantic rebuild verification for open-source packages.**

Trigon takes a published package artifact, finds the source it claims to come from, rebuilds it in a
controlled environment, and decides whether the rebuild and the published artifact are the same
thing. It signs a statement either way, and someone who does not trust us can check that statement.

Registries distribute artifacts and people audit source, but almost nothing checks that the two
correspond, and build-time supply-chain attacks live in that gap.

**Today it rebuilds npm, PyPI, crates.io and NuGet packages.** RubyGems and GitHub releases are
designed for and sequenced next; Trigon refuses a target in either by name and does not attempt it.
Comparing two artifacts you already have (the judgement half, below) needs no network and has no
prerequisites. Wheels, gems, crates and `.nupkg` files each get their own normalization. An npm
tarball does not, because nothing inside a `.tgz` says whose it is. It takes the generic tar+gzip
set unless you run `verify` or `stabilize` with `--profile npm-tarball`, so the left-pad run below
reports `tar-gzip`.

**If you are new,** start with [`docs/introduction.md`](docs/introduction.md), which explains what
Trigon is, how it works and how to use it, in ten minutes.
`scripts/evidence-e2e.sh pkg:npm/wrappy@1.0.2` runs the whole loop on one machine for the package
you name: rebuild it, publish the verdict, and check it as a consumer would.

**If you are using it,** [`docs/using-trigon.md`](docs/using-trigon.md) is the task-oriented guide:
install, compare two artifacts, rebuild a package, read a verdict, and what a verdict does *not*
tell you, the section worth reading first.

## What it does

```
$ trigon verify left-pad-1.3.0.tgz rebuilt/left-pad-1.3.0.tgz
✔ normalized

  format       tar+gzip
  stabilizers  tar-gzip (4598411b636d…)

               upstream           rebuild
  raw          870c0fe10962…      55b10c02dc3c…      ≠
  container    2bc27360d33b…      39d388af65d0…      ≠
  stabilized   f0a01941419d…      f0a01941419d…      =

  containers differ as well as the framing

  applied
    gzip-meta-v2             metadata        1 entries
    tar-entry-order-v2       structural     10 entries
    tar-mode                 metadata       10 entries
    tar-time                 metadata       10 entries

  members  10 identical, 0 differ, 0 upstream-only, 0 rebuild-only
```

npm published that tarball in 2018; the rebuild is from this morning. They differ in gzip framing,
member order and file modes, and the `applied` list names the stabilizer that removed each
difference and how many entries it touched. The shared `stabilized` digest says they differ in
nothing else. Change one byte of `index.js` and the verdict is `divergent`, the output names the
member, and the exit code is 1.

Each side gets three digests because "the same tar in different gzip framing" and "a different tar"
are different findings, and a single digest cannot tell you which you have.

## How it works

The diagram follows one rebuild, end to end. The boxes are four of the five persisted states (the
fifth, `Queued`, belongs to the sweep planner, and a single `trigon rebuild` never sits in it), and
the labels on the arrows between them are the only things that cross.

```mermaid
flowchart TB
    target(["pkg:npm/left-pad@1.3.0"])

    subgraph inferring["Inferring — may use the network and a model, holds no build rights"]
        direction TB
        resolve["Resolve<br/>registry metadata → artifact URL,<br/>digest, declared repo, publish instant"]
        decompose["Decompose<br/>fetch the published artifact,<br/>enumerate its members"]
        locate["LocateSource<br/>provenance → tag ladder →<br/>tree hash → model"]
        strategy["InferStrategy<br/>definitions → ecosystem heuristic<br/>→ model, where one is named"]
        materialize["Materialize<br/>git fetch at the pinned commit"]
        resolve --> decompose --> locate --> strategy --> materialize
    end

    subgraph building["Building — egress-restricted, write-only blob access"]
        direction TB
        run["Build<br/>container, under a declared egress tier"]
        mirror[("trigon-mirror<br/>the registry index as it stood<br/>at the publish instant")]
        extract["Extract<br/>find the artifact it produced"]
        run -->|"every fetch, hashed and transcribed"| mirror
        run --> extract
    end

    subgraph judging["Judging — links no async runtime, no network client, no model"]
        direction TB
        stabilize["Stabilize<br/>normalize both sides identically"]
        compare["Compare<br/>one pass, six digests,<br/>structured notes"]
        stabilize --> compare
    end

    subgraph done["Done — a separate process, and the only one holding the signing key"]
        direction TB
        attest["Attest<br/>in-toto statement, DSSE"]
        publish["Publish<br/>store; an evidence repository"]
        attest --> publish
    end

    target --> resolve
    materialize -->|"strategy as data · pinned source ·<br/>guard manifest: digests, never bytes"| run
    decompose -->|"the published artifact"| stabilize
    extract -->|"the rebuilt artifact"| stabilize
    compare -->|"exact · normalized · normalized-with-caveats · divergent"| attest
    decompose -. "never: a build must not reach the artifact<br/>it is going to be compared against" .-> run
```

Two edges in that picture are easy to lose in implementation.

**The dashed one never happens.** Judging reads both sides, so a build must have no route to the
published artifact, including through our own content-addressed store, whose digest travels with
every target and whose reads would never cross the egress proxy. Today `Decompose` enforces that by
handing forward a set of hashes rather than bytes: the guard manifest names what the build must not
produce and carries none of it. The fleet shape adds a second rule, a write-only blob credential
scoped to the one run, which [`01-architecture.md`](docs/01-architecture.md) §1 specifies and no
code enforces yet.

**The mirror is the build's only route out.** At `--egress mirror-only` the container sits in a
network island whose one reachable host serves the registry index *as it stood at the publish
instant*, so a dependency resolved during the rebuild is the one the publisher would have got, not
today's. The mirror hashes everything it serves on the way past and writes it to a transcript the
run keeps.

The design puts a fifth step, `Explain`, inside Judging, to describe a difference in words. It is
not built: `Phase` has no such variant, and the existing `--explain` flag only raises a print limit;
it opens no socket and calls no model. `Explain` will be advisory when it arrives and unable to
change a verdict, because the verdict is the digest comparison and that half links nothing.

**The four boxes are states, and the deployment decides which process runs each.** On a fleet they
run as separate workers with different credentials, which is why the diagram draws them apart. On a
laptop `trigon rebuild` runs the first three in one process and `trigon attest` is the second
command in [`scripts/rebuild-and-attest.sh`](scripts/rebuild-and-attest.sh). They are separate
commands on purpose, so the process holding the key re-derives the verdict from stored bytes instead
of taking it from the process that executed a package's build script.

## Status

M0, M1 and M2 are complete, and M3 has begun. The design in [`docs/`](docs/) predates the code;
[`docs/16-findings.md`](docs/16-findings.md) records where building it proved the design wrong.

| Milestone | | |
|---|---|---|
| **M0** the judgement half | done | differential against the reference implementation: 34 match, 24 deviate by a declared entry, **0 unexplained** |
| **M1** first rebuilds | done | npm and PyPI rebuild end to end, under an enforced egress tier, against a time-filtered index |
| **M2** attestations | done | signed statements, re-derivable cross-machine and through an archived stabilizer set run under `wasmtime`. Publishing them is [`docs/19`](docs/19-distribution-and-lookup.md): an evidence repository with a log of our own, written by `trigon publish`, synced by `trigon evidence`, and queried by `trigon lookup` and `trigon check`. It replaced a Rekor client we built, measured and removed ([ADR-0014](docs/adr/0014-git-evidence-store-without-rekor.md)) |
| **M3** the search half | begun | the deterministic parts first: failure signatures, log compression, the repair-loop policy, the Builder |

Tier-1 observability landed early, out of milestone order: every run at an enforced egress tier now
records a **network transcript** of everything that crossed into the build, and Trigon derives
`attestable` from whether that account is complete; it used to be a constant. The mirror had been
computing all of it (it hashes every body as it streams past, which is how the artifact guard works)
and discarding it unless the hash matched.

The figures below come from the **M1 common-path corpus** (197 npm and 200 PyPI targets, stratified
by build system rather than by popularity) at `--egress mirror-only`, the tier this README
recommends, where the build's only route out is a time-filtered mirror that writes down everything
it serves:

| | reproduce | reach a comparison |
|---|---|---|
| npm | **100 of 132 (76%)** | 132 of 197 (67%) |
| PyPI | **136 of 163 (83%)** | 163 of 200 (81%) |

**crates.io and NuGet have no rate here, because they have no corpus yet.** Both rebuild end to end
at `mirror-only`, but neither has a stratified corpus, and a number quoted over targets picked by
hand is not a rate. Of the twelve crates we have tried, six reproduce (`hashbrown@0.17.1` and
`serde@1.0.219` among them, lockfile included), and each remaining divergence is the `Cargo.toml`
manifest rewrite that [`17-backlog.md`](docs/17-backlog.md) B20 is about.

The npm row folds in a six-target re-run rather than a second full sweep. npm 7.0 through 8.2
corrupts the tarballs it fetches concurrently; for months that looked like a broken mirror, which it
was not. It failed the six targets that pin an npm in that window and no others. We re-ran those six
after the fix, and no other target in the corpus pins one, so nothing else could have moved.
[`16-findings.md`](docs/16-findings.md) §3.26 has the evidence.

**Quote the strata.** Both totals above hide a range wide enough to make them useless on their own,
which is the argument of [`15-corpora.md`](docs/15-corpora.md) §3:

| npm | compared | reproduced | | PyPI | compared | reproduced | |
|---|---:|---:|---|---|---:|---:|---|
| no lifecycle script | 74 of 90 | 65 | 88% | flit / hatchling | 47 of 50 | 47 | **100%** |
| `prepare`/`prepack` | 32 of 60 | 24 | 75% | setuptools + pyproject | 49 of 60 | 40 | 81% |
| TypeScript build | 23 of 30 | 10 | 43% | setuptools + `setup.py` | 30 of 40 | 18 | 60% |
| monorepo member | 3 of 17 | 1 | **33%** | poetry-core | 26 of 30 | 25 | 96% |
| | | | | maturin / C extension | 11 of 20 | 6 | **54%** |

npm's aggregate 76% spans 88% down to 33%; PyPI's 83% spans 100% down to 54%. **The reach is still
the worse number**: only 3 of 17 monorepo members get as far as a comparison, so the 33% beside them
is one of the three we could measure.

Every earlier figure came from the 37-target smoke corpora, which are almost all one stratum (small
utility packages with no build step), where npm reproduces at 89% and PyPI at 88%. The common-path
corpus is harder: it adds TypeScript builds, monorepo members, poetry projects and native
extensions, and exists to make the table above possible.

**Both ecosystems moved since the previous figures, and PyPI's rate fell because its reach rose.**
npm was 84 of 115 (73%) reaching 115 of 197; PyPI was 119 of 136 (88%) reaching 136 of 200. npm
improved on both axes: the mirror now serves a lockfile-resolved tarball the index never offered,
which admitted a cluster that could not build before. Most of that cluster is TypeScript, and the
TypeScript stratum went from 1 of 8 to 10 of 23. PyPI's *reach* rose from 68% to 81% and its *rate*
fell from 88% to 83% as a consequence: the twenty-seven more targets that now reach a comparison are
the hard ones, and adding them to the denominator lowered the rate and made it a better measure.

**Sixteen of npm's 65 non-compared targets are our fault:** ten a missing tool (3 × npx, 3 × pnpm,
3 × yarn, 1 × just), five a `workspace:` protocol npm does not speak, and one a workspace sibling
the recipe did not build first. A further fifteen are `Fault::Policy`: the enforced tier doing what
it was asked, most of them a host the build may not reach. Nineteen are the package's own build,
eleven produced no strategy, and four are upstream's.

The reproduction rate leaves those first sixteen out by design, since only `Fault::Build` says
anything about the package ([`02-domain-model.md`](docs/02-domain-model.md) §4). They are inside the
*reach* figure, so read that figure as a floor.

The six that showed up as a mirror handing the build a body it could not read are gone from this
list: npm was corrupting its own concurrent fetches, and those targets now reach a comparison. We
have fixed the three npx failures since the sweep, but they still count above because we have not
re-run them.

Most targets that fail to reach a comparison fail for a known reason: a base image missing a tool, a
package whose install fetches from a forge, a monorepo member we build outside its workspace.
[`16-findings.md`](docs/16-findings.md) §3.25 has the breakdown and the cost of each.

PyPI was 5 of 15 that morning. Three deterministic fixes produced the lift, with no model involved;
[`docs/16-findings.md`](docs/16-findings.md) §2 has the arithmetic.

## Verify a package end to end

Both examples below rebuild a real target, start to finish; both need `podman` and take a few
minutes each, most of it spent pulling the base image the first time.

### An npm package

```
$ trigon rebuild pkg:npm/left-pad@1.3.0 \
      --image docker.io/library/debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 \
      --work ./work --egress open --timewarp auto

  artifact   left-pad-1.3.0.tgz
  published  sha256 870c0fe1096223a5
  guarding   the artifact and 0 of its members (10 too small, too common, or also in the source)
  source     https://github.com/stevemao/left-pad @ ff8e7ba8b41228…
  strategy   Heuristic, commit found by RegistryCommit, confidence Certain

  mirror     69 index request(s), 1044 version(s) withheld across them

✔ normalized

  format       tar+gzip
  stabilizers  tar-gzip (4598411b636d…)

               upstream           rebuild
  raw          870c0fe10962…      0ebf94afb7c6…      ≠
  container    2bc27360d33b…      b7142014cce1…      ≠
  stabilized   f0a01941419d…      f0a01941419d…      =

  members  10 identical, 0 differ, 0 upstream-only, 0 rebuild-only
```

The verdict is `normalized` rather than `exact` because the two tarballs differ in mtimes, file
modes and member order, all of which the stabilizers remove, and in nothing else.

The `rebuild` raw digest differs from the one in the first example. That was a different run at a
different egress tier, and a fresh `npm pack` does not produce the same bytes twice. The
**stabilized** digest is `f0a01941419d…` in both, so the verdict does not depend on which run
rebuilt the package.

The `mirror` line is the evidence that the build saw the dependency index as it stood on the publish
date. The count covers all 69 packuments the build fetched, not only left-pad's: left-pad has
published nothing since 2018, so the mirror withheld none of its fifteen versions. The thousand-odd
come from its devDependency tree, where `fast-check` accounts for 198 versions that did not exist in
April 2018, `core-js` for 180 and `glob` for 73.

### A PyPI package

```
$ trigon rebuild pkg:pypi/chardet@7.6.0 \
      --image docker.io/library/python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b \
      --work ./work-py --egress open --timewarp auto

  mirror     10 index request(s), 12 version(s) withheld across them

✔ exact

  format       zip
  stabilizers  wheel (738725964c4a…)

               upstream           rebuild
  raw          4076d795897c…      4076d795897c…      =
  stabilized   aafb77c84b42…      aafb77c84b42…      =

  members  41 identical, 0 differ, 0 upstream-only, 0 rebuild-only
```

`exact` is the strongest outcome: the rebuilt wheel is byte-for-byte the published one, before any
stabilizer ran.

### Signing it, and checking the signature

`--store` records the run so a **separate process** can sign it. The process that ran the build
could record any outcome it liked, so the attestor re-derives the claim from the artifact bytes
before it signs anything.

```
$ trigon keygen --out key.bin                # 0600, and refuses to overwrite an existing key
$ trigon rebuild pkg:pypi/chardet@7.6.0 --image <as above> --work ./work-py \
      --egress open --timewarp auto --store ./store
$ trigon runs --store ./store
1789215251-4076d795  pkg:pypi/chardet@7.6.0    exact    unattested

$ trigon attest --store ./store --key key.bin
target    pkg:pypi/chardet@7.6.0
rederived exact under wheel@738725964c4a — signing

  attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/1789215251-4076d795/equivalence.intoto.json
  attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/1789215251-4076d795/rebuild.intoto.json
  attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/1789215251-4076d795/buildobservation.intoto.json

signed with key 8238c7031caabae5
```

`rederived exact … — signing` means the attestor did not take the run record's word for the outcome:
it fetched both artifacts from the store **by hash**, checked each against the hash it asked for,
recomputed the comparison, and would have refused to sign had the answer differed. `trigon attest`
files the statements under the run's id, so signing another run of the same package, or this run
again, adds statements beside these and never replaces them.

**That transcript is from before 2026-09-27, and `trigon attest` signs this run differently today.**
It ran at `--egress open`, where nothing the build produced is evidence about the package, and the
publication gate calls such a run void. `trigon attest` now signs a void run only as `void/v1` (the
reason, the facts that establish it, and no verdict), so attesting this run today prints
`void      open_egress: …` and files `void.intoto.json`. It signs a run at `--egress mirror-only` or
`deny-all` as `equivalence/v2` or `divergence/v2`, which carry everything a published record needs
([`docs/09`](docs/09-attestations.md) §2.5). The `equivalence/v1` statement written then still
verifies as shown below.

Anyone holding the two artifacts can now check that claim without trusting us and without a network:

```
$ trigon verify-attestation \
      ./store/attestations/pypi/chardet/7.6.0/chardet-7.6.0-py3-none-any.whl/1789215251-4076d795/equivalence.intoto.json \
      --rerun-comparison \
      --upstream ./work-py/chardet-7.6.0-py3-none-any.whl \
      --rebuild ./work-py/rebuild/*/chardet-7.6.0-py3-none-any.whl \
      --public-key "$(trigon public-key key.bin)"

subject   chardet-7.6.0-py3-none-any.whl (4076d795897ce45239825956a1334e134322ecc4bfe84dbb12acd5390de0fbc1)
predicate https://trigon.dev/equivalence/v1
claims    exact
signature verified
rederived exact under wheel@738725964c4a — the claim holds
```

Drop `--public-key` and it still re-derives, reporting only that the signature was present and
unchecked, because "unsigned" and "signed by someone you do not trust" are different answers. Edit
the payload and the signature fails. Edit the claimed outcome and **the bytes refute it even with no
key**; an attestation from a rebuilder is worth something only because of that property.

### Publishing it

Signing is local: `trigon attest` writes into the store and opens no socket. Publishing is a
separate step, `trigon publish`, which asks the publication gate about each run and writes what it
allows to a git repository holding the signed records, the evidence to re-derive each one, and an
append-only log we sign. Each publication is one commit, pushed without force, with its checkpoint
signed by `trigon log sign`, the only thing that holds the log's key
([`docs/using-trigon.md`](docs/using-trigon.md)). Rotating either key is also a leaf of that log,
which every client follows (`trigon log key-change`, `trigon log succeed`).
[`docs/19`](docs/19-distribution-and-lookup.md) is the design and its build plan, and
[ADR-0014](docs/adr/0014-git-evidence-store-without-rekor.md) records why it replaced the Rekor
client this README used to describe.

### Checking a lockfile against it

As a consumer, you trust a repository once, and Trigon answers every lockfile after that from a
clone you verified yourself. That takes one sync, then no request per package, and nothing learns
which packages you asked about:

```
$ trigon evidence add trigon https://github.com/owner/trigon-evidence.git \
      --log-key 'github.com/owner/trigon-evidence+1a2b3c4d+AR…' --attestation-key <64 hex>
$ trigon check package-lock.json          # every package, by the integrity digest it pins
$ trigon lookup ./left-pad-1.3.0.tgz      # one artifact: every record, and how to falsify it
```

Each source you trust answers for itself, the output says when sources disagree, and a package no
source holds a record for reads *never checked*, never as a pass. The exit codes are for CI: `1` for
a divergence, `2` never checked, `4` anything that failed verification.
[`docs/using-trigon.md`](docs/using-trigon.md) has the rest, `--remote` and the falsifying command
among it; `trigon check --store <path>` is the old check against a store of your own runs.

A signature says *who* signed but not *when*. A statement carries no third-party time, so nothing
bounds what a stolen key can sign ([threat model](docs/threat-model.md) D24), and publishing will
not change that until docs/19 D6 is decided. Keep the key where [`docs/12`](docs/12-security.md) §9
puts it: never in a worker that has executed a build.

### Comparing two files you already have

You need no registry, container or network:

```
$ trigon verify upstream.tgz rebuild.tgz
```

That comparison is the whole judgement half.

### A note on `--egress open`

`open` lets the build reach the internet, which is the quick way to try this. It is also the weaker
claim, and the attestation says so with `attestable: false`, because a run with no enforced mirror
cannot show the build fetched nothing it should not have. `--egress mirror-only` puts the build on a
network whose only route out is the time-filtered mirror, and you need to build that mirror's image
first:

```
$ trigon mirror-image          # compiles trigon in a container; several minutes
$ trigon base-image --from <a pinned image>     # the packages an enforced tier cannot install
$ trigon rebuild pkg:npm/left-pad@1.3.0 --image <the base image's id> --work ./work \
      --egress mirror-only --timewarp auto --store ./store --verbose

  network   141 responses crossed into the build, 0 opened and checked
            ./work/rebuild/network.jsonl

  mirror     69 index request(s), 1044 version(s) withheld across them
             1 toolchain download(s) through the allowlist

✔ normalized
…
  cost       21.2s building, 21.4 MB fetched, 66.1 KB stored
```

**That `network` line is what `attestable: true` means, and it is the only difference from
`attestable: false`.** The mirror is the build's only route out, and it writes down every response
body it serves: the route, the URL, the SHA-256 of the bytes as served, the byte count, and how far
the artifact guard got with each one. `network.jsonl` is that list, one JSON object per line, and
the signed `buildobservation/v1` names it by hash, so a reader fetches those bytes, checks them
against the hash, and reads what the build downloaded without taking our word that we looked.

```json
{"route":"toolchain","url":"https://nodejs.org/dist/v9.2.1/node-v9.2.1-linux-x64.tar.gz",
 "sha256":"b8507b17277b1582…","bytes":17823914,"checked":"hashed"}
{"route":"index","url":"https://registry.npmjs.org/benchmark",
 "sha256":"6d08de7ac3190fb9…","bytes":46606,"checked":"generated","withheld":0}
```

The `checked` field records how far the guard got: `opened` means the guard compared every member
against the run's manifest, `hashed` means it compared only the whole body, and `partial` means the
build hung up before the body finished. Without the field, "opened and clean" and "never opened"
would read the same, and a reader could not tell whether the guard had checked anything.

`deny-all` is attestable too, and its account is complete and *empty*: with `--network none` on both
the image build and the run there is no interface, so the kernel enforces "nothing crossed" rather
than a proxy observing it. Trigon keeps present-and-empty and absent apart at every layer (an empty
blob, no blob, and `attestable` derived from which), because collapsing them would turn "we never
looked" into "we looked and it was clean".

`attestable` does *not* assert that the sandbox class, the base image or the strategy are good
enough to sign; those are separate claims. Reading `attestable` as "full trust" credits it with a
success it has not earned.

Both images are built from this workspace, so the mirror goes stale when the mirror code changes.
`rebuild` compares the two and says so before the build starts rather than after it fails inside the
island.

At this tier **no phase reaches the network.** The image build runs with `--network none`, so it
cannot clone the source; Trigon fetches it on the host at the pinned commit and copies it in, and
the checkout step becomes the check that the copy landed on the right commit. The deps phase runs
inside the island and reaches the mirror; the toolchain comes through the mirror's `/-toolchain/`
route and dependencies through `/-artifact/`. Both routes are compiled-in exact-match allowlists
that refuse everything else.

With no network there is also no `apt-get`, so the setup phase stops installing and starts checking:
it reads the package manager's own database, names anything the base image is missing, and prints
the `trigon base-image` line that fixes it.

The tier does **not** bound what the allowed hosts serve: the allowlists bound which hosts the
mirror will fetch from, and `registry.npmjs.org` serves whatever anybody published. The artifact
guard is the control for that. Nor does the tier cover the source, which Trigon fetches on the host,
outside the boundary, where only the checkout's own rules bound it: https only, a full commit id
only, no ambient git configuration, no credential helper, and a tree that is read and copied but
never executed.

### Asking a model

Model use is off unless you name a provider. The ladder tries a checked-in definition, then the
ecosystem heuristic, and last, if `--model` says so, asks a model for a strategy. The model rung
answers for npm and PyPI only: on a crates.io or NuGet target `--model` adds no rung, though it
still drives the repair loop below.

```
$ trigon rebuild pkg:npm/some-package@1.0.0 --model ollama:qwen2.5:0.5b …
$ trigon rebuild …  --model anthropic:claude-opus-5      # $ANTHROPIC_API_KEY
$ trigon rebuild …  --model openai:gpt-5                 # $OPENAI_API_KEY
$ trigon rebuild …  --model openrouter:<model>           # $OPENROUTER_API_KEY
$ trigon rebuild …  --model copilot:auto                 # the Copilot CLI, signed in
$ trigon rebuild …  --model compatible:http://host/v1#m  # vLLM, llama.cpp, a gateway
$ trigon rebuild …  --model replay:run.transcript.json   # a recording; opens no socket
```

Trigon reads keys from the environment, never the command line. A model rung needs the repository,
so it fetches the pinned commit to a local cache first; it declines where there is no source, no
commit, or an answer that will not parse, and the ladder moves on.

If a build fails, or succeeds and produces something that is not the published artifact, Trigon
sends the recipe, the failure and the compressed log back to the model for another attempt. The loop
is bounded: six iterations, a token budget, a wall clock, and a stop as soon as two attempts fail
the same way.

Trigon records a model-derived recipe as `derivation: model_assisted` **beside** the claim, never
inside it, so a consumer can filter on "no model touched this". It does not change the match
outcome: the provenance cap is about *stabilizers*, and a model-authored stabilizer can reach
`normalized_with_caveats` at best. The artifact guard still applies to a model-written recipe: a
build that downloads its own published output is `Void` however it was derived.

`copilot` is an agent with a shell on your machine; Trigon configures it so the model sees no tools.
Read the module documentation in `trigon-ai/src/copilot.rs` before using it.

The artifact guard runs either way. If the package's own published bytes, or any of its member
files, arrive over the network, the run is `Void`, which is neither a pass nor a failure: a build
that downloads its own output reproduces it without proving anything.

## Watching a sweep, or reading the runs you already have

`trigon sweep` prints its summary once, at the end, into the terminal that launched it.
`trigon watch` reads the same work directory from somewhere else, while the sweep is still running:

```
$ trigon sweep corpora/m1-npm-smoke.txt --image <digest> --work ./sweeps/npm …
$ trigon watch ./sweeps/npm --targets corpora/m1-npm-smoke.txt     # in another terminal
watching on http://127.0.0.1:8099  (read-only; ctrl-c to stop)
```

It serves the board (the two rates with their denominators printed, and the failure clusters ranked
by size), a cluster page that says whether forty red rows are one problem or three, and a run page
with the log and what the ladder decided.

`trigon watch` never talks to the sweep. It reads the files the sweep already writes, so it survives
the sweep's death: every completed result stays on the page, the page labels the silence with its
age, and it reports the target that was in flight as unknown rather than converting it into a
failure. It has no write path, and a cluster hands you the `trigon rebuild` line to paste.

Point it at a directory of runs and it reads that instead, one row per rebuild, with the verdict,
the commit it was built from, when, and what it cost:

```
$ trigon watch ./work                                              # no sweep anywhere
```

```
a directory of runs · 24 rebuild(s), each in a work directory of its own
1 of them left no run.json: the rebuild is still going, or it ended before it could
write one. This page cannot say what those found.
not a sweep: nothing here was launched by one process, so there is no corpus to be a
fraction of, no progress, and no sweep to be alive or dead

 target                       outcome      built from                                when      cost
 npm/once@1.4.0               normalized   isaacs/once @ 0e614d9f                    61m ago   30s · 31.3 MB
                                           registry_commit
 npm/semver@3.0.1             no-strategy  no source resolved: nothing here was      30h ago   1s
                                           compared against a commit
 nuget/Newtonsoft.Json@11.0.1 divergent    JamesNK/Newtonsoft.Json @ d50b912e        33h ago   310s · 91.8 MB
                                           Src/Newtonsoft.Json  exact_tag

 18 reproduced  1 divergent  0 build failed  1 no strategy  4 ours  0 void
```

This view shows counts and no rate, because a directory you filled by hand has no corpus for a
percentage to be of. The run page opens with one sentence saying what happened (the error, the
void, or *why each rung declined*) before any panel.

It binds to loopback by default, because a work directory holds artifacts fetched from registries
and build logs that may carry credentials. [`docs/18`](docs/18-management-ui.md) has the plan it is
being built to.

## The two halves

The system rests on one idea: **rebuild verification is a search problem wrapped in an equivalence
problem.** A model helps with search, and Trigon never trusts one with equivalence.

```
                         trigon-core
                    /              \
      trigon-archive            trigon-strategy
             |
      trigon-stabilize
             |
      trigon-compare
             |
      trigon-attest        (core, archive, compare and stabilize — all four)
              \____________ _______ ___________/
   ================= JUDGEMENT / SEARCH LINE =================
   trigon-registry  trigon-ai  trigon-sandbox ──▶ trigon-mirror
                    trigon-store ──▶ trigon-attest, trigon-stabilize
                             |
                        trigon (bin)
```

Everything above the line is synchronous, declares no cargo features, and cannot reach `tokio`,
`reqwest` or `trigon-ai`. Everything below it is budgeted and replayable. The policy forbids
`trigon-ai` from naming `trigon-compare`, `trigon-stabilize` or `trigon-archive`, which is the
invariant read from the other side, because a crate that cannot name a function cannot call it.

`cargo run -p xtask -- policy` enforces all of it and fails the build on a violation. A sceptic can
check the claim without reading any of this by running `cargo tree` on the verifier build.

## Layout

```
crates/trigon-core        digests, paths, formats, outcomes, risk tiers, evidence,
                          failure signatures, log compression, RFC 8785 canonicalization
crates/trigon-archive     the mutable archive model; hand-written tar, zip and gzip writers
crates/trigon-stabilize   the stabilizer catalogue and its profiles
crates/trigon-compare     one pass, six digests, the provenance cap, the difference signature
crates/trigon-strategy    the strategy schema, the flow DSL, the tool registry, rendering
crates/trigon-attest      in-toto statements, DSSE, signing, re-derivation
crates/trigon-registry    registry clients, source discovery, strategy inference
crates/trigon-sandbox     the build runner, egress islands, isolation
crates/trigon-mirror      the time-filtered index, the artifact guard and the fetch cache
crates/trigon-politeness  what we ask of an upstream host, and how fast: one limiter, one counter
crates/trigon-store       content-addressed blobs and run records
crates/trigon-ai          the provider seam, the Builder, budgets and admission control
crates/trigon-stabilize-wasm  a stabilizer set archived as a WebAssembly module, and its host
crates/trigon             the binary
xtask                     dependency policy, corpora, golden digests, the differential
docs/                     the design, and what implementing it changed
corpora/                  frozen corpora and declared deviations (manifests only)
scripts/                  the cross-machine verification check
```

## Build and check

```
rustup target add wasm32-unknown-unknown    # once: the stabilizer-set module's target
scripts/build-set-module.sh                 # the module the parity and publish tests run
cargo test --workspace                      # 939 pass, 0 fail
TRIGON_LIVE=1 cargo test --workspace        # plus the ones that need a network
cargo run -p xtask -- policy                # the dependency policy
cargo run -p xtask -- differential          # against the reference implementation
scripts/cross-machine-verify.sh             # the claim a third party can check

# Coverage. The leading slash matters: `tests?/` without it silently excludes the
# whole of trigon-attest, because `attest/` contains `test/`.
cargo llvm-cov --workspace --no-fail-fast --summary-only \
  --ignore-filename-regex '(/tests?/|/xtask/)'

# The archived stabilizer set's parity tests on their own. `cargo test --workspace` runs
# them through the `wasm` feature and fails without the module built first. Tested alone,
# the crate needs `--features host`: without it the parity tests compile to nothing and
# the run still exits 0, so CI greps for the two test names rather than trusting the
# exit code.
scripts/build-set-module.sh
cargo test  -p trigon-stabilize-wasm --features host
```

The judgement half (`core`, `archive`, `stabilize`, `compare`, `attest`) is at **88.4% of lines**;
the workspace is at 69.0%, or 71.4% with `TRIGON_LIVE=1` set so the tests that need a network run.
The split is on purpose: the judgement half is what the verifier binary contains, what a third party
re-derives a verdict with, and the only part whose bugs are silent. A divergence is self-consistent,
so both sides get the same wrong treatment and the failure surfaces as a wrong verdict rather than a
crash.

**The judgement half is the one number that does not move between those two runs.** It is 88.4%
either way: every covered line in that half is covered by a test that opens no socket, which is the
architecture's central claim, measured.

Building Trigon needs Rust 1.85 or later, edition 2024. Rebuilds also need `podman`. Nothing else
has prerequisites, `trigon verify` included.

## Reading the design

Start with [`docs/00-overview.md`](docs/00-overview.md) for the thesis, then
[`docs/05-archive-and-normalization.md`](docs/05-archive-and-normalization.md) for the hard part,
then [`docs/12-security.md`](docs/12-security.md) for the attack that shapes the rest of the design.
[`docs/16-findings.md`](docs/16-findings.md) measures what the design got wrong.

## License

Apache-2.0.

---

## Running a fleet

A fleet runs on four commands that compose. The queue is SQLite on a laptop and Postgres in a cloud;
the same statements serve both, and the URL decides which one you get.

```console
$ trigon enqueue sqlite://queue.db pkg:npm/left-pad@1.3.0 --migrate
offered 1 target(s) to the bulk queue
  ready    1

$ trigon worker sqlite://queue.db --image auto --work ./work --store ./store
worker host-4821 on sqlite://queue.db, building with auto at egress mirror-only
```

A job goes to exactly one worker. A worker that dies releases its job by itself: the lease is a
timestamp, not a lock, so nothing has to observe the death. The run and the acknowledgement land in
one transaction, so nothing is built twice.

**A verdict enqueues a second, independent attempt**, and publication depends on it:
[`ADR-0010`](docs/adr/0010-publish-divergences.md)'s first safeguard is two agreeing attempts, for
divergences and matches alike, because a single attempt cannot show that its recipe is
deterministic.

Then serve it:

```console
$ trigon serve ./store --public --queue sqlite://queue.db
serving 2 run(s) on http://127.0.0.1:8100  (public: an unauthenticated reader sees only what the
publication gate released, and no unredacted bytes)
```

A run's page renders the comparison: the reason for the verdict (the three questions, with the one
that answered marked), what differs, what the package holds, the stabilizer ledger with each pass's
risk and provenance, and every member with what differed about it (the file's own bytes, or only its
archive entry). The raw blobs are still there underneath, because a reader wants a page and a third
party re-derives a verdict from the bytes.

Click a member that differs and it opens: a line diff where the bytes are text, a hex diff centred
on the differing runs where they are not, and a download for each copy. Binaries open as hex, and
the page tells a binary from its bytes rather than its filename. On `Newtonsoft.Json@11.0.1` that is
how you find out the rebuild drops `<owners>` from the `.nuspec` and that the DLLs differ at offset
0x88, the PE timestamp.

`--public` turns on two controls together, and you cannot ask for one without the other: the
publication gate, so nothing reaches an anonymous reader until two attempts agree and the run was
not built at an open egress tier; and the evidence class table, so no build log or network
transcript leaves the process. Trigon stores build logs unredacted, and before this existed the only
thing protecting them was that `trigon watch` binds to loopback.

Reading is anonymous, and asking costs a credential and a quota:

```console
$ trigon grant sqlite://queue.db alice --scopes request --daily-quota 20
token      27807464512f…                    # shown once; only its digest is stored
```

[`docs/22-management-layer.md`](docs/22-management-layer.md) lists each stage and whether it is
built or planned.
