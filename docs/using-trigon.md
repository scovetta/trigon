# Using Trigon

A task-oriented guide. [`README.md`](../README.md) shows what Trigon is and proves it works;
[`docs/`](README.md) explains how it was designed. This is for the person who has a package and a
question about it.

Everything below is output from a real run. Where a command needs a flag that is easy to get wrong,
the error it produces without it is shown too.

---

## First: what a Trigon verdict means

A verdict answers exactly one question:

> **Does this published artifact correspond to that source?**

It does **not** answer any of these, and reading it as though it does is the most expensive mistake
you can make with this tool:

| You might read it as | What it actually says |
| --- | --- |
| "this package is safe" | Nothing. A package that faithfully builds a backdoor **reproduces**, and that is a correct result. |
| "this is the real source" | Only that the artifact matches *the source you pointed it at*. For npm especially — see below. |
| "nobody could have tampered with it" | Only that the bytes we rebuilt match the bytes that were published, under a named set of transforms. |

**For npm, read `reproduced` carefully.** npm packages are close to fully reproducible at the tarball
level with no source linkage at all. A wall of green on an npm lockfile is true and nearly
worthless. The interesting npm question is *source attribution* — whether the tarball corresponds to
the repository it claims — not whether it rebuilds.

---

## Install

```
cargo build --release -p trigon
```

Rust 1.85 or later, edition 2024. **`trigon verify` has no prerequisites at all.** Rebuilding a
package additionally needs `podman`.

### The verifier build

```
cargo build --release -p trigon --no-default-features
```

This is the build to use when you are checking somebody else's claim and would rather not run their
code path. It carries seven commands — `verify`, `verify-attestation`, `stabilize`, `stabilizers`, `strategy`,
`keygen` and `public-key` — and links no async runtime, no network client and no model code. The
two key commands are here deliberately: making a signing key on a machine that has never had a
socket open is a reasonable thing to want, and nothing about making one needs the build half.
Checking a transparency log entry is in `verify-attestation` for the same reason — it is arithmetic
over bytes already on disk, so it needs no network and gets none. You can check that
yourself rather than take it on trust:

```
$ cargo tree -p trigon --no-default-features --edges normal --prefix none | grep -Ei '^(tokio|reqwest|hyper) '
$ echo $?
1
```

No matches. That is the whole claim: a binary that reproduces our verdict and cannot phone home.

---

## Task: compare two artifacts you already have

The fastest useful thing Trigon does. No network, no containers, no configuration.

```
$ trigon verify upstream.whl rebuild.whl
✔ exact

  format         zip
  stabilizer set wheel (58632c3c627d…)

               upstream           rebuild
  raw          347ba5223fbf…      347ba5223fbf…      =
  stabilized   87e00f4c8084…      87e00f4c8084…      =

  applied
    pyc-header               content         7 entries
    wheel-metadata-eol       content         1 entries
```

Useful flags:

- `--explain` — name every differing member rather than the first few. On a divergence this is the
  difference between "four members differ" and a list of paths you can go and look at.
- `--output json` — `{outcome, upstream, rebuild, diff}`, for a script.
- `--attest out.json` — write a DSSE-wrapped in-toto statement of the result. Emitted for a
  divergence as readily as for a match.

**Exit codes**, so this works in CI:

| code | meaning |
| --- | --- |
| `0` | `exact` or `normalized` |
| `1` | `divergent` |

Trigon infers the container format and the stabilizer profile from the file name. A `.whl` gets the
`wheel` profile, a `.crate` gets `crate`, a `.gem` gets `gem`. Override with `--format` and
`--profile` if you are comparing something whose name does not say what it is.

---

## Task: rebuild a package from its source

The real thing. Needs `podman`, and a few minutes the first time while the base image pulls.

```
$ trigon rebuild pkg:npm/left-pad@1.3.0 \
      --image docker.io/library/debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 \
      --work ./work --egress open --timewarp auto
```

Three flags people get wrong, with the errors they produce:

**`--image` must be pinned by digest.** A tag is refused:

```
Error: base image `localhost/trigon-base:latest` is not pinned by digest.
A tag makes the run unreproducible.
```

Get a digest with `podman image inspect <image> --format '{{.Id}}'`, or use a published
`name@sha256:…` reference.

**`--timewarp auto`** pins the dependency index to the package's publish instant. Without it the
build resolves against today's registry, and the run tells you so:

```
assuming    no registry mirror configured, so dependencies resolve against today's npm
            rather than against 2018-04-09T01:10:45.796Z
```

That is not a failure — the run still happens — but a dependency graph resolved eight years late is
not the graph the publisher had, and the rebuild is much less likely to match.

**`--egress`** decides what the build may reach. See the next section.

### Choosing an egress tier

| tier | the build can reach | use it when |
| --- | --- | --- |
| `open` *(default)* | the whole internet | you are exploring, or a package needs a host the mirror does not carry |
| `mirror-only` | only the time-filtering mirror | you want the strongest claim available today |
| `deny-all` | nothing | the build needs no network at all |

`mirror-only` and `deny-all` need two images built once:

```
trigon mirror-image
trigon base-image --from <a digest-pinned base>
```

**An enforced tier is the point, not a formality.** At `mirror-only` the mirror is the build's only
route out, and every response body crossing it is hashed against the artifact under test. A build
that downloads its own published artifact makes the run `void` — not a pass and not a failure,
because the build may be perfectly honest and we cannot tell.

---

## Reading a verdict

### The outcomes

Strongest first. They are strings on the wire, never a boolean, and never an ordinal.

| outcome | means |
| --- | --- |
| `exact` | the raw bytes are identical, before any stabilizer ran |
| `normalized` | the stabilized forms are identical, **and** every stabilizer that fired was built in and no riskier than metadata |
| `normalized_with_caveats` | the stabilized forms are identical, but some stabilizer that fired changes content, or was authored by a human or a model |
| `divergent` | the stabilized forms differ |

And one state outside all four:

| `void` | the artifact under test reached the build over the network, so the run is evidence of nothing |

`void` is not a failure. It means the question was not answered.

### Read the `applied` list

This is the part most people skip, and it is where the verdict's real content is.

```
  applied
    gzip-meta                metadata        1 entries
    tar-entry-order          structural      3 entries
    tar-time                 metadata        3 entries
```

Each line is a transform that fired to make the two artifacts match, with its **risk tier**. If you
do not accept a particular normalization, you can see that it fired and discard the result. The
tiers, least to most invasive:

- `structural` — reordering, framing. Changes no bytes of any member.
- `metadata` — timestamps, modes, owners.
- `content` — rewrites a member's bytes. `wheel-record` regenerating a wheel's `RECORD` is one.
- `lossy` — drops information.

**`normalized` is the tier gate.** Trigon will not report `normalized` if any applied stabilizer is
riskier than `metadata`, or was not built in. That rule is the reason the outcome is worth anything,
and it is why `normalized_with_caveats` exists as a separate answer rather than a footnote.

### Setting your own bar

There is no `--min` flag. You read the outcome string and decide:

```sh
case "$(trigon verify a.tgz b.tgz --output json | jq -r .outcome)" in
  exact)                    echo "byte-identical" ;;
  normalized)               echo "equal under builtin metadata transforms only" ;;
  normalized_with_caveats)  echo "equal, but read the applied list" ;;
  divergent)                echo "not the same artifact" ; exit 1 ;;
esac
```

A consumer who wants the strongest claim demands `exact`. One who accepts routine build
nondeterminism accepts `normalized`. Accepting `normalized_with_caveats` without reading `applied`
is accepting a transform you have not looked at.

### `capped below normalized`

When you see this line:

```
  capped below `normalized`: cargo-vcs-hash is Builtin at Content risk
```

it means the two artifacts *did* stabilize to the same digest, and the outcome is
`normalized_with_caveats` rather than `normalized` **because of the named stabilizer**. It tells you
which transform to go and look at. It appears only when the cap actually decided the outcome.

### Inspecting a stabilizer set

```
$ trigon stabilizers --profile npm-tarball
npm-tarball (562ce45ae6056536bb12b7995d670e06fcfaeee86cd59567fb7484e63aca4314)

  gzip-meta          metadata    default   Builtin
  tar-entry-order    structural  default   Builtin
  tar-time           metadata    default   Builtin
```

The long hex is the **set digest**, and it appears in every attestation. A verdict without it cannot
be re-derived by anyone, because the answer depends on which transforms were in play.

---

## Task: check a claim somebody else made

This is what the whole design is for. You need the bundle and the two artifacts. No network, and no
trust in whoever produced it.

```
$ trigon verify-attestation left-pad.intoto.json \
      --rerun-comparison --upstream left-pad-1.3.0.tgz --rebuild rebuilt.tgz

subject   left-pad-1.3.0.tgz (870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd)
predicate https://trigon.dev/equivalence/v1
claims    normalized
rederived normalized under tar-gzip@4598411b636d — the claim holds
```

`--rerun-comparison` recomputes the claim from the bytes rather than believing the statement. Without
it, you are reading what the statement asserts.

**Check the signature, or know that you did not.** `--public-key <hex>` verifies against a key you
pinned — `trigon public-key <keyfile>` prints the hex for a key you hold. Omitted, the tool says so rather than staying quiet:

```
signature unsigned
```

or, where a signature is present but you named no key:

```
signature present (ed25519), not checked — pass --public-key to check it
```

"Unsigned" and "signed by somebody you did not check" are different things, and the tool keeps them
different.

**Check the transparency log entry, where there is one.** A signature says who; it does not say
when. `--transparency <entry.json>` takes a run record's `transparency` field
(`jq .transparency <run>.json`) and checks it offline:

```
$ trigon verify-attestation left-pad.intoto.json \
      --transparency ./entry.json

logged    rekor.sigstage.dev index 56042318 at 2026-09-16T15:20:26Z (71d46696179fcd5d)
          the log's timestamp verifies, and the entry is about this bundle
```

Both halves matter. The log's own signature over the entry verifies, which is what dates it — and
the entry is about **this** bundle rather than some other statement logged at that instant. The
second is the one easy to leave out, and leaving it out means every individual check passes while
the result means nothing.

No network is involved. The key is chosen by the `logID` the entry names, which is the SHA-256 of
the log's own public key, so the keys compiled in for `rekor.sigstore.dev` and `rekor.sigstage.dev`
are an index rather than an authority; `--log-key <pem>` covers any other log. Pin a log's key
rather than fetching it at verification time, which would ask the log whose signature you are
checking to vouch for itself.

If the entry is for a different statement, that is a refusal and not a footnote:

```
Error: that log entry is about a different statement: the log recorded payload d8ee7745…, and this
bundle's payload is 5be9935c…. The timestamp is real and it is not about this bundle.
```

**One caveat worth stating plainly.** `--rerun-comparison` re-derives the *equivalence* claim from
two artifacts you hold. If you obtained the rebuilt artifact from the same party that produced the
attestation, you have checked their arithmetic and not their build. Full independence means
producing the rebuild yourself.

---

## What a run leaves behind

Every terminal outcome writes `<work>/NNN/run.json`, whether the run reproduced, diverged, failed to
build, or never found a recipe. Beside it: `strategy.yaml` (the recipe as rendered),
`guard.json` (the manifest the artifact guard checked against), `rebuild/build.log` (the container's
own output) and `rebuild/network.jsonl` (every response that crossed into the build, one per line).

`run.json` is the one to read first, and these are the fields that answer "why should I believe
this":

| Field | What it settles |
|---|---|
| `source` | The repository, commit and subdirectory the artifact was rebuilt from — plus `how`, the rung that found the commit, and `declared_url`, what the registry actually said before we canonicalized it |
| `derivation`, `confidence`, `assumptions` | Which rung produced the recipe, how much to believe it, and every guess it had to make |
| `declines` | One line per rung that was asked and said no, with its reason. A `no-strategy` is otherwise a verdict with no explanation |
| `attestable`, `egress`, `network_exchanges`, `network_bytes` | Whether the build's egress is fully accounted for, and what crossed |
| `pin` | What the time-filtering mirror was actually asked for and what it withheld — evidence the moment *bound*, not just that it was configured |
| `guard_trips`, `refused_artifact`, `guard_notes` | The artifact guard tripping (the run is void), the build asking for its own artifact and being refused (the control working), and near-misses |
| `failure`, `timings` | The classified failure and where the time went. A `None` timing means no data, never zero |

**`source.how` is the field people skip and shouldn't.** `registry_commit` is npm's own `gitHead`.
`exact_tag` is a tag named exactly for the version. `fuzzy_tag` means we matched
`python-ecdsa-0.19.2` to version `0.19.2` by stripping a prefix — reasonable, and a materially
weaker claim than the first two. A verdict built on one should not be read like a verdict built on
the other.

The same facts reach the signed statement: `rebuild/v1`'s `resolvedDependencies` carries the
repository, the `gitCommit` digest, and annotations for `discovery`, `ref`, `subdirectory` and
`declaredUri`. See [`09-attestations.md`](09-attestations.md) §2.1.

**What is not written to a file:** our own `tracing` output, which goes to stderr at `warn` by
default (`-v` for info, `-vv` for debug, or `RUST_LOG`). The structured records above are the audit
trail; the log is for watching a run happen.

## What a verdict does not tell you

Sourced from [`threat-model.md`](threat-model.md), which states the contract precisely.

- **`attestable` means the egress is accounted for, and nothing more.** A run at `mirror-only` or
  `deny-all` records a network transcript — every response that crossed into the build, with its
  digest — and `attestable: true` says that account is complete. It does **not** say the sandbox
  class, the base image or the strategy are good enough to sign. A run at `open` records no
  transcript and says so.
- **The artifact guard compares bytes.** A build that fetches the published artifact re-encoded,
  encrypted, or reassembled from chunks defeats it.
- **An enforced egress tier bounds which hosts a build reaches, never what those hosts serve.**
  `registry.npmjs.org` will serve anything anybody published.
- **A divergence has not been confirmed by a second run.** The two-agreeing-attempts policy is
  specified and not implemented.
- **Build logs are not redacted.** If your build environment carries credentials, they may appear in
  a stored log.
- **A published reproduction rate is a statement about the pipeline, not an ecosystem.** The corpora
  are small smoke sets, not prevalence-sampled.

---

## Troubleshooting

**`base image … is not pinned by digest`** — use `name@sha256:…`. See above.

**`could not start the mirror container` / `names must match [a-zA-Z0-9]…`** — an old symptom of a
relative `--work` path being read by podman as a volume name. Fixed, but if you see any variant of
it, pass an absolute `--work`.

**`Build one with 'trigon mirror-image'`** — an enforced tier needs the mirror image. Build it once.

**`cannot infer a format from '…'; pass --format`** — the file name does not say what the artifact
is. A `.gem` is a tar and only the ecosystem knows that; pass `--format` and `--profile`.

**`trigon does not speak gem; this build knows npm, pypi`** — the ecosystem in your PURL has no registry client yet. crates.io,
RubyGems and NuGet have stabilizer profiles but no resolver.

**A build that appears to hang** — a container build is minutes of silence. `-v` says what phase it
is in; `-vv` streams the build's own output.

**`unknown` as a failure signature** — Trigon could not name the failure from the build log. The run
is still recorded and the log is still on disk under `--work`.

---

## Where to go next

- [`README.md`](../README.md) — two complete worked examples with real output.
- [`threat-model.md`](threat-model.md) — what Trigon assumes, guarantees, and explicitly does not.
  §1.13 is the list of things a consumer is expected to check themselves.
- [`16-findings.md`](16-findings.md) — where building it proved the design wrong. Read this before
  believing any of the design chapters.
