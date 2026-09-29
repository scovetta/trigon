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
code path. It carries eight commands — `verify`, `verify-attestation`, `stabilize`, `stabilizers`,
`strategy`, `keygen`, `public-key`, and `log` with its `keygen` and `sign` — and links no async
runtime, no network client and no model code. The key commands are here deliberately: making a
signing key on a machine that has never had a socket open is a reasonable thing to want, and nothing
about making one needs the build half; nor does `log sign`, which holds an evidence log's key and
opens no socket, so that key can live on such a machine too.
Everything `verify-attestation` does is arithmetic over bytes already on disk, so it needs no
network and gets none. You can check that yourself rather than take it on trust:

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
  divergence as readily as for a match. It is a claim about two local files, `equivalence/v1` or
  `divergence/v1`, and not publishable: there is no run behind it for the publication gate to ask
  about, and `trigon publish` takes only v2 verdicts, voids and withdrawals. A claim about a
  published package comes from `trigon rebuild --store` and `trigon attest`.

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

**What a signature does not say.** It says who, never when. A statement carries no third-party
time, so a key stolen today signs statements that verify exactly like the ones it signed before, and
nothing yet bounds that ([threat model](threat-model.md) D24). An earlier version checked a
transparency-log entry here to date a statement. Nothing ever compared that date with anything that
bounds a key, and [ADR-0014](adr/0014-git-evidence-store-without-rekor.md) removed the check with
the log; `--output json` no longer has the `transparency` key it reported.

**One caveat worth stating plainly.** `--rerun-comparison` re-derives the *equivalence* claim from
two artifacts you hold. If you obtained the rebuilt artifact from the same party that produced the
attestation, you have checked their arithmetic and not their build. Full independence means
producing the rebuild yourself.

`--rerun-comparison` checks more than the outcome and the stabilized digests: what the statement
says the comparison found — which members differ and how, and which passes fired on which side —
is re-derived too, and a statement that got the outcome right and misreported either does not hold.

### A published record, from an evidence repository

A record published to an evidence repository ([`19`](19-distribution-and-lookup.md)) is checked
against that repository's log, from a clone or any copy of it, with no network:

```
$ trigon verify-attestation --record records/53/0a/530a…ede.json --evidence ./trigon-evidence \
      --source trigon
```

`--source` takes the source's pinned keys from `evidence.toml` and the checkpoint you last accepted
for it from the state directory; `--log-vkey`, `--attestation-key` and `--checkpoint` give the same
for a source you have not configured. The log is verified whole first, and held to that checkpoint;
then the record, against its leaf and the key its source had there; then what the source says of
the artifact now, with every later record that supersedes it shown. The record is shown with what
it signs about its run: the stabilizer set, when it ran, the Trigon that built it and the one that
signed it, the egress tier, the derivation method, and for a verdict the command that would falsify
it and where to dispute it, each marked absent where it signs none. An evidence file the directory
does not hold is reported unchecked, never passed. The exit code is
[`19`](19-distribution-and-lookup.md) §6's: 0, 1 for a divergence, 2 withdrawn, 3 void, 4 for
anything that failed verification or for a log that continues in a repository the directory does
not hold, 5 when it could not check at all, bad arguments included. Add `--rerun-comparison
--upstream <file> --rebuild <file>` to re-derive the verdict, and the published comparison report
is held to the re-derivation too, member by member.

Without a checkpoint, the output says so: the log is then checked for being whole, and not for
extending anything you have seen before, so a rewrite of the whole repository would not be noticed.
Keep the checkpoint from your last check.

With a source you sync (below), `--source <name>` without `--evidence` reads its clones as its
last sync left them, following its log into every repository it has gone on in; and
`verify-attestation --lookup`, the form of every verdict's falsifying command, finds the current
record for you (see *Task: look up an artifact, or check a lockfile*).

---

## Task: sign what a stored run says

`trigon rebuild … --store ./trigon-store` records a run; `trigon attest` signs it, in a separate
process that runs no build and opens no socket. It reads the run's blobs back by hash, re-derives
the claim from the two artifacts, and only then signs, into the store.

```
trigon attest [<run>] --store ./trigon-store --key ~/.trigon/signing.key [--prune]
```

`--prune` drops the rebuilt artifact's bytes afterwards, keeping its digests; where rebuilt
artifacts are published as release assets, it waits until the run is published (see *Pruning, once
published*, below).

What it signs depends on the run, and it says which:

- **A run that compared** gets `equivalence/v2`, or `divergence/v2` for a divergence, with
  `rebuild/v1` and `buildobservation/v1` beside it. The verdict carries the package's canonical
  purl, the Trigon that built it and the one signing it, the egress tier, the derivation method
  where one was recorded, and the digests of the evidence a third party fetches to re-derive it.
  [`09-attestations.md`](09-attestations.md) §2.5 lists every field.
- **A void run** — the artifact guard tripped, the build ran at `--egress open`, or a stabilizer a
  person or a model wrote applied — gets `void/v1` and nothing else. It says why, and never which
  way the comparison went:

  ```
  void      open_egress: the build ran with unrestricted network access, so nothing it produced is
            evidence about the package.

  signing void/v1 and nothing else: a void run gets no verdict, and no statement that says which way
  its comparison went
  ```

**Correcting a published record.** A published record is never edited; it is superseded, with a
reason from a closed list: `withdrawn`, `set_changed`, `attempts_disagree_later`, `pipeline_bug`.

```
trigon attest <run> --supersedes <record.json> --reason set_changed   # a verdict in its place
trigon attest --withdraw <record.json> --reason withdrawn              # "we were wrong", no verdict
```

`<record.json>` is a record file, `trigon.record/v1`. A superseding verdict is refused unless the
record is about the same artifact, digest for digest, and the same package. A withdrawal has no run,
and is filed in the store at `withdrawals/sha256/<record>/withdrawal.intoto.json`.

`trigon rebuild … --store ./trigon-store --attest out.json` signs the same statements through the
same code, in the process that ran the build, files them under the run, and writes the one about
the result — the verdict, or the void — to `out.json`. `--store` and then `trigon attest` keeps the
key out of that process, which is the separation a claim that matters wants.

## Task: confirm a run, so it can be published

Nothing is published on one attempt (ADR-0010 safeguard 1). A second attempt at the same work, which
agrees, is what the publication gate asks for, and `--confirm` runs it:

```
trigon rebuild --confirm <run> --store ./trigon-store
```

It repeats the run exactly: its target and artifact, the strategy it stored, its stabilizer set, and
the image and egress tier it ran on. No model is asked and no repair is tried. Every cache is
emptied — the build runs with no cached layer, the source is checked out again into a directory of
its own, no fetch cache is used — and the base image is taken out of the image store and pulled
again by digest where it has a registry to be pulled from. The record says which of that happened,
with the machine it ran on and when it began, and the gate reads it:

- the two attempts must be keyed alike — the target, the strategy and the set — and have found the
  same thing, not only reached the same outcome;
- the second must begin at least `confirmation_interval` after the first (`1h` by default);
- and on another machine — or on the same one, where `same_host_confirmation = true`, only if the
  confirming attempt was cold and its image was pulled again.

A pair that falls short is withheld with the reason: `attempts_too_close`, `same_host`,
`confirmation_not_cold`, `confirmation_unrecorded`, or `attempts_disagree`. `--confirm` refuses a
run it cannot repeat, before fetching anything: one that kept no strategy blob, a void run, one that
reached no verdict, and one recorded before runs were keyed on what they ran — rebuild that target,
and confirm the new run.

"Another machine" means another machine id. A machine with no `/etc/machine-id` (nor D-Bus's
`/var/lib/dbus/machine-id`) records an id derived from its hostname, and two of those may be two
containers on one machine, so such a pair is held to what one machine is held to. A run on a
derived image (`--image derive`) is confirmed on that image, and its confirmation says it reused
one: it is never cold, so it confirms only from another machine, and a divergence on a derived image
stays withheld however it is confirmed.

A worker's second attempt is the same thing, queued by the engine for a machine other than the
first attempt's — so a fleet of one machine confirms nothing unless `same_host_confirmation = true`
— and never for a void verdict.

## Task: publish to an evidence repository

`trigon publish` is the only thing that writes an evidence repository
([`19`](19-distribution-and-lookup.md)): a git repository holding signed records, the log that holds
them, and an index for finding them. Set one up once. First the log's own key:

```
$ trigon log keygen --origin example.com/trigon-evidence --out ~/.config/trigon/log.key
  wrote        /home/you/.config/trigon/log.key (0600)

  log key      example.com/trigon-evidence+0a714227+AUQS5nZWL9BI4ddCHeT5QyKj/Qjs6BPs6KWF5qTkZHGl
```

It signs the log's checkpoints and nothing else, and is a separate key from the one `trigon attest`
signs records with: Ed25519 in Go's private-key format, written `0600` and never over a file already
there. Point `[publish] log_key` at it. Only `trigon log sign` ever reads it — `publish` runs `log
sign` as a child process and never opens the key — and `log keygen` and `log sign` are in the
verifier build too, so the key can be kept on a machine that has never had a socket open. The line
it prints is what a client pins as the source's `log_key`.

Then, with `[publish] origin` and `disputes` set in `evidence.toml`, begin the log:

```
$ trigon log init --origin example.com/trigon-evidence --repo /srv/trigon-evidence.git \
      --attestation-key feaf1c610a3938f709780cc762f30e1add00513b5691edf2c13a7194750aed49
  repository   /srv/trigon-evidence.git (main)
  commit       e88208bf388f8d42ae2ba260f6fa474d94442924
  origin       example.com/trigon-evidence
  log key      example.com/trigon-evidence+0a714227+AUQS5nZWL9BI4ddCHeT5QyKj/Qjs6BPs6KWF5qTkZHGl
  attestation  feaf1c610a3938f709780cc762f30e1add00513b5691edf2c13a7194750aed49 (key id 59d9d354f06b4e8b)
```

That is the repository's first commit: `keys/log.vkey` and `keys/attestation.pub`, copies of the two
keys a client pins; a README stating the origin, the keys, how often a checkpoint appears — once per
publication, and at least every `[publish] heartbeat` — and where a dispute goes; and a checkpoint
of size 0, signed by `log sign --init`. A repository that already has a log is refused, and so is a
log this host has already published: another repository needs a log of its own, with its own origin
and key. On GitHub the branch also wants a ruleset that forbids force-pushes and deletion with no
one exempt; `log init` prints the `gh api` call that sets one on `[publish] branch`, and never runs
it.

Then publish runs the gate releases, one commit each time:

```
$ trigon publish 1789000000-aaaa0001 --store ./trigon-store --repo /srv/trigon-evidence.git
repository /srv/trigon-evidence.git (main)
logged    leaf 0: run 1789000000-aaaa0001: equivalence/v2 normalized, pkg:npm/demo-a@1.0.0
commit    bcdd74de13f1838cce145824577918f097a9908c (publish: 1 record, tree 0 → 1)
checkpoint example.com/trigon-evidence 1 2DY/vIdbRFHytloyGdm9M4zsk21mswwqlxN2n8Vo/8A=
```

The commit holds each record, the evidence it names, its leaf, the new tiles and checkpoint, and the
index file of every key the record is found by, and it is pushed without force. Before any of it is
written, `publish`:

- **verifies the repository's log**, whole, under `keys/log.vkey` — whose origin must be `[publish]
  origin` — and against the newest checkpoint of the log this host has published or verified, which
  it keeps in the host's state directory. A remote rolled back or rewritten behind that is refused,
  from any store and however the repository is named, and so is one whose log does not verify, or
  whose branch names git attributes; files beyond the checkpoint are never read;
- **asks the publication gate** about every run, as `trigon serve` does, with the repository's
  `kill-switch` file as safeguard 5. A withheld run is refused with its reason; a void one is
  published only as its `void/v1`; a divergence is refused while `divergences = "refuse"`, the
  default until [`19`](19-distribution-and-lookup.md) D7 decides how a maintainer is told, and
  published with its entry in the divergence feed under `"feed"` (below);
- **refuses** a run already published, the second of two agreeing attempts whose first is, a record
  for an artifact that already has a current one unless it supersedes it (`trigon attest <run>
  --supersedes <record> --reason <code>`), and a verdict without the falsifying command naming
  `[publish] origin` and the dispute pointer `[publish] disputes` names — attest it again with both
  set. Every refusal is listed at once:

  ```
  Error: refusing to publish, and nothing was written:
    - run `1789007200-aaaa0002`: it agrees with run `1789000000-aaaa0001`, which is published: of
      two agreeing attempts one is published, and the second would be the same finding again
      (docs/19 §3)
  ```

- **checks every record it would write as every client will**, and `trigon log sign` checks the
  tree again from disk before it signs: it extends a checkpoint the log key itself verifies, and the
  newest checkpoint of the log this host has published, and every new leaf is a heartbeat, a key
  change, a log-end, or names a record file whose envelopes verify under the attestation key the
  log has at that leaf and agree with the leaf.

A push that loses to another writer is never forced: the commit and the checkpoint signed for it
are discarded, and the publication is built again on what the other writer pushed. A publisher
killed part way leaves the repository as it was or with the whole publication; a run whose record
was pushed and not yet noted on the run is completed by the next `publish` of it, and never logged
twice. The run records where it went, as `published`: the repository, the commit, the record's
digest and its leaf.

The commit holds exactly the bytes `publish` wrote and `log sign` checked, and is read back before
it is pushed; it is never made by `git add`, so no `.gitignore`, excludes file or attribute keeps a
file out or rewrites one.

The repository is `--repo`, else `TRIGON_PUBLISH_REPO`, else `[publish] repo`: anything `git`
accepts, with `git`'s own credentials, and never a prompt — `GIT_TERMINAL_PROMPT=0`, and ssh with
`BatchMode=yes`, added to a configured `ssh` command too, so a missing credential or an unknown host
key fails rather than waits. A credential helper, an askpass, or an ssh wrapper that is not `ssh`,
runs as you configured it. Nothing else in your git configuration changes what is published:
`core.autocrlf` and your attributes file are switched off, and neither commit nor push is signed
with your key. `publish` keeps a clone of the repository in the store under `publish/`. One
`publish` runs at a time on a host, whatever store it runs from — a second is refused with the
first's pid, start time and store rather than left waiting — and the newest checkpoint of each log
the host has published is kept in `$XDG_STATE_HOME/trigon/publish/`. Keep that directory from one
run to the next: a host without it, such as a fresh CI runner, is held only to the checkpoint the
repository holds. A local path to a working tree, rather than a bare repository, is published into
in place: the commit is made there, nothing is pushed, and it is refused unless it is clean, holds
nothing git ignores under `keys/`, `log/`, `records/`, `evidence/` or `index/`, and is on
`[publish] branch`.

The other forms:

```
trigon publish --withdrawal <store>/withdrawals/sha256/<record>/withdrawal.intoto.json
trigon publish --heartbeat         # a heartbeat leaf, if the newest leaf is older than `heartbeat`
trigon publish --reconcile         # rebuild index/ from the log, in one commit
trigon publish <run>… --dry-run    # every file and leaf, and the checkpoint, unsigned
```

A withdrawal, signed by `trigon attest --withdraw`, is published only of a record the log holds and
nothing supersedes yet, and gets an entry in every index file of that artifact's keys.
`--heartbeat` logs a leaf only when one is due, and says so otherwise, so a scheduler can run it
daily; without one, every client's copy of an honest but quiet log turns *unknown* after
`frozen_after`. `--dry-run` prints what it would write, runs no `log sign`, and leaves the
repository, the working clone and the store's runs exactly as they were:

```
dry run   nothing is written, and `trigon log sign` is not run; the working clone and the repository are left as they are
write     evidence/sha256/0c/3d/0c3d0652f1e9abf9c749507dc33b2fd5df380ae15995014cb360aac1b5681cb6 (3014 bytes)
…
write     records/84/06/84061f04c7ef35caa4ae4f147909670f136bfe016869ad71e88b003326fc1cfd.json (8740 bytes)
leaf 0    {"keyId":"b62e867fa2f33afe","kind":"record","outcome":"normalized",…,"time":1790592152}
checkpoint, unsigned:
  example.com/trigon-evidence
  1
  2DY/vIdbRFHytloyGdm9M4zsk21mswwqlxN2n8Vo/8A=
commit    publish: 1 record, tree 0 → 1
```

### Rebuilt artifacts as release assets

With `rebuilt_artifacts = "github-release"` ([`19`](19-distribution-and-lookup.md) D4), every
verdict's rebuilt artifact but an exact one's is published beside its record, so that
`verify-attestation --rerun-comparison` needs nothing from the person running it but the published
artifact. An exact verdict's rebuilt artifact is the published artifact byte for byte, and is never
uploaded (below): its falsifying command takes the upstream file, `--upstream`, as its rebuilt
artifact too. Others are release assets of the evidence repository, never files in git: named
`sha256-<hex>` by the digest the verdict signs, in the month's release, `rebuilt-2026-09`, continued
as `rebuilt-2026-09.2` and so on once a release holds GitHub's 1,000 assets. The setting says what
`publish` uploads and nothing else: `verify-attestation --lookup` looks for a record's rebuilt
artifact in the repository that holds the record whatever your own setting is, since another
operator's repository publishes what its operator chose.

```
$ GITHUB_TOKEN=… trigon publish 1789000000-aaaa0001 --store ./trigon-store
repository https://github.com/<owner>/trigon-evidence.git (main)
asset     sha256-8b2e… in release rebuilt-2026-09 of <owner>/trigon-evidence
logged    leaf 12: run 1789000000-aaaa0001: equivalence/v2 normalized, pkg:npm/demo-a@1.0.0
commit    …
```

The asset is uploaded, or found, before the commit that names it; a publication that fails after
an upload leaves an asset nobody names, which is harmless, and the next attempt finds it by its name
and reuses it — once its size, and the digest GitHub reports for it, are the artifact's. An asset
of that name that is not the artifact is refused rather than taken for it; one GitHub left
unfinished, or reports no digest for, is removed and uploaded again from the store, since its size
alone cannot tell it from another artifact's. No asset goes into a draft release, which only the
repository's writers can see: where a draft has the month's tag, `publish` is refused and says so.
An exact rebuild is the published artifact byte for byte, which is not ours to redistribute, and is
not uploaded; a void has none. An artifact not under GitHub's 2 GiB is refused before anything is
written, and so is one the store no longer holds that no release has yet.

It is GitHub's REST API, not git, so it takes a credential of its own: a token with contents-write
on the repository — a fine-grained token, or a workflow's own `GITHUB_TOKEN` — from `GITHUB_TOKEN`,
or else `GH_TOKEN`, in the environment. Never on the command line or in a file, never printed —
not even where a server quotes it back — sent only in a request's header, and only to the API and
the upload host it names. Without one,
`publish` is refused before anything is written. The repository is the publish location's, which
must be on github.com — `https://github.com/<owner>/<repo>.git` or
`git@github.com:<owner>/<repo>.git`; any other location is refused with this mode on. `--dry-run`
says where each asset would go, and uploads nothing. `TRIGON_GITHUB_API` replaces
`https://api.github.com`, for a test server; it must be HTTPS, or HTTP to this machine.

### The divergence feed

With `divergences = "feed"` ([`19`](19-distribution-and-lookup.md) D7), a confirmed divergence is
published, with its entry in `feed/divergences.atom` in the same commit: an Atom feed that
maintainers and registry security teams can subscribe to, holding the most recent 200 divergences,
newest first — the log holds every one, and the README says so. Each entry names its record by
digest, links the record file and the dispute pointer it signs, and carries the command that would
falsify it. The feed is regenerated from the log whole each time a divergence, or a record
superseding one, is published, and by `--reconcile`: a withdrawal marks its entry superseded, and an
entry anybody else wrote into the file is gone at the next. Under the default, `divergences =
"refuse"`, divergences are refused as before.

### Pruning, once published

```
trigon publish <run>… --prune
```

`--prune` drops each published run's rebuilt artifact from the store, keeping its digests, once the
publication is pushed and recorded on the run; a divergence keeps its bytes, as `attest --prune`
keeps them. Where a publish repository is configured with `rebuilt_artifacts = "github-release"`,
`trigon attest --prune` refuses a run that is not published yet, before signing anything, since the
artifact is uploaded from the store when it is published — including one the gate withholds now,
which a confirmation can release later. A run no publication would ever upload an artifact for is
pruned as it always was: an exact rebuild, a void run, and the second of two agreeing attempts
whose first is published, which `publish` refuses. Anywhere else it prunes as it always did.
Pruning drops the run's reference to its rebuilt artifact, and deletes the bytes only where no
other run still names them: the two attempts of an agreeing pair rebuilt the same bytes, which the
store keeps once, so pruning one keeps them for the other. A run whose record says its bytes are
kept and whose store has lost them is reported as missing them, by `attest`, `rederive`, `serve`
and `watch`, never as holding them.

### Rotating a key: `log key-change` and `log succeed`

A rotation is logged, and every client follows it from the keys it pinned
([`19`](19-distribution-and-lookup.md) §8). Both go through `publish`'s own steps — the remote's
log verified first, `log sign` checking the tree, one commit pushed without force — and take
`--store`, `--repo` and `--dry-run` as `publish` does. A dry run signs nothing: `log key-change
--dry-run` shows the leaf with both signatures empty, and the files it would write by path — their
bytes, and the checkpoint's root, cover the signatures — since a signed leaf printed by a preview,
in a CI log say, would be a hand-over anyone holding the log key could append.

**The attestation key.** `trigon log key-change` logs a key-change leaf signed by the key current
now and the new one:

```
$ trigon log key-change --key ~/.trigon/signing.key --new-key ~/.trigon/signing-2.key
logged    leaf 40: key change: the attestation key 51e4f091d48fee98 hands over to 8702836caee10b5f
commit    bf670c4b… (publish: key change, tree 40 → 41)
```

From that leaf on, `trigon publish` publishes only records signed by the new key, and every client
refuses a record signed by the old one whose leaf comes later. To switch: sign with the new key —
`trigon attest <run> --key <new key file>`, and `trigon rebuild --attest --key` with the same — and
attest again, with it, any run attested with the old key that is still to be published; `publish`
refuses such a run and says so. Nothing in `evidence.toml` names the key a record is signed with,
so nothing there changes: a `[[source]]` pinning this repository, yours or anyone's, keeps pinning
the key its chain starts at and follows the change from the log, and the repository's
`keys/attestation.pub` stays that key too. Its README gains an account of the change. Only the key
current now can hand over, and a key the log has retired is never current again.

**The log key.** `trigon log succeed` ends the log with a log-end leaf naming its successor — its
origin, its log key, where it is — and begins the successor with a log-continuation leaf holding the
old log's final checkpoint, signed by both log keys:

```
$ trigon log keygen --origin example.com/trigon-evidence/1 --out ~/.config/trigon/log-1.key
$ trigon log succeed --origin example.com/trigon-evidence/1 --log-key ~/.config/trigon/log-1.key
logged    leaf 1: log-end: `example.com/trigon-evidence` is succeeded by `example.com/trigon-evidence/1`, at log/1 in this repository
commit    fa79a80c… (log succeed: `example.com/trigon-evidence` ends, tree 1 → 2; …)
checkpoint example.com/trigon-evidence 2 OtzRAIHy1wtwB6fU8gT6iZ6kBKMKGEpo7GE8rld54NE=
checkpoint example.com/trigon-evidence/1 1 tKNVlIvtcFjtrmngQj8s5yxsVXAlTTumQpxcaN1wZBA=
```

`publish` never opens a log key, so the successor's is named by `trigon log public-key <file>`, run
as a child, and `trigon log sign` is run twice: once with `--successor-key`, holding both keys, to
sign the final checkpoint and cosign it with the successor's — it signs a log-end only then, and
only for the key it names — and once with `--continuing`, to begin the successor only as the log
that log-end names. By default the successor is at the next free `log/<n>` of the same repository,
and both leaves are one commit. With `--url <location>`, repeatable, it is in another repository,
at `log` unless `--dir` says otherwise: the old log's end is pushed first, and the successor is
begun as the first commit of the repository at the first URL; stopped in between, the old log
refuses anything more, and the same `log succeed` run again begins the successor from the final
checkpoint already published. A log-end is for good, so before it is written that repository is
cloned and looked at: `log succeed` refuses, with nothing written, a first URL that names the
evidence repository itself, one git cannot reach, one holding `keys/`, `log/` or the successor's
directory, one whose branch names git attributes, and one that would not take a push, which `git
push --dry-run` asks. Where the old repository's `kill-switch` is set, the successor's first commit
sets it too, with the same words, and `log succeed` says so: a succession never clears safeguard 5,
and only a person removing the file in the successor's repository does.

Then switch to the successor: set `[publish] origin` to its origin and `log_key` to its key — and
`repo` to it, for another repository — and attest again whatever is still to be published, since a
verdict signs the origin of the log it is published into. `publish` refuses to publish under the old
origin once the log has ended, and says where publishing goes on. Publishing runs or a withdrawal
into a successor in another repository stands on the whole chain, so that an artifact with a current
record in the old repository has one in the new: `publish` reads the logs before it through an
evidence source whose chain reaches them from the chain's first log, synced first where it is
stale, and refuses, saying how, where none does — `trigon evidence add <name> <the old repository>
--log-key <its first log key> --attestation-key <key>` is the one to add. A source pinned to a later
log's key reads the chain from partway, and is passed over. A source synced before the old log
ended does not hold its end yet, so where none serves, `publish` syncs every source it did not just
sync, however fresh, and looks again; `--dry-run` syncs nothing, and reads each source from its
clone as it is. Keep the old log key: nothing more is appended to the old log, but its final
checkpoint is what a client holding it checks the succession against. `keys/log.vkey` stays the
first log's key, which clients pin; they follow the succession themselves.

### `trigon serve` and the repository's kill-switch

With a publish repository configured, `trigon serve` reports the repository's `kill-switch` beside
its own `--stop-divergences`, and says which is set: the repository's stops what `trigon publish`
publishes, the server's what it shows, and neither stands in for the other. It is read from the
working clone `publish` keeps in the store `serve` reads, as of that clone's last fetch that
succeeded, with when that was: a fetch that fails — the remote unreachable, a credential expired —
changes neither, so a report whose time stops moving is one to look into. It is set wherever the
branch has anything named `kill-switch`, and clear only where git lists nothing of that name; with
no working clone yet, no record of a fetch that succeeded, or a tree git cannot read, it is
`unknown`, never clear. `serve` reads it when it starts and every ten seconds after, never for a
request, since each read runs `git`. It is on the page's header and in `/v1/health` as
`kill_switches`, where an anonymous reader is told the state and when, and not where it was read
from.

## Task: keep the evidence sources you trust

A consumer asks evidence repositories — ours, other operators', mirrors of either — through
**sources**: one log each, pinned by its log key, whose name is the log's origin, and its
attestation key, and served from one or more locations ([`19`](19-distribution-and-lookup.md)
§6.1). `trigon evidence` configures them and keeps a verified clone of each, and `trigon lookup`,
`trigon check` and `verify-attestation --lookup` answer from those clones (the next task).

```
$ trigon evidence add trigon https://github.com/owner/trigon-evidence.git \
      https://codeberg.org/owner/trigon-evidence.git \
      --log-key 'github.com/owner/trigon-evidence+1a2b3c4d+AR…' --attestation-key <64 hex>
added     `trigon` to /home/you/.config/trigon/evidence.toml
origin    github.com/owner/trigon-evidence, the log key's name
url       https://github.com/owner/trigon-evidence.git (https)
url       https://codeberg.org/owner/trigon-evidence.git (https)
required  no
next      trigon evidence sync --source trigon

$ trigon evidence sync
source    `trigon`, from /home/you/.config/trigon/evidence.toml
synced    `github.com/owner/trigon-evidence`: 1204 leaves, newest leaf 2026-09-27T09:12:44Z
url       https://github.com/owner/trigon-evidence.git (https): 1204 leaves, answering
url       https://codeberg.org/owner/trigon-evidence.git (https): 1201 leaves, lagging
note      https://codeberg.org/owner/trigon-evidence.git is lagging: it serves …
```

**Adding one.** `evidence add <name> <url>… --log-key <vkey> --attestation-key <key>` writes a
`[[source]]` into your `evidence.toml` — or the file `TRIGON_EVIDENCE_CONFIG` names, made if it is
not there — keeping every comment and the order of what is already in it. Every URL is a location
of the one log: a mirror, which is how a split view is caught before witnesses exist. A relative
path is taken from where you run the command, and written absolute. The name is the source's
directory in the cache and the state directory, so a name any source already has is refused in any
case, whichever file or variable added it. `--checkpoint <file>` pins an initial checkpoint, which
must open under the log key; `--required` makes a check fail while the source cannot answer. A
source that pins neither key, or one of them, is refused unless `--trust-on-first-use` (below).

**Syncing.** `evidence sync` brings every source up to date in parallel, or those `--source <name>`
names. Each location has its own clone, at `~/.cache/trigon/evidence/<name>/<sha256 of the
location>/`: a remote is cloned shallow, partial and sparse, holding `keys/`, `log/` and
`records/`, and a local path in full, since git ignores depth and filters there (`-v` says so). A
later sync is a fetch and a reset, never a pull. Before anything is accepted, each clone is verified
whole — the checkpoint under the log key, the root recomputed from every leaf, leaf times that never
go back, every key change and succession followed, a successor in another repository cloned from
the URLs its log-end names and followed there as part of the same source — and every location is
held to every other: at one size one root, and at two sizes the smaller a prefix of the larger. The
largest answers, and a smaller one is reported as lagging. Only then is the state written, in
`~/.local/state/trigon/evidence/<name>/`: `checkpoint`, the one accepted; `keys`, the key history
the log gives, which the next sync compares with the log and says so where they disagree; and
`sync`, when it last worked. `--full-history` keeps each clone's whole git history, and says when
a fetch is not a fast-forward.

`evidence sync` exits 0 when every source synced and 4 when any did not. A source is **refused** —
its clones and state kept exactly as they were — when it fails verification: a checkpoint that does
not extend the one accepted, a clone rolled back behind it, or two locations that are not one log,
each printed with both signed notes. A refused source answers nothing, and every command asking it
exits 4, until a sync of it works. A source that could not be reached still answers from its clone
until the clone is stale.

**The first sync, and a lost state.** Without a checkpoint accepted or configured, the first sync
accepts the first checkpoint that verifies under the log key, and says so; from then on every
checkpoint must extend the one accepted. So the state directory is what a rollback is caught
against: a source that has synced before — a clone of it that a sync accepted is in the cache, or
its state records a sync that worked — and has lost its state is refused, never given a new one
quietly, and `evidence sync --accept-state-loss <name>` is how you say the loss is known. Only what
was lost starts over: with the checkpoint gone, the log is held only to its initial checkpoint, or
to nothing but itself, and a source trusting on first use keeps the keys it first read; with those
keys gone, they are read again from `keys/`, and the checkpoint that was kept must open under them.
A sync stopped partway — killed, or timed out — leaves no clone that counts as one a sync accepted,
and the next sync makes it again.

**In CI**, keep `~/.cache/trigon/evidence` and `~/.local/state/trigon/evidence` together, in one
cache step: the cache makes a job pay for a fetch and not a clone, and the state is what a rollback
is caught against. A runner that restores the clones without the state has lost it, as far as
Trigon can tell, and every sync is refused, exit 4, until `--accept-state-loss <name>`; one that
keeps neither is a fresh client, and detects a rollback only back to the checkpoint it is
configured with.

**Trust on first use.** A source added with `--trust-on-first-use`, or `TRIGON_EVIDENCE_REPO` with
`TRIGON_EVIDENCE_TOFU=1`, reads a key it does not pin from `keys/` of the first location reached on
its first sync, and records it in its state; every later sync is held to that key, whatever `keys/`
says afterwards. Whoever served that location at that moment chose the key, so every answer from
the source says it rests on keys trusted on first use, and where and when they were read — `evidence
list` does, and `verify-attestation --record --source <name>`, which reads the recorded keys, and
refuses, as a sync does, a source that has synced before and lost its checkpoint.

**Freshness.** Two clocks, from `[freshness]`: a source whose last successful sync is older than
`stale_after` (a day) is stale, and a command that needs it syncs it first and says so, or answers
unknown for it under `--offline` or when that sync fails; a source whose newest leaf is older than
`frozen_after` (fourteen days) is frozen, and answers unknown whatever the sync did, so a host
serving an old but consistent log cannot turn a withdrawal back into a verdict. A log with no leaf
yet is frozen too. An unknown source fails a check only where it is required.

**Listing and removing.** `evidence list` shows each source's origin, its locations and their
transports, whether it is required, the file that added it, whether its keys are pinned or trusted
on first use, when it last synced, the size of the checkpoint it answers from, when its newest leaf
was logged, and how it stands now — fresh; usable from its clone after a failed sync, until it goes
stale; unknown; frozen; refused — with each clone verified as a command asking it would, touching no
network (`--output json` for a script); a source whose state files cannot be read says so on its
own row and answers unknown, and the others are listed as they are. `evidence remove <name>` takes
a source out of your file, with its clones and its state; a source the project's
`.trigon/evidence.toml` or `TRIGON_EVIDENCE_REPO` added is refused, with why. `add` and `remove`
write the file a symlinked `evidence.toml` leads to, and keep the link. A project's sources sync
like any other, and everything said about one names the file that added it; a project's source is
fetched over HTTPS only, and so is a successor its log names in another repository — one at any
other location is refused.

---

## Task: look up an artifact, or check a lockfile

With a source configured (above), `trigon lookup` says what every source says of one artifact or
package, and `trigon check` of every package a lockfile names. Both answer from the verified clones:
a source that is stale is synced first, and said to be, and then nothing is fetched per package, so
a thousand-entry lockfile costs one fetch per source. Neither reads `index/`: a key is resolved from
the leaves of each source's log, which it holds whole, with every supersession the log records
applied.

```
$ trigon lookup sha512-r2cOJ3V46+rn1LIvf1Lpu…
key       sha512:af670e277578ebeae7d4b22f7f52e9b9555e40ec62f8e8792ad65e7c82daf3131375a4f2…

source    `trigon`, from /home/you/.config/trigon/evidence.toml; as of 2 leaves of `github.com/owner/trigon-evidence`
note      synced first: it had never been synced
answer    normalized — from 1 record(s) its log holds for it
record    sha256:83ef8bb2…eb9737 at leaf 1 of `github.com/owner/trigon-evidence`, current
subject   ws-1.0.0.tgz (ae1ea36b70b6ea951b818629222b1b628bf67fecef4f044e2f1f84002221ee1d)
purl      pkg:npm/ws@1.0.0
predicate https://trigon.dev/equivalence/v2
claims    normalized
set       tar-gzip, sha256:4598411b636d2d2cc62832312d37a1f2677681951a2ce19a3b8327e416b8abb3
run       1789000000-bbbb0001, from 2026-09-27T00:00:00Z; its finish was not recorded
trigon    built by 0.0.0+git.1111111…, signed by 0.0.0+git.5f06afd…
egress    mirror-only, attestable
derived   heuristic
falsify   trigon verify-attestation --lookup sha256:ae1ea36b…21ee1d --predicate https://trigon.dev/equivalence/v2 --origin github.com/owner/trigon-evidence --rerun-comparison --upstream <file>
dispute   https://github.com/owner/trigon-evidence/issues
evidence  not checked here: comparison, guardManifest, rebuiltArtifact, stabilizerSetManifest, strategy. A clone keeps `evidence/` out, and `verify-attestation --lookup` fetches what it re-derives the claim from

source    `theirs`, from /home/you/.config/trigon/evidence.toml; as of 1 leaves of `example.org/their-evidence`
note      synced first: it had never been synced
answer    never checked — its log holds no record for it

exit      0: every answer at or above the threshold
```

**The key** is what you have: npm's `integrity` string (`sha512-<base64>`), `sha256:<hex>`,
`sha512:<hex>` or `sha1:<hex>`, a purl with its version, a purl without one for every version of the
package, or the artifact itself, whose digests are computed. A record found by sha1 alone says that
sha1 is collision-broken.

**Every source answers for itself**, beside its name, the file that added it, the keys it rests on
where it trusts them on first use, and the checkpoint its answer came from. Every record the key
led to is shown with the outcome as a string, the stabilizer set, when it ran and which Trigon built
and signed it, the egress tier and whether it was `attestable`, the derivation, the command that
would falsify it and where to dispute it. A superseded record is struck through — `~~…~~` without
colour — with the record that superseded it, its leaf and the reason; a withdrawn artifact reads
`withdrawn`; a leaf whose record file is gone reads `DELETED`, and its outcome is not shown; a
record that fails verification says why. Two sources that answer differently are said to disagree,
and neither answer is taken over the other:

```
disagree  the sources disagree about it:
          `trigon` says normalized
          `theirs` says divergent
          each is its own claim, shown as its source makes it, and neither is taken over the other (docs/19 §6.1)

exit      1: a divergence
```

**`trigon check <lockfile>`** reads `package-lock.json` and `npm-shrinkwrap.json`,
`requirements.txt` and SPDX JSON, and looks each package up by the digest the file declares first —
npm's `integrity`, every `--hash` of a requirement, an SBOM's `checksums` — and by its purl only
where no digest finds a record about the artifact the file pins. A record is an answer about a
package only where its digests are that artifact's: where `integrity` or `checksums` declare more
than one digest, the strongest the record carries decides, as npm installs by the strongest, so a
record found by sha1 whose sha512 is another's answers nothing, and a sha1 that disagrees with the
sha512 that found a record is said; a requirement's `--hash`es are alternatives, any one of which
pip installs, and any one matching is enough. A purl whose records are all about another artifact
is not an answer: the package is never checked, and the note says which record was found. One whose
record carries none of the algorithms the file declares — a PyPI record, and an SBOM's sha1 — is
answered, and says the digests could not be compared. Two entries of one name and version with
different digests are two packages, each answered for itself. An SBOM's packages are all kept,
whatever their ecosystem and whether they carry a purl, and a purl with no version is the version
its `versionInfo` gives; one nothing can answer for is never checked, never left out.

```
$ trigon check package-lock.json
/home/you/app/package-lock.json · 3 package(s) · 2 source(s) · threshold at least normalized_with_caveats
source    `trigon`, from /home/you/.config/trigon/evidence.toml; as of 2 leaves of `github.com/owner/trigon-evidence`
source    `theirs`, from /home/you/.config/trigon/evidence.toml; as of 1 leaves of `example.org/their-evidence`

  ✔ normalized                   1   ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░
  ✖ divergent                    1   ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░
  ? never checked                1   ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░

  ✖  pkg:npm/left-pad@1.3.0 — divergent
      `trigon`: normalized, found by sha512; sha256:1ff0828f…5275fb at leaf 0 of `github.com/owner/trigon-evidence`; falsify: trigon verify-attestation --lookup sha256:0d718245…bd7a4e --predicate https://trigon.dev/equivalence/v2 --origin github.com/owner/trigon-evidence --rerun-comparison --upstream <file>; dispute: https://github.com/owner/trigon-evidence/issues
      `theirs`: divergent, found by sha512; sha256:61350666…aafdc3 at leaf 0 of `example.org/their-evidence`; falsify: trigon verify-attestation --lookup sha256:0d718245…bd7a4e --predicate https://trigon.dev/divergence/v2 --origin example.org/their-evidence --rerun-comparison --upstream <file>; dispute: https://example.org/their-evidence/issues
      the sources disagree: `trigon` says normalized, `theirs` says divergent; each is its own claim, and neither is taken over the other
  ?  pkg:npm/c@1.0.0 — never checked
      `trigon`: never checked
      `theirs`: never checked

exit      1: a divergence
```

`--format json` and `--format sarif` carry every source's answer for every package, with each
record it found. The SARIF has a result for every package: `trigon/pass`, of kind `pass` and level
`none`, for one that passes; one under the rule of what its sources said where that fails the
check; and, where a source fails it whatever was answered, `trigon/source-refused` or
`trigon/required-source-unknown`, at level `error` — a package that fails only because a required
source could not answer is never filed as the warning its answers alone would be. **A bare `trigon
check` answers from the evidence sources**; it used to read
`./trigon-store`, and `--store <path>` still does exactly that — a local store of your own runs,
newest run per package, five rows, exit 0 — with none of the flags below.

**Exit codes**, the same for `lookup`, `check` and `verify-attestation`
([`19`](19-distribution-and-lookup.md) §6): `0` every package at or above the threshold; `1` any
divergence; `2` any package never checked, or withdrawn; `3` any void, or any result below the
threshold; `4` any deleted record, any record or source that failed verification, a required source
that is unknown, or no source able to answer at all; `5` the tool could not check — bad arguments,
an unreadable lockfile, no source configured. The first of 5, 4, 1, 3, 2 wins. A package takes the
most severe answer any source gives that is not unknown, and is never checked only where no source
that answered holds a record for it, so a private source that holds only your own packages does not
make every public one read as never checked.

**The threshold.** `--min exact|normalized|normalized_with_caveats` (the default) is the outcome
floor, and `--max-risk structural|metadata|content|lossy` caps the riskiest stabilizer a verdict
may have been reached through, as its statement signs it — `--min normalized --max-risk
structural` is `Normalized` with `risk <= Structural` ([`05`](05-archive-and-normalization.md) §1).
An exact verdict needed no transform and meets any cap. Below either, a package is `3`.

**Freshness, and a source that cannot answer.** A source that is stale and cannot be synced, or is
frozen, answers unknown ([`19`](19-distribution-and-lookup.md) §6). An unknown source leaves only
its own answers missing, and says so, unless it is required — `required = true`, `--require
<name>`, or the one `TRIGON_EVIDENCE_REPO` adds — when every package fails, `4`, and the report says
which source fails it. `--offline` touches no network: a stale source answers unknown without
trying. `--source <name>` asks only the sources named, and `--require` of a source it leaves out is
refused, `5`, since that source would never be asked. A source none of whose locations has a clone
— its URL changed since its last sync — is synced first, as a stale one is.

**`--remote`** asks each source over HTTPS from `raw.githubusercontent.com` instead of from a clone,
for one question where a clone is unwelcome: the checkpoint, held to the pinned key and to the
checkpoint your last sync accepted by a consistency proof; a successor's first leaf, held to be the
log-continuation its predecessor's log-end requires; the index file for the key; each record; and
the tiles that prove each record's leaf included. A record whose leaf does not prove fails
verification; one it cannot read — the host failing or rate-limiting a request, a file not served,
an index entry past the checkpoint it read because a publish landed meanwhile — answers unknown,
and asking again, or syncing, answers it. A source whose last sync was refused answers nothing this
way either, and one whose attestation key you have re-pinned since its last sync is held to the new
pin alone until the next sync. It says, every time, what it costs: it tells GitHub which package was
asked about; it is rate-limited; and it sees a supersession or a withdrawal only where the index
lists it. Only for a source with an `https://github.com/<owner>/<repo>` URL; any other is refused,
exit 5, and `--source` leaves it out.

**Re-deriving a verdict: its falsifying command.** Every verdict signs the command that would
falsify it, and it runs as written, with the upstream artifact you hold in place of `<file>`:

```
$ trigon verify-attestation --lookup sha256:0d718245…bd7a4e       --predicate https://trigon.dev/equivalence/v2 --origin github.com/owner/trigon-evidence       --rerun-comparison --upstream ./left-pad-1.3.0.tgz --rebuild ./rebuilt/left-pad-1.3.0.tgz
```

It resolves the current record in your clone of the source whose log is `--origin`, syncing only
that source where it is stale — no such source is said, exit 4, and nothing is resolved elsewhere —
fetches the evidence the record names from the clone's remote, which names the record to that host
and is said, checks the record as `--record` does, and re-derives the verdict from the two
artifacts, the published comparison report held to it member by member. A source a project's
`.trigon/evidence.toml` added that gives the origin to a log key of its own is set aside, and said
to be, where your own sources hold that origin; two of your own that give it to different keys are
refused as ambiguous, `5`. Every source it asks is weighed as `lookup` weighs it, so a required
source that cannot answer fails it though another holds the record. A void has no claim to
re-derive, and is reported as the void it is, `3`. The rebuilt artifact is `--rebuild <file>`, the
output of rebuilding under the record's published strategy, and given, nothing is fetched for it.
Left out, it is looked for in the repository that holds the record, whatever your own `[publish]
rebuilt_artifacts` — that says what you publish, not what the source does: the release asset
`sha256-<hex>` of the digest the verdict signs, in the `rebuilt-YYYY-MM` releases of that
repository on GitHub, named by an HTTPS or an SSH location — a successor's, after a succession into
another repository — asked of GitHub's API without a token, and then in those of any other source
of yours that holds the record; a source a project's `.trigon/evidence.toml` added is not asked
where one of yours resolved it. Only the series of the month the record was logged in and the
months either side are listed, which is where `publish` puts it, so a lookup costs a few of the
sixty requests an hour GitHub allows without a token. It is downloaded into a file of its own, in a
directory made for it that only you can enter, and held to that digest: other bytes in the
repository of the source that resolved the record are refused, `4`; in another source's, they are
that repository's, and the next is asked. Downloading it names the artifact to GitHub, and the
report says so however it ended. An exact verdict's rebuilt artifact is the published artifact
itself, never uploaded, so GitHub is asked nothing and the upstream file is taken as the rebuilt
artifact too, held to the digest the verdict signs: its falsifying command runs as signed, with
`--upstream` alone. Where no repository that holds the record is on github.com, which asks GitHub
nothing, where none holds such an asset, or where GitHub refuses or cannot be reached, the check is
not made, `5`, and it asks for `--rebuild <file>`.

`verify-attestation --record <file> --source <name>` without `--evidence` reads the same clones,
following the source's chain into every repository its log has gone on in; it is in the verifier
build too, and fetches nothing.

---

## Configuring where evidence goes: `evidence.toml`

Publishing and looking up verdicts in an evidence repository
([`19-distribution-and-lookup.md`](19-distribution-and-lookup.md)) are configured, never compiled
in. `trigon attest`, `trigon publish`, `trigon log init`, `log key-change`, `log succeed`, `trigon
serve` and `trigon worker` read the configuration today — `serve` and `worker` for
`same_host_confirmation` and `confirmation_interval`, which decide when two attempts count as two,
and `serve` for `[publish] repo` and `branch` too, to report the repository's kill-switch — and
`trigon evidence` reads and writes the `[[source]]` tables and reads `[freshness]`, as `trigon
lookup`, `trigon check` and `verify-attestation` read them.

The file is `~/.config/trigon/evidence.toml` (`$XDG_CONFIG_HOME/trigon/evidence.toml`), or
whatever `TRIGON_EVIDENCE_CONFIG` names instead. Every key, with its default:

```toml
[publish]
repo = "git@github.com:<owner>/trigon-evidence.git"   # https://, ssh://, git://, http://, file://,
branch = "main"                                       #   user@host:path, or a path
origin = "github.com/<owner>/trigon-evidence"         # the log's origin
disputes = "https://github.com/<owner>/trigon-evidence/issues"
log_key = "~/.config/trigon/log.key"                  # read only by `trigon log sign`
divergences = "refuse"                                # or "feed": published, with the Atom feed
rebuilt_artifacts = "none"                            # or "github-release": `publish` uploads them
same_host_confirmation = false
confirmation_interval = "1h"                          # durations: <n>s, m, h or d
heartbeat = "7d"

[freshness]
stale_after = "1d"
frozen_after = "14d"

[[source]]
name = "trigon"
urls = ["https://github.com/<owner>/trigon-evidence.git"]    # one log, and any mirrors of it
log_key = "github.com/<owner>/trigon-evidence+1a2b3c4d+AR…"  # a C2SP verifier key
attestation_key = "<64 hex>"                                 # or a path to a PEM
checkpoint = "~/.config/trigon/trigon.checkpoint"            # optional
required = false
trust_on_first_use = false     # true only to read an unpinned key from the repository once
```

`attest` signs `origin` and `disputes` into every verdict's falsifying command and dispute pointer
when **both** are set, and leaves both out when either is not — which is right for local use, and
what `publish` refuses.

**An unknown key is an error**, and so is a value of the wrong kind, a pin that does not parse, or a
source without both keys that does not ask for trust on first use: a typo in a security setting that
was silently ignored would be a setting that is silently off. The error names the file and the key,
and the command exits `5`:

```
$ trigon attest
Error: /home/you/.config/trigon/evidence.toml: TOML parse error at line 2, column 1
  |
2 | orign = "github.com/owner/trigon-evidence"
  | ^^^^^
unknown field `orign`, expected one of `repo`, `branch`, `origin`, `disputes`, …
```

**Locations.** A URL is passed to `git` exactly as written, so credentials are `git`'s own — an SSH
key, a credential helper — and a URL carrying a password is refused, as is an `https://`, `http://`
or `git://` URL with any user name in it (`https://<token>@github.com/…` is how a token is written
there); tell a credential helper the user with `git config credential.https://<host>.username`
instead. An SSH user, `git@github.com:…`, names the account and is kept. A path is made absolute:
`~/` is expanded, and a relative path is taken from the directory of the file that names it. `git`
reads a colon before the first slash as SSH, so `backup:evidence` is refused; write
`./backup:evidence`, `file://…`, or `ssh://backup/…` for a host alias.

**A source by any location.** One log may be served from several places, each written as `git`
takes it; each is a mirror, cloned and held to the others:

```toml
[[source]]
name = "trigon"
urls = [
  "https://github.com/owner/trigon-evidence.git",      # HTTPS
  "git@codeberg.org:owner/trigon-evidence.git",         # SSH, scp form; or ssh://git@host/path
  "~/mirrors/trigon-evidence.git",                      # a local path, cloned in full
]
log_key = "github.com/owner/trigon-evidence+1a2b3c4d+AR…"
attestation_key = "<64 hex>"
```

or, for one run, the same from the environment — a required source named `env`:

```
$ TRIGON_EVIDENCE_REPO='https://github.com/owner/trigon-evidence.git file:///srv/mirror.git' \
  TRIGON_EVIDENCE_LOG_KEY='github.com/owner/trigon-evidence+1a2b3c4d+AR…' \
  TRIGON_EVIDENCE_ATTESTATION_KEY=<64 hex> trigon check package-lock.json
```

`--remote` needs an `https://github.com/<owner>/<repo>` location among them; everything else reads
the clones, whatever the transport.

**The environment** overrides the files for one run: `TRIGON_PUBLISH_REPO` for `[publish] repo`;
`TRIGON_EVIDENCE_REPO` (locations separated by spaces) adds a required source named `env`, pinned
by `TRIGON_EVIDENCE_LOG_KEY` and `TRIGON_EVIDENCE_ATTESTATION_KEY` — refused without both unless
`TRIGON_EVIDENCE_TOFU=1` — with `TRIGON_EVIDENCE_CHECKPOINT` as its optional checkpoint; and
`TRIGON_EVIDENCE_CACHE` and `TRIGON_EVIDENCE_STATE` replace the directories clones and sync state
are kept in (`~/.cache/trigon/evidence`, `~/.local/state/trigon/evidence`). With `rebuilt_artifacts
= "github-release"`, `publish` reads its GitHub token from `GITHUB_TOKEN`, or else `GH_TOKEN`, and
nowhere else.

**A project's own sources.** `.trigon/evidence.toml` in the working directory is read too, unless
`TRIGON_EVIDENCE_CONFIG` is set. It is chosen by whoever controls the project — in CI, the author of
the pull request — so it may only add `[[source]]` entries under new names, each with both keys and
an initial checkpoint, HTTPS URLs only, and files inside the project. The file itself must be inside
the project too, once symlinks are followed, a regular file of at most 64 KiB. Anything else refuses
the whole file, with the rule it broke. Source names are compared ignoring case, in every file,
since each is a directory under `~/.cache/trigon/evidence`.

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
| `pin` | What the time-filtering mirror was actually asked for and what it withheld — evidence the moment *bound* rather than that it was configured |
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
