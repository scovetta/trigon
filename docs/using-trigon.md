# Using Trigon

A task-oriented guide. If you are new to Trigon, read [`introduction.md`](introduction.md) first: in
ten minutes it explains what Trigon is and how the pieces fit. [`README.md`](../README.md) proves it
works, and [`docs/`](README.md) explains how it was designed. This guide is for someone with a
package and a question about it.

Every output below comes from a real run. If a command needs a flag that is easy to get wrong, the
guide also shows the error you get without it.

---

## First: what a Trigon verdict means

A verdict answers a single question:

> **Does this published artifact correspond to that source?**

It does **not** answer any of the questions below, and reading a verdict as though it did is a
costly mistake:

| You might read it as | It says |
| --- | --- |
| "this package is safe" | Nothing. A package built from source that contains a backdoor **reproduces**, and that is a correct result. |
| "this is the real source" | Only that the artifact matches *the source you pointed it at*. See below for npm in particular. |
| "nobody could have tampered with it" | Only that the bytes we rebuilt match the bytes that were published, under a named set of transforms. |

**Be wary of `reproduced` on npm.** npm packages come close to full reproducibility at the tarball
level without any link to their source. A wall of green on an npm lockfile is true and close to
worthless. The interesting npm question is *source attribution*, whether the tarball corresponds to
the repository it claims, rather than whether it rebuilds.

---

## Install

```
cargo build --release -p trigon
```

Rust 1.85 or later, edition 2024. **`trigon verify` has no other prerequisites.** Rebuilding a
package also needs `podman`.

### The verifier build

```
cargo build --release -p trigon --no-default-features
```

Use this build when you are checking somebody else's claim and would rather not run their code path.
It carries eight commands (`verify`, `verify-attestation`, `stabilize`, `stabilizers`, `strategy`,
`keygen`, `public-key`, and `log` with its `keygen` and `sign`) and links no async runtime, no
network client and no model code. The key commands are included on purpose. You may want to make a
signing key on a machine that has never had a socket open, and making one needs nothing from the
build half. Neither does `log sign`, which holds an evidence log's key and opens no socket, so that
key can live on such a machine too. Everything `verify-attestation` does is arithmetic over bytes
already on disk, so it needs no network and gets none. You can check that yourself instead of taking
it on trust:

```
$ cargo tree -p trigon --no-default-features --edges normal --prefix none | grep -Ei '^(tokio|reqwest|hyper) '
$ echo $?
1
```

`grep` matched nothing: the binary reproduces our verdict and cannot phone home.

---

## Task: compare two artifacts you already have

Comparing two artifacts is the fastest useful thing Trigon does, and it needs no network, containers
or configuration.

```
$ trigon verify upstream.whl rebuild.whl
✔ exact

  format       zip
  stabilizers  wheel (738725964c4a…)

               upstream           rebuild
  raw          347ba5223fbf…      347ba5223fbf…      =
  stabilized   87e00f4c8084…      87e00f4c8084…      =

  applied
    pyc-header               content         7 entries
    wheel-metadata-eol       content         1 entries
```

Useful flags:

- `--explain`: names every differing member instead of the first few. On a divergence, that turns
  "four members differ" into a list of paths you can go and look at.
- `--output json`: `{outcome, upstream, rebuild, diff}`, for a script.
- `--attest out.json`: writes a DSSE-wrapped in-toto statement of the result, for a divergence as
  well as for a match. The statement (`equivalence/v1` or `divergence/v1`) is a claim about two
  local files and cannot be published: no run stands behind it for the publication gate to ask
  about, and `trigon publish` takes only v2 verdicts, voids and withdrawals. For a claim about a
  published package, use `trigon rebuild --store` and `trigon attest`.

**Exit codes**, so this works in CI:

| code | meaning |
| --- | --- |
| `0` | `exact` or `normalized` |
| `1` | `divergent` |

Trigon infers the container format and the stabilizer profile from the file name. A `.whl` gets the
`wheel` profile, a `.crate` gets `crate`, a `.gem` gets `gem`. Override them with `--format` and
`--profile` if you are comparing something whose name does not say what it is.

---

## Task: rebuild a package from its source

A full rebuild needs `podman`, and a few minutes the first time while the base image pulls.

```
$ trigon rebuild pkg:npm/left-pad@1.3.0 \
      --image docker.io/library/debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 \
      --work ./work --egress open --timewarp auto
```

Three flags are easy to get wrong:

**`--image` must be pinned by digest.** Trigon refuses a tag:

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

The run still happens, so this is not a failure, but a dependency graph resolved eight years late is
not the graph the publisher had, and the rebuild is less likely to match.

**`--egress`** decides what the build may reach. See the next section.

### Choosing an egress tier

| tier | the build can reach | use it when |
| --- | --- | --- |
| `open` *(default)* | the whole internet | you are exploring, or a package needs a host the mirror does not carry |
| `mirror-only` | only the time-filtering mirror | you want the strongest claim available today |
| `deny-all` | nothing | the build needs no network at all |

`mirror-only` and `deny-all` need two images, built once:

```
trigon mirror-image
trigon base-image --from <a digest-pinned base>
```

**`mirror-only` and `deny-all` are enforced.** At `mirror-only` the mirror is the build's only route
out, and it hashes every response body that passes through it against the artifact under test. A
build that downloads its own published artifact makes the run `void`, which is neither a pass nor a
failure: the build may be honest, and we cannot tell.

---

## Reading a verdict

### The outcomes

Strongest first. On the wire each is a string, never a boolean or an ordinal.

| outcome | means |
| --- | --- |
| `exact` | the raw bytes are identical, before any stabilizer ran |
| `normalized` | the stabilized forms are identical, **and** every stabilizer that fired was built in and no riskier than metadata |
| `normalized_with_caveats` | the stabilized forms are identical, but some stabilizer that fired changes content, or was authored by a human or a model |
| `divergent` | the stabilized forms differ |

One state sits outside all four:

| `void` | the artifact under test reached the build over the network, so the run is evidence of nothing |

`void` means the question went unanswered, so it does not count as a failure.

### Read the `applied` list

Most of what the verdict says is in this list, so do not skip it.

```
  applied
    gzip-meta                metadata        1 entries
    tar-entry-order          structural      3 entries
    tar-time                 metadata        3 entries
```

Each line is a transform that fired to make the two artifacts match, with its **risk tier**. If you
do not accept a particular normalization, you can see that it fired and discard the result. The
tiers, least to most invasive:

- `structural`: reordering and framing. Changes no bytes of any member.
- `metadata`: timestamps, modes, owners.
- `content`: rewrites a member's bytes. `wheel-record-v2` regenerating a wheel's `RECORD` is one.
- `lossy`: drops information.

**`normalized` is the tier gate.** Trigon does not report `normalized` if any applied stabilizer is
riskier than `metadata` or was not built in. That rule is what makes the outcome worth anything, and
it is why `normalized_with_caveats` exists as a separate answer instead of a footnote.

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

Demand `exact` for the strongest claim, or accept `normalized` if you accept routine build
nondeterminism. Accepting `normalized_with_caveats` without reading `applied` means accepting a
transform you have not looked at.

### `capped below normalized`

A line like this one

```
  capped below `normalized`: cargo-vcs-hash is Builtin at Content risk
```

means the two artifacts *did* stabilize to the same digest, and that the outcome is
`normalized_with_caveats` rather than `normalized` **because of the named stabilizer**, which is the
transform to go and look at. The line appears only when the cap decided the outcome.

### Inspecting a stabilizer set

```
$ trigon stabilizers --profile npm-tarball
npm-tarball (562ce45ae6056536bb12b7995d670e06fcfaeee86cd59567fb7484e63aca4314)

  gzip-meta          metadata    default   Builtin
  tar-entry-order    structural  default   Builtin
  tar-time           metadata    default   Builtin
```

The long hex is the **set digest**, and it appears in every attestation. You cannot re-derive a
verdict without it, because the answer depends on which transforms were in play.

---

## Task: check a claim somebody else made

Trigon is designed for this task: you need the bundle and the two artifacts, and you need neither a
network nor trust in whoever produced the bundle.

```
$ trigon verify-attestation left-pad.intoto.json \
      --rerun-comparison --upstream left-pad-1.3.0.tgz --rebuild rebuilt.tgz

subject   left-pad-1.3.0.tgz (870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd)
predicate https://trigon.dev/equivalence/v1
claims    normalized
rederived normalized under tar-gzip@4598411b636d — the claim holds
```

`--rerun-comparison` recomputes the claim from the bytes instead of believing the statement. Without
it, you are reading what the statement asserts.

**Check the signature, or know that you did not.** `--public-key <hex>` verifies against a key you
pinned; `trigon public-key <keyfile>` prints the hex for a key you hold. Without `--public-key`, the
tool tells you so instead of staying quiet:

```
signature unsigned
```

or, where a signature is present but you named no key:

```
signature present (ed25519), not checked — pass --public-key to check it
```

"Unsigned" and "signed by somebody you did not check" are different things, and the tool keeps them
apart.

**A signature says who, never when.** A statement carries no third-party time, so a key stolen today
signs statements that verify the same way as the ones it signed before, and nothing bounds that yet
([threat model](threat-model.md) D24). An earlier version checked a transparency-log entry here to
date a statement, but nothing compared that date with anything that bounds a key, and
[ADR-0014](adr/0014-git-evidence-store-without-rekor.md) removed the check along with the log;
`--output json` no longer has the `transparency` key it reported.

**A caveat about independence.** `--rerun-comparison` re-derives the *equivalence* claim from two
artifacts you hold. If you got the rebuilt artifact from the party that produced the attestation,
you have checked their arithmetic and not their build. For full independence, produce the rebuild
yourself.

`--rerun-comparison` checks more than the outcome and the stabilized digests. It also re-derives
what the statement says the comparison found (which members differ and how, and which passes fired
on which side), and a statement that got the outcome right but misreported either of those does not
hold.

### A published record, from an evidence repository

You check a record published to an evidence repository ([`19`](19-distribution-and-lookup.md))
against that repository's log, from a clone or any copy of it, with no network:

```
$ trigon verify-attestation --record records/53/0a/530a…ede.json --evidence ./trigon-evidence \
      --source trigon
```

`--source` takes the source's pinned keys from `evidence.toml`, and the checkpoint you last accepted
for it from the state directory; `--log-vkey`, `--attestation-key` and `--checkpoint` give the same
for a source you have not configured. The command first verifies the whole log and holds it to that
checkpoint. It then checks the record against its leaf and the key its source had there, and then
what the source says of the artifact now, showing every later record that supersedes it. It shows
the record with what the record signs about its run: the stabilizer set, when it ran, the Trigon
that built it and the one that signed it, the egress tier, the derivation method, and, for a
verdict, the command that would falsify it and where to dispute it, each marked absent where the
record signs none. It reports an evidence file the directory does not hold as unchecked, never as
passed. The exit code is [`19`](19-distribution-and-lookup.md) §6's: 0; 1 for a divergence; 2
withdrawn; 3 void; 4 for anything that failed verification, or for a log that continues in a
repository the directory does not hold; 5 when it could not check at all, bad arguments included.
Add `--rerun-comparison --upstream <file> --rebuild <file>` to re-derive the verdict, and the
command holds the published comparison report to the re-derivation too, member by member.

Without a checkpoint, the output says so. The command then checks that the log is whole, but not
that it extends anything you have seen before, so it would not notice a rewrite of the whole
repository. Keep the checkpoint from your last check.

For a source you sync (below), `--source <name>` without `--evidence` reads its clones as its last
sync left them, following its log into every repository it has gone on in. `verify-attestation
--lookup`, the form every verdict's falsifying command takes, finds the current record for you (see
*Task: look up an artifact, or check a lockfile*).

---

## Task: sign what a stored run says

`trigon rebuild … --store ./trigon-store` records a run; `trigon attest` signs it, in a separate
process that runs no build and opens no socket. It reads the run's blobs back by hash and re-derives
the claim from the two artifacts before it signs anything into the store.

```
trigon attest [<run>] --store ./trigon-store --key ~/.trigon/signing.key [--prune]
```

`--prune` drops the rebuilt artifact's bytes afterwards, keeping its digests; where rebuilt
artifacts are published as release assets, it waits until the run is published (see *Pruning, once
published*, below).

The statement `attest` signs depends on the run, and it says which:

- **A run that compared** gets `equivalence/v2`, or `divergence/v2` for a divergence, with
  `rebuild/v1` and `buildobservation/v1` beside it. The verdict carries the package's canonical
  purl, the Trigon that built it and the one signing it, the egress tier, the derivation method
  where one was recorded, and the digests of the evidence a third party fetches to re-derive it.
  [`09-attestations.md`](09-attestations.md) §2.5 lists every field.
- **A void run** (the artifact guard tripped, the build ran at `--egress open`, or a stabilizer
  written by a person or a model applied) gets `void/v1` and nothing else. The statement says why,
  and never which way the comparison went:

  ```
  void      open_egress: the build ran with unrestricted network access, so nothing it produced is
            evidence about the package.

  signing void/v1 and nothing else: a void run gets no verdict, and no statement that says which way
  its comparison went
  ```

**Correcting a published record.** A published record is never edited. You supersede it instead,
with a reason from a closed list: `withdrawn`, `set_changed`, `attempts_disagree_later`,
`pipeline_bug`.

```
trigon attest <run> --supersedes <record.json> --reason set_changed   # a verdict in its place
trigon attest --withdraw <record.json> --reason withdrawn              # "we were wrong", no verdict
```

`<record.json>` is a record file, `trigon.record/v1`. `attest` refuses a superseding verdict unless
the record is about the same artifact, digest for digest, and the same package. A withdrawal has no
run, and `attest` files it in the store at `withdrawals/sha256/<record>/withdrawal.intoto.json`.

`trigon rebuild … --store ./trigon-store --attest out.json` signs the same statements through the
same code, in the process that ran the build, files them under the run, and writes the one about the
result (the verdict, or the void) to `out.json`. Running `--store` and then `trigon attest` keeps
the key out of that process, and a claim that matters wants that separation.

## Task: confirm a run, so it can be published

Trigon publishes nothing on one attempt (ADR-0010 safeguard 1). The publication gate asks for a
second attempt at the same work that agrees with the first, and `--confirm` runs it:

```
trigon rebuild --confirm <run> --store ./trigon-store
```

It repeats the run with the same target and artifact, the strategy it stored, its stabilizer set,
and the image and egress tier it ran on. It asks no model and tries no repair. It empties every
cache: the build runs with no cached layer, the source is checked out again into a directory of its
own, and no fetch cache is used. It takes the base image out of the image store and pulls it again
by digest where there is a registry to pull it from. The record says which of that happened, how the
base image was pinned (a registry digest, a local image's content id, or neither), the machine the
attempt ran on and when it began, and the gate reads it:

- the two attempts must be keyed alike (the target, the strategy and the set) and must have found
  the same thing, not only reached the same outcome;
- the second must begin at least `confirmation_interval` after the first (`1h` by default);
- and it must run on another machine, or on the same one where `same_host_confirmation = true`, and
  then only if the confirming attempt was cold and its image was pulled again or, where
  `same_host_local_images = true` as well, was a local image pinned by its content id.

The gate withholds a pair that falls short, with the reason: `attempts_too_close`, `same_host`,
`confirmation_not_cold`, `confirmation_unrecorded`, or `attempts_disagree`. Before fetching
anything, `--confirm` refuses a run it cannot repeat: one that kept no strategy blob, a void run,
one that reached no verdict, and one recorded before runs were keyed on what they ran. Rebuild that
target, and confirm the new run.

"Another machine" means another machine id. A machine with no `/etc/machine-id` (nor D-Bus's
`/var/lib/dbus/machine-id`) records an id derived from its hostname, and two such ids may belong to
two containers on one machine, so the gate holds such a pair to the rules for one machine. A run on
a derived image (`--image derive`) is confirmed on that image, and its confirmation records that it
reused one. That confirmation is never cold, so it confirms only from another machine, and a
divergence on a derived image stays withheld however it is confirmed.

A worker's second attempt is the same thing. The engine queues it for a machine other than the first
attempt's, and never for a void verdict, so a fleet of one machine confirms nothing unless
`same_host_confirmation = true`.

**A base image built on this machine.** `trigon base-image`, and `--image auto` with it, name the
images they build by content id, which no registry serves, so a confirmation has nothing to pull
such an image again by. On one machine the gate withholds the pair as `confirmation_not_cold`, and
`--confirm` says so as it starts, naming the setting that would accept it. With
`same_host_local_images = true` beside `same_host_confirmation = true`, a confirmation that nothing
warm could supply, on a local image pinned by its full content id, counts as cold, and `--confirm`
says the setting accepts the image. The cost is a registry's word on the image: the second attempt
runs on whatever the machine's image store holds under that id. The image store is part of what one
machine holds constant, and so beyond what a same-host confirmation can catch anyway
([`19`](19-distribution-and-lookup.md) D8, and the [threat model](threat-model.md) D38). The setting
is off by default. The gate refuses a registry's image that was not pulled again, and any warm
cache, either way. Set alone, the setting changes nothing, and `serve`, `worker`, `attest`,
`publish` and `--confirm` say so in a note.

An id alone does not make an image local. `--confirm` asks podman which registry digests name the
image. A registry's image named by its id (`TRIGON_BASE_PARENT=<an image id>`, or the parent a base
image's label names) is still that registry's: `--confirm` takes it out by the id and pulls it again
by the digest, and refuses if that fails, whatever is set. The confirmation of a run on an image
that `--image derive` built reuses that image, which is a cache. The gate refuses it on one machine
however the two settings stand, and `--confirm` says so instead of naming a setting.

## Task: publish to an evidence repository

`trigon publish` is the only thing that writes an evidence repository
([`19`](19-distribution-and-lookup.md)): a git repository holding signed records, the log that holds
them, and an index for finding them. You set one up once, starting with the log's own key:

```
$ trigon log keygen --origin example.com/trigon-evidence --out ~/.config/trigon/log.key
  wrote        /home/you/.config/trigon/log.key (0600)

  log key      example.com/trigon-evidence+0a714227+AUQS5nZWL9BI4ddCHeT5QyKj/Qjs6BPs6KWF5qTkZHGl
```

This key signs the log's checkpoints and nothing else, and is separate from the key `trigon attest`
signs records with. It is Ed25519 in Go's private-key format, written `0600` and never over an
existing file. Point `[publish] log_key` at it. Only `trigon log sign` reads it (`publish` runs `log
sign` as a child process and never opens the key), and `log keygen` and `log sign` are in the
verifier build too, so you can keep the key on a machine that has never had a socket open. A client
pins the line `log keygen` prints as the source's `log_key`.

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

That is the repository's first commit. It holds `keys/log.vkey` and `keys/attestation.pub`, copies
of the two keys a client pins; a README stating the origin, the keys, how often a checkpoint appears
(once per publication, and at least every `[publish] heartbeat`) and where a dispute goes; and a
checkpoint of size 0, signed by `log sign --init`. `log init` refuses a repository that already has
a log, and a log this host has already published: another repository needs a log of its own, with
its own origin and key. On GitHub the branch should also have a ruleset that forbids force-pushes
and deletion with no one exempt; `log init` prints the `gh api` call that sets one on `[publish]
branch`, and never runs it.

After that, `publish` publishes the runs the gate releases, one commit each time:

```
$ trigon publish 1789000000-aaaa0001 --store ./trigon-store --repo /srv/trigon-evidence.git
repository /srv/trigon-evidence.git (main)
logged    leaf 0: run 1789000000-aaaa0001: equivalence/v2 normalized, pkg:npm/demo-a@1.0.0
commit    bcdd74de13f1838cce145824577918f097a9908c (publish: 1 record, tree 0 → 1)
checkpoint example.com/trigon-evidence 1 2DY/vIdbRFHytloyGdm9M4zsk21mswwqlxN2n8Vo/8A=
```

The commit holds each record, the evidence it names, its leaf, the new tiles and checkpoint, and the
index file of every key the record is found by, and `publish` pushes it without force. Before it
writes any of that, `publish`:

- **verifies the repository's log**, whole, under `keys/log.vkey` (whose origin must be `[publish]
  origin`) and against the newest checkpoint of the log this host has published or verified, which
  it keeps in the host's state directory. It refuses a remote rolled back or rewritten behind that
  checkpoint, from any store and however the repository is named, and also one whose log does not
  verify or whose branch names git attributes. It never reads files beyond the checkpoint;
- **asks the publication gate** about every run, as `trigon serve` does, with the repository's
  `kill-switch` file as safeguard 5. It refuses a withheld run with its reason, and publishes a void
  one only as its `void/v1`. It refuses a divergence while `divergences = "refuse"`, the default
  until [`19`](19-distribution-and-lookup.md) D7 decides how a maintainer is told, and under
  `"feed"` publishes it with its entry in the divergence feed (below);
- **refuses** a run already published; the second of two agreeing attempts whose first is published;
  a record for an artifact that already has a current one, unless it supersedes it (`trigon attest
  <run> --supersedes <record> --reason <code>`); and a verdict without the falsifying command naming
  `[publish] origin` and the dispute pointer `[publish] disputes` names (attest it again with both
  set). It lists every refusal at once:

  ```
  Error: refusing to publish, and nothing was written:
    - run `1789007200-aaaa0002`: it agrees with run `1789000000-aaaa0001`, which is published: of
      two agreeing attempts one is published, and the second would be the same finding again
      (docs/19 §3)
  ```

- **checks every record it would write as every client will**, and `trigon log sign` checks the tree
  again from disk before it signs. The tree must extend a checkpoint the log key itself verifies,
  and the newest checkpoint of the log this host has published, and each new leaf must be a
  heartbeat, a key change or a log-end, or name a record file whose envelopes verify under the
  attestation key the log has at that leaf and agree with the leaf.

`publish` never forces a push that loses to another writer: it discards the commit and the
checkpoint signed for it, and builds the publication again on what the other writer pushed. A
publisher killed part way leaves the repository either as it was or with the whole publication. If a
run's record was pushed but not yet noted on the run, the next `publish` of that run completes it,
and never logs it twice. The run records where it went, as `published`: the repository, the commit,
the record's digest and its leaf.

The commit holds the same bytes that `publish` wrote and `log sign` checked, and `publish` reads it
back before pushing it. `publish` never makes the commit with `git add`, so no `.gitignore`,
excludes file or attribute can keep a file out or rewrite one.

The repository is `--repo`, else `TRIGON_PUBLISH_REPO`, else `[publish] repo`. It can be anything
`git` accepts. `publish` uses `git`'s own credentials and never prompts: it sets
`GIT_TERMINAL_PROMPT=0`, and runs ssh with `BatchMode=yes`, added to a configured `ssh` command too,
so a missing credential or an unknown host key fails instead of waiting. A credential helper, an
askpass, or an ssh wrapper that is not `ssh` runs as you configured it. Nothing else in your git
configuration changes what is published: `publish` switches off `core.autocrlf` and your attributes
file, and signs neither commit nor push with your key. `publish` keeps a clone of the repository in
the store under `publish/`. One `publish` runs at a time on a host, whatever store it runs from;
`publish` refuses a second, naming the first's pid, start time and store, instead of leaving it
waiting. The host keeps the newest checkpoint of each log it has published in
`$XDG_STATE_HOME/trigon/publish/`. Keep that directory from one run to the next: a host without it,
such as a fresh CI runner, is held only to the checkpoint the repository holds. Given a local path
to a working tree instead of a bare repository, `publish` publishes into it in place. It makes the
commit there and pushes nothing, and it refuses unless the tree is clean, holds nothing git ignores
under `keys/`, `log/`, `records/`, `evidence/` or `index/`, and is on `[publish] branch`.

The other forms:

```
trigon publish --withdrawal <store>/withdrawals/sha256/<record>/withdrawal.intoto.json
trigon publish --heartbeat         # a heartbeat leaf, if the newest leaf is older than `heartbeat`
trigon publish --reconcile         # rebuild index/ from the log, in one commit
trigon publish <run>… --dry-run    # every file and leaf, and the checkpoint, unsigned
```

`publish` publishes a withdrawal, signed by `trigon attest --withdraw`, only for a record the log
holds and nothing supersedes yet, and adds an entry for it to every index file of that artifact's
keys. `--heartbeat` logs a leaf only when one is due, and otherwise says so, so a scheduler can run
it daily; without heartbeats, every client's copy of an honest but quiet log turns *unknown* after
`frozen_after`. `--dry-run` prints what it would write, runs no `log sign`, and leaves the
repository, the working clone and the store's runs as they were:

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

With `rebuilt_artifacts = "github-release"` ([`19`](19-distribution-and-lookup.md) D4), `publish`
publishes every verdict's rebuilt artifact except an exact one's beside its record, so that
`verify-attestation --rerun-comparison` needs nothing from the person running it but the published
artifact. An exact verdict's rebuilt artifact is the published artifact byte for byte, and is never
uploaded (below); its falsifying command takes the upstream file, `--upstream`, as its rebuilt
artifact too. The others become release assets of the evidence repository, never files in git. Each
is named `sha256-<hex>` by the digest the verdict signs and goes in the month's release,
`rebuilt-2026-09`, continued as `rebuilt-2026-09.2` and so on once a release holds GitHub's 1,000
assets. The setting controls what `publish` uploads and nothing else: `verify-attestation --lookup`
looks for a record's rebuilt artifact in the repository that holds the record whatever your own
setting is, since another operator's repository publishes what its operator chose.

```
$ GITHUB_TOKEN=… trigon publish 1789000000-aaaa0001 --store ./trigon-store
repository https://github.com/<owner>/trigon-evidence.git (main)
asset     sha256-8b2e… in release rebuilt-2026-09 of <owner>/trigon-evidence
logged    leaf 12: run 1789000000-aaaa0001: equivalence/v2 normalized, pkg:npm/demo-a@1.0.0
commit    …
```

`publish` uploads the asset, or finds it, before the commit that names it. A publication that fails
after an upload leaves an asset nobody names, which is harmless, and the next attempt finds it by
its name and reuses it once its size, and the digest GitHub reports for it, match the artifact's.
`publish` refuses an asset of that name that is not the artifact instead of taking it for the
artifact. It removes one that GitHub left unfinished, or reports no digest for, and uploads it again
from the store, since its size alone cannot tell it from another artifact's. No asset goes into a
draft release, which only the repository's writers can see: where a draft has the month's tag,
`publish` refuses and says so. An exact rebuild is the published artifact byte for byte, which is
not ours to redistribute, so `publish` does not upload it; a void has none. Before writing anything,
`publish` refuses an artifact that is not under GitHub's 2 GiB, and one the store no longer holds
that no release has yet.

The upload goes through GitHub's REST API, not git, so it takes a credential of its own: a token
with contents-write on the repository (a fine-grained token, or a workflow's own `GITHUB_TOKEN`),
from `GITHUB_TOKEN`, or else `GH_TOKEN`, in the environment. `publish` never takes the token on the
command line or from a file and never prints it, even where a server quotes it back; it sends the
token only in a request's header, and only to the API and the upload host the API names. Without a
token, `publish` refuses before writing anything. The repository is the publish location's, which
must be on github.com (`https://github.com/<owner>/<repo>.git` or
`git@github.com:<owner>/<repo>.git`); with this mode on, `publish` refuses any other location.
`--dry-run` says where each asset would go, and uploads nothing. `TRIGON_GITHUB_API` replaces
`https://api.github.com`, for a test server; it must be HTTPS, or HTTP to this machine.

### The divergence feed

With `divergences = "feed"` ([`19`](19-distribution-and-lookup.md) D7), `publish` publishes a
confirmed divergence with its entry in `feed/divergences.atom`, in the same commit. Maintainers and
registry security teams can subscribe to this Atom feed, which holds the most recent 200
divergences, newest first; the log holds all of them, and the README says so. Each entry names its
record by digest, links the record file and the dispute pointer it signs, and carries the command
that would falsify it. `publish` regenerates the feed from the whole log each time it publishes a
divergence or a record superseding one, and so does `--reconcile`. A withdrawal marks its entry
superseded, and an entry anybody else wrote into the file is gone at the next regeneration. Under
the default, `divergences = "refuse"`, `publish` refuses divergences as before.

### Pruning, once published

```
trigon publish <run>… --prune
```

`--prune` drops each published run's rebuilt artifact from the store, keeping its digests, once the
publication is pushed and recorded on the run; a divergence keeps its bytes, as it does under
`attest --prune`. If the configured publish repository has `rebuilt_artifacts = "github-release"`,
`trigon attest --prune` refuses a run that is not published yet, before signing anything, since
`publish` uploads the artifact from the store when it publishes the run. That includes a run the
gate withholds now, which a confirmation can release later. For a run that no publication would
upload an artifact for, `attest --prune` prunes as before: an exact rebuild, a void run, and the
second of two agreeing attempts whose first is published, which `publish` refuses. Anywhere else,
`attest --prune` prunes as before. Pruning drops the run's reference to its rebuilt artifact, and
deletes the bytes only where no other run still names them. The two attempts of an agreeing pair
rebuilt the same bytes, which the store keeps once, so pruning one keeps them for the other.
`attest`, `rederive`, `serve` and `watch` report a run whose record says its bytes are kept, and
whose store has lost them, as missing them, never as holding them.

### Rotating a key: `log key-change` and `log succeed`

The log records a rotation, and every client follows it from the keys it pinned
([`19`](19-distribution-and-lookup.md) §8). Both commands go through `publish`'s own steps (the
remote's log verified first, `log sign` checking the tree, one commit pushed without force) and take
`--store`, `--repo` and `--dry-run` as `publish` does. A dry run signs nothing, since a signed leaf
printed by a preview, in a CI log for example, would be a hand-over that anyone holding the log key
could append. `log key-change --dry-run` shows the leaf with both signatures empty, and names the
files it would write by path only, because their bytes, and the checkpoint's root, cover the
signatures.

**The attestation key.** `trigon log key-change` logs a key-change leaf signed by both the current
key and the new one:

```
$ trigon log key-change --key ~/.trigon/signing.key --new-key ~/.trigon/signing-2.key
logged    leaf 40: key change: the attestation key 51e4f091d48fee98 hands over to 8702836caee10b5f
commit    bf670c4b… (publish: key change, tree 40 → 41)
```

From that leaf on, `trigon publish` publishes only records signed by the new key, and every client
refuses a record signed by the old one whose leaf comes later. To switch, sign with the new key
(`trigon attest <run> --key <new key file>`, and `trigon rebuild --attest --key` with the same), and
attest again with it any run attested with the old key that is still to be published; `publish`
refuses such a run and says so. Nothing in `evidence.toml` names the key a record is signed with, so
nothing there changes. A `[[source]]` pinning this repository, yours or anyone's, keeps pinning the
key its chain starts at and follows the change from the log, and the repository's
`keys/attestation.pub` stays that key too. The repository's README gains an account of the change.
Only the current key can hand over, and a key the log has retired never becomes current again.

**The log key.** `trigon log succeed` ends the log with a log-end leaf naming its successor (its
origin, its log key and where it is), and begins the successor with a log-continuation leaf holding
the old log's final checkpoint, signed by both log keys:

```
$ trigon log keygen --origin example.com/trigon-evidence/1 --out ~/.config/trigon/log-1.key
$ trigon log succeed --origin example.com/trigon-evidence/1 --log-key ~/.config/trigon/log-1.key
logged    leaf 1: log-end: `example.com/trigon-evidence` is succeeded by `example.com/trigon-evidence/1`, at log/1 in this repository
commit    fa79a80c… (log succeed: `example.com/trigon-evidence` ends, tree 1 → 2; …)
checkpoint example.com/trigon-evidence 2 OtzRAIHy1wtwB6fU8gT6iZ6kBKMKGEpo7GE8rld54NE=
checkpoint example.com/trigon-evidence/1 1 tKNVlIvtcFjtrmngQj8s5yxsVXAlTTumQpxcaN1wZBA=
```

`publish` never opens a log key, so it names the successor's key by running `trigon log public-key
<file>` as a child, and runs `trigon log sign` twice. The first run, with `--successor-key`, holds
both keys, and signs the final checkpoint and cosigns it with the successor's; `log sign` signs a
log-end only then, and only for the key it names. The second, with `--continuing`, begins the
successor, and only as the log that the log-end names. By default the successor is at the next free
`log/<n>` of the same repository, and both leaves go in one commit. With `--url <location>`,
repeatable, the successor is in another repository, at `log` unless `--dir` says otherwise. `log
succeed` then pushes the old log's end first, and begins the successor as the first commit of the
repository at the first URL. If it stops in between, the old log refuses anything more, and running
the same `log succeed` again begins the successor from the final checkpoint already published. A
log-end is permanent, so before writing it `log succeed` clones that repository and inspects it.
With nothing written, it refuses a first URL that names the evidence repository itself, one git
cannot reach, one holding `keys/`, `log/` or the successor's directory, one whose branch names git
attributes, and one that would not take a push, which it asks with `git push --dry-run`. If the old
repository's `kill-switch` is set, the successor's first commit sets it too, with the same words,
and `log succeed` says so. A succession never clears safeguard 5; only a person removing the file in
the successor's repository does.

Then switch to the successor: set `[publish] origin` to its origin and `log_key` to its key (and
`repo` to it, for another repository), and attest again whatever is still to be published, since a
verdict signs the origin of the log it is published into. Once the log has ended, `publish` refuses
to publish under the old origin, and says where publishing continues. Publishing runs or a
withdrawal into a successor in another repository rests on the whole chain, so that an artifact with
a current record in the old repository has one in the new. `publish` reads the logs before it
through an evidence source whose chain reaches them from the chain's first log, syncing that source
first where it is stale; where no source does, it refuses and says how to add one, and `trigon
evidence add <name> <the old repository> --log-key <its first log key> --attestation-key <key>` is
the one to add. It passes over a source pinned to a later log's key, which reads the chain from
partway. A source synced before the old log ended does not hold its end yet, so where none serves,
`publish` syncs every source it has not already synced, however fresh, and looks again; `--dry-run`
syncs nothing, and reads each source from its clone as it is. Keep the old log key: nothing more is
appended to the old log, but a client holding it checks the succession against its final checkpoint.
`keys/log.vkey` stays the first log's key, which clients pin; they follow the succession themselves.

### `trigon serve` and the repository's kill-switch

With a publish repository configured, `trigon serve` reports the repository's `kill-switch` beside
its own `--stop-divergences`, and says which is set. The repository's switch stops what `trigon
publish` publishes, the server's stops what the server shows, and neither stands in for the other.
`serve` reads the repository's switch from the working clone `publish` keeps in the store `serve`
reads, as of that clone's last successful fetch, and reports when that fetch was. A fetch that fails
(the remote unreachable, a credential expired) changes neither the state nor that time, so look into
a report whose time stops moving. The switch is set wherever the branch has anything named
`kill-switch`, and clear only where git lists nothing of that name. With no working clone yet, no
record of a successful fetch, or a tree git cannot read, it is `unknown`, never clear. `serve` reads
it when it starts and every ten seconds after, never for a request, since each read runs `git`. The
state is in the page's header and in `/v1/health` as `kill_switches`, which tells an anonymous
reader the state and when it was read, and not where it was read from.

## Task: keep the evidence sources you trust

You ask evidence repositories (ours, other operators', or mirrors of either) through **sources**. A
source is one log, pinned by its log key, whose name is the log's origin, and by its attestation
key, and served from one or more locations ([`19`](19-distribution-and-lookup.md) §6.1). `trigon
evidence` configures sources and keeps a verified clone of each, and `trigon lookup`, `trigon check`
and `verify-attestation --lookup` answer from those clones (the next task).

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
`[[source]]` into your `evidence.toml` (or the file `TRIGON_EVIDENCE_CONFIG` names, creating it if
it is not there), keeping every comment and the order of what is already in it. Every URL is a
location of the one log, a mirror, and mirrors are how Trigon catches a split view before witnesses
exist. `add` takes a relative path from where you run the command, and writes it absolute. The name
is the source's directory in the cache and the state directory, so `add` refuses a name any source
already has, ignoring case, whichever file or variable added it. `--checkpoint <file>` pins an
initial checkpoint, which must open under the log key; `--required` makes a check fail while the
source cannot answer. `add` refuses a source that pins neither key, or only one of them, unless you
pass `--trust-on-first-use` (below).

**Syncing.** `evidence sync` brings every source up to date in parallel, or only those `--source
<name>` names. Each location has its own clone, at `~/.cache/trigon/evidence/<name>/<sha256 of the
location>/`. `sync` clones a remote shallow, partial and sparse, holding `keys/`, `log/` and
`records/`, and a local path in full, since git ignores depth and filters there (`-v` says so). A
later sync is a fetch and a reset, never a pull. Before accepting anything, `sync` verifies each
clone whole: the checkpoint under the log key, the root recomputed from every leaf, leaf times that
never go back, every key change and succession followed, and a successor in another repository
cloned from the URLs its log-end names and followed there as part of the same source. It also holds
every location to every other: at one size, one root, and at two sizes, the smaller a prefix of the
larger. The largest answers, and `sync` reports a smaller one as lagging. Only then does it write
the state, in `~/.local/state/trigon/evidence/<name>/`: `checkpoint`, the one accepted; `keys`, the
key history the log gives, which the next sync compares with the log, saying so where they disagree;
and `sync`, when it last worked. `--full-history` keeps each clone's whole git history, and says
when a fetch is not a fast-forward.

`evidence sync` exits 0 when every source synced and 4 when any did not. `sync` **refuses** a source
that fails verification, and leaves its clones and state as they were. Verification fails on a
checkpoint that does not extend the one accepted, a clone rolled back behind it, or two locations
that are not one log, and `sync` prints each with both signed notes. A refused source answers
nothing, and every command asking it exits 4, until a sync of it works. A source that could not be
reached still answers from its clone until the clone is stale.

**The first sync, and a lost state.** Without a checkpoint accepted or configured, the first sync
accepts the first checkpoint that verifies under the log key, and says so; from then on every
checkpoint must extend the one accepted. The state directory is therefore what Trigon catches a
rollback against. `sync` refuses a source that has synced before (a clone of it that a sync accepted
is in the cache, or its state records a sync that worked) and has lost its state, and never gives it
a new state without saying so; `evidence sync --accept-state-loss <name>` is how you say the loss is
known. Only what was lost starts over. With the checkpoint gone, the log is held only to its initial
checkpoint, or to nothing but itself, and a source trusting on first use keeps the keys it first
read. With those keys gone, `sync` reads them again from `keys/`, and the checkpoint that was kept
must open under them. A sync stopped partway (killed, or timed out) leaves no clone that counts as
one a sync accepted, and the next sync makes it again.

**In CI**, keep `~/.cache/trigon/evidence` and `~/.local/state/trigon/evidence` together, in one
cache step. The cache means a job pays for a fetch instead of a clone, and the state is what Trigon
catches a rollback against. As far as Trigon can tell, a runner that restores the clones without the
state has lost the state, and `sync` refuses every sync, exit 4, until `--accept-state-loss <name>`.
A runner that keeps neither is a fresh client, and detects a rollback only back to the checkpoint it
is configured with.

**Trust on first use.** A source added with `--trust-on-first-use`, or through
`TRIGON_EVIDENCE_REPO` with `TRIGON_EVIDENCE_TOFU=1`, reads a key it does not pin from `keys/` at
the first location reached on its first sync, and records it in its state. Every later sync is held
to that key, whatever `keys/` says afterwards. Whoever served that location at that moment chose the
key, so every answer from the source says it rests on keys trusted on first use, and where and when
they were read. `evidence list` says so, and so does `verify-attestation --record --source <name>`,
which reads the recorded keys and, as a sync does, refuses a source that has synced before and lost
its checkpoint.

**Freshness.** `[freshness]` sets two clocks. A source whose last successful sync is older than
`stale_after` (a day) is stale: a command that needs it syncs it first and says so, or answers
unknown for it under `--offline` or when that sync fails. A source whose newest leaf is older than
`frozen_after` (fourteen days) is frozen, and answers unknown whatever the sync did, so a host
serving an old but consistent log cannot turn a withdrawal back into a verdict. A log with no leaf
yet is frozen too. An unknown source fails a check only where it is required.

**Listing and removing.** `evidence list` shows each source's origin, its locations and their
transports, whether it is required, the file that added it, whether its keys are pinned or trusted
on first use, when it last synced, the size of the checkpoint it answers from, when its newest leaf
was logged, and how it stands now: fresh; usable from its clone after a failed sync, until it goes
stale; unknown; frozen; or refused. It verifies each clone as a command asking it would, touching no
network (`--output json` for a script). A source whose state files cannot be read says so on its own
row and answers unknown, and `list` shows the others as they are. `evidence remove <name>` takes a
source out of your file, with its clones and its state; it refuses a source the project's
`.trigon/evidence.toml` or `TRIGON_EVIDENCE_REPO` added, and says why. `add` and `remove` write the
file a symlinked `evidence.toml` leads to, and keep the link. A project's sources sync like any
other, and everything Trigon says about one names the file that added it. Trigon fetches a project's
source over HTTPS only, and the same goes for a successor its log names in another repository; it
refuses one at any other location.

---

## Task: look up an artifact, or check a lockfile

With a source configured (above), `trigon lookup` reports what every source says of one artifact or
package, and `trigon check` does the same for every package a lockfile names. Both answer from the
verified clones. They sync a stale source first, and say so, and then fetch nothing per package, so
a thousand-entry lockfile costs one fetch per source. Neither reads `index/`: each resolves a key
from the leaves of each source's log, which the clone holds whole, applying every supersession the
log records.

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

**The key** is whatever you have: npm's `integrity` string (`sha512-<base64>`), `sha256:<hex>`,
`sha512:<hex>` or `sha1:<hex>`, a purl with its version, a purl without one for every version of the
package, or the artifact itself, whose digests `lookup` computes. For a record found by sha1 alone,
the answer says that sha1 is collision-broken.

**Every source answers for itself**, beside its name, the file that added it, the keys it rests on
where it trusts them on first use, and the checkpoint its answer came from. `lookup` shows every
record the key led to with the outcome as a string, the stabilizer set, when it ran and which Trigon
built and signed it, the egress tier and whether it was `attestable`, the derivation, the command
that would falsify it and where to dispute it. A superseded record is struck through (`~~…~~`
without colour), with the record that superseded it, its leaf and the reason. A withdrawn artifact
reads `withdrawn`; a leaf whose record file is gone reads `DELETED`, and its outcome is not shown; a
record that fails verification says why. `lookup` reports two sources that answer differently as
disagreeing, and takes neither answer over the other:

```
disagree  the sources disagree about it:
          `trigon` says normalized
          `theirs` says divergent
          each is its own claim, shown as its source makes it, and neither is taken over the other (docs/19 §6.1)

exit      1: a divergence
```

**`trigon check <lockfile>`** reads `package-lock.json` and `npm-shrinkwrap.json`,
`requirements.txt` and SPDX JSON. It looks each package up first by the digest the file declares
(npm's `integrity`, every `--hash` of a requirement, an SBOM's `checksums`), and by its purl only
where no digest finds a record about the artifact the file pins. A record is an answer about a
package only where its digests are that artifact's. If `integrity` or `checksums` declare more than
one digest, the strongest the record carries decides, as npm installs by the strongest: a record
found by sha1 whose sha512 is another artifact's answers nothing, and `check` reports a sha1 that
disagrees with the sha512 that found a record. A requirement's `--hash`es are alternatives, any one
of which pip installs, and any one matching is enough. A purl whose records all concern another
artifact is not an answer: the package is never checked, and the note says which record was found. A
package whose record carries none of the algorithms the file declares (a PyPI record, and an SBOM's
sha1) is answered, and the answer says the digests could not be compared. Two entries of one name
and version with different digests are two packages, each answered for itself. `check` keeps all of
an SBOM's packages, whatever their ecosystem and whether they carry a purl, and takes a purl with no
version as the version its `versionInfo` gives; it reports a package nothing can answer for as never
checked instead of leaving it out.

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

`--format json` and `--format sarif` carry every source's answer for every package, with each record
it found. The SARIF has a result for every package: `trigon/pass`, of kind `pass` and level `none`,
for one that passes; a result under the rule of what its sources said, where that fails the check;
and, where a source fails the check whatever was answered, `trigon/source-refused` or
`trigon/required-source-unknown`, at level `error`. If a package fails only because a required
source could not answer, `check` does not file it as the warning its answers alone would be. **A
bare `trigon check` answers from the evidence sources.** It used to read `./trigon-store`, and
`--store <path>` still does that (a local store of your own runs, newest run per package, five rows,
exit 0 whatever it reports), with none of the flags below. A store or lockfile it cannot read is the
tool failing, `5`, as it is for every form of `check`.

**Exit codes**, the same for `lookup`, `check` and `verify-attestation`
([`19`](19-distribution-and-lookup.md) §6): `0` every package at or above the threshold; `1` any
divergence; `2` any package never checked, or withdrawn; `3` any void, or any result below the
threshold; `4` any deleted record, any record or source that failed verification, a required source
that is unknown, or no source able to answer at all; `5` the tool could not check (bad arguments, an
unreadable lockfile, no source configured). The first of 5, 4, 1, 3, 2 wins. A package takes the
most severe answer, other than unknown, that any source gives, and counts as never checked only
where no source that answered holds a record for it, so a private source that holds only your own
packages does not make every public one read as never checked.

**The threshold.** `--min exact|normalized|normalized_with_caveats` (the default) is the outcome
floor, and `--max-risk structural|metadata|content|lossy` caps the riskiest stabilizer a verdict may
have been reached through, as its statement signs it: `--min normalized --max-risk structural` is
`Normalized` with `risk <= Structural` ([`05`](05-archive-and-normalization.md) §1). An exact
verdict needed no transform and meets any cap. A package below either gets `3`.

**Freshness, and a source that cannot answer.** A source that is stale and cannot be synced, or is
frozen, answers unknown ([`19`](19-distribution-and-lookup.md) §6). An unknown source leaves only
its own answers missing, and says so, unless it is required (`required = true`, `--require <name>`,
or the one `TRIGON_EVIDENCE_REPO` adds); then every package fails, `4`, and the report says which
source fails it. `--offline` touches no network: a stale source answers unknown without trying.
`--source <name>` asks only the sources named, and Trigon refuses `--require` of a source that
`--source` leaves out, `5`, since that source would never be asked. A source with no clone at any of
its locations, because its URL changed since its last sync, is synced first, as a stale one is.

**`--remote`** asks each source over HTTPS from `raw.githubusercontent.com` instead of from a clone,
for one question where a clone is unwelcome. It reads the checkpoint, held to the pinned key and, by
a consistency proof, to the checkpoint your last sync accepted; a successor's first leaf, held to be
the log-continuation its predecessor's log-end requires; the index file for the key; each record;
and the tiles that prove each record's leaf included. A record whose leaf does not prove fails
verification. A record it cannot read (the host failing or rate-limiting a request, a file not
served, an index entry past the checkpoint it read because a publish landed meanwhile) answers
unknown, and asking again, or syncing, answers it. A source whose last sync was refused answers
nothing this way either, and one whose attestation key you have re-pinned since its last sync is
held to the new pin alone until the next sync. Each time, `--remote` says what it costs: it tells
GitHub which package was asked about, it is rate-limited, and it sees a supersession or a withdrawal
only where the index lists it. It works only for a source with an
`https://github.com/<owner>/<repo>` URL; it refuses any other, exit 5, and `--source` leaves such a
source out.

**Re-deriving a verdict: its falsifying command.** Every verdict signs the command that would
falsify it, and the command runs as written, with the upstream artifact you hold in place of
`<file>`:

```
$ trigon verify-attestation --lookup sha256:0d718245…bd7a4e       --predicate https://trigon.dev/equivalence/v2 --origin github.com/owner/trigon-evidence       --rerun-comparison --upstream ./left-pad-1.3.0.tgz --rebuild ./rebuilt/left-pad-1.3.0.tgz
```

The command resolves the current record in your clone of the source whose log is `--origin`, syncing
only that source, and only where it is stale. If there is no such source, it says so, exits 4, and
resolves nothing elsewhere. It fetches the evidence the record names from the clone's remote, which
names the record to that host, and says so; checks the record as `--record` does; and re-derives the
verdict from the two artifacts, holding the published comparison report to it member by member. If
your own sources hold the origin, it sets aside a source that a project's `.trigon/evidence.toml`
added and that gives the origin to a log key of its own, and says so; if two of your own sources
give the origin to different keys, the command refuses them as ambiguous, `5`. It weighs every
source it asks as `lookup` weighs it, so a required source that cannot answer fails the check even
though another holds the record. A void has no claim to re-derive, and the command reports it as the
void it is, `3`. The rebuilt artifact is `--rebuild <file>`, the output of rebuilding under the
record's published strategy; given that, the command fetches nothing for it.

Without `--rebuild`, the command looks for the rebuilt artifact in the repository that holds the
record, whatever your own `[publish] rebuilt_artifacts` says, since that setting covers what you
publish, not what the source does. It looks for the release asset `sha256-<hex>` of the digest the
verdict signs in the `rebuilt-YYYY-MM` releases of that repository on GitHub, named by an HTTPS or
an SSH location (a successor's, after a succession into another repository), asking GitHub's API
without a token, and then in the releases of any other source of yours that holds the record. It
does not ask a source that a project's `.trigon/evidence.toml` added where one of yours resolved the
record. It lists only the series of the month the record was logged in and the months either side,
which is where `publish` puts the asset, so a lookup costs a few of the sixty requests an hour
GitHub allows without a token. It downloads the asset into a file of its own, in a directory made
for it that only you can enter, and holds it to that digest. The command refuses other bytes in the
repository of the source that resolved the record, `4`; other bytes in another source's repository
are that repository's, and the command asks the next. Downloading the asset names the artifact to
GitHub, and the report says so however the check ended.

An exact verdict's rebuilt artifact is the published artifact itself and is never uploaded, so the
command asks GitHub nothing and takes the upstream file as the rebuilt artifact too, held to the
digest the verdict signs: its falsifying command runs as signed, with `--upstream` alone. The
command does not make the check, exits `5`, and asks for `--rebuild <file>` if no repository that
holds the record is on github.com (which asks GitHub nothing), if none holds such an asset, or if
GitHub refuses or cannot be reached.

`verify-attestation --record <file> --source <name>` without `--evidence` reads the same clones,
following the source's chain into every repository its log has gone on in; it is in the verifier
build too, and fetches nothing.

**The `stopped` field.** If either form of `verify-attestation` stops before it has a record to
report on, `--output json` prints `{exit, stopped, error, signedNotes}`: the exit code; the cause,
from the table below; the reason, as the text gives it; and, for an equivocation or a rollback, both
signed notes, `null` otherwise. `stopped` names the cause, so `failed-verification` appears for a
record and for nothing else. The one stop with no document is an argument that `clap` itself refuses
(a flag it does not know, a flag without its value, a value it does not take), which comes before
`--output` is read: exit `5`, `clap`'s message on stderr, and nothing on stdout.

| `stopped` | exit | the cause |
| --- | --- | --- |
| `cannot-check` | `5` | it could not check at all: an unreadable input, no such source, a rebuilt artifact that could not be had, or bad arguments other than those `clap` refuses |
| `equivocation` | `4` | two different logs under one key; `signedNotes` holds both, with the directory each came from |
| `inconsistent` | `4` | the log does not extend the checkpoint it is held to, a rollback or a rewrite; `signedNotes` holds the checkpoint accepted and the one offered |
| `log-failed-verification` | `4` | the log failed verification otherwise: a signature, a tree, a leaf against the log's rules, a key change |
| `log-unreadable` | `4` | the log could not be read: a file of it missing, unreadable or malformed |
| `failed-verification` | `4` | a record failed verification or was deleted, or a file it names is other bytes than it signs: a release asset in the repository of the source that resolved it |
| `source-refused` | `4` | a source failed verification as a whole, its last sync refused or its clones not verifying, and no record was checked |
| `source-unknown` | `4` | a source cannot say what it says now (required and unknown, every one asked unknown, or its clones not there to be read), and no record was checked |
| `no-source` | `4` | `--lookup`: no source configured here has the log `--origin` names |
| `no-current-record` | `0`–`3` | `--lookup`: the subject has no current verdict or void (never checked, withdrawn, or only a record of another predicate than `--predicate`), and the command exits with what the sources say of it instead |

`no-current-record` is not a failure; the command reports it as the answer it is, never with
`Error:`.

---

## Configuring where evidence goes: `evidence.toml`

Publishing and looking up verdicts in an evidence repository
([`19-distribution-and-lookup.md`](19-distribution-and-lookup.md)) are configured, never compiled
in. `trigon attest`, `trigon publish`, `trigon log init`, `log key-change`, `log succeed`, `trigon
serve` and `trigon worker` read the configuration today. `serve` and `worker` read
`same_host_confirmation`, `same_host_local_images` and `confirmation_interval`, which decide when
two attempts count as two, and `serve` also reads `[publish] repo` and `branch`, to report the
repository's kill-switch. `trigon evidence` reads and writes the `[[source]]` tables and reads
`[freshness]`, and `trigon lookup`, `trigon check` and `verify-attestation` read them too.

The file is `~/.config/trigon/evidence.toml` (`$XDG_CONFIG_HOME/trigon/evidence.toml`), or whatever
`TRIGON_EVIDENCE_CONFIG` names instead. Every key, with its default:

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
same_host_local_images = false                        # only beside same_host_confirmation
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
when **both** are set, and leaves both out when either is not. Leaving them out is right for local
use, and `publish` refuses such a verdict.

**An unknown key is an error**, and so is a value of the wrong kind, a pin that does not parse, or a
source without both keys that does not ask for trust on first use: if Trigon ignored a typo in a
security setting, the setting would be off and nothing would tell you. The error names the file and
the key, and the command exits `5`:

```
$ trigon attest
Error: /home/you/.config/trigon/evidence.toml: TOML parse error at line 2, column 1
  |
2 | orign = "github.com/owner/trigon-evidence"
  | ^^^^^
unknown field `orign`, expected one of `repo`, `branch`, `origin`, `disputes`, …
```

**Locations.** Trigon passes a URL to `git` as written, so credentials are `git`'s own (an SSH key,
a credential helper). It refuses a URL carrying a password, and an `https://`, `http://` or `git://`
URL with any user name in it (`https://<token>@github.com/…` is how a token is written there); tell
a credential helper the user with `git config credential.https://<host>.username` instead. An SSH
user, `git@github.com:…`, names the account and is kept. Trigon makes a path absolute: it expands
`~/`, and takes a relative path from the directory of the file that names it. `git` reads a colon
before the first slash as SSH, so Trigon refuses `backup:evidence`; write `./backup:evidence`,
`file://…`, or `ssh://backup/…` for a host alias.

**A source by any location.** One log may be served from several places, each written as `git` takes
it. Trigon treats each as a mirror, clones it, and holds it to the others:

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

or, for one run, the same from the environment, as a required source named `env`:

```
$ TRIGON_EVIDENCE_REPO='https://github.com/owner/trigon-evidence.git file:///srv/mirror.git' \
  TRIGON_EVIDENCE_LOG_KEY='github.com/owner/trigon-evidence+1a2b3c4d+AR…' \
  TRIGON_EVIDENCE_ATTESTATION_KEY=<64 hex> trigon check package-lock.json
```

`--remote` needs an `https://github.com/<owner>/<repo>` location among them; everything else reads
the clones, whatever the transport.

**The environment** overrides the files for one run: `TRIGON_PUBLISH_REPO` for `[publish] repo`;
`TRIGON_EVIDENCE_REPO` (locations separated by spaces) adds a required source named `env`, pinned by
`TRIGON_EVIDENCE_LOG_KEY` and `TRIGON_EVIDENCE_ATTESTATION_KEY` (refused without both unless
`TRIGON_EVIDENCE_TOFU=1`), with `TRIGON_EVIDENCE_CHECKPOINT` as its optional checkpoint; and
`TRIGON_EVIDENCE_CACHE` and `TRIGON_EVIDENCE_STATE` replace the directories clones and sync state
are kept in (`~/.cache/trigon/evidence`, `~/.local/state/trigon/evidence`). With `rebuilt_artifacts
= "github-release"`, `publish` reads its GitHub token from `GITHUB_TOKEN`, or else `GH_TOKEN`, and
nowhere else.

**A project's own sources.** Trigon also reads `.trigon/evidence.toml` in the working directory,
unless `TRIGON_EVIDENCE_CONFIG` is set. Whoever controls the project chooses that file (in CI, the
author of the pull request), so it may only add `[[source]]` entries under new names, each with both
keys and an initial checkpoint, HTTPS URLs only, and files inside the project. The file itself must
be inside the project too, once symlinks are followed, and a regular file of at most 64 KiB.
Anything else makes Trigon refuse the whole file, naming the rule it broke. Trigon compares source
names ignoring case, in every file, since each is a directory under `~/.cache/trigon/evidence`.

---

## What a run leaves behind

Every terminal outcome writes `<work>/NNN/run.json`, whether the run reproduced, diverged, failed to
build, or never found a recipe. Beside it are `strategy.yaml` (the recipe as rendered), `guard.json`
(the manifest the artifact guard checked against), `rebuild/build.log` (the container's own output)
and `rebuild/network.jsonl` (every response that crossed into the build, one per line).

Read `run.json` first. These fields answer "why should I believe this":

| Field | What it settles |
|---|---|
| `source` | The repository, commit and subdirectory the artifact was rebuilt from, plus `how`, the rung that found the commit, and `declared_url`, what the registry said before we canonicalized it |
| `derivation`, `confidence`, `assumptions` | The rung that produced the recipe, how much to believe it, and every guess it had to make |
| `declines` | One line per rung that was asked and said no, with its reason. Without it, a `no-strategy` is a verdict with no explanation |
| `attestable`, `egress`, `network_exchanges`, `network_bytes` | Whether all of the build's egress is accounted for, and what crossed |
| `pin` | What the time-filtering mirror was asked for and what it withheld: evidence that the moment *bound*, rather than that it was configured |
| `guard_trips`, `refused_artifact`, `guard_notes` | The artifact guard tripping (the run is void), the build asking for its own artifact and being refused (the control working), and near-misses |
| `failure`, `timings` | The classified failure and where the time went. A `None` timing means no data, never zero |

**Do not skip `source.how`.** `registry_commit` is npm's own `gitHead`. `exact_tag` is a tag whose
name is the version. `fuzzy_tag` means we matched `python-ecdsa-0.19.2` to version `0.19.2` by
stripping a prefix, which is reasonable but a weaker claim than the first two. Do not read a verdict
built on one as you would a verdict built on the other.

The signed statement carries the same facts: `rebuild/v1`'s `resolvedDependencies` carries the
repository, the `gitCommit` digest, and annotations for `discovery`, `ref`, `subdirectory` and
`declaredUri`. See [`09-attestations.md`](09-attestations.md) §2.1.

**Not written to a file:** our own `tracing` output, which goes to stderr at `warn` by default (`-v`
for info, `-vv` for debug, or `RUST_LOG`). The structured records above are the audit trail; the log
is for watching a run happen.

## What a verdict does not tell you

This list comes from [`threat-model.md`](threat-model.md), which gives the precise contract.

- **`attestable` means the egress is accounted for, and nothing more.** A run at `mirror-only` or
  `deny-all` records a network transcript (every response that crossed into the build, with its
  digest), and `attestable: true` says that account is complete. It does **not** say the sandbox
  class, the base image or the strategy are good enough to sign. A run at `open` records no
  transcript and says so.
- **The artifact guard compares bytes.** A build that fetches the published artifact re-encoded,
  encrypted, or reassembled from chunks defeats it.
- **An enforced egress tier bounds which hosts a build reaches, never what those hosts serve.**
  `registry.npmjs.org` will serve anything anybody published.
- **One run is not a confirmed result.** Trigon publishes a verdict only once a second attempt
  agrees (see *Task: confirm a run*), but the verdict `trigon rebuild` prints on your screen is one
  attempt, and a divergence in it may be the build's own nondeterminism rather than the package's.
- **Build logs are not redacted.** If your build environment carries credentials, they may appear in
  a stored log.
- **A published reproduction rate describes the pipeline, not an ecosystem.** The corpora are small
  smoke sets, and were not sampled for prevalence.

---

## Troubleshooting

**`base image … is not pinned by digest`**: use `name@sha256:…` (see above).

**`could not start the mirror container` / `names must match [a-zA-Z0-9]…`**: an old symptom of
podman reading a relative `--work` path as a volume name. The bug is fixed, but if you see any
variant of it, pass an absolute `--work`.

**`Build one with 'trigon mirror-image'`**: an enforced tier needs the mirror image, which you build
once.

**`cannot infer a format from '…'; pass --format`**: the file name does not say what the artifact
is. A `.gem` is a tar, and only the ecosystem knows that; pass `--format` and `--profile`.

**`trigon does not speak gem; this build knows npm, pypi, cargo, nuget`**: the ecosystem in your
PURL has no registry client yet. RubyGems has a stabilizer profile, so `trigon verify` compares two
`.gem` files, but nothing resolves or rebuilds one.

**A build that appears to hang**: a container build is minutes of silence. `-v` says what phase it
is in; `-vv` streams the build's own output.

**`unknown` as a failure signature**: Trigon could not name the failure from the build log. It still
records the run, and the log stays on disk under `--work`.

---

## Where to go next

- [`README.md`](../README.md): two complete worked examples with real output.
- [`threat-model.md`](threat-model.md): what Trigon assumes, what it guarantees, and what it
  disclaims. §1.13 lists what a consumer is expected to check for themselves.
- [`16-findings.md`](16-findings.md): where building Trigon proved the design wrong. Read it before
  you believe any of the design chapters.
