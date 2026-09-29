# 19. Publishing verdicts, and looking them up

**Status: built through §10 phase 6**, apart from phase 5's spike against a scratch GitHub
repository, which has not been run; phases 7a, 7b and 9 wait on decisions.
[ADR-0014](adr/0014-git-evidence-store-without-rekor.md) (accepted) records the decisions this
chapter argues for. §10 is the build plan, and §11 lists the decisions it waits on. What exists
today:

| | Status |
|---|---|
| Signing: DSSE and in-toto, with an ed25519 key we hold | built (`trigon attest`) |
| ADR-0010's publication gate (`publication::decide`) | built, and consulted by `trigon serve` only, not by any publishing path |
| `verify-attestation --rerun-comparison`, `Match::is_at_least` | built |
| A lockfile check by purl against the local store (`trigon check`, `POST /v1/check`) | built; §6 says what it lacks. §10 phase 0 closed its leak ([findings](16-findings.md) §3.93) |
| Rekor publication (`attest --rekor`) and verification (`verify-attestation --transparency`) | built, measured, and **removed** (ADR-0014; §10 phase 1, [findings](16-findings.md) §3.94) |
| Subjects with sha512, and sha1 for npm, beside sha256 (§5); fetchers that verify every digest their registry declares, and runs that record what was declared (§5); the strategy, guard manifest and building version kept on the run (§4.2 items 3, 7); attestations per run, append-only | built (§10 phase 2, first half; [findings](16-findings.md) §3.95) |
| The v2 verdicts with every §4.2 field, `void/v1` and `withdrawal/v1`, the record file's types, the versioned purl canonicalisation, and a building version that names its git revision | built (§10 phase 2, second half; [findings](16-findings.md) §3.96) |
| The configuration of §2.4: `evidence.toml`, the project's file, the environment, locations and pinned keys | built and read by `attest`, `serve`, `worker`, `publish`, `trigon evidence`, `lookup`, `check` and `verify-attestation` (§10 phases 2, 3, 5, 6) |
| A publishable run: every cache key built from the target, the strategy and the set, worker and CLI alike; attempts that agree on what the comparison found, not on its outcome string; `trigon rebuild --confirm <run>`, cold and re-pulled; each attempt's host, cache state and start; `decide`'s rules for a pair, from `same_host_confirmation` and `confirmation_interval`; and a worker's confirmation made on another machine unless `same_host_confirmation` allows its own | built (§10 phase 3, backlog B31; [findings](16-findings.md) §3.97) |
| `rebuild --attest` signing through `attest`'s own code, so no path signs a verdict for a run the gate voids; `rebuild/v1` naming the model exchange a run kept; a `pkg1` key that is the package alone | built (§10 phase 3; [findings](16-findings.md) §3.97) |
| The evidence log as pure code: C2SP signed notes and checkpoints, the log key in Go's format, RFC 6962 inclusion and consistency proofs, tiles and entry bundles and what an append writes, every leaf kind of §2.3, a log verified from its files, and key-change, log-end and log-continuation leaves followed as §8 says | built (§10 phase 4, first half; [findings](16-findings.md) §3.98) |
| Records verified against the log, lookup over its leaves with every supersession applied, the paths of records, evidence and the index, and the index derived from the log; `verify-attestation --record` in the network-free verifier, with keys and checkpoint from `--source` or from flags, showing every §4.2 field; `--rerun-comparison` re-deriving what a verdict says the comparison found and holding the published report to it; two trees under one log key refused as an equivocation; and the threat model's properties for record, inclusion and consistency verification (P31–P33) | built (§10 phase 4, second half; [findings](16-findings.md) §3.99) |
| The evidence repository and its writer: `trigon log keygen`, `log init` and `log sign`, and `trigon publish` for runs, withdrawals and heartbeats, with `--dry-run` and `--reconcile` — the remote's log verified before anything is built on it, the gate asked through the index `serve` uses, one commit pushed without force, a lost race discarded and built again, `RunRecord.published`; and a logged verdict without its falsifying command, or a divergence without its dispute pointer, failing verification | built (§10 phase 5, first half; [findings](16-findings.md) §3.100) |
| Rebuilt artifacts as release assets, uploaded before the commit that names them and reused on a retry; the divergence feed, regenerated from the log; `log key-change` and `log succeed`, followed by a fresh verification, with publishing going on into a successor in this repository or another; `publish --prune`, and `attest --prune` refusing a run not yet published; `serve`'s report of the repository's kill-switch beside its own | built (§10 phase 5, second half; [findings](16-findings.md) §3.101) |
| The phase 5 spike against a scratch GitHub repository | written (`scripts/evidence-spike.sh`) and **not run**: it needs a repository of the owner's naming, which nothing here creates (§10 phase 5; [findings](16-findings.md) §3.101) |
| `trigon evidence add`, `list`, `remove` and `sync`: sources written into `evidence.toml` keeping its comments; a verified clone of every location in the cache, and each source's checkpoint, key history and last sync in the state directory, written only once everything verifies; a checkpoint that does not extend the accepted one, and a rollback, refused with both notes; mirrors held to one another; a successor in another repository followed as part of the source; trust on first use recorded and labelled, and read by `verify-attestation --record --source`; a lost state refused until `--accept-state-loss`, which starts over only what was lost; and the two freshness clocks, as the standing every command asking a source reads. `publish` reading the whole chain, from its first log, when it publishes into a successor elsewhere; pruning that keeps bytes another run still names, and takes turns with the writers that name them | built (§10 phase 6, first half; [findings](16-findings.md) §3.102) |
| `trigon lookup` over the verified leaves of every source, per source and never merged, with every §4.2 field and state, supersessions struck through, and sources that disagree said to; `trigon check` against the sources — one sync and then no request, by digest first and purl second, every package of an SBOM kept, `--min`, `--max-risk`, `--require`, §6's exit codes, per-source detail in text, JSON and SARIF — with `--store` keeping the old check; the lockfile parser keeping npm's `integrity` and `resolved`, `--hash`, and SBOM `checksums`; `verify-attestation --lookup`, resolved in the source of its origin, its evidence fetched on demand from the partial clone and its rebuilt artifact from `--rebuild` or else the release asset of the GitHub repository that holds the record, whatever the client's own `rebuilt_artifacts`; `--record --source` reading the source's clones across repositories; `--remote`, proving each leaf from the tiles; a sync removing clones of locations no longer configured; and `serve` showing a run's published record, and `/v1/artifacts/{alg}:{digest}` honouring its algorithm over every run | built (§10 phases 6, second half, and 6c; [findings](16-findings.md) §3.103) |

---

## 1. The problem, which is not the one it looks like

Trigon produces a signed statement about somebody else's package. Every existing way to distribute
such a statement assumes the **publisher** made it:

- npm serves provenance at `/-/npm/v1/attestations/{pkg}@{ver}`, written by `npm publish
  --provenance`.
- PyPI serves PEP 740 attestations from its Integrity API, linked from each file in the simple
  index, and they are uploaded with the distribution.
- GitHub's attestation API stores Sigstore bundles under whichever repository uploaded them, and is
  queried per repository, organisation or user. We could write there only under our own name and
  only in Sigstore's format, and a consumer would still have to know to ask us.

We are not the publisher and will never be able to write into the first two, and the third helps
only a consumer who already knows to ask us. **The distribution problem for a third-party rebuilder
is a different problem, and pretending otherwise is how this ends up as a repository nobody can
find.**

There are two distinct questions hiding here, and conflating them is the usual failure:

1. **Where do the bytes live?** A storage and transport question. Several good answers.
2. **How does a consumer know to ask?** A discovery question. Almost no good answers, and it is the
   one that decides whether any of this gets used.

The only query that works without a naming authority is **by artifact digest**, because the consumer
already holds the artifact. Everything else — by name, by purl, by ecosystem — needs somebody to
agree that *we* are the place to ask. So whatever gets built, the primary key is the digest of the
published artifact and the purl is a secondary key.

---

## 2. Where the bytes live

### 2.1 What was considered

**A transparency log (Rekor).** Built as `trigon attest --rekor` — `intoto` v0.0.1 over the v1 API,
signed with a key we hold, per [ADR-0011](adr/0011-keyed-signing-under-a-trusted-root.md) — measured
against staging, and removed by ADR-0014. Three measurements decided it.

- **It commits hashes, not documents.** An `intoto` v0.0.1 entry's committed body is the envelope
  hash, the payload hash and the verification key or certificate, and no field of the statement,
  whatever the outcome. The fields an earlier draft of this chapter wanted a log entry to "carry" —
  the outcome, the set digest — cannot be committed by any entry type that takes an in-toto
  statement.
- **It serves the documents anyway, uncommitted, and that is worse.** Rekor v1 stores the decoded
  payload when it is 100 KiB or less and serves it, searchable by the artifact's own digest: staging
  entry 56042318 returns a whole Trigon `equivalence/v1`, and a query by the chardet wheel's sha256
  returns our entries. An earlier version of this section said the index returns `[]` for an
  artifact digest; that was measured against a fixture whose subject was a placeholder, and it was
  wrong. A divergence logged this way would sit, in full, in storage we cannot correct, which is
  exactly §3's concern — and `attest --rekor` logged divergences without consulting the publication
  gate.
- **Its successor cannot take our statements.** Rekor v2 accepts only `hashedrekord`, which rejects
  pure Ed25519, keeps no attestation storage, issues no signed entry timestamp, and has no search in
  the log itself (Sigstore plans a separate search service).

What survives is the lesson: **a transparency log dates a claim somebody already holds; it is not
where a consumer finds one.**

**An OCI registry (GHCR).** Designed in detail and set aside. Content-addressed and CDN-backed, but
for this job every property counted against it. GHCR has no OCI 1.1 referrers API (`GET
/v2/<name>/referrers/<digest>` returns 404, measured 2026-09-23), so lookup means tags that a
client-maintained index keeps by read-modify-write, and concurrent writers to one tag silently drop
entries (miracum/.github#212). Answering a lockfile privately meant publishing that index again as
signed prefix shards, with their own binding and completeness problems. A registry and a history
mirror cannot be pushed atomically, and the ordering that avoids our own log key signing two
different checkpoints of one size is delicate. A new package starts private and is made public by
hand, irreversibly. Push from outside GitHub Actions needs a classic personal access token. And it
needs a registry client, which on the Rust side means either `oci-client` — a second HTTP stack and
about 25 new crates — or one of our own. Neither cosign nor oras attaches to a subject that is not
itself in the registry, so none of the OCI tooling would read our records anyway. The design stays
shaped so that a registry could be added later as a second implementation of the same store (§2.2),
if a private operator ever needs one.

**The registries themselves.** npm, PyPI and friends serving third-party rebuild attestations beside
publisher provenance. This is the endgame and it is a standards conversation, not a plan;
`docs/10-scale.md` §2 already says we have to talk to the registries before the first real sweep.

### 2.2 The decision: a public git repository, cloned to be read

**One public GitHub repository, `github.com/<owner>/trigon-evidence`, holds everything: the records,
the evidence log, and the lookup index, all as files.** A publication is one commit, and a consumer
clones the repository — alongside any other evidence repositories it chooses to trust (§6.1) — and
queries its own copies. Where the repository is, for a publisher and for a consumer, is
configuration, never code (§2.4).

- **The records** are files (§4): one per published result — a verdict, a void, or a withdrawal —
  holding the signed statements, with the evidence needed to re-derive the comparison stored beside
  them by digest.
- **The evidence log** is files too: an append-only log that we sign, with one small leaf per
  published record, a Merkle tree over the leaves, and its root signed as a checkpoint (§2.3). Its
  job is to make it impossible for us to quietly change our minds, and it is what a client reads to
  find a record.
- **The lookup index** is paths derived from each record's keys (§5), for readers that do not hold
  the log. It is derived data, rebuilt from the log whenever it is in doubt.
- **Large artifacts** — the rebuilt artifact, if D4 decides to publish it — do not go into git. They
  are release assets of the same repository, named by digest, and a record names them by digest
  (§4.1).

Why git fits this job:

- **A commit is atomic, and a non-forced push is a compare-and-swap.** The record, its leaf, its
  index paths and the new log checkpoint land together or not at all, and a second writer's push is
  rejected rather than interleaved, so a partial publication is never visible. The one hazard left,
  a checkpoint signed for a push that then loses, is contained by publishing from one host under a
  lock (§10 phase 5).
- **Reading is a clone, and a clone is private.** A consumer who clones learns nothing about which
  of their dependencies they then look up, and the per-dependency request leak disappears. A
  thousand-entry lockfile is checked with no network requests at all once the clone is fresh.
- **Every clone holds the whole log.** A rewrite shows up as a leaf with no record file, or as a
  checkpoint that does not extend the one a client already holds; a clone kept with `--full-history`
  also shows a rewritten commit.
- **No new client.** Trigon already shells out to `git` to fetch sources; publishing and syncing do
  the same.
- **It is public, forkable and greppable,** disputes can be issues on the same repository, and it
  costs nothing.

The design keeps the store behind a narrow seam — write these files atomically with the new
checkpoint; read a file by path — with one implementation, per ADR-0008. The file layout refers to
nothing git-specific, so a registry or a bucket could be a second implementation later without
changing a signed byte.

The log holds hashes; the records hold documents; a record is bound to its leaf by digest, and a
consumer checks both.

### 2.3 The repository layout, and the log format

```
trigon-evidence/                          main: a ruleset forbids force-push and deletion
├── README.md                             origin, keys, checkpoint rate, how to dispute, rotations
├── keys/                                 copies for people, and for trust on first use (§2.4);
│   │                                       the keys the chain starts at, whatever rotated since
│   ├── log.vkey                          C2SP verifier key for the log
│   └── attestation.pub                   ed25519 SPKI PEM
├── log/                                  C2SP tlog-tiles
│   ├── checkpoint                        rewritten by every publication
│   └── tile/
│       ├── 0/000 … 0/003                 full level-0 tiles: 256 leaf hashes each
│       ├── 0/004.p/177                   one partial per checkpoint size since 0/003,
│       ├── 0/004.p/180                     all removed in the commit that writes 0/004
│       ├── 1/000.p/4
│       └── entries/
│           ├── 000 … 003                 256 leaves each, length-prefixed canonical JSON
│           ├── 004.p/177
│           └── 004.p/180
├── records/
│   └── 7f/3a/7f3a…c2.json                one per published record, named by its sha256
├── evidence/
│   └── sha256/
│       ├── 51/d0/51d0…3b                 a stabilizer-set manifest, shared by many records
│       ├── 3d/88/3d88…1a                 a comparison report
│       ├── b0/2f/b02f…77                 a strategy, as canonical JSON
│       └── e5/c9/e5c9…04                 a guard manifest
├── index/                                for --remote and for tools that do not read the log
│   ├── sha512/1d/f6/1df6….json           the full 128-hex digest; npm's integrity
│   ├── sha1/0e/7c/0e7c….json             npm's shasum
│   ├── sha256/8b/2e/8b2e….json
│   ├── purl1/c4/19/c419….json            sha256 of "pkg:npm/left-pad@1.3.0"
│   └── pkg1/a0/5d/a05d….json             sha256 of "pkg:npm/left-pad": every version
├── feed/
│   └── divergences.atom                  if D7 chooses a feed; the most recent 200 entries
└── kill-switch                           present only while divergence publishing is stopped
```

Rebuilt artifacts, if D4 publishes them, are not in the tree: they are release assets, one release
per month (`rebuilt-2026-09`), continued as `rebuilt-2026-09.2` and so on when a release reaches
GitHub's limit of 1,000 assets, each asset named `sha256-<hex>` and under GitHub's 2 GiB limit. The
fan-out is four hex characters, `<aa>/<bb>/`, everywhere, so at a million records a directory holds
some fifteen files; GitHub recommends at most 3,000 entries in a directory, and its file browser
lists only the first 1,000. A consumer's default clone checks out `keys/`, `log/` and `records/`;
`index/`, `evidence/` and the release assets are fetched only when a command needs them (§6).

A rotation (§8) leaves `keys/` as it is: the keys there are the ones the chain of logs starts at,
which is what a client pins and what trust on first use reads, and a client follows every key
change and succession from them itself. The README's account of key changes and successors is
regenerated from the log with each rotation, and names the keys after them. A successor in the same
repository is at `log/<n>/`, laid out as `log/` is. The old log's final checkpoint, in its
`checkpoint` file as in the successor's first leaf, carries the successor's cosignature beside its
own key's, which a reader of the old log ignores as it ignores a witness's.

The log is C2SP tlog-tiles with a C2SP tlog-checkpoint from its first leaf, so nothing about it
changes when witnesses are added (§10 phase 7b). The files are laid out as tlog-tiles specifies, but
`raw.githubusercontent.com` serves them as `text/plain` with a five-minute cache, which is not a
conforming tlog-tiles endpoint, so a generic tlog tool reads them from a clone.

- **Origin and key.** The origin line is `github.com/<owner>/trigon-evidence` for the first log, and
  `github.com/<owner>/trigon-evidence/<n>` for its n-th successor, whether a log-key rotation or a
  D2 rollover made it: schema-less, and permanent for that log. The checkpoint is a C2SP signed note
  under an Ed25519 key (vkey type 0x01) whose name is the origin. The witness network requires the
  Ed25519 key and recommends the schema-less origin, and both hold from the first checkpoint. That
  key is the log key, separate from the attestation key (§8). The first log's files are at `log/`; a
  successor in the same repository is at `log/<n>/`.
- **Leaves.** Every leaf is canonical JSON (`trigon_core::jcs`) with a `kind` and a `time`, the Unix
  seconds at which we logged it, never earlier than the previous leaf's; its hash is RFC 6962's
  SHA-256(0x00 ‖ leaf). A `record` leaf holds the subject's digests; the canonical purl and its
  canonicalisation version; the predicate type and outcome; the stabilizer-set digest; the signing
  key's id; the record file's digest; and, for a supersession, the superseded record's digest and
  the reason. A void's record leaf has the outcome `void`, and its set digest where its run
  compared, as `void/v1` has it — a build the guard stopped compared under no set; a withdrawal's
  has neither. The other kinds are:
  - `heartbeat`, which carries only its time, and is appended when nothing else has been logged for
    a week (§7);
  - `key-change`, which names the old and new attestation keys and carries a signature by each (§8);
  - `release`, which carries a client release's digests and a signature by the release key (§6, §10
    phase 9);
  - `log-end`, the last leaf of a log being succeeded, which names the successor's origin, its log
    vkey, and where it is: clone URLs and a directory (§8);
  - `log-continuation`, the first leaf of the successor, which holds the old log's final checkpoint,
    cosigned by the new log key (§8).
- **Framing and position.** An entry bundle frames each leaf with a big-endian uint16 length, as
  tlog-tiles specifies, so a leaf is at most 65,535 bytes; ours are under 1 KB. A leaf's index is
  its position: the size of the checkpoint the publication built on, plus its place in the
  publication. Nothing signed contains it.
- **Immutability.** Full tiles, full entry bundles, record files and evidence files are never
  modified or removed. A partial tile or bundle is never rewritten either: a wider partial is a new
  file beside it, and every partial of a tile is removed in the commit that writes the full one, as
  tlog-tiles allows. Otherwise only `log/checkpoint`, the index files, `kill-switch`, the feed and
  the README change.
- **No extension lines.** A witness's cosignature makes no statement about a checkpoint's extension
  lines, and an ML-DSA-44 cosignature does not cover them at all, so the time is in the leaves,
  where the tree commits to it (§7).
- **Rate.** The README states how often a new checkpoint can appear — once per publication, and at
  least weekly from the heartbeat — because the witness network's application asks for it.

What the log's files hold — illustrative, since phase 4 fixes the schema. `log/checkpoint` is a
signed note:

```
github.com/<owner>/trigon-evidence
1204
kP0Qm2h4y3cXq1N9vT0Jx8m1b7r2Wf3e5A6s8D0f1g4=

— github.com/<owner>/trigon-evidence Gk7v2eQx…
```

and one record leaf, as it sits inside `log/tile/entries/004.p/180`, is:

```json
{"kind": "record", "time": 1790467200,
 "subject": {"sha512": "1df6…", "sha1": "0e7c…", "sha256": "8b2e…"},
 "purl": "pkg:npm/left-pad@1.3.0", "purlCanon": 1,
 "predicateType": "https://trigon.dev/equivalence/v2", "outcome": "normalized",
 "stabilizerSet": "sha256:9c41…e0", "keyId": "4f1c09a2b7e3d586",
 "record": "sha256:7f3a…c2"}
```

A publication is one commit touching all of it together — the new record, any new evidence, the
appended tiles, the new checkpoint, one index file per key, and the feed for a divergence — with a
message such as `publish: 3 records, tree 1201 → 1204`. The history of `main` therefore reads as the
list of everything ever published.

### 2.4 Where the repository is, and how Trigon is told

Nothing about a repository's location is compiled in. The repository `publish` writes to, and every
repository a consumer syncs, is named in configuration or in the environment, and may be anything
`git` itself can clone from or push to.

**A location** is one of:

- an HTTPS URL, such as `https://github.com/<owner>/trigon-evidence.git`;
- an SSH URL, in either form: `ssh://git@example.org/owner/trigon-evidence.git` or
  `git@github.com:<owner>/trigon-evidence.git`;
- a `git://` or `http://` URL;
- a `file://` URL, or a local path: absolute, relative, or starting with `~/`.

Trigon passes a URL to `git` unchanged, so anything `git` accepts is accepted and nothing it rejects
is worked around. A local path is made absolute first: `~/` is expanded, and a relative path is
taken from the directory of the configuration file that names it, or from the working directory when
it comes from the environment or the command line. A path with a colon before its first slash is
read by `git` as an SSH location, so such a path is written with a leading `./` or as `file://`;
the scp form is taken as SSH where the part before the colon is `user@host`, a name with a dot, or
a bracketed IPv6 address, and anything else before a colon is refused with that advice (a host
alias is written `ssh://alias/…`). A URL carrying a password, an `https://`, `http://` or
`git://` URL naming any user — the place a token goes, so a name there is refused as a token would
be — a git remote helper (`<transport>::…`) and any other scheme are refused, and a refusal prints
the location with its user part as `***`.
Plain-text transports (`git://`, `http://`) are allowed, because integrity rests on the signatures
and the log rather than on the transport, and Trigon says which transport it used. **Credentials are
`git`'s own** — SSH keys, a credential helper, `GIT_ASKPASS` — and Trigon never reads, stores, logs
or passes a git credential. The one exception is uploading rebuilt artifacts, if D4 publishes them,
which is GitHub's REST API rather than git and takes a token from the environment, `GITHUB_TOKEN`
or `GH_TOKEN` (§10 phase 5).

**Local paths.** For syncing, a local path is cloned like any remote, so only what is committed
there counts, and it is verified exactly like a remote. For publishing, a local path to a bare
repository is a remote like any other. A local path to a non-bare working tree is published into
directly — the commit is made in that working tree, and nothing is pushed — and `publish` refuses
unless the working tree is clean and on the configured branch. That is the form tests and
single-machine setups use.

**Configuration.** `evidence.toml` is read from `$XDG_CONFIG_HOME/trigon/evidence.toml`
(`~/.config/trigon/evidence.toml` when the variable is unset). If `TRIGON_EVIDENCE_CONFIG` names a
file, that file is read instead.

```toml
[publish]
repo = "git@github.com:<owner>/trigon-evidence.git"  # or https://…, ssh://…, file://…, a path
branch = "main"
origin = "github.com/<owner>/trigon-evidence"        # the log's origin, signed into records (D3)
disputes = "https://github.com/<owner>/trigon-evidence/issues"   # the dispute pointer (D3)
log_key = "~/.config/trigon/log.key"                 # read only by `trigon log sign`
divergences = "refuse"                               # or "feed" (D7)
rebuilt_artifacts = "none"                           # or "github-release" (D4)
same_host_confirmation = false                       # D8
confirmation_interval = "1h"                         # least time between agreeing attempts
heartbeat = "7d"                                     # §7

[freshness]
stale_after = "1d"                                   # older last sync: sync first
frozen_after = "14d"                                 # older newest leaf: answers unknown

[[source]]
name = "trigon"
urls = ["https://github.com/<owner>/trigon-evidence.git",
        "https://codeberg.org/<owner>/trigon-evidence.git"]   # one log, served from two places
log_key = "github.com/<owner>/trigon-evidence+1a2b3c4d+AR…"   # C2SP vkey; its name is the origin
attestation_key = "…hex, or a path to a PEM…"
checkpoint = "~/.config/trigon/trigon.checkpoint"             # optional initial checkpoint
required = true                                               # its unknown fails a check (§6)
trust_on_first_use = false          # true: read an unpinned key from keys/ on the first sync
```

Every table rejects a key it does not know, so a misspelt security setting is an error rather than a
setting silently off. Durations are a whole number and one unit, `s`, `m`, `h` or `d`. A source
without both keys is refused unless `trust_on_first_use = true`, the file form of
`--trust-on-first-use`. The values shown for `branch`, `divergences`, `rebuilt_artifacts`,
`same_host_confirmation`, `confirmation_interval`, `heartbeat`, `stale_after` and `frozen_after`
are their defaults; `required` and `trust_on_first_use` default to `false`, and `repo`, `origin`,
`disputes`, `log_key` and `checkpoint` to unset.

**A project's own sources.** `.trigon/evidence.toml` in the working directory is read too, unless
`TRIGON_EVIDENCE_CONFIG` is set. It is chosen by whoever controls the project — in CI on a pull
request, by the pull request's author — so it is held to less. It may only add `[[source]]` entries,
each under a new name, with both keys and an initial checkpoint pinned, and with HTTPS URLs only. It
cannot add a URL to a source that already exists, change or remove one, turn on trust on first use,
set `required`, or change any other setting, and a file that tries is refused whole. A file it names
— the checkpoint, a PEM attestation key — must be inside the working directory once symlinks are
followed, so a project cannot have Trigon read a file of the host's by calling it a key, and so must
`.trigon/evidence.toml` itself, which must also be a regular file of at most 64 KiB; its refusals
quote its strings escaped, and a parse error gives the line and column without quoting the line.
A source's name is its directory under the cache and state directories, so names are compared
ignoring ASCII case, in every file: on a case-insensitive filesystem `Trigon` is `trigon`'s
directory. Every answer from such a source names the file that added it.

**Environment.** Each variable overrides the files for one run:

- `TRIGON_PUBLISH_REPO` names the repository `publish` writes to, and `--repo` overrides it.
- `TRIGON_EVIDENCE_REPO` adds one source, named `env`, required, pinned by `TRIGON_EVIDENCE_LOG_KEY`
  and `TRIGON_EVIDENCE_ATTESTATION_KEY`, with `TRIGON_EVIDENCE_CHECKPOINT` as its optional initial
  checkpoint. Several URLs — one log and its mirrors — are separated by spaces. Without both keys it
  is refused, unless `TRIGON_EVIDENCE_TOFU=1`, which reads the keys from the repository's `keys/` on
  the first sync, records them, and labels every answer from that source as resting on them.
- `TRIGON_EVIDENCE_CACHE` replaces `$XDG_CACHE_HOME/trigon/evidence` as the directory clones are
  kept in, and `TRIGON_EVIDENCE_STATE` replaces `$XDG_STATE_HOME/trigon/evidence` as the one each
  source's last accepted checkpoint and key history are kept in (§6.1).

`attest` reads `origin` and `disputes` and signs them into the falsifying command and the dispute
pointer (§4.2 item 6) when both are set, and leaves both out, absent rather than empty, when they
are not, so attesting for local use needs no repository. `publish` refuses a statement that lacks
them, or names another origin, and a repository whose `keys/log.vkey` names a different origin.
`publication::decide` reads `same_host_confirmation` and `confirmation_interval` wherever it runs,
`trigon serve` included.

**Pins.** A source is pinned by its log key, whose name is the log's origin, and its attestation
key. Its initial checkpoint is optional: without one, the first sync accepts the first checkpoint
that verifies under the pinned log key, and says that it did. From then on every checkpoint must
extend the last one accepted.

**No default source** ships until D3 names our repository; from then on the client carries it,
required, with its keys and the checkpoint current at the client's release. Until then a consumer
configures at least one, and a command that needs a source and has none says so and exits 5.

**The publisher's working clone.** `publish` keeps its own clone of the repository it writes to
under the store, at `<store>/publish/<sha256 of the location>/`, beside the store's lock. The newest
checkpoint of a log that the host has published, or verified on its repository, is kept apart from
any store, at `$XDG_STATE_HOME/trigon/publish/<sha256 of the origin>.checkpoint`, beside a lock that
keeps the host to one `publish` at a time. Kept by the log rather than by the store or by how the
location is spelled, it holds every `publish` on the host, and `trigon log sign` too, which refuses
a tree that does not extend it: a repository rolled back holds an older checkpoint the log key opens
as well as the newest, and a tree built on that would be a second root for a size already published
(§8). A host with none — a fresh CI runner — is held only to what the repository holds, so the state
directory is kept from one run to the next. A local non-bare working tree is used in place, with the
same locks and state.

---

## 3. Publishing, correcting, and an accusation you cannot retract

This is the decision with teeth, and a direct consequence of the threat model
(`docs/threat-model.md`, adversary A7): **publishing a divergence is a public claim that somebody
else's package does not match its source.** ADR-0010 publishes divergences anyway, behind five
safeguards, and the design has to keep those safeguards true at the moment of publication, not
somewhere near it.

**Attesting is not publishing.** `trigon attest` signs, locally, and opens no socket. `trigon
publish` is the only thing that writes to the evidence repository. It loads the store into a
`trigon_api::Index`, with `Switches { stop_divergences }` set from the repository's kill-switch, and
reads each run's `Index::entry(run).publication` — the same code and the same corroboration `trigon
serve` uses (§10 phase 5).

- A run it calls `Published` is published in full.
- A run it calls `Void` — the artifact guard tripped, egress was open, or a non-builtin stabilizer
  fired — is published only as a void record (§4.3), never as a verdict. It needs no second attempt,
  because it makes no claim a second attempt could confirm.
- A run it calls `Withheld` — awaiting a confirming attempt, attempts that disagree, a base image
  derived outside the boundary, unknown provenance, or the kill-switch — is not published at all.

Disagreeing attempts are withheld rather than void, as `decide` and `docs/12-security.md` invariant
12 already say; ADR-0010 safeguard 2 says otherwise, and ADR-0014 corrects it. Of two agreeing
attempts, one is published. The Rekor path broke every part of this, because it logged at attest
time, before any gate had been asked.

**What the kill-switch can and cannot do.** Safeguard 5 stops *future* divergence publication until
a human clears it. Here it is a file in the repository: present means stop, turning it on is a
commit, and every publisher sees the same switch. `trigon serve --stop-divergences` stays what it
is, a switch on what one server shows; the repository's file is the switch on what is published.
When a publish repository is configured, `serve` reports that file's state, as of its publisher's
last fetch, beside its own switch, and says which one is set. The kill-switch never could retract,
and nothing here pretends otherwise. Safeguard 4, maintainer notification at publish time, has no
channel yet; until D7 decides one, `publish` refuses divergences.

**Correction is by superseding, never by deleting.** A published record is immutable: it is
content-addressed and its digest is in the log. So the superseding record names what it replaces,
signed: `supersedes: <record digest>` and a reason from a closed list — `withdrawn`, `set_changed`,
`attempts_disagree_later`, `pipeline_bug`. A superseding verdict is signed by `trigon attest <run>
--supersedes <record> --reason <code>`, which reads the superseded record from a local clone.
`publish` refuses a verdict or a void for a subject that already has a current record in the
repository unless it supersedes that record: a second current record is a second answer, which a
client can only show beside the first.

A client collects every record for a subject and verifies each. It drops a record only when a
verified, logged record, signed by a key it trusts for that record (the pinned key, or its successor
under a key-change leaf, §8), names it in `supersedes`, has a later leaf, and has the same subject
digests and canonical purl. A superseded record is never hidden: it is shown struck through, with
the reason and both leaf indices. If a source nevertheless holds two current records for one
subject, the client shows both and takes the more severe for the exit code.

"We were wrong" is its own predicate, `withdrawal/v1`: the superseded record's subject and purl,
`supersedes`, a reason, and no verdict. A subject whose only current record is a withdrawal reads as
`withdrawn`, not as never checked. A withdrawal has no run behind it, so it is signed by `trigon
attest --withdraw <record> --reason <code>` and pushed by `trigon publish --withdrawal` (§10 phase
5).

**What is permanent, and what is not.** A published leaf — for a divergence, the subject's digests,
`divergent`, the set digest and the record's digest — stays in the log for ever, and every clone
keeps it. The record file is meant to be permanent too, but a repository admin can rewrite history:
the ruleset that forbids force-pushes to the default branch is a setting an admin can change. So a
record whose leaf is logged but whose file is missing is evidence of a deletion, and a client says
so (§4.2). This is what "we cannot secretly retract" costs, and it is what ADR-0010 chose when it
chose to publish divergences at all. What makes it defensible is unchanged: the record carries the
dispute pointer and the command that would falsify it, and the gate in front of publication is where
a false divergence is stopped. Logging only a divergence's digest and outcome would not help: a stub
that says "trigon: divergent" without the dispute pointer and the falsifying command is still an
accusation, and a worse one.

---

## 4. What a record is, and what it has to carry

### 4.1 The record

A record is one JSON file, `records/<aa>/<bb>/<hex>.json`, named by the sha256 of its own bytes: one
per published result, a verdict, a void, or a withdrawal. It holds the signed statements inline and
names every piece of evidence by digest.

| Part | Where | How it is bound | Present in |
|---|---|---|---|
| the statement: an `equivalence`, `divergence`, `void` or `withdrawal` envelope | inline | signed | every record |
| the `rebuild` envelope | inline | signed | every verdict with a rebuild |
| the `buildobservation` envelope | inline | signed | every verdict |
| the stabilizer-set manifest | `evidence/sha256/…` | by its file digest, in the verdict (§4.2 item 7) | every verdict |
| the comparison report: per-member differences, codes, field edits and, where recorded, the per-pass progression | `evidence/sha256/…` | by digest, in the verdict | every verdict; never a void record |
| the strategy, as the canonical JSON the run stores | `evidence/sha256/…` | by blob digest, in the verdict (§4.2 item 7) | every verdict with a rebuild |
| the guard manifest | `evidence/sha256/…` | by digest, in `buildobservation`, or in `void/v1` | when the guard was armed |
| the rebuilt artifact | a release asset named by its sha256 | by digest, in the verdict | every verdict except `exact`, if D4 decides to publish rebuilt artifacts; never a void record |

Evidence files are content-addressed, so a stabilizer-set manifest shared by a thousand records is
stored once.

A record file, illustratively — `records/7f/3a/7f3a…c2.json`:

```json
{
  "schema": "trigon.record/v1",
  "subject": {"purl": "pkg:npm/left-pad@1.3.0",
              "digests": {"sha512": "1df6…", "sha1": "0e7c…", "sha256": "8b2e…"}},
  "statements": [
    {"payloadType": "application/vnd.in-toto+json", "payload": "…equivalence/v2…",
     "signatures": [{"keyid": "4f1c09a2b7e3d586", "sig": "…"}]},
    {"payloadType": "application/vnd.in-toto+json", "payload": "…rebuild/v1…",
     "signatures": ["…"]},
    {"payloadType": "application/vnd.in-toto+json", "payload": "…buildobservation/v1…",
     "signatures": ["…"]}
  ],
  "evidence": {
    "stabilizerSetManifest": "sha256:51d0…3b",
    "comparison": "sha256:3d88…1a",
    "strategy": "sha256:b02f…77",
    "guardManifest": "sha256:e5c9…04",
    "rebuiltArtifact": "sha256:a91c…"
  }
}
```

The top-level `subject` and the `evidence` map are unsigned conveniences for finding things. The
signed verdict inside `statements` names the same subject and digests, and that is what a client
checks: a lookup key is matched against the signed statement's subject, and a record whose map
disagrees with its signed verdict fails verification. A rebuilt artifact is found as the asset
`sha256-<hex>` in whichever release holds it, so no release name is recorded. A superseding record
carries `supersedes` and `reason` inside its signed statement, not beside it.

A void record has one statement, `void/v1`, and an evidence map holding at most the guard manifest,
when the guard tripped. Its leaf has the outcome `void`, and the set digest where its run compared
(a build the guard stopped names none). A withdrawal record has one statement, `withdrawal/v1`,
and an empty evidence map; its leaf has no outcome and no set digest, and carries `supersedes` and
`reason`. Both are written like any other record, including an entry in every index file of the
subject's keys.

And the index file a lockfile's npm integrity digest leads to — `index/sha512/1d/f6/1df6….json`:

```json
{"key": "sha512:1df6…(all 128 hex)",
 "records": [{"record": "sha256:7f3a…c2", "leaf": 1203}]}
```

If left-pad 1.3.0 were later withdrawn or re-published, the new record would be appended to that
list. An entry whose leaf is in a successor log also names that log's directory, `"log": "log/1"`,
since a leaf's index is its place in one log. A client with a clone never reads this file (§6).

Publishing the comparison report moves it from Operator-only (`Class::Comparison` in
`crates/trigon-api/src/evidence.rs`) to public. It was Operator-only because nothing bounds its
size. The largest in the local store is 5.94 MB, and 3 of 163 are over 1 MB: above the 1 MB GitHub
recommends for any one object, and well under the 50 MiB at which it warns and the 100 MiB it
refuses. It is published whole, because the verdict signs its digest and `--rerun-comparison` checks
it, and its member paths come from the published artifact, which the reader already holds. A size
ceiling, if one is needed, is a refusal to publish, recorded as withheld, never a truncation.

Not published, and why:

- **The upstream artifact.** It is not ours to redistribute, and the consumer already holds it.
- **Build logs, network transcripts and model transcripts.** They are unredacted today and may hold
  credentials or private hostnames. A redactor is a precondition for publishing any of them; until
  then the signed statements carry their digests and counts.
- **Rendered instructions, and the filtered registry documents the mirror served.** Neither is
  retained today, so a record lets a third party re-derive the comparison, but not re-run the build
  byte for byte.
- **Decompiled source, and a model's opinion of a diff.** Reading aids, never evidence.

### 4.2 The fields, and where each is signed

`docs/11-interfaces.md` §4 says a stale pass is worse than no data, and runtime lookup makes that
acute. Every record must carry, and every client that shows a record must render:

1. **The outcome as a string** — `exact`, `normalized`, `normalized_with_caveats`, `divergent` — and
   never a boolean. Signed today, in the verdict.
2. **The stabilizer set id and digest.** Signed today in the verdict. Missing from `rebuild`, where
   the attestor passes no set; to fix. The set digest covers pass ids, stages, risks and provenance
   but not pass code, so a pass whose behaviour changes under an unchanged id keeps the digest; §11
   asks what to do about that.
3. **When, and which Trigon version.** Signed today only in `rebuild`, whose subject is the
   *rebuilt* artifact, so a lookup by the upstream digest never reaches it. And the version it signs
   is the attestor's own, not the version that ran the build, which the run record did not keep
   until §10 phase 2 (`RunRecord.trigon_version`). Put both in the verdict.
4. **The egress tier, and whether the run was `attestable`.** The egress tier is signed today in
   `buildobservation`, whose subject is the upstream artifact; `attestable` only in `rebuild`. Put
   both in the verdict, so that one statement answers.
5. **`derivation.method`**, so a consumer can filter out model-assisted derivations themselves.
   Signed today only in `rebuild`, as item 3; and a run with no recorded derivation is signed as
   `heuristic`, which is absence rendered as a value. Absent must stay absent.
6. **The falsifying command, and for a divergence the dispute pointer** ADR-0010 requires. In no
   statement today. The command cannot name its own record's digest, which is the digest of the file
   that contains it. It names the subject, the predicate type and the log's origin, and the client
   resolves the current record through the log and its supersessions: `trigon verify-attestation
   --lookup sha256:<subject> --predicate <type> --origin <origin> --rerun-comparison --upstream
   <file>`. A client with no source of that origin says so rather than resolving elsewhere. Where
   the repository that holds the record publishes its rebuilt artifact (D4) — a release asset of a
   repository on github.com, named by the digest the verdict signs — the command fetches it itself
   and holds it to that digest; otherwise it takes `--rebuild <file>`, the output of re-running the
   build under the record's published strategy, so the same signed command works either way. Which
   it is depends on the record and its source alone: the client's own `[publish]
   rebuilt_artifacts` says what the client's host publishes, and nothing of another operator's
   repository. An exact verdict's rebuilt artifact is the published artifact byte for byte, which
   no repository publishes again (§4.1), so for one the command asks nothing, and the upstream file
   is its rebuilt artifact, held to the digest the verdict signs like any other: the command runs
   as signed, with `--upstream` alone. The dispute pointer is a typed object, such as
   `{"kind": "url", "url": …}`, pointing at the repository's issues. Both carry the namespace, so D3
   is decided before either is signed.
7. **The digests of the evidence the record names**: the comparison report, the rebuilt artifact,
   the set manifest file and the strategy. Two of these need a digest that does not exist yet. The
   stabilizer-set digest (`StabilizerSet::digest`) is a hash over sorted `id|stage|risk|provenance`
   rows, not the digest of the manifest file, so the verdict signs the manifest file's digest beside
   it. `rebuild`'s `strategy.json` byproduct named `strategyDigest`, which is a domain-separated
   hash over the canonical strategy and the tools it reaches, not the digest of any file;
   `RunRecord.strategy` existed for the blob digest of the strategy's canonical JSON, and nothing
   wrote it (0 of 371 stored runs). Since §10 phase 2 the run stores the strategy as a blob and sets
   that field, the byproduct names that blob, and the record's strategy evidence is bound by it.
8. **The package's purl**, canonical under a named canonicalisation version. No statement carries
   one today. A record found under a purl is accepted only if its signed purl canonicalises to it.
9. **`supersedes` and `reason`**, on a superseding record, equal to its leaf's.

Items 2 to 9 change what the verdict signs, so its predicate types move to `equivalence/v2` and
`divergence/v2`, beside the new `void/v1` and `withdrawal/v1`. `rebuild` gains the set as an
additive field and stays `rebuild/v1`, which verifiers read without rejecting unknown fields; phase
2 tests that an old verifier reads the new statement. **This lands before the first publication.**
Subjects and predicates are signed, and changing them afterwards means re-signing the corpus.

A client distinguishes these as loudly as it distinguishes the outcomes:

- **never checked**: the source is neither stale nor frozen (§6) and its log has no record for the
  key;
- **withdrawn**: the only current record is a withdrawal;
- **deleted**: the log has a leaf, and the clone has no file for its record;
- **record failed verification**: a signature, inclusion, digest or leaf that does not check,
  including a record with no leaf. It is reported loudly and never as never checked, because it may
  be an attack;
- **unknown**: the source is stale and could not be synced, or it is frozen, or a `--remote` lookup
  failed.

Absence rendered as a zero is a bug this project has already shipped (`docs/18-management-ui.md`
§3), and a stale clone rendered as "never checked" is the same bug one level up.

### 4.3 Void

A void run — the artifact guard tripped, egress was open, or a non-builtin stabilizer fired — must
never be published as a verdict. Until §10 phase 2 only a guard-tripped run went unsigned, because
the attestor refused it (threat-model property P6); an open-egress or non-builtin run was still
signed as `equivalence/v1` or `divergence/v1`, and the API withheld that statement from anonymous
callers only. So a void is published as a leaf and a record whose only statement is `void/v1`,
new. It carries the outcome `void`, the reason, the facts that establish it (which guarded members
tripped, which egress tier, which stabilizer), and **no comparison outcome and no difference
data**: "we looked, and could not tell, for this reason". `trigon attest` signs `void/v1` for a run
`decide` calls void, and still refuses to sign a verdict for it; since §10 phase 3 `trigon rebuild
--attest` signs through the same code, so P6 holds without a qualification: no path signs a verdict
for a run the gate calls void. (`trigon verify --attest` compares two local files, with no run
behind them, and signs a v1 comparison claim that `publish` does not accept.) Clients treat void as
its own state and not as a rung of `Match`, which has none, and the exit codes (§6) give it code 3,
shared only with a result below the threshold. `docs/09-attestations.md` §2.6 has the predicate as
built.

---

## 5. Keys: how a consumer finds a record

Every record leaf carries its subject's digests and canonical purl, so a client that holds the log
finds a record by any of them without an index, and that is how every command with a clone resolves
a key (§6). For `--remote`, and for tools that do not read the log, every record is also reachable
under every key its subject carries, as a file under `index/`:

| Key | Path |
|---|---|
| sha256 | `index/sha256/<aa>/<bb>/<64 hex>.json` |
| sha512 | `index/sha512/<aa>/<bb>/<128 hex>.json` |
| sha1 | `index/sha1/<aa>/<bb>/<40 hex>.json` |
| purl, with version | `index/purl1/<aa>/<bb>/<sha256 of the canonical purl>.json` |
| the package, every version | `index/pkg1/<aa>/<bb>/<sha256 of the package's versionless form>.json` |

`<aa>/<bb>` are the key's first four hex characters, so no directory holds more than a few dozen
entries. An index file lists the record digests for its key with their leaf indices, and is
annotated with nothing a client trusts: it narrows a search, and the log is the authority on what
exists (§8). Paths have no length limit worth the name, so every digest is stored whole — no
truncation, no collision class. Purl characters are not path-safe, so purls are hashed; the
canonicalisation — case, qualifier order, percent-encoding — becomes part of the lookup protocol,
ships with test vectors shared by the writer and every reader
(`crates/trigon-core/testdata/purl-canon-v1.json`, rules in `docs/09-attestations.md` §2.9), and the
digit in `purl1` and `pkg1` is its version, so changing the rule starts new paths rather than
silently missing old ones.

**The versionless form names the package and nothing about one version of it**:
`pkg:<type>/<namespace>/<name>` in canonical form, with the `repository_url` qualifier where the
purl has one, and no version, no subpath and no other qualifier. Most qualifiers name one version's
files — `file_name`, `checksum`, `download_url` — and a form that kept them gave every version its
own `pkg1` key, where the key exists to find every version. `repository_url` stays because it
changes which package this is: the same name on another registry is another package, and merging
the two is the answer for the wrong package that keeping case exists to avoid. This is `purlCanon`
1; nothing had been published under it when the rule was fixed.

**Subjects carry every sha256, sha512 and sha1 the ecosystem publishes.** npm publishes sha512, as
the `integrity` string, and sha1, as `shasum`, and never sha256. NuGet's catalog carries a sha512
`packageHash` for some entries and not others, and its flat container publishes none beside the
download URL (`crates/trigon-registry/src/nuget.rs`). Until §10 phase 2 `Subject::new` carried
sha256 only, and the npm fetcher verified nothing, because it read only a `sha256-` integrity string
and npm never sends one. The fix was one change with two effects: decode what the ecosystem
declares, verify the download against it where it is declared and record its absence where it is
not, and put every sha256, sha512 and sha1 in the subject (`Subject::with_digests`). Absence is
recorded only where the declaration was read and is absent: a NuGet registration or catalog leaf
that cannot be read refuses the download, retried where the failure was transient, rather than
recording that NuGet declared nothing. Other algorithms — PyPI's md5 and blake2b_256, a pip
`--hash=sha384:` — are verified on download where declared and this build can compute them, and are
not keys; blake2b_256, which it cannot, is recorded as declared and unchecked. sha512 of the
upstream was already computed on every run and signed inside the predicate, so this was smaller than
it sounds. sha1 is collision-broken; npm accepts that risk for its oldest entries, and a client that
matched on sha1 says so.

**The index is derived data.** `publish` writes a record's index entries in the same commit as the
record and its leaf, so they cannot drift in the normal case, and `trigon publish --reconcile`
rebuilds the whole `index/` tree from the log if they ever do. A client with a clone never reads it,
and `--remote`, which does, says what that costs (§6).

---

## 6. Querying: clone, then ask your own copy

**The default is a local clone.** The first lookup clones each configured source (§2.4, §6.1) into
the user's cache (`$XDG_CACHE_HOME/trigon/evidence/<name>/`); later lookups fetch only what changed.
Every query then runs against that copy, with no network requests. A thousand-dependency lockfile
costs one fetch, not a thousand GETs.

```
trigon evidence add <name> <url>… --log-key <vkey> --attestation-key <key> \
    [--checkpoint <file>] [--required] [--trust-on-first-use]
trigon evidence list
trigon evidence remove <name>
trigon evidence sync [--source <name>]… [--full-history] [--accept-state-loss <name>]…
trigon lookup sha512-<base64>|sha256:<hex>|pkg:npm/left-pad@1.3.0|./left-pad-1.3.0.tgz \
    [--source <name>]… [--offline | --remote]
trigon check ./package-lock.json [--min normalized] [--max-risk structural] \
    [--source <name>]… [--require <name>]… [--offline | --remote] [--store <path>] [--format …]
trigon verify-attestation --lookup sha256:<subject> [--predicate <type>] [--origin <origin>] \
    --rerun-comparison --upstream ./left-pad-1.3.0.tgz [--rebuild <file>]
trigon verify-attestation --record <file> --evidence <dir> --source <name> \
    [--rerun-comparison --upstream <file> --rebuild <file>]
trigon verify-attestation --record <file> --source <name> \
    [--rerun-comparison --upstream <file> --rebuild <file>]
```

- **`evidence sync`** fetches every URL of every source and verifies each log locally before
  anything is answered from it: the checkpoint's signature against the pinned log key; the Merkle
  root recomputed from every leaf and compared with the checkpoint's; leaf times that never go
  backwards; consistency with the last checkpoint this client accepted; and every key-change and
  log-end leaf, which it follows as §8 says. A checkpoint that does not extend the stored one is
  refused (§8). Recomputing the root over a million leaves is a second or two of hashing, so every
  client is a full monitor of the log, not a sampler of it.
- **The clone.** The default clone is shallow, partial and sparse: `git clone --depth 1
  --filter=blob:none --sparse`, then `git sparse-checkout set keys log records`. The filter is what
  keeps `evidence/` and `index/` out — without it a sparse checkout still downloads every blob — and
  git fetches an evidence file on demand when a command reads it, which is when `--rerun-comparison`
  or an audit asks. A shallow clone has no merge base to fast-forward from, so a sync is `git fetch
  --depth 1 origin <branch>` and then `git reset --hard FETCH_HEAD`, never a pull. A local path is
  cloned in full, because git ignores depth and filters for a local clone, which costs only disk.
  `--full-history` keeps the whole git history, for anyone who wants to check commits as well as
  checkpoints. Unauthenticated clones and fetches count against GitHub's rate limits like any other
  request, so in CI the cache directory is what a cache step keeps between jobs, and a pipeline pays
  for a fetch, not a clone — with the state directory beside it, always: the clones show a source
  has synced before, so a cache restored without its state is a state lost, and refused until
  `--accept-state-loss` (§6.1). A runner that keeps neither is a fresh client (§8).
- **Freshness has two clocks.** A source is *stale* when its last successful sync is older than
  `stale_after` (a day, by default), and a command then syncs it first and says so. A source is
  *frozen* when its newest leaf's time is older than `frozen_after` (14 days, by default); a frozen
  source's answers are unknown whatever the sync did, so a host serving an old but consistent state
  cannot turn a withdrawal back into a verdict. The heartbeat (§7) keeps an honest log from
  freezing. `--offline` never touches the network, labels every answer with the checkpoint it came
  from, applies the frozen threshold to what the clone holds, and answers unknown for a stale
  source, as a failed sync would.
- **`lookup`** resolves a key from the verified leaves — every record leaf carries its subject's
  digests and canonical purl — to record files, verifies each envelope against the source's
  attestation key, checks that the record file matches its leaf, applies every supersession the log
  records, which it can see directly because it holds the whole log, and prints the §4.2 fields, per
  source. It never consults `index/`.
- **`check`** is the lockfile front door. It needs the lockfile parser to keep what it throws away
  today — npm `integrity` and `resolved`, `requirements.txt` `--hash=` lines (which today also
  corrupt the parsed version), SPDX `checksums` — and to look up by digest first and by purl second.
  Given `--store <path>`, it keeps its earlier behaviour, checking against a local store of the
  operator's own runs; without it, it answers from the evidence sources. That changes what a bare
  `trigon check` means — it defaulted to `./trigon-store` — so the release notes say so, as the
  command's help and `docs/using-trigon.md` already do; there are no release notes yet, and the
  first to be written carries it. `--format text|json|sarif` carries over, and the JSON and the
  SARIF carry every source's answer for every package.
- **`verify-attestation --lookup`**, which is also the form of a record's falsifying command (§4.2
  item 6), resolves the current record in the clone of the source whose origin `--origin` names, and
  fetches the evidence it names, so `--rerun-comparison` needs only the upstream artifact from the
  user, and the rebuilt artifact too unless the repository that holds the record publishes it (D4)
  or the verdict is exact. Without `--rebuild <file>` it looks for the release
  asset `sha256-<hex>` of the digest the verdict signs in that repository's `rebuilt-YYYY-MM`
  releases, where the repository is on github.com by an HTTPS or an SSH location, asking GitHub's
  API without a token; then in those of every other source that holds the record, but never one a
  project's `.trigon/evidence.toml` added where the record was resolved in the user's own (§8). It
  lists only the series of the month the record was logged in and the months either side, where
  `publish` puts the asset, so that finding it costs a few of the sixty requests an hour GitHub
  allows a client with no token, however many releases of other months the repository has. It holds
  what it downloads to that digest: other bytes in the repository of the source the record was
  resolved in fail, exit 4, and in another source's are that repository's, and the next is asked. A
  repository elsewhere is asked nothing, and neither is GitHub for an exact verdict, whose rebuilt
  artifact is the upstream file itself, held to the digest the verdict signs; a verdict that signs
  the subject's sha256 as its rebuilt artifact's is one. Where no such asset exists, or where GitHub
  refuses or cannot be reached, the check is not made, exit 5, and it asks for `--rebuild <file>`,
  never guessing at another artifact. With `--rebuild <file>` it fetches nothing for the rebuilt
  artifact. The client's own `[publish] rebuilt_artifacts` plays no part: it governs what `publish`
  uploads.
- **The network-free verifier** (`--no-default-features`) takes `--record <file> --evidence <dir>`
  for one source, with that source's keys and last accepted checkpoint from `--source <name>` (read
  from `evidence.toml` and the state directory) or given as `--log-vkey`, `--attestation-key` and
  `--checkpoint`. `<dir>` is a clone or any directory with the §2.3 layout. An evidence file absent
  from `<dir>` is reported as unchecked, never as passed. `bundle` becomes optional. Without
  `--evidence`, `--source <name>` reads the source's own clones as its last sync left them, its
  chain followed into every repository it has gone on in. It opens no socket, so threat-model
  property P21 — the verifier links no network client — stays true. Cloning is the default build's
  job; verifying a clone needs no network at all.
- **`--remote`**, on `lookup` and `check`, is the one-off alternative: plain HTTPS GETs from
  `raw.githubusercontent.com`, for a single question in a place a clone is unwelcome. It fetches the
  checkpoint and verifies it against the pinned key and the last accepted checkpoint, reads the
  index file for the key, fetches each record and its leaf's entry bundle, and proves each leaf
  included from the hash tiles; a record whose leaf it cannot prove fails verification. It tells
  GitHub which package was asked about, it is rate-limited for unauthenticated clients, and it sees
  a supersession only if the index file lists it; it says all three when used.

**Exit codes**, because this ends up in CI:

- `0`: every package at or above the threshold;
- `1`: any divergence;
- `2`: any package never checked, or withdrawn;
- `3`: any void, or any result below the threshold;
- `4`: any deleted record, any record that failed verification, an equivocation (§8), a required
  source that is unknown, or no source able to answer at all;
- `5`: the tool itself failed — bad arguments, an unreadable lockfile, or no source configured.

When several apply, the first in the order 5, 4, 1, 3, 2 wins. With several sources (§6.1), a
package's result is the most severe answer any source gives that is not unknown; it is never checked
only when no source that answered holds a record for it. An unknown source contributes nothing
unless it is required — `required = true`, `--require <name>`, `TRIGON_EVIDENCE_REPO`, or the
default source once there is one — and otherwise the report names it as missing. `--min
exact|normalized|normalized_with_caveats`, default `normalized_with_caveats`, maps onto
`Match::is_at_least`, which ranks only the four outcomes; never checked, withdrawn, void, deleted,
failed verification and unknown have no rung and take the codes listed above. `--min` is an outcome
floor, and `docs/05-archive-and-normalization.md` §1's example also caps risk (`Normalized` with
`risk <= Structural`), so `--max-risk` sits beside it.

**The lookup client must not have to be Trigon.** Everything above verifies with a pinned key,
SHA-256 and a Merkle tree, over files. A standalone `npx trigon-check` / `uvx trigon-check` is a few
hundred lines and does not even need `git`: GitHub serves any commit of a public repository as a
tarball, so the client downloads the tarball of the default branch, verifies the log inside it, and
answers from it. The tarball holds the whole tree, `evidence/` included, so it is larger than the
default clone; a client that runs often keeps it, and fetches `log/checkpoint` first to download a
new tarball only when the checkpoint has moved. It is the eventual front door, because if checking a
lockfile requires installing the rebuilder, nobody checks a lockfile. It is phase 9, which waits on
D3, because it ships pinned to our repository. Its obligations:

- It prints the key it trusted, and points at `verify-attestation --rerun-comparison` as the thing
  that re-derives rather than trusts.
- It pins the keys and a checkpoint. Each release is signed with a release key, distinct from the
  attestation and log keys, and logged as a `release` leaf (§2.3), so the verifier binary, or any
  earlier client, can check a new one. It is published without npm or PyPI provenance, because that
  is Sigstore (ADR-0014 Decision 1).
- For npm it leads with source attribution, because a wall of green on an npm lockfile is true and
  nearly worthless (`docs/03-ecosystems.md` §0).

### 6.1 Several repositories

A consumer can sync any number of evidence repositories — other operators running Trigon, a private
instance inside a company, the parts of ours if D2 splits it, and mirrors of any of them — and the
design treats each as a separate witness, never as one pool.

- **A source is one log.** It is configured as a name, one or more locations (§2.4), the pinned log
  key, whose name is the origin, the pinned attestation key (or, once one exists, root), and
  optionally an initial checkpoint. `trigon evidence add` writes one into the user's
  `evidence.toml`, and `evidence list` and `evidence remove` do what they say. A source without
  pinned keys is refused, except under an explicit `--trust-on-first-use`, which reads the keys from
  the repository's `keys/` on the first sync, records them, and labels every answer from that source
  as resting on them.
- **Keys never cross sources.** A record is verified against its own source's keys only. A record in
  one source cannot supersede a record in another, and a key one source trusts means nothing in any
  other. Each source has its own clones under `$XDG_CACHE_HOME/trigon/evidence/<name>/`, and its
  last accepted checkpoint and key history under `$XDG_STATE_HOME/trigon/evidence/<name>/`, outside
  the clone. A clone whose checkpoint is older than the accepted one is refused as a rollback, and a
  missing state file is reported rather than silently recreated: `evidence sync --accept-state-loss
  <name>` is how a user says it was lost, and only what was lost starts over — with the checkpoint
  gone, the log is held only to its initial checkpoint, or to nothing, and keys a source trusts on
  first use are kept; with those keys gone, they are read again, and must open the checkpoint kept.
- **Mirrors are locations of one source.** Several URLs with one origin and one log key are one log
  served from several places. `sync` fetches every one of them, verifies each log, and requires them
  to be consistent: at the same size the roots must match, and at different sizes the smaller must
  be a prefix of the larger. It answers from the largest, and reports a URL serving an older
  checkpoint as lagging. A mismatch is an equivocation, reported with both signed notes. That is the
  split-view check §8 otherwise lacks until witnesses cosign, and mirroring our repository on a
  second host — Codeberg, GitLab, a self-hosted git server — makes it cheap for everyone.
- **Sync, and failure, are per source.** `trigon evidence sync` brings every configured source up to
  date, in parallel. A source that cannot be reached still answers from its clone until the clone is
  stale, labelled with the checkpoint it came from; after that, or once the source is frozen, its
  answers are unknown, while the other sources still answer. `--source <name>` restricts any command
  to the named sources.
- **Answers are reported per source, and disagreement is shown.** `lookup` prints each source's
  result beside the source's name. When two sources disagree about one artifact — one says exact,
  another divergent — the client prints both and says that they disagree; it never picks one and
  never merges them into a single verdict. For exit codes, a package takes the most severe answer
  (§6), so a divergence from any configured source fails a check, while a private source that holds
  only internal packages does not make every public one read as never checked.
- **Splits and rollovers follow the log.** If D2 splits our repository, each part ships as its own
  source with its own origin. A successor log stays inside one source: the old log's `log-end` leaf
  names the successor, and the client follows it and checks the successor's `log-continuation` leaf
  (§8), so the source keeps its name while its origin and log key change.
- **The network-free verifier** checks one source at a time, with that source's keys.

---

## 7. Privacy, size, and freshness

**The clone is the privacy story.** A per-dependency lookup would tell the host, and every CDN on
the path, the full dependency graph of whoever ran it. Cloning tells GitHub only that somebody
cloned the repository; every question after that is answered locally. Two things still reach the
network with a package in them: fetching a record's evidence for `--rerun-comparison`, and its
rebuilt artifact's release asset where no `--rebuild` is given, which name that record to GitHub;
and `--remote`. Each says so when it is used.

**Size.** A leaf is canonical JSON of roughly 500 to 700 bytes. A published verdict adds its record
file (the three envelopes, some 7 to 15 KB), five index entries, which the default clone does not
fetch, and a comparison report whose median in the local store is 7.5 KB and whose 90th percentile
is 75 KB, in `evidence/`, which the default clone does not fetch either. So the part a consumer
clones is roughly 10 to 15 KB per published version before git's compression, which does well on
JSON: some hundreds of megabytes per hundred thousand versions, packed. On top of that sit the
partial tiles and bundles of the tile being filled, one per publication since the last full tile,
averaging half a tile each: at a few records per publication that is several megabytes of `log/`,
which the commit writing the full tile removes. That is comfortable for a long while and not for
ever. GitHub asks that a repository stay under about 1 GB and strongly under 5 GB, so the plan for
size is part of the design from the start: D2 decides when and how the repository is split, and the
split has to be one a client can follow from the pinned origin.

**Freshness, and what it proves.** A client that holds a checkpoint refuses a newer one that is not
an extension of it. Every leaf carries the time we logged it, and a `heartbeat` leaf is appended
whenever a week passes with nothing else logged, so the newest leaf of an honest log is never more
than a week old. A source whose newest leaf is older than `frozen_after` answers unknown (§6). The
heartbeat needs a scheduled job that holds the log key; where it runs is part of D5. That time is
committed in the tree, so it cannot later be changed without a rewrite that anyone holding an older
checkpoint detects, but it is ours: it catches a host or a mirror withholding a newer checkpoint,
not us withholding one. Once witnesses cosign (phase 7b), each cosignature carries the witness's own
timestamp, and freshness can rest on that instead.

---

## 8. Trust: who has to be believed about what

- **GitHub is trusted for availability only.** Whoever can push to the repository — an organisation
  admin, a leaked token or deploy key, whoever inherits a renamed namespace — can delete, withhold,
  rewrite or refuse to serve, and cannot forge: every record verifies against a key the client pins,
  and every leaf against the log the client recomputed itself. The client never treats who committed
  a file as who signed it, and does not rely on commit signatures. The repository forbids
  force-pushes and deletion of its default branch with a ruleset whose bypass list is empty, because
  classic branch protection exempts admins unless told otherwise; an admin can still change the
  ruleset.
- **When the log and the files disagree, the log wins, and the disagreement is shown.** A record
  file with no leaf is refused and reported as record failed verification ("unlogged record"), never
  shown as a verdict. A leaf whose record file is missing is reported as deleted, whatever the
  leaf's outcome: the client never renders an outcome it cannot show with its dispute pointer and
  falsifying command. A record whose verified statement disagrees with its leaf on digests, purl,
  outcome, set digest or supersession fails verification. The index is never consulted by a client
  with a clone, so a missing or altered index file changes nothing it answers, and `--reconcile`
  repairs it. A checkpoint that does not extend the one the client last accepted is an equivocation
  or a rewrite: the client refuses it, prints both signed notes, and exits 4.
- **The log is our word, made checkable.** A signed checkpoint over a Merkle tree lets anyone who
  kept an older checkpoint or an older clone prove that we rewrote history. Until witnesses cosign
  (phase 7b), nothing *prevents* a rewrite, and nothing stops GitHub or us from serving different
  clones different histories; both can only be caught — by one client comparing the mirrors of a
  source (§6.1), or by two users comparing checkpoints. A client with no state of its own, such as a
  fresh CI runner, detects a rollback only back to the checkpoint it was configured with, which is
  why the default source will ship with the checkpoint current at each client release. Every client
  is a full monitor, because it recomputes the whole tree.
- **The keys, and what each is worth to a thief.** The log key is separate from the attestation key
  and used only by the socketless `trigon log sign`. Whether it is also held apart — on another
  machine, or offline — is D5; under D5's workstation option one machine holds both keys and the
  push credential. A stolen log key lets its holder sign, for any client, a tree that extends the
  newest checkpoint that client holds but differs from the real log after it: a fork, or a split
  view, which the client cannot detect alone, and which can omit a withdrawal or a supersession. It
  cannot forge a record. A stolen attestation key alone produces records no client accepts, because
  clients require inclusion. With both, a thief can publish anything clients accept. Witnesses
  (phase 7b) make that visible and prevent a split view, and key epochs or rotation (phase 7a) bound
  it; neither stops it. Nothing dates the theft of the attestation key until phase 7a, or bounds a
  stolen log key until phase 7b. That was already true in practice: the Rekor timestamp check meant
  to bound it was never enforced.
- **Rotation is logged, and a client follows it.** An attestation-key rotation, until a root exists,
  is a `key-change` leaf signed by both the current key and the new one (ADR-0014 Decision 8). A
  client that verifies it under the key it holds for that source records the new key in the source's
  state and, from that leaf on, refuses a record signed by the old key whose leaf comes later; the
  pinned key in the configuration stays as the start of the chain. A log-key rotation, or a D2
  rollover, ends the old log with a `log-end` leaf naming the successor's origin, log vkey and
  location, and starts the successor with a `log-continuation` leaf holding the old log's final
  checkpoint, cosigned by the new key. A client follows that pair only when both verify, and a
  successor that is not named by the old log's `log-end` is refused. `trigon log key-change` writes
  the first, which a child process that opens no socket signs with both attestation keys; `trigon
  log succeed` writes the second pair, and `trigon log sign` signs a log-end only holding the
  successor's log key as well, which it cosigns the final checkpoint with, and begins a successor
  only as the one a log-end names.
- **The push credential is a third secret.** Alone it cannot make a client accept a record. It can
  delete and withhold files, add or remove the kill-switch, write unsigned feed entries, plant
  files beyond the checkpoint, and commit a `.gitignore` or a `.gitattributes`. So `publish`
  verifies the remote log before building on it, never signs a leaf it did not write, commits
  exactly the bytes it wrote whatever git is told to ignore, refuses a branch that names git
  attributes, and regenerates the index and the feed from the log (§10 phase 5). Where the ruleset
  is missing it can roll the branch back too; `publish` and `log sign` then refuse to build behind
  the newest checkpoint the host has published (§2.4).
  A fine-grained token or a GitHub App installation token with contents-write on this one
  repository, and an expiry, is the narrowest form; a write deploy key is scoped to the repository
  too, but never expires (D5).
- **Several sources multiply anchors, not trust.** Each configured source is trusted exactly as far
  as the keys pinned for it, and adding a source never widens what another source's keys can sign. A
  source added by a project's `.trigon/evidence.toml` is input chosen by the thing under test
  (threat model §1.10), not trusted input: it can add a claim, attributed to the file that added it,
  and cannot change what any other source answers (§2.4).
- **Discovery is distribution.** A consumer asks our repository because our client told it to. The
  repository location, the pinned keys and the checkpoint travel together in the client once D3 is
  decided, and that is the whole discovery story until the registries conversation (§2.1) goes
  somewhere.

---

## 9. What this design deliberately does not do

- **No transparency log we do not run, and no Sigstore** (ADR-0014).
- **No service.** Publishing is a push; reading is a clone. Nothing answers a query on our behalf.
- **No account, no API key, no per-user state.** Cloning a public repository needs none.
- **No writing into a publisher's namespace**, ever, even if a registry offers it. A third party's
  verdict served under the publisher's provenance endpoint would be read as the publisher's claim.
- **No aggregate "trust score".** Four outcomes and void, a freshness, and a set digest. Any
  collapse of those into a number is a lie with a decimal point.
- **No automatic issue-filing against maintainers.** ADR-0010's notification is best-effort with a
  dispute pointer (D7); an unattended bot opening issues against strangers' repositories on the
  strength of a rate we know to be imperfect is not that.
- **No merging of sources.** Two operators' verdicts about one artifact are two claims, shown side
  by side, never averaged or reconciled into one.
- **No publishing of build logs or transcripts** until a redactor exists.
- **No large artifacts in git, and no Git LFS,** whose bandwidth quota a popular repository would
  exhaust.

---

## 10. The build plan

Each phase ends in something that works on its own, and is tested the way this repository tests
anything that touches a network: offline fixtures pinned to real bytes; `--dry-run` previews that
print exactly what would be written; tests against a local bare git repository, which need no
network and run in CI like any other; anything that talks to GitHub itself behind `TRIGON_LIVE=1`,
never in CI; and at every step both builds (the `--no-default-features` verifier in a scratch target
directory, so it does not overwrite `target/debug/trigon`), every test, and `cargo run -p xtask --
policy`.

### Phase 0 — close the publication-gate bypass that exists today

`POST /v1/check` is anonymous and answers from `Index::newest_for`, which does not consult
publication, so it reports a withheld divergence as `divergent` to anyone
(`crates/trigon-api/src/fleet.rs`, `crates/trigon-api/src/index.rs`); its own doc comment promises
the opposite. Filtering on "public" would not be enough: `Publication::is_public` is true for `Void`
as well, and `RunRecord::status` reports an open-egress divergence as `divergent`. So answer
anonymous callers only from runs the gate calls `Published`; show a run it calls `Void` as
`unsupported`, with its reason, never as `divergent`; treat a `Withheld` run as absent; and add a
seam test for each. The same premise reaches every anonymous route that serializes `Entry.outcome` —
`GET /v1/runs`, `/v1/runs/{id}`, `/v1/targets/{purl}` and `/v1/artifacts/{digest}` — so each omits
the outcome of a `Void` row. Independent of everything else here, and can land first.

**Done when** an anonymous check of a lockfile reports a withheld divergence as `never checked`, a
void divergence as `unsupported`, and a published run as its verdict; when the newest run of a
target is withheld, it reports the newest older published run of that target, or `never checked` if
there is none; and no anonymous route returns `divergent` for a void run.

### Phase 0b — decide

The build removes a path that an accepted ADR mandates, so the decisions come first. ADR-0014
accepted. ADR-0011 marked partly superseded. ADR-0010 amended: the publication point, which is an
explicit `trigon publish` rather than automatic; supersession; disagreeing attempts withheld rather
than void; safeguard 1 narrowed to verdicts, so a void is publishable on one attempt; safeguard 4 as
D7 decides it; and, if D8 accepts it, same-host confirmation. ADR-0008's table gains an "Evidence
store | git (ADR-0014)" row. The threat model keeps "The operator" — whoever passes the flags — out
of scope, and gains A8, the operator of any evidence repository a client trusts, and A9, a host or
mirror serving a stale or split view, with a project's configuration naming sources as input chosen
by the thing under test (phase 8). Backlog B10 rewritten to this chapter. B21's done-when rewritten
to "a statement under a real chain verifies in the verifier, and the negatives fail", with the time
check deferred to phase 7a, and dropped if D6 chooses key epochs.

**Done when** the ADRs' status lines and the backlog say so.

### Phase 1 — remove Rekor and Sigstore

Delete:

- `crates/trigon-attest/src/transparency.rs`, its re-exports, and the `p256` dependency;
- `mod rekor` and its tests in `crates/trigon/src/main.rs`, `attest --rekor`, and
  `verify-attestation --transparency` and `--log-key` with `check_log_entry`;
- the Rekor fixtures; the `transparency_live_entry.rs` and `transparency_cli.rs` tests; the
  `--rekor` and `--dry-run` tests in `crates/trigon/tests/keys_and_dry_run.rs`; and the
  `transparency` field in `crates/trigon-store/tests/seam_store_round_trip.rs`;
- `RunRecord.transparency`, the fifth column of `trigon runs`, and the Rekor options in
  `scripts/rebuild-and-attest.sh`.

`crates/trigon` keeps its `reqwest` dependency, which only `mod rekor` uses today: phases 5 and 6
need an HTTP client for release assets and `--remote`, and this is the one the workspace already
links. `attest --dry-run` goes with `--rekor`, and returns on `publish` in phase 5.

Update the prose that describes the removed path: `README.md`; `docs/09-attestations.md` §2's
`buildobservation` row, whose subject is the upstream artifact, and §3 and §6–§7;
`docs/using-trigon.md`; `docs/11-interfaces.md`; `docs/13-roadmap.md`; `docs/01-architecture.md`;
`docs/00-overview.md` §2.1, whose criticism of OSS Rebuild for having no transparency log must be
reworded now that we run our own; `docs/adr/0008-one-implementation-per-seam.md`'s Signer row; the
0011 row of `docs/adr/README.md`; the transparency-log wording in the `keygen --public-out` and
`public-key --pem` help; the `transparency` key of `verify-attestation --output json`, noted as
removed; backlog B21's body and B29; the module doc of `crates/trigon-attest/src/signer.rs`
("sigstore") and `LocalKey::public_pem`'s doc ("transparency log"); and the threat model,
regenerating `docs/threat-model.yaml` with `scripts/threat-model-sidecar.py` rather than editing it.

Two hazards. The `#[cfg(feature = "build")]` directly after `mod rekor` belongs to `mod attestor`
and must stay attached to it; only the verifier build notices if it moves. And one stored run,
`1789588410-870c0fe1`, carries a `transparency` value that the next rewrite of that record will
drop, so archive it first.

**Done when** `git grep -i -e rekor -e sigstore -- crates scripts xtask` is empty; `transparency`
survives only in one read-compatibility test for old run files; `git grep -e '--rekor' -e
'--transparency' -- README.md docs ':!docs/16-findings.md' ':!docs/adr'
':!docs/19-distribution-and-lookup.md'` is empty; a run file with a `transparency` key still reads;
and both builds, every test and `xtask policy` pass.

### Phase 2 — make the statements carry what a published record needs

Before anything is published, because all of it is signed. D3 is decided first, because the
repository is signed into the falsifying command and the dispute pointer. Until it is, the namespace
is configuration (`[publish] repo`), and nothing is published.

- Subjects carry sha256, sha512 and sha1 wherever the ecosystem publishes them. The npm fetcher
  verifies downloads against the declared digests; the NuGet fetcher does so where the catalog
  carries `packageHash`, and records its absence where it does not; the run records what was
  declared and whether it matched.
- The verdict moves to `equivalence/v2` and `divergence/v2` with every §4.2 field: the evidence
  digests, including the set manifest's file digest; the canonical purl; the building Trigon
  version; the falsifying command, with the log's origin; and the dispute pointer. `rebuild` names
  the stabilizer set, additively. An absent derivation stays absent.
- The `void/v1` and `withdrawal/v1` predicates exist. `attest` signs `void/v1` for a run `decide`
  calls void, and still refuses a verdict for it. `attest --withdraw <record> --reason <code>` signs
  a withdrawal, and `attest <run> --supersedes <record> --reason <code>` a superseding verdict, each
  reading the named record from a local clone. Threat-model P6 is reworded to match. `GET
  /v1/runs/{id}/attestation` serves `void/v1` to anonymous callers, and still refuses a verdict
  envelope for a void run.
- The run keeps what it throws away today — the strategy as a blob with `RunRecord.strategy` set,
  the guard manifest, and the building Trigon version.
- Attestations are stored per run and append-only, instead of per target, where a later attest
  overwrites an earlier one: 40 of the 93 attestation paths in the local store were shared by more
  than one run when this was measured.

**Done when** a fresh `attest` produces v2 statements with every §4.2 field present, a test
asserting each; old v1 bundles still verify; attesting one target twice leaves both runs' envelopes
readable; and a guard-tripped run yields `void/v1` and never a verdict.

### Phase 3 — make a run publishable

`publication::decide` needs two agreeing attempts, counted by a cache key that only worker jobs set,
so none of the runs in the local store qualifies and a publish command built today would publish
nothing. This is backlog B31.

- Build every cache key, worker and CLI alike, from the target, the strategy digest and the
  stabilizer-set digest, as `RunRecord::cache_key` documents; `trigon enqueue` uses the purl alone
  today.
- Give CLI rebuilds a way to run the confirming attempt, such as `trigon rebuild --confirm <run>`.
- Make the agreement count compare comparison digests, as `Corroboration::agreeing_attempts`
  documents, rather than outcomes alone.
- ADR-0010 safeguard 1 asks for attempts "on different workers at different times", because ambient
  nondeterminism dominates. So a confirming attempt records its host, its cache state and when it
  started, and `decide` refuses a pair on one host unless D8 accepts same-host confirmation
  (`same_host_confirmation`), and a pair whose second attempt started less than a configured
  interval after the first.

**Done when** a CLI-originated run reaches `Published` only through a second attempt at the same
cache key, started at least the configured interval after the first, on a different host or, if D8
accepts it, on the same host with an empty build cache and images re-pulled by digest.

### Phase 4 — the record, the log and the index, as pure code

In `trigon-attest`, with no network:

- the record file's format and its checks: every envelope verifies, every evidence file present
  matches the digest its statement names and an absent one is reported unchecked, the signed subject
  matches the key it was found under, and the signed purl canonicalises to it;
- `--rerun-comparison` also re-derives the signed `differences`, `applied` and `members`, and checks
  the published comparison report against them, where today it checks only the outcome and the
  stabilized digests;
- the log: the leaf encoding for every kind in §2.3, with leaf times that never go backwards; RFC
  6962 hashing; recomputing a root from every leaf; inclusion proofs and consistency between two
  checkpoints over C2SP tiles; checkpoint and signed-note verification in the form §2.3 fixes, which
  is the form witnesses require; and following key-change, log-end and log-continuation leaves as §8
  describes;
- lookup by key over the verified leaves, and supersession;
- index path derivation for every key in §5, and the versioned purl canonicalisation, with test
  vectors shared by writer and readers;
- `verify-attestation --record <file> --evidence <dir>` in the network-free verifier, with the
  source's keys and checkpoint from `--source` or from `--log-vkey`, `--attestation-key` and
  `--checkpoint`, and `bundle` optional.

**Done when** the network-free verifier checks a record, its leaf and the log's consistency from a
directory; golden files cover every format; and `xtask policy` passes.

### Phase 5 — `trigon publish`

In the build half, shelling out to `git` as Trigon already does for sources, to the repository
`[publish] repo`, `TRIGON_PUBLISH_REPO` or `--repo` names (§2.4). The push credential is `git`'s own
(§2.4) and is chosen by D5; if D4 publishes rebuilt artifacts, uploading them also takes a token
with contents-write on the repository, or a workflow's `GITHUB_TOKEN`, from the environment, never
logged and never on argv. `trigon publish [RUN…] [--repo <location>] [--withdrawal <envelope>]
[--heartbeat] [--dry-run] [--reconcile] [--prune]` runs one at a time per host, enforced by a lock
in the host's state directory and one in the store, against its working clone (§2.4):

1. Fetch, and reset the working clone hard to the remote, discarding any unpushed commit and any
   checkpoint signed for it. Verify the remote checkpoint's signature, recompute the root from
   exactly its first N leaves, and refuse if they differ, or if the checkpoint does not extend the
   newest one this host has published or verified for the log (§2.4). Anything in `log/` beyond N
   is ignored and overwritten, and a branch that names git attributes is refused before it is
   checked out.
2. For each run, read its publication from a `trigon_api::Index` loaded from the store, with
   `Switches { stop_divergences }` set from the repository's kill-switch. Refuse anything not
   `Published` or `Void`; every divergence while `divergences = "refuse"`; a run already logged; the
   second run of an agreeing pair whose first is published; and a verdict for a subject with a
   current record, unless it supersedes it.
3. Upload any rebuilt artifacts as release assets, if D4 publishes them, before anything references
   them. An asset is named by its digest, so a retry reuses it, and an asset orphaned by a failed
   publication is harmless.
4. Write each record file and its evidence files, deduplicated by digest; append one leaf per
   record, in the order the runs were named, each at the next index after N; write the new tiles,
   removing the partials of any tile this fills; and regenerate the index entries for every key of
   every record, and the feed if D7 chose one, from the log.
5. Sign the checkpoint in a separate, socketless step, `trigon log sign`, which reads the new tree
   from disk and holds the log key; `publish` never holds it. `log sign` signs only a tree whose
   first N leaves recompute to a checkpoint it has itself verified, which extends the newest
   checkpoint of the log this host has published, and whose every new leaf names a record file on
   disk whose envelopes verify under the attestation key and whose signed statement matches the
   leaf.
6. Commit exactly what steps 4 and 5 wrote as one commit — never by `git add`, which a
   `.gitignore` or an attribute can make skip or rewrite a file — check that it holds those bytes
   and nothing else, and `git push` without force. If the push is rejected, another writer won:
   discard the commit and the signed checkpoint, which must never leave this host, and return to
   step 1. With one publishing host (D5) and the lock, that cannot happen; it is handled
   because a second host is a configuration mistake away.
7. Record `RunRecord.published`: repository, commit, record digest and leaf index. A run whose
   record is already logged but has no `published` — a crash after the push — is completed here.
   Only now may a rebuilt artifact be pruned locally: when a publish repository is configured and D4
   publishes rebuilt artifacts, `attest --prune` refuses a run that is not published, and `publish
   --prune` prunes after this step.

`trigon publish --withdrawal <envelope>` pushes a withdrawal signed by `trigon attest --withdraw
<record> --reason <code>`. It asks no `decide`, because there is no run; it refuses unless the
record it names is logged; and it runs steps 1 and 4 to 6 for it. `trigon publish --heartbeat`
appends a `heartbeat` leaf, by steps 1 and 4 to 6, when the newest leaf is older than `heartbeat`,
and does nothing otherwise, so a scheduler can run it daily.

`--dry-run` prints every file and leaf it would write, and the checkpoint body it would sign,
unsigned; it never runs `trigon log sign`, and writes nothing. `--reconcile` rebuilds `index/` and
the feed from the log in one commit.

The repository is created by `trigon log init --origin <origin> --repo <location>`, which writes
`keys/`, the README, and a checkpoint of size 0, whose root is the SHA-256 of the empty string, in
the first commit. The README states the origin, the keys, the checkpoint rate and how to report a
dispute. On GitHub, the default branch then gets a ruleset that forbids force-pushes and deletion
with an empty bypass list; `log init` prints the `gh api` call that sets it, and never makes it
itself. `trigon log key-change --new-key <file>` and `trigon log succeed --origin <origin> --log-key
<file> [--url <location>]… [--dir <dir>]` write the rotation leaves of §8 through the same steps.

Before this phase is finished, a spike against a scratch GitHub repository records what matters at
scale: clone and fetch times for a partial, shallow clone at 10⁴ and 10⁵ synthetic records; push
times for a commit of a few hundred files; the practical limits on release assets; and GitHub's
behaviour for a repository growing by thousands of files a day, including its limits for
unauthenticated clones and fetches, which GitHub advises keeping to about 15 git reads a second, and
its advice of at most 6 pushes a minute to one repository. The results go into `16-findings.md` and
feed D2. The spike is `scripts/evidence-spike.sh`, which runs only with `TRIGON_LIVE=1`, against a
scratch repository the person running it names and that holds nothing else; it has not been run,
and `16-findings.md` §3.101 says so until it is.

**Done when** a run publishes to a local bare repository in one commit and a fresh clone verifies
it; `publish` refuses a withheld run and publishes a void run only as `void/v1`; two concurrent
publishers leave one linear history and never two different roots for one size on the remote, and a
lost race leaves no signed checkpoint outside the losing host; a publisher killed at any step leaves
either the old state or the new, never half of one, apart from orphaned release assets that the
retry reuses; files planted in `log/` beyond the checkpoint are never signed; `--dry-run` leaves the
repository byte-identical; `--reconcile` restores a deleted index file; `attest --prune` refuses a
run that is not published when a repository is configured and D4 publishes rebuilt artifacts; a
withdrawal of a published record is logged with its supersession; a heartbeat leaf is appended only
when one is due; a key change and a log succession are followed by a client; a repository named by
an HTTPS URL, an SSH URL, a `file://` URL, a bare repository's path and a working tree's path each
publish; and the spike is recorded.

### Phase 6 — consuming

`trigon evidence add`, `list`, `remove` and `sync` over any number of sources, with the
configuration and environment of §2.4, per-source caches and state, and mirror checks (§6.1).
`trigon lookup`, `trigon check [--min …] [--max-risk …] [--require …]` and `verify-attestation
--lookup` over the local clone, all as §6 describes: the partial shallow clone by default, full-log
verification on every sync, lookup from the leaves, the two freshness clocks and `--offline`, and
`--remote` as the labelled exception. The lockfile parser keeps integrity digests. `trigon serve`
shows a run's published record, and the repository's kill-switch beside its own. `GET
/v1/artifacts/{alg}:{digest}` honours the algorithm it is given instead of discarding it, and
searches every run rather than the newest 500.

**Done when**, on a machine whose only network access is to GitHub: `trigon check` over a lockfile
names every published verdict after one sync and no further requests, says never checked for the
rest, and says unknown when the clone is stale and GitHub cannot be reached, or the source is
frozen; a record file removed in a later commit is reported as deleted; a logged record whose index
entry was removed is still found; a superseded record is shown superseded; a checkpoint that does
not extend the stored one is refused, and so is a clone rolled back behind the state directory; a
record with one byte changed fails verification with exit 4; a withdrawn record reads as withdrawn;
`verify-attestation --lookup … --rerun-comparison` re-derives a published verdict from the upstream
file alone for an exact verdict, and from the rebuilt one too where the repository that holds the
record does not publish rebuilt artifacts (D4); a source is configured by `evidence.toml`, by
`TRIGON_EVIDENCE_REPO`, and by `evidence add`, with an HTTPS URL, a `file://` URL and a local path
each; a project's `.trigon/evidence.toml` that tries to add a URL to an existing source is refused;
and, with two sources configured, a divergence in either fails the check and the disagreement is
printed, an unreachable source that is not required leaves only its own answers missing, a mirror
whose checkpoint does not extend its source's is reported as an equivocation, and a record signed
with one source's key is refused when found in another's repository.

### Phase 6c — the rebuilt artifact by the record's source

A follow-up to phase 6, settling the first owner item of [findings](16-findings.md) §3.103.
`verify-attestation --lookup … --rerun-comparison` decided whether to fetch the rebuilt artifact
from the consumer's own `[publish] rebuilt_artifacts`, which says what the consumer's host
publishes and nothing of what the source being checked publishes. It now depends on the record and
its source alone (§4.2 item 6, §6), and the setting governs only what `publish` uploads.

**Done when**, against a server on `127.0.0.1:0`: an asset of the verdict's digest in the
`rebuilt-YYYY-MM` releases of the source's GitHub repository is used; one of other bytes is refused,
exit 4; no such asset, including one only in a release outside the series, is exit 5 with the advice
to pass `--rebuild <file>`; a source not on github.com is the same, with no request made;
`--rebuild` given makes no request; and the consumer's own setting, unset or either value, changes
none of it. Built ([findings](16-findings.md) §3.103), and its review added: an exact verdict makes
no request and takes the upstream file as its rebuilt artifact, held to the digest it signs (it
exited 5 at first, asking for that file again as `--rebuild`); only the series of the
record's month and the months either side are listed, so that full releases of other months cost
nothing; an unfinished upload is passed over, and a failed download goes on to the next release;
GitHub refusing or failing is exit 5, never a refutation, and a download asked for is said to have
named the artifact however it ended; plain HTTP is followed nowhere but loopback; a source on
github.com by SSH is on github.com; and every repository that holds the record is asked, the source
it was resolved in first, other bytes in another source's being exit 5, and a project's source never
where the user's own resolved it.

### Phase 7a — bounding a compromised attestation key (D6)

Whichever D6 chooses: key epochs sealed in the log by an offline root, so that a statement signed by
a retired key after its seal is refused without a clock; or ADR-0011's certificate chain (B21 steps
4 and 5), checked against a witness cosignature time or against RFC 3161 tokens from two independent
authorities. This can follow phase 6 whenever D6 is decided.

**Done when** a client refuses a statement signed by a retired key after its seal, or, under the
chain, one whose certificate was not valid at the witnessed or time-stamped time.

### Phase 7b — witnessing (D1)

Apply to the witness network, push each checkpoint to the witnesses that accept us, and make clients
require k-of-n pinned cosignatures, Ed25519 or ML-DSA-44. The network publishes testing and staging
witness lists today and no production list yet, and its application asks for the log's checkpoint
rate, which the README states. A log-key rotation starts a new origin and needs a new application.
The log format needs no change: §2.3 already fixes what witnesses require.

**Done when** a client refuses a checkpoint that lacks its required cosignatures.

### Phase 8 — keep the threat model and the record current (alongside every phase)

With phase 0b, the threat model keeps "The operator" — whoever passes the flags — out of scope, and
gains A8, the operator of any evidence repository a client trusts: a stolen attestation key, a
stolen log key, a stolen push credential, and silent retraction or equivocation; and A9, a host or
mirror serving a stale or split view. A project's `.trigon/evidence.toml` is recorded as input
chosen by the thing under test. Each phase then updates it as it ships. Phase 2 rewords P6 for
`void/v1`. Phase 4 adds properties for record, inclusion and consistency verification. Phase 5 adds
the outbound push and release upload, and the credential read. Phase 6 adds the clones into the
user's cache and the state directory as side effects, configured sources as trusted input and
project sources as untrusted, and disclaimers for record availability and freshness.
`docs/09-attestations.md` §6–§7 describe the store and verification as built, and each phase gets a
findings entry.

### Phase 9 — the standalone client (after D3)

`npx trigon-check` and `uvx trigon-check`, as §6 describes, pinned to our repository's keys and a
checkpoint, and a release key with the `release` leaf that logs each client release. It waits on D3,
because what it pins does not exist until then.

**Done when** each checks a lockfile against a downloaded tarball of the repository with the same
answers and exit codes as `trigon check`, and refuses a release that is not logged.

---

## 11. Decisions for the owner, and open questions

Each decision blocks something. D3 blocks phase 2, because the repository is signed into every
record, and phase 9. D8 blocks phase 3. D4 and D5 block phase 5 — D4 because a record either names a
rebuilt artifact or does not, and a published record is immutable. D4 does not block phase 2: the
signed falsifying command takes the rebuilt artifact from the user when none is published (§4.2 item
6). D2 blocks the first split of the repository, and the spike in phase 5 informs it. D7 blocks
publishing any divergence, which phase 5 refuses until it is decided. D6 blocks phase 7a and the
first rotation of the attestation key. D1 blocks phase 7b. Every decision that changes behaviour is
also a setting (§2.4), so the code is built with each default and the decision flips it.

**D1. Witnessing: now, later, or never?** Without it the log is ours alone, and a rewrite is
detectable but not preventable. Recommendation: build phases 0 to 6 with the log already in
witness-ready form, apply to the witness network in parallel, and schedule phase 7b when a witness
accepts us.

**D2. When and how the repository splits.** One repository is simplest for a consumer, and GitHub
asks for a repository under about 1 GB and strongly under 5 GB. The candidates are one repository
per ecosystem, each with its own log and origin and shipped to clients as its own source (§6.1); or
rolling over to a new repository per era, the old log ending in a `log-end` leaf and the successor
starting with a `log-continuation`. Recommendation: one repository until the phase 5 spike says
otherwise, with the split rule and the client's way of following it written down before the first
split, not during it.

**D3. The namespace, and the dispute channel.** `github.com/<owner>/trigon-evidence`, with disputes
as issues there. Which owner? Needed before phase 2 publishes anything, and before phase 9.

**D4. Publishing rebuilt artifacts** (`rebuilt_artifacts`, default `none`). Makes
`--rerun-comparison` possible without a rebuild. It means redistributing a build of an open-source
package beside its evidence, as a release asset. Licences that require source availability are
satisfied by the source being where the record says it is, but it is still a redistribution, and
that wants a decision rather than an assumption.

**D5. Where `publish` runs, where the log key lives, and with which credential.** Where the store
is: today a workstation, pushing with a fine-grained token or a deploy key scoped to the evidence
repository, with the log key on the same machine, used only by the socketless `trigon log sign`, and
the heartbeat run by the workstation's scheduler. That puts both keys and the push credential on one
machine (§8). Or a GitHub Actions workflow in the evidence repository using `GITHUB_TOKEN`, which
needs the publishable runs made available to it, and makes the log key a secret on a networked
runner; moving the store into object storage for that is itself infrastructure to run and pay for.
The heartbeat of §7 is part of this decision: it needs a scheduled job that holds the log key, and
without one every source freezes after `frozen_after`.

**D6. What bounds a compromised attestation key.** Either ADR-0011's certificate chain (B21 steps 4
and 5), checked against witness or RFC 3161 time, or key epochs sealed in the log by an offline
root, which need no clock. Needed before the first rotation of the attestation key, and before phase
7a is designed. Until then no statement's validity depends on a time, and a rotation is a
`key-change` leaf (ADR-0014 Decision 8).

**D7. Safeguard 4 without infrastructure** (`divergences`, default `refuse`). ADR-0010 requires
maintainer notification at publish time, and §9 rules out filing issues automatically. The git
design makes one answer cheap: a divergence feed, `feed/divergences.atom`, written in the same
commit as the record and keeping the most recent entries (the log keeps them all), which maintainers
and registry security teams can subscribe to. That amends "fires at publish time" to "is published
at publish time". The alternative is email, which needs a sending account and is infrastructure.
Until this is decided, `publish` refuses divergences.

**D8. Confirming attempts on one host** (`same_host_confirmation`, default `false`). ADR-0010
safeguard 1 asks for two agreeing attempts "on different workers at different times", because
ambient nondeterminism dominates. With no infrastructure to run, there is one host. Same-host
confirmation — an empty build cache, images re-pulled by digest, and a minimum interval between the
attempts — catches a floating dependency or a fetch that happened to succeed, and cannot catch
anything the host itself holds constant. Recommendation: accept it, and amend safeguard 1 to say so.

**Open questions:**

1. **What happens to the corpus when a stabilizer set changes?** Re-running everything is a warm
   re-sweep; the alternative is records under several set digests and a client that picks. §4.2 item
   2 sharpens it: the set digest does not cover pass code, so a behaviour change can hide under an
   unchanged digest. Should the digest cover the code, or should each set be archived as WASM, in
   `evidence/`, so that a claim can be re-derived under the set that made it?
2. **Sigstore in the endgame.** If npm or PyPI ever accept third-party attestations, they will want
   Sigstore bundles; ADR-0014 defers that bridge until then. What would it have to carry?
3. **When the gate changes its mind after publication.** A later disagreeing attempt, or a crossed
   false-mismatch rate, leaves a published verdict standing, and the kill-switch stops only what
   comes next. Should `publish` then issue a `withdrawal/v1` with reason `attempts_disagree_later`
   automatically, queue one for a human, or leave the record and let the history show the later run?
4. **Comparing checkpoints between users.** Until witnesses exist, a split view is caught by a
   client that syncs a source's mirrors, or when two users compare. Should the client print each
   source's checkpoint root in every report, so that comparing is as easy as pasting a line into an
   issue, and should we run the second mirror ourselves from day one?
