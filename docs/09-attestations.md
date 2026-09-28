# 09. Attestations

## 1. What we are willing to sign

Every Trigon attestation is an [in-toto Statement v1](https://in-toto.io/Statement/v1) wrapped in a
[DSSE](https://github.com/secure-systems-lab/dsse) envelope with payload type
`application/vnd.in-toto+json`, published as a JSONL bundle.

A verifier **who has never heard of a language model** has to be able to check the claim:

> Recipe **R**, executed in fully described environment **E**, produced artifact **A** whose
> stabilized form under versioned stabilizer set **S** equals the stabilized form of published
> artifact **P**.

Every noun there is deterministic. Whether a model helped derive **R** appears beside the claim as a
provenance fact and stays out of it.

## 2. Predicates

| Predicate type | Emitted when | Subject |
|---|---|---|
| `https://trigon.dev/rebuild/v1` | a run that is not void is attested, and a build ran | the rebuilt artifact: sha256 and sha512 |
| `https://trigon.dev/equivalence/v2` | `trigon attest`, and `trigon rebuild --attest` through the same code, for a run that compared and is not void (§2.5) | the **upstream** artifact: sha256, sha512, and sha1 for npm |
| `https://trigon.dev/divergence/v2` | as `equivalence/v2`, when the verdict is `Divergent` | the upstream artifact, as above |
| `https://trigon.dev/equivalence/v1` | `trigon verify --attest`, which compares two files with no run behind it, and whose statement is **not publishable**: `publish` accepts only v2 verdicts, `void/v1` and `withdrawal/v1`. Before 2026-09-27, `trigon attest`; before 2026-09-28, `trigon rebuild --attest`, which asked no gate and so signed a verdict even for a run voided by open egress or a stabilizer somebody wrote | the upstream artifact, as above |
| `https://trigon.dev/divergence/v1` | as `equivalence/v1`, when the verdict is `Divergent` | the upstream artifact, as above |
| `https://trigon.dev/buildobservation/v1` | a run that is not void is attested; its `tier` says what was observed | the **upstream** artifact, as above |
| `https://trigon.dev/void/v1` | `trigon attest` and `trigon rebuild --attest`, for a run the publication gate calls void, and nothing else is signed for it (§2.6) | the upstream artifact, as above |
| `https://trigon.dev/withdrawal/v1` | `trigon attest --withdraw`: a published record is withdrawn (§2.7) | the withdrawn record's own subject |

**A subject carries every digest a consumer might hold the artifact by**, because a lookup key that
is not in the subject finds nothing ([`19`](19-distribution-and-lookup.md) §5). An npm lockfile
names a package by its sha512 `integrity`, and an old one by its sha1 `shasum`, and neither is
sha256. So the upstream subject carries sha256 and sha512 always, and sha1 where the ecosystem
publishes one, which is npm alone (`Ecosystem::publishes_sha1`); the rebuilt artifact is ours and
nobody looks it up by sha1. Every digest is **computed over the bytes**, by the attestor from the
blob it fetched by hash, and never copied from what a registry declared: a declaration is a claim
the fetch checked, and is recorded on the run instead (`RunRecord.upstream_digests`). Where a run
kept no bytes — one that reached no verdict — the subject uses the digests the fetch computed and
recorded; a run recorded before those existed is named by sha256 alone. `verify-attestation
--rerun-comparison` checks every digest a subject names against the file in hand, and a statement
signed before subjects carried more than sha256 verifies exactly as it did. Signed statements from
before 2026-09-27 carry sha256 only.

We **also** emit a conformant `https://slsa.dev/provenance/v1` statement alongside `rebuild/v1`, so
existing SLSA tooling consumes our output without knowing anything about Trigon.

### 2.1 `rebuild/v1`

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "rebuild/left-pad-1.3.0.tgz",
      "digest": { "sha256": "b1946ac92492d2347c6235b4d2611184…", "sha512": "…" } }
  ],
  "predicateType": "https://trigon.dev/rebuild/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://trigon.dev/builds/Rebuild@v1",
      "externalParameters": {
        "target": {
          "purl": "pkg:npm/left-pad@1.3.0",
          "artifact": "left-pad-1.3.0.tgz",
          "upstreamDigest": { "sha256": "e9f1a3b0…" },
          "selectionPolicy": "bulk-default@3"
        }
      },
      "internalParameters": {
        "strategy": {
          "digest": { "sha256": "9c1185a5c5e9fc54612808977ee8f5…" },
          "kind": "flow",
          "derivation": "ci_derived",
          "trustTier": "typed",
          "inline": "<base64 of the canonical JCS strategy>"
        },
        "renderedInstructions": {
          "sourceScript": { "sha256": "…" },
          "depsScript":   { "sha256": "…" },
          "buildScript":  { "sha256": "…" },
          "outputPath": "left-pad-1.3.0.tgz"
        },
        "environment": {
          "baseImage": "trigon/base-node@sha256:5f2b…",
          "runner": "k8s-job",
          "isolation": "gvisor",
          "egressTier": "mirror-only",
          "observabilityTier": 1,
          "registryMoment": { "kind": "timestamp", "value": "2018-11-22T17:00:04Z" },
          "sourceDateEpoch": 1542906004,
          "locale": "C.UTF-8", "timezone": "UTC", "umask": "0022",
          "arch": "x86_64",
          "toolchains": { "node": "10.17.0", "npm": "6.11.3" }
        },
        "confirmation": {
          "policy": "two-agreeing-attempts",
          "cacheKey": { "sha256": "c41f…" },
          "attempts": [
            { "runId": "01J…A", "ordinal": 0, "purpose": "initial",
              "worker": "w-17", "finishedOn": "2026-09-08T02:11:40Z" },
            { "runId": "01J…B", "ordinal": 1, "purpose": "confirmation",
              "worker": "w-42", "finishedOn": "2026-09-08T06:35:02Z" }
          ]
        }
      },
      "resolvedDependencies": [
        { "uri": "https://github.com/stringandstring/left-pad",
          "digest": { "gitCommit": "ea6b26bb8b3f01a1b3f6b0b2d3a7…" },
          "annotations": {
            "discovery": "fuzzy_tag",
            "ref": "left-pad-1.3.0",
            "subdirectory": "packages/left-pad",
            "declaredUri": "git+ssh://git@github.com/stringandstring/left-pad.git"
          } },
        { "uri": "trigon/base-node", "digest": { "sha256": "5f2b…" } },
        { "name": "definitions", "uri": "git+https://github.com/trigon-dev/trigon-definitions",
          "digest": { "sha1": "77c1b0…" } }
      ]
    },
    "runDetails": {
      "builder": { "id": "https://trigon.dev/builder/v1",
                   "version": { "trigon": "0.4.2", "stabilizers": "sha256:2b7c…" } },
      "metadata": { "invocationId": "01J…A",
                    "startedOn": "2026-09-08T02:09:12Z",
                    "finishedOn": "2026-09-08T02:11:40Z" },
      "byproducts": [
        { "name": "build.log",     "digest": { "sha256": "…" } },
        { "name": "Dockerfile",    "digest": { "sha256": "…" } },
        { "name": "network.jsonl", "digest": { "sha256": "…" } }
      ]
    },
    "derivation": {
      "method": "ci_derived",
      "transcript": null,
      "reviewedBy": null
    }
  }
}
```

Note `derivation`. When a model was involved it reads:

```json
"derivation": {
  "method": "model_assisted",
  "transcript": { "sha256": "3fa1…" },
  "models": ["claude-opus-5"],
  "reviewedBy": null
}
```

**Method records provenance rather than trust.** A consumer who wants to filter on "no model
touched this" can, and offering that capability costs one field.

**And `resolvedDependencies` records the other half of the verdict.** This section described it from
the beginning and the implementation emitted an empty array for months: the statement said which
recipe by digest, which image and which egress tier, and not what source the artifact was built
from. A reader holding it could not answer the question the npm chapter of
[`03-ecosystems.md`](03-ecosystems.md) says *is* the npm product — whether the published tarball
corresponds to the claimed source.

Three details of the source entry are load-bearing:

- **`gitCommit`, not `sha1`.** SLSA's digest set names the algorithm, and "sha1" does not say what
  was hashed. A generic SLSA consumer reads `gitCommit` without knowing anything about Trigon.
- **`annotations.discovery`** names the rung that found the commit: `registry_commit`, `exact_tag`,
  `fuzzy_tag`, `tree_hash_match`, and so on. A commit npm recorded in `gitHead` and a commit found
  by stripping `python-ecdsa-` off a tag name support very different verdicts, and a consumer that
  cannot tell them apart will read every verdict as the stronger one. `SourceDiscovery`'s own
  definition says it "predicts a false result better than anything else available"; until it was
  put here it was recorded nowhere a reader could see, only on a `--verbose` terminal line.
- **`annotations.declaredUri`** is what the registry actually said, present only when it differs
  from `uri`. Canonicalizing is lossy and the canonical form is what every other field shows:
  `git+ssh://…`, `github:a/b`, `http://` and a `…/issues` view URL all collapse to the same
  `https://github.com/a/b`, and a record holding only the result cannot be checked against the
  package. `ecdsa` declares `http://github.com/tlsfuzzer/python-ecdsa` and we build from `https://`;
  that is almost certainly fine and it is not ours to assert silently.

The strategy is also listed among `byproducts`, not only hashed in `internalParameters`: a digest of
a blob the statement does not offer is not something a reader can check.

**As built, two things differ from the example above.** `rebuild/v1` names the stabilizer set the
rebuilt artifact was judged under, as `stabilizerSet: {"id", "digest": {"sha256"}}` in the verdict's
shape, beside `runDetails.builder.version.stabilizers`; the field was declared and the attestor
passed no set, so no statement carried one ([`19`](19-distribution-and-lookup.md) §4.2 item 2). It
is additive, and the predicate stays v1: nothing that reads a statement rejects a field it does not
know, and a test holds `Statement` and `Envelope` to that. And `derivation.method` is present only
where the run recorded a derivation. It used to be signed as `heuristic` for a run that recorded
none, which is absence rendered as a value. `derivation.transcript` is `{"sha256": …}`, the digest
of the model exchange the run kept (`RunRecord.transcript`), and `null` only where it kept none: it
was `null` whatever the run held, and 24 of 75 attested runs in one store had a transcript no
statement named. The exchange itself is not published, since it is unredacted
([`19`](19-distribution-and-lookup.md) §4.1); the digest binds the derivation to it for anybody who
holds it. There is no `models` list; `reviewedBy` stays, as `null`.
`runDetails.builder.version.trigon` is the attestor's version, which since the same change names the
git revision it was built from (`0.0.0+git.<rev>`); the version that ran the build is in the
verdict.

### 2.2 `equivalence/v1`

The load-bearing one.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "left-pad-1.3.0.tgz",
      "digest": { "sha1": "5b8a3a77…", "sha256": "e9f1a3b0…", "sha512": "5c8e4c3f…" } }
  ],
  "predicateType": "https://trigon.dev/equivalence/v1",
  "predicate": {
    "outcome": "normalized",
    "containerBitIdentical": false,
    "archiveFormat": "tar+gzip",
    "artifacts": {
      "upstream": { "sha256": "e9f1a3b0…", "sha512": "…", "bytes": 2412 },
      "rebuild":  { "sha256": "b1946ac9…", "sha512": "…", "bytes": 2455 }
    },
    "container": {
      "upstream": { "sha256": "1f0c2d44…" },
      "rebuild":  { "sha256": "1f0c2d44…" }
    },
    "stabilized": {
      "upstream": { "sha256": "7d865e95…" },
      "rebuild":  { "sha256": "7d865e95…" }
    },
    "stabilizerSet": {
      "id": "npm-tarball",
      "digest": { "sha256": "2b7c4f…" },
      "members": [
        "tar-entry-order", "tar-time", "tar-mode", "tar-owners", "tar-xattrs", "tar-device",
        "gzip-compression", "gzip-name", "gzip-time", "gzip-misc",
        "npm-prefix", "npm-install-fields"
      ]
    },
    "applied": [
      { "id": "tar-time",           "risk": "metadata",   "provenance": "builtin",
        "entriesTouched": 41, "bytesChanged": 0 },
      { "id": "gzip-compression",   "risk": "structural", "provenance": "builtin",
        "entriesTouched": 0,  "bytesChanged": 0 },
      { "id": "npm-install-fields", "risk": "metadata",   "provenance": "builtin",
        "entriesTouched": 1,  "bytesChanged": 78 }
    ],
    "provenanceCap": {
      "applied": true,
      "maxRiskApplied": "metadata",
      "allBuiltin": true
    },
    "comparator": { "digest": { "sha256": "8e1f…" } },
    "diffReport": { "sha256": "0000…" },
    "rebuildAttestation": { "sha256": "<digest of the rebuild/v1 statement>" }
  }
}
```

`outcome` is a **string** rather than an ordinal. `provenanceCap` states the invariant from
[`00-overview.md`](00-overview.md) §3.1 outright, so a consumer never re-derives it from `applied`.

`archiveFormat` is there because a verifier holding an attestation and two artifacts has no
`EcosystemSpec` to ask. The stabilizer profile implies the format in most cases and not in all, and a
verifier that guesses wrong reads a `.gem` as a plain tar and produces a different digest for a
correct artifact. Naming it costs one string.

The `container` digests are present for a compressed container and absent otherwise. They are what
`container_bit_identical` derives from ([`05`](05-archive-and-normalization.md) §4.2), and they let a
verifier tell "the tar matched, the gzip framing did not" without re-running the pipeline.

### 2.3 `divergence/v1`

Negative results are first-class. The predicate carries the **deterministic** difference signature
and no model prose.

```json
{
  "predicateType": "https://trigon.dev/divergence/v1",
  "predicate": {
    "outcome": "divergent",
    "stabilizerSet": { "id": "wheel", "digest": { "sha256": "…" } },
    "summary": { "onlyUpstream": 0, "onlyRebuild": 0, "differs": 3 },
    "differences": [
      { "path": "pkg/_version.py", "kind": "source",
        "ruleIds": ["embedded-vcs-describe"],
        "upstreamDigest": { "sha256": "…" }, "rebuildDigest": { "sha256": "…" },
        "byteRanges": [[112, 148]] },
      { "path": "pkg/_speedups.abi3.so", "kind": "executable",
        "ruleIds": [], "note": "executable-content-differs",
        "upstreamDigest": { "sha256": "…" }, "rebuildDigest": { "sha256": "…" } }
    ],
    "diffReport": { "sha256": "…" },
    "confirmation": { "policy": "two-agreeing-attempts",
                      "attempts": [ { "runId": "01J…A" }, { "runId": "01J…B" } ] },
    "disputes": "https://trigon.dev/dispute/01J…A",
    "reverify": "trigon verify-attestation trigon.intoto.jsonl --rerun-comparison"
  }
}
```

### 2.4 `buildobservation/v1`

```json
{
  "predicateType": "https://trigon.dev/buildobservation/v1",
  "predicate": {
    "tier": 1,
    "egressTier": "mirror-only",
    "networkTranscript": { "sha256": "…", "requests": 214, "bytes": 18244912 },
    "hosts": ["mirror.internal", "registry.internal"],
    "violations": [],
    "artifactHashCheck": {
      "performed": true,
      "matched": false,
      "guardManifest": { "sha256": "aa71…" },
      "guardedMembers": 34,
      "mirrorRefusedTargetUrl": true
    }
  }
}
```

`artifactHashCheck.matched: true` means the upstream artifact entered the sandbox. The run is then
void, and `trigon attest` signs `void/v1` (§2.6) and nothing else: no verdict, and not this
statement either.

### 2.5 `equivalence/v2` and `divergence/v2`

What `trigon attest` signs since [`19`](19-distribution-and-lookup.md) §10 phase 2: the verdict a
published record carries. **A v2 verdict is a v1 verdict with fields added**, never one with a field
moved, so `outcome`, `stabilizerSet`, `archiveFormat`, `artifacts`, `stabilized`, `applied`,
`provenanceCap`, `container`, `members` and `differences` are where §2.2 and §2.3 put them, and
`verify-attestation --rerun-comparison` reads both versions through one path. The subject is the
upstream artifact, with every digest §2 describes. A divergence is `divergence/v2`, an outcome of
anything else `equivalence/v2`.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "left-pad-1.3.0.tgz",
      "digest": { "sha1": "5b8a3a77…", "sha256": "e9f1a3b0…", "sha512": "5c8e4c3f…" } }
  ],
  "predicateType": "https://trigon.dev/equivalence/v2",
  "predicate": {
    "outcome": "normalized",
    "stabilizerSet": { "id": "tar-gzip", "digest": { "sha256": "4598411b…" } },
    "…": "every v1 field, unchanged",
    "purl": "pkg:npm/left-pad@1.3.0",
    "purlCanon": 1,
    "run": { "id": "1789000000-870c0fe1",
             "startedOn": "2026-09-27T00:00:00Z", "finishedOn": "2026-09-27T00:03:00Z" },
    "trigonVersion": { "builder": "0.0.0+git.255d2f57…", "attestor": "0.0.0+git.9c41e0aa…" },
    "egressTier": "mirror-only",
    "attestable": true,
    "derivation": { "method": "heuristic" },
    "evidence": {
      "stabilizerSetManifest": { "sha256": "51d0…" },
      "comparison": { "sha256": "3d88…" },
      "strategy": { "sha256": "b02f…" },
      "guardManifest": { "sha256": "e5c9…" },
      "rebuiltArtifact": { "sha256": "a91c…" }
    },
    "falsifyingCommand": { "argv": ["trigon", "verify-attestation",
      "--lookup", "sha256:e9f1a3b0…", "--predicate", "https://trigon.dev/equivalence/v2",
      "--origin", "github.com/<owner>/trigon-evidence", "--rerun-comparison",
      "--upstream", "<file>"] },
    "disputePointer": { "kind": "url",
                        "url": "https://github.com/<owner>/trigon-evidence/issues" }
  }
}
```

| Field | What it is | Present | `docs/19` §4.2 |
|---|---|---|---|
| `outcome` | `exact`, `normalized`, `normalized_with_caveats` or `divergent`, a string | always | 1 |
| `stabilizerSet.id`, `.digest.sha256` | the set the comparison was made under | always | 2 |
| `run.id`, `.startedOn`, `.finishedOn` | the run, and when it ran | always; `finishedOn` where the run recorded it | 3 |
| `trigonVersion.builder` | the Trigon that ran the build, from `RunRecord.trigon_version` | where the run recorded it | 3 |
| `trigonVersion.attestor` | the Trigon signing this statement | always | 3 |
| `egressTier`, `attestable` | in the verdict itself, where they were only in `buildobservation` and `rebuild` | always | 4 |
| `derivation.method` | `definition`, `heuristic`, `ci_derived`, `model_assisted` | only where the run recorded one; absent stays absent | 5 |
| `falsifyingCommand.argv` | the command that would falsify this verdict | only when `[publish] origin` and `disputes` are both set | 6 |
| `disputePointer` | `{"kind": "url", "url": …}`, where a dispute goes | as `falsifyingCommand` | 6 |
| `evidence.stabilizerSetManifest` | sha256 of the set manifest's canonical JSON — a file, and not the set digest, which hashes the manifest's rows | always | 7 |
| `evidence.comparison` | the comparison report the run stored | always | 7 |
| `evidence.rebuiltArtifact` | the rebuilt artifact | always | 7 |
| `evidence.strategy` | the strategy blob (`RunRecord.strategy`), fetched and recomputed before it is signed | where the run stored its strategy | 7 |
| `evidence.guardManifest` | the manifest the artifact guard was armed with | where the guard was armed **and** the store holds the manifest | 7 |
| `purl`, `purlCanon` | the package's canonical purl (§2.9) and the canonicalisation version | always | 8 |
| `supersedes`, `reason` | `sha256:<record>` and one of `withdrawn`, `set_changed`, `attempts_disagree_later`, `pipeline_bug` | on a superseding verdict (`attest --supersedes`) | 9 |

**The falsifying command is argv, not a shell line.** A client runs it without parsing one out of
a signed document, and renders it by joining with spaces, which gives exactly `trigon
verify-attestation --lookup sha256:<subject> --predicate <type> --origin <origin>
--rerun-comparison --upstream <file>`. It cannot name its own record's digest, which is the digest
of the file that contains it, so it names the subject, the predicate type and the log's origin and
the client resolves the current record through the log. `<file>` is the upstream artifact the reader
holds; where rebuilt artifacts are not published (D4), the client asks for `--rebuild <file>` too.

**Both or neither.** `attest` signs the falsifying command and the dispute pointer only when
`[publish] origin` and `disputes` are both set in `evidence.toml`, and leaves both out — absent,
never empty — when either is missing, and says so. A statement made for local use names no
repository, and `publish` will refuse it.

**Every evidence digest names a blob the attestor read.** The set manifest is written to the store
as a blob of its canonical JSON (`trigon_attest::set_manifest_file`) when the verdict is signed, so
its digest names bytes a record can carry; the strategy is fetched by hash and its `strategyDigest`
recomputed; a guard manifest the store does not hold, which is every run recorded before manifests
were kept, is left out of `evidence` and the attestor says so, while `buildobservation` still names
its digest for what the guard was armed with. The names are shared with the record file's `evidence`
map (§2.8, `trigon_attest::evidence_key`), so the two compare key for key.

**v1 is still signed, and still verifies, and is not published.** `trigon verify --attest`
compares two files with no run behind them — no purl, no strategy, no building version, no attempt
a gate could count — and writes `equivalence/v1` and `divergence/v1`: a claim about two local files,
which `publish` refuses, since it accepts only `equivalence/v2`, `divergence/v2`, `void/v1` and
`withdrawal/v1`. `trigon rebuild --attest` has a run behind it and, since
[`19`](19-distribution-and-lookup.md) §10 phase 3, signs exactly what `trigon attest` signs for
that run, through the same code: v2 for a verdict, `void/v1` for a run the gate calls void, and
never a verdict for one. It wrote v1 until then, signing what the comparison said without asking
the gate, so at `--egress open`, its default, every run it signed was a void signed as a verdict
([`16-findings.md`](16-findings.md) §3.97). **No path signs a verdict for a run the gate voids.**
Every v1 statement verifies exactly as it did, through `verify-attestation`, `--rerun-comparison`
and `GET /v1/runs/{id}/attestation`; bundles signed before v2 existed are kept as fixtures and
checked (`crates/trigon/tests/fixtures/v1-statements/`).

### 2.6 `void/v1`

What `trigon attest` signs, **and all it signs**, for a run the publication gate calls void — and
`trigon rebuild --attest`, which signs through the same code:
`trigon_api::publication::voided`, which is `decide`'s own answer. The artifact guard tripped —
whether or not the run reached an outcome, since a tripped guard ends the build — or the run
reached an outcome at `open` egress, or a stabilizer a person or a model wrote applied. It is "we
looked, and could not tell, for this reason".

```json
{
  "predicateType": "https://trigon.dev/void/v1",
  "predicate": {
    "outcome": "void",
    "because": "guard_tripped",
    "facts": {
      "artifactHashCheck": {
        "performed": true,
        "trips": ["the artifact under test arrived from registry.npmjs.org"],
        "guardManifest": { "sha256": "e5c9…" },
        "guardedMembers": 34
      }
    },
    "egressTier": "mirror-only",
    "attestable": true,
    "purl": "pkg:npm/left-pad@1.3.0",
    "purlCanon": 1,
    "run": { "id": "1789000000-870c0fe1", "startedOn": "…" },
    "trigonVersion": { "builder": "…", "attestor": "…" },
    "evidence": { "guardManifest": { "sha256": "e5c9…" } }
  }
}
```

- `because` is the gate's reason, `guard_tripped`, `open_egress` or `non_builtin_stabilizer`, as
  `Withheld::key` spells it.
- `facts` holds what establishes it: `artifactHashCheck`, which says whether the guard ran and what
  tripped it, and `authoredStabilizers` — each non-builtin pass that applied, by id, risk and
  provenance — where there were any. The third fact, the egress tier, is `egressTier` at the top
  level, where every statement about a run has it. The attestor checks each against the store:
  a record that says a hand-written pass applied, over a comparison in which none did, is refused.
- `stabilizerSet` is present where the run compared; a build the guard stopped names no set.
- `evidence` holds at most the guard manifest (§2.8).
- `supersedes` and `reason`, as §2.5, where `attest --supersedes` names a record.

**No comparison outcome and no difference data**: no `artifacts`, `stabilized`, `applied`,
`members`, `differences`, `container` or `provenanceCap`, no comparison report and no rebuilt
artifact digest — beside the upstream's, the rebuilt artifact's digest says whether the rebuild was
`exact`. Anything that says which way the run went is an outcome published without the safeguards
an outcome needs, and for a divergence it is the accusation the gate exists to stop. There is no
falsifying command, because there is no claim to falsify, and `--rerun-comparison` refuses a void as
"makes no comparison claim".

`GET /v1/runs/{id}/attestation` serves an anonymous reader of a void run its `void/v1` envelopes and
nothing else, chosen by the predicate each envelope carries; a void run whose only statements are
verdicts — every open-egress run attested before this — is refused with the gate's reason. An
operator is served every statement the run names.

### 2.7 `withdrawal/v1`

"We were wrong", with no verdict in its place, signed by `trigon attest --withdraw <record>
--reason <code>`. There is no run behind it.

```json
{
  "subject": [ "…the withdrawn record's signed subject, digest for digest…" ],
  "predicateType": "https://trigon.dev/withdrawal/v1",
  "predicate": {
    "purl": "pkg:npm/left-pad@1.3.0",
    "purlCanon": 1,
    "supersedes": "sha256:7f3a…c2",
    "reason": "withdrawn",
    "trigonVersion": { "attestor": "…" }
  }
}
```

The subject and `purl` are the withdrawn record's own, as its signed statement names them, so a
client that finds the withdrawal under a key finds it under every key the record had. `supersedes`
is the sha256 of the record file; `reason` is one of the closed list. There is no `outcome`. The
envelope is filed in the store under the record it withdraws, append-only as statements are:
`withdrawals/sha256/<record>/withdrawal.intoto.json`, then `.2`, `.3`.

`<record>`, for `--withdraw` and `--supersedes` alike, is a path to a record file for now. Nothing
checks its signatures yet ([`19`](19-distribution-and-lookup.md) §10 phase 4 defines that, and
phase 6 adds resolving a record by digest in a clone); what is taken from it is its name, the sha256
of its bytes, and what its own statement says it is about. A superseding verdict must be about the
same artifact, digest for digest, and the same canonical purl, since a client drops a superseded
record only for one that is, and `attest` refuses one that is not.

### 2.8 The record file, `trigon.record/v1`

One published result, as [`19`](19-distribution-and-lookup.md) §4.1 lays it out:
`trigon_attest::Record`, verified by `trigon_attest::evidence::check_record` (§7).

```json
{
  "schema": "trigon.record/v1",
  "subject": { "purl": "pkg:npm/left-pad@1.3.0",
               "digests": { "sha512": "1df6…", "sha1": "0e7c…", "sha256": "8b2e…" } },
  "statements": [ "…the verdict, void or withdrawal envelope, then rebuild and buildobservation…" ],
  "evidence": { "stabilizerSetManifest": "sha256:51d0…", "comparison": "sha256:3d88…" }
}
```

The record's own name is the sha256 of its bytes, which are its canonical JSON
(`Record::encode`), so a record's name is a function of what it holds. `Record::assemble` writes one
from its envelopes, taking the unsigned `subject` and `evidence` map from the signed statement, so a
record agrees with itself by construction; a reader still checks that it does. The map writes each
piece of evidence as `sha256:<hex>` under the name the statement signs it by, and is empty for a
withdrawal. `Record::statement` finds the one statement that is its result — a verdict, a void or a
withdrawal — by predicate type, not by position. Reading a record refuses a file that is not one
(another `schema`, not this shape) and checks nothing else; unknown keys are read past, as
everywhere a verifier reads. `evidence::record_leaf` gives the leaf a record is logged under, from
its signed statement, for the writer of §10 phase 5.

### 2.9 The canonical purl

Every v2 verdict, void and withdrawal signs its package's purl in canonical form beside
`purlCanon`, the version of the rule, which is also the digit in the `purl1` and `pkg1` index paths.
Version 1 is `trigon_core::purl::canonicalize`:

- the scheme is `pkg` in any case, and slashes after it are ignored; the type is lowercased, and
  `crates.io` and `rubygems` become `cargo` and `gem`;
- every component is percent-decoded and re-encoded: ASCII letters, digits and `-._~:` as
  themselves, `/` as itself inside a version or a qualifier value, and every other byte `%XX` in
  uppercase hex; an unencoded npm scope, `@babel/core`, reads as `%40babel/core`;
- empty namespace segments are dropped; namespace and name are lowercased where the purl
  specification says the type is case-insensitive — both for `alpm`, `apk`, `bitbucket`,
  `composer`, `deb`, `github` and `hex`, the namespace for `rpm`, the name for `bitnami`, `npm` and
  `oci` — and nowhere else, so Go, Maven, NuGet and crate names keep their case;
- lowercasing is of the ASCII letters `A`–`Z` only. Every type above spells its names in ASCII, and
  Unicode case mapping would merge names that are different (KELVIN SIGN lowercases to `k`) and is
  not one mapping across languages (full and simple mapping disagree on `İ`);
- a PyPI name is normalised as PEP 503 says — lowercased, each run of `-`, `_` and `.` one `-` —
  which is stricter than the purl specification's `_`-only rule, because PyPI resolves all of those
  spellings to one project;
- qualifier keys are lowercased, an empty value drops its pair, a key given twice is refused, and
  pairs are sorted; a subpath segment that decodes to nothing, `.` or `..` is dropped, so `%2E%2E`
  is dropped as `..` is, and the canonical form canonicalises to itself;
- whitespace, a malformed escape and bytes that are not UTF-8 are refused.

The versionless form, the `pkg1` key, is the package and nothing about one version of it:
`pkg:<type>/<namespace>/<name>` as above, with the `repository_url` qualifier where the purl has
one, and no version, no subpath and no other qualifier. A qualifier that names one version's files —
`file_name`, `checksum`, `download_url` — gave every version its own `pkg1` key while it was kept;
`repository_url` stays because the same name on another registry is another package
([`16-findings.md`](16-findings.md) §3.97). The test vectors,
`crates/trigon-core/testdata/purl-canon-v1.json`, are the rule's other definition: every writer and
reader of these keys, a client in another language included, is held to them.

### 2.10 The evidence log's formats

The log of [`19`](19-distribution-and-lookup.md) §2.3, which is the design, as built in
`trigon_attest::log`: pure code, no network, reading only the directory it is given. Nothing writes
an evidence repository yet (`publish` is §10 phase 5); `verify-attestation --record` (§7) reads one.
Golden files for every format are in `crates/trigon-attest/testdata/log/`, and were checked against
Go's `golang.org/x/mod/sumdb/note` and `sumdb/tlog` ([`16-findings.md`](16-findings.md) §3.98).

- **Checkpoint.** C2SP tlog-checkpoint, three lines — origin, decimal size, base64 root — and no
  extension lines when we write one; a reader tolerates extension lines and keeps nothing of them.
  It is a C2SP signed note under the log key, an Ed25519 key (type `0x01`) whose name is the
  origin, and it opens only when a signature by the pinned key verifies and its first line is the
  key's name. A log with no leaves signs SHA-256 of the empty string.
- **Signed notes** are read as Go reads them: at most 100 signature lines, and a line by a key not
  pinned read past, since a witness cosigns beside us. Two things are stricter: base64 must be
  canonical, and every line naming the pinned key must verify, where Go checks only the first.
- **The log key's private half** is a file in Go's format, `PRIVATE+KEY+<name>+<hash>+<keydata>`,
  where `<hash>` is the verifier key's eight hex digits and `<keydata>` is base64 of `0x01` and the
  32-byte seed; the hash is recomputed from the seed and a mismatch refused. No refusal quotes the
  key, or any byte of it: the length is checked before the type byte, which is never shown, since
  a bare seed's first byte is a byte of the secret. Its name is held to the verifier key's rule —
  no space, no control character, no `+` — so no signer exists whose verifier key cannot.
- **Tree and proofs.** RFC 6962: a leaf hashes as SHA-256(0x00 ‖ leaf), a node as SHA-256(0x01 ‖
  left ‖ right). Inclusion and consistency proofs are generated as RFC 6962 defines them and
  verified by RFC 9162's algorithms. A proof binds the tree's size only by its shape — leaf 3's path
  is the same in trees of 5 to 8 leaves — so the size a proof is checked against is always the
  signed checkpoint's.
- **Tiles.** C2SP tlog-tiles, height 8: `tile/<L>/<N>[.p/<W>]` for hashes and
  `tile/entries/<N>[.p/<W>]` for leaves, N in groups of three digits with every group but the last
  prefixed `x`, and each leaf in a bundle framed by its length as a big-endian uint16, so a leaf
  over 65,535 bytes is refused. A tree of N leaves has exactly the full tiles and partials that size
  gives, and a reader opens those and no others: a full tile or wider partial beside them is beyond
  the checkpoint and never read. An append writes each new tile and bundle, partials beside older
  ones, and names the `.p` directory of every tile it fills, which the same commit removes.
- **Leaves** are canonical JSON (`trigon_core::jcs`), each with `kind` and `time`, in Unix seconds
  and at most 2^53 − 1, so a JavaScript client reads it exactly. Decoding is strict: an unknown
  kind, an unknown field, a field that breaks a rule, or bytes not in canonical form are refused,
  because these formats are ours and signed into the tree. A record leaf's `purl` is checked
  against the canonicalisation rule its `purlCanon` names, any this build has
  (`trigon_core::purl::canonicalize_under`), not only the newest: a leaf is never rewritten, and
  one logged under rule 1 must still read once there is a rule 2. A refusal escapes whatever it
  quotes of a leaf.

| `kind` | Fields besides `time` |
|---|---|
| `record` | `subject` (`sha256`, and `sha512` and `sha1` where signed, lowercase hex); `purl`, canonical under `purlCanon`; `predicateType`, one of `equivalence/v2`, `divergence/v2`, `void/v1`, `withdrawal/v1`; `outcome`, the verdict's, `void` for a void, absent for a withdrawal; `stabilizerSet`, `sha256:<hex>`, on every verdict and on a void where its run compared; `keyId`; `record`, `sha256:<hex>` of the record file; `supersedes` and `reason` together, on a supersession and every withdrawal |
| `heartbeat` | none |
| `key-change` | `old` and `new`, each `keyId`, `publicKey` (hex) and `signature` (base64) over the message below |
| `release` | `name`, `version`, `artifacts` (file name to `sha256` and optional `sha512`), `keyId`, `signature` by the release key |
| `log-end` | `successor`: `origin`, `logKey` (its C2SP vkey, named by that origin), `urls` (empty for this repository), `dir` (`log/<n>`, or `log` in another repository) |
| `log-continuation` | `checkpoint`: the old log's final checkpoint, a signed note carrying both log keys' signatures |

Both keys of a `key-change` sign `trigon.dev/key-change/v1`, the origin of the log the leaf is in,
the leaf's time, and the old and new public keys in hex, each on a line of its own and each line
ending in a newline. The release key signs `trigon.dev/release/v1`, the origin, the time, and the
canonical JSON of `name`, `version` and `artifacts`, likewise. The first line is a domain no other
signature by those keys begins with; the origin keeps a change from being replayed into another
log.

**Verifying a log** (`verify_log`) checks, from its files: the checkpoint's signature and origin;
every leaf of every bundle the checkpoint's tree has, hashed, and the root recomputed and compared
first; then each leaf decoded, with times that never go backwards, a `log-end` only as the last
leaf and a `log-continuation` only as the first; every tile, against the recomputed hashes, since a
reader proving inclusion from tiles relies on them; and, given the checkpoint last accepted, that
the new one is no smaller and its first leaves hash to the accepted root. The root comes before the
leaves because a leaf that breaks a rule is the log key's doing only if the checkpoint signs it: a
bundle altered after signing is refused as files that are not the signed tree, never as the log
breaking its own rules. A refusal for not extending the accepted checkpoint carries both signed
notes as read, and shows them escaped. A reader without the leaves asks the same of the tiles alone
(`verify_extension_from_tiles`, and `prove_inclusion_from_tiles` against a signed checkpoint only).
There a failed consistency proof is an equivocation only when its hashes lead to the new signed
root, which authenticates them; tiles that do not are damaged or planted, and say nothing about the
log key. `verify_source` walks a repository's chain, `log/` then each successor a `log-end` names,
following one only when its first leaf is a `log-continuation` that holds the old log's final
checkpoint, signed by both log keys, and reports every `log/<n>` that no `log-end` names as refused.
The chain starts at the newest checkpoint the pinned key opens, in whichever directory holds it, and
at the first such directory whose files verify: a directory is never chosen on what its checkpoint's
text says, and any other claiming that log — unsigned, unreadable, an older state the newest
extends, a copy — is reported and set aside, so planting one neither stops the source nor moves it
back. Two checkpoints the pinned key opens whose trees are not one tree — the same size with two
roots, or an older one the newest does not extend — are something only the log key can sign: an
equivocation, which refuses the source with both signed notes (`LogError::Equivocation`,
[`16-findings.md`](16-findings.md) §3.99). `KeyHistory`
follows `key-change` leaves from the pinned attestation key: one from the current key counts only
when both keys signed it over this log's origin, and from that leaf on a record signed by the old
key is refused. The writer (`VerifiedLog::plan_append`) is held to what those readers check, as far
as one log can know it — a key change signed over this log's origin, a `log-end` naming a successor
with another origin, a `log-continuation` signed by this log's key and holding another log's
checkpoint — and the free `plan_append` to a tail that is the tree's own leaves, because a leaf or a
full bundle once written is there for good.

### 2.11 The evidence repository's paths, and the index

Where each file of an evidence repository is ([`19`](19-distribution-and-lookup.md) §2.3, §5), as
`trigon_attest::evidence::paths` derives it, for the writer and every reader. The fan-out is the
first four hex characters of the name, everywhere, and every digest is whole.

| What | Path |
|---|---|
| a record file, by the sha256 of its bytes | `records/<aa>/<bb>/<hex>.json` |
| an evidence file, by the sha256 of its bytes | `evidence/sha256/<aa>/<bb>/<hex>` |
| the index, by a subject digest | `index/sha256/…/<64 hex>.json`, `index/sha512/…/<128 hex>.json`, `index/sha1/…/<40 hex>.json` |
| the index, by purl | `index/purl<n>/<aa>/<bb>/<sha256 of the canonical purl>.json` |
| the index, by package | `index/pkg<n>/<aa>/<bb>/<sha256 of the versionless form>.json` |

`<n>` is the canonicalisation rule the record's leaf names (§2.9), so a record is filed under the
rule it was logged under, and a reader looking a purl up tries every rule it has. The rebuilt
artifact is never in the repository: it is a release asset, if D4 publishes it.

An index file is canonical JSON, `{"key": …, "records": [{"record": "sha256:…", "leaf": 1203}]}`,
with `"log": "log/<n>"` on an entry whose leaf is in a successor log. Its `key` is the index
directory's name and the key's value — `sha512:<hex>`, `purl1:pkg:npm/left-pad@1.3.0`,
`pkg1:pkg:npm/left-pad` — so a reader can check a file is at the path its key derives. It is
derived data: `evidence::index_files` computes the whole index from a verified log, entries in the
log's order and the superseded ones included, and a client with the log never reads it. The shared
purl vectors (§2.9) are held to these paths in `crates/trigon-attest/tests/evidence_repo/paths.rs`.

## 3. Signing

```rust
pub trait Signer: Send + Sync {
    fn key_id(&self) -> String;
    fn sign(&self, pae: &[u8]) -> Result<Signature, AttestError>;
}
```

**Synchronous, revised during implementation** ([`16-findings.md`](16-findings.md) §3.1). The trait was specified `#[async_trait]`, and the
verifier build is why it is not. `trigon verify-attestation` links `trigon-attest` and must contain
no async runtime — that is the claim §7 makes checkable, and `xtask policy` enforces it — so an
async method here would drag `tokio` across the judgement line for the benefit of signers that do
not exist yet. A synchronous trait is callable from an async context by whoever holds the runtime;
the reverse needs an executor everywhere. A network signer (a KMS) blocks in its own
implementation, or lives behind an async façade in a crate below the line.

| Implementation | Use | Built |
|---|---|---|
| **keyed, under a trusted root** — a key we hold, a certificate chaining to a published root | The default for public instances once a root exists ([ADR-0011](adr/0011-keyed-signing-under-a-trusted-root.md)); whether one is built is [docs/19](19-distribution-and-lookup.md) D6 | partly — the envelope carries a chain; nothing validates it to a root yet ([B21](17-backlog.md#b21-keyed-signing-under-a-trusted-root)) |
| **cloud KMS** (AWS, GCP, Azure) holding the intermediate | Where the chain above is issued from in a fleet | no |
| **local file key** (`ed25519-dalek`) | Development and air-gapped use, and, until a root exists, the single pinned key records are published under ([ADR-0014](adr/0014-git-evidence-store-without-rekor.md) Decision 8). Produces an *unchained* statement and says so. | **yes** |
| **unsigned** | We still emit statements, and they still help locally | **yes** |

**Sigstore keyless is not the default and is not planned.** ADR-0011 has the reasoning; the short
version is that a Fulcio certificate's identity is an email address or a CI workflow, and the claim
an attestation makes is *"the attestor, at this version, re-derived this from these bytes"* — which
that identity cannot say, and which would put a person's name on a public accusation about somebody
else's package. Nor is any other part of Sigstore used:
[ADR-0014](adr/0014-git-evidence-store-without-rekor.md) removed the transparency-log client that
was built, and [`16-findings.md`](16-findings.md) §3.92 has the measurements behind it.

**Nothing bounds a stolen key yet.** An ephemeral key bounds a compromise by construction; a
long-lived one is bounded by whatever dates its signatures, and today nothing does. ADR-0011 meant a
log's signed timestamp to do it, checked against a certificate's validity window; that check was
never live, and the log is gone. [`19-distribution-and-lookup.md`](19-distribution-and-lookup.md)
D6 chooses what replaces it — key epochs sealed in our own evidence log, or a certificate chain
checked against a witness's or a time-stamping authority's time — and until then no statement's
validity depends on a time ([threat model](threat-model.md) D24).

#### End to end

```bash
# 1. A signing key, once. `trigon public-key <file>` prints the public half again later.
trigon keygen --out ~/.trigon/signing.key

# 2. Rebuild and attest, in one script that keeps the two processes separate.
scripts/rebuild-and-attest.sh pkg:pypi/chardet@7.4.3 --key ~/.trigon/signing.key

# 3. Check it, offline, with nothing trusted: the signature, and the claim re-derived from the two
#    files. Step 2 prints this command with every path filled in for the run it just did — the
#    shape below is what those parts mean, not something to retype.
trigon verify-attestation <store>/attestations/.../equivalence.intoto.json \
    --public-key "$(trigon public-key ~/.trigon/signing.key)" \
    --rerun-comparison --upstream <published> --rebuild <rebuilt>
```

`<published>` and `<rebuilt>` are the two artifacts the rebuild left behind: the published one at
the top of the work directory, and the one Trigon built under
`<work>/rebuild/<strategy>-<pid>/` with the same name. The script resolves that pair itself, and
says so rather than printing a placeholder if it cannot.

Step 3 prints:

```
subject   chardet-7.4.3-py3-none-any.whl (1173b74051570cf0…)
predicate https://trigon.dev/equivalence/v2
claims    exact
signature verified
rederived exact under wheel@58632c3c627d — the claim holds
```

The rebuild's record stays in the store, so a later `trigon attest` signs it again without building.

At an enforced egress tier the image build has no network, so the base image must already carry
what the strategy needs. A build that is missing something says which packages and prints the
`trigon base-image` command that adds them.

#### Making the key

```
trigon keygen --out ~/.trigon/signing.key [--public-out ~/.trigon/public.pem]
```

The private key is written `0600` — created at that mode rather than `chmod`ed to it afterwards,
because a `chmod` leaves a window in which the key is on disk and world-readable. The mode is then
read back and the file removed if it did not take, since a filesystem that ignores permissions
accepts the request and hands everyone the key.

It **refuses to overwrite an existing key, and there is no `--force`.** A signing key is not a file
you can regenerate: the moment the old one is gone, every statement ever signed with it is
unattributable. Move it aside deliberately if that is what you want.

The command prints the public key as hex, which is what a checker pins:

```
trigon verify-attestation <bundle> --public-key <hex>
```

That pinning is the whole point — an unpinned signature is worth exactly the bundle's
re-derivation and no more. `--public-out` additionally writes SPKI PEM, the form `openssl` reads
and the one an evidence repository publishes its attestation key in (`keys/attestation.pub`,
[`19`](19-distribution-and-lookup.md) §2.3).

`keygen` is deliberately available in the `--no-default-features` verifier too, which links no
runtime and no network client: generating a signing key on a machine that has never had a socket
open is a reasonable thing to want. What it produces is a **bare** key, signing unchained
statements that verify against a pinned public key and nothing else. Until a root exists, that is
also the key records are published under: one attestation key, pinned by every client and named by
key id in every record, rotated only by a key-change leaf that the old key and the new both sign
([ADR-0014](adr/0014-git-evidence-store-without-rekor.md) Decision 8). Whether a root is built at
all (B21 steps 4-5), or key epochs sealed in our own log take its place, is
[`19`](19-distribution-and-lookup.md) D6.

#### Publishing

Nothing in this section publishes. `trigon attest` signs into the store and opens no socket;
publishing is a separate `trigon publish`, behind the publication gate, to an evidence repository —
a public git repository holding the signed records, the evidence to re-derive each, and an
append-only log we sign. It is designed in
[`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) and not built.

Until 2026-09-27 this section described a Rekor client in `trigon attest`, which logged each
equivalence statement at attest time, before any gate had been asked, and a check of the log's
signed timestamp in `verify-attestation`. ADR-0014 removed both. Run records written while it
existed may still carry a `transparency` key, which Trigon now ignores
(`crates/trigon-store/tests/old_run_files.rs`), and `verify-attestation --output json` no longer
has a `transparency` key.

**We hand-write the attestation layer.** The Rust `in-toto` crate does not work, the `sigstore`
crate is incomplete and churning, and RFC 8785 JCS canonicalization sits in the signing path, so we
vendor it at about 150 lines rather than depend on it. in-toto Statement v1 and SLSA Provenance v1
come to about 200 lines of plain serde structs, and DSSE PAE takes five. Owning this costs little,
and the alternative puts a supply-chain dependency in the one place we can least afford one.

### 3.1 The attestor process

Signing happens outside the build sandbox, and outside any process that has executed
sandbox-derived code.

```
build worker ──writes blobs by content hash──▶ CAS
                                                │
                                    attestor process (separate pod, holds the key)
                                                │  reads by hash
                                                │  RE-DERIVES the equivalence claim independently
                                                │  signs only if its own derivation agrees
                                                ▼
                                          attestation bundle
```

Having the attestor run the same comparison a client would run is the cheapest defence against a
compromised judge worker, and it costs one stabilize-and-compare pass over blobs that are already
local.

The road not taken, kept because the reasoning is what led to
[ADR-0011](adr/0011-keyed-signing-under-a-trusted-root.md): under sigstore keyless the workload
identity is the crown jewel, so tokens stay **run-scoped with
minute-scale TTLs** and no worker holds a long-lived credential.

## 4. Model output never enters a signed document

We state this as a rule because the temptation is real. Put an advisory annotation inside a signed
statement and someone reads it as a claim.

| Goes in the signed statement | Stays in the database and UI |
|---|---|
| deterministic difference signature | the Explainer's prose |
| rule ids matched, byte ranges | confidence scores |
| which stabilizers fired, with risk and provenance | suggested stabilizers |
| `derivation.method` and transcript digest | the transcript's content |

We sign the transcript **digest**, which makes the derivation auditable and tamper-evident. Its
*content* makes no claim about the artifact.

## 5. Publishing, including divergences

> **Amended by [ADR-0014](adr/0014-git-evidence-store-without-rekor.md).** Publishing is an explicit
> `trigon publish`, not automatic; a published record is corrected by superseding it; disagreeing
> attempts are withheld rather than void; a void needs one attempt; and divergences are refused
> until safeguard 4 has a channel. [ADR-0010](adr/0010-publish-divergences.md)'s Amendments and
> [`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) §3 have the detail. The list
> below is ADR-0010 as first written.

Attestations publish automatically. A divergence makes a public claim about someone else's
package, so the technical safeguards run strict:

1. **Two agreeing attempts** before anything publishes, divergences and matches alike
   ([`07-ai.md`](07-ai.md) §3). Attempts share a cache key and differ in `Attempt`
   ([`01-architecture.md`](01-architecture.md) §1.1), so the deduplication rule does not collapse the
   second one.
2. A run publishes as `Void`, or waits for review, and **never as a divergence**, when:
   - the egress tier was `Open`, or
   - the **artifact-hash check tripped**, or
   - any applied stabilizer was non-`Builtin`, or
   - the two attempts disagreed.
3. Every published divergence carries a **machine-readable dispute pointer** and the exact
   `trigon verify-attestation --rerun-comparison` command that would falsify it.
4. Maintainer notification fires at publish time, best-effort, via registry contact metadata.
5. **False-mismatch rate is an SLO with a publication kill-switch.** Cross the threshold and
   divergence publication stops until a human clears it.

We built in that asymmetry. A false `Reproduced` is an error. A false `Divergent` is an
accusation.

## 6. Storage layout

Content-addressed and cloud-agnostic (`object_store` over S3, GCS, Azure, or a local filesystem).
As built:

```
blobs/sha256/<aa>/<digest>                         artifacts, comparisons, logs, transcripts,
                                                   strategies and guard manifests
attestations/<eco>/<pkg>/<ver>/<artifact>/<run-id>/<predicate>.intoto.json   one DSSE envelope
runs/<run-id>.json                                 the run record, naming its blobs by digest
stabilizers/sha256/<set-digest>.json               each set a claim was made under, as a manifest
derived/comparison/sha256/<aa>/<digest>.json       a comparison re-derived by `trigon rederive`
decompiled/sha256/<aa>/<digest>.cs                 decompiled .NET source, a reading aid only
```

The design wrote one JSONL bundle per artifact (§8) and a directory per run; the store keeps one
envelope per predicate, and one record per run that names its blobs by digest.

**Attestations are filed per run, and never overwritten.** They were filed per target, so a later
attest of the same target overwrote an earlier one, and the earlier run's record went on naming a
path that held the later run's claim: 40 of the 93 attestation paths in the local store were shared
by more than one run. Since [`19`](19-distribution-and-lookup.md) §10 phase 2 the run id is a
directory below the artifact. Attesting one run again — with a key it was first signed without, or
by a binary that signs something newer — writes a statement that differs beside the one already
there, as `<predicate>.2.intoto.json`, `.3` and so on, and the run record lists every one; the same
bytes again are the same statement and add nothing. A run attested before the change still names
its per-target paths, which still read, since a record names its statements by path. Attested
again, it names only the statements filed under its own id, and its per-target paths move to
`per_target_attestations`, which nothing serves: another run of the same target may have written
over any of them, and neither a build observation nor an equivalence statement says which run it is
about. The attestor merges its paths into the record as it stands when it finishes, not into the
copy it read before signing, and the write is conditional on that version where the backend has
conditional writes, so two attestors on one run do not drop each other's paths. The local
filesystem has none, and there a window of one read and one write remains.

The run also keeps, since that phase, what a published record needs and the work directory used to
take with it: the strategy that ran, as a blob of its canonical JSON named by `RunRecord.strategy`
(the file digest, distinct from `strategy_digest`, which also covers the tools the strategy
reaches); the guard manifest the mirror was armed with, as a blob under the digest
`environment.guard_manifest` already carried; the Trigon version that ran the build; and the
upstream artifact's sha512 and sha1 beside what its registry declared. The attestor signs the
strategy blob's digest only after fetching it by hash, reading it as the strategy's canonical JSON,
and recomputing `strategy_digest` from it under its own tools; a blob that is missing, is not that,
or does not recompute refuses the attestation before any statement is filed.

Path-addressing matches the definitions repository layout, so a downstream analyzer parses an
object-storage notification straight back into a `Target`.

The store is the operator's own and nothing outside it reads it. What is published goes, one
record per result, to an evidence repository whose layout is
[`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) §2.3.

**Retention:** on a match, store the rebuilt artifact's digests rather than the artifact. Keep bytes
on divergence, where they are the evidence. That one rule accounts for most of the storage budget
([`10-scale.md`](10-scale.md) §2).

## 7. Verification

Two forms, both in the network-free verifier. A bundle, on its own:

```
trigon verify-attestation equivalence.intoto.json \
    --public-key <hex> \
    --rerun-comparison --upstream <published> --rebuild <rebuilt>
```

and a published record, against the log of the evidence repository it is from
([`19`](19-distribution-and-lookup.md) §6):

```
trigon verify-attestation --record <file> --evidence <dir> \
    (--source <name> | --log-vkey <vkey> --attestation-key <key> [--checkpoint <file>]) \
    [--rerun-comparison --upstream <published> --rebuild <rebuilt>]
```

`<dir>` is a clone, or any directory with the §2.3 layout of `19`. `--source` takes the source's
keys from `evidence.toml` and the checkpoint last accepted for it from its state directory,
`$TRIGON_EVIDENCE_STATE/<name>/checkpoint` or else
`$XDG_STATE_HOME/trigon/evidence/<name>/checkpoint`, or, before any sync has accepted one, its
configured initial checkpoint; the flags give the same for a source not configured. Where there is
no checkpoint at all, the output says the log was checked whole and not against anything seen
before.

Steps:

1. **Decode** the envelope, and its in-toto statement.
2. **Check the signature** against a pinned key. For a bundle, the key given with `--public-key`;
   without one the signature is reported present and unchecked. For a record, always: every
   envelope must carry a signature that verifies under the attestation key its source had at the
   record's leaf — the pinned key, or one a `key-change` leaf signed by both keys moved to — so a
   record signed by a key the source never had, or by one retired before its leaf, fails. A chain to
   a root replaces the pinned key if [B21](17-backlog.md#b21-keyed-signing-under-a-trusted-root) is
   built.
3. **Check the record against the log**, for the record form (`trigon_attest::evidence`). The log
   first, whole, as §2.10 says, under the pinned log key and against the checkpoint last accepted:
   a checkpoint it does not extend, or two trees under its key in one repository, refuses it. A
   checkpoint given that is not one is a bad argument, and never the source's failure. Then the
   record: its sha256 must be a leaf's `record` — a record no leaf names is *unlogged*, and one the
   log holds at two leaves is *logged twice*, since a record logged again after what withdraws it
   would otherwise read as current again; its signed statement must agree with that leaf on
   subject digests, purl and its rule, predicate type, outcome, set digest, `supersedes` and
   `reason`; a void or a withdrawal is one statement; a verdict's `rebuild` is of its run and under
   its set, and about the rebuilt artifact it names, and its `buildobservation` about its subject,
   under its egress tier and the guard manifest it names, with no guard tripped —
   `buildobservation` names no run, so one of another attempt at the same artifact under the same
   tier and guard is not told apart; the unsigned `subject` and `evidence` map must agree with the
   statement; and every evidence file the statement names that the directory holds must be the
   bytes it names. One absent is reported unchecked, never passed, and so is a rebuilt artifact,
   which is a release asset. Each failure is *record failed verification*, with its reason. Then
   what the source says of the record's artifact now: every record the log holds for its sha256,
   resolved from the leaves and never from `index/`, a leaf whose file is missing *deleted*, and
   every supersession applied as `19` §3 says — only by a verified, logged record signed by the key
   its source had at its own later leaf, about the same subject digests and canonical purl. A
   superseded record is shown superseded, with the reason and both leaves, and never hidden. Where
   the log continues in a repository the directory does not hold, a record logged there may
   withdraw or supersede this one, so what the source says now is *unknown*, never current.
4. **Select statements** with a small typed filter (by predicate type, by build type, by subject
   digest). Not built: the command takes one envelope or one record.
5. **`--rerun-comparison`**: take the upstream and the rebuilt artifacts, load the stabilizer set
   named in the attestation, run both through it, and check that the stabilized digests and the
   outcome are what the statement claims, and so is what it says the comparison found — its
   `differences`, `applied` and `members`, each re-derived by the function that builds a verdict and
   compared whole. A subject whose sha256 is the artifact's and whose sha512 or sha1 is not is
   refuted too: the file in hand is the artifact, and the statement's digests were not all computed
   over it. For a record, the published comparison report, where the directory holds it, is read
   again, held to its signed digest again, and held to the same re-derivation field by field:
   outcome, archive format, set, raw and stabilized digests, differences, applied passes and
   members; every member, with its status, kind, digests and sizes; and the field edits, where it
   carries any. Its progression and notes are explanation a later build may word differently, and
   the members' raw paths are missing from a report written before they were kept, so those are
   reported unchecked, and so are field edits a report does not carry. Through an archived set
   (§7.1), which returns stabilized bytes and no report, those three fields and the report are
   reported unchecked.

A record is shown as [`19`](19-distribution-and-lookup.md) §4.2 has every client show one: with its
outcome, its set's id and digest, its run and when it ran, the Trigon that built it and the one that
signed it, the egress tier and whether the run was `attestable`, and, for a verdict, the derivation
method, the command that would falsify it and where to dispute it. Each is shown as signed, and one
the statement does not sign is shown as absent, never as a value.

The record form exits as [`19`](19-distribution-and-lookup.md) §6 says, from what the source says of
the artifact now: 0 for a verdict at or above `normalized_with_caveats`, 1 for a divergence, 2 for
an artifact withdrawn, 3 for a void or a lower verdict, 4 for a record, a log or a re-derived claim
that failed verification — an equivocation and a deleted record among them — or a source whose log
continues where the directory does not reach, and 5 when it could not check at all: bad arguments,
those `clap` refuses included, an unreadable input, a checkpoint or state file that is not a
checkpoint, a source not configured, a set this build does not carry, or the wrong artifact given to
`--rerun-comparison`. `--rerun-comparison`'s arguments are checked before the record, so a bad one
exits 5 whatever the record is. Of several, the first in the order 5, 4, 1, 3, 2 wins. `--output
json` prints the report with its exit code, and, where the check stops before a record is read, the
exit code, what stopped it and why, with both signed notes of an equivocation or a rollback. A
signature that does not verify, a claim that does not re-derive and a log that fails are reported as
the evidence's fault and never as a bug in Trigon, in both forms.

Step 5 is the flagship, and it explains several other decisions.

An attestation from a **rebuilder**, rather than from the original builder, is worth something only
to someone who distrusts the rebuilder. `--rerun-comparison` makes the equivalence claim
**falsifiable by a third party holding two artifacts and our stabilizer implementation.**

Three consequences, all binding:

- The stabilizer set must be identified by **id and digest** in every attestation.
- **A verifier has to be able to obtain the exact stabilizer implementation**, three years later,
  without trusting us. Naming the set digest is necessary and not sufficient. §7.1 says how.
- `trigon verify` **refuses to compare across differing set digests**. It either loads the named set
  and verifies the original claim, or it re-derives under today's set and labels the result as a new
  claim rather than a verification.

The binary that does it builds `--no-default-features` from
`core + archive + stabilize + compare + attest`, with no network client beyond artifact fetch, no
model code, and nothing from the search half. That is the claim a sceptic can check, and it beats any
architecture diagram.

### 7.1 Getting the implementation that produced the claim

The set digest identifies *which* stabilizers ran. Verifying the original claim needs the *code* that
ran, and a 2029 binary carrying 2029 stabilizers cannot reproduce a 2026 digest. Saying "we archive
every stabilizer version permanently" names a requirement without naming a mechanism, so here is the
mechanism.

**Stabilizer sets ship as content-addressed WASM modules.** A set is a manifest of member ids plus
the digest of one `stabilizers.wasm` component that implements them. We publish that component
alongside the attestation bundle and mirror it into the same object store:

```
stabilizers/sha256/<set-digest>.wasm        the component
stabilizers/sha256/<set-digest>.json        member ids, risk tiers, provenance, build provenance
```

`trigon verify-attestation --rerun-comparison` reads the set digest from the attestation, fetches the
matching component (or takes `--stabilizers ./set.wasm` for an offline verifier), instantiates it
under `wasmtime`, and runs the comparison through it. The component is pure, total, and has no
network or filesystem access, which is what made stabilizers the right first WASM guest in the first
place ([`01-architecture.md`](01-architecture.md) §4).

Three consequences to accept with open eyes:

- **The WASM host moves from v2 to v1**, at least for the verifier. `trigon verify` links `wasmtime`;
  the fleet keeps running native stabilizers compiled from the same source, and a CI test asserts the
  two produce identical digests over the M0 corpus.
- **The component is itself attested**, built reproducibly from a tagged commit, so a verifier can
  check that the code they fetched matches the source they can read.
- **A verifier who declines to run our WASM** can rebuild the component from that tagged commit, or
  fall back to `--stabilizers` with their own build. Neither path requires trusting the binary we
  published.

The fallback, if the WASM host proves impractical, is to name a `trigon` release version in every
attestation and require that release to verify. It works, it keeps every historical binary alive
forever, and it is the option we take only if §7.1 fails.

## 8. Bundle format

One JSONL file per target artifact, each line a DSSE envelope:

```
{"payloadType":"application/vnd.in-toto+json","payload":"…","signatures":[…]}   ← rebuild/v1
{"payloadType":"application/vnd.in-toto+json","payload":"…","signatures":[…]}   ← slsa provenance v1
{"payloadType":"application/vnd.in-toto+json","payload":"…","signatures":[…]}   ← equivalence/v1
{"payloadType":"application/vnd.in-toto+json","payload":"…","signatures":[…]}   ← buildobservation/v1
```

Appending is allowed. A later run against a newer stabilizer set adds lines rather than replacing
the file, which preserves the history of what we claimed and when. Existing lines stay as they
are.
