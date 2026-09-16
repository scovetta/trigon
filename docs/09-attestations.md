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
| `https://trigon.dev/rebuild/v1` | a build ran | the rebuilt artifact |
| `https://trigon.dev/equivalence/v1` | a comparison ran | the **upstream** artifact |
| `https://trigon.dev/divergence/v1` | the verdict is `Divergent` | the upstream artifact |
| `https://trigon.dev/buildobservation/v1` | observability tier ≥ 1 | the rebuilt artifact |

We **also** emit a conformant `https://slsa.dev/provenance/v1` statement alongside `rebuild/v1`, so
existing SLSA tooling consumes our output without knowing anything about Trigon.

### 2.1 `rebuild/v1`

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "rebuild/left-pad-1.3.0.tgz",
      "digest": { "sha256": "b1946ac92492d2347c6235b4d2611184…" } }
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

### 2.2 `equivalence/v1`

The load-bearing one.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "left-pad-1.3.0.tgz",
      "digest": { "sha256": "e9f1a3b0…" } }
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

`artifactHashCheck.matched: true` means the upstream artifact entered the sandbox. In that case we
emit no `equivalence/v1` and no `divergence/v1` statement, and the verdict is `Void`.

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
the reverse needs an executor everywhere. A network signer (sigstore, KMS) blocks in its own
implementation, or lives behind an async façade in a crate below the line.

| Implementation | Use | Built |
|---|---|---|
| **keyed, under a trusted root** — a key we hold, a certificate chaining to a published root, every signature logged to Rekor | The default for public instances ([ADR-0011](adr/0011-keyed-signing-under-a-trusted-root.md)) | partly — the envelope carries a chain and the log entry is real; nothing validates the chain to a root yet ([B21](17-backlog.md#b21-keyed-signing-under-a-trusted-root-and-the-rekor-client)) |
| **cloud KMS** (AWS, GCP, Azure) holding the intermediate | Where the chain above is issued from in a fleet | no |
| **local file key** (`ed25519-dalek`) | Development and air-gapped use. Produces an *unchained* statement and says so. | **yes** |
| **unsigned** | We still emit statements, and they still help locally | **yes** |

**Sigstore keyless is not the default and is not planned.** ADR-0011 has the reasoning; the short
version is that a Fulcio certificate's identity is an email address or a CI workflow, and the claim
an attestation makes is *"the attestor, at this version, re-derived this from these bytes"* — which
that identity cannot say, and which would put a person's name on a public accusation about somebody
else's package. We use Rekor and not Fulcio: the log, not the CA.

**The transparency log is required rather than a bonus, and more so with a key we hold.** An
ephemeral key bounds a compromise by construction; a long-lived one is bounded only by the log.
Rekor returns a **Signed Entry Timestamp** — its own signature over "this entry existed at time T" —
and verification checks that T falls inside the certificate's validity window. An attacker holding
the key from today cannot forge a statement dated last year, because there is no entry for it and
the log is append-only and publicly auditable. Skipping that check silently reduces the whole design
to a pinned public key with extra ceremony.

Rekor accepts an entry signed by any key or certificate and does not require Fulcio, which is what
makes "their log, our CA" a coherent position rather than a hybrid. Staging confirmed it for the
shape we actually emit: an ed25519 key under a self-issued certificate is accepted.

#### End to end

```bash
# 1. A signing key, once. `trigon public-key <file>` prints the public half again later.
trigon keygen --out ~/.trigon/signing.key

# 2. Rebuild, attest and log, in one script that keeps the two processes separate.
scripts/rebuild-and-attest.sh pkg:pypi/chardet@7.4.3 \
    --key ~/.trigon/signing.key --rekor https://rekor.sigstage.dev

# 3. Check it, offline, with nothing trusted: the signature, the claim re-derived from the two
#    files, and the log entry.
trigon verify-attestation <store>/attestations/.../equivalence.intoto.json \
    --public-key "$(trigon public-key ~/.trigon/signing.key)" \
    --rerun-comparison --upstream <published> --rebuild <rebuilt> \
    --transparency <(jq .transparency <store>/runs/<run>.json)
```

Step 3 prints all four results:

```
logged    rekor.sigstage.dev index 56042318 at 2026-09-16T15:20:26Z (71d46696179fcd5d)
          the log's timestamp verifies, and the entry is about this bundle
subject   chardet-7.4.3-py3-none-any.whl (1173b74051570cf0…)
claims    exact
signature verified
rederived exact under wheel@58632c3c627d — the claim holds
```

Add `--dry-run` to step 2 to see the log entry before it exists anywhere. The rebuild is real and
its record stays in the store, so a later run attests without building again.

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
re-derivation and no more. `--public-out` additionally writes SPKI PEM, the form a log entry
carries.

`keygen` is deliberately available in the `--no-default-features` verifier too, which links no
runtime and no network client: generating a signing key on a machine that has never had a socket
open is a reasonable thing to want. What it produces is a **bare** key, signing unchained
statements; a public instance wants a key under a trusted root instead (B21 steps 4-5).

#### What exporting to the log looks like today

`trigon attest --rekor <log-url>` publishes each envelope it signs, and needs `--key` — an unsigned
statement has nothing for a log to be evidence about, and the flag errors rather than quietly
logging nothing. The URL is required because there is no default: a default of
`rekor.sigstore.dev` would make the append-only public log the thing you get by not thinking about
it, and a malformed entry there is public and permanent. Reach for `https://rekor.sigstage.dev`
until the entry shape is settled.

The entry is `intoto` **v0.0.1**, not v0.0.2 — the envelope goes in as a serialized JSON *string*
with the certificate as a sibling `spec.publicKey`. A duplicate submission returns `409` carrying
the UUID of the existing entry, which we fetch and store, so retrying after a timeout is safe
rather than a second entry for the same statement.

**`--dry-run` shows the entry before it exists anywhere.** Publication to an append-only log is the
one write here that cannot be taken back, so `trigon attest --rekor <url> --dry-run` prints the
exact entry that would be POSTed, posts nothing, and writes nothing — not to the log and not to the
store. Everything up to the POST really happens: the claim is re-derived from the artifact bytes and
the envelope is really signed, so what you are shown is the entry rather than a rendering of one.
ed25519 signatures are deterministic, so a real run afterwards signs the identical bytes, which is
what makes the preview predictive rather than indicative. The statement inside the envelope is
printed a second time in readable form, clearly marked as not part of the entry, because it is
base64 twice over and a preview nobody can read is not a preview.

What comes back is stored on the run as `RunRecord.transparency`: the log's URL, the entry UUID,
`logIndex`, `integratedTime`, `logID`, the `signedEntryTimestamp`, and `body` verbatim as the log
returned it. Verbatim matters — the SET covers the log's own serialization, and a re-encoding that
differs by one byte verifies against nothing.

**Verification of that SET is below the judgement line**, in `trigon-attest::transparency`, so the
`--no-default-features` verifier checks it without linking a network client: it is ECDSA P-256 over
RFC 8785 JCS of exactly `{body, integratedTime, logID, logIndex}`, and the log's public key should
be pinned rather than fetched at verification time — fetching it from the log that produced the
signature asks the log to vouch for itself.

#### Reading an entry back

`trigon runs` shows the log and index beside each run, so finding your own entry does not mean
reading the store's JSON by hand:

```
run-4f2a  pkg:npm/demo@1.0.0   exact   attested   rekor.sigstage.dev index 56042173 on 2026-09-16
```

To check one rather than read it:

```
trigon verify-attestation <bundle> --transparency <entry.json>
```

where `entry.json` is a run record's `transparency` field (`jq .transparency runs/<id>.json`). Two
things are checked, and the second is the one that is easy to leave out:

1. **The SET verifies**, which is what says *when* this statement existed.
2. **The entry is about this bundle**, by the payload hash the log recorded. A verifying timestamp
   on an unrelated entry proves that some statement existed at some instant, which is not a claim
   anyone wants to make. Rekor does not keep the envelope — the stored body has only hashes and the
   public key — so the binding runs the other way: hash the statement you hold and check the log
   recorded that one.

No network, and it works in the `--no-default-features` verifier. The log's key is selected by the
`logID` the entry names, which **is** the SHA-256 of that key — so the compiled-in table
(`rekor.sigstore.dev`, `rekor.sigstage.dev`) is an index rather than an authority, and a wrong row
cannot be chosen for an entry it does not belong to. `--log-key <pem>` covers any other log. A key
should be pinned rather than fetched at verification time, because fetching it from the log whose
signature is under test asks that log to vouch for itself.

That identity check also fixed a real ambiguity: verifying against the wrong log's key used to
surface as "the signature does not verify", which reads exactly like a forged entry. It is now
refused by name, before any signature is checked.

#### Finding an entry you did not record

Measured against staging rather than assumed:

| Search | Works |
|---|---|
| `GET /api/v1/log/entries?logIndex=N` | yes |
| `GET /api/v1/log/entries/<uuid>` | yes |
| `POST /api/v1/index/retrieve` with the **DSSE envelope hash** or **payload hash** | yes |
| ...with the **public key** | **no** — returns `[]` |
| ...with the **artifact's sha256** | **no** — returns `[]` |

The last two matter. The index keys on Fulcio-style identity, and a self-issued certificate has
none, so **our entries cannot be enumerated by key.** And Rekor indexes the envelope and payload
hashes, not the statement's `subject` digest, so **a consumer holding the artifact cannot find our
attestation** — they can only check one they were given. This confirms empirically what
[`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) takes from Rekor's maintainers:
the log is an *audit* mechanism, not a *lookup* service. Discovery has to come from somewhere else.

The gap worth naming: the SET yields a time, and **nothing consumes that time yet**, because
certificate validity windows arrive with B21 steps 4-5. Until then the log entry is an auditable
public record of when we said what, which is worth having, but it is not yet the thing that bounds
a compromise of the signing key.

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

Under sigstore keyless the workload identity is the crown jewel, so tokens stay **run-scoped with
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

Content-addressed and cloud-agnostic (`object_store` over S3, GCS, Azure, or a local filesystem):

```
blobs/sha256/<aa>/<full-digest>                       artifacts, diff reports, logs, transcripts
attestations/<eco>/<pkg>/<ver>/<artifact>/trigon.intoto.jsonl
runs/<run-id>/manifest.json
runs/<run-id>/{build.log.gz,network.jsonl,transcript.json}
```

Path-addressing matches the definitions repository layout, so a downstream analyzer parses an
object-storage notification straight back into a `Target`.

**Retention:** on a match, store the rebuilt artifact's digests rather than the artifact. Keep bytes
on divergence, where they are the evidence. That one rule accounts for most of the storage budget
([`10-scale.md`](10-scale.md) §2).

## 7. Verification

```
trigon verify-attestation trigon.intoto.jsonl \
    --identity 'https://github.com/trigon-dev/.github/workflows/sign.yml@refs/heads/main' \
    --rerun-comparison
```

Steps:

1. **Decode** the JSONL bundle; verify each DSSE envelope.
2. **Check the signing identity** against policy, whether a Fulcio certificate identity, a KMS key
   id, or a pinned public key.
3. **Check Rekor inclusion**, if the bundle claims it.
4. **Select statements** with a small typed filter (by predicate type, by build type, by subject
   digest).
5. **`--rerun-comparison`**: fetch the upstream artifact by digest and the rebuilt artifact by
   digest, load the stabilizer set named in the attestation, run both through it, and check that the
   stabilized digests match what the statement claims.

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
