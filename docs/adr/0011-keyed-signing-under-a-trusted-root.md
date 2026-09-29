# ADR-0011. Sign with a key under a trusted root, and log to Rekor anyway

**Status:** accepted, superseding the keyless default in
[`09-attestations.md`](../09-attestations.md) §3. **Partly superseded** by
[ADR-0014](0014-git-evidence-store-without-rekor.md), accepted 2026-09-27, which removed Rekor and
every other Sigstore dependency. Superseded: the Rekor half — the third sentence of the Decision,
"and log to Rekor anyway" in the title, "Combined with a log timestamp" in item 2 of "Why a
certificate rather than a pinned public key", "Why Rekor is still required", the Rekor arm of
"Shape", the `verify` and `Attestation` rows of "What has to change in the code", verification steps
2 and 3, "and by the log" in the costs, and "Testing, and what staging already told us". Amended
until a root exists: "Verifiers pin the root, not the key", the `verify-attestation` row, and
"`LocalKey` … is not a deployment mode for anything published" — records are published under a
single pinned ed25519 key (ADR-0014 Decision 8). The keyed-signing half stands. Each superseded or
amended part below carries a short note; the text is kept as the record of what was decided.

## Decision

Sign attestations with a **key we hold, carrying an X.509 certificate that chains to a root we
publish**. Verifiers pin the root, not the key. Publish every signature to a **Rekor transparency
log**, and treat the log's signed timestamp as part of what makes the signature checkable rather
than as an optional extra.

> **Superseded, and amended, by ADR-0014.** Nothing is published to Rekor: published records go to
> an evidence repository with an append-only log we sign (`docs/19-distribution-and-lookup.md`).
> Until a root exists, verifiers pin the attestation key, not a root.

Sigstore keyless — an ephemeral key, an OIDC identity, a ten-minute Fulcio certificate — is **not**
the default and is not planned.

## Why not keyless, when the rest of the ecosystem went that way

Keyless solves one problem extremely well: there is no key to steal, because the key exists for the
length of one signing operation. Giving that up is a real cost and §"What this costs" below does not
soften it.

Four things make it the wrong fit here regardless.

**The identity in a Fulcio certificate cannot say the thing we need to say.** It is an email address
or a CI workflow reference. The claim a Trigon attestation makes is *"the attestor, at this version,
re-derived this equivalence from these bytes"* — and `michael@example.com was present` is not that.
Worse, it puts a **person's name on a public accusation about somebody else's package**, which is
what a published divergence is ([`09`](../09-attestations.md) §5). A certificate we issue can carry
the attestor's identity, its version and its environment in extensions, because we decide what goes
in it.

**A sweep signs thousands of statements and a Fulcio certificate lives ten minutes.** The interactive
flow is a browser popup per batch, which is absurd at that rate; the ambient flow ties the deployment
to a CI provider or a cloud's workload identity. An attestor that runs on a laptop, in a private
fleet, or air-gapped can do neither, and "runs anywhere" is a stated goal
([`01`](../01-architecture.md)).

**Keyless makes verification depend on Sigstore's trust root and TUF distribution**, on top of ours.
A sceptic checking a Trigon claim should have to trust as few parties as possible; adding Fulcio's
root and Sigstore's TUF repo to the set is the wrong direction for a project whose flagship feature
is *"here is a binary that reproduces our verdict without trusting us"*.

**Rekor is public and permanent.** For a public instance that is the point. For somebody running
Trigon against internal packages it leaks every package name they verify, and keyless has no mode
that avoids it because the certificate is only meaningful alongside the log entry.

## Why a certificate rather than a pinned public key

A bare pinned ed25519 key already gives authenticity, and that is what `LocalKey` and
`--public-key` do today. The certificate buys four things, and the first is the one that matters:

1. **Rotation without redistributing trust.** Verifiers pin the root. The signing key can rotate on
   any schedule without every consumer updating a pin — which, at the scale this is meant to reach,
   is the difference between a rotation and an outage.
2. **A validity window.** A signature is good only if it was made while the certificate was valid.
   Combined with a log timestamp this bounds the damage from a compromise to the window, where a
   bare long-lived key's compromise is retroactively unbounded.
   *(Superseded by ADR-0014: there is no Rekor timestamp. A window can be checked only against a
   witness cosignature's time or an RFC 3161 token, or replaced by key epochs sealed in the log;
   docs/19 D6 chooses.)*
3. **Revocation.** Short leaves make it mostly unnecessary, and CRL/OCSP exist for when it is not.
4. **Identity.** The attestor instance, the `trigon` version and the environment go in the
   certificate rather than being asserted inside the payload that the same key signed.

## Why Rekor is still required, and is required *more*

> **Superseded by ADR-0014.** Rekor is gone. The SET check this section argues for was never live
> (`within_validity` was called only from tests), so removing it lost a designed guarantee, not an
> enforced one. What bounds a stolen key now is docs/19 D6 and phase 7a.

This is the part most likely to be read as optional and is not.

With an ephemeral key, a compromise is bounded by construction. With a key we hold, **a transparency
log is the only thing that bounds it.** Rekor returns a **Signed Entry Timestamp**: Rekor's own
signature over "this entry existed at time T". Verification then checks that T falls inside the
leaf's validity window — so an attacker who steals the key today cannot forge a statement dated last
year, because there is no log entry for it and the log is append-only and publicly auditable.

Without the log, a stolen key rewrites history. With it, a stolen key can only sign things from the
moment of theft onwards, and every one of them is publicly visible.

Rekor accepts an entry signed by any key or certificate; it does not require Fulcio. We use the
infrastructure and not the CA.

## Shape

```
  offline root  ──issues──▶  intermediate (KMS/HSM)  ──issues──▶  leaf (short-lived)
        │                                                              │
   published,                                                     signs the DSSE PAE
   pinned in the                                                        │
   verifier binary                                            ┌─────────┴─────────┐
        │                                                     ▼                   ▼
        └────────────────── verification ◀──── chain + validity          Rekor entry → SET
```

> **Superseded by ADR-0014:** the Rekor arm on the right. A statement is published inside a record
> in the evidence repository, and its leaf in our log is what dates it.

- **Root**: offline, long-lived, published by digest and compiled into the verifier. Its digest is
  named in every attestation, so a statement says which root it expects rather than leaving a
  verifier to guess.
- **Intermediate**: in a KMS or an HSM. This is the crown jewel and the thing keyless did not have.
- **Leaf**: short-lived, issued per attestor instance or per sweep. Short enough that revocation is
  rarely the mechanism that saves us.
- **`LocalKey` stays** for development and air-gapped use, and produces a statement that says it is
  unchained. It is not a deployment mode for anything published.
  *(Amended by ADR-0014: until a root exists, records are published under a single pinned ed25519
  key, rotated by a key-change leaf signed by the old key and the new.)*

## What has to change in the code

Each is small and none is optional.

| | Today | Needs |
|---|---|---|
| `dsse::Signature` | `sig`, `keyid` | a certificate chain, PEM, leaf first |
| `Signer::sign` | returns `Signature` | must be able to return the chain it signed under |
| `verify` | one raw ed25519 key from `--public-key` | chain-to-root, validity at the log time, then the signature |
| Attestation | no log reference | the Rekor entry's log index, UUID and SET |
| `verify-attestation` | `--public-key <hex>` | `--root <pem>` defaulting to the compiled-in root |

> **Superseded by ADR-0014:** the `verify` row (no log time to check a window against) and the
> `Attestation` row (no Rekor entry; a published record is bound to its leaf in our log instead).
> Amended until a root exists: the `verify-attestation` row, which keeps `--public-key`.

`Signature` gaining a field is a wire-format change and the envelope is already versioned by
`payloadType`, so old bundles keep verifying against a pinned key and new ones carry a chain.

## Verification order, and why it is this order

1. **Chain the leaf to the pinned root**, collecting the validity window. A signature from a
   certificate that does not chain is not worth the cost of verifying.
2. **Check the Rekor inclusion proof and its SET.** This yields a time.
3. **Check that time falls inside the leaf's window.** This is the step that makes a long-lived key
   safe, and skipping it silently reduces the design to a pinned key with extra ceremony.
4. **Verify the DSSE signature** over the PAE.
5. **`--rerun-comparison`**, unchanged: re-derive the equivalence claim from the artifact bytes.

> **Superseded by ADR-0014:** steps 2 and 3. There is no Rekor entry; a published record's
> inclusion in our log is checked instead (docs/19 §6), and a time check waits on docs/19 D6.

Step 5 is what an attestation from a *rebuilder* is worth anything for, and it is independent of all
of the above — a verifier who distrusts our signing entirely can still falsify the claim.

## What this costs, stated plainly

- **Key custody becomes the crown jewel.** Keyless had nothing to steal; we now do. Mitigated by the
  intermediate living in a KMS, by short leaves, and by the log — not eliminated.
  *(Superseded by ADR-0014: "and by the log". No external log bounds a compromise now.)*
- **We run a CA.** Root ceremony, rotation, revocation, and publishing the root somewhere durable.
  That is operational work keyless does not have.
- **Verifiers need our root.** Pinned in the verifier binary is the honest answer, and it means the
  verifier binary is itself a trust distribution mechanism.

## Testing, and what staging already told us

> **Superseded by ADR-0014.** The client, the fixtures and the tests this section describes were
> removed. It stays as the record of what was measured; `16-findings.md` §3.92 has why Rekor went.

Against **Rekor staging** (`https://rekor.sigstage.dev`) before anything touches production, because
a transparency log is append-only: a malformed entry published to `rekor.sigstore.dev` is there
permanently. Staging exists precisely so that the first hundred attempts are not.

**The central question is answered: Rekor accepted an ed25519 key under a self-issued certificate.**
A DSSE envelope over a real `equivalence/v1` statement, signed with a throwaway ed25519 key whose
certificate chains to nothing Sigstore has ever heard of, was logged at index 56040866. Fulcio is
not a prerequisite, which is what makes "their log, our CA" a position rather than a hope.

Four details a future implementer needs, each measured rather than read:

- **`intoto` v0.0.1, not v0.0.2.** v0.0.2 takes the envelope as an *object* and rejected ours with
  `could not verify envelope: unable to base64 decode payload`. v0.0.1 takes the envelope as a
  **serialized JSON string** under `spec.content.envelope`, with the certificate as
  `spec.publicKey` — base64 of the PEM — as a sibling of `content` rather than inside the
  signature. The two versions disagree about shape, not about content.
- **The signature is base64 of the raw 64 bytes**, once. Base64-ing the already-base64 signature is
  the mistake that produces the v0.0.2 error above and looks like a payload problem.
- **The response carries everything verification needs**: `logIndex`, `integratedTime`, a
  `signedEntryTimestamp`, and an `inclusionProof` with the audit path, the root hash, the tree size
  and a **signed checkpoint**. The log's own public key is at `/api/v1/log/publicKey`, which is what
  verifies the SET — and verifying it is the step ADR-0011 hinges on, because it is what bounds a
  key compromise in time.
- **Resubmitting an identical entry returns `409` naming the existing UUID** rather than creating a
  second one. The log is content-addressed, so publication is idempotent and a retry after a
  timeout is safe — which matters for a fleet signing thousands of statements over a flaky link.

What staging has **not** yet told us: whether the SET verifies against the published log key in our
own code, and how a leaf issued by a real intermediate behaves. Both are implementation rather than
design questions, and both are cheap now that the shape is known.
