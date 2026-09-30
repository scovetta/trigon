# ADR-0014. Publish evidence to a public git repository with a log we sign, and drop Rekor

**Status:** accepted, 2026-09-27. It supersedes the transparency-log half of
[ADR-0011](0011-keyed-signing-under-a-trusted-root.md): the third sentence of its Decision ("Publish
every signature to a Rekor transparency log …"), "and log to Rekor anyway" in its title, "Combined
with a log timestamp" in item 2 of "Why a certificate rather than a pinned public key", the Rekor
arm of "Shape", the `verify` and `Attestation` rows of "What has to change in the code", "Why Rekor
is still required", verification steps 2 and 3, "and by the log" in its costs, and "Testing, and
what staging already told us". Until a root exists it amends ADR-0011's "Verifiers pin the root, not
the key", its `verify-attestation` row, and its statement that `LocalKey` "is not a deployment mode
for anything published" (Decision 8). It amends [ADR-0010](0010-publish-divergences.md): publishing
is an explicit `trigon publish` rather than automatic, and this names where and when a result is
published and how it is corrected; it corrects safeguard 2 on disagreeing attempts, and narrows
safeguard 1 to verdicts, so that a void is publishable on one attempt (Decision 6); and safeguard 4
becomes whatever docs/19 D7 decides, with divergences refused until then. The rest of ADR-0011's
keyed-signing half stands. Amended on 2026-09-30: the Sigstore bridge that "Interoperability", in
"What this costs", leaves to be built if npm or PyPI ever take third-party attestations in
Sigstore's shape is dropped, because it buys nothing. No part of Sigstore is planned (docs/19 §9).
Amended on the same day: Decision 10's rule that each docs/19 §11 decision is a setting holds for
the decisions still open, and D9 to D11, decided then, have none (Decision 10 carries the note).

The design this records, and the build plan, are in
[`19-distribution-and-lookup.md`](../19-distribution-and-lookup.md). Accepting this ADR was phase 0b
of that plan, and came before anything was removed.

## Decision

1. **Remove Rekor and every other Sigstore dependency.** No entry type, client, fixture, flag, or
   verification step for a transparency log we do not run.
2. **Publish evidence to one public git repository**, `github.com/<owner>/trigon-evidence`. A record
   is one JSON file per published result — a verdict, a void, or a withdrawal — named by its own
   sha256, holding the signed statements and naming by digest the evidence a third party needs to
   re-derive the comparison behind it without asking us. That evidence is content-addressed files in
   the same repository. Large artifacts, the rebuilt artifact if it is published at all, are release
   assets of the same repository, named by digest, and never in git.
3. **Keep an append-only evidence log of our own, in the same repository**, in C2SP tlog-tiles and
   tlog-checkpoint form from its first leaf. Every published record appends one small leaf: the
   subject's digests, the canonical purl and its canonicalisation version, the predicate type and
   outcome, the stabilizer-set digest, the signing key's id, the record's digest, and any record it
   supersedes with the reason. Every leaf carries the time it was logged, and a heartbeat leaf is
   appended in any week with nothing else; the checkpoint carries no extension lines. The other leaf
   kinds — key-change, release, log-end and log-continuation — are listed in docs/19 §2.3. The
   leaves are committed to by an RFC 6962 Merkle tree whose root is signed as a checkpoint, with a
   log key separate from the attestation key.
4. **A publication is one commit, pushed without force.** The record, its evidence, its leaf, the
   new tiles, the new checkpoint and the lookup index land together or not at all, and a rejected
   push means another writer won. A ruleset with an empty bypass list forbids force-pushes and
   deletion of the default branch.
5. **Consumers clone, and query their own copies.** A consumer can sync several evidence
   repositories — ours, mirrors of ours, and other operators' — each verified only against the keys
   pinned for it, and answers are reported per repository, never merged; mirrors of one log are
   checked against each other for a split view. The default client keeps a shallow, partial clone in
   the user's cache, verifies the whole log on every sync, finds records from the verified leaves,
   and answers every question locally, with no per-package request. A source whose newest leaf is
   too old answers unknown. A lookup of individual files over HTTPS exists as a labelled,
   non-private exception, and it proves each record's inclusion from the tiles. The lookup index is
   files under paths derived from each key — sha256, sha512 and sha1 in full, and hashed purls — for
   that exception and for tools that do not read the log; it is derived data, and the log is the
   authority on what exists.
6. **Publishing is its own step, behind ADR-0010's gate.** `trigon attest` signs locally and opens
   no socket. `trigon publish` reads what attest signed and asks `publication::decide`, with the
   kill-switch read from a file in the repository. It publishes a run the gate calls `Published` in
   full, a run it calls `Void` only as a void record and never as a verdict, and a `Withheld` run
   not at all. Two attempts that disagree are withheld, not void, as `decide` and
   [`12-security.md`](../12-security.md) invariant 12 already say; this corrects the last clause of
   ADR-0010 safeguard 2. A void needs no second attempt, because it makes no claim a second attempt
   could confirm; this narrows safeguard 1 to verdicts. `publish` is the only writer, and it builds
   only on a remote log it has verified.
7. **Correct by superseding, never by deleting.** A superseding record names the record it replaces
   and why, signed, and is logged like any other; "we were wrong" is a withdrawal record with no
   verdict. A divergence is published in full, dispute pointer and falsifying command included, and
   its log leaf is permanent.
8. **Publish under a pinned ed25519 key until a root exists.** Until then this amends ADR-0011's
   "Verifiers pin the root, not the key", its `verify-attestation` row, and its statement that
   `LocalKey` "is not a deployment mode for anything published". Records are published under a
   single pinned attestation key, named by key id in every record and leaf, until something that can
   rotate it exists (docs/19 D6). Rotating that key before then is a key-change leaf signed by both
   the old key and the new, which clients follow.
9. **One store implementation, behind a seam.** Per [ADR-0008](0008-one-implementation-per-seam.md),
   the store is a narrow interface — write these files atomically with the new checkpoint; read a
   file by path — with git as its only implementation. The layout refers to nothing git-specific, so
   a registry or a bucket could be a second implementation later without changing a signed byte.
10. **Where a repository is, is configuration.** The repository `publish` writes to and every
    repository a consumer syncs are named in a configuration file or in the environment, as any
    location `git` accepts: an HTTPS, SSH, `git://` or `file://` URL, or a local path. Credentials
    are `git`'s own. Every decision in docs/19 §11 that changes behaviour is a setting with a
    conservative default, so the code does not wait on the decision.
    *(Amended on 2026-09-30: this holds for the decisions still open. D9 to D11, decided that day
    (docs/19 §11.1), have no setting: each is built as decided, and for D9 `publish` refuses a
    verdict that names no stabilizer-set module.)*

## Why Rekor goes

Everything here was measured against the running services or read in their source, between
2026-09-17 and 2026-09-23, and is recorded in [`16-findings.md`](../16-findings.md) §3.92.

- **It could not hold what we wanted it to hold.** An `intoto` v0.0.1 entry commits the envelope
  hash, the payload hash and the verification key or certificate, and no field of the statement. The
  previous docs/19 described log entries "carrying" the outcome and the set digest. No entry type
  usable for an in-toto statement commits application-chosen fields, so that could never have been
  built.
- **What it did serve, it served in a way that broke ADR-0010.** Rekor v1 keeps the decoded payload
  in an uncommitted attestation store when it is 100 KiB or less, and serves it, searchable by the
  artifact's digest. Staging entry 56042318 returns the whole of a Trigon `equivalence/v1`. A
  divergence logged the same way would sit in Sigstore's storage, where we cannot supersede it.
  `attest --rekor` did exactly that, because it never consulted `publication::decide`.
- **The version we built on is in maintenance, and its successor cannot take our statements.** Rekor
  v2 went GA on 2025-10-10. It dropped `intoto`, dropped `dsse` in rekor-tiles v2.3.0 (2026-06-10),
  keeps no attestation storage, issues no Signed Entry Timestamp (time comes from an RFC 3161 TSA),
  has no search in the log itself, and accepts only `hashedrekord`, which rejects pure Ed25519.
  Trigon signs with pure Ed25519. The public instance keeps Rekor v1 as its default log "for the
  foreseeable future" (Sigstore, 2026-06-28), and a freeze will be announced a year ahead. Staying
  meant a signing-algorithm change, a TSA, and a migration, all to keep a log that could not serve
  our documents.
- **The time bound it was kept for was never live.** ADR-0011 required Rekor because its SET bounds
  a key compromise in time. The check that uses it, `within_validity`, is called only from tests,
  and the leaf certificate chain it would check against (B21 steps 4 and 5) was never built.
  Removing Rekor therefore loses a designed guarantee, not an enforced one.

## Why git, and not an OCI registry

An OCI registry on GHCR was designed in full first, and set aside for these reasons:

- **Atomicity.** A registry and a history mirror cannot be written in one operation. A git commit
  holds everything, and a non-forced push is a compare-and-swap, so a partial publication is never
  visible. It does not stop the log key signing a checkpoint whose push then loses the race; that
  checkpoint is destroyed on the losing host, and a single publishing host under a lock makes the
  race impossible rather than rare.
- **Lookup.** GHCR has no OCI 1.1 referrers API (404, measured), so lookup would mean tags kept by
  read-modify-write, which lose entries under concurrent writers (miracum/.github#212), and
  truncated sha512 keys. In git, every leaf of the log carries its keys whole, and the index paths
  do too.
- **Consumption.** The private way to answer a lockfile is to have the whole log locally. That is
  what a clone is; on a registry it had to be rebuilt as signed prefix shards with their own binding
  and completeness problems.
- **Cost of the client.** A registry needs an HTTP client for its protocol — `oci-client`, with a
  second HTTP stack and about 25 new crates, or one of our own. Trigon already runs `git`.
- **Operational friction.** A GHCR package starts private and is made public by hand, irreversibly,
  and a push from outside GitHub Actions needs a classic token. A repository needs neither.

What the registry did better — content-addressed blobs at any size, CDN reads — matters here only
for large artifacts, and those go to release assets.

## What replaces the log, and what does not

| What Rekor gave, or was meant to give | After this ADR |
|---|---|
| A dated, signed, third-party record that an entry existed | A time in every leaf, committed by the tree, and a weekly heartbeat. **Ours, not third-party,** until it is witnessed: each witness cosignature then carries the witness's own time |
| Append-only history: we cannot quietly change our minds | Merkle log in the repository, recomputed in full by every client on every sync. A rewrite changes every later root, and anyone holding an older checkpoint can prove it. **Detection after the fact, not prevention** |
| A bound on a stolen key (designed, never enforced) | Lost for now. Restored by key epochs sealed in the log, or by a certificate chain checked against witness or TSA time (docs/19 D6), as a later phase |
| Lookup by artifact digest | Better: a local clone answers by sha256, sha512, sha1 or purl, privately, from the verified log. Rekor's index was best-effort, unauthenticated, and removed from the v2 log (Sigstore plans a separate search service) |
| The full statement retrievable from the log | Better: the whole record, evidence included, in the same repository, bound to the log by digest. A repository admin can still rewrite history, and the log then shows what was removed |
| Sigstore's monitoring ecosystem | Partly replaced: every client recomputes the whole log, so every client is a monitor, and a client that syncs a source's mirrors compares their checkpoints. Nobody compares their checkpoints with other users' unless we make that easy |

**Witnessing is the step that makes the log someone else's word as well as ours.** C2SP tlog-witness
cosigners, such as the witness-network.org participants, cosign only a checkpoint consistent with
every one they have seen before. That restores a third-party time and prevents a split view —
GitHub, or we, serving different clones different histories. It needs no server of ours, and the log
needs no change to add it, provided the checkpoint is fixed now in the form witnesses take: a C2SP
signed note under an Ed25519 key (vkey type 0x01), which the witness network requires, whose name is
a permanent, schema-less origin line, which it recommends, with no extension lines, about which
cosignatures say nothing, and a stated checkpoint rate. docs/19 §2.3 fixes all of it. Joining also
needs approval by the witness network's maintainers, whose lists are testing and staging only today,
and a log-key rotation needs a new application; that is why it is the plan's decision-gated phase 7b
rather than day one. Until then the honest description is **a signed, append-only log that we
operate, copied by every consumer so that a rewrite is detectable.**

## Alternatives considered

- **Keep Rekor v1.** Rejected. It leaks divergences into storage we do not control, its successor
  cannot accept our signatures, and the guarantee it was kept for was never enforced.
- **Move to Rekor v2 (`hashedrekord` over the DSSE PAE, plus an RFC 3161 TSA).** Rejected. It means
  a signing-algorithm change (ECDSA P-256 or Ed25519ph) before the corpus is signed, adds a TSA to
  the trust set, and still leaves lookup, the documents and correction to us. It is Sigstore in the
  trust set, which ADR-0011 argued to keep minimal, for a timestamp.
- **An OCI registry (GHCR) as the store.** Designed and set aside; see "Why git".
- **Both git and a registry, chosen by configuration.** Rejected for now, per ADR-0008. Every reader
  would need both paths, the test matrix doubles, and no user needs a registry today. The store seam
  (Decision 9) keeps the option.
- **Per-package lookups over HTTPS as the default.** Rejected. It tells GitHub every dependency of
  everyone who checks, meets unauthenticated rate limits, and cannot see a supersession the index
  does not mention without fetching the log anyway. It survives as a labelled exception.
- **A witnessed log from day one.** Deferred, not rejected. It is the same log with witnesses added,
  and whether they accept us is outside our control.
- **Do nothing: signatures in a repository and no log.** Rejected. Nothing would record what we
  published when in a form a client can check, and a force-push would rewrite history for anyone
  without an older clone. That is the "public bucket" design [`00-overview.md`](../00-overview.md)
  §2.1 criticises OSS Rebuild for.

## What this costs, stated plainly

- **We operate a log, and its key and state become crown jewels.** A lost log is permanent, and a
  forked one is an equivocation we would have to explain. The log key is separate from the
  attestation key: the checkpoint is signed by a socketless step that reads the new tree from disk
  and signs only a tree extending a checkpoint it has verified, and it is pushed by a separate
  networked step. Whether the log key is also held apart, on another machine, is docs/19 D5. A
  stolen log key lets its holder sign, for any client, a tree that extends the newest checkpoint
  that client holds but differs from the real log after it — a fork the client cannot detect alone,
  which can omit a withdrawal — though it cannot forge a record. A stolen attestation key alone
  produces records no client accepts, because clients require inclusion. With both keys, an attacker
  can publish anything clients accept. Witnesses make that visible and prevent a split view, and key
  epochs or rotation bound it; neither stops it. A log-key rotation starts a new origin: the old log
  ends in a leaf naming its successor, and the successor's first leaf is the old log's final
  checkpoint, cosigned by the new key.
- **Independence is weaker than Rekor's until witnesses cosign.** A consumer who does not trust us
  detects a rewrite only by holding an older checkpoint or clone, and a split view only by comparing
  mirrors or comparing with someone else.
- **Nothing dates a key theft.** That was already true in practice, because the SET check was never
  live. The remedy is key epochs, or a certificate chain checked against third-party time (docs/19
  D6 and phase 7a).
- **Freshness needs a scheduled job.** Leaf times are how a client tells a frozen host from a quiet
  log, so a heartbeat leaf has to be logged in any week with no publication, by something that holds
  the log key (docs/19 D5). Without it, every consumer's answers turn unknown after two weeks of
  silence.
- **Size.** The consumed part of the repository grows by roughly 10 to 15 KB per published version
  before compression, and GitHub asks for a repository under about 1 GB and strongly under 5 GB. The
  repository will have to be split eventually, and the split rule has to be written down before it
  is needed (docs/19 D2).
- **GitHub as the host.** A ruleset is a setting its admin can change. Rate limits and
  acceptable-use terms apply to anyone who leans on it hard, unauthenticated clones and fetches
  included, and GitHub advises at most 6 pushes a minute to one repository. A repository that grows
  by thousands of files a day is an unusual repository. The integrity of what it serves does not
  depend on GitHub; its availability does.
- **Interoperability.** Tools that expect a Sigstore bundle, or an OCI referrer, cannot check our
  records without our verifier. If npm or PyPI ever accept third-party attestations in Sigstore's
  shape, that bridge has to be built then.
  *(Amended on 2026-09-30: the bridge is dropped and will not be built, then or later, because it
  buys nothing.)*
- **Safeguard 4 has no channel yet.** ADR-0010's maintainer notification needs a feed maintainers
  subscribe to — which the repository makes cheap — or an email-sending account, which is
  infrastructure. Until docs/19 D7 decides, divergences are not published.

## Consequences

- `trigon-attest` loses `transparency.rs` and its `p256` dependency, and gains pure verification of
  records, leaves, Merkle trees, inclusion and consistency proofs, and checkpoints over a directory.
  It still reaches no network client, which `xtask policy` enforces, and the network-free verifier
  can check a clone completely.
- No registry client and no new HTTP stack: publishing and syncing shell out to `git`, as fetching
  sources already does, in the build half. Release assets and `--remote` use the HTTP client the
  workspace already links.
- `RunRecord.transparency` goes. Old run files still read, because `RunRecord` does not use
  `deny_unknown_fields`, and a run record gains `published` (docs/19 §10 phase 5).
- The statements gain what docs/19 §4.2 requires a published record to carry, including the
  canonical purl and signed supersession, and two new predicates exist, `void/v1` and
  `withdrawal/v1`. That is a wire change, made **before the first publication** so the corpus never
  needs re-signing. Threat-model property P6 is reworded: `trigon attest` never signs a verdict for
  a void run, and signs only `void/v1` for it.
- ADR-0011's root and certificate chain (B21 steps 4 and 5) remain one candidate for rotating the
  signing key. The log supplies no third-party time of its own, so a validity window can be checked
  only against a witness cosignature time or an RFC 3161 token. The alternative is key epochs sealed
  in the log, which need no clock. docs/19 D6 chooses between them, and until it does, no
  statement's validity depends on a time.
