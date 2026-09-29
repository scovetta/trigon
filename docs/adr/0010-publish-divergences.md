# ADR-0010. Publish divergences automatically, with technical safeguards

**Status:** accepted, amended by [ADR-0014](0014-git-evidence-store-without-rekor.md) on 2026-09-27.
The amendments come first, below, because they change what the Decision and the safeguards say.

## Amendments

ADR-0014 decides where and when a result is published and how it is corrected: a public git
repository holding signed records and an append-only log we sign, designed in
[`19-distribution-and-lookup.md`](../19-distribution-and-lookup.md). Against the text below, that
changes six things.

1. **Publishing is an explicit `trigon publish`, not automatic.** `trigon attest` signs locally and
   publishes nothing. `trigon publish` is the only thing that writes to the evidence repository,
   and it asks `publication::decide` for each run at the moment of publication: a run the gate calls
   `Published` is published in full, a `Void` run only as a void record, and a `Withheld` run not
   at all (docs/19 §3). "All results publish automatically" in the Decision now reads "all results
   the gate allows are published by `trigon publish`".
2. **Correction is by supersession, never by deletion.** A published record is immutable, and its
   leaf in the log is permanent. A correction is a new record that names the one it replaces, with a
   reason from a closed list (`withdrawn`, `set_changed`, `attempts_disagree_later`,
   `pipeline_bug`), signed; "we were wrong" is a `withdrawal/v1` record with no verdict. The
   superseded record stays visible, marked superseded (docs/19 §3).
3. **Safeguard 2: attempts that disagree are withheld, not void.** Its last clause, "or the two
   attempts disagreed", is struck. Disagreeing attempts are withheld from publication, as
   `publication::decide` and [`12-security.md`](../12-security.md) invariant 12 already say: a void
   says "we looked, and could not tell, for this reason", and a disagreement is a reason to look
   again, not a result.
4. **Safeguard 1 is narrowed to verdicts.** Two agreeing attempts are required before a match or a
   divergence is published. A void is publishable on one attempt, because it makes no claim a second
   attempt could confirm.
5. **Safeguard 4 is whatever docs/19 D7 decides**: a divergence feed in the evidence repository, or
   email. Until D7 is decided there is no notification channel, so `trigon publish` refuses every
   divergence (the setting `divergences`, default `refuse`).
6. **Same-host confirmation is not accepted.** Safeguard 1's "on different workers" stands. docs/19
   D8 proposes accepting two attempts on one host, with an empty build cache, images re-pulled by
   digest and a minimum interval between them; it has not been decided. It is a setting,
   `same_host_confirmation`, default `false`, so the code does not wait on the decision, and this
   amendment will say so if D8 accepts it. D8 now carries a second setting beside it,
   `same_host_local_images`, also default `false`: where both are set, a confirmation on a local
   base image pinned by its full content id, which no registry digest names and so nothing can
   pull again, counts as cold ([findings](../16-findings.md) §3.105). Accepting D8 accepts both
   settings, and what the second gives up (threat model D38).

## Decision

All results publish automatically, divergences included, subject to five technical safeguards.

## Context

A divergence makes a public claim about **someone else's package**, produced by an automated system,
about software a volunteer probably maintains. We considered three options: publish positives only
and route divergences to human review; publish after an embargo with maintainer notice; or publish
everything.

We chose to publish everything, for transparency, and because a private finding helps nobody. The
asymmetry that creates is real, and the technical safeguards compensate for it:

**A false `Reproduced` is an error. A false `Divergent` is an accusation.**

## Safeguards

1. **Two agreeing attempts** before anything publishes, divergences and matches alike, on different
   workers at different times. One attempt cannot tell a deterministic recipe from a lucky one, and
   the risk that dominates is ambient nondeterminism, whether a floating dependency range, a mutable
   tag, or a network fetch that happened to succeed, rather than malice. Attempts share a cache key
   and differ in `Attempt`, so deduplication does not collapse the second one.
2. **A run publishes as `Void` and never as a divergence** when the egress tier was `Open`, the
   artifact-hash guard tripped, any applied stabilizer was non-`Builtin`, or the two attempts
   disagreed.
3. **Every published divergence carries a machine-readable dispute pointer** and the exact
   `trigon verify-attestation --rerun-comparison` command that would falsify it. A maintainer should
   be able to disprove us in one command, and that command belongs in the document.
4. **Maintainer notification fires at publish time**, best-effort, through registry contact metadata.
5. **False-mismatch rate is an SLO with a publication kill-switch.** Cross the threshold and
   divergence publication stops until a human clears it.

## No prose in the divergence predicate

`divergence/v1` carries the **deterministic** difference signature: rule ids matched, byte ranges,
per-file digests, and which stabilizers fired. The Explainer's natural-language explanation stays in
the database and the UI, unsigned, with its model id attached.

Put an advisory annotation inside a signed document and someone reads it as a claim. "A signed
document said my package contains an unexplained binary difference" is the sentence that has to rest
on determinism rather than on a model's opinion.

## The thing that makes this defensible

`--rerun-comparison`. A maintainer never has to argue with us or trust us, because they can re-derive
the comparison from the attestation and the two artifacts, using a binary that contains no model
code. A public accusation its subject can falsify in one command is a different thing from one they
cannot.
