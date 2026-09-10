# ADR-0010. Publish divergences automatically, with technical safeguards

**Status:** accepted

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
