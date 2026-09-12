# Backlog

Work that is agreed and not yet done. Each entry says what "done" means, because a backlog whose
items cannot be finished is a list of anxieties.

Ordered by when it was raised, not by priority; the roadmap in [`13`](13-roadmap.md) says what the
current milestone is.

---

## B1. Security sweep over the whole codebase

Not the design's threat model — the *code*. Every place we run a subprocess, parse
attacker-controlled bytes, join a path, or hand a string to a shell, read with an attacker in mind.

The system executes untrusted code by design, so the interesting findings are the ones where
untrusted input reaches something that was written as though it were ours: a package's repository
URL on a `git` command line, a build log in a prompt, an archive member path joined to an output
directory, a strategy's template rendering into a shell script.

**Done when:** every finding is either fixed or written down with a reason it is acceptable, and
each one has a test that would catch the regression.

## B2. A threat model for Trigon

The implicit security contract between this project and the people who depend on its verdicts:
what it assumes, what it guarantees, what it explicitly does not, and which misuses are out of
scope. [`12`](12-security.md) is a controls document and is not this.

The interesting questions are the ones a consumer of an attestation has to answer: what does a
signed `equivalence` predicate actually claim, what would have to be true for it to be wrong, and
what is the reader expected to check themselves.

**Done when:** `docs/threat-model.md` exists as prose with a machine-readable companion, every
non-trivial claim is marked as documented / maintainer-stated / inferred, and it routes a corpus of
real findings to exactly one disposition each.

## B3. Documentation that is accurate and reads for a user

Two separate problems. **Accurate:** the docs were written before the code and the code has since
corrected them — [`16`](16-findings.md) records the corrections, but the original chapters still
say the original thing in places. A reader who starts at `04` and believes it is misled.

**User-friendly:** the `README` is the only document written for somebody who wants to *use* this,
and the seventeen design chapters are written for somebody building it. At minimum a user needs:
install, verify one package, read the verdict, understand what the verdict does not say.

**Done when:** every claim in `00`–`15` is either true of the code or marked as a design intent not
yet built, and a person who has never seen this repository can verify a package from the README
alone.

## B4. Test coverage worth the name

Coverage measured rather than asserted. The suite is large and grew by accretion; what matters is
whether the parts that would be expensive to get wrong are covered — the writers, the guard, the
provenance cap, the egress boundary, the attestation round-trip — and whether the corpora still
exercise what they claim to.

**Done when:** a coverage number exists per crate, the judgement half is at a stated bar, and every
gap that is deliberate is named as deliberate.

## B5. A bug sweep

Not a review of the last change: a sweep of the whole thing, looking for the classes this project
keeps producing — configuration that looks applied and is not, an error that reads as the package's
fault when it is ours, a silent zero where there is no data, a cache key that is not a function of
everything it depends on.

**Done when:** every confirmed bug is fixed or filed with a failing test, and the sweep's negative
result is recorded so the next one starts from here rather than from nothing.
