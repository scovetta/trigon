# 19. Publishing verdicts, and looking them up

**Status: design, not built.** Nothing in this chapter exists in the code. It is here to be argued
with before any of it is written.

---

## 1. The problem, which is not the one it looks like

Trigon produces a signed statement about somebody else's package. Every existing way to distribute
such a statement assumes the **publisher** made it:

- npm serves provenance at `/-/npm/v1/attestations/{pkg}@{ver}`, written by `npm publish
  --provenance`.
- PyPI serves PEP 740 attestations from the simple index, uploaded with the distribution.
- GitHub's attestation API is scoped to the repository that produced the artifact.

We are not the publisher and will never be able to write into any of those. **The distribution
problem for a third-party rebuilder is a different problem, and pretending otherwise is how this ends
up as a repository nobody can find.**

There are two distinct questions hiding here, and conflating them is the usual failure:

1. **Where do the bytes live?** A storage and transport question. Several good answers.
2. **How does a consumer know to ask?** A discovery question. Almost no good answers, and it is the
   one that decides whether any of this gets used.

The only query that works without a naming authority is **by artifact digest**, because the consumer
already holds the artifact. Everything else — by name, by purl, by ecosystem — needs somebody to
agree that *we* are the place to ask. So whatever gets built, the primary key is the digest of the
published artifact and the purl is a secondary index.

---

## 2. Where the bytes live

### 2.1 The candidates

**A transparency log (Rekor).** Already half-decided: `docs/09-attestations.md` names Rekor v2 and
the signer supports sigstore keyless. Its strengths are exactly the ones we need — append-only,
publicly auditable, and it needs nobody's permission. Its weakness is that it is a *transparency* log
and not a *lookup* service. Rekor's maintainers say so; the v2 tile-based design is built for
monitors that follow the whole log, not for a package manager doing a point query per dependency. It
also wants small entries, and a divergence predicate carrying a difference signature is not small.

**A git repository of attestations.** `trigon-attestations`, content-addressed, served over
`raw.githubusercontent.com`. Cheap, familiar, forkable, greppable, and it needs no infrastructure.
The objection is scale: a hundred thousand targets times several predicates times many versions is
millions of small files, which is the shape git handles worst. Sharding by digest prefix helps and
does not save it; a clone becomes hostile long before the corpus is interesting.

The framing that makes it survivable is that **the repository is a CDN, not an authority**. Every
record is independently signed, so rewriting history in the repository does not forge anything — it
can only hide. That reduces the repository's job to availability, and availability has other answers.

**An OCI registry.** The under-considered option, and probably the right one. OCI 1.1's referrers API
answers precisely our query: *given this digest, what else refers to it?* Registries are
content-addressed, CDN-backed, built for high read throughput, and free at our scale on GHCR. The
tooling exists — `cosign` and `oras` already store attestations this way, using the
`sha256-<hex>.att` tag convention for subjects that are not themselves images. The cost is that a
consumer still has to know to look at *our* namespace, which is the discovery problem again, and that
the convention is ugly.

**The registries themselves.** npm, PyPI and friends serving third-party rebuild attestations
alongside publisher provenance. This is the endgame and it is a standards conversation, not a v1
plan. `docs/10-scale.md` §2 already says we have to talk to the registries before the first real
sweep; this is what that conversation is eventually for.

### 2.2 The recommendation

**Two stores with different jobs, not one store doing both.**

- **A transparency log entry for every verdict**, carrying the subject digests, the outcome, the
  stabilizer set digest, and the digest of the full record. Small, permanent, auditable. Its job is
  to make it impossible for us to quietly change our minds.
- **An OCI registry for the full records**, addressed by subject digest through the referrers API,
  with a git repository as a mirror for people who want to grep and fork. Its job is to serve the
  bytes fast, and it may serve a *superseding* version of a record.

The log holds hashes; the store holds documents. That split is what makes the next section possible.

---

## 3. An accusation you cannot retract is a different product

This is the decision with teeth, and it is a direct consequence of the threat model
(`docs/threat-model.md`, adversary A7): **publishing a divergence is a public claim that somebody
else's package does not match its source.** `docs/09-attestations.md` §5 and ADR-0010 already treat
the false-mismatch rate as a safety property with a publication kill-switch, not merely a quality
metric.

Putting divergences in an append-only log takes the kill-switch away. Once an entry is in Rekor it is
there permanently; the most you can do is add a retraction that the original's readers will never
fetch. A tracked, non-zero false-mismatch rate plus an immutable log means we will eventually and
permanently accuse an innocent maintainer, and the correction will not reach the people who saw the
accusation.

**So the two stores get different content:**

| | transparency log | record store |
| --- | --- | --- |
| reproductions and voids | full statement | full statement |
| divergences | **the record's digest and outcome only** | the full statement, **supersedable** |

That gives both properties. We cannot secretly retract — the log proves an entry with that digest
existed at that time, and a monitor can see a divergence was claimed. And we *can* correct — the
store serves a superseding record, and a consumer following the pointer gets the current one.

A record is therefore never deleted, only superseded, and a superseded record says what replaced it
and why. "We were wrong" has to be a first-class document type, because it will be needed.

---

## 4. What a record has to carry, or it is worse than nothing

`docs/11-interfaces.md` §4 says a stale pass is worse than no data. Runtime lookup makes that acute:
a consumer asks about `left-pad@1.3.0` and gets a pass from eighteen months ago, produced by a
different Trigon under a different stabilizer set, at an egress tier that voids the strong claim. If
the client renders that as a green tick, we have built exactly the meaningless checkmark this project
exists to complain about.

Every record must carry, and every client must be able to render:

1. **The outcome as a string** — `exact`, `normalized`, `normalized_with_caveats`, `divergent` — and
   never a boolean. A client that collapses four outcomes into a tick throws away
   `normalized_with_caveats`, which is the whole point of the provenance cap.
2. **The stabilizer set id and digest.** This is the field most likely to be omitted and the most
   important one. `docs/13-roadmap.md` §16 calls the stabilized digest's dependence on our whole
   serialization stack the single biggest technical risk: when the set changes, old verdicts are not
   wrong, they are **no longer re-derivable by a current binary**. A record without the set digest
   cannot be checked by anyone, ever.
3. **When**, and **which Trigon version**.
4. **The egress tier and whether the run was `attestable`.** Today no run is attestable at full trust
   at any tier, because there is no network transcript (`docs/17-backlog.md` B7). A record that does
   not say so is overclaiming.
5. **`derivation.method`** — whether a model was involved — so a consumer can filter it out
   themselves, which `docs/09-attestations.md` §2.1 makes their job rather than ours.
6. **The falsifying command**, verbatim: the exact `trigon verify-attestation --rerun-comparison`
   invocation that would prove us wrong.

And the client must distinguish **"not checked"** from **"checked and failed"** as loudly as it
distinguishes the four outcomes. Absence rendered as a zero is this project's most reliable bug class
(`docs/16-findings.md` §1), and at ecosystem scale the absent case is the common one.

---

## 5. The lookup key, and an npm problem found by reading the code

The plan above assumes a consumer can ask "what do you know about the artifact with this digest"
without downloading anything. For a lockfile-driven check that is the whole value: `package-lock.json`
and `uv.lock` already record integrity digests, so the check costs no bandwidth at all.

It does not work today, for a reason specific to npm. From `crates/trigon-registry/src/npm.rs`:

> npm publishes sha1 in `dist.shasum` and, for newer entries, a subresource-integrity string that is
> usually sha512. **Neither is sha256.**

Our subjects carry sha256 only — `Subject::new` builds a one-entry map
(`crates/trigon-attest/src/statement.rs`). So a consumer holding an npm lockfile has a sha512 and we
are indexed by sha256, and the "free" lookup turns into a tarball download per dependency. PyPI is
fine; its JSON API publishes sha256.

**The fix is small and has to happen before anything is published, because subjects are signed.**
`Subject.digest` is already a map keyed by algorithm, exactly as in-toto intends. Populate every
digest the ecosystem publishes — sha256 always, plus sha512 and sha1 where the registry gives them —
and index the store by all of them. Retrofitting this later means re-signing the corpus.

---

## 6. The end-user command

`npm check-reproducibility left-pad` is the right shape and npm has no way to add a subcommand. What
delivers the same ergonomics with no ecosystem buy-in:

```
npx trigon-check left-pad@1.3.0        # one package
npx trigon-check                        # the lockfile in this directory
uvx trigon-check                        # the same, for Python
```

Four design points, in decreasing obviousness.

**The lockfile is the front door, not the single package.** `docs/11-interfaces.md` already calls
`trigon check ./package-lock.json` the hero view. The single-package form is its degenerate case, and
it is worth shipping because it is what people will type first, but the value is in the thousand
dependencies nobody will check one at a time.

**The client must not be Trigon.** A lookup client hashes what it has, fetches a record, checks a
signature, and prints. That is a few hundred lines with no Rust toolchain, no container runtime and
no archive parser, and it can ship as an ordinary npm or PyPI package. If checking a lockfile
requires installing the rebuilder, nobody checks a lockfile.

**It must be honest that it is trusting a signature.** There is a large difference between *"our
signed record says this reproduced"* and *"I re-derived the equivalence claim myself"*, and the
ergonomic command does the first. It must print the identity it trusted, and it must point at
`trigon verify-attestation --rerun-comparison` as the thing that does the second. A tool that blurs
the two has reinvented the problem in `docs/00-overview.md` §1: a green tick that means less than its
reader thinks.

**For npm it must say what the verdict is not.** npm packages are close to fully reproducible at the
tarball level with no source linkage at all (`docs/03-ecosystems.md` §0). A wall of green on an npm
lockfile is true and nearly worthless, so the npm client's summary line has to lead with source
attribution — *"1,204 of 1,310 reproduce; 318 of those have no verified link to a source
repository"* — or npm users will read it once and never again.

**Exit codes**, because this ends up in CI: `0` everything at or above the requested threshold, `1`
a divergence, `2` something unchecked, `3` a caveated or void result below the threshold. With
`--min exact|normalized|normalized_with_caveats` mapping onto `Match::is_at_least`, so the consumer
sets their own bar, as `docs/05-archive-and-normalization.md` §1 says they should.

---

## 7. Privacy, and the case for shipping the index

A runtime lookup per dependency tells us — and every CDN in the path — the full dependency graph of
whoever ran it. That is a real objection and it will be raised by exactly the security-conscious
users we most want.

The mitigation is pleasant: **the answer set is small enough to ship.** A hundred thousand entries of
(digest, outcome, set digest, date) is a few megabytes compressed, and a client that downloads it
weekly answers almost every query offline, at no privacy cost and no per-query latency. Only a miss
needs a network call, and a miss can use a digest-prefix range query in the style of Have I Been
Pwned, so the service never learns which artifact was asked about.

This also removes the dependency on any single service being up, which is the practical argument for
it even if nobody cared about privacy.

---

## 8. What this design deliberately does not do

- **No account, no API key, no per-user state.** Lookup is anonymous and cacheable or it will not be
  adopted.
- **No writing into a publisher's namespace**, ever, even if a registry offers it. A third party's
  verdict served under the publisher's provenance endpoint would be read as the publisher's claim.
- **No aggregate "trust score".** Four outcomes, a freshness, and a set digest. Any collapse of those
  into a number is a lie with a decimal point.
- **No automatic issue-filing against maintainers.** `docs/09-attestations.md` §5 provides for
  best-effort notification with a dispute pointer; an unattended bot opening issues against strangers'
  repositories on the strength of a rate we know to be imperfect is not that.

---

## 9. Open questions

1. **Does the transparency-log split survive contact with a monitor?** Logging only a digest for
   divergences means a log monitor sees that *something* was claimed and cannot tell what. Is that an
   acceptable transparency story, or does it read as hiding the bad news?
2. **Who signs?** Sigstore keyless binds the claim to a workflow identity, which is right for a
   public instance and useless for an operator running a private sweep. Two identity models, or one
   with a documented downgrade?
3. **What happens to the corpus when a stabilizer set changes?** Re-running a hundred thousand
   targets for a stabilizer fix is days and thousands of dollars (`docs/10-scale.md`). The
   alternative is a store holding verdicts under several set digests at once, and a client that picks.
   Neither is obviously right.
4. **Is the git-repository mirror worth its maintenance**, given the OCI store does the job and git
   handles this shape badly? The argument for it is sociological — people trust what they can fork —
   and that may be enough.
5. **Does `subject` carry the ecosystem's own digests from the first signed statement onward?** §5
   says it must. It is cheap now and expensive later, so it wants a decision before, not after.
