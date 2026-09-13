# Trigon

**Semantic rebuild verification for open-source packages.**

Trigon takes a published package artifact, finds the source it claims to come from, rebuilds it in a
controlled environment, and decides whether the rebuild and the published artifact are the same
thing. It signs an attestation either way.

It supports npm, PyPI, crates.io, RubyGems, NuGet, and arbitrary GitHub projects behind a single
extension seam. It runs as one binary on a laptop or as a fleet on any cloud. It uses LLMs hard for
the parts that are a search problem, and not at all for the parts that are a correctness problem.

---

## The thesis

Rebuild verification is a search problem wrapped in an equivalence problem. Finding the source,
guessing the build, and repairing a failure are search. Deciding whether two artifacts are the same
thing is equivalence. Models handle search well. They have no place in the equivalence.

Everything in this design follows from that split. See [`00-overview.md`](00-overview.md).

---

## Document set

| Doc | Read it for |
|---|---|
| [`using-trigon.md`](using-trigon.md) | **Start here to use it.** Install, verify, rebuild, read a verdict, and what a verdict does not say |
| [`00-overview.md`](00-overview.md) | The problem, what the prior art got right and wrong, the thesis, goals and non-goals, glossary |
| [`01-architecture.md`](01-architecture.md) | Pipeline, crate graph, dependency policy and its CI enforcement, the trait catalogue |
| [`02-domain-model.md`](02-domain-model.md) | The types: `Target`, `Verdict`, `Match`, `Comparison`, `Run`, `Evidence` |
| [`03-ecosystems.md`](03-ecosystems.md) | One chapter per ecosystem: resolution, source discovery, build, nondeterminism, expected rates |
| [`04-strategies.md`](04-strategies.md) | The strategy schema, the flow DSL, template rules, versioning, the definitions repo |
| [`05-archive-and-normalization.md`](05-archive-and-normalization.md) | The mutable archive model, the stabilizer catalogue, the comparison outcomes |
| [`06-ci-awareness.md`](06-ci-awareness.md) | Reading GitHub Actions, action allowlists, ingesting trusted-publishing provenance |
| [`07-ai.md`](07-ai.md) | Provider abstraction, the three AI roles, caching keys, the repair flywheel, evaluation |
| [`08-execution.md`](08-execution.md) | Sandboxing, image policy, egress tiers, dependency-state pinning, observability tiers |
| [`09-attestations.md`](09-attestations.md) | Predicate schemas with example JSON, signing, verification, storage, divergence publication |
| [`10-scale.md`](10-scale.md) | Sizing and cost arithmetic, the queue, mirrors and caches, scheduling, DB schema |
| [`11-interfaces.md`](11-interfaces.md) | CLI, API, and the web UI views, with the personas they serve |
| [`12-security.md`](12-security.md) | The threat model, centred on the attack that shapes the design |
| [`13-roadmap.md`](13-roadmap.md) | M0 to M5 with exit criteria |
| [`14-worked-examples.md`](14-worked-examples.md) | Four targets traced end to end, including the ones that come out messy |
| [`15-corpora.md`](15-corpora.md) | The five test corpora, the manifest format, and how to fetch them without getting blocked |
| [`16-findings.md`](16-findings.md) | **What building it changed.** Corrections to these documents, the measured rates, and what is still open |
| [`17-backlog.md`](17-backlog.md) | Agreed work not yet done, each with what "done" means |
| [`18-management-ui.md`](18-management-ui.md) | The plan for `trigon watch`: monitoring a sweep from outside the process running it |
| [`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) | Where a verdict is published, and how an end user looks one up — design only |
| [`threat-model.md`](threat-model.md) | The contract with a consumer of a verdict: what is assumed, guaranteed, disclaimed, and out of scope |
| [`threat-model.yaml`](threat-model.yaml) | The same, as a machine-readable index for triage. Generated from the prose by `scripts/threat-model-sidecar.py` |
| [`adr/`](adr/) | Short records for the load-bearing decisions |

## Suggested reading order

- **Evaluating the design?** `00`, `01`, `05`, `12`.
- **Implementing?** `13` for what to build first, then `05` for the hard part, then `15` for the corpus it needs, then `02` and `04`.
- **Operating it?** `10`, `08`, `11`.
- **Consuming its output?** `09`, then run `trigon verify-attestation --rerun-comparison`.
  `scripts/cross-machine-verify.sh` runs the whole thing end to end — it builds the verifier from a
  fresh clone, hands it a bundle and two files with the network taken away, and requires three
  different lies to be caught for three different reasons.
- **Sceptical?** `14`, where two of the four examples come out with caveats, and `16`, which is the
  list of things these documents got wrong.

## Status

**These documents were written before any code, and describe the system as intended rather than as
built.** Where the two disagree, [`16-findings.md`](16-findings.md) records which is right and why;
individual documents carry a note where a decision has been revised. Keeping the record separate is
deliberate — amending each document in place would erase which beliefs were wrong and how they were
found out, and that history is most of what a later reader needs.

M0, M1 and M2 are complete, and M3 has begun. The top-level
[`README`](../README.md) carries the current rates.

Every claim in these documents about the prior art was checked against the source of
[google/oss-rebuild](https://github.com/google/oss-rebuild) and
[microsoft/OSSGadget](https://github.com/microsoft/OSSGadget), and every claim about ecosystem
reproducibility rates is cited in [`03-ecosystems.md`](03-ecosystems.md).
