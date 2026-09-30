# Trigon

**Semantic rebuild verification for open-source packages.**

Trigon takes a published package artifact, finds the source it claims to come from, rebuilds it in a
controlled environment, and decides whether the rebuild and the published artifact are the same
thing. It signs an attestation either way.

It is designed for npm, PyPI, crates.io, RubyGems, NuGet, and arbitrary GitHub projects behind a
single extension seam, and runs as one binary on a laptop or as a fleet on any cloud. It makes heavy
use of LLMs for the parts that are a search problem and no use of them for the parts that are a
correctness problem.

**These documents are the design, written before the code.** The code wins where the two disagree,
and [`16-findings.md`](16-findings.md) records which. First, **npm, PyPI, crates.io and NuGet are
the ecosystems with a registry client**: Trigon refuses RubyGems and GitHub releases by name, and
[`03-ecosystems.md`](03-ecosystems.md) §7.2 counts what adding one costs. Second, several types
these documents describe were never written; we have marked each where the documents name it.

---

## The thesis

Rebuild verification is a search problem wrapped in an equivalence problem. Finding the source,
guessing the build, and repairing a failure are search; deciding whether two artifacts are the same
thing is equivalence. Models handle search well and have no place in the equivalence.

The rest of the design follows from that split; see [`00-overview.md`](00-overview.md).

---

## Document set

**New readers:** start with [`introduction.md`](introduction.md), a ten-minute read on what Trigon
is, how it works and how to use it.

| Doc | Read it for |
|---|---|
| [`introduction.md`](introduction.md) | **Start here.** What Trigon is, the five ideas it rests on, how the pieces fit, and the three things people use it for |
| [`using-trigon.md`](using-trigon.md) | **Start here to use it.** Install, verify, rebuild, read a verdict, and what a verdict does not say |
| [`00-overview.md`](00-overview.md) | The problem, what the prior art got right and wrong, the thesis, goals and non-goals, glossary |
| [`01-architecture.md`](01-architecture.md) | Pipeline, crate graph, dependency policy and its CI enforcement, the trait catalogue |
| [`02-domain-model.md`](02-domain-model.md) | The types: `Target`, `Verdict`, `Match`, `Comparison`, `Run`, `Evidence` |
| [`03-ecosystems.md`](03-ecosystems.md) | One chapter per ecosystem: resolution, source discovery, build, nondeterminism, expected rates |
| [`04-strategies.md`](04-strategies.md) | The strategy schema, the flow DSL, template rules, versioning, the definitions repo |
| [`05-archive-and-normalization.md`](05-archive-and-normalization.md) | The mutable archive model, the stabilizer design, the comparison outcomes |
| [`stabilizers.md`](stabilizers.md) | Every profile and pass as built: what each changes, its risk tier and stage, how a profile is chosen, and how the passes that fired cap a verdict |
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
| [`19-distribution-and-lookup.md`](19-distribution-and-lookup.md) | Publishing a verdict and looking it up: a public git repository holding the records and an append-only log we sign, which consumers clone and query locally, and the phased build plan. Partly built, mostly planned; ADR-0014 (accepted) |
| [`20-m4-plan.md`](20-m4-plan.md) | What M4 needs before it starts: the six exit criteria against the code, the measured cost of a 5,000-target sweep, and the order |
| [`21-base-image-automation.md`](21-base-image-automation.md) | Having Trigon derive a base image when a build needs a tool the image lacks, and what `--image auto` may and may not decide. Design only |
| [`22-management-layer.md`](22-management-layer.md) | The decoupled front-end, the database, and multiple workers. Stages 0, 1, 2 and most of 3 and 4 are built: `trigon serve`, `trigon worker`, `trigon enqueue`, `trigon grant`, the ADR-0010 publication gate, the evidence classes and the queue. Each stage says what is built and what is still plan |
| [`threat-model.md`](threat-model.md) | The contract with a consumer of a verdict: what is assumed, guaranteed, disclaimed, and out of scope |
| [`threat-model.yaml`](threat-model.yaml) | The same, as a machine-readable index for triage. `scripts/threat-model-sidecar.py` generates it from the prose |
| [`adr/`](adr/) | Short records for the load-bearing decisions |

## Suggested reading order

- **New to Trigon:** [`introduction.md`](introduction.md), then
  [`using-trigon.md`](using-trigon.md).
- **Evaluating the design:** `00`, `01`, `05`, `12`.
- **Implementing:** `13` for what to build first, then `05` for the hard part, then `15` for the
  corpus it needs, then `02` and `04`.
- **Operating it:** `10`, `08`, `11`.
- **Consuming its output:** `09`, then run `trigon verify-attestation --rerun-comparison`.
  `scripts/cross-machine-verify.sh` runs the whole thing end to end: it builds the verifier from a
  fresh clone, hands it a bundle and two files with the network taken away, and requires it to
  catch three different lies for three different reasons.
- **Sceptical:** `14`, where two of the four examples come out with caveats, and `16`, which lists
  what these documents got wrong.

## Status

**We wrote these documents before any code, and they describe the system as intended rather than
as built.** [`16-findings.md`](16-findings.md) records each place the two disagree, which one is
right, and why; individual documents carry a note where we revised a decision. We keep that record
separate on purpose: amending each document in place would erase which beliefs were wrong and how
we found out, and that history is most of what a later reader needs.

M0, M1 and M2 are complete, and M3 has begun. The top-level [`README`](../README.md) carries the
current rates.

We checked every claim these documents make about the prior art against the source of
[google/oss-rebuild](https://github.com/google/oss-rebuild) and
[microsoft/OSSGadget](https://github.com/microsoft/OSSGadget), and every claim these documents make
about ecosystem reproducibility rates has its citation in [`03-ecosystems.md`](03-ecosystems.md).
