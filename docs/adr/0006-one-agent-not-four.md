# ADR-0006. One real agent rather than four

**Status:** accepted, reversing an earlier draft

## Decision

| Earlier draft | Ship instead |
|---|---|
| SourceScout, an agent | **Resolver**, a deterministic ladder with a model on the last rung |
| StrategySmith and BuildDoctor, both agents | **Builder**, one agent |
| DiffJudge, an agent | **Explainer**, a deterministic classifier with a model fallback |
| Triage, an agent | Deferred, and constrained to emitting queries |

## Reasoning

**Two of the four were doing something other than search.**

*SourceScout* handles a problem that resolves by lookup about 95% of the time: registry metadata,
published provenance, ecosystem-specific fields such as npm's `gitHead` and crates'
`.cargo_vcs_info.json`, then a tag ladder, then manifest history, then **tree-hash scoring against
the published artifact**. That last rung is an *algorithm*, and it beats any prompt at this task. Ask
a model which commit a tarball came from and it guesses, where a tree-hash comparison measures.
Calling the whole thing an agent invites 100,000 model calls for a problem that resolves, most of the
time, with an HTTP GET.

*DiffJudge* classifies over a near-closed taxonomy, where about ten difference classes cover most
real mismatches. And there is a sharper point: **something that can only downgrade a verdict and
never promote one is not a judge.** It explains diffs, which is a UI feature.

**StrategySmith and BuildDoctor are one agent.** Same tools, same output type, same validation, and
the only difference is whether `prior_attempts` is empty. Keeping them apart buys two prompt
families, two eval sets, two budget configurations and two regression surfaces for one capability.

## The gain

Half the prompt surface, eval surface, budget plumbing and failure modes. Nothing is lost, because
the cut agents were doing lookup and classification rather than search.

## The Explainer's real job

Over time its value shows up as a **stabilizer proposer**. It says that a difference is a build
timestamp in `META-INF/MANIFEST.MF` and offers a candidate custom stabilizer with a draft `reason:`.
That goes to a corpus-wide impact preview, then human review, then a definitions pull request. Build
that loop. Prose annotations are a side effect, and they stay out of every signed document.

## The related decision: one model call per iteration

We decline to copy the prior art's cycle of Diagnose, Implement and Clean. "Clean" is a model call
whose job is to strip markdown fences, followed by manual fence-stripping anyway, and it is a
2024-era workaround for models that could not reliably emit structured output. "Diagnose" serves
observability rather than accuracy, as their own code comment says, and we get the same artifact by
making `diagnosis` a required field in the structured output.

One structured call per iteration cuts cost by three times and improves fidelity.

Two things from their design stay: the `MaxToolIterations` budget with an explicit "budget nearly
exhausted, respond now" nudge at N minus 2, and the split between exploration and verification, which
states the idea more sharply than "bounded retries plus a clean re-run".
