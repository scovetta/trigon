# ADR-0008. Keep the traits, build one implementation of each

**Status:** accepted

## Decision

Keep every seam as a trait, since traits cost little and force clean boundaries. Build **one
implementation of each** in v1:

| Seam | v1 implementation |
|---|---|
| Queue | Our own SQL over Postgres (ADR-0005) |
| Blob store | `object_store`, which already covers S3, GCS, Azure, local and memory |
| Metadata store | Postgres, with SQLite for single-binary mode |
| Sandbox | Podman locally, Kubernetes Jobs in the fleet |
| Signer | sigstore keyless, plus a local file key |
| LLM provider | **Two**: Anthropic native, and one OpenAI-compatible client |

## Reasoning

**Every adapter becomes a permanent cell in the test matrix.** An SQS adapter nobody uses still
compiles, still needs testing, still breaks on an SDK bump, and still shows up in every dependency
audit. Writing it is not the cost. Owning it is.

**The OpenAI-compatible client is the highest-leverage single implementation in the design.** It
covers OpenAI, Ollama, vLLM, llama.cpp, Azure, OpenRouter, Groq and Together in one code path, which
satisfies "multiple providers including locally" almost on its own. Adding Anthropic native buys
prompt-cache breakpoints, reasoning controls and batch.

**`object_store` deserves a mention of its own.** It already is the abstraction, mature and widely
used, so wrapping it in a Trigon trait would add a layer and subtract nothing. Blob storage gets no
Trigon trait at all.

## Deferred

SQS, Pub/Sub, NATS, Cloud Build, CodeBuild, Bedrock, Vertex, Azure OpenAI. All documented seams, none
built until a user asks by name. The trait shapes make adding one self-contained.

## The related rule

Deferring adapters stays safe only where the traits are right, which is why `01-architecture.md` §3
spends its effort on trait *shape*: object safety, error types, stream versus reader, a consuming
`wait`. A trait with one implementation and the wrong shape is worse than no trait.
