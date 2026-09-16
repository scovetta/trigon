# Architecture Decision Records

Short records for the load-bearing decisions. Each one states the decision, the alternatives we
considered, and the reasoning, so the reasoning outlasts the people who did the deciding.

| ADR | Decision |
|---|---|
| [0001](0001-rust-and-the-judgement-split.md) | Rust, and a judgement half that cannot call a model |
| [0002](0002-four-match-outcomes.md) | Four match outcomes rather than a six-rung ladder |
| [0003](0003-strategy-representation.md) | An internally tagged enum with four variants, and ecosystem strategies as templates |
| [0004](0004-own-the-archive-writers.md) | Hand-written tar, zip and gzip writers, with copy-on-write bodies |
| [0005](0005-own-the-queue.md) | Our own queue in SQL rather than a Postgres extension |
| [0006](0006-one-agent-not-four.md) | One real agent rather than four |
| [0007](0007-observability-tiers.md) | Observability as a tier, shipping the network transcript only |
| [0008](0008-one-implementation-per-seam.md) | Keep the traits, build one implementation of each |
| [0009](0009-no-gha-emulation.md) | Read GitHub Actions, do not emulate runners |
| [0010](0010-publish-divergences.md) | Publish divergences automatically, with technical safeguards |
| [0011](0011-keyed-signing-under-a-trusted-root.md) | Sign with a key under a trusted root, and log to Rekor anyway — not keyless |
