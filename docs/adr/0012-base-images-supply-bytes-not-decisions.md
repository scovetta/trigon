# ADR-0012. A base image supplies bytes, never decisions

**Status:** accepted

## Decision

Keep **a small number of long-lived, digest-pinned base images, one per ecosystem-and-toolchain
family** — roughly six, the shape [`08-execution.md`](../08-execution.md) §3 already describes. Do
**not** ship an image per language runtime version, per npm version, or per SDK version.

The rule that decides what may go in one:

> A base image may supply **bytes** the evidence does not pin. It may never supply a **decision**
> the evidence does pin.

`ca-certificates`, `git`, `wget`, a C compiler, `pkg-config`, `ssh`, PCL reference assemblies — all
bytes. Nothing about a package says which of them to use, so an image carrying them decides nothing.

Node, npm, the .NET SDK, yarn, pnpm — all decisions. The registry records `_nodeVersion` and
`_npmVersion` for every npm publish; a `.csproj` names its frameworks; a repository pins its own
package manager. An image carrying any of them either loses to the pin and is dead weight, or wins
over it and silently answers a different question from the one asked.

> **Correction, 2026-09-19: the .NET SDK does not belong in that list, and the reason given for it
> was wrong.**
>
> The rule above is about *a decision the evidence pins*. For npm the evidence does pin one — the
> registry records `_nodeVersion` for every publish, so an image's Node overrides it and the run
> measures a toolchain nobody chose. That is real and the SIGABRT in `npx.yaml` is what it looks
> like.
>
> NuGet is not that case. The reason given here — "a `.csproj` names its frameworks" — is true and
> is not a pin: naming `net45` or `net10.0` constrains which SDKs *can* build a project, it does not
> select one. The NuGet rung's own recorded assumption says as much in the run record of every
> target: *"NuGet publishes no compiler version, so this builds with whatever .NET SDK the base
> image carries."*
>
> So there is no pin for an image to override. Refusing to supply an SDK protects nothing and
> costs the whole ecosystem: twenty-one of twenty-five NuGet targets in the 125-target random sweep
> failed with `dotnet: not found`. `--image auto` therefore starts a NuGet target from
> `mcr.microsoft.com/dotnet/sdk`, resolved to a digest at use time and recorded in
> `Environment.base_image`.
>
> **This is the rule applied, not an exception to it.** An image may supply bytes the evidence does
> not pin. The SDK is exactly that, and the run says which one it was. What has not changed: an
> image must still never carry Node, npm, yarn, pnpm or a Rust toolchain, because those *are*
> pinned, and `trigon-sandbox`'s admission table refuses every one of them.
>
> What this leaves open is *which* SDK. The tag is a constant today, and the SDK announces a wrong
> guess precisely — `NETSDK1045`, named as `env/dotnet-sdk-too-old` and carrying the version it
> wanted. Deriving it from the project's declared `TargetFramework` is the better answer and is not
> built.

## What prompted it

A 197-target npm sweep reported nine `env/missing-tool` failures. The bucket is named after the
environment, so the natural reading was that the environment should carry more — should there be a
"golden" image per language, with the common tools already in it?

The nine were **four unrelated causes wearing one name**:

| cause | count | whose |
|---|---:|---|
| `npx` absent from Node < 8.2, and our recipe reached for it anyway | 3 | ours — a recipe bug |
| the package's own lifecycle script shells out to yarn or pnpm | 6 | the package's |

Three were a real defect in `npm/npx`, fixed. Six were packages declaring a build that needs a
package manager Trigon does not drive. **Neither is an image gap**, and an image would have made the
second group worse rather than better: yarn in the image means those builds run under *some* yarn,
producing a verdict about a build the publisher never did.

The question was asked because the classifier gave four findings one name. That misattribution is
now split (`npm/unsupported-package-manager`, `Fault::Build`), and with it the apparent case for
golden images largely disappears.

## Why not an image per runtime version

The arithmetic is unflattering and the trust argument is worse.

**Arithmetic.** The M1 npm corpus of 197 targets pins **102 distinct Node versions** — 1.82 targets
per image. Installing the toolchain is **4.1% of wall time** (457s of ~11,000s across the corpus).
So the proposal is roughly 13.4 GB of images, each rebuilt whenever Debian moves, to recover one
twenty-fifth of a sweep.

**Trust.** The image digest is in the run key
([`seam_cache_keys.rs`](../../crates/trigon-core/tests/seam_cache_keys.rs)), in
`Environment.base_image` ([`record.rs`](../../crates/trigon-store/src/record.rs)), and in the
attestation's `externalParameters` ([`rebuild.rs`](../../crates/trigon-attest/src/rebuild.rs)).
Every distinct digest is a distinct environment and a distinct run-key namespace. A hundred images
is a hundred namespaces holding under two verdicts each, none comparable with any other — and two
runs that cannot be compared cannot attribute a divergence to the package, which is the only thing a
verdict is for.

## The strongest objection, which is not answered here

**The base image is already the least pinned input in the run.** `apt-get update && apt-get install`
floats, so every rebuild of a base image changes its digest, changes the run key, and orphans every
verdict cached under the old one — silently, with nothing in the record saying what moved.
[`12-security.md`](../12-security.md) admits the build links against whatever libssl the image
happened to carry the day it was built.

So this ADR defends a patch-level Node pin while a floating libssl sits in the same container. That
ordering is arguably backwards, and the honest position is that it is a real gap rather than a
refutation: the fix is to make base images themselves reproducible, not to add more of them. Until
then, fewer images means fewer floating inputs, which points the same way as the decision above.

## The option this framing missed

Three independent reviews — a reproducibility lens, an operator lens and a maintainer lens —
converged on a fourth answer that the per-language / per-version / minimal framing cannot express,
because it separates two things those three conflate: **having the bytes locally** and **what the
environment is said to be**.

A **content-addressed toolchain store**, keyed by the tarball's sha256, kept on the worker and
mounted read-only into the build. `npm/install-node` checks it by hash before reaching the network.
Image-speed provisioning at exact per-target fidelity, and no digest proliferation at all, because
the toolchain's identity travels as a hash in the run record rather than as a layer in an image
digest. `rebuild/network.jsonl` already records those hashes as `"checked":"hashed"`.

Filed as [B24](../17-backlog.md). Note the operator lens's objection to a *mirror-side* cache, which
is why the store is host-side: a cache inside `trigon-mirror` is invisible to the attestation and
sits beside the guard that enforces "the build must not fetch its own published artifact". A store
whose entries are verified by hash on every use is a different proposition from one that is trusted
because it is warm.

## What this costs, stated plainly

- **Every build pays for its toolchain**: ~4% of wall time, and 8.66 GB of egress across the
  197-target npm corpus for 4.41 GB of distinct content. Until B24 lands, the other 4.25 GB is the
  same hundred tarballs fetched again.
- **Ecosystems whose toolchain is not a tarball need a base image anyway.** The .NET SDK is the
  live example: it is not an apt package, so `trigon base-image --packages` cannot express it, and
  the image is currently the only place to put it. That is a decision in an image, and it is an
  admitted exception rather than a refutation — recorded in [`03-ecosystems.md`](../03-ecosystems.md)
  §5 alongside the assumption it forces every NuGet run to state.
- **Operators build their own images** for anything past the default set, and today that is
  under-supported: two flags had to be added in one week (`--pcl-reference-assemblies`, and the
  `--packages` list form) for cases the interface could not express.
