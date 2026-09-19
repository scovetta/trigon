# 22. The management layer

A public site where a visitor can browse what we rebuilt, search it, read a run in detail, ask for a
rebuild behind auth, and — with authorization — propose a transform and see what it would do to the
corpus before anyone accepts it. Several workers behind it. A front-end that shares no filesystem,
no process and no release cycle with them.

This document is the plan for that. It replaces the fleet half of [`11-interfaces.md`](11-interfaces.md)
§3–4, supplies the shape of [`20-m4-plan.md`](20-m4-plan.md)'s Stage B, and takes over from
[`18-management-ui.md`](18-management-ui.md) at the point that document stops — `watch` stage 3, the
board, which it defers "behind the recording that would make it honest".

It was drafted, then read by three adversarial reviews — security, decided doctrine, and staging
realism. All three returned **needs-changes**, and §2 is what they changed. The uncorrected draft
would have shipped an unredacted build log to the public internet in its third stage and protected
it in its fifth.

## 1. The thesis

[`10-scale.md`](10-scale.md) §4 deferred the schema on the grounds that "a schema built before there
is a fleet to put in it is a schema whose shape is a guess", and the trigger it named was headcount.
The real trigger is sharper, and this request supplies it:

> **Two processes that do not share a filesystem must agree about one run.**

A sweep on one machine could always be served by a work directory and an end-of-sweep rollup. That
is what `trigon watch` is, and it is correct. A worker pool plus a separately deployed front-end
cannot be served that way at all.

So: build exactly one control plane — the [`ADR-0005`](adr/0005-own-the-queue.md) queue and the
[`10-scale.md`](10-scale.md) §4 tables inside `trigon-store`, with the existing content-addressed
store unchanged beside it — and hang three surfaces off it.

- `trigon watch`: unchanged, loopback, read-only, rooted in a work directory. It keeps every
  property that makes it correct when a sweep dies.
- `trigon serve`: the only HTTP surface with identity, and the only write path.
- The front-end: a separate deployable that talks to nothing but that API.

And one sentence keeps the verdict meaning something once a write path exists:

> **The management layer enqueues work. It never computes, edits or overrides an outcome.**

A user-applied transform is not an edit to a stored verdict. It is a *new run*, whose job payload
carries `Provenance::Human { reviewer }` into the ordinary comparison path, where
`crates/trigon-compare/src/lib.rs`'s `ceiling` caps it exactly as it caps everything else today.

## 2. What the reviews changed

### 2.1 The build order was backwards

The draft's first four to five weeks produced no user-facing surface: schema, then queue, then an
engine split, then a website. That breaks the rule this repository wrote for itself at
[`18-management-ui.md`](18-management-ui.md) §5, verbatim: *"Each step is independently useful and
none pays off only if the next three land."*

Worse, it was unnecessary. **Three of the four things asked for are read-only over data the store
already holds.** `trigon-store` is already `Arc<dyn ObjectStore>`, so the corpus can already live in
S3 or GCS; it already has `put_run`, `get_run`, `list_runs` and content-addressed,
re-hashed-on-every-read blobs. Browse, search and run detail need no Postgres, no queue, no engine
split and no auth. They need a reader.

So the read-only site moves to the front, before the database. See §8.

### 2.2 The public detail page was scheduled before the thing that makes it safe

The draft shipped public run-detail pages in its third stage and the evidence tier that gates bytes
in its fifth, while its own risk register said "Stage 5 lands before any detail view goes public".
Both could not be true.

This matters more than an ordering slip, because D14 — *redaction of credentials from a build log
before it is stored, rendered or sent to a model* — is **disclaimed and security-critical**, and the
only mitigation the threat model ever offered for it was "keep `trigon watch` on loopback". A public
site is exactly the removal of that mitigation. The chain is three steps: publish a package, request
a rebuild of it, read our fleet's secrets off our own public website.

**The evidence tier is not a stage. It is a precondition of the first public byte.** §7.2.

### 2.3 ADR-0010 was never named, and the site *is* the publication surface

[`ADR-0010`](adr/0010-publish-divergences.md) opens: *"All results publish automatically,
divergences included, subject to five technical safeguards."* A public browse page showing
`divergent` against someone else's package **is** publication in that ADR's sense. The draft
contained no implementation of any of the five, and carried forward `verdicts.published` from
[`10-scale.md`](10-scale.md) without ever saying what sets it.

Today safeguard 1 — two agreeing attempts — is enforced by *nothing*
([`12-security.md`](12-security.md), invariant 12). §7.1 makes the gate a schema object with one
producer.

### 2.4 A request button is a remote-code-execution button at the shipped default

`--egress open` is the shipped default for `rebuild` and `sweep`, and the threat model names it "the
insecure default": at that tier the runner adds no network flags at all. The draft specified the
`POST /v1/runs` body as "a target and a purpose, never a strategy or a stabilizer" — which never
pins the tier, and the tier is a property of the *plan the engine builds*, not of the target.

**A visitor-requested run is `--egress mirror`, always, not by default but by construction**: the
API cannot express a tier, and the engine refuses a job whose principal is not an operator and whose
plan is not mirrored. §6.

### 2.5 `LocationHint` escapes the cap

Governance today is "two-party review for anything touching stabilizers, one reviewer for a
`LocationHint`", and the draft imported that asymmetry. But the provenance cap keys on the *applied
stabilizer list*, and a `LocationHint` applies no stabilizer. It changes which repository is cloned
and whose build scripts run, and then the comparison reports `Normalized` with nothing capped.

A `LocationHint` proposed through this API is **two-party, like everything else**, and the run it
produces is capped by a mechanism of its own: §6.3.

### 2.6 `no_cache` was the wrong lever

The draft set `RunOpts::no_cache` on every visitor-requested run, citing B15. That flag is
`podman build --no-cache` — the most expensive setting in the system, discarding exactly the setup,
source and deps layers where the cost is — and B15 scopes it to *confirmation re-runs*, the second
of two attempts before a divergence publishes. A visitor asking "is this reproducible" wants an
answer, not a cold cache. Cache-key reuse is handled at admission by idempotency, not by burning the
layer cache. §5.2.

### 2.7 Two run-detail renderers

The draft froze `watch` "so run, diff and cluster are not built twice", then specified
`GET /v1/runs/{id}` and a run-detail view. That is two renderers over two data shapes that stage 0
deliberately makes disagree. [`ADR-0008`](adr/0008-one-implementation-per-seam.md) is about owning,
not writing. §3 assigns the owner: **the API owns run detail; `watch` owns the work directory.** The
two answer different questions — *what happened to this target, ever* versus *what is this sweep
doing right now, on this disk* — and the second is the one that has to survive the first being down.

### 2.8 Smaller corrections carried in

- `Provenance::Human { reviewer }` is not the right variant for an ADR-0006 model-proposed
  stabilizer a human approved. That is `Model { model_id, run_id }` with an approval reference.
  Provenance is hashed into the set digest, so a misattribution here is permanent.
- `put_attestation` overwrites one file per predicate, contradicting
  [`09-attestations.md`](09-attestations.md) §8's appendable JSONL. Fixed with the `attestations`
  table, not after it.
- The `runs/<run-id>/` write-only blob credential **cannot be expressed** by a content-addressed
  store — every writer writes under `blobs/sha256/`. The document's own fallback, a sidecar that
  holds the credential and derives the path from the bytes, is what gets built, and
  [`12-security.md`](12-security.md) §2.3 gets restated against the layout that exists.
- `POST /v1/proposals/{id}/pr` would put a `trigon-definitions` write credential inside the
  internet-facing process. Cut; the endpoint returns a patch, and a human pushes it.
- The queue's own ADR names three operational caveats and the draft addressed one. pgbouncer, a
  connection budget, and per-table autovacuum settings for the long-visibility-timeout table are
  §4.4, not folklore.
- ADR-0010 assigns the Explainer's prose to "the database and the UI, unsigned, with its model id
  attached". That is the one thing an ADR explicitly puts in the database, and the draft's seven new
  tables did not include it. `explanations` is now one of them.

## 3. Components

| Component | Owns | May never | State |
|---|---|---|---|
| `trigon-store` | The §4 schema, the ADR-0005 queue, the existing CAS. `enqueue` and `record_state` in one `sqlx::Transaction`. Row versions. | Hold a payload over 8 KB inline. Store an outcome `compare()` did not produce. Expose a role a build worker can use to read an upstream digest. | exists; gains `sqlx` |
| `trigon-engine` | The run state machine cut into leasable stages, leases, heartbeats, live `RunState` writes, phase events, host-budget reads before leasing. | Bind a listening socket. Hold a signing key. Run a build and a judge in one process in a deployment claiming invariant 6. | **new** — named at [`01-architecture.md`](01-architecture.md) |
| `trigon-api` (`trigon serve`) | The only HTTP write path. Identity, scopes, quota, enqueue, proposals, cursor-paged reads, SSE from `run_events`. **Run detail.** | Call `compare()` or `stabilize`. Write any `outcome`. Hold the signing key. Hold a definitions-repo credential. Read a worker's disk. Proxy to a live worker. Serve a byte it did not re-hash. | **new**, behind the `build` feature |
| Front-end | A separately deployed SPA: browse, search, run detail, permalinks, request form, proposal and review UI. | Hold a database or object-store credential. Be the only way to get an answer. Render an absent value as zero. Merge the two denominators. | **new** |
| Evidence gateway | Authenticated, digest-addressed, class-gated fetch of blob bytes with retention bounds. | Serve a build log or network transcript anonymously. Return bytes without re-hashing them against the digest asked for. | **new**, inside `trigon-api` |
| Publication gate | The ADR-0010 safeguards as one object with one producer: agreement, the `Void` rule, the dispute pointer, notification, the SLO kill-switch. | Let anything reach a public read path with `published` unset. | **new** — §7.1 |
| `trigon watch` | The local, database-free, directory-rooted reader. Loopback. Survives the sweep's death. | Gain a write path, a database client, an auth layer, or a routable default bind. | exists, frozen in scope |
| Attestor | Signing, unchanged: re-derives `RunFacts` from blob **bytes**; refuses a void run. | Take any fact from a database column. Sign a statement reassembled from rows. | exists; gains a DB *trigger*, never a DB *input* |

## 4. The schema

[`10-scale.md`](10-scale.md) §4's ten tables are built as written: `runs` partitioned by range on
`created`, monthly; `verdicts` append-only; `rollups` so the fleet view never scans partitions —
which stops being optional the moment a public landing page exists; SQLite with the same schema
minus partitioning for laptop mode; and the ADR-0005 rule that **Postgres holds pointers and small
scalars**, every payload over 8 KB in blob storage addressed by content hash.

### 4.1 What a front-end and a request button add

| Addition | Why |
|---|---|
| `principals`, `api_tokens`, `requests`, append-only `audit` | Ten tables and not one records *who asked*. `RunRecord` has no actor field, so "behind auth" and "auth'z'ed users" cannot be expressed at all today. |
| `tenant` / `visibility` on rows and blob paths; trust origin in the strategy cache key | [`12-security.md`](12-security.md) §2.6 already decided these "because retrofitting them costs far more later" and filed them under v2. A public request button makes the strategy cache a live poisoning vector now. |
| `runs` written **live** and on **every terminal outcome** | `record_run` has one call site, past the early return that unwraps the comparison. A browse page over today's store reports a 100 % reproduction rate on a sweep where nothing built. `RunState::Queued` gets a producer. |
| `target_digests(target_id, algorithm, digest)` replacing singular `targets.upstream_digest` | The lookup key is the published artifact's digest, and an npm consumer holds sha1 and sha512 and never sha256. Must land before anything is signed at scale. |
| `run_events`, `host_budget` as separate tables | ADR-0005: heartbeats and progress off the queue's hot path. `host_budget` is the only carrier fleet-global backoff can have — the mirror runs in a per-run container with no route to a database. |
| `attestations(...)`, append-only | Attestations are keyed by purl path and **overwritten** today, against [`09-attestations.md`](09-attestations.md) §8. The object layout becomes JSONL-append at the same time. |
| `proposals`, `approvals`, `overlays` | The write half. The approval record copies `PrebuiltStrategy { approved_by, reason }` rather than inventing a shape. |
| `publications` | §7.1: the ADR-0010 gate, and the only thing that may set `verdicts.published`. |
| `explanations(comparison_digest, model_id, text, created)` | The one thing an ADR puts in the database by name: ADR-0010, "stays in the database and the UI, unsigned, with its model id attached". Improvise it at the UI layer and the model id is what gets dropped. |

### 4.2 Two corrections to columns that were already specified

`runs.stabilizer_set_digest` has no source: `RunRecord` has no such field and `facts()` passes
`stabilizer_set: None`. Add the field to `RunRecord` rather than denormalise a column with no origin
— Freshness needs it per row, and `trigon verify` refuses to compare across differing set digests.

The definitions-repo resolved SHA, which [`04-strategies.md`](04-strategies.md) says "goes into
every attestation", is in neither `RunRecord` nor `RunFacts`. It is the provenance half of a
user-applied transform.

### 4.3 Rules that are schema constraints and not style

**No `NOT NULL DEFAULT 0`** on any timing, any `Costs` field, `attestable`, `stored`,
`guarded_members`, or `network_transcript`. `None` means no data and never zero; present-and-empty
is not absent. Tokens get one row per model in `ai_calls` and are never summed across models.

**There is no `runs.failed` boolean, at any size.** A package that did not reproduce and a build we
could not run are different findings, and a column that merges them merges the two denominators
before the front-end ever sees them.

**Outcomes serialize as strings, never ordinals** ([`ADR-0002`](adr/0002-four-match-outcomes.md)).
No Postgres `ENUM` (which orders by declaration order), no smallint, and no range index on an
outcome column — each of those is the ladder that ADR exists to prevent, rebuilt in SQL where a
downstream policy engine can write `rung <= 3`. `rollups` is keyed on
`(day, ecosystem, outcome, fault)` — the `fault` dimension is what keeps "our infrastructure could
not run the build" from being folded into a reproduction rate inside the aggregate, where no amount
of front-end discipline can pull it back out.

**The join, stated once:** a row holds an id, small scalars, and digests. A digest is a pointer, and
`Blobs::get` re-hashes on every read because the store is exactly the thing a compromised worker can
write to. Nothing signed is ever reassembled from columns. A `runs.egress_bytes` column may serve a
page and may never feed a predicate.

**Two rows carry decisions, and a re-hash cannot save them.** `target_digests` is the reference
value the artifact-hash guard enforces — [`ADR-0007`](adr/0007-observability-tiers.md) calls it the
most important security control in the system — and `strategies.trust_tier` decides whether a cached
strategy may be reused. Re-hashing validates a blob *we hold*; it cannot validate a claim about what
the registry *published*. Both are re-derived at run time from the registry and the definitions repo
and the row is a cache that the run is free to disagree with, loudly. This is
[`ADR-0013`](adr/0013-a-cache-supplies-bytes-never-decisions.md)'s rule applied to the database: **a row supplies
bytes, never a decision.**

### 4.4 The queue's operational load

ADR-0005 names three caveats. All three are now the plan's actual operating conditions, because a
public site makes the connection count a function of site traffic:

- **pgbouncer in transaction mode, with a connection budget** split explicitly between workers
  (leasing), the API (request-scoped), and SSE. SSE is a long-lived connection *per viewer*; it gets
  a bounded pool of its own and sheds rather than starving the queue.
- **Per-table autovacuum tuning** on the job table, whose 45-minute visibility timeouts produce
  exactly the long-transaction pattern the default settings handle worst.
- **Poll every 10 to 15 seconds**, unchanged, with jitter.

## 5. The API

`axum`, JSON, cursor pagination, one version prefix. Narrower than
[`11-interfaces.md`](11-interfaces.md) §3's twenty endpoints, and the absences are the design.

### 5.1 Anonymous — verdicts and claims, never bytes

```
GET /v1/artifacts/{alg}:{digest}     the one query that works without a naming authority
GET /v1/targets/{purl}   /versions
GET /v1/runs?ecosystem&outcome&fault&failure_sig&since&cursor
GET /v1/runs/{id}                    a stable run id, never a position in a directory listing
GET /v1/runs/{id}/attestation        the statement, not the log
GET /v1/stats                        off rollups
GET /v1/health   /v1/metrics
```

`GET /v1/runs/{id}` is a *stable* id. `watch`'s `/run/{index}` is a position in a directory listing
that shifts under the reader as the sweep writes, which is correct for a live local view and wrong
for a permalink.

**Anonymous reads are gated on `publications`.** An unpublished run is a 404 to an anonymous caller,
not a row with a blank field. §7.1.

### 5.2 Authenticated — a principal and a quota

```
POST /v1/runs                request a rebuild
GET  /v1/runs/{id}/events    SSE, read from run_events, never proxied to a worker
GET  /v1/evidence/{digest}   class-gated, retention-bounded, re-hashed
```

`POST /v1/runs` takes **a target and a purpose**. It cannot express a strategy, a stabilizer, a base
image, an egress tier, or a platform, and the engine independently refuses a non-operator job whose
plan is not mirrored (§2.4). It is idempotent on `cache_key`; a repeat inside the window returns the
existing run rather than enqueuing a second. It is admitted into the `interactive` tier — whose
stated source in [`10-scale.md`](10-scale.md) is literally "a UI request" — and charged against a
per-principal budget **inside the same transaction as the insert**, so admission stops rather than
overspending and reporting it afterwards.

It does **not** set `no_cache` (§2.6). The confirmation attempt that ADR-0010 safeguard 1 requires
does, because that is what B15 scoped the flag to.

### 5.3 Authorized — reviewer scope

```
POST /v1/proposals                    target scope, one bounded form, a non-empty prose reason
POST /v1/proposals/{id}/preview       judge-only re-comparison over a sampled corpus
POST /v1/proposals/{id}/approvals     the second party
POST /v1/proposals/{id}/runs          a capped run under the approved overlay
GET  /v1/proposals/{id}/patch         a patch to apply by hand against trigon-definitions
```

The preview returns *"would flip N to reproduced, M to void"* — see §7.3 for why the third number is
not "to divergent". It is what [`11-interfaces.md`](11-interfaces.md) calls "the thing that makes
accepting a stabilizer safe. Without it, every stabilizer is a leap of faith, and we sign
stabilizers."

### 5.4 Deliberately absent

No endpoint that writes `outcome`, `verdict`, or any field of a comparison — **the API cannot
express a verdict, so it cannot launder one.** No blob upload from a browser. No anonymous evidence
route. No `DELETE` of anything signed; supersession is an appended statement. No worker-proxying
route — the reader must survive the producer's death, and with multiple workers the API has no
filesystem in common with the build anyway. No `POST /v1/clusters/{id}/rerun` until per-principal
budgets exist, because it is a bulk enqueue behind one click. No `/v1/costs` in dollars while there
is no price table. No Ask endpoint. No `/pr` (§2.8).

OpenAPI 3.1 is generated from the handlers and checked in, because a decoupled front-end is *defined
by* that boundary and today nothing defines it.

## 6. Authorization, and how a transform stays capped

**Five principals.** *Anonymous*: published verdicts, attestations, digests, rollups, freshness —
never bytes. *Authenticated visitor*: the above, plus `POST /v1/runs` within a quota, plus evidence
for runs within their grant. *Disputing maintainer*: evidence for runs against packages they control
— the principal [`12-security.md`](12-security.md) §5 already names ("a maintainer disputing a
finding gets access; a scraper does not") and the draft omitted, leaving the `disputes` URL in every
signed divergence pointing at a grant with no issuance path. *Reviewer*: propose, preview, approve,
enqueue a capped run. *Operator*: fleet health, budgets, supersession, retention, and the only
principal who may name an egress tier.

Scopes are rows. The audit table is append-only. Every run carries a trace id and the principal that
requested it.

### 6.1 The cap is mechanical, not procedural

1. **The API has no code path that produces a `Match`.** It enqueues. The only producer of an
   outcome stays `compare()`, whose doc comment says the provenance cap lives there and nowhere
   else, and whose predicate is now the single named `caps_normalized`.
2. **The job payload names an overlay digest, not a stabilizer instance.** The loader that turns an
   overlay into passes constructs `Provenance::Human { reviewer }` — the variant that today has **no
   producer anywhere in production code**. Wiring that producer is the single highest-risk line in
   this plan: a transform that reaches `compare()` as `Builtin` yields `normalized` on a
   human-touched artifact, which is [`12-security.md`](12-security.md) §1.1's attack with our own UI
   performing it. It gets an exhaustive seam test beside `seam_provenance_cap.rs`.
3. **A belt-and-braces refusal in the engine.** If a job carries a non-builtin overlay and the
   comparison comes back `Normalized`, the engine refuses to record or attest and raises an
   integrity error. The cap is still computed in one place; this asserts that it was.
4. **The overlay is content-addressed** (`overlays/sha256/<digest>.json`), so a transform a user
   applied has an identity an attestation can name. A transform that lives only as a database row
   has no ref a verifier can resolve, which would break third-party verifiability for exactly the
   runs a human touched. The set digest covers `(id, stage, risk, provenance)`, so applying a
   transform changes set identity by construction: preview and adopt are different verbs with
   different digests, and neither is a rendering toggle.

### 6.2 Two-party review, reimplemented at equal strength

Today it is branch protection on `trigon-definitions` and nothing models it. In the database:
`approvals UNIQUE(proposal_id, approver)` plus `CHECK (approver <> proposer)`, both parties
authenticated, both recorded, the approval scoped to one target set and one overlay digest.

**What one approval buys.** Two parties are enough to produce a *capped run* whose attestation names
the overlay and both reviewers. They are **not** enough to make the transform a corpus default for a
package — that still requires a merged pull request against the definitions repository, which is
what keeps the repo the authority.

### 6.3 `LocationHint` is two-party here, and capped by its own mechanism

The one-reviewer asymmetry in [`04-strategies.md`](04-strategies.md) is safe in a repository where a
human reads a diff. It is not safe behind a form, because a `LocationHint` changes which repository
is cloned and whose build scripts run, and the provenance cap keys on applied *stabilizers* — of
which a `LocationHint` applies none. A hint proposed through this API is two-party like everything
else, and the run it produces carries a **source-provenance field** into `RunFacts` that caps the
outcome the same way: a run whose source location came from anything other than registry metadata or
the definitions repo cannot reach `Normalized`.

### 6.4 Three governance gaps close before the button exists

Each is a control the docs claim and the code does not enforce, and a form POST is what stops a
human noticing:

- The non-empty `reason` is validated **at load**. `compat.rs` requires the key, trims it, and
  accepts `""`.
- `CustomStabilizer` gains `reviewer`, `risk` and an approval reference — three fields the bounds
  and the cap both need, none of which exist.
- `NoteCode::CustomStabilizerTouchedExecutable` gets its first producer and its byte threshold; it
  is asserted producerless by a seam test today. Without it, "may not rewrite executable content" is
  a sentence in a document, which is what D22 already says.

### 6.5 One affordance refused outright

Anything shaped like *"normalize the rebuild to match upstream"*. A stabilizer takes no parameter
telling it which side it is on, structurally, by invariant 5. That is not a feature request; it is a
request to delete the type signature that makes a verdict mean anything.

## 7. Publication, evidence, and the two things that gate a public byte

### 7.1 The publication gate — ADR-0010's five safeguards, as one object

Nothing reaches an anonymous read path with `publications` unset. One producer, in `trigon-engine`,
which refuses to set it unless all five hold:

| Safeguard | As built |
|---|---|
| 1. Two agreeing attempts, different workers, different times | `runs.attempt`, a shared `cache_key`, and a gate that requires two terminal runs with equal `outcome` and equal comparison digest. Enforced by nothing today (invariant 12). |
| 2. Publishes as `Void`, never as a divergence, when the egress tier was `Open`, the artifact-hash guard tripped, any applied stabilizer was non-`Builtin`, or the attempts disagreed | A computed column on the gate, not a rule in a renderer. |
| 3. A machine-readable dispute pointer, and the exact falsifying command | Already in the `divergence/v1` predicate; the site serves the route the pointer names, and §6's disputing-maintainer principal is how the grant is issued. |
| 4. Maintainer notification at publish time, best-effort | A queue job, so a notification outage cannot block or silently skip a publication. |
| 5. A false-mismatch-rate SLO with a kill-switch | An operator-flippable row the gate reads. Crossing the threshold stops divergence publication until a human clears it. |

The signed statement names **two** runs, each with its own `worker` and `finishedOn`. So
`verdicts(run_id, ...)` becomes `verdicts(attempt_run_ids[], ...)`: a verdict row that cannot express
the pair is a row that contradicts the statement it points at.

### 7.2 The evidence tier is a precondition, not a stage

Class by class, from the first public byte:

| Class | Anonymous | Note |
|---|---|---|
| Signed statements, digests, verdicts, rollups | yes | the product |
| Stabilizer set manifest and `.wasm`, transform overlays | **yes** | without these a third party cannot re-derive a verdict made under a non-default set, and re-derivability is the whole claim |
| Comparison blobs | authenticated | attacker-controlled member paths at unbounded size |
| Published artifacts | authenticated, retention-bounded | redistribution |
| Build logs, network transcripts | **authenticated, redacted, retention-bounded** | D14 is unmitigated; loopback was the entire mitigation and this removes it |

Everything is fetched by digest through the gateway, which re-hashes. The front-end never holds an
object-store credential.

### 7.3 A page is a publication, and a preview number is a publication too

The draft's "never computes an outcome" rule covered predicates and not pages. Two consequences:

A judge worker is semi-trusted by design and the attestor re-derives the equivalence claim from
bytes before signing, because *nothing cheaper defends against a compromised judge worker*. Once
judge and attestor are on different machines, `runs.outcome` is a claim by that worker and the
signed statement is the checked one. **The public UI renders an unattested outcome differently from
an attested one, always, and says which it is** — a badge, not a footnote.

And the preview endpoint reports "would flip M to **void**", not "to divergent", because every run a
proposal produces carries a non-`Builtin` applied stabilizer, and safeguard 2 says such a run
publishes as `Void` and never as a divergence. A preview promising divergences promises a category
doctrine forbids.

## 8. Build order

Revised per §2.1. Each stage is independently useful. **Stage 1 puts the website in front of a
person before a single row of Postgres exists.**

**Stage 0 — record every terminal outcome, and give a run an identity. BUILT (in part).** Move `record_run` out from behind the comparison early return so a `Void`, a build
failure, a no-strategy and an infrastructure error all produce a `RunRecord` — while the attestor
keeps refusing to sign anything that is not evidence. Fold `RunReport`'s unique fields (declines,
assumptions, void reason, hosts, fetch cache, repairs, confidence) into the record so there is one
source of truth. Add `cache_key`, `attempt`, `sweep_id`, `stabilizer_set_digest`, the definitions
SHA, and multi-algorithm target digests. Add **raw per-member digests to the comparison blob** — the
recording change [`18-management-ui.md`](18-management-ui.md) §5 says is worth making *before* the
source view rather than after, and without which the aligned ORIGIN/VERDICT bars cannot exist
outside a machine holding the checkout.
*Unblocks everything. Nothing moves from a work directory to a corpus until this is true.*

What landed: a `Recording` accumulator filled as a run learns its facts, and a wrapper around
`run_inner` that writes a record on **every** terminal path — a `no-strategy`, a build failure, a
tripped guard, an infrastructure error. `RunRecord` gained `attempt`, `cache_key`, `terminal`,
`declines`, `assumptions` and `confidence`. Split into `run_inner` (the wrapper) and `run_body`
(everything a run does, unchanged), so "on every terminal outcome" is a property of a wrapper rather
than a rule six return statements are each expected to remember — the same shape `RunReport` already
uses, and the reason this is an addition rather than the rewrite §2 warned about.

`terminal` is a new field rather than a value in `outcome`, and both were needed. `outcome` is what
a *comparison* produced and stays one of the four matches (ADR-0002); `failure` is a signature, and
a `no-strategy` is a scope statement with no failure in it. Without the third field every run that
reached no verdict was indistinguishable from every other, and the corpus page could only report
them as `unclassified` — the word for a cause nobody named, not for one that was named and then
dropped on the way to the store.

Measured immediately: three `no-strategy` runs against random npm packages, each carrying the rung's
own sentence (*"npm-heuristic: the registry declared no repository for this package"*) into the
record and onto the page. The corpus went from 32 runs and zero failures to two populated columns.

**Not yet:** a run that dies in `resolve` or `fetch` still records nothing, because it has no
artifact to be a record *about* and no digest to build a run id from. Those are `Fault::Upstream`
and `Fault::Infra` — never the package's — and they stay in the work directory, where `RunReport`
already writes them on every path. Folding the rest of `RunReport` into the record, and the
multi-algorithm target digests, are the remainder of this stage.

**Stage 1 — the read-only site, over the store that exists. BUILT.** `trigon serve <store>` in
`crates/trigon-api`, against `Arc<dyn ObjectStore>`: `list_runs` / `get_run` / blobs, an index built
at startup and refreshed on a timer, cursor pagination, the twelve anonymous routes of §5.1, the
evidence classes of §7.2 enforced from the first byte, and the publication gate of §7.1 as one
object with one producer. `--public` turns on both halves at once, because a reader who enabled only
one would have a site that either accuses without confirmation or leaks unredacted logs.

The front-end is static files that talk to nothing but the JSON API, compiled into the binary and
deployable to a CDN unchanged. No bundler, no `node_modules`, nothing loaded off-origin — the same
"boring technology" reading that picked Postgres over a search service, applied to a page whose
subject is supply chains.

*Delivers browse, search and view-details — three of the four things asked for — with no Postgres, no
queue, no engine split, no auth and no write path.*

Four things only rendering it found:

- **The gate withholds the entire corpus today**, all 32 runs, every one `awaiting_confirmation`.
  That is correct: safeguard 1 is "two agreeing attempts, divergences and matches alike", and every
  run on disk is a single attempt. It is also the number that makes stage 0's `attempt` and
  `cache_key` fields real work rather than schema decoration.
- **`by_fault` is empty and `evidence` is 32 of 32.** The store holds no failure at all, because
  `record_run` sits past the comparison early return. A browse page over it reports a perfect
  reproduction rate on a corpus where nothing has ever failed to build — exactly what §4.1 predicted,
  now visible rather than argued.
- **The page's own CSP broke its bar chart.** `style-src 'self'` blocks the `style` *attribute*, so
  four proportional bars were written, silently dropped, and drawn at the track's full width. CSP
  does not govern CSSOM, so the fix was to assign each property rather than to add `'unsafe-inline'`.
- **A permalink painted the word "Loading".** An SPA that fetches its own data puts that word in
  every link preview and screenshot of itself, and a permalink is the URL people share. The document
  now carries a `<!--BOOT-->` marker the server fills with the route's data, and the publication gate
  is asked again when filling it — injecting a withheld run into the page source and trusting the
  front-end not to draw it would put the accusation in `view-source:`, which is the one place a
  front-end cannot gate.

**Stage 2 — the schema and the queue in `trigon-store`. BUILT.** Postgres and SQLite behind one trait: the job table exactly as ADR-0005
specifies, `FOR UPDATE SKIP LOCKED`, visibility timeout, attempt counter; the §4 tables;
`run_events` and `host_budget` separate; row versions so two writers stop being last-writer-wins;
`enqueue` and `record_state` in one transaction; pgbouncer and autovacuum settings from §4.4.
Stage 1's reader gains a second backend and loses nothing.
*This is M4 Stage B's first half, unchanged in shape. Its blast radius grows, not its design.*

`crates/trigon-store/src/queue.rs`, behind a `queue` feature so nothing that only reads a corpus
acquires a database driver, and `sqlx` added to the verifier's forbidden list. Postgres or SQLite
from the URL, with one statement differing between them and every other statement shared.

Three bugs the tests found: two concurrent SQLite leases deadlocking on a deferred transaction's
write upgrade, fixed by making the lease one `UPDATE … RETURNING`; `RETURNING` not preserving the
subquery's `ORDER BY`, so a batch arrived unsorted and a bulk job could be built ahead of an
interactive one held at the same moment; and a reused `$2` placeholder silently shifting every bind
after it, reading back a 4 ms interval where 50 ms was asked for.

Not yet: `runs`, `verdicts` and `rollups` as specified. The `run` table here is the pointers-and-
scalars row the outbox needs — id, target, ecosystem, state, outcome, terminal, fault, failure code,
attempt, cache key, and the digest of the record — and the API still reads the object store. Row
versions are a column and not yet a conditional update, so D7 is narrowed rather than closed.

**Stage 3 — `trigon-engine`, enforcement test first. BUILT (in part).** Cut `run_one` into leasable stages
with a serialisable handoff (strategy, pinned source, and a guard manifest of digests only). Write
*the build worker cannot fetch the upstream artifact* **first**, now in three parts: network refusal
(built), blob denial, and — new — the build worker's DB role cannot read a target's upstream digest.
Adopt the write sidecar (§2.8).
*M4 Stage B's second half.*

`crates/trigon-engine` owns the loop — lease, heartbeat, outbox, backoff, the confirmation attempt
and the cap refusal — and owns nothing about how a package is rebuilt. That is a `Work`
implementation, so the whole loop is tested without podman, a network or a registry.
`trigon worker` implements it by calling the same `run_one` the CLI calls; a worker that rebuilt
differently from `trigon rebuild` would make every local reproduction of a fleet result a
coincidence. `trigon enqueue` puts targets on the queue.

**The confirmation attempt is what makes anything publishable.** A verdict enqueues a second,
independent attempt at `Regression` tier, delayed, because the risk safeguard 1 exists against is
ambient nondeterminism and two runs back to back on a warm cache sample the same moment twice. A
run that reached *no* verdict is not confirmed — a `no-strategy` asked twice is still a
`no-strategy` — and a confirmation does not confirm itself.

Measured end to end: `enqueue` → worker `w1` builds `left-pad@1.3.0` and records `normalized` →
the engine enqueues attempt 2 → worker `w2` builds it and agrees → `trigon serve --public` shows
**`published`**, for the first time in this project's history. Everything before it was
`awaiting_confirmation`, correctly, because nothing had ever asked the same question twice.

Four bugs only running it found:

- **The worker acknowledged infrastructure failures as completed work.** `run_one` returns `Ok` for
  every terminal outcome including the ones that say *we* could not test this package, so one
  worker on a broken machine would have drained a queue without building anything. A run that is
  about the package is finished work whatever it concluded; a run that is about us goes back.
- **Five copies of the mirror-image default**, and the new one drifted to a tag that does not
  exist. The failure surfaced as a connection refused to `localhost:443`, which says nothing about
  the mistake. One constant now.
- **`--egress mirror`** is not a tier; the tiers are `deny-all`, `mirror-only`, `git-and-mirror`,
  `open`. Now validated at the flag rather than 1,400 lines later.
- **Records carried no `cache_key`**, so the gate could not tell two attempts at one package from
  two packages, and the confirmation it had just enqueued would have corroborated nothing.

**Not yet, and it matters:** `run_one` is not cut into three independently leasable stages. That is
what **invariant 6** needs, and until it exists the invariant still holds by collocation rather than
by enforcement. The enforcement test — the build worker cannot fetch the upstream artifact, in its
three parts — waits on that split, and the threat model should not be updated to claim otherwise.

**Stage 4 — identity, quota, and the request button. BUILT (in part).** Principals, tokens and OIDC,
scopes, audit. `POST /v1/runs` into the `interactive` tier, charged inside the enqueue transaction,
`--egress mirror` by construction. Scheduler admission that stops rather than overspends.
`host_budget` read before leasing and seeded into each island at creation, accepting one run of
latency.
*Delivers "visitors request rebuilds (behind auth)". Gives the `interactive` tier its first
producer.*

`principal`, `api_token`, `request` and an append-only `audit` table; `trigon grant` issues a
credential and prints it once, storing only its sha256. `POST /v1/runs` is the API's one write
route, and the rule it keeps is not "no writes" but **no route can express a verdict** — enforced
by the crate not depending on anything that computes one. The front-end gains a request form shown
only where `/v1/me` says the credential carries the scope, a queue page, and a job page that polls
the events table rather than a worker.

**The quota is charged inside the enqueue transaction**, which is the whole reason identity lives
in the same database as the queue: a limiter in front of the API is a different process reading a
different number, and the gap between its check and the insert is where a burst of clicks gets
through. A repeat request is idempotent, so clicking twice gets an answer rather than two builds.

A request names a **target and nothing else** — no strategy, no stabilizer, no base image, and
above all no egress tier, which is a property of the worker. Extra fields in the body are dropped
by the type, so there is no path by which one could reach a job.

**Not yet:** OIDC, tenancy, and the scheduler's fair-share across ecosystems. A token is a row and
a scope is a string; that is enough to have the button and not enough to run a public instance.

### What a first frame costs, three times over

The same bug appeared on three routes and each fix was narrower than the last. An SPA that fetches
its own data paints "Loading" into every link preview, screenshot and slow connection — so the
document carries a `<!--BOOT-->` marker the server fills with the route's data. That fixed browse.
Then a *permalink* — the URL people actually share — painted it again, because the island only
covered browse; `run_boot` fixed that, and asks the publication gate a second time while filling it,
since a withheld run injected into the page source is an accusation no front-end can take back.
Then `/queue` painted it a third time, and the cause was different: the view awaited `/v1/me`, and
who the viewer is depends on a token the server never saw. Identity cannot be booted, so it is no
longer awaited — the page paints with what is known and fills the credential-dependent slot when
the answer arrives.

**Stage 5 — transforms, governance before execution.** *~3 weeks. The riskiest stage.* In order:
(a) §6.4's three gaps; (b) `Stage::Patch` execution with `Provenance::Human { reviewer }` wired and
the engine's integrity refusal; (c) the corpus-wide preview as a judge-only re-comparison job;
(d) propose / approve / run / patch endpoints.
*Delivers "for auth'z'ed users, apply additional transforms" — and only after the preview exists,
because an apply button without it is strictly worse than the CLI it replaces.*

**Stage 6 — rollups, ingestion, retention.** *~2 weeks, parallelisable against 3–5.* Continuous
ingestion with cursors and catch-up; nightly rollups; a retention job that asks `prune_rebuild`'s
three refusals plus a blob refcount, since many rows now point at one blob.
*M4 Stage C, promoted from optional garnish to what makes the site truthful: "a stale pass is worse
than no data, because it looks like data."*

### 8.1 What this means for M4

Stages 0, 2 and 3 **are** M4 Stage B, in the order the M4 plan already has them. Stage 1 is new and
sits between Stage A and Stage B. Stage 6 is M4 Stage C.

Stages 4 and 5 are not M4. They are auth, authz, tenancy, abuse control and quotas — roughly
[`13-roadmap.md`](13-roadmap.md)'s M5 "public instance" pulled forward. §11 is the scope call.

## 9. Risks

**The transform button launders a human-touched artifact into `normalized`.** `Provenance::Human`
has no producer in production code today, so the entire verdict-safety story rests on a variant
nothing constructs. *Mitigated by* the three independent checks of §6.1, an exhaustive seam test, and
an API with no code path that can produce a `Match` at all.

**A public run-detail page becomes a credential-disclosure surface on day one.** *Mitigated by* §7.2
being a precondition rather than a stage: bytes are authenticated, class-gated, redacted and
retention-bounded before the first public page, not two stages after it.

**An authenticated-but-hostile visitor spends our compute and our registry reputation.** 219 req/s
from one User-Agent is a description of an incident, and unblocking is a human process measured in
days. *Mitigated by* charging the quota inside the enqueue transaction rather than in an API-layer
limiter bolted on after; admission that stops rather than reports; `--egress mirror` by construction,
which also closes the SSRF shape where a package's metadata chooses the host our fleet contacts.

**The shared database becomes the read path the build worker never had.** Invariant 6 holds today by
collocation: the host process fetches the upstream artifact and calls `blobs().put()` itself.
Splitting build from judge removes the thing enforcing it. *Mitigated by* a separate DB role with no
select on target digests or upstream blob pointers, asserted by the stage-3 test written first.

**The database quietly becomes the source of signed facts, because a column is faster than a blob
fetch.** *Mitigated by* one rule with no exceptions: derived-from-bytes stays derived from bytes. The
attestor takes no input from a row.

**Re-attesting destroys the earlier claim,** and the version ladder, freshness and regression stories
are all about a target's history. *Mitigated in* stage 0/1, together with the append-only
`attestations` table, so the object layout stops contradicting the database.

**Concurrent writers corrupt a run.** `put_run` replaces wholesale, `prune_rebuild` is
read-modify-write, and D7 verifies there is no lock of any kind — disclaimed, not mitigated.
*Mitigated in* stage 2: the row is where exclusion lives, via row versions and conditional updates. A
prune racing an attest is exactly the case `prune_rebuild`'s three refusals were written for.

**Scope.** See §11.

**Two front-ends.** [`11-interfaces.md`](11-interfaces.md) §4 embeds the React UI with `rust-embed`
"so `trigon serve` gives the full UI with no separate deployment step", and "decoupled" contradicts
it directly. Drifting rather than deciding produces an embedded UI that silently rots. *Decided:* the
API is the only contract; the embedded UI is a build of the same front-end vendored for local mode.
`xtask policy` stays the guard that no API, `sqlx` or async dependency reaches a
`--no-default-features` verifier build.

## 10. Rejected

| Option | Why not |
|---|---|
| Put a write path on `watch` and give it `--bind 0.0.0.0` plus auth | P20 is a published security-critical property, and `watch` authenticates nobody *by design* because a work directory holds registry artifacts and build logs that may carry credentials. A decoupled front-end also cannot read a worker's disk. The two surfaces fork; they do not merge. |
| `pgmq`, or a broker as the primary | ADR-0005: pgmq is an extension most managed Postgres declines, turning deployment into procurement; no broker shares a transaction with the run-state write. |
| A `trigon-queue` crate | `enqueue` and `record_state` must share one `sqlx::Transaction`. Split across a crate boundary, both crates need `sqlx` anyway — the boundary buys nothing and costs the transaction. |
| Store user transforms only as database rows | A row has no ref a verifier can resolve, so third-party verifiability breaks for exactly the runs a human touched. |
| One authorized user applies a transform that becomes the target's canonical verdict | One user clicking Apply is one party, and two-party review is the control that stops a custom stabilizer normalising a backdoor away. |
| Ship the apply button before the corpus-wide preview | Shipping apply first ships the feature with its safety case removed. |
| An API that computes or edits a verdict — "mark as reproduced", a cap override | The cap is one predicate in one place, and invariant 2 is one of only two security invariants this project can claim actually holds. An editable outcome column is how you break it without touching the comparator. |
| SSE proxied from the worker running the build | The reader must survive the producer's death — the property that makes `watch` correct when a sweep crashes. Workers write `run_events`; the API reads it. |
| Elasticsearch, GraphQL, a search service | Boring technology, small team, laptop-to-cloud. Postgres full-text plus trigram over indexed columns, with `rollups` keeping the landing page off the partitions, is enough at the scale [`10-scale.md`](10-scale.md) implies. |
| Treat the public site as B10 | Lookup must be anonymous and cacheable or it will not be adopted, and the shippable offline index is a different product for a different persona. The site subsumes B10's record-schema half only. |
| A dollar cost view | There is no price table, and multiplying by a rate we typed in puts an invented number on the one view whose purpose is that you do not discover the cost on an invoice. |
| The `runs/<run-id>/` write-only blob prefix credential as specified | A content-addressed store cannot express a per-run write prefix, so the credential as specified grants write access to nothing. §2.8. |
| `POST /v1/proposals/{id}/pr` | It puts a definitions-repo write credential inside the internet-facing process to save a reviewer a copy-paste. The endpoint returns a patch. |
| Full multi-tenancy now | Out of scope for a small team — but the *rules* stop being deferrable the moment a public site accepts visitor-requested rebuilds. Tenant scoping is designed into the schema and the strategy cache key in stage 2, the cheap half; cross-tenant isolation of compute stays v2. |
| The Ask view, the contradiction feed, `check --format sarif` as part of this work | Each is independently useful and none blocks or is blocked by this. `check` stays M4 Stage D and gets *cheaper*, because `POST /v1/check` and the CLI share one store-backed lookup once stage 2 exists. |

## 11. The scope call

Stages 0–3 are M4 Stage B plus a website that needs none of it, and they fit the milestone. Stages 4
and 5 are auth, authz, quotas and a governed write path — [`13-roadmap.md`](13-roadmap.md) puts the
public instance in M5, and M4's budget is four weeks.

The honest reading: **stage 1 delivers three of the four things asked for and does not commit the
project to anything.** Stage 2 is the irreversible step, because a Postgres dependency in
`trigon-store` is not something you back out of on a Friday.

So the decision to make before stage 2 — not after it — is whether stages 4 and 5 are M4 growing to
absorb them, or a milestone of their own between M4 and M5. This plan does not make that call.

One criterion should be restated either way. "The UI ships six views" now splits three ways: `watch`
(local, live, directory-rooted), the public site (corpus, historical, attested), and CI-facing
`check`. Left as one line it is unfalsifiable.

## 12. What stage 1 actually shipped

`crates/trigon-api`, `trigon serve <store>`, and the static front-end beside it.

**The API** — twelve GET routes, no verb that writes, and the absence is structural rather than
observed: the crate does not depend on `trigon-compare` or `trigon-stabilize`, so no handler can
produce a `Match` however the code is arranged. `xtask policy` refuses the verifier build if
`trigon-api` reaches it. `GET /v1/openapi.json` is generated from the route table, and a route that
answers without appearing in that table fails a test.

**The publication gate** — `publication::decide`, one function, `Published` / `Void` / `Withheld`,
with the reason attached and a sentence a reader can act on. Safeguard 2's clauses are checked
before safeguard 1's, so an open-egress run reads "published as void" rather than being told to wait
for a confirmation that could not change the answer. The gate is asked **twice** for a permalink:
once by the JSON route and once when filling the boot island, because a withheld run injected into
the page source is an accusation the front-end has no way to take back.

**The evidence classes** — `Statement` and `Definition` anonymous, everything else needing a
principal. Definitions are anonymous on purpose: a third party who has to ask our permission for the
stabilizer set a verdict was computed under cannot check that verdict, and checkability is the claim.

**The front-end** — browse with filters and text search, a package's version ladder, lookup by the
sha256 of an artifact you are holding, run detail with the chain, the source, the costs and the
class-gated evidence links, and cursor paging. Both themes. No bundler, no `node_modules`, nothing
loaded off-origin, and a CSP that says so.

**Two denominators, still apart.** The landing page has two cards and no third. There is no
percentage anywhere in the front-end, because the only honest one needs a denominator the reader has
to choose.

### What it measured on the corpus that exists

| | |
|---|---|
| Runs in the store | 32 |
| Reached a verdict | 32 |
| Never became evidence | **0** |
| Released to a public reader | **0** — all 32 `awaiting_confirmation` |

Both zeroes are findings rather than results. The first is §4.1's prediction confirmed from the
other side: `record_run` sits past the comparison early return, so a build that failed leaves no
record at all, and a corpus browser over today's store reports a perfect reproduction rate on a
corpus where nothing has ever failed to build. The second is ADR-0010 safeguard 1 meeting a
single-attempt corpus, which is what `attempt` and `cache_key` exist to fix.

Both are now fixed, and the second is worth recording as a measurement rather than a plan:

| | then | now |
|---|---|---|
| Runs in the store | 32 | 35 |
| Never became evidence | **0** | 3, each `no-strategy`, each carrying the rung's own sentence |
| Released to a public reader | **0** | `left-pad@1.3.0`, on two agreeing attempts from two workers |

The second row is stage 0. The third is the engine's confirmation attempt, and it is the first
thing this project has ever published under ADR-0010's safeguards rather than in spite of their
absence.

## 12.1 The comparison, rendered

The first version of stage 1 served the corpus and linked the evidence: `/v1/runs/{id}/comparison`
gave you the stored blob and nothing read it for you. Honest, and also asking somebody to read three
thousand lines of JSON to learn that ten members of a NuGet package differ.

`GET /v1/runs/{id}/diff` renders it, and the run page shows six panels built from it:

- **Why this is the verdict** — the three questions a verdict is, with the one that answered marked
  and the ones above it greyed. Six digests are unreadable; three questions with one of them marked
  is the same information a person can hold.
- **What differs** — one banded bar, the finding first, and the executable count called out
  separately because `ExecutableContentDiffers` carries the doc comment *"Never benign"*.
- **What the package holds** — the contents, by kind. The question "what is in this package" had an
  answer the site did not give.
- **The stabilizers** — the ceiling, which passes hold it there and why, and a ledger with risk and
  provenance.
- **Member by member** — every member with its state, kind and both sizes, the finding sorted
  first, capped at 500 with the remainder stated.
- **What the comparison noticed** — the notes, with the ones the type documents as never benign
  marked as reaching a human.

**The raw routes stay.** A rendering is what a reader wants; the blob is what a third party
re-derives a verdict from, and no page replaces `trigon verify-attestation --rerun-comparison`.

Three decisions worth recording.

**The cap predicate moved to `trigon-core`.** Showing a reader *which* passes cost them a clean
verdict needs the rule, and the API deliberately does not link `trigon-compare`. The choice was
between linking the comparator into a read-only surface or writing
`provenance != Builtin || risk > Metadata` a second time. Neither: the rule is about two core types
and now lives beside them, with `trigon-compare` projecting onto it. Moving a seam down is how
ADR-0008 is kept when two crates need one rule.

**The rendered diff is anonymous, and that is a correction.** The evidence class table gated member
paths as though they were secret. They are not — the same paths reach a signed `divergence/v1`
statement served to anybody. What is dangerous about the raw blob is its **size**: D9 disclaims any
bound on a difference summary, so one request against a pathological artifact is an amplifier. The
bound is the control. Gating the rendered view too would have meant a public site that shows a
verdict and cannot say what it is about.

**The projection is a second description of one shape**, which is the defect this tree keeps
finding, so it has the assertion that was missing the other times:
`the_projection_reads_a_real_comparison` builds a genuine `Comparison` through a dev-dependency,
serializes it, and asserts every field the page claims to read comes back populated. A field renamed
upstream fails that test rather than silently rendering a blank.

And one thing the record cannot answer: **which passes were configured and stayed silent.** `apply`
returns only what fired, and the comparison keeps the set's id and digest but not its membership, so
nothing downstream can tell a pass that found nothing from one that was never configured. That
difference is evidence — `nupkg-signature` finding no signature says the package was unsigned — and
the view reports it as *unknown* rather than as an empty list. `trigon watch` can show it only
because it re-derives the set locally. Putting the set's membership in the comparison would fix it
everywhere.

### What a first frame costs, a fourth time

Adding the comparison fetch in front of `view.replaceChildren` put the word "Loading" back into the
run page's first frame — the fourth time, after browse, a permalink and the queue. Each earlier fix
was correct and none generalised, because the bug is not in any view: it is that `await` before a
paint is easy to write and invisible until somebody looks at a screenshot. There is now one helper,
`fillLater`, named after the rule, and the rule is stated where it will be read: **paint first,
fetch second**; if you are awaiting something before `replaceChildren`, that is the bug.

## 12.2 What actually differs inside a member

The census says *that* `lib/net20/Newtonsoft.Json.dll` differs and what kind of difference it is.
For a maintainer reading a finding about their own package that is not the question. Two routes
answer the real one:

- `GET /v1/runs/{id}/member?path=…` — both copies, as a **line diff** where the bytes are text and
  as a **hex diff** where they are not. Both are built; the default is chosen from the bytes.
- `GET /v1/runs/{id}/member/raw?path=…&side=…` — one copy, whole, to read or to save. A member the
  build produced and the published artifact never had has no diff and is still the thing somebody
  needs to look at.

In the UI a differing member is a button; it opens under its row, with a text/hex toggle, download
links for each side that has the file, and a fragment in the address bar so "look at this file" is
something you can send someone.

On `Newtonsoft.Json@11.0.1` the `.nuspec` diff is three hunks and every one is a finding: the
rebuild drops `<owners>` and `<requireLicenseAcceptance>`, adds a `commit` attribute to
`<repository>`, and writes `.NETPortable4.5-Profile259` where 2018's NuGet wrote
`.NETPortable0.0-Profile259`. The DLL's hex view opens at offset 0x88 with `eb84659e` against
`93faaab5` — the PE timestamp, which is the reproducibility problem .NET has had for fifteen years,
sitting in a table a person can read.

**Binary is decided from the bytes, not from the comparison's `kind`.** A zero byte in the first 8 KB,
or bytes that are not valid UTF-8; and the panel says which, so a reader who disagrees knows what to
look at. The `.nuspec` above is classified `binary` by the comparator, from its name, and opens as
text because its bytes are XML. That disagreement is the argument for reading the bytes.

**Raw, and only raw.** These are the copies as published and as built, *before any pass ran*.
Showing the stabilized forms would need `trigon-stabilize`, which this crate does not link. It is
also the more useful pair, but the panel says which it is, because "these two files differ" and
"these two files differ after we rewrote both" are different claims.

### Gated, unlike the census

The rendered census is anonymous because its control is a bound. A member is not: a diff of a file
that differs everywhere *is* the file, and `12-security.md` §5's rule applies unchanged — we hold
somebody else's bytes to check them, not to redistribute them. Both member routes are
`Class::Artifact`. That is the line the class table now draws: **a count is a claim about an
artifact, and a member is its content.**

### Bounds, each of which says what it left out

256 MB of artifact parsed, 16 MB of member returned, 2 MB per side considered for a line diff, 600
lines of unmatched middle aligned before the rest is reported as wholly replaced, 8 KB of hex across
at most 8 regions.

Two of those were wrong first. The hex view showed **the first 8 KB of the file**, which on a DLL
with an identical header is two screens of agreement and none of the finding — so it now finds the
differing runs, coalesces them, and shows a window around each. And the byte budget went to whichever
region asked first, so one enormous region took all of it and `regions_omitted` reported **zero**:
no *region* had been dropped, because one had been silently truncated instead. It reports
`differing_bytes` against `shown_bytes` now — 469,719 against 1,264 on that DLL — and no region may
take more than its share, so four separate differences get four windows rather than one.

### Two walks that have to agree

The comparison names a nested member `data.tar.gz!package/index.js`. This crate has to find it by
that name and does not link the comparator, so it walks archives itself — two traversals of one tree
in two crates, which is the defect this tree keeps finding. `seam_member_bytes.rs` asserts it
against a real gem-shaped archive: build one, compare it, and demand that every path the comparison
produced resolves here.

The vacuity check in that test earned itself immediately. The first fixture was a `.tgz`, which is
*not* nested — gzip is that format's container, so its members are named plainly and the `!` form
never appears. The assertion that the fixture still contains a `!` failed, and said so.

### The deep link boots server-side

The member lived in `#member=…`. A fragment is the natural home for in-page state and exactly wrong
for a link somebody sends: **it never reaches the server**, so the one thing a deep link most wants
rendered was the one thing the document could not carry. It is `?member=…` now, and the run
document carries the panel. The old form is still read, because links to it exist and a link that
silently does nothing is worse than three lines of compatibility.

**The gate is asked at document-render time**, not delegated to the script. A member's bytes are
`Class::Artifact`, and putting them in the page for a reader who may not fetch them would move the
content from a route that refuses to a page source that cannot — the same reasoning that makes
`run_boot` re-ask the publication gate. An anonymous reader gets `"member": null` and the script
falls through to the route, whose refusal explains itself. A reader signed in with a bearer token
lands there too: a browser sends a token on an XHR and not on a document request, so identity
cannot be booted, which is the limit `/v1/me` already has.

**The comparison is booted with it, and that is not scope creep.** The member panel is drawn inside
the member table, which the comparison produces, so booting one without the other saves a request
and still leaves a reader watching a placeholder. Bounded at 192 KB of rendered comparison — past
that the script fetches, which is what it did before — and measured after rendering rather than
guessed from the member count, because members are not the only thing that varies.

Measured: a deep link to the `.nuspec` diff on `Newtonsoft.Json@11.0.1` now makes **no requests at
all**. The document is 19.8 KB and carries the verdict, the ladder, the census, the ledger, all 23
members and the open diff. Without the member it is 12.4 KB; the browse page is 19.2 KB.

**Three reasons a member has no bytes, and three messages.** Retention dropped the artifacts;
the artifacts are there and the member is not; the member would not read. The first is our policy,
the second a fact about the package, the third a fault — and they were one message until the route
was pointed at a run that had reproduced, where the bytes are dropped by design.

And one test had to exist before any of this could: `a_members_content_cannot_close_the_island`.
Until now the island held package names and counts. It now holds **the bytes of a file somebody
else published**, which is the most attacker-controlled thing on the page — a member whose content
is `</script><script>…` would be executing on this origin before the first paint.

### What a member request costs

Twice the artifact, because both copies are fetched and parsed to compare one file inside them.
Measured: 409 MiB peak for a 200 MiB-per-side artifact. `MAX_ARTIFACT` allows 256 MiB a side, so a
request can cost half a gigabyte and nothing bounded how many ran at once — member reads hold one of
four permits now, and an artifact the record says is over the cap is refused before the blob store
is touched at all. `docs/16-findings.md` §3.45 has the table.

## 13. What is left

Three things, and each is blocked on something real rather than on time.

**Transforms (stage 5).** The write half of the user's request, and the only one of their four asks
that is not built. It is not a matter of adding a button: §10 rejects shipping apply before the
corpus-wide preview, on the grounds that doing so ships the feature with its safety case removed —
and the preview is a judge-only re-comparison over a sampled corpus, which needs the judge worker
class that stage 3 has not split out yet. The engine already carries the refusal that will guard
it: a job with a non-`Builtin` overlay whose comparison returns `normalized` is refused, left dead,
and raised, because the cap should have held it.

**The infer/build/judge split (stage 3's remainder).** Invariant 6 — the build worker cannot fetch
the upstream artifact — holds today by *collocation*: one process does all three, so there is no
boundary to cross. A fleet does not change that, because the fleet's unit of work is still one
whole run. Splitting it is what turns the invariant into something a test can assert, and the
enforcement test waits on the split rather than the other way around. Until then the threat model
should keep saying collocation.

**The set's membership in the comparison blob.** One recording change, and it closes a gap
everywhere at once. `apply` returns only the passes that fired; the comparison keeps the set's id
and digest but not its members, so nothing downstream can tell a pass that found nothing from one
that was never configured. That distinction is evidence — a signature pass with nothing to strip
means the package was unsigned — and today only `trigon watch` can show it, by re-deriving the set
locally from a crate the API deliberately does not link. The same shape as §5's raw per-member
digests: a fact that exists at run time, is not written down, and therefore cannot be shown by
anything that was not there.

**The §4 tables, and D7.** `run` is the pointers-and-scalars row the outbox needs, not
`10-scale.md` §4's `runs`/`verdicts`/`rollups`. The API still reads the object store, which is
correct at this size and is the thing stage 2 was supposed to replace behind the same reader.
`version` is a column and not yet a conditional update, so concurrent writers are narrowed rather
than excluded.

Everything else in §8 is built. §11's scope call is still the scope call: stages 4 and 5 are not
M4, and the part of stage 4 that shipped is the cheap half — a token is a row and a scope is a
string, which is enough to have the button and not enough to run a public instance.
