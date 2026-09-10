# ADR-0005. Our own queue in SQL

**Status:** accepted

## Decision

Implement the job queue as roughly 200 lines of SQL over plain PostgreSQL, using
`SELECT … FOR UPDATE SKIP LOCKED` with a visibility timeout and an attempt counter, living in
`trigon-store` alongside the metadata store. Do not depend on `pgmq`.

## Not `pgmq`

`pgmq` is a Postgres **extension**, and most managed Postgres offerings decline to install arbitrary
extensions. That conflicts with running on any cloud and on a laptop, and it turns a deployment
question into a procurement question.

## Not a dedicated broker

SQS, Pub/Sub and NATS are fine brokers, and each becomes an adapter later. None of them shares a
transaction with the run-state write.

## The queue lives in the store crate

`enqueue` and `record_state` have to happen in **one transaction**, a transactional outbox. Split
across a crate boundary, both crates need `sqlx` anyway, so the boundary buys nothing and costs the
transaction. This is the clearest case of the principle in `01-architecture.md` §2.1: split where you
want to enforce a policy, and nowhere else.

## Postgres is enough

90,000 jobs spread over days works out well under one message per second, and the implementation
handles thousands. Something else breaks first: upstream rate limits, image pull bandwidth, or the
build-duration tail (`10-scale.md` §2).

Three caveats are real:

- **Long visibility timeouts.** A 45-minute build needs a 45-plus-minute lease, and the archive table
  needs per-table autovacuum tuning or it bloats.
- **Keep heartbeats and progress off the queue.** Use a separate table, or you amplify writes on the
  hot path.
- **KEDA polling** at one-second intervals across many scalers creates pointless connection load.
  Poll every 10 to 15 seconds, through pgbouncer, with a connection cap.

## The rule that keeps this true

**Postgres holds pointers and small scalars. Every payload over 8 KB goes to blob storage, addressed
by content hash.** The scaling risk was never the queue. It is the `runs` table, and only where
payloads sit inline.
