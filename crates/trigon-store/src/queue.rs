//! The queue: about two hundred lines of SQL over plain Postgres, or SQLite on a laptop.
//!
//! [ADR-0005] decided all of this and the reasoning is not re-litigated here, only implemented:
//!
//! - **Not `pgmq`.** It is an extension, most managed Postgres declines to install it, and that
//!   turns a deployment into a procurement.
//! - **Not a broker.** None of them shares a transaction with the run-state write, and that
//!   transaction is the whole point.
//! - **Not a `trigon-queue` crate.** `enqueue` and the run-state write must share one
//!   `sqlx::Transaction`; split across a crate boundary both crates need `sqlx` anyway, so the
//!   boundary buys nothing and costs the transaction. This module lives beside [`crate::Blobs`]
//!   for that reason and no other.
//!
//! **Postgres holds pointers and small scalars.** A job payload over 8 KB goes to blob storage and
//! the row keeps its digest; a run row keeps its outcome, its fault and the digest of the
//! [`RunRecord`] that says the rest. The row is a cache; the blob is the record, and
//! [`crate::Blobs::get`] re-hashes it on every read because the store is exactly the thing a
//! compromised worker can write to.
//!
//! **One divergence between the two backends, and it is inherent.** Postgres leases with
//! `FOR UPDATE SKIP LOCKED`; SQLite has a single writer, so the same statement without that clause
//! is already exclusive. Every other statement is one string used by both. [ADR-0008] is about one
//! *owner* per seam, and the owner is this module.
//!
//! [ADR-0005]: ../../../docs/adr/0005-own-the-queue.md
//! [ADR-0008]: ../../../docs/adr/0008-one-implementation-per-seam.md

use crate::{RunRecord, StoreError};
use serde::{Deserialize, Serialize};
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row as _};
use std::sync::Arc;
use std::time::Duration;

/// Which backend, because exactly one statement differs between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Postgres,
    Sqlite,
}

/// What a job is waiting behind.
///
/// **An ordering, and therefore genuinely a scale** — unlike an outcome, which [ADR-0002] says must
/// never be one. The distinction is not a loophole: a priority exists to be compared, and a verdict
/// exists to be read. The ordinal is computed in the query and never stored, so a tier added
/// between two existing ones changes one `CASE` and no rows.
///
/// [ADR-0002]: ../../../docs/adr/0002-four-match-outcomes.md
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Somebody is waiting. `10-scale.md` names the source of this tier literally as "a UI
    /// request", and it is the tier a visitor-requested rebuild is admitted into.
    Interactive,
    /// A confirmation attempt, or a re-run after a stabilizer change. Ahead of bulk because a
    /// divergence publishes only once a second attempt agrees, and a corpus whose confirmations
    /// queue behind a sweep publishes nothing.
    Regression,
    /// A sweep. Everything else waits for nobody.
    Bulk,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Interactive => "interactive",
            Tier::Regression => "regression",
            Tier::Bulk => "bulk",
        }
    }

    fn parse(s: &str) -> Tier {
        match s {
            "interactive" => Tier::Interactive,
            "regression" => Tier::Regression,
            // An unreadable tier is the slowest one. A row we cannot classify must not be able to
            // jump the queue by being malformed.
            _ => Tier::Bulk,
        }
    }
}

/// Where a job is. A string on the wire and in the column, never an ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Waiting, and visible once `visible_at` has passed.
    Ready,
    /// Leased by a worker. Returns to `Ready` on its own when the lease expires — nothing has to
    /// run for that to happen, which is what makes a worker's death survivable.
    Leased,
    Done,
    /// Failed, and out of attempts. Kept rather than deleted: a dead job is the evidence that
    /// something is wrong, and a queue that tidies those away is a queue that looks healthy.
    Dead,
}

/// A unit of work, as a worker receives it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Job {
    pub id: i64,
    /// `rebuild`, `confirm`, `judge`. A worker leases only the kinds it can do.
    pub kind: String,
    pub target: String,
    /// The job's identity in the queue, which enqueueing is idempotent on with `attempt`.
    ///
    /// **Two kinds of key share this column, and neither is copied onto a record.** A first
    /// attempt is queued under [`request_key`], which names what was asked for — the target, all
    /// an enqueuer knows before a strategy has been inferred. A confirmation is queued under the
    /// first attempt's [`RunRecord::cache_key`], which the run built from the target, the strategy
    /// it ran and the set it was judged under ([`crate::cache_key`]). The record a run writes
    /// carries the key the run built, never this one: when the worker copied this onto the record,
    /// every fleet run was keyed on its purl alone, and two attempts straddling a change of
    /// strategy or set counted as one question (`docs/17-backlog.md` B31).
    pub cache_key: String,
    pub attempt: i32,
    pub tier: Tier,
    /// The job's parameters, inline while they are small.
    ///
    /// `None` with `payload_ref` set means the payload went to blob storage because it crossed 8
    /// KB. Both `None` means a job that needs no parameters beyond its target.
    pub payload: Option<String>,
    pub payload_ref: Option<String>,
    pub failures: i32,
}

/// What to enqueue.
#[derive(Clone, Debug)]
pub struct NewJob {
    pub kind: String,
    pub target: String,
    pub cache_key: String,
    pub attempt: i32,
    pub tier: Tier,
    pub payload: Option<String>,
    pub payload_ref: Option<String>,
    /// Hold it back until this many milliseconds from now. Zero is "as soon as a worker asks".
    pub delay: Duration,
    /// A machine that may not take this job, by its host id (`crate::host_id`): the one that made
    /// the first attempt, for a confirmation the gate would not count from it.
    ///
    /// Kept in a table of its own rather than as a column, so a queue made before it gains it from
    /// `migrate` like any other table and no existing table has a second version.
    pub avoid_host: Option<String>,
}

/// The key a first attempt is queued under: the target in canonical form, where it has one.
///
/// What an enqueuer knows is what it was asked for, and nothing a run has decided yet — the
/// strategy is inferred by the worker — so this names the request and is not a cache key
/// ([`Job::cache_key`] says why the two are kept apart). Canonical, so two spellings of one
/// package are one request; `trigon enqueue` and [`Queue::request_rebuild`] both key through here,
/// so a visitor's request and a sweep's entry for one package are one job.
pub fn request_key(target: &str) -> String {
    trigon_core::purl::canonicalize(target)
        .map(|c| c.as_str().to_string())
        .unwrap_or_else(|_| target.to_string())
}

/// A target's first attempt, found under its [`request_key`] or under the target as it was typed.
///
/// **Both, because a first attempt was keyed on the typed target before requests were canonical.**
/// `pkg:npm/@babel/core@7.24.0` was its own key, and its canonical form, with the scope's `@`
/// encoded, is another: looked up by the canonical key alone, a queue made before would answer
/// "no job" for a package it holds, and a request would queue, build and charge it a second time.
/// `$1` is the canonical key and `$2` the typed target; they are one string for most targets.
const FIRST_ATTEMPT: &str =
    "SELECT id, state FROM job WHERE cache_key IN ($1, $2) AND attempt = 1 ORDER BY id LIMIT 1";

impl NewJob {
    pub fn rebuild(target: impl Into<String>, cache_key: impl Into<String>, tier: Tier) -> Self {
        NewJob {
            kind: "rebuild".into(),
            target: target.into(),
            cache_key: cache_key.into(),
            attempt: 1,
            tier,
            payload: None,
            payload_ref: None,
            delay: Duration::ZERO,
            avoid_host: None,
        }
    }
}

/// The shared floor a fleet paces itself against.
///
/// `trigon-politeness` gives one node a cross-process limiter over a file lock. A fleet has no
/// shared filesystem, and the mirror runs inside a per-run container with no route to a database —
/// so the host process reads this before leasing and seeds each island at creation, accepting one
/// run of latency. That latency is the honest cost of the only carrier a fleet can have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostBudget {
    pub host: String,
    /// The next microsecond any worker may make a request to this host.
    pub next_at_us: i64,
    pub interval_ms: i64,
    /// How many times this host has answered 429. Not reset on success: the number that matters is
    /// how often we have been told to slow down, and a counter that forgets cannot tell anyone.
    pub throttled: i64,
}

/// A handle on the queue and the small tables beside it.
#[derive(Clone, Debug)]
pub struct Queue {
    pool: AnyPool,
    backend: Backend,
    clock: Clock,
}

/// Where the queue reads the time: the system clock, or one a test moves by hand.
///
/// **Every lease, visibility and host-budget decision is a comparison against this**, and the
/// other side of the comparison is a number in the database, so `tokio::time::pause` cannot reach
/// it. Two tests asserted a renewed lease and a shared throttle by racing the real clock, and each
/// failed once on a loaded machine that stalled past its margin while the queue behaved correctly.
/// A test that moves this clock itself asserts the same property with nothing left to the
/// scheduler. See [`Queue::with_clock`].
#[derive(Clone)]
struct Clock(Option<Arc<dyn Fn() -> i64 + Send + Sync>>);

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Some(_) => "Clock(given)",
            None => "Clock(system)",
        })
    }
}

impl Queue {
    /// Open a queue. `sqlite://…`, `sqlite::memory:`, or `postgres://…`.
    pub async fn open(url: &str) -> Result<Self, StoreError> {
        // Idempotent, and required before `AnyPool` knows how to speak either dialect. Calling it
        // here rather than asking every caller to remember: a driver registry that is a
        // precondition of the first connection is a precondition this type should keep.
        sqlx::any::install_default_drivers();
        let backend = if url.starts_with("postgres") {
            Backend::Postgres
        } else {
            Backend::Sqlite
        };
        let pool = AnyPoolOptions::new()
            // SQLite gives up on a busy database immediately unless told otherwise, and a queue is
            // by definition contended. WAL so a reader never blocks the writer; five seconds so a
            // lease behind another lease waits instead of failing. Both are no-ops on Postgres,
            // which declines an unknown pragma rather than erroring — so the statement is only sent
            // where it means something.
            .after_connect(|conn, _| {
                Box::pin(async move {
                    for p in ["PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000"] {
                        let _ = sqlx::query(p).execute(&mut *conn).await;
                    }
                    Ok(())
                })
            })
            // ADR-0005's third caveat. The cap is small on purpose and belongs in front of
            // pgbouncer in transaction mode: with a public API and N workers the connection count
            // becomes a function of site traffic, which is not what the caveat was written against.
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
            .map_err(|e| StoreError::Malformed(format!("opening the queue at {url}: {e}")))?;
        Ok(Queue {
            pool,
            backend,
            clock: Clock(None),
        })
    }

    /// This queue, reading the time from `now_ms` — milliseconds since the Unix epoch — instead of
    /// the system clock.
    ///
    /// For tests. A lease that lapses, a job held back and a host told to wait are all decided by
    /// the clock, and one the test moves decides them the same way however slowly the machine
    /// runs. Every handle cloned from this one reads the same clock; another handle opened on the
    /// same database does not, and the two would disagree about what has lapsed.
    pub fn with_clock(self, now_ms: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        Queue {
            clock: Clock(Some(Arc::new(now_ms))),
            ..self
        }
    }

    /// Now, in milliseconds since the Unix epoch, by this queue's clock.
    fn now_ms(&self) -> i64 {
        match &self.clock.0 {
            Some(now) => now(),
            None => system_now_ms(),
        }
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Create the tables if they are not there.
    ///
    /// Plain `CREATE TABLE IF NOT EXISTS`, not a migration framework: there is one version of this
    /// schema and adding a second is the moment to acquire the framework, not before.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let serial = match self.backend {
            Backend::Postgres => "BIGSERIAL PRIMARY KEY",
            Backend::Sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
        };
        for stmt in schema(serial) {
            sqlx::query(&stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Malformed(format!("creating the queue schema: {e}")))?;
        }
        Ok(())
    }

    /// Put a job on the queue.
    ///
    /// **Idempotent on `(cache_key, attempt)`**, which is what makes a retried HTTP request, a
    /// resumed sweep and a duplicated feed entry all produce one job. Returns the existing job's id
    /// when there was one, so a caller cannot tell a first enqueue from a repeat and does not have
    /// to.
    ///
    /// The host a job must avoid is written in the same transaction as the job: written after it,
    /// a job queued to run at once could be leased by that host in between.
    pub async fn enqueue(&self, j: &NewJob) -> Result<i64, StoreError> {
        let now = self.now_ms();
        let visible = now + j.delay.as_millis() as i64;
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO job (kind, target, cache_key, attempt, tier, payload, payload_ref, \
             state, visible_at, failures, created) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'ready', $8, 0, $9) \
             ON CONFLICT (cache_key, attempt) DO NOTHING",
        )
        .bind(&j.kind)
        .bind(&j.target)
        .bind(&j.cache_key)
        .bind(j.attempt)
        .bind(j.tier.as_str())
        .bind(j.payload.as_deref())
        .bind(j.payload_ref.as_deref())
        .bind(visible)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Malformed(format!("enqueueing: {e}")))?;

        let id = sqlx::query("SELECT id FROM job WHERE cache_key = $1 AND attempt = $2")
            .bind(&j.cache_key)
            .bind(j.attempt)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| StoreError::Malformed(format!("reading back the job: {e}")))?
            .get::<i64, _>("id");
        if let Some(host) = &j.avoid_host {
            sqlx::query("INSERT INTO job_avoid (job, host) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(id)
                .bind(host)
                .execute(&mut *tx)
                .await
                .map_err(|e| older_queue("recording the host a job avoids", e))?;
        }
        tx.commit()
            .await
            .map_err(|e| StoreError::Malformed(format!("committing a job: {e}")))?;
        Ok(id)
    }

    /// Take up to `n` jobs, by tier and then by age.
    ///
    /// **One statement, no transaction.** `UPDATE … WHERE id IN (SELECT … LIMIT n) RETURNING …` is
    /// atomic in both backends, and the Postgres form takes `FOR UPDATE SKIP LOCKED` in the
    /// subquery, which is the canonical shape. The first version opened a deferred transaction,
    /// selected, then updated — and two concurrent SQLite leases deadlocked on the upgrade with
    /// `database is locked`, because a deferred transaction that becomes a writer cannot wait. The
    /// test that found it is `one_job_goes_to_one_worker`, which is the property the whole queue
    /// exists for.
    ///
    /// **The lease is a timestamp, not a lock.** A worker that dies holds nothing: `leased_until`
    /// passes and the row is visible again to the next query, with no reaper process and nothing to
    /// notice the death. That is what makes a fleet of unreliable workers workable, and it is why
    /// `visible_at` and `leased_until` are two columns rather than one.
    ///
    /// A worker that names no machine: it takes a job whatever host the job avoids. The engine
    /// leases through [`Queue::lease_on`].
    pub async fn lease(
        &self,
        worker: &str,
        kinds: &[&str],
        n: i64,
        lease_for: Duration,
    ) -> Result<Vec<Job>, StoreError> {
        self.lease_on(worker, None, kinds, n, lease_for).await
    }

    /// [`Queue::lease`], by a worker on the machine `host` names, which takes no job that avoids
    /// that machine ([`NewJob::avoid_host`]).
    ///
    /// **Left on the queue, not taken and handed back.** A confirmation made on the machine that
    /// made the first attempt is one the gate does not count, unless the operator accepts one
    /// (`docs/19` D8); refusing it at the lease costs nothing, where leasing and declining it would
    /// be a lease and a release every poll for as long as no other machine asks. On a fleet of one
    /// machine such a job waits for good, which is what the gate would make of its answer.
    pub async fn lease_on(
        &self,
        worker: &str,
        host: Option<&str>,
        kinds: &[&str],
        n: i64,
        lease_for: Duration,
    ) -> Result<Vec<Job>, StoreError> {
        let now = self.now_ms();
        let until = now + lease_for.as_millis() as i64;
        let kind_list = kinds
            .iter()
            .map(|k| format!("'{}'", k.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "UPDATE job SET state = 'leased', leased_by = $1, leased_until = $2 \
             WHERE id IN ( \
               SELECT j.id FROM job j \
               WHERE j.kind IN ({kind_list}) \
                 AND j.visible_at <= {now} \
                 AND (j.state = 'ready' OR (j.state = 'leased' AND j.leased_until < {now})){} \
               ORDER BY \
                 CASE j.tier WHEN 'interactive' THEN 0 WHEN 'regression' THEN 1 ELSE 2 END, \
                 j.created, j.id \
               LIMIT {n}{}) \
             RETURNING id, kind, target, cache_key, attempt, tier, payload, payload_ref, failures",
            match host {
                Some(_) => {
                    " AND NOT EXISTS \
                     (SELECT 1 FROM job_avoid a WHERE a.job = j.id AND a.host = $3)"
                }
                None => "",
            },
            match self.backend {
                // The one clause that differs. Postgres skips rows another worker has locked;
                // SQLite has a single writer, so the statement itself is the exclusion.
                Backend::Postgres => " FOR UPDATE SKIP LOCKED",
                Backend::Sqlite => "",
            }
        );
        let mut query = sqlx::query(&sql).bind(worker).bind(until);
        if let Some(h) = host {
            query = query.bind(h);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| older_queue("leasing", e))?;

        // **`RETURNING` does not promise the subquery's order.** The `ORDER BY` above decides
        // *which* rows are taken; it says nothing about the order they come back in, and on SQLite
        // they came back by id — so a worker handed a batch would have built a bulk sweep job
        // before an interactive one it was holding at the same time. Ordering the batch here is
        // what makes the tier mean something all the way to the worker, rather than only to the
        // selection. Another instance of the shape this tree keeps finding: two things that had to
        // agree, with nothing asserting they did.
        let mut jobs: Vec<Job> = rows.iter().map(job_of).collect();
        jobs.sort_by_key(|j| (priority(j.tier), j.id));
        Ok(jobs)
    }

    /// Keep a lease alive, and say what phase the work is in.
    ///
    /// **Heartbeats and progress go to their own table**, which ADR-0005 asks for in as many words:
    /// a 45-minute build heartbeating onto the job row amplifies writes on exactly the row every
    /// lease query contends for. Only `leased_until` moves here, and only for the worker holding
    /// it — `false` means somebody else has the lease and this worker should stop.
    ///
    /// **And the phase is recorded only for the worker holding it.** A phase is a claim about where
    /// the job has got to, and a job whose lease lapsed and was taken is another worker's. The
    /// displaced one often keeps building, since its container cannot always be cancelled, and
    /// its phases used to land in the one stream a reader follows, between the holder's. So a
    /// displaced worker's heartbeat records nothing, and says so with `false`.
    ///
    /// A phase reached after the job has left `leased` — `recorded`, once [`Self::finish`] has
    /// claimed it — is not a heartbeat, and is written with [`Self::event`].
    pub async fn heartbeat(
        &self,
        job: i64,
        worker: &str,
        extend: Duration,
        phase: Option<&str>,
    ) -> Result<bool, StoreError> {
        let until = self.now_ms() + extend.as_millis() as i64;
        let n = sqlx::query(
            "UPDATE job SET leased_until = $1 WHERE id = $2 AND leased_by = $3 AND state = 'leased'",
        )
        .bind(until)
        .bind(job)
        .bind(worker)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("heartbeat: {e}")))?
        .rows_affected();
        if n == 0 {
            return Ok(false);
        }
        if let Some(p) = phase {
            self.event(job, p, None).await?;
        }
        Ok(true)
    }

    /// Record a phase or a note against a job. Read by the API's event stream.
    pub async fn event(
        &self,
        job: i64,
        phase: &str,
        detail: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO run_event (job, at, phase, detail) VALUES ($1, $2, $3, $4)")
            .bind(job)
            .bind(self.now_ms())
            .bind(phase)
            .bind(detail)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Malformed(format!("recording an event: {e}")))?;
        Ok(())
    }

    pub async fn events(&self, job: i64) -> Result<Vec<(i64, String, Option<String>)>, StoreError> {
        let rows =
            sqlx::query("SELECT at, phase, detail FROM run_event WHERE job = $1 ORDER BY at, id")
                .bind(job)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StoreError::Malformed(format!("reading events: {e}")))?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<i64, _>("at"),
                    r.get::<String, _>("phase"),
                    r.get::<Option<String>, _>("detail"),
                )
            })
            .collect())
    }

    /// The transactional outbox: the run is recorded and the job is finished, or neither happens.
    ///
    /// This is the reason the queue lives in this crate. Two statements in two systems cannot both
    /// happen, so a worker that records a run and then dies before acknowledging its job leaves the
    /// job to be leased again — and the second worker rebuilds a package that has already been
    /// rebuilt, charges for it, and may reach a different answer. One transaction is the only shape
    /// where that cannot happen.
    ///
    /// `record_ref` is the digest of the full [`RunRecord`] in blob storage, which the caller has
    /// already written: blobs are content-addressed and idempotent, so writing them outside the
    /// transaction is safe in a way writing the row would not be.
    /// Begin a transaction that is going to write, having read first.
    ///
    /// `Pool::begin()` issues `BEGIN DEFERRED` on SQLite. A deferred transaction takes a read lock
    /// on its first `SELECT` and tries to upgrade to a write lock on its first `INSERT`, and two of
    /// them that both read before writing deadlock on that upgrade. `PRAGMA busy_timeout` does not
    /// save it: SQLite returns `SQLITE_BUSY` *immediately* rather than waiting, because waiting
    /// cannot resolve it — the other transaction holds a read snapshot it would have to abandon,
    /// and neither side will.
    ///
    /// `BEGIN IMMEDIATE` takes the write lock at the start, so two callers serialize instead.
    ///
    /// **This is the same defect `lease` was already rewritten for once**, in this file, and it
    /// survived in the two functions that happen to `SELECT` first. How a transaction begins
    /// decides what it can do later, so there is now one place that decides it.
    async fn begin_write(&self) -> Result<sqlx::Transaction<'_, sqlx::Any>, StoreError> {
        let tx = match self.backend {
            Backend::Sqlite => self.pool.begin_with("BEGIN IMMEDIATE").await,
            // Postgres takes row locks as it goes and has no deferred-upgrade problem.
            Backend::Postgres => self.pool.begin().await,
        };
        tx.map_err(|e| StoreError::Malformed(format!("starting a transaction: {e}")))
    }

    pub async fn finish(
        &self,
        job: i64,
        worker: &str,
        record: &RunRecord,
        record_ref: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Malformed(format!("starting the outbox: {e}")))?;

        let claimed = sqlx::query(
            "UPDATE job SET state = 'done', leased_until = NULL \
             WHERE id = $1 AND leased_by = $2 AND state = 'leased'",
        )
        .bind(job)
        .bind(worker)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Malformed(format!("finishing a job: {e}")))?
        .rows_affected();
        if claimed == 0 {
            // The lease expired and somebody else holds it. Writing the run row anyway would let
            // two workers' answers race, and the loser's answer is the one that would survive.
            tx.rollback().await.ok();
            return Ok(false);
        }

        insert_run(&mut tx, record, record_ref).await?;
        tx.commit()
            .await
            .map_err(|e| StoreError::Malformed(format!("committing the outbox: {e}")))?;
        Ok(true)
    }

    /// Give a job back, with or without another attempt.
    ///
    /// `retry_in` absent means out of attempts: the row goes to `Dead` and stays. A dead job is the
    /// evidence that something is wrong, and a queue that deletes them is a queue that looks
    /// healthy while a whole ecosystem fails to build.
    pub async fn fail(
        &self,
        job: i64,
        worker: &str,
        why: &str,
        retry_in: Option<Duration>,
    ) -> Result<bool, StoreError> {
        let now = self.now_ms();
        let sql = match retry_in {
            Some(d) => format!(
                "UPDATE job SET state = 'ready', leased_by = NULL, leased_until = NULL, \
                 failures = failures + 1, last_error = $1, visible_at = {} \
                 WHERE id = $2 AND leased_by = $3",
                now + d.as_millis() as i64
            ),
            None => "UPDATE job SET state = 'dead', leased_by = NULL, leased_until = NULL, \
                     failures = failures + 1, last_error = $1 \
                     WHERE id = $2 AND leased_by = $3"
                .to_string(),
        };
        let n = sqlx::query(&sql)
            .bind(why)
            .bind(job)
            .bind(worker)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Malformed(format!("failing a job: {e}")))?
            .rows_affected();
        Ok(n > 0)
    }

    /// How many jobs are in each state, for a health page.
    pub async fn depth(&self) -> Result<Vec<(String, i64)>, StoreError> {
        let rows =
            sqlx::query("SELECT state, COUNT(*) AS n FROM job GROUP BY state ORDER BY state")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StoreError::Malformed(format!("measuring the queue: {e}")))?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<String, _>("state"), r.get::<i64, _>("n")))
            .collect())
    }

    /// Reserve the next slot against a host, fleet-wide.
    ///
    /// The same reservation `trigon-politeness` makes over a file lock, moved somewhere several
    /// machines can see. It **reserves** rather than asking "was the last request long ago": two
    /// workers asking at the same instant get two different answers, which is the whole difference
    /// between a rate limit and a race.
    pub async fn reserve_host(
        &self,
        host: &str,
        interval: Duration,
    ) -> Result<Duration, StoreError> {
        let interval_us = interval.as_micros() as i64;
        let now_us = self.now_ms() * 1000;
        let mut tx = self.begin_write().await?;

        let existing: Option<i64> =
            sqlx::query("SELECT next_at_us FROM host_budget WHERE host = $1")
                .bind(host)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| StoreError::Malformed(format!("reading a host budget: {e}")))?
                .map(|r| r.get::<i64, _>("next_at_us"));

        let slot = existing.unwrap_or(now_us).max(now_us);
        let next = slot + interval_us;
        // **Every placeholder appears once.** Reusing `$2` in the `DO UPDATE` clause read back as
        // a 4 ms interval where 50 ms was asked for — `sqlx`'s `Any` layer binds positionally, so a
        // repeated `$n` consumed a fresh slot and silently shifted every value after it. Repeating
        // the bind is the fix; `excluded.*` would also work and says less about which value is
        // which.
        sqlx::query(
            "INSERT INTO host_budget (host, next_at_us, interval_ms, throttled, updated) \
             VALUES ($1, $2, $3, 0, $4) \
             ON CONFLICT (host) DO UPDATE SET next_at_us = $5, interval_ms = $6, updated = $7",
        )
        .bind(host)
        .bind(next)
        .bind(interval.as_millis() as i64)
        .bind(self.now_ms())
        .bind(next)
        .bind(interval.as_millis() as i64)
        .bind(self.now_ms())
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Malformed(format!("writing a host budget: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| StoreError::Malformed(format!("committing a reservation: {e}")))?;

        Ok(Duration::from_micros((slot - now_us).max(0) as u64))
    }

    /// A host told us to slow down. Widen the interval for everybody, not just this worker.
    ///
    /// `Retry-After` is a statement about the host and not about the connection that received it,
    /// so it belongs where every worker can read it. Today the counter a mirror bumps dies with its
    /// container; this is where it stops doing that.
    pub async fn note_throttled(
        &self,
        host: &str,
        retry_after: Duration,
    ) -> Result<(), StoreError> {
        let until_us = (self.now_ms() + retry_after.as_millis() as i64) * 1000;
        sqlx::query(
            "INSERT INTO host_budget (host, next_at_us, interval_ms, throttled, updated) \
             VALUES ($1, $2, 1000, 1, $3) \
             ON CONFLICT (host) DO UPDATE SET \
               next_at_us = CASE WHEN host_budget.next_at_us > $4 THEN host_budget.next_at_us \
                                 ELSE $5 END, \
               throttled = host_budget.throttled + 1, \
               updated = $6",
        )
        .bind(host)
        .bind(until_us)
        .bind(self.now_ms())
        .bind(until_us)
        .bind(until_us)
        .bind(self.now_ms())
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("recording a throttle: {e}")))?;
        Ok(())
    }

    pub async fn host_budget(&self, host: &str) -> Result<Option<HostBudget>, StoreError> {
        let row = sqlx::query(
            "SELECT host, next_at_us, interval_ms, throttled FROM host_budget WHERE host = $1",
        )
        .bind(host)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("reading a host budget: {e}")))?;
        Ok(row.map(|r| HostBudget {
            host: r.get::<String, _>("host"),
            next_at_us: r.get::<i64, _>("next_at_us"),
            interval_ms: r.get::<i64, _>("interval_ms"),
            throttled: r.get::<i64, _>("throttled"),
        }))
    }

    /// Record a run outside the outbox, for a run that had no job.
    ///
    /// `trigon rebuild` on a laptop is not a queued job and still deserves a row. Separate from
    /// [`Self::finish`] so that nothing can mistake it for the transactional path: this one has no
    /// job to acknowledge and therefore nothing to be atomic *with*.
    pub async fn record(&self, record: &RunRecord, record_ref: &str) -> Result<(), StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Malformed(format!("recording a run: {e}")))?;
        insert_run(&mut tx, record, record_ref).await?;
        tx.commit()
            .await
            .map_err(|e| StoreError::Malformed(format!("committing a run: {e}")))?;
        Ok(())
    }
}

/// The run row: small scalars and one digest, never the record itself.
///
/// **A finished run is not moved back.** D7 in the threat model verifies that there is no lock of
/// any kind around a run record and disclaims the consequence rather than mitigating it. The
/// `WHERE` on `ON CONFLICT` is the one condition an update is held to: a row that is `done` takes
/// another `done` record and ignores a record of any earlier state, which is a stale copy arriving
/// late. Otherwise the last writer wins: `version` counts the updates a row took, and no caller
/// yet carries the version it read to compare, so D7 is narrowed rather than closed.
async fn insert_run(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    r: &RunRecord,
    record_ref: &str,
) -> Result<(), StoreError> {
    let ecosystem = r
        .target
        .strip_prefix("pkg:")
        .and_then(|s| s.split_once('/'))
        .map(|(e, _)| e)
        .unwrap_or("unknown");
    sqlx::query(
        "INSERT INTO run (id, target, ecosystem, state, outcome, terminal, fault, failure_code, \
         attempt, cache_key, record_ref, started, finished, version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1) \
         ON CONFLICT (id) DO UPDATE SET \
           state = $4, outcome = $5, terminal = $6, fault = $7, failure_code = $8, \
           record_ref = $11, finished = $13, version = run.version + 1 \
         WHERE NOT (run.state = 'done' AND excluded.state <> 'done')",
    )
    .bind(&r.id)
    .bind(&r.target)
    .bind(ecosystem)
    .bind(format!("{:?}", r.state).to_lowercase())
    // A string, never an ordinal, and no database ENUM — a Postgres enum orders by declaration
    // order, which is the six-rung ladder ADR-0002 exists to prevent, rebuilt in SQL.
    .bind(r.outcome.as_deref())
    .bind(r.terminal.as_deref())
    .bind(
        r.failure
            .as_ref()
            .map(|f| format!("{:?}", f.fault).to_lowercase()),
    )
    .bind(r.failure.as_ref().map(|f| f.code.to_string()))
    .bind(r.attempt as i32)
    .bind(r.cache_key.as_deref())
    .bind(record_ref)
    .bind(&r.started)
    .bind(r.finished.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(|e| StoreError::Malformed(format!("writing a run row: {e}")))?;
    Ok(())
}

fn job_of(r: &AnyRow) -> Job {
    Job {
        id: r.get::<i64, _>("id"),
        kind: r.get::<String, _>("kind"),
        target: r.get::<String, _>("target"),
        cache_key: r.get::<String, _>("cache_key"),
        attempt: r.get::<i32, _>("attempt"),
        tier: Tier::parse(&r.get::<String, _>("tier")),
        payload: r.get::<Option<String>, _>("payload"),
        payload_ref: r.get::<Option<String>, _>("payload_ref"),
        failures: r.get::<i32, _>("failures"),
    }
}

/// Tier order, as the query's `CASE` computes it. Named once so the batch a worker receives is
/// sorted by the same rule that chose it.
fn priority(t: Tier) -> u8 {
    match t {
        Tier::Interactive => 0,
        Tier::Regression => 1,
        Tier::Bulk => 2,
    }
}

/// A statement's error, saying what to run where the queue was made before a table it needs.
///
/// `job_avoid` came after the queue's first tables, and a queue made before it gains it only from
/// `migrate`. A worker started without `--migrate` against one failed every lease with "no such
/// table", which names what is missing and not what to do about it.
fn older_queue(doing: &str, e: sqlx::Error) -> StoreError {
    let e = e.to_string();
    if e.contains("job_avoid") {
        StoreError::Malformed(format!(
            "{doing}: {e}. This queue was made before the `job_avoid` table existed; run `trigon \
             worker --migrate` or `trigon enqueue --migrate` against it once to add the table"
        ))
    } else {
        StoreError::Malformed(format!("{doing}: {e}"))
    }
}

fn system_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Every statement, in order. Read by [`Queue::migrate`] and by the test that asserts the shape.
fn schema(serial: &str) -> Vec<String> {
    vec![
        format!(
            "CREATE TABLE IF NOT EXISTS job (
               id           {serial},
               kind         TEXT NOT NULL,
               target       TEXT NOT NULL,
               cache_key    TEXT NOT NULL,
               attempt      INTEGER NOT NULL DEFAULT 1,
               tier         TEXT NOT NULL,
               payload      TEXT,
               payload_ref  TEXT,
               state        TEXT NOT NULL DEFAULT 'ready',
               visible_at   BIGINT NOT NULL,
               leased_by    TEXT,
               leased_until BIGINT,
               failures     INTEGER NOT NULL DEFAULT 0,
               last_error   TEXT,
               created      BIGINT NOT NULL,
               UNIQUE (cache_key, attempt)
             )"
        ),
        // The index every lease query runs against. `visible_at` last, because the first two
        // columns are equality and range-scanning the third is what the index is for.
        "CREATE INDEX IF NOT EXISTS job_ready ON job (state, tier, visible_at)".into(),
        // The machines a job may not be leased on (`NewJob::avoid_host`). A table beside `job`
        // rather than a column on it: `CREATE TABLE IF NOT EXISTS` gives a queue made before it
        // the table, and would not have given it the column.
        "CREATE TABLE IF NOT EXISTS job_avoid (
           job  BIGINT NOT NULL,
           host TEXT NOT NULL,
           PRIMARY KEY (job, host)
         )"
        .into(),
        format!(
            "CREATE TABLE IF NOT EXISTS run_event (
               id     {serial},
               job    BIGINT NOT NULL,
               at     BIGINT NOT NULL,
               phase  TEXT NOT NULL,
               detail TEXT
             )"
        ),
        "CREATE INDEX IF NOT EXISTS run_event_job ON run_event (job, at)".into(),
        "CREATE TABLE IF NOT EXISTS host_budget (
           host        TEXT PRIMARY KEY,
           next_at_us  BIGINT NOT NULL,
           interval_ms BIGINT NOT NULL,
           throttled   BIGINT NOT NULL DEFAULT 0,
           updated     BIGINT NOT NULL
         )"
        .into(),
        // Pointers and small scalars. The record itself is a blob, named by `record_ref` and
        // re-hashed on every read; nothing signed is ever reassembled from these columns.
        //
        // No `failed` boolean, at any size: a package that did not reproduce and a build we could
        // not run are different findings, and one column merging them merges the two denominators
        // before any renderer sees them.
        "CREATE TABLE IF NOT EXISTS run (
           id           TEXT PRIMARY KEY,
           target       TEXT NOT NULL,
           ecosystem    TEXT NOT NULL,
           state        TEXT NOT NULL,
           outcome      TEXT,
           terminal     TEXT,
           fault        TEXT,
           failure_code TEXT,
           attempt      INTEGER NOT NULL,
           cache_key    TEXT,
           record_ref   TEXT NOT NULL,
           started      TEXT NOT NULL,
           finished     TEXT,
           version      INTEGER NOT NULL DEFAULT 1
         )"
        .into(),
        "CREATE INDEX IF NOT EXISTS run_browse ON run (finished)".into(),
        "CREATE INDEX IF NOT EXISTS run_target ON run (target)".into(),
        "CREATE INDEX IF NOT EXISTS run_key ON run (cache_key, outcome)".into(),
    ]
}

// ---------------------------------------------------------------------------
// Identity, quota, and the request button
// ---------------------------------------------------------------------------

/// Who asked. `docs/22-management-layer.md` §4.1: ten tables and not one recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub name: String,
    /// `request`, `review`, `operate`. A row, not a claim in a token: a scope that travels inside
    /// the credential is a scope that cannot be revoked without revoking the credential.
    pub scopes: Vec<String>,
    /// How many rebuilds this principal may ask for in a day.
    ///
    /// **A bound, not a report.** `20-m4-plan.md` §6: the budget should be enforced by the thing
    /// that admits work, which stops when it is exceeded, rather than checked afterwards in a
    /// report nobody reads until the block arrives.
    pub daily_quota: i64,
}

impl Principal {
    pub fn may(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// What happened to a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Requested {
    /// A new job. `job` is its id.
    Queued { job: i64, spent: i64, quota: i64 },
    /// This work was already on the queue, or already done. The request is idempotent, so a repeat
    /// costs the requester nothing and produces no second build.
    Already { job: i64, spent: i64, quota: i64 },
    /// Out of quota for today. Refused at admission rather than admitted and reported.
    OverQuota { spent: i64, quota: i64 },
}

impl Queue {
    /// Create the identity tables. Separate from [`Self::migrate`] so a fleet with no public
    /// surface does not carry tables nothing writes.
    pub async fn migrate_identity(&self) -> Result<(), StoreError> {
        let serial = match self.backend {
            Backend::Postgres => "BIGSERIAL PRIMARY KEY",
            Backend::Sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
        };
        for stmt in identity_schema(serial) {
            sqlx::query(&stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Malformed(format!("creating identity tables: {e}")))?;
        }
        Ok(())
    }

    /// Register a principal and mint a token for it.
    ///
    /// Returns the token **once**. Only its digest is stored, so a stolen database yields no
    /// credentials — the same reason the blob store holds digests rather than paths it trusts.
    pub async fn add_principal(
        &self,
        id: &str,
        name: &str,
        scopes: &[&str],
        daily_quota: i64,
        token: &str,
    ) -> Result<(), StoreError> {
        let now = self.now_ms();
        sqlx::query(
            "INSERT INTO principal (id, name, scopes, daily_quota, created) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO UPDATE SET name = $6, scopes = $7, daily_quota = $8",
        )
        .bind(id)
        .bind(name)
        .bind(scopes.join(","))
        .bind(daily_quota)
        .bind(now)
        .bind(name)
        .bind(scopes.join(","))
        .bind(daily_quota)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("adding a principal: {e}")))?;

        sqlx::query(
            "INSERT INTO api_token (hash, principal, created) VALUES ($1, $2, $3) \
             ON CONFLICT (hash) DO NOTHING",
        )
        .bind(token_hash(token))
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("adding a token: {e}")))?;
        Ok(())
    }

    /// Who is this token? `None` for an unknown one, which is also what a revoked one gives.
    pub async fn principal_for(&self, token: &str) -> Result<Option<Principal>, StoreError> {
        let row = sqlx::query(
            "SELECT p.id, p.name, p.scopes, p.daily_quota FROM api_token t \
             JOIN principal p ON p.id = t.principal WHERE t.hash = $1",
        )
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("resolving a token: {e}")))?;
        Ok(row.map(|r| Principal {
            id: r.get::<String, _>("id"),
            name: r.get::<String, _>("name"),
            scopes: r
                .get::<String, _>("scopes")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            daily_quota: r.get::<i64, _>("daily_quota"),
        }))
    }

    /// Ask for a rebuild, and charge it — **in one transaction**.
    ///
    /// `docs/22-management-layer.md` §5.2 and `20-m4-plan.md` §6 both insist on this shape and it is
    /// the whole reason identity lives in the same database as the queue. A rate limiter in front
    /// of the API is a different process reading a different number, and the gap between the check
    /// and the insert is exactly where a burst of clicks gets through. Counting and inserting in one
    /// transaction has no such gap.
    ///
    /// Idempotent on the target, so a repeat costs the requester nothing and produces no second
    /// build: somebody clicking twice should get their answer, not two builds of it.
    pub async fn request_rebuild(
        &self,
        who: &Principal,
        target: &str,
        day: &str,
    ) -> Result<Requested, StoreError> {
        let now = self.now_ms();
        let mut tx = self.begin_write().await?;

        let spent: i64 =
            sqlx::query("SELECT COUNT(*) AS n FROM request WHERE principal = $1 AND day = $2")
                .bind(&who.id)
                .bind(day)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| StoreError::Malformed(format!("counting requests: {e}")))?
                .get::<i64, _>("n");

        // Already queued or already answered: not a new request, not charged, not a second build.
        let key = request_key(target);
        let existing: Option<i64> = sqlx::query(FIRST_ATTEMPT)
            .bind(&key)
            .bind(target)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StoreError::Malformed(format!("looking for the job: {e}")))?
            .map(|r| r.get::<i64, _>("id"));
        if let Some(job) = existing {
            tx.commit()
                .await
                .map_err(|e| StoreError::Malformed(format!("committing: {e}")))?;
            return Ok(Requested::Already {
                job,
                spent,
                quota: who.daily_quota,
            });
        }

        if spent >= who.daily_quota {
            tx.rollback().await.ok();
            return Ok(Requested::OverQuota {
                spent,
                quota: who.daily_quota,
            });
        }

        sqlx::query(
            "INSERT INTO job (kind, target, cache_key, attempt, tier, state, visible_at, \
             failures, created) VALUES ('rebuild', $1, $2, 1, 'interactive', 'ready', $3, 0, $4)",
        )
        .bind(target)
        .bind(&key)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Malformed(format!("enqueueing a request: {e}")))?;

        let job = sqlx::query("SELECT id FROM job WHERE cache_key = $1 AND attempt = 1")
            .bind(&key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| StoreError::Malformed(format!("reading back the job: {e}")))?
            .get::<i64, _>("id");

        sqlx::query(
            "INSERT INTO request (principal, target, job, day, created) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&who.id)
        .bind(target)
        .bind(job)
        .bind(day)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Malformed(format!("charging the request: {e}")))?;

        // Append-only, and in the same transaction: an action that happened without an audit row
        // is an action nobody can account for later.
        sqlx::query("INSERT INTO audit (at, principal, action, detail) VALUES ($1, $2, $3, $4)")
            .bind(now)
            .bind(&who.id)
            .bind("request_rebuild")
            .bind(target)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Malformed(format!("writing the audit row: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Malformed(format!("committing a request: {e}")))?;
        Ok(Requested::Queued {
            job,
            spent: spent + 1,
            quota: who.daily_quota,
        })
    }

    /// What is on the queue right now, for a status page.
    /// Which workers hold leases right now, and how stale each one's is.
    ///
    /// The fleet-health question is not "how many workers are configured" — nothing knows that —
    /// but "which processes are currently holding work, and is any of them about to lose it". A
    /// worker whose lease is nearly expired is either very slow or dead, and the two look
    /// identical from here until it renews.
    ///
    /// Returns `(worker, jobs_held, earliest_lease_expiry_ms)`.
    pub async fn workers(&self) -> Result<Vec<(String, i64, i64)>, StoreError> {
        let rows = sqlx::query(
            "SELECT leased_by, COUNT(*) AS n, MIN(leased_until) AS soonest FROM job \
             WHERE state = 'leased' AND leased_by IS NOT NULL \
             GROUP BY leased_by ORDER BY leased_by",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("reading workers: {e}")))?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("leased_by"),
                    r.get::<i64, _>("n"),
                    r.get::<i64, _>("soonest"),
                )
            })
            .collect())
    }

    pub async fn in_flight(
        &self,
        limit: i64,
    ) -> Result<Vec<(i64, String, String, i32)>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT id, target, state, attempt FROM job \
             WHERE state IN ('ready', 'leased') \
             ORDER BY CASE tier WHEN 'interactive' THEN 0 WHEN 'regression' THEN 1 ELSE 2 END, \
                      created \
             LIMIT {limit}"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("reading the queue: {e}")))?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<i64, _>("id"),
                    r.get::<String, _>("target"),
                    r.get::<String, _>("state"),
                    r.get::<i32, _>("attempt"),
                )
            })
            .collect())
    }

    /// The job covering a target, if any, with its state: its first attempt, keyed as
    /// [`request_key`] keys one, or as the target was typed before requests were canonical.
    pub async fn job_for(&self, target: &str) -> Result<Option<(i64, String)>, StoreError> {
        let row = sqlx::query(FIRST_ATTEMPT)
            .bind(request_key(target))
            .bind(target)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Malformed(format!("finding a job: {e}")))?;
        Ok(row.map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("state"))))
    }
}

/// A token's digest, which is all that is ever stored.
fn token_hash(token: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    format!("{:x}", h.finalize())
}

fn identity_schema(serial: &str) -> Vec<String> {
    vec![
        "CREATE TABLE IF NOT EXISTS principal (
           id          TEXT PRIMARY KEY,
           name        TEXT NOT NULL,
           scopes      TEXT NOT NULL,
           daily_quota BIGINT NOT NULL,
           created     BIGINT NOT NULL
         )"
        .into(),
        // Only the digest. A stolen database yields no credentials.
        "CREATE TABLE IF NOT EXISTS api_token (
           hash      TEXT PRIMARY KEY,
           principal TEXT NOT NULL,
           created   BIGINT NOT NULL,
           last_used BIGINT
         )"
        .into(),
        format!(
            "CREATE TABLE IF NOT EXISTS request (
               id        {serial},
               principal TEXT NOT NULL,
               target    TEXT NOT NULL,
               job       BIGINT,
               day       TEXT NOT NULL,
               created   BIGINT NOT NULL
             )"
        ),
        "CREATE INDEX IF NOT EXISTS request_quota ON request (principal, day)".into(),
        // Append-only. Nothing in this module updates or deletes a row here.
        format!(
            "CREATE TABLE IF NOT EXISTS audit (
               id        {serial},
               at        BIGINT NOT NULL,
               principal TEXT NOT NULL,
               action    TEXT NOT NULL,
               detail    TEXT
             )"
        ),
    ]
}
