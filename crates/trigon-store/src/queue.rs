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
//! `FOR UPDATE SKIP LOCKED`; SQLite has one writer, so it leases inside `BEGIN IMMEDIATE` and needs
//! no such clause. Every other statement is one string used by both. [ADR-0008] is about one
//! *owner* per seam, and the owner is this module.
//!
//! [ADR-0005]: ../../../docs/adr/0005-own-the-queue.md
//! [ADR-0008]: ../../../docs/adr/0008-one-implementation-per-seam.md

use crate::{RunRecord, StoreError};
use serde::{Deserialize, Serialize};
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row as _};
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
    /// What makes two attempts attempts at the *same thing*. See [`RunRecord::cache_key`].
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
}

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
            // ADR-0005's third caveat. The cap is small on purpose and belongs in front of
            // pgbouncer in transaction mode: with a public API and N workers the connection count
            // becomes a function of site traffic, which is not what the caveat was written against.
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
            .map_err(|e| StoreError::Malformed(format!("opening the queue at {url}: {e}")))?;
        Ok(Queue { pool, backend })
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
    pub async fn enqueue(&self, j: &NewJob) -> Result<i64, StoreError> {
        let now = now_ms();
        let visible = now + j.delay.as_millis() as i64;
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
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Malformed(format!("enqueueing: {e}")))?;

        let row = sqlx::query("SELECT id FROM job WHERE cache_key = $1 AND attempt = $2")
            .bind(&j.cache_key)
            .bind(j.attempt)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StoreError::Malformed(format!("reading back the job: {e}")))?;
        Ok(row.get::<i64, _>("id"))
    }

    /// Take up to `n` jobs, by tier and then by age.
    ///
    /// **The lease is a timestamp, not a lock.** A worker that dies holds nothing: `leased_until`
    /// passes and the row is `Ready` again to the next query, with no reaper process and nothing to
    /// notice the death. That is the property that makes a fleet of unreliable workers workable,
    /// and it is why `visible_at` and `leased_until` are two columns rather than one.
    pub async fn lease(
        &self,
        worker: &str,
        kinds: &[&str],
        n: i64,
        lease_for: Duration,
    ) -> Result<Vec<Job>, StoreError> {
        let now = now_ms();
        let until = now + lease_for.as_millis() as i64;
        let kind_list = kinds
            .iter()
            .map(|k| format!("'{}'", k.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        // The one place the two backends differ. Postgres skips rows another worker has locked;
        // SQLite has a single writer, so the transaction *is* the exclusion.
        let pick = format!(
            "SELECT id FROM job \
             WHERE kind IN ({kind_list}) \
               AND visible_at <= {now} \
               AND (state = 'ready' OR (state = 'leased' AND leased_until < {now})) \
             ORDER BY CASE tier WHEN 'interactive' THEN 0 WHEN 'regression' THEN 1 ELSE 2 END, \
                      created \
             LIMIT {n}{}",
            match self.backend {
                Backend::Postgres => " FOR UPDATE SKIP LOCKED",
                Backend::Sqlite => "",
            }
        );

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Malformed(format!("starting a lease: {e}")))?;
        let ids: Vec<i64> = sqlx::query(&pick)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| StoreError::Malformed(format!("picking jobs: {e}")))?
            .into_iter()
            .map(|r| r.get::<i64, _>("id"))
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let in_list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!(
            "UPDATE job SET state = 'leased', leased_by = $1, leased_until = $2 \
             WHERE id IN ({in_list})"
        ))
        .bind(worker)
        .bind(until)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Malformed(format!("taking the lease: {e}")))?;

        let rows = sqlx::query(&format!(
            "SELECT id, kind, target, cache_key, attempt, tier, payload, payload_ref, failures \
             FROM job WHERE id IN ({in_list})"
        ))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| StoreError::Malformed(format!("reading leased jobs: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| StoreError::Malformed(format!("committing a lease: {e}")))?;
        Ok(rows.iter().map(job_of).collect())
    }

    /// Keep a lease alive, and say what phase the work is in.
    ///
    /// **Heartbeats and progress go to their own table**, which ADR-0005 asks for in as many words:
    /// a 45-minute build heartbeating onto the job row amplifies writes on exactly the row every
    /// lease query contends for. Only `leased_until` moves here, and only for the worker holding
    /// it — `false` means somebody else has the lease and this worker should stop.
    pub async fn heartbeat(
        &self,
        job: i64,
        worker: &str,
        extend: Duration,
        phase: Option<&str>,
    ) -> Result<bool, StoreError> {
        let until = now_ms() + extend.as_millis() as i64;
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
        if let Some(p) = phase {
            self.event(job, p, None).await?;
        }
        Ok(n > 0)
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
            .bind(now_ms())
            .bind(phase)
            .bind(detail)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Malformed(format!("recording an event: {e}")))?;
        Ok(())
    }

    pub async fn events(&self, job: i64) -> Result<Vec<(i64, String, Option<String>)>, StoreError> {
        let rows = sqlx::query(
            "SELECT at, phase, detail FROM run_event WHERE job = $1 ORDER BY at, id",
        )
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
        let now = now_ms();
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
        let rows = sqlx::query("SELECT state, COUNT(*) AS n FROM job GROUP BY state ORDER BY state")
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
        let now_us = now_ms() * 1000;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Malformed(format!("reserving a slot: {e}")))?;

        let existing: Option<i64> = sqlx::query("SELECT next_at_us FROM host_budget WHERE host = $1")
            .bind(host)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StoreError::Malformed(format!("reading a host budget: {e}")))?
            .map(|r| r.get::<i64, _>("next_at_us"));

        let slot = existing.unwrap_or(now_us).max(now_us);
        let next = slot + interval_us;
        sqlx::query(
            "INSERT INTO host_budget (host, next_at_us, interval_ms, throttled, updated) \
             VALUES ($1, $2, $3, 0, $4) \
             ON CONFLICT (host) DO UPDATE SET next_at_us = $2, interval_ms = $3, updated = $4",
        )
        .bind(host)
        .bind(next)
        .bind(interval.as_millis() as i64)
        .bind(now_ms())
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
        let until_us = (now_ms() + retry_after.as_millis() as i64) * 1000;
        sqlx::query(
            "INSERT INTO host_budget (host, next_at_us, interval_ms, throttled, updated) \
             VALUES ($1, $2, 1000, 1, $3) \
             ON CONFLICT (host) DO UPDATE SET \
               next_at_us = CASE WHEN host_budget.next_at_us > $2 THEN host_budget.next_at_us \
                                 ELSE $2 END, \
               throttled = host_budget.throttled + 1, \
               updated = $3",
        )
        .bind(host)
        .bind(until_us)
        .bind(now_ms())
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
/// **Row version, not last-writer-wins.** D7 in the threat model verifies that there is no lock of
/// any kind around a run record and disclaims the consequence rather than mitigating it. Here the
/// row is where exclusion lives: an update carries the version it read and loses if somebody else
/// has moved on. `ON CONFLICT` keeps a re-record idempotent while refusing to move a run backwards.
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
           record_ref = $11, finished = $13, version = run.version + 1",
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

fn now_ms() -> i64 {
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
