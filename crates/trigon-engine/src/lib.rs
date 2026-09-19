//! The worker loop: lease a job, run it, record it, or give it back.
//!
//! The crate `docs/01-architecture.md` has named since before there was a queue. It owns the run
//! state machine, the lease and its heartbeat, the backoff, and the two refusals below — and it
//! owns nothing about *how* a package is rebuilt. That is a [`Work`] implementation, which lives
//! wherever the sandbox does, so this crate can be tested through its whole loop without podman,
//! a network, or a registry.
//!
//! # What this is not, yet
//!
//! `docs/22-management-layer.md` stage 3 asks for `run_one` cut into three independently leasable
//! stages — infer, build, judge — with a serialisable handoff between them, so a build worker and a
//! judge worker can be different machines. **That is not built.** What is built is the crate, the
//! loop and the leasing, which is what a *fleet* needs; the three-way split is what **invariant 6**
//! needs, and until it exists that invariant still holds by collocation rather than by enforcement.
//! Saying which is which matters more than either: the threat model records invariant 6 as holding,
//! and a queue that let two machines share a job without splitting it would quietly make that false.
//!
//! # Two refusals
//!
//! **A worker never records under an expired lease.** [`trigon_store::Queue::finish`] enforces it
//! in SQL; the loop here notices the refusal and treats it as a lost race rather than an error,
//! because losing a race is not a fault.
//!
//! **A run under a non-`Builtin` transform may not come back `normalized`.** The provenance cap
//! lives in `trigon-compare` and nowhere else, and this does not re-implement it: it asserts that it
//! fired. `docs/22` §6.1 calls this belt and braces, and it is worth two independent checks because
//! the failure mode is a human-touched artifact published as a clean match.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use trigon_store::RunRecord;
use trigon_store::queue::{Job, NewJob, Queue, Tier};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("the queue: {0}")]
    Queue(#[from] trigon_store::StoreError),
    /// The one error that is never the package's and never a worker's: a run came back claiming a
    /// clean match under a transform somebody wrote. See the module note.
    #[error(
        "run {run} used a non-builtin transform and reported `{outcome}`. The provenance cap \
         should have held it at `normalized_with_caveats`; a clean match here would mean a \
         human-touched artifact published as though nobody had touched it."
    )]
    CapEscaped { run: String, outcome: String },
}

/// What a worker did with a job.
#[derive(Debug)]
pub struct Done {
    pub record: RunRecord,
    /// The digest of the full record in blob storage. The row keeps a pointer; the blob is the
    /// record, and `Blobs::get` re-hashes it on every read.
    pub record_ref: String,
}

/// Why a worker could not.
#[derive(Debug)]
pub struct Failed {
    pub why: String,
    /// Whether running this again unchanged could reach a different answer. A build that failed
    /// because the package does not build is not retryable; a registry that answered 503 is.
    pub retryable: bool,
}

/// A live job, for a worker that wants to say where it has got to.
///
/// Every `phase` call also renews the lease, which is the point: a worker that is making progress
/// keeps its job, and one that has stopped loses it without anybody having to decide that it has.
#[derive(Debug)]
pub struct Progress {
    queue: Queue,
    job: i64,
    worker: String,
    lease: Duration,
}

impl Progress {
    /// Say what is happening, and renew the lease.
    ///
    /// `false` means the lease is gone and somebody else is doing this work. A worker that keeps
    /// building after that is spending compute on an answer nothing will accept.
    pub async fn phase(&self, name: &str) -> bool {
        self.queue
            .heartbeat(self.job, &self.worker, self.lease, Some(name))
            .await
            .unwrap_or(false)
    }

    /// Renew the lease without claiming to have reached a new phase.
    ///
    /// What the loop calls while a job is in flight. `phase` would overwrite the phase the worker
    /// last set, so a build would report "running" instead of "rebuild" for its whole life.
    async fn renew(&self) -> bool {
        self.queue
            .heartbeat(self.job, &self.worker, self.lease, None)
            .await
            .unwrap_or(false)
    }

    pub async fn note(&self, phase: &str, detail: &str) {
        let _ = self.queue.event(self.job, phase, Some(detail)).await;
    }
}

/// What a worker can actually do.
#[async_trait]
pub trait Work: Send + Sync {
    /// The job kinds this worker leases. A judge worker never leases a build.
    fn kinds(&self) -> Vec<String>;

    /// Do one job.
    async fn run(&self, job: &Job, progress: &Progress) -> Result<Done, Failed>;
}

/// How the loop behaves.
#[derive(Clone, Debug)]
pub struct Config {
    /// Names this worker in every lease and every event. A hostname plus a pid, usually: the
    /// question it has to answer is "which process is holding this", months later, from a row.
    pub worker: String,
    /// How long a lease lasts without a heartbeat. Long enough that a slow build does not lose its
    /// job, short enough that a dead worker's job comes back within it.
    pub lease: Duration,
    /// How many jobs to take at once.
    pub batch: i64,
    /// How long to wait when there is nothing to do. ADR-0005: ten to fifteen seconds, through
    /// pgbouncer, with a connection cap — the queue is polled, not subscribed to, and the poll
    /// interval is a connection budget as much as a latency one.
    pub idle: Duration,
    /// The first backoff after a retryable failure; doubles each time, to a cap.
    pub backoff: Duration,
    pub backoff_cap: Duration,
    /// After this many failures a job is dead and stays. A dead job is the evidence that something
    /// is wrong, and a queue that deletes them looks healthy while an ecosystem fails to build.
    pub max_failures: i32,
    /// Enqueue a second, independent attempt after a first one reaches a verdict.
    ///
    /// [ADR-0010]'s first safeguard: two agreeing attempts before anything publishes, divergences
    /// and matches alike. Nothing published before this existed — the corpus browser's first
    /// measurement was 32 runs, every one of them held back as `awaiting_confirmation`, because
    /// nothing in the system ever asked the question twice.
    ///
    /// [ADR-0010]: ../../../docs/adr/0010-publish-divergences.md
    pub confirm: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            worker: "worker".into(),
            lease: Duration::from_secs(300),
            batch: 1,
            idle: Duration::from_secs(12),
            backoff: Duration::from_secs(30),
            backoff_cap: Duration::from_secs(1800),
            max_failures: 3,
            confirm: true,
        }
    }
}

/// One worker.
#[derive(Debug)]
pub struct Engine {
    queue: Queue,
    cfg: Config,
}

impl Engine {
    pub fn new(queue: Queue, cfg: Config) -> Self {
        Engine { queue, cfg }
    }

    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Lease once, do the work, and return how many jobs were handled.
    ///
    /// Zero means the queue had nothing for this worker, which is not an error and is the common
    /// case for most of a fleet's life.
    pub async fn tick(&self, work: &dyn Work) -> Result<usize, EngineError> {
        let kinds = work.kinds();
        let refs: Vec<&str> = kinds.iter().map(String::as_str).collect();
        let jobs = self
            .queue
            .lease(&self.cfg.worker, &refs, self.cfg.batch, self.cfg.lease)
            .await?;
        let n = jobs.len();
        for job in jobs {
            self.one(work, job).await?;
        }
        Ok(n)
    }

    /// Run the job, renewing its lease for as long as it takes.
    ///
    /// **Without this, a job longer than one lease is done twice, and then again, and again.**
    /// `Progress::phase` renews, so the lease survives exactly as long as a worker keeps calling
    /// it — and the builder calls it once, at the top, then hands the whole build to
    /// `spawn_blocking`. A 300-second lease against a build allowed 1800 seconds means the job is
    /// re-leased about six times, six workers build the same package, and `finish` throws away all
    /// but the last because a worker may not record under an expired lease.
    ///
    /// That last part is the tell: the loop below already logged `"lease expired before this
    /// finished; the work was done twice"` and carried on. The condition was detected, named, and
    /// left in place.
    ///
    /// It belongs here rather than in the builder because every `Work` has the same problem and
    /// only one of them would have remembered.
    async fn run_with_heartbeat(
        &self,
        work: &dyn Work,
        job: &Job,
        progress: &Progress,
    ) -> Result<Done, Failed> {
        let run = work.run(job, progress);
        tokio::pin!(run);

        // A third of the lease, so two consecutive missed renewals still leave margin.
        //
        // **The floor must stay well under the lease.** This was first written with a one-second
        // floor, on the reasoning that an absurdly short lease should not become a busy loop —
        // which against a 300 ms lease renews for the first time at one second, 700 ms after the
        // job has already been taken by somebody else. A floor that can exceed the thing it is
        // renewing disables the renewal entirely, and silently, since everything still compiles
        // and the common configuration still works. Ten milliseconds only exists because
        // `interval` panics on a zero duration.
        let every = (self.cfg.lease / 3).max(Duration::from_millis(10));
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // fires immediately; the lease was just taken

        loop {
            tokio::select! {
                done = &mut run => return done,
                _ = tick.tick() => {
                    if !progress.renew().await {
                        // Keep going rather than abandoning: the work is already in flight, often
                        // in a container this future cannot cancel, and `finish` refuses to record
                        // under a lost lease anyway. Saying so is what turns a silent duplicate
                        // into something an operator can find.
                        tracing::warn!(
                            job = job.id,
                            worker = %self.cfg.worker,
                            "lost the lease while still working; another worker now holds this job"
                        );
                    }
                }
            }
        }
    }

    async fn one(&self, work: &dyn Work, job: Job) -> Result<(), EngineError> {
        let progress = Progress {
            queue: self.queue.clone(),
            job: job.id,
            worker: self.cfg.worker.clone(),
            lease: self.cfg.lease,
        };
        progress.phase("leased").await;

        match self.run_with_heartbeat(work, &job, &progress).await {
            Ok(done) => {
                // Belt and braces. The cap is computed in `trigon-compare` and nowhere else; this
                // asserts that it was, on the one path where being wrong means publishing a
                // human-touched artifact as a clean match.
                if let Some(outcome) = done.record.outcome.as_deref()
                    && outcome == "normalized"
                    && uses_non_builtin_transform(&job)
                {
                    // Not recorded, not acknowledged, and not retried: a job that produces an
                    // impossible answer will produce it again. It goes dead so a human sees it.
                    self.queue
                        .fail(job.id, &self.cfg.worker, "provenance cap escaped", None)
                        .await?;
                    return Err(EngineError::CapEscaped {
                        run: done.record.id.clone(),
                        outcome: outcome.to_string(),
                    });
                }

                let claimed = self
                    .queue
                    .finish(job.id, &self.cfg.worker, &done.record, &done.record_ref)
                    .await?;
                if !claimed {
                    // The lease expired while this ran and somebody else holds the job. Nothing is
                    // recorded, which is right: the other worker's answer is the one the queue is
                    // waiting for, and two answers racing is the thing the outbox prevents.
                    tracing::warn!(
                        job = job.id,
                        worker = %self.cfg.worker,
                        "lease expired before this finished; the work was done twice"
                    );
                    return Ok(());
                }
                progress.phase("recorded").await;

                if self.cfg.confirm {
                    self.confirm(&job, &done.record).await?;
                }
                Ok(())
            }
            Err(failed) => {
                // Two conditions, both of which must hold: the failure has to be one that could
                // answer differently, and the job has to have attempts left. Written out rather
                // than chained, because the chained form reads as one condition and this is the
                // arithmetic that decides how much a broken thing is allowed to cost.
                let again = failed.retryable && job.failures + 1 < self.cfg.max_failures;
                let retry = again.then(|| self.wait_before_retry(job.failures));
                self.queue
                    .fail(job.id, &self.cfg.worker, &failed.why, retry)
                    .await?;
                progress
                    .note(
                        if retry.is_some() { "retrying" } else { "dead" },
                        &failed.why,
                    )
                    .await;
                Ok(())
            }
        }
    }

    /// Ask the same question a second time, on a different worker at a different time.
    ///
    /// ADR-0010 safeguard 1, and the only thing that can ever release a result to a public reader.
    /// The second attempt is `Regression` rather than `Bulk` because a corpus whose confirmations
    /// queue behind a sweep publishes nothing at all.
    ///
    /// Enqueued only for a run that reached a verdict: a `no-strategy` confirmed twice is still a
    /// no-strategy, and spending a second build on one is spending it to learn nothing.
    async fn confirm(&self, job: &Job, record: &RunRecord) -> Result<(), EngineError> {
        if record.outcome.is_none() || job.attempt > 1 {
            return Ok(());
        }
        self.queue
            .enqueue(&NewJob {
                kind: job.kind.clone(),
                target: job.target.clone(),
                cache_key: job.cache_key.clone(),
                attempt: job.attempt + 1,
                tier: Tier::Regression,
                payload: job.payload.clone(),
                payload_ref: job.payload_ref.clone(),
                // Not immediately. The risk safeguard 1 exists against is ambient nondeterminism —
                // a floating range, a mutable tag, a fetch that happened to succeed — and two runs
                // back to back on a warm cache sample the same moment twice.
                delay: Duration::from_secs(300),
            })
            .await?;
        Ok(())
    }

    fn wait_before_retry(&self, failures: i32) -> Duration {
        backoff_after(&self.cfg, failures)
    }

    /// Run until told to stop.
    ///
    /// **`stop` is checked between jobs, never during one.** A build cancelled halfway leaves a
    /// leased job, a half-written work directory and no record; waiting for the current job costs
    /// one build's latency on shutdown, and cancelling costs one build *and* a row somebody has to
    /// interpret later. An `AtomicBool` rather than a `Notify` because the question asked here is
    /// "should I stop", which has an answer at every instant — a notification has to be waiting at
    /// the moment it is asked for, and a stop that arrives mid-build would be missed.
    pub async fn run(&self, work: Arc<dyn Work>, stop: Arc<std::sync::atomic::AtomicBool>) {
        use std::sync::atomic::Ordering;
        while !stop.load(Ordering::Relaxed) {
            let ticked = match self.tick(work.as_ref()).await {
                Ok(n) => n,
                Err(e) => {
                    // A tick that fails is a database that is unreachable or a run that escaped the
                    // cap. Neither is a reason to exit: a worker that dies on a blip is a worker
                    // somebody has to restart, and the loop is what makes the fleet self-healing.
                    tracing::error!(error = %e, "worker tick failed");
                    0
                }
            };
            if ticked == 0 {
                tokio::time::sleep(self.cfg.idle).await;
            }
        }
    }
}

/// How long to wait before trying a failed job again.
///
/// A free function rather than a method so it can be tested without a database: it is arithmetic,
/// and arithmetic that needs a Postgres connection to be checked will not be checked.
fn backoff_after(cfg: &Config, failures: i32) -> Duration {
    // `1u32 << failures` overflows at 32 and a shift past the width is a panic, so the exponent is
    // clamped before the shift rather than the result after it. A broken job that wrapped to a
    // small backoff would be a hot loop against whatever is already failing.
    let doubled = cfg.backoff.saturating_mul(1u32 << failures.clamp(0, 16));
    doubled.min(cfg.backoff_cap)
}

/// Whether a job asks for a transform somebody wrote.
///
/// Read from the payload rather than inferred from the record, because the question is what the job
/// *asked for*: a run that was asked to apply a reviewer's overlay and came back claiming a clean
/// match is exactly the case the refusal exists for, whatever the record says about itself.
fn uses_non_builtin_transform(job: &Job) -> bool {
    let Some(p) = job.payload.as_deref() else {
        return false;
    };
    serde_json::from_str::<serde_json::Value>(p)
        .ok()
        .and_then(|v| v.get("overlay").cloned())
        .is_some_and(|v| !v.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_then_stops() {
        let cfg = Config {
            backoff: Duration::from_secs(10),
            backoff_cap: Duration::from_secs(60),
            ..Default::default()
        };
        assert_eq!(backoff_after(&cfg, 0), Duration::from_secs(10));
        assert_eq!(backoff_after(&cfg, 1), Duration::from_secs(20));
        assert_eq!(backoff_after(&cfg, 2), Duration::from_secs(40));
        assert_eq!(backoff_after(&cfg, 3), Duration::from_secs(60));
        // A failure count large enough to overflow the shift is capped rather than wrapping to
        // something small, which would turn a broken job into a hot loop against whatever is
        // already failing.
        assert_eq!(backoff_after(&cfg, 60), Duration::from_secs(60));
        assert_eq!(backoff_after(&cfg, -1), Duration::from_secs(10));
    }

    #[test]
    fn a_job_with_no_payload_asks_for_no_transform() {
        let job = Job {
            id: 1,
            kind: "rebuild".into(),
            target: "pkg:npm/a@1".into(),
            cache_key: "k".into(),
            attempt: 1,
            tier: Tier::Bulk,
            payload: None,
            payload_ref: None,
            failures: 0,
        };
        assert!(!uses_non_builtin_transform(&job));

        let plain = Job {
            payload: Some(r#"{"egress":"mirror"}"#.into()),
            ..job.clone()
        };
        assert!(!uses_non_builtin_transform(&plain));

        let overlaid = Job {
            payload: Some(r#"{"overlay":"sha256:ab","reviewer":"someone"}"#.into()),
            ..job
        };
        assert!(uses_non_builtin_transform(&overlaid));
    }
}
