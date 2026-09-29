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
//! because losing a race is not a fault. The same goes for a failure: a worker whose job was taken
//! while it ran neither gives the job back nor says it ended.
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
    /// A worker asked to lease work its class may not do.
    ///
    /// Refused rather than filtered, because a class is a *capability* statement and a process
    /// that quietly leased less than it asked for would be a fleet silently missing a worker.
    #[error(
        "a `{class}` worker asked to lease `{kind}` jobs, which belong to another class. The \
         class decides what this process may reach — see docs/12-security.md §2.6 — so leasing \
         across it is a deployment mistake, not a job to skip."
    )]
    WrongClass { class: &'static str, kind: String },
}

/// What a worker may do, and therefore which jobs it may lease.
///
/// [`docs/10-scale.md`](../../../docs/10-scale.md) §"Three classes": `infer` is cheap, network-
/// and model-heavy, and runs at high concurrency; `build` is expensive, isolated and
/// egress-restricted, at low concurrency; `judge` is cheap, fetches the upstream artifact, and
/// executes no container.
///
/// **The split is a control before it is a cost lever.** `docs/12-security.md` §2.6: judging reads
/// the upstream artifact and the build worker has to be unable to, or a build can produce a
/// perfect reproduction by copying the thing it was meant to reproduce. The blob store is on the
/// build's deny list for the same reason the registry is, and
/// `trigon-sandbox/tests/podman.rs::a_blob_store_read_from_inside_the_sandbox_is_denied` asserts
/// the kernel boundary that makes it true.
///
/// **What is not here yet.** The `rebuild` kind still runs inference, the build and the comparison
/// in one process, so `Build` is the only class with a worker today and the separation is enforced
/// at this seam rather than achieved across machines. Splitting that job is `docs/17-backlog.md`
/// B32; until then this type is what stops the three classes from being three names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Infer,
    Build,
    Judge,
}

impl Class {
    /// The job kinds a worker of this class may lease, and no others.
    pub const fn kinds(self) -> &'static [&'static str] {
        match self {
            Class::Infer => &["infer"],
            // `rebuild` is the combined job described above. It is registered here because what it
            // executes is a container, which is what makes a worker a build worker.
            Class::Build => &["rebuild"],
            Class::Judge => &["judge"],
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Class::Infer => "infer",
            Class::Build => "build",
            Class::Judge => "judge",
        }
    }

    /// Whether a worker of this class may hold the upstream artifact's bytes.
    ///
    /// Stated as a method so the answer has one home. It is not yet an access control — see the
    /// note on [`Class`] — and the kernel boundary that does enforce it for the *container* is
    /// tested in `trigon-sandbox`.
    pub const fn may_read_upstream(self) -> bool {
        matches!(self, Class::Judge)
    }
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
    /// `false` means the lease is gone and somebody else is doing this work, and the phase was not
    /// recorded: the job's stream is the holder's. A worker that keeps building after that is
    /// spending compute on an answer nothing will accept.
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

    /// Why a verdict this worker recorded is not worth a second attempt, or `None` where it is.
    ///
    /// **A void above all**: a run the publication gate calls void makes no claim a second attempt
    /// could confirm, and the attempt that repeats it refuses one — so a confirmation queued for
    /// it was leased, refused and retried until it died, one dead job per void verdict, and a dead
    /// job is how this queue says something is wrong. Asked of the worker rather than decided
    /// here, because the gate lives above this crate and a second copy of its clauses here would
    /// be a second opinion about what is void.
    ///
    /// Required, with no default: a `Work` that forgot it would queue exactly those jobs.
    fn unconfirmable(&self, record: &RunRecord) -> Option<String>;
}

/// How the loop behaves.
#[derive(Clone, Debug)]
pub struct Config {
    /// Names this worker in every lease and every event. A hostname plus a pid, usually: the
    /// question it has to answer is "which process is holding this", months later, from a row.
    pub worker: String,
    /// What this worker may do. See [`Class`].
    pub class: Class,
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
    /// How long after a verdict its confirmation becomes visible to a worker.
    ///
    /// At least `[publish] confirmation_interval`, which `trigon worker` reads from the
    /// configuration and sets here: the publication gate withholds a pair whose second attempt
    /// began sooner than that after the first (`docs/19` §10 phase 3), so a confirmation enqueued
    /// to run earlier is a build spent on an answer the gate will not count. It was five minutes,
    /// against an interval of an hour.
    pub confirm_after: Duration,
    /// The machine this worker runs on, as a run records it (`trigon_store::host_id`), which
    /// leases no job queued to avoid it. `None` where it has no id, and then it is avoided by
    /// nothing and its runs record no host.
    pub host: Option<String>,
    /// `[publish] same_host_confirmation` (`docs/19` D8), which `trigon worker` reads from the
    /// configuration and sets here.
    ///
    /// Off, the gate does not count a confirmation made on the machine that made the first
    /// attempt, so the confirmation is queued to avoid that machine: nothing asks a third time,
    /// and a confirmation leased by the first attempt's machine because it happened to be idle
    /// first was a build spent on a pair withheld as `same_host` for good. On, any machine may take
    /// it, since the attempt that repeats a run is cold and re-pulls its image. **A fleet of one
    /// machine confirms nothing with this off**: its confirmations wait for a machine that is not
    /// there, which is what the gate would make of their answers.
    pub same_host_confirmation: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            worker: "worker".into(),
            class: Class::Build,
            lease: Duration::from_secs(300),
            batch: 1,
            idle: Duration::from_secs(12),
            backoff: Duration::from_secs(30),
            backoff_cap: Duration::from_secs(1800),
            max_failures: 3,
            confirm: true,
            // The configuration's default interval. A default of its own here would be a second
            // number that has to agree with that one.
            confirm_after: trigon_attest::config::PublishConfig::default().confirmation_interval,
            host: None,
            // And its default for D8, for the same reason.
            same_host_confirmation: trigon_attest::config::PublishConfig::default()
                .same_host_confirmation,
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
        // **The class is checked before anything is leased.** A worker that asked for a kind
        // outside its class is misconfigured, and the honest response is to say so rather than
        // lease the subset it happens to be allowed — a fleet whose judge workers silently do
        // nothing looks exactly like a fleet with no judging to do.
        if let Some(kind) = kinds
            .iter()
            .find(|k| !self.cfg.class.kinds().contains(&k.as_str()))
        {
            return Err(EngineError::WrongClass {
                class: self.cfg.class.name(),
                kind: kind.clone(),
            });
        }
        let refs: Vec<&str> = kinds.iter().map(String::as_str).collect();
        let jobs = self
            .queue
            .lease_on(
                &self.cfg.worker,
                self.cfg.host.as_deref(),
                &refs,
                self.cfg.batch,
                self.cfg.lease,
            )
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

        let mut tick = tokio::time::interval(renew_every(self.cfg.lease));
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
                // An event, not a phase: `finish` has taken the job out of `leased`, so there is
                // no lease left to renew, and a heartbeat records nothing for a worker that does
                // not hold one.
                let _ = self.queue.event(job.id, "recorded", None).await;

                if self.cfg.confirm {
                    self.confirm(work, &job, &done.record).await?;
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
                let released = self
                    .queue
                    .fail(job.id, &self.cfg.worker, &failed.why, retry)
                    .await?;
                if !released {
                    // The lease expired while this ran and somebody else holds the job, so there
                    // was nothing to give back — and nothing to say, as with `finish` above:
                    // "dead" or "retrying" in the stream of a job another worker is still on
                    // would tell a reader it had ended when it had not.
                    tracing::warn!(
                        job = job.id,
                        worker = %self.cfg.worker,
                        why = %failed.why,
                        "lease expired before this failed; another worker now holds this job"
                    );
                    return Ok(());
                }
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
    ///
    /// **The same question, not the same request.** The job is keyed on the first attempt's
    /// `RunRecord::cache_key` — the target, the strategy it ran and the set it was judged under —
    /// and its payload names that run as `confirm`, so the worker repeats that strategy cold
    /// rather than inferring one again. A first attempt's own job key names what was asked for,
    /// which is the target and nothing the run had yet decided. A verdict with no key cannot be
    /// confirmed at all, since no second attempt could be counted beside it, and is not asked
    /// again; nor is one the worker says is not worth it ([`Work::unconfirmable`]), a void above
    /// all.
    ///
    /// **On another machine**, unless the operator accepts one machine confirming itself
    /// ([`Config::same_host_confirmation`]): the job is queued to avoid the machine the first
    /// attempt recorded, so it waits for a worker elsewhere rather than being taken by whichever is
    /// idle first. The job's events say so, since on a fleet of one machine it waits for good.
    async fn confirm(
        &self,
        work: &dyn Work,
        job: &Job,
        record: &RunRecord,
    ) -> Result<(), EngineError> {
        if record.outcome.is_none() || job.attempt > 1 {
            return Ok(());
        }
        let Some(key) = record.cache_key.clone() else {
            tracing::warn!(
                run = %record.id,
                "this verdict has no cache key, so no second attempt could be counted beside it; \
                 not asking again"
            );
            return Ok(());
        };
        if let Some(why) = work.unconfirmable(record) {
            self.queue
                .event(
                    job.id,
                    "unconfirmed",
                    Some(&format!("no second attempt is asked for: {why}")),
                )
                .await?;
            return Ok(());
        }
        let avoid_host = if self.cfg.same_host_confirmation {
            None
        } else {
            record.host.clone()
        };
        if let Some(host) = &avoid_host {
            self.queue
                .event(
                    job.id,
                    "confirmation",
                    Some(&format!(
                        "queued for a machine other than {host}, which made this attempt: \
                         same_host_confirmation is off, so the gate would not count a \
                         confirmation made there"
                    )),
                )
                .await?;
        }
        self.queue
            .enqueue(&NewJob {
                kind: job.kind.clone(),
                target: job.target.clone(),
                cache_key: key,
                attempt: job.attempt + 1,
                tier: Tier::Regression,
                payload: Some(confirming(job.payload.as_deref(), &record.id)),
                payload_ref: job.payload_ref.clone(),
                // Not immediately. The risk safeguard 1 exists against is ambient nondeterminism —
                // a floating range, a mutable tag, a fetch that happened to succeed — and two runs
                // back to back on a warm cache sample the same moment twice.
                delay: self.cfg.confirm_after,
                avoid_host,
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

/// How often the loop renews a lease while a job is in flight.
///
/// A third of the lease, so two consecutive missed renewals still leave margin.
///
/// **The floor must stay well under the lease.** This was first written with a one-second floor,
/// on the reasoning that an absurdly short lease should not become a busy loop — which against a
/// 300 ms lease renews for the first time at one second, 700 ms after the job has already been
/// taken by somebody else. A floor that can exceed the thing it is renewing disables the renewal
/// entirely, and silently, since everything still compiles and the common configuration still
/// works. Ten milliseconds only exists because `interval` panics on a zero duration.
///
/// A free function, like [`backoff_after`], because the seam test that a long job keeps its lease
/// waits for each renewal however long it takes to come round, so only this can say how long that
/// is.
fn renew_every(lease: Duration) -> Duration {
    (lease / 3).max(Duration::from_millis(10))
}

/// A job's payload with `confirm` naming the run it is the confirmation of.
///
/// Merged into what the first attempt was asked with, so an artifact choice or an overlay carries
/// over, and the worker, which owns the payload's shape, reads the rest. A payload that is not a
/// JSON object is replaced rather than guessed at.
fn confirming(payload: Option<&str>, run: &str) -> String {
    let mut v = payload
        .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    v["confirm"] = serde_json::Value::String(run.to_string());
    v.to_string()
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

    /// The shipped lease, the one the seam tests use, and the shortest the floor lets through:
    /// each renewed at least three times a lease. Below thirty milliseconds the floor binds, and
    /// nothing leases for that little but a test that wants its lease to lapse.
    #[test]
    fn a_lease_is_renewed_well_inside_itself() {
        for lease in [
            Duration::from_secs(300),
            Duration::from_millis(300),
            Duration::from_millis(30),
        ] {
            let every = renew_every(lease);
            assert!(
                every <= lease / 3,
                "a {lease:?} lease renewed every {every:?}: a job longer than one lease goes back \
                 on the queue while it is still being built"
            );
        }
        // Never zero, which `interval` panics on.
        assert!(renew_every(Duration::ZERO) > Duration::ZERO);
        assert!(renew_every(Duration::from_millis(1)) > Duration::ZERO);
    }

    #[test]
    fn a_confirmation_names_its_run_and_keeps_what_the_first_attempt_was_asked() {
        assert_eq!(confirming(None, "r1"), r#"{"confirm":"r1"}"#);
        let v: serde_json::Value =
            serde_json::from_str(&confirming(Some(r#"{"artifact":"a.whl"}"#), "r1")).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "artifact": "a.whl", "confirm": "r1" })
        );
        assert_eq!(confirming(Some("not json"), "r1"), r#"{"confirm":"r1"}"#);
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
