//! The worker loop's properties, through a real queue and a fake build.
//!
//! The build is fake on purpose. What these assert is the *loop* — the lease, the heartbeat, the
//! outbox, the backoff, the confirmation and the cap refusal — and a test that needed podman to
//! check backoff arithmetic would be a test nobody runs.

use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;
use trigon_core::Digest;
use trigon_engine::{Config, Done, Engine, Failed, Progress, Work};
use trigon_store::queue::{Job, NewJob, Queue, Tier};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState};

async fn queue(dir: &tempfile::TempDir, name: &str) -> Queue {
    let q = Queue::open(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join(format!("{name}.db")).display()
    ))
    .await
    .expect("open");
    q.migrate().await.expect("migrate");
    q
}

fn record(id: &str, target: &str, outcome: Option<&str>, key: &str) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        target,
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([5u8; 32]),
            bytes: 7,
            stored: true,
        },
        Environment {
            base_image: "x@sha256:0".into(),
            derived_image: None,
            egress: "mirror".into(),
            isolation: "podman".into(),
            attestable: true,
            registry_moment: None,
            pin: None,
            guard_manifest: None,
            guarded_members: None,
        },
        "2026-01-01T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = outcome.map(str::to_string);
    r.cache_key = Some(key.into());
    r
}

/// A build that always answers the same way, counting how often it was asked.
#[derive(Debug)]
struct Fake {
    outcome: Option<&'static str>,
    fail: Option<(&'static str, bool)>,
    ran: AtomicUsize,
    phases: std::sync::Mutex<Vec<String>>,
}

impl Fake {
    fn answering(outcome: Option<&'static str>) -> Arc<Self> {
        Arc::new(Fake {
            outcome,
            fail: None,
            ran: AtomicUsize::new(0),
            phases: std::sync::Mutex::new(Vec::new()),
        })
    }
    fn failing(why: &'static str, retryable: bool) -> Arc<Self> {
        Arc::new(Fake {
            outcome: None,
            fail: Some((why, retryable)),
            ran: AtomicUsize::new(0),
            phases: std::sync::Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl Work for Fake {
    fn kinds(&self) -> Vec<String> {
        vec!["rebuild".into()]
    }

    fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
        None
    }

    async fn run(&self, job: &Job, progress: &Progress) -> Result<Done, Failed> {
        self.ran.fetch_add(1, Ordering::SeqCst);
        for phase in ["resolve", "fetch", "build"] {
            let held = progress.phase(phase).await;
            self.phases
                .lock()
                .unwrap()
                .push(format!("{phase}:{}", if held { "held" } else { "lost" }));
        }
        if let Some((why, retryable)) = self.fail {
            return Err(Failed {
                why: why.into(),
                retryable,
            });
        }
        Ok(Done {
            record: record(
                &format!("run-{}-{}", job.id, job.attempt),
                &job.target,
                self.outcome,
                &job.cache_key,
            ),
            record_ref: "00".repeat(32),
        })
    }
}

fn engine(q: Queue, cfg: Config) -> Engine {
    Engine::new(q, cfg)
}

/// A verdict enqueues a second, independent attempt.
///
/// **This is what makes anything publishable at all.** ADR-0010 safeguard 1 needs two agreeing
/// attempts, and before the engine existed nothing in the system ever asked the same question
/// twice — so the corpus browser's first measurement against a real store was 32 runs, every one of
/// them withheld as `awaiting_confirmation`.
#[tokio::test]
async fn a_verdict_asks_the_question_a_second_time() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "confirm").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();

    let work = Fake::answering(Some("divergent"));
    assert_eq!(e.tick(work.as_ref()).await.unwrap(), 1);

    // The confirmation is delayed on purpose: the risk safeguard 1 exists against is ambient
    // nondeterminism, and two runs back to back on a warm cache sample the same moment twice.
    let now = q
        .lease("w2", &["rebuild"], 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(now.is_empty(), "the confirmation was runnable immediately");

    let depth = q.depth().await.unwrap();
    assert_eq!(
        depth,
        vec![("done".to_string(), 1), ("ready".to_string(), 1)],
        "a confirmation attempt was not enqueued"
    );
}

/// A build that answers with a record keyed as the run path keys one: on what it ran, not on
/// what the job asked for.
#[derive(Debug)]
struct KeyedByTheRun {
    key: Option<&'static str>,
}

#[async_trait]
impl Work for KeyedByTheRun {
    fn kinds(&self) -> Vec<String> {
        vec!["rebuild".into()]
    }

    fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
        None
    }

    async fn run(&self, job: &Job, _progress: &Progress) -> Result<Done, Failed> {
        let mut r = record(
            &format!("run-{}-{}", job.id, job.attempt),
            &job.target,
            Some("exact"),
            "",
        );
        r.cache_key = self.key.map(str::to_string);
        Ok(Done {
            record: r,
            record_ref: "00".repeat(32),
        })
    }
}

/// The confirmation is the same question, not the same request.
///
/// A first attempt's job is keyed on its target, which is all `trigon enqueue` knows; the run
/// keys its record on the target, the strategy it ran and the set it was judged under. The second
/// attempt is asked of that key, naming the run it confirms, so the worker repeats that strategy
/// rather than inferring one that may differ (`docs/19` §10 phase 3).
#[tokio::test]
async fn a_confirmation_is_keyed_on_what_the_first_attempt_ran_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "keyed").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            confirm_after: Duration::ZERO,
            ..Default::default()
        },
    );
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
        .await
        .unwrap();
    e.tick(&KeyedByTheRun {
        key: Some("ck1:the-work"),
    })
    .await
    .unwrap();

    let next = q
        .lease("w2", &["rebuild"], 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(next.len(), 1, "a confirmation was not enqueued");
    assert_eq!(next[0].cache_key, "ck1:the-work");
    assert_eq!(next[0].attempt, 2);
    let payload: serde_json::Value =
        serde_json::from_str(next[0].payload.as_deref().expect("a payload")).unwrap();
    assert_eq!(payload["confirm"], format!("run-{}-1", next[0].id - 1));
}

/// A verdict whose record has no key cannot be confirmed, so it is not asked again: no second
/// attempt could be counted beside it.
#[tokio::test]
async fn a_verdict_with_no_key_is_not_asked_again() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "keyless").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            confirm_after: Duration::ZERO,
            ..Default::default()
        },
    );
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
        .await
        .unwrap();
    e.tick(&KeyedByTheRun { key: None }).await.unwrap();
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 1)]);
}

/// A run with no verdict is not confirmed.
///
/// A `no-strategy` asked twice is still a `no-strategy`, and the second build spends compute to
/// learn nothing. The corpus is mostly these, so getting it wrong doubles the bill.
#[tokio::test]
async fn a_run_that_reached_no_verdict_is_not_asked_again() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "noconfirm").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();

    e.tick(Fake::answering(None).as_ref()).await.unwrap();
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 1)]);
}

/// A confirmation does not confirm itself.
///
/// Otherwise the first verdict enqueues a second attempt, which enqueues a third, and the queue
/// rebuilds one package until somebody notices the bill.
#[tokio::test]
async fn confirmations_do_not_breed() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "breed").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    q.enqueue(&NewJob {
        attempt: 2,
        ..NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Regression)
    })
    .await
    .unwrap();

    e.tick(Fake::answering(Some("exact")).as_ref())
        .await
        .unwrap();
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 1)]);
}

/// A build on a named machine, answering as the run path does: a verdict keyed on what it ran,
/// with the machine it ran on recorded.
#[derive(Debug, Clone, Copy)]
struct OnMachine {
    host: &'static str,
    /// What the worker says when asked whether its verdict is worth a second attempt.
    unconfirmable: Option<&'static str>,
}

#[async_trait]
impl Work for OnMachine {
    fn kinds(&self) -> Vec<String> {
        vec!["rebuild".into()]
    }

    async fn run(&self, job: &Job, _progress: &Progress) -> Result<Done, Failed> {
        let mut r = record(
            &format!("run-{}-{}", job.id, job.attempt),
            &job.target,
            Some("exact"),
            "ck1:the-work",
        );
        r.host = Some(self.host.into());
        Ok(Done {
            record: r,
            record_ref: "00".repeat(32),
        })
    }

    fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
        self.unconfirmable.map(str::to_string)
    }
}

/// A worker on `host`, whose confirmations are runnable at once.
fn on(q: &Queue, host: &'static str, same_host_confirmation: bool) -> (Engine, OnMachine) {
    let e = engine(
        q.clone(),
        Config {
            worker: format!("worker-on-{host}"),
            host: Some(host.into()),
            confirm_after: Duration::ZERO,
            same_host_confirmation,
            ..Default::default()
        },
    );
    (
        e,
        OnMachine {
            host,
            unconfirmable: None,
        },
    )
}

/// A confirmation goes to another machine, whichever is idle first.
///
/// With `same_host_confirmation` off, as it is by default, the gate does not count a confirmation
/// made on the machine that made the first attempt, and nothing asks a third time. Nothing kept
/// the first machine from leasing it, so a fleet lost the one confirmation of every target whose
/// first machine happened to ask for work first, each after a full cold build.
#[tokio::test]
async fn a_confirmation_is_made_on_another_machine() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "elsewhere").await;
    let (a, on_a) = on(&q, "machine-id:a", false);
    let (b, on_b) = on(&q, "machine-id:b", false);
    let first = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
        .await
        .unwrap();
    assert_eq!(a.tick(&on_a).await.unwrap(), 1);

    // The first machine is idle first, and does not take its own confirmation.
    assert_eq!(
        a.tick(&on_a).await.unwrap(),
        0,
        "the machine that made the first attempt leased its confirmation"
    );
    assert_eq!(
        q.depth().await.unwrap(),
        vec![("done".to_string(), 1), ("ready".to_string(), 1)]
    );
    assert_eq!(b.tick(&on_b).await.unwrap(), 1, "another machine takes it");
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 2)]);

    // And the first job says where its confirmation went, which on a fleet of one machine is the
    // only account of why it never runs.
    let events = q.events(first).await.unwrap();
    assert!(
        events
            .iter()
            .any(|(_, phase, detail)| phase == "confirmation"
                && detail
                    .as_deref()
                    .is_some_and(|d| d.contains("machine-id:a"))),
        "{events:?}"
    );
}

/// Where the operator accepts one machine confirming itself (`docs/19` D8), any machine may make
/// the confirmation, the first included: the attempt that repeats a run is cold and re-pulls its
/// image, which is what the gate then asks of it.
#[tokio::test]
async fn one_machine_confirms_itself_where_the_operator_accepts_it() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "same-host").await;
    let (a, on_a) = on(&q, "machine-id:a", true);
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
        .await
        .unwrap();
    assert_eq!(a.tick(&on_a).await.unwrap(), 1);
    assert_eq!(a.tick(&on_a).await.unwrap(), 1, "the confirmation");
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 2)]);
}

/// A verdict the worker says is not worth confirming — a void, which the attempt that repeats a
/// run refuses — is not asked again, and the job says why.
///
/// It was: the engine asked only whether there was a verdict and a key, so every void verdict
/// queued a confirmation that was leased, refused and retried until it was dead.
#[tokio::test]
async fn a_void_verdict_is_not_asked_again() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "void").await;
    let (a, on_a) = on(&q, "machine-id:a", false);
    let first = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
        .await
        .unwrap();
    let void = OnMachine {
        unconfirmable: Some("the run is void (open_egress)"),
        ..on_a
    };
    assert_eq!(a.tick(&void).await.unwrap(), 1);
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 1)]);
    let events = q.events(first).await.unwrap();
    assert!(
        events
            .iter()
            .any(|(_, phase, detail)| phase == "unconfirmed"
                && detail.as_deref().is_some_and(|d| d.contains("open_egress"))),
        "{events:?}"
    );
}

/// A retryable failure comes back; an unretryable one does not.
#[tokio::test]
async fn a_failure_is_retried_only_where_retrying_could_answer_differently() {
    let dir = tempfile::tempdir().unwrap();

    let q = queue(&dir, "retry").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            backoff: Duration::ZERO,
            ..Default::default()
        },
    );
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    let flaky = Fake::failing("the registry answered 503", true);
    // Three attempts, then dead: `max_failures` is a bound on how much a broken thing may cost.
    for _ in 0..5 {
        e.tick(flaky.as_ref()).await.unwrap();
    }
    assert_eq!(q.depth().await.unwrap(), vec![("dead".to_string(), 1)]);
    assert_eq!(
        flaky.ran.load(Ordering::SeqCst),
        3,
        "a job was retried past its limit"
    );

    let q2 = queue(&dir, "noretry").await;
    let e2 = engine(
        q2.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    q2.enqueue(&NewJob::rebuild("pkg:npm/b@1", "k2", Tier::Bulk))
        .await
        .unwrap();
    let broken = Fake::failing("this package does not build", false);
    for _ in 0..3 {
        e2.tick(broken.as_ref()).await.unwrap();
    }
    assert_eq!(q2.depth().await.unwrap(), vec![("dead".to_string(), 1)]);
    assert_eq!(
        broken.ran.load(Ordering::SeqCst),
        1,
        "an unretryable failure was run again"
    );
}

/// A worker whose lease expired mid-build is told so, and records nothing.
#[tokio::test]
async fn a_worker_that_lost_its_lease_learns_it_from_the_heartbeat() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "lost").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "slow".into(),
            // Expires before the fake's first heartbeat can renew it.
            lease: Duration::from_millis(1),
            ..Default::default()
        },
    );
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    e.tick(Fake::answering(Some("exact")).as_ref())
        .await
        .unwrap();

    // The job was leased and finished within its own (expired) lease, so it is done — the point
    // being asserted is the one below: a *second* worker taking over means the first cannot record.
    let q2 = queue(&dir, "lost2").await;
    let e2 = engine(
        q2.clone(),
        Config {
            worker: "slow".into(),
            lease: Duration::from_millis(1),
            ..Default::default()
        },
    );
    let id = q2
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    q2.lease("slow", &["rebuild"], 1, Duration::from_millis(1))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    q2.lease("fast", &["rebuild"], 1, Duration::from_secs(60))
        .await
        .unwrap();

    let work = Fake::answering(Some("exact"));
    // `tick` leases nothing — "fast" holds it — so the loop does no work and reports zero.
    assert_eq!(e2.tick(work.as_ref()).await.unwrap(), 0);
    assert_eq!(work.ran.load(Ordering::SeqCst), 0);
    assert!(
        !q2.heartbeat(id, "slow", Duration::from_secs(60), None)
            .await
            .unwrap(),
        "the displaced worker was told it still held the lease"
    );
}

/// Every phase a worker reports reaches the events table, in order.
#[tokio::test]
async fn a_worker_says_where_it_has_got_to() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "phases").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    e.tick(Fake::answering(Some("exact")).as_ref())
        .await
        .unwrap();

    let phases: Vec<String> = q
        .events(id)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, p, _)| p)
        .collect();
    assert_eq!(
        phases,
        ["leased", "resolve", "fetch", "build", "recorded"],
        "a reader following this job could not see it move"
    );
}

/// A clean match under a transform somebody wrote is refused, recorded nowhere, and left dead.
///
/// `docs/12-security.md` §1.1's attack with our own UI performing it: a human-approved stabilizer
/// that reached the comparator as `Builtin` yields `normalized` on a human-touched artifact. The
/// cap is computed in `trigon-compare` and nowhere else; this asserts it fired, because the failure
/// mode is publishing a touched artifact as a clean match and it is worth two checks.
#[tokio::test]
async fn a_transform_that_escaped_the_cap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "cap").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    q.enqueue(&NewJob {
        payload: Some(r#"{"overlay":"sha256:ab","reviewer":"someone"}"#.into()),
        ..NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Regression)
    })
    .await
    .unwrap();

    let err = e
        .tick(Fake::answering(Some("normalized")).as_ref())
        .await
        .expect_err("a clean match under an overlay was accepted");
    assert!(matches!(err, trigon_engine::EngineError::CapEscaped { .. }));

    // Dead, not retried: a job that produces an impossible answer produces it again, and a human
    // needs to see the row rather than a queue quietly working through it.
    assert_eq!(q.depth().await.unwrap(), vec![("dead".to_string(), 1)]);
    // And no confirmation was enqueued off the back of it.
    assert_eq!(q.depth().await.unwrap().len(), 1);
}

/// The same run under an overlay, correctly capped, is accepted.
///
/// The companion to the test above. A refusal that fired on every overlay would pass that one while
/// making reviewer-applied transforms impossible, which is the feature the cap exists to permit.
#[tokio::test]
async fn a_transform_that_was_capped_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "capok").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    q.enqueue(&NewJob {
        payload: Some(r#"{"overlay":"sha256:ab","reviewer":"someone"}"#.into()),
        ..NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Regression)
    })
    .await
    .unwrap();

    e.tick(Fake::answering(Some("normalized_with_caveats")).as_ref())
        .await
        .expect("a correctly capped overlay run was refused");
    assert!(
        q.depth()
            .await
            .unwrap()
            .iter()
            .any(|(s, n)| s == "done" && *n == 1)
    );
}

/// A worker only ever leases what it can do.
#[tokio::test]
async fn a_worker_leases_only_its_own_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "kinds").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            ..Default::default()
        },
    );
    q.enqueue(&NewJob {
        kind: "judge".into(),
        ..NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk)
    })
    .await
    .unwrap();

    let work = Fake::answering(Some("exact"));
    assert_eq!(e.tick(work.as_ref()).await.unwrap(), 0);
    assert_eq!(work.ran.load(Ordering::SeqCst), 0);
}

/// A worker that is silent in `Work::run` keeps its lease, because the loop renews it.
///
/// **The defect this asserts against.** `Progress::phase` renews the lease, so the lease lives
/// exactly as long as a worker keeps calling it. The real builder calls it once, at the top, and
/// then hands the whole build to `spawn_blocking`. With the shipped defaults — a 300-second lease
/// and a build allowed 1800 seconds — the job is re-leased roughly six times, six workers build
/// the same package, and `finish` discards every result but the last, because a worker may not
/// record under an expired lease.
///
/// The loop already knew: it logged `"lease expired before this finished; the work was done
/// twice"` and carried on. The condition was detected, named, and left in place.
///
/// Here the work runs for well over a lease without saying anything, which is exactly what a
/// build does, and finishes only when the test says so. It must still be able to record.
struct Silent {
    finish: tokio::sync::Notify,
    heartbeats_seen: AtomicUsize,
}

#[async_trait]
impl Work for Silent {
    fn kinds(&self) -> Vec<String> {
        vec!["rebuild".into()]
    }

    fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
        None
    }

    async fn run(&self, job: &Job, _progress: &Progress) -> Result<Done, Failed> {
        // Deliberately silent. A `Work` that never calls `phase` is the case that broke.
        self.finish.notified().await;
        self.heartbeats_seen.fetch_add(1, Ordering::SeqCst);
        Ok(Done {
            record: record(
                &format!("run-{}", job.id),
                &job.target,
                Some("exact"),
                &job.cache_key,
            ),
            record_ref: "00".repeat(32),
        })
    }
}

/// Wait until `worker` holds a lease on the queue that runs to `until`: taken, or renewed, at the
/// moment the test last set the clock to.
///
/// Polled, because the renewal is the loop's own and nothing outside it is told. The bound is
/// there only so a loop that never renews fails the test rather than hanging it; on the way to a
/// pass it is never reached, however slowly the machine runs.
async fn renewed_to(q: &Queue, worker: &str, until: i64) {
    let wait = async {
        loop {
            let held = q.workers().await.expect("workers");
            if held
                .iter()
                .any(|(w, _, soonest)| w == worker && *soonest == until)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(60), wait)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the loop never renewed `{worker}`'s lease to {until}: a job longer than one \
                 lease goes back on the queue while it is still being built"
            )
        });
}

/// **On the queue's clock, which only the test moves.** This ran on the wall clock — a 300 ms
/// lease renewed every 100 ms, a 900 ms job, a thief at 500 ms — and failed on a loaded machine:
/// a renewal the scheduler delayed past the lease let the thief lease the job, and the queue was
/// right to let it. Here the clock moves by less than a lease at a time and the test waits for the
/// loop to renew at each moment, so by the time the thief asks, three leases after the job was
/// taken, the lease has lapsed only if the loop did not renew it.
///
/// **What this cannot see is how often.** It waits for each renewal however long that takes, so a
/// loop renewing once a minute passes it; that a renewal comes round well inside the lease is the
/// unit test `a_lease_is_renewed_well_inside_itself` beside `renew_every`, and the two together
/// assert what the wall-clock version did.
#[tokio::test]
async fn a_second_worker_cannot_take_a_job_that_is_still_being_worked_on() {
    const LEASE_MS: i64 = 300;
    let dir = tempfile::tempdir().unwrap();
    let now = Arc::new(AtomicI64::new(1_800_000_000_000));
    let q = {
        let now = now.clone();
        queue(&dir, "longjob")
            .await
            .with_clock(move || now.load(Ordering::SeqCst))
    };
    let cfg = Config {
        worker: "slow".into(),
        // The loop renews every third of this on its own timer, which the queue's clock does not
        // govern: a renewal takes a tenth of a second to come round whatever the clock says.
        lease: Duration::from_millis(LEASE_MS as u64),
        ..Default::default()
    };
    let e = engine(q.clone(), cfg);
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/slow@1", "k-slow", Tier::Bulk))
        .await
        .unwrap();

    let work = Arc::new(Silent {
        finish: tokio::sync::Notify::new(),
        heartbeats_seen: AtomicUsize::new(0),
    });
    let w = work.clone();
    let running = tokio::spawn(async move { e.tick(w.as_ref()).await });

    // Taken, and marked `leased` at the moment the job was taken.
    let taken = now.load(Ordering::SeqCst);
    renewed_to(&q, "slow", taken + LEASE_MS).await;

    // Two thirds of a lease at a time, five times: well past three leases, and still inside the
    // job. Without a renewal at each moment, the lease would lapse by the second.
    for _ in 0..5 {
        let at = now.fetch_add(LEASE_MS * 2 / 3, Ordering::SeqCst) + LEASE_MS * 2 / 3;
        renewed_to(&q, "slow", at + LEASE_MS).await;
    }
    assert!(now.load(Ordering::SeqCst) - taken > 3 * LEASE_MS);

    let stolen = q
        .lease(
            "thief",
            &["rebuild"],
            5,
            Duration::from_millis(LEASE_MS as u64),
        )
        .await
        .expect("lease");
    assert!(
        stolen.is_empty(),
        "a second worker took a job that is still being worked on: {:?}. Both will build the same \
         package, and `finish` will throw away whichever finishes first.",
        stolen.iter().map(|j| j.id).collect::<Vec<_>>()
    );

    work.finish.notify_one();
    running.await.expect("join").expect("tick");
    assert_eq!(work.heartbeats_seen.load(Ordering::SeqCst), 1);

    // `job_for` finds attempt 1 by cache key. The confirmation attempt this verdict enqueues is a
    // second row and is meant to be `ready`, so this names the job that ran rather than the queue.
    let (got_id, state) = q
        .job_for("k-slow")
        .await
        .expect("job_for")
        .expect("the job that ran");
    assert_eq!(got_id, id);
    assert_eq!(
        state, "done",
        "the worker that did the work could not record it"
    );
}

/// And the renewal does not overwrite the phase the worker last reported.
///
/// `phase` both renews and sets a name. A loop that renewed by calling `phase("running")` would
/// keep the lease and destroy the only signal an operator has about where a long build has got to
/// — which is the field `trigon watch` renders.
#[tokio::test]
async fn renewing_a_lease_does_not_erase_the_phase() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "phasekeep").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "slow".into(),
            lease: Duration::from_millis(300),
            ..Default::default()
        },
    );
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/p@1", "k-p", Tier::Bulk))
        .await
        .unwrap();

    struct Named;
    #[async_trait]
    impl Work for Named {
        fn kinds(&self) -> Vec<String> {
            vec!["rebuild".into()]
        }
        fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
            None
        }
        async fn run(&self, job: &Job, progress: &Progress) -> Result<Done, Failed> {
            progress.phase("rebuild").await;
            tokio::time::sleep(Duration::from_millis(700)).await;
            Ok(Done {
                record: record(
                    &format!("run-{}", job.id),
                    &job.target,
                    Some("exact"),
                    &job.cache_key,
                ),
                record_ref: "00".repeat(32),
            })
        }
    }

    e.tick(&Named).await.unwrap();

    let events = q.events(id).await.expect("events");
    let phases: Vec<String> = events.iter().map(|(_, phase, _)| phase.clone()).collect();
    assert!(
        phases.iter().any(|p| p == "rebuild"),
        "the worker's own phase is missing: {phases:?}"
    );
    assert!(
        !phases.iter().any(|p| p == "running"),
        "the loop invented a phase of its own and buried the worker's: {phases:?}"
    );
}

/// A worker leases only what its class may do, and says so when asked for more.
///
/// The three classes are a control before they are a cost lever. `docs/12-security.md` §2.6: the
/// judge reads the upstream artifact and the build worker has to be unable to, because a build
/// that can reach our own blob store can reproduce the artifact by copying it —
/// `trigon-sandbox/tests/podman.rs::a_blob_store_read_from_inside_the_sandbox_is_denied` asserts
/// the kernel boundary for the container half.
///
/// **Refused rather than filtered.** A judge worker that quietly leased nothing because its kinds
/// were outside its class looks exactly like a fleet with no judging to do, which is the failure
/// that would go unnoticed longest.
#[tokio::test]
async fn a_worker_cannot_lease_across_its_class() {
    use trigon_engine::Class;

    // The mapping itself: every kind belongs to exactly one class, so no job is reachable from two.
    let mut seen: Vec<&str> = Vec::new();
    for c in [Class::Infer, Class::Build, Class::Judge] {
        for k in c.kinds() {
            assert!(
                !seen.contains(k),
                "`{k}` belongs to two classes, so a job of that kind is reachable from both"
            );
            seen.push(k);
        }
    }

    // Only the judge may hold upstream bytes. This is the whole reason the split exists.
    assert!(Class::Judge.may_read_upstream());
    assert!(!Class::Build.may_read_upstream());
    assert!(!Class::Infer.may_read_upstream());

    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "classes").await;
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k-class", Tier::Bulk))
        .await
        .unwrap();

    // `Fake` leases `rebuild`, which is the build class's kind. A judge worker asking for it is a
    // deployment mistake and is named as one.
    let judge = engine(
        q.clone(),
        Config {
            worker: "j".into(),
            class: Class::Judge,
            ..Default::default()
        },
    );
    let e = judge
        .tick(Fake::answering(Some("exact")).as_ref())
        .await
        .expect_err("a judge worker must not lease a build");
    let text = format!("{e}");
    assert!(
        text.contains("judge"),
        "the error must name the class: {text}"
    );
    assert!(text.contains("rebuild"), "and the kind it refused: {text}");

    // And nothing was taken: the job is still there for a worker that may do it.
    assert_eq!(q.depth().await.unwrap(), vec![("ready".to_string(), 1)]);

    let builder = engine(
        q.clone(),
        Config {
            worker: "b".into(),
            class: Class::Build,
            ..Default::default()
        },
    );
    assert_eq!(
        builder
            .tick(Fake::answering(Some("exact")).as_ref())
            .await
            .expect("a build worker may lease a rebuild"),
        1
    );
}

/// A class is named as itself when it refuses, whichever class it is.
///
/// The judge case is above. An infer worker handed the build's kind and a build worker handed the
/// judge's are the same deployment mistake, and an error that named the wrong class would send an
/// operator to fix the wrong worker.
#[tokio::test]
async fn every_class_names_itself_when_it_refuses_a_kind() {
    use trigon_engine::Class;

    /// A worker that leases only judge jobs.
    struct Judging;

    #[async_trait]
    impl Work for Judging {
        fn kinds(&self) -> Vec<String> {
            vec!["judge".into()]
        }

        fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
            None
        }

        async fn run(&self, _: &Job, _: &Progress) -> Result<Done, Failed> {
            unreachable!("nothing may be leased across a class")
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "every-class").await;
    let as_class = |class: Class| {
        engine(
            q.clone(),
            Config {
                worker: "w".into(),
                class,
                ..Default::default()
            },
        )
    };

    let e = as_class(Class::Infer)
        .tick(Fake::answering(Some("exact")).as_ref())
        .await
        .expect_err("an infer worker must not lease a build");
    let text = e.to_string();
    assert!(text.contains("`infer` worker"), "{text}");
    assert!(text.contains("`rebuild`"), "{text}");

    let e = as_class(Class::Build)
        .tick(&Judging)
        .await
        .expect_err("a build worker must not lease judging");
    let text = e.to_string();
    assert!(text.contains("`build` worker"), "{text}");
    assert!(text.contains("`judge`"), "{text}");
}

/// A worker whose job was taken from it while it ran records nothing and asks nothing again.
///
/// `finish` refuses a worker that no longer holds the lease, so the other worker's answer is the
/// one the queue keeps; the loop must treat that refusal as a lost race, not an error, and must not
/// go on to act on an answer nothing accepted — no "recorded", and no confirmation of a verdict
/// the queue never recorded.
#[tokio::test]
async fn a_worker_whose_job_was_taken_while_it_ran_records_nothing_and_asks_nothing() {
    /// A build during which another worker takes the job, as one would once this worker's lease
    /// had lapsed. Released and leased again here rather than waited out, so nothing depends on
    /// how long anything takes.
    struct Displaced {
        q: Queue,
    }

    #[async_trait]
    impl Work for Displaced {
        fn kinds(&self) -> Vec<String> {
            vec!["rebuild".into()]
        }

        fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
            None
        }

        async fn run(&self, job: &Job, _: &Progress) -> Result<Done, Failed> {
            self.q
                .fail(job.id, "slow", "the lease lapsed", Some(Duration::ZERO))
                .await
                .unwrap();
            let taken = self
                .q
                .lease("fast", &["rebuild"], 1, Duration::from_secs(60))
                .await
                .unwrap();
            assert_eq!(
                taken.len(),
                1,
                "the fixture did not hand the job to another worker"
            );
            Ok(Done {
                record: record(
                    &format!("run-{}-{}", job.id, job.attempt),
                    &job.target,
                    Some("exact"),
                    "ck1:the-work",
                ),
                record_ref: "00".repeat(32),
            })
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "displaced").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "slow".into(),
            confirm_after: Duration::ZERO,
            ..Default::default()
        },
    );
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
        .await
        .unwrap();

    assert_eq!(
        e.tick(&Displaced { q: q.clone() }).await.unwrap(),
        1,
        "losing the race is not an error"
    );

    // The other worker still holds it, and nothing was finished or queued behind it.
    assert_eq!(
        e.queue().depth().await.unwrap(),
        vec![("leased".to_string(), 1)]
    );
    let holders: Vec<String> = q
        .workers()
        .await
        .unwrap()
        .into_iter()
        .map(|(w, ..)| w)
        .collect();
    assert_eq!(holders, ["fast"]);
    let phases: Vec<String> = q
        .events(id)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, phase, _)| phase)
        .collect();
    assert!(phases.contains(&"leased".to_string()), "{phases:?}");
    assert!(
        !phases.contains(&"recorded".to_string()),
        "a worker said it recorded an answer the queue refused: {phases:?}"
    );
}

/// And one whose job was taken while it ran, and whose build then failed, says nothing either.
///
/// `fail` gives nothing back for a worker that no longer holds the lease, and the loop wrote its
/// "retrying" or "dead" regardless — so a reader following the job saw it end while another worker
/// was still on it. `/v1/jobs/{id}/events` shows phase names to anybody.
#[tokio::test]
async fn a_worker_whose_job_was_taken_while_it_ran_says_nothing_when_it_fails() {
    /// `Displaced` above, with a build that fails.
    struct DisplacedThenFails {
        q: Queue,
        retryable: bool,
    }

    #[async_trait]
    impl Work for DisplacedThenFails {
        fn kinds(&self) -> Vec<String> {
            vec!["rebuild".into()]
        }

        fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
            None
        }

        async fn run(&self, job: &Job, _: &Progress) -> Result<Done, Failed> {
            self.q
                .fail(job.id, "slow", "the lease lapsed", Some(Duration::ZERO))
                .await
                .unwrap();
            let taken = self
                .q
                .lease("fast", &["rebuild"], 1, Duration::from_secs(60))
                .await
                .unwrap();
            assert_eq!(
                taken.len(),
                1,
                "the fixture did not hand the job to another worker"
            );
            Err(Failed {
                why: "the build failed".into(),
                retryable: self.retryable,
            })
        }
    }

    // Both ways out of a failure: another attempt, and none.
    for retryable in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(&dir, "displaced-fails").await;
        let e = engine(
            q.clone(),
            Config {
                worker: "slow".into(),
                ..Default::default()
            },
        );
        let id = q
            .enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
            .await
            .unwrap();

        let work = DisplacedThenFails {
            q: q.clone(),
            retryable,
        };
        assert_eq!(
            e.tick(&work).await.unwrap(),
            1,
            "losing the race is not an error"
        );

        // The other worker still holds it.
        assert_eq!(
            e.queue().depth().await.unwrap(),
            vec![("leased".to_string(), 1)]
        );
        let holders: Vec<String> = q
            .workers()
            .await
            .unwrap()
            .into_iter()
            .map(|(w, ..)| w)
            .collect();
        assert_eq!(holders, ["fast"]);
        let phases: Vec<String> = q
            .events(id)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, phase, _)| phase)
            .collect();
        assert!(phases.contains(&"leased".to_string()), "{phases:?}");
        assert!(
            !phases.iter().any(|p| p == "retrying" || p == "dead"),
            "a displaced worker said a job another worker holds had ended (retryable: \
             {retryable}): {phases:?}"
        );
    }
}

/// A worker told not to confirm records its verdict and asks nothing a second time.
#[tokio::test]
async fn a_worker_told_not_to_confirm_asks_nothing_twice() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "no-confirm").await;
    let e = engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            confirm: false,
            confirm_after: Duration::ZERO,
            ..Default::default()
        },
    );
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "pkg:npm/a@1", Tier::Bulk))
        .await
        .unwrap();
    e.tick(&KeyedByTheRun {
        key: Some("ck1:the-work"),
    })
    .await
    .unwrap();
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 1)]);
}

/// A build that asks the loop to stop while it is running, counting how often it was asked for its
/// kinds and how often it ran. Its kinds are refused as another class's the first `refuse` times.
struct StopsWhileRunning {
    stop: Arc<std::sync::atomic::AtomicBool>,
    refuse: usize,
    asked: AtomicUsize,
    ran: AtomicUsize,
}

#[async_trait]
impl Work for StopsWhileRunning {
    fn kinds(&self) -> Vec<String> {
        let n = self.asked.fetch_add(1, Ordering::SeqCst);
        vec![if n < self.refuse { "judge" } else { "rebuild" }.into()]
    }

    fn unconfirmable(&self, _: &RunRecord) -> Option<String> {
        None
    }

    async fn run(&self, job: &Job, _: &Progress) -> Result<Done, Failed> {
        self.ran.fetch_add(1, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
        Ok(Done {
            record: record(
                &format!("run-{}-{}", job.id, job.attempt),
                &job.target,
                Some("exact"),
                &job.cache_key,
            ),
            record_ref: "00".repeat(32),
        })
    }
}

fn looping(q: &Queue) -> Engine {
    engine(
        q.clone(),
        Config {
            worker: "w1".into(),
            confirm: false,
            // Nothing here waits on the queue being empty, so the idle wait is nothing.
            idle: Duration::ZERO,
            ..Default::default()
        },
    )
}

/// `stop` is asked between jobs, never during one: the job in hand is finished and recorded, and
/// the next is left on the queue for whoever asks next.
#[tokio::test]
async fn the_loop_finishes_the_job_in_hand_before_it_stops() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "stop").await;
    for i in 0..2 {
        q.enqueue(&NewJob::rebuild(
            format!("pkg:npm/p{i}@1"),
            format!("k{i}"),
            Tier::Bulk,
        ))
        .await
        .unwrap();
    }
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let work = Arc::new(StopsWhileRunning {
        stop: stop.clone(),
        refuse: 0,
        asked: AtomicUsize::new(0),
        ran: AtomicUsize::new(0),
    });
    looping(&q).run(work.clone(), stop).await;

    assert_eq!(work.ran.load(Ordering::SeqCst), 1);
    assert_eq!(
        q.depth().await.unwrap(),
        vec![("done".to_string(), 1), ("ready".to_string(), 1)],
        "the job in hand was not finished, or the next was taken after the stop"
    );

    // And a loop told to stop before it starts takes nothing.
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let idle = Arc::new(StopsWhileRunning {
        stop: stopped.clone(),
        refuse: 0,
        asked: AtomicUsize::new(0),
        ran: AtomicUsize::new(0),
    });
    looping(&q).run(idle.clone(), stopped).await;
    assert_eq!(idle.asked.load(Ordering::SeqCst), 0);
    assert_eq!(
        q.depth().await.unwrap(),
        vec![("done".to_string(), 1), ("ready".to_string(), 1)]
    );
}

/// A tick that fails does not end the loop.
///
/// A worker that exits on a blip is a worker somebody has to restart. Here the first tick fails —
/// the work asks for a kind outside its class — and the loop carries on to the next, which leases
/// and finishes the job.
#[tokio::test]
async fn a_failed_tick_does_not_end_the_loop() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "survives").await;
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let work = Arc::new(StopsWhileRunning {
        stop: stop.clone(),
        refuse: 1,
        asked: AtomicUsize::new(0),
        ran: AtomicUsize::new(0),
    });
    looping(&q).run(work.clone(), stop).await;

    assert_eq!(
        work.asked.load(Ordering::SeqCst),
        2,
        "the loop stopped at the failed tick"
    );
    assert_eq!(work.ran.load(Ordering::SeqCst), 1);
    assert_eq!(q.depth().await.unwrap(), vec![("done".to_string(), 1)]);
}
