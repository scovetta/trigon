//! The worker loop's properties, through a real queue and a fake build.
//!
//! The build is fake on purpose. What these assert is the *loop* — the lease, the heartbeat, the
//! outbox, the backoff, the confirmation and the cap refusal — and a test that needed podman to
//! check backoff arithmetic would be a test nobody runs.

use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
