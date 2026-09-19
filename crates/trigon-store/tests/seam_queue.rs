//! The queue's properties, against a real SQLite database.
//!
//! Each test opens its own file-backed database in a temp dir rather than `:memory:`, because an
//! in-memory SQLite database is per-connection and a pool would hand each test a different empty
//! one — the tests would pass by never seeing each other's rows, which is the opposite of what a
//! queue test is for.
//!
//! The Postgres path differs in exactly one statement (`FOR UPDATE SKIP LOCKED`) and is exercised
//! by `TRIGON_TEST_POSTGRES`, skipped where no server is configured. A skipped test is named in
//! the output rather than silently absent.

#![cfg(feature = "queue")]

use std::time::Duration;
use trigon_core::Digest;
use trigon_store::queue::{Backend, NewJob, Queue, Tier};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState};

async fn queue(dir: &tempfile::TempDir, name: &str) -> Queue {
    let path = dir.path().join(format!("{name}.db"));
    let q = Queue::open(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .expect("open");
    q.migrate().await.expect("migrate");
    q
}

fn record(id: &str, target: &str, outcome: Option<&str>) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        target,
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([3u8; 32]),
            bytes: 10,
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
    r.cache_key = Some("k1".into());
    r
}

/// Two enqueues of the same work are one job.
///
/// The property that makes a retried HTTP request, a resumed sweep and a duplicated feed entry all
/// produce one rebuild. Without it, the front-end's request button is a way to spend our compute by
/// double-clicking.
#[tokio::test]
async fn the_same_work_enqueues_once() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "idem").await;
    let j = NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk);

    let first = q.enqueue(&j).await.unwrap();
    let again = q.enqueue(&j).await.unwrap();
    assert_eq!(first, again, "a repeat enqueue made a second job");

    let leased = q
        .lease("w1", &["rebuild"], 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(leased.len(), 1);
}

/// A second attempt at the same work is a *different* job.
///
/// ADR-0010 safeguard 1 needs two attempts, and the deduplication above would collapse them into
/// one if the key were the cache key alone. The ADR says so in as many words: "Attempts share a
/// cache key and differ in `Attempt`, so deduplication does not collapse the second one."
#[tokio::test]
async fn a_confirmation_attempt_is_not_deduplicated_away() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "attempts").await;
    let first = NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk);
    let second = NewJob {
        attempt: 2,
        tier: Tier::Regression,
        ..first.clone()
    };

    let a = q.enqueue(&first).await.unwrap();
    let b = q.enqueue(&second).await.unwrap();
    assert_ne!(a, b, "the confirmation attempt was deduplicated away");

    let leased = q
        .lease("w1", &["rebuild"], 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(leased.len(), 2);
    // Regression ahead of bulk: a corpus whose confirmations queue behind a sweep publishes
    // nothing, because a divergence needs a second agreeing attempt before it may be shown.
    assert_eq!(leased[0].attempt, 2);
}

/// Two workers asking at once never get the same job.
#[tokio::test]
async fn one_job_goes_to_one_worker() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "exclusive").await;
    for i in 0..6 {
        q.enqueue(&NewJob::rebuild(
            format!("pkg:npm/p{i}@1"),
            format!("k{i}"),
            Tier::Bulk,
        ))
        .await
        .unwrap();
    }

    let (a, b) = tokio::join!(
        q.lease("w1", &["rebuild"], 3, Duration::from_secs(60)),
        q.lease("w2", &["rebuild"], 3, Duration::from_secs(60)),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    let mut ids: Vec<i64> = a.iter().chain(&b).map(|j| j.id).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "a job was leased by two workers at once");
}

/// A worker that dies holds nothing.
///
/// The lease is a timestamp, not a lock: nothing has to notice the death, no reaper runs, and the
/// row is simply visible again to the next query. That is the property that makes a fleet of
/// unreliable workers workable at all.
#[tokio::test]
async fn a_dead_worker_releases_its_work_without_anybody_noticing() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "lease").await;
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();

    let held = q
        .lease("dies", &["rebuild"], 1, Duration::from_millis(1))
        .await
        .unwrap();
    assert_eq!(held.len(), 1);

    // Nothing runs in between. The only thing that happens is time.
    tokio::time::sleep(Duration::from_millis(30)).await;

    let next = q
        .lease("w2", &["rebuild"], 1, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(next.len(), 1, "an expired lease did not come back");
    assert_eq!(next[0].id, held[0].id);
}

/// A worker whose lease expired cannot record its answer.
///
/// The other half of the property above, and the one that matters. If an expired lease could still
/// finish, two workers would race to record answers to the same question and the loser's answer
/// would be the one that survived. The outbox refuses, and the refusal is a return value rather
/// than an error, because losing a race is not a fault.
#[tokio::test]
async fn a_worker_that_lost_its_lease_cannot_record() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "outbox").await;
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();

    q.lease("slow", &["rebuild"], 1, Duration::from_millis(1))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    q.lease("fast", &["rebuild"], 1, Duration::from_secs(60))
        .await
        .unwrap();

    let wrote = q
        .finish(
            id,
            "slow",
            &record("r-slow", "pkg:npm/a@1", Some("exact")),
            "aa",
        )
        .await
        .unwrap();
    assert!(!wrote, "a worker without the lease recorded an answer");

    let wrote = q
        .finish(
            id,
            "fast",
            &record("r-fast", "pkg:npm/a@1", Some("divergent")),
            "bb",
        )
        .await
        .unwrap();
    assert!(wrote, "the worker holding the lease could not record");
}

/// The outbox is one transaction: the run and the acknowledgement, or neither.
#[tokio::test]
async fn the_run_and_the_acknowledgement_land_together() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "atomic").await;
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    q.lease("w1", &["rebuild"], 1, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        q.finish(id, "w1", &record("r1", "pkg:npm/a@1", Some("exact")), "aa")
            .await
            .unwrap()
    );

    // Done, and not leasable again — so no second worker rebuilds what has been rebuilt.
    let again = q
        .lease("w2", &["rebuild"], 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(again.is_empty());

    let depth = q.depth().await.unwrap();
    assert_eq!(depth, vec![("done".to_string(), 1)]);
}

/// A job out of attempts stays, as a dead row.
///
/// Deleting it would make the queue look healthy while an entire ecosystem failed to build.
#[tokio::test]
async fn a_job_out_of_attempts_is_kept_as_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "dead").await;
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();

    q.lease("w1", &["rebuild"], 1, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        q.fail(id, "w1", "podman is not usable", Some(Duration::ZERO))
            .await
            .unwrap()
    );
    let retried = q
        .lease("w1", &["rebuild"], 1, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(retried.len(), 1, "a retryable failure did not come back");
    assert_eq!(retried[0].failures, 1);

    assert!(q.fail(id, "w1", "still not usable", None).await.unwrap());
    assert!(
        q.lease("w1", &["rebuild"], 1, Duration::from_secs(60))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(q.depth().await.unwrap(), vec![("dead".to_string(), 1)]);
}

/// A worker leases only the kinds it can do.
#[tokio::test]
async fn a_judge_worker_never_leases_a_build() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "kinds").await;
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    q.enqueue(&NewJob {
        kind: "judge".into(),
        ..NewJob::rebuild("pkg:npm/b@1", "k2", Tier::Bulk)
    })
    .await
    .unwrap();

    let judged = q
        .lease("j1", &["judge"], 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(judged.len(), 1);
    assert_eq!(judged[0].kind, "judge");
}

/// The host budget reserves a slot rather than reporting the past.
///
/// "Was the last request long ago" hands two workers asking at the same instant the same answer,
/// which is the difference between a rate limit and a race. Each reservation moves the floor.
#[tokio::test]
async fn the_fleet_reserves_slots_rather_than_racing_for_them() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "hosts").await;
    let interval = Duration::from_millis(50);

    // **Asserted on the stored floor, not on the clock.** A reservation's whole point is that it
    // moves a shared number; how long any one caller then waits depends on when it asked. Two
    // earlier versions of this test measured durations and failed by five milliseconds — once to
    // a bug and once to the round trips themselves — which is the signature of a test measuring
    // the wrong thing. The invariant is exact and has no timing in it: each reservation advances
    // the floor by exactly one interval.
    let first = q
        .reserve_host("registry.npmjs.org", interval)
        .await
        .unwrap();
    assert!(
        first < Duration::from_millis(5),
        "the first caller was made to wait: {first:?}"
    );

    let after_one = q.host_budget("registry.npmjs.org").await.unwrap().unwrap();
    q.reserve_host("registry.npmjs.org", interval)
        .await
        .unwrap();
    let after_two = q.host_budget("registry.npmjs.org").await.unwrap().unwrap();
    q.reserve_host("registry.npmjs.org", interval)
        .await
        .unwrap();
    let after_three = q.host_budget("registry.npmjs.org").await.unwrap().unwrap();

    let step = interval.as_micros() as i64;
    assert_eq!(
        after_two.next_at_us - after_one.next_at_us,
        step,
        "a reservation did not move the floor by one interval"
    );
    assert_eq!(after_three.next_at_us - after_two.next_at_us, step);

    // A different host is a different floor. One slow registry must not pace the others.
    let other = q.reserve_host("pypi.org", interval).await.unwrap();
    assert!(
        other < Duration::from_millis(5),
        "pypi waited behind npm: {other:?}"
    );
}

/// `Retry-After` widens the floor for every worker, not for the one that received it.
///
/// Today the counter a mirror bumps dies with its container, so nothing a host told us ever reached
/// a sibling lane. This is the carrier.
#[tokio::test]
async fn being_throttled_slows_the_whole_fleet() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "throttle").await;
    q.note_throttled("registry.npmjs.org", Duration::from_millis(400))
        .await
        .unwrap();

    let wait = q
        .reserve_host("registry.npmjs.org", Duration::from_millis(10))
        .await
        .unwrap();
    assert!(
        wait >= Duration::from_millis(300),
        "a 429 did not reach the next worker: {wait:?}"
    );

    let b = q.host_budget("registry.npmjs.org").await.unwrap().unwrap();
    assert_eq!(b.throttled, 1);
}

/// Progress goes to its own table, and the lease row is not written per heartbeat.
#[tokio::test]
async fn heartbeats_stay_off_the_hot_path() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "beats").await;
    let id = q
        .enqueue(&NewJob::rebuild("pkg:npm/a@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    q.lease("w1", &["rebuild"], 1, Duration::from_millis(50))
        .await
        .unwrap();

    for phase in ["resolve", "fetch", "build"] {
        assert!(
            q.heartbeat(id, "w1", Duration::from_secs(60), Some(phase))
                .await
                .unwrap()
        );
    }
    let events = q.events(id).await.unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].1, "resolve");
    assert_eq!(events[2].1, "build");

    // And a worker that has lost the lease is told so rather than silently extending somebody
    // else's — the signal it needs to stop building.
    assert!(
        !q.heartbeat(id, "someone-else", Duration::from_secs(60), None)
            .await
            .unwrap()
    );
}

/// The backend is chosen from the URL, and only one statement depends on it.
#[tokio::test]
async fn the_url_picks_the_dialect() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(queue(&dir, "dialect").await.backend(), Backend::Sqlite);
}
