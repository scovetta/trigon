//! The queue's rows, read back: which tier goes first, what a run row holds, who holds a lease, and
//! what a queue made before a table says when that table is asked for.
//!
//! Against a real SQLite file, for the reason `seam_queue.rs` gives: an in-memory database is per
//! connection, and a pool would hand each statement a different empty one.

#![cfg(feature = "queue")]

use std::time::Duration;
use trigon_core::Digest;
use trigon_store::queue::{NewJob, Queue, Tier};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState};

fn url(dir: &tempfile::TempDir, name: &str) -> String {
    format!(
        "sqlite://{}?mode=rwc",
        dir.path().join(format!("{name}.db")).display()
    )
}

async fn queue(dir: &tempfile::TempDir, name: &str) -> Queue {
    let q = Queue::open(&url(dir, name)).await.expect("open");
    q.migrate().await.expect("migrate");
    q
}

/// A second connection to the same file, for reading and altering what the queue's API does not.
async fn raw(dir: &tempfile::TempDir, name: &str) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect(&url(dir, name))
        .await
        .expect("a second connection")
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
    r.cache_key = Some("k1".into());
    r
}

const LEASE: Duration = Duration::from_secs(60);

/// Somebody who asked is served before a confirmation, and a confirmation before a sweep.
///
/// Interactive first because a visitor is waiting on the page; regression next because a corpus
/// whose confirmations queue behind a sweep publishes nothing. Both in the selection and in the
/// batch a worker is handed, which `RETURNING` does not order.
#[tokio::test]
async fn a_visitors_request_is_leased_before_confirmations_and_sweeps() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "tiers").await;
    q.migrate_identity().await.expect("identity");

    let sweep = q
        .enqueue(&NewJob::rebuild("pkg:npm/sweep@1", "k-sweep", Tier::Bulk))
        .await
        .unwrap();
    let confirmation = q
        .enqueue(&NewJob {
            attempt: 2,
            ..NewJob::rebuild("pkg:npm/confirm@1", "k-confirm", Tier::Regression)
        })
        .await
        .unwrap();
    let queued = q
        .enqueue(&NewJob::rebuild(
            "pkg:npm/queued@1",
            "k-queued",
            Tier::Interactive,
        ))
        .await
        .unwrap();

    // A visitor's request, through the request path: it is interactive as well.
    q.add_principal("p1", "one", &["request"], 10, "tok-1")
        .await
        .unwrap();
    let who = q
        .principal_for("tok-1")
        .await
        .unwrap()
        .expect("a principal");
    let asked = match q
        .request_rebuild(&who, "pkg:npm/asked@1.0.0", "2026-09-28")
        .await
        .unwrap()
    {
        trigon_store::Requested::Queued { job, .. } => job,
        other => panic!("the request was not queued: {other:?}"),
    };

    // One at a time, the sweep that was queued first comes last.
    let first = q.lease("w1", &["rebuild"], 1, LEASE).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].tier, Tier::Interactive);
    assert_eq!(
        first[0].id, queued,
        "the older interactive job first, by age within a tier"
    );

    // And a batch comes back in the order it was chosen in.
    let rest = q.lease("w2", &["rebuild"], 10, LEASE).await.unwrap();
    let ids: Vec<i64> = rest.iter().map(|j| j.id).collect();
    assert_eq!(ids, [asked, confirmation, sweep]);
    let tiers: Vec<Tier> = rest.iter().map(|j| j.tier).collect();
    assert_eq!(tiers, [Tier::Interactive, Tier::Regression, Tier::Bulk]);
}

/// A row whose tier cannot be read is the slowest there is. Malformed must not mean urgent.
#[tokio::test]
async fn a_job_whose_tier_cannot_be_read_waits_behind_every_tier_it_could_have_been() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "bad-tier").await;
    let odd = q
        .enqueue(&NewJob::rebuild(
            "pkg:npm/odd@1",
            "k-odd",
            Tier::Interactive,
        ))
        .await
        .unwrap();
    let pool = raw(&dir, "bad-tier").await;
    sqlx::query("UPDATE job SET tier = 'URGENT!!' WHERE id = ?")
        .bind(odd)
        .execute(&pool)
        .await
        .unwrap();
    let confirmation = q
        .enqueue(&NewJob::rebuild(
            "pkg:npm/confirm@1",
            "k-confirm",
            Tier::Regression,
        ))
        .await
        .unwrap();

    // The selection: a worker taking one job at a time is given the confirmation, though the odd
    // job was queued first.
    let first = q.lease("w", &["rebuild"], 1, LEASE).await.unwrap();
    let ids: Vec<i64> = first.iter().map(|j| j.id).collect();
    assert_eq!(ids, [confirmation], "the malformed job was selected first");
    assert_eq!(first[0].tier, Tier::Regression);

    // What is left comes back read as the slowest tier.
    let rest = q.lease("w", &["rebuild"], 10, LEASE).await.unwrap();
    let ids: Vec<i64> = rest.iter().map(|j| j.id).collect();
    assert_eq!(ids, [odd]);
    assert_eq!(rest[0].tier, Tier::Bulk);
}

/// And in a batch, which `RETURNING` does not order, the malformed job still comes last.
#[tokio::test]
async fn a_batch_hands_back_a_job_whose_tier_cannot_be_read_last() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "bad-tier-batch").await;
    let odd = q
        .enqueue(&NewJob::rebuild(
            "pkg:npm/odd@1",
            "k-odd",
            Tier::Interactive,
        ))
        .await
        .unwrap();
    let pool = raw(&dir, "bad-tier-batch").await;
    sqlx::query("UPDATE job SET tier = 'URGENT!!' WHERE id = ?")
        .bind(odd)
        .execute(&pool)
        .await
        .unwrap();
    let confirmation = q
        .enqueue(&NewJob::rebuild(
            "pkg:npm/confirm@1",
            "k-confirm",
            Tier::Regression,
        ))
        .await
        .unwrap();

    let batch = q.lease("w", &["rebuild"], 10, LEASE).await.unwrap();
    let ids: Vec<i64> = batch.iter().map(|j| j.id).collect();
    assert_eq!(ids, [confirmation, odd]);
    assert_eq!(batch[1].tier, Tier::Bulk);
}

/// A run with no job still gets a row, and recording it twice is still one row.
///
/// `trigon rebuild` on a laptop is not a queued job. The row carries the two denominators as two
/// columns — the outcome of a package that was compared, the fault of a build that could not be
/// run — and never one `failed` flag over both.
#[tokio::test]
async fn a_run_recorded_without_a_job_is_one_row_that_keeps_the_two_denominators_apart() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "record").await;

    let compared = record("r-compared", "pkg:npm/left-pad@1.3.0", Some("divergent"));
    q.record(&compared, "aa").await.unwrap();
    q.record(&compared, "aa").await.unwrap();

    let mut failed = record("r-failed", "pkg:pypi/requests@2.31.0", None);
    failed.failure = Some(trigon_core::FailureSignature {
        code: "env/missing-tool".into(),
        subject: Some("dotnet".into()),
        fault: trigon_core::Fault::Infra,
        retryable: false,
        repairable: false,
        evidence: "the line the classifier matched".into(),
    });
    q.record(&failed, "bb").await.unwrap();

    let pool = raw(&dir, "record").await;
    let rows = sqlx::query(
        "SELECT id, target, ecosystem, state, outcome, fault, failure_code, record_ref \
         FROM run ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    use sqlx::Row as _;
    type Row = (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    );
    let got: Vec<Row> = rows
        .iter()
        .map(|r| {
            (
                r.get("id"),
                r.get("target"),
                r.get("ecosystem"),
                r.get("state"),
                r.get("outcome"),
                r.get("fault"),
                r.get("failure_code"),
                r.get("record_ref"),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "r-compared".to_string(),
                "pkg:npm/left-pad@1.3.0".to_string(),
                "npm".to_string(),
                "done".to_string(),
                Some("divergent".to_string()),
                None,
                None,
                "aa".to_string(),
            ),
            (
                "r-failed".to_string(),
                "pkg:pypi/requests@2.31.0".to_string(),
                "pypi".to_string(),
                "done".to_string(),
                None,
                Some("infra".to_string()),
                Some("env/missing-tool".to_string()),
                "bb".to_string(),
            ),
        ]
    );

    // No job was touched: this is not the outbox.
    assert!(q.depth().await.unwrap().is_empty());
}

/// Which workers hold work right now, and how soon each one's earliest lease runs out.
#[tokio::test]
async fn the_fleet_can_see_which_worker_holds_what_and_until_when() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "workers").await;
    assert!(
        q.workers().await.unwrap().is_empty(),
        "nobody holds anything yet"
    );
    for i in 0..3 {
        q.enqueue(&NewJob::rebuild(
            format!("pkg:npm/p{i}@1"),
            format!("k{i}"),
            Tier::Bulk,
        ))
        .await
        .unwrap();
    }
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let held_by_b = q.lease("w-b", &["rebuild"], 2, LEASE).await.unwrap();
    let held_by_a = q
        .lease("w-a", &["rebuild"], 1, Duration::from_secs(600))
        .await
        .unwrap();
    assert_eq!((held_by_a.len(), held_by_b.len()), (1, 2));

    let workers = q.workers().await.unwrap();
    let names: Vec<(&str, i64)> = workers.iter().map(|(w, n, _)| (w.as_str(), *n)).collect();
    assert_eq!(
        names,
        [("w-a", 1), ("w-b", 2)],
        "one row per worker, by name"
    );
    for (w, _, soonest) in &workers {
        assert!(
            *soonest > before,
            "{w}'s lease expires in the past: {soonest}"
        );
    }
    // w-b's leases run 60 s and w-a's 600 s. Five minutes tells them apart without asking the
    // clock to keep pace with the test on a loaded machine.
    let (_, _, b_soonest) = &workers[1];
    assert!(
        *b_soonest <= before + 300_000,
        "w-b's earliest expiry is not its own lease's: {b_soonest}"
    );

    // A job given back is no longer held by anybody.
    q.fail(held_by_a[0].id, "w-a", "gave up", None)
        .await
        .unwrap();
    let names: Vec<String> = q
        .workers()
        .await
        .unwrap()
        .into_iter()
        .map(|(w, ..)| w)
        .collect();
    assert_eq!(names, ["w-b"]);
}

/// A queue made before `job_avoid` says to run `--migrate`, rather than "no such table".
///
/// `migrate` is what gives an older queue the table. A worker started without it against one failed
/// every lease with an error that named what was missing and not what to do about it.
#[tokio::test]
async fn a_queue_made_before_the_avoid_table_says_what_to_run() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, "older").await;
    let pool = raw(&dir, "older").await;
    sqlx::query("DROP TABLE job_avoid")
        .execute(&pool)
        .await
        .unwrap();
    q.enqueue(&NewJob::rebuild("pkg:npm/a@1", "k-a", Tier::Bulk))
        .await
        .unwrap();

    let e = q
        .lease_on("w", Some("machine-id:one"), &["rebuild"], 1, LEASE)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("--migrate"), "{e}");
    assert!(e.starts_with("leasing"), "{e}");

    let e = q
        .enqueue(&NewJob {
            attempt: 2,
            avoid_host: Some("machine-id:one".into()),
            ..NewJob::rebuild("pkg:npm/a@1", "k-a", Tier::Regression)
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("--migrate"), "{e}");

    // Nothing was queued by the enqueue that failed: the job and its avoidance are one transaction.
    assert_eq!(q.depth().await.unwrap(), vec![("ready".to_string(), 1)]);

    // Migrating adds the table, and the lease that failed goes through.
    q.migrate().await.unwrap();
    let got = q
        .lease_on("w", Some("machine-id:one"), &["rebuild"], 1, LEASE)
        .await
        .unwrap();
    assert_eq!(got.len(), 1);

    // A lease that fails for another reason still says what it was doing and what failed.
    sqlx::query("DROP TABLE job").execute(&pool).await.unwrap();
    let e = q
        .lease("w", &["rebuild"], 1, LEASE)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.starts_with("leasing"), "{e}");
    assert!(e.contains("no such table"), "{e}");
}
