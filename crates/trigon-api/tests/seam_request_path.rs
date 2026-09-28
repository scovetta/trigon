//! The one route that writes: who may use it, what it costs them, and what it cannot express.
//!
//! Every assertion here is about a refusal. That is the shape of the feature: the request button
//! spends our compute and our standing with a registry, so the interesting behaviour is all in
//! what it declines to do.

use std::sync::Arc;
use trigon_api::{Api, Index, Principal, Switches};
use trigon_store::Store;
use trigon_store::queue::Queue;

async fn api_with_queue(dir: &tempfile::TempDir, public: bool) -> (Arc<Api>, Queue) {
    let queue = Queue::open(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("q.db").display()
    ))
    .await
    .expect("open");
    queue.migrate().await.expect("migrate");
    queue.migrate_identity().await.expect("identity");

    let store = Arc::new(Store::in_memory());
    let index = Index::new();
    index
        .refresh(&store, Switches::default())
        .await
        .expect("refresh");
    (
        Arc::new(Api {
            store,
            queue: Some(queue.clone()),
            index,
            switches: Switches::default(),
            unauthenticated: if public {
                Principal::Anonymous
            } else {
                Principal::Operator
            },
            decompiler: None,
            member_reads: trigon_api::default_member_permits(),
            repository_switch: None,
        }),
        queue,
    )
}

async fn post(api: Arc<Api>, path: &str, token: Option<&str>, body: &str) -> (u16, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let mut router = trigon_api::router(api);
    let res = router
        .call(req.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("response");
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Reading is anonymous. Asking is not.
#[tokio::test]
async fn the_public_may_read_and_may_not_spend() {
    let dir = tempfile::tempdir().unwrap();
    let (api, _q) = api_with_queue(&dir, true).await;

    let (status, body) = post(api.clone(), "/v1/runs", None, r#"{"target":"pkg:npm/a@1"}"#).await;
    assert_eq!(status, 401);
    assert!(
        body.contains("spends our compute"),
        "the refusal did not say why: {body}"
    );

    // And a credential the instance does not know is a 401 rather than being quietly demoted to
    // anonymous — somebody who presented a token and was treated as the public would spend a long
    // time wondering why their quota never moved.
    let (status, _) = post(
        api,
        "/v1/runs",
        Some("not-a-real-token"),
        r#"{"target":"pkg:npm/a@1"}"#,
    )
    .await;
    assert_eq!(status, 401);
}

/// A credential without the scope may read and may not ask.
#[tokio::test]
async fn a_reader_scope_cannot_request() {
    let dir = tempfile::tempdir().unwrap();
    let (api, q) = api_with_queue(&dir, true).await;
    q.add_principal("watcher", "A watcher", &["review"], 100, "tok-watch")
        .await
        .unwrap();

    let (status, _) = post(
        api,
        "/v1/runs",
        Some("tok-watch"),
        r#"{"target":"pkg:npm/a@1"}"#,
    )
    .await;
    assert_eq!(status, 403);
}

/// The quota stops the work rather than reporting it afterwards.
#[tokio::test]
async fn admission_stops_at_the_quota() {
    let dir = tempfile::tempdir().unwrap();
    let (api, q) = api_with_queue(&dir, true).await;
    q.add_principal("asker", "An asker", &["request"], 2, "tok-ask")
        .await
        .unwrap();

    for i in 0..2 {
        let (status, _) = post(
            api.clone(),
            "/v1/runs",
            Some("tok-ask"),
            &format!(r#"{{"target":"pkg:npm/p{i}@1"}}"#),
        )
        .await;
        assert_eq!(status, 202, "request {i} was refused");
    }

    let (status, body) = post(
        api,
        "/v1/runs",
        Some("tok-ask"),
        r#"{"target":"pkg:npm/p9@1"}"#,
    )
    .await;
    assert_eq!(status, 429);
    assert!(body.contains("over_quota"));

    // Nothing past the bound reached the queue. The point of charging inside the transaction is
    // that there is no instant at which the job exists and the charge does not.
    assert_eq!(
        q.depth().await.unwrap(),
        vec![("ready".to_string(), 2)],
        "a job was admitted past the quota"
    );
}

/// Clicking twice gets an answer, not two builds.
#[tokio::test]
async fn a_repeat_costs_nothing_and_builds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (api, q) = api_with_queue(&dir, true).await;
    q.add_principal("asker", "An asker", &["request"], 10, "tok")
        .await
        .unwrap();

    let (first, _) = post(
        api.clone(),
        "/v1/runs",
        Some("tok"),
        r#"{"target":"pkg:npm/a@1"}"#,
    )
    .await;
    assert_eq!(first, 202);

    let (again, body) = post(api, "/v1/runs", Some("tok"), r#"{"target":"pkg:npm/a@1"}"#).await;
    assert_eq!(again, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["state"], "already");
    assert_eq!(v["quota"]["spent"], 1, "a repeat was charged");
    assert_eq!(q.depth().await.unwrap(), vec![("ready".to_string(), 1)]);
}

/// A request names a target and cannot name anything else.
///
/// **The egress tier especially.** The shipped default elsewhere is `open`, which adds no network
/// isolation at all, so a payload that could carry a tier would make this route a way to run
/// arbitrary code unsandboxed on our fleet. `docs/22-management-layer.md` §2.4.
#[tokio::test]
async fn a_request_cannot_ask_for_an_egress_tier_or_anything_else() {
    let dir = tempfile::tempdir().unwrap();
    let (api, q) = api_with_queue(&dir, true).await;
    q.add_principal("asker", "An asker", &["request"], 10, "tok")
        .await
        .unwrap();

    // Extra fields are ignored rather than honoured: the type has two fields and serde drops the
    // rest, so there is no path by which any of these could reach a worker.
    let (status, _) = post(
        api,
        "/v1/runs",
        Some("tok"),
        r#"{"target":"pkg:npm/a@1","egress":"open","image":"evil","overlay":"sha256:ff",
            "outcome":"exact","privileged":true}"#,
    )
    .await;
    assert_eq!(status, 202);

    let jobs = q
        .lease("w", &["rebuild"], 10, std::time::Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].payload, None,
        "a caller's fields reached the job payload"
    );
    // And nothing named an outcome, because the request type has no field one could arrive in.
    assert_eq!(jobs[0].target, "pkg:npm/a@1");
}

/// A target that is not a package URL is refused at the boundary.
///
/// Rather than handed to a worker, where it becomes a dead job and a row somebody has to read.
#[tokio::test]
async fn a_malformed_target_never_becomes_a_job() {
    let dir = tempfile::tempdir().unwrap();
    let (api, q) = api_with_queue(&dir, true).await;
    q.add_principal("asker", "An asker", &["request"], 10, "tok")
        .await
        .unwrap();

    for bad in [
        r#"{"target":"left-pad"}"#,
        r#"{"target":"pkg:npm/a @1"}"#,
        r#"{"target":""}"#,
    ] {
        let (status, _) = post(api.clone(), "/v1/runs", Some("tok"), bad).await;
        assert_eq!(status, 400, "{bad} was accepted");
    }
    assert!(q.depth().await.unwrap().is_empty());
}

/// An instance with no queue says so rather than accepting what it cannot honour.
#[tokio::test]
async fn a_reader_with_no_queue_refuses_plainly() {
    let store = Arc::new(Store::in_memory());
    let api = Arc::new(Api {
        store,
        queue: None,
        index: Index::new(),
        switches: Switches::default(),
        unauthenticated: Principal::Anonymous,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    });
    let (status, body) = post(api, "/v1/runs", None, r#"{"target":"pkg:npm/a@1"}"#).await;
    // Anonymous first: the instance's shape is not something an unauthenticated caller needs told.
    assert_eq!(status, 401);
    assert!(!body.contains("no_queue"));
}

/// The queue is not a side channel around the publication gate.
///
/// `/v1/queue` names targets, anonymously, and that is a deliberate call: it says what the fleet is
/// *about to look at*, which is not a finding about anybody. The line it must not cross is carrying
/// a verdict — a withheld divergence whose confirmation is still queued would otherwise be
/// published by the status page while the gate was holding it back.
#[tokio::test]
async fn the_queue_says_what_is_coming_and_never_what_was_found() {
    let dir = tempfile::tempdir().unwrap();
    let (api, q) = api_with_queue(&dir, true).await;
    q.enqueue(&trigon_store::queue::NewJob::rebuild(
        "pkg:npm/accused@1.0.0",
        "k1",
        trigon_store::queue::Tier::Regression,
    ))
    .await
    .unwrap();

    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;
    let mut router = trigon_api::router(api);
    let res = router
        .call(
            Request::builder()
                .uri("/v1/queue")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);

    assert!(
        body.contains("accused"),
        "the queue did not say what is coming"
    );
    for verdict in ["exact", "normalized", "divergent", "outcome", "void"] {
        assert!(
            !body.contains(verdict),
            "`{verdict}` reached the queue view, which publishes around the gate"
        );
    }
}
