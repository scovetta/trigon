//! Identity, and the views of the queue: what a credential reads back as, and what each view says
//! when there is no queue or the queue cannot be read.
//!
//! `seam_request_path.rs` holds the refusals of the one write route. This holds the rest of what
//! touches the queue — `/v1/me`, `/v1/queue`, `/v1/jobs/{id}/events`, `/v1/fleet` and the queue
//! page — and one rule across all of them: an instance that cannot answer says so, in a code a
//! client can read, and never answers as though the question had an empty answer. A credential
//! that cannot be checked is not the public; a queue that cannot be read is not an empty queue.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches};
use trigon_store::Store;
use trigon_store::queue::{NewJob, Queue, Tier};

/// A queue in `dir`, with the tables `tables` asks for: `"jobs"`, `"identity"`, both or neither.
async fn queue(dir: &tempfile::TempDir, tables: &[&str]) -> Queue {
    let q = Queue::open(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("q.db").display()
    ))
    .await
    .expect("open");
    if tables.contains(&"jobs") {
        q.migrate().await.expect("migrate");
    }
    if tables.contains(&"identity") {
        q.migrate_identity().await.expect("identity");
    }
    q
}

async fn api_with(queue: Option<Queue>, who: Principal) -> Arc<Api> {
    let store = Arc::new(Store::in_memory());
    let index = Index::new();
    index
        .refresh(&store, Switches::default())
        .await
        .expect("refresh");
    Arc::new(Api {
        store,
        queue,
        index,
        switches: Switches::default(),
        unauthenticated: who,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    })
}

async fn send(
    api: Arc<Api>,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, axum::http::HeaderMap, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut req = Request::builder()
        .method(method)
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
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn get_json(api: Arc<Api>, path: &str, token: Option<&str>) -> (u16, serde_json::Value) {
    let (status, _, body) = send(api, "GET", path, token, "").await;
    let v = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("{path} did not answer JSON ({e}): {body}"));
    (status, v)
}

async fn request(api: Arc<Api>, token: &str, target: &str) -> (u16, serde_json::Value) {
    let (status, _, body) = send(
        api,
        "POST",
        "/v1/runs",
        Some(token),
        &serde_json::json!({ "target": target }).to_string(),
    )
    .await;
    (status, serde_json::from_str(&body).unwrap_or_default())
}

fn boot_of(page: &str) -> serde_json::Value {
    let island = page
        .split_once("<script type=\"application/json\" id=\"boot\">")
        .and_then(|(_, rest)| rest.split_once("</script>"))
        .map(|(json, _)| json)
        .expect("the document has a boot island");
    serde_json::from_str(island).expect("the boot island is JSON")
}

#[tokio::test]
async fn a_credential_reads_back_as_the_principal_it_names_and_never_as_itself() {
    // So a front-end can show or hide the request form from a fact, and a person can check what
    // they hold without trying something and reading the refusal.
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs", "identity"]).await;
    q.add_principal("p-ada", "Ada", &["request", "review"], 7, "tok-secret-ada")
        .await
        .unwrap();
    let api = api_with(Some(q), Principal::Anonymous).await;

    let (status, me) = get_json(api.clone(), "/v1/me", Some("tok-secret-ada")).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(
        me,
        serde_json::json!({
            "principal": "p-ada",
            "name": "Ada",
            "scopes": ["request", "review"],
            "daily_quota": 7,
        })
    );
    assert!(
        !me.to_string().contains("tok-secret"),
        "the credential was echoed: {me}"
    );

    // No credential is the public, and says which public this instance means.
    let (status, me) = get_json(api, "/v1/me", None).await;
    assert_eq!(status, 200);
    assert!(me["principal"].is_null());
    assert!(
        me["detail"]
            .as_str()
            .is_some_and(|d| d.starts_with("anonymous")),
        "{me}"
    );
}

/// The scheme of a credential is case-insensitive (RFC 9110 §11.1): `bearer` names the same
/// credential `Bearer` does, and reading it as no credential at all treats its holder as the
/// public — the thing a wrong token is refused rather than done to.
#[tokio::test]
async fn a_credential_is_read_whatever_case_its_scheme_is_written_in() {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs", "identity"]).await;
    q.add_principal("p-ada", "Ada", &["request"], 7, "tok-secret-ada")
        .await
        .unwrap();
    let api = api_with(Some(q), Principal::Anonymous).await;

    for scheme in ["Bearer", "bearer", "BEARER"] {
        let mut router = trigon_api::router(api.clone());
        let res = router
            .call(
                Request::builder()
                    .uri("/v1/me")
                    .header("authorization", format!("{scheme} tok-secret-ada"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200, "{scheme}");
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let me: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            me["principal"], "p-ada",
            "`{scheme}` was read as no credential: {me}"
        );
    }
}

/// A header of another scheme is no credential for this API: `Basic` is addressed to a proxy in
/// front of the site, and refusing it would refuse every read behind that proxy. Reading is
/// anonymous, `/v1/me` says so, and asking for a rebuild still wants a principal.
#[tokio::test]
async fn a_header_of_another_scheme_is_anonymous_and_asking_still_wants_a_principal() {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs", "identity"]).await;
    q.add_principal("p-ada", "Ada", &["request"], 7, "tok-secret-ada")
        .await
        .unwrap();
    let api = api_with(Some(q), Principal::Anonymous).await;

    for (method, path, body, status) in [
        ("GET", "/v1/me", "", 200),
        (
            "POST",
            "/v1/runs",
            r#"{"target":"pkg:npm/left-pad@1.3.0"}"#,
            401,
        ),
    ] {
        let mut router = trigon_api::router(api.clone());
        let res = router
            .call(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), status, "{path}");
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        match path {
            "/v1/me" => assert!(v["principal"].is_null(), "{v}"),
            _ => assert_eq!(v["error"], "authentication_required", "{v}"),
        }
    }
}

#[tokio::test]
async fn a_credential_nobody_issued_is_refused_and_never_read_as_the_public() {
    // Somebody who presented a credential and was treated as the public would spend a long time
    // wondering why their quota never moved.
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs", "identity"]).await;
    let api = api_with(Some(q), Principal::Operator).await;
    let (status, v) = get_json(api, "/v1/me", Some("tok-nobody-issued")).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (401, Some("unknown_token")),
        "{v}"
    );
}

#[tokio::test]
async fn a_credential_shown_to_an_instance_with_no_queue_is_told_it_has_no_identities() {
    let api = api_with(None, Principal::Anonymous).await;
    let (status, v) = get_json(api.clone(), "/v1/me", Some("tok-1")).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (503, Some("no_queue")),
        "{v}"
    );
    let (status, v) = request(api, "tok-1", "pkg:npm/a@1").await;
    assert_eq!(
        (status, v["error"].as_str()),
        (503, Some("no_queue")),
        "{v}"
    );
}

#[tokio::test]
async fn an_identity_store_that_cannot_be_read_is_an_error_and_never_the_public() {
    // A queue with no identity tables: the credential cannot be checked either way, and a request
    // made with it is neither admitted nor treated as anonymous.
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs"]).await;
    let api = api_with(Some(q.clone()), Principal::Anonymous).await;

    let (status, v) = get_json(api.clone(), "/v1/me", Some("tok-1")).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (500, Some("identity_unavailable")),
        "{v}"
    );
    let (status, v) = request(api, "tok-1", "pkg:npm/a@1").await;
    assert_eq!(
        (status, v["error"].as_str()),
        (500, Some("identity_unavailable")),
        "{v}"
    );
    assert!(
        q.depth().await.unwrap().is_empty(),
        "a request nobody could identify was queued"
    );
}

#[tokio::test]
async fn a_request_the_queue_cannot_take_says_the_queue_failed_and_costs_nothing() {
    // Identity is there and the job tables are not. The request is refused as the queue's fault,
    // and the refusal is not charged: once the queue can take it, the same request is the first
    // of the day.
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["identity"]).await;
    q.add_principal("p1", "one", &["request"], 5, "tok-1")
        .await
        .unwrap();
    let api = api_with(Some(q.clone()), Principal::Anonymous).await;

    let (status, v) = request(api.clone(), "tok-1", "pkg:npm/a@1.0.0").await;
    assert_eq!(
        (status, v["error"].as_str()),
        (500, Some("queue_unavailable")),
        "{v}"
    );
    assert!(
        v["detail"]
            .as_str()
            .is_some_and(|d| d.contains("could not be reached")),
        "{v}"
    );

    q.migrate().await.unwrap();
    let (status, v) = request(api, "tok-1", "pkg:npm/a@1.0.0").await;
    assert_eq!(status, 202, "{v}");
    assert_eq!(
        v["quota"]["spent"], 1,
        "the failed request was charged: {v}"
    );
}

#[tokio::test]
async fn a_queue_that_cannot_be_read_says_so_on_every_view_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &[]).await;
    let api = api_with(Some(q), Principal::Operator).await;

    for path in ["/v1/queue", "/v1/jobs/1/events"] {
        let (status, v) = get_json(api.clone(), path, None).await;
        assert_eq!(
            (status, v["error"].as_str()),
            (503, Some("queue_unavailable")),
            "{path}: {v}"
        );
        assert!(
            v["detail"].as_str().is_some_and(|d| !d.is_empty()),
            "{path}: {v}"
        );
    }

    // The fleet page still renders, with the queue's error where its numbers would be.
    let (status, fleet) = get_json(api.clone(), "/v1/fleet", None).await;
    assert_eq!(status, 200, "{fleet}");
    assert!(
        fleet["queue"]["error"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "{fleet}"
    );
    assert!(
        fleet["queue"]["depth"].is_null(),
        "an unreadable queue reported a depth: {fleet}"
    );
    assert!(fleet["corpus"].is_object(), "{fleet}");

    // And the queue page boots without the queue rather than with an empty one: its own fetch
    // reports the error.
    let (status, _, page) = send(api, "GET", "/queue", None, "").await;
    assert_eq!(status, 200);
    let boot = boot_of(&page);
    assert!(boot["health"].is_object(), "{boot}");
    assert!(
        boot.get("queue").is_none(),
        "an unreadable queue booted as a queue: {boot}"
    );
}

#[tokio::test]
async fn an_instance_with_no_queue_says_so_on_every_view_of_it() {
    let api = api_with(None, Principal::Anonymous).await;

    let (status, v) = get_json(api.clone(), "/v1/queue", None).await;
    assert_eq!(status, 200);
    assert!(v["queue"].is_null(), "{v}");
    assert!(
        v["detail"].as_str().is_some_and(|d| d.contains("no queue")),
        "{v}"
    );

    let (status, v) = get_json(api.clone(), "/v1/jobs/1/events", None).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (404, Some("no_queue")),
        "{v}"
    );

    let (status, _, page) = send(api, "GET", "/queue", None, "").await;
    assert_eq!(status, 200);
    let boot = boot_of(&page);
    assert!(boot["queue"]["depth"].is_null(), "{boot}");
    assert!(
        boot["queue"]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("no queue")),
        "{boot}"
    );
}

#[tokio::test]
async fn the_queue_page_boots_what_is_waiting_and_what_is_running() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs"]).await;
    let waiting = q
        .enqueue(&NewJob::rebuild("pkg:npm/waiting@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    let api = api_with(Some(q), Principal::Anonymous).await;

    let (status, _, page) = send(api.clone(), "GET", "/queue", None, "").await;
    assert_eq!(status, 200);
    let boot = boot_of(&page);
    assert_eq!(
        boot["queue"]["depth"],
        serde_json::json!({ "ready": 1 }),
        "{boot}"
    );
    assert_eq!(
        boot["queue"]["in_flight"],
        serde_json::json!([{
            "job": waiting,
            "target": "pkg:npm/waiting@1",
            "state": "ready",
            "attempt": 1,
        }])
    );
    // The same facts the route gives, so the first frame and the fetch after it agree.
    let (_, route) = get_json(api, "/v1/queue", None).await;
    assert_eq!(route["depth"], boot["queue"]["depth"]);
    assert_eq!(route["in_flight"], boot["queue"]["in_flight"]);
}

#[tokio::test]
async fn the_fleet_view_names_who_holds_work_and_how_long_until_it_lapses() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs"]).await;
    for i in 0..2 {
        q.enqueue(&NewJob::rebuild(
            format!("pkg:npm/p{i}@1"),
            format!("k{i}"),
            Tier::Bulk,
        ))
        .await
        .unwrap();
    }
    q.lease(
        "worker-7",
        &["rebuild"],
        1,
        std::time::Duration::from_secs(120),
    )
    .await
    .unwrap();
    let api = api_with(Some(q), Principal::Operator).await;

    let (status, fleet) = get_json(api, "/v1/fleet", None).await;
    assert_eq!(status, 200, "{fleet}");
    assert_eq!(
        fleet["queue"]["depth"],
        serde_json::json!({ "leased": 1, "ready": 1 })
    );
    let workers = fleet["queue"]["workers"].as_array().expect("a worker list");
    assert_eq!(workers.len(), 1, "{fleet}");
    assert_eq!(workers[0]["worker"], "worker-7");
    assert_eq!(workers[0]["jobs_held"], 1);
    // Reported as a number, not interpreted: a slow worker and a dead one look alike from here.
    let left = workers[0]["lease_expires_in_seconds"]
        .as_i64()
        .expect("seconds until the lease lapses");
    assert!((0..=120).contains(&left), "{left}");
}

/// The public is told how many hold work and how soon each lease lapses, and never who holds it.
///
/// A worker is named `$HOSTNAME-<pid>` unless it is given a name, and a hostname is often a
/// person's name: the reason an anonymous reader is shown no run's host id, which is only a keyed
/// hash of it. This page printed the name itself, to anybody.
#[tokio::test]
async fn the_fleet_view_names_no_worker_to_an_anonymous_reader() {
    let dir = tempfile::tempdir().unwrap();
    let q = queue(&dir, &["jobs"]).await;
    q.enqueue(&NewJob::rebuild("pkg:npm/p@1", "k1", Tier::Bulk))
        .await
        .unwrap();
    q.lease(
        "alice-laptop-4242",
        &["rebuild"],
        1,
        std::time::Duration::from_secs(120),
    )
    .await
    .unwrap();
    let api = api_with(Some(q), Principal::Anonymous).await;

    let (status, _, body) = send(api, "GET", "/v1/fleet", None, "").await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains("alice-laptop"),
        "an anonymous reader was shown a worker's name: {body}"
    );
    let fleet: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let workers = fleet["queue"]["workers"].as_array().expect("a worker list");
    assert_eq!(workers.len(), 1, "{fleet}");
    assert!(workers[0].get("worker").is_none(), "{fleet}");
    assert_eq!(workers[0]["jobs_held"], 1);
    let left = workers[0]["lease_expires_in_seconds"]
        .as_i64()
        .expect("seconds until the lease lapses");
    assert!((0..=120).contains(&left), "{left}");
    // Said, so a missing name is not read as a worker that has none.
    assert!(
        fleet["queue"]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("not shown to an anonymous reader")),
        "{fleet}"
    );
}

#[tokio::test]
async fn the_site_serves_its_own_files_under_its_own_policy() {
    // The same bytes a CDN would serve, with the policy that keeps the page from loading anything
    // from anywhere else, and each as the media type it is.
    let api = api_with(None, Principal::Anonymous).await;
    for (path, media) in [
        ("/app.js", "text/javascript; charset=utf-8"),
        ("/app.css", "text/css; charset=utf-8"),
        ("/index.html", "text/html; charset=utf-8"),
    ] {
        let (status, headers, body) = send(api.clone(), "GET", path, None, "").await;
        assert_eq!(status, 200, "{path}");
        assert!(!body.is_empty(), "{path}");
        let h = |n: &str| {
            headers
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        assert_eq!(h("content-type"), media, "{path}");
        assert_eq!(h("x-content-type-options"), "nosniff", "{path}");
        let csp = h("content-security-policy");
        assert!(csp.contains("default-src 'self'"), "{path}: {csp}");
        assert!(csp.contains("script-src 'self'"), "{path}: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
    }
}

#[tokio::test]
async fn an_api_path_that_is_no_route_is_refused_in_json_and_never_answered_with_the_page() {
    // Every other unknown path is the front-end's own route and gets the document. One under
    // `/v1/` is a client asking the API, and a client reading `error` must get one.
    let api = api_with(None, Principal::Anonymous).await;
    let (status, v) = get_json(api.clone(), "/v1/no-such-route", None).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (404, Some("no_such_route")),
        "{v}"
    );

    let (status, headers, page) = send(api, "GET", "/runs/1700000001-aa", None, "").await;
    assert_eq!(status, 200);
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("text/html")),
        "a front-end route did not get the document"
    );
    boot_of(&page);
}
