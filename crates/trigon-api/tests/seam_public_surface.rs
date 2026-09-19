//! What the public surface may and may not carry, asserted against a real store.
//!
//! These go through `put_run` → `Index::refresh` → the handler, rather than a hand-built index,
//! because the properties being asserted are about what reaches a *reader* and every shortcut past
//! the store is a step the reader does not take.

use std::sync::Arc;
use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn env(egress: &str) -> Environment {
    Environment {
        base_image: "example@sha256:0".into(),
        egress: egress.into(),
        isolation: "podman".into(),
        attestable: true,
        registry_moment: None,
        pin: None,
        guard_manifest: None,
        guarded_members: None,
    }
}

fn record(id: &str, target: &str, outcome: Option<&str>, key: Option<&str>) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        target,
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([7u8; 32]),
            bytes: 1,
            stored: true,
        },
        env("mirror"),
        "2026-01-01T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = outcome.map(str::to_string);
    r.cache_key = key.map(str::to_string);
    r
}

async fn api_over(records: Vec<RunRecord>, who: Principal) -> Arc<Api> {
    let store = Arc::new(Store::in_memory());
    for r in &records {
        store.put_run(r).await.expect("put_run");
    }
    let index = Index::new();
    index
        .refresh(&store, Switches::default())
        .await
        .expect("refresh");
    Arc::new(Api {
        store,
        // No queue: these assert the read path, and an instance that reads a corpus out of object
        // storage is exactly the shape stage 1 shipped.
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: who,
    })
}

/// Fetch a path through the real router and return `(status, body)`.
async fn get(api: Arc<Api>, path: &str) -> (u16, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut router = trigon_api::router(api);
    let res = router
        .call(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A package name cannot close the script tag the boot island lives in.
///
/// The island carries package names taken from a registry, and a registry name is
/// attacker-controlled. Without escaping, a package called `</script><script>…` would be executing
/// on our own origin on the first paint — which is the worst place in the system for it, because
/// the page's whole job is to be trusted about supply-chain integrity.
#[tokio::test]
async fn a_package_name_cannot_close_the_island() {
    let hostile = "pkg:npm/</script><script>alert(1)</script>@1.0.0";
    let api = api_over(
        vec![record("1700000001-aa", hostile, Some("exact"), None)],
        Principal::Operator,
    )
    .await;
    let (status, body) = get(api, "/").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("\\u003c/script"),
        "the island did not escape the angle brackets in a package name"
    );
    // One opening and one closing tag for the island, one for the module script, and nothing the
    // record put there.
    assert_eq!(
        body.matches("</script>").count(),
        2,
        "a record's contents closed a script tag"
    );
}

/// A withheld run is not in the page source either.
///
/// The gate is asked twice on purpose: once by the JSON route and once by the document. Injecting a
/// withheld run into the island and relying on the front-end not to draw it would put the
/// accusation in `view-source:`, which is the one place a front-end cannot gate.
#[tokio::test]
async fn a_withheld_run_is_absent_from_the_page_source() {
    let api = api_over(
        vec![record(
            "1700000001-aa",
            "pkg:npm/accused-package@1.0.0",
            Some("divergent"),
            Some("k1"),
        )],
        Principal::Anonymous,
    )
    .await;

    let (_, browse) = get(api.clone(), "/").await;
    assert!(
        !browse.contains("accused-package"),
        "a withheld divergence is in the browse page's source"
    );

    let (_, permalink) = get(api.clone(), "/runs/1700000001-aa").await;
    assert!(
        !permalink.contains("accused-package"),
        "a withheld divergence is in its own permalink's source"
    );

    // And the JSON route agrees — 404 rather than 403, because a 403 confirms the run exists,
    // which for a withheld divergence is most of the accusation the gate is holding back.
    let (status, _) = get(api, "/v1/runs/1700000001-aa").await;
    assert_eq!(status, 404);
}

/// The same run, once confirmed, reaches the public.
///
/// The companion to the test above: a gate that withheld everything would pass that one while
/// making the site useless, so the release path is asserted in the same breath as the hold.
#[tokio::test]
async fn two_agreeing_attempts_reach_the_public() {
    let api = api_over(
        vec![
            record(
                "1700000001-aa",
                "pkg:npm/confirmed@1.0.0",
                Some("divergent"),
                Some("k1"),
            ),
            record(
                "1700000002-ab",
                "pkg:npm/confirmed@1.0.0",
                Some("divergent"),
                Some("k1"),
            ),
        ],
        Principal::Anonymous,
    )
    .await;
    let (status, body) = get(api.clone(), "/v1/runs/1700000002-ab").await;
    assert_eq!(status, 200);
    assert!(body.contains("divergent"));
    let (_, page) = get(api, "/").await;
    assert!(
        page.contains("confirmed"),
        "the released run is not on the page"
    );
}

/// An unredacted class never leaves the process to an anonymous caller, through any route.
#[tokio::test]
async fn no_route_hands_the_internet_an_unredacted_byte() {
    let mut r = record("1700000001-aa", "pkg:npm/a@1.0.0", Some("exact"), Some("k"));
    r.build_log = Some(Digest::from_bytes([1u8; 32]));
    r.network_transcript = Some(Digest::from_bytes([2u8; 32]));
    r.comparison = Some(Digest::from_bytes([3u8; 32]));
    let mut confirming = r.clone();
    confirming.id = "1700000002-ab".into();

    let api = api_over(vec![r, confirming], Principal::Anonymous).await;
    for path in [
        "/v1/runs/1700000001-aa/log",
        "/v1/runs/1700000001-aa/network",
        "/v1/runs/1700000001-aa/comparison",
        // Digest-addressed, where the caller would be the one naming the class.
        "/v1/evidence/0101010101010101010101010101010101010101010101010101010101010101",
    ] {
        let (status, body) = get(api.clone(), path).await;
        assert_eq!(status, 403, "{path} did not refuse: {body}");
        // A refusal that says nothing teaches a reader the site is arbitrary.
        assert!(body.len() > 80, "{path} refused without explaining why");
    }
}

/// Every route in the contract answers, and none of them is a write.
#[tokio::test]
async fn the_contract_describes_the_router_that_exists() {
    let api = api_over(
        vec![record(
            "1700000001-aa",
            "pkg:npm/a@1.0.0",
            Some("exact"),
            None,
        )],
        Principal::Operator,
    )
    .await;
    let (status, body) = get(api.clone(), "/v1/openapi.json").await;
    assert_eq!(status, 200);
    let doc: serde_json::Value = serde_json::from_str(&body).expect("openapi is json");
    let paths = doc["paths"].as_object().expect("paths");
    for (path, spec) in paths {
        let ops: Vec<&String> = spec.as_object().expect("operations").keys().collect();
        assert_eq!(ops, vec!["get"], "{path} declares a verb that is not `get`");
    }
    // And every concrete route actually answers rather than 404ing, which is what makes the
    // contract a description rather than a wish.
    for (path, ..) in trigon_api::routes::ROUTES {
        if path.contains('{') {
            continue;
        }
        let (status, _) = get(api.clone(), path).await;
        assert_eq!(status, 200, "{path} is in the contract and does not answer");
    }
}
