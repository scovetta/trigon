//! `GET /v1/targets/{purl}`: every run against one package, newest first — the version ladder.
//!
//! "Never checked" is an answer of its own on this site, and not a pass: a package reported as
//! never checked when it was is a finding that did not happen. So the route answers from every run
//! the index holds for the package, and not from a page of the newest rows whose text happens to
//! contain the package's name, which other packages' names contain too.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn run(id: &str, target: &str, key: &str, host: &str, started: &str) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        target,
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([3; 32]),
            bytes: 1,
            stored: false,
        },
        Environment {
            base_image: "example@sha256:0".into(),
            derived_image: None,
            egress: "mirror".into(),
            isolation: "podman".into(),
            attestable: true,
            registry_moment: None,
            pin: None,
            guard_manifest: None,
            guarded_members: None,
        },
        started,
    );
    r.state = RunState::Done;
    r.outcome = Some("exact".into());
    r.cache_key = Some(key.into());
    r.non_builtin_stabilizer = Some(false);
    r.agreement = Some(trigon_store::digest_of(b"exact"));
    r.host = Some(host.into());
    r.cache = Some(trigon_store::CacheState::default());
    r
}

async fn api_over(records: &[RunRecord], who: Principal) -> Arc<Api> {
    let store = Arc::new(Store::in_memory());
    for r in records {
        store.put_run(r).await.expect("put_run");
    }
    let index = Index::new();
    index
        .refresh(&store, Switches::default())
        .await
        .expect("refresh");
    Arc::new(Api {
        store,
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: who,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    })
}

async fn get_json(api: Arc<Api>, path: &str) -> (u16, serde_json::Value) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut router = trigon_api::router(api);
    let res = router
        .call(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), 64 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn ids(rows: &serde_json::Value) -> Vec<&str> {
    rows.as_array()
        .unwrap_or_else(|| panic!("not a list of rows: {rows}"))
        .iter()
        .map(|e| e["id"].as_str().unwrap_or_default())
        .collect()
}

/// A package whose name is the start of another's is still found when the other has hundreds of
/// newer runs, and a package with hundreds of runs is listed whole.
///
/// The route searched the newest 500 rows whose text contained the purl and kept those of the
/// package: `pkg:npm/demo` is in every `pkg:npm/demo-extra@…`, so six hundred newer runs of that
/// one crowded out the only run of this one, and the route said it had never been checked.
#[tokio::test]
async fn every_run_of_the_package_is_listed_however_many_other_packages_share_its_name() {
    let mut runs = vec![run(
        "1700000001-aa",
        "pkg:npm/demo@1.0.0",
        "k-demo",
        "machine-id:one",
        "2026-01-01T00:00:00Z",
    )];
    for i in 0..600u32 {
        runs.push(run(
            &format!("1800{i:06}-bb"),
            &format!("pkg:npm/demo-extra@1.0.{i}"),
            &format!("k-extra-{i}"),
            "machine-id:two",
            "2026-06-01T00:00:00Z",
        ));
    }
    let api = api_over(&runs, Principal::Operator).await;

    let (status, rows) = get_json(api.clone(), "/v1/targets/pkg%3Anpm%2Fdemo").await;
    assert_eq!(
        status, 200,
        "a package with a run was reported as never checked: {rows}"
    );
    assert_eq!(ids(&rows), ["1700000001-aa"]);

    let (status, rows) = get_json(api, "/v1/targets/pkg%3Anpm%2Fdemo-extra").await;
    assert_eq!(status, 200);
    let listed = ids(&rows);
    assert_eq!(listed.len(), 600, "the ladder stopped short of every run");
    assert_eq!(listed[0], "1800000599-bb", "newest first");
}

/// The gate holds as it did: an anonymous reader is listed what it released, and a package whose
/// only runs it withholds is one nothing published covers.
#[tokio::test]
async fn an_anonymous_reader_is_listed_only_what_the_gate_released() {
    let confirmed = [
        run(
            "1700000001-aa",
            "pkg:npm/demo@1.0.0",
            "k-demo",
            "machine-id:one",
            "2026-01-01T00:00:00Z",
        ),
        run(
            "1700000002-ab",
            "pkg:npm/demo@1.0.0",
            "k-demo",
            "machine-id:two",
            "2026-01-01T02:00:00Z",
        ),
    ];
    let alone = run(
        "1700000003-ac",
        "pkg:npm/demo@2.0.0",
        "k-demo-2",
        "machine-id:one",
        "2026-01-02T00:00:00Z",
    );
    let lonely = run(
        "1700000004-ad",
        "pkg:npm/lonely@1.0.0",
        "k-lonely",
        "machine-id:one",
        "2026-01-03T00:00:00Z",
    );
    let mut runs = confirmed.to_vec();
    runs.extend([alone, lonely]);

    let anonymous = api_over(&runs, Principal::Anonymous).await;
    let (status, rows) = get_json(anonymous.clone(), "/v1/targets/pkg%3Anpm%2Fdemo").await;
    assert_eq!(status, 200);
    assert_eq!(ids(&rows), ["1700000002-ab", "1700000001-aa"]);
    let (status, refusal) = get_json(anonymous, "/v1/targets/pkg%3Anpm%2Flonely").await;
    assert_eq!(
        (status, refusal["error"].as_str()),
        (404, Some("never_checked"))
    );

    let operator = api_over(&runs, Principal::Operator).await;
    let (_, rows) = get_json(operator, "/v1/targets/pkg%3Anpm%2Fdemo").await;
    assert_eq!(
        ids(&rows),
        ["1700000003-ac", "1700000002-ab", "1700000001-aa"]
    );
}
