//! What a run page's first frame carries of the rendered comparison, and when it carries none.
//!
//! The boot island is an optimisation: it lets a permalink paint the page rather than the word
//! "Loading", and the script fetches whatever the island does not hold. So a comparison the store
//! cannot return, one this build cannot render, and one too large to be worth inlining all boot as
//! no comparison — and the page itself still renders, with the run in it — rather than failing the
//! document or booting something the route would not say.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn run(comparison: Digest) -> RunRecord {
    let mut r = RunRecord::new(
        "1700000001-aa",
        "pkg:pypi/demo@1.0.0",
        ArtifactRef {
            name: "demo-1.0.0.zip".into(),
            sha256: Digest::from_bytes([7; 32]),
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
        "2026-01-01T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = Some("divergent".into());
    r.comparison = Some(comparison);
    r
}

async fn operator_over(store: Arc<Store>, r: RunRecord) -> Arc<Api> {
    store.put_run(&r).await.unwrap();
    let index = Index::new();
    index.refresh(&store, Switches::default()).await.unwrap();
    Arc::new(Api {
        store,
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: Principal::Operator,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    })
}

async fn get(api: Arc<Api>, path: &str) -> (u16, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut router = trigon_api::router(api);
    let res = router
        .call(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), 16 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn boot_of(page: &str) -> serde_json::Value {
    let island = page
        .split_once("<script type=\"application/json\" id=\"boot\">")
        .and_then(|(_, rest)| rest.split_once("</script>"))
        .map(|(json, _)| json)
        .expect("the document has a boot island");
    serde_json::from_str(island).expect("the boot island is JSON")
}

/// A stored comparison with `members` differing members, each named by a path `path_len` long.
fn comparison(members: usize, path_len: usize) -> Vec<u8> {
    let side = |raw: &str| {
        serde_json::json!({
            "format": "zip",
            "bytes": 100,
            "raw": { "sha256": raw },
            "stabilized": { "sha256": raw },
            "set": ["zip", "sha256:set"],
        })
    };
    let files: Vec<serde_json::Value> = (0..members)
        .map(|i| {
            let path = format!("{i:06}/{}", "p".repeat(path_len));
            serde_json::json!({
                "path": path.as_bytes(),
                "status": "differs",
                "kind": "text",
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "outcome": "divergent",
        "upstream": side("aa"),
        "rebuild": side("bb"),
        "diff": {
            "identical": 0,
            "differs": members,
            "only_upstream": 0,
            "only_rebuild": 0,
            "executable_differs": 0,
            "files": files,
        },
    }))
    .unwrap()
}

#[tokio::test]
async fn a_small_comparison_is_in_the_first_frame() {
    let store = Arc::new(Store::in_memory());
    let d = store.blobs().put(comparison(3, 10)).await.unwrap();
    let api = operator_over(store, run(d)).await;
    let (status, page) = get(api, "/runs/1700000001-aa").await;
    assert_eq!(status, 200);
    let boot = boot_of(&page);
    assert_eq!(boot["diff"]["census"]["differs"], 3, "{}", boot["diff"]);
}

#[tokio::test]
async fn a_comparison_the_store_cannot_return_boots_as_none_and_the_page_still_renders() {
    let store = Arc::new(Store::in_memory());
    let api = operator_over(store, run(Digest::from_bytes([0xee; 32]))).await;
    let (status, page) = get(api.clone(), "/runs/1700000001-aa").await;
    assert_eq!(status, 200);
    let boot = boot_of(&page);
    assert_eq!(boot["run"]["entry"]["id"], "1700000001-aa");
    assert!(boot["diff"].is_null(), "{}", boot["diff"]);
    // The route the script falls through to says what happened.
    let (status, body) = get(api, "/v1/runs/1700000001-aa/diff").await;
    assert_eq!(status, 404);
    assert!(body.contains("no_such_blob"), "{body}");
}

#[tokio::test]
async fn a_comparison_this_build_cannot_render_boots_as_none_and_the_page_still_renders() {
    let store = Arc::new(Store::in_memory());
    let d = store
        .blobs()
        .put(&b"{\"not\": \"a comparison\"}"[..])
        .await
        .unwrap();
    let api = operator_over(store, run(d)).await;
    let (status, page) = get(api, "/runs/1700000001-aa").await;
    assert_eq!(status, 200);
    let boot = boot_of(&page);
    assert_eq!(boot["run"]["entry"]["id"], "1700000001-aa");
    assert!(boot["diff"].is_null(), "{}", boot["diff"]);
}

#[tokio::test]
async fn a_comparison_too_large_to_inline_is_left_to_the_fetch() {
    // Five hundred members with long names: bounded, and still more than a document should carry
    // on every load of the page. The route serves it whole.
    let store = Arc::new(Store::in_memory());
    let d = store.blobs().put(comparison(500, 400)).await.unwrap();
    let api = operator_over(store, run(d)).await;

    let (status, body) = get(api.clone(), "/v1/runs/1700000001-aa/diff").await;
    assert_eq!(status, 200);
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["members"].as_array().map(Vec::len), Some(500));
    assert!(
        body.len() > 192 << 10,
        "the fixture is not large: {} bytes",
        body.len()
    );

    let (status, page) = get(api, "/runs/1700000001-aa").await;
    assert_eq!(status, 200);
    let boot = boot_of(&page);
    assert!(
        boot["diff"].is_null(),
        "a {}-byte comparison was inlined",
        body.len()
    );
    assert_eq!(boot["run"]["entry"]["id"], "1700000001-aa");
}
