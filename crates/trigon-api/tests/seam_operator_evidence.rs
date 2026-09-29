//! The evidence routes as an operator reads them, and the refusals that stand either side of that.
//!
//! `seam_public_surface.rs` holds the anonymous half: no unredacted byte reaches the internet. This
//! is the other half, which nothing exercised: that a principal who may read a build log, a
//! transcript or a comparison is handed **the bytes the record named** — re-hashed on the way out,
//! served as data and never as a page — and that each way of not being handed them says which
//! it is. A route that answered "not recorded" for a blob the store lost, or served whatever it
//! found at a digest's path, would be wrong in exactly the way a reader cannot see.
//!
//! Through `put_run` → `Index::refresh` → the router, as the other seam tests do.

use std::sync::Arc;

use axum::http::HeaderMap;
use trigon_api::evidence::Class;
use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

const TARGET: &str = "pkg:npm/demo@1.0.0";
const ARTIFACT: &str = "demo-1.0.0.tgz";

fn record(id: &str, outcome: Option<&str>) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: ARTIFACT.into(),
            sha256: Digest::from_bytes([7u8; 32]),
            bytes: 212,
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
    r.outcome = outcome.map(str::to_string);
    r.cache_key = Some("k1".into());
    r.non_builtin_stabilizer = Some(false);
    r.agreement = outcome.map(|o| trigon_store::digest_of(o.as_bytes()));
    r
}

/// Two agreeing attempts on two machines an hour apart: a pair the gate publishes with no
/// configuration, so an anonymous reader reaches the per-run routes at all.
fn published_pair(first: RunRecord) -> Vec<RunRecord> {
    let mut a = first;
    a.started = "2026-01-01T00:00:00Z".into();
    a.host = Some("machine-id:one".into());
    a.cache = Some(trigon_store::CacheState::default());
    let mut b = a.clone();
    b.id = format!("{}-2", a.id);
    b.started = "2026-01-01T01:00:00Z".into();
    b.host = Some("machine-id:two".into());
    vec![a, b]
}

async fn api_over(store: Arc<Store>, records: &[RunRecord], who: Principal) -> Arc<Api> {
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

/// Fetch a path through the real router: status, headers, body.
async fn fetch(api: Arc<Api>, path: &str) -> (u16, HeaderMap, Vec<u8>) {
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
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .expect("body");
    (status, headers, bytes.to_vec())
}

/// A refusal's machine-readable code and its sentence.
async fn refusal(api: Arc<Api>, path: &str) -> (u16, String, String) {
    let (status, _, body) = fetch(api, path).await;
    let v: serde_json::Value = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("{path} did not refuse in JSON ({e}): {body:?}"));
    (
        status,
        v["error"].as_str().unwrap_or_default().to_string(),
        v["detail"].as_str().unwrap_or_default().to_string(),
    )
}

fn content_type(h: &HeaderMap) -> &str {
    h.get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

const LOG: &[u8] = b"compiling demo\n<script>alert('from the build log')</script>\ndone\n";
const TRANSCRIPT: &[u8] = concat!(
    r#"{"route":"toolchain","url":"https://nodejs.org/node.tgz","bytes":1000,"checked":"hashed"}"#,
    "\n",
    r#"{"route":"artifact","url":"https://u:tok@registry.npmjs.org/demo.tgz","bytes":212}"#,
    "\n",
)
.as_bytes();
const COMPARISON: &[u8] =
    br#"{"outcome":"divergent","note":"not a comparison this build renders"}"#;

/// A run whose log, transcript and comparison are all in `store`.
async fn with_evidence(store: &Store, id: &str) -> RunRecord {
    let mut r = record(id, Some("divergent"));
    r.build_log = Some(store.blobs().put(LOG).await.unwrap());
    r.network_transcript = Some(store.blobs().put(TRANSCRIPT).await.unwrap());
    r.comparison = Some(store.blobs().put(COMPARISON).await.unwrap());
    r
}

#[tokio::test]
async fn an_operator_is_handed_each_blob_the_record_names_as_the_data_it_is() {
    let store = Arc::new(Store::in_memory());
    let r = with_evidence(&store, "1700000001-aa").await;
    let api = api_over(store, &[r], Principal::Operator).await;

    for (route, bytes, media) in [
        ("log", LOG, "text/plain; charset=utf-8"),
        ("network", TRANSCRIPT, "application/x-ndjson"),
        ("comparison", COMPARISON, "application/json"),
    ] {
        let (status, headers, body) =
            fetch(api.clone(), &format!("/v1/runs/1700000001-aa/{route}")).await;
        assert_eq!(status, 200, "{route}: {}", String::from_utf8_lossy(&body));
        assert_eq!(
            body, bytes,
            "{route} served other bytes than the record named"
        );
        // A log holding markup is still a log: served as text, never as a page on this origin.
        assert_eq!(content_type(&headers), media, "{route}");
    }
}

#[tokio::test]
async fn bytes_that_do_not_hash_to_the_digest_the_record_names_are_never_served() {
    // The store is exactly the thing a compromised worker can write to. What a route hands out is
    // bytes that hash to the digest the record named, or a refusal — never what it merely found
    // at that path.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::local(dir.path()).unwrap());
    let r = with_evidence(&store, "1700000001-aa").await;
    for d in [r.build_log.unwrap(), r.network_transcript.unwrap()] {
        let hex = d.to_hex();
        std::fs::write(
            dir.path().join(format!("blobs/sha256/{}/{hex}", &hex[..2])),
            b"SUBSTITUTED by something with write access",
        )
        .unwrap();
    }
    let log = r.build_log.unwrap();
    let api = api_over(store, &[r], Principal::Operator).await;

    for path in [
        "/v1/runs/1700000001-aa/log".to_string(),
        "/v1/runs/1700000001-aa/network".to_string(),
        "/v1/runs/1700000001-aa/network/summary".to_string(),
        format!("/v1/evidence/sha256:{}", log.to_hex()),
    ] {
        let (status, _, body) = fetch(api.clone(), &path).await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 404, "{path}: {text}");
        assert!(
            !text.contains("SUBSTITUTED"),
            "{path} served the substituted bytes: {text}"
        );
        assert!(text.contains("no_such_blob"), "{path}: {text}");
    }
}

#[tokio::test]
async fn a_blob_the_store_lost_is_missing_and_never_unrecorded() {
    // "This run recorded no log" and "the store cannot return the log this run recorded" are two
    // facts, and only the second is our fault.
    let store = Arc::new(Store::in_memory());
    let mut lost = record("1700000001-aa", Some("exact"));
    lost.build_log = Some(Digest::from_bytes([0xab; 32]));
    lost.network_transcript = Some(Digest::from_bytes([0xcd; 32]));
    let never = record("1700000002-bb", Some("exact"));
    let api = api_over(store, &[lost, never], Principal::Operator).await;

    for route in ["log", "network", "network/summary"] {
        let (status, code, detail) =
            refusal(api.clone(), &format!("/v1/runs/1700000001-aa/{route}")).await;
        assert_eq!(
            (status, code.as_str()),
            (404, "no_such_blob"),
            "{route}: {detail}"
        );
        assert!(detail.contains("cannot return"), "{route}: {detail}");

        let (status, code, detail) =
            refusal(api.clone(), &format!("/v1/runs/1700000002-bb/{route}")).await;
        assert_eq!(
            (status, code.as_str()),
            (404, "not_recorded"),
            "{route}: {detail}"
        );
        assert!(detail.contains("Absent is not empty"), "{route}: {detail}");
    }
}

#[tokio::test]
async fn an_operator_reads_a_blob_by_its_digest_in_either_spelling() {
    let store = Arc::new(Store::in_memory());
    let d = store.blobs().put(LOG).await.unwrap();
    let api = api_over(store, &[], Principal::Operator).await;

    for path in [
        format!("/v1/evidence/sha256:{}", d.to_hex()),
        format!("/v1/evidence/{}", d.to_hex()),
    ] {
        let (status, headers, body) = fetch(api.clone(), &path).await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(body, LOG);
        // A digest does not say what it is, so nothing here is served as anything but bytes.
        assert_eq!(content_type(&headers), "application/octet-stream");
    }

    let (status, code, _) = refusal(api.clone(), "/v1/evidence/sha256:not-hex").await;
    assert_eq!((status, code.as_str()), (400, "malformed_digest"));
    let (status, code, _) =
        refusal(api.clone(), &format!("/v1/evidence/{}", "ab".repeat(16))).await;
    assert_eq!(
        (status, code.as_str()),
        (400, "malformed_digest"),
        "a short digest is not one"
    );
    let (status, code, _) = refusal(api, &format!("/v1/evidence/{}", "ee".repeat(32))).await;
    assert_eq!((status, code.as_str()), (404, "no_such_blob"));
}

#[tokio::test]
async fn a_transcript_summary_reaches_whoever_may_read_the_transcript_and_nobody_else() {
    // The summary carries the transcript's URLs, unredacted. So it is refused to exactly the
    // readers the transcript is, in the transcript's own words.
    let store = Arc::new(Store::in_memory());
    let records = published_pair(with_evidence(&store, "1700000001-aa").await);

    let operator = api_over(store.clone(), &records, Principal::Operator).await;
    let (status, _, body) = fetch(operator, "/v1/runs/1700000001-aa/network/summary").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let summary: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(summary["exchanges"], 2);
    assert_eq!(summary["bytes"], 1212);

    let anonymous = api_over(store, &records, Principal::Anonymous).await;
    let (status, _, body) = fetch(anonymous.clone(), "/v1/runs/1700000001-aa").await;
    assert_eq!(
        status, 200,
        "the fixture must be a run the gate published: {body:?}"
    );
    let raw = refusal(anonymous.clone(), "/v1/runs/1700000001-aa/network").await;
    let summarized = refusal(anonymous, "/v1/runs/1700000001-aa/network/summary").await;
    assert_eq!(summarized.0, 403);
    assert_eq!(summarized.1, "class_gated");
    assert_eq!(summarized.2, Class::Transcript.refusal());
    assert_eq!(
        summarized, raw,
        "the summary is refused differently from the transcript"
    );
}

#[tokio::test]
async fn an_operator_asking_for_a_run_that_is_not_there_is_told_it_is_not_there() {
    // The anonymous sentence says "published", because a withheld run and an absent one must read
    // the same to the internet. An operator sees withheld runs, so their sentence says only that
    // there is no such run.
    let api = api_over(Arc::new(Store::in_memory()), &[], Principal::Operator).await;
    for path in [
        "/v1/runs/1700000009-zz",
        "/v1/runs/1700000009-zz/log",
        "/v1/runs/1700000009-zz/network/summary",
    ] {
        let (status, code, detail) = refusal(api.clone(), path).await;
        assert_eq!((status, code.as_str()), (404, "no_such_run"), "{path}");
        assert_eq!(detail, "no run by that id", "{path}");
    }
}

#[tokio::test]
async fn a_run_with_no_comparison_has_nothing_to_render() {
    let api = api_over(
        Arc::new(Store::in_memory()),
        &[record("1700000001-aa", None)],
        Principal::Operator,
    )
    .await;
    let (status, code, _) = refusal(api, "/v1/runs/1700000001-aa/diff").await;
    assert_eq!((status, code.as_str()), (404, "not_recorded"));
}

#[tokio::test]
async fn a_comparison_this_build_cannot_render_is_refused_as_ours_and_still_served_raw() {
    // "Our fault rather than the run's", and nothing is lost but the rendering: the raw blob, which
    // is what a third party re-derives from, is still there to fetch.
    let store = Arc::new(Store::in_memory());
    let r = with_evidence(&store, "1700000001-aa").await;
    let api = api_over(store, &[r], Principal::Operator).await;

    let (status, code, detail) = refusal(api.clone(), "/v1/runs/1700000001-aa/diff").await;
    assert_eq!(
        (status, code.as_str()),
        (422, "unreadable_comparison"),
        "{detail}"
    );
    let (status, _, body) = fetch(api, "/v1/runs/1700000001-aa/comparison").await;
    assert_eq!(status, 200);
    assert_eq!(body, COMPARISON);
}

#[tokio::test]
async fn a_run_nothing_has_signed_says_so() {
    let api = api_over(
        Arc::new(Store::in_memory()),
        &[record("1700000001-aa", Some("exact"))],
        Principal::Operator,
    )
    .await;
    let (status, code, detail) = refusal(api, "/v1/runs/1700000001-aa/attestation").await;
    assert_eq!((status, code.as_str()), (404, "unattested"));
    assert!(detail.contains("nothing has been signed"), "{detail}");
}

#[tokio::test]
async fn a_statement_whose_payload_does_not_decode_is_not_served_as_a_void() {
    // An anonymous reader of a void run is served `void/v1` statements and nothing else, chosen by
    // the predicate the envelope carries. An envelope whose payload is not even base64 carries no
    // predicate, so it is not a void, and the run has none to serve.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::local(dir.path()).unwrap());
    let mut r = record("1700000001-aa", Some("divergent"));
    r.environment.egress = "open".into();
    let garbled = trigon_attest::Envelope {
        payload: "%%% this is not base64 %%%".into(),
        payload_type: "application/vnd.in-toto+json".into(),
        signatures: Vec::new(),
    };
    let target = trigon_core::Target::new(
        TARGET.parse().unwrap(),
        trigon_core::ArtifactId::new(ARTIFACT),
    );
    let path = store
        .put_attestation(&target, &r.id, ARTIFACT, trigon_attest::VOID, &garbled)
        .await
        .unwrap();
    r.attestations.push(path);

    let anonymous = api_over(store.clone(), &[r.clone()], Principal::Anonymous).await;
    let (status, code, detail) = refusal(anonymous, "/v1/runs/1700000001-aa/attestation").await;
    assert_eq!(
        (status, code.as_str()),
        (404, "no_void_statement"),
        "{detail}"
    );

    // An operator is not choosing by predicate, and is handed what the record names.
    let operator = api_over(store, &[r], Principal::Operator).await;
    let (status, _, body) = fetch(operator, "/v1/runs/1700000001-aa/attestation").await;
    assert_eq!(status, 200);
    let served: Vec<trigon_attest::Envelope> = serde_json::from_slice(&body).unwrap();
    assert_eq!(served, [garbled]);
}
