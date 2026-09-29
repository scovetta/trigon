//! A re-derived comparison is a reading aid: rendered where it agrees with what the run recorded,
//! ignored where it says anything different, and never served as the evidence.
//!
//! `trigon rederive` fills in what a comparison judged before per-field attribution and the
//! pass-by-pass progression existed lacks, and writes it beside the recorded one. The page renders
//! it only where it agrees with the recorded comparison on everything the verdict rests on — the
//! outcome, both sides' digests and sets, the member counts and the difference signature — so a
//! derived blob that disagrees, however it came to, cannot put a different verdict on a run's page.
//! The raw route serves what the run recorded, always: that is what a third party re-derives from.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches};
use trigon_archive::Limits;
use trigon_compare::compare_bytes;
use trigon_core::{Digest, Format};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

/// Two zips that differ in one member, agree on another, and have one member on one side only.
fn compared() -> serde_json::Value {
    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, body) in entries {
                use std::io::Write as _;
                w.start_file(*name, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        out
    }
    let up = zip(&[
        ("same.txt", b"identical"),
        ("differs.txt", b"upstream side"),
        ("only-upstream.txt", b"here"),
    ]);
    let rb = zip(&[
        ("same.txt", b"identical"),
        ("differs.txt", b"rebuild side!"),
    ]);
    let set = trigon_stabilize::default_for(Format::Zip);
    let c = compare_bytes(up, rb, Format::Zip, &set, &Limits::default()).expect("compare");
    serde_json::to_value(&c).expect("serialize")
}

/// The comparison as a run judged before the progression was recorded wrote it, and the same
/// comparison as `trigon rederive` fills it in.
fn recorded_and_derived() -> (Vec<u8>, serde_json::Value) {
    let mut recorded = compared();
    recorded["diff"]
        .as_object_mut()
        .expect("a diff")
        .remove("progression");
    let mut derived = recorded.clone();
    derived["diff"]["progression"] = serde_json::json!({
        "steps": [
            { "differences": 3, "members": 2, "bodies": 1 },
            { "pass": "zip-time", "differences": 2, "members": 2, "bodies": 1 },
        ],
        "consistent": true,
    });
    (serde_json::to_vec(&recorded).unwrap(), derived)
}

async fn operator_over(store: Arc<Store>, comparison: Digest) -> Arc<Api> {
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

async fn get(api: Arc<Api>, path: &str) -> (u16, Vec<u8>) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut router = trigon_api::router(api);
    let res = router
        .call(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

#[tokio::test]
async fn a_rederivation_that_agrees_is_rendered_and_the_evidence_route_still_serves_the_record() {
    let (recorded, derived) = recorded_and_derived();
    let store = Arc::new(Store::in_memory());
    let d = store.blobs().put(recorded.clone()).await.unwrap();
    store
        .put_derived_comparison(&d, &serde_json::to_vec(&derived).unwrap())
        .await
        .unwrap();

    let chosen = trigon_api::comparison::bytes_for_view(&store, &d)
        .await
        .unwrap();
    assert_eq!(chosen, serde_json::to_vec(&derived).unwrap());

    let api = operator_over(store, d).await;
    let (status, body) = get(api.clone(), "/v1/runs/1700000001-aa/diff").await;
    assert_eq!(status, 200);
    let view: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        view["progression"]["steps"][1]["pass"], "zip-time",
        "the page did not render the re-derivation: {view}"
    );

    let (status, raw) = get(api, "/v1/runs/1700000001-aa/comparison").await;
    assert_eq!(status, 200);
    assert_eq!(
        raw, recorded,
        "the evidence route served something other than the record"
    );
}

#[tokio::test]
async fn a_rederivation_that_says_anything_different_about_the_verdict_is_ignored() {
    let (recorded, derived) = recorded_and_derived();
    let recorded_view: serde_json::Value = serde_json::from_slice(&recorded).unwrap();
    let mut differing: Vec<(&str, Vec<u8>)> = Vec::new();
    // Every field the verdict rests on, one at a time: both digests and the set on each side, the
    // difference signature and each member count.
    for (what, pointer, value) in [
        ("the outcome", "/outcome", serde_json::json!("normalized")),
        (
            "the upstream raw digest",
            "/upstream/raw/sha256",
            serde_json::json!("00".repeat(32)),
        ),
        (
            "the upstream stabilized digest",
            "/upstream/stabilized/sha256",
            serde_json::json!("22".repeat(32)),
        ),
        (
            "the upstream set",
            "/upstream/set",
            serde_json::json!(["another", "sha256:00"]),
        ),
        (
            "the rebuild raw digest",
            "/rebuild/raw/sha256",
            serde_json::json!("33".repeat(32)),
        ),
        (
            "the rebuild stabilized digest",
            "/rebuild/stabilized/sha256",
            serde_json::json!("11".repeat(32)),
        ),
        (
            "the rebuild set",
            "/rebuild/set",
            serde_json::json!(["another", "sha256:00"]),
        ),
        ("the signature", "/diff/codes", serde_json::json!([])),
        (
            "the identical count",
            "/diff/identical",
            serde_json::json!(99),
        ),
        ("the differing count", "/diff/differs", serde_json::json!(0)),
        (
            "the upstream-only count",
            "/diff/only_upstream",
            serde_json::json!(0),
        ),
        (
            "the rebuild-only count",
            "/diff/only_rebuild",
            serde_json::json!(1),
        ),
        (
            "the executable count",
            "/diff/executable_differs",
            serde_json::json!(1),
        ),
    ] {
        let mut v = derived.clone();
        *v.pointer_mut(pointer)
            .unwrap_or_else(|| panic!("the fixture has no {pointer}")) = value;
        assert_ne!(
            v.pointer(pointer),
            recorded_view.pointer(pointer),
            "{what}: the fixture changed nothing"
        );
        differing.push((what, serde_json::to_vec(&v).unwrap()));
    }
    differing.push(("bytes that are not JSON", b"{ not json".to_vec()));

    for (what, bytes) in differing {
        let store = Arc::new(Store::in_memory());
        let d = store.blobs().put(recorded.clone()).await.unwrap();
        store.put_derived_comparison(&d, &bytes).await.unwrap();

        let chosen = trigon_api::comparison::bytes_for_view(&store, &d)
            .await
            .unwrap();
        assert_eq!(
            chosen, recorded,
            "a re-derivation that changed {what} was chosen"
        );

        let api = operator_over(store, d).await;
        let (status, body) = get(api, "/v1/runs/1700000001-aa/diff").await;
        assert_eq!(status, 200, "{what}");
        let view: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(view["outcome"], recorded_view["outcome"], "{what}");
        assert!(
            view["progression"].is_null(),
            "{what}: the page rendered the re-derivation"
        );
    }
}
