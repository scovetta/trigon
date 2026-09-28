//! `trigon serve` and the evidence repository (`docs/19` §10 phase 6): a run's page and `GET
//! /v1/runs/{id}` show where its record was published, from `RunRecord.published`; and `GET
//! /v1/artifacts/{alg}:{digest}` honours the algorithm it is given — sha256, sha512 or sha1, the
//! digests a run computes over the published artifact — and searches every run, not the newest
//! 500. Through `put_run` → `Index::refresh` → the router, as every seam here is, and with the
//! anonymous gating of phase 0 held: a withheld run is found by no route, and a void one without
//! its outcome.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::{Digest, Sha1, Sha512};
use trigon_store::{ArtifactRef, Environment, Published, RunRecord, RunState, Store};

const TARGET: &str = "pkg:npm/left-pad@1.3.0";

/// A clean run of `TARGET` whose published artifact is `upstream`, with its sha512 and sha1 as a
/// run computes them.
fn run(id: &str, started: &str, key: &str, upstream: u8) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: "left-pad-1.3.0.tgz".into(),
            sha256: Digest::from_bytes([upstream; 32]),
            bytes: 1,
            stored: true,
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
    r.outcome = Some("normalized".into());
    r.cache_key = Some(key.to_string());
    r.non_builtin_stabilizer = Some(false);
    r.agreement = Some(trigon_store::digest_of(b"normalized"));
    r.host = Some(format!("machine-id:{id}"));
    r.cache = Some(trigon_store::CacheState::default());
    r.upstream_digests = Some(trigon_store::UpstreamDigests {
        sha512: Sha512([upstream; 64]),
        sha1: Some(Sha1([upstream; 20])),
        declared: Vec::new(),
        note: None,
    });
    r
}

/// Two agreeing attempts at one cache key, a day apart on two machines: a pair the gate publishes.
fn published_pair(tag: &str, upstream: u8) -> Vec<RunRecord> {
    vec![
        run(
            &format!("1700000001-{tag}"),
            "2026-01-01T00:00:00Z",
            tag,
            upstream,
        ),
        run(
            &format!("1700090001-{tag}"),
            "2026-01-02T01:00:00Z",
            tag,
            upstream,
        ),
    ]
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
    let bytes = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn get_json(api: Arc<Api>, path: &str) -> (u16, serde_json::Value) {
    let (status, body) = get(api, path).await;
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body)),
    )
}

/// A run with a published record shows where: the repository, the commit, the record's digest and
/// the path of its file, and its leaf — to an anonymous reader as to an operator, since the record
/// is already public in the repository it names — in `GET /v1/runs/{id}` and in the run page's
/// document. A run with none shows none.
#[tokio::test]
async fn a_runs_published_record_is_shown_where_it_was_published() {
    let mut runs = published_pair("a", 1);
    let record = Digest::from_bytes([0x7f; 32]);
    runs[0].published = Some(Published {
        repository: "https://github.com/owner/trigon-evidence.git".into(),
        commit: "c0ffee".into(),
        record,
        leaf: 12,
        log: None,
    });
    let id = runs[0].id.clone();
    let other = runs[1].id.clone();
    for who in [Principal::Anonymous, Principal::Operator] {
        let api = api_over(&runs, who).await;
        let (status, doc) = get_json(api.clone(), &format!("/v1/runs/{id}")).await;
        assert_eq!(status, 200, "{doc}");
        let p = &doc["published"];
        assert_eq!(
            p["repository"], "https://github.com/owner/trigon-evidence.git",
            "{who:?}: {doc}"
        );
        assert_eq!(p["commit"], "c0ffee");
        assert_eq!(p["record"], format!("sha256:{}", record.to_hex()));
        assert_eq!(
            p["path"],
            format!("records/7f/7f/{}.json", record.to_hex()),
            "{doc}"
        );
        assert_eq!(p["leaf"], 12);
        assert_eq!(p["log"], "log");
        // The record says it too, in its own field.
        assert_eq!(doc["record"]["published"]["leaf"], 12, "{doc}");
        // The other attempt of the pair was not published as its own record.
        let (_, doc) = get_json(api.clone(), &format!("/v1/runs/{other}")).await;
        assert!(doc["published"].is_null(), "{doc}");
        // The page a permalink opens carries it in its boot island, as the route gives it.
        let (status, page) = get(api, &format!("/runs/{id}")).await;
        assert_eq!(status, 200);
        assert!(
            page.contains(&format!("records/7f/7f/{}.json", record.to_hex())),
            "the run page's document does not carry where its record was published"
        );
    }
}

/// `GET /v1/artifacts/{alg}:{digest}` matches the digest of the algorithm it names, and a bare
/// digest by its length: a sha512 is what an npm lockfile holds, and it matched nothing when the
/// algorithm was discarded and every digest compared with the sha256.
#[tokio::test]
async fn the_artifact_route_honours_the_algorithm_it_is_given() {
    let runs = published_pair("a", 1);
    let api = api_over(&runs, Principal::Anonymous).await;
    let hex = |n: usize| format!("{:02x}", 1u8).repeat(n);
    for path in [
        format!("/v1/artifacts/sha256:{}", hex(32)),
        format!("/v1/artifacts/sha512:{}", hex(64)),
        format!("/v1/artifacts/sha1:{}", hex(20)),
        format!("/v1/artifacts/SHA512:{}", hex(64).to_uppercase()),
        format!("/v1/artifacts/{}", hex(32)),
        format!("/v1/artifacts/{}", hex(64)),
        format!("/v1/artifacts/{}", hex(20)),
    ] {
        let (status, doc) = get_json(api.clone(), &path).await;
        assert_eq!(status, 200, "{path}: {doc}");
        assert_eq!(doc.as_array().unwrap().len(), 2, "{path}: {doc}");
    }
    // The sha512 of another artifact, whose first 32 bytes are this one's sha256: not a match, as
    // it was when the algorithm was discarded and the hex compared with the sha256.
    let (status, _) = get_json(
        api.clone(),
        &format!("/v1/artifacts/sha512:{}{}", hex(32), "00".repeat(32)),
    )
    .await;
    assert_eq!(status, 404);
    // Another algorithm, or a digest of the wrong length, is refused, never guessed at.
    let (status, doc) = get_json(api.clone(), &format!("/v1/artifacts/md5:{}", hex(16))).await;
    assert_eq!(status, 400, "{doc}");
    assert_eq!(doc["error"], "unknown_algorithm");
    let (status, doc) = get_json(api, &format!("/v1/artifacts/sha512:{}", hex(32))).await;
    assert_eq!(status, 400, "{doc}");
    assert_eq!(doc["error"], "malformed_digest");
}

/// Every run is searched: an artifact whose only runs are older than 600 newer ones is still
/// found, where a page of the newest 500 missed it and read it as never checked.
#[tokio::test]
async fn the_artifact_route_searches_every_run() {
    let mut runs = published_pair("old", 9);
    for i in 0..600u32 {
        let mut r = run(
            &format!("1800{i:06}-new"),
            &format!("2026-06-01T00:{:02}:{:02}Z", i / 60, i % 60),
            &format!("new-{i}"),
            2,
        );
        r.upstream.sha256 = Digest::from_bytes([2; 32]);
        runs.push(r);
    }
    let api = api_over(&runs, Principal::Operator).await;
    let (status, doc) = get_json(api, &format!("/v1/artifacts/sha512:{}", "09".repeat(64))).await;
    assert_eq!(status, 200, "{doc}");
    assert_eq!(doc.as_array().unwrap().len(), 2, "{doc}");
}

/// Phase 0's gating holds for every algorithm: a withheld run is found by none, anonymously, and
/// is found by an operator.
#[tokio::test]
async fn a_withheld_run_is_found_by_no_algorithm_anonymously() {
    // One attempt, alone at its cache key: withheld, awaiting confirmation.
    let runs = vec![run("1700000001-alone", "2026-01-01T00:00:00Z", "alone", 5)];
    let anon = api_over(&runs, Principal::Anonymous).await;
    let op = api_over(&runs, Principal::Operator).await;
    for path in [
        format!("/v1/artifacts/sha256:{}", "05".repeat(32)),
        format!("/v1/artifacts/sha512:{}", "05".repeat(64)),
        format!("/v1/artifacts/sha1:{}", "05".repeat(20)),
    ] {
        let (status, body) = get(anon.clone(), &path).await;
        assert_eq!(status, 404, "{path}: {body}");
        assert!(!body.contains("normalized"), "{path}: {body}");
        let (status, _) = get(op.clone(), &path).await;
        assert_eq!(status, 200, "{path}");
    }
}
