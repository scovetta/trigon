//! `GET /v1/runs/{id}/attestation` serves each run its own statements, whichever layout filed them.
//!
//! Statements used to be filed per target, so attesting a second run of one package overwrote the
//! first run's, and the route then served the second run's claim for the first run's id. They are
//! filed per run now (`docs/19` §10 phase 2), and runs attested before that still name the old
//! per-target paths. Both go through `put_run` → `Index::refresh` → the handler, against a store on
//! disk, because the property is about what a reader is served.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

const TARGET: &str = "pkg:npm/left-pad@1.3.0";

fn record(id: &str) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: "left-pad-1.3.0.tgz".into(),
            sha256: Digest::from_bytes([7u8; 32]),
            bytes: 3619,
            stored: true,
        },
        Environment {
            base_image: "example@sha256:0".into(),
            derived_image: None,
            egress: "mirror-only".into(),
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
    r.outcome = Some("exact".into());
    r.non_builtin_stabilizer = Some(false);
    r
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

#[tokio::test]
async fn each_run_is_served_its_own_statement_in_either_layout() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::local(dir.path()).unwrap());
    let target = trigon_core::Target::new(
        TARGET.parse().unwrap(),
        trigon_core::ArtifactId::new("left-pad-1.3.0.tgz"),
    );

    // A run attested before per-run filing: its statement sits at the per-target path, written
    // here as the old writer wrote it, and its record names that path.
    let old_path = "attestations/npm/left-pad/1.3.0/left-pad-1.3.0.tgz/equivalence.intoto.json";
    let old_env = trigon_attest::Envelope::new(b"the statement signed for the older run", vec![]);
    let file = dir.path().join(old_path);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, serde_json::to_vec_pretty(&old_env).unwrap()).unwrap();
    let mut older = record("1789000000-870c0fe1");
    older.attestations = vec![old_path.into()];

    // Two runs of the same target attested since, each under its own id.
    let mut newer = Vec::new();
    for (id, payload) in [
        (
            "1789000100-870c0fe1",
            &b"the first newer run's statement"[..],
        ),
        (
            "1789000200-870c0fe1",
            &b"the second newer run's statement"[..],
        ),
    ] {
        let env = trigon_attest::Envelope::new(payload, vec![]);
        let path = store
            .put_attestation(
                &target,
                id,
                "left-pad-1.3.0.tgz",
                "https://trigon.dev/equivalence/v1",
                &env,
            )
            .await
            .unwrap();
        let mut r = record(id);
        r.attestations = vec![path];
        newer.push((r, env));
    }

    for r in std::iter::once(&older).chain(newer.iter().map(|(r, _)| r)) {
        store.put_run(r).await.unwrap();
    }
    let index = Index::new();
    index.refresh(&store, Switches::default()).await.unwrap();
    let api = Arc::new(Api {
        store,
        queue: None,
        index,
        switches: Switches::default(),
        // The operator, because the gate is not what this is about: `seam_public_surface.rs`
        // covers who may read a statement, and this covers which statement they are given.
        unauthenticated: Principal::Operator,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    });

    let served = |body: &str| -> Vec<trigon_attest::Envelope> {
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
    };
    let (status, body) = get(api.clone(), &format!("/v1/runs/{}/attestation", older.id)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(served(&body), [old_env], "the per-target path still reads");

    for (r, env) in &newer {
        let (status, body) = get(api.clone(), &format!("/v1/runs/{}/attestation", r.id)).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            served(&body),
            std::slice::from_ref(env),
            "{} was served a statement that is not its own",
            r.id
        );
    }
}

#[tokio::test]
async fn a_run_attested_again_is_served_its_own_statements_and_not_a_shared_per_target_one() {
    // Two runs of one target attested before per-run filing named the same per-target path, and
    // the later one's attest wrote over it: the file now holds the second run's claim. The first
    // run, attested again, gets statements under its own id — and used to keep the shared path
    // beside them, so it went on being served the other run's statement, which may be a withheld
    // divergence. Re-attesting sets the shared path aside, the same calls the attestor makes.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::local(dir.path()).unwrap());
    let target = trigon_core::Target::new(
        TARGET.parse().unwrap(),
        trigon_core::ArtifactId::new("left-pad-1.3.0.tgz"),
    );
    let shared = "attestations/npm/left-pad/1.3.0/left-pad-1.3.0.tgz/equivalence.intoto.json";
    let theirs = trigon_attest::Envelope::new(b"the later run's statement, written over", vec![]);
    let file = dir.path().join(shared);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, serde_json::to_vec_pretty(&theirs).unwrap()).unwrap();

    let mut first = record("1789000000-870c0fe1");
    first.attestations = vec![shared.into()];
    let mut later = record("1789000100-870c0fe1");
    later.attestations = vec![shared.into()];
    store.put_run(&first).await.unwrap();
    store.put_run(&later).await.unwrap();

    // The first run, attested again.
    let own = trigon_attest::Envelope::new(b"the first run's own statement", vec![]);
    let path = store
        .put_attestation(
            &target,
            &first.id,
            "left-pad-1.3.0.tgz",
            "https://trigon.dev/equivalence/v1",
            &own,
        )
        .await
        .unwrap();
    let named = store
        .record_attestations(&first.id, std::slice::from_ref(&path))
        .await
        .unwrap();
    assert_eq!(named.attestations, [path]);
    assert_eq!(named.per_target_attestations, [shared]);

    let index = Index::new();
    index.refresh(&store, Switches::default()).await.unwrap();
    let api = Arc::new(Api {
        store,
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: Principal::Operator,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    });
    let served = |body: &str| -> Vec<trigon_attest::Envelope> {
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
    };

    let (status, body) = get(api.clone(), &format!("/v1/runs/{}/attestation", first.id)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        served(&body),
        [own],
        "the first run was served a statement another run wrote"
    );

    // The later run, never attested again, still reads its per-target path, which is its own.
    let (status, body) = get(api, &format!("/v1/runs/{}/attestation", later.id)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(served(&body), [theirs]);
}
