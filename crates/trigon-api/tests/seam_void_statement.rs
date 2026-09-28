//! `GET /v1/runs/{id}/attestation` for a void run: its `void/v1`, and never a verdict.
//!
//! A void run is shown to an anonymous reader, as a void (ADR-0010 safeguard 2), and the route
//! refused it any statement at all, because the only statements a void run had were verdicts: the
//! attestor signed `equivalence/v1` or `divergence/v1` for an open-egress run. `trigon attest`
//! now signs `void/v1` for such a run and no verdict (`docs/19` §4.3), and this route serves that
//! statement to anybody while still refusing a verdict envelope for the run — including one signed
//! before the change. Through `put_run` → `Index::refresh` → the router, against a store on disk.
//!
//! And the other direction: a published run's v1 statement, signed before any of this existed, is
//! still served as it was and still verifies.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches, Withheld};
use trigon_attest::{LocalKey, RunIdentity, Statement, Subject, VOID, VoidFacts};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

const TARGET: &str = "pkg:npm/demo@1.0.0";
const ARTIFACT: &str = "demo-1.0.0.tgz";

fn record(id: &str, egress: &str) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: ARTIFACT.into(),
            sha256: Digest::from_bytes([7u8; 32]),
            bytes: 212,
            stored: true,
        },
        Environment {
            base_image: "example@sha256:0".into(),
            derived_image: None,
            egress: egress.into(),
            isolation: "podman".into(),
            attestable: egress != "open",
            registry_moment: None,
            pin: None,
            guard_manifest: None,
            guarded_members: None,
        },
        "2026-01-01T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = Some("divergent".into());
    r.non_builtin_stabilizer = Some(false);
    r
}

fn target() -> trigon_core::Target {
    trigon_core::Target::new(
        TARGET.parse().unwrap(),
        trigon_core::ArtifactId::new(ARTIFACT),
    )
}

fn key() -> LocalKey {
    LocalKey::from_bytes(&[5u8; 32]).unwrap()
}

/// A signed `void/v1` about the run, as `trigon attest` makes one.
fn void_envelope(r: &RunRecord) -> trigon_attest::Envelope {
    let purl = trigon_core::purl::canonicalize(TARGET).unwrap();
    let st = Statement::void(
        Subject::new(ARTIFACT, &r.upstream.sha256),
        &VoidFacts {
            run: RunIdentity {
                purl: &purl,
                run_id: &r.id,
                started: &r.started,
                finished: None,
                builder_version: None,
                attestor_version: "test",
                egress: &r.environment.egress,
                attestable: r.environment.attestable,
            },
            because: "open_egress",
            guard_trips: &[],
            guard_manifest: None,
            guarded_members: None,
            authored: &[],
            stabilizer_set: None,
            guard_manifest_evidence: None,
            supersedes: None,
        },
    );
    trigon_attest::sign_statement(&st, &key()).unwrap()
}

/// A verdict about the run: what the attestor signed for an open-egress run before it signed
/// voids. The v1 fixture signed at `255d2f5`.
fn legacy_verdict() -> trigon_attest::Envelope {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../trigon/tests/fixtures/v1-statements");
    serde_json::from_slice(&std::fs::read(dir.join("divergence-v1.intoto.json")).unwrap()).unwrap()
}

async fn api_over(
    dir: &std::path::Path,
    runs: Vec<(RunRecord, Vec<(&str, trigon_attest::Envelope)>)>,
    who: Principal,
) -> Arc<Api> {
    let store = Arc::new(Store::local(dir).unwrap());
    for (mut r, statements) in runs {
        for (predicate, env) in statements {
            let path = store
                .put_attestation(&target(), &r.id, ARTIFACT, predicate, &env)
                .await
                .unwrap();
            r.attestations.push(path);
        }
        store.put_run(&r).await.unwrap();
    }
    let index = Index::new();
    index.refresh(&store, Switches::default()).await.unwrap();
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

fn predicates(body: &str) -> Vec<String> {
    let envs: Vec<trigon_attest::Envelope> =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"));
    envs.iter()
        .map(|e| {
            let st: Statement = serde_json::from_slice(&e.decoded_payload().unwrap()).unwrap();
            st.predicate_type
        })
        .collect()
}

#[tokio::test]
async fn an_anonymous_reader_of_a_void_run_is_served_its_void_and_not_its_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let r = record("1789000000-aaaaaaaa", "open");
    let statements = vec![
        ("https://trigon.dev/divergence/v1", legacy_verdict()),
        (VOID, void_envelope(&r)),
    ];
    let anon = api_over(
        dir.path(),
        vec![(r.clone(), statements)],
        Principal::Anonymous,
    )
    .await;
    let (status, body) = get(anon, &format!("/v1/runs/{}/attestation", r.id)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(predicates(&body), [VOID]);
    assert!(!body.contains("divergen"), "{body}");

    // The operator gets both: the verdict is on disk, so its absence above is the gate.
    let dir = tempfile::tempdir().unwrap();
    let op = api_over(
        dir.path(),
        vec![(
            r.clone(),
            vec![
                ("https://trigon.dev/divergence/v1", legacy_verdict()),
                (VOID, void_envelope(&r)),
            ],
        )],
        Principal::Operator,
    )
    .await;
    let (status, body) = get(op, &format!("/v1/runs/{}/attestation", r.id)).await;
    assert_eq!(status, 200, "{body}");
    let mut served = predicates(&body);
    served.sort();
    assert_eq!(served, ["https://trigon.dev/divergence/v1", VOID]);
}

#[tokio::test]
async fn a_void_run_signed_only_as_a_verdict_serves_nothing_and_says_why() {
    // Every run the attestor signed before it signed voids: an open-egress divergence with a
    // `divergence/v1` and nothing else. Refused, in the gate's words, without the word.
    let dir = tempfile::tempdir().unwrap();
    let r = record("1789000100-bbbbbbbb", "open");
    let anon = api_over(
        dir.path(),
        vec![(
            r.clone(),
            vec![("https://trigon.dev/divergence/v1", legacy_verdict())],
        )],
        Principal::Anonymous,
    )
    .await;
    let (status, body) = get(anon, &format!("/v1/runs/{}/attestation", r.id)).await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("no_void_statement"), "{body}");
    assert!(body.contains(Withheld::OpenEgress.sentence()), "{body}");
    assert!(!body.contains("divergen"), "{body}");
}

#[tokio::test]
async fn a_published_runs_v1_statement_is_still_served_and_still_verifies() {
    // Two agreeing attempts, so the gate publishes; the statement is the one signed at
    // `255d2f5`, before v2 existed.
    let dir = tempfile::tempdir().unwrap();
    let mut a = record("1789000200-cccccccc", "mirror-only");
    let mut b = record("1789000300-cccccccc", "mirror-only");
    for (r, host, started) in [
        (&mut a, "machine-id:one", "2026-01-01T00:00:00Z"),
        (&mut b, "machine-id:two", "2026-01-02T00:00:00Z"),
    ] {
        r.cache_key = Some("k".into());
        r.outcome = Some("normalized".into());
        // What both runs found, and where and when each ran: a day apart on two machines.
        r.agreement = Some(Digest::from_bytes([9u8; 32]));
        r.host = Some(host.into());
        r.started = started.into();
        r.cache = Some(trigon_store::CacheState::default());
    }
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../trigon/tests/fixtures/v1-statements");
    let v1: trigon_attest::Envelope = serde_json::from_slice(
        &std::fs::read(fixtures.join("equivalence-v1.intoto.json")).unwrap(),
    )
    .unwrap();
    let anon = api_over(
        dir.path(),
        vec![
            (
                a.clone(),
                vec![("https://trigon.dev/equivalence/v1", v1.clone())],
            ),
            (b, vec![]),
        ],
        Principal::Anonymous,
    )
    .await;
    let (status, body) = get(anon, &format!("/v1/runs/{}/attestation", a.id)).await;
    assert_eq!(status, 200, "{body}");
    let served: Vec<trigon_attest::Envelope> = serde_json::from_str(&body).unwrap();
    assert_eq!(served, std::slice::from_ref(&v1));
    let public = std::fs::read_to_string(fixtures.join("public.hex")).unwrap();
    let e = &served[0];
    assert!(
        trigon_attest::verify_signature(&e.pae().unwrap(), &e.signatures[0], public.trim()).is_ok()
    );
}

#[tokio::test]
async fn a_run_the_guard_stopped_is_shown_as_void_with_its_statement() {
    // As a real void run is recorded: the guard ended the build, so no comparison and no outcome.
    // The gate withheld such a run as `no_outcome`, so its void was published nowhere.
    let dir = tempfile::tempdir().unwrap();
    let mut r = record("1789000400-dddddddd", "mirror-only");
    r.outcome = None;
    r.terminal = Some("void".into());
    r.guard_trips = vec!["package/index.js arrived from registry.npmjs.org".into()];
    let env = void_envelope(&r);
    let anon = api_over(
        dir.path(),
        vec![(r.clone(), vec![(VOID, env.clone())])],
        Principal::Anonymous,
    )
    .await;
    let (status, body) = get(anon.clone(), &format!("/v1/runs/{}", r.id)).await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["entry"]["publication"]["state"], "void", "{doc}");
    assert_eq!(
        doc["entry"]["publication"]["because"], "guard_tripped",
        "{doc}"
    );
    let (status, body) = get(anon, &format!("/v1/runs/{}/attestation", r.id)).await;
    assert_eq!(status, 200, "{body}");
    let served: Vec<trigon_attest::Envelope> = serde_json::from_str(&body).unwrap();
    assert_eq!(served, [env]);
}
