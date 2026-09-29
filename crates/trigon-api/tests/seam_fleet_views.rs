//! The three fleet views: what they sniff, what they gate, and what they never divide.
//!
//! `POST /v1/check` is the only anonymous route that takes a body somebody else composed, and the
//! only one that has to *guess* what that body is. `GET /v1/clusters` reads build-log-derived
//! text and is class-gated for it. Both decisions are one-line tests in the handler with nothing
//! asserting them, and both fail quietly: a body read as the wrong format reports zero packages,
//! which a reader sees as nothing to worry about, and a gate that stops admitting is invisible
//! until someone reads a log they should not have.

use std::sync::Arc;

use trigon_api::{Api, Index, Principal, Switches};
use trigon_core::{Digest, FailureSignature, Fault};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn env() -> Environment {
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
    }
}

fn record(id: &str, target: &str, outcome: Option<&str>) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        target,
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([7u8; 32]),
            bytes: 1,
            stored: true,
        },
        env(),
        "2026-01-01T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = outcome.map(str::to_string);
    r.non_builtin_stabilizer = Some(false);
    r
}

/// A failed run carrying a signature, which is what a cluster is made of.
fn failed(
    id: &str,
    target: &str,
    code: &'static str,
    subject: Option<&str>,
    when: &str,
) -> RunRecord {
    let mut r = record(id, target, None);
    r.finished = Some(when.to_string());
    r.failure = Some(FailureSignature {
        code: code.into(),
        subject: subject.map(str::to_string),
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        evidence: "fatal error: Python.h: No such file or directory".into(),
    });
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
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: who,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    })
}

async fn send(api: Arc<Api>, method: &str, path: &str, body: &str) -> (u16, serde_json::Value) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut router = trigon_api::router(api);
    let res = router
        .call(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = res.status().as_u16();
    // Generous, because `/v1/check` answers with one row per package and the cap it enforces is
    // on the request. A 3 MiB requirements file is ~160,000 rows.
    let bytes = axum::body::to_bytes(res.into_body(), 256 << 20)
        .await
        .expect("body");
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, json)
}

async fn check(api: Arc<Api>, body: &str) -> (u16, serde_json::Value) {
    send(api, "POST", "/v1/check", body).await
}

async fn get(api: Arc<Api>, path: &str) -> (u16, serde_json::Value) {
    send(api, "GET", path, "").await
}

// ---------------------------------------------------------------------------
// POST /v1/check — the one route that has to guess what it was given
// ---------------------------------------------------------------------------

const NPM_LOCK: &str = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/left-pad": { "version": "1.3.0" }
  }
}"#;

const REQUIREMENTS: &str = "requests==2.31.0\nurllib3==2.0.7\n";

const SPDX: &str = r#"{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "app",
  "packages": [
    { "name": "left-pad", "versionInfo": "1.3.0", "externalRefs": [
      { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
        "referenceLocator": "pkg:npm/left-pad@1.3.0" } ] }
  ]
}"#;

#[tokio::test]
async fn each_lockfile_shape_is_read_as_itself() {
    // A POST carries no file name, so the shape is sniffed from the first byte and, for JSON, from
    // whether it says SPDX. Getting it wrong is not an error — it is a successful parse of zero
    // packages, which reads as a clean bill of health.
    let api = api_over(Vec::new(), Principal::Anonymous).await;

    for (what, body) in [
        ("npm lock", NPM_LOCK),
        ("requirements", REQUIREMENTS),
        ("spdx", SPDX),
    ] {
        let (status, doc) = check(Arc::clone(&api), body).await;
        assert_eq!(status, 200, "{what}: {doc}");
        assert!(
            doc["packages"].as_u64().unwrap_or(0) > 0,
            "{what} was sniffed as something else and read as zero packages: {doc}"
        );
    }
}

#[tokio::test]
async fn an_unreadable_body_is_refused_rather_than_read_as_empty() {
    let api = api_over(Vec::new(), Principal::Anonymous).await;
    let (status, doc) = check(api, "{ this is not json at all ").await;
    assert_eq!(status, 400, "{doc}");
    assert_eq!(doc["error"], "unreadable_lockfile", "{doc}");
}

/// The cap the handler documents. The test states it independently so that changing one number in
/// the source without changing the other is a failure rather than a silent narrowing.
const MAX_LOCKFILE: usize = 8 << 20;

#[tokio::test]
async fn a_lockfile_larger_than_the_cap_is_refused_with_both_numbers() {
    // A lockfile is a body somebody else composed. The refusal names the cap so the reader knows
    // whether to split the file or give up.
    //
    // One byte over, because this is also the regression test for the two caps: axum buffers a
    // body up to its own limit before any handler runs, and at `MAX_LOCKFILE + 1` the request has
    // to still arrive for the handler to be the thing that refuses it.
    let api = api_over(Vec::new(), Principal::Anonymous).await;
    let over = "#".repeat(MAX_LOCKFILE + 1);
    let (status, doc) = check(api, &over).await;
    assert_eq!(status, 413, "{doc}");
    assert_eq!(
        doc["error"], "lockfile_too_large",
        "the framework refused before the handler, so the refusal lost its error code: {doc}"
    );
    let detail = doc["detail"].as_str().unwrap_or_default();
    // Both figures round to the same string one byte over the cap, which is the honest thing for
    // a reader to see: the file is not meaningfully bigger than what we read.
    assert!(
        detail.contains("8.0 MB"),
        "the cap is not in the message: {detail}"
    );
}

#[tokio::test]
async fn a_lockfile_the_handler_says_it_reads_is_not_refused_by_the_transport() {
    // The bug this pins. `MAX_LOCKFILE` documents eight MiB as "a 40,000-package
    // package-lock.json with room over", but axum caps a buffered body at 2 MiB by default, so
    // the eight was never the number that applied: a 3 MiB lockfile — comfortably inside what the
    // route claims to read — came back as a plain-text `length limit exceeded` with no error code
    // at all. Two caps on one quantity, one of them invisible, disagreeing.
    let api = api_over(Vec::new(), Principal::Anonymous).await;

    // Real requirements lines, so this measures the cap rather than the parser's tolerance.
    let mut body = String::with_capacity(3 << 20);
    let mut n = 0u32;
    while body.len() < (3 << 20) {
        body.push_str(&format!("package-{n}==1.0.{n}\n"));
        n += 1;
    }
    assert!(
        body.len() > (2 << 20),
        "the fixture has to exceed axum's default limit"
    );
    assert!(
        body.len() < MAX_LOCKFILE,
        "and stay inside the documented cap"
    );

    let (status, doc) = check(api, &body).await;
    assert_eq!(
        status, 200,
        "a lockfile inside the documented cap was refused: {doc}"
    );
    assert_eq!(
        doc["packages"].as_u64(),
        Some(n as u64),
        "{}",
        doc["packages"]
    );
}

#[tokio::test]
async fn the_tally_names_all_five_verdicts_even_at_zero() {
    // Absent is not zero anywhere else in this system, but a tally is a count over a known set of
    // labels: a missing `divergent` key would make a reader's chart silently drop a category
    // rather than draw it at zero.
    let api = api_over(Vec::new(), Principal::Anonymous).await;
    let (status, doc) = check(api, REQUIREMENTS).await;
    assert_eq!(status, 200);
    for label in [
        "reproduced",
        "caveats",
        "divergent",
        "unsupported",
        "never checked",
    ] {
        assert!(
            doc["tally"].get(label).is_some(),
            "`{label}` is missing from the tally: {doc}"
        );
    }
}

#[tokio::test]
async fn the_check_reports_counts_and_never_a_rate() {
    // `unsupported` and `never checked` have different denominators from the three verdicts and
    // from each other. One percentage over the lot would be a number with no meaning, so the
    // response carries no rate field at all.
    let api = api_over(Vec::new(), Principal::Anonymous).await;
    let (_, doc) = check(api, REQUIREMENTS).await;
    let text = doc.to_string();
    for forbidden in [
        "\"rate\"",
        "\"percent\"",
        "\"percentage\"",
        "\"success_rate\"",
    ] {
        assert!(
            !text.contains(forbidden),
            "the check grew a {forbidden} field: {text}"
        );
    }
}

#[tokio::test]
async fn a_package_nobody_ran_is_never_checked_not_a_failure() {
    // "No run exists" is not a judgement about the package, and a reader who cannot tell it from
    // a divergence is being told something false.
    let api = api_over(Vec::new(), Principal::Anonymous).await;
    let (_, doc) = check(api, REQUIREMENTS).await;
    let rows = doc["results"].as_array().expect("results");
    assert!(!rows.is_empty());
    for row in rows {
        assert_eq!(row["status"], "never checked", "{row}");
        assert!(
            row["run"].is_null(),
            "a never-checked row named a run: {row}"
        );
    }
}

#[tokio::test]
async fn a_package_with_a_run_carries_the_run_id_back() {
    let api = api_over(
        vec![record(
            "1700000001-aa",
            "pkg:pypi/requests@2.31.0",
            Some("exact"),
        )],
        Principal::Operator,
    )
    .await;
    let (_, doc) = check(api, REQUIREMENTS).await;
    let rows = doc["results"].as_array().expect("results");
    let hit = rows
        .iter()
        .find(|r| r["name"] == "requests")
        .expect("requests row");
    assert_eq!(hit["status"], "reproduced", "{hit}");
    assert_eq!(hit["run"], "1700000001-aa", "{hit}");
    // The row that had no run keeps saying so.
    let miss = rows
        .iter()
        .find(|r| r["name"] == "urllib3")
        .expect("urllib3 row");
    assert_eq!(miss["status"], "never checked", "{miss}");
}

// ---------------------------------------------------------------------------
// GET /v1/clusters — gated, because a signature is derived from a build log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_anonymous_reader_cannot_see_failure_subjects() {
    // The count is not the sensitive part; the subject is. `FailureSignature::subject` carries
    // paths and, despite the rule its own doc states, sometimes package names.
    let api = api_over(
        vec![failed(
            "1700000001-aa",
            "pkg:pypi/x@1",
            "pypi/missing-header",
            Some("Python.h"),
            "2026-01-01T00:00:01Z",
        )],
        Principal::Anonymous,
    )
    .await;
    let (status, doc) = get(api, "/v1/clusters").await;
    assert_eq!(status, 403, "{doc}");
    assert!(
        !doc.to_string().contains("Python.h"),
        "the gate leaked the subject: {doc}"
    );
}

#[tokio::test]
async fn runs_that_failed_the_same_way_are_one_cluster() {
    // Five hundred failures are twelve causes. The signature key is what says which twelve, and it
    // is the same string that keys the repair cache — so a cluster is exactly the set of runs one
    // fix would move.
    let api = api_over(
        vec![
            failed(
                "1700000001-aa",
                "pkg:pypi/x@1",
                "pypi/missing-header",
                Some("Python.h"),
                "2026-01-01T00:00:03Z",
            ),
            failed(
                "1700000002-bb",
                "pkg:pypi/y@1",
                "pypi/missing-header",
                Some("Python.h"),
                "2026-01-01T00:00:01Z",
            ),
            failed(
                "1700000003-cc",
                "pkg:npm/z@1",
                "npm/no-lockfile",
                None,
                "2026-01-01T00:00:02Z",
            ),
        ],
        Principal::Operator,
    )
    .await;
    let (status, doc) = get(api, "/v1/clusters").await;
    assert_eq!(status, 200, "{doc}");

    let clusters = doc["clusters"].as_array().expect("clusters");
    assert_eq!(clusters.len(), 2, "{doc}");
    // Biggest first: the point of the view is which fix moves the most.
    assert_eq!(clusters[0]["count"], 2, "{doc}");
    assert_eq!(clusters[0]["key"], "pypi/missing-header:Python.h", "{doc}");
    assert_eq!(clusters[1]["count"], 1, "{doc}");

    // The window spans every run in the cluster, not just the one that landed last.
    assert_eq!(clusters[0]["first_seen"], "2026-01-01T00:00:01Z", "{doc}");
    assert_eq!(clusters[0]["last_seen"], "2026-01-01T00:00:03Z", "{doc}");
}

#[tokio::test]
async fn a_cluster_spanning_ecosystems_names_each_one_once() {
    let api = api_over(
        vec![
            failed(
                "1700000001-aa",
                "pkg:pypi/x@1",
                "generic/oom",
                None,
                "2026-01-01T00:00:01Z",
            ),
            failed(
                "1700000002-bb",
                "pkg:npm/y@1",
                "generic/oom",
                None,
                "2026-01-01T00:00:02Z",
            ),
            failed(
                "1700000003-cc",
                "pkg:npm/z@1",
                "generic/oom",
                None,
                "2026-01-01T00:00:03Z",
            ),
        ],
        Principal::Operator,
    )
    .await;
    let (_, doc) = get(api, "/v1/clusters").await;
    let ecos = doc["clusters"][0]["ecosystems"]
        .as_array()
        .expect("ecosystems");
    assert_eq!(ecos.len(), 2, "{doc}");
    assert!(
        ecos.contains(&serde_json::json!("npm")) && ecos.contains(&serde_json::json!("pypi")),
        "{doc}"
    );
}

#[tokio::test]
async fn a_run_that_did_not_fail_is_in_no_cluster() {
    let api = api_over(
        vec![record("1700000001-aa", "pkg:pypi/x@1", Some("exact"))],
        Principal::Operator,
    )
    .await;
    let (status, doc) = get(api, "/v1/clusters").await;
    assert_eq!(status, 200);
    assert!(
        doc["clusters"].as_array().expect("clusters").is_empty(),
        "{doc}"
    );
}

// ---------------------------------------------------------------------------
// GET /v1/fleet — is it running, and whose answer is this
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_fleet_view_says_which_principal_it_answered_for() {
    // An operator's fleet page counts the whole corpus and an anonymous one counts what the gate
    // released. Two different true answers to one question, and a reader comparing two numbers
    // needs to know which they are holding.
    for (who, want) in [
        (Principal::Anonymous, "anonymous"),
        (Principal::Operator, "operator"),
    ] {
        let api = api_over(
            vec![record("1700000001-aa", "pkg:pypi/x@1", Some("exact"))],
            who,
        )
        .await;
        let (status, doc) = get(api, "/v1/fleet").await;
        assert_eq!(status, 200, "{doc}");
        assert_eq!(doc["principal"], want, "{doc}");
    }
}

#[tokio::test]
async fn the_fleet_view_keeps_the_two_denominators_apart() {
    // `by_outcome` and `by_fault` answer different questions — a package that did not reproduce,
    // and a build we could not run — and one number over both would answer neither.
    let api = api_over(
        vec![
            record("1700000001-aa", "pkg:pypi/x@1", Some("exact")),
            failed(
                "1700000002-bb",
                "pkg:npm/y@1",
                "generic/oom",
                None,
                "2026-01-01T00:00:02Z",
            ),
        ],
        Principal::Operator,
    )
    .await;
    let (_, doc) = get(api, "/v1/fleet").await;
    assert!(doc["corpus"]["by_outcome"].is_object(), "{doc}");
    assert!(doc["corpus"]["by_fault"].is_object(), "{doc}");
    let text = doc["corpus"].to_string();
    for forbidden in ["\"rate\"", "\"percent\"", "\"success_rate\""] {
        assert!(
            !text.contains(forbidden),
            "the corpus summary grew a {forbidden}: {text}"
        );
    }
}

#[tokio::test]
async fn an_instance_with_no_queue_reports_null_rather_than_breaking() {
    // The shape stage 1 shipped: an instance that reads a corpus out of object storage and runs
    // nothing. The fleet page still has to render.
    let api = api_over(Vec::new(), Principal::Operator).await;
    let (status, doc) = get(api, "/v1/fleet").await;
    assert_eq!(status, 200, "{doc}");
    assert!(doc["queue"].is_null(), "{doc}");
}
