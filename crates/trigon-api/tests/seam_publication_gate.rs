//! The publication gate, asked by every anonymous answer that can carry a verdict.
//!
//! `POST /v1/check` answered from `Index::newest_for`, which never asks the gate, so a withheld
//! divergence reached anyone as `divergent`, and its doc comment said the opposite
//! (`docs/16-findings.md` §3.92). Filtering on "public" would not have been enough:
//! `Publication::is_public` is true for a void, and the outcome of an open-egress divergence is
//! still `divergent`, so every route that filtered on the one and serialized the other published
//! the accusation safeguard 2 exists to turn into a void. These are `docs/19` §10 phase 0's
//! done-when, one test each, through `put_run` → `Index::refresh` → the router, because what is
//! asserted is what reaches a reader and every shortcut past the store is a step no reader takes.

use std::sync::{Arc, LazyLock};

use trigon_api::{Api, Index, Principal, Switches, Withheld};
use trigon_core::Digest;
use trigon_store::queue::{NewJob, Queue, Tier};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

const TARGET: &str = "pkg:pypi/requests@2.31.0";

/// The lockfile every check here reads: one package, the one the fixtures ran.
const LOCKFILE: &str = "requests==2.31.0\n";

/// A clean run: mirror-only, no guard trip, every pass built in. What the gate decides about it is
/// then a matter of how many attempts agree, which each test sets through its cache key.
fn run(id: &str, outcome: &str, started: &str, key: &str) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: "requests-2.31.0.tar.gz".into(),
            sha256: Digest::from_bytes([7u8; 32]),
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
    r.outcome = Some(outcome.to_string());
    r.cache_key = Some(key.to_string());
    r.non_builtin_stabilizer = Some(false);
    r
}

/// Two agreeing attempts at one cache key, which is what safeguard 1 asks for.
fn published(ids: [&str; 2], outcome: &str, started: [&str; 2], key: &str) -> Vec<RunRecord> {
    vec![
        run(ids[0], outcome, started[0], key),
        run(ids[1], outcome, started[1], key),
    ]
}

/// One attempt, alone at its cache key: withheld, awaiting confirmation.
fn withheld(id: &str, outcome: &str, started: &str) -> RunRecord {
    run(id, outcome, started, &format!("alone-{id}"))
}

/// The three clauses of safeguard 2, each of which turns a divergence into a void.
const VOID_CAUSES: [Withheld; 3] = [
    Withheld::OpenEgress,
    Withheld::GuardTripped,
    Withheld::NonBuiltinStabilizer,
];

/// One attempt, void for `cause`. A void needs no second attempt, because it makes no claim a
/// second attempt could confirm, so a single run is enough to be shown.
fn void(id: &str, outcome: &str, started: &str, cause: Withheld) -> RunRecord {
    let mut r = withheld(id, outcome, started);
    match cause {
        Withheld::OpenEgress => r.environment.egress = "open".into(),
        Withheld::GuardTripped => r
            .guard_trips
            .push("the build fetched its own published artifact".into()),
        Withheld::NonBuiltinStabilizer => r.non_builtin_stabilizer = Some(true),
        other => panic!("{other:?} does not void a run"),
    }
    r
}

/// A real stored comparison of two archives that differ, as `trigon-compare` writes one.
///
/// Real, because the rendered diff and the run page's boot island are made from it, and a digest
/// naming no blob would have them return nothing whatever the gate decided — which a test of the
/// gate would then pass for the wrong reason. Built once, so every store holds the same bytes.
static COMPARISON: LazyLock<Vec<u8>> = LazyLock::new(|| {
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
    ]);
    let rb = zip(&[
        ("same.txt", b"identical"),
        ("differs.txt", b"rebuild side!"),
    ]);
    let set = trigon_stabilize::default_for(trigon_core::Format::Zip);
    let c = trigon_compare::compare_bytes(
        up,
        rb,
        trigon_core::Format::Zip,
        &set,
        &trigon_archive::Limits::default(),
    )
    .expect("compare");
    assert_eq!(
        c.outcome,
        trigon_core::Match::Divergent,
        "the fixture has to diverge"
    );
    serde_json::to_vec(&c).expect("serialize")
});

async fn api_over(records: Vec<RunRecord>, who: Principal) -> Arc<Api> {
    api_with(records, who, None).await
}

/// A queue holding one job for [`TARGET`], with the events the engine and the worker write for it:
/// a first attempt that compared and could not record, then a second that recorded.
///
/// `label` is what `worker.rs` notes as `outcome` — `ran.outcome.label()`, the comparison's own
/// word, written for every attempt before the gate has decided anything — and what the engine's
/// retry note carries when the record is missing (`"{label} produced no record"`). Written with
/// `Queue::event`, which is all `Progress::note` and `Progress::phase` do.
async fn queue_after(dir: &tempfile::TempDir, label: &str) -> (Queue, i64) {
    let queue = Queue::open(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("q.db").display()
    ))
    .await
    .expect("open");
    queue.migrate().await.expect("migrate");
    let job = queue
        .enqueue(&NewJob::rebuild(TARGET, "k1", Tier::Regression))
        .await
        .expect("enqueue");
    let no_record = format!("{label} produced no record");
    for (phase, detail) in [
        ("leased", None),
        ("rebuild", None),
        ("outcome", Some(label)),
        ("retrying", Some(no_record.as_str())),
        ("leased", None),
        ("rebuild", None),
        ("outcome", Some(label)),
        ("recorded", None),
    ] {
        queue.event(job, phase, detail).await.expect("event");
    }
    (queue, job)
}

async fn api_with(records: Vec<RunRecord>, who: Principal, queue: Option<Queue>) -> Arc<Api> {
    let store = Arc::new(Store::in_memory());
    store
        .blobs()
        .put(COMPARISON.clone())
        .await
        .expect("put comparison");
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
        queue,
        index,
        switches: Switches::default(),
        unauthenticated: who,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
    })
}

/// Send a request through the real router and return `(status, body)`.
async fn send(api: Arc<Api>, method: &str, path: &str, body: &str) -> (u16, String) {
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
    let bytes = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn get(api: Arc<Api>, path: &str) -> (u16, String) {
    send(api, "GET", path, "").await
}

async fn get_json(api: Arc<Api>, path: &str) -> (u16, serde_json::Value) {
    let (status, body) = get(api, path).await;
    let doc = serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body));
    (status, doc)
}

/// The check's one row, and its tally.
async fn check(api: Arc<Api>) -> (serde_json::Value, serde_json::Value) {
    let (status, body) = send(api, "POST", "/v1/check", LOCKFILE).await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("the check answers in JSON");
    let rows = doc["results"].as_array().expect("results");
    assert_eq!(rows.len(), 1, "{doc}");
    (rows[0].clone(), doc["tally"].clone())
}

// ---------------------------------------------------------------------------
// POST /v1/check, anonymous: only what the gate releases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_anonymous_check_reports_a_withheld_divergence_as_never_checked() {
    let runs = vec![withheld(
        "1700000001-aa",
        "divergent",
        "2026-01-01T00:00:00Z",
    )];

    let (row, tally) = check(api_over(runs.clone(), Principal::Anonymous).await).await;
    assert_eq!(row["status"], "never checked", "{row}");
    // Nothing that would let the reader find the run the gate is holding back: a run id beside
    // `never checked` would say there is something here worth not showing.
    assert!(row["run"].is_null(), "{row}");
    assert!(row["detail"].is_null(), "{row}");
    assert_eq!(tally["divergent"], 0, "{tally}");
    assert_eq!(tally["never checked"], 1, "{tally}");

    // The route's other half, and the control that makes the above a test of the gate rather than
    // of an empty index: an operator reading their own store is answered as `trigon check`
    // answers from it, newest run and ungated.
    let (row, _) = check(api_over(runs, Principal::Operator).await).await;
    assert_eq!(row["status"], "divergent", "{row}");
    assert_eq!(row["run"], "1700000001-aa", "{row}");
}

#[tokio::test]
async fn an_anonymous_check_reports_a_void_divergence_as_unsupported_with_its_reason() {
    for cause in VOID_CAUSES {
        let runs = vec![void(
            "1700000001-aa",
            "divergent",
            "2026-01-01T00:00:00Z",
            cause,
        )];
        let (row, tally) = check(api_over(runs, Principal::Anonymous).await).await;

        assert_eq!(row["status"], "unsupported", "{cause:?}: {row}");
        assert_eq!(tally["divergent"], 0, "{cause:?}: {tally}");
        // With its reason: "we looked and could not tell" is only useful with the because.
        let detail = row["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains(cause.sentence()),
            "{cause:?}: the row does not say why it is void: {row}"
        );
        // Named, because a void is published and its page says the same at more length.
        assert_eq!(row["run"], "1700000001-aa", "{cause:?}: {row}");
        assert!(
            !row.to_string().contains("divergent"),
            "{cause:?}: the void row still carries its outcome: {row}"
        );
    }
}

#[tokio::test]
async fn an_anonymous_check_reports_a_published_run_as_its_verdict() {
    // A confirmed divergence among them: the gate releases it, and a check that suppressed it
    // anyway would be hiding a published finding to look careful.
    for (outcome, status) in [
        ("exact", "reproduced"),
        ("normalized", "reproduced"),
        ("normalized_with_caveats", "caveats"),
        ("divergent", "divergent"),
    ] {
        let runs = published(
            ["1700000001-aa", "1700000002-ab"],
            outcome,
            ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"],
            "k1",
        );
        let (row, tally) = check(api_over(runs, Principal::Anonymous).await).await;
        assert_eq!(row["status"], status, "{outcome}: {row}");
        assert_eq!(
            row["run"], "1700000002-ab",
            "{outcome}: the newest of the pair: {row}"
        );
        assert_eq!(tally[status], 1, "{outcome}: {tally}");
    }
}

#[tokio::test]
async fn a_withheld_newest_run_gives_way_to_the_newest_older_published_one() {
    // A confirmed match, then a newer divergence nothing has confirmed yet. The reader is told
    // what was published — and nothing in the row says a newer run exists.
    let mut runs = published(
        ["1700000001-aa", "1700000002-ab"],
        "exact",
        ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"],
        "k1",
    );
    runs.push(withheld(
        "1700000009-zz",
        "divergent",
        "2026-01-09T00:00:00Z",
    ));

    let (row, _) = check(api_over(runs.clone(), Principal::Anonymous).await).await;
    assert_eq!(row["status"], "reproduced", "{row}");
    assert_eq!(row["run"], "1700000002-ab", "{row}");

    // An operator is answered from the newest run, withheld or not.
    let (row, _) = check(api_over(runs, Principal::Operator).await).await;
    assert_eq!(row["status"], "divergent", "{row}");
    assert_eq!(row["run"], "1700000009-zz", "{row}");
}

#[tokio::test]
async fn a_withheld_newest_run_with_nothing_published_behind_it_is_never_checked() {
    let runs = vec![
        withheld("1700000001-aa", "exact", "2026-01-01T00:00:00Z"),
        withheld("1700000009-zz", "divergent", "2026-01-09T00:00:00Z"),
    ];
    let (row, _) = check(api_over(runs, Principal::Anonymous).await).await;
    assert_eq!(row["status"], "never checked", "{row}");
    assert!(row["run"].is_null(), "{row}");
}

#[tokio::test]
async fn a_void_run_is_published_as_a_void_when_it_is_what_a_withheld_run_gives_way_to() {
    // A void is published — as a void — so it is what the reader falls back to, and it is still
    // shown as `unsupported`, never as the outcome it carries.
    let runs = vec![
        void(
            "1700000001-aa",
            "divergent",
            "2026-01-01T00:00:00Z",
            Withheld::OpenEgress,
        ),
        withheld("1700000009-zz", "exact", "2026-01-09T00:00:00Z"),
    ];
    let (row, _) = check(api_over(runs, Principal::Anonymous).await).await;
    assert_eq!(row["status"], "unsupported", "{row}");
    assert_eq!(row["run"], "1700000001-aa", "{row}");

    // And the newest run the reader may see wins over an older published verdict, as newest wins
    // everywhere else: a later run was made under a later stabilizer set.
    let mut runs = published(
        ["1700000001-aa", "1700000002-ab"],
        "exact",
        ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"],
        "k1",
    );
    runs.push(void(
        "1700000009-zz",
        "divergent",
        "2026-01-09T00:00:00Z",
        Withheld::OpenEgress,
    ));
    let (row, _) = check(api_over(runs, Principal::Anonymous).await).await;
    assert_eq!(row["status"], "unsupported", "{row}");
    assert_eq!(row["run"], "1700000009-zz", "{row}");
}

// ---------------------------------------------------------------------------
// Every anonymous route: a void run is shown, and never as a divergence
// ---------------------------------------------------------------------------

/// The run the tests below serve, where one id is all they need.
const ID: &str = "1700000001-aa";

/// The JSON a document carries in its boot island, which is what the page draws its first frame
/// from and what `view-source:` shows.
fn boot_of(page: &str) -> serde_json::Value {
    let island = page
        .split_once("<script type=\"application/json\" id=\"boot\">")
        .and_then(|(_, rest)| rest.split_once("</script>"))
        .map(|(json, _)| json)
        .expect("the document has a boot island");
    serde_json::from_str(island).expect("the boot island is JSON")
}

/// What a run leaves on its record once it has compared, as `record_run`, `trigon attest` and a
/// configured model write it: the rebuilt artifact, the comparison, the signed statement named by
/// its predicate, what it cost, and a reading of the diff with the exchange that produced it.
///
/// The outcome decides the rest, as it does on a real run. An `exact` rebuild is the published
/// artifact's own bytes, so its digest is `upstream`'s; `attest --prune` drops a match's rebuilt
/// bytes and keeps a divergence's; the statement is an equivalence or a divergence; and a model is
/// asked about a diff only where there is a divergence to read. Every one of those says what the
/// comparison found. The comparison's digest is the same whatever it found, because it is kept
/// for every reader on purpose — a digest is not a verdict, and the bytes it names are refused by
/// class — and a test of everything else needs it held still.
fn compared(mut r: RunRecord) -> RunRecord {
    let divergent = r.outcome.as_deref() == Some("divergent");
    let exact = r.outcome.as_deref() == Some("exact");
    let rebuild = ArtifactRef {
        name: "requests-2.31.0.tar.gz".into(),
        sha256: if exact {
            r.upstream.sha256
        } else {
            Digest::from_bytes([8u8; 32])
        },
        bytes: if exact { r.upstream.bytes } else { 2 },
        stored: divergent,
    };
    r.comparison = Some(trigon_store::digest_of(&COMPARISON));
    r.costs = Some(trigon_store::Costs {
        build_seconds: Some(12.0),
        artifact_bytes: Some(r.upstream.bytes + rebuild.bytes),
        blob_bytes: Some(if divergent { 9_000 } else { 3_000 }),
        ..Default::default()
    });
    r.rebuild = Some(rebuild);
    let predicate = if divergent {
        "divergence"
    } else {
        "equivalence"
    };
    r.attestations = vec![format!(
        "attestations/pypi/requests/2.31.0/requests-2.31.0.tar.gz/{predicate}.intoto.json"
    )];
    if divergent {
        r.diff_opinion = Some(trigon_core::DiffOpinion {
            verdict: trigon_core::DiffVerdict::Substantive,
            reason: "a changed function body".into(),
            model: "m".into(),
            members_shown: 1,
            members_differing: 1,
        });
        r.transcript = Some(Digest::from_bytes([9u8; 32]));
        if let Some(c) = r.costs.as_mut() {
            c.inference_seconds = Some(3.0);
            c.tokens = vec![trigon_store::Tokens {
                input: 900,
                cached_input: 0,
                output: 40,
                model: "m".into(),
                calls: 1,
            }];
        }
    }
    r
}

/// A void divergence carrying everything a divergence leaves on its record.
fn void_divergence(cause: Withheld) -> RunRecord {
    compared(void(ID, "divergent", "2026-01-01T00:00:00Z", cause))
}

/// The same run, had it matched: `exact`, or `normalized_with_caveats` where the void is a pass
/// somebody wrote, because a pass that applied changed something and the two sides were not
/// byte-identical.
fn void_match(cause: Withheld) -> RunRecord {
    let outcome = match cause {
        Withheld::NonBuiltinStabilizer => "normalized_with_caveats",
        _ => "exact",
    };
    compared(void(ID, outcome, "2026-01-01T00:00:00Z", cause))
}

/// The listings a reader can ask for with a filter that could select a row by its verdict, or tell
/// two verdicts apart by what the filter counts.
const QUERIES: &[&str] = &[
    "outcome=divergent",
    "outcome=exact",
    "outcome=normalized_with_caveats",
    "q=divergent",
    "q=exact",
    "q=requests",
    "q=requests&outcome=divergent",
    "q=requests&outcome=exact",
    "kind=evidence",
    "kind=failed",
    "fault=void",
    "fault=unclassified",
];

/// Every path an anonymous reader can `GET` that could say anything about a run: the contract's
/// routes with their templates filled in, the filters that could select a row by the outcome it
/// was not shown, and the documents whose boot island carries the same rows.
///
/// The contract is the whole versioned surface — `the_table_lists_every_route_the_router_mounts`
/// holds it to the router, since `/v1/jobs/{id}/events`, `/v1/queue` and `/v1/me` were once
/// missing from it and so from here — and `job` fills the one template that names a job.
fn every_anonymous_path(id: &str, job: i64) -> Vec<String> {
    let hex = Digest::from_bytes([7u8; 32]).to_hex();
    let purl = "pkg%3Apypi%2Frequests";
    let job = job.to_string();
    let mut paths: Vec<String> = trigon_api::routes::ROUTES
        .iter()
        .filter(|(_, verb, _)| *verb == "get")
        .map(|(path, ..)| {
            let which = if path.starts_with("/v1/jobs/") {
                job.as_str()
            } else {
                id
            };
            path.replace("{id}", which)
                .replace("{purl}", purl)
                .replace("{digest}", &hex)
        })
        .collect();
    paths.extend(QUERIES.iter().map(|q| format!("/v1/runs?{q}")));
    paths.extend([
        format!("/v1/targets/{purl}%402.31.0"),
        format!("/v1/runs/{id}/member?path=a"),
        format!("/v1/runs/{id}/member/raw?path=a&side=rebuild"),
        "/".into(),
        format!("/runs/{id}"),
        format!("/targets/{purl}"),
        format!("/artifacts/{hex}"),
        "/queue".into(),
        format!("/jobs/{job}"),
    ]);
    paths
}

#[tokio::test]
async fn no_anonymous_route_returns_divergent_for_a_void_run() {
    for cause in VOID_CAUSES {
        let r = void_divergence(cause);
        // A queue whose job noted the divergence, as the worker does before the gate has run, so
        // the routes that read the queue are asked too and not answered `no_queue`.
        let dir = tempfile::tempdir().expect("tempdir");
        let (queue, job) = queue_after(&dir, "divergent").await;
        let anon = api_with(vec![r.clone()], Principal::Anonymous, Some(queue.clone())).await;
        for path in every_anonymous_path(&r.id, job) {
            let (status, body) = get(anon.clone(), &path).await;
            assert!(
                !body.contains("divergent"),
                "{cause:?}: {path} ({status}) told an anonymous reader a void run is divergent: \
                 {}",
                &body[..body.len().min(600)]
            );
        }
        // Nor may a filter select the row by the outcome it was not shown. Listed under
        // `?outcome=divergent`, it would say the word without printing it, and the loop above
        // would not notice.
        for query in ["outcome=divergent", "q=divergent"] {
            let (_, doc) = get_json(anon.clone(), &format!("/v1/runs?{query}")).await;
            assert_eq!(
                doc["total"], 0,
                "{cause:?}: ?{query} selected the void: {doc}"
            );
            assert_eq!(
                doc["rows"],
                serde_json::json!([]),
                "{cause:?}: ?{query}: {doc}"
            );
        }
        // And `POST /v1/check`, whose tally names every status at zero, so it is read by row.
        let (row, _) = check(anon.clone()).await;
        assert_eq!(row["status"], "unsupported", "{cause:?}: {row}");

        // The control that makes the loop above a test: the same routes, asked by an operator,
        // do carry the word — so it is one these routes can produce, and its absence is the gate.
        let op = api_with(vec![r.clone()], Principal::Operator, Some(queue)).await;
        let (_, body) = get(op.clone(), &format!("/v1/runs/{}", r.id)).await;
        assert!(
            body.contains("\"outcome\":\"divergent\""),
            "{cause:?}: {body}"
        );
        let (_, body) = get(op.clone(), &format!("/v1/jobs/{job}/events")).await;
        assert!(body.contains("divergent"), "{cause:?}: {body}");
        let (_, doc) = get_json(op.clone(), "/v1/runs?outcome=divergent").await;
        assert_eq!(doc["total"], 1, "{cause:?}: {doc}");
        // A guard-tripped run was never counted as evidence, for anybody, so only the other two
        // causes put the word in an operator's counts.
        if cause != Withheld::GuardTripped {
            let (_, stats) = get_json(op, "/v1/stats").await;
            assert_eq!(stats["by_outcome"]["divergent"], 1, "{cause:?}: {stats}");
        }
    }
}

#[tokio::test]
async fn a_void_row_is_kept_with_its_reason_and_without_its_outcome() {
    // Omitted, not dropped: a row that vanished would read as never checked, and one with a blank
    // where its verdict was would read as a run that never finished. The reason is what makes the
    // absence mean something.
    let r = void_divergence(Withheld::OpenEgress);
    let anon = api_over(vec![r.clone()], Principal::Anonymous).await;

    for path in [
        "/v1/runs".to_string(),
        "/v1/targets/pkg%3Apypi%2Frequests".into(),
        format!("/v1/artifacts/{}", Digest::from_bytes([7u8; 32]).to_hex()),
    ] {
        let (status, doc) = get_json(anon.clone(), &path).await;
        assert_eq!(status, 200, "{path}: {doc}");
        let rows = doc
            .get("rows")
            .unwrap_or(&doc)
            .as_array()
            .unwrap_or_else(|| panic!("{path} is not a list of rows: {doc}"));
        assert_eq!(rows.len(), 1, "{path}: the void row is gone: {doc}");
        let row = &rows[0];
        assert!(row["outcome"].is_null(), "{path}: {row}");
        assert_eq!(
            row["evidence"], false,
            "{path}: a void is not evidence: {row}"
        );
        assert_eq!(row["publication"]["state"], "void", "{path}: {row}");
        assert_eq!(
            row["publication"]["because"], "open_egress",
            "{path}: {row}"
        );
    }

    // The run itself: shown, with everything the comparison decided removed from the record, and
    // what establishes the void — and what a reader holding the artifact looks it up by — kept.
    let (status, doc) = get_json(anon.clone(), &format!("/v1/runs/{}", r.id)).await;
    assert_eq!(status, 200, "{doc}");
    assert!(doc["entry"]["outcome"].is_null(), "{doc}");
    assert_eq!(
        doc["entry"]["publication"]["because"], "open_egress",
        "{doc}"
    );
    // `rebuild`: its digest against `upstream`'s says `exact` or not, and after a prune its
    // `stored` says match or divergence. `transcript` and `costs`: a model is asked about a diff
    // only on a divergence, and the costs count the rebuild's bytes, the comparison's, and that
    // model's tokens.
    const GONE: [&str; 6] = [
        "outcome",
        "rebuild",
        "attestations",
        "diff_opinion",
        "transcript",
        "costs",
    ];
    let record = doc["record"].as_object().expect("record");
    for key in GONE {
        assert!(
            !record.contains_key(key),
            "the record still carries `{key}`: {doc}"
        );
    }
    for key in [
        "upstream",
        "environment",
        "non_builtin_stabilizer",
        "comparison",
    ] {
        assert!(record.contains_key(key), "`{key}` went too: {doc}");
    }

    // The rendered comparison is refused, and says why in the gate's words; and the run page does
    // not carry it in its source instead.
    let (status, doc) = get_json(anon.clone(), &format!("/v1/runs/{}/diff", r.id)).await;
    assert_eq!(status, 404, "{doc}");
    assert_eq!(doc["error"], "published_as_void", "{doc}");
    assert!(
        doc["detail"]
            .as_str()
            .is_some_and(|d| d.contains(Withheld::OpenEgress.sentence())),
        "{doc}"
    );
    let (_, page) = get(anon.clone(), &format!("/runs/{}", r.id)).await;
    assert!(
        page.contains("\"diff\":null"),
        "the void's comparison was booted"
    );
    assert!(
        page.contains("\"state\":\"void\""),
        "the void run was not booted at all"
    );
    let boot = boot_of(&page);
    for key in GONE {
        assert!(
            boot["run"]["record"].get(key).is_none(),
            "the run page's boot island carries `{key}`: {boot}"
        );
    }

    // An operator gets all of it, from the same store: the comparison is real and the record
    // carries every field above, so their absence is the gate and not the fixture.
    let op = api_over(vec![r.clone()], Principal::Operator).await;
    let (status, doc) = get_json(op.clone(), &format!("/v1/runs/{}/diff", r.id)).await;
    assert_eq!(status, 200, "{doc}");
    assert_eq!(doc["outcome"], "divergent", "{doc}");
    let (_, doc) = get_json(op.clone(), &format!("/v1/runs/{}", r.id)).await;
    for key in GONE {
        assert!(
            doc["record"].get(key).is_some(),
            "the fixture has no `{key}`, so its absence above tests nothing: {doc}"
        );
    }
    let (_, page) = get(op, &format!("/runs/{}", r.id)).await;
    assert!(
        page.contains("\"ladder\""),
        "an operator's run page did not boot the comparison"
    );

    // Counted where a run that is not evidence is counted, under its name, and not dropped.
    let (_, stats) = get_json(anon, "/v1/stats").await;
    assert_eq!(stats["runs"], 1, "{stats}");
    assert_eq!(stats["evidence"], 0, "{stats}");
    assert_eq!(stats["by_fault"]["void"], 1, "{stats}");
    assert_eq!(stats["by_outcome"], serde_json::json!({}), "{stats}");
}

// ---------------------------------------------------------------------------
// What the reader cannot see changes nothing the reader can fetch
// ---------------------------------------------------------------------------

/// A JSON body with its event times taken out, or any other body as it is.
///
/// Two queues written a moment apart differ in `at`, and in nothing else that is not about the
/// run; everything else is compared byte for byte.
fn without_times(body: &str) -> String {
    fn strip(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                m.remove("at");
                m.values_mut().for_each(strip);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(mut v) => {
            strip(&mut v);
            v.to_string()
        }
        Err(_) => body.to_string(),
    }
}

/// Everything an anonymous reader can fetch about `records`, with a queue whose job noted `label`:
/// every path above, and the check of the lockfile.
async fn anonymous_view(records: Vec<RunRecord>, label: &str) -> Vec<(String, u16, String)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let (queue, job) = queue_after(&dir, label).await;
    let anon = api_with(records, Principal::Anonymous, Some(queue)).await;
    let mut seen = Vec::new();
    for path in every_anonymous_path(ID, job) {
        let (status, body) = get(anon.clone(), &path).await;
        seen.push((path, status, without_times(&body)));
    }
    let (status, body) = send(anon, "POST", "/v1/check", LOCKFILE).await;
    seen.push(("POST /v1/check".into(), status, body));
    seen
}

/// That two views are the same answer to every request, and where they first differ if not.
fn assert_same_view(a: &[(String, u16, String)], b: &[(String, u16, String)], what: &str) {
    assert_eq!(a.len(), b.len());
    for ((path, sa, ba), (_, sb, bb)) in a.iter().zip(b) {
        let at = ba
            .bytes()
            .zip(bb.bytes())
            .position(|(x, y)| x != y)
            .unwrap_or(ba.len().min(bb.len()));
        let window = |s: &str| {
            let b = s.as_bytes();
            String::from_utf8_lossy(
                &b[at.saturating_sub(120).min(b.len())..(at + 120).min(b.len())],
            )
            .into_owned()
        };
        assert!(
            sa == sb && ba == bb,
            "{what}: {path} tells them apart ({sa} and {sb}):\n  {}\n  {}",
            window(ba),
            window(bb)
        );
    }
}

/// The strongest form of `docs/19` §4.3, "no comparison outcome and no difference data": a void
/// that matched and one that diverged are the same answer to every anonymous request.
///
/// A sweep for the word `divergent` finds a route that prints the outcome. It does not find one
/// that says it some other way — a rebuilt digest equal to the published one, a pruned artifact,
/// a model asked about a diff, a byte count that includes the comparison — and each of those was
/// on the record of a void run served to anybody. Asserting that the two views are identical
/// finds all of them, and the next one.
#[tokio::test]
async fn a_void_that_matched_and_one_that_diverged_look_the_same_to_an_anonymous_reader() {
    for cause in VOID_CAUSES {
        let matched = void_match(cause);
        let label = matched.outcome.clone().expect("an outcome");
        let a = anonymous_view(vec![matched.clone()], &label).await;
        let b = anonymous_view(vec![void_divergence(cause)], "divergent").await;
        assert_same_view(&a, &b, &format!("{cause:?}"));

        // The control: an operator can tell them apart, so what the two share above is the gate
        // and not two fixtures that happen to agree.
        let path = format!("/v1/runs/{ID}");
        let (_, x) = get(api_over(vec![matched], Principal::Operator).await, &path).await;
        let op = api_over(vec![void_divergence(cause)], Principal::Operator).await;
        let (_, y) = get(op, &path).await;
        assert_ne!(x, y, "{cause:?}: the fixtures do not differ");
    }
}

/// And the same of a withheld run, which is not shown at all: nothing an anonymous reader can
/// fetch depends on what it found.
///
/// Before this held, `/v1/jobs/{id}/events` returned the worker's `outcome` note, and
/// `/v1/runs?q=requests&outcome=divergent` answered `"withheld":1` where `outcome=exact` answered 0
/// — the accusation the gate was holding back, one query away.
#[tokio::test]
async fn a_withheld_divergence_and_a_withheld_match_look_the_same_to_an_anonymous_reader() {
    let started = "2026-01-01T00:00:00Z";
    let a = anonymous_view(vec![compared(withheld(ID, "exact", started))], "exact").await;
    let b = anonymous_view(
        vec![compared(withheld(ID, "divergent", started))],
        "divergent",
    )
    .await;
    assert_same_view(&a, &b, "withheld");

    // Counted, still: the denominator stays honest for a query that says nothing about a verdict.
    let anon = api_over(
        vec![compared(withheld(ID, "divergent", started))],
        Principal::Anonymous,
    )
    .await;
    let (_, doc) = get_json(anon, "/v1/runs?q=requests").await;
    assert_eq!(doc["total"], 1, "{doc}");
    assert_eq!(doc["withheld"], 1, "{doc}");
}

/// A withheld run is refused in the same bytes as a run that does not exist.
///
/// The per-run routes each said 404 so as not to confirm that a withheld run exists, and each
/// confirmed it another way: a different sentence, a class-gated 403 where an absent run got a
/// 404, or a `not_recorded` where an absent run got `no_such_run`. Run ids are a timestamp and the
/// first eight hex digits of the published artifact's digest, which anyone holding it can compute.
#[tokio::test]
async fn a_withheld_run_is_refused_in_the_words_an_absent_one_is() {
    let held = compared(withheld(ID, "divergent", "2026-01-01T00:00:00Z"));
    let absent = "1700000002-aa";
    let anon = api_over(vec![held.clone()], Principal::Anonymous).await;
    let per_run: Vec<String> = every_anonymous_path(ID, 1)
        .into_iter()
        .filter(|p| p.contains(ID))
        .collect();
    assert!(per_run.len() > 10, "{per_run:?}");
    for path in per_run {
        let there = get(anon.clone(), &path).await;
        let not = get(anon.clone(), &path.replace(ID, absent)).await;
        assert_eq!(
            there, not,
            "{path} answers a withheld run differently from one that does not exist"
        );
    }

    // The control: an operator is answered from the run.
    let op = api_over(vec![held], Principal::Operator).await;
    let (status, _) = get(op, &format!("/v1/runs/{ID}")).await;
    assert_eq!(status, 200);
}

/// A job's notes reach an operator and never an anonymous reader, who is told where the job got
/// to and why the notes are missing.
///
/// `/v1/queue` hands out job ids to anybody, and the worker notes the comparison's label before the
/// gate has decided anything — so a first attempt awaiting confirmation, and an open-egress run the
/// gate turns into a void, both reached the public here as `divergent`, and the job page drew it
/// under "It publishes once a second attempt agrees".
#[tokio::test]
async fn a_jobs_notes_reach_an_operator_and_not_an_anonymous_reader() {
    for (what, run) in [
        (
            "withheld",
            compared(withheld(ID, "divergent", "2026-01-01T00:00:00Z")),
        ),
        ("void", void_divergence(Withheld::OpenEgress)),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let (queue, job) = queue_after(&dir, "divergent").await;
        let path = format!("/v1/jobs/{job}/events");

        let anon = api_with(vec![run.clone()], Principal::Anonymous, Some(queue.clone())).await;
        let (status, doc) = get_json(anon, &path).await;
        assert_eq!(status, 200, "{what}: {doc}");
        let events = doc["events"].as_array().expect("events");
        let phases: Vec<&str> = events.iter().filter_map(|e| e["phase"].as_str()).collect();
        assert_eq!(
            phases,
            [
                "leased", "rebuild", "outcome", "retrying", "leased", "rebuild", "outcome",
                "recorded"
            ],
            "{what}: where the job got to is still the page"
        );
        assert!(
            events.iter().all(|e| e.get("detail").is_none()),
            "{what}: a note reached an anonymous reader: {doc}"
        );
        assert!(!doc.to_string().contains("divergent"), "{what}: {doc}");
        assert!(
            doc["detail"]
                .as_str()
                .is_some_and(|d| d.contains("not shown")),
            "{what}: the missing notes are not explained: {doc}"
        );

        let op = api_with(vec![run], Principal::Operator, Some(queue)).await;
        let (_, doc) = get_json(op, &path).await;
        let notes: Vec<&str> = doc["events"]
            .as_array()
            .expect("events")
            .iter()
            .filter_map(|e| e["detail"].as_str())
            .collect();
        assert_eq!(
            notes,
            ["divergent", "divergent produced no record", "divergent"],
            "{what}: an operator keeps every note"
        );
    }
}

/// A void that matched is not described as a divergence.
///
/// `decide` voids a run on safeguard 2 before it reads the outcome, so a pass somebody wrote that
/// made the two sides agree voids it as well, and the reason's sentence is shown to a reader of a
/// package that reproduced. It said the run "publishes as void rather than as a divergence".
#[tokio::test]
async fn a_void_that_matched_is_not_described_as_a_divergence() {
    let r = void_match(Withheld::NonBuiltinStabilizer);
    assert_eq!(r.outcome.as_deref(), Some("normalized_with_caveats"));
    let anon = api_over(vec![r], Principal::Anonymous).await;

    let (row, _) = check(anon.clone()).await;
    assert_eq!(row["status"], "unsupported", "{row}");
    assert!(!row.to_string().contains("divergen"), "{row}");
    for path in [format!("/v1/runs/{ID}"), format!("/v1/runs/{ID}/diff")] {
        let (_, body) = get(anon.clone(), &path).await;
        assert!(!body.contains("divergen"), "{path}: {body}");
    }
}

// ---------------------------------------------------------------------------
// The browse page's bars
// ---------------------------------------------------------------------------

/// Every bar on the browse page lists, when clicked, the runs it counted.
///
/// `by_fault` counted a row under its fault, else how it ended, else `void`, while `?fault=` matched
/// the fault alone — so the `void` bar phase 0 added, and the `no-strategy` one before it, were
/// counts whose click listed nothing.
#[tokio::test]
async fn every_bar_on_the_browse_page_lists_what_it_counted() {
    let started = "2026-01-03T00:00:00Z";
    let mut runs = published(
        ["1700000001-aa", "1700000002-ab"],
        "exact",
        ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"],
        "k1",
    );
    runs.push(compared(void(
        "1700000003-ac",
        "divergent",
        started,
        Withheld::OpenEgress,
    )));
    let mut scope = run("1700000004-ad", "exact", started, "k4");
    scope.outcome = None;
    scope.terminal = Some("no-strategy".into());
    runs.push(scope);
    let mut broke = run("1700000005-ae", "exact", started, "k5");
    broke.outcome = None;
    broke.terminal = Some("build-failed".into());
    broke.failure = Some(trigon_core::FailureSignature {
        code: "env/missing-tool".into(),
        subject: None,
        fault: trigon_core::Fault::Infra,
        retryable: false,
        repairable: false,
        evidence: "the line the classifier matched".into(),
    });
    runs.push(broke);

    for (who, expected) in [
        (Principal::Anonymous, &["void"][..]),
        (Principal::Operator, &["infra", "no-strategy"][..]),
    ] {
        let api = api_over(runs.clone(), who).await;
        let (_, stats) = get_json(api.clone(), "/v1/stats").await;
        let faults = stats["by_fault"].as_object().expect("by_fault");
        let keys: Vec<&str> = faults.keys().map(String::as_str).collect();
        assert_eq!(keys, expected, "{who:?}: {stats}");
        for (filter, bars) in [
            ("fault", faults),
            (
                "outcome",
                stats["by_outcome"].as_object().expect("by_outcome"),
            ),
        ] {
            for (key, n) in bars {
                let (_, page) = get_json(api.clone(), &format!("/v1/runs?{filter}={key}")).await;
                let listed = page["rows"].as_array().expect("rows").len();
                assert_eq!(
                    serde_json::json!(listed),
                    *n,
                    "{who:?}: the `{key}` bar counts {n} and clicking it lists {listed}: {page}"
                );
            }
        }
    }
}
