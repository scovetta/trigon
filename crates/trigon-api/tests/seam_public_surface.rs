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
        derived_image: None,
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
    // Every pass that fired was built in, which is what the run path writes for an ordinary
    // rebuild. `None` here would mean a record from before the field existed, and the gate treats
    // that as a safeguard it could not evaluate — correct, and not what these fixtures are about.
    r.non_builtin_stabilizer = Some(false);
    // Runs with one outcome found one thing, so two at a key agree unless a test says otherwise.
    r.agreement = outcome.map(|o| trigon_store::digest_of(o.as_bytes()));
    ran(&mut r);
    r
}

/// Where and when the run with this id ran, as the run path records it: on a machine of its own,
/// and `<id> - 1700000000` hours into 2026. Two ids one apart are then an hour apart on two
/// machines, which is a confirmation under the settings `trigon serve` uses with no configuration,
/// and these tests are about what a confirmed or unconfirmed run shows, not about how it was
/// confirmed.
fn ran(r: &mut RunRecord) {
    let n: i64 =
        r.id.split('-')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1_700_000_000);
    let hours = n - 1_700_000_000;
    r.started = format!("2026-01-{:02}T{:02}:00:00Z", 1 + hours / 24, hours % 24);
    r.host = Some(format!("machine-id:{}", r.id));
    r.cache = Some(trigon_store::CacheState::default());
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
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
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

/// No anonymous reader is told which machine a run ran on, by the record route or the page.
///
/// A host id is a keyed hash under a key that is in the source. Where it was derived from a
/// hostname — often a person's name — a guess at the hostname can be checked against it. The gate
/// reads the index's own records, so the field is of no use to a reader; the operator keeps it.
#[tokio::test]
async fn no_anonymous_reader_is_told_which_machine_a_run_ran_on() {
    let published = vec![
        record(
            "1700000001-aa",
            "pkg:npm/p@1.0.0",
            Some("exact"),
            Some("k1"),
        ),
        record(
            "1700000002-ab",
            "pkg:npm/p@1.0.0",
            Some("exact"),
            Some("k1"),
        ),
    ];
    let mut void = record(
        "1700000005-cc",
        "pkg:npm/v@1.0.0",
        Some("exact"),
        Some("k2"),
    );
    void.environment.egress = "open".into();
    let mut all = published.clone();
    all.push(void.clone());

    let anon = api_over(all.clone(), Principal::Anonymous).await;
    for id in ["1700000002-ab", "1700000005-cc"] {
        for path in [format!("/v1/runs/{id}"), format!("/runs/{id}")] {
            let (status, body) = get(anon.clone(), &path).await;
            assert_eq!(status, 200, "{path}: {body}");
            assert!(body.contains(id), "{path} does not show the run at all");
            assert!(
                !body.contains("machine-id:"),
                "{path} names the machine: {body}"
            );
        }
    }
    let operator = api_over(all, Principal::Operator).await;
    let (_, body) = get(operator, "/v1/runs/1700000002-ab").await;
    assert!(
        body.contains("machine-id:1700000002-ab"),
        "the operator keeps it"
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
    ran(&mut confirming);

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
    // Every verb the table gives a path, and no other. A set rather than one verb per path:
    // `/v1/runs` is browsed with `GET` and asked of with `POST`, and a document with room for one
    // of them had listed it as the verb it is not browsed with.
    for (path, ..) in trigon_api::routes::ROUTES {
        assert!(
            paths.contains_key(*path),
            "{path} is in the table and not in the contract"
        );
    }
    for (path, spec) in paths {
        let declared: std::collections::BTreeSet<&str> = spec
            .as_object()
            .expect("operations")
            .keys()
            .map(String::as_str)
            .collect();
        let expected: std::collections::BTreeSet<&str> = trigon_api::routes::ROUTES
            .iter()
            .filter(|(p, ..)| p == path)
            .map(|(_, verb, _)| *verb)
            .collect();
        assert_eq!(
            declared, expected,
            "{path} is rendered with {declared:?} and the table says {expected:?}"
        );
    }
    // And every concrete route actually answers rather than 404ing, which is what makes the
    // contract a description rather than a wish.
    for (path, verb, _) in trigon_api::routes::ROUTES {
        // A templated path has no concrete instance to call here, and a `POST` route is not
        // answerable by a `GET` — asserting it were is how `/v1/check` came to be described as
        // something the router does not have.
        if path.contains('{') || *verb != "get" {
            continue;
        }
        let (status, _) = get(api.clone(), path).await;
        assert_eq!(status, 200, "{path} is in the contract and does not answer");
    }
}

/// The rendered diff is gated by the publication gate, like the run it describes.
///
/// It is anonymous *as a class* — the bound is its control, not secrecy — but that says nothing
/// about whether this particular run may be shown. A withheld divergence whose member list was
/// served because the route was "anonymous" would publish the accusation the gate is holding back,
/// in more detail than the verdict would have.
#[tokio::test]
async fn a_withheld_run_has_no_renderable_diff_either() {
    let mut r = record(
        "1700000001-aa",
        "pkg:npm/accused@1.0.0",
        Some("divergent"),
        Some("k1"),
    );
    r.comparison = Some(Digest::from_bytes([4u8; 32]));

    let api = api_over(vec![r.clone()], Principal::Anonymous).await;
    let (status, body) = get(api, "/v1/runs/1700000001-aa/diff").await;
    assert_eq!(status, 404, "a withheld run's diff was served: {body}");
    assert!(
        !body.contains("accused"),
        "the refusal named the package it was refusing to name"
    );

    // An operator reading their own store gets past the gate and then fails on the missing blob,
    // which is a different refusal and says so.
    let api = api_over(vec![r], Principal::Operator).await;
    let (status, body) = get(api, "/v1/runs/1700000001-aa/diff").await;
    assert_eq!(status, 404);
    assert!(
        body.contains("no_such_blob"),
        "an operator got the gate's refusal rather than the store's: {body}"
    );
}

/// A member's bytes and its diff are class-gated, even though the census is not.
///
/// The distinction the class table now turns on: a count is a claim about an artifact and a member
/// is the artifact's content. `12-security.md` §5 covers the second — we hold somebody else's bytes
/// to check them, not to redistribute them — and the bound that makes the rendered census
/// anonymous does not apply here, because a diff of a file that differs everywhere is the file.
#[tokio::test]
async fn a_members_bytes_never_reach_the_internet() {
    let mut r = record(
        "1700000001-aa",
        "pkg:npm/a@1.0.0",
        Some("divergent"),
        Some("k1"),
    );
    r.comparison = Some(Digest::from_bytes([4u8; 32]));
    let mut confirming = r.clone();
    confirming.id = "1700000002-ab".into();
    ran(&mut confirming);

    let api = api_over(vec![r, confirming], Principal::Anonymous).await;
    for path in [
        "/v1/runs/1700000001-aa/member?path=lib%2Fx.dll",
        "/v1/runs/1700000001-aa/member/raw?path=lib%2Fx.dll&side=upstream",
    ] {
        let (status, body) = get(api.clone(), path).await;
        assert_eq!(status, 403, "{path} was served anonymously: {body}");
        assert!(
            body.contains("class_gated"),
            "{path} refused for some other reason: {body}"
        );
    }

    // And the rendered census of the same run *is* anonymous, so this test is about the boundary
    // rather than about the run being withheld.
    let (status, _) = get(api, "/v1/runs/1700000001-aa/diff").await;
    assert_ne!(
        status, 403,
        "the census was gated as though it were content"
    );
}

/// Build a zip holding one member, and put it in a store.
async fn artifact_with(store: &Store, name: &str, body: &[u8]) -> Digest {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        use std::io::Write as _;
        w.start_file(name, opts).unwrap();
        w.write_all(body).unwrap();
        w.finish().unwrap();
    }
    store.blobs().put(buf).await.expect("put artifact")
}

/// A member's **content** cannot close the script tag the boot island lives in.
///
/// This is the assertion that had to exist before the document could carry a member panel. Until
/// then the island held package names and counts; now it holds the bytes of a file somebody else
/// published, which is the most attacker-controlled thing on the page. A member whose content is
/// `</script><script>…` would be executing on this origin before the first paint.
#[tokio::test]
async fn a_members_content_cannot_close_the_island() {
    let hostile = b"before\n</script><script>alert(1)</script>\nafter\n";
    let store = Arc::new(Store::in_memory());
    let up = artifact_with(&store, "package/index.js", hostile).await;
    let rb = artifact_with(&store, "package/index.js", b"before\nharmless\nafter\n").await;

    let mut r = record("1700000001-aa", "pkg:npm/a@1.0.0", Some("divergent"), None);
    r.upstream = ArtifactRef {
        name: "pkg.zip".into(),
        sha256: up,
        bytes: 1,
        stored: true,
    };
    r.rebuild = Some(ArtifactRef {
        name: "pkg.zip".into(),
        sha256: rb,
        bytes: 1,
        stored: true,
    });
    store.put_run(&r).await.unwrap();

    let index = Index::new();
    index.refresh(&store, Switches::default()).await.unwrap();
    let api = Arc::new(Api {
        store,
        queue: None,
        index,
        switches: Switches::default(),
        // Operator, because that is the principal the member panel is booted for at all.
        unauthenticated: Principal::Operator,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    });

    let (status, body) = get(api, "/runs/1700000001-aa?member=package%2Findex.js").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("\\u003c/script"),
        "the island did not escape a member's content"
    );
    // One closing tag for the island, one for the module script, and nothing the file put there.
    assert_eq!(
        body.matches("</script>").count(),
        2,
        "a member's content closed a script tag"
    );
    // And the panel really was booted, so this is not passing because nothing was rendered.
    assert!(
        body.contains("package/index.js"),
        "the member was not booted at all, so the escaping is untested"
    );
}

/// The boot asks the same gate the route does.
///
/// A member's bytes are `Class::Artifact`. Putting them in the document for a reader who may not
/// fetch them would move the content from a route that refuses to a page source that cannot.
#[tokio::test]
async fn an_anonymous_reader_gets_no_member_in_the_page_source() {
    let secret = b"a line nobody outside should read\n";
    let store = Arc::new(Store::in_memory());
    let up = artifact_with(&store, "package/index.js", secret).await;
    let rb = artifact_with(&store, "package/index.js", b"different\n").await;

    // Two agreeing attempts, so the *run* is published and this test is about the member alone.
    for (id, key) in [("1700000001-aa", "k1"), ("1700000002-ab", "k1")] {
        let mut r = record(id, "pkg:npm/a@1.0.0", Some("divergent"), Some(key));
        r.upstream = ArtifactRef {
            name: "pkg.zip".into(),
            sha256: up,
            bytes: 1,
            stored: true,
        };
        r.rebuild = Some(ArtifactRef {
            name: "pkg.zip".into(),
            sha256: rb,
            bytes: 1,
            stored: true,
        });
        store.put_run(&r).await.unwrap();
    }

    let index = Index::new();
    index.refresh(&store, Switches::default()).await.unwrap();
    let api = Arc::new(Api {
        store,
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: Principal::Anonymous,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: None,
    });

    let (status, body) = get(api.clone(), "/runs/1700000001-aa?member=package%2Findex.js").await;
    assert_eq!(status, 200, "the page itself should still render");
    assert!(
        !body.contains("a line nobody outside should read"),
        "a member's content reached an anonymous reader's page source"
    );
    assert!(
        body.contains("\"member\":null"),
        "the boot did not say plainly that there is no member here: {}",
        &body[..body.len().min(400)]
    );
    // The run is published, so the page is not empty — the member alone was withheld.
    assert!(body.contains("divergent"));
}

/// One bad query parameter costs that parameter, not the deep link.
///
/// `?member=x&offset=abc` used to boot nothing: deserializing `DocQuery` is all-or-nothing, so an
/// unreadable `offset` discarded the `member` beside it. The reason a reader's link did nothing
/// would have been a parameter with no bearing on which member they asked for.
#[tokio::test]
async fn a_bad_parameter_does_not_discard_the_rest_of_the_query() {
    let store = Arc::new(Store::in_memory());
    let up = artifact_with(&store, "package/index.js", b"one\ntwo\n").await;
    let rb = artifact_with(&store, "package/index.js", b"one\nTWO\n").await;

    let mut r = record("1700000001-aa", "pkg:npm/a@1.0.0", Some("divergent"), None);
    r.upstream = ArtifactRef {
        name: "pkg.zip".into(),
        sha256: up,
        bytes: 1,
        stored: true,
    };
    r.rebuild = Some(ArtifactRef {
        name: "pkg.zip".into(),
        sha256: rb,
        bytes: 1,
        stored: true,
    });
    store.put_run(&r).await.unwrap();

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

    // The member alone boots, as a control.
    let (_, plain) = get(api.clone(), "/runs/1700000001-aa?member=package%2Findex.js").await;
    assert!(
        plain.contains("package/index.js"),
        "the control did not boot"
    );

    for query in [
        "member=package%2Findex.js&offset=abc",
        "member=package%2Findex.js&offset=",
        "member=package%2Findex.js&utm_source=somewhere",
        "member=package%2Findex.js&view=hex&offset=-1",
    ] {
        let (status, body) = get(api.clone(), &format!("/runs/1700000001-aa?{query}")).await;
        assert_eq!(status, 200, "?{query} cost the page");
        assert!(
            body.contains("package/index.js"),
            "?{query} threw the member away with the parameter it could not read"
        );
    }
}

/// The signed statement is gated by the publication gate, like everything else about a run.
///
/// Attestations are written at attest time. Nothing there knows whether a second attempt will
/// agree, so a first-attempt divergence is signed and on disk while `decide` still returns
/// `Withheld { AwaitingConfirmation }` — ADR-0010 safeguard 1, holding back an accusation until
/// something corroborates it.
///
/// Observed on a real store before this test existed, against a real `divergent` run whose entry
/// read `{"state":"withheld","because":"awaiting_confirmation"}`, through a `--public` server:
///
/// ```text
///   /v1/runs/{id}              -> 404
///   /v1/runs/{id}/diff         -> 404
///   /v1/runs/{id}/strategy     -> 404
///   /v1/runs/{id}/comparison   -> 403
///   /v1/runs/{id}/log          -> 403
///   /v1/runs/{id}/attestation  -> 200   13,536 bytes
/// ```
///
/// Every route held except the one that serves the claim in signed, quotable, independently
/// verifiable form — which is the version of it that does the most damage if it is wrong, and
/// safeguard 1 exists precisely because a one-attempt divergence may be wrong.
#[tokio::test]
async fn an_unconfirmed_divergence_has_no_public_statement() {
    let mut r = record("1700000010-dd", "pkg:npm/x@1.0.0", Some("divergent"), None);
    r.attestations = vec!["attestations/x/statement.json".into()];

    let anon = api_over(vec![r.clone()], Principal::Anonymous).await;
    let (status, body) = get(anon.clone(), "/v1/runs/1700000010-dd/attestation").await;
    assert_eq!(
        status, 404,
        "a withheld divergence must not serve its signed statement; got {status}: {body}"
    );
    assert!(
        !body.contains("statement.json"),
        "and the refusal must not name what it is withholding: {body}"
    );

    // The gate, not the route, is what changed: an operator gets past it. Otherwise this test
    // would pass just as well if the route had been deleted.
    //
    // Asserted on the *reason*, not the status. This store holds no blob at that path, so the
    // operator's request 404s too — as `unreadable`, which is a different fact from `no_such_run`
    // and the distinction this whole file is about.
    let op = api_over(vec![r.clone()], Principal::Operator).await;
    let (_, body) = get(op, "/v1/runs/1700000010-dd/attestation").await;
    assert!(
        !body.contains("no_such_run"),
        "an operator must get past the gate; the gate is about anonymous readers: {body}"
    );

    // And the same 404 the record gives, so the two cannot be used against each other: a 403 here
    // beside a 404 there would confirm the run exists, which is most of the accusation.
    let (record_status, _) = get(anon, "/v1/runs/1700000010-dd").await;
    assert_eq!(
        record_status, 404,
        "the record route is the one this is meant to agree with"
    );
}

/// A published run still serves its statement anonymously. That is the point of the route.
#[tokio::test]
async fn a_confirmed_run_still_publishes_its_statement() {
    // Two attempts at one cache key, agreeing, which is what safeguard 1 asks for.
    let mut a = record(
        "1700000020-ee",
        "pkg:npm/y@1.0.0",
        Some("divergent"),
        Some("k"),
    );
    a.attestations = vec!["attestations/y/statement.json".into()];
    let mut b = record(
        "1700000021-ee",
        "pkg:npm/y@1.0.0",
        Some("divergent"),
        Some("k"),
    );
    b.attestations = vec!["attestations/y/statement.json".into()];

    let anon = api_over(vec![a, b], Principal::Anonymous).await;
    let (_, body) = get(anon, "/v1/runs/1700000020-ee/attestation").await;
    assert!(
        !body.contains("no_such_run"),
        "a corroborated divergence is exactly what this route exists to publish, and the gate \
         refused it: {body}"
    );
}
