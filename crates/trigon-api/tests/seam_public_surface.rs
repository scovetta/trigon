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
        // No queue: these assert the read path, and an instance that reads a corpus out of object
        // storage is exactly the shape stage 1 shipped.
        queue: None,
        index,
        switches: Switches::default(),
        unauthenticated: who,
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

/// An unredacted class never leaves the process to an anonymous caller, through any route.
#[tokio::test]
async fn no_route_hands_the_internet_an_unredacted_byte() {
    let mut r = record("1700000001-aa", "pkg:npm/a@1.0.0", Some("exact"), Some("k"));
    r.build_log = Some(Digest::from_bytes([1u8; 32]));
    r.network_transcript = Some(Digest::from_bytes([2u8; 32]));
    r.comparison = Some(Digest::from_bytes([3u8; 32]));
    let mut confirming = r.clone();
    confirming.id = "1700000002-ab".into();

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
    for (path, spec) in paths {
        let ops: Vec<&String> = spec.as_object().expect("operations").keys().collect();
        assert_eq!(ops, vec!["get"], "{path} declares a verb that is not `get`");
    }
    // And every concrete route actually answers rather than 404ing, which is what makes the
    // contract a description rather than a wish.
    for (path, ..) in trigon_api::routes::ROUTES {
        if path.contains('{') {
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
