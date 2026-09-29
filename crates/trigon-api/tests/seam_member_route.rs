//! `GET /v1/runs/{id}/member` and `/member/raw` against stored artifacts, for a principal who may
//! read them.
//!
//! `seam_member_bytes.rs` holds the reading itself — the walk, the caps, the three reasons a member
//! has no bytes. This holds what the routes do with it: that a member a renaming pass named is
//! found in both artifacts through the route, as the comparison names it; that a download is
//! always bytes, under a name a browser cannot be talked into treating as anything else; and that
//! each way of not getting a member says which way it is.

use std::sync::Arc;

use axum::http::HeaderMap;
use trigon_api::{Api, Index, Principal, Switches};
use trigon_archive::Limits;
use trigon_compare::compare_bytes;
use trigon_core::{Digest, Format};
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn run(id: &str, upstream: ArtifactRef, rebuild: Option<ArtifactRef>) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        "pkg:nuget/demo@1.0.0",
        upstream,
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
    r.rebuild = rebuild;
    r
}

async fn kept(store: &Store, name: &str, bytes: &[u8]) -> ArtifactRef {
    ArtifactRef {
        name: name.into(),
        sha256: store.blobs().put(bytes.to_vec()).await.unwrap(),
        bytes: bytes.len() as u64,
        stored: true,
    }
}

async fn operator_over(store: Arc<Store>, records: &[RunRecord]) -> Arc<Api> {
    for r in records {
        store.put_run(r).await.unwrap();
    }
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

async fn fetch(api: Arc<Api>, path: &str) -> (u16, HeaderMap, Vec<u8>) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut router = trigon_api::router(api);
    let res = router
        .call(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, headers, bytes.to_vec())
}

async fn json(api: Arc<Api>, path: &str) -> (u16, serde_json::Value) {
    let (status, _, body) = fetch(api, path).await;
    let v = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("{path} did not answer JSON ({e}): {body:?}"));
    (status, v)
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// A query value, percent-encoded byte by byte: a member path is anything an archive can hold.
fn q(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut b = tar::Builder::new(&mut out);
        for (name, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *body).unwrap();
        }
        b.finish().unwrap();
    }
    out
}

/// A `.nupkg` whose portable-library folder is spelled `portable`, as the two real spellings of one
/// folder differ between a published package and a rebuilt one.
fn nupkg(portable: &str) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, body) in [
            (format!("lib/{portable}/x.dll"), &b"MZ\x90\x00payload"[..]),
            ("x.nuspec".into(), b"<package/>"),
        ] {
            use std::io::Write as _;
            w.start_file(name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
    }
    out
}

const CANONICAL: &str = "lib/portable-net45+win8+wp8+wpa81/x.dll";

/// A member the comparison names after a renaming pass is found in each artifact through the
/// route, under the name that artifact carries: in the diff, and in the download beside it.
///
/// Measured before the fallback existed: 5 of 23 members on one real NuGet divergence page were
/// dead links. The reading half is asserted in `seam_comparison_projection.rs`; this is the half a
/// reader clicks.
#[tokio::test]
async fn a_renamed_member_is_read_from_both_artifacts_by_the_name_the_comparison_gave_it() {
    let up = nupkg("portable-net45%2Bwin8%2Bwp8%2Bwpa81");
    let rb = nupkg("portable45-net45+win8+wp8+wpa81");
    let set = trigon_stabilize::profile("nupkg").expect("the nupkg profile");
    let c = compare_bytes(
        up.clone(),
        rb.clone(),
        Format::Zip,
        &set,
        &Limits::default(),
    )
    .expect("compare");

    let store = Arc::new(Store::in_memory());
    let mut r = run(
        "1700000001-aa",
        kept(&store, "demo.1.0.0.nupkg", &up).await,
        Some(kept(&store, "demo.1.0.0.nupkg", &rb).await),
    );
    r.comparison = Some(
        store
            .blobs()
            .put(serde_json::to_vec(&c).unwrap())
            .await
            .unwrap(),
    );
    let api = operator_over(store, &[r]).await;

    let (status, view) = json(
        api.clone(),
        &format!("/v1/runs/1700000001-aa/member?path={}", q(CANONICAL)),
    )
    .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["in_upstream"], true, "{view}");
    assert_eq!(view["in_rebuild"], true, "{view}");
    assert!(view["unavailable"].is_null(), "{view}");

    for side in ["upstream", "rebuild"] {
        let (status, headers, body) = fetch(
            api.clone(),
            &format!(
                "/v1/runs/1700000001-aa/member/raw?path={}&side={side}",
                q(CANONICAL)
            ),
        )
        .await;
        assert_eq!(status, 200, "{side}: {}", String::from_utf8_lossy(&body));
        assert_eq!(body, b"MZ\x90\x00payload", "{side}");
        assert_eq!(
            header(&headers, "content-disposition"),
            format!("attachment; filename=\"{side}-x.dll\"")
        );
    }
}

/// A download is bytes, whatever the member is called.
///
/// A member path is attacker-controlled, and these are bytes from an artifact we did not write: a
/// browser that rendered them because the name ends in `.html` would run somebody else's content
/// on this origin, and a name that could close its own quotes would say what the header means.
#[tokio::test]
async fn a_member_with_a_hostile_name_downloads_as_bytes_under_a_name_that_says_nothing_else() {
    let hostile = "package/<img src=x onerror=alert(1)>\"; filename=evil.html";
    let body: &[u8] = b"<html><script>alert('member')</script></html>";
    let store = Arc::new(Store::in_memory());
    let artifact = tar_of(&[(hostile, body), ("package/$$$", b"nameless")]);
    let r = run(
        "1700000001-aa",
        kept(&store, "demo.tar", &artifact).await,
        None,
    );
    let api = operator_over(store, &[r]).await;

    let (status, headers, served) = fetch(
        api.clone(),
        &format!("/v1/runs/1700000001-aa/member/raw?path={}", q(hostile)),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&served));
    assert_eq!(served, body);
    assert_eq!(header(&headers, "content-type"), "application/octet-stream");
    assert_eq!(header(&headers, "x-content-type-options"), "nosniff");
    let disposition = header(&headers, "content-disposition");
    assert_eq!(
        disposition,
        "attachment; filename=\"upstream-imgsrcxonerroralert1filenameevil.html\""
    );

    // A name with nothing a header may carry is still a name.
    let (status, headers, served) = fetch(
        api,
        &format!(
            "/v1/runs/1700000001-aa/member/raw?path={}",
            q("package/$$$")
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(served, b"nameless");
    assert_eq!(
        header(&headers, "content-disposition"),
        "attachment; filename=\"upstream-member\""
    );
}

/// Each way of not getting a member's bytes says which way it is.
#[tokio::test]
async fn a_download_that_cannot_be_served_says_why() {
    let store = Arc::new(Store::in_memory());
    let artifact = tar_of(&[("package/index.js", b"module.exports = 1;\n")]);
    let only_upstream = run(
        "1700000001-aa",
        kept(&store, "demo.tar", &artifact).await,
        None,
    );
    let dropped = run(
        "1700000002-bb",
        ArtifactRef {
            stored: false,
            ..kept(&store, "demo.tar", &artifact).await
        },
        None,
    );
    let api = operator_over(store, &[only_upstream, dropped]).await;
    let path = q("package/index.js");

    let refused = async |uri: String| {
        let (status, v) = json(api.clone(), &uri).await;
        (
            status,
            v["error"].as_str().unwrap_or_default().to_string(),
            v["detail"].to_string(),
        )
    };

    // Two sides, and no third.
    let (status, code, _) = refused(format!(
        "/v1/runs/1700000001-aa/member/raw?path={path}&side=sideways"
    ))
    .await;
    assert_eq!((status, code.as_str()), (400, "no_such_side"));

    // A run that produced no artifact has only the published one.
    let (status, code, detail) = refused(format!(
        "/v1/runs/1700000001-aa/member/raw?path={path}&side=rebuild"
    ))
    .await;
    assert_eq!((status, code.as_str()), (404, "no_such_side"));
    assert!(detail.contains("has only the first"), "{detail}");

    // Retention dropped the bytes: said as that, and not as a member the artifact lacks.
    let (status, code, detail) =
        refused(format!("/v1/runs/1700000002-bb/member/raw?path={path}")).await;
    assert_eq!((status, code.as_str()), (404, "not_kept"), "{detail}");

    // The artifact is there and the member is not.
    let (status, code, _) = refused(format!(
        "/v1/runs/1700000001-aa/member/raw?path={}",
        q("package/absent.js")
    ))
    .await;
    assert_eq!((status, code.as_str()), (404, "no_such_member"));
}

/// Bytes that do not hash to the digest the record names are not read from, and the page says the
/// store would not return them rather than that the member is absent. Where one side is readable,
/// it is shown, beside the reason the other is not.
#[tokio::test]
async fn an_artifact_whose_bytes_are_not_its_digest_is_not_read_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::local(dir.path()).unwrap());
    let upstream = tar_of(&[("package/index.js", b"module.exports = 1;\n")]);
    let rebuilt = tar_of(&[("package/index.js", b"module.exports = 2;\n")]);
    let up = kept(&store, "demo.tar", &upstream).await;
    let rb = kept(&store, "demo.tar", &rebuilt).await;
    let corrupt = |d: &Digest| {
        let hex = d.to_hex();
        std::fs::write(
            dir.path().join(format!("blobs/sha256/{}/{hex}", &hex[..2])),
            tar_of(&[("package/index.js", b"SUBSTITUTED\n")]),
        )
        .unwrap();
    };
    corrupt(&rb.sha256);
    let partly = run("1700000001-aa", up.clone(), Some(rb.clone()));
    let api = operator_over(store.clone(), &[partly]).await;
    let path = q("package/index.js");

    let (status, view) = json(
        api.clone(),
        &format!("/v1/runs/1700000001-aa/member?path={path}"),
    )
    .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["in_upstream"], true);
    assert_eq!(view["in_rebuild"], false);
    let why = view["unavailable"].as_str().unwrap_or_default();
    assert!(
        why.contains("rebuild") && why.contains("would not return it"),
        "the unreadable side was not named: {view}"
    );
    assert!(!view.to_string().contains("SUBSTITUTED"), "{view}");

    let (status, v) = json(
        api.clone(),
        &format!("/v1/runs/1700000001-aa/member/raw?path={path}&side=rebuild"),
    )
    .await;
    assert_eq!(
        (status, v["error"].as_str()),
        (404, Some("no_such_blob")),
        "{v}"
    );

    // Both sides unreadable: nothing to show, and the reason is the store, not the member.
    corrupt(&up.sha256);
    let (status, v) = json(api, &format!("/v1/runs/1700000001-aa/member?path={path}")).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (404, Some("unreadable_member")),
        "{v}"
    );
}

/// A binary member can be paged: the view asked for an offset is the window there, with the whole
/// file's counts beside it.
#[tokio::test]
async fn a_member_view_pages_to_the_offset_asked_for() {
    let mut a = vec![0u8; 20_000];
    a[0] = 0x7f;
    let mut b = a.clone();
    b[100] = 1;
    let store = Arc::new(Store::in_memory());
    let r = run(
        "1700000001-aa",
        kept(&store, "demo.tar", &tar_of(&[("package/blob.bin", &a)])).await,
        Some(kept(&store, "demo.tar", &tar_of(&[("package/blob.bin", &b)])).await),
    );
    let api = operator_over(store, &[r]).await;

    let (status, view) = json(
        api,
        &format!(
            "/v1/runs/1700000001-aa/member?path={}&offset=12345",
            q("package/blob.bin")
        ),
    )
    .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["binary"], true);
    assert_eq!(view["hex"]["regions"][0]["offset"], 12_345 & !0xF);
    assert_eq!(view["hex"]["first_difference"], 100);
}

/// A deep link to a member boots what the route would say, for the reader it would say it to: a
/// member that is not there boots nothing, and one side that cannot be read boots the other with
/// the reason.
#[tokio::test]
async fn a_deep_link_boots_the_member_as_the_route_would_show_it() {
    fn boot_of(page: &str) -> serde_json::Value {
        let island = page
            .split_once("<script type=\"application/json\" id=\"boot\">")
            .and_then(|(_, rest)| rest.split_once("</script>"))
            .map(|(json, _)| json)
            .expect("the document has a boot island");
        serde_json::from_str(island).expect("the boot island is JSON")
    }

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::local(dir.path()).unwrap());
    let up = kept(
        &store,
        "demo.tar",
        &tar_of(&[("package/index.js", b"one\n")]),
    )
    .await;
    let rb = kept(
        &store,
        "demo.tar",
        &tar_of(&[("package/index.js", b"two\n")]),
    )
    .await;
    let hex = rb.sha256.to_hex();
    std::fs::write(
        dir.path().join(format!("blobs/sha256/{}/{hex}", &hex[..2])),
        b"not the rebuilt artifact",
    )
    .unwrap();
    let api = operator_over(store, &[run("1700000001-aa", up, Some(rb))]).await;

    let (status, _, page) = fetch(
        api.clone(),
        &format!("/runs/1700000001-aa?member={}", q("package/absent.js")),
    )
    .await;
    assert_eq!(status, 200);
    let boot = boot_of(&String::from_utf8_lossy(&page));
    assert!(
        boot["run"].is_object(),
        "the run itself still boots: {boot}"
    );
    assert!(boot["member"].is_null(), "{}", boot["member"]);

    let (status, _, page) = fetch(
        api,
        &format!(
            "/runs/1700000001-aa?member={}&view=text",
            q("package/index.js")
        ),
    )
    .await;
    assert_eq!(status, 200);
    let boot = boot_of(&String::from_utf8_lossy(&page));
    assert_eq!(boot["member"]["view"], "text");
    let member = &boot["member"]["member"];
    assert_eq!(member["in_upstream"], true, "{member}");
    assert_eq!(member["in_rebuild"], false, "{member}");
    assert!(
        member["unavailable"]
            .as_str()
            .is_some_and(|w| w.contains("would not return it")),
        "{member}"
    );
}
