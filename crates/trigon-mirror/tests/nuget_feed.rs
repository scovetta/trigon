//! The NuGet V3 feed as `dotnet restore` sees it.
//!
//! Live against api.nuget.org, because the shapes that matter here are upstream's: which
//! registration pages arrive inline, where `packageContent` points, and what a `published` looks
//! like. A fixture would pin what I believed rather than what the feed does.

use trigon_mirror::Mirror;

#[track_caller]
fn refuse_to_skip(why: &str) {
    if std::env::var("TRIGON_TESTS_MUST_RUN").as_deref() == Ok("1") {
        panic!("TRIGON_TESTS_MUST_RUN=1 but this test skipped: {why}");
    }
    eprintln!("skipped: {why}");
}

fn live() -> bool {
    if std::env::var("TRIGON_LIVE").as_deref() == Ok("1") {
        return true;
    }
    refuse_to_skip("set TRIGON_LIVE=1");
    false
}

async fn get(addr: &std::net::SocketAddr, path: &str) -> (u16, String) {
    let url = format!("http://{addr}{path}");
    let r = reqwest::get(&url).await.expect("the mirror answers");
    let status = r.status().as_u16();
    (status, r.text().await.unwrap_or_default())
}

/// A moment long after every version below, so the filter is not what removes them.
const NOW: &str = "2030-01-01T00:00:00Z";
/// Before Newtonsoft.Json 12 and after 11.0.1.
const EARLY_2018: &str = "2018-06-01T00:00:00Z";

#[tokio::test]
async fn the_service_index_points_every_resource_back_at_this_mirror() {
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let (status, body) = get(&m.addr, &format!("/-nuget/{NOW}/index.json")).await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("json");

    let resources = doc["resources"].as_array().expect("resources");
    assert!(!resources.is_empty());
    for r in resources {
        let id = r["@id"].as_str().unwrap_or_default();
        // The whole point. A resource still naming api.nuget.org is one the client would fetch
        // directly, which at an enforced tier is a refusal and everywhere else is an unfiltered
        // answer — and the second is worse, because it succeeds.
        assert!(
            id.starts_with(&format!("http://{}/-nuget/", m.addr)),
            "resource {} points off the mirror: {id}",
            r["@type"]
        );
        assert!(id.contains(NOW), "resource {id} lost the moment");
    }

    // Both resources a restore needs.
    let types: Vec<&str> = resources
        .iter()
        .filter_map(|r| r["@type"].as_str())
        .collect();
    assert!(types.contains(&"PackageBaseAddress/3.0.0"), "{types:?}");
    assert!(
        types.iter().any(|t| t.starts_with("RegistrationsBaseUrl")),
        "{types:?}"
    );

    // **Follow them.** Asserting the prefix let a doubled path through — the resources read
    // `/-nuget/<moment>/-nuget/flat/`, which still starts with `/-nuget/` and still contains the
    // moment, and which restore reported as `NU1101 … No packages exist with this id`: a message
    // about the package, for a URL that was never going to resolve. A URL is only advertised
    // correctly if asking for it answers.
    //
    // **Live, and only live.** Everything above is this mirror talking to itself; composing onto
    // a resource asks api.nuget.org. It went out ungated once, asserting only that the answer was
    // not a 404 — which the 502 a machine with no network gets passed, so a plain `cargo test`
    // made the requests and proved nothing by them. Offline, `seam_routes_served_from_the_cache`'s
    // `the_service_index_points_every_resource_back_here_and_each_one_answers` holds this line
    // against a seeded cache.
    if !live() {
        return;
    }
    for r in resources {
        let id = r["@id"].as_str().unwrap();
        let path = id.strip_prefix(&format!("http://{}", m.addr)).unwrap();
        // A base address is a prefix, so probe it the way a client composes one.
        let probe = format!("{path}newtonsoft.json/index.json");
        let (status, body) = get(&m.addr, &probe).await;
        assert_eq!(
            status, 200,
            "the index advertises {id}, and composing a request onto it does not answer: \
             {probe} -> {body}"
        );
    }
}

#[tokio::test]
async fn a_registration_is_filtered_to_the_moment() {
    if !live() {
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let (status, body) = get(
        &m.addr,
        &format!("/-nuget/{EARLY_2018}/reg/newtonsoft.json/index.json"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();

    let mut versions = Vec::new();
    for page in doc["items"].as_array().expect("pages") {
        for leaf in page["items"].as_array().expect("leaves inline") {
            versions.push(
                leaf["catalogEntry"]["version"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
    }
    assert!(!versions.is_empty(), "everything was filtered away");
    assert!(
        versions.iter().any(|v| v == "11.0.1"),
        "11.0.1 was published before the moment and should survive"
    );
    // 12.0.1 is from November 2018. A filter that let it through would be doing nothing.
    assert!(
        !versions.iter().any(|v| v.starts_with("12.")),
        "a version published after the moment survived: {versions:?}"
    );
}

#[tokio::test]
async fn a_package_whose_pages_are_all_remote_is_still_filtered() {
    // **The trap this route exists to avoid.** `system.text.json` has three registration pages and
    // none of them carry their leaves inline — a filter that read only what arrived would report
    // that it removed nothing and pass every version through, and it would look correct against
    // `newtonsoft.json`, which is wholly inline.
    if !live() {
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    // 2020-01-01: after System.Text.Json's first releases (the earliest listed leaf on its first
    // page is 2019-05-10) and well before 5.0.0. A moment before the package existed at all would
    // pass this test by filtering everything, which proves nothing about paging.
    let (status, body) = get(
        &m.addr,
        "/-nuget/2020-01-01T00:00:00Z/reg/system.text.json/index.json",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();

    let mut versions = Vec::new();
    for page in doc["items"].as_array().expect("pages") {
        let leaves = page["items"]
            .as_array()
            .expect("every page inlined, including the remote ones");
        for leaf in leaves {
            versions.push(
                leaf["catalogEntry"]["version"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
    }
    // Survivors prove the remote pages were fetched *and* read: an unfetched page yields nothing,
    // and an unfiltered one yields everything. Both halves are asserted.
    assert!(
        versions.iter().any(|v| v.starts_with("4.")),
        "the 2019 releases should have survived a 2020 moment: {versions:?}"
    );
    assert!(
        !versions.iter().any(|v| v.starts_with("5.")
            || v.starts_with("6.")
            || v.starts_with("8.")
            || v.starts_with("9.")),
        "a version published after the moment survived: {versions:?}"
    );
}

#[tokio::test]
async fn the_flat_container_version_list_is_derived_from_the_filtered_registration() {
    if !live() {
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let (status, body) = get(
        &m.addr,
        &format!("/-nuget/{EARLY_2018}/flat/newtonsoft.json/index.json"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let versions: Vec<&str> = doc["versions"]
        .as_array()
        .expect("versions")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert!(versions.contains(&"11.0.1"), "{versions:?}");
    // Upstream's own flat-container list has no dates on it, so a mirror that proxied it would
    // answer with every version and report that it had filtered. This is the check that it did not.
    assert!(
        !versions.iter().any(|v| v.starts_with("12.")),
        "the version list was not filtered: {versions:?}"
    );
}

#[tokio::test]
async fn package_content_urls_point_at_the_mirror() {
    if !live() {
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let (_, body) = get(
        &m.addr,
        &format!("/-nuget/{EARLY_2018}/reg/newtonsoft.json/index.json"),
    )
    .await;
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut checked = 0;
    for page in doc["items"].as_array().unwrap() {
        for leaf in page["items"].as_array().unwrap() {
            let url = leaf["packageContent"].as_str().expect("packageContent");
            assert!(
                url.starts_with(&format!("http://{}/-nuget/", m.addr)),
                "a download URL still points upstream, which an enforced tier cannot reach: {url}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "nothing was checked");
}

#[tokio::test]
async fn a_shape_this_route_does_not_serve_is_named_rather_than_guessed_at() {
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let (status, body) = get(&m.addr, &format!("/-nuget/{NOW}/nonsense/x")).await;
    assert_eq!(status, 404, "{body}");
    assert!(
        body.contains("/-nuget/<moment>/"),
        "the error should say what it does serve: {body}"
    );

    // A request with no moment at all must not be answered with an unfiltered anything.
    let (status, _) = get(&m.addr, "/-nuget/index.json").await;
    assert_eq!(
        status, 400,
        "a feed with no moment is not a feed this mirror serves"
    );
}

#[tokio::test]
async fn the_toolchains_own_packages_are_not_dated() {
    // `Microsoft.NETCore.App.Ref` is a targeting pack the SDK picks for itself. Filtering it by the
    // package's publish date leaves a constraint nothing can satisfy — measured as
    // `NU1102 … Found 91 version(s) [ Nearest version: 7.0.0-preview… ]` against a build that
    // wanted 6.0.36 — and the question it answers is "when did Microsoft ship this toolchain",
    // which is not a dependency decision.
    if !live() {
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    // A moment long before 6.0.36 existed.
    let (status, body) = get(
        &m.addr,
        "/-nuget/2020-01-01T00:00:00Z/flat/microsoft.netcore.app.ref/index.json",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let versions: Vec<&str> = doc["versions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        versions.iter().any(|v| v.starts_with("6.0.")),
        "a targeting pack released after the moment should still be offered: {versions:?}"
    );

    // And the exemption is narrow: a package a project actually depends on is still dated.
    let (_, body) = get(
        &m.addr,
        "/-nuget/2020-01-01T00:00:00Z/flat/newtonsoft.json/index.json",
    )
    .await;
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let versions: Vec<&str> = doc["versions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        !versions.iter().any(|v| v.starts_with("13.")),
        "the exemption leaked to an ordinary package: {versions:?}"
    );
}
