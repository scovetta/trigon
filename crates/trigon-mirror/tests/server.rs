//! The mirror as a package manager sees it.

use trigon_mirror::{Filter, Mirror, Platform, normalize, published_by, url_for};

#[test]
fn the_filter_rides_in_the_credentials() {
    // The one configuration channel every package manager forwards on every request, which is why
    // this works with no per-client support and no MITM.
    let f = Filter::from_authorization("Basic bnBtOjIwMTgtMDQtMDlUMDE6MTA6NDVa").unwrap();
    assert_eq!(f.platform, Platform::Npm);
    assert_eq!(f.moment, "2018-04-09T01:10:45");
}

#[test]
fn the_timestamps_colons_stay_with_the_timestamp() {
    // Split on the first colon only: an RFC 3339 instant contains two more and they are not
    // separators. Splitting on the last would give a password of "45Z".
    let encoded = base64("npm:2018-04-09T01:10:45.796Z");
    let f = Filter::from_authorization(&format!("Basic {encoded}")).unwrap();
    assert_eq!(f.moment, "2018-04-09T01:10:45");
}

#[test]
fn a_request_with_no_filter_is_refused_rather_than_passed_through() {
    // Serving the index as it is today is the exact opposite of what this exists for, and doing it
    // silently would make every rebuild behind the mirror quietly meaningless.
    let e = Filter::from_authorization("Bearer something").unwrap_err();
    assert!(
        e.to_string().contains("opposite of what this exists for"),
        "{e}"
    );
    assert_eq!(e.status(), 400);
}

#[test]
fn an_unknown_platform_says_what_is_served() {
    let e = Filter::from_authorization(&format!("Basic {}", base64("maven:2018-01-01T00:00:00")))
        .unwrap_err();
    assert!(e.to_string().contains("npm and pypi"), "{e}");
}

#[test]
fn registry_timestamp_dialects_all_normalize() {
    // npm writes milliseconds, PyPI writes microseconds, and PyPI's older field writes a space
    // instead of a T. All are UTC, so the only thing between them and a lexical comparison is the
    // fractional part and the separator.
    for s in [
        "2024-02-25T23:20:01.196159Z",
        "2024-02-25T23:20:01Z",
        "2024-02-25 23:20:01",
        "2024-02-25T23:20:01+00:00",
        "2024-02-25T23%3A20%3A01Z",
    ] {
        assert_eq!(normalize(s).unwrap(), "2024-02-25T23:20:01", "{s}");
    }
}

#[test]
fn a_timestamp_that_will_not_normalize_is_refused_not_guessed() {
    // A silently mis-parsed filter serves a different index than the one asked for, and the
    // rebuild is then of a different dependency graph with nothing to show it.
    for s in ["yesterday", "2024-02", "1708902001"] {
        assert!(normalize(s).is_err(), "{s} should not normalize");
    }
}

#[test]
fn comparison_is_lexical_and_inclusive() {
    assert!(published_by(
        "2018-04-09T01:10:45.796Z",
        "2018-04-09T01:10:45"
    ));
    assert!(published_by("2018-04-09T01:10:44Z", "2018-04-09T01:10:45"));
    assert!(!published_by("2018-04-09T01:10:46Z", "2018-04-09T01:10:45"));
    // Not orderable, so not published in time. Including what we cannot date would let a rebuild
    // resolve a version we could not place in time.
    assert!(!published_by("who knows", "2018-04-09T01:10:45"));
}

#[test]
fn the_url_is_the_one_a_package_manager_is_configured_with() {
    assert_eq!(
        url_for("timewarp:8129", Platform::Npm, "2018-04-09T01:10:45"),
        "http://npm:2018-04-09T01:10:45@timewarp:8129"
    );
}

#[tokio::test]
async fn the_server_starts_and_stops() {
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    assert_ne!(m.addr.port(), 0);
    m.shutdown().await;
}

#[tokio::test]
async fn an_unfiltered_request_gets_a_400_rather_than_the_live_index() {
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let resp = reqwest::Client::new()
        .get(format!("http://{}/left-pad", m.host()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("no time filter"));
    m.shutdown().await;
}

#[tokio::test]
async fn npm_sees_the_index_as_it_was() {
    if std::env::var("TRIGON_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set TRIGON_LIVE=1");
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let packument = |moment: &str| {
        let url = format!("http://npm:{moment}@{}/left-pad", m.host());
        async move {
            reqwest::get(&url)
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };

    // left-pad 1.3.0 was published 2018-04-09T01:10:45.796Z.
    let after = packument("2018-04-09T01:10:46").await;
    assert!(after["versions"].get("1.3.0").is_some());
    assert_eq!(after["dist-tags"]["latest"], "1.3.0");

    let before = packument("2018-04-09T01:10:44").await;
    assert!(
        before["versions"].get("1.3.0").is_none(),
        "a version published a second later must not be resolvable"
    );
    // And the tag follows, or every install of a floating range fails on a missing version.
    assert_eq!(before["dist-tags"]["latest"], "1.2.0");

    m.shutdown().await;
}

#[tokio::test]
async fn pypi_sees_the_index_as_it_was() {
    if std::env::var("TRIGON_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set TRIGON_LIVE=1");
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let files = |moment: &str| {
        let url = format!("http://pypi:{moment}@{}/simple/sniffio/", m.host());
        async move {
            let doc: serde_json::Value = reqwest::Client::new()
                .get(&url)
                .header("Accept", "application/vnd.pypi.simple.v1+json")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            doc["files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["filename"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        }
    };

    // sniffio 1.3.1 was uploaded 2024-02-25T23:20:01Z.
    let after = files("2024-02-26T00:00:00").await;
    assert!(after.iter().any(|f| f.contains("1.3.1")));
    let before = files("2024-02-25T00:00:00").await;
    assert!(!before.iter().any(|f| f.contains("1.3.1")), "{before:?}");
    assert!(before.iter().any(|f| f.contains("1.3.0")));

    m.shutdown().await;
}

fn base64(s: &str) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = s.as_bytes();
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
