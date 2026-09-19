//! The mirror as a package manager sees it.

use trigon_mirror::{Filter, Mirror, Platform, normalize, published_by, url_for};

/// A skip the caller was supposed to have prevented.
///
/// Every gate below is a thing *the environment* controls — podman is installed or it is not, the
/// image was pulled or it was not, `TRIGON_LIVE` was set or it was not. A gate like that reports
/// `ok` when it declines to run, so a CI job that forgets one of them is green and says nothing,
/// which is how thirteen container tests came to skip on every pull request for the life of the
/// repository.
///
/// `TRIGON_TESTS_MUST_RUN=1` is the job asserting it did its setup: under it a gate of this kind
/// is a failure, not a skip. Conditions the job does *not* control — an upstream host being
/// unreachable — stay skips, and say so where they are written.
#[track_caller]
fn refuse_to_skip(why: &str) {
    if std::env::var("TRIGON_TESTS_MUST_RUN").as_deref() == Ok("1") {
        panic!("TRIGON_TESTS_MUST_RUN=1 but this test skipped: {why}");
    }
    eprintln!("skipped: {why}");
}

/// Whether a test that talks to a real registry should run.
fn live() -> bool {
    if std::env::var("TRIGON_LIVE").as_deref() == Ok("1") {
        return true;
    }
    refuse_to_skip("set TRIGON_LIVE=1");
    false
}

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
async fn a_toolchain_host_outside_the_allowlist_is_refused() {
    // The toolchain route exists because the deps phase runs inside the network island and needs a
    // pinned Node. What it must not become is a general proxy: at `mirror-only` egress this server
    // is the only host the build can reach, so an open toolchain route hands the build back the
    // internet under a different path.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{}/-toolchain/evil.example/x.tar.gz",
            m.host()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("evil.example"), "{body}");

    // Exact match, not a suffix: the obvious `ends_with` rule accepts this one.
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{}/-toolchain/evil-nodejs.org/x.tar.gz",
            m.host()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    assert!(trigon_mirror::toolchain_host_allowed("nodejs.org"));
    assert!(trigon_mirror::toolchain_host_allowed(
        "static.rust-lang.org"
    ));
    // The same exact-match rule as above, on the host this list gained for crates.io.
    assert!(!trigon_mirror::toolchain_host_allowed(
        "static.rust-lang.org.evil.example"
    ));
    assert!(!trigon_mirror::toolchain_host_allowed(
        "evil-static.rust-lang.org"
    ));
    assert!(!trigon_mirror::toolchain_host_allowed(
        "nodejs.org.evil.example"
    ));
    m.shutdown().await;
}

#[tokio::test]
async fn an_artifact_host_outside_the_allowlist_is_refused() {
    // This route had no allowlist at all, and the consequence was measured rather than argued:
    // `/-artifact/npm/<moment>/example.com/` returned 200 with example.com's home page while the
    // toolchain route returned 403 for the same host. It also sits before the credential check, so
    // it needed none. At `mirror-only` that made the build's only route out a general proxy to the
    // internet — a larger hole than the one it was found while closing.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let get = |path: String| {
        let url = format!("http://{}{path}", m.host());
        async move { reqwest::Client::new().get(&url).send().await.unwrap() }
    };

    let resp = get("/-artifact/npm/2024-01-01T00:00:00Z/example.com/".into()).await;
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("example.com"), "{body}");
    assert!(body.contains("artifact"), "the route is named: {body}");

    // Exact match, not a suffix: the obvious `ends_with` rule accepts this.
    let resp =
        get("/-artifact/npm/2024-01-01T00:00:00Z/registry.npmjs.org.evil.example/x".into()).await;
    assert_eq!(resp.status(), 403);

    assert!(trigon_mirror::artifact_host_allowed("registry.npmjs.org"));
    assert!(trigon_mirror::artifact_host_allowed(
        "files.pythonhosted.org"
    ));
    assert!(!trigon_mirror::artifact_host_allowed(
        "registry.npmjs.org.evil.example"
    ));
    assert!(!trigon_mirror::artifact_host_allowed("example.com"));
    m.shutdown().await;
}

#[tokio::test]
async fn a_toolchain_download_comes_back_through_the_mirror() {
    if !live() {
        return;
    }
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{}/-toolchain/nodejs.org/dist/v9.2.1/SHASUMS256.txt",
            m.host()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("node-v9.2.1-linux-x64.tar.gz")
    );
    assert_eq!(m.observed().toolchain_requests, 1);
    // And it counts as contact, so a run cannot report "the mirror was never asked for anything"
    // while the toolchain came through it.
    assert!(m.observed().contacted());
    m.shutdown().await;
}

#[tokio::test]
async fn npm_sees_the_index_as_it_was() {
    if !live() {
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
    if !live() {
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

#[tokio::test]
async fn artifact_urls_point_back_at_the_mirror() {
    if !live() {
        return;
    }
    // Without this a build behind an enforced egress boundary resolves a version and then cannot
    // fetch it: the packument's dist.tarball is an absolute upstream URL, and upstream is exactly
    // what the boundary forbids. Found by running a build under mirror-only, where npm resolved
    // left-pad 1.2.0 through the mirror and then failed with ENETUNREACH on registry.npmjs.org.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let doc: serde_json::Value = reqwest::get(format!(
        "http://npm:2018-04-09T01:10:46@{}/left-pad",
        m.host()
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let tarball = doc["versions"]["1.3.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    // Addressed at the mirror, with the filter in the path rather than in credentials. npm
    // forwards the registry's credentials to the packument request and not to the tarball request,
    // so a URL relying on them comes back unfiltered and is refused.
    assert!(
        tarball.starts_with(&format!(
            "http://{}/-artifact/npm/2018-04-09T01:10:46/",
            m.host()
        )),
        "the tarball must be fetchable from the mirror: {tarball}"
    );
    assert!(tarball.ends_with("left-pad-1.3.0.tgz"), "{tarball}");

    // And it serves the bytes rather than redirecting somewhere the build cannot reach.
    let bytes = reqwest::get(tarball).await.unwrap().bytes().await.unwrap();
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "a gzip member");
    assert_eq!(bytes.len(), 3619);
    m.shutdown().await;
}

#[tokio::test]
async fn pypi_file_urls_point_back_at_the_mirror() {
    if !live() {
        return;
    }
    // PyPI serves files from a separate CDN host, so the upstream host rides in the rewritten path:
    // dropping it would leave nothing to proxy to.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let doc: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://pypi:2024-02-26T00:00:00@{}/simple/sniffio/",
            m.host()
        ))
        .header("Accept", "application/vnd.pypi.simple.v1+json")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let url = doc["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["filename"]
                .as_str()
                .unwrap()
                .ends_with("1.3.1-py3-none-any.whl")
        })
        .map(|f| f["url"].as_str().unwrap().to_string())
        .unwrap();
    assert!(
        url.starts_with(&format!(
            "http://{}/-artifact/pypi/2024-02-26T00:00:00/",
            m.host()
        )),
        "{url}"
    );
    assert!(
        url.contains("files.pythonhosted.org"),
        "the real host must survive: {url}"
    );

    let bytes = reqwest::get(&url).await.unwrap().bytes().await.unwrap();
    assert_eq!(&bytes[..2], b"PK");
    m.shutdown().await;
}

#[tokio::test]
async fn the_mirror_refuses_the_runs_own_artifact() {
    if !live() {
        return;
    }
    // The cheapest control there is. At mirror-only egress this is the only reachable host, so a
    // build that asks for its own published artifact gets nothing.
    let manifest = trigon_mirror::GuardManifest {
        refuse_url: Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into()),
        ..Default::default()
    };
    let m = Mirror::new()
        .unwrap()
        .with_guard(manifest)
        .serve(0)
        .await
        .unwrap();

    let url = format!(
        "http://{}/-artifact/npm/2018-04-09T01:10:46/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        m.host()
    );
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), 403);
    assert!(resp.text().await.unwrap().contains("proves nothing"));
    assert_eq!(
        m.trips().len(),
        1,
        "and the refusal is recorded, so the run is void"
    );

    // A different version is served normally: the guard is about this run's artifact, not the
    // package.
    let other = format!(
        "http://{}/-artifact/npm/2018-04-09T01:10:46/registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz",
        m.host()
    );
    assert_eq!(reqwest::get(&other).await.unwrap().status(), 200);
    m.shutdown().await;
}

#[tokio::test]
async fn the_artifact_arriving_from_anywhere_trips_the_guard() {
    if !live() {
        return;
    }
    // The case the URL refusal does not cover: the same bytes under a different name. This is what
    // a strategy fetching from cdn.evil.example looks like, and it is why the body is hashed rather
    // than the request matched.
    let bytes = reqwest::get("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let manifest = trigon_mirror::GuardManifest::for_artifact(
        &bytes,
        trigon_core::Format::TarGz,
        // No URL refusal, so only the hash can catch it.
        None,
    );
    let m = Mirror::new()
        .unwrap()
        .with_guard(manifest)
        .serve(0)
        .await
        .unwrap();

    let url = format!(
        "http://{}/-artifact/npm/2018-04-09T01:10:46/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        m.host()
    );
    let resp = reqwest::get(&url).await.unwrap();
    // Served, and noticed. The build still gets its bytes; what changes is the verdict.
    assert_eq!(resp.status(), 200);
    let got = resp.bytes().await.unwrap();
    assert_eq!(got.len(), bytes.len());

    let trips = m.trips();
    assert_eq!(trips.len(), 1, "the artifact under test reached the build");
    assert_eq!(trips[0].matched, trigon_mirror::GuardMatch::WholeArtifact);
    m.shutdown().await;
}

#[tokio::test]
async fn an_ordinary_dependency_does_not_trip_the_guard() {
    if !live() {
        return;
    }
    // Without this the control is worthless: a guard that fires on every build is one people turn
    // off. left-pad is guarded; ms is an unrelated package the build legitimately fetches.
    let bytes = reqwest::get("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let m = Mirror::new()
        .unwrap()
        .with_guard(trigon_mirror::GuardManifest::for_artifact(
            &bytes,
            trigon_core::Format::TarGz,
            Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into()),
        ))
        .serve(0)
        .await
        .unwrap();

    let url = format!(
        "http://{}/-artifact/npm/2024-01-01T00:00:00/registry.npmjs.org/ms/-/ms-2.1.3.tgz",
        m.host()
    );
    assert_eq!(reqwest::get(&url).await.unwrap().status(), 200);
    assert!(
        m.trips().is_empty(),
        "an unrelated dependency must pass through"
    );
    m.shutdown().await;
}

#[test]
fn the_source_filter_narrows_a_real_package() {
    // Needs a published artifact and a checkout of the repository it came from, which the test
    // does not fetch for itself. Point `TRIGON_GUARD_FIXTURE` at a directory holding `pkg.tgz` and
    // `src/`:
    //
    //     trigon fetch pkg:npm/semver@7.6.3 --out $F/pkg.tgz
    //     git clone --depth 1 -b v7.6.3 https://github.com/npm/node-semver $F/src
    let Ok(fixture) = std::env::var("TRIGON_GUARD_FIXTURE") else {
        refuse_to_skip("set TRIGON_GUARD_FIXTURE to a directory with pkg.tgz and src/");
        return;
    };
    let dir = std::path::Path::new(&fixture);
    if !dir.join("pkg.tgz").is_file() || !dir.join("src").is_dir() {
        refuse_to_skip(&format!("{fixture} has no pkg.tgz and src/"));
        return;
    }
    let bytes = std::fs::read(dir.join("pkg.tgz")).unwrap();

    let wide = trigon_mirror::GuardManifest::for_artifact(&bytes, trigon_core::Format::TarGz, None);
    let narrow = trigon_mirror::GuardManifest::for_artifact_with_source(
        &bytes,
        trigon_core::Format::TarGz,
        None,
        &dir.join("src"),
    );

    // Every published file of a pure-JavaScript package is in its repository, so the source filter
    // should remove most of the member set. What it leaves is whatever the publish step generated.
    assert!(
        !wide.members.is_empty(),
        "the package has members worth guarding"
    );
    assert!(
        narrow.members.len() < wide.members.len(),
        "the source filter removed nothing: {} vs {}",
        narrow.members.len(),
        wide.members.len()
    );
    assert!(narrow.filtered_out > wide.filtered_out);
    println!(
        "guarded members: {} without the source tree, {} with it",
        wide.members.len(),
        narrow.members.len()
    );
}

// --- The network transcript ---------------------------------------------------------------
//
// Tier 1 of `docs/08-execution.md` §7. The mirror already hashed every body that crossed it, to
// feed the artifact guard, and kept the hash only when it matched — so the answer to "what did
// this build download" was computed on every run and dropped. These cover the two halves that can
// go wrong without anything failing: the line surviving the trip out through a container log, and
// the guard reporting how far it actually got rather than how far it could have got.

#[test]
fn a_transcript_line_survives_the_trip_out_through_a_container_log() {
    // The escape is `podman logs`, so a line is written by one process, interleaved with unrelated
    // output, and read back by another. Round-tripped through the real formatter rather than a
    // hand-written copy of it: two spellings of one format is the bug this whole codebase keeps
    // finding, and here it would show up as a transcript that is silently short.
    let e = trigon_mirror::Exchange {
        route: "artifact".into(),
        url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into(),
        sha256: "e1".repeat(32),
        bytes: 2361,
        checked: trigon_mirror::Checked::Opened,
        withheld: None,
    };
    let log = format!(
        "2026-09-13T10:00:00Z  INFO trigon_mirror: listening\n{}\nsomething else entirely\n",
        e.line()
    );
    assert_eq!(trigon_mirror::Exchange::parse_log(&log).unwrap(), vec![e]);
}

#[test]
fn an_unreadable_transcript_line_is_an_error_rather_than_a_shorter_transcript() {
    // "We could not read one of these" and "there were fewer of these" are different answers, and
    // only one of them leaves the run attestable. Skipping the line would turn a truncated log or
    // a version skew into a clean, short, believable transcript.
    let log = format!("{} {{not json at all\n", trigon_mirror::EXCHANGE_MARKER);
    let e = trigon_mirror::Exchange::parse_log(&log).unwrap_err();
    assert!(e.contains("unreadable transcript line"), "{e}");
}

#[test]
fn a_log_with_no_transcript_lines_reads_as_a_transcript_of_nothing() {
    // The empty case has to be `Ok(vec![])` rather than an error: a build that downloaded nothing
    // is a real build, and it is the one `deny-all` produces every time.
    assert_eq!(
        trigon_mirror::Exchange::parse_log("listening\nfiltered a packument\n").unwrap(),
        vec![]
    );
}

#[test]
fn the_guard_reports_how_far_it_got_and_not_how_far_it_could_have() {
    use trigon_core::Digest;
    use trigon_mirror::{Checked, Guard, GuardManifest};

    // Every reason the member check stops early lives inside `observe`, so `observe` is what says
    // whether it ran. A caller reconstructing this from a size limit would call a body `opened`
    // that was never an archive — which is exactly the difference between a check that ran and one
    // that only looks like it did.
    let armed = Guard::new(GuardManifest {
        artifact: Some(Digest::from_bytes([1; 32])),
        members: [Digest::from_bytes([2; 32])].into_iter().collect(),
        ..Default::default()
    });
    let other = Digest::from_bytes([9; 32]);

    // Not an archive: hashed whole, never opened.
    assert_eq!(
        armed.observe("https://x/notes.txt", other, Some(b"plain text")),
        Checked::Hashed
    );
    // No body collected at all: the same answer, for a different reason, and neither is `opened`.
    assert_eq!(
        armed.observe("https://x/big.tgz", other, None),
        Checked::Hashed
    );
    // A real archive the guard walked. The manifest member is not in it, so nothing trips — and
    // that is the case where saying `opened` is a claim worth making.
    assert_eq!(
        armed.observe("https://x/dep.tgz", other, Some(&tiny_gzip_tar())),
        Checked::Opened
    );

    // With no manifest there is nothing to compare against, and a transcript that said `opened`
    // here would describe a check that does not exist on this run.
    let unarmed = Guard::default();
    assert_eq!(
        unarmed.observe("https://x/dep.tgz", other, Some(&tiny_gzip_tar())),
        Checked::Unarmed
    );
}

/// The smallest thing `sniff` accepts and `trigon_archive::parse` can walk.
fn tiny_gzip_tar() -> Vec<u8> {
    let mut tar = Vec::new();
    let mut header = [0u8; 512];
    header[..8].copy_from_slice(b"a.txt\0\0\0");
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000002\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[156] = b'0';
    // The checksum is computed with the checksum field read as spaces, then written into it.
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|b| *b as u32).sum();
    let text = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(text.as_bytes());
    tar.extend_from_slice(&header);
    let mut body = [0u8; 512];
    body[..2].copy_from_slice(b"hi");
    tar.extend_from_slice(&body);
    tar.extend_from_slice(&[0u8; 1024]);

    let mut out = Vec::new();
    let mut enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::none());
    std::io::Write::write_all(&mut enc, &tar).unwrap();
    enc.finish().unwrap();
    out
}

#[test]
fn a_credential_in_a_url_does_not_reach_the_transcript() {
    // `docs/08-execution.md` §6: the proxy sees plaintext and transcripts are shown to users. The
    // mirror's own rewritten URLs carry the pinned moment as a password, so the shape is one the
    // codebase already produces — and the cheap place to stop it is the one place an `Exchange` is
    // built, rather than in each of its readers.
    let e = trigon_mirror::Exchange::new(
        "index",
        "http://npm:2018-04-09T01:10:45Z@timewarp:8129/left-pad",
        "aa".repeat(32),
        12,
        trigon_mirror::Checked::Generated,
    );
    assert_eq!(e.url, "http://timewarp:8129/left-pad");
}

#[test]
fn an_at_sign_outside_the_authority_is_left_alone() {
    // Every scoped npm package has one in its path, and a redactor that ate those would quietly
    // rewrite the URLs that matter most.
    for url in [
        "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
        "https://files.pythonhosted.org/packages/a/b/x.whl?sig=a@b",
        "https://nodejs.org/dist/v20.11.0/SHASUMS256.txt",
    ] {
        let e = trigon_mirror::Exchange::new(
            "artifact",
            url,
            "bb".repeat(32),
            1,
            trigon_mirror::Checked::Hashed,
        );
        assert_eq!(e.url, url);
    }
}

#[test]
fn the_stored_form_and_the_log_form_are_read_by_different_readers() {
    // The marker is the container log's escape mechanism and is stripped before storage, so the
    // two forms differ. A single tolerant reader would read a blob of the wrong format as an empty
    // transcript — and an empty transcript is a *claim* here, that the build fetched nothing,
    // rather than an absence. That is the claim `attestable` is derived from.
    let e = trigon_mirror::Exchange::new(
        "index",
        "https://registry.npmjs.org/left-pad",
        "cc".repeat(32),
        4096,
        trigon_mirror::Checked::Generated,
    );
    let stored = format!("{}\n", serde_json::to_string(&e).unwrap());
    assert_eq!(
        trigon_mirror::Exchange::parse_jsonl(&stored).unwrap(),
        vec![e.clone()]
    );
    // The log form carries the marker, so the stored reader must refuse it rather than read it as
    // nothing.
    assert!(trigon_mirror::Exchange::parse_jsonl(&e.line()).is_err());
    // And a trailing newline — which every writer produces — is not an unreadable line.
    assert_eq!(
        trigon_mirror::Exchange::parse_jsonl("").unwrap(),
        Vec::<trigon_mirror::Exchange>::new()
    );
}

// --- The registry-pin evidence, and the two ways to compute it ------------------------------
//
// `docs/17-backlog.md` B7b. The counters live on the `Mirror` object; under `--egress mirror-only`
// that object runs inside the build's network island and the host has no route to it. So the one
// control that says "the pin actually bound something" — the counter that eventually exposed the
// `PIP_TRUSTED_HOST` finding — read `null` on exactly the tier where it is the claim, and read fine
// at `open`, where a build can ignore the mirror entirely.
//
// The fix derives the same counters from the transcript, which does get out. That is a second way
// to compute one thing, which is this project's most reliable bug shape, so these bind them.

#[test]
fn the_pin_evidence_counts_rows_rather_than_carrying_a_number_out() {
    use trigon_mirror::{Checked, Exchange, Observed};

    let row = |route: &str, withheld: Option<u64>| {
        let e = Exchange::new(route, "https://x/y", "aa".repeat(32), 10, Checked::Hashed);
        match withheld {
            Some(n) => e.withholding(n),
            None => e,
        }
    };
    let rows = vec![
        row("index", Some(40)),
        // Zero withheld is not the same as absent: the filter ran and found nothing to remove,
        // which is evidence the pin applied. Summing `Option` rather than a defaulted field is
        // what keeps that from collapsing into "no index documents were filtered".
        row("index", Some(0)),
        row("artifact", None),
        row("artifact", None),
        // An index host serving something no filter applied to. It is the build fetching a file,
        // not resolving against an index, which is the distinction `artifact_requests` draws.
        row("passthrough", None),
        row("toolchain", None),
    ];

    let o = Observed::from_transcript(&rows, 3);
    assert_eq!(o.index_requests, 2);
    assert_eq!(o.versions_withheld, 40);
    assert_eq!(o.artifact_requests, 3, "passthrough counts as a fetch");
    assert_eq!(o.toolchain_requests, 1);
    assert_eq!(o.rejected, 3);
    assert!(o.pin_bound());
    assert!(o.contacted());

    // And the empty case, which is the one that must not read like the populated one.
    let none = Observed::from_transcript(&[], 0);
    assert!(!none.pin_bound(), "nothing served is not a bound pin");
    assert!(!none.contacted());
}

#[tokio::test]
async fn a_refusal_reaches_the_counters_and_the_transcript_alike() {
    // Offline on purpose: every request here is refused before the mirror reaches upstream, so this
    // runs everywhere and still exercises the path that had no way out of the island at all. A
    // refusal serves no body, so it is not an `Exchange` — and a `rejected` count that stayed at
    // zero under an enforced tier would read exactly like a build nobody turned away.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let host = m.host();

    // No filter at all: the credentials that carry the pinned moment never arrived.
    assert_eq!(
        reqwest::get(format!("http://{host}/left-pad"))
            .await
            .unwrap()
            .status(),
        400
    );
    // A host nobody allowlisted, on each of the two routes that take one.
    for path in [
        "/-toolchain/evil.example/node.tar.gz",
        "/-artifact/npm/2024-01-01T00:00:00/evil.example/x.tgz",
    ] {
        let status = reqwest::get(format!("http://{host}{path}"))
            .await
            .unwrap()
            .status();
        assert!(
            status.is_client_error() || status.is_server_error(),
            "{path}: {status}"
        );
    }

    let counted = m.observed();
    assert_eq!(counted.rejected, 3);
    assert!(!counted.pin_bound());

    // The rows the mirror wrote, read back the way the host reads them out of a container log.
    let refusals = m.seen().refusals();
    assert_eq!(refusals.len(), 3, "{refusals:?}");
    assert!(
        refusals.iter().any(|r| r.path == "/left-pad"),
        "a refusal names what was asked for: {refusals:?}"
    );
    assert!(
        refusals.iter().any(|r| r.reason.contains("evil.example")),
        "and why, so `no filter` and `host not allowed` are not one number: {refusals:?}"
    );

    // The seam: the counters and the rows must agree about the same traffic.
    assert_eq!(
        trigon_mirror::Observed::from_transcript(&m.seen().exchanges(), refusals.len() as u64),
        counted,
        "the counters and the transcript disagree about what this mirror did"
    );
    m.shutdown().await;
}

#[tokio::test]
async fn the_counters_and_the_transcript_agree_on_real_traffic() {
    if !live() {
        return;
    }
    // The same assertion as above, over traffic that actually reaches upstream — an index document
    // that withholds versions, a dependency tarball, a toolchain download and a refusal. Offline
    // the derivation is exercised with every count at zero but `rejected`, and a derivation that is
    // only ever checked against zeros is not checked.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let host = m.host();
    let moment = "2018-04-09T01:10:45";

    let index = reqwest::Client::new()
        .get(format!("http://{host}/left-pad"))
        .basic_auth("npm", Some(moment))
        .send()
        .await
        .unwrap();
    assert_eq!(index.status(), 200);

    for path in [
        format!("/-artifact/npm/{moment}/registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
        "/-toolchain/nodejs.org/dist/v20.11.0/SHASUMS256.txt".to_string(),
    ] {
        let r = reqwest::get(format!("http://{host}{path}")).await.unwrap();
        assert_eq!(r.status(), 200, "{path}");
        // **Read the body.** A row is written when the body finishes, so a test that checks the
        // status and drops the response can record a *partial* row instead — which is the correct
        // product behaviour and the wrong thing to assert here. Finding that out is what this test
        // did; see `a_body_the_client_abandons_is_still_accounted_for`.
        assert!(!r.bytes().await.unwrap().is_empty(), "{path}");
    }
    assert_eq!(
        reqwest::get(format!("http://{host}/ms"))
            .await
            .unwrap()
            .status(),
        400
    );

    let counted = m.observed();
    let rows = m.seen().exchanges();
    assert_eq!(
        m.seen().truncated(),
        0,
        "the rows are a sample, not a record"
    );
    assert_eq!(
        trigon_mirror::Observed::from_transcript(&rows, m.seen().refusals().len() as u64),
        counted,
        "counters {counted:?} disagree with {} transcript rows",
        rows.len()
    );
    assert!(
        counted.pin_bound(),
        "an index document was served: {counted:?}"
    );
    assert_eq!(counted.toolchain_requests, 1);
    assert_eq!(counted.rejected, 1);
    // left-pad published its last version in 2018, so a filter at its own publish moment withholds
    // nothing — and `Some(0)` is the value that says so, rather than the field being absent.
    assert!(
        rows.iter()
            .any(|e| e.route == "index" && e.withheld.is_some()),
        "an index row carries a withheld count even when it is zero: {rows:?}"
    );
    m.shutdown().await;
}

// --- The allowlist, on every hop -------------------------------------------------------------

#[test]
fn an_artifact_url_that_names_no_file_is_compared_one_segment_deeper() {
    // `same_artifact` is what `Guard::refuses` uses to spot the run's own artifact being asked for
    // by a different route. Comparing the last path segment works for npm and PyPI, whose artifact
    // URLs end in a filename. A crates.io download URL ends in the literal word `download` for
    // every crate ever published — so under that rule the first dependency a crates.io build
    // fetched would match the run's own `refuse_url`, be refused 403, and be recorded as a trip.
    // Every crates.io run `Void`, every time, from a control firing on traffic it never meant.
    use trigon_mirror::{Guard, GuardManifest};
    let g = Guard::new(GuardManifest {
        refuse_url: Some("https://static.crates.io/crates/serde/1.0.197/download".into()),
        ..Default::default()
    });

    assert!(
        g.refuses("https://static.crates.io/crates/serde/1.0.197/download"),
        "the run's own artifact is still refused"
    );
    assert!(
        !g.refuses("https://static.crates.io/crates/itoa/1.0.11/download"),
        "an unrelated crate must not be mistaken for it"
    );
    assert!(
        !g.refuses("https://static.crates.io/crates/serde/1.0.196/download"),
        "nor must a different version of the same crate"
    );

    // And the npm/PyPI shape is unchanged: those end in a filename, so one segment is enough.
    let g = Guard::new(GuardManifest {
        refuse_url: Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into()),
        ..Default::default()
    });
    assert!(
        g.refuses("http://mirror/-artifact/npm/x/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
    );
    assert!(!g.refuses("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"));
}

#[tokio::test]
async fn an_off_list_host_is_refused_on_the_route_that_names_it() {
    // The first hop, which always worked. The hop that did not is covered by the unit test on
    // `host_allowed` in server.rs, which is where the redirect loop now calls it.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    for path in [
        "/-toolchain/cdn.evil.example/payload.tgz",
        "/-artifact/npm/2024-01-01T00:00:00/cdn.evil.example/payload.tgz",
    ] {
        assert_eq!(
            reqwest::get(format!("http://{}{path}", m.host()))
                .await
                .unwrap()
                .status(),
            403,
            "{path}"
        );
    }
    m.shutdown().await;
}

#[tokio::test]
async fn a_body_the_client_abandons_is_still_accounted_for() {
    if !live() {
        return;
    }
    // The transcript's whole claim is that it lists everything that crossed into the build, and
    // `attestable` is derived from that claim being complete. A row is written when the body
    // finishes — so a client that hangs up mid-body produced **no row at all**, and bytes crossed
    // with nothing saying they did. A build aborting every download at ninety-nine per cent would
    // have pulled gigabytes and left an empty, `attestable: true` account behind it.
    //
    // Found by the agreement test above, which checked a status and dropped the response: the
    // counters reported an artifact request and a toolchain request, and the transcript had
    // neither.
    //
    // A *large* body, deliberately. A small one is written into the socket buffer in one go and the
    // server-side stream completes whether the client reads it or not, so it would test nothing.
    let m = Mirror::new().unwrap().serve(0).await.unwrap();
    let url = format!(
        "http://{}/-toolchain/nodejs.org/dist/v20.11.0/node-v20.11.0-linux-x64.tar.gz",
        m.host()
    );

    let r = reqwest::get(&url).await.unwrap();
    assert_eq!(r.status(), 200);
    let mut stream = r.bytes_stream();
    // One chunk, then hang up in the middle of seventeen megabytes.
    let first = futures::StreamExt::next(&mut stream).await;
    assert!(first.is_some(), "the body never started");
    drop(stream);
    // The row is written when the server-side stream is dropped, on its own task.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let rows = m.seen().exchanges();
    let row = rows
        .iter()
        .find(|e| e.url.contains("node-v20.11.0"))
        .unwrap_or_else(|| panic!("an abandoned body left no trace at all: {rows:?}"));
    assert_eq!(
        row.checked,
        trigon_mirror::Checked::Partial,
        "a truncated body must not be recorded as a checked one: {row:?}"
    );
    assert!(
        row.bytes > 0 && row.bytes < 17_000_000,
        "the row records what actually crossed, not what was asked for: {row:?}"
    );
    // And the counters agree, because both count the request either way.
    assert_eq!(
        trigon_mirror::Observed::from_transcript(&rows, 0).toolchain_requests,
        m.observed().toolchain_requests
    );
    m.shutdown().await;
}

#[tokio::test]
async fn refusing_the_runs_own_artifact_is_not_the_artifact_arriving() {
    use trigon_core::Digest;
    use trigon_mirror::{Guard, GuardManifest, GuardMatch};

    // The guard trips three ways and they are not equally serious. Two mean the artifact *arrived*,
    // and the run is evidence of nothing: a build that downloads its own published output
    // reproduces it perfectly. The third means the build *asked* and was turned away — nothing
    // arrived, so the thing a void describes did not happen.
    //
    // Folding them cost three of seventeen targets on the M1 PyPI corpus at `mirror-only`, none of
    // them a real catch. `python -m build` needs `packaging` and `pyproject-hooks`, so rebuilding
    // either makes the build ask for it; voiding there means `setuptools`, `wheel`, `tomli`,
    // `flit-core` and `hatchling` can never be verified at an enforced tier.
    let artifact = Digest::from_bytes([7; 32]);
    let g = Guard::new(GuardManifest {
        artifact: Some(artifact),
        refuse_url: Some("https://files.pythonhosted.org/a/packaging-26.3.whl".into()),
        ..Default::default()
    });

    g.record_refusal("https://files.pythonhosted.org/a/packaging-26.3.whl");
    assert_eq!(g.trips().len(), 1, "the refusal is recorded");
    assert!(
        g.arrived().is_empty(),
        "a refusal must not void the run: nothing arrived"
    );
    assert_eq!(g.refused().len(), 1);
    assert_eq!(g.refused()[0].matched, GuardMatch::RefusedUrl);

    // And the control that actually catches an attempt is untouched. A build fetching the same
    // bytes from some other URL — which is what an attacker would do once refused — still trips,
    // because every body is hashed whatever route it came by.
    g.observe("https://cdn.evil.example/anything.bin", artifact, None);
    assert_eq!(
        g.arrived().len(),
        1,
        "the artifact arriving by another name is still a void"
    );
    assert_eq!(g.arrived()[0].matched, GuardMatch::WholeArtifact);
}

/// Two requests for one artifact: the first from the registry, the second from disk.
///
/// The unit tests in `cache.rs` cover the store — round trip, a corrupt entry refused, scoping,
/// pruning. What they cannot cover is the **wiring**: that the proxy consults it after the guard,
/// that a body streamed to a client is also written, and that the second request serves the same
/// bytes without asking anybody. That gap is where this project's bugs live — a control that is
/// correct in isolation and not in the path.
#[tokio::test]
async fn a_second_request_for_one_artifact_asks_nobody() {
    if !live() {
        return;
    }
    let root = std::env::temp_dir().join(format!("trigon-cache-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let m = Mirror::new()
        .unwrap()
        .with_cache(root.clone(), "test-scope".into(), None)
        .unwrap()
        .serve(0)
        .await
        .unwrap();
    let host = m.host();
    let path = "/-artifact/npm/2018-04-09T01:10:45/registry.npmjs.org/ms/-/ms-2.1.3.tgz";

    let first = reqwest::get(format!("http://{host}{path}")).await.unwrap();
    assert_eq!(first.status(), 200);
    let first_bytes = first.bytes().await.unwrap();
    assert!(!first_bytes.is_empty());

    let second = reqwest::get(format!("http://{host}{path}")).await.unwrap();
    assert_eq!(second.status(), 200);
    let second_bytes = second.bytes().await.unwrap();
    assert_eq!(
        first_bytes, second_bytes,
        "the cached body is not the fetched one"
    );

    let stats = m.cache_stats().expect("a cache was configured");
    assert_eq!((stats.hits, stats.written), (1, 1), "{stats:?}");
    assert_eq!(stats.rejected, 0, "{stats:?}");

    // And the transcript still lists both, because it describes what crossed into the build and a
    // cache does not change that. It is the *request* count that changes, which is why the two are
    // no longer derived from the same rows.
    assert_eq!(
        m.seen().exchanges().len(),
        2,
        "a served body is a transcript row whether or not we fetched it"
    );
    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}
