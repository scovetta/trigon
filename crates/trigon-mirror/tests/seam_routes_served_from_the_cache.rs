//! Every route the mirror serves, end to end, with no network.
//!
//! The end-to-end tests in `tests/server.rs` and `tests/nuget_feed.rs` that show a filter working
//! on a served document are all behind `TRIGON_LIVE=1`, and CI runs a bare `cargo test
//! --workspace`. So the wiring between a route, the time filter, the guard and the transcript was
//! exercised by nobody who could not reach the registries — the finding
//! `seam_controls_fail_closed.rs` opens with, and it only closed the half of it that refuses before
//! a packet leaves.
//!
//! The other half is closed here without a network, through the one seam the mirror already has:
//! its cache. ADR-0013 puts the cache *behind* the guard and the filter — it supplies bytes, never
//! a decision — so a document seeded into it goes through exactly the code a fetched one does: the
//! guard still runs first, the filter still runs on every request, and the transcript is byte for
//! byte what it would have been.
//!
//! What the cache counters prove, and what they do not. Every URL a route is expected to read is
//! seeded and `hits` and `misses` are asserted, so a test expecting a 200 that got it from a live
//! registry fails on the count. But an index fetch is counted as a miss only once upstream has
//! answered, and offline nothing answers: a route that wrongly reached for the network where a
//! test expects a refusal fails with a transport error — a 502, which can be the very status the
//! refusal was expected to have — and counts nothing at all. So where a refusal is the point, the
//! URL a broken route *would* build is seeded too, with a document it could serve: a regression
//! then answers 200 off the disk and moves the hit count, rather than passing as the refusal.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use trigon_core::{Classify, Fault, Format};
use trigon_mirror::{
    Cache, Checked, GuardManifest, GuardMatch, Mirror, MirrorError, MirrorHandle, Observed, Tier,
};

// ---------------------------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------------------------

/// A cached packument is filtered to each request's own moment.
///
/// The index tier caches the document as the registry published it, and the time filter runs on
/// it afterwards on every request — so one cached copy read at two moments gives two answers. A
/// cache that stored the *filtered* document, or answered from it, would hand the second build the
/// first build's dependency graph and say nothing.
#[tokio::test]
async fn a_cached_packument_is_filtered_to_each_requests_own_moment() {
    let root = scratch("npm-two-moments");
    let c = seed(&root);
    index(&c, "https://registry.npmjs.org/demo-pkg", &packument());
    let m = serve(&root, None).await;

    let late = get(
        &m,
        "/demo-pkg",
        Some(("npm", "2020-01-01T00:00:00.000Z")),
        None,
    )
    .await;
    assert_eq!(late.status, 200, "{}", late.text());
    let doc = late.json();
    assert_eq!(versions(&doc), ["1.0.0", "1.1.0"], "{doc}");
    // The tag follows the filter, or every floating range resolves to a version that is not there.
    assert_eq!(doc["dist-tags"]["latest"], "1.1.0");
    // And the tarball points back at this mirror with the moment in the path, because npm drops
    // the credentials that carry it on a tarball request.
    assert_eq!(
        doc["versions"]["1.1.0"]["dist"]["tarball"],
        format!(
            "http://{}/-artifact/npm/2020-01-01T00:00:00/registry.npmjs.org/demo-pkg/-/\
             demo-pkg-1.1.0.tgz",
            m.host()
        )
    );

    let early = get(&m, "/demo-pkg", Some(("npm", "2018-06-01T00:00:00Z")), None).await;
    assert_eq!(early.status, 200, "{}", early.text());
    let doc = early.json();
    assert_eq!(
        versions(&doc),
        ["1.0.0"],
        "the second request was answered with the first request's decision: {doc}"
    );
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");

    let stats = m.cache_stats().expect("a cache was configured");
    assert_eq!(
        (stats.hits, stats.misses),
        (2, 0),
        "both documents came off the disk and nothing was fetched: {stats:?}"
    );
    // The index tier's whole obligation: the run can say how old the document it decided against
    // was, rather than reading as though it resolved against the live registry.
    assert_eq!(stats.oldest_index_read, Some(FETCHED_AT));

    let o = m.observed();
    assert_eq!(o.index_requests, 2);
    assert_eq!(
        o.versions_withheld,
        1 + 2,
        "one removed at 2020, two at mid-2018"
    );
    let rows = m.seen().exchanges();
    let withheld: Vec<_> = rows
        .iter()
        .map(|e| (e.route.as_str(), e.withheld))
        .collect();
    assert_eq!(
        withheld,
        [("index", Some(1)), ("index", Some(2))],
        "{rows:?}"
    );
    // Transcribed as the bytes served, not as a second serialization of the document.
    assert_eq!(rows[0].sha256, sha256_hex(&late.body));
    assert_eq!(rows[1].sha256, sha256_hex(&early.body));
    assert!(rows.iter().all(|e| e.checked == Checked::Generated));

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// The version under test is never offered, and withholding it is not counted as the pin working.
///
/// `versions_withheld` is the evidence that the registry pin bound something. Folding the guard's
/// own removal into it would make a packument where only the target was dropped read as the moment
/// having done work it did not do.
#[tokio::test]
async fn the_version_under_test_is_never_offered_and_is_not_counted_as_the_pin_working() {
    let root = scratch("npm-withhold");
    let c = seed(&root);
    index(&c, "https://registry.npmjs.org/demo-pkg", &packument());
    let guard = GuardManifest::default().withholding("demo-pkg", "1.1.0");
    let m = serve(&root, Some(guard)).await;
    // What the void decision reads to tell the package's own other releases from anybody else's.
    let w = m.withheld().expect("the run says what it is about");
    assert_eq!(
        (w.project.as_str(), w.version.as_str()),
        ("demo-pkg", "1.1.0")
    );

    let r = get(&m, "/demo-pkg", Some(("npm", "2020-01-01T00:00:00Z")), None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let doc = r.json();
    assert_eq!(versions(&doc), ["1.0.0"], "{doc}");
    assert_eq!(
        doc["dist-tags"]["latest"], "1.0.0",
        "latest must not name the version that was just withheld"
    );
    assert_eq!(
        m.observed().versions_withheld,
        1,
        "only 2.0.0 was removed by the moment; 1.1.0 was the guard's"
    );

    // And a resolver that composes the tarball URL itself is refused it too, because the index at
    // this moment does not offer it — the question the bare-tarball route asks before serving.
    let bare = get(&m, "/demo-pkg/-/demo-pkg-1.1.0.tgz", None, None).await;
    assert_eq!(bare.status, 400, "{}", bare.text());

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// A bare tarball — npm composes the URL itself and drops the credentials — is served only once a
/// filtered index has offered it.
///
/// The route exists because npm 11 re-bases `dist.tarball` onto the registry root instead of using
/// the rewritten URL. What it must not become is a way to fetch any npm tarball unfiltered, and
/// `seam_controls_fail_closed.rs` specifies the refusal with nothing offered; this is the other
/// side: offered is served, and a version published after the moment is still unreachable.
#[tokio::test]
async fn a_bare_tarball_is_served_only_once_the_filtered_index_has_offered_it() {
    let root = scratch("npm-bare");
    let c = seed(&root);
    index(&c, "https://registry.npmjs.org/demo-pkg", &packument());
    let tarball = b"\x1f\x8b pretend this is demo-pkg 1.0.0".to_vec();
    bytes(
        &c,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
        &tarball,
    );
    bytes(
        &c,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-2.0.0.tgz",
        b"published later",
    );
    let m = serve(&root, None).await;

    // Nothing has pinned a moment yet, so there is nothing to filter against and nothing offered.
    let before = get(&m, "/demo-pkg/-/demo-pkg-1.0.0.tgz", None, None).await;
    assert_eq!(before.status, 400, "{}", before.text());

    let index = get(&m, "/demo-pkg", Some(("npm", "2020-01-01T00:00:00Z")), None).await;
    assert_eq!(index.status, 200);

    let after = get(&m, "/demo-pkg/-/demo-pkg-1.0.0.tgz", None, None).await;
    assert_eq!(after.status, 200, "{}", after.text());
    assert_eq!(after.body, tarball);

    let later = get(&m, "/demo-pkg/-/demo-pkg-2.0.0.tgz", None, None).await;
    assert_eq!(
        later.status, 400,
        "a version published after the pinned moment was served on the route with no filter"
    );

    let rows = m.seen().exchanges();
    let served: Vec<_> = rows.iter().filter(|e| e.route == "artifact").collect();
    assert_eq!(served.len(), 1, "{rows:?}");
    assert_eq!(
        served[0].url,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz"
    );
    assert_eq!(served[0].sha256, sha256_hex(&tarball));
    assert_eq!(served[0].bytes, tarball.len() as u64);

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// A build that resolves from a lockfile asks for no packument, so nothing was ever *offered* — and
/// the route asks the index at the pinned moment instead of refusing it.
///
/// That was 23 of 150 targets on the npm corpus, each reported as the package failing. The answer
/// has to come from the same filter the index route runs, so a version after the moment and the
/// version under test are both still refused.
#[tokio::test]
async fn a_lockfile_tarball_is_served_when_the_index_at_the_pinned_moment_offers_it() {
    let root = scratch("npm-lockfile");
    let c = seed(&root);
    index(&c, "https://registry.npmjs.org/demo-pkg", &packument());
    index(
        &c,
        "https://registry.npmjs.org/@scope/other",
        &scoped_packument(),
    );
    index(
        &c,
        "https://registry.npmjs.org/pin-only",
        &json!({ "name": "pin-only" }),
    );
    c.put(
        Tier::Index,
        "https://registry.npmjs.org/broken",
        b"<html>maintenance</html>",
        "text/html",
        FETCHED_AT,
    )
    .unwrap();
    bytes(
        &c,
        "https://registry.npmjs.org/broken/-/broken-1.0.0.tgz",
        b"never offered",
    );
    let one_one = b"\x1f\x8b demo-pkg 1.1.0".to_vec();
    let scoped = b"\x1f\x8b @scope/other 3.0.0".to_vec();
    bytes(
        &c,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.1.0.tgz",
        &one_one,
    );
    bytes(
        &c,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
        b"under test",
    );
    bytes(
        &c,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-2.0.0.tgz",
        b"published later",
    );
    bytes(
        &c,
        "https://registry.npmjs.org/@scope/other/-/other-3.0.0.tgz",
        &scoped,
    );
    let guard = GuardManifest::default().withholding("demo-pkg", "1.0.0");
    let m = serve(&root, Some(guard)).await;

    // One index request for some *other* package is what pins the moment for the run, and it
    // offers none of the tarballs below — so every answer after it comes from asking the index.
    let pin = get(&m, "/pin-only", Some(("npm", "2020-01-01T00:00:00Z")), None).await;
    assert_eq!(pin.status, 200, "{}", pin.text());

    let r = get(&m, "/demo-pkg/-/demo-pkg-1.1.0.tgz", None, None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.body, one_one);
    // A scoped name repeats only its last segment in the filename.
    let r = get(&m, "/@scope/other/-/other-3.0.0.tgz", None, None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.body, scoped);

    for (path, why) in [
        (
            "/demo-pkg/-/demo-pkg-2.0.0.tgz",
            "published after the moment",
        ),
        ("/demo-pkg/-/demo-pkg-1.0.0.tgz", "the version under test"),
        (
            "/demo-pkg/-/demo-pkg-9.9.9.tgz",
            "a version that never existed",
        ),
        // An index that will not say is not permission, and a filename that does not belong to
        // the package names no version to ask about.
        (
            "/broken/-/broken-1.0.0.tgz",
            "a version whose index will not parse",
        ),
        (
            "/demo-pkg/-/other-1.1.0.tgz",
            "a file that is not the package's",
        ),
    ] {
        let r = get(&m, path, None, None).await;
        assert_eq!(r.status, 400, "{why} was served: {}", r.text());
    }

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// An index document that will not parse is upstream's failure and a 502, never a document served
/// unfiltered and never a 200 with nothing in it.
#[tokio::test]
async fn an_index_document_that_will_not_parse_is_upstreams_failure_and_is_not_served() {
    let root = scratch("npm-garbage");
    let c = seed(&root);
    c.put(
        Tier::Index,
        "https://registry.npmjs.org/demo-pkg",
        b"<html>not a packument</html>",
        "text/html",
        FETCHED_AT,
    )
    .unwrap();
    c.put(
        Tier::Index,
        "https://pypi.org/simple/demo/",
        b"{\"files\": [",
        "application/json",
        FETCHED_AT,
    )
    .unwrap();
    let m = serve(&root, None).await;

    let npm = get(&m, "/demo-pkg", Some(("npm", "2020-01-01T00:00:00Z")), None).await;
    assert_eq!(npm.status, 502, "{}", npm.text());
    assert!(npm.text().contains("upstream npm"), "{}", npm.text());
    let pypi = get(
        &m,
        "/simple/demo/",
        Some(("pypi", "2020-01-01T00:00:00Z")),
        None,
    )
    .await;
    assert_eq!(pypi.status, 502, "{}", pypi.text());

    let o = m.observed();
    assert_eq!(o.index_requests, 0, "nothing was served through the filter");
    assert_eq!(o.rejected, 2);
    assert!(m.seen().exchanges().is_empty());

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------------------------
// The guard, on bytes that came off the disk.
// ---------------------------------------------------------------------------------------------

/// The artifact arriving from the cache trips the guard exactly as it would from the network.
///
/// `proxy` streams a cached body through the same hashing stream as a fetched one, so the guard
/// sees the same bytes either way. If it did not, a warm cache would be the way to smuggle the
/// published artifact into a build: the second target of a sweep would get it off the disk,
/// unhashed.
#[tokio::test]
async fn the_artifact_arriving_from_the_cache_trips_the_guard_exactly_as_from_the_network() {
    let root = scratch("guard-cache");
    let c = seed(&root);
    let member = guarded_member();
    let published = tgz(&[("package/lib/index.js", &member)]);
    // The published artifact, cached under an innocuous name, and an unrelated dependency that
    // carries one of its files.
    let carrier = tgz(&[
        ("package/README.md", b"an unrelated package"),
        ("package/vendor/index.js", &member),
    ]);
    let smuggled = "https://registry.npmjs.org/innocent/-/innocent-1.0.0.tgz";
    let carried = "https://registry.npmjs.org/carrier/-/carrier-2.0.0.tgz";
    bytes(&c, smuggled, &published);
    bytes(&c, carried, &carrier);
    let guard = GuardManifest::for_artifact(&published, Format::TarGz, None);
    let guarded: Vec<String> = guard.members.iter().map(|d| d.to_hex()).collect();
    assert_eq!(guarded.len(), 1, "the fixture must guard its one member");
    let m = serve(&root, Some(guard)).await;

    let moment = "2020-01-01T00:00:00";
    let r = get(
        &m,
        &format!("/-artifact/npm/{moment}/registry.npmjs.org/innocent/-/innocent-1.0.0.tgz"),
        None,
        None,
    )
    .await;
    // Served, and noticed: the build still gets its bytes, and what changes is the verdict.
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.body, published);
    let r = get(
        &m,
        &format!("/-artifact/npm/{moment}/registry.npmjs.org/carrier/-/carrier-2.0.0.tgz"),
        None,
        None,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());

    let arrived = m.arrived();
    assert_eq!(arrived.len(), 2, "{arrived:?}");
    assert_eq!(arrived[0].url, smuggled);
    assert_eq!(arrived[0].matched, GuardMatch::WholeArtifact);
    assert_eq!(arrived[1].url, carried);
    assert_eq!(
        arrived[1].member(),
        Some(guarded[0].as_str()),
        "the member that matched is the one the manifest guards: {:?}",
        arrived[1]
    );
    assert!(m.refused().is_empty());

    // The transcript says how far the guard got with each: the whole-body hash matched the first,
    // and the second was opened and its members compared.
    let rows = m.seen().exchanges();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].sha256, sha256_hex(&published));
    assert_eq!(rows[0].checked, Checked::Hashed);
    assert_eq!(rows[1].checked, Checked::Opened);
    assert_eq!(m.cache_stats().unwrap().hits, 2);

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// The run's own artifact is refused even when the cache holds it.
///
/// ADR-0013's ordering rule, and the reason the cache sits behind the guard: an artifact this run
/// is reproducing must be refused whether or not we happen to have it on disk. A cache consulted
/// first would turn the one control separating a verdict from a tautology into a control on cold
/// requests only.
#[tokio::test]
async fn the_runs_own_artifact_is_refused_even_when_the_cache_holds_it() {
    let root = scratch("guard-before-cache");
    let c = seed(&root);
    let own = "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz";
    bytes(&c, own, b"the published artifact, sitting on disk");
    let guard = GuardManifest {
        refuse_url: Some(own.into()),
        ..Default::default()
    };
    let m = serve(&root, Some(guard)).await;

    let r = get(
        &m,
        "/-artifact/npm/2020-01-01T00:00:00/registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
        None,
        None,
    )
    .await;
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("proves nothing"), "{}", r.text());

    let stats = m.cache_stats().unwrap();
    assert_eq!(
        (stats.hits, stats.misses),
        (0, 0),
        "the cache was consulted before the guard: {stats:?}"
    );
    assert_eq!(m.refused().len(), 1);
    assert_eq!(m.refused()[0].matched, GuardMatch::RefusedUrl);
    // Asked and turned away, which is not the artifact arriving.
    assert!(m.arrived().is_empty());
    assert!(m.seen().exchanges().is_empty(), "no body crossed");

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------------------------
// PyPI
// ---------------------------------------------------------------------------------------------

/// A cached simple index is filtered and served in the form the client asked for.
///
/// Upstream is always asked for JSON, because the HTML form carries no upload times and cannot be
/// filtered; a client that wanted HTML gets it rendered back from the filtered JSON. Either way the
/// file URLs point back at this mirror with the CDN host carried in the path, and the transcript
/// holds the digest of exactly the bytes that went out.
#[tokio::test]
async fn a_cached_simple_index_is_filtered_and_served_in_the_form_the_client_asked_for() {
    let root = scratch("pypi-simple");
    let c = seed(&root);
    index(&c, "https://pypi.org/simple/demo/", &simple());
    let sdist = b"pretend sdist".to_vec();
    bytes(
        &c,
        "https://files.pythonhosted.org/packages/aa/demo-1.0.tar.gz",
        &sdist,
    );
    let m = serve(&root, None).await;
    let moment = "2020-01-01T00:00:00";

    let r = get(
        &m,
        "/simple/demo/",
        Some(("pypi", moment)),
        Some("application/vnd.pypi.simple.v1+json"),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.content_type, "application/vnd.pypi.simple.v1+json");
    let doc = r.json();
    let files = doc["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{doc}");
    assert_eq!(files[0]["filename"], "demo-1.0.tar.gz");
    let url = files[0]["url"].as_str().unwrap().to_string();
    assert_eq!(
        url,
        format!(
            "http://{}/-artifact/pypi/{moment}/files.pythonhosted.org/packages/aa/demo-1.0.tar.gz",
            m.host()
        )
    );

    let html = get(
        &m,
        "/simple/demo/",
        Some(("pypi", moment)),
        Some("text/html"),
    )
    .await;
    assert_eq!(html.status, 200, "{}", html.text());
    assert_eq!(html.content_type, "application/vnd.pypi.simple.v1+html");
    let text = html.text();
    assert!(
        text.contains(&format!("href=\"{url}#sha256=aaa\"")),
        "{text}"
    );
    assert!(
        !text.contains("demo-2.0"),
        "the HTML form must be the filtered document, not the live one: {text}"
    );

    // The rewritten URL is one the mirror answers.
    let got = get_url(&url).await;
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.body, sdist);

    let rows = m.seen().exchanges();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows[0].sha256, sha256_hex(&r.body));
    assert_eq!(
        rows[1].sha256,
        sha256_hex(&html.body),
        "the HTML response is transcribed as the HTML that was served"
    );
    // The late wheel and the file with no upload time, each time.
    assert_eq!(rows[0].withheld, Some(2));
    assert_eq!(rows[1].withheld, Some(2));
    assert_eq!(rows[2].route, "artifact");
    assert_eq!(m.observed().versions_withheld, 4);

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// The version under test is withheld from a PyPI index, in both places a version appears.
#[tokio::test]
async fn the_version_under_test_is_withheld_from_a_simple_index_too() {
    let root = scratch("pypi-withhold");
    let c = seed(&root);
    index(&c, "https://pypi.org/simple/demo/", &simple());
    // Spelled the way a purl spells it rather than the way the index does: both sides normalize.
    let guard = GuardManifest::default().withholding("Demo", "1.0");
    let m = serve(&root, Some(guard)).await;

    let r = get(
        &m,
        "/simple/demo/",
        Some(("pypi", "2030-01-01T00:00:00")),
        Some("application/vnd.pypi.simple.v1+json"),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let doc = r.json();
    let names: Vec<&str> = doc["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["filename"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["demo-2.0-py3-none-any.whl"], "{doc}");
    assert_eq!(
        doc["versions"],
        json!(["2.0"]),
        "a version with no files behind it: {doc}"
    );
    assert_eq!(
        m.observed().versions_withheld,
        1,
        "only the undated file was the moment's doing"
    );

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// Anything on the index host that is not a simple page is passed through — and still runs the
/// guard, and is counted as a fetch rather than as the pin working.
#[tokio::test]
async fn a_passthrough_on_the_index_host_runs_the_guard_and_is_not_index_traffic() {
    let root = scratch("pypi-passthrough");
    let guard = GuardManifest {
        refuse_url: Some("https://files.pythonhosted.org/packages/aa/demo-1.0.tar.gz".into()),
        ..Default::default()
    };
    let m = serve(&root, Some(guard)).await;

    let r = get(
        &m,
        "/packages/aa/demo-1.0.tar.gz",
        Some(("pypi", "2020-01-01T00:00:00")),
        None,
    )
    .await;
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("proves nothing"), "{}", r.text());
    assert_eq!(m.refused().len(), 1, "the guard is what stopped it");
    // Not index traffic, so no evidence that the moment bound anything. Whether a request the
    // guard turned away also counts as an artifact request is left unasserted: the counters say it
    // does and the transcript, which has no row for it, says it does not — the disagreement
    // `docs/17-backlog.md` lists, and not something to pin in either direction here.
    let o = m.observed();
    assert_eq!(o.index_requests, 0, "{o:?}");
    assert!(!o.pin_bound());
    assert!(m.seen().exchanges().is_empty(), "no body crossed");

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------------------------
// Toolchains, and the two accounts of one run.
// ---------------------------------------------------------------------------------------------

/// The counters and the transcript agree about traffic that actually served bodies.
///
/// `tests/server.rs` binds them offline with every count at zero but `rejected`, and online behind
/// `TRIGON_LIVE`. A derivation only ever checked against zeros is not checked, so this is the same
/// assertion over an index document, a bare tarball, an artifact, a toolchain download and a
/// refusal — which is every route that writes a row.
#[tokio::test]
async fn the_counters_and_the_transcript_agree_on_traffic_that_served_bodies() {
    let root = scratch("agreement");
    let c = seed(&root);
    index(&c, "https://registry.npmjs.org/demo-pkg", &packument());
    bytes(
        &c,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
        b"one",
    );
    bytes(
        &c,
        "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.1.0.tgz",
        b"one one",
    );
    let shasums = b"abc123  node-v20.0.0-linux-x64.tar.gz\n".to_vec();
    bytes(
        &c,
        "https://nodejs.org/dist/v20.0.0/SHASUMS256.txt",
        &shasums,
    );
    let m = serve(&root, None).await;
    let moment = "2020-01-01T00:00:00";

    for (path, auth) in [
        ("/demo-pkg", Some(("npm", moment))),
        ("/demo-pkg/-/demo-pkg-1.0.0.tgz", None),
        (
            "/-artifact/npm/2020-01-01T00:00:00/registry.npmjs.org/demo-pkg/-/demo-pkg-1.1.0.tgz",
            None,
        ),
        ("/-toolchain/nodejs.org/dist/v20.0.0/SHASUMS256.txt", None),
    ] {
        let r = get(&m, path, auth, None).await;
        assert_eq!(r.status, 200, "{path}: {}", r.text());
        if path.starts_with("/-toolchain/") {
            assert_eq!(r.body, shasums);
        }
    }
    let refused = get(&m, "/-toolchain/cdn.evil.example/node.tar.gz", None, None).await;
    assert_eq!(refused.status, 403);

    let counted = m.observed();
    assert_eq!(
        (
            counted.index_requests,
            counted.artifact_requests,
            counted.toolchain_requests,
            counted.rejected
        ),
        (1, 2, 1, 1),
        "{counted:?}"
    );
    let rows = m.seen().exchanges();
    assert_eq!(m.seen().truncated(), 0);
    assert_eq!(
        Observed::from_transcript(&rows, m.seen().refusals().len() as u64),
        counted,
        "the counters and the transcript disagree about what this mirror did: {rows:?}"
    );
    let toolchain = rows.iter().find(|e| e.route == "toolchain").unwrap();
    assert_eq!(
        toolchain.url,
        "https://nodejs.org/dist/v20.0.0/SHASUMS256.txt"
    );
    // No manifest on this run, so nothing was compared against anything — and the row says so
    // rather than claiming a check.
    assert_eq!(toolchain.checked, Checked::Unarmed);

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------------------------
// NuGet
// ---------------------------------------------------------------------------------------------

/// A registration is filtered across every page, remote pages included, and points back here.
///
/// `nuget.rs` names the trap: a page either carries its leaves inline or only an `@id` to fetch
/// them from, and a filter that reads only inline leaves passes every version of a large package
/// through while reporting that it filtered. So the remote page is fetched, filtered and inlined.
/// Unlisted versions go too — `1900-01-01` is the unlisted sentinel, not a date — and so does a
/// leaf the feed marks `listed: false`.
#[tokio::test]
async fn a_registration_is_filtered_across_every_page_and_points_back_at_this_mirror() {
    let root = scratch("nuget-reg");
    let c = seed(&root);
    index(&c, &format!("{REG}/demo.pkg/index.json"), &registration());
    index(
        &c,
        &format!("{REG}/demo.pkg/page/2.0.0/3.0.0.json"),
        &remote_page(),
    );
    let nupkg = b"PK pretend nupkg".to_vec();
    bytes(
        &c,
        &format!("{FLAT}/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg"),
        &nupkg,
    );
    let m = serve(&root, None).await;
    let base = format!("http://{}/-nuget/2020-01-01T00:00:00Z", m.host());

    // Asked for in the case the project file spells it; the feed's own URLs are lowercased.
    let r = get(
        &m,
        "/-nuget/2020-01-01T00:00:00Z/reg/Demo.Pkg/index.json",
        None,
        None,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let doc = r.json();
    assert_eq!(doc["@id"], format!("{base}/reg/demo.pkg/index.json"));
    assert_eq!(doc["count"], 2, "both pages survive: {doc}");
    assert_eq!(doc["totalVersions"], 2, "{doc}");
    let pages = doc["items"].as_array().unwrap();
    let leaves: Vec<&Value> = pages
        .iter()
        .flat_map(|p| p["items"].as_array().expect("every page inlined"))
        .collect();
    let kept: Vec<&str> = leaves
        .iter()
        .map(|l| l["catalogEntry"]["version"].as_str().unwrap())
        .collect();
    assert_eq!(kept, ["1.0.0", "2.0.0"], "{doc}");
    // Each page's own `count` agrees with what it now holds, or NuGet reports a corrupt feed.
    for p in pages {
        assert_eq!(p["count"], p["items"].as_array().unwrap().len(), "{p}");
    }
    let leaf = leaves[0];
    let content = format!("{base}/flat/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg");
    assert_eq!(leaf["packageContent"], content);
    assert_eq!(leaf["catalogEntry"]["packageContent"], content);
    assert_eq!(leaf["@id"], format!("{base}/reg/demo.pkg/1.0.0.json"));
    assert_eq!(
        leaf["registration"],
        format!("{base}/reg/demo.pkg/index.json")
    );
    assert_eq!(
        pages[1]["@id"],
        format!("{base}/reg/demo.pkg/page/2.0.0/3.0.0.json"),
        "a page a client might follow must not leave the mirror"
    );
    // 1.1.0 unlisted by sentinel, 1.1.5 unlisted outright, 1.2.0 and 3.0.0 after the moment.
    assert_eq!(m.observed().versions_withheld, 4);

    // The flat container's list is derived from the filtered registration, never proxied.
    let flat = get(
        &m,
        "/-nuget/2020-01-01T00:00:00Z/flat/demo.pkg/index.json",
        None,
        None,
    )
    .await;
    assert_eq!(flat.status, 200, "{}", flat.text());
    assert_eq!(flat.json(), json!({ "versions": ["1.0.0", "2.0.0"] }));

    // And the bytes, through the proxy and its guard.
    let path = content
        .strip_prefix(&format!("http://{}", m.host()))
        .unwrap();
    let got = get(&m, path, None, None).await;
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.body, nupkg);

    let o = m.observed();
    assert_eq!((o.index_requests, o.artifact_requests), (2, 1), "{o:?}");
    let rows = m.seen().exchanges();
    assert_eq!(
        Observed::from_transcript(&rows, 0),
        o,
        "the pin evidence is built from the transcript: {rows:?}"
    );
    assert_eq!(m.cache_stats().unwrap().misses, 0, "nothing was fetched");

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// The toolchain's own packages are not dated, and the exemption is exactly that narrow.
///
/// `Microsoft.NETCore.App.Ref` is a targeting pack the SDK picks for itself: filtering it by the
/// package's publish date leaves a constraint nothing can satisfy (`NU1102 … Found 91 version(s)`).
/// The offline twin of the live test in `tests/nuget_feed.rs`.
#[tokio::test]
async fn the_toolchains_own_packages_are_not_dated_and_nothing_else_is_exempt() {
    let root = scratch("nuget-toolchain");
    let c = seed(&root);
    let reg = |id: &str| {
        json!({
            "count": 1,
            "items": [{
                "@id": format!("{REG}/{}/index.json#page/1", id.to_ascii_lowercase()),
                "count": 2,
                "items": [
                    leaf(id, "6.0.0", "2019-01-01T00:00:00+00:00", None),
                    leaf(id, "6.0.36", "2024-11-12T00:00:00+00:00", None),
                ],
            }],
        })
    };
    index(
        &c,
        &format!("{REG}/microsoft.netcore.app.ref/index.json"),
        &reg("Microsoft.NETCore.App.Ref"),
    );
    index(
        &c,
        &format!("{REG}/newtonsoft.json/index.json"),
        &reg("Newtonsoft.Json"),
    );
    let m = serve(&root, None).await;

    for (id, want) in [
        ("microsoft.netcore.app.ref", json!(["6.0.0", "6.0.36"])),
        ("newtonsoft.json", json!(["6.0.0"])),
    ] {
        let r = get(
            &m,
            &format!("/-nuget/2020-01-01T00:00:00Z/flat/{id}/index.json"),
            None,
            None,
        )
        .await;
        assert_eq!(r.status, 200, "{id}: {}", r.text());
        assert_eq!(r.json()["versions"], want, "{id}");
    }
    assert_eq!(
        m.observed().versions_withheld,
        1,
        "the exemption is not counted as the pin working"
    );

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// The version under test is withheld from a registration, and routed around rather than refused.
#[tokio::test]
async fn the_version_under_test_is_withheld_from_a_registration() {
    let root = scratch("nuget-withhold");
    let c = seed(&root);
    index(&c, &format!("{REG}/demo.pkg/index.json"), &registration());
    index(
        &c,
        &format!("{REG}/demo.pkg/page/2.0.0/3.0.0.json"),
        &remote_page(),
    );
    // NuGet ids fold case and versions do not.
    let guard = GuardManifest::default().withholding("DEMO.PKG", "2.0.0");
    let m = serve(&root, Some(guard)).await;

    let r = get(
        &m,
        "/-nuget/2020-01-01T00:00:00Z/flat/demo.pkg/index.json",
        None,
        None,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json(), json!({ "versions": ["1.0.0"] }));
    assert_eq!(
        m.observed().versions_withheld,
        4,
        "the guard's removal is not the moment's"
    );

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// A registration page this mirror cannot read is refused, and one pointing off the registry is
/// never followed.
///
/// An empty page is indistinguishable from a filtered one, and this route's whole job is to be
/// distinguishable. And a page `@id` naming some other host would make the route a proxy to
/// whatever a feed chose to name — so it is not fetched at all. Offline, fetching it would fail
/// with the same 502 as refusing it, so the page it names is seeded with leaves that would be
/// served: a route that followed it answers 200 off the disk, and reads one entry more.
#[tokio::test]
async fn a_page_that_cannot_be_read_is_refused_and_one_off_the_registry_is_never_fetched() {
    let root = scratch("nuget-bad-pages");
    let c = seed(&root);
    let remote = |id: &str, url: &str| {
        json!({
            "id": id,
            "count": 1,
            "items": [{ "@id": url, "count": 3 }],
        })
    };
    index(
        &c,
        &format!("{REG}/offsite/index.json"),
        &remote("offsite", "https://cdn.evil.example/page.json"),
    );
    index(
        &c,
        "https://cdn.evil.example/page.json",
        &json!({
            "count": 1,
            "items": [leaf("offsite", "1.0.0", "2018-01-01T00:00:00+00:00", None)],
        }),
    );
    index(
        &c,
        &format!("{REG}/torn/index.json"),
        &remote("torn", &format!("{REG}/torn/page.json")),
    );
    // Neither leaves nor an address to fetch them from.
    index(
        &c,
        &format!("{REG}/hollow/index.json"),
        &json!({ "count": 1, "items": [{ "count": 7 }] }),
    );
    c.put(
        Tier::Index,
        &format!("{REG}/torn/page.json"),
        b"{\"items\": [",
        "application/json",
        FETCHED_AT,
    )
    .unwrap();
    c.put(
        Tier::Index,
        &format!("{REG}/garbled/index.json"),
        b"not json",
        "application/json",
        FETCHED_AT,
    )
    .unwrap();
    let m = serve(&root, None).await;

    for id in ["offsite", "torn", "garbled", "hollow"] {
        let r = get(
            &m,
            &format!("/-nuget/2020-01-01T00:00:00Z/reg/{id}/index.json"),
            None,
            None,
        )
        .await;
        assert_eq!(r.status, 502, "{id}: {}", r.text());
    }
    // And a registration shape this route does not serve is named rather than guessed at.
    let r = get(
        &m,
        "/-nuget/2020-01-01T00:00:00Z/reg/demo.pkg/page.json",
        None,
        None,
    )
    .await;
    assert_eq!(r.status, 404, "{}", r.text());

    let o = m.observed();
    assert_eq!((o.index_requests, o.rejected), (0, 5), "{o:?}");
    assert!(m.seen().exchanges().is_empty());
    let stats = m.cache_stats().unwrap();
    assert_eq!(
        (stats.hits, stats.misses),
        (5, 0),
        "four registrations and the torn page were read and nothing else was, the off-registry \
         page least of all: {stats:?}"
    );

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// The service index points every resource back at this mirror, and each one answers.
///
/// The offline twin of the test in `tests/nuget_feed.rs`, which asserts the same thing by asking
/// api.nuget.org. Asserting the prefix alone let a doubled path through — `/-nuget/<moment>/-nuget/
/// flat/` still starts with `/-nuget/` — which restore reported as `NU1101 … No packages exist with
/// this id`. A resource is only advertised correctly if composing a request onto it answers.
#[tokio::test]
async fn the_service_index_points_every_resource_back_here_and_each_one_answers() {
    let root = scratch("nuget-service-index");
    let c = seed(&root);
    index(&c, &format!("{REG}/demo.pkg/index.json"), &registration());
    index(
        &c,
        &format!("{REG}/demo.pkg/page/2.0.0/3.0.0.json"),
        &remote_page(),
    );
    let m = serve(&root, None).await;
    let moment = "2020-01-01T00:00:00Z";
    let base = format!("http://{}/-nuget/{moment}/", m.host());

    let r = get(&m, &format!("/-nuget/{moment}/index.json"), None, None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let doc = r.json();
    let resources = doc["resources"].as_array().expect("resources");
    let types: BTreeSet<&str> = resources
        .iter()
        .map(|r| r["@type"].as_str().unwrap())
        .collect();
    for needed in ["PackageBaseAddress/3.0.0", "RegistrationsBaseUrl/3.6.0"] {
        assert!(types.contains(needed), "{needed} missing: {types:?}");
    }
    // Nothing a build has no reason to use, and in particular no unfiltered search.
    assert!(
        !types.iter().any(|t| t.starts_with("SearchQueryService")),
        "{types:?}"
    );
    for resource in resources {
        let id = resource["@id"].as_str().unwrap();
        assert!(id.starts_with(&base), "{id} points off the mirror");
        let path = format!(
            "{}demo.pkg/index.json",
            id.strip_prefix(&format!("http://{}", m.host())).unwrap()
        );
        let r = get(&m, &path, None, None).await;
        assert_eq!(
            r.status,
            200,
            "{id} advertised, and {path} answers {}",
            r.text()
        );
    }

    // The service index is itself an index document the build resolved against, so it is a row.
    let rows = m.seen().exchanges();
    assert_eq!(rows[0].url, format!("{base}index.json"));
    assert_eq!(
        (rows[0].route.as_str(), rows[0].withheld),
        ("index", Some(0))
    );

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// A request that does not say which platform, which moment and which host it wants is refused,
/// and a filter that arrived in the wrong place is not quietly honoured.
///
/// NuGet and Cargo carry their moment in the path because their clients send no credentials to a
/// feed URL. A NuGet or Cargo filter arriving *in* credentials means something built one where the
/// mirror never tells a client to, which is a bug rather than a request to serve.
#[tokio::test]
async fn a_request_that_does_not_say_what_it_wants_is_refused_and_counted() {
    let root = scratch("malformed");
    let m = serve(&root, None).await;

    for (path, auth, want, why) in [
        (
            "/-artifact/npm/2020-01-01T00:00:00",
            None,
            400,
            "no host or path",
        ),
        (
            "/-artifact/maven/2020-01-01T00:00:00/registry.npmjs.org/x.jar",
            None,
            400,
            "a platform this mirror does not serve",
        ),
        ("/-nuget//index.json", None, 400, "an empty NuGet moment"),
        (
            "/demo-pkg",
            Some(("nuget", "2020-01-01T00:00:00")),
            400,
            "a NuGet filter in credentials",
        ),
        (
            "/demo-pkg",
            Some(("cargo", "2020-01-01T00:00:00")),
            400,
            "a Cargo filter in credentials",
        ),
    ] {
        let r = get(&m, path, auth, None).await;
        assert_eq!(r.status, want, "{why}: {}", r.text());
    }
    let r = get(
        &m,
        "/-artifact/maven/2020-01-01T00:00:00/registry.npmjs.org/x.jar",
        None,
        None,
    )
    .await;
    assert!(
        r.text().contains("`maven`"),
        "it names what it did not recognise: {}",
        r.text()
    );

    let o = m.observed();
    assert_eq!(
        (o.rejected, o.index_requests, o.artifact_requests),
        (6, 0, 0),
        "{o:?}"
    );
    assert_eq!(m.seen().refusals().len(), 6);

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// A NuGet moment that will not parse is refused, rather than compared as a string.
///
/// The moment travels in the path here, not in credentials, so it never went through
/// `Filter::from_authorization` and nothing normalized it. `published_by` normalizes the timestamp
/// it compares and not the moment it compares against, so `yesterday` was a moment every
/// registry timestamp sorts before: the registration came back with every version in it, as a 200,
/// under a URL that claims filtering. The Cargo route already refuses this for the reason written
/// on it; this holds the NuGet route to the same rule, and to the specification in
/// `seam_controls_fail_closed.rs` that a moment which is not an instant is a refusal.
#[tokio::test]
async fn a_nuget_moment_that_will_not_parse_is_refused_rather_than_compared() {
    let root = scratch("nuget-moment");
    let c = seed(&root);
    index(&c, &format!("{REG}/demo.pkg/index.json"), &registration());
    index(
        &c,
        &format!("{REG}/demo.pkg/page/2.0.0/3.0.0.json"),
        &remote_page(),
    );
    let m = serve(&root, None).await;

    for moment in ["yesterday", "2020-01", "latest", "2020%2F01%2F01"] {
        for tail in [
            "index.json",
            "reg/demo.pkg/index.json",
            "flat/demo.pkg/index.json",
        ] {
            let r = get(&m, &format!("/-nuget/{moment}/{tail}"), None, None).await;
            assert_eq!(r.status, 400, "{moment}/{tail} was served: {}", r.text());
        }
    }
    assert_eq!(m.observed().index_requests, 0);

    // The spelling the strategy actually writes — a catalog `published`, offset and all — still
    // works, and filters at whole-second resolution like every other route.
    let r = get(
        &m,
        "/-nuget/2019-01-01T00:00:00.500+00:00/flat/demo.pkg/index.json",
        None,
        None,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json(), json!({ "versions": ["1.0.0", "2.0.0"] }));

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------------------------
// Cargo
// ---------------------------------------------------------------------------------------------

/// The sparse index is filtered by `pubtime`, yanks are cleared, and `dl` points back here.
#[tokio::test]
async fn a_sparse_index_is_filtered_to_the_moment_and_downloads_come_back_through_the_mirror() {
    let root = scratch("cargo");
    let c = seed(&root);
    let lines = concat!(
        r#"{"name":"demo","vers":"0.1.0","cksum":"aa","pubtime":"2018-10-29T14:28:15Z"}"#,
        "\n",
        r#"{"name":"demo","vers":"0.2.0","yanked":true,"pubtime":"2019-03-01T00:00:00Z"}"#,
        "\n",
        r#"{"name":"demo","vers":"0.3.0","cksum":"cc","pubtime":"2021-05-09T04:35:04Z"}"#,
        "\n",
    );
    c.put(
        Tier::Index,
        "https://index.crates.io/de/mo/demo",
        lines.as_bytes(),
        "text/plain",
        FETCHED_AT,
    )
    .unwrap();
    let late = concat!(
        r#"{"name":"new","vers":"1.0.0","cksum":"dd","pubtime":"2024-01-01T00:00:00Z"}"#,
        "\n"
    );
    c.put(
        Tier::Index,
        "https://index.crates.io/3/n/new",
        late.as_bytes(),
        "text/plain",
        FETCHED_AT,
    )
    .unwrap();
    let krate = b"pretend .crate".to_vec();
    bytes(
        &c,
        "https://static.crates.io/crates/demo/0.1.0/download",
        &krate,
    );
    let m = serve(&root, None).await;
    // Fractional seconds in the path are normalized before anything is compared.
    let moment = "2020-01-01T00:00:00.251Z";

    let config = get(&m, &format!("/-cargo/{moment}/config.json"), None, None).await;
    assert_eq!(config.status, 200, "{}", config.text());
    let dl = format!(
        "http://{}/-artifact/cargo/2020-01-01T00:00:00/static.crates.io/crates",
        m.host()
    );
    assert_eq!(
        config.json(),
        json!({ "dl": dl, "api": "https://crates.io" })
    );

    let doc = get(&m, &format!("/-cargo/{moment}/de/mo/demo"), None, None).await;
    assert_eq!(doc.status, 200, "{}", doc.text());
    assert_eq!(doc.content_type, "text/plain; charset=utf-8");
    let served: Vec<Value> = doc
        .text()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let vers: Vec<&str> = served.iter().map(|v| v["vers"].as_str().unwrap()).collect();
    assert_eq!(vers, ["0.1.0", "0.2.0"]);
    assert_eq!(
        served[1]["yanked"], false,
        "yank state has no history and is cleared"
    );
    // A line whose flag did not change goes out as the registry wrote it.
    assert!(
        doc.text().starts_with(lines.lines().next().unwrap()),
        "{}",
        doc.text()
    );

    // Cargo appends `/{crate}/{version}/download` to `dl`, which is a real crates.io path.
    let got = get_url(&format!("{dl}/demo/0.1.0/download")).await;
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.body, krate);

    // A crate whose every version postdates the pin did not exist then: 404, not an empty 200.
    let r = get(&m, &format!("/-cargo/{moment}/3/n/new"), None, None).await;
    assert_eq!(r.status, 404, "{}", r.text());

    let rows = m.seen().exchanges();
    let index_rows: Vec<_> = rows.iter().filter(|e| e.route == "index").collect();
    assert_eq!(index_rows.len(), 2, "{rows:?}");
    // The config document filtered nothing; the index document withheld the one late version.
    assert_eq!(index_rows[0].withheld, Some(0));
    assert_eq!(index_rows[1].withheld, Some(1));
    // Newline-delimited JSON is not a JSON document, so it is transcribed as the text served.
    assert_eq!(index_rows[1].sha256, sha256_hex(&doc.body));
    // The 404 is a refusal with no row. What the counters make of the version it filtered out is
    // left unasserted: they count it and the transcript does not, and `Seen` says the two must
    // agree — a question for the route, not something to pin here.
    assert_eq!(m.seen().refusals().len(), 1);

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// A Cargo request with no usable moment, or an index path that could climb out of the index, is
/// refused before anything is fetched.
///
/// Cargo derives an index path from a crate name, so it never contains `..` — but the check is on
/// the path about to be built, because the request is from whatever is on the other end of the
/// socket, and a raw request line is how that looks.
#[tokio::test]
async fn a_cargo_request_with_no_usable_moment_or_a_climbing_path_is_refused() {
    let root = scratch("cargo-refusals");
    let c = seed(&root);
    // The documents the two climbing paths would become if nothing checked them, seeded with a
    // line that would be served. Upstream answers a normalized `/etc/passwd` with a 404, which is
    // also the refusal's status — so without these a route that fetched it would still pass.
    let line = concat!(
        r#"{"name":"x","vers":"0.1.0","cksum":"aa","pubtime":"2018-01-01T00:00:00Z"}"#,
        "\n"
    );
    for url in [
        "https://index.crates.io/../../etc/passwd",
        "https://index.crates.io//absolute",
    ] {
        c.put(Tier::Index, url, line.as_bytes(), "text/plain", FETCHED_AT)
            .unwrap();
    }
    let m = serve(&root, None).await;

    for (path, want, why) in [
        ("/-cargo/2020-01-01T00:00:00/", 400, "no index path at all"),
        ("/-cargo//config.json", 400, "an empty moment"),
        ("/-cargo/config.json", 400, "no moment segment"),
        (
            "/-cargo/yesterday/config.json",
            400,
            "a moment that is not an instant",
        ),
        ("/-cargo/2020-01/de/mo/demo", 400, "a truncated instant"),
    ] {
        let r = get(&m, path, None, None).await;
        assert_eq!(r.status, want, "{why}: {}", r.text());
    }
    for path in [
        "/-cargo/2020-01-01T00:00:00/../../etc/passwd",
        "/-cargo/2020-01-01T00:00:00//absolute",
    ] {
        assert_eq!(raw_status(&m, path).await, 404, "{path}");
    }

    let o = m.observed();
    assert_eq!((o.index_requests, o.rejected), (0, 7), "{o:?}");
    let stats = m.cache_stats().unwrap();
    assert_eq!(
        (stats.hits, stats.misses),
        (0, 0),
        "nothing was read or fetched: {stats:?}"
    );

    m.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------------------------
// Starting up.
// ---------------------------------------------------------------------------------------------

/// A cache directory that cannot be opened stops the mirror at startup, as ours.
///
/// Never the package's fault and never the registry's; and never a mirror that quietly runs without
/// the cache it was told to use, because a sweep that thinks it is caching and is not looks like a
/// slow machine.
#[test]
fn a_cache_that_cannot_be_opened_refuses_to_start_and_is_charged_to_us() {
    let root = scratch("cache-is-a-file");
    std::fs::create_dir_all(root.parent().unwrap()).unwrap();
    std::fs::write(&root, b"a file where the directory should be").unwrap();

    let e = match Mirror::new()
        .unwrap()
        .with_cache(root.clone(), SCOPE.into(), None)
    {
        Err(e) => e,
        Ok(_) => panic!("a mirror started on a cache it could not open"),
    };
    assert!(matches!(e, MirrorError::Cache(_)), "{e:?}");
    assert_eq!(e.status(), 500);
    assert_eq!(e.fault(), Fault::Infra);
    assert!(e.to_string().contains("refuses at startup"), "{e}");
    let _ = std::fs::remove_file(&root);
}

/// A ceiling on the cache is applied when the mirror starts, and only past the ceiling.
#[tokio::test]
async fn a_cache_over_its_ceiling_is_pruned_at_startup_and_one_under_it_is_left_alone() {
    let root = scratch("cache-ceiling");
    let url = "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz";
    bytes(&seed(&root), url, &[b'x'; 1000]);

    let under = Mirror::new()
        .unwrap()
        .with_cache(root.clone(), SCOPE.into(), Some(1_000_000))
        .unwrap();
    drop(under);
    assert!(
        seed(&root).get(Tier::Bytes, url).is_some(),
        "pruned under its ceiling"
    );

    let over = Mirror::new()
        .unwrap()
        .with_cache(root.clone(), SCOPE.into(), Some(0))
        .unwrap();
    drop(over);
    assert!(
        seed(&root).get(Tier::Bytes, url).is_none(),
        "kept past its ceiling"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A port that cannot be claimed says which port, and is ours rather than the package's.
#[tokio::test]
async fn a_port_that_is_already_taken_is_named_in_the_refusal() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let e = trigon_mirror::reserve(port)
        .await
        .expect_err("two listeners on one port");
    assert!(
        matches!(e, MirrorError::Bind { port: p, .. } if p == port),
        "{e:?}"
    );
    assert!(e.to_string().contains(&port.to_string()), "{e}");
    assert_eq!((e.status(), e.fault()), (500, Fault::Infra));
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

const SCOPE: &str = "seam-scope";
/// When the seeded documents were "fetched", so the run's report of it can be checked exactly.
const FETCHED_AT: u64 = 1_700_000_000;
const REG: &str = "https://api.nuget.org/v3/registration5-gz-semver2";
const FLAT: &str = "https://api.nuget.org/v3-flatcontainer";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trigon-seam-cache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn seed(root: &Path) -> Cache {
    Cache::open(root.to_path_buf(), SCOPE.into()).unwrap()
}

fn index(c: &Cache, url: &str, doc: &Value) {
    let body = serde_json::to_vec(doc).unwrap();
    c.put(Tier::Index, url, &body, "application/json", FETCHED_AT)
        .unwrap();
}

fn bytes(c: &Cache, url: &str, body: &[u8]) {
    c.put(
        Tier::Bytes,
        url,
        body,
        "application/octet-stream",
        FETCHED_AT,
    )
    .unwrap();
}

/// A mirror on loopback, reading the cache at `root`.
async fn serve(root: &Path, guard: Option<GuardManifest>) -> MirrorHandle {
    let mut m = Mirror::new()
        .unwrap()
        .with_cache(root.to_path_buf(), SCOPE.into(), None)
        .unwrap();
    if let Some(g) = guard {
        m = m.with_guard(g);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    m.serve_on(listener).await.unwrap()
}

struct Got {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

impl Got {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }
}

async fn get(
    m: &MirrorHandle,
    path: &str,
    auth: Option<(&str, &str)>,
    accept: Option<&str>,
) -> Got {
    let mut req = reqwest::Client::new().get(format!("http://{}{path}", m.host()));
    if let Some((user, moment)) = auth {
        req = req.basic_auth(user, Some(moment));
    }
    if let Some(a) = accept {
        req = req.header(reqwest::header::ACCEPT, a);
    }
    read(req.send().await.unwrap()).await
}

/// A URL the mirror handed out, fetched exactly as a client would.
async fn get_url(url: &str) -> Got {
    read(reqwest::get(url).await.unwrap()).await
}

async fn read(resp: reqwest::Response) -> Got {
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    Got {
        status,
        content_type,
        body: resp.bytes().await.unwrap().to_vec(),
    }
}

/// The status of a request sent as a raw request line, so a path reaches the mirror exactly as
/// written rather than as an HTTP client normalizes it.
async fn raw_status(m: &MirrorHandle, path: &str) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut s = tokio::net::TcpStream::connect(m.addr).await.unwrap();
    s.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            m.host()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    text.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {text}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn versions(doc: &Value) -> Vec<String> {
    doc["versions"]
        .as_object()
        .map(|v| v.keys().cloned().collect())
        .unwrap_or_default()
}

/// Three versions straddling 2019: one old, one mid-2019, one from 2021.
fn packument() -> Value {
    let v = |version: &str| {
        json!({
            "name": "demo-pkg",
            "version": version,
            "dist": {
                "tarball": format!(
                    "https://registry.npmjs.org/demo-pkg/-/demo-pkg-{version}.tgz"
                )
            }
        })
    };
    json!({
        "name": "demo-pkg",
        "dist-tags": { "latest": "2.0.0", "next": "2.0.0" },
        "versions": { "1.0.0": v("1.0.0"), "1.1.0": v("1.1.0"), "2.0.0": v("2.0.0") },
        "time": {
            "created": "2018-01-01T00:00:00.000Z",
            "modified": "2021-01-01T00:00:00.000Z",
            "1.0.0": "2018-01-01T00:00:00.000Z",
            "1.1.0": "2019-06-01T00:00:00.000Z",
            "2.0.0": "2021-01-01T00:00:00.000Z"
        }
    })
}

fn scoped_packument() -> Value {
    json!({
        "name": "@scope/other",
        "versions": {
            "3.0.0": {
                "dist": { "tarball": "https://registry.npmjs.org/@scope/other/-/other-3.0.0.tgz" }
            }
        },
        "time": { "3.0.0": "2019-01-01T00:00:00.000Z" }
    })
}

/// A simple index with one file before 2020, one after, and one nobody dated.
fn simple() -> Value {
    json!({
        "name": "demo",
        "meta": { "api-version": "1.1" },
        "versions": ["1.0", "2.0"],
        "files": [
            {
                "filename": "demo-1.0.tar.gz",
                "url": "https://files.pythonhosted.org/packages/aa/demo-1.0.tar.gz",
                "upload-time": "2018-01-01T00:00:00.000000Z",
                "hashes": { "sha256": "aaa" }
            },
            {
                "filename": "demo-2.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/packages/bb/demo-2.0-py3-none-any.whl",
                "upload-time": "2021-06-01T12:00:00.000000Z",
                "hashes": { "sha256": "bbb" }
            },
            {
                "filename": "demo-0.9.zip",
                "url": "https://files.pythonhosted.org/packages/cc/demo-0.9.zip",
                "hashes": { "sha256": "ccc" }
            }
        ]
    })
}

fn leaf(id: &str, version: &str, published: &str, listed: Option<bool>) -> Value {
    let lower = id.to_ascii_lowercase();
    let content = format!("{FLAT}/{lower}/{version}/{lower}.{version}.nupkg");
    let mut entry = json!({
        "id": id,
        "version": version,
        "published": published,
        "packageContent": content,
    });
    if let Some(l) = listed {
        entry["listed"] = json!(l);
    }
    json!({
        "@id": format!("{REG}/{lower}/{version}.json"),
        "packageContent": content,
        "registration": format!("{REG}/{lower}/index.json"),
        "catalogEntry": entry,
    })
}

/// One inline page and one page that is only a URL, the shape `system.text.json` has.
fn registration() -> Value {
    json!({
        "count": 2,
        "items": [
            {
                "@id": format!("{REG}/demo.pkg/index.json#page/1.0.0/1.2.0"),
                "count": 4,
                "items": [
                    leaf("Demo.Pkg", "1.0.0", "2018-01-01T00:00:00+00:00", None),
                    leaf("Demo.Pkg", "1.1.0", "1900-01-01T00:00:00+00:00", None),
                    leaf("Demo.Pkg", "1.1.5", "2018-06-01T00:00:00+00:00", Some(false)),
                    leaf("Demo.Pkg", "1.2.0", "2021-01-01T00:00:00+00:00", None),
                ],
            },
            {
                "@id": format!("{REG}/demo.pkg/page/2.0.0/3.0.0.json"),
                "count": 2,
                "lower": "2.0.0",
                "upper": "3.0.0",
            },
        ],
    })
}

fn remote_page() -> Value {
    json!({
        "@id": format!("{REG}/demo.pkg/page/2.0.0/3.0.0.json"),
        "count": 2,
        "items": [
            leaf("Demo.Pkg", "2.0.0", "2019-01-01T00:00:00+00:00", None),
            leaf("Demo.Pkg", "3.0.0", "2022-01-01T00:00:00+00:00", None),
        ],
    })
}

/// A file large enough to be guarded, and not boilerplate any other package would carry.
fn guarded_member() -> Vec<u8> {
    (0..6000u32)
        .flat_map(|i| format!("export const v{i} = {};\n", i * 7).into_bytes())
        .take(8192)
        .collect()
}

fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, *name, *body).unwrap();
    }
    let tar = b.into_inner().unwrap();
    let mut out = Vec::new();
    {
        use std::io::Write as _;
        let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap();
    }
    out
}
