//! What each resolver reads out of its registry's documents, and what the client does with a status.
//!
//! Everything here is a document someone else wrote: a version document, a packument, a JSON API
//! answer, a catalog. What the resolvers promise about them is in their module docs — a malformed
//! answer is refused rather than read as absence, a missing version names the ones that exist, a
//! sentinel date is not a date, and what the registry recorded about the source and the toolchain
//! reaches the target at the confidence it deserves. The client's promise is `client.rs`'s: retry
//! the transient statuses, honour the wait a server asked for, and never read a GitHub rate limit as
//! a missing tag.
//!
//! Every server is bound to `127.0.0.1:0` in this process. Nothing here reaches the network.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use trigon_core::{
    CheckResult, Claim, Classify as _, Confidence, Evidence, RegistryMoment, SourceDiscovery,
    TargetRef,
};
use trigon_registry::{
    Client, ClientConfig, CratesIoRegistry, NpmRegistry, NuGetRegistry, PyPiRegistry, Registry,
    RegistryError, ResolvedTarget,
};

/// One answer a path gives: a status, extra headers, and a body — or no answer at all.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    /// Read the request, then close the connection without writing a byte.
    hang_up: bool,
}

fn ok(body: impl Into<Vec<u8>>) -> Reply {
    Reply {
        status: 200,
        headers: Vec::new(),
        body: body.into(),
        hang_up: false,
    }
}

/// A connection that breaks after the request: the transport failure a registry's load balancer
/// produces, rather than a status it chose.
fn hang_up() -> Reply {
    Reply {
        hang_up: true,
        ..status(0)
    }
}

fn json(v: serde_json::Value) -> Reply {
    ok(serde_json::to_vec(&v).unwrap())
}

fn status(code: u16) -> Reply {
    Reply {
        status: code,
        headers: Vec::new(),
        body: b"{}".to_vec(),
        hang_up: false,
    }
}

impl Reply {
    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

/// A registry on loopback. Each path answers its replies in order and then repeats the last one;
/// a path with none answers 404. Every request's path is written down, so a test can say how many
/// times the client asked.
struct Loopback {
    base: String,
    listener: std::net::TcpListener,
}

type Seen = Arc<Mutex<Vec<String>>>;

impl Loopback {
    fn bind() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().unwrap());
        Loopback { base, listener }
    }

    fn serve(self, routes: Vec<(String, Vec<Reply>)>) -> (String, Seen) {
        let mut routes: BTreeMap<String, Vec<Reply>> = routes.into_iter().collect();
        let seen: Seen = Arc::default();
        let log = seen.clone();
        let base = self.base.clone();
        std::thread::spawn(move || {
            for stream in self.listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let line = String::from_utf8_lossy(&head);
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                log.lock().unwrap().push(path.clone());
                let reply = match routes.get_mut(&path) {
                    Some(queue) if queue.len() > 1 => queue.remove(0),
                    Some(queue) if !queue.is_empty() => queue[0].clone(),
                    _ => status(404),
                };
                if reply.hang_up {
                    continue;
                }
                let mut out = format!(
                    "HTTP/1.1 {} Answer\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in &reply.headers {
                    out.push_str(&format!("{name}: {value}\r\n"));
                }
                out.push_str("\r\n");
                let _ = stream.write_all(out.as_bytes());
                let _ = stream.write_all(&reply.body);
            }
        });
        (base, seen)
    }
}

/// A client that does not retry, so a status under test is the answer rather than the first of
/// several backoffs.
fn client() -> Client {
    client_retrying(0)
}

fn client_retrying(max_retries: u32) -> Client {
    Client::new(ClientConfig {
        max_retries,
        ..ClientConfig::default()
    })
    .unwrap()
}

fn target(purl: &str) -> TargetRef {
    TargetRef::from_str(purl).unwrap()
}

fn host(base: &str) -> String {
    base.trim_start_matches("http://").to_string()
}

fn count(seen: &Seen, path: &str) -> usize {
    seen.lock().unwrap().iter().filter(|p| *p == path).count()
}

fn evidence<'a>(t: &'a ResolvedTarget, source: &str) -> Vec<&'a Evidence> {
    t.intrinsics
        .evidence
        .iter()
        .filter(|e| e.source == source)
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------------------------

async fn npm(
    routes: Vec<(String, Vec<Reply>)>,
    purl: &str,
) -> Result<ResolvedTarget, RegistryError> {
    let (base, _) = Loopback::bind().serve(routes);
    NpmRegistry::new(client())
        .with_base(base)
        .resolve(&target(purl))
        .await
}

fn npm_doc(base_tarball: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "widget",
        "version": "1.0.0",
        "dist": {
            "tarball": format!("{base_tarball}/widget/-/widget-1.0.0.tgz"),
            "shasum": "5b8a3a7765dfe001261dde915589e782f8c94d1e",
            "unpackedSize": 1234,
        },
    })
}

#[tokio::test]
async fn an_npm_version_document_without_a_tarball_is_refused_as_malformed() {
    // The tarball URL is the one thing a version document exists to give. A document without it is
    // not a package with nothing to fetch; it is an answer the resolver cannot use, and saying so
    // is better than inventing a URL.
    for (doc, missing) in [
        (serde_json::json!({ "name": "widget" }), "`dist`"),
        (
            serde_json::json!({ "dist": { "shasum": "00" } }),
            "`dist.tarball`",
        ),
    ] {
        let e = npm(
            vec![("/widget/1.0.0".into(), vec![json(doc)])],
            "pkg:npm/widget@1.0.0",
        )
        .await
        .unwrap_err();
        assert!(matches!(e, RegistryError::Malformed { .. }), "{e}");
        assert!(e.to_string().contains(missing), "{e}");
        assert!(
            !e.is_retryable(),
            "a malformed answer is not a busy one: {e}"
        );
    }
}

#[tokio::test]
async fn a_missing_npm_version_names_the_versions_the_packument_has() {
    // "no such version" alone sends someone to a browser; the list of what exists does not.
    let packument = serde_json::json!({
        "versions": { "1.2.0": {}, "0.9.0": {}, "1.0.1": {} },
    });
    let e = npm(
        vec![("/widget".into(), vec![json(packument)])],
        "pkg:npm/widget@1.0.0",
    )
    .await
    .unwrap_err();
    let RegistryError::NoSuchVersion {
        name,
        version,
        available,
        ..
    } = &e
    else {
        panic!("not a missing version: {e}");
    };
    assert_eq!((name.as_str(), version.as_str()), ("widget", "1.0.0"));
    assert_eq!(available, &["0.9.0", "1.0.1", "1.2.0"]);
    assert!(e.to_string().contains("Recent:"), "{e}");
    assert!(!e.is_retryable());
}

#[tokio::test]
async fn the_npm_versions_called_recent_are_the_highest_numbers_not_the_last_strings() {
    // A packument's keys sort as strings, which puts `1.10.0` before `1.9.0`, and the message once
    // called `1.9.0` the newest and left the real one out.
    let packument = serde_json::json!({
        "versions": { "1.9.0": {}, "1.10.0": {}, "1.2.0": {} },
    });
    let e = npm(
        vec![("/widget".into(), vec![json(packument)])],
        "pkg:npm/widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(
        e.to_string().contains("Recent: 1.10.0, 1.9.0, 1.2.0"),
        "{e}"
    );
}

#[tokio::test]
async fn a_package_npm_has_never_heard_of_is_no_such_package() {
    // Both the version and the package 404. That is a different fact from a missing version, and
    // the message has to say which one it is.
    let e = npm(Vec::new(), "pkg:npm/widget@1.0.0").await.unwrap_err();
    assert!(
        matches!(&e, RegistryError::NoSuchPackage { name, .. } if name == "widget"),
        "{e}"
    );

    // A packument that answers with something other than JSON says no more than a 404 does.
    let e = npm(
        vec![("/widget".into(), vec![ok("<html>not json</html>")])],
        "pkg:npm/widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RegistryError::NoSuchPackage { .. }), "{e}");
}

#[tokio::test]
async fn what_npm_recorded_about_a_publish_reaches_the_resolved_target() {
    // A scoped name, so the `/` that npm wants percent-encoded is in the path, and a version
    // document carrying everything the resolver reads: the commit, the repository and where in it
    // the package lives, the publishing toolchain, and a build script `npm pack` will not run.
    let server = Loopback::bind();
    let mut doc = npm_doc(&server.base);
    doc["name"] = "@scope/widget".into();
    doc["gitHead"] = "ff8e7ba8b4122829cf66125ca8445cac7f073bce".into();
    doc["repository"] = serde_json::json!({
        "type": "git",
        "url": "git+https://github.com/scope/monorepo.git",
        "directory": "packages/widget",
    });
    doc["_nodeVersion"] = "20.11.1".into();
    doc["_npmVersion"] = "10.2.4".into();
    doc["scripts"] = serde_json::json!({ "build": "tsc -p ." });
    doc["devDependencies"] = serde_json::json!({ "tsc": "2.0.0" });
    let packument = serde_json::json!({ "time": { "1.0.0": "2024-03-01T12:00:00.000Z" } });
    let (base, _) = server.serve(vec![
        ("/@scope%2fwidget/1.0.0".into(), vec![json(doc)]),
        ("/@scope%2fwidget".into(), vec![json(packument)]),
    ]);
    let t = NpmRegistry::new(client())
        .with_base(base)
        .resolve(&target("pkg:npm/@scope/widget@1.0.0"))
        .await
        .unwrap();

    let a = t.sole_artifact().expect("one tarball");
    assert_eq!(a.id.as_str(), "widget-1.0.0.tgz");
    assert_eq!(a.size, Some(1234));
    assert_eq!(a.declared[0].source, "npm:dist.shasum");
    assert_eq!(a.declared_sha256(), None, "npm never declares a sha256");

    let s = t.source.as_ref().expect("a source location");
    assert_eq!(s.repo_url, "https://github.com/scope/monorepo");
    assert_eq!(
        s.declared_url.as_deref(),
        Some("git+https://github.com/scope/monorepo.git"),
        "what the package said, beside what it was canonicalized to"
    );
    assert_eq!(s.commit, "ff8e7ba8b4122829cf66125ca8445cac7f073bce");
    assert_eq!(s.subdir.as_deref(), Some("packages/widget"));
    assert_eq!(s.how, SourceDiscovery::RegistryCommit);

    assert_eq!(
        t.intrinsics.publish_time.as_deref(),
        Some("2024-03-01T12:00:00.000Z")
    );
    assert_eq!(
        t.intrinsics.registry_moment,
        Some(RegistryMoment::Timestamp {
            rfc3339: "2024-03-01T12:00:00.000Z".into()
        })
    );
    assert_eq!(
        t.intrinsics.declared_repo.as_deref(),
        Some("https://github.com/scope/monorepo")
    );
    let toolchain: Vec<(&Claim, Confidence)> = ["npm:_nodeVersion", "npm:_npmVersion"]
        .iter()
        .flat_map(|src| evidence(&t, src))
        .map(|e| (&e.claim, e.confidence))
        .collect();
    assert_eq!(
        toolchain,
        [
            (
                &Claim::ToolchainExact {
                    tool: "node".into(),
                    version: "20.11.1".into()
                },
                Confidence::Certain
            ),
            (
                &Claim::ToolchainExact {
                    tool: "npm".into(),
                    version: "10.2.4".into()
                },
                Confidence::Certain
            ),
        ]
    );
    assert_eq!(
        evidence(&t, "npm:scripts")[0].claim,
        Claim::UnrunScript {
            name: "build".into(),
            command: "tsc -p .".into()
        }
    );
    assert_eq!(
        evidence(&t, "npm:package.json:repository")[0].confidence,
        Confidence::Strong
    );
}

#[tokio::test]
async fn an_npm_repository_without_a_commit_is_still_a_source_to_find_one_in() {
    // Monorepo publishing tools mostly do not write `gitHead`. The repository is still where the
    // source is; what is missing is which commit, and that is said by how it was discovered rather
    // than by dropping the repository.
    let server = Loopback::bind();
    let mut doc = npm_doc(&server.base);
    doc["repository"] = "github:owner/widget".into();
    let (base, _) = server.serve(vec![("/widget/1.0.0".into(), vec![json(doc)])]);
    let t = NpmRegistry::new(client())
        .with_base(base)
        .resolve(&target("pkg:npm/widget@1.0.0"))
        .await
        .unwrap();
    let s = t
        .source
        .as_ref()
        .expect("a repository is a source location");
    assert_eq!(s.repo_url, "https://github.com/owner/widget");
    assert!(s.commit.is_empty());
    assert_eq!(s.how, SourceDiscovery::RegistryMetadata);
    // The packument's `time` could not be read, so no moment is claimed rather than a guessed one.
    assert_eq!(t.intrinsics.publish_time, None);
    assert!(evidence(&t, "npm:time").is_empty());
}

// ---------------------------------------------------------------------------------------------
// PyPI
// ---------------------------------------------------------------------------------------------

async fn pypi(
    routes: Vec<(String, Vec<Reply>)>,
    purl: &str,
) -> Result<ResolvedTarget, RegistryError> {
    let (base, _) = Loopback::bind().serve(routes);
    PyPiRegistry::new(client())
        .with_base(base)
        .resolve(&target(purl))
        .await
}

fn wheel(name: &str) -> serde_json::Value {
    serde_json::json!({
        "filename": name,
        "url": format!("https://files.invalid/{name}"),
        "digests": { "sha256": "ab".repeat(32) },
    })
}

#[tokio::test]
async fn a_pypi_answer_with_no_file_list_is_malformed_and_one_with_no_files_is_no_version() {
    let e = pypi(
        vec![(
            "/pypi/widget/1.0.0/json".into(),
            vec![json(serde_json::json!({ "info": {} }))],
        )],
        "pkg:pypi/widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RegistryError::Malformed { .. }), "{e}");
    assert!(e.to_string().contains("`urls`"), "{e}");

    // A release whose every entry lacks a filename or a URL has nothing to verify, which is the
    // same answer as a release with no files.
    let e = pypi(
        vec![(
            "/pypi/widget/1.0.0/json".into(),
            vec![json(serde_json::json!({
                "urls": [{ "filename": "widget-1.0.0.tar.gz" }, { "url": "https://x.invalid/a" }],
            }))],
        )],
        "pkg:pypi/widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&e, RegistryError::NoSuchVersion { available, .. } if available.is_empty()),
        "{e}"
    );
}

#[tokio::test]
async fn a_missing_pypi_release_names_the_releases_the_project_has() {
    let project = serde_json::json!({ "releases": { "2.0.0": [], "1.0.0": [], "1.5.0": [] } });
    let e = pypi(
        vec![("/pypi/widget/json".into(), vec![json(project)])],
        "pkg:pypi/widget@9.9.9",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&e, RegistryError::NoSuchVersion { available, .. }
            if available == &["1.0.0", "1.5.0", "2.0.0"]),
        "{e}"
    );

    // And a project that is not there at all is a missing package, whatever else fails.
    let e = pypi(Vec::new(), "pkg:pypi/widget@9.9.9").await.unwrap_err();
    assert!(matches!(e, RegistryError::NoSuchPackage { .. }), "{e}");
    let e = pypi(
        vec![("/pypi/widget/json".into(), vec![ok("not json")])],
        "pkg:pypi/widget@9.9.9",
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RegistryError::NoSuchPackage { .. }), "{e}");
}

#[tokio::test]
async fn the_pypi_releases_called_recent_are_the_highest_numbers_not_the_last_strings() {
    // The same string-order trap as npm's, with a release candidate that belongs below its release.
    let project = serde_json::json!({
        "releases": { "1.9.0": [], "1.10.0rc1": [], "1.10.0": [] },
    });
    let e = pypi(
        vec![("/pypi/widget/json".into(), vec![json(project)])],
        "pkg:pypi/widget@9.9.9",
    )
    .await
    .unwrap_err();
    assert!(
        e.to_string().contains("Recent: 1.10.0, 1.10.0rc1, 1.9.0"),
        "{e}"
    );
}

#[tokio::test]
async fn a_pypi_digest_that_is_not_a_digest_refuses_the_resolve_and_names_the_file() {
    // A malformed declaration dropped would be a download checked against nothing that reads like
    // one the registry declared nothing for.
    for digests in [
        serde_json::json!({ "sha256": "not-hex" }),
        serde_json::json!({ "sha256": 42 }),
    ] {
        let mut file = wheel("widget-1.0.0-py3-none-any.whl");
        file["digests"] = digests.clone();
        let e = pypi(
            vec![(
                "/pypi/widget/1.0.0/json".into(),
                vec![json(serde_json::json!({ "urls": [file] }))],
            )],
            "pkg:pypi/widget@1.0.0",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(e, RegistryError::Malformed { .. }),
            "{digests}: {e}"
        );
        let msg = e.to_string();
        assert!(msg.contains("widget-1.0.0-py3-none-any.whl"), "{msg}");
        assert!(msg.contains("pypi:digests.sha256"), "{msg}");
    }

    // A file with no `digests` at all declares nothing, which is recorded as absence downstream
    // rather than refused here.
    let mut file = wheel("widget-1.0.0-py3-none-any.whl");
    file.as_object_mut().unwrap().remove("digests");
    let t = pypi(
        vec![(
            "/pypi/widget/1.0.0/json".into(),
            vec![json(serde_json::json!({ "urls": [file] }))],
        )],
        "pkg:pypi/widget@1.0.0",
    )
    .await
    .unwrap();
    assert!(t.artifacts[0].declared.is_empty());
}

#[tokio::test]
async fn the_earliest_upload_is_the_release_moment_whichever_field_carries_it() {
    // A wheel backfilled months later for a new Python is not when the release happened. The older
    // `upload_time` field counts where the ISO one is absent.
    let mut late = wheel("widget-1.0.0-cp313-cp313-manylinux_2_17_x86_64.whl");
    late["upload_time_iso_8601"] = "2024-09-01T00:00:00.000000Z".into();
    let mut early = wheel("widget-1.0.0.tar.gz");
    early["upload_time"] = "2024-03-01T10:00:00".into();
    let t = pypi(
        vec![(
            "/pypi/widget/1.0.0/json".into(),
            vec![json(serde_json::json!({
                "info": { "project_urls": { "Source": "https://github.com/o/widget" } },
                "urls": [late, early],
            }))],
        )],
        "pkg:pypi/widget@1.0.0",
    )
    .await
    .unwrap();
    assert_eq!(t.artifacts.len(), 2);
    assert_eq!(
        t.intrinsics.publish_time.as_deref(),
        Some("2024-03-01T10:00:00")
    );
    let moment = evidence(&t, "pypi:upload_time");
    assert_eq!(moment[0].confidence, Confidence::Certain);
}

#[tokio::test]
async fn a_release_naming_no_forge_asks_the_project_and_says_whose_word_it_took() {
    // `pytz`'s shape: the release names a docs site; the project, today, names the repository.
    let release = serde_json::json!({
        "info": { "project_urls": { "Homepage": "http://pythonhosted.org/widget" } },
        "urls": [wheel("widget-1.0.0-py3-none-any.whl")],
    });
    let project = serde_json::json!({
        "info": { "project_urls": {
            "Source": "https://github.com/o/mono/tree/main/python/widget",
        } },
    });
    let t = pypi(
        vec![
            (
                "/pypi/widget/1.0.0/json".into(),
                vec![json(release.clone())],
            ),
            ("/pypi/widget/json".into(), vec![json(project)]),
        ],
        "pkg:pypi/widget@1.0.0",
    )
    .await
    .unwrap();
    let s = t.source.as_ref().expect("the project's repository");
    assert_eq!(s.repo_url, "https://github.com/o/mono");
    assert_eq!(s.subdir.as_deref(), Some("python/widget"));
    assert_eq!(
        s.declared_url.as_deref(),
        Some("https://github.com/o/mono/tree/main/python/widget")
    );
    let repo = evidence(&t, "pypi:project_urls@latest");
    assert_eq!(repo.len(), 1, "recorded under its own source");
    assert_eq!(repo[0].confidence, Confidence::Weak);
    assert!(evidence(&t, "pypi:project_urls").is_empty());

    // A project document that cannot be read leaves the resolve where the release left it: no
    // repository, and not a failed target.
    let t = pypi(
        vec![
            ("/pypi/widget/1.0.0/json".into(), vec![json(release)]),
            ("/pypi/widget/json".into(), vec![status(503)]),
        ],
        "pkg:pypi/widget@1.0.0",
    )
    .await
    .expect("a best-effort fallback never fails the resolve");
    assert_eq!(t.source, None);
    assert!(evidence(&t, "pypi:project_urls@latest").is_empty());
}

// ---------------------------------------------------------------------------------------------
// crates.io
// ---------------------------------------------------------------------------------------------

async fn cargo(
    routes: Vec<(String, Vec<Reply>)>,
    purl: &str,
) -> Result<ResolvedTarget, RegistryError> {
    let (base, _) = Loopback::bind().serve(routes);
    CratesIoRegistry::new(client())
        .with_base(base)
        .resolve(&target(purl))
        .await
}

#[tokio::test]
async fn what_crates_io_records_about_a_version_reaches_the_resolved_target() {
    // The repository from the crate when the version has none, the edition as a floor and never a
    // version, the publish instant, the size, and a download URL built from the name when the API
    // gives no `dl_path`.
    let sha256 = hex(&[0xab; 32]);
    let doc = serde_json::json!({
        "crate": { "repository": "https://github.com/o/widget.git" },
        "version": {
            "num": "1.0.0",
            "checksum": sha256.to_uppercase(),
            "created_at": "2024-03-01T00:00:00Z",
            "edition": "2021",
            "crate_size": 4096,
        },
    });
    let (base, _) = Loopback::bind().serve(vec![(
        "/api/v1/crates/widget/1.0.0".into(),
        vec![json(doc)],
    )]);
    let t = CratesIoRegistry::new(client())
        .with_base(base.clone())
        .resolve(&target("pkg:cargo/widget@1.0.0"))
        .await
        .unwrap();

    let a = t.sole_artifact().unwrap();
    assert_eq!(a.id.as_str(), "widget-1.0.0.crate");
    assert_eq!(a.url, format!("{base}/api/v1/crates/widget/1.0.0/download"));
    assert_eq!(a.size, Some(4096));
    assert_eq!(
        a.declared_sha256().map(|d| d.to_string()),
        Some(sha256.clone()),
        "declared in upper case, compared in lower"
    );

    let s = t.source.as_ref().unwrap();
    assert_eq!(s.repo_url, "https://github.com/o/widget");
    assert_eq!(
        s.declared_url.as_deref(),
        Some("https://github.com/o/widget.git")
    );
    assert!(s.commit.is_empty(), "crates.io records no commit");
    assert_eq!(s.how, SourceDiscovery::RegistryMetadata);
    assert_eq!(
        evidence(&t, "cargo:version.repository")[0].confidence,
        Confidence::Strong
    );
    assert_eq!(
        evidence(&t, "cargo:edition")[0].claim,
        Claim::ToolchainRange {
            tool: "cargo".into(),
            lo: Some("1.56.0".into()),
            hi: None
        }
    );
    assert_eq!(
        t.intrinsics.publish_time.as_deref(),
        Some("2024-03-01T00:00:00Z")
    );
}

#[tokio::test]
async fn an_edition_crates_io_has_not_taught_us_is_no_claim_at_all() {
    // A future edition must not become a claim about an old Cargo.
    let doc = serde_json::json!({
        "version": { "num": "1.0.0", "edition": "2027", "repository": "https://github.com/o/w" },
    });
    let t = cargo(
        vec![("/api/v1/crates/widget/1.0.0".into(), vec![json(doc)])],
        "pkg:cargo/widget@1.0.0",
    )
    .await
    .unwrap();
    assert!(evidence(&t, "cargo:edition").is_empty());
    assert!(t.artifacts[0].declared.is_empty(), "no checksum declared");
    assert_eq!(t.intrinsics.registry_moment, None);
}

#[tokio::test]
async fn a_crates_io_answer_that_cannot_be_used_is_refused_rather_than_read_as_absence() {
    // No `version` object: nothing to resolve from.
    let e = cargo(
        vec![(
            "/api/v1/crates/widget/1.0.0".into(),
            vec![json(serde_json::json!({ "crate": {} }))],
        )],
        "pkg:cargo/widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RegistryError::Malformed { .. }), "{e}");
    assert!(e.to_string().contains("`version`"), "{e}");

    // A checksum that is not a sha256. Dropping it, as this once did, made a malformed declaration
    // read as no declaration and the download went unchecked.
    let e = cargo(
        vec![(
            "/api/v1/crates/widget/1.0.0".into(),
            vec![json(
                serde_json::json!({ "version": { "checksum": "abc123" } }),
            )],
        )],
        "pkg:cargo/widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RegistryError::Malformed { .. }), "{e}");
    assert!(e.to_string().contains("cargo:checksum"), "{e}");
}

#[tokio::test]
async fn a_missing_crate_version_names_what_crates_io_lists() {
    let listing = serde_json::json!({
        "versions": [{ "num": "1.1.0" }, { "num": "0.9.0" }, { "yanked": true }],
    });
    let e = cargo(
        vec![("/api/v1/crates/widget".into(), vec![json(listing)])],
        "pkg:cargo/widget@1.0.0",
    )
    .await
    .unwrap_err();
    // Every version the listing names, and nothing for an entry that names none. (Which of them
    // the message calls recent is the next test's question.)
    let RegistryError::NoSuchVersion { available, .. } = &e else {
        panic!("not a missing version: {e}");
    };
    let mut listed = available.clone();
    listed.sort();
    assert_eq!(listed, ["0.9.0", "1.1.0"]);

    // A listing that could not be read still answers the question that was asked: that version
    // does not exist. It does not become an error about the listing.
    let e = cargo(Vec::new(), "pkg:cargo/widget@1.0.0")
        .await
        .unwrap_err();
    assert!(
        matches!(&e, RegistryError::NoSuchVersion { available, .. } if available.is_empty()),
        "{e}"
    );
    assert!(!e.to_string().contains("Recent"), "{e}");
}

#[tokio::test]
async fn the_crate_versions_called_recent_are_the_newest_although_crates_io_lists_them_first() {
    // crates.io lists newest first. Read as oldest first, the message called the oldest recent.
    let listing = serde_json::json!({
        "versions": [
            { "num": "1.1.0" },
            { "num": "1.1.0-rc.1" },
            { "num": "1.0.1" },
            { "num": "0.9.0" },
        ],
    });
    let e = cargo(
        vec![("/api/v1/crates/widget".into(), vec![json(listing)])],
        "pkg:cargo/widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(
        e.to_string()
            .contains("Recent: 1.1.0, 1.1.0-rc.1, 1.0.1, 0.9.0"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------------------------
// NuGet
// ---------------------------------------------------------------------------------------------

const FLAT: &str = "/v3-flatcontainer/widget/index.json";
const REGISTRATION: &str = "/v3/registration5-gz-semver2/widget/index.json";

async fn nuget(
    routes: Vec<(String, Vec<Reply>)>,
    purl: &str,
) -> Result<ResolvedTarget, RegistryError> {
    nuget_seen(routes, purl).await.0
}

async fn nuget_seen(
    routes: Vec<(String, Vec<Reply>)>,
    purl: &str,
) -> (Result<ResolvedTarget, RegistryError>, Seen) {
    let (base, seen) = Loopback::bind().serve(routes);
    let r = NuGetRegistry::new(client())
        .with_base(base)
        .resolve(&target(purl))
        .await;
    (r, seen)
}

/// A registration whose one inline page lists `entry`.
fn registration(entry: serde_json::Value) -> Reply {
    json(serde_json::json!({ "items": [{ "items": [{ "catalogEntry": entry }] }] }))
}

fn listed(versions: &[&str]) -> Reply {
    json(serde_json::json!({ "versions": versions }))
}

#[tokio::test]
async fn a_nuget_package_the_flat_container_does_not_know_is_no_such_package() {
    let e = nuget(Vec::new(), "pkg:nuget/Widget@1.0.0")
        .await
        .unwrap_err();
    assert!(
        matches!(&e, RegistryError::NoSuchPackage { name, .. } if name == "Widget"),
        "{e}"
    );

    let e = nuget(
        vec![(FLAT.into(), vec![listed(&["0.9.0", "1.1.0"])])],
        "pkg:nuget/Widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&e, RegistryError::NoSuchVersion { available, .. }
            if available == &["0.9.0", "1.1.0"]),
        "{e}"
    );
}

#[tokio::test]
async fn a_nuget_version_matches_without_case_and_every_path_is_lowercased() {
    // `Newtonsoft.Json` is `newtonsoft.json` in every path and `Newtonsoft.Json` in every document.
    let hash = "A".repeat(86) + "==";
    let (r, seen) = nuget_seen(
        vec![
            (FLAT.into(), vec![listed(&["1.0.0-rc1"])]),
            (
                REGISTRATION.into(),
                vec![registration(serde_json::json!({
                    "version": "1.0.0-rc1",
                    "packageHash": hash,
                    "packageHashAlgorithm": "SHA512",
                    "published": "2024-03-01T00:00:00+00:00",
                    "projectUrl": "https://github.com/o/widget/",
                }))],
            ),
        ],
        "pkg:nuget/Widget@1.0.0-RC1",
    )
    .await;
    let t = r.unwrap();
    let a = t.sole_artifact().unwrap();
    assert_eq!(a.id.as_str(), "widget.1.0.0-rc1.nupkg");
    assert!(
        a.url
            .ends_with("/v3-flatcontainer/widget/1.0.0-rc1/widget.1.0.0-rc1.nupkg"),
        "{}",
        a.url
    );
    // A hash carried on the entry itself needs no leaf, and none is asked for.
    assert_eq!(a.declared.len(), 1);
    assert_eq!(a.declared[0].algorithm, "sha512");
    assert_eq!(a.declared[0].value, "00".repeat(64));
    assert_eq!(a.declared_note, None);
    assert_eq!(seen.lock().unwrap().len(), 2, "{:?}", seen.lock().unwrap());

    // The projectUrl is on a forge, so it is a repository: at `Weak`, because it is a link an
    // author typed.
    let s = t.source.as_ref().unwrap();
    assert_eq!(s.repo_url, "https://github.com/o/widget");
    assert_eq!(
        s.declared_url.as_deref(),
        Some("https://github.com/o/widget/")
    );
    assert_eq!(
        evidence(&t, "nuget:projectUrl")[0].confidence,
        Confidence::Weak
    );
    assert_eq!(
        t.intrinsics.publish_time.as_deref(),
        Some("2024-03-01T00:00:00+00:00")
    );
    assert_eq!(
        evidence(&t, "nuget:published")[0].claim,
        Claim::RegistryMomentIs {
            moment: RegistryMoment::Timestamp {
                rfc3339: "2024-03-01T00:00:00+00:00".into()
            }
        }
    );
}

#[tokio::test]
async fn an_unlisted_nuget_package_is_not_published_in_1900() {
    // NuGet stamps a delisted package with `1900-01-01`. Carried into the registry moment it would
    // pin every dependency resolution to the nineteenth century.
    let t = nuget(
        vec![
            (FLAT.into(), vec![listed(&["1.0.0"])]),
            (
                REGISTRATION.into(),
                vec![registration(serde_json::json!({
                    "version": "1.0.0",
                    "published": "1900-01-01T00:00:00+00:00",
                    "projectUrl": "https://www.widget.example/docs",
                }))],
            ),
        ],
        "pkg:nuget/Widget@1.0.0",
    )
    .await
    .unwrap();
    assert_eq!(t.intrinsics.publish_time, None);
    assert_eq!(t.intrinsics.registry_moment, None);
    assert!(evidence(&t, "nuget:published").is_empty());
    // And a documentation site is not a repository.
    assert_eq!(t.source, None);
    assert!(evidence(&t, "nuget:projectUrl").is_empty());
    // An entry naming no leaf has no hash to read, and the note says that rather than that the
    // catalog declared nothing.
    let note = t.artifacts[0].declared_note.as_deref().unwrap();
    assert!(note.contains("names no catalog leaf"), "{note}");
}

#[tokio::test]
async fn a_nuget_package_hash_that_is_not_a_digest_refuses_the_resolve() {
    for (hash, algorithm) in [("not base64!", "SHA512"), (&*"A".repeat(88), "SHA256")] {
        let e = nuget(
            vec![
                (FLAT.into(), vec![listed(&["1.0.0"])]),
                (
                    REGISTRATION.into(),
                    vec![registration(serde_json::json!({
                        "version": "1.0.0",
                        "packageHash": hash,
                        "packageHashAlgorithm": algorithm,
                    }))],
                ),
            ],
            "pkg:nuget/Widget@1.0.0",
        )
        .await
        .unwrap_err();
        assert!(matches!(e, RegistryError::Malformed { .. }), "{hash}: {e}");
        assert!(e.to_string().contains("nuget:catalog.packageHash"), "{e}");
    }
}

#[tokio::test]
async fn a_registration_that_is_not_the_document_it_should_be_is_refused_not_read_as_absence() {
    // "No catalog entry for this version" has to be a fact about the registry. A registration
    // whose shape is wrong, or whose body is not JSON, is not evidence that the entry is absent.
    for (doc, detail) in [
        (json(serde_json::json!({ "count": 1 })), "no `items` list"),
        (
            json(serde_json::json!({ "items": [{ "count": 1 }] })),
            "neither `items` nor an `@id`",
        ),
        (
            json(serde_json::json!({ "items": [{ "items": "none" }] })),
            "`items` is not a list",
        ),
        (
            json(serde_json::json!({ "items": [{ "items": [{ "@id": "x" }] }] })),
            "no `catalogEntry`",
        ),
    ] {
        let e = nuget(
            vec![
                (FLAT.into(), vec![listed(&["1.0.0"])]),
                (REGISTRATION.into(), vec![doc]),
            ],
            "pkg:nuget/Widget@1.0.0",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(e, RegistryError::Malformed { .. }),
            "{detail}: {e}"
        );
        assert!(e.to_string().contains(detail), "{e}");
    }

    let e = nuget(
        vec![
            (FLAT.into(), vec![listed(&["1.0.0"])]),
            (REGISTRATION.into(), vec![ok("<html>maintenance</html>")]),
        ],
        "pkg:nuget/Widget@1.0.0",
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RegistryError::CatalogUnreadable { .. }), "{e}");
    assert!(!e.to_string().contains("no catalog entry"), "{e}");
}

// ---------------------------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_github_rate_limit_is_a_rate_limit_and_not_an_http_failure() {
    // GitHub's primary limit answers `403` with `X-RateLimit-Remaining: 0`. Read as an ordinary
    // failure it became "resolving the tag failed", then `no-strategy`: a statement about our
    // request budget wearing the costume of a finding about the package.
    let reply = status(403)
        .header("X-RateLimit-Remaining", " 0 ")
        .header("Retry-After", "7");
    let (base, seen) = Loopback::bind().serve(vec![("/x".into(), vec![reply])]);
    let e = client()
        .get(&format!("{base}/x"), "github")
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            RegistryError::RateLimited {
                retry_after_s: Some(7),
                ..
            }
        ),
        "{e}"
    );
    assert!(e.is_retryable(), "a rate limit passes");
    assert!(e.to_string().contains("asked for 7s"), "{e}");
    assert_eq!(count(&seen, "/x"), 1);
    let t = &trigon_registry::traffic()[&host(&base)];
    assert_eq!((t.requests, t.throttled), (1, 1));
}

#[tokio::test]
async fn an_exhausted_budget_waits_for_the_reset_and_never_longer_than_the_window() {
    // `X-RateLimit-Reset` is an absolute unix time, not a duration. The limit window is an hour,
    // so a reset further out than that is a clock disagreement rather than a wait to honour.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (reset, want) in [(now + 10 * 3600, 3600), (now.saturating_sub(60), 0)] {
        let reply = status(403)
            .header("X-RateLimit-Remaining", "0")
            .header("X-RateLimit-Reset", reset.to_string());
        let (base, _) = Loopback::bind().serve(vec![("/x".into(), vec![reply])]);
        let e = client()
            .get(&format!("{base}/x"), "github")
            .await
            .unwrap_err();
        assert!(
            matches!(e, RegistryError::RateLimited { retry_after_s: Some(s), .. } if s == want),
            "reset {reset}: {e}"
        );
    }
}

#[tokio::test]
async fn a_forbidden_that_is_not_a_rate_limit_fails_at_once_and_is_counted() {
    // A private repository or a bad token. Waited on as a rate limit it would wait an hour and
    // then fail anyway; retried, it would spend the budget of every other lane.
    let reply = status(403).header("X-RateLimit-Remaining", "57");
    let (base, seen) = Loopback::bind().serve(vec![("/x".into(), vec![reply])]);
    let e = client_retrying(3)
        .get(&format!("{base}/x"), "github")
        .await
        .unwrap_err();
    assert!(matches!(e, RegistryError::Http { status: 403, .. }), "{e}");
    assert!(!e.is_retryable());
    assert_eq!(count(&seen, "/x"), 1, "not retried");
    let t = &trigon_registry::traffic()[&host(&base)];
    assert_eq!((t.requests, t.throttled, t.failed), (1, 0, 1));
}

#[tokio::test]
async fn a_429_that_names_its_wait_is_waited_out_and_retried() {
    let (base, seen) = Loopback::bind().serve(vec![(
        "/x".into(),
        vec![status(429).header("Retry-After", "0"), ok("answered")],
    )]);
    let body = client_retrying(1)
        .get(&format!("{base}/x"), "pypi")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "answered");
    assert_eq!(count(&seen, "/x"), 2);
    let t = &trigon_registry::traffic()[&host(&base)];
    assert_eq!((t.requests, t.throttled, t.failed), (2, 1, 0));
}

#[tokio::test]
async fn a_busy_registry_is_retried_and_a_missing_document_is_an_answer() {
    let (base, seen) = Loopback::bind().serve(vec![
        ("/busy".into(), vec![status(503), ok("answered")]),
        ("/gone".into(), vec![status(404)]),
    ]);
    let c = client_retrying(1);
    let body = c
        .get(&format!("{base}/busy"), "npm")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "answered");
    assert_eq!(count(&seen, "/busy"), 2, "a 5xx is transient");

    let e = c.get(&format!("{base}/gone"), "npm").await.unwrap_err();
    assert!(matches!(e, RegistryError::Http { status: 404, .. }), "{e}");
    assert_eq!(count(&seen, "/gone"), 1, "a 404 is not retried");
    // And not a failure. Resolving a tag probes spellings that mostly miss, and "2 failed" on a
    // healthy run makes the next real failure read as noise.
    assert_eq!(trigon_registry::traffic()[&host(&base)].failed, 0);
}

#[tokio::test]
async fn a_connection_that_breaks_once_is_retried_and_answered() {
    // A transport failure is as transient as a 5xx: the same backoff, the same request again, and
    // the answer the second connection gives. Not a failure against the host, since it passed.
    let (base, seen) = Loopback::bind().serve(vec![("/x".into(), vec![hang_up(), ok("answered")])]);
    let body = client_retrying(1)
        .get(&format!("{base}/x"), "npm")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "answered");
    assert_eq!(count(&seen, "/x"), 2);
    let t = &trigon_registry::traffic()[&host(&base)];
    assert_eq!((t.requests, t.failed), (2, 0));
}

#[tokio::test]
async fn a_connection_that_keeps_breaking_is_a_transport_failure_once_the_retries_are_spent() {
    let (base, seen) = Loopback::bind().serve(vec![("/x".into(), vec![hang_up()])]);
    let e = client_retrying(1)
        .get(&format!("{base}/x"), "npm")
        .await
        .unwrap_err();
    assert!(matches!(e, RegistryError::Transport(_)), "{e}");
    assert!(
        e.is_retryable(),
        "a connection that broke may work next time"
    );
    assert_eq!(
        count(&seen, "/x"),
        2,
        "tried once, retried once, and no more"
    );
    // A request that failed after every retry, which is what `failed` counts.
    let t = &trigon_registry::traffic()[&host(&base)];
    assert_eq!((t.requests, t.failed), (2, 1));
}

#[tokio::test]
async fn a_server_error_that_outlasts_the_retries_is_a_failure_the_queue_retries() {
    let (base, seen) = Loopback::bind().serve(vec![("/x".into(), vec![status(502)])]);
    let e = client()
        .get(&format!("{base}/x"), "nuget")
        .await
        .unwrap_err();
    assert!(matches!(e, RegistryError::Http { status: 502, .. }), "{e}");
    assert!(e.is_retryable());
    assert_eq!(count(&seen, "/x"), 1);
    assert_eq!(trigon_registry::traffic()[&host(&base)].failed, 1);
}

#[tokio::test]
async fn a_registry_that_never_answers_is_a_transport_failure_not_a_hang() {
    // Bound and never accepted: the connection is made and nothing is ever said on it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let c = Client::new(ClientConfig {
        max_retries: 0,
        timeout: Duration::from_millis(300),
        ..ClientConfig::default()
    })
    .unwrap();
    let e = c.get(&format!("{base}/x"), "npm").await.unwrap_err();
    drop(listener);
    assert!(matches!(e, RegistryError::Transport(_)), "{e}");
    assert!(
        e.is_retryable(),
        "a connection that broke may work next time"
    );
}

#[tokio::test]
async fn a_fetch_through_a_resolver_checks_the_bytes_it_streamed() {
    // End to end through a resolver whose declaration is a sha1 alone: the fetch computes every
    // digest over the bytes as they streamed, and checks the one declared.
    use sha1::Digest as _;
    let bytes = b"\x1f\x8b a tarball";
    let server = Loopback::bind();
    let mut doc = npm_doc(&server.base);
    doc["dist"]["shasum"] = hex(&sha1::Sha1::digest(bytes)).into();
    let (base, _) = server.serve(vec![
        ("/widget/1.0.0".into(), vec![json(doc)]),
        (
            "/widget/-/widget-1.0.0.tgz".into(),
            vec![ok(bytes.to_vec())],
        ),
    ]);
    let reg = NpmRegistry::new(client()).with_base(base);
    let t = reg.resolve(&target("pkg:npm/widget@1.0.0")).await.unwrap();
    let mut sink = Vec::new();
    let f = reg
        .fetch(t.sole_artifact().unwrap(), &mut sink)
        .await
        .unwrap();
    assert_eq!(sink, bytes);
    assert_eq!(f.bytes, bytes.len() as u64);
    assert_eq!(f.checks[0].result, CheckResult::Matched);
    assert_eq!(f.sha1.to_hex(), hex(&sha1::Sha1::digest(bytes)));
}
