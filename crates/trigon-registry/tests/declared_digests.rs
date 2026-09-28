//! What each fetcher does with the digests its registry declares, against a registry on loopback.
//!
//! `docs/19` §5's rule: decode what the ecosystem declares, verify the download against every
//! declared digest the code can compute, refuse it on a mismatch, and record absence as absence.
//! These go through `resolve` and `fetch` exactly as a run does, against a server bound to
//! `127.0.0.1:0` in this process. Nothing here reaches the network.
//!
//! The npm case is pinned to real bytes: `left-pad@1.3.0`'s version document, trimmed to the fields
//! the resolver reads, and its tarball, byte for byte (`fixtures/npm/`). The other ecosystems use
//! synthetic bytes whose declarations are computed here, because what is under test is the check
//! and not the package.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::str::FromStr as _;

use sha2::Digest as _;
use trigon_core::{CheckResult, Classify as _, Fault, TargetRef};
use trigon_registry::{
    Client, ClientConfig, CratesIoRegistry, DigestMismatch, Fetched, NpmRegistry, NuGetRegistry,
    PyPiRegistry, Registry, RegistryError,
};

const LEFT_PAD_DOC: &str = include_str!("fixtures/npm/left-pad-1.3.0.json");
const LEFT_PAD_TGZ: &[u8] = include_bytes!("fixtures/npm/left-pad-1.3.0.tgz");

/// A registry on loopback: every path in `routes` answers 200 with its body, and anything else 404.
///
/// A thread per server, serving one request per connection and then closing it. Deliberately
/// small: the client under test is `reqwest`, and what matters is that it is fed exactly these
/// bytes.
struct Loopback {
    base: String,
    listener: std::net::TcpListener,
}

impl Loopback {
    fn bind() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().unwrap());
        Loopback { base, listener }
    }

    fn serve(self, routes: BTreeMap<String, Vec<u8>>) -> String {
        self.serve_failing(routes, BTreeMap::new())
    }

    /// As [`Self::serve`], except that each path in `failing` answers its status instead, which is
    /// how a registry that is busy, or has lost a document, looks from here.
    fn serve_failing(
        self,
        routes: BTreeMap<String, Vec<u8>>,
        failing: BTreeMap<String, u16>,
    ) -> String {
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
                let (status, body) = match (failing.get(&path), routes.get(&path)) {
                    (Some(code), _) => (format!("{code} Failing"), b"{}".to_vec()),
                    (None, Some(b)) => ("200 OK".to_string(), b.clone()),
                    (None, None) => ("404 Not Found".to_string(), b"{}".to_vec()),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            }
        });
        base
    }
}

fn client() -> Client {
    Client::new(ClientConfig::default()).unwrap()
}

fn target(purl: &str) -> TargetRef {
    TargetRef::from_str(purl).unwrap()
}

/// Serve left-pad 1.3.0 with `edit` applied to its version document and `tarball` as its bytes,
/// and resolve and fetch it as a run does.
async fn left_pad(
    edit: impl FnOnce(&mut serde_json::Value),
    tarball: &[u8],
) -> Result<Fetched, RegistryError> {
    let server = Loopback::bind();
    let mut doc: serde_json::Value = serde_json::from_str(LEFT_PAD_DOC).unwrap();
    doc["dist"]["tarball"] = format!("{}/left-pad/-/left-pad-1.3.0.tgz", server.base).into();
    edit(&mut doc);
    let routes = BTreeMap::from([
        (
            "/left-pad/1.3.0".to_string(),
            serde_json::to_vec(&doc).unwrap(),
        ),
        (
            "/left-pad/-/left-pad-1.3.0.tgz".to_string(),
            tarball.to_vec(),
        ),
    ]);
    let base = server.serve(routes);
    let npm = NpmRegistry::new(client()).with_base(base);
    let resolved = npm.resolve(&target("pkg:npm/left-pad@1.3.0")).await?;
    let meta = resolved.sole_artifact().expect("one tarball");
    let mut sink = Vec::new();
    npm.fetch(meta, &mut sink).await
}

fn results(f: &Fetched) -> Vec<(&str, &str, CheckResult)> {
    f.checks
        .iter()
        .map(|c| {
            (
                c.declared.algorithm.as_str(),
                c.declared.source.as_str(),
                c.result,
            )
        })
        .collect()
}

#[tokio::test]
async fn an_npm_download_matching_its_integrity_records_sha512_and_sha1_as_matched() {
    // npm declares sha512 in `integrity` and sha1 in `shasum`, and never sha256. The fetcher read
    // only a `sha256-` integrity string, so this list was empty for every npm package there is.
    let f = left_pad(|_| {}, LEFT_PAD_TGZ)
        .await
        .expect("the real bytes");
    assert_eq!(
        results(&f),
        [
            ("sha512", "npm:dist.integrity", CheckResult::Matched),
            ("sha1", "npm:dist.shasum", CheckResult::Matched),
        ]
    );
    assert_eq!(f.note, None, "everything declared was checked");
    // The digests the run keeps are computed over the bytes, and are the real ones.
    assert_eq!(
        f.sha256.to_hex(),
        "870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd"
    );
    assert_eq!(f.sha1.to_hex(), "5b8a3a7765dfe001261dde915589e782f8c94d1e");
    assert_eq!(f.sha512.to_hex(), f.checks[0].declared.value);
    assert_eq!(f.bytes, 3619);
}

#[tokio::test]
async fn an_npm_download_whose_bytes_do_not_match_its_integrity_is_refused() {
    // One byte of the real tarball, changed. What a registry mirror serving something else, or a
    // proxy in between, would look like from here.
    let mut tampered = LEFT_PAD_TGZ.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let computed = hex(&sha2::Sha512::digest(&tampered));

    let e = left_pad(|_| {}, &tampered)
        .await
        .expect_err("bytes npm does not vouch for");
    let RegistryError::DigestMismatch(mismatch) = &e else {
        panic!("not a digest mismatch: {e}");
    };
    let DigestMismatch {
        algorithm,
        field,
        declared,
        computed: got,
        ..
    } = &**mismatch;
    assert_eq!(algorithm, "sha512");
    assert_eq!(field, "npm:dist.integrity");
    assert_eq!(got, &computed);
    // The message names the algorithm and both values, which is what lets a reader tell a
    // registry serving other bytes from metadata declaring the wrong digest.
    let msg = e.to_string();
    for part in [
        "sha512",
        declared.as_str(),
        computed.as_str(),
        "proves nothing",
    ] {
        assert!(msg.contains(part), "`{part}` missing from: {msg}");
    }
    assert_eq!(e.fault(), Fault::Upstream);
    assert!(!e.is_retryable(), "retrying cannot fix a mismatch");
}

#[tokio::test]
async fn an_npm_shasum_is_checked_on_its_own_when_there_is_no_integrity() {
    // An entry old enough to have no `integrity` still has a `shasum`, and it is still a claim.
    let mut tampered = LEFT_PAD_TGZ.to_vec();
    tampered[0] ^= 0x01;
    let drop_integrity = |d: &mut serde_json::Value| {
        d["dist"].as_object_mut().unwrap().remove("integrity");
    };
    let e = left_pad(drop_integrity, &tampered).await.unwrap_err();
    assert!(
        matches!(&e, RegistryError::DigestMismatch(m) if m.algorithm == "sha1"),
        "{e}"
    );

    let f = left_pad(drop_integrity, LEFT_PAD_TGZ).await.unwrap();
    assert_eq!(
        results(&f),
        [("sha1", "npm:dist.shasum", CheckResult::Matched)]
    );
}

#[tokio::test]
async fn an_npm_entry_that_declares_nothing_is_recorded_as_absence_not_as_a_check() {
    let f = left_pad(
        |d| {
            let dist = d["dist"].as_object_mut().unwrap();
            dist.remove("integrity");
            dist.remove("shasum");
        },
        LEFT_PAD_TGZ,
    )
    .await
    .expect("nothing declared is nothing to refuse");
    assert!(f.checks.is_empty(), "{:?}", f.checks);
    let note = f.note.expect("absence says why");
    assert!(
        note.contains("dist.integrity") && note.contains("dist.shasum"),
        "{note}"
    );
}

#[tokio::test]
async fn every_algorithm_in_an_npm_integrity_string_is_checked_sha384_included() {
    // SRI allows several tokens of different algorithms in one string, and each is a claim. The
    // sha384 is hashed only when something declares one, so this is the path that proves it is.
    let sha512 = base64(&sha2::Sha512::digest(LEFT_PAD_TGZ));
    let sha384 = base64(&sha2::Sha384::digest(LEFT_PAD_TGZ));
    let both = format!("sha512-{sha512} sha384-{sha384}");
    let f = left_pad(|d| d["dist"]["integrity"] = both.into(), LEFT_PAD_TGZ)
        .await
        .expect("the real bytes");
    assert_eq!(
        results(&f),
        [
            ("sha512", "npm:dist.integrity", CheckResult::Matched),
            ("sha384", "npm:dist.integrity", CheckResult::Matched),
            ("sha1", "npm:dist.shasum", CheckResult::Matched),
        ]
    );

    // A sha384 that disagrees refuses the download, though the sha512 beside it agrees.
    let wrong = format!("sha512-{sha512} sha384-{}", base64(&[0u8; 48]));
    let e = left_pad(|d| d["dist"]["integrity"] = wrong.into(), LEFT_PAD_TGZ)
        .await
        .unwrap_err();
    assert!(
        matches!(&e, RegistryError::DigestMismatch(m)
            if m.algorithm == "sha384" && m.computed == hex(&sha2::Sha384::digest(LEFT_PAD_TGZ))),
        "{e}"
    );
}

#[tokio::test]
async fn a_malformed_npm_integrity_string_refuses_the_resolve_rather_than_checking_nothing() {
    let e = left_pad(
        |d| d["dist"]["integrity"] = "sha512-notbase64!".into(),
        LEFT_PAD_TGZ,
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RegistryError::Malformed { .. }), "{e}");
    assert!(e.to_string().contains("dist.integrity"), "{e}");
}

/// A PyPI release with one file, declaring what `digests` says.
async fn pypi(digests: serde_json::Value, bytes: &[u8]) -> Result<Fetched, RegistryError> {
    let server = Loopback::bind();
    let file = "widget-1.0.0-py3-none-any.whl";
    let doc = serde_json::json!({
        "info": { "project_urls": { "Source": "https://github.com/example/widget" } },
        "urls": [{
            "filename": file,
            "url": format!("{}/files/{file}", server.base),
            "digests": digests,
            "size": bytes.len(),
            "upload_time_iso_8601": "2026-01-01T00:00:00Z",
        }],
    });
    let routes = BTreeMap::from([
        (
            "/pypi/widget/1.0.0/json".to_string(),
            serde_json::to_vec(&doc).unwrap(),
        ),
        (format!("/files/{file}"), bytes.to_vec()),
    ]);
    let base = server.serve(routes);
    let reg = PyPiRegistry::new(client()).with_base(base);
    let resolved = reg.resolve(&target("pkg:pypi/widget@1.0.0")).await?;
    let mut sink = Vec::new();
    reg.fetch(resolved.sole_artifact().unwrap(), &mut sink)
        .await
}

#[tokio::test]
async fn pypi_md5_is_checked_beside_sha256_and_blake2b_is_recorded_unchecked() {
    let bytes = b"PK\x03\x04 a wheel";
    let digests = serde_json::json!({
        "sha256": hex(&sha2::Sha256::digest(bytes)),
        "md5": hex(&md5::Md5::digest(bytes)),
        // This build has no blake2b. Recorded as declared and not checked, never as absent.
        "blake2b_256": "ab".repeat(32),
    });
    let f = pypi(digests, bytes).await.expect("matches");
    assert_eq!(
        results(&f),
        [
            (
                "blake2b_256",
                "pypi:digests.blake2b_256",
                CheckResult::Unchecked
            ),
            ("md5", "pypi:digests.md5", CheckResult::Matched),
            ("sha256", "pypi:digests.sha256", CheckResult::Matched),
        ]
    );
    assert!(
        f.note
            .expect("says what was not checked")
            .contains("blake2b_256")
    );
}

#[tokio::test]
async fn a_pypi_md5_that_disagrees_refuses_the_download_even_when_sha256_agrees() {
    // Every declaration has to hold. A sha256 that agrees does not excuse an md5 that does not:
    // the two cannot both be about these bytes.
    let bytes = b"PK\x03\x04 a wheel";
    let digests = serde_json::json!({
        "sha256": hex(&sha2::Sha256::digest(bytes)),
        "md5": "00".repeat(16),
    });
    let e = pypi(digests, bytes).await.unwrap_err();
    assert!(
        matches!(&e, RegistryError::DigestMismatch(m)
            if m.algorithm == "md5" && m.field == "pypi:digests.md5"),
        "{e}"
    );
}

#[tokio::test]
async fn a_crate_is_checked_against_its_checksum() {
    let bytes = b"\x1f\x8b a crate";
    let server = Loopback::bind();
    let doc = serde_json::json!({
        "version": {
            "num": "1.0.0",
            "dl_path": "/api/v1/crates/widget/1.0.0/download",
            "checksum": hex(&sha2::Sha256::digest(bytes)),
            "created_at": "2026-01-01T00:00:00Z",
        },
    });
    let routes = BTreeMap::from([
        (
            "/api/v1/crates/widget/1.0.0".to_string(),
            serde_json::to_vec(&doc).unwrap(),
        ),
        (
            "/api/v1/crates/widget/1.0.0/download".to_string(),
            bytes.to_vec(),
        ),
    ]);
    let base = server.serve(routes);
    let reg = CratesIoRegistry::new(client()).with_base(base);
    let resolved = reg
        .resolve(&target("pkg:cargo/widget@1.0.0"))
        .await
        .unwrap();
    let mut sink = Vec::new();
    let f = reg
        .fetch(resolved.sole_artifact().unwrap(), &mut sink)
        .await
        .unwrap();
    assert_eq!(
        results(&f),
        [("sha256", "cargo:checksum", CheckResult::Matched)]
    );
}

const NUGET_REGISTRATION: &str = "/v3/registration5-gz-semver2/widget/index.json";
const NUGET_PAGE: &str = "/v3/registration5-gz-semver2/widget/page/1.0.0/1.0.0.json";
const NUGET_LEAF: &str = "/v3/catalog0/data/2026.01.01.00.00.00/widget.1.0.0.json";

/// How the NuGet catalog on loopback is laid out, and which of its documents fail.
struct Catalog {
    /// The version the registration lists. `1.0.0` is the one resolved.
    listed: &'static str,
    /// Whether the registration's items are behind a page reference, as nuget.org's are for a
    /// package with enough releases, rather than inline.
    paged: bool,
    /// Paths that answer this status instead of their document.
    failing: Vec<(&'static str, u16)>,
}

impl Default for Catalog {
    fn default() -> Self {
        Catalog {
            listed: "1.0.0",
            paged: false,
            failing: Vec::new(),
        }
    }
}

/// A NuGet package whose catalog leaf is `leaf`, served with `bytes`.
async fn nuget(
    leaf: impl FnOnce(&str) -> serde_json::Value,
    bytes: &[u8],
) -> Result<Fetched, RegistryError> {
    nuget_with(Catalog::default(), leaf, bytes).await
}

async fn nuget_with(
    catalog: Catalog,
    leaf: impl FnOnce(&str) -> serde_json::Value,
    bytes: &[u8],
) -> Result<Fetched, RegistryError> {
    let server = Loopback::bind();
    let leaf_url = format!("{}{NUGET_LEAF}", server.base);
    // The registration's `catalogEntry` carries no hash, as nuget.org's does not: it names the
    // leaf that does.
    let page = serde_json::json!({
        "items": [{
            "catalogEntry": {
                "@id": leaf_url,
                "id": "Widget",
                "version": catalog.listed,
                "published": "2026-01-01T00:00:00Z",
            },
        }],
    });
    let registration = match catalog.paged {
        true => serde_json::json!({ "items": [{ "@id": format!("{}{NUGET_PAGE}", server.base) }] }),
        false => serde_json::json!({ "items": [page.clone()] }),
    };
    let routes = BTreeMap::from([
        (
            "/v3-flatcontainer/widget/index.json".to_string(),
            br#"{"versions":["1.0.0"]}"#.to_vec(),
        ),
        (
            NUGET_REGISTRATION.to_string(),
            serde_json::to_vec(&registration).unwrap(),
        ),
        (NUGET_PAGE.to_string(), serde_json::to_vec(&page).unwrap()),
        (
            NUGET_LEAF.to_string(),
            serde_json::to_vec(&leaf(&leaf_url)).unwrap(),
        ),
        (
            "/v3-flatcontainer/widget/1.0.0/widget.1.0.0.nupkg".to_string(),
            bytes.to_vec(),
        ),
    ]);
    let failing = catalog
        .failing
        .iter()
        .map(|(path, status)| (path.to_string(), *status))
        .collect();
    let base = server.serve_failing(routes, failing);
    // No retries: a 5xx here is the answer under test, and waiting out three backoffs for it
    // would only slow the test down.
    let client = Client::new(ClientConfig {
        max_retries: 0,
        ..ClientConfig::default()
    })
    .unwrap();
    let reg = NuGetRegistry::new(client).with_base(base);
    let resolved = reg.resolve(&target("pkg:nuget/Widget@1.0.0")).await?;
    let mut sink = Vec::new();
    reg.fetch(resolved.sole_artifact().unwrap(), &mut sink)
        .await
}

fn base64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A catalog leaf declaring `hash` as the package's sha512, as nuget.org writes one.
fn leaf_declaring(hash: String) -> impl FnOnce(&str) -> serde_json::Value {
    move |id| {
        serde_json::json!({
            "@id": id,
            "packageHash": hash,
            "packageHashAlgorithm": "SHA512",
        })
    }
}

#[tokio::test]
async fn a_nupkg_is_checked_against_the_package_hash_its_catalog_leaf_carries() {
    let bytes = b"PK\x03\x04 a nupkg";
    let hash = base64(&sha2::Sha512::digest(bytes));
    let f = nuget(leaf_declaring(hash.clone()), bytes)
        .await
        .expect("matches");
    assert_eq!(
        results(&f),
        [("sha512", "nuget:catalog.packageHash", CheckResult::Matched)]
    );
    assert_eq!(f.checks[0].declared.value, f.sha512.to_hex());

    // And a package the catalog vouches for differently is refused.
    let e = nuget(leaf_declaring(hash), b"PK\x03\x04 another nupkg")
        .await
        .unwrap_err();
    assert!(
        matches!(&e, RegistryError::DigestMismatch(m) if m.algorithm == "sha512"),
        "{e}"
    );
}

#[tokio::test]
async fn a_catalog_leaf_with_no_package_hash_is_recorded_as_absence_with_its_reason() {
    let f = nuget(|id| serde_json::json!({ "@id": id }), b"PK a nupkg")
        .await
        .expect("nothing declared is nothing to refuse");
    assert!(f.checks.is_empty());
    let note = f.note.expect("absence says why");
    assert!(note.contains("packageHash"), "{note}");
}

#[tokio::test]
async fn a_nuget_catalog_that_cannot_be_read_refuses_the_resolve_rather_than_recording_absence() {
    // The catalog normally carries a `packageHash`, and it was not read. Recording that as "the
    // registry declared nothing" would let bytes through unchecked and say the registry had not
    // vouched for them, when nobody asked. So none of these gets as far as the download, and a
    // tampered package is never accepted for want of a catalog.
    let bytes = b"PK\x03\x04 a nupkg";
    let hash = base64(&sha2::Sha512::digest(bytes));
    for (path, status, paged) in [
        (NUGET_REGISTRATION, 503, false),
        (NUGET_REGISTRATION, 429, false),
        (NUGET_REGISTRATION, 500, false),
        (NUGET_PAGE, 503, true),
        (NUGET_LEAF, 503, false),
        (NUGET_LEAF, 404, false),
    ] {
        let catalog = Catalog {
            paged,
            failing: vec![(path, status)],
            ..Catalog::default()
        };
        let e = nuget_with(
            catalog,
            leaf_declaring(hash.clone()),
            b"PK\x03\x04 tampered",
        )
        .await
        .expect_err("a catalog nobody read vouched for nothing");
        let msg = e.to_string();
        assert!(
            matches!(e, RegistryError::CatalogUnreadable { .. }),
            "{path} {status}: {msg}"
        );
        assert!(
            !msg.contains("no catalog entry"),
            "{path} {status} was recorded as a fact about the registry: {msg}"
        );
        assert!(msg.contains("packageHash"), "{msg}");
        // Busy is retried; a document that is gone is not.
        assert_eq!(e.is_retryable(), status != 404, "{path} {status}: {msg}");
        assert_eq!(e.fault(), Fault::Upstream);
    }
}

#[tokio::test]
async fn a_paged_registration_is_followed_to_the_leaf_and_checked() {
    let bytes = b"PK\x03\x04 a nupkg";
    let hash = base64(&sha2::Sha512::digest(bytes));
    let catalog = Catalog {
        paged: true,
        ..Catalog::default()
    };
    let f = nuget_with(catalog, leaf_declaring(hash), bytes)
        .await
        .expect("matches");
    assert_eq!(
        results(&f),
        [("sha512", "nuget:catalog.packageHash", CheckResult::Matched)]
    );
}

#[tokio::test]
async fn a_registration_that_was_read_and_does_not_list_the_version_is_recorded_as_absence() {
    // The one case where "no catalog entry" is true: the index answered, and the version is not in
    // it. What the run records then is a fact about the registry, and says so.
    let catalog = Catalog {
        listed: "0.9.0",
        ..Catalog::default()
    };
    let f = nuget_with(
        catalog,
        |id| serde_json::json!({ "@id": id }),
        b"PK a nupkg",
    )
    .await
    .expect("nothing declared is nothing to refuse");
    assert!(f.checks.is_empty());
    let note = f.note.expect("absence says why");
    assert!(note.contains("no catalog entry"), "{note}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
