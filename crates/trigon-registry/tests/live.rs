//! Against the real registries.
//!
//! Skipped unless `TRIGON_LIVE=1`, so the ordinary suite stays offline and deterministic. These
//! are the tests that catch a registry changing its metadata shape under us, which is the failure
//! a mocked test cannot see.

use std::str::FromStr;

use trigon_core::{Ecosystem, SourceDiscovery, TargetRef};
use trigon_registry::{Client, ClientConfig, RegistryError, for_ecosystem};

fn live() -> bool {
    let on = std::env::var("TRIGON_LIVE").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set TRIGON_LIVE=1 to talk to real registries");
    }
    on
}

fn client() -> Client {
    Client::new(ClientConfig::default()).unwrap()
}

#[tokio::test]
async fn npm_resolves_left_pad_with_the_commit_it_was_published_from() {
    if !live() {
        return;
    }
    let r = for_ecosystem(Ecosystem::Npm, client()).unwrap();
    let t = TargetRef::from_str("pkg:npm/left-pad@1.3.0").unwrap();
    let resolved = r.resolve(&t).await.expect("resolves");

    let a = resolved
        .sole_artifact()
        .expect("npm publishes one tarball per version");
    assert_eq!(a.id.as_str(), "left-pad-1.3.0.tgz");
    assert!(a.url.ends_with("left-pad-1.3.0.tgz"), "{}", a.url);

    // The rung that makes npm source discovery a lookup rather than a search.
    let src = resolved.source.expect("npm records gitHead");
    assert_eq!(src.how, SourceDiscovery::RegistryCommit);
    assert_eq!(src.repo_url, "https://github.com/stevemao/left-pad");
    assert_eq!(
        src.commit.len(),
        40,
        "a resolved commit, not a ref: {}",
        src.commit
    );

    assert!(
        resolved.intrinsics.publish_time.is_some(),
        "needed to pin the registry moment"
    );
}

#[tokio::test]
async fn npm_fetches_and_the_digest_is_computed_not_taken_on_trust() {
    if !live() {
        return;
    }
    let r = for_ecosystem(Ecosystem::Npm, client()).unwrap();
    let t = TargetRef::from_str("pkg:npm/left-pad@1.3.0").unwrap();
    let resolved = r.resolve(&t).await.unwrap();
    let meta = resolved.sole_artifact().unwrap();

    let mut bytes: Vec<u8> = Vec::new();
    let digest = r.fetch(meta, &mut bytes).await.expect("fetches");

    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "a gzip member");

    // The returned digest is of what we received, not what we were told. That is the property the
    // run key and the attestation rest on, and it holds whatever the registry serves.
    use sha2::Digest as _;
    let recomputed = sha2::Sha256::digest(&bytes);
    assert_eq!(digest.as_bytes()[..], recomputed[..]);

    // And a canary. npm's registry is append-only by policy, so this moving means either the
    // policy was broken or we are talking to something that is not npm. Either is worth a failing
    // test rather than a silently different verdict.
    assert_eq!(bytes.len(), 3619);
    assert_eq!(
        digest.to_hex(),
        "870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd"
    );
}

#[tokio::test]
async fn a_scoped_package_resolves() {
    if !live() {
        return;
    }
    // The case a naive PURL parse gets wrong: asking npm for `core` finds a different package.
    let r = for_ecosystem(Ecosystem::Npm, client()).unwrap();
    let t = TargetRef::from_str("pkg:npm/@babel/core@7.24.0").unwrap();
    let resolved = r.resolve(&t).await.expect("scoped names resolve");
    assert!(
        resolved
            .sole_artifact()
            .unwrap()
            .url
            .contains("@babel/core"),
        "{}",
        resolved.sole_artifact().unwrap().url
    );
}

#[tokio::test]
async fn pypi_resolves_every_artifact_of_a_release() {
    if !live() {
        return;
    }
    let r = for_ecosystem(Ecosystem::PyPI, client()).unwrap();
    let t = TargetRef::from_str("pkg:pypi/sniffio@1.3.1").unwrap();
    let resolved = r.resolve(&t).await.expect("resolves");

    // A release is several files, and they do not reproduce alike.
    assert!(resolved.artifacts.len() >= 2, "{:?}", resolved.artifacts);
    assert!(
        resolved.sole_artifact().is_none(),
        "so there is no sole artifact to pick"
    );

    let whl = resolved
        .artifact("sniffio-1.3.1-py3-none-any.whl")
        .expect("the wheel");
    // PyPI publishes sha256 for every file, so there is always something to check against.
    assert!(whl.declared_sha256.is_some());
    assert_eq!(
        whl.declared_sha256.unwrap().to_hex(),
        "2f6da418d1f1e0fddd844478f41680e794e6051915791a034ff65e5f100525a2"
    );

    let src = resolved.source.expect("sniffio declares a repository");
    assert_eq!(src.repo_url, "https://github.com/python-trio/sniffio");
    // One rung lower than npm: a repository, and still no commit.
    assert_eq!(src.how, SourceDiscovery::RegistryMetadata);
    assert!(src.commit.is_empty());
}

#[tokio::test]
async fn pypi_verifies_the_declared_digest() {
    if !live() {
        return;
    }
    let r = for_ecosystem(Ecosystem::PyPI, client()).unwrap();
    let t = TargetRef::from_str("pkg:pypi/sniffio@1.3.1").unwrap();
    let resolved = r.resolve(&t).await.unwrap();
    let meta = resolved.artifact("sniffio-1.3.1-py3-none-any.whl").unwrap();

    let mut bytes: Vec<u8> = Vec::new();
    let digest = r
        .fetch(meta, &mut bytes)
        .await
        .expect("fetches and verifies");
    assert_eq!(&digest, meta.declared_sha256.as_ref().unwrap());
    assert_eq!(&bytes[..2], b"PK");
}

#[tokio::test]
async fn a_tampered_digest_is_refused() {
    if !live() {
        return;
    }
    // The check exists so a run cannot silently proceed against bytes the registry does not vouch
    // for. Simulated by claiming a digest the real bytes will not have.
    let r = for_ecosystem(Ecosystem::PyPI, client()).unwrap();
    let t = TargetRef::from_str("pkg:pypi/sniffio@1.3.1").unwrap();
    let resolved = r.resolve(&t).await.unwrap();
    let mut meta = resolved
        .artifact("sniffio-1.3.1-py3-none-any.whl")
        .unwrap()
        .clone();
    meta.declared_sha256 = Some(trigon_core::Digest::from_bytes([0xab; 32]));

    let mut bytes: Vec<u8> = Vec::new();
    let err = r.fetch(&meta, &mut bytes).await.expect_err("must refuse");
    let msg = err.to_string();
    assert!(msg.contains("proves nothing"), "{msg}");
    assert!(
        !trigon_core::Classify::is_retryable(&err),
        "retrying cannot fix a mismatch"
    );
}

#[tokio::test]
async fn a_missing_version_lists_what_exists() {
    if !live() {
        return;
    }
    let r = for_ecosystem(Ecosystem::Npm, client()).unwrap();
    let t = TargetRef::from_str("pkg:npm/left-pad@99.0.0").unwrap();
    let err = r.resolve(&t).await.expect_err("no such version");
    assert!(matches!(err, RegistryError::NoSuchVersion { .. }), "{err}");
    assert!(err.to_string().contains("Recent:"), "{err}");
    assert!(!trigon_core::Classify::is_retryable(&err));
}

#[tokio::test]
async fn an_unsupported_ecosystem_says_what_is_supported() {
    // RubyGems rather than NuGet, because NuGet gained a client. The test is about the *shape* of
    // the refusal — the ecosystem named, the alternatives named — rather than about which of the
    // eight we currently speak, so it follows the frontier instead of pinning it.
    let e = match for_ecosystem(Ecosystem::RubyGems, client()) {
        Err(e) => e,
        Ok(_) => panic!("gem has no client in this build"),
    };
    assert!(e.to_string().contains("does not speak gem"), "{e}");
    assert!(e.to_string().contains("npm, pypi, cargo, nuget"), "{e}");
}

#[tokio::test]
async fn every_ecosystem_with_a_client_produces_one() {
    // The counterpart, and what the test above used to cover by accident: a factory arm that is
    // written but not reachable reads exactly like one that was never written. Named individually
    // so a missing arm says which.
    for e in [
        Ecosystem::Npm,
        Ecosystem::PyPI,
        Ecosystem::CratesIo,
        Ecosystem::NuGet,
    ] {
        let r = for_ecosystem(e, client()).unwrap_or_else(|err| panic!("{e}: {err}"));
        assert_eq!(
            r.ecosystem(),
            e,
            "the client answers for a different ecosystem"
        );
    }
}
