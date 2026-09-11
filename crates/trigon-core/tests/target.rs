//! Parsing package URLs, and the one case everything gets wrong.

use std::str::FromStr;

use trigon_core::{ArtifactId, ArtifactKind, Ecosystem, PurlError, TargetRef};

#[test]
fn a_plain_coordinate_round_trips() {
    let t = TargetRef::from_str("pkg:npm/left-pad@1.3.0").unwrap();
    assert_eq!(t.ecosystem, Ecosystem::Npm);
    assert_eq!(t.namespace, None);
    assert_eq!(t.name, "left-pad");
    assert_eq!(t.version, "1.3.0");
    assert_eq!(t.to_string(), "pkg:npm/left-pad@1.3.0");
}

#[test]
fn a_scoped_npm_package_rejoins_for_the_registry() {
    // The case that matters. A PURL splits `@babel/core` into namespace and name, and asking npm
    // for `core` finds a different package that exists and is unrelated.
    let t = TargetRef::from_str("pkg:npm/@babel/core@7.24.0").unwrap();
    assert_eq!(t.namespace.as_deref(), Some("@babel"));
    assert_eq!(t.name, "core");
    assert_eq!(t.registry_name(), "@babel/core");
}

#[test]
fn maven_joins_its_namespace_with_a_colon() {
    let t = TargetRef::from_str("pkg:maven/org.apache.commons/commons-lang3@3.14.0").unwrap();
    assert_eq!(t.registry_name(), "org.apache.commons:commons-lang3");
}

#[test]
fn a_missing_version_is_refused_with_the_reason() {
    // A run is about one version. Defaulting to "latest" would produce a verdict that stops being
    // true without anything changing on our side.
    let e = TargetRef::from_str("pkg:npm/left-pad").unwrap_err();
    assert!(matches!(e, PurlError::NoVersion(_)));
    assert!(e.to_string().contains("nothing to compare"), "{e}");
}

#[test]
fn an_unknown_ecosystem_lists_the_known_ones() {
    let e = TargetRef::from_str("pkg:cpan/Some-Module@1.0").unwrap_err();
    assert!(e.to_string().contains("cpan"), "{e}");
    assert!(e.to_string().contains("npm, pypi"), "{e}");
}

#[test]
fn something_that_is_not_a_purl_says_so() {
    let e = TargetRef::from_str("left-pad@1.3.0").unwrap_err();
    assert!(matches!(e, PurlError::NotAPurl(_)));
}

#[test]
fn qualifiers_parse_and_sort() {
    let t = TargetRef::from_str("pkg:pypi/cryptography@42.0.5?arch=x86_64&abi=cp39").unwrap();
    assert_eq!(t.qualifiers.get("arch").map(String::as_str), Some("x86_64"));
    // BTreeMap, so the rendering is stable whatever order they arrived in.
    assert_eq!(
        t.to_string(),
        "pkg:pypi/cryptography@42.0.5?abi=cp39&arch=x86_64"
    );
}

#[test]
fn the_version_is_taken_after_the_last_at_sign() {
    // Which is what makes a scoped npm name work: splitting on the *first* `@` would make
    // `pkg:npm/@babel/core@7.24.0` a package called `babel/core@7.24.0`.
    let t = TargetRef::from_str("pkg:npm/@babel/core@7.24.0").unwrap();
    assert_eq!(t.version, "7.24.0");

    // The cost is that an unencoded `@` inside a version mis-splits. The spec requires it
    // percent-encoded, so this is a limit of the stated subset rather than a case to guess at, and
    // guessing would break the scoped names that actually occur.
    let t = TargetRef::from_str("pkg:npm/thing@1.0.0+build@2").unwrap();
    assert_eq!(t.name, "thing@1.0.0+build");
    assert_eq!(t.version, "2");
}

#[test]
fn the_artifact_kind_comes_from_the_filename() {
    for (name, kind) in [
        ("left-pad-1.3.0.tgz", ArtifactKind::Tarball),
        ("sniffio-1.3.1-py3-none-any.whl", ArtifactKind::Wheel),
        ("sniffio-1.3.1.tar.gz", ArtifactKind::Sdist),
        ("serde-1.0.0.crate", ArtifactKind::Crate),
        ("rake-13.2.1.gem", ArtifactKind::Gem),
        ("Newtonsoft.Json.13.0.3.nupkg", ArtifactKind::Nupkg),
        ("README", ArtifactKind::Other),
    ] {
        assert_eq!(ArtifactId::new(name).kind(), kind, "{name}");
    }
}

#[test]
fn github_is_an_ordinary_target() {
    // The type system gives it no special case: its artifact is a release asset like any other.
    let t = TargetRef::from_str("pkg:github/stevemao/left-pad@v1.3.0").unwrap();
    assert_eq!(t.ecosystem, Ecosystem::GitHub);
    assert_eq!(t.registry_name(), "stevemao/left-pad");
}
