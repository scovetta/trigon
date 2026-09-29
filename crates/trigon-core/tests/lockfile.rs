//! Reading a lockfile somebody else wrote.
//!
//! `trigon check` and `POST /v1/check` both report on what this returns, and a package left out of
//! it is reported on by nobody: it does not appear as never checked, it does not appear at all. So
//! the cases here are the ones where the parser decides to skip, refuse or merge — each of which
//! has to be the decision the module documents (`src/lockfile.rs`).

use base64::Engine as _;
use trigon_core::{Kind, LockfileError, Status, parse_lockfile};

fn sri(byte: u8) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 64])
    )
}

// --- package-lock.json ----------------------------------------------------------------------------

#[test]
fn a_package_lock_naming_no_packages_either_way_is_refused_not_read_as_empty() {
    // Zero packages reads as "nothing to worry about", which a malformed file has not earned.
    let e = parse_lockfile(r#"{"lockfileVersion": 3, "name": "demo"}"#, Kind::NpmLock).unwrap_err();
    assert!(matches!(e, LockfileError::Malformed(_)), "{e:?}");
    assert!(
        e.to_string()
            .contains("neither a `packages` nor a `dependencies`"),
        "{e}"
    );

    let e = parse_lockfile("not json", Kind::NpmLock).unwrap_err();
    assert!(
        e.to_string().starts_with("package-lock.json is not JSON"),
        "{e}"
    );
}

#[test]
fn an_install_path_that_names_no_package_is_skipped() {
    let got = parse_lockfile(
        r#"{"lockfileVersion": 3, "packages": {
             "": {"name": "demo"},
             "node_modules/": {"version": "9.9.9"},
             "node_modules/real": {"version": "1.0.0"}}}"#,
        Kind::NpmLock,
    )
    .unwrap();
    let purls: Vec<&str> = got.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(purls, ["pkg:npm/real@1.0.0"]);
}

#[test]
fn a_copy_declaring_no_integrity_merges_into_one_that_declares_it() {
    // v1's recursive tree lists a nested copy of `b` before the top-level one, and only the
    // top-level one carries `integrity`. One artifact, so one package, carrying the digest.
    let text = format!(
        r#"{{"lockfileVersion": 1, "dependencies": {{
             "a": {{"version": "1.0.0", "dependencies": {{"b": {{"version": "2.0.0"}}}}}},
             "b": {{"version": "2.0.0", "integrity": "{}",
                    "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"}}}}}}"#,
        sri(7)
    );
    let got = parse_lockfile(&text, Kind::NpmLock).unwrap();
    let b: Vec<_> = got.iter().filter(|p| p.purl == "pkg:npm/b@2.0.0").collect();
    assert_eq!(b.len(), 1, "{got:?}");
    assert_eq!(b[0].digests.len(), 1, "{:?}", b[0].digests);
    assert_eq!(b[0].digests[0].algorithm, "sha512");
    assert_eq!(b[0].digests[0].value, "07".repeat(64));
    assert_eq!(
        b[0].resolved.as_deref(),
        Some("https://registry.npmjs.org/b/-/b-2.0.0.tgz"),
        "where it resolved survives the merge too"
    );
}

// --- requirements.txt -----------------------------------------------------------------------------

#[test]
fn a_pin_with_no_name_or_no_single_version_is_skipped() {
    let got = parse_lockfile(
        "==1.0\n\
         empty==\n\
         spaced== 1.0 2.0\n\
         good==1.0\n",
        Kind::Requirements,
    );
    let purls: Vec<String> = got.unwrap().into_iter().map(|p| p.purl).collect();
    assert_eq!(purls, ["pkg:pypi/good@1.0"]);
}

#[test]
fn options_other_than_a_hash_are_passed_over_without_taking_the_hash_after_them() {
    let digest = "ab".repeat(32);
    let text = format!("wheel-only==2.0 --no-binary :all: --hash=sha256:{digest} --hashes=x\n");
    let got = parse_lockfile(&text, Kind::Requirements).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].purl, "pkg:pypi/wheel-only@2.0");
    let digests: Vec<(&str, &str)> = got[0]
        .digests
        .iter()
        .map(|d| (d.algorithm.as_str(), d.value.as_str()))
        .collect();
    assert_eq!(digests, [("sha256", digest.as_str())]);
}

// --- SPDX -----------------------------------------------------------------------------------------

#[test]
fn an_sbom_with_no_packages_array_is_refused() {
    let e = parse_lockfile(r#"{"spdxVersion": "SPDX-2.3"}"#, Kind::Spdx).unwrap_err();
    assert!(matches!(e, LockfileError::Malformed(_)), "{e:?}");
    assert!(e.to_string().contains("no `packages` array"), "{e}");

    let e = parse_lockfile("[", Kind::Spdx).unwrap_err();
    assert!(e.to_string().starts_with("the SBOM is not JSON"), "{e}");
}

#[test]
fn a_package_named_by_neither_purl_nor_spdx_id_is_kept_with_no_line() {
    // Kept rather than dropped: it is reported as never checked, which is the truth.
    let got = parse_lockfile(
        r#"{"packages": [{"name": "anonymous", "versionInfo": "0.1"}]}"#,
        Kind::Spdx,
    )
    .unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        (got[0].name.as_str(), got[0].version.as_str()),
        ("anonymous", "0.1")
    );
    assert_eq!(got[0].purl, "");
    assert_eq!(got[0].line, 0, "0 means unknown");
}

// --- how a status is reported ---------------------------------------------------------------------

#[test]
fn every_status_has_its_own_rule_and_a_level_and_never_checked_is_never_absent() {
    let all = [
        Status::Reproduced,
        Status::Caveats,
        Status::Divergent,
        Status::Unsupported,
        Status::NeverChecked,
    ];
    let rules: Vec<&str> = all.iter().map(|s| s.rule_id()).collect();
    assert_eq!(
        rules,
        [
            "trigon/reproduced",
            "trigon/caveats",
            "trigon/divergent",
            "trigon/unsupported",
            "trigon/never-checked",
        ]
    );
    let levels: Vec<&str> = all.iter().map(|s| s.sarif_level()).collect();
    assert_eq!(levels, ["none", "warning", "error", "note", "note"]);
}
