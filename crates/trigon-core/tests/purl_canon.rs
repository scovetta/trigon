//! The canonical purl, held to the shared test vectors.
//!
//! `testdata/purl-canon-v1.json` is the rule's second definition: every writer and reader of the
//! `purl1` and `pkg1` lookup keys reads it, including clients not written in Rust (`docs/19` §5).
//! This test is what keeps the Rust implementation and that file saying the same thing, so a
//! change to either that the other does not follow fails here rather than as a lookup that
//! silently misses.

use trigon_core::purl::{PURL_CANON, PurlCanonError, canonicalize, canonicalize_under};

const VECTORS: &str = include_str!("../testdata/purl-canon-v1.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).expect("the vectors file is JSON")
}

#[test]
fn the_vectors_are_for_this_version_of_the_rule() {
    // A file for another version would pass or fail against the wrong rule and say nothing either
    // way.
    assert_eq!(vectors()["purlCanon"], PURL_CANON);
}

#[test]
fn every_vector_canonicalises_as_the_file_says() {
    let v = vectors();
    let cases = v["vectors"].as_array().expect("a list of vectors");
    assert!(
        cases.len() >= 30,
        "the vectors went missing: {}",
        cases.len()
    );
    let mut failures = Vec::new();
    for case in cases {
        let input = case["input"].as_str().unwrap();
        let want = case["canonical"].as_str().unwrap();
        let package = case["package"].as_str().unwrap();
        match canonicalize(input) {
            Ok(c) if c.as_str() == want && c.package() == package => {
                // A canonical form is a fixed point: canonicalising it again changes nothing.
                // Without this a reader that canonicalises what it was handed, and a writer that
                // canonicalised once, could disagree about the key.
                let again = canonicalize(c.as_str()).expect("a canonical purl canonicalises");
                if again != c {
                    failures.push(format!("{input}: not a fixed point: {c} -> {again}"));
                }
            }
            Ok(c) => failures.push(format!(
                "{input}: got {} / {}, want {want} / {package}",
                c.as_str(),
                c.package()
            )),
            Err(e) => failures.push(format!("{input}: refused: {e}")),
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// A purl signed under rule 1 is in leaves and statements that are never rewritten, so rule 1 is
/// read as its vectors say for good, whatever [`PURL_CANON`] becomes: bumping the rule must add
/// one, and not change this one under every record already signed.
#[test]
fn every_rule_this_build_has_had_is_still_the_rule_it_was() {
    let v = vectors();
    let rule = u32::try_from(v["purlCanon"].as_u64().unwrap()).unwrap();
    assert_eq!(rule, 1, "this file is rule 1's");
    for case in v["vectors"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let c = canonicalize_under(rule, input).unwrap();
        assert_eq!(c.as_str(), case["canonical"].as_str().unwrap(), "{input}");
        assert_eq!(c.package(), case["package"].as_str().unwrap(), "{input}");
    }
    for case in v["invalid"].as_array().unwrap() {
        assert!(canonicalize_under(rule, case["input"].as_str().unwrap()).is_err());
    }
    for known in 1..=PURL_CANON {
        canonicalize_under(known, "pkg:npm/left-pad@1.3.0").unwrap();
    }
    // A rule before the first, or after the newest this build has, is none it can check.
    for unknown in [0, PURL_CANON + 1] {
        assert_eq!(
            canonicalize_under(unknown, "pkg:npm/left-pad@1.3.0"),
            Err(PurlCanonError::UnknownRule(unknown))
        );
    }
}

#[test]
fn every_invalid_input_is_refused() {
    let v = vectors();
    let mut accepted = Vec::new();
    for case in v["invalid"].as_array().expect("a list of invalid inputs") {
        let input = case["input"].as_str().unwrap();
        if let Ok(c) = canonicalize(input) {
            accepted.push(format!("{input:?} became {c} ({})", case["why"]));
        }
    }
    assert!(accepted.is_empty(), "\n{}", accepted.join("\n"));
}

#[test]
fn the_versionless_form_is_the_package_and_nothing_about_one_version() {
    // `pkg1` is "every version of this package". It kept the purl's qualifiers and subpath, so a
    // qualifier that names one version's file — `file_name`, `checksum`, `download_url` — gave
    // each version its own `pkg1` key, and a lookup by package found one version.
    let c = canonicalize("pkg:npm/@babel/core@7.24.0?a=1#x").unwrap();
    assert_eq!(c.as_str(), "pkg:npm/%40babel/core@7.24.0?a=1#x");
    assert_eq!(c.package(), "pkg:npm/%40babel/core");
    assert!(c.has_version());
    assert!(!canonicalize("pkg:npm/left-pad").unwrap().has_version());

    let one = canonicalize("pkg:pypi/requests@2.31.0?file_name=requests-2.31.0.tar.gz").unwrap();
    let two = canonicalize("pkg:pypi/requests@2.32.0?file_name=requests-2.32.0.tar.gz").unwrap();
    assert_eq!(one.package(), two.package(), "two versions, one package");

    // Except the registry, which says which package this is: the same name elsewhere is another.
    let elsewhere =
        canonicalize("pkg:pypi/requests@2.31.0?repository_url=https://pypi.example.org").unwrap();
    assert_eq!(
        elsewhere.package(),
        "pkg:pypi/requests?repository_url=https://pypi.example.org"
    );
    assert_ne!(elsewhere.package(), one.package());
}

#[test]
fn a_refusal_says_what_is_wrong_and_what_to_write() {
    let e = canonicalize("pkg:npm/left pad@1.3.0")
        .unwrap_err()
        .to_string();
    assert!(e.contains("%20"), "{e}");
    let e = canonicalize("pkg:npm/x@1?a=1&A=2").unwrap_err().to_string();
    assert!(e.contains("more than once"), "{e}");
    let e = canonicalize("left-pad@1.3.0").unwrap_err().to_string();
    assert!(e.contains("pkg:"), "{e}");
}

#[test]
fn every_target_trigon_writes_has_a_canonical_form() {
    // A run's target is written by `TargetRef`'s `Display`, and a statement signs its canonical
    // form. One that Trigon can write and not canonicalise would be a run nobody could attest.
    for purl in [
        "pkg:npm/left-pad@1.3.0",
        "pkg:npm/@babel/core@7.24.0",
        "pkg:pypi/requests@2.31.0",
        "pkg:cargo/serde@1.0.203",
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        "pkg:github/stevemao/left-pad@v1.3.0",
    ] {
        let t: trigon_core::TargetRef = purl.parse().unwrap();
        let c = canonicalize(&t.to_string()).unwrap_or_else(|e| panic!("{purl}: {e}"));
        assert!(c.has_version(), "{purl}");
    }
}

#[test]
fn every_canonical_form_is_a_fixed_point_however_its_parts_were_spelt() {
    // The vectors hold the fixed point for what they list; this holds it for every combination of
    // the spellings that decode to something a component treats specially — a dot segment, an
    // empty one, a slash inside a segment, a case the rule folds — which is where a rule applied
    // before decoding and not after makes a canonical form that canonicalises to another key.
    let pieces = [
        "",
        ".",
        "..",
        "%2E",
        "%2e",
        "%2E%2E",
        "%2e.",
        "a",
        "A",
        "%41",
        "a%2F..",
        "%2F",
        "%C4%B0",
        "%E2%84%AA",
        "~",
    ];
    let mut failures = Vec::new();
    for ty in ["npm", "pypi", "github", "golang", "generic"] {
        for a in pieces {
            for b in pieces {
                for input in [
                    format!("pkg:{ty}/{a}{b}x@1"),
                    format!("pkg:{ty}/{a}/{b}/x@1"),
                    format!("pkg:{ty}/x@1?q={a}{b}"),
                    format!("pkg:{ty}/x@1#{a}/{b}"),
                    format!("pkg:{ty}/x@1#{a}{b}/{b}"),
                ] {
                    let Ok(c) = canonicalize(&input) else {
                        continue;
                    };
                    match canonicalize(c.as_str()) {
                        Ok(again) if again == c => {}
                        Ok(again) => failures.push(format!("{input} -> {c} -> {again}")),
                        Err(e) => failures.push(format!("{input} -> {c}, refused: {e}")),
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn a_canonical_purl_displays_as_its_canonical_form() {
    // Written into a message or a statement with `{}`, it is the key a reader looks up, so it
    // prints as nothing else.
    let c = canonicalize("PKG:npm/@Babel/Core@7.24.0?B=2&a=1#./x").unwrap();
    assert_eq!(c.to_string(), "pkg:npm/%40Babel/core@7.24.0?a=1&b=2#x");
    assert_eq!(c.to_string(), c.as_str());
}

#[test]
fn a_malformed_escape_is_named_as_it_was_written_and_no_further() {
    // The message points at the one place to fix: the `%` and the two characters an escape takes,
    // or what there is of them at the end of the component.
    for (input, near) in [
        ("pkg:npm/left%2pad@1.3.0", "%2p"),
        ("pkg:npm/left%zzpad@1.3.0", "%zz"),
        ("pkg:npm/left-pad@1.3.0%", "%"),
        ("pkg:npm/left-pad@1.3.0%2", "%2"),
        ("pkg:npm/left-pad@1.3.0%+f", "%+f"),
    ] {
        assert_eq!(
            canonicalize(input),
            Err(PurlCanonError::BadEscape {
                purl: input.to_string(),
                near: near.to_string(),
            }),
            "{input}"
        );
    }
}
