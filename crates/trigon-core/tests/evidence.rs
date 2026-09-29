//! Intersecting evidence, and the two outcomes that mean "ask a model".

use trigon_core::{Claim, Confidence, Evidence, ToolchainResolution, resolve_toolchain};

fn range(lo: Option<&str>, hi: Option<&str>, source: &str) -> Evidence {
    Evidence::new(
        Claim::ToolchainRange {
            tool: "cargo".into(),
            lo: lo.map(str::to_owned),
            hi: hi.map(str::to_owned),
        },
        Confidence::Strong,
        source,
    )
}

fn exact(v: &str, source: &str) -> Evidence {
    Evidence::new(
        Claim::ToolchainExact {
            tool: "cargo".into(),
            version: v.into(),
        },
        Confidence::Certain,
        source,
    )
}

#[test]
fn independent_ranges_intersect_to_the_tightest() {
    // This is the prior art's clamping sequence, written as what it actually is. Each constraint
    // came from somewhere different and none of them knows about the others.
    let r = resolve_toolchain(
        "cargo",
        &[
            range(Some("1.55"), None, "cargo-manifest:header-comment"),
            range(Some("1.60"), None, "cargo-manifest:pretty-arrays"),
            range(None, Some("1.71"), "cargo-manifest:debug-denormalized"),
        ],
    );
    assert_eq!(
        r,
        ToolchainResolution::Window {
            lo: Some("1.60".into()),
            hi: Some("1.71".into())
        }
    );
    assert!(!r.needs_help());
}

#[test]
fn no_evidence_is_a_signal_rather_than_a_default() {
    // The alternative is picking "whatever was current" and reporting a divergence when it was
    // wrong. Unconstrained says so, and that is what escalates.
    let r = resolve_toolchain("cargo", &[]);
    assert_eq!(r, ToolchainResolution::Unconstrained);
    assert!(r.needs_help());
}

#[test]
fn evidence_about_another_tool_is_ignored() {
    let r = resolve_toolchain("cargo", &[exact("3.11", "python")]);
    let other = resolve_toolchain(
        "cargo",
        &[Evidence::new(
            Claim::ToolchainExact {
                tool: "rustc".into(),
                version: "1.70".into(),
            },
            Confidence::Certain,
            "rust-toolchain.toml",
        )],
    );
    assert_eq!(other, ToolchainResolution::Unconstrained);
    let _ = r;
}

#[test]
fn contradictory_ranges_name_both_sides() {
    // Empty intersection. One of these constraints is wrong, and guessing which produces a build
    // that fails for a reason nobody can trace back here.
    let r = resolve_toolchain(
        "cargo",
        &[
            range(Some("1.75"), None, "declared-msrv"),
            range(None, Some("1.71"), "cargo-manifest:debug-denormalized"),
        ],
    );
    let ToolchainResolution::Contradiction { conflicting } = &r else {
        panic!("expected a contradiction, got {r:?}")
    };
    assert_eq!(conflicting.len(), 2);
    assert!(conflicting.iter().any(|e| e.source == "declared-msrv"));
    assert!(r.needs_help());
}

#[test]
fn an_exact_version_outside_a_range_is_a_contradiction() {
    let r = resolve_toolchain(
        "cargo",
        &[
            exact("1.50", "rust-toolchain.toml"),
            range(Some("1.60"), None, "cargo-manifest:pretty-arrays"),
        ],
    );
    assert!(
        matches!(r, ToolchainResolution::Contradiction { .. }),
        "{r:?}"
    );
}

#[test]
fn an_exact_version_inside_every_range_pins_it() {
    let r = resolve_toolchain(
        "cargo",
        &[
            exact("1.65", "rust-toolchain.toml"),
            range(Some("1.60"), None, "cargo-manifest:pretty-arrays"),
            range(None, Some("1.71"), "cargo-manifest:debug-denormalized"),
        ],
    );
    assert_eq!(
        r,
        ToolchainResolution::Pinned {
            version: "1.65".into()
        }
    );
}

#[test]
fn two_different_exact_versions_contradict() {
    let r = resolve_toolchain("cargo", &[exact("1.65", "a"), exact("1.66", "b")]);
    assert!(
        matches!(r, ToolchainResolution::Contradiction { .. }),
        "{r:?}"
    );
}

#[test]
fn versions_compare_numerically_not_lexically() {
    // "1.10" sorts before "1.9" as text. A toolchain window silently off by a release is worse
    // than one we declined to compute.
    let r = resolve_toolchain(
        "cargo",
        &[
            range(Some("1.9"), None, "a"),
            range(Some("1.10"), None, "b"),
        ],
    );
    assert_eq!(
        r,
        ToolchainResolution::Window {
            lo: Some("1.10".into()),
            hi: None
        }
    );
}

#[test]
fn a_version_we_cannot_parse_is_skipped_rather_than_ordered_wrongly() {
    let r = resolve_toolchain(
        "cargo",
        &[
            range(Some("nightly-2024-01-01"), None, "unparseable"),
            range(Some("1.60"), None, "cargo-manifest:pretty-arrays"),
        ],
    );
    assert_eq!(
        r,
        ToolchainResolution::Window {
            lo: Some("1.60".into()),
            hi: None
        }
    );
}

#[test]
fn prerelease_and_build_metadata_do_not_break_the_comparison() {
    let r = resolve_toolchain(
        "cargo",
        &[range(Some("1.60.0-beta.1"), Some("1.71.0+nightly"), "a")],
    );
    assert_eq!(
        r,
        ToolchainResolution::Window {
            lo: Some("1.60.0".into()),
            hi: Some("1.71.0".into())
        }
    );
}

#[test]
fn a_match_outcome_reads_back_as_itself() {
    use std::str::FromStr;
    use trigon_core::Match;
    // Anything that writes a verdict to a file and reads it back depends on this. Restating the
    // strings at a call site is how they drift, and the drift is silent: a sweep's resume path
    // spelled one of them with hyphens and dropped every caveated match from its own rate.
    for m in [
        Match::Exact,
        Match::Normalized,
        Match::NormalizedWithCaveats,
        Match::Divergent,
    ] {
        assert_eq!(Match::from_str(&m.to_string()), Ok(m), "{m}");
    }
    assert!(
        Match::from_str("normalized-with-caveats").is_err(),
        "hyphens are not the spelling"
    );
}

#[test]
fn an_exact_version_nobody_can_order_is_skipped_rather_than_contradicting() {
    // "nightly" has no place in a dotted numeric order. Ordering it as text would put it somewhere
    // wrong; skipping it leaves the claims that can be compared.
    for evidence in [
        [exact("nightly", "a"), exact("1.65", "b")],
        [exact("1.65", "b"), exact("nightly", "a")],
    ] {
        assert_eq!(
            resolve_toolchain("cargo", &evidence),
            ToolchainResolution::Pinned {
                version: "1.65".into()
            }
        );
    }
    let r = resolve_toolchain("cargo", &[exact("stable", "a")]);
    assert_eq!(r, ToolchainResolution::Unconstrained, "a claim we cannot read is not a pin");
    assert!(r.needs_help());
}

#[test]
fn a_rung_that_names_a_commit_is_exact_and_one_that_names_a_tag_or_a_repository_is_not() {
    use trigon_core::SourceDiscovery as S;
    for s in [S::RegistryCommit, S::PublishedProvenance, S::Definition] {
        assert!(s.is_exact(), "{s:?} identifies a commit on its own");
    }
    // A tag still has to be resolved to a commit, and a declared repository names none.
    for s in [S::RegistryMetadata, S::ExactTag, S::PrefixedTag, S::FuzzyTag] {
        assert!(!s.is_exact(), "{s:?} needs a commit resolved");
    }
}
