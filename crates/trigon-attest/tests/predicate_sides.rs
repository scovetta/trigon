//! The signed predicate has to describe both artifacts.
//!
//! `trigon_stabilize::apply` returns only the passes that actually changed something, so the two
//! sides of a comparison routinely differ: a wheel whose `RECORD` needed regenerating on the
//! rebuild and not upstream produces a `wheel-record` entry on one side only, and that pass is
//! `RiskTier::Content`.
//!
//! `equivalence_predicate` used to read `c.upstream.applied` for the `applied` array, for
//! `allBuiltin` and for `maxRiskApplied`, while `compare()` correctly capped the outcome on both
//! sides. A statement could therefore say `allBuiltin: true` and `maxRiskApplied: metadata` beside
//! an outcome of `normalized_with_caveats`, with nothing in `applied` to account for the caveat —
//! and a consumer following `docs/threat-model.md` §1.13 item 4, "read the `applied` list and
//! discard the result if you reject a normalization", could not see the one that caused it.

use trigon_compare::{Comparison, Summary};
use trigon_core::{Digest, Format, MultiDigest, ProfileId, Provenance, RiskTier, StabilizerId};
use trigon_stabilize::Applied;

fn digest(b: u8) -> Digest {
    Digest::from_bytes([b; 32])
}

fn side(applied: Vec<Applied>, stabilized: u8) -> Summary {
    Summary {
        format: Format::Zip,
        bytes: 1024,
        raw: MultiDigest::sha256_only(digest(0xAA)),
        container: None,
        stabilized: MultiDigest::sha256_only(digest(stabilized)),
        applied,
        notes: Vec::new(),
        set: (ProfileId::new("wheel"), digest(0x5E)),
    }
}

fn pass(id: &str, risk: RiskTier, provenance: Provenance) -> Applied {
    Applied {
        id: StabilizerId::new(id),
        risk,
        provenance,
        entries_touched: 1,
        bytes_changed: 64,
    }
}

/// The rebuild side carries the only interesting pass. Everything the predicate says about the cap
/// has to come from both sides or it contradicts the outcome sitting next to it.
#[test]
fn a_pass_that_fired_only_on_the_rebuild_reaches_the_signed_statement() {
    let c = Comparison {
        outcome: trigon_core::Match::NormalizedWithCaveats,
        upstream: side(
            vec![pass("zip-time", RiskTier::Metadata, Provenance::Builtin)],
            0x11,
        ),
        rebuild: side(
            vec![
                pass("zip-time", RiskTier::Metadata, Provenance::Builtin),
                pass("wheel-record", RiskTier::Content, Provenance::Builtin),
            ],
            0x11,
        ),
        diff: None,
    };

    let s = trigon_attest::Statement::equivalence("x-1.0-py3-none-any.whl", &c);
    let p = &s.predicate;

    let ids: Vec<&str> = p["applied"]
        .as_array()
        .expect("applied is an array")
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"wheel-record"),
        "a pass that fired only on the rebuild is missing from the signed statement: {ids:?}"
    );

    // And the summary fields must agree with the outcome beside them.
    assert_eq!(
        p["provenanceCap"]["maxRiskApplied"], "content",
        "maxRiskApplied ignored the rebuild side: {p}"
    );
}

/// The provenance half of the cap, from the side the old code did not read.
#[test]
fn a_model_authored_pass_on_the_rebuild_clears_all_builtin() {
    let c = Comparison {
        outcome: trigon_core::Match::NormalizedWithCaveats,
        upstream: side(Vec::new(), 0x22),
        rebuild: side(
            vec![pass(
                "invented",
                RiskTier::Lossy,
                Provenance::Model {
                    model_id: "m-20260101".into(),
                    run_id: "r1".into(),
                },
            )],
            0x22,
        ),
        diff: None,
    };

    let p = &trigon_attest::Statement::equivalence("x.whl", &c).predicate;
    assert_eq!(
        p["provenanceCap"]["allBuiltin"], false,
        "allBuiltin read only the upstream side, so a model-authored pass was invisible: {p}"
    );
    assert_eq!(p["provenanceCap"]["maxRiskApplied"], "lossy", "{p}");
}

/// Each entry says which artifact it fired on, so the same id on both sides is legible rather than
/// looking like a duplicate.
#[test]
fn each_applied_entry_names_its_side() {
    let c = Comparison {
        outcome: trigon_core::Match::Normalized,
        upstream: side(
            vec![pass("zip-time", RiskTier::Metadata, Provenance::Builtin)],
            0x33,
        ),
        rebuild: side(
            vec![pass("zip-time", RiskTier::Metadata, Provenance::Builtin)],
            0x33,
        ),
        diff: None,
    };
    let p = &trigon_attest::Statement::equivalence("x.whl", &c).predicate;
    let sides: Vec<&str> = p["applied"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["side"].as_str().unwrap())
        .collect();
    assert_eq!(sides, vec!["upstream", "rebuild"], "{p}");
}
