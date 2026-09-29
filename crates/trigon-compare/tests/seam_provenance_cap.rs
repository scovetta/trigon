//! The provenance cap, over every stabilizer shape that can exist.
//!
//! `Match::Normalized` is unreachable when any *applied* stabilizer carries non-`Builtin`
//! provenance or a risk tier above `Metadata` (`docs/00-overview.md` §3.1). That one sentence is
//! the load-bearing rule of the project: it is what stops a model-authored pass, a fetch-and-re-emit
//! build script, or an accidentally-enabled feature from presenting as a clean match, and it is the
//! claim the attestation predicate reports.
//!
//! `docs/05-archive-and-normalization.md` §4.4, `docs/01-architecture.md` §2.2 and the invariant table
//! in `docs/12-security.md` §10 all say the rule "runs as a runtime check, a unit test, and a proptest
//! over arbitrary stabilizer sets". At the time of writing only the middle leg existed: three
//! behavioural tests in `tests/outcomes.rs` drive one clean case, one model-authored case and one
//! `Content`-risk case through real archives. There is no `debug_assert` in `trigon-compare`, and
//! `proptest` is a dev-dependency of `trigon-archive` and `trigon-stabilize` but not of this crate.
//! This file supplies the missing leg — in the stronger form.
//!
//! **Why exhaustive rather than sampled.** The cap reads exactly two fields of `Applied` and one
//! fact about where it landed, so the domain is `RiskTier` (4) × `Provenance` (3) × side (3) = 36
//! points per digest state. Enumerating 36 points is a proof over the domain; sampling 200 draws
//! from it is evidence about the same 36 points and strictly weaker. The dimension that actually
//! carries risk is not the value distribution but the *variant set*, and that is where a generator
//! rots: a hand-written `Arbitrary` impl that predates a new `RiskTier::Destructive` or
//! `Provenance::Vendored` keeps drawing from the old variants and keeps passing, which is the exact
//! failure mode of finding 3 — `all_profiles()` omitted `wheel`, so the parity test that iterated
//! it never covered the profile PyPI uses. Here the classification helper below is an exhaustive
//! `match` with no wildcard arm: a new variant does not silently pass, it fails to compile, and
//! somebody has to say which side of the cap it falls on. That compile error is the real test.
//!
//! The four cap tests drive `compare()` on hand-built `Summary` values rather than on real
//! archives. `tests/outcomes.rs` already proves the real path reaches this function with honest
//! inputs; what was untested is the decision itself over shapes no builtin profile can currently
//! produce — a `Lossy` pass, a `Human`-reviewed one — which the definitions repository exists to
//! supply. The fifth test, on how the cap is *reported*, runs two real `.crate` files end to end,
//! because a hand-built `Summary` would prove the decision and not the path.

use trigon_archive::Limits;
use trigon_compare::{Comparison, Summary, compare, compare_bytes};
use trigon_core::{
    Digest, Format, Match, MultiDigest, ProfileId, Provenance, RiskTier, StabilizerId,
};
use trigon_stabilize::{Applied, profile};

// --- the domain -----------------------------------------------------------------------------------

const EVERY_RISK: [RiskTier; 4] = [
    RiskTier::Structural,
    RiskTier::Metadata,
    RiskTier::Content,
    RiskTier::Lossy,
];

/// One of each `Provenance` variant, with the payloads a real one would carry.
fn every_provenance() -> Vec<Provenance> {
    vec![
        Provenance::Builtin,
        Provenance::Human {
            reviewer: "a-maintainer".into(),
        },
        Provenance::Model {
            model_id: "claude-opus-5".into(),
            run_id: "01JABCDEF".into(),
        },
    ]
}

/// Which side of the comparison the pass under test fired on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Upstream,
    Rebuild,
    Both,
}

const EVERY_SIDE: [Side; 3] = [Side::Upstream, Side::Rebuild, Side::Both];

/// Does a pass of this shape leave `Normalized` reachable?
///
/// Stated as two exhaustive matches rather than as `risk <= RiskTier::Metadata &&
/// provenance == Builtin`, deliberately. Restating the implementation's expression would make every
/// assertion below a tautology: reorder the `RiskTier` variants so that `Content` sorts under
/// `Metadata` and both the implementation and the oracle would change meaning together, silently,
/// and every test would still pass while the cap had quietly stopped capping. Naming each variant
/// literally is what makes the derived `Ord` on `RiskTier` a thing under test rather than a shared
/// assumption.
fn leaves_normalized_reachable(risk: RiskTier, provenance: &Provenance) -> bool {
    let risk_is_clean = match risk {
        // Reordering and reframing, and dropping integrity metadata computed over content we are
        // rebuilding. Nothing a consumer reads changes. See `docs/05` §3.
        RiskTier::Structural => true,
        // Timestamps, modes, owners: the benign nondeterminism this project exists to absorb.
        RiskTier::Metadata => true,
        // Rewrites bytes inside a distributed file. `wheel-record-v2` is the builtin example, and
        // it is why a wheel that needed its RECORD regenerated cannot present as a clean match.
        RiskTier::Content => false,
        // Discards information outright.
        RiskTier::Lossy => false,
    };
    let provenance_is_clean = match provenance {
        Provenance::Builtin => true,
        // A human reviewed it, which is not the same as this project having written it.
        Provenance::Human { .. } => false,
        // The case the invariant exists for.
        Provenance::Model { .. } => false,
    };
    risk_is_clean && provenance_is_clean
}

// --- building comparisons the cap can decide ------------------------------------------------------

/// A digest that is equal to itself and to nothing else. The cap never reads digest *content*, only
/// whether two of them agree, so a seeded constant says what matters and hides what does not.
fn digest(seed: u8) -> MultiDigest {
    MultiDigest::sha256_only(Digest::from_bytes([seed; 32]))
}

fn a_pass(risk: RiskTier, provenance: Provenance) -> Applied {
    let tag = match &provenance {
        Provenance::Builtin => "builtin".to_string(),
        Provenance::Human { .. } => "human".to_string(),
        Provenance::Model { .. } => "model".to_string(),
    };
    Applied {
        id: StabilizerId::new(format!("test-{}-{tag}", format!("{risk:?}").to_lowercase())),
        risk,
        provenance,
        // The cap reads neither of these. A pass reaches `applied` at all only because `apply`
        // observed it change something (`set.rs`: the filter on `entries > 0 || bytes > 0`), which
        // is the invariant `a_capped_pass_that_does_nothing_does_not_cap` in `outcomes.rs` pins.
        entries_touched: 1,
        bytes_changed: 8,
    }
}

/// The pass every comparison below carries on the side *not* under test.
///
/// Its presence is what makes `Side::Upstream` and `Side::Rebuild` mean something. Without it the
/// other side's list is empty, and an implementation that decided the cap from whichever list it
/// happened to look at first would still pass half the table. With a clean builtin pass sitting
/// opposite, the assertion becomes "one capped pass anywhere in the union caps the outcome" — the
/// cap is an `all` over both lists and not an `any`, a first-match, or a short-circuit on the first
/// clean entry. That is finding 4 restated at the level that decides the outcome rather than at the
/// level that reports it: `equivalence_predicate` derived `allBuiltin` from `c.upstream.applied`
/// alone, so a `wheel-record` that fired only on the rebuild was invisible to the signed document
/// while `compare()` capped on it correctly.
fn companion() -> Applied {
    a_pass(RiskTier::Metadata, Provenance::Builtin)
}

fn placed(side: Side, under_test: Applied) -> (Vec<Applied>, Vec<Applied>) {
    match side {
        Side::Upstream => (vec![under_test], vec![companion()]),
        Side::Rebuild => (vec![companion()], vec![under_test]),
        Side::Both => (vec![under_test.clone(), companion()], vec![under_test]),
    }
}

fn summary(raw: u8, stabilized: u8, applied: Vec<Applied>) -> Summary {
    Summary {
        format: Format::Tar,
        bytes: 4096,
        raw: digest(raw),
        container: None,
        stabilized: digest(stabilized),
        applied,
        notes: Vec::new(),
        // Both sides must report the same set digest or `compare` refuses outright, which is a
        // different invariant (`comparing_across_stabilizer_sets_is_refused`) and not this one.
        set: (ProfileId::new("tar"), Digest::from_bytes([0xEE; 32])),
        edits: Vec::new(),
    }
}

/// Compare two sides that agree on their stabilized digest and disagree on their raw bytes — the
/// only state in which the cap gets to decide anything.
fn compare_with(side: Side, risk: RiskTier, provenance: &Provenance) -> Comparison {
    let (u, r) = placed(side, a_pass(risk, provenance.clone()));
    compare(summary(1, 9, u), summary(2, 9, r), None, None).expect("same set on both sides")
}

// --- the cap itself -------------------------------------------------------------------------------

#[test]
fn normalized_is_reachable_exactly_when_every_applied_pass_on_both_sides_is_builtin_at_metadata_or_below()
 {
    // The baseline first: nothing fired anywhere, so there is nothing to cap on. A cap implemented
    // as "find a reason" rather than "check every pass" gets this right and everything else wrong,
    // so it earns its line but not its own test.
    let none = compare(summary(1, 9, vec![]), summary(2, 9, vec![]), None, None).unwrap();
    assert_eq!(none.outcome, Match::Normalized);

    let mut cases = 0;
    for risk in EVERY_RISK {
        for provenance in every_provenance() {
            for side in EVERY_SIDE {
                let c = compare_with(side, risk, &provenance);
                let clean = leaves_normalized_reachable(risk, &provenance);
                let expected = if clean {
                    Match::Normalized
                } else {
                    Match::NormalizedWithCaveats
                };
                assert_eq!(
                    c.outcome, expected,
                    "a {risk:?} pass with {provenance:?} provenance on {side:?}: \
                     the stabilized digests agree, so the cap alone decides"
                );

                // The invariant as `docs/00-overview.md` §3.1 states it — an implication, checked
                // independently of the equality above. `Normalized` must be unreachable, not merely
                // differently-reached, when anything capped fired.
                assert!(
                    c.outcome != Match::Normalized
                        || c.applied()
                            .iter()
                            .all(|a| a.provenance == Provenance::Builtin
                                && a.risk <= RiskTier::Metadata),
                    "outcome {:?} with a {risk:?} {provenance:?} pass on {side:?}",
                    c.outcome
                );

                // And the ordering the policy surface exposes: a capped run must not satisfy a
                // `--require normalized` floor. `Match` derives `Ord` for exactly this, so the two
                // have to agree or a consumer's threshold means something other than the outcome.
                assert_eq!(
                    c.outcome.is_at_least(Match::Normalized),
                    clean,
                    "a {risk:?} {provenance:?} pass on {side:?} must not clear a `normalized` floor"
                );
                cases += 1;
            }
        }
    }
    // If a variant is added and this file still compiles — it should not, but if a wildcard arm is
    // ever introduced above — the count is the second line of defence.
    assert_eq!(cases, 36, "4 risk tiers x 3 provenances x 3 sides");
}

#[test]
fn exact_is_decided_by_the_raw_digests_alone_and_never_by_what_fired() {
    // `Exact` means the published bytes and the rebuilt bytes are the same bytes. No stabilizer
    // participated in that conclusion even if several fired, so no stabilizer can qualify it.
    let mut cases = 0;
    for risk in EVERY_RISK {
        for provenance in every_provenance() {
            for side in EVERY_SIDE {
                let (u, r) = placed(side, a_pass(risk, provenance.clone()));

                // The honest state: identical raw bytes stabilize identically.
                let c = compare(
                    summary(7, 9, u.clone()),
                    summary(7, 9, r.clone()),
                    None,
                    None,
                )
                .unwrap();
                assert_eq!(
                    c.outcome,
                    Match::Exact,
                    "a {risk:?} {provenance:?} pass on {side:?} must not demote an exact match"
                );

                // The impossible state, asserted for branch precedence: equal raw digests with
                // differing stabilized ones cannot arise from a deterministic pipeline, because the
                // same bytes under the same set produce the same stabilized form. It is pinned
                // because the *order* of the branches is load-bearing — flip the raw check below
                // the stabilized one and an exact match starts being read through the cap and
                // reported as `normalized_with_caveats`, a strictly worse verdict for an artifact
                // that matched byte for byte.
                let c = compare(summary(7, 8, u), summary(7, 9, r), None, None).unwrap();
                assert_eq!(c.outcome, Match::Exact, "raw equality is checked first");
                cases += 2;
            }
        }
    }
    assert_eq!(cases, 72);
}

#[test]
fn divergent_is_decided_by_the_stabilized_digests_alone_and_never_by_what_fired() {
    // The mirror of the cap, and the one that protects the *negative* result. A divergence is a
    // publishable claim in its own right (`docs/00-overview.md` §4.5), so it must not be softened
    // by a clean stabilizer set, and it must not be reached early by a dirty one: both sides
    // disagreeing after stabilization is the whole of the reason.
    let mut cases = 0;
    for risk in EVERY_RISK {
        for provenance in every_provenance() {
            for side in EVERY_SIDE {
                let (u, r) = placed(side, a_pass(risk, provenance.clone()));
                let c = compare(summary(1, 8, u), summary(2, 9, r), None, None).unwrap();
                assert_eq!(
                    c.outcome,
                    Match::Divergent,
                    "a {risk:?} {provenance:?} pass on {side:?} cannot change a divergence"
                );
                assert!(!c.outcome.is_reproduced());
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 36);
}

#[test]
fn the_outcome_is_the_same_whichever_artifact_is_called_upstream() {
    // The cap is a property of the union of the two `applied` lists, so it cannot depend on which
    // artifact was handed in first. Stated as a symmetry because that is the shape finding 4 broke:
    // reading one named side rather than both produces an outcome that changes when the arguments
    // are swapped, and no single-direction assertion catches it. `raw` and `stabilized` equality
    // are symmetric by construction, so any asymmetry here is the cap's.
    for risk in EVERY_RISK {
        for provenance in every_provenance() {
            let capped = a_pass(risk, provenance.clone());
            let clean = companion();
            for (raw_u, raw_r, stab_u, stab_r) in [(1u8, 2u8, 9u8, 9u8), (1, 2, 8, 9), (7, 7, 9, 9)]
            {
                let forward = compare(
                    summary(raw_u, stab_u, vec![capped.clone()]),
                    summary(raw_r, stab_r, vec![clean.clone()]),
                    None,
                    None,
                )
                .unwrap();
                let reversed = compare(
                    summary(raw_r, stab_r, vec![clean.clone()]),
                    summary(raw_u, stab_u, vec![capped.clone()]),
                    None,
                    None,
                )
                .unwrap();
                assert_eq!(
                    forward.outcome, reversed.outcome,
                    "a {risk:?} {provenance:?} pass changed the verdict by changing sides"
                );
            }
        }
    }
}

// --- reporting the cap ----------------------------------------------------------------------------

/// A `.crate` shaped the way cargo packages one: a source file beside the `.cargo_vcs_info.json`
/// that every crates.io artifact carries.
///
/// Built from the shipped `crate` profile rather than from a test-only stabilizer on purpose.
/// `cargo-vcs-hash` is a **builtin** pass at `Content` risk (`passes.rs`), and it fires on every
/// `.crate` there is, so the behaviour below is not a contrivance that needs a model-authored pass
/// to reach — it is what `trigon verify` does on the crates.io path today.
fn crate_file(body: &[u8], sha1: &str) -> Vec<u8> {
    let vcs = format!(r#"{{"git":{{"sha1":"{sha1}"}},"path_in_vcs":""}}"#);
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, content) in [
        ("p-1.0.0/.cargo_vcs_info.json", vcs.as_bytes()),
        ("p-1.0.0/src/lib.rs", body),
    ] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, name, content).unwrap();
    }
    let mut out = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        &b.into_inner().unwrap(),
        flate2::Compression::default(),
        &mut out,
    )
    .unwrap();
    out
}

fn compare_crates(upstream: Vec<u8>, rebuild: Vec<u8>) -> Comparison {
    compare_bytes(
        upstream,
        rebuild,
        Format::TarGz,
        &profile("crate").unwrap(),
        &Limits::default(),
    )
    .unwrap()
}

#[test]
fn cap_reason_speaks_exactly_when_the_cap_actually_decided_the_outcome() {
    // `cap_reason()` documents itself as "whether **the outcome** was capped below `Normalized` by
    // provenance or risk, and why", and `trigon verify` prints it verbatim as
    // ``capped below `normalized`: {reason}`` (`crates/trigon/src/main.rs`). It is derived from the
    // applied lists alone and never consults the outcome it is describing, so it answers a
    // different question from the one it is asked: "did any capped pass fire" rather than "was this
    // verdict capped".
    //
    // This is finding 4's shape one level down. The cap itself is correct — the four tests above
    // establish that over the whole domain — but what is *reported* about it reads a different
    // input from what decided it, exactly as `equivalence_predicate` once derived `allBuiltin` from
    // one side while `compare()` capped on both.
    //
    // Observed against the shipped binary, on the two `.crate` files this test rebuilds:
    //
    //     ✖ divergent                              ✔ exact
    //       ...                                      ...
    //       applied                                  applied
    //         cargo-vcs-hash   content               cargo-vcs-hash   content
    //       capped below `normalized`:               capped below `normalized`:
    //         cargo-vcs-hash is Builtin at             cargo-vcs-hash is Builtin at
    //         Content risk                             Content risk
    //
    // Neither line is true. The divergence was decided by `src/lib.rs` differing, and an operator
    // triaging it is pointed at the stabilizer set instead of at the artifacts. The exact match
    // reached the rung *above* `Normalized` on identical bytes, so there was nothing below it to be
    // capped to. `cargo-vcs-hash` is in the profile every crates.io artifact uses, so this prints on
    // every crates.io verdict that is not already `NormalizedWithCaveats`.
    for risk in EVERY_RISK {
        for provenance in every_provenance() {
            for side in EVERY_SIDE {
                let c = compare_with(side, risk, &provenance);
                assert_eq!(
                    c.cap_reason().is_some(),
                    c.outcome == Match::NormalizedWithCaveats,
                    "{:?} with a {risk:?} {provenance:?} pass on {side:?} reported {:?}",
                    c.outcome,
                    c.cap_reason()
                );
            }
        }
    }

    // The two real cases are collected rather than asserted in place: they are independent facts
    // about two different outcomes, and a test that aborted on the first would leave the second
    // unmeasured.
    let mut wrong: Vec<String> = Vec::new();

    let divergent = compare_crates(
        crate_file(b"pub fn f() -> u32 { 1 }\n", &"a".repeat(40)),
        crate_file(b"pub fn f() -> u32 { 2 }\n", &"b".repeat(40)),
    );
    assert_eq!(divergent.outcome, Match::Divergent);
    assert!(
        divergent
            .applied()
            .iter()
            .any(|a| a.id.as_str() == "cargo-vcs-hash"),
        "the builtin content-risk pass has to have fired for this to be the case it looks like"
    );
    if let Some(r) = divergent.cap_reason() {
        wrong.push(format!(
            "divergent: the artifacts differ, nothing capped the verdict, yet cap_reason said {r:?}"
        ));
    }

    let same = crate_file(b"pub fn f() -> u32 { 1 }\n", &"a".repeat(40));
    let exact = compare_crates(same.clone(), same);
    assert_eq!(exact.outcome, Match::Exact);
    assert!(
        exact
            .applied()
            .iter()
            .any(|a| a.id.as_str() == "cargo-vcs-hash"),
        "the builtin content-risk pass has to have fired for this to be the case it looks like"
    );
    if let Some(r) = exact.cap_reason() {
        wrong.push(format!(
            "exact: the artifacts are byte-identical and `Exact` outranks `Normalized`, so nothing \
             was capped below it, yet cap_reason said {r:?}"
        ));
    }

    assert!(
        wrong.is_empty(),
        "`trigon verify` prints each of these as ``capped below `normalized`: ...``:\n  {}",
        wrong.join("\n  ")
    );
}
