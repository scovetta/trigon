//! The [ADR-0010] gate: what an anonymous reader is allowed to be shown.
//!
//! A public page showing `divergent` against somebody else's package **is publication**. That ADR's
//! opening sentence is "All results publish automatically, divergences included, subject to five
//! technical safeguards", and it gives the reason in one line:
//!
//! > **A false `Reproduced` is an error. A false `Divergent` is an accusation.**
//!
//! Before this module the five safeguards existed as prose. `12-security.md`'s invariant 12 —
//! *two attempts that disagree publish nothing* — records its enforcement as the word **nothing**.
//! So the gate is built here, as one object with one producer, and it is what every anonymous read
//! path in this crate asks before returning a row.
//!
//! **It withholds far more than it will once there is a fleet, and that is the correct direction to
//! be wrong in.** A single-attempt corpus cannot satisfy safeguard 1 at all, so in public mode a
//! one-attempt divergence is withheld and the reason is named rather than the row silently
//! vanishing. The number of withheld rows is itself reported, because a public page that quietly
//! shows two thirds of a corpus is a page whose denominator is a lie.
//!
//! [ADR-0010]: ../../../docs/adr/0010-publish-divergences.md

use serde::Serialize;
use trigon_store::RunRecord;

/// Why a run is not shown to an anonymous reader.
///
/// Serialized as a string, never an ordinal, for the reason every outcome in this system is
/// ([ADR-0002]): a consumer filtering on an integer breaks the moment a reason is inserted between
/// two existing ones.
///
/// [ADR-0002]: ../../../docs/adr/0002-four-match-outcomes.md
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Withheld {
    /// Safeguard 1. Fewer than two terminal attempts at the same work.
    AwaitingConfirmation,
    /// Safeguard 1. Two attempts, and they did not agree. This is the case the ADR cares about
    /// most: the disagreement is the finding, and the finding is that we do not know.
    AttemptsDisagree,
    /// Safeguard 2, egress clause. The build ran at a tier that adds no network isolation, so a
    /// divergence cannot be attributed to the package.
    OpenEgress,
    /// Safeguard 2, guard clause. The artifact under test reached the build over the network.
    GuardTripped,
    /// Safeguard 2, provenance clause. A non-`Builtin` stabilizer was applied, so the normalization
    /// itself is something a human or a model chose.
    NonBuiltinStabilizer,
    /// Safeguard 2, provenance clause, **unevaluated**. The record does not say whether a
    /// non-`Builtin` stabilizer applied, so the clause can be neither cleared nor fired.
    ///
    /// Distinct from [`Self::NonBuiltinStabilizer`] on purpose: "a person wrote the normalization"
    /// and "we do not know who wrote the normalization" are different sentences, and a reader who
    /// is shown the first when the second is true has been told something nobody established.
    ProvenanceUnknown,
    /// Safeguard 2, egress clause, the half that happens before the build.
    ///
    /// This run built its own base image, which means `apt-get`, which means network — spent
    /// outside the boundary the transcript accounts for. The build itself still ran at the tier
    /// it claims; what is unaccounted is the environment it ran *in*.
    ///
    /// Accusations only. A match from a derived image is still evidence — the mirror and the
    /// guard both ran, and reproducing an artifact is not made easier by an image carrying
    /// `build-essential`. A divergence is an accusation, and an accusation is not published on a
    /// step nobody accounted for.
    ImageDerivedOutsideBoundary,
    /// Safeguard 5. An operator stopped divergence publication.
    KillSwitch,
    /// Not a safeguard: the run never reached an outcome, so there is nothing to publish.
    NoOutcome,
}

impl Withheld {
    /// The wire name, matching what `serde` writes for the same variant.
    ///
    /// Not `format!("{:?}")`. Debug gives `AwaitingConfirmation` while the serialized field gives
    /// `awaiting_confirmation`, and a page keyed on one while reading the other has two names for
    /// one reason — which is how a legend ends up with a row nothing ever matches.
    pub fn key(self) -> &'static str {
        match self {
            Withheld::AwaitingConfirmation => "awaiting_confirmation",
            Withheld::AttemptsDisagree => "attempts_disagree",
            Withheld::OpenEgress => "open_egress",
            Withheld::GuardTripped => "guard_tripped",
            Withheld::NonBuiltinStabilizer => "non_builtin_stabilizer",
            Withheld::ImageDerivedOutsideBoundary => "image_derived_outside_boundary",
            Withheld::KillSwitch => "kill_switch",
            Withheld::ProvenanceUnknown => "provenance_unknown",
            Withheld::NoOutcome => "no_outcome",
        }
    }

    /// The sentence a page shows in place of the row.
    ///
    /// Written out here rather than in the front-end because the reason a finding is withheld is a
    /// claim about our own process, and a claim about our own process belongs with the code that
    /// makes it rather than in a translation table somebody edits later.
    pub fn sentence(self) -> &'static str {
        match self {
            Withheld::AwaitingConfirmation => {
                "held back until a second, independent attempt agrees. One attempt cannot tell a \
                 deterministic recipe from a lucky one."
            }
            Withheld::AttemptsDisagree => {
                "two attempts at this disagreed, so the honest answer is that we do not know. That \
                 is a finding about our own repeatability, not about the package."
            }
            Withheld::OpenEgress => {
                "the build ran with unrestricted network access, so nothing it produced is evidence \
                 about the package."
            }
            Withheld::GuardTripped => {
                "the build reached the published artifact over the network, so a match would prove \
                 only that it downloaded it."
            }
            Withheld::NonBuiltinStabilizer => {
                "a stabilizer a person or a model wrote was applied, so the normalization is itself \
                 a judgement call and this publishes as void rather than as a divergence."
            }
            Withheld::ImageDerivedOutsideBoundary => {
                "this run built its own base image, which spends network outside the boundary the \
                 rest of the run accounts for. The build ran at the tier it claims; the \
                 environment it ran in was assembled without that account, and an accusation is \
                 not published on a step nobody measured."
            }
            Withheld::ProvenanceUnknown => {
                "this record does not say whether a hand-written or model-written stabilizer was \
                 applied, so one of the five safeguards cannot be checked. An accusation is not \
                 published on a safeguard nobody evaluated."
            }
            Withheld::KillSwitch => {
                "divergence publication is stopped while the false-mismatch rate is reviewed."
            }
            Withheld::NoOutcome => {
                "this run never reached a verdict, so there is nothing to publish."
            }
        }
    }
}

/// What the gate decided about one run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Publication {
    /// Every safeguard holds. An anonymous reader may see the verdict.
    Published,
    /// Safeguard 2 fired: the run is *shown*, as `void`, and never as a divergence. The distinction
    /// matters — "we looked and could not tell" is a publishable result and an accusation is not.
    Void { because: Withheld },
    /// Not shown at all to an anonymous reader.
    Withheld { because: Withheld },
}

impl Publication {
    pub fn is_public(self) -> bool {
        !matches!(self, Publication::Withheld { .. })
    }

    pub fn because(self) -> Option<Withheld> {
        match self {
            Publication::Published => None,
            Publication::Void { because } | Publication::Withheld { because } => Some(because),
        }
    }
}

/// Operator switches the gate reads. Safeguard 5, and the one knob it is allowed to have.
#[derive(Clone, Copy, Debug, Default)]
pub struct Switches {
    /// Safeguard 5's kill-switch. Set it and divergences stop publishing until a human clears it;
    /// matches are unaffected, because a false match is an error and a false divergence is an
    /// accusation.
    pub stop_divergences: bool,
}

/// The evidence the gate needs beyond the record itself.
///
/// Separated from `RunRecord` because two of the three answers are not on the record: whether a
/// non-`Builtin` stabilizer applied lives in the comparison blob, and whether a second attempt
/// agreed is a fact about a *set* of records. Passing them in keeps [`decide`] a pure function of
/// its arguments, which is what lets it be tested exhaustively rather than through a store.
#[derive(Clone, Copy, Debug, Default)]
pub struct Corroboration {
    /// Terminal attempts at the same `cache_key` whose outcome and comparison digest match this
    /// one's.
    pub agreeing_attempts: u32,
    /// Terminal attempts at the same `cache_key` that reached a *different* outcome.
    pub disagreeing_attempts: u32,
    /// Whether any applied stabilizer carried non-`Builtin` provenance.
    ///
    /// **`Option`, and the reason is this project's own rule.** This was a `bool` hard-wired to
    /// `false` at its one call site, under a comment saying the gate was "told nothing rather than
    /// told no" — which a `bool` cannot do. `false` is told "no": it is the positive claim that
    /// every applied pass was built in, made by an index that had not looked. Safeguard 2's
    /// provenance clause therefore could not fire, and absent had become zero in the one place
    /// this codebase is most insistent that it must not.
    ///
    /// `None` is now genuinely "not known", and [`decide`] refuses to clear a safeguard on it.
    pub non_builtin_stabilizer: Option<bool>,
}

/// The five safeguards, in the order they can each stop a row, for one run.
///
/// **Order is load-bearing.** Safeguard 2's clauses are checked before safeguard 1's, because a run
/// with an open egress tier publishes as `Void` — a shown, useful, non-accusatory result — whereas
/// an unconfirmed run is withheld entirely. Checking confirmation first would hide behind
/// "awaiting confirmation" a run that we already know can never be a divergence, and the reader
/// would be told to wait for something that would not change the answer.
pub fn decide(r: &RunRecord, c: Corroboration, s: Switches) -> Publication {
    let Some(outcome) = r.outcome.as_deref() else {
        return Publication::Withheld {
            because: Withheld::NoOutcome,
        };
    };
    let accusatory = outcome == "divergent";

    // Safeguard 2. Each clause converts a divergence into a void rather than suppressing it.
    if !r.guard_trips.is_empty() {
        return Publication::Void {
            because: Withheld::GuardTripped,
        };
    }
    if r.environment.egress.eq_ignore_ascii_case("open") {
        return Publication::Void {
            because: Withheld::OpenEgress,
        };
    }
    if c.non_builtin_stabilizer == Some(true) {
        return Publication::Void {
            because: Withheld::NonBuiltinStabilizer,
        };
    }

    // Safeguard 1. Two agreeing attempts, divergences and matches alike — the ADR says "alike" and
    // means it, because a false `Reproduced` published from one lucky build is still wrong.
    if c.disagreeing_attempts > 0 {
        return Publication::Withheld {
            because: Withheld::AttemptsDisagree,
        };
    }
    if c.agreeing_attempts < 2 {
        return Publication::Withheld {
            because: Withheld::AwaitingConfirmation,
        };
    }

    // Safeguard 5. Late, because it is a deliberate operator intervention and the page should say
    // *that* rather than whichever structural reason happened to be checked first.
    if accusatory && s.stop_divergences {
        return Publication::Withheld {
            because: Withheld::KillSwitch,
        };
    }

    // Safeguard 2's egress clause, the half that happens before the build starts.
    //
    // `--image derive` builds a base image with network, then runs the build at `mirror-only`.
    // The transcript is still a complete account of what crossed into the *build*; it is not an
    // account of what went into the image the build ran on. Before this existed the gate read
    // `environment.egress` and nothing else about the boundary, so such a run was indistinguishable
    // from a clean one and published as a divergence — which is an accusation.
    //
    // Accusations only, and that is a judgement rather than an oversight: a *match* from a derived
    // image is still evidence, because the mirror and the artifact guard both ran and reproducing
    // a published artifact is not made easier by an image that carries `build-essential`.
    if accusatory && r.environment.derived_image.is_some() {
        return Publication::Withheld {
            because: Withheld::ImageDerivedOutsideBoundary,
        };
    }

    // Safeguard 2's provenance clause, unevaluated. **Last of all**, and only for an accusation.
    //
    // Last because every reason above is more informative: an operator pulled the lever, two
    // attempts disagreed, this is not confirmed yet. Each of those tells a reader something about
    // the run; this tells them something about the record, and only matters once nothing else
    // stands in the way. What is left when it does fire is exactly the dangerous case — a
    // confirmed, guard-clean, mirror-only accusation about to be published on a safeguard nobody
    // evaluated.
    //
    // Only for an accusation because that is what safeguard 2 is for. A match published without
    // knowing who wrote the normalization is not an allegation against anyone.
    if accusatory && c.non_builtin_stabilizer.is_none() {
        return Publication::Withheld {
            because: Withheld::ProvenanceUnknown,
        };
    }

    Publication::Published
}

#[cfg(test)]
mod tests {
    use super::*;
    use trigon_store::{ArtifactRef, Environment};

    fn env(egress: &str) -> Environment {
        Environment {
            base_image: "example@sha256:00".into(),
            derived_image: None,
            egress: egress.into(),
            isolation: "podman".into(),
            attestable: true,
            registry_moment: None,
            pin: None,
            guard_manifest: None,
            guarded_members: None,
        }
    }

    fn record(outcome: Option<&str>, egress: &str) -> RunRecord {
        let mut r = RunRecord::new(
            "1700000000-abcdef01",
            "pkg:npm/left-pad@1.3.0",
            ArtifactRef {
                name: "left-pad-1.3.0.tgz".into(),
                sha256: trigon_core::Digest::from_bytes([0u8; 32]),
                bytes: 1,
                stored: true,
            },
            env(egress),
            "2026-01-01T00:00:00Z",
        );
        r.outcome = outcome.map(str::to_string);
        r
    }

    fn confirmed() -> Corroboration {
        Corroboration {
            agreeing_attempts: 2,
            ..Default::default()
        }
    }

    /// Confirmed, with the provenance clause answered, so these tests isolate the one clause
    /// they are about rather than tripping `ProvenanceUnknown` first.
    fn confirmed_and_evaluated() -> Corroboration {
        Corroboration {
            non_builtin_stabilizer: Some(false),
            ..confirmed()
        }
    }

    fn derived() -> trigon_store::DerivedImage {
        trigon_store::DerivedImage {
            parent: "docker.io/library/debian@sha256:aa".into(),
            packages: vec!["build-essential".into()],
            built_here: true,
        }
    }

    #[test]
    fn an_accusation_is_not_published_from_a_run_that_built_its_own_image() {
        // `--image derive` spends network before the build, outside the account the transcript
        // gives. The gate read `environment.egress` and nothing else about the boundary, so such
        // a run looked exactly like a clean one — and a divergence is an accusation.
        let mut r = record(Some("divergent"), "mirror-only");
        r.environment.derived_image = Some(derived());
        assert_eq!(
            decide(&r, confirmed_and_evaluated(), Switches::default()),
            Publication::Withheld {
                because: Withheld::ImageDerivedOutsideBoundary
            }
        );
    }

    #[test]
    fn a_match_from_a_derived_image_still_publishes() {
        // Deliberately not symmetric with the test above, and the asymmetry is the claim. The
        // mirror and the artifact guard both ran; reproducing a published artifact byte for byte
        // is not made easier by an image that carries `build-essential`. Voiding a match here
        // would discard real evidence to be seen to be careful, which is its own kind of wrong
        // answer.
        let mut r = record(Some("exact"), "mirror-only");
        r.environment.derived_image = Some(derived());
        assert_eq!(
            decide(&r, confirmed_and_evaluated(), Switches::default()),
            Publication::Published
        );
    }

    #[test]
    fn a_run_that_derived_nothing_is_unaffected() {
        // `None` is the common case — an operator named an image, or one already on the machine
        // carried what the strategy needed — and it must not be read as "we do not know".
        let r = record(Some("divergent"), "mirror-only");
        assert_eq!(r.environment.derived_image, None);
        assert_eq!(
            decide(&r, confirmed_and_evaluated(), Switches::default()),
            Publication::Published
        );
    }

    #[test]
    fn a_model_opinion_about_the_diff_never_moves_the_gate() {
        // `trigon_core::opinion`'s rule, asserted where it could break: a model supplies
        // opinions, never verdicts. "Equivalent" must not soften a divergence out of publication,
        // and "substantive" must not harden one in — in either direction, an opinion moving the
        // gate would be a model deciding what Trigon publishes.
        // Every published baseline catches softening (Published → anything trips the
        // assert_eq); catching *hardening* needs a baseline the gate already holds back, or a
        // `decide` that gained `if substantive { publish }` would pass every row. The first
        // draft of this test had only published baselines, which is half a test wearing the
        // name of a whole one.
        let corroborations = [
            ("confirmed", confirmed_and_evaluated()),
            (
                "awaiting confirmation",
                Corroboration {
                    agreeing_attempts: 1,
                    ..confirmed_and_evaluated()
                },
            ),
        ];
        for (baseline, c) in corroborations {
            for (outcome, verdict) in [
                ("divergent", trigon_core::DiffVerdict::Equivalent),
                ("divergent", trigon_core::DiffVerdict::Substantive),
                ("exact", trigon_core::DiffVerdict::Substantive),
            ] {
                let mut with = record(Some(outcome), "mirror-only");
                with.diff_opinion = Some(trigon_core::DiffOpinion {
                    verdict,
                    reason: "a reading".into(),
                    model: "m".into(),
                    members_shown: 1,
                    members_differing: 1,
                });
                let without = record(Some(outcome), "mirror-only");
                assert_eq!(
                    decide(&with, c, Switches::default()),
                    decide(&without, c, Switches::default()),
                    "the gate read the opinion on a {outcome}/{verdict:?} record ({baseline})"
                );
            }
        }
    }

    #[test]
    fn a_single_attempt_publishes_nothing_even_when_it_matched() {
        // The ADR's word is "alike": safeguard 1 is not a divergence-only rule. A false
        // `Reproduced` from one lucky build is still a false claim, and the corpus this ships
        // against is entirely single-attempt — so the gate's first honest act is to withhold most
        // of it.
        let r = record(Some("exact"), "mirror");
        assert_eq!(
            decide(&r, Corroboration::default(), Switches::default()),
            Publication::Withheld {
                because: Withheld::AwaitingConfirmation
            }
        );
    }

    #[test]
    fn two_attempts_that_disagree_publish_nothing() {
        // Invariant 12, which `12-security.md` records as enforced by "nothing".
        let r = record(Some("divergent"), "mirror");
        let c = Corroboration {
            agreeing_attempts: 1,
            disagreeing_attempts: 1,
            ..Default::default()
        };
        assert_eq!(
            decide(&r, c, Switches::default()),
            Publication::Withheld {
                because: Withheld::AttemptsDisagree
            }
        );
    }

    #[test]
    fn safeguard_two_voids_rather_than_hides() {
        // The difference between "we looked and could not tell" and an accusation. A void is shown.
        for (egress, guard, non_builtin, expect) in [
            ("open", false, false, Withheld::OpenEgress),
            ("mirror", true, false, Withheld::GuardTripped),
            ("mirror", false, true, Withheld::NonBuiltinStabilizer),
        ] {
            let mut r = record(Some("divergent"), egress);
            if guard {
                r.guard_trips
                    .push("the build fetched its own artifact".into());
            }
            let c = Corroboration {
                non_builtin_stabilizer: Some(non_builtin),
                ..confirmed()
            };
            let d = decide(&r, c, Switches::default());
            assert_eq!(d, Publication::Void { because: expect });
            assert!(d.is_public(), "a void is shown, not hidden");
        }
    }

    /// A safeguard nobody evaluated does not clear.
    ///
    /// `Corroboration::non_builtin_stabilizer` was a `bool` hard-wired to `false` at its only call
    /// site, under a comment saying the gate was "told nothing rather than told no". A `bool`
    /// cannot be told nothing. `false` is the positive claim that every applied pass was built in,
    /// asserted by an index that never looked — so safeguard 2's provenance clause could not fire,
    /// and this tree's own "absent is not zero" rule was broken inside the safeguard code.
    #[test]
    fn an_unevaluated_provenance_clause_withholds_an_accusation() {
        let r = record(Some("divergent"), "mirror");
        let unknown = Corroboration {
            non_builtin_stabilizer: None,
            ..confirmed()
        };
        assert_eq!(
            decide(&r, unknown, Switches::default()),
            Publication::Withheld {
                because: Withheld::ProvenanceUnknown
            },
            "a confirmed, guard-clean, mirror-only divergence whose record does not carry the \
             provenance fact must not publish on a clause nobody checked"
        );

        // Knowing it is the point. The same run, with the fact recorded, publishes.
        let known = Corroboration {
            non_builtin_stabilizer: Some(false),
            ..confirmed()
        };
        assert_eq!(decide(&r, known, Switches::default()), Publication::Published);
    }

    /// And only an accusation. A match is not an allegation against anyone.
    #[test]
    fn an_unevaluated_provenance_clause_does_not_withhold_a_match() {
        for outcome in ["exact", "normalized", "normalized_with_caveats"] {
            let r = record(Some(outcome), "mirror");
            let unknown = Corroboration {
                non_builtin_stabilizer: None,
                ..confirmed()
            };
            assert_eq!(
                decide(&r, unknown, Switches::default()),
                Publication::Published,
                "`{outcome}` is not an accusation, and safeguard 2 exists to stop accusations"
            );
        }
    }

    /// Every reason above it is more informative, so it is checked last.
    ///
    /// A reader told "the provenance is unknown" about a run whose two attempts disagreed, or
    /// whose operator pulled the kill switch, has been handed the least useful of the true things.
    #[test]
    fn a_more_informative_reason_wins_over_an_unknown_provenance() {
        let r = record(Some("divergent"), "mirror");
        let unknown = |extra: Corroboration| Corroboration {
            non_builtin_stabilizer: None,
            ..extra
        };

        assert_eq!(
            decide(
                &r,
                unknown(Corroboration {
                    agreeing_attempts: 1,
                    disagreeing_attempts: 1,
                    ..Default::default()
                }),
                Switches::default()
            ),
            Publication::Withheld {
                because: Withheld::AttemptsDisagree
            },
            "the disagreement is the finding"
        );

        assert_eq!(
            decide(&r, unknown(Default::default()), Switches::default()),
            Publication::Withheld {
                because: Withheld::AwaitingConfirmation
            },
            "and waiting for a second attempt is the ordinary state, which re-running also fixes"
        );

        assert_eq!(
            decide(
                &r,
                unknown(confirmed()),
                Switches {
                    stop_divergences: true
                }
            ),
            Publication::Withheld {
                because: Withheld::KillSwitch
            },
            "an operator pulled the lever and the page must say so"
        );
    }

    #[test]
    fn safeguard_two_is_checked_before_safeguard_one() {
        // An open-egress run with one attempt is a void, not "awaiting confirmation". Telling the
        // reader to wait for a second attempt would be telling them to wait for something that
        // cannot change the answer.
        let r = record(Some("divergent"), "open");
        assert_eq!(
            decide(&r, Corroboration::default(), Switches::default()),
            Publication::Void {
                because: Withheld::OpenEgress
            }
        );
    }

    #[test]
    fn the_kill_switch_stops_accusations_and_not_matches() {
        let s = Switches {
            stop_divergences: true,
        };
        let div = record(Some("divergent"), "mirror");
        assert_eq!(
            decide(&div, confirmed(), s),
            Publication::Withheld {
                because: Withheld::KillSwitch
            }
        );
        let ok = record(Some("exact"), "mirror");
        assert_eq!(decide(&ok, confirmed(), s), Publication::Published);
    }

    #[test]
    fn a_run_with_no_verdict_is_not_a_verdict() {
        let r = record(None, "mirror");
        assert_eq!(
            decide(&r, confirmed(), Switches::default()),
            Publication::Withheld {
                because: Withheld::NoOutcome
            }
        );
    }

    #[test]
    fn every_reason_says_something_a_reader_can_act_on() {
        // A withheld row shows its reason. A reason that is an enum name, or that ends without
        // saying whose problem it is, leaves the reader worse off than a blank.
        for w in [
            Withheld::AwaitingConfirmation,
            Withheld::AttemptsDisagree,
            Withheld::OpenEgress,
            Withheld::GuardTripped,
            Withheld::NonBuiltinStabilizer,
            Withheld::KillSwitch,
            Withheld::NoOutcome,
        ] {
            let s = w.sentence();
            assert!(s.len() > 40, "{w:?} says too little: {s}");
            assert!(
                s.chars().next().is_some_and(|c| c.is_lowercase()),
                "{w:?} reads as a heading, not as a sentence completing 'held back because …'"
            );
        }
    }

    /// Every reason the gate can give has a row in the page that renders it.
    ///
    /// `key()`'s own doc warns about "a legend ending up with a row nothing ever matches"; this is
    /// the other direction, and it had already happened. `provenance_unknown` was added to the
    /// enum and never to `app.js`, so a reader whose accusation was withheld for the one reason
    /// that is about *our record* rather than about their package got the generic fallback
    /// sentence instead.
    ///
    /// Existence, not wording: the sentences are written twice — [`Withheld::sentence`] and the
    /// `withheldTitle` table — and a test that pinned the text would just be a third copy. The
    /// duplication itself is filed; this stops the two from losing a row.
    #[test]
    fn every_withheld_reason_has_a_row_in_the_page_that_renders_it() {
        let js = include_str!("../ui/app.js");
        let table = js
            .split_once("const withheldTitle")
            .expect("the page still renders a reason for a withheld row")
            .1;
        let table = &table[..table.find("}[pub.because]").expect("the table is an object literal")];
        for w in [
            Withheld::AwaitingConfirmation,
            Withheld::AttemptsDisagree,
            Withheld::OpenEgress,
            Withheld::GuardTripped,
            Withheld::NonBuiltinStabilizer,
            Withheld::ImageDerivedOutsideBoundary,
            Withheld::ProvenanceUnknown,
            Withheld::KillSwitch,
            Withheld::NoOutcome,
        ] {
            assert!(
                table.contains(&format!("{}:", w.key())),
                "`{}` is a reason the gate can give and the page has no row for it; a reader \
                 would be shown the fallback sentence instead of why their finding was held back",
                w.key()
            );
        }
    }
}
