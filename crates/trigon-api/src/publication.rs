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
            Withheld::KillSwitch => "kill_switch",
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
    /// Whether any applied stabilizer carried non-`Builtin` provenance, read from the comparison.
    pub non_builtin_stabilizer: bool,
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
    if c.non_builtin_stabilizer {
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

    // Safeguard 5. Last, because it is a deliberate operator intervention and the page should say
    // *that* rather than whichever structural reason happened to be checked first.
    if accusatory && s.stop_divergences {
        return Publication::Withheld {
            because: Withheld::KillSwitch,
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
                non_builtin_stabilizer: non_builtin,
                ..confirmed()
            };
            let d = decide(&r, c, Switches::default());
            assert_eq!(d, Publication::Void { because: expect });
            assert!(d.is_public(), "a void is shown, not hidden");
        }
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
}
