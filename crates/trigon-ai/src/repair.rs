//! Deciding whether to spend money on a build, and when to stop.
//!
//! The first thing in this crate, before any provider or prompt, because it is the part that
//! decides whether the AI subsystem costs $4,000 or $168,000 for the same work
//! (`docs/07-ai.md` §4). Budgets alone do not do that — they cap the blast radius while leaving the
//! ratio untouched. What changes the ratio is refusing to start.
//!
//! Three rules, each of which exists because the obvious alternative is worse:
//!
//! - **Enter on evidence, not on failure.** A build that failed is not by itself a reason to call a
//!   model. A failure *nobody has repaired before*, on a package people import, is.
//! - **Stop on a repeated signature, not on an iteration count.** If two attempts fail the same
//!   way, the model is not searching, it is restating. This is the cheapest and best stop rule
//!   available and it usually fires long before the iteration cap.
//! - **Escalate on progress, not on frustration.** A more expensive model is worth it when the
//!   cheap one is *getting somewhere* — a different failure, further along. Escalating because the
//!   third attempt failed is paying more for the same answer.
//!
//! Pure and synchronous. It holds no client and makes no call; it is asked a question and returns a
//! decision, which is what makes every rule above a unit test rather than a hope.

use serde::{Deserialize, Serialize};
use trigon_core::{FailureSignature, Phase};

/// What the loop decided to do next.
#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    /// Try a repair. `escalate` asks for the stronger model.
    Attempt {
        escalate: bool,
    },
    Stop(StopReason),
}

/// Why the loop is not going to try again.
///
/// Each variant is a different thing to do about it, which is why this is not a boolean. A budget
/// exhaustion is a knob; a repeated signature is a gap in the rule table; a target below the
/// prevalence threshold is working as intended.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The failure is not one a strategy change can fix. An out-of-memory kill, a registry 503.
    NotRepairable,
    /// This signature has been attempted before, everywhere, and never repaired.
    KnownUnfixable,
    /// Two attempts failed the same way. The model is restating, not searching.
    NoProgress {
        signature: String,
    },
    /// Nobody imports this package, and a sweep has a budget.
    BelowPrevalenceThreshold {
        score: f64,
        threshold: f64,
    },
    IterationCap {
        cap: u32,
    },
    BudgetExhausted {
        what: &'static str,
    },
    /// The build succeeded. Not a failure, and the loop still has to end.
    Repaired,
}

impl StopReason {
    /// Whether this stop is a gap in our own rules rather than a decision working as intended.
    ///
    /// The cluster view ranks on this: a `NoProgress` is a repair we do not know how to make and a
    /// human should see it, while a `BelowPrevalenceThreshold` is the budget doing its job and
    /// showing it to anyone would be noise.
    pub fn wants_attention(&self) -> bool {
        matches!(
            self,
            StopReason::NoProgress { .. } | StopReason::KnownUnfixable
        )
    }
}

/// What one repair attempt cost and how far it got.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub signature: String,
    /// The furthest phase the build reached. Progress is measured against this.
    pub reached: Phase,
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// Of `tokens_in`, how many were served from the provider's cache. A subset, not an addition,
    /// matching the prior art's schema so published cost figures stay comparable.
    pub cached_in: u64,
}

/// Per-target limits. `docs/07-ai.md` §4.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub max_iterations: u32,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub wall_seconds: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_iterations: 6,
            tokens_in: 500_000,
            tokens_out: 30_000,
            wall_seconds: 20 * 60,
        }
    }
}

/// What the world knows about a failure signature, from outside this run.
///
/// A trait rather than a struct because the answer comes from the fleet's history at scale and from
/// a fixture in a test, and the loop should not know which.
pub trait Prior {
    /// Whether this signature has ever been repaired anywhere.
    ///
    /// `false` is the expensive answer: it means every attempt so far has failed, and a new one
    /// will probably fail too. It is the single biggest saving available, because unfixable
    /// signatures are exactly the ones that recur across thousands of targets.
    fn ever_repaired(&self, signature: &str) -> bool;

    /// Whether we have seen this signature before at all. A novel failure is worth a look even if
    /// the package is obscure, because what is learned generalizes.
    fn is_novel(&self, signature: &str) -> bool;
}

/// Nothing known. Every signature is novel and none has been repaired.
///
/// The right default for a cold start and for a single interactive run, where there is no history
/// to consult and refusing on its absence would refuse everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPrior;

impl Prior for NoPrior {
    fn ever_repaired(&self, _signature: &str) -> bool {
        false
    }
    fn is_novel(&self, _signature: &str) -> bool {
        true
    }
}

/// Why we are here, which changes what we are willing to spend.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Trigger {
    /// A person is waiting. Admission control is off: they asked, and the cost is one target's.
    Interactive,
    /// A sweep. Every gate applies, because the cost is one target's times a hundred thousand.
    Sweep {
        /// Normalized dependency-graph prevalence, 0.0 to 1.0.
        prevalence: f64,
    },
}

/// The repair loop's bookkeeping. Holds no client and makes no call.
#[derive(Clone, Debug)]
pub struct RepairLoop {
    budget: Budget,
    trigger: Trigger,
    prevalence_threshold: f64,
    attempts: Vec<Attempt>,
}

impl RepairLoop {
    pub fn new(budget: Budget, trigger: Trigger) -> Self {
        RepairLoop {
            budget,
            trigger,
            prevalence_threshold: 0.01,
            attempts: Vec::new(),
        }
    }

    pub fn with_prevalence_threshold(mut self, t: f64) -> Self {
        self.prevalence_threshold = t;
        self
    }

    pub fn attempts(&self) -> &[Attempt] {
        &self.attempts
    }

    /// Record what an attempt cost and how far it got.
    pub fn record(&mut self, a: Attempt) {
        self.attempts.push(a);
    }

    pub fn tokens_in(&self) -> u64 {
        self.attempts.iter().map(|a| a.tokens_in).sum()
    }

    pub fn tokens_out(&self) -> u64 {
        self.attempts.iter().map(|a| a.tokens_out).sum()
    }

    /// The share of input tokens served from the provider's cache.
    ///
    /// A first-class SLO, target above 0.7. It is the difference between a prompt built
    /// `[stable prelude | stable tools | volatile target]` and one that interleaves them, and it is
    /// invisible unless measured.
    pub fn cache_read_rate(&self) -> Option<f64> {
        let total: u64 = self.attempts.iter().map(|a| a.tokens_in).sum();
        (total > 0)
            .then(|| self.attempts.iter().map(|a| a.cached_in).sum::<u64>() as f64 / total as f64)
    }

    /// Whether to attempt a repair, given what just happened.
    pub fn next(&self, failure: &FailureSignature, prior: &dyn Prior, elapsed_s: u64) -> Decision {
        let key = failure.key();

        // First, the failure itself. Nothing below matters if no strategy can fix it — and this is
        // checked before the budget so that an out-of-memory kill costs nothing even on the first
        // iteration of an interactive run.
        if !failure.repairable {
            return Decision::Stop(StopReason::NotRepairable);
        }

        // Two attempts that failed the same way. Checked before the budget too: the point is to
        // stop early, and a rule that only fires once the budget runs out is the iteration cap
        // wearing a different name.
        if self.attempts.iter().filter(|a| a.signature == key).count() >= 2 {
            return Decision::Stop(StopReason::NoProgress { signature: key });
        }

        if self.attempts.len() as u32 >= self.budget.max_iterations {
            return Decision::Stop(StopReason::IterationCap {
                cap: self.budget.max_iterations,
            });
        }
        if self.tokens_in() >= self.budget.tokens_in {
            return Decision::Stop(StopReason::BudgetExhausted {
                what: "input tokens",
            });
        }
        if self.tokens_out() >= self.budget.tokens_out {
            return Decision::Stop(StopReason::BudgetExhausted {
                what: "output tokens",
            });
        }
        if elapsed_s >= self.budget.wall_seconds {
            return Decision::Stop(StopReason::BudgetExhausted { what: "wall clock" });
        }

        // Admission control, and only for a sweep. Interactive use has already passed the only
        // gate that matters: somebody asked.
        if let Trigger::Sweep { prevalence } = self.trigger {
            // A signature nobody has ever repaired will probably not be repaired now, and these are
            // exactly the ones that recur across thousands of targets.
            if !prior.is_novel(&key) && !prior.ever_repaired(&key) {
                return Decision::Stop(StopReason::KnownUnfixable);
            }
            // Novelty overrides prevalence: what is learned from an unseen failure generalizes to
            // every target that hits it later, however obscure the one in hand.
            if prevalence < self.prevalence_threshold && !prior.is_novel(&key) {
                return Decision::Stop(StopReason::BelowPrevalenceThreshold {
                    score: prevalence,
                    threshold: self.prevalence_threshold,
                });
            }
        }

        Decision::Attempt {
            escalate: self.should_escalate(&key),
        }
    }

    /// Whether the next attempt is worth the stronger model.
    ///
    /// Progress, not frustration: the cheap model earns an escalation by producing a *different*
    /// failure that is also *further along*. One without the other is not progress — a new error in
    /// the same phase is a lateral move, and the same error later is usually the same error.
    fn should_escalate(&self, key: &str) -> bool {
        const CHEAP_ITERATIONS: usize = 3;
        if self.attempts.len() < CHEAP_ITERATIONS {
            return false;
        }
        let Some(last) = self.attempts.last() else {
            return false;
        };
        let moved_on = last.signature != key;
        let got_further = self
            .attempts
            .iter()
            .rev()
            .skip(1)
            .take(1)
            .all(|prev| last.reached > prev.reached);
        moved_on && got_further
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trigon_core::Fault;

    fn sig(code: &'static str, repairable: bool) -> FailureSignature {
        FailureSignature {
            code,
            subject: None,
            fault: Fault::Build,
            retryable: false,
            repairable,
            evidence: String::new(),
        }
    }

    fn attempt(signature: &str, reached: Phase) -> Attempt {
        Attempt {
            signature: signature.into(),
            reached,
            tokens_in: 1_000,
            tokens_out: 100,
            cached_in: 800,
        }
    }

    struct Known {
        novel: bool,
        repaired: bool,
    }
    impl Prior for Known {
        fn ever_repaired(&self, _: &str) -> bool {
            self.repaired
        }
        fn is_novel(&self, _: &str) -> bool {
            self.novel
        }
    }

    #[test]
    fn a_failure_no_strategy_can_fix_costs_nothing_even_on_the_first_iteration() {
        let l = RepairLoop::new(Budget::default(), Trigger::Interactive);
        assert_eq!(
            l.next(&sig("env/out-of-memory", false), &NoPrior, 0),
            Decision::Stop(StopReason::NotRepairable)
        );
    }

    #[test]
    fn the_same_failure_twice_stops_the_loop() {
        // The cheapest and best stop rule available, and it fires long before the iteration cap.
        let mut l = RepairLoop::new(Budget::default(), Trigger::Interactive);
        let f = sig("cc/missing-header", true);
        l.record(attempt(&f.key(), Phase::Build));
        assert!(matches!(l.next(&f, &NoPrior, 0), Decision::Attempt { .. }));
        l.record(attempt(&f.key(), Phase::Build));
        assert_eq!(
            l.next(&f, &NoPrior, 0),
            Decision::Stop(StopReason::NoProgress {
                signature: "cc/missing-header".into()
            })
        );
    }

    #[test]
    fn a_different_failure_each_time_keeps_going() {
        // Changing failures mean the model is searching. That is what we are paying for.
        let mut l = RepairLoop::new(Budget::default(), Trigger::Interactive);
        for (i, code) in ["a/one", "b/two", "c/three"].into_iter().enumerate() {
            assert!(
                matches!(
                    l.next(&sig(code, true), &NoPrior, 0),
                    Decision::Attempt { .. }
                ),
                "stopped at iteration {i}"
            );
            l.record(attempt(code, Phase::Build));
        }
    }

    #[test]
    fn escalation_needs_progress_not_frustration() {
        let f = sig("d/four", true);
        // Three cheap iterations that went nowhere: same phase every time. No escalation, because
        // paying more for the same answer is the failure mode this rule exists to prevent.
        let mut stuck = RepairLoop::new(Budget::default(), Trigger::Interactive);
        for code in ["a/one", "b/two", "c/three"] {
            stuck.record(attempt(code, Phase::Deps));
        }
        assert_eq!(
            stuck.next(&f, &NoPrior, 0),
            Decision::Attempt { escalate: false }
        );

        // Three iterations that got further each time, ending somewhere new.
        let mut moving = RepairLoop::new(Budget::default(), Trigger::Interactive);
        moving.record(attempt("a/one", Phase::Setup));
        moving.record(attempt("b/two", Phase::Deps));
        moving.record(attempt("c/three", Phase::Build));
        assert_eq!(
            moving.next(&f, &NoPrior, 0),
            Decision::Attempt { escalate: true }
        );
    }

    #[test]
    fn a_later_phase_with_the_same_failure_is_not_progress() {
        // The same error further along is usually the same error. Escalating on it pays more to
        // rediscover it.
        let f = sig("c/three", true);
        let mut l = RepairLoop::new(Budget::default(), Trigger::Interactive);
        l.record(attempt("a/one", Phase::Setup));
        l.record(attempt("b/two", Phase::Deps));
        l.record(attempt(&f.key(), Phase::Build));
        assert_eq!(
            l.next(&f, &NoPrior, 0),
            Decision::Attempt { escalate: false }
        );
    }

    #[test]
    fn a_sweep_refuses_a_signature_nobody_has_ever_repaired() {
        // The single biggest saving available: unfixable signatures are exactly the ones that recur
        // across thousands of targets.
        let l = RepairLoop::new(Budget::default(), Trigger::Sweep { prevalence: 0.9 });
        let known_bad = Known {
            novel: false,
            repaired: false,
        };
        assert_eq!(
            l.next(&sig("x/hopeless", true), &known_bad, 0),
            Decision::Stop(StopReason::KnownUnfixable)
        );
    }

    #[test]
    fn an_interactive_run_is_not_subject_to_admission_control() {
        // Somebody asked. That is the gate, and the cost is one target's.
        let l = RepairLoop::new(Budget::default(), Trigger::Interactive);
        let known_bad = Known {
            novel: false,
            repaired: false,
        };
        assert!(matches!(
            l.next(&sig("x/hopeless", true), &known_bad, 0),
            Decision::Attempt { .. }
        ));
    }

    #[test]
    fn novelty_beats_prevalence_because_what_is_learned_generalizes() {
        let l = RepairLoop::new(Budget::default(), Trigger::Sweep { prevalence: 0.0001 });
        let seen = Known {
            novel: false,
            repaired: true,
        };
        assert!(matches!(
            l.next(&sig("y/rare", true), &seen, 0),
            Decision::Stop(StopReason::BelowPrevalenceThreshold { .. })
        ));
        let unseen = Known {
            novel: true,
            repaired: false,
        };
        assert!(matches!(
            l.next(&sig("y/rare", true), &unseen, 0),
            Decision::Attempt { .. }
        ));
    }

    #[test]
    fn every_budget_dimension_stops_the_loop() {
        let f = sig("z/whatever", true);
        let budget = Budget {
            max_iterations: 2,
            tokens_in: 5_000,
            tokens_out: 500,
            wall_seconds: 60,
        };

        let mut iters = RepairLoop::new(budget, Trigger::Interactive);
        iters.record(attempt("a/one", Phase::Deps));
        iters.record(attempt("b/two", Phase::Deps));
        assert_eq!(
            iters.next(&f, &NoPrior, 0),
            Decision::Stop(StopReason::IterationCap { cap: 2 })
        );

        let mut tokens = RepairLoop::new(
            Budget {
                max_iterations: 99,
                ..budget
            },
            Trigger::Interactive,
        );
        tokens.record(Attempt {
            tokens_in: 6_000,
            ..attempt("a/one", Phase::Deps)
        });
        assert_eq!(
            tokens.next(&f, &NoPrior, 0),
            Decision::Stop(StopReason::BudgetExhausted {
                what: "input tokens"
            })
        );

        let wall = RepairLoop::new(
            Budget {
                max_iterations: 99,
                ..budget
            },
            Trigger::Interactive,
        );
        assert_eq!(
            wall.next(&f, &NoPrior, 61),
            Decision::Stop(StopReason::BudgetExhausted { what: "wall clock" })
        );
    }

    #[test]
    fn a_stop_that_is_the_budget_working_is_not_reported_as_a_gap() {
        // The cluster view ranks on this. A repair we do not know how to make is a ticket; a target
        // the budget declined is the budget doing its job.
        assert!(
            StopReason::NoProgress {
                signature: "a".into()
            }
            .wants_attention()
        );
        assert!(StopReason::KnownUnfixable.wants_attention());
        assert!(
            !StopReason::BelowPrevalenceThreshold {
                score: 0.0,
                threshold: 0.01
            }
            .wants_attention()
        );
        assert!(!StopReason::Repaired.wants_attention());
    }

    #[test]
    fn the_cache_read_rate_is_measured_because_it_is_an_slo() {
        let mut l = RepairLoop::new(Budget::default(), Trigger::Interactive);
        assert_eq!(
            l.cache_read_rate(),
            None,
            "no attempts is not a rate of zero"
        );
        l.record(attempt("a/one", Phase::Deps));
        assert_eq!(l.cache_read_rate(), Some(0.8));
    }
}
