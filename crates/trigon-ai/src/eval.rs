//! Labelling a corpus by the capability a target needs, and scoring a run against it.
//!
//! The argument for this, from `docs/07-ai.md` §6.2, in one sentence: **a model change that raises
//! the aggregate pass rate while making the model fire on `trivial-deterministic` targets is a
//! regression, and a single number would never show it.**
//!
//! That is not a hypothetical. Everything measured in this project so far moved because of
//! deterministic work — PyPI went from 33% to 80% on three fixes with no model involved — and the
//! milestone this serves requires the model-invocation rate to trend *down* while the pass rate
//! goes up. Those two can only be read together against a corpus that says what each target was
//! supposed to need.
//!
//! Labels are assigned by a human and checked by a run, not inferred from one. A label derived from
//! the outcome would make every scorecard tautological: the corpus would say a target needs
//! whatever it turned out to need, and a regression would relabel itself rather than show up.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a target is expected to require.
///
/// Ordered from cheapest to most expensive, and the order is used: a run that needed *more* than
/// its label is the interesting direction, and a run that needed less is a fix worth relabelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Reproduces from a deterministic strategy with no search of any kind. **Any model invocation
    /// on one of these is a regression**, however good the answer.
    TrivialDeterministic,
    /// The registry does not record a commit, so the source has to be found.
    NeedsSourceDiscovery,
    /// The published artifact contains output the ecosystem's default packaging command does not
    /// produce — a compiled `dist/`, a generated file — so a build step has to be inferred from the
    /// repository or its CI.
    ///
    /// **Not in `docs/07-ai.md` §6.2's list**, and added because the corpus contained one:
    /// `escalade 3.2.0` publishes `dist/index.js` and `dist/index.mjs` that `npm pack` alone never
    /// creates. None of the four `needs-repair-*` labels fits — nothing is being *repaired*, a
    /// recipe is missing — and filing it under the nearest one would have hidden the most common
    /// thing the Builder is actually for. Recorded in `docs/16-findings.md`.
    NeedsBuildInference,
    NeedsRepairTimestamp,
    NeedsRepairPath,
    NeedsRepairToolchain,
    NeedsRepairDeps,
    /// Known not to reproduce, for a reason somebody has written down. Kept in the corpus on
    /// purpose: a change that makes one of these pass is either a real advance or a bug in the
    /// comparison, and both are worth a second look.
    KnownUnreproducible,
}

impl Capability {
    /// Whether a model invocation on a target with this label is by itself a regression.
    pub fn forbids_model(self) -> bool {
        self == Capability::TrivialDeterministic
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Capability::TrivialDeterministic => "trivial-deterministic",
            Capability::NeedsSourceDiscovery => "needs-source-discovery",
            Capability::NeedsBuildInference => "needs-build-inference",
            Capability::NeedsRepairTimestamp => "needs-repair-timestamp",
            Capability::NeedsRepairPath => "needs-repair-path",
            Capability::NeedsRepairToolchain => "needs-repair-toolchain",
            Capability::NeedsRepairDeps => "needs-repair-deps",
            Capability::KnownUnreproducible => "known-unreproducible",
        }
    }
}

/// One labelled target.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Labelled {
    pub purl: String,
    pub capability: Capability,
    /// Why it carries this label. Required, and not decoration: a label with no reason is a label
    /// nobody can argue with, and the corpus is the thing every later claim is measured against.
    pub reason: String,
}

/// What one target did on one run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub purl: String,
    /// `exact`, `normalized`, `normalized_with_caveats`, `divergent`, or absent where the run never
    /// reached a comparison. A string, for the same reason it is one on the wire.
    pub outcome: Option<String>,
    /// How many times a model was called for this target. Zero is the expected value for most of a
    /// healthy corpus, and the only acceptable value for `trivial-deterministic`.
    pub model_calls: u32,
    /// Whether the run said anything about the package at all. An infrastructure fault is not an
    /// unreproducible package, and counting it as one makes a rate a measure of our own
    /// reliability.
    pub is_evidence: bool,
}

impl Observation {
    fn reproduced(&self) -> bool {
        matches!(
            self.outcome.as_deref(),
            Some("exact" | "normalized" | "normalized_with_caveats")
        )
    }
}

/// A run scored against the corpus it was run on.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Scorecard {
    /// Reproduced over targets that produced evidence, per label. The headline, split, because the
    /// aggregate is what hides the regression this whole module exists to catch.
    pub by_capability: BTreeMap<String, Rate>,
    /// Targets whose label forbids a model and which called one anyway. **Any entry here is a
    /// regression**, whatever happened to the rate.
    pub forbidden_model_calls: Vec<String>,
    /// Labelled targets the run did not report on. Named rather than counted: a corpus quietly
    /// shrinking is how a rate improves without anything improving.
    pub missing: Vec<String>,
    /// Reported targets that are not in the corpus, which means the two have drifted apart.
    pub unlabelled: Vec<String>,
    pub model_calls: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    pub reproduced: u32,
    /// Targets that produced evidence. Not the same as the number of targets: a build our own
    /// infrastructure could not run belongs in neither numerator nor denominator.
    pub evidence: u32,
    pub total: u32,
}

impl Rate {
    /// `None` when nothing produced evidence, rather than zero.
    ///
    /// A corpus where every run errored has no rate, and reporting 0% would read as "nothing
    /// reproduces" when the truth is "nothing was tested".
    pub fn fraction(&self) -> Option<f64> {
        (self.evidence > 0).then(|| self.reproduced as f64 / self.evidence as f64)
    }
}

impl Scorecard {
    /// Whether this run is acceptable against its corpus.
    ///
    /// Deliberately not "did the rate go up". A model firing where it was forbidden fails
    /// regardless of the rate, and that asymmetry is the entire point of labelling.
    pub fn acceptable(&self) -> bool {
        self.forbidden_model_calls.is_empty() && self.missing.is_empty()
    }
}

/// Score observations against a labelled corpus.
pub fn score(corpus: &[Labelled], observed: &[Observation]) -> Scorecard {
    let by_purl: BTreeMap<&str, &Observation> =
        observed.iter().map(|o| (o.purl.as_str(), o)).collect();
    let labelled: BTreeMap<&str, &Labelled> = corpus.iter().map(|l| (l.purl.as_str(), l)).collect();

    let mut card = Scorecard::default();
    for l in corpus {
        let Some(o) = by_purl.get(l.purl.as_str()) else {
            card.missing.push(l.purl.clone());
            continue;
        };
        let r = card
            .by_capability
            .entry(l.capability.as_str().to_string())
            .or_default();
        r.total += 1;
        if o.is_evidence {
            r.evidence += 1;
            if o.reproduced() {
                r.reproduced += 1;
            }
        }
        card.model_calls += o.model_calls;
        if l.capability.forbids_model() && o.model_calls > 0 {
            card.forbidden_model_calls.push(l.purl.clone());
        }
    }
    for o in observed {
        if !labelled.contains_key(o.purl.as_str()) {
            card.unlabelled.push(o.purl.clone());
        }
    }
    card
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labelled(purl: &str, capability: Capability) -> Labelled {
        Labelled {
            purl: purl.into(),
            capability,
            reason: "because".into(),
        }
    }

    fn observed(purl: &str, outcome: Option<&str>, calls: u32) -> Observation {
        Observation {
            purl: purl.into(),
            outcome: outcome.map(str::to_string),
            model_calls: calls,
            is_evidence: outcome.is_some(),
        }
    }

    #[test]
    fn a_model_firing_where_it_is_forbidden_fails_however_good_the_rate() {
        // The regression a single aggregate number cannot show, and the reason this module exists:
        // every target reproduced, so the headline improved, and a model fired on one that was
        // supposed to need nothing.
        let corpus = vec![
            labelled("pkg:npm/a@1", Capability::TrivialDeterministic),
            labelled("pkg:npm/b@1", Capability::NeedsRepairToolchain),
        ];
        let run = vec![
            observed("pkg:npm/a@1", Some("exact"), 1),
            observed("pkg:npm/b@1", Some("normalized"), 3),
        ];
        let card = score(&corpus, &run);
        assert_eq!(
            card.by_capability["trivial-deterministic"].fraction(),
            Some(1.0),
            "the rate is perfect"
        );
        assert_eq!(card.forbidden_model_calls, ["pkg:npm/a@1"]);
        assert!(!card.acceptable(), "and the run is still a regression");
    }

    #[test]
    fn a_corpus_that_quietly_shrinks_is_caught() {
        // The other way a rate improves without anything improving. Named rather than counted, so
        // the report says which targets stopped being measured.
        let corpus = vec![
            labelled("pkg:npm/a@1", Capability::TrivialDeterministic),
            labelled("pkg:npm/hard@1", Capability::KnownUnreproducible),
        ];
        let run = vec![observed("pkg:npm/a@1", Some("exact"), 0)];
        let card = score(&corpus, &run);
        assert_eq!(card.missing, ["pkg:npm/hard@1"]);
        assert!(!card.acceptable());
    }

    #[test]
    fn a_target_nobody_labelled_is_reported_rather_than_scored() {
        // The corpus and the sweep drifting apart is a thing to fix, not to average over.
        let corpus = vec![labelled("pkg:npm/a@1", Capability::TrivialDeterministic)];
        let run = vec![
            observed("pkg:npm/a@1", Some("exact"), 0),
            observed("pkg:npm/surprise@1", Some("divergent"), 0),
        ];
        let card = score(&corpus, &run);
        assert_eq!(card.unlabelled, ["pkg:npm/surprise@1"]);
        assert_eq!(card.by_capability["trivial-deterministic"].total, 1);
    }

    #[test]
    fn a_run_that_produced_no_evidence_has_no_rate_rather_than_zero() {
        // "Nothing reproduces" and "nothing was tested" are different findings, and 0% says the
        // first when the truth is the second.
        let corpus = vec![labelled("pkg:npm/a@1", Capability::TrivialDeterministic)];
        let run = vec![Observation {
            purl: "pkg:npm/a@1".into(),
            outcome: None,
            model_calls: 0,
            is_evidence: false,
        }];
        let card = score(&corpus, &run);
        let r = &card.by_capability["trivial-deterministic"];
        assert_eq!(r.total, 1);
        assert_eq!(r.evidence, 0);
        assert_eq!(r.fraction(), None);
    }

    #[test]
    fn rates_are_split_by_label_because_the_aggregate_hides_the_shape() {
        // Two labels moving in opposite directions read as "no change" in one number.
        let corpus = vec![
            labelled("pkg:npm/a@1", Capability::TrivialDeterministic),
            labelled("pkg:npm/b@1", Capability::TrivialDeterministic),
            labelled("pkg:npm/c@1", Capability::NeedsRepairDeps),
            labelled("pkg:npm/d@1", Capability::NeedsRepairDeps),
        ];
        let run = vec![
            observed("pkg:npm/a@1", Some("exact"), 0),
            observed("pkg:npm/b@1", Some("exact"), 0),
            observed("pkg:npm/c@1", Some("divergent"), 0),
            observed("pkg:npm/d@1", Some("divergent"), 0),
        ];
        let card = score(&corpus, &run);
        assert_eq!(
            card.by_capability["trivial-deterministic"].fraction(),
            Some(1.0)
        );
        assert_eq!(
            card.by_capability["needs-repair-deps"].fraction(),
            Some(0.0)
        );
    }

    #[test]
    fn an_infrastructure_failure_is_in_neither_numerator_nor_denominator() {
        // Counting our own faults against packages makes a reproduction rate a measure of our
        // reliability wearing the costume of a claim about packages.
        let corpus = vec![
            labelled("pkg:npm/a@1", Capability::TrivialDeterministic),
            labelled("pkg:npm/b@1", Capability::TrivialDeterministic),
        ];
        let run = vec![
            observed("pkg:npm/a@1", Some("exact"), 0),
            Observation {
                purl: "pkg:npm/b@1".into(),
                outcome: None,
                model_calls: 0,
                is_evidence: false,
            },
        ];
        let r = &score(&corpus, &run).by_capability["trivial-deterministic"];
        assert_eq!((r.total, r.evidence, r.reproduced), (2, 1, 1));
        assert_eq!(r.fraction(), Some(1.0), "one of one tested, not one of two");
    }

    #[test]
    fn a_label_carries_its_reason_through_a_round_trip() {
        // The corpus is a file somebody edits and everything later is measured against it. A label
        // with no reason is one nobody can argue with.
        let l = labelled("pkg:npm/a@1", Capability::KnownUnreproducible);
        let back: Labelled = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back, l);
        assert_eq!(
            serde_json::to_value(Capability::NeedsRepairToolchain).unwrap(),
            "needs-repair-toolchain"
        );
    }
}
