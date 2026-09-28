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
use std::time::Duration;
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
    /// Safeguard 1, "on different workers at different times", **unevaluated**. The attempts
    /// that agree do not all record which machine ran them and when they began, so whether the
    /// second is independent of the first cannot be checked. Every run recorded before
    /// `docs/19` §10 phase 3 is one.
    ConfirmationUnrecorded,
    /// Safeguard 1, "at different times". The second agreeing attempt began less than
    /// `[publish] confirmation_interval` after the first.
    AttemptsTooClose,
    /// Safeguard 1, "on different workers". The attempts that agree ran on one machine, or on
    /// machines their records cannot tell apart, and `[publish] same_host_confirmation` (`docs/19`
    /// D8) is off.
    ///
    /// "Cannot tell apart" is two different host ids where either was derived from a hostname:
    /// every container has a hostname of its own, so two of them name two containers, which may
    /// be on one machine (`trigon_store::names_a_machine`).
    SameHost,
    /// Safeguard 1 under D8. The attempts ran on one machine, or on machines their records cannot
    /// tell apart, which the operator accepts only when the confirming attempt was cold with its
    /// base image re-pulled by digest, and it was not.
    ConfirmationNotCold,
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
            Withheld::ConfirmationUnrecorded => "confirmation_unrecorded",
            Withheld::AttemptsTooClose => "attempts_too_close",
            Withheld::SameHost => "same_host",
            Withheld::ConfirmationNotCold => "confirmation_not_cold",
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
            Withheld::ConfirmationUnrecorded => {
                "the attempts that agree do not all record which machine ran them and when they \
                 began, so whether the second is independent of the first cannot be checked. A \
                 confirmation is not accepted on a safeguard nobody could evaluate."
            }
            Withheld::AttemptsTooClose => {
                "the attempts that agree began closer together than the confirmation interval \
                 allows. Two runs moments apart sample the same state of every registry, so the \
                 second cannot catch a floating dependency or a fetch that happened to succeed."
            }
            Withheld::SameHost => {
                "the attempts that agree ran on one machine, or on machines their records cannot \
                 tell apart, and this operator does not accept a confirmation from the machine \
                 that made the first attempt: nothing that machine holds constant could make the \
                 two disagree."
            }
            Withheld::ConfirmationNotCold => {
                "the attempts that agree ran on one machine, or on machines their records cannot \
                 tell apart, and the second was not cold: it could reuse a build cache, or did not \
                 pull its base image again by digest, so it may have replayed the first attempt \
                 rather than repeated it."
            }
            Withheld::OpenEgress => {
                "the build ran with unrestricted network access, so nothing it produced is evidence \
                 about the package."
            }
            Withheld::GuardTripped => {
                "the build reached the published artifact over the network, so a match would prove \
                 only that it downloaded it."
            }
            // Said of every run this voids, a match among them: `decide` voids on this clause
            // whatever the outcome. It said "void rather than a divergence", which told a reader
            // that a package that reproduced would otherwise have been accused.
            Withheld::NonBuiltinStabilizer => {
                "a stabilizer a person or a model wrote was applied, so the normalization is itself \
                 a judgement call, and the run is evidence of nothing about the package in either \
                 direction."
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

/// What an operator chooses about the gate: safeguard 5's kill-switch, and safeguard 1's
/// confirmation settings. Nothing else about it is a setting.
#[derive(Clone, Copy, Debug, Default)]
pub struct Switches {
    /// Safeguard 5's kill-switch. Set it and divergences stop publishing until a human clears it;
    /// matches are unaffected, because a false match is an error and a false divergence is an
    /// accusation.
    pub stop_divergences: bool,
    /// What makes a second agreeing attempt a confirmation, from `[publish]` in `evidence.toml`
    /// wherever the gate runs (`docs/19` §2.4).
    pub confirmation: Confirmation,
}

/// Safeguard 1's settings: when two agreeing attempts count as two.
///
/// ADR-0010 asks for attempts "on different workers at different times", because the risk that
/// dominates is ambient nondeterminism, and two attempts that shared a machine and a moment share
/// most of it. `docs/19` D8 asks whether one machine may confirm itself; these are its answer and
/// the interval, as the operator set them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmation {
    /// `[publish] same_host_confirmation`. Whether two attempts on one machine may confirm each
    /// other — and then only where the confirming attempt ran cold, its base image re-pulled by
    /// digest.
    pub same_host: bool,
    /// `[publish] confirmation_interval`: the least time between the two attempts' starts.
    pub interval: Duration,
}

impl Default for Confirmation {
    /// The configuration's own defaults, read from where they are defined rather than restated: a
    /// gate built with no configuration file — every test, and `trigon serve` on a machine with
    /// none — decides exactly as one that read an empty file.
    fn default() -> Self {
        Confirmation::from(&trigon_attest::config::PublishConfig::default())
    }
}

impl From<&trigon_attest::config::PublishConfig> for Confirmation {
    fn from(p: &trigon_attest::config::PublishConfig) -> Self {
        Confirmation {
            same_host: p.same_host_confirmation,
            interval: p.confirmation_interval,
        }
    }
}

/// What one attempt recorded about where, how and when it ran: the facts that make a second
/// attempt a confirmation of the first rather than the first replayed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    /// The run, which orders two attempts that began in the same second.
    pub run: String,
    /// `RunRecord::host`. `None` on a record from before hosts were recorded.
    pub host: Option<String>,
    /// When it began, in seconds since the epoch. Read from `RunRecord::started` only beside a
    /// host: before hosts were recorded, a run that reached a comparison wrote the time it
    /// finished there.
    pub began: Option<i64>,
    /// Whether it ran with no cache able to supply it and its base image re-pulled by digest
    /// (`CacheState::independent`). `None` where the record does not say.
    pub independent: Option<bool>,
}

impl Attempt {
    pub fn of(r: &RunRecord) -> Attempt {
        Attempt {
            run: r.id.clone(),
            host: r.host.clone(),
            began: r
                .host
                .as_ref()
                .and_then(|_| trigon_core::time::rfc3339_epoch(&r.started)),
            independent: r.cache.as_ref().map(trigon_store::CacheState::independent),
        }
    }
}

/// The evidence the gate needs beyond the record itself.
///
/// Separated from `RunRecord` because two of the three answers are not on the record: whether a
/// non-`Builtin` stabilizer applied lives in the comparison blob, and whether a second attempt
/// agreed is a fact about a *set* of records. Passing them in keeps [`decide`] a pure function of
/// its arguments, which is what lets it be tested exhaustively rather than through a store.
#[derive(Clone, Debug, Default)]
pub struct Corroboration {
    /// Terminal attempts at the same `cache_key` whose outcome **and agreement digest**
    /// (`RunRecord::agreement`) match this one's, this run's own included, and none of them void:
    /// with what each recorded about where, how and when it ran, which [`decide`] reads to tell a
    /// confirmation from a repeat.
    ///
    /// The agreement digest covers the outcome, the set, the published artifact's raw digest and
    /// both sides' stabilized digests. Matching on the outcome alone let a divergence in one
    /// member confirm a divergence in every other; matching on the stored comparison report's
    /// digest, which names the rebuilt artifact's raw bytes, would let no two honest builds agree.
    /// An attempt whose record carries no agreement digest agrees with nothing, itself aside. A
    /// void attempt is evidence of nothing, so it confirms nothing either.
    pub agreeing_attempts: Vec<Attempt>,
    /// Terminal attempts at the same `cache_key`, none of them void, that reached a *different*
    /// outcome, or the same outcome with a different agreement digest: a divergence that found
    /// something else is a disagreement, not a confirmation.
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

/// Whether [`decide`] calls this run void, and why, for a caller holding the one record.
///
/// `trigon attest` asks this, and signs `void/v1` and no verdict for a run it answers: the answer
/// is `decide`'s own, because every clause that voids a run reads the record alone — the index
/// hands `decide` the record's own provenance bit, for a run with no cache key as for any other —
/// so the attempts at the same work, the kill-switch and the confirmation settings, which it cannot
/// see, cannot change it. That is why `trigon attest` reads the settings from the configuration and
/// passes none of them here.
/// The index's test `the_index_voids_exactly_the_runs_the_attestor_calls_void` holds the two to
/// each other through the index itself, not through a `Corroboration` built by hand.
pub fn voided(r: &RunRecord) -> Option<Withheld> {
    void_clause(r, r.non_builtin_stabilizer)
}

/// Safeguard 2's clauses, in order.
///
/// **A guard trip first, and whether or not the run reached an outcome.** A tripped guard ends
/// the build, so a real void run has no outcome, and asking for one first withheld it as
/// `NoOutcome`: a run that is publishable as a void — it makes no claim a second attempt could
/// confirm — was not published at all, and `trigon attest` could not sign the void it is. The
/// other two clauses describe a comparison that reached an outcome, and a run that reached none
/// is not voided by them: a build that failed at open egress is a failed build, not a void.
fn void_clause(r: &RunRecord, non_builtin_stabilizer: Option<bool>) -> Option<Withheld> {
    if !r.guard_trips.is_empty() {
        return Some(Withheld::GuardTripped);
    }
    r.outcome.as_ref()?;
    if r.environment.egress.eq_ignore_ascii_case("open") {
        return Some(Withheld::OpenEgress);
    }
    if non_builtin_stabilizer == Some(true) {
        return Some(Withheld::NonBuiltinStabilizer);
    }
    None
}

/// The five safeguards, in the order they can each stop a row, for one run.
///
/// **Order is load-bearing.** Safeguard 2's clauses are checked before safeguard 1's, because a run
/// with an open egress tier publishes as `Void` — a shown, useful, non-accusatory result — whereas
/// an unconfirmed run is withheld entirely. Checking confirmation first would hide behind
/// "awaiting confirmation" a run that we already know can never be a divergence, and the reader
/// would be told to wait for something that would not change the answer.
pub fn decide(r: &RunRecord, c: &Corroboration, s: Switches) -> Publication {
    // Safeguard 2. Each clause converts a divergence into a void rather than suppressing it.
    if let Some(because) = void_clause(r, c.non_builtin_stabilizer) {
        return Publication::Void { because };
    }
    let Some(outcome) = r.outcome.as_deref() else {
        return Publication::Withheld {
            because: Withheld::NoOutcome,
        };
    };
    let accusatory = outcome == "divergent";

    // Safeguard 1. Two agreeing attempts, divergences and matches alike — the ADR says "alike" and
    // means it, because a false `Reproduced` published from one lucky build is still wrong.
    if c.disagreeing_attempts > 0 {
        return Publication::Withheld {
            because: Withheld::AttemptsDisagree,
        };
    }
    if c.agreeing_attempts.len() < 2 {
        return Publication::Withheld {
            because: Withheld::AwaitingConfirmation,
        };
    }
    // "On different workers at different times": two agreeing records are two attempts only if
    // the second could have come out differently. Checked here, in the gate, against the
    // operator's settings, so `serve`, `attest` and `publish` cannot each decide it their own way.
    if let Err(because) = confirmed(&c.agreeing_attempts, s.confirmation) {
        return Publication::Withheld { because };
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

/// Whether some pair of agreeing attempts is a confirmation under `rules`, and if none is, why
/// the nearest is not.
///
/// A pair is the earlier attempt and a later one. It confirms when both record a machine and a
/// start, the later began at least `rules.interval` after the earlier, and they ran on two
/// machines — or on one, where `rules.same_host` allows it and the later attempt ran cold with its
/// base image re-pulled. Two machines means two host ids that differ and were both derived from a
/// machine id; a pair any other way is held to what one machine is held to. Any pair that confirms
/// is enough; where none does, the reason given is the one for the pair that met the most of those
/// conditions, in that order, because that is the one an operator is nearest to satisfying and the
/// one worth telling them.
fn confirmed(attempts: &[Attempt], rules: Confirmation) -> Result<(), Withheld> {
    let mut ordered: Vec<&Attempt> = attempts.iter().collect();
    ordered.sort_by(|a, b| a.began.cmp(&b.began).then_with(|| a.run.cmp(&b.run)));
    let mut nearest: Option<Withheld> = None;
    for (i, first) in ordered.iter().enumerate() {
        for second in &ordered[i + 1..] {
            match pair(first, second, rules) {
                Ok(()) => return Ok(()),
                Err(w) if nearest.is_none_or(|n| rank(w) > rank(n)) => nearest = Some(w),
                Err(_) => {}
            }
        }
    }
    Err(nearest.unwrap_or(Withheld::AwaitingConfirmation))
}

/// One pair, `first` the earlier. The conditions in the order [`rank`] counts them.
fn pair(first: &Attempt, second: &Attempt, rules: Confirmation) -> Result<(), Withheld> {
    let (Some(h1), Some(h2), Some(t1), Some(t2)) =
        (&first.host, &second.host, first.began, second.began)
    else {
        return Err(Withheld::ConfirmationUnrecorded);
    };
    let interval = i64::try_from(rules.interval.as_secs()).unwrap_or(i64::MAX);
    if t2.saturating_sub(t1) < interval {
        return Err(Withheld::AttemptsTooClose);
    }
    // Two machines only where both ids say so. An id derived from a hostname names a container as
    // readily as a machine, and two containers on one machine share its kernel, its CPU and often
    // its image store: two such ids that differ are not shown to be two machines, and counting
    // them as two let one machine confirm itself with D8 off.
    if h1 != h2 && trigon_store::names_a_machine(h1) && trigon_store::names_a_machine(h2) {
        return Ok(());
    }
    if !rules.same_host {
        return Err(Withheld::SameHost);
    }
    // The *confirming* attempt, which is the later: one that could reuse what the first left
    // behind is the first one replayed. The first attempt's own state is not asked about, since
    // nothing ran before it on this key that it could have replayed.
    if second.independent != Some(true) {
        return Err(Withheld::ConfirmationNotCold);
    }
    Ok(())
}

/// How far a pair got through [`pair`]'s conditions before one stopped it.
fn rank(w: Withheld) -> u8 {
    match w {
        Withheld::ConfirmationUnrecorded => 0,
        Withheld::AttemptsTooClose => 1,
        Withheld::SameHost => 2,
        Withheld::ConfirmationNotCold => 3,
        _ => 0,
    }
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

    /// One agreeing attempt: on a machine of its own, cold, at `began`.
    fn attempt(run: &str, host: &str, began: i64, independent: bool) -> Attempt {
        Attempt {
            run: run.into(),
            host: Some(host.into()),
            began: Some(began),
            independent: Some(independent),
        }
    }

    /// Two attempts on two machines a day apart, the second warm: a pair every setting accepts,
    /// so a test using it isolates the clause it is about.
    fn two_machines() -> Vec<Attempt> {
        vec![
            attempt("a", "machine-id:one", 0, false),
            attempt("b", "machine-id:two", 86_400, false),
        ]
    }

    fn confirmed() -> Corroboration {
        Corroboration {
            agreeing_attempts: two_machines(),
            ..Default::default()
        }
    }

    /// One attempt, agreeing with nothing but itself.
    fn alone() -> Vec<Attempt> {
        two_machines()[..1].to_vec()
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
            decide(&r, &confirmed_and_evaluated(), Switches::default()),
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
            decide(&r, &confirmed_and_evaluated(), Switches::default()),
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
            decide(&r, &confirmed_and_evaluated(), Switches::default()),
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
                    agreeing_attempts: alone(),
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
                    decide(&with, &c, Switches::default()),
                    decide(&without, &c, Switches::default()),
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
            decide(&r, &Corroboration::default(), Switches::default()),
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
            agreeing_attempts: alone(),
            disagreeing_attempts: 1,
            ..Default::default()
        };
        assert_eq!(
            decide(&r, &c, Switches::default()),
            Publication::Withheld {
                because: Withheld::AttemptsDisagree
            }
        );
    }

    /// `docs/19` §10 phase 3: two agreeing attempts are two only if the second could have come out
    /// differently — on another machine, or on this one cold, and not moments later.
    fn with(attempts: Vec<Attempt>) -> Corroboration {
        Corroboration {
            agreeing_attempts: attempts,
            non_builtin_stabilizer: Some(false),
            ..Default::default()
        }
    }

    fn rules(same_host: bool, interval: u64) -> Switches {
        Switches {
            confirmation: Confirmation {
                same_host,
                interval: Duration::from_secs(interval),
            },
            ..Default::default()
        }
    }

    const HOUR: i64 = 3600;

    #[test]
    fn a_second_attempt_on_another_machine_an_interval_later_confirms() {
        let r = record(Some("divergent"), "mirror-only");
        let c = with(vec![
            attempt("a", "machine-id:one", 0, false),
            attempt("b", "machine-id:two", HOUR, false),
        ]);
        // "At least the interval": a second attempt that began exactly one interval later is
        // far enough apart.
        assert_eq!(decide(&r, &c, rules(false, 3600)), Publication::Published);
    }

    #[test]
    fn a_second_attempt_that_began_too_soon_is_withheld_for_that() {
        let r = record(Some("exact"), "mirror-only");
        let c = with(vec![
            attempt("a", "machine-id:one", 0, true),
            attempt("b", "machine-id:two", HOUR - 1, true),
        ]);
        assert_eq!(
            decide(&r, &c, rules(true, 3600)),
            Publication::Withheld {
                because: Withheld::AttemptsTooClose
            },
            "two runs a second short of the interval sample the same moment, on any machines"
        );
        // And the interval is the operator's: the same pair clears a shorter one.
        assert_eq!(decide(&r, &c, rules(true, 60)), Publication::Published);
    }

    #[test]
    fn a_pair_on_one_machine_is_withheld_unless_the_operator_accepts_one() {
        let r = record(Some("normalized"), "mirror-only");
        let c = with(vec![
            attempt("a", "machine-id:one", 0, true),
            attempt("b", "machine-id:one", 2 * HOUR, true),
        ]);
        assert_eq!(
            decide(&r, &c, rules(false, 3600)),
            Publication::Withheld {
                because: Withheld::SameHost
            },
            "D8 is off by default, and one machine cannot confirm itself however cold"
        );
        assert_eq!(decide(&r, &c, rules(true, 3600)), Publication::Published);
    }

    /// Two different ids show two machines only where both came from a machine id. A hostname is
    /// given to every container, so two workers in containers on one machine — or a run on the
    /// machine and one in a container on it — recorded two ids, and the gate counted them as a
    /// confirmation from another machine with D8 off.
    #[test]
    fn ids_derived_from_hostnames_do_not_show_two_machines() {
        let r = record(Some("divergent"), "mirror-only");
        for (one, two) in [
            ("hostname:one", "hostname:two"),
            ("machine-id:one", "hostname:two"),
            ("hostname:one", "machine-id:two"),
        ] {
            let pair = |second_cold| {
                with(vec![
                    attempt("a", one, 0, false),
                    attempt("b", two, HOUR, second_cold),
                ])
            };
            // Held to what one machine is held to: not counted with D8 off …
            assert_eq!(
                decide(&r, &pair(true), rules(false, 3600)),
                Publication::Withheld {
                    because: Withheld::SameHost
                },
                "{one} and {two}"
            );
            // … and with it on, only where the confirmation was cold and re-pulled.
            assert_eq!(
                decide(&r, &pair(false), rules(true, 3600)),
                Publication::Withheld {
                    because: Withheld::ConfirmationNotCold
                },
                "{one} and {two}"
            );
            assert_eq!(
                decide(&r, &pair(true), rules(true, 3600)),
                Publication::Published,
                "{one} and {two}"
            );
        }
    }

    #[test]
    fn a_same_host_confirmation_has_to_be_cold_and_re_pulled() {
        let r = record(Some("divergent"), "mirror-only");
        // The *confirming* attempt is the later one, and it is the one that has to be cold: the
        // first attempt being cold is no help if the second replayed it.
        for (first_cold, second_cold) in [(false, false), (true, false)] {
            let c = with(vec![
                attempt("a", "machine-id:one", 0, first_cold),
                attempt("b", "machine-id:one", 2 * HOUR, second_cold),
            ]);
            assert_eq!(
                decide(&r, &c, rules(true, 3600)),
                Publication::Withheld {
                    because: Withheld::ConfirmationNotCold
                },
                "first cold: {first_cold}"
            );
        }
        let c = with(vec![
            attempt("a", "machine-id:one", 0, false),
            attempt("b", "machine-id:one", 2 * HOUR, true),
        ]);
        assert_eq!(decide(&r, &c, rules(true, 3600)), Publication::Published);

        // A cache state nobody recorded is not a cold one.
        let mut unrecorded = c.clone();
        unrecorded.agreeing_attempts[1].independent = None;
        assert_eq!(
            decide(&r, &unrecorded, rules(true, 3600)),
            Publication::Withheld {
                because: Withheld::ConfirmationNotCold
            }
        );
    }

    #[test]
    fn attempts_that_do_not_say_where_they_ran_confirm_nothing() {
        let r = record(Some("exact"), "mirror-only");
        let mut c = confirmed();
        c.non_builtin_stabilizer = Some(false);
        c.agreeing_attempts[1].host = None;
        assert_eq!(
            decide(&r, &c, rules(true, 0)),
            Publication::Withheld {
                because: Withheld::ConfirmationUnrecorded
            },
            "a run recorded before hosts were, beside one recorded since, is not shown to be on \
             another machine, and absent is not a different machine"
        );
        let mut c = confirmed();
        c.agreeing_attempts[0].began = None;
        assert_eq!(
            decide(&r, &c, rules(true, 0)),
            Publication::Withheld {
                because: Withheld::ConfirmationUnrecorded
            }
        );
    }

    #[test]
    fn any_pair_that_confirms_is_enough_and_otherwise_the_nearest_is_named() {
        let r = record(Some("exact"), "mirror-only");
        // `b` is too close to `a`, and `c` is on `a`'s machine; `b` and `c` confirm.
        let c = with(vec![
            attempt("a", "machine-id:one", 0, false),
            attempt("b", "machine-id:two", 60, false),
            attempt("c", "machine-id:one", 3 * HOUR, false),
        ]);
        assert_eq!(decide(&r, &c, rules(false, 3600)), Publication::Published);

        // No pair confirms. One pair is unrecorded, one is too close; the nearest is the one
        // that only lacked the interval, and that is what an operator can act on.
        let c = with(vec![
            Attempt {
                run: "a".into(),
                ..Attempt::default()
            },
            attempt("b", "machine-id:one", 0, true),
            attempt("c", "machine-id:two", 60, true),
        ]);
        assert_eq!(
            decide(&r, &c, rules(false, 3600)),
            Publication::Withheld {
                because: Withheld::AttemptsTooClose
            }
        );
    }

    #[test]
    fn with_no_configuration_the_gate_holds_to_the_documented_defaults() {
        // `docs/19` §2.4: `same_host_confirmation = false`, `confirmation_interval = "1h"`. The
        // gate `trigon serve` builds on a machine with no `evidence.toml`.
        assert_eq!(
            Switches::default().confirmation,
            Confirmation {
                same_host: false,
                interval: Duration::from_secs(3600),
            }
        );
    }

    #[test]
    fn the_confirmation_rules_come_after_the_count_and_before_the_kill_switch() {
        let r = record(Some("divergent"), "mirror-only");
        let too_close = with(vec![
            attempt("a", "machine-id:one", 0, false),
            attempt("b", "machine-id:two", 1, false),
        ]);
        // Disagreement is the finding, and outranks how the agreeing pair ran.
        let disagreeing = Corroboration {
            disagreeing_attempts: 1,
            ..too_close.clone()
        };
        assert_eq!(
            decide(&r, &disagreeing, Switches::default()),
            Publication::Withheld {
                because: Withheld::AttemptsDisagree
            }
        );
        // And safeguard 1 is answered before safeguard 5, as it was before these rules.
        assert_eq!(
            decide(
                &r,
                &too_close,
                Switches {
                    stop_divergences: true,
                    ..Default::default()
                }
            ),
            Publication::Withheld {
                because: Withheld::AttemptsTooClose
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
            let d = decide(&r, &c, Switches::default());
            assert_eq!(d, Publication::Void { because: expect });
            assert!(d.is_public(), "a void is shown, not hidden");
        }
    }

    /// A void's reason is shown beside a match as often as beside a divergence, so it may not say
    /// which one it is beside.
    ///
    /// `decide` voids on safeguard 2 before it reads the outcome, so a hand-written pass that made
    /// two sides agree voids the run too. The `NonBuiltinStabilizer` sentence said it "publishes as
    /// void rather than as a divergence", and an anonymous check of a package that reproduced
    /// answered with it: no verdict leaked, and an accusation was planted all the same. Both copies
    /// of the sentence are read, because the page shows the other one.
    #[test]
    fn a_void_says_nothing_about_which_way_the_run_went() {
        let js = include_str!("../ui/app.js");
        let table = js
            .split_once("const withheldTitle")
            .expect("the page still renders a reason")
            .1;
        for (egress, guard, non_builtin, cause) in [
            ("open", false, false, Withheld::OpenEgress),
            ("mirror", true, false, Withheld::GuardTripped),
            ("mirror", false, true, Withheld::NonBuiltinStabilizer),
        ] {
            for outcome in [
                "exact",
                "normalized",
                "normalized_with_caveats",
                "divergent",
            ] {
                let mut r = record(Some(outcome), egress);
                if guard {
                    r.guard_trips
                        .push("the build fetched its own artifact".into());
                }
                let c = Corroboration {
                    non_builtin_stabilizer: Some(non_builtin),
                    ..confirmed()
                };
                assert_eq!(
                    decide(&r, &c, Switches::default()),
                    Publication::Void { because: cause },
                    "{outcome}: the premise, that this reason is given whatever the outcome"
                );
            }
            let row = table
                .split_once(&format!("{}:", cause.key()))
                .and_then(|(_, rest)| rest.lines().next())
                .unwrap_or_else(|| panic!("the page has no row for {cause:?}"));
            for (whose, s) in [("the server's", cause.sentence()), ("the page's", row)] {
                assert!(
                    !s.contains("divergen"),
                    "{whose} sentence for {cause:?} names a divergence, and it is shown for runs \
                     that matched: {s}"
                );
            }
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
            decide(&r, &unknown, Switches::default()),
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
        assert_eq!(
            decide(&r, &known, Switches::default()),
            Publication::Published
        );
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
                decide(&r, &unknown, Switches::default()),
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
                &unknown(Corroboration {
                    agreeing_attempts: alone(),
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
            decide(&r, &unknown(Default::default()), Switches::default()),
            Publication::Withheld {
                because: Withheld::AwaitingConfirmation
            },
            "and waiting for a second attempt is the ordinary state, which re-running also fixes"
        );

        assert_eq!(
            decide(
                &r,
                &unknown(confirmed()),
                Switches {
                    stop_divergences: true,
                    ..Default::default()
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
            decide(&r, &Corroboration::default(), Switches::default()),
            Publication::Void {
                because: Withheld::OpenEgress
            }
        );
    }

    #[test]
    fn the_kill_switch_stops_accusations_and_not_matches() {
        let s = Switches {
            stop_divergences: true,
            ..Default::default()
        };
        let div = record(Some("divergent"), "mirror");
        assert_eq!(
            decide(&div, &confirmed(), s),
            Publication::Withheld {
                because: Withheld::KillSwitch
            }
        );
        let ok = record(Some("exact"), "mirror");
        assert_eq!(decide(&ok, &confirmed(), s), Publication::Published);
    }

    #[test]
    fn a_run_with_no_verdict_is_not_a_verdict() {
        let r = record(None, "mirror");
        assert_eq!(
            decide(&r, &confirmed(), Switches::default()),
            Publication::Withheld {
                because: Withheld::NoOutcome
            }
        );
        // Nor is a build that failed at open egress void: it is a failed build.
        let r = record(None, "open");
        assert_eq!(
            decide(&r, &confirmed(), Switches::default()),
            Publication::Withheld {
                because: Withheld::NoOutcome
            }
        );
        assert_eq!(voided(&r), None);
    }

    #[test]
    fn a_run_the_guard_stopped_is_void_though_it_reached_no_outcome() {
        // What a real void run looks like: the guard ended the build, so there is no comparison
        // and no outcome. It was withheld as `NoOutcome`, so nothing could publish it as the void
        // it is, and `trigon attest` had no void to sign.
        let mut r = record(None, "mirror-only");
        r.guard_trips
            .push("the artifact under test arrived from registry.npmjs.org".into());
        for c in [Corroboration::default(), confirmed()] {
            assert_eq!(
                decide(&r, &c, Switches::default()),
                Publication::Void {
                    because: Withheld::GuardTripped
                }
            );
        }
        assert_eq!(voided(&r), Some(Withheld::GuardTripped));
    }

    /// `voided` is `decide`'s answer about voidness, whatever the attempts and the switches: the
    /// attestor asks it without an index, and signs a void or a verdict on the answer.
    #[test]
    fn voided_agrees_with_decide_whatever_it_cannot_see() {
        let corroborations = [
            Corroboration::default(),
            confirmed(),
            Corroboration {
                agreeing_attempts: alone(),
                disagreeing_attempts: 1,
                ..Default::default()
            },
        ];
        for outcome in [None, Some("exact"), Some("divergent")] {
            for egress in ["open", "mirror-only"] {
                for guard in [false, true] {
                    for non_builtin in [None, Some(false), Some(true)] {
                        let mut r = record(outcome, egress);
                        r.non_builtin_stabilizer = non_builtin;
                        if guard {
                            r.guard_trips.push("tripped".into());
                        }
                        for c in &corroborations {
                            for (stop, same_host) in [(false, false), (true, false), (false, true)]
                            {
                                let c = Corroboration {
                                    non_builtin_stabilizer: r.non_builtin_stabilizer,
                                    ..c.clone()
                                };
                                // The confirmation settings too: `attest` reads them from the
                                // configuration and asks `voided`, which must not need them.
                                let d = decide(
                                    &r,
                                    &c,
                                    Switches {
                                        stop_divergences: stop,
                                        confirmation: Confirmation {
                                            same_host,
                                            interval: Duration::from_secs(7 * 86_400),
                                        },
                                    },
                                );
                                let via_decide = match d {
                                    Publication::Void { because } => Some(because),
                                    _ => None,
                                };
                                assert_eq!(
                                    voided(&r),
                                    via_decide,
                                    "{outcome:?} {egress} guard={guard} {non_builtin:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_reason_says_something_a_reader_can_act_on() {
        // A withheld row shows its reason. A reason that is an enum name, or that ends without
        // saying whose problem it is, leaves the reader worse off than a blank.
        for w in [
            Withheld::AwaitingConfirmation,
            Withheld::AttemptsDisagree,
            Withheld::ConfirmationUnrecorded,
            Withheld::AttemptsTooClose,
            Withheld::SameHost,
            Withheld::ConfirmationNotCold,
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

    /// Every state the evidence repository's kill-switch can be in has a row in the page that
    /// paints it, so that none is drawn as another — `unknown` least of all as `clear`.
    #[test]
    fn every_repository_switch_state_has_a_row_in_the_page_that_paints_it() {
        let js = include_str!("../ui/app.js");
        let table = js
            .split_once("const repositorySwitchText")
            .expect("the page still paints the repository's switch")
            .1;
        let table = &table[..table.find("};").expect("the table is an object literal")];
        for s in [
            crate::SwitchState::Set,
            crate::SwitchState::Clear,
            crate::SwitchState::Unknown,
        ] {
            let key = serde_json::to_value(s).unwrap();
            let key = key.as_str().unwrap();
            assert!(
                table.contains(&format!("{key}:")),
                "`{key}` is a state the repository's switch can be in, and the page has no row \
                 for it"
            );
        }
        // Painted beside this server's own, never in its place.
        assert!(js.contains("paintRepositorySwitch();"));
        assert!(include_str!("../ui/index.html").contains("id=\"repo-switch\""));
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
            Withheld::ConfirmationUnrecorded,
            Withheld::AttemptsTooClose,
            Withheld::SameHost,
            Withheld::ConfirmationNotCold,
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
