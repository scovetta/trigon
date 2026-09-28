//! Whether a source can answer now, and what several sources' answers come to (`docs/19` §6,
//! §6.1).
//!
//! **Two clocks.** A source is *stale* when its last successful sync is older than `stale_after`;
//! a command syncs it first, and one that cannot, or runs `--offline`, has it answer unknown, as a
//! failed sync would. It is *frozen* when its newest leaf is older than `frozen_after`, and then it
//! answers unknown whatever the sync did, so a host serving an old but consistent state cannot turn
//! a withdrawal back into a verdict. A log with no leaf at all proves nothing about how recent it is
//! — its checkpoint of size 0 is the oldest consistent state there is — so it is frozen too.
//!
//! **Per source, never pooled.** A package takes the most severe answer any source gives that is
//! not unknown; an unknown source matters only where it is required; no source able to answer is
//! 4; no source configured is 5 ([`exit_code`]). A source whose last sync was refused — it failed
//! verification — answers nothing and is 4 for every package, since `docs/19` §6 gives an
//! equivocation that code whatever else is said.
//!
//! Pure: the caller reads the state directory and the clock, and passes them in, so a test states
//! the time it means instead of waiting for it.

use trigon_core::Match;

use super::lookup::{Answer, precedence};
use crate::config::Freshness;
use crate::state::SyncRecord;

/// Whether a source can answer now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Its last sync worked, within `stale_after`.
    Fresh,
    /// Its last sync failed — the source could not be reached or read — and the last one that
    /// worked is within `stale_after`: it answers from its clone until `stale_at`, labelled with
    /// the checkpoint the answer came from (`docs/19` §6.1).
    Usable { failure: String, stale_at: u64 },
    /// Its newest leaf is older than `frozen_after`, or it has none: it answers unknown.
    Frozen { newest: Option<u64> },
    /// It cannot answer: never synced, or its last sync that worked is older than `stale_after`.
    Unknown { why: String },
    /// Its last sync was refused because the source failed verification: it answers nothing, and
    /// every command asking it exits 4.
    Refused { why: String },
}

impl Standing {
    /// Whether answers are read from the source.
    pub fn answers(&self) -> bool {
        matches!(self, Standing::Fresh | Standing::Usable { .. })
    }

    /// The name a report and `--output json` use.
    pub fn key(&self) -> &'static str {
        match self {
            Standing::Fresh => "fresh",
            Standing::Usable { .. } => "usable",
            Standing::Frozen { .. } => "frozen",
            Standing::Unknown { .. } => "unknown",
            Standing::Refused { .. } => "refused",
        }
    }

    /// How a source stands now, `now` in Unix seconds: from its sync record, `None` where it has
    /// never been synced, and `newest`, the newest leaf's time in the chain it answers from, `None`
    /// for a log with no leaf.
    pub fn of(
        freshness: &Freshness,
        sync: Option<&SyncRecord>,
        newest: Option<u64>,
        now: u64,
    ) -> Standing {
        let Some(sync) = sync else {
            return Standing::Unknown {
                why: "it has never been synced".into(),
            };
        };
        if let Some(f) = sync.refusal() {
            return Standing::Refused { why: f.why.clone() };
        }
        let Some(last) = sync.last_success else {
            return Standing::Unknown {
                why: match &sync.failure {
                    Some(f) => format!("no sync of it has worked; the last failed: {}", f.why),
                    None => "no sync of it has worked".into(),
                },
            };
        };
        let stale_at = last.saturating_add(freshness.stale_after.as_secs());
        if now > stale_at {
            return Standing::Unknown {
                why: format!(
                    "it is stale: its last sync that worked was {} ago, and `stale_after` is {}",
                    ago(now.saturating_sub(last)),
                    ago(freshness.stale_after.as_secs())
                ),
            };
        }
        let frozen = match newest {
            Some(t) => now.saturating_sub(t) > freshness.frozen_after.as_secs(),
            None => true,
        };
        if frozen {
            return Standing::Frozen { newest };
        }
        match &sync.failure {
            Some(f) if f.at >= last => Standing::Usable {
                failure: f.why.clone(),
                stale_at,
            },
            _ => Standing::Fresh,
        }
    }
}

/// A duration in seconds as a person reads it: the largest whole unit.
pub fn ago(secs: u64) -> String {
    match secs {
        s if s >= 86_400 && s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s >= 86_400 => format!("{}d {}h", s / 86_400, (s % 86_400) / 3600),
        s if s >= 3600 => format!("{}h", s / 3600),
        s if s >= 60 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// What one source says of one package, as the exit code of `docs/19` §6 weighs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Said {
    /// It answered.
    Answered(Answer),
    /// It could not say — stale, frozen, never synced — which matters only where it is required.
    Unknown { required: bool },
    /// Its last sync was refused: it failed verification as a whole.
    Refused,
}

/// The exit code of one package from what every source asked said of it (`docs/19` §6): the most
/// severe answer any source gave that is not unknown; 4 where a required source is unknown or a
/// source was refused; 4 where no source could answer at all; and 5 where no source is configured,
/// which `configured` says.
pub fn exit_code(said: &[Said], min: Match, configured: bool) -> u8 {
    if !configured {
        return 5;
    }
    let answered: Vec<Answer> = said
        .iter()
        .filter_map(|s| match s {
            Said::Answered(a) => Some(a.clone()),
            _ => None,
        })
        .collect();
    let mut codes = Vec::new();
    if said
        .iter()
        .any(|s| matches!(s, Said::Refused | Said::Unknown { required: true }))
    {
        codes.push(4);
    }
    // Never checked only where no source that answered holds a record for it: a private source
    // that holds only internal packages does not make every public one read as never checked.
    let held: Vec<Answer> = answered
        .iter()
        .filter(|a| **a != Answer::NeverChecked)
        .cloned()
        .collect();
    match (answered.is_empty(), held.is_empty()) {
        (true, _) => codes.push(4),
        (false, true) => codes.push(Answer::NeverChecked.exit_code(min)),
        (false, false) => codes.push(Answer::most_severe(held, min).exit_code(min)),
    }
    first_that_wins(codes)
}

/// Of several exit codes, the one `docs/19` §6 has win: the first in the order 5, 4, 1, 3, 2, and
/// 0 only where every one is 0.
pub fn first_that_wins(codes: impl IntoIterator<Item = u8>) -> u8 {
    codes
        .into_iter()
        .max_by_key(|c| precedence(*c))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Failure;
    use std::time::Duration;

    const DAY: u64 = 86_400;

    fn freshness() -> Freshness {
        Freshness {
            stale_after: Duration::from_secs(DAY),
            frozen_after: Duration::from_secs(14 * DAY),
        }
    }

    fn synced(at: u64) -> SyncRecord {
        SyncRecord {
            last_success: Some(at),
            last_attempt: Some(at),
            ..Default::default()
        }
    }

    /// Time is stated, never waited for: the clock is an argument.
    #[test]
    fn stale_is_read_from_the_last_sync_that_worked_and_frozen_from_the_newest_leaf() {
        let now = 100 * DAY;
        let f = freshness();
        let fresh = synced(now - 3600);
        assert_eq!(
            Standing::of(&f, Some(&fresh), Some(now - DAY), now),
            Standing::Fresh
        );
        // A day and a second since the last sync: stale, so unknown, whatever the leaves say.
        let stale = synced(now - DAY - 1);
        assert!(matches!(
            Standing::of(&f, Some(&stale), Some(now), now),
            Standing::Unknown { why } if why.contains("stale")
        ));
        // Synced a minute ago, and the newest leaf is fifteen days old: frozen.
        assert_eq!(
            Standing::of(&f, Some(&fresh), Some(now - 15 * DAY), now),
            Standing::Frozen {
                newest: Some(now - 15 * DAY)
            }
        );
        // A log with no leaf proves nothing about how recent it is.
        assert_eq!(
            Standing::of(&f, Some(&fresh), None, now),
            Standing::Frozen { newest: None }
        );
        // Never synced.
        assert!(matches!(
            Standing::of(&f, None, Some(now), now),
            Standing::Unknown { why } if why.contains("never")
        ));
    }

    #[test]
    fn a_failed_sync_leaves_the_clone_answering_until_it_is_stale_and_a_refused_one_answers_nothing()
     {
        let now = 100 * DAY;
        let f = freshness();
        let mut r = synced(now - 3600);
        r.failure = Some(Failure {
            at: now - 60,
            why: "could not be reached".into(),
            refused: false,
        });
        assert_eq!(
            Standing::of(&f, Some(&r), Some(now - DAY), now),
            Standing::Usable {
                failure: "could not be reached".into(),
                stale_at: now - 3600 + DAY
            }
        );
        // Past `stale_after`, the same failure is unknown.
        assert!(!Standing::of(&f, Some(&r), Some(now - DAY), now + DAY).answers());
        // Refused: nothing is answered, however fresh.
        r.failure = Some(Failure {
            at: now - 60,
            why: "an equivocation".into(),
            refused: true,
        });
        assert_eq!(
            Standing::of(&f, Some(&r), Some(now - DAY), now),
            Standing::Refused {
                why: "an equivocation".into()
            }
        );
        // A refusal a later sync that worked has put behind it no longer stands.
        r.last_success = Some(now - 10);
        assert_eq!(
            Standing::of(&f, Some(&r), Some(now - DAY), now),
            Standing::Fresh
        );
    }

    #[test]
    fn several_sources_come_to_the_most_severe_answer_and_unknown_counts_only_where_required() {
        let min = Match::NormalizedWithCaveats;
        let ok = Said::Answered(Answer::Outcome(Match::Exact));
        let divergent = Said::Answered(Answer::Outcome(Match::Divergent));
        let never = Said::Answered(Answer::NeverChecked);
        // A divergence from any source fails the check.
        assert_eq!(exit_code(&[ok.clone(), divergent.clone()], min, true), 1);
        // A private source that holds nothing about a public package does not make it never checked.
        assert_eq!(exit_code(&[ok.clone(), never.clone()], min, true), 0);
        assert_eq!(exit_code(std::slice::from_ref(&never), min, true), 2);
        // Unknown contributes nothing unless required.
        let unknown = Said::Unknown { required: false };
        assert_eq!(exit_code(&[ok.clone(), unknown.clone()], min, true), 0);
        assert_eq!(
            exit_code(&[ok.clone(), Said::Unknown { required: true }], min, true),
            4
        );
        // No source able to answer at all.
        assert_eq!(exit_code(&[unknown.clone(), unknown], min, true), 4);
        // A refused source is 4 whatever else is said, and 4 wins over a divergence.
        assert_eq!(exit_code(&[divergent, Said::Refused], min, true), 4);
        // No source configured.
        assert_eq!(exit_code(&[], min, false), 5);
        assert_eq!(first_that_wins([2, 3, 1, 0]), 1);
        assert_eq!(first_that_wins([2, 3]), 3);
        assert_eq!(first_that_wins([]), 0);
    }
}
