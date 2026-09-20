//! What a model thought about a diff, kept apart from what a run established.
//!
//! A comparison ends in facts: these members differ, by these bytes. Whether the difference
//! *matters* — a rebuilt bundle whose only change is a banner timestamp, against one that ships
//! different logic — is a judgement, and when a model is configured the run asks it for one.
//!
//! **An opinion, never a verdict.** The rule for models here is the rule ADR-0013 gives caches:
//! a cache supplies bytes, never decisions, and a model supplies opinions, never verdicts. The
//! comparison outcome is unchanged by anything in this module, the publication gate does not read
//! it (`trigon-api` asserts that), and it appears in no signed statement — a signed accusation
//! carrying a model's guess would be Trigon signing something nobody established.
//!
//! `None` on a record means no model was configured, the diff had nothing to show, or the ask
//! failed. It never means "the diff is fine".

use serde::{Deserialize, Serialize};

/// A model's reading of the difference between the published artifact and the rebuild.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffOpinion {
    pub verdict: DiffVerdict,
    /// One sentence of why, bounded at recording time. Package-derived text can appear here in
    /// quotation; it is display-only and feeds nothing.
    pub reason: String,
    /// Which model said it. An opinion with no author is a fact costume.
    pub model: String,
    /// The condition the opinion was formed under: how many differing members the model was
    /// shown, of how many there were. An opinion over 3 of 300 members is a different claim from
    /// one over 3 of 3, and a reader gets to see which this is.
    pub members_shown: u32,
    pub members_differing: u32,
}

/// Serialized as words, per ADR-0002: an ordinal in a record outlives the enum that gave it
/// meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffVerdict {
    /// The difference plausibly changes what the software does.
    Substantive,
    /// The difference is plausibly semantic noise: timestamps, ordering, paths, toolchain
    /// banners, generated-file formatting.
    Equivalent,
    /// The model could not tell, or was shown too little to say. The honest third state — a
    /// classifier forced to two answers turns "I was shown a truncated diff" into one of them.
    Unclear,
}

impl DiffVerdict {
    /// The whole vocabulary, in one place, so the prompt's schema and rubric can be built from it
    /// rather than restating it. Five spellings of three words is how one of them drifts.
    pub const ALL: [DiffVerdict; 3] =
        [DiffVerdict::Substantive, DiffVerdict::Equivalent, DiffVerdict::Unclear];

    pub fn as_str(self) -> &'static str {
        match self {
            DiffVerdict::Substantive => "substantive",
            DiffVerdict::Equivalent => "equivalent",
            DiffVerdict::Unclear => "unclear",
        }
    }

    /// The reverse of `as_str`, tolerant of the casings a model actually produces.
    pub fn parse(s: &str) -> Option<DiffVerdict> {
        match s.trim().to_ascii_lowercase().as_str() {
            "substantive" => Some(DiffVerdict::Substantive),
            "equivalent" => Some(DiffVerdict::Equivalent),
            "unclear" => Some(DiffVerdict::Unclear),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_is_a_word_on_the_wire_and_the_same_word_everywhere() {
        // ADR-0002 gives the first half: a record holding `2` means nothing to a reader without
        // this exact enum at this exact version. The second half is the tie: `as_str` feeds the
        // terminal and the serde name feeds the record, and the first draft of this test pinned
        // two of the three variants against literals — `unclear`'s wire word was pinned against
        // nothing at all.
        for v in DiffVerdict::ALL {
            assert_eq!(
                serde_json::to_string(&v).unwrap(),
                format!("\"{}\"", v.as_str()),
                "the record and the terminal spell {v:?} differently"
            );
            let back: DiffVerdict =
                serde_json::from_str(&format!("\"{}\"", v.as_str())).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn parse_is_the_inverse_of_as_str_and_forgives_casing() {
        for v in [DiffVerdict::Substantive, DiffVerdict::Equivalent, DiffVerdict::Unclear] {
            assert_eq!(DiffVerdict::parse(v.as_str()), Some(v));
            assert_eq!(DiffVerdict::parse(&v.as_str().to_uppercase()), Some(v));
        }
        assert_eq!(DiffVerdict::parse("fine"), None);
    }
}
