//! Which blob classes an anonymous reader may fetch, and which need a principal.
//!
//! `12-security.md` §5 resolved the redistribution question for *artifact bytes* and stopped there.
//! It never covered build logs or network transcripts, and D14 — *redaction of credentials from a
//! build log before it is stored, rendered or sent to a model* — is **disclaimed and
//! security-critical**. The only mitigation the threat model ever offered was item 12 of §1.13:
//! "Keep `trigon watch` on loopback. Build logs are not redacted."
//!
//! A public site is precisely the removal of that mitigation. The chain is three steps long:
//! publish a package, ask for a rebuild of it, read our fleet's secrets off our own website. So the
//! class table is not a later hardening stage; it is what every byte route asks first.
//!
//! **Two classes are anonymous that a cautious reading would have gated, and the reason is the
//! product.** The stabilizer set manifest and a transform overlay have to be fetchable by anyone,
//! because without them a third party cannot re-derive a verdict made under a non-default set — and
//! re-derivability by a third party is the entire claim. A verifier who has to ask us for
//! permission to check our work is not checking our work.

use crate::Principal;
use serde::Serialize;

/// What a blob is, for the purpose of deciding who may read it.
///
/// Derived from *which field of the run record named the digest*, never from the bytes. A class
/// guessed by sniffing content is a class an attacker chooses by choosing their content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Signed statements, and the digests and verdicts that point at them. The product.
    Statement,
    /// The stabilizer set manifest, its `.wasm`, and transform overlays. Anonymous **on purpose**:
    /// see the module note.
    Definition,
    /// The **rendered, bounded** comparison: counts, the digest ladder, the stabilizer ledger, and
    /// a member list capped with the remainder stated.
    ///
    /// Anonymous, and that is a correction rather than a relaxation. The first version of this
    /// table gated member paths as though they were secret. They are not: the same paths reach a
    /// signed `divergence/v1` statement, which is served to anybody. What is dangerous about the
    /// raw blob is its **size** — D9 disclaims any bound on a difference summary, so one request
    /// against a pathological artifact is an amplifier. The bound is the control. Gating the
    /// rendered view too would have meant a public site that shows a verdict and cannot say what
    /// it is about, which is most of the product.
    Diff,
    /// The full `Comparison` as stored. Carries member paths taken from an attacker-controlled
    /// artifact, at a size nothing bounds (D9).
    Comparison,
    /// A published or rebuilt artifact. Redistribution, and size.
    Artifact,
    /// A build log. Unredacted (D14).
    BuildLog,
    /// A network transcript. Every URL the build touched, unredacted.
    Transcript,
    /// A model exchange. Carries whatever of the build log was put in the prompt.
    ModelTranscript,
}

impl Class {
    /// Whether the public internet may fetch this class.
    pub fn is_anonymous(self) -> bool {
        matches!(self, Class::Statement | Class::Definition | Class::Diff)
    }

    /// Why not, for the reader who asked and was refused.
    ///
    /// A 403 with no sentence teaches a reader that the site is arbitrary. A 403 that says "this is
    /// an unredacted build log and we have not yet built the redactor" teaches them something true
    /// about the system, and is the kind of refusal this project would rather make.
    pub fn refusal(self) -> &'static str {
        match self {
            Class::Statement | Class::Definition | Class::Diff => {
                "this class is public; if you are reading this sentence, something asked the wrong \
                 question"
            }
            Class::Comparison => {
                "a comparison lists member paths taken from the artifact under test, at a size \
                 nothing bounds. It is served to a principal and not to the internet."
            }
            Class::Artifact => {
                "these are somebody else's published bytes. We hold them to check them, not to \
                 redistribute them."
            }
            Class::BuildLog => {
                "build logs are stored unredacted. Credential redaction is a known gap, not a \
                 solved problem, and until it is solved a log reaches a principal and not the \
                 internet."
            }
            Class::Transcript => {
                "a network transcript is every URL the build touched, unredacted, including any \
                 that carried a token."
            }
            Class::ModelTranscript => {
                "a model exchange carries whatever of the build log went into the prompt, so it \
                 inherits the build log's problem."
            }
        }
    }

    /// The whole table, so a listing over it cannot silently miss a class.
    pub const ALL: [Class; 8] = [
        Class::Statement,
        Class::Definition,
        Class::Diff,
        Class::Comparison,
        Class::Artifact,
        Class::BuildLog,
        Class::Transcript,
        Class::ModelTranscript,
    ];
}

/// May this principal read this class?
pub fn admits(who: Principal, class: Class) -> bool {
    match who {
        Principal::Operator => true,
        Principal::Anonymous => class.is_anonymous(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_internet_never_reads_an_unredacted_byte() {
        // The three classes D14 and its neighbours are about. If this test ever goes green after
        // someone widens `is_anonymous`, the site has become the exfiltration channel the threat
        // model says loopback was the only thing preventing.
        for c in [Class::BuildLog, Class::Transcript, Class::ModelTranscript] {
            assert!(
                !admits(Principal::Anonymous, c),
                "{c:?} is reachable without a principal"
            );
        }
    }

    #[test]
    fn a_verifier_can_re_derive_without_asking_us() {
        // Definitions are anonymous on purpose. A third party who must request permission to fetch
        // the stabilizer set a verdict was computed under cannot independently check that verdict,
        // and independent checkability is the claim the whole project rests on.
        assert!(admits(Principal::Anonymous, Class::Definition));
        assert!(admits(Principal::Anonymous, Class::Statement));
    }

    #[test]
    fn every_class_has_a_refusal_worth_reading() {
        for c in Class::ALL {
            let r = c.refusal();
            assert!(r.len() > 40, "{c:?} refuses without saying anything: {r}");
        }
    }

    #[test]
    fn the_gated_classes_are_the_ones_carrying_bytes_we_did_not_write() {
        // Stated as a property rather than a list, so adding a class forces a decision here instead
        // of defaulting to whichever arm the match happens to fall into.
        let anonymous: Vec<Class> = Class::ALL
            .into_iter()
            .filter(|c| c.is_anonymous())
            .collect();
        assert_eq!(
            anonymous,
            vec![Class::Statement, Class::Definition, Class::Diff],
            "the anonymous set changed. Every member of it must be either the product itself or \
             bounded by construction. The rendered diff qualifies because it caps its member list and says \
             how many it left out, which the raw comparison does not."
        );
    }
}
