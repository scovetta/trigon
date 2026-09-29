use thiserror::Error;
use trigon_core::{Classify, Fault};

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("could not canonicalize the statement: {0}")]
    Canonicalize(String),

    #[error("{0}")]
    Malformed(String),

    /// Evidence — an envelope, the statement in it, a record file — that is not in the form it
    /// claims to be: damaged on the way, or written to mislead. Kept apart from
    /// [`AttestError::Malformed`], which is also a caller's mistake or an artifact that will not
    /// parse, because whose fault it is differs: this is the evidence's, and a report that blamed
    /// the published artifact, or trigon, would send the reader to the wrong party.
    #[error("{0}")]
    Evidence(String),

    #[error("{0}")]
    Key(String),

    #[error("the signature does not verify against the key it was checked with")]
    BadSignature,

    #[error(
        "this bundle carries no signature. It is still a complete claim and \
         `--rerun-comparison` still checks it, but nothing here says who produced it."
    )]
    Unsigned,

    #[error(
        "the attestation was made under stabilizer set {claimed}, and this build has {current}. \
         Refusing to compare across them: the digests answer different questions, so a match would \
         mean nothing and a mismatch would not be evidence either. Re-derive under today's set and \
         read the result as a new claim."
    )]
    SetMismatch { claimed: String, current: String },

    #[error(
        "the {side} artifact given is not the one this statement is about: it names \
         {algorithm} {expected} and this file is {got}"
    )]
    WrongArtifact {
        side: &'static str,
        /// Which digest disagreed. A subject names several, and "sha1 differs, sha256 agrees"
        /// is a different finding from a different file: it is a statement whose digests were
        /// not all computed over the same bytes.
        algorithm: String,
        expected: String,
        got: String,
    },

    #[error(
        "the statement claims {claimed} for the {side} stabilized form; recomputing gives {actual}"
    )]
    ClaimRefuted {
        side: &'static str,
        claimed: String,
        actual: String,
    },

    /// A subject whose sha256 is the file in hand's, and whose other digest is not: the file is
    /// the artifact the statement is about, and the statement's digests were not all computed
    /// over it. Not [`AttestError::WrongArtifact`], which is a mistake of whoever handed the file
    /// in: this is a signed claim refuted, and a lookup by that digest would find the statement
    /// for another artifact's bytes (`docs/19` §5).
    #[error(
        "the statement's subject names {algorithm} {claimed}, and the artifact its sha256 names — \
         the file given — has the {algorithm} {actual}: its digests were not all computed over \
         one file, and a lookup by that {algorithm} would find it for another artifact"
    )]
    SubjectRefuted {
        algorithm: String,
        claimed: String,
        actual: String,
    },

    /// The evidence log, or one of its files, refused (`docs/19` §2.3, §8).
    #[error(transparent)]
    Log(#[from] crate::log::LogError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl AttestError {
    /// Whether this is evidence failing verification — a signature that does not verify, a claim
    /// that does not re-derive, a log that does not hold — rather than a mistake, a refusal or a
    /// fault of ours. `docs/19` §4.2 and §8 report such evidence as failed verification, since it
    /// may be lying, and the evidence is at fault and not Trigon, so nothing reporting one may say
    /// otherwise; `Fault::Bug` stays the class, as [`crate::log::LogError`] keeps it, so that it is
    /// never retried.
    pub fn fails_verification(&self) -> bool {
        match self {
            AttestError::BadSignature
            | AttestError::ClaimRefuted { .. }
            | AttestError::SubjectRefuted { .. } => true,
            AttestError::Log(e) => e.fails_verification(),
            AttestError::Canonicalize(_)
            | AttestError::Malformed(_)
            | AttestError::Evidence(_)
            | AttestError::Key(_)
            | AttestError::Unsigned
            | AttestError::SetMismatch { .. }
            | AttestError::WrongArtifact { .. }
            | AttestError::Json(_)
            | AttestError::Io(_) => false,
        }
    }
}

impl Classify for AttestError {
    fn fault(&self) -> Fault {
        match self {
            // A claim that does not hold is the most important thing this system can report, and it
            // is not an infrastructure problem: something signed a statement that is not true.
            // `Bug`, so that it is never retried and never counted as an input that would not
            // parse; whose it is, the evidence's and not Trigon's, is what
            // [`AttestError::fails_verification`] tells a reporter.
            AttestError::BadSignature
            | AttestError::ClaimRefuted { .. }
            | AttestError::SubjectRefuted { .. } => Fault::Bug,
            AttestError::Unsigned | AttestError::SetMismatch { .. } => Fault::Policy,
            // Not a refutation. Somebody handed the verifier the wrong file, which is a mistake to
            // report as a mistake rather than as a signed lie.
            AttestError::WrongArtifact { .. } => Fault::Upstream,
            // Evidence that cannot be read as what it says it is, as a log that cannot be read is
            // `Upstream`: somebody else's bytes, not a claim that was checked and failed.
            AttestError::Malformed(_)
            | AttestError::Evidence(_)
            | AttestError::Key(_)
            | AttestError::Json(_) => Fault::Upstream,
            AttestError::Canonicalize(_) => Fault::Bug,
            AttestError::Log(e) => e.fault(),
            AttestError::Io(_) => Fault::Infra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogError;

    /// Evidence that fails verification — a signature, a re-derivation, a subject refuted, a log
    /// that does not hold — is said as such, and is the evidence's fault class that is never
    /// retried; what could not be read, a policy, or a file handed in wrongly is not.
    #[test]
    fn only_evidence_that_fails_verification_is_said_to() {
        let s = || "why".to_string();
        let io = || std::io::Error::other("disk");
        let json = || serde_json::from_str::<u8>("x").unwrap_err();
        for (e, fails, fault) in [
            (AttestError::BadSignature, true, Fault::Bug),
            (
                AttestError::ClaimRefuted {
                    side: "upstream",
                    claimed: s(),
                    actual: s(),
                },
                true,
                Fault::Bug,
            ),
            (
                AttestError::SubjectRefuted {
                    algorithm: s(),
                    claimed: s(),
                    actual: s(),
                },
                true,
                Fault::Bug,
            ),
            (AttestError::Canonicalize(s()), false, Fault::Bug),
            (AttestError::Malformed(s()), false, Fault::Upstream),
            (AttestError::Evidence(s()), false, Fault::Upstream),
            (AttestError::Key(s()), false, Fault::Upstream),
            (AttestError::Json(json()), false, Fault::Upstream),
            (
                AttestError::WrongArtifact {
                    side: "upstream",
                    algorithm: s(),
                    expected: s(),
                    got: s(),
                },
                false,
                Fault::Upstream,
            ),
            (AttestError::Unsigned, false, Fault::Policy),
            (
                AttestError::SetMismatch {
                    claimed: s(),
                    current: s(),
                },
                false,
                Fault::Policy,
            ),
            (AttestError::Io(io()), false, Fault::Infra),
            (AttestError::Log(LogError::Mismatch(s())), true, Fault::Bug),
            (
                AttestError::Log(LogError::Missing { path: s() }),
                false,
                Fault::Upstream,
            ),
        ] {
            assert_eq!(e.fails_verification(), fails, "{e:?}");
            assert_eq!(e.fault(), fault, "{e:?}");
        }
    }

    /// A log that may be lying fails verification and is never retried; one that could not be
    /// read is the source's or the disk's, and does not.
    #[test]
    fn a_log_that_may_be_lying_fails_verification_and_one_unread_does_not() {
        let s = || "why".to_string();
        for (e, fails, fault) in [
            (LogError::Unverified(s()), true, Fault::Bug),
            (LogError::BadSignature(s()), true, Fault::Bug),
            (LogError::Mismatch(s()), true, Fault::Bug),
            (
                LogError::Inconsistent {
                    why: s(),
                    accepted: s(),
                    offered: s(),
                },
                true,
                Fault::Bug,
            ),
            (
                LogError::Equivocation {
                    why: s(),
                    first_dir: s(),
                    first: s(),
                    second_dir: s(),
                    second: s(),
                },
                true,
                Fault::Bug,
            ),
            (LogError::Rule(s()), true, Fault::Bug),
            (LogError::Rotation(s()), true, Fault::Bug),
            (LogError::Malformed(s()), false, Fault::Upstream),
            (LogError::Missing { path: s() }, false, Fault::Upstream),
            (
                LogError::Io {
                    path: s(),
                    source: std::io::Error::other("disk"),
                },
                false,
                Fault::Infra,
            ),
        ] {
            assert_eq!(e.fails_verification(), fails, "{e:?}");
            assert_eq!(e.fault(), fault, "{e:?}");
        }
    }
}
