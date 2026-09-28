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
