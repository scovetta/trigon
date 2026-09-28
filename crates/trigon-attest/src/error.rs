use thiserror::Error;
use trigon_core::{Classify, Fault};

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("could not canonicalize the statement: {0}")]
    Canonicalize(String),

    #[error("{0}")]
    Malformed(String),

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

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Classify for AttestError {
    fn fault(&self) -> Fault {
        match self {
            // A claim that does not hold is the most important thing this system can report, and it
            // is not an infrastructure problem: something signed a statement that is not true.
            AttestError::BadSignature | AttestError::ClaimRefuted { .. } => Fault::Bug,
            AttestError::Unsigned | AttestError::SetMismatch { .. } => Fault::Policy,
            // Not a refutation. Somebody handed the verifier the wrong file, which is a mistake to
            // report as a mistake rather than as a signed lie.
            AttestError::WrongArtifact { .. } => Fault::Upstream,
            AttestError::Malformed(_) | AttestError::Key(_) | AttestError::Json(_) => {
                Fault::Upstream
            }
            AttestError::Canonicalize(_) => Fault::Bug,
            AttestError::Io(_) => Fault::Infra,
        }
    }
}
