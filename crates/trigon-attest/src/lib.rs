//! What we are willing to sign, and what a sceptic can do with it.
//!
//! An attestation from a **rebuilder**, rather than from whoever originally built the artifact, is
//! worth something only to someone who distrusts the rebuilder. That is the whole design
//! constraint: every claim here is re-derivable by a third party holding two artifacts and our
//! stabilizer implementation, and `verify` is the function that does the re-deriving.
//!
//! See `docs/09-attestations.md`.

mod dsse;
mod error;
mod rebuild;
mod signer;
mod statement;
mod verify;

pub use dsse::{Envelope, PAYLOAD_TYPE, Signature, pae};
pub use error::AttestError;
pub use rebuild::{BUILD_OBSERVATION, REBUILD, RunFacts, SourceFacts, TranscriptRef};
pub use signer::{LocalKey, Signer, Unsigned, verify as verify_signature};
pub use statement::{DIVERGENCE, EQUIVALENCE, STATEMENT_TYPE, Statement, Subject};
pub use verify::{
    ArchivedStabilizer, Rederived, rederive, rederive_with, sign_statement, subject_sha256,
};
