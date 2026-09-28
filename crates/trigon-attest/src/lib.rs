//! What we are willing to sign, and what a sceptic can do with it.
//!
//! An attestation from a **rebuilder**, rather than from whoever originally built the artifact, is
//! worth something only to someone who distrusts the rebuilder. That is the whole design
//! constraint: every claim here is re-derivable by a third party holding two artifacts and our
//! stabilizer implementation, and `verify` is the function that does the re-deriving.
//!
//! See `docs/09-attestations.md`.

pub mod config;
mod dsse;
mod error;
pub mod evidence;
mod keys;
pub mod location;
pub mod log;
mod rebuild;
mod record;
mod signer;
pub mod state;
mod statement;
mod verdict;
mod verify;

pub use dsse::{Envelope, PAYLOAD_TYPE, Signature, pae};
pub use error::AttestError;
pub use keys::{AttestationKey, LogVkey};
pub use rebuild::{BUILD_OBSERVATION, REBUILD, RunFacts, SourceFacts, TranscriptRef};
pub use record::{RECORD_SCHEMA, Record, RecordSubject};
pub use signer::{LocalKey, Signer, Unsigned, verify as verify_signature};
pub use statement::{
    DIVERGENCE, EQUIVALENCE, STATEMENT_TYPE, Statement, Subject, sha1_of, sha512_of,
};
pub use verdict::{
    AuthoredPass, DIVERGENCE_V2, DisputePointer, EQUIVALENCE_V2, EvidenceDigests,
    FalsifyingCommand, RunIdentity, SupersedeReason, Supersession, VOID, VerdictFacts, VoidFacts,
    WITHDRAWAL, evidence_key, is_primary, is_verdict, set_manifest_file,
};
pub use verify::{
    ArchivedStabilizer, Disagreement, Rederived, ReportCheck, rederive, rederive_with,
    sign_statement, subject_sha256,
};
