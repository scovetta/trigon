//! The record file, `trigon.record/v1`: one published result, as `docs/19` §4.1 lays it out.
//!
//! Plain types, and reading them, and nothing else yet. A record holds the signed statements
//! inline and names each piece of evidence by digest; its top-level `subject` and `evidence` map
//! are unsigned conveniences for finding things, and the signed statement inside is what a client
//! checks. `docs/19` §10 phase 4 defines that check — every envelope verifies, every evidence file
//! present matches the digest its statement names, the map agrees with the signed verdict — and
//! builds it on these types, so there is one definition of the file for the writer and every
//! reader. Until then `trigon attest --withdraw` and `--supersedes` read a record to learn what
//! they supersede, and nothing here says a record is genuine.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use trigon_core::Digest;

use crate::AttestError;
use crate::dsse::Envelope;
use crate::statement::Statement;
use crate::verdict::is_primary;

/// The value of a record's `schema`.
pub const RECORD_SCHEMA: &str = "trigon.record/v1";

/// A record file.
///
/// Without `deny_unknown_fields`, like every type a verifier reads: a later writer may add a key,
/// and a reader that refused it would refuse every record written after it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub schema: String,
    pub subject: RecordSubject,
    /// The statement first — an `equivalence`, `divergence`, `void` or `withdrawal` envelope —
    /// then, for a verdict, its `rebuild` and `buildobservation` envelopes.
    pub statements: Vec<Envelope>,
    /// Evidence by name, each value `sha256:<hex>`, under the names the verdict signs them by
    /// ([`crate::evidence_key`]). Empty for a withdrawal, and at most the guard manifest for a
    /// void.
    #[serde(default)]
    pub evidence: BTreeMap<String, String>,
}

/// A record's unsigned subject: what to find it by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSubject {
    pub purl: String,
    /// Keyed by algorithm, as a statement's subject is.
    pub digests: BTreeMap<String, String>,
}

impl Record {
    /// Read a record file's bytes.
    ///
    /// Refuses a file that is not a record at all — not JSON of this shape, or another `schema` —
    /// and nothing more: whether its statements verify, and whether its unsigned parts agree with
    /// them, is `docs/19` §10 phase 4's check.
    pub fn from_slice(bytes: &[u8]) -> Result<Record, AttestError> {
        let r: Record = serde_json::from_slice(bytes).map_err(|e| {
            AttestError::Malformed(format!("this is not a {RECORD_SCHEMA} record file: {e}"))
        })?;
        if r.schema != RECORD_SCHEMA {
            return Err(AttestError::Malformed(format!(
                "this record's schema is `{}`, and this build reads `{RECORD_SCHEMA}`",
                r.schema
            )));
        }
        Ok(r)
    }

    /// A record's name: the sha256 of its own bytes, which is what a supersession names and what
    /// its log leaf binds (`docs/19` §4.1).
    pub fn digest_of(bytes: &[u8]) -> Digest {
        Digest::from_bytes(Sha256::digest(bytes).into())
    }

    /// The record's one statement that is its result — a verdict, a void or a withdrawal — decoded
    /// from its envelope. Read, not verified: the signature is not checked here.
    pub fn statement(&self) -> Result<Statement, AttestError> {
        let mut found = Vec::new();
        for e in &self.statements {
            let st: Statement = serde_json::from_slice(&e.decoded_payload()?).map_err(|e| {
                AttestError::Malformed(format!(
                    "a statement in this record is not an in-toto statement: {e}"
                ))
            })?;
            if is_primary(&st.predicate_type) {
                found.push(st);
            }
        }
        match found.len() {
            1 => Ok(found.remove(0)),
            0 => Err(AttestError::Malformed(
                "this record holds no verdict, void or withdrawal statement".into(),
            )),
            n => Err(AttestError::Malformed(format!(
                "this record holds {n} verdict, void or withdrawal statements, and a record is one \
                 result"
            ))),
        }
    }
}
