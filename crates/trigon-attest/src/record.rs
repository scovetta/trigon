//! The record file, `trigon.record/v1`: one published result, as `docs/19` §4.1 lays it out.
//!
//! Plain types, reading them, and writing them. A record holds the signed statements inline and
//! names each piece of evidence by digest; its top-level `subject` and `evidence` map are unsigned
//! conveniences for finding things, and the signed statement inside is what a client checks.
//! Whether a record is genuine — every envelope verifies under the key current at its leaf, the
//! statement agrees with its leaf, the map with the statement, every evidence file present with
//! its digest — is [`crate::evidence::check_record`], built on these types, so there is one
//! definition of the file for the writer and every reader. Nothing here says a record is genuine:
//! `trigon attest --withdraw` and `--supersedes` read one only to learn what they supersede.

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
    /// A record holding these envelopes — the result's statement, then for a verdict its
    /// `rebuild` and `buildobservation` — as `publish` writes one (`docs/19` §4.1).
    ///
    /// The unsigned `subject` and `evidence` map are taken from the signed statement, so a record
    /// written here agrees with itself by construction; a reader still checks that it does,
    /// since a record is anyone's bytes until then.
    pub fn assemble(statements: Vec<Envelope>) -> Result<Record, AttestError> {
        let mut record = Record {
            schema: RECORD_SCHEMA.into(),
            subject: RecordSubject {
                purl: String::new(),
                digests: BTreeMap::new(),
            },
            statements,
            evidence: BTreeMap::new(),
        };
        let st = record.statement()?;
        let [subject] = st.subject.as_slice() else {
            return Err(AttestError::Evidence(format!(
                "a record's statement is about one artifact, and this one names {}",
                st.subject.len()
            )));
        };
        let purl = st.predicate["purl"].as_str().ok_or_else(|| {
            AttestError::Evidence(format!(
                "this `{}` signs no purl, so no client could find the record by one",
                st.predicate_type
            ))
        })?;
        record.subject = RecordSubject {
            purl: purl.to_string(),
            digests: subject.digest.clone(),
        };
        record.evidence = signed_evidence(&st)?;
        Ok(record)
    }

    /// The record file's bytes: its canonical JSON (`trigon_core::jcs`), so that a record's name,
    /// the sha256 of these bytes, is a function of what it holds and not of how one writer spaced
    /// it.
    pub fn encode(&self) -> Result<Vec<u8>, AttestError> {
        let v = serde_json::to_value(self)?;
        Ok(trigon_core::jcs::canonicalize(&v)
            .map_err(|e| AttestError::Canonicalize(e.to_string()))?
            .into_bytes())
    }

    /// Read a record file's bytes.
    ///
    /// Refuses a file that is not a record at all — not JSON of this shape, or another `schema` —
    /// and nothing more: whether its statements verify, and whether its unsigned parts agree with
    /// them, is [`crate::evidence::check_record`].
    pub fn from_slice(bytes: &[u8]) -> Result<Record, AttestError> {
        let r: Record = serde_json::from_slice(bytes).map_err(|e| {
            AttestError::Evidence(format!("this is not a {RECORD_SCHEMA} record file: {e}"))
        })?;
        if r.schema != RECORD_SCHEMA {
            return Err(AttestError::Evidence(format!(
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
                AttestError::Evidence(format!(
                    "a statement in this record is not an in-toto statement: {e}"
                ))
            })?;
            if is_primary(&st.predicate_type) {
                found.push(st);
            }
        }
        match found.len() {
            1 => Ok(found.remove(0)),
            0 => Err(AttestError::Evidence(
                "this record holds no verdict, void or withdrawal statement".into(),
            )),
            n => Err(AttestError::Evidence(format!(
                "this record holds {n} verdict, void or withdrawal statements, and a record is one \
                 result"
            ))),
        }
    }
}

/// The evidence a statement signs, by name, as a record's map writes it: `sha256:<hex>`.
///
/// A statement signs each as `{"sha256": "<hex>"}` under its `evidence`; a withdrawal signs no
/// `evidence` at all, and names none. Anything else under a name is not a digest this build can
/// check, and is refused rather than read past, since the map is compared against it.
pub(crate) fn signed_evidence(st: &Statement) -> Result<BTreeMap<String, String>, AttestError> {
    let mut out = BTreeMap::new();
    let Some(signed) = st.predicate.get("evidence") else {
        return Ok(out);
    };
    let Some(signed) = signed.as_object() else {
        return Err(AttestError::Evidence(format!(
            "this `{}` signs `evidence` as something other than an object of digests",
            st.predicate_type
        )));
    };
    for (name, digest) in signed {
        let hex = digest
            .as_object()
            .filter(|o| o.len() == 1)
            .and_then(|o| o.get("sha256"))
            .and_then(|h| h.as_str())
            .filter(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .ok_or_else(|| {
                AttestError::Evidence(format!(
                    "this `{}` signs its `{}` evidence as something other than \
                     `{{\"sha256\": <64 lowercase hex>}}`",
                    st.predicate_type,
                    crate::location::printable(name)
                ))
            })?;
        out.insert(name.clone(), format!("sha256:{hex}"));
    }
    Ok(out)
}
