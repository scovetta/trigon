//! DSSE envelopes, and the pre-authentication encoding a signature actually covers.
//!
//! PAE is five lines and it is the whole reason DSSE exists rather than signing the payload
//! directly: the payload type is signed alongside the payload, so a statement cannot be lifted out
//! of one envelope and presented as a different kind of document. Length-prefixing every field is
//! what stops a crafted payload from impersonating a different (type, payload) pair.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Base64 of the canonical statement.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Base64. Empty when the bundle was produced unsigned.
    pub sig: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyid: String,
    /// The certificate chain this signature was made under, PEM, **leaf first**.
    ///
    /// Absent for a signature verified against a pinned public key, which is what `LocalKey`
    /// produces and what every bundle written before [ADR-0011] contains — so an old bundle keeps
    /// verifying exactly as it did, and a `--root` verification of one fails for the honest reason
    /// that there is no chain rather than for a parse error.
    ///
    /// Leaf first because that is the order every X.509 consumer expects and the order a chain
    /// builder walks: the leaf carries the public key that made this signature, and each
    /// certificate after it issued the one before.
    ///
    /// [ADR-0011]: ../../../docs/adr/0011-keyed-signing-under-a-trusted-root.md
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
}

impl Signature {
    /// Whether this signature carries a chain to validate rather than a key to pin.
    ///
    /// The two verification paths are different claims and a verifier must not silently take the
    /// weaker one: a chained signature checked against `--public-key` proves the bytes were signed
    /// by *a* key and says nothing about whose.
    pub fn is_chained(&self) -> bool {
        !self.chain.is_empty()
    }

    /// The leaf, which holds the public key that made this signature.
    pub fn leaf(&self) -> Option<&str> {
        self.chain.first().map(String::as_str)
    }
}

/// The pre-authentication encoding: `DSSEv1 <len> <type> <len> <payload>`.
///
/// Length-prefixed, so no payload can be constructed that reads as a different type-and-payload
/// pair. This is what is signed and what is verified; the base64 in the envelope is transport.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 64);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

impl Envelope {
    pub fn new(payload: &[u8], signatures: Vec<Signature>) -> Self {
        Envelope {
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            payload_type: PAYLOAD_TYPE.into(),
            signatures,
        }
    }

    /// The bytes inside, decoded.
    pub fn decoded_payload(&self) -> Result<Vec<u8>, crate::AttestError> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(|e| crate::AttestError::Evidence(format!("payload is not base64: {e}")))
    }

    /// What a signature over this envelope covers.
    pub fn pae(&self) -> Result<Vec<u8>, crate::AttestError> {
        Ok(pae(&self.payload_type, &self.decoded_payload()?))
    }

    /// Whether this envelope carries any signature at all.
    ///
    /// Asked separately from verification, because "unsigned" and "signed by someone you do not
    /// trust" are different answers and collapsing them is how an unsigned bundle comes to be
    /// treated as verified.
    pub fn is_signed(&self) -> bool {
        self.signatures.iter().any(|s| !s.sig.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_is_length_prefixed() {
        assert_eq!(pae("t", b"p"), b"DSSEv1 1 t 1 p".to_vec());
    }

    #[test]
    fn no_payload_can_impersonate_another_type_and_payload_pair() {
        // The reason for the length prefixes. Without them these two would encode identically and
        // a statement could be lifted out of one envelope into another kind of document.
        assert_ne!(pae("ab", b"c"), pae("a", b"bc"));
    }

    #[test]
    fn an_envelope_round_trips() {
        let e = Envelope::new(b"hello", vec![]);
        assert_eq!(e.decoded_payload().unwrap(), b"hello");
        assert_eq!(e.pae().unwrap(), pae(PAYLOAD_TYPE, b"hello"));
        assert!(!e.is_signed(), "no signatures means unsigned");
    }

    #[test]
    fn an_empty_signature_does_not_count_as_signed() {
        let e = Envelope::new(
            b"x",
            vec![Signature {
                sig: String::new(),
                keyid: "k".into(),
                ..Default::default()
            }],
        );
        assert!(!e.is_signed());
    }
}
