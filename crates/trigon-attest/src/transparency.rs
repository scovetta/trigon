//! Rekor entries, and the part of one that is worth anything: the Signed Entry Timestamp.
//!
//! [ADR-0011](../../../docs/adr/0011-keyed-signing-under-a-trusted-root.md) chose a key we hold over
//! an ephemeral one, and **the transparency log is what makes that safe rather than a convenience
//! on top.** An ephemeral key bounds a compromise by construction. A key we hold is bounded only by
//! this: Rekor's SET is its own signature over "this entry existed at time T", and verification
//! checks T falls inside the signing certificate's validity window. An attacker holding our key
//! from today cannot produce a statement dated last year, because there is no log entry for one and
//! the log is append-only and publicly auditable.
//!
//! Skipping that check reduces the whole design to a pinned public key with extra ceremony, which
//! is why this module exists before anything that posts to a log.
//!
//! **Verification lives here and publication does not.** `trigon verify-attestation` builds with
//! `--no-default-features` and links no network client — that is the claim a sceptic checks — so
//! the POST lives above the judgement line in the binary, and everything a verifier needs is here:
//! pure, and dependent on arithmetic rather than on a socket.

use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};

use crate::AttestError;

/// What a log said about one entry, kept beside the attestation it is about.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Which log. `rekor.sigstore.dev`, `rekor.sigstage.dev`, or a private one.
    pub log: String,
    /// The entry's UUID, which is its address in the log.
    pub uuid: String,
    /// Monotonic position. Two entries with the same index are the same entry.
    pub log_index: u64,
    /// Seconds since the epoch, as the log recorded them. **Not ours** — the whole point is that
    /// this number comes from somewhere the signer does not control.
    pub integrated_time: i64,
    /// Base64 SHA-256 of the log's public key, as Rekor spells its `logID`.
    pub log_id: String,
    /// Base64 ECDSA signature over the canonicalized entry. The thing this module verifies.
    pub signed_entry_timestamp: String,
    /// The `body` field exactly as the log returned it, base64 of the entry JSON.
    ///
    /// Kept verbatim rather than rebuilt, because the SET covers the log's own serialization and a
    /// re-encoding that differs by one byte verifies against nothing.
    pub body: String,
}

impl LogEntry {
    /// The instant this entry was logged.
    pub fn integrated_at(&self) -> i64 {
        self.integrated_time
    }

    /// Verify the SET against the log's public key, and return the time it attests to.
    ///
    /// `log_public_key_pem` is what the log publishes at `/api/v1/log/publicKey`. A verifier should
    /// pin it rather than fetch it at verification time: fetching it from the log that produced the
    /// signature asks the log to vouch for itself.
    ///
    /// **The canonicalization is the whole trick and it is not obvious.** Rekor signs an RFC 8785
    /// canonical JSON object of exactly four fields — `body`, `integratedTime`, `logID`, `logIndex`
    /// — and nothing else from the entry. Adding a field, omitting one, or serializing in a
    /// different order produces a different message and a signature that fails for a reason that
    /// looks like a bad key.
    pub fn verify_set(&self, log_public_key_pem: &str) -> Result<i64, AttestError> {
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey as _;

        let key = VerifyingKey::from_public_key_pem(log_public_key_pem.trim())
            .map_err(|e| AttestError::Key(format!("the log's public key did not parse: {e}")))?;

        let raw = base64::engine::general_purpose::STANDARD
            .decode(&self.signed_entry_timestamp)
            .map_err(|e| AttestError::Malformed(format!("the SET is not base64: {e}")))?;
        // DER, which is what Rekor emits — not the fixed-width form.
        let sig = Signature::from_der(&raw)
            .map_err(|e| AttestError::Malformed(format!("the SET is not a DER signature: {e}")))?;

        let message = self.canonical_for_set()?;
        key.verify(message.as_bytes(), &sig).map_err(|_| {
            AttestError::Malformed(
                "the log's signed entry timestamp does not verify against its public key, so \
                 nothing here says when this entry existed"
                    .into(),
            )
        })?;
        Ok(self.integrated_time)
    }

    /// The four fields the SET covers, in RFC 8785 canonical form.
    fn canonical_for_set(&self) -> Result<String, AttestError> {
        let v = serde_json::json!({
            "body": self.body,
            "integratedTime": self.integrated_time,
            "logID": self.log_id,
            "logIndex": self.log_index,
        });
        trigon_core::jcs::canonicalize(&v)
            .map_err(|e| AttestError::Malformed(format!("canonicalizing the entry: {e}")))
    }
}

/// Whether a log time falls inside a certificate's validity window.
///
/// The step ADR-0011 hinges on, kept as its own function so it cannot be forgotten inside a longer
/// one: a signature is good only if the log says it existed while the certificate that made it was
/// valid. Both bounds inclusive, because a certificate issued and used in the same second is
/// ordinary rather than suspicious.
pub fn within_validity(logged_at: i64, not_before: i64, not_after: i64) -> bool {
    logged_at >= not_before && logged_at <= not_after
}

/// Build the `intoto` v0.0.1 entry body a log expects for a DSSE envelope.
///
/// **v0.0.1 and not v0.0.2**, measured against `rekor.sigstage.dev`: v0.0.2 takes the envelope as an
/// object and rejects this one with `could not verify envelope: unable to base64 decode payload`,
/// which is a message about shape wearing a message about encoding. v0.0.1 takes the envelope as a
/// **serialized JSON string** and the certificate as a sibling `publicKey`.
///
/// Returned as a `Value` rather than posted, because posting needs a network client and this crate
/// links none.
pub fn intoto_entry(envelope: &crate::Envelope, public_key_pem: &str) -> serde_json::Value {
    use sha2::Digest as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    // Only the fields v0.0.1 reads. The envelope the log stores is this serialization, and the hash
    // below is over these bytes — so building it once and hashing what was built is the only way
    // the two agree.
    let envelope_json = serde_json::json!({
        "payload": envelope.payload,
        "payloadType": envelope.payload_type,
        "signatures": envelope
            .signatures
            .iter()
            .map(|s| serde_json::json!({ "sig": s.sig }))
            .collect::<Vec<_>>(),
    });
    let blob = serde_json::to_string(&envelope_json).unwrap_or_default();

    serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "intoto",
        "spec": {
            "content": {
                "envelope": blob,
                "hash": {
                    "algorithm": "sha256",
                    "value": hex(&sha2::Sha256::digest(blob.as_bytes())),
                },
            },
            "publicKey": b64.encode(public_key_pem),
        },
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_set_covers_four_fields_and_no_others() {
        // The canonicalization is the whole trick: Rekor signs exactly `body`, `integratedTime`,
        // `logID` and `logIndex`, RFC 8785, and a fifth field or a different order produces a
        // different message and a failure that looks like a bad key.
        let e = LogEntry {
            log: "rekor.sigstage.dev".into(),
            uuid: "71d4".into(),
            log_index: 56040866,
            integrated_time: 1789562059,
            log_id: "abc".into(),
            signed_entry_timestamp: String::new(),
            body: "eyJhcGkiOjF9".into(),
        };
        let c = e.canonical_for_set().unwrap();
        assert_eq!(
            c,
            r#"{"body":"eyJhcGkiOjF9","integratedTime":1789562059,"logID":"abc","logIndex":56040866}"#
        );
        // Sorted by key, which is what RFC 8785 requires and what the log did when it signed.
        assert!(c.find("body").unwrap() < c.find("integratedTime").unwrap());
        assert!(c.find("logID").unwrap() < c.find("logIndex").unwrap());
    }

    #[test]
    fn a_set_that_does_not_verify_says_what_that_costs() {
        // The message has to say what is lost rather than that a check failed, because what is lost
        // is the only thing bounding a key compromise in time.
        // The real staging log's key, so the failure under test is the signature rather than the
        // parse. The two are different failures and only one of them is interesting.
        let key = "-----BEGIN PUBLIC KEY-----\n\
                   MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9\n\
                   nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==\n\
                   -----END PUBLIC KEY-----";
        let b64 = base64::engine::general_purpose::STANDARD;

        // Well-formed DER, wrong values: `SEQUENCE { INTEGER 1, INTEGER 1 }`. This reaches the
        // verification and fails there, which is the branch that matters.
        let wrong = LogEntry {
            signed_entry_timestamp: b64.encode([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            ..Default::default()
        };
        let err = wrong
            .verify_set(key)
            .expect_err("a valid DER signature of nothing");
        assert!(
            format!("{err}").contains("when this entry existed"),
            "the message has to say what is lost, not that a check failed: {err}"
        );

        // Not a signature at all fails earlier and says so differently, because "this is not a
        // signature" and "this signature is wrong" send a reader to different places.
        let malformed = LogEntry {
            signed_entry_timestamp: b64.encode([0u8; 70]),
            ..Default::default()
        };
        let err = malformed.verify_set(key).expect_err("zeroes are not DER");
        assert!(format!("{err}").contains("not a DER signature"), "{err}");
    }

    #[test]
    fn a_window_is_inclusive_at_both_ends() {
        // A certificate issued and used in the same second is ordinary. Excluding either bound
        // would reject correct signatures at a rate nobody would trace back to here.
        assert!(within_validity(100, 100, 200));
        assert!(within_validity(200, 100, 200));
        assert!(!within_validity(99, 100, 200));
        assert!(!within_validity(201, 100, 200));
    }

    #[test]
    fn the_entry_hash_is_over_the_bytes_the_entry_carries() {
        // The log stores the serialized envelope and the hash beside it; building the string once
        // and hashing what was built is the only way those two agree. Hashing a re-serialization
        // is the mistake that produces an accepted entry whose hash nobody can reproduce.
        let env = crate::Envelope {
            payload: "eyJhIjoxfQ==".into(),
            payload_type: crate::PAYLOAD_TYPE.into(),
            signatures: vec![crate::Signature {
                sig: "AAAA".into(),
                ..Default::default()
            }],
        };
        let entry = intoto_entry(
            &env,
            "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
        );
        let blob = entry["spec"]["content"]["envelope"].as_str().unwrap();
        let claimed = entry["spec"]["content"]["hash"]["value"].as_str().unwrap();
        assert_eq!(
            claimed,
            hex(&<sha2::Sha256 as sha2::Digest>::digest(blob.as_bytes()))
        );
        assert_eq!(entry["apiVersion"], "0.0.1", "v0.0.2 rejects this shape");
    }
}
