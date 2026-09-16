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

        // **The key and the entry have to agree, and until now nothing said they did.** `logID` is
        // the SHA-256 of the log's own public key, so an entry names the key that must verify it.
        // Checking that first turns the commonest mistake — verifying against the wrong log's key —
        // from "the signature failed", which is indistinguishable from a forged entry, into a
        // statement about which key was handed over.
        let named = log_key_id(log_public_key_pem)?;
        if named != self.log_id {
            return Err(AttestError::Malformed(format!(
                "this entry names log {} and the key given is for log {named}, so verifying it \
                 against that key would prove nothing either way",
                self.log_id
            )));
        }

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

    /// The SHA-256 the log recorded for the statement inside the envelope.
    ///
    /// **This is what ties an entry to an attestation.** Rekor does not keep the envelope — the
    /// stored body has only these hashes and the public key — so a verifier cannot read the claim
    /// out of the log. What it can do is hash the statement it already holds and check the log
    /// recorded that one, which is the difference between "some entry exists" and "this entry is
    /// about this document".
    ///
    /// `None` when the body does not carry one, which is a body from a different entry type rather
    /// than a malformed one.
    pub fn payload_sha256(&self) -> Result<Option<String>, AttestError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&self.body)
            .map_err(|e| AttestError::Malformed(format!("the entry body is not base64: {e}")))?;
        let body: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| AttestError::Malformed(format!("the entry body is not JSON: {e}")))?;
        Ok(body["spec"]["content"]["payloadHash"]["value"]
            .as_str()
            .map(str::to_owned))
    }

    /// Whether the log recorded this exact statement.
    pub fn is_about(&self, payload: &[u8]) -> Result<bool, AttestError> {
        use sha2::Digest as _;
        Ok(self.payload_sha256()? == Some(hex(&sha2::Sha256::digest(payload))))
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

/// The SHA-256 a log records for a statement, as hex — the value [`LogEntry::is_about`] compares.
pub fn payload_id(payload: &[u8]) -> String {
    use sha2::Digest as _;
    hex(&sha2::Sha256::digest(payload))
}

/// A log's identifier, which is the SHA-256 of its public key in DER `SubjectPublicKeyInfo` form.
///
/// Not a convention we chose — it is how Rekor spells `logID`, and it is what lets an entry name the
/// key that verifies it. Measured against staging: the fixture's `logID` is exactly this hash of
/// the key `rekor.sigstage.dev` publishes.
pub fn log_key_id(pem: &str) -> Result<String, AttestError> {
    use p256::pkcs8::DecodePublicKey as _;
    use sha2::Digest as _;

    // Through a real parser and back out as DER rather than un-base64ing the PEM body directly:
    // the hash must be over canonical DER, and a PEM with a stray header or different line breaks
    // would otherwise produce a different id for the same key.
    let key = p256::ecdsa::VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|e| AttestError::Key(format!("the log's public key did not parse: {e}")))?;
    let der = p256::pkcs8::EncodePublicKey::to_public_key_der(&key)
        .map_err(|e| AttestError::Key(format!("re-encoding the log's public key: {e}")))?;
    Ok(hex(&sha2::Sha256::digest(der.as_bytes())))
}

/// The public keys of the two logs anyone is likely to be verifying against.
///
/// Compiled in and looked up by `logID`, which is the hash of the key itself — so a wrong or
/// tampered entry in this table cannot be selected for an entry it does not belong to. That is the
/// property that makes shipping keys safe: the table is an index, not an authority.
///
/// A pinned key rather than one fetched at verification time, because fetching a log's key from the
/// log whose signature you are checking asks it to vouch for itself.
pub const KNOWN_LOGS: &[(&str, &str, &str)] = &[
    (
        "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
        "rekor.sigstore.dev",
        "-----BEGIN PUBLIC KEY-----\n\
         MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
         kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
         -----END PUBLIC KEY-----\n",
    ),
    (
        "d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496",
        "rekor.sigstage.dev",
        "-----BEGIN PUBLIC KEY-----\n\
         MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9\n\
         nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==\n\
         -----END PUBLIC KEY-----\n",
    ),
];

/// The compiled-in key for a log id, and the name it goes by.
pub fn known_log(log_id: &str) -> Option<(&'static str, &'static str)> {
    KNOWN_LOGS
        .iter()
        .find(|(id, ..)| *id == log_id)
        .map(|(_, name, pem)| (*name, *pem))
}

/// Format a Unix timestamp as RFC 3339 UTC.
///
/// Hand-rolled because a date crate on this side of the judgement line buys one string. The
/// day-to-date arithmetic is Howard Hinnant's `civil_from_days`, which is exact for the whole
/// proleptic Gregorian range rather than only for dates near today.
pub fn utc_rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);

    // Shift the era so that March is month 1 and the leap day lands at the end of a cycle, which
    // is what removes the special-casing from the rest of the arithmetic.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);

    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        (secs / 60) % 60,
        secs % 60
    )
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
            // The id of the key above. Without it the entry is refused for naming a different log
            // and never reaches the signature check, which is the branch under test.
            log_id: "d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496".into(),
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
            log_id: wrong.log_id.clone(),
            ..Default::default()
        };
        let err = malformed.verify_set(key).expect_err("zeroes are not DER");
        assert!(format!("{err}").contains("not a DER signature"), "{err}");
    }

    #[test]
    fn a_key_for_another_log_is_refused_before_any_signature_is_checked() {
        // The two had to agree and nothing said they did. `logID` *is* the hash of the log's key,
        // so an entry names the key that must verify it — and verifying against a different one
        // produces a failure indistinguishable from a forged entry. Caught by identity instead.
        let (name, pem) =
            super::known_log("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d")
                .expect("production is a known log");
        assert_eq!(name, "rekor.sigstore.dev");

        let staging_entry = LogEntry {
            log_id: "d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496".into(),
            ..Default::default()
        };
        let err = staging_entry
            .verify_set(pem)
            .expect_err("production's key cannot speak for a staging entry");
        let msg = format!("{err}");
        assert!(
            msg.contains("names log d32f") && msg.contains("key given is for log c0d2"),
            "the refusal has to name both logs, or it reads like a bad signature: {msg}"
        );
    }

    #[test]
    fn a_compiled_in_key_hashes_to_the_id_it_is_filed_under() {
        // What makes shipping keys safe: the table is indexed by the hash of its own values, so a
        // wrong or tampered entry cannot be selected for an entry it does not belong to.
        for (id, name, pem) in super::KNOWN_LOGS {
            assert_eq!(
                &super::log_key_id(pem).expect("a known log's key parses"),
                id,
                "{name} is filed under an id its key does not hash to"
            );
        }
    }

    #[test]
    fn a_timestamp_reads_back_as_the_date_it_is() {
        // Spot dates the arithmetic is easy to get wrong on: a leap day, the epoch, a year 2100
        // that is not a leap year, and the instant our own staging entry was logged.
        assert_eq!(super::utc_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::utc_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::utc_rfc3339(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(super::utc_rfc3339(1_789_568_827), "2026-09-16T14:27:07Z");
        assert_eq!(super::utc_rfc3339(-1), "1969-12-31T23:59:59Z");
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
