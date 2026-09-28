//! The signing seam.
//!
//! Synchronous, which departs from `docs/09` §3. The reason is the verifier build: it links this
//! crate and must contain no async runtime, and a synchronous trait can be called from an async
//! context by whatever holds the runtime while the reverse needs an executor everywhere. Local and
//! subprocess signers are the ones that exist; a network signer (a KMS) blocks in its own
//! implementation or lives behind an async façade in a crate below the line.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::AttestError;
use crate::dsse::Signature;

pub trait Signer: Send + Sync {
    /// Identifies the key, so a verifier can say which one it checked against.
    fn key_id(&self) -> String;
    fn sign(&self, pae: &[u8]) -> Result<Signature, AttestError>;
}

/// Emit statements without signing them.
///
/// Not a placeholder: an unsigned statement is still the full claim, still canonical, and still
/// re-derivable by `verify-attestation --rerun-comparison`, which is the part that makes a
/// rebuilder's attestation worth anything. What it lacks is a way to know who produced it, so
/// nothing downstream may treat it as verified. `Envelope::is_signed` is how that stays visible.
pub struct Unsigned;

impl Signer for Unsigned {
    fn key_id(&self) -> String {
        String::new()
    }
    fn sign(&self, _pae: &[u8]) -> Result<Signature, AttestError> {
        Ok(Signature::default())
    }
}

/// An ed25519 key held in a file. Development and air-gapped use, and, until a root exists, the
/// single pinned key records are published under (ADR-0014 Decision 8).
pub struct LocalKey {
    key: SigningKey,
    key_id: String,
}

impl LocalKey {
    /// Generate one.
    pub fn generate() -> Self {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        Self::from_key(key)
    }

    fn from_key(key: SigningKey) -> Self {
        // The key id is a digest of the public key, not a name someone chose. A name can be
        // reused for a different key; this cannot.
        let key_id = hex(&Sha256::digest(key.verifying_key().as_bytes()))[..16].to_string();
        LocalKey { key, key_id }
    }

    /// Read the raw 32-byte seed.
    pub fn from_bytes(seed: &[u8]) -> Result<Self, AttestError> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| AttestError::Key("an ed25519 seed is 32 bytes".into()))?;
        Ok(Self::from_key(SigningKey::from_bytes(&seed)))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The public key as hex, which is what a verifier is given to pin.
    pub fn public_hex(&self) -> String {
        hex(self.key.verifying_key().as_bytes())
    }

    /// The public key as SPKI PEM, which is what `openssl` and most other tools read, and the form
    /// an evidence repository publishes its attestation key in (`keys/attestation.pub`, docs/19
    /// §2.3).
    ///
    /// Hand-built rather than pulled from a PEM crate, because for ed25519 the SPKI DER is a fixed
    /// twelve-byte prefix and the thirty-two key bytes — `SEQUENCE { SEQUENCE { OID 1.3.101.112 },
    /// BIT STRING }`, where every length is known at compile time. RFC 8410 §4. A crate would be
    /// more code in the judgement half to emit forty-four constant-shaped bytes.
    pub fn public_pem(&self) -> String {
        const SPKI_ED25519: [u8; 12] = [
            0x30, 0x2a, // SEQUENCE, 42 bytes
            0x30, 0x05, // SEQUENCE, 5 bytes — the algorithm identifier
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112, id-Ed25519
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
        ];
        let mut der = SPKI_ED25519.to_vec();
        der.extend_from_slice(self.key.verifying_key().as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
        for line in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END PUBLIC KEY-----\n");
        out
    }
}

impl Signer for LocalKey {
    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn sign(&self, pae: &[u8]) -> Result<Signature, AttestError> {
        let sig = self.key.sign(pae);
        Ok(Signature {
            sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            keyid: self.key_id.clone(),
            // A bare key, so there is no chain and the statement says so rather than implying one.
            // `LocalKey` is the development rung of ADR-0011's ladder and produces an *unchained*
            // signature by design.
            chain: Vec::new(),
        })
    }
}

/// Check a signature against a public key given as hex.
///
/// Separate from the signer because verification is the half a sceptic runs, and they have our
/// public key rather than our signer.
pub fn verify(pae: &[u8], sig: &Signature, public_hex: &str) -> Result<(), AttestError> {
    let key_bytes =
        unhex(public_hex).ok_or_else(|| AttestError::Key("public key is not hex".into()))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AttestError::Key("an ed25519 public key is 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AttestError::Key(format!("not a valid ed25519 public key: {e}")))?;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(&sig.sig)
        .map_err(|e| AttestError::Evidence(format!("signature is not base64: {e}")))?;
    let raw: [u8; 64] = raw
        .try_into()
        .map_err(|_| AttestError::Evidence("an ed25519 signature is 64 bytes".into()))?;

    // `verify_strict`, not `verify`. The permissive form implements RFC 8032's verification
    // equation and accepts a small-order public key and a non-canonical encoding, which together
    // mean a signature does not uniquely bind to one key or to one byte string. The practical
    // exposure here is small — the key comes from the operator's `--public-key`, not from the
    // bundle — but the strict form costs nothing and the thing being checked is the only reason to
    // trust any of this.
    key.verify_strict(pae, &ed25519_dalek::Signature::from_bytes(&raw))
        .map_err(|_| AttestError::BadSignature)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod pem_tests {
    use base64::Engine as _;
    use ed25519_dalek::pkcs8::DecodePublicKey as _;

    use super::LocalKey;

    #[test]
    fn the_public_pem_is_spki_and_round_trips_through_a_real_parser() {
        // Hand-built DER is exactly the kind of thing that looks right and is off by a byte, so it
        // is checked against a parser that did not write it: `ed25519-dalek`'s own SPKI decoder,
        // which has to read the structure, the algorithm and the key back to the same key.
        let key = LocalKey::from_bytes(&[7u8; 32]).unwrap();
        let pem = key.public_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));

        // 12 prefix bytes + 32 key bytes = 44, which is 60 base64 characters on one line.
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let der = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .expect("the body is base64");
        assert_eq!(der.len(), 44, "SPKI for ed25519 is 44 bytes");
        // The OID for id-Ed25519, where RFC 8410 §4 puts it.
        assert_eq!(&der[4..9], &[0x06, 0x03, 0x2b, 0x65, 0x70]);
        assert_eq!(&der[12..], key.public_key().as_bytes());

        let parsed = ed25519_dalek::VerifyingKey::from_public_key_pem(&pem)
            .expect("a PEM decoder that did not write this reads it");
        assert_eq!(parsed, key.public_key());
    }
}
