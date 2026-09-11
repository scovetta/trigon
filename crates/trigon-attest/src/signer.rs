//! The signing seam.
//!
//! Synchronous, which departs from `docs/09` §3. The reason is the verifier build: it links this
//! crate and must contain no async runtime, and a synchronous trait can be called from an async
//! context by whatever holds the runtime while the reverse needs an executor everywhere. Local and
//! subprocess signers are the ones that exist; a network signer (sigstore, KMS) blocks in its own
//! implementation or lives behind an async façade in a crate below the line.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
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
        Ok(Signature {
            sig: String::new(),
            keyid: String::new(),
        })
    }
}

/// An ed25519 key held in a file. Development and air-gapped use.
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
        .map_err(|e| AttestError::Malformed(format!("signature is not base64: {e}")))?;
    let raw: [u8; 64] = raw
        .try_into()
        .map_err(|_| AttestError::Malformed("an ed25519 signature is 64 bytes".into()))?;

    key.verify(pae, &ed25519_dalek::Signature::from_bytes(&raw))
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
