//! The two public keys an evidence source is pinned by, parsed and checked where they are named.
//!
//! A source is pinned by its **log key**, a C2SP verifier key whose name is the log's origin, and
//! its **attestation key**, the ed25519 key its records are signed with (`docs/19` §2.4, §6.1).
//! Both are checked when the configuration is read rather than when a record first needs them: a
//! pin that does not parse is a source that verifies nothing, and finding that out on the first
//! sync, or not at all, is how a check comes to pass against no key.

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePublicKey as _;
use sha2::{Digest as _, Sha256};

use crate::AttestError;
use crate::location::printable;

/// The C2SP signed-note key type for Ed25519, the only one the witness network takes and the one
/// `docs/19` §2.3 fixes for the log.
pub(crate) const ED25519: u8 = 0x01;

/// A C2SP verifier key: `<name>+<hash>+<key>`.
///
/// `name` is the log's origin (`docs/19` §2.3). `hash` is eight hex digits, the first four bytes
/// of SHA-256 over the name, a newline and the key bytes; `key` is base64 of the type byte `0x01`
/// followed by the 32-byte Ed25519 public key. The hash is recomputed and a key whose hash does not
/// match is refused, because the hash is how a signed note names the key that signed it: a vkey
/// whose hash names some other key would verify notes nobody signed with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogVkey {
    origin: String,
    hash: [u8; 4],
    key: VerifyingKey,
}

impl LogVkey {
    /// Parse and check a verifier key string.
    pub fn parse(s: &str) -> Result<Self, AttestError> {
        // Escaped: a key comes from a configuration a project may have written, and the refusal
        // is printed into a terminal or a CI log.
        let shown = printable(s);
        let bad = |why: &str| {
            AttestError::Key(format!(
                "`{shown}` is not a C2SP verifier key: {why}. A log key is \
                 `<origin>+<8 hex>+<base64>`, as in \
                 `github.com/<owner>/trigon-evidence+1a2b3c4d+AR…`"
            ))
        };
        // The name ends at the first `+`, which a name may not contain; the hash is the next eight
        // characters; the key is everything after, and base64 may itself contain `+`.
        let (name, rest) = s.split_once('+').ok_or_else(|| bad("it has no `+`"))?;
        let (hash, key) = rest
            .split_once('+')
            .ok_or_else(|| bad("it has one `+`, and a verifier key has two"))?;
        if name.is_empty() {
            return Err(bad("its name, the log's origin, is empty"));
        }
        if !is_key_name(name) {
            return Err(bad("its name contains whitespace or a control character"));
        }
        let hash = parse_hash(hash).ok_or_else(|| bad("its key hash is not eight hex digits"))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|e| bad(&format!("its key is not base64 ({e})")))?;
        let Some((&kind, bytes)) = raw.split_first() else {
            return Err(bad("its key is empty"));
        };
        if kind != ED25519 {
            return Err(bad(&format!(
                "its key type is 0x{kind:02x}, and a Trigon log key is Ed25519 (type 0x01)"
            )));
        }
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            bad(&format!(
                "its Ed25519 key is {} bytes, and one is 32",
                bytes.len()
            ))
        })?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| bad(&format!("its key is not a valid Ed25519 point ({e})")))?;
        let want = key_hash(name, &bytes);
        if want != hash {
            return Err(bad(&format!(
                "its hash is {} and its name and key hash to {}, so it names a key other than the \
                 one it carries",
                hex(&hash),
                hex(&want)
            )));
        }
        Ok(LogVkey {
            origin: name.to_string(),
            hash,
            key,
        })
    }

    /// The verifier key of an Ed25519 key under a name, as [`crate::log::LogSigner`] derives its
    /// own. The name is held to what [`Self::parse`] accepts, so the key it makes reads back.
    pub fn new(name: &str, key: &VerifyingKey) -> Result<Self, AttestError> {
        let mut raw = vec![ED25519];
        raw.extend_from_slice(key.as_bytes());
        Self::parse(&format!(
            "{name}+{}+{}",
            hex(&key_hash(name, key.as_bytes())),
            base64::engine::general_purpose::STANDARD.encode(raw)
        ))
    }

    /// The log's origin: the key's name, which is also the first line of every checkpoint it signs.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The four-byte key hash a signed note names this key by.
    pub fn key_hash(&self) -> [u8; 4] {
        self.hash
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

impl std::fmt::Display for LogVkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut raw = vec![ED25519];
        raw.extend_from_slice(self.key.as_bytes());
        write!(
            f,
            "{}+{}+{}",
            self.origin,
            hex(&self.hash),
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }
}

/// An attestation key: the ed25519 public key a source's records are signed with.
///
/// Given as 64 hex digits, which is what `trigon keygen` and `trigon public-key` print, or as SPKI
/// PEM, which is what `keygen --public-out` and `public-key --pem` write and what an evidence
/// repository publishes as `keys/attestation.pub`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationKey {
    key: VerifyingKey,
}

impl AttestationKey {
    /// Whether `s` is written as a key rather than as a path to one: exactly 64 hex digits.
    pub fn looks_like_hex(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    pub fn from_hex(s: &str) -> Result<Self, AttestError> {
        if !Self::looks_like_hex(s) {
            return Err(AttestError::Key(format!(
                "`{}` is not an ed25519 public key in hex: one is 64 hex digits, as `trigon \
                 public-key` prints it",
                printable(s)
            )));
        }
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| AttestError::Key(format!("`{s}` is not hex: {e}")))?;
        }
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| AttestError::Key(format!("`{s}` is not a valid ed25519 key: {e}")))?;
        Ok(AttestationKey { key })
    }

    /// Read SPKI PEM, as `LocalKey::public_pem` writes it.
    pub fn from_pem(pem: &str) -> Result<Self, AttestError> {
        let key = VerifyingKey::from_public_key_pem(pem.trim()).map_err(|e| {
            AttestError::Key(format!(
                "not an ed25519 public key in SPKI PEM ({e}); `trigon public-key <key> --pem` \
                 writes one"
            ))
        })?;
        Ok(AttestationKey { key })
    }

    /// The key as SPKI PEM, as [`crate::LocalKey::public_pem`] writes it: what an evidence
    /// repository publishes as `keys/attestation.pub`, and what `trigon log init` writes there.
    pub fn to_pem(&self) -> String {
        crate::signer::spki_pem(&self.key)
    }

    /// The key as hex, which is what [`crate::verify_signature`] takes.
    pub fn to_hex(&self) -> String {
        hex(self.key.as_bytes())
    }

    /// The key id a signature made with this key carries, as [`crate::LocalKey`] computes it.
    pub fn key_id(&self) -> String {
        hex(&Sha256::digest(self.key.as_bytes()))[..16].to_string()
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

impl From<VerifyingKey> for AttestationKey {
    fn from(key: VerifyingKey) -> Self {
        AttestationKey { key }
    }
}

/// Whether `name` can name a key this crate pins or makes: non-empty, and no Unicode space, no
/// control character, and no `+`, which ends the name in a verifier key. One rule for both, so a
/// log signer exists only under a name its verifier key can carry.
pub(crate) fn is_key_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '+')
}

/// SHA-256(name || "\n" || 0x01 || key), first four bytes: the C2SP key hash of an Ed25519 key.
pub(crate) fn key_hash(name: &str, key: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([ED25519]);
    h.update(key);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

fn parse_hash(s: &str) -> Option<[u8; 4]> {
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Published verifier keys, so the hash is checked against somebody else's arithmetic rather
    /// than against itself. The first is the Go checksum database's, pinned in every Go toolchain;
    /// the second is the example in the documentation of `golang.org/x/mod/sumdb/note`.
    const PUBLISHED: [(&str, &str, [u8; 4]); 2] = [
        (
            "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
            "sum.golang.org",
            [0x03, 0x3d, 0xe0, 0xae],
        ),
        (
            "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
            "PeterNeumann",
            [0xc7, 0x4f, 0x20, 0xa3],
        ),
    ];

    #[test]
    fn published_verifier_keys_parse_and_their_hashes_recompute() {
        for (vkey, origin, hash) in PUBLISHED {
            let k = LogVkey::parse(vkey).unwrap_or_else(|e| panic!("{vkey}: {e}"));
            assert_eq!(k.origin(), origin);
            assert_eq!(k.key_hash(), hash);
            // And it writes itself back byte for byte, so a key read from a configuration file
            // and shown to a person is the string they wrote.
            assert_eq!(k.to_string(), vkey);
        }
    }

    #[test]
    fn a_vkey_whose_hash_names_another_key_is_refused() {
        let wrong = "sum.golang.org+033de0af+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";
        let e = LogVkey::parse(wrong).unwrap_err().to_string();
        assert!(e.contains("033de0af") && e.contains("033de0ae"), "{e}");
        // The same key under another name hashes differently, so it too is refused: the name is
        // the origin, and a key moved to another origin is a different key.
        let renamed = "sum.golang.org2+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";
        assert!(LogVkey::parse(renamed).is_err());
    }

    #[test]
    fn malformed_vkeys_are_refused_with_the_reason() {
        for (s, says) in [
            ("sum.golang.org", "no `+`"),
            ("sum.golang.org+033de0ae", "one `+`"),
            (
                "+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
                "empty",
            ),
            ("sum.golang.org+033de0a+Ac4zct", "eight hex"),
            ("sum.golang.org+033de0ae+!!!", "base64"),
            ("sum.golang.org+033de0ae+", "its key is empty"),
            // Type 0x02, and the ed25519 bytes after it: the right length, the wrong kind.
            (
                "sum.golang.org+033de0ae+As4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
                "Ed25519",
            ),
            ("sum.golang.org+033de0ae+AQID", "32"),
            (
                "sum golang+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
                "whitespace",
            ),
        ] {
            let e = LogVkey::parse(s).unwrap_err().to_string();
            assert!(e.contains(says), "{s}: {e}");
        }
    }

    #[test]
    fn an_attestation_key_reads_the_forms_keygen_writes() {
        let local = crate::LocalKey::from_bytes(&[7u8; 32]).unwrap();
        let from_hex = AttestationKey::from_hex(&local.public_hex()).unwrap();
        let from_pem = AttestationKey::from_pem(&local.public_pem()).unwrap();
        assert_eq!(from_hex, from_pem);
        assert_eq!(from_hex.to_hex(), local.public_hex());
        assert_eq!(from_hex.verifying_key(), &local.public_key());
        // The key id a signature carries, so a check can say which key it expected.
        use crate::Signer as _;
        assert_eq!(from_hex.key_id(), local.key_id());

        assert!(AttestationKey::from_hex("abcd").is_err());
        assert!(
            AttestationKey::from_pem(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
            )
            .is_err()
        );
        assert!(!AttestationKey::looks_like_hex("./keys/attestation.pub"));
    }
}
