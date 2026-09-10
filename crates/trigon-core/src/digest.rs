use std::fmt;

use serde::{Deserialize, Serialize};

/// A SHA-256 digest.
///
/// Trigon addresses everything by this: blobs, stabilizer sets, strategies, corpora.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(#[serde(with = "hex32")] pub [u8; 32]);

impl Digest {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn from_hex(s: &str) -> Result<Self, ParseDigestError> {
        if s.len() != 64 {
            return Err(ParseDigestError::Length(s.len()));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = hexval(chunk[0]).ok_or(ParseDigestError::Char)?;
            let lo = hexval(chunk[1]).ok_or(ParseDigestError::Char)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseDigestError {
    #[error("expected 64 hex characters, got {0}")]
    Length(usize),
    #[error("non-hex character in digest")]
    Char,
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::Digest(*v).to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        super::Digest::from_hex(&s)
            .map(|x| x.0)
            .map_err(D::Error::custom)
    }
}

/// A SHA-512 digest. Recorded only on raw artifact digests, where a registry publishes one to
/// cross-check against.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha512(#[serde(with = "hex64")] pub [u8; 64]);

impl Sha512 {
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(128);
        for b in self.0 {
            use fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn from_hex(s: &str) -> Result<Self, ParseDigestError> {
        if s.len() != 128 {
            return Err(ParseDigestError::Length(s.len()));
        }
        let mut out = [0u8; 64];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = hexval(chunk[0]).ok_or(ParseDigestError::Char)?;
            let lo = hexval(chunk[1]).ok_or(ParseDigestError::Char)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

impl fmt::Debug for Sha512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha512({})", self.to_hex())
    }
}

mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::Sha512(*v).to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        super::Sha512::from_hex(&s)
            .map(|x| x.0)
            .map_err(D::Error::custom)
    }
}

/// Digests recorded for one artifact form.
///
/// SHA-256 always. SHA-512 alongside it on the two **raw** artifact digests only, because those are
/// the values a third party cross-checks against a registry and registries publish both. Container
/// and stabilized digests are SHA-256 alone: they are ours, nobody else publishes them, and doubling
/// them doubles the hashing cost of the hottest loop in the system.
///
/// See `docs/02-domain-model.md` §5.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MultiDigest {
    pub sha256: Digest,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha512: Option<Sha512>,
}

impl MultiDigest {
    pub const fn sha256_only(d: Digest) -> Self {
        Self {
            sha256: d,
            sha512: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let d = Digest([0xab; 32]);
        assert_eq!(d.to_hex().len(), 64);
        assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
    }

    #[test]
    fn empty_sha256_vector() {
        // The digest of the empty string, which the guard filters care about.
        let known = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(Digest::from_hex(known).unwrap().to_hex(), known);
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(Digest::from_hex("zz").is_err());
        assert!(Digest::from_hex(&"g".repeat(64)).is_err());
    }
}
