//! The evidence log's leaves (`docs/19` §2.3).
//!
//! A leaf is one JSON object in canonical form (`trigon_core::jcs`), with its `kind` and the
//! `time` it was logged, in Unix seconds. Six kinds:
//!
//! - `record`: one published record — a verdict, a void or a withdrawal — and what a client finds
//!   it by: the subject's digests, the canonical purl, the predicate type and outcome, the
//!   stabilizer set, the signing key's id and the record file's digest, and any supersession;
//! - `heartbeat`: its time and nothing else, appended in a week with nothing else (§7);
//! - `key-change`: the old and new attestation keys, each signing a message that names both
//!   (§8);
//! - `release`: a client release's digests, signed by the release key (§6, phase 9);
//! - `log-end`: the last leaf of a log being succeeded, naming the successor (§8);
//! - `log-continuation`: the successor's first leaf, holding the old log's final checkpoint signed
//!   by both log keys (§8).
//!
//! **Decoding is strict.** An unknown kind and an unknown field are errors, not things to read
//! past, unlike the statements and record files a verifier reads (which may gain fields): these
//! are formats we own and sign into the tree, and a leaf this build cannot fully read is one it
//! cannot say anything true about. A leaf that is valid JSON but not canonical is refused too, so
//! a leaf's hash is a function of what it says. The rules on each field are the ones a writer is
//! held to, checked on both sides, so nothing is written that a reader would refuse.
//!
//! Times are at most 2^53 − 1, the largest integer every JSON reader holds exactly, since the
//! standalone client (`docs/19` §6) is JavaScript and Python.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trigon_core::Digest;
use trigon_core::purl::{self, PURL_CANON};

use super::LogError;
use super::checkpoint::Checkpoint;
use super::note::SignedNote;
use super::tiles::MAX_LEAF;
use crate::location::{Location, Transport, printable};
use crate::signer::Signer as _;
use crate::{
    AttestationKey, DIVERGENCE_V2, EQUIVALENCE_V2, LocalKey, LogVkey, Signature, SupersedeReason,
    VOID, WITHDRAWAL,
};

/// The latest time a leaf may carry: 2^53 − 1.
pub const MAX_TIME: u64 = (1 << 53) - 1;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// One leaf of the evidence log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Leaf {
    Record(RecordLeaf),
    Heartbeat(HeartbeatLeaf),
    KeyChange(KeyChangeLeaf),
    Release(ReleaseLeaf),
    LogEnd(LogEndLeaf),
    LogContinuation(LogContinuationLeaf),
}

/// Every `kind`, in the order `docs/19` §2.3 lists them.
pub const KINDS: [&str; 6] = [
    "record",
    "heartbeat",
    "key-change",
    "release",
    "log-end",
    "log-continuation",
];

impl Leaf {
    /// The leaf's `kind`.
    pub fn kind(&self) -> &'static str {
        match self {
            Leaf::Record(_) => KINDS[0],
            Leaf::Heartbeat(_) => KINDS[1],
            Leaf::KeyChange(_) => KINDS[2],
            Leaf::Release(_) => KINDS[3],
            Leaf::LogEnd(_) => KINDS[4],
            Leaf::LogContinuation(_) => KINDS[5],
        }
    }

    /// When the leaf was logged, in Unix seconds.
    pub fn time(&self) -> u64 {
        match self {
            Leaf::Record(l) => l.time,
            Leaf::Heartbeat(l) => l.time,
            Leaf::KeyChange(l) => l.time,
            Leaf::Release(l) => l.time,
            Leaf::LogEnd(l) => l.time,
            Leaf::LogContinuation(l) => l.time,
        }
    }

    /// Check every rule on the leaf's fields.
    pub fn validate(&self) -> Result<(), LogError> {
        let kind = self.kind();
        if self.time() > MAX_TIME {
            return Err(invalid(
                kind,
                format!(
                    "its time {} is past {MAX_TIME}, the largest integer every JSON reader holds \
                     exactly",
                    self.time()
                ),
            ));
        }
        match self {
            Leaf::Record(l) => l.validate(),
            Leaf::Heartbeat(_) => Ok(()),
            Leaf::KeyChange(l) => l.validate(),
            Leaf::Release(l) => l.validate(),
            Leaf::LogEnd(l) => l.validate(),
            Leaf::LogContinuation(l) => l.validate(),
        }
        .map_err(|why| invalid(kind, why))
    }

    /// The leaf's bytes: its canonical JSON. Refused if any rule on its fields fails, or if it is
    /// too long for an entry bundle to frame.
    pub fn encode(&self) -> Result<Vec<u8>, LogError> {
        self.validate()?;
        let value = match self {
            Leaf::Record(l) => serde_json::to_value(l),
            Leaf::Heartbeat(l) => serde_json::to_value(l),
            Leaf::KeyChange(l) => serde_json::to_value(l),
            Leaf::Release(l) => serde_json::to_value(l),
            Leaf::LogEnd(l) => serde_json::to_value(l),
            Leaf::LogContinuation(l) => serde_json::to_value(l),
        }
        .map_err(|e| LogError::Malformed(format!("could not write a {} leaf: {e}", self.kind())))?;
        let Value::Object(mut map) = value else {
            unreachable!("every leaf is a struct, which serializes as an object");
        };
        map.insert("kind".into(), Value::String(self.kind().into()));
        let bytes = trigon_core::jcs::canonicalize(&Value::Object(map))
            .map_err(|e| {
                LogError::Malformed(format!("could not write a {} leaf: {e}", self.kind()))
            })?
            .into_bytes();
        if bytes.len() > MAX_LEAF {
            return Err(LogError::Malformed(format!(
                "this {} leaf is {} bytes, and an entry bundle frames a leaf of at most {MAX_LEAF}",
                self.kind(),
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Read a leaf, strictly: a known kind, no unknown field, every rule on its fields, and the
    /// canonical form byte for byte.
    pub fn decode(bytes: &[u8]) -> Result<Leaf, LogError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|e| {
            LogError::Malformed(format!(
                "this leaf is not JSON: {}",
                printable(&e.to_string())
            ))
        })?;
        let Value::Object(mut map) = value else {
            return Err(LogError::Malformed(
                "this leaf is not a JSON object, and every leaf is one".into(),
            ));
        };
        let kind = match map.remove("kind") {
            Some(Value::String(k)) => k,
            Some(_) => {
                return Err(LogError::Malformed(
                    "this leaf's `kind` is not a string".into(),
                ));
            }
            None => return Err(LogError::Malformed("this leaf has no `kind`".into())),
        };
        let rest = Value::Object(map);
        let leaf = match kind.as_str() {
            "record" => Leaf::Record(fields(rest, &kind)?),
            "heartbeat" => Leaf::Heartbeat(fields(rest, &kind)?),
            "key-change" => Leaf::KeyChange(fields(rest, &kind)?),
            "release" => Leaf::Release(fields(rest, &kind)?),
            "log-end" => Leaf::LogEnd(fields(rest, &kind)?),
            "log-continuation" => Leaf::LogContinuation(fields(rest, &kind)?),
            other => {
                return Err(LogError::Malformed(format!(
                    "this leaf's kind is `{}`, which this build does not know; the kinds are {}. \
                     A log that holds one was written by a newer Trigon, and this one cannot say \
                     what it means: update it",
                    printable(other),
                    KINDS.join(", ")
                )));
            }
        };
        leaf.validate()?;
        if leaf.encode()? != bytes {
            return Err(LogError::Malformed(format!(
                "this {kind} leaf is not in canonical form: written canonically it is other bytes, \
                 and a leaf is written canonically so that its hash is a function of what it says"
            )));
        }
        Ok(leaf)
    }
}

/// A leaf's fields, by kind. serde's refusal quotes an unknown field or variant as it was written,
/// and a leaf is anyone's bytes until its root is checked, so the refusal is escaped before it
/// reaches a terminal.
fn fields<T: DeserializeOwned>(rest: Value, kind: &str) -> Result<T, LogError> {
    serde_json::from_value(rest)
        .map_err(|e| LogError::Malformed(format!("a {kind} leaf: {}", printable(&e.to_string()))))
}

fn invalid(kind: &str, why: String) -> LogError {
    LogError::Malformed(format!("a {kind} leaf: {why}"))
}

/// A published record's leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordLeaf {
    pub time: u64,
    /// The subject's digests, by algorithm, in lowercase hex: `sha256` always, and `sha512` and
    /// `sha1` where the signed subject carries them. Every one is a key a client finds the record
    /// by (§5).
    pub subject: BTreeMap<String, String>,
    /// The canonical purl, under [`Self::purl_canon`].
    pub purl: String,
    pub purl_canon: u32,
    /// `equivalence/v2`, `divergence/v2`, `void/v1` or `withdrawal/v1`: the only predicates
    /// `publish` logs.
    pub predicate_type: String,
    /// The verdict's outcome; `void` for a void; absent for a withdrawal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<LeafOutcome>,
    /// The stabilizer-set digest: every verdict's, a void's where its run compared, never a
    /// withdrawal's.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sha256_opt")]
    pub stabilizer_set: Option<Digest>,
    /// The id of the attestation key the record is signed with.
    pub key_id: String,
    /// The sha256 of the record file.
    #[serde(with = "sha256_ref")]
    pub record: Digest,
    /// The record this one supersedes, for a supersession and every withdrawal.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sha256_opt")]
    pub supersedes: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<SupersedeReason>,
}

/// A record leaf's outcome: a verdict's four, and `void`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeafOutcome {
    Exact,
    Normalized,
    NormalizedWithCaveats,
    Divergent,
    Void,
}

impl LeafOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            LeafOutcome::Exact => "exact",
            LeafOutcome::Normalized => "normalized",
            LeafOutcome::NormalizedWithCaveats => "normalized_with_caveats",
            LeafOutcome::Divergent => "divergent",
            LeafOutcome::Void => "void",
        }
    }
}

impl std::fmt::Display for LeafOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RecordLeaf {
    fn validate(&self) -> Result<(), String> {
        check_digests(&self.subject, "its subject")?;
        // Canonical under the rule the leaf names, not today's: a leaf is never rewritten, so one
        // logged under an earlier rule must still read once the rule moves on. A rule this build
        // does not have is refused, since it cannot say whether the purl is canonical under it.
        if !(1..=PURL_CANON).contains(&self.purl_canon) {
            return Err(format!(
                "its purl is canonical under rule {}, and this build has rules 1 to \
                 {PURL_CANON}. A log that holds one was written by a newer Trigon: update it",
                self.purl_canon
            ));
        }
        match purl::canonicalize_under(self.purl_canon, &self.purl) {
            Ok(c) if c.as_str() == self.purl => {}
            Ok(c) => {
                return Err(format!(
                    "its purl `{}` is not canonical under rule {}: canonical, it is `{c}`",
                    printable(&self.purl),
                    self.purl_canon
                ));
            }
            Err(e) => {
                return Err(format!(
                    "its purl `{}` is not one: {e}",
                    printable(&self.purl)
                ));
            }
        }
        use LeafOutcome as O;
        let (outcomes, set): (&[LeafOutcome], Need) = match self.predicate_type.as_str() {
            EQUIVALENCE_V2 => (
                &[O::Exact, O::Normalized, O::NormalizedWithCaveats],
                Need::Always,
            ),
            DIVERGENCE_V2 => (&[O::Divergent], Need::Always),
            VOID => (&[O::Void], Need::Maybe),
            WITHDRAWAL => (&[], Need::Never),
            other => {
                return Err(format!(
                    "its predicate type `{}` is not one `publish` logs: {EQUIVALENCE_V2}, \
                     {DIVERGENCE_V2}, {VOID} or {WITHDRAWAL}",
                    printable(other)
                ));
            }
        };
        match self.outcome {
            None if outcomes.is_empty() => {}
            Some(o) if outcomes.contains(&o) => {}
            None => {
                return Err(format!(
                    "it has no outcome, and a {} has one",
                    self.predicate_type
                ));
            }
            Some(o) => {
                return Err(format!(
                    "its outcome `{o}` is not one a {} has",
                    self.predicate_type
                ));
            }
        }
        match (set, self.stabilizer_set) {
            (Need::Always, None) => {
                return Err(format!(
                    "it has no stabilizer set, and every {} names one",
                    self.predicate_type
                ));
            }
            (Need::Never, Some(_)) => {
                return Err("it names a stabilizer set, and a withdrawal names none".into());
            }
            _ => {}
        }
        check_key_id(&self.key_id)?;
        match (self.supersedes, self.reason) {
            (Some(_), Some(_)) => Ok(()),
            (None, None) if self.predicate_type != WITHDRAWAL => Ok(()),
            (None, None) => Err("a withdrawal names the record it supersedes and why".into()),
            _ => Err("it has one of `supersedes` and `reason` without the other".into()),
        }
    }
}

enum Need {
    Always,
    Maybe,
    Never,
}

/// A heartbeat: a leaf whose only fact is its time (§7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatLeaf {
    pub time: u64,
}

/// An attestation-key rotation (§8, ADR-0014 Decision 8): the old key and the new, each signing
/// [`KeyChangeLeaf::message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyChangeLeaf {
    pub time: u64,
    pub old: KeyChangeKey,
    pub new: KeyChangeKey,
}

/// One side of a key change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeyChangeKey {
    /// The key's id, as a record leaf and a signature name it.
    pub key_id: String,
    /// The Ed25519 public key, 64 lowercase hex.
    pub public_key: String,
    /// This key's signature over the message, base64.
    pub signature: String,
}

impl KeyChangeLeaf {
    /// What begins the message both keys sign, so no signature over it is a signature over
    /// anything else either key signs: a DSSE envelope's PAE begins `DSSEv1 `.
    pub const DOMAIN: &str = "trigon.dev/key-change/v1";

    /// The message both keys sign: the domain, the origin of the log the leaf is in, the leaf's
    /// time, and the old and new keys in hex, each on a line of its own.
    ///
    /// The origin binds the change to one log, so a key shared by two sources cannot have one's
    /// rotation replayed into the other; the time binds it to its place in that log.
    pub fn message(origin: &str, time: u64, old: &AttestationKey, new: &AttestationKey) -> Vec<u8> {
        format!(
            "{}\n{origin}\n{time}\n{}\n{}\n",
            Self::DOMAIN,
            old.to_hex(),
            new.to_hex()
        )
        .into_bytes()
    }

    /// A key change from `old` to `new`, logged at `time` in the log `origin`, signed by both.
    pub fn sign(
        origin: &str,
        time: u64,
        old: &LocalKey,
        new: &LocalKey,
    ) -> Result<KeyChangeLeaf, LogError> {
        let (o, n) = (
            AttestationKey::from(old.public_key()),
            AttestationKey::from(new.public_key()),
        );
        let message = Self::message(origin, time, &o, &n);
        let side = |key: &LocalKey, public: &AttestationKey| -> Result<KeyChangeKey, LogError> {
            let sig = key
                .sign(&message)
                .map_err(|e| LogError::Malformed(format!("could not sign a key change: {e}")))?;
            Ok(KeyChangeKey {
                key_id: public.key_id(),
                public_key: public.to_hex(),
                signature: sig.sig,
            })
        };
        let leaf = KeyChangeLeaf {
            time,
            old: side(old, &o)?,
            new: side(new, &n)?,
        };
        Leaf::KeyChange(leaf.clone()).validate()?;
        Ok(leaf)
    }

    pub fn old_key(&self) -> Result<AttestationKey, LogError> {
        AttestationKey::from_hex(&self.old.public_key)
            .map_err(|e| invalid("key-change", e.to_string()))
    }

    pub fn new_key(&self) -> Result<AttestationKey, LogError> {
        AttestationKey::from_hex(&self.new.public_key)
            .map_err(|e| invalid("key-change", e.to_string()))
    }

    /// Check both signatures, for a leaf in the log `origin`.
    pub fn verify(&self, origin: &str) -> Result<(), LogError> {
        let (old, new) = (self.old_key()?, self.new_key()?);
        let message = Self::message(origin, self.time, &old, &new);
        for (side, which) in [(&self.old, "old"), (&self.new, "new")] {
            let sig = Signature {
                sig: side.signature.clone(),
                keyid: side.key_id.clone(),
                chain: Vec::new(),
            };
            crate::verify_signature(&message, &sig, &side.public_key).map_err(|_| {
                LogError::Rotation(format!(
                    "the key change logged at {} names {} as its {which} key, and that key's \
                     signature does not verify over the change in `{origin}`: a key change \
                     counts only when both keys sign it",
                    self.time, side.key_id
                ))
            })?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        for (side, which) in [(&self.old, "old"), (&self.new, "new")] {
            let key = AttestationKey::from_hex(&side.public_key)
                .ok()
                .filter(|k| k.to_hex() == side.public_key)
                .ok_or_else(|| {
                    format!("its {which} key is not an Ed25519 public key in 64 lowercase hex")
                })?;
            if key.key_id() != side.key_id {
                return Err(format!(
                    "its {which} key's id is {}, and that key's id is {}",
                    printable(&side.key_id),
                    key.key_id()
                ));
            }
            check_signature(&side.signature).map_err(|why| format!("its {which} key's {why}"))?;
        }
        if self.old.public_key == self.new.public_key {
            return Err("its old and new keys are one key".into());
        }
        Ok(())
    }
}

/// A client release, signed by the release key (§6, `docs/19` §10 phase 9). The format is fixed
/// here; nothing writes one until phase 9.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReleaseLeaf {
    pub time: u64,
    /// The client, such as `trigon-check`.
    pub name: String,
    pub version: String,
    /// Each released file by name, and its digests: `sha256` always, `sha512` where given, in
    /// lowercase hex.
    pub artifacts: BTreeMap<String, BTreeMap<String, String>>,
    /// The id of the release key.
    pub key_id: String,
    /// The release key's signature over [`ReleaseLeaf::message`], base64.
    pub signature: String,
}

impl ReleaseLeaf {
    pub const DOMAIN: &str = "trigon.dev/release/v1";

    /// The message the release key signs: the domain, the log's origin, the time, and the
    /// canonical JSON of the name, version and artifacts, each on a line of its own.
    pub fn message(&self, origin: &str) -> Result<Vec<u8>, LogError> {
        let what = serde_json::json!({
            "name": self.name,
            "version": self.version,
            "artifacts": self.artifacts,
        });
        let what =
            trigon_core::jcs::canonicalize(&what).map_err(|e| invalid("release", e.to_string()))?;
        Ok(format!("{}\n{origin}\n{}\n{what}\n", Self::DOMAIN, self.time).into_bytes())
    }

    /// A release leaf, signed with the release key.
    pub fn sign(
        origin: &str,
        time: u64,
        name: &str,
        version: &str,
        artifacts: BTreeMap<String, BTreeMap<String, String>>,
        key: &LocalKey,
    ) -> Result<ReleaseLeaf, LogError> {
        let mut leaf = ReleaseLeaf {
            time,
            name: name.into(),
            version: version.into(),
            artifacts,
            key_id: key.key_id(),
            signature: String::new(),
        };
        let sig = key
            .sign(&leaf.message(origin)?)
            .map_err(|e| LogError::Malformed(format!("could not sign a release: {e}")))?;
        leaf.signature = sig.sig;
        Leaf::Release(leaf.clone()).validate()?;
        Ok(leaf)
    }

    /// Check the signature under the pinned release key, for a leaf in the log `origin`.
    pub fn verify(&self, origin: &str, release_key: &AttestationKey) -> Result<(), LogError> {
        if release_key.key_id() != self.key_id {
            return Err(LogError::Unverified(format!(
                "the release {} {} is signed by the key {}, and the release key pinned is {}",
                self.name,
                self.version,
                self.key_id,
                release_key.key_id()
            )));
        }
        let sig = Signature {
            sig: self.signature.clone(),
            keyid: self.key_id.clone(),
            chain: Vec::new(),
        };
        crate::verify_signature(&self.message(origin)?, &sig, &release_key.to_hex()).map_err(|_| {
            LogError::BadSignature(format!(
                "the release {} {}'s signature does not verify under the release key",
                self.name, self.version
            ))
        })
    }

    fn validate(&self) -> Result<(), String> {
        for (what, s) in [("name", &self.name), ("version", &self.version)] {
            if !is_token(s, 128) {
                return Err(format!(
                    "its {what} `{}` is not 1 to 128 printable ASCII characters without spaces",
                    printable(s)
                ));
            }
        }
        if self.artifacts.is_empty() {
            return Err("it names no released file".into());
        }
        for (file, digests) in &self.artifacts {
            if !is_token(file, 255) || file.contains(['/', '\\']) || file == "." || file == ".." {
                return Err(format!(
                    "`{}` is not a file name: 1 to 255 printable ASCII characters, without spaces \
                     or slashes",
                    printable(file)
                ));
            }
            if digests.keys().any(|k| k == "sha1") {
                return Err(format!(
                    "{file} has a sha1, and a release names sha256 and sha512"
                ));
            }
            check_digests(digests, &format!("the file `{file}`"))?;
        }
        check_key_id(&self.key_id)?;
        check_signature(&self.signature)
    }
}

/// The last leaf of a log that a successor continues (§8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEndLeaf {
    pub time: u64,
    pub successor: Successor,
}

/// Where a log's successor is, and what verifies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Successor {
    /// The successor's origin, which is also its log key's name.
    pub origin: String,
    /// The successor's log key, a C2SP verifier key.
    pub log_key: String,
    /// Where to clone it. Empty when it is in this repository, which every mirror of the
    /// repository then serves too.
    pub urls: Vec<String>,
    /// Its directory in the repository: `log/<n>` in this one, and `log` or `log/<n>` in another.
    pub dir: String,
}

impl Successor {
    /// The successor's log key.
    pub fn vkey(&self) -> Result<LogVkey, LogError> {
        LogVkey::parse(&self.log_key).map_err(|e| invalid("log-end", e.to_string()))
    }

    /// Whether the successor is in the same repository as the log that names it.
    pub fn in_this_repository(&self) -> bool {
        self.urls.is_empty()
    }
}

impl LogEndLeaf {
    fn validate(&self) -> Result<(), String> {
        let s = &self.successor;
        let vkey = LogVkey::parse(&s.log_key).map_err(|e| format!("its successor's {e}"))?;
        if vkey.origin() != s.origin {
            return Err(format!(
                "its successor's origin is `{}` and its log key is named `{}`; a log key's name \
                 is its log's origin",
                printable(&s.origin),
                vkey.origin()
            ));
        }
        for (i, u) in s.urls.iter().enumerate() {
            let l = Location::parse(u, std::path::Path::new("/"), None)
                .map_err(|e| format!("its successor's {e}"))?;
            if matches!(l.transport(), Transport::LocalPath | Transport::File) {
                return Err(format!(
                    "its successor's location `{}` is a path on some machine, and a leaf names \
                     only locations anyone can clone",
                    printable(u)
                ));
            }
            if s.urls[..i].contains(u) {
                return Err(format!("it names `{}` twice", printable(u)));
            }
        }
        let numbered = s.dir.strip_prefix("log/").is_some_and(|n| {
            !n.starts_with('0') && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
        });
        if !(numbered || (s.dir == "log" && !s.in_this_repository())) {
            return Err(format!(
                "its successor's directory `{}` is not `log/<n>`, or `log` in another repository \
                 (docs/19 §2.3)",
                printable(&s.dir)
            ));
        }
        Ok(())
    }
}

/// The first leaf of a successor log: the old log's final checkpoint, signed by the old log key
/// and cosigned by the new one (§8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogContinuationLeaf {
    pub time: u64,
    /// The signed note, whole.
    pub checkpoint: String,
}

impl LogContinuationLeaf {
    pub fn note(&self) -> Result<SignedNote, LogError> {
        SignedNote::parse(self.checkpoint.as_bytes())
    }

    /// The old log's final checkpoint, as the note says; not verified.
    pub fn old_checkpoint(&self) -> Result<Checkpoint, LogError> {
        Checkpoint::parse(self.note()?.text())
    }

    fn validate(&self) -> Result<(), String> {
        let note = self.note().map_err(|e| format!("its checkpoint: {e}"))?;
        Checkpoint::parse(note.text()).map_err(|e| format!("its checkpoint: {e}"))?;
        if note.signatures().len() < 2 {
            return Err(
                "its checkpoint carries one signature, and it is signed by the old log key and \
                 the new"
                    .into(),
            );
        }
        Ok(())
    }
}

/// A digest map: `sha256` required, `sha512` and `sha1` allowed, each lowercase hex of its length.
/// `what` names the map's owner in a message: "its subject", "the file `x`".
fn check_digests(digests: &BTreeMap<String, String>, what: &str) -> Result<(), String> {
    if !digests.contains_key("sha256") {
        return Err(format!("{what} names no sha256"));
    }
    for (alg, hex) in digests {
        let len = match alg.as_str() {
            "sha256" => 64,
            "sha512" => 128,
            "sha1" => 40,
            other => {
                return Err(format!(
                    "{what} names `{}`, and a digest here is sha256, sha512 or sha1",
                    printable(other)
                ));
            }
        };
        if !is_lower_hex(hex, len) {
            return Err(format!(
                "the {alg} {what} names is not {len} lowercase hex digits"
            ));
        }
    }
    Ok(())
}

/// An attestation key's id: the first 16 hex digits of the sha256 of the public key.
fn check_key_id(id: &str) -> Result<(), String> {
    if is_lower_hex(id, 16) {
        Ok(())
    } else {
        Err(format!(
            "its key id `{}` is not 16 lowercase hex digits",
            printable(id)
        ))
    }
}

fn check_signature(b64: &str) -> Result<(), String> {
    match B64.decode(b64) {
        Ok(raw) if raw.len() == 64 => Ok(()),
        _ => Err("signature is not the base64 of an Ed25519 signature".into()),
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_token(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
}

/// `sha256:<64 lowercase hex>`, as a leaf writes a record's digest.
mod sha256_ref {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
    use trigon_core::Digest;

    pub fn serialize<S: Serializer>(d: &Digest, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("sha256:{}", d.to_hex()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Digest, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).ok_or_else(|| {
            D::Error::custom(format!(
                "`{}` is not `sha256:` and 64 lowercase hex digits",
                crate::location::printable(&s)
            ))
        })
    }

    pub fn parse(s: &str) -> Option<Digest> {
        let hex = s.strip_prefix("sha256:")?;
        super::is_lower_hex(hex, 64)
            .then(|| Digest::from_hex(hex).ok())
            .flatten()
    }
}

mod sha256_opt {
    use serde::{Deserializer, Serializer};
    use trigon_core::Digest;

    pub fn serialize<S: Serializer>(d: &Option<Digest>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => super::sha256_ref::serialize(d, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Digest>, D::Error> {
        super::sha256_ref::deserialize(d).map(Some)
    }
}
