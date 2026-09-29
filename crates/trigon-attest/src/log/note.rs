//! C2SP signed notes (<https://c2sp.org/signed-note>), and the log key that signs them.
//!
//! A note is text ending in a newline, a blank line, and one or more signature lines, each an em
//! dash, a space, the key's name, a space, and the base64 of the key's four-byte hash followed by
//! the signature. The signature covers the text including its final newline, and not the blank
//! line. A checkpoint is a note (`docs/19` §2.3), and a witness cosigns one by adding a line, so
//! this follows the specification to the letter and reads what Go's `golang.org/x/mod/sumdb/note`
//! reads: the same limit on signature lines, a signature by an unknown key kept and ignored, and a
//! note refused whole when a line naming the pinned key does not verify. Two things are stricter.
//! Base64 must be canonical, since a line with two spellings is a line whose bytes are not fixed by
//! what it says. And every line naming the pinned key must verify, where Go checks the first and
//! skips the rest: Ed25519 is deterministic, so an honest signer writes one line, and a second,
//! different one was written by something else.
//!
//! **The private key format is Go's**, so a log key made with Go's tooling signs here and one made
//! here signs there: `PRIVATE+KEY+<name>+<hash>+<keydata>`, where `<hash>` is the same eight hex
//! digits as the verifier key's and `<keydata>` is base64 of the type byte `0x01` followed by the
//! 32-byte Ed25519 seed. The literal `PRIVATE+KEY` is there so the file is never mistaken for the
//! verifier key it pairs with.

use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use super::LogError;
use crate::keys::{ED25519, hex, is_key_name, key_hash};
use crate::location::printable;
use crate::{AttestError, LogVkey};

/// The most signature lines a note may carry. Go's reader stops at the same number. A checkpoint
/// carries one signature and a witnessed one a handful, so a note near this is not a checkpoint,
/// and reading on would spend a verifier's time for whoever wrote it.
pub const MAX_SIGNATURES: usize = 100;

/// What begins every signature line: an em dash (U+2014) and a space.
const SIGNATURE_PREFIX: &str = "\u{2014} ";

/// The longest private key file read. A key is some eighty bytes; this leaves room for a long
/// name and a trailing newline, and stops a path to something else being read whole.
const KEY_FILE_LIMIT: u64 = 4096;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A signed note, parsed and not yet verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedNote {
    text: String,
    signatures: Vec<NoteSignature>,
}

/// One signature line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSignature {
    name: String,
    key_hash: [u8; 4],
    /// The signature, after the key hash.
    signature: Vec<u8>,
    /// The line's base64 as written, so a note is written back byte for byte.
    base64: String,
}

impl NoteSignature {
    /// The name of the key that made it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The four-byte hash of the key that made it.
    pub fn key_hash(&self) -> [u8; 4] {
        self.key_hash
    }

    /// The signature, after the key hash.
    fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn line(&self) -> String {
        format!("{SIGNATURE_PREFIX}{} {}\n", self.name, self.base64)
    }

    fn names(&self, vkey: &LogVkey) -> bool {
        self.name == vkey.origin() && self.key_hash == vkey.key_hash()
    }
}

impl SignedNote {
    /// Read a note, strictly.
    ///
    /// Valid UTF-8 with no control character but the newline; text that ends in a newline, then a
    /// blank line; then between one and [`MAX_SIGNATURES`] well-formed signature lines, the last
    /// ending in a newline. Nothing is verified here: that is [`Self::verify`].
    pub fn parse(msg: &[u8]) -> Result<SignedNote, LogError> {
        let bad = |why: &str| LogError::Malformed(format!("this is not a signed note: {why}"));
        let msg = std::str::from_utf8(msg).map_err(|_| bad("it is not UTF-8"))?;
        if let Some(c) = msg.chars().find(|&c| c < ' ' && c != '\n') {
            return Err(bad(&format!(
                "it contains the control character {}, and a note may hold no control character \
                 but the newline",
                c.escape_default()
            )));
        }
        // The last blank line ends the text: a signature line cannot be empty, so no later one
        // can be the separator, and the text itself may hold blank lines.
        let split = msg
            .rfind("\n\n")
            .ok_or_else(|| bad("it has no blank line between its text and its signatures"))?;
        let (text, lines) = (&msg[..split + 1], &msg[split + 2..]);
        if lines.is_empty() {
            return Err(bad("it has no signature lines after its blank line"));
        }
        if !lines.ends_with('\n') {
            return Err(bad("its last signature line does not end in a newline"));
        }
        let mut signatures: Vec<NoteSignature> = Vec::new();
        for (i, line) in lines[..lines.len() - 1].split('\n').enumerate() {
            if i == MAX_SIGNATURES {
                return Err(bad(&format!(
                    "it has more than {MAX_SIGNATURES} signature lines"
                )));
            }
            let sig = parse_signature_line(line).map_err(|why| bad(&why))?;
            // A line given twice says nothing the first did not; Go drops it too.
            if !signatures.contains(&sig) {
                signatures.push(sig);
            }
        }
        Ok(SignedNote {
            text: text.to_string(),
            signatures,
        })
    }

    /// The note's text, including its final newline: what every signature covers.
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn signatures(&self) -> &[NoteSignature] {
        &self.signatures
    }

    /// Check the note against one key: it must carry a signature line naming the key, by name and
    /// key hash, whose signature verifies.
    ///
    /// Lines naming other keys are ignored, as the specification requires, because a witness adds
    /// its cosignature beside ours and a client need not know every witness. A line that names
    /// this key and does not verify refuses the note, even when another line by it does: the note
    /// was altered, or signed by something holding a key with our name and our hash.
    pub fn verify(&self, vkey: &LogVkey) -> Result<(), LogError> {
        let mine: Vec<&NoteSignature> = self.signatures.iter().filter(|s| s.names(vkey)).collect();
        if mine.is_empty() {
            let others: Vec<String> = self
                .signatures
                .iter()
                .map(|s| format!("{}+{}", printable(&s.name), hex(&s.key_hash)))
                .collect();
            return Err(LogError::Unverified(format!(
                "this note carries no signature by {}+{}; it is signed only by {}. A note is \
                 trusted only under a key pinned for it, so check that the key configured for \
                 this log is the one it is signed with",
                vkey.origin(),
                hex(&vkey.key_hash()),
                others.join(", ")
            )));
        }
        for s in mine {
            let raw = s.signature();
            let ok = <[u8; 64]>::try_from(raw).is_ok_and(|b| {
                // Strict, as every other signature check in this crate: a small-order key or a
                // non-canonical signature does not bind one key to one text.
                vkey.verifying_key()
                    .verify_strict(
                        self.text.as_bytes(),
                        &ed25519_dalek::Signature::from_bytes(&b),
                    )
                    .is_ok()
            });
            if !ok {
                return Err(LogError::BadSignature(format!(
                    "this note has a signature line naming {}+{} that does not verify under that \
                     key: the note was altered after it was signed, or signed by another key \
                     under the same name and hash",
                    vkey.origin(),
                    hex(&vkey.key_hash())
                )));
            }
        }
        Ok(())
    }

    /// Sign `text` as a new note.
    pub fn sign(text: &str, signer: &LogSigner) -> Result<SignedNote, LogError> {
        check_text(text)?;
        Ok(SignedNote {
            text: text.to_string(),
            signatures: vec![signer.sign_text(text)],
        })
    }

    /// Add a signature by `signer`, keeping every line already there except one by the same key,
    /// which the new line replaces. This is how a second key cosigns a note, as a log-continuation
    /// leaf's checkpoint is cosigned by the successor's key (`docs/19` §8).
    pub fn cosign(&self, signer: &LogSigner) -> Result<SignedNote, LogError> {
        let new = signer.sign_text(&self.text);
        let mut signatures: Vec<NoteSignature> = self
            .signatures
            .iter()
            .filter(|s| !(s.name == new.name && s.key_hash == new.key_hash))
            .cloned()
            .collect();
        if signatures.len() == MAX_SIGNATURES {
            return Err(LogError::Malformed(format!(
                "this note already carries {MAX_SIGNATURES} signatures, the most a note may"
            )));
        }
        signatures.push(new);
        Ok(SignedNote {
            text: self.text.clone(),
            signatures,
        })
    }
}

impl std::fmt::Display for SignedNote {
    /// The note as bytes on the wire: text, blank line, signature lines.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)?;
        f.write_str("\n")?;
        for s in &self.signatures {
            f.write_str(&s.line())?;
        }
        Ok(())
    }
}

fn parse_signature_line(line: &str) -> Result<NoteSignature, String> {
    let rest = line.strip_prefix(SIGNATURE_PREFIX).ok_or_else(|| {
        format!(
            "the line `{}` after its blank line is not a signature line, which begins with an em \
             dash and a space",
            printable(line)
        )
    })?;
    let (name, b64) = rest.split_once(' ').unwrap_or((rest, ""));
    if !is_valid_name(name) {
        return Err(format!(
            "`{}` is not a key name: one is non-empty and holds no space and no `+`",
            printable(name)
        ));
    }
    // A name need not be printable to be well formed, and this line is anyone's until it verifies.
    let shown = printable(name);
    let raw = B64
        .decode(b64)
        .map_err(|e| format!("the signature by `{shown}` is not base64 ({e})"))?;
    // A key hash and at least one byte of signature, as Go requires; the length a key type needs
    // is checked when a key of that type verifies it.
    if raw.len() < 5 {
        return Err(format!(
            "the signature by `{shown}` is {} bytes, shorter than a key hash and a signature",
            raw.len()
        ));
    }
    Ok(NoteSignature {
        name: name.to_string(),
        key_hash: [raw[0], raw[1], raw[2], raw[3]],
        signature: raw[4..].to_vec(),
        base64: b64.to_string(),
    })
}

/// A key name as a signature line may carry it: non-empty, no Unicode space, no `+`. What the
/// specification and Go's reader allow, so a cosignature by any key reads; a key this crate makes
/// or pins is held to [`LogVkey::parse`]'s stricter rule, with no control character either.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c == '+')
}

/// What a note's text must be before it is signed.
fn check_text(text: &str) -> Result<(), LogError> {
    let bad =
        |why: &str| LogError::Malformed(format!("this text cannot be signed as a note: {why}"));
    if text.is_empty() || !text.ends_with('\n') {
        return Err(bad("a note's text is non-empty and ends in a newline"));
    }
    if text.chars().any(|c| c < ' ' && c != '\n') {
        return Err(bad("it holds a control character other than the newline"));
    }
    Ok(())
}

/// A log key's private half: what signs a checkpoint.
///
/// Held only by the socketless `trigon log sign` (`docs/19` §8, §10 phase 5), and never printed:
/// `Debug` shows the name and the verifier key and nothing of the seed, and no error from reading
/// one quotes the key.
pub struct LogSigner {
    name: String,
    key: SigningKey,
    hash: [u8; 4],
    /// Made with the signer, so that a signer exists only where its verifier key does: a name
    /// that no `LogVkey` can carry would sign notes nothing can check.
    vkey: LogVkey,
}

impl std::fmt::Debug for LogSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogSigner")
            .field("name", &self.name)
            .field("key_hash", &hex(&self.hash))
            .finish_non_exhaustive()
    }
}

impl LogSigner {
    /// A new key for a log whose origin is `name`.
    pub fn generate(name: &str) -> Result<Self, AttestError> {
        Self::from_seed(name, SigningKey::generate(&mut rand_core::OsRng).to_bytes())
    }

    /// The key with this seed. For tests and fixtures, whose signatures must be the same on every
    /// run; a real key is [`Self::generate`]d.
    pub fn from_seed(name: &str, seed: [u8; 32]) -> Result<Self, AttestError> {
        if !is_key_name(name) {
            return Err(AttestError::Key(format!(
                "`{}` cannot name a log key: a name is non-empty and holds no space, no control \
                 character and no `+`",
                printable(name)
            )));
        }
        let key = SigningKey::from_bytes(&seed);
        let hash = key_hash(name, key.verifying_key().as_bytes());
        let vkey = LogVkey::new(name, &key.verifying_key())?;
        Ok(LogSigner {
            name: name.to_string(),
            key,
            hash,
            vkey,
        })
    }

    /// Read a private key in Go's format, `PRIVATE+KEY+<name>+<hash>+<keydata>`.
    ///
    /// The hash is recomputed from the key the seed derives, and a key whose hash does not match
    /// is refused, as Go refuses it: the hash is what every signature names the key by, so a
    /// mismatch would sign notes no verifier key could check.
    pub fn from_skey(skey: &str) -> Result<Self, AttestError> {
        // Never quoted: whatever is wrong with it, it may still be most of a secret.
        let bad = |why: &str| {
            AttestError::Key(format!(
                "this is not a log signing key: {why}. A signing key is \
                 `PRIVATE+KEY+<name>+<8 hex>+<base64>`, the format of Go's \
                 golang.org/x/mod/sumdb/note, where the base64 is the byte 0x01 and a 32-byte \
                 Ed25519 seed"
            ))
        };
        let mut parts = skey.splitn(5, '+');
        let (private, key, name, hash, data) = (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        );
        if private != "PRIVATE" || key != "KEY" {
            return Err(bad("it does not begin `PRIVATE+KEY+`"));
        }
        if !is_key_name(name) {
            return Err(bad(
                "its name is empty, or holds a space or a control character",
            ));
        }
        let hash = parse_hash(hash).ok_or_else(|| bad("its key hash is not eight hex digits"))?;
        let raw = B64
            .decode(data)
            .map_err(|_| bad("its key data is not base64"))?;
        // The length before the type byte, and the type byte's value never shown: key data of the
        // wrong length may be a bare seed, whose first byte is a byte of the secret.
        if raw.is_empty() {
            return Err(bad("its key data is empty"));
        }
        let Ok([kind, seed @ ..]) = <[u8; 33]>::try_from(raw.as_slice()) else {
            return Err(bad(&format!(
                "its key data is {} bytes, and a log key's is 33: the type byte and a 32-byte \
                 seed",
                raw.len()
            )));
        };
        if kind != ED25519 {
            return Err(bad(
                "its key type is not Ed25519 (type 0x01), the only type a log key has",
            ));
        }
        let signer = Self::from_seed(name, seed)?;
        if signer.hash != hash {
            return Err(bad(&format!(
                "its hash is {} and the key it holds hashes to {}, so it names another key",
                hex(&hash),
                hex(&signer.hash)
            )));
        }
        Ok(signer)
    }

    /// Read a private key from a file: one line, in [`Self::from_skey`]'s format.
    pub fn from_file(path: &Path) -> Result<Self, AttestError> {
        use std::io::Read as _;
        let shown = path.display();
        let file = std::fs::File::open(path)
            .map_err(|e| AttestError::Key(format!("could not read the log key {shown}: {e}")))?;
        let mut text = String::new();
        file.take(KEY_FILE_LIMIT)
            .read_to_string(&mut text)
            .map_err(|e| AttestError::Key(format!("could not read the log key {shown}: {e}")))?;
        let skey = text.trim_end_matches(['\n', '\r']);
        if skey.contains(['\n', '\r']) || text.len() as u64 == KEY_FILE_LIMIT {
            return Err(AttestError::Key(format!(
                "{shown} is not a log key file: one holds a single line"
            )));
        }
        Self::from_skey(skey).map_err(|e| AttestError::Key(format!("{shown}: {e}")))
    }

    /// The key in Go's private format: a secret, for writing to the file `[publish] log_key`
    /// names, and nowhere else.
    pub fn to_skey(&self) -> String {
        let mut raw = vec![ED25519];
        raw.extend_from_slice(&self.key.to_bytes());
        format!(
            "PRIVATE+KEY+{}+{}+{}",
            self.name,
            hex(&self.hash),
            B64.encode(raw)
        )
    }

    /// The verifier key a client pins for this log.
    pub fn vkey(&self) -> LogVkey {
        self.vkey.clone()
    }

    /// The key's name, which for a log key is its origin.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    fn sign_text(&self, text: &str) -> NoteSignature {
        let signature = self.key.sign(text.as_bytes()).to_bytes().to_vec();
        let raw = [self.hash.as_slice(), &signature].concat();
        NoteSignature {
            name: self.name.clone(),
            key_hash: self.hash,
            signature,
            base64: B64.encode(raw),
        }
    }
}

fn parse_hash(s: &str) -> Option<[u8; 4]> {
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok().map(u32::to_be_bytes)
}
