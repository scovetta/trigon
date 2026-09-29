//! C2SP tlog-checkpoint (<https://c2sp.org/tlog-checkpoint>): what the log key signs.
//!
//! A checkpoint's text is the log's origin, the tree size in decimal and the root hash in base64,
//! one per line, and it is signed as a note by the log key, whose name is the origin. The format
//! lets a log add extension lines after the root; ours writes none (`docs/19` §2.3), because a
//! witness's cosignature says nothing about them, and a reader tolerates them and ignores them —
//! nothing in one is ever trusted, since nobody but us would have vouched for it.

use base64::Engine as _;

use super::LogError;
use super::merkle::{Hash, empty_root};
use super::note::{LogSigner, SignedNote};
use crate::LogVkey;
use crate::location::printable;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A checkpoint's three facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

impl Checkpoint {
    /// The checkpoint of a log with no leaves: size 0, and the empty tree's root, SHA-256 of
    /// nothing. The first commit of an evidence repository holds one (`docs/19` §10 phase 5).
    pub fn empty(origin: &str) -> Checkpoint {
        Checkpoint {
            origin: origin.to_string(),
            size: 0,
            root: empty_root(),
        }
    }

    /// The text the log key signs: three lines, and no extension lines.
    pub fn body(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            B64.encode(self.root)
        )
    }

    /// Read a checkpoint's text. Extension lines after the root are read past and not kept.
    pub fn parse(text: &str) -> Result<Checkpoint, LogError> {
        let bad = |why: String| {
            LogError::Malformed(format!("this note's text is not a checkpoint: {why}"))
        };
        let Some(body) = text.strip_suffix('\n') else {
            return Err(bad("it does not end in a newline".into()));
        };
        let mut lines = body.split('\n');
        let (Some(origin), Some(size), Some(root)) = (lines.next(), lines.next(), lines.next())
        else {
            return Err(bad(
                "it has fewer than three lines: the origin, the tree size and the root hash".into(),
            ));
        };
        if origin.is_empty() {
            return Err(bad("its origin line is empty".into()));
        }
        let canonical = size == "0" || (!size.starts_with('0') && !size.is_empty());
        let size = size
            .parse::<u64>()
            .ok()
            .filter(|_| canonical && size.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| {
                bad(format!(
                    "its tree size `{}` is not a decimal number without leading zeros",
                    printable(size)
                ))
            })?;
        let root: Hash = B64
            .decode(root)
            .ok()
            .and_then(|r| r.try_into().ok())
            .ok_or_else(|| {
                bad(format!(
                    "its root hash `{}` is not the base64 of 32 bytes",
                    printable(root)
                ))
            })?;
        // Tolerated, never read. An empty one is not an extension line but a malformed note.
        if lines.any(str::is_empty) {
            return Err(bad("it has an empty line".into()));
        }
        Ok(Checkpoint {
            origin: origin.to_string(),
            size,
            root,
        })
    }
}

/// A checkpoint whose note verifies under its log's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    note: SignedNote,
    checkpoint: Checkpoint,
}

impl SignedCheckpoint {
    /// Read a checkpoint note and verify it: signed by `vkey`, and its origin is the key's name.
    ///
    /// The origin is checked as well as the signature because the key's name is what a client was
    /// told to trust; a checkpoint whose first line names another log is a statement about that
    /// log, whoever signed it.
    pub fn open(note: &[u8], vkey: &LogVkey) -> Result<SignedCheckpoint, LogError> {
        let note = SignedNote::parse(note)?;
        note.verify(vkey)?;
        let checkpoint = Checkpoint::parse(note.text())?;
        if checkpoint.origin != vkey.origin() {
            return Err(LogError::Unverified(format!(
                "this checkpoint is for the log `{}`, and the key it was checked with is \
                 `{}`'s; a checkpoint is accepted only for the origin its key names",
                printable(&checkpoint.origin),
                vkey.origin()
            )));
        }
        Ok(SignedCheckpoint { note, checkpoint })
    }

    /// Sign a checkpoint with the log key, as `trigon log sign` will. The signer's name must be
    /// the checkpoint's origin, so that what it signs opens under its own verifier key.
    pub fn sign(checkpoint: &Checkpoint, signer: &LogSigner) -> Result<SignedCheckpoint, LogError> {
        if checkpoint.origin != signer.name() {
            return Err(LogError::Malformed(format!(
                "a checkpoint for `{}` cannot be signed by the key named `{}`: a log key's name is \
                 its log's origin",
                printable(&checkpoint.origin),
                signer.name()
            )));
        }
        Checkpoint::parse(&checkpoint.body())?;
        Ok(SignedCheckpoint {
            note: SignedNote::sign(&checkpoint.body(), signer)?,
            checkpoint: checkpoint.clone(),
        })
    }

    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    pub fn note(&self) -> &SignedNote {
        &self.note
    }

    pub fn origin(&self) -> &str {
        &self.checkpoint.origin
    }

    pub fn size(&self) -> u64 {
        self.checkpoint.size
    }

    pub fn root(&self) -> &Hash {
        &self.checkpoint.root
    }
}

impl std::fmt::Display for SignedCheckpoint {
    /// The signed note, as `log/checkpoint` holds it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.note.fmt(f)
    }
}
