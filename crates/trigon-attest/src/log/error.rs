//! What can be wrong with a log, said so that a client can tell an attack from a broken file.

use trigon_core::{Classify, Fault};

use crate::location::printable;

/// Why a log, or one of its files, was refused.
///
/// The kinds are kept apart because a client answers them differently: a malformed or missing file
/// is a source that cannot be read, while a signature that does not verify, a tree that is not the
/// one its checkpoint signs, or a checkpoint that does not extend the one last accepted, is a
/// source that may be lying (`docs/19` §8), and is reported as failed verification, never as
/// nothing found.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// A note, checkpoint, leaf, tile or entry bundle that is not in the form its specification
    /// fixes.
    #[error("{0}")]
    Malformed(String),

    /// A file the checkpoint's tree needs, and the log does not have.
    #[error(
        "`{path}` is missing, and the checkpoint's tree needs it. A clone that holds the \
         checkpoint holds every file it covers; sync the clone again, and if the file is still \
         missing, the log's repository has lost it"
    )]
    Missing { path: String },

    /// A note that carries no valid signature by the key it was checked against.
    #[error("{0}")]
    Unverified(String),

    /// A signature line that names the key it was checked against and does not verify under it.
    #[error("{0}")]
    BadSignature(String),

    /// The files do not hold the tree the checkpoint signs, or a proof does not prove what it
    /// claims.
    #[error("{0}")]
    Mismatch(String),

    /// A checkpoint that does not extend the one last accepted: a rollback, a rewrite, or an
    /// equivocation. Both signed notes are kept as they were read, because `docs/19` §8 has the
    /// client print them, and are printed escaped: a signature line by a key nobody pinned is read
    /// past unverified, so its name, and a checkpoint's extension lines, are anyone's bytes.
    #[error(
        "{why}. This is a rollback, a rewrite of the log, or two different logs under one key, \
         and it is refused; keep both signed notes as evidence.\n\nThe checkpoint last accepted:\n\
         {}\nThe checkpoint offered:\n{}",
        shown(.accepted),
        shown(.offered)
    )]
    Inconsistent {
        why: String,
        accepted: String,
        offered: String,
    },

    /// Two checkpoints signed by the log's key whose trees are not one tree: the same size with
    /// two roots, or a smaller one the larger does not extend, found side by side in one
    /// repository. Only whoever holds the log key can sign both, so this is the log equivocating
    /// (`docs/19` §6.1, §8), and the source is refused. Both signed notes are kept as read and
    /// printed escaped, as [`LogError::Inconsistent`]'s are.
    #[error(
        "{why}. Two different trees signed by one log key is an equivocation, which only whoever \
         holds the key can sign, and the source is refused; keep both signed notes as \
         evidence.\n\nIn `{first_dir}`:\n{}\nIn `{second_dir}`:\n{}",
        shown(.first),
        shown(.second)
    )]
    Equivocation {
        why: String,
        first_dir: String,
        first: String,
        second_dir: String,
        second: String,
    },

    /// Leaves that break a rule of the log itself (`docs/19` §2.3): a time earlier than the leaf
    /// before it, a log-end that is not the last leaf, a log-continuation that is not the first.
    #[error("{0}")]
    Rule(String),

    /// A key-change, log-end or log-continuation leaf that does not do what `docs/19` §8 requires
    /// of it, or a successor log that no log-end leaf names.
    #[error("{0}")]
    Rotation(String),

    #[error("could not read `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl LogError {
    /// Whether this is a source failing verification — a signature, a tree or a checkpoint that
    /// does not hold — rather than one that could not be read. `docs/19` §4.2 and §8 report such a
    /// source as failed verification, since it may be lying, and never as nothing found; and the
    /// source is at fault, not Trigon, so nothing reporting one may say otherwise.
    pub fn fails_verification(&self) -> bool {
        match self {
            LogError::Unverified(_)
            | LogError::BadSignature(_)
            | LogError::Mismatch(_)
            | LogError::Inconsistent { .. }
            | LogError::Equivocation { .. }
            | LogError::Rule(_)
            | LogError::Rotation(_) => true,
            LogError::Malformed(_) | LogError::Missing { .. } | LogError::Io { .. } => false,
        }
    }
}

impl Classify for LogError {
    fn fault(&self) -> Fault {
        match self {
            // A claim that does not hold, which is what a log exists to make visible: `Bug`, as
            // `AttestError` classes a signature that does not verify, so that it is never retried
            // and never counted as an input that would not parse. It is the source's fault and
            // not Trigon's, which is what [`LogError::fails_verification`] tells a reporter.
            LogError::Unverified(_)
            | LogError::BadSignature(_)
            | LogError::Mismatch(_)
            | LogError::Inconsistent { .. }
            | LogError::Equivocation { .. }
            | LogError::Rule(_)
            | LogError::Rotation(_) => Fault::Bug,
            LogError::Malformed(_) | LogError::Missing { .. } => Fault::Upstream,
            LogError::Io { .. } => Fault::Infra,
        }
    }
}

/// A signed note as a terminal is shown it: each line with its control characters escaped, and
/// the newlines between them kept.
fn shown(note: &str) -> String {
    note.split('\n')
        .map(printable)
        .collect::<Vec<_>>()
        .join("\n")
}
