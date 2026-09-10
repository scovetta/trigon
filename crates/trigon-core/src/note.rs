use serde::{Deserialize, Serialize};

use crate::EntryPath;

/// Something the pipeline observed that a reader should know about, whatever the verdict.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Note {
    pub code: NoteCode,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<EntryPath>,
    pub detail: String,
}

impl Note {
    pub fn new(code: NoteCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            path: None,
            detail: detail.into(),
        }
    }

    pub fn at(code: NoteCode, path: EntryPath, detail: impl Into<String>) -> Self {
        Self {
            code,
            path: Some(path),
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteCode {
    // --- parse and limits ---
    /// A nested archive would not parse. The body stays inline and the digest reflects that, rather
    /// than the run changing its answer without saying so. The prior art swallows this error.
    NestedParseFailed,
    RecursionLimitReached,
    EntryLimitReached,
    SizeLimitReached,
    SpilledToDisk,

    // --- structural oddities ---
    /// Two or more members share a path. Sort ties break on parse order, so the output stays
    /// deterministic, but an archive whose members are not uniquely named is worth flagging.
    DuplicateEntryPath,
    /// For example a symlink carrying a body. Bytes are preserved rather than discarded.
    MalformedEntry,
    /// An unrecognized tar typeflag, passed through untouched. Guessing is worse than declining.
    UnknownEntryKind,
    /// A GNU long name on the way in became a PAX long name on the way out.
    LongNameReencoded,

    // --- comparison ---
    MemberOnlyInUpstream,
    MemberOnlyInRebuild,
    MemberContentDiffers,
    /// Never benign.
    ExecutableContentDiffers,
    /// Flagged in the UI and in the attestation.
    CustomStabilizerTouchedExecutable,
}

impl NoteCode {
    /// Whether this note should reach a human even when the verdict is a clean match.
    pub const fn is_noteworthy(self) -> bool {
        matches!(
            self,
            NoteCode::NestedParseFailed
                | NoteCode::RecursionLimitReached
                | NoteCode::EntryLimitReached
                | NoteCode::SizeLimitReached
                | NoteCode::MalformedEntry
                | NoteCode::UnknownEntryKind
                | NoteCode::ExecutableContentDiffers
                | NoteCode::CustomStabilizerTouchedExecutable
        )
    }
}
