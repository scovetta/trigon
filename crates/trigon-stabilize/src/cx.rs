use smallvec::SmallVec;
use trigon_core::{EntryPath, Format};

/// One level of archive nesting.
#[derive(Clone, Debug)]
pub struct Level {
    pub format: Format,
    /// The member path this archive was found at, or `None` for the outermost archive.
    pub archive_path: Option<EntryPath>,
}

/// Where in an artifact a pass is running.
///
/// Mirrors the prior art's stabilization context, so its constraint vocabulary ("at depth 0", "at
/// minimum depth 1", "only inside `metadata.gz`") ports across unchanged.
#[derive(Clone, Debug, Default)]
pub struct Cx {
    levels: SmallVec<[Level; 4]>,
}

impl Cx {
    pub fn root(format: Format) -> Self {
        let mut levels = SmallVec::new();
        levels.push(Level {
            format,
            archive_path: None,
        });
        Self { levels }
    }

    pub fn push(&self, format: Format, at: EntryPath) -> Self {
        let mut next = self.clone();
        next.levels.push(Level {
            format,
            archive_path: Some(at),
        });
        next
    }

    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    pub fn format(&self) -> Format {
        self.levels.last().map(|l| l.format).unwrap_or(Format::Raw)
    }

    pub fn archive_path(&self) -> Option<&EntryPath> {
        self.levels.last().and_then(|l| l.archive_path.as_ref())
    }

    pub fn at_depth(&self, d: usize) -> bool {
        self.depth() == d
    }

    pub fn min_depth(&self, d: usize) -> bool {
        self.depth() >= d
    }

    /// Whether this archive was found at a member path ending in `suffix`.
    pub fn archive_path_ends_with(&self, suffix: &[u8]) -> bool {
        self.archive_path().is_some_and(|p| p.ends_with(suffix))
    }
}
