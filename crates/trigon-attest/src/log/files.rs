//! Where a log's files are read from.
//!
//! A narrow seam, per ADR-0014 Decision 9: read a file by its path in the log's directory. A clone
//! on disk is the one implementation here; `--remote` (`docs/19` §6) will be another, reading the
//! same paths over HTTPS, and everything that verifies a log reads through this.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use super::LogError;
use crate::location::printable;

/// A log's files, by path relative to the log's directory: `checkpoint`, `tile/0/000`, and so on.
pub trait LogFiles {
    /// The file at `path`, or `None` where there is none. A file longer than `limit` bytes is
    /// refused rather than read, because no file of a log is longer than its format allows and a
    /// reader should not be made to find that out by reading it.
    fn read(&self, path: &str, limit: u64) -> Result<Option<Vec<u8>>, LogError>;

    /// How to name `path` to a person: where it really is, for a message.
    fn shown(&self, path: &str) -> String {
        path.to_string()
    }
}

/// A log's directory on disk: `log/` of an evidence repository's clone, or `log/<n>/` for a
/// successor.
///
/// A clone is written by whoever can push to the repository, so it is read defensively: a path
/// that leads outside its bound through a symbolic link is refused, since git stores links and one
/// planted in `log/` could otherwise have a verifier read a file of the host's; so is anything
/// that is not a regular file, such as a FIFO a read would block on.
#[derive(Clone, Debug)]
pub struct DirFiles {
    root: PathBuf,
    /// What every file read must be inside once links are followed: the log's directory, or the
    /// repository it is in, so that the directory itself cannot be a link out of it either.
    bound: PathBuf,
}

impl DirFiles {
    /// The files under `root`, and nowhere else.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        DirFiles {
            bound: root.clone(),
            root,
        }
    }

    /// The files of the log at `dir` in the repository at `repo`, which must stay inside `repo`:
    /// a `log/1` that is a link to elsewhere reads nothing.
    pub fn in_repository(repo: &Path, dir: &str) -> Self {
        DirFiles {
            root: repo.join(dir),
            bound: repo.to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl LogFiles for DirFiles {
    fn read(&self, path: &str, limit: u64) -> Result<Option<Vec<u8>>, LogError> {
        let rel = Path::new(path);
        if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(LogError::Malformed(format!(
                "`{path}` is not a path inside a log's directory"
            )));
        }
        let full = self.root.join(rel);
        let io = |e: std::io::Error| LogError::Io {
            path: full.display().to_string(),
            source: e,
        };
        let absent = |e: &std::io::Error| {
            matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            )
        };
        match std::fs::symlink_metadata(&full) {
            Ok(_) => {}
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(io(e)),
        }
        let bound = self.bound.canonicalize().map_err(io)?;
        let real = match full.canonicalize() {
            Ok(p) => p,
            // A link to nothing: there is no file.
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        if !real.starts_with(&bound) {
            // Where the link leads is written by whoever wrote the clone, so it is escaped.
            return Err(LogError::Malformed(format!(
                "`{}` leads through a symbolic link to `{}`, outside `{}`, and a log's files are \
                 read only inside it",
                full.display(),
                printable(&real.display().to_string()),
                self.bound.display()
            )));
        }
        let meta = std::fs::metadata(&real).map_err(io)?;
        if !meta.is_file() {
            return Err(LogError::Malformed(format!(
                "`{path}` is not a regular file"
            )));
        }
        let too_long = |len: u64| {
            LogError::Malformed(format!(
                "`{path}` is {len} bytes, and no file at that path can be more than {limit}"
            ))
        };
        if meta.len() > limit {
            return Err(too_long(meta.len()));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&real)
            .map_err(io)?
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.len() as u64 > limit {
            return Err(too_long(bytes.len() as u64));
        }
        Ok(Some(bytes))
    }

    fn shown(&self, path: &str) -> String {
        self.root.join(path).display().to_string()
    }
}
