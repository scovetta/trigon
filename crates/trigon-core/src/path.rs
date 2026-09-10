use std::fmt;

use serde::{Deserialize, Serialize};

/// An archive member path, held as **bytes**.
///
/// Real npm tarballs contain non-UTF-8 paths, zip carries an explicit non-UTF-8 flag, and `PathBuf`
/// would bring Windows path semantics into a format that has none. Ordering is over raw bytes, which
/// also matches Go's `strings.Compare` and so keeps the differential test in
/// `docs/05-archive-and-normalization.md` §6 meaningful.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryPath(pub Vec<u8>);

impl EntryPath {
    pub fn new(b: impl Into<Vec<u8>>) -> Self {
        Self(b.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Lossy text, for display and for matching against glob patterns. Never for ordering.
    pub fn to_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    /// The final path component, or the whole path when there is no separator.
    pub fn file_name(&self) -> &[u8] {
        match self.0.iter().rposition(|&c| c == b'/') {
            Some(i) => &self.0[i + 1..],
            None => &self.0,
        }
    }

    pub fn ends_with(&self, suffix: &[u8]) -> bool {
        self.0.ends_with(suffix)
    }
}

impl From<&str> for EntryPath {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl fmt::Debug for EntryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_lossy())
    }
}

impl fmt::Display for EntryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_by_raw_bytes() {
        // '.' (0x2E) sorts before '/' (0x2F), which byte ordering gets right and any
        // path-component-aware ordering would not.
        let mut v = vec![
            EntryPath::from("a/b"),
            EntryPath::from("a.b"),
            EntryPath::from("a"),
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                EntryPath::from("a"),
                EntryPath::from("a.b"),
                EntryPath::from("a/b")
            ]
        );
    }

    #[test]
    fn survives_non_utf8() {
        let p = EntryPath::new(vec![0xff, 0xfe, b'/', b'x']);
        assert_eq!(p.file_name(), b"x");
        assert!(p.to_lossy().contains('\u{fffd}'));
    }

    #[test]
    fn file_name_without_separator() {
        assert_eq!(EntryPath::from("plain").file_name(), b"plain");
    }
}
