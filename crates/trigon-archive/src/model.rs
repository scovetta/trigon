use std::collections::BTreeMap;
use std::sync::Arc;

use trigon_core::{EntryPath, Format};

/// A parsed archive, ready to be mutated and re-serialized byte-exactly.
#[derive(Debug)]
pub struct Archive {
    pub format: Format,
    pub entries: Vec<Entry>,
    pub trailer: Trailer,
    /// Set when a pass changes the container itself, as distinct from any of its members. Only the
    /// trailer lives there, so only a trailer pass sets it.
    pub(crate) trailer_dirty: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trailer {
    Zip { comment: Vec<u8> },
    Gzip(GzipHeader),
    Tar,
    None,
}

/// The gzip member header, captured so a stabilizer can normalize it and the writer can reproduce
/// it. `mtime: None` means the field is absent, which is how the format encodes "unset": writing an
/// epoch value instead would not round-trip.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GzipHeader {
    pub mtime: Option<u32>,
    pub name: Option<Vec<u8>>,
    pub comment: Option<Vec<u8>>,
    pub extra: Option<Vec<u8>>,
    pub os: u8,
    /// The XFL byte. Tracked because a stabilizer that changes the compression level has to change
    /// it too, and `flate2` does not expose it.
    pub xfl: u8,
}

#[derive(Debug)]
pub struct Entry {
    pub path: EntryPath,
    /// Position as parsed. The sort tiebreaker: both tar and zip permit duplicate paths, so
    /// ordering by path alone is not a total order and the digest would be a coin flip.
    /// See `docs/05-archive-and-normalization.md` §2.2 (6).
    pub ordinal: u32,
    pub kind: EntryKind,
    pub meta: Meta,
    pub raw: RawMeta,
    pub body: Body,
    pub(crate) dirty: bool,
    /// The name this entry carried in the artifact, when a stabilizer has since renamed it.
    ///
    /// Two passes rename — `nupkg-portable-folder-name` and `nupkg-packaging-names` — and the
    /// comparison names its members from the *stabilized* archive. Anything that has to go back to
    /// the bytes on disk, which is every member the management UI links to, needs the name the
    /// bytes are actually under. Without it those links resolve to nothing: measured at 5 dead
    /// links out of 23 members on one real NuGet divergence page.
    pub(crate) renamed_from: Option<EntryPath>,
}

impl Entry {
    /// Rename, remembering the name the artifact on disk carries.
    ///
    /// The *first* name wins: two renames of one entry leave the original recorded, not the
    /// intermediate, because what a caller needs is the spelling in the bytes and never a step
    /// along the way.
    pub fn rename_to(&mut self, next: EntryPath) {
        if next == self.path {
            return;
        }
        if self.renamed_from.is_none() {
            self.renamed_from = Some(std::mem::replace(&mut self.path, next));
        } else {
            self.path = next;
        }
        self.mark_dirty();
    }

    /// The name in the artifact: the pre-stabilization one where a pass renamed this entry, and
    /// the current one otherwise.
    pub fn raw_path(&self) -> &EntryPath {
        self.renamed_from.as_ref().unwrap_or(&self.path)
    }

    /// Whether a stabilizer renamed this entry.
    pub fn was_renamed(&self) -> bool {
        self.renamed_from.is_some()
    }
}

/// What an entry *is*. Decides which stabilizers apply and what the writer must emit.
/// See `docs/05-archive-and-normalization.md` §2.2 (7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Regular,
    Directory,
    Symlink {
        target: Vec<u8>,
    },
    Hardlink {
        target: Vec<u8>,
    },
    CharDevice {
        major: u32,
        minor: u32,
    },
    BlockDevice {
        major: u32,
        minor: u32,
    },
    Fifo,
    /// An unrecognized tar typeflag, passed through byte for byte. Guessing is worse than declining.
    Other(u8),
}

impl EntryKind {
    /// Whether the format requires this entry to carry no body. The writer emits `size = 0` for
    /// these regardless of what the parser found.
    pub const fn requires_empty_body(&self) -> bool {
        matches!(
            self,
            EntryKind::Directory
                | EntryKind::Symlink { .. }
                | EntryKind::Hardlink { .. }
                | EntryKind::CharDevice { .. }
                | EntryKind::BlockDevice { .. }
                | EntryKind::Fifo
        )
    }

    /// Whether normalizing stabilizers apply. `Other` is passed through untouched.
    pub const fn is_normalizable(&self) -> bool {
        !matches!(self, EntryKind::Other(_))
    }

    pub fn link_target(&self) -> Option<&[u8]> {
        match self {
            EntryKind::Symlink { target } | EntryKind::Hardlink { target } => Some(target),
            _ => None,
        }
    }
}

/// Format-agnostic metadata. Stabilizers that work across tar and zip touch only this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub size: u64,
    /// Seconds since the epoch. `None` means the format carries no value.
    pub mtime: Option<i64>,
    pub mode: u32,
}

/// Format-specific metadata, preserved verbatim. Stabilizers that need it match on the variant,
/// which is what lets one `Stabilizer` trait serve both formats without a dispatch table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawMeta {
    Tar(TarRaw),
    Zip(ZipRaw),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarRaw {
    pub typeflag: u8,
    pub linkname: Vec<u8>,
    pub uid: u64,
    pub gid: u64,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub devmajor: u32,
    pub devminor: u32,
    pub atime: Option<i64>,
    pub ctime: Option<i64>,
    /// Extended records other than the ones the writer synthesizes (`path`, `linkpath`, `size`,
    /// `mtime`, `atime`, `ctime`). Sorted, because PAX records are emitted in keyword order.
    pub pax: BTreeMap<String, String>,
    /// The input encoded a long name using a GNU `L` entry rather than a PAX record. We always emit
    /// PAX, so this drives `NoteCode::LongNameReencoded`.
    pub long_name_was_gnu: bool,
}

impl Default for TarRaw {
    fn default() -> Self {
        Self {
            typeflag: b'0',
            linkname: Vec::new(),
            uid: 0,
            gid: 0,
            uname: Vec::new(),
            gname: Vec::new(),
            devmajor: 0,
            devminor: 0,
            atime: None,
            ctime: None,
            pax: BTreeMap::new(),
            long_name_was_gnu: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZipRaw {
    pub creator_version: u16,
    pub reader_version: u16,
    pub flags: u16,
    pub method: u16,
    pub crc32: u32,
    pub extra: Vec<u8>,
    pub comment: Vec<u8>,
    pub external_attrs: u32,
    pub internal_attrs: u16,
    /// MS-DOS date and time as stored, so a stabilizer can zero exactly those bytes.
    pub dos_datetime: (u16, u16),
}

/// Where an entry's bytes live.
///
/// `Original` is the copy-on-write case and the reason a 2 GB wheel stabilizes at near-zero heap:
/// sorting touches the entry list, zeroing timestamps touches headers, and most bodies are never
/// read at all. See `docs/05-archive-and-normalization.md` §2.2 (1).
#[derive(Debug)]
pub enum Body {
    Original {
        src: Arc<SourceMap>,
        off: u64,
        len: u64,
    },
    Inline(Vec<u8>),
    Spilled {
        file: Arc<SpillFile>,
        off: u64,
        len: u64,
    },
    /// A parsed inner archive, alongside the bytes it was parsed from.
    ///
    /// `original` is what gets written back when nothing inside `inner` changed. Without it every
    /// nested archive is re-serialized, and re-serialization is not the identity: the stabilized
    /// form stores rather than deflates, so an untouched `.gz` asset a package ships would be
    /// decompressed and rewritten. One npm tarball in the corpus grew a 4,887-byte member to 66,090
    /// that way. Descending is for seeing inside; it is not licence to rewrite.
    Nested {
        inner: Box<Archive>,
        original: Box<Body>,
    },
}

impl Body {
    pub const fn empty() -> Self {
        Body::Inline(Vec::new())
    }

    pub fn len(&self) -> u64 {
        match self {
            Body::Original { len, .. } | Body::Spilled { len, .. } => *len,
            Body::Inline(v) => v.len() as u64,
            // A nested archive's length is only known once it is re-serialized.
            Body::Nested { .. } => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0 && !matches!(self, Body::Nested { .. })
    }

    /// The bytes this body holds.
    ///
    /// A nested archive has none until it is re-serialized, so it is an error rather than an empty
    /// slice: returning nothing would silently drop an inner archive from the digest.
    pub fn bytes(&self) -> Result<std::borrow::Cow<'_, [u8]>, crate::ArchiveError> {
        use std::borrow::Cow;
        use std::io::{Read, Seek, SeekFrom};
        match self {
            Body::Inline(v) => Ok(Cow::Borrowed(v)),
            Body::Original { src, off, len } => src
                .slice(*off, *len)
                .map(Cow::Borrowed)
                .ok_or_else(|| crate::ArchiveError::Malformed {
                    format: "archive",
                    // Saturating: a range whose end overflows is exactly the one being refused,
                    // and `+` panicked on it under the workspace's overflow checks.
                    detail: format!("body range {off}..{} out of bounds", off.saturating_add(*len)),
                }),
            Body::Spilled { file, off, len } => {
                let mut f = file.file.try_clone()?;
                f.seek(SeekFrom::Start(*off))?;
                let mut buf = vec![0u8; usize::try_from(*len).unwrap_or(0)];
                f.read_exact(&mut buf)?;
                Ok(Cow::Owned(buf))
            }
            Body::Nested { .. } => Err(crate::ArchiveError::Unsupported(
                "bytes() on a nested archive; re-serialize it first".into(),
            )),
        }
    }
}

/// Bytes an archive was parsed from: an mmap for a file, an owned buffer for a decompressed stream.
#[derive(Debug)]
pub struct SourceMap {
    data: SourceData,
}

#[derive(Debug)]
enum SourceData {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl SourceMap {
    pub fn owned(v: Vec<u8>) -> Self {
        Self {
            data: SourceData::Owned(v),
        }
    }

    /// # Safety
    ///
    /// The caller must not modify the file while the map is live. We only map artifacts we have
    /// just written into our own cache, which is why this is acceptable at all.
    pub fn map(file: &std::fs::File) -> std::io::Result<Self> {
        // SAFETY: documented above; the file is ours and read-only for the map's lifetime.
        let m = unsafe { memmap2::Mmap::map(file)? };
        Ok(Self {
            data: SourceData::Mapped(m),
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.data {
            SourceData::Mapped(m) => m,
            SourceData::Owned(v) => v,
        }
    }

    pub fn slice(&self, off: u64, len: u64) -> Option<&[u8]> {
        let s = self.as_slice();
        let start = usize::try_from(off).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        s.get(start..end)
    }
}

#[derive(Debug)]
pub struct SpillFile {
    pub(crate) file: std::fs::File,
}

impl Archive {
    pub fn new(format: Format, trailer: Trailer) -> Self {
        Self {
            format,
            entries: Vec::new(),
            trailer,
            trailer_dirty: false,
        }
    }

    /// Mark the container itself as changed. A pass that edits the trailer calls this; a pass that
    /// edits a member marks the entry instead.
    pub fn mark_trailer_dirty(&mut self) {
        self.trailer_dirty = true;
    }

    /// Did any pass change this archive, at any depth?
    ///
    /// Drives the one decision that needs it: whether a nested archive is re-serialized or written
    /// back as the bytes it arrived as.
    pub fn is_dirty(&self) -> bool {
        self.trailer_dirty
            || self.entries.iter().any(|e| {
                e.dirty
                    || match &e.body {
                        Body::Nested { inner, .. } => inner.is_dirty(),
                        _ => false,
                    }
            })
    }

    /// Sort by `(path bytes, ordinal)`. The ordinal makes the order total over a multiset, so an
    /// archive with duplicate member paths still serializes to one byte sequence.
    pub fn sort_entries(&mut self) {
        self.entries
            .sort_by(|a, b| a.path.cmp(&b.path).then(a.ordinal.cmp(&b.ordinal)));
    }

    /// Paths that appear more than once, with their counts, in path order.
    pub fn duplicate_paths(&self) -> Vec<(EntryPath, usize)> {
        let mut counts: BTreeMap<&EntryPath, usize> = BTreeMap::new();
        for e in &self.entries {
            *counts.entry(&e.path).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(p, n)| (p.clone(), n))
            .collect()
    }

    pub fn touched_entries(&self) -> u32 {
        self.entries.iter().filter(|e| e.dirty).count() as u32
    }
}

impl Entry {
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Bytes of this entry's body.
    pub fn body_bytes(&self) -> Result<std::borrow::Cow<'_, [u8]>, crate::ArchiveError> {
        self.body.bytes()
    }

    /// The bytes this entry will contribute to a *stabilized* archive.
    ///
    /// Differs from [`Entry::body_bytes`] on exactly one case: a nested archive, which has no bytes
    /// of its own until it is written. An inner archive nothing changed yields the bytes it arrived
    /// as; a changed one is re-serialized store-only, which is what the stabilized form does with
    /// it either way.
    ///
    /// A pass that hashes members must use this. `body_bytes` returns an error for a nested
    /// archive, and a caller that skips the members it cannot read writes a manifest of an archive
    /// that does not exist. Silent membership deletion is how a stabilizer turns a real difference
    /// into a false match, which is the most expensive mistake in the system.
    pub fn stabilized_bytes(&self) -> Result<std::borrow::Cow<'_, [u8]>, crate::ArchiveError> {
        match &self.body {
            Body::Nested { inner, original } => {
                if inner.is_dirty() {
                    Ok(std::borrow::Cow::Owned(crate::serialize(inner, true)?))
                } else {
                    original.bytes()
                }
            }
            _ => self.body_bytes(),
        }
    }

    /// Promote the body to `Inline` so it can be mutated, and mark the entry dirty.
    pub fn body_mut(&mut self) -> Result<&mut Vec<u8>, crate::ArchiveError> {
        if !matches!(self.body, Body::Inline(_)) {
            let owned = self.body_bytes()?.into_owned();
            self.body = Body::Inline(owned);
        }
        self.dirty = true;
        match &mut self.body {
            Body::Inline(v) => Ok(v),
            _ => unreachable!("just promoted to Inline"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::Arc;

    use super::{Body, SpillFile};

    /// Nothing constructs `Body::Spilled` yet (`docs/16-findings.md` §3.15), but the read is here
    /// and whoever wires spilling inherits it, so it is held to its window now.
    #[test]
    fn a_spilled_body_reads_exactly_its_window_of_the_spill_file() {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"....window....").unwrap();
        let file = Arc::new(SpillFile { file: f });
        let body = Body::Spilled {
            file: file.clone(),
            off: 4,
            len: 6,
        };
        assert_eq!(body.len(), 6);
        assert_eq!(body.bytes().unwrap().as_ref(), b"window");
        // Twice: each read seeks, rather than trusting where the last one left the handle.
        assert_eq!(body.bytes().unwrap().as_ref(), b"window");

        let past_the_end = Body::Spilled {
            file,
            off: 10,
            len: 10,
        };
        assert!(matches!(
            past_the_end.bytes(),
            Err(crate::ArchiveError::Io(_))
        ));
    }
}
