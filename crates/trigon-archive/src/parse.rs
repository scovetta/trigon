//! Format dispatch and nested-archive recursion.
//!
//! Recursion lives here, in the model, rather than in a stabilizer. The prior art implements gem
//! inner-archive descent *as* a stabilizer and swallows its error, so a malformed `data.tar.gz`
//! yields a different stabilized digest with no signal at all. Here a nested parse failure keeps the
//! body inline and emits a note: the run reports that it could not see inside rather than changing
//! its answer without telling anyone. See `docs/05-archive-and-normalization.md` §2.2 (4).

use std::sync::Arc;

use trigon_core::{EntryPath, Format, Note, NoteCode};

use crate::error::Result;
use crate::limits::Limits;
use crate::model::{
    Archive, Body, Entry, EntryKind, GzipHeader, Meta, RawMeta, SourceMap, TarRaw, Trailer,
};
use crate::{gzip, tar, zip};

/// A parsed artifact, plus the decompressed container bytes when the format has an outer codec.
///
/// `container` is what the container digest is taken over, which is how a comparison answers
/// "same tar, different gzip framing" without re-running anything.
#[derive(Debug)]
pub struct Parsed {
    pub archive: Archive,
    /// The decompressed container, for whoever wants to digest it — **shared with the archive's
    /// own bodies, not a second copy of them.**
    ///
    /// It used to be a `Vec<u8>` cloned out of the same buffer the reader was handed, so a
    /// `.tar.gz` sat in memory twice for as long as the `Parsed` lived. Measured: a 19.5 MB
    /// tarball expanding to 4095 MiB peaked at 8213 MB of RSS, 2.006x the decompressed size, for a
    /// single request. Its one real consumer hashes it and drops it.
    pub container: Option<Arc<SourceMap>>,
}

impl Parsed {
    /// The container's bytes, if this format has one.
    pub fn container_bytes(&self) -> Option<&[u8]> {
        self.container.as_ref().map(|s| s.as_slice())
    }
}

/// Parse an artifact.
///
/// The `notes` this leaves behind are the point of the signature: a nested archive that would not
/// parse, a limit reached, a duplicate member path. They reach the verdict rather than being
/// logged and forgotten, and they are traced as well so an operator sweeping a corpus sees them
/// without reading every report.
#[tracing::instrument(
    level = "debug",
    skip(bytes, limits, notes),
    fields(format = ?format, bytes = bytes.len())
)]
pub fn parse(
    bytes: Vec<u8>,
    format: Format,
    limits: &Limits,
    notes: &mut Vec<Note>,
) -> Result<Parsed> {
    let before = notes.len();
    let out = parse_inner(bytes, format, limits, notes);
    for n in &notes[before..] {
        // `warn` for the ones that mean we could not see something, `debug` for the ones that are
        // merely unusual. A run that hit a recursion limit answered a narrower question than it was
        // asked, and that should not need a `-v` to discover.
        if n.code.is_noteworthy() {
            tracing::warn!(
                code = ?n.code,
                path = n.path.as_ref().map(|p| p.to_lossy().into_owned()),
                "{}", n.detail
            );
        } else {
            tracing::debug!(code = ?n.code, "{}", n.detail);
        }
    }
    if let Ok(p) = &out {
        tracing::debug!(entries = p.archive.entries.len(), "parsed");
    }
    out
}

fn parse_inner(
    bytes: Vec<u8>,
    format: Format,
    limits: &Limits,
    notes: &mut Vec<Note>,
) -> Result<Parsed> {
    match format {
        Format::Tar => {
            // The artifact's shared expansion budget, spent by every nested member it holds. An
            // uncompressed container costs nothing to open, so it starts at zero. The gzip
            // members it may read are shared the same way.
            let mut spent = 0u64;
            let mut members = limits.max_entries;
            let mut a = tar::read(Arc::new(SourceMap::owned(bytes)), limits, notes)?;
            descend(&mut a, limits, notes, 1, &mut spent, &mut members);
            Ok(Parsed {
                archive: a,
                container: None,
            })
        }
        Format::Zip => {
            // `zip::read` charges its own members against the ceiling internally; this is the
            // budget for whatever `.gz` members it turns out to hold.
            let mut spent = 0u64;
            let mut members = limits.max_entries;
            let mut a = zip::read(Arc::new(SourceMap::owned(bytes)), limits, notes)?;
            descend(&mut a, limits, notes, 1, &mut spent, &mut members);
            Ok(Parsed {
                archive: a,
                container: None,
            })
        }
        Format::TarGz => {
            let mut members = limits.max_entries;
            let (header, inner) = gzip::read(&bytes, limits.total_expanded_bytes, &mut members)?;
            // One buffer, two owners. `tar::read` keeps entry bodies as offsets into this map
            // rather than copying them, so sharing the `Arc` is the whole cost of keeping the
            // container around — where cloning the `Vec` doubled the artifact.
            // The container's own decompression is the first charge against the ceiling, which
            // is what "everything one artifact expands to" has to mean if it means anything.
            let mut spent = inner.len() as u64;
            let src = Arc::new(SourceMap::owned(inner));
            let mut a = tar::read(src.clone(), limits, notes)?;
            a.format = Format::TarGz;
            a.trailer = Trailer::Gzip(header);
            descend(&mut a, limits, notes, 1, &mut spent, &mut members);
            Ok(Parsed {
                archive: a,
                container: Some(src),
            })
        }
        Format::Gzip => {
            let mut members = limits.max_entries;
            let (header, inner) = gzip::read(&bytes, limits.total_expanded_bytes, &mut members)?;
            let src = Arc::new(SourceMap::owned(inner));
            let a = single_member(header, src.clone());
            Ok(Parsed {
                archive: a,
                container: Some(src),
            })
        }
        Format::Raw => Ok(Parsed {
            archive: raw(bytes),
            container: None,
        }),
    }
}

/// A gzip member wrapping something that is not a tar: one entry, named by the gzip header.
///
/// The body is a window onto `payload` rather than a copy of it, so this entry and `Parsed`'s
/// container are one allocation.
fn single_member(header: GzipHeader, payload: Arc<SourceMap>) -> Archive {
    let name = header.name.clone().unwrap_or_else(|| b"payload".to_vec());
    let len = payload.as_slice().len() as u64;
    let mut a = Archive::new(Format::Gzip, Trailer::Gzip(header));
    a.entries.push(Entry {
        path: EntryPath::new(name),
        ordinal: 0,
        kind: EntryKind::Regular,
        meta: Meta {
            size: len,
            mtime: None,
            mode: 0o644,
        },
        raw: RawMeta::Tar(TarRaw::default()),
        body: Body::Original {
            src: payload,
            off: 0,
            len,
        },
        dirty: false,
        renamed_from: None,
    });
    a
}

fn raw(bytes: Vec<u8>) -> Archive {
    let mut a = Archive::new(Format::Raw, Trailer::None);
    a.entries.push(Entry {
        path: EntryPath::new(b"".to_vec()),
        ordinal: 0,
        kind: EntryKind::Regular,
        meta: Meta {
            size: bytes.len() as u64,
            mtime: None,
            mode: 0o644,
        },
        raw: RawMeta::Tar(TarRaw::default()),
        body: Body::Inline(bytes),
        dirty: false,
        renamed_from: None,
    });
    a
}

/// Parse nested archives in place, to `limits.recursion` levels.
/// Parse every nested `.gz` member in place, **against one shared expansion budget**.
///
/// `spent` is the running total of inflated bytes this artifact is holding. Without it each member
/// was handed `limits.total_expanded_bytes` in full and all of their inflated bodies were retained
/// at once, so the one ceiling operators are told to size a host against was multiplied by the
/// member count. Measured: a 70 KB tar of eight `.gz` members, each inflating to 8 MiB, parsed
/// under a 16 MiB ceiling, returned `Ok` holding **64 MiB** — four times the limit — and emitted no
/// note. A `.gem` is literally an outer tar of `.gz` members, so this shape is entirely ordinary.
///
/// `zip::read` already does this, with `let remaining = total_expanded_bytes.saturating_sub(
/// expanded)`. This is the same idea in the crate's other reader.
///
/// `members` is the same idea for gzip members, which cost time that bytes do not measure (see
/// [`gzip::read`]): how many more the artifact may read, counted down by every nested `.gz`.
fn descend(
    a: &mut Archive,
    limits: &Limits,
    notes: &mut Vec<Note>,
    depth: u8,
    spent: &mut u64,
    members: &mut u32,
) {
    if depth >= limits.recursion {
        if a.entries.iter().any(looks_nested) {
            notes.push(Note::new(
                NoteCode::RecursionLimitReached,
                format!("stopped descending at depth {depth}"),
            ));
        }
        return;
    }
    for e in &mut a.entries {
        if !looks_nested(e) {
            continue;
        }
        let path = e.path.clone();
        let Ok(body) = e.body_bytes() else { continue };
        let body = body.into_owned();
        match parse_nested(&body, limits, notes, depth, spent, members) {
            Ok(nested) => {
                let original = std::mem::replace(&mut e.body, Body::empty());
                e.body = Body::Nested {
                    inner: Box::new(nested),
                    original: Box::new(original),
                };
            }
            Err(err) => {
                // The body stays where it is. The digest reflects the bytes we could not read,
                // and the note says so.
                notes.push(Note::at(
                    NoteCode::NestedParseFailed,
                    path,
                    format!("{err}; body left inline"),
                ));
            }
        }
    }
}

fn parse_nested(
    body: &[u8],
    limits: &Limits,
    notes: &mut Vec<Note>,
    depth: u8,
    spent: &mut u64,
    members: &mut u32,
) -> Result<Archive> {
    // What is left of the artifact's budget, not the whole of it. Exceeding this returns an error,
    // which `descend` turns into a note and an inline body — the member stays in the archive, is
    // digested as the bytes we could not open, and the note says why. That is the right failure
    // for a large-but-legal artifact: the outer comparison still works.
    let remaining = limits.total_expanded_bytes.saturating_sub(*spent);
    let (header, inner) = gzip::read(body, remaining, members)?;
    *spent = spent.saturating_add(inner.len() as u64);

    // Members deeper in are charged against what this one already spent.
    let inner_limits = Limits {
        total_expanded_bytes: limits.total_expanded_bytes.saturating_sub(*spent),
        ..*limits
    };
    if sniff_tar(&inner) {
        let mut a = tar::read(Arc::new(SourceMap::owned(inner)), &inner_limits, notes)?;
        a.format = Format::TarGz;
        a.trailer = Trailer::Gzip(header);
        descend(&mut a, &inner_limits, notes, depth + 1, spent, members);
        Ok(a)
    } else {
        Ok(single_member(header, Arc::new(SourceMap::owned(inner))))
    }
}

fn looks_nested(e: &Entry) -> bool {
    matches!(e.kind, EntryKind::Regular)
        && e.path.ends_with(b".gz")
        && matches!(
            e.body,
            Body::Original { .. } | Body::Inline(_) | Body::Spilled { .. }
        )
}

/// A ustar magic in the first header block. Old-style tars without it fall through to being treated
/// as opaque, which is the safe direction: we never guess a structure we cannot confirm.
fn sniff_tar(b: &[u8]) -> bool {
    b.len() >= 512 && (&b[257..262] == b"ustar")
}

/// Serialize an archive back to bytes.
///
/// `store_only` drives the stabilized path: zip members become method 0 and gzip members use no
/// compression, so the stabilized stream never passes through a deflate encoder and no encoder's
/// behaviour reaches a signed digest.
pub fn serialize(a: &Archive, store_only: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match a.format {
        Format::Tar => {
            let flat = flatten(a, store_only)?;
            tar::write(&flat, &mut out)?;
        }
        Format::TarGz => {
            let flat = flatten(a, store_only)?;
            let mut inner = Vec::new();
            tar::write(&flat, &mut inner)?;
            let header = gzip_header(a, store_only);
            let level = level_for(store_only);
            gzip::write(&header, &inner, level, &mut out)?;
        }
        Format::Zip => {
            let flat = flatten(a, store_only)?;
            zip::write(&flat, &mut out, store_only)?;
        }
        Format::Gzip => {
            let payload = a
                .entries
                .first()
                .map(|e| e.body_bytes())
                .transpose()?
                .map(|c| c.into_owned())
                .unwrap_or_default();
            gzip::write(
                &gzip_header(a, store_only),
                &payload,
                level_for(store_only),
                &mut out,
            )?;
        }
        Format::Raw => {
            if let Some(e) = a.entries.first() {
                out.extend_from_slice(&e.body_bytes()?);
            }
        }
    }
    Ok(out)
}

fn level_for(store_only: bool) -> flate2::Compression {
    if store_only {
        flate2::Compression::none()
    } else {
        flate2::Compression::default()
    }
}

fn gzip_header(a: &Archive, store_only: bool) -> GzipHeader {
    let mut h = match &a.trailer {
        Trailer::Gzip(h) => h.clone(),
        _ => GzipHeader::default(),
    };
    if store_only {
        h.xfl = gzip::xfl_for(0);
    }
    h
}

/// Re-serialize nested archives so the parent can write them as ordinary member bodies.
fn flatten(a: &Archive, store_only: bool) -> Result<Archive> {
    let mut out = Archive::new(a.format, a.trailer.clone());
    out.tar_trailing = a.tar_trailing.clone();
    for e in &a.entries {
        let body = match &e.body {
            // An untouched inner archive writes back the bytes it arrived as. Re-serializing it
            // would store what was deflated and drop the header fields the inner file legitimately
            // carries, rewriting content the package ships rather than normalizing a container.
            Body::Nested { inner, original } => {
                if inner.is_dirty() {
                    Body::Inline(serialize(inner, store_only)?)
                } else {
                    Body::Inline(original.bytes()?.into_owned())
                }
            }
            Body::Inline(v) => Body::Inline(v.clone()),
            other => Body::Inline(match other {
                Body::Original { .. } | Body::Spilled { .. } => e.body_bytes()?.into_owned(),
                _ => unreachable!(),
            }),
        };
        let size = body.len();
        out.entries.push(Entry {
            path: e.path.clone(),
            ordinal: e.ordinal,
            kind: e.kind.clone(),
            meta: Meta { size, ..e.meta },
            raw: e.raw.clone(),
            body,
            dirty: e.dirty,
            renamed_from: None,
        });
    }
    Ok(out)
}
