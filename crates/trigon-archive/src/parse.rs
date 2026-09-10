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
    pub container: Option<Vec<u8>>,
}

pub fn parse(
    bytes: Vec<u8>,
    format: Format,
    limits: &Limits,
    notes: &mut Vec<Note>,
) -> Result<Parsed> {
    match format {
        Format::Tar => {
            let mut a = tar::read(Arc::new(SourceMap::owned(bytes)), limits, notes)?;
            descend(&mut a, limits, notes, 1);
            Ok(Parsed {
                archive: a,
                container: None,
            })
        }
        Format::Zip => {
            let mut a = zip::read(Arc::new(SourceMap::owned(bytes)), limits, notes)?;
            descend(&mut a, limits, notes, 1);
            Ok(Parsed {
                archive: a,
                container: None,
            })
        }
        Format::TarGz => {
            let (header, inner) = gzip::read(&bytes)?;
            let mut a = tar::read(Arc::new(SourceMap::owned(inner.clone())), limits, notes)?;
            a.format = Format::TarGz;
            a.trailer = Trailer::Gzip(header);
            descend(&mut a, limits, notes, 1);
            Ok(Parsed {
                archive: a,
                container: Some(inner),
            })
        }
        Format::Gzip => {
            let (header, inner) = gzip::read(&bytes)?;
            let a = single_member(header.clone(), inner.clone());
            Ok(Parsed {
                archive: a,
                container: Some(inner),
            })
        }
        Format::Raw => Ok(Parsed {
            archive: raw(bytes),
            container: None,
        }),
    }
}

/// A gzip member wrapping something that is not a tar: one entry, named by the gzip header.
fn single_member(header: GzipHeader, payload: Vec<u8>) -> Archive {
    let name = header.name.clone().unwrap_or_else(|| b"payload".to_vec());
    let mut a = Archive::new(Format::Gzip, Trailer::Gzip(header));
    a.entries.push(Entry {
        path: EntryPath::new(name),
        ordinal: 0,
        kind: EntryKind::Regular,
        meta: Meta {
            size: payload.len() as u64,
            mtime: None,
            mode: 0o644,
        },
        raw: RawMeta::Tar(TarRaw::default()),
        body: Body::Inline(payload),
        dirty: false,
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
    });
    a
}

/// Parse nested archives in place, to `limits.recursion` levels.
fn descend(a: &mut Archive, limits: &Limits, notes: &mut Vec<Note>, depth: u8) {
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
        match parse_nested(&body, limits, notes, depth) {
            Ok(nested) => e.body = Body::Nested(Box::new(nested)),
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

fn parse_nested(body: &[u8], limits: &Limits, notes: &mut Vec<Note>, depth: u8) -> Result<Archive> {
    let (header, inner) = gzip::read(body)?;
    if sniff_tar(&inner) {
        let mut a = tar::read(Arc::new(SourceMap::owned(inner)), limits, notes)?;
        a.format = Format::TarGz;
        a.trailer = Trailer::Gzip(header);
        descend(&mut a, limits, notes, depth + 1);
        Ok(a)
    } else {
        Ok(single_member(header, inner))
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
    for e in &a.entries {
        let body = match &e.body {
            Body::Nested(inner) => Body::Inline(serialize(inner, store_only)?),
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
        });
    }
    Ok(out)
}
