//! Zip reading and byte-exact writing.
//!
//! Both directions are ours. The reading side started out delegating to the `zip` crate, but that
//! crate hides the four fields stabilization has to control (version-made-by, version-needed,
//! general-purpose flags, internal attributes), so we walk the central directory instead and use
//! `flate2` only to inflate. The `zip` crate stays a dev-dependency, where it cross-checks our
//! output the way an external implementation should.

use std::io::Write;
use std::sync::Arc;

use trigon_core::{EntryPath, Format, Note, NoteCode};

use crate::error::{ArchiveError, Result};
use crate::limits::Limits;
use crate::model::{Archive, Body, Entry, EntryKind, Meta, RawMeta, SourceMap, Trailer, ZipRaw};

const SIG_LFH: u32 = 0x0403_4b50;
const SIG_CDH: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
const SIG_EOCD64_LOCATOR: u32 = 0x0706_4b50;
const ZIP64_MARK32: u32 = 0xFFFF_FFFF;
const ZIP64_MARK16: u16 = 0xFFFF;
const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
/// Flag bit 3: sizes live in a data descriptor after the body rather than in the local header.
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;

fn bad(detail: impl Into<String>) -> ArchiveError {
    ArchiveError::Malformed {
        format: "zip",
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8], p: usize) -> Self {
        Self { b, p }
    }
    fn u16(&mut self) -> Result<u16> {
        let v = self
            .b
            .get(self.p..self.p + 2)
            .ok_or_else(|| bad("short read (u16)"))?;
        self.p += 2;
        Ok(u16::from_le_bytes([v[0], v[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let v = self
            .b
            .get(self.p..self.p + 4)
            .ok_or_else(|| bad("short read (u32)"))?;
        self.p += 4;
        Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let v = self
            .b
            .get(self.p..self.p + 8)
            .ok_or_else(|| bad("short read (u64)"))?;
        self.p += 8;
        Ok(u64::from_le_bytes(v.try_into().unwrap()))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let v = self
            .b
            .get(self.p..self.p + n)
            .ok_or_else(|| bad("short read (bytes)"))?;
        self.p += n;
        Ok(v)
    }
}

pub fn read(src: Arc<SourceMap>, limits: &Limits, notes: &mut Vec<Note>) -> Result<Archive> {
    let b = src.as_slice();
    let (cd_offset, cd_count, comment) = find_eocd(b)?;

    let mut out = Archive::new(Format::Zip, Trailer::Zip { comment });
    let mut c = Cursor::new(b, cd_offset);
    let mut expanded: u64 = 0;

    for ordinal in 0..cd_count {
        if ordinal >= u64::from(limits.max_entries) {
            notes.push(Note::new(
                NoteCode::EntryLimitReached,
                format!("stopped at {ordinal}"),
            ));
            break;
        }
        if c.u32()? != SIG_CDH {
            return Err(bad(format!(
                "central directory entry {ordinal} has a bad signature"
            )));
        }
        let creator_version = c.u16()?;
        let reader_version = c.u16()?;
        let flags = c.u16()?;
        let method = c.u16()?;
        let dos_time = c.u16()?;
        let dos_date = c.u16()?;
        let crc32 = c.u32()?;
        let mut comp_size = u64::from(c.u32()?);
        let mut uncomp_size = u64::from(c.u32()?);
        let name_len = c.u16()? as usize;
        let extra_len = c.u16()? as usize;
        let comment_len = c.u16()? as usize;
        let _disk = c.u16()?;
        let internal_attrs = c.u16()?;
        let external_attrs = c.u32()?;
        let mut local_offset = u64::from(c.u32()?);
        let name = c.take(name_len)?.to_vec();
        let extra = c.take(extra_len)?.to_vec();
        let entry_comment = c.take(comment_len)?.to_vec();

        // Zip64 rewrites the oversized fields into an extra field, in a fixed order, present only
        // for the fields that overflowed.
        if uncomp_size == u64::from(ZIP64_MARK32)
            || comp_size == u64::from(ZIP64_MARK32)
            || local_offset == u64::from(ZIP64_MARK32)
        {
            let (u, cmp, off) = parse_zip64_extra(&extra, uncomp_size, comp_size, local_offset)?;
            uncomp_size = u;
            comp_size = cmp;
            local_offset = off;
        }

        expanded = expanded.saturating_add(uncomp_size);
        if expanded > limits.total_expanded_bytes {
            return Err(ArchiveError::LimitExceeded {
                limit: "total_expanded_bytes",
                actual: expanded,
                allowed: limits.total_expanded_bytes,
            });
        }

        let data = read_member(b, local_offset, method, comp_size, uncomp_size)?;
        let path = EntryPath::new(name);
        // Zip has no type flags. A trailing slash is the universal convention for a directory.
        let kind = if path.as_bytes().ends_with(b"/") {
            EntryKind::Directory
        } else if unix_mode(external_attrs).is_some_and(|m| m & 0o170000 == 0o120000) {
            EntryKind::Symlink {
                target: data.clone(),
            }
        } else {
            EntryKind::Regular
        };

        out.entries.push(Entry {
            path,
            ordinal: ordinal as u32,
            kind,
            meta: Meta {
                size: uncomp_size,
                mtime: dos_to_unix(dos_date, dos_time),
                mode: unix_mode(external_attrs).unwrap_or(0o644),
            },
            raw: RawMeta::Zip(ZipRaw {
                creator_version,
                reader_version,
                flags,
                method,
                crc32,
                extra,
                comment: entry_comment,
                external_attrs,
                internal_attrs,
                dos_datetime: (dos_date, dos_time),
            }),
            body: Body::Inline(data),
            dirty: false,
        });
    }

    for (p, n) in out.duplicate_paths() {
        notes.push(Note::at(
            NoteCode::DuplicateEntryPath,
            p,
            format!("appears {n} times; sort ties break on parse order"),
        ));
    }
    Ok(out)
}

fn find_eocd(b: &[u8]) -> Result<(usize, u64, Vec<u8>)> {
    // The EOCD is at the end, after a comment of up to 64 KiB.
    let window = b.len().min(66 * 1024);
    let start = b.len() - window;
    let pos = (start..b.len().saturating_sub(21))
        .rev()
        .find(|&i| {
            b[i..].len() >= 4 && u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) == SIG_EOCD
        })
        .ok_or_else(|| bad("no end-of-central-directory record"))?;

    let mut c = Cursor::new(b, pos + 4);
    let _disk = c.u16()?;
    let _cd_disk = c.u16()?;
    let _n_here = c.u16()?;
    let n_total = c.u16()?;
    let _cd_size = c.u32()?;
    let cd_offset = c.u32()?;
    let comment_len = c.u16()? as usize;
    let comment = c.take(comment_len).unwrap_or(&[]).to_vec();

    if n_total == ZIP64_MARK16 || cd_offset == ZIP64_MARK32 {
        let (off, count) = find_eocd64(b, pos)?;
        return Ok((off, count, comment));
    }
    Ok((cd_offset as usize, u64::from(n_total), comment))
}

fn find_eocd64(b: &[u8], eocd_pos: usize) -> Result<(usize, u64)> {
    // The zip64 locator sits immediately before the EOCD.
    let loc = eocd_pos
        .checked_sub(20)
        .ok_or_else(|| bad("no zip64 locator"))?;
    let mut c = Cursor::new(b, loc);
    if c.u32()? != SIG_EOCD64_LOCATOR {
        return Err(bad("zip64 locator signature"));
    }
    let _disk = c.u32()?;
    let eocd64_off = c.u64()? as usize;

    let mut c = Cursor::new(b, eocd64_off);
    if c.u32()? != SIG_EOCD64 {
        return Err(bad("zip64 end-of-central-directory signature"));
    }
    let _size = c.u64()?;
    let _made = c.u16()?;
    let _need = c.u16()?;
    let _disk = c.u32()?;
    let _cd_disk = c.u32()?;
    let _n_here = c.u64()?;
    let n_total = c.u64()?;
    let _cd_size = c.u64()?;
    let cd_offset = c.u64()? as usize;
    Ok((cd_offset, n_total))
}

fn parse_zip64_extra(extra: &[u8], u: u64, c: u64, off: u64) -> Result<(u64, u64, u64)> {
    let mut p = 0usize;
    while p + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[p], extra[p + 1]]);
        let len = u16::from_le_bytes([extra[p + 2], extra[p + 3]]) as usize;
        let body = extra
            .get(p + 4..p + 4 + len)
            .ok_or_else(|| bad("truncated extra field"))?;
        if id == 0x0001 {
            let mut q = Cursor::new(body, 0);
            let u2 = if u == u64::from(ZIP64_MARK32) {
                q.u64()?
            } else {
                u
            };
            let c2 = if c == u64::from(ZIP64_MARK32) {
                q.u64()?
            } else {
                c
            };
            let o2 = if off == u64::from(ZIP64_MARK32) {
                q.u64()?
            } else {
                off
            };
            return Ok((u2, c2, o2));
        }
        p += 4 + len;
    }
    Err(bad("zip64 marker without a zip64 extra field"))
}

fn read_member(
    b: &[u8],
    local_offset: u64,
    method: u16,
    comp: u64,
    uncomp: u64,
) -> Result<Vec<u8>> {
    let mut c = Cursor::new(
        b,
        usize::try_from(local_offset).map_err(|_| bad("offset overflow"))?,
    );
    if c.u32()? != SIG_LFH {
        return Err(bad("local file header signature"));
    }
    let _ver = c.u16()?;
    let _flags = c.u16()?;
    let _method = c.u16()?;
    let _time = c.u16()?;
    let _date = c.u16()?;
    let _crc = c.u32()?;
    let _cs = c.u32()?;
    let _us = c.u32()?;
    let name_len = c.u16()? as usize;
    let extra_len = c.u16()? as usize;
    c.take(name_len)?;
    c.take(extra_len)?;

    let raw = c.take(usize::try_from(comp).map_err(|_| bad("compressed size overflow"))?)?;
    match method {
        METHOD_STORE => Ok(raw.to_vec()),
        METHOD_DEFLATE => {
            use std::io::Read as _;
            let mut out = Vec::with_capacity(usize::try_from(uncomp).unwrap_or(0));
            flate2::read::DeflateDecoder::new(raw)
                .read_to_end(&mut out)
                .map_err(|e| bad(format!("inflate: {e}")))?;
            Ok(out)
        }
        other => Err(ArchiveError::Unsupported(format!(
            "zip compression method {other}"
        ))),
    }
}

fn unix_mode(external_attrs: u32) -> Option<u32> {
    let mode = external_attrs >> 16;
    (mode != 0).then_some(mode)
}

/// MS-DOS date and time to seconds since the epoch. `(0, 0)` is the zeroed form a stabilizer
/// leaves behind and reads back as absent.
fn dos_to_unix(date: u16, time: u16) -> Option<i64> {
    if date == 0 && time == 0 {
        return None;
    }
    let (y, mo, d) = (
        1980 + (date >> 9) as i64,
        ((date >> 5) & 0xf) as i64,
        (date & 0x1f) as i64,
    );
    let (h, mi, s) = (
        (time >> 11) as i64,
        ((time >> 5) & 0x3f) as i64,
        ((time & 0x1f) * 2) as i64,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from civil, Howard Hinnant's algorithm.
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

/// Write the archive as a zip.
///
/// `store_only` emits method 0 for every member, which is what stabilized output uses: the
/// stabilized stream never passes through a deflate encoder, so no encoder's behaviour can leak into
/// a signed digest.
pub fn write<W: Write>(archive: &Archive, w: &mut W, store_only: bool) -> Result<()> {
    let mut sink = CountingWriter { inner: w, count: 0 };
    let mut central: Vec<CentralRecord> = Vec::with_capacity(archive.entries.len());

    for e in &archive.entries {
        let raw = match &e.raw {
            RawMeta::Zip(z) => z.clone(),
            RawMeta::Tar(_) => return Err(ArchiveError::Unsupported("tar entry in a zip".into())),
        };
        let body = e.body_bytes()?;
        let uncomp = body.len() as u64;
        let method = if store_only { METHOD_STORE } else { raw.method };
        let payload: Vec<u8> = match method {
            METHOD_STORE => body.to_vec(),
            METHOD_DEFLATE => {
                let mut enc =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(&body)?;
                enc.finish()?
            }
            other => return Err(ArchiveError::Unsupported(format!("zip method {other}"))),
        };
        let crc = crc32fast::hash(&body);
        let offset = sink.count;
        let needs64 = uncomp > u64::from(ZIP64_MARK32)
            || payload.len() as u64 > u64::from(ZIP64_MARK32)
            || offset > u64::from(ZIP64_MARK32);

        // Local file header. We never set the data-descriptor flag: sizes are known here, and a
        // descriptor is one more thing two writers can disagree about.
        let flags = raw.flags & !FLAG_DATA_DESCRIPTOR;
        sink.write_all(&SIG_LFH.to_le_bytes())?;
        sink.write_all(&if needs64 { 45u16 } else { raw.reader_version }.to_le_bytes())?;
        sink.write_all(&flags.to_le_bytes())?;
        sink.write_all(&method.to_le_bytes())?;
        sink.write_all(&raw.dos_datetime.1.to_le_bytes())?;
        sink.write_all(&raw.dos_datetime.0.to_le_bytes())?;
        sink.write_all(&crc.to_le_bytes())?;
        let local_extra = if needs64 {
            zip64_extra(uncomp, payload.len() as u64, None)
        } else {
            Vec::new()
        };
        if needs64 {
            sink.write_all(&ZIP64_MARK32.to_le_bytes())?;
            sink.write_all(&ZIP64_MARK32.to_le_bytes())?;
        } else {
            sink.write_all(&(payload.len() as u32).to_le_bytes())?;
            sink.write_all(&(uncomp as u32).to_le_bytes())?;
        }
        sink.write_all(&(e.path.len() as u16).to_le_bytes())?;
        sink.write_all(&(local_extra.len() as u16).to_le_bytes())?;
        sink.write_all(e.path.as_bytes())?;
        sink.write_all(&local_extra)?;
        sink.write_all(&payload)?;

        central.push(CentralRecord {
            raw,
            path: e.path.as_bytes().to_vec(),
            crc,
            comp: payload.len() as u64,
            uncomp,
            offset,
            method,
            flags,
            needs64,
        });
    }

    let cd_offset = sink.count;
    for r in &central {
        r.write(&mut sink)?;
    }
    let cd_size = sink.count - cd_offset;
    write_end(
        &mut sink,
        cd_offset,
        cd_size,
        central.len() as u64,
        archive.trailer_comment(),
    )?;
    Ok(())
}

struct CentralRecord {
    raw: ZipRaw,
    path: Vec<u8>,
    crc: u32,
    comp: u64,
    uncomp: u64,
    offset: u64,
    method: u16,
    flags: u16,
    needs64: bool,
}

impl CentralRecord {
    fn write<W: Write>(&self, w: &mut CountingWriter<'_, W>) -> Result<()> {
        // Zip64 rewrites only the fields that overflowed, in the order the spec fixes.
        let z64 = self.needs64;
        let extra = if z64 {
            let mut base = zip64_extra(self.uncomp, self.comp, Some(self.offset));
            base.extend_from_slice(&self.raw.extra);
            base
        } else {
            self.raw.extra.clone()
        };

        w.write_all(&SIG_CDH.to_le_bytes())?;
        w.write_all(&self.raw.creator_version.to_le_bytes())?;
        w.write_all(&if z64 { 45u16 } else { self.raw.reader_version }.to_le_bytes())?;
        w.write_all(&self.flags.to_le_bytes())?;
        w.write_all(&self.method.to_le_bytes())?;
        w.write_all(&self.raw.dos_datetime.1.to_le_bytes())?;
        w.write_all(&self.raw.dos_datetime.0.to_le_bytes())?;
        w.write_all(&self.crc.to_le_bytes())?;
        w.write_all(&if z64 { ZIP64_MARK32 } else { self.comp as u32 }.to_le_bytes())?;
        w.write_all(
            &if z64 {
                ZIP64_MARK32
            } else {
                self.uncomp as u32
            }
            .to_le_bytes(),
        )?;
        w.write_all(&(self.path.len() as u16).to_le_bytes())?;
        w.write_all(&(extra.len() as u16).to_le_bytes())?;
        w.write_all(&(self.raw.comment.len() as u16).to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?; // disk number start
        w.write_all(&self.raw.internal_attrs.to_le_bytes())?;
        w.write_all(&self.raw.external_attrs.to_le_bytes())?;
        w.write_all(
            &if z64 {
                ZIP64_MARK32
            } else {
                self.offset as u32
            }
            .to_le_bytes(),
        )?;
        w.write_all(&self.path)?;
        w.write_all(&extra)?;
        w.write_all(&self.raw.comment)?;
        Ok(())
    }
}

fn zip64_extra(uncomp: u64, comp: u64, offset: Option<u64>) -> Vec<u8> {
    let n = if offset.is_some() { 24 } else { 16 };
    let mut v = Vec::with_capacity(n + 4);
    v.extend_from_slice(&0x0001u16.to_le_bytes());
    v.extend_from_slice(&(n as u16).to_le_bytes());
    v.extend_from_slice(&uncomp.to_le_bytes());
    v.extend_from_slice(&comp.to_le_bytes());
    if let Some(o) = offset {
        v.extend_from_slice(&o.to_le_bytes());
    }
    v
}

fn write_end<W: Write>(
    w: &mut CountingWriter<'_, W>,
    cd_offset: u64,
    cd_size: u64,
    count: u64,
    comment: &[u8],
) -> Result<()> {
    let needs64 = count > u64::from(ZIP64_MARK16)
        || cd_offset > u64::from(ZIP64_MARK32)
        || cd_size > u64::from(ZIP64_MARK32);

    if needs64 {
        let eocd64_at = w.count;
        w.write_all(&SIG_EOCD64.to_le_bytes())?;
        w.write_all(&44u64.to_le_bytes())?;
        w.write_all(&45u16.to_le_bytes())?;
        w.write_all(&45u16.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&count.to_le_bytes())?;
        w.write_all(&count.to_le_bytes())?;
        w.write_all(&cd_size.to_le_bytes())?;
        w.write_all(&cd_offset.to_le_bytes())?;

        w.write_all(&SIG_EOCD64_LOCATOR.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&eocd64_at.to_le_bytes())?;
        w.write_all(&1u32.to_le_bytes())?;
    }

    w.write_all(&SIG_EOCD.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    let c16 = if needs64 { ZIP64_MARK16 } else { count as u16 };
    w.write_all(&c16.to_le_bytes())?;
    w.write_all(&c16.to_le_bytes())?;
    w.write_all(
        &if needs64 {
            ZIP64_MARK32
        } else {
            cd_size as u32
        }
        .to_le_bytes(),
    )?;
    w.write_all(
        &if needs64 {
            ZIP64_MARK32
        } else {
            cd_offset as u32
        }
        .to_le_bytes(),
    )?;
    w.write_all(&(comment.len() as u16).to_le_bytes())?;
    w.write_all(comment)?;
    Ok(())
}

struct CountingWriter<'a, W: Write> {
    inner: &'a mut W,
    count: u64,
}

impl<W: Write> Write for CountingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Archive {
    fn trailer_comment(&self) -> &[u8] {
        match &self.trailer {
            Trailer::Zip { comment } => comment,
            _ => &[],
        }
    }
}
