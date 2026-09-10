//! Tar reading and byte-exact writing.
//!
//! The reader leans on the `tar` crate, which handles PAX and GNU long-name parsing well. The writer
//! is ours, because `tar::Header` is a `[u8; 512]` newtype with no first-class PAX-record emission
//! and stabilization depends on forcing PAX. See `docs/05-archive-and-normalization.md` §2.1.

use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::sync::Arc;

use trigon_core::{EntryPath, Format, Note, NoteCode};

use crate::error::{ArchiveError, Result};
use crate::limits::Limits;
use crate::model::{Archive, Body, Entry, EntryKind, Meta, RawMeta, SourceMap, TarRaw, Trailer};

const BLOCK: usize = 512;
const NAME_LEN: usize = 100;
const PREFIX_LEN: usize = 155;
/// The largest value an 11-digit octal field holds.
const MAX_OCTAL_12: u64 = 0o77_777_777_777;
/// The largest value a 7-digit octal field holds.
const MAX_OCTAL_8: u64 = 0o7_777_777;

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

pub fn read(src: Arc<SourceMap>, limits: &Limits, notes: &mut Vec<Note>) -> Result<Archive> {
    let bytes = src.as_slice();
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut out = Archive::new(Format::Tar, Trailer::Tar);
    let mut expanded: u64 = 0;

    let entries = archive.entries().map_err(|e| ArchiveError::Malformed {
        format: "tar",
        detail: format!("reading entries: {e}"),
    })?;

    for (ordinal, item) in entries.enumerate() {
        let ordinal = ordinal as u32;
        let mut e = item.map_err(|err| ArchiveError::Malformed {
            format: "tar",
            detail: format!("entry {ordinal}: {err}"),
        })?;

        if ordinal >= limits.max_entries {
            notes.push(Note::new(
                NoteCode::EntryLimitReached,
                format!("stopped at {ordinal}"),
            ));
            break;
        }

        let path = EntryPath::new(e.path_bytes().into_owned());
        let size = e.size();
        expanded = expanded.saturating_add(size);
        if expanded > limits.total_expanded_bytes {
            return Err(ArchiveError::LimitExceeded {
                limit: "total_expanded_bytes",
                actual: expanded,
                allowed: limits.total_expanded_bytes,
            });
        }

        // PAX records: the ones we synthesize on the way out are lifted into typed fields, the
        // rest are preserved verbatim and re-emitted in keyword order.
        let mut pax: BTreeMap<String, String> = BTreeMap::new();
        let mut pax_mtime: Option<String> = None;
        let mut pax_atime: Option<String> = None;
        let mut pax_ctime: Option<String> = None;
        let mut had_pax_path = false;
        if let Ok(Some(exts)) = e.pax_extensions() {
            for ext in exts.flatten() {
                let key = String::from_utf8_lossy(ext.key_bytes()).into_owned();
                let val = String::from_utf8_lossy(ext.value_bytes()).into_owned();
                match key.as_str() {
                    "path" => had_pax_path = true,
                    "linkpath" | "size" => {}
                    "mtime" => pax_mtime = Some(val),
                    "atime" => pax_atime = Some(val),
                    "ctime" => pax_ctime = Some(val),
                    _ => {
                        pax.insert(key, val);
                    }
                }
            }
        }

        let header = e.header();
        let et = header.entry_type();
        let typeflag = et.as_byte();
        let linkname = e
            .link_name_bytes()
            .map(|c| c.into_owned())
            .unwrap_or_default();
        let devmajor = header.device_major().ok().flatten().unwrap_or(0);
        let devminor = header.device_minor().ok().flatten().unwrap_or(0);

        let kind = classify(typeflag, &linkname, devmajor, devminor);
        if matches!(kind, EntryKind::Other(_)) {
            notes.push(Note::at(
                NoteCode::UnknownEntryKind,
                path.clone(),
                format!("typeflag {:?}", typeflag as char),
            ));
        }
        if kind.requires_empty_body() && size != 0 {
            notes.push(Note::at(
                NoteCode::MalformedEntry,
                path.clone(),
                format!("{kind:?} carries a {size}-byte body; bytes preserved"),
            ));
        }
        // A name that fits the ustar prefix field needed no extension at all. Only a name that
        // cannot split, and did not arrive as PAX, must have come from a GNU long-name entry.
        let needs_extension = ustar_split(path.as_bytes()).is_none();
        let long_name_was_gnu = needs_extension && !had_pax_path;
        if long_name_was_gnu {
            notes.push(Note::at(
                NoteCode::LongNameReencoded,
                path.clone(),
                "GNU long name in, PAX long name out",
            ));
        }

        let mtime =
            parse_pax_time(pax_mtime.as_deref()).or_else(|| Some(header.mtime().ok()? as i64));

        let raw = TarRaw {
            typeflag,
            linkname,
            uid: header.uid().unwrap_or(0),
            gid: header.gid().unwrap_or(0),
            uname: header
                .username_bytes()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
            gname: header
                .groupname_bytes()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
            devmajor,
            devminor,
            atime: parse_pax_time(pax_atime.as_deref()),
            ctime: parse_pax_time(pax_ctime.as_deref()),
            pax,
            long_name_was_gnu,
        };

        let body = Body::Original {
            src: Arc::clone(&src),
            off: e.raw_file_position(),
            len: size,
        };

        out.entries.push(Entry {
            path,
            ordinal,
            kind,
            meta: Meta {
                size,
                mtime,
                mode: header.mode().unwrap_or(0o644),
            },
            raw: RawMeta::Tar(raw),
            body,
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

fn classify(typeflag: u8, linkname: &[u8], major: u32, minor: u32) -> EntryKind {
    match typeflag {
        b'0' | b'\0' | b'7' => EntryKind::Regular,
        b'5' => EntryKind::Directory,
        b'2' => EntryKind::Symlink {
            target: linkname.to_vec(),
        },
        b'1' => EntryKind::Hardlink {
            target: linkname.to_vec(),
        },
        b'3' => EntryKind::CharDevice { major, minor },
        b'4' => EntryKind::BlockDevice { major, minor },
        b'6' => EntryKind::Fifo,
        other => EntryKind::Other(other),
    }
}

/// PAX times are decimal seconds with an optional fraction. We keep whole seconds; a fraction is
/// dropped, and the record is regenerated from the integer on the way out.
fn parse_pax_time(s: Option<&str>) -> Option<i64> {
    let s = s?;
    let whole = s.split_once('.').map(|(a, _)| a).unwrap_or(s);
    whole.parse::<i64>().ok()
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

pub fn write<W: Write>(archive: &Archive, w: &mut W) -> Result<()> {
    for entry in &archive.entries {
        write_entry(entry, w)?;
    }
    // Two zero blocks and nothing more: no blocking-factor padding, so the output is a pure
    // function of the entries.
    w.write_all(&[0u8; BLOCK * 2])?;
    Ok(())
}

fn write_entry<W: Write>(e: &Entry, w: &mut W) -> Result<()> {
    let raw = match &e.raw {
        RawMeta::Tar(t) => t,
        RawMeta::Zip(_) => {
            return Err(ArchiveError::Unsupported(
                "zip entry in a tar archive".into(),
            ));
        }
    };

    let body = e.body_bytes()?;
    // The format requires an empty body for these kinds, whatever the parser found.
    let size = if e.kind.requires_empty_body() {
        0
    } else {
        body.len() as u64
    };

    let mut pax: BTreeMap<String, String> = raw.pax.clone();

    // `path`: ustar splits at a '/' into a 155-byte prefix and a 100-byte name. Anything that will
    // not split takes a PAX record. We never emit a GNU long-name entry.
    let name_bytes = e.path.as_bytes();
    let split = ustar_split(name_bytes);
    if split.is_none() {
        pax.insert(
            "path".into(),
            String::from_utf8_lossy(name_bytes).into_owned(),
        );
    }

    if raw.linkname.len() > NAME_LEN {
        pax.insert(
            "linkpath".into(),
            String::from_utf8_lossy(&raw.linkname).into_owned(),
        );
    }
    if size > MAX_OCTAL_12 {
        pax.insert("size".into(), size.to_string());
    }
    if raw.uid > MAX_OCTAL_8 {
        pax.insert("uid".into(), raw.uid.to_string());
    }
    if raw.gid > MAX_OCTAL_8 {
        pax.insert("gid".into(), raw.gid.to_string());
    }
    // ustar has no atime or ctime field, so a value there is only representable as PAX. This is why
    // `tar-time` "forces PAX": it sets atime, and atime cannot survive otherwise.
    if let Some(t) = raw.atime {
        pax.insert("atime".into(), t.to_string());
    }
    if let Some(t) = raw.ctime {
        pax.insert("ctime".into(), t.to_string());
    }
    let mtime = e.meta.mtime.unwrap_or(0);
    if mtime < 0 || mtime as u64 > MAX_OCTAL_12 {
        pax.insert("mtime".into(), mtime.to_string());
    }

    if !pax.is_empty() {
        write_pax_header(&pax, name_bytes, w)?;
    }

    // The ustar header. When a PAX `path` record carried the real name, the header still needs
    // something; truncating the original is what every implementation does.
    let (prefix, name) =
        split.unwrap_or_else(|| (&[][..], &name_bytes[..name_bytes.len().min(NAME_LEN)]));

    let mut hdr = [0u8; BLOCK];
    put_bytes(&mut hdr[0..100], name);
    put_octal(&mut hdr[100..108], u64::from(e.meta.mode & 0o7777));
    put_octal(&mut hdr[108..116], raw.uid.min(MAX_OCTAL_8));
    put_octal(&mut hdr[116..124], raw.gid.min(MAX_OCTAL_8));
    put_octal(&mut hdr[124..136], size.min(MAX_OCTAL_12));
    put_octal(
        &mut hdr[136..148],
        if mtime < 0 {
            0
        } else {
            (mtime as u64).min(MAX_OCTAL_12)
        },
    );
    // chksum (148..156) is filled last.
    hdr[156] = raw.typeflag;
    put_bytes(
        &mut hdr[157..257],
        &raw.linkname[..raw.linkname.len().min(NAME_LEN)],
    );
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");
    put_bytes(&mut hdr[265..297], &raw.uname);
    put_bytes(&mut hdr[297..329], &raw.gname);
    put_octal(&mut hdr[329..337], u64::from(raw.devmajor));
    put_octal(&mut hdr[337..345], u64::from(raw.devminor));
    put_bytes(&mut hdr[345..500], prefix);
    finish_checksum(&mut hdr);

    w.write_all(&hdr)?;
    if size > 0 {
        w.write_all(&body[..size as usize])?;
        pad_to_block(w, size as usize)?;
    }
    Ok(())
}

/// A PAX extended header is itself a tar entry with typeflag `x`, whose body is the records.
fn write_pax_header<W: Write>(
    pax: &BTreeMap<String, String>,
    for_name: &[u8],
    w: &mut W,
) -> Result<()> {
    let mut body = Vec::new();
    // BTreeMap iterates in keyword order, which is the ordering rule the writer promises.
    for (k, v) in pax {
        body.extend_from_slice(&pax_record(k, v));
    }

    // A PAX extended header entry is built minimally: name, typeflag, mode, uid, gid, size,
    // mtime, magic. Everything else stays NUL. In particular the device fields are left untouched
    // rather than octal-formatted, and the mode is 0 rather than a plausible file mode. Both are
    // reference behaviour, and both showed up as byte differences the first time the differential
    // test ran. See `docs/05-archive-and-normalization.md` §6.
    let name = pax_header_name(for_name);
    let mut hdr = [0u8; BLOCK];
    put_bytes(&mut hdr[0..100], &name);
    put_octal(&mut hdr[100..108], 0);
    put_octal(&mut hdr[108..116], 0);
    put_octal(&mut hdr[116..124], 0);
    put_octal(&mut hdr[124..136], body.len() as u64);
    put_octal(&mut hdr[136..148], 0);
    hdr[156] = b'x';
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");
    finish_checksum(&mut hdr);

    w.write_all(&hdr)?;
    w.write_all(&body)?;
    pad_to_block(w, body.len())?;
    Ok(())
}

/// `"%d %s=%s\n"`, where the length counts itself. Adding a digit can push the length over a power
/// of ten, so the length is a fixpoint rather than a calculation.
fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let payload = key.len() + 1 + value.len() + 1; // key=value\n
    let mut len = payload + 1; // one digit for the length, plus the space
    loop {
        let digits = len.to_string().len();
        let candidate = payload + digits + 1;
        if candidate == len {
            break;
        }
        len = candidate;
    }
    format!("{len} {key}={value}\n").into_bytes()
}

/// `dir/PaxHeaders.0/file`, truncated to the name field. Matching the convention Go and GNU tar use
/// keeps the differential test focused on things that matter.
fn pax_header_name(name: &[u8]) -> Vec<u8> {
    let (dir, file) = match name.iter().rposition(|&c| c == b'/') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (&[][..], name),
    };
    let mut out = Vec::with_capacity(name.len() + 14);
    if !dir.is_empty() {
        out.extend_from_slice(dir);
        out.push(b'/');
    }
    out.extend_from_slice(b"PaxHeaders.0/");
    out.extend_from_slice(file);
    out.truncate(NAME_LEN);
    while out.last() == Some(&b'/') {
        out.pop();
    }
    out
}

/// Split a path into a ustar `(prefix, name)` pair, or `None` when it will not fit.
fn ustar_split(name: &[u8]) -> Option<(&[u8], &[u8])> {
    if name.len() <= NAME_LEN {
        return Some((&[], name));
    }
    if name.len() > NAME_LEN + PREFIX_LEN + 1 {
        return None;
    }
    // The split point must be a '/', the prefix must fit, and the remainder must fit.
    let cut = name
        .iter()
        .enumerate()
        .filter(|&(i, &c)| c == b'/' && i <= PREFIX_LEN && name.len() - i - 1 <= NAME_LEN)
        .map(|(i, _)| i)
        .next()?;
    Some((&name[..cut], &name[cut + 1..]))
}

fn put_bytes(field: &mut [u8], value: &[u8]) {
    let n = value.len().min(field.len());
    field[..n].copy_from_slice(&value[..n]);
    for b in &mut field[n..] {
        *b = 0;
    }
}

/// Zero-padded octal filling `field.len() - 1` bytes, then a NUL. What GNU tar and Go both emit.
fn put_octal(field: &mut [u8], value: u64) {
    let s = format!("{value:o}");
    let width = field.len() - 1;
    let s = if s.len() > width {
        s[s.len() - width..].to_string()
    } else {
        s
    };
    let pad = width - s.len();
    for b in &mut field[..pad] {
        *b = b'0';
    }
    field[pad..width].copy_from_slice(s.as_bytes());
    field[width] = 0;
}

fn finish_checksum(hdr: &mut [u8; BLOCK]) {
    for b in &mut hdr[148..156] {
        *b = b' ';
    }
    let sum: u32 = hdr.iter().map(|&b| u32::from(b)).sum();
    let s = format!("{sum:06o}");
    hdr[148..154].copy_from_slice(s.as_bytes());
    hdr[154] = 0;
    hdr[155] = b' ';
}

fn pad_to_block<W: Write>(w: &mut W, written: usize) -> Result<()> {
    let rem = written % BLOCK;
    if rem != 0 {
        w.write_all(&vec![0u8; BLOCK - rem])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pax_record_length_is_a_fixpoint() {
        // "9 x=y\n" is 6 bytes, so the length is 6, not 9.
        assert_eq!(pax_record("x", "y"), b"6 x=y\n".to_vec());
        // A record whose length crosses a power of ten has to grow its own digit count.
        let long = "a".repeat(92);
        let r = pax_record("path", &long);
        let len: usize = String::from_utf8_lossy(&r)
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(len, r.len());
    }

    #[test]
    fn octal_fields_match_the_gnu_convention() {
        let mut f = [0u8; 8];
        put_octal(&mut f, 0o644);
        assert_eq!(&f, b"0000644\0");
        let mut f = [0u8; 12];
        put_octal(&mut f, 0);
        assert_eq!(&f, b"00000000000\0");
    }

    #[test]
    fn ustar_split_prefers_no_prefix() {
        assert_eq!(
            ustar_split(b"short/path"),
            Some((&b""[..], &b"short/path"[..]))
        );
        let long = format!("{}/{}", "d".repeat(120), "f".repeat(50));
        let (p, n) = ustar_split(long.as_bytes()).unwrap();
        assert_eq!(p.len(), 120);
        assert_eq!(n.len(), 50);
        // No '/' in reach, so PAX has to carry it.
        assert_eq!(ustar_split(&vec![b'x'; 300]), None);
    }

    #[test]
    fn pax_header_name_follows_the_convention() {
        assert_eq!(
            pax_header_name(b"a/b/c.txt"),
            b"a/b/PaxHeaders.0/c.txt".to_vec()
        );
        assert_eq!(pax_header_name(b"top"), b"PaxHeaders.0/top".to_vec());
    }
}
