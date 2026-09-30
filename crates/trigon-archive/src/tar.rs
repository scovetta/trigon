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
/// The largest value an 11-digit octal field holds.
const MAX_OCTAL_12: u64 = 0o77_777_777_777;
/// The largest value a 7-digit octal field holds.
const MAX_OCTAL_8: u64 = 0o7_777_777;

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

/// Read a tar, ending it where every reader agrees it ends.
///
/// A lone zero block with more of the archive after it is refused, because node-tar reads on past
/// one and the `tar` crate does not. Bytes after two zero blocks that are not padding are kept, in
/// [`Archive::tar_trailing`].
pub fn read(src: Arc<SourceMap>, limits: &Limits, notes: &mut Vec<Note>) -> Result<Archive> {
    let bytes = src.as_slice();
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut out = Archive::new(Format::Tar, Trailer::Tar);
    let mut expanded: u64 = 0;

    let entries = archive.entries().map_err(|e| ArchiveError::Malformed {
        format: "tar",
        detail: format!("reading entries: {e}"),
    })?;

    let mut cut = false;
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
            cut = true;
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
        // rest are preserved verbatim and re-emitted in keyword order. A value is kept as its
        // bytes, which POSIX lets be binary; a keyword is text, and one that is not is refused
        // rather than decoded into one another keyword could decode into too.
        let mut pax: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut pax_mtime: Option<Vec<u8>> = None;
        let mut pax_atime: Option<Vec<u8>> = None;
        let mut pax_ctime: Option<Vec<u8>> = None;
        let mut had_pax_path = false;
        if let Ok(Some(exts)) = e.pax_extensions() {
            for ext in exts.flatten() {
                let Ok(key) = std::str::from_utf8(ext.key_bytes()) else {
                    return Err(ArchiveError::Malformed {
                        format: "tar",
                        detail: format!("entry {ordinal}: a PAX keyword that is not UTF-8"),
                    });
                };
                let val = ext.value_bytes().to_vec();
                match key {
                    "path" => had_pax_path = true,
                    "linkpath" | "size" => {}
                    "mtime" => pax_mtime = Some(val),
                    "atime" => pax_atime = Some(val),
                    "ctime" => pax_ctime = Some(val),
                    _ => {
                        pax.insert(key.to_string(), val);
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
        // The writer re-encodes every name over 100 bytes as PAX. One that arrived without a PAX
        // `path` record therefore came in as either a GNU long-name entry or a ustar prefix split,
        // and either way the framing changes on the way out.
        let long_name_was_gnu = path.as_bytes().len() > NAME_LEN && !had_pax_path;
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
            renamed_from: None,
        });
    }

    // Where the `tar` crate stopped: past the zero block it took for the end, or at the end of
    // the bytes. An entry limit stops the walk short of either, and its note already says so.
    if !cut {
        let stop = archive.into_inner().position();
        out.tar_trailing = after_the_end(bytes, usize::try_from(stop).unwrap_or(usize::MAX))?;
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

/// What follows the entries, from `stop`, the offset the `tar` crate stopped reading at.
///
/// The `tar` crate ends an archive at its first zero block, as GNU tar, bsdtar and Python do.
/// node-tar, which npm installs with, ends it only at two in a row and reads on past one. So
/// entries after a lone zero block installed from npm and were never seen here, and a `.tgz`
/// carrying them matched an honest rebuild without them. Where readers disagree on what an archive
/// holds there is no one answer to compare, and the archive is refused.
///
/// After two zero blocks every reader has stopped. Zero padding after them is dropped, as the
/// writer drops a blocking factor. Anything else is returned, to be kept rather than lost.
fn after_the_end(bytes: &[u8], stop: usize) -> Result<Vec<u8>> {
    let rest = bytes.get(stop..).unwrap_or_default();
    if rest.iter().all(|&b| b == 0) {
        return Ok(Vec::new());
    }
    // Something follows, so the crate stopped at a zero block and not at the end of the bytes.
    // The block after it, whole or cut short, decides which kind of end that was.
    let (second, after) = rest.split_at(rest.len().min(BLOCK));
    if second.iter().any(|&b| b != 0) {
        return Err(ArchiveError::Malformed {
            format: "tar",
            detail: format!(
                "a lone zero block ends the entries, and more of the archive follows at offset \
                 {stop}: node-tar reads on past it and other readers do not"
            ),
        });
    }
    Ok(after.to_vec())
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
fn parse_pax_time(s: Option<&[u8]>) -> Option<i64> {
    let s = std::str::from_utf8(s?).ok()?;
    let whole = s.split_once('.').map(|(a, _)| a).unwrap_or(s);
    whole.parse::<i64>().ok()
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

/// Write `archive`'s entries, its end-of-archive marker, and then its [`Archive::tar_trailing`].
///
/// Trailing bytes that are all zero are refused: [`read`] takes them for padding, so they could
/// not come back as what they were.
pub fn write<W: Write>(archive: &Archive, w: &mut W) -> Result<()> {
    let trailing = &archive.tar_trailing;
    if !trailing.is_empty() && trailing.iter().all(|&b| b == 0) {
        return Err(ArchiveError::Unsupported(
            "tar trailing bytes that are all zero would read back as padding".into(),
        ));
    }
    for entry in &archive.entries {
        write_entry(entry, w)?;
    }
    // Two zero blocks and no blocking-factor padding, so the output is a pure function of the
    // entries and of whatever followed the end of the archive they were read from.
    w.write_all(&[0u8; BLOCK * 2])?;
    w.write_all(trailing)?;
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

    // A device number past seven octal digits has no spelling here that reads back as itself.
    // `put_octal` would keep the low digits, which is another device; GNU base-256 is a field the
    // `tar` crate reads as 0; and a `SCHILY.devmajor` record is one our reader does not lift back
    // into the field. Each breaks `parse(write(a)) == a`, so the entry is refused instead, before
    // anything is written. `tar-device` zeroes both before a stabilized write.
    for (field, v) in [("devmajor", raw.devmajor), ("devminor", raw.devminor)] {
        if u64::from(v) > MAX_OCTAL_8 {
            return Err(ArchiveError::Unsupported(format!(
                "{field} {v:#o} does not fit the seven octal digits of its ustar field"
            )));
        }
    }

    let body = e.body_bytes()?;
    // The format requires an empty body for these kinds, whatever the parser found.
    let size = if e.kind.requires_empty_body() {
        0
    } else {
        body.len() as u64
    };

    let mut pax: BTreeMap<String, Vec<u8>> = raw.pax.clone();

    // `path`: a name over 100 bytes always takes a PAX record, and the ustar `prefix` field is
    // never used. ustar could carry some of these names as a 155-byte prefix plus a 100-byte name,
    // but only those with a '/' in the right place, which makes the encoding a property of where
    // the slashes fall. Two paths of the same length would then be framed differently. Emitting
    // PAX for every long name removes that per-entry choice from a signed digest, and it is what a
    // writer pinned to the PAX format does. See docs/05 §2.1.
    //
    // The name and the link target go into their records as the bytes they are, as the reader
    // took them. Decoded lossily, two names that differed past their hundredth byte only in bytes
    // that are not UTF-8 became one record, and with the header field holding the first hundred
    // bytes of each, two entries wrote the same bytes (`docs/16-findings.md` §3.106). POSIX would
    // put `hdrcharset=BINARY` ahead of such a value; the `tar` crate, which reads it back, takes the
    // bytes either way, and a record written here would come back as one the archive carried.
    let name_bytes = e.path.as_bytes();
    if name_bytes.len() > NAME_LEN {
        pax.insert("path".into(), name_bytes.to_vec());
    }

    if raw.linkname.len() > NAME_LEN {
        pax.insert("linkpath".into(), raw.linkname.clone());
    }
    let mut number = |key: &str, n: String| pax.insert(key.into(), n.into_bytes());
    if size > MAX_OCTAL_12 {
        number("size", size.to_string());
    }
    if raw.uid > MAX_OCTAL_8 {
        number("uid", raw.uid.to_string());
    }
    if raw.gid > MAX_OCTAL_8 {
        number("gid", raw.gid.to_string());
    }
    // ustar has no atime or ctime field, so a value there is only representable as PAX. This is why
    // `tar-time` "forces PAX": it sets atime, and atime cannot survive otherwise.
    if let Some(t) = raw.atime {
        number("atime", t.to_string());
    }
    if let Some(t) = raw.ctime {
        number("ctime", t.to_string());
    }
    let mtime = e.meta.mtime.unwrap_or(0);
    if mtime < 0 || mtime as u64 > MAX_OCTAL_12 {
        number("mtime", mtime.to_string());
    }

    if !pax.is_empty() {
        write_pax_header(&pax, name_bytes, w)?;
    }

    // The ustar header. When a PAX `path` record carried the real name, the header still needs
    // something; truncating the original is what every implementation does.
    //
    // A truncation can land just after a '/', and readers that infer "directory" from a trailing
    // slash in the name field then misread a regular file as one. So a truncated name loses its
    // trailing slashes and the NUL terminates the field. Only truncated names: a name that fits is
    // written as it is, trailing slash and all, because there it means what it says.
    let mut name = &name_bytes[..name_bytes.len().min(NAME_LEN)];
    if name_bytes.len() > NAME_LEN {
        while name.last() == Some(&b'/') {
            name = &name[..name.len() - 1];
        }
    }

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
    // 345..500 is the ustar `prefix` field, deliberately left NUL: see the `path` record above.
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
    pax: &BTreeMap<String, Vec<u8>>,
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
fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
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
    let mut out = format!("{len} {key}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    out
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
fn put_bytes(field: &mut [u8], value: &[u8]) {
    let n = value.len().min(field.len());
    field[..n].copy_from_slice(&value[..n]);
    for b in &mut field[n..] {
        *b = 0;
    }
}

/// Zero-padded octal filling `field.len() - 1` bytes, then a NUL. What GNU tar and Go both emit.
///
/// A value too wide keeps its low digits, which is a different number. So a caller whose value can
/// be too wide either clamps it and carries it whole in a PAX record, or refuses it, first; neither
/// GNU tar nor Go truncates.
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
        assert_eq!(pax_record("x", b"y"), b"6 x=y\n".to_vec());
        // A record whose length crosses a power of ten has to grow its own digit count.
        let long = "a".repeat(92);
        let r = pax_record("path", long.as_bytes());
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
    fn pax_header_name_follows_the_convention() {
        assert_eq!(
            pax_header_name(b"a/b/c.txt"),
            b"a/b/PaxHeaders.0/c.txt".to_vec()
        );
        assert_eq!(pax_header_name(b"top"), b"PaxHeaders.0/top".to_vec());
    }
}
