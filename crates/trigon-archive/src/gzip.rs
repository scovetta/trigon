//! The gzip container, hand-rolled.
//!
//! `flate2` gives us deflate, and its `GzEncoder` writes its own header with its own MTIME, OS and
//! XFL bytes. Stabilization needs those fields under our control, so we frame the member ourselves
//! and use `flate2` only for the payload.

use std::io::{Read, Write};

use crate::error::{ArchiveError, Result};
use crate::model::GzipHeader;

const MAGIC: [u8; 2] = [0x1f, 0x8b];
const CM_DEFLATE: u8 = 8;
const FTEXT: u8 = 1 << 0;
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;
/// "unknown", which is what a stabilized member reports rather than leaking the build host.
pub const OS_UNKNOWN: u8 = 255;

/// Parse a gzip file, inflating at most `budget` bytes across all of its members and reading at
/// most `members` of them, a count this takes one from for each member it reads.
///
/// The budget is not advisory. `total_expanded_bytes` used to be checked against the sizes a zip's
/// central directory *declares*, and gzip took no limits at all — so a 200 KB member of compressed
/// zeros inflated to 200 MB inside this process whatever the caller's limits said, and `.tar.gz`,
/// which is every npm package, went through this path. The ceiling has to be enforced against what
/// comes out, because what goes in is a number the attacker wrote.
///
/// **Every member, the way gunzip reads them.** RFC 1952 makes a gzip file a series of members,
/// and gunzip, Node's zlib and Python's gzip inflate all of them into one stream. This used to
/// inflate the first and take the file's last eight bytes as its trailer, so nothing between was
/// ever looked at: a second member whose stored CRC was forged to the first's content read as the
/// first alone, and an npm tarball carrying extra tar entries in one stabilized to the digest of an
/// honest rebuild without them. A member's trailer is now the eight bytes after its own deflate
/// stream, and CRC-32 and ISIZE both have to agree with what inflated or the member is refused
/// rather than read as that content. The header returned is the first member's; the others'
/// headers are checked and set aside, as gunzip sets them aside.
///
/// After a member, the magic starts another one and anything else is not a member. Those bytes
/// are kept, in [`GzipHeader::trailing`], rather than dropped.
///
/// **Members are counted, because bytes do not bound them.** An empty member adds nothing to the
/// output and still costs an inflate, a few microseconds. Nor does the input's size bound them: a
/// `.gz` inside a `.tar.gz` is the outer file's expansion, up to the 4 GiB ceiling from a download
/// of a few MB. Measured, a 242,743-byte `.tgz` holding one `.gz` of five million empty members
/// took 12.9 s to parse, and the ceiling holds forty times as many. So the member past `members`
/// is refused, as `gzip_members`, which at the default count of a million comes 2.7 s in.
/// [`crate::parse()`] gives every read in one artifact the same count, `Limits::max_entries`, so
/// spreading the members over many `.gz` files gains nothing.
pub fn read(bytes: &[u8], budget: u64, members: &mut u32) -> Result<(GzipHeader, Vec<u8>)> {
    let allowed = *members;
    let mut count = || match members.checked_sub(1) {
        Some(left) => {
            *members = left;
            Ok(())
        }
        None => Err(ArchiveError::LimitExceeded {
            limit: "gzip_members",
            actual: u64::from(allowed) + 1,
            allowed: u64::from(allowed),
        }),
    };
    let mut out = Vec::new();
    // One inflater for every member, reset between them rather than allocated afresh. A member
    // can be twenty bytes, and a reset still clears a 32 KiB window: measured, a million empty
    // members (20 MB) read in 2.8 s this way and 4.3 s with a new inflater apiece.
    let mut z = flate2::bufread::DeflateDecoder::new(&bytes[..0]);
    count()?;
    let (mut header, mut p) = member(bytes, &mut z, &mut out, budget)?;
    while p < bytes.len() {
        let rest = &bytes[p..];
        if !rest.starts_with(&MAGIC) {
            header.trailing = rest.to_vec();
            break;
        }
        count()?;
        p += member(rest, &mut z, &mut out, budget)?.1;
    }
    Ok((header, out))
}

/// Read the member `bytes` starts with, appending what it inflates to onto `out`, and return its
/// header and how many bytes of `bytes` it takes up.
fn member<'a>(
    bytes: &'a [u8],
    z: &mut flate2::bufread::DeflateDecoder<&'a [u8]>,
    out: &mut Vec<u8>,
    budget: u64,
) -> Result<(GzipHeader, usize)> {
    let bad = |d: &str| ArchiveError::Malformed {
        format: "gzip",
        detail: d.to_string(),
    };
    if bytes.len() < 18 || bytes[0..2] != MAGIC {
        return Err(bad("not a gzip member"));
    }
    if bytes[2] != CM_DEFLATE {
        return Err(bad("compression method is not deflate"));
    }
    let flg = bytes[3];
    let mtime = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let xfl = bytes[8];
    let os = bytes[9];

    let mut p = 10usize;
    let mut extra = None;
    if flg & FEXTRA != 0 {
        let n = u16::from_le_bytes([
            *bytes.get(p).ok_or_else(|| bad("truncated FEXTRA"))?,
            *bytes.get(p + 1).ok_or_else(|| bad("truncated FEXTRA"))?,
        ]) as usize;
        p += 2;
        extra = Some(
            bytes
                .get(p..p + n)
                .ok_or_else(|| bad("truncated FEXTRA body"))?
                .to_vec(),
        );
        p += n;
    }
    let take_cstr = |p: &mut usize| -> Result<Vec<u8>> {
        let start = *p;
        while *p < bytes.len() && bytes[*p] != 0 {
            *p += 1;
        }
        if *p >= bytes.len() {
            return Err(ArchiveError::Malformed {
                format: "gzip",
                detail: "unterminated string".into(),
            });
        }
        let v = bytes[start..*p].to_vec();
        *p += 1;
        Ok(v)
    };
    let name = if flg & FNAME != 0 {
        Some(take_cstr(&mut p)?)
    } else {
        None
    };
    let comment = if flg & FCOMMENT != 0 {
        Some(take_cstr(&mut p)?)
    } else {
        None
    };
    if flg & FHCRC != 0 {
        p += 2;
    }

    // The deflate stream runs from here to wherever it says it ends, and the trailer follows it. A
    // header that leaves no room for the trailer leaves none for a payload either.
    if p + 8 > bytes.len() {
        return Err(bad("truncated payload"));
    }
    let start = out.len();
    // One byte past what is left of the budget, so an exhausted reader is distinguishable from one
    // that stopped exactly at the limit.
    let ceiling = budget.saturating_sub(start as u64).saturating_add(1);
    z.reset(&bytes[p..]);
    z.by_ref()
        .take(ceiling)
        .read_to_end(out)
        .map_err(|e| bad(&format!("inflate: {e}")))?;
    if out.len() as u64 > budget {
        return Err(ArchiveError::LimitExceeded {
            limit: "total_expanded_bytes",
            actual: out.len() as u64,
            allowed: budget,
        });
    }

    // What the inflater left unread starts where the deflate stream ended, which is the only place
    // this member's trailer can be.
    let end = bytes.len() - z.get_ref().len();
    let tail = bytes
        .get(end..end + 8)
        .ok_or_else(|| bad("truncated trailer"))?;
    let content = &out[start..];
    let want_crc = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
    let got_crc = crc32fast::hash(content);
    if want_crc != got_crc {
        return Err(bad(&format!(
            "crc32 mismatch: stored {want_crc:08x}, computed {got_crc:08x}"
        )));
    }
    // ISIZE is the length modulo 2^32, so the cast wraps exactly as the format does.
    let want_len = u32::from_le_bytes([tail[4], tail[5], tail[6], tail[7]]);
    let got_len = content.len() as u32;
    if want_len != got_len {
        return Err(bad(&format!(
            "isize mismatch: stored {want_len}, inflated {got_len}"
        )));
    }

    // MTIME 0 is how the format spells "no timestamp available", so it reads back as absent.
    let header = GzipHeader {
        mtime: if mtime == 0 { None } else { Some(mtime) },
        name,
        comment,
        extra,
        os,
        xfl,
        trailing: Vec::new(),
    };
    Ok((header, end + 8))
}

/// Frame `payload` as a gzip member under `header`, then write the header's trailing bytes.
///
/// `level` is `flate2::Compression::none()` for stabilized output, which emits stored deflate blocks
/// and so removes any dependence on the encoder's behaviour. See
/// `docs/05-archive-and-normalization.md` §2.1.
///
/// Trailing bytes that begin with the magic are refused: [`read`] would take them for another
/// member, so they could not come back as what they were.
pub fn write<W: Write>(
    header: &GzipHeader,
    payload: &[u8],
    level: flate2::Compression,
    w: &mut W,
) -> Result<()> {
    if header.trailing.starts_with(&MAGIC) {
        return Err(ArchiveError::Unsupported(
            "trailing bytes beginning with the gzip magic would read back as a member".into(),
        ));
    }
    let mut flg = 0u8;
    if header.extra.is_some() {
        flg |= FEXTRA;
    }
    if header.name.is_some() {
        flg |= FNAME;
    }
    if header.comment.is_some() {
        flg |= FCOMMENT;
    }
    // We never emit FTEXT or FHCRC: both are optional, neither carries content, and omitting them
    // removes two more ways for two writers to disagree.
    debug_assert_eq!(flg & (FTEXT | FHCRC), 0);

    w.write_all(&MAGIC)?;
    w.write_all(&[CM_DEFLATE, flg])?;
    w.write_all(&header.mtime.unwrap_or(0).to_le_bytes())?;
    w.write_all(&[header.xfl, header.os])?;
    if let Some(x) = &header.extra {
        w.write_all(&(x.len() as u16).to_le_bytes())?;
        w.write_all(x)?;
    }
    if let Some(n) = &header.name {
        w.write_all(n)?;
        w.write_all(&[0])?;
    }
    if let Some(c) = &header.comment {
        w.write_all(c)?;
        w.write_all(&[0])?;
    }

    if level.level() == 0 {
        // Stored deflate, written by us. The design says the stabilized stream never passes through
        // a deflate encoder; routing it through one that happens to choose stored blocks made that
        // almost true. Twenty lines make it true, and they also remove the one byte-level deviation
        // the differential test found in every tar.gz: an encoder is free to set BFINAL on the last
        // data block or to append an empty final block, and the reference does the latter.
        write_stored_deflate(payload, w)?;
    } else {
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), level);
        enc.write_all(payload)?;
        w.write_all(&enc.finish()?)?;
    }

    w.write_all(&crc32fast::hash(payload).to_le_bytes())?;
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(&header.trailing)?;
    Ok(())
}

/// Deflate with no entropy coding: stored blocks, then an empty final block.
///
/// A stored block is a 3-bit header padded to a byte boundary, then LEN and its complement, then the
/// bytes. 65535 is the largest LEN the format allows.
fn write_stored_deflate<W: Write>(payload: &[u8], w: &mut W) -> Result<()> {
    const MAX: usize = 65535;
    for chunk in payload.chunks(MAX) {
        w.write_all(&[0u8])?; // BFINAL=0, BTYPE=00, padded to the byte
        w.write_all(&(chunk.len() as u16).to_le_bytes())?;
        w.write_all(&(!(chunk.len() as u16)).to_le_bytes())?;
        w.write_all(chunk)?;
    }
    // The final block is empty rather than the last data block being marked final. Both are legal;
    // this is the one the reference emits.
    w.write_all(&[1u8, 0, 0, 0xff, 0xff])?;
    Ok(())
}

/// The XFL byte deflate writers set for a given level: 2 for best compression, 4 for fastest,
/// 0 otherwise. Stabilized output uses no compression, so it reports 0.
pub const fn xfl_for(level: u32) -> u8 {
    match level {
        9 => 2,
        1 => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_member() {
        let h = GzipHeader {
            mtime: Some(1_700_000_000),
            name: Some(b"payload.tar".to_vec()),
            comment: None,
            extra: None,
            os: 3,
            xfl: 0,
            trailing: Vec::new(),
        };
        let payload = b"the quick brown fox".repeat(50);
        let mut out = Vec::new();
        write(&h, &payload, flate2::Compression::none(), &mut out).unwrap();

        let (h2, p2) = read(&out, u64::MAX, &mut 1).unwrap();
        assert_eq!(h2, h);
        assert_eq!(p2, payload);
    }

    #[test]
    fn stored_output_is_byte_stable() {
        let h = GzipHeader {
            os: OS_UNKNOWN,
            ..Default::default()
        };
        let payload = b"abc".repeat(1000);
        let first = {
            let mut v = Vec::new();
            write(&h, &payload, flate2::Compression::none(), &mut v).unwrap();
            v
        };
        for _ in 0..10 {
            let mut v = Vec::new();
            write(&h, &payload, flate2::Compression::none(), &mut v).unwrap();
            assert_eq!(v, first);
        }
    }

    #[test]
    fn mtime_zero_reads_back_as_absent() {
        let h = GzipHeader::default();
        let mut out = Vec::new();
        write(&h, b"x", flate2::Compression::none(), &mut out).unwrap();
        assert_eq!(read(&out, u64::MAX, &mut 1).unwrap().0.mtime, None);
    }

    #[test]
    fn detects_a_corrupt_payload() {
        let h = GzipHeader::default();
        let mut out = Vec::new();
        write(&h, b"hello world", flate2::Compression::none(), &mut out).unwrap();
        let n = out.len();
        out[n - 6] ^= 0xff; // corrupt the stored crc
        assert!(read(&out, u64::MAX, &mut 1).is_err());
    }

    #[test]
    fn reads_what_flate2_writes() {
        // Cross-check against another implementation's framing.
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"interoperability").unwrap();
        let bytes = e.finish().unwrap();
        let (_, payload) = read(&bytes, u64::MAX, &mut 1).unwrap();
        assert_eq!(payload, b"interoperability");
    }
}
