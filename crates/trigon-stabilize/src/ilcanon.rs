//! The canonical *functional* form of a managed (.NET) assembly: its methods' names, signatures
//! and IL bodies, and nothing about how the compiler laid the rest of the file out.
//!
//! Two assemblies built from identical source can still differ across ~18% of their bytes without
//! differing in a line of code — [`docs/16-findings.md`](../../../docs/16-findings.md) §3.87 peeled
//! `moq@4.20.72` apart to exactly this: the method IL is byte-for-byte identical, and the whole
//! divergence is the embedded PDB and the metadata *layout* — SourceLink's git URL, the order a
//! source generator's documents landed in, heap offsets that shift when one string upstream is a
//! different length. None of it is code. `dotnet-assembly-identity` zeroes the fixed-location part
//! of that (signature, MVID, timestamps, most of the debug directory), but the layout shifts are
//! scattered and a byte-zeroing pass cannot align them ([B46](../../../docs/17-backlog.md)).
//!
//! So this does not try to align them. It reads the assembly's own tables and emits, per method, a
//! record that names what the method *is* — its name, its signature, its IL — resolved through the
//! heaps to values rather than to the offsets that shifted. Code-identical assemblies produce the
//! same records in the same order; a real code difference (a changed body, a new method, a changed
//! signature) still shows. It is **lossy**: it drops resources, custom attributes, field data and
//! the exact metadata encoding, so a match under it is `normalized_with_caveats`, never `exact`.
//!
//! A record is, in table order: the name, then the signature, each behind its length as a
//! little-endian `u32`; then a byte, `0` for a method with no body read and `1` for one with a
//! body, and the body's IL behind its length. Lengths, not separators, because a signature blob
//! and an IL body may each hold any byte: framed by NUL and newline, a call moved out of a body
//! into the tail of its signature, or a whole method folded into the body before it, read back as
//! the records of the original program.
//!
//! Byte-level, no external tool: the same reason `passes.rs` reads a PE by hand rather than take on
//! a decompiler or a metadata crate the verifier would then have to link and a sceptic re-audit.

// Every offset here is a sum of fields the publisher wrote, and the archived stabilizer set runs
// this code as a wasm32 guest, where `usize` is 32 bits and an overflow traps (release builds keep
// `overflow-checks`). A trap there is an error where the native build returns bytes, so the
// archived set could not re-check the artifact. Hence the checked reads, the differences rather
// than sums in the section lookup, and the offsets past the file clamped or saturated rather than
// wrapped: past the end is past the end, on either width.
fn u16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(o..o.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The two heaps a method record resolves into, plus the sizes that decide how wide every index is.
struct Meta<'a> {
    b: &'a [u8],
    strings: usize, // file offset of the `#Strings` heap
    blob: usize,    // file offset of the `#Blob` heap
    heap_sizes: u8, // bit 1: `#Strings` 4-byte, bit 2: `#GUID` 4-byte, bit 4: `#Blob` 4-byte
    counts: [u32; 64],
}

impl Meta<'_> {
    fn str_w(&self) -> usize {
        if self.heap_sizes & 0x01 != 0 { 4 } else { 2 }
    }
    fn guid_w(&self) -> usize {
        if self.heap_sizes & 0x02 != 0 { 4 } else { 2 }
    }
    fn blob_w(&self) -> usize {
        if self.heap_sizes & 0x04 != 0 { 4 } else { 2 }
    }
    /// A simple index into table `t` is 4 bytes once that table has more rows than a `u16` can name.
    fn idx_w(&self, t: usize) -> usize {
        if self.counts[t] > 0xffff { 4 } else { 2 }
    }
    /// A coded index packs a `tag_bits`-wide table tag below the row number, so it needs 4 bytes
    /// once the largest table it can point at outgrows the space left after the tag.
    fn coded_w(&self, tables: &[usize], tag_bits: u32) -> usize {
        let max = tables.iter().map(|&t| self.counts[t]).max().unwrap_or(0);
        if max as u64 >= (1u64 << (16 - tag_bits)) {
            4
        } else {
            2
        }
    }

    /// The byte width of one row of table `t`. Only the tables that can precede `MethodDef`
    /// (`0x06`) need to be exact, because all this computes is the offset of the `MethodDef` rows;
    /// an unknown table id declines the whole assembly rather than guess a width and desync.
    fn row_size(&self, t: usize) -> Option<usize> {
        let (s, g, bl) = (self.str_w(), self.guid_w(), self.blob_w());
        Some(match t {
            0x00 => 2 + s + 3 * g,                                      // Module
            0x01 => self.coded_w(&[0x00, 0x1a, 0x23, 0x01], 2) + 2 * s, // TypeRef (ResolutionScope)
            0x02 => {
                // TypeDef: Flags, Name, Namespace, Extends(TypeDefOrRef), FieldList, MethodList
                4 + 2 * s
                    + self.coded_w(&[0x02, 0x01, 0x1b], 2)
                    + self.idx_w(0x04)
                    + self.idx_w(0x06)
            }
            0x03 => self.idx_w(0x04), // FieldPtr (only in uncompressed metadata)
            0x04 => 2 + s + bl,       // Field
            0x05 => self.idx_w(0x06), // MethodPtr
            0x06 => 4 + 2 + 2 + s + bl + self.idx_w(0x08), // MethodDef
            _ => return None,
        })
    }

    /// A `#Strings` entry: a NUL-terminated UTF-8 run at `off`.
    fn string_at(&self, off: usize) -> &[u8] {
        let start = self.strings.saturating_add(off);
        let rest = self.b.get(start..).unwrap_or(&[]);
        let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        &rest[..end]
    }

    /// A `#Blob` entry: a compressed-length prefix then that many bytes.
    fn blob_at(&self, off: usize) -> &[u8] {
        let start = self.blob.saturating_add(off);
        let Some(&b0) = self.b.get(start) else {
            return &[];
        };
        let (len, hdr) = if b0 & 0x80 == 0 {
            (b0 as usize, 1)
        } else if b0 & 0x40 == 0 {
            (
                ((b0 as usize & 0x3f) << 8) | self.b.get(start + 1).copied().unwrap_or(0) as usize,
                2,
            )
        } else {
            let x = |i: usize| self.b.get(start + i).copied().unwrap_or(0) as usize;
            (
                ((b0 as usize & 0x1f) << 24) | (x(1) << 16) | (x(2) << 8) | x(3),
                4,
            )
        };
        self.b.get(start + hdr..start + hdr + len).unwrap_or(&[])
    }
}

/// The functional canonical form, or `None` when `b` is not a managed PE this can read whole. A
/// `None` leaves the caller to fall back to the bytes as they are — declining, never guessing.
pub fn canonical_managed(b: &[u8]) -> Option<Vec<u8>> {
    if b.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32(b, 0x3c)? as usize;
    if b.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let num_sections = u16(b, coff + 2)? as usize;
    let opt_size = u16(b, coff + 16)? as usize;
    let opt = coff + 20;
    let dir_off = match u16(b, opt)? {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    let sec = opt + opt_size;
    let rva_to_off = |rva: usize| -> Option<usize> {
        (0..num_sections).find_map(|i| {
            let s = sec + i * 40;
            let vsize = u32(b, s + 8)? as usize;
            let vaddr = u32(b, s + 12)? as usize;
            let praw = u32(b, s + 20)? as usize;
            // `then`, not `then_some`: the offset is only computable once the RVA is known to be
            // in this section, and an eager `rva - vaddr` panics on any RVA below it. An offset
            // past the file is clamped to its end, which every caller reads as nothing there.
            (rva >= vaddr && rva - vaddr < vsize.max(1)).then(|| {
                praw.checked_add(rva - vaddr)
                    .map_or(b.len(), |o| o.min(b.len()))
            })
        })
    };

    // CLI header (data dir 14) → metadata root.
    let cli_rva = u32(b, dir_off + 14 * 8)? as usize;
    if cli_rva == 0 {
        return None;
    }
    let cli = rva_to_off(cli_rva)?;
    let md = rva_to_off(u32(b, cli + 8)? as usize)?;
    if b.get(md..md + 4)? != [0x42, 0x53, 0x4a, 0x42] {
        return None; // `BSJB`
    }

    // Stream directory: past the version string, a flags/count pair, then the stream headers.
    let ver_len = u32(b, md + 12)? as usize;
    let after_ver = (md + 16).checked_add(ver_len.checked_add(3)? & !3)?;
    let n_streams = u16(b, after_ver.checked_add(2)?)? as usize;
    let (mut tables_off, mut strings_off, mut blob_off) = (None, None, None);
    let mut q = after_ver + 4;
    for _ in 0..n_streams {
        let s_off = u32(b, q)? as usize;
        let name_start = q + 8;
        let name_end = name_start + b.get(name_start..)?.iter().position(|&c| c == 0)?;
        let name = b.get(name_start..name_end)?;
        match name {
            b"#~" | b"#-" => tables_off = Some(md.saturating_add(s_off)),
            b"#Strings" => strings_off = Some(md.saturating_add(s_off)),
            b"#Blob" => blob_off = Some(md.saturating_add(s_off)),
            _ => {}
        }
        // Name is padded to a 4-byte boundary, counting its own terminator.
        q = name_start + (((name_end - name_start + 1) + 3) & !3);
    }
    let (tables, strings, blob) = (tables_off?, strings_off?, blob_off?);

    // `#~` header: HeapSizes at +6, the `Valid` bitmask at +8, then a row count per present table.
    let heap_sizes = *b.get(tables.checked_add(6)?)?;
    let valid = u64::from_le_bytes(b.get(tables + 8..tables + 16)?.try_into().ok()?);
    let mut counts = [0u32; 64];
    let mut p = tables + 24; // after reserved/version/heapsizes/reserved/valid/sorted
    for (t, slot) in counts.iter_mut().enumerate() {
        if valid & (1 << t) != 0 {
            *slot = u32(b, p)?;
            p += 4;
        }
    }
    let meta = Meta {
        b,
        strings,
        blob,
        heap_sizes,
        counts,
    };

    // `p` now points at the first table's rows. Walk forward to `MethodDef` (0x06).
    let mut row = p;
    for (t, &c) in counts.iter().enumerate().take(0x06) {
        if valid & (1 << t) != 0 {
            row = row.saturating_add(meta.row_size(t)?.saturating_mul(c as usize));
        }
    }
    if valid & (1 << 0x06) == 0 {
        return Some(Vec::new()); // no methods: an empty-but-valid canonical form
    }
    let method_row = meta.row_size(0x06)?;
    let (s, bl) = (meta.str_w(), meta.blob_w());

    // The row count is the file's own claim, so it sizes nothing the file cannot back: trusted as
    // a capacity, a count of `u32::MAX` asked for ~100 GB and aborted before a row was read.
    let mut out = Vec::with_capacity((counts[0x06] as usize).saturating_mul(24).min(b.len()));
    // Every row may name the same heap entry or body, so the records can repeat one long string
    // once per row — rows × file, not file: 258 KB crafted that way expanded to 524 MB. A genuine
    // assembly's form is a fraction of the file, which holds each name, signature and body beside
    // everything the form drops, so a form several times the file is not code this can honestly
    // reduce. Declined, and the bytes are compared as they are.
    let limit = b.len().saturating_mul(MAX_EXPANSION);
    for i in 0..counts[0x06] as usize {
        let r = row + i * method_row;
        let rva = u32(b, r)? as usize;
        // RVA, ImplFlags(2), Flags(2), then Name(#Strings) and Signature(#Blob).
        let name_off = read_idx(b, r + 8, s)?;
        let sig_off = read_idx(b, r + 8 + s, bl)?;

        put_field(&mut out, meta.string_at(name_off))?;
        put_field(&mut out, meta.blob_at(sig_off))?;
        match method_il(b, &rva_to_off, rva) {
            Some(il) => {
                out.push(1);
                put_field(&mut out, il)?;
            }
            None => out.push(0),
        }
        if out.len() > limit {
            return None;
        }
    }
    Some(out)
}

/// How many times its own size an assembly's canonical form may reach before it is declined.
const MAX_EXPANSION: usize = 4;

/// One field of a record: its length as a little-endian `u32`, then its bytes. A field too long for
/// the length to name declines the assembly rather than write a length that is not the field's.
fn put_field(out: &mut Vec<u8>, field: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(field.len()).ok()?.to_le_bytes());
    out.extend_from_slice(field);
    Some(())
}

/// A heap index is 2 or 4 bytes wide, per the heap-size flags.
fn read_idx(b: &[u8], o: usize, width: usize) -> Option<usize> {
    Some(if width == 4 {
        u32(b, o)? as usize
    } else {
        u16(b, o)? as usize
    })
}

/// The IL of a method body at `rva`, or `None` for an abstract/`extern`/pinvoke method (`rva == 0`)
/// or an unreadable header. A tiny header is one byte carrying the code size in its top six bits; a
/// fat header is twelve bytes with the size at offset 4.
fn method_il<'a>(
    b: &'a [u8],
    rva_to_off: &impl Fn(usize) -> Option<usize>,
    rva: usize,
) -> Option<&'a [u8]> {
    if rva == 0 {
        return None;
    }
    let off = rva_to_off(rva)?;
    let b0 = *b.get(off)?;
    let (start, size) = match b0 & 0x03 {
        0x02 => (off + 1, (b0 >> 2) as usize), // CorILMethod_TinyFormat
        0x03 => (off + 12, u32(b, off + 4)? as usize), // CorILMethod_FatFormat
        _ => return None,
    };
    b.get(start..start.checked_add(size)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_managed_input_is_declined() {
        assert!(canonical_managed(b"not a PE").is_none());
        assert!(canonical_managed(&[]).is_none());
        assert!(canonical_managed(b"MZ").is_none());
    }

    /// Gated on two real assemblies: point them at a published managed DLL and its rebuild. The
    /// canonical form is equal when the two differ only in metadata/debug layout — the case
    /// `dotnet-assembly-identity` cannot reach. `TRIGON_DOTNET_A`/`_B`, as the sibling test uses.
    #[test]
    fn code_identical_assemblies_share_a_canonical_form() {
        let (Ok(pa), Ok(pb)) = (
            std::env::var("TRIGON_DOTNET_A"),
            std::env::var("TRIGON_DOTNET_B"),
        ) else {
            eprintln!("skipped: set TRIGON_DOTNET_A and TRIGON_DOTNET_B to two assemblies");
            return;
        };
        let a = std::fs::read(pa).unwrap();
        let b = std::fs::read(pb).unwrap();
        let ca = canonical_managed(&a).expect("A is a managed assembly");
        let cb = canonical_managed(&b).expect("B is a managed assembly");
        eprintln!(
            "raw differing bytes: {}; canonical len A={} B={}; canonical equal: {}",
            a.iter().zip(&b).filter(|(x, y)| x != y).count(),
            ca.len(),
            cb.len(),
            ca == cb
        );
        assert_eq!(ca, cb, "canonical forms differ");
    }
}
