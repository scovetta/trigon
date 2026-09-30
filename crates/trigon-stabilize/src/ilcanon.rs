//! The canonical *functional* form of a managed (.NET) assembly: its methods, every row and
//! literal their IL and signatures can name, and the declarations that decide how they run, and
//! nothing about how the compiler laid the rest of the file out.
//!
//! Two assemblies built from identical source can still differ across ~18% of their bytes without
//! differing in a line of code — [`docs/16-findings.md`](../../../docs/16-findings.md) §3.87 peeled
//! `moq@4.20.72` apart to exactly this: the method IL is byte-for-byte identical, and the whole
//! divergence is the embedded PDB and the metadata *layout* — SourceLink's git URL, the order a
//! source generator's documents landed in, heap offsets that shift when one string upstream is a
//! different length. None of it is code. `dotnet-assembly-identity-v2` zeroes the fixed-location
//! part of that (signature, MVID, timestamps, the debug directory's data), but the layout shifts
//! are scattered and a byte-zeroing pass cannot align them ([B46](../../../docs/17-backlog.md)).
//!
//! So this does not try to align them. It reads the assembly's own tables and emits what the code
//! *is*, resolved through the heaps to values rather than to the offsets that shifted. Per method:
//! its name, signature, flags, first parameter row and whole body — header, IL, and the
//! exception-handling sections after the IL. Then, row by row, every table an IL token or a
//! signature can name — TypeRef, TypeDef, Field, MemberRef, StandAloneSig, ModuleRef, TypeSpec,
//! MethodSpec — with the AssemblyRef rows a TypeRef resolves in; the declarations that change what
//! the code does when it runs though no token names them — parameters, constants and marshalling,
//! the interfaces a type implements (InterfaceImpl), explicit overrides (MethodImpl), P/Invoke
//! entry points (ImplMap), type and field layout, nesting, generic parameters and their
//! constraints, properties and events and the methods behind them, type forwarders; and, in the
//! uncompressed layout, the pointer tables that decide which type or method owns which row. Then
//! the `#US` heap `ldstr` reads its literals from, whole. A token is a row number or a `#US`
//! offset, and whatever it names is in the form at that position, so a body calling another
//! method, catching another type or loading another literal under the same token still differs.
//! Code-identical assemblies produce the same form; a real code difference (a changed body, flag,
//! reference or literal, a new method, a changed signature, another P/Invoke target, override or
//! interface) still shows. Everything is read where the runtime reads it: from the bytes the file
//! backs of the section an address falls in, never from the file bytes past them, which the loader
//! replaces with zeros. A method whose body is native code, as a mixed-mode assembly's C++ is,
//! declines the assembly: that body is not IL, and nothing here can say what it does. So does an
//! image whose CLI header says it carries native code anywhere (ILONLY clear, a native entry point,
//! ReadyToRun's precompiled methods), whether or not a method names it.
//!
//! It is **lossy**: it drops resources, custom attributes and security declarations, the data a
//! field is initialized from (FieldRVA, such as a static array's initial bytes), the Module and
//! Assembly rows, and the exact metadata encoding. A difference only there does not show, so a
//! match under it is `normalized_with_caveats`, never `exact`.
//!
//! The form, every length and number little-endian: `0x06`, the MethodDef row count as a `u32`,
//! and a record per method in table order — the name, then the signature, each behind its length
//! as a `u32`; ImplFlags and Flags as the row holds them; its ParamList as a `u32`; then a byte,
//! `0` for a method with no body and `1` for one with a body, and the body's header, IL and
//! sections, each behind its length. Then each kept table in id order: its id as a byte, its row
//! count as a `u32`, and each row column by column — a heap index as the string or blob it names
//! behind its length, a table or coded index as a `u32`, anything else as the integer it is. Last,
//! `0x70`, the token type of a literal, and the `#US` heap behind its length. Lengths, not
//! separators, because a signature blob and an IL body may each hold any byte: framed by NUL and
//! newline, a call moved out of a body into the tail of its signature, or a whole method folded
//! into the body before it, read back as the records of the original program.
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

#[cfg(test)]
thread_local! {
    /// Each section header read and each probe of the section index, so a test can hold the lookup
    /// to its cost by counting rather than by timing it.
    static SECTION_VISITS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn visited() {
    #[cfg(test)]
    SECTION_VISITS.with(|v| v.set(v.get() + 1));
}

/// A section as an RVA lookup needs it: where it is mapped, how much address space it covers, and
/// where its bytes start in the file and how many of them the file backs.
#[derive(Clone, Copy)]
struct Section {
    vaddr: usize,
    /// `VirtualSize`, and at least one byte: a section of size zero still maps its first address.
    extent: usize,
    raw: usize,
    /// `VirtualSize` or `SizeOfRawData`, whichever is less: the loader maps that many bytes from
    /// the file and fills the rest of the section with zeros.
    backed: usize,
}

/// The section table, read once and sorted by address, so every RVA an assembly names — one per
/// method — is placed by binary search rather than by a scan of up to 65,535 headers.
///
/// Scanned per lookup, as it was, a crafted `NumberOfSections` and a method table pointing past
/// all but the last section cost methods × sections: seconds for half a megabyte, minutes for
/// sixteen, in a verifier and in the archived wasm set, which has no fuel limit.
struct Sections {
    by_address: Vec<Section>,
}

impl Sections {
    /// The `count` headers at `table`, as far as the file holds them: a header past its end maps
    /// nothing, as it never did. `None` when two sections claim one address — the loader lays
    /// sections out in ascending, disjoint order, and which of two a lookup found would otherwise
    /// depend on the order the headers happen to be listed in.
    fn read(b: &[u8], table: usize, count: usize) -> Option<Sections> {
        let mut by_address = Vec::with_capacity(count.min(b.len() / 40));
        for i in 0..count {
            visited();
            let Some(s) = i.checked_mul(40).and_then(|o| table.checked_add(o)) else {
                break;
            };
            let (Some(vsize), Some(vaddr), Some(raw_size), Some(raw)) = (
                s.checked_add(8).and_then(|o| u32(b, o)),
                s.checked_add(12).and_then(|o| u32(b, o)),
                s.checked_add(16).and_then(|o| u32(b, o)),
                s.checked_add(20).and_then(|o| u32(b, o)),
            ) else {
                break;
            };
            by_address.push(Section {
                vaddr: vaddr as usize,
                extent: (vsize as usize).max(1),
                raw: raw as usize,
                backed: vsize.min(raw_size) as usize,
            });
        }
        by_address.sort_by_key(|s| s.vaddr);
        // Differences, not sums: `vaddr + extent` passes `u32::MAX` for a section near the top of
        // the address space, which is an overflow on the wasm32 guest.
        if by_address
            .windows(2)
            .any(|w| w[1].vaddr - w[0].vaddr < w[0].extent)
        {
            return None;
        }
        Some(Sections { by_address })
    }

    /// The bytes of `b` the runtime sees from `rva` on, to the end of what the file backs of the
    /// section that maps it, or `None` for an address no section maps. Empty when `rva` is past
    /// what the file backs, or past the file.
    ///
    /// Past what the file backs, the loader maps zeros, whatever bytes the file happens to hold
    /// next. Read from the file instead, a body or heap placed across that line said one thing to
    /// this form and another to the runtime, and two assemblies differing only in `SizeOfRawData`
    /// shared a form while running different code. So nothing is read past it: whatever runs off
    /// the end of these bytes declines the assembly, or, for a string, ends it where the zeros do.
    fn bytes<'a>(&self, b: &'a [u8], rva: usize) -> Option<&'a [u8]> {
        let (start, end) = self.span(b.len(), rva)?;
        b.get(start..end)
    }

    /// Where [`Sections::bytes`] lies in a file of `len` bytes: the file offset of `rva`, and the
    /// end of what the file backs of the section that maps it.
    fn span(&self, len: usize, rva: usize) -> Option<(usize, usize)> {
        // The last section starting at or below `rva` is the only one that can hold it.
        let i = self.by_address.partition_point(|s| {
            visited();
            s.vaddr <= rva
        });
        let s = self.by_address.get(i.checked_sub(1)?)?;
        // `rva >= s.vaddr` by the search, so the difference cannot fall below zero.
        let into = rva - s.vaddr;
        if into >= s.extent {
            return None;
        }
        // Saturated rather than wrapped, and clamped to the file: past the end is past the end.
        let start = s.raw.saturating_add(into).min(len);
        let end = s.raw.saturating_add(s.backed).min(len);
        Some((start, end.max(start)))
    }
}

/// One column of a metadata table, as ECMA-335 §II.22 lays it out.
#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    /// A simple index into the table named.
    Idx(usize),
    /// A coded index over the tables listed, in tag order, with a tag this many bits wide
    /// (§II.24.2.6). A tag the standard leaves unused names no table, so it is not listed.
    Coded(&'static [usize], u32),
}

const TYPE_DEF_OR_REF: &[usize] = &[0x02, 0x01, 0x1b];
const HAS_CONSTANT: &[usize] = &[0x04, 0x08, 0x17];
const HAS_CUSTOM_ATTRIBUTE: &[usize] = &[
    0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23,
    0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b,
];
const HAS_FIELD_MARSHAL: &[usize] = &[0x04, 0x08];
const HAS_DECL_SECURITY: &[usize] = &[0x02, 0x06, 0x20];
const MEMBER_REF_PARENT: &[usize] = &[0x02, 0x01, 0x1a, 0x06, 0x1b];
const HAS_SEMANTICS: &[usize] = &[0x14, 0x17];
const METHOD_DEF_OR_REF: &[usize] = &[0x06, 0x0a];
const MEMBER_FORWARDED: &[usize] = &[0x04, 0x06];
const IMPLEMENTATION: &[usize] = &[0x26, 0x23, 0x27];
const CUSTOM_ATTRIBUTE_TYPE: &[usize] = &[0x06, 0x0a];
const RESOLUTION_SCOPE: &[usize] = &[0x00, 0x1a, 0x23, 0x01];
const TYPE_OR_METHOD_DEF: &[usize] = &[0x02, 0x06];

/// Every table ECMA-335 defines, by id, as its columns. Each table before the last one the form
/// keeps is stepped over to reach the next, so each has to be exact: a width guessed wrong reads
/// every later row from the wrong bytes. An id past these names no table, and none precedes one
/// the form reads.
fn columns(t: usize) -> Option<&'static [Col]> {
    use Col::*;
    Some(match t {
        // Module: Generation, Name, Mvid, EncId, EncBaseId
        0x00 => &[U16, Str, Guid, Guid, Guid],
        // TypeRef: ResolutionScope, TypeName, TypeNamespace
        0x01 => &[Coded(RESOLUTION_SCOPE, 2), Str, Str],
        // TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList
        0x02 => &[
            U32,
            Str,
            Str,
            Coded(TYPE_DEF_OR_REF, 2),
            Idx(0x04),
            Idx(0x06),
        ],
        // FieldPtr, only in uncompressed metadata
        0x03 => &[Idx(0x04)],
        // Field: Flags, Name, Signature
        0x04 => &[U16, Str, Blob],
        // MethodPtr
        0x05 => &[Idx(0x06)],
        // MethodDef: RVA, ImplFlags, Flags, Name, Signature, ParamList
        0x06 => &[U32, U16, U16, Str, Blob, Idx(0x08)],
        // ParamPtr
        0x07 => &[Idx(0x08)],
        // Param: Flags, Sequence, Name
        0x08 => &[U16, U16, Str],
        // InterfaceImpl: Class, Interface
        0x09 => &[Idx(0x02), Coded(TYPE_DEF_OR_REF, 2)],
        // MemberRef: Class, Name, Signature
        0x0a => &[Coded(MEMBER_REF_PARENT, 3), Str, Blob],
        // Constant: Type and a padding byte, Parent, Value
        0x0b => &[U16, Coded(HAS_CONSTANT, 2), Blob],
        // CustomAttribute: Parent, Type, Value
        0x0c => &[
            Coded(HAS_CUSTOM_ATTRIBUTE, 5),
            Coded(CUSTOM_ATTRIBUTE_TYPE, 3),
            Blob,
        ],
        // FieldMarshal: Parent, NativeType
        0x0d => &[Coded(HAS_FIELD_MARSHAL, 1), Blob],
        // DeclSecurity: Action, Parent, PermissionSet
        0x0e => &[U16, Coded(HAS_DECL_SECURITY, 2), Blob],
        // ClassLayout: PackingSize, ClassSize, Parent
        0x0f => &[U16, U32, Idx(0x02)],
        // FieldLayout: Offset, Field
        0x10 => &[U32, Idx(0x04)],
        // StandAloneSig: Signature
        0x11 => &[Blob],
        // EventMap: Parent, EventList
        0x12 => &[Idx(0x02), Idx(0x14)],
        // EventPtr
        0x13 => &[Idx(0x14)],
        // Event: EventFlags, Name, EventType
        0x14 => &[U16, Str, Coded(TYPE_DEF_OR_REF, 2)],
        // PropertyMap: Parent, PropertyList
        0x15 => &[Idx(0x02), Idx(0x17)],
        // PropertyPtr
        0x16 => &[Idx(0x17)],
        // Property: Flags, Name, Type
        0x17 => &[U16, Str, Blob],
        // MethodSemantics: Semantics, Method, Association
        0x18 => &[U16, Idx(0x06), Coded(HAS_SEMANTICS, 1)],
        // MethodImpl: Class, MethodBody, MethodDeclaration
        0x19 => &[
            Idx(0x02),
            Coded(METHOD_DEF_OR_REF, 1),
            Coded(METHOD_DEF_OR_REF, 1),
        ],
        // ModuleRef: Name
        0x1a => &[Str],
        // TypeSpec: Signature
        0x1b => &[Blob],
        // ImplMap: MappingFlags, MemberForwarded, ImportName, ImportScope
        0x1c => &[U16, Coded(MEMBER_FORWARDED, 1), Str, Idx(0x1a)],
        // FieldRVA: RVA, Field
        0x1d => &[U32, Idx(0x04)],
        // EncLog: Token, FuncCode
        0x1e => &[U32, U32],
        // EncMap: Token
        0x1f => &[U32],
        // Assembly: HashAlgId, the four-part version, Flags, PublicKey, Name, Culture
        0x20 => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
        // AssemblyProcessor
        0x21 => &[U32],
        // AssemblyOS
        0x22 => &[U32, U32, U32],
        // AssemblyRef: the four-part version, Flags, PublicKeyOrToken, Name, Culture, HashValue
        0x23 => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
        // AssemblyRefProcessor
        0x24 => &[U32, Idx(0x23)],
        // AssemblyRefOS
        0x25 => &[U32, U32, U32, Idx(0x23)],
        // File: Flags, Name, HashValue
        0x26 => &[U32, Str, Blob],
        // ExportedType: Flags, TypeDefId, TypeName, TypeNamespace, Implementation
        0x27 => &[U32, U32, Str, Str, Coded(IMPLEMENTATION, 2)],
        // ManifestResource: Offset, Flags, Name, Implementation
        0x28 => &[U32, U32, Str, Coded(IMPLEMENTATION, 2)],
        // NestedClass: NestedClass, EnclosingClass
        0x29 => &[Idx(0x02), Idx(0x02)],
        // GenericParam: Number, Flags, Owner, Name
        0x2a => &[U16, U16, Coded(TYPE_OR_METHOD_DEF, 1), Str],
        // MethodSpec: Method, Instantiation
        0x2b => &[Coded(METHOD_DEF_OR_REF, 1), Blob],
        // GenericParamConstraint: Owner, Constraint
        0x2c => &[Idx(0x2a), Coded(TYPE_DEF_OR_REF, 2)],
        _ => return None,
    })
}

/// The tables the form keeps after the methods, in the order it writes them: everything an IL
/// token or a signature can name, and the AssemblyRef rows a TypeRef resolves in; the declarations
/// that decide what the code does when it runs — parameters and their defaults and marshalling,
/// implemented interfaces, explicit overrides, P/Invoke targets, type layout, nesting, generic
/// parameters and their constraints, properties and events and the methods behind them, type
/// forwarders; and the pointer tables through which, in the uncompressed layout, a type's fields,
/// methods, properties and events and a method's parameters run.
///
/// Not kept: Module and Assembly (a build's own identity), CustomAttribute and DeclSecurity,
/// FieldRVA (its RVA moves with the layout, and the data it names is not read), the File and
/// ManifestResource rows of the resources the form drops, and the edit-and-continue and
/// processor/OS tables, which no compiler still writes.
const KEPT: [usize; 31] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0d, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x23, 0x27, 0x29, 0x2a, 0x2b, 0x2c,
];

/// The last table whose rows the form reads.
const LAST_KEPT: usize = 0x2c;

/// The two heaps a row resolves into, plus the sizes that decide how wide every index is.
struct Meta<'a> {
    b: &'a [u8],
    strings: usize, // file offset of the `#Strings` heap
    blob: usize,    // file offset of the `#Blob` heap
    heap_sizes: u8, // bit 1: `#Strings` 4-byte, bit 2: `#GUID` 4-byte, bit 4: `#Blob` 4-byte
    counts: [u32; 64],
}

impl Meta<'_> {
    /// How many bytes a column takes in a row.
    fn width(&self, c: Col) -> usize {
        let wide = |bit: u8| if self.heap_sizes & bit != 0 { 4 } else { 2 };
        match c {
            Col::U16 => 2,
            Col::U32 => 4,
            Col::Str => wide(0x01),
            Col::Guid => wide(0x02),
            Col::Blob => wide(0x04),
            // A simple index is 4 bytes once its table has more rows than a `u16` can name.
            Col::Idx(t) => {
                if self.counts[t] > 0xffff {
                    4
                } else {
                    2
                }
            }
            // A coded index packs a tag below the row number, so it needs 4 bytes once the largest
            // table it can point at outgrows the space left after the tag.
            Col::Coded(tables, tag_bits) => {
                let max = tables.iter().map(|&t| self.counts[t]).max().unwrap_or(0);
                if max as u64 >= (1u64 << (16 - tag_bits)) {
                    4
                } else {
                    2
                }
            }
        }
    }

    /// The byte width of one row of table `t`.
    fn row_size(&self, t: usize) -> Option<usize> {
        Some(columns(t)?.iter().map(|&c| self.width(c)).sum())
    }

    /// A `#Strings` entry: a NUL-terminated UTF-8 run at `off`. One running off the end of the
    /// metadata's bytes ends there, where the runtime reads the zeros the loader mapped.
    fn string_at(&self, off: usize) -> &[u8] {
        let start = self.strings.saturating_add(off);
        let rest = self.b.get(start..).unwrap_or(&[]);
        let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        &rest[..end]
    }

    /// A `#Blob` entry: a compressed-length prefix then that many bytes, or `None` for one that
    /// runs off the end of the metadata's bytes. Cut short there, what the runtime reads is those
    /// bytes and then zeros, and an empty field in their place would be the form of every blob cut
    /// at that point, whatever its first bytes said.
    fn blob_at(&self, off: usize) -> Option<&[u8]> {
        let start = self.blob.saturating_add(off);
        let x = |i: usize| Some(*self.b.get(start.checked_add(i)?)? as usize);
        let b0 = x(0)?;
        let (len, hdr) = if b0 & 0x80 == 0 {
            (b0, 1)
        } else if b0 & 0x40 == 0 {
            (((b0 & 0x3f) << 8) | x(1)?, 2)
        } else {
            (
                ((b0 & 0x1f) << 24) | (x(1)? << 16) | (x(2)? << 8) | x(3)?,
                4,
            )
        };
        // The prefix was read, so `start + hdr` is at most the end of the metadata; `len` is the
        // publisher's, and checked.
        self.b.get(start + hdr..(start + hdr).checked_add(len)?)
    }
}

/// A managed assembly walked from its PE headers to the first row of every table: what both the
/// canonical form and [`occupied`] read, so the two cannot disagree about where anything is.
struct Walked<'a> {
    sections: Sections,
    /// The optional header, where its data directories start, and whether it is PE32+'s.
    opt: usize,
    dir_off: usize,
    pe32_plus: bool,
    /// Where the section table ends.
    table_end: usize,
    /// The CLI header, from its first byte to the end of what the file backs of its section, and
    /// the file offset it starts at.
    cli: &'a [u8],
    cli_at: usize,
    /// The metadata, from its root to the end of what the file backs of its section, and the file
    /// offset the root is at.
    m: &'a [u8],
    m_at: usize,
    /// Where the stream directory ends, from the root: the signature, the version string and a
    /// header per stream lie before it, and say where every table and heap is.
    dir_end: usize,
    /// Each stream the directory lists, in its order: the name, and the offset from the root and
    /// the size the directory states.
    streams: Vec<(&'a [u8], usize, usize)>,
    /// Where the table stream starts, from the root.
    tables: usize,
    user_strings: &'a [u8],
    meta: Meta<'a>,
    valid: u64,
    /// Where each table's rows start, from the root, through the last table the form keeps.
    at: [usize; LAST_KEPT + 1],
    /// Where the rows of the last of those tables end, from the root.
    rows_end: usize,
}

/// `b` walked to its tables, or `None` when it is not a managed PE whose headers, streams and
/// rows this can place.
fn walk(b: &[u8]) -> Option<Walked<'_>> {
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
    let (dir_off, pe32_plus) = match u16(b, opt)? {
        0x10b => (opt + 96, false),
        0x20b => (opt + 112, true),
        _ => return None,
    };
    let sections = Sections::read(b, opt + opt_size, num_sections)?;

    // CLI header (data dir 14) → metadata root.
    let cli_rva = u32(b, dir_off + 14 * 8)? as usize;
    if cli_rva == 0 {
        return None;
    }
    let (cli_at, cli_end) = sections.span(b.len(), cli_rva)?;
    let cli = b.get(cli_at..cli_end)?;
    // Everything the metadata holds is read from the bytes its section backs, from the root on:
    // each stream's offset is the root's own, and a row or heap entry past those bytes is one the
    // runtime reads as zeros.
    let (m_at, m_end) = sections.span(b.len(), u32(cli, 8)? as usize)?;
    let m = b.get(m_at..m_end)?;
    if m.get(0..4)? != [0x42, 0x53, 0x4a, 0x42] {
        return None; // `BSJB`
    }

    // Stream directory: past the version string, a flags/count pair, then the stream headers.
    let ver_len = u32(m, 12)? as usize;
    let after_ver = 16usize.checked_add(ver_len.checked_add(3)? & !3)?;
    let n_streams = u16(m, after_ver.checked_add(2)?)? as usize;
    let mut streams = Vec::new();
    let (mut tables_off, mut strings_off, mut blob_off, mut us_at) = (None, None, None, None);
    let mut q = after_ver + 4;
    for _ in 0..n_streams {
        let s_off = u32(m, q)? as usize;
        let s_size = u32(m, q + 4)? as usize;
        let name_start = q + 8;
        let name_end = name_start + m.get(name_start..)?.iter().position(|&c| c == 0)?;
        let name = m.get(name_start..name_end)?;
        match name {
            b"#~" | b"#-" => tables_off = Some(s_off),
            b"#Strings" => strings_off = Some(s_off),
            b"#Blob" => blob_off = Some(s_off),
            b"#US" => us_at = Some((s_off, s_size)),
            _ => {}
        }
        streams.push((name, s_off, s_size));
        // Name is padded to a 4-byte boundary, counting its own terminator.
        q = name_start + (((name_end - name_start + 1) + 3) & !3);
    }
    let (tables, strings, blob) = (tables_off?, strings_off?, blob_off?);
    // An assembly with no string literal need not carry `#US` at all. One that does is read
    // whole, because every `ldstr` in it reads from there.
    let user_strings = match us_at {
        Some((at, len)) => m.get(at..at.checked_add(len)?)?,
        None => &[],
    };

    // `#~` header: HeapSizes at +6, the `Valid` bitmask at +8, then a row count per present table.
    let heap_sizes = *m.get(tables.checked_add(6)?)?;
    let valid = u64::from_le_bytes(m.get(tables + 8..tables + 16)?.try_into().ok()?);
    let mut counts = [0u32; 64];
    let mut p = tables + 24; // after reserved/version/heapsizes/reserved/valid/sorted
    for (t, slot) in counts.iter_mut().enumerate() {
        if valid & (1 << t) != 0 {
            *slot = u32(m, p)?;
            p += 4;
        }
    }
    let meta = Meta {
        b: m,
        strings,
        blob,
        heap_sizes,
        counts,
    };

    // `p` now points at the first table's rows. Walk forward to where each table's rows start,
    // through the last table the form keeps.
    let mut at = [0usize; LAST_KEPT + 1];
    let mut end = p;
    for (t, start) in at.iter_mut().enumerate() {
        *start = end;
        if valid & (1 << t) != 0 {
            end = end.saturating_add(meta.row_size(t)?.saturating_mul(counts[t] as usize));
        }
    }
    // The row counts are the file's own claim, so they size nothing the file cannot back: rows
    // it does not hold decline the assembly here, before one is read. Trusted as a capacity, a
    // MethodDef count of `u32::MAX` once asked for ~100 GB and aborted before a row was read.
    if end > m.len() {
        return None;
    }
    Some(Walked {
        sections,
        opt,
        dir_off,
        pe32_plus,
        table_end: (opt + opt_size).saturating_add(num_sections.saturating_mul(40)),
        cli,
        cli_at,
        m,
        m_at,
        dir_end: q,
        streams,
        tables,
        user_strings,
        meta,
        valid,
        at,
        rows_end: end,
    })
}

/// Whether the CLI header says the image carries native code, which the runtime runs and which no
/// table states the extent of: ILONLY clear (a mixed-mode C++/CLI image), a native entry point (a
/// `DllMain` the loader calls, named by an RVA where a managed image names a method), or a
/// ManagedNativeHeader (ReadyToRun's precompiled methods, which the runtime runs in place of their
/// IL).
fn carries_native_code(cli: &[u8]) -> Option<bool> {
    const ILONLY: u32 = 0x01;
    const NATIVE_ENTRYPOINT: u32 = 0x10;
    let flags = u32(cli, 16)?;
    Some(
        flags & ILONLY == 0
            || flags & NATIVE_ENTRYPOINT != 0
            || u32(cli, 64)? != 0
            || u32(cli, 68)? != 0,
    )
}

/// The functional canonical form, or `None` when `b` is not a managed PE this can read whole. A
/// `None` leaves the caller to fall back to the bytes as they are — declining, never guessing.
///
/// An image carrying native code is declined whole, not only a method whose body is native. A
/// ReadyToRun image's IL is what the runtime falls back to, and the precompiled code beside it is
/// what it runs first; a mixed-mode image's native entry point runs at load. Neither is in the
/// form, so two images of the same IL and different native code shared one and matched
/// (`docs/16-findings.md` §3.106).
pub fn canonical_managed(b: &[u8]) -> Option<Vec<u8>> {
    let w = walk(b)?;
    if carries_native_code(w.cli)? {
        return None;
    }
    let (m, meta, counts, at) = (w.m, &w.meta, &w.meta.counts, &w.at);

    // Every row may name the same heap entry or body, so the records can repeat one long string
    // once per row — rows × file, not file: 258 KB crafted that way expanded to 524 MB. A genuine
    // assembly's form is a small multiple of the file, which holds each name, signature and body
    // beside everything the form drops, so a form several times the file is not code this can
    // honestly reduce. Declined, and the bytes are compared as they are.
    let limit = b.len().saturating_mul(MAX_EXPANSION);
    let mut out = Vec::with_capacity(b.len());

    let method_row = meta.row_size(0x06)?;
    let (s, bl) = (meta.width(Col::Str), meta.width(Col::Blob));
    let param = meta.width(Col::Idx(0x08));
    out.push(0x06);
    out.extend_from_slice(&counts[0x06].to_le_bytes());
    for i in 0..counts[0x06] as usize {
        let r = at[0x06] + i * method_row;
        // RVA, ImplFlags(2), Flags(2), Name(#Strings), Signature(#Blob), then ParamList.
        let rva = u32(m, r)? as usize;
        let name_off = read_idx(m, r + 8, s)?;
        let sig_off = read_idx(m, r + 8 + s, bl)?;
        let params = read_idx(m, r + 8 + s + bl, param)?;

        let flags = m.get(r + 4..r + 8)?;
        // ImplFlags' code type, `0` for IL. The body of a native method — a mixed-mode
        // assembly's C++ — is machine code the runtime runs as it stands, and read as IL it is
        // a guess at a program nothing runs, however much of it happens to parse as a header.
        if rva != 0 && flags[0] & 0x03 != 0 {
            return None;
        }

        put_field(&mut out, meta.string_at(name_off))?;
        put_field(&mut out, meta.blob_at(sig_off)?)?;
        out.extend_from_slice(flags);
        // The first of its Param rows, which are kept: which parameters are whose.
        out.extend_from_slice(&u32::try_from(params).ok()?.to_le_bytes());
        match method_body(b, &w.sections, rva)? {
            Some(body) => {
                out.push(1);
                put_field(&mut out, body.header)?;
                put_field(&mut out, body.il)?;
                let len: usize = body.sections.iter().map(|x| x.len()).sum();
                out.extend_from_slice(&u32::try_from(len).ok()?.to_le_bytes());
                for x in body.sections {
                    out.extend_from_slice(x);
                }
            }
            None => out.push(0),
        }
        if out.len() > limit {
            return None;
        }
    }
    for t in KEPT {
        put_table(&mut out, meta, t, at[t], limit)?;
    }
    out.push(0x70);
    put_field(&mut out, w.user_strings)?;
    (out.len() <= limit).then_some(out)
}

/// Where a managed assembly's content lies in its file, for `dotnet-assembly-identity-v2`, which
/// zeroes the build identity around it and has to show that nothing it zeroes is content.
///
/// Content is every byte the code and metadata are read from — the CLI header, the metadata root,
/// its stream directory and every stream but `#GUID`, every table's rows, every method body with
/// its exception sections — and every other structure the headers name: managed resources, the
/// data fields are initialized from (FieldRVA), the CLI header's other directories and the slots
/// its VTable fixups name, each PE data directory but the debug directory, what the import and
/// resource directories point at (the imported DLL and function names, the lookup and address
/// tables, each resource's name, data entry and data), and the entry point's startup stub. Each is
/// found where the runtime reads it, through the section that maps its address or, below
/// `SizeOfHeaders`, through the headers. `#GUID` is left out because the pass zeroes it, and
/// nothing but a GUID column reads it once every index stays in its own heap.
pub(crate) struct Occupied {
    /// File ranges, sorted by start, merged, and inside the file.
    ranges: Vec<(usize, usize)>,
    /// The `#GUID` heap, wholly in the file, or `None` for an assembly without one.
    pub(crate) guid: Option<(usize, usize)>,
    /// Where the headers end: the DOS and PE headers and the section table, or `SizeOfHeaders` if
    /// that is further.
    pub(crate) headers_end: usize,
    /// The file offset of the CLI header.
    pub(crate) cli: usize,
    sections: Sections,
}

impl Occupied {
    /// The file offset of the `n` bytes at `rva` in a file of `len` bytes, when the file backs
    /// every one of them.
    pub(crate) fn file_range(&self, len: usize, rva: usize, n: usize) -> Option<usize> {
        let (start, end) = self.sections.span(len, rva)?;
        (start.checked_add(n)? <= end).then_some(start)
    }

    /// Whether the `n` bytes at file offset `o` share one with anything the assembly holds.
    pub(crate) fn overlaps(&self, o: usize, n: usize) -> bool {
        let end = o.saturating_add(n);
        // The first range that ends past `o` is the only one that can start before `end`.
        let i = self.ranges.partition_point(|&(s, l)| s + l <= o);
        self.ranges.get(i).is_some_and(|&(s, _)| s < end)
    }
}

/// How much of the startup stub the entry point names is taken to be code. A managed compiler
/// writes `jmp [IAT]` there, six bytes, for an image that can run on x86, and no stub for x64;
/// sixteen covers the jump with room to spare.
const STUB: usize = 16;

/// What [`occupied`] holds as it walks the image: file ranges, where an address lies, and how many
/// more bytes of the structures the directories point at it may read to find them.
struct Holder<'a> {
    b: &'a [u8],
    sections: &'a Sections,
    /// `SizeOfHeaders`, clamped to the file.
    headers: usize,
    ranges: Vec<(usize, usize)>,
    /// A linker writes each structure a directory points at once, so reading more of them than the
    /// file holds is a table naming one structure over and over, at a cost of its entries times
    /// that structure's size, in a verifier and in the archived wasm set alike.
    budget: usize,
}

impl Holder<'_> {
    fn put(&mut self, start: usize, end: usize) {
        let end = end.min(self.b.len());
        if end > start {
            self.ranges.push((start, end - start));
        }
    }

    /// Where the runtime reads the bytes at `rva`: its file offset, and the end of what the loader
    /// maps from the file there. Through the section that maps it, or, below `SizeOfHeaders` where
    /// no section does, through the headers, which the loader maps at the image's base, so that
    /// there an address is its own file offset. `None` for an address neither places.
    fn place(&self, rva: usize) -> Option<(usize, usize)> {
        match self.sections.span(self.b.len(), rva) {
            Some(span) => Some(span),
            None => (rva < self.headers).then_some((rva, self.headers)),
        }
    }

    /// What a directory `(rva, size)` names, held as far as the loader maps it from the file. One
    /// with no address or no size names nothing; `None` for one at an address nothing places.
    fn put_named(&mut self, rva: usize, size: usize) -> Option<()> {
        if rva != 0 && size != 0 {
            let (start, end) = self.place(rva)?;
            self.put(start, start.saturating_add(size).min(end));
        }
        Some(())
    }

    /// The `n` bytes at `rva`, held and paid for, as their file offset: `None` when the loader does
    /// not map all of them from the file, or when the budget runs out.
    fn hold(&mut self, rva: usize, n: usize) -> Option<usize> {
        let (start, end) = self.place(rva)?;
        if start.checked_add(n)? > end {
            return None;
        }
        self.budget = self.budget.checked_sub(n)?;
        self.put(start, start + n);
        Some(start)
    }

    /// The NUL-terminated string at `rva`, held with its terminator.
    fn hold_str(&mut self, rva: usize) -> Option<()> {
        let (start, end) = self.place(rva)?;
        let s = self.b.get(start..end)?;
        let n = s.iter().take(self.budget).position(|&c| c == 0)? + 1;
        self.budget -= n;
        self.put(start, start + n);
        Some(())
    }
}

/// The import directory at `rva`, and what the loader reads through it: each descriptor to the
/// empty one that ends the list, the name of the DLL it imports from, its lookup and address tables
/// to their terminators, and the hint and name of each import a lookup entry names by name. A
/// managed image imports `_CorDllMain` or `_CorExeMain` from `mscoree.dll` this way, and those
/// names lie outside the directory's own range.
fn hold_imports(h: &mut Holder<'_>, rva: usize, pe32_plus: bool) -> Option<()> {
    let b = h.b;
    let (width, by_ordinal) = if pe32_plus {
        (8, 1u64 << 63)
    } else {
        (4, 1u64 << 31)
    };
    let mut d = rva;
    loop {
        let at = h.hold(d, 20)?;
        let desc = b.get(at..at + 20)?;
        if desc.iter().all(|&c| c == 0) {
            return Some(());
        }
        // OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk.
        let (lookup, name, address) = (
            u32(desc, 0)? as usize,
            u32(desc, 12)? as usize,
            u32(desc, 16)? as usize,
        );
        h.hold_str(name)?;
        // An old linker left the lookup table out, and then the address table names the imports.
        let names = if lookup != 0 { lookup } else { address };
        for table in [lookup, address].into_iter().filter(|&t| t != 0) {
            let mut t = table;
            loop {
                let at = h.hold(t, width)?;
                let v = if pe32_plus {
                    u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?)
                } else {
                    u64::from(u32(b, at)?)
                };
                if v == 0 {
                    break;
                }
                if table == names && v & by_ordinal == 0 {
                    // A two-byte hint, then the name.
                    let hint = (v & 0x7fff_ffff) as usize;
                    h.hold(hint, 2)?;
                    h.hold_str(hint.checked_add(2)?)?;
                }
                t = t.checked_add(width)?;
            }
        }
        d = d.checked_add(20)?;
    }
}

/// The Win32 resource directory at `rva`, and what the loader reads through it: each directory
/// table and its entries, each entry's name, and each data entry and the data it points at, which
/// lies wherever the linker put it, inside the directory's stated size or not. The tree's own
/// offsets are from its root.
fn hold_resources(h: &mut Holder<'_>, rva: usize) -> Option<()> {
    const DEEPER: u32 = 0x8000_0000;
    let b = h.b;
    let mut tables = vec![0usize];
    // Each table once: an entry can name a table above it, and the walk would not end.
    let mut seen = std::collections::BTreeSet::new();
    while let Some(rel) = tables.pop() {
        if !seen.insert(rel) {
            continue;
        }
        let at = rva.checked_add(rel)?;
        // Characteristics, TimeDateStamp, the version, then how many named and numbered entries
        // follow the table's sixteen bytes, eight bytes each.
        let (start, _) = h.place(at)?;
        let n = usize::from(u16(b, start.checked_add(12)?)?)
            + usize::from(u16(b, start.checked_add(14)?)?);
        let table = h.hold(at, 16 + 8 * n)?;
        for k in 0..n {
            let e = table + 16 + 8 * k;
            let (name, off) = (u32(b, e)?, u32(b, e + 4)?);
            if name & DEEPER != 0 {
                // A name: its length in UTF-16 units, then the units.
                let s = rva.checked_add((name & !DEEPER) as usize)?;
                let (named, _) = h.place(s)?;
                let units = usize::from(u16(b, named)?);
                h.hold(s, 2 + 2 * units)?;
            }
            let target = (off & !DEEPER) as usize;
            if off & DEEPER != 0 {
                tables.push(target);
            } else {
                // OffsetToData (an RVA), Size, CodePage, Reserved.
                let entry = h.hold(rva.checked_add(target)?, 16)?;
                h.put_named(u32(b, entry)? as usize, u32(b, entry + 4)? as usize)?;
            }
        }
    }
    Some(())
}

/// Where `b`'s content lies, or `None` when this cannot delimit all of it: not a managed PE this
/// can walk, native code anywhere, a method body it cannot read, a stream listed twice, a heap
/// index that runs out of its heap, a `#GUID` heap anywhere but among the heaps, a structure named
/// at an address no section or header places, or a directory that points at code or at tables a
/// managed compiler does not write.
pub(crate) fn occupied(b: &[u8]) -> Option<Occupied> {
    let w = walk(b)?;
    let len = b.len();
    // Native code has no extent the metadata states: a mixed-mode image's C++, a native entry
    // point, and a ReadyToRun image's precompiled methods lie wherever the linker put them, so
    // nothing in the file is provably not code.
    if carries_native_code(w.cli)? {
        return None;
    }
    // A table ECMA-335 does not define has rows of no known width, and the runtime refuses one.
    if w.valid >> (LAST_KEPT + 1) != 0 {
        return None;
    }

    let mut h = Holder {
        b,
        sections: &w.sections,
        headers: (u32(b, w.opt + 60)? as usize).min(len),
        ranges: Vec::new(),
        budget: len,
    };

    // The CLI header, and the directories it names other than the metadata and the strong-name
    // signature: managed resources, the code manager table, VTable fixups, export address table
    // jumps.
    h.put(
        w.cli_at,
        w.cli_at.saturating_add(72).min(w.cli_at + w.cli.len()),
    );
    for d in [24, 40, 48, 56] {
        h.put_named(u32(w.cli, d)? as usize, u32(w.cli, d + 4)? as usize)?;
    }
    // Each VTable fixup names a run of slots, each a method token the loader replaces with the
    // address of the method it calls.
    let (fixups, fixups_size) = (u32(w.cli, 40)? as usize, u32(w.cli, 44)? as usize);
    if fixups != 0 && fixups_size != 0 {
        for k in (0..fixups_size / 8).map(|k| k * 8) {
            // RVA, Count, Type: COR_VTABLE_64BIT (0x02) for slots of eight bytes, else four.
            let at = h.hold(fixups.checked_add(k)?, 8)?;
            let (slots, count) = (u32(b, at)? as usize, usize::from(u16(b, at + 4)?));
            let width = if u16(b, at + 6)? & 0x02 != 0 { 8 } else { 4 };
            h.hold(slots, count * width)?;
        }
    }

    // Every stream but `#GUID`, and the metadata around them, from the root to the size the CLI
    // header gives it, `#GUID` cut out.
    let m_end = w.m_at + w.m.len();
    let md_end = w.m_at.saturating_add(u32(w.cli, 12)? as usize).min(m_end);
    let dir_end = w.m_at.saturating_add(w.dir_end);
    let mut guid = None;
    // A set, not a scan of the streams before each: the directory can list 65,535 of them.
    let mut seen = std::collections::BTreeSet::new();
    for &(name, off, size) in &w.streams {
        // The form reads the last stream of a name, and nothing says the runtime does too.
        if !seen.insert(name) {
            return None;
        }
        let start = w.m_at.saturating_add(off);
        let end = start.saturating_add(size);
        if name == b"#GUID" {
            // After the stream directory, inside the metadata the CLI header states, and a whole
            // number of GUIDs. Laid over the root or the directory, it is the signature, the
            // version and the headers that say where every table and heap is, and it was zeroed as
            // an MVID: two images whose directories named different streams then shared one set of
            // zeros and matched, and neither could be read as code again.
            if start < dir_end || end > md_end || size % 16 != 0 {
                return None;
            }
            guid = Some((start, size));
        } else {
            h.put(start.min(m_end), end.min(m_end));
        }
    }
    match guid {
        Some((g, n)) => {
            h.put(w.m_at, g);
            h.put(g + n, md_end);
        }
        None => h.put(w.m_at, md_end),
    }
    // The rows, wherever the counts carry them, and the table stream's header before them.
    h.put(w.m_at + w.tables.min(w.m.len()), w.m_at + w.rows_end);
    if !heaps_hold_every_index(&w)? {
        return None;
    }

    // Every method body: header, IL, and the exception sections after it.
    let meta = &w.meta;
    let method_row = meta.row_size(0x06)?;
    for i in 0..meta.counts[0x06] as usize {
        let r = w.at[0x06] + i * method_row;
        let rva = u32(w.m, r)? as usize;
        if rva != 0 && w.m.get(r + 4)? & 0x03 != 0 {
            return None;
        }
        if let Some(body) = method_body(b, &w.sections, rva)? {
            let (start, _) = w.sections.span(len, rva)?;
            h.put(start, start.saturating_add(body.extent));
        }
    }

    // The data each FieldRVA row names, as long as its field's type says, or to the end of what
    // the loader maps there where that type has no size this can read.
    let sizes = class_sizes(&w)?;
    let rva_row = meta.row_size(0x1d)?;
    for i in 0..meta.counts[0x1d] as usize {
        let r = w.at[0x1d] + i * rva_row;
        let rva = u32(w.m, r)? as usize;
        let field = read_idx(w.m, r + 4, meta.width(Col::Idx(0x04)))?;
        let (start, end) = h.place(rva)?;
        let size = field_size(&w, &sizes, field);
        h.put(
            start,
            size.map_or(end, |n| start.saturating_add(n).min(end)),
        );
    }

    // Every PE data directory but the debug directory, which is what the pass reads, and the CLI
    // header, placed above; and what the two a managed image carries that point further point at.
    let n_dirs = (u32(b, w.dir_off - 4)? as usize).min(16);
    for i in (0..n_dirs).filter(|&i| i != 6 && i != 14) {
        let (rva, size) = (
            u32(b, w.dir_off + 8 * i)? as usize,
            u32(b, w.dir_off + 8 * i + 4)? as usize,
        );
        if rva == 0 || size == 0 {
            continue;
        }
        match i {
            // The certificate table: its address is a file offset, not an RVA, and nothing in it
            // points elsewhere.
            4 => h.put(rva, rva.saturating_add(size)),
            // Exports, exception data, TLS, load configuration, bound and delay imports point at
            // native code or at tables of their own, and no managed compiler writes one.
            0 | 3 | 9 | 10 | 11 | 13 => return None,
            _ => {
                h.put_named(rva, size)?;
                match i {
                    1 => hold_imports(&mut h, rva, w.pe32_plus)?,
                    2 => hold_resources(&mut h, rva)?,
                    _ => {}
                }
            }
        }
    }
    let entry = u32(b, w.opt + 16)? as usize;
    if entry != 0 {
        let (s, e) = h.place(entry)?;
        h.put(s, s.saturating_add(STUB).min(e));
    }

    let headers = h.headers;
    let mut ranges = h.ranges;
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (o, l) in ranges {
        match merged.last_mut() {
            Some((mo, ml)) if o <= *mo + *ml => *ml = (*ml).max(o + l - *mo),
            _ => merged.push((o, l)),
        }
    }
    Some(Occupied {
        ranges: merged,
        guid,
        headers_end: headers.max(w.table_end).min(len),
        cli: w.cli_at,
        sections: w.sections,
    })
}

/// Whether every heap index in every row names an entry inside its heap: a string that ends before
/// `#Strings` does, a blob that ends before `#Blob` does, a GUID inside `#GUID`. The runtime
/// refuses an image that breaks this. The form reads on to the end of what the file backs, past
/// the heap into whatever follows it, so an image that breaks it could have a string or a
/// signature read out of a region the identity pass zeroes.
fn heaps_hold_every_index(w: &Walked<'_>) -> Option<bool> {
    let size = |name: &[u8]| {
        w.streams
            .iter()
            .find(|&&(n, _, _)| n == name)
            .map_or(0, |&(_, off, size)| size.min(w.m.len().saturating_sub(off)))
    };
    let (strings, blobs, guids) = (size(b"#Strings"), size(b"#Blob"), size(b"#GUID"));
    // A string ends inside the heap when a NUL follows it there, so any offset up to the heap's
    // last NUL is one; checked once rather than scanned per row.
    let heap =
        w.m.get(w.meta.strings..w.meta.strings.checked_add(strings)?)?;
    let last_nul = heap.iter().rposition(|&c| c == 0);
    let blob_heap = w.m.get(w.meta.blob..w.meta.blob.checked_add(blobs)?)?;
    let meta = &w.meta;
    for (t, &start) in w.at.iter().enumerate() {
        if w.valid & (1 << t) == 0 {
            continue;
        }
        let cols = columns(t)?;
        let row = meta.row_size(t)?;
        for k in 0..meta.counts[t] as usize {
            let mut o = start + k * row;
            for &c in cols {
                let width = meta.width(c);
                let v = read_idx(w.m, o, width)?;
                let inside = match c {
                    Col::Str => last_nul.is_some_and(|n| v <= n),
                    // A length the heap holds, then that many bytes it holds too.
                    Col::Blob => blob_heap
                        .get(v..)
                        .and_then(compressed)
                        .is_some_and(|(n, hdr)| (n as usize).saturating_add(hdr) <= blobs - v),
                    Col::Guid => v.checked_mul(16).is_some_and(|e| e <= guids),
                    _ => true,
                };
                if !inside {
                    return Some(false);
                }
                o += width;
            }
        }
    }
    Some(true)
}

/// Each TypeDef row whose size a ClassLayout row states whole, and that size: a `ClassSize` that is
/// not 0, of a type that owns no fields, which no other ClassLayout row names.
///
/// Nothing else says how long a value of the type is. A `ClassSize` of 0 is no `.size` at all, the
/// size left to the fields (ECMA-335 §II.22.8), and a type with fields is as long as `ClassSize` or
/// as its fields lay out, whichever is longer (§II.10.7); taken as a length, a `ClassSize` of 0 made
/// the data of a sequential struct with no stated size no bytes long, and the identity pass zeroed a
/// signature laid over it (`docs/16-findings.md` §3.106). A second row for the same type is one the
/// runtime may read in place of the first. The type a compiler declares field data with,
/// `__StaticArrayInitTypeSize=N`, is sized exactly: no fields, and a `ClassSize` of `N`.
fn class_sizes(w: &Walked<'_>) -> Option<std::collections::BTreeMap<usize, usize>> {
    let meta = &w.meta;
    let row = meta.row_size(0x0f)?;
    let parent = meta.width(Col::Idx(0x02));
    let mut stated = std::collections::BTreeMap::new();
    let mut twice = std::collections::BTreeSet::new();
    for k in 0..meta.counts[0x0f] as usize {
        // ClassLayout: PackingSize (2), ClassSize (4), Parent.
        let r = w.at[0x0f] + k * row;
        let t = read_idx(w.m, r + 6, parent)?;
        if stated.insert(t, u32(w.m, r + 2)? as usize).is_some() {
            twice.insert(t);
        }
    }
    // TypeDef: Flags (4), Name, Namespace, Extends, then FieldList. Each type's fields run from its
    // FieldList to the next type's, or past the end of the table FieldList indexes for the last:
    // FieldPtr where the uncompressed layout has one, Field otherwise.
    let types = meta.counts[0x02] as usize;
    let type_row = meta.row_size(0x02)?;
    let list_at = 4 + 2 * meta.width(Col::Str) + meta.width(Col::Coded(TYPE_DEF_OR_REF, 2));
    let list_width = meta.width(Col::Idx(0x04));
    let field_list =
        |t: usize| read_idx(w.m, w.at[0x02] + (t - 1) * type_row + list_at, list_width);
    let listed = if meta.counts[0x03] > 0 {
        meta.counts[0x03]
    } else {
        meta.counts[0x04]
    } as usize;
    let mut out = std::collections::BTreeMap::new();
    for (t, size) in stated {
        if size == 0 || twice.contains(&t) || t == 0 || t > types {
            continue;
        }
        let end = if t < types {
            field_list(t + 1)?
        } else {
            listed + 1
        };
        if field_list(t)? == end {
            out.insert(t, size);
        }
    }
    Some(out)
}

/// How many bytes field `row` holds, from its signature: a primitive's width, or the size a
/// ClassLayout row states whole for a value type defined here ([`class_sizes`]). `None` for a type
/// with no size this can read, whose data the caller takes to run to the end of what the loader
/// maps there.
fn field_size(
    w: &Walked<'_>,
    sizes: &std::collections::BTreeMap<usize, usize>,
    row: usize,
) -> Option<usize> {
    let meta = &w.meta;
    if row == 0 || row > meta.counts[0x04] as usize {
        return None;
    }
    // Field: Flags (2), Name, Signature. The row is inside the rows `walk` placed.
    let r = w.at[0x04] + (row - 1) * meta.row_size(0x04)?;
    let sig = meta.blob_at(read_idx(
        w.m,
        r + 2 + meta.width(Col::Str),
        meta.width(Col::Blob),
    )?)?;
    // FIELD, then any custom modifiers, each a CMOD_REQD or CMOD_OPT byte and a coded token.
    if *sig.first()? != 0x06 {
        return None;
    }
    let mut i = 1;
    while matches!(sig.get(i), Some(0x1f | 0x20)) {
        i += 1 + compressed(sig.get(i + 1..)?)?.1;
    }
    Some(match *sig.get(i)? {
        0x02 | 0x04 | 0x05 => 1, // bool, i1, u1
        0x03 | 0x06 | 0x07 => 2, // char, i2, u2
        0x08 | 0x09 | 0x0c => 4, // i4, u4, r4
        0x0a | 0x0b | 0x0d => 8, // i8, u8, r8
        0x18 | 0x19 => 8,        // native int and uint, at the wider of their widths
        // VALUETYPE, then a TypeDefOrRef coded index; a TypeDef is tag 0.
        0x11 => {
            let (coded, _) = compressed(sig.get(i + 1..)?)?;
            if coded & 0x03 != 0 {
                return None;
            }
            *sizes.get(&((coded >> 2) as usize))?
        }
        _ => return None,
    })
}

/// A compressed unsigned integer (§II.23.2), and how many bytes it took.
fn compressed(b: &[u8]) -> Option<(u32, usize)> {
    let x = |i: usize| b.get(i).map(|&c| u32::from(c));
    let b0 = x(0)?;
    if b0 & 0x80 == 0 {
        Some((b0, 1))
    } else if b0 & 0xc0 == 0x80 {
        Some((((b0 & 0x3f) << 8) | x(1)?, 2))
    } else if b0 & 0xe0 == 0xc0 {
        Some((
            ((b0 & 0x1f) << 24) | (x(1)? << 16) | (x(2)? << 8) | x(3)?,
            4,
        ))
    } else {
        None
    }
}

/// How many times its own size an assembly's canonical form may reach before it is declined.
///
/// Measured over 5,582 real IL-only assemblies (a NuGet cache, an SDK, source checkouts, fetched
/// and rebuilt packages): the form is at most 2.21 times the file, a reference assembly's, and 1.54
/// at p99 (`docs/16-findings.md` §3.107). Declining costs normalization and never a false match,
/// so the bound sits well clear.
const MAX_EXPANSION: usize = 4;

/// One field of a record: its length as a little-endian `u32`, then its bytes. A field too long for
/// the length to name declines the assembly rather than write a length that is not the field's.
fn put_field(out: &mut Vec<u8>, field: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(field.len()).ok()?.to_le_bytes());
    out.extend_from_slice(field);
    Some(())
}

/// Table `t`, whose rows start at `start`: its id, its row count, and each row column by column —
/// a heap index as the string or blob it names, anything else as the number it is. A row number
/// stays a row number, because a token is one: the form says what each row is at the position a
/// token names it by.
fn put_table(
    out: &mut Vec<u8>,
    meta: &Meta<'_>,
    t: usize,
    start: usize,
    limit: usize,
) -> Option<()> {
    let cols = columns(t)?;
    let row = meta.row_size(t)?;
    out.push(u8::try_from(t).ok()?);
    out.extend_from_slice(&meta.counts[t].to_le_bytes());
    // Every row of a kept table is inside the file: `canonical_managed` checked where the last one
    // ends before it wrote a byte, so none of these sums can pass the end, on either width.
    for i in 0..meta.counts[t] as usize {
        let mut o = start + i * row;
        for &c in cols {
            let w = meta.width(c);
            let v = read_idx(meta.b, o, w)?;
            match c {
                Col::Str => put_field(out, meta.string_at(v))?,
                Col::Blob => put_field(out, meta.blob_at(v)?)?,
                Col::U16 => out.extend_from_slice(&u16::try_from(v).ok()?.to_le_bytes()),
                _ => out.extend_from_slice(&u32::try_from(v).ok()?.to_le_bytes()),
            }
            o += w;
        }
        if out.len() > limit {
            return None;
        }
    }
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

/// A method body as the runtime reads it (§II.25.4): its header, its IL, and the extra-data
/// sections after the IL, each exactly as long as its own header says.
struct MethodBody<'a> {
    header: &'a [u8],
    il: &'a [u8],
    sections: Vec<&'a [u8]>,
    /// How far the body runs from its first byte: to the end of the last byte read of it, the
    /// padding between the IL and a section included.
    extent: usize,
}

/// The body at `rva`: `Some(None)` for a method with none (`rva == 0`: abstract, `extern` or
/// P/Invoke), and `None` for one this cannot read as the runtime reads it — an address no section
/// maps, a header that is neither format, or a header, IL or section that runs off the end of what
/// the file backs of the section holding the body's first byte, where the runtime reads zeros.
/// Declined rather than written as a method with no body: that record is the same for every body
/// it could not read, and the runtime runs, or fails, each one differently.
///
/// A tiny header is one byte carrying the code size in its top six bits. A fat one is a flags word
/// whose top four bits are the header's own length in dwords, MaxStack, the code size and
/// LocalVarSigTok; the code starts where that length says, as the runtime starts it — read from
/// twelve bytes on when it says less, where this form has always read it, and the header, whole in
/// the form, shows the difference.
fn method_body<'a>(b: &'a [u8], sections: &Sections, rva: usize) -> Option<Option<MethodBody<'a>>> {
    if rva == 0 {
        return Some(None);
    }
    // From the body's first byte to the end of what the file backs of its section, so every read
    // below is of a byte the runtime reads too.
    let s = sections.bytes(b, rva)?;
    let b0 = *s.first()?;
    Some(Some(match b0 & 0x03 {
        // CorILMethod_TinyFormat: no sections, ever.
        0x02 => MethodBody {
            header: &s[..1],
            il: s.get(1..1 + usize::from(b0 >> 2))?,
            sections: Vec::new(),
            extent: 1 + usize::from(b0 >> 2),
        },
        0x03 => {
            // CorILMethod_FatFormat.
            let flags = u16(s, 0)?;
            let header_len = 4 * usize::from(flags >> 12).max(3);
            let size = u32(s, 4)? as usize;
            let code_len = header_len.checked_add(size)?;
            let (sections, extent) = if flags & 0x08 != 0 {
                // CorILMethod_MoreSects.
                extra_sections(s, rva, code_len)?
            } else {
                (Vec::new(), code_len)
            };
            MethodBody {
                header: s.get(..header_len)?,
                il: s.get(header_len..code_len)?,
                sections,
                extent,
            }
        }
        _ => return None,
    }))
}

/// The extra-data sections of the fat body `s`, at `rva`, whose header and code are `code_len`
/// bytes (§II.25.4.5). Each starts on the next 4-byte boundary of the *address*, as the runtime
/// aligns it, and is a kind byte, then its length including that header — one byte, or three in
/// the fat format — and each says whether another follows. The padding between them is not the
/// code's, so only the sections themselves are kept.
///
/// A header too short to step over ends the chain where it stands: the section or header before it
/// still says another follows, so the form shows the chain was cut short there. A header or section
/// that runs off the end of `s` declines the body: past it the runtime reads zeros, and the part of
/// a section before that line would otherwise be the form of every section cut there. Every step
/// moves at least four bytes on and stays inside `s`, so the walk ends. Beside the sections, how
/// far into `s` the last byte read lies.
fn extra_sections(s: &[u8], rva: usize, code_len: usize) -> Option<(Vec<&[u8]>, usize)> {
    let mut out = Vec::new();
    let mut next = rva.checked_add(code_len)?;
    loop {
        let sect_rva = next.checked_add(3)? & !3;
        // At or past `next`, which is at or past `rva`, so the difference cannot fall below zero.
        let o = sect_rva - rva;
        let word = u32(s, o)?;
        let kind = word & 0xff;
        let len = if kind & 0x40 != 0 {
            word >> 8 // CorILMethod_Sect_FatFormat: a 24-bit length
        } else {
            (word >> 8) & 0xff
        } as usize;
        if len < 4 {
            // The header word was read, so the body runs to its end.
            return Some((out, o + 4));
        }
        out.push(s.get(o..o.checked_add(len)?)?);
        if kind & 0x80 == 0 {
            return Some((out, o + len)); // CorILMethod_Sect_MoreSects clear: the last one
        }
        next = sect_rva.checked_add(len)?;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn put16(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn set32(v: &mut [u8], at: usize, x: u32) {
        v[at..at + 4].copy_from_slice(&x.to_le_bytes());
    }

    /// Where [`assembly_with_sections`] maps the section it puts everything in.
    pub(crate) const RVA: u32 = 0x2000;

    /// A managed PE (ECMA-335 §II.24–§II.25) holding `methods` methods, each a tiny `ret`, and
    /// `sections` section headers of which only the last one listed maps anything the assembly
    /// uses. The others lie above it, listed highest first, and map nothing it points at.
    pub(crate) fn assembly_with_sections(sections: usize, methods: u32) -> Vec<u8> {
        let table = 0x178; // after a PE32 optional header of 0xe0 bytes, at 0x98
        let raw = (table + 40 * sections + 0x1ff) & !0x1ff;

        // The section: the CLI header, one body every method shares, then the metadata.
        let mut s = vec![0u8; 72];
        let body = s.len() as u32;
        s.extend_from_slice(&[(1 << 2) | 0x02, 0x2a, 0, 0]);
        let mut t = Vec::new();
        put32(&mut t, 0);
        t.extend_from_slice(&[2, 0, 0, 1]);
        t.extend_from_slice(&(1u64 << 0x06).to_le_bytes());
        t.extend_from_slice(&0u64.to_le_bytes());
        put32(&mut t, methods);
        for _ in 0..methods {
            put32(&mut t, RVA + body);
            for x in [0, 0x0086, 1, 1, 1] {
                put16(&mut t, x);
            }
        }
        let streams: [(&[u8], Vec<u8>); 4] = [
            (b"#~\0\0", t),
            (b"#Strings\0\0\0\0", b"\0m\0\0".to_vec()),
            (b"#GUID\0\0\0", vec![0x11; 16]),
            (b"#Blob\0\0\0", vec![0, 3, 0x00, 0x00, 0x01, 0, 0, 0]),
        ];
        let md_at = s.len() as u32;
        let mut md = b"BSJB".to_vec();
        put32(&mut md, 0x0001_0001);
        put32(&mut md, 0);
        put32(&mut md, 12);
        md.extend_from_slice(b"v4.0.30319\0\0");
        put16(&mut md, 0);
        put16(&mut md, streams.len() as u16);
        let mut off = md.len() + streams.iter().map(|(n, _)| 8 + n.len()).sum::<usize>();
        for (name, data) in &streams {
            put32(&mut md, off as u32);
            put32(&mut md, data.len() as u32);
            md.extend_from_slice(name);
            off += data.len().next_multiple_of(4);
        }
        for (_, data) in &streams {
            md.extend_from_slice(data);
            md.resize(md.len().next_multiple_of(4), 0);
        }
        s.extend_from_slice(&md);
        set32(&mut s, 0, 72);
        set32(&mut s, 8, RVA + md_at);
        set32(&mut s, 12, md.len() as u32);
        set32(&mut s, 16, 1); // ILONLY, as a compiler sets it on an image of IL alone

        let mut f = vec![0u8; raw];
        f[0..2].copy_from_slice(b"MZ");
        set32(&mut f, 0x3c, 0x80);
        f[0x80..0x84].copy_from_slice(b"PE\0\0");
        f[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        f[0x86..0x88].copy_from_slice(&(sections as u16).to_le_bytes());
        f[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        f[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        set32(&mut f, 0x98 + 92, 16);
        set32(&mut f, 0x98 + 96 + 14 * 8, RVA);
        set32(&mut f, 0x98 + 96 + 14 * 8 + 4, 72);
        for i in 0..sections - 1 {
            let h = table + 40 * i;
            set32(&mut f, h + 8, 0x1000); // VirtualSize
            let vaddr = 0x0010_0000 + 0x1000 * (sections - 2 - i) as u32;
            set32(&mut f, h + 12, vaddr);
        }
        let h = table + 40 * (sections - 1);
        set32(&mut f, h + 8, s.len() as u32);
        set32(&mut f, h + 12, RVA);
        set32(&mut f, h + 16, s.len() as u32);
        set32(&mut f, h + 20, raw as u32);
        f.extend_from_slice(&s);
        f
    }

    #[test]
    fn the_section_table_is_indexed_once_rather_than_scanned_per_method() {
        // NumberOfSections is a u16 the file states, and every method's RVA is looked up through
        // the section table. Scanned front to back per lookup, 65535 sections and a method table
        // pointing past all but the last cost methods × sections: seconds for half a megabyte,
        // minutes for 16 MB, on a verifier and in the archived wasm set, which has no fuel limit.
        let (sections, methods) = (65_535, 500);
        let big = assembly_with_sections(sections, methods);
        SECTION_VISITS.with(|v| v.set(0));
        let form = canonical_managed(&big).expect("read through its last-listed section");
        let visits = SECTION_VISITS.with(|v| v.get());
        assert_eq!(
            Some(form),
            canonical_managed(&assembly_with_sections(1, methods)),
            "the section found is the one a scan found"
        );
        // Each header read once, then every lookup — the CLI header, the metadata root and each
        // method — a binary search over the sorted index.
        let bound = sections as u64 + (methods as u64 + 2) * 17;
        assert!(visits <= bound, "{visits} visits, more than {bound}");
    }

    #[test]
    fn sections_that_claim_one_address_are_declined() {
        // A scan found whichever was listed first; a search over sorted sections finds whichever
        // sorts last. Neither is what the file means, so neither is guessed at.
        let good = assembly_with_sections(3, 2);
        assert!(canonical_managed(&good).is_some());
        let table = 0x178;
        for (what, header, vaddr, vsize) in [
            ("two sections at one address", 0, RVA, 0x10),
            ("a section running into the next", 0, RVA - 0x10, 0x11),
            ("an empty section on another's first byte", 1, RVA, 0),
        ] {
            let mut bad = good.clone();
            set32(&mut bad, table + 40 * header + 8, vsize);
            set32(&mut bad, table + 40 * header + 12, vaddr);
            assert!(canonical_managed(&bad).is_none(), "{what}");
        }
        // Touching is not overlapping: a section ending where the next begins is read.
        let mut touching = good.clone();
        set32(&mut touching, table + 8, 0x10);
        set32(&mut touching, table + 12, RVA - 0x10);
        assert_eq!(canonical_managed(&touching), canonical_managed(&good));
    }

    #[test]
    fn a_guid_heap_over_the_root_or_its_stream_directory_is_not_among_the_heaps() {
        // The identity pass zeroes `#GUID` whole. Laid over the metadata root or the stream
        // directory, it held what says where every table and heap is, and `occupied` left those
        // bytes out as `#GUID`'s, so they were zeroed as an MVID.
        let good = assembly_with_sections(1, 1);
        assert!(occupied(&good).is_some_and(|o| o.guid.is_some()));
        let header = good.windows(6).position(|w| w == b"#GUID\0").unwrap() - 8;
        // The root's sixteen bytes and the version string's twelve, then the flags and the count.
        for (what, at) in [("over the root", 0), ("over the stream directory", 32)] {
            let mut bad = good.clone();
            set32(&mut bad, header, at);
            assert!(occupied(&bad).is_none(), "#GUID {what}");
        }
    }

    #[test]
    fn a_non_managed_input_is_declined() {
        assert!(canonical_managed(b"not a PE").is_none());
        assert!(canonical_managed(&[]).is_none());
        assert!(canonical_managed(b"MZ").is_none());
    }

    /// Gated on two real assemblies: point them at a published managed DLL and its rebuild. The
    /// canonical form is equal when the two differ only in metadata/debug layout — the case
    /// `dotnet-assembly-identity-v2` cannot reach. `TRIGON_DOTNET_A`/`_B`, as the sibling test
    /// uses.
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
