//! Managed (.NET) assemblies: `dotnet-assembly-identity` and `dotnet-il-canonical-v2`.
//!
//! Both passes walk a PE by hand, through bytes the publisher wrote, and one of them decides
//! whether two assemblies are the same code. So the fixtures here are real managed PEs, assembled
//! byte by byte from ECMA-335 (Partition II §24–§25) rather than taken from the passes' own idea of
//! the layout: a reader that sized a row wrongly would agree with a writer that made the same
//! mistake, and agree with nothing a compiler emits.
//!
//! What they hold the passes to is what `passes.rs` and `docs/16-findings.md` §3.81/§3.89 promise:
//! code-identical assemblies reduce to the same bytes, a changed body, a new method or a changed
//! signature still shows — and so does a change only to what a token names, a method's flags, a
//! body's header and exception handlers, or a P/Invoke target, override or implemented interface —
//! the identity pass zeroes its named regions and nothing else, and an assembly either pass cannot
//! read whole, or could read only past what the runtime maps from the file, is left exactly as it
//! was.

use proptest::prelude::*;
use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note, RiskTier};
use trigon_stabilize::{Applied, StabilizerSet, apply, profile};

// --- the fixture: a managed PE, assembled from the spec -----------------------------------------

/// Where the one section is mapped, and where its bytes start in the file.
const SECTION_RVA: u32 = 0x2000;
const SECTION_RAW: usize = 0x200;

#[derive(Clone, Debug)]
enum Code {
    /// `RVA == 0`: an abstract, `extern` or P/Invoke method with no body.
    Abstract,
    /// A one-byte header carrying the size.
    Tiny(Vec<u8>),
    /// A twelve-byte header with the size at offset 4.
    Fat(Vec<u8>),
    /// A fat body whose header says a section follows the code: one small exception-handling
    /// section, holding a clause that catches the type the token names.
    Guarded(Vec<u8>, u32),
}

#[derive(Clone, Debug)]
struct Method {
    name: String,
    sig: Vec<u8>,
    /// `MethodAttributes` and `MethodImplAttributes` (§II.23.1.10, §II.23.1.11).
    flags: u16,
    impl_flags: u16,
    code: Code,
}

/// `public hidebysig`, the flags the builder gives every method unless a case says otherwise.
const PUBLIC_HIDEBYSIG: u16 = 0x0086;

fn tiny(name: &str, sig: &[u8], il: &[u8]) -> Method {
    Method {
        name: name.into(),
        sig: sig.to_vec(),
        flags: PUBLIC_HIDEBYSIG,
        impl_flags: 0,
        code: Code::Tiny(il.to_vec()),
    }
}

/// `instance void (int32)`, `void ()` and `static int32 ()`, as a compiler writes them.
const SIG_INSTANCE_INT: &[u8] = &[0x20, 0x01, 0x01, 0x08];
const SIG_VOID: &[u8] = &[0x00, 0x00, 0x01];
const SIG_STATIC_INT: &[u8] = &[0x00, 0x00, 0x08];
/// `instance void ()`, and a local signature of one `int32`.
const SIG_INSTANCE_VOID: &[u8] = &[0x20, 0x00, 0x01];
const LOCALS_INT: &[u8] = &[0x07, 0x01, 0x08];

/// A MemberRefParent coded index naming TypeRef `row`, and a TypeDefOrRef one.
const fn member_parent_typeref(row: u32) -> u32 {
    (row << 3) | 1
}
const fn typedef_or_ref_typeref(row: u32) -> u32 {
    (row << 2) | 1
}
/// A MethodDefOrRef coded index naming MethodDef `row`, and one naming MemberRef `row`.
const fn method_def_or_ref_def(row: u32) -> u32 {
    row << 1
}
const fn method_def_or_ref_ref(row: u32) -> u32 {
    (row << 1) | 1
}
/// A MemberForwarded coded index naming MethodDef `row`.
const fn member_forwarded_method(row: u32) -> u32 {
    (row << 1) | 1
}

/// `ldstr` of the literal at `#US` offset 1, `pop`, `ret`.
const LDSTR_FIRST: &[u8] = &[0x72, 0x01, 0x00, 0x00, 0x70, 0x26, 0x2a];

#[derive(Clone, Debug)]
struct Asm {
    pe32_plus: bool,
    methods: Vec<Method>,
    /// `HeapSizes`: 0x01 wide `#Strings`, 0x02 wide `#GUID`, 0x04 wide `#Blob`.
    heap_sizes: u8,
    /// TypeRef rows, written. Enough of them widens every coded index that can name a TypeRef.
    typeref_rows: u32,
    /// The names of the first TypeRef rows; any row past them is `Object`.
    typeref_names: Vec<String>,
    /// TypeDef rows: the name, Extends (a TypeDefOrRef coded index), and the first MethodDef row
    /// the type owns.
    types: Vec<(String, u32, u32)>,
    /// Field rows, written (and FieldPtr rows too, in the uncompressed layout).
    field_rows: u32,
    /// MemberRef rows: Class (a MemberRefParent coded index), the name and the signature.
    member_refs: Vec<(u32, String, Vec<u8>)>,
    /// StandAloneSig rows, each the signature it holds.
    standalone_sigs: Vec<Vec<u8>>,
    /// AssemblyRef rows: the name and the four-part version.
    assembly_refs: Vec<(String, [u16; 4])>,
    /// InterfaceImpl rows: Class (a TypeDef row) and Interface (a TypeDefOrRef coded index).
    interface_impls: Vec<(u32, u32)>,
    /// MethodImpl rows: Class (a TypeDef row), then MethodBody and MethodDeclaration, each a
    /// MethodDefOrRef coded index.
    method_impls: Vec<(u32, u32, u32)>,
    /// ModuleRef rows, each the native library it names.
    module_refs: Vec<String>,
    /// ImplMap rows: MappingFlags, MemberForwarded (a coded index), the entry point's name, and the
    /// ModuleRef row it is imported from.
    impl_maps: Vec<(u16, u32, String, u32)>,
    /// The `#US` literals, in order, the first at offset 1.
    user_strings: Vec<String>,
    /// Every fat body's header: the flags word, whose top four bits are the header's own size in
    /// dwords, then MaxStack and LocalVarSigTok.
    fat_header: (u16, u16, u32),
    /// Row counts for the other tables after `MethodDef`, each written as that many rows of zeros:
    /// a reader walking to a table it keeps needs every row before it sized exactly.
    declared: Vec<(usize, u32)>,
    /// `#-` with FieldPtr/MethodPtr tables, the uncompressed layout, rather than `#~`.
    uncompressed: bool,
    /// Junk ahead of the real entries in `#Strings` and `#Blob`, which shifts every heap offset.
    string_pad: usize,
    blob_pad: usize,
    /// Bytes between the CLI header and the first method body, which shifts every RVA.
    code_pad: usize,
    mvid: [u8; 16],
    timestamp: u32,
    checksum: u32,
    strong_name: Option<Vec<u8>>,
    /// Debug directory entries: each one's TimeDateStamp and the data it points at.
    debug: Vec<(u32, Vec<u8>)>,
}

impl Default for Asm {
    fn default() -> Self {
        Asm {
            pe32_plus: false,
            methods: vec![
                tiny(
                    ".ctor",
                    SIG_INSTANCE_INT,
                    &[0x02, 0x28, 0x01, 0x00, 0x00, 0x0a, 0x2a],
                ),
                tiny("Run", SIG_VOID, &[0x00, 0x2a]),
                Method {
                    name: "Answer".into(),
                    sig: SIG_STATIC_INT.to_vec(),
                    flags: PUBLIC_HIDEBYSIG,
                    impl_flags: 0,
                    code: Code::Fat(vec![0x1f, 0x2a, 0x0a, 0x06, 0x2a]),
                },
                Method {
                    name: "Hook".into(),
                    sig: SIG_VOID.to_vec(),
                    flags: PUBLIC_HIDEBYSIG,
                    impl_flags: 0,
                    code: Code::Abstract,
                },
            ],
            heap_sizes: 0,
            typeref_rows: 2,
            typeref_names: vec!["Object".into(), "Exception".into()],
            types: vec![("<Module>".into(), 0, 1)],
            field_rows: 1,
            // What `.ctor`'s `call 0x0a000001` calls: `Object::.ctor`.
            member_refs: vec![(
                member_parent_typeref(1),
                ".ctor".into(),
                SIG_INSTANCE_VOID.to_vec(),
            )],
            standalone_sigs: vec![LOCALS_INT.to_vec()],
            assembly_refs: vec![("System.Runtime".into(), [8, 0, 0, 0])],
            interface_impls: Vec::new(),
            method_impls: Vec::new(),
            module_refs: Vec::new(),
            impl_maps: Vec::new(),
            user_strings: vec!["Hello, world".into()],
            // Three dwords of header, fat, InitLocals; MaxStack 8; the first StandAloneSig.
            fat_header: (0x3013, 8, 0x1100_0001),
            declared: Vec::new(),
            uncompressed: false,
            string_pad: 0,
            blob_pad: 0,
            code_pad: 0,
            mvid: [0x11; 16],
            timestamp: 0x6543_2100,
            checksum: 0x0001_2345,
            strong_name: Some(vec![0x5a; 128]),
            debug: vec![(0x6543_2100, codeview(b"/home/alice/src/Demo/obj/Demo.pdb"))],
        }
    }
}

impl Asm {
    /// The default assembly, declaring what its code does beyond its bodies and its tokens: `Hook`
    /// a P/Invoke of `puts` in `libc`, `Run` the explicit implementation of the method MemberRef 1
    /// names, and `<Module>` an implementer of `IDisposable`.
    fn declaring() -> Asm {
        let mut a = Asm::default();
        a.methods[3].flags = PUBLIC_HIDEBYSIG | 0x2010; // static pinvokeimpl
        a.typeref_rows = 3;
        a.typeref_names.push("IDisposable".into());
        a.interface_impls = vec![(1, typedef_or_ref_typeref(3))];
        a.method_impls = vec![(1, method_def_or_ref_def(2), method_def_or_ref_ref(1))];
        a.module_refs = vec!["libc".into()];
        // `nomangle`, `cdecl`.
        a.impl_maps = vec![(0x0201, member_forwarded_method(4), "puts".into(), 1)];
        a
    }

    /// The same code as `self`, compiled somewhere else: every piece of build identity and every
    /// layout offset differs, and not one method does.
    ///
    /// The rows of a table the form keeps are what the code is, so a rebuild of the same code has
    /// the same rows there; what moves is the layout around them. `#Blob` indexes are written a
    /// width wider or narrower, which shifts every row from Field on, and a table the form drops
    /// (CustomAttribute) grows, which shifts every table after it.
    fn rebuilt_elsewhere(&self) -> Asm {
        let mut declared = self.declared.clone();
        match declared.iter_mut().find(|(t, _)| *t == 0x0c) {
            Some((_, n)) => *n += 3,
            None => declared.push((0x0c, 3)),
        }
        Asm {
            string_pad: self.string_pad + 37,
            blob_pad: self.blob_pad + 11,
            code_pad: self.code_pad + 24,
            heap_sizes: self.heap_sizes ^ 0x04,
            declared,
            mvid: [0x22; 16],
            timestamp: 0x7000_0001,
            checksum: 0x000f_eeee,
            strong_name: Some(vec![0xa5; 128]),
            debug: vec![(
                0x7000_0001,
                codeview(b"/build/agent/_work/1/s/obj/Release/Demo.pdb"),
            )],
            ..self.clone()
        }
    }
}

/// A CodeView record: `RSDS`, the PDB's GUID, its age, and the path it was written to.
fn codeview(path: &[u8]) -> Vec<u8> {
    let mut v = b"RSDS".to_vec();
    v.extend_from_slice(&[0x33; 16]);
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(path);
    v.push(0);
    v
}

/// Where the builder put things, so a test can name a region without re-parsing the file.
#[derive(Debug, Default)]
struct Layout {
    timestamp: usize,
    checksum: usize,
    /// Data directory 6, the debug directory's own RVA and size.
    debug_dir: usize,
    /// Data directory 14, the CLI header's RVA and size.
    cli_dir: usize,
    num_sections: usize,
    opt_magic: usize,
    pe_sig: usize,
    strong_name: Option<(usize, usize)>,
    debug_entries: Vec<usize>,
    debug_data: Vec<(usize, usize)>,
    guid_heap: (usize, usize),
    metadata: usize,
    /// The file offset of each stream header's name.
    stream_names: Vec<(String, usize)>,
    /// The file offset of `MethodDef`'s row count in the table stream's header.
    method_count: usize,
    method_rows: usize,
    method_row_size: usize,
    /// The file offset of the first MemberRef row.
    member_ref_rows: usize,
    /// The CLI header's own StrongNameSignature slot.
    cli_strong_name: usize,
}

impl Layout {
    /// Every region `dotnet-assembly-identity` is documented to zero, as file ranges.
    fn identity_regions(&self) -> Vec<(usize, usize)> {
        let mut r = vec![(self.timestamp, 4), (self.checksum, 4), self.guid_heap];
        r.extend(self.strong_name);
        if !self.debug_entries.is_empty() {
            r.push((self.debug_dir, 8));
        }
        r.extend(self.debug_entries.iter().map(|&e| (e + 4, 4)));
        r.extend(self.debug_data.iter().copied());
        r
    }
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_idx(v: &mut Vec<u8>, x: u32, width: usize) {
    if width == 4 {
        put32(v, x);
    } else {
        put16(v, u16::try_from(x).expect("a 2-byte index that fits"));
    }
}
fn set16(v: &mut [u8], at: usize, x: u16) {
    v[at..at + 2].copy_from_slice(&x.to_le_bytes());
}
fn set32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}
fn align(v: &mut Vec<u8>, n: usize) {
    while v.len() % n != 0 {
        v.push(0);
    }
}

/// A `#Strings` entry, returning its offset.
fn put_str(heap: &mut Vec<u8>, s: &[u8]) -> u32 {
    let at = heap.len() as u32;
    heap.extend_from_slice(s);
    heap.push(0);
    at
}

/// A `#Blob` entry behind its compressed length (§II.24.2.4), returning its offset.
fn put_blob(heap: &mut Vec<u8>, b: &[u8]) -> u32 {
    let at = heap.len() as u32;
    let n = b.len();
    if n < 0x80 {
        heap.push(n as u8);
    } else if n < 0x4000 {
        heap.extend_from_slice(&(0x8000 | n as u16).to_be_bytes());
    } else {
        heap.extend_from_slice(&(0xc000_0000 | n as u32).to_be_bytes());
    }
    heap.extend_from_slice(b);
    at
}

/// A `#US` literal (§II.24.2.4): UTF-16 behind a blob length, and a final byte that is 1 when a
/// character needs more than the plain ASCII handling. The builder's literals never do.
fn put_user_string(heap: &mut Vec<u8>, s: &str) {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    v.push(0);
    put_blob(heap, &v);
}

// --- every table's columns (§II.22), for sizing the rows the builder writes ---------------------

/// One column of a metadata table.
#[derive(Clone, Copy)]
enum Col {
    /// A constant this many bytes wide.
    Fixed(usize),
    Str,
    Guid,
    Blob,
    /// A simple index into the table.
    Table(usize),
    /// A coded index over these tables, in tag order, with a tag this many bits wide
    /// (§II.24.2.6). An unused tag is listed as the Module table, which always has one row.
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
const CUSTOM_ATTRIBUTE_TYPE: &[usize] = &[0x00, 0x00, 0x06, 0x0a, 0x00];
const RESOLUTION_SCOPE: &[usize] = &[0x00, 0x1a, 0x23, 0x01];
const TYPE_OR_METHOD_DEF: &[usize] = &[0x02, 0x06];

fn columns(t: usize) -> &'static [Col] {
    use Col::*;
    match t {
        0x00 => &[Fixed(2), Str, Guid, Guid, Guid],
        0x01 => &[Coded(RESOLUTION_SCOPE, 2), Str, Str],
        0x02 => &[
            Fixed(4),
            Str,
            Str,
            Coded(TYPE_DEF_OR_REF, 2),
            Table(0x04),
            Table(0x06),
        ],
        0x03 => &[Table(0x04)],
        0x04 => &[Fixed(2), Str, Blob],
        0x05 => &[Table(0x06)],
        0x06 => &[Fixed(4), Fixed(2), Fixed(2), Str, Blob, Table(0x08)],
        0x07 => &[Table(0x08)],
        0x08 => &[Fixed(2), Fixed(2), Str],
        0x09 => &[Table(0x02), Coded(TYPE_DEF_OR_REF, 2)],
        0x0a => &[Coded(MEMBER_REF_PARENT, 3), Str, Blob],
        0x0b => &[Fixed(2), Coded(HAS_CONSTANT, 2), Blob],
        0x0c => &[
            Coded(HAS_CUSTOM_ATTRIBUTE, 5),
            Coded(CUSTOM_ATTRIBUTE_TYPE, 3),
            Blob,
        ],
        0x0d => &[Coded(HAS_FIELD_MARSHAL, 1), Blob],
        0x0e => &[Fixed(2), Coded(HAS_DECL_SECURITY, 2), Blob],
        0x0f => &[Fixed(2), Fixed(4), Table(0x02)],
        0x10 => &[Fixed(4), Table(0x04)],
        0x11 => &[Blob],
        0x12 => &[Table(0x02), Table(0x14)],
        0x13 => &[Table(0x14)],
        0x14 => &[Fixed(2), Str, Coded(TYPE_DEF_OR_REF, 2)],
        0x15 => &[Table(0x02), Table(0x17)],
        0x16 => &[Table(0x17)],
        0x17 => &[Fixed(2), Str, Blob],
        0x18 => &[Fixed(2), Table(0x06), Coded(HAS_SEMANTICS, 1)],
        0x19 => &[
            Table(0x02),
            Coded(METHOD_DEF_OR_REF, 1),
            Coded(METHOD_DEF_OR_REF, 1),
        ],
        0x1a => &[Str],
        0x1b => &[Blob],
        0x1c => &[Fixed(2), Coded(MEMBER_FORWARDED, 1), Str, Table(0x1a)],
        0x1d => &[Fixed(4), Table(0x04)],
        0x1e => &[Fixed(4), Fixed(4)],
        0x1f => &[Fixed(4)],
        0x20 => &[Fixed(4), Fixed(8), Fixed(4), Blob, Str, Str],
        0x21 => &[Fixed(4)],
        0x22 => &[Fixed(12)],
        0x23 => &[Fixed(8), Fixed(4), Blob, Str, Str, Blob],
        0x24 => &[Fixed(4), Table(0x23)],
        0x25 => &[Fixed(12), Table(0x23)],
        0x26 => &[Fixed(4), Str, Blob],
        0x27 => &[Fixed(8), Str, Str, Coded(IMPLEMENTATION, 2)],
        0x28 => &[Fixed(8), Str, Coded(IMPLEMENTATION, 2)],
        0x29 => &[Table(0x02), Table(0x02)],
        0x2a => &[Fixed(4), Coded(TYPE_OR_METHOD_DEF, 1), Str],
        0x2b => &[Coded(METHOD_DEF_OR_REF, 1), Blob],
        0x2c => &[Table(0x2a), Coded(TYPE_DEF_OR_REF, 2)],
        _ => panic!("no table {t:#04x} in ECMA-335"),
    }
}

/// The tables `dotnet-il-canonical-v2` keeps after the methods, in the order it writes them.
const KEPT: [usize; 31] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0d, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x23, 0x27, 0x29, 0x2a, 0x2b, 0x2c,
];

impl Asm {
    fn width(&self, counts: &[u32; 64], c: Col) -> usize {
        let wide = |bit: u8| if self.heap_sizes & bit != 0 { 4 } else { 2 };
        match c {
            Col::Fixed(n) => n,
            Col::Str => wide(0x01),
            Col::Guid => wide(0x02),
            Col::Blob => wide(0x04),
            Col::Table(t) => {
                if counts[t] >= 0x1_0000 {
                    4
                } else {
                    2
                }
            }
            Col::Coded(ts, bits) => {
                let max = ts.iter().map(|&t| counts[t]).max().unwrap_or(0);
                if max >= 1 << (16 - bits) { 4 } else { 2 }
            }
        }
    }

    fn row_size(&self, counts: &[u32; 64], t: usize) -> usize {
        columns(t).iter().map(|&c| self.width(counts, c)).sum()
    }

    /// Every table's row count, as the table stream's header states it.
    fn counts(&self) -> [u32; 64] {
        let mut counts = [0u32; 64];
        counts[0x00] = 1;
        counts[0x01] = self.typeref_rows;
        counts[0x02] = self.types.len() as u32;
        counts[0x04] = self.field_rows;
        counts[0x06] = self.methods.len() as u32;
        if self.uncompressed {
            counts[0x03] = self.field_rows;
            counts[0x05] = self.methods.len() as u32;
        }
        counts[0x09] = self.interface_impls.len() as u32;
        counts[0x0a] = self.member_refs.len() as u32;
        counts[0x11] = self.standalone_sigs.len() as u32;
        counts[0x19] = self.method_impls.len() as u32;
        counts[0x1a] = self.module_refs.len() as u32;
        counts[0x1c] = self.impl_maps.len() as u32;
        counts[0x23] = self.assembly_refs.len() as u32;
        for &(t, n) in &self.declared {
            assert!(
                t > 0x06 && counts[t] == 0,
                "table {t:#04x} is written from its own field, not declared"
            );
            counts[t] = n;
        }
        counts
    }

    fn typeref_name(&self, row: usize) -> &str {
        self.typeref_names.get(row).map_or("Object", |s| s.as_str())
    }
}

/// The public-key token every AssemblyRef carries, as a reference to a framework assembly does.
const PUBLIC_KEY_TOKEN: &[u8] = &[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a];

/// The one exception-handling section a [`Code::Guarded`] body carries (§II.25.4.5–6): small
/// format, sixteen bytes, and a single catch clause over the first instruction.
fn eh_section(catch: u32) -> Vec<u8> {
    let mut v = vec![0x01, 16, 0, 0]; // CorILMethod_Sect_EHTable, DataSize, reserved
    put16(&mut v, 0); // COR_ILEXCEPTION_CLAUSE_EXCEPTION: a typed catch
    put16(&mut v, 0); // TryOffset
    v.push(1); // TryLength
    put16(&mut v, 1); // HandlerOffset
    v.push(1); // HandlerLength
    put32(&mut v, catch); // ClassToken
    v
}

impl Asm {
    fn build(&self) -> (Vec<u8>, Layout) {
        let mut lay = Layout::default();

        // The section: CLI header, method bodies, strong-name signature, debug directory, metadata.
        let mut sec = vec![0u8; 72];
        sec.extend(std::iter::repeat_n(0xcc, self.code_pad));
        let mut rvas = Vec::new();
        for m in &self.methods {
            match &m.code {
                Code::Abstract => rvas.push(0u32),
                Code::Tiny(il) => {
                    assert!(il.len() < 64, "a tiny header holds six bits of size");
                    rvas.push(SECTION_RVA + sec.len() as u32);
                    sec.push(((il.len() as u8) << 2) | 0x02);
                    sec.extend_from_slice(il);
                }
                Code::Fat(il) | Code::Guarded(il, _) => {
                    let guarded = matches!(m.code, Code::Guarded(..));
                    let (flags, max_stack, locals) = self.fat_header;
                    align(&mut sec, 4);
                    rvas.push(SECTION_RVA + sec.len() as u32);
                    // CorILMethod_MoreSects says a section follows the code.
                    put16(&mut sec, if guarded { flags | 0x08 } else { flags });
                    put16(&mut sec, max_stack);
                    put32(&mut sec, il.len() as u32);
                    put32(&mut sec, locals);
                    sec.extend_from_slice(il);
                    if let Code::Guarded(_, catch) = m.code {
                        align(&mut sec, 4);
                        sec.extend_from_slice(&eh_section(catch));
                    }
                }
            }
        }
        align(&mut sec, 4);
        let sn = self.strong_name.as_ref().map(|sn| {
            let at = sec.len();
            sec.extend_from_slice(sn);
            (at, sn.len())
        });
        align(&mut sec, 4);
        let dbg = sec.len();
        sec.extend(std::iter::repeat_n(0, 28 * self.debug.len()));
        for (i, (ts, data)) in self.debug.iter().enumerate() {
            let at = sec.len();
            sec.extend_from_slice(data);
            let e = dbg + 28 * i;
            set32(&mut sec, e + 4, *ts);
            set32(&mut sec, e + 12, 2); // IMAGE_DEBUG_TYPE_CODEVIEW
            set32(&mut sec, e + 16, data.len() as u32);
            set32(&mut sec, e + 20, SECTION_RVA + at as u32);
            set32(&mut sec, e + 24, (SECTION_RAW + at) as u32);
            lay.debug_entries.push(SECTION_RAW + e);
            lay.debug_data.push((SECTION_RAW + at, data.len()));
        }
        align(&mut sec, 4);

        // Heaps.
        let mut strings = vec![0u8];
        if self.string_pad > 0 {
            strings.extend(std::iter::repeat_n(b'p', self.string_pad));
            strings.push(0);
        }
        let module_name = put_str(&mut strings, b"Demo.dll");
        let object_name = put_str(&mut strings, b"Object");
        let typeref_names: Vec<u32> = self
            .typeref_names
            .iter()
            .map(|n| put_str(&mut strings, n.as_bytes()))
            .collect();
        let type_names: Vec<u32> = self
            .types
            .iter()
            .map(|(n, ..)| put_str(&mut strings, n.as_bytes()))
            .collect();
        let field_name = put_str(&mut strings, b"state");
        let names: Vec<u32> = self
            .methods
            .iter()
            .map(|m| put_str(&mut strings, m.name.as_bytes()))
            .collect();
        let member_names: Vec<u32> = self
            .member_refs
            .iter()
            .map(|(_, n, _)| put_str(&mut strings, n.as_bytes()))
            .collect();
        let module_names: Vec<u32> = self
            .module_refs
            .iter()
            .map(|n| put_str(&mut strings, n.as_bytes()))
            .collect();
        let import_names: Vec<u32> = self
            .impl_maps
            .iter()
            .map(|(_, _, n, _)| put_str(&mut strings, n.as_bytes()))
            .collect();
        // Interned, as a compiler interns them: sixteen thousand references to one assembly name
        // are one string, or the heap outgrows the index width the case is about.
        let mut interned = std::collections::HashMap::new();
        let assembly_names: Vec<u32> = self
            .assembly_refs
            .iter()
            .map(|(n, _)| {
                *interned
                    .entry(n.as_str())
                    .or_insert_with(|| put_str(&mut strings, n.as_bytes()))
            })
            .collect();
        let mut blob = vec![0u8];
        if self.blob_pad > 0 {
            put_blob(&mut blob, &vec![0x07; self.blob_pad]);
        }
        let sigs: Vec<u32> = self
            .methods
            .iter()
            .map(|m| put_blob(&mut blob, &m.sig))
            .collect();
        let member_sigs: Vec<u32> = self
            .member_refs
            .iter()
            .map(|(_, _, sig)| put_blob(&mut blob, sig))
            .collect();
        let standalone_sigs: Vec<u32> = self
            .standalone_sigs
            .iter()
            .map(|sig| put_blob(&mut blob, sig))
            .collect();
        let token = put_blob(&mut blob, PUBLIC_KEY_TOKEN);
        let guid = self.mvid.to_vec();
        let us = self.user_string_heap();

        // The table stream (§II.24.2.6).
        let s = if self.heap_sizes & 0x01 != 0 { 4 } else { 2 };
        let g = if self.heap_sizes & 0x02 != 0 { 4 } else { 2 };
        let bw = if self.heap_sizes & 0x04 != 0 { 4 } else { 2 };
        let counts = self.counts();
        let idx = |t: usize| self.width(&counts, Col::Table(t));
        let coded =
            |ts: &'static [usize], tag_bits: u32| self.width(&counts, Col::Coded(ts, tag_bits));
        let valid = (0..64)
            .filter(|&t| counts[t] > 0)
            .fold(0u64, |m, t| m | 1 << t);

        let mut t = Vec::new();
        put32(&mut t, 0);
        t.extend_from_slice(&[2, 0, self.heap_sizes, 1]);
        t.extend_from_slice(&valid.to_le_bytes());
        t.extend_from_slice(&0u64.to_le_bytes());
        let mut method_count_at = None;
        for (i, &n) in counts.iter().enumerate() {
            if n > 0 {
                if i == 0x06 {
                    method_count_at = Some(t.len());
                }
                put32(&mut t, n);
            }
        }
        // Module
        put16(&mut t, 0);
        put_idx(&mut t, module_name, s);
        put_idx(&mut t, 1, g);
        put_idx(&mut t, 0, g);
        put_idx(&mut t, 0, g);
        // TypeRef: ResolutionScope is Module, ModuleRef, AssemblyRef or TypeRef.
        let scope = coded(RESOLUTION_SCOPE, 2);
        for i in 0..self.typeref_rows as usize {
            put_idx(&mut t, (1 << 2) | 2, scope); // AssemblyRef 1
            put_idx(&mut t, *typeref_names.get(i).unwrap_or(&object_name), s);
            put_idx(&mut t, 0, s);
        }
        // TypeDef: Extends is TypeDef, TypeRef or TypeSpec.
        for (i, (_, extends, methods)) in self.types.iter().enumerate() {
            put32(&mut t, 0);
            put_idx(&mut t, type_names[i], s);
            put_idx(&mut t, 0, s);
            put_idx(&mut t, *extends, coded(TYPE_DEF_OR_REF, 2));
            put_idx(&mut t, 1, idx(0x04));
            put_idx(&mut t, *methods, idx(0x06));
        }
        if self.uncompressed {
            for i in 0..self.field_rows {
                put_idx(&mut t, i + 1, idx(0x04));
            }
        }
        for _ in 0..self.field_rows {
            put16(&mut t, 0x0001);
            put_idx(&mut t, field_name, s);
            put_idx(&mut t, 0, bw);
        }
        if self.uncompressed {
            for i in 0..self.methods.len() as u32 {
                put_idx(&mut t, i + 1, idx(0x06));
            }
        }
        let method_rows_at = t.len();
        for (i, m) in self.methods.iter().enumerate() {
            put32(&mut t, rvas[i]);
            put16(&mut t, m.impl_flags);
            put16(&mut t, m.flags);
            put_idx(&mut t, names[i], s);
            put_idx(&mut t, sigs[i], bw);
            put_idx(&mut t, 1, idx(0x08));
        }
        lay.method_row_size = 4 + 2 + 2 + s + bw + idx(0x08);
        assert_eq!(lay.method_row_size, self.row_size(&counts, 0x06));

        // Every table after MethodDef, in order: the ones the fixture names, and rows of zeros for
        // the ones it only declares.
        let mut member_ref_rows_at = t.len();
        for (table, &n) in counts.iter().enumerate().skip(0x07) {
            match table {
                // A table given rows of its own is written from them; one only declared is not.
                0x09 if !self.interface_impls.is_empty() => {
                    for &(class, interface) in &self.interface_impls {
                        put_idx(&mut t, class, idx(0x02));
                        put_idx(&mut t, interface, coded(TYPE_DEF_OR_REF, 2));
                    }
                }
                0x19 if !self.method_impls.is_empty() => {
                    for &(class, body, declaration) in &self.method_impls {
                        put_idx(&mut t, class, idx(0x02));
                        put_idx(&mut t, body, coded(METHOD_DEF_OR_REF, 1));
                        put_idx(&mut t, declaration, coded(METHOD_DEF_OR_REF, 1));
                    }
                }
                0x1a if !self.module_refs.is_empty() => {
                    for &name in &module_names {
                        put_idx(&mut t, name, s);
                    }
                }
                0x1c if !self.impl_maps.is_empty() => {
                    for (i, &(flags, member, _, scope)) in self.impl_maps.iter().enumerate() {
                        put16(&mut t, flags);
                        put_idx(&mut t, member, coded(MEMBER_FORWARDED, 1));
                        put_idx(&mut t, import_names[i], s);
                        put_idx(&mut t, scope, idx(0x1a));
                    }
                }
                0x0a => {
                    member_ref_rows_at = t.len();
                    for (i, (class, ..)) in self.member_refs.iter().enumerate() {
                        put_idx(&mut t, *class, coded(MEMBER_REF_PARENT, 3));
                        put_idx(&mut t, member_names[i], s);
                        put_idx(&mut t, member_sigs[i], bw);
                    }
                }
                0x11 => {
                    for &sig in &standalone_sigs {
                        put_idx(&mut t, sig, bw);
                    }
                }
                0x23 => {
                    for (i, (_, version)) in self.assembly_refs.iter().enumerate() {
                        for &part in version {
                            put16(&mut t, part);
                        }
                        put32(&mut t, 0); // Flags
                        put_idx(&mut t, token, bw);
                        put_idx(&mut t, assembly_names[i], s);
                        put_idx(&mut t, 0, s); // Culture
                        put_idx(&mut t, 0, bw); // HashValue
                    }
                }
                _ if n > 0 => t.extend(std::iter::repeat_n(
                    0,
                    self.row_size(&counts, table) * n as usize,
                )),
                _ => {}
            }
        }

        // The metadata root (§II.24.2.1) and its stream headers.
        let tables_name = if self.uncompressed { "#-" } else { "#~" };
        let streams: Vec<(&str, Vec<u8>)> = vec![
            (tables_name, t),
            ("#Strings", strings),
            ("#US", us),
            ("#GUID", guid),
            ("#Blob", blob),
        ];
        let version = b"v4.0.30319\0\0";
        let mut header_len = 16 + version.len() + 4;
        for (name, _) in &streams {
            header_len += 8 + ((name.len() + 1 + 3) & !3);
        }
        let md_at = sec.len();
        let mut md = b"BSJB".to_vec();
        put16(&mut md, 1);
        put16(&mut md, 1);
        put32(&mut md, 0);
        put32(&mut md, version.len() as u32);
        md.extend_from_slice(version);
        put16(&mut md, 0);
        put16(&mut md, streams.len() as u16);
        let mut off = header_len;
        let mut offsets = Vec::new();
        for (name, data) in &streams {
            let padded = (data.len() + 3) & !3;
            put32(&mut md, off as u32);
            put32(&mut md, data.len() as u32);
            lay.stream_names
                .push((name.to_string(), SECTION_RAW + md_at + md.len()));
            md.extend_from_slice(name.as_bytes());
            md.push(0);
            align(&mut md, 4);
            offsets.push(off);
            off += padded;
        }
        assert_eq!(md.len(), header_len);
        for (_, data) in &streams {
            md.extend_from_slice(data);
            align(&mut md, 4);
        }
        let file_md = SECTION_RAW + md_at;
        lay.metadata = file_md;
        lay.method_count = file_md + offsets[0] + method_count_at.unwrap_or(0);
        lay.method_rows = file_md + offsets[0] + method_rows_at;
        lay.member_ref_rows = file_md + offsets[0] + member_ref_rows_at;
        lay.guid_heap = (file_md + offsets[3], 16);
        sec.extend_from_slice(&md);

        // The CLI header (§II.25.3.3).
        set32(&mut sec, 0, 72);
        set16(&mut sec, 4, 2);
        set16(&mut sec, 6, 5);
        set32(&mut sec, 8, SECTION_RVA + md_at as u32);
        set32(&mut sec, 12, md.len() as u32);
        set32(&mut sec, 16, 1); // ILONLY
        if let Some((at, len)) = sn {
            set32(&mut sec, 32, SECTION_RVA + at as u32);
            set32(&mut sec, 36, len as u32);
            lay.strong_name = Some((SECTION_RAW + at, len));
        }
        lay.cli_strong_name = SECTION_RAW + 32;

        // The DOS stub, PE signature, COFF header, optional header and section table.
        let mut f = vec![0u8; SECTION_RAW];
        f[0..2].copy_from_slice(b"MZ");
        set32(&mut f, 0x3c, 0x80);
        lay.pe_sig = 0x80;
        f[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        set16(&mut f, coff, if self.pe32_plus { 0x8664 } else { 0x014c });
        set16(&mut f, coff + 2, 1);
        lay.num_sections = coff + 2;
        set32(&mut f, coff + 4, self.timestamp);
        lay.timestamp = coff + 4;
        let opt = coff + 20;
        let (magic, dirs) = if self.pe32_plus {
            (0x20b, 112)
        } else {
            (0x10b, 96)
        };
        let opt_size = dirs + 16 * 8;
        set16(&mut f, coff + 16, opt_size as u16);
        set16(&mut f, coff + 18, 0x2102);
        set16(&mut f, opt, magic);
        lay.opt_magic = opt;
        set32(&mut f, opt + 64, self.checksum);
        lay.checksum = opt + 64;
        let dir = opt + dirs;
        set32(&mut f, dir - 4, 16);
        lay.debug_dir = dir + 6 * 8;
        if !self.debug.is_empty() {
            set32(&mut f, dir + 6 * 8, SECTION_RVA + dbg as u32);
            set32(&mut f, dir + 6 * 8 + 4, 28 * self.debug.len() as u32);
        }
        lay.cli_dir = dir + 14 * 8;
        set32(&mut f, dir + 14 * 8, SECTION_RVA);
        set32(&mut f, dir + 14 * 8 + 4, 72);
        let sh = opt + opt_size;
        assert!(sh + 40 <= SECTION_RAW);
        f[sh..sh + 5].copy_from_slice(b".text");
        set32(&mut f, sh + 8, sec.len() as u32);
        set32(&mut f, sh + 12, SECTION_RVA);
        set32(&mut f, sh + 16, sec.len() as u32);
        set32(&mut f, sh + 20, SECTION_RAW as u32);
        set32(&mut f, sh + 36, 0x6000_0020);
        f.extend_from_slice(&sec);
        (f, lay)
    }

    fn bytes(&self) -> Vec<u8> {
        self.build().0
    }

    /// The `#US` heap as the builder writes it: the empty entry, then each literal.
    fn user_string_heap(&self) -> Vec<u8> {
        let mut us = vec![0u8];
        for s in &self.user_strings {
            put_user_string(&mut us, s);
        }
        us
    }

    /// The canonical form `dotnet-il-canonical-v2` documents, every number little-endian: `0x06`
    /// and the method count, then per method in table order its name and its signature, each
    /// behind its length as a u32, its ImplFlags and Flags, its ParamList as a u32, and `0` for a
    /// method without a body or `1` and the body's header, IL and exception-handling sections, each
    /// behind its length. Then
    /// each kept table's id, row count and rows, column by column: a string or blob behind its
    /// length, a row or coded index as a u32, anything else as the integer it is. Last, `0x70` and
    /// the `#US` heap behind its length.
    fn canonical(&self) -> Vec<u8> {
        fn field(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        let counts = self.counts();
        let mut out = vec![0x06];
        put32(&mut out, self.methods.len() as u32);
        for m in &self.methods {
            field(&mut out, m.name.as_bytes());
            field(&mut out, &m.sig);
            put16(&mut out, m.impl_flags);
            put16(&mut out, m.flags);
            put32(&mut out, 1); // every method's ParamList, as the builder writes it
            match &m.code {
                Code::Abstract => out.push(0),
                Code::Tiny(il) => {
                    out.push(1);
                    field(&mut out, &[((il.len() as u8) << 2) | 0x02]);
                    field(&mut out, il);
                    field(&mut out, &[]);
                }
                Code::Fat(il) | Code::Guarded(il, _) => {
                    let (flags, max_stack, locals) = self.fat_header;
                    let (flags, sections) = match m.code {
                        Code::Guarded(_, catch) => (flags | 0x08, eh_section(catch)),
                        _ => (flags, Vec::new()),
                    };
                    let mut header = Vec::new();
                    put16(&mut header, flags);
                    put16(&mut header, max_stack);
                    put32(&mut header, il.len() as u32);
                    put32(&mut header, locals);
                    out.push(1);
                    field(&mut out, &header);
                    field(&mut out, il);
                    field(&mut out, &sections);
                }
            }
        }
        for t in KEPT {
            out.push(t as u8);
            put32(&mut out, counts[t]);
            match t {
                0x01 => {
                    for i in 0..self.typeref_rows as usize {
                        put32(&mut out, (1 << 2) | 2);
                        field(&mut out, self.typeref_name(i).as_bytes());
                        field(&mut out, b"");
                    }
                }
                0x02 => {
                    for (name, extends, methods) in &self.types {
                        put32(&mut out, 0);
                        field(&mut out, name.as_bytes());
                        field(&mut out, b"");
                        put32(&mut out, *extends);
                        put32(&mut out, 1);
                        put32(&mut out, *methods);
                    }
                }
                0x03 | 0x05 => {
                    for i in 0..counts[t] {
                        put32(&mut out, i + 1);
                    }
                }
                0x04 => {
                    for _ in 0..self.field_rows {
                        put16(&mut out, 0x0001);
                        field(&mut out, b"state");
                        field(&mut out, b"");
                    }
                }
                0x0a => {
                    for (class, name, sig) in &self.member_refs {
                        put32(&mut out, *class);
                        field(&mut out, name.as_bytes());
                        field(&mut out, sig);
                    }
                }
                0x11 => {
                    for sig in &self.standalone_sigs {
                        field(&mut out, sig);
                    }
                }
                0x23 => {
                    for (name, version) in &self.assembly_refs {
                        for &part in version {
                            put16(&mut out, part);
                        }
                        put32(&mut out, 0);
                        field(&mut out, PUBLIC_KEY_TOKEN);
                        field(&mut out, name.as_bytes());
                        field(&mut out, b"");
                        field(&mut out, b"");
                    }
                }
                0x09 if !self.interface_impls.is_empty() => {
                    for &(class, interface) in &self.interface_impls {
                        put32(&mut out, class);
                        put32(&mut out, interface);
                    }
                }
                0x19 if !self.method_impls.is_empty() => {
                    for &(class, body, declaration) in &self.method_impls {
                        put32(&mut out, class);
                        put32(&mut out, body);
                        put32(&mut out, declaration);
                    }
                }
                0x1a if !self.module_refs.is_empty() => {
                    for name in &self.module_refs {
                        field(&mut out, name.as_bytes());
                    }
                }
                0x1c if !self.impl_maps.is_empty() => {
                    for (flags, member, name, scope) in &self.impl_maps {
                        put16(&mut out, *flags);
                        put32(&mut out, *member);
                        field(&mut out, name.as_bytes());
                        put32(&mut out, *scope);
                    }
                }
                // A table the fixture only declares is rows of zeros: every integer 0, and every
                // string and blob the empty one at offset 0.
                _ => {
                    for _ in 0..counts[t] {
                        for &c in columns(t) {
                            match c {
                                Col::Fixed(n) => out.extend(std::iter::repeat_n(0, n)),
                                _ => put32(&mut out, 0),
                            }
                        }
                    }
                }
            }
        }
        out.push(0x70);
        field(&mut out, &self.user_string_heap());
        out
    }
}

// --- running the passes --------------------------------------------------------------------------

const DLL: &str = "lib/net8.0/Demo.dll";

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// The `nupkg` profile narrowed to one pass, so each is held to its own promise.
fn only(pass: &str) -> StabilizerSet {
    let set = profile("nupkg").unwrap().filtered(&[pass.to_string()], &[]);
    assert_eq!(
        set.members.len(),
        1,
        "no pass `{pass}` in the nupkg profile"
    );
    set
}

const IDENTITY: &str = "dotnet-assembly-identity";
const CANONICAL: &str = "dotnet-il-canonical-v2";

/// One member after a set ran over a package holding it.
#[derive(Debug)]
struct Out {
    body: Vec<u8>,
    dirty: bool,
    applied: Vec<Applied>,
}

fn run(set: &StabilizerSet, name: &str, bytes: &[u8]) -> Out {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(
        zip(&[(name, bytes)]),
        Format::Zip,
        &Limits::default(),
        &mut notes,
    )
    .unwrap();
    let applied = apply(set, &mut p.archive);
    let e = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == name)
        .expect("the member");
    Out {
        body: e.body_bytes().unwrap().into_owned(),
        dirty: e.is_dirty(),
        applied,
    }
}

/// The whole `nupkg` profile over a package holding one assembly, as the stabilized bytes a
/// digest is taken over.
fn nupkg_stabilized(dll: &[u8]) -> (Vec<u8>, Vec<Applied>) {
    let mut notes: Vec<Note> = Vec::new();
    let pkg = zip(&[
        (
            "Demo.nuspec",
            b"<package><metadata><id>Demo</id></metadata></package>",
        ),
        (DLL, dll),
    ]);
    let mut p = parse(pkg, Format::Zip, &Limits::default(), &mut notes).unwrap();
    let applied = apply(&profile("nupkg").unwrap(), &mut p.archive);
    (serialize(&p.archive, true).unwrap(), applied)
}

fn assert_left_whole(out: &Out, input: &[u8], why: &str) {
    assert!(
        out.body == input,
        "{why}: the assembly was rewritten ({} bytes in, {} out)",
        input.len(),
        out.body.len()
    );
    assert!(
        !out.dirty,
        "{why}: the member was promoted and marked changed"
    );
    assert!(
        out.applied.is_empty(),
        "{why}: a pass claimed work: {:?}",
        out.applied
    );
}

// --- dotnet-il-canonical-v2: what the form is ----------------------------------------------------

#[test]
fn an_assembly_reduces_to_its_methods_and_what_their_tokens_name() {
    let asm = Asm::default();
    let bytes = asm.bytes();
    let out = run(&only(CANONICAL), DLL, &bytes);
    assert_eq!(
        String::from_utf8_lossy(&out.body),
        String::from_utf8_lossy(&asm.canonical()),
        "the form is the methods in table order, the rows their tokens name, the literals, and \
         nothing else"
    );
    // A tiny body, a fat body and a body-less method are each read for what they are: the fat
    // body's IL follows its twelve-byte header, and the abstract method still names itself, its
    // ImplFlags and Flags and its first parameter row, and says it has no body, just before the
    // first kept table: TypeRef's two rows.
    assert!(
        out.body
            .windows(5)
            .any(|w| w == [0x1f, 0x2a, 0x0a, 0x06, 0x2a])
    );
    let hook = b"\x04\0\0\0Hook\x03\0\0\0\x00\x00\x01\x00\x00\x86\x00\x01\0\0\0\x00\x01\x02\0\0\0";
    assert!(out.body.windows(hook.len()).any(|w| w == hook));
    // And the literals `ldstr` reads come last, whole.
    let mut us = vec![0x70];
    us.extend_from_slice(&(asm.user_string_heap().len() as u32).to_le_bytes());
    us.extend_from_slice(&asm.user_string_heap());
    assert!(out.body.ends_with(&us));

    let [a] = out.applied.as_slice() else {
        panic!("one pass fired: {:?}", out.applied)
    };
    assert_eq!(a.id.as_str(), CANONICAL);
    assert_eq!(a.entries_touched, 1);
    assert_eq!(a.bytes_changed, out.body.len() as u64);
}

#[test]
fn a_match_through_the_canonical_form_is_never_clean() {
    // It drops resources, custom attributes and field data, so a match it makes is
    // `normalized_with_caveats`. The tier is what carries that into the verdict.
    let out = run(&only(CANONICAL), DLL, &Asm::default().bytes());
    assert_eq!(out.applied[0].risk, RiskTier::Lossy);
}

#[test]
fn assemblies_differing_only_in_layout_and_build_identity_stabilize_identically() {
    // The moq case (docs/16-findings.md §3.87): the method IL byte for byte equal, and the whole
    // divergence heap offsets that moved, a different MVID, PDB path, strong-name signature and
    // build stamp, `#Blob` indexes a width wider or narrower, which moves every row from Field on,
    // and more rows in a table the form drops (CustomAttribute), which moves every table after it.
    let a = Asm::default();
    let b = a.rebuilt_elsewhere();
    let (ra, rb) = (a.bytes(), b.bytes());
    assert_ne!(ra, rb);
    assert_ne!(ra.len(), rb.len(), "the layouts really differ");

    let (sa, applied) = nupkg_stabilized(&ra);
    let (sb, _) = nupkg_stabilized(&rb);
    assert!(sa == sb, "two builds of the same code did not agree");
    let worst = applied.iter().map(|x| x.risk).max().unwrap();
    assert_eq!(
        worst,
        RiskTier::Lossy,
        "the match must carry its caveat: {applied:?}"
    );
}

#[test]
fn stabilizing_a_package_twice_changes_nothing_the_second_time() {
    // The canonical form is not a PE, so the second run must decline it rather than read it as
    // one. `stab(stab(x)) == stab(x)` is what a signed digest rests on.
    let (once, _) = nupkg_stabilized(&Asm::default().bytes());
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(once.clone(), Format::Zip, &Limits::default(), &mut notes).unwrap();
    let again = apply(&profile("nupkg").unwrap(), &mut p.archive);
    assert_eq!(serialize(&p.archive, true).unwrap(), once);
    assert!(again.is_empty(), "a second pass reported work: {again:?}");
}

// --- dotnet-il-canonical-v2: a real code difference still shows ----------------------------------

/// Two assemblies, laid out identically, that `dotnet-il-canonical-v2` must still tell apart.
fn assert_code_difference_shows(what: &str, edit: impl Fn(&mut Asm)) {
    assert_code_difference_shows_against(&Asm::default(), what, edit);
}

/// The same, from a starting assembly the case chooses.
fn assert_code_difference_shows_against(a: &Asm, what: &str, edit: impl Fn(&mut Asm)) {
    let mut b = a.clone();
    edit(&mut b);
    let (sa, _) = nupkg_stabilized(&a.bytes());
    let (sb, _) = nupkg_stabilized(&b.bytes());
    assert!(
        sa != sb,
        "{what} was normalized away: a changed program reported as reproduced"
    );
    // And from the other side of the comparison too: rebuilt elsewhere, the difference is still
    // the one thing left.
    let (sc, _) = nupkg_stabilized(&b.rebuilt_elsewhere().bytes());
    assert!(
        sa != sc,
        "{what} was normalized away once the layout also moved"
    );
    assert!(sb == sc, "the fixture itself changed more than {what}");
}

#[test]
fn a_changed_method_body_still_shows() {
    assert_code_difference_shows("a changed tiny body", |b| {
        b.methods[1].code = Code::Tiny(vec![0x14, 0x2a]);
    });
    assert_code_difference_shows("a changed fat body", |b| {
        b.methods[2].code = Code::Fat(vec![0x1f, 0x2b, 0x0a, 0x06, 0x2a]);
    });
    assert_code_difference_shows("a body given to an abstract method", |b| {
        b.methods[3].code = Code::Tiny(vec![0x2a]);
    });
    // No body and a body of no instructions are different methods, and a record that wrote
    // nothing for either could not say which one it read.
    assert_code_difference_shows("an empty body given to an abstract method", |b| {
        b.methods[3].code = Code::Tiny(Vec::new());
    });
}

#[test]
fn a_changed_signature_still_shows() {
    assert_code_difference_shows("a changed signature", |b| {
        b.methods[1].sig = SIG_STATIC_INT.to_vec();
    });
}

#[test]
fn a_renamed_method_still_shows() {
    assert_code_difference_shows("a renamed method", |b| b.methods[1].name = "Walk".into());
}

#[test]
fn an_added_or_removed_method_still_shows() {
    assert_code_difference_shows("an added method", |b| {
        b.methods.push(tiny("Backdoor", SIG_VOID, &[0x2a]));
    });
    assert_code_difference_shows("a removed method", |b| {
        b.methods.remove(1);
    });
}

// An IL token is a row number, or an offset into `#US`, so what a body does depends on the row or
// the literal it names as much as on its own bytes. Each case below changes only what a token
// names, and leaves every byte of every body as it was.

#[test]
fn a_changed_string_literal_still_shows() {
    // `ldstr` names its literal by offset, and a literal of the same length keeps every offset.
    let mut a = Asm::default();
    a.methods[1].code = Code::Tiny(LDSTR_FIRST.to_vec());
    assert_code_difference_shows_against(&a, "a same-length ldstr literal", |b| {
        b.user_strings[0] = "Hello, World".into();
    });
}

#[test]
fn a_member_reference_changed_under_its_token_still_shows() {
    // `.ctor` calls MemberRef 1, `Object::.ctor`. Each edit makes that call something else.
    assert_code_difference_shows("a MemberRef renamed under the same token", |b| {
        b.member_refs[0].1 = "Finalize".into();
    });
    assert_code_difference_shows("a MemberRef moved to another type", |b| {
        b.member_refs[0].0 = member_parent_typeref(2);
    });
    assert_code_difference_shows("a MemberRef given another signature", |b| {
        b.member_refs[0].2 = SIG_INSTANCE_INT.to_vec();
    });
    assert_code_difference_shows("the TypeRef a MemberRef names, renamed", |b| {
        b.typeref_names[0] = "Activator".into();
    });
    assert_code_difference_shows("the assembly a TypeRef resolves in, renamed", |b| {
        b.assembly_refs[0].0 = "System.Runtime.Evil".into();
    });
    assert_code_difference_shows("the assembly a TypeRef resolves in, another version", |b| {
        b.assembly_refs[0].1 = [9, 0, 0, 0];
    });
}

#[test]
fn a_changed_method_flag_still_shows() {
    // Flags and ImplFlags decide who can call a method and how it is dispatched and run.
    assert_code_difference_shows("a public method made private", |b| {
        b.methods[1].flags = (PUBLIC_HIDEBYSIG & !0x0007) | 0x0001;
    });
    assert_code_difference_shows("a method made virtual", |b| {
        b.methods[1].flags |= 0x0040;
    });
    assert_code_difference_shows("a method made synchronized", |b| {
        b.methods[1].impl_flags = 0x0020;
    });
}

#[test]
fn a_changed_catch_clause_still_shows() {
    // An exception-handling section sits after the code, and its clause names the type it catches
    // by token: which exceptions a method handles is part of what it does.
    let il = vec![0x00, 0x26, 0x2a];
    let mut a = Asm::default();
    a.methods[2].code = Code::Guarded(il.clone(), 0x0100_0002);
    assert_code_difference_shows_against(&a, "a catch clause's type changed", |b| {
        b.methods[2].code = Code::Guarded(il.clone(), 0x0100_0001);
    });
    assert_code_difference_shows_against(&a, "the caught type renamed under its token", |b| {
        b.typeref_names[1] = "ArgumentException".into();
    });
    assert_code_difference_shows_against(&a, "the catch clause removed", |b| {
        b.methods[2].code = Code::Fat(il.clone());
    });
}

#[test]
fn a_changed_fat_header_or_local_signature_still_shows() {
    // The fat header carries the stack depth, whether locals start zeroed, and the token of the
    // signature that types them.
    assert_code_difference_shows("a changed MaxStack", |b| b.fat_header.1 = 1);
    assert_code_difference_shows("InitLocals cleared", |b| b.fat_header.0 &= !0x0010);
    assert_code_difference_shows("a local retyped under the same token", |b| {
        b.standalone_sigs[0] = vec![0x07, 0x01, 0x0e];
    });
    assert_code_difference_shows("the locals given another signature's token", |b| {
        b.standalone_sigs.push(vec![0x07, 0x01, 0x0e]);
        b.fat_header.2 = 0x1100_0002;
    });
}

#[test]
fn a_method_moved_to_another_type_or_a_changed_base_type_still_shows() {
    // A TypeDef owns the methods from its MethodList up to the next type's, so moving that
    // boundary changes which type a method is declared on without changing the method.
    let mut a = Asm::default();
    let program = ("Program".to_string(), typedef_or_ref_typeref(1), 3);
    a.types.push(program);
    assert_code_difference_shows_against(&a, "a method moved into another type", |b| {
        b.types[1].2 = 2;
    });
    assert_code_difference_shows_against(&a, "a type given another base", |b| {
        b.types[1].1 = typedef_or_ref_typeref(2);
    });
}

// What code does when it runs also turns on declarations no token in a body names: the native
// function a P/Invoke calls, the method that implements an interface method or an override, the
// interfaces a type implements. Each case below changes one of those and leaves every body and
// every row a token names as it was.

#[test]
fn a_changed_pinvoke_target_still_shows() {
    let a = Asm::declaring();
    assert_code_difference_shows_against(&a, "a P/Invoke bound to another entry point", |b| {
        b.impl_maps[0].2 = "system".into();
    });
    assert_code_difference_shows_against(&a, "a P/Invoke marshalling strings otherwise", |b| {
        b.impl_maps[0].0 |= 0x0004; // `charset unicode`
    });
    let mut two_libraries = a.clone();
    two_libraries.module_refs.push("libevil".into());
    assert_code_difference_shows_against(
        &two_libraries,
        "a P/Invoke bound to the same entry point in another library",
        |b| b.impl_maps[0].3 = 2,
    );
}

#[test]
fn a_changed_explicit_override_still_shows() {
    let a = Asm::declaring();
    assert_code_difference_shows_against(&a, "another method made the implementation", |b| {
        b.method_impls[0].1 = method_def_or_ref_def(3);
    });
    assert_code_difference_shows_against(&a, "the implementation of another method", |b| {
        b.method_impls[0].2 = method_def_or_ref_def(1);
    });
}

#[test]
fn a_changed_implemented_interface_still_shows() {
    let a = Asm::declaring();
    assert_code_difference_shows_against(&a, "another interface implemented", |b| {
        b.interface_impls[0].1 = typedef_or_ref_typeref(2);
    });
    assert_code_difference_shows_against(&a, "an interface no longer implemented", |b| {
        b.interface_impls.clear();
    });
}

// A signature blob and an IL body may each hold any byte, NUL and newline included, so a record
// has to say where each of its fields ends. The two cases below are edits a publisher chooses to
// make the records of a changed program spell the records of the original.

#[test]
fn a_body_shifted_into_its_signature_still_shows() {
    // `Run` calls a method and returns. The changed build drops the call, and carries its bytes
    // as the tail of the signature instead, where the runtime never executes them.
    let mut a = Asm::default();
    a.methods[1].code = Code::Tiny(vec![0x28, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x2a]);
    assert_code_difference_shows_against(&a, "a call moved into the signature", |b| {
        b.methods[1].sig = vec![0x00, 0x00, 0x01, 0x00, 0x28, 0x01, 0x00, 0x00, 0x0a];
        b.methods[1].code = Code::Tiny(vec![0x2a]);
    });
}

#[test]
fn a_method_folded_into_its_neighbours_body_still_shows() {
    // `Run` is removed, and the bytes of its record are appended to `.ctor`'s body, after the
    // `ret` that ends it.
    assert_code_difference_shows("a method folded into the one before it", |b| {
        let removed = b.methods.remove(1);
        let Code::Tiny(il) = &mut b.methods[0].code else {
            panic!("`.ctor` has a tiny body")
        };
        il.extend_from_slice(b"\nRun\0");
        il.extend_from_slice(&removed.sig);
        il.push(0);
        il.extend_from_slice(&[0x00, 0x2a]);
    });
}

// --- dotnet-il-canonical-v2: every layout ECMA-335 allows is read at its real widths -------------

/// Read through the pass, `asm` must reduce to exactly its own methods: a row or index read at
/// the wrong width lands on the wrong bytes, and the names that come out are garbage.
fn assert_reads_back(what: &str, asm: &Asm) {
    let out = run(&only(CANONICAL), DLL, &asm.bytes());
    assert!(
        out.body == asm.canonical(),
        "{what}: read back as {:?}",
        String::from_utf8_lossy(&out.body[..out.body.len().min(200)])
    );
}

#[test]
fn a_pe32_plus_assembly_is_read_like_a_pe32_one() {
    // The optional header is 16 bytes longer, so the data directories move. Whether a PE32 and a
    // PE32+ build of the same IL should agree is not asserted: the form records no platform, and
    // nothing promises that leaving it out is right.
    let asm = Asm {
        pe32_plus: true,
        ..Asm::default()
    };
    assert_reads_back("PE32+", &asm);
}

#[test]
fn wide_heap_indexes_are_read_at_their_width() {
    for heap_sizes in [0x01, 0x02, 0x04, 0x07] {
        let asm = Asm {
            heap_sizes,
            ..Asm::default()
        };
        assert_reads_back(&format!("HeapSizes {heap_sizes:#04x}"), &asm);
    }
}

#[test]
fn the_declarations_are_read_at_their_real_widths_too() {
    for heap_sizes in [0x00, 0x01, 0x04, 0x07] {
        let asm = Asm {
            heap_sizes,
            ..Asm::declaring()
        };
        assert_reads_back(&format!("declarations, HeapSizes {heap_sizes:#04x}"), &asm);
    }
}

#[test]
fn a_large_table_widens_every_index_that_can_point_at_it() {
    // A simple index is four bytes once its table outgrows a u16; a coded index once its largest
    // table outgrows the bits the tag leaves. Each case widens a different column of a row the
    // reader has to step over or read to reach the methods.
    let cases: Vec<(&str, Asm)> = vec![
        (
            // TypeRef's own ResolutionScope, and TypeDef's Extends.
            "16384 TypeRefs",
            Asm {
                typeref_rows: 1 << 14,
                ..Asm::default()
            },
        ),
        (
            // TypeDef's FieldList.
            "65536 Fields",
            Asm {
                field_rows: 1 << 16,
                ..Asm::default()
            },
        ),
        (
            // MethodDef's own ParamList: the stride between method rows.
            "65536 Params",
            Asm {
                declared: vec![(0x08, 1 << 16)],
                ..Asm::default()
            },
        ),
        (
            "16384 AssemblyRefs",
            Asm {
                assembly_refs: vec![("System.Runtime".into(), [8, 0, 0, 0]); 1 << 14],
                ..Asm::default()
            },
        ),
        (
            "16384 ModuleRefs",
            Asm {
                declared: vec![(0x1a, 1 << 14)],
                ..Asm::default()
            },
        ),
        (
            "16384 TypeSpecs",
            Asm {
                declared: vec![(0x1b, 1 << 14)],
                ..Asm::default()
            },
        ),
        (
            // One short of each threshold: still two bytes wide.
            "16383 TypeRefs, 65535 Fields and Params",
            Asm {
                typeref_rows: (1 << 14) - 1,
                field_rows: (1 << 16) - 1,
                declared: vec![(0x08, (1 << 16) - 1)],
                ..Asm::default()
            },
        ),
    ];
    for (what, asm) in cases {
        assert_reads_back(what, &asm);
    }
}

#[test]
fn the_uncompressed_table_stream_is_read_too() {
    // `#-`, with the FieldPtr and MethodPtr indirection tables in front of the methods.
    let asm = Asm {
        uncompressed: true,
        field_rows: 3,
        ..Asm::default()
    };
    assert_reads_back("#- with FieldPtr and MethodPtr", &asm);
}

#[test]
fn a_long_signature_is_read_whole_through_its_length_prefix() {
    // A blob's length is one, two or four bytes. Reading the prefix wrong truncates the
    // signature, and a truncated signature hides a changed parameter type at its end.
    for len in [0x7f, 0x80, 0x3fff, 0x4000, 20_000] {
        let mut sig = vec![0x00, 0x7f];
        sig.resize(len, 0x08);
        let mut asm = Asm::default();
        asm.methods[1].sig = sig.clone();
        assert_reads_back(&format!("a {len}-byte signature"), &asm);

        let mut other = asm.clone();
        *other.methods[1].sig.last_mut().unwrap() = 0x0e;
        let (sa, _) = nupkg_stabilized(&asm.bytes());
        let (sb, _) = nupkg_stabilized(&other.bytes());
        assert!(
            sa != sb,
            "the last byte of a {len}-byte signature was not compared"
        );
    }
}

#[test]
fn an_assembly_with_no_methods_reduces_to_a_form_with_no_method_records() {
    // No MethodDef table at all: an assembly of types and resources. Its form has no method
    // records, only the rows and literals it declares, which is a valid form and not a refusal.
    let asm = Asm {
        methods: Vec::new(),
        ..Asm::default()
    };
    let out = run(&only(CANONICAL), DLL, &asm.bytes());
    assert!(
        out.body.starts_with(&[0x06, 0, 0, 0, 0, 0x01]),
        "{:?}",
        out.body
    );
    assert!(out.body == asm.canonical(), "{:?}", out.body);
    assert_eq!(out.applied.len(), 1, "{:?}", out.applied);
}

// --- dotnet-il-canonical-v2: an assembly it cannot read whole is left exactly as it was ----------

#[test]
fn a_member_named_like_something_else_is_not_read_as_an_assembly() {
    let bytes = Asm::default().bytes();
    for name in [
        "lib/net8.0/Demo.pdb",
        "lib/net8.0/Demo.dll.config",
        "content/Demo.bin",
    ] {
        let out = run(&profile("nupkg").unwrap(), name, &bytes);
        assert!(out.body == bytes, "`{name}` was rewritten");
    }
    // The extension is matched without regard to case, as the file system that loads it would.
    for name in ["lib/net8.0/DEMO.DLL", "tools/demo.exe"] {
        let out = run(&only(CANONICAL), name, &bytes);
        assert!(
            out.body == Asm::default().canonical(),
            "`{name}` was not read"
        );
    }
}

/// Every corruption below leaves the assembly unreadable as a whole, so the pass must decline
/// it — the bytes compared as they are — rather than emit a form built from a guess.
#[test]
fn an_assembly_it_cannot_read_whole_is_left_exactly_as_it_was() {
    let (good, lay) = Asm::default().build();
    let stream = |name: &str| lay.stream_names.iter().find(|(n, _)| n == name).unwrap().1;
    type Corrupt = Box<dyn Fn(&mut Vec<u8>)>;
    let cases: Vec<(&str, Corrupt)> = vec![
        ("no MZ", Box::new(|b: &mut Vec<u8>| b[0] = b'Z')),
        (
            "e_lfanew past the end",
            Box::new(|b: &mut Vec<u8>| set32(b, 0x3c, 0xffff_ff00)),
        ),
        ("no PE signature", {
            let at = lay.pe_sig;
            Box::new(move |b: &mut Vec<u8>| b[at + 1] = b'X')
        }),
        ("an optional header neither PE32 nor PE32+", {
            let at = lay.opt_magic;
            Box::new(move |b: &mut Vec<u8>| set16(b, at, 0x107))
        }),
        ("a native image: no CLI header", {
            let at = lay.cli_dir;
            Box::new(move |b: &mut Vec<u8>| set32(b, at, 0))
        }),
        ("a CLI header outside every section", {
            let at = lay.cli_dir;
            Box::new(move |b: &mut Vec<u8>| set32(b, at, 0x0090_0000))
        }),
        // Below the section rather than past it. The section lookup computed `rva - vaddr` before
        // it had checked the order, and release builds check overflow: a panic, not a decline.
        ("a CLI header below its section", {
            let at = lay.cli_dir;
            Box::new(move |b: &mut Vec<u8>| set32(b, at, 0x100))
        }),
        ("no section table at all", {
            let at = lay.num_sections;
            Box::new(move |b: &mut Vec<u8>| set16(b, at, 0))
        }),
        ("metadata without its BSJB signature", {
            let at = lay.metadata;
            Box::new(move |b: &mut Vec<u8>| b[at] = b'X')
        }),
        ("no #Blob stream", {
            let at = stream("#Blob");
            Box::new(move |b: &mut Vec<u8>| b[at + 1] = b'b')
        }),
        ("no #Strings stream", {
            let at = stream("#Strings");
            Box::new(move |b: &mut Vec<u8>| b[at + 1] = b's')
        }),
        ("no table stream", {
            let at = stream("#~");
            Box::new(move |b: &mut Vec<u8>| b[at + 1] = b'!')
        }),
        ("cut off inside the MethodDef rows", {
            let at = lay.method_rows + lay.method_row_size + 3;
            Box::new(move |b: &mut Vec<u8>| b.truncate(at))
        }),
        // After every method body and row: what the tokens name is part of the form, so rows the
        // file does not hold leave it unreadable too.
        ("cut off inside the MemberRef rows", {
            let at = lay.member_ref_rows + 3;
            Box::new(move |b: &mut Vec<u8>| b.truncate(at))
        }),
        ("a #US stream that runs past the file", {
            let at = stream("#US") - 4;
            Box::new(move |b: &mut Vec<u8>| set32(b, at, 0x0100_0000))
        }),
        ("cut off inside the table stream header", {
            let at = lay.method_count;
            Box::new(move |b: &mut Vec<u8>| b.truncate(at))
        }),
        ("cut off inside the stream directory", {
            let at = stream("#GUID");
            Box::new(move |b: &mut Vec<u8>| b.truncate(at))
        }),
    ];
    for (what, corrupt) in cases {
        let mut bad = good.clone();
        corrupt(&mut bad);
        let out = run(&only(CANONICAL), DLL, &bad);
        assert_left_whole(&out, &bad, what);
    }
}

/// `asm`, with method `i`'s guarded body copied into a second section, mapped at 0x10_0000 and
/// appended to the file, and the method pointed at the copy. That section maps the whole body,
/// and the file holds the whole body, but `backed` of the body's `len` bytes decides how many of
/// them the section's `SizeOfRawData` says the loader copies from the file.
fn body_in_a_section_of_its_own(asm: &Asm, i: usize, backed: impl Fn(usize) -> usize) -> Vec<u8> {
    let Code::Guarded(il, _) = &asm.methods[i].code else {
        panic!("method {i} has a guarded body")
    };
    // The header, the IL, padding to a 4-byte boundary, then the one 16-byte handler section.
    let len = (12 + il.len()).next_multiple_of(4) + 16;
    let (mut f, lay) = asm.build();
    let row = lay.method_rows + i * lay.method_row_size;
    let rva = u32::from_le_bytes(f[row..row + 4].try_into().unwrap());
    let at = (rva - SECTION_RVA) as usize + SECTION_RAW;
    let body = f[at..at + len].to_vec();
    let raw = f.len().next_multiple_of(0x200);
    f.resize(raw, 0);
    f.extend_from_slice(&body);

    let sh = lay.cli_dir + 8 * 2 + 40; // the section table follows directory 15; its second header
    f[sh..sh + 6].copy_from_slice(b".text2");
    set32(&mut f, sh + 8, len as u32); // VirtualSize
    set32(&mut f, sh + 12, 0x0010_0000); // VirtualAddress
    set32(&mut f, sh + 16, backed(len) as u32); // SizeOfRawData
    set32(&mut f, sh + 20, raw as u32); // PointerToRawData
    set32(&mut f, sh + 36, 0x6000_0020);
    set16(&mut f, lay.num_sections, 2);
    set32(&mut f, row, 0x0010_0000);
    f
}

#[test]
fn a_body_is_read_only_as_far_as_the_file_backs_its_section() {
    // Past `SizeOfRawData` the loader maps zeros, whatever the file holds next. A catch clause the
    // file holds past that line is one the runtime never sees, and the method runs without it; read
    // from the file anyway, an assembly cut there and one whose section backs the whole clause
    // shared a form while running different code.
    let mut asm = Asm::default();
    asm.methods[2].code = Code::Guarded(vec![0x00, 0x26, 0x2a], 0x0100_0002);
    let whole = body_in_a_section_of_its_own(&asm, 2, |len| len);
    assert!(
        run(&only(CANONICAL), DLL, &whole).body == asm.canonical(),
        "the body is read through the section it was moved to"
    );
    for (what, cut) in [
        ("inside the catch clause", 8),
        ("at the handler section's header", 16),
        ("inside the IL", 18),
    ] {
        let bad = body_in_a_section_of_its_own(&asm, 2, |len| len - cut);
        let out = run(&only(CANONICAL), DLL, &bad);
        assert_left_whole(&out, &bad, &format!("SizeOfRawData ending {what}"));
    }

    // The metadata likewise: the last heap, cut short by its section's `SizeOfRawData`, ends in
    // zeros where the runtime reads it, and in an AssemblyRef's public-key token.
    let (mut bad, lay) = Asm::default().build();
    let sh = lay.cli_dir + 8 * 2;
    let backed = u32::from_le_bytes(bad[sh + 16..sh + 20].try_into().unwrap());
    set32(&mut bad, sh + 16, backed - 12);
    let out = run(&only(CANONICAL), DLL, &bad);
    assert_left_whole(&out, &bad, "SizeOfRawData ending inside #Blob");
}

#[test]
fn a_method_whose_body_is_native_code_is_not_read_as_il() {
    // A mixed-mode assembly's C++ methods carry machine code, which the runtime runs as it stands.
    // Whatever its first byte parsed as, a tiny or a fat header, the form held a few bytes of it as
    // IL and none of the rest: another native method would have read the same.
    let mut asm = Asm::default();
    asm.methods[1].impl_flags = 0x0001; // `native`
    let bytes = asm.bytes();
    let out = run(&only(CANONICAL), DLL, &bytes);
    assert_left_whole(&out, &bytes, "a method of native code");
}

#[test]
fn a_method_count_larger_than_the_file_is_declined_without_allocating_for_it() {
    // MethodDef's row count is a u32 the file states. Trusted as a capacity it asked the
    // allocator for 24 bytes a row — about 100 GB here — and a verifier fed this `.dll` inside a
    // package aborted with "memory allocation failed" before it had read one row.
    let (mut bad, lay) = Asm::default().build();
    set32(&mut bad, lay.method_count, u32::MAX);
    let out = run(&only(CANONICAL), DLL, &bad);
    assert_left_whole(&out, &bad, "a MethodDef count of u32::MAX");
}

#[test]
fn records_that_repeat_one_heap_entry_without_bound_are_declined() {
    // Every MethodDef row may name the same `#Strings` offset, and nothing bounds how long the
    // string there is. Pointed at one long entry, N rows copy it N times: the form grows as rows
    // times file, not with the file. This one is about 500 KB and would expand to about 500 MB;
    // scaled up, a package of them exhausts a verifier's memory. An assembly whose code is
    // hundreds of times its own size is not one this pass can honestly reduce, so it declines.
    let long = "L".repeat(64 * 1024);
    let mut methods = vec![tiny(&long, SIG_VOID, &[0x2a])];
    methods.extend((1..8000).map(|_| tiny("m", SIG_VOID, &[0x2a])));
    let (mut bad, lay) = Asm {
        methods,
        heap_sizes: 0x01,
        ..Asm::default()
    }
    .build();
    // The builder interns each name once; point every row at the long one instead, the way a
    // crafted file would, so the file itself stays small.
    let first = lay.method_rows + 8;
    let name = u32::from_le_bytes(bad[first..first + 4].try_into().unwrap());
    for i in 1..8000 {
        set32(
            &mut bad,
            lay.method_rows + i * lay.method_row_size + 8,
            name,
        );
    }
    assert!(
        bad.len() < 1 << 20,
        "the fixture is meant to be small: {}",
        bad.len()
    );
    let out = run(&only(CANONICAL), DLL, &bad);
    assert_left_whole(&out, &bad, "rows that all name one 64 KB string");
}

// --- dotnet-assembly-identity --------------------------------------------------------------------

#[test]
fn builds_differing_only_in_build_identity_agree_after_the_identity_pass() {
    // castle.core's residual (docs/16-findings.md §3.81): a strong-name signature made with a key
    // we do not have, an MVID, build stamps, and debug data naming where the PDB was written.
    let a = Asm::default();
    let b = Asm {
        mvid: [0x22; 16],
        timestamp: 0x7000_0001,
        checksum: 0x000f_eeee,
        strong_name: Some(vec![0xa5; 128]),
        debug: vec![(0x7000_0001, codeview(b"/home/carol/src/Demo/obj/Demo.pdb"))],
        ..a.clone()
    };
    let (ra, rb) = (a.bytes(), b.bytes());
    assert_eq!(ra.len(), rb.len(), "fixed-location identity only");
    assert_ne!(ra, rb);

    let oa = run(&only(IDENTITY), DLL, &ra);
    let ob = run(&only(IDENTITY), DLL, &rb);
    assert!(
        oa.body == ob.body,
        "identity-only differences survived the identity pass"
    );
    assert_eq!(
        oa.body.len(),
        ra.len(),
        "zeroed in place, so the member keeps its length"
    );
    let [x] = oa.applied.as_slice() else {
        panic!("{:?}", oa.applied)
    };
    assert_eq!(x.id.as_str(), IDENTITY);
    assert_eq!(
        x.risk,
        RiskTier::Metadata,
        "bookkeeping, so a clean `normalized` stays reachable"
    );
}

#[test]
fn the_identity_pass_zeroes_its_named_regions_and_nothing_else() {
    for pe32_plus in [false, true] {
        let asm = Asm {
            pe32_plus,
            debug: vec![
                (0x6543_2100, codeview(b"/src/obj/Demo.pdb")),
                (0x6543_2101, vec![0xee; 24]),
            ],
            ..Asm::default()
        };
        let (before, lay) = asm.build();
        let out = run(&only(IDENTITY), DLL, &before);
        let after = &out.body;
        assert_eq!(after.len(), before.len());

        let regions = lay.identity_regions();
        let inside = |i: usize| regions.iter().any(|&(o, l)| i >= o && i < o + l);
        for &(o, l) in &regions {
            assert!(
                after[o..o + l].iter().all(|&x| x == 0),
                "PE32+ {pe32_plus}: region {o:#x}+{l} was not zeroed"
            );
        }
        let stray: Vec<usize> = (0..before.len())
            .filter(|&i| before[i] != after[i] && !inside(i))
            .collect();
        assert!(
            stray.is_empty(),
            "PE32+ {pe32_plus}: bytes outside the named regions changed at {stray:x?}"
        );
        let zeroed = (0..before.len()).filter(|&i| before[i] != after[i]).count() as u64;
        assert_eq!(
            out.applied[0].bytes_changed, zeroed,
            "Touched counts the bytes it zeroed"
        );
    }
}

#[test]
fn an_assembly_whose_code_is_in_its_second_section_is_still_walked() {
    // Every RVA is resolved through whichever section maps it, not through the first: here a
    // resource section is listed ahead of `.text`, as a linker is free to list it.
    let (mut bytes, lay) = Asm::default().build();
    let sh = lay.cli_dir + 8 * 2; // directory 14 is the CLI header; the section table follows 15
    bytes.copy_within(sh..sh + 40, sh + 40);
    let mut rsrc = [0u8; 40];
    rsrc[..5].copy_from_slice(b".rsrc");
    set32(&mut rsrc, 8, 0x100); // VirtualSize
    set32(&mut rsrc, 12, 0x1000); // VirtualAddress, below `.text`
    set32(&mut rsrc, 16, 0x100); // SizeOfRawData
    set32(&mut rsrc, 20, 0x100); // PointerToRawData, in the headers' padding
    bytes[sh..sh + 40].copy_from_slice(&rsrc);
    set16(&mut bytes, lay.num_sections, 2);

    let out = run(&only(IDENTITY), DLL, &bytes);
    for (o, l) in lay.identity_regions() {
        assert!(
            out.body[o..o + l].iter().all(|&x| x == 0),
            "region {o:#x}+{l} was not zeroed"
        );
    }
}

#[test]
fn a_guid_heap_listed_last_in_the_stream_directory_is_still_found() {
    // ECMA-335 fixes no order for the metadata streams, so the heap is found by its name wherever
    // the directory lists it: here after `#Blob` rather than before it.
    let (mut bytes, lay) = Asm::default().build();
    let header = |name: &str| lay.stream_names.iter().find(|(n, _)| n == name).unwrap().1 - 8;
    let (guid, blob) = (header("#GUID"), header("#Blob"));
    assert_eq!(
        blob,
        guid + 16,
        "the fixture lists `#Blob` right after `#GUID`"
    );
    let listed = bytes[guid..guid + 16].to_vec();
    bytes.copy_within(blob..blob + 16, guid);
    bytes[blob..blob + 16].copy_from_slice(&listed);

    let out = run(&only(IDENTITY), DLL, &bytes);
    let (g, gl) = lay.guid_heap;
    assert!(
        out.body[g..g + gl].iter().all(|&x| x == 0),
        "the MVID survived"
    );
}

#[test]
fn a_real_difference_survives_the_identity_pass() {
    // It zeroes identity by position; a changed instruction is at no position it names.
    let a = Asm::default();
    let mut b = a.clone();
    b.methods[1].code = Code::Tiny(vec![0x14, 0x2a]);
    let oa = run(&only(IDENTITY), DLL, &a.bytes());
    let ob = run(&only(IDENTITY), DLL, &b.bytes());
    assert!(oa.body != ob.body);
}

#[test]
fn an_assembly_with_no_identity_left_is_not_touched() {
    // Public-signed and deterministic already: nothing to zero, so the member stays on its
    // original body and the pass does not appear in `applied`.
    let asm = Asm {
        mvid: [0; 16],
        timestamp: 0,
        checksum: 0,
        strong_name: Some(vec![0; 128]),
        debug: Vec::new(),
        ..Asm::default()
    };
    let bytes = asm.bytes();
    let out = run(&only(IDENTITY), DLL, &bytes);
    assert_left_whole(&out, &bytes, "an assembly already free of identity");
}

#[test]
fn a_native_image_is_left_whole() {
    // No CLI header: not a managed assembly, so not this pass's to touch, stamp and all.
    let (mut bytes, lay) = Asm::default().build();
    set32(&mut bytes, lay.cli_dir, 0);
    let out = run(&only(IDENTITY), DLL, &bytes);
    assert_left_whole(&out, &bytes, "a native PE");

    for (what, bad) in [
        ("not a PE", b"MZ but nothing else of a PE".to_vec()),
        ("empty", Vec::new()),
    ] {
        let out = run(&only(IDENTITY), DLL, &bad);
        assert_left_whole(&out, &bad, what);
    }
}

#[test]
fn a_member_named_like_something_else_is_not_zeroed() {
    let bytes = Asm::default().bytes();
    let out = run(&only(IDENTITY), "lib/net8.0/Demo.xml", &bytes);
    assert_left_whole(&out, &bytes, "a non-assembly member");
}

#[test]
fn a_region_that_runs_past_the_file_is_skipped_and_the_rest_still_zeroed() {
    // A strong-name signature or debug data the headers place beyond the end is not zeroed —
    // there is nothing there — and must not stop the regions that are there from being zeroed.
    let (mut bytes, lay) = Asm::default().build();
    set32(&mut bytes, lay.cli_strong_name + 4, 0x0100_0000);
    let e = lay.debug_entries[0];
    set32(&mut bytes, e + 24, 0x0100_0000);
    let out = run(&only(IDENTITY), DLL, &bytes);

    let zero = |(o, l): (usize, usize)| out.body[o..o + l].iter().all(|&x| x == 0);
    assert!(zero((lay.timestamp, 4)) && zero((lay.checksum, 4)) && zero(lay.guid_heap));
    assert!(zero((e + 4, 4)), "the debug entry's own timestamp");
    let (sn, sn_len) = lay.strong_name.unwrap();
    assert!(
        !zero((sn, sn_len)),
        "a signature the header says runs past the file was zeroed"
    );
    assert!(
        !zero(lay.debug_data[0]),
        "debug data the entry says is past the file was zeroed"
    );

    // The #GUID heap likewise: a size running past the end names no heap, and the rest holds.
    let (mut bytes, lay) = Asm::default().build();
    let guid = lay
        .stream_names
        .iter()
        .find(|(n, _)| n == "#GUID")
        .unwrap()
        .1;
    set32(&mut bytes, guid - 4, 0x0100_0000);
    let out = run(&only(IDENTITY), DLL, &bytes);
    let (g, gl) = lay.guid_heap;
    assert_eq!(
        out.body[g..g + gl],
        bytes[g..g + gl],
        "a heap past the end was zeroed"
    );
    assert!(
        out.body[lay.timestamp..lay.timestamp + 4]
            .iter()
            .all(|&x| x == 0)
    );
}

#[test]
fn an_image_the_identity_pass_cannot_walk_is_left_whole() {
    // Every region is reached by walking the headers, so where the walk fails there is no region
    // it can name with confidence — not even the timestamp — and the member stays as it arrived.
    let (good, lay) = Asm::default().build();
    type Corrupt = Box<dyn Fn(&mut Vec<u8>)>;
    let cases: Vec<(&str, Corrupt)> = vec![
        ("no MZ", Box::new(|b: &mut Vec<u8>| b[1] = b'Q')),
        (
            "e_lfanew past the end",
            Box::new(|b: &mut Vec<u8>| set32(b, 0x3c, 0xffff_ff00)),
        ),
        ("no PE signature", {
            let at = lay.pe_sig;
            Box::new(move |b: &mut Vec<u8>| b[at] = b'N')
        }),
        ("an optional header neither PE32 nor PE32+", {
            let at = lay.opt_magic;
            Box::new(move |b: &mut Vec<u8>| set16(b, at, 0x107))
        }),
        ("a CLI header outside every section", {
            let at = lay.cli_dir;
            Box::new(move |b: &mut Vec<u8>| set32(b, at, 0x0090_0000))
        }),
        ("cut off inside the CLI header", {
            Box::new(move |b: &mut Vec<u8>| b.truncate(SECTION_RAW + 10))
        }),
    ];
    for (what, corrupt) in cases {
        let mut bad = good.clone();
        corrupt(&mut bad);
        let out = run(&only(IDENTITY), DLL, &bad);
        assert_left_whole(&out, &bad, what);
    }
}

#[test]
fn a_debug_directory_outside_every_section_clears_only_its_own_slot() {
    let (mut bytes, lay) = Asm::default().build();
    set32(&mut bytes, lay.debug_dir, 0x00a0_0000);
    let out = run(&only(IDENTITY), DLL, &bytes);
    assert!(
        out.body[lay.debug_dir..lay.debug_dir + 8]
            .iter()
            .all(|&x| x == 0)
    );
    assert_eq!(
        out.body[lay.debug_entries[0] + 4..lay.debug_entries[0] + 8],
        bytes[lay.debug_entries[0] + 4..lay.debug_entries[0] + 8],
        "an entry the directory no longer reaches was zeroed"
    );
    assert!(
        out.body[lay.timestamp..lay.timestamp + 4]
            .iter()
            .all(|&x| x == 0)
    );
}

#[test]
fn a_debug_directory_slot_naming_no_bytes_is_not_a_debug_directory() {
    // A data directory is present when it has both an address and a size. A slot with only one
    // names nothing to zero, so it is not build identity this pass may clear; the regions the
    // headers do reach are zeroed as ever.
    let (good, lay) = Asm {
        debug: Vec::new(),
        ..Asm::default()
    }
    .build();
    for (rva, size) in [(SECTION_RVA + 72, 0), (0, 28)] {
        let mut bytes = good.clone();
        set32(&mut bytes, lay.debug_dir, rva);
        set32(&mut bytes, lay.debug_dir + 4, size);
        let out = run(&only(IDENTITY), DLL, &bytes);
        assert_eq!(
            out.body[lay.debug_dir..lay.debug_dir + 8],
            bytes[lay.debug_dir..lay.debug_dir + 8],
            "RVA {rva:#x}, size {size}: the slot was cleared"
        );
        assert!(
            out.body[lay.timestamp..lay.timestamp + 4]
                .iter()
                .all(|&x| x == 0)
        );
    }
}

#[test]
fn a_debug_entry_with_no_data_in_the_file_names_no_bytes() {
    // PointerToRawData 0 is how an entry says its data is not in the file. Read as an offset it
    // would name the DOS header, and zero the `MZ` that makes this a PE at all.
    let (mut bytes, lay) = Asm::default().build();
    let e = lay.debug_entries[0];
    set32(&mut bytes, e + 24, 0);
    let out = run(&only(IDENTITY), DLL, &bytes);
    assert_eq!(out.body[..0x40], bytes[..0x40], "the DOS header was zeroed");
    assert!(
        out.body[e + 4..e + 8].iter().all(|&x| x == 0),
        "the entry's own timestamp is still build identity"
    );
}

#[test]
fn a_debug_directory_mapped_onto_the_files_first_bytes_is_walked_without_a_panic() {
    // A section table can map its section to file offset 0, and a debug directory at the start
    // of it then has its first entry at offset 0. Every offset the walk takes from there is a sum
    // of fields inside the file; one taken as a difference would fall below zero and trap under
    // the overflow checks release builds carry, on bytes the publisher chose.
    let (mut bytes, lay) = Asm::default().build();
    let sh = lay.cli_dir + 8 * 2; // directory 14 is the CLI header; the section table follows 15
    set32(&mut bytes, sh + 20, 0); // PointerToRawData
    set32(&mut bytes, lay.debug_dir, SECTION_RVA);
    set32(&mut bytes, lay.debug_dir + 4, 28);
    let out = run(&only(IDENTITY), DLL, &bytes);
    assert_eq!(out.body.len(), bytes.len(), "zeroing must not move a byte");
    assert_eq!(&out.body[..2], b"MZ");
}

#[test]
fn metadata_without_its_signature_keeps_its_guid_heap() {
    // The #GUID heap is found through the metadata root. Where the root is not one, no heap is
    // named — the other identity regions are still found by their headers.
    let (mut bytes, lay) = Asm::default().build();
    bytes[lay.metadata] = b'X';
    let out = run(&only(IDENTITY), DLL, &bytes);
    let (g, gl) = lay.guid_heap;
    assert_eq!(out.body[g..g + gl], bytes[g..g + gl]);
    assert!(
        out.body[lay.checksum..lay.checksum + 4]
            .iter()
            .all(|&x| x == 0)
    );
}

#[test]
fn an_rva_below_its_section_is_declined_rather_than_a_panic() {
    // Stabilizers are total. An RVA the headers place below the only section mapped nowhere, and
    // computing its offset anyway underflowed — a panic under the overflow checks release builds
    // carry, on bytes the publisher chose.
    let (good, lay) = Asm::default().build();

    let mut bad = good.clone();
    set32(&mut bad, lay.cli_dir, 0x100);
    let out = run(&only(IDENTITY), DLL, &bad);
    assert_left_whole(&out, &bad, "a CLI header below its section");

    // The metadata root and the debug directory are looked up the same way. Neither is found, so
    // neither's regions are named; the regions the headers do reach are still zeroed.
    let mut bad = good.clone();
    set32(&mut bad, SECTION_RAW + 8, 0x10);
    set32(&mut bad, lay.debug_dir, 0x10);
    let out = run(&only(IDENTITY), DLL, &bad);
    let (g, gl) = lay.guid_heap;
    assert_eq!(
        out.body[g..g + gl],
        bad[g..g + gl],
        "an unreachable #GUID heap was zeroed"
    );
    let e = lay.debug_entries[0];
    assert_eq!(
        out.body[e + 4..e + 8],
        bad[e + 4..e + 8],
        "an unreachable entry was zeroed"
    );
    assert!(
        out.body[lay.debug_dir..lay.debug_dir + 8]
            .iter()
            .all(|&x| x == 0)
    );
    assert!(
        out.body[lay.timestamp..lay.timestamp + 4]
            .iter()
            .all(|&x| x == 0)
    );
}

#[test]
fn debug_entries_naming_the_same_bytes_zero_them_and_count_each_byte_once() {
    // A debug directory names regions by file offset, and a crafted one can name the whole file
    // from every entry. Zeroed region by region that cost entries × file — half a second for this
    // 65 KB fixture in a debug build, growing with the square of the file — for the same bytes as
    // zeroing it once. This test holds the bytes and the count, which zeroing region by region
    // produced too; the merge that keeps it fast is held beside `dotnet_build_identity_regions`.
    let (mut bad, lay) = Asm {
        debug: vec![(1, vec![0xee; 4]); 2000],
        ..Asm::default()
    }
    .build();
    let len = bad.len() as u32;
    for &e in &lay.debug_entries {
        set32(&mut bad, e + 16, len - 1);
        set32(&mut bad, e + 24, 1);
    }
    let out = run(&only(IDENTITY), DLL, &bad);
    assert_eq!(out.body[0], b'M', "the one byte no entry names");
    assert!(
        out.body[1..].iter().all(|&x| x == 0),
        "every named byte is zeroed"
    );
    let nonzero = bad[1..].iter().filter(|&&x| x != 0).count() as u64;
    assert_eq!(
        out.applied[0].bytes_changed, nonzero,
        "each byte counted once"
    );
}

// --- totality over input nobody wrote by hand ----------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Stabilizers are total: whatever a publisher's bytes say, both passes return, and a pass
    /// that declines leaves the member as it arrived. Mutating a real assembly reaches every
    /// header field the passes trust, which a random byte string would almost never parse far
    /// enough to reach.
    #[test]
    fn both_passes_are_total_over_a_damaged_assembly(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        cut in any::<prop::sample::Index>(),
        truncate in any::<bool>(),
    ) {
        let (mut bytes, _) = Asm::default().build();
        for (at, v) in edits {
            let i = at.index(bytes.len());
            bytes[i] = v;
        }
        if truncate {
            let n = cut.index(bytes.len());
            bytes.truncate(n);
        }
        for pass in [IDENTITY, CANONICAL] {
            let out = run(&only(pass), DLL, &bytes);
            if out.applied.is_empty() {
                prop_assert!(out.body == bytes, "{pass} declined and still changed the bytes");
            }
            if pass == IDENTITY {
                prop_assert_eq!(out.body.len(), bytes.len(), "zeroing must not move a byte");
            }
        }
    }
}
