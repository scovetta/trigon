//! Managed (.NET) assemblies: `dotnet-assembly-identity` and `dotnet-il-canonical`.
//!
//! Both passes walk a PE by hand, through bytes the publisher wrote, and one of them decides
//! whether two assemblies are the same code. So the fixtures here are real managed PEs, assembled
//! byte by byte from ECMA-335 (Partition II §24–§25) rather than taken from the passes' own idea of
//! the layout: a reader that sized a row wrongly would agree with a writer that made the same
//! mistake, and agree with nothing a compiler emits.
//!
//! What they hold the passes to is what `passes.rs` and `docs/16-findings.md` §3.81/§3.89 promise:
//! code-identical assemblies reduce to the same bytes, a changed body, a new method or a changed
//! signature still shows, the identity pass zeroes its named regions and nothing else, and an
//! assembly either pass cannot read whole is left exactly as it was.

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
}

#[derive(Clone, Debug)]
struct Method {
    name: String,
    sig: Vec<u8>,
    code: Code,
}

fn tiny(name: &str, sig: &[u8], il: &[u8]) -> Method {
    Method {
        name: name.into(),
        sig: sig.to_vec(),
        code: Code::Tiny(il.to_vec()),
    }
}

/// `instance void (int32)`, `void ()` and `static int32 ()`, as a compiler writes them.
const SIG_INSTANCE_INT: &[u8] = &[0x20, 0x01, 0x01, 0x08];
const SIG_VOID: &[u8] = &[0x00, 0x00, 0x01];
const SIG_STATIC_INT: &[u8] = &[0x00, 0x00, 0x08];

#[derive(Clone, Debug)]
struct Asm {
    pe32_plus: bool,
    methods: Vec<Method>,
    /// `HeapSizes`: 0x01 wide `#Strings`, 0x02 wide `#GUID`, 0x04 wide `#Blob`.
    heap_sizes: u8,
    /// TypeRef rows, written. Enough of them widens every coded index that can name a TypeRef.
    typeref_rows: u32,
    /// Field rows, written (and FieldPtr rows too, in the uncompressed layout).
    field_rows: u32,
    /// Row counts for tables after `MethodDef`. Declared in the header only: a reader walking to
    /// `MethodDef` needs their sizes, because they decide how wide an index into them is, and has
    /// no business reading their rows.
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
                    code: Code::Fat(vec![0x1f, 0x2a, 0x0a, 0x06, 0x2a]),
                },
                Method {
                    name: "Hook".into(),
                    sig: SIG_VOID.to_vec(),
                    code: Code::Abstract,
                },
            ],
            heap_sizes: 0,
            typeref_rows: 2,
            field_rows: 1,
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
    /// The same code as `self`, compiled somewhere else: every piece of build identity and every
    /// layout offset differs, and not one method does.
    fn rebuilt_elsewhere(&self) -> Asm {
        Asm {
            string_pad: self.string_pad + 37,
            blob_pad: self.blob_pad + 11,
            code_pad: self.code_pad + 24,
            typeref_rows: self.typeref_rows + 3,
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
                Code::Fat(il) => {
                    align(&mut sec, 4);
                    rvas.push(SECTION_RVA + sec.len() as u32);
                    put16(&mut sec, 0x3013); // three dwords of header, fat, InitLocals
                    put16(&mut sec, 8); // MaxStack
                    put32(&mut sec, il.len() as u32);
                    put32(&mut sec, 0x1100_0001); // LocalVarSigTok
                    sec.extend_from_slice(il);
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
        let module_type = put_str(&mut strings, b"<Module>");
        let typeref_name = put_str(&mut strings, b"Object");
        let field_name = put_str(&mut strings, b"state");
        let names: Vec<u32> = self
            .methods
            .iter()
            .map(|m| put_str(&mut strings, m.name.as_bytes()))
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
        let guid = self.mvid.to_vec();
        let us = vec![0u8; 4];

        // The table stream (§II.24.2.6).
        let s = if self.heap_sizes & 0x01 != 0 { 4 } else { 2 };
        let g = if self.heap_sizes & 0x02 != 0 { 4 } else { 2 };
        let bw = if self.heap_sizes & 0x04 != 0 { 4 } else { 2 };
        let mut counts = [0u32; 64];
        counts[0x00] = 1;
        counts[0x01] = self.typeref_rows;
        counts[0x02] = 1;
        counts[0x04] = self.field_rows;
        counts[0x06] = self.methods.len() as u32;
        if self.uncompressed {
            counts[0x03] = self.field_rows;
            counts[0x05] = self.methods.len() as u32;
        }
        for &(t, n) in &self.declared {
            assert!(t > 0x06, "tables up to MethodDef are written, not declared");
            counts[t] = n;
        }
        let idx = |t: usize| if counts[t] >= 0x1_0000 { 4 } else { 2 };
        let coded = |ts: &[usize], tag_bits: u32| {
            let max = ts.iter().map(|&t| counts[t]).max().unwrap_or(0);
            if max >= 1 << (16 - tag_bits) { 4 } else { 2 }
        };
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
        let scope = coded(&[0x00, 0x1a, 0x23, 0x01], 2);
        for _ in 0..self.typeref_rows {
            put_idx(&mut t, (1 << 2) | 2, scope); // AssemblyRef 1
            put_idx(&mut t, typeref_name, s);
            put_idx(&mut t, 0, s);
        }
        // TypeDef: Extends is TypeDef, TypeRef or TypeSpec.
        put32(&mut t, 0);
        put_idx(&mut t, module_type, s);
        put_idx(&mut t, 0, s);
        put_idx(&mut t, 0, coded(&[0x02, 0x01, 0x1b], 2));
        put_idx(&mut t, 1, idx(0x04));
        put_idx(&mut t, 1, idx(0x06));
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
        for i in 0..self.methods.len() {
            put32(&mut t, rvas[i]);
            put16(&mut t, 0);
            put16(&mut t, 0x0086);
            put_idx(&mut t, names[i], s);
            put_idx(&mut t, sigs[i], bw);
            put_idx(&mut t, 1, idx(0x08));
        }
        lay.method_row_size = 4 + 2 + 2 + s + bw + idx(0x08);

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

    /// The canonical form `dotnet-il-canonical` documents: per method, in table order, its name
    /// and its signature, each behind its length as a little-endian u32; then `0` for a method
    /// without a body, or `1` and its IL behind its length.
    fn canonical(&self) -> Vec<u8> {
        fn field(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::new();
        for m in &self.methods {
            field(&mut out, m.name.as_bytes());
            field(&mut out, &m.sig);
            match &m.code {
                Code::Abstract => out.push(0),
                Code::Tiny(il) | Code::Fat(il) => {
                    out.push(1);
                    field(&mut out, il);
                }
            }
        }
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
const CANONICAL: &str = "dotnet-il-canonical";

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

// --- dotnet-il-canonical: what the form is -------------------------------------------------------

#[test]
fn an_assembly_reduces_to_each_methods_name_signature_and_il() {
    let asm = Asm::default();
    let bytes = asm.bytes();
    let out = run(&only(CANONICAL), DLL, &bytes);
    assert_eq!(
        String::from_utf8_lossy(&out.body),
        String::from_utf8_lossy(&asm.canonical()),
        "the form is the methods, in table order, and nothing else"
    );
    // A tiny body, a fat body and a body-less method are each read for what they are: the fat
    // body's IL follows its twelve-byte header, and the abstract method still names itself.
    assert!(
        out.body
            .windows(5)
            .any(|w| w == [0x1f, 0x2a, 0x0a, 0x06, 0x2a])
    );
    assert!(
        out.body
            .ends_with(b"\x04\0\0\0Hook\x03\0\0\0\x00\x00\x01\x00")
    );

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
    // build stamp, and a different number of rows in a table before MethodDef.
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

// --- dotnet-il-canonical: a real code difference still shows -------------------------------------

/// Two assemblies, laid out identically, that `dotnet-il-canonical` must still tell apart.
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

// --- dotnet-il-canonical: every layout ECMA-335 allows is read at its real widths ---------------

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
                declared: vec![(0x23, 1 << 14)],
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
fn an_assembly_with_no_methods_reduces_to_an_empty_form() {
    // No MethodDef table at all: an assembly of types and resources. Its form is empty, which is
    // a valid form and not a refusal.
    let asm = Asm {
        methods: Vec::new(),
        ..Asm::default()
    };
    let out = run(&only(CANONICAL), DLL, &asm.bytes());
    assert!(out.body.is_empty(), "{:?}", out.body);
    assert_eq!(out.applied.len(), 1, "{:?}", out.applied);
}

// --- dotnet-il-canonical: an assembly it cannot read whole is left exactly as it was ------------

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
    assert_eq!(blob, guid + 16, "the fixture lists `#Blob` right after `#GUID`");
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
