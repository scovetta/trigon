//! The builtin stabilizer catalogue.
//!
//! Risk tiers follow `docs/05-archive-and-normalization.md` §3. Note where signature and checksum
//! exclusion sit: `Structural`, not `Lossy`. A `checksums.yaml.gz` is a hash *of* the members we are
//! rebuilding and a `.sig` is a signature *over* them, made with a key we will never hold. Neither
//! is content a consumer reads, and neither can differ while the content matches, so both belong
//! with entry ordering. Calling them `Lossy` would strip the clean tier from every gem and every
//! signed nupkg for no gain in honesty.

use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use trigon_archive::{Archive, Entry, EntryKind, RawMeta, Trailer};
use trigon_core::{Format, RiskTier, StabilizerId};

use crate::{Cx, Stabilizer, Stage, Touched};

macro_rules! archive_pass {
    ($(#[$doc:meta])* $name:ident, $id:literal, $risk:expr, $applies:expr, |$a:ident| $body:block) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;
        impl Stabilizer for $name {
            fn id(&self) -> StabilizerId { StabilizerId::new($id) }
            fn risk(&self) -> RiskTier { $risk }
            fn applies(&self, cx: &Cx) -> bool { $applies(cx) }
            fn on_archive(&self, $a: &mut Archive, _cx: &Cx) -> Touched $body
        }
    };
}

macro_rules! entry_pass {
    ($(#[$doc:meta])* $name:ident, $id:literal, $risk:expr, $applies:expr, |$e:ident| $body:block) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;
        impl Stabilizer for $name {
            fn id(&self) -> StabilizerId { StabilizerId::new($id) }
            fn risk(&self) -> RiskTier { $risk }
            fn applies(&self, cx: &Cx) -> bool { $applies(cx) }
            fn on_entry(&self, $e: &mut Entry, _cx: &Cx) -> Touched $body
        }
    };
}

fn is_tar(cx: &Cx) -> bool {
    matches!(cx.format(), Format::Tar | Format::TarGz)
}
fn is_zip(cx: &Cx) -> bool {
    cx.format() == Format::Zip
}
fn has_gzip(cx: &Cx) -> bool {
    matches!(cx.format(), Format::TarGz | Format::Gzip) && (cx.at_depth(0) || is_structural(cx))
}

/// Whether a nested archive is framing the format defines, or a compressed file the package ships.
///
/// The parser cannot tell them apart: a gem's `metadata.gz` and an npm package's `banner.json.gz`
/// are both gzip members of an outer tar. The difference is that the gem format mandates the first
/// and the second is a deliverable, so normalizing its header rewrites content rather than a
/// container. The profile is what knows, and this is the list.
/// The `.gem` container itself, and not the payload inside it.
///
/// A `.gem` is a tar holding `metadata.gz`, `checksums.yaml.gz`, `data.tar.gz` and the signing
/// artifacts `*.sig`. The two exclusions below are about that envelope. `apply` runs the whole set
/// at every archive depth, so written as plain `is_tar` they also fired inside `data.tar.gz` — and
/// a gem that ships a certificate, a test fixture, or anything else named `*.sig` had it deleted
/// from *both* sides before they were compared. A real difference became no difference, and the
/// run reported a match.
///
/// Measured: two gems differing only in `lib/trusted-cert.sig` stabilized to identical bytes.
fn is_gem_envelope(cx: &Cx) -> bool {
    is_tar(cx) && cx.at_depth(0)
}

fn is_structural(cx: &Cx) -> bool {
    const GEM_MEMBERS: [&[u8]; 3] = [b"data.tar.gz", b"metadata.gz", b"checksums.yaml.gz"];
    cx.at_depth(1)
        && cx
            .archive_path()
            .is_some_and(|p| GEM_MEMBERS.contains(&p.as_bytes()))
}

fn is_sorted(a: &Archive) -> bool {
    a.entries
        .windows(2)
        .all(|w| (&w[0].path, w[0].ordinal) <= (&w[1].path, w[1].ordinal))
}

// --- tar ---------------------------------------------------------------------------------------

/// Sort a tar's entries by path, and by the order they were read where two share one.
///
/// A nested tar is written again whether or not it had to move anything. The tar passes normalize
/// its entries at every depth; were it written back as it arrived whenever none of them found
/// anything to change, its bytes — its compressed stream above all — would depend on whether it
/// arrived already in their form. Two `.tgz` files that shipped one `.tar.gz`, sorted in one and not in the
/// other, stayed `divergent` for that alone. Writing it again is not reported: it changes no entry,
/// and a run over the pass's own output must find nothing to do. The outermost archive is always
/// written again anyway.
///
/// `-v2` because the first sorted without saying so to the archive. The order is the container's
/// rather than any member's, so it marked no entry changed, and a nested tar in which no other pass
/// changed anything went out as it arrived, unsorted, with the pass in `applied`
/// (`docs/16-findings.md` §3.106).
#[derive(Debug)]
pub struct TarEntryOrder;

impl Stabilizer for TarEntryOrder {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("tar-entry-order-v2")
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Structural
    }
    fn applies(&self, cx: &Cx) -> bool {
        is_tar(cx)
    }
    fn on_archive(&self, a: &mut Archive, cx: &Cx) -> Touched {
        if !cx.at_depth(0) {
            a.mark_order_dirty();
        }
        if is_sorted(a) {
            return Touched::NONE;
        }
        a.sort_entries();
        a.mark_order_dirty();
        Touched {
            entries: a.entries.len() as u32,
            bytes: 0,
        }
    }
}

entry_pass!(TarTime, "tar-time", RiskTier::Metadata, is_tar, |e| {
    let RawMeta::Tar(raw) = &mut e.raw else {
        return Touched::NONE;
    };
    // PAX time records are regenerated from the typed fields, so stale copies have to go.
    let stale = raw.pax.remove("mtime").is_some()
        | raw.pax.remove("atime").is_some()
        | raw.pax.remove("ctime").is_some();
    if !stale && e.meta.mtime == Some(0) && raw.atime == Some(0) && raw.ctime.is_none() {
        return Touched::NONE;
    }
    e.meta.mtime = Some(0);
    // atime becomes an explicit PAX record: ustar has no atime field, which is the whole reason
    // this pass is described as "forcing PAX". The value is only representable as an extension.
    raw.atime = Some(0);
    raw.ctime = None;
    e.mark_dirty();
    Touched::entry()
});

entry_pass!(TarMode, "tar-mode", RiskTier::Metadata, is_tar, |e| {
    // Every kind, symlinks and devices included, where the mode means nothing on any platform we
    // target and normalizing it costs nothing. See docs/05 §2.2 (7).
    if !e.kind.is_normalizable() || e.meta.mode == 0o777 {
        return Touched::NONE;
    }
    e.meta.mode = 0o777;
    e.mark_dirty();
    Touched::entry()
});

entry_pass!(TarOwners, "tar-owners", RiskTier::Metadata, is_tar, |e| {
    let RawMeta::Tar(raw) = &mut e.raw else {
        return Touched::NONE;
    };
    if raw.uid == 0 && raw.gid == 0 && raw.uname.is_empty() && raw.gname.is_empty() {
        return Touched::NONE;
    }
    raw.uid = 0;
    raw.gid = 0;
    raw.uname.clear();
    raw.gname.clear();
    e.mark_dirty();
    Touched::entry()
});

entry_pass!(
    /// Drops every surviving PAX record, not only the xattr ones.
    ///
    /// The keyword set is open, and what turns up in real tarballs is host state: node-tar writes
    /// `SCHILY.ino` and `SCHILY.dev` (inode and device numbers from the packing machine),
    /// `SCHILY.nlink`, and a `NODETAR.*` record per field of the packed `package.json`. An npm
    /// tarball repacked on another machine differs in all of them, so keeping any of them makes
    /// the stabilized digest a function of where the package was built.
    ///
    /// Records that mean something are not stored here: the reader lifts `path`, `linkpath`,
    /// `size`, `mtime`, `atime` and `ctime` into typed fields and the writer regenerates them, so
    /// clearing the map does not lose a long name or the `atime=0` that forces PAX.
    TarXattrs,
    "tar-xattrs",
    RiskTier::Metadata,
    is_tar,
    |e| {
        let RawMeta::Tar(raw) = &mut e.raw else {
            return Touched::NONE;
        };
        if raw.pax.is_empty() {
            return Touched::NONE;
        }
        raw.pax.clear();
        e.mark_dirty();
        Touched::entry()
    }
);

entry_pass!(TarDevice, "tar-device", RiskTier::Metadata, is_tar, |e| {
    let RawMeta::Tar(raw) = &mut e.raw else {
        return Touched::NONE;
    };
    if raw.devmajor == 0 && raw.devminor == 0 {
        return Touched::NONE;
    }
    raw.devmajor = 0;
    raw.devminor = 0;
    if let EntryKind::CharDevice { major, minor } | EntryKind::BlockDevice { major, minor } =
        &mut e.kind
    {
        *major = 0;
        *minor = 0;
    }
    e.mark_dirty();
    Touched::entry()
});

// --- zip ---------------------------------------------------------------------------------------

archive_pass!(
    ZipEntryOrder,
    "zip-entry-order",
    RiskTier::Structural,
    is_zip,
    |a| {
        if is_sorted(a) {
            return Touched::NONE;
        }
        a.sort_entries();
        Touched {
            entries: a.entries.len() as u32,
            bytes: 0,
        }
    }
);

entry_pass!(ZipTime, "zip-time", RiskTier::Metadata, is_zip, |e| {
    let RawMeta::Zip(raw) = &mut e.raw else {
        return Touched::NONE;
    };
    if raw.dos_datetime == (0, 0) && e.meta.mtime.is_none() {
        return Touched::NONE;
    }
    raw.dos_datetime = (0, 0);
    e.meta.mtime = None;
    e.mark_dirty();
    Touched::entry()
});

entry_pass!(
    ZipVersions,
    "zip-versions",
    RiskTier::Metadata,
    is_zip,
    |e| {
        // **The file-type bits are not metadata.** Permissions are packaging noise — 0644 against
        // 0664 says nothing about a package — but *what the entry is* does, and zeroing the whole
        // field erased it along with them. A zip member that is a symlink and one that is a
        // regular file with the same bytes stabilized to identical output, so `trigon verify`
        // answered `normalized` for a pair whose `pkg/x.py` was a symlink to `/etc/passwd` on one
        // side and a file containing that text on the other. Measured: both stabilized to
        // `b60c55d03b98…`.
        //
        // Taken from `kind`, which is the reader's own finding, rather than from the raw bits —
        // so a zip written by a tool that records no unix mode at all still agrees with one that
        // records `0100644`, which is what zeroing the field was for.
        let type_bits: u32 = match &e.kind {
            EntryKind::Symlink { .. } => 0o120000 << 16,
            _ => 0,
        };
        let RawMeta::Zip(raw) = &mut e.raw else {
            return Touched::NONE;
        };
        if raw.creator_version == 0 && raw.reader_version == 0 && raw.external_attrs == type_bits {
            return Touched::NONE;
        }
        raw.creator_version = 0;
        raw.reader_version = 0;
        raw.external_attrs = type_bits;
        e.mark_dirty();
        Touched::entry()
    }
);

entry_pass!(ZipMisc, "zip-misc", RiskTier::Metadata, is_zip, |e| {
    let RawMeta::Zip(raw) = &mut e.raw else {
        return Touched::NONE;
    };
    if raw.extra.is_empty() && raw.comment.is_empty() && raw.flags == 0 && raw.internal_attrs == 0 {
        return Touched::NONE;
    }
    raw.extra.clear();
    raw.comment.clear();
    raw.flags = 0;
    raw.internal_attrs = 0;
    e.mark_dirty();
    Touched::entry()
});

archive_pass!(
    ZipCompression,
    "zip-compression",
    RiskTier::Structural,
    is_zip,
    |a| {
        let mut t = Touched::NONE;
        if let Trailer::Zip { comment } = &mut a.trailer {
            if !comment.is_empty() {
                comment.clear();
                t.entries += 1;
            }
        }
        for e in &mut a.entries {
            if let RawMeta::Zip(raw) = &mut e.raw {
                if raw.method != 0 {
                    raw.method = 0;
                    e.mark_dirty();
                    t.entries += 1;
                }
            }
        }
        t
    }
);

// --- gzip --------------------------------------------------------------------------------------

/// Clear the gzip header: when the compressor ran, on which system, and the name of the file it
/// read.
///
/// `-v2` because a gzip layer the format defines is now always written again. A gem's
/// `data.tar.gz`, `metadata.gz` and `checksums.yaml.gz` are framing rather than files the gem ships
/// (`is_structural`), and the serializer writes framing at no compression so that no encoder's
/// behaviour reaches a digest. It wrote a nested layer again only once something in it had changed,
/// though, so a layer with a clean header and nothing to change inside went out as it arrived, and
/// two gems that differed only in the compression level of `data.tar.gz` came out `divergent`
/// (`docs/16-findings.md` §3.106). The outermost layer was always written again. A `.tar.gz` a
/// package ships keeps its header, which is bytes the package delivers, and is written again by
/// `tar-entry-order-v2`, since the tar passes normalize what it holds; a `.gz` of anything else a
/// package ships is left as it arrived, compressed stream and all, because nothing normalizes it.
#[derive(Debug)]
pub struct GzipMeta;

impl Stabilizer for GzipMeta {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("gzip-meta-v2")
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Metadata
    }
    fn applies(&self, cx: &Cx) -> bool {
        has_gzip(cx)
    }
    fn on_archive(&self, a: &mut Archive, cx: &Cx) -> Touched {
        if !matches!(a.trailer, Trailer::Gzip(_)) {
            return Touched::NONE;
        }
        // Framing below the top is written again whether or not its header needs anything, so its
        // compressed bytes are the serializer's, as the outermost layer's always are. It is not
        // reported: no field changed, and a run over the pass's own output must find nothing to do.
        if !cx.at_depth(0) {
            a.mark_trailer_dirty();
        }
        let Trailer::Gzip(h) = &mut a.trailer else {
            return Touched::NONE;
        };
        // MTIME 0 is how gzip spells "no timestamp available", so absent and zero are the same
        // bytes.
        if h.mtime.is_none()
            && h.name.is_none()
            && h.comment.is_none()
            && h.extra.is_none()
            && h.os == trigon_archive::gzip::OS_UNKNOWN
        {
            return Touched::NONE;
        }
        h.mtime = None;
        h.name = None;
        h.comment = None;
        h.extra = None;
        h.os = trigon_archive::gzip::OS_UNKNOWN;
        // The trailer is the container, not a member, so the archive carries the dirty bit. It
        // decides whether a nested archive is re-serialized or written back byte for byte.
        a.mark_trailer_dirty();
        Touched::entry()
    }
}

// --- ecosystem-specific --------------------------------------------------------------------------

// `-v2`: a file that is not valid UTF-8 is left as it is, where the first decoded it lossily
// (`text_of`).
entry_pass!(
    CargoVcsHash,
    "cargo-vcs-hash-v2",
    RiskTier::Content,
    is_tar,
    |e| {
        if !e.path.ends_with(b".cargo_vcs_info.json") {
            return Touched::NONE;
        }
        let Some(text) = text_of(e) else {
            return Touched::NONE;
        };
        let Some(replaced) = replace_sha1_field(&text) else {
            return Touched::NONE;
        };
        match e.body_mut() {
            Ok(b) => {
                *b = replaced.into_bytes();
                let n = b.len() as u64;
                e.meta.size = n;
                Touched::entry_bytes(40)
            }
            Err(_) => Touched::NONE,
        }
    }
);

/// Rewrite `"sha1": "<40 hex>"` to a placeholder. Returns `None` when there is nothing to do, which
/// is what keeps the pass total: a shape we do not recognize is left alone rather than guessed at.
fn replace_sha1_field(text: &str) -> Option<String> {
    const KEY: &str = "\"sha1\"";
    let k = text.find(KEY)?;
    let rest = &text[k + KEY.len()..];
    let colon = rest.find(':')?;
    let after = &rest[colon + 1..];
    let q1 = after.find('"')?;
    let q2 = after[q1 + 1..].find('"')? + q1 + 1;
    if after[q1 + 1..q2].len() != 40 || !after[q1 + 1..q2].bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let head = k + KEY.len() + colon + 1;
    Some(format!(
        "{}{}{}",
        &text[..head + q1 + 1],
        "x".repeat(40),
        &text[head + q2..]
    ))
}

// `-v2`: a file that is not valid UTF-8 is left as it is, where the first decoded it lossily
// (`text_of`). Nothing selects `npm-tarball`, so no record names the old id; the rule that a
// changed pass takes a new id is kept anyway, since a rule with exceptions is one somebody has to
// remember the exceptions to.
entry_pass!(
    NpmInstallFields,
    "npm-install-fields-v2",
    RiskTier::Metadata,
    is_tar,
    |e| {
        if e.path.file_name() != b"package.json" {
            return Touched::NONE;
        }
        let Some(text) = text_of(e) else {
            return Touched::NONE;
        };
        const DROP: [&str; 4] = ["\"_resolved\"", "\"_integrity\"", "\"_from\"", "\"_id\""];
        let mut out = String::with_capacity(text.len());
        let mut removed = 0u64;
        // Where the last non-blank line kept ends in `out`, and whether a line was dropped since.
        let mut last_kept: Option<usize> = None;
        let mut dropped_since = false;
        for line in text.lines() {
            if DROP.iter().any(|k| line.trim_start().starts_with(k)) {
                removed += line.len() as u64;
                dropped_since = true;
                continue;
            }
            // Fields dropped from the end of an object leave the property before them carrying the
            // comma that separated it from them, in front of the `}`: not JSON, and never the
            // authored form. It goes with them. The pass has never run on anything this tool has
            // verified (`docs/16-findings.md` §3.28), so no record re-derives differently under
            // its id.
            if dropped_since && line.trim_start().starts_with('}') {
                if let Some(end) = last_kept {
                    let kept = out[..end].trim_end();
                    if kept.ends_with(',') {
                        let comma = kept.len() - 1;
                        out.replace_range(comma..comma + 1, "");
                        removed += 1;
                    }
                }
            }
            dropped_since = false;
            out.push_str(line);
            if !line.trim().is_empty() {
                last_kept = Some(out.len());
            }
            out.push('\n');
        }
        if removed == 0 {
            return Touched::NONE;
        }
        match e.body_mut() {
            Ok(b) => {
                *b = out.into_bytes();
                e.meta.size = b.len() as u64;
                Touched::entry_bytes(removed)
            }
            Err(_) => Touched::NONE,
        }
    }
);

archive_pass!(
    GemExcludeChecksums,
    "gem-exclude-checksums",
    RiskTier::Structural,
    is_gem_envelope,
    |a| {
        let before = a.entries.len();
        a.entries
            .retain(|e| e.path.file_name() != b"checksums.yaml.gz");
        match before - a.entries.len() {
            0 => Touched::NONE,
            n => Touched {
                entries: n as u32,
                bytes: 0,
            },
        }
    }
);

archive_pass!(
    GemExcludeSignatures,
    "gem-exclude-signatures",
    RiskTier::Structural,
    is_gem_envelope,
    |a| {
        let before = a.entries.len();
        a.entries.retain(|e| !e.path.ends_with(b".sig"));
        match before - a.entries.len() {
            0 => Touched::NONE,
            n => Touched {
                entries: n as u32,
                bytes: 0,
            },
        }
    }
);

// --- .NET assemblies -----------------------------------------------------------------------------

// Checked, because the stream directory's count sits wherever the metadata's version length puts
// it, up to `u32::MAX`, and in the archived wasm32 guest that is `usize::MAX`: `o + 2` there traps
// rather than failing the read. Each `u32le` offset is a bounded step from one inside the file.
fn u16le(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The byte ranges of a managed assembly that a rebuild cannot reproduce and a consumer does not
/// read as logic: the PE timestamp and checksum, the strong-name signature, the debug directory's
/// slot in the optional header, each debug entry's timestamp and the data it names, and the
/// `#GUID` heap that holds the module's MVID.
///
/// `None` declines the whole assembly, which the caller leaves exactly as it arrived: a member
/// that is not a managed PE, and one in which any of those regions cannot be shown to be what its
/// header calls it. Every region but the three fixed header fields is named by a pointer the
/// publisher wrote, and a pointer can name code as readily as a signature. So each must lie wholly
/// in the file, clear of the headers, of everything [`crate::ilcanon::occupied`] finds the
/// assembly holds, and of every other such region, and each debug entry must be a type this knows,
/// laid out as that type is. Nothing is zeroed on a guess, and nothing is zeroed in part.
///
/// Last, the zeroing must leave the assembly's canonical form ([`crate::ilcanon`]) as it was, with
/// the form readable at all. `dotnet-il-canonical-v3` runs next in the `nupkg` profile and replaces
/// the assembly with that form, so there nothing this zeroes reaches a digest: it acts only where
/// the IL pass reads the same code from the zeroed bytes as from the published ones. Before this, an
/// assembly whose form the IL pass declined, one grown past its size limit, was left to this pass
/// alone, and its zeroing decided a clean `normalized` with nothing to check it but `occupied`
/// (`docs/16-findings.md` §3.106).
fn dotnet_build_identity_regions(b: &[u8]) -> Option<Vec<(usize, usize)>> {
    if b.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32le(b, 0x3c)? as usize;
    if b.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let opt = coff + 20;
    // The checksum sits at optional-header offset 64 in both PE32 and PE32+; only the data
    // directories move, because the two headers differ in the fields before them.
    let (dir_off, checksum_off) = match u16le(b, opt)? {
        0x10b => (opt + 96, opt + 64),
        0x20b => (opt + 112, opt + 64),
        _ => return None,
    };
    // Where the assembly's content lies. `None` for a native image, which has no CLI header, for
    // one whose metadata or method bodies cannot be placed, and for one carrying native code,
    // which has no extent to keep clear of.
    let held = crate::ilcanon::occupied(b)?;

    // The PE timestamp and checksum: a date and a hash of the file, neither reproducible nor read
    // as logic. `Metadata` risk, the tier `tar-time`/`zip-time` already sit at. Fields at fixed
    // places in the headers, where every other region is found through a pointer.
    let mut zeroed = vec![(coff + 4, 4), (checksum_off, 4)];
    // Every region a pointer names, each of which has to be shown to be what it is called.
    let mut pointed: Vec<(usize, usize)> = Vec::new();

    // The strong-name signature: an RSA signature over the assembly, made with a private key we do
    // not have, exactly the ".sig over content we are rebuilding" the `Structural` tier and
    // `nupkg-signature` are about.
    let sn_rva = u32le(b, held.cli + 32)? as usize;
    let sn_size = u32le(b, held.cli + 36)? as usize;
    if sn_rva != 0 && sn_size != 0 {
        let sn = (held.file_range(b.len(), sn_rva, sn_size)?, sn_size);
        pointed.push(sn);
        zeroed.push(sn);
    }

    // The debug directory (data directory 6): a table of entries, each with a build timestamp and
    // the data it names — the CodeView record (the PDB's GUID, which is the MVID again, its age,
    // and the path it was written to), a hash of a `.pdb` the package does not even ship, an
    // embedded portable PDB. All build identity, none of it read as behaviour. Zero the
    // directory's own RVA/size in the header, each entry's timestamp, and each entry's data, so
    // two builds that differ only in where and when they wrote their debug info agree.
    let dbg_dir = dir_off + 6 * 8;
    let dbg_rva = u32le(b, dbg_dir)? as usize;
    let dbg_size = u32le(b, dbg_dir + 4)? as usize;
    if dbg_rva != 0 && dbg_size != 0 {
        // The 8-byte directory entry itself (RVA + size): it moves between builds.
        zeroed.push((dbg_dir, 8));
        if dbg_size % 28 != 0 {
            return None;
        }
        // The table is kept clear of everything else, though only its stamps are zeroed: data
        // that overlapped it would zero the entries that name it.
        let dbg = held.file_range(b.len(), dbg_rva, dbg_size)?;
        pointed.push((dbg, dbg_size));
        let mut records = Vec::new();
        for ent in (dbg..dbg + dbg_size).step_by(28) {
            zeroed.push((ent + 4, 4));
            if let Some(r) = debug_record(b, &held, ent)? {
                records.push(r);
            }
        }
        // Every entry's data is placed before any of it is read, and two that share a byte decline
        // the assembly there. Each record is then read once, so reading them costs the file's
        // length at most. Read as each entry came, a directory of entries all naming one large
        // record read it once per entry, entries times record, before anything noticed they
        // overlapped.
        records.sort_unstable_by_key(|r| r.at);
        if !records.windows(2).all(|w| w[0].at + w[0].len <= w[1].at) {
            return None;
        }
        for r in records {
            if !r.laid_out(b) {
                return None;
            }
            pointed.push((r.at, r.len));
            zeroed.push((r.at, r.len));
        }
    }

    // The MVID: a per-compilation GUID the runtime never reads for behaviour, in the `#GUID` heap.
    // Zero the whole heap rather than parse the tables to reach `Module.Mvid`: the heap holds only
    // GUIDs, all of them build identifiers, and `occupied` has checked that nothing but a GUID
    // column reads it.
    if let Some(guid) = held.guid.filter(|&(_, n)| n > 0) {
        pointed.push(guid);
        zeroed.push(guid);
    }

    // Each region a pointer names, clear of the headers, of what the assembly holds, and of every
    // other; and the fixed fields clear of what it holds, which a section mapped over the headers
    // could place there.
    pointed.sort_unstable();
    let clear = pointed.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0)
        && pointed
            .iter()
            .all(|&(o, n)| o >= held.headers_end && !held.overlaps(o, n))
        && zeroed.iter().all(|&(o, n)| !held.overlaps(o, n));
    if !clear {
        return None;
    }
    zeroed.sort_unstable();
    let mut after = b.to_vec();
    for &(o, n) in &zeroed {
        after.get_mut(o..o.checked_add(n)?)?.fill(0);
    }
    let form = crate::ilcanon::canonical_managed(b)?;
    (crate::ilcanon::canonical_managed(&after)? == form).then_some(zeroed)
}

#[cfg(test)]
thread_local! {
    /// The bytes of debug records read to check their layout, so a test can hold the check to the
    /// file's length by counting rather than by timing it.
    static RECORD_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The data a debug directory entry names, placed but not yet read.
struct DebugRecord {
    kind: u32,
    at: usize,
    len: usize,
}

impl DebugRecord {
    /// Whether the data is laid out as its type's is.
    fn laid_out(&self, b: &[u8]) -> bool {
        #[cfg(test)]
        RECORD_BYTES.with(|n| n.set(n.get() + self.len as u64));
        let d = &b[self.at..self.at + self.len];
        match self.kind {
            2 => codeview(d),
            17 => embedded_pdb(d),
            19 => pdb_checksum(d),
            _ => false,
        }
    }
}

/// The data debug directory entry `ent` names, when the entry is of a type this knows and its
/// data lies wholly in the file, where its address, if it gives one, maps it too: `Some(None)` for
/// an entry that names no data, and `None`, which declines the assembly, for anything else. The
/// data's layout is [`DebugRecord::laid_out`]'s to check, once no two entries' data overlap.
fn debug_record(
    b: &[u8],
    held: &crate::ilcanon::Occupied,
    ent: usize,
) -> Option<Option<DebugRecord>> {
    // IMAGE_DEBUG_DIRECTORY: Characteristics, TimeDateStamp, the two version words, Type,
    // SizeOfData, AddressOfRawData, PointerToRawData.
    let kind = u32le(b, ent + 12)?;
    let size = u32le(b, ent + 16)? as usize;
    let rva = u32le(b, ent + 20)? as usize;
    let ptr = u32le(b, ent + 24)? as usize;
    // Reproducible: it says the build was deterministic, and it names no data at all.
    if kind == 16 {
        return (size == 0 && rva == 0 && ptr == 0).then_some(None);
    }
    // CodeView, an embedded portable PDB, a PDB checksum: what a managed compiler writes.
    if !matches!(kind, 2 | 17 | 19) {
        return None;
    }
    // A pointer of 0 is how an entry says its data is not in the file. Read as an offset it would
    // name the DOS header, and a record of a type that has data cannot be checked without it.
    if size == 0 || ptr == 0 {
        return None;
    }
    b.get(ptr..ptr.checked_add(size)?)?;
    // Where the loader maps it and where the file holds it have to be one place, or the two
    // readers would each find a different record.
    if rva != 0 && held.file_range(b.len(), rva, size)? != ptr {
        return None;
    }
    Some(Some(DebugRecord {
        kind,
        at: ptr,
        len: size,
    }))
}

/// A CodeView record as a managed compiler writes it: `RSDS`, the PDB's GUID and age, then the
/// path it was written to, NUL-terminated, with nothing after the NUL but zeros.
fn codeview(d: &[u8]) -> bool {
    d.starts_with(b"RSDS")
        && d.get(24..)
            .and_then(|path| path.iter().position(|&c| c == 0))
            .is_some_and(|nul| d[24 + nul..].iter().all(|&c| c == 0))
}

/// An embedded portable PDB: `MPDB`, the size it inflates to, then the deflated PDB.
fn embedded_pdb(d: &[u8]) -> bool {
    d.len() > 8 && d.starts_with(b"MPDB") && u32le(d, 4).is_some_and(|n| n != 0)
}

/// A PDB checksum: the name of the hash, NUL-terminated, then a digest exactly as long as that
/// hash's.
fn pdb_checksum(d: &[u8]) -> bool {
    let Some(nul) = d.iter().position(|&c| c == 0) else {
        return false;
    };
    let digest = match &d[..nul] {
        b"SHA256" => 32,
        b"SHA384" => 48,
        b"SHA512" => 64,
        _ => return false,
    };
    d.len() == nul + 1 + digest
}

entry_pass!(
    /// Zero a managed assembly's build and signing identity: the PE timestamp and checksum, the
    /// strong-name signature, the debug directory's slot in the optional header, each debug
    /// entry's timestamp and the debug data it names, and the `#GUID` heap that holds the module
    /// MVID.
    ///
    /// **The residual after the code already matches.** With the version reconstructed and the SDK
    /// close, `castle.core`'s assemblies decompile identically and differ only here — a signature
    /// made with a key we do not have, a per-compilation GUID, a build date. None is code and none
    /// is reproducible, so a signed .NET package can never match byte-for-byte until they are
    /// normalized. This is the strong-name signature's `nupkg-signature`, applied one level in, to
    /// the assembly rather than the package.
    ///
    /// `Metadata` risk: the signature alone would be `Structural` (integrity metadata over content
    /// we rebuild), the MVID and timestamp are `Metadata` like the archive timestamps, and a pass
    /// carries the higher of what it does. Builtin and at `Metadata`, so it caps nothing itself.
    /// In the `nupkg` profile nothing it zeroes reaches a digest: it acts only on an assembly that
    /// `dotnet-il-canonical-v3` reads to the same form from the zeroed bytes as from the published
    /// ones, and that pass, which runs next, replaces the assembly with the form. A match there is
    /// `normalized_with_caveats` whatever this pass did. Its checks are what stand between its
    /// zeroing and a digest only in a set narrowed without the IL pass, which `trigon stabilize
    /// --disable-passes` makes and no verdict is reached under.
    ///
    /// Every region is reached by walking the PE and CLI headers and the metadata, and zeroed only
    /// once it is shown to be what its header calls it (`dotnet_build_identity_regions`). A native
    /// `.dll`, a mislabelled data file, and an assembly any one region of which cannot be shown are
    /// left whole. Zeroed in place, so the member's length and the archive's framing do not move.
    ///
    /// `-v2` because what it zeroes narrowed. The first zeroed whatever range each debug entry
    /// named, and nothing tied the range to debug data: an entry could name the whole file, and two
    /// assemblies of different code, each carrying such an entry, stabilized to the same bytes,
    /// which the IL pass could then not read, so nothing capped a clean `normalized`
    /// (`docs/16-findings.md` §3.106). The set digest covers pass ids, not pass code
    /// (`docs/19-distribution-and-lookup.md` §11, open question 1), so the narrower pass under the
    /// old id would have re-derived old records differently under the digest they were signed with.
    DotnetAssemblyIdentity,
    "dotnet-assembly-identity-v2",
    RiskTier::Metadata,
    is_zip,
    |e| {
        if !trigon_core::is_managed_assembly(&String::from_utf8_lossy(e.path.as_bytes())) {
            return Touched::NONE;
        }
        let Ok(body) = e.body_bytes() else {
            return Touched::NONE;
        };
        let Some(regions) = dotnet_build_identity_regions(&body) else {
            return Touched::NONE;
        };
        // Nothing to do unless a named region actually carries a non-zero byte — so an assembly
        // that was already public-signed and deterministic stays on its original `Body` rather
        // than being promoted to `Inline` for no change.
        let dirty = regions
            .iter()
            .any(|&(o, l)| body.get(o..o + l).is_some_and(|s| s.iter().any(|&x| x != 0)));
        if !dirty {
            return Touched::NONE;
        }
        drop(body);
        match e.body_mut() {
            Ok(b) => {
                let mut n = 0u64;
                for (o, l) in regions {
                    if let Some(s) = b.get_mut(o..o + l) {
                        for x in s.iter_mut() {
                            if *x != 0 {
                                *x = 0;
                                n += 1;
                            }
                        }
                    }
                }
                Touched::entry_bytes(n)
            }
            Err(_) => Touched::NONE,
        }
    }
);

// **The last resort for a managed assembly, and a lossy one.** `dotnet-assembly-identity-v2`
// zeroes the fixed-location build identity, but a rebuild whose SourceLink URL, source-generator
// document order or a heap's length differs from the publisher's lays its metadata and embedded PDB
// out at shifted offsets that a byte-zeroing pass cannot align ([B46](../../../docs/17-backlog.md),
// `docs/16-findings.md` §3.87). None of that is code: `moq@4.20.72`'s four assemblies decompile
// identically and their method IL is byte-for-byte equal.
//
// So this replaces a managed assembly with the canonical *functional* form [`crate::ilcanon`]
// reads out of it — every method's name, signature, flags and whole body, every row and literal
// an IL token or a signature can name, and the declarations that decide how the code runs
// (P/Invoke entry points, explicit overrides, implemented interfaces, parameters, layout),
// resolved through the heaps to values rather than the offsets that moved. Two assemblies built
// from the same source reduce to the same bytes. A change to a method, to anything its tokens
// name or to how it is declared still shows; one only to resources, custom attributes or the data
// a field is initialized from does not. Those it drops, so it is `Lossy`: a match it produces is
// `normalized_with_caveats`, never a clean `normalized` — the honest tier for "the code is the
// same, and we did not check the rest." An assembly it cannot read whole, as the runtime reads
// it, is left exactly as it was, and so is one carrying native code the form cannot hold.
//
// `-v2` because the form changed. The first kept each method's name, signature and IL and nothing
// its tokens named, so a changed string literal, a MemberRef renamed under its token, a method's
// flags, a catch clause's type or a P/Invoke's entry point all compared equal. The set digest
// covers pass ids, not pass code (`docs/19-distribution-and-lookup.md` §11, open question 1), so a
// new form under the old id would have re-derived old records differently under the digest they
// were signed with. A new id is a new set digest, and a record made under the old one is
// re-derived under its archived set.
//
// `-v3` because what it reads narrowed. The second declined a method whose body was native, and
// read the rest of an image that carried native code no method named: a ReadyToRun image's
// precompiled methods, which the runtime runs in place of their IL, and a mixed-mode image's native
// entry point. Two such images of one IL and different native code shared a form and matched
// (`docs/16-findings.md` §3.106). Now the CLI header's word decides: ILONLY clear, a native entry
// point or a ManagedNativeHeader, and the image is left as it is.
entry_pass!(
    DotnetIlCanonical,
    "dotnet-il-canonical-v3",
    RiskTier::Lossy,
    is_zip,
    |e| {
        if !trigon_core::is_managed_assembly(&String::from_utf8_lossy(e.path.as_bytes())) {
            return Touched::NONE;
        }
        let Ok(body) = e.body_bytes() else {
            return Touched::NONE;
        };
        let Some(canon) = crate::ilcanon::canonical_managed(&body) else {
            return Touched::NONE;
        };
        drop(body);
        match e.body_mut() {
            Ok(b) => {
                *b = canon;
                let n = b.len() as u64;
                e.meta.size = n;
                Touched::entry_bytes(n)
            }
            Err(_) => Touched::NONE,
        }
    }
);

// The `<repository>` element's `branch` attribute is the git ref the package was built from, and
// nothing the package does depends on it. A publisher who builds from the release tag stamps
// `branch="v4.20.72"`; trigon checks the same commit out detached, so the ref is nameless and the
// attribute is absent — `moq@4.20.72`'s nuspec differed in exactly this and nothing else. The commit
// is the identity and is kept; the branch is a label on how the commit was reached, so it is
// dropped from both sides. `Metadata`, the tier the other provenance stamps sit at. `-v2`: a
// `.nuspec` that is not valid UTF-8 is left as it is, where the first decoded it lossily
// (`text_of`); and the element is read attribute by attribute, where the first cut from the first
// ` branch="` in it, inside another attribute's value too (`drop_repository_branch`).
entry_pass!(
    NupkgRepositoryBranch,
    "nupkg-repository-branch-v2",
    RiskTier::Metadata,
    is_zip,
    |e| {
        if !e.path.as_bytes().ends_with(b".nuspec") {
            return Touched::NONE;
        }
        rewrite_body(e, drop_repository_branch)
    }
);

/// Remove the `branch` attribute, and the whitespace before it, from the first `<repository …>`
/// element: `None` when it has none, and when this cannot read the element's tag whole, to its `>`.
///
/// Attribute by attribute, each value stepped over to its closing quote, so only an attribute named
/// `branch` goes. A search for ` branch="` found one inside another attribute's value as readily:
/// in `url="https://example.com/r branch=" commit="0123…"` it cut from inside the URL through the
/// opening quote of `commit`, and the nuspec read as one with another URL and no commit, which is the
/// identity this pass exists to keep (`docs/16-findings.md` §3.106).
fn drop_repository_branch(t: &str) -> Option<String> {
    const TAG: &str = "<repository";
    let open = t.find(TAG)?;
    // Inside a comment it is text, not an element.
    if t[..open]
        .rfind("<!--")
        .is_some_and(|c| !t[c..open].contains("-->"))
    {
        return None;
    }
    let s = t.as_bytes();
    let space = |i: usize| s.get(i).is_some_and(u8::is_ascii_whitespace);
    let mut i = open + TAG.len();
    let mut branch = None;
    loop {
        // Whitespace, then an attribute, or the end of the tag; `<repositoryUrl` is another element.
        let before = i;
        while space(i) {
            i += 1;
        }
        match s.get(i)? {
            b'>' => break,
            b'/' if s.get(i + 1) == Some(&b'>') => break,
            _ if i == before => return None,
            _ => {}
        }
        let name = i;
        while s
            .get(i)
            .is_some_and(|&c| !c.is_ascii_whitespace() && !matches!(c, b'=' | b'>' | b'/'))
        {
            i += 1;
        }
        let name = &t[name..i];
        while space(i) {
            i += 1;
        }
        if s.get(i) != Some(&b'=') {
            return None;
        }
        i += 1;
        while space(i) {
            i += 1;
        }
        let quote = *s.get(i).filter(|&&q| q == b'"' || q == b'\'')?;
        i += 1 + t[i + 1..].find(char::from(quote))? + 1;
        // An element names an attribute once, and one naming it twice is no element an XML reader
        // reads, so which of the two was meant is not guessed at.
        if name == "branch" && branch.replace((before, i)).is_some() {
            return None;
        }
    }
    let (from, to) = branch?;
    Some(format!("{}{}", &t[..from], &t[to..]))
}

// NuGetizer (devlooped) assembles a package readme from `<!-- include <path-or-url> -->` directives
// and leaves the directive and its close marker in the file as comments. A remote include is
// fetched at pack time, which `mirror-only` forbids, so `nuget/build/pack` neutralises it
// (`docs/16-findings.md` §3.86) — and that leaves the markers spelled a hair differently than the
// publisher's networked build did (`<!-- include … -->` kept vs dropped, a stray blank). The sponsor
// list itself, which comes from a *local* include, reproduces byte for byte; only the invisible
// markers and the whitespace around them differ. So strip the single-token marker comments from
// both, squeeze the blank runs that removing them leaves, and trim trailing space. `Content`: it
// edits the bytes of every `.md` in the package, not only NuGetizer's readme, and trimming trailing
// whitespace removes Markdown's hard line break (two trailing spaces), which changes how a file
// renders. `-v2`: a file that is not valid UTF-8 is left as it is, where the first decoded it
// lossily (`text_of`).
entry_pass!(
    NupkgReadmeMarkers,
    "nupkg-readme-markers-v2",
    RiskTier::Content,
    is_zip,
    |e| {
        if !e.path.as_bytes().ends_with(b".md") {
            return Touched::NONE;
        }
        rewrite_body(e, normalize_readme_markers)
    }
);

/// A single-token `<!-- include foo -->` or `<!-- foo -->` marker — NuGetizer's, not a prose comment
/// (which carries spaces inside). Only these are stripped.
fn is_nugetizer_marker(line: &str) -> bool {
    let l = line.trim();
    let Some(inner) = l.strip_prefix("<!--").and_then(|r| r.strip_suffix("-->")) else {
        return false;
    };
    let inner = inner.trim();
    let inner = inner
        .strip_prefix("include")
        .map(str::trim)
        .unwrap_or(inner);
    !inner.is_empty() && !inner.contains(char::is_whitespace)
}

/// Drop NuGetizer marker comments, squeeze the blank runs that leaves, and trim trailing whitespace.
/// `None` when nothing changed, so a readme with no markers stays on its original body.
fn normalize_readme_markers(t: &str) -> Option<String> {
    let mut out = String::with_capacity(t.len());
    let mut prev_blank = true; // treat the start as "after a blank" so a leading blank is squeezed
    let mut changed = false;
    for line in t.split('\n') {
        let trimmed = line.trim_end();
        if trimmed != line {
            changed = true;
        }
        if is_nugetizer_marker(trimmed) {
            changed = true;
            continue;
        }
        let blank = trimmed.is_empty();
        if blank && prev_blank {
            changed = true;
            continue;
        }
        out.push_str(trimmed);
        out.push('\n');
        prev_blank = blank;
    }
    while out.ends_with("\n\n") {
        out.pop();
        changed = true;
    }
    // The pop above also fires on the empty piece `split` yields after a final newline, so
    // `changed` alone claimed every readme that ends in one — a `Content` pass in `applied`, and a
    // capped verdict, for a file left byte for byte as it was.
    (changed && out != t).then_some(out)
}

/// Every builtin pass. Used by the profile registry and by the dependency-policy test.
pub fn all_builtin() -> Vec<Arc<dyn Stabilizer>> {
    vec![
        Arc::new(TarEntryOrder),
        Arc::new(TarTime),
        Arc::new(TarMode),
        Arc::new(TarOwners),
        Arc::new(TarXattrs),
        Arc::new(TarDevice),
        Arc::new(ZipEntryOrder),
        Arc::new(ZipTime),
        Arc::new(ZipVersions),
        Arc::new(ZipMisc),
        Arc::new(ZipCompression),
        Arc::new(GzipMeta),
        Arc::new(CargoVcsHash),
        Arc::new(NpmInstallFields),
        Arc::new(GemExcludeChecksums),
        Arc::new(GemExcludeSignatures),
        Arc::new(NupkgSignature),
        Arc::new(NupkgPortableFolderName),
        Arc::new(NupkgTextEol),
        Arc::new(NupkgDocMemberOrder),
        Arc::new(NupkgPackagingNames),
        Arc::new(NupkgPackagerVersion),
        Arc::new(DotnetAssemblyIdentity),
        Arc::new(DotnetIlCanonical),
        Arc::new(NupkgRepositoryBranch),
        Arc::new(NupkgReadmeMarkers),
        // The wheel and gemspec passes were missing, so the "every builtin pass" this returns
        // omitted the one `Finalize` pass and every pass that runs inside `metadata.gz`.
        Arc::new(WheelDirectUrl),
        Arc::new(PycHeader),
        Arc::new(WheelMetadataEol),
        Arc::new(WheelRecord),
        Arc::new(GemMetadataDate),
        Arc::new(GemMetadataRubygemsVersion),
        Arc::new(GemMetadataCertChain),
    ]
}

// --- wheel ---------------------------------------------------------------------------------------

archive_pass!(
    /// `direct_url.json` records where pip installed a wheel from, not what the wheel contains.
    ///
    /// `Lossy`, and it earns the tier: this removes a file a consumer would otherwise receive. Contrast
    /// the gem and nupkg signature passes, which remove integrity metadata over content we are
    /// rebuilding and so sit at `Structural`.

    WheelDirectUrl,
    "wheel-direct-url",
    RiskTier::Lossy,
    is_zip,
    |a| {
        let before = a.entries.len();
        a.entries
            .retain(|e| e.path.file_name() != b"direct_url.json");
        match before - a.entries.len() {
            0 => Touched::NONE,
            n => Touched {
                entries: n as u32,
                bytes: 0,
            },
        }
    }
);

/// Where a `.pyc`'s source mtime sits, read off the magic number that says which CPython wrote it:
/// `None` for a magic this does not recognise, a header too short for the layout it implies, and a
/// header with no mtime to zero.
///
/// The magic is a two-byte number, then `\r\n`. CPython 1.5 to 2.7 wrote an 8-byte header, the
/// magic and then the mtime, and so did 3.0 to 3.2. 3.3 (3210) added the source size after the
/// mtime, 12 bytes. 3.7 (3392, PEP 552) put a flags word between the magic and the rest, 16 bytes:
/// with the flags clear the mtime and the size follow it, with bit 0 set eight bytes of the
/// source's hash do and there is no mtime, and any other flags are a header PEP 552 does not
/// define. Python 3 numbers its magics upward from 3000 and 3.14's are in the 3600s, so everything
/// from 3392 to 3999 is read as PEP 552's; Python 2's are listed, since they jump.
fn pyc_mtime(b: &[u8]) -> Option<usize> {
    if b.get(2..4)? != b"\r\n" {
        return None;
    }
    let (at, header) = match u16::from_le_bytes([b[0], b[1]]) {
        20121 | 50428 | 50823 | 60202 | 60717 | 62011 | 62021 | 62041 | 62051 | 62061 | 62071
        | 62081 | 62091 | 62092 | 62101 | 62111 | 62121 | 62131 | 62151 | 62161 | 62171 | 62181
        | 62191 | 62201 | 62211 => (4, 8),
        3000..=3209 => (4, 8),
        3210..=3391 => (4, 12),
        3392..=3999 => {
            if u32le(b, 4)? != 0 {
                return None;
            }
            (8, 16)
        }
        _ => return None,
    };
    (b.len() >= header).then_some(at)
}

entry_pass!(
    /// Zero the source mtime embedded in a timestamp-validated `.pyc`, wherever the header the
    /// magic names puts it (`pyc_mtime`).
    ///
    /// Only the mtime is touched. The magic identifies the bytecode version. The flags word says
    /// how to read the rest, so zeroing it changes what the file means. The source size and the
    /// source hash are both derived from the source: neither can differ while the source matches,
    /// so zeroing them removes a signal and normalizes nothing. A hash-based `.pyc` has no mtime,
    /// and a magic this does not recognise leaves the file as it is. The reference has no `.pyc`
    /// pass at all, which is why this one is a listed deviation.
    ///
    /// `-v2` because the first never read the magic. It took every header for PEP 552's, so in a
    /// `.pyc` from before 3.7, whose second word is the mtime itself, it zeroed bytes 8 to 12 —
    /// the source size on 3.3 to 3.6, the start of the code object on Python 2 — when that mtime
    /// was even, and did nothing when it was odd (`docs/16-findings.md` §3.106).
    PycHeader,
    "pyc-header-v2",
    RiskTier::Content,
    is_zip,
    |e| {
        if !e.path.ends_with(b".pyc") {
            return Touched::NONE;
        }
        let Ok(body) = e.body_bytes() else {
            return Touched::NONE;
        };
        let Some(at) = pyc_mtime(&body) else {
            return Touched::NONE;
        };
        if body[at..at + 4].iter().all(|b| *b == 0) {
            return Touched::NONE;
        }
        match e.body_mut() {
            Ok(b) => {
                b[at..at + 4].fill(0);
                Touched::entry_bytes(4)
            }
            Err(_) => Touched::NONE,
        }
    }
);

entry_pass!(
    /// Normalize CRLF to LF in a wheel's **generated** metadata files.
    ///
    /// A publisher on Windows gets `\r\n` in `METADATA` because the tool that wrote it opened the
    /// file in text mode; the same tool on Linux writes `\n`. The content is identical — these are
    /// RFC 822-style headers, and a line terminator carries no meaning in them — but the bytes are
    /// not, and `RECORD` then differs too because it digests `METADATA`. `sniffio 1.3.1` is the
    /// case that prompted this: with the build backend pinned and the index time-filtered, its
    /// rebuild matched in every member except these, and no amount of pinning reaches it. We cannot
    /// reproduce Windows text-mode I/O, so normalizing is the only route to a match.
    ///
    /// **Scoped to the four files a wheel builder generates**, never to package source. A `.py`
    /// file with CRLF is the package's content and its line endings are the author's choice; a
    /// stabilizer that rewrote those would be editing the thing under test. That is the whole
    /// distinction this pass rests on, and it is why the list is explicit rather than a glob over
    /// `dist-info/`: a wheel may ship arbitrary files there, including licences the author wrote.
    ///
    /// `Content` risk, because it rewrites bytes inside a file. A file it rewrites is one the
    /// wheel's `RECORD` digests, so `wheel-record-v3`, `Content` too, regenerates `RECORD` beside
    /// it, and this costs an outcome only where the wheel has no `RECORD` of its own to regenerate.
    /// It runs at `Default` so `RECORD` is regenerated over the normalized bytes at `Finalize`.
    ///
    /// Measured impact when added: one wheel in the seventeen-package M1 PyPI corpus carries CRLF
    /// metadata at all. It is a rare case that recurs rather than a common one.
    WheelMetadataEol,
    "wheel-metadata-eol",
    RiskTier::Content,
    is_zip,
    |e| {
        const GENERATED: [&[u8]; 4] = [
            b".dist-info/METADATA",
            b".dist-info/WHEEL",
            b".dist-info/entry_points.txt",
            b".dist-info/top_level.txt",
        ];
        if !GENERATED.iter().any(|suffix| e.path.ends_with(suffix)) {
            return Touched::NONE;
        }
        let Ok(body) = e.body_bytes() else {
            return Touched::NONE;
        };
        // Count first so an untouched file stays on its original `Body` and reports nothing: a pass
        // that promotes every wheel's METADATA to `Inline` would defeat the copy-on-write the
        // archive model exists for.
        let carriage_returns = body.windows(2).filter(|w| w == b"\r\n").count();
        if carriage_returns == 0 {
            return Touched::NONE;
        }
        match e.body_mut() {
            Ok(b) => {
                // Only `\r` immediately before `\n`. A lone carriage return is not a line ending
                // in any convention still in use, and dropping one would be editing content.
                let mut out = Vec::with_capacity(b.len());
                let mut i = 0;
                while i < b.len() {
                    if b[i] == b'\r' && b.get(i + 1) == Some(&b'\n') {
                        i += 1;
                        continue;
                    }
                    out.push(b[i]);
                    i += 1;
                }
                *b = out;
                Touched::entry_bytes(carriage_returns as u64)
            }
            Err(_) => Touched::NONE,
        }
    }
);

/// Regenerate the wheel's own `RECORD` from the members that are actually present.
///
/// This is why `Stage::Finalize` exists. `RECORD` is a manifest *of* membership, and earlier passes
/// change membership: `wheel-direct-url` removes a file, and a definitions-supplied `exclude_path`
/// can remove any file at all. Regenerating it at `Default` would produce a manifest of the wheel as
/// it arrived rather than the wheel as it stands.
///
/// `-v2` because what is recorded of it changed, though not what it writes. An archive pass names
/// no member in what it reports, so the RECORD it regenerated carried no `body` edit; now each body
/// is compared across the pass, and a comparison's field edits name RECORD as rewritten by it. A
/// report published with field edits before that would re-derive with one it does not carry, under
/// the set digest it was published with, and read as a disagreement. The set digest covers pass ids
/// and not pass code (`docs/19-distribution-and-lookup.md` §11, open question 1), so a new id is
/// what sends such a record to its archived set.
///
/// `-v3` because which `RECORD` it rewrites changed. It took the first member whose path ended
/// `.dist-info/RECORD`, in path order once `zip-entry-order` had sorted them, and a wheel that
/// vendors a distribution can carry that distribution's `.dist-info` too: under `aaa/_vendor/`, it
/// sorts before the wheel's own, so the vendored `RECORD` was regenerated and the wheel's own
/// compared as published (`docs/16-findings.md` §3.106). Now it is the wheel's own or none
/// (`own_record`).
#[derive(Debug)]
pub struct WheelRecord;

impl Stabilizer for WheelRecord {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("wheel-record-v3")
    }
    fn stage(&self) -> Stage {
        Stage::Finalize
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Content
    }
    fn applies(&self, cx: &Cx) -> bool {
        is_zip(cx)
    }
    fn on_archive(&self, a: &mut Archive, _cx: &Cx) -> Touched {
        let Some(idx) = own_record(a) else {
            return Touched::NONE;
        };
        let record_path = a.entries[idx].path.clone();

        // PEP 376: one line per member. Archive order is unstable, so the other entries sort
        // lexicographically. RECORD's own line carries an empty digest and size and goes last,
        // outside the sort, which is what every wheel builder and the reference implementation do.
        let mut rows: Vec<String> = Vec::with_capacity(a.entries.len());
        for (i, e) in a.entries.iter().enumerate() {
            if i == idx {
                continue;
            }
            // `stabilized_bytes`, not `body_bytes`: a `.gz` a wheel ships parses as a nested
            // archive and has no bytes of its own. Skipping the members we cannot read would drop
            // them from the manifest, which is a silent membership change dressed up as a
            // normalization. A member we genuinely cannot read means the manifest cannot be
            // computed, so RECORD is left exactly as it arrived.
            let Ok(body) = e.stabilized_bytes() else {
                return Touched::NONE;
            };
            rows.push(format!(
                "{},sha256={},{}",
                csv_quote(&e.path.to_lossy()),
                base64url_nopad(&Sha256::digest(&body)),
                body.len()
            ));
        }
        rows.sort();
        rows.push(format!("{},,", csv_quote(&a.entries[idx].path.to_lossy())));

        let mut out = rows.join("\n");
        out.push('\n');
        let new = out.into_bytes();

        let entry = &mut a.entries[idx];
        let old_len = entry.body_bytes().map(|b| b.len()).unwrap_or(0);
        if entry
            .body_bytes()
            .map(|b| b.as_ref() == new.as_slice())
            .unwrap_or(false)
        {
            return Touched::NONE;
        }
        match entry.body_mut() {
            Ok(b) => {
                *b = new;
                let n = b.len() as u64;
                entry.meta.size = n;
                let _ = record_path;
                Touched::entry_bytes(old_len as u64)
            }
            Err(_) => Touched::NONE,
        }
    }
}

/// The wheel's own `RECORD`: the one in the `.dist-info` directory at the root of the archive,
/// which the wheel format names `{distribution}-{version}.dist-info`. `None` when the root holds no
/// such directory, or more than one, which pip refuses to install: then no `RECORD` is the wheel's
/// by the format, and every one stays as it arrived. A `.dist-info` below the root is a vendored
/// distribution's, and its `RECORD` is content the wheel ships like any other file.
fn own_record(a: &Archive) -> Option<usize> {
    let mut dirs = a.entries.iter().filter_map(|e| {
        let p = e.path.as_bytes();
        let top = &p[..p.iter().position(|&c| c == b'/')?];
        top.ends_with(b".dist-info").then_some(top)
    });
    let own = dirs.next()?;
    if dirs.any(|d| d != own) {
        return None;
    }
    let record = [own, b"/RECORD"].concat();
    a.entries
        .iter()
        .position(|e| e.path.as_bytes() == record.as_slice())
}

/// PEP 376 quotes a path only when it has to, which keeps the common case byte-identical to what
/// every wheel builder emits.
fn csv_quote(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// URL-safe base64 without padding, which is the form `RECORD` uses.
///
/// Hand-rolled rather than pulled in: twenty lines against a dependency in the crate whose whole
/// claim is that it depends on nothing that can perform I/O.
fn base64url_nopad(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(A[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

// --- gem metadata --------------------------------------------------------------------------------
//
// These run inside `metadata.gz`, which the archive model has already descended into, so `applies`
// asks where this archive was found rather than what it contains.
//
// A note on tiers. A gemspec `date` is a build timestamp and a `rubygems_version` is the tool that
// packaged it: both are environment noise that happens to be serialized inside a file rather than
// stored in a header. The tier is about *what* is normalized, not *where* it lives, so both are
// `Metadata`. `cert_chain` is a certificate chain over content we are rebuilding, which is the same
// argument that puts signature exclusion at `Structural`.

fn in_gem_metadata(cx: &Cx) -> bool {
    cx.archive_path_ends_with(b"metadata.gz")
}

/// Replace the whole of a line beginning `prefix`, returning `None` when there is nothing to do.
///
/// Line-anchored rather than a regex: three fixed patterns do not justify a dependency in the crate
/// whose claim is that it depends on nothing that can perform I/O.
fn replace_line(text: &str, prefix: &str, replacement: &str) -> Option<String> {
    if !text
        .lines()
        .any(|l| l.starts_with(prefix) && l != replacement)
    {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with(prefix) {
            out.push_str(replacement);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    Some(out)
}

/// A member's bytes as text, or `None` when they are not valid UTF-8, which every pass that edits
/// text takes as its cue to leave the member exactly as it is.
///
/// The seven text passes decoded lossily before their `-v2` ids: each invalid sequence became
/// U+FFFD, and a pass that rewrote the member wrote the replacement back. Two members that
/// differed only in an invalid byte then stabilized to the same bytes: two gemspecs, one with 0xFF
/// where the other had 0xFE, matched as a clean `normalized` through `gem-metadata-date`
/// (`docs/16-findings.md` §3.106). A pass that needs text and is not given any has nothing it can
/// normalize, and the bytes compare as they are. Each pass took a new id because its output on
/// such a member changed, and the set digest covers pass ids, not pass code
/// (`docs/19-distribution-and-lookup.md` §11, open question 1).
fn text_of(e: &Entry) -> Option<String> {
    String::from_utf8(e.body_bytes().ok()?.into_owned()).ok()
}

fn rewrite_body(e: &mut Entry, f: impl Fn(&str) -> Option<String>) -> Touched {
    let Some(text) = text_of(e) else {
        return Touched::NONE;
    };
    let Some(new) = f(&text) else {
        return Touched::NONE;
    };
    let before = text.len() as u64;
    match e.body_mut() {
        Ok(b) => {
            *b = new.into_bytes();
            e.meta.size = b.len() as u64;
            Touched::entry_bytes(before.abs_diff(e.meta.size).max(1))
        }
        Err(_) => Touched::NONE,
    }
}

entry_pass!(
    /// The date the gem was packaged. `-v2`: a gemspec that is not valid UTF-8 is left as it is
    /// (`text_of`).
    GemMetadataDate,
    "gem-metadata-date-v2",
    RiskTier::Metadata,
    in_gem_metadata,
    |e| {
        rewrite_body(e, |t| {
            replace_line(t, "date:", "date: 1980-01-02 00:00:00.000000000 Z")
        })
    }
);

entry_pass!(
    /// The RubyGems version that packaged the gem, which is a property of the build host. `-v2`: a
    /// gemspec that is not valid UTF-8 is left as it is (`text_of`).
    GemMetadataRubygemsVersion,
    "gem-metadata-rubygems-version-v2",
    RiskTier::Metadata,
    in_gem_metadata,
    |e| { rewrite_body(e, |t| replace_line(t, "rubygems_version:", "rubygems_version: 0.0.0")) }
);

entry_pass!(
    /// A certificate chain over members we are rebuilding, made with a key we will never hold.
    /// `-v2`: a gemspec that is not valid UTF-8 is left as it is (`text_of`).
    GemMetadataCertChain,
    "gem-metadata-cert-chain-v2",
    RiskTier::Structural,
    in_gem_metadata,
    |e| {
        rewrite_body(e, |t| {
            // `cert_chain:` followed by its block: continuation lines start with a space or a dash.
            let start = t.lines().position(|l| l.starts_with("cert_chain:"))?;
            let lines: Vec<&str> = t.lines().collect();
            if lines[start] == "cert_chain: []" {
                return None;
            }
            let mut end = start + 1;
            while end < lines.len() && lines[end].starts_with([' ', '-']) {
                end += 1;
            }
            let mut out = String::with_capacity(t.len());
            for l in &lines[..start] {
                out.push_str(l);
                out.push('\n');
            }
            out.push_str("cert_chain: []\n");
            for l in &lines[end..] {
                out.push_str(l);
                out.push('\n');
            }
            Some(out)
        })
    }
);

// --- nupkg ---------------------------------------------------------------------------------------
//
// A `.nupkg` is an OPC package: a zip carrying a `.nuspec`, the payload under `lib/`, and three
// pieces of packaging bookkeeping that have nothing to do with what the package contains. All three
// were measured against a real pair rather than reasoned about — two `dotnet pack` runs over
// identical source, and `newtonsoft.json.11.0.1.nupkg` as nuget.org serves it.
//
// The good news first: the compiled assembly was **byte-identical across packs**. Roslyn's
// deterministic compilation is on by default for SDK projects, so the hard part of this ecosystem is
// already solved upstream and what remains is packaging noise.

/// The publisher signature nuget.org attaches, which a rebuilder can never produce.
///
/// Added by the gallery *after* the author packed, so it is present on every published package and
/// on nothing anyone builds. Not a claim about the payload we are rebuilding — it is the gallery's
/// countersignature over the bytes it received — which is why this sits at `Structural` beside the
/// gem signature pass rather than at `Lossy` beside `direct_url.json`.
fn is_nupkg_signature(path: &[u8]) -> bool {
    path == b".signature.p7s"
}

archive_pass!(
    NupkgSignature,
    "nupkg-signature",
    RiskTier::Structural,
    is_zip,
    |a| {
        let before = a.entries.len();
        a.entries.retain(|e| !is_nupkg_signature(e.path.as_bytes()));
        match before - a.entries.len() {
            0 => Touched::NONE,
            n => Touched {
                entries: n as u32,
                bytes: 0,
            },
        }
    }
);

/// The random GUID in the core-properties path, and the `_rels/.rels` entry that points at it.
///
/// `dotnet pack` names this file after a fresh GUID on every invocation, so two packs of identical
/// source differ in a member *name* — and in `_rels/.rels`, which carries that name as a `Target`.
/// Measured: two packs minutes apart produced
/// `…/55d4e0b4ecfa412baa282881ce747f48.psmdcp` and `…/4f28fcb5c9304310a279a6ce74f94f55.psmdcp`.
///
/// The relationship `Id` attributes are the second random value, and the one easy to miss by fixing
/// only the path: they varied between those same two packs, and against the published package they
/// differ in case as well (`R192ff84775f641df` from NuGet 4.5 against `R2BEFEA914E60C8DE` from
/// NuGet 7.0). Both are rewritten here, because normalizing the name and leaving a random `Id`
/// beside it would leave the comparison failing on the half nobody looked at.
///
/// `Structural`: the renaming is bijective and nothing is dropped. The stabilized form is only ever
/// compared, never redistributed, so a canonical name costs a consumer nothing.
const PSMDCP_DIR: &[u8] = b"package/services/metadata/core-properties/";
const PSMDCP_CANONICAL: &[u8] = b"package/services/metadata/core-properties/core.psmdcp";

fn is_psmdcp(path: &[u8]) -> bool {
    path.starts_with(PSMDCP_DIR) && path.ends_with(b".psmdcp")
}

/// Rewrite `Target="/…/<guid>.psmdcp"` and every `Id="…"` in an OPC relationships part.
///
/// Byte-level rather than through an XML parser, for the reason `embedded.rs` gives for reading a
/// `.nuspec` the same way: one element, in the judgement half's neighbourhood, is not worth a
/// dependency. The cost is that this rewrites the attribute wherever it appears, which for a file
/// whose entire content is three relationship elements is the intent rather than a hazard.
fn normalize_rels(body: &mut Vec<u8>) -> bool {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    let mut ids = 0usize;
    let mut changed = false;

    while i < body.len() {
        // `Target="…psmdcp"` — replace the whole attribute value with the canonical path.
        if body[i..].starts_with(b"Target=\"") {
            let start = i + b"Target=\"".len();
            if let Some(end) = body[start..]
                .iter()
                .position(|b| *b == b'"')
                .map(|p| start + p)
            {
                let value = &body[start..end];
                if value.ends_with(b".psmdcp") {
                    out.extend_from_slice(b"Target=\"/");
                    out.extend_from_slice(PSMDCP_CANONICAL);
                    out.push(b'"');
                    // Only a target not already canonical is a change, or a second pass over
                    // stabilized bytes claims work and the set stops being idempotent.
                    changed |= value.strip_prefix(b"/") != Some(PSMDCP_CANONICAL);
                    i = end + 1;
                    continue;
                }
            }
        }
        // `Id="R…"` — numbered by position, so the result is stable and the two relationships keep
        // distinct ids rather than collapsing onto one.
        if body[i..].starts_with(b"Id=\"") {
            let start = i + b"Id=\"".len();
            if let Some(end) = body[start..]
                .iter()
                .position(|b| *b == b'"')
                .map(|p| start + p)
            {
                let replacement = format!("Id=\"R{ids}\"");
                if body[start..end] != replacement.as_bytes()[b"Id=\"".len()..replacement.len() - 1]
                {
                    changed = true;
                }
                out.extend_from_slice(replacement.as_bytes());
                ids += 1;
                i = end + 1;
                continue;
            }
        }
        out.push(body[i]);
        i += 1;
    }

    if changed {
        *body = out;
    }
    changed
}

archive_pass!(
    NupkgPackagingNames,
    "nupkg-packaging-names",
    RiskTier::Structural,
    is_zip,
    |a| {
        // Only where this really is an OPC package. A plain zip with no relationships part is a
        // wheel or a jar, and renaming members of one of those on the strength of a suffix is the
        // kind of over-application a risk tier cannot excuse.
        let has_rels = a
            .entries
            .iter()
            .any(|e| e.path.as_bytes() == b"_rels/.rels");
        if !has_rels {
            return Touched::NONE;
        }

        let mut touched = Touched::NONE;
        for e in a.entries.iter_mut() {
            if is_psmdcp(e.path.as_bytes()) && e.path.as_bytes() != PSMDCP_CANONICAL {
                // `rename_to`, not a bare assignment: the comparison names members from the
                // stabilized archive, and anything that goes back to the bytes on disk needs the
                // spelling they are actually under.
                e.rename_to(trigon_core::EntryPath::new(PSMDCP_CANONICAL.to_vec()));
                touched.entries += 1;
            }
            if e.path.as_bytes() == b"_rels/.rels" {
                // A body we cannot read is left alone rather than dropped: a relationships part
                // that will not decode is a difference worth reporting, not one to normalize away.
                if let Ok(body) = e.body_mut() {
                    if normalize_rels(body) {
                        touched.entries += 1;
                    }
                }
            }
        }
        touched
    }
);

entry_pass!(
    /// Which tool packed it, and on what operating system.
    ///
    /// The core-properties part records `<lastModifiedBy>` — for the published Newtonsoft.Json
    /// 11.0.1 that is `NuGet.Build.Tasks.Pack, Version=4.5.0.4, …;Microsoft Windows NT
    /// 10.0.16299.0;.NET Framework 4.5`, naming a Windows machine in 2018. No rebuild on any other
    /// machine can match it, and it says nothing about the package's contents.
    ///
    /// `Metadata`, for the same reason `gem-metadata-rubygems-version-v2` is: this records the
    /// packaging tool, not the payload.
    NupkgPackagerVersion,
    "nupkg-packager-version",
    RiskTier::Metadata,
    is_zip,
    |e| {
        if !is_psmdcp(e.path.as_bytes()) && e.path.as_bytes() != PSMDCP_CANONICAL {
            return Touched::NONE;
        }
        let Ok(body) = e.body_mut() else {
            return Touched::NONE;
        };
        let (open, close) = (&b"<lastModifiedBy>"[..], &b"</lastModifiedBy>"[..]);
        let Some(start) = body.windows(open.len()).position(|w| w == open) else {
            return Touched::NONE;
        };
        let from = start + open.len();
        let Some(rel) = body[from..].windows(close.len()).position(|w| w == close) else {
            return Touched::NONE;
        };
        if rel == 0 {
            return Touched::NONE;
        }
        let before = body.len();
        body.splice(from..from + rel, std::iter::empty());
        Touched {
            entries: 1,
            bytes: (before - body.len()) as u64,
        }
    }
);

/// Two spellings of one target framework, thirty NuGet releases apart.
///
/// A `.nupkg` names each payload folder after a target framework, and NuGet's own spelling of a
/// PCL profile changed: the 2018 client wrote `lib/portable-net45%2Bwin8%2Bwp8%2Bwpa81` — percent
/// encoding the `+` — and a modern one writes `lib/portable45-net45+win8+wp8+wpa81`, with the
/// profile's .NET version spliced in after `portable`. Measured on Newtonsoft.Json 11.0.1: the
/// components and their order are identical on both sides, and only the spelling differs.
///
/// Without this, a rebuild that reproduced both PCL assemblies exactly reports them as four
/// members only in upstream and four only in the rebuild — a total miss on the framework that was
/// hardest to build, for a reason that is a filename convention.
///
/// `Structural`: the mapping is a rename, nothing is added or dropped, and the stabilized form is
/// only ever compared. Applied before the entry ordering, because a rename after the sort leaves
/// the order stale.
fn canonical_portable(segment: &[u8]) -> Option<Vec<u8>> {
    if !segment.starts_with(b"portable") {
        return None;
    }
    // `portable45-net45+...` -> `portable-net45+...`. Only digits, and only immediately after the
    // word: anything else is a folder name we do not recognise and must not rewrite.
    let rest = &segment[b"portable".len()..];
    let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    let mut out = b"portable".to_vec();
    out.extend_from_slice(&rest[digits..]);

    // `%2B` -> `+`, in either case. Done after the prefix so both spellings converge on one.
    let mut decoded = Vec::with_capacity(out.len());
    let mut i = 0;
    while i < out.len() {
        if out[i] == b'%' && i + 2 < out.len() && out[i + 1] == b'2' && (out[i + 2] | 0x20) == b'b'
        {
            decoded.push(b'+');
            i += 3;
        } else {
            decoded.push(out[i]);
            i += 1;
        }
    }
    (decoded != segment).then_some(decoded)
}

entry_pass!(
    NupkgPortableFolderName,
    "nupkg-portable-folder-name",
    RiskTier::Structural,
    is_zip,
    |e| {
        let path = e.path.as_bytes().to_vec();
        // Only the framework segment of a payload path, which is the second component of `lib/`.
        let Some(rest) = path.strip_prefix(b"lib/".as_slice()) else {
            return Touched::NONE;
        };
        let Some(slash) = rest.iter().position(|c| *c == b'/') else {
            return Touched::NONE;
        };
        let Some(canonical) = canonical_portable(&rest[..slash]) else {
            return Touched::NONE;
        };
        let mut next = b"lib/".to_vec();
        next.extend_from_slice(&canonical);
        next.extend_from_slice(&rest[slash..]);
        // See `nupkg-packaging-names`: renaming has to leave the original recoverable.
        e.rename_to(trigon_core::EntryPath::new(next));
        Touched {
            entries: 1,
            bytes: 0,
        }
    }
);

#[cfg(test)]
mod nupkg_portable_tests {
    use super::canonical_portable;

    #[test]
    fn the_two_spellings_of_one_profile_converge() {
        // Both taken verbatim from a real comparison: the published Newtonsoft.Json 11.0.1 on the
        // left, a `dotnet pack` of its own source on the right.
        let old = b"portable-net45%2Bwin8%2Bwp8%2Bwpa81".as_slice();
        let new = b"portable45-net45+win8+wp8+wpa81".as_slice();
        assert_eq!(
            canonical_portable(old).unwrap(),
            b"portable-net45+win8+wp8+wpa81".to_vec()
        );
        assert_eq!(
            canonical_portable(new).unwrap(),
            b"portable-net45+win8+wp8+wpa81".to_vec()
        );
    }

    #[test]
    fn the_other_profile_converges_too() {
        for s in [
            b"portable-net40%2Bsl5%2Bwin8%2Bwp8%2Bwpa81".as_slice(),
            b"portable40-net40+sl5+win8+wp8+wpa81".as_slice(),
        ] {
            assert_eq!(
                canonical_portable(s).unwrap(),
                b"portable-net40+sl5+win8+wp8+wpa81".to_vec()
            );
        }
    }

    #[test]
    fn a_framework_that_is_not_portable_is_left_alone() {
        // The pass must not touch the seven target frameworks that already agree.
        for s in [
            b"net45".as_slice(),
            b"netstandard2.0".as_slice(),
            b"net6.0".as_slice(),
        ] {
            assert_eq!(
                canonical_portable(s),
                None,
                "{}",
                String::from_utf8_lossy(s)
            );
        }
    }

    #[test]
    fn a_name_already_canonical_reports_no_change() {
        // `Touched` is how a run says which passes did anything; a pass that claims an entry it
        // did not change inflates the applied list a verdict is read against.
        assert_eq!(canonical_portable(b"portable-net45+win8"), None);
    }

    #[test]
    fn only_digits_immediately_after_the_word_are_dropped() {
        // `portable-net45...` has no digits to strip; `portable45-...` has two. A rule that
        // stripped any digits would mangle the profile's own version numbers.
        assert_eq!(
            canonical_portable(b"portable45-net45+win8").unwrap(),
            b"portable-net45+win8".to_vec()
        );
        assert_eq!(canonical_portable(b"portablish-net45"), None);
    }
}

/// Whether a `.nupkg` member is text that a packer wrote line endings into.
///
/// By extension, not by sniffing. A heuristic that guessed at content would eventually rewrite a
/// `.dll` that happened to contain no `0x00` in its first page, and the cost of that mistake — a
/// false match on an executable member — is the most expensive one in the system.
fn is_nupkg_text(path: &[u8]) -> bool {
    const TEXT: &[&[u8]] = &[b".nuspec", b".rels", b".psmdcp", b".xml", b".md", b".txt"];
    TEXT.iter().any(|e| path.ends_with(e))
}

entry_pass!(
    /// CRLF against LF, which is what a Windows publisher and a Linux rebuilder disagree about
    /// before they disagree about anything else.
    ///
    /// **The highest-leverage difference in this ecosystem, and not a quirk of one package.** NuGet
    /// writes a package's text members with the line endings of the machine that packed it, so a
    /// package published from Windows — which is most of them, historically — differs from any
    /// Linux rebuild in every `.nuspec`, `.rels`, `.psmdcp`, `[Content_Types].xml`, `.md` and
    /// generated `.xml` doc it contains. Measured on Newtonsoft.Json 11.0.1: nine of twenty-three
    /// members are byte-identical once this is applied and differ without it.
    ///
    /// **`Content`, not `Metadata`.** These are bytes a consumer receives, and the provenance cap
    /// is meant to bite: a package that matches only after its line endings are rewritten has not
    /// been reproduced byte for byte, and `NormalizedWithCaveats` is the honest ceiling for it.
    NupkgTextEol,
    "nupkg-text-eol",
    RiskTier::Content,
    is_zip,
    |e| {
        if !is_nupkg_text(e.path.as_bytes()) {
            return Touched::NONE;
        }
        let Ok(body) = e.body_mut() else {
            return Touched::NONE;
        };
        // Only `\r` immediately before `\n`. A lone `\r` is a classic-Mac line ending and a lone
        // `\n` is already what we want; rewriting either would be changing the file rather than
        // reconciling two spellings of the same break.
        let before = body.len();
        let mut out = Vec::with_capacity(before);
        let mut i = 0;
        while i < body.len() {
            if body[i] == b'\r' && body.get(i + 1) == Some(&b'\n') {
                i += 1;
                continue;
            }
            out.push(body[i]);
            i += 1;
        }
        if out.len() == before {
            return Touched::NONE;
        }
        *body = out;
        Touched {
            entries: 1,
            bytes: (before - body.len()) as u64,
        }
    }
);

/// Sort the `<member>` elements of a generated XML documentation file by name.
///
/// Roslyn emits them in the host's collation order, and Windows and ICU disagree about where `.`
/// sorts — so the same source produces the same elements in a different order on a different
/// machine. Measured on Newtonsoft.Json 11.0.1: exactly one twenty-one-line block moves, in four of
/// the nine doc files, with no content difference at all.
///
/// Byte-level rather than through an XML parser, for the reason `embedded.rs` gives for reading a
/// `.nuspec` the same way. The shape this relies on is narrow and is checked before anything is
/// rewritten: one `<members>` element whose children are `<member ...>` elements.
fn sort_doc_members(body: &[u8]) -> Option<Vec<u8>> {
    let open = b"<members>";
    let close = b"</members>";
    let start = body.windows(open.len()).position(|w| w == open)? + open.len();
    let end = body.windows(close.len()).position(|w| w == close)?;
    if end <= start {
        return None;
    }
    let inner = &body[start..end];

    // Split on the element boundary rather than on lines: a `<member>` body can contain anything,
    // including text that looks like a tag.
    let mark = b"<member ";
    let mut cuts = Vec::new();
    let mut i = 0;
    while let Some(p) = inner[i..].windows(mark.len()).position(|w| w == mark) {
        cuts.push(i + p);
        i += p + mark.len();
    }
    if cuts.len() < 2 {
        return None;
    }
    let mut blocks: Vec<&[u8]> = Vec::with_capacity(cuts.len());
    for (n, c) in cuts.iter().enumerate() {
        let stop = cuts.get(n + 1).copied().unwrap_or(inner.len());
        blocks.push(&inner[*c..stop]);
    }
    let lead = &inner[..cuts[0]];

    // Keyed on the `name` attribute, which is the documented identity of the element. Ordering by
    // the whole block would sort by the documentation text, which is not stable under an edit that
    // changes only prose.
    let key = |b: &&[u8]| -> Vec<u8> {
        let m = b"name=\"";
        match b.windows(m.len()).position(|w| w == m) {
            Some(p) => {
                let from = p + m.len();
                let to = b[from..].iter().position(|c| *c == b'"').unwrap_or(0) + from;
                b[from..to].to_vec()
            }
            None => Vec::new(),
        }
    };
    let mut sorted = blocks.clone();
    sorted.sort_by_key(key);
    if sorted == blocks {
        return None;
    }

    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..start]);
    out.extend_from_slice(lead);
    for b in sorted {
        out.extend_from_slice(b);
    }
    out.extend_from_slice(&body[end..]);
    Some(out)
}

// `-v2` because what it reports changed. It rewrote the file and said it had changed no bytes, so
// `applied` signed `bytesChanged: 0` for a body it had rewritten and no edit named the member it
// had reconciled. Now it counts the bytes it wrote, and that count is signed, so the same id would
// re-derive old statements to a different `applied` under the digest they were made with
// (`docs/19-distribution-and-lookup.md` §11, open question 1).
entry_pass!(
    NupkgDocMemberOrder,
    "nupkg-doc-member-order-v2",
    RiskTier::Structural,
    is_zip,
    |e| {
        // Only the generated documentation beside an assembly, which is where the ordering comes
        // from a collation rather than from the author.
        let p = e.path.as_bytes();
        if !p.starts_with(b"lib/") || !p.ends_with(b".xml") {
            return Touched::NONE;
        }
        let Ok(body) = e.body_mut() else {
            return Touched::NONE;
        };
        let Some(sorted) = sort_doc_members(body) else {
            return Touched::NONE;
        };
        *body = sorted;
        // The body is rewritten, and saying so is what names it: a body change is attributed from
        // the bytes an entry pass reports.
        Touched::entry_bytes(body.len() as u64)
    }
);

#[cfg(test)]
mod nupkg_text_tests {
    use super::{is_nupkg_text, sort_doc_members};

    #[test]
    fn only_text_members_are_candidates_for_rewriting() {
        for yes in [
            b"Newtonsoft.Json.nuspec".as_slice(),
            b"_rels/.rels".as_slice(),
            b"[Content_Types].xml".as_slice(),
            b"LICENSE.md".as_slice(),
            b"lib/net45/Newtonsoft.Json.xml".as_slice(),
        ] {
            assert!(is_nupkg_text(yes), "{}", String::from_utf8_lossy(yes));
        }
        // The one that must never be rewritten. A content pass that reached an assembly could turn
        // a real difference into a match, which is the most expensive mistake in the system.
        for no in [
            b"lib/net45/Newtonsoft.Json.dll".as_slice(),
            b".signature.p7s".as_slice(),
            b"lib/net45/Newtonsoft.Json.pdb".as_slice(),
        ] {
            assert!(!is_nupkg_text(no), "{}", String::from_utf8_lossy(no));
        }
    }

    #[test]
    fn doc_members_sort_by_name_and_keep_their_bodies() {
        let doc = b"<?xml version=\"1.0\"?>\n<doc>\n<members>\n\
            <member name=\"T:B\">\n<summary>bee</summary>\n</member>\n\
            <member name=\"T:A\">\n<summary>ay</summary>\n</member>\n\
            </members>\n</doc>\n"
            .as_slice();
        let out = sort_doc_members(doc).expect("the order changed");
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.find("T:A").unwrap() < text.find("T:B").unwrap(),
            "not sorted: {text}"
        );
        // Bodies travel with their elements rather than being reordered independently.
        assert!(
            text.contains("<member name=\"T:A\">\n<summary>ay</summary>"),
            "{text}"
        );
        assert!(
            text.contains("<member name=\"T:B\">\n<summary>bee</summary>"),
            "{text}"
        );
        // And the frame is untouched.
        assert!(
            text.starts_with("<?xml version=\"1.0\"?>\n<doc>\n<members>"),
            "{text}"
        );
        assert!(text.trim_end().ends_with("</members>\n</doc>"), "{text}");
    }

    #[test]
    fn a_document_already_in_order_reports_no_change() {
        // `Touched` is what a verdict's `applied` list is read against; a pass that claims an entry
        // it did not change inflates it.
        let doc = b"<doc><members><member name=\"T:A\"/><member name=\"T:B\"/></members></doc>";
        assert!(sort_doc_members(doc).is_none());
    }

    #[test]
    fn a_shape_this_does_not_understand_is_left_alone() {
        // No `<members>`, one member, or an unterminated document: all reasons to do nothing rather
        // than to rewrite on a guess.
        assert!(sort_doc_members(b"<doc>no members here</doc>").is_none());
        assert!(
            sort_doc_members(b"<doc><members><member name=\"T:A\"/></members></doc>").is_none()
        );
        assert!(sort_doc_members(b"<doc><members><member name=\"T:B\"/>").is_none());
    }
}

#[cfg(test)]
mod dotnet_assembly_tests {
    use super::{
        RECORD_BYTES, codeview, dotnet_build_identity_regions, embedded_pdb, pdb_checksum,
    };

    /// `ilcanon`'s one-method fixture with a debug directory appended to its section: `entries`
    /// entries, each naming one CodeView record of `record` bytes appended after them.
    fn with_debug_entries(entries: usize, record: usize) -> Vec<u8> {
        use crate::ilcanon::tests::{RVA, assembly_with_sections};
        let put =
            |f: &mut Vec<u8>, at: usize, x: u32| f[at..at + 4].copy_from_slice(&x.to_le_bytes());
        // The fixture's one section header, where its bytes start, and the debug directory's slot.
        let (header, raw, slot) = (0x178, 0x200, 0x128);
        let mut f = assembly_with_sections(1, 1);
        let rva = |o: usize| RVA + (o - raw) as u32;
        let table = f.len();
        let at = table + 28 * entries;
        f.resize(at, 0);
        for e in (table..at).step_by(28) {
            put(&mut f, e + 12, 2); // CodeView
            put(&mut f, e + 16, record as u32);
            put(&mut f, e + 20, rva(at));
            put(&mut f, e + 24, at as u32);
        }
        let mut cv = b"RSDS".to_vec();
        cv.extend_from_slice(&[0x33; 20]);
        cv.extend_from_slice(b"x.pdb\0");
        cv.resize(record, 0);
        f.extend_from_slice(&cv);
        let len = (f.len() - raw) as u32;
        put(&mut f, header + 8, len); // VirtualSize
        put(&mut f, header + 16, len); // SizeOfRawData
        put(&mut f, slot, rva(table));
        put(&mut f, slot + 4, (28 * entries) as u32);
        f
    }

    #[test]
    fn a_debug_record_is_read_once_however_many_entries_name_it() {
        // Each entry's record was read as the entry came, and only then were they checked for
        // overlap: two thousand entries naming one 64 KB record read it two thousand times, 128 MB,
        // before the pass declined, a cost that grows with the square of the file, in a verifier
        // and in the archived wasm set, which has no fuel limit. Placed first, the overlap is seen
        // before a byte of any record is read.
        let one = with_debug_entries(1, 64 * 1024);
        RECORD_BYTES.with(|n| n.set(0));
        assert!(
            dotnet_build_identity_regions(&one).is_some(),
            "one entry is zeroed"
        );
        assert_eq!(
            RECORD_BYTES.with(|n| n.get()),
            64 * 1024,
            "its record read once"
        );

        let many = with_debug_entries(2000, 64 * 1024);
        RECORD_BYTES.with(|n| n.set(0));
        assert!(dotnet_build_identity_regions(&many).is_none());
        let read = RECORD_BYTES.with(|n| n.get());
        assert!(
            read <= many.len() as u64,
            "{read} bytes of records read in a file of {}",
            many.len()
        );
    }

    /// The whole point, against two real assemblies: with the code already identical, zeroing the
    /// build/signing identity makes the bytes equal. Gated on two paths so the suite runs without
    /// them; point them at a published assembly and its rebuild to check the residual closes.
    #[test]
    fn dotnet_identity_closes_the_residual_between_two_real_assemblies() {
        let (Ok(pa), Ok(pb)) = (
            std::env::var("TRIGON_DOTNET_A"),
            std::env::var("TRIGON_DOTNET_B"),
        ) else {
            eprintln!("skipped: set TRIGON_DOTNET_A and TRIGON_DOTNET_B to two assemblies");
            return;
        };
        let mut a = std::fs::read(pa).unwrap();
        let mut b = std::fs::read(pb).unwrap();
        let before = a.iter().zip(&b).filter(|(x, y)| x != y).count();
        for buf in [&mut a, &mut b] {
            for (o, l) in dotnet_build_identity_regions(buf).unwrap_or_default() {
                buf[o..o + l].fill(0);
            }
        }
        let after = a.iter().zip(&b).filter(|(x, y)| x != y).count();
        eprintln!("differing bytes: {before} before, {after} after identity normalization");
        // A reduction, not necessarily zero: the signature, MVID, timestamps and debug data are
        // fixed-location and close here, but a residual can remain when the two builds laid their
        // debug/PDB data out differently (a different PDB path length shifts it) — that is the
        // build environment, not something a byte-zeroing stabilizer can reach. See B46.
        assert!(
            after < before,
            "identity normalization changed nothing ({before} bytes)"
        );
    }

    /// A non-managed input is left whole: no `MZ`, or a PE with no CLI header, yields no regions.
    #[test]
    fn a_non_managed_input_yields_no_regions() {
        assert!(dotnet_build_identity_regions(b"not a PE at all").is_none());
        assert!(dotnet_build_identity_regions(&[]).is_none());
        // `MZ` but nothing after: must not panic, must decline.
        assert!(dotnet_build_identity_regions(b"MZ").is_none());
    }

    /// A debug entry's data is zeroed only when it is laid out as its type's is. A record that runs
    /// on past its terminator, a digest of the wrong length, a hash this does not know, and bytes
    /// that only begin like a record are none of them.
    #[test]
    fn each_debug_record_is_recognised_by_its_layout_and_nothing_else() {
        let mut cv = b"RSDS".to_vec();
        cv.extend_from_slice(&[0x33; 20]);
        cv.extend_from_slice(b"/src/obj/Demo.pdb\0");
        assert!(codeview(&cv));
        let mut padded = cv.clone();
        padded.extend_from_slice(&[0; 3]);
        assert!(codeview(&padded), "zeros after the terminator are padding");
        let mut more = cv.clone();
        more.push(0x2a);
        assert!(
            !codeview(&more),
            "a byte after the path is not the record's"
        );
        assert!(!codeview(&cv[..24]), "no path, so no terminator");
        let mut nb10 = cv.clone();
        nb10[..4].copy_from_slice(b"NB10");
        assert!(!codeview(&nb10), "a signature no managed compiler writes");

        let mut sum = b"SHA256\0".to_vec();
        sum.extend_from_slice(&[0xee; 32]);
        assert!(pdb_checksum(&sum));
        assert!(!pdb_checksum(&sum[..sum.len() - 1]), "one byte short");
        let mut long = sum.clone();
        long.push(0);
        assert!(!pdb_checksum(&long), "one byte over");
        let mut md5 = b"MD5\0".to_vec();
        md5.extend_from_slice(&[0xee; 16]);
        assert!(
            !pdb_checksum(&md5),
            "a hash this does not know the length of"
        );

        assert!(embedded_pdb(b"MPDB\x10\0\0\0\x78\x9c"));
        assert!(
            !embedded_pdb(b"MPDB\0\0\0\0\x78"),
            "a PDB that inflates to nothing"
        );
        assert!(!embedded_pdb(b"MPDB\x10\0\0\0"), "no deflated bytes");
        assert!(
            !embedded_pdb(b"BSJB\x10\0\0\0\x78"),
            "metadata is not a PDB"
        );
    }
}
