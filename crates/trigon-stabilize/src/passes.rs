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

archive_pass!(
    TarEntryOrder,
    "tar-entry-order",
    RiskTier::Structural,
    is_tar,
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
        let RawMeta::Zip(raw) = &mut e.raw else {
            return Touched::NONE;
        };
        if raw.creator_version == 0 && raw.reader_version == 0 && raw.external_attrs == 0 {
            return Touched::NONE;
        }
        raw.creator_version = 0;
        raw.reader_version = 0;
        raw.external_attrs = 0;
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

archive_pass!(GzipMeta, "gzip-meta", RiskTier::Metadata, has_gzip, |a| {
    let Trailer::Gzip(h) = &mut a.trailer else {
        return Touched::NONE;
    };
    // MTIME 0 is how gzip spells "no timestamp available", so absent and zero are the same bytes.
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
    // The trailer is the container, not a member, so the archive carries the dirty bit. It decides
    // whether a nested archive is re-serialized or written back byte for byte.
    a.mark_trailer_dirty();
    Touched::entry()
});

// --- ecosystem-specific --------------------------------------------------------------------------

entry_pass!(
    CargoVcsHash,
    "cargo-vcs-hash",
    RiskTier::Content,
    is_tar,
    |e| {
        if !e.path.ends_with(b".cargo_vcs_info.json") {
            return Touched::NONE;
        }
        let Ok(text) = e
            .body_bytes()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
        else {
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

entry_pass!(
    NpmInstallFields,
    "npm-install-fields",
    RiskTier::Metadata,
    is_tar,
    |e| {
        if e.path.file_name() != b"package.json" {
            return Touched::NONE;
        }
        let Ok(text) = e
            .body_bytes()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
        else {
            return Touched::NONE;
        };
        const DROP: [&str; 4] = ["\"_resolved\"", "\"_integrity\"", "\"_from\"", "\"_id\""];
        let mut out = String::with_capacity(text.len());
        let mut removed = 0u64;
        for line in text.lines() {
            if DROP.iter().any(|k| line.trim_start().starts_with(k)) {
                removed += line.len() as u64;
                continue;
            }
            out.push_str(line);
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
    is_tar,
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
    is_tar,
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

entry_pass!(
    /// Zero the source mtime embedded in a timestamp-validated `.pyc`.
    ///
    /// A PEP 552 header is 16 bytes: a 4-byte magic, a 4-byte flags word, and 8 bytes whose meaning
    /// bit 0 of the flags selects. Clear, and they are a 4-byte source mtime and a 4-byte source
    /// size. Set, and they are an 8-byte hash of the source.
    ///
    /// Only the mtime is touched. The magic identifies the bytecode version. The flags word says
    /// how to read the rest, so zeroing it changes what the file means. The source size and the
    /// source hash are both derived from the source: neither can differ while the source matches,
    /// so zeroing them removes a signal and normalizes nothing. The reference has no `.pyc` pass at
    /// all, which is why this one is a listed deviation.
    PycHeader,
    "pyc-header",
    RiskTier::Content,
    is_zip,
    |e| {
        if !e.path.ends_with(b".pyc") {
            return Touched::NONE;
        }
        let Ok(body) = e.body_bytes() else {
            return Touched::NONE;
        };
        if body.len() < 16 {
            return Touched::NONE;
        }
        let flags = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let hash_based = flags & 1 == 1;
        if hash_based || body[8..12].iter().all(|b| *b == 0) {
            return Touched::NONE;
        }
        match e.body_mut() {
            Ok(b) => {
                b[8..12].fill(0);
                Touched::entry_bytes(4)
            }
            Err(_) => Touched::NONE,
        }
    }
);

/// Regenerate `*.dist-info/RECORD` from the members that are actually present.
///
/// This is why `Stage::Finalize` exists. `RECORD` is a manifest *of* membership, and earlier passes
/// change membership: `wheel-direct-url` removes a file, and a definitions-supplied `exclude_path`
/// can remove any file at all. Regenerating it at `Default` would produce a manifest of the wheel as
/// it arrived rather than the wheel as it stands.
#[derive(Debug)]
pub struct WheelRecord;

impl Stabilizer for WheelRecord {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("wheel-record")
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
        let Some(idx) = a
            .entries
            .iter()
            .position(|e| e.path.ends_with(b".dist-info/RECORD"))
        else {
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

fn rewrite_body(e: &mut Entry, f: impl Fn(&str) -> Option<String>) -> Touched {
    let Ok(text) = e
        .body_bytes()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
    else {
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
    /// The date the gem was packaged.
    GemMetadataDate,
    "gem-metadata-date",
    RiskTier::Metadata,
    in_gem_metadata,
    |e| {
        rewrite_body(e, |t| {
            replace_line(t, "date:", "date: 1980-01-02 00:00:00.000000000 Z")
        })
    }
);

entry_pass!(
    /// The RubyGems version that packaged the gem, which is a property of the build host.
    GemMetadataRubygemsVersion,
    "gem-metadata-rubygems-version",
    RiskTier::Metadata,
    in_gem_metadata,
    |e| { rewrite_body(e, |t| replace_line(t, "rubygems_version:", "rubygems_version: 0.0.0")) }
);

entry_pass!(
    /// A certificate chain over members we are rebuilding, made with a key we will never hold.
    GemMetadataCertChain,
    "gem-metadata-cert-chain",
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
