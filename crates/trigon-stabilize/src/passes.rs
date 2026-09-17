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
        Arc::new(NupkgSignature),
        Arc::new(NupkgPortableFolderName),
        Arc::new(NupkgTextEol),
        Arc::new(NupkgDocMemberOrder),
        Arc::new(NupkgPackagingNames),
        Arc::new(NupkgPackagerVersion),
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
    /// `Content` risk, because it rewrites bytes inside a file. Wheels are already capped below
    /// `Normalized` by `wheel-record`, so this costs no outcome that was otherwise reachable, and
    /// it runs at `Default` so `RECORD` is regenerated over the normalized bytes at `Finalize`.
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
                    changed = true;
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
                e.path = trigon_core::EntryPath::new(PSMDCP_CANONICAL.to_vec());
                e.mark_dirty();
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
    /// `Metadata`, for the same reason `gem-metadata-rubygems-version` is: this records the
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
        e.path = trigon_core::EntryPath::new(next);
        e.mark_dirty();
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

entry_pass!(
    NupkgDocMemberOrder,
    "nupkg-doc-member-order",
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
        Touched {
            entries: 1,
            bytes: 0,
        }
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
