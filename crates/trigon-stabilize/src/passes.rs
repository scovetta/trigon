//! The builtin stabilizer catalogue.
//!
//! Risk tiers follow `docs/05-archive-and-normalization.md` §3. Note where signature and checksum
//! exclusion sit: `Structural`, not `Lossy`. A `checksums.yaml.gz` is a hash *of* the members we are
//! rebuilding and a `.sig` is a signature *over* them, made with a key we will never hold. Neither
//! is content a consumer reads, and neither can differ while the content matches, so both belong
//! with entry ordering. Calling them `Lossy` would strip the clean tier from every gem and every
//! signed nupkg for no gain in honesty.

use std::sync::Arc;

use trigon_archive::{Archive, Entry, EntryKind, RawMeta, Trailer};
use trigon_core::{Format, RiskTier, StabilizerId};

use crate::{Cx, Stabilizer, Touched};

macro_rules! archive_pass {
    ($name:ident, $id:literal, $risk:expr, $applies:expr, |$a:ident| $body:block) => {
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
    ($name:ident, $id:literal, $risk:expr, $applies:expr, |$e:ident| $body:block) => {
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
    matches!(cx.format(), Format::TarGz | Format::Gzip)
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

entry_pass!(TarXattrs, "tar-xattrs", RiskTier::Metadata, is_tar, |e| {
    let RawMeta::Tar(raw) = &mut e.raw else {
        return Touched::NONE;
    };
    let before = raw.pax.len();
    raw.pax
        .retain(|k, _| !k.starts_with("SCHILY.xattr.") && !k.starts_with("LIBARCHIVE.xattr."));
    if raw.pax.len() == before {
        return Touched::NONE;
    }
    e.mark_dirty();
    Touched::entry()
});

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
