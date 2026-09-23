use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use trigon_archive::{Archive, Body, Entry};
use trigon_core::{Digest, EntryPath};

/// Per-file status after stabilization.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Identical,
    Differs,
    OnlyUpstream,
    OnlyRebuild,
}

/// How a file is treated when deciding how much leniency it gets. Executable content never gets
/// any: a difference there is never benign.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Executable,
    Source,
    Metadata,
    Documentation,
    Binary,
}

impl ContentKind {
    pub fn classify(path: &EntryPath) -> Self {
        let name = String::from_utf8_lossy(path.file_name()).to_ascii_lowercase();
        let ext = name
            .rsplit_once('.')
            .map(|(_, e)| e.to_string())
            .unwrap_or_default();
        match ext.as_str() {
            "so" | "dylib" | "dll" | "exe" | "a" | "o" | "pyd" | "node" | "wasm" | "class" => {
                ContentKind::Executable
            }
            "rs" | "js" | "ts" | "py" | "rb" | "go" | "c" | "h" | "cpp" | "cs" | "java" => {
                ContentKind::Source
            }
            "md" | "rst" | "txt" | "adoc" => ContentKind::Documentation,
            "json" | "toml" | "yaml" | "yml" | "xml" | "cfg" | "ini" => ContentKind::Metadata,
            _ => ContentKind::Binary,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: EntryPath,
    pub status: FileStatus,
    pub kind: ContentKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_digest: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebuild_digest: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebuild_bytes: Option<u64>,
    /// The name this member has **in the published artifact**, when a stabilizer renamed it.
    ///
    /// `path` is the stabilized name, which is the one a comparison should report: it is what the
    /// two sides agree to call the same file. It is not the name either artifact carries, and a
    /// reader who wants the bytes — the management UI's member view, chiefly — has to ask the
    /// archive for the name the archive uses.
    ///
    /// Absent where nothing renamed it, which is almost always. Measured before it existed: 5 of
    /// 23 members on one NuGet divergence page were dead links, and the refusal said "neither
    /// artifact holds a member by that name", which blamed the artifacts for a name this crate
    /// had invented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_raw_path: Option<EntryPath>,
    /// As [`Self::upstream_raw_path`], for the rebuilt side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild_raw_path: Option<EntryPath>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffReport {
    /// Every difference, named by what it *is* rather than by where it turned up.
    ///
    /// The part of a divergence a maintainer can act on. "Four members differ" is an accusation;
    /// `entry:zip.method@lib/x.py` is a thing to go and look at, and it goes into the signed
    /// divergence statement for exactly that reason. Empty when the two sides agree — and empty
    /// while the digests disagree is itself a finding, because it means the difference is below
    /// this vocabulary's resolution.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub codes: std::collections::BTreeSet<String>,
    pub identical: u32,
    pub differs: u32,
    pub only_upstream: u32,
    pub only_rebuild: u32,
    /// Differences in files classified `Executable`. Never benign.
    pub executable_differs: u32,
    pub files: Vec<FileDiff>,
    /// Which passes changed which field of which member — the ground-truth join partner for
    /// [`codes`](Self::codes). A code names a difference the stabilizers *left*; this names, for
    /// every field either side's passes touched, the passes that touched it. The two together
    /// distinguish a difference a pass erased (a `(field, path)` here with no matching code) from
    /// one it could not (a code here) from one nothing addressed (a code with no entry here).
    ///
    /// Empty on an exact match, where nothing fired, and absent from every comparison written
    /// before this field existed — which is what the default is for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_edits: Vec<FieldProvenance>,
    /// The differences left after each pass of the set, from the artifacts as published to the
    /// last pass — how the gap closed, or how far it got. Explanation only; see
    /// [`crate::progression`]. Absent from every comparison written before it existed, and from
    /// one produced by [`crate::compare`] alone, which never saw the published bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progression: Option<crate::progression::Progression>,
}

/// Which passes changed one field of one member, merged and deduplicated across both sides.
///
/// `field` and `path` are spelled exactly as a difference [`code`](DiffReport::codes) spells them
/// (`mode`, `zip.crc32`, `body`; `outer!inner` for a nested member), so the join is a string match.
/// `passes` is sorted, so the blob is stable and signable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldProvenance {
    pub path: String,
    pub field: String,
    pub passes: Vec<String>,
}

/// Compare two stabilized archives member by member.
///
/// Members are keyed by `(path, occurrence)`, so upstream's second `lib/index.js` compares against
/// the rebuild's second one. Keying on path alone would make a duplicate path unmatchable.
///
/// `codes` is left empty here and filled by [`crate::compare`] on a divergence only: naming every
/// field that differs means walking both archives a second time, and on a match there is nothing
/// to name. Every comparison in a sweep is a match if the system is working, so this is the hot
/// path.
pub fn report(upstream: &Archive, rebuild: &Archive) -> DiffReport {
    let u = index(upstream);
    let r = index(rebuild);

    let mut files = Vec::new();
    let mut counts = (0u32, 0u32, 0u32, 0u32, 0u32);

    let mut keys: Vec<_> = u.keys().chain(r.keys()).cloned().collect();
    keys.sort();
    keys.dedup();

    for key in keys {
        let (path, _) = &key;
        let kind = ContentKind::classify(path);
        let (us, rs) = (u.get(&key), r.get(&key));
        let status = match (us, rs) {
            (Some(a), Some(b)) if a.digest == b.digest => {
                counts.0 += 1;
                FileStatus::Identical
            }
            (Some(_), Some(_)) => {
                counts.1 += 1;
                if kind == ContentKind::Executable {
                    counts.4 += 1;
                }
                FileStatus::Differs
            }
            (Some(_), None) => {
                counts.2 += 1;
                FileStatus::OnlyUpstream
            }
            (None, Some(_)) => {
                counts.3 += 1;
                FileStatus::OnlyRebuild
            }
            (None, None) => unreachable!("key came from one of the two maps"),
        };
        files.push(FileDiff {
            path: path.clone(),
            status,
            kind,
            upstream_digest: us.map(|m| m.digest),
            rebuild_digest: rs.map(|m| m.digest),
            upstream_bytes: us.map(|m| m.bytes),
            rebuild_bytes: rs.map(|m| m.bytes),
            // Each side separately: a package published with `%2B` and rebuilt with `portable45-`
            // canonicalize to one name from two different spellings, and going back to either
            // side's bytes needs that side's.
            upstream_raw_path: us.and_then(|m| m.raw.clone()),
            rebuild_raw_path: rs.and_then(|m| m.raw.clone()),
        });
    }

    DiffReport {
        codes: Default::default(),
        identical: counts.0,
        differs: counts.1,
        only_upstream: counts.2,
        only_rebuild: counts.3,
        executable_differs: counts.4,
        files,
        field_edits: Vec::new(),
        progression: None,
    }
}

/// Merge both sides' per-field edits into one deduplicated attribution, keyed by `(path, field)`.
///
/// A field is normalized to one value across the pair, so the pass that wrote it on the upstream
/// side and the pass that wrote it on the rebuild side are, in the intended case, the same id; the
/// union is taken anyway so an asymmetry (a pass that fired on one side only) is not silently
/// dropped. Sorted throughout, so the blob is deterministic.
pub fn merge_edits(sides: [&[trigon_stabilize::FieldEdit]; 2]) -> Vec<FieldProvenance> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_key: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for side in sides {
        for e in side {
            by_key
                .entry((e.path.clone(), e.field.clone()))
                .or_default()
                .insert(e.pass.to_string());
        }
    }
    by_key
        .into_iter()
        .map(|((path, field), passes)| FieldProvenance {
            path,
            field,
            passes: passes.into_iter().collect(),
        })
        .collect()
}

type Key = (EntryPath, u32);

/// One side, keyed by the stabilized name, carrying the raw name beside the bytes.
fn index(a: &Archive) -> BTreeMap<Key, Member> {
    let mut seen: BTreeMap<EntryPath, u32> = BTreeMap::new();
    let mut out = BTreeMap::new();
    walk(a, &mut |e, prefix, raw_prefix| {
        let mut path = prefix.to_vec();
        path.extend_from_slice(e.path.as_bytes());
        let path = EntryPath::new(path);
        let mut raw = raw_prefix.to_vec();
        raw.extend_from_slice(e.raw_path().as_bytes());
        let raw = EntryPath::new(raw);
        let n = seen.entry(path.clone()).or_insert(0);
        let key = (path.clone(), *n);
        *n += 1;
        if let Ok(b) = e.body_bytes() {
            out.insert(
                key,
                Member {
                    digest: Digest::from_bytes(Sha256::digest(&b).into()),
                    bytes: b.len() as u64,
                    // Recorded only where it differs, so the common case costs nothing in the
                    // stored blob and an old comparison reads back identically.
                    raw: (raw != path).then_some(raw),
                },
            );
        }
    });
    out
}

/// One member of one side, as `index` sees it.
struct Member {
    digest: Digest,
    bytes: u64,
    /// The name in the artifact, where a stabilizer renamed it away from the key.
    raw: Option<EntryPath>,
}

/// Depth-first over members, flattening nested archives into `outer.gz!inner/path` keys so a
/// difference inside a `.gem` names the file rather than the container.
///
/// Two prefixes are carried, not one. The stabilized prefix names the member as the comparison
/// reports it; the raw prefix names it as the artifact on disk spells it, which is what anyone
/// going back to the bytes has to ask for. They are the same string until a renaming pass runs,
/// and a container that was itself renamed makes them differ for everything inside it too.
fn walk(a: &Archive, f: &mut impl FnMut(&Entry, &[u8], &[u8])) {
    fn go(a: &Archive, prefix: &[u8], raw_prefix: &[u8], f: &mut impl FnMut(&Entry, &[u8], &[u8])) {
        for e in &a.entries {
            match &e.body {
                Body::Nested { inner, .. } => {
                    let mut p = prefix.to_vec();
                    p.extend_from_slice(e.path.as_bytes());
                    p.push(b'!');
                    let mut rp = raw_prefix.to_vec();
                    rp.extend_from_slice(e.raw_path().as_bytes());
                    rp.push(b'!');
                    go(inner, &p, &rp, f);
                }
                _ => f(e, prefix, raw_prefix),
            }
        }
    }
    go(a, &[], &[], f);
}
