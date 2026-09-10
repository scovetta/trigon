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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffReport {
    pub identical: u32,
    pub differs: u32,
    pub only_upstream: u32,
    pub only_rebuild: u32,
    /// Differences in files classified `Executable`. Never benign.
    pub executable_differs: u32,
    pub files: Vec<FileDiff>,
}

/// Compare two stabilized archives member by member.
///
/// Members are keyed by `(path, occurrence)`, so upstream's second `lib/index.js` compares against
/// the rebuild's second one. Keying on path alone would make a duplicate path unmatchable.
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
        let (status, ud, rd, ub, rb) = match (u.get(&key), r.get(&key)) {
            (Some(a), Some(b)) if a.0 == b.0 => {
                counts.0 += 1;
                (
                    FileStatus::Identical,
                    Some(a.0),
                    Some(b.0),
                    Some(a.1),
                    Some(b.1),
                )
            }
            (Some(a), Some(b)) => {
                counts.1 += 1;
                if kind == ContentKind::Executable {
                    counts.4 += 1;
                }
                (
                    FileStatus::Differs,
                    Some(a.0),
                    Some(b.0),
                    Some(a.1),
                    Some(b.1),
                )
            }
            (Some(a), None) => {
                counts.2 += 1;
                (FileStatus::OnlyUpstream, Some(a.0), None, Some(a.1), None)
            }
            (None, Some(b)) => {
                counts.3 += 1;
                (FileStatus::OnlyRebuild, None, Some(b.0), None, Some(b.1))
            }
            (None, None) => unreachable!("key came from one of the two maps"),
        };
        files.push(FileDiff {
            path: path.clone(),
            status,
            kind,
            upstream_digest: ud,
            rebuild_digest: rd,
            upstream_bytes: ub,
            rebuild_bytes: rb,
        });
    }

    DiffReport {
        identical: counts.0,
        differs: counts.1,
        only_upstream: counts.2,
        only_rebuild: counts.3,
        executable_differs: counts.4,
        files,
    }
}

type Key = (EntryPath, u32);

fn index(a: &Archive) -> BTreeMap<Key, (Digest, u64)> {
    let mut seen: BTreeMap<EntryPath, u32> = BTreeMap::new();
    let mut out = BTreeMap::new();
    walk(a, &mut |e, prefix| {
        let mut path = prefix.to_vec();
        path.extend_from_slice(e.path.as_bytes());
        let path = EntryPath::new(path);
        let n = seen.entry(path.clone()).or_insert(0);
        let key = (path, *n);
        *n += 1;
        if let Ok(b) = e.body_bytes() {
            out.insert(
                key,
                (
                    Digest::from_bytes(Sha256::digest(&b).into()),
                    b.len() as u64,
                ),
            );
        }
    });
    out
}

/// Depth-first over members, flattening nested archives into `outer.gz!inner/path` keys so a
/// difference inside a `.gem` names the file rather than the container.
fn walk(a: &Archive, f: &mut impl FnMut(&Entry, &[u8])) {
    fn go(a: &Archive, prefix: &[u8], f: &mut impl FnMut(&Entry, &[u8])) {
        for e in &a.entries {
            match &e.body {
                Body::Nested(inner) => {
                    let mut p = prefix.to_vec();
                    p.extend_from_slice(e.path.as_bytes());
                    p.push(b'!');
                    go(inner, &p, f);
                }
                _ => f(e, prefix),
            }
        }
    }
    go(a, &[], f);
}
