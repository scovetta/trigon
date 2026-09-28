//! Where everything is in an evidence repository (`docs/19` §2.3, §5): record files, evidence
//! files, and the lookup index, whose paths are derived from each key a record is found by.
//!
//! One definition for the writer and every reader: `publish` files a record, its evidence and its
//! index entries at these paths (`docs/19` §10 phase 5), `--remote` reads them (phase 6), and the
//! verifier finds records and evidence here. The fan-out is the first four hex characters,
//! `<aa>/<bb>/`, everywhere, so at a million records no directory holds more than a few dozen
//! entries; and every digest is whole — paths have no length limit worth the name, so there is no
//! truncation and no collision class.
//!
//! **The index is derived data.** It narrows a search for a reader without the log, and a client
//! holding the log never reads it: the log is the authority on what exists (`docs/19` §5, §8).
//! [`index_files`] derives the whole of it from a verified log, which is what `publish` writes
//! beside each record and what `publish --reconcile` rebuilds when it is in doubt.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use trigon_core::Digest;
use trigon_core::purl::canonicalize_under;

use crate::location::printable;
use crate::log::{Leaf, LogError, RecordLeaf, VerifiedSource};

/// The directory record files are in.
pub const RECORDS: &str = "records";
/// The directory evidence files are in, by algorithm.
pub const EVIDENCE: &str = "evidence";
/// The directory the lookup index is in.
pub const INDEX: &str = "index";

/// `<aa>/<bb>`: a key's first four hex characters.
fn fan_out(hex: &str) -> String {
    format!("{}/{}", &hex[..2], &hex[2..4])
}

/// `records/<aa>/<bb>/<hex>.json`: a record file, named by the sha256 of its own bytes.
pub fn record_path(record: &Digest) -> String {
    let hex = record.to_hex();
    format!("{RECORDS}/{}/{hex}.json", fan_out(&hex))
}

/// `evidence/sha256/<aa>/<bb>/<hex>`: an evidence file, named by the sha256 of its bytes, stored
/// once however many records name it.
pub fn evidence_path(digest: &Digest) -> String {
    let hex = digest.to_hex();
    format!("{EVIDENCE}/sha256/{}/{hex}", fan_out(&hex))
}

/// The length in hex of a digest a key may be, by algorithm: the three a subject carries.
pub(crate) fn digest_len(algorithm: &str) -> Option<usize> {
    match algorithm {
        "sha256" => Some(64),
        "sha512" => Some(128),
        "sha1" => Some(40),
        _ => None,
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn sha256_hex(s: &str) -> String {
    Digest::from_bytes(Sha256::digest(s.as_bytes()).into()).to_hex()
}

/// A key the index files a record under (`docs/19` §5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndexKey {
    /// A digest of the subject — `sha256`, `sha512` or `sha1` — in lowercase hex, whole.
    Digest {
        algorithm: &'static str,
        hex: String,
    },
    /// A canonical purl, with its version, under canonicalisation rule `rule`: `purl<rule>`.
    Purl { rule: u32, purl: String },
    /// A package in its versionless form under rule `rule` — every version of it: `pkg<rule>`.
    Package { rule: u32, package: String },
}

impl IndexKey {
    /// A digest key, checked: an algorithm a subject carries, and lowercase hex of its length.
    pub fn digest(algorithm: &str, hex: &str) -> Result<IndexKey, String> {
        let (algorithm, len) = ["sha256", "sha512", "sha1"]
            .into_iter()
            .find(|a| *a == algorithm)
            .and_then(|a| Some((a, digest_len(a)?)))
            .ok_or_else(|| {
                format!(
                    "`{}` is not a digest a record is filed under: sha256, sha512 or sha1",
                    printable(algorithm)
                )
            })?;
        if !is_lower_hex(hex, len) {
            return Err(format!(
                "`{}` is not a {algorithm} digest: {len} lowercase hex digits",
                printable(hex)
            ));
        }
        Ok(IndexKey::Digest {
            algorithm,
            hex: hex.to_string(),
        })
    }

    /// A purl key, checked: `purl` is canonical under `rule`, and names a version.
    pub fn purl(rule: u32, purl: &str) -> Result<IndexKey, String> {
        let c = canonicalize_under(rule, purl).map_err(|e| e.to_string())?;
        if c.as_str() != purl || !c.has_version() {
            return Err(format!(
                "`{}` is not a canonical purl with a version under rule {rule}",
                printable(purl)
            ));
        }
        Ok(IndexKey::Purl {
            rule,
            purl: purl.to_string(),
        })
    }

    /// A package key, checked: `package` is the versionless form of itself under `rule`.
    pub fn package(rule: u32, package: &str) -> Result<IndexKey, String> {
        let c = canonicalize_under(rule, package).map_err(|e| e.to_string())?;
        if c.package() != package {
            return Err(format!(
                "`{}` is not a package's versionless form under rule {rule}: that is `{}`",
                printable(package),
                c.package()
            ));
        }
        Ok(IndexKey::Package {
            rule,
            package: package.to_string(),
        })
    }

    /// Its directory under `index/`: `sha256`, `sha512`, `sha1`, `purl1`, `pkg1`. The digit is the
    /// canonicalisation rule, so changing the rule starts new paths rather than silently missing
    /// old ones.
    pub fn kind(&self) -> String {
        match self {
            IndexKey::Digest { algorithm, .. } => (*algorithm).to_string(),
            IndexKey::Purl { rule, .. } => format!("purl{rule}"),
            IndexKey::Package { rule, .. } => format!("pkg{rule}"),
        }
    }

    /// The hex its file is named by: the digest itself, or the sha256 of the canonical purl or
    /// package, since purl characters are not path-safe.
    pub fn hex(&self) -> String {
        match self {
            IndexKey::Digest { hex, .. } => hex.clone(),
            IndexKey::Purl { purl, .. } => sha256_hex(purl),
            IndexKey::Package { package, .. } => sha256_hex(package),
        }
    }

    /// `index/<kind>/<aa>/<bb>/<hex>.json`.
    pub fn path(&self) -> String {
        let hex = self.hex();
        format!("{INDEX}/{}/{}/{hex}.json", self.kind(), fan_out(&hex))
    }

    /// What an index file's `key` says: `<kind>:<digest>`, or `<kind>:<canonical string>` for a
    /// purl or a package, which a reader hashes to check the file is at the path its key derives.
    pub fn name(&self) -> String {
        match self {
            IndexKey::Digest { hex, .. } => format!("{}:{hex}", self.kind()),
            IndexKey::Purl { purl, .. } => format!("{}:{purl}", self.kind()),
            IndexKey::Package { package, .. } => format!("{}:{package}", self.kind()),
        }
    }

    /// Read a key as [`Self::name`] writes it.
    pub fn parse(name: &str) -> Result<IndexKey, String> {
        let (kind, value) = name.split_once(':').ok_or_else(|| {
            format!(
                "`{}` is not an index key: `<kind>:<value>`",
                printable(name)
            )
        })?;
        let rule = |prefix: &str| -> Option<u32> {
            let n = kind.strip_prefix(prefix)?;
            (!n.starts_with('0') && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                .then(|| n.parse().ok())
                .flatten()
        };
        if let Some(r) = rule("purl") {
            return IndexKey::purl(r, value);
        }
        if let Some(r) = rule("pkg") {
            return IndexKey::package(r, value);
        }
        IndexKey::digest(kind, value)
    }

    /// Every key a record's leaf files it under: each digest its subject carries, its purl, and
    /// its package — under the rule the leaf names, since a leaf is never rewritten.
    pub fn of_leaf(leaf: &RecordLeaf) -> Result<Vec<IndexKey>, LogError> {
        let bad = |why: String| {
            LogError::Malformed(format!(
                "the record leaf for sha256:{} names a key that cannot be filed: {why}",
                leaf.record.to_hex()
            ))
        };
        let mut keys = Vec::new();
        for (algorithm, hex) in &leaf.subject {
            keys.push(IndexKey::digest(algorithm, hex).map_err(bad)?);
        }
        keys.push(IndexKey::purl(leaf.purl_canon, &leaf.purl).map_err(bad)?);
        let c = canonicalize_under(leaf.purl_canon, &leaf.purl).map_err(|e| bad(e.to_string()))?;
        keys.push(IndexKey::package(leaf.purl_canon, c.package()).map_err(bad)?);
        Ok(keys)
    }
}

impl std::fmt::Display for IndexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

/// An index file: a key, and every record filed under it with where its leaf is (`docs/19` §4.1).
///
/// ```json
/// {"key": "sha512:1df6…", "records": [{"leaf": 1203, "record": "sha256:7f3a…"}]}
/// ```
///
/// Annotated with nothing a client trusts: it narrows a search, and every entry is checked
/// against the log before anything it leads to is believed. Read without `deny_unknown_fields`,
/// like everything a reader may meet from a later writer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexFile {
    /// The key, as [`IndexKey::name`] writes it.
    pub key: String,
    /// Every record filed under the key, in the order the log holds them.
    pub records: Vec<IndexEntry>,
}

/// One record in an index file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// The sha256 of the record file.
    #[serde(with = "crate::log::leaf::sha256_ref")]
    pub record: Digest,
    /// The leaf's index in its log.
    pub leaf: u64,
    /// The log the leaf is in, where it is not the repository's first: its directory, `log/<n>`.
    /// A leaf's index alone names a leaf of one log, and a repository may hold a succession.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

impl IndexFile {
    /// The file's bytes: canonical JSON, so that the same index is the same bytes whoever wrote it.
    pub fn encode(&self) -> Result<Vec<u8>, LogError> {
        let v = serde_json::to_value(self)
            .map_err(|e| LogError::Malformed(format!("could not write an index file: {e}")))?;
        Ok(trigon_core::jcs::canonicalize(&v)
            .map_err(|e| LogError::Malformed(format!("could not write an index file: {e}")))?
            .into_bytes())
    }

    /// Read an index file, and check that its key is one.
    pub fn parse(bytes: &[u8]) -> Result<IndexFile, LogError> {
        let f: IndexFile = serde_json::from_slice(bytes).map_err(|e| {
            LogError::Malformed(format!(
                "this is not an index file: {}",
                printable(&e.to_string())
            ))
        })?;
        IndexKey::parse(&f.key)
            .map_err(|why| LogError::Malformed(format!("this index file's key: {why}")))?;
        Ok(f)
    }
}

/// Every index file a verified log implies, by path: an entry under every key of every record
/// leaf, in the order the chain of logs holds them.
pub fn index_files(source: &VerifiedSource) -> Result<BTreeMap<String, IndexFile>, LogError> {
    index_files_after(source, &[])
}

/// Every index file the chain of logs implies once `appended` is logged after the last log's
/// leaves, by path. What `publish` writes each index file of a record it appends from (`docs/19`
/// §10 phase 5 step 4): derived from the log whole, never read and edited, so an index file a
/// push credential altered or removed is written again as the log implies it.
pub fn index_files_after(
    source: &VerifiedSource,
    appended: &[Leaf],
) -> Result<BTreeMap<String, IndexFile>, LogError> {
    let mut files: BTreeMap<String, IndexFile> = BTreeMap::new();
    let last = source.logs.len().saturating_sub(1);
    for (n, chained) in source.logs.iter().enumerate() {
        let log = (chained.dir != "log").then(|| chained.dir.clone());
        let size = chained.log.size();
        let more = match n == last {
            true => appended,
            false => &[],
        };
        let leaves = chained
            .log
            .leaves()
            .chain(more.iter().enumerate().map(|(i, l)| (size + i as u64, l)));
        for (index, leaf) in leaves {
            let Leaf::Record(r) = leaf else {
                continue;
            };
            for key in IndexKey::of_leaf(r)? {
                files
                    .entry(key.path())
                    .or_insert_with(|| IndexFile {
                        key: key.name(),
                        records: Vec::new(),
                    })
                    .records
                    .push(IndexEntry {
                        record: r.record,
                        leaf: index,
                        log: log.clone(),
                    });
            }
        }
    }
    Ok(files)
}
