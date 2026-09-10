//! Corpus manifests: what we test against, pinned by digest.
//!
//! A corpus is a fixed object rather than a query that returns different rows each week. The
//! manifest is checked in; the artifacts are fetched into a cache outside the repository and never
//! committed. See `docs/15-corpora.md`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub artifact: Vec<Artifact>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Artifact {
    pub purl: String,
    pub file: String,
    pub url: String,
    pub sha256: String,
    pub bytes: u64,
    pub format: String,
    pub profile: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let m: Manifest =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if m.schema != 1 {
            bail!("unsupported manifest schema {}", m.schema);
        }
        Ok(m)
    }

    /// SHA-256 over the sorted artifact digests, one per line.
    ///
    /// Covers the artifacts and nothing else, so editing a description leaves the hash alone while
    /// adding or removing an artifact moves it. Every run records it, because otherwise an
    /// improvement cannot be told apart from a corpus edit.
    pub fn content_hash(&self) -> String {
        let mut rows: Vec<&str> = self.artifact.iter().map(|a| a.sha256.as_str()).collect();
        rows.sort_unstable();
        let mut h = Sha256::new();
        for r in rows {
            h.update(r.as_bytes());
            h.update(b"\n");
        }
        hex(&h.finalize())
    }
}

pub fn cache_dir(name: &str) -> PathBuf {
    let base = std::env::var("TRIGON_CORPUS_DIR").unwrap_or_else(|_| {
        format!(
            "{}/.cache/trigon/corpora",
            std::env::var("HOME").unwrap_or_else(|_| ".".into())
        )
    });
    PathBuf::from(base).join(name)
}

/// Fetch a manifest's artifacts into the cache, verifying each against its pinned digest.
///
/// Politeness is not optional: a corpus build downloads from registries that owe us nothing. One
/// request at a time per host, a declared User-Agent with a contact URL, and a hard stop on 429.
pub fn fetch(manifest: &Path) -> Result<String> {
    let m = Manifest::load(manifest)?;
    let dir = cache_dir(&m.name);
    std::fs::create_dir_all(&dir)?;

    let mut fetched = 0usize;
    let mut cached = 0usize;
    for a in &m.artifact {
        let dest = dir.join(&a.file);
        if dest.exists() && verify(&dest, &a.sha256).unwrap_or(false) {
            cached += 1;
            continue;
        }
        download(&a.url, &dest)?;
        // A mismatch means the registry served something other than what the corpus pins, which is
        // a hard failure rather than a warning.
        let got_bytes = std::fs::metadata(&dest)?.len();
        if got_bytes != a.bytes {
            std::fs::remove_file(&dest).ok();
            bail!("{}: expected {} bytes, got {got_bytes}", a.file, a.bytes);
        }
        if !verify(&dest, &a.sha256)? {
            let got = digest_of(&dest)?;
            std::fs::remove_file(&dest).ok();
            bail!(
                "{}: digest mismatch\n  want {}\n  got  {}",
                a.file,
                a.sha256,
                got
            );
        }
        fetched += 1;
    }
    Ok(format!(
        "corpus {} ({}) ready in {}\n  {}\n  {fetched} fetched, {cached} already cached, {} total",
        m.name,
        &m.content_hash()[..12],
        dir.display(),
        m.description.lines().next().unwrap_or("").trim(),
        m.artifact.len()
    ))
}

fn download(url: &str, dest: &Path) -> Result<()> {
    const UA: &str = "trigon-corpus/0.1 (+https://github.com/trigon-dev/trigon; corpus build)";
    let out = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            "120",
            "--retry",
            "2",
            "--retry-delay",
            "3",
            "--user-agent",
            UA,
            "--output",
            &dest.to_string_lossy(),
            url,
        ])
        .output()
        .context("running curl")?;
    if !out.status.success() {
        bail!(
            "fetching {url}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn verify(path: &Path, want: &str) -> Result<bool> {
    Ok(digest_of(path)? == want)
}

pub fn digest_of(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(hex(&Sha256::digest(&bytes)))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
