//! Finding the artifacts a differential test actually needs.
//!
//! A corpus sampled by download count is 95% small pure-Python wheels and exercises none of the
//! strata where two writers can disagree. This walks real registries, parses headers with the same
//! parser the differential test uses, records which strata each artifact satisfies, and **discards
//! the bytes**. Nothing is kept that is not needed. See `docs/15-corpora.md` §2.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use trigon_archive::{Body, EntryKind, Limits, RawMeta, parse};
use trigon_core::{Format, Note};

const UA: &str = "trigon-corpus/0.1 (+https://github.com/trigon-dev/trigon; corpus scan)";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Candidate {
    pub purl: String,
    pub file: String,
    pub url: String,
    pub sha256: String,
    pub bytes: u64,
    pub format: String,
    pub profile: String,
    pub strata: Vec<String>,
}

/// One artifact to consider, before we know anything about its shape.
struct Target {
    purl: String,
    file: String,
    url: String,
    format: Format,
    profile: &'static str,
}

pub fn scan(ecosystem: &str, limit: usize, out: &Path, delay_ms: u64) -> Result<String> {
    let targets = match ecosystem {
        "npm" => enumerate_npm(limit)?,
        "cargo" => enumerate_cargo(limit)?,
        "pypi" => enumerate_pypi(limit)?,
        "rubygems" => enumerate_rubygems(limit)?,
        other => bail!("unknown ecosystem `{other}`; try npm, cargo, pypi or rubygems"),
    };

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out)?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut ok = 0usize;
    // A fetch failure is the registry's business. A parse failure on a real published artifact is
    // ours, and lumping the two together would hide it.
    let mut unfetchable = 0usize;
    let mut unparseable: Vec<String> = Vec::new();

    for (i, t) in targets.iter().enumerate() {
        // One request at a time, with a pause. A corpus build downloads from registries that owe us
        // nothing, and getting abuse-flagged is a human problem to unwind.
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        let Ok(bytes) = fetch(&t.url) else {
            unfetchable += 1;
            continue;
        };
        let sha = hex(&Sha256::digest(&bytes));
        let n = bytes.len() as u64;
        let Some(strata) = classify(&bytes, t.format) else {
            unparseable.push(t.purl.clone());
            continue;
        };
        for s in &strata {
            *counts.entry(s.clone()).or_default() += 1;
        }
        ok += 1;
        let c = Candidate {
            purl: t.purl.clone(),
            file: t.file.clone(),
            url: t.url.clone(),
            sha256: sha,
            bytes: n,
            format: t.format.to_string(),
            profile: t.profile.to_string(),
            strata,
        };
        writeln!(file, "{}", serde_json::to_string(&c)?)?;
    }

    let mut report = format!("scanned {ok} artifacts from {ecosystem}\n");
    for (s, n) in counts {
        report.push_str(&format!("  {s:<22} {n}\n"));
    }
    report.push_str(&format!("  {unfetchable} could not be fetched\n"));
    if !unparseable.is_empty() {
        report.push_str(&format!(
            "  {} PUBLISHED ARTIFACTS OUR PARSER REJECTED, which is a finding rather than noise:\n",
            unparseable.len()
        ));
        for p in unparseable.iter().take(20) {
            report.push_str(&format!("    {p}\n"));
        }
    }
    report.push_str(&format!("  appended to {}\n", out.display()));
    Ok(report)
}

/// Which strata an artifact satisfies. `None` when it will not parse at all.
///
/// Uses the production parser rather than a second header reader, so a stratum the scanner finds is
/// one the differential test can actually exercise.
fn classify(bytes: &[u8], format: Format) -> Option<Vec<String>> {
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(bytes.to_vec(), format, &Limits::default(), &mut notes).ok()?;
    let a = &p.archive;
    let mut s = Vec::new();

    if a.entries.is_empty() {
        s.push("empty-archive".into());
    }
    if !a.duplicate_paths().is_empty() {
        s.push("duplicate-paths".into());
    }
    if a.entries.iter().any(|e| e.path.len() > 100) {
        s.push("long-names".into());
    }
    if a.entries
        .iter()
        .any(|e| std::str::from_utf8(e.path.as_bytes()).is_err())
    {
        s.push("non-utf8-paths".into());
    }
    if a.entries
        .iter()
        .any(|e| !matches!(e.kind, EntryKind::Regular | EntryKind::Directory))
    {
        s.push("non-regular-entries".into());
    }
    if a.entries
        .iter()
        .any(|e| matches!(e.body, Body::Nested { .. }))
    {
        s.push("nested-archives".into());
    }
    if a.entries
        .iter()
        .any(|e| e.meta.size == 0 && matches!(e.kind, EntryKind::Regular))
    {
        s.push("empty-members".into());
    }
    if a.entries
        .iter()
        .any(|e| matches!(&e.raw, RawMeta::Tar(t) if !t.pax.is_empty()))
    {
        s.push("pax-records".into());
    }
    if a.entries
        .iter()
        .any(|e| matches!(&e.raw, RawMeta::Zip(z) if z.flags & 0x8 != 0))
    {
        s.push("data-descriptors".into());
    }
    if a.entries
        .iter()
        .any(|e| matches!(&e.raw, RawMeta::Zip(z) if z.method == 0))
    {
        s.push("stored-entries".into());
    }
    // Zip64 is a property of the container framing rather than of any member, so it is read from
    // the bytes: the end-of-central-directory record has its own signature.
    if format == Format::Zip && bytes.windows(4).any(|w| w == [0x50, 0x4b, 0x06, 0x06]) {
        s.push("zip64".into());
    }
    if bytes.len() > 50 * 1024 * 1024 {
        s.push("large".into());
    } else if bytes.len() < 4096 {
        s.push("tiny".into());
    }
    if a.entries.len() > 1000 {
        s.push("many-members".into());
    }
    if notes.iter().any(|n| n.code.is_noteworthy()) {
        s.push("notes-on-parse".into());
    }
    if s.is_empty() {
        s.push("plain".into());
    }
    Some(s)
}

// --- enumerators ---------------------------------------------------------------------------------
//
// Breadth beats popularity here. A download-ranked sample is unusually clean, and the strata this
// corpus exists for live in the tail.

fn enumerate_npm(limit: usize) -> Result<Vec<Target>> {
    // The replication feed is mostly tombstones: a slice of two hundred rows came back with zero
    // live packages. The search API paginates, returns live entries, and carries the version, which
    // also saves a packument fetch per package.
    //
    // Seed terms spread the sample across corners of the registry rather than around one topic.
    const SEEDS: &[&str] = &[
        "cli", "test", "react", "util", "server", "parser", "config", "json", "log", "http",
        "stream", "build", "file", "data", "async", "type", "crypto", "date", "color", "path",
    ];
    let mut out = Vec::new();
    'outer: for seed in SEEDS {
        for from in (0..500).step_by(250) {
            let Ok(v) = get_json(&format!(
                "https://registry.npmjs.org/-/v1/search?text={seed}&size=250&from={from}"
            )) else {
                continue;
            };
            let objects = v["objects"].as_array().cloned().unwrap_or_default();
            if objects.is_empty() {
                break;
            }
            for o in objects {
                let (Some(name), Some(version)) = (
                    o["package"]["name"].as_str(),
                    o["package"]["version"].as_str(),
                ) else {
                    continue;
                };
                // The tarball path uses the unscoped basename even for a scoped package.
                let base = name.rsplit('/').next().unwrap_or(name);
                let file = format!("{base}-{version}.tgz");
                out.push(Target {
                    purl: format!("pkg:npm/{name}@{version}"),
                    url: format!("https://registry.npmjs.org/{name}/-/{file}"),
                    file,
                    format: Format::TarGz,
                    profile: "npm-tarball",
                });
                if out.len() >= limit {
                    break 'outer;
                }
            }
        }
    }
    Ok(out)
}

fn enumerate_cargo(limit: usize) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    for page in 1.. {
        let v: serde_json::Value = get_json(&format!(
            "https://crates.io/api/v1/crates?page={page}&per_page=100&sort=alphabetical"
        ))?;
        let crates = v["crates"].as_array().cloned().unwrap_or_default();
        if crates.is_empty() {
            break;
        }
        for c in crates {
            let (Some(name), Some(ver)) = (c["name"].as_str(), c["max_version"].as_str()) else {
                continue;
            };
            out.push(Target {
                purl: format!("pkg:cargo/{name}@{ver}"),
                file: format!("{name}-{ver}.crate"),
                url: format!("https://static.crates.io/crates/{name}/{ver}/download"),
                format: Format::TarGz,
                profile: "crate",
            });
            if out.len() >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn enumerate_pypi(limit: usize) -> Result<Vec<Target>> {
    // The simple index is the whole project list. We only need names, so take a slice of it rather
    // than streaming 45 MB every run.
    let html = get_text("https://pypi.org/simple/")?;
    let names: Vec<&str> = html
        .lines()
        .filter_map(|l| l.split("/simple/").nth(1))
        .filter_map(|l| l.split('/').next())
        .collect();
    let stride = (names.len() / limit.max(1)).max(1);

    let mut out = Vec::new();
    for name in names.iter().step_by(stride) {
        let Ok(v) = get_json(&format!("https://pypi.org/pypi/{name}/json")) else {
            continue;
        };
        let urls = v["urls"].as_array().cloned().unwrap_or_default();
        // One artifact per project: prefer a wheel, since that is the zip path.
        let pick = urls
            .iter()
            .find(|u| u["packagetype"] == "bdist_wheel")
            .or_else(|| urls.first());
        let Some(u) = pick else { continue };
        let (Some(url), Some(file)) = (u["url"].as_str(), u["filename"].as_str()) else {
            continue;
        };
        let version = v["info"]["version"].as_str().unwrap_or("0");
        let (format, profile) = if file.ends_with(".whl") {
            (Format::Zip, "wheel")
        } else {
            (Format::TarGz, "tar-gzip")
        };
        out.push(Target {
            purl: format!("pkg:pypi/{name}@{version}"),
            file: file.to_string(),
            url: url.to_string(),
            format,
            profile,
        });
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

fn enumerate_rubygems(limit: usize) -> Result<Vec<Target>> {
    let v: serde_json::Value = get_json("https://rubygems.org/api/v1/activity/just_updated.json")?;
    let mut out = Vec::new();
    for g in v.as_array().cloned().unwrap_or_default() {
        let (Some(name), Some(ver)) = (g["name"].as_str(), g["version"].as_str()) else {
            continue;
        };
        out.push(Target {
            purl: format!("pkg:gem/{name}@{ver}"),
            file: format!("{name}-{ver}.gem"),
            url: format!("https://rubygems.org/downloads/{name}-{ver}.gem"),
            format: Format::Tar,
            profile: "gem",
        });
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

// --- selection -----------------------------------------------------------------------------------

/// Turn scanned candidates into a manifest, taking up to `per_stratum` artifacts per stratum.
///
/// Rare strata are the point, so they are filled first: an artifact that satisfies
/// `duplicate-paths` is taken before one that only satisfies `plain`.
pub fn select(from: &Path, out: &Path, per_stratum: usize, name: &str) -> Result<String> {
    let text =
        std::fs::read_to_string(from).with_context(|| format!("reading {}", from.display()))?;
    let all: Vec<Candidate> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;

    // Rarest first, so a scarce stratum claims its artifacts before a common one takes them.
    let mut freq: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &all {
        for s in &c.strata {
            *freq.entry(s.as_str()).or_default() += 1;
        }
    }
    let mut strata: Vec<&str> = freq.keys().copied().collect();
    strata.sort_by_key(|s| freq[s]);

    let mut chosen: BTreeMap<&str, Candidate> = BTreeMap::new();
    let mut filled: BTreeMap<&str, usize> = BTreeMap::new();
    for s in &strata {
        for c in &all {
            if filled.get(s).copied().unwrap_or(0) >= per_stratum {
                break;
            }
            if c.strata.iter().any(|x| x == s) && !chosen.contains_key(c.sha256.as_str()) {
                chosen.insert(&c.sha256, c.clone());
                *filled.entry(s).or_default() += 1;
            }
        }
    }

    let mut picked: Vec<&Candidate> = chosen.values().collect();
    picked.sort_by(|a, b| a.purl.cmp(&b.purl));

    let mut doc = format!(
        "schema = 1\nname = {name:?}\ndescription = \"\"\"\nStratified by structure rather than by \
         popularity: a download-ranked sample is unusually clean, and the cases where two writers \
         disagree live in the tail. Selected by `xtask corpus select` from a scan of \
         {} candidates.\n\"\"\"\ncreated = {:?}\n\n[provenance]\nmethod = \"stratified-by-structure\"\n\
         source = \"registry enumeration, see xtask/src/scan.rs\"\nscript = \"xtask corpus scan | select\"\n",
        all.len(),
        today()
    );
    for c in &picked {
        doc.push_str(&format!(
            "\n[[artifact]]\npurl = {:?}\nfile = {:?}\nurl = {:?}\nsha256 = {:?}\nbytes = {}\n\
             format = {:?}\nprofile = {:?}\ntags = [{}]\n",
            c.purl,
            c.file,
            c.url,
            c.sha256,
            c.bytes,
            c.format,
            c.profile,
            c.strata
                .iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    std::fs::write(out, doc)?;

    let mut report = format!(
        "selected {} artifacts into {}\n",
        picked.len(),
        out.display()
    );
    for s in &strata {
        report.push_str(&format!(
            "  {s:<22} {} of {} available\n",
            filled.get(s).copied().unwrap_or(0),
            freq[s]
        ));
    }
    Ok(report)
}

// --- plumbing ------------------------------------------------------------------------------------

fn fetch(url: &str) -> Result<Vec<u8>> {
    let o = std::process::Command::new("curl")
        .args(["-sfL", "--max-time", "60", "-A", UA, url])
        .output()?;
    if !o.status.success() {
        bail!("fetching {url}");
    }
    Ok(o.stdout)
}

fn get_text(url: &str) -> Result<String> {
    Ok(String::from_utf8_lossy(&fetch(url)?).into_owned())
}

fn get_json(url: &str) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&fetch(url)?)?)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn today() -> String {
    let o = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output();
    o.ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}
