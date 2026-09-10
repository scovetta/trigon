//! Golden stabilized digests, and how to change them.
//!
//! The corpus test compares against recorded digests, so **any stabilizer or writer change fails the
//! whole corpus by construction**. That is correct behaviour and it needs a workflow, or the first
//! person to hit it deletes the test. See `docs/05-archive-and-normalization.md` §6.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::corpus::{Manifest, cache_dir};

#[derive(Debug, Deserialize)]
struct Golden {
    #[serde(default)]
    reason: String,
    #[serde(default)]
    corpus_hash: String,
    #[serde(default)]
    entry: Vec<GoldenEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct GoldenEntry {
    file: String,
    stabilized: String,
    #[serde(default)]
    applied: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Report {
    stabilized: String,
    applied: Vec<AppliedJson>,
}

#[derive(Debug, Deserialize)]
struct AppliedJson {
    id: String,
}

/// Compute the current stabilized digest and applied-pass list for every corpus artifact.
fn measure(m: &Manifest, bin: &str) -> Result<Vec<GoldenEntry>> {
    let dir = cache_dir(&m.name);
    let tmp = std::env::temp_dir().join(format!("trigon-golden-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;

    let mut out = Vec::new();
    for a in &m.artifact {
        let input = dir.join(&a.file);
        if !input.exists() {
            bail!(
                "{} is not in the cache; run `xtask corpus fetch` first",
                a.file
            );
        }
        let o = std::process::Command::new(bin)
            .args(["stabilize", "--infile"])
            .arg(&input)
            .arg("--outfile")
            .arg(tmp.join(&a.file))
            .args(["--format", &a.format, "--profile", &a.profile, "--report"])
            .output()
            .context("running trigon stabilize")?;
        if !o.status.success() {
            bail!("{}: {}", a.file, String::from_utf8_lossy(&o.stderr).trim());
        }
        let r: Report = serde_json::from_slice(&o.stdout)
            .with_context(|| format!("parsing the report for {}", a.file))?;
        out.push(GoldenEntry {
            file: a.file.clone(),
            stabilized: r.stabilized,
            applied: r.applied.into_iter().map(|x| x.id).collect(),
        });
    }
    Ok(out)
}

pub fn check(manifest: &Path, bin: &str) -> Result<String> {
    let m = Manifest::load(manifest)?;
    let path = golden_path(manifest);
    if !path.exists() {
        bail!(
            "no golden file at {}; create it with `xtask golden --write --reason \"...\"`",
            path.display()
        );
    }
    let g: Golden = toml::from_str(&std::fs::read_to_string(&path)?)
        .with_context(|| format!("parsing {}", path.display()))?;
    let now = measure(&m, bin)?;
    let was: BTreeMap<&str, &GoldenEntry> = g.entry.iter().map(|e| (e.file.as_str(), e)).collect();

    let mut moved = Vec::new();
    for e in &now {
        match was.get(e.file.as_str()) {
            Some(old) if old.stabilized == e.stabilized => {}
            Some(old) => moved.push((e.file.clone(), old.stabilized.clone(), e.stabilized.clone())),
            None => moved.push((e.file.clone(), "(new)".into(), e.stabilized.clone())),
        }
    }
    if g.corpus_hash != m.content_hash() {
        bail!(
            "the corpus itself changed ({} -> {}), which makes old and new results incomparable.\n\
             Re-gold deliberately: `xtask golden --write --reason \"...\"`",
            &g.corpus_hash[..12.min(g.corpus_hash.len())],
            &m.content_hash()[..12]
        );
    }
    if !moved.is_empty() {
        let detail: String = moved
            .iter()
            .map(|(f, a, b)| format!("    {f}\n      was {}\n      now {}\n", short(a), short(b)))
            .collect();
        bail!(
            "{} golden digest(s) moved:\n{detail}\n\
             If a stabilizer or writer changed, re-gold and say why:\n  \
             xtask golden --write --reason \"what changed and why\"\n\
             If nothing changed, this is a nondeterminism bug and re-golding would bury it.",
            moved.len()
        );
    }
    Ok(format!(
        "golden digests match for all {} artifacts ({})\n  last re-golded: {}\n",
        now.len(),
        &m.content_hash()[..12],
        if g.reason.is_empty() {
            "(no reason recorded)"
        } else {
            g.reason.trim()
        }
    ))
}

pub fn write(manifest: &Path, bin: &str, reason: &str, force: bool) -> Result<String> {
    if reason.trim().is_empty() {
        bail!(
            "--reason is required: a digest move without an explanation is how a regression hides"
        );
    }
    // A digest that moves without a change to the code that produces it is a nondeterminism bug,
    // and re-golding would bury it. `--force` exists for the case where the corpus itself changed.
    if !force && !touched_producing_code()? {
        bail!(
            "no uncommitted change under crates/trigon-archive or crates/trigon-stabilize.\n\
             A digest that moves on its own is a bug rather than a new baseline.\n\
             Pass --force if the corpus changed instead."
        );
    }

    let m = Manifest::load(manifest)?;
    let path = golden_path(manifest);
    let previous: Option<Golden> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| toml::from_str(&t).ok());
    let now = measure(&m, bin)?;

    let mut doc = String::new();
    doc.push_str("# Golden stabilized digests. Regenerate with `xtask golden --write --reason`.\n");
    doc.push_str("# A moved digest is reviewed, never rubber-stamped: see docs/05 §6.\n\n");
    doc.push_str(&format!("reason = {}\n", toml_string(reason.trim())));
    doc.push_str(&format!("corpus_hash = \"{}\"\n", m.content_hash()));
    for e in &now {
        doc.push_str("\n[[entry]]\n");
        doc.push_str(&format!("file = {}\n", toml_string(&e.file)));
        doc.push_str(&format!("stabilized = \"{}\"\n", e.stabilized));
        let ids: Vec<String> = e.applied.iter().map(|i| toml_string(i)).collect();
        doc.push_str(&format!("applied = [{}]\n", ids.join(", ")));
    }
    std::fs::write(&path, doc)?;

    // The review artifact: what moved, grouped by the pass that plausibly moved it.
    let mut out = format!("wrote {}\n  reason: {}\n", path.display(), reason.trim());
    match previous {
        None => out.push_str(&format!(
            "  {} artifacts recorded for the first time\n",
            now.len()
        )),
        Some(p) => {
            let was: BTreeMap<&str, &GoldenEntry> =
                p.entry.iter().map(|e| (e.file.as_str(), e)).collect();
            let mut by_pass: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let mut unchanged = 0;
            for e in &now {
                match was.get(e.file.as_str()) {
                    Some(old) if old.stabilized == e.stabilized => unchanged += 1,
                    Some(old) => {
                        // Passes whose participation changed are the likely cause; if the set is
                        // identical the cause is a writer change, which gets its own bucket.
                        let added: Vec<&String> = e
                            .applied
                            .iter()
                            .filter(|i| !old.applied.contains(i))
                            .collect();
                        let removed: Vec<&String> = old
                            .applied
                            .iter()
                            .filter(|i| !e.applied.contains(i))
                            .collect();
                        let key = if added.is_empty() && removed.is_empty() {
                            // The same passes fired, so the cause is a change in what one of them
                            // does or in how the writer serializes it. Naming it a writer change
                            // would be a guess.
                            "same passes fired; a pass or writer changed behaviour".to_string()
                        } else {
                            let mut k = Vec::new();
                            k.extend(added.iter().map(|i| format!("+{i}")));
                            k.extend(removed.iter().map(|i| format!("-{i}")));
                            k.join(", ")
                        };
                        by_pass.entry(key).or_default().push(e.file.clone());
                    }
                    None => by_pass
                        .entry("(new artifact)".into())
                        .or_default()
                        .push(e.file.clone()),
                }
            }
            out.push_str(&format!(
                "  {} unchanged, {} moved\n",
                unchanged,
                now.len() - unchanged
            ));
            for (cause, files) in by_pass {
                out.push_str(&format!("    {cause}\n"));
                for f in files {
                    out.push_str(&format!("      {f}\n"));
                }
            }
        }
    }
    out.push_str("  attach this to the pull request\n");
    Ok(out)
}

/// Whether the code that *produces* digests has uncommitted changes.
///
/// `src` only. A new test file under `crates/trigon-archive` cannot move a digest, and counting it
/// would let a nondeterminism bug be re-golded away while someone was writing tests.
fn touched_producing_code() -> Result<bool> {
    let o = std::process::Command::new("git")
        .args([
            "status",
            "--porcelain",
            "--",
            "crates/trigon-archive/src",
            "crates/trigon-stabilize/src",
            "crates/trigon-core/src",
        ])
        .output()?;
    Ok(!o.stdout.is_empty())
}

fn golden_path(manifest: &Path) -> std::path::PathBuf {
    manifest.with_extension("golden.toml")
}

fn short(h: &str) -> String {
    h.chars().take(16).collect()
}

fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
