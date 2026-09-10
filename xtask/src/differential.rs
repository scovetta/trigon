//! The M0 differential test.
//!
//! Runs the reference implementation and ours over the same corpus and compares stabilized digests.
//! The criterion is equality **except a checked-in deviation list**: three of the deviations are
//! decisions we defend, one records a gap. An unexplained difference fails the build.
//!
//! `--enable-passes` and `--disable-passes` exist on both sides, so a mismatch localizes to one
//! pass rather than to "somewhere in the pipeline". That is what turns a day of bisecting into a
//! table. See `docs/05-archive-and-normalization.md` §6.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::corpus::{Manifest, cache_dir, digest_of};

#[derive(Debug, Deserialize)]
struct Deviations {
    #[serde(default)]
    deviation: Vec<Deviation>,
}

#[derive(Debug, Deserialize, Clone)]
struct Deviation {
    id: String,
    /// Corpus files this deviation is known to explain. Attribution is per artifact rather than per
    /// format: a list that matches by class lets a genuine bug hide behind an unrelated entry.
    #[serde(default)]
    artifacts: Vec<String>,
    /// Documentation of scope. Not used for matching.
    #[serde(default)]
    #[allow(dead_code)]
    applies_to: Vec<String>,
    summary: String,
    #[serde(default)]
    open: bool,
}

#[derive(Debug)]
enum Verdict {
    Match,
    Explained(Vec<String>),
    Unexplained,
    ReferenceFailed(String),
    OursFailed(String),
}

pub fn run(manifest: &Path, deviations: &Path, reference: &str) -> Result<String> {
    let m = Manifest::load(manifest)?;
    let dev: Deviations = toml::from_str(&std::fs::read_to_string(deviations)?)
        .with_context(|| format!("parsing {}", deviations.display()))?;
    let dir = cache_dir(&m.name);
    let work = tempdir()?;

    let ours = std::env::var("TRIGON_BIN").unwrap_or_else(|_| "target/debug/trigon".into());
    // Resolve once. `which` also searches $GOPATH/bin, which `Command::new` does not, so passing
    // the bare name on would look up a binary we already found and then fail to exec it.
    let Some(reference) = which(reference) else {
        bail!(
            "reference implementation `{reference}` not on PATH or in $GOPATH/bin.\n  \
             go install github.com/google/oss-rebuild/cmd/stabilize@latest"
        );
    };
    let reference = reference.as_str();

    let mut rows = Vec::new();
    let (mut matched, mut explained, mut unexplained, mut errored) = (0, 0, 0, 0);

    for a in &m.artifact {
        let input = dir.join(&a.file);
        if !input.exists() {
            bail!(
                "{} is not in the cache; run `xtask corpus fetch` first",
                a.file
            );
        }
        let go_out = work.join(format!("{}.go", a.file));
        let rs_out = work.join(format!("{}.rs", a.file));

        let ecosystem = ecosystem_for(&a.purl);
        let v = match (
            run_reference(reference, &input, &go_out, ecosystem),
            run_ours(&ours, &input, &rs_out, &a.format, &a.profile),
        ) {
            (Err(e), _) => Verdict::ReferenceFailed(e.to_string()),
            (_, Err(e)) => Verdict::OursFailed(e.to_string()),
            (Ok(()), Ok(())) => {
                let g = digest_of(&go_out)?;
                let r = digest_of(&rs_out)?;
                if g == r {
                    Verdict::Match
                } else {
                    let hits: Vec<String> = dev
                        .deviation
                        .iter()
                        .filter(|d| d.artifacts.iter().any(|f| f == &a.file))
                        .map(|d| {
                            format!(
                                "{}{}: {}",
                                d.id,
                                if d.open { " (OPEN)" } else { "" },
                                d.summary
                            )
                        })
                        .collect();
                    if hits.is_empty() {
                        Verdict::Unexplained
                    } else {
                        Verdict::Explained(hits)
                    }
                }
            }
        };

        match &v {
            Verdict::Match => matched += 1,
            Verdict::Explained(_) => explained += 1,
            Verdict::Unexplained => unexplained += 1,
            _ => errored += 1,
        }
        rows.push((a.file.clone(), a.profile.clone(), v));
        let _ = &a.tags;
    }

    let mut out = String::new();
    out.push_str(&format!(
        "differential against `{reference}`, corpus {} ({})\n\n",
        m.name,
        &m.content_hash()[..12]
    ));
    for (file, profile, v) in &rows {
        let (mark, note) = match v {
            Verdict::Match => ("match", String::new()),
            Verdict::Explained(ids) => (
                "deviates",
                format!(
                    "\n{}",
                    ids.iter()
                        .map(|i| format!("               {i}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            ),
            Verdict::Unexplained => ("UNEXPLAINED", String::new()),
            Verdict::ReferenceFailed(e) => ("ref-failed", format!("  {e}")),
            Verdict::OursFailed(e) => ("ours-failed", format!("  {e}")),
        };
        out.push_str(&format!("  {mark:<12} {file:<38} {profile:<12}{note}\n"));
    }
    out.push_str(&format!(
        "\n  {matched} match, {explained} deviate by a listed entry, {unexplained} unexplained, \
         {errored} errored\n"
    ));

    // An artifact listed in a deviation that no longer mismatches means the deviation was closed by
    // a fix and nobody removed the entry. That is worth failing on too: a stale exemption is a place
    // a future regression can hide.
    let matching: Vec<&str> = rows
        .iter()
        .filter(|(_, _, v)| matches!(v, Verdict::Match))
        .map(|(f, _, _)| f.as_str())
        .collect();
    let stale: Vec<&str> = dev
        .deviation
        .iter()
        .flat_map(|d| d.artifacts.iter())
        .filter(|f| matching.contains(&f.as_str()))
        .map(|s| s.as_str())
        .collect();
    if !stale.is_empty() {
        out.push_str(&format!(
            "\n  stale exemptions (these now match): {}\n",
            stale.join(", ")
        ));
    }

    if unexplained > 0 || errored > 0 || !stale.is_empty() {
        bail!(
            "{out}\ndifferential failed: an unexplained difference is a bug, and a stale exemption is a hiding place"
        );
    }
    Ok(out)
}

fn run_reference(bin: &str, input: &Path, out: &Path, ecosystem: Option<&str>) -> Result<()> {
    // The reference resolves relative paths against the filesystem root, so both must be absolute.
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("--infile")
        .arg(abs(input)?)
        .arg("--outfile")
        .arg(abs(out)?);
    if let Some(e) = ecosystem {
        cmd.arg("--ecosystem").arg(e);
    }
    let o = cmd.output().context("running the reference")?;
    if !o.status.success() {
        bail!(
            "{}",
            String::from_utf8_lossy(&o.stderr)
                .trim()
                .replace('\n', "; ")
        );
    }
    Ok(())
}

fn run_ours(bin: &str, input: &Path, out: &Path, format: &str, profile: &str) -> Result<()> {
    let o = std::process::Command::new(bin)
        .args(["stabilize", "--infile"])
        .arg(input)
        .arg("--outfile")
        .arg(out)
        .args(["--format", format, "--profile", profile])
        .output()
        .context("running trigon")?;
    if !o.status.success() {
        bail!(
            "{}",
            String::from_utf8_lossy(&o.stderr)
                .trim()
                .replace('\n', "; ")
        );
    }
    Ok(())
}

fn ecosystem_for(purl: &str) -> Option<&'static str> {
    // Only where the file extension leaves it ambiguous: a .gem is a tar, and the reference cannot
    // tell from the name alone either.
    purl.starts_with("pkg:gem/").then_some("rubygems")
}

fn abs(p: &Path) -> Result<String> {
    Ok(std::path::absolute(p)?.to_string_lossy().into_owned())
}

fn which(bin: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    let gopath = std::env::var("GOPATH")
        .unwrap_or_else(|_| format!("{}/go", std::env::var("HOME").unwrap_or_default()));
    for dir in path.split(':').chain([format!("{gopath}/bin").as_str()]) {
        let c = Path::new(dir).join(bin);
        if c.is_file() {
            return Some(c.to_string_lossy().into_owned());
        }
    }
    None
}

fn tempdir() -> Result<std::path::PathBuf> {
    let d = std::env::temp_dir().join(format!("trigon-diff-{}", std::process::id()));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}
