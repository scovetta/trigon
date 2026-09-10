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
use crate::signature::{matches, signature};

#[derive(Debug, Deserialize)]
struct Deviations {
    #[serde(default)]
    deviation: Vec<Deviation>,
}

#[derive(Debug, Deserialize, Clone)]
struct Deviation {
    id: String,
    /// The difference codes this deviation explains, as `signature::matches` patterns.
    ///
    /// Attribution is by what the difference *is*, not by which file it turned up in. A list of
    /// filenames grows with every corpus and is trivial to extend without thinking, so a real bug
    /// in a wheel hides the moment some other wheel is exempt. A pattern cannot hide one: a wheel
    /// that differs in a field no deviation claims stays unexplained.
    #[serde(default)]
    signature: Vec<String>,
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
    /// The difference codes that no deviation claims, plus the ones that were claimed. Printing
    /// both is the difference between "a wheel differs" and "this wheel differs in `zip.method`".
    Unexplained(Vec<String>),
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

    if let Some(newer) = source_newer_than(&ours) {
        bail!(
            "{ours} is older than {}.\n  \
             A differential run against a stale build reads exactly like a real difference.\n  \
             cargo build, then re-run.",
            newer.display()
        );
    }

    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
                    // Both outputs are re-parsed to say what differs. A digest comparison alone
                    // cannot tell an exempt difference from a new one.
                    let codes = codes_for(&go_out, &rs_out, &a.format)?;
                    let mut claimed = Vec::new();
                    let mut uncovered = Vec::new();
                    for c in &codes {
                        match dev
                            .deviation
                            .iter()
                            .find(|d| d.signature.iter().any(|p| matches(p, c)))
                        {
                            Some(d) => {
                                used.insert(d.id.clone());
                                if !claimed.contains(&d.id) {
                                    claimed.push(d.id.clone());
                                }
                            }
                            None => uncovered.push(c.clone()),
                        }
                    }
                    if codes.is_empty() {
                        // The digests differ but nothing in the signature vocabulary does. That is
                        // a gap in the test, not a pass.
                        Verdict::Unexplained(vec![
                            "digests differ but no difference code was produced; \
                             the signature vocabulary is missing something"
                                .into(),
                        ])
                    } else if uncovered.is_empty() {
                        Verdict::Explained(
                            claimed
                                .iter()
                                .filter_map(|id| dev.deviation.iter().find(|d| &d.id == id))
                                .map(|d| {
                                    format!(
                                        "{}{}: {}",
                                        d.id,
                                        if d.open { " (OPEN)" } else { "" },
                                        d.summary
                                    )
                                })
                                .collect(),
                        )
                    } else {
                        Verdict::Unexplained(uncovered)
                    }
                }
            }
        };

        match &v {
            Verdict::Match => matched += 1,
            Verdict::Explained(_) => explained += 1,
            Verdict::Unexplained(_) => unexplained += 1,
            _ => errored += 1,
        }
        rows.push((a.file.clone(), a.profile.clone(), v));
        let _ = &a.tags;
    }

    let mut out = String::new();
    // Both binaries are named, and the source tree is checked against ours. A differential run
    // that silently used a stale build reads exactly like a real difference, and once did.
    out.push_str(&format!(
        "differential against `{reference}`, corpus {} ({})\n  ours: {ours}\n\n",
        m.name,
        &m.content_hash()[..12],
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
            Verdict::Unexplained(codes) => ("UNEXPLAINED", format!("\n{}", summarize(codes))),
            Verdict::ReferenceFailed(e) => ("ref-failed", format!("  {e}")),
            Verdict::OursFailed(e) => ("ours-failed", format!("  {e}")),
        };
        out.push_str(&format!("  {mark:<12} {file:<38} {profile:<12}{note}\n"));
    }
    out.push_str(&format!(
        "\n  {matched} match, {explained} deviate by a listed entry, {unexplained} unexplained, \
         {errored} errored\n"
    ));

    // A deviation that explained nothing anywhere in the corpus was either closed by a fix that
    // nobody recorded, or is written in patterns that no longer match anything. Both are places a
    // future regression can hide, so both fail the run.
    // An entry with no patterns makes no claim about the corpus: it records a writer property
    // pinned by the test it names. Only entries that claim to explain a corpus difference can go
    // stale by explaining none.
    let stale: Vec<&str> = dev
        .deviation
        .iter()
        .filter(|d| !d.signature.is_empty() && !used.contains(&d.id))
        .map(|d| d.id.as_str())
        .collect();
    if !stale.is_empty() {
        out.push_str(&format!(
            "\n  stale exemptions (claimed nothing in this corpus): {}\n",
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

/// The first source file newer than the binary under test, if any.
///
/// Cheap, and it catches the failure that costs the most time: editing a stabilizer, forgetting to
/// build, and then reading a table of differences that describe the previous build.
fn source_newer_than(bin: &str) -> Option<std::path::PathBuf> {
    let built = std::fs::metadata(bin).ok()?.modified().ok()?;
    // Only `src`. A test file cannot change the binary under test, and treating one as staleness
    // makes the guard fire on every edit that is not the one it exists to catch.
    let mut stack: Vec<std::path::PathBuf> =
        std::fs::read_dir(crate::workspace_root().join("crates"))
            .ok()?
            .flatten()
            .map(|e| e.path().join("src"))
            .filter(|p| p.is_dir())
            .collect();
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).ok()?.flatten() {
            let p = e.path();
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs")
                && md.modified().is_ok_and(|t| t > built)
            {
                return Some(p);
            }
        }
    }
    None
}

/// Re-parse both stabilized outputs and name every difference between them.
fn codes_for(reference: &Path, ours: &Path, format: &str) -> Result<Vec<String>> {
    let f = match format {
        "tar+gzip" => trigon_core::Format::TarGz,
        "zip" => trigon_core::Format::Zip,
        "tar" => trigon_core::Format::Tar,
        "gzip" => trigon_core::Format::Gzip,
        other => bail!("no signature support for format `{other}`"),
    };
    let read = |p: &Path| -> Result<trigon_archive::Archive> {
        let mut notes = Vec::new();
        let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
        Ok(
            trigon_archive::parse(bytes, f, &trigon_archive::Limits::default(), &mut notes)
                .with_context(|| format!("parsing {}", p.display()))?
                .archive,
        )
    };
    Ok(signature(&read(reference)?, &read(ours)?)
        .into_iter()
        .collect())
}

/// Group difference codes by class, with a couple of example paths each.
///
/// A framing difference produces one code per member, and a thousand lines of
/// `entry:mtime@<path>` says nothing that `entry:mtime  412 members` does not. The counts are the
/// diagnosis: "412 members differ in mtime" and "1 member differs in body" are different bugs.
fn summarize(codes: &[String]) -> String {
    let mut by_class: std::collections::BTreeMap<&str, (usize, Vec<&str>)> =
        std::collections::BTreeMap::new();
    for c in codes {
        let (class, path) = c.split_once('@').unwrap_or((c.as_str(), ""));
        let e = by_class.entry(class).or_default();
        e.0 += 1;
        if e.1.len() < 2 && !path.is_empty() {
            e.1.push(path);
        }
    }
    by_class
        .into_iter()
        .map(|(class, (n, examples))| {
            let ex = if examples.is_empty() {
                String::new()
            } else {
                format!("  ({})", examples.join(", "))
            };
            format!("               {class:<28} {n:>5}{ex}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
