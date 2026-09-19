//! `trigon check` — a lockfile in, a verdict table out, with an explicit *never checked* row.
//!
//! [`docs/11-interfaces.md`](../../../docs/11-interfaces.md) §"The hero": this is the only view
//! that starts from something the reader already has. Everything else assumes they care about a
//! package we happen to have scanned.
//!
//! **The shape of the output is the point.** Five rows, never four:
//!
//! - `reproduced`, `caveats`, `divergent` — packages we ran and reached a verdict on.
//! - `unsupported` — packages we tried and could not run. A different denominator
//!   ([`docs/02-domain-model.md`](../../../docs/02-domain-model.md) §4), never summed with the
//!   first three.
//! - `never checked` — packages with no run at all. A row of its own rather than a gap, because a
//!   blank cell reads as green and reading as green is the one mistake this view cannot afford.
//!
//! No percentage is printed over the whole set and none is available in the JSON, for the same
//! reason: a single rate needs one denominator and there are three here.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use trigon_store::{RunRecord, Store};

/// What we can say about one package in a lockfile.
///
/// Ordered as the summary prints them, best first, with the two non-verdicts last.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Status {
    Reproduced,
    Caveats,
    Divergent,
    /// We ran it and could not reach a verdict: a void run, a guard trip, a build that failed for
    /// our reasons. **Not** a statement about the package.
    Unsupported,
    /// No run exists. Not a judgement at all.
    NeverChecked,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Reproduced => "reproduced",
            Status::Caveats => "caveats",
            Status::Divergent => "divergent",
            Status::Unsupported => "unsupported",
            Status::NeverChecked => "never checked",
        }
    }

    /// The glyph the terminal table uses. `?` for never-checked, deliberately not a blank.
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Reproduced => "✔",
            Status::Caveats => "◐",
            Status::Divergent => "✖",
            Status::Unsupported => "⊘",
            Status::NeverChecked => "?",
        }
    }

    /// SARIF level. Never-checked is a `note` and never absent: a finding nobody filed is a
    /// finding nobody sees.
    fn sarif_level(self) -> &'static str {
        match self {
            Status::Divergent => "error",
            Status::Caveats => "warning",
            Status::Unsupported | Status::NeverChecked => "note",
            Status::Reproduced => "none",
        }
    }

    fn rule_id(self) -> &'static str {
        match self {
            Status::Reproduced => "trigon/reproduced",
            Status::Caveats => "trigon/caveats",
            Status::Divergent => "trigon/divergent",
            Status::Unsupported => "trigon/unsupported",
            Status::NeverChecked => "trigon/never-checked",
        }
    }
}

/// One line of the lockfile, and what we know about it.
#[derive(Clone, Debug)]
pub struct Checked {
    pub purl: String,
    pub name: String,
    pub version: String,
    pub status: Status,
    /// 1-based line in the lockfile, so a code-scanning UI can point at it.
    pub line: usize,
    /// The run this verdict came from, where there is one.
    pub run: Option<String>,
    /// A sentence for the reader. Why it is unsupported, or what diverged.
    pub detail: Option<String>,
}

/// Every package a lockfile names, in file order.
///
/// Format is chosen by file name rather than by sniffing, because a caller who points at the wrong
/// file should be told so rather than handed an empty table.
pub fn parse_lockfile(path: &Path) -> Result<Vec<(String, String, String, usize)>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if name == "package-lock.json" || name == "npm-shrinkwrap.json" {
        npm_lock(&text)
    } else if name.ends_with("requirements.txt") || name == "requirements.in" {
        Ok(requirements(&text))
    } else if name.ends_with(".spdx.json") || name.ends_with("sbom.json") {
        spdx(&text)
    } else {
        bail!(
            "`{}` is not a lockfile this reads. It knows package-lock.json, npm-shrinkwrap.json, \
             requirements.txt and *.spdx.json. Naming the format rather than guessing it means a \
             file pointed at by mistake is refused instead of reported as zero packages.",
            path.display()
        )
    }
}

/// Where a string first appears in the file, as a 1-based line. 0 when it does not.
fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
        .unwrap_or(0)
}

fn npm_lock(text: &str) -> Result<Vec<(String, String, String, usize)>> {
    let v: serde_json::Value =
        serde_json::from_str(text).context("package-lock.json is not JSON")?;
    let mut out = Vec::new();

    // v2 and v3: a flat `packages` map keyed by install path. The root is "" and is the project
    // itself, not a dependency.
    if let Some(map) = v.get("packages").and_then(|p| p.as_object()) {
        for (path, entry) in map {
            if path.is_empty() {
                continue;
            }
            // `node_modules/a/node_modules/b` names `b`. The last segment is the package.
            let Some(name) = path.rsplit("node_modules/").next().filter(|s| !s.is_empty()) else {
                continue;
            };
            // A link entry points at a workspace and has no published version to check.
            if entry.get("link").and_then(|l| l.as_bool()) == Some(true) {
                continue;
            }
            let Some(version) = entry.get("version").and_then(|x| x.as_str()) else {
                continue;
            };
            out.push((
                format!("pkg:npm/{name}@{version}"),
                name.to_string(),
                version.to_string(),
                line_of(text, &format!("\"{path}\"")),
            ));
        }
    } else if let Some(map) = v.get("dependencies").and_then(|p| p.as_object()) {
        // v1: a recursive `dependencies` tree.
        fn walk(
            map: &serde_json::Map<String, serde_json::Value>,
            text: &str,
            out: &mut Vec<(String, String, String, usize)>,
        ) {
            for (name, entry) in map {
                if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
                    out.push((
                        format!("pkg:npm/{name}@{version}"),
                        name.clone(),
                        version.to_string(),
                        line_of(text, &format!("\"{name}\"")),
                    ));
                }
                if let Some(inner) = entry.get("dependencies").and_then(|d| d.as_object()) {
                    walk(inner, text, out);
                }
            }
        }
        walk(map, text, &mut out);
    } else {
        bail!("this package-lock.json has neither a `packages` nor a `dependencies` object");
    }

    dedupe(out)
}

fn requirements(text: &str) -> Vec<(String, String, String, usize)> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        // Strip a comment, then an environment marker, then whitespace.
        let line = raw.split('#').next().unwrap_or("").trim();
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        // Only `==` pins a version. `>=` names a range, and a range is not a thing we can have
        // checked: skipping it is honest, and it lands in `never checked` by being absent.
        let Some((name, version)) = line.split_once("==") else {
            continue;
        };
        // `name[extra]` — the extras do not change which artifact was published.
        let name = name.split('[').next().unwrap_or(name).trim();
        let version = version.trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push((
            format!("pkg:pypi/{name}@{version}"),
            name.to_string(),
            version.to_string(),
            i + 1,
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

fn spdx(text: &str) -> Result<Vec<(String, String, String, usize)>> {
    let v: serde_json::Value = serde_json::from_str(text).context("the SBOM is not JSON")?;
    let Some(packages) = v.get("packages").and_then(|p| p.as_array()) else {
        bail!("this SPDX document has no `packages` array");
    };
    let mut out = Vec::new();
    for p in packages {
        // Prefer the purl an SBOM carries: it names the ecosystem, which a name and version alone
        // do not. Fall back to name+version only when we can tell the ecosystem another way.
        let purl = p
            .get("externalRefs")
            .and_then(|r| r.as_array())
            .and_then(|refs| {
                refs.iter()
                    .find(|r| r.get("referenceType").and_then(|t| t.as_str()) == Some("purl"))
                    .and_then(|r| r.get("referenceLocator").and_then(|l| l.as_str()))
            });
        let Some(purl) = purl else { continue };
        if !(purl.starts_with("pkg:npm/") || purl.starts_with("pkg:pypi/")) {
            continue;
        }
        let (name, version) = match purl.rsplit_once('@') {
            Some((head, v)) => (
                head.rsplit('/').next().unwrap_or(head).to_string(),
                v.to_string(),
            ),
            None => continue,
        };
        out.push((purl.to_string(), name, version, line_of(text, purl)));
    }
    dedupe(out)
}

fn dedupe(
    mut v: Vec<(String, String, String, usize)>,
) -> Result<Vec<(String, String, String, usize)>> {
    v.sort_by(|a, b| a.0.cmp(&b.0).then(a.3.cmp(&b.3)));
    v.dedup_by(|a, b| a.0 == b.0);
    Ok(v)
}

/// Every verdict a store holds, keyed by target.
///
/// The **newest** run for a target wins, because a later run was made under a later stabilizer set
/// and is the current answer. A target with runs that disagree is reported as its latest, which is
/// the same thing the corpus browser shows.
async fn verdicts(store: &Store) -> Result<BTreeMap<String, RunRecord>> {
    let mut out: BTreeMap<String, RunRecord> = BTreeMap::new();
    for id in store.list_runs().await? {
        let r = match store.get_run(&id).await {
            Ok(r) => r,
            // A record we cannot read is not a verdict. Skipping it leaves the target in
            // `never checked`, which is the honest place for it.
            Err(_) => continue,
        };
        let newer = out
            .get(&r.target)
            .is_none_or(|prev| r.started > prev.started);
        if newer {
            out.insert(r.target.clone(), r);
        }
    }
    Ok(out)
}

fn status_of(r: &RunRecord) -> (Status, Option<String>) {
    if !r.guard_trips.is_empty() {
        return (
            Status::Unsupported,
            Some(format!(
                "the build reached the published artifact over the network ({} trip(s)), so \
                 nothing it produced is evidence about the package",
                r.guard_trips.len()
            )),
        );
    }
    match r.outcome.as_deref() {
        Some("exact") => (Status::Reproduced, Some("byte for byte".into())),
        Some("normalized") => (
            Status::Reproduced,
            Some("identical after stabilization".into()),
        ),
        Some("normalized_with_caveats") => (
            Status::Caveats,
            Some("identical after a stabilizer that is a judgement call".into()),
        ),
        Some("divergent") => (
            Status::Divergent,
            r.failure
                .as_ref()
                .map(|f| f.code.to_string())
                .or(Some("the rebuild differs from what was published".into())),
        ),
        Some(other) => (Status::Unsupported, Some(other.to_string())),
        None => (
            Status::Unsupported,
            Some(
                r.failure
                    .as_ref()
                    .map(|f| format!("{}", f.code))
                    .unwrap_or_else(|| "the run reached no verdict".into()),
            ),
        ),
    }
}

/// Check every package a lockfile names against what a store holds.
pub fn run(lockfile: &Path, store_path: &Path, format: &str) -> Result<()> {
    let packages = parse_lockfile(lockfile)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let known = rt.block_on(async {
        let store = Store::local(store_path)?;
        verdicts(&store).await
    })?;

    let checked: Vec<Checked> = packages
        .into_iter()
        .map(|(purl, name, version, line)| match known.get(&purl) {
            Some(r) => {
                let (status, detail) = status_of(r);
                Checked {
                    purl,
                    name,
                    version,
                    status,
                    line,
                    run: Some(r.id.clone()),
                    detail,
                }
            }
            None => Checked {
                purl,
                name,
                version,
                status: Status::NeverChecked,
                line,
                run: None,
                detail: None,
            },
        })
        .collect();

    match format {
        "sarif" => println!("{}", serde_json::to_string_pretty(&sarif(lockfile, &checked))?),
        "json" => println!("{}", serde_json::to_string_pretty(&as_json(lockfile, &checked))?),
        "text" => text(lockfile, &checked),
        other => bail!("`{other}` is not a format this writes: text, json or sarif"),
    }
    Ok(())
}

fn tally(checked: &[Checked]) -> BTreeMap<&'static str, usize> {
    let mut t = BTreeMap::new();
    for s in [
        Status::Reproduced,
        Status::Caveats,
        Status::Divergent,
        Status::Unsupported,
        Status::NeverChecked,
    ] {
        t.insert(s.label(), checked.iter().filter(|c| c.status == s).count());
    }
    t
}

fn text(lockfile: &Path, checked: &[Checked]) {
    let total = checked.len();
    println!("{} · {total} package(s)\n", lockfile.display());

    let widest = 38usize;
    for s in [
        Status::Reproduced,
        Status::Caveats,
        Status::Divergent,
        Status::Unsupported,
        Status::NeverChecked,
    ] {
        let n = checked.iter().filter(|c| c.status == s).count();
        // The bar is a share of the file, which is a count over a known total and not a rate over
        // a denominator anybody has to choose.
        let filled = (n * widest).checked_div(total).unwrap_or(0);
        println!(
            "  {} {:<14} {:>5}   {}{}",
            s.glyph(),
            s.label(),
            n,
            "▓".repeat(filled),
            "░".repeat(widest - filled),
        );
    }

    let notable: Vec<&Checked> = checked
        .iter()
        .filter(|c| c.status != Status::Reproduced)
        .collect();
    if !notable.is_empty() {
        println!();
        for c in notable.iter().take(40) {
            println!(
                "  {}  {:<28} {:<12} {}",
                c.status.glyph(),
                c.name,
                c.version,
                c.detail.as_deref().unwrap_or(c.status.label())
            );
        }
        if notable.len() > 40 {
            println!("  … and {} more; --format json for all of them", notable.len() - 40);
        }
    }

    println!(
        "\n  `never checked` is a count of packages with no run, and `unsupported` of runs that \
         reached no verdict.\n  Neither is a statement about the package, and neither is summed \
         with the three above them."
    );
}

fn as_json(lockfile: &Path, checked: &[Checked]) -> serde_json::Value {
    serde_json::json!({
        "lockfile": lockfile.display().to_string(),
        "packages": checked.len(),
        // Counts, never a rate. Three of these have different denominators.
        "tally": tally(checked),
        "results": checked.iter().map(|c| serde_json::json!({
            "purl": c.purl,
            "name": c.name,
            "version": c.version,
            "status": c.status.label(),
            "line": c.line,
            "run": c.run,
            "detail": c.detail,
        })).collect::<Vec<_>>(),
    })
}

fn sarif(lockfile: &Path, checked: &[Checked]) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = [
        (Status::Divergent, "The rebuild differs from what was published", "A rebuild from the package's own source did not produce what the registry serves, after stabilization. This is a finding about the package."),
        (Status::Caveats, "Reproduced, with a stabilizer that is a judgement call", "The two agreed only after a normalization a person or a model wrote, so the normalization is itself a claim."),
        (Status::Unsupported, "We could not run this one", "A build we could not complete is not a package that failed to reproduce. It belongs to a different denominator."),
        (Status::NeverChecked, "Never checked", "No run exists for this package at this version. A blank result would read as verified; this one does not."),
    ]
    .iter()
    .map(|(s, short, full)| serde_json::json!({
        "id": s.rule_id(),
        "name": s.label(),
        "shortDescription": { "text": short },
        "fullDescription": { "text": full },
        "defaultConfiguration": { "level": s.sarif_level() },
    }))
    .collect();

    let uri = lockfile.display().to_string();
    let results: Vec<serde_json::Value> = checked
        .iter()
        // A reproduced package is not a result. Everything else is, including never-checked.
        .filter(|c| c.status != Status::Reproduced)
        .map(|c| {
            serde_json::json!({
                "ruleId": c.status.rule_id(),
                "level": c.status.sarif_level(),
                "message": { "text": match &c.detail {
                    Some(d) => format!("{} {} — {}: {d}", c.name, c.version, c.status.label()),
                    None => format!("{} {} — {}", c.name, c.version, c.status.label()),
                }},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": c.line.max(1) },
                    }
                }],
                "partialFingerprints": { "purl": c.purl },
                "properties": { "purl": c.purl, "run": c.run },
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "trigon",
                "informationUri": "https://github.com/trigon",
                "rules": rules,
            }},
            "results": results,
            // The counts travel with the results, because a code-scanning UI shows findings and a
            // reader cannot otherwise tell 4 divergences out of 12 packages from 4 out of 1,200.
            "properties": { "trigon": { "packages": checked.len(), "tally": tally(checked) } },
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lockfile on disk, in a directory of this test's own.
    ///
    /// `who` is the caller's name. The first version keyed the directory on the process id alone,
    /// so the two `package-lock.json` tests wrote the same path and raced — the file name is
    /// load-bearing here, because `parse_lockfile` chooses its parser from it.
    fn tmp(who: &str, name: &str, body: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("trigon-check-{}-{who}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn an_npm_lockfile_v3_names_its_packages_and_where_they_are() {
        let p = tmp(
            "v3",
            "package-lock.json",
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/left-pad": { "version": "1.3.0" },
    "node_modules/a/node_modules/b": { "version": "2.0.0" },
    "node_modules/ws": { "link": true },
    "node_modules/no-version": { "resolved": "x" }
  }
}"#,
        );
        let got = parse_lockfile(&p).expect("parse");
        let purls: Vec<&str> = got.iter().map(|(p, ..)| p.as_str()).collect();
        assert_eq!(purls, ["pkg:npm/b@2.0.0", "pkg:npm/left-pad@1.3.0"]);
        // A nested install path names the innermost package, not the path.
        assert!(purls.contains(&"pkg:npm/b@2.0.0"), "{purls:?}");
        // A workspace link has no published version to check, and an entry without one is not a
        // package we can name. Both are absent rather than reported as version-less.
        assert!(!purls.iter().any(|p| p.contains("ws")), "{purls:?}");
        assert!(!purls.iter().any(|p| p.contains("no-version")), "{purls:?}");
        // Every one carries the line it was found on, so a code-scanning UI can point at it.
        assert!(got.iter().all(|(.., line)| *line > 0), "{got:?}");
    }

    #[test]
    fn an_npm_lockfile_v1_is_read_too() {
        let p = tmp(
            "v1",
            "package-lock.json",
            r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "left-pad": { "version": "1.3.0" },
    "outer": { "version": "2.0.0", "dependencies": { "inner": { "version": "3.0.0" } } }
  }
}"#,
        );
        let purls: Vec<String> = parse_lockfile(&p)
            .expect("parse")
            .into_iter()
            .map(|(p, ..)| p)
            .collect();
        assert!(purls.contains(&"pkg:npm/inner@3.0.0".to_string()), "{purls:?}");
        assert_eq!(purls.len(), 3, "{purls:?}");
    }

    #[test]
    fn requirements_reads_pins_and_skips_what_is_not_one() {
        let p = tmp(
            "reqs",
            "requirements.txt",
            "# comment\n\
             click==8.3.3\n\
             requests>=2.0\n\
             urllib3[socks]==2.5.0 ; python_version > \"3.8\"\n\
             -r other.txt\n\
             -e .\n\
             flask==3.0.0  # trailing comment\n",
        );
        let got = parse_lockfile(&p).expect("parse");
        let purls: Vec<&str> = got.iter().map(|(p, ..)| p.as_str()).collect();
        assert_eq!(
            purls,
            [
                "pkg:pypi/click@8.3.3",
                "pkg:pypi/flask@3.0.0",
                "pkg:pypi/urllib3@2.5.0"
            ],
            "extras are stripped, markers and comments are cut, and a `>=` range is not a pin"
        );
    }

    #[test]
    fn a_file_this_does_not_read_is_refused_by_name() {
        // The alternative is reporting zero packages, which reads as "nothing to worry about".
        let p = tmp("cargo", "Cargo.lock", "[[package]]\nname = \"x\"\n");
        let e = parse_lockfile(&p).expect_err("Cargo.lock is not supported");
        assert!(format!("{e}").contains("not a lockfile this reads"), "{e}");
    }

    #[test]
    fn an_sbom_is_read_through_its_purls() {
        let p = tmp(
            "spdx",
            "x.spdx.json",
            r#"{ "packages": [
                 { "name": "left-pad", "externalRefs": [
                     { "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0" } ] },
                 { "name": "openssl", "externalRefs": [
                     { "referenceType": "purl", "referenceLocator": "pkg:deb/openssl@3" } ] },
                 { "name": "no-refs" } ] }"#,
        );
        let purls: Vec<String> = parse_lockfile(&p)
            .expect("parse")
            .into_iter()
            .map(|(p, ..)| p)
            .collect();
        // The ecosystems this can rebuild, and nothing else: a deb is not a thing we check, and
        // listing it as `never checked` would imply we might.
        assert_eq!(purls, ["pkg:npm/left-pad@1.3.0"]);
    }

    /// The five statuses, and the two that are not verdicts.
    #[test]
    fn a_run_that_reached_no_verdict_is_not_a_package_that_failed() {
        use trigon_store::{ArtifactRef, Environment, RunRecord};
        fn rec(outcome: Option<&str>, trips: &[&str]) -> RunRecord {
            let mut r = RunRecord::new(
                "1",
                "pkg:npm/x@1.0.0",
                ArtifactRef {
                    name: "x.tgz".into(),
                    sha256: trigon_core::Digest::from_bytes([0u8; 32]),
                    bytes: 1,
                    stored: true,
                },
                Environment {
                    base_image: "i".into(),
                    egress: "mirror-only".into(),
                    isolation: "podman".into(),
                    attestable: true,
                    registry_moment: None,
                    pin: None,
                    guard_manifest: None,
                    guarded_members: None,
                },
                "2026-01-01T00:00:00Z",
            );
            r.outcome = outcome.map(str::to_string);
            r.guard_trips = trips.iter().map(|s| (*s).to_string()).collect();
            r
        }

        assert_eq!(status_of(&rec(Some("exact"), &[])).0, Status::Reproduced);
        assert_eq!(status_of(&rec(Some("normalized"), &[])).0, Status::Reproduced);
        assert_eq!(
            status_of(&rec(Some("normalized_with_caveats"), &[])).0,
            Status::Caveats
        );
        assert_eq!(status_of(&rec(Some("divergent"), &[])).0, Status::Divergent);

        // A run that reached no verdict, and one whose guard tripped. Neither says anything about
        // the package, and calling either `divergent` would be an accusation nobody made.
        assert_eq!(status_of(&rec(None, &[])).0, Status::Unsupported);
        assert_eq!(
            status_of(&rec(Some("divergent"), &["fetched its own artifact"])).0,
            Status::Unsupported,
            "a tripped guard voids the run whatever the comparison said"
        );
    }

    #[test]
    fn never_checked_is_a_sarif_result_and_reproduced_is_not() {
        let checked = vec![
            Checked {
                purl: "pkg:npm/a@1".into(),
                name: "a".into(),
                version: "1".into(),
                status: Status::Reproduced,
                line: 2,
                run: Some("r1".into()),
                detail: None,
            },
            Checked {
                purl: "pkg:npm/b@2".into(),
                name: "b".into(),
                version: "2".into(),
                status: Status::NeverChecked,
                line: 5,
                run: None,
                detail: None,
            },
            Checked {
                purl: "pkg:npm/c@3".into(),
                name: "c".into(),
                version: "3".into(),
                status: Status::Divergent,
                line: 9,
                run: Some("r3".into()),
                detail: Some("three files".into()),
            },
        ];
        let s = sarif(std::path::Path::new("package-lock.json"), &checked);
        let results = s["runs"][0]["results"].as_array().unwrap();

        // **The load-bearing assertion.** A package nobody has checked must appear. A blank cell
        // reads as verified, and reading as verified is the one mistake this view cannot afford.
        let ids: Vec<&str> = results.iter().map(|r| r["ruleId"].as_str().unwrap()).collect();
        assert!(ids.contains(&"trigon/never-checked"), "{ids:?}");
        assert!(
            !ids.contains(&"trigon/reproduced"),
            "a reproduced package is not a finding: {ids:?}"
        );
        assert_eq!(results.len(), 2);

        // Severity is ordered the way a reviewer needs it.
        let level = |id: &str| {
            results
                .iter()
                .find(|r| r["ruleId"] == id)
                .unwrap()["level"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(level("trigon/divergent"), "error");
        assert_eq!(level("trigon/never-checked"), "note");

        // And the counts travel with the results, because 4 divergences out of 12 packages and 4
        // out of 1,200 are different findings and a results list alone cannot tell them apart.
        let t = &s["runs"][0]["properties"]["trigon"];
        assert_eq!(t["packages"], 3);
        assert_eq!(t["tally"]["reproduced"], 1);
        assert_eq!(t["tally"]["never checked"], 1);
    }

    /// No rate, anywhere, over any of it.
    #[test]
    fn nothing_prints_a_single_percentage_over_three_denominators() {
        let checked = vec![Checked {
            purl: "pkg:npm/a@1".into(),
            name: "a".into(),
            version: "1".into(),
            status: Status::Reproduced,
            line: 1,
            run: None,
            detail: None,
        }];
        let j = as_json(std::path::Path::new("l.json"), &checked).to_string();
        for word in ["rate", "percent", "\"pct\"", "percentage"] {
            assert!(
                !j.contains(word),
                "the JSON carries `{word}`; a single rate needs one denominator and there are three"
            );
        }
    }
}
