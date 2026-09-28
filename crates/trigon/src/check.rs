//! `trigon check --store <path>` — a lockfile in, a verdict table out, with an explicit *never
//! checked* row, from a local store of the operator's own runs. A bare `trigon check` answers from
//! the evidence sources instead (`crate::evidence::check`, `docs/19` §6); this is what it did
//! before there were any.
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

use anyhow::{Result, bail};
use trigon_core::Status;
use trigon_store::{RunRecord, Store};

/// One package from the lockfile, and what we know about it.
///
/// The rendering type, which is why it lives here and the parsing does not: `trigon-core` knows
/// what a lockfile names, `trigon-store` knows what a run said, and this is the join.
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

/// Check every package a lockfile names against what a store holds.
pub fn run(lockfile: &Path, store_path: &Path, format: &str) -> Result<()> {
    let packages = trigon_core::read_lockfile(lockfile)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let known = rt.block_on(async {
        let store = Store::local(store_path)?;
        verdicts(&store).await
    })?;

    let checked: Vec<Checked> = packages
        .into_iter()
        .map(|p| match known.get(&p.purl) {
            Some(r) => {
                let (status, detail) = r.status();
                Checked {
                    purl: p.purl,
                    name: p.name,
                    version: p.version,
                    status,
                    line: p.line,
                    run: Some(r.id.clone()),
                    detail,
                }
            }
            None => Checked {
                purl: p.purl,
                name: p.name,
                version: p.version,
                status: Status::NeverChecked,
                line: p.line,
                run: None,
                detail: None,
            },
        })
        .collect();

    match format {
        "sarif" => println!(
            "{}",
            serde_json::to_string_pretty(&sarif(lockfile, &checked))?
        ),
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(&as_json(lockfile, &checked))?
        ),
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

/// A label, count, glyph or bar painted to what the status means: a reproduction is green, a
/// caveated one yellow, a divergence red, and the two non-verdicts recede to grey. The colour is
/// the fastest read of the view, and it is the one thing the plain glyphs already encode.
fn paint(s: Status, text: &str) -> String {
    match s {
        Status::Reproduced => crate::style::good(text),
        Status::Caveats => crate::style::warn(text),
        Status::Divergent => crate::style::bad(text),
        Status::Unsupported | Status::NeverChecked => crate::style::muted(text),
    }
}

fn text(lockfile: &Path, checked: &[Checked]) {
    use crate::style;
    let total = checked.len();
    println!(
        "{} {}",
        style::heading(&lockfile.display().to_string()),
        style::muted(&format!("· {total} package(s)"))
    );
    println!();

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
            "  {} {} {}   {}{}",
            paint(s, s.glyph()),
            paint(s, &format!("{:<14}", s.label())),
            paint(s, &format!("{n:>5}")),
            paint(s, &"▓".repeat(filled)),
            style::muted(&"░".repeat(widest - filled)),
        );
    }

    let notable: Vec<&Checked> = checked
        .iter()
        .filter(|c| c.status != Status::Reproduced)
        .collect();
    if !notable.is_empty() {
        println!();
        for c in notable.iter().take(40) {
            let detail = c.detail.as_deref().unwrap_or(c.status.label());
            println!(
                "  {}  {} {} {}",
                paint(c.status, c.status.glyph()),
                style::ident(&format!("{:<28}", c.name)),
                style::muted(&format!("{:<12}", c.version)),
                paint(c.status, &style::wrap(detail, 6)),
            );
        }
        if notable.len() > 40 {
            println!(
                "  {}",
                style::muted(&format!(
                    "… and {} more; --format json for all of them",
                    notable.len() - 40
                ))
            );
        }
    }

    println!();
    println!(
        "  {}",
        style::muted(&style::wrap(
            "`never checked` is a count of packages with no run, and `unsupported` of runs that \
             reached no verdict. Neither is a statement about the package, and neither is summed \
             with the three above them.",
            2,
        ))
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
                    derived_image: None,
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

        assert_eq!(rec(Some("exact"), &[]).status().0, Status::Reproduced);
        assert_eq!(rec(Some("normalized"), &[]).status().0, Status::Reproduced);
        assert_eq!(
            rec(Some("normalized_with_caveats"), &[]).status().0,
            Status::Caveats
        );
        assert_eq!(rec(Some("divergent"), &[]).status().0, Status::Divergent);

        // A run that reached no verdict, and one whose guard tripped. Neither says anything about
        // the package, and calling either `divergent` would be an accusation nobody made.
        assert_eq!(rec(None, &[]).status().0, Status::Unsupported);
        assert_eq!(
            rec(Some("divergent"), &["fetched its own artifact"])
                .status()
                .0,
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
        let ids: Vec<&str> = results
            .iter()
            .map(|r| r["ruleId"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"trigon/never-checked"), "{ids:?}");
        assert!(
            !ids.contains(&"trigon/reproduced"),
            "a reproduced package is not a finding: {ids:?}"
        );
        assert_eq!(results.len(), 2);

        // Severity is ordered the way a reviewer needs it.
        let level = |id: &str| {
            results.iter().find(|r| r["ruleId"] == id).unwrap()["level"]
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
