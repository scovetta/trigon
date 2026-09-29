//! `trigon check <lockfile>` against the evidence sources: the lockfile front door (`docs/19` §6).
//!
//! **One sync, then no network.** Every source is made ready once, before the first package — a
//! stale one synced, and said to be — and every package is then answered from the clones, with no
//! request per package: a thousand-entry lockfile costs one fetch per source, not a thousand GETs.
//! `--offline` touches no network at all, and `--remote` is the labelled exception.
//!
//! **By digest first, and by purl second.** A lockfile pins an artifact by the digest it declares
//! — npm's `integrity`, a requirement's `--hash`, an SBOM's `checksums` — and a record is about an
//! artifact, so each package is looked up by every digest it declares that a record may be filed
//! under, and only where none finds a record, by its purl. A purl that finds records only about
//! another artifact than every digest the lockfile declares is not an answer about the one it
//! pins: that package is never checked, and the records found are said.
//!
//! **Every package, and every source, reported.** A package no source holds a record for is never
//! checked; one that nothing can look up — an SBOM entry with no purl and no checksum — is never
//! checked too, and says why. Each source's answer is kept beside its name, in the text, the JSON
//! and the SARIF alike, and a package two sources answer differently is said to be disagreed about.
//!
//! **Exit codes are exactly §6's**: 0 at or above the threshold; 1 for any divergence; 2 for any
//! package never checked, or withdrawn; 3 for any void or result below the threshold — an outcome
//! below `--min`, or reached through a stabilizer riskier than `--max-risk`; 4 for any deleted
//! record, record or source that failed verification, required source that is unknown, or package
//! no source could answer at all; 5 when the tool failed. The first of 5, 4, 1, 3, 2 wins, and a
//! package's answer across sources is `trigon_attest::evidence::exit_code`'s.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use serde_json::{Value, json};
use trigon_attest::config::{Env, EvidenceConfig};
use trigon_attest::evidence::{Answer, Key, Said, exit_code, risk_name};
use trigon_attest::location::printable;
use trigon_core::{Match, Package, RiskTier};

use super::lookup::{
    Asked, Asker, Via, answer_word, askers, code_said, disagreement, record_json, said_word,
    source_json, weighed, worst,
};
use super::remote::{self, Http};

/// What `trigon check` is given when it answers from the evidence sources.
pub(crate) struct Args {
    pub lockfile: PathBuf,
    pub min: Match,
    pub max_risk: Option<RiskTier>,
    pub sources: Vec<String>,
    pub require: Vec<String>,
    pub offline: bool,
    pub remote: bool,
    pub format: String,
    pub verbose: bool,
}

/// One package, and what every source said of it.
struct Row {
    package: Package,
    asked: Vec<Asked>,
    /// §6's code for the package, across every source.
    code: u8,
    /// What the package comes to: the most severe answer any source gave that is not unknown, or
    /// `unknown` where none answered.
    status: String,
    /// Each source's answer, where they are not one claim.
    disagreement: Option<Vec<String>>,
    /// Why the package could not be looked up at all, where it could not.
    unfindable: Option<String>,
    /// §6's code of `status` alone: what the answering sources' answer comes to, without the
    /// sources that fail every package.
    status_code: u8,
    /// The sources that fail it whatever was answered: refused, or required and unknown.
    failing: Failing,
}

/// The statuses a package can come to, in the order the summary prints them: the verdicts, then
/// the answers that are not one, and `unknown` last.
const STATUSES: [&str; 11] = [
    "exact",
    "normalized",
    "normalized_with_caveats",
    "above --max-risk",
    "divergent",
    "void",
    "withdrawn",
    "deleted",
    "failed verification",
    "never checked",
    "unknown",
];

/// The keys a package is looked up by: every digest it declares that a record may be filed under,
/// and its purl where it names a version. A purl with none — an SBOM's, with no `versionInfo`
/// either — would find every version of the package, and a record of another version is no answer
/// about the one installed, so such a package is looked up by its digests alone.
fn keys_of(p: &Package) -> (Vec<Key>, Option<Key>) {
    let mut digests: Vec<Key> = Vec::new();
    // sha512 and sha256 before sha1, which is collision-broken and found by alone only where
    // nothing better is declared.
    for algorithm in ["sha512", "sha256", "sha1"] {
        for d in p.digests.iter().filter(|d| d.algorithm == algorithm) {
            if let Ok(k) = Key::parse(&format!("{algorithm}:{}", d.value))
                && !digests.contains(&k)
            {
                digests.push(k);
            }
        }
    }
    let purl = match p.purl.is_empty() {
        true => None,
        false => Key::parse(&p.purl)
            .ok()
            .filter(|k| matches!(k, Key::Purl(_))),
    };
    (digests, purl)
}

/// Why a package cannot be looked up at all, where it cannot: it declares no digest a record is
/// filed under, and no purl with a version.
fn unfindable(p: &Package, digests: &[Key], purl: Option<&Key>) -> Option<String> {
    if !digests.is_empty() || purl.is_some() {
        return None;
    }
    Some(match p.purl.is_empty() {
        true => "the lockfile declares no purl and no digest a record is filed under, so there is \
                 nothing to look it up by"
            .to_string(),
        false => format!(
            "the lockfile names it as {} with no version, and declares no digest a record is filed \
             under, so there is nothing to look the version installed up by",
            printable(&p.purl)
        ),
    })
}

/// Which sources fail a package whatever they answered, by name: those refused, and those required
/// and unknown.
#[derive(Default)]
struct Failing {
    refused: Vec<String>,
    required: Vec<String>,
}

impl Failing {
    fn of(askers: &[Asker<'_>], asked: &[Asked]) -> Failing {
        let mut f = Failing::default();
        for (a, x) in askers.iter().zip(asked) {
            match x.said {
                Said::Refused => f.refused.push(a.name.clone()),
                Said::Unknown { required: true } => f.required.push(a.name.clone()),
                _ => {}
            }
        }
        f
    }

    fn any(&self) -> bool {
        !self.refused.is_empty() || !self.required.is_empty()
    }

    /// What fails the package, in words.
    fn said(&self) -> String {
        let names = |n: &[String]| {
            n.iter()
                .map(|x| format!("`{x}`"))
                .collect::<Vec<_>>()
                .join(" and ")
        };
        let mut out = Vec::new();
        if !self.refused.is_empty() {
            out.push(format!(
                "{} refused: its last sync failed verification",
                names(&self.refused)
            ));
        }
        if !self.required.is_empty() {
            out.push(format!(
                "{} required, and could not answer",
                names(&self.required)
            ));
        }
        out.join("; ")
    }

    fn json(&self) -> Value {
        match self.any() {
            true => json!({ "refused": self.refused, "requiredUnknown": self.required }),
            false => Value::Null,
        }
    }
}

/// `trigon check <lockfile>` without `--store`: the report, and §6's exit code; anything that
/// stops it before it can answer is the tool failing, exit 5.
pub(crate) fn run(args: Args) -> Result<()> {
    super::lookup::finish(answer(args))
}

fn answer(args: Args) -> Result<u8> {
    let packages = match trigon_core::read_lockfile(&args.lockfile) {
        Ok(p) => p,
        // An unreadable lockfile is the tool failing before it could answer: exit 5.
        Err(e) => crate::verify_record::usage(&e.to_string()),
    };
    let env = Env::from_process()?;
    let config = EvidenceConfig::load(&env)?;
    let via = match (args.offline, args.remote) {
        (_, true) => Via::Remote,
        (true, false) => Via::Offline,
        (false, false) => Via::Sync,
    };
    let http = match via {
        Via::Remote => Some(Http::new()?),
        _ => None,
    };
    // Every source, once: a stale one synced here, before the first package, and never again.
    let askers = askers(
        &config,
        &args.sources,
        &args.require,
        via,
        http.as_ref(),
        args.verbose,
    )?;
    let rows: Vec<Row> = packages
        .into_iter()
        .map(|package| {
            let (digests, purl) = keys_of(&package);
            let unfindable = unfindable(&package, &digests, purl.as_ref());
            let alternatives = package.alternatives();
            let asked: Vec<Asked> = askers
                .iter()
                .map(|a| {
                    a.ask_package(
                        &digests,
                        alternatives,
                        purl.as_ref(),
                        args.min,
                        args.max_risk,
                    )
                })
                .collect();
            let said: Vec<Said> = asked.iter().map(|x| x.said.clone()).collect();
            let code = exit_code(&said, args.min, true);
            let (status, status_code) = match weighed(&said, args.min) {
                Some(a) => (status_of(&a), a.exit_code(args.min)),
                // No source answered, which is 4 however it came about.
                None => ("unknown".to_string(), 4),
            };
            let disagreement = disagreement(&askers, &asked);
            let failing = Failing::of(&askers, &asked);
            Row {
                package,
                asked,
                code,
                status,
                disagreement,
                unfindable,
                status_code,
                failing,
            }
        })
        .collect();
    let code = worst(rows.iter().map(|r| r.code));
    match args.format.as_str() {
        "json" => println!(
            "{}",
            crate::verify_record::pretty(&as_json(&args, via, &askers, &rows, code, &http))
        ),
        "sarif" => println!(
            "{}",
            crate::verify_record::pretty(&sarif(&args, &askers, &rows, code))
        ),
        _ => text(&args, via, &askers, &rows, code),
    }
    Ok(code)
}

/// A package's status, from the most severe answer any source gave.
fn status_of(a: &Answer) -> String {
    match a {
        Answer::AboveMaxRisk { .. } => "above --max-risk".into(),
        a => answer_word(a),
    }
}

/// The threshold, as a person reads it.
fn threshold(args: &Args) -> String {
    match args.max_risk {
        Some(r) => format!(
            "at least {}, through no stabilizer riskier than `{}`",
            args.min,
            risk_name(r)
        ),
        None => format!("at least {}", args.min),
    }
}

/// How far up §6's order a code is: 5, 4, 1, 3, 2, then 0.
fn severity(code: u8) -> u8 {
    match code {
        5 => 5,
        4 => 4,
        1 => 3,
        3 => 2,
        2 => 1,
        _ => 0,
    }
}

/// A status painted by what it means.
fn paint(status: &str, text: &str) -> String {
    match status {
        "exact" | "normalized" | "normalized_with_caveats" => crate::style::good(text),
        "divergent" | "deleted" | "failed verification" => crate::style::bad(text),
        "never checked" | "unknown" => crate::style::muted(text),
        _ => crate::style::warn(text),
    }
}

fn glyph(status: &str) -> &'static str {
    match status {
        "exact" | "normalized" => "✔",
        "normalized_with_caveats" => "◐",
        "divergent" => "✖",
        "void" => "⊘",
        "withdrawn" => "↩",
        "deleted" | "failed verification" => "!",
        "above --max-risk" => "▽",
        _ => "?",
    }
}

fn text(args: &Args, via: Via, askers: &[Asker<'_>], rows: &[Row], code: u8) {
    use crate::style;
    println!(
        "{} {}",
        style::heading(&args.lockfile.display().to_string()),
        style::muted(&format!(
            "· {} package(s) · {} source(s) · threshold {}",
            rows.len(),
            askers.len(),
            threshold(args)
        ))
    );
    for a in askers {
        println!("source    {}", style::wrap(&a.label, 10));
        for n in &a.notes {
            println!("note      {}", style::wrap(&printable(n), 10));
        }
        if let Some(why) = &a.why {
            println!(
                "          {} — {}{}",
                a.standing,
                style::wrap(why, 10),
                match (a.required, a.standing) {
                    (true, _) => "; it is required, so every package fails the check",
                    (false, "refused") => "",
                    (false, _) => "; it is not required, so only its own answers are missing",
                }
            );
        }
    }
    println!();
    let widest = 38usize;
    let total = rows.len();
    for s in STATUSES {
        let n = rows.iter().filter(|r| r.status == s).count();
        if n == 0 && !matches!(s, "never checked" | "divergent") {
            continue;
        }
        let filled = (n * widest).checked_div(total).unwrap_or(0);
        println!(
            "  {} {} {}   {}{}",
            paint(s, glyph(s)),
            paint(s, &format!("{s:<24}")),
            paint(s, &format!("{n:>5}")),
            paint(s, &"▓".repeat(filled)),
            style::muted(&"░".repeat(widest - filled)),
        );
    }
    // The most severe first, as §6 orders the codes, then as the lockfile names them.
    let mut notable: Vec<&Row> = rows
        .iter()
        .filter(|r| args.verbose || r.code != 0 || r.disagreement.is_some())
        .collect();
    notable.sort_by_key(|r| std::cmp::Reverse(severity(r.code)));
    if !notable.is_empty() {
        println!();
    }
    for r in notable.iter().take(match args.verbose {
        true => usize::MAX,
        false => 60,
    }) {
        let name = package_name(&r.package, rows);
        // A package a source fails whatever was answered is said to fail, beside what was
        // answered: a verdict that passes is not painted as passing a check it fails.
        let fails = (r.failing.any() && r.status != "unknown").then(|| r.failing.said());
        let mark = match &fails {
            Some(_) if r.status_code == 0 => style::bad("!"),
            _ => paint(&r.status, glyph(&r.status)),
        };
        println!(
            "  {}  {} {}{}",
            mark,
            style::ident(&name),
            paint(&r.status, &format!("— {}", r.status)),
            fails
                .map(|f| style::bad(&format!("; fails the check: {f}")))
                .unwrap_or_default()
        );
        if let Some(why) = &r.unfindable {
            println!("      {}", style::wrap(why, 6));
        }
        for (a, x) in askers.iter().zip(&r.asked) {
            let mut said = format!("`{}`: {}", a.name, said_word(&x.said));
            if !x.by.is_empty() {
                said.push_str(&format!(", found by {}", x.by.join(" and ")));
            }
            if let Some(l) = &x.lookup {
                let origins = a.origins();
                for f in l.current() {
                    said.push_str(&format!(
                        "; sha256:{} at {}",
                        f.leaf.record.to_hex(),
                        super::lookup::leaf_said(&origins, f.pos)
                    ));
                    if let Some(v) = f.verified() {
                        for (label, value) in crate::verify_record::signed_fields(v) {
                            if matches!(label, "falsify" | "dispute") {
                                said.push_str(&format!("; {label}: {value}"));
                            }
                        }
                    }
                }
                let superseded = l
                    .found
                    .iter()
                    .filter(|f| !f.superseded_by.is_empty())
                    .count();
                if superseded > 0 {
                    said.push_str(&format!("; {superseded} superseded record(s) besides"));
                }
            }
            println!("      {}", style::wrap(&said, 6));
            for n in x.notes.iter().chain(&x.unproven) {
                println!("        {}", style::wrap(&printable(n), 8));
            }
        }
        if let Some(d) = &r.disagreement {
            println!(
                "      {}",
                style::bad(&style::wrap(
                    &format!(
                        "the sources disagree: {}; each is its own claim, and neither is taken \
                         over the other",
                        d.join(", ")
                    ),
                    6
                ))
            );
        }
    }
    if notable.len() > 60 && !args.verbose {
        println!(
            "  {}",
            style::muted(&format!(
                "… and {} more; -v or --format json for all of them",
                notable.len() - 60
            ))
        );
    }
    if via == Via::Remote {
        println!();
        for c in remote::CAVEATS {
            println!("caveat    {}", style::wrap(c, 10));
        }
    }
    println!();
    println!(
        "  {}",
        style::muted(&style::wrap(
            "`never checked` is a package no source that answered holds a record for, and \
             `unknown` one no source could answer for at all. Neither is a statement about the \
             package, and neither is summed with the verdicts.",
            2,
        ))
    );
    println!();
    println!("exit      {code}: {}", code_said(code));
}

/// A package as a report names it: its purl, or its name and version, and where another package
/// of the lockfile has the same purl — two artifacts of one name and version — the digest that
/// tells them apart.
fn package_name(p: &Package, rows: &[Row]) -> String {
    let name = match p.purl.is_empty() {
        true => format!("{} {}", p.name, p.version),
        false => printable(&p.purl),
    };
    let twin = !p.purl.is_empty() && rows.iter().filter(|r| r.package.purl == p.purl).count() > 1;
    match (twin, p.digests.first()) {
        (true, Some(d)) => format!(
            "{name} ({}:{}…)",
            d.algorithm,
            d.value.get(..16).unwrap_or(&d.value)
        ),
        _ => name,
    }
}

fn tally(rows: &[Row]) -> BTreeMap<&'static str, usize> {
    STATUSES
        .iter()
        .map(|s| (*s, rows.iter().filter(|r| r.status == *s).count()))
        .collect()
}

fn package_json(p: &Package) -> Value {
    json!({
        "purl": p.purl,
        "name": p.name,
        "version": p.version,
        "line": p.line,
        "digests": p.digests.iter().map(|d| json!({
            "algorithm": d.algorithm,
            "value": d.value,
            "source": d.source,
        })).collect::<Vec<_>>(),
        "resolved": p.resolved,
    })
}

fn as_json(
    args: &Args,
    via: Via,
    askers: &[Asker<'_>],
    rows: &[Row],
    code: u8,
    http: &Option<Http>,
) -> Value {
    json!({
        "lockfile": args.lockfile.display().to_string(),
        "packages": rows.len(),
        "min": args.min.to_string(),
        "maxRisk": args.max_risk.map(risk_name),
        "via": match via {
            Via::Sync => "clones",
            Via::Offline => "clones, offline",
            Via::Remote => "remote",
        },
        "sources": askers.iter().map(|a| json!({
            "name": a.name,
            "label": a.label,
            "required": a.required,
            "projectFile": a.project_file,
            "trustOnFirstUse": a.first_use,
            "standing": a.standing,
            "why": a.why,
            "notes": a.notes,
        })).collect::<Vec<_>>(),
        // Counts, never a rate: the statuses have different denominators.
        "tally": tally(rows),
        "results": rows.iter().map(|r| {
            let mut doc = package_json(&r.package);
            doc["status"] = json!(r.status);
            doc["exit"] = json!(r.code);
            doc["unfindable"] = json!(r.unfindable);
            doc["disagreement"] = json!(r.disagreement);
            doc["sourceFailure"] = r.failing.json();
            doc["sources"] = json!(askers.iter().zip(&r.asked).map(|(a, x)| source_json(a, x)).collect::<Vec<_>>());
            doc
        }).collect::<Vec<_>>(),
        "caveats": match via {
            Via::Remote => json!(remote::CAVEATS),
            _ => json!([]),
        },
        "requested": http.as_ref().map(|h| json!(h.asked())),
        "exit": code,
    })
}

/// A SARIF rule: its id, its level, what it says, and whether a result under it passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rule {
    id: &'static str,
    level: &'static str,
    short: &'static str,
    pass: bool,
}

impl Rule {
    const fn fail(id: &'static str, level: &'static str, short: &'static str) -> Rule {
        Rule {
            id,
            level,
            short,
            pass: false,
        }
    }
}

/// The rule of what the answering sources said of a package, where that fails the check.
fn status_rule(status: &str) -> Rule {
    match status {
        "divergent" => Rule::fail(
            "trigon/divergent",
            "error",
            "A source says the rebuild differs from what was published",
        ),
        "deleted" => Rule::fail(
            "trigon/deleted",
            "error",
            "A source's log has a leaf for this artifact, and the record it names is gone",
        ),
        "failed verification" => Rule::fail(
            "trigon/failed-verification",
            "error",
            "A record, or a source, failed verification: it may be an attack",
        ),
        "void" => Rule::fail(
            "trigon/void",
            "warning",
            "A source looked, and could not tell",
        ),
        "above --max-risk" => Rule::fail(
            "trigon/above-max-risk",
            "warning",
            "Reproduced only through a stabilizer riskier than the one allowed",
        ),
        "normalized" | "normalized_with_caveats" | "exact" => Rule::fail(
            "trigon/below-threshold",
            "warning",
            "Reproduced, below the outcome asked for",
        ),
        "withdrawn" => Rule::fail(
            "trigon/withdrawn",
            "note",
            "The only current record is a withdrawal",
        ),
        // No source answered, which fails the check whatever made it so (`docs/19` §6: 4).
        "unknown" => Rule::fail(
            "trigon/unknown",
            "error",
            "No source could answer: stale, frozen, unreachable or refused",
        ),
        _ => Rule::fail(
            "trigon/never-checked",
            "note",
            "No source that answered holds a record for this artifact",
        ),
    }
}

const PASS: Rule = Rule {
    id: "trigon/pass",
    level: "none",
    short: "Reproduced at or above the outcome asked for, by every source that answered",
    pass: true,
};

const SOURCE_REFUSED: Rule = Rule::fail(
    "trigon/source-refused",
    "error",
    "A source's last sync failed verification, so it answers nothing and fails every package",
);

const REQUIRED_UNKNOWN: Rule = Rule::fail(
    "trigon/required-source-unknown",
    "error",
    "A source the check requires could not answer: stale, frozen or unreachable",
);

/// The rules a package's result is filed under. A package that passes, one result that says so.
/// Otherwise the rule of what its sources answered, where that fails the check; and where a source
/// fails it whatever was answered — refused, or required and unknown — that source's rule too, at
/// `error`, so a package that fails for a source is never filed as the warning its answer alone
/// would be, and a divergence that a source's failure outranks is never filed only under it.
fn rules_of(r: &Row) -> Vec<Rule> {
    if r.code == 0 {
        return vec![PASS];
    }
    let mut out = Vec::new();
    if r.status_code != 0 {
        out.push(status_rule(&r.status));
    }
    if r.status != "unknown" {
        if !r.failing.refused.is_empty() {
            out.push(SOURCE_REFUSED);
        }
        if !r.failing.required.is_empty() {
            out.push(REQUIRED_UNKNOWN);
        }
    }
    out
}

/// `--format sarif`: a result for every package — those that pass as `pass`, at level `none` — and
/// every source's answer for each, as `docs/19` §6 has the SARIF carry them.
fn sarif(args: &Args, askers: &[Asker<'_>], rows: &[Row], code: u8) -> Value {
    let uri = args.lockfile.display().to_string();
    let mut rules: Vec<Value> = Vec::new();
    let mut results: Vec<Value> = Vec::new();
    for r in rows {
        let p = &r.package;
        let per: Vec<String> = askers
            .iter()
            .zip(&r.asked)
            .map(|(a, x)| format!("`{}` says {}", a.name, said_word(&x.said)))
            .collect();
        let sources: Vec<Value> = askers
            .iter()
            .zip(&r.asked)
            .map(|(a, x)| {
                json!({
                    "name": a.name,
                    "label": a.label,
                    "required": a.required,
                    "said": said_word(&x.said),
                    "foundBy": x.by,
                    "notes": x.notes,
                    "unproven": x.unproven,
                    "records": x.lookup.as_ref().map_or_else(Vec::new, |l| {
                        let origins = a.origins();
                        l.found.iter().map(|f| record_json(f, &origins)).collect::<Vec<_>>()
                    }),
                })
            })
            .collect();
        let digests: Vec<String> = p
            .digests
            .iter()
            .map(|d| format!("{}:{}", d.algorithm, d.value))
            .collect();
        for rule in rules_of(r) {
            if !rules.iter().any(|x| x["id"] == rule.id) {
                rules.push(json!({
                    "id": rule.id,
                    "shortDescription": { "text": rule.short },
                    "defaultConfiguration": { "level": rule.level },
                }));
            }
            let why = match rule.id {
                "trigon/source-refused" | "trigon/required-source-unknown" => {
                    format!("; it fails the check: {}", r.failing.said())
                }
                _ => String::new(),
            };
            results.push(json!({
                "ruleId": rule.id,
                "kind": match rule.pass {
                    true => "pass",
                    false => "fail",
                },
                "level": rule.level,
                "message": { "text": format!(
                    "{} {} — {}: {}{}{why}",
                    p.name,
                    p.version,
                    r.status,
                    per.join("; "),
                    match &r.disagreement {
                        Some(_) => "; the sources disagree",
                        None => "",
                    }
                )},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": p.line.max(1) },
                    }
                }],
                // The digests as well as the purl: two artifacts of one name and version are two
                // packages, and each keeps its own result from one run to the next.
                "partialFingerprints": { "package": format!("{} {}", p.purl, digests.join(" ")) },
                "properties": {
                    "purl": p.purl,
                    "digests": digests,
                    "status": r.status,
                    "exit": r.code,
                    "sourceFailure": r.failing.json(),
                    "disagreement": r.disagreement,
                    "sources": sources,
                },
            }));
        }
    }
    json!({
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
            "properties": { "trigon": {
                "packages": rows.len(),
                "tally": tally(rows),
                "exit": code,
                "sources": askers.iter().map(|a| json!({
                    "name": a.name,
                    "label": a.label,
                    "standing": a.standing,
                    "why": a.why,
                })).collect::<Vec<_>>(),
            }},
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, status_code: u8, code: u8, failing: Failing) -> Row {
        Row {
            package: Package {
                purl: "pkg:npm/x@1.0.0".into(),
                name: "x".into(),
                version: "1.0.0".into(),
                line: 1,
                digests: Vec::new(),
                resolved: None,
            },
            asked: Vec::new(),
            code,
            status: status.into(),
            disagreement: None,
            unfindable: None,
            status_code,
            failing,
        }
    }

    /// A package is filed under the rule of what failed it: one that fails only for a source is
    /// never filed as the warning its answer alone would be, a divergence that a source's failure
    /// outranks is filed under both, and one that passes is filed as passing.
    #[test]
    fn a_package_is_filed_under_what_fails_it() {
        let required = || Failing {
            refused: Vec::new(),
            required: vec!["b".into()],
        };
        let ids = |r: &Row| rules_of(r).iter().map(|x| x.id).collect::<Vec<_>>();
        assert_eq!(
            ids(&row("exact", 0, 0, Failing::default())),
            ["trigon/pass"]
        );
        assert_eq!(
            ids(&row("normalized", 0, 4, required())),
            ["trigon/required-source-unknown"]
        );
        assert_eq!(
            ids(&row("divergent", 1, 4, required())),
            ["trigon/divergent", "trigon/required-source-unknown"]
        );
        let refused = Failing {
            refused: vec!["b".into()],
            required: Vec::new(),
        };
        assert_eq!(
            ids(&row("never checked", 2, 4, refused)),
            ["trigon/never-checked", "trigon/source-refused"]
        );
        assert!(
            rules_of(&row("normalized", 0, 4, required()))
                .iter()
                .all(|r| r.level == "error" && !r.pass)
        );
        // No source answered: that is the failure, and it is an error.
        let unknown = rules_of(&row("unknown", 4, 4, required()));
        assert_eq!(unknown.len(), 1);
        assert_eq!(
            (unknown[0].id, unknown[0].level),
            ("trigon/unknown", "error")
        );
        assert_eq!(
            ids(&row("normalized", 3, 3, Failing::default())),
            ["trigon/below-threshold"]
        );
    }
}
