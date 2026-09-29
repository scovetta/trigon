//! `trigon score`: a sweep's results against its labelled corpus, and against an earlier sweep.
//!
//! A pass rate alone cannot show the regression that matters — a change that raises the aggregate
//! while the model fires on targets that were supposed to need nothing — so the command splits
//! the rate by capability and fails on a model invocation the label forbids, whatever the rate
//! did. What is held here is that gate and its honesty: a count never recorded is said to be
//! unchecked rather than passed, a target the sweep never reported fails the score, no evidence is
//! not zero percent, and a comparison names every kind of change rather than a net number.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-score-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(d: &Path, name: &str, body: &str) -> PathBuf {
    let p = d.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

/// Labels: every target given, with the capability named.
fn labels(d: &Path, targets: &[(&str, &str)]) -> PathBuf {
    let rows: Vec<serde_json::Value> = targets
        .iter()
        .map(|(purl, capability)| {
            serde_json::json!({"purl": purl, "capability": capability, "reason": "labelled"})
        })
        .collect();
    write(
        d,
        "labels.json",
        &serde_json::json!({ "labels": rows }).to_string(),
    )
}

fn score(results: &Path, labels: &Path, extra: &[&Path]) -> (Option<i32>, String) {
    let mut args: Vec<&OsStr> = Vec::new();
    if let Some(baseline) = extra.first() {
        args.extend([OsStr::new("--baseline"), baseline.as_os_str()]);
    }
    score_args(results, labels, &args)
}

/// `score` against `baseline`, with `flags` after it.
fn score_with(
    results: &Path,
    labels: &Path,
    baseline: &Path,
    flags: &[&str],
) -> (Option<i32>, String) {
    let mut args = vec![OsStr::new("--baseline"), baseline.as_os_str()];
    args.extend(flags.iter().map(OsStr::new));
    score_args(results, labels, &args)
}

fn score_args(results: &Path, labels: &Path, args: &[&OsStr]) -> (Option<i32>, String) {
    let out: Output = Command::new(bin())
        .env("NO_COLOR", "1")
        .arg("score")
        .arg(results)
        .arg("--labels")
        .arg(labels)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The entries listed under `heading`: the lines after it that are indented under it, up to the
/// first that is not.
fn listed<'a>(text: &'a str, heading: &str) -> Vec<&'a str> {
    let mut lines = text.lines().skip_while(|l| l.trim() != heading);
    assert!(lines.next().is_some(), "no `{heading}` in:\n{text}");
    lines
        .take_while(|l| l.starts_with("    "))
        .map(str::trim)
        .collect()
}

const TRIVIAL: &str = "trivial-deterministic";
const INFERRED: &str = "needs-build-inference";

/// A model that fired on a target labelled trivial-deterministic fails the score, with the target
/// named, even where every target reproduced and no baseline was given.
#[test]
fn a_model_where_the_label_forbids_one_fails_whatever_the_rate() {
    let d = dir("forbidden");
    let labels = labels(&d, &[("pkg:npm/a@1", TRIVIAL), ("pkg:npm/b@1", INFERRED)]);
    let results = write(
        &d,
        "results.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t2\npkg:npm/b@1\tnormalized\t1.0\t\t1\n",
    );
    let (code, text) = score(&results, &labels, &[]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("2 targets, 3 model call(s)"), "{text}");
    let regression = text
        .split("REGRESSION: a model fired on targets labelled trivial-deterministic:")
        .nth(1)
        .unwrap_or_else(|| panic!("{text}"));
    assert!(regression.contains("pkg:npm/a@1"), "{text}");
    assert!(!regression.contains("pkg:npm/b@1"), "{text}");

    // The same results with no model call on the trivial target pass.
    let results = write(
        &d,
        "results.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t0\npkg:npm/b@1\tnormalized\t1.0\t\t1\n",
    );
    let (code, text) = score(&results, &labels, &[]);
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("REGRESSION"), "{text}");
}

/// A count that was never recorded is not zero: a target that forbids a model and recorded no
/// count is named as not checked, the total says how many rows it covers, and a sweep that
/// recorded none says that instead of printing a total.
#[test]
fn a_count_never_recorded_is_said_unchecked_and_never_read_as_zero() {
    let d = dir("unrecorded");
    let labels = labels(&d, &[("pkg:npm/a@1", TRIVIAL), ("pkg:npm/b@1", TRIVIAL)]);
    let results = write(
        &d,
        "results.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t0\npkg:npm/b@1\texact\t1.0\n",
    );
    let (code, text) = score(&results, &labels, &[]);
    assert_eq!(
        code,
        Some(0),
        "an unrecorded count is not a failure: {text}"
    );
    assert!(
        text.contains("2 targets, 0 model call(s) across 1 that recorded one; 1 did not"),
        "{text}"
    );
    let unchecked = text
        .split("NOT CHECKED: these forbid a model and recorded no count, so the gate did not run:")
        .nth(1)
        .unwrap_or_else(|| panic!("{text}"));
    assert!(unchecked.contains("pkg:npm/b@1"), "{text}");
    assert!(!unchecked.contains("pkg:npm/a@1"), "{text}");

    let results = write(
        &d,
        "results.tsv",
        "pkg:npm/a@1\texact\t1.0\npkg:npm/b@1\texact\t1.0\n",
    );
    let (_, text) = score(&results, &labels, &[]);
    assert!(
        text.contains("2 targets, model calls not recorded by this sweep"),
        "{text}"
    );
    assert!(!text.contains("0 model call(s)"), "{text}");
}

/// A corpus that shrank is how a rate improves without anything improving: a labelled target the
/// sweep never reported — a half-written last row included — fails the score, and a reported one
/// nobody labelled is named.
#[test]
fn a_labelled_target_the_sweep_never_reported_fails_the_score() {
    let d = dir("missing");
    let labels = labels(&d, &[("pkg:npm/a@1", INFERRED), ("pkg:npm/c@1", INFERRED)]);
    let results = write(
        &d,
        "results.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t0\npkg:npm/x@1\texact\t1.0\t\t0\npkg:npm/c@1\texact\n",
    );
    let (code, text) = score(&results, &labels, &[]);
    assert_eq!(code, Some(1), "{text}");
    let missing = text
        .split("labelled but not reported on:")
        .nth(1)
        .unwrap_or_else(|| panic!("{text}"));
    assert!(missing.contains("pkg:npm/c@1"), "{text}");
    let unlabelled = text
        .split("reported but not labelled:")
        .nth(1)
        .unwrap_or_else(|| panic!("{text}"));
    assert!(unlabelled.contains("pkg:npm/x@1"), "{text}");
}

/// "Nothing reproduces" and "nothing was tested" are different findings: a capability whose
/// targets produced no evidence says so, never 0%.
#[test]
fn a_capability_with_no_evidence_is_not_zero_percent() {
    let d = dir("no-evidence");
    let labels = labels(&d, &[("pkg:npm/a@1", INFERRED), ("pkg:npm/b@1", TRIVIAL)]);
    let results = write(
        &d,
        "results.tsv",
        "pkg:npm/a@1\terror:infra\t1.0\terror:x\t0\npkg:npm/b@1\tdivergent\t1.0\t\t0\n",
    );
    let (_, text) = score(&results, &labels, &[]);
    // The columns are padded for a terminal; compared with the padding folded.
    let row = |capability: &str| -> String {
        text.lines()
            .find(|l| l.trim_start().starts_with(capability))
            .unwrap_or_else(|| panic!("no {capability} row:\n{text}"))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert!(row(INFERRED).contains("no evidence"), "{text}");
    assert!(!row(INFERRED).contains('%'), "{text}");
    assert!(row(TRIVIAL).contains("0/1 reproduced (0%)"), "{text}");
}

/// Against a baseline every kind of change is named, not counted: a target that reproduces
/// differently, one that now reproduces, and — where nothing moved — that nothing did; and the
/// verdict on the change is a gain only where something was fixed and nothing broke.
#[test]
fn a_comparison_names_each_kind_of_change_and_calls_a_gain_only_a_gain() {
    let d = dir("baseline");
    let labels = labels(
        &d,
        &[
            ("pkg:npm/a@1", INFERRED),
            ("pkg:npm/b@1", INFERRED),
            ("pkg:npm/c@1", INFERRED),
        ],
    );
    let before = write(
        &d,
        "before.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t0\n\
         pkg:npm/b@1\tdivergent\t1.0\t\t0\n\
         pkg:npm/c@1\texact\t1.0\t\t0\n",
    );

    let same = write(&d, "same.tsv", &std::fs::read_to_string(&before).unwrap());
    let (code, text) = score(&same, &labels, &[&before]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("nothing changed"), "{text}");
    assert!(text.contains("not a gain: nothing was fixed"), "{text}");

    let after = write(
        &d,
        "after.tsv",
        "pkg:npm/a@1\tnormalized\t1.0\t\t0\n\
         pkg:npm/b@1\texact\t1.0\t\t0\n\
         pkg:npm/c@1\texact\t1.0\t\t0\n",
    );
    let (code, text) = score(&after, &labels, &[&before]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("1 reproduce differently:"), "{text}");
    assert!(text.contains("pkg:npm/a@1 exact -> normalized"), "{text}");
    assert_eq!(
        listed(&text, "1 now reproduces:"),
        ["pkg:npm/b@1"],
        "{text}"
    );
    assert!(!text.contains("in the baseline and not this run"), "{text}");
    assert!(
        text.contains("a net gain: something was fixed and nothing regressed"),
        "{text}"
    );
}

/// One fixed and one broken is a trade, not a gain: the target that no longer reproduces is named
/// on its own, and `--fail-on-regression` makes it the exit code — without the flag a person
/// reading the comparison is not told their command failed.
#[test]
fn a_target_that_no_longer_reproduces_is_never_part_of_a_gain() {
    let d = dir("regressed");
    let labels = labels(&d, &[("pkg:npm/a@1", INFERRED), ("pkg:npm/b@1", INFERRED)]);
    let before = write(
        &d,
        "before.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t0\npkg:npm/b@1\tdivergent\t1.0\t\t0\n",
    );
    let after = write(
        &d,
        "after.tsv",
        "pkg:npm/a@1\tdivergent\t1.0\t\t0\npkg:npm/b@1\texact\t1.0\t\t0\n",
    );
    let (code, text) = score(&after, &labels, &[&before]);
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        listed(&text, "1 NO LONGER REPRODUCES:"),
        ["pkg:npm/a@1"],
        "{text}"
    );
    assert_eq!(
        listed(&text, "1 now reproduces:"),
        ["pkg:npm/b@1"],
        "{text}"
    );
    assert!(
        text.contains("NOT a net gain: something that reproduced no longer does"),
        "{text}"
    );
    assert!(!text.contains("a net gain: something was fixed"), "{text}");

    let (code, text) = score_with(&after, &labels, &before, &["--fail-on-regression"]);
    assert_eq!(code, Some(1), "{text}");
}

/// A labelled target in the baseline that this run left out is named as dropped, and fails the
/// score as any labelled target the run never reported does.
#[test]
fn a_target_dropped_since_the_baseline_is_named_and_fails_the_score() {
    let d = dir("dropped");
    let labels = labels(
        &d,
        &[
            ("pkg:npm/a@1", INFERRED),
            ("pkg:npm/b@1", INFERRED),
            ("pkg:npm/c@1", INFERRED),
        ],
    );
    let before = write(
        &d,
        "before.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t0\n\
         pkg:npm/b@1\tdivergent\t1.0\t\t0\n\
         pkg:npm/c@1\texact\t1.0\t\t0\n",
    );
    let after = write(
        &d,
        "after.tsv",
        "pkg:npm/a@1\texact\t1.0\t\t0\npkg:npm/b@1\tdivergent\t1.0\t\t0\n",
    );
    let (code, text) = score(&after, &labels, &[&before]);
    assert_eq!(code, Some(1), "{text}");
    assert_eq!(
        listed(&text, "1 in the baseline and not this run:"),
        ["pkg:npm/c@1"],
        "{text}"
    );
    assert_eq!(
        listed(&text, "labelled but not reported on:"),
        ["pkg:npm/c@1"],
        "{text}"
    );
}
