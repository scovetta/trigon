//! `trigon check --store`: a lockfile checked against a local store of the operator's own runs.
//!
//! The shape of the output is the point (`docs/11-interfaces.md` §"The hero"): five rows, never
//! four, with the packages nobody ran in a row of their own, because a blank cell reads as green.
//! Through the binary, against a store of the test's own.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-check-store-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A `package-lock.json` naming each `(name, version)`, one entry per line so each has a line of
/// its own for the SARIF to point at.
fn lockfile(d: &Path, packages: &[(&str, &str)]) -> PathBuf {
    let mut text = String::from("{\n  \"name\": \"consumer\",\n  \"lockfileVersion\": 3,\n");
    text.push_str("  \"packages\": {\n    \"\": {\"name\": \"consumer\"}");
    for (name, version) in packages {
        text.push_str(&format!(
            ",\n    \"node_modules/{name}\": {{\"version\": \"{version}\"}}"
        ));
    }
    text.push_str("\n  }\n}\n");
    let p = d.join("package-lock.json");
    std::fs::write(&p, text).unwrap();
    p
}

fn env() -> Environment {
    Environment {
        base_image: "docker.io/library/node@sha256:00".into(),
        derived_image: None,
        egress: "mirror-only".into(),
        isolation: "user_ns".into(),
        guard_manifest: None,
        guarded_members: None,
        attestable: true,
        registry_moment: None,
        pin: None,
    }
}

/// A finished run of `target` that concluded `outcome`, started at `started`.
fn run(id: &str, target: &str, outcome: Option<&str>, started: &str) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        target,
        ArtifactRef {
            name: "x.tgz".into(),
            sha256: trigon_store::digest_of(id.as_bytes()),
            bytes: 1,
            stored: false,
        },
        env(),
        started,
    );
    r.state = RunState::Done;
    r.outcome = outcome.map(str::to_string);
    r
}

fn store_of(d: &Path, runs: &[RunRecord]) -> PathBuf {
    let root = d.join("store");
    let store = Store::local(&root).unwrap();
    rt().block_on(async {
        for r in runs {
            store.put_run(r).await.unwrap();
        }
    });
    root
}

fn check(lock: &Path, store: &Path, extra: &[&str]) -> Output {
    let mut c = Command::new(bin());
    c.env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("COLUMNS")
        .arg("check")
        .arg(lock)
        .arg("--store")
        .arg(store)
        .args(extra);
    c.output().unwrap()
}

fn stdout(out: &Output) -> String {
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    text
}

fn json(lock: &Path, store: &Path) -> serde_json::Value {
    serde_json::from_str(&stdout(&check(lock, store, &["--format", "json"]))).unwrap()
}

fn result<'a>(doc: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("{name}: {doc}"))
}

/// The five packages every test here checks: one of each row.
const FIVE: &[(&str, &str)] = &[
    ("same", "1.0.0"),
    ("judged", "1.0.0"),
    ("differs", "1.0.0"),
    ("unbuilt", "1.0.0"),
    ("nobody", "1.0.0"),
];

fn five_runs() -> Vec<RunRecord> {
    vec![
        run(
            "1789000000-same",
            "pkg:npm/same@1.0.0",
            Some("normalized"),
            "2026-09-01T00:00:00Z",
        ),
        run(
            "1789000001-judged",
            "pkg:npm/judged@1.0.0",
            Some("normalized_with_caveats"),
            "2026-09-01T00:00:00Z",
        ),
        run(
            "1789000002-differs",
            "pkg:npm/differs@1.0.0",
            Some("divergent"),
            "2026-09-01T00:00:00Z",
        ),
        run(
            "1789000003-unbuilt",
            "pkg:npm/unbuilt@1.0.0",
            None,
            "2026-09-01T00:00:00Z",
        ),
    ]
}

/// Every package lands in exactly one of five rows, and the one nobody ran is `never checked` with
/// no run, never absent and never read as a verdict.
#[test]
fn every_package_is_in_one_of_five_rows_and_the_unrun_one_is_never_checked() {
    let d = dir("five");
    let lock = lockfile(&d, FIVE);
    let store = store_of(&d, &five_runs());
    let doc = json(&lock, &store);

    assert_eq!(doc["packages"], 5, "{doc}");
    for row in [
        "reproduced",
        "caveats",
        "divergent",
        "unsupported",
        "never checked",
    ] {
        assert_eq!(doc["tally"][row], 1, "{row}: {doc}");
    }
    assert_eq!(result(&doc, "same")["status"], "reproduced");
    assert_eq!(result(&doc, "same")["run"], "1789000000-same");
    assert_eq!(result(&doc, "judged")["status"], "caveats");
    assert_eq!(result(&doc, "differs")["status"], "divergent");
    assert_eq!(result(&doc, "unbuilt")["status"], "unsupported");
    assert_eq!(
        result(&doc, "unbuilt")["detail"],
        "the run reached no verdict"
    );
    let nobody = result(&doc, "nobody");
    assert_eq!(nobody["status"], "never checked");
    assert_eq!(nobody["purl"], "pkg:npm/nobody@1.0.0");
    assert!(nobody["run"].is_null(), "{nobody}");
    assert!(nobody["detail"].is_null(), "{nobody}");
    // The line in the lockfile, for a code-scanning UI to point at.
    let text = std::fs::read_to_string(&lock).unwrap();
    let at = text
        .lines()
        .position(|l| l.contains("node_modules/nobody"))
        .unwrap()
        + 1;
    assert_eq!(nobody["line"], at, "{nobody}");
}

/// The newest run of a package is its answer — by when it started, not by where its id sorts —
/// and a record that cannot be read is no verdict at all.
#[test]
fn the_newest_readable_run_of_a_package_is_its_answer() {
    let d = dir("newest");
    let lock = lockfile(
        &d,
        &[("twice", "1.0.0"), ("again", "1.0.0"), ("garbled", "2.0.0")],
    );
    let store = store_of(
        &d,
        &[
            // The id sorts later and the run started earlier.
            run(
                "1789000900-older",
                "pkg:npm/twice@1.0.0",
                Some("normalized"),
                "2026-01-01T00:00:00Z",
            ),
            run(
                "1789000000-newer",
                "pkg:npm/twice@1.0.0",
                Some("divergent"),
                "2026-06-01T00:00:00Z",
            ),
            // And the other way about: the id sorts later and the run started later. Between the
            // two packages, neither end of the id order can pass for the newest run.
            run(
                "1789000800-late",
                "pkg:npm/again@1.0.0",
                Some("divergent"),
                "2026-06-01T00:00:00Z",
            ),
            run(
                "1789000100-early",
                "pkg:npm/again@1.0.0",
                Some("normalized"),
                "2026-01-01T00:00:00Z",
            ),
        ],
    );
    // A record that is not one. It names `garbled`, and saying so would take reading it.
    std::fs::write(
        store.join("runs/1789000500-garbled.json"),
        "{\"target\": \"pkg:npm/garbled@2.0.0\", \"outcome\": ",
    )
    .unwrap();

    let doc = json(&lock, &store);
    let twice = result(&doc, "twice");
    assert_eq!(twice["status"], "divergent", "{doc}");
    assert_eq!(twice["run"], "1789000000-newer", "{doc}");
    let again = result(&doc, "again");
    assert_eq!(again["status"], "divergent", "{doc}");
    assert_eq!(again["run"], "1789000800-late", "{doc}");
    // Skipped, which leaves the package where an honest reader puts it.
    assert_eq!(result(&doc, "garbled")["status"], "never checked", "{doc}");
    assert_eq!(doc["tally"]["never checked"], 1);
}

/// The text form: the five rows with their counts, then a line for every package that did not
/// reproduce — its detail, or its row where it has none — and none for one that did.
#[test]
fn text_lists_what_did_not_reproduce_under_the_five_rows() {
    let d = dir("text");
    let lock = lockfile(&d, FIVE);
    let store = store_of(&d, &five_runs());
    let text = stdout(&check(&lock, &store, &[]));

    assert!(text.contains("· 5 package(s)"), "{text}");
    let row = |label: &str| {
        text.lines()
            .find(|l| l.contains(label) && (l.contains('░') || l.contains('▓')))
            .unwrap_or_else(|| panic!("no {label} row: {text}"))
            .to_string()
    };
    for label in [
        "reproduced",
        "caveats",
        "divergent",
        "unsupported",
        "never checked",
    ] {
        let r = row(label);
        let n: usize = r
            .split_whitespace()
            .find_map(|w| w.parse().ok())
            .unwrap_or_else(|| panic!("{r}"));
        assert_eq!(n, 1, "{r}");
    }

    let listed = |name: &str| {
        text.lines()
            .find(|l| l.split_whitespace().nth(1) == Some(name))
    };
    assert!(
        listed("same").is_none(),
        "a reproduction is not a finding: {text}"
    );
    assert!(
        listed("differs")
            .unwrap()
            .ends_with("the rebuild differs from what was published"),
        "{text}"
    );
    assert!(
        listed("judged")
            .unwrap()
            .ends_with("identical after a stabilizer that is a judgement call"),
        "{text}"
    );
    assert!(
        listed("unbuilt")
            .unwrap()
            .ends_with("the run reached no verdict"),
        "{text}"
    );
    // No detail, so the row's own name.
    assert!(
        listed("nobody").unwrap().ends_with("never checked"),
        "{text}"
    );
    // And no rate anywhere: three of the rows have different denominators.
    assert!(!text.contains('%'), "{text}");
    assert!(
        text.contains("neither is summed with the three above them"),
        "{text}"
    );
}

/// Forty lines of findings, and a count of the rest with where to find them.
#[test]
fn text_lists_forty_findings_and_counts_the_rest() {
    let d = dir("many");
    let names: Vec<String> = (0..43).map(|i| format!("p{i:02}")).collect();
    let packages: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "1.0.0")).collect();
    let lock = lockfile(&d, &packages);
    let store = store_of(&d, &[]);
    let text = stdout(&check(&lock, &store, &[]));

    let findings = text
        .lines()
        .filter(|l| l.trim_end().ends_with("never checked") && l.contains(" p"))
        .count();
    assert_eq!(findings, 40, "{text}");
    assert!(
        text.contains("… and 3 more; --format json for all of them"),
        "{text}"
    );
    // The JSON has all of them.
    let doc = json(&lock, &store);
    assert_eq!(doc["results"].as_array().unwrap().len(), 43);
}

/// SARIF: a result for every package that did not reproduce, never-checked included, each pointing
/// at its line, with the counts travelling beside them.
#[test]
fn sarif_has_a_result_for_everything_but_a_reproduction() {
    let d = dir("sarif");
    let lock = lockfile(&d, FIVE);
    let store = store_of(&d, &five_runs());
    let doc: serde_json::Value =
        serde_json::from_str(&stdout(&check(&lock, &store, &["--format", "sarif"]))).unwrap();

    assert_eq!(doc["version"], "2.1.0");
    let run = &doc["runs"][0];
    let results = run["results"].as_array().unwrap();
    let mut rules: Vec<&str> = results
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap())
        .collect();
    rules.sort();
    assert_eq!(
        rules,
        [
            "trigon/caveats",
            "trigon/divergent",
            "trigon/never-checked",
            "trigon/unsupported"
        ],
        "{doc}"
    );
    let text = std::fs::read_to_string(&lock).unwrap();
    for r in results {
        let purl = r["partialFingerprints"]["purl"].as_str().unwrap();
        let name = purl
            .trim_start_matches("pkg:npm/")
            .split('@')
            .next()
            .unwrap();
        let line = text
            .lines()
            .position(|l| l.contains(&format!("node_modules/{name}\"")))
            .unwrap()
            + 1;
        let loc = &r["locations"][0]["physicalLocation"];
        assert_eq!(loc["region"]["startLine"], line, "{r}");
        assert_eq!(loc["artifactLocation"]["uri"], lock.display().to_string());
    }
    let divergent = results
        .iter()
        .find(|r| r["ruleId"] == "trigon/divergent")
        .unwrap();
    assert_eq!(
        divergent["message"]["text"],
        "differs 1.0.0 — divergent: the rebuild differs from what was published"
    );
    assert_eq!(divergent["properties"]["run"], "1789000002-differs");
    let never = results
        .iter()
        .find(|r| r["ruleId"] == "trigon/never-checked")
        .unwrap();
    assert_eq!(never["message"]["text"], "nobody 1.0.0 — never checked");
    assert!(never["properties"]["run"].is_null());
    // Every rule a result names is declared.
    let declared: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    for r in &rules {
        assert!(declared.contains(r), "{r} is not declared: {declared:?}");
    }
    assert_eq!(run["properties"]["trigon"]["packages"], 5);
    assert_eq!(run["properties"]["trigon"]["tally"]["reproduced"], 1);
}

/// A `--store` that names nothing is refused, and not created: an empty store made on the spot
/// would report every package as never checked, of a store that never existed, and exit 0. The
/// refusal is the command line's mistake, never a bug in trigon to be reported.
#[test]
fn a_store_that_is_not_there_is_refused_rather_than_read_as_empty() {
    let d = dir("typo");
    let lock = lockfile(&d, FIVE);
    let typo = d.join("trigon-stroe");
    let out = check(&lock, &typo, &[]);
    // Exit 5, the tool failing (`docs/19` §6), as a bad argument to `check` exits: never 0, and
    // not a code the rest of `check` gives to something it found.
    assert_eq!(
        out.status.code(),
        Some(5),
        "a store that does not exist was read: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("is not a directory"), "{err}");
    assert!(err.contains("the command line's: no such store"), "{err}");
    assert!(!err.contains("bug in trigon"), "{err}");
    assert!(!typo.exists(), "checking against a store created one");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("never checked"),
        "a verdict table was printed about a store that does not exist"
    );
}

/// A lockfile that cannot be read is the tool failing, exit 5, with `--store` as without it: one
/// that is not there, one that does not parse, and a file name no parser claims. Nothing is
/// printed as though a lockfile had been checked.
#[test]
fn a_lockfile_that_cannot_be_read_exits_5_with_a_store_too() {
    let d = dir("unreadable-lock");
    let store = store_of(&d, &five_runs());
    let broken = d.join("broken").join("package-lock.json");
    std::fs::create_dir_all(broken.parent().unwrap()).unwrap();
    std::fs::write(&broken, "{ this is not json").unwrap();
    let unknown = d.join("dependencies.txt");
    std::fs::write(&unknown, "same==1.0.0\n").unwrap();
    for lock in [d.join("absent").join("package-lock.json"), broken, unknown] {
        let out = check(&lock, &store, &[]);
        assert_eq!(
            out.status.code(),
            Some(5),
            "{}: {}{}",
            lock.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Error: "),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
