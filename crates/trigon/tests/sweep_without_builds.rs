//! `trigon sweep` on the paths that build nothing: a sweep resumed with every target already done,
//! targets that are not package URLs — each of which fails before any registry is asked — and the
//! breaker that stops a sweep whose failures are all one failure.
//!
//! What is held is what makes a sweep's number mean something: rows written as they finish and
//! put back into target order at the end, a rate whose denominator is only the targets that
//! reached a comparison, failures grouped into the clusters that explain them, and a wall that
//! stops the run instead of spending the night proving one fact.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const IMAGE: &str = "docker.io/library/debian@sha256:aa";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-sweep-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("home")).unwrap();
    d
}

/// `trigon sweep <targets> --image … --work <d>/work`, with this test's home and temporary
/// directory and no `TRIGON_*` from this process.
fn sweep(d: &Path, targets: &str, extra: &[&str]) -> Output {
    let file = d.join("targets.txt");
    std::fs::write(&file, targets).unwrap();
    let mut c = Command::new(bin());
    c.current_dir(d)
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"))
        .env("XDG_CACHE_HOME", d.join("home/.cache"))
        .env("TMPDIR", d)
        .env("NO_COLOR", "1")
        // The breaker says why it stopped in a log line, which a `RUST_LOG` of the developer's own
        // could silence.
        .env_remove("RUST_LOG")
        .arg("sweep")
        .arg(&file)
        .args(["--image", IMAGE, "--work"])
        .arg(d.join("work"))
        .args(extra);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.output().unwrap()
}

fn results(d: &Path) -> Vec<Vec<String>> {
    std::fs::read_to_string(d.join("work/results.tsv"))
        .unwrap()
        .lines()
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// A sweep whose every target is already in its results file builds nothing, says it resumed,
/// puts the file back into target order — a reader lines it up against the corpus by position —
/// and reports a rate over the targets that reached a comparison and nothing else.
#[test]
fn a_finished_sweep_resumes_without_building_and_reports_the_rate_it_recorded() {
    let d = dir("resumed");
    std::fs::create_dir_all(d.join("work")).unwrap();
    // Completion order, not target order, as a sweep of several lanes leaves it.
    std::fs::write(
        d.join("work/results.tsv"),
        "pkg:npm/d@1\tbuild-failed:deps\t40.0\tcc/missing-header:python.h\t2\n\
         pkg:npm/b@1\tdivergent\t20.0\t\t0\n\
         pkg:npm/a@1\texact\t10.0\t\t0\n\
         pkg:npm/c@1\terror:infra\t5.0\terror:the mirror container did not start\t0\n",
    )
    .unwrap();
    let out = sweep(
        &d,
        "# a corpus\npkg:npm/a@1\n\npkg:npm/b@1\npkg:npm/c@1\npkg:npm/d@1\n",
        &[],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("resuming: 4 of 4 already done"), "{text}");
    assert_eq!(text.matches("(done)").count(), 4, "{text}");
    for i in 0..4 {
        assert!(
            !d.join(format!("work/{i:03}")).exists(),
            "target {i} was run again"
        );
    }

    assert_eq!(
        results(&d),
        [
            ["pkg:npm/a@1", "exact", "10.0", "", "0"],
            ["pkg:npm/b@1", "divergent", "20.0", "", "0"],
            [
                "pkg:npm/c@1",
                "error:infra",
                "5.0",
                "error:the mirror container did not start",
                "0"
            ],
            [
                "pkg:npm/d@1",
                "build-failed:deps",
                "40.0",
                "cc/missing-header:python.h",
                // A resumed row's model calls are the file's, so a resumed sweep's total is a
                // fresh one's.
                "2"
            ],
        ]
    );

    // An infrastructure failure and a build that failed are not packages that did not reproduce:
    // the rate is one of the two that were compared, not one of four.
    assert!(text.contains("4 targets"), "{text}");
    assert!(
        text.contains("1 of 2 compared targets reproduced (50%)"),
        "{text}"
    );
    assert!(
        text.contains("2 of 4 targets reached a comparison at all"),
        "{text}"
    );
    let clusters = text
        .split("failure clusters")
        .nth(1)
        .unwrap_or_else(|| panic!("no clusters:\n{text}"));
    assert!(clusters.contains("1  cc/missing-header:python.h"), "{text}");
    assert!(
        clusters.contains("1  error:the mirror container did not start"),
        "{text}"
    );
    assert!(text.contains("75s total"), "{text}");
}

/// A target that cannot even be parsed is that target's problem and not the sweep's: it is
/// recorded as a failure of policy with a cluster, and the targets after it are still tried.
#[test]
fn a_target_that_is_not_a_package_url_is_its_own_failure_and_the_sweep_goes_on() {
    let d = dir("unparseable");
    let out = sweep(&d, "left-pad-1\npkg:npm/left-pad\n", &[]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = results(&d);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0][0], "left-pad-1");
    assert_eq!(rows[0][1], "error:policy");
    assert!(
        rows[0][3].starts_with("error:a package URL starts with"),
        "{rows:?}"
    );
    assert_eq!(rows[1][0], "pkg:npm/left-pad");
    assert_eq!(rows[1][1], "error:policy");
    assert!(rows[1][3].starts_with("error:no version in"), "{rows:?}");
    // What differs per target is not what the cluster is keyed on.
    assert!(!rows[1][3].contains("left-pad"), "{rows:?}");
    assert!(
        text.contains("no target reached a comparison, so there is no rate to report"),
        "{text}"
    );

    // And each target's own directory says why, as every terminal outcome's does
    // (`docs/18-management-ui.md`): the run ended before it made the directory, and a watch page
    // over the sweep would otherwise report that the target left nothing behind.
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("could not write run.json"), "{err}");
    for (i, says) in [(0, "starts with `pkg:`"), (1, "no version in")] {
        let path = d.join(format!("work/{i:03}/run.json"));
        let report: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
        )
        .unwrap();
        assert!(
            report["error"].as_str().is_some_and(|e| e.contains(says)),
            "{report}"
        );
        assert!(report["finished"].is_string(), "{report}");
    }
}

/// A single `trigon rebuild` whose target is not a package URL leaves its `run.json` in `--work`
/// too, saying so, and exits non-zero: the same record a sweep's target leaves.
#[test]
fn a_rebuild_that_ends_before_it_starts_still_leaves_its_record() {
    let d = dir("rebuild-record");
    let work = d.join("work");
    let out = Command::new(bin())
        .current_dir(&d)
        .env("HOME", d.join("home"))
        .env("NO_COLOR", "1")
        .args(["rebuild", "left-pad-1.3.0", "--image", IMAGE, "--work"])
        .arg(&work)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("a package URL starts with `pkg:`"), "{err}");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("run.json")).unwrap()).unwrap();
    assert_eq!(report["purl"], "left-pad-1.3.0", "{report}");
    assert!(
        report["error"]
            .as_str()
            .is_some_and(|e| e.contains("starts with `pkg:`")),
        "{report}"
    );
    assert!(report.get("outcome").is_none(), "{report}");
}

/// `trigon rebuild <purl> --image … --work <work> <extra>`, with this test's home and no
/// `TRIGON_*` from this process.
fn rebuild(d: &Path, purl: &str, work: &Path, extra: &[&str]) -> Output {
    let mut c = Command::new(bin());
    c.current_dir(d)
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"))
        .env("XDG_CACHE_HOME", d.join("home/.cache"))
        .env("NO_COLOR", "1")
        .args(["rebuild", purl, "--image", IMAGE, "--work"])
        .arg(work)
        .args(extra);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.output().unwrap()
}

/// A target that parses and is refused before any registry is asked — a `--model` that names no
/// provider, an ecosystem this build has no client for — ends the run the same way: refused with
/// what was wrong, and a `run.json` in `--work` saying so, with no outcome, because nothing was
/// compared.
#[test]
fn a_rebuild_refused_for_its_model_or_ecosystem_still_leaves_its_record() {
    let d = dir("rebuild-refused");
    for (what, purl, extra, says) in [
        (
            "model",
            "pkg:npm/left-pad@1.3.0",
            &["--model", "nonsense"][..],
            "`nonsense` is not a provider this build knows",
        ),
        (
            "ecosystem",
            "pkg:gem/rails@7.0.0",
            &[][..],
            "trigon does not speak gem",
        ),
    ] {
        let work = d.join(what);
        let out = rebuild(&d, purl, &work, extra);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{what}: {err}");
        assert!(err.contains(says), "{what}: {err}");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("run.json")).unwrap()).unwrap();
        assert_eq!(report["purl"], purl, "{report}");
        assert!(
            report["error"].as_str().is_some_and(|e| e.contains(says)),
            "{what}: {report}"
        );
        assert!(report["finished"].is_string(), "{report}");
        assert!(report.get("outcome").is_none(), "{what}: {report}");
    }
}

/// The same failure over and over with nothing succeeding between them is a wall rather than a
/// set of findings. The sweep stops at it with every row so far written, and the same command
/// resumes where it stopped.
#[test]
fn a_run_of_identical_failures_stops_the_sweep_and_the_same_command_resumes_it() {
    let d = dir("wall");
    let targets = "bad-target-1\nbad-target-2\nbad-target-3\nbad-target-4\n";
    let out = sweep(&d, targets, &["--wall", "2"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("2 targets in a row failed the same way and none succeeded between them"),
        "{err}"
    );
    assert!(!err.contains("panicked"), "{err}");
    let rows = results(&d);
    assert_eq!(
        rows.iter().map(|r| r[0].as_str()).collect::<Vec<_>>(),
        ["bad-target-1", "bad-target-2"],
        "the breaker stopped the reporting and not the sweep"
    );
    assert_eq!(rows[0][3], rows[1][3], "one cluster, whatever the target");

    let out = sweep(&d, targets, &["--wall", "2"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("resuming: 2 of 4 already done"), "{text}");
    assert_eq!(
        results(&d)
            .iter()
            .map(|r| r[0].as_str().to_string())
            .collect::<Vec<_>>(),
        [
            "bad-target-1",
            "bad-target-2",
            "bad-target-3",
            "bad-target-4"
        ]
    );
}

/// A different failure between two identical ones resets the count, and `--wall 0` turns the
/// breaker off for a corpus expected to answer the same way this often.
#[test]
fn the_wall_counts_only_an_unbroken_run_and_zero_turns_it_off() {
    let d = dir("no-wall");
    let out = sweep(
        &d,
        "bad-1\npkg:npm/x\nbad-2\npkg:npm/y\nbad-3\n",
        &["--wall", "2"],
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains("in a row"));
    assert_eq!(results(&d).len(), 5);

    let d = dir("wall-off");
    let out = sweep(&d, "bad-1\nbad-2\nbad-3\nbad-4\n", &["--wall", "0"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("in a row"));
    assert_eq!(results(&d).len(), 4);
}

/// A targets file with nothing in it but comments is refused, not reported as a sweep of nothing.
#[test]
fn a_targets_file_with_no_targets_is_refused() {
    let d = dir("empty");
    let out = sweep(&d, "# nothing yet\n\n   \n", &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("has no targets"), "{err}");
    assert!(!d.join("work/results.tsv").exists());
}
