//! Watching a sweep from outside the process running it.
//!
//! `trigon sweep` already computes this. It computes it once, at the end, into a terminal owned by
//! whoever launched it. The gap a page fills is narrow and worth stating narrowly: a **second
//! reader, mid-run, from somewhere else**. That is the whole claim, and it is small enough to be
//! worth a day and cheap enough to delete — see [`18`](../../../docs/18-management-ui.md).
//!
//! # The monitor never talks to the sweep
//!
//! It reads the files the sweep already writes in order to survive its own death. The test of that
//! inversion is the moment the sweep crashes: every completed result stays on screen, the silence
//! is labelled with its exact age, and the target that was in flight is reported as unknown rather
//! than converted into a failure. A server inside `trigon sweep` fails that test — the socket
//! closes exactly when the operator most needs to know what happened — and would put a listening
//! socket and a second async runtime inside a process running untrusted builds.
//!
//! Nothing is held between requests. Killing and restarting this loses nothing, and pointing a
//! second one at the same directory is free.
//!
//! # Three rules, each a bug this project has already shipped
//!
//! - **Nothing absent is rendered as a zero.** "No results yet" is not "0% reproduced".
//! - **The two denominators never merge.** A package that did not reproduce and a build our own
//!   infrastructure could not run are different findings; one bucket holding both is a number about
//!   our reliability wearing a reproduction rate's costume.
//! - **Every panel says what it shows when empty, when stale, and when the producer has died.**
//!
//! # What it cannot do yet
//!
//! Liveness. Until a sweep writes a heartbeat (`18` step 3) this can only report how long ago the
//! last row landed, and it says so rather than guessing. There is no write path anywhere: a cluster
//! hands you the `trigon rebuild` line to paste.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use axum::extract::{Path as UrlPath, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

/// One row of `results.tsv`.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub purl: String,
    pub label: String,
    pub seconds: f64,
    /// The failure cluster, where the outcome had one.
    pub cluster: Option<String>,
    /// `None` where the sweep that wrote this row did not count — which is not the same as zero,
    /// and is the distinction the column exists for.
    pub model_calls: Option<u32>,
}

/// What kind of outcome a label names.
///
/// Deliberately not an ordering. These are different findings, not degrees of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// Reproduced, by whichever route.
    Reproduced,
    /// Compared, and did not match. A finding about the package.
    Divergent,
    /// The build ran and failed. A finding about the package or about the recipe.
    BuildFailed,
    /// Our own infrastructure. Never counted against a package.
    Error,
    /// Neither a pass nor a failure: the run is evidence of nothing.
    Void,
    /// Nothing on the ladder produced a recipe.
    NoStrategy,
}

impl Family {
    pub fn of(label: &str) -> Family {
        if let Ok(m) = label.parse::<trigon_core::Match>() {
            return match m {
                trigon_core::Match::Divergent => Family::Divergent,
                _ => Family::Reproduced,
            };
        }
        match label.split(':').next().unwrap_or(label) {
            "build-failed" => Family::BuildFailed,
            "void" => Family::Void,
            "no-strategy" => Family::NoStrategy,
            _ => Family::Error,
        }
    }

    /// Whether this row says anything about the package reproducing.
    pub fn is_evidence(self) -> bool {
        matches!(self, Family::Reproduced | Family::Divergent)
    }

    fn css(self) -> &'static str {
        match self {
            Family::Reproduced => "ok",
            Family::Divergent => "diff",
            Family::BuildFailed => "fail",
            Family::Error => "ours",
            Family::Void => "void",
            Family::NoStrategy => "none",
        }
    }

    /// The same colour the class in `STYLE` sets, for a swatch that cannot take one from CSS.
    ///
    /// Two places holding one colour is the shape of defect this project keeps finding, so a test
    /// reads `STYLE` and asserts the pair still agree rather than trusting that they do.
    fn colour(self) -> &'static str {
        match self {
            Family::Reproduced => "#137333",
            Family::Divergent => "#b26a00",
            Family::BuildFailed => "#b3261e",
            Family::Error => "#6b4fbb",
            Family::Void => "#6b6b66",
            Family::NoStrategy => "#6b6b66",
        }
    }

    /// The word for a legend.
    fn label(self) -> &'static str {
        match self {
            Family::Reproduced => "reproduced",
            Family::Divergent => "divergent",
            Family::BuildFailed => "build failed",
            Family::Error => "ours",
            Family::Void => "void",
            Family::NoStrategy => "no strategy",
        }
    }

    /// Every family, in the order a legend reads them: the two that are evidence, then the three
    /// that are a failure of some kind, then the one that is nothing at all.
    fn all() -> [Family; 6] {
        [
            Family::Reproduced,
            Family::Divergent,
            Family::BuildFailed,
            Family::NoStrategy,
            Family::Error,
            Family::Void,
        ]
    }
}

/// Read `results.tsv`.
///
/// Rows are appended and flushed per target, so a process killed mid-write can leave a partial
/// line. That line is dropped rather than rejecting the file — and the count of what was dropped is
/// returned, because silently discarding a row is how a board under-reports a sweep.
pub fn parse_results(text: &str) -> (Vec<Row>, usize) {
    let mut rows = Vec::new();
    let mut dropped = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let (Some(purl), Some(label), Some(secs)) = (f.next(), f.next(), f.next()) else {
            dropped += 1;
            continue;
        };
        let Ok(seconds) = secs.parse::<f64>() else {
            dropped += 1;
            continue;
        };
        rows.push(Row {
            purl: purl.to_string(),
            label: label.to_string(),
            seconds,
            cluster: f.next().filter(|c| !c.is_empty()).map(str::to_string),
            // Absent and zero are different answers: a sweep written before the column existed did
            // not count, and rendering that as "0 model calls" is the same sentence a clean run
            // prints.
            model_calls: f.next().and_then(|c| c.parse().ok()),
        });
    }
    (rows, dropped)
}

/// The two rates, with their denominators.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rates {
    pub reproduced: usize,
    /// Targets that produced evidence either way. The denominator of the reproduction rate.
    pub evidence: usize,
    /// Every row in the file. The denominator of the second rate, which is about us.
    pub attempted: usize,
}

impl Rates {
    pub fn of(rows: &[Row]) -> Rates {
        let evidence: Vec<Family> = rows
            .iter()
            .map(|r| Family::of(&r.label))
            .filter(|f| f.is_evidence())
            .collect();
        Rates {
            reproduced: evidence
                .iter()
                .filter(|f| **f == Family::Reproduced)
                .count(),
            evidence: evidence.len(),
            attempted: rows.len(),
        }
    }

    /// `None` when nothing was compared. Not zero: "nothing reproduced" and "nothing was tested"
    /// are different findings, and only one of them is about the packages.
    pub fn reproduction(&self) -> Option<f64> {
        (self.evidence > 0).then(|| self.reproduced as f64 / self.evidence as f64)
    }

    /// How much of what was attempted said anything at all. A number about our infrastructure.
    pub fn evidence_rate(&self) -> Option<f64> {
        (self.attempted > 0).then(|| self.evidence as f64 / self.attempted as f64)
    }
}

/// A group of rows that failed the same way.
#[derive(Clone, Debug, PartialEq)]
pub struct Cluster {
    pub key: String,
    pub members: Vec<String>,
}

/// Failure clusters, most members first.
///
/// What turns forty red rows into a handful of tickets. Ranked by size because that is what says
/// which one to fix first; ties break by key so the order is stable across refreshes.
pub fn clusters(rows: &[Row]) -> Vec<Cluster> {
    let mut by_key: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for r in rows {
        let Some(key) = r.cluster.as_deref() else {
            continue;
        };
        by_key.entry(key).or_default().push(r.purl.clone());
    }
    let mut out: Vec<Cluster> = by_key
        .into_iter()
        .map(|(key, members)| Cluster {
            key: key.to_string(),
            members,
        })
        .collect();
    out.sort_by_key(|c| (std::cmp::Reverse(c.members.len()), c.key.clone()));
    out
}

/// How long ago, in words.
pub fn ago(secs: u64) -> String {
    match secs {
        0..=90 => format!("{secs}s ago"),
        91..=5400 => format!("{}m ago", secs / 60),
        _ => format!("{}h ago", secs / 3600),
    }
}

/// The run's own end-to-end duration, where both ends are readable.
///
/// `None` rather than zero: a run whose timestamps this page cannot parse did not take no time.
fn bracket_seconds(r: &crate::progress::RunReport) -> Option<i64> {
    let start = rfc3339_epoch(&r.started)?;
    let finish = rfc3339_epoch(r.finished.as_deref()?)?;
    Some((finish - start).max(0))
}

/// The row a report makes, for the layouts whose rows are reports rather than `results.tsv` lines.
///
/// One function because there are now two of those, and a second copy is how the synthetic row a
/// single rebuild gets and the one an index gets start disagreeing about what an absent outcome
/// means.
fn row_of(r: &crate::progress::RunReport) -> Row {
    Row {
        purl: r.purl.clone(),
        // A report with no outcome is a run that raised before a verdict. `Family::of` sends
        // anything it does not recognise to `Error`, which is the safe direction: an unlabelled run
        // is never counted against the package.
        label: r
            .outcome
            .clone()
            .or_else(|| r.error.as_ref().map(|_| "error:infra".to_string()))
            .unwrap_or_else(|| "error:unknown".into()),
        // The started→finished bracket, which is the only honest duration a report carries. `0.0`
        // where it cannot be computed, and every page that shows it says so rather than letting a
        // zero read as an instant run.
        seconds: bracket_seconds(r).unwrap_or(0) as f64,
        cluster: r.failure.as_ref().map(|f| f.key()),
        model_calls: Some(r.model_calls),
    }
}

/// Everything a page needs, re-read per request.
struct Sweep {
    work: PathBuf,
    targets: Option<PathBuf>,
    bind: String,
    /// A store to enrich a compared run from, where the sweep was given one.
    ///
    /// Only ever an enrichment. The store records a run **only past a comparison** — `record_run`
    /// sits after the early return that unwraps it — so a page rooted here would report a perfect
    /// rate on a sweep where nothing built. It hangs off a row; it is never the root.
    store: Option<PathBuf>,
    /// Another sweep of the same corpus, to say what changed.
    baseline: Option<PathBuf>,
}

/// One run record, and how long it took to find it.
///
/// The join is O(runs): `list_runs` returns ids without opening records, so finding the one for a
/// target means opening them. Fine for twenty and wrong for a fleet, which is what M4's Postgres
/// exists to replace — so the page prints the cost, and the moment it stops being fine is visible
/// rather than felt.
struct Found {
    record: trigon_store::RunRecord,
    /// Whether the store has the blob of a rebuilt artifact the record says is kept: the record's
    /// word alone would show bytes the store has lost as present.
    rebuild_kept: bool,
    read: usize,
    millis: u128,
}

/// What looking a target up in a store produced.
///
/// **Four outcomes, not one `None`.** They used to collapse: a `--store` naming a directory that
/// does not exist rendered the identical sentence to a run that is genuinely not in the store — and
/// that sentence explains the absence as "no statement may be written about a run that is evidence
/// of nothing". So a mistyped path told the reader their run was evidence of nothing. Our own
/// configuration error, reported as a finding about their package.
enum Lookup {
    /// The store could not be opened. A path that is not there, or not a store.
    Unusable(String),
    /// Opened, and its index could not be listed.
    Unreadable(String),
    /// Opened and searched, and no record names this target.
    Absent {
        read: usize,
        millis: u128,
    },
    Found(Box<Found>),
}

async fn find_record(store: &Path, purl: &str) -> Lookup {
    let started = std::time::Instant::now();
    // `existing`, not `local`: this page is read-only and `local` creates the directory it is
    // given. A mistyped `--store` was making an empty store and then explaining, at length, why the
    // run was not in it.
    let opened = match trigon_store::Store::existing(store) {
        Ok(s) => s,
        Err(e) => return Lookup::Unusable(e.to_string()),
    };
    let ids = match opened.list_runs().await {
        Ok(i) => i,
        Err(e) => return Lookup::Unreadable(e.to_string()),
    };
    let mut read = 0;
    for id in ids {
        read += 1;
        // `get_run` re-hashes the blob it reads, which is the check the store exists to provide;
        // reading `blobs/` directly would skip it.
        if let Ok(r) = opened.get_run(&id).await
            && r.target == purl
        {
            let rebuild_kept = match &r.rebuild {
                Some(b) => opened.kept(b).await.unwrap_or(false),
                None => false,
            };
            return Lookup::Found(Box::new(Found {
                record: r,
                rebuild_kept,
                read,
                millis: started.elapsed().as_millis(),
            }));
        }
    }
    Lookup::Absent {
        read,
        millis: started.elapsed().as_millis(),
    }
}

/// Which shape of work directory this is.
///
/// `watch` was written for a sweep and understood nothing else, so a plain
/// `trigon rebuild --work ./work` — the command the README opens with — rendered "no results". The
/// layouts are told apart by what is on disk rather than by a flag, because a flag is a second
/// thing that has to agree with the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// A sweep wrote here: `results.tsv`, or the `sweep.json` and `status.json` it writes before
    /// its first target lands. Evidence lives in `<work>/{index:03}`.
    Sweep,
    /// No sweep, but a run left its report or its strategy at the root. One target, whose evidence
    /// directory *is* `<work>`.
    Single,
    /// No run at the root, and subdirectories that each hold one.
    ///
    /// What `scripts/rebuild-and-attest.sh` produces — one `./work/<purl-slug>` per invocation —
    /// and the shape every run in this repository is actually stored in. It rendered as `Unknown`,
    /// so `trigon watch ./work` answered **"state unknown · 0 attempted"** over twenty-four
    /// finished rebuilds: a sweep's vocabulary applied to a directory no sweep made, reporting
    /// evidence that is right there as absence. The first rule at the top of this file, running
    /// backwards.
    Index,
    /// None of those. Not a work directory this page can read, which is a different answer from an
    /// empty sweep and is said in those words.
    Unknown,
}

/// One run-bearing subdirectory of an [`Layout::Index`] directory.
///
/// **The directory's name is not the target.** `rebuild-and-attest.sh` names it by replacing every
/// character a path dislikes in the purl, which is lossy, and is one script's convention rather
/// than anything `trigon` writes — `--work` takes any path at all. So the target is read from
/// `run.json` or it is not known, and a directory without one is named as a directory.
struct Entry {
    dir: PathBuf,
    name: String,
    report: Option<crate::progress::RunReport>,
}

/// The subdirectories of a work directory that hold a run, in name order.
///
/// One `read_dir` and two `is_file` per child, no recursion: the question is only whether this
/// directory is a shelf of runs, and answering it by descending would cost a page load proportional
/// to every artifact underneath.
///
/// Name order rather than mtime, because the number in `/run/{i}` is a position in this list, and a
/// list that reorders itself under the reader turns a bookmarked run into a different one. It still
/// shifts when a new run lands — the sweep layout's numbering has the same property — so the page
/// names the target it is showing rather than leaving the number to carry it.
fn run_bearing_children(work: &Path) -> Vec<Entry> {
    let Ok(dir) = std::fs::read_dir(work) else {
        return Vec::new();
    };
    let mut out: Vec<Entry> = dir
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .filter(|p| p.join("run.json").is_file() || p.join("strategy.yaml").is_file())
        .map(|p| Entry {
            name: p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            report: std::fs::read_to_string(p.join("run.json"))
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok()),
            dir: p,
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

struct View {
    layout: Layout,
    /// The single run's report, where this is a `Single` directory and one parsed.
    ///
    /// `Some` and `None` are both meaningful: a report that is present and will not parse is a torn
    /// write, not an absent run, and the page says which.
    report: Option<crate::progress::RunReport>,
    /// Set when `run.json` exists and could not be read, which is not the same as no run.
    report_unreadable: bool,
    rows: Vec<Row>,
    dropped: usize,
    /// `None` when there is no `results.tsv` at all — which is not an empty sweep.
    age: Option<u64>,
    /// Target purls in the order the sweep will attempt them, when a targets file was named.
    targets: Option<Vec<String>>,
    /// Under [`Layout::Index`], the run-bearing subdirectories in name order — one per row.
    ///
    /// Positionally joined to `rows`: `rows[i]` is what `entries[i]` recorded. That join is what
    /// makes `/run/{i}` resolve to a directory nobody numbered.
    entries: Vec<Entry>,
    /// What the sweep said about itself, where it wrote it down.
    sweep: Option<crate::progress::Sweep>,
    status: Option<crate::progress::Status>,
    live: crate::progress::Liveness,
}

impl Sweep {
    fn read(&self) -> View {
        let results = self.work.join("results.tsv");
        let text = std::fs::read_to_string(&results).unwrap_or_default();
        let (rows, dropped) = parse_results(&text);

        // Decided from disk, before anything is rendered. `results.tsv` is written only by a sweep;
        // `run.json` and `strategy.yaml` only by a single rebuild. A directory with neither is
        // neither, and saying so beats rendering an empty sweep over it.
        let run_json = self.work.join("run.json");
        let report_text = std::fs::read_to_string(&run_json).ok();
        let report: Option<crate::progress::RunReport> = report_text
            .as_deref()
            .and_then(|t| serde_json::from_str(t).ok());
        let report_unreadable = report_text.is_some() && report.is_none();
        // A sweep that has not finished its first target has no `results.tsv` yet and is still a
        // sweep: it writes `sweep.json` before it starts and heartbeats into `status.json` while it
        // runs. Without those two, such a directory would read as an index of whatever its
        // in-flight `000/` happens to contain, and the liveness strip — the only thing worth
        // watching at that moment — would be replaced by a table of one.
        let sweepish = results.is_file()
            || self.work.join("sweep.json").is_file()
            || self.work.join("status.json").is_file();
        let singleish = report_text.is_some() || self.work.join("strategy.yaml").is_file();
        // Asked only where the answer can change anything. On a sweep of five thousand targets this
        // would be a `read_dir` and ten thousand `stat`s per page load, to re-answer a question
        // `results.tsv` already settled.
        let entries = if sweepish || singleish {
            Vec::new()
        } else {
            run_bearing_children(&self.work)
        };
        let layout = if sweepish {
            Layout::Sweep
        } else if singleish {
            Layout::Single
        } else if !entries.is_empty() {
            Layout::Index
        } else {
            Layout::Unknown
        };

        // One synthetic row, so the board, the run page and every panel below them keep working
        // against `View.rows` rather than growing a second code path. What the row cannot carry —
        // that its evidence directory is the work root rather than `{index:03}` — is `Layout`'s
        // job, which is why the two travel together.
        let (rows, dropped) = match (layout, &report) {
            (Layout::Single, Some(r)) => (vec![row_of(r)], 0),
            (Layout::Index, _) => (
                entries
                    .iter()
                    .map(|e| match &e.report {
                        Some(r) => row_of(r),
                        // A directory with a strategy and no report: the rebuild is still going, or
                        // it ended before it could write one. `error:` sends it to `Family::Error`,
                        // which is where an unknown belongs — ours until shown otherwise, and never
                        // counted against the package. The purl is empty because nothing on disk
                        // says what the target was; the directory's name is not a record of it.
                        None => Row {
                            purl: String::new(),
                            label: "error:no-report".into(),
                            seconds: 0.0,
                            cluster: None,
                            model_calls: None,
                        },
                    })
                    .collect(),
                0,
            ),
            _ => (rows, dropped),
        };
        let age = std::fs::metadata(&results)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs());
        let targets = self.targets.as_ref().and_then(|p| {
            let text = std::fs::read_to_string(p).ok()?;
            Some(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string)
                    .collect(),
            )
        });
        // The sweep's own account of itself. A `status.json` that is present and will not parse is
        // `Unreadable` rather than absent: somebody wrote something, and a reader that treats the
        // two alike turns a torn write into "no sweep here".
        let sweep: Option<crate::progress::Sweep> =
            std::fs::read_to_string(self.work.join("sweep.json"))
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok());
        let status_text = std::fs::read_to_string(self.work.join("status.json")).ok();
        let status: Option<crate::progress::Status> = status_text
            .as_deref()
            .and_then(|t| serde_json::from_str(t).ok());
        let live = match (&status, status_text.is_some()) {
            (Some(st), _) => {
                let age = rfc3339_age(&st.heartbeat).unwrap_or(u64::MAX);
                crate::progress::Liveness::of(
                    st,
                    age,
                    // `None` on a platform with no `/proc`: a wrong answer here is a page calling a
                    // running sweep dead, so an unknown pid is treated as alive.
                    crate::progress::pid_alive(st.pid).unwrap_or(true),
                    sweep.as_ref().map(|s| s.timeout_seconds).unwrap_or(0),
                )
            }
            (None, true) => crate::progress::Liveness::Unreadable,
            (None, false) => crate::progress::Liveness::Unknown,
        };

        View {
            layout,
            report,
            report_unreadable,
            rows,
            dropped,
            age,
            targets,
            entries,
            sweep,
            status,
            live,
        }
    }

    /// What the browser tab says.
    ///
    /// **Every tab said `target 000`** — every run page of every layout, so three open windows were
    /// three identical tabs and the history was a guess. The target where one is known, the work
    /// directory where it is not, and the tool's name on the end, because a tab reading
    /// `once@1.4.0` does not say what is looking at it.
    fn tab_title(&self, name: Option<&str>) -> String {
        let what = name.map(str::to_string).unwrap_or_else(|| {
            self.work
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| self.work.display().to_string())
        });
        format!("{what} · trigon watch")
    }

    /// Which per-target directory a purl's evidence is in.
    ///
    /// The sweep names them by the target's index in the targets file, so without that file this
    /// falls back to the row's position — which is the same number only if the sweep was not
    /// resumed against a reordered list. The page says which of the two it used.
    /// Where one target's evidence lives.
    ///
    /// One function, because the join was written out twice — in `read_log` and in `run` — and a
    /// layout where the answer is not `{index:03}` would have had to be taught to both. Under
    /// `Single` there is one target and its directory *is* the work root: a rebuild writes
    /// `rebuild/build.log` and `run.json` straight into `--work`.
    fn target_dir(&self, view: &View, index: usize) -> PathBuf {
        match view.layout {
            Layout::Single => self.work.clone(),
            // A name, not a number: these directories were named by whoever ran them. An index past
            // the end formats to a directory that does not exist, and the run page then reports
            // every fact as absent — which is the truth about a run that is not there.
            Layout::Index => view
                .entries
                .get(index)
                .map(|e| e.dir.clone())
                .unwrap_or_else(|| self.work.join(format!("{index:03}"))),
            _ => self.work.join(format!("{index:03}")),
        }
    }

    fn dir_of(&self, view: &View, purl: &str) -> Option<(usize, bool)> {
        // A targets file names a corpus. An index directory is not one — its contents are whatever
        // was run by hand — so a position in that corpus would point at somebody else's run.
        if view.layout != Layout::Index
            && let Some(targets) = &view.targets
        {
            return targets.iter().position(|t| t == purl).map(|i| (i, true));
        }
        view.rows
            .iter()
            .position(|r| r.purl == purl)
            .map(|i| (i, false))
    }
}

// ---------------------------------------------------------------------------------------------
// Rendering. Plain string templates: eight tables, nothing interactive, no bundler and no node.
// ---------------------------------------------------------------------------------------------

/// Escape for HTML text and attribute values.
///
/// Every string on these pages came from a package: its name, its build log, its failure evidence.
/// `docs/12-security.md` §4 calls build output the highest-risk injection channel in the system,
/// and a page that renders it raw makes the operator's browser the next target.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1a1a19;--dim:#6b6b66;--line:#e0e0dc;--card:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#141413;--fg:#e8e8e4;--dim:#8f8f88;--line:#2c2c29;--card:#1c1c1a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,sans-serif}
main{max-width:60rem;margin:0 auto;padding:1.5rem 1rem 4rem}
h1{font-size:1.1rem;margin:0 0 .25rem}h2{font-size:.95rem;margin:2rem 0 .5rem;font-weight:600}
a{color:inherit}
.state{border:1px solid var(--line);background:var(--card);border-radius:6px;padding:.6rem .8rem;margin:0 0 1.5rem}
.dim{color:var(--dim)}
.note{color:var(--dim);font-style:italic}
/* A transcript URL is the longest string on any of these pages and the least useful to read in
   full, so it wraps rather than pushing the columns that matter off the side. */
.url{word-break:break-all;max-width:38em;font-size:.9em}
.legend{display:flex;gap:1.2rem;flex-wrap:wrap;margin:.4rem 0 0;font-size:.85rem}
.key{display:inline-flex;align-items:center;gap:.35rem}
.key i{width:.7rem;height:.7rem;border-radius:2px;display:inline-block}
svg{display:block;border-radius:3px}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th{text-align:left;font-weight:600;color:var(--dim);font-size:.8rem;padding:.3rem .5rem;border-bottom:1px solid var(--line)}
td{padding:.3rem .5rem;border-bottom:1px solid var(--line)}
td.n{text-align:right}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.75rem;overflow-x:auto;font-size:.8rem}
.tag{display:inline-block;padding:0 .4rem;border-radius:3px;font-size:.78rem;border:1px solid var(--line)}
.ok{color:#137333}.diff{color:#b26a00}.fail{color:#b3261e}.ours{color:#6b4fbb}.void{color:#6b6b66}.none{color:#6b6b66}
.rate{font-size:1.6rem;font-weight:600}
.pair{display:flex;gap:2.5rem;flex-wrap:wrap}
";

fn page(title: &str, live: bool, body: &str, bind: &str) -> Html<String> {
    // Refreshes only while something might still be writing. A finished page that keeps polling
    // itself is what a stale page looks like when it is pretending to be alive.
    let refresh = if live {
        "<meta http-equiv=\"refresh\" content=\"5\">"
    } else {
        ""
    };
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">{refresh}\
         <title>{}</title><style>{STYLE}</style></head><body><main>{body}\
         <p class=\"dim\" style=\"margin-top:3rem;font-size:.78rem\">trigon watch on {} — read-only, \
         no write path. Absent measurements are never shown as zero.</p>\
         </main></body></html>",
        esc(title),
        esc(bind),
    ))
}

/// The strip that appears on every page.
fn state_strip(v: &View, targets_path: Option<&Path>) -> String {
    // A shelf of independent runs has no corpus, no progress and no process: every number the sweep
    // strip reaches for is a number about something that does not exist here. It used to print all
    // of them anyway — "state unknown · 0 attempted, of an unknown total · no results.tsv here
    // yet" — over a directory holding two dozen finished rebuilds.
    if v.layout == Layout::Index {
        let runs = v.entries.len();
        let unreported = v.entries.iter().filter(|e| e.report.is_none()).count();
        let note = if unreported > 0 {
            format!(
                "<br><span class=\"note\">{unreported} of them left no run.json: the rebuild is \
                 still going, or it ended before it could write one. This page cannot say what \
                 those found.</span>"
            )
        } else {
            String::new()
        };
        return format!(
            "<div class=\"state\"><strong>a directory of runs</strong> · {runs} rebuild(s), each \
             in a work directory of its own{note}<br><span class=\"note\">not a sweep: nothing \
             here was launched by one process, so there is no corpus to be a fraction of, no \
             progress, and no sweep to be alive or dead</span></div>"
        );
    }

    // A single run has no corpus, no denominator and no `results.tsv`, so the sweep's own strip —
    // "0 attempted, of an unknown total · no results.tsv here yet" — was three sentences of the
    // wrong vocabulary about a run that had in fact completed. Its strip answers the questions a
    // single run has instead.
    if v.layout == Layout::Single {
        let what = match (&v.report, v.report_unreadable) {
            (Some(r), _) => {
                // The only honest duration a report carries, and it brackets the whole of `run_one`
                // — resolve, fetch, infer, build, compare — not the build alone.
                let bracket = match (&r.finished, rfc3339_epoch(&r.started)) {
                    (Some(f), Some(st)) => match rfc3339_epoch(f) {
                        Some(fin) => format!(" · {}s end to end", (fin - st).max(0)),
                        None => " · <span class=\"note\">finished at an instant this page cannot \
                                 read</span>"
                            .into(),
                    },
                    // Written on every terminal outcome, so an absent `finished` means the process
                    // died before it could write one — not that the run is still going.
                    _ => " · <span class=\"note\">no finish recorded: the process did not reach \
                          the end of the run</span>"
                        .into(),
                };
                format!("one run · {}{bracket}", esc(&r.purl))
            }
            (None, true) => "one run · <span class=\"note\">run.json is here and will not parse: \
                             a torn write, not an absent run</span>"
                .to_string(),
            (None, false) => "one run · <span class=\"note\">no run.json, so this page is reading \
                              the files a rebuild leaves rather than its own report</span>"
                .to_string(),
        };
        return format!("<div class=\"state\"><strong>single rebuild</strong> · {what}</div>");
    }

    let attempted = v.rows.len();
    // The targets file if one was named, otherwise the count the sweep recorded about itself.
    let total = v
        .targets
        .as_ref()
        .map(|t| t.len())
        .or_else(|| v.sweep.as_ref().map(|s| s.targets_count));

    let progress = match total {
        Some(n) => format!("{attempted} of {n} attempted"),
        None => format!(
            "{attempted} attempted, of an unknown total \
             (<span class=\"note\">pass --targets to name the corpus</span>)"
        ),
    };
    let freshness = match v.age {
        // No file at all is not an empty sweep: it is a directory that has not been written to.
        None => "no results.tsv here yet — either the sweep has not finished its first target, or \
                 this is not a sweep work directory"
            .to_string(),
        Some(s) => format!(
            "last result {}{}",
            ago(s),
            if s > 600 {
                " — nothing new for a while"
            } else {
                ""
            }
        ),
    };
    let dropped = if v.dropped > 0 {
        format!(
            "<br><span class=\"note\">{} line(s) in results.tsv did not parse and were dropped — \
             a process killed mid-write leaves a partial row</span>",
            v.dropped
        )
    } else {
        String::new()
    };
    let targets_note = targets_path
        .map(|p| format!(" · targets {}", esc(&p.display().to_string())))
        .unwrap_or_default();

    format!(
        "<div class=\"state\"><strong>{}</strong> · {progress} · {freshness}{targets_note}{dropped}\
         {}</div>",
        liveness_text(v),
        liveness_detail(v),
    )
}

/// The sweep's state, in a word.
fn liveness_text(v: &View) -> String {
    use crate::progress::Liveness as L;
    // Not `Unknown`. We looked, and what is here is not the kind of thing that has a state: no
    // process launched these runs together, so none of them can be running now.
    if v.layout == Layout::Index {
        return "not a sweep".into();
    }
    match &v.live {
        L::Unknown => "state unknown".into(),
        L::Unreadable => "state unreadable".into(),
        L::Starting => "starting".into(),
        L::Running => "running".into(),
        L::Stuck { .. } => "STUCK".into(),
        L::Stopped => "stopped".into(),
        L::Unresponsive => "UNRESPONSIVE".into(),
        L::Finished => "finished".into(),
    }
}

/// The sentence under it, which is where the honesty lives.
fn liveness_detail(v: &View) -> String {
    use crate::progress::Liveness as L;
    let note = |s: String| format!("<br><span class=\"note\">{s}</span>");
    if v.layout == Layout::Index {
        return note(format!(
            "this directory holds {} independent rebuild(s), each in a work directory of its own. \
             There is no sweep process here to be alive or dead, and no corpus these runs are a \
             sample of.",
            v.entries.len()
        ));
    }
    match &v.live {
        // A sweep from before the heartbeat existed, or a directory that is not one. Named as
        // absent rather than reported as stopped: we did not look and find nothing, there was
        // nothing to look at.
        L::Unknown => note(
            "this directory has no status.json — either the sweep predates the heartbeat, or it \
             is not a sweep work directory. Whether a process is running cannot be told from here."
                .into(),
        ),
        L::Unreadable => note(
            "status.json is present and did not parse — a torn write, or a file from another \
             version. The results below are still what the sweep recorded."
                .into(),
        ),
        L::Starting => note("no target has been attempted yet".into()),
        L::Running => match &v.status.as_ref().and_then(|s| s.current.clone()) {
            Some(c) => note(format!(
                "on {} for {}{}",
                esc(c.purl.strip_prefix("pkg:").unwrap_or(&c.purl)),
                ago(c.elapsed_seconds).trim_end_matches(" ago"),
                phase_text(c),
            )),
            None => note("between targets".into()),
        },
        L::Stuck { seconds } => {
            let ceiling = v.sweep.as_ref().map(|s| s.timeout_seconds).unwrap_or(0);
            let on = v
                .status
                .as_ref()
                .and_then(|s| s.current.clone())
                .map(|c| esc(c.purl.strip_prefix("pkg:").unwrap_or(&c.purl)))
                .unwrap_or_default();
            let phase = v
                .status
                .as_ref()
                .and_then(|s| s.current.clone())
                .map(|c| phase_text(&c))
                .unwrap_or_default();
            note(format!(
                "heartbeating, and on {on} for {seconds}s{phase} — past the {ceiling}s ceiling \
                 this sweep set for one target. Something is wrong by the sweep's own standard."
            ))
        }
        L::Stopped => note(
            "the heartbeat stopped and the process is gone. Everything below is what it recorded \
             before that; the target it was on has no outcome, which is not the same as failing."
                .into(),
        ),
        L::Unresponsive => note(
            "the heartbeat stopped and the process is still there — wedged in a way that took the \
             heartbeat with it. Worse than stopped."
                .into(),
        ),
        L::Finished => match v.sweep.as_ref().and_then(|s| s.finished.clone()) {
            Some(t) => note(format!("finished at {}", esc(&t))),
            None => note("finished".into()),
        },
    }
}

/// Which phase, and how long it has been in it.
///
/// The phase's own clock rather than the target's: a target twenty minutes in is perfectly healthy
/// if nineteen of them were `deps`, and the number that says otherwise is this one.
///
/// A phase nobody wrote is named as unrecorded rather than left blank — an absent phase is not a
/// phase of zero length, and a blank reads as one.
fn phase_text(c: &crate::progress::Current) -> String {
    match &c.phase {
        Some(p) => format!(
            ", in <strong>{}</strong> for {}",
            esc(p),
            ago(c.phase_elapsed_seconds).trim_end_matches(" ago")
        ),
        None => ", phase not yet recorded for this target".into(),
    }
}

/// Seconds since an RFC 3339 UTC instant of the shape this project writes.
///
/// `None` when it will not parse, which the caller treats as "very old" rather than as "now": a
/// timestamp we cannot read must not make a dead sweep look alive.
fn rfc3339_age(s: &str) -> Option<u64> {
    let then = rfc3339_epoch(s)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some((now - then).max(0) as u64)
}

/// The same instant as epoch seconds.
///
/// Split out rather than copied: a single-run page needs the started→finished bracket, and a second
/// implementation of days-from-civil is a second thing that has to agree with this one — which is
/// why the one implementation now lives in `trigon-core`, where the publication gate reads it too.
fn rfc3339_epoch(s: &str) -> Option<i64> {
    trigon_core::time::rfc3339_epoch(s)
}

fn rates_panel(r: &Rates) -> String {
    if r.attempted == 0 {
        return "<h2>Rates</h2><p class=\"note\">nothing has been attempted, so there is no rate to \
                report</p>"
            .into();
    }
    let reproduction = match r.reproduction() {
        // `summarize`'s own sentence, and for its reason: 0% is a claim about the packages, and no
        // comparison happened to make it.
        None => {
            "<div><div class=\"note\" style=\"max-width:22rem\">no target reached a comparison, \
                 so there is no reproduction rate to report</div></div>"
                .to_string()
        }
        Some(f) => format!(
            "<div><div class=\"rate ok\">{:.0}%</div>\
             <div class=\"dim\">{} of {} compared targets reproduced</div></div>",
            f * 100.0,
            r.reproduced,
            r.evidence
        ),
    };
    let evidence = format!(
        "<div><div class=\"rate\">{:.0}%</div>\
         <div class=\"dim\">{} of {} attempted targets reached a comparison at all</div>\
         <div class=\"note\">this one is about our infrastructure, not the packages</div></div>",
        r.evidence_rate().unwrap_or(0.0) * 100.0,
        r.evidence,
        r.attempted
    );
    format!("<h2>Rates</h2><div class=\"pair\">{reproduction}{evidence}</div>")
}

fn clusters_panel(rows: &[Row]) -> String {
    let cs = clusters(rows);
    if cs.is_empty() {
        // A statement about what has been recorded, never about the corpus.
        return format!(
            "<h2>Failure clusters</h2><p class=\"note\">nothing failed in the {} target(s) \
             recorded so far</p>",
            rows.len()
        );
    }
    let mut body = String::from(
        "<h2>Failure clusters</h2><table><tr><th class=\"n\">n</th><th>cluster</th></tr>",
    );
    for c in &cs {
        body.push_str(&format!(
            "<tr><td class=\"n\">{}</td><td><a href=\"/cluster?key={}\"><code>{}</code></a></td></tr>",
            c.members.len(),
            esc(&urlencode(&c.key)),
            esc(&c.key),
        ));
    }
    body.push_str("</table>");
    body
}

/// What changed against an earlier sweep of the same corpus.
///
/// The question a change has to answer, and the one an aggregate rate cannot: not "did the rate go
/// up" but "which targets flipped, in which direction". A change that fixes one package and breaks
/// two leaves the rate untouched.
///
/// Refuses to compare two sweeps of different corpora. Both record the sha256 of their targets
/// file, so "these are the same twenty packages" is checkable rather than assumed — and a
/// comparison across different lists is a number about the lists.
fn baseline_panel(sweep: &Sweep, v: &View) -> String {
    let Some(path) = &sweep.baseline else {
        return String::new();
    };
    let other = Sweep {
        work: path.clone(),
        targets: None,
        bind: String::new(),
        store: None,
        baseline: None,
    };
    let b = other.read();

    let mut out = format!("<h2>Against {}</h2>", esc(&path.display().to_string()));
    match (
        v.sweep.as_ref().and_then(|s| s.targets_sha256.clone()),
        b.sweep.as_ref().and_then(|s| s.targets_sha256.clone()),
    ) {
        (Some(a), Some(c)) if a != c => {
            return out
                + "<p class=\"note\">these are sweeps of different corpora — the targets files \
                   hash differently, so a comparison between them would be a number about the \
                   lists rather than about the change</p>";
        }
        (Some(_), Some(_)) => {}
        // One of them predates `sweep.json`. Comparable, and said so rather than silently assumed.
        _ => out.push_str(
            "<p class=\"note\">one of these sweeps recorded no corpus digest, so that they are \
             the same corpus is an assumption rather than a check</p>",
        ),
    }

    let obs = |rows: &[Row]| -> Vec<trigon_ai::Observation> {
        rows.iter()
            .map(|r| trigon_ai::Observation {
                purl: r.purl.clone(),
                outcome: r
                    .label
                    .parse::<trigon_core::Match>()
                    .ok()
                    .map(|m| m.to_string()),
                // Already `Option` here, and it stays one: `watch` renders an absent count as an
                // em dash per row, and flattening it to zero on the way into a scorecard is the
                // bug the other reader had.
                model_calls: r.model_calls,
                is_evidence: Family::of(&r.label).is_evidence(),
            })
            .collect()
    };
    let f = trigon_ai::flips(&obs(&b.rows), &obs(&v.rows));

    let sections: [(&str, &[String]); 5] = [
        ("now reproduces", &f.fixed),
        ("NO LONGER REPRODUCES", &f.broken),
        // Ours, not the change's. Filing it as a regression would make every flaky sweep look like
        // a bad change.
        (
            "stopped producing evidence — ours, not the change's",
            &f.lost_evidence,
        ),
        ("now produces evidence", &f.gained_evidence),
        ("in this sweep and not the baseline", &f.added),
    ];
    let mut said = false;
    for (heading, list) in sections {
        if list.is_empty() {
            continue;
        }
        said = true;
        out.push_str(&format!(
            "<p><strong>{} {heading}</strong></p><ul>",
            list.len()
        ));
        for p in list {
            out.push_str(&format!("<li><code>{}</code></li>", esc(p)));
        }
        out.push_str("</ul>");
    }
    if !f.changed.is_empty() {
        said = true;
        out.push_str(&format!(
            "<p><strong>{} reproduce differently</strong></p><ul>",
            f.changed.len()
        ));
        for c in &f.changed {
            out.push_str(&format!(
                "<li><code>{}</code> {} → {}</li>",
                esc(&c.purl),
                esc(&c.from),
                esc(&c.to)
            ));
        }
        out.push_str("</ul>");
    }
    if !f.dropped.is_empty() {
        said = true;
        // A corpus that quietly shrank is how a rate improves without anything improving.
        out.push_str(&format!(
            "<p><strong>{} in the baseline and not this sweep</strong></p><ul>",
            f.dropped.len()
        ));
        for p in &f.dropped {
            out.push_str(&format!("<li><code>{}</code></li>", esc(p)));
        }
        out.push_str("</ul>");
    }
    if !said {
        out.push_str("<p class=\"note\">nothing changed</p>");
    }
    out.push_str(&format!(
        "<p><strong>{}</strong></p>",
        if f.is_net_gain() {
            "A net gain: something was fixed and nothing regressed."
        } else if !f.broken.is_empty() {
            "NOT a net gain: something that reproduced no longer does."
        } else {
            "Not a gain: nothing was fixed."
        }
    ));
    out
}

/// The first `n` characters, never a byte index that could land inside one.
///
/// A commit is hex and eight bytes is eight characters — until a `run.json` somebody edited by hand
/// says otherwise, and then `&s[..8]` is a panic inside a request handler rather than a short
/// string. The page renders whatever is on disk; it does not get to assume the shape of it.
fn short_hex(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// A repository, at the length a table column can hold.
///
/// Only one host prefix comes off, and only the host that is most of every corpus we run. A URL
/// that is not GitHub's keeps its host, because which forge a package builds from is part of what
/// the reader is checking.
fn short_repo(url: &str) -> &str {
    url.strip_prefix("https://github.com/")
        .unwrap_or_else(|| url.strip_prefix("https://").unwrap_or(url))
}

/// The front door for a directory of independent runs.
///
/// Five columns, each answering something the reader has before they open anything: what was
/// attempted, what the run concluded, **which source it was compared against**, when, and what it
/// cost. The third is new to this page in a strong sense — `run.json`'s `source` had no reader
/// anywhere in this file, though its own doc comment calls it "the one thing a reader has to have
/// and did not", and `SourceDiscovery` "predicts a false result better than anything else
/// available". A verdict is a claim about a published artifact *and a commit*, and the commit half
/// was reaching nobody.
///
/// The column that is not here is how much of the artifact actually came from that commit. That is
/// the source→artifact join, and it hashes a checkout: 19 seconds cold on the largest one in this
/// cache. It is not a thing a page load may do, and a number that arrives 19 seconds late is not a
/// column.
fn index_panel(v: &View) -> String {
    let mut body = String::from(
        "<h2>Runs</h2><table><tr><th>target</th><th>outcome</th><th>built from</th>\
         <th>when</th><th class=\"n\">cost</th></tr>",
    );
    for (i, e) in v.entries.iter().enumerate() {
        let Some(r) = &e.report else {
            body.push_str(&format!(
                "<tr><td><a href=\"/run/{i}\"><code>{}</code></a></td>\
                 <td colspan=\"4\" class=\"note\">no run.json: the rebuild is still going, or it \
                 ended before it could write one. Nothing inside names a target — the directory's \
                 name is whatever the caller passed to <code>--work</code>, not a record.</td></tr>",
                esc(&e.name),
            ));
            continue;
        };
        let row = row_of(r);
        let fam = Family::of(&row.label);
        let name = r.purl.strip_prefix("pkg:").unwrap_or(&r.purl);
        let outcome = format!(
            "<span class=\"tag {}\">{}</span>{}",
            fam.css(),
            esc(&row.label),
            match &row.cluster {
                Some(c) => format!(
                    "<br><a href=\"/cluster?key={}\"><code class=\"dim\">{}</code></a>",
                    esc(&urlencode(c)),
                    esc(c)
                ),
                None => String::new(),
            }
        );
        let source = match &r.source {
            Some(src) => format!(
                "<code>{}</code>@<code title=\"{}\">{}</code>{}<br><span class=\"dim\">{}</span>",
                esc(short_repo(&src.repo_url)),
                esc(&src.commit),
                esc(short_hex(&src.commit, 8)),
                match &src.subdir {
                    // Load-bearing, not decoration: Newtonsoft.Json builds from
                    // `Src/Newtonsoft.Json`, and a reader comparing the artifact against the
                    // repository root would be comparing against the wrong tree.
                    Some(d) => format!(" <span class=\"dim\">{}</span>", esc(d)),
                    None => String::new(),
                },
                esc(src.how.as_str()),
            ),
            None => "<span class=\"note\">no source resolved: nothing here was compared against a \
                     commit</span>"
                .to_string(),
        };
        let when = match r.finished.as_deref().and_then(rfc3339_age) {
            Some(a) => ago(a),
            None => "<span class=\"note\">no finish recorded</span>".to_string(),
        };
        // Absent is not zero on either half: a run whose clock this page cannot read did not take
        // no time, and a run with no transcript did not fetch nothing.
        let mut cost = vec![match bracket_seconds(r) {
            Some(secs) => format!("{secs}s"),
            None => "<span class=\"note\">no duration</span>".to_string(),
        }];
        if let Some(b) = r.network_bytes {
            cost.push(human_bytes(b));
        }
        body.push_str(&format!(
            "<tr><td><a href=\"/run/{i}\">{}</a></td><td>{outcome}</td><td>{source}</td>\
             <td>{when}</td><td class=\"n\">{}</td></tr>",
            esc(name),
            cost.join(" · "),
        ));
    }
    body.push_str("</table>");
    body
}

/// What the colours mean, and how many of each are here.
///
/// **A tally, never a rate.** Six counts that add up to the number of runs, and no percentage: this
/// directory is whatever somebody chose to run, so there is no corpus for a percentage to be of. A
/// reproduction rate over a hand-picked shelf is the number this project exists to stop people
/// quoting, and the sweep board's rates panel names both its denominators out loud precisely
/// because a sweep does have one.
///
/// Every family is listed, including the ones at zero — unlike `ladder_svg`, which draws no band
/// for an empty class. The difference is what the two are for: that one is a key to a picture,
/// where an entry pointing at nothing sends the reader hunting for it, and this one is also the
/// answer to "what could I have found here", where a zero is a finding.
fn family_tally(rows: &[Row]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::from("<p class=\"legend\">");
    for f in Family::all() {
        out.push_str(&format!(
            "<span class=\"key\"><i style=\"background:{}\"></i>{} {}</span>",
            f.colour(),
            rows.iter().filter(|r| Family::of(&r.label) == f).count(),
            f.label(),
        ));
    }
    out.push_str(
        "</p><p class=\"note\">Counts, not a rate. These runs are whatever was launched by hand in \
         this directory, so there is no denominator here worth dividing by — only a sweep over a \
         named corpus has one. <strong>Ours</strong> is never counted against a package, and \
         <strong>void</strong> and <strong>no strategy</strong> share a grey because neither is \
         evidence either way.</p>",
    );
    out
}

fn board_panel(sweep: &Sweep, v: &View) -> String {
    if v.rows.is_empty() {
        return String::new();
    }
    let mut body = String::from(
        "<h2>Targets</h2><table><tr><th>target</th><th>outcome</th><th class=\"n\">s</th>\
         <th>cluster</th><th class=\"n\">model</th></tr>",
    );
    for r in &v.rows {
        let fam = Family::of(&r.label);
        let idx = sweep.dir_of(v, &r.purl);
        let name = r.purl.strip_prefix("pkg:").unwrap_or(&r.purl);
        let target = match idx {
            Some((i, _)) => format!("<a href=\"/run/{i}\">{}</a>", esc(name)),
            None => esc(name),
        };
        body.push_str(&format!(
            "<tr><td>{target}</td><td><span class=\"tag {}\">{}</span></td>\
             <td class=\"n\">{:.0}</td><td><code class=\"dim\">{}</code></td><td class=\"n\">{}</td></tr>",
            fam.css(),
            esc(&r.label),
            r.seconds,
            esc(r.cluster.as_deref().unwrap_or("")),
            // Absent is not zero, and the two must not look alike.
            match r.model_calls {
                Some(n) => n.to_string(),
                None => "<span class=\"note\">—</span>".into(),
            },
        ));
    }
    body.push_str("</table>");
    body
}

/// Percent-encode everything that is not unreserved, so a cluster key with a slash or a space
/// survives a round trip through the query string.
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The whole view model as one object.
///
/// The same numbers the page renders, so a script, a TUI, or a page polling without a full reload
/// reads exactly what a person does. Every `Option` stays an `Option` on the wire: absent is the
/// answer, and a JSON zero would be a different one.
#[derive(serde::Serialize)]
struct ApiState {
    /// Which shape of directory this is, in the serialized spelling of [`Layout`].
    ///
    /// Here because the page and the API must not answer differently: the page stops showing a
    /// reproduction rate over a directory of hand-run rebuilds, and a script reading the rate
    /// fields is owed the same caveat rather than a percentage with nothing attached.
    layout: &'static str,
    state: String,
    detail: String,
    attempted: usize,
    total: Option<usize>,
    /// `None` when nothing was compared. Not zero.
    reproduction: Option<f64>,
    reproduced: usize,
    evidence: usize,
    evidence_rate: Option<f64>,
    dropped_rows: usize,
    results_age_seconds: Option<u64>,
    current: Option<crate::progress::Current>,
    clusters: Vec<ApiCluster>,
}

#[derive(serde::Serialize)]
struct ApiCluster {
    key: String,
    members: usize,
}

async fn api_state(State(sweep): State<std::sync::Arc<Sweep>>) -> Response {
    let v = sweep.read();
    let r = Rates::of(&v.rows);
    axum::Json(ApiState {
        layout: match v.layout {
            Layout::Sweep => "sweep",
            Layout::Single => "single",
            Layout::Index => "index",
            Layout::Unknown => "unknown",
        },
        state: liveness_text(&v),
        // The rendered sentence, stripped of its markup: a reader of the JSON gets the same
        // caveat a reader of the page does, rather than a bare word they have to interpret.
        detail: strip_tags(&liveness_detail(&v)),
        attempted: r.attempted,
        total: v
            .targets
            .as_ref()
            .map(|t| t.len())
            .or_else(|| v.sweep.as_ref().map(|s| s.targets_count)),
        reproduction: r.reproduction(),
        reproduced: r.reproduced,
        evidence: r.evidence,
        evidence_rate: r.evidence_rate(),
        dropped_rows: v.dropped,
        results_age_seconds: v.age,
        current: v.status.as_ref().and_then(|s| s.current.clone()),
        clusters: clusters(&v.rows)
            .into_iter()
            .map(|c| ApiCluster {
                key: c.key,
                members: c.members.len(),
            })
            .collect(),
    })
    .into_response()
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.replace("&quot;", "\"").trim().to_string()
}

async fn board(State(sweep): State<std::sync::Arc<Sweep>>) -> Response {
    let v = sweep.read();
    let live = v.live.is_live();
    let body = match v.layout {
        // No rates panel: see `family_tally`. No board panel either — its columns are seconds,
        // cluster and model calls, which is a sweep's triage view, and this page's reader is
        // asking a different question.
        Layout::Index => format!(
            "<h1>{}</h1>{}{}{}{}",
            esc(&sweep.work.display().to_string()),
            state_strip(&v, sweep.targets.as_deref()),
            index_panel(&v),
            family_tally(&v.rows),
            clusters_panel(&v.rows),
        ),
        _ => format!(
            "<h1>{}</h1>{}{}{}{}{}",
            esc(&sweep.work.display().to_string()),
            state_strip(&v, sweep.targets.as_deref()),
            rates_panel(&Rates::of(&v.rows)),
            clusters_panel(&v.rows),
            board_panel(&sweep, &v),
            baseline_panel(&sweep, &v),
        ),
    };
    page(&sweep.tab_title(None), live, &body, &sweep.bind).into_response()
}

#[derive(serde::Deserialize)]
struct ClusterQuery {
    key: String,
}

async fn cluster(
    State(sweep): State<std::sync::Arc<Sweep>>,
    Query(q): Query<ClusterQuery>,
) -> Response {
    let v = sweep.read();
    let members: Vec<&Row> = v
        .rows
        .iter()
        .filter(|r| r.cluster.as_deref() == Some(q.key.as_str()))
        .collect();
    if members.is_empty() {
        return Redirect::to("/").into_response();
    }

    // The evidence line for each member, re-classified from its log. Deduplicated with counts,
    // because a cluster of forty is usually three sentences: that is the question this page is
    // open to answer — one thing, or three wearing one name.
    let mut lines: BTreeMap<String, usize> = BTreeMap::new();
    let mut unread = 0;
    for m in &members {
        match sweep
            .dir_of(&v, &m.purl)
            .and_then(|(i, _)| read_log(&sweep.target_dir(&v, i)))
        {
            Some(log) => {
                let sig = trigon_core::classify(&log);
                *lines.entry(sig.evidence.trim().to_string()).or_default() += 1;
            }
            None => unread += 1,
        }
    }

    let mut body = format!(
        "<h1><code>{}</code></h1>{}<p>{} target(s) failed this way.</p>",
        esc(&q.key),
        state_strip(&v, sweep.targets.as_deref()),
        members.len()
    );

    body.push_str("<h2>What the logs say</h2>");
    if lines.is_empty() {
        body.push_str(
            "<p class=\"note\">no log for any member is on disk — these rows were resumed from an \
             earlier sweep whose work directory is gone</p>",
        );
    } else {
        let mut ranked: Vec<_> = lines.into_iter().collect();
        ranked.sort_by_key(|(line, n)| (std::cmp::Reverse(*n), line.clone()));
        body.push_str("<table><tr><th class=\"n\">n</th><th>evidence</th></tr>");
        for (line, n) in ranked {
            body.push_str(&format!(
                "<tr><td class=\"n\">{n}</td><td><code>{}</code></td></tr>",
                esc(&line)
            ));
        }
        body.push_str("</table>");
        if unread > 0 {
            body.push_str(&format!(
                "<p class=\"note\">{unread} member(s) have no log on disk and are not counted \
                 above</p>"
            ));
        }
    }

    body.push_str("<h2>Members</h2><table><tr><th>target</th><th>outcome</th><th></th></tr>");
    for m in &members {
        let name = m.purl.strip_prefix("pkg:").unwrap_or(&m.purl);
        let link = match sweep.dir_of(&v, &m.purl) {
            Some((i, _)) => format!("<a href=\"/run/{i}\">open</a>"),
            None => "<span class=\"note\">no directory</span>".into(),
        };
        body.push_str(&format!(
            "<tr><td>{}</td><td><span class=\"tag {}\">{}</span></td><td>{link}</td></tr>",
            esc(name),
            Family::of(&m.label).css(),
            esc(&m.label),
        ));
    }
    body.push_str("</table>");

    // The action, as something to paste. There is no write path here on purpose: no queue, no
    // lease and no worker, so a page forking builds it cannot track or cancel is a control plane
    // wearing a page's clothes.
    body.push_str(&format!(
        "<h2>Reproduce one</h2><pre>trigon rebuild {} --image &lt;the image this sweep used&gt; \\\n    \
         --work ./one --egress mirror-only --timewarp auto -v</pre>",
        esc(&members[0].purl)
    ));
    body.push_str("<p><a href=\"/\">← all targets</a></p>");

    page(&q.key, v.live.is_live(), &body, &sweep.bind).into_response()
}

/// What the mirror served into this build, read from the run's own `network.jsonl`.
///
/// **Three states, decided before a single number is printed.** The file being absent and the file
/// being empty mean opposite things, and the difference is the one `attestable` is derived from: no
/// file means no complete account exists — which at `--egress open` is the ordinary case and not a
/// fault — while an empty file is a complete account of a build that fetched nothing.
fn read_transcript(dir: &Path) -> Transcript {
    let path = dir.join("rebuild").join("network.jsonl");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Transcript::Absent;
    };
    let bytes = text.len() as u64;
    match trigon_mirror::Exchange::parse_jsonl(&text) {
        // A parse failure is neither of the honest states. Saying "0 responses" here would turn a
        // version skew or a torn write into a clean, short, believable account.
        Err(detail) => Transcript::Unreadable(detail),
        Ok(rows) => Transcript::Present { rows, bytes },
    }
}

enum Transcript {
    Absent,
    Unreadable(String),
    Present {
        rows: Vec<trigon_mirror::Exchange>,
        bytes: u64,
    },
}

/// The summary that sits on the run page, linking to the full table.
fn network_panel(dir: &Path, index: usize) -> String {
    let mut out = String::from("<h2>Network</h2>");
    match read_transcript(dir) {
        Transcript::Absent => out.push_str(
            "<p class=\"note\">no <code>network.jsonl</code>, so no complete account of what \
             crossed into this build exists. At <code>--egress open</code> that is the ordinary \
             case rather than a fault: the build can reach the internet directly, so nothing is in \
             a position to write the account. An enforced tier records one.</p>",
        ),
        Transcript::Unreadable(detail) => out.push_str(&format!(
            "<p class=\"void\">the transcript is here and will not parse, so what crossed is \
             unknown rather than nothing: {}</p>",
            esc(&detail)
        )),
        Transcript::Present { rows, bytes } => {
            if rows.is_empty() {
                out.push_str(
                    "<p>a complete account, and <strong>nothing crossed the network into this \
                     build</strong>. <span class=\"note\">Which is what it means either way, but \
                     not always what a reader wants to know: a run that died before its build phase \
                     never got as far as fetching anything, so check the phase it reached before \
                     reading this as a build that needed nothing.</span></p>",
                );
            } else {
                let total: u64 = rows.iter().map(|e| e.bytes).sum();
                let count =
                    |c: trigon_mirror::Checked| rows.iter().filter(|e| e.checked == c).count();
                let opened = count(trigon_mirror::Checked::Opened);
                let partial = count(trigon_mirror::Checked::Partial);
                let unarmed = count(trigon_mirror::Checked::Unarmed);
                out.push_str(&format!(
                    "<p><strong>{} response(s)</strong> crossed into this build, carrying {}. \
                     <a href=\"/run/{index}/network\">Every row →</a></p>",
                    rows.len(),
                    human_bytes(total),
                ));
                // Every figure with its denominator, because "12 opened" on its own reads as a
                // total rather than as a share.
                out.push_str(&format!(
                    "<p class=\"dim\">{opened} of {} opened and member-checked by the artifact \
                     guard</p>",
                    rows.len()
                ));
                if unarmed > 0 {
                    out.push_str(&format!(
                        "<p class=\"note\">{unarmed} of {} arrived with no guard manifest \
                         loaded, so nothing was compared against anything</p>",
                        rows.len()
                    ));
                }
                if partial > 0 {
                    out.push_str(&format!(
                        "<p class=\"note\">{partial} of {} were abandoned part-way, so their \
                         bytes crossed unchecked and their digest is of a prefix rather than of \
                         the resource</p>",
                        rows.len()
                    ));
                }
            }
            out.push_str(&format!(
                "<p class=\"dim\">source: <code>rebuild/network.jsonl</code>, {}</p>",
                human_bytes(bytes)
            ));
        }
    }
    out.push_str(&not_collected_note());
    out
}

/// Bytes, at the precision a page needs.
fn human_bytes(b: u64) -> String {
    match b {
        0..=1023 => format!("{b} B"),
        1024..=1_048_575 => format!("{:.1} KB", b as f64 / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.1} MB", b as f64 / 1_048_576.0),
        _ => format!("{:.2} GB", b as f64 / 1_073_741_824.0),
    }
}

/// Said on every run, including a clean one.
///
/// The transcript answers what the build *fetched*. A reader will reasonably expect it to answer
/// what the build *did*, and nothing here can: Tier 2 and Tier 3 observability are cut by decision,
/// not missing by accident. Rendering the gap as a blank would be this project's own bug —
/// absence read as presence — on the page that exists to prevent it.
fn not_collected_note() -> String {
    "<p class=\"note\"><strong>What ran inside the sandbox is not recorded.</strong> There is no \
     process tree, no syscall log and no record of which files the build opened. Trigon ships Tier 1 \
     observability — this transcript — and Tiers 2 and 3 are a deliberate cut, not an omission: \
     eBPF does not compose with gVisor, it breaks on managed Kubernetes, and it needs privilege the \
     sandbox otherwise refuses (<code>docs/08-execution.md</code> §7, ADR-0007). What stands in \
     their place is this list of everything that crossed the network, the per-phase timings, and \
     the build log.</p>"
        .into()
}

/// Every response the mirror served into one build, in the order it finished serving them.
///
/// The whole list rather than a sample. It is the evidence behind `attestable`, and a page that
/// showed the first twenty rows of it would be asking to be believed about the rest.
async fn network(
    State(sweep): State<std::sync::Arc<Sweep>>,
    UrlPath(index): UrlPath<usize>,
) -> Response {
    let v = sweep.read();
    let dir = sweep.target_dir(&v, index);
    let title = v
        .rows
        .iter()
        .find(|r| sweep.dir_of(&v, &r.purl).map(|(i, _)| i) == Some(index))
        .map(|r| esc(r.purl.strip_prefix("pkg:").unwrap_or(&r.purl)))
        .unwrap_or_else(|| format!("target {index:03}"));

    let mut body = format!(
        "<h1>{title} · network</h1><p><a href=\"/run/{index}\">← the run</a></p>{}",
        not_collected_note()
    );

    match read_transcript(&dir) {
        Transcript::Absent | Transcript::Unreadable(_) => {
            body.push_str(&network_panel(&dir, index));
        }
        Transcript::Present { rows, bytes } => {
            body.push_str(&format!(
                "<p class=\"dim\">{} row(s) · {} on disk · <code>rebuild/network.jsonl</code></p>",
                rows.len(),
                human_bytes(bytes)
            ));
            if rows.is_empty() {
                body.push_str(&network_panel(&dir, index));
            } else {
                // The pin evidence, recomputed here from the rows rather than copied from the
                // report. Two ways to compute one thing — and this is the side that can be checked,
                // because the reader is looking at the rows it was computed from.
                let o = trigon_mirror::Observed::from_transcript(&rows, 0);
                body.push_str(&format!(
                    "<p>recomputed from these rows: <strong>{}</strong> index request(s), \
                     <strong>{}</strong> version(s) withheld across them, {} artifact, {} \
                     toolchain. <span class=\"note\">Refusals are not in this file, so the \
                     rejected count is not recomputable here and is left out rather than shown as \
                     zero.</span></p>",
                    o.index_requests,
                    o.versions_withheld,
                    o.artifact_requests,
                    o.toolchain_requests
                ));
                body.push_str(
                    "<table><tr><th>#</th><th>route</th><th>checked</th><th>bytes</th>\
                     <th>withheld</th><th>sha256</th><th>url</th></tr>",
                );
                for (n, e) in rows.iter().enumerate() {
                    body.push_str(&format!(
                        "<tr><td class=\"dim\">{}</td><td>{}</td><td>{}</td>\
                         <td style=\"text-align:right\">{}</td><td style=\"text-align:right\">{}</td>\
                         <td><code>{}</code></td><td class=\"url\">{}</td></tr>",
                        n + 1,
                        esc(&e.route),
                        checked_cell(e.checked),
                        human_bytes(e.bytes),
                        // An em dash, never a digit. `None` means this was not a filtered index
                        // document at all, and `Some(0)` means the filter ran and removed nothing:
                        // rendering the first as `0` merges the two readings the field exists for.
                        match e.withheld {
                            Some(w) => w.to_string(),
                            None => "—".into(),
                        },
                        esc(&e.sha256[..16.min(e.sha256.len())]),
                        esc(&e.url),
                    ));
                }
                body.push_str("</table>");
            }
        }
    }
    page(&format!("{title} · network"), false, &body, &sweep.bind).into_response()
}

/// How far the guard got, in words rather than in an enum name.
fn checked_cell(c: trigon_mirror::Checked) -> &'static str {
    match c {
        trigon_mirror::Checked::Opened => "opened",
        trigon_mirror::Checked::Hashed => "<span class=\"dim\">hashed only</span>",
        trigon_mirror::Checked::Generated => "<span class=\"dim\">mirror-composed</span>",
        trigon_mirror::Checked::Unarmed => "<span class=\"note\">unarmed</span>",
        trigon_mirror::Checked::Partial => "<span class=\"void\">partial</span>",
    }
}

/// The one-line version, on the run page.
fn compare_panel(dir: &Path, index: usize) -> String {
    let Some((upstream, rebuild)) = artifact_pair(dir) else {
        return "<h2>What differs</h2><p class=\"note\">both artifacts are not on disk here, so \
                nothing can be re-derived. The verdict still stands — it was computed when they \
                were.</p>"
            .into();
    };
    match member_diffs(&upstream, &rebuild) {
        Err(detail) => format!(
            "<h2>What differs</h2><p class=\"void\">the artifacts could not both be re-derived: \
             {}</p>",
            esc(&detail)
        ),
        Ok((m, _)) => {
            let differs = m
                .iter()
                .filter(|d| !d.only_one_side() && d.content_differs())
                .count();
            let meta_only = m.iter().filter(|d| d.metadata_only()).count();
            let removed = m.iter().filter(|d| d.removed_by_stabilization()).count();
            format!(
                "<h2>What differs</h2><p>{} member(s): <strong>{differs}</strong> differ in \
                 content, <strong>{meta_only}</strong> are byte-identical and packed differently, \
                 <strong>{removed}</strong> were stabilized out. \
                 <a href=\"/run/{index}/compare\">The stabilizer ledger →</a></p>",
                m.len()
            )
        }
    }
}

/// The stabilizer ledger: every pass in the set, what it changed, and what it cost the verdict.
///
/// **Demoted from a verdict page.** This used to open with "what differs" and a census bar, which
/// made it a second, competing answer to the question the run page now answers with the digest
/// ladder — and a reader with two verdict pages has to work out which one to believe. The ladder is
/// the verdict. This is the audit: which of the set's passes fired, at what risk and under whose
/// provenance, what each one moved, and which of them hold the outcome below `normalized` however
/// well the bytes agree.
///
/// Two things reach a reader here that reached one nowhere before:
///
/// - **Provenance.** `Applied` has carried it since the type existed and no page had ever printed
///   it. It is half the cap rule — a `Metadata`-risk pass a model wrote caps the verdict exactly as
///   firmly as a `Content`-risk builtin — and a ledger that showed risk alone was showing half a
///   reason and reading as a whole one.
/// - **The passes that did nothing.** `apply` returns only what fired, so a set member that found
///   nothing to do was indistinguishable from one that was never configured. Those are different
///   facts: `nupkg-signature` finding no signature to strip is evidence about the package.
async fn compare(
    State(sweep): State<std::sync::Arc<Sweep>>,
    UrlPath(index): UrlPath<usize>,
) -> Response {
    let v = sweep.read();
    let dir = sweep.target_dir(&v, index);
    let title = v
        .rows
        .iter()
        .find(|r| sweep.dir_of(&v, &r.purl).map(|(i, _)| i) == Some(index))
        .map(|r| esc(r.purl.strip_prefix("pkg:").unwrap_or(&r.purl)))
        .unwrap_or_else(|| format!("target {index:03}"));

    let mut body = format!(
        "<h1>{title} · the stabilizer ledger</h1><p><a href=\"/run/{index}\">← the run, where the \
         verdict is</a></p>"
    );

    let Some((upstream, rebuild)) = artifact_pair(&dir) else {
        body.push_str(
            "<p class=\"note\">both artifacts are not on disk here, so there is nothing to \
             re-derive. A run keeps the published artifact at the work root and the rebuilt one \
             under <code>rebuild/&lt;run id&gt;/</code>; a build that produced nothing, or a work \
             directory that has been cleaned, leaves this page with no inputs. The verdict in the \
             run record still stands — it was computed when both were there.</p>",
        );
        return page(&format!("{title} · compare"), false, &body, &sweep.bind).into_response();
    };

    body.push_str(&format!(
        "<p class=\"dim\">recomputed now from <code>{}</code> and <code>{}</code>, not read from a \
         record. This is the judgement half — pure, model-free, no network — so the page can redo \
         it, and you are looking at the bytes it was computed from.</p>",
        esc(&file_name_of(&upstream)),
        esc(&file_name_of(&rebuild)),
    ));

    match member_diffs(&upstream, &rebuild) {
        Err(detail) => body.push_str(&format!(
            "<p class=\"void\">the two artifacts could not both be re-derived, so this page has \
             nothing to show rather than nothing to report: {}</p>",
            esc(&detail)
        )),
        Ok((members, applied)) => {
            let outcome = read_report(&dir).and_then(|r| r.outcome);
            body.push_str(&ceiling_panel(&applied, outcome.as_deref()));
            body.push_str(&ledger_table(&applied));
            body.push_str(&silent_panel(&upstream, &applied));
            body.push_str(&ladder_svg(&members));
            body.push_str(&member_table(&members));
        }
    }
    page(&format!("{title} · stabilizers"), false, &body, &sweep.bind).into_response()
}

/// The best verdict this set of passes could reach, and what holds it there.
///
/// The question a reader of a `divergent` run actually has, and one no page has answered: *if the
/// remaining differences went away, what would this get?* For a crate, never `normalized` —
/// `cargo-vcs-hash` fires at `Content` risk on every crates.io artifact there has ever been, so a
/// perfect crate rebuild is `normalized_with_caveats` and the caveat is structural rather than
/// anything about that package.
///
/// The ceiling is asked of `trigon-compare`, not computed here. The cap rule has one home by
/// ADR-0008, and a page re-deriving it would be a second implementation that agrees until it
/// doesn't — the defect this file has now been bitten by twice.
fn ceiling_panel(applied: &[trigon_stabilize::Applied], outcome: Option<&str>) -> String {
    let ceiling = trigon_compare::ceiling(applied);
    let holders: Vec<&trigon_stabilize::Applied> = applied
        .iter()
        .filter(|a| trigon_compare::caps_normalized(a))
        .collect();

    // `exact` is decided on raw bytes before a pass runs, so no ledger can put a ceiling on it.
    let reached = match outcome {
        Some("exact") => {
            return "<h2>The ceiling</h2><p>This run matched on the published bytes themselves,                     before a single pass ran. No ledger below can raise or lower that: a stabilizer                     set only matters once the raw digests disagree.</p>"
                .to_string();
        }
        Some(o) => o,
        None => "unknown",
    };

    if holders.is_empty() {
        return format!(
            "<h2>The ceiling</h2><p>Every pass that fired is <code>Builtin</code> at              <code>Metadata</code> risk or below, so nothing in this set holds the verdict down.              Were the stabilized digests to agree, this run would read <strong>normalized</strong>              — a clean match, no caveat. It read <strong>{}</strong>.</p>",
            esc(reached)
        );
    }

    let mut rows = String::new();
    for a in &holders {
        // Which half of the rule this row trips. Both can be true, and saying only one of them
        // would be the same half-reason the ledger used to give.
        let why = match (
            a.provenance != trigon_core::Provenance::Builtin,
            a.risk > trigon_core::RiskTier::Metadata,
        ) {
            (true, true) => format!(
                "{:?} provenance, and {:?} risk is above Metadata",
                a.provenance, a.risk
            ),
            (true, false) => format!("{:?} provenance — not Builtin", a.provenance),
            (false, true) => format!("{:?} risk is above Metadata", a.risk),
            (false, false) => {
                unreachable!("caps_normalized said this row caps and neither half does")
            }
        };
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td></tr>",
            esc(a.id.as_str()),
            esc(&why)
        ));
    }

    format!(
        "<h2>The ceiling</h2>         <p>This run can reach <strong>{ceiling}</strong> and no higher, whatever the bytes do.          It read <strong>{}</strong>.</p>         <table><tr><th>pass</th><th>why it caps</th></tr>{rows}</table>         <p class=\"note\">A cap is not a complaint about the package. It says the tool got there          using something it will not vouch for unconditionally — a pass that rewrites content, or          one a model or a person wrote rather than one compiled in. Both halves of that rule weigh          the same: a <code>Metadata</code>-risk pass a model proposed caps the verdict exactly as          firmly as a <code>Content</code>-risk builtin.</p>",
        esc(reached)
    )
}

/// Which passes did the work, how much, and under whose authority.
///
/// Bar length is `entries_touched`, which `docs/08` calls the triage number: "wheel-record touched
/// 412 entries" is a diagnosis. Risk is the colour. Provenance is a column, and it is new — the
/// field has existed as long as `Applied` has and no page had ever rendered it.
fn ledger_table(applied: &[trigon_stabilize::Applied]) -> String {
    if applied.is_empty() {
        return "<h2>The ledger</h2><p class=\"note\">no pass changed anything on either side, so                 the two artifacts were compared exactly as published. The verdict, whatever it is,                 is about the bytes and owes nothing to normalization.</p>"
            .into();
    }
    // Both sides fire the same set, so the same id appears twice. Summed rather than listed twice:
    // a reader wants "tar-time touched 20 entries across the pair", not two rows of 10.
    let mut by_id: std::collections::BTreeMap<
        String,
        (
            u32,
            u64,
            trigon_core::RiskTier,
            trigon_core::Provenance,
            bool,
        ),
    > = Default::default();
    for a in applied {
        let e = by_id.entry(a.id.to_string()).or_insert((
            0,
            0,
            a.risk,
            a.provenance.clone(),
            trigon_compare::caps_normalized(a),
        ));
        e.0 += a.entries_touched;
        e.1 += a.bytes_changed;
    }
    let max = by_id.values().map(|v| v.0).max().unwrap_or(1).max(1) as f64;
    let mut rows = String::new();
    for (id, (touched, bytes, risk, provenance, caps)) in &by_id {
        let w = 420.0 * (*touched as f64 / max);
        let fill = match risk {
            trigon_core::RiskTier::Structural => "#6b6b66",
            trigon_core::RiskTier::Metadata => "#137333",
            trigon_core::RiskTier::Content => "#b26a00",
            trigon_core::RiskTier::Lossy => "#b3261e",
        };
        // The provenance a reader needs is "who stands behind this", so a `Model` row names the
        // model and a `Human` row names the reviewer rather than both reading as "not builtin".
        let who = match provenance {
            trigon_core::Provenance::Builtin => "<span class=\"dim\">builtin</span>".to_string(),
            trigon_core::Provenance::Human { reviewer } => {
                format!("<span class=\"diff\">reviewed by {}</span>", esc(reviewer))
            }
            trigon_core::Provenance::Model { model_id, .. } => {
                format!("<span class=\"diff\">proposed by {}</span>", esc(model_id))
            }
        };
        let mark = if *caps {
            " <span class=\"diff\">caps</span>"
        } else {
            ""
        };
        rows.push_str(&format!(
            "<tr><td><code>{}</code>{mark}</td><td class=\"n\">{touched}</td>\
             <td style=\"width:100%\"><svg viewBox=\"0 0 420 12\" width=\"{:.0}\" height=\"12\" \
             preserveAspectRatio=\"none\" role=\"img\" aria-label=\"{touched} entries\">\
             <rect x=\"0\" y=\"0\" width=\"420\" height=\"12\" fill=\"{fill}\"/></svg></td>\
             <td class=\"dim\">{:?}</td><td>{who}</td><td class=\"n dim\">{}</td></tr>",
            esc(id),
            w.max(2.0),
            risk,
            human_bytes(*bytes),
        ));
    }
    format!(
        "<h2>The ledger</h2>         <table><tr><th>pass</th><th class=\"n\">entries</th><th></th><th>risk</th>\
         <th>provenance</th><th class=\"n\">bytes</th></tr>{rows}</table>         <p class=\"note\">Summed across both sides, which fire the same set. A row marked \
         <span class=\"diff\">caps</span> is one of the rows in the ceiling above.</p>"
    )
}

/// The passes that were in the set and found nothing to do.
///
/// `apply` returns only what fired, which left a set member that found nothing indistinguishable
/// from one that was never configured — and those are different facts. `nupkg-signature` finding no
/// signature to strip is a statement about the package: it was not signed. A reader who cannot see
/// the silent rows cannot tell "this set has no signature pass" from "this set has one and the
/// package had no signature", and only the second is evidence.
fn silent_panel(artifact: &Path, applied: &[trigon_stabilize::Applied]) -> String {
    let Some(format) = trigon_core::Format::from_file_name(
        &artifact.file_name().unwrap_or_default().to_string_lossy(),
    ) else {
        return String::new();
    };
    let set = run_profile(artifact, format);
    let fired: std::collections::BTreeSet<String> =
        applied.iter().map(|a| a.id.to_string()).collect();
    let silent: Vec<String> = set
        .members
        .iter()
        .map(|m| m.id().to_string())
        .filter(|id| !fired.contains(id))
        .collect();

    if silent.is_empty() {
        return format!(
            "<h2>What stayed silent</h2><p class=\"note\">nothing. Every one of the \
             <code>{}</code> set's {} passes found something to do on this pair.</p>",
            esc(set.id.as_str()),
            set.members.len()
        );
    }
    format!(
        "<h2>What stayed silent</h2>         <p>{} of the <code>{}</code> set's {} passes ran and found nothing to change:</p>         <p class=\"legend\">{}</p>         <p class=\"note\">Listed because silence is evidence. A signature pass with nothing to \
         strip means the package carried no signature; a timestamp pass with nothing to flatten \
         means the archive already held none. Neither fact is visible from the ledger above, which \
         by construction holds only the passes that moved something.</p>",
        silent.len(),
        esc(set.id.as_str()),
        set.members.len(),
        silent
            .iter()
            .map(|id| format!("<code>{}</code>", esc(id)))
            .collect::<Vec<_>>()
            .join(" · "),
    )
}

/// The census, as a picture: what the two archives hold, and where the difference went.
///
/// One bar, four bands, in the order a reader needs them — the members that differ *after*
/// stabilization first, because those are the finding, then the ones stabilization accounted for,
/// then the ones that were identical all along, then the ones present on one side only.
fn ladder_svg(m: &[MemberDiff]) -> String {
    let total = m.len().max(1) as f64;
    let one_side = m.iter().filter(|d| d.only_one_side()).count();
    let differs = m
        .iter()
        .filter(|d| !d.only_one_side() && d.content_differs())
        .count();
    let meta_only = m.iter().filter(|d| d.metadata_only()).count();
    let removed = m.iter().filter(|d| d.removed_by_stabilization()).count();
    let identical = m.len() - one_side - differs - meta_only - removed;

    // `(count, label, fill)`. The colours are the verdict palette the rest of the page uses, so a
    // red band here and a red tag above it mean the same thing.
    let bands = [
        (differs, "content differs", "#b3261e"),
        (meta_only, "same bytes, packed differently", "#8a6d1f"),
        (removed, "stabilized out", "#b26a00"),
        (identical, "identical as published", "#137333"),
        (one_side, "on one side only", "#6b4fbb"),
    ];

    let w = 720.0;
    let mut x = 0.0;
    let mut rects = String::new();
    let mut legend = String::new();
    for (n, label, fill) in bands {
        if n == 0 {
            // A band of zero width is not drawn, and it is not listed either — a legend entry
            // pointing at nothing invites the reader to look for it.
            continue;
        }
        let bw = w * (n as f64 / total);
        rects.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"0\" width=\"{bw:.1}\" height=\"26\" fill=\"{fill}\"/>"
        ));
        legend.push_str(&format!(
            "<span class=\"key\"><i style=\"background:{fill}\"></i>{n} {label}</span>"
        ));
        x += bw;
    }

    format!(
        "<h2>Which members the passes account for</h2>\
         <svg viewBox=\"0 0 {w} 26\" width=\"100%\" height=\"26\" role=\"img\" \
          aria-label=\"{} members: {differs} differ in content, {meta_only} same bytes packed \
          differently, {removed} stabilized out, {identical} identical, {one_side} on one side \
          only\" preserveAspectRatio=\"none\">{rects}</svg>\
         <p class=\"legend\">{legend}</p>\
         <p class=\"note\">{} member(s) in total. <strong>Stabilized out</strong> is the band the \
         verdict turns on: those members' published and rebuilt bytes are not the same, and every \
         way in which they differ was removed by one of the passes in the ledger above. \
         <strong>Same bytes, packed differently</strong> is the one worth reading twice — the file \
         is byte-for-byte what was published and its archive entry is not, so the divergence is \
         about how it was packed and not about what anybody wrote.</p>",
        m.len(),
        m.len()
    )
}

/// Every member, with the two comparisons side by side.
fn member_table(m: &[MemberDiff]) -> String {
    // Most interesting first: a hundred identical members must not bury the four that differ.
    let mut rows: Vec<&MemberDiff> = m.iter().collect();
    rows.sort_by_key(|d| {
        (
            !d.content_differs(),
            !d.only_one_side(),
            !d.metadata_only(),
            !d.removed_by_stabilization(),
            d.path.clone(),
        )
    });
    let mut out = String::from(
        "<h2>Every member</h2><table><tr><th>member</th><th>as published</th>\
         <th>stabilized</th><th class=\"n\">upstream</th><th class=\"n\">rebuild</th></tr>",
    );
    for d in rows {
        let (raw_cell, stab_cell) = if d.only_one_side() {
            let which = if d.raw.0.is_some() {
                "upstream"
            } else {
                "rebuild"
            };
            (
                format!("<span class=\"ours\">only in {which}</span>"),
                "<span class=\"ours\">—</span>".to_string(),
            )
        } else if d.content_differs() {
            (
                "<span class=\"fail\">differs</span>".to_string(),
                "<span class=\"fail\">content still differs</span>".to_string(),
            )
        } else if d.metadata_only() {
            (
                "<span class=\"diff\">differs</span>".to_string(),
                "<span class=\"diff\">same bytes, packed differently</span>".to_string(),
            )
        } else if d.removed_by_stabilization() {
            (
                "<span class=\"diff\">differs</span>".to_string(),
                "<span class=\"ok\">equal — stabilized out</span>".to_string(),
            )
        } else {
            (
                "<span class=\"ok\">identical</span>".to_string(),
                "<span class=\"ok\">identical</span>".to_string(),
            )
        };
        let b = |v: Option<u64>| match v {
            Some(n) => human_bytes(n),
            // Absent, not zero: the member is not on that side at all.
            None => "—".to_string(),
        };
        out.push_str(&format!(
            "<tr><td class=\"url\"><code>{}</code></td><td>{raw_cell}</td><td>{stab_cell}</td>\
             <td class=\"n dim\">{}</td><td class=\"n dim\">{}</td></tr>",
            esc(&d.path),
            b(d.bytes.0),
            b(d.bytes.1),
        ));
    }
    out.push_str("</table>");
    out
}

fn file_name_of(p: &Path) -> String {
    p.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// The two artifacts a run compared, where both are still on disk.
///
/// The published one keeps the registry's filename at the work root; the rebuilt one sits under
/// `rebuild/<run id>/`. Either can be absent — a pruned store keeps only digests on a match, and a
/// failed build produced nothing — and absent is said rather than rendered as an empty comparison.
fn artifact_pair(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let is_artifact = |p: &Path| {
        p.is_file()
            && p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| !crate::build::OURS.contains(&n))
                .unwrap_or(false)
    };
    let upstream = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            is_artifact(p)
                && trigon_core::Format::from_file_name(
                    &p.file_name().unwrap_or_default().to_string_lossy(),
                )
                .is_some()
        })?;
    // The build writes into `rebuild/<run id>/`, one level below where the log and the transcript
    // sit, which is why `collect` finds exactly one file there and this walk does too.
    let rebuild = std::fs::read_dir(dir.join("rebuild"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
        .map(|e| e.path())
        .find(|p| is_artifact(p))?;
    Some((upstream, rebuild))
}

/// One side's members, keyed by `(path, occurrence)`, each as `(raw fingerprint, stabilized
/// fingerprint, size)`. The occurrence is in the key because a duplicate member path is legal and
/// would otherwise be unmatchable — the rule `diff.rs` keys on.
type MemberKey = (Vec<u8>, usize);
/// `(raw content, raw metadata, stabilized content, stabilized metadata, size)`.
type Fingerprints = (String, String, String, String, u64);
type SideMembers = std::collections::BTreeMap<MemberKey, Fingerprints>;

/// One member of the artifact, before and after stabilization, on both sides.
struct MemberDiff {
    path: String,
    /// `None` where the member is on one side only.
    raw: (Option<String>, Option<String>),
    stabilized: (Option<String>, Option<String>),
    /// The member's **content** after stabilization, ignoring every header field.
    ///
    /// Separate from `stabilized` because the two answer different questions and a reader needs
    /// both. `py-cpuinfo` has six members whose bytes are identical and whose zip modes are not:
    /// the archive digests differ, so the verdict is `divergent` and correctly so, but reporting
    /// those six as "still differs" reads as "the code changed" — which it did not. Overstating a
    /// divergence is the expensive direction, because a published one is a public claim about
    /// somebody else's package.
    content: (Option<String>, Option<String>),
    bytes: (Option<u64>, Option<u64>),
}

impl MemberDiff {
    fn raw_differs(&self) -> bool {
        self.raw.0 != self.raw.1
    }
    fn stabilized_differs(&self) -> bool {
        self.stabilized.0 != self.stabilized.1
    }
    fn content_differs(&self) -> bool {
        self.content.0 != self.content.1
    }
    /// Byte-for-byte the same file, in an archive entry that is not. The diagnosis a maintainer
    /// wants: nothing you wrote changed, and something about how it was packed did.
    fn metadata_only(&self) -> bool {
        self.stabilized_differs() && !self.content_differs() && !self.only_one_side()
    }
    /// The interesting case, and the one the whole tool exists for: the bytes differ and the
    /// stabilized forms do not. This member is why the verdict is `normalized` rather than `exact`.
    fn removed_by_stabilization(&self) -> bool {
        self.raw_differs() && !self.stabilized_differs()
    }
    fn only_one_side(&self) -> bool {
        self.raw.0.is_none() || self.raw.1.is_none()
    }
}

/// Diff both artifacts member by member, **twice**: as published, then as stabilized.
///
/// `DiffReport` walks the stabilized archives, which is the right input for a verdict and the wrong
/// one for the question a reader actually has — *what was different, and what stopped it
/// mattering?* A member that differs raw and agrees stabilized is the whole argument of the tool,
/// and nothing anywhere showed one.
///
/// Recomputed here from the two files rather than read from a record. That is affordable because
/// this is the judgement half: pure, model-free, no network. It is also the honest way round — the
/// reader is looking at the bytes it was computed from.
fn member_diffs(
    upstream: &Path,
    rebuild: &Path,
) -> Result<(Vec<MemberDiff>, Vec<trigon_stabilize::Applied>), String> {
    let format = trigon_core::Format::from_file_name(
        &upstream.file_name().unwrap_or_default().to_string_lossy(),
    )
    .ok_or_else(|| {
        "the upstream artifact's name names no format this build can parse".to_string()
    })?;
    // The run's own selection, not the format's default. See `run_profile`.
    let set = run_profile(upstream, format);
    let limits = trigon_archive::Limits::default();

    // `BTreeMap<(path, occurrence), digest>` on each side, at each of the two moments. Keyed on the
    // occurrence as well as the path because a duplicate member path is legal and would otherwise
    // be unmatchable — the same rule `diff.rs` keys on.
    let side = |p: &Path| -> Result<(SideMembers, Vec<trigon_stabilize::Applied>), String> {
        let bytes = std::fs::read(p).map_err(|e| format!("reading {}: {e}", p.display()))?;
        let mut notes = Vec::new();
        let parsed = trigon_archive::parse(bytes, format, &limits, &mut notes)
            .map_err(|e| format!("parsing {}: {e}", p.display()))?;
        let mut archive = parsed.archive;

        let mut seen: std::collections::BTreeMap<Vec<u8>, usize> = Default::default();
        let mut raw: Vec<(MemberKey, (String, String, u64))> = Vec::new();
        for e in &archive.entries {
            let path = e.path.as_bytes().to_vec();
            let n = seen.entry(path.clone()).or_default();
            let key = (path, *n);
            *n += 1;
            let (c, m) = member_fingerprint(e)?;
            raw.push((key, (c, m, e.meta.size)));
        }

        let applied = trigon_stabilize::apply(&set, &mut archive);

        let mut seen: std::collections::BTreeMap<Vec<u8>, usize> = Default::default();
        let mut out = std::collections::BTreeMap::new();
        for (i, e) in archive.entries.iter().enumerate() {
            let path = e.path.as_bytes().to_vec();
            let n = seen.entry(path.clone()).or_default();
            let key = (path, *n);
            *n += 1;
            let (after_c, after_m) = member_fingerprint(e)?;
            // Stabilizers may reorder, so the raw entry for this key is looked up rather than
            // taken positionally. A member that a pass *removed* has a raw row and no stabilized
            // one, which the join below renders rather than dropping.
            let (raw_c, raw_m, size) = raw
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| (after_c.clone(), after_m.clone(), e.meta.size));
            let _ = i;
            out.insert(key, (raw_c, raw_m, after_c, after_m, size));
        }
        Ok((out, applied))
    };

    let (u, ua) = side(upstream)?;
    let (r, ra) = side(rebuild)?;

    let mut keys: Vec<_> = u.keys().chain(r.keys()).cloned().collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    for k in keys {
        let a = u.get(&k);
        let b = r.get(&k);
        out.push(MemberDiff {
            path: String::from_utf8_lossy(&k.0).into_owned(),
            raw: (
                a.map(|v| format!("{}{}", v.0, v.1)),
                b.map(|v| format!("{}{}", v.0, v.1)),
            ),
            stabilized: (
                a.map(|v| format!("{}{}", v.2, v.3)),
                b.map(|v| format!("{}{}", v.2, v.3)),
            ),
            content: (a.map(|v| v.2.clone()), b.map(|v| v.2.clone())),
            bytes: (a.map(|v| v.4), b.map(|v| v.4)),
        });
    }
    let mut applied = ua;
    applied.extend(ra);
    Ok((out, applied))
}

/// One member's identity: its content **and** the metadata a stabilizer can change.
///
/// Body bytes alone are the wrong fingerprint, and being wrong the wrong way round: for npm they
/// are almost always identical, so the page reported "0 stabilized out" on a `normalized` verdict
/// whose every difference was an mtime, a mode or a member order. What differs between a tarball
/// published in 2018 and one built this morning is exactly the fields this hashes.
///
/// **`ordinal` is deliberately out.** It is the member's position *as parsed*, kept as a sort
/// tiebreaker and never rewritten — so it survives the very reordering `tar-entry-order` and
/// `zip-entry-order` exist to normalize. Including it made every member of a reordered archive
/// differ forever: `py-cpuinfo` read as nine of nine still differing where the comparison that
/// decides the verdict says three. Overstating a divergence is the expensive direction, because a
/// published divergence is a public claim about somebody's package. Member order is a property of
/// the archive rather than of a member, and it is already visible in the applied-stabilizer list.
///
/// `size` is out too, being a function of the body.
fn member_fingerprint(e: &trigon_archive::Entry) -> Result<(String, String), String> {
    use sha2::Digest as _;
    let body = e.stabilized_bytes().map_err(|e| e.to_string())?;
    let content = format!("{:x}", sha2::Sha256::digest(&body));

    let mut h = sha2::Sha256::new();
    h.update(e.path.as_bytes());
    h.update([0]);
    h.update(e.meta.mode.to_le_bytes());
    // `None` is its own value rather than a zero: a format that carries no mtime and one that
    // carries the epoch are different things, and collapsing them would hide `tar-time`'s work.
    match e.meta.mtime {
        Some(t) => {
            h.update([1]);
            h.update(t.to_le_bytes());
        }
        None => h.update([0]),
    }
    h.update(format!("{:?}", e.kind).as_bytes());
    // The format-specific header — owners, typeflag, zip method and flags — in its `Debug` form.
    // Structural rather than pretty, and it is only ever compared against itself.
    h.update(format!("{:?}", e.raw).as_bytes());
    Ok((content, format!("{:x}", h.finalize())))
}

#[allow(dead_code)]
fn digest_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(b))
}

fn read_log(dir: &Path) -> Option<String> {
    // `<target dir>/rebuild/build.log`, which is where `run_one` writes it: the collect directory
    // is `args.work.join("rebuild")` and the log goes beside the artifacts in it. The target
    // directory comes from `Sweep::target_dir` rather than being rebuilt here, so a layout whose
    // answer is not `{index:03}` does not have to be taught to two places.
    std::fs::read_to_string(dir.join("rebuild").join("build.log")).ok()
}

async fn run(
    State(sweep): State<std::sync::Arc<Sweep>>,
    UrlPath(index): UrlPath<usize>,
) -> Response {
    let v = sweep.read();
    // The only path parameter anywhere, parsed as an integer by the extractor and re-formatted
    // before it is joined to anything, so no request string reaches the filesystem.
    let dir = sweep.target_dir(&v, index);
    // Under `Index` the row and the directory are one position, and the round trip through `purl`
    // would be ambiguous the moment two directories hold runs of the same target.
    let row = match v.layout {
        Layout::Index => v.rows.get(index),
        _ => v
            .rows
            .iter()
            .find(|r| sweep.dir_of(&v, &r.purl).map(|(i, _)| i) == Some(index)),
    };
    let report = read_report(&dir);

    // The target where one is known, the directory's own name where it is not, and the number only
    // when neither is true.
    let name = match row.filter(|r| !r.purl.is_empty()) {
        Some(r) => r.purl.strip_prefix("pkg:").unwrap_or(&r.purl).to_string(),
        None => match v.entries.get(index) {
            Some(e) => e.name.clone(),
            None => format!("target {index:03}"),
        },
    };

    let mut body = format!(
        "<h1>{}</h1>{}",
        esc(&name),
        state_strip(&v, sweep.targets.as_deref()),
    );

    match row {
        Some(r) => {
            let fam = Family::of(&r.label);
            // A run with no report has no clock either, and its synthetic row carries a `0.0` that
            // is a placeholder rather than a measurement. Printing it would be this page's own
            // first rule broken on the one row that exists because something is missing.
            let duration = match (v.layout, &report) {
                (Layout::Index, None) => {
                    " · <span class=\"note\">no duration recorded</span>".to_string()
                }
                _ => format!(" · {:.0}s", r.seconds),
            };
            body.push_str(&format!(
                "<p><span class=\"tag {}\">{}</span>{duration}{}</p>",
                fam.css(),
                esc(&r.label),
                match &r.cluster {
                    Some(c) => format!(
                        " · cluster <a href=\"/cluster?key={}\"><code>{}</code></a>",
                        esc(&urlencode(c)),
                        esc(c)
                    ),
                    None => String::new(),
                }
            ));
        }
        None => body.push_str(&match v.layout {
            Layout::Index => format!(
                "<p class=\"note\">this directory holds {} run(s), numbered 0 to {}, and no run \
                 {index}</p>",
                v.entries.len(),
                v.entries.len().saturating_sub(1),
            ),
            _ => "<p class=\"note\">no row in results.tsv maps to this directory — it may be the \
                  target in flight, whose outcome is unknown rather than failed</p>"
                .to_string(),
        }),
    }

    // The whole derivation on one line, directly under the verdict: commit, strategy, build,
    // artifact, the stabilizer set, the outcome. Before the sentence rather than after, because a
    // reader who has just been told a package diverged asks "from what?" first.
    // **Parsed and compared once for the whole page.** Three panels want it — the ribbon, the
    // ladder and the notes — and each parsing both artifacts for itself would triple the cost of
    // the one request that is already the expensive one.
    let recomputed = recompare(&dir);
    if let Some(r) = &report {
        body.push_str(&chain_ribbon(r, recomputed.as_ref()));
    }

    // The sentence, before any panel. Everything below it is the evidence for it.
    match (&report, v.layout) {
        (Some(r), _) => body.push_str(&verdict_sentence(r)),
        // The one row that exists *because* something is missing. Without this it was a bare tag
        // over eight panels of absence, which is the shape this whole stage is about.
        (None, Layout::Index) => body.push_str(
            "<p><strong>This run left no report.</strong> The rebuild is still going, or it ended \
             before it could write one — either way nothing here is a finding about the package, \
             and the directory's name is not a record of which target it holds.</p>",
        ),
        (None, _) => {}
    }

    // Each absent fact is named, together with what would have to change for it to exist. An empty
    // panel that says nothing reads as a run that produced nothing.
    for (name, path, missing) in [
        (
            "Strategy",
            dir.join("strategy.yaml"),
            "no strategy.yaml — the ladder produced no recipe, or this target was never attempted",
        ),
        (
            "Artifact guard",
            dir.join("guard.json"),
            "no guard.json — the guard manifest is written only where a mirror is enforced",
        ),
    ] {
        body.push_str(&format!("<h2>{name}</h2>"));
        match std::fs::read_to_string(&path) {
            Ok(text) => body.push_str(&format!("<pre>{}</pre>", esc(&clip(&text, 8000)))),
            Err(_) => body.push_str(&format!("<p class=\"note\">{missing}</p>")),
        }
    }

    // The centrepiece, linked from the verdict rather than buried: a reader who has just been
    // told a package diverged wants to know which of its files anybody wrote.
    body.push_str(&format!(
        "<p><a href=\"/run/{index}/source\"><strong>how the source became this artifact →</strong></a></p>"
    ));
    // The ladder says why the verdict is what it is; the notes say what was observed on the way.
    // Both are derived from the bytes on disk rather than from a stored record, so a run without
    // `--store` still has them.
    if let Some(cmp) = &recomputed {
        body.push_str(&digest_ladder(cmp));
    }
    body.push_str(&compare_panel(&dir, index));
    if let Some(cmp) = &recomputed {
        body.push_str(&notes_panel(cmp));
    }
    body.push_str(&network_panel(&dir, index));

    body.push_str("<h2>Build log</h2>");
    match read_log(&dir) {
        Some(log) => {
            let sig = trigon_core::classify(&log);
            body.push_str(&format!(
                "<p>classified now as <code>{}</code>{} · <span class=\"dim\">{:?}, {}, {}</span></p>",
                esc(&sig.code),
                match &sig.subject {
                    Some(s) => format!(" <code>{}</code>", esc(s)),
                    None => String::new(),
                },
                sig.fault,
                if sig.retryable { "retryable" } else { "not retryable" },
                if sig.repairable { "repairable" } else { "nothing to repair" },
            ));
            body.push_str(
                "<p class=\"note\">classified from the log on disk under today's rule table, not \
                 recorded at the time — docs/18 step 5 writes failure.json so the two cannot \
                 disagree</p>",
            );
            body.push_str(&format!("<pre>{}</pre>", esc(&tail(&log, 12_000))));
        }
        None => body.push_str(
            "<p class=\"note\">no build.log on disk — the run never reached a build, or this row \
             was resumed from a sweep whose work directory is gone</p>",
        ),
    }

    body.push_str(&report_panel(report.as_ref()));
    if let (Some(store), Some(r)) = (&sweep.store, row) {
        body.push_str(&store_panel(store, &r.purl).await);
    } else if sweep.store.is_none() {
        body.push_str(
            "<h2>Run record</h2><p class=\"note\">no store was configured for this watch — pass \
             <code>--store</code> to show the digest chain and the stabilizers that fired</p>",
        );
    }
    body.push_str("<p><a href=\"/\">← all targets</a></p>");

    page(
        &sweep.tab_title(Some(&name)),
        v.live.is_live(),
        &body,
        &sweep.bind,
    )
    .into_response()
}

/// The run's own report, wherever this layout keeps it.
fn read_report(dir: &Path) -> Option<crate::progress::RunReport> {
    serde_json::from_str(&std::fs::read_to_string(dir.join("run.json")).ok()?).ok()
}

/// The one sentence that says what happened, directly under the verdict.
///
/// **Every fact in it was already on disk and none of them were on the page.** `declines` had no
/// reader anywhere in this file; `error` and `void_reason` were rows in a table eight panels down,
/// below the build log. `work/pkg-npm-semver@3.0.1` is the case that makes it plain — a
/// `no-strategy` whose `run.json` carries the exact reason the npm rung refused, under a page that
/// rendered eight panels of absence and never said it.
///
/// Precedence is the order in which one answer makes the rest beside the point: an error of ours
/// means the run never reached a verdict; a void means it reached one that may not be counted; a
/// decline means there was no recipe to try; otherwise the outcome, in words.
fn verdict_sentence(r: &crate::progress::RunReport) -> String {
    if let Some(e) = &r.error {
        return format!(
            "<p><strong>The run stopped on an error of ours.</strong> {}<br>\
             <span class=\"note\">nothing below is a finding about the package</span></p>",
            esc(e)
        );
    }
    if let Some(v) = &r.void_reason {
        return format!(
            "<p><strong>This run is evidence of nothing.</strong> {}<br>\
             <span class=\"note\">a void is not a failure — it is a run whose result may not be \
             counted in either direction</span></p>",
            esc(v)
        );
    }
    if !r.declines.is_empty() {
        let mut out = String::from(
            "<p><strong>No rung produced a recipe.</strong> Each one that was asked said why:</p>\
             <ul>",
        );
        for d in &r.declines {
            out.push_str(&format!("<li>{}</li>", esc(d)));
        }
        out.push_str("</ul>");
        return out;
    }

    let label = r.outcome.as_deref().unwrap_or("");
    let words = if label.is_empty() {
        "The run recorded no outcome. It ended before it reached one, and nothing it wrote says \
         what stopped it."
    } else {
        match label.parse::<trigon_core::Match>() {
            Ok(trigon_core::Match::Exact) => {
                "The rebuilt artifact is byte for byte the published one. Nothing had to be \
                 normalized away."
            }
            Ok(trigon_core::Match::Normalized) => {
                "The rebuilt artifact matched the published one after normalization, and every \
                 pass that fired was a built-in one at metadata risk or below."
            }
            // The distinction the verdict exists to carry, and the one a reader skims past: a
            // caveated match is a match a pass could have manufactured.
            Ok(trigon_core::Match::NormalizedWithCaveats) => {
                "The rebuilt artifact matched the published one only after a pass that can hide a \
                 real difference. Read the stabilizer ledger below before calling this reproduced."
            }
            Ok(trigon_core::Match::Divergent) => {
                "The rebuilt artifact is not the published one. What differs is below, member by \
                 member."
            }
            Err(_) => match Family::of(label) {
                Family::BuildFailed => {
                    "The build ran and failed. That is a finding about the package or about the \
                     recipe, and the log below says which."
                }
                Family::NoStrategy => {
                    "Nothing on the ladder produced a recipe, and no rung recorded why — this run \
                     is older than the declines it would have written."
                }
                Family::Void => {
                    "This run is evidence of nothing, and did not record why it was voided."
                }
                // The fault is the half of the label that matters here: `docs`' own division is
                // that one of these is ours and the other is the registry's, and neither is the
                // package's.
                _ => match label.split(':').nth(1) {
                    Some("upstream") => {
                        "The registry or the network stopped this run before it reached a verdict. \
                         Not a finding about the package."
                    }
                    _ => {
                        "Our own infrastructure stopped this run before it reached a verdict. Not \
                         a finding about the package."
                    }
                },
            },
        }
    };

    // Pointed at rather than repeated: an assumption is long, and a verdict read without knowing
    // one was made is the failure mode this exists for.
    let assumed = match r.assumptions.len() {
        0 => String::new(),
        n => format!(
            "<br><span class=\"note\">read against <a href=\"#assumed\">{n} assumption(s)</a> the \
             rung had to make to build this at all</span>"
        ),
    };
    format!("<p>{words}{assumed}</p>")
}

/// What the run recorded about itself.
///
/// Written on every terminal outcome, unlike the store, which records only runs that reached a
/// comparison. Each absent fact is named together with why, because an empty panel reads as a run
/// that produced nothing.
fn report_panel(r: Option<&crate::progress::RunReport>) -> String {
    let Some(r) = r else {
        return "<h2>What the run recorded</h2><p class=\"note\">no run.json — this target ran \
                before the record existed, or was never attempted</p>"
            .into();
    };

    let mut out = String::from("<h2>What the run recorded</h2><table>");
    let mut row = |k: &str, v: String| {
        out.push_str(&format!("<tr><td class=\"dim\">{k}</td><td>{v}</td></tr>"));
    };
    row("started", esc(&r.started));
    if let Some(f) = &r.finished {
        row("finished", esc(f));
    }
    if let Some(d) = &r.derivation {
        row(
            "derivation",
            format!(
                "{}{}",
                esc(d),
                match &r.confidence {
                    Some(c) => format!(" · confidence {}", esc(c)),
                    None => String::new(),
                }
            ),
        );
    }
    if let Some(d) = &r.strategy_digest {
        row(
            "strategy",
            format!("<code>{}</code>", esc(&d[..16.min(d.len())])),
        );
    }
    // **Always a row, on every run.** A verdict is a claim about a published artifact *and* a
    // commit, and the commit half reached nobody: this field had no reader in this file, though its
    // own doc comment calls it "the one thing a reader has to have and did not". How it was found
    // is part of it — `SourceDiscovery`'s doc says a fuzzy tag match on a repository with four
    // thousand tags is a coin flip, and the verdict that follows deserves to be read differently.
    row(
        "built from",
        match &r.source {
            Some(src) => format!(
                "<code>{}</code> at <code>{}</code>{}<br><span class=\"dim\">found by {}{}</span>{}",
                esc(&src.repo_url),
                esc(&src.commit),
                match &src.subdir {
                    Some(d) => format!(" · <code>{}</code>", esc(d)),
                    None => String::new(),
                },
                esc(src.how.as_str()),
                match &src.ref_name {
                    Some(t) => format!(", from <code>{}</code>", esc(t)),
                    None => String::new(),
                },
                match &src.declared_url {
                    // Kept only where it differs, and shown for the same reason it is kept: a
                    // record naming a repository the package never declared reads exactly like a
                    // correct one.
                    Some(u) => format!(
                        "<br><span class=\"note\">the registry declared {}, which was trimmed to \
                         the repository above</span>",
                        esc(u)
                    ),
                    None => String::new(),
                },
            ),
            None => "<span class=\"note\">no source resolved — this run was never compared \
                     against a commit, so its verdict is a claim about an artifact and nothing \
                     else</span>"
                .to_string(),
        },
    );
    if let Some(e) = &r.egress {
        row(
            "egress",
            format!(
                "{}{}",
                esc(e),
                match r.attestable {
                    // The run's own answer, not the flag's. Three states, and the third is the
                    // point: a build that never finished has not told us anything, and rendering
                    // that as "not attestable" sends the reader after an egress tier when the
                    // problem is a build that died.
                    Some(false) =>
                        " · <span class=\"note\">no network transcript: this run cannot \
                                    say what the build fetched</span>",
                    Some(true) => " · transcript recorded",
                    None => "",
                }
            ),
        );
    }
    if let Some(v) = &r.void_reason {
        row("void", format!("<span class=\"void\">{}</span>", esc(v)));
    }
    // The guard fired and the run still stands, because the bytes did not come back out. Shown as
    // a note rather than a void, and shown at all because a control whose near-misses are invisible
    // cannot be told from one that never fires.
    if !r.guard_notes.is_empty() {
        row(
            "guard",
            format!(
                "<span class=\"note\">{}</span>",
                esc(&r.guard_notes.join("; "))
            ),
        );
    }
    if !r.refused_artifact.is_empty() {
        row(
            "refused",
            format!(
                "<span class=\"note\">the build asked for its own published artifact {} time(s) \
                 and was refused; nothing arrived</span>",
                r.refused_artifact.len()
            ),
        );
    }
    if let Some(m) = &r.model {
        row("model", format!("{} · {} call(s)", esc(m), r.model_calls));
    }
    out.push_str("</table>");

    // Where the mirror got the bytes, which ADR-0013 requires the run to say rather than leave to
    // whoever remembers the cache exists.
    if let Some(c) = &r.fetch_cache {
        out.push_str(&format!(
            "<h2>What the mirror already had</h2><p>{} body/bodies from disk, {} from a \
             registry.</p>",
            c.hits, c.fetched,
        ));
        out.push_str(&match &c.oldest_index_snapshot {
            // The claim this weakens, stated rather than rounded off. An artifact is immutable and
            // its digest is checked on every read; an index document decides which versions exist.
            Some(when) => format!(
                "<p class=\"note\">the oldest index document this run resolved against was \
                 fetched at <code>{}</code>. A packument decides which versions exist, so a \
                 divergence here is readable against when that copy was taken rather than as a \
                 fact about the package.</p>",
                esc(when)
            ),
            None => "<p class=\"note\">no cached index was read, so every resolution in this run \
                     went to the network. Stronger than fresh, and different from it.</p>"
                .to_string(),
        });
    }

    // **What this run asked of each host, beside what it concluded from them.** The mirror's
    // transcript said what a build fetched and the per-host counters went to a sweep's stdout, so
    // nothing this system wrote down stated what it had asked of anybody.
    out.push_str("<h2>What this run asked upstream</h2>");
    if r.hosts.is_empty() {
        out.push_str(
            "<p class=\"note\">no per-host counts — this run predates the counter, or it made no \
             request of its own. Not a run that asked for nothing: a run that asked for nothing \
             would have resolved no package.</p>",
        );
    } else {
        out.push_str(
            "<table><tr><th>host</th><th class=\"n\">requests</th><th class=\"n\">throttled</th>\
             <th class=\"n\">failed</th></tr>",
        );
        for (host, t) in &r.hosts {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td class=\"n\">{}</td>\
                 <td class=\"n\">{}</td><td class=\"n\">{}</td></tr>",
                esc(host),
                t.requests,
                // Non-zero means the numbers from this run are about our politeness rather than
                // about the package, which is worth colouring rather than leaving in a column.
                if t.throttled > 0 {
                    format!("<span class=\"fail\">{}</span>", t.throttled)
                } else {
                    "0".into()
                },
                if t.failed > 0 {
                    format!("<span class=\"ours\">{}</span>", t.failed)
                } else {
                    "0".into()
                },
            ));
        }
        out.push_str("</table>");
        if r.hosts.values().any(|t| t.throttled > 0) {
            out.push_str(
                "<p class=\"note\">a host told us to slow down during this run, so read whatever \
                 failed below as a statement about our request rate before reading it as one about \
                 the package</p>",
            );
        }
    }

    if !r.timings.is_empty() {
        out.push_str("<h2>Timeline</h2><table><tr><th>phase</th><th class=\"n\">seconds</th></tr>");
        for (phase, secs) in &r.timings {
            out.push_str(&format!(
                "<tr><td>{}</td><td class=\"n\">{}</td></tr>",
                esc(phase),
                // `None` is no data, never zero: a timing we failed to read is not a fast phase,
                // and averaging the two quietly understates every build.
                match secs {
                    Some(s) => format!("{s:.1}"),
                    None => "<span class=\"note\">no data</span>".into(),
                }
            ));
        }
        out.push_str("</table>");
    }

    if let Some(f) = &r.failure {
        out.push_str(&format!(
            "<h2>Failure, as classified at the time</h2><p><code>{}</code>{} · \
             <span class=\"dim\">{:?}, {}, {}</span></p><pre>{}</pre>\
             <p class=\"note\">recorded when the log was in hand, so it cannot drift from the \
             rule table the way a re-classification does</p>",
            esc(&f.code),
            match &f.subject {
                Some(s) => format!(" <code>{}</code>", esc(s)),
                None => String::new(),
            },
            f.fault,
            if f.retryable {
                "retryable"
            } else {
                "not retryable"
            },
            if f.repairable {
                "repairable"
            } else {
                "nothing to repair"
            },
            esc(&f.evidence),
        ));
    }

    if !r.assumptions.is_empty() {
        out.push_str("<h2 id=\"assumed\">What the rung assumed</h2><ul>");
        for a in &r.assumptions {
            out.push_str(&format!("<li>{}</li>", esc(a)));
        }
        out.push_str(
            "</ul><p class=\"note\">a divergence has to be readable against the guesses \
                      that produced it rather than taken as a fact about the package</p>",
        );
    }

    if !r.repairs.is_empty() || r.repair_stopped.is_some() {
        out.push_str("<h2>Repairs</h2><ul>");
        for a in &r.repairs {
            out.push_str(&format!("<li>{}</li>", esc(a)));
        }
        if let Some(stop) = &r.repair_stopped {
            out.push_str(&format!("<li class=\"note\">stopped: {}</li>", esc(stop)));
        }
        out.push_str("</ul>");
    }

    // **Always a heading, never a blank.** `None` rendered as nothing at all, and a test asserted
    // that it did — so the one section that says whether the dependency index was really pinned
    // simply vanished on every run that could not answer, which is the file's own third rule
    // broken in the file that states it. The counters are absent for three different reasons and
    // the reader is owed which one, because two of them are ordinary and one is a gap.
    let Some(p) = &r.pin else {
        out.push_str(
            "<h2>Registry pin</h2><p class=\"note\">no counters, which is not five zeroes. Either \
             no mirror ran — <code>--timewarp</code> was not asked for, or the tier is \
             <code>deny-all</code>, where there is no index to resolve against — or the build ended \
             before the mirror's record could be read. Whether this build's dependency graph was \
             pinned is unknown from here, rather than known to be unpinned.</p>",
        );
        return out;
    };
    {
        out.push_str(&format!(
            "<h2>Registry pin</h2><table>\
             <tr><td class=\"dim\">index requests</td><td>{}</td></tr>\
             <tr><td class=\"dim\">versions withheld</td><td>{}</td></tr>\
             <tr><td class=\"dim\">artifacts</td><td>{}</td></tr>\
             <tr><td class=\"dim\">toolchain</td><td>{}</td></tr>\
             <tr><td class=\"dim\">refused</td><td>{}</td></tr></table><p class=\"note\">{}</p>",
            p.index_requests,
            p.versions_withheld,
            p.artifact_requests,
            p.toolchain_requests,
            p.rejected,
            if p.pin_bound() {
                "non-zero index requests are proof the pin reached the client — the failure this \
                 exists to catch is silent: pip ignores an untrusted plain-HTTP index after one \
                 warning and resolves against the live one"
            } else if p.contacted() {
                "the mirror was contacted and served no index document. Either this build needed \
                 no dependencies, or the pin did not reach the client"
            } else {
                "the mirror was never contacted. Either this build needed no dependencies, or it \
                 resolved somewhere else"
            }
        ));
    }
    out
}

/// What the store holds about this run.
///
/// Present only for a run that reached a comparison, because that is the only kind the store keeps.
/// Said out loud rather than rendered as an empty pane: a missing record here means the run was a
/// void, a build failure or an error of ours, not that the store lost it.
async fn store_panel(store: &Path, purl: &str) -> String {
    let found = match find_record(store, purl).await {
        Lookup::Found(f) => *f,
        // Ours, and said as ours. The reader's next move is to check the path, not to wonder what
        // their package did.
        Lookup::Unusable(detail) => {
            return format!(
                "<h2>Run record</h2><p class=\"void\">the store at <code>{}</code> could not be \
                 opened, so nothing was looked up: {}</p><p class=\"note\">This is a problem with \
                 <code>--store</code>, not with the run. A relative path is resolved against the \
                 directory <code>trigon watch</code> was started in.</p>",
                esc(&store.display().to_string()),
                esc(&detail)
            );
        }
        Lookup::Unreadable(detail) => {
            return format!(
                "<h2>Run record</h2><p class=\"void\">the store at <code>{}</code> opened and its \
                 runs could not be listed, so whether this target is in it is unknown rather than \
                 no: {}</p>",
                esc(&store.display().to_string()),
                esc(&detail)
            );
        }
        Lookup::Absent { read, millis } => {
            return format!(
                "<h2>Run record</h2><p class=\"note\">the store at <code>{}</code> holds {read} \
                 run(s) and none of them is this target{}. The store keeps only runs that reached a \
                 comparison — a void, a build failure and an error of ours all write nothing there, \
                 by design: no statement may be written about a run that is evidence of nothing. A \
                 run that did compare is missing here only if it was given no <code>--store</code>, \
                 or a different one.</p>",
                esc(&store.display().to_string()),
                if read == 0 {
                    ", because it holds none at all".to_string()
                } else {
                    format!(" (read in {millis}ms)")
                }
            );
        }
    };
    let r = &found.record;
    let mut out = format!(
        "<h2>Run record</h2><p class=\"dim\">{} · read {} record(s) in {}ms</p>",
        esc(&r.id),
        found.read,
        found.millis
    );
    out.push_str("<table>");
    let mut row = |k: &str, v: String| {
        out.push_str(&format!("<tr><td class=\"dim\">{k}</td><td>{v}</td></tr>"))
    };
    row("outcome", esc(r.outcome.as_deref().unwrap_or("—")));
    row(
        "upstream",
        format!("<code>{}</code>", esc(&r.upstream.sha256.to_hex()[..16])),
    );
    match &r.rebuild {
        Some(b) => row(
            "rebuild",
            format!(
                "<code>{}</code>{}",
                esc(&b.sha256.to_hex()[..16]),
                match (b.stored, found.rebuild_kept) {
                    (true, true) => "",
                    (true, false) => {
                        " · <span class=\"void\">bytes missing: the record says they are kept, \
                         and the store has no blob of them</span>"
                    }
                    (false, _) => {
                        " · <span class=\"note\">bytes pruned; a match can be re-derived, and a \
                         divergence keeps its bytes</span>"
                    }
                }
            ),
        ),
        None => row(
            "rebuild",
            "<span class=\"note\">none recorded</span>".into(),
        ),
    }
    row(
        "environment",
        format!(
            "{} · {}",
            esc(&r.environment.egress),
            if r.environment.attestable {
                "egress fully accounted for"
            } else {
                "no network transcript"
            }
        ),
    );
    if let Some(c) = &r.costs {
        // Every figure carries its unit, and what is not known is left out rather than printed as
        // zero: a `0` here would be read as a measurement, and `docs/03` §3 is explicit that on
        // this record `None` means no data and never zero.
        let mut parts = Vec::new();
        if let Some(s) = c.build_seconds {
            parts.push(format!("{s:.1}s building"));
        }
        if let Some(s) = c.inference_seconds {
            parts.push(format!("{s:.1}s inference"));
        }
        for t in &c.tokens {
            parts.push(format!(
                "{} in / {} out over {} to {}",
                t.input,
                t.output,
                match t.calls {
                    1 => "1 call".to_string(),
                    n => format!("{n} calls"),
                },
                esc(&t.model)
            ));
        }
        if let Some(b) = c.egress_bytes {
            // Through the same formatter every other byte count on these pages goes through. It was
            // defined and unused on this one path, so the run page said `96.3 MB` and the record
            // below it said `96255729 bytes fetched` about the same fetch.
            parts.push(format!("{} fetched", human_bytes(b)));
        }
        if !parts.is_empty() {
            row("cost", parts.join(" · "));
        }
    }
    // Stated on every run, including the runs that have none. A row that appears only when there
    // is a transcript makes "this run was at open egress" and "this view has not been updated yet"
    // the same observation, and the reader cannot tell which.
    row(
        "network",
        match &r.network_transcript {
            Some(d) => format!("transcript <code>{}</code>", esc(&d.to_hex()[..16])),
            None => "<span class=\"note\">no transcript: this run cannot say what the build \
                     fetched</span>"
                .into(),
        },
    );
    if let Some(d) = &r.derivation {
        row("derivation", esc(d));
    }
    if !r.guard_trips.is_empty() {
        row(
            "guard",
            format!(
                "<span class=\"void\">{}</span>",
                esc(&r.guard_trips.join("; "))
            ),
        );
    }
    if !r.attestations.is_empty() {
        row("signed", format!("{} statement(s)", r.attestations.len()));
    }
    out.push_str("</table>");

    if let Some(p) = &r.environment.pin {
        out.push_str(&format!(
            "<p class=\"note\">the pin {}</p>",
            if p.bound() {
                "bound: the index served documents through the time filter"
            } else {
                "cannot be confirmed from this run — the mirror served no index document, which is \
                 ambiguous: a package with no dependencies asks for nothing"
            }
        ));
    }
    out
}

fn clip(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}\n… clipped", &s[..i]),
        None => s.to_string(),
    }
}

/// The end of a log, which is where the failure is.
fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let start = s.len() - n;
    let start = s
        .char_indices()
        .map(|(i, _)| i)
        .find(|i| *i >= start)
        .unwrap_or(0);
    format!("… earlier output clipped\n{}", &s[start..])
}

/// Serve a read-only view of one sweep's work directory.
pub fn serve(
    work: PathBuf,
    targets: Option<PathBuf>,
    bind: String,
    store: Option<PathBuf>,
    baseline: Option<PathBuf>,
) -> Result<()> {
    if !work.is_dir() {
        anyhow::bail!("{} is not a directory", work.display());
    }
    let sweep = std::sync::Arc::new(Sweep {
        work,
        targets,
        bind: bind.clone(),
        store,
        baseline,
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(board))
        .route("/cluster", axum::routing::get(cluster))
        .route("/run/{index}", axum::routing::get(run))
        .route("/run/{index}/network", axum::routing::get(network))
        .route("/run/{index}/compare", axum::routing::get(compare))
        .route("/run/{index}/source", axum::routing::get(source_page))
        .route("/api/state", axum::routing::get(api_state))
        .with_state(sweep);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .with_context(|| format!("binding {bind}"))?;
        println!(
            "{} {} {}",
            crate::style::heading("watching on"),
            crate::style::ident(&format!("http://{bind}")),
            crate::style::muted("(read-only; ctrl-c to stop)")
        );
        axum::serve(listener, app).await?;
        Ok(())
    })
}

/// Every member of the published artifact, with its **raw** content digest.
///
/// Raw: taken before any stabilizer runs, because that is the only key a join against a checkout
/// may use. See `provenance`'s module documentation for what joining on the blob's digests does
/// instead — it turns one normalized line ending into a file "carried from the commit".
fn raw_members(artifact: &Path) -> Result<Vec<(String, String, u64)>, String> {
    let format = trigon_core::Format::from_file_name(
        &artifact.file_name().unwrap_or_default().to_string_lossy(),
    )
    .ok_or_else(|| "this artifact's name names no format we can parse".to_string())?;
    let bytes = std::fs::read(artifact).map_err(|e| format!("reading the artifact: {e}"))?;
    let mut notes = Vec::new();
    let parsed = trigon_archive::parse(
        bytes,
        format,
        &trigon_archive::Limits::default(),
        &mut notes,
    )
    .map_err(|e| format!("parsing the artifact: {e}"))?;
    let mut out = Vec::new();
    for e in &parsed.archive.entries {
        let body = e
            .body_bytes()
            .map_err(|e| format!("reading a member: {e}"))?;
        out.push((
            String::from_utf8_lossy(e.path.as_bytes()).into_owned(),
            digest_hex(&body),
            e.meta.size,
        ));
    }
    Ok(out)
}

/// Two bars over one x-axis: where each member came from, and what the comparison said about it.
///
/// **Alignment does a Sankey's job with no crossings.** The members are sorted once, into origin
/// order, and both bars use that order — so a band in the lower bar sits directly under the members
/// it describes. The reading that matters is vertical: red in the verdict bar under green in the
/// origin bar is a file the maintainer wrote coming back different, which is the alarming case and
/// was undetectable before this page.
fn origin_bars(
    members: &[crate::provenance::Member],
    verdicts: &BTreeMap<String, &'static str>,
) -> String {
    if members.is_empty() {
        return String::new();
    }
    let total = members.len() as f64;
    let w = 720.0;

    // One order, used by both bars. Sorted by origin so the bands are contiguous; within an origin
    // by path so the same artifact draws the same picture twice.
    let mut sorted: Vec<&crate::provenance::Member> = members.iter().collect();
    sorted.sort_by_key(|m| {
        let rank = match &m.origin {
            crate::provenance::Origin::Verbatim => 0,
            crate::provenance::Origin::Normalized(_) => 1,
            crate::provenance::Origin::Built => 2,
            crate::provenance::Origin::Unknown => 3,
        };
        (rank, m.path.clone())
    });

    let mut origin_rects = String::new();
    let mut verdict_rects = String::new();
    let mut x = 0.0;
    let step = w / total;
    for m in &sorted {
        origin_rects.push_str(&format!(
            "<rect x=\"{x:.2}\" y=\"0\" width=\"{step:.2}\" height=\"26\" fill=\"{}\"><title>{}</title></rect>",
            m.origin.colour(),
            esc(&format!("{} — {}", m.path, m.origin.label())),
        ));
        let (fill, what) = match verdicts.get(&m.path).copied() {
            Some("identical") => ("#137333", "identical as published"),
            Some("stabilized") => ("#b26a00", "stabilized out"),
            Some("packed") => ("#8a6d1f", "same bytes, packed differently"),
            Some("differs") => ("#b3261e", "still differs"),
            Some("one-side") => ("#6b4fbb", "on one side only"),
            _ => ("#d8d8d4", "not compared"),
        };
        verdict_rects.push_str(&format!(
            "<rect x=\"{x:.2}\" y=\"0\" width=\"{step:.2}\" height=\"26\" fill=\"{fill}\"><title>{}</title></rect>",
            esc(&format!("{} — {what}", m.path)),
        ));
        x += step;
    }

    // The alarming case, counted rather than left for the eye: a member the commit explains whose
    // comparison says it changed.
    let alarming = sorted
        .iter()
        .filter(|m| {
            !matches!(
                m.origin,
                crate::provenance::Origin::Built | crate::provenance::Origin::Unknown
            ) && verdicts.get(&m.path).is_some_and(|v| *v == "differs")
        })
        .count();

    format!(
        "<p class=\"dim\" style=\"margin:.8rem 0 .2rem\">where each member came from</p>\
         <svg viewBox=\"0 0 {w} 26\" width=\"100%\" height=\"26\" role=\"img\" \
          aria-label=\"origin of each member\" preserveAspectRatio=\"none\">{origin_rects}</svg>\
         <p class=\"dim\" style=\"margin:.55rem 0 .2rem\">and what the comparison said about it</p>\
         <svg viewBox=\"0 0 {w} 26\" width=\"100%\" height=\"26\" role=\"img\" \
          aria-label=\"comparison verdict for each member\" preserveAspectRatio=\"none\">{verdict_rects}</svg>\
         <p class=\"note\">Same members, same order, in both bars: read it vertically. {}</p>",
        if alarming > 0 {
            format!(
                "<strong>{alarming} member(s) the commit explains came back different</strong> — a \
                 file somebody wrote, rebuilt into something else. That is the case worth opening."
            )
        } else {
            "Nothing the commit explains came back different.".to_string()
        }
    )
}

/// The verdict each member got, keyed by path, in the vocabulary the lower bar draws.
fn member_verdicts(diffs: &[MemberDiff]) -> BTreeMap<String, &'static str> {
    diffs
        .iter()
        .map(|d| {
            let v = if d.only_one_side() {
                "one-side"
            } else if d.removed_by_stabilization() {
                "stabilized"
            } else if d.metadata_only() {
                "packed"
            } else if d.content_differs() {
                "differs"
            } else {
                "identical"
            };
            (d.path.clone(), v)
        })
        .collect()
}

/// How the source became the artifact.
///
/// The page the watch redesign exists for. A verdict is a claim about a published artifact **and a
/// commit**, and every other view answers the first half. This one answers the second: of the
/// members in this artifact, which are the maintainer's bytes and which did the build make.
async fn source_page(
    State(sweep): State<std::sync::Arc<Sweep>>,
    UrlPath(index): UrlPath<usize>,
) -> Response {
    let v = sweep.read();
    let dir = sweep.target_dir(&v, index);
    let report = read_report(&dir);
    let name = match &report {
        Some(r) => r.purl.strip_prefix("pkg:").unwrap_or(&r.purl).to_string(),
        None => format!("target {index:03}"),
    };

    let mut body = format!(
        "<h1>{}</h1>{}<p><a href=\"/run/{index}\">← the run</a></p>",
        esc(&name),
        state_strip(&v, sweep.targets.as_deref()),
    );

    let Some(src) = report.as_ref().and_then(|r| r.source.as_ref()) else {
        body.push_str(
            "<h2>How the source became the artifact</h2><p class=\"note\">this run recorded no \
             source, so there is no commit to compare the artifact against. A verdict without one \
             is a claim about an artifact and nothing else.</p>",
        );
        return page(&sweep.tab_title(Some(&name)), false, &body, &sweep.bind).into_response();
    };

    let Some((upstream, _)) = artifact_pair(&dir) else {
        body.push_str(
            "<h2>How the source became the artifact</h2><p class=\"note\">the published artifact \
             is not on disk, so its members cannot be read. This page works from bytes rather than \
             from the comparison record, deliberately — see the note below — so a pruned work \
             directory takes it with it.</p>",
        );
        return page(&sweep.tab_title(Some(&name)), false, &body, &sweep.bind).into_response();
    };

    let members = match raw_members(&upstream) {
        Ok(m) => m,
        Err(e) => {
            body.push_str(&format!(
                "<h2>How the source became the artifact</h2><p class=\"note\">{}</p>",
                esc(&e)
            ));
            return page(&sweep.tab_title(Some(&name)), false, &body, &sweep.bind).into_response();
        }
    };

    // The same cache the rungs fetch into. Read-only: `default_root` computes a path and
    // `checkout_dir` derives a key from it; neither creates anything, which is the property this
    // page needs — `SourceCache::new` makes the directory it is given, and a monitor that created
    // a cache would be a monitor that changed what it observes.
    let root = trigon_registry::SourceCache::default_root();
    let checkout = crate::provenance::checkout_dir(&root, &src.repo_url, &src.commit);
    let started = std::time::Instant::now();
    let (joined, scope) = crate::provenance::join(
        &members,
        Some(&checkout),
        src.subdir.as_deref(),
        &src.commit,
    );
    let took = started.elapsed();

    // The sentence, before the picture. Tiers reported separately and never summed: "38 are the
    // commit's bytes and 4 the build made" is a different claim from "42 are accounted for".
    let t = crate::provenance::tally(&joined);
    let (verbatim, normalized, built, unknown) = (t[0].1, t[1].1, t[2].1, t[3].1);
    body.push_str("<h2>How the source became the artifact</h2>");
    let mut sentence = format!("<p><strong>{} member(s).</strong> ", joined.len());
    if unknown == joined.len() {
        sentence.push_str(&format!(
            "Where they came from is unknown: {}.</p>",
            esc(&scope.where_we_looked())
        ));
    } else {
        sentence.push_str(&format!("{verbatim} are the commit's bytes unchanged. "));
        if normalized > 0 {
            sentence.push_str(&format!(
                "{normalized} are the commit's bytes after a line-ending rewrite. "
            ));
        }
        sentence.push_str(&format!(
            "{built} the build made — meaning {}.</p>",
            esc(&scope.where_we_looked())
        ));
    }
    body.push_str(&sentence);

    let verdicts = artifact_pair(&dir)
        .and_then(|(u, r)| member_diffs(&u, &r).ok())
        .map(|(d, _)| member_verdicts(&d))
        .unwrap_or_default();
    body.push_str(&origin_bars(&joined, &verdicts));

    // The table, ordered so the things worth reading are at the top.
    body.push_str(
        "<h2>Member by member</h2><table><tr><th>member</th><th>origin</th><th>from</th>\
         <th class=\"n\">bytes</th></tr>",
    );
    let mut rows: Vec<&crate::provenance::Member> = joined.iter().collect();
    rows.sort_by_key(|m| {
        let rank = match &m.origin {
            crate::provenance::Origin::Unknown => 0,
            crate::provenance::Origin::Built => 1,
            crate::provenance::Origin::Normalized(_) => 2,
            crate::provenance::Origin::Verbatim => 3,
        };
        (rank, m.path.clone())
    });
    for m in rows {
        body.push_str(&format!(
            "<tr><td><code>{}</code></td><td style=\"color:{}\">{}</td>\
             <td><code class=\"dim\">{}</code></td><td class=\"n\">{}</td></tr>",
            esc(&m.path),
            m.origin.colour(),
            esc(&m.origin.label()),
            esc(m.source_path.as_deref().unwrap_or("")),
            human_bytes(m.bytes),
        ));
    }
    body.push_str("</table>");

    body.push_str(&format!(
        "<p class=\"note\">Joined on the artifact's <strong>raw</strong> member digests, taken \
         before any stabilizer ran, against {} — and the comparison record's digests were not used, \
         because they are taken <em>after</em>. Joining on those, one rewritten line ending reads as \
         a file carried from the commit. Took {}ms; the checkout index is memoised per directory \
         and mtime, because hashing a large one takes seconds.</p>",
        esc(&scope.where_we_looked()),
        took.as_millis(),
    ));

    page(&sweep.tab_title(Some(&name)), false, &body, &sweep.bind).into_response()
}

/// A verdict's whole derivation on one line.
///
/// **The question no page answered: where did this come from?** A verdict is a claim about a
/// published artifact and a commit, reached through a strategy, in an image, under a stabilizer
/// set. Every one of those is recorded and each lived on a different part of the page, so
/// reconstructing the chain meant scrolling and remembering. Here it is left to right, in the order
/// the run went through it, with every digest eight characters and the whole value in `title`.
///
/// The arrow into the verdict is labelled with the stabilizer set, because that is the one link a
/// reader is most likely to want and least likely to guess: two runs of the same commit under
/// different sets are not comparable, and the set is what an attestation names.
fn chain_ribbon(
    r: &crate::progress::RunReport,
    cmp: Option<&trigon_compare::Comparison>,
) -> String {
    let chip = |label: &str, value: String, title: &str| {
        format!(
            "<span class=\"tag\" title=\"{}\" style=\"padding:.25rem .5rem\">\
             <span class=\"dim\" style=\"font-size:.72rem\">{}</span> {}</span>",
            esc(title),
            esc(label),
            value
        )
    };
    let short = |h: &str| esc(&h[..8.min(h.len())]).to_string();
    let arrow = "<span class=\"dim\" style=\"margin:0 .35rem\">→</span>";

    let mut parts: Vec<String> = Vec::new();
    match &r.source {
        Some(src) => parts.push(chip(
            "commit",
            format!("<code>{}</code>", short(&src.commit)),
            &format!("{} — found by {}", src.repo_url, src.how.as_str()),
        )),
        // Named rather than omitted. A chain with a link missing is the interesting case: a verdict
        // reached without a commit is a claim about an artifact and nothing else.
        None => parts.push(chip(
            "commit",
            "<span class=\"note\">none</span>".into(),
            "this run resolved no source, so the chain starts at the strategy",
        )),
    }
    if let Some(d) = &r.strategy_digest {
        parts.push(chip(
            "strategy",
            format!("<code>{}</code>", short(d)),
            &format!(
                "{}{}",
                d,
                r.derivation
                    .as_deref()
                    .map(|x| format!(" — {x}"))
                    .unwrap_or_default()
            ),
        ));
    }
    let seconds: f64 = r.timings.iter().filter_map(|(_, s)| *s).sum();
    if seconds > 0.0 {
        parts.push(chip(
            "build",
            format!("{seconds:.0}s"),
            "the phases this run timed",
        ));
    }
    if let Some(c) = cmp {
        parts.push(chip(
            "artifact",
            format!(
                "{} members",
                c.diff.as_ref().map(|d| d.files.len()).unwrap_or(0)
            ),
            "the published artifact, as parsed from the bytes on disk",
        ));
    }

    let verdict = match r.outcome.as_deref() {
        Some(o) => {
            let fam = Family::of(o);
            format!("<span class=\"tag {}\">{}</span>", fam.css(), esc(o))
        }
        None => "<span class=\"note\">no outcome</span>".to_string(),
    };
    // The set on the last arrow, because two runs of one commit under different sets are not
    // comparable and the set is what an attestation names.
    let set = cmp
        .map(|c| {
            format!(
                "<span class=\"dim\" style=\"font-size:.72rem\" title=\"{}\">under {} {}</span>",
                esc(&c.upstream.set.1.to_hex()),
                esc(&c.upstream.set.0.to_string()),
                short(&c.upstream.set.1.to_hex()),
            )
        })
        .unwrap_or_default();

    format!(
        "<p style=\"display:flex;align-items:center;flex-wrap:wrap;gap:.15rem;margin:.6rem 0 1rem\">\
         {}{arrow}{set}{arrow}{verdict}</p>",
        parts.join(arrow)
    )
}

/// The verdict as three questions, of which exactly one decided it.
///
/// **Six digests, made readable.** A comparison produces a raw pair, a container pair and a
/// stabilized pair, and a page that prints six hex strings has told a reader nothing. The verdict
/// is a walk down three rungs, and it stops at the first that answers:
///
/// 1. **Are the published and rebuilt bytes the same?** If yes the verdict is `exact` and no pass
///    ran on anything that mattered.
/// 2. **Are they the same after the stabilizers?** If yes the verdict is `normalized`, and the
///    ledger below says which passes did it and whether any of them can hide a real difference.
/// 3. **Which members differ?** Only reached when the first two say no, and then the answer is the
///    divergence itself.
///
/// The rung that answered is drawn live and the others are greyed, because a reader's question is
/// "why is this the verdict" and the answer is one of the three.
fn digest_ladder(cmp: &trigon_compare::Comparison) -> String {
    let short = |d: &trigon_core::Digest| {
        let hex = d.to_hex();
        format!(
            "<code title=\"{}\">{}</code>",
            esc(&hex),
            esc(&hex[..8.min(hex.len())])
        )
    };
    let raw_same = cmp.upstream.raw.sha256 == cmp.rebuild.raw.sha256;
    let stab_same = cmp.upstream.stabilized.sha256 == cmp.rebuild.stabilized.sha256;
    let decided = if raw_same {
        0
    } else if stab_same {
        1
    } else {
        2
    };

    let differs = cmp.diff.as_ref().map(|d| d.differs).unwrap_or(0);
    let identical = cmp.diff.as_ref().map(|d| d.identical).unwrap_or(0);

    let rungs = [
        (
            "the published bytes and the rebuilt bytes",
            format!(
                "{} {} {}",
                short(&cmp.upstream.raw.sha256),
                if raw_same { "=" } else { "≠" },
                short(&cmp.rebuild.raw.sha256)
            ),
            if raw_same {
                "identical, so nothing had to be normalized away"
            } else {
                "different, so the next question is whether the difference survives normalization"
            },
        ),
        (
            "after the stabilizers",
            format!(
                "{} {} {}",
                short(&cmp.upstream.stabilized.sha256),
                if stab_same { "=" } else { "≠" },
                short(&cmp.rebuild.stabilized.sha256)
            ),
            if stab_same {
                "equal, so every difference was one a named pass removes"
            } else {
                "still different, so the difference is in the members themselves"
            },
        ),
        (
            "member by member",
            format!("<strong>{differs}</strong> differ, {identical} identical"),
            "which files, and how, is below",
        ),
    ];

    let mut out = String::from("<h2>Why this is the verdict</h2><table>");
    for (i, (question, answer, gloss)) in rungs.iter().enumerate() {
        // Greyed rather than hidden. A reader who wants to know what the *other* questions would
        // have said is asking something reasonable, and a rung that vanished would leave them
        // reconstructing the ladder from the outcome word.
        let live = i == decided;
        let style = if live { "" } else { " style=\"opacity:.45\"" };
        out.push_str(&format!(
            "<tr{style}><td>{}{}</td><td>{answer}</td><td class=\"dim\">{gloss}</td></tr>",
            if live { "▸ " } else { "&nbsp;&nbsp;" },
            esc(question),
        ));
        if live {
            break;
        }
    }
    out.push_str("</table>");
    out.push_str(&format!(
        "<p class=\"note\">The marked row is the one that decided <code>{}</code>.{}</p>",
        esc(&cmp.outcome.to_string()),
        // Only where there are any. Printing "the rows below were never asked" under the last rung
        // is the small kind of wrong that makes a reader distrust the rest of the page.
        if decided + 1 < rungs.len() {
            " The rows below it were never asked."
        } else {
            " Every question was asked, and this is the last one there is."
        }
    ));
    out
}

/// What the comparison observed and nobody has ever been shown.
///
/// **A promise made by a type and kept by no renderer.** `NoteCode::ExecutableContentDiffers`
/// carries the doc comment "Never benign", `is_noteworthy()` says these "should reach a human even
/// when the verdict is a clean match", and a seam test asserts the promise against the enum — while
/// the only references to `is_noteworthy` in the whole tree are in tests. `Newtonsoft.Json@11.0.1`'s
/// stored comparison holds ten notes, nine of them that code, and no page has ever rendered one.
///
/// Recomputed from the two artifacts rather than read from the store, for the reason the rest of
/// this page works that way: a run without `--store` still has its bytes, and a reader holding the
/// artifacts can redo the arithmetic instead of trusting a record.
fn recompare(dir: &Path) -> Option<trigon_compare::Comparison> {
    let (upstream, rebuild) = artifact_pair(dir)?;
    let format = trigon_core::Format::from_file_name(
        &upstream.file_name().unwrap_or_default().to_string_lossy(),
    )?;
    let (ub, rb) = (
        std::fs::read(&upstream).ok()?,
        std::fs::read(&rebuild).ok()?,
    );
    let set = run_profile(&upstream, format);
    trigon_compare::compare_bytes(ub, rb, format, &set, &trigon_archive::Limits::default()).ok()
}

/// The stabilizer set a **run** would choose for this artifact — not the one its format implies.
///
/// `default_for(format)` is not how a run chooses. `resolve_profile` looks at the *file name* first
/// (`.whl`, `.crate`, `.gem`, `.nupkg`) and only falls through to the format. A `.nupkg` is a zip,
/// so deriving from the format alone handed this page the `zip` profile where the run used `nupkg`
/// — six passes short, among them `nupkg-text-eol`, which decides members on exactly these
/// packages. The ladder, the member table and the note list were all computed under a set the run
/// never used, sitting beside a verdict computed under the set it did.
///
/// The chain ribbon is what exposed it: it prints the set, and the set it printed disagreed with
/// the one in the run's own stored record. Same shape as the npm-tarball finding — two selectors
/// for one question, nothing asserting they agree. `set_matches_the_run` now asserts it.
fn run_profile(artifact: &Path, format: trigon_core::Format) -> trigon_stabilize::StabilizerSet {
    crate::resolve_profile(artifact, None, format).unwrap_or_else(|_| {
        // `resolve_profile` errors only on an explicitly requested name, and none is requested
        // here; the format default keeps a page rendering rather than vanishing on an impossibility.
        trigon_stabilize::default_for(format)
    })
}

fn notes_panel(cmp: &trigon_compare::Comparison) -> String {
    // Both sides' parse notes and the comparison's own, in one list: a reader does not care which
    // phase observed something, only that something was observed.
    let mut all: Vec<&trigon_core::Note> = Vec::new();
    all.extend(&cmp.notes);
    all.extend(&cmp.upstream.notes);
    all.extend(&cmp.rebuild.notes);
    if all.is_empty() {
        return "<h2>What the comparison noticed</h2><p class=\"note\">nothing beyond the verdict. \
                Not an empty section by accident: parse limits, malformed entries and executables \
                whose content differs all leave a note here, and none did.</p>"
            .to_string();
    }

    let mut by_code: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    for n in all {
        let entry = by_code
            .entry(format!("{:?}", n.code))
            .or_insert((n.code.is_noteworthy(), Vec::new()));
        if let Some(p) = &n.path {
            entry
                .1
                .push(String::from_utf8_lossy(p.as_bytes()).into_owned());
        }
    }

    let mut out = String::from("<h2>What the comparison noticed</h2><table>");
    for (code, (noteworthy, paths)) in &by_code {
        // The enum's own word, not a gloss on it: `ExecutableContentDiffers` is documented "Never
        // benign", and a page that softened that would be editorialising over the type.
        let weight = if *noteworthy {
            " <span class=\"fail\">reaches a human even on a clean match</span>"
        } else {
            ""
        };
        out.push_str(&format!(
            "<tr><td><code>{}</code>{weight}</td><td class=\"n\">{}</td><td><code class=\"dim\">{}</code></td></tr>",
            esc(code),
            paths.len().max(1),
            esc(&clip(&paths.join(", "), 160)),
        ));
    }
    out.push_str("</table>");
    if by_code.contains_key("ExecutableContentDiffers") {
        out.push_str(
            "<p class=\"note\"><strong>An executable whose content differs is never benign</strong> \
             — the enum says so in those words. Two builds of the same source produce different \
             machine code for ordinary reasons (a path baked in, a timestamp, a compiler version), \
             and also for the reason that matters. Nothing here tells those apart; what this says \
             is that the difference is in a file that runs.</p>",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    /// The page must judge under the set the run judged under.
    ///
    /// This is the assertion that was missing when the chain ribbon found the bug. Every artifact
    /// kind the CLI names by *extension* is checked against what the page would choose, and the
    /// `.nupkg` row is the one that mattered: its format is `Zip`, so a format-only derivation
    /// answers `zip` — a different, smaller set than the run's, which the page then rendered a
    /// ladder, a member table and a note list from.
    ///
    /// Written as a loop over the CLI's own table rather than a list of pairs, so a kind added
    /// there is covered here without anyone remembering to come back.
    #[test]
    fn the_page_judges_under_the_set_the_run_used() {
        for (ext, id) in crate::BY_EXTENSION {
            let name = std::path::PathBuf::from(format!("pkg-1.0{ext}"));
            let fmt = trigon_core::Format::from_file_name(&name.to_string_lossy())
                .unwrap_or_else(|| panic!("`{ext}` names no format trigon can read"));
            let chosen = super::run_profile(&name, fmt);
            assert_eq!(
                chosen.id.as_str(),
                *id,
                "a `{ext}` is compared under `{id}` by a run and `{}` by the page",
                chosen.id
            );
        }
    }

    /// And the reason the test above cannot be waved off as trivially true.
    ///
    /// At least one kind's format-default disagrees with its run profile. If that ever stops being
    /// so, the two selectors have converged and this test should be deleted along with the doc
    /// comment on `run_profile` — but while it holds, reaching for `default_for` in a rendering
    /// path is a live bug and not a stylistic preference.
    #[test]
    fn a_format_default_is_not_a_substitute_for_the_run_s_choice() {
        let disagreements: Vec<_> = crate::BY_EXTENSION
            .iter()
            .filter_map(|(ext, id)| {
                let name = std::path::PathBuf::from(format!("pkg-1.0{ext}"));
                let fmt = trigon_core::Format::from_file_name(&name.to_string_lossy())?;
                let by_format = trigon_stabilize::default_for(fmt);
                (by_format.id.as_str() != *id).then(|| (*ext, by_format.id.to_string(), *id))
            })
            .collect();
        assert!(
            disagreements.iter().any(|(ext, ..)| *ext == ".nupkg"),
            "a `.nupkg` used to be judged under the zip set by every page in this file; if that is \
             no longer a way to get it wrong, say so here rather than deleting the guard"
        );
        assert!(!disagreements.is_empty());
    }

    use super::*;

    fn rows(text: &str) -> Vec<Row> {
        parse_results(text).0
    }

    #[test]
    fn a_torn_final_line_is_dropped_and_counted_rather_than_rejecting_the_file() {
        // Rows are appended and flushed per target, so a process killed mid-write leaves a partial
        // one. Rejecting the file loses a whole sweep; dropping it silently under-reports one.
        let (rows, dropped) = parse_results(
            "pkg:npm/a@1\texact\t12.0\t\t0\npkg:npm/b@1\tdivergent\t3.0\t\t0\npkg:npm/c@1\tbuild-fai",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(dropped, 1);
        assert_eq!(rows[0].purl, "pkg:npm/a@1");
    }

    #[test]
    fn an_uncounted_model_column_is_not_a_zero() {
        // A sweep written before the column existed did not count. Rendering that as "0 model
        // calls" is the same sentence a clean run prints.
        let old = rows("pkg:npm/a@1\texact\t1.0\n");
        assert_eq!(old[0].model_calls, None);
        let new = rows("pkg:npm/a@1\texact\t1.0\t\t0\n");
        assert_eq!(new[0].model_calls, Some(0));
    }

    #[test]
    fn the_outcome_families_are_findings_and_not_degrees() {
        assert_eq!(Family::of("exact"), Family::Reproduced);
        assert_eq!(Family::of("normalized_with_caveats"), Family::Reproduced);
        assert_eq!(Family::of("divergent"), Family::Divergent);
        assert_eq!(Family::of("build-failed:deps"), Family::BuildFailed);
        assert_eq!(Family::of("void"), Family::Void);
        assert_eq!(Family::of("no-strategy"), Family::NoStrategy);
        // Anything else is ours until proven otherwise, which is the safe direction: an
        // unrecognised label must not be counted against a package.
        assert_eq!(Family::of("error:infra"), Family::Error);
        assert_eq!(Family::of("something-new"), Family::Error);

        // Only a comparison is evidence about a package.
        assert!(Family::of("exact").is_evidence());
        assert!(Family::of("divergent").is_evidence());
        for label in ["build-failed:deps", "error:infra", "void", "no-strategy"] {
            assert!(!Family::of(label).is_evidence(), "{label}");
        }
    }

    #[test]
    fn nothing_compared_is_not_a_zero_percent_reproduction_rate() {
        // "Nothing reproduced" and "nothing was tested" are different findings, and only one of
        // them is about the packages.
        let r = Rates::of(&rows(
            "pkg:npm/a@1\tbuild-failed:deps\t1.0\tnpm/x\t0\npkg:npm/b@1\terror:infra\t1.0\terror:y\t0\n",
        ));
        assert_eq!(r.reproduction(), None);
        assert_eq!(r.attempted, 2);
        assert_eq!(r.evidence, 0);
        // And the second rate is about us: nothing reached a comparison.
        assert_eq!(r.evidence_rate(), Some(0.0));
    }

    #[test]
    fn the_two_denominators_never_merge() {
        // Four targets: two reproduced, one diverged, one was our own fault. The reproduction rate
        // is over the three that were compared, never over the four attempted.
        let r = Rates::of(&rows(
            "a\texact\t1.0\t\t0\nb\tnormalized\t1.0\t\t0\nc\tdivergent\t1.0\t\t0\nd\terror:infra\t1.0\terror:x\t0\n",
        ));
        assert_eq!((r.reproduced, r.evidence, r.attempted), (2, 3, 4));
        assert!((r.reproduction().unwrap() - 2.0 / 3.0).abs() < 1e-9);
        assert!((r.evidence_rate().unwrap() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn clusters_rank_by_size_and_are_stable() {
        let cs = clusters(&rows(
            "a\tbuild-failed:deps\t1.0\tnpm/peer-conflict\t0\n\
             b\tbuild-failed:deps\t1.0\tenv/missing-tool:npx\t0\n\
             c\tbuild-failed:deps\t1.0\tnpm/peer-conflict\t0\n\
             d\texact\t1.0\t\t0\n",
        ));
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].key, "npm/peer-conflict");
        assert_eq!(cs[0].members.len(), 2);
        assert_eq!(cs[1].key, "env/missing-tool:npx");
        // A row with no cluster is in none of them.
        assert!(!cs.iter().any(|c| c.members.iter().any(|m| m == "d")));
    }

    #[test]
    fn a_package_cannot_write_html_into_the_page() {
        // Every string on these pages came from a package: its name, its log, its failure
        // evidence. `docs/12-security.md` §4 calls build output the highest-risk injection channel
        // in the system, and the operator's browser is the next target.
        let nasty = "<script>alert('x')</script>\"&";
        let out = esc(nasty);
        assert!(!out.contains('<'), "{out}");
        assert!(!out.contains('>'), "{out}");
        assert!(out.contains("&lt;script&gt;"), "{out}");
        assert!(out.contains("&quot;") && out.contains("&amp;"), "{out}");
    }

    #[test]
    fn a_cluster_key_survives_the_query_string() {
        // Real keys carry slashes and colons: `cc/missing-header:python.h`.
        assert_eq!(
            urlencode("cc/missing-header:python.h"),
            "cc%2Fmissing-header%3Apython.h"
        );
        assert_eq!(urlencode("plain-key"), "plain-key");
    }

    #[test]
    fn a_log_tail_keeps_the_end_where_the_failure_is() {
        let log = format!("{}\nthe error", "noise\n".repeat(4000));
        let t = tail(&log, 100);
        assert!(t.ends_with("the error"));
        assert!(t.starts_with("… earlier output clipped"));
        // And a short log is untouched.
        assert_eq!(tail("short", 100), "short");
    }

    #[test]
    fn a_phase_nobody_wrote_is_named_rather_than_left_blank() {
        // An absent phase is not a phase of zero length, and a blank reads as one. It also matters
        // which clock is shown: a target twenty minutes in is healthy if nineteen were `deps`.
        let mut c = crate::progress::Current {
            index: 0,
            purl: "pkg:npm/a@1".into(),
            started: "2026-01-01T00:00:00Z".into(),
            elapsed_seconds: 1200,
            phase: None,
            phase_elapsed_seconds: 0,
        };
        assert!(
            phase_text(&c).contains("not yet recorded"),
            "{}",
            phase_text(&c)
        );

        c.phase = Some("deps".into());
        c.phase_elapsed_seconds = 1140;
        let t = phase_text(&c);
        assert!(t.contains("deps"), "{t}");
        // The phase's own clock, not the target's.
        assert!(t.contains("19m"), "{t}");
        assert!(!t.contains("20m"), "{t}");
    }

    #[test]
    fn a_timestamp_we_cannot_read_does_not_make_a_dead_sweep_look_alive() {
        // The caller treats `None` as very old. A parse failure that answered "now" would report a
        // stopped sweep as running, which is the one direction this must not err in.
        assert_eq!(rfc3339_age("not a timestamp"), None);
        assert_eq!(rfc3339_age("2026-01-01T00:00Z"), None);
        // A round trip against the writer's own format, which is the only format this has to read.
        let now = crate::now_rfc3339();
        let age = rfc3339_age(&now).expect("the formatter's own output");
        assert!(age <= 2, "{now} read back as {age}s old");
    }

    #[test]
    fn the_api_says_absent_rather_than_zero() {
        // A JSON zero is a different answer from an absent field, and the page and the API must
        // give the same one.
        let r = Rates::of(&rows("a\tbuild-failed:deps\t1.0\tx\t0\n"));
        assert_eq!(r.reproduction(), None);
        let json = serde_json::to_string(&ApiState {
            layout: "sweep",
            state: "running".into(),
            detail: "on a for 3s".into(),
            attempted: r.attempted,
            total: None,
            reproduction: r.reproduction(),
            reproduced: r.reproduced,
            evidence: r.evidence,
            evidence_rate: r.evidence_rate(),
            dropped_rows: 0,
            results_age_seconds: None,
            current: None,
            clusters: Vec::new(),
        })
        .unwrap();
        assert!(json.contains("\"reproduction\":null"), "{json}");
        assert!(json.contains("\"total\":null"), "{json}");
    }

    // -----------------------------------------------------------------------------------------
    // A directory of runs. Everything below reads a real directory, because the bug it is about
    // was a directory this page could not name: `Sweep::read` decides the layout from what is on
    // disk, so a test that hands it a `View` would be testing the half that was never wrong.
    // -----------------------------------------------------------------------------------------

    /// A fresh, empty directory named for the test that owns it.
    fn work_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("trigon-watch-{}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(path: PathBuf, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn sweep_at(work: PathBuf) -> Sweep {
        Sweep {
            work,
            targets: None,
            bind: "127.0.0.1:0".into(),
            store: None,
            baseline: None,
        }
    }

    fn report(json: &str) -> crate::progress::RunReport {
        serde_json::from_str(json).expect("a report the writer could have written")
    }

    #[test]
    fn a_directory_of_finished_runs_is_not_a_directory_where_nothing_happened() {
        // What `./work` is, and what it rendered as: "state unknown · 0 attempted" over two dozen
        // finished rebuilds. The sweep's vocabulary over a directory no sweep made — this file's
        // first rule running backwards, with presence read as absence.
        let w = work_dir("index");
        put(
            w.join("pkg-npm-once@1.4.0").join("run.json"),
            r#"{"purl":"pkg:npm/once@1.4.0","started":"2026-09-17T19:57:42Z",
                "finished":"2026-09-17T19:58:42Z","outcome":"normalized","model_calls":0}"#,
        );
        put(
            w.join("pkg-npm-semver@3.0.1").join("run.json"),
            r#"{"purl":"pkg:npm/semver@3.0.1","started":"2026-09-17T19:57:42Z",
                "outcome":"no-strategy","declines":["npm-heuristic: no `_nodeVersion`"],
                "model_calls":0}"#,
        );
        let s = sweep_at(w);
        let v = s.read();

        assert_eq!(v.layout, Layout::Index);
        assert_eq!(v.entries.len(), 2);
        // Name order, so `/run/{i}` means the same directory on the next request.
        assert_eq!(v.entries[0].name, "pkg-npm-once@1.4.0");
        // And the row at that position is what that directory recorded, which is the join
        // `/run/{i}` rests on.
        assert_eq!(v.rows[0].purl, "pkg:npm/once@1.4.0");
        assert_eq!(v.rows[1].label, "no-strategy");
        assert_eq!(s.target_dir(&v, 1), v.entries[1].dir);
    }

    #[test]
    fn a_run_directory_that_left_no_report_is_ours_and_never_the_packages() {
        // `work/pkg-pypi-semver@3.0.1` is this: a strategy, an artifact, and no run.json. Either
        // the rebuild is still going or it died before writing one, and both are unknowns of ours.
        // Counting an unknown against the package is the direction this must never err in.
        let w = work_dir("no-report");
        put(
            w.join("half-a-run").join("strategy.yaml"),
            "id: x\nsteps: []\n",
        );
        let v = sweep_at(w).read();

        assert_eq!(v.layout, Layout::Index);
        assert_eq!(v.rows.len(), 1);
        assert_eq!(Family::of(&v.rows[0].label), Family::Error);
        assert!(!Family::of(&v.rows[0].label).is_evidence());
        // And nothing claims to know which target it was: the directory's name is the caller's
        // choice, not a record.
        assert_eq!(v.rows[0].purl, "");
    }

    #[test]
    fn a_sweep_that_has_not_written_a_result_yet_is_still_a_sweep() {
        // It writes `sweep.json` before its first target and heartbeats into `status.json` while it
        // runs, so both exist long before `results.tsv` does. Reading that moment as an index would
        // replace the liveness strip — the only thing worth watching then — with a table of one.
        let w = work_dir("young-sweep");
        put(
            w.join("status.json"),
            r#"{"heartbeat":"2026-09-17T19:57:42Z","pid":1,"state":"running","done":0,"total":20}"#,
        );
        put(
            w.join("000").join("run.json"),
            r#"{"purl":"pkg:npm/a@1","started":"2026-09-17T19:57:42Z","model_calls":0}"#,
        );
        let v = sweep_at(w).read();
        assert_eq!(v.layout, Layout::Sweep);
        assert!(v.entries.is_empty(), "and it never paid for the walk");
    }

    #[test]
    fn an_empty_directory_is_still_unknown_rather_than_an_index_of_nothing() {
        // The third answer has to survive: a directory that is not a work directory at all is not
        // an index with no runs in it, and the page says so in those words.
        let v = sweep_at(work_dir("empty")).read();
        assert_eq!(v.layout, Layout::Unknown);
    }

    #[test]
    fn the_legend_swatch_is_the_colour_the_stylesheet_sets() {
        // Two places holding one colour, which is the defect shape this project keeps finding. The
        // swatch cannot take its colour from the class — `.key i` has no background — so the hex is
        // written twice, and this is the thing that asserts they are the same hex.
        for f in Family::all() {
            let rule = format!(".{}{{color:{}}}", f.css(), f.colour());
            assert!(STYLE.contains(&rule), "{rule} is not in the stylesheet");
        }
        // Six families, and the legend lists all six even at zero: a count of nothing is an answer
        // to "what could I have found here".
        let tally = family_tally(&rows("a\texact\t1.0\t\t0\n"));
        for f in Family::all() {
            assert!(tally.contains(f.label()), "{} is missing", f.label());
        }
        assert!(
            tally.contains("1 reproduced") && tally.contains("0 divergent"),
            "{tally}"
        );
        // And no percentage anywhere near it.
        assert!(!tally.contains('%'), "{tally}");
    }

    #[test]
    fn the_sentence_says_the_thing_that_makes_the_rest_beside_the_point() {
        // Precedence, in the order one answer retires the others. All four facts were on disk and
        // none of them were on the page: `declines` had no reader in this file at all.
        let ours = verdict_sentence(&report(
            r#"{"purl":"p","started":"s","error":"podman: no such image","outcome":"error:infra",
                "void_reason":"never read","declines":["never read"],"model_calls":0}"#,
        ));
        assert!(ours.contains("error of ours"), "{ours}");
        assert!(ours.contains("podman: no such image"), "{ours}");
        assert!(!ours.contains("never read"), "{ours}");

        let void = verdict_sentence(&report(
            r#"{"purl":"p","started":"s","outcome":"void","void_reason":"the guard tripped",
                "declines":["never read"],"model_calls":0}"#,
        ));
        assert!(void.contains("evidence of nothing"), "{void}");
        assert!(void.contains("the guard tripped"), "{void}");
        assert!(!void.contains("never read"), "{void}");

        // `work/pkg-npm-semver@3.0.1`, which rendered eight panels of absence over the one sentence
        // that answers the question.
        let declined = verdict_sentence(&report(
            r#"{"purl":"p","started":"s","outcome":"no-strategy",
                "declines":["npm-heuristic: the registry recorded no `_nodeVersion`"],
                "model_calls":0}"#,
        ));
        assert!(declined.contains("No rung produced a recipe"), "{declined}");
        assert!(declined.contains("_nodeVersion"), "{declined}");
    }

    #[test]
    fn a_caveated_match_does_not_read_like_an_exact_one() {
        // The distinction the verdict exists to carry: a caveated match is one a pass could have
        // manufactured, and the word `normalized_with_caveats` does not say so on its own.
        let exact = verdict_sentence(&report(
            r#"{"purl":"p","started":"s","outcome":"exact","model_calls":0}"#,
        ));
        assert!(exact.contains("byte for byte"), "{exact}");

        let caveats = verdict_sentence(&report(
            r#"{"purl":"p","started":"s","outcome":"normalized_with_caveats","model_calls":0}"#,
        ));
        assert!(caveats.contains("can hide a real difference"), "{caveats}");

        // And an upstream error is the registry's, not ours and not the package's — the fault is
        // the half of the label that says whose it was.
        let upstream = verdict_sentence(&report(
            r#"{"purl":"p","started":"s","outcome":"error:upstream","model_calls":0}"#,
        ));
        assert!(upstream.contains("registry or the network"), "{upstream}");
        assert!(
            upstream.contains("Not a finding about the package"),
            "{upstream}"
        );
    }

    #[test]
    fn an_assumption_is_pointed_at_rather_than_left_for_the_reader_to_find() {
        // `pkg:npm/isexe@2.0.0` reproduces under a Node the registry never recorded, and the
        // sentence that says so is four panels below the verdict. The anchor it points at has to
        // exist, or the link is a promise the page does not keep.
        let r = report(
            r#"{"purl":"p","started":"s","outcome":"normalized",
                "assumptions":["the registry records Node 8.0.0-pre for this publish"],
                "model_calls":0}"#,
        );
        assert!(verdict_sentence(&r).contains("#assumed"), "no link");
        assert!(
            report_panel(Some(&r)).contains("id=\"assumed\""),
            "no anchor"
        );
    }

    #[test]
    fn a_tab_is_named_after_what_is_in_it() {
        // Every tab said `target 000`, on every run page of every layout.
        let s = sweep_at(PathBuf::from("/tmp/some-corpus"));
        assert_eq!(s.tab_title(Some("once@1.4.0")), "once@1.4.0 · trigon watch");
        assert_eq!(s.tab_title(None), "some-corpus · trigon watch");
    }

    #[test]
    fn a_duration_we_cannot_compute_is_not_a_run_that_took_no_time() {
        // A report with no `finished` is a process that died before writing one. Zero seconds is a
        // measurement, and this is not one.
        assert_eq!(
            bracket_seconds(&report(
                r#"{"purl":"p","started":"2026-09-17T19:57:42Z","model_calls":0}"#
            )),
            None
        );
        assert_eq!(
            bracket_seconds(&report(
                r#"{"purl":"p","started":"2026-09-17T19:57:42Z",
                    "finished":"2026-09-17T19:58:42Z","model_calls":0}"#
            )),
            Some(60)
        );
    }

    #[test]
    fn ages_read_as_words() {
        assert_eq!(ago(5), "5s ago");
        assert_eq!(ago(300), "5m ago");
        assert_eq!(ago(7200), "2h ago");
    }
}
