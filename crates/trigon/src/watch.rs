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
    /// The source cache the rungs fetch into, which the source page reads checkouts from.
    ///
    /// Decided once, in `serve`, from `SourceCache::default_root` — held here rather than asked
    /// for per request so a test can point it at a directory it made instead of this host's cache.
    sources: PathBuf,
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
    ///
    /// Every page's title comes through here. A page under a run passes its view in with the name —
    /// `once@1.4.0 · network` — so a run and the three pages under it are four tabs, not one tab
    /// four times; the two that skipped this carried no tool name, and the source page carried
    /// nothing but the run's.
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

    /// The `/run/{i}` number of the row at `position` in `view.rows`.
    ///
    /// Under [`Layout::Index`] the row and the directory are one position, and the round trip
    /// through the purl is ambiguous the moment two directories hold runs of the same target — a
    /// retry into a second work directory is exactly that, and it sent both members of a cluster
    /// to the first directory and read its log twice.
    fn index_of_row(&self, view: &View, position: usize) -> Option<usize> {
        match view.layout {
            Layout::Index => (position < view.rows.len()).then_some(position),
            _ => {
                let r = view.rows.get(position)?;
                self.dir_of(view, &r.purl).map(|(i, _)| i)
            }
        }
    }

    /// The row `/run/{index}` shows, where one maps to it.
    fn row_at<'a>(&self, view: &'a View, index: usize) -> Option<&'a Row> {
        match view.layout {
            Layout::Index => view.rows.get(index),
            _ => view
                .rows
                .iter()
                .find(|r| self.dir_of(view, &r.purl).map(|(i, _)| i) == Some(index)),
        }
    }

    /// What `/run/{index}` and the pages under it are called, unescaped.
    ///
    /// The target where one is known, the directory's own name where it is not, and the number
    /// only when neither is true. One function because the run page had this and the pages under
    /// it did not: a run that left no report titled its network page with an empty string.
    fn name_at(&self, view: &View, index: usize) -> String {
        match self.row_at(view, index).filter(|r| !r.purl.is_empty()) {
            Some(r) => r.purl.strip_prefix("pkg:").unwrap_or(&r.purl).to_string(),
            None => match view.entries.get(index) {
                Some(e) => e.name.clone(),
                None => format!("target {index:03}"),
            },
        }
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
                    // A finish that is there, beside a start that will not parse. Not the arm
                    // below: that one says the process died, and this one wrote its finish.
                    (Some(_), None) => " · <span class=\"note\">started at an instant this page \
                                        cannot read</span>"
                        .into(),
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
        sources: sweep.sources.clone(),
    };
    let b = other.read();

    let mut out = format!("<h2>Against {}</h2>", esc(&path.display().to_string()));
    // Before a single flip is counted. A path that is not a work directory reads as a sweep that
    // attempted nothing, and every target here would then be "in this sweep and not the
    // baseline", under a "Not a gain" — a mistyped `--baseline`, rendered as a finding about the
    // change.
    if b.layout == Layout::Unknown {
        // Why, asked so that "could not look" never reads as "not there": `exists` is false on a
        // permission error, and a directory this user may not list or enter reads, to `read`, as
        // one that holds nothing. The probe of `results.tsv` is the entering half.
        let why = match path.try_exists() {
            Err(e) => format!("whether anything is there could not be told: {e}"),
            Ok(false) => "there is nothing at that path".to_string(),
            Ok(true) => {
                match std::fs::read_dir(path).and_then(|_| path.join("results.tsv").try_exists()) {
                    Err(e) => format!("it could not be read as a directory: {e}"),
                    Ok(_) => "it holds no sweep, no run and no directory of runs".to_string(),
                }
            }
        };
        return out
            + &format!(
                "<p class=\"void\"><code>{}</code> is not a work directory this page can read — \
                 {} — so nothing was compared against it</p><p class=\"note\">This is a problem \
                 with <code>--baseline</code>, not with either sweep. A relative path is resolved \
                 against the directory <code>trigon watch</code> was started in.</p>",
                esc(&path.display().to_string()),
                esc(&why),
            );
    }
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
    // Every entity `esc` writes, undone, `&amp;` last so an escaped `&lt;` comes back as the text
    // `&lt;` and not as `<`. Undoing only `&quot;` left a maven purl's `&` reaching a JSON reader
    // as `&amp;` — a sentence that is not the one the page shows.
    out.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .trim()
        .to_string()
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
    // Each member with the `/run/{i}` it opens, decided once from its position.
    let members: Vec<(Option<usize>, &Row)> = v
        .rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.cluster.as_deref() == Some(q.key.as_str()))
        .map(|(position, r)| (sweep.index_of_row(&v, position), r))
        .collect();
    if members.is_empty() {
        return Redirect::to("/").into_response();
    }

    // The evidence line for each member, re-classified from its log. Deduplicated with counts,
    // because a cluster of forty is usually three sentences: that is the question this page is
    // open to answer — one thing, or three wearing one name.
    let mut lines: BTreeMap<String, usize> = BTreeMap::new();
    let mut unread = 0;
    for (index, _) in &members {
        match index.and_then(|i| read_log(&sweep.target_dir(&v, i))) {
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
    for (index, m) in &members {
        let name = m.purl.strip_prefix("pkg:").unwrap_or(&m.purl);
        let link = match index {
            Some(i) => format!("<a href=\"/run/{i}\">open</a>"),
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
        esc(&members[0].1.purl)
    ));
    body.push_str("<p><a href=\"/\">← all targets</a></p>");

    page(
        &sweep.tab_title(Some(&q.key)),
        v.live.is_live(),
        &body,
        &sweep.bind,
    )
    .into_response()
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
    // Unescaped: `page` escapes the title, and escaping it here too put `&amp;` in the tab.
    let title = sweep.name_at(&v, index);

    let mut body = format!(
        "<h1>{} · network</h1><p><a href=\"/run/{index}\">← the run</a></p>{}",
        esc(&title),
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
                        esc(short_hex(&e.sha256, 16)),
                        esc(&e.url),
                    ));
                }
                body.push_str("</table>");
            }
        }
    }
    let tab = sweep.tab_title(Some(&format!("{title} · network")));
    page(&tab, false, &body, &sweep.bind).into_response()
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
            let count = |b: Band| m.iter().filter(|d| d.band() == b).count();
            let differs = count(Band::Differs);
            let meta_only = count(Band::Packed);
            let removed = count(Band::Stabilized);
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
    // Unescaped: `page` escapes the title, and escaping it here too put `&amp;` in the tab.
    let title = sweep.name_at(&v, index);

    let mut body = format!(
        "<h1>{} · the stabilizer ledger</h1><p><a href=\"/run/{index}\">← the run, where the \
         verdict is</a></p>",
        esc(&title)
    );

    let Some((upstream, rebuild)) = artifact_pair(&dir) else {
        body.push_str(
            "<p class=\"note\">both artifacts are not on disk here, so there is nothing to \
             re-derive. A run keeps the published artifact at the work root and the rebuilt one \
             under <code>rebuild/&lt;run id&gt;/</code>; a build that produced nothing, or a work \
             directory that has been cleaned, leaves this page with no inputs. The verdict in the \
             run record still stands — it was computed when both were there.</p>",
        );
        let tab = sweep.tab_title(Some(&format!("{title} · compare")));
        return page(&tab, false, &body, &sweep.bind).into_response();
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
    let tab = sweep.tab_title(Some(&format!("{title} · stabilizers")));
    page(&tab, false, &body, &sweep.bind).into_response()
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
/// Bar length is `entries_touched`, which `docs/02` calls the triage number: "wheel-record-v2
/// touched 412 entries" is a diagnosis. Risk is the colour. Provenance is a column, and it is new —
/// the field has existed as long as `Applied` has and no page had ever rendered it.
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
    // Each band counted, none of them derived: a remainder hides a member counted twice.
    let count = |b: Band| m.iter().filter(|d| d.band() == b).count();
    let one_side = count(Band::OneSide);
    let differs = count(Band::Differs);
    let meta_only = count(Band::Packed);
    let removed = count(Band::Stabilized);
    let identical = count(Band::Identical);

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
         way in which they differ was removed by one of the passes in the ledger above — a member \
         only one side carried, when a pass took it out whole, among them. \
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
    rows.sort_by_key(|d| (d.band(), d.path.clone()));
    let mut out = String::from(
        "<h2>Every member</h2><table><tr><th>member</th><th>as published</th>\
         <th>stabilized</th><th class=\"n\">upstream</th><th class=\"n\">rebuild</th></tr>",
    );
    for d in rows {
        let which = if d.raw.0.is_some() {
            "upstream"
        } else {
            "rebuild"
        };
        let (raw_cell, stab_cell) = match d.band() {
            Band::OneSide => (
                format!("<span class=\"ours\">only in {which}</span>"),
                "<span class=\"ours\">—</span>".to_string(),
            ),
            Band::Differs => (
                "<span class=\"fail\">differs</span>".to_string(),
                "<span class=\"fail\">content still differs</span>".to_string(),
            ),
            Band::Packed => (
                "<span class=\"diff\">differs</span>".to_string(),
                "<span class=\"diff\">same bytes, packed differently</span>".to_string(),
            ),
            // Where a pass took the member out rather than rewriting it, the row says so: "equal"
            // over two archives that no longer hold it would be a comparison nobody made.
            Band::Stabilized => (
                if d.only_one_side() {
                    format!("<span class=\"diff\">only in {which}</span>")
                } else {
                    "<span class=\"diff\">differs</span>".to_string()
                },
                if d.stabilized == (None, None) {
                    "<span class=\"ok\">removed — stabilized out</span>".to_string()
                } else {
                    "<span class=\"ok\">equal — stabilized out</span>".to_string()
                },
            ),
            // And the same where the published bytes agreed: identical as published is a fact about
            // two archives that held it, and neither stabilized one does.
            Band::Identical => (
                "<span class=\"ok\">identical</span>".to_string(),
                if d.stabilized == (None, None) {
                    "<span class=\"ok\">removed by a pass</span>".to_string()
                } else {
                    "<span class=\"ok\">identical</span>".to_string()
                },
            ),
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
/// fingerprint, size, published name)`. The path is the stabilized name, or the published one for
/// a member a pass removed. The occurrence is in the key because a duplicate member path is legal
/// and would otherwise be unmatchable — the rule `diff.rs` keys on.
type MemberKey = (Vec<u8>, usize);
/// `(raw content, raw metadata, (stabilized content, stabilized metadata), size, published name)`.
///
/// The stabilized half is `None` for a member a pass removed: it was published and is not in the
/// stabilized archive, which is a different fact from never having been on this side at all.
type Fingerprints = (String, String, Option<(String, String)>, u64, Vec<u8>);
type SideMembers = std::collections::BTreeMap<MemberKey, Fingerprints>;

/// Which of the census's five bands a member is in. Exactly one, by construction.
///
/// **One classifier, for every reader of it.** The ladder, the table, the run page's sentence and
/// the source page's lower bar each asked five overlapping predicates in their own order, and the
/// ladder counted `identical` as the total minus the other four — so a member two predicates both
/// claimed was subtracted twice, and the one that could make that true (a member a pass removed
/// from the only side it was on) was dropped before any of them saw it.
///
/// Declared in the table's order, most interesting first; the ladder draws its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Band {
    OneSide,
    Differs,
    Packed,
    Stabilized,
    Identical,
}

impl Band {
    /// The word `member_verdicts` hands the source page's lower bar.
    fn word(self) -> &'static str {
        match self {
            Band::OneSide => "one-side",
            Band::Differs => "differs",
            Band::Packed => "packed",
            Band::Stabilized => "stabilized",
            Band::Identical => "identical",
        }
    }
}

/// One member of the artifact, before and after stabilization, on both sides.
struct MemberDiff {
    /// The name after stabilization, which both sides are matched under.
    path: String,
    /// The name upstream published it under, where upstream has it.
    ///
    /// `path` unless a pass renamed it: every nupkg's `<guid>.psmdcp` is `core.psmdcp` in `path`,
    /// and the source page, which reads the published archive, knows it only by the GUID.
    published: Option<String>,
    /// `None` where the member is on one side only.
    raw: (Option<String>, Option<String>),
    /// `None` where the member is not on that side after stabilization: never published there, or
    /// published and removed by a pass.
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
    fn only_one_side(&self) -> bool {
        self.raw.0.is_none() || self.raw.1.is_none()
    }
    /// The band this member is in, asked in the order one answer retires the others.
    ///
    /// - **Stabilized out**, first, for a member that differed as published and that a pass took
    ///   out of both archives. `.signature.p7s` is on every package nuget.org serves and on none
    ///   anybody builds: on one side as published, and on neither once `nupkg-signature` has run.
    ///   The difference is gone because a pass took it, which is what this band means.
    /// - **On one side only**: in one archive and not the other, as published and still after.
    /// - **Content differs**: the stabilized bodies disagree, or one side's pass removed it and the
    ///   other's did not.
    /// - **Same bytes, packed differently**: byte-for-byte the same file in an archive entry that
    ///   is not. The diagnosis a maintainer wants: nothing you wrote changed, and something about
    ///   how it was packed did.
    /// - **Stabilized out**, again: the bytes differ and the stabilized forms do not. The case the
    ///   whole tool exists for, and the reason a verdict is `normalized` rather than `exact`.
    /// - **Identical as published**: everything else.
    fn band(&self) -> Band {
        if self.raw_differs() && self.stabilized == (None, None) {
            Band::Stabilized
        } else if self.only_one_side() {
            Band::OneSide
        } else if self.content_differs() {
            Band::Differs
        } else if self.stabilized_differs() {
            Band::Packed
        } else if self.raw_differs() {
            Band::Stabilized
        } else {
            Band::Identical
        }
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

        // By ordinal: the position as parsed, which no pass rewrites, and the key
        // `trigon-stabilize` itself follows an entry across its passes by. Not by name, because
        // two nupkg passes rename — every package's `<guid>.psmdcp` becomes `core.psmdcp` — and a
        // raw row looked up under the new name found nothing and stood in the stabilized one for
        // it.
        let mut raw: std::collections::BTreeMap<u32, (Vec<u8>, String, String, u64)> =
            Default::default();
        for e in &archive.entries {
            let (c, m) = member_fingerprint(e)?;
            raw.insert(e.ordinal, (e.path.as_bytes().to_vec(), c, m, e.meta.size));
        }

        let applied = trigon_stabilize::apply(&set, &mut archive);

        let mut seen: std::collections::BTreeMap<Vec<u8>, usize> = Default::default();
        let mut out = SideMembers::new();
        for e in &archive.entries {
            let path = e.path.as_bytes().to_vec();
            let n = seen.entry(path.clone()).or_default();
            let key = (path.clone(), *n);
            *n += 1;
            let after = member_fingerprint(e)?;
            // Taken out as it is found, so what is left afterwards is what a pass removed. No pass
            // adds a member; one that did would have no published form, and its stabilized one is
            // the only reading there is.
            let (published, raw_c, raw_m, size) = match raw.remove(&e.ordinal) {
                Some(row) => row,
                None => (path, after.0.clone(), after.1.clone(), e.meta.size),
            };
            out.insert(key, (raw_c, raw_m, Some(after), size, published));
        }
        // A member that a pass *removed* has a raw row and no stabilized one. It keeps its
        // published name and has nothing after stabilization, so the join below renders it rather
        // than dropping it — `.signature.p7s` on every package nuget.org serves, for one.
        for (path, c, m, size) in raw.into_values() {
            let n = seen.entry(path.clone()).or_default();
            out.insert((path.clone(), *n), (c, m, None, size, path));
            *n += 1;
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
            published: a.map(|v| String::from_utf8_lossy(&v.4).into_owned()),
            raw: (
                a.map(|v| format!("{}{}", v.0, v.1)),
                b.map(|v| format!("{}{}", v.0, v.1)),
            ),
            stabilized: (
                a.and_then(|v| v.2.as_ref()).map(|(c, m)| format!("{c}{m}")),
                b.and_then(|v| v.2.as_ref()).map(|(c, m)| format!("{c}{m}")),
            ),
            content: (
                a.and_then(|v| v.2.as_ref()).map(|(c, _)| c.clone()),
                b.and_then(|v| v.2.as_ref()).map(|(c, _)| c.clone()),
            ),
            bytes: (a.map(|v| v.3), b.map(|v| v.3)),
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
    let row = sweep.row_at(&v, index);
    let report = read_report(&dir);

    // The target where one is known, the directory's own name where it is not, and the number only
    // when neither is true.
    let name = sweep.name_at(&v, index);

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
            //
            // The same holds for a report whose clock cannot be read — no `finished`, or an
            // instant that will not parse — because the synthetic row carries the same `0.0` for
            // it. Only a sweep's row is a measurement: `results.tsv` wrote the seconds down.
            let duration = match (v.layout, &report) {
                (Layout::Index | Layout::Single, rep) => {
                    match rep.as_ref().and_then(bracket_seconds) {
                        Some(secs) => format!(" · {secs}s"),
                        None => " · <span class=\"note\">no duration recorded</span>".to_string(),
                    }
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
    if let (Some(_), Some(r)) = (&sweep.store, row)
        && r.purl.is_empty()
    {
        // Not looked up. A search for no target at all finds none, and `Lookup::Absent` would then
        // say the store was searched for this one and does not hold it — a claim about a run whose
        // target is unknown, and one that can be false: a run can be recorded and then die before
        // it writes its report.
        // Which of three: a report that is there and will not parse is a torn write, and "it wrote
        // no report" over one is the absent-run reading `View.report` warns against.
        body.push_str(&format!(
            "<h2>Run record</h2><p class=\"note\">nothing on disk says which target this run \
             was{} — so the store was not searched for it. The directory's name is not a record of \
             its target.</p>",
            if report.is_some() {
                " — its report names none"
            } else if dir.join("run.json").is_file() {
                " — its report will not parse"
            } else {
                " — it wrote no report"
            }
        ));
    } else if let (Some(store), Some(r)) = (&sweep.store, row) {
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
            format!("<code>{}</code>", esc(short_hex(d, 16))),
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
    // The sweep it is compared against, refused the same way and for the same reason `trigon score
    // --baseline` refuses a file that is not there. The panel still says so if it goes missing
    // later, but a typo is better answered before anything listens.
    if let Some(b) = &baseline
        && !b.is_dir()
    {
        anyhow::bail!("--baseline {} is not a directory", b.display());
    }
    let sweep = std::sync::Arc::new(Sweep {
        work,
        targets,
        bind: bind.clone(),
        store,
        baseline,
        sources: trigon_registry::SourceCache::default_root(),
    });
    let app = app(sweep);

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

/// Every route, over one sweep.
///
/// Apart from `serve` so a test can put the same router on a port the OS chose and ask it what a
/// browser would, extractors included: `/run/{index}` is the only path parameter anywhere, and
/// what keeps a request string off the filesystem is the extractor refusing anything but a number.
fn app(sweep: std::sync::Arc<Sweep>) -> axum::Router {
    axum::Router::new()
        .route("/", axum::routing::get(board))
        .route("/cluster", axum::routing::get(cluster))
        .route("/run/{index}", axum::routing::get(run))
        .route("/run/{index}/network", axum::routing::get(network))
        .route("/run/{index}/compare", axum::routing::get(compare))
        .route("/run/{index}/source", axum::routing::get(source_page))
        .route("/api/state", axum::routing::get(api_state))
        .with_state(sweep)
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
///
/// The path is the one upstream published, where upstream has the member, because the lower bar
/// reads the published archive and looks each member up by that name. Keyed by the stabilized name
/// instead, every nupkg's `<guid>.psmdcp` — renamed `core.psmdcp` by a pass — was drawn as never
/// compared.
fn member_verdicts(diffs: &[MemberDiff]) -> BTreeMap<String, &'static str> {
    diffs
        .iter()
        .map(|d| {
            let path = d.published.as_ref().unwrap_or(&d.path);
            (path.clone(), d.band().word())
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
    // What the run page calls this run, because this page is one it links to — and the tab says
    // which of the two it is, or a run and its source are two identical tabs.
    let name = sweep.name_at(&v, index);
    let tab = sweep.tab_title(Some(&format!("{name} · source")));

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
        return page(&tab, false, &body, &sweep.bind).into_response();
    };

    let Some((upstream, _)) = artifact_pair(&dir) else {
        body.push_str(
            "<h2>How the source became the artifact</h2><p class=\"note\">the published artifact \
             is not on disk, so its members cannot be read. This page works from bytes rather than \
             from the comparison record, deliberately — see the note below — so a pruned work \
             directory takes it with it.</p>",
        );
        return page(&tab, false, &body, &sweep.bind).into_response();
    };

    let members = match raw_members(&upstream) {
        Ok(m) => m,
        Err(e) => {
            body.push_str(&format!(
                "<h2>How the source became the artifact</h2><p class=\"note\">{}</p>",
                esc(&e)
            ));
            return page(&tab, false, &body, &sweep.bind).into_response();
        }
    };

    // The same cache the rungs fetch into. Read-only: `default_root` computes a path and
    // `checkout_dir` derives a key from it; neither creates anything, which is the property this
    // page needs — `SourceCache::new` makes the directory it is given, and a monitor that created
    // a cache would be a monitor that changed what it observes.
    let checkout = crate::provenance::checkout_dir(&sweep.sources, &src.repo_url, &src.commit);
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

    page(&tab, false, &body, &sweep.bind).into_response()
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
    // `short_hex`, not a byte slice: the commit and the strategy digest are read from a `run.json`,
    // and eight bytes of a hand-edited one can end inside a character.
    let short = |h: &str| esc(short_hex(h, 8));
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
            // Never this host's cache: a directory under the test's own that nobody made.
            sources: work.join("no-source-cache"),
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

    // -----------------------------------------------------------------------------------------
    // The pages, as a browser gets them. Each handler is called the way the router calls it and
    // its body read back, because what these pages promise is a sentence on a page: a helper can
    // hand the right value to a caller that then renders it as the wrong one.
    // -----------------------------------------------------------------------------------------

    fn shared(s: Sweep) -> State<std::sync::Arc<Sweep>> {
        State(std::sync::Arc::new(s))
    }

    async fn text(r: Response) -> String {
        let bytes = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .expect("a page body");
        String::from_utf8(bytes.to_vec()).expect("a page is UTF-8")
    }

    async fn board_page(s: Sweep) -> String {
        text(board(shared(s)).await).await
    }

    async fn run_page(s: Sweep, index: usize) -> String {
        text(run(shared(s), UrlPath(index)).await).await
    }

    async fn network_page(s: Sweep, index: usize) -> String {
        text(network(shared(s), UrlPath(index)).await).await
    }

    async fn compare_page(s: Sweep, index: usize) -> String {
        text(compare(shared(s), UrlPath(index)).await).await
    }

    async fn source_of(s: Sweep, index: usize) -> String {
        text(source_page(shared(s), UrlPath(index)).await).await
    }

    async fn cluster_page(s: Sweep, key: &str) -> Response {
        cluster(shared(s), Query(ClusterQuery { key: key.into() })).await
    }

    async fn api(s: Sweep) -> serde_json::Value {
        serde_json::from_str(&text(api_state(shared(s)).await).await).expect("the API is JSON")
    }

    /// One GET through the real router, on a loopback port the OS chose: the status, and the whole
    /// response with its headers.
    async fn served(s: Sweep, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = app(std::sync::Arc::new(s));
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: watch\r\nConnection: close\r\n\r\n");
        conn.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        server.abort();
        let out = String::from_utf8_lossy(&out).into_owned();
        let status = out
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, out)
    }

    /// A gzipped tarball, one `(path, body, mtime)` per member, in the order given.
    fn tgz(members: &[(&str, &[u8], u64)]) -> Vec<u8> {
        use std::io::Write as _;
        let mut b = ::tar::Builder::new(Vec::new());
        for (path, body, mtime) in members {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(*mtime);
            h.set_cksum();
            b.append_data(&mut h, path, *body).unwrap();
        }
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    /// A stored zip, one `(path, body, unix mode)` per member.
    fn zip_of(members: &[(&str, &[u8], u32)]) -> Vec<u8> {
        use std::io::Write as _;
        let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (path, body, mode) in members {
            let opts: zip_crate::write::FileOptions<'_, ()> =
                zip_crate::write::FileOptions::default()
                    .compression_method(zip_crate::CompressionMethod::Stored)
                    .last_modified_time(zip_crate::DateTime::default())
                    .unix_permissions(*mode);
            w.start_file(*path, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// A single rebuild's work directory as a run leaves it: `run.json`, the published artifact at
    /// the root under the registry's file name, and the rebuilt one under `rebuild/<run id>/`.
    fn one_run(name: &str, report: &str, file: &str, upstream: &[u8], rebuild: &[u8]) -> PathBuf {
        let w = work_dir(name);
        put(w.join("run.json"), report);
        std::fs::write(w.join(file), upstream).unwrap();
        let built = w.join("rebuild").join("1789000000-run");
        std::fs::create_dir_all(&built).unwrap();
        std::fs::write(built.join(file), rebuild).unwrap();
        w
    }

    /// A `run.json` with the fields most tests do not care about filled in.
    fn run_json(purl: &str, outcome: &str) -> String {
        serde_json::json!({
            "purl": purl,
            "started": "2026-09-17T19:57:42Z",
            "finished": "2026-09-17T19:58:42Z",
            "outcome": outcome,
            "model_calls": 0,
        })
        .to_string()
    }

    fn sweep_json(sha: Option<&str>, count: usize, timeout: u64, finished: Option<&str>) -> String {
        serde_json::json!({
            "started": "2026-09-17T19:57:42Z",
            "pid": 1,
            "version": "0.0.0",
            "targets_path": null,
            "targets_sha256": sha,
            "targets_count": count,
            "resumed_from": 0,
            "image": "docker.io/library/debian@sha256:aa",
            "egress": "mirror-only",
            "timewarp": null,
            "model": null,
            "store": null,
            "definitions": null,
            "timeout_seconds": timeout,
            "finished": finished,
        })
        .to_string()
    }

    /// The target in flight, as a heartbeat carries it.
    fn in_flight(
        purl: &str,
        elapsed: u64,
        phase: Option<&str>,
        in_phase: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "index": 1,
            "purl": purl,
            "started": "2026-09-17T19:57:42Z",
            "elapsed_seconds": elapsed,
            "phase": phase,
            "phase_elapsed_seconds": in_phase,
        })
    }

    fn status_json(
        state: &str,
        heartbeat: &str,
        pid: u32,
        current: Option<serde_json::Value>,
    ) -> String {
        serde_json::json!({
            "heartbeat": heartbeat,
            "pid": pid,
            "state": state,
            "done": 1,
            "total": 7,
            "current": current,
        })
        .to_string()
    }

    /// `results.tsv`, one `(purl, label)` per row.
    fn results(rows: &[(&str, &str)]) -> String {
        rows.iter()
            .map(|(purl, label)| format!("{purl}\t{label}\t1.0\t\t0\n"))
            .collect()
    }

    const XSS: &str = "<img src=x onerror=alert(1)>";

    // --- what reaches the filesystem, and what reaches the page ----------------------------------

    #[tokio::test]
    async fn the_only_path_parameter_reaches_the_filesystem_as_a_number_or_not_at_all() {
        // `/run/{index}` is the one request string joined to a path, and what keeps it off the
        // filesystem is the extractor refusing anything that is not an integer. A secret beside
        // the work directory stands in for what a traversal would be after.
        let root = work_dir("path-parameter");
        put(root.join("secret.txt"), "the-secret-contents");
        let w = root.join("work");
        put(w.join("run.json"), &run_json("pkg:npm/a@1", "exact"));

        for path in [
            "/run/..%2Fsecret.txt",
            "/run/..%2F..%2Fsecret.txt",
            "/run/../secret.txt",
            "/run/-1",
            "/run/1e3",
            "/run/18446744073709551616",
            "/run/0/network/..%2F..%2Fsecret.txt",
        ] {
            let (status, page) = served(sweep_at(w.clone()), path).await;
            assert!(
                (400..500).contains(&status),
                "`{path}` was answered {status}, not refused:\n{page}"
            );
            assert!(!page.contains("the-secret-contents"), "`{path}`:\n{page}");
        }
        // And the number itself is served.
        let (status, page) = served(sweep_at(w), "/run/0").await;
        assert_eq!(status, 200, "{page}");
        assert!(page.contains("<h1>npm/a@1</h1>"), "{page}");
    }

    #[tokio::test]
    async fn a_cluster_key_survives_the_round_trip_through_the_board_s_link() {
        // A real key carries slashes and colons, and its subject is whatever the log said — a
        // space, an ampersand, a name that is not ASCII. The board writes the link, the router
        // decodes it, and the page at the end has to be the cluster the link was for.
        let key = "cc/missing-header:python h&x=é";
        let w = work_dir("cluster-link");
        put(
            w.join("results.tsv"),
            &format!(
                "pkg:npm/a@1\tbuild-failed:deps\t1.0\t{key}\t0\npkg:npm/b@1\texact\t1.0\t\t0\n"
            ),
        );
        let board = board_page(sweep_at(w.clone())).await;
        let href = board
            .split("href=\"/cluster?key=")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("the board links the cluster")
            .to_string();
        assert!(!href.contains('&') && !href.contains(' '), "{href}");

        let (status, page) = served(sweep_at(w.clone()), &format!("/cluster?key={href}")).await;
        assert_eq!(status, 200, "{page}");
        assert!(
            page.contains(&format!("<h1><code>{}</code></h1>", esc(key))),
            "{page}"
        );
        assert!(page.contains("1 target(s) failed this way"), "{page}");

        // A key nothing carries is not an empty cluster page: it goes back to the board.
        let (status, page) = served(sweep_at(w), "/cluster?key=nobody").await;
        assert_eq!(status, 303, "{page}");
        assert!(
            page.to_ascii_lowercase().contains("\r\nlocation: /\r\n"),
            "{page}"
        );
    }

    #[tokio::test]
    async fn nothing_a_package_wrote_reaches_a_page_as_markup() {
        // Every string on these pages came from a package or from a build it controlled
        // (`docs/12-security.md` §4). One payload in every field of `run.json` a page renders, in
        // the build log, the strategy, the guard manifest, the transcript and a member's name —
        // and every page that shows any of them is read.
        let report = serde_json::json!({
            "purl": format!("pkg:npm/{XSS}@1"),
            "started": "2026-09-17T19:57:42Z",
            "finished": "2026-09-17T19:58:42Z",
            "outcome": "build-failed:deps",
            "void_reason": XSS,
            "failure": {"code": "npm/peer-conflict", "subject": XSS, "fault": "build",
                        "retryable": false, "repairable": true, "evidence": XSS},
            "source": {"repo_url": XSS, "declared_url": XSS, "commit": XSS, "ref_name": XSS,
                       "subdir": XSS, "how": "exact_tag"},
            "assumptions": [XSS],
            "guard_notes": [XSS],
            "timings": [[XSS, 1.0]],
            "hosts": {XSS: {"requests": 1, "throttled": 0, "failed": 0}},
            "repairs": [XSS],
            "repair_stopped": XSS,
            "model": XSS,
            "model_calls": 1,
            "derivation": XSS,
            "confidence": XSS,
            "egress": XSS,
            "strategy_digest": XSS,
            "fetch_cache": {"hits": 1, "fetched": 1, "oldest_index_snapshot": XSS},
        })
        .to_string();
        let member = format!("package/{XSS}.js");
        let w = one_run(
            "escape-everything",
            &report,
            "a-1.tgz",
            &tgz(&[(&member, b"published", 1)]),
            &tgz(&[(&member, b"rebuilt", 1)]),
        );
        put(
            w.join("rebuild").join("build.log"),
            "<script>alert(1)</script>\n",
        );
        put(w.join("strategy.yaml"), XSS);
        put(w.join("guard.json"), XSS);
        put(
            w.join("rebuild").join("network.jsonl"),
            &format!(
                "{}\n",
                serde_json::json!({"route": XSS, "url": XSS, "sha256": XSS, "bytes": 1,
                                   "checked": "opened"})
            ),
        );
        let key = format!("npm/peer-conflict:{XSS}");

        // The verdict sentence says one thing, in precedence order, so a void hides the two
        // answers it outranks: an error of ours, and the rungs' declines. Each gets a run of its
        // own, and the second carries the payload as its outcome, since nothing above it does.
        let errored = work_dir("escape-error");
        put(
            errored.join("run.json"),
            &serde_json::json!({"purl": "pkg:npm/a@1", "started": XSS, "finished": XSS,
                                "error": XSS, "model_calls": 0})
            .to_string(),
        );
        let declined = one_run(
            "escape-declines",
            &serde_json::json!({"purl": "pkg:npm/a@1", "started": "2026-09-17T19:57:42Z",
                                "finished": "2026-09-17T19:58:42Z", "outcome": XSS,
                                "declines": [XSS], "model_calls": 0})
            .to_string(),
            "a-1.tgz",
            &tgz(&[("package/a.js", b"published", 1)]),
            &tgz(&[("package/a.js", b"rebuilt", 1)]),
        );
        // And a directory of runs, whose board is a different renderer: one directory named with
        // the payload — a directory's name is whatever the caller passed to `--work` — and one
        // whose record names the payload as its target and its source.
        let shelf = work_dir("escape-shelf");
        put(shelf.join(XSS).join("strategy.yaml"), "id: x\n");
        put(
            shelf.join("b").join("run.json"),
            &serde_json::json!({
                "purl": format!("pkg:npm/{XSS}@1"),
                "started": "2026-09-17T19:57:42Z",
                "finished": "2026-09-17T19:58:42Z",
                "outcome": "build-failed:deps",
                "failure": {"code": "npm/peer-conflict", "subject": XSS, "fault": "build",
                            "retryable": false, "repairable": true, "evidence": XSS},
                "source": {"repo_url": XSS, "commit": XSS, "subdir": XSS, "how": "exact_tag"},
                "model_calls": 0,
            })
            .to_string(),
        );

        let pages = [
            ("board", board_page(sweep_at(w.clone())).await),
            ("run", run_page(sweep_at(w.clone()), 0).await),
            ("network", network_page(sweep_at(w.clone()), 0).await),
            ("compare", compare_page(sweep_at(w.clone()), 0).await),
            ("source", source_of(sweep_at(w.clone()), 0).await),
            ("cluster", text(cluster_page(sweep_at(w), &key).await).await),
            ("errored run", run_page(sweep_at(errored), 0).await),
            (
                "declined board",
                board_page(sweep_at(declined.clone())).await,
            ),
            (
                "declined run",
                run_page(sweep_at(declined.clone()), 0).await,
            ),
            (
                "declined compare",
                compare_page(sweep_at(declined), 0).await,
            ),
            ("shelf board", board_page(sweep_at(shelf.clone())).await),
            ("shelf run", run_page(sweep_at(shelf.clone()), 0).await),
            (
                "shelf network",
                network_page(sweep_at(shelf.clone()), 0).await,
            ),
            (
                "shelf compare",
                compare_page(sweep_at(shelf.clone()), 0).await,
            ),
            ("shelf source", source_of(sweep_at(shelf.clone()), 0).await),
            (
                "shelf's other run",
                run_page(sweep_at(shelf.clone()), 1).await,
            ),
            (
                "shelf's other source",
                source_of(sweep_at(shelf.clone()), 1).await,
            ),
            (
                "shelf cluster",
                text(cluster_page(sweep_at(shelf), &key).await).await,
            ),
        ];
        let shown = "&lt;img src=x onerror=alert(1)&gt;";
        for (name, page) in &pages {
            assert!(
                !page.contains("<img") && !page.contains("<script"),
                "the {name} page rendered a package's string as markup:\n{page}"
            );
            assert!(
                page.contains(shown),
                "the {name} page should show the string, escaped, rather than drop it:\n{page}"
            );
        }
        // Each field is on its page, and not merely some other field that carries the payload: a
        // renderer that dropped one would pass the loop above on the strength of its neighbours.
        let on = |which: &str, what: String| {
            let page = &pages.iter().find(|(n, _)| *n == which).unwrap().1;
            assert!(
                page.contains(&what),
                "the {which} page is missing `{what}`:\n{page}"
            );
        };
        on(
            "errored run",
            format!("an error of ours.</strong> {shown}<br>"),
        );
        on("declined run", format!("<li>{shown}</li>"));
        on("declined board", format!(">{shown}</span>"));
        on(
            "declined compare",
            format!("It read <strong>{shown}</strong>"),
        );
        on(
            "shelf board",
            format!("<a href=\"/run/0\"><code>{shown}</code></a>"),
        );
        on(
            "shelf board",
            format!("<a href=\"/run/1\">npm/{shown}@1</a>"),
        );
        on(
            "shelf board",
            format!("<code>{shown}</code>@<code title=\"{shown}\">"),
        );
        on("shelf board", format!("<span class=\"dim\">{shown}</span>"));
        on("shelf source", format!("<h1>{shown}</h1>"));
        on("shelf's other source", format!("<h1>npm/{shown}@1</h1>"));
    }

    // --- the store: four answers, not one `None` ------------------------------------------------

    fn record(id: &str, target: &str) -> trigon_store::RunRecord {
        let upstream = b"the published bytes";
        trigon_store::RunRecord::new(
            id,
            target,
            trigon_store::ArtifactRef {
                name: "a-1.tgz".into(),
                sha256: trigon_store::digest_of(upstream),
                bytes: upstream.len() as u64,
                stored: false,
            },
            trigon_store::Environment {
                base_image: "docker.io/library/debian@sha256:aa".into(),
                egress: "mirror-only".into(),
                isolation: "user_ns".into(),
                attestable: true,
                registry_moment: None,
                pin: None,
                guard_manifest: None,
                derived_image: None,
                guarded_members: None,
            },
            "2026-09-17T19:57:42Z",
        )
    }

    #[tokio::test]
    async fn a_store_path_that_is_not_there_is_our_mistake_and_stays_not_there() {
        // A mistyped `--store` used to render the sentence a run genuinely absent from a store
        // gets — which explains the absence as the run being evidence of nothing. Our own
        // configuration error, told to the reader as a finding about their package. And the page
        // is read-only: it must not make the store it was pointed at.
        let w = work_dir("store-missing");
        put(w.join("run.json"), &run_json("pkg:npm/a@1", "exact"));
        let store = w.join("no-such-store");
        let page = run_page(
            Sweep {
                store: Some(store.clone()),
                ..sweep_at(w)
            },
            0,
        )
        .await;
        assert!(page.contains("could not be opened"), "{page}");
        assert!(
            page.contains("a problem with <code>--store</code>, not with the run"),
            "{page}"
        );
        assert!(
            !page.contains("evidence of nothing"),
            "a mistyped path must not explain a run away:\n{page}"
        );
        assert!(
            !store.exists(),
            "a read-only page created the store it was asked to read"
        );
    }

    #[tokio::test]
    async fn a_run_whose_target_is_not_known_is_not_looked_up_under_no_target() {
        // A run that left no report has an empty purl, because nothing on disk says which target
        // it was. Looking that up searched the store for `""` and reported the run absent from it —
        // "none of them is this target" about a target nobody named, with the sentence that
        // explains an absence as a run that was evidence of nothing.
        //
        // A report that is there and will not parse leaves the same empty purl, and it is a torn
        // write rather than no report: the note says which.
        let w = work_dir("store-no-target");
        put(w.join("half-a-run").join("strategy.yaml"), "id: x\n");
        put(w.join("torn").join("run.json"), "{");
        let store = w.join("store");
        trigon_store::Store::local(&store).unwrap();
        for (index, why) in [(0, "it wrote no report"), (1, "its report will not parse")] {
            let page = run_page(
                Sweep {
                    store: Some(store.clone()),
                    ..sweep_at(w.clone())
                },
                index,
            )
            .await;
            assert!(!page.contains("none of them is this target"), "{page}");
            assert!(!page.contains("evidence of nothing"), "{page}");
            assert!(
                page.contains(&format!(
                    "<h2>Run record</h2><p class=\"note\">nothing on disk says which target this \
                     run was — {why} — so the store was not searched for it"
                )),
                "{page}"
            );
        }
    }

    #[tokio::test]
    async fn an_empty_store_and_a_store_without_this_target_are_different_answers() {
        let dir = work_dir("store-absent").join("store");
        let store = trigon_store::Store::local(&dir).unwrap();
        let empty = store_panel(&dir, "pkg:npm/a@1").await;
        assert!(
            empty.contains("holds 0 run(s)") && empty.contains("because it holds none at all"),
            "{empty}"
        );

        store
            .put_run(&record("1789000000-other", "pkg:npm/other@1"))
            .await
            .unwrap();
        let other = store_panel(&dir, "pkg:npm/a@1").await;
        assert!(
            other.contains("holds 1 run(s) and none of them is this target (read in"),
            "{other}"
        );
        assert!(!other.contains("none at all"), "{other}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_store_whose_runs_cannot_be_listed_is_unknown_rather_than_empty() {
        // Opened, and its index could not be read: whether this target is in it is not known, and
        // "none of them is this target" would be a claim the page never checked.
        let dir = work_dir("store-unlistable").join("store");
        std::fs::create_dir_all(&dir).unwrap();
        // `runs` is a link to itself, so the store opens and listing it cannot finish.
        std::os::unix::fs::symlink("runs", dir.join("runs")).unwrap();
        let page = store_panel(&dir, "pkg:npm/a@1").await;
        assert!(page.contains("could not be listed"), "{page}");
        assert!(page.contains("unknown rather than no"), "{page}");
        assert!(!page.contains("none of them is this target"), "{page}");
    }

    #[tokio::test]
    async fn a_record_that_says_its_bytes_are_kept_is_checked_against_the_store() {
        // The record's word alone would show bytes the store has lost as present.
        let dir = work_dir("store-kept").join("store");
        let store = trigon_store::Store::local(&dir).unwrap();
        let kept = store
            .blobs()
            .put(b"rebuilt and kept".to_vec())
            .await
            .unwrap();
        let lost = trigon_store::digest_of(b"named as kept and never put");
        let rebuild = |sha256, stored| {
            Some(trigon_store::ArtifactRef {
                name: "a-1.tgz".into(),
                sha256,
                bytes: 16,
                stored,
            })
        };
        for (id, target, artifact) in [
            ("1789000001-kept", "pkg:npm/kept@1", rebuild(kept, true)),
            ("1789000002-lost", "pkg:npm/lost@1", rebuild(lost, true)),
            (
                "1789000003-pruned",
                "pkg:npm/pruned@1",
                rebuild(kept, false),
            ),
            ("1789000004-none", "pkg:npm/none@1", None),
        ] {
            let mut r = record(id, target);
            r.outcome = Some("divergent".into());
            r.rebuild = artifact;
            store.put_run(&r).await.unwrap();
        }

        let panel = store_panel(&dir, "pkg:npm/kept@1").await;
        assert!(panel.contains(&kept.to_hex()[..16]), "{panel}");
        assert!(
            !panel.contains("bytes missing") && !panel.contains("bytes pruned"),
            "{panel}"
        );
        let panel = store_panel(&dir, "pkg:npm/lost@1").await;
        assert!(
            panel.contains(
                "bytes missing: the record says they are kept, and the store has no blob of them"
            ),
            "{panel}"
        );
        let panel = store_panel(&dir, "pkg:npm/pruned@1").await;
        assert!(panel.contains("bytes pruned"), "{panel}");
        assert!(!panel.contains("bytes missing"), "{panel}");
        let panel = store_panel(&dir, "pkg:npm/none@1").await;
        assert!(
            panel.contains("<td class=\"dim\">rebuild</td><td><span class=\"note\">none recorded"),
            "{panel}"
        );
    }

    #[tokio::test]
    async fn a_run_record_leaves_out_what_it_did_not_measure_rather_than_printing_zero() {
        // `docs/03` §3: on this record `None` means no data and never zero.
        let dir = work_dir("store-costs").join("store");
        let store = trigon_store::Store::local(&dir).unwrap();
        let mut r = record("1789000001-costs", "pkg:npm/costs@1");
        r.outcome = Some("normalized".into());
        r.environment.attestable = false;
        r.environment.pin = Some(trigon_store::PinEvidence {
            index_requests: 3,
            versions_withheld: 1,
            artifact_requests: 2,
            toolchain_requests: 0,
            rejected: 0,
        });
        r.costs = Some(trigon_store::Costs {
            build_seconds: Some(12.34),
            tokens: vec![
                trigon_store::Tokens {
                    input: 100,
                    cached_input: 0,
                    output: 20,
                    model: "m-a".into(),
                    calls: 1,
                },
                trigon_store::Tokens {
                    input: 7,
                    cached_input: 0,
                    output: 8,
                    model: "m<b>".into(),
                    calls: 3,
                },
            ],
            egress_bytes: Some(1_048_576),
            ..Default::default()
        });
        r.derivation = Some("heuristic".into());
        r.guard_trips = vec!["lib/a.js arrived and shipped".into()];
        r.attestations = vec!["a".into(), "b".into()];
        store.put_run(&r).await.unwrap();

        let mut bare = record("1789000002-bare", "pkg:npm/bare@1");
        bare.costs = Some(trigon_store::Costs::default());
        bare.environment.pin = Some(trigon_store::PinEvidence {
            index_requests: 0,
            versions_withheld: 0,
            artifact_requests: 0,
            toolchain_requests: 0,
            rejected: 0,
        });
        bare.network_transcript = None;
        store.put_run(&bare).await.unwrap();

        let p = store_panel(&dir, "pkg:npm/costs@1").await;
        assert!(p.contains("12.3s building"), "{p}");
        assert!(
            !p.contains("inference"),
            "an unmeasured phase is left out:\n{p}"
        );
        assert!(p.contains("100 in / 20 out over 1 call to m-a"), "{p}");
        assert!(p.contains("7 in / 8 out over 3 calls to m&lt;b&gt;"), "{p}");
        assert!(
            p.contains("1.0 MB fetched") && !p.contains("bytes fetched"),
            "{p}"
        );
        assert!(p.contains("mirror-only · no network transcript"), "{p}");
        assert!(p.contains("the pin bound"), "{p}");
        assert!(
            p.contains("<span class=\"void\">lib/a.js arrived and shipped</span>"),
            "{p}"
        );
        assert!(p.contains("2 statement(s)"), "{p}");
        assert!(
            p.contains("<td class=\"dim\">derivation</td><td>heuristic"),
            "{p}"
        );

        let p = store_panel(&dir, "pkg:npm/bare@1").await;
        assert!(
            !p.contains("<td class=\"dim\">cost</td>"),
            "a cost with nothing measured is no row, not a row of zeroes:\n{p}"
        );
        assert!(
            p.contains("no transcript: this run cannot say what the build fetched"),
            "{p}"
        );
        assert!(p.contains("egress fully accounted for"), "{p}");
        assert!(
            p.contains("the pin cannot be confirmed from this run"),
            "{p}"
        );
        assert!(!p.contains("statement(s)"), "{p}");

        // What was measured is printed, in its unit, and a transcript is named by its digest.
        let transcript = trigon_store::digest_of(b"the transcript");
        let mut measured = record("1789000003-measured", "pkg:npm/measured@1");
        measured.costs = Some(trigon_store::Costs {
            inference_seconds: Some(3.0),
            ..Default::default()
        });
        measured.network_transcript = Some(transcript);
        store.put_run(&measured).await.unwrap();
        let p = store_panel(&dir, "pkg:npm/measured@1").await;
        assert!(
            p.contains("<td class=\"dim\">cost</td><td>3.0s inference</td>"),
            "{p}"
        );
        assert!(
            p.contains(&format!(
                "transcript <code>{}</code>",
                &transcript.to_hex()[..16]
            )),
            "{p}"
        );
    }

    // --- a sweep's state, and what the strip says about it ---------------------------------------

    #[tokio::test]
    async fn every_sweep_state_is_named_and_only_a_live_one_keeps_refreshing() {
        // Each state is a different instruction to the reader — wait, look, or stop waiting — and
        // a page that keeps refreshing after the sweep is gone is what a stale page looks like
        // pretending to be alive.
        let now = crate::now_rfc3339();
        let me = std::process::id();
        let long_ago = "2020-01-01T00:00:00Z";
        let refresh = "<meta http-equiv=\"refresh\"";
        let cases = [
            (
                "live-finished",
                Some(status_json("finished", long_ago, me, None)),
                sweep_json(None, 7, 60, Some("2026-09-17T20:00:00Z")),
                "finished",
                "finished at 2026-09-17T20:00:00Z",
                false,
            ),
            (
                "live-unresponsive",
                Some(status_json("running", long_ago, me, None)),
                sweep_json(None, 7, 60, None),
                "UNRESPONSIVE",
                "the heartbeat stopped and the process is still there",
                false,
            ),
            (
                "live-stuck",
                Some(status_json(
                    "running",
                    &now,
                    me,
                    Some(in_flight("pkg:npm/a@1", 600, Some("deps"), 65)),
                )),
                sweep_json(None, 7, 60, None),
                "STUCK",
                "on npm/a@1 for 600s, in <strong>deps</strong> for 65s — past the 60s ceiling",
                true,
            ),
            (
                "live-running",
                Some(status_json(
                    "running",
                    &now,
                    me,
                    Some(in_flight("pkg:npm/a@1", 125, Some("deps"), 65)),
                )),
                sweep_json(None, 7, 3600, None),
                "running",
                "on npm/a@1 for 2m, in <strong>deps</strong> for 65s",
                true,
            ),
            (
                "live-between",
                Some(status_json("running", &now, me, None)),
                sweep_json(None, 7, 3600, None),
                "running",
                "between targets",
                true,
            ),
            (
                "live-starting",
                Some(status_json("starting", &now, me, None)),
                sweep_json(None, 7, 3600, None),
                "starting",
                "no target has been attempted yet",
                true,
            ),
            (
                "live-unreadable",
                Some("{\"heartbeat\":".to_string()),
                sweep_json(None, 7, 3600, None),
                "state unreadable",
                "status.json is present and did not parse",
                false,
            ),
            (
                "live-unknown",
                None,
                sweep_json(None, 7, 3600, None),
                "state unknown",
                "this directory has no status.json",
                false,
            ),
        ];
        for (name, status, sweep, word, detail, live) in cases {
            let w = work_dir(name);
            put(w.join("results.tsv"), &results(&[("pkg:npm/z@1", "exact")]));
            put(w.join("sweep.json"), &sweep);
            if let Some(s) = status {
                put(w.join("status.json"), &s);
            }
            let page = board_page(sweep_at(w)).await;
            assert!(
                page.contains(&format!("<strong>{word}</strong>")),
                "{name}:\n{page}"
            );
            assert!(page.contains(detail), "{name}:\n{page}");
            assert_eq!(
                page.contains(refresh),
                live,
                "{name} refreshes wrongly:\n{page}"
            );
        }

        // A dead pid needs `/proc` to be seen as dead: without it the page must not guess, and
        // an unknown pid is read as alive.
        if Path::new("/proc").is_dir() {
            let w = work_dir("live-stopped");
            put(w.join("results.tsv"), &results(&[("pkg:npm/z@1", "exact")]));
            // Past the kernel's ceiling on pid numbers, so no process has it.
            put(
                w.join("status.json"),
                &status_json("running", long_ago, u32::MAX, None),
            );
            let page = board_page(sweep_at(w)).await;
            assert!(page.contains("<strong>stopped</strong>"), "{page}");
            assert!(
                page.contains(
                    "the target it was on has no outcome, which is not the same as failing"
                ),
                "{page}"
            );
            assert!(!page.contains(refresh), "{page}");
        }
    }

    #[tokio::test]
    async fn a_sweep_counts_against_its_corpus_and_links_each_row_to_the_directory_it_numbered() {
        // The sweep names each evidence directory by the target's line in the targets file, so a
        // row that landed second may live in `000`. Comments and blank lines are not targets.
        let w = work_dir("corpus");
        let targets = w.join("targets.txt");
        put(
            targets.clone(),
            "# the corpus\n\npkg:npm/b@1\n  pkg:npm/a@1  \n\npkg:npm/c@1\n",
        );
        put(
            w.join("results.tsv"),
            &results(&[("pkg:npm/a@1", "exact"), ("pkg:npm/b@1", "divergent")]),
        );
        let s = Sweep {
            targets: Some(targets.clone()),
            ..sweep_at(w.clone())
        };
        let v = s.read();
        assert_eq!(
            v.targets,
            Some(vec![
                "pkg:npm/b@1".to_string(),
                "pkg:npm/a@1".into(),
                "pkg:npm/c@1".into()
            ])
        );
        let strip = state_strip(&v, s.targets.as_deref());
        assert!(strip.contains("2 of 3 attempted"), "{strip}");
        assert!(
            strip.contains(&format!("targets {}", targets.display())),
            "{strip}"
        );
        let page = board_page(s).await;
        assert!(page.contains("<a href=\"/run/1\">npm/a@1</a>"), "{page}");
        assert!(page.contains("<a href=\"/run/0\">npm/b@1</a>"), "{page}");

        // Without a targets file, the count the sweep recorded about itself.
        put(w.join("sweep.json"), &sweep_json(None, 7, 60, None));
        let strip = state_strip(&sweep_at(w.clone()).read(), None);
        assert!(strip.contains("2 of 7 attempted"), "{strip}");

        // And without either, the total is unknown rather than the number attempted.
        let bare = work_dir("corpus-unknown");
        put(
            bare.join("results.tsv"),
            &results(&[("pkg:npm/a@1", "exact")]),
        );
        let strip = state_strip(&sweep_at(bare).read(), None);
        assert!(
            strip.contains("1 attempted, of an unknown total"),
            "{strip}"
        );
    }

    #[tokio::test]
    async fn a_row_the_corpus_does_not_name_links_nowhere_and_an_uncounted_column_is_a_dash() {
        // A resumed sweep can carry a row for a target its current targets file no longer lists.
        // Its directory number would be a guess, and a guessed link opens somebody else's run.
        let w = work_dir("corpus-stray-row");
        let targets = w.join("targets.txt");
        put(targets.clone(), "pkg:npm/a@1\n");
        put(
            w.join("results.tsv"),
            "pkg:npm/a@1\texact\t1.0\t\t0\npkg:npm/gone@1\tdivergent\t2.0\n",
        );
        let page = board_page(Sweep {
            targets: Some(targets),
            ..sweep_at(w)
        })
        .await;
        assert!(page.contains("<a href=\"/run/0\">npm/a@1</a>"), "{page}");
        assert!(page.contains("<tr><td>npm/gone@1</td>"), "{page}");
        assert!(!page.contains("/run/1"), "{page}");
        // A row written before the model column existed did not count, and must not read as 0.
        assert!(
            page.contains("<td class=\"n\"><span class=\"note\">—</span></td></tr>"),
            "{page}"
        );
    }

    #[tokio::test]
    async fn a_sweep_that_has_written_nothing_yet_says_so_rather_than_showing_empty_tables() {
        // `sweep.json` is written before the first target; `results.tsv` only after it.
        let w = work_dir("sweep-before-results");
        put(w.join("sweep.json"), &sweep_json(None, 7, 60, None));
        let s = sweep_at(w);
        let v = s.read();
        assert_eq!(v.layout, Layout::Sweep);
        assert_eq!(board_panel(&s, &v), "", "no rows is no table");
        let page = board_page(s).await;
        assert!(
            page.contains(
                "no results.tsv here yet — either the sweep has not finished its first \
                 target, or this is not a sweep work directory"
            ),
            "{page}"
        );
        assert!(page.contains("0 of 7 attempted"), "{page}");
        assert!(page.contains("nothing has been attempted"), "{page}");

        // A finished sweep that recorded no finishing time says finished, and no more.
        let done = work_dir("sweep-finished-untimed");
        put(
            done.join("results.tsv"),
            &results(&[("pkg:npm/a@1", "exact")]),
        );
        put(
            done.join("status.json"),
            &status_json("finished", "2020-01-01T00:00:00Z", 1, None),
        );
        let page = board_page(sweep_at(done)).await;
        assert!(
            page.contains("<strong>finished</strong>")
                && page.contains("<span class=\"note\">finished</span>"),
            "{page}"
        );

        // A work directory that does not exist is not a directory of runs.
        let v = sweep_at(work_dir("sweep-missing").join("nowhere")).read();
        assert_eq!(v.layout, Layout::Unknown);
    }

    #[test]
    fn a_quiet_results_file_and_a_torn_row_are_both_said_out_loud() {
        let w = work_dir("quiet-results");
        put(
            w.join("results.tsv"),
            "pkg:npm/a@1\texact\t1.0\t\t0\npkg:npm/b@1\texact\tnot-a-number\t\t0\n",
        );
        let fresh = state_strip(&sweep_at(w.clone()).read(), None);
        assert!(!fresh.contains("nothing new for a while"), "{fresh}");
        assert!(
            fresh.contains("1 line(s) in results.tsv did not parse and were dropped"),
            "{fresh}"
        );

        std::fs::File::options()
            .write(true)
            .open(w.join("results.tsv"))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(7200))
            .unwrap();
        let quiet = state_strip(&sweep_at(w).read(), None);
        assert!(
            quiet.contains("last result 2h ago — nothing new for a while"),
            "{quiet}"
        );
    }

    #[test]
    fn a_single_run_says_how_long_it_took_or_exactly_why_it_cannot() {
        let strip = |name: &str, file: &str, body: &str| {
            let w = work_dir(name);
            put(w.join(file), body);
            let v = sweep_at(w).read();
            assert_eq!(v.layout, Layout::Single, "{name}");
            state_strip(&v, None)
        };
        let report = |started: &str, finished: Option<&str>| {
            serde_json::json!({"purl": "pkg:npm/a@1", "started": started, "finished": finished,
                               "model_calls": 0})
            .to_string()
        };
        let t0 = "2026-09-17T19:57:42Z";

        let whole = strip(
            "single-whole",
            "run.json",
            &report(t0, Some("2026-09-17T19:58:42Z")),
        );
        assert!(
            whole.contains("one run · pkg:npm/a@1 · 60s end to end"),
            "{whole}"
        );
        let died = strip("single-died", "run.json", &report(t0, None));
        assert!(
            died.contains("no finish recorded: the process did not reach the end of the run"),
            "{died}"
        );
        let odd_finish = strip(
            "single-odd-finish",
            "run.json",
            &report(t0, Some("yesterday")),
        );
        assert!(
            odd_finish.contains("finished at an instant this page cannot read"),
            "{odd_finish}"
        );
        // A start that will not parse is not a process that died: this one wrote its finish.
        let odd_start = strip(
            "single-odd-start",
            "run.json",
            &report("last tuesday", Some("2026-09-17T19:58:42Z")),
        );
        assert!(
            odd_start.contains("started at an instant this page cannot read"),
            "{odd_start}"
        );
        assert!(
            !odd_start.contains("did not reach the end of the run"),
            "a run that wrote its finish is reported as having died:\n{odd_start}"
        );
        let torn = strip("single-torn", "run.json", "{\"purl\":");
        assert!(torn.contains("a torn write, not an absent run"), "{torn}");
        let no_report = strip("single-no-report", "strategy.yaml", "id: x\n");
        assert!(
            no_report.contains("no run.json, so this page is reading the files a rebuild leaves"),
            "{no_report}"
        );
    }

    #[tokio::test]
    async fn a_run_whose_clock_cannot_be_read_shows_no_duration_rather_than_zero_seconds() {
        // The synthetic row a report makes carries `0.0` where its clock cannot be read, and that
        // is a placeholder, not a measurement. The run page printed it as `0s` for every run that
        // died before writing its finish — which is exactly the run a reader opens.
        let w = work_dir("no-clock");
        put(
            w.join("pkg-npm-a@1").join("run.json"),
            r#"{"purl":"pkg:npm/a@1","started":"2026-09-17T19:57:42Z","outcome":"error:infra",
                "error":"podman went away","model_calls":0}"#,
        );
        put(
            w.join("pkg-npm-b@1").join("run.json"),
            r#"{"purl":"pkg:npm/b@1","started":"2026-09-17T19:57:42Z",
                "finished":"2026-09-17T19:59:12Z","outcome":"exact","model_calls":0}"#,
        );
        let died = run_page(sweep_at(w.clone()), 0).await;
        assert!(
            died.contains("no duration recorded") && !died.contains("· 0s"),
            "{died}"
        );
        let whole = run_page(sweep_at(w), 1).await;
        assert!(whole.contains("· 90s"), "{whole}");

        let one = work_dir("no-clock-single");
        put(
            one.join("run.json"),
            r#"{"purl":"pkg:npm/a@1","started":"2026-09-17T19:57:42Z","outcome":"void",
                "model_calls":0}"#,
        );
        let page = run_page(sweep_at(one), 0).await;
        assert!(
            page.contains("no duration recorded") && !page.contains("· 0s"),
            "{page}"
        );

        // A sweep's row is a measurement: `results.tsv` wrote the seconds down.
        let sweep = work_dir("no-clock-sweep");
        put(sweep.join("results.tsv"), "pkg:npm/a@1\texact\t0.0\t\t0\n");
        let page = run_page(sweep_at(sweep), 0).await;
        assert!(page.contains("· 0s"), "{page}");
    }

    #[tokio::test]
    async fn the_api_names_the_layout_and_hands_a_script_the_sentence_a_reader_sees() {
        let unknown = work_dir("api-unknown");
        assert_eq!(api(sweep_at(unknown)).await["layout"], "unknown");
        let single = work_dir("api-single");
        put(single.join("run.json"), &run_json("pkg:npm/a@1", "exact"));
        assert_eq!(api(sweep_at(single)).await["layout"], "single");
        let index = work_dir("api-index");
        put(
            index.join("a").join("run.json"),
            &run_json("pkg:npm/a@1", "exact"),
        );
        assert_eq!(api(sweep_at(index)).await["layout"], "index");

        // A maven purl joins its qualifiers with `&`, and a phase can carry an apostrophe. The page
        // escapes both; the JSON is text, and a reader of it is owed the characters.
        let purl = "pkg:maven/org.example/a@1?classifier=x&type=jar";
        let w = work_dir("api-sweep");
        put(
            w.join("results.tsv"),
            "pkg:npm/a@1\tbuild-failed:deps\t1.0\tk\t0\npkg:npm/b@1\tbuild-failed:deps\t1.0\tk\t0\n\
             pkg:npm/c@1\texact\t1.0\t\t0\n",
        );
        put(w.join("sweep.json"), &sweep_json(None, 7, 3600, None));
        put(
            w.join("status.json"),
            &status_json(
                "running",
                &crate::now_rfc3339(),
                std::process::id(),
                Some(in_flight(purl, 30, Some("it's-deps"), 5)),
            ),
        );
        let j = api(sweep_at(w)).await;
        assert_eq!(j["layout"], "sweep");
        assert_eq!(j["state"], "running");
        assert_eq!(j["total"], 7);
        assert_eq!(j["attempted"], 3);
        assert_eq!(
            (j["reproduced"].clone(), j["evidence"].clone()),
            (1.into(), 1.into())
        );
        assert_eq!(j["reproduction"], 1.0);
        assert_eq!(j["clusters"][0]["key"], "k");
        assert_eq!(j["clusters"][0]["members"], 2);
        assert_eq!(j["current"]["purl"], purl);
        assert!(j["results_age_seconds"].is_u64(), "{j}");
        let detail = j["detail"].as_str().unwrap();
        assert!(
            detail.contains("on maven/org.example/a@1?classifier=x&type=jar for 30s"),
            "{detail}"
        );
        assert!(detail.contains("it's-deps"), "{detail}");
        assert!(
            !detail.contains("&amp;") && !detail.contains("&#39;") && !detail.contains('<'),
            "the API handed a script the page's markup instead of its sentence: {detail}"
        );
    }

    #[test]
    fn stripping_the_markup_leaves_the_text_a_reader_saw() {
        let html = format!(
            "<br><span class=\"note\">on {} for 3s</span>",
            esc("g/a@1?c=x&t=jar 'q' \"r\" <s>")
        );
        assert_eq!(strip_tags(&html), "on g/a@1?c=x&t=jar 'q' \"r\" <s> for 3s");
        // An escaped entity in the text is text, and comes back as the entity, not as markup.
        assert_eq!(strip_tags(&esc("&lt;")), "&lt;");
    }

    // --- against a baseline ----------------------------------------------------------------------

    #[test]
    fn a_baseline_of_a_different_corpus_is_refused_rather_than_compared() {
        let base = work_dir("baseline-other-corpus");
        put(base.join("results.tsv"), &results(&[("a", "exact")]));
        put(
            base.join("sweep.json"),
            &sweep_json(Some("aaaa"), 1, 60, None),
        );
        let w = work_dir("baseline-this-corpus");
        put(w.join("results.tsv"), &results(&[("a", "divergent")]));
        put(w.join("sweep.json"), &sweep_json(Some("bbbb"), 1, 60, None));
        let s = Sweep {
            baseline: Some(base),
            ..sweep_at(w)
        };
        let p = baseline_panel(&s, &s.read());
        assert!(p.contains("these are sweeps of different corpora"), "{p}");
        assert!(
            !p.contains("NO LONGER REPRODUCES") && !p.contains("net gain"),
            "a comparison across two lists is a number about the lists:\n{p}"
        );
    }

    #[test]
    fn a_baseline_that_is_not_a_work_directory_is_not_read_as_an_empty_sweep() {
        // A mistyped `--baseline` read as a sweep that attempted nothing, so every target here was
        // "in this sweep and not the baseline" and the verdict under them was "Not a gain" — our
        // configuration error, rendered as a finding about the change.
        let w = work_dir("baseline-mistyped");
        put(w.join("results.tsv"), &results(&[("a", "exact")]));
        let empty = work_dir("baseline-empty-dir");
        for (base, why) in [
            (w.join("no-such-sweep"), "there is nothing at that path"),
            (empty, "it holds no sweep, no run and no directory of runs"),
        ] {
            let s = Sweep {
                baseline: Some(base.clone()),
                ..sweep_at(w.clone())
            };
            let p = baseline_panel(&s, &s.read());
            assert!(
                p.contains(&format!(
                    "<code>{}</code> is not a work directory this page can read — {why} — so \
                     nothing was compared against it",
                    esc(&base.display().to_string())
                )),
                "{p}"
            );
            for claim in [
                "in this sweep and not the baseline",
                "Not a gain",
                "net gain",
                "nothing changed",
            ] {
                assert!(!p.contains(claim), "`{claim}` about no comparison:\n{p}");
            }
        }
    }

    #[test]
    fn a_baseline_that_cannot_be_read_is_not_said_to_hold_no_sweep() {
        // A directory this user may not list, or may list and not enter, is one `read` finds
        // nothing in — so the panel said "it holds no sweep" over a sweep that is there, which is
        // "could not look" rendered as "not there".
        use std::os::unix::fs::PermissionsExt as _;
        let w = work_dir("baseline-sealed");
        put(w.join("results.tsv"), &results(&[("a", "exact")]));
        let sealed = w.join("sealed");
        put(sealed.join("results.tsv"), &results(&[("a", "exact")]));
        let set = |mode: u32| {
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        for mode in [0o000, 0o400] {
            set(mode);
            // A user the permissions do not stop (root) reads everything, and there is nothing to
            // test.
            let stopped = std::fs::read_to_string(sealed.join("results.tsv")).is_err();
            let s = Sweep {
                baseline: Some(sealed.clone()),
                ..sweep_at(w.clone())
            };
            let p = baseline_panel(&s, &s.read());
            set(0o755);
            if stopped {
                assert!(
                    p.contains("— it could not be read as a directory: "),
                    "{mode:o}: {p}"
                );
                assert!(!p.contains("holds no sweep"), "{mode:o}: {p}");
                assert!(!p.contains("Not a gain"), "{mode:o}: {p}");
            }
        }
    }

    #[test]
    fn a_baseline_names_every_flip_and_calls_a_regression_a_regression() {
        // A change that fixes one package and breaks another leaves the rate where it was. The
        // panel's job is which targets flipped, and in which direction.
        let base = work_dir("baseline-flips-before");
        put(
            base.join("results.tsv"),
            &results(&[
                ("a", "exact"),
                ("b", "divergent"),
                ("c", "exact"),
                ("d", "error:infra"),
                ("e", "exact"),
                ("f", "exact"),
                ("h", "build-failed:deps"),
            ]),
        );
        put(
            base.join("sweep.json"),
            &sweep_json(Some("cccc"), 7, 60, None),
        );
        let w = work_dir("baseline-flips-after");
        put(
            w.join("results.tsv"),
            &results(&[
                ("a", "divergent"),
                ("b", "exact"),
                ("c", "error:infra"),
                ("d", "normalized"),
                ("e", "normalized"),
                ("g", "exact"),
                ("h", "build-failed:deps"),
            ]),
        );
        put(w.join("sweep.json"), &sweep_json(Some("cccc"), 7, 60, None));
        let s = Sweep {
            baseline: Some(base.clone()),
            ..sweep_at(w)
        };
        let p = baseline_panel(&s, &s.read());
        assert!(
            p.contains(&format!("<h2>Against {}</h2>", base.display())),
            "{p}"
        );
        for (heading, who) in [
            ("1 now reproduces", "b"),
            ("1 NO LONGER REPRODUCES", "a"),
            ("1 stopped producing evidence — ours, not the change's", "c"),
            ("1 now produces evidence", "d"),
            ("1 in this sweep and not the baseline", "g"),
            ("1 in the baseline and not this sweep", "f"),
        ] {
            assert!(
                p.contains(&format!(
                    "<p><strong>{heading}</strong></p><ul><li><code>{who}</code></li></ul>"
                )),
                "`{heading}` should name `{who}`:\n{p}"
            );
        }
        assert!(
            p.contains("<strong>1 reproduce differently</strong>")
                && p.contains("<li><code>e</code> exact → normalized</li>"),
            "{p}"
        );
        // Unchanged, and not evidence either time: in no list.
        assert!(!p.contains("<code>h</code>"), "{p}");
        assert!(p.contains("NOT a net gain"), "{p}");
        assert!(!p.contains("assumption rather than a check"), "{p}");
    }

    #[test]
    fn a_baseline_says_when_nothing_changed_and_a_fix_alone_is_a_net_gain() {
        let pair = |name: &str, before: &str, after: &str| {
            let base = work_dir(&format!("{name}-before"));
            put(base.join("results.tsv"), &results(&[("a", before)]));
            let w = work_dir(&format!("{name}-after"));
            put(w.join("results.tsv"), &results(&[("a", after)]));
            let s = Sweep {
                baseline: Some(base),
                ..sweep_at(w)
            };
            baseline_panel(&s, &s.read())
        };
        let same = pair("baseline-same", "exact", "exact");
        assert!(
            same.contains("<p class=\"note\">nothing changed</p>"),
            "{same}"
        );
        assert!(same.contains("Not a gain: nothing was fixed."), "{same}");
        // Neither sweep wrote `sweep.json`, so that they share a corpus is assumed, and said.
        assert!(
            same.contains(
                "recorded no corpus digest, so that they are the same corpus is an \
                 assumption rather than a check"
            ),
            "{same}"
        );
        let fixed = pair("baseline-fixed", "divergent", "exact");
        assert!(
            fixed.contains("A net gain: something was fixed and nothing regressed."),
            "{fixed}"
        );
        // No baseline, no panel.
        let w = work_dir("baseline-none");
        let s = sweep_at(w);
        assert_eq!(baseline_panel(&s, &s.read()), "");
    }

    // --- a directory of runs --------------------------------------------------------------------

    #[test]
    fn a_shelf_row_says_what_it_was_built_from_or_that_nothing_was() {
        let w = work_dir("shelf-rows");
        put(
            w.join("a").join("run.json"),
            r#"{"purl":"pkg:nuget/Newtonsoft.Json@11.0.1","started":"2026-01-01T00:00:00Z",
                "finished":"2026-01-01T00:02:00Z","outcome":"build-failed:deps",
                "failure":{"code":"dotnet/restore","subject":"x","fault":"build",
                           "retryable":false,"repairable":true,"evidence":"e"},
                "source":{"repo_url":"https://gitlab.com/o/r","commit":"abcdefgé0123",
                          "subdir":"Src/Newtonsoft.Json","how":"fuzzy_tag"},
                "network_bytes":2048,"model_calls":0}"#,
        );
        put(
            w.join("b").join("run.json"),
            r#"{"purl":"pkg:npm/b@1","started":"not a time","outcome":"exact","model_calls":0}"#,
        );
        put(w.join("c").join("strategy.yaml"), "id: x\n");
        let v = sweep_at(w).read();
        let p = index_panel(&v);
        // A forge that is not GitHub keeps its host: which one a package builds from is part of
        // what the reader is checking.
        assert!(p.contains("<code>gitlab.com/o/r</code>"), "{p}");
        // Eight characters of a hand-edited commit, never eight bytes of it.
        assert!(
            p.contains("<code title=\"abcdefgé0123\">abcdefgé</code>"),
            "{p}"
        );
        assert!(
            p.contains("<span class=\"dim\">Src/Newtonsoft.Json</span>"),
            "{p}"
        );
        assert!(p.contains("fuzzy_tag"), "{p}");
        assert!(p.contains("/cluster?key=dotnet%2Frestore%3Ax"), "{p}");
        assert!(p.contains("120s · 2.0 KB"), "{p}");
        assert!(
            p.contains("h ago"),
            "a finish long past reads in hours:\n{p}"
        );
        // The run with nothing resolved and no clock says both, rather than a blank and a zero.
        assert!(p.contains("no source resolved"), "{p}");
        assert!(p.contains("no finish recorded"), "{p}");
        assert!(p.contains("no duration"), "{p}");
        // And the directory with no report is named as a directory.
        assert!(
            p.contains("<a href=\"/run/2\"><code>c</code></a>") && p.contains("no run.json"),
            "{p}"
        );
        assert_eq!(family_tally(&[]), "");
    }

    #[tokio::test]
    async fn a_directory_of_runs_gets_a_tally_and_its_clusters_but_no_rate_and_no_sweep_board() {
        // A reproduction rate over a hand-picked shelf is the number this project exists to stop
        // people quoting; the failures on it still group, and still link to their clusters.
        let w = work_dir("shelf-board");
        put(
            w.join("a").join("run.json"),
            r#"{"purl":"pkg:npm/a@1","started":"2026-09-17T19:57:42Z",
                "finished":"2026-09-17T19:58:42Z","outcome":"build-failed:deps",
                "failure":{"code":"npm/peer-conflict","fault":"build","retryable":false,
                           "repairable":true,"evidence":"ERESOLVE"},
                "source":{"repo_url":"https://github.com/o/r","commit":"0123456789abcdef",
                          "how":"registry_commit"},"model_calls":0}"#,
        );
        put(
            w.join("b").join("run.json"),
            &run_json("pkg:npm/b@1", "exact"),
        );
        let page = board_page(sweep_at(w)).await;
        assert!(
            page.contains("<strong>a directory of runs</strong>"),
            "{page}"
        );
        assert!(
            page.contains("1 reproduced") && page.contains("1 build failed"),
            "{page}"
        );
        assert!(page.contains("<h2>Failure clusters</h2>"), "{page}");
        assert!(page.contains("/cluster?key=npm%2Fpeer-conflict"), "{page}");
        assert!(!page.contains("<h2>Rates</h2>"), "{page}");
        assert!(!page.contains("<h2>Targets</h2>"), "{page}");
        // A source with no subdirectory is the repository root, and nothing is appended.
        assert!(
            page.contains("<code>o/r</code>@<code title=\"0123456789abcdef\">01234567</code><br>"),
            "{page}"
        );
    }

    #[tokio::test]
    async fn a_retried_target_in_a_directory_of_runs_is_two_members_and_not_one_counted_twice() {
        // `rebuild-and-attest.sh` names one work directory per invocation, so a failure retried
        // into a second directory leaves two runs of one target. The cluster page found each
        // member's directory by its purl, and both found the first: the retry's log was never
        // read, and the first run's was counted twice.
        let w = work_dir("retried-target");
        let report = serde_json::json!({
            "purl": "pkg:npm/a@1", "started": "2026-09-17T19:57:42Z",
            "finished": "2026-09-17T19:58:42Z", "outcome": "build-failed:deps",
            "failure": {"code": "npm/peer-conflict", "fault": "build", "retryable": false,
                        "repairable": true, "evidence": "ERESOLVE"},
            "model_calls": 0,
        })
        .to_string();
        let (first, second) = (
            "npm ERR! the first attempt ended here\n",
            "npm ERR! the retry ended somewhere else\n",
        );
        put(w.join("a-first").join("run.json"), &report);
        put(w.join("a-first").join("rebuild").join("build.log"), first);
        put(w.join("a-retry").join("run.json"), &report);
        put(w.join("a-retry").join("rebuild").join("build.log"), second);
        let (first, second) = (
            trigon_core::classify(first).evidence,
            trigon_core::classify(second).evidence,
        );
        assert_ne!(first, second, "the fixture needs two different sentences");

        let page = text(cluster_page(sweep_at(w), "npm/peer-conflict").await).await;
        assert!(
            page.contains("<a href=\"/run/0\">open</a>")
                && page.contains("<a href=\"/run/1\">open</a>"),
            "each run opens its own directory:\n{page}"
        );
        for line in [&first, &second] {
            assert!(
                page.contains(&format!(
                    "<td class=\"n\">1</td><td><code>{}</code>",
                    esc(line.trim())
                )),
                "each log is read once:\n{page}"
            );
        }
        assert!(!page.contains("<td class=\"n\">2</td>"), "{page}");
    }

    #[tokio::test]
    async fn a_cluster_page_says_whether_it_is_one_failure_or_several_wearing_one_name() {
        let w = work_dir("cluster-evidence");
        let key = "cc/missing-header:python.h";
        let row = |p: &str| format!("{p}\tbuild-failed:deps\t1.0\t{key}\t0\n");
        put(
            w.join("results.tsv"),
            &format!(
                "{}{}{}{}pkg:npm/e@1\texact\t1.0\t\t0\n",
                row("pkg:npm/a@1"),
                row("pkg:npm/b@1"),
                row("pkg:npm/c@1"),
                row("pkg:npm/d@1")
            ),
        );
        let same = "compiling\ngcc: fatal error: Python.h: No such file or directory\n";
        let other = "compiling\nx.c:1:10: fatal error: Python.h: No such file or directory <b>\n";
        put(w.join("000").join("rebuild").join("build.log"), same);
        put(w.join("001").join("rebuild").join("build.log"), same);
        put(w.join("002").join("rebuild").join("build.log"), other);
        // `003` has no log: resumed from a sweep whose work directory is gone.
        let (twice, once) = (
            trigon_core::classify(same).evidence,
            trigon_core::classify(other).evidence,
        );
        assert_ne!(twice, once, "the fixture needs two different sentences");

        let page = text(cluster_page(sweep_at(w.clone()), key).await).await;
        assert!(page.contains("4 target(s) failed this way"), "{page}");
        let twice = format!(
            "<td class=\"n\">2</td><td><code>{}</code>",
            esc(twice.trim())
        );
        let once = format!(
            "<td class=\"n\">1</td><td><code>{}</code>",
            esc(once.trim())
        );
        assert!(page.contains(&twice) && page.contains(&once), "{page}");
        assert!(
            page.find(&twice) < page.find(&once),
            "most-carried first:\n{page}"
        );
        assert!(page.contains("1 member(s) have no log on disk"), "{page}");
        for i in 0..4 {
            assert!(
                page.contains(&format!("<a href=\"/run/{i}\">open</a>")),
                "{page}"
            );
        }
        assert!(!page.contains("npm/e@1"), "not a member:\n{page}");
        assert!(
            page.contains("trigon rebuild pkg:npm/a@1 --image"),
            "{page}"
        );
        assert!(
            !page.contains("<b>"),
            "a log line is text, not markup:\n{page}"
        );

        // A cluster none of whose logs survive says so, rather than rendering an empty table.
        let gone = work_dir("cluster-no-logs");
        put(gone.join("results.tsv"), &row("pkg:npm/a@1"));
        let page = text(cluster_page(sweep_at(gone), key).await).await;
        assert!(page.contains("no log for any member is on disk"), "{page}");
        assert!(!page.contains("<th>evidence</th>"), "{page}");

        // And a member the targets file does not name has no directory to open.
        let t = w.join("targets.txt");
        put(t.clone(), "pkg:npm/a@1\n");
        let page = text(
            cluster_page(
                Sweep {
                    targets: Some(t),
                    ..sweep_at(w)
                },
                key,
            )
            .await,
        )
        .await;
        assert!(
            page.contains("<span class=\"note\">no directory</span>"),
            "{page}"
        );
    }

    // --- the run record, as `run.json` has it ----------------------------------------------------

    #[test]
    fn the_run_record_says_what_the_source_was_and_how_it_was_found() {
        let r = report(
            r##"{"purl":"p","started":"s","model_calls":0,
                "source":{"repo_url":"https://github.com/o/r",
                          "declared_url":"git+https://github.com/o/r.git#main",
                          "commit":"0123456789abcdef","ref_name":"v1.0.0","subdir":"packages/a",
                          "how":"exact_tag"}}"##,
        );
        let p = report_panel(Some(&r));
        assert!(
            p.contains(
                "<code>https://github.com/o/r</code> at <code>0123456789abcdef</code> · \
                 <code>packages/a</code>"
            ),
            "{p}"
        );
        assert!(
            p.contains("found by exact_tag, from <code>v1.0.0</code>"),
            "{p}"
        );
        assert!(
            p.contains("the registry declared git+https://github.com/o/r.git#main"),
            "{p}"
        );
        let none = report_panel(Some(&report(
            r#"{"purl":"p","started":"s","model_calls":0}"#,
        )));
        assert!(
            none.contains("no source resolved — this run was never compared against a commit"),
            "{none}"
        );
        assert!(
            report_panel(None).contains("no run.json — this target ran before the record existed"),
            "no report is said, not rendered as an empty table"
        );

        // A commit the registry recorded, at the repository root: nothing is appended to it.
        let bare = report_panel(Some(&report(
            r#"{"purl":"p","started":"s","model_calls":0,"derivation":"heuristic",
                "failure":{"code":"env/missing-tool","fault":"infra","retryable":false,
                           "repairable":true,"evidence":"npx: not found"},
                "source":{"repo_url":"https://github.com/o/r","commit":"0123456789abcdef",
                          "how":"registry_commit"}}"#,
        )));
        assert!(
            bare.contains(
                "<code>https://github.com/o/r</code> at <code>0123456789abcdef</code><br>\
                 <span class=\"dim\">found by registry_commit</span></td>"
            ),
            "{bare}"
        );
        assert!(!bare.contains("the registry declared"), "{bare}");
        assert!(
            bare.contains("<td class=\"dim\">derivation</td><td>heuristic</td>"),
            "{bare}"
        );
        assert!(
            bare.contains("<code>env/missing-tool</code> · <span class=\"dim\">Infra"),
            "{bare}"
        );
    }

    #[test]
    fn a_build_that_never_finished_has_not_said_whether_it_is_attestable() {
        // Three states, and the third is the point: rendering "never finished" as "not attestable"
        // sends the reader after an egress tier when the problem is a build that died.
        let egress = |attestable: &str| {
            report_panel(Some(&report(&format!(
                r#"{{"purl":"p","started":"s","model_calls":0,"egress":"mirror-only"{attestable}}}"#
            ))))
        };
        let yes = egress(r#","attestable":true"#);
        assert!(yes.contains("mirror-only · transcript recorded"), "{yes}");
        let no = egress(r#","attestable":false"#);
        assert!(
            no.contains("no network transcript: this run cannot say what the build fetched"),
            "{no}"
        );
        let unknown = egress("");
        assert!(
            unknown.contains("<td class=\"dim\">egress</td><td>mirror-only</td>"),
            "{unknown}"
        );
    }

    #[test]
    fn a_registry_pin_is_proven_ambiguous_or_unknown_and_never_five_zeroes() {
        let pin = |json: &str| {
            report_panel(Some(&report(&format!(
                r#"{{"purl":"p","started":"s","model_calls":0{json}}}"#
            ))))
        };
        let counters = |index: u64, artifact: u64| {
            format!(
                r#","pin":{{"index_requests":{index},"versions_withheld":2,
                          "artifact_requests":{artifact},"toolchain_requests":0,"rejected":0}}"#
            )
        };
        let absent = pin("");
        assert!(
            absent.contains("no counters, which is not five zeroes"),
            "{absent}"
        );
        assert!(!absent.contains("index requests"), "{absent}");
        let bound = pin(&counters(3, 5));
        assert!(
            bound.contains("proof the pin reached the client"),
            "{bound}"
        );
        assert!(
            bound.contains("<td class=\"dim\">versions withheld</td><td>2</td>"),
            "{bound}"
        );
        let unbound = pin(&counters(0, 4));
        assert!(
            unbound.contains(
                "served no index document. Either this build needed no \
                 dependencies, or the pin did not reach the client"
            ),
            "{unbound}"
        );
        let silent = pin(&counters(0, 0));
        assert!(
            silent.contains("the mirror was never contacted"),
            "{silent}"
        );
    }

    #[test]
    fn a_throttled_host_is_read_as_our_request_rate_before_it_is_read_as_the_package() {
        let r = report(
            r#"{"purl":"p","started":"s","model_calls":3,"model":"m-1",
                "hosts":{"registry.npmjs.org":{"requests":40,"throttled":2,"failed":1},
                         "github.com":{"requests":3,"throttled":0,"failed":0}},
                "timings":[["deps",12.34],["build",null]],
                "fetch_cache":{"hits":4,"fetched":1,"oldest_index_snapshot":"2026-09-01T00:00:00Z"},
                "failure":{"code":"npm/peer-conflict","subject":"react","fault":"build",
                           "retryable":true,"repairable":false,"evidence":"npm ERR! ERESOLVE"},
                "repairs":["pinned react@17"],"repair_stopped":"budget spent",
                "guard_notes":["x.js arrived and did not ship"],"refused_artifact":["a","b"],
                "derivation":"heuristic","confidence":"high",
                "strategy_digest":"0123456789abcdef0123"}"#,
        );
        let p = report_panel(Some(&r));
        assert!(
            p.contains("<span class=\"fail\">2</span>")
                && p.contains("<span class=\"ours\">1</span>"),
            "{p}"
        );
        assert!(
            p.contains(
                "<tr><td><code>github.com</code></td><td class=\"n\">3</td><td class=\"n\">0</td>\
                 <td class=\"n\">0</td></tr>"
            ),
            "{p}"
        );
        assert!(
            p.contains("a host told us to slow down during this run"),
            "{p}"
        );
        assert!(p.contains("<td>deps</td><td class=\"n\">12.3</td>"), "{p}");
        assert!(
            p.contains("<td>build</td><td class=\"n\"><span class=\"note\">no data</span>"),
            "a timing nobody took is not a fast phase:\n{p}"
        );
        assert!(
            p.contains("4 body/bodies from disk, 1 from a registry"),
            "{p}"
        );
        assert!(
            p.contains("fetched at <code>2026-09-01T00:00:00Z</code>"),
            "{p}"
        );
        assert!(
            p.contains(
                "<code>npm/peer-conflict</code> <code>react</code> · <span class=\"dim\">\
                 Build, retryable, nothing to repair</span>"
            ),
            "{p}"
        );
        assert!(p.contains("<pre>npm ERR! ERESOLVE</pre>"), "{p}");
        assert!(
            p.contains("<li>pinned react@17</li><li class=\"note\">stopped: budget spent</li>"),
            "{p}"
        );
        assert!(p.contains("x.js arrived and did not ship"), "{p}");
        assert!(p.contains("its own published artifact 2 time(s)"), "{p}");
        assert!(p.contains("m-1 · 3 call(s)"), "{p}");
        assert!(p.contains("heuristic · confidence high"), "{p}");
        assert!(p.contains("<code>0123456789abcdef</code>"), "{p}");

        // The quiet version: no hosts is not a run that asked for nothing, and a cache with no
        // index read went to the network for every resolution.
        let quiet = report_panel(Some(&report(
            r#"{"purl":"p","started":"s","model_calls":0,"fetch_cache":{"hits":0,"fetched":3}}"#,
        )));
        assert!(quiet.contains("no per-host counts"), "{quiet}");
        assert!(quiet.contains("no cached index was read"), "{quiet}");
        assert!(!quiet.contains("slow down"), "{quiet}");
        assert!(!quiet.contains("<h2>Timeline</h2>"), "{quiet}");
    }

    #[test]
    fn every_outcome_gets_its_own_sentence_and_ours_is_never_the_package_s() {
        let say = |outcome: Option<&str>| {
            verdict_sentence(&report(
                &serde_json::json!({"purl": "p", "started": "s", "outcome": outcome,
                                    "model_calls": 0})
                .to_string(),
            ))
        };
        for (outcome, words) in [
            (
                Some("normalized"),
                "every pass that fired was a built-in one",
            ),
            (
                Some("divergent"),
                "The rebuilt artifact is not the published one",
            ),
            (
                Some("build-failed:deps"),
                "a finding about the package or about the recipe",
            ),
            (Some("no-strategy"), "no rung recorded why"),
            (Some("void"), "did not record why it was voided"),
            (
                Some("error:infra"),
                "Our own infrastructure stopped this run",
            ),
            // A label nobody has seen before is ours until shown otherwise.
            (
                Some("something-new"),
                "Our own infrastructure stopped this run",
            ),
            (None, "The run recorded no outcome"),
        ] {
            let s = say(outcome);
            assert!(s.contains(words), "{outcome:?}: {s}");
        }
    }

    // --- the verdict, re-derived from the bytes on disk ------------------------------------------

    const T: u64 = 1_600_000_000;

    /// A divergence with one of everything: a member that is identical, one only a timestamp
    /// separates, a native library whose code changed, and one the rebuild never produced.
    fn divergent_pair() -> (Vec<u8>, Vec<u8>) {
        let up = tgz(&[
            ("package/gone.js", b"only upstream\n", T),
            ("package/lib/native.so", b"\x7fELF as published", T),
            ("package/same.js", b"identical\n", T),
            ("package/time.js", b"same bytes\n", T),
        ]);
        let rb = tgz(&[
            ("package/lib/native.so", b"\x7fELF as rebuilt!!", T),
            ("package/same.js", b"identical\n", T),
            ("package/time.js", b"same bytes\n", T + 100_000_000),
        ]);
        (up, rb)
    }

    #[tokio::test]
    async fn a_divergence_is_taken_apart_member_by_member_and_the_executable_is_called_out() {
        let (up, rb) = divergent_pair();
        let w = one_run(
            "divergence",
            &run_json("pkg:npm/a@1", "divergent"),
            "a-1.tgz",
            &up,
            &rb,
        );

        let (m, _) = member_diffs(
            &w.join("a-1.tgz"),
            &w.join("rebuild").join("1789000000-run").join("a-1.tgz"),
        )
        .unwrap();
        let verdicts = member_verdicts(&m);
        assert_eq!(
            verdicts,
            BTreeMap::from([
                ("package/gone.js".to_string(), "one-side"),
                ("package/lib/native.so".to_string(), "differs"),
                ("package/same.js".to_string(), "identical"),
                ("package/time.js".to_string(), "stabilized"),
            ])
        );

        let run = run_page(sweep_at(w.clone()), 0).await;
        assert!(
            run.contains(
                "4 member(s): <strong>1</strong> differ in content, <strong>0</strong> are \
                 byte-identical and packed differently, <strong>1</strong> were stabilized out"
            ),
            "{run}"
        );
        // Both digests disagree, so the ladder reaches its last rung and says there is no other.
        assert!(run.contains("▸ member by member"), "{run}");
        assert!(
            run.contains(
                "decided <code>divergent</code>. Every question was asked, and this is \
                 the last one there is."
            ),
            "{run}"
        );
        // A native library that came back different is never benign, and is said in those words.
        assert!(
            run.contains("<code>ExecutableContentDiffers</code>"),
            "{run}"
        );
        assert!(
            run.contains("reaches a human even on a clean match"),
            "{run}"
        );
        assert!(
            run.contains("An executable whose content differs is never benign"),
            "{run}"
        );
        assert!(run.contains("package/lib/native.so"), "{run}");
        assert!(run.contains("<code>MemberOnlyInUpstream</code>"), "{run}");
        // The ribbon names the set the verdict was reached under.
        assert!(run.contains("under tar-gzip"), "{run}");

        let cmp = compare_page(sweep_at(w), 0).await;
        assert!(
            cmp.contains("<title>npm/a@1 · stabilizers · trigon watch</title>"),
            "{cmp}"
        );
        // Every pass in the tarball set is a builtin at metadata risk or below, so nothing caps it.
        assert!(
            cmp.contains("nothing in this set holds the verdict down"),
            "{cmp}"
        );
        assert!(cmp.contains("It read <strong>divergent</strong>"), "{cmp}");
        // Both sides fire, and the ledger sums them: four members and three.
        assert!(
            cmp.contains("<code>tar-time</code></td><td class=\"n\">7</td>"),
            "{cmp}"
        );
        // The set's passes that found nothing to do are listed, because silence is evidence.
        let silent = cmp
            .split("What stayed silent")
            .nth(1)
            .expect("a silent section");
        assert!(silent.contains("<code>tar-device</code>"), "{silent}");
        assert!(!silent.contains("<code>tar-time</code>"), "{silent}");
        // The census: each non-empty band keyed, and the empty one left out of the key.
        for key in [
            "1 content differs",
            "1 stabilized out",
            "1 identical as published",
            "1 on one side only",
        ] {
            assert!(cmp.contains(&format!("</i>{key}</span>")), "{key}:\n{cmp}");
        }
        assert!(
            !cmp.contains("#8a6d1f\"></i>"),
            "an empty band has no key:\n{cmp}"
        );
        // Most interesting first: a hundred identical members must not bury the few that differ.
        let table = cmp.split("<h2>Every member</h2>").nth(1).unwrap();
        let at = |p: &str| {
            table
                .find(&format!("<code>{p}</code>"))
                .unwrap_or_else(|| panic!("{p} is not in the table:\n{table}"))
        };
        assert!(
            at("package/gone.js") < at("package/lib/native.so"),
            "{table}"
        );
        assert!(
            at("package/lib/native.so") < at("package/time.js"),
            "{table}"
        );
        assert!(at("package/time.js") < at("package/same.js"), "{table}");
        assert!(table.contains("only in upstream"), "{table}");
        assert!(table.contains("equal — stabilized out"), "{table}");
    }

    #[tokio::test]
    async fn the_ladder_marks_the_one_question_that_decided_the_verdict() {
        let up = tgz(&[("package/a.js", b"a\n", T)]);
        let exact = one_run(
            "ladder-exact",
            &run_json("pkg:npm/a@1", "exact"),
            "a-1.tgz",
            &up,
            &up,
        );
        let page = run_page(sweep_at(exact.clone()), 0).await;
        assert!(
            page.contains("▸ the published bytes and the rebuilt bytes"),
            "{page}"
        );
        assert!(
            !page.contains("after the stabilizers"),
            "a question never asked is not drawn:\n{page}"
        );
        assert!(
            page.contains("decided <code>exact</code>. The rows below it were never asked."),
            "{page}"
        );
        assert!(page.contains("nothing beyond the verdict"), "{page}");
        let cmp = compare_page(sweep_at(exact), 0).await;
        assert!(
            cmp.contains("matched on the published bytes themselves"),
            "no ledger can put a ceiling on raw bytes:\n{cmp}"
        );

        let later = tgz(&[("package/a.js", b"a\n", T + 100_000_000)]);
        let normalized = one_run(
            "ladder-normalized",
            &run_json("pkg:npm/a@1", "normalized"),
            "a-1.tgz",
            &up,
            &later,
        );
        let page = run_page(sweep_at(normalized), 0).await;
        assert!(page.contains("▸ after the stabilizers"), "{page}");
        // The rung above it is drawn, greyed, and the one below it is not drawn at all.
        assert!(
            page.contains("<tr style=\"opacity:.45\"><td>&nbsp;&nbsp;the published bytes"),
            "{page}"
        );
        assert!(!page.contains("member by member"), "{page}");
        assert!(
            page.contains("The rows below it were never asked."),
            "{page}"
        );
    }

    #[tokio::test]
    async fn a_member_packed_differently_is_counted_apart_from_one_whose_content_changed() {
        // `py-cpuinfo`: byte-identical files in zip entries with different modes. The archive
        // digests differ and the verdict is `divergent`, correctly — but "the code changed" is
        // not what identical bytes mean, and overstating a divergence is the expensive direction.
        let up = zip_of(&[("f.txt", b"same bytes on both sides\n", 0o644)]);
        let rb = zip_of(&[("f.txt", b"same bytes on both sides\n", 0o755)]);
        let w = one_run(
            "packed-differently",
            &run_json("pkg:pypi/a@1", "divergent"),
            "a-1.zip",
            &up,
            &rb,
        );
        let (m, _) = member_diffs(
            &w.join("a-1.zip"),
            &w.join("rebuild").join("1789000000-run").join("a-1.zip"),
        )
        .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].band(), Band::Packed, "same bytes, different entry");
        assert!(!m[0].content_differs());
        assert_eq!(member_verdicts(&m).get("f.txt").copied(), Some("packed"));
        let panel = compare_panel(&w, 0);
        assert!(
            panel.contains(
                "<strong>0</strong> differ in content, <strong>1</strong> are byte-identical \
                 and packed differently"
            ),
            "{panel}"
        );
        assert!(panel.contains("<a href=\"/run/0/compare\">"), "{panel}");
    }

    #[tokio::test]
    async fn a_member_a_pass_removed_is_counted_as_stabilized_out_rather_than_dropped() {
        // nuget.org countersigns every package it serves and nothing anybody builds, so the
        // published `.nupkg` carries a `.signature.p7s` the rebuild never has, and
        // `nupkg-signature` takes it out. That is a difference a pass accounted for — the band the
        // census note describes — and the page dropped the member instead: gone from the total,
        // from the table, and drawn on the source page as never compared.
        //
        // And a member a pass *renamed* is one member, not a removal and an arrival: `dotnet pack`
        // names the core-properties part after a fresh GUID, so the two sides publish it under two
        // names that `nupkg-packaging-names` makes one.
        let props = "package/services/metadata/core-properties/";
        let (up_props, rb_props) = (format!("{props}aaaa.psmdcp"), format!("{props}bbbb.psmdcp"));
        let up = zip_of(&[
            (".signature.p7s", b"the gallery's countersignature", 0o644),
            ("_rels/.rels", b"<Relationships/>", 0o644),
            ("lib/a.dll", b"MZ the assembly", 0o644),
            (&up_props, b"<coreProperties/>", 0o644),
        ]);
        let rb = zip_of(&[
            ("_rels/.rels", b"<Relationships/>", 0o644),
            ("lib/a.dll", b"MZ the assembly", 0o644),
            (&rb_props, b"<coreProperties/>", 0o644),
        ]);
        let w = one_run(
            "removed-by-a-pass",
            &run_json("pkg:nuget/a@1", "normalized"),
            "a.1.nupkg",
            &up,
            &rb,
        );
        let (m, _) = member_diffs(
            &w.join("a.1.nupkg"),
            &w.join("rebuild").join("1789000000-run").join("a.1.nupkg"),
        )
        .unwrap();
        // Under the names upstream published, because the source page's lower bar reads the
        // published archive: under `core.psmdcp`, the GUID-named part was drawn as never compared.
        let verdicts = member_verdicts(&m);
        assert_eq!(
            verdicts,
            BTreeMap::from([
                (".signature.p7s".to_string(), "stabilized"),
                ("_rels/.rels".to_string(), "identical"),
                ("lib/a.dll".to_string(), "identical"),
                (up_props.clone(), "stabilized"),
            ])
        );
        let (joined, _) = crate::provenance::join(
            &raw_members(&w.join("a.1.nupkg")).unwrap(),
            None,
            None,
            "d50b912e",
        );
        let bars = origin_bars(&joined, &verdicts);
        assert!(
            bars.contains(&format!("{up_props} — stabilized out")),
            "{bars}"
        );
        assert!(!bars.contains("not compared"), "{bars}");
        // The total is the four members upstream published, each in one band: the count of
        // identical members was the total minus the rest, and a member in two bands underflowed it.
        let bar = ladder_svg(&m);
        assert!(
            bar.contains(
                "4 members: 0 differ in content, 0 same bytes packed differently, 2 stabilized \
                 out, 2 identical, 0 on one side only"
            ),
            "{bar}"
        );
        assert!(bar.contains("</i>2 stabilized out</span>"), "{bar}");
        assert!(bar.contains("4 member(s) in total"), "{bar}");
        let t = member_table(&m);
        assert!(
            t.contains(
                "<code>.signature.p7s</code></td><td><span class=\"diff\">only in upstream</span>\
                 </td><td><span class=\"ok\">removed — stabilized out</span>"
            ),
            "{t}"
        );
        assert!(
            t.contains(&format!(
                "<code>{props}core.psmdcp</code></td><td><span class=\"diff\">differs</span>\
                 </td><td><span class=\"ok\">equal — stabilized out</span>"
            )),
            "{t}"
        );
        assert!(
            !t.contains("aaaa.psmdcp") && !t.contains("bbbb.psmdcp"),
            "{t}"
        );
        let panel = compare_panel(&w, 0);
        assert!(
            panel.contains(
                "4 member(s): <strong>0</strong> differ in content, <strong>0</strong> are \
                 byte-identical and packed differently, <strong>2</strong> were stabilized out"
            ),
            "{panel}"
        );

        // The same rule by hand, for the shapes a pair of real archives is slow to reach: removed
        // from both sides after differing is stabilized out, removed from both after agreeing is
        // identical, and removed from one side of two is a difference that is still there.
        let m = [
            member(
                "gone-both-differed",
                (Some("x"), Some("y")),
                (None, None),
                (None, None),
            ),
            member(
                "gone-both-agreed",
                (Some("x"), Some("x")),
                (None, None),
                (None, None),
            ),
            member(
                "gone-one-side",
                (Some("x"), Some("x")),
                (Some("x"), None),
                (Some("c"), None),
            ),
            member(
                "only-rebuilt-and-gone",
                (None, Some("y")),
                (None, None),
                (None, None),
            ),
        ];
        assert_eq!(
            member_verdicts(&m),
            BTreeMap::from([
                ("gone-both-differed".to_string(), "stabilized"),
                ("gone-both-agreed".to_string(), "identical"),
                ("gone-one-side".to_string(), "differs"),
                ("only-rebuilt-and-gone".to_string(), "stabilized"),
            ])
        );
        let bar = ladder_svg(&m);
        assert!(
            bar.contains(
                "4 members: 1 differ in content, 0 same bytes packed differently, 2 stabilized \
                 out, 1 identical, 0 on one side only"
            ),
            "{bar}"
        );
        // Identical as published, and in neither stabilized archive: the stabilized cell says a
        // pass took it, not "identical" over a comparison nobody made.
        let t = member_table(&m);
        assert!(
            t.contains(
                "<code>gone-both-agreed</code></td><td><span class=\"ok\">identical</span></td>\
                 <td><span class=\"ok\">removed by a pass</span>"
            ),
            "{t}"
        );
    }

    #[tokio::test]
    async fn artifacts_that_will_not_parse_are_said_to_be_unreadable_rather_than_equal() {
        let w = one_run(
            "unparseable-pair",
            &run_json("pkg:npm/a@1", "divergent"),
            "a-1.tgz",
            b"not a gzip at all",
            b"nor this",
        );
        let panel = compare_panel(&w, 0);
        assert!(
            panel.contains("the artifacts could not both be re-derived"),
            "{panel}"
        );
        let cmp = compare_page(sweep_at(w.clone()), 0).await;
        assert!(
            cmp.contains(
                "could not both be re-derived, so this page has nothing to show rather \
                 than nothing to report"
            ),
            "{cmp}"
        );
        assert!(!cmp.contains("<h2>The ledger</h2>"), "{cmp}");
        let run = run_page(sweep_at(w), 0).await;
        assert!(
            !run.contains("Why this is the verdict"),
            "a ladder drawn from a comparison that did not happen:\n{run}"
        );
    }

    fn applied(
        id: &str,
        risk: trigon_core::RiskTier,
        provenance: trigon_core::Provenance,
        touched: u32,
    ) -> trigon_stabilize::Applied {
        trigon_stabilize::Applied {
            id: trigon_core::StabilizerId::new(id),
            risk,
            provenance,
            entries_touched: touched,
            bytes_changed: 2048,
        }
    }

    fn a_set_with_every_kind_of_pass() -> [trigon_stabilize::Applied; 4] {
        use trigon_core::{Provenance, RiskTier};
        [
            applied("tar-time", RiskTier::Metadata, Provenance::Builtin, 3),
            applied("cargo-vcs-hash", RiskTier::Content, Provenance::Builtin, 1),
            applied(
                "model-pass",
                RiskTier::Metadata,
                Provenance::Model {
                    model_id: "claude-x".into(),
                    run_id: "r1".into(),
                },
                2,
            ),
            applied(
                "reviewed-pass",
                RiskTier::Lossy,
                Provenance::Human {
                    reviewer: "alice".into(),
                },
                5,
            ),
        ]
    }

    #[test]
    fn the_ceiling_names_each_pass_that_holds_the_verdict_down_and_the_half_of_the_rule_it_trips() {
        // Both halves of the cap rule weigh the same: a metadata pass a model wrote caps the
        // verdict as firmly as a content pass compiled in. A ledger showing risk alone was showing
        // half a reason and reading as a whole one.
        let set = a_set_with_every_kind_of_pass();
        let p = ceiling_panel(&set, Some("divergent"));
        assert!(
            p.contains(&format!(
                "can reach <strong>{}</strong> and no higher",
                trigon_compare::ceiling(&set)
            )),
            "{p}"
        );
        assert!(p.contains("It read <strong>divergent</strong>"), "{p}");
        assert!(
            p.contains("<code>cargo-vcs-hash</code></td><td>Content risk is above Metadata</td>"),
            "{p}"
        );
        let row = |id: &str| {
            p.split(&format!("<code>{id}</code></td><td>"))
                .nth(1)
                .and_then(|s| s.split("</td>").next())
                .unwrap_or_else(|| panic!("no row for {id}:\n{p}"))
                .to_string()
        };
        assert!(
            row("model-pass").ends_with("provenance — not Builtin"),
            "{p}"
        );
        assert!(row("model-pass").contains("claude-x"), "{p}");
        assert!(
            row("reviewed-pass").ends_with("provenance, and Lossy risk is above Metadata"),
            "{p}"
        );
        assert!(
            !p.contains("<code>tar-time</code>"),
            "a builtin metadata pass holds nothing down:\n{p}"
        );

        let clean = ceiling_panel(&set[..1], None);
        assert!(
            clean.contains("nothing in this set holds the verdict down"),
            "{clean}"
        );
        assert!(
            clean.contains("It read <strong>unknown</strong>"),
            "{clean}"
        );
    }

    #[test]
    fn the_ledger_sums_both_sides_and_says_who_stands_behind_each_pass() {
        let one = a_set_with_every_kind_of_pass();
        let both: Vec<_> = one.iter().chain(one.iter()).cloned().collect();
        let p = ledger_table(&both);
        assert!(
            p.contains("<code>tar-time</code></td><td class=\"n\">6</td>"),
            "{p}"
        );
        assert!(
            p.contains(
                "<code>reviewed-pass</code> <span class=\"diff\">caps</span></td>\
                 <td class=\"n\">10</td>"
            ),
            "{p}"
        );
        assert!(
            p.contains("<code>cargo-vcs-hash</code> <span class=\"diff\">caps</span>"),
            "{p}"
        );
        assert!(
            p.contains("<span class=\"diff\">proposed by claude-x</span>"),
            "{p}"
        );
        assert!(
            p.contains("<span class=\"diff\">reviewed by alice</span>"),
            "{p}"
        );
        assert!(p.contains("<span class=\"dim\">builtin</span>"), "{p}");
        // The bar is `entries_touched`, relative to the pass that touched most.
        assert!(
            p.contains(
                "width=\"420\" height=\"12\" preserveAspectRatio=\"none\" role=\"img\" \
                 aria-label=\"10 entries\""
            ),
            "{p}"
        );
        assert!(
            p.contains(
                "width=\"84\" height=\"12\" preserveAspectRatio=\"none\" role=\"img\" \
                 aria-label=\"2 entries\""
            ),
            "{p}"
        );
        assert!(p.contains("4.0 KB"), "{p}");
        assert!(
            ledger_table(&[]).contains("no pass changed anything on either side"),
            "an empty ledger is a statement about the bytes"
        );
        // Risk is the colour: grey for a structural pass, the verdict palette for the rest.
        let structural = ledger_table(&[applied(
            "tar-entry-order",
            trigon_core::RiskTier::Structural,
            trigon_core::Provenance::Builtin,
            4,
        )]);
        assert!(structural.contains("fill=\"#6b6b66\""), "{structural}");
        assert!(p.contains("fill=\"#b3261e\""), "Lossy is red:\n{p}");
    }

    /// One member, as `member_diffs` would describe it: `(upstream, rebuild)` for each reading.
    fn member(
        path: &str,
        raw: (Option<&str>, Option<&str>),
        stabilized: (Option<&str>, Option<&str>),
        content: (Option<&str>, Option<&str>),
    ) -> MemberDiff {
        let own =
            |(a, b): (Option<&str>, Option<&str>)| (a.map(str::to_string), b.map(str::to_string));
        MemberDiff {
            path: path.into(),
            published: raw.0.map(|_| path.into()),
            raw: own(raw),
            stabilized: own(stabilized),
            content: own(content),
            bytes: (raw.0.map(|_| 10), raw.1.map(|_| 2048)),
        }
    }

    #[test]
    fn every_member_is_in_exactly_one_band_and_the_table_opens_on_what_differs() {
        let m = [
            member(
                "a-identical",
                (Some("x"), Some("x")),
                (Some("x"), Some("x")),
                (Some("c"), Some("c")),
            ),
            member(
                "b-packed",
                (Some("x"), Some("y")),
                (Some("x"), Some("y")),
                (Some("c"), Some("c")),
            ),
            member(
                "c-new",
                (None, Some("y")),
                (None, Some("y")),
                (None, Some("c")),
            ),
            member(
                "d-stabilized",
                (Some("x"), Some("y")),
                (Some("z"), Some("z")),
                (Some("c"), Some("c")),
            ),
            member(
                "e-changed",
                (Some("x"), Some("y")),
                (Some("x"), Some("y")),
                (Some("c"), Some("d")),
            ),
        ];
        assert_eq!(
            member_verdicts(&m),
            BTreeMap::from([
                ("a-identical".to_string(), "identical"),
                ("b-packed".to_string(), "packed"),
                ("c-new".to_string(), "one-side"),
                ("d-stabilized".to_string(), "stabilized"),
                ("e-changed".to_string(), "differs"),
            ])
        );
        let bar = ladder_svg(&m);
        assert!(
            bar.contains(
                "5 members: 1 differ in content, 1 same bytes packed differently, 1 stabilized \
                 out, 1 identical, 1 on one side only"
            ),
            "{bar}"
        );

        let t = member_table(&m);
        let at = |p: &str| t.find(&format!("<code>{p}</code>")).unwrap();
        let order = [
            "c-new",
            "e-changed",
            "b-packed",
            "d-stabilized",
            "a-identical",
        ];
        for w in order.windows(2) {
            assert!(
                at(w[0]) < at(w[1]),
                "{} should come before {}:\n{t}",
                w[0],
                w[1]
            );
        }
        assert!(
            t.contains("<span class=\"ours\">only in rebuild</span>"),
            "a lone member says which side it is on:\n{t}"
        );
        // Absent from a side is not zero bytes on it.
        assert!(
            t.contains("<td class=\"n dim\">—</td><td class=\"n dim\">2.0 KB</td>"),
            "{t}"
        );
        assert!(
            t.contains("<span class=\"diff\">same bytes, packed differently</span>"),
            "{t}"
        );
        assert!(
            member_diffs(Path::new("a-1.bin"), Path::new("b-1.bin"))
                .err()
                .is_some_and(|e| e.contains("names no format")),
            "a file whose name names no format is refused, not guessed at"
        );
    }

    #[test]
    fn a_pass_that_found_nothing_to_do_is_listed_apart_from_one_never_configured() {
        let set = trigon_stabilize::profile("tar-gzip").unwrap();
        let ids: Vec<String> = set.members.iter().map(|m| m.id().to_string()).collect();
        let fired = |ids: &[String]| -> Vec<trigon_stabilize::Applied> {
            ids.iter()
                .map(|id| {
                    applied(
                        id,
                        trigon_core::RiskTier::Metadata,
                        trigon_core::Provenance::Builtin,
                        1,
                    )
                })
                .collect()
        };
        let artifact = Path::new("a-1.tgz");
        let none = silent_panel(artifact, &[]);
        assert!(
            none.contains(&format!(
                "{} of the <code>tar-gzip</code> set's {} passes ran and found nothing to change",
                ids.len(),
                ids.len()
            )),
            "{none}"
        );
        let all = silent_panel(artifact, &fired(&ids));
        assert!(
            all.contains(&format!(
                "nothing. Every one of the <code>tar-gzip</code> set's {} passes found something",
                ids.len()
            )),
            "{all}"
        );
        let most = silent_panel(artifact, &fired(&ids[1..]));
        assert!(
            most.contains(&format!("<code>{}</code>", ids[0])) && most.contains("1 of the"),
            "{most}"
        );
        // A file whose name names no format has no set to be silent in.
        assert_eq!(silent_panel(Path::new("a-1.bin"), &[]), "");
    }

    // --- the network transcript ------------------------------------------------------------------

    fn exchange(
        route: &str,
        url: &str,
        sha256: &str,
        bytes: u64,
        checked: &str,
    ) -> serde_json::Value {
        serde_json::json!({"route": route, "url": url, "sha256": sha256, "bytes": bytes,
                           "checked": checked})
    }

    #[tokio::test]
    async fn a_transcript_is_counted_against_its_own_length_and_every_row_is_listed() {
        // "12 opened" on its own reads as a total rather than a share, so every figure carries
        // its denominator. And the digest column is cut at a character: this file is read from
        // disk, and sixteen bytes of an edited one can end inside one.
        let odd = format!("a{}", "é".repeat(20));
        let mut index = exchange(
            "index",
            "http://mirror/npm/a",
            &"a".repeat(64),
            2048,
            "generated",
        );
        index["withheld"] = 3.into();
        let rows = [
            index,
            exchange(
                "artifact",
                "http://mirror/a.tgz",
                &"b".repeat(64),
                1_048_576,
                "opened",
            ),
            exchange("artifact", "http://mirror/b.tgz", &odd, 10, "unarmed"),
            exchange(
                "passthrough",
                "http://mirror/c.tgz",
                &"c".repeat(64),
                5,
                "partial",
            ),
        ];
        let w = work_dir("transcript-rows");
        put(w.join("run.json"), &run_json("pkg:npm/a@1", "exact"));
        put(
            w.join("rebuild").join("network.jsonl"),
            &rows.iter().map(|r| format!("{r}\n")).collect::<String>(),
        );

        let panel = network_panel(&w, 0);
        assert!(
            panel.contains(
                "<strong>4 response(s)</strong> crossed into this build, carrying 1.0 MB"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("1 of 4 opened and member-checked"),
            "{panel}"
        );
        assert!(
            panel.contains("1 of 4 arrived with no guard manifest loaded"),
            "{panel}"
        );
        assert!(panel.contains("1 of 4 were abandoned part-way"), "{panel}");
        assert!(
            panel.contains("<a href=\"/run/0/network\">Every row →</a>"),
            "{panel}"
        );

        let page = network_page(sweep_at(w), 0).await;
        assert!(page.contains("<h1>npm/a@1 · network</h1>"), "{page}");
        assert!(page.contains("4 row(s) · "), "{page}");
        assert!(
            page.contains(
                "<strong>1</strong> index request(s), <strong>3</strong> version(s) withheld \
                 across them, 3 artifact, 0 toolchain"
            ),
            "{page}"
        );
        for cell in [
            "<span class=\"dim\">mirror-composed</span>",
            "<td>opened</td>",
            "<span class=\"note\">unarmed</span>",
            "<span class=\"void\">partial</span>",
        ] {
            assert!(page.contains(cell), "{cell}:\n{page}");
        }
        assert!(
            page.contains(&format!("<code>{}</code>", "a".repeat(16))),
            "a digest is shown as its first sixteen characters:\n{page}"
        );
        assert!(!page.contains(&"a".repeat(17)), "{page}");
        assert!(
            page.contains(&format!("<code>a{}</code>", "é".repeat(15))),
            "{page}"
        );
    }

    #[tokio::test]
    async fn a_transcript_that_will_not_parse_is_not_a_transcript_of_nothing() {
        // No file, an empty file and a torn file are three answers, and only the empty one says
        // nothing crossed. The torn line is quoted back, and it is whatever the build asked for.
        let w = work_dir("transcript-states");
        put(w.join("run.json"), &run_json("pkg:npm/a@1", "exact"));
        let transcript = w.join("rebuild").join("network.jsonl");
        put(transcript.clone(), &format!("{{\"route\":\"{XSS}\n"));
        let torn = network_panel(&w, 0);
        assert!(
            torn.contains("will not parse, so what crossed is unknown rather than nothing"),
            "{torn}"
        );
        assert!(!torn.contains("<img") && torn.contains("&lt;img"), "{torn}");
        assert!(!torn.contains("response(s)"), "{torn}");

        put(transcript.clone(), "");
        let empty = network_panel(&w, 0);
        assert!(
            empty.contains("nothing crossed the network into this build"),
            "{empty}"
        );
        assert!(
            empty.contains("source: <code>rebuild/network.jsonl</code>, 0 B"),
            "{empty}"
        );
        let page = network_page(sweep_at(w.clone()), 0).await;
        assert!(page.contains("0 row(s) · 0 B on disk"), "{page}");
        assert!(page.contains("nothing crossed the network"), "{page}");
        assert!(!page.contains("<th>route</th>"), "{page}");

        // A body past what the guard opens is hashed and no more, and the row says so.
        put(
            transcript,
            &format!(
                "{}\n",
                exchange("artifact", "http://mirror/big.tgz", "d", 9, "hashed")
            ),
        );
        let page = network_page(sweep_at(w), 0).await;
        assert!(
            page.contains("<span class=\"dim\">hashed only</span>"),
            "{page}"
        );
    }

    // --- what the pages under a run are called ---------------------------------------------------

    #[tokio::test]
    async fn the_pages_under_a_run_are_named_the_way_the_run_page_is() {
        // A maven purl joins its qualifiers with `&`. The network and ledger pages escaped the
        // title and then handed it to `page`, which escapes it again — the tab read `&amp;` — and
        // a run that left no report titled them with an empty string.
        let w = work_dir("titles");
        put(
            w.join("a").join("run.json"),
            &run_json("pkg:maven/org.example/a@1?classifier=x&type=jar", "exact"),
        );
        put(w.join("zz-half-a-run").join("strategy.yaml"), "id: x\n");
        let tab = "<title>maven/org.example/a@1?classifier=x&amp;type=jar · ";
        for (what, page) in [
            ("network", network_page(sweep_at(w.clone()), 0).await),
            ("compare", compare_page(sweep_at(w.clone()), 0).await),
            ("source", source_of(sweep_at(w.clone()), 0).await),
            ("run", run_page(sweep_at(w.clone()), 0).await),
        ] {
            assert!(page.contains(tab), "{what}:\n{page}");
            assert!(
                !page.contains("&amp;amp;"),
                "the {what} page escaped its title twice:\n{page}"
            );
        }
        for (what, page) in [
            ("network", network_page(sweep_at(w.clone()), 1).await),
            ("compare", compare_page(sweep_at(w.clone()), 1).await),
        ] {
            assert!(
                page.contains("<h1>zz-half-a-run · "),
                "the {what} page of a run with no report names its directory:\n{page}"
            );
        }
        // The source page is the fourth under a run, and it built its own name from the report:
        // `target 001` under a run page that says `zz-half-a-run`.
        for (what, page) in [
            ("run", run_page(sweep_at(w.clone()), 1).await),
            ("source", source_of(sweep_at(w), 1).await),
        ] {
            assert!(
                page.contains("<h1>zz-half-a-run</h1>"),
                "the {what} page of a run with no report names its directory:\n{page}"
            );
        }
        // A sweep row whose directory holds no `run.json` — a resumed row, say — is named by the
        // row on both pages, not by its number on one of them.
        let w = work_dir("titles-sweep");
        put(w.join("results.tsv"), &results(&[("pkg:npm/a@1", "exact")]));
        for (what, page) in [
            ("run", run_page(sweep_at(w.clone()), 0).await),
            ("source", source_of(sweep_at(w), 0).await),
        ] {
            assert!(
                page.contains("<h1>npm/a@1</h1>"),
                "the {what} page names the row's target:\n{page}"
            );
        }
    }

    #[tokio::test]
    async fn every_tab_says_which_page_it_is_and_what_is_looking_at_it() {
        // The network and ledger tabs carried no tool name, the cluster tab was the bare key, and
        // the source tab was the run's own — two windows on one run, indistinguishable in the tab
        // bar and in the history.
        let w = work_dir("tabs");
        put(
            w.join("results.tsv"),
            "pkg:npm/a@1\tbuild-failed\t1.0\tcc/missing-header\t0\n",
        );
        let mut seen = BTreeMap::new();
        for path in [
            "/run/0",
            "/run/0/network",
            "/run/0/compare",
            "/run/0/source",
            "/cluster?key=cc%2Fmissing-header",
        ] {
            let (status, out) = served(sweep_at(w.clone()), path).await;
            assert_eq!(status, 200, "{path}:\n{out}");
            let tab = out
                .split("<title>")
                .nth(1)
                .and_then(|t| t.split("</title>").next())
                .unwrap_or_else(|| panic!("{path} has no title:\n{out}"))
                .to_string();
            assert!(tab.ends_with(" · trigon watch"), "{path}: {tab}");
            if let Some(other) = seen.insert(tab.clone(), path) {
                panic!("{path} and {other} are both `{tab}`");
            }
        }
        assert_eq!(
            seen.keys().cloned().collect::<Vec<_>>(),
            [
                "cc/missing-header · trigon watch",
                "npm/a@1 · compare · trigon watch",
                "npm/a@1 · network · trigon watch",
                "npm/a@1 · source · trigon watch",
                "npm/a@1 · trigon watch",
            ]
        );
    }

    #[tokio::test]
    async fn a_run_page_names_every_absent_fact_and_what_would_have_made_it_exist() {
        let w = work_dir("run-absences");
        put(w.join("results.tsv"), &results(&[("pkg:npm/a@1", "exact")]));
        let p = run_page(sweep_at(w.clone()), 3).await;
        assert!(p.contains("<h1>target 003</h1>"), "{p}");
        for absent in [
            "no row in results.tsv maps to this directory — it may be the target in flight, \
             whose outcome is unknown rather than failed",
            "no strategy.yaml",
            "no guard.json",
            "no build.log on disk",
            "no run.json — this target ran before the record existed",
            "no store was configured for this watch",
            "no <code>network.jsonl</code>",
            "both artifacts are not on disk here",
            "What ran inside the sandbox is not recorded",
        ] {
            assert!(p.contains(absent), "`{absent}` is not said:\n{p}");
        }
        assert!(!p.contains("Why this is the verdict"), "{p}");

        // What is there is shown: the strategy clipped, the guard escaped, the log classified.
        put(w.join("000").join("strategy.yaml"), &"x".repeat(9000));
        put(w.join("000").join("guard.json"), "{\"artifact\":\"a\"}");
        put(
            w.join("000").join("rebuild").join("build.log"),
            "step 1\ngcc: fatal error: Python.h: No such file or directory\n",
        );
        let p = run_page(sweep_at(w), 0).await;
        assert!(p.contains("<h1>npm/a@1</h1>"), "{p}");
        assert!(p.contains("… clipped</pre>"), "{p}");
        assert!(
            p.contains("<pre>{&quot;artifact&quot;:&quot;a&quot;}</pre>"),
            "{p}"
        );
        assert!(
            p.contains("classified now as <code>cc/missing-header</code>"),
            "{p}"
        );
        assert!(p.contains("not recorded at the time"), "{p}");

        // A number past the end of a directory of runs says how many there are.
        let idx = work_dir("run-out-of-range");
        put(
            idx.join("a").join("run.json"),
            &run_json("pkg:npm/a@1", "exact"),
        );
        put(
            idx.join("b").join("run.json"),
            &run_json("pkg:npm/b@1", "exact"),
        );
        let p = run_page(sweep_at(idx), 5).await;
        assert!(
            p.contains("this directory holds 2 run(s), numbered 0 to 1, and no run 5"),
            "{p}"
        );
        assert!(
            p.contains("<title>target 005 · trigon watch</title>"),
            "{p}"
        );
    }

    // --- how the source became the artifact ------------------------------------------------------

    fn sourced(repo: &str, commit: &str) -> String {
        serde_json::json!({
            "purl": "pkg:npm/a@1",
            "started": "2026-09-17T19:57:42Z",
            "finished": "2026-09-17T19:58:42Z",
            "outcome": "divergent",
            "source": {"repo_url": repo, "commit": commit, "how": "registry_commit"},
            "model_calls": 0,
        })
        .to_string()
    }

    #[tokio::test]
    async fn the_source_page_says_why_it_has_nothing_to_join() {
        let w = work_dir("source-none");
        put(w.join("run.json"), &run_json("pkg:npm/a@1", "exact"));
        let p = source_of(sweep_at(w), 0).await;
        assert!(p.contains("this run recorded no source"), "{p}");
        let w = work_dir("source-no-report");
        put(w.join("strategy.yaml"), "id: x\n");
        let p = source_of(sweep_at(w), 0).await;
        assert!(
            p.contains("<h1>target 000</h1>") && p.contains("this run recorded no source"),
            "{p}"
        );

        let commit = "0123456789abcdef0123456789abcdef01234567";
        let w = work_dir("source-no-artifact");
        put(
            w.join("run.json"),
            &sourced("https://github.com/o/r", commit),
        );
        let p = source_of(sweep_at(w), 0).await;
        assert!(p.contains("the published artifact is not on disk"), "{p}");

        let w = one_run(
            "source-garbage",
            &sourced("https://github.com/o/r", commit),
            "a-1.tgz",
            b"not a gzip",
            b"not a gzip",
        );
        let p = source_of(sweep_at(w), 0).await;
        assert!(p.contains("parsing the artifact"), "{p}");

        // No checkout on this machine: every member is unknown, and nothing was searched.
        let (up, rb) = divergent_pair();
        let w = one_run(
            "source-no-checkout",
            &sourced("https://github.com/o/r", commit),
            "a-1.tgz",
            &up,
            &rb,
        );
        let p = source_of(sweep_at(w), 0).await;
        assert!(
            p.contains(
                "<strong>4 member(s).</strong> Where they came from is unknown: the checkout for \
                 this commit is not on this machine, so nothing was searched."
            ),
            "{p}"
        );
        assert!(
            p.contains("Nothing the commit explains came back different."),
            "{p}"
        );
    }

    #[tokio::test]
    async fn a_member_the_commit_explains_that_came_back_different_is_the_case_worth_opening() {
        // Red in the verdict bar under green in the origin bar: a file somebody wrote, rebuilt
        // into something else. Counted rather than left for the eye.
        let up = tgz(&[
            ("package/README.md", b"line one\r\nline two\r\n", T),
            ("package/generated.js", b"made by the build\n", T),
            ("package/lib/native.so", b"\x7fELF as written", T),
            ("package/same.js", b"the maintainer's bytes\n", T),
        ]);
        let rb = tgz(&[
            ("package/README.md", b"line one\r\nline two\r\n", T),
            ("package/generated.js", b"made by the build\n", T),
            ("package/lib/native.so", b"\x7fELF as rebuilt", T),
            ("package/same.js", b"the maintainer's bytes\n", T),
        ]);
        let (repo, commit) = (
            "https://github.com/o/r",
            "0123456789abcdef0123456789abcdef01234567",
        );
        let w = one_run("source-join", &sourced(repo, commit), "a-1.tgz", &up, &rb);
        let s = sweep_at(w);
        let checkout = crate::provenance::checkout_dir(&s.sources, repo, commit);
        // LF in the commit and CRLF in the artifact: the commit's bytes after a rewrite, which is
        // not the commit's bytes.
        put(checkout.join("README.md"), "line one\nline two\n");
        put(checkout.join("lib").join("native.so"), "\x7fELF as written");
        put(checkout.join("same.js"), "the maintainer's bytes\n");

        let p = source_of(s, 0).await;
        assert!(
            p.contains(
                "<strong>4 member(s).</strong> 2 are the commit's bytes unchanged. 1 are the \
                 commit's bytes after a line-ending rewrite. 1 the build made — meaning 3 \
                 file(s) at 01234567."
            ),
            "tiers are reported apart and never summed:\n{p}"
        );
        assert!(
            p.contains("<strong>1 member(s) the commit explains came back different</strong>"),
            "{p}"
        );
        assert!(
            p.contains("<code class=\"dim\">lib/native.so</code>"),
            "{p}"
        );
        // The table puts what the commit does not explain first.
        let table = p.split("<h2>Member by member</h2>").nth(1).unwrap();
        let at = |m: &str| table.find(&format!("<code>{m}</code>")).unwrap();
        assert!(
            at("package/generated.js") < at("package/README.md"),
            "{table}"
        );
        assert!(
            at("package/README.md") < at("package/lib/native.so"),
            "{table}"
        );
        assert_eq!(origin_bars(&[], &BTreeMap::new()), "");
        // A member the comparison never reached is drawn as not compared, never as identical.
        let lone = [crate::provenance::Member {
            path: "package/x.js".into(),
            bytes: 1,
            origin: crate::provenance::Origin::Verbatim,
            source_path: Some("x.js".into()),
        }];
        let bars = origin_bars(&lone, &BTreeMap::new());
        assert!(bars.contains("package/x.js — not compared"), "{bars}");
        assert!(
            bars.contains("Nothing the commit explains came back different."),
            "{bars}"
        );
    }

    // --- the ribbon, and the small things every page leans on ------------------------------------

    #[test]
    fn the_ribbon_names_a_missing_link_rather_than_leaving_it_out() {
        let bare = chain_ribbon(
            &report(r#"{"purl":"p","started":"s","model_calls":0}"#),
            None,
        );
        assert!(
            bare.contains("commit</span> <span class=\"note\">none</span>"),
            "{bare}"
        );
        assert!(
            bare.contains("<span class=\"note\">no outcome</span>"),
            "{bare}"
        );
        for link in [">strategy</span>", ">build</span>", ">artifact</span>"] {
            assert!(
                !bare.contains(link),
                "{link} with nothing behind it:\n{bare}"
            );
        }

        let full = chain_ribbon(
            &report(
                r#"{"purl":"p","started":"s","model_calls":0,"outcome":"divergent",
                    "source":{"repo_url":"https://github.com/o/r","commit":"0123456789abcdef",
                              "how":"registry_commit"},
                    "strategy_digest":"fedcba9876543210","derivation":"heuristic",
                    "timings":[["deps",10.4],["build",null],["pack",20.0]]}"#,
            ),
            None,
        );
        assert!(
            full.contains("title=\"https://github.com/o/r — found by registry_commit\""),
            "{full}"
        );
        assert!(full.contains("<code>01234567</code>"), "{full}");
        assert!(
            full.contains("title=\"fedcba9876543210 — heuristic\"")
                && full.contains("<code>fedcba98</code>"),
            "{full}"
        );
        // The phases it timed, and a phase with no timing is not a phase of zero seconds.
        assert!(full.contains(">build</span> 30s"), "{full}");
        assert!(
            full.contains("<span class=\"tag diff\">divergent</span>"),
            "{full}"
        );
    }

    #[test]
    fn a_hand_edited_record_is_cut_at_a_character_and_never_inside_one() {
        // `&s[..8]` on a string somebody edited by hand is a panic inside a request handler rather
        // than a short string. Each value below puts a two-byte character across the cut.
        assert_eq!(short_hex("abcdefgé0123", 8), "abcdefgé");
        assert_eq!(short_hex("abc", 8), "abc");
        assert_eq!(clip("ééé", 2), "éé\n… clipped");
        assert_eq!(clip("éé", 2), "éé");
        let t = tail(&"é".repeat(10), 5);
        assert!(t.starts_with("… earlier output clipped\n"), "{t}");
        assert!(t.ends_with('é'), "{t}");

        let ribbon = chain_ribbon(
            &report(
                r#"{"purl":"p","started":"s","model_calls":0,"strategy_digest":"0123456é89",
                    "source":{"repo_url":"https://github.com/o/r","commit":"abcdefgé0123",
                              "how":"registry_commit"}}"#,
            ),
            None,
        );
        assert!(ribbon.contains("<code>abcdefgé</code>"), "{ribbon}");
        assert!(ribbon.contains("<code>0123456é</code>"), "{ribbon}");
        let record = report_panel(Some(&report(
            r#"{"purl":"p","started":"s","model_calls":0,"strategy_digest":"0123456789abcdeé0"}"#,
        )));
        assert!(record.contains("<code>0123456789abcdeé</code>"), "{record}");
    }

    #[test]
    fn a_blank_line_is_not_a_row_and_a_row_without_a_duration_is_not_one_either() {
        let (rows, dropped) = parse_results(
            "\n  \npkg:npm/a@1\texact\t1.5\t\t2\n\
             pkg:npm/b@1\texact\tnever\t\t0\npkg:npm/c@1\tvoid\n",
        );
        assert_eq!(
            dropped, 2,
            "a row whose seconds will not parse, and one with none"
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].seconds, 1.5);
        assert_eq!(
            rows[0].cluster, None,
            "an empty cluster column is no cluster"
        );
        assert_eq!(rows[0].model_calls, Some(2));
    }

    #[test]
    fn bytes_ages_and_forges_read_at_the_precision_a_page_needs() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1_048_576), "1.0 MB");
        assert_eq!(human_bytes(1_073_741_824), "1.00 GB");
        assert_eq!(ago(90), "90s ago");
        assert_eq!(ago(91), "1m ago");
        assert_eq!(ago(5400), "90m ago");
        assert_eq!(ago(5401), "1h ago");
        assert_eq!(short_repo("https://github.com/o/r"), "o/r");
        assert_eq!(short_repo("https://gitlab.com/o/r"), "gitlab.com/o/r");
        assert_eq!(short_repo("git@example.org:o/r"), "git@example.org:o/r");
    }

    #[test]
    fn the_rates_panel_says_which_rate_it_cannot_give_and_why() {
        assert!(
            rates_panel(&Rates::of(&[])).contains("nothing has been attempted"),
            "no rows is no rate, not two zeroes"
        );
        let uncompared = rates_panel(&Rates::of(&rows("a\terror:infra\t1.0\t\t0\n")));
        assert!(
            uncompared.contains("no target reached a comparison"),
            "{uncompared}"
        );
        assert!(!uncompared.contains("rate ok"), "{uncompared}");
        assert!(
            uncompared.contains("0 of 1 attempted targets reached a comparison at all"),
            "{uncompared}"
        );
        let some = rates_panel(&Rates::of(&rows(
            "a\texact\t1.0\t\t0\nb\tdivergent\t1.0\t\t0\n\
             c\tnormalized\t1.0\t\t0\nd\tvoid\t1.0\t\t0\n",
        )));
        assert!(
            some.contains("<div class=\"rate ok\">67%</div>")
                && some.contains("2 of 3 compared targets reproduced"),
            "{some}"
        );
        assert!(
            some.contains("<div class=\"rate\">75%</div>")
                && some.contains("3 of 4 attempted targets reached a comparison"),
            "{some}"
        );
        let quiet = clusters_panel(&rows("a\texact\t1.0\t\t0\nb\texact\t1.0\t\t0\n"));
        assert!(
            quiet.contains("nothing failed in the 2 target(s) recorded so far"),
            "a statement about what was recorded, never about the corpus:\n{quiet}"
        );
    }

    #[test]
    fn a_path_that_is_not_a_directory_is_refused_before_anything_listens() {
        let w = work_dir("serve-refuses");
        put(w.join("results.tsv"), "");
        let err = serve(
            w.join("results.tsv"),
            None,
            "127.0.0.1:0".into(),
            None,
            None,
        )
        .expect_err("a file is not a work directory");
        assert!(err.to_string().contains("is not a directory"), "{err}");
    }

    #[test]
    fn a_baseline_that_is_not_a_directory_is_refused_before_anything_listens() {
        // The address is held by this test, so a watch that let the baseline through fails on the
        // bind rather than serving forever: the error says which of the two stopped it.
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = held.local_addr().unwrap().to_string();
        let w = work_dir("serve-refuses-baseline");
        let err = serve(w.clone(), None, addr, None, Some(w.join("no-such-sweep")))
            .expect_err("a baseline that is not there");
        assert!(
            format!("{err:#}").contains("--baseline ")
                && format!("{err:#}").contains("no-such-sweep is not a directory"),
            "{err:#}"
        );
    }

    #[test]
    fn an_address_that_is_already_taken_is_named_rather_than_served_on() {
        // A port this test holds, so the watch cannot have it: the error names the address it
        // tried, which is the thing the operator has to change.
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = held.local_addr().unwrap().to_string();
        let err = serve(work_dir("serve-taken"), None, addr.clone(), None, None)
            .expect_err("the address is held by this test");
        assert!(
            format!("{err:#}").contains(&format!("binding {addr}")),
            "{err:#}"
        );
    }
}
