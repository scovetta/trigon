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
            reproduced: evidence.iter().filter(|f| **f == Family::Reproduced).count(),
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

/// Everything a page needs, re-read per request.
struct Sweep {
    work: PathBuf,
    targets: Option<PathBuf>,
    bind: String,
}

struct View {
    rows: Vec<Row>,
    dropped: usize,
    /// `None` when there is no `results.tsv` at all — which is not an empty sweep.
    age: Option<u64>,
    /// Target purls in the order the sweep will attempt them, when a targets file was named.
    targets: Option<Vec<String>>,
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
        let sweep: Option<crate::progress::Sweep> = std::fs::read_to_string(self.work.join("sweep.json"))
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
            rows,
            dropped,
            age,
            targets,
            sweep,
            status,
            live,
        }
    }

    /// Which per-target directory a purl's evidence is in.
    ///
    /// The sweep names them by the target's index in the targets file, so without that file this
    /// falls back to the row's position — which is the same number only if the sweep was not
    /// resumed against a reordered list. The page says which of the two it used.
    fn dir_of(&self, view: &View, purl: &str) -> Option<(usize, bool)> {
        if let Some(targets) = &view.targets {
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
             version. The results below are still what the sweep recorded.".into(),
        ),
        L::Starting => note("no target has been attempted yet".into()),
        L::Running => match &v.status.as_ref().and_then(|s| s.current.clone()) {
            Some(c) => note(format!(
                "on {} for {}, phase not recorded yet (docs/18 step 4)",
                esc(c.purl.strip_prefix("pkg:").unwrap_or(&c.purl)),
                ago(c.elapsed_seconds).trim_end_matches(" ago")
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
            note(format!(
                "heartbeating, and on {on} for {}s — past the {ceiling}s ceiling this sweep set \
                 for one target. Something is wrong by the sweep's own standard.",
                seconds
            ))
        }
        L::Stopped => note(
            "the heartbeat stopped and the process is gone. Everything below is what it recorded \
             before that; the target it was on has no outcome, which is not the same as failing."
                .into(),
        ),
        L::Unresponsive => note(
            "the heartbeat stopped and the process is still there — wedged in a way that took the \
             heartbeat with it. Worse than stopped.".into(),
        ),
        L::Finished => match v.sweep.as_ref().and_then(|s| s.finished.clone()) {
            Some(t) => note(format!("finished at {}", esc(&t))),
            None => note("finished".into()),
        },
    }
}

/// Seconds since an RFC 3339 UTC instant of the shape this project writes.
///
/// `None` when it will not parse, which the caller treats as "very old" rather than as "now": a
/// timestamp we cannot read must not make a dead sweep look alive.
fn rfc3339_age(s: &str) -> Option<u64> {
    let (date, rest) = s.split_once('T')?;
    let time = rest.strip_suffix('Z')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let mut t = time.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    // Days from civil, the inverse of the formatter in main.rs.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let then = days * 86_400 + hh * 3600 + mm * 60 + ss;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some((now - then).max(0) as u64)
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
        None => "<div><div class=\"note\" style=\"max-width:22rem\">no target reached a comparison, \
                 so there is no reproduction rate to report</div></div>"
            .to_string(),
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
    let rates = Rates::of(&v.rows);
    let live = v.live.is_live();
    let body = format!(
        "<h1>{}</h1>{}{}{}{}",
        esc(&sweep.work.display().to_string()),
        state_strip(&v, sweep.targets.as_deref()),
        rates_panel(&rates),
        clusters_panel(&v.rows),
        board_panel(&sweep, &v),
    );
    page("trigon watch", live, &body, &sweep.bind).into_response()
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
        match sweep.dir_of(&v, &m.purl).and_then(|(i, _)| read_log(&sweep.work, i)) {
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

fn read_log(work: &Path, index: usize) -> Option<String> {
    // `<work>/NNN/rebuild/build.log`, which is where `run_one` writes it: the collect directory is
    // `args.work.join("rebuild")` and the log goes beside the artifacts in it.
    std::fs::read_to_string(work.join(format!("{index:03}")).join("rebuild").join("build.log")).ok()
}

async fn run(State(sweep): State<std::sync::Arc<Sweep>>, UrlPath(index): UrlPath<usize>) -> Response {
    let v = sweep.read();
    // The only path parameter anywhere, parsed as an integer by the extractor and re-formatted
    // before it is joined to anything, so no request string reaches the filesystem.
    let dir = sweep.work.join(format!("{index:03}"));
    let row = v
        .rows
        .iter()
        .find(|r| sweep.dir_of(&v, &r.purl).map(|(i, _)| i) == Some(index));

    let mut body = format!(
        "<h1>{}</h1>{}",
        match row {
            Some(r) => esc(r.purl.strip_prefix("pkg:").unwrap_or(&r.purl)),
            None => format!("target {index:03}"),
        },
        state_strip(&v, sweep.targets.as_deref()),
    );

    match row {
        Some(r) => {
            let fam = Family::of(&r.label);
            body.push_str(&format!(
                "<p><span class=\"tag {}\">{}</span> · {:.0}s{}</p>",
                fam.css(),
                esc(&r.label),
                r.seconds,
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
        None => body.push_str(
            "<p class=\"note\">no row in results.tsv maps to this directory — it may be the target \
             in flight, whose outcome is unknown rather than failed</p>",
        ),
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

    body.push_str("<h2>Build log</h2>");
    match read_log(&sweep.work, index) {
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

    body.push_str(
        "<h2>Not recorded</h2><ul class=\"note\">\
         <li>per-phase timings: measured in the sandbox, printed under <code>-v</code>, never \
         persisted (docs/18 step 5)</li>\
         <li>the repair history and its stop reason: same</li>\
         <li>what the mirror observed: only reaches a store, and only where <code>--store</code> \
         was passed (step 6)</li></ul>",
    );
    body.push_str("<p><a href=\"/\">← all targets</a></p>");

    page(&format!("target {index:03}"), v.live.is_live(), &body, &sweep.bind).into_response()
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
pub fn serve(work: PathBuf, targets: Option<PathBuf>, bind: String) -> Result<()> {
    if !work.is_dir() {
        anyhow::bail!("{} is not a directory", work.display());
    }
    let sweep = std::sync::Arc::new(Sweep {
        work,
        targets,
        bind: bind.clone(),
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(board))
        .route("/cluster", axum::routing::get(cluster))
        .route("/run/{index}", axum::routing::get(run))
        .route("/api/state", axum::routing::get(api_state))
        .with_state(sweep);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .with_context(|| format!("binding {bind}"))?;
        println!("watching on http://{bind}  (read-only; ctrl-c to stop)");
        axum::serve(listener, app).await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
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
        assert_eq!(urlencode("cc/missing-header:python.h"), "cc%2Fmissing-header%3Apython.h");
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

    #[test]
    fn ages_read_as_words() {
        assert_eq!(ago(5), "5s ago");
        assert_eq!(ago(300), "5m ago");
        assert_eq!(ago(7200), "2h ago");
    }
}
