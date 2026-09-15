//! What a sweep says about itself while it runs.
//!
//! Two files in the work directory, and the division between them is the design:
//!
//! - **`sweep.json`** is written once at the start and never rewritten — what this sweep *is*. It
//!   carries the corpus it was given (by path and by the digest of its bytes), the image, the tier,
//!   and the version of the binary that ran it. Without it a reader has no denominator, and two
//!   sweeps cannot be told to be of the same corpus, which is what a comparison depends on.
//! - **`status.json`** is replaced on every heartbeat — where this sweep *is*. It exists so that a
//!   reader can tell a sweep that is working from one that stopped, which cannot be inferred from
//!   results alone: a long build and a dead process look identical from outside.
//!
//! # The reader is not trusted to be lucky
//!
//! `status.json` is written to a temporary file in the same directory and renamed over the target,
//! so a reader never sees half of one. Where rename is not atomic — a network filesystem — the
//! reader's job is to treat an unparseable status as *unreadable* and keep showing the previous
//! state with its age. Never blank, and never zero.
//!
//! # Liveness is three separate questions
//!
//! "Is it alive" is not one fact. A heartbeat says the process is running; the pid says whether it
//! exists at all; the current target's age says whether it is making progress. A sweep can be alive
//! and stuck, and that is the state that pages a human — so it is derived from a threshold the
//! sweep itself chose, its own per-target timeout, rather than from a number we invented.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// How often the heartbeat is rewritten.
pub const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(10);

/// What this sweep is. Written once.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sweep {
    pub started: String,
    pub pid: u32,
    /// The binary that ran it, so a result set is attributable to a version.
    pub version: String,
    /// The corpus, by path and by content. The digest is what says two sweeps are of the same
    /// corpus; the path is what says where to look.
    pub targets_path: Option<String>,
    pub targets_sha256: Option<String>,
    pub targets_count: usize,
    /// Already recorded when this sweep started, from a previous run of it.
    pub resumed_from: usize,
    pub image: String,
    pub egress: String,
    pub timewarp: Option<String>,
    pub model: Option<String>,
    pub store: Option<String>,
    pub definitions: Option<String>,
    /// The per-target wall-clock ceiling. A reader uses it as the threshold past which a target is
    /// stuck, so the threshold is the sweep's own and not one a page invented.
    pub timeout_seconds: u64,
    /// Set on a clean exit. Absent means the sweep did not finish, which is not the same as failing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,
}

/// Where this sweep is. Replaced on every heartbeat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub heartbeat: String,
    pub pid: u32,
    /// `starting`, `running`, or `finished`. Everything else a reader shows — stopped, stuck — is
    /// derived from this plus the clock plus the pid, because the process cannot report its own
    /// death.
    pub state: String,
    pub done: usize,
    pub total: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Current>,
}

/// The target in flight.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Current {
    pub index: usize,
    pub purl: String,
    pub started: String,
    /// Seconds since this target started, at the moment of the heartbeat. Carried rather than
    /// derived, so a reader with a skewed clock still reports what the sweep measured.
    pub elapsed_seconds: u64,
    /// Which phase it is in. `None` before the first mark, and shown as "not recorded" rather than
    /// as a blank: a phase nobody wrote is not a phase of zero length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// Seconds in *this phase*, which is the number that says whether a build is hung. A target can
    /// be twenty minutes in and perfectly healthy if nineteen of them were `deps`.
    #[serde(default)]
    pub phase_elapsed_seconds: u64,
}

/// The writer. Owns the heartbeat thread and stops it on drop.
pub struct Progress {
    work: PathBuf,
    shared: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Progress {
    /// Write `sweep.json` and start the heartbeat.
    ///
    /// Every failure here is ignored and logged. A sweep is hours of work and a page is a
    /// convenience; refusing to start one because the other could not be written would be the
    /// wrong way round.
    #[allow(clippy::too_many_arguments)]
    pub fn start(work: &Path, sweep: Sweep) -> Progress {
        let status = Status {
            heartbeat: crate::now_rfc3339(),
            pid: std::process::id(),
            state: "starting".into(),
            done: sweep.resumed_from,
            total: sweep.targets_count,
            current: None,
        };
        if let Err(e) = write_atomic(&work.join("sweep.json"), &sweep) {
            tracing::warn!("could not write sweep.json: {e}");
        }
        let shared = Arc::new(Mutex::new(status));
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let (work, shared, stop) = (work.to_path_buf(), shared.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(mut s) = shared.lock() {
                        s.heartbeat = crate::now_rfc3339();
                        if let Some(c) = &mut s.current {
                            c.elapsed_seconds =
                                c.elapsed_seconds.saturating_add(HEARTBEAT.as_secs());
                            c.phase_elapsed_seconds =
                                c.phase_elapsed_seconds.saturating_add(HEARTBEAT.as_secs());
                        }
                        let _ = write_atomic(&work.join("status.json"), &*s);
                    }
                    // Short sleeps rather than one long one, so a finished sweep is not held open
                    // for ten seconds waiting for its own heartbeat to notice.
                    for _ in 0..20 {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(HEARTBEAT / 20);
                    }
                }
            })
        };

        Progress {
            work: work.to_path_buf(),
            shared,
            stop,
            thread: Some(thread),
        }
    }

    /// Say which phase the target in flight is in. Written immediately.
    ///
    /// The phase is what turns "on left-pad for 40s" into "in deps for 40s", which is the
    /// difference between a slow dependency install and a hung build — and it is the whole content
    /// of `stuck`.
    pub fn phase(&self, phase: &str) {
        if let Ok(mut s) = self.shared.lock()
            && let Some(c) = &mut s.current
        {
            if c.phase.as_deref() == Some(phase) {
                return;
            }
            c.phase = Some(phase.to_string());
            // The phase's own clock, so a page can say how long *this* phase has taken rather than
            // how long the target has.
            c.phase_elapsed_seconds = 0;
            s.heartbeat = crate::now_rfc3339();
            let _ = write_atomic(&self.work.join("status.json"), &*s);
        }
    }

    /// Say which target is in flight. Written immediately, not at the next heartbeat.
    pub fn target(&self, index: usize, purl: &str, done: usize) {
        if let Ok(mut s) = self.shared.lock() {
            s.state = "running".into();
            s.done = done;
            s.current = Some(Current {
                index,
                purl: purl.to_string(),
                started: crate::now_rfc3339(),
                elapsed_seconds: 0,
                phase: None,
                phase_elapsed_seconds: 0,
            });
            s.heartbeat = crate::now_rfc3339();
            let _ = write_atomic(&self.work.join("status.json"), &*s);
        }
    }

    /// The sweep finished cleanly. Stamps both files, because "finished" is a fact about the sweep
    /// and not only about where it got to.
    pub fn finish(&self, done: usize) {
        if let Ok(mut s) = self.shared.lock() {
            s.state = "finished".into();
            s.done = done;
            s.current = None;
            s.heartbeat = crate::now_rfc3339();
            let _ = write_atomic(&self.work.join("status.json"), &*s);
        }
        let path = self.work.join("sweep.json");
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(mut sweep) = serde_json::from_str::<Sweep>(&text)
        {
            sweep.finished = Some(crate::now_rfc3339());
            let _ = write_atomic(&path, &sweep);
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Write JSON to a temporary file beside the target and rename over it.
///
/// The same directory on purpose: rename is only atomic within a filesystem, and a temp directory
/// elsewhere would turn this into a copy that a reader can catch half-done.
fn write_atomic<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(value)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// The sha256 of a file's bytes, for the corpus digest.
pub fn digest_of(path: &Path) -> Option<String> {
    use sha2::Digest as _;
    let bytes = std::fs::read(path).ok()?;
    Some(format!("{:x}", sha2::Sha256::digest(&bytes)))
}

// ---------------------------------------------------------------------------------------------
// The reader's half: what a status file means, given the clock and the pid.
// ---------------------------------------------------------------------------------------------

/// What a reader should say about a sweep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Liveness {
    /// No `status.json` at all. A sweep that predates this, or a directory that is not one.
    Unknown,
    /// There is a file and it did not parse. Distinct from absent: somebody wrote something.
    Unreadable,
    Starting,
    Running,
    /// Alive, heartbeating, and on the same target for longer than the sweep's own timeout.
    Stuck {
        seconds: u64,
    },
    /// The heartbeat stopped and the process is gone.
    Stopped,
    /// The heartbeat stopped and the process is still there. Worse than stopped: it is wedged in a
    /// way that took the heartbeat thread with it.
    Unresponsive,
    Finished,
}

impl Liveness {
    /// Derive it. `heartbeat_age` is in seconds; `alive` is whether the pid still exists.
    ///
    /// A heartbeat is late rather than missing until it is several beats out: one missed write on a
    /// loaded machine is not a dead sweep, and calling it one would make the page cry wolf on
    /// exactly the machine a sweep loads.
    pub fn of(status: &Status, heartbeat_age: u64, alive: bool, timeout_seconds: u64) -> Liveness {
        const LATE: u64 = 4;
        if status.state == "finished" {
            return Liveness::Finished;
        }
        if heartbeat_age > LATE * HEARTBEAT.as_secs() {
            return if alive {
                Liveness::Unresponsive
            } else {
                Liveness::Stopped
            };
        }
        if let Some(c) = &status.current
            && timeout_seconds > 0
            && c.elapsed_seconds > timeout_seconds
        {
            // Past the ceiling the sweep set for one target. Something is wrong by the sweep's own
            // standard rather than by one this page chose.
            return Liveness::Stuck {
                seconds: c.elapsed_seconds,
            };
        }
        if status.state == "starting" {
            Liveness::Starting
        } else {
            Liveness::Running
        }
    }

    /// Whether a page showing this should keep refreshing itself.
    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Liveness::Starting | Liveness::Running | Liveness::Stuck { .. }
        )
    }
}

/// Whether a process id still exists.
///
/// Linux only, and deliberately: a wrong answer here is a page that says "stopped" about a running
/// sweep, so on anything without `/proc` the reader must not guess — it reports the heartbeat's age
/// and no more.
pub fn pid_alive(pid: u32) -> Option<bool> {
    let proc = Path::new("/proc");
    proc.is_dir().then(|| proc.join(pid.to_string()).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: &str, elapsed: Option<u64>) -> Status {
        Status {
            heartbeat: "2026-01-01T00:00:00Z".into(),
            pid: 1,
            state: state.into(),
            done: 3,
            total: 20,
            current: elapsed.map(|elapsed_seconds| Current {
                index: 3,
                purl: "pkg:npm/a@1".into(),
                started: "2026-01-01T00:00:00Z".into(),
                elapsed_seconds,
                phase: None,
                phase_elapsed_seconds: elapsed_seconds,
            }),
        }
    }

    #[test]
    fn a_late_heartbeat_is_not_a_dead_sweep() {
        // One missed write on a loaded machine is not a death, and a page that cries wolf on the
        // machine a sweep loads is a page nobody keeps open.
        let s = status("running", Some(5));
        assert_eq!(Liveness::of(&s, 12, true, 600), Liveness::Running);
        assert_eq!(Liveness::of(&s, 39, true, 600), Liveness::Running);
        // Four beats out, it is not late any more.
        assert_eq!(Liveness::of(&s, 41, true, 600), Liveness::Unresponsive);
        assert_eq!(Liveness::of(&s, 41, false, 600), Liveness::Stopped);
    }

    #[test]
    fn stuck_is_measured_against_the_sweeps_own_timeout() {
        // Not a threshold this page invented: the sweep declared how long one target may take, and
        // a target past it is wrong by that standard.
        let s = status("running", Some(700));
        assert_eq!(
            Liveness::of(&s, 2, true, 600),
            Liveness::Stuck { seconds: 700 }
        );
        // Under the ceiling it is just a slow build, which is most builds.
        assert_eq!(
            Liveness::of(&status("running", Some(500)), 2, true, 600),
            Liveness::Running
        );
        // And a sweep with no declared ceiling is never called stuck, rather than being measured
        // against zero.
        assert_eq!(Liveness::of(&s, 2, true, 0), Liveness::Running);
    }

    #[test]
    fn finished_wins_over_everything() {
        // A finished sweep's heartbeat is as old as the sweep, and none of that is a problem.
        let s = status("finished", None);
        assert_eq!(Liveness::of(&s, 86_400, false, 600), Liveness::Finished);
        assert!(!Liveness::of(&s, 86_400, false, 600).is_live());
    }

    #[test]
    fn a_status_file_round_trips() {
        let dir = std::env::temp_dir().join(format!("trigon-progress-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = status("running", Some(12));
        write_atomic(&dir.join("status.json"), &s).unwrap();

        let text = std::fs::read_to_string(dir.join("status.json")).unwrap();
        let back: Status = serde_json::from_str(&text).unwrap();
        assert_eq!(back.state, "running");
        assert_eq!(back.current.unwrap().elapsed_seconds, 12);
        // Nothing is left behind for a reader to trip over.
        assert!(!dir.join("status.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sweep_that_did_not_finish_says_so_by_omission() {
        // `finished` absent is not `finished: false`. A sweep killed at hour three did not fail;
        // it did not finish, and the two want different reactions.
        let json = serde_json::to_string(&Sweep {
            started: "2026-01-01T00:00:00Z".into(),
            pid: 1,
            version: "0.0.0".into(),
            targets_path: None,
            targets_sha256: None,
            targets_count: 20,
            resumed_from: 0,
            image: "img".into(),
            egress: "open".into(),
            timewarp: None,
            model: None,
            store: None,
            definitions: None,
            timeout_seconds: 600,
            finished: None,
        })
        .unwrap();
        assert!(!json.contains("finished"), "{json}");
        let back: Sweep = serde_json::from_str(&json).unwrap();
        assert!(back.finished.is_none());
    }
}

// ---------------------------------------------------------------------------------------------
// What one target did, written whatever happened to it.
// ---------------------------------------------------------------------------------------------

/// Everything one run knows about itself, on disk beside its logs.
///
/// One file rather than the two the plan sketched — a `failure.json` beside a `run.json` invites
/// the question of which is authoritative when they disagree, and they will: the signature is
/// classified where the log is in hand and everything else is known at the end.
///
/// Written on **every** terminal outcome. The store is not: `record_run` sits past the early return
/// that unwraps the comparison, so a void, a build failure, a no-strategy and an error of ours all
/// write nothing there. That is right for an attestor — no statement may be written about a run
/// that is evidence of nothing — and it is exactly why something else has to record the rest.
///
/// Every `Option` is a real absence. A timing we failed to read is not a phase that took no time,
/// and a run with no strategy digest is not a run whose strategy hashed to nothing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunReport {
    pub purl: String,
    pub started: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,
    /// The label the sweep would write: `exact`, `build-failed:deps`, `void`, and so on. Absent
    /// when the run did not reach an outcome at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Our own error, where one stopped the run before it had an outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<trigon_core::FailureSignature>,
    /// Why the run is evidence of nothing, where it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub void_reason: Option<String>,
    /// Times the build asked for its own published artifact and the mirror refused it.
    ///
    /// **Not a void**: nothing arrived. Kept because it is usually the explanation for whatever
    /// failed next — a package that appears anywhere in its own dependency tree makes the build ask
    /// for the version under test — and because a sweep run without `--store` has only this file,
    /// so leaving it out lost the fact entirely.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_artifact: Vec<String>,
    /// Guarded members that arrived over the network and are **not** in the rebuilt artifact.
    ///
    /// **Not a void**: the bytes came in and did not come out, which is not what the guard exists
    /// to catch — a build that installs the neighbouring version of the package under test gets
    /// files that are byte-identical to the target's and ships none of them. Kept because a
    /// control whose near-misses are invisible cannot be told from one that never fires.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_notes: Vec<String>,

    /// What was built, and how we came to believe that is what was built.
    ///
    /// **The one thing a reader has to have and did not.** A verdict is a statement about a
    /// published artifact *and a source*, and the source half reached a `--verbose` terminal line
    /// and nothing else: `strategy.yaml` carries the repository and commit, and even that does not
    /// say whether the commit came from the registry or from stripping a prefix off a tag name.
    /// `SourceDiscovery`'s own doc comment says it "predicts a false result better than anything
    /// else available"; it was recorded nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<trigon_core::SourceProvenance>,

    /// One line per rung that was asked and declined: the rung's name and its reason.
    ///
    /// `no-strategy` is the most common non-answer a sweep produces and it carried no explanation
    /// at all — the CI rung computes a careful `Decline` naming the job it picked and what stopped
    /// it, and every one of those ended at a `debug!` nothing wrote down. Re-deriving them by hand
    /// from the registry days later is reading a record that did not record the thing that
    /// mattered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declines: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    /// What the rung had to assume. Printed beside a divergence so the result can be read against
    /// the guesses that produced it rather than as a fact about the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assumptions: Vec<String>,

    /// Per-phase durations in seconds. `None` means no data, never zero, and the convention
    /// survives the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timings: Vec<(String, Option<f64>)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<String>,
    /// Whether this run can account for everything that crossed into the build. Taken from the run
    /// itself, never from the flag that asked for a tier.
    ///
    /// Three states, and the third is load-bearing: `None` is a build that never finished and so
    /// has told us nothing. Rendering that as `false` sends a reader after an egress tier when the
    /// problem is a build that died.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestable: Option<bool>,
    /// How many responses crossed the network into the build. `None` where no transcript exists;
    /// `Some(0)` where one does and nothing came through, which is what `deny-all` produces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_exchanges: Option<usize>,
    /// Bytes those responses carried. `None` and `Some(0)` are the same two answers as above, one
    /// level out: `docs/10-scale.md` §1 puts dependency bytes first among the things that break at
    /// fleet scale, and a denominator that cannot tell "fetched nothing" from "not measured" is
    /// not a measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_bytes: Option<u64>,
    /// Seconds spent waiting on a model, and the tokens it cost. `None` where none was asked,
    /// which `docs/07-ai.md` §6 says should be the healthy majority of a corpus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_out: Option<u64>,
    /// Cached tokens, **a subset of `tokens_in` and never an addition**. Cache-read rate is an SLO
    /// (`docs/07-ai.md` §5), and summing the two inverts its sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_cached: Option<u64>,

    /// One entry per repair the loop attempted, and why it stopped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repairs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_stopped: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub model_calls: u32,

    /// What the mirror served, where one ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<trigon_mirror::Observed>,
}

impl RunReport {
    pub fn new(purl: &str) -> RunReport {
        RunReport {
            purl: purl.to_string(),
            started: crate::now_rfc3339(),
            ..Default::default()
        }
    }

    /// Write it into the target's work directory.
    ///
    /// Best effort and loud about failing: losing the record is a thing to report, not a reason to
    /// throw away the verdict the caller asked for.
    pub fn write(&mut self, work: &Path) {
        self.finished = Some(crate::now_rfc3339());
        if let Err(e) = write_atomic(&work.join("run.json"), self) {
            tracing::warn!("could not write run.json: {e}");
        }
    }
}
