//! **Absent must never render as zero.**
//!
//! `docs/16-findings.md` §1 names the bug class that dominated this project: *configuration that
//! looks applied and is not, with the failure surfacing somewhere that implicates the package
//! instead of us.* Four of its six instances produced a **number that looked like a package
//! problem** — a low reproduction rate, a corrupt artifact, an upstream error. The counter that
//! eventually exposed the `PIP_TRUSTED_HOST` finding had been printing `0 index request(s)` for
//! weeks, and a zero there reads exactly like a build that happened not to need anything.
//!
//! So the design goes out of its way: per-phase timings are `Option<Duration>` where `None` means
//! *no data, never zero*; `Rates::reproduction()` is `None` when nothing was compared rather than
//! 0%; `trigon watch`'s footer promises in so many words that "absent measurements are never shown
//! as zero"; and `docs/11-interfaces.md` §4 says a stale pass is worse than no data, because it
//! looks like data.
//!
//! Every one of those is a **seam**: something produces an absence, something else renders it, and
//! nothing asserts the two still agree. `watch.rs` and `eval.rs` both have careful unit tests for
//! their own halves — and unit tests are exactly what missed the five bugs found on 2026-09-13,
//! because each unit was correct in isolation.
//!
//! These tests therefore assert against the **rendered form a human or a CI gate actually sees**,
//! produced by running the real binary: the HTML and JSON `trigon watch` serves, and the stdout and
//! exit code of `trigon score`. Each constructs the *no data* case and the *genuine zero* case side
//! by side and asserts they do not read alike.
//!
//! Gated on `build` because `watch` and `score` are: the verifier binary
//! (`--no-default-features`) carries neither.

#![cfg(feature = "build")]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

/// A fresh, empty work directory named for the test that owns it.
///
/// Named rather than numbered so a failure leaves something readable behind, and cleared on entry
/// so a re-run never reads the previous one's files.
fn work(name: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join(format!("trigon-absent-{}", std::process::id()))
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

/// Now, in the shape `progress.rs` writes heartbeats in.
///
/// A heartbeat several beats old is `Unresponsive`, and `liveness_detail` says nothing about the
/// target in flight for a sweep it believes is wedged — so any test about what *running* renders
/// has to hand the page a timestamp it reads as current. Civil-from-days, the same algorithm
/// `main.rs::now_rfc3339` uses, because the reader is its exact inverse.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (days, tod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

// ---------------------------------------------------------------------------------------------
// A real `trigon watch`, over a real socket.
//
// The page is the product here: `watch.rs`'s own unit tests check `Rates::reproduction()` returns
// `None`, which is the half that was never in doubt. What this pins is that the `None` survives
// every step between the file on disk and the sentence an operator reads — the parse, the rate,
// the panel, the escape, the JSON. That is the span the five bugs of 2026-09-13 all lived in.
// ---------------------------------------------------------------------------------------------

struct Watch {
    child: Child,
    port: u16,
}

impl Watch {
    fn on(dir: &Path) -> Watch {
        // Three attempts: the port is chosen by asking the OS for one and then letting go of it,
        // so a parallel test can take it in between. Losing that race must not fail the assertion
        // under test.
        for attempt in 0..3 {
            let port = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let mut child = Command::new(bin())
                .arg("watch")
                .arg(dir)
                .args(["--bind", &format!("127.0.0.1:{port}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawning trigon watch");
            for _ in 0..200 {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                    Err(e) => panic!("waiting on trigon watch: {e}"),
                }
                // A real request, not a bare `connect`. The two are not the same claim: connect
                // succeeds as soon as the listening socket exists, because the kernel completes
                // the handshake into the accept backlog on the server's behalf — before anything
                // has called `accept`, and before the router is built. Treating "the port answers
                // a TCP handshake" as "the server will answer an HTTP request" made this suite
                // fail about one run in eight, always as a `ConnectionReset` in a later `get`,
                // always on a different test.
                if try_get(port, "/").is_some() {
                    return Watch { child, port };
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let _ = child.kill();
            let _ = child.wait();
            assert!(
                attempt < 2,
                "trigon watch never came up on {}",
                dir.display()
            );
        }
        unreachable!()
    }

    /// The body of one response.
    fn get(&self, path: &str) -> String {
        let text = try_get(self.port, path)
            .unwrap_or_else(|| panic!("GET {path} got no response from the watch server"));
        match text.split_once("\r\n\r\n") {
            Some((_, body)) => body.to_string(),
            None => text,
        }
    }
}

/// One request, or `None` if the server did not answer it.
///
/// HTTP/1.0 with `Connection: close`, so the read ends at EOF and this needs no client library the
/// crate does not already have. Used both to serve requests and to decide the server is up, which
/// is the point: readiness is defined as "answered a request", because that is what every caller
/// then goes on to assume.
fn try_get(port: u16, path: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut raw = Vec::new();
    // A reset here is the server not being ready yet, which is a retry rather than a failure.
    s.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.starts_with("HTTP/1").then_some(text)
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The `<tr>` whose first cell names `phase`. Enough HTML parsing to name a row, and no more.
fn row_for<'a>(html: &'a str, first_cell: &str) -> &'a str {
    let needle = format!(">{first_cell}</td>");
    html.split("<tr>")
        .find(|r| r.contains(&needle))
        .unwrap_or_else(|| panic!("no row for {first_cell} in:\n{html}"))
}

/// Run `trigon score` and return what a person and a CI job each see: stdout, and the exit code.
fn score(results: &Path, labels: &Path) -> (String, i32) {
    let out = Command::new(bin())
        .arg("score")
        .arg(results)
        .arg("--labels")
        .arg(labels)
        .output()
        .expect("running trigon score");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

// ---------------------------------------------------------------------------------------------

#[test]
fn a_sweep_that_compared_nothing_reports_no_reproduction_rate_rather_than_zero_percent() {
    // The headline number, and the one place this rule is load-bearing rather than tidy.
    // "Nothing reproduced" is a claim about the packages; "nothing reached a comparison" is a claim
    // about us, and `docs/16-findings.md` §1 is explicit that a rate which silently absorbs our own
    // faults "becomes a measure of our own reliability wearing the costume of a claim about
    // packages." Both of these sweeps have `reproduced == 0`. Only one of them has a rate.
    let absent = work("rate-absent");
    write(
        &absent.join("results.tsv"),
        "pkg:npm/a@1\tbuild-failed:deps\t12.0\tnpm/peer-conflict\t0\n\
         pkg:npm/b@1\terror:infra\t3.0\ttrigon/mirror-corrupted-artifact\t0\n",
    );
    let zero = work("rate-zero");
    write(
        &zero.join("results.tsv"),
        "pkg:npm/a@1\tdivergent\t12.0\t\t0\n\
         pkg:npm/b@1\tdivergent\t3.0\t\t0\n",
    );

    let (a, z) = (Watch::on(&absent), Watch::on(&zero));
    let (a_api, z_api) = (a.get("/api/state"), z.get("/api/state"));

    // On the wire the two answers are different JSON values, not the same one twice. A consumer
    // that plots `reproduction` must be able to leave a gap rather than draw a line to the floor.
    assert!(a_api.contains("\"reproduction\":null"), "{a_api}");
    assert!(z_api.contains("\"reproduction\":0.0"), "{z_api}");
    // And the denominators stay apart: nothing was compared in the first, everything in the second.
    assert!(a_api.contains("\"evidence\":0"), "{a_api}");
    assert!(z_api.contains("\"evidence\":2"), "{z_api}");

    let (a_html, z_html) = (a.get("/"), z.get("/"));
    assert!(
        a_html.contains("no target reached a comparison"),
        "a sweep that compared nothing has to say so:\n{a_html}"
    );
    assert!(
        !a_html.contains("class=\"rate ok\""),
        "and must not print a percentage at all:\n{a_html}"
    );
    assert!(
        z_html.contains("class=\"rate ok\">0%"),
        "two real divergences are a real 0%:\n{z_html}"
    );
}

#[test]
fn a_directory_with_no_results_is_not_a_sweep_whose_results_are_zero_seconds_old() {
    // Freshness is the other number `docs/11-interfaces.md` §4 cares about: "a stale pass is worse
    // than no data, because it looks like data." An age of zero says the sweep wrote something a
    // moment ago. No file at all says nobody has written anything here — possibly because this is
    // not a sweep directory. Rendering the second as the first invents a heartbeat.
    let nothing = work("age-absent");
    let empty = work("age-zero");
    // Present and empty: zero rows, and an mtime. Distinct from having no file.
    write(&empty.join("results.tsv"), "");

    let (n, e) = (Watch::on(&nothing), Watch::on(&empty));
    let (n_api, e_api) = (n.get("/api/state"), e.get("/api/state"));

    assert!(n_api.contains("\"results_age_seconds\":null"), "{n_api}");
    assert!(
        !e_api.contains("\"results_age_seconds\":null"),
        "a file that exists has an age, even with nothing in it:\n{e_api}"
    );
    // Both are honestly zero *attempted*: that is a count, and the count really is zero.
    assert!(n_api.contains("\"attempted\":0"), "{n_api}");
    assert!(e_api.contains("\"attempted\":0"), "{e_api}");

    let n_html = n.get("/");
    assert!(
        n_html.contains("no results.tsv here yet"),
        "an absent file is named, together with what it would mean:\n{n_html}"
    );
    assert!(
        e.get("/").contains("last result"),
        "and a present one is dated"
    );
}

#[test]
fn a_sweep_that_wrote_no_status_is_not_a_sweep_that_has_started_and_done_nothing() {
    // `Liveness::Unknown` and `Liveness::Starting` both have `done == 0` and no current target.
    // They are opposite findings: the first means the page could not look, the second means it
    // looked and the sweep has genuinely not begun a target. `progress.rs` says it out loud —
    // "we did not look and find nothing, there was nothing to look at" — and only the rendering
    // can prove the distinction survived.
    let unknown = work("live-absent");
    let starting = work("live-zero");
    write(
        &starting.join("status.json"),
        &format!(
            r#"{{"heartbeat":"{}","pid":{},"state":"starting","done":0,"total":20}}"#,
            now_rfc3339(),
            std::process::id()
        ),
    );

    let (u, s) = (Watch::on(&unknown), Watch::on(&starting));
    let (u_api, s_api) = (u.get("/api/state"), s.get("/api/state"));

    assert!(u_api.contains("\"state\":\"state unknown\""), "{u_api}");
    assert!(s_api.contains("\"state\":\"starting\""), "{s_api}");
    // The detail is where the honesty lives, and it is carried into the JSON stripped of its
    // markup so a script reader gets the same caveat a person does.
    assert!(
        u_api.contains("no status.json"),
        "an absent heartbeat has to name itself as absent:\n{u_api}"
    );
    assert!(
        s_api.contains("no target has been attempted yet"),
        "and a real zero has to say it is a real zero:\n{s_api}"
    );
}

#[test]
fn a_phase_with_no_timing_renders_differently_from_a_phase_that_took_no_time() {
    // The convention `docs/02-domain-model.md` inherited from the prior art, and the one every
    // downstream average depends on: `None` is no data, never zero. It has to survive four hops —
    // the sandbox's `Option<Duration>`, the event sink's `Option<f64>`, `run.json` on disk, and the
    // page. A `0.0` that started life as "we failed to read the clock" understates every build it
    // is averaged into, and nothing downstream can tell.
    let w = work("timings");
    write(&w.join("results.tsv"), "pkg:npm/a@1\texact\t54.0\t\t0\n");
    write(
        &w.join("000").join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z",
            "timings":[["source",null],["deps",0.0],["build",41.5]]}"#,
    );

    let html = Watch::on(&w).get("/run/0");
    let (source, deps, build) = (
        row_for(&html, "source"),
        row_for(&html, "deps"),
        row_for(&html, "build"),
    );
    assert!(
        source.contains("no data"),
        "an unread timing says so:\n{source}"
    );
    assert!(
        deps.contains(">0.0<") && !deps.contains("no data"),
        "a phase that genuinely took no measurable time shows the number:\n{deps}"
    );
    assert!(build.contains(">41.5<"), "{build}");
    // And the two are not merely styled differently: the absent one carries no number at all, so
    // nothing scraping this page can read it as a duration.
    assert!(
        !source.contains("0.0"),
        "no data must not be spelled with a digit:\n{source}"
    );
}

#[test]
fn a_mirror_that_never_ran_is_not_a_mirror_that_served_nothing() {
    // The canonical instance of the whole class, from `docs/16-findings.md` §1. `PIP_INDEX_URL`
    // without `PIP_TRUSTED_HOST` makes pip warn once and resolve against the live index, so every
    // PyPI run recorded a pin it did not have — and the counter that would have shown it sat at
    // zero, reading exactly like a build that needed no dependencies. The repair was not to hide
    // the zero but to make the page say which of the two readings applies, and to keep "no mirror
    // ran at all" a third state rather than the same zero.
    let never = work("pin-absent");
    write(&never.join("results.tsv"), "pkg:npm/a@1\texact\t1.0\t\t0\n");
    write(
        &never.join("000").join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z"}"#,
    );

    let silent = work("pin-zero");
    write(
        &silent.join("results.tsv"),
        "pkg:npm/a@1\texact\t1.0\t\t0\n",
    );
    write(
        &silent.join("000").join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z",
            "pin":{"index_requests":0,"versions_withheld":0,"artifact_requests":0,
                   "toolchain_requests":0,"rejected":0}}"#,
    );

    let bound = work("pin-bound");
    write(&bound.join("results.tsv"), "pkg:npm/a@1\texact\t1.0\t\t0\n");
    write(
        &bound.join("000").join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z",
            "pin":{"index_requests":7,"versions_withheld":1044,"artifact_requests":3,
                   "toolchain_requests":0,"rejected":0}}"#,
    );

    let n = Watch::on(&never).get("/run/0");
    let s = Watch::on(&silent).get("/run/0");
    let b = Watch::on(&bound).get("/run/0");

    // **A heading with a caveat, not a blank.** This used to assert the section was absent
    // entirely, which is the bug this file is about, asserted into place: the one section that says
    // whether the dependency index was really pinned simply vanished on every run that could not
    // answer. What must not appear is five zeroes; what must appear is why there are no counters.
    assert!(
        n.contains("Registry pin"),
        "a run that cannot answer still owes the reader the question:\n{n}"
    );
    assert!(
        n.contains("not five zeroes"),
        "the absence has to name itself:\n{n}"
    );
    assert!(
        !n.contains("<td>0</td>"),
        "no mirror ran, so there are no counters to show — not five zeroes:\n{n}"
    );
    assert!(s.contains("Registry pin"), "{s}");
    assert!(
        s.contains("the mirror was never contacted"),
        "a zeroed counter is ambiguous and has to be read out as ambiguous:\n{s}"
    );
    assert!(
        b.contains("proof the pin reached the client"),
        "and a non-zero one is the evidence the finding asked for:\n{b}"
    );
    // The three readings are three different sentences, which is the whole repair.
    assert!(!s.contains("proof the pin reached the client"), "{s}");
}

#[test]
fn a_target_nobody_ran_is_named_rather_than_scored_as_a_target_that_needed_nothing() {
    // `trigon_ai::score` splits these: a labelled target with no row lands in `missing` and in no
    // denominator, while a target that ran and called no model is scored at zero. Collapsing the
    // first into the second is `eval.rs`'s own stated failure mode — "a corpus quietly shrinking is
    // how a rate improves without anything improving" — and it also flips the verdict, because
    // `Scorecard::acceptable()` refuses a corpus with anything missing.
    let d = work("score-missing");
    write(
        &d.join("labels.json"),
        r#"{"labels":[
            {"purl":"pkg:npm/ran@1","capability":"trivial-deterministic","reason":"pure tarball"},
            {"purl":"pkg:npm/never@1","capability":"trivial-deterministic","reason":"pure tarball"}]}"#,
    );
    write(&d.join("one.tsv"), "pkg:npm/ran@1\texact\t1.0\t\t0\n");
    write(
        &d.join("two.tsv"),
        "pkg:npm/ran@1\texact\t1.0\t\t0\npkg:npm/never@1\texact\t1.0\t\t0\n",
    );

    let (one, one_code) = score(&d.join("one.tsv"), &d.join("labels.json"));
    let (two, two_code) = score(&d.join("two.tsv"), &d.join("labels.json"));

    assert!(
        one.contains("labelled but not reported on") && one.contains("pkg:npm/never@1"),
        "the unrun target is named, not averaged over:\n{one}"
    );
    // The rate is over what was measured. Reporting `1/2` would fold the unmeasured target into
    // the denominator as a failure; reporting `of 2 labelled` would claim it was scored.
    assert!(one.contains("of 1 labelled"), "{one}");
    assert!(two.contains("of 2 labelled"), "{two}");
    assert_eq!(
        one_code, 1,
        "a corpus that shrank is not acceptable:\n{one}"
    );
    assert_eq!(two_code, 0, "and a complete one is:\n{two}");
}

#[test]
fn watch_and_score_agree_that_an_unrecorded_model_call_count_is_not_a_count_of_zero() {
    // Two readers of one file, in one binary — the shape of every bug found on 2026-09-13.
    //
    // `results.tsv` grew its model-call column after the cluster column did, so a row written by an
    // older binary has four fields and a row written by this one has five. A sweep resumed across
    // that boundary produces a file with both: `completed()` re-reads the old rows and appends new
    // ones beside them.
    //
    // `watch.rs::parse_results` reads the column as `Option<u32>` and the board renders an absent
    // count as an em dash, per row. `main.rs::read_results` reads it as `u32` with `unwrap_or(0)`
    // and tracks "was anything counted" as a single flag for the whole file — so one counted row is
    // enough to suppress the caveat for every uncounted one, and the uncounted rows are then summed
    // in as zeroes.
    //
    // What that costs: `trigon score` is the promotion gate, and the one regression it exists to
    // catch is a model firing on a target labelled `trivial-deterministic`. On a row whose count
    // was never recorded that check cannot be made — and a silent zero reports it as passed.
    let d = work("score-model-calls");
    write(
        &d.join("labels.json"),
        r#"{"labels":[
            {"purl":"pkg:npm/old@1","capability":"trivial-deterministic","reason":"pure tarball"},
            {"purl":"pkg:npm/new@1","capability":"trivial-deterministic","reason":"pure tarball"}]}"#,
    );
    // Resumed across the column's introduction: the first row never counted, the second counted
    // zero. The only difference between this file and the next is that one fact.
    let mixed = "pkg:npm/old@1\texact\t1.0\npkg:npm/new@1\texact\t1.0\t\t0\n";
    let counted = "pkg:npm/old@1\texact\t1.0\t\t0\npkg:npm/new@1\texact\t1.0\t\t0\n";
    write(&d.join("mixed.tsv"), mixed);
    write(&d.join("counted.tsv"), counted);

    // The half that is right. Two work directories differing only in that one column.
    let wm = work("watch-model-mixed");
    write(&wm.join("results.tsv"), mixed);
    let wc = work("watch-model-counted");
    write(&wc.join("results.tsv"), counted);
    let (m_html, c_html) = (Watch::on(&wm).get("/"), Watch::on(&wc).get("/"));
    // The model cell of the board, exactly as `board_panel` writes it. Matched on the whole cell
    // rather than on a bare dash, because the page's own prose uses em dashes too.
    let dash = "<td class=\"n\"><span class=\"note\">—</span></td>";
    let zero = "<td class=\"n\">0</td>";
    assert!(
        m_html.contains(dash) && m_html.contains(zero),
        "the board renders a count nobody took as a dash, beside a real zero as a zero:\n{m_html}"
    );
    assert!(
        !c_html.contains(dash),
        "and a file where every row counted has no dashed cell at all:\n{c_html}"
    );

    // The half under test. Same two files, same binary, and the answer has to distinguish them
    // too — either by naming the uncounted rows or by refusing to state a total it cannot know.
    let (m_out, _) = score(&d.join("mixed.tsv"), &d.join("labels.json"));
    let (c_out, _) = score(&d.join("counted.tsv"), &d.join("labels.json"));
    assert_ne!(
        m_out, c_out,
        "trigon score reports a sweep that never counted one target's model calls identically to \
         one that counted zero for both — and `trigon watch`, reading the same file in the same \
         binary, distinguishes them. The total on the first line is a claim the data does not \
         support, and the trivial-deterministic gate silently passes a target it could not check.\n\
         mixed:\n{m_out}\ncounted:\n{c_out}"
    );
}

// --- The network transcript's three states ---------------------------------------------------
//
// `attestable` is derived from whether a complete account of the build's egress exists, and the
// transcript is that account. So its three states carry the whole claim: no file means no account
// exists, an empty file is a complete account of a build that fetched nothing, and a file that will
// not parse is neither. Rendering any two of them alike would put the project's own headline
// control behind a sentence that is not true.

#[test]
fn an_absent_transcript_and_an_empty_one_are_not_the_same_page() {
    // The distinction the store keeps with an empty blob versus no blob, carried one level out to
    // the reader. A page that said "0 responses" for both would turn "we never looked" into "we
    // looked and nothing crossed" — which is the difference between an `open`-tier run, where
    // nothing is in a position to record, and a `deny-all` run, where the kernel guarantees it.
    let absent = work("transcript-absent");
    write(
        &absent.join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z","outcome":"normalized"}"#,
    );

    let empty = work("transcript-empty");
    write(
        &empty.join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z","outcome":"normalized"}"#,
    );
    write(&empty.join("rebuild").join("network.jsonl"), "");

    let a = Watch::on(&absent).get("/run/0");
    let e = Watch::on(&empty).get("/run/0");

    assert!(
        a.contains("no complete account"),
        "an absent transcript says no account exists:\n{a}"
    );
    assert!(
        e.contains("nothing crossed"),
        "an empty one is an account, of nothing:\n{e}"
    );
    assert_ne!(
        a, e,
        "the two states must not render alike — that is the whole distinction"
    );
    for (name, page) in [("absent", &a), ("empty", &e)] {
        assert!(
            !page.contains("0 response"),
            "`{name}` renders a count where a state belongs:\n{page}"
        );
    }
    // And an absent one must not read as an accusation: at `--egress open` it is the ordinary case.
    assert!(
        a.contains("ordinary case"),
        "no transcript is normal at open egress, and the page has to say so:\n{a}"
    );
}

#[test]
fn a_withheld_count_of_zero_is_not_a_row_that_withheld_nothing_knowable() {
    // `withheld` is `Option<u64>`: `None` means the row is not a filtered index document at all —
    // a dependency tarball is no evidence about the pin — and `Some(0)` means the filter ran and
    // found nothing to remove. Rendering the first as `0` merges the two readings the field exists
    // for, and the sum of those zeroes is the number that says whether the pin bound anything.
    let d = work("transcript-withheld");
    write(
        &d.join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z","outcome":"normalized"}"#,
    );
    write(
        &d.join("rebuild").join("network.jsonl"),
        // One index row that withheld nothing, one artifact row that cannot withhold anything.
        "{\"route\":\"index\",\"url\":\"https://r/x\",\"sha256\":\"aa\",\"bytes\":10,\
         \"checked\":\"generated\",\"withheld\":0}\n\
         {\"route\":\"artifact\",\"url\":\"https://r/y.tgz\",\"sha256\":\"bb\",\"bytes\":20,\
         \"checked\":\"hashed\"}\n",
    );

    let p = Watch::on(&d).get("/run/0/network");
    // The em dash is the artifact row's cell; the digit is the index row's. Both must be present,
    // which is only possible if they render differently.
    assert!(
        p.contains("—"),
        "a row that cannot withhold anything gets no digit:\n{p}"
    );
    assert!(
        p.contains("recomputed from these rows"),
        "the pin evidence is recomputed where the reader can check it:\n{p}"
    );
    // One index document, and zero versions withheld across it — a real zero, and it must survive.
    assert!(
        p.contains("1</strong> index request(s)") || p.contains("<strong>1</strong> index"),
        "the recomputed count is the rows the reader is looking at:\n{p}"
    );
}

#[test]
fn a_transcript_that_will_not_parse_is_not_a_transcript_of_nothing() {
    // The third state. A version skew or a torn write must not become a clean, short, believable
    // account — that is the shape that would let a run claim its egress was accounted for when the
    // account could not be read.
    let d = work("transcript-torn");
    write(
        &d.join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z","outcome":"normalized"}"#,
    );
    write(
        &d.join("rebuild").join("network.jsonl"),
        "{not json at all\n",
    );

    let p = Watch::on(&d).get("/run/0");
    assert!(
        p.contains("unknown rather than nothing"),
        "an unreadable account is not an empty one:\n{p}"
    );
    assert!(!p.contains("nothing crossed"), "{p}");
}

#[test]
fn the_page_says_what_it_does_not_observe_even_on_a_clean_run() {
    // A reader arriving at a page titled "network" will reasonably expect it to say what the build
    // *did*, and nothing here can: Tier 2 and Tier 3 observability are a deliberate cut, not a
    // missing feature. Rendering that gap as a blank would be this project's own bug on the page
    // built to prevent it, so the note is unconditional — it appears on a clean run too.
    let d = work("not-collected");
    write(
        &d.join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z","outcome":"exact"}"#,
    );
    write(
        &d.join("rebuild").join("network.jsonl"),
        "{\"route\":\"artifact\",\"url\":\"https://r/y.tgz\",\"sha256\":\"bb\",\"bytes\":20,\
         \"checked\":\"opened\"}\n",
    );

    for route in ["/run/0", "/run/0/network"] {
        let p = Watch::on(&d).get(route);
        assert!(
            p.contains("not recorded") && p.contains("syscall"),
            "`{route}` must name what it does not observe:\n{p}"
        );
        // And say it is a decision rather than an oversight, or it reads as a bug report.
        assert!(
            p.contains("deliberate cut"),
            "`{route}` must say the gap is a decision:\n{p}"
        );
    }
}

#[test]
fn a_comparison_with_no_artifacts_says_so_rather_than_showing_no_differences() {
    // The compare view re-derives from the two files, so a work directory that has been cleaned —
    // or a build that produced nothing — leaves it with no inputs. "0 members differ" would be the
    // same sentence a perfect reproduction prints, from a page that compared nothing at all.
    let d = work("compare-no-artifacts");
    write(
        &d.join("run.json"),
        r#"{"purl":"pkg:npm/a@1","started":"2026-01-01T00:00:00Z","outcome":"normalized"}"#,
    );

    for route in ["/run/0", "/run/0/compare"] {
        let p = Watch::on(&d).get(route);
        assert!(
            p.contains("not on disk"),
            "`{route}` must say it had nothing to compare:\n{p}"
        );
        assert!(
            !p.contains("0 member(s)") && !p.contains("<strong>0</strong> still differ"),
            "`{route}` renders a comparison it did not make:\n{p}"
        );
    }
}

#[test]
fn a_member_packed_differently_is_not_a_member_whose_content_changed() {
    // The compare view fingerprints each member twice: its bytes, and its bytes plus the archive
    // metadata a stabilizer can touch. Folding the two made `py-cpuinfo` read as nine of nine
    // members still differing where the comparison that decides the verdict says three — six had
    // byte-identical content and different zip modes, which no pass normalizes.
    //
    // Both readings are true and they answer different questions, so the page shows both.
    // Overstating is the expensive direction: a published divergence is a public claim about
    // somebody else's package, and "the code changed" is not what six identical files mean.
    //
    // Driven through the real binary against real artifacts, because the claim is about what the
    // page renders and not about a helper.
    let d = work("packed-differently");
    write(
        &d.join("run.json"),
        r#"{"purl":"pkg:pypi/a@1","started":"2026-01-01T00:00:00Z","outcome":"divergent"}"#,
    );
    // Two zips holding the same file at two different modes. `zip` is not available everywhere, so
    // this skips loudly rather than passing without having run.
    let make = |path: &std::path::Path, mode: &str| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let stage = d.join(format!("stage{mode}"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("f.txt"), "same bytes on both sides\n").unwrap();
        let _ = Command::new("chmod")
            .arg(mode)
            .arg(stage.join("f.txt"))
            .status();
        Command::new("zip")
            .args(["-X", "-q", path.to_str().unwrap(), "f.txt"])
            .current_dir(&stage)
            .status()
    };
    let up = d.join("a-1.zip");
    let rb = d.join("rebuild").join("run").join("a-1.zip");
    match (make(&up, "644"), make(&rb, "755")) {
        (Ok(a), Ok(b)) if a.success() && b.success() => {}
        _ => {
            eprintln!("skipped: `zip` is not available to build the fixture");
            return;
        }
    }

    let p = Watch::on(&d).get("/run/0/compare");
    assert!(
        p.contains("same bytes, packed differently"),
        "identical content in a differing entry must say so:\n{p}"
    );
    assert!(
        !p.contains("content still differs"),
        "nothing here changed content, and saying it did is an accusation:\n{p}"
    );
}
