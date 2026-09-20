//! Cutting a build log down to what a model needs to read.
//!
//! The single largest cost lever in the AI subsystem, worth roughly **7×** on its own
//! (`docs/07-ai.md` §4.2) — more than any choice of model. A 60,000-token log becomes 8,000, and
//! the 52,000 discarded are progress bars, download lines and repeated warnings that carry nothing
//! a repair could act on. The prior art truncates to a byte cap, which keeps the *end* of the log
//! and throws away the first error, usually the only line that mattered.
//!
//! Two properties this has to have, and they pull against each other:
//!
//! - **Deterministic.** The output feeds a cache key. A compressor that sampled, or that depended
//!   on wall-clock or map order, would make the same failure miss its own cached repair.
//! - **Honest about what it dropped.** Every elision says how many lines went and why. A model
//!   handed a silently truncated log reasons confidently about a build it cannot see, and the
//!   elision markers are what stop that.
//!
//! Control characters are stripped on the way through. The build script chose every byte here, and
//! this string is about to be put in front of a model that holds tools; see `docs/12-security.md`
//! §4. Stripping is not the mitigation — delimiting and typing the transcript is — but a log that
//! can repaint the terminal is not one anybody can read either.

use serde::{Deserialize, Serialize};

/// A log, cut down, with an account of what was removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compressed {
    pub text: String,
    pub original_lines: usize,
    pub kept_lines: usize,
    pub original_bytes: usize,
}

impl Compressed {
    /// How much smaller, as a factor. The number the cost model is built on.
    pub fn ratio(&self) -> f64 {
        if self.text.is_empty() {
            return 1.0;
        }
        self.original_bytes as f64 / self.text.len() as f64
    }
}

/// Lines that carry a failure. Matched case-sensitively where the marker is conventionally cased,
/// because `error` appears inside ordinary output far more often than `ERROR` does.
const ERROR_MARKERS: &[&str] = &[
    "error:",
    "Error:",
    "ERROR",
    "ERR!",
    "fatal:",
    "fatal error",
    "Traceback (most recent call last)",
    "FAILED",
    "failed with exit",
    "No such file or directory",
    "command not found",
    "Permission denied",
    "cannot find",
    "Cannot find",
    "not found",
    "Killed",
    "Segmentation fault",
    "panicked at",
];

/// Lines that are progress rather than information.
///
/// The bulk of a real log. `pip` prints one `Collecting` and one `Downloading` per dependency, and
/// `npm` prints a progress line per tick; on a package with 400 transitive dependencies that is
/// most of the file and none of the meaning.
const NOISE_PREFIXES: &[&str] = &[
    "Collecting ",
    "Downloading ",
    "Using cached ",
    "Requirement already satisfied",
    "Saved ",
    "added ",
    "npm http fetch",
    "npm timing",
    "npm sill",
    "npm verb",
    "Get:",
    "Hit:",
    "Fetched ",
    "Preparing to unpack",
    "Unpacking ",
    "Selecting previously unselected",
    "Setting up ",
    "Processing triggers",
    "Reading package lists",
    "Building dependency tree",
    "Reading state information",
    // npm's `--loglevel` install table: one line per package, hundreds of them on a real tree.
    "add\t",
];

/// Whether a line is a transfer progress meter rather than output.
///
/// `wget`'s dot progress has no fixed prefix — it is an indented run of dots and a percentage — and
/// it dominated a real log in the npm corpus: 55 MB of Node came down as roughly a thousand lines
/// of dots, which is most of the file and none of the meaning. Ten consecutive dots is not
/// something a diagnostic says.
fn is_progress(line: &str) -> bool {
    line.contains("..........")
}


/// What [`compress`] will actually emit, in bytes, for a given chosen set.
///
/// **Including the elision markers**, which is the whole point: their number depends on which
/// lines were chosen, so the greedy pass that chooses them cannot price them, and something has to
/// before the emit loop runs. Mirrors that loop exactly — a marker before each chosen line that
/// follows a gap, one more if the log ends in a gap, and the truncation notice.
fn rendered_len(
    cleaned: &[String],
    chosen: &std::collections::BTreeSet<usize>,
    truncated: bool,
) -> usize {
    let mut used = 0usize;
    let mut skipped = 0usize;
    for (i, line) in cleaned.iter().enumerate() {
        if !chosen.contains(&i) {
            skipped += 1;
            continue;
        }
        if skipped > 0 {
            used += marker_len(skipped);
            skipped = 0;
        }
        used += line.len() + 1;
    }
    if skipped > 0 {
        used += marker_len(skipped);
    }
    // `truncated`, not "ends in a gap". A log can lose a line from the middle and end on a kept
    // one, and the notice is pushed for either — pricing only the trailing case left the output 59
    // bytes over a 4096 budget, which is the notice, unpaid.
    if truncated {
        used += NOTICE.len() + 1;
    }
    used
}

fn marker_len(skipped: usize) -> usize {
    format!("… {skipped} lines omitted …").len() + 1
}

const NOTICE: &str = "… compressed to fit; the full log is in the run record …";

/// Cut a log down to roughly `budget` bytes.
///
/// What survives, in order of claim on the budget: every line that looks like an error, with a
/// little context around it; the tail, because the last thing a build said is usually why it
/// stopped; and the head, because the first error is often the real one and everything after it is
/// consequence. Everything else goes, and the gaps are marked.
pub fn compress(log: &str, budget: usize) -> Compressed {
    let original_bytes = log.len();
    let raw: Vec<&str> = log.lines().collect();
    let original_lines = raw.len();

    // Strip control characters and collapse runs of the same line before anything else decides
    // what to keep. A hundred identical warnings should cost one line of budget, not a hundred.
    let cleaned = dedup(raw.iter().map(|l| strip_controls(l)).collect());

    if cleaned.iter().map(|l| l.len() + 1).sum::<usize>() <= budget {
        let text = cleaned.join("\n");
        let kept_lines = cleaned.len();
        return Compressed {
            text,
            original_lines,
            kept_lines,
            original_bytes,
        };
    }

    let n = cleaned.len();
    let mut keep = vec![false; n];

    // 1. Errors, with two lines of context. A compiler's message is on one line and the source it
    //    points at is on the next; keeping only the first makes it unreadable.
    for (i, line) in cleaned.iter().enumerate() {
        if is_error(line) {
            let window = i.saturating_sub(1)..(i + 3).min(n);
            keep[window].fill(true);
        }
    }

    // 2. The tail. Whatever the build said last.
    for k in keep.iter_mut().skip(n.saturating_sub(TAIL_LINES)) {
        *k = true;
    }

    // 3. The head, for the setup that shaped everything after it.
    for k in keep.iter_mut().take(HEAD_LINES.min(n)) {
        *k = true;
    }

    // Noise never survives on context alone. A `Downloading` line beside an error is still a
    // `Downloading` line.
    for (i, line) in cleaned.iter().enumerate() {
        if is_noise(line) && !is_error(line) {
            keep[i] = false;
        }
    }

    // What to give up first, when the kept set does not fit.
    //
    // This used to emit in file order and `break` on the first line that overran the budget, so a
    // long log spent its whole budget on the head and never reached the end. The cause line is
    // usually the last thing said, so the compressed form of a chatty failure could omit the one
    // line that names it — `classify` then returned `unknown`, and since that signature is the
    // repair cache key, the same failure keyed two ways depending on how much the build printed.
    //
    // Priority, highest first: an error line, then the tail, then the head, then context. Within a
    // class the later line wins, because the deepest cause is usually the last mention of it.
    let priority = |i: usize| -> u8 {
        if is_error(&cleaned[i]) {
            3
        } else if i >= n.saturating_sub(TAIL_LINES) {
            2
        } else if i < HEAD_LINES.min(n) {
            1
        } else {
            0
        }
    };

    // Take best-first rather than dropping worst-first: one sort and one pass, where the removal
    // loop it replaced was quadratic and took 47 seconds on a 300 KB log.
    //
    // The sort is what stops a huge head crowding out the error at the end: the highest-priority
    // lines get first claim on the *whole* budget, which is a stronger guarantee than reserving a
    // fraction of it. (An earlier version of this comment claimed a third of the budget was
    // reserved. No reservation existed, and none was needed.)
    let mut order: Vec<usize> = (0..n).filter(|i| keep[*i]).collect();
    order.sort_by_key(|i| (std::cmp::Reverse(priority(*i)), std::cmp::Reverse(*i)));

    let mut chosen: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut budget_left = budget;
    let mut truncated = false;
    for i in order {
        let cost = cleaned[i].len() + 1;
        if cost <= budget_left {
            budget_left -= cost;
            chosen.insert(i);
        } else {
            truncated = true;
        }
    }

    // **Now pay for the elision markers, which the pass above does not price.**
    //
    // A marker costs bytes and its count is a function of *which* lines were chosen, so it cannot
    // be known until the set is. Left unpaid, the emit loop below discovers the shortfall and
    // resolves it by stopping — and it walks in file order, so the lines it drops are the last
    // ones in the log. That is where the error is, and where the priority sort had deliberately
    // spent the budget.
    //
    // Measured on a 4,000-line build log with scattered warnings, at both shipped budgets (4096 in
    // the rebuild path, 8192 in the repair path): the final `fatal error: Python.h` line was never
    // emitted, `classify` returned `unknown` on the compressed text and `cc/missing-header` on the
    // raw, and since that signature is the repair cache key the same failure keyed two ways
    // depending on how much the build printed. The comment at the top of this function describes
    // that exact regression as already fixed; it was reintroduced one loop later.
    //
    // So eviction happens here, by priority, which is what the loop below only claimed to do.
    // `truncated` feeds back in: the first eviction makes it true, which adds the notice's cost,
    // which may require another. The loop settles because every pass removes a line.
    while rendered_len(&cleaned, &chosen, truncated) > budget {
        let Some(&victim) = chosen
            .iter()
            .min_by_key(|i| (priority(**i), **i))
        else {
            break;
        };
        chosen.remove(&victim);
        truncated = true;
    }

    let mut out: Vec<String> = Vec::new();
    let mut kept_lines = 0usize;
    let mut used = 0usize;
    let mut skipped = 0usize;

    for (i, line) in cleaned.iter().enumerate() {
        if !chosen.contains(&i) {
            skipped += 1;
            continue;
        }
        if skipped > 0 {
            let marker = format!("… {skipped} lines omitted …");
            used += marker.len() + 1;
            out.push(marker);
            skipped = 0;
        }
        // No budget check here any more. The eviction above already made the whole rendering fit,
        // and a check in this loop can only ever resolve an overrun in file order — which is the
        // defect. If this ever did overrun, dropping the tail would be the wrong repair.
        debug_assert!(
            used + line.len() < budget,
            "the eviction pass should have made this fit"
        );
        used += line.len() + 1;
        kept_lines += 1;
        out.push(line.clone());
    }
    if skipped > 0 {
        out.push(format!("… {skipped} lines omitted …"));
    }
    if truncated {
        // Said outright. A model given a silently cut log reasons about a build it cannot see.
        out.push(NOTICE.to_string());
    }

    Compressed {
        text: out.join("\n"),
        original_lines,
        kept_lines,
        original_bytes,
    }
}

const HEAD_LINES: usize = 10;
const TAIL_LINES: usize = 40;

/// How many identical lines in a row before they collapse into one.
const RUN_LIMIT: usize = 2;

fn is_error(line: &str) -> bool {
    let t = line.trim_start();
    ERROR_MARKERS.iter().any(|m| t.contains(m))
}

fn is_noise(line: &str) -> bool {
    let t = line.trim_start();
    is_progress(t) || NOISE_PREFIXES.iter().any(|p| t.starts_with(p))
}

/// Collapse runs of identical lines.
///
/// Kept to *identical* rather than similar on purpose. "Similar" needs a distance threshold, and a
/// threshold is a knob whose value nobody can justify and which quietly merges two different errors
/// that happen to share a prefix.
///
/// The marker counts what was **omitted**, not how long the run was. Those differ by the copies
/// still on screen, and a marker that reported the run length beside three visible copies of the
/// line would overstate what is missing — in a log whose whole job is to be honest about what it
/// dropped.
fn dedup(lines: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        let mut end = i + 1;
        if !line.trim().is_empty() {
            while end < lines.len() && lines[end] == *line {
                end += 1;
            }
        }
        let run = end - i;
        let shown = run.min(RUN_LIMIT + 1);
        for _ in 0..shown {
            out.push(line.clone());
        }
        if run > shown {
            out.push(format!(
                "… the previous line repeated {} more times …",
                run - shown
            ));
        }
        i = end;
    }
    out
}

/// Drop control characters and ANSI escape sequences, keeping tabs.
///
/// `pub` because it is the one implementation of P12's little sibling — "text reaching a model is
/// bounded and control-stripped" (threat-model P7) — and the diff-opinion prompt needs the same
/// scrub this compressor gives build logs. A second copy is how the two would come to disagree.
pub fn strip_controls(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI and the handful of other escapes a build tool emits. Consume up to the final
            // byte rather than leaving the parameters behind as text.
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        if c == '\r' || (c.is_control() && c != '\t') {
            continue;
        }
        out.push(c);
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npmish(deps: usize) -> String {
        let mut s = String::from("npm info it worked if it ends with ok\n");
        for i in 0..deps {
            s.push_str(&format!(
                "npm http fetch GET 200 https://registry/pkg-{i} 12ms\n"
            ));
            s.push_str(&format!("added pkg-{i}@1.0.0\n"));
        }
        s.push_str("> demo@1.0.0 build\n> webpack\n");
        s.push_str("Module build failed: Error: Cannot find module 'node:path'\n");
        s.push_str("npm ERR! code ELIFECYCLE\n");
        s
    }

    #[test]
    fn the_error_survives_and_the_progress_does_not() {
        // The property the whole module exists for. A byte-cap truncation keeps the tail and loses
        // the first error; this keeps the error and loses the downloads.
        let log = npmish(400);
        let c = compress(&log, 4096);
        assert!(
            c.text.contains("Cannot find module 'node:path'"),
            "{}",
            c.text
        );
        assert!(
            !c.text.contains("pkg-200"),
            "progress lines survived:\n{}",
            c.text
        );
        assert!(c.ratio() > 7.0, "ratio was only {:.1}×", c.ratio());
    }

    #[test]
    fn an_error_keeps_the_line_that_explains_it() {
        // A compiler names the file on one line and shows the source on the next. Half of that is
        // not a diagnostic.
        let log = "noise\n".repeat(200)
            + "yarl/_quoting_c.c:6:10: fatal error: Python.h: No such file or directory\n    6 | #include \"Python.h\"\n      |          ^~~~~~~~~~\n"
            + &"more\n".repeat(200);
        let c = compress(&log, 2048);
        assert!(c.text.contains("fatal error: Python.h"), "{}", c.text);
        assert!(
            c.text.contains("#include"),
            "the context line went missing:\n{}",
            c.text
        );
    }

    #[test]
    fn what_was_dropped_is_stated_rather_than_hidden() {
        let c = compress(&npmish(400), 2048);
        assert!(c.text.contains("lines omitted"), "{}", c.text);
        assert!(c.kept_lines < c.original_lines);
    }

    #[test]
    fn a_short_log_passes_through_whole() {
        // Nothing is gained by eliding a log that already fits, and an elision marker in a 12-line
        // log reads as a bug.
        let log = "line one\nline two\nerror: it broke\n";
        let c = compress(log, 4096);
        assert_eq!(c.text, "line one\nline two\nerror: it broke");
        assert!(!c.text.contains("omitted"));
    }

    #[test]
    fn a_line_repeated_a_thousand_times_costs_one_line() {
        let log = "warning: unused variable\n".repeat(1000) + "error: it broke\n";
        let c = compress(&log, 8192);
        assert!(c.text.lines().count() < 10, "{}", c.text);
        assert!(c.text.contains("error: it broke"));
        // The count is what was omitted, not how long the run was: 1000 copies, 3 still shown.
        assert!(c.text.contains("repeated 997 more times"), "{}", c.text);
    }

    #[test]
    fn control_characters_do_not_survive() {
        // The build script chose every byte of this, and it is about to be put in front of a model.
        let log = format!(
            "\u{1b}[2J\u{1b}[1;31merror:\u{1b}[0m it broke\u{7}\nplain\r\n{}",
            "x\n".repeat(500)
        );
        let c = compress(&log, 1024);
        assert!(!c.text.contains('\u{1b}'), "{:?}", c.text);
        assert!(!c.text.contains('\u{7}'));
        assert!(!c.text.contains('\r'));
        assert!(c.text.contains("error: it broke"), "{}", c.text);
    }

    #[test]
    fn a_download_progress_meter_does_not_survive() {
        // 55 MB of Node came down as about a thousand lines of dots in a real sweep log, burying
        // the one line that said why the build then failed.
        let mut log = String::new();
        for i in 0..1000 {
            log.push_str(&format!(
                " {}K .......... .......... .......... .......... .......... 99%  112M 0s\n",
                i * 50
            ));
        }
        log.push_str("node: error while loading shared libraries: libatomic.so.1\n");
        let c = compress(&log, 4096);
        assert!(c.text.contains("libatomic.so.1"), "{}", c.text);
        assert!(
            !c.text.contains(".........."),
            "progress survived:\n{}",
            c.text
        );
        assert!(c.ratio() > 20.0, "ratio was only {:.1}×", c.ratio());
    }

    #[test]
    fn compression_is_deterministic_because_a_cache_key_depends_on_it() {
        let log = npmish(300);
        assert_eq!(compress(&log, 4096), compress(&log, 4096));
    }

    #[test]
    fn the_budget_is_respected_with_room_for_the_marker() {
        let c = compress(&npmish(2000), 3000);
        assert!(c.text.len() <= 3200, "{} bytes", c.text.len());
    }

    #[test]
    fn an_empty_log_does_not_panic_or_lie() {
        let c = compress("", 1024);
        assert!(c.text.is_empty());
        assert_eq!(c.kept_lines, 0);
    }

    #[test]
    fn the_classifier_still_names_the_failure_in_the_compressed_form() {
        // These two are used together on every repair: the signature keys the cache, the compressed
        // log is what the model reads. If compression dropped the line the classifier needs, the
        // model would be asked to explain a failure the cache had already named from other
        // evidence.
        let log = npmish(400);
        let before = crate::classify(&log);
        let after = crate::classify(&compress(&log, 4096).text);
        assert_eq!(before.key(), after.key());
        assert_eq!(before.key(), "env/node-too-old");
    }
}

#[cfg(test)]
mod the_error_at_the_end {
    //! The last line of a build log is where the error is, and it must survive compression.
    //!
    //! `the_classifier_still_names_the_failure_in_the_compressed_form` above asserts this already,
    //! and passed throughout — its npm fixture has a *contiguous* chosen set, so it never reaches
    //! the emit loop's budget check. These use a fragmented one, which is what a real build log
    //! with scattered warnings looks like.

    use super::compress;

    /// 4,000 lines of noise with a warning every eighth, then the line that matters.
    fn fragmented(lines: usize, gap: usize) -> String {
        let mut out = Vec::with_capacity(lines + 1);
        for i in 0..lines {
            if i % gap == 0 {
                out.push(format!(
                    "src/mod{i}.c:12:5: warning: cannot find prototype decl {i}"
                ));
            } else {
                out.push(format!(
                    "compiling translation unit number {i} of the project"
                ));
            }
        }
        out.push(
            "yarl/_quoting_c.c:6:10: fatal error: Python.h: No such file or directory".to_string(),
        );
        out.join("\n")
    }

    #[test]
    fn a_fragmented_log_still_carries_its_last_line() {
        // Both shipped budgets: 4096 in the rebuild path, 8192 in the repair path.
        for budget in [4096usize, 8192] {
            for gap in [3usize, 5, 8, 12, 20, 40] {
                let raw = fragmented(4000, gap);
                let c = compress(&raw, budget);
                assert!(
                    c.text.contains("fatal error: Python.h"),
                    "budget {budget}, gap {gap}: the error at the end was dropped. The priority \
                     sort chose it and the emit loop threw it away in file order."
                );
            }
        }
    }

    /// The consequence, which is what makes it more than cosmetic.
    #[test]
    fn the_signature_does_not_depend_on_how_much_the_build_printed() {
        let raw = fragmented(4000, 8);
        let from_raw = crate::classify(&raw);
        for budget in [4096usize, 8192] {
            let c = compress(&raw, budget);
            let from_compressed = crate::classify(&c.text);
            assert_eq!(
                from_raw.key(),
                from_compressed.key(),
                "budget {budget}: the same failure keyed two ways. That key is the repair cache \
                 key, so a noisy build and a quiet one with the same cause miss each other."
            );
        }
    }

    /// And the promise the old comment made and could not keep.
    #[test]
    fn the_output_fits_the_budget_it_was_given() {
        for budget in [512usize, 1024, 4096, 8192] {
            for gap in [3usize, 8, 40] {
                let c = compress(&fragmented(2000, gap), budget);
                assert!(
                    c.text.len() <= budget,
                    "budget {budget}, gap {gap}: emitted {} bytes. The elision markers cost budget \
                     and were not priced.",
                    c.text.len()
                );
            }
        }
    }
}
