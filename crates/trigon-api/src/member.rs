//! One member of an artifact: its bytes, and what differs between the two copies.
//!
//! The comparison says *that* `lib/net20/Newtonsoft.Json.dll` differs and *what kind* of difference
//! it is. It does not say what the difference **is**, and for a maintainer reading a finding about
//! their own package that is the only question. This module answers it: the two copies' bytes, as a
//! line diff where that means anything and as a hex diff where it does not.
//!
//! # Where the bytes come from
//!
//! Not from the comparison — it stores digests and sizes, never content. From the two stored
//! artifacts, parsed, with the member found by the same walk `trigon-compare::diff` uses to name
//! it: depth-first, nested archives flattened into `outer.gz!inner/path`. **The two walks have to
//! agree or a path from one will not resolve in the other**, which is the shape this tree keeps
//! finding, so `a_nested_member_resolves_by_the_name_the_comparison_gave_it` asserts it against a
//! real nested archive rather than trusting that both were written from the same paragraph.
//!
//! # Raw, and only raw
//!
//! These are the bytes as published and as built, **before any pass ran**. Showing the stabilized
//! forms would need `trigon-stabilize`, which this crate does not link and must not: a crate that
//! cannot reach the comparator or the stabilizers cannot produce a verdict, whatever its handlers
//! do. It is also the more useful pair — a reader wants the file, not our normalization of it — but
//! the page has to say which it is showing, because "these two files differ" and "these two files
//! differ after we rewrote both" are different claims.
//!
//! # Bounds
//!
//! Every one of these is a cap on attacker-controlled input, and each states what it left out
//! rather than stopping quietly. A member is somebody else's file and a published artifact can be
//! any size at all.

use serde::Serialize;
use std::collections::BTreeMap;
use trigon_archive::{Archive, Body, Entry, Limits};
use trigon_core::{Digest, Format};

/// The largest artifact this will parse to reach one member of it.
///
/// Parsing holds the whole archive in memory, and `Blobs::get` re-hashes the blob on the way in, so
/// the cost of a request is linear in this. Generous enough for every ecosystem this project
/// handles and small enough that a pathological artifact is a refusal rather than an outage.
pub(crate) const MAX_ARTIFACT: usize = 256 << 20;

/// The largest member this will return or diff.
const MAX_MEMBER: usize = 16 << 20;

/// How much of a member to consider for a **text** diff, per side.
const MAX_TEXT: usize = 2 << 20;

/// Lines per side beyond which the middle is reported as replaced rather than aligned.
///
/// The alignment below is O(n·m) in the *unmatched middle*, which is tiny in the case that matters:
/// two builds of one file usually differ in a version string and a timestamp. A file that differs
/// everywhere has no useful line alignment anyway — "all of it changed" is the finding.
const MAX_ALIGN: usize = 600;

/// Lines of unchanged context either side of a change.
const CONTEXT: usize = 3;

/// Lines the rendered diff will carry, across every hunk.
///
/// **`MAX_TEXT` bounds the input and bounded nothing about the output.** Measured on the worst case
/// — 2 MiB of bare newlines against 2 MiB of `x\n` — the view held **3,145,728 line structs**,
/// serialized to an **86 MB** JSON body, and took 3.5 seconds to do it. Four of those at once
/// peaked at a gigabyte. A browser handed 86 MB of JSON is a browser that appears to have lost the
/// network, which is the symptom this whole investigation started from.
///
/// Two thousand is far more than anyone reads and turns that body into about a hundred kilobytes.
/// What is dropped is counted and said, because a list that stops without saying so is a list that
/// lies about its total — the same rule the hex view's `differing_bytes` exists for.
const MAX_DIFF_LINES: usize = 2_000;

/// Total bytes of hex to return across all regions.
const MAX_HEX: usize = 8 << 10;

/// Bytes of context either side of a differing run, and the window a run is coalesced within.
const HEX_CONTEXT: usize = 32;

/// How many separate differing regions to show before saying how many were left.
const MAX_HEX_REGIONS: usize = 8;

// --------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MemberView {
    pub path: String,
    /// Present on each side. `(true, false)` is a member the published artifact has and the rebuild
    /// does not — for which there is no diff, only a file to read.
    pub in_upstream: bool,
    pub in_rebuild: bool,
    pub upstream_bytes: Option<u64>,
    pub rebuild_bytes: Option<u64>,
    /// Whether the bytes are text. **Decided from the bytes, not from the comparison's `kind`.**
    /// A `.xml` full of NULs is binary whatever it is called, and a classification is a guess about
    /// a name where this is an observation about content.
    pub binary: bool,
    /// Why it was called binary, so a reader who disagrees knows what to look at.
    pub binary_because: Option<String>,
    pub text: Option<TextDiff>,
    pub hex: Option<HexDiff>,
    /// Set when a member could not be read or was too large, with the reason.
    pub unavailable: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TextDiff {
    pub hunks: Vec<Hunk>,
    pub upstream_lines: usize,
    pub rebuild_lines: usize,
    /// Set when only part of the file was considered, with what was left out.
    pub truncated: Option<String>,
    /// Set when the changed middle was too large to align line by line, so it is reported as
    /// wholly replaced. Saying so matters: "every line changed" and "we did not look" are
    /// different claims and they render identically.
    pub unaligned: bool,
    /// Lines the diff holds, and lines it stopped short of. See [`MAX_DIFF_LINES`].
    pub lines_shown: usize,
    pub lines_omitted: usize,
}

#[derive(Debug, Serialize)]
pub struct Hunk {
    /// 1-based line numbers of the first line in this hunk, on each side.
    pub upstream_start: usize,
    pub rebuild_start: usize,
    pub lines: Vec<Line>,
}

#[derive(Debug, Serialize)]
pub struct Line {
    /// `same`, `removed`, `added`.
    pub kind: &'static str,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct HexDiff {
    pub regions: Vec<HexRegion>,
    pub upstream_bytes: u64,
    pub rebuild_bytes: u64,
    /// Offset of the first byte that differs, where both sides exist.
    pub first_difference: Option<u64>,
    /// How many separate runs of differing bytes there are in total.
    pub differing_runs: usize,
    /// How many bytes differ in total.
    ///
    /// **The number that tells a reader what they are looking at.** A DLL with 37,039 differing
    /// runs across 480 KB is not a file with a few changed bytes, and two 4 KB windows out of it
    /// look exactly like one that is. The first version of this reported `regions_omitted: 0` on
    /// precisely that file — no *region* had been skipped, because one enormous region had been
    /// silently truncated to fit instead. A cap that reports nothing is a cap that lies.
    pub differing_bytes: u64,
    /// How many bytes the regions below actually carry.
    pub shown_bytes: u64,
    /// Regions dropped entirely. Distinct from bytes trimmed off the ones that were kept.
    pub regions_omitted: usize,
}

/// One window of bytes, aligned to 16 so the rows line up with a conventional dump.
#[derive(Debug, Serialize)]
pub struct HexRegion {
    pub offset: u64,
    /// Lowercase hex, two characters a byte. Absent where that side ends before this offset.
    pub upstream: String,
    pub rebuild: String,
}

// --------------------------------------------------------------------------

/// What this process will let one request expand an artifact into.
///
/// `Limits::default()` allows 4 GiB, which is the right budget for a *rebuild*: one at a time, on a
/// machine sized for it, doing the work the tool exists to do. It is the wrong budget for an HTTP
/// handler. `MAX_ARTIFACT` bounds the stored blob at 256 MiB, and a 19.5 MB tarball of compressible
/// content reaches the 4 GiB ceiling without going anywhere near it — measured at 4.1 GB resident
/// for a single member read, times the four concurrent reads `member_reads` permits.
///
/// A gigabyte still serves every artifact this has been pointed at, large ML wheels included, and
/// bounds the process at four of them.
fn serving_limits() -> Limits {
    Limits {
        total_expanded_bytes: MAX_EXPANDED,
        ..Limits::default()
    }
}

/// How large an artifact may expand to while serving one member of it. See [`serving_limits`].
const MAX_EXPANDED: u64 = 1 << 30;

/// The refusal for an artifact that is within [`MAX_ARTIFACT`] compressed and past
/// [`MAX_EXPANDED`] once opened.
///
/// A limit is not a parse failure, and saying "the artifact would not parse" about a perfectly good
/// tarball sends the reader to look at the package. Same rule as everywhere else here: name the
/// reason that actually applied.
fn parse_refusal(e: &trigon_archive::ArchiveError) -> String {
    match e {
        trigon_archive::ArchiveError::LimitExceeded {
            actual, allowed, ..
        } => format!(
            "that artifact expands to {} and this will not expand more than {} to serve one member \
             of it. The whole artifact is still downloadable.",
            human(*actual),
            human(*allowed)
        ),
        _ => format!("the artifact would not parse: {e}"),
    }
}

/// Read one member's bytes out of a stored artifact.
///
/// `None` where the artifact will not parse, the member is not in it, or either is over a cap. The
/// caller turns that into a refusal that says which.
pub fn read(bytes: Vec<u8>, name: &str, path: &str) -> Result<Vec<u8>, String> {
    if bytes.len() > MAX_ARTIFACT {
        return Err(format!(
            "that artifact is {} and this will not parse anything over {} to reach one member of \
             it. The whole artifact is still downloadable.",
            human(bytes.len() as u64),
            human(MAX_ARTIFACT as u64)
        ));
    }
    let format = Format::from_file_name(name)
        .ok_or_else(|| format!("`{name}` names no format this build can parse"))?;
    let mut notes = Vec::new();
    let parsed = trigon_archive::parse(bytes, format, &serving_limits(), &mut notes)
        .map_err(|e| parse_refusal(&e))?;

    let want = path.as_bytes();
    let mut found: Option<Vec<u8>> = None;
    let mut error: Option<String> = None;
    walk(&parsed.archive, &mut |e, prefix| {
        if found.is_some() || error.is_some() {
            // Duplicate member paths are legal in both tar and zip. The first is taken, matching
            // the comparison's own index, which numbers occurrences in the order it walks them.
            return;
        }
        let mut full = prefix.to_vec();
        full.extend_from_slice(e.path.as_bytes());
        if full != want {
            return;
        }
        match e.body.bytes() {
            Ok(b) if b.len() > MAX_MEMBER => {
                error = Some(format!(
                    "that member is {} and this will not return anything over {}.",
                    human(b.len() as u64),
                    human(MAX_MEMBER as u64)
                ));
            }
            Ok(b) => found = Some(b.into_owned()),
            Err(e) => error = Some(format!("that member's body could not be read: {e}")),
        }
    });

    if let Some(e) = error {
        return Err(e);
    }
    found.ok_or_else(|| "that artifact holds no member by that name".to_string())
}

/// Depth-first over members, flattening nested archives into `outer.gz!inner/path`.
///
/// **The same walk `trigon-compare::diff::walk` does**, deliberately and separately, because this
/// crate does not link the comparator. Two implementations of one traversal is the defect this tree
/// keeps finding; the assertion that closes it is in `tests/seam_member_bytes.rs`, against a real
/// nested archive rather than against a reading of the other function.
fn walk(a: &Archive, f: &mut impl FnMut(&Entry, &[u8])) {
    fn go(a: &Archive, prefix: &[u8], f: &mut impl FnMut(&Entry, &[u8])) {
        for e in &a.entries {
            match &e.body {
                Body::Nested { inner, .. } => {
                    let mut p = prefix.to_vec();
                    p.extend_from_slice(e.path.as_bytes());
                    p.push(b'!');
                    go(inner, &p, f);
                }
                _ => f(e, prefix),
            }
        }
    }
    go(a, &[], f);
}

/// Every member's name, for a listing that does not need their bytes.
pub fn names(bytes: Vec<u8>, name: &str) -> Result<BTreeMap<String, u64>, String> {
    // Same ceiling as `read`. This has no caller outside tests today, and a cap that is missing
    // because nothing currently calls the function is a cap that is missing on the day something
    // does.
    if bytes.len() > MAX_ARTIFACT {
        return Err(format!(
            "that artifact is {} and this will not parse anything over {} to list it.",
            human(bytes.len() as u64),
            human(MAX_ARTIFACT as u64)
        ));
    }
    let format = Format::from_file_name(name)
        .ok_or_else(|| format!("`{name}` names no format this build can parse"))?;
    let mut notes = Vec::new();
    let parsed = trigon_archive::parse(bytes, format, &serving_limits(), &mut notes)
        .map_err(|e| parse_refusal(&e))?;
    let mut out = BTreeMap::new();
    walk(&parsed.archive, &mut |e, prefix| {
        let mut full = prefix.to_vec();
        full.extend_from_slice(e.path.as_bytes());
        out.insert(String::from_utf8_lossy(&full).into_owned(), e.body.len());
    });
    Ok(out)
}

// --------------------------------------------------------------------------

/// Is this text? Decided from the bytes.
///
/// A NUL is the classic signal and the reason `grep` uses it: no text encoding this would be
/// rendered in puts one in the middle of a document. Invalid UTF-8 is the other. Both are
/// observations about content, unlike the comparison's `kind`, which is a guess from a filename —
/// and the question here is whether a *hex* view is the right default, which only the bytes decide.
fn binary_because(b: &[u8]) -> Option<String> {
    // Only the head is examined: a 16 MB file that is text for 15 MB and then has a NUL is still
    // going to render as text, and reading all of it to find out costs more than it settles.
    let head = &b[..b.len().min(8 << 10)];
    if let Some(i) = head.iter().position(|&c| c == 0) {
        return Some(format!("a zero byte at offset {i}"));
    }
    if std::str::from_utf8(head).is_err() {
        // A truncated multi-byte sequence at the window's edge is not evidence of anything, so the
        // last three bytes are excused before concluding.
        let trimmed = &head[..head.len().saturating_sub(3)];
        if std::str::from_utf8(trimmed).is_err() {
            return Some("bytes that are not valid UTF-8".into());
        }
    }
    None
}

/// Build the view for one member.
///
/// `at` asks for a specific window of the hex view rather than the difference-centred regions.
/// That is what makes a file which differs throughout explorable: on a 513 KB DLL with 469 KB of
/// differing bytes, the default view is two windows and honest about it, and paging is how a reader
/// gets to the rest without downloading both copies.
pub fn view(
    path: &str,
    upstream: Option<Vec<u8>>,
    rebuild: Option<Vec<u8>>,
    at: Option<u64>,
) -> MemberView {
    let binary_reason = upstream
        .as_deref()
        .and_then(binary_because)
        .or_else(|| rebuild.as_deref().and_then(binary_because));
    let binary = binary_reason.is_some();

    MemberView {
        path: path.to_string(),
        in_upstream: upstream.is_some(),
        in_rebuild: rebuild.is_some(),
        upstream_bytes: upstream.as_ref().map(|b| b.len() as u64),
        rebuild_bytes: rebuild.as_ref().map(|b| b.len() as u64),
        binary,
        binary_because: binary_reason,
        // Both views are built, whatever the default is. A reader who disagrees with the guess
        // should not have to make another request to say so, and the cost is bounded by the caps
        // above rather than by the file.
        text: (!binary).then(|| text_diff(upstream.as_deref(), rebuild.as_deref())),
        hex: Some(match at {
            Some(off) => hex_window(upstream.as_deref(), rebuild.as_deref(), off),
            None => hex_diff(upstream.as_deref(), rebuild.as_deref()),
        }),
        unavailable: None,
    }
}

// --------------------------------------------------------------------------
// Text
// --------------------------------------------------------------------------

fn text_diff(up: Option<&[u8]>, rb: Option<&[u8]>) -> TextDiff {
    let (a, a_cut) = lines_of(up);
    let (b, b_cut) = lines_of(rb);
    let truncated = match (a_cut, b_cut) {
        (false, false) => None,
        _ => Some(format!(
            "only the first {} of each side was read.",
            human(MAX_TEXT as u64)
        )),
    };

    // A file present on one side only is not a diff; it is a file. Every line is an addition or a
    // removal, which is both true and the only honest rendering — up to the line budget.
    if up.is_none() || rb.is_none() {
        let kind = if up.is_none() { "added" } else { "removed" };
        let src = if up.is_none() { &b } else { &a };
        let shown = src.len().min(MAX_DIFF_LINES);
        return TextDiff {
            upstream_lines: a.len(),
            rebuild_lines: b.len(),
            hunks: vec![Hunk {
                upstream_start: 1,
                rebuild_start: 1,
                lines: src[..shown]
                    .iter()
                    .map(|l| Line {
                        kind,
                        text: l.clone(),
                    })
                    .collect(),
            }],
            truncated,
            unaligned: false,
            lines_shown: shown,
            lines_omitted: src.len() - shown,
        };
    }

    // The common case is a handful of lines in the middle. Trimming the shared head and tail first
    // is what keeps the alignment below cheap enough to be exact where it matters.
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);

    if am.is_empty() && bm.is_empty() {
        return TextDiff {
            hunks: Vec::new(),
            upstream_lines: a.len(),
            rebuild_lines: b.len(),
            truncated,
            unaligned: false,
            lines_shown: 0,
            lines_omitted: 0,
        };
    }

    let unaligned = am.len() > MAX_ALIGN || bm.len() > MAX_ALIGN;
    let ops = if unaligned {
        // Whole middle replaced. Honest, and flagged, because it renders identically to a file in
        // which every line really did change.
        let mut v: Vec<Op> = am.iter().map(|_| Op::Remove).collect();
        v.extend(bm.iter().map(|_| Op::Add));
        v
    } else {
        align(am, bm)
    };

    let (hunks, omitted) = hunks(&a, &b, head, tail, &ops);
    TextDiff {
        lines_shown: hunks.iter().map(|h| h.lines.len()).sum(),
        lines_omitted: omitted,
        hunks,
        upstream_lines: a.len(),
        rebuild_lines: b.len(),
        truncated,
        unaligned,
    }
}

fn lines_of(b: Option<&[u8]>) -> (Vec<String>, bool) {
    let Some(b) = b else {
        return (Vec::new(), false);
    };
    let cut = b.len() > MAX_TEXT;
    let slice = &b[..b.len().min(MAX_TEXT)];
    let text = String::from_utf8_lossy(slice);
    // `split` rather than `lines`, so a file's trailing newline is visible as an empty final line
    // rather than silently absent — "the rebuild lost the trailing newline" is a real finding and
    // `lines()` cannot express it.
    let mut v: Vec<String> = text
        .split('\n')
        .map(|s| s.trim_end_matches('\r').to_string())
        .collect();
    if v.last().is_some_and(String::is_empty) {
        v.pop();
    }
    (v, cut)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Same,
    Remove,
    Add,
}

/// Longest common subsequence over the unmatched middle.
///
/// O(n·m), which is why the middle is trimmed and bounded first. Row-at-a-time so the table is
/// O(min) memory rather than O(n·m) — at the 600-line cap that is 600 cells instead of 360,000.
fn align(a: &[String], b: &[String]) -> Vec<Op> {
    let (n, m) = (a.len(), b.len());
    // Full table, because the traceback needs it. Bounded by MAX_ALIGN² cells of u32.
    let mut lcs = vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[at(i, j)] = if a[i] == b[j] {
                lcs[at(i + 1, j + 1)] + 1
            } else {
                lcs[at(i + 1, j)].max(lcs[at(i, j + 1)])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::with_capacity(n + m);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(Op::Same);
            i += 1;
            j += 1;
        } else if lcs[at(i + 1, j)] >= lcs[at(i, j + 1)] {
            ops.push(Op::Remove);
            i += 1;
        } else {
            ops.push(Op::Add);
            j += 1;
        }
    }
    ops.extend(std::iter::repeat_n(Op::Remove, n - i));
    ops.extend(std::iter::repeat_n(Op::Add, m - j));
    ops
}

/// Turn the op list back into hunks with context, against the untrimmed files.
///
/// Stops at [`MAX_DIFF_LINES`] and returns how many lines it did not reach. The budget is spent on
/// the first changes rather than sampled across the file, because a reader who opens a diff starts
/// at the top — and because the alternative is a rendering whose gaps nobody can locate.
fn hunks(
    a: &[String],
    b: &[String],
    head: usize,
    tail: usize,
    ops: &[Op],
) -> (Vec<Hunk>, usize) {
    // Replay the whole file as ops, so line numbers below are the real ones.
    let mut all: Vec<Op> = vec![Op::Same; head];
    all.extend_from_slice(ops);
    all.extend(std::iter::repeat_n(Op::Same, tail));

    let mut out = Vec::new();
    let mut cur: Option<Hunk> = None;
    let (mut ai, mut bi) = (0usize, 0usize);
    let mut quiet = 0usize;
    let mut spent = 0usize;
    // Every changed line the budget did not reach. Counted from the ops rather than from what was
    // emitted, so the number is what a reader is missing rather than what the loop skipped.
    let mut omitted = 0usize;

    for (k, op) in all.iter().enumerate() {
        if spent >= MAX_DIFF_LINES {
            if *op != Op::Same {
                omitted += 1;
            }
            continue;
        }
        let changed = *op != Op::Same;
        if changed {
            if cur.is_none() {
                // Open a hunk CONTEXT lines back, which means walking the preceding same-lines.
                let back = all[..k]
                    .iter()
                    .rev()
                    .take(CONTEXT)
                    .take_while(|o| **o == Op::Same)
                    .count();
                let mut h = Hunk {
                    upstream_start: ai + 1 - back,
                    rebuild_start: bi + 1 - back,
                    lines: Vec::new(),
                };
                for n in (1..=back).rev() {
                    h.lines.push(Line {
                        kind: "same",
                        text: a[ai - n].clone(),
                    });
                }
                cur = Some(h);
            }
            quiet = 0;
        } else if cur.is_some() {
            quiet += 1;
            if quiet > CONTEXT {
                out.push(cur.take().expect("checked"));
                quiet = 0;
            }
        }

        if let Some(h) = cur.as_mut() {
            spent += 1;
            match op {
                Op::Same => h.lines.push(Line {
                    kind: "same",
                    text: a.get(ai).cloned().unwrap_or_default(),
                }),
                Op::Remove => h.lines.push(Line {
                    kind: "removed",
                    text: a.get(ai).cloned().unwrap_or_default(),
                }),
                Op::Add => h.lines.push(Line {
                    kind: "added",
                    text: b.get(bi).cloned().unwrap_or_default(),
                }),
            }
        }
        match op {
            Op::Same => {
                ai += 1;
                bi += 1;
            }
            Op::Remove => ai += 1,
            Op::Add => bi += 1,
        }
    }
    if let Some(h) = cur {
        out.push(h);
    }
    (out, omitted)
}

// --------------------------------------------------------------------------
// Hex
// --------------------------------------------------------------------------

/// A hex view centred on the differences.
///
/// **Not the first 8 KB of the file.** A DLL that differs at offset 0x4A120 has an identical header,
/// so a dump from zero shows a reader two screens of bytes that agree and nothing that does not.
/// The differing runs are found first, coalesced, and each shown with context.
fn hex_diff(up: Option<&[u8]>, rb: Option<&[u8]>) -> HexDiff {
    let a = up.unwrap_or(&[]);
    let b = rb.unwrap_or(&[]);

    // One side only: there is nothing to compare, so show the file from the start.
    if up.is_none() || rb.is_none() {
        let src = if up.is_none() { b } else { a };
        let end = src.len().min(MAX_HEX);
        return HexDiff {
            regions: if src.is_empty() {
                Vec::new()
            } else {
                vec![HexRegion {
                    offset: 0,
                    upstream: if up.is_none() {
                        String::new()
                    } else {
                        hex(&src[..end])
                    },
                    rebuild: if up.is_none() {
                        hex(&src[..end])
                    } else {
                        String::new()
                    },
                }]
            },
            upstream_bytes: a.len() as u64,
            rebuild_bytes: b.len() as u64,
            first_difference: None,
            differing_runs: 0,
            // Every byte of a one-sided member is a difference: the other side has none of them.
            differing_bytes: src.len() as u64,
            shown_bytes: end as u64,
            regions_omitted: 0,
        };
    }

    // Differing byte offsets, coalesced into runs. A length difference counts from the shorter
    // file's end: the tail one side has and the other does not is a difference.
    let common = a.len().min(b.len());
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < common {
        if a[i] != b[i] {
            let start = i;
            while i < common && a[i] != b[i] {
                i += 1;
            }
            runs.push((start, i));
        } else {
            i += 1;
        }
    }
    if a.len() != b.len() {
        runs.push((common, a.len().max(b.len())));
    }
    let first_difference = runs.first().map(|(s, _)| *s as u64);
    let differing_runs = runs.len();
    let differing_bytes: u64 = runs.iter().map(|(s, e)| (e - s) as u64).sum();

    // Coalesce runs whose context windows would overlap, so two changes four bytes apart are one
    // region rather than two that repeat each other's bytes.
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in runs {
        match merged.last_mut() {
            Some((_, pe)) if s.saturating_sub(HEX_CONTEXT) <= *pe + HEX_CONTEXT => *pe = e,
            _ => merged.push((s, e)),
        }
    }

    // **No region may take the whole budget.** A file that differs from offset 200 to its end
    // coalesces into one enormous region, and giving it everything shows a reader one window and
    // calls it the diff. Capping each region's share means several windows spread across the file,
    // which is what "it differs in four places" should look like.
    let per_region = (MAX_HEX / MAX_HEX_REGIONS).max(64);
    let mut regions = Vec::new();
    let mut spent = 0usize;
    let mut omitted = 0usize;
    for (s, e) in &merged {
        if regions.len() >= MAX_HEX_REGIONS || spent >= MAX_HEX {
            omitted += 1;
            continue;
        }
        // Aligned to 16 so the rows line up with a conventional dump and the offsets are round.
        let start = s.saturating_sub(HEX_CONTEXT) & !0xF;
        let want = (e + HEX_CONTEXT).next_multiple_of(16);
        let budget = per_region.min(MAX_HEX - spent);
        let end = want.min(start + budget);
        spent += end.saturating_sub(start);
        regions.push(HexRegion {
            offset: start as u64,
            upstream: hex(&a[start.min(a.len())..end.min(a.len())]),
            rebuild: hex(&b[start.min(b.len())..end.min(b.len())]),
        });
    }

    HexDiff {
        regions,
        upstream_bytes: a.len() as u64,
        rebuild_bytes: b.len() as u64,
        first_difference,
        differing_runs,
        differing_bytes,
        shown_bytes: spent as u64,
        regions_omitted: omitted,
    }
}

/// One window at a caller-chosen offset, for paging through a file that differs everywhere.
///
/// The counts are the same as [`hex_diff`]'s — they describe the whole file, not the window — so a
/// reader who has paged to offset 300,000 still sees how much of the file differs rather than
/// losing the denominator the moment they move.
fn hex_window(up: Option<&[u8]>, rb: Option<&[u8]>, offset: u64) -> HexDiff {
    let mut d = hex_diff(up, rb);
    let a = up.unwrap_or(&[]);
    let b = rb.unwrap_or(&[]);
    let longest = a.len().max(b.len());

    // Aligned down to a dump row, and clamped inside the file: a caller paging past the end gets
    // the last window rather than an empty one, which reads as "there is nothing here".
    let start = ((offset as usize) & !0xF).min(longest.saturating_sub(1) & !0xF);
    let end = (start + MAX_HEX).min(longest);

    d.regions = if longest == 0 {
        Vec::new()
    } else {
        vec![HexRegion {
            offset: start as u64,
            upstream: hex(&a[start.min(a.len())..end.min(a.len())]),
            rebuild: hex(&b[start.min(b.len())..end.min(b.len())]),
        }]
    };
    d.shown_bytes = end.saturating_sub(start) as u64;
    // Nothing was *dropped*; a window was asked for. Reporting omissions here would be reporting
    // the rest of the file as missing, which it is not — it is one page away.
    d.regions_omitted = 0;
    d
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        use std::fmt::Write as _;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn human(b: u64) -> String {
    match b {
        0..=1023 => format!("{b} B"),
        1024..=1_048_575 => format!("{:.1} KB", b as f64 / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.1} MB", b as f64 / 1_048_576.0),
        _ => format!("{:.2} GB", b as f64 / 1_073_741_824.0),
    }
}

/// The digest of a side's artifact, for the caller.
pub fn side_digest(r: &trigon_store::RunRecord, side: &str) -> Option<(Digest, String)> {
    match side {
        "upstream" => Some((r.upstream.sha256, r.upstream.name.clone())),
        "rebuild" => r.rebuild.as_ref().map(|a| (a.sha256, a.name.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<String> {
        s.split('\n').map(str::to_string).collect()
    }

    #[test]
    fn one_changed_line_is_one_hunk_with_context() {
        let a = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj";
        let b = "a\nb\nc\nd\nE\nf\ng\nh\ni\nj";
        let d = text_diff(Some(a.as_bytes()), Some(b.as_bytes()));
        assert_eq!(d.hunks.len(), 1);
        assert!(!d.unaligned);
        let h = &d.hunks[0];
        // Three lines of context, the removal, the addition, three more lines.
        assert_eq!(
            h.upstream_start, 2,
            "the hunk did not open three lines back"
        );
        assert_eq!(h.lines.iter().filter(|l| l.kind == "removed").count(), 1);
        assert_eq!(h.lines.iter().filter(|l| l.kind == "added").count(), 1);
        assert!(h.lines.iter().any(|l| l.kind == "removed" && l.text == "e"));
        assert!(h.lines.iter().any(|l| l.kind == "added" && l.text == "E"));
    }

    #[test]
    fn identical_files_produce_no_hunks() {
        let s = "one\ntwo\nthree";
        let d = text_diff(Some(s.as_bytes()), Some(s.as_bytes()));
        assert!(d.hunks.is_empty());
        assert_eq!(d.upstream_lines, 3);
    }

    #[test]
    fn a_lost_trailing_newline_is_visible() {
        // `lines()` cannot express this and it is a real finding: a rebuild that drops a file's
        // final newline differs from the published bytes and looks identical in most viewers.
        let (with, _) = lines_of(Some(b"a\nb\n"));
        let (without, _) = lines_of(Some(b"a\nb"));
        assert_eq!(with, vec!["a", "b"]);
        assert_eq!(without, vec!["a", "b"]);
        // The line lists match, so the diff is empty — and the *bytes* differ, which is why the hex
        // view exists and why a text diff is never the whole answer.
        let d = hex_diff(Some(b"a\nb\n"), Some(b"a\nb"));
        assert_eq!(d.first_difference, Some(3));
        assert_eq!(d.differing_runs, 1);
    }

    #[test]
    fn a_file_on_one_side_only_is_all_additions() {
        let d = text_diff(None, Some(b"x\ny"));
        assert_eq!(d.hunks.len(), 1);
        assert!(d.hunks[0].lines.iter().all(|l| l.kind == "added"));
        assert_eq!(d.upstream_lines, 0);
        assert_eq!(d.rebuild_lines, 2);
    }

    #[test]
    fn a_middle_too_large_to_align_says_so() {
        let a: String = (0..MAX_ALIGN + 50).map(|i| format!("a{i}\n")).collect();
        let b: String = (0..MAX_ALIGN + 50).map(|i| format!("b{i}\n")).collect();
        let d = text_diff(Some(a.as_bytes()), Some(b.as_bytes()));
        assert!(
            d.unaligned,
            "a middle past the cap was aligned anyway, or the flag was not set"
        );
        // Still reports every line, as a wholesale replacement.
        assert!(
            d.hunks
                .iter()
                .flat_map(|h| &h.lines)
                .any(|l| l.kind == "removed")
        );
        assert!(
            d.hunks
                .iter()
                .flat_map(|h| &h.lines)
                .any(|l| l.kind == "added")
        );
    }

    #[test]
    fn the_hex_view_centres_on_the_difference() {
        // A header that agrees for 4 KB, then one differing byte. A dump from zero would show a
        // reader two screens of identical bytes and none of the finding.
        let mut a = vec![0x41u8; 5000];
        let mut b = a.clone();
        b[4096] = 0x42;
        a[4096] = 0x41;
        let d = hex_diff(Some(&a), Some(&b));
        assert_eq!(d.first_difference, Some(4096));
        assert_eq!(d.regions.len(), 1);
        let r = &d.regions[0];
        assert!(
            r.offset <= 4096 && r.offset + (r.upstream.len() / 2) as u64 > 4096,
            "the region does not contain the difference: offset {} len {}",
            r.offset,
            r.upstream.len() / 2
        );
        assert_eq!(r.offset % 16, 0, "the region is not aligned to a dump row");
    }

    #[test]
    fn nearby_differences_are_one_region() {
        let a = vec![0u8; 512];
        let mut b = a.clone();
        b[100] = 1;
        b[104] = 1;
        let d = hex_diff(Some(&a), Some(&b));
        assert_eq!(d.differing_runs, 2, "two runs four bytes apart");
        assert_eq!(d.regions.len(), 1, "and one region covering both");
    }

    #[test]
    fn a_file_that_differs_throughout_says_how_much_rather_than_showing_a_window() {
        // The DLL case. 480 KB differing coalesces into one region; giving it the whole budget
        // shows one window and reports nothing omitted, which reads as "these are the differences".
        let a = vec![0x41u8; 200_000];
        let mut b = a.clone();
        for (i, x) in b.iter_mut().enumerate().skip(200) {
            *x = (i % 251) as u8;
        }
        let d = hex_diff(Some(&a), Some(&b));
        assert!(d.differing_bytes > 100_000, "{}", d.differing_bytes);
        assert!(
            d.shown_bytes < d.differing_bytes,
            "the whole difference fitted, so this test proves nothing"
        );
        assert!(
            d.shown_bytes as usize <= MAX_HEX,
            "the budget was exceeded: {}",
            d.shown_bytes
        );
        // And the numbers say so, which is the point: a reader can tell one window from the truth.
        assert!(d.first_difference.is_some());
    }

    #[test]
    fn no_single_region_eats_the_whole_budget() {
        // Four widely separated differences. Each should get a window rather than the first one
        // taking everything.
        let a = vec![0u8; 100_000];
        let mut b = a.clone();
        for off in [1_000usize, 20_000, 50_000, 90_000] {
            for x in b.iter_mut().skip(off).take(4_000) {
                *x = 1;
            }
        }
        let d = hex_diff(Some(&a), Some(&b));
        assert_eq!(d.differing_runs, 4);
        assert_eq!(d.regions.len(), 4, "a region took more than its share");
        let offsets: Vec<u64> = d.regions.iter().map(|r| r.offset).collect();
        assert!(
            offsets[3] > 80_000,
            "the last difference was never reached: {offsets:?}"
        );
    }

    #[test]
    fn a_length_difference_is_a_difference() {
        let d = hex_diff(Some(b"abc"), Some(b"abcdef"));
        assert_eq!(d.first_difference, Some(3));
        assert_eq!(d.upstream_bytes, 3);
        assert_eq!(d.rebuild_bytes, 6);
        assert_eq!(d.regions.len(), 1);
    }

    #[test]
    fn binary_is_decided_from_the_bytes() {
        assert!(binary_because(b"plain text\nwith lines\n").is_none());
        assert!(binary_because(b"MZ\x90\x00\x03\0\0\0").is_some_and(|s| s.contains("zero byte")));
        assert!(
            binary_because(&[0xff, 0xfe, 0xfd, b'a', b'b', b'c', b'd'])
                .is_some_and(|s| s.contains("UTF-8"))
        );
        // A multi-byte character straddling the examined window is not evidence of anything.
        let mut s = "é".repeat(4100).into_bytes();
        s.truncate(8 << 10);
        assert!(
            binary_because(&s).is_none(),
            "a truncated character at the window edge was read as binary"
        );
    }

    #[test]
    fn a_window_keeps_the_whole_file_s_counts() {
        // Paging must not cost a reader the denominator. The window says where they are; the
        // counts say what they are in the middle of.
        let a = vec![0u8; 100_000];
        let mut b = a.clone();
        for x in b.iter_mut().skip(50_000) {
            *x = 9;
        }
        let whole = hex_diff(Some(&a), Some(&b));
        let win = hex_window(Some(&a), Some(&b), 70_000);
        assert_eq!(win.differing_bytes, whole.differing_bytes);
        assert_eq!(win.differing_runs, whole.differing_runs);
        assert_eq!(win.first_difference, Some(50_000));
        assert_eq!(win.regions.len(), 1);
        assert_eq!(win.regions[0].offset, 70_000 & !0xF);
    }

    #[test]
    fn paging_past_the_end_lands_on_the_last_window() {
        let a = vec![1u8; 1000];
        let b = vec![2u8; 1000];
        let win = hex_window(Some(&a), Some(&b), 9_000_000);
        assert_eq!(
            win.regions.len(),
            1,
            "a window past the end rendered as empty"
        );
        assert!(win.regions[0].offset < 1000);
    }

    #[test]
    fn a_binary_member_gets_hex_and_no_text() {
        let v = view(
            "x.dll",
            Some(b"MZ\0\0ab".to_vec()),
            Some(b"MZ\0\0cd".to_vec()),
            None,
        );
        assert!(v.binary);
        assert!(v.text.is_none(), "a binary member built a line diff");
        assert!(v.hex.is_some());
        assert!(v.binary_because.is_some());
    }

    #[test]
    fn a_text_member_gets_both() {
        let v = view(
            "a.txt",
            Some(b"one\ntwo".to_vec()),
            Some(b"one\nTWO".to_vec()),
            None,
        );
        assert!(!v.binary);
        // Both, so a reader who wants the bytes does not have to make a second request.
        assert!(v.text.is_some());
        assert!(v.hex.is_some());
    }

    #[test]
    fn alignment_finds_an_insertion_rather_than_rewriting_the_tail() {
        let a = lines("one\ntwo\nthree");
        let b = lines("one\ninserted\ntwo\nthree");
        let ops = align(&a, &b);
        assert_eq!(
            ops.iter().filter(|o| **o == Op::Add).count(),
            1,
            "an insertion was reported as a rewrite: {ops:?}"
        );
        assert_eq!(ops.iter().filter(|o| **o == Op::Remove).count(), 0);
    }
}
