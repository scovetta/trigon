//! How the gap closed, pass by pass.
//!
//! A verdict is taken after the whole stabilizer set has run, which is the right place to take it
//! and the wrong place to *understand* it. A reader looking at a normalized verdict wants to know
//! which pass closed which difference; a reader looking at a divergence wants to know how far the
//! set got before it stopped. So the set is re-applied here one pass at a time, in the order the
//! set runs them, and the differences left after each pass are counted.
//!
//! **Explanation, never verdict.** Nothing reads this to decide an outcome. The last step is
//! checked against the signature of the comparison that did decide, and a disagreement is recorded
//! as `consistent: false` rather than smoothed over — one pass at a time and the whole set at once
//! are the same for a flat archive, and a nested one is exactly where they could part.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use trigon_archive::{Limits, parse};
use trigon_core::Format;
use trigon_stabilize::{StabilizerSet, apply};

use crate::{CompareError, signature};

/// Both artifacts together, above which the set is not re-applied pass by pass.
///
/// A step costs one full walk of both archives, so the whole progression costs one walk per pass
/// in the set. That is nothing for a package and minutes for a multi-gigabyte wheel, and the
/// comparison it rides along with is on the sweep's hot path.
pub const MAX_BYTES: usize = 128 << 20;

/// How many member names one step lists. The count is always whole; the list is a sample to read.
const LISTED: usize = 25;

/// The differences left after each pass, from the artifacts as published to the last pass.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progression {
    /// Step 0 is the two artifacts as published; step `k` follows the set's `k`th pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
    /// Whether the last step reproduces, code for code, the difference signature of the comparison
    /// that decided the verdict. False means this explanation is not trustworthy for this run.
    pub consistent: bool,
    /// Why there are no steps, where there are none. Distinct from a progression that was never
    /// computed at all, which is an absent field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted: Option<String>,
}

/// One point on the way from published to stabilized.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The pass applied to reach this step. Absent for the artifacts as published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
    /// Every difference left, counted as `rule@path` codes: members and the archive as a whole.
    pub differences: u32,
    /// Members with at least one difference left. A nested archive whose own framing or order
    /// differs is one: `container:gzip.os@data.tar.gz` is a difference in `data.tar.gz`.
    pub members: u32,
    /// Members whose own bytes still differ.
    pub bodies: u32,
    /// Members that had a difference before this step and none after it, up to a bound.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closed: Vec<String>,
    pub closed_total: u32,
    /// Members that had no difference before this step and have one after it, up to a bound. A
    /// pass is not supposed to do this; it is recorded because a pass that does is a finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub opened: Vec<String>,
    pub opened_total: u32,
}

impl Progression {
    /// The two artifacts were identical as published: one step, nothing to close.
    pub fn nothing_to_close() -> Self {
        Progression {
            steps: vec![Step::default()],
            consistent: true,
            omitted: None,
        }
    }

    pub fn omitted(why: impl Into<String>) -> Self {
        Progression {
            steps: Vec::new(),
            consistent: false,
            omitted: Some(why.into()),
        }
    }
}

/// Re-apply `set` one pass at a time to both artifacts and count what is left after each.
///
/// `full` is the difference signature of the stabilized archives the verdict was taken on; the
/// last step is checked against it. A failure here never fails the comparison: it becomes an
/// `omitted` progression that says why.
pub fn compute(
    upstream: Vec<u8>,
    rebuild: Vec<u8>,
    format: Format,
    set: &StabilizerSet,
    limits: &Limits,
    full: &BTreeSet<String>,
) -> Progression {
    match walk(upstream, rebuild, format, set, limits, full) {
        Ok(p) => p,
        Err(e) => {
            Progression::omitted(format!("the set could not be re-applied pass by pass: {e}"))
        }
    }
}

fn walk(
    upstream: Vec<u8>,
    rebuild: Vec<u8>,
    format: Format,
    set: &StabilizerSet,
    limits: &Limits,
    full: &BTreeSet<String>,
) -> Result<Progression, CompareError> {
    let mut notes = Vec::new();
    let mut u = parse(upstream, format, limits, &mut notes)?.archive;
    let mut r = parse(rebuild, format, limits, &mut notes)?.archive;

    let mut codes = signature(&u, &r);
    let mut before = Tally::of(&codes, format);
    let mut steps = vec![before.step(None, None)];

    // The set's own order — `StabilizerSet::new` sorts by stage then id — so step `k` is exactly
    // "the first `k` passes", which is what the whole-set comparison ran.
    for pass in &set.members {
        let one = StabilizerSet::new(set.id.as_str().to_string(), vec![pass.clone()]);
        apply(&one, &mut u);
        apply(&one, &mut r);
        codes = signature(&u, &r);
        let after = Tally::of(&codes, format);
        steps.push(after.step(Some(pass.id().to_string()), Some(&before)));
        before = after;
    }

    Ok(Progression {
        steps,
        consistent: &codes == full,
        omitted: None,
    })
}

/// The differences one step leaves, as a reader should count them.
struct Tally {
    differences: u32,
    members: BTreeSet<String>,
    bodies: u32,
}

impl Tally {
    fn of(codes: &BTreeSet<String>, format: Format) -> Self {
        let mut differences = 0;
        let mut members = BTreeSet::new();
        let mut bodies = BTreeSet::new();
        for code in codes {
            if !counted(code, codes, format) {
                continue;
            }
            differences += 1;
            // `rule@path`, split at the first `@`: a rule id never contains one, a path may.
            let Some((rule, path)) = code.split_once('@') else {
                continue;
            };
            // An archive-level code carries a path only inside a nested archive, and the path is
            // the member that holds it: when `gzip-meta` clears a gem's inner gzip header, what it
            // closed is `data.tar.gz`. A member but not a body, because what differs is how its
            // contents are framed or ordered.
            let member_level = rule == "body"
                || rule == "body-unreadable"
                || rule.starts_with("entry:")
                || rule.starts_with("member-only-in-")
                || rule.starts_with("container:")
                || rule == "entry-order";
            if member_level {
                members.insert(path.to_string());
                if rule.starts_with("body") {
                    bodies.insert(path.to_string());
                }
            }
        }
        Tally {
            differences,
            members,
            bodies: bodies.len() as u32,
        }
    }

    fn step(&self, pass: Option<String>, before: Option<&Tally>) -> Step {
        let (closed, opened): (Vec<&String>, Vec<&String>) = match before {
            Some(b) => (
                b.members.difference(&self.members).collect(),
                self.members.difference(&b.members).collect(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        Step {
            pass,
            differences: self.differences,
            members: self.members.len() as u32,
            bodies: self.bodies,
            closed_total: closed.len() as u32,
            closed: closed.into_iter().take(LISTED).cloned().collect(),
            opened_total: opened.len() as u32,
            opened: opened.into_iter().take(LISTED).cloned().collect(),
        }
    }
}

/// Whether a code is a difference a reader should see counted.
///
/// `signature` compares the stabilized archive *in memory*, where three fields are stale shadows of
/// what serialization will write (B47): an entry's size and crc32 are recomputed from the body on
/// every write, and a zip member's `mode` is a parse-time shadow of `external_attrs`, which is what
/// the writer emits. Counting them would show a member the set made byte-identical as still
/// differing, which for this view — "how far did the set get?" — is the one wrong answer.
fn counted(code: &str, all: &BTreeSet<String>, format: Format) -> bool {
    let Some((rule, path)) = code.split_once('@') else {
        return true;
    };
    match rule {
        "entry:size" | "entry:zip.crc32" => false,
        "entry:mode" if format == Format::Zip => {
            all.contains(&format!("entry:zip.external_attrs@{path}"))
        }
        _ => true,
    }
}
