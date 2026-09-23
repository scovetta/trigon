//! A stored comparison, rendered.
//!
//! The page a reader actually wants: what the package holds, what differs, which passes accounted
//! for the rest, and what that cost the verdict. Until this existed the site offered the raw blob
//! and a link — which is honest, and is also asking somebody to read three thousand lines of JSON
//! to learn that ten members of a NuGet package differ.
//!
//! # Read as data, not as a type
//!
//! `trigon-api` does not depend on `trigon-compare`, and a test asserts it: a crate that cannot
//! reach the comparator cannot produce a `Match`, however the handlers are arranged. So the blob is
//! deserialized into the structs below rather than into `Comparison`.
//!
//! That is a second description of one shape, which is the defect this tree keeps finding. The
//! guard is `the_projection_reads_a_real_comparison`, which builds a genuine `Comparison` through a
//! dev-dependency, serializes it, and asserts every field this file claims to read comes back
//! populated. A field renamed upstream fails that test rather than silently rendering a blank.
//!
//! # What is bounded, and why that is the control
//!
//! Member paths come from an artifact somebody else published, at a count nothing bounds — D9
//! disclaims any limit on the size of a difference summary. The full blob therefore stays
//! class-gated. **This view is anonymous and bounded**: the counts, the ladder and the ledger are
//! the product, and the member list is capped with the remainder stated rather than dropped. The
//! control is the bound, not the secrecy: the same paths already reach a signed `divergence/v1`
//! statement, which is served to anyone.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trigon_core::{Match, NoteCode, Provenance, RiskTier};

/// How many members a rendered view will carry.
///
/// Enough that every real artifact this project has looked at fits whole, and low enough that an
/// artifact with a hundred thousand members cannot turn one anonymous request into a megabyte. The
/// remainder is reported; a list that silently stops is a list that lies about the total.
const MEMBER_CAP: usize = 500;

// --------------------------------------------------------------------------
// What is on disk
// --------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Stored {
    outcome: String,
    upstream: Side,
    rebuild: Side,
    diff: Diff,
    #[serde(default)]
    notes: Vec<StoredNote>,
}

#[derive(Debug, Deserialize)]
struct Side {
    format: String,
    bytes: u64,
    raw: Digests,
    stabilized: Digests,
    #[serde(default)]
    applied: Vec<StoredApplied>,
    /// `(profile id, set digest)`.
    set: (String, String),
    #[serde(default)]
    notes: Vec<StoredNote>,
}

#[derive(Debug, Deserialize)]
struct Digests {
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct StoredApplied {
    id: String,
    risk: RiskTier,
    provenance: Provenance,
    entries_touched: u32,
    bytes_changed: u64,
}

#[derive(Debug, Deserialize)]
struct StoredNote {
    code: NoteCode,
    /// Bytes, because an archive member's name is not guaranteed to be UTF-8.
    #[serde(default)]
    path: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct Diff {
    /// `rule@path` for every difference that *survived* stabilization — the residual that keeps a
    /// run divergent, not the pre-stabilization difference the passes erased.
    ///
    /// `body@lib/x.dll` is the file's own bytes; `entry:mode@lib/x.dll` is the archive entry's
    /// mode. A member listed identical with an `entry:mode` code beside it has bytes that match and
    /// an archive frame that still differs. What the passes *did* erase is not here — it left no
    /// code precisely because it was erased — it is in [`field_edits`](Self::field_edits).
    #[serde(default)]
    codes: Vec<String>,
    identical: usize,
    differs: usize,
    only_upstream: usize,
    only_rebuild: usize,
    executable_differs: usize,
    #[serde(default)]
    files: Vec<StoredFile>,
    /// Which passes changed which field of which member — the ground-truth join partner for
    /// `codes`. A `(field, path)` here whose field is not among that member's codes was reconciled
    /// by these passes; one that is among them was touched but not resolved; a code with no entry
    /// here is a difference nothing addressed.
    #[serde(default)]
    field_edits: Vec<StoredEdit>,
}

/// One `field_edits` row: the passes that wrote one field of one member. `field` is bare (`mode`,
/// `zip.crc32`, `body`); a code spells the same field `entry:mode` / `body`.
#[derive(Debug, Deserialize)]
struct StoredEdit {
    path: String,
    field: String,
    #[serde(default)]
    passes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StoredFile {
    path: Vec<u8>,
    status: String,
    kind: String,
    #[serde(default)]
    upstream_digest: Option<String>,
    #[serde(default)]
    rebuild_digest: Option<String>,
    #[serde(default)]
    upstream_bytes: Option<u64>,
    #[serde(default)]
    rebuild_bytes: Option<u64>,
    /// The name each side's artifact carries, where a stabilizer renamed this member.
    ///
    /// `path` is the *stabilized* name — what the two sides agree to call one file — and it is
    /// correct for the comparison and wrong for anyone going back to the bytes. Absent for every
    /// member no pass renamed, and absent from every comparison written before this field existed,
    /// which is what the defaults are for.
    #[serde(default)]
    upstream_raw_path: Option<Vec<u8>>,
    #[serde(default)]
    rebuild_raw_path: Option<Vec<u8>>,
}

// --------------------------------------------------------------------------
// What a page gets
// --------------------------------------------------------------------------

/// The whole rendered comparison.
#[derive(Debug, Serialize)]
pub struct View {
    pub outcome: String,
    pub format: String,
    pub set: SetRef,
    /// The three questions a verdict is, in order, with the one that answered marked.
    pub ladder: Vec<Rung>,
    /// The best this run could have reached, whatever the bytes did, and what held it there.
    pub ceiling: String,
    pub caps: Vec<Cap>,
    /// Every pass that fired, summed across the two sides.
    pub applied: Vec<Pass>,
    /// Passes in the set that fired on neither side, where that can be known.
    ///
    /// **`None` means nobody can tell from here, and that is a finding.** `apply` returns only what
    /// fired, and the comparison records the set's *id and digest* but not its membership — so a
    /// pass that found nothing is indistinguishable from one that was never configured, to
    /// everything downstream of the run. `trigon watch` can show it only because it re-derives the
    /// set locally from a crate this one deliberately does not link.
    ///
    /// The difference is real evidence: `nupkg-signature` finding no signature to strip says the
    /// package was not signed. Rendering an empty list here would claim we had checked and found
    /// none, which is the "absent is not zero" mistake in its exact form.
    pub silent: Option<Vec<String>>,
    pub census: Census,
    /// What the artifact holds, by kind.
    pub kinds: BTreeMap<String, usize>,
    pub members: Vec<Member>,
    /// Members beyond [`MEMBER_CAP`]. Stated, never dropped silently.
    pub members_omitted: usize,
    pub notes: Vec<NoteGroup>,
    pub upstream_bytes: u64,
    pub rebuild_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct SetRef {
    pub id: String,
    pub digest: String,
}

/// One question in the walk down to a verdict.
#[derive(Debug, Serialize)]
pub struct Rung {
    pub question: String,
    pub upstream: Option<String>,
    pub rebuild: Option<String>,
    pub equal: bool,
    /// Whether this is the rung that decided. Exactly one is true.
    pub answered: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Cap {
    pub id: String,
    pub why: String,
}

#[derive(Debug, Serialize)]
pub struct Pass {
    pub id: String,
    pub risk: String,
    pub provenance: String,
    /// Who stands behind it, in words — `builtin`, `reviewed by …`, `proposed by …`.
    pub who: String,
    pub entries: u32,
    pub bytes: u64,
    pub caps: bool,
}

/// The members, by what happened to them. Never summed into a rate.
#[derive(Debug, Default, Serialize)]
pub struct Census {
    pub differs: usize,
    pub identical: usize,
    pub only_upstream: usize,
    pub only_rebuild: usize,
    /// Of the differing members, how many are executables. Never benign.
    pub executable_differs: usize,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct Member {
    pub path: String,
    pub status: String,
    pub kind: String,
    pub upstream_bytes: Option<u64>,
    pub rebuild_bytes: Option<u64>,
    /// Whether the two sides' stored digests differ. Distinct from `status`, which is the
    /// comparator's word for it.
    pub digests_differ: bool,
    /// What *still* differs about this member after stabilization: `body`, `entry:mode`. Each is
    /// annotated with the passes that touched that field, if any — an empty list means nothing in
    /// the set addresses it. The residual half of the transform.
    pub residual: Vec<FieldWork>,
    /// What a pass *changed and reconciled* on this member: a field some pass wrote that no longer
    /// differs. This is how the transform is made visible — `body` reconciled by `dotnet-il-canonical`
    /// on a `.dll`, `mtime` by `zip-time`, and so on. Empty for a member no pass touched.
    pub reconciled: Vec<FieldWork>,
    /// The raw residual codes, kept for readers written before `residual`/`reconciled` existed.
    pub differences: Vec<String>,
}

/// One field of a member and the passes that wrote it. `field` is spelled as the comparator's
/// difference code spells it — `entry:mode`, `body` — so the reader sees one vocabulary.
#[derive(Debug, Serialize)]
pub struct FieldWork {
    pub field: String,
    pub passes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NoteGroup {
    pub code: String,
    /// `NoteCode::is_noteworthy` — "should reach a human even when the verdict is a clean match".
    pub noteworthy: bool,
    pub count: usize,
    pub paths: Vec<String>,
}

/// Project a stored comparison into what a page needs.
///
/// `None` where the bytes are not a comparison at all, which a corrupt or truncated blob would be.
/// The caller reports that rather than rendering an empty page that looks like a clean result.
/// The name one side's artifact carries for a member the comparison calls `path`.
///
/// `None` where the comparison does not know the member, or knows it under the same name the
/// artifact does — which is every member of every artifact no renaming pass touched. Only two
/// passes rename, both in the `nupkg` profile, so a caller reaches this on a handful of members of
/// one ecosystem and never otherwise.
pub fn raw_name(bytes: &[u8], path: &str, side: &str) -> Option<String> {
    let c: Stored = serde_json::from_slice(bytes).ok()?;
    let f = c.diff.files.into_iter().find(|f| path_of(&f.path) == path)?;
    let raw = match side {
        "upstream" => f.upstream_raw_path,
        _ => f.rebuild_raw_path,
    }?;
    Some(String::from_utf8_lossy(&raw).into_owned())
}

/// A residual difference code that cannot reach the serialized output, so presenting it as "still
/// differs" would mislead. Each is proven at the writer (`trigon_archive::zip`):
///   - `entry:zip.crc32` is the checksum of the body and `entry:size` is the body's length; the
///     writer recomputes both from the body on every write. Neither is ever an independent
///     difference — equal when the body is, following the body when not, and in that case `body@`
///     already names it. So both are redundant with `body@` and dropped.
///   - `entry:mode` on a zip is a stale parse-time shadow of `external_attrs`, which is what the
///     writer emits; once `external_attrs` is reconciled the serialized mode is equal. A tar has no
///     `external_attrs`, so this never fires there and a genuine tar mode difference is kept.
///
/// This filters the *projection* only. The stored comparison keeps every code, so an attestation
/// and anyone reading the blob still see exactly what the comparator found.
fn spurious_residual(
    rule: &str,
    reconciled_rules: &std::collections::BTreeSet<String>,
    residual_rules: &std::collections::BTreeSet<String>,
) -> bool {
    match rule {
        "entry:zip.crc32" | "entry:size" => true,
        "entry:mode" => {
            reconciled_rules.contains("entry:zip.external_attrs")
                && !residual_rules.contains("entry:zip.external_attrs")
        }
        _ => false,
    }
}

pub fn render(bytes: &[u8], set_members: Option<&[String]>) -> Option<View> {
    let c: Stored = serde_json::from_slice(bytes).ok()?;

    // Both sides fire the same set, so the same id appears twice. Summed rather than listed twice:
    // a reader wants "tar-time touched 20 entries across the pair", not two rows of 10.
    let mut by_id: BTreeMap<String, Pass> = BTreeMap::new();
    for a in c.upstream.applied.iter().chain(&c.rebuild.applied) {
        let e = by_id.entry(a.id.clone()).or_insert_with(|| Pass {
            id: a.id.clone(),
            risk: format!("{:?}", a.risk).to_lowercase(),
            provenance: provenance_kind(&a.provenance).into(),
            who: who(&a.provenance),
            entries: 0,
            bytes: 0,
            caps: trigon_core::caps_normalized(a.risk, &a.provenance),
        });
        e.entries += a.entries_touched;
        e.bytes += a.bytes_changed;
    }

    let ceiling = trigon_core::ceiling_of(
        c.upstream
            .applied
            .iter()
            .chain(&c.rebuild.applied)
            .map(|a| (a.risk, &a.provenance)),
    );
    let caps: Vec<Cap> = by_id
        .values()
        .filter(|p| p.caps)
        .map(|p| Cap {
            id: p.id.clone(),
            why: cap_reason(p),
        })
        .collect();

    let fired: std::collections::BTreeSet<&str> = by_id.keys().map(String::as_str).collect();
    let silent = set_members.map(|members| {
        members
            .iter()
            .filter(|m| !fired.contains(m.as_str()))
            .cloned()
            .collect()
    });

    let total = c.diff.files.len();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for f in &c.diff.files {
        *kinds.entry(f.kind.clone()).or_default() += 1;
    }

    // Most interesting first: a hundred identical members must not bury the ten that differ, and a
    // capped list that sorted by path would cap away exactly the rows somebody came to read.
    // `rule@path` split once from the right-hand side, because a member's path may contain `@` and
    // a rule id may not. Splitting from the left would attribute `body@lib/a@b.dll` to a rule
    // called `body` and a path called `lib/a`, which is wrong in a way nothing would report.
    let mut why: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for code in &c.diff.codes {
        if let Some((rule, path)) = code.split_once('@') {
            let e = why.entry(path).or_default();
            if !e.contains(&rule) {
                e.push(rule);
            }
        }
    }

    // Ground-truth attribution: which passes wrote which field of which member, indexed by path.
    // Joined against the residual codes above, this splits each member's fields into what a pass
    // reconciled (a field it wrote that left no surviving code) and what still differs.
    let mut edits_by_path: BTreeMap<&str, Vec<(&str, &Vec<String>)>> = BTreeMap::new();
    for e in &c.diff.field_edits {
        edits_by_path
            .entry(e.path.as_str())
            .or_default()
            .push((e.field.as_str(), &e.passes));
    }
    // A bare field name as a difference code spells it: `body`, else `entry:<field>`.
    let rule_of = |field: &str| -> String {
        if field == "body" {
            "body".to_string()
        } else {
            format!("entry:{field}")
        }
    };

    let mut files: Vec<&StoredFile> = c.diff.files.iter().collect();
    files.sort_by_key(|f| (rank(&f.status), path_of(&f.path)));
    let members: Vec<Member> = files
        .iter()
        .take(MEMBER_CAP)
        .map(|f| {
            // Decoded once and used twice: as the member's own path and as the key into the rule
            // map. Two calls would be two allocations per member, five hundred times.
            let path = path_of(&f.path);
            let residual_rules: std::collections::BTreeSet<String> = why
                .get(path.as_str())
                .map(|v| v.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default();
            let edits = edits_by_path.get(path.as_str());
            // Reconciled: a field a pass wrote whose rule is not among the surviving codes.
            let reconciled_all: Vec<FieldWork> = edits
                .map(|es| {
                    es.iter()
                        .filter(|(field, _)| !residual_rules.contains(&rule_of(field)))
                        .map(|(field, passes)| FieldWork {
                            field: rule_of(field),
                            passes: (*passes).clone(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            // From the unfiltered set, so `entry:mode`'s test still sees a reconciled `external_attrs`.
            let reconciled_rules: std::collections::BTreeSet<String> =
                reconciled_all.iter().map(|fw| fw.field.clone()).collect();
            // A body-derived field (size, crc32) reconciled on its own is an echo of the body being
            // reconciled — dropped so the list shows the work, not its shadow.
            let reconciled: Vec<FieldWork> = reconciled_all
                .into_iter()
                .filter(|fw| !spurious_residual(&fw.field, &reconciled_rules, &residual_rules))
                .collect();
            // Residual: each surviving code that can actually reach the output, annotated with any
            // pass that touched that field. A code the writer recomputes away is dropped, so a
            // member the passes truly reconciled does not read as still-differing.
            let residual: Vec<FieldWork> = residual_rules
                .iter()
                .filter(|rule| !spurious_residual(rule, &reconciled_rules, &residual_rules))
                .map(|rule| {
                    let field = rule.strip_prefix("entry:").unwrap_or(rule);
                    let passes = edits
                        .and_then(|es| es.iter().find(|(fld, _)| *fld == field))
                        .map(|(_, p)| (*p).clone())
                        .unwrap_or_default();
                    FieldWork {
                        field: rule.clone(),
                        passes,
                    }
                })
                .collect();
            Member {
                differences: residual_rules
                    .iter()
                    .filter(|rule| !spurious_residual(rule, &reconciled_rules, &residual_rules))
                    .cloned()
                    .collect(),
                residual,
                reconciled,
                path,
                status: f.status.clone(),
                kind: f.kind.clone(),
                upstream_bytes: f.upstream_bytes,
                rebuild_bytes: f.rebuild_bytes,
                digests_differ: f.upstream_digest != f.rebuild_digest,
            }
        })
        .collect();

    // Every note from either side and from the comparison itself, in one list: a reader does not
    // care which phase observed something, only that something was observed.
    let mut groups: BTreeMap<String, NoteGroup> = BTreeMap::new();
    for n in c
        .notes
        .iter()
        .chain(&c.upstream.notes)
        .chain(&c.rebuild.notes)
    {
        let code = format!("{:?}", n.code);
        let g = groups.entry(code.clone()).or_insert_with(|| NoteGroup {
            code,
            noteworthy: n.code.is_noteworthy(),
            count: 0,
            paths: Vec::new(),
        });
        g.count += 1;
        if let Some(p) = &n.path
            && g.paths.len() < 20
        {
            g.paths.push(path_of(p));
        }
    }

    Some(View {
        ladder: ladder(&c),
        outcome: c.outcome.clone(),
        format: c.upstream.format.clone(),
        set: SetRef {
            id: c.upstream.set.0.clone(),
            digest: c.upstream.set.1.clone(),
        },
        ceiling: match ceiling {
            Match::Normalized => "normalized".into(),
            other => other.to_string(),
        },
        caps,
        applied: by_id.into_values().collect(),
        silent,
        census: Census {
            differs: c.diff.differs,
            identical: c.diff.identical,
            only_upstream: c.diff.only_upstream,
            only_rebuild: c.diff.only_rebuild,
            executable_differs: c.diff.executable_differs,
            total,
        },
        kinds,
        members,
        members_omitted: total.saturating_sub(MEMBER_CAP),
        notes: groups.into_values().collect(),
        upstream_bytes: c.upstream.bytes,
        rebuild_bytes: c.rebuild.bytes,
    })
}

/// The three questions, and which one answered.
///
/// A verdict is a walk that stops at the first question that answers. Six digests are unreadable;
/// three questions with one of them marked is the same information a person can hold.
fn ladder(c: &Stored) -> Vec<Rung> {
    let raw_equal = c.upstream.raw.sha256 == c.rebuild.raw.sha256;
    let stab_equal = c.upstream.stabilized.sha256 == c.rebuild.stabilized.sha256;
    vec![
        Rung {
            question: "Are the published and rebuilt bytes the same?".into(),
            upstream: Some(c.upstream.raw.sha256.clone()),
            rebuild: Some(c.rebuild.raw.sha256.clone()),
            equal: raw_equal,
            answered: raw_equal,
            detail: if raw_equal {
                "Yes. Nothing had to be normalized for this to hold.".into()
            } else {
                "No, so the question becomes whether they differ in ways a named pass removes."
                    .into()
            },
        },
        Rung {
            question: "Are they the same after the stabilizers?".into(),
            upstream: Some(c.upstream.stabilized.sha256.clone()),
            rebuild: Some(c.rebuild.stabilized.sha256.clone()),
            equal: stab_equal,
            answered: !raw_equal && stab_equal,
            // Three answers, not two. On an `exact` run the bytes were already the same, so
            // "every way in which they differ was removed by a pass" describes differences that
            // never existed — a sentence that reads as a caveat on a result that has none.
            detail: match (raw_equal, stab_equal) {
                (true, _) => "They were already the same, so the stabilizers had nothing to \
                              account for."
                    .into(),
                (false, true) => "Yes. Every way in which they differ was removed by a pass named \
                                  below."
                    .into(),
                (false, false) => "No. Something survived every pass, so the answer is member by \
                                   member."
                    .into(),
            },
        },
        Rung {
            question: "Which members differ?".into(),
            upstream: None,
            rebuild: None,
            equal: c.diff.differs == 0,
            answered: !raw_equal && !stab_equal,
            detail: if raw_equal {
                format!(
                    "None. All {} member(s) are byte for byte what was published.",
                    c.diff.files.len()
                )
            } else {
                format!(
                    "{} of {} member(s) still differ after stabilization.",
                    c.diff.differs,
                    c.diff.files.len()
                )
            },
        },
    ]
}

/// Which half of the cap rule a pass trips. Both can be true, and saying only one would be the
/// half-reason a risk-only ledger used to give.
fn cap_reason(p: &Pass) -> String {
    let non_builtin = p.provenance != "builtin";
    let risky = matches!(p.risk.as_str(), "content" | "lossy");
    match (non_builtin, risky) {
        (true, true) => format!(
            "{} provenance, and {} risk is above metadata",
            p.who, p.risk
        ),
        (true, false) => format!("{} — not compiled in", p.who),
        (false, true) => format!("{} risk is above metadata", p.risk),
        // `caps_normalized` said this row caps, so one of the two must hold. Reached only if the
        // projection's spelling of risk or provenance has drifted from core's.
        (false, false) => "the cap fired and this projection cannot say which half".into(),
    }
}

fn provenance_kind(p: &Provenance) -> &'static str {
    match p {
        Provenance::Builtin => "builtin",
        Provenance::Human { .. } => "human",
        Provenance::Model { .. } => "model",
    }
}

/// Who stands behind a pass, in the words a reader needs: a `Model` row names the model and a
/// `Human` row names the reviewer, rather than both reading as "not builtin".
fn who(p: &Provenance) -> String {
    match p {
        Provenance::Builtin => "builtin".into(),
        Provenance::Human { reviewer } => format!("reviewed by {reviewer}"),
        Provenance::Model { model_id, .. } => format!("proposed by {model_id}"),
    }
}

/// Sort key: the finding first.
fn rank(status: &str) -> u8 {
    match status {
        "differs" => 0,
        "only_upstream" | "only_rebuild" => 1,
        "normalized" => 2,
        "identical" => 3,
        _ => 4,
    }
}

/// An archive member's name is bytes, and is not guaranteed to be UTF-8 — a member whose name is
/// not decodable is exactly the kind of member worth looking at, so it is rendered lossily rather
/// than dropped.
fn path_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_whose_name_is_not_utf8_still_appears() {
        assert_eq!(path_of(b"lib/net20/x.dll"), "lib/net20/x.dll");
        assert!(path_of(&[0xff, 0xfe, b'a']).contains('a'));
    }

    #[test]
    fn the_finding_sorts_above_the_noise() {
        let mut v = vec!["identical", "differs", "normalized", "only_upstream"];
        v.sort_by_key(|s| rank(s));
        assert_eq!(v, ["differs", "only_upstream", "normalized", "identical"]);
    }

    #[test]
    fn a_cap_always_says_which_half_fired() {
        let p = |risk: &str, prov: &str, who: &str| Pass {
            id: "x".into(),
            risk: risk.into(),
            provenance: prov.into(),
            who: who.into(),
            entries: 0,
            bytes: 0,
            caps: true,
        };
        assert!(cap_reason(&p("content", "builtin", "builtin")).contains("above metadata"));
        assert!(cap_reason(&p("metadata", "human", "reviewed by ada")).contains("reviewed by ada"));
        let both = cap_reason(&p("lossy", "model", "proposed by m"));
        assert!(both.contains("proposed by m") && both.contains("above metadata"));
    }
}
