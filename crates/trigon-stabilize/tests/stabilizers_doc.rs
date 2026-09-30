//! `docs/stabilizers.md` is the reference for every profile and pass this crate ships, and it is held
//! to the registry here rather than to memory.
//!
//! A reader who meets a pass id in a statement's `applied` list looks it up there, so the page is
//! only worth anything if it cannot fall behind. Each check reads the registry through the crate's
//! own public API (`all_profiles`, `profile`, `all_builtin`) and fails with the edit to make:
//!
//! - the page's first sentence counts the profiles and passes the registry has;
//! - every profile has a row in the §2 summary giving its pass count and the first sixteen hex
//!   digits of its set digest, and a `### \`id\`` section giving the full digest and a pass table
//!   that lists its members in the order they run, with their tiers and stages;
//! - the §1.4 cap table lists, for each profile, exactly the passes that can cap its verdict;
//! - every pass has a `#### \`id\`` entry whose opening paragraph gives its tier, its stage and the
//!   profiles it runs in, as the code has them;
//! - every id on [`RETIRED`] keeps an entry marked superseded, so an old statement's `applied` list
//!   can still be read, and the list names every id a `-vN` pass replaced;
//! - the page documents no profile the registry lacks, and no pass it lacks that is not retired.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use trigon_core::caps_normalized;
use trigon_stabilize::{Stabilizer, StabilizerSet, all_builtin, all_profiles, profile};

const DOC: &str = "docs/stabilizers.md";

/// Every id a pass has given up, with the id that replaced it, or `None` for a pass removed with no
/// successor. A statement signed under an old set names these in its `applied` list, so each keeps
/// an entry on the page. A `-vN` rename is derived from the registry and checked against this list;
/// a pass removed outright, or renamed to another base name, has to be added here by hand, and the
/// stale-entry check says so when its entry outlives it.
const RETIRED: &[(&str, Option<&str>)] = &[
    ("wheel-record", Some("wheel-record-v2")),
    ("nupkg-doc-member-order", Some("nupkg-doc-member-order-v2")),
    ("dotnet-il-canonical", Some("dotnet-il-canonical-v2")),
    (
        "dotnet-assembly-identity",
        Some("dotnet-assembly-identity-v2"),
    ),
    ("cargo-vcs-hash", Some("cargo-vcs-hash-v2")),
    ("npm-install-fields", Some("npm-install-fields-v2")),
    ("gem-metadata-date", Some("gem-metadata-date-v2")),
    (
        "gem-metadata-rubygems-version",
        Some("gem-metadata-rubygems-version-v2"),
    ),
    (
        "gem-metadata-cert-chain",
        Some("gem-metadata-cert-chain-v2"),
    ),
    (
        "nupkg-repository-branch",
        Some("nupkg-repository-branch-v2"),
    ),
    ("nupkg-readme-markers", Some("nupkg-readme-markers-v2")),
    ("pyc-header", Some("pyc-header-v2")),
    ("wheel-record-v2", Some("wheel-record-v3")),
    ("tar-entry-order", Some("tar-entry-order-v2")),
    ("gzip-meta", Some("gzip-meta-v2")),
    ("dotnet-il-canonical-v2", Some("dotnet-il-canonical-v3")),
];

fn reference() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/stabilizers.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// A pass as the registry has it.
struct Pass {
    tier: String,
    stage: String,
    profiles: BTreeSet<String>,
}

fn tier(s: &dyn Stabilizer) -> String {
    format!("{:?}", s.risk()).to_lowercase()
}

fn stage(s: &dyn Stabilizer) -> String {
    format!("{:?}", s.stage()).to_lowercase()
}

fn set(id: &str) -> StabilizerSet {
    profile(id).unwrap_or_else(|| panic!("`all_profiles` lists `{id}` and `profile` refuses it"))
}

/// Every pass the registry exposes: the builtin catalogue, and every member of every profile, so a
/// pass that reaches a profile without the catalogue is still held to the page.
fn passes() -> BTreeMap<String, Pass> {
    let mut out: BTreeMap<String, Pass> = BTreeMap::new();
    let mut put = |s: &dyn Stabilizer| {
        out.entry(s.id().to_string()).or_insert_with(|| Pass {
            tier: tier(s),
            stage: stage(s),
            profiles: BTreeSet::new(),
        });
    };
    for s in all_builtin() {
        put(s.as_ref());
    }
    for id in all_profiles() {
        for m in &set(id).members {
            put(m.as_ref());
        }
    }
    for id in all_profiles() {
        for m in &set(id).members {
            out.get_mut(m.id().as_str())
                .unwrap()
                .profiles
                .insert(id.to_string());
        }
    }
    out
}

/// The body under the heading line `heading`, up to the next heading of the same level or higher,
/// or `None` when the page has no such heading. Lines inside a code fence are never headings.
fn section<'a>(doc: &'a str, heading: &str) -> Option<&'a str> {
    let level = heading.chars().take_while(|&c| c == '#').count();
    let mut fence = false;
    let mut start: Option<usize> = None;
    let mut at = 0;
    for line in doc.split_inclusive('\n') {
        let text = line.trim_end_matches(['\n', '\r']);
        if text.starts_with("```") {
            fence = !fence;
        }
        if !fence {
            let hashes = text.chars().take_while(|&c| c == '#').count();
            let is_heading = hashes > 0 && text[hashes..].starts_with(' ');
            match start {
                None if text == heading => start = Some(at + line.len()),
                Some(s) if is_heading && hashes <= level => return Some(&doc[s..at]),
                _ => {}
            }
        }
        at += line.len();
    }
    start.map(|s| &doc[s..])
}

/// The first paragraph of `text`, its lines joined by single spaces, so a claim the 100-column wrap
/// splits across lines still reads as one.
fn opening(text: &str) -> String {
    text.lines()
        .skip_while(|l| l.trim().is_empty())
        .take_while(|l| !l.trim().is_empty())
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The cells of a Markdown table row, trimmed.
fn cells(row: &str) -> Vec<&str> {
    let row = row.trim();
    let row = row.strip_prefix('|').unwrap_or(row);
    let row = row.strip_suffix('|').unwrap_or(row);
    row.split('|').map(str::trim).collect()
}

/// Every heading line at exactly `level` whose text is a code span, as the id it names.
fn headed_ids(doc: &str, level: usize) -> Vec<String> {
    let prefix = format!("{} `", "#".repeat(level));
    let mut fence = false;
    let mut out = Vec::new();
    for line in doc.lines() {
        if line.starts_with("```") {
            fence = !fence;
        }
        if fence {
            continue;
        }
        if let Some(rest) = line.strip_prefix(&prefix) {
            if let Some(end) = rest.find('`') {
                out.push(rest[..end].to_string());
            }
        }
    }
    out
}

/// The ids a pass called `<base>-vN` replaced: `<base>`, then `<base>-v2` up to `<base>-v(N-1)`.
fn predecessors(id: &str) -> Vec<String> {
    let Some((base, n)) = id.rsplit_once("-v") else {
        return Vec::new();
    };
    let Ok(n) = n.parse::<u32>() else {
        return Vec::new();
    };
    if n < 2 {
        return Vec::new();
    }
    std::iter::once(base.to_string())
        .chain((2..n).map(|k| format!("{base}-v{k}")))
        .collect()
}

/// A count as the page spells it: "ten", "thirty-three".
fn in_words(n: usize) -> String {
    const ONES: &str = "zero one two three four five six seven eight nine ten eleven twelve \
                        thirteen fourteen fifteen sixteen seventeen eighteen nineteen";
    const TENS: &str = "twenty thirty forty fifty sixty seventy eighty ninety";
    let one = |k: usize| ONES.split_whitespace().nth(k).unwrap();
    let ten = |k: usize| TENS.split_whitespace().nth(k - 2).unwrap();
    match n {
        0..=19 => one(n).to_string(),
        20..=99 if n % 10 == 0 => ten(n / 10).to_string(),
        20..=99 => format!("{}-{}", ten(n / 10), one(n % 10)),
        _ => n.to_string(),
    }
}

#[test]
fn the_first_sentence_counts_the_profiles_and_passes_the_registry_has() {
    let doc = reference();
    let (_, after_title) = doc.split_once('\n').expect("a title line");
    let claim = format!(
        "Trigon ships {} stabilizer profiles and {} passes.",
        in_words(all_profiles().len()),
        in_words(passes().len())
    );
    let first = opening(after_title);
    assert!(
        first.starts_with(&claim),
        "{DOC} opens \"{first}\": it must open \"{claim}\""
    );
}

#[test]
fn every_profile_has_a_summary_row_and_a_section_that_match_its_set() {
    let doc = reference();
    let summary = section(&doc, "## 2. Profiles").expect("a `## 2. Profiles` section");
    let mut wrong = Vec::new();
    for id in all_profiles() {
        let s = set(id);
        let digest = s.digest().to_hex();

        let lead = format!("| [`{id}`](#{id}) |");
        let short = format!("`{}…`", &digest[..16]);
        let count = s.members.len().to_string();
        match summary.lines().find(|l| l.starts_with(&lead)).map(cells) {
            None => wrong.push(format!(
                "`{id}` has no row in the §2 summary of {DOC}: add one opening \"{lead}\", with \
                 {count} passes and the digest {short}"
            )),
            Some(row) if row.len() < 4 || row[2] != count || row[3] != short => wrong.push(format!(
                "the §2 summary row for `{id}` in {DOC} reads {row:?}: it must give {count} passes \
                 and the digest {short}"
            )),
            Some(_) => {}
        }

        let heading = format!("### `{id}`");
        let Some(body) = section(&doc, &heading) else {
            wrong.push(format!(
                "`{id}` has no `{heading}` section: document the new profile in {DOC}, with its \
                 set digest and its passes in the order they run"
            ));
            continue;
        };
        if !body.contains(&digest) {
            wrong.push(format!(
                "the `{id}` section does not carry the set digest {digest}: the set changed, so \
                 update its digest, its row in the summary table and its pass table in {DOC}"
            ));
        }
        let listed: Vec<String> = body
            .lines()
            .filter(|l| l.starts_with('|'))
            .map(cells)
            .filter(|c| c.len() >= 4 && c[0].parse::<usize>().is_ok())
            .map(|c| format!("| {} | {} | {} | {} |", c[0], c[1], c[2], c[3]))
            .collect();
        let expected: Vec<String> = s
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let p = m.id();
                format!(
                    "| {} | [`{p}`](#{p}) | {} | {} |",
                    i + 1,
                    tier(m.as_ref()),
                    stage(m.as_ref())
                )
            })
            .collect();
        if listed != expected {
            wrong.push(format!(
                "the pass table of `{id}` in {DOC} does not list the set in the order it runs; its \
                 first four columns must read:\n{}",
                expected.join("\n")
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_cap_table_lists_the_passes_that_can_cap_each_profile() {
    let doc = reference();
    let body = section(&doc, "### 1.4 Risk tiers and the verdict")
        .expect("a `### 1.4 Risk tiers and the verdict` section");
    let table: BTreeMap<String, Vec<String>> = body
        .lines()
        .skip_while(|l| !l.starts_with("| Profile | Passes that cap |"))
        .skip(1)
        .take_while(|l| l.starts_with('|'))
        .map(cells)
        .filter(|c| c.len() == 2 && !c[0].starts_with('-'))
        .map(|c| {
            let id = c[0].trim_matches('`').to_string();
            (id, c[1].split(", ").map(str::to_string).collect())
        })
        .collect();
    let expected: BTreeMap<String, Vec<String>> = all_profiles()
        .into_iter()
        .map(|id| {
            let capping = set(id)
                .members
                .iter()
                .filter(|m| caps_normalized(m.risk(), &m.provenance()))
                .map(|m| format!("`{}` ({})", m.id(), tier(m.as_ref())))
                .collect::<Vec<_>>();
            (id.to_string(), capping)
        })
        .filter(|(_, capping)| !capping.is_empty())
        .collect();
    assert_eq!(
        table, expected,
        "the §1.4 cap table in {DOC} must list, for each profile with a pass that can cap its \
         verdict, those passes in the order they run and no others"
    );
}

#[test]
fn every_pass_has_an_entry_with_its_tier_stage_and_profiles() {
    let doc = reference();
    let mut wrong = Vec::new();
    for (id, pass) in passes() {
        let heading = format!("#### `{id}`");
        let Some(body) = section(&doc, &heading) else {
            wrong.push(format!(
                "`{id}` has no `{heading}` entry: document the new pass in {DOC}, under its \
                 family in §3, and add it to the table of every profile that runs it"
            ));
            continue;
        };
        // The opening paragraph of the entry: "`tier` tier, `stage` stage. Profiles: `a`, `b`."
        let opening = opening(body);
        let claim = format!("`{}` tier, `{}` stage.", pass.tier, pass.stage);
        if !opening.starts_with(&claim) {
            wrong.push(format!(
                "`{id}` is {} at {} and the entry in {DOC} opens \"{opening}\": it must open \
                 \"{claim}\"",
                pass.tier, pass.stage
            ));
        }
        let listed: BTreeSet<String> = opening
            .split_once("Profile")
            .map(|(_, rest)| {
                rest.split('`')
                    .skip(1)
                    .step_by(2)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if listed != pass.profiles {
            wrong.push(format!(
                "`{id}` runs in {:?} and its entry in {DOC} lists {listed:?}",
                pass.profiles
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn every_retired_id_keeps_an_entry_marked_superseded() {
    let doc = reference();
    let passes = passes();
    let retired: BTreeSet<&str> = RETIRED.iter().map(|(old, _)| *old).collect();
    let mut wrong = Vec::new();
    for &(old, new) in RETIRED {
        if passes.contains_key(old) {
            wrong.push(format!(
                "`{old}` is on RETIRED and the registry still has it: take it off the list"
            ));
        }
        if let Some(new) = new {
            if !passes.contains_key(new) && !retired.contains(new) {
                wrong.push(format!(
                    "RETIRED says `{new}` replaced `{old}`, and `{new}` is neither in the \
                     registry nor retired itself"
                ));
            }
        }
        let heading = format!("#### `{old}`");
        let mark = match new {
            Some(new) => format!("Superseded by `{new}`"),
            None => "Retired".to_string(),
        };
        let marked = section(&doc, &heading).is_some_and(|b| opening(b).starts_with(&mark));
        if !marked {
            wrong.push(format!(
                "`{old}` is retired: keep a `{heading}` entry in {DOC} opening \"{mark}\", so a \
                 statement whose `applied` list names `{old}` can still be read"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_retired_list_names_every_id_a_versioned_pass_replaced() {
    let retired: BTreeSet<&str> = RETIRED.iter().map(|(old, _)| *old).collect();
    let mut missing = Vec::new();
    for id in passes().keys() {
        for old in predecessors(id) {
            if !retired.contains(old.as_str()) {
                missing.push(format!(
                    "`{id}` replaced `{old}`: add (\"{old}\", Some(\"{id}\")) to RETIRED in this \
                     file, and keep its entry in {DOC}, opening \"Superseded by `{id}`\""
                ));
            }
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[test]
fn the_reference_documents_nothing_the_registry_lacks() {
    let doc = reference();
    let passes = passes();
    let retired: BTreeSet<&str> = RETIRED.iter().map(|(old, _)| *old).collect();
    let mut stale = Vec::new();
    for id in headed_ids(&doc, 3) {
        if !all_profiles().contains(&id.as_str()) {
            stale.push(format!(
                "{DOC} has a section for profile `{id}`, which `all_profiles()` does not list"
            ));
        }
    }
    for id in headed_ids(&doc, 4) {
        if !passes.contains_key(&id) && !retired.contains(id.as_str()) {
            stale.push(format!(
                "{DOC} documents pass `{id}`, which the registry does not have: if a statement \
                 can name it in `applied`, add it to RETIRED in this file and mark its entry \
                 superseded or retired; otherwise remove the entry"
            ));
        }
    }
    assert!(stale.is_empty(), "{}", stale.join("\n"));
}

#[test]
fn a_superseded_id_is_derived_from_its_successor() {
    assert_eq!(predecessors("wheel-record-v2"), ["wheel-record"]);
    assert_eq!(
        predecessors("x-v4"),
        ["x", "x-v2", "x-v3"].map(String::from).to_vec()
    );
    // A `-v` inside an id is not a version suffix.
    assert!(predecessors("tar-vendor").is_empty());
    assert!(predecessors("gzip-meta").is_empty());
    assert!(predecessors("x-v1").is_empty());
}

#[test]
fn a_count_is_spelled_as_the_page_spells_it() {
    assert_eq!(in_words(0), "zero");
    assert_eq!(in_words(10), "ten");
    assert_eq!(in_words(19), "nineteen");
    assert_eq!(in_words(20), "twenty");
    assert_eq!(in_words(33), "thirty-three");
    assert_eq!(in_words(99), "ninety-nine");
    assert_eq!(in_words(100), "100");
}
