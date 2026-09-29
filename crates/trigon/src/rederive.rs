//! `trigon rederive`: fill in the explanation a stored comparison predates.
//!
//! A comparison written before per-field attribution and the pass-by-pass progression existed
//! carries neither, so the management UI can show *that* a run normalized and not *how*. Both are
//! re-derivable from what the store already holds — the two artifacts and the stabilizer set named
//! in the comparison — and this does exactly that, for the runs where it can be done honestly.
//!
//! **The original is never touched.** The run record keeps naming the comparison it was judged on,
//! and the re-derivation is written beside it under `derived/`, keyed by that comparison's digest.
//! It is written only when the re-derivation agrees with the original on everything a verdict
//! rests on — outcome, the four digests, the set, the member statuses and the difference signature —
//! and only under the very set the run was judged with. A run judged under a set this binary no
//! longer has is skipped and says so: explaining a verdict with a different set would explain a
//! different verdict.
//!
//! **A run that failed fails the command.** Every run is still tried and every line and the tally
//! still printed, and then the command exits 1 naming each run that could not be re-derived and
//! each that re-derived to a comparison other than the one recorded. An artifact the record says
//! is kept and the store has lost, or cannot give back as the bytes the record names, is one that
//! could not be re-derived. Skips alone exit 0: a run with nothing to fill in is not a failure, and
//! a second backfill over a store the first one finished skips every run.

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use trigon_archive::Limits;
use trigon_compare::{Comparison, compare_bytes};
use trigon_store::Store;

#[derive(Debug)]
pub struct Args {
    pub store: PathBuf,
    pub runs: Vec<String>,
    pub force: bool,
    pub dry_run: bool,
}

/// What happened to one run.
enum Done {
    Written { steps: usize, edits: usize },
    Skipped(String),
    /// Re-derived, to something other than the recorded comparison: the first thing a verdict
    /// rests on that the two disagree about. Not written.
    Disagrees(String),
}

pub fn run(args: Args) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let store = Store::existing(&args.store)?;
        let ids = if args.runs.is_empty() {
            store.list_runs().await?
        } else {
            args.runs.clone()
        };
        let (mut written, mut skipped) = (0usize, 0usize);
        // The runs that failed, apart by kind: one the store could not give us, and one whose
        // re-derivation disagrees with its record, which is a finding about the comparator.
        let (mut unread, mut disagreed) = (Vec::new(), Vec::new());
        for id in &ids {
            match one(&store, id, args.force, args.dry_run).await {
                Ok(Done::Written { steps, edits }) => {
                    written += 1;
                    println!(
                        "{id}  {}  {steps} step(s), {edits} field edit(s)",
                        if args.dry_run { "would write" } else { "written" }
                    );
                }
                Ok(Done::Skipped(why)) => {
                    skipped += 1;
                    println!("{id}  skipped  {why}");
                }
                Ok(Done::Disagrees(why)) => {
                    disagreed.push(id.as_str());
                    println!(
                        "{id}  failed   re-derivation disagrees with the recorded comparison: {why}"
                    );
                }
                Err(e) => {
                    unread.push(id.as_str());
                    println!("{id}  failed   {e:#}");
                }
            }
        }
        println!(
            "\n{written} {}, {skipped} skipped, {} failed, of {} run(s)",
            if args.dry_run { "would be written" } else { "written" },
            unread.len() + disagreed.len(),
            ids.len()
        );
        failures(&unread, &disagreed)
    })
}

/// The command's own verdict on a backfill: `Ok` only when no run failed, and otherwise an error
/// naming each run that failed, by kind, which `main` prints and exits 1 on.
fn failures(unread: &[&str], disagreed: &[&str]) -> Result<()> {
    let mut said = Vec::new();
    if !disagreed.is_empty() {
        said.push(format!(
            "{} run(s) re-derived to a comparison other than the one recorded: {}",
            disagreed.len(),
            disagreed.join(", ")
        ));
    }
    if !unread.is_empty() {
        said.push(format!(
            "{} run(s) could not be re-derived: {}",
            unread.len(),
            unread.join(", ")
        ));
    }
    if !said.is_empty() {
        bail!("{}", said.join("; "));
    }
    Ok(())
}

async fn one(store: &Store, id: &str, force: bool, dry_run: bool) -> Result<Done> {
    let r = store.get_run(id).await?;
    let Some(recorded) = r.comparison else {
        return Ok(Done::Skipped("reached no comparison".into()));
    };
    let original_bytes = store
        .blobs()
        .get(&recorded)
        .await
        .context("reading the recorded comparison")?;
    let original: Comparison =
        serde_json::from_slice(&original_bytes).context("parsing the recorded comparison")?;

    if !force {
        if store.get_derived_comparison(&recorded).await?.is_some() {
            return Ok(Done::Skipped("already re-derived".into()));
        }
        if original
            .diff
            .as_ref()
            .is_some_and(|d| d.progression.is_some())
        {
            return Ok(Done::Skipped(
                "recorded its own progression when it was judged; nothing to fill in".into(),
            ));
        }
    }

    let Some(rebuilt) = r.rebuild.as_ref() else {
        return Ok(Done::Skipped("has no rebuilt artifact".into()));
    };
    let (upstream, rebuild) = match (
        store
            .artifact(&r.id, "published artifact", &r.upstream)
            .await,
        store.artifact(&r.id, "rebuilt artifact", rebuilt).await,
    ) {
        (Ok(Some(u)), Ok(Some(b))) => (u, b),
        // Kept by the record's word and gone from the store: missing, and said so, never taken
        // for a run whose bytes were pruned on purpose. Both this and bytes the store cannot give
        // back as the ones the record names are damage, not a run with nothing to fill in, so
        // they fail the command: a second backfill would meet them again.
        (Err(e @ trigon_store::StoreError::Missing { .. }), _)
        | (_, Err(e @ trigon_store::StoreError::Missing { .. })) => return Err(e.into()),
        (Err(e), _) | (_, Err(e)) => {
            return Err(anyhow::Error::new(e)
                .context("one of the two artifacts could not be read from the store"));
        }
        _ => {
            return Ok(Done::Skipped(
                "one of the two artifacts was not kept in the store: pruned after a match, or \
                 never stored"
                    .into(),
            ));
        }
    };

    let (set_id, set_digest) = &original.upstream.set;
    let Some(set) = trigon_stabilize::profile(set_id.as_str()) else {
        return Ok(Done::Skipped(format!(
            "was judged under profile `{set_id}`, which this binary does not have"
        )));
    };
    if set.digest() != *set_digest {
        return Ok(Done::Skipped(format!(
            "was judged under {set_id} {}; this binary's {set_id} is {} — a different set would \
             explain a different verdict",
            &set_digest.to_hex()[..12],
            &set.digest().to_hex()[..12],
        )));
    }

    let fresh = compare_bytes(
        upstream.to_vec(),
        rebuild.to_vec(),
        original.upstream.format,
        &set,
        &Limits::default(),
    )
    .context("re-deriving the comparison")?;

    if let Some(why) = disagreement(&original, &fresh) {
        // Loud, not written, and a failure of the command. The same bytes under the same set should
        // give the same verdict; when they do not, that is a finding about the comparator, not a
        // gap to paper over.
        return Ok(Done::Disagrees(why));
    }

    let diff = fresh.diff.as_ref();
    let steps = diff
        .and_then(|d| d.progression.as_ref())
        .map_or(0, |p| p.steps.len());
    let edits = diff.map_or(0, |d| d.field_edits.len());
    if !dry_run {
        store
            .put_derived_comparison(&recorded, &serde_json::to_vec(&fresh)?)
            .await?;
    }
    Ok(Done::Written { steps, edits })
}

/// The first thing a verdict rests on that the two comparisons disagree about, if any.
///
/// Field-for-field on what decides and locates a verdict, not a byte comparison of the two blobs:
/// a comparison written by an older binary lacks fields a newer one adds (raw member names, for
/// one), and those are not a disagreement.
fn disagreement(a: &Comparison, b: &Comparison) -> Option<String> {
    if a.outcome != b.outcome {
        return Some(format!("outcome {} vs {}", a.outcome, b.outcome));
    }
    for (side, x, y) in [
        ("upstream", &a.upstream, &b.upstream),
        ("rebuild", &a.rebuild, &b.rebuild),
    ] {
        if x.raw.sha256 != y.raw.sha256 {
            return Some(format!("{side} raw digest"));
        }
        if x.stabilized.sha256 != y.stabilized.sha256 {
            return Some(format!("{side} stabilized digest"));
        }
        if x.set != y.set {
            return Some(format!("{side} stabilizer set"));
        }
    }
    match (&a.diff, &b.diff) {
        (Some(x), Some(y)) => {
            let counts = |d: &trigon_compare::DiffReport| {
                (d.identical, d.differs, d.only_upstream, d.only_rebuild, d.executable_differs)
            };
            if counts(x) != counts(y) {
                return Some("member counts".into());
            }
            if x.codes != y.codes {
                return Some("difference signature".into());
            }
            let statuses = |d: &trigon_compare::DiffReport| {
                d.files
                    .iter()
                    .map(|f| (f.path.to_lossy().into_owned(), f.status))
                    .collect::<Vec<_>>()
            };
            if statuses(x) != statuses(y) {
                return Some("member statuses".into());
            }
            None
        }
        (None, None) => None,
        _ => Some("one side has a member report and the other does not".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trigon_compare::FileStatus;
    use trigon_core::Digest;

    /// A gzipped tarball of `members`, every one stamped `mtime`.
    fn tgz(members: &[(&str, &[u8])], mtime: u64) -> Vec<u8> {
        let mut b = ::tar::Builder::new(Vec::new());
        for (name, body) in members {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(mtime);
            h.set_cksum();
            b.append_data(&mut h, *name, *body).unwrap();
        }
        let mut gz = Vec::new();
        {
            use std::io::Write as _;
            let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            e.write_all(&b.into_inner().unwrap()).unwrap();
            e.finish().unwrap();
        }
        gz
    }

    /// A real comparison with a member report: two members, one of which differs in content.
    fn divergent() -> Comparison {
        let set = trigon_stabilize::profile("tar-gzip").unwrap();
        let c = compare_bytes(
            tgz(&[("package/a.js", b"a\n"), ("package/b.js", b"one\n")], 1_700_000_000),
            tgz(&[("package/a.js", b"a\n"), ("package/b.js", b"two\n")], 1_600_000_000),
            trigon_core::Format::TarGz,
            &set,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(c.outcome, trigon_core::Match::Divergent, "the fixture");
        assert!(c.diff.as_ref().is_some_and(|d| d.files.len() == 2), "the fixture");
        c
    }

    fn other() -> Digest {
        Digest::from_bytes([7u8; 32])
    }

    #[test]
    fn a_comparison_agrees_with_itself() {
        let a = divergent();
        assert_eq!(disagreement(&a, &a.clone()), None);
    }

    /// What an older binary wrote lacks what a newer one adds — attribution, the progression, raw
    /// member names — and none of those is something a verdict rests on.
    #[test]
    fn what_an_older_binary_did_not_record_is_not_a_disagreement() {
        let fresh = divergent();
        let mut old = fresh.clone();
        let d = old.diff.as_mut().unwrap();
        d.field_edits.clear();
        d.progression = None;
        for f in &mut d.files {
            f.upstream_raw_path = None;
            f.rebuild_raw_path = None;
        }
        assert_eq!(disagreement(&old, &fresh), None);
    }

    /// Every field a verdict rests on is compared, and the first that differs is named.
    #[test]
    fn each_thing_a_verdict_rests_on_is_named_when_it_differs() {
        let a = divergent();
        let differs = |edit: &dyn Fn(&mut Comparison)| {
            let mut b = a.clone();
            edit(&mut b);
            disagreement(&a, &b)
        };
        type Edit = Box<dyn Fn(&mut Comparison)>;
        let cases: Vec<(&str, Edit)> = vec![
            (
                "outcome divergent vs normalized",
                Box::new(|b| b.outcome = trigon_core::Match::Normalized),
            ),
            ("upstream raw digest", Box::new(|b| b.upstream.raw.sha256 = other())),
            (
                "upstream stabilized digest",
                Box::new(|b| b.upstream.stabilized.sha256 = other()),
            ),
            ("upstream stabilizer set", Box::new(|b| b.upstream.set.1 = other())),
            ("rebuild raw digest", Box::new(|b| b.rebuild.raw.sha256 = other())),
            (
                "rebuild stabilized digest",
                Box::new(|b| b.rebuild.stabilized.sha256 = other()),
            ),
            (
                "rebuild stabilizer set",
                Box::new(|b| b.rebuild.set.0 = trigon_core::ProfileId::new("other")),
            ),
            (
                "member counts",
                Box::new(|b| b.diff.as_mut().unwrap().identical += 1),
            ),
            (
                "member counts",
                Box::new(|b| b.diff.as_mut().unwrap().executable_differs += 1),
            ),
            (
                "difference signature",
                Box::new(|b| {
                    b.diff.as_mut().unwrap().codes.insert("entry:mode@x".into());
                }),
            ),
            (
                "member statuses",
                Box::new(|b| b.diff.as_mut().unwrap().files[0].status = FileStatus::OnlyRebuild),
            ),
            (
                "one side has a member report and the other does not",
                Box::new(|b| b.diff = None),
            ),
        ];
        for (want, edit) in &cases {
            assert_eq!(differs(edit.as_ref()).as_deref(), Some(*want));
        }
        // A member of the same status under another name is a different member.
        let renamed = differs(&|b| {
            let f = &mut b.diff.as_mut().unwrap().files[0];
            f.path = trigon_core::EntryPath::from("package/renamed.js");
        });
        assert_eq!(renamed.as_deref(), Some("member statuses"));
    }

    /// Two comparisons without a member report agree on it; the outcome is still compared.
    #[test]
    fn two_comparisons_without_a_member_report_agree_on_having_none() {
        let mut a = divergent();
        a.diff = None;
        assert_eq!(disagreement(&a, &a.clone()), None);
        let mut b = a.clone();
        b.outcome = trigon_core::Match::Exact;
        assert_eq!(
            disagreement(&a, &b).as_deref(),
            Some("outcome divergent vs exact")
        );
    }
}
