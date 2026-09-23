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

use std::path::PathBuf;

use anyhow::{Context as _, Result};
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
        let (mut written, mut skipped, mut failed) = (0usize, 0usize, 0usize);
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
                Err(e) => {
                    failed += 1;
                    println!("{id}  failed   {e:#}");
                }
            }
        }
        println!(
            "\n{written} {}, {skipped} skipped, {failed} failed, of {} run(s)",
            if args.dry_run { "would be written" } else { "written" },
            ids.len()
        );
        Ok(())
    })
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
    let (Ok(upstream), Ok(rebuild)) = (
        store.blobs().get(&r.upstream.sha256).await,
        store.blobs().get(&rebuilt.sha256).await,
    ) else {
        return Ok(Done::Skipped(
            "one of the two artifacts is not in the store (pruned, or never stored)".into(),
        ));
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
        // Loud, and not written. The same bytes under the same set should give the same verdict;
        // when they do not, that is a finding about the comparator, not a gap to paper over.
        anyhow::bail!("re-derivation disagrees with the recorded comparison: {why}");
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
