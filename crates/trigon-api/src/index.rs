//! The corpus index: browse and search over the store that already exists.
//!
//! `docs/22-management-layer.md` §2.1 is why this is here rather than in Postgres. Three of the
//! four things the management layer was asked for — browse, search, read a run in detail — are
//! **read-only over data `trigon-store` already holds**. It is `Arc<dyn ObjectStore>`, so the
//! corpus can already live in S3 or GCS, and it already has `list_runs`, `get_run` and
//! content-addressed, re-hashed-on-every-read blobs. Putting a schema first would have meant four
//! weeks with no website, which breaks the rule `18-management-ui.md` §5 sets for itself: *each
//! step is independently useful and none pays off only if the next three land.*
//!
//! So: one `list_runs` and one `get_run` per record at startup, held in memory, refreshed by
//! listing again and fetching only the ids that are new. Run ids are `<unix>-<digest prefix>` and
//! time-ordered by construction, so "newest first" costs a sort of strings and not a fetch of the
//! corpus.
//!
//! **What this is not.** It is not a substitute for the §4 schema. It holds the whole index in
//! memory, it rebuilds from zero on restart, and a second writer is invisible until the next
//! refresh. At the ~255k-run scale `10-scale.md` implies it would want replacing, and stage 2 of
//! the plan replaces it behind the same reader. Until then a laptop and a bucket are enough, and
//! the site exists.

use crate::publication::{Corroboration, Publication, Switches, decide};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use trigon_store::{RunRecord, Store};

/// One row of a listing. Small scalars only — everything large stays a digest.
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub id: String,
    pub target: String,
    /// `npm`, `pypi`, `cargo`, `nuget`… parsed from the purl, because every filter a reader wants
    /// is per-ecosystem and re-parsing a purl per request to answer it is work done 200 times.
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub state: String,
    pub outcome: Option<String>,
    /// How a run that reached no verdict ended: `no-strategy`, `build-failed`, `void`, `failed`.
    ///
    /// **Never merged with `outcome`.** A package that did not reproduce and one we never managed
    /// to test are different findings, and the two fields exist so no renderer has to be trusted to
    /// keep them apart.
    pub terminal: Option<String>,
    /// The failure's stable code, where the run failed. `env/missing-tool`, `src/no-repository`.
    pub failure_code: Option<String>,
    /// Whose fault, as the classifier decided. **Never merged with `outcome`.**
    pub fault: Option<String>,
    pub started: String,
    pub finished: Option<String>,
    pub attempt: u32,
    /// Whether the run is evidence about the package at all — `RunRecord::is_evidence`, hoisted so
    /// a listing cannot get it wrong by reading two fields separately.
    pub evidence: bool,
    pub attested: bool,
    pub publication: Publication,
    /// Digests the detail page will ask for, so the front-end never guesses a URL.
    pub has: Has,
}

/// Which evidence this run left behind. Presence, not bytes.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Has {
    pub comparison: bool,
    pub build_log: bool,
    pub network_transcript: bool,
    pub strategy: bool,
    pub artifacts: bool,
}

/// How a listing was filtered, and what it cost.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Page {
    pub rows: Vec<Entry>,
    /// Rows matching the filter, before paging.
    pub total: usize,
    /// Rows the publication gate removed for this principal. **Reported, never silent**: a page
    /// that quietly shows two thirds of a corpus is a page whose denominator is a lie.
    pub withheld: usize,
    /// The id to pass as `cursor` for the next page, or absent at the end.
    pub next: Option<String>,
}

/// The two denominators, kept apart.
///
/// `18-management-ui.md` §3 is the whole argument: *a package that did not reproduce and a build we
/// could not run are different findings*, and a single "success rate" merges them. So this type has
/// no total and no percentage. It has counts, and whoever renders them has to decide which
/// denominator they meant — which is the decision the merge exists to hide.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub runs: usize,
    /// Runs that are evidence about a package: they reached a verdict and no guard tripped.
    pub evidence: usize,
    /// Of those, by outcome. A string key, never an ordinal ([ADR-0002]).
    ///
    /// [ADR-0002]: ../../../docs/adr/0002-four-match-outcomes.md
    pub by_outcome: BTreeMap<String, usize>,
    /// Runs that never became evidence, by whose fault they were. This is the *other* denominator,
    /// and it is deliberately not summed with the one above.
    pub by_fault: BTreeMap<String, usize>,
    /// Runs the gate keeps from an anonymous reader, by reason.
    pub by_withheld: BTreeMap<String, usize>,
    pub by_ecosystem: BTreeMap<String, usize>,
    /// The freshest and stalest run in the corpus. A page that does not say how old its data is
    /// invites a reader to assume it is current — and *a stale pass is worse than no data, because
    /// it looks like data*.
    pub newest: Option<String>,
    pub oldest: Option<String>,
}

/// Everything the reader holds, behind one lock.
#[derive(Clone)]
pub struct Index {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
    /// Newest first, which for these ids is reverse lexical order.
    entries: Vec<Entry>,
    /// The full record, kept so a detail request costs no round trip. Records are small; the large
    /// parts of a run are digests.
    records: BTreeMap<String, RunRecord>,
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Index {
    /// Read the index, recovering from a poisoned lock rather than propagating the poison.
    ///
    /// **`.read().unwrap()` was a way for one bug to become a permanently broken server.** A
    /// `std::sync` lock is poisoned when a thread panics while holding it, and every later
    /// `unwrap` on it panics too — so a single panic under the write lock in `refresh` would make
    /// every subsequent request fail for the life of the process. A reader would call that a crash,
    /// and they would be right to.
    ///
    /// Poison is the correct default for data whose invariants a panic could have broken. This is
    /// a **cache**: entries derived from records that are still on disk, rebuilt wholesale on the
    /// next refresh. The worst a half-written one costs is a stale row until then, which is cheaper
    /// by a wide margin than refusing to serve anything ever again.
    fn read_or_recover(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|poisoned| {
            tracing::warn!(
                "the index lock was poisoned by an earlier panic; serving the entries it holds. \
                 They are rebuilt from the store on the next refresh."
            );
            poisoned.into_inner()
        })
    }

    fn write_or_recover(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn new() -> Self {
        Index {
            inner: Arc::new(RwLock::new(Inner::default())),
        }
    }

    /// Read every run the store holds and build the index.
    ///
    /// Fetches each record once. A store with a run that fails to deserialize is not a store that
    /// fails to serve: the id is skipped, a warning names it, and every other run stays readable.
    /// A corpus is the one place where one bad record must not take the page down, because the bad
    /// record is often exactly what somebody came to look at.
    pub async fn refresh(&self, store: &Store, switches: Switches) -> Result<usize, String> {
        let ids = store
            .list_runs()
            .await
            .map_err(|e| format!("listing runs: {e}"))?;

        let known: Vec<String> = {
            let g = self.read_or_recover();
            ids.iter()
                .filter(|id| !g.records.contains_key(*id))
                .cloned()
                .collect()
        };

        let mut fetched: Vec<RunRecord> = Vec::with_capacity(known.len());
        for id in &known {
            match store.get_run(id).await {
                Ok(r) => fetched.push(r),
                Err(e) => {
                    tracing::warn!(run = %id, error = %e, "skipping an unreadable run record")
                }
            }
        }
        let added = fetched.len();

        let mut g = self.write_or_recover();
        for r in fetched {
            g.records.insert(r.id.clone(), r);
        }
        g.entries = build(&g.records, switches);
        Ok(added)
    }

    pub fn get(&self, id: &str) -> Option<RunRecord> {
        self.read_or_recover().records.get(id).cloned()
    }

    pub fn entry(&self, id: &str) -> Option<Entry> {
        self.read_or_recover()
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    /// Every record, cloned.
    ///
    /// For the views that fold over the whole corpus rather than paging it — the failure clusters,
    /// chiefly. Cloned rather than handed out behind the lock, because a caller holding the read
    /// guard while it does its own work is how a refresh comes to block on a page render.
    pub fn records(&self) -> Vec<RunRecord> {
        self.read_or_recover().records.values().cloned().collect()
    }

    /// The newest run for one target, or `None` where there is no run at all.
    ///
    /// Newest wins because a later run was made under a later stabilizer set and is the current
    /// answer. `None` is "never checked", which is a different thing from every status a record
    /// can carry and is why this returns an `Option` rather than a default.
    pub fn newest_for(&self, target: &str) -> Option<RunRecord> {
        self.read_or_recover()
            .records
            .values()
            .filter(|r| r.target == target)
            .max_by(|a, b| a.started.cmp(&b.started))
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.read_or_recover().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Filter, gate, and page. In that order, which is the order that keeps the counts honest.
    ///
    /// The gate runs *after* the filter so `withheld` counts rows that matched what the reader
    /// asked for and were then held back — which is the number they need — rather than every
    /// withheld row in the corpus, which tells them nothing about their query.
    pub fn page(&self, q: &Query, public: bool) -> Page {
        let g = self.read_or_recover();
        let matched: Vec<&Entry> = g.entries.iter().filter(|e| q.matches(e)).collect();
        let total = matched.len();

        let visible: Vec<&Entry> = if public {
            matched
                .into_iter()
                .filter(|e| e.publication.is_public())
                .collect()
        } else {
            matched
        };
        let withheld = total - visible.len();

        let start = match &q.cursor {
            Some(c) => visible
                .iter()
                .position(|e| &e.id == c)
                .map(|i| i + 1)
                .unwrap_or(0),
            None => 0,
        };
        let limit = q.limit.clamp(1, 500);
        let rows: Vec<Entry> = visible
            .iter()
            .skip(start)
            .take(limit)
            .map(|e| (*e).clone())
            .collect();
        let next = (start + rows.len() < visible.len())
            .then(|| rows.last().map(|e| e.id.clone()))
            .flatten();

        Page {
            rows,
            total,
            withheld,
            next,
        }
    }

    pub fn stats(&self, public: bool) -> Stats {
        let g = self.read_or_recover();
        let mut s = Stats::default();
        for e in &g.entries {
            if public && !e.publication.is_public() {
                *s.by_withheld
                    .entry(
                        e.publication
                            .because()
                            .map(|w| w.key().to_string())
                            .unwrap_or_else(|| "unknown".into()),
                    )
                    .or_default() += 1;
                continue;
            }
            s.runs += 1;
            *s.by_ecosystem.entry(e.ecosystem.clone()).or_default() += 1;
            if e.evidence {
                s.evidence += 1;
                if let Some(o) = &e.outcome {
                    *s.by_outcome.entry(o.clone()).or_default() += 1;
                }
            } else if let Some(f) = &e.fault {
                // The other denominator. Never added to the one above.
                *s.by_fault.entry(f.clone()).or_default() += 1;
            } else if let Some(t) = &e.terminal {
                // A `no-strategy` is a scope statement with no fault attached, and filing it as
                // `unclassified` would say nobody had named the cause when somebody had.
                *s.by_fault.entry(t.clone()).or_default() += 1;
            } else {
                *s.by_fault.entry("unclassified".into()).or_default() += 1;
            }
            if s.newest.is_none() {
                s.newest = Some(e.started.clone());
            }
            s.oldest = Some(e.started.clone());
        }
        s
    }
}

/// What a listing was asked for.
#[derive(Clone, Debug, Default)]
pub struct Query {
    pub ecosystem: Option<String>,
    pub outcome: Option<String>,
    pub fault: Option<String>,
    /// Substring of the package name or the failure code, lowercased. Postgres trigram is stage 2;
    /// at this size a scan over an in-memory vector is faster than the round trip would be.
    pub q: Option<String>,
    /// `evidence`, `failed`, or absent. The two denominators as a filter, named rather than
    /// numbered, so a caller cannot ask for "the successes" and get a merged set.
    pub kind: Option<String>,
    pub cursor: Option<String>,
    pub limit: usize,
}

impl Query {
    fn matches(&self, e: &Entry) -> bool {
        if let Some(x) = &self.ecosystem
            && &e.ecosystem != x
        {
            return false;
        }
        if let Some(x) = &self.outcome
            && e.outcome.as_deref() != Some(x.as_str())
        {
            return false;
        }
        if let Some(x) = &self.fault
            && e.fault.as_deref() != Some(x.as_str())
        {
            return false;
        }
        match self.kind.as_deref() {
            Some("evidence") if !e.evidence => return false,
            Some("failed") if e.evidence => return false,
            _ => {}
        }
        if let Some(x) = &self.q {
            let hay = format!(
                "{} {} {} {}",
                e.target,
                e.failure_code.as_deref().unwrap_or(""),
                e.outcome.as_deref().unwrap_or(""),
                e.terminal.as_deref().unwrap_or("")
            )
            .to_ascii_lowercase();
            if !hay.contains(&x.to_ascii_lowercase()) {
                return false;
            }
        }
        true
    }
}

/// Turn records into rows, running the publication gate over the whole set at once.
///
/// The gate needs a fact about a *set* — how many other attempts at the same `cache_key` agreed —
/// so it cannot be computed one record at a time. That is why this is a function over the map
/// rather than a method on `Entry`.
fn build(records: &BTreeMap<String, RunRecord>, switches: Switches) -> Vec<Entry> {
    // `cache_key -> (outcome -> count)`. A record with no cache key corroborates nothing, including
    // itself: two runs that cannot be shown to be attempts at the same work are not a confirmation,
    // and treating a missing key as a match would turn the absence of evidence into evidence.
    let mut attempts: BTreeMap<&str, BTreeMap<&str, u32>> = BTreeMap::new();
    for r in records.values() {
        if let (Some(k), Some(o)) = (r.cache_key.as_deref(), r.outcome.as_deref()) {
            *attempts.entry(k).or_default().entry(o).or_default() += 1;
        }
    }

    let mut out: Vec<Entry> = records
        .values()
        .map(|r| {
            let c = corroboration(r, &attempts);
            let (eco, name, version) = split_purl(&r.target);
            Entry {
                id: r.id.clone(),
                target: r.target.clone(),
                ecosystem: eco,
                name,
                version,
                state: format!("{:?}", r.state).to_ascii_lowercase(),
                outcome: r.outcome.clone(),
                terminal: r.terminal.clone(),
                failure_code: r.failure.as_ref().map(|f| f.code.to_string()),
                fault: r
                    .failure
                    .as_ref()
                    .map(|f| format!("{:?}", f.fault).to_ascii_lowercase()),
                started: r.started.clone(),
                finished: r.finished.clone(),
                attempt: r.attempt,
                evidence: r.is_evidence(),
                attested: !r.attestations.is_empty(),
                publication: decide(r, c, switches),
                has: Has {
                    comparison: r.comparison.is_some(),
                    build_log: r.build_log.is_some(),
                    network_transcript: r.network_transcript.is_some(),
                    strategy: r.strategy.is_some(),
                    artifacts: r.upstream.stored,
                },
            }
        })
        .collect();
    // Newest first. These ids lead with unix seconds, so reverse lexical order is reverse
    // chronological — the same property `Store::list_runs` relies on, for the same reason.
    out.sort_by(|a, b| b.id.cmp(&a.id));
    out
}

fn corroboration(r: &RunRecord, attempts: &BTreeMap<&str, BTreeMap<&str, u32>>) -> Corroboration {
    let (Some(k), Some(o)) = (r.cache_key.as_deref(), r.outcome.as_deref()) else {
        return Corroboration::default();
    };
    let Some(by_outcome) = attempts.get(k) else {
        return Corroboration::default();
    };
    Corroboration {
        agreeing_attempts: by_outcome.get(o).copied().unwrap_or(0),
        disagreeing_attempts: by_outcome
            .iter()
            .filter(|(other, _)| **other != o)
            .map(|(_, n)| *n)
            .sum(),
        // From the record, where the run path writes it: the fact lives in the comparison blob
        // and the index does not fetch blobs. `None` on a record written before the field existed
        // reaches the gate as `None` and is treated as an unevaluated safeguard — which is what
        // the previous `false` claimed to mean and could not, being a `bool`.
        non_builtin_stabilizer: r.non_builtin_stabilizer,
    }
}

/// `pkg:npm/left-pad@1.3.0` → `("npm", "left-pad", "1.3.0")`.
///
/// Tolerant on purpose: a purl this cannot parse still produces a row, with the whole string as the
/// name. A corpus browser that drops records it cannot classify hides exactly the records somebody
/// came to look at.
fn split_purl(purl: &str) -> (String, String, String) {
    let rest = purl.strip_prefix("pkg:").unwrap_or(purl);
    let (eco, rest) = rest.split_once('/').unwrap_or(("unknown", rest));
    let (name, version) = rest.rsplit_once('@').unwrap_or((rest, ""));
    (eco.to_string(), name.to_string(), version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trigon_store::{ArtifactRef, Environment, RunState};

    fn rec(id: &str, target: &str, outcome: Option<&str>, key: Option<&str>) -> RunRecord {
        let mut r = RunRecord::new(
            id,
            target,
            ArtifactRef {
                name: "a.tgz".into(),
                sha256: trigon_core::Digest::from_bytes([0u8; 32]),
                bytes: 1,
                stored: true,
            },
            Environment {
                base_image: "x@sha256:0".into(),
                derived_image: None,
                egress: "mirror".into(),
                isolation: "podman".into(),
                attestable: true,
                registry_moment: None,
                pin: None,
                guard_manifest: None,
                guarded_members: None,
            },
            "2026-01-01T00:00:00Z",
        );
        r.state = RunState::Done;
        r.outcome = outcome.map(str::to_string);
        r.cache_key = key.map(str::to_string);
        r
    }

    fn index_of(rs: Vec<RunRecord>) -> Index {
        let ix = Index::new();
        {
            let mut g = ix.inner.write().unwrap();
            for r in rs {
                g.records.insert(r.id.clone(), r);
            }
            g.entries = build(&g.records, Switches::default());
        }
        ix
    }

    /// Nothing outside the two recovery helpers takes the lock directly.
    ///
    /// `entry()` was missed when the readers were converted: `rustfmt` had split
    /// `self.inner.read().unwrap()` across four lines, and the edit that fixed the others matched
    /// the single-line form. One accessor kept the poison — and it is the one every run page and
    /// every diff route calls, so the conversion protected everything except the hot path.
    ///
    /// **Whitespace is stripped entirely before matching**, because the first version of this test
    /// normalised runs of whitespace to single spaces and therefore matched
    /// `self.inner\n.write()` but not `self.inner.read()`. A check for a formatting-dependent
    /// mistake that is itself formatting-dependent is not a check.
    #[test]
    fn no_accessor_takes_the_lock_without_recovering_from_poison() {
        let src = include_str!("index.rs");
        let production = src.split("#[cfg(test)]").next().unwrap_or(src);
        let dense: String = production.chars().filter(|c| !c.is_whitespace()).collect();

        for form in ["self.inner.read().unwrap()", "self.inner.write().unwrap()"] {
            assert!(
                !dense.contains(form),
                "an accessor takes the lock with `{form}` rather than through \
                 `read_or_recover`/`write_or_recover`, so one panic anywhere poisons it for good"
            );
        }
        // And the lock is taken in exactly the two helpers, nowhere else.
        assert_eq!(
            dense.matches("self.inner.read()").count()
                + dense.matches("self.inner.write()").count(),
            2,
            "the lock is taken somewhere other than the two recovery helpers"
        );
    }

    /// A poisoned lock keeps serving.
    ///
    /// `std::sync` poisons a lock when a thread panics while holding it, and every later `unwrap`
    /// on it panics too — so one bug anywhere under the write lock would make every subsequent
    /// request fail for the life of the process, which a reader would call a crash and be right to.
    ///
    /// Poison is the right default for data whose invariants a panic may have broken. This is a
    /// cache rebuilt from the store on the next refresh, so serving a possibly-stale entry beats
    /// refusing to serve anything ever again. The test lives here because poisoning requires
    /// holding the guard across the panic, which only this module can arrange.
    #[test]
    fn a_poisoned_lock_keeps_serving() {
        let ix = index_of(vec![rec(
            "1700000001-aa",
            "pkg:npm/a@1",
            Some("exact"),
            None,
        )]);

        let poisoner = ix.clone();
        let joined = std::thread::spawn(move || {
            let _guard = poisoner.inner.write().unwrap();
            panic!("a panic while the index was being rebuilt");
        })
        .join();
        assert!(
            joined.is_err(),
            "the fixture did not panic, so nothing is poisoned"
        );
        assert!(
            ix.inner.read().is_err(),
            "the lock is not poisoned, so this test asserts nothing"
        );

        // And the readers still answer.
        assert_eq!(ix.len(), 1);
        assert_eq!(
            ix.page(
                &Query {
                    limit: 10,
                    ..Default::default()
                },
                false
            )
            .rows
            .len(),
            1
        );
        assert_eq!(ix.stats(false).runs, 1);
        assert!(ix.get("1700000001-aa").is_some());
    }

    #[test]
    fn newest_first_without_reading_a_timestamp() {
        let ix = index_of(vec![
            rec("1700000001-aa", "pkg:npm/a@1", Some("exact"), None),
            rec("1700000009-bb", "pkg:npm/b@1", Some("exact"), None),
            rec("1700000005-cc", "pkg:npm/c@1", Some("exact"), None),
        ]);
        let ids: Vec<String> = ix
            .page(
                &Query {
                    limit: 10,
                    ..Default::default()
                },
                false,
            )
            .rows
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, ["1700000009-bb", "1700000005-cc", "1700000001-aa"]);
    }

    #[test]
    fn a_withheld_row_is_counted_and_not_merely_missing() {
        // The number that keeps a public page's denominator honest. Two single-attempt runs, both
        // withheld by safeguard 1, and the page says so rather than reporting an empty corpus.
        let ix = index_of(vec![
            rec("1700000001-aa", "pkg:npm/a@1", Some("exact"), Some("k1")),
            rec(
                "1700000002-bb",
                "pkg:npm/b@1",
                Some("divergent"),
                Some("k2"),
            ),
        ]);
        let p = ix.page(
            &Query {
                limit: 10,
                ..Default::default()
            },
            true,
        );
        assert_eq!(p.total, 2);
        assert_eq!(p.withheld, 2);
        assert!(p.rows.is_empty());

        let operator = ix.page(
            &Query {
                limit: 10,
                ..Default::default()
            },
            false,
        );
        assert_eq!(operator.rows.len(), 2, "an operator sees their own corpus");
        assert_eq!(operator.withheld, 0);
    }

    #[test]
    fn two_agreeing_attempts_publish_and_two_disagreeing_do_not() {
        let ix = index_of(vec![
            rec("1700000001-aa", "pkg:npm/a@1", Some("exact"), Some("k1")),
            rec("1700000002-ab", "pkg:npm/a@1", Some("exact"), Some("k1")),
            rec(
                "1700000003-ba",
                "pkg:npm/b@1",
                Some("divergent"),
                Some("k2"),
            ),
            rec("1700000004-bb", "pkg:npm/b@1", Some("exact"), Some("k2")),
        ]);
        let p = ix.page(
            &Query {
                limit: 10,
                ..Default::default()
            },
            true,
        );
        let ids: Vec<&str> = p.rows.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["1700000002-ab", "1700000001-aa"]);
        assert_eq!(p.withheld, 2, "the pair that disagreed publishes nothing");
    }

    #[test]
    fn a_missing_cache_key_corroborates_nothing_not_even_itself() {
        // Two runs of the same target with no key are not a confirmation. Treating them as one
        // would turn the absence of evidence into evidence, which is the exact move safeguard 1
        // exists to prevent.
        let ix = index_of(vec![
            rec("1700000001-aa", "pkg:npm/a@1", Some("exact"), None),
            rec("1700000002-ab", "pkg:npm/a@1", Some("exact"), None),
        ]);
        assert_eq!(
            ix.page(
                &Query {
                    limit: 10,
                    ..Default::default()
                },
                true
            )
            .withheld,
            2
        );
    }

    #[test]
    fn the_two_denominators_are_never_summed() {
        // A failed build and a package that did not reproduce are different findings, and `Stats`
        // has no field in which they could be added together.
        let mut failed = rec("1700000003-cc", "pkg:npm/c@1", None, None);
        failed.failure = Some(trigon_core::FailureSignature {
            code: "env/missing-tool".into(),
            subject: Some("dotnet".into()),
            fault: trigon_core::Fault::Infra,
            retryable: false,
            repairable: false,
            evidence: "the line the classifier matched".into(),
        });
        let ix = index_of(vec![
            rec("1700000001-aa", "pkg:npm/a@1", Some("exact"), None),
            failed,
        ]);
        let s = ix.stats(false);
        assert_eq!(s.runs, 2);
        assert_eq!(s.evidence, 1);
        assert_eq!(s.by_outcome.get("exact"), Some(&1));
        assert_eq!(s.by_fault.get("infra"), Some(&1));
        assert_eq!(
            s.by_outcome.values().sum::<usize>() + s.by_fault.values().sum::<usize>(),
            2,
            "the parts account for every run without the type ever adding them"
        );
    }

    #[test]
    fn a_purl_that_does_not_parse_still_produces_a_row() {
        let ix = index_of(vec![rec(
            "1700000001-aa",
            "something-odd",
            Some("exact"),
            None,
        )]);
        let row = &ix
            .page(
                &Query {
                    limit: 10,
                    ..Default::default()
                },
                false,
            )
            .rows[0];
        assert_eq!(row.ecosystem, "unknown");
        assert_eq!(row.name, "something-odd");
    }

    #[test]
    fn search_reaches_the_failure_code_and_not_only_the_name() {
        // The query a person actually types into a corpus browser is a failure code, because that
        // is what a cluster is named by.
        let mut failed = rec("1700000003-cc", "pkg:npm/c@1", None, None);
        failed.failure = Some(trigon_core::FailureSignature {
            code: "env/missing-tool".into(),
            subject: None,
            fault: trigon_core::Fault::Infra,
            retryable: false,
            repairable: false,
            evidence: "the line the classifier matched".into(),
        });
        let ix = index_of(vec![
            rec("1700000001-aa", "pkg:npm/a@1", Some("exact"), None),
            failed,
        ]);
        let p = ix.page(
            &Query {
                q: Some("missing-tool".into()),
                limit: 10,
                ..Default::default()
            },
            false,
        );
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0].id, "1700000003-cc");
    }

    #[test]
    fn paging_walks_the_whole_set_exactly_once() {
        let rs: Vec<RunRecord> = (0..7)
            .map(|i| {
                rec(
                    &format!("17000000{i:02}-x"),
                    &format!("pkg:npm/p{i}@1"),
                    Some("exact"),
                    None,
                )
            })
            .collect();
        let ix = index_of(rs);
        let mut seen: Vec<String> = Vec::new();
        let mut cursor = None;
        loop {
            let p = ix.page(
                &Query {
                    limit: 3,
                    cursor: cursor.clone(),
                    ..Default::default()
                },
                false,
            );
            seen.extend(p.rows.iter().map(|e| e.id.clone()));
            match p.next {
                Some(n) => cursor = Some(n),
                None => break,
            }
        }
        assert_eq!(seen.len(), 7);
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 7, "a row was served twice or skipped");
    }
}
