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

use crate::publication::{Attempt, Corroboration, Publication, Switches, decide, voided};
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

impl Entry {
    /// Whether an anonymous reader reads this row without its outcome: every row the gate does not
    /// call `Published`.
    ///
    /// A `Void` row is shown — "we looked and could not tell, for this reason" is publishable — but
    /// never with its outcome. [`Publication::is_public`] is true for it, and the outcome of an
    /// open-egress divergence is still `divergent`, so a route that filtered on the one and
    /// serialized the other published exactly the accusation safeguard 2 turns into a void.
    ///
    /// A `Withheld` row is not shown at all, but it is still *counted*, per query, so a page's
    /// denominator is honest — and a count of rows matching `?outcome=divergent` is the outcome,
    /// one package at a time. So it is matched as it is read: without one.
    fn hides_outcome(&self, public: bool) -> bool {
        public && self.publication != Publication::Published
    }

    /// The key this row is counted under in `Stats::by_fault`, as the reader is shown it, or
    /// `None` where it is not counted there.
    ///
    /// One function for the count and the filter, because a bar a reader can click promises that
    /// the click lists what the bar counted. The filter compared `fault` alone while the count fell
    /// back to `terminal` and then to `void`, so `no-strategy` and `void` were bars whose click
    /// listed nothing.
    fn fault_bucket(&self, public: bool) -> Option<&str> {
        let hidden = self.hides_outcome(public);
        if self.evidence && !hidden {
            // Counted by outcome, in the other denominator.
            return None;
        }
        match (self.fault.as_deref(), self.terminal.as_deref()) {
            (Some(f), _) => Some(f),
            // A `no-strategy` is a scope statement with no fault attached, and filing it as
            // `unclassified` would say nobody had named the cause when somebody had.
            (None, Some(t)) => Some(t),
            // Named, for the same reason: the gate said why, and the reason is `void`.
            _ if hidden && matches!(self.publication, Publication::Void { .. }) => Some("void"),
            // A withheld verdict. It is no more a failure nobody classified than it is a match,
            // and filing it under one would put a verdict the reader was not shown into a count.
            _ if hidden && self.outcome.is_some() => None,
            _ => Some("unclassified"),
        }
    }

    /// This row as the reader is to be shown it: unchanged for an operator.
    ///
    /// For an anonymous reader a `Void` row keeps everything but its outcome. The row stays, with
    /// `publication` carrying the reason, so the reader is told why there is no verdict rather
    /// than shown a gap; and it is not counted as evidence, because not being evidence about the
    /// package is what void means.
    pub fn shown(mut self, public: bool) -> Entry {
        if self.hides_outcome(public) {
            self.outcome = None;
            self.evidence = false;
        }
        self
    }
}

/// A run's record as the reader is to be shown it, given the gate's decision about it.
///
/// The record-level half of [`Entry::shown`]. `GET /v1/runs/{id}` returns the record beside the
/// entry, and the record says what the comparison found in more places than `outcome`, so for an
/// anonymous reader of a void run everything the rebuilt side, the comparison, or anything done
/// because of what the comparison found produced is removed. `docs/19` §4.3: a void carries "no
/// comparison outcome and no difference data".
///
/// **Every field is named, on purpose.** The first version cleared three fields and left others
/// saying the same thing: `rebuild`, whose digest equals `upstream`'s exactly when the run was
/// `exact`, and whose `stored` flag after `attest --prune` is kept on a divergence and dropped on
/// a match; and the external log's entry for the very statement `attestations` was cleared to
/// hide, a field since removed with the log (ADR-0014). A list of fields to remove misses the next
/// one, so the record is taken apart without `..`, and a field added to `RunRecord` does not
/// compile here until somebody has decided whether an anonymous reader of a void may see it.
///
/// **And the host id, from an anonymous reader of any run.** It is a keyed hash under a key that
/// is in the source, so where it was derived from a hostname anyone can check a guess at the
/// hostname against it, and a hostname is often a person's name — the leak `host_id` exists to
/// prevent. The gate reads the index's own records, never these, so a reader loses nothing by it.
pub fn record_shown(r: RunRecord, publication: Publication, public: bool) -> RunRecord {
    if !public {
        return r;
    }
    let r = RunRecord { host: None, ..r };
    if !matches!(publication, Publication::Void { .. }) {
        return r;
    }
    let RunRecord {
        // Kept: which run, of what, and how far it got.
        id,
        target,
        state,
        started,
        finished,
        attempt,
        cache_key,
        // Kept: what the attempt could reuse and when it began, both settled before anything was
        // built. The machine it ran on is removed above, for every anonymous reader.
        host: _,
        cache,
        // Kept: the facts that establish the void — what tripped, which egress tier, whether a
        // pass somebody wrote applied — which §4.3 says a void carries.
        guard_trips,
        refused_artifact,
        environment,
        non_builtin_stabilizer,
        // Kept: what was built, and from where, and by which Trigon. All of it is decided before
        // the comparison runs.
        strategy,
        strategy_digest,
        trigon_version,
        derivation,
        source,
        instructions,
        declines,
        assumptions,
        confidence,
        timings,
        failure,
        terminal,
        // Kept: the published artifact, which is what a reader holding it looks the run up by —
        // by any of its digests — and what its registry declared about it. All of it is settled
        // at fetch, before anything is built.
        upstream,
        upstream_digests,
        // Kept: digests of blobs this reader is refused by class. A digest is not a verdict, and
        // the class table is where the control on the bytes lives.
        comparison,
        build_log,
        network_transcript,
        // Gone: the verdict itself.
        outcome: _,
        // Gone: a digest over the outcome, the published artifact's digest and both sides'
        // stabilized digests. A reader holding the published artifact can compute its two, and
        // for every match the rebuilt side's is the same, so four guesses at the outcome would
        // find the one this hashes.
        agreement: _,
        // Gone: the rebuilt artifact. See above: its digest and its retention both say the verdict.
        rebuild: _,
        // Gone: named by predicate (`divergence.intoto.json`), pointing at statements
        // `/v1/runs/{id}/attestation` refuses this reader.
        attestations: _,
        // Gone, for the same reason, and because they may name another run's claims besides.
        per_target_attestations: _,
        // Gone: a model's reading of the diff, which is only ever asked of a divergence and so
        // names one by existing.
        diff_opinion: _,
        // Gone: the model exchange. It records every question the run asked, the reading of a
        // divergence and a repair after one among them, so its presence on a run whose recipe
        // needed no model says what the comparison found.
        transcript: _,
        // Gone: what the run cost. It counts the rebuilt artifact's bytes (the difference from
        // `upstream.bytes` is the rebuild's size), the comparison's, and the tokens spent on the
        // two questions above — three measurements of the difference.
        costs: _,
        // Kept: where the void's record was published. It is the `void/v1` record, which says
        // why the run is void and nothing of which way its comparison went, and it is already
        // public, in the evidence repository it names.
        published,
    } = r;
    RunRecord {
        id,
        target,
        state,
        outcome: None,
        guard_trips,
        refused_artifact,
        started,
        finished,
        attempt,
        cache_key,
        agreement: None,
        host: None,
        cache,
        environment,
        strategy,
        strategy_digest,
        trigon_version,
        derivation,
        source,
        instructions,
        upstream,
        upstream_digests,
        rebuild: None,
        comparison,
        build_log,
        timings,
        failure,
        terminal,
        declines,
        assumptions,
        confidence,
        transcript: None,
        network_transcript,
        costs: None,
        attestations: Vec::new(),
        per_target_attestations: Vec::new(),
        non_builtin_stabilizer,
        diff_opinion: None,
        published,
    }
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

    /// The newest run for one target that the gate lets an anonymous reader see, with the gate's
    /// decision about it.
    ///
    /// [`Self::newest_for`] with the gate asked first. A `Withheld` run is passed over as though it
    /// did not exist, so the answer is the newest *older* run the gate releases, or `None`; a
    /// `Void` run is returned, because a void is shown, and it is the caller's job to show it as
    /// one. Ties on `started` go to the larger id, which is what `newest_for`'s walk over the
    /// id-ordered records does, so the two agree whenever the gate withholds nothing.
    pub fn newest_public_for(&self, target: &str) -> Option<(RunRecord, Publication)> {
        let g = self.read_or_recover();
        g.entries
            .iter()
            .filter(|e| e.target == target && e.publication.is_public())
            .max_by(|a, b| a.started.cmp(&b.started).then_with(|| a.id.cmp(&b.id)))
            .and_then(|e| g.records.get(&e.id).map(|r| (r.clone(), e.publication)))
    }

    /// The other attempts at `id`'s work that agree with it — the same cache key, outcome and
    /// agreement digest, none of them void — as the gate counts them.
    ///
    /// For `trigon publish`, which publishes one of two agreeing attempts (`docs/19` §3): a run
    /// whose agreeing attempt is already published is the same finding again, and a second record
    /// for it would be a second current record for one subject. Empty for a run the index does not
    /// hold, a void one, or one with no cache key or no outcome, which agrees with nothing but
    /// itself.
    pub fn agreeing(&self, id: &str) -> Vec<RunRecord> {
        let g = self.read_or_recover();
        // A void run is evidence of nothing, so it confirms nothing and nothing confirms it, as
        // `attempts_by_key` leaves it out of every count.
        let Some(r) = g.records.get(id).filter(|r| voided(r).is_none()) else {
            return Vec::new();
        };
        let attempts = attempts_by_key(&g.records);
        let Some(at_key) = r.cache_key.as_deref().and_then(|k| attempts.get(k)) else {
            return Vec::new();
        };
        at_key
            .iter()
            .filter(|other| other.id != r.id && agrees(r, other) == Some(true))
            .map(|other| (*other).clone())
            .collect()
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
    ///
    /// The filter reads each row as the reader is shown it, though. A void row reaches an
    /// anonymous reader without its outcome, and matching `?outcome=divergent` against the outcome
    /// it was not shown would list it under the word the redaction removed. A withheld row is read
    /// the same way, and for a sharper reason: it is only ever a count, and a count of withheld rows
    /// matching `?q=<package>&outcome=divergent` was 1 where `outcome=exact` was 0 — the accusation
    /// the gate was holding back, named one package at a time. So a withheld row is counted against
    /// what the reader may know of it (its package, its ecosystem, how it failed if it did) and
    /// never selected by its verdict.
    pub fn page(&self, q: &Query, public: bool) -> Page {
        let g = self.read_or_recover();
        let matched: Vec<&Entry> = g.entries.iter().filter(|e| q.matches(e, public)).collect();
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
            .map(|e| (*e).clone().shown(public))
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
                // One total, never broken down by reason. Three reasons — the kill-switch, an image
                // derived outside the boundary, and unknown provenance — are only ever given to a
                // divergence, so a count under any of them is a count of held-back accusations,
                // and on a small corpus the key alone names one. A total is safe because every
                // outcome can be awaiting confirmation.
                *s.by_withheld.entry("withheld".to_string()).or_default() += 1;
                continue;
            }
            s.runs += 1;
            *s.by_ecosystem.entry(e.ecosystem.clone()).or_default() += 1;
            // A void row is counted as the reader is shown it. An anonymous `by_outcome` that
            // counted it under its outcome would publish, as a number, the divergence the row
            // itself no longer carries.
            if e.evidence && !e.hides_outcome(public) {
                s.evidence += 1;
                if let Some(o) = &e.outcome {
                    *s.by_outcome.entry(o.clone()).or_default() += 1;
                }
            } else if let Some(k) = e.fault_bucket(public) {
                // The other denominator. Never added to the one above.
                *s.by_fault.entry(k.to_string()).or_default() += 1;
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
    /// Whether this row matches, read as a reader who is `public` or not is shown it.
    fn matches(&self, e: &Entry, public: bool) -> bool {
        let hidden = e.hides_outcome(public);
        let outcome = if hidden { None } else { e.outcome.as_deref() };
        if let Some(x) = &self.ecosystem
            && &e.ecosystem != x
        {
            return false;
        }
        if let Some(x) = &self.outcome
            && outcome != Some(x.as_str())
        {
            return false;
        }
        // The bucket `Stats::by_fault` counts the row under, so a clicked bar lists what it counted.
        if let Some(x) = &self.fault
            && e.fault_bucket(public) != Some(x.as_str())
        {
            return false;
        }
        let evidence = e.evidence && !hidden;
        match self.kind.as_deref() {
            Some("evidence") if !evidence => return false,
            Some("failed") if evidence => return false,
            _ => {}
        }
        if let Some(x) = &self.q {
            let hay = format!(
                "{} {} {} {}",
                e.target,
                e.failure_code.as_deref().unwrap_or(""),
                outcome.unwrap_or(""),
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
/// The gate needs a fact about a *set* — which other attempts at the same `cache_key` agreed, and
/// where and when they ran — so it cannot be computed one record at a time. That is why this is a
/// function over the map rather than a method on `Entry`.
fn build(records: &BTreeMap<String, RunRecord>, switches: Switches) -> Vec<Entry> {
    let attempts = attempts_by_key(records);
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
                publication: decide(r, &c, switches),
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

/// `cache_key -> the attempts at it that reached an outcome`, which [`corroboration`] counts.
///
/// A record with no cache key corroborates nothing, including itself: two runs that cannot be
/// shown to be attempts at the same work are not a confirmation, and treating a missing key as a
/// match would turn the absence of evidence into evidence. A void attempt is left out too, for the
/// reason it is void: it is evidence of nothing about the package, so it can neither confirm
/// another attempt nor contradict one. Egress is not in the key, and `trigon rebuild` defaults to
/// `open`, so without this an open-egress rebuild would confirm a `mirror-only` one.
fn attempts_by_key(records: &BTreeMap<String, RunRecord>) -> BTreeMap<&str, Vec<&RunRecord>> {
    let mut attempts: BTreeMap<&str, Vec<&RunRecord>> = BTreeMap::new();
    for r in records.values() {
        if let (Some(k), Some(_)) = (r.cache_key.as_deref(), r.outcome.as_deref())
            && voided(r).is_none()
        {
            attempts.entry(k).or_default().push(r);
        }
    }
    attempts
}

fn corroboration(r: &RunRecord, attempts: &BTreeMap<&str, Vec<&RunRecord>>) -> Corroboration {
    // From the record, where the run path writes it: the fact lives in the comparison blob and the
    // index does not fetch blobs. `None` on a record written before the field existed reaches the
    // gate as `None` and is treated as an unevaluated safeguard — which is what the previous
    // `false` claimed to mean and could not, being a `bool`.
    //
    // **Whatever the attempts are.** It is a fact about this run, not about the other attempts at
    // the same work, and it was carried only where there were some to count: a run with no cache
    // key — every run the CLI records — reached the gate as "not known", so `serve` withheld as
    // awaiting confirmation a run `trigon attest` signs as void.
    let own = Corroboration {
        non_builtin_stabilizer: r.non_builtin_stabilizer,
        ..Corroboration::default()
    };
    let (Some(k), Some(_)) = (r.cache_key.as_deref(), r.outcome.as_deref()) else {
        return own;
    };
    let Some(at_key) = attempts.get(k) else {
        return own;
    };
    let mut c = own;
    for other in at_key {
        match agrees(r, other) {
            Some(true) => c.agreeing_attempts.push(Attempt::of(other)),
            Some(false) => c.disagreeing_attempts += 1,
            None => {}
        }
    }
    c
}

/// Whether two attempts at one cache key agree, disagree, or cannot be told apart.
///
/// **By agreement digest, never by outcome alone.** Two runs that both landed on `divergent`
/// agreed on nine letters, whatever each found: a divergence in the nuspec confirmed a divergence
/// in every DLL. Different outcomes disagree whatever else the records say. The same outcome
/// agrees only where both records carry the digest over what the comparison found and it is one
/// digest, and disagrees where they carry two; where either record carries none — every run
/// recorded before the digest existed — nothing can be said, and nothing is counted either way.
/// A run always agrees with itself, which is what makes one attempt a count of one.
fn agrees(r: &RunRecord, other: &RunRecord) -> Option<bool> {
    if r.id == other.id {
        return Some(true);
    }
    if r.outcome != other.outcome {
        return Some(false);
    }
    match (r.agreement, other.agreement) {
        (Some(a), Some(b)) => Some(a == b),
        _ => None,
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
        // Each run on a machine of its own, and runs with one outcome finding one thing, so two
        // attempts at a key with one outcome are a confirmation unless a test says otherwise.
        r.host = Some(format!("machine-id:{id}"));
        r.cache = Some(trigon_store::CacheState::default());
        r.agreement = outcome.map(|o| trigon_store::digest_of(o.as_bytes()));
        r
    }

    /// Every fixture here begins at one instant, so the gate these build asks for no interval
    /// between attempts; the interval is asserted in `publication.rs`, and through this index in
    /// `the_index_holds_a_pair_to_the_confirmation_rules`.
    fn no_interval() -> Switches {
        Switches {
            confirmation: crate::publication::Confirmation {
                interval: std::time::Duration::ZERO,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn index_of(rs: Vec<RunRecord>) -> Index {
        let ix = Index::new();
        {
            let mut g = ix.inner.write().unwrap();
            for r in rs {
                g.records.insert(r.id.clone(), r);
            }
            g.entries = build(&g.records, no_interval());
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
    fn an_anonymous_reader_gets_one_withheld_total_and_no_reason_that_only_a_divergence_has() {
        // A confirmed divergence stopped by the kill-switch, beside an unconfirmed match. Counted
        // by reason, the public stats would say `kill_switch: 1`, and that reason is only ever
        // given to a divergence.
        let ix = Index::new();
        {
            let mut g = ix.inner.write().unwrap();
            for r in [
                rec("1700000001-aa", "pkg:npm/a@1", Some("exact"), Some("k1")),
                rec("1700000002-ba", "pkg:npm/b@1", Some("divergent"), Some("k2")),
                rec("1700000003-bb", "pkg:npm/b@1", Some("divergent"), Some("k2")),
            ] {
                g.records.insert(r.id.clone(), r);
            }
            g.entries = build(
                &g.records,
                Switches {
                    stop_divergences: true,
                    ..no_interval()
                },
            );
            let reasons: Vec<_> = g
                .entries
                .iter()
                .filter_map(|e| e.publication.because().map(|w| w.key()))
                .collect();
            assert!(reasons.contains(&"kill_switch"), "{reasons:?}");
        }
        let s = ix.stats(true);
        assert_eq!(
            s.by_withheld,
            BTreeMap::from([("withheld".to_string(), 3)]),
            "the public count is a total, never a reason"
        );
        assert!(ix.stats(false).by_withheld.is_empty(), "an operator is shown every row");
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
    fn the_index_voids_exactly_the_runs_the_attestor_calls_void() {
        // `trigon attest` asks `publication::voided` of the record alone; `serve` and `publish`
        // ask the index. They must agree, and they did not for a run with no cache key: the
        // index dropped its provenance bit, and withheld as awaiting confirmation a run the
        // attestor signed as void.
        let mut rs = Vec::new();
        let mut n = 0;
        for key in [None, Some("k1")] {
            for outcome in [None, Some("exact"), Some("divergent")] {
                for egress in ["open", "mirror-only"] {
                    for guard in [false, true] {
                        for non_builtin in [None, Some(false), Some(true)] {
                            n += 1;
                            let mut r = rec(&format!("17000{n:05}-x"), "pkg:npm/a@1", outcome, key);
                            r.environment.egress = egress.into();
                            r.non_builtin_stabilizer = non_builtin;
                            if guard {
                                r.guard_trips.push("tripped".into());
                            }
                            rs.push(r);
                        }
                    }
                }
            }
        }
        let ix = index_of(rs.clone());
        for r in &rs {
            let via_index = match ix.entry(&r.id).unwrap().publication {
                Publication::Void { because } => Some(because),
                _ => None,
            };
            assert_eq!(
                crate::publication::voided(r),
                via_index,
                "key={:?} {:?} {} guard={} {:?}",
                r.cache_key,
                r.outcome,
                r.environment.egress,
                !r.guard_trips.is_empty(),
                r.non_builtin_stabilizer
            );
        }
        // The case that disagreed, by name.
        let mut cli = rec("1800000001-cli", "pkg:npm/b@1", Some("exact"), None);
        cli.environment.egress = "mirror-only".into();
        cli.non_builtin_stabilizer = Some(true);
        let ix = index_of(vec![cli]);
        assert_eq!(
            ix.entry("1800000001-cli").unwrap().publication,
            Publication::Void {
                because: crate::publication::Withheld::NonBuiltinStabilizer
            }
        );
    }

    /// `Corroboration::agreeing_attempts` says "whose outcome and agreement digest match", and
    /// this holds `build` to it rather than leaving the two to be read side by side — which is
    /// how the gate came to count agreement on the outcome string for as long as it did
    /// (`docs/17-backlog.md` B31).
    #[test]
    fn corroboration_is_counted_as_its_doc_says() {
        let at = |id: &str, outcome: &str, found: &str| {
            let mut r = rec(id, "pkg:npm/a@1", Some(outcome), Some("k"));
            r.agreement = Some(trigon_store::digest_of(found.as_bytes()));
            r
        };
        let this = at("1700000001-a", "divergent", "the nuspec differs");
        let rs = [
            this.clone(),
            // Same outcome, same finding: agrees.
            at("1700000002-b", "divergent", "the nuspec differs"),
            // Same outcome, another finding: a disagreement, not a confirmation.
            at("1700000003-c", "divergent", "every DLL differs"),
            // Another outcome: a disagreement.
            at("1700000004-d", "exact", "exact"),
            // Same outcome and no digest: recorded before it existed, and counted neither way.
            {
                let mut r = at("1700000005-e", "divergent", "x");
                r.agreement = None;
                r
            },
            // Same outcome, same finding, and void: evidence of nothing, counted neither way.
            {
                let mut r = at("1700000006-f", "divergent", "the nuspec differs");
                r.environment.egress = "open".into();
                r
            },
            // Same finding at another key: another question.
            {
                let mut r = at("1700000007-g", "divergent", "the nuspec differs");
                r.cache_key = Some("other".into());
                r
            },
        ];
        let records: BTreeMap<String, RunRecord> =
            rs.iter().map(|r| (r.id.clone(), r.clone())).collect();
        // Grouped by the function `build` groups by, not by a copy of it here.
        let c = corroboration(&this, &attempts_by_key(&records));
        let agreeing: Vec<&str> = c.agreeing_attempts.iter().map(|a| a.run.as_str()).collect();
        assert_eq!(agreeing, ["1700000001-a", "1700000002-b"]);
        assert_eq!(c.disagreeing_attempts, 2, "c and d");

        // And the index, built the same way, reaches the same verdict about the set: the
        // disagreement withholds, whatever else agreed.
        let ix = index_of(rs.to_vec());
        assert_eq!(
            ix.entry("1700000001-a").unwrap().publication,
            Publication::Withheld {
                because: crate::publication::Withheld::AttemptsDisagree
            }
        );

        // What `publish` asks, so that of two agreeing attempts one is published: the same set,
        // the run itself left out.
        let others: Vec<String> = ix
            .agreeing("1700000001-a")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(others, ["1700000002-b"]);
        assert!(
            ix.agreeing("1700000006-f").is_empty(),
            "a void agrees with nothing"
        );
        assert!(ix.agreeing("no-such-run").is_empty());
    }

    /// A void attempt at a key neither confirms another attempt there nor contradicts it, through
    /// `build`, with the gate `trigon serve` builds when there is no configuration.
    ///
    /// Egress is not in the key and `trigon rebuild` defaults to `open`, so this one clause is what
    /// stops a plain rebuild of a target confirming a `mirror-only` one. It had no test that went
    /// through `build`: the one above grouped the attempts itself, with its own copy of the filter.
    #[test]
    fn a_void_attempt_neither_confirms_nor_contradicts_another_at_its_key() {
        use crate::publication::Withheld;
        let at = |id: &str, host: &str, started: &str| {
            let mut r = rec(id, "pkg:npm/a@1", Some("exact"), Some("k"));
            r.host = Some(host.into());
            r.started = started.into();
            r
        };
        let clean = at("1700000001-a", "machine-id:one", "2026-09-27T10:00:00Z");
        let decided = |other: &RunRecord| {
            let ix = Index::new();
            {
                let mut g = ix.inner.write().unwrap();
                for r in [clean.clone(), other.clone()] {
                    g.records.insert(r.id.clone(), r);
                }
                g.entries = build(&g.records, Switches::default());
            }
            ix.entry(&clean.id).unwrap().publication
        };
        // Another machine, an hour later, finding the same thing: a confirmation, while clean.
        let later = at("1700000002-b", "machine-id:two", "2026-09-27T11:00:00Z");
        assert_eq!(decided(&later), Publication::Published);

        let mut open = later.clone();
        open.environment.egress = "open".into();
        let mut tripped = later.clone();
        tripped
            .guard_trips
            .push("package/index.js arrived from registry.npmjs.org".into());
        for (what, void) in [("at open egress", open), ("whose guard tripped", tripped)] {
            assert_eq!(
                decided(&void),
                Publication::Withheld {
                    because: Withheld::AwaitingConfirmation
                },
                "an attempt {what} confirmed a clean one"
            );
            let mut found_otherwise = void;
            found_otherwise.outcome = Some("divergent".into());
            found_otherwise.agreement = Some(trigon_store::digest_of(b"divergent"));
            assert_eq!(
                decided(&found_otherwise),
                Publication::Withheld {
                    because: Withheld::AwaitingConfirmation
                },
                "an attempt {what} contradicted a clean one"
            );
        }
    }

    /// An anonymous reader is shown no host id, on a published run or a void one, and an operator
    /// is shown it.
    #[test]
    fn an_anonymous_reader_is_shown_no_host_id() {
        let r = rec("1700000001-a", "pkg:npm/a@1", Some("exact"), Some("k"));
        assert!(r.host.is_some());
        let void = Publication::Void {
            because: crate::publication::Withheld::OpenEgress,
        };
        for publication in [Publication::Published, void] {
            assert_eq!(record_shown(r.clone(), publication, true).host, None);
            assert_eq!(record_shown(r.clone(), publication, false).host, r.host);
        }
    }

    /// Through the index, with the gate `trigon serve` builds when there is no configuration: a
    /// second agreeing attempt counts only on another machine and an hour after the first.
    #[test]
    fn the_index_holds_a_pair_to_the_confirmation_rules() {
        use crate::publication::Withheld;
        let pair = |second_host: &str, second_started: &str| {
            let mut first = rec("1700000001-a", "pkg:npm/a@1", Some("exact"), Some("k"));
            first.host = Some("machine-id:one".into());
            first.started = "2026-09-27T10:00:00Z".into();
            let mut second = rec("1700000002-b", "pkg:npm/a@1", Some("exact"), Some("k"));
            second.host = Some(second_host.into());
            second.started = second_started.into();
            let ix = Index::new();
            {
                let mut g = ix.inner.write().unwrap();
                for r in [first, second] {
                    g.records.insert(r.id.clone(), r);
                }
                g.entries = build(&g.records, Switches::default());
            }
            ix.entry("1700000002-b").unwrap().publication
        };
        assert_eq!(
            pair("machine-id:two", "2026-09-27T11:00:00Z"),
            Publication::Published
        );
        assert_eq!(
            pair("machine-id:two", "2026-09-27T10:59:59Z"),
            Publication::Withheld {
                because: Withheld::AttemptsTooClose
            }
        );
        assert_eq!(
            pair("machine-id:one", "2026-09-27T12:00:00Z"),
            Publication::Withheld {
                because: Withheld::SameHost
            }
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
