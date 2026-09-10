use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use trigon_archive::{Archive, Body};
use trigon_core::{Digest, ProfileId, Provenance, RiskTier, StabilizerId};

use crate::{Cx, Stabilizer};

/// What one pass changed. Explicit, because a signed digest should not depend on a convention that
/// every stabilizer author has to remember.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Touched {
    pub entries: u32,
    pub bytes: u64,
}

impl Touched {
    pub const NONE: Touched = Touched {
        entries: 0,
        bytes: 0,
    };

    pub const fn entry() -> Touched {
        Touched {
            entries: 1,
            bytes: 0,
        }
    }

    pub const fn entry_bytes(n: u64) -> Touched {
        Touched {
            entries: 1,
            bytes: n,
        }
    }

    fn merge(&mut self, o: Touched) {
        self.entries += o.entries;
        self.bytes += o.bytes;
    }
}

/// A named, ordered, content-digested collection of stabilizers.
#[derive(Debug)]
pub struct StabilizerSet {
    pub id: ProfileId,
    pub members: Vec<Arc<dyn Stabilizer>>,
}

impl StabilizerSet {
    pub fn new(id: impl Into<String>, mut members: Vec<Arc<dyn Stabilizer>>) -> Self {
        members.sort_by_key(|m| (m.stage(), m.id()));
        Self {
            id: ProfileId::new(id),
            members,
        }
    }

    /// SHA-256 over sorted `(id, stage, risk, provenance)`.
    ///
    /// A content digest rather than a hand-bumped integer, because the integer is a promise someone
    /// forgets to keep and an out-of-band edit would then reuse cache entries that no longer apply.
    pub fn digest(&self) -> Digest {
        let mut rows: Vec<String> = self
            .members
            .iter()
            .map(|m| {
                format!(
                    "{}|{:?}|{:?}|{}",
                    m.id(),
                    m.stage(),
                    m.risk(),
                    provenance_tag(&m.provenance())
                )
            })
            .collect();
        rows.sort();
        let mut h = Sha256::new();
        for r in rows {
            h.update(r.as_bytes());
            h.update(b"\n");
        }
        Digest::from_bytes(h.finalize().into())
    }

    pub fn ids(&self) -> Vec<StabilizerId> {
        self.members.iter().map(|m| m.id()).collect()
    }
}

fn provenance_tag(p: &Provenance) -> String {
    match p {
        Provenance::Builtin => "builtin".into(),
        Provenance::Human { reviewer } => format!("human:{reviewer}"),
        Provenance::Model { model_id, run_id } => format!("model:{model_id}:{run_id}"),
    }
}

/// A stabilizer that fired, and what it cost the claim.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Applied {
    pub id: StabilizerId,
    pub risk: RiskTier,
    pub provenance: Provenance,
    pub entries_touched: u32,
    pub bytes_changed: u64,
}

/// Run a set over an archive, in stage order, recursing into nested archives.
///
/// Returns only the stabilizers that actually changed something: `applied` drives the provenance cap
/// and the attestation, so a pass that was configured but did no work has no business in either.
pub fn apply(set: &StabilizerSet, archive: &mut Archive) -> Vec<Applied> {
    let cx = Cx::root(archive.format);
    let mut totals: Vec<Touched> = vec![Touched::NONE; set.members.len()];
    run(set, archive, &cx, &mut totals);

    set.members
        .iter()
        .zip(totals)
        .filter(|(_, t)| t.entries > 0 || t.bytes > 0)
        .map(|(m, t)| Applied {
            id: m.id(),
            risk: m.risk(),
            provenance: m.provenance(),
            entries_touched: t.entries,
            bytes_changed: t.bytes,
        })
        .collect()
}

fn run(set: &StabilizerSet, archive: &mut Archive, cx: &Cx, totals: &mut [Touched]) {
    // Depth first: a nested archive is stabilized before the parent re-serializes it, so a parent
    // pass sees the bytes its children will actually produce.
    for i in 0..archive.entries.len() {
        let (path, nested_format) = {
            let e = &archive.entries[i];
            match &e.body {
                Body::Nested(inner) => (e.path.clone(), Some(inner.format)),
                _ => (e.path.clone(), None),
            }
        };
        if let Some(f) = nested_format {
            let child = cx.push(f, path);
            if let Body::Nested(inner) = &mut archive.entries[i].body {
                run(set, inner, &child, totals);
            }
        }
    }

    for (idx, s) in set.members.iter().enumerate() {
        if !s.applies(cx) {
            continue;
        }
        let mut t = s.on_archive(archive, cx);
        for e in &mut archive.entries {
            t.merge(s.on_entry(e, cx));
        }
        totals[idx].merge(t);
    }
}
