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

    /// Narrow a set to a chosen list of passes.
    ///
    /// `enable` of `["all"]` keeps everything and `["none"]` keeps nothing; otherwise it names the
    /// passes to keep. `disable` then removes from whatever survived. This mirrors the reference
    /// implementation's flags so a differential run can bisect a digest mismatch down to one pass
    /// rather than to "somewhere in the pipeline".
    pub fn filtered(&self, enable: &[String], disable: &[String]) -> StabilizerSet {
        let keep_all = enable.iter().any(|e| e == "all");
        let keep_none = enable.len() == 1 && enable[0] == "none";
        let drop_all = disable.iter().any(|d| d == "all");

        let members = self
            .members
            .iter()
            .filter(|m| {
                let id = m.id().as_str().to_string();
                let enabled = keep_all || (!keep_none && enable.contains(&id));
                let disabled = drop_all || disable.contains(&id);
                enabled && !disabled
            })
            .cloned()
            .collect();
        StabilizerSet::new(self.id.as_str(), members)
    }

    pub fn ids(&self) -> Vec<StabilizerId> {
        self.members.iter().map(|m| m.id()).collect()
    }
}

/// One member of a set, as the manifest records it.
///
/// Exactly the four fields the digest is computed over, in the same spelling. That is the point: a
/// reader can recompute the digest from the manifest and confirm it names the set it claims to. A
/// manifest carrying prettier or richer fields than the digest covers would be a document nobody
/// could check.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SetMember {
    pub id: String,
    pub stage: String,
    pub risk: String,
    /// `builtin`, `human:<reviewer>` or `model:<id>:<run>`. A string rather than a structure because
    /// it is a digest input, and a structure invites a second serialization to disagree with it.
    pub provenance: String,
}

/// What a stabilizer set is, in a form that outlives the binary that produced it.
///
/// `trigon verify` refuses to compare across differing set digests and re-derives instead, which is
/// correct and leaves a verifier holding an old attestation with nothing to go on: they get a
/// digest that does not match theirs and no way to learn what it was. This is the smallest thing
/// that fixes it. It does not let them *run* the old set — that wants the WASM component of
/// `docs/09-attestations.md` §7.1 — but it tells them precisely what the claim was made under, and
/// it is self-verifying, so it cannot quietly describe a different set than the one it names.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SetManifest {
    pub id: String,
    /// The set digest, as hex. Recomputable from `members` alone.
    pub digest: String,
    pub members: Vec<SetMember>,
}

impl SetManifest {
    /// Recompute the digest from the members and check it against the one recorded.
    ///
    /// The reason to publish a manifest rather than a list: a reader can tell a faithful record of
    /// a set from a document that merely claims a digest.
    pub fn self_consistent(&self) -> bool {
        let mut rows: Vec<String> = self
            .members
            .iter()
            .map(|m| format!("{}|{}|{}|{}", m.id, m.stage, m.risk, m.provenance))
            .collect();
        rows.sort();
        let mut h = Sha256::new();
        for r in rows {
            h.update(r.as_bytes());
            h.update(b"\n");
        }
        Digest::from_bytes(h.finalize().into()).to_hex() == self.digest
    }
}

impl StabilizerSet {
    /// The set as a publishable document.
    pub fn manifest(&self) -> SetManifest {
        SetManifest {
            id: self.id.as_str().to_string(),
            digest: self.digest().to_hex(),
            members: self
                .members
                .iter()
                .map(|m| SetMember {
                    id: m.id().to_string(),
                    stage: format!("{:?}", m.stage()),
                    risk: format!("{:?}", m.risk()),
                    provenance: provenance_tag(&m.provenance()),
                })
                .collect(),
        }
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
#[tracing::instrument(level = "debug", skip(set, archive), fields(profile = %set.id))]
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
        .inspect(|a: &Applied| {
            tracing::debug!(
                stabilizer = %a.id,
                risk = ?a.risk,
                entries = a.entries_touched,
                bytes = a.bytes_changed,
                "applied"
            );
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
                Body::Nested { inner, .. } => (e.path.clone(), Some(inner.format)),
                _ => (e.path.clone(), None),
            }
        };
        if let Some(f) = nested_format {
            let child = cx.push(f, path);
            if let Body::Nested { inner, .. } = &mut archive.entries[i].body {
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
