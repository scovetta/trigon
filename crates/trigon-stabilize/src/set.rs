use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use trigon_archive::{Archive, Body, Entry, EntryKind, RawMeta};
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

/// One field of one member that one pass changed.
///
/// This is the ground truth behind "which pass did what to this file". A pass changes an entry;
/// this records exactly which of the entry's comparable fields moved and which pass moved it,
/// named as the comparator names the same field in a difference code — so a residual `entry:mode@x`
/// or a reconciled `body@x` joins to the pass that wrote it by `(field, path)`. Where the join
/// finds a pass, attribution is proven rather than guessed; where it finds none, no pass touched
/// that field, which is itself worth saying.
///
/// `field` is the code's rule minus its `entry:`/`body` framing: `mode`, `mtime`, `size`,
/// `zip.crc32`, `tar.uid`, `tar.pax.<k>`, or `body`. `path` is the member as the comparator names
/// it — lossy UTF-8, a nested member as `outer!inner`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FieldEdit {
    pub path: String,
    pub field: String,
    pub pass: StabilizerId,
}

/// Exactly the fields [`trigon_compare`]'s `signature::entry` compares, snapshotted so a change to
/// any one can be attributed to the pass that made it. Body is kept apart, in [`BodyWas`]: reading
/// a body the archive still borrows would defeat the copy-on-write model a 2 GB wheel relies on.
///
/// Kept in lockstep with that comparator: a field it compares and this omits is a difference no
/// pass could ever be shown to have caused, and the join would silently attribute it to nothing.
#[derive(Clone)]
struct Fp {
    kind: EntryKind,
    size: u64,
    mtime: Option<i64>,
    mode: u32,
    raw: RawMeta,
}

impl Fp {
    fn of(e: &Entry) -> Self {
        Fp {
            kind: e.kind.clone(),
            size: e.meta.size,
            mtime: e.meta.mtime,
            mode: e.meta.mode,
            raw: e.raw.clone(),
        }
    }
}

/// A body as it stood before an `on_archive` pass, as much of it as telling whether the pass
/// rewrote it takes.
///
/// An entry pass reports each body it rewrote through its own `Touched::bytes`, one entry at a
/// time. An archive pass reports its work for the archive as a whole — `wheel-record-v3`
/// regenerating RECORD, `nupkg-packaging-names` rewriting `_rels/.rels` — and no count of its names
/// the member.
/// So its bodies are compared across it instead, and promotion to `Inline` is not taken for a
/// change: `nupkg-packaging-names` asks for `_rels/.rels` mutably whether or not it finds anything
/// to rewrite.
enum BodyWas {
    /// Still the source's bytes, held by another handle onto the same window rather than a copy. A
    /// body still borrowed afterwards is the one it was; one a pass promoted is compared with the
    /// bytes it borrowed, which are still there.
    Borrowed(Body),
    /// Already in memory, so already read: its digest.
    Inline([u8; 32]),
    /// A nested archive, whose members are attributed at their own level.
    Nested,
}

impl BodyWas {
    fn of(e: &Entry, digests: &mut BodyDigests) -> BodyWas {
        match &e.body {
            Body::Original { src, off, len } => BodyWas::Borrowed(Body::Original {
                src: Arc::clone(src),
                off: *off,
                len: *len,
            }),
            Body::Spilled { file, off, len } => BodyWas::Borrowed(Body::Spilled {
                file: Arc::clone(file),
                off: *off,
                len: *len,
            }),
            Body::Inline(v) => BodyWas::Inline(digests.of(e.ordinal, v)),
            Body::Nested { .. } => BodyWas::Nested,
        }
    }

    /// Whether `e`'s body is other bytes than it was. One that cannot be read on either side is
    /// taken as changed only if it is no longer the same window: a pass cannot have read it either.
    fn changed(&self, e: &Entry, digests: &mut BodyDigests) -> bool {
        match (self, &e.body) {
            (BodyWas::Nested, Body::Nested { .. }) => false,
            (BodyWas::Nested, _) | (_, Body::Nested { .. }) => true,
            (BodyWas::Inline(d), Body::Inline(v)) => digests.fresh(e.ordinal, v) != *d,
            (BodyWas::Inline(d), now) => now
                .bytes()
                .map_or(true, |b| <[u8; 32]>::from(Sha256::digest(&b)) != *d),
            (BodyWas::Borrowed(was), now) if same_window(was, now) => false,
            (BodyWas::Borrowed(was), now) => match (was.bytes(), now.bytes()) {
                (Ok(a), Ok(b)) => a != b,
                _ => true,
            },
        }
    }
}

/// Two handles onto one window of one source: the same bytes, without reading them.
fn same_window(a: &Body, b: &Body) -> bool {
    match (a, b) {
        (
            Body::Original { src, off, len },
            Body::Original {
                src: s,
                off: o,
                len: l,
            },
        ) => Arc::ptr_eq(src, s) && (off, len) == (o, l),
        (
            Body::Spilled { file, off, len },
            Body::Spilled {
                file: f,
                off: o,
                len: l,
            },
        ) => Arc::ptr_eq(file, f) && (off, len) == (o, l),
        _ => false,
    }
}

/// Each `Inline` body's digest, kept from pass to pass so a body in memory is read again only once
/// something may have changed it: an entry pass reporting bytes on it, an archive pass reporting
/// any work, or its buffer moving or changing length.
#[derive(Default)]
struct BodyDigests(std::collections::HashMap<u32, (usize, usize, [u8; 32])>);

impl BodyDigests {
    /// The digest of `v`, from the last time it was read if its buffer is where and as long as it
    /// was then.
    fn of(&mut self, ordinal: u32, v: &[u8]) -> [u8; 32] {
        match self.0.get(&ordinal) {
            Some(&(at, len, d)) if (at, len) == (v.as_ptr() as usize, v.len()) => d,
            _ => self.fresh(ordinal, v),
        }
    }

    /// The digest of `v`, read now: a pass may have rewritten it in place.
    fn fresh(&mut self, ordinal: u32, v: &[u8]) -> [u8; 32] {
        let d: [u8; 32] = Sha256::digest(v).into();
        self.0.insert(ordinal, (v.as_ptr() as usize, v.len(), d));
        d
    }

    fn forget(&mut self, ordinal: u32) {
        self.0.remove(&ordinal);
    }
}

/// Every field name (as the comparator spells it) that differs between two fingerprints of one
/// entry, pushed as an edit attributed to `pass` at `path`.
fn record_field_changes(
    before: &Fp,
    after: &Fp,
    path: &str,
    pass: &StabilizerId,
    out: &mut Vec<FieldEdit>,
) {
    let mut edit = |field: &str| {
        out.push(FieldEdit {
            path: path.to_string(),
            field: field.to_string(),
            pass: pass.clone(),
        });
    };
    if before.kind != after.kind {
        edit("kind");
    }
    if before.size != after.size {
        edit("size");
    }
    if before.mtime != after.mtime {
        edit("mtime");
    }
    if before.mode != after.mode {
        edit("mode");
    }
    match (&before.raw, &after.raw) {
        (RawMeta::Tar(a), RawMeta::Tar(b)) => {
            if a.typeflag != b.typeflag {
                edit("tar.typeflag");
            }
            if a.linkname != b.linkname {
                edit("tar.linkname");
            }
            if a.uid != b.uid {
                edit("tar.uid");
            }
            if a.gid != b.gid {
                edit("tar.gid");
            }
            if a.uname != b.uname {
                edit("tar.uname");
            }
            if a.gname != b.gname {
                edit("tar.gname");
            }
            if a.devmajor != b.devmajor || a.devminor != b.devminor {
                edit("tar.device");
            }
            if a.atime != b.atime {
                edit("tar.atime");
            }
            if a.ctime != b.ctime {
                edit("tar.ctime");
            }
            // Each keyword once: one present on both sides turns up in both key lists, and it is
            // still one field one pass changed, as the comparator's set of codes names it.
            let keys: std::collections::BTreeSet<&String> =
                a.pax.keys().chain(b.pax.keys()).collect();
            for k in keys {
                if a.pax.get(k) != b.pax.get(k) {
                    edit(&format!("tar.pax.{k}"));
                }
            }
        }
        (RawMeta::Zip(a), RawMeta::Zip(b)) => {
            if a.creator_version != b.creator_version {
                edit("zip.creator_version");
            }
            if a.reader_version != b.reader_version {
                edit("zip.reader_version");
            }
            if a.flags != b.flags {
                edit("zip.flags");
            }
            if a.method != b.method {
                edit("zip.method");
            }
            if a.crc32 != b.crc32 {
                edit("zip.crc32");
            }
            if a.extra != b.extra {
                edit("zip.extra");
            }
            if a.comment != b.comment {
                edit("zip.comment");
            }
            if a.external_attrs != b.external_attrs {
                edit("zip.external_attrs");
            }
            if a.internal_attrs != b.internal_attrs {
                edit("zip.internal_attrs");
            }
            if a.dos_datetime != b.dos_datetime {
                edit("zip.dos_datetime");
            }
        }
        _ => edit("raw.format"),
    }
}

/// Run a set over an archive, in stage order, recursing into nested archives.
///
/// Returns only the stabilizers that actually changed something: `applied` drives the provenance cap
/// and the attestation, so a pass that was configured but did no work has no business in either.
#[tracing::instrument(level = "debug", skip(set, archive), fields(profile = %set.id))]
pub fn apply(set: &StabilizerSet, archive: &mut Archive) -> Vec<Applied> {
    stabilize(set, archive, None)
}

/// [`apply`], and additionally the per-field, per-member edits each pass made — the ground truth a
/// comparison joins to its difference codes to say which pass touched which field of which member.
///
/// The edits are the only extra work: the stabilization itself is identical. The fingerprints it
/// diffs are metadata, and a body is read only where it is in memory already — to tell whether an
/// archive pass that reported work rewrote it — never where the archive still borrows it. [`apply`]
/// takes none of them, so the archived set, which runs it, pays for none.
pub fn apply_traced(set: &StabilizerSet, archive: &mut Archive) -> (Vec<Applied>, Vec<FieldEdit>) {
    let mut edits: Vec<FieldEdit> = Vec::new();
    let applied = stabilize(set, archive, Some(&mut edits));
    (applied, edits)
}

fn stabilize(
    set: &StabilizerSet,
    archive: &mut Archive,
    edits: Option<&mut Vec<FieldEdit>>,
) -> Vec<Applied> {
    let cx = Cx::root(archive.format);
    let mut totals: Vec<Touched> = vec![Touched::NONE; set.members.len()];
    run(set, archive, &cx, &[], &mut totals, edits);

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

/// The stabilized-name prefix a nested archive's members carry, matching the comparator's
/// `outer!inner` spelling. Built from the path each entry is descended at, not from `Cx`, so the
/// two never drift.
fn joined(prefix: &[u8], name: &[u8]) -> String {
    let mut p = Vec::with_capacity(prefix.len() + name.len());
    p.extend_from_slice(prefix);
    p.extend_from_slice(name);
    String::from_utf8_lossy(&p).into_owned()
}

fn run(
    set: &StabilizerSet,
    archive: &mut Archive,
    cx: &Cx,
    prefix: &[u8],
    totals: &mut [Touched],
    mut edits: Option<&mut Vec<FieldEdit>>,
) {
    // Depth first: a nested archive is stabilized before the parent re-serializes it, so a parent
    // pass sees the bytes its children will actually produce.
    for i in 0..archive.entries.len() {
        let (name, nested_format) = {
            let e = &archive.entries[i];
            match &e.body {
                Body::Nested { inner, .. } => (e.path.clone(), Some(inner.format)),
                _ => (e.path.clone(), None),
            }
        };
        if let Some(f) = nested_format {
            let child = cx.push(f, name.clone());
            // `outer!inner`, the same key `signature`/`diff` build for a nested member.
            let mut child_prefix = prefix.to_vec();
            child_prefix.extend_from_slice(name.as_bytes());
            child_prefix.push(b'!');
            if let Body::Nested { inner, .. } = &mut archive.entries[i].body {
                run(
                    set,
                    inner,
                    &child,
                    &child_prefix,
                    totals,
                    edits.as_deref_mut(),
                );
            }
        }
    }

    let mut digests = BodyDigests::default();
    for (idx, s) in set.members.iter().enumerate() {
        if !s.applies(cx) {
            continue;
        }
        // Fingerprint every entry before the pass, keyed by `ordinal` — stable across the reorder
        // an `on_archive` pass may perform, where position is not. Only when the edits are wanted.
        let before: Option<std::collections::HashMap<u32, (Fp, BodyWas)>> =
            edits.is_some().then(|| {
                archive
                    .entries
                    .iter()
                    .map(|e| (e.ordinal, (Fp::of(e), BodyWas::of(e, &mut digests))))
                    .collect()
            });

        let mut t = s.on_archive(archive, cx);
        // Which entries the pass rewrote the body of, by ordinal. An archive pass's are found by
        // comparing each body across it, and only when it reported work, as its other edits are.
        let mut body_changed: std::collections::HashSet<u32> = std::collections::HashSet::new();
        if let Some(before) = &before {
            if t.entries > 0 || t.bytes > 0 {
                for e in &archive.entries {
                    if let Some((_, was)) = before.get(&e.ordinal) {
                        if was.changed(e, &mut digests) {
                            body_changed.insert(e.ordinal);
                        }
                    }
                }
            }
        }
        // An entry pass's, from its own `Touched::bytes`, the lossless signal, rather than from
        // re-hashing the bytes it just changed.
        for e in &mut archive.entries {
            let te = s.on_entry(e, cx);
            if te.bytes > 0 {
                body_changed.insert(e.ordinal);
                digests.forget(e.ordinal);
            }
            t.merge(te);
        }
        totals[idx].merge(t);

        let (Some(edits), Some(before)) = (edits.as_deref_mut(), before) else {
            continue;
        };
        if t.entries == 0 && t.bytes == 0 {
            continue;
        }
        let id = s.id();
        for e in &archive.entries {
            let path = joined(prefix, e.path.as_bytes());
            if let Some((b, _)) = before.get(&e.ordinal) {
                record_field_changes(b, &Fp::of(e), &path, &id, edits);
            }
            if body_changed.contains(&e.ordinal) {
                edits.push(FieldEdit {
                    path,
                    field: "body".to_string(),
                    pass: id.clone(),
                });
            }
        }
    }
}
