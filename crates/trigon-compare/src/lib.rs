//! One-pass comparison of two artifacts.
//!
//! Six digests per comparison, three per side: the bytes as published, the decompressed container
//! before any stabilizer, and the stabilized re-serialization. The container digest is what answers
//! "same tar, different gzip framing", the most common near-miss for `.crate`, `.tgz` and `.gem`,
//! and it costs one more hasher on a stream that is already flowing.
//!
//! See `docs/05-archive-and-normalization.md` §4.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod diff;
pub mod progression;
mod signature;

pub use diff::{ContentKind, DiffReport, FileDiff, FileStatus};
pub use progression::{Progression, Step};
pub use signature::{matches, signature};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512 as Sha512Hasher};
use trigon_archive::{ArchiveError, Limits, parse, serialize};
use trigon_core::{Digest, Format, Match, MultiDigest, Note, NoteCode, ProfileId, Sha512};
use trigon_stabilize::{Applied, FieldEdit, StabilizerSet, apply_traced};

#[derive(Debug, thiserror::Error)]
pub enum CompareError {
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("the two sides were stabilized under different sets: {0} and {1}")]
    SetMismatch(ProfileId, ProfileId),
}

impl trigon_core::Classify for CompareError {
    fn fault(&self) -> trigon_core::Fault {
        match self {
            // Delegate rather than restate. A malformed artifact is the artifact's fault whether
            // the parser was reached through a comparison or directly, and duplicating the mapping
            // here is how the two answers drift apart.
            CompareError::Archive(e) => e.fault(),
            // Comparing across stabilizer sets is a caller error: the two digests answer different
            // questions, so the comparison was never going to mean anything.
            CompareError::SetMismatch(..) => trigon_core::Fault::Bug,
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            CompareError::Archive(e) => e.is_retryable(),
            CompareError::SetMismatch(..) => false,
        }
    }
}

/// What one artifact looks like at each of the three forms we digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary {
    pub format: Format,
    pub bytes: u64,
    pub raw: MultiDigest,
    /// Present only for a format with an outer codec.
    pub container: Option<MultiDigest>,
    pub stabilized: MultiDigest,
    pub applied: Vec<Applied>,
    pub notes: Vec<Note>,
    pub set: (ProfileId, Digest),
    /// Which pass changed which field of which member, on this side. Ground truth for attribution;
    /// consumed by [`compare`] to annotate the diff and never stored on its own — the merged,
    /// deduplicated result lives on the [`diff::DiffReport`] instead, so the blob carries it once.
    #[serde(skip)]
    pub edits: Vec<FieldEdit>,
}

/// Parse, stabilize and digest one artifact.
pub fn summarize(
    bytes: Vec<u8>,
    format: Format,
    set: &StabilizerSet,
    limits: &Limits,
) -> Result<(Summary, trigon_archive::Archive), CompareError> {
    let raw = multi_digest(&bytes, true);
    let n = bytes.len() as u64;

    let mut notes = Vec::new();
    let mut parsed = parse(bytes, format, limits, &mut notes)?;
    let container = parsed.container_bytes().map(|c| multi_digest(c, false));

    let (applied, edits) = apply_traced(set, &mut parsed.archive);
    // `store_only`: the stabilized stream never passes through a deflate encoder, so no encoder's
    // behaviour can reach a signed digest.
    let stabilized_bytes = serialize(&parsed.archive, true)?;
    let stabilized = multi_digest(&stabilized_bytes, false);

    Ok((
        Summary {
            format,
            bytes: n,
            raw,
            container,
            stabilized,
            applied,
            notes,
            set: (set.id.clone(), set.digest()),
            edits,
        },
        parsed.archive,
    ))
}

fn multi_digest(bytes: &[u8], with_sha512: bool) -> MultiDigest {
    let sha256 = Digest::from_bytes(Sha256::digest(bytes).into());
    // SHA-512 rides along on raw artifact digests only: those are what a third party cross-checks
    // against a registry, and registries publish both. Doubling the others would double the hashing
    // cost of the hottest loop in the system for a value nobody else publishes.
    let sha512 = with_sha512.then(|| Sha512(Sha512Hasher::digest(bytes).into()));
    MultiDigest { sha256, sha512 }
}

/// The result of comparing two artifacts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Comparison {
    pub outcome: Match,
    pub upstream: Summary,
    pub rebuild: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffReport>,
    /// What the comparison observed about the two archives, as opposed to what either side's parse
    /// observed about itself.
    ///
    /// `docs/02-domain-model.md` §5 puts this on `Comparison` and it was missing, which is why the
    /// four `NoteCode` variants about membership — `MemberOnlyInUpstream`, `MemberOnlyInRebuild`,
    /// `MemberContentDiffers`, `ExecutableContentDiffers` — were declared and never constructed.
    /// `ExecutableContentDiffers` is the one that matters: the enum calls it "never benign" and
    /// `is_noteworthy()` promises it reaches a human even on a clean match, and nothing could emit
    /// it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<Note>,
}

impl Comparison {
    /// What two attempts at the same work must share to agree: the outcome, the stabilizer set,
    /// the published artifact's raw digest, and both sides' stabilized digests, hashed under a
    /// domain tag.
    ///
    /// **The rebuild stabilized, never raw.** Two honest builds of one package are rarely
    /// byte-identical — six builds of `Newtonsoft.Json@11.0.1` produced six raw artifacts and one
    /// stabilized digest (`docs/17-backlog.md` B31) — so a digest over the stored report, which
    /// names the rebuilt artifact's raw bytes, would never let a `normalized` run be confirmed.
    /// And **not the outcome alone**, which let a divergence in the nuspec confirm a divergence in
    /// every DLL: two stabilized rebuilds with one digest differ from the published artifact in
    /// exactly the same members and the same ways, because the difference is a function of the two
    /// stabilized archives under the set.
    ///
    /// **The published artifact raw as well**, because it is the question, and the cache key does
    /// not name it. A registry that serves other bytes under one file name — a republished
    /// artifact that differs only in what the set strips, timestamps or a gzip header — gives two
    /// attempts one stabilized upstream digest, and they confirmed each other while each was
    /// about different bytes, and a signed statement names only one of them. Two honest attempts
    /// fetch the same bytes, so this costs a confirmation nothing.
    pub fn agreement(&self) -> Digest {
        let mut h = Sha256::new();
        h.update(b"trigon.agreement.v1\n");
        for part in [
            self.outcome.to_string(),
            self.upstream.set.0.0.clone(),
            self.upstream.set.1.to_hex(),
            self.upstream.raw.sha256.to_hex(),
            self.upstream.stabilized.sha256.to_hex(),
            self.rebuild.stabilized.sha256.to_hex(),
        ] {
            h.update(part.as_bytes());
            h.update(b"\n");
        }
        Digest::from_bytes(h.finalize().into())
    }

    /// "Same tar, different gzip framing". `None` when the format has no outer codec.
    pub fn container_bit_identical(&self) -> Option<bool> {
        Some(self.upstream.container.as_ref()?.sha256 == self.rebuild.container.as_ref()?.sha256)
    }

    /// Every stabilizer that fired on either side.
    pub fn applied(&self) -> Vec<&Applied> {
        self.upstream
            .applied
            .iter()
            .chain(&self.rebuild.applied)
            .collect()
    }

    /// Whether the outcome was capped below `Normalized` by provenance or risk, and why.
    ///
    /// **Gated on the outcome it describes.** This used to report the first pass that *would* cap,
    /// whatever the outcome was, and `trigon verify` prints the answer — so a `divergent` run was
    /// told "capped below `normalized`: cargo-vcs-hash is Builtin at Content risk" when nothing had
    /// been capped and the artifacts simply differed, and an `exact` run was told the same when
    /// `Exact` outranks `Normalized` and nothing was below anything. `cargo-vcs-hash-v2` is
    /// `Content` risk and fires on any crate carrying `.cargo_vcs_info.json`, so that was every
    /// crates.io artifact the tool has ever looked at.
    pub fn cap_reason(&self) -> Option<String> {
        if self.outcome != Match::NormalizedWithCaveats {
            return None;
        }
        self.applied()
            .into_iter()
            .find(|a| caps_normalized(a))
            .map(|a| format!("{} is {:?} at {:?} risk", a.id, a.provenance, a.risk))
    }
}

/// Does this pass hold the verdict below [`Match::Normalized`]?
///
/// The [`Applied`]-shaped spelling of [`trigon_core::caps_normalized`], which is where the rule
/// itself lives — see that function for why it moved down to the crate holding its operands. This
/// is a projection, not a second implementation: if the two ever disagree it is because somebody
/// edited this line, which is why there is nothing here to edit.
pub fn caps_normalized(a: &Applied) -> bool {
    trigon_core::caps_normalized(a.risk, &a.provenance)
}

/// The best verdict a run using these passes could reach — before a single byte is compared.
///
/// Distinct from [`Comparison::cap_reason`], which is gated on an outcome that has already been
/// capped and so says nothing about a run that diverged. This answers the question a reader of a
/// `divergent` run actually has: *if the remaining differences were fixed, what would this get?*
/// For a crate that is `normalized_with_caveats` and not `normalized`, because `cargo-vcs-hash-v2`
/// fires at `Content` risk on every crates.io artifact there has ever been.
///
/// [`Match::Exact`] is not among the answers and that is not an omission: identical bytes are
/// decided before any pass runs, so no ledger of passes can put a ceiling on it.
pub fn ceiling<'a>(applied: impl IntoIterator<Item = &'a Applied>) -> Match {
    trigon_core::ceiling_of(applied.into_iter().map(|a| (a.risk, &a.provenance)))
}

/// Compare two summaries.
///
/// The provenance cap lives here and nowhere else: `Match::Normalized` is unreachable when any
/// applied stabilizer carries non-`Builtin` provenance or a risk tier above `Metadata`. Anything a
/// model touched reaches at most `NormalizedWithCaveats`. See `docs/00-overview.md` §3.1.
pub fn compare(
    upstream: Summary,
    rebuild: Summary,
    upstream_archive: Option<&trigon_archive::Archive>,
    rebuild_archive: Option<&trigon_archive::Archive>,
) -> Result<Comparison, CompareError> {
    if upstream.set.1 != rebuild.set.1 {
        return Err(CompareError::SetMismatch(
            upstream.set.0.clone(),
            rebuild.set.0.clone(),
        ));
    }

    let outcome = if upstream.raw.sha256 == rebuild.raw.sha256 {
        Match::Exact
    } else if upstream.stabilized.sha256 == rebuild.stabilized.sha256 {
        ceiling(upstream.applied.iter().chain(&rebuild.applied))
    } else {
        Match::Divergent
    };

    // A diff report is produced on every run, including a success: it is what makes a verdict
    // auditable, and it is what the UI renders.
    let mut diff = match (upstream_archive, rebuild_archive) {
        (Some(u), Some(r)) => Some(diff::report(u, r)),
        _ => None,
    };

    // The deterministic difference signature, on a divergence only. It is what makes a published
    // divergence reproducible rather than merely accusatory, and it is the one place worth walking
    // both archives a second time for.
    if outcome == Match::Divergent
        && let (Some(d), Some(u), Some(r)) = (diff.as_mut(), upstream_archive, rebuild_archive)
    {
        d.codes = signature::signature(u, r);
    }

    // What each pass changed, merged from both sides. Recorded on every outcome that ran a pass:
    // on a divergence it says which pass owns each residual code, and on a match it is the only
    // record of what the passes did — the difference codes are empty because nothing survived.
    if let Some(d) = diff.as_mut() {
        d.field_edits = diff::merge_edits([&upstream.edits, &rebuild.edits]);
    }

    // Membership notes, from the report the walker already built. One per differing member rather
    // than a count, because "four members differ" is an accusation and a named path is a thing to
    // go and look at — the same reason `codes` exists.
    let mut notes = Vec::new();
    if let Some(d) = &diff {
        for f in &d.files {
            let code = match f.status {
                FileStatus::Identical => continue,
                FileStatus::OnlyUpstream => NoteCode::MemberOnlyInUpstream,
                FileStatus::OnlyRebuild => NoteCode::MemberOnlyInRebuild,
                // Executable first: a difference there is never benign, and saying only that some
                // member differs loses exactly the distinction the verdict turns on.
                FileStatus::Differs if f.kind == ContentKind::Executable => {
                    NoteCode::ExecutableContentDiffers
                }
                FileStatus::Differs => NoteCode::MemberContentDiffers,
            };
            notes.push(Note::at(
                code,
                f.path.clone(),
                match f.status {
                    FileStatus::OnlyUpstream => "in the published artifact and not the rebuild",
                    FileStatus::OnlyRebuild => "in the rebuild and not the published artifact",
                    _ => "the two copies differ",
                },
            ));
        }
    }

    // One event carrying the verdict and the digests it rests on. This is the line a fleet
    // aggregates, so it names the outcome as a string rather than an ordinal: a downstream filter
    // written against an integer breaks the moment an outcome is inserted.
    tracing::info!(
        outcome = %outcome,
        upstream_stabilized = %upstream.stabilized.sha256,
        rebuild_stabilized = %rebuild.stabilized.sha256,
        applied = upstream.applied.len(),
        differs = diff.as_ref().map(|d| d.differs).unwrap_or(0),
        "compared"
    );
    Ok(Comparison {
        outcome,
        upstream,
        rebuild,
        diff,
        notes,
    })
}

/// Convenience: summarize both sides under one set and compare them.
pub fn compare_bytes(
    upstream: Vec<u8>,
    rebuild: Vec<u8>,
    format: Format,
    set: &StabilizerSet,
    limits: &Limits,
) -> Result<Comparison, CompareError> {
    // Kept for the pass-by-pass explanation, which re-parses both from the published bytes. A copy
    // of each, bounded, because `summarize` consumes its input and the archive it returns has been
    // stabilized in place.
    let total = upstream.len() + rebuild.len();
    let explain = (total <= progression::MAX_BYTES).then(|| (upstream.clone(), rebuild.clone()));
    let (us, ua) = summarize(upstream, format, set, limits)?;
    let (rs, ra) = summarize(rebuild, format, set, limits)?;
    let mut c = compare(us, rs, Some(&ua), Some(&ra))?;

    let explained = match explain {
        _ if c.outcome == Match::Exact => Progression::nothing_to_close(),
        Some((u, r)) => {
            // The signature the verdict rests on, which the last step must reproduce. A divergence
            // already carries it; any other outcome skipped computing it.
            let full = match &c.diff {
                Some(d) if c.outcome == Match::Divergent => d.codes.clone(),
                _ => signature(&ua, &ra),
            };
            progression::compute(u, r, format, set, limits, &full)
        }
        None => Progression::omitted(format!(
            "the two artifacts total {} MiB, over the {} MiB bound for re-applying the set one pass \
             at a time",
            total >> 20,
            progression::MAX_BYTES >> 20
        )),
    };
    if let Some(d) = c.diff.as_mut() {
        d.progression = Some(explained);
    }
    Ok(c)
}
