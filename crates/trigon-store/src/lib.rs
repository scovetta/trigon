//! Where a run's evidence lives once the run is over.
//!
//! Scoped to what makes the **attestor a separate process** (`docs/09-attestations.md` §6): the
//! sandbox writes blobs and a run record, the attestor reads them by hash, re-derives the
//! equivalence claim, and signs. It executes nothing the sandbox produced and needs no access to
//! the machine that produced it.
//!
//! Deliberately not a database. `docs/10-scale.md` §4 specifies Postgres tables for `runs`,
//! `verdicts` and `rollups`, and those exist to make a *fleet* legible — the failure-cluster view,
//! the cost view, the queue. None of that is needed to sign a statement, and building a schema
//! before there is a fleet to put in it means maintaining one whose shape is a guess. The layout
//! here is the one `docs/09` §7 already specifies, which is content-addressed files:
//!
//! ```text
//! blobs/sha256/<aa>/<digest>
//! runs/<run-id>.json
//! attestations/<eco>/<name>/<version>/<artifact>/<predicate>.intoto.json
//! ```
//!
//! **The queue arrived with M4** and lives in [`queue`], behind a feature flag, for the reason
//! ADR-0005 gives: `enqueue` and the run-state write must share one `sqlx::Transaction`, and a
//! `trigon-queue` crate would put a boundary between them that buys nothing and costs the
//! transaction. The content-addressed layout above is unchanged and still holds everything a
//! signature is about; the database holds pointers, small scalars, and the jobs.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod blobs;
#[cfg(feature = "queue")]
pub mod queue;
mod record;

pub use blobs::Blobs;
#[cfg(feature = "queue")]
pub use queue::{Backend, HostBudget, Job, JobState, NewJob, Principal, Queue, Requested, Tier};
pub use record::{ArtifactRef, Costs, Environment, PinEvidence, RunRecord, RunState, Tokens};

use std::path::Path;
use std::sync::Arc;

use futures::TryStreamExt as _;
use object_store::{ObjectStore, ObjectStoreExt as _, PutPayload, path::Path as ObjPath};
use trigon_core::{Classify, Fault};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(
        "the store returned bytes that do not match the digest they were asked for: asked {asked}, found {found}"
    )]
    Corrupt { asked: String, found: String },

    #[error("no run `{0}` in this store")]
    NoSuchRun(String),

    /// A record the store cannot address and list back under the same name.
    #[error("{0}")]
    Malformed(String),

    #[error("no stabilizer set `{0}` in this store")]
    NoSuchSet(String),

    #[error(
        "the manifest for stabilizer set {digest} does not recompute to the digest it claims. It \
         describes some other set, or it has been edited."
    )]
    InconsistentSet { digest: String },

    #[error(
        "run `{0}` has no signed attestation, and pruning its artifacts would destroy the evidence \
         a signature is supposed to be about. Attest first, or delete the run."
    )]
    NotAttested(String),

    #[error(transparent)]
    Object(#[from] object_store::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Classify for StoreError {
    fn fault(&self) -> Fault {
        match self {
            // Bytes that do not match their own address mean something wrote to the store that
            // should not have, or the store lost data. Either way somebody should look now.
            StoreError::Corrupt { .. } => Fault::Bug,
            StoreError::NotAttested(_) => Fault::Policy,
            // A manifest that does not describe its own digest is the same class of problem as a
            // blob that does not hash to its own address: something wrote a document that cannot be
            // true.
            StoreError::InconsistentSet { .. } => Fault::Bug,
            StoreError::NoSuchRun(_) | StoreError::NoSuchSet(_) | StoreError::Json(_) => Fault::Bug,
            // A record this store cannot address is a caller handing it something it should not
            // have: our own ids are `<unix>-<digest prefix>`.
            StoreError::Malformed(_) => Fault::Bug,
            StoreError::Object(_) | StoreError::Io(_) => Fault::Infra,
        }
    }

    /// Every variant named, never a catch-all.
    ///
    /// This was `matches!(self, Object | Io)` over an eight-variant enum, so six variants took
    /// their answer from a wildcard nobody chose and a new variant would silently join them. The
    /// direction matters in both ways: retrying a policy refusal forever is a loop, and refusing to
    /// retry a transient fault throws away a run that would have succeeded.
    fn is_retryable(&self) -> bool {
        match self {
            // The disk or the network, which is what retrying is for.
            StoreError::Object(_) | StoreError::Io(_) => true,
            // Deterministic: the same bytes hash the same way, the same manifest recomputes the
            // same digest, and the same id is addressable or is not. Asking twice asks the same
            // question.
            StoreError::Corrupt { .. }
            | StoreError::InconsistentSet { .. }
            | StoreError::Malformed(_)
            | StoreError::Json(_) => false,
            // A record that is absent now may be present later, but nothing this process does will
            // make it so — the caller named a run that was never written.
            StoreError::NoSuchRun(_) | StoreError::NoSuchSet(_) => false,
            // A refusal we issued on purpose answers the same way every time.
            StoreError::NotAttested(_) => false,
        }
    }
}

/// The filename a predicate type is filed under.
///
/// `https://trigon.dev/equivalence/v1` is `equivalence`, not `v1`. The last segment of these URLs is
/// the schema version, which every predicate shares, so naming files by it would put every
/// attestation for one artifact at the same path and each would overwrite the last.
fn predicate_name(predicate: &str) -> &str {
    let mut segments = predicate.rsplit('/');
    let last = segments.next().unwrap_or(predicate);
    let looks_like_a_version =
        last.starts_with('v') && last[1..].chars().all(|c| c.is_ascii_digit()) && last.len() > 1;
    if looks_like_a_version {
        segments.next().unwrap_or(last)
    } else {
        last
    }
}

/// Blobs, run records and attestations over one object store.
#[derive(Clone, Debug)]
pub struct Store {
    inner: Arc<dyn ObjectStore>,
    blobs: Blobs,
}

impl Store {
    /// A store rooted at a local directory. The single-binary case.
    /// Open a store that already exists, creating nothing.
    ///
    /// For readers. `local` creates the directory it is pointed at, which is right for a run that
    /// is about to write to it and wrong for anything that only looks: `trigon watch` documents
    /// itself as read-only and was silently creating whatever `--store` named. The cost was not the
    /// stray directory — it was that a mistyped path then presented as a real, empty store, so the
    /// page reported "no record for this target, by design" about a store that had never existed.
    pub fn existing(root: &Path) -> Result<Self, StoreError> {
        if !root.is_dir() {
            return Err(StoreError::Malformed(format!(
                "{} is not a directory, so there is no store here to read. A relative path is \
                 resolved against the working directory of the process that was given it.",
                root.display()
            )));
        }
        Self::local(root)
    }

    pub fn local(root: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root)?;
        let fs = object_store::local::LocalFileSystem::new_with_prefix(root)?;
        Ok(Self::new(Arc::new(fs)))
    }

    /// A store in memory. For tests, and for a run that must leave nothing behind.
    pub fn in_memory() -> Self {
        Self::new(Arc::new(object_store::memory::InMemory::new()))
    }

    pub fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Store {
            blobs: Blobs::new(inner.clone()),
            inner,
        }
    }

    pub fn blobs(&self) -> &Blobs {
        &self.blobs
    }

    fn run_path(id: &str) -> ObjPath {
        ObjPath::from(format!("runs/{id}.json"))
    }

    /// Whether a run id is one the store can address and list back unchanged.
    ///
    /// `ObjPath::from` percent-encodes what it cannot carry literally, and `list_runs` reads the
    /// raw filename and never decodes — so an id containing `%`, `#`, a brace or a control
    /// character was written under one name and listed under another, and `get_run` on what the
    /// listing reported found nothing. Two halves of one store disagreeing about what a run is
    /// called.
    ///
    /// Refused at the boundary rather than round-tripped through encoding, because the ids this
    /// system generates are `<unix>-<digest prefix>` and anything else arrived from somewhere that
    /// should say so. A store that quietly renames its records is worse than one that declines.
    fn addressable(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 128
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && !id.starts_with('.')
    }

    /// Write a run record, replacing any earlier version of it.
    pub async fn put_run(&self, r: &RunRecord) -> Result<(), StoreError> {
        if !Self::addressable(&r.id) {
            return Err(StoreError::Malformed(format!(
                "`{}` is not a usable run id. Letters, digits, `-`, `_` and `.` only, at most 128 \
                 of them, not starting with a dot — anything else is percent-encoded on the way in \
                 and not decoded on the way out, so the run would be listed under a name it cannot \
                 be fetched by.",
                r.id
            )));
        }
        let body = serde_json::to_vec_pretty(r)?;
        self.inner
            .put(&Self::run_path(&r.id), PutPayload::from(body))
            .await?;
        Ok(())
    }

    pub async fn get_run(&self, id: &str) -> Result<RunRecord, StoreError> {
        let bytes = match self.inner.get(&Self::run_path(id)).await {
            Ok(r) => r.bytes().await?,
            Err(object_store::Error::NotFound { .. }) => {
                return Err(StoreError::NoSuchRun(id.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Every run in the store, most recent first.
    ///
    /// Sorted by the id rather than by a stored timestamp: ids are time-ordered by construction and
    /// listing is already the expensive part, so reading every record to sort them would turn a
    /// listing into a fetch of the whole store.
    pub async fn list_runs(&self) -> Result<Vec<String>, StoreError> {
        let prefix = ObjPath::from("runs");
        let mut out: Vec<String> = self
            .inner
            .list(Some(&prefix))
            .map_ok(|m| {
                m.location
                    .filename()
                    .and_then(|f| f.strip_suffix(".json"))
                    .unwrap_or_default()
                    .to_string()
            })
            .try_collect()
            .await?;
        out.retain(|s| !s.is_empty());
        out.sort();
        out.reverse();
        Ok(out)
    }

    /// File a signed statement where a consumer holding the *published* artifact can find it.
    ///
    /// Keyed by the target rather than by the run, because that is the question people actually
    /// ask: "is there an attestation for the thing I just downloaded". A layout keyed on our run id
    /// would be findable only by someone who already had our run id, which is nobody.
    pub async fn put_attestation(
        &self,
        target: &trigon_core::Target,
        artifact: &str,
        predicate: &str,
        envelope: &trigon_attest::Envelope,
    ) -> Result<String, StoreError> {
        let short = predicate_name(predicate);
        let path = format!(
            "attestations/{}/{}/{}/{artifact}/{short}.intoto.json",
            target.reference.ecosystem.purl_type(),
            target.reference.registry_name(),
            target.reference.version,
        );
        let body = serde_json::to_vec_pretty(envelope)?;
        self.inner
            .put(&ObjPath::from(path.clone()), PutPayload::from(body))
            .await?;
        Ok(path)
    }

    /// Publish a stabilizer set's manifest, addressed by the set digest.
    ///
    /// `trigon verify` refuses to compare across differing set digests and re-derives instead,
    /// which is right and leaves a verifier holding an older attestation with a digest that matches
    /// nothing they have and no way to learn what it was. Publishing the manifest beside the
    /// attestation is the smallest fix: it does not let them *run* the old set — that wants the
    /// component of `docs/09-attestations.md` §7.1 — but it says exactly what the claim was made
    /// under, and it recomputes its own digest so it cannot describe a different set than it names.
    ///
    /// The path is the digest, so publishing the same set twice is a no-op and two writers cannot
    /// disagree about what a digest means.
    pub async fn put_stabilizer_set(
        &self,
        manifest: &trigon_stabilize::SetManifest,
    ) -> Result<String, StoreError> {
        if !manifest.self_consistent() {
            return Err(StoreError::InconsistentSet {
                digest: manifest.digest.clone(),
            });
        }
        let path = format!("stabilizers/sha256/{}.json", manifest.digest);
        let body = serde_json::to_vec_pretty(manifest)?;
        self.inner
            .put(&ObjPath::from(path.clone()), PutPayload::from(body))
            .await?;
        Ok(path)
    }

    /// Read a published set manifest back, **checking it against the digest asked for**.
    ///
    /// Two checks, not one: the document must recompute its own digest, and that digest must be the
    /// one requested. Either alone is insufficient — a self-consistent manifest for some other set
    /// is a correct document and the wrong answer.
    pub async fn get_stabilizer_set(
        &self,
        digest: &str,
    ) -> Result<trigon_stabilize::SetManifest, StoreError> {
        let path = format!("stabilizers/sha256/{digest}.json");
        let bytes = match self.inner.get(&ObjPath::from(path)).await {
            Ok(r) => r.bytes().await?,
            Err(object_store::Error::NotFound { .. }) => {
                return Err(StoreError::NoSuchSet(digest.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        let m: trigon_stabilize::SetManifest = serde_json::from_slice(&bytes)?;
        if !m.self_consistent() || m.digest != digest {
            return Err(StoreError::InconsistentSet {
                digest: digest.to_string(),
            });
        }
        Ok(m)
    }

    pub async fn get_attestation(&self, path: &str) -> Result<trigon_attest::Envelope, StoreError> {
        let bytes = self.inner.get(&ObjPath::from(path)).await?.bytes().await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Drop the rebuilt artifact's bytes for a run that matched, keeping its digests.
    ///
    /// The retention rule that keeps a sweep's storage in the hundreds of gigabytes rather than the
    /// tens of terabytes. Three refusals, each because the alternative destroys evidence:
    ///
    /// - **A run with no attestation** is refused outright. The signature is a claim *about these
    ///   bytes*, and a third party re-deriving it needs them; pruning first would leave a statement
    ///   nobody can check, which is the one thing this whole design exists to avoid.
    /// - **A divergence keeps its bytes.** A divergence is a public claim about someone else's
    ///   package, and a maintainer who cannot obtain the artifact we compared against has no way to
    ///   answer it.
    /// - **The upstream artifact is never pruned here.** It is what a consumer already has and what
    ///   they would re-derive against.
    pub async fn prune_rebuild(&self, id: &str) -> Result<bool, StoreError> {
        let mut run = self.get_run(id).await?;
        if run.attestations.is_empty() {
            return Err(StoreError::NotAttested(id.to_string()));
        }
        if run.outcome.as_deref() == Some("divergent") || !run.is_evidence() {
            return Ok(false);
        }
        let Some(rebuild) = run.rebuild.as_mut() else {
            return Ok(false);
        };
        if !rebuild.stored {
            return Ok(false);
        }
        // Only when the two sides are genuinely distinct bytes. On an `exact` match they are the
        // same blob, and deleting it would take the upstream artifact with it.
        if rebuild.sha256 != run.upstream.sha256 {
            self.blobs.delete(&rebuild.sha256).await?;
        }
        rebuild.stored = false;
        self.put_run(&run).await?;
        Ok(true)
    }
}
