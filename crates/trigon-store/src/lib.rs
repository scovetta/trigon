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
//! Postgres, the queue and the rollups arrive with M4, where there is a fleet to justify them.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod blobs;
mod record;

pub use blobs::Blobs;
pub use record::{ArtifactRef, Environment, RunRecord, RunState};

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
            StoreError::NoSuchRun(_) | StoreError::Json(_) => Fault::Bug,
            StoreError::Object(_) | StoreError::Io(_) => Fault::Infra,
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(self, StoreError::Object(_) | StoreError::Io(_))
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

    /// Write a run record, replacing any earlier version of it.
    pub async fn put_run(&self, r: &RunRecord) -> Result<(), StoreError> {
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
