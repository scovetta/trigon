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
//! attestations/<eco>/<name>/<version>/<artifact>/<run-id>/<predicate>.intoto.json
//! ```
//!
//! Attestations are filed per run and never overwritten ([`Store::put_attestation`]). Runs attested
//! before `docs/19` §10 phase 2 name statements one level up, per target, and still read: a run
//! record names its statements by path, and nothing about reading one depends on the layout. A run
//! attested again since sets those paths aside ([`Store::record_attestations`]), because another
//! run of the same target may have written over any of them.
//!
//! **The queue arrived with M4** and lives in [`queue`], behind a feature flag, for the reason
//! ADR-0005 gives: `enqueue` and the run-state write must share one `sqlx::Transaction`, and a
//! `trigon-queue` crate would put a boundary between them that buys nothing and costs the
//! transaction. The content-addressed layout above is unchanged and still holds everything a
//! signature is about; the database holds pointers, small scalars, and the jobs.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod attempt;
mod blobs;
#[cfg(feature = "queue")]
pub mod queue;
mod record;

pub use attempt::{
    CACHE_KEY_VERSION, CacheState, ImagePin, cache_key, host_id, host_id_from, names_a_machine,
};
pub use blobs::{Blobs, digest_of};
#[cfg(feature = "queue")]
pub use queue::{
    Backend, HostBudget, Job, JobState, NewJob, Principal, Queue, Requested, Tier, request_key,
};
pub use record::{
    ArtifactRef, Costs, DerivedImage, Environment, PinEvidence, Published, RunRecord, RunState,
    Tokens, UpstreamDigests,
};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::TryStreamExt as _;
use object_store::{ObjectStore, ObjectStoreExt as _, PutMode, PutPayload, path::Path as ObjPath};
use trigon_core::{Classify, Digest, Fault};

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

    /// A path a reader was given to open a store at, where there is no directory: a mistyped
    /// `--store`, and nothing about any record. Its own variant rather than `Malformed`, so the
    /// command line can be named as the party at fault instead of trigon.
    #[error(
        "{} is not a directory, so there is no store here to read. A relative path is resolved \
         against the working directory of the process that was given it.",
        .0.display()
    )]
    NotAStore(PathBuf),

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

    /// Every name beside a statement already holds a different statement for the same run.
    ///
    /// Statements are append-only, so a re-attestation that differs from what is there is written
    /// alongside it as `<predicate>.2.intoto.json`, `.3`, and so on. A thousand of them for one run
    /// is not a history, it is something attesting in a loop.
    #[error(
        "{first} and the {tried} names after it all hold other statements for this run, and \
         statements are never overwritten. Something is re-attesting this run in a loop: find \
         what, rather than clearing the store."
    )]
    NoFreeAttestationPath { first: String, tried: usize },

    /// A run's record says an artifact's bytes are kept, and the store has no blob of them.
    ///
    /// Said as missing, never read as there: the record's digests still stand, and what they are
    /// digests of is gone — deleted from outside the store, or pruned for another run that named
    /// the same bytes before pruning counted who else did.
    #[error(
        "run `{run}`'s record says its {what}, sha256:{digest}, is kept in the store, and the store \
         has no blob of it: the bytes are missing. Its digests still stand; the bytes were removed \
         from outside the store, or pruned for another run that named the same bytes"
    )]
    Missing {
        run: String,
        what: &'static str,
        digest: String,
    },

    /// A statement file is already at the path a run names another at, and holds other bytes
    /// ([`Store::put_statement`]).
    #[error(
        "{0} already holds a different statement, and statements are never overwritten: the run \
         naming this path names another statement at it than the one the store holds"
    )]
    StatementTaken(String),

    /// A run record is already under the id another is created at, and says something else
    /// ([`Store::create_run`]).
    #[error(
        "run `{0}` is in this store already, and its record here differs: a run id names one run, \
         and a record is never written over another's"
    )]
    RunTaken(String),

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
            // A refusal to overwrite a statement or a record, which is the store's rule and not a
            // fault in it.
            StoreError::StatementTaken(_) | StoreError::RunTaken(_) => Fault::Policy,
            // Nothing a store does on its own produces a thousand differing statements for one
            // run; a caller in a loop does.
            StoreError::NoFreeAttestationPath { .. } => Fault::Bug,
            // A manifest that does not describe its own digest is the same class of problem as a
            // blob that does not hash to its own address: something wrote a document that cannot be
            // true.
            StoreError::InconsistentSet { .. } => Fault::Bug,
            StoreError::NoSuchRun(_) | StoreError::NoSuchSet(_) | StoreError::Json(_) => Fault::Bug,
            // The class a run that is not there has, so it is never retried. `trigon`'s fault
            // report names the command line for it rather than trigon, since a store's path comes
            // from there; and for a run that is not there too, where a run's id mostly comes from,
            // though not for the run `rebuild --attest` has just recorded, which is trigon's own.
            StoreError::NotAStore(_) => Fault::Bug,
            // Bytes a record says are kept and are not: the store lost data, which somebody should
            // look at, as a blob that does not match its address is.
            StoreError::Missing { .. } => Fault::Bug,
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
            // Gone is gone: asking again finds it gone.
            StoreError::Missing { .. } => false,
            // A record that is absent now may be present later, but nothing this process does will
            // make it so — the caller named a run that was never written.
            StoreError::NoSuchRun(_) | StoreError::NoSuchSet(_) => false,
            // Nor will a directory that is not there appear by opening it again.
            StoreError::NotAStore(_) => false,
            // A refusal we issued on purpose answers the same way every time.
            StoreError::NotAttested(_)
            | StoreError::StatementTaken(_)
            | StoreError::RunTaken(_) => false,
            // The names that are taken stay taken.
            StoreError::NoFreeAttestationPath { .. } => false,
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

/// Append `written` to what a record names, and set its per-target paths aside once it names a
/// statement filed under its own id. See [`Store::record_attestations`].
fn name_statements(record: &mut RunRecord, written: &[String]) {
    for p in written {
        if !record.attestations.contains(p) {
            record.attestations.push(p.clone());
        }
    }
    // The directory a statement sits in is the run it was filed under; a per-target path's is the
    // artifact's.
    let own = |p: &String| p.rsplit('/').nth(1) == Some(record.id.as_str());
    if !record.attestations.iter().any(own) {
        return;
    }
    let (own, per_target): (Vec<String>, Vec<String>) =
        record.attestations.drain(..).partition(|p| own(p));
    record.attestations = own;
    for p in per_target {
        if !record.per_target_attestations.contains(&p) {
            record.per_target_attestations.push(p);
        }
    }
}

/// Blobs, run records and attestations over one object store.
#[derive(Clone, Debug)]
pub struct Store {
    inner: Arc<dyn ObjectStore>,
    blobs: Blobs,
    lock: BlobLock,
}

/// What a writer naming bytes as kept and a prune deleting them take turns on ([`Store::keeping`]).
#[derive(Clone, Debug)]
enum BlobLock {
    /// `<root>/blobs.lock`, locked with `flock`: every process on the host that opens the store,
    /// released when its holder exits however it exits.
    File(std::path::PathBuf),
    /// One process's own, for a store with no directory: one in memory. Held alone by writers
    /// too, which there are rarely two of.
    Memory(Arc<futures::lock::Mutex<()>>),
}

/// A hold on a store's blobs, released when it is dropped ([`Store::keeping`]).
#[derive(Debug)]
pub struct Keeping {
    held: Held,
}

#[derive(Debug)]
enum Held {
    File(std::fs::File),
    Memory(#[allow(dead_code, reason = "held for its drop")] futures::lock::OwnedMutexGuard<()>),
}

impl Drop for Keeping {
    fn drop(&mut self) {
        // Unlocked explicitly, not by the close alone: `flock` belongs to the open file
        // description, which a child forked from another thread shares until it execs, and the
        // close would leave the lock held that long.
        if let Held::File(f) = &self.held {
            let _ = rustix::fs::flock(f, rustix::fs::FlockOperation::Unlock);
        }
    }
}

impl BlobLock {
    async fn hold(&self, alone: bool) -> Result<Keeping, StoreError> {
        use rustix::fs::FlockOperation;
        match self {
            BlobLock::File(path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(path)?;
                let how = match alone {
                    true => FlockOperation::LockExclusive,
                    false => FlockOperation::LockShared,
                };
                rustix::fs::flock(&file, how).map_err(std::io::Error::from)?;
                Ok(Keeping {
                    held: Held::File(file),
                })
            }
            BlobLock::Memory(m) => Ok(Keeping {
                held: Held::Memory(m.clone().lock_owned().await),
            }),
        }
    }
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
            return Err(StoreError::NotAStore(root.to_path_buf()));
        }
        Self::local(root)
    }

    pub fn local(root: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root)?;
        let fs = object_store::local::LocalFileSystem::new_with_prefix(root)?;
        Ok(Store {
            lock: BlobLock::File(std::path::absolute(root)?.join("blobs.lock")),
            ..Self::new(Arc::new(fs))
        })
    }

    /// A store in memory. For tests, and for a run that must leave nothing behind.
    pub fn in_memory() -> Self {
        Self::new(Arc::new(object_store::memory::InMemory::new()))
    }

    pub fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Store {
            blobs: Blobs::new(inner.clone()),
            inner,
            lock: BlobLock::Memory(Arc::default()),
        }
    }

    /// Hold the store's blobs as they are, for a writer about to name bytes as kept.
    ///
    /// Taken before the bytes a new run record will name as kept are put, and held until that
    /// record is written. [`Self::prune_rebuild`] deletes a blob only when no record names it,
    /// and between a `put` that finds the bytes already there — another run's, as a confirming
    /// attempt's are — and the record that names them, none does; a prune asking then would
    /// delete the bytes the record is about to say are kept. So a prune holds this alone, from
    /// asking who names a blob until it is deleted, and the two take turns. Shared between writers
    /// of a store on disk, which never wait on one another. Waiting blocks the thread.
    pub async fn keeping(&self) -> Result<Keeping, StoreError> {
        self.lock.hold(false).await
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

    /// Whether [`Self::put_run`] would write a record under `id`: the rule of `addressable`, for a
    /// caller that must refuse a record before it writes anything the record names, as `trigon runs
    /// import` does.
    pub fn is_run_id(id: &str) -> bool {
        Self::addressable(id)
    }

    /// Whether `path` is one [`Self::put_statement`] writes a statement at: under `attestations/`,
    /// ending `.intoto.json`, at least six segments deep as the per-target layout is, and every
    /// segment a non-empty run of letters, digits, `-`, `_`, `.`, `@`, `+` and `!` that is not `.`
    /// or `..`.
    ///
    /// Narrower than what `ObjPath::from` would take, which percent-encodes a `..` rather than
    /// refusing it and drops an empty segment: a path in a record that came from another store is
    /// held to the shape this store writes, so it cannot name a file anywhere else, or name one
    /// file in the record and another on disk. The characters are the ones a purl type, a registry
    /// name, a version, an artifact's file name and a run id are written with; `!` is a PEP 440
    /// epoch's, as in `1!2.0`, and `ObjPath::from` writes it as it is.
    pub fn is_statement_path(path: &str) -> bool {
        let segments: Vec<&str> = path.split('/').collect();
        path.len() <= 1024
            && segments.len() >= 6
            && segments[0] == "attestations"
            && path.ends_with(".intoto.json")
            && segments.iter().all(|s| {
                !s.is_empty()
                    && *s != "."
                    && *s != ".."
                    && s.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+' | '!')
                    })
            })
    }

    /// Write a run record, replacing any earlier version of it.
    pub async fn put_run(&self, r: &RunRecord) -> Result<(), StoreError> {
        Self::usable_run_id(&r.id)?;
        let body = serde_json::to_vec_pretty(r)?;
        self.inner
            .put(&Self::run_path(&r.id), PutPayload::from(body))
            .await?;
        Ok(())
    }

    /// Write a run record where the store holds none under its id, as the store it was made in
    /// holds it: `trigon runs import`.
    ///
    /// **Never over another**, as [`Self::put_statement`] never writes over a statement: the write
    /// is a create that fails where the name is taken, the same record already there is the same
    /// run and answered as written, and another is [`StoreError::RunTaken`] and left as it is. A
    /// look before a plain write would leave a window in which a record another writer files under
    /// the same id is replaced, and [`Self::keeping`] is shared between writers, so it closes none.
    /// An id [`Self::put_run`] refuses is [`StoreError::Malformed`], and nothing is written.
    pub async fn create_run(&self, r: &RunRecord) -> Result<(), StoreError> {
        Self::usable_run_id(&r.id)?;
        let location = Self::run_path(&r.id);
        let body = serde_json::to_vec_pretty(r)?;
        let written = self
            .inner
            .put_opts(&location, PutPayload::from(body), PutMode::Create.into())
            .await;
        match written {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let there = self.inner.get(&location).await?.bytes().await?;
                let there: RunRecord = serde_json::from_slice(&there)?;
                match there == *r {
                    true => Ok(()),
                    false => Err(StoreError::RunTaken(r.id.clone())),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The refusal a write under `id` gives where [`Self::addressable`] says no.
    fn usable_run_id(id: &str) -> Result<(), StoreError> {
        match Self::addressable(id) {
            true => Ok(()),
            false => Err(StoreError::Malformed(format!(
                "`{id}` is not a usable run id. Letters, digits, `-`, `_` and `.` only, at most \
                 128 of them, not starting with a dot — anything else is percent-encoded on the \
                 way in and not decoded on the way out, so the run would be listed under a name it \
                 cannot be fetched by."
            ))),
        }
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

    /// File a signed statement under the run it is about, and never over one that is already there.
    ///
    /// **Per run, because per target destroyed signed history.** Statements were filed at
    /// `…/<artifact>/<predicate>.intoto.json`, so attesting a second run of a target overwrote the
    /// first run's statement, and the first run's record went on naming a path that now held
    /// somebody else's claim: 40 of the 93 attestation paths in the local store were shared by
    /// more than one run when this was measured (`docs/19` §10 phase 2). The run id is the
    /// directory now.
    ///
    /// The target stays in the path above it, so everything signed about one artifact still lists
    /// under one prefix, and the layout still parses back into a `Target` as `docs/09` §6 says.
    ///
    /// **Append-only, by writing alongside rather than refusing.** A run is attested again on
    /// purpose — `docs/09` §3 says a stored run can be signed again without building, with a key it
    /// was first signed without, or by a binary that signs a newer predicate — and a refusal would
    /// make that impossible. So the store does what it does for re-derived comparisons, which sit
    /// beside the original and never replace it: the first statement keeps its name, and one that
    /// differs is written as `<predicate>.2.intoto.json`, `.3`, and so on. Identical bytes are the
    /// same statement — ed25519 signs deterministically, so re-attesting unchanged evidence with
    /// the same key reproduces them — and are answered with the path they are already at, as the
    /// blob store answers bytes it already holds.
    ///
    /// Each write is a create that fails if the name is taken, not a check followed by a write, so
    /// two attestors racing on one run cannot overwrite each other's statement files. The record's
    /// list of them is a separate write, and [`Self::record_attestations`] says how far that one is
    /// protected.
    pub async fn put_attestation(
        &self,
        target: &trigon_core::Target,
        run_id: &str,
        artifact: &str,
        predicate: &str,
        envelope: &trigon_attest::Envelope,
    ) -> Result<String, StoreError> {
        if !Self::addressable(run_id) {
            return Err(StoreError::Malformed(format!(
                "`{run_id}` is not a run id this store writes, so a statement cannot be filed \
                 under it. Attest a run the store holds."
            )));
        }
        let short = predicate_name(predicate);
        let dir = format!(
            "attestations/{}/{}/{}/{artifact}/{run_id}",
            target.reference.ecosystem.purl_type(),
            target.reference.registry_name(),
            target.reference.version,
        );
        self.put_beside(&dir, short, envelope).await
    }

    /// File a signed `withdrawal/v1` under the record it withdraws, append-only as statements are.
    ///
    /// A withdrawal has no run behind it (`docs/19` §3), so it cannot be filed under one, and it is
    /// about one record, so it is filed under that record's digest:
    /// `withdrawals/sha256/<record>/withdrawal.intoto.json`, then `.2`, `.3` for another. `trigon
    /// publish --withdrawal` reads it from there (§10 phase 5).
    pub async fn put_withdrawal(
        &self,
        record: &Digest,
        envelope: &trigon_attest::Envelope,
    ) -> Result<String, StoreError> {
        let dir = format!("withdrawals/sha256/{}", record.to_hex());
        self.put_beside(&dir, "withdrawal", envelope).await
    }

    /// Write `envelope` as `<dir>/<short>.intoto.json`, or beside a different one already there as
    /// `.2`, `.3` and so on, never over it. The same bytes again answer the path they are at.
    async fn put_beside(
        &self,
        dir: &str,
        short: &str,
        envelope: &trigon_attest::Envelope,
    ) -> Result<String, StoreError> {
        /// How many statements of one predicate a run may accumulate before this refuses.
        const MOST: usize = 1000;
        let body = serde_json::to_vec_pretty(envelope)?;
        for n in 1..=MOST {
            let path = match n {
                1 => format!("{dir}/{short}.intoto.json"),
                n => format!("{dir}/{short}.{n}.intoto.json"),
            };
            let location = ObjPath::from(path.clone());
            let written = self
                .inner
                .put_opts(
                    &location,
                    PutPayload::from(body.clone()),
                    PutMode::Create.into(),
                )
                .await;
            match written {
                Ok(_) => return Ok(path),
                Err(object_store::Error::AlreadyExists { .. }) => {
                    let there = self.inner.get(&location).await?.bytes().await?;
                    if there[..] == body[..] {
                        return Ok(path);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(StoreError::NoFreeAttestationPath {
            first: format!("{dir}/{short}.intoto.json"),
            tried: MOST - 1,
        })
    }

    /// Name newly written statements on a run's record, merged into the record as it is now.
    ///
    /// **Merged, never written back.** The attestor reads the record, spends seconds re-deriving
    /// and signing, and used to write back the copy it had read: a second attestor finishing in
    /// between had its paths dropped from the record, its signed files still on disk and named by
    /// nothing a reader goes by. So the record is read again here and `written` appended to what it
    /// holds by then. Where the backend has conditional writes — object storage, and the in-memory
    /// store — the write succeeds only over the version read, and is retried when another writer
    /// got there first, so two attestors cannot drop each other's paths. The local filesystem has
    /// none (`object_store` does not implement `PutMode::Update` for it), and there the window is
    /// the gap between this read and this write, not the whole attestation. It is not zero.
    ///
    /// **Per-target paths are set aside once the run has statements of its own.** A run attested
    /// before statements were filed per run names paths every run of its target shared, and a
    /// later run may have written over any of them. Kept in `attestations` beside the run's own,
    /// they were served as this run's; they move to `per_target_attestations`, which nothing
    /// serves, so that re-attesting a run is how it stops being served another run's claims.
    ///
    /// Returns the record as written.
    pub async fn record_attestations(
        &self,
        run_id: &str,
        written: &[String],
    ) -> Result<RunRecord, StoreError> {
        self.update_run(run_id, |record| name_statements(record, written))
            .await
    }

    /// Record where a run's record was published (`docs/19` §10 phase 5 step 7), merged into the
    /// record as it is now, as [`Self::record_attestations`] merges: an attestor or a confirming
    /// run writing the record meanwhile keeps what it wrote.
    ///
    /// Returns the record as written.
    pub async fn record_published(
        &self,
        run_id: &str,
        published: &Published,
    ) -> Result<RunRecord, StoreError> {
        self.update_run(run_id, |record| record.published = Some(published.clone()))
            .await
    }

    /// Change a run's record by `change`, read as it is now and written only over that version
    /// where the backend can say so: see [`Self::record_attestations`] for how far that holds.
    async fn update_run(
        &self,
        run_id: &str,
        change: impl Fn(&mut RunRecord),
    ) -> Result<RunRecord, StoreError> {
        /// How often a conditional write may lose to another writer before this gives up. Each
        /// loss means another writer wrote this run's record in between, which is rare; this many
        /// in a row means something is writing it in a loop.
        const ATTEMPTS: usize = 16;
        let location = Self::run_path(run_id);
        let mut attempt = 1;
        loop {
            let got = match self.inner.get(&location).await {
                Ok(g) => g,
                Err(object_store::Error::NotFound { .. }) => {
                    return Err(StoreError::NoSuchRun(run_id.to_string()));
                }
                Err(e) => return Err(e.into()),
            };
            let version = object_store::UpdateVersion {
                e_tag: got.meta.e_tag.clone(),
                version: got.meta.version.clone(),
            };
            let mut record: RunRecord = serde_json::from_slice(&got.bytes().await?)?;
            change(&mut record);
            let body = serde_json::to_vec_pretty(&record)?;
            let put = self
                .inner
                .put_opts(
                    &location,
                    PutPayload::from(body.clone()),
                    PutMode::Update(version).into(),
                )
                .await;
            match put {
                Ok(_) => return Ok(record),
                // Somebody else wrote the record since it was read. Read it again, with their
                // change in it; the last loss is returned like any other failed write.
                Err(object_store::Error::Precondition { .. }) if attempt < ATTEMPTS => {
                    attempt += 1;
                }
                Err(object_store::Error::NotImplemented { .. }) => {
                    self.inner.put(&location, PutPayload::from(body)).await?;
                    return Ok(record);
                }
                Err(e) => return Err(e.into()),
            }
        }
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

    /// Sharded two-character like the blob store, and for the same reason: a flat prefix of a
    /// hundred thousand `.cs` is slow to list and a hot key on object storage.
    fn decompiled_path(assembly: &Digest) -> ObjPath {
        let hex = assembly.to_hex();
        ObjPath::from(format!("decompiled/sha256/{}/{hex}.cs", &hex[..2]))
    }

    /// Store the C# decompiled from one managed assembly, keyed by the **assembly's** own digest.
    ///
    /// Pre-computed during a divergent run so `trigon serve` shows the source diff without podman
    /// — a read replica over a bucket has neither the container tool nor a reason to hold one, and
    /// this is the only way the decompiled view reaches it. Content-addressed by the assembly, so
    /// a re-run of the same target and the two sides that happen to share bytes all resolve to one
    /// object. A reading aid, never a verdict: `trigon-core::opinion`'s rule holds here too, and
    /// nothing reads this to decide an outcome.
    pub async fn put_decompiled(&self, assembly: &Digest, csharp: &str) -> Result<(), StoreError> {
        let path = Self::decompiled_path(assembly);
        self.inner
            .put(&path, PutPayload::from(csharp.as_bytes().to_vec()))
            .await?;
        Ok(())
    }

    /// The decompiled C# for an assembly, or `None` if it was never computed.
    ///
    /// `None` is "not pre-computed", never "the sources match" — the caller falls back to a live
    /// decompile where it can and to the hex view where it cannot.
    pub async fn get_decompiled(&self, assembly: &Digest) -> Result<Option<String>, StoreError> {
        match self.inner.get(&Self::decompiled_path(assembly)).await {
            Ok(r) => Ok(Some(
                String::from_utf8_lossy(&r.bytes().await?).into_owned(),
            )),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn derived_comparison_path(original: &Digest) -> ObjPath {
        let hex = original.to_hex();
        ObjPath::from(format!(
            "derived/comparison/sha256/{}/{hex}.json",
            &hex[..2]
        ))
    }

    /// Store a comparison **re-derived** from a run's stored artifacts, keyed by the digest of the
    /// comparison the run actually recorded.
    ///
    /// The re-derivation carries the explanatory detail a comparison written before it existed
    /// lacks — which pass changed which field, and how the differences shrank pass by pass — and
    /// nothing else may differ: `trigon rederive` refuses to write one whose verdict, digests or
    /// difference signature disagree with the original. The original is never replaced. The run
    /// record keeps naming it, it stays in the blob store, and it is what the raw evidence route
    /// serves; this sits beside it as a reading aid, like [`Self::put_decompiled`], and nothing
    /// reads it to decide an outcome.
    pub async fn put_derived_comparison(
        &self,
        original: &Digest,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.inner
            .put(
                &Self::derived_comparison_path(original),
                PutPayload::from(bytes.to_vec()),
            )
            .await?;
        Ok(())
    }

    /// The re-derived comparison for a recorded one, or `None` if none was written.
    ///
    /// `None` is "never re-derived", never "nothing to explain".
    pub async fn get_derived_comparison(
        &self,
        original: &Digest,
    ) -> Result<Option<bytes::Bytes>, StoreError> {
        match self
            .inner
            .get(&Self::derived_comparison_path(original))
            .await
        {
            Ok(r) => Ok(Some(r.bytes().await?)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Read a statement back by the path a run record names it by.
    ///
    /// Either layout: the per-run one [`Self::put_attestation`] writes, and the per-target one runs
    /// attested before it still name. The path is the record's, so nothing here has to know which.
    pub async fn get_attestation(&self, path: &str) -> Result<trigon_attest::Envelope, StoreError> {
        let bytes = self.inner.get(&ObjPath::from(path)).await?.bytes().await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// A statement file's bytes as the store holds them, by the path a run record names it by, or
    /// `None` where no file is there.
    ///
    /// The bytes, not an [`trigon_attest::Envelope`] read from them: `trigon runs export` carries a
    /// statement to another store as the file it is, and `import` compares what it carries with
    /// what is already at the path.
    pub async fn statement_bytes(&self, path: &str) -> Result<Option<bytes::Bytes>, StoreError> {
        match self.inner.get(&ObjPath::from(path)).await {
            Ok(r) => Ok(Some(r.bytes().await?)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// File a statement at the path a run record names it by, as it is filed in the store the run
    /// came from: `trigon runs import`.
    ///
    /// **Never over another**, as [`Self::put_attestation`] never writes over one: the write is a
    /// create that fails where the name is taken, the same bytes already there are the same
    /// statement and answered as written, and other bytes are [`StoreError::StatementTaken`]. A
    /// path [`Self::is_statement_path`] refuses is [`StoreError::Malformed`], and nothing is
    /// written.
    pub async fn put_statement(
        &self,
        path: &str,
        bytes: impl Into<bytes::Bytes>,
    ) -> Result<(), StoreError> {
        let bytes: bytes::Bytes = bytes.into();
        if !Self::is_statement_path(path) {
            return Err(StoreError::Malformed(format!(
                "`{path}` is not a path this store files a statement at: under `attestations/`, \
                 ending `.intoto.json`, and every segment letters, digits, `-`, `_`, `.`, `@`, \
                 `+` and `!`, never `.` or `..`"
            )));
        }
        let location = ObjPath::from(path);
        let written = self
            .inner
            .put_opts(
                &location,
                PutPayload::from_bytes(bytes.clone()),
                PutMode::Create.into(),
            )
            .await;
        match written {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let there = self.inner.get(&location).await?.bytes().await?;
                match there == bytes {
                    true => Ok(()),
                    false => Err(StoreError::StatementTaken(path.to_string())),
                }
            }
            Err(e) => Err(e.into()),
        }
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
    ///
    /// **And bytes another run still names stay.** Blobs are content-addressed, so two runs that
    /// rebuilt byte-identical artifacts — the agreeing pair a confirmation is, exactly — share one
    /// blob, and deleting it for one would leave the other's record saying `stored: true` over
    /// nothing. So the blob is deleted only when no other run's record names it as kept, as its
    /// published or its rebuilt artifact; otherwise only this run's reference is dropped
    /// ([`Pruned::Shared`]). A record that cannot be read refuses the prune, since it may be one
    /// that names the bytes.
    ///
    /// **Alone, from the question to the delete.** A run written meanwhile that names the same
    /// bytes would not be counted and would lose them, so the prune holds the store's blobs alone
    /// ([`Self::keeping`]), which every writer naming bytes as kept holds shared until its record
    /// is written: it waits for any such writer to finish, and they for it.
    pub async fn prune_rebuild(&self, id: &str) -> Result<Pruned, StoreError> {
        let _alone = self.lock.hold(true).await?;
        let mut run = self.get_run(id).await?;
        if run.attestations.is_empty() {
            return Err(StoreError::NotAttested(id.to_string()));
        }
        if run.outcome.as_deref() == Some("divergent") || !run.is_evidence() {
            return Ok(Pruned::Kept);
        }
        let upstream = run.upstream.sha256;
        let Some(rebuild) = run.rebuild.as_mut() else {
            return Ok(Pruned::Kept);
        };
        if !rebuild.stored {
            return Ok(Pruned::Kept);
        }
        let digest = rebuild.sha256;
        let others = self.naming(&digest, id).await?;
        // Only when the two sides are genuinely distinct bytes. On an `exact` match they are the
        // same blob, and deleting it would take the upstream artifact with it.
        let delete = digest != upstream && others.is_empty();
        if delete {
            self.blobs.delete(&digest).await?;
        }
        rebuild.stored = false;
        self.put_run(&run).await?;
        Ok(match delete {
            true => Pruned::Deleted,
            false => Pruned::Shared(others),
        })
    }

    /// The runs other than `except` whose record names the blob `digest` as bytes it keeps: its
    /// published artifact, or its rebuilt one.
    pub async fn naming(&self, digest: &Digest, except: &str) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        for id in self.list_runs().await? {
            if id == except {
                continue;
            }
            let r = self.get_run(&id).await?;
            let names = (r.upstream.stored && r.upstream.sha256 == *digest)
                || r.rebuild
                    .as_ref()
                    .is_some_and(|a| a.stored && a.sha256 == *digest);
            if names {
                out.push(id);
            }
        }
        Ok(out)
    }

    /// An artifact of `run`'s, as its record names it: its bytes, checked against their digest,
    /// where the record says they are kept; `None` where it says they are not; and
    /// [`StoreError::Missing`] where it says they are kept and the store has no blob of them —
    /// reported as missing, never read as there. `what` names the artifact for that message.
    pub async fn artifact(
        &self,
        run: &str,
        what: &'static str,
        a: &ArtifactRef,
    ) -> Result<Option<bytes::Bytes>, StoreError> {
        if !a.stored {
            return Ok(None);
        }
        match self.blobs.get(&a.sha256).await {
            Ok(b) => Ok(Some(b)),
            Err(StoreError::Object(object_store::Error::NotFound { .. })) => {
                Err(StoreError::Missing {
                    run: run.to_string(),
                    what,
                    digest: a.sha256.to_hex(),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Whether an artifact a record names is kept: the record says so, and the store has the blob.
    /// A record that says so over a blob that is gone is not kept.
    pub async fn kept(&self, a: &ArtifactRef) -> Result<bool, StoreError> {
        Ok(a.stored && self.blobs.has(&a.sha256).await?)
    }
}

/// What [`Store::prune_rebuild`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pruned {
    /// Nothing: a divergence keeps its bytes, and a run with none kept has none to drop.
    Kept,
    /// The run's reference to its rebuilt artifact is dropped, and the bytes are deleted.
    Deleted,
    /// The run's reference is dropped, and the bytes stay: they are the published artifact too,
    /// an exact match, or these other runs' records still name them as kept.
    Shared(Vec<String>),
}

impl Pruned {
    /// Whether the run's reference to its rebuilt artifact was dropped.
    pub fn dropped(&self) -> bool {
        !matches!(self, Pruned::Kept)
    }
}
