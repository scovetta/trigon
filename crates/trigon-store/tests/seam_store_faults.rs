//! What the store says when the object store under it fails, and what it refuses on its own.
//!
//! Every reader in this crate draws the same line: *absent* is an answer — no such run, never
//! decompiled, never re-derived — and *unreachable* is an error. A reader that folded the second
//! into the first would tell a page "the sources match" or "no record" about a bucket that blinked,
//! and a caller deciding whether to retry would be told there was nothing to retry. So each is
//! asserted here against an object store that fails on purpose, beside the refusals the store makes
//! by its own rule: a thousand statements for one run, a directory that is not there, a prune with
//! nothing to drop.

use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::StreamExt as _;
use futures::stream::BoxStream;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt as _, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use trigon_core::{Classify as _, Digest, Fault};
use trigon_store::{ArtifactRef, Environment, Pruned, RunRecord, RunState, Store, StoreError};

type Fut<'a, T> = Pin<Box<dyn Future<Output = object_store::Result<T>> + Send + 'a>>;

/// What the store under test should fail at.
#[derive(Debug, Default)]
struct Faults {
    /// Reads of any path under this prefix fail.
    get: Option<String>,
    /// Writes of any path under this prefix fail.
    put: Option<String>,
    /// Every conditional update loses, as it would to a writer that always got there first.
    lose_every_update: bool,
}

/// An in-memory object store that fails where it is told to, and counts conditional updates
/// attempted, whether they then fail or not.
#[derive(Debug, Default)]
struct Failing {
    inner: InMemory,
    faults: Mutex<Faults>,
    updates: AtomicUsize,
}

impl Failing {
    fn set(&self, f: impl FnOnce(&mut Faults)) {
        f(&mut self.faults.lock().unwrap());
    }

    fn broken(what: &str) -> object_store::Error {
        object_store::Error::Generic {
            store: "failing",
            source: format!("the disk under {what} went away").into(),
        }
    }
}

impl fmt::Display for Failing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failing")
    }
}

/// `object_store` declares the trait with `async_trait`; this is that expansion written out, so
/// the test needs no macro crate of its own.
impl ObjectStore for Failing {
    fn put_opts<'a, 'b, 'c>(
        &'a self,
        location: &'b Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> Fut<'c, PutResult>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            let (fail, lose) = {
                let f = self.faults.lock().unwrap();
                let fail = f
                    .put
                    .as_deref()
                    .is_some_and(|p| location.as_ref().starts_with(p));
                (fail, f.lose_every_update)
            };
            // Every conditional write is counted, the ones that fail included: a caller that
            // retried a broken disk would otherwise look as though it had tried once.
            let update = matches!(opts.mode, PutMode::Update(_));
            if update {
                self.updates.fetch_add(1, Ordering::SeqCst);
            }
            if fail {
                return Err(Failing::broken(location.as_ref()));
            }
            if update && lose {
                return Err(object_store::Error::Precondition {
                    path: location.to_string(),
                    source: "another writer got there first".into(),
                });
            }
            self.inner.put_opts(location, payload, opts).await
        })
    }

    fn put_multipart_opts<'a, 'b, 'c>(
        &'a self,
        location: &'b Path,
        opts: PutMultipartOptions,
    ) -> Fut<'c, Box<dyn MultipartUpload>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move { self.inner.put_multipart_opts(location, opts).await })
    }

    fn get_opts<'a, 'b, 'c>(&'a self, location: &'b Path, options: GetOptions) -> Fut<'c, GetResult>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            let fail = self
                .faults
                .lock()
                .unwrap()
                .get
                .as_deref()
                .is_some_and(|p| location.as_ref().starts_with(p));
            if fail {
                return Err(Failing::broken(location.as_ref()));
            }
            self.inner.get_opts(location, options).await
        })
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>> {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    fn list_with_delimiter<'a, 'b, 'c>(&'a self, prefix: Option<&'b Path>) -> Fut<'c, ListResult>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move { self.inner.list_with_delimiter(prefix).await })
    }

    fn copy_opts<'a, 'b, 'c, 'd>(
        &'a self,
        from: &'b Path,
        to: &'c Path,
        options: CopyOptions,
    ) -> Fut<'d, ()>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        Box::pin(async move { self.inner.copy_opts(from, to, options).await })
    }
}

fn store() -> (Store, Arc<Failing>) {
    let inner = Arc::new(Failing::default());
    (Store::new(inner.clone()), inner)
}

fn env() -> Environment {
    Environment {
        base_image: "docker.io/library/debian@sha256:aa".into(),
        derived_image: None,
        egress: "mirror-only".into(),
        isolation: "UserNs".into(),
        guard_manifest: None,
        guarded_members: None,
        attestable: true,
        registry_moment: None,
        pin: None,
    }
}

fn artifact(name: &str, sha: &Digest, bytes: u64) -> ArtifactRef {
    ArtifactRef {
        name: name.into(),
        sha256: *sha,
        bytes,
        stored: true,
    }
}

fn record(id: &str, upstream: &Digest) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        "pkg:npm/@babel/core@7.24.0",
        artifact("core-7.24.0.tgz", upstream, 15),
        env(),
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = Some("exact".into());
    r
}

fn babel_core() -> trigon_core::Target {
    let reference: trigon_core::TargetRef = "pkg:npm/@babel/core@7.24.0".parse().unwrap();
    trigon_core::Target::new(reference, trigon_core::ArtifactId::new("core-7.24.0.tgz"))
}

const EQUIVALENCE: &str = "https://trigon.dev/equivalence/v1";

/// An infrastructure fault, as the rest of the system is to read it: somebody's disk or network,
/// and worth asking again.
fn assert_infra(e: &StoreError) {
    assert!(matches!(e, StoreError::Object(_)), "{e}");
    assert_eq!(e.fault(), Fault::Infra, "{e}");
    assert!(
        e.is_retryable(),
        "a fault in the disk under the store is what retrying is for: {e}"
    );
}

#[tokio::test]
async fn a_run_the_store_cannot_read_is_an_error_and_never_a_run_that_does_not_exist() {
    let (s, inner) = store();
    let up = Digest::from_bytes([1; 32]);
    s.put_run(&record("0001-a", &up)).await.unwrap();

    inner.set(|f| f.get = Some("runs/".into()));
    let e = s.get_run("0001-a").await.unwrap_err();
    assert!(
        !matches!(e, StoreError::NoSuchRun(_)),
        "an unreadable record was reported as one that was never written: {e}"
    );
    assert_infra(&e);

    // And an id that really is absent is still absent once the store is back.
    inner.set(|f| f.get = None);
    assert!(matches!(
        s.get_run("0002-b").await.unwrap_err(),
        StoreError::NoSuchRun(_)
    ));
}

#[tokio::test]
async fn decompiled_source_the_store_cannot_read_is_an_error_and_never_not_precomputed() {
    // `None` sends the member view to a live decompile or to the hex view; an error says the store
    // is broken. Reading the second as the first would hide a broken bucket behind a slower page.
    let (s, inner) = store();
    let assembly = Digest::from_bytes([2; 32]);
    s.put_decompiled(&assembly, "class A {}").await.unwrap();
    assert_eq!(
        s.get_decompiled(&assembly).await.unwrap().as_deref(),
        Some("class A {}")
    );
    assert_eq!(
        s.get_decompiled(&Digest::from_bytes([3; 32]))
            .await
            .unwrap(),
        None,
        "never computed is None"
    );

    inner.set(|f| f.get = Some("decompiled/".into()));
    assert_infra(&s.get_decompiled(&assembly).await.unwrap_err());
}

#[tokio::test]
async fn a_rederivation_sits_beside_the_recorded_comparison_and_never_replaces_it() {
    let (s, inner) = store();
    let recorded = s
        .blobs()
        .put(&b"{\"outcome\":\"divergent\"}"[..])
        .await
        .unwrap();
    assert_eq!(
        s.get_derived_comparison(&recorded).await.unwrap(),
        None,
        "never re-derived is None, not an empty document"
    );

    let derived = b"{\"outcome\":\"divergent\",\"progression\":{}}";
    s.put_derived_comparison(&recorded, derived).await.unwrap();
    assert_eq!(
        s.get_derived_comparison(&recorded)
            .await
            .unwrap()
            .as_deref(),
        Some(&derived[..])
    );
    // The recorded comparison is the evidence, and it is untouched: still at its own digest, still
    // the bytes that hash to it.
    assert_eq!(
        &s.blobs().get(&recorded).await.unwrap()[..],
        b"{\"outcome\":\"divergent\"}"
    );
    // Keyed by the comparison it re-derives, so another run's comparison has none.
    assert_eq!(
        s.get_derived_comparison(&Digest::from_bytes([9; 32]))
            .await
            .unwrap(),
        None
    );

    // An unreadable one is an error, never "never re-derived".
    inner.set(|f| f.get = Some("derived/".into()));
    assert_infra(&s.get_derived_comparison(&recorded).await.unwrap_err());
}

#[tokio::test]
async fn a_set_manifest_the_store_cannot_read_is_an_error_and_never_an_unknown_set() {
    // A verifier told "no such set" goes looking for a manifest that was never published; one told
    // the store is down asks again.
    let (s, inner) = store();
    let wheel = trigon_stabilize::profile("wheel").unwrap().manifest();
    s.put_stabilizer_set(&wheel).await.unwrap();

    inner.set(|f| f.get = Some("stabilizers/".into()));
    let e = s.get_stabilizer_set(&wheel.digest).await.unwrap_err();
    assert!(!matches!(e, StoreError::NoSuchSet(_)), "{e}");
    assert_infra(&e);
}

#[tokio::test]
async fn a_statement_that_cannot_be_written_is_an_error_and_names_no_path() {
    let (s, inner) = store();
    inner.set(|f| f.put = Some("attestations/".into()));
    let env = trigon_attest::Envelope::new(b"payload", vec![]);
    let e = s
        .put_attestation(
            &babel_core(),
            "1789000000-ab",
            "core-7.24.0.tgz",
            EQUIVALENCE,
            &env,
        )
        .await
        .unwrap_err();
    assert_infra(&e);

    // Nothing was filed, under the first name or beside it.
    inner.set(|f| f.put = None);
    let listed: Vec<ObjectMeta> = inner
        .list(Some(&Path::from("attestations")))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(listed.is_empty(), "{listed:?}");
}

#[tokio::test]
async fn naming_statements_on_a_record_the_store_cannot_read_fails_and_writes_nothing() {
    // The merge reads the record again before appending, so that a second attestor's paths are not
    // dropped. A read that fails must stop it: writing a record assembled from nothing would drop
    // every path the record held.
    let (s, inner) = store();
    let up = Digest::from_bytes([4; 32]);
    let mut r = record("1789000000-ab", &up);
    r.attestations = vec![
        "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/1789000000-ab/\
                           equivalence.intoto.json"
            .into(),
    ];
    s.put_run(&r).await.unwrap();

    inner.set(|f| f.get = Some("runs/".into()));
    let e = s
        .record_attestations("1789000000-ab", &["another/path.intoto.json".into()])
        .await
        .unwrap_err();
    assert_infra(&e);

    inner.set(|f| f.get = None);
    assert_eq!(
        s.get_run("1789000000-ab").await.unwrap(),
        r,
        "a failed merge changed the record"
    );
}

#[tokio::test]
async fn a_record_update_that_keeps_losing_gives_up_and_says_so() {
    // Each loss means another writer wrote the record in between, and the merge reads it again
    // with their change in it. A loss every time is something writing it in a loop: the merge
    // stops, returns the last loss as the failed write it is, and writes nothing unconditionally.
    let (s, inner) = store();
    let up = Digest::from_bytes([5; 32]);
    let r = record("1789000000-cd", &up);
    s.put_run(&r).await.unwrap();

    inner.set(|f| f.lose_every_update = true);
    let e = s
        .record_attestations("1789000000-cd", &["some/statement.intoto.json".into()])
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            StoreError::Object(object_store::Error::Precondition { .. })
        ),
        "{e}"
    );
    let tries = inner.updates.load(Ordering::SeqCst);
    assert!(
        tries > 1,
        "a lost conditional write was not tried again with the other writer's change: {tries}"
    );

    inner.set(|f| f.lose_every_update = false);
    assert_eq!(s.get_run("1789000000-cd").await.unwrap(), r);

    // And a write that fails for any other reason is not retried as though it had lost a race.
    let before = inner.updates.load(Ordering::SeqCst);
    inner.set(|f| f.put = Some("runs/".into()));
    let e = s
        .record_published(
            "1789000000-cd",
            &trigon_store::Published {
                repository: "file:///evidence".into(),
                commit: "0".repeat(40),
                record: Digest::from_bytes([6; 32]),
                leaf: 1,
                log: None,
            },
        )
        .await
        .unwrap_err();
    assert_infra(&e);
    assert_eq!(
        inner.updates.load(Ordering::SeqCst) - before,
        1,
        "a broken disk was not tried exactly once: it was retried as a lost race"
    );
}

#[tokio::test]
async fn an_artifact_whose_bytes_are_not_its_digest_is_corrupt_and_never_missing() {
    // Three answers, and each means something different: not kept by policy, kept and gone, and
    // kept and wrong. The third is somebody writing to the store who should not be.
    let inner = Arc::new(InMemory::new());
    let s = Store::new(inner.clone());
    let up = s.blobs().put(&b"the published artifact"[..]).await.unwrap();
    let hex = up.to_hex();
    inner
        .put(
            &Path::from(format!("blobs/sha256/{}/{hex}", &hex[..2])),
            PutPayload::from_static(b"a substituted artifact"),
        )
        .await
        .unwrap();
    let r = record("0010-x", &up);
    let e = s
        .artifact(&r.id, "published artifact", &r.upstream)
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::Corrupt { .. }), "{e}");
    assert_eq!(e.fault(), Fault::Bug);
    assert!(
        !e.is_retryable(),
        "the same bytes hash the same way the second time"
    );
}

#[tokio::test]
async fn put_repairs_a_blob_of_the_right_length_and_the_wrong_bytes() {
    // The length check is free and catches most substitutions; one of the same length costs a read,
    // and is overwritten like any other. `bytes_that_put_reported_stored_are_the_bytes_the_store_
    // gives_back` holds the wrong-length case.
    let inner = Arc::new(InMemory::new());
    let s = Store::new(inner.clone());
    let real = b"the rebuilt artifact, 32 bytes!!";
    let fake = b"a substituted one, also 32 bytes";
    assert_eq!(real.len(), fake.len());
    let d = trigon_store::digest_of(real);
    let hex = d.to_hex();
    inner
        .put(
            &Path::from(format!("blobs/sha256/{}/{hex}", &hex[..2])),
            PutPayload::from_static(fake),
        )
        .await
        .unwrap();

    assert_eq!(s.blobs().put(&real[..]).await.unwrap(), d);
    assert_eq!(&s.blobs().get(&d).await.unwrap()[..], &real[..]);
}

#[tokio::test]
async fn a_store_is_not_opened_where_there_is_no_directory_and_none_is_made() {
    // `existing` is for readers. A mistyped path presented as a real, empty store — "no record for
    // this target" about a store that never existed — is what it exists to prevent.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-store");
    let e = Store::existing(&missing).unwrap_err();
    // Its own variant and not `Malformed`, which is about a record: a path that names no store is
    // the command line's mistake, and `trigon` says so rather than asking for a bug report.
    assert!(
        matches!(&e, StoreError::NotAStore(p) if *p == missing),
        "{e}"
    );
    assert!(
        e.to_string().contains("no-such-store"),
        "the refusal names the path it was given: {e}"
    );
    assert_eq!(e.fault(), Fault::Bug);
    assert!(!e.is_retryable(), "a directory is not made by asking again");
    assert!(
        !missing.exists(),
        "a reader created the directory it was pointed at"
    );

    let file = dir.path().join("a-file");
    std::fs::write(&file, b"not a store").unwrap();
    assert!(matches!(
        Store::existing(&file).unwrap_err(),
        StoreError::NotAStore(_)
    ));

    // A directory that is there opens, and reads as the empty store it is.
    let s = Store::existing(dir.path()).unwrap();
    assert!(s.list_runs().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_thousand_statements_for_one_run_is_a_loop_and_is_refused_without_overwriting_one() {
    let inner = Arc::new(InMemory::new());
    let s = Store::new(inner.clone());
    let dir = "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/1789000000-ef";
    for n in 1..=1000 {
        let name = match n {
            1 => format!("{dir}/equivalence.intoto.json"),
            n => format!("{dir}/equivalence.{n}.intoto.json"),
        };
        inner
            .put(
                &Path::from(name),
                PutPayload::from(format!("statement {n}").into_bytes()),
            )
            .await
            .unwrap();
    }

    let env = trigon_attest::Envelope::new(b"yet another", vec![]);
    let e = s
        .put_attestation(
            &babel_core(),
            "1789000000-ef",
            "core-7.24.0.tgz",
            EQUIVALENCE,
            &env,
        )
        .await
        .unwrap_err();
    match &e {
        StoreError::NoFreeAttestationPath { first, .. } => {
            assert_eq!(first, &format!("{dir}/equivalence.intoto.json"));
        }
        other => panic!("a thousand-and-first statement was not refused as a loop: {other}"),
    }
    assert!(e.to_string().contains("re-attesting"), "{e}");
    // Something is attesting in a loop: somebody should look, and asking again is the loop.
    assert_eq!(e.fault(), Fault::Bug);
    assert!(!e.is_retryable());

    // Every statement already there is still what it was.
    for n in [1, 2, 500, 1000] {
        let name = match n {
            1 => format!("{dir}/equivalence.intoto.json"),
            n => format!("{dir}/equivalence.{n}.intoto.json"),
        };
        let there = inner
            .get(&Path::from(name))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(&there[..], format!("statement {n}").as_bytes());
    }
}

#[tokio::test]
async fn a_predicate_is_filed_under_its_name_and_never_under_its_schema_version() {
    // `…/equivalence/v1` is filed as `equivalence`, because every predicate shares the version and
    // filing by it would put them all at one path. A last segment that is not a version is the
    // name itself, including one that merely begins with a `v`.
    let s = Store::in_memory();
    let env = trigon_attest::Envelope::new(b"payload", vec![]);
    for (predicate, file) in [
        (EQUIVALENCE, "equivalence.intoto.json"),
        ("https://trigon.dev/void/v12", "void.intoto.json"),
        (
            "https://example.org/predicates/custom",
            "custom.intoto.json",
        ),
        (
            "https://example.org/predicates/vendor",
            "vendor.intoto.json",
        ),
        ("https://example.org/predicates/v", "v.intoto.json"),
    ] {
        let path = s
            .put_attestation(
                &babel_core(),
                "1789000000-aa",
                "core-7.24.0.tgz",
                predicate,
                &env,
            )
            .await
            .unwrap();
        assert!(
            path.ends_with(&format!("/1789000000-aa/{file}")),
            "{predicate} was filed at {path}"
        );
    }
}

#[tokio::test]
async fn pruning_a_run_with_no_rebuilt_bytes_kept_changes_nothing() {
    // Signed, matched, and with nothing of its own to drop: a run that produced no rebuilt artifact
    // and one whose rebuilt bytes were already dropped. Neither may touch the upstream artifact.
    let s = Store::in_memory();
    let up = s.blobs().put(&b"upstream"[..]).await.unwrap();

    let mut none = record("0020-none", &up);
    none.outcome = Some("normalized".into());
    none.attestations = vec!["attestations/x/equivalence.intoto.json".into()];
    s.put_run(&none).await.unwrap();
    assert_eq!(s.prune_rebuild("0020-none").await.unwrap(), Pruned::Kept);
    assert_eq!(s.get_run("0020-none").await.unwrap(), none);

    let rb = s.blobs().put(&b"rebuilt"[..]).await.unwrap();
    let mut dropped = none.clone();
    dropped.id = "0021-dropped".into();
    dropped.rebuild = Some(ArtifactRef {
        stored: false,
        ..artifact("core-7.24.0.tgz", &rb, 7)
    });
    s.put_run(&dropped).await.unwrap();
    let pruned = s.prune_rebuild("0021-dropped").await.unwrap();
    assert_eq!(pruned, Pruned::Kept);
    assert!(!pruned.dropped());
    assert_eq!(s.get_run("0021-dropped").await.unwrap(), dropped);
    assert!(s.blobs().has(&up).await.unwrap());
    assert!(
        s.blobs().has(&rb).await.unwrap(),
        "bytes the record already calls dropped are not the prune's to delete"
    );
}

#[tokio::test]
async fn each_refusal_the_store_makes_is_classified_as_what_it_is() {
    // Retrying a refusal the store makes on purpose answers the same way every time, and a caller
    // in a loop over one is a loop. Each is produced here the way the store produces it, rather
    // than built by hand, so the classification is of the error a caller actually receives.
    let s = Store::in_memory();

    let e = s.prune_rebuild("0030-absent").await.unwrap_err();
    assert!(matches!(e, StoreError::NoSuchRun(_)), "{e}");
    assert_eq!(e.fault(), Fault::Bug);
    assert!(
        !e.is_retryable(),
        "a run that was never written will not appear by asking again"
    );

    let tar = trigon_stabilize::profile("tar-gzip").unwrap().manifest();
    let e = s.get_stabilizer_set(&tar.digest).await.unwrap_err();
    assert!(matches!(e, StoreError::NoSuchSet(_)), "{e}");
    assert!(!e.is_retryable());

    let up = s.blobs().put(&b"upstream"[..]).await.unwrap();
    let rb = s.blobs().put(&b"rebuilt"[..]).await.unwrap();
    let mut unsigned = record("0031-unsigned", &up);
    unsigned.rebuild = Some(artifact("core-7.24.0.tgz", &rb, 7));
    s.put_run(&unsigned).await.unwrap();
    let e = s.prune_rebuild("0031-unsigned").await.unwrap_err();
    assert!(matches!(e, StoreError::NotAttested(_)), "{e}");
    assert_eq!(
        e.fault(),
        Fault::Policy,
        "a refusal we issued on purpose is policy"
    );
    assert!(!e.is_retryable());

    let mut m = trigon_stabilize::profile("wheel").unwrap().manifest();
    m.members[0].risk = "Structural".into();
    let e = s.put_stabilizer_set(&m).await.unwrap_err();
    assert!(matches!(e, StoreError::InconsistentSet { .. }), "{e}");
    assert_eq!(e.fault(), Fault::Bug);
    assert!(!e.is_retryable());

    let e = s.put_run(&record("../escape", &up)).await.unwrap_err();
    assert!(matches!(e, StoreError::Malformed(_)), "{e}");
    assert_eq!(
        e.fault(),
        Fault::Bug,
        "our own ids are `<unix>-<digest prefix>`"
    );
    assert!(!e.is_retryable());
}

#[test]
fn a_record_written_before_stored_existed_reads_as_kept() {
    // Every artifact was kept before retention could drop one, so a record from then says nothing
    // about `stored` and means `true`. Reading it as `false` would report every old artifact as
    // pruned, and send a verifier to the registry for bytes the store has.
    let old = serde_json::json!({
        "name": "core-7.24.0.tgz",
        "sha256": Digest::from_bytes([7; 32]),
        "bytes": 15,
    });
    let a: ArtifactRef = serde_json::from_value(old).unwrap();
    assert!(a.stored);
}

#[test]
fn an_outcome_this_build_does_not_know_is_unsupported_and_never_a_verdict() {
    // A record written by a newer build, or edited: whatever the word is, it is not one this build
    // can report as reproduced or as divergent, and the reason says what was found.
    let mut r = record("0040-new", &Digest::from_bytes([8; 32]));
    r.outcome = Some("partially_reproduced".into());
    let (status, why) = r.status();
    assert_eq!(status, trigon_core::Status::Unsupported);
    assert_eq!(why.as_deref(), Some("partially_reproduced"));
}
