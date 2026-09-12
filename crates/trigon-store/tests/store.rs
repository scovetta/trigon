//! What the store has to guarantee for the attestor to be worth separating from the sandbox.

use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store, StoreError};

fn env() -> Environment {
    Environment {
        base_image: "docker.io/library/debian@sha256:aa".into(),
        egress: "mirror-only".into(),
        isolation: "UserNs".into(),
        attestable: true,
        registry_moment: Some("2018-04-09T01:10:45Z".into()),
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

#[tokio::test]
async fn a_blob_is_addressed_by_what_it_contains() {
    let s = Store::in_memory();
    let a = s.blobs().put(&b"hello"[..]).await.unwrap();
    let b = s.blobs().put(&b"hello"[..]).await.unwrap();
    assert_eq!(a, b, "the same bytes are the same blob");
    assert_ne!(a, s.blobs().put(&b"world"[..]).await.unwrap());
    assert_eq!(&s.blobs().get(&a).await.unwrap()[..], b"hello");
    assert!(s.blobs().has(&a).await.unwrap());
}

#[tokio::test]
async fn reading_a_blob_checks_it_against_the_digest_it_was_asked_for() {
    // The reason the attestor can be separated at all. It trusts the hash, not the process that
    // wrote the bytes — and the store is exactly the thing a compromised worker can write to.
    use object_store::{ObjectStoreExt as _, PutPayload, path::Path};
    let inner = std::sync::Arc::new(object_store::memory::InMemory::new());
    let s = Store::new(inner.clone());

    let d = s.blobs().put(&b"the real artifact"[..]).await.unwrap();
    // Overwrite the blob in place, the way something with write access to the store would.
    let hex = d.to_hex();
    inner
        .put(
            &Path::from(format!("blobs/sha256/{}/{hex}", &hex[..2])),
            PutPayload::from_static(b"a substituted artifact"),
        )
        .await
        .unwrap();

    let e = s.blobs().get(&d).await.unwrap_err();
    assert!(matches!(e, StoreError::Corrupt { .. }), "{e}");
    assert!(e.to_string().contains("do not match"), "{e}");
    // And it is our bug, not the registry's: the store lost data or something wrote to it.
    assert_eq!(trigon_core::Classify::fault(&e), trigon_core::Fault::Bug);
}

#[tokio::test]
async fn a_run_record_round_trips() {
    let s = Store::in_memory();
    let up = s.blobs().put(&b"upstream bytes"[..]).await.unwrap();
    let mut r = RunRecord::new(
        "0001-abc",
        "pkg:npm/left-pad@1.3.0",
        artifact("left-pad-1.3.0.tgz", &up, 14),
        env(),
        "2026-09-11T19:00:00Z",
    );
    r.outcome = Some("normalized".into());
    r.state = RunState::Done;
    r.failure = None;
    r.timings = vec![("deps".into(), Some(12.5)), ("build".into(), None)];

    s.put_run(&r).await.unwrap();
    let back = s.get_run("0001-abc").await.unwrap();
    assert_eq!(back, r);
    // `None` means no data, never zero. A timing we failed to read is not a phase that took no time.
    assert_eq!(back.timings[1].1, None);
}

#[tokio::test]
async fn a_run_record_carries_a_failure_signature() {
    // The type has to survive a file, because this is where it ends up.
    let s = Store::in_memory();
    let up = s.blobs().put(&b"x"[..]).await.unwrap();
    let mut r = RunRecord::new("0002", "pkg:npm/a@1", artifact("a.tgz", &up, 1), env(), "t");
    r.failure = Some(trigon_core::classify(
        "fatal error: Python.h: No such file or directory",
    ));
    s.put_run(&r).await.unwrap();
    let back = s.get_run("0002").await.unwrap();
    assert_eq!(
        back.failure.as_ref().map(|f| f.key()).as_deref(),
        Some("cc/missing-header:python.h")
    );
}

#[tokio::test]
async fn a_missing_run_says_so_rather_than_failing_obscurely() {
    let s = Store::in_memory();
    let e = s.get_run("nope").await.unwrap_err();
    assert!(matches!(e, StoreError::NoSuchRun(_)), "{e}");
}

#[tokio::test]
async fn a_tripped_guard_means_the_run_is_evidence_of_nothing() {
    // The one question a consumer of a record must not get wrong, which is why it is a method and
    // not a convention about reading two fields together.
    let d = Digest::from_bytes([0; 32]);
    let mut r = RunRecord::new("0003", "pkg:npm/a@1", artifact("a.tgz", &d, 1), env(), "t");
    r.outcome = Some("exact".into());
    assert!(r.is_evidence());
    r.guard_trips = vec!["the artifact arrived from registry.npmjs.org".into()];
    assert!(
        !r.is_evidence(),
        "a perfect match from a build that downloaded its own output proves nothing"
    );
}

#[tokio::test]
async fn pruning_refuses_a_run_nothing_has_signed() {
    // Pruning first would leave a statement nobody can check, which is the one outcome the whole
    // design exists to avoid.
    let s = Store::in_memory();
    let up = s.blobs().put(&b"upstream"[..]).await.unwrap();
    let rb = s.blobs().put(&b"rebuild"[..]).await.unwrap();
    let mut r = RunRecord::new("0004", "pkg:npm/a@1", artifact("a.tgz", &up, 8), env(), "t");
    r.rebuild = Some(artifact("a.tgz", &rb, 7));
    r.outcome = Some("normalized".into());
    s.put_run(&r).await.unwrap();

    let e = s.prune_rebuild("0004").await.unwrap_err();
    assert!(matches!(e, StoreError::NotAttested(_)), "{e}");
    assert!(
        s.blobs().has(&rb).await.unwrap(),
        "the bytes are still there"
    );

    // Once something has signed for it, the bytes can go and the digests stay.
    r.attestations = vec!["attestations/npm/a/1/a.tgz/equivalence.intoto.json".into()];
    s.put_run(&r).await.unwrap();
    assert!(s.prune_rebuild("0004").await.unwrap());
    assert!(!s.blobs().has(&rb).await.unwrap());

    let back = s.get_run("0004").await.unwrap();
    assert_eq!(
        back.rebuild.as_ref().unwrap().sha256,
        rb,
        "the digest stays"
    );
    assert!(
        !back.rebuild.as_ref().unwrap().stored,
        "and the record says the bytes are gone rather than leaving it to be discovered"
    );
    // The upstream artifact is never pruned: it is what a consumer already has.
    assert!(s.blobs().has(&up).await.unwrap());
}

#[tokio::test]
async fn a_divergence_keeps_its_bytes() {
    // A divergence is a public claim about someone else's package. A maintainer who cannot obtain
    // the artifact we compared against has no way to answer it.
    let s = Store::in_memory();
    let up = s.blobs().put(&b"upstream"[..]).await.unwrap();
    let rb = s.blobs().put(&b"different"[..]).await.unwrap();
    let mut r = RunRecord::new("0005", "pkg:npm/a@1", artifact("a.tgz", &up, 8), env(), "t");
    r.rebuild = Some(artifact("a.tgz", &rb, 9));
    r.outcome = Some("divergent".into());
    r.attestations = vec!["attestations/npm/a/1/a.tgz/divergence.intoto.json".into()];
    s.put_run(&r).await.unwrap();

    assert!(!s.prune_rebuild("0005").await.unwrap());
    assert!(s.blobs().has(&rb).await.unwrap());
}

#[tokio::test]
async fn an_exact_match_does_not_prune_the_one_blob_both_sides_share() {
    // Both sides are the same bytes, so they are the same blob. Deleting "the rebuild" would take
    // the upstream artifact with it.
    let s = Store::in_memory();
    let d = s.blobs().put(&b"identical"[..]).await.unwrap();
    let mut r = RunRecord::new("0006", "pkg:npm/a@1", artifact("a.tgz", &d, 9), env(), "t");
    r.rebuild = Some(artifact("a.tgz", &d, 9));
    r.outcome = Some("exact".into());
    r.attestations = vec!["somewhere".into()];
    s.put_run(&r).await.unwrap();

    assert!(s.prune_rebuild("0006").await.unwrap());
    assert!(
        s.blobs().has(&d).await.unwrap(),
        "the shared blob is still the upstream artifact"
    );
}

#[tokio::test]
async fn runs_list_most_recent_first() {
    let s = Store::in_memory();
    let d = Digest::from_bytes([1; 32]);
    for id in ["0001-a", "0003-c", "0002-b"] {
        s.put_run(&RunRecord::new(
            id,
            "pkg:npm/a@1",
            artifact("a.tgz", &d, 1),
            env(),
            "t",
        ))
        .await
        .unwrap();
    }
    assert_eq!(s.list_runs().await.unwrap(), ["0003-c", "0002-b", "0001-a"]);
}

#[tokio::test]
async fn an_attestation_is_filed_where_someone_with_the_published_artifact_would_look() {
    // Keyed by target, not by run id. A layout keyed on our run id is findable only by someone who
    // already has our run id, which is nobody.
    let s = Store::in_memory();
    let reference: trigon_core::TargetRef = "pkg:npm/@babel/core@7.24.0".parse().unwrap();
    let target =
        trigon_core::Target::new(reference, trigon_core::ArtifactId::new("core-7.24.0.tgz"));
    let env = trigon_attest::Envelope::new(b"payload", vec![]);
    let path = s
        .put_attestation(
            &target,
            "core-7.24.0.tgz",
            "https://trigon.dev/equivalence/v1",
            &env,
        )
        .await
        .unwrap();
    assert_eq!(
        path,
        "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/equivalence.intoto.json"
    );
    assert_eq!(s.get_attestation(&path).await.unwrap(), env);
}

#[tokio::test]
async fn a_local_store_is_readable_by_a_process_that_did_not_write_it() {
    // The whole point of separating the attestor: a second process, opening the same directory,
    // finds the run and its bytes with nothing shared but the filesystem.
    let dir = tempfile::tempdir().unwrap();
    let written = {
        let s = Store::local(dir.path()).unwrap();
        let up = s.blobs().put(&b"published bytes"[..]).await.unwrap();
        let r = RunRecord::new(
            "0007",
            "pkg:npm/a@1",
            artifact("a.tgz", &up, 15),
            env(),
            "t",
        );
        s.put_run(&r).await.unwrap();
        up
    };

    let reader = Store::local(dir.path()).unwrap();
    let r = reader.get_run("0007").await.unwrap();
    assert_eq!(r.upstream.sha256, written);
    assert_eq!(
        &reader.blobs().get(&written).await.unwrap()[..],
        b"published bytes"
    );
}

#[tokio::test]
async fn a_pinned_moment_is_recorded_with_the_evidence_that_it_bound_something() {
    // A `registry_moment` describes how a build was configured, not how it resolved, and the two
    // came apart silently: pip ignores an untrusted plain-HTTP index after one warning and resolves
    // against the live one, so every PyPI run recorded a pin it did not have. The evidence sits
    // beside the claim so a reader can tell which they are looking at.
    use trigon_store::PinEvidence;
    let s = Store::in_memory();
    let d = Digest::from_bytes([4; 32]);

    let bound = PinEvidence {
        index_requests: 153,
        versions_withheld: 903,
        artifact_requests: 40,
        rejected: 0,
    };
    assert!(bound.bound());
    let unproven = PinEvidence {
        index_requests: 0,
        ..bound
    };
    assert!(!unproven.bound(), "nothing went through the time filter");

    let mut r = RunRecord::new(
        "0008",
        "pkg:pypi/a@1",
        artifact("a.whl", &d, 1),
        Environment {
            registry_moment: Some("2024-02-25T23:20:01Z".into()),
            pin: Some(unproven),
            ..env()
        },
        "t",
    );
    r.outcome = Some("normalized".into());
    s.put_run(&r).await.unwrap();

    let back = s.get_run("0008").await.unwrap();
    let pin = back.environment.pin.unwrap();
    assert!(!pin.bound());
    // The moment is still there. An unproven pin is not an absent one, and erasing it would hide
    // what the build was trying to do.
    assert_eq!(
        back.environment.registry_moment.as_deref(),
        Some("2024-02-25T23:20:01Z")
    );
}

#[tokio::test]
async fn no_mirror_is_a_third_state_rather_than_an_unproven_pin() {
    // Nothing was configured, so there is nothing to prove — distinct from a pin that was claimed
    // and cannot be confirmed, which is the case worth investigating.
    let d = Digest::from_bytes([5; 32]);
    let r = RunRecord::new(
        "0009",
        "pkg:npm/a@1",
        artifact("a.tgz", &d, 1),
        Environment {
            registry_moment: None,
            pin: None,
            ..env()
        },
        "t",
    );
    assert!(r.environment.pin.is_none());
    assert!(r.environment.registry_moment.is_none());
}

#[tokio::test]
async fn a_published_set_manifest_is_checked_against_the_digest_asked_for() {
    // Two checks, not one. A self-consistent manifest for some *other* set is a perfectly correct
    // document and the wrong answer, so recomputing it is not enough on its own.
    let s = Store::in_memory();
    let wheel = trigon_stabilize::profile("wheel").unwrap().manifest();
    let tar = trigon_stabilize::profile("tar-gzip").unwrap().manifest();
    assert_ne!(wheel.digest, tar.digest);

    let path = s.put_stabilizer_set(&wheel).await.unwrap();
    assert_eq!(path, format!("stabilizers/sha256/{}.json", wheel.digest));
    assert_eq!(s.get_stabilizer_set(&wheel.digest).await.unwrap(), wheel);

    // Asking for a set that was never published says so rather than failing obscurely — this is
    // the case a verifier with an old attestation actually hits.
    let e = s.get_stabilizer_set(&tar.digest).await.unwrap_err();
    assert!(matches!(e, StoreError::NoSuchSet(_)), "{e}");
}

#[tokio::test]
async fn a_manifest_that_does_not_describe_its_own_digest_is_refused() {
    // Both on the way in and on the way out. A document asserting a digest it cannot reproduce is
    // the same class of problem as a blob that does not hash to its own address.
    use object_store::{ObjectStoreExt as _, PutPayload, path::Path};
    let inner = std::sync::Arc::new(object_store::memory::InMemory::new());
    let s = Store::new(inner.clone());
    let mut m = trigon_stabilize::profile("wheel").unwrap().manifest();

    m.members[0].risk = "Structural".into();
    let e = s.put_stabilizer_set(&m).await.unwrap_err();
    assert!(matches!(e, StoreError::InconsistentSet { .. }), "{e}");

    // And the same edit made directly in the store is caught on read, because a writer we do not
    // control is exactly who this protects against.
    let good = trigon_stabilize::profile("wheel").unwrap().manifest();
    s.put_stabilizer_set(&good).await.unwrap();
    let mut tampered = good.clone();
    tampered.members[0].risk = "Structural".into();
    inner
        .put(
            &Path::from(format!("stabilizers/sha256/{}.json", good.digest)),
            PutPayload::from(serde_json::to_vec(&tampered).unwrap()),
        )
        .await
        .unwrap();
    let e = s.get_stabilizer_set(&good.digest).await.unwrap_err();
    assert!(matches!(e, StoreError::InconsistentSet { .. }), "{e}");
}
