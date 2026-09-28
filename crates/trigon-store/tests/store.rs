//! What the store has to guarantee for the attestor to be worth separating from the sandbox.

use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store, StoreError};

fn env() -> Environment {
    Environment {
        base_image: "docker.io/library/debian@sha256:aa".into(),
        derived_image: None,
        egress: "mirror-only".into(),
        isolation: "UserNs".into(),
        guard_manifest: None,
        guarded_members: None,
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
async fn a_model_assisted_run_keeps_the_exchange_it_came_out_of() {
    // `derivation: model_assisted` with no transcript is an assertion; with one it is a record.
    // Pruning is about the rebuilt artifact, which can be re-derived, and must not reach the
    // derivation, which cannot.
    let s = Store::in_memory();
    let up = s.blobs().put(&b"upstream"[..]).await.unwrap();
    let rb = s.blobs().put(&b"rebuilt"[..]).await.unwrap();
    let transcript = serde_json::json!({
        "target": "pkg:npm/a@1",
        "turns": [{
            "model": "claude-haiku-4-5-20251001",
            "temperature": 0.0,
            "prompt_sha256": "0".repeat(64),
            "system_sha256": "1".repeat(64),
            "answer": "kind: flow\n",
            "usage": { "input": 10, "cached_input": 8, "output": 2 },
            "stop_reason": "end_turn",
        }],
    });
    let t = s
        .blobs()
        .put(serde_json::to_vec(&transcript).unwrap())
        .await
        .unwrap();

    let mut r = RunRecord::new("0009", "pkg:npm/a@1", artifact("a.tgz", &up, 8), env(), "t");
    r.rebuild = Some(artifact("a.tgz", &rb, 7));
    r.outcome = Some("normalized".into());
    r.derivation = Some("model_assisted".into());
    r.transcript = Some(t);
    r.attestations = vec!["attestations/npm/a/1/a.tgz/equivalence.intoto.json".into()];
    s.put_run(&r).await.unwrap();

    assert!(s.prune_rebuild("0009").await.unwrap());
    assert!(!s.blobs().has(&rb).await.unwrap(), "the rebuild goes");
    assert!(
        s.blobs().has(&t).await.unwrap(),
        "and the transcript stays: it is the only account of how the strategy came to exist"
    );
    let back = s.get_run("0009").await.unwrap();
    assert_eq!(back.transcript, Some(t));
    assert_eq!(back.derivation.as_deref(), Some("model_assisted"));
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

fn babel_core() -> trigon_core::Target {
    let reference: trigon_core::TargetRef = "pkg:npm/@babel/core@7.24.0".parse().unwrap();
    trigon_core::Target::new(reference, trigon_core::ArtifactId::new("core-7.24.0.tgz"))
}

const EQUIVALENCE: &str = "https://trigon.dev/equivalence/v1";

#[tokio::test]
async fn an_attestation_is_filed_under_its_target_and_then_its_run() {
    // Under the target, so everything signed about one artifact lists under one prefix; under the
    // run below that, so a second run's statement cannot land on the first's.
    let s = Store::in_memory();
    let env = trigon_attest::Envelope::new(b"payload", vec![]);
    let path = s
        .put_attestation(
            &babel_core(),
            "1789000000-0a1b2c3d",
            "core-7.24.0.tgz",
            EQUIVALENCE,
            &env,
        )
        .await
        .unwrap();
    assert_eq!(
        path,
        "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/1789000000-0a1b2c3d/\
         equivalence.intoto.json"
    );
    assert_eq!(s.get_attestation(&path).await.unwrap(), env);
}

#[tokio::test]
async fn attesting_one_target_twice_leaves_both_runs_statements_readable() {
    // The overwrite this layout exists to end. Filed per target, the second attest wrote over the
    // first, and the first run's record went on naming a path that held the second run's claim:
    // 40 of 93 attestation paths in the local store were shared by more than one run.
    let s = Store::in_memory();
    let first = trigon_attest::Envelope::new(b"the first run's statement", vec![]);
    let second = trigon_attest::Envelope::new(b"the second run's statement", vec![]);
    let a = s
        .put_attestation(
            &babel_core(),
            "1789000000-aa",
            "core-7.24.0.tgz",
            EQUIVALENCE,
            &first,
        )
        .await
        .unwrap();
    let b = s
        .put_attestation(
            &babel_core(),
            "1789000100-bb",
            "core-7.24.0.tgz",
            EQUIVALENCE,
            &second,
        )
        .await
        .unwrap();
    assert_ne!(a, b);
    assert_eq!(s.get_attestation(&a).await.unwrap(), first);
    assert_eq!(s.get_attestation(&b).await.unwrap(), second);
}

#[tokio::test]
async fn a_run_attested_again_keeps_what_it_signed_before() {
    // Re-attesting a stored run is a supported thing to do: with a key it was first signed without,
    // or by a binary that signs a newer predicate. The earlier statement is history and stays.
    let dir = tempfile::tempdir().unwrap();
    let s = Store::local(dir.path()).unwrap();
    let unsigned = trigon_attest::Envelope::new(b"the claim", vec![]);
    let signed = trigon_attest::Envelope::new(
        b"the claim",
        vec![trigon_attest::Signature {
            keyid: "8238c7031caabae5".into(),
            sig: "c2ln".into(),
            ..Default::default()
        }],
    );
    let run = "1789000000-cc";
    let put = |e: &trigon_attest::Envelope| {
        let (s, e) = (s.clone(), e.clone());
        async move {
            s.put_attestation(&babel_core(), run, "core-7.24.0.tgz", EQUIVALENCE, &e)
                .await
                .unwrap()
        }
    };

    let first = put(&unsigned).await;
    let second = put(&signed).await;
    assert!(
        first.ends_with(&format!("/{run}/equivalence.intoto.json")),
        "{first}"
    );
    assert!(
        second.ends_with(&format!("/{run}/equivalence.2.intoto.json")),
        "{second}"
    );
    assert_eq!(s.get_attestation(&first).await.unwrap(), unsigned);
    assert_eq!(s.get_attestation(&second).await.unwrap(), signed);

    // The same bytes again are the same statement, and answered with the path they are at: an
    // unchanged re-attest adds nothing, rather than a third copy.
    assert_eq!(put(&signed).await, second);
    assert_eq!(put(&unsigned).await, first);
    let files = walk(dir.path());
    assert_eq!(files.len(), 2, "{files:?}");
}

#[tokio::test]
async fn a_statement_filed_per_target_before_runs_had_their_own_still_reads() {
    // Runs attested before the per-run layout name their statements one level up. A record names
    // its statements by path, so reading one is the same call whichever layout wrote it.
    let dir = tempfile::tempdir().unwrap();
    let old = "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/equivalence.intoto.json";
    let env = trigon_attest::Envelope::new(b"attested before phase 2", vec![]);
    let file = dir.path().join(old);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, serde_json::to_vec_pretty(&env).unwrap()).unwrap();

    let s = Store::local(dir.path()).unwrap();
    assert_eq!(s.get_attestation(old).await.unwrap(), env);

    // And a new statement about the same target does not disturb it.
    let new = trigon_attest::Envelope::new(b"attested after", vec![]);
    s.put_attestation(
        &babel_core(),
        "1789000200-dd",
        "core-7.24.0.tgz",
        EQUIVALENCE,
        &new,
    )
    .await
    .unwrap();
    assert_eq!(s.get_attestation(old).await.unwrap(), env);
}

#[tokio::test]
async fn a_withdrawal_is_filed_under_the_record_it_withdraws_and_never_overwritten() {
    // It has no run to be filed under (`docs/19` §3), so it goes under the record's digest, and a
    // second, different withdrawal of the same record is written beside the first.
    let s = Store::in_memory();
    let record = Digest::from_bytes([0x7f; 32]);
    let first = trigon_attest::Envelope::new(b"withdrawn", vec![]);
    let path = s.put_withdrawal(&record, &first).await.unwrap();
    assert_eq!(
        path,
        format!(
            "withdrawals/sha256/{}/withdrawal.intoto.json",
            record.to_hex()
        )
    );
    assert_eq!(s.get_attestation(&path).await.unwrap(), first);

    // The same bytes are the same statement.
    assert_eq!(s.put_withdrawal(&record, &first).await.unwrap(), path);
    let second = trigon_attest::Envelope::new(b"pipeline_bug", vec![]);
    let beside = s.put_withdrawal(&record, &second).await.unwrap();
    assert!(beside.ends_with("/withdrawal.2.intoto.json"), "{beside}");
    assert_eq!(s.get_attestation(&path).await.unwrap(), first);
    assert_eq!(s.get_attestation(&beside).await.unwrap(), second);
}

/// A run of `babel_core()` with nothing signed yet, written to `s`.
async fn unattested(s: &Store, id: &str) -> RunRecord {
    let up = s.blobs().put(&b"core-7.24.0.tgz"[..]).await.unwrap();
    let mut r = RunRecord::new(
        id,
        "pkg:npm/@babel/core@7.24.0",
        artifact("core-7.24.0.tgz", &up, 15),
        env(),
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = Some("exact".into());
    s.put_run(&r).await.unwrap();
    r
}

async fn file(s: &Store, run: &str, predicate: &str, payload: &[u8]) -> String {
    let env = trigon_attest::Envelope::new(payload, vec![]);
    s.put_attestation(&babel_core(), run, "core-7.24.0.tgz", predicate, &env)
        .await
        .unwrap()
}

#[tokio::test]
async fn statements_are_named_on_the_record_as_it_is_now_not_as_the_attestor_read_it() {
    // The attestor reads the record, re-derives and signs, and used to write back the copy it had
    // read. Two attestors on one run each wrote their own statement file, and the second's write
    // of the record dropped the first's path: the file on disk, named by nothing a reader uses.
    // The merge reads the record again, so the second call cannot lose the first's path.
    let s = Store::in_memory();
    let run = "1789000000-ab";
    let stale = unattested(&s, run).await;
    let first = file(&s, run, EQUIVALENCE, b"unsigned").await;
    let second = file(&s, run, EQUIVALENCE, b"signed").await;

    s.record_attestations(run, std::slice::from_ref(&first))
        .await
        .unwrap();
    let back = s
        .record_attestations(run, std::slice::from_ref(&second))
        .await
        .unwrap();
    assert!(stale.attestations.is_empty(), "both attestors read this");
    assert_eq!(back.attestations, [first.clone(), second.clone()]);
    assert_eq!(s.get_run(run).await.unwrap(), back);

    // The same path again adds nothing.
    let again = s.record_attestations(run, &[first]).await.unwrap();
    assert_eq!(again.attestations.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attestors_racing_on_one_run_all_end_up_named_where_writes_are_conditional() {
    // In memory, as on object storage, the record's write is conditional on the version read and
    // retried when it lost. Eight writers at once, and every path survives.
    let s = Store::in_memory();
    let run = "1789000000-cd";
    unattested(&s, run).await;
    let mut paths = Vec::new();
    for n in 0..8 {
        let predicate = format!("https://trigon.dev/racer{n}/v1");
        paths.push(file(&s, run, &predicate, b"x").await);
    }
    let writers: Vec<_> = paths
        .iter()
        .map(|p| {
            let (s, p) = (s.clone(), p.clone());
            tokio::spawn(async move { s.record_attestations(run, &[p]).await })
        })
        .collect();
    for w in writers {
        w.await.unwrap().unwrap();
    }
    let mut named = s.get_run(run).await.unwrap().attestations;
    named.sort();
    paths.sort();
    assert_eq!(named, paths);
}

#[tokio::test]
async fn a_local_store_names_statements_without_a_conditional_write() {
    // `object_store` has no `PutMode::Update` for the local filesystem, which is where the owner's
    // store lives. It still merges from a fresh read rather than refusing.
    let dir = tempfile::tempdir().unwrap();
    let s = Store::local(dir.path()).unwrap();
    let run = "1789000000-ef";
    unattested(&s, run).await;
    let a = file(&s, run, EQUIVALENCE, b"a").await;
    let b = file(&s, run, "https://trigon.dev/rebuild/v1", b"b").await;
    s.record_attestations(run, std::slice::from_ref(&a))
        .await
        .unwrap();
    s.record_attestations(run, std::slice::from_ref(&b))
        .await
        .unwrap();
    assert_eq!(s.get_run(run).await.unwrap().attestations, [a, b]);

    let e = s
        .record_attestations("1789000000-00", &[])
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::NoSuchRun(_)), "{e}");
}

#[tokio::test]
async fn a_run_attested_again_sets_its_per_target_paths_aside_and_names_only_its_own() {
    // A per-target path was shared by every run of the target, and a later run may have written
    // over it: what it holds is whoever attested last. Left beside the run's own statements, it
    // went on being served as this run's.
    let s = Store::in_memory();
    let run = "1789000000-0f";
    let mut r = unattested(&s, run).await;
    let per_target = [
        "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/equivalence.intoto.json".to_string(),
        "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/buildobservation.intoto.json"
            .to_string(),
    ];
    r.attestations = per_target.to_vec();
    s.put_run(&r).await.unwrap();

    let own = file(&s, run, EQUIVALENCE, b"filed under the run").await;
    let back = s
        .record_attestations(run, std::slice::from_ref(&own))
        .await
        .unwrap();
    assert_eq!(back.attestations, [own]);
    assert_eq!(
        back.per_target_attestations, per_target,
        "kept, and not served"
    );

    // A run with no statement of its own yet keeps what it names: nothing replaces it.
    let other = "1789000100-1f";
    let mut o = unattested(&s, other).await;
    o.attestations = per_target.to_vec();
    s.put_run(&o).await.unwrap();
    let back = s.record_attestations(other, &[]).await.unwrap();
    assert_eq!(back.attestations, per_target);
    assert!(back.per_target_attestations.is_empty());
}

#[tokio::test]
async fn a_statement_is_not_filed_under_a_run_id_the_store_would_not_write() {
    // The run id is now a path segment. One the store refuses for a run record it refuses here.
    let s = Store::in_memory();
    let env = trigon_attest::Envelope::new(b"x", vec![]);
    for bad in ["", "../escape", ".hidden", "a b"] {
        let e = s
            .put_attestation(&babel_core(), bad, "core-7.24.0.tgz", EQUIVALENCE, &env)
            .await
            .unwrap_err();
        assert!(matches!(e, StoreError::Malformed(_)), "{bad:?}: {e}");
    }
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
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
        toolchain_requests: 1,
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
