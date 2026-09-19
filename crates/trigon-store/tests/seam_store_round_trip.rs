//! What the store writes, it must read back unchanged.
//!
//! The store is the only thing standing between the sandbox and the attestor. `trigon attest` reads
//! a run record and blobs out of it and signs a statement assembled from what it finds, so a field
//! that does not survive the trip is not a cosmetic loss: it is a field the signature covers wrongly
//! or does not cover at all. A `guard_trips` entry dropped on the way through serde turns a void run
//! into a clean one; a `pin` dropped turns an unproven pin into no pin; a `stored: false` dropped
//! turns a pruned artifact into one a verifier will go looking for.
//!
//! `tests/store.rs` already covers the individual behaviours — addressing, pruning, the two checks
//! on a set manifest. What it does not do is populate a record *completely* and demand it back, and
//! a serde attribute only ever drops the field nobody put a value in. This file is the demand.
//!
//! It also pins the boundary `docs/threat-model.md` D6 draws: the store hash-checks blobs and does
//! not check its own records. Both halves of that sentence are asserted here, so the disclaimer
//! cannot quietly stop being true in either direction.

use std::collections::BTreeSet;
use std::path::{Path as FsPath, PathBuf};

use trigon_core::{Classify as _, Digest, Ecosystem, Fault, TargetRef};
use trigon_store::{
    ArtifactRef, Costs, Environment, PinEvidence, RunRecord, RunState, Store, StoreError, Tokens,
};

/// Every file under `root`, relative and slash-separated.
///
/// The tests that care about paths care about them as the filesystem sees them, not as
/// `object_store` reports them — the whole point of the traversal test is that the two can differ.
fn files_under(root: &FsPath) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(
                    p.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    out
}

/// A record with **every** field carrying a value a default would not produce.
///
/// Deliberately hostile to defaults: no `None`, no empty collection, no `false` where `true` is the
/// serde default, no zero where the field is a counter. A field that reads back equal here read
/// back because it was written, not because both sides agreed on nothing.
fn every_field_populated() -> RunRecord {
    RunRecord {
        id: "0001-full".into(),
        target: "pkg:npm/@babel/core@7.24.0".into(),
        // Not `Done`: a state that is nobody's default, so a dropped field cannot masquerade.
        state: RunState::Judging,
        outcome: Some("normalized_with_caveats".into()),
        // Not 1, which is the serde default and what a dropped field would read back as. The
        // publication gate keys on this pair: a record that loses them looks like a first and only
        // attempt, which is the value that leaves a confirmed result withheld forever.
        attempt: 3,
        cache_key: Some("babel-core-7.24.0/ab54e552/nupkg-2b104124".into()),
        // What the log said, every field set. The SET especially: a record that carries an index
        // and an instant but loses the log's signature over them has kept the claim and dropped
        // the only thing that makes it checkable.
        //
        // Real values from staging index 56041854, with `body` elided — this test is about the
        // fields surviving a round trip and verifies no signature. The entry that really is
        // verified offline lives in `trigon-attest/tests/transparency_live_entry.rs`.
        transparency: Some(trigon_attest::LogEntry {
            log: "https://rekor.sigstage.dev".into(),
            uuid: "71d46696179fcd5d91e308b5d6453380e77da0647e5f7afbfa557fcf00c0f97172182ce03da97706".into(),
            log_index: 56_041_854,
            integrated_time: 1_789_568_827,
            log_id: "d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496".into(),
            signed_entry_timestamp: "MEQCIGJAOvbuGC/JZnL7MCEqxbiyN5JUjurHTuccwv+9LIP/AiAfz0bt6mxmho7w2v5xBMbdSwTiU6VAMWT7vW+K95P82w=="
                .into(),
            body: "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaW50…".into(),
        }),
        // The source half of the verdict. Every field set, `declared_url` included: it is the one
        // that says what the package pointed at before we trimmed it, and a record that drops it
        // cannot be checked against the registry.
        source: Some(trigon_core::SourceProvenance {
            repo_url: "https://github.com/babel/babel".into(),
            declared_url: Some(
                "https://github.com/babel/babel/tree/main/packages/babel-core".into(),
            ),
            commit: "a0e1d9a6f4f2d52a9e3c8b7a6d5e4f3c2b1a0987".into(),
            ref_name: Some("v7.24.0".into()),
            subdir: Some("packages/babel-core".into()),
            how: trigon_core::SourceDiscovery::FuzzyTag,
        }),
        // A refusal and a trip in the same record, because they mean opposite things and only one of
        // them makes the run void. `is_evidence` keys on `guard_trips` alone.
        refused_artifact: vec![
            "GUARD-REFUSED https://files.pythonhosted.org/packages/aa/packaging-26.3.whl".into(),
        ],
        guard_trips: vec![
            "the artifact under test arrived from registry.npmjs.org".into(),
            "and again from a mirror".into(),
        ],
        started: "2026-09-11T19:00:00Z".into(),
        finished: Some("2026-09-11T19:04:11Z".into()),
        environment: Environment {
            base_image: "docker.io/library/debian@sha256:aa".into(),
            egress: "mirror-only".into(),
            isolation: "UserNs".into(),
            guard_manifest: None,
            guarded_members: None,
            // `false` is the interesting value: it is the one that keeps a run out of a full-trust
            // statement, so it is the one a dropped field would silently convert to `true`.
            attestable: false,
            registry_moment: Some("2018-04-09T01:10:45Z".into()),
            pin: Some(PinEvidence {
                index_requests: 153,
                versions_withheld: 903,
                artifact_requests: 40,
                toolchain_requests: 1,
                rejected: 7,
            }),
        },
        strategy: Some(Digest::from_bytes([1; 32])),
        strategy_digest: Some(Digest::from_bytes([1; 32]).to_hex()),
        derivation: Some("model_assisted".into()),
        instructions: Some(Digest::from_bytes([2; 32])),
        upstream: ArtifactRef {
            name: "core-7.24.0.tgz".into(),
            sha256: Digest::from_bytes([3; 32]),
            bytes: 1_234_567,
            stored: true,
        },
        rebuild: Some(ArtifactRef {
            name: "core-7.24.0.tgz".into(),
            sha256: Digest::from_bytes([4; 32]),
            bytes: 1_234_566,
            // `stored` defaults to *true* for records written before the field existed, so `false`
            // is the value a missing `#[serde(default = "yes")]` or a dropped key would invert. It
            // is also the one a verifier acts on: it is the difference between "pruned after a
            // match" and "go and fetch these bytes".
            stored: false,
        }),
        comparison: Some(Digest::from_bytes([5; 32])),
        build_log: Some(Digest::from_bytes([6; 32])),
        // Both inhabitants of the option, in one vector: a phase we timed, and a phase whose timing
        // we failed to read. Collapsing the second into `0.0` understates every build that contains
        // one, which is why the type is what it is.
        timings: vec![
            ("deps".into(), Some(12.5)),
            ("build".into(), None),
            ("compare".into(), Some(0.0)),
        ],
        failure: Some(trigon_core::classify(
            "fatal error: Python.h: No such file or directory",
        )),
        transcript: Some(Digest::from_bytes([7; 32])),
        network_transcript: Some(Digest::from_bytes([8; 32])),
        costs: Some(Costs {
            inference_seconds: Some(41.5),
            tokens: vec![Tokens {
                input: 120_400,
                // Deliberately non-zero and *less* than `input`: it is a subset, and a record that
                // read it back as an addition would double-count every cached token.
                cached_input: 98_000,
                output: 3_140,
                model: "claude-opus-5".into(),
                calls: 3,
            }],
            build_seconds: Some(212.75),
            // Not zero. Zero is the other interesting value and it means something different, so
            // the populated record uses a number no default would produce.
            egress_bytes: Some(268_435_456),
            blob_bytes: Some(3_145_728),
            artifact_bytes: Some(2_469_134),
            log_bytes: Some(65_536),
        }),
        attestations: vec![
            "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/equivalence.intoto.json".into(),
            "attestations/npm/@babel/core/7.24.0/core-7.24.0.tgz/rebuild.intoto.json".into(),
        ],
    }
}

#[tokio::test]
async fn every_field_of_a_run_record_survives_the_file_it_is_written_to() {
    // The attestor is a separate process reading this file cold. Anything serde drops between the
    // two is a fact the signed statement is missing or wrong about, and the way it goes missing is
    // never loud: a rename, an over-eager `skip_serializing_if`, a `default` that fills a hole with
    // a plausible value. So populate everything and demand everything.
    let store = Store::in_memory();
    let record = every_field_populated();
    store.put_run(&record).await.unwrap();
    let back = store.get_run("0001-full").await.unwrap();

    // Field by field first, because `assert_eq!` on the whole struct names the record and not the
    // field, and the field is the thing somebody has to go and fix.
    assert_eq!(back.id, record.id, "id");
    assert_eq!(back.target, record.target, "target");
    assert_eq!(back.state, record.state, "state");
    assert_eq!(back.outcome, record.outcome, "outcome");
    assert_eq!(
        back.guard_trips, record.guard_trips,
        "guard_trips: this is the field that decides whether the run is evidence at all"
    );
    assert_eq!(back.started, record.started, "started");
    assert_eq!(back.finished, record.finished, "finished");
    assert_eq!(
        back.environment.base_image, record.environment.base_image,
        "environment.base_image"
    );
    assert_eq!(
        back.environment.egress, record.environment.egress,
        "environment.egress"
    );
    assert_eq!(
        back.environment.isolation, record.environment.isolation,
        "environment.isolation"
    );
    assert!(
        !back.environment.attestable,
        "environment.attestable: `false` must survive, or an unobserved run reads as a full-trust one"
    );
    assert_eq!(
        back.environment.registry_moment, record.environment.registry_moment,
        "environment.registry_moment"
    );
    let pin = back.environment.pin.expect("environment.pin");
    assert_eq!(pin, record.environment.pin.unwrap(), "environment.pin");
    assert_eq!(
        pin.toolchain_requests, 1,
        "environment.pin.toolchain_requests: the one fetched thing that then *runs*, and the \
         newest field here, so the one most likely to be missing a `default`"
    );
    assert_eq!(pin.rejected, 7, "environment.pin.rejected");
    assert_eq!(back.strategy, record.strategy, "strategy");
    assert_eq!(
        back.strategy_digest, record.strategy_digest,
        "strategy_digest"
    );
    assert_eq!(back.derivation, record.derivation, "derivation");
    assert_eq!(back.instructions, record.instructions, "instructions");
    assert_eq!(back.upstream, record.upstream, "upstream");
    let rebuild = back.rebuild.clone().expect("rebuild");
    assert_eq!(rebuild, record.rebuild.clone().unwrap(), "rebuild");
    assert!(
        !rebuild.stored,
        "rebuild.stored: `false` must survive, or a pruned artifact reads as one still in the store"
    );
    assert_eq!(back.comparison, record.comparison, "comparison");
    assert_eq!(back.build_log, record.build_log, "build_log");
    assert_eq!(back.timings, record.timings, "timings");
    assert_eq!(
        back.timings[1].1, None,
        "timings: an unread timing must not come back as a phase that took no time"
    );
    assert_eq!(
        back.timings[2].1,
        Some(0.0),
        "timings: and a phase that really took no time must not come back as unread"
    );
    assert_eq!(back.failure, record.failure, "failure");
    assert_eq!(
        back.failure.as_ref().unwrap().subject.as_deref(),
        Some("python.h"),
        "failure.subject: half the cluster key, and the only optional field in the signature"
    );
    assert_eq!(back.transcript, record.transcript, "transcript");
    assert_eq!(
        back.network_transcript, record.network_transcript,
        "network_transcript: present and empty is not the same as absent, and `attestable` is \
         derived from which of the two it is"
    );
    assert_eq!(back.costs, record.costs, "costs");
    let tokens = &back.costs.as_ref().unwrap().tokens[0];
    assert!(
        tokens.cached_input < tokens.input,
        "cached_input is a subset of input, not an addition: reading it back as one makes a \
         well-cached run look more expensive than a cold one"
    );
    assert_eq!(back.attestations, record.attestations, "attestations");

    // And the whole thing, which catches anything the list above forgot to name.
    assert_eq!(back, record);
}

#[tokio::test]
async fn the_round_trip_above_is_told_when_a_field_is_added_to_the_record() {
    // A round-trip test is only as good as the record it round-trips, and a record grows fields.
    // The failure this guards against is the quiet one: somebody adds `network_transcript` to
    // `RunRecord`, every existing test still passes because none of them set it, and the field's
    // serde behaviour is never exercised until an attestation is wrong about it.
    //
    // So pin the shape. If this fails, add the new field to `every_field_populated` with a value no
    // default would produce, and add an assertion for it above.
    let json = serde_json::to_value(every_field_populated()).unwrap();
    let keys: BTreeSet<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "id",
        "target",
        "state",
        "outcome",
        "guard_trips",
        "started",
        "finished",
        "attempt",
        "cache_key",
        "environment",
        "strategy",
        "strategy_digest",
        "derivation",
        "source",
        "transparency",
        "instructions",
        "upstream",
        "rebuild",
        "comparison",
        "build_log",
        "timings",
        "failure",
        "refused_artifact",
        "transcript",
        "network_transcript",
        "costs",
        "attestations",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        keys, expected,
        "a fully populated RunRecord no longer writes exactly these keys"
    );

    let env = json.get("environment").unwrap().as_object().unwrap();
    let env_keys: BTreeSet<&str> = env.keys().map(|s| s.as_str()).collect();
    assert_eq!(
        env_keys,
        [
            "base_image",
            "egress",
            "isolation",
            "attestable",
            "registry_moment",
            "pin"
        ]
        .into_iter()
        .collect::<BTreeSet<&str>>(),
        "Environment changed shape"
    );
    let pin_keys: BTreeSet<&str> = env
        .get("pin")
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(
        pin_keys,
        [
            "index_requests",
            "versions_withheld",
            "artifact_requests",
            "toolchain_requests",
            "rejected"
        ]
        .into_iter()
        .collect::<BTreeSet<&str>>(),
        "PinEvidence changed shape"
    );
    let art_keys: BTreeSet<&str> = json
        .get("upstream")
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(
        art_keys,
        ["name", "sha256", "bytes", "stored"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
        "ArtifactRef changed shape"
    );

    // The state is a name on the wire, never an ordinal, for the same reason the outcome is.
    assert_eq!(json.get("state").unwrap(), "judging");
}

#[tokio::test]
async fn a_record_with_nothing_optional_in_it_reads_back_as_nothing_rather_than_as_a_default() {
    // The other half of the round trip, and the one `#[serde(default)]` actually decides. A record
    // written at the start of a run has no outcome, no rebuild and no attestation, and every one of
    // those absences means something specific downstream: no outcome is "not judged yet", not
    // "divergent"; no attestation is "nothing has signed for this", which is what `prune_rebuild`
    // refuses on. A default that filled any of them in would be a lie the store told quietly.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::local(dir.path()).unwrap();
    let record = RunRecord::new(
        "0002-bare",
        "pkg:npm/a@1",
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([9; 32]),
            bytes: 0,
            stored: true,
        },
        Environment {
            base_image: "docker.io/library/debian@sha256:aa".into(),
            egress: "none".into(),
            isolation: "UserNs".into(),
            guard_manifest: None,
            guarded_members: None,
            attestable: true,
            registry_moment: None,
            pin: None,
        },
        "2026-09-11T19:00:00Z",
    );
    store.put_run(&record).await.unwrap();

    // The file itself omits them. This is the shape the attestor and a human both read, and the
    // reason it is asserted rather than left implicit is that an absent key and a present-but-null
    // key are the same value to serde and different answers to anyone reading the file.
    let raw = std::fs::read_to_string(dir.path().join("runs/0002-bare.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    for absent in [
        "outcome",
        "guard_trips",
        "refused_artifact",
        "finished",
        "strategy",
        "strategy_digest",
        "derivation",
        "instructions",
        "rebuild",
        "comparison",
        "build_log",
        "timings",
        "failure",
        "refused_artifact",
        "transcript",
        "network_transcript",
        "costs",
        "attestations",
    ] {
        assert!(
            json.get(absent).is_none(),
            "`{absent}` is empty and should not be written at all"
        );
    }
    // `attestable` is not optional and must be written even when it is the boring value: the whole
    // point of the field is that it is read, and a skipped `true` would be indistinguishable from a
    // record whose writer did not know about the field.
    assert_eq!(json.get("attestable"), None);
    assert_eq!(
        json.get("environment").unwrap().get("attestable").unwrap(),
        &serde_json::Value::Bool(true)
    );

    let back = store.get_run("0002-bare").await.unwrap();
    assert_eq!(back, record);
    assert!(back.outcome.is_none(), "no outcome, not an empty outcome");
    assert!(back.guard_trips.is_empty());
    assert!(back.attestations.is_empty());
    assert!(back.timings.is_empty());
    assert!(back.environment.pin.is_none());
    assert!(
        !back.is_evidence(),
        "an unjudged run is not evidence, and must not read as one that passed"
    );
    // `stored` is the one field whose default is `true`, because records predate it. A record that
    // *says* true and a record that says nothing must both read as true.
    assert!(back.upstream.stored);
}

#[tokio::test]
async fn rewriting_a_run_replaces_the_record_rather_than_leaving_the_tail_of_the_old_one() {
    // `put_run` is documented as replacing any earlier version, and a run is written repeatedly as
    // it moves through its states — the later writes are *shorter* than the ones before them only
    // rarely, but a prune is exactly that case, and so is a re-run of a target that previously
    // diverged. A backend that opened the file without truncating would leave the tail of the
    // longer record behind, and the result parses: JSON stops at the closing brace. The record
    // would be right and the bytes on disk would carry a second, stale record nobody can see.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::local(dir.path()).unwrap();
    let full = every_field_populated();
    store.put_run(&full).await.unwrap();
    let long = std::fs::read(dir.path().join("runs/0001-full.json")).unwrap();

    let mut short = RunRecord::new(
        &full.id,
        &full.target,
        full.upstream.clone(),
        full.environment.clone(),
        &full.started,
    );
    short.environment.pin = None;
    short.environment.registry_moment = None;
    store.put_run(&short).await.unwrap();

    let after = std::fs::read(dir.path().join("runs/0001-full.json")).unwrap();
    assert!(
        after.len() < long.len(),
        "the shorter record should have replaced the longer one, not been written into it"
    );
    // Not just "parses" — parses with nothing after it. This is what a truncating write buys.
    let tail = std::str::from_utf8(&after).unwrap();
    assert_eq!(tail.trim_end().matches("\"id\"").count(), 1);

    let back = store.get_run("0001-full").await.unwrap();
    assert_eq!(back, short);
    assert!(
        back.attestations.is_empty() && back.rebuild.is_none() && back.guard_trips.is_empty(),
        "fields the new record does not have must not survive from the old one"
    );
}

#[tokio::test]
async fn a_blob_lands_at_the_digest_of_its_own_bytes_and_at_no_other_path() {
    // The address *is* the check. An attestor that can be a separate process at all is one that
    // fetches by hash and verifies the hash, so the layout has to be derivable by someone who has
    // only the digest out of the record — no listing, no index, no trust in whoever chose the path.
    //
    // The expected digests here are written out rather than recomputed with `sha2`, because
    // recomputing them with the same library the store uses would assert only that the library
    // agrees with itself. These are `sha256sum` of the literal bytes.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::local(dir.path()).unwrap();

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let d = store.blobs().put(&b"abc"[..]).await.unwrap();
    assert_eq!(d.to_hex(), ABC, "the digest is sha256 of the bytes");
    // The empty blob is worth storing on purpose: an empty build log is a real thing, and a store
    // that treats zero bytes as "nothing to store" would hand back a digest nothing lives under.
    let e = store.blobs().put(&b""[..]).await.unwrap();
    assert_eq!(e.to_hex(), EMPTY);

    assert_eq!(
        files_under(dir.path()),
        [
            format!("blobs/sha256/{}/{ABC}", &ABC[..2]),
            format!("blobs/sha256/{}/{EMPTY}", &EMPTY[..2]),
        ]
        .into_iter()
        .collect::<BTreeSet<String>>(),
        "a blob lives at exactly one path, and it is the one its digest spells out"
    );
    // The bytes on disk are the bytes, unwrapped — no envelope, no length prefix. Anyone can check
    // this store with `sha256sum`, which is the property that makes the claim independently
    // checkable rather than checkable by us.
    assert_eq!(
        std::fs::read(dir.path().join(format!("blobs/sha256/ba/{ABC}"))).unwrap(),
        b"abc"
    );
    assert_eq!(&store.blobs().get(&d).await.unwrap()[..], b"abc");
    assert_eq!(&store.blobs().get(&e).await.unwrap()[..], b"");
    assert!(
        store.blobs().has(&e).await.unwrap(),
        "the empty blob is there"
    );
}

#[tokio::test]
async fn asking_for_a_digest_nothing_was_stored_under_fails_rather_than_returning_a_neighbour() {
    // The shard directory is an optimisation, not part of the key, and the failure it invites is
    // returning the wrong blob to a caller whose digest happens to share two hex characters. Sixty
    // thousand blobs and the collision is certain. A reader that fell back to "the file in the
    // right shard" would hand the attestor bytes it never asked for, and the attestor would hash
    // them, find they do not match, and report corruption — for a blob that was simply absent.
    let store = Store::in_memory();
    let stored = store.blobs().put(&b"abc"[..]).await.unwrap();
    assert!(stored.to_hex().starts_with("ba"));

    // Same shard, different blob.
    let neighbour = Digest::from_hex(&format!("ba{}", "0".repeat(62))).unwrap();
    assert_ne!(neighbour, stored);
    assert!(
        !store.blobs().has(&neighbour).await.unwrap(),
        "nothing was stored under this digest and the store must say so"
    );
    let err = store.blobs().get(&neighbour).await.unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::Object(object_store::Error::NotFound { .. })
        ),
        "absent, not corrupt, and not silently substituted: {err}"
    );
    assert!(
        !matches!(err, StoreError::Corrupt { .. }),
        "a corruption error here would mean bytes came back for a digest nothing was stored under"
    );

    // A shard that does not exist at all, for the other side of the same question.
    let elsewhere = Digest::from_hex(&format!("ff{}", "0".repeat(62))).unwrap();
    assert!(!store.blobs().has(&elsewhere).await.unwrap());
    assert!(store.blobs().get(&elsewhere).await.is_err());
    // And the blob that is there is still exactly itself.
    assert_eq!(&store.blobs().get(&stored).await.unwrap()[..], b"abc");
}

#[tokio::test]
async fn an_attestation_path_built_from_a_package_name_cannot_climb_out_of_the_store() {
    // `put_attestation` interpolates a package's namespace, name and version straight into a path.
    // Those three strings come from a PURL, which comes from a registry or from an operator's
    // command line — they are attacker-influenced by construction, and `..` in any of them would
    // put a signed document wherever the attacker liked.
    //
    // It is safe today, and the safety is *borrowed*: `object_store`'s `Path` percent-encodes each
    // segment, so `..` becomes `%2E%2E` and means a directory with a strange name rather than a
    // level up. That is exactly the kind of protection that disappears without a sound — a
    // `PathBuf::join` here would look like a simplification and would compile. This test is what
    // makes that swap loud.
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("store");
    let store = Store::local(&root).unwrap();

    let mut reference = TargetRef::new(Ecosystem::Npm, "..", "../../../../pwned");
    reference.namespace = Some("../../..".into());
    let target = trigon_core::Target::new(
        reference,
        trigon_core::ArtifactId::new("../../../../../evil.tgz"),
    );
    let envelope =
        trigon_attest::Envelope::new(b"a statement about someone else's package", vec![]);

    let path = store
        .put_attestation(
            &target,
            "../../../../../evil.tgz",
            "https://trigon.dev/equivalence/v1",
            &envelope,
        )
        .await
        .unwrap();

    // Everything the store created is inside the store.
    let outside: Vec<String> = std::fs::read_dir(outer.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        outside,
        vec!["store".to_string()],
        "the store wrote something next to itself"
    );
    let inside = files_under(&root);
    assert_eq!(
        inside.len(),
        1,
        "exactly one document was written: {inside:?}"
    );
    let written = inside.iter().next().unwrap();
    assert!(
        written.starts_with("attestations/npm/"),
        "still under the attestation prefix: {written}"
    );
    assert!(
        !written.split('/').any(|seg| seg == ".." || seg == "."),
        "no segment of the path on disk is a traversal: {written}"
    );
    assert!(
        written.contains("%2E%2E"),
        "the traversal was encoded into an ordinary directory name rather than obeyed: {written}"
    );

    // And the returned string still round-trips, which is the part callers depend on: the path goes
    // into `RunRecord::attestations` verbatim and comes back out through `get_attestation`. It is an
    // identifier, not a filesystem path — `put` and `get` encode it identically, so the two agree
    // even though neither matches what `ls` shows.
    assert!(
        path.contains(".."),
        "the returned path is the un-encoded form"
    );
    assert_eq!(store.get_attestation(&path).await.unwrap(), envelope);
}

#[tokio::test]
async fn each_predicate_an_artifact_carries_is_filed_where_the_others_cannot_overwrite_it() {
    // One artifact can carry several statements — the equivalence claim, the rebuild provenance,
    // the build observation. They share a directory, and the filename is derived from the predicate
    // URL by a rule that deliberately throws away the last segment, because every predicate ends in
    // `/v1` and filing by that would put all of them at the same path where each overwrote the last.
    //
    // The rule works, and what this test protects is the next predicate somebody adds: a URL whose
    // second-to-last segment collides with an existing one would silently destroy the statement
    // already there, and the run record would still name a path that now holds somebody else's
    // claim. Writing all five and demanding all five back is the only way that shows up.
    let store = Store::in_memory();
    let reference: TargetRef = "pkg:npm/@babel/core@7.24.0".parse().unwrap();
    let target =
        trigon_core::Target::new(reference, trigon_core::ArtifactId::new("core-7.24.0.tgz"));

    let predicates = [
        "https://trigon.dev/equivalence/v1",
        "https://trigon.dev/divergence/v1",
        "https://trigon.dev/rebuild/v1",
        "https://trigon.dev/buildobservation/v1",
        "https://trigon.dev/builder/v1",
    ];
    let mut written = Vec::new();
    for p in predicates {
        let envelope = trigon_attest::Envelope::new(p.as_bytes(), vec![]);
        let path = store
            .put_attestation(&target, "core-7.24.0.tgz", p, &envelope)
            .await
            .unwrap();
        written.push((p, path, envelope));
    }

    let paths: BTreeSet<&str> = written.iter().map(|(_, p, _)| p.as_str()).collect();
    assert_eq!(
        paths.len(),
        predicates.len(),
        "two predicates were filed at the same path, so one statement destroyed another: {paths:?}"
    );
    for (predicate, path, envelope) in &written {
        assert_eq!(
            &store.get_attestation(path).await.unwrap(),
            envelope,
            "{predicate} did not read back as itself from {path}"
        );
    }
}

#[tokio::test]
async fn no_such_run_is_a_different_answer_from_a_run_that_recorded_nothing() {
    // Absent is not zero, and here it is not empty either. A sweep that conflated them would
    // re-queue a target whose record exists but is still bare, and overwrite a run in flight; a
    // reader that conflated them would report "no data" for a run that is simply queued.
    let store = Store::in_memory();

    // Nothing at all.
    let err = store.get_run("never-written").await.unwrap_err();
    assert!(matches!(err, StoreError::NoSuchRun(_)), "{err}");
    assert!(
        err.to_string().contains("never-written"),
        "the error names the run it could not find: {err}"
    );
    // An empty store lists nothing rather than failing, which is what makes "no runs yet" a state
    // a caller can render instead of an error it has to special-case.
    assert!(store.list_runs().await.unwrap().is_empty());

    // A run that exists and has recorded nothing.
    let bare = RunRecord::new(
        "0003-bare",
        "pkg:npm/a@1",
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: Digest::from_bytes([0; 32]),
            bytes: 0,
            stored: true,
        },
        Environment {
            base_image: "i@sha256:aa".into(),
            egress: "none".into(),
            isolation: "UserNs".into(),
            guard_manifest: None,
            guarded_members: None,
            attestable: true,
            registry_moment: None,
            pin: None,
        },
        "t",
    );
    store.put_run(&bare).await.unwrap();
    let back = store.get_run("0003-bare").await.unwrap();
    assert!(back.outcome.is_none() && back.timings.is_empty());
    assert_eq!(store.list_runs().await.unwrap(), ["0003-bare"]);

    // Every id the listing reports is one `get_run` can fetch. The two derive the path
    // independently — one formats it, the other parses it back off a filename — so a change to the
    // layout that only touched one of them would produce a listing full of ids that resolve to
    // nothing.
    for id in store.list_runs().await.unwrap() {
        store.get_run(&id).await.unwrap_or_else(|e| {
            panic!("list_runs named `{id}` and get_run could not fetch it: {e}")
        });
    }
}

#[tokio::test]
async fn a_record_is_read_back_without_being_checked_against_anything_but_json() {
    // `docs/threat-model.md` D6: the store hash-checks blobs and does not verify its own records.
    // This is the test that keeps that sentence honest, and it asserts the *weakness* on purpose —
    // if somebody adds record verification, this fails, and D6 has to be rewritten rather than left
    // standing as a disclaimer of something the code now does.
    //
    // What it costs is worth stating plainly. `guard_trips` is the field that decides whether a run
    // is evidence at all, and anything that can write to the store can remove it: the record comes
    // back clean, `is_evidence()` flips to true, and the digests it names are still whatever the
    // editor put there. The blob check is what limits the damage — the bytes cannot be swapped
    // without detection — but the *claims about* the bytes can be.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::local(dir.path()).unwrap();
    let bytes = store
        .blobs()
        .put(&b"the published artifact"[..])
        .await
        .unwrap();

    let mut record = RunRecord::new(
        "0004-void",
        "pkg:npm/a@1",
        ArtifactRef {
            name: "a.tgz".into(),
            sha256: bytes,
            bytes: 22,
            stored: true,
        },
        Environment {
            base_image: "i@sha256:aa".into(),
            egress: "open".into(),
            isolation: "None".into(),
            guard_manifest: None,
            guarded_members: None,
            attestable: false,
            registry_moment: None,
            pin: None,
        },
        "t",
    );
    record.outcome = Some("exact".into());
    record.guard_trips = vec!["the artifact under test arrived from registry.npmjs.org".into()];
    store.put_run(&record).await.unwrap();
    assert!(!record.is_evidence(), "as written, this run proves nothing");

    // Edit the file the way anything with write access to the store could.
    let file = dir.path().join("runs/0004-void.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("guard_trips");
    json["environment"]["attestable"] = serde_json::Value::Bool(true);
    json["upstream"]["sha256"] = serde_json::Value::String("aa".repeat(32));
    json["upstream"]["bytes"] = serde_json::json!(999_999);
    std::fs::write(&file, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

    let tampered = store.get_run("0004-void").await.unwrap();
    assert!(
        tampered.is_evidence(),
        "D6 says the store does not verify records; if this now fails, D6 is out of date"
    );
    assert!(tampered.environment.attestable);
    assert_ne!(tampered.upstream.sha256, bytes);
    assert_eq!(tampered.upstream.bytes, 999_999);
    // The record can name bytes that are not in the store, and reading it does not notice.
    assert!(
        !store.blobs().has(&tampered.upstream.sha256).await.unwrap(),
        "the record now points at a blob that was never stored, and `get_run` was happy"
    );

    // The other half of D6, and the half that holds: the bytes themselves cannot be swapped. This
    // is the line between "a record can lie about which blob" and "a blob can lie about itself".
    let real = store.blobs().get(&bytes).await.unwrap();
    assert_eq!(&real[..], b"the published artifact");
    let err = store
        .blobs()
        .get(&Digest::from_hex(&"aa".repeat(32)).unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Object(_)),
        "the blob the tampered record names is simply not there: {err}"
    );
}

#[tokio::test]
async fn a_half_written_record_reads_as_unreadable_rather_than_as_a_run_that_does_not_exist() {
    // There is no temp-and-rename in this crate's own code (D6 again), so whether a partial record
    // can be observed is a property of the backend rather than of anything asserted here. What
    // *can* be asserted is what happens when one is: the two failures must stay distinguishable.
    //
    // Collapsing them is a plausible tidy-up — "a record we cannot read is a record we do not
    // have" — and it is the wrong answer in the one case that matters. A sweep that sees
    // `NoSuchRun` starts the target again and overwrites the truncated file; a sweep that sees a
    // parse error stops and lets somebody look at what is on disk before the evidence is gone.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::local(dir.path()).unwrap();
    store.put_run(&every_field_populated()).await.unwrap();

    let file = dir.path().join("runs/0001-full.json");
    let whole = std::fs::read(&file).unwrap();
    std::fs::write(&file, &whole[..whole.len() / 2]).unwrap();

    let err = store.get_run("0001-full").await.unwrap_err();
    assert!(
        matches!(err, StoreError::Json(_)),
        "a truncated record is unreadable, not absent: {err}"
    );
    assert!(
        !matches!(err, StoreError::NoSuchRun(_)),
        "if this ever becomes NoSuchRun, a re-run will overwrite the partial evidence"
    );
    // Both are our bug rather than the registry's, and neither is worth retrying: retrying a parse
    // reaches the same bytes.
    assert_eq!(err.fault(), Fault::Bug);
    assert!(!err.is_retryable());

    // The listing still names it, which is the point of keeping the two errors apart: the run is
    // visible and unreadable, and only the error says which.
    assert_eq!(store.list_runs().await.unwrap(), ["0001-full"]);
}

#[tokio::test]
async fn bytes_that_put_reported_stored_are_the_bytes_the_store_gives_back() {
    // FAILING. Two doc comments in `blobs.rs` disagree, and the code implements the wrong one.
    //
    // The module header says "a digest that is already present is already correct", and `put` acts
    // on it: it does a HEAD, and returns the digest without writing if anything is there. `get`'s
    // own comment says the opposite and is the reason the crate is shaped the way it is — "the
    // store is exactly the thing a compromised worker can write to", which is precisely a claim
    // that what is present may *not* be correct. Both cannot be true, and nothing asserted which.
    //
    // The consequence is not a slow path, it is lost evidence. Something writes wrong bytes to a
    // blob path — a hostile co-tenant, a buggy writer, no lock excludes either (D7). A later run
    // produces the real bytes for that digest and calls `put`. `put` returns `Ok(digest)`, so the
    // run record names the blob and the run proceeds; the real bytes are dropped, because the
    // caller has been told they are safely stored. `attest` then reads the blob, the digest check
    // fires, and the run is unrecoverable: re-running does not help, because every subsequent `put`
    // takes the same short circuit. The one path that could repair the store is the one that
    // refuses to write.
    //
    // `put`'s own doc comment even describes the repair it does not do: "a re-run overwrites itself
    // with the same content".
    use object_store::{ObjectStoreExt as _, PutPayload, path::Path as ObjPath};
    let inner = std::sync::Arc::new(object_store::memory::InMemory::new());
    let store = Store::new(inner.clone());

    // Someone else gets there first with the wrong bytes, at the right address.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    inner
        .put(
            &ObjPath::from(format!("blobs/sha256/ba/{ABC}")),
            PutPayload::from_static(b"a substituted artifact"),
        )
        .await
        .unwrap();

    // The run stores what it built and is told it worked.
    let d = store.blobs().put(&b"abc"[..]).await.unwrap();
    assert_eq!(d.to_hex(), ABC);

    // So the bytes under that digest must be the bytes that were put. They are not.
    let back = store.blobs().get(&d).await.unwrap_or_else(|e| {
        panic!(
            "put reported these bytes stored and the store will not give them back: {e}. \
             The HEAD short circuit in Blobs::put skipped the write, so the run's artifact is gone \
             and no re-run can put it back."
        )
    });
    assert_eq!(&back[..], b"abc");
}

#[tokio::test]
async fn every_id_the_listing_reports_is_one_get_run_can_fetch() {
    // FAILING. `list_runs` and `get_run` derive the same path by opposite routes — one formats
    // `runs/{id}.json` and hands it to `object_store`, the other takes the filename back off a
    // listing — and the two do not agree, because the formatting step percent-encodes and the
    // parsing step does not decode. Nothing asserted they agreed.
    //
    // `list_runs` is the store's only enumeration, and all three of its callers immediately feed
    // what it returns back into `get_run`: `trigon runs` and `trigon attest` (with no `--run`)
    // propagate the resulting error, and `trigon watch`'s target lookup swallows it, which is worse
    // — the run is present, fetchable by its true id, and invisible to the only path that finds it.
    //
    // Reachability today is narrow and that is the whole reason to pin it now: the CLI builds ids
    // as `{digest[..12]}-{pid}` (`crates/trigon/src/main.rs:1104`), which is hex and a number, so
    // nothing currently escapes. But `Store::put_run` takes whatever id the record carries, and the
    // day an id gains a `#`, a `/`, or is empty, the failure is silent in exactly the place a
    // silent failure costs the most.
    let store = Store::in_memory();
    let mut written = Vec::new();
    for id in [
        // What the CLI produces today. These work, and they are here so that a regression in the
        // ordinary case is caught by the same test as the awkward one.
        "0001-abcdef012-4711",
        "ff00aa22bb33-9",
    ] {
        let record = RunRecord::new(
            id,
            "pkg:npm/a@1",
            ArtifactRef {
                name: "a.tgz".into(),
                sha256: Digest::from_bytes([0; 32]),
                bytes: 1,
                stored: true,
            },
            Environment {
                base_image: "i@sha256:aa".into(),
                egress: "none".into(),
                isolation: "UserNs".into(),
                guard_manifest: None,
                guarded_members: None,
                attestable: true,
                registry_moment: None,
                pin: None,
            },
            "t",
        );
        store.put_run(&record).await.unwrap();
        written.push(id.to_string());

        // Fetching by the id we wrote works, which is what makes the listing the broken half.
        assert_eq!(
            store.get_run(id).await.unwrap().id,
            id,
            "get_run by the id that was written"
        );
    }

    let listed = store.list_runs().await.unwrap();
    for id in &written {
        assert!(
            listed.contains(id),
            "put_run wrote `{id}` and list_runs does not name it: {listed:?}"
        );
    }
    for id in &listed {
        store
            .get_run(id)
            .await
            .unwrap_or_else(|e| panic!("list_runs named `{id}` and get_run cannot fetch it: {e}"));
    }

    // And the ids that cannot round-trip are refused on the way in rather than renamed.
    //
    // `ObjPath::from` percent-encodes what it cannot carry and `list_runs` never decodes, so an id
    // holding `#` or `/` was written under one name and listed under another. The fix is the
    // boundary, not the decode: a store that quietly renames its records is worse than one that
    // declines, and every id this system generates is `<unix>-<digest prefix>`. The two below are
    // the obvious next sources of a run id — a CI build number, and a layout namespaced by
    // ecosystem — so both should meet a sentence rather than a silent rename.
    for bad in ["build#4711", "npm/left-pad", "", ".hidden", "a%2Fb"] {
        let record = RunRecord::new(
            bad,
            "pkg:npm/a@1",
            ArtifactRef {
                name: "a.tgz".into(),
                sha256: Digest::from_bytes([0; 32]),
                bytes: 1,
                stored: true,
            },
            Environment {
                base_image: "i@sha256:aa".into(),
                egress: "none".into(),
                isolation: "UserNs".into(),
                guard_manifest: None,
                guarded_members: None,
                attestable: true,
                registry_moment: None,
                pin: None,
            },
            "t",
        );
        let err = store
            .put_run(&record)
            .await
            .expect_err("`{bad}` cannot be listed back under its own name and was accepted anyway");
        assert!(
            err.to_string().contains("not a usable run id"),
            "refused `{bad}` for the wrong reason: {err}"
        );
    }
}
