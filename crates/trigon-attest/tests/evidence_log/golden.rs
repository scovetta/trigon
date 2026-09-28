//! The golden evidence repository: a log of every leaf kind, grown by five publications until it
//! ends, and its successor, laid out as `docs/19` §2.3 lays one out. Regenerated from the writer
//! and compared byte for byte, and verified as a client verifies one.
//!
//! What it holds, so a reader of `testdata/log/repo/` knows what to look for:
//!
//! - `log/`, `example.com/trigon-evidence`: three records (a verdict, a divergence, a void), 250
//!   heartbeats, then a supersession, the attestation key's change from key 3 to key 4, a record
//!   under key 4, a client release and a withdrawal — which fills the first tile, so its partials
//!   are gone — then a heartbeat, then a log-end naming `log/1`. 260 leaves; the partials of the
//!   second tile at each size since, 2, 3 and 4, are all there, as the immutability rule leaves
//!   them.
//! - `log/1/`, `example.com/trigon-evidence/1`: the log-continuation holding `log/`'s final
//!   checkpoint signed by both log keys, a record, a heartbeat.
//!
//! `leaves/` holds one leaf of each kind, taken from it, and `repo-proofs.json` the consistency
//! proofs between every checkpoint `log/` had and inclusion proofs for some of its leaves, which an
//! implementation that is not this one can check (`docs/16-findings.md` §3.98).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{Value, json};
use trigon_attest::log::merkle::{leaf_hash, verify_consistency, verify_inclusion};
use trigon_attest::log::{
    KeyChangeLeaf, KeyHistory, Leaf, LeafOutcome, LeafPos, LogContinuationLeaf, LogEndLeaf,
    RecordLeaf, ReleaseLeaf, SignedCheckpoint, Successor, verify_source,
};
use trigon_attest::{AttestationKey, DIVERGENCE_V2, SupersedeReason, VOID, WITHDRAWAL};

use crate::common::{
    T0, Writer, attestation_key, heartbeat, log_key, record_leaf, sha256, successor_key, tree_of,
};

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/log")
}

fn rewriting() -> bool {
    std::env::var_os("TRIGON_WRITE_GOLDEN").is_some_and(|v| v == "1")
}

/// What building the golden repository produced beside its files.
pub struct Golden {
    /// One leaf of each kind, by the name of its golden file.
    pub examples: Vec<(&'static str, Leaf)>,
    /// `repo-proofs.json`.
    pub proofs: Value,
}

/// A clock that moves a minute at a time.
struct Clock(u64);

impl Clock {
    fn tick(&mut self) -> u64 {
        let t = self.0;
        self.0 += 60;
        t
    }
}

/// Write the golden repository under `repo`.
pub fn build(repo: &Path) -> Golden {
    let (k3, k4, release_key) = (attestation_key(3), attestation_key(4), attestation_key(5));
    let mut clock = Clock(T0);
    let mut examples = Vec::new();
    let mut notes = Vec::new();

    let mut log = Writer::init(&repo.join("log"), log_key());
    notes.push(log.checkpoint());

    // Publication 1: a verdict, with every digest npm publishes; a divergence; a void.
    let mut verdict = record_leaf(clock.tick(), 1, &k3);
    let sha1: String = sha256("sha1 of 1").as_bytes()[..20]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    verdict.subject.insert("sha1".into(), sha1);
    let divergent = RecordLeaf {
        predicate_type: DIVERGENCE_V2.into(),
        outcome: Some(LeafOutcome::Divergent),
        ..record_leaf(clock.tick(), 2, &k3)
    };
    let void = RecordLeaf {
        predicate_type: VOID.into(),
        outcome: Some(LeafOutcome::Void),
        ..record_leaf(clock.tick(), 3, &k3)
    };
    let first = vec![
        Leaf::Record(verdict.clone()),
        Leaf::Record(divergent.clone()),
        Leaf::Record(void.clone()),
    ];
    examples.push(("record", first[0].clone()));
    examples.push(("record-divergent", first[1].clone()));
    examples.push(("record-void", first[2].clone()));
    log.append(&first);
    notes.push(log.checkpoint());

    // Publication 2: a quiet stretch.
    let quiet: Vec<Leaf> = (0..250).map(|_| heartbeat(clock.tick())).collect();
    examples.push(("heartbeat", quiet[0].clone()));
    log.append(&quiet);
    notes.push(log.checkpoint());

    // Publication 3: a supersession, the key change, a record under the new key, a client
    // release, and a withdrawal — which fills the first tile.
    let supersedes = RecordLeaf {
        supersedes: Some(verdict.record),
        reason: Some(SupersedeReason::SetChanged),
        ..record_leaf(clock.tick(), 4, &k3)
    };
    let change = KeyChangeLeaf::sign(log_key().name(), clock.tick(), &k3, &k4).unwrap();
    let under_new = record_leaf(clock.tick(), 5, &k4);
    let release = ReleaseLeaf::sign(
        log_key().name(),
        clock.tick(),
        "trigon-check",
        "0.1.0",
        BTreeMap::from([(
            "trigon-check-0.1.0.tgz".to_string(),
            BTreeMap::from([
                (
                    "sha256".to_string(),
                    sha256("trigon-check-0.1.0.tgz").to_hex(),
                ),
                (
                    "sha512".to_string(),
                    format!("{}{}", sha256("a").to_hex(), sha256("b").to_hex()),
                ),
            ]),
        )]),
        &release_key,
    )
    .unwrap();
    let withdrawal = RecordLeaf {
        time: clock.tick(),
        subject: divergent.subject.clone(),
        purl: divergent.purl.clone(),
        purl_canon: 1,
        predicate_type: WITHDRAWAL.into(),
        outcome: None,
        stabilizer_set: None,
        key_id: AttestationKey::from(k4.public_key()).key_id(),
        record: sha256("record 7"),
        supersedes: Some(divergent.record),
        reason: Some(SupersedeReason::Withdrawn),
    };
    let third = vec![
        Leaf::Record(supersedes),
        Leaf::KeyChange(change),
        Leaf::Record(under_new),
        Leaf::Release(release),
        Leaf::Record(withdrawal),
    ];
    examples.push(("record-supersedes", third[0].clone()));
    examples.push(("key-change", third[1].clone()));
    examples.push(("release", third[3].clone()));
    examples.push(("record-withdrawal", third[4].clone()));
    log.append(&third);
    notes.push(log.checkpoint());

    // Publication 4: a heartbeat, so the second tile has a second partial.
    log.append(&[heartbeat(clock.tick())]);
    notes.push(log.checkpoint());

    // Publication 5: the end, naming a successor in this repository.
    let end = Leaf::LogEnd(LogEndLeaf {
        time: clock.tick(),
        successor: Successor {
            origin: successor_key().name().into(),
            log_key: successor_key().vkey().to_string(),
            urls: Vec::new(),
            dir: "log/1".into(),
        },
    });
    examples.push(("log-end", end.clone()));
    log.append(&[end]);
    let last = log.checkpoint();
    notes.push(last.clone());

    // The successor: its first leaf holds the old log's final checkpoint, cosigned.
    let mut next = Writer::init(&repo.join("log/1"), successor_key());
    let continuation = Leaf::LogContinuation(LogContinuationLeaf {
        time: clock.tick(),
        checkpoint: last.note().cosign(&successor_key()).unwrap().to_string(),
    });
    examples.push(("log-continuation", continuation.clone()));
    next.append(&[
        continuation,
        Leaf::Record(record_leaf(clock.tick(), 6, &k4)),
    ]);
    next.append(&[heartbeat(clock.tick())]);

    Golden {
        examples,
        proofs: proofs(&log, &notes),
    }
}

/// Every checkpoint `log/` had, with the proof that the final one extends it, and inclusion
/// proofs for leaves on either side of each tile boundary.
fn proofs(log: &Writer, notes: &[SignedCheckpoint]) -> Value {
    let b64 = |h: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(h);
    let n = log.tree.size();
    let checkpoints: Vec<Value> = notes
        .iter()
        .map(|c| {
            let proof = log.tree.consistency_proof(c.size(), n).unwrap();
            json!({
                "size": c.size(),
                "root": b64(c.root()),
                "note": c.to_string(),
                "consistencyToFinal": proof.iter().map(b64).collect::<Vec<_>>(),
            })
        })
        .collect();
    let inclusion: Vec<Value> = [0u64, 2, 3, 252, 255, 256, 257, n - 1]
        .iter()
        .map(|&i| {
            let proof = log.tree.inclusion_proof(i, n).unwrap();
            json!({
                "index": i,
                "leaf": String::from_utf8(log.entries[i as usize].clone()).unwrap(),
                "proof": proof.iter().map(b64).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "about": "Proofs over the golden repository's first log, log/ (testdata/log/repo). Every \
                  checkpoint the log had, as a signed note, with the RFC 6962 consistency proof \
                  from it to the final one; and inclusion proofs in the final tree for leaves \
                  either side of the first tile boundary, each leaf as the canonical JSON it is. \
                  Hashes are base64. Written by crates/trigon-attest's writer and checked by an \
                  implementation that is not it (docs/16-findings.md section 3.98).",
        "origin": log.signer.name(),
        "logKey": log.signer.vkey().to_string(),
        "size": n,
        "checkpoints": checkpoints,
        "inclusion": inclusion,
    })
}

fn pretty(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s.into_bytes()
}

#[test]
fn the_golden_repository_is_what_the_writer_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let golden = build(tmp.path());
    let proofs = pretty(&golden.proofs);
    let (repo, leaves) = (testdata().join("repo"), testdata().join("leaves"));
    if rewriting() {
        let _ = std::fs::remove_dir_all(&repo);
        let _ = std::fs::remove_dir_all(&leaves);
        for (path, bytes) in tree_of(tmp.path()) {
            let p = repo.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        std::fs::create_dir_all(&leaves).unwrap();
        for (name, leaf) in &golden.examples {
            std::fs::write(leaves.join(format!("{name}.json")), leaf.encode().unwrap()).unwrap();
        }
        std::fs::write(testdata().join("repo-proofs.json"), &proofs).unwrap();
    }
    let (want, got) = (tree_of(&repo), tree_of(tmp.path()));
    assert_eq!(
        want.keys().collect::<Vec<_>>(),
        got.keys().collect::<Vec<_>>(),
        "the files the writer writes are not the golden repository's; if the change is \
         deliberate, TRIGON_WRITE_GOLDEN=1 rewrites it"
    );
    for (path, bytes) in &got {
        assert!(want[path] == *bytes, "{path} differs from the golden file");
    }
    for (name, leaf) in &golden.examples {
        let file = std::fs::read(leaves.join(format!("{name}.json"))).unwrap();
        assert_eq!(file, leaf.encode().unwrap(), "leaves/{name}.json");
    }
    assert_eq!(
        std::fs::read(testdata().join("repo-proofs.json")).unwrap(),
        proofs,
        "repo-proofs.json"
    );
}

/// The immutability rule, as the golden repository shows it: the first tile is full and none of
/// its partials is left; the second is partial, and every partial it has had is still there.
#[test]
fn the_golden_repository_keeps_the_partials_of_the_tile_being_filled_and_no_others() {
    let files = tree_of(&testdata().join("repo/log"));
    let tiles: Vec<&str> = files
        .keys()
        .map(String::as_str)
        .filter(|p| p.starts_with("tile/"))
        .collect();
    assert_eq!(
        tiles,
        [
            "tile/0/000",
            "tile/0/001.p/2",
            "tile/0/001.p/3",
            "tile/0/001.p/4",
            "tile/1/000.p/1",
            "tile/entries/000",
            "tile/entries/001.p/2",
            "tile/entries/001.p/3",
            "tile/entries/001.p/4",
        ]
    );
}

#[test]
fn the_golden_repository_verifies_and_its_rotations_are_followed() {
    let repo = testdata().join("repo");
    let source = verify_source(&repo, &log_key().vkey(), None).unwrap();
    let dirs: Vec<&str> = source.logs.iter().map(|c| c.dir.as_str()).collect();
    assert_eq!(dirs, ["log", "log/1"]);
    assert!(source.continues_at.is_none() && source.unnamed.is_empty());
    assert!(source.refused.is_empty(), "{:?}", source.refused);
    assert_eq!(source.logs[0].log.size(), 260);
    assert_eq!(source.logs[1].log.size(), 3);

    let mut kinds: Vec<&str> = source
        .logs
        .iter()
        .flat_map(|c| c.log.leaves().map(|(_, l)| l.kind()))
        .collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(
        kinds,
        [
            "heartbeat",
            "key-change",
            "log-continuation",
            "log-end",
            "record",
            "release"
        ]
    );

    // The key change at leaf 254 of log 0 moves the source from key 3 to key 4.
    let k3 = AttestationKey::from(attestation_key(3).public_key());
    let k4 = AttestationKey::from(attestation_key(4).public_key());
    let (history, skipped) = KeyHistory::from_source(k3.clone(), &source).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(history.current(), &k4);
    let at = |log, index| LeafPos { log, index };
    assert_eq!(history.key_for(&k3.key_id(), at(0, 253)).unwrap(), &k3);
    assert!(history.key_for(&k3.key_id(), at(0, 255)).is_err());
    assert_eq!(history.key_for(&k4.key_id(), at(1, 1)).unwrap(), &k4);

    // The release verifies under the release key it was signed with.
    let release_key = AttestationKey::from(attestation_key(5).public_key());
    let release = source.logs[0]
        .log
        .leaves()
        .find_map(|(_, l)| match l {
            Leaf::Release(r) => Some(r.clone()),
            _ => None,
        })
        .unwrap();
    release.verify(log_key().name(), &release_key).unwrap();
}

#[test]
fn the_golden_proofs_verify() {
    let proofs: Value =
        serde_json::from_slice(&std::fs::read(testdata().join("repo-proofs.json")).unwrap())
            .unwrap();
    let hash = |v: &Value| -> [u8; 32] {
        base64::engine::general_purpose::STANDARD
            .decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let list = |v: &Value| v.as_array().unwrap().iter().map(hash).collect::<Vec<_>>();
    let checkpoints = proofs["checkpoints"].as_array().unwrap();
    let last = checkpoints.last().unwrap();
    let (n, final_root) = (last["size"].as_u64().unwrap(), hash(&last["root"]));
    for c in checkpoints {
        let note = c["note"].as_str().unwrap();
        let signed = SignedCheckpoint::open(note.as_bytes(), &log_key().vkey()).unwrap();
        assert_eq!(signed.size(), c["size"].as_u64().unwrap());
        assert_eq!(*signed.root(), hash(&c["root"]));
        verify_consistency(
            signed.size(),
            n,
            signed.root(),
            &final_root,
            &list(&c["consistencyToFinal"]),
        )
        .unwrap();
    }
    for p in proofs["inclusion"].as_array().unwrap() {
        let leaf = p["leaf"].as_str().unwrap().as_bytes();
        Leaf::decode(leaf).unwrap();
        verify_inclusion(
            p["index"].as_u64().unwrap(),
            n,
            &leaf_hash(leaf),
            &list(&p["proof"]),
            &final_root,
        )
        .unwrap();
    }
}
