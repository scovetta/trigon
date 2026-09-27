//! A run file written before a field was removed from `RunRecord` still reads.
//!
//! `RunRecord` does not use `deny_unknown_fields`, so a key the struct no longer has is ignored
//! rather than refused. That is a property of one missing attribute, and the store holds run files
//! written by every version of this binary, so it is pinned here against a real file rather than
//! left to be true by accident.
//!
//! The file is `trigon-store/runs/1789588410-870c0fe1.json`, byte for byte: the one stored run
//! that carried a `transparency` value, the entry an external log returned for its equivalence
//! statement while `trigon attest` still logged to one. ADR-0014 removed the log client and the
//! field (docs/19 §10 phase 1), and the next rewrite of that record drops the value, so this copy
//! is its archive as well as this test's input. It is stored gzipped. The bytes are exactly the
//! stored file's, which the test checks by digest; compressed, the log's name inside them is not a
//! string that a search of `crates/` for the removed client turns up as though it were live code.

use std::io::Read as _;

use sha2::{Digest as _, Sha256};
use trigon_store::Store;

const ID: &str = "1789588410-870c0fe1";

/// The run file, gzipped with `gzip -9 -n` so that the archive holds no name or timestamp of its
/// own.
const ARCHIVE: &[u8] = include_bytes!("fixtures/run-1789588410-870c0fe1.json.gz");

/// The sha256 of the run file as the local store held it on 2026-09-27, when it was archived.
const STORED_SHA256: &str = "d8e29e046bd40cde971be6cb24af294d6d306ed46fe52160c0ad541a5ebf5f13";

fn stored_file() -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(ARCHIVE)
        .read_to_end(&mut out)
        .expect("the archive is gzip");
    out
}

#[tokio::test]
async fn a_run_file_with_a_transparency_key_still_reads_and_the_next_write_drops_the_key() {
    let bytes = stored_file();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        STORED_SHA256,
        "the archive is not the file the store held"
    );

    // The key is there, holding a whole entry, or reading past it would test nothing.
    let old: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        old["transparency"]["log_index"].is_u64() && old["transparency"]["body"].is_string(),
        "the archived file no longer carries the removed field: {old}"
    );

    // Read through the store, the way `trigon runs`, `trigon attest` and `trigon serve` read it,
    // rather than through serde alone: a listing that named the run and a `get_run` that refused
    // it would be the failure that matters.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(format!("runs/{ID}.json"));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &bytes).unwrap();
    let store = Store::local(dir.path()).unwrap();
    assert_eq!(store.list_runs().await.unwrap(), vec![ID.to_string()]);
    let run = store
        .get_run(ID)
        .await
        .expect("a run file with a key RunRecord no longer has is still a run file");

    // What the record said about the package survives the key it no longer has.
    assert_eq!(run.id, ID);
    assert_eq!(run.target, "pkg:npm/left-pad@1.3.0");
    assert_eq!(run.outcome.as_deref(), Some("normalized"));
    assert_eq!(
        run.upstream.sha256.to_hex(),
        "870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd"
    );
    assert_eq!(run.attestations.len(), 3, "{:?}", run.attestations);
    assert!(run.is_evidence());

    // The next write drops the key, which is why the archive above exists, and drops nothing else:
    // every other value the old file held is written back unchanged.
    store.put_run(&run).await.unwrap();
    let new: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert!(new.get("transparency").is_none(), "{new}");
    for (key, value) in old.as_object().unwrap() {
        if key != "transparency" {
            assert_eq!(&new[key], value, "`{key}` changed on the rewrite");
        }
    }
}
