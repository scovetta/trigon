//! Where every file of an evidence repository is (`docs/19` §2.3, §5): record and evidence paths,
//! the index paths of every key, held to the purl vectors every writer and reader shares, and the
//! index file.

use serde_json::Value;
use sha2::Digest as _;
use trigon_attest::evidence::{IndexFile, IndexKey, Key, evidence_path, index_files, record_path};
use trigon_attest::log::verify_source;
use trigon_core::Digest;

use crate::build::{digest, pairs, repo};
use crate::common::{log_key, tree_of};

fn sha256_hex(s: &str) -> String {
    Digest::from_bytes(sha2::Sha256::digest(s.as_bytes()).into()).to_hex()
}

#[test]
fn records_and_evidence_are_named_by_their_whole_digest_under_a_four_hex_fan_out() {
    let d = Digest::from_hex(&format!("7f3a{}", "c2".repeat(30))).unwrap();
    let hex = d.to_hex();
    assert_eq!(record_path(&d), format!("records/7f/3a/{hex}.json"));
    assert_eq!(evidence_path(&d), format!("evidence/sha256/7f/3a/{hex}"));
}

#[test]
fn every_key_of_docs_19_5_has_its_path() {
    let (sha256, sha512, sha1) = ("8b2e".repeat(16), "1df6".repeat(32), "0e7c".repeat(10));
    for (key, path) in [
        (
            IndexKey::digest("sha256", &sha256).unwrap(),
            format!("index/sha256/8b/2e/{sha256}.json"),
        ),
        (
            IndexKey::digest("sha512", &sha512).unwrap(),
            format!("index/sha512/1d/f6/{sha512}.json"),
        ),
        (
            IndexKey::digest("sha1", &sha1).unwrap(),
            format!("index/sha1/0e/7c/{sha1}.json"),
        ),
    ] {
        assert_eq!(key.path(), path);
        // The whole digest, never truncated.
        assert!(key.path().contains(&key.hex()));
        assert_eq!(IndexKey::parse(&key.name()).unwrap(), key);
    }
    let purl = IndexKey::purl(1, "pkg:npm/left-pad@1.3.0").unwrap();
    let hex = sha256_hex("pkg:npm/left-pad@1.3.0");
    assert_eq!(
        purl.path(),
        format!("index/purl1/{}/{}/{hex}.json", &hex[..2], &hex[2..4])
    );
    assert_eq!(purl.name(), "purl1:pkg:npm/left-pad@1.3.0");
    let pkg = IndexKey::package(1, "pkg:npm/left-pad").unwrap();
    let hex = sha256_hex("pkg:npm/left-pad");
    assert_eq!(
        pkg.path(),
        format!("index/pkg1/{}/{}/{hex}.json", &hex[..2], &hex[2..4])
    );
    assert_eq!(IndexKey::parse(&pkg.name()).unwrap(), pkg);

    // A key is held to its form: whole lowercase hex, a canonical purl with a version, a
    // package's versionless form.
    for bad in [
        "sha256:8B2E",
        &format!("sha256:{}", "8B2E".repeat(16)),
        &format!("sha256:{}", &sha256[..63]),
        &format!("md5:{}", "0".repeat(32)),
        "purl1:pkg:npm/Left-Pad@1.3.0",
        "purl1:pkg:npm/left-pad",
        "pkg1:pkg:npm/left-pad@1.3.0",
        "purl2:pkg:npm/left-pad@1.3.0",
        "purl01:pkg:npm/left-pad@1.3.0",
        "sha256",
    ] {
        assert!(IndexKey::parse(bad).is_err(), "{bad}");
    }
}

/// `crates/trigon-core/testdata/purl-canon-v1.json`, shared by every writer and reader of the
/// `purl1` and `pkg1` keys: each input's key is the sha256 of its canonical form under `purl1`,
/// and of its package under `pkg1`, and each invalid one is no key at all.
#[test]
fn the_shared_purl_vectors_give_the_purl1_and_pkg1_paths() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../trigon-core/testdata/purl-canon-v1.json");
    let vectors: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(vectors["purlCanon"], 1);
    let all = vectors["vectors"].as_array().unwrap();
    assert!(all.len() > 40, "the vectors are all there");
    for v in all {
        let (input, canonical, package) = (
            v["input"].as_str().unwrap(),
            v["canonical"].as_str().unwrap(),
            v["package"].as_str().unwrap(),
        );
        let key = Key::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        let paths: Vec<String> = key.index_keys().iter().map(IndexKey::path).collect();
        let at = |kind: &str, s: &str| {
            let hex = sha256_hex(s);
            format!("index/{kind}/{}/{}/{hex}.json", &hex[..2], &hex[2..4])
        };
        match &key {
            Key::Purl(_) => assert_eq!(paths, [at("purl1", canonical)], "{input}"),
            Key::Package(_) => {
                assert_eq!(
                    canonical, package,
                    "{input}: no version, so no more than the package"
                );
                assert_eq!(paths, [at("pkg1", package)], "{input}");
            }
            other => panic!("{input} read as {other:?}"),
        }
        // And every version of it is found under its package.
        let pkg = Key::parse(package).unwrap();
        assert_eq!(
            pkg.index_keys()
                .iter()
                .map(IndexKey::path)
                .collect::<Vec<_>>(),
            [at("pkg1", package)],
            "{input}"
        );
    }
    for v in vectors["invalid"].as_array().unwrap() {
        let input = v["input"].as_str().unwrap();
        assert!(Key::parse(input).is_err(), "{input}: {}", v["why"]);
    }
}

#[test]
fn a_record_is_filed_under_every_key_its_leaf_carries() {
    let source = verify_source(&repo(), &log_key().vkey(), None).unwrap();
    let files = index_files(&source).unwrap();
    let a = &pairs()["a"];
    let Key::File(d) = Key::of_bytes(&a.upstream) else {
        unreachable!()
    };
    let keys = [
        IndexKey::digest("sha256", &d["sha256"]).unwrap(),
        IndexKey::digest("sha512", &d["sha512"]).unwrap(),
        IndexKey::digest("sha1", &d["sha1"]).unwrap(),
        IndexKey::purl(1, "pkg:npm/demo-a@1.0.0").unwrap(),
        IndexKey::package(1, "pkg:npm/demo-a").unwrap(),
    ];
    for key in &keys {
        let file = &files[&key.path()];
        assert_eq!(file.key, key.name());
        // Both records, the superseded one included, with their leaves, in the log's order.
        let entries: Vec<(Digest, u64)> = file.records.iter().map(|e| (e.record, e.leaf)).collect();
        assert_eq!(entries, [(digest("a1"), 0), (digest("a2"), 8)], "{key}");
        assert!(file.records.iter().all(|e| e.log.is_none()));
    }
    // A record in the successor names the log its leaf is in.
    let k = IndexKey::purl(1, "pkg:npm/demo-k@1.0.0").unwrap();
    let entry = &files[&k.path()].records[0];
    assert_eq!((entry.leaf, entry.log.as_deref()), (1, Some("log/1")));

    // What the log implies is what the golden repository holds, byte for byte, and nothing else.
    let on_disk: Vec<String> = tree_of(&repo().join("index"))
        .into_keys()
        .map(|p| format!("index/{p}"))
        .collect();
    assert_eq!(on_disk, files.keys().cloned().collect::<Vec<_>>());
    for (path, file) in &files {
        let bytes = std::fs::read(repo().join(path)).unwrap();
        assert_eq!(bytes, file.encode().unwrap(), "{path}");
        assert_eq!(&IndexFile::parse(&bytes).unwrap(), file);
        // Each file is at the path its key derives.
        assert_eq!(&IndexKey::parse(&file.key).unwrap().path(), path);
    }
}

#[test]
fn an_index_file_reads_past_what_a_later_writer_adds_and_refuses_a_key_that_is_not_one() {
    let v = serde_json::json!({
        "key": format!("sha1:{}", "0e7c".repeat(10)),
        "records": [{
            "leaf": 3,
            "record": format!("sha256:{}", "7f3a".repeat(16)),
            "signedBy": "x",
        }],
        "note": 1,
    });
    let f = IndexFile::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(f.records[0].leaf, 3);
    let bad = br#"{"key":"sha1:0E7C","records":[]}"#;
    assert!(IndexFile::parse(bad).is_err());
}
