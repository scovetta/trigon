//! What `trigon attest` files, and what its statements are about.
//!
//! Two properties from `docs/19` §10 phase 2, through the binary rather than the library, because
//! the attestor is the code that decides what a statement's subject is and where it goes:
//!
//! - **Per run, append-only.** Attesting a second run of one target used to overwrite the first
//!   run's statements, and the first run's record went on naming them. Attesting one run again
//!   keeps what it signed before.
//! - **Every digest a consumer holds.** An npm consumer has the sha512 `integrity` and, from an old
//!   lockfile, the sha1 `shasum`; a statement keyed on sha256 alone is unfindable by either. Each
//!   is computed over the bytes, and `verify-attestation` checks each.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store, UpstreamDigests};

const TARGET: &str = "pkg:npm/demo@1.0.0";
const ARTIFACT: &str = "demo-1.0.0.tgz";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-attest-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn tgz() -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let body = b"module.exports = 1\n";
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(1_700_000_000);
    h.set_cksum();
    b.append_data(&mut h, "package/index.js", &body[..])
        .unwrap();
    let tar = b.into_inner().unwrap();
    let mut gz = Vec::new();
    {
        use std::io::Write as _;
        let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap();
    }
    gz
}

fn env() -> Environment {
    Environment {
        base_image: "docker.io/library/debian@sha256:aa".into(),
        derived_image: None,
        egress: "mirror-only".into(),
        isolation: "user_ns".into(),
        guard_manifest: None,
        guarded_members: None,
        attestable: false,
        registry_moment: None,
        pin: None,
    }
}

/// The digests a fetch of `bytes` from npm records: computed over them, sha1 included.
fn fetched(bytes: &[u8]) -> UpstreamDigests {
    UpstreamDigests {
        sha512: trigon_attest::sha512_of(bytes),
        sha1: Some(trigon_attest::sha1_of(bytes)),
        declared: Vec::new(),
        note: None,
    }
}

/// A run that compared two identical tarballs for real, with both artifacts and the comparison in
/// the blob store, recorded as `record_run` records one.
async fn compared_run(store: &Store, id: &str, bytes: &[u8]) -> RunRecord {
    let up = store.blobs().put(bytes.to_vec()).await.unwrap();
    let comparison = trigon_compare::compare_bytes(
        bytes.to_vec(),
        bytes.to_vec(),
        trigon_core::Format::TarGz,
        &trigon_stabilize::profile("tar-gzip").unwrap(),
        &trigon_archive::Limits::default(),
    )
    .unwrap();
    let cmp = store
        .blobs()
        .put(serde_json::to_vec(&comparison).unwrap())
        .await
        .unwrap();
    let artifact = |stored| ArtifactRef {
        name: ARTIFACT.into(),
        sha256: up,
        bytes: bytes.len() as u64,
        stored,
    };
    let mut r = RunRecord::new(id, TARGET, artifact(true), env(), "2026-09-27T00:00:00Z");
    r.state = RunState::Done;
    r.outcome = Some(comparison.outcome.to_string());
    r.comparison = Some(cmp);
    r.rebuild = Some(artifact(true));
    r.upstream_digests = Some(fetched(bytes));
    store.put_run(&r).await.unwrap();
    r
}

fn attest(store: &Path, id: &str, key: Option<&Path>) -> Output {
    let mut c = Command::new(bin());
    // Away from the developer's own `evidence.toml`, which `attest` reads for `[publish]`, and
    // from any project file where the tests happen to run.
    let home = store.parent().unwrap();
    c.current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.args(["attest", id, "--store"]).arg(store);
    if let Some(k) = key {
        c.arg("--key").arg(k);
    }
    c.output().unwrap()
}

fn ok(out: &Output) {
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The statement inside an envelope the store holds at `path`.
fn statement(store: &Store, path: &str) -> serde_json::Value {
    let env = rt().block_on(store.get_attestation(path)).unwrap();
    serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap()
}

fn predicate_of(s: &serde_json::Value) -> &str {
    s["predicateType"].as_str().unwrap()
}

#[test]
fn attesting_one_target_twice_leaves_both_runs_envelopes_readable() {
    let d = dir("twice");
    let root = d.join("store");
    let bytes = tgz();
    let store = Store::local(&root).unwrap();
    let (first, second) = rt().block_on(async {
        (
            compared_run(&store, "1789000000-aaaaaaaa", &bytes).await,
            compared_run(&store, "1789000100-bbbbbbbb", &bytes).await,
        )
    });

    ok(&attest(&root, &first.id, None));
    ok(&attest(&root, &second.id, None));

    let mut seen = Vec::new();
    for run in [&first, &second] {
        let r = rt().block_on(store.get_run(&run.id)).unwrap();
        assert_eq!(r.attestations.len(), 3, "{:?}", r.attestations);
        for path in &r.attestations {
            // Filed under the run, below the target, so the other run's attest cannot reach it.
            assert!(
                path.starts_with(&format!(
                    "attestations/npm/demo/1.0.0/{ARTIFACT}/{}/",
                    run.id
                )),
                "{path}"
            );
            let s = statement(&store, path);
            // The rebuild statement names the run it describes, so it says whose it is.
            if predicate_of(&s) == trigon_attest::REBUILD {
                assert_eq!(
                    s["predicate"]["runDetails"]["metadata"]["invocationId"],
                    run.id
                );
            }
            seen.push(path.clone());
        }
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 6, "each run's statements are its own: {seen:?}");
}

#[test]
fn a_run_attested_again_keeps_what_it_signed_before() {
    let d = dir("again");
    let root = d.join("store");
    let key = d.join("signing.key");
    ok(&Command::new(bin())
        .args(["keygen", "--out"])
        .arg(&key)
        .output()
        .unwrap());
    let store = Store::local(&root).unwrap();
    let run = rt().block_on(compared_run(&store, "1789000200-cccccccc", &tgz()));

    ok(&attest(&root, &run.id, None));
    let unsigned = rt().block_on(store.get_run(&run.id)).unwrap().attestations;
    let before: Vec<_> = unsigned
        .iter()
        .map(|p| rt().block_on(store.get_attestation(p)).unwrap())
        .collect();

    // Signed this time: different bytes, so written beside the unsigned statements, never over.
    ok(&attest(&root, &run.id, Some(&key)));
    let after = rt().block_on(store.get_run(&run.id)).unwrap().attestations;
    assert_eq!(after.len(), 6, "{after:?}");
    assert_eq!(
        after[..3],
        unsigned[..],
        "the record names what it named before, first"
    );
    for (path, env) in unsigned.iter().zip(&before) {
        assert_eq!(&rt().block_on(store.get_attestation(path)).unwrap(), env);
    }
    for path in &after[3..] {
        assert!(path.ends_with(".2.intoto.json"), "{path}");
        assert!(
            rt().block_on(store.get_attestation(path))
                .unwrap()
                .is_signed()
        );
    }

    // The same key again signs the same bytes, which are the same statements: nothing is added.
    ok(&attest(&root, &run.id, Some(&key)));
    assert_eq!(
        rt().block_on(store.get_run(&run.id)).unwrap().attestations,
        after
    );
}

#[test]
fn an_npm_statement_is_about_every_digest_of_the_upstream_bytes_and_verifies() {
    let d = dir("digests");
    let root = d.join("store");
    let bytes = tgz();
    let store = Store::local(&root).unwrap();
    let run = rt().block_on(compared_run(&store, "1789000300-dddddddd", &bytes));
    ok(&attest(&root, &run.id, None));

    let r = rt().block_on(store.get_run(&run.id)).unwrap();
    let want = serde_json::json!({
        "sha256": run.upstream.sha256.to_hex(),
        "sha512": trigon_attest::sha512_of(&bytes).to_hex(),
        "sha1": trigon_attest::sha1_of(&bytes).to_hex(),
    });
    let mut checked = Vec::new();
    for path in &r.attestations {
        let s = statement(&store, path);
        let subject = &s["subject"][0]["digest"];
        match predicate_of(&s) {
            // The rebuilt artifact is ours and nobody looks it up by sha1.
            trigon_attest::REBUILD => {
                assert_eq!(subject["sha256"], want["sha256"]);
                assert_eq!(subject["sha512"], want["sha512"]);
                assert!(subject.get("sha1").is_none(), "{subject}");
            }
            // Both statements about the published artifact carry all three.
            p => assert_eq!(subject, &want, "{p}"),
        }
        checked.push(predicate_of(&s).to_string());
    }
    checked.sort();
    assert_eq!(
        checked,
        [
            trigon_attest::BUILD_OBSERVATION,
            trigon_attest::EQUIVALENCE_V2,
            trigon_attest::REBUILD
        ]
    );

    // And a third party checks every one of them against the file in hand.
    let file = d.join(ARTIFACT);
    std::fs::write(&file, &bytes).unwrap();
    let equivalence = r
        .attestations
        .iter()
        .find(|p| p.ends_with("/equivalence.intoto.json"))
        .unwrap();
    let out = Command::new(bin())
        .arg("verify-attestation")
        .arg(root.join(equivalence))
        .arg("--rerun-comparison")
        .arg("--upstream")
        .arg(&file)
        .arg("--rebuild")
        .arg(&file)
        .output()
        .unwrap();
    ok(&out);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("the claim holds"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn a_run_without_its_bytes_takes_its_subject_from_what_it_recorded_at_fetch() {
    // A run that reached no verdict keeps no artifact, and its build observation still needs a
    // subject. The fetch computed the digests over the bytes as they arrived; a run recorded before
    // that has sha256 alone, and says only that.
    let d = dir("unstored");
    let root = d.join("store");
    let bytes = tgz();
    let store = Store::local(&root).unwrap();
    let artifact = ArtifactRef {
        name: ARTIFACT.into(),
        sha256: trigon_store::digest_of(&bytes),
        bytes: bytes.len() as u64,
        stored: false,
    };
    let mut recent = RunRecord::new("1789000400-eeeeeeee", TARGET, artifact.clone(), env(), "t");
    recent.terminal = Some("build-failed".into());
    recent.upstream_digests = Some(fetched(&bytes));
    let mut older = RunRecord::new("1789000500-ffffffff", TARGET, artifact, env(), "t");
    older.terminal = Some("build-failed".into());
    rt().block_on(async {
        store.put_run(&recent).await.unwrap();
        store.put_run(&older).await.unwrap();
    });

    for (run, keys) in [
        (&recent, &["sha1", "sha256", "sha512"][..]),
        (&older, &["sha256"][..]),
    ] {
        ok(&attest(&root, &run.id, None));
        let r = rt().block_on(store.get_run(&run.id)).unwrap();
        assert_eq!(r.attestations.len(), 1, "a build observation alone");
        let s = statement(&store, &r.attestations[0]);
        assert_eq!(predicate_of(&s), trigon_attest::BUILD_OBSERVATION);
        let named: Vec<&str> = s["subject"][0]["digest"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(named, keys, "{}", run.id);
    }
}

#[test]
fn a_record_whose_digests_are_not_of_its_bytes_is_not_signed() {
    // The record and the store describe different artifacts. Signing either would be signing
    // whichever a reader happened to check.
    let d = dir("disagree");
    let root = d.join("store");
    let store = Store::local(&root).unwrap();
    let mut run = rt().block_on(compared_run(&store, "1789000600-abababab", &tgz()));
    run.upstream_digests = Some(fetched(b"some other artifact"));
    rt().block_on(store.put_run(&run)).unwrap();

    let out = attest(&root, &run.id, None);
    assert!(!out.status.success(), "it signed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("do not hash to"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        rt().block_on(store.get_run(&run.id))
            .unwrap()
            .attestations
            .is_empty()
    );
}

#[test]
fn a_run_attested_per_target_and_attested_again_names_only_what_is_filed_under_it() {
    // A run attested before per-run filing names a per-target path, and another run of the target
    // may since have written over it. Attested again, the run names its own statements and sets
    // the shared path aside, where nothing serves it; the file itself is left alone.
    let d = dir("per-target");
    let root = d.join("store");
    let store = Store::local(&root).unwrap();
    let mut run = rt().block_on(compared_run(&store, "1789000700-a0a0a0a0", &tgz()));
    let shared = format!("attestations/npm/demo/1.0.0/{ARTIFACT}/equivalence.intoto.json");
    let theirs = serde_json::to_vec_pretty(&trigon_attest::Envelope::new(
        b"another run's statement, written over this one's",
        vec![],
    ))
    .unwrap();
    std::fs::create_dir_all(root.join(&shared).parent().unwrap()).unwrap();
    std::fs::write(root.join(&shared), &theirs).unwrap();
    run.attestations = vec![shared.clone()];
    rt().block_on(store.put_run(&run)).unwrap();

    let out = attest(&root, &run.id, None);
    ok(&out);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("set aside 1"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let r = rt().block_on(store.get_run(&run.id)).unwrap();
    assert_eq!(r.attestations.len(), 3, "{:?}", r.attestations);
    for path in &r.attestations {
        assert!(path.contains(&format!("/{}/", run.id)), "{path}");
    }
    assert_eq!(r.per_target_attestations, std::slice::from_ref(&shared));
    assert_eq!(std::fs::read(root.join(&shared)).unwrap(), theirs);
}

#[test]
fn a_run_naming_a_strategy_the_store_does_not_hold_is_not_signed_and_nothing_is_filed() {
    // The `strategy.json` byproduct would name a file no reader can fetch. Refused before the
    // first statement is filed, so a refusal leaves nothing behind it.
    let d = dir("no-strategy");
    let root = d.join("store");
    let store = Store::local(&root).unwrap();
    let mut run = rt().block_on(compared_run(&store, "1789000800-b0b0b0b0", &tgz()));
    run.strategy = Some(trigon_store::digest_of(b"a strategy nobody kept"));
    rt().block_on(store.put_run(&run)).unwrap();

    let out = attest(&root, &run.id, None);
    assert!(!out.status.success(), "it signed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("strategy blob"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = rt().block_on(store.get_run(&run.id)).unwrap();
    assert!(r.attestations.is_empty(), "{:?}", r.attestations);
    assert!(
        !root.join("attestations").exists(),
        "a refused attest filed a statement anyway"
    );
}
