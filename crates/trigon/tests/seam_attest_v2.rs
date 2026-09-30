//! What `trigon attest` signs for a published record: `docs/19` §10 phase 2's done-when, through
//! the binary.
//!
//! - A fresh `attest` produces v2 statements with every §4.2 field present, a test asserting each.
//! - Old v1 bundles still verify.
//! - A guard-tripped run yields `void/v1` and never a verdict, and so does an open-egress run.
//! - With `[publish] origin` and `disputes` unset, the falsifying command and the dispute pointer
//!   are absent; with them set they are present and render as specified.
//! - `--supersedes` and `--withdraw` sign what they supersede, and why, and refuse a record about
//!   another artifact.
//!
//! Each test gets a store, a home and a working directory of its own, and runs the binary with
//! the environment it names and no `TRIGON_*` variable it did not, so a developer's own
//! `evidence.toml` changes nothing here.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store, UpstreamDigests};

const TARGET: &str = "pkg:npm/demo@1.0.0";
const ARTIFACT: &str = "demo-1.0.0.tgz";
const ORIGIN: &str = "github.com/owner/trigon-evidence";
const DISPUTES: &str = "https://github.com/owner/trigon-evidence/issues";

const STRATEGY: &str = r#"
schema: 1
kind: flow
location:
  repo: https://github.com/owner/demo
  ref: ff8e7ba8b4122829cf66125ca8445cac7f073bce
src:
- uses: git-checkout
build:
- runs: npm pack
output_path: '*.tgz'
"#;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

/// A directory with `store/`, `home/` and `project/` under it.
fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-attest-v2-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["store", "home", "project"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    d
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn tgz(body: &[u8], mtime: u64) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
    h.set_cksum();
    b.append_data(&mut h, "package/index.js", body).unwrap();
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

fn environment(egress: &str) -> Environment {
    Environment {
        base_image: "docker.io/library/debian@sha256:aa".into(),
        derived_image: None,
        egress: egress.into(),
        isolation: "user_ns".into(),
        guard_manifest: None,
        guarded_members: None,
        attestable: egress != "open",
        registry_moment: None,
        pin: None,
    }
}

fn fetched(bytes: &[u8]) -> UpstreamDigests {
    UpstreamDigests {
        sha512: trigon_attest::sha512_of(bytes),
        sha1: Some(trigon_attest::sha1_of(bytes)),
        declared: Vec::new(),
        note: None,
    }
}

/// A run as `record_run` writes one today: both artifacts, the comparison, the strategy and the
/// guard manifest in the store; the Trigon that built it, how the strategy was derived, and when.
async fn compared_run(store: &Store, id: &str, upstream: &[u8], rebuilt: &[u8]) -> RunRecord {
    let up = store.blobs().put(upstream.to_vec()).await.unwrap();
    let rb = store.blobs().put(rebuilt.to_vec()).await.unwrap();
    let comparison = trigon_compare::compare_bytes(
        upstream.to_vec(),
        rebuilt.to_vec(),
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
    let strategy = trigon_strategy::from_yaml(STRATEGY).unwrap();
    let json = trigon_strategy::canonical(&strategy).unwrap();
    let strategy_blob = store.blobs().put(json.into_bytes()).await.unwrap();
    let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
    let guard = store
        .blobs()
        .put(br#"{"artifact":"demo","members":["cd"]}"#.to_vec())
        .await
        .unwrap();

    let mut env = environment("mirror-only");
    env.guard_manifest = Some(guard.to_hex());
    env.guarded_members = Some(1);
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: ARTIFACT.into(),
            sha256: up,
            bytes: upstream.len() as u64,
            stored: true,
        },
        env,
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.finished = Some("2026-09-27T00:03:00Z".into());
    r.outcome = Some(comparison.outcome.to_string());
    r.comparison = Some(cmp);
    r.rebuild = Some(ArtifactRef {
        name: ARTIFACT.into(),
        sha256: rb,
        bytes: rebuilt.len() as u64,
        stored: true,
    });
    r.upstream_digests = Some(fetched(upstream));
    r.strategy = Some(strategy_blob);
    r.strategy_digest = Some(trigon_strategy::strategy_digest(&strategy, &tools).unwrap());
    r.trigon_version = Some("0.0.0+git.1111111111111111111111111111111111111111".into());
    r.derivation = Some("heuristic".into());
    r.non_builtin_stabilizer = Some(false);
    store.put_run(&r).await.unwrap();
    r
}

/// `trigon <args>` in `d`, with `d/home` as HOME and nothing from this process's `TRIGON_*`.
fn trigon(d: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(bin());
    c.current_dir(d.join("project"))
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.args(args).envs(env.iter().copied()).output().unwrap()
}

fn attest(d: &Path, id: &str, extra: &[&str], env: &[(&str, &str)]) -> Output {
    let store = d.join("store");
    let mut args = vec!["attest", id, "--store", store.to_str().unwrap()];
    args.extend_from_slice(extra);
    trigon(d, &args, env)
}

fn ok(out: &Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    text
}

/// A user `evidence.toml` naming an origin and a dispute channel.
fn configure_namespace(d: &Path) {
    let path = d.join("home/.config/trigon/evidence.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        format!("[publish]\norigin = \"{ORIGIN}\"\ndisputes = \"{DISPUTES}\"\n"),
    )
    .unwrap();
}

/// Every statement the run's record names, decoded, keyed by predicate type.
fn statements(store: &Store, id: &str) -> Vec<serde_json::Value> {
    let r = rt().block_on(store.get_run(id)).unwrap();
    r.attestations
        .iter()
        .map(|p| {
            let env = rt().block_on(store.get_attestation(p)).unwrap();
            serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap()
        })
        .collect()
}

fn predicate_types(statements: &[serde_json::Value]) -> Vec<String> {
    let mut t: Vec<String> = statements
        .iter()
        .map(|s| s["predicateType"].as_str().unwrap().to_string())
        .collect();
    t.sort();
    t
}

fn the(statements: &[serde_json::Value], predicate: &str) -> serde_json::Value {
    statements
        .iter()
        .find(|s| s["predicateType"] == predicate)
        .unwrap_or_else(|| {
            panic!(
                "no {predicate} among {}",
                predicate_types(statements).join(", ")
            )
        })
        .clone()
}

// ---------------------------------------------------------------------------------------------
// A verdict
// ---------------------------------------------------------------------------------------------

#[test]
fn a_fresh_attest_signs_a_v2_verdict_with_every_field_docs_19_asks_for() {
    let d = dir("fields");
    configure_namespace(&d);
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (
        tgz(b"module.exports = 1\n", 1),
        tgz(b"module.exports = 1\n", 2),
    );
    let run = rt().block_on(compared_run(&store, "1789000000-aaaaaaaa", &u, &r));
    let out = ok(&attest(&d, &run.id, &[], &[]));
    assert!(
        out.contains(ORIGIN),
        "the operator is told what is signed: {out}"
    );

    let all = statements(&store, &run.id);
    assert_eq!(
        predicate_types(&all),
        [
            trigon_attest::BUILD_OBSERVATION,
            trigon_attest::EQUIVALENCE_V2,
            trigon_attest::REBUILD
        ]
    );
    let v = the(&all, trigon_attest::EQUIVALENCE_V2);
    let p = &v["predicate"];
    let subject_sha256 = v["subject"][0]["digest"]["sha256"].as_str().unwrap();
    let blob_hex = |d: trigon_core::Digest| d.to_hex();

    // 1. The outcome, as a string.
    assert_eq!(p["outcome"], "normalized");
    // 2. The stabilizer set: id and digest.
    assert_eq!(p["stabilizerSet"]["id"], "tar-gzip");
    assert_eq!(
        p["stabilizerSet"]["digest"]["sha256"],
        trigon_stabilize::profile("tar-gzip")
            .unwrap()
            .digest()
            .to_hex()
    );
    // …and the manifest's file, which is not the set digest, and is in the store under it.
    let manifest = p["evidence"]["stabilizerSetManifest"]["sha256"]
        .as_str()
        .unwrap();
    assert_ne!(
        manifest,
        p["stabilizerSet"]["digest"]["sha256"].as_str().unwrap()
    );
    let bytes = rt()
        .block_on(
            store
                .blobs()
                .get(&trigon_core::Digest::from_hex(manifest).unwrap()),
        )
        .unwrap();
    let m: trigon_stabilize::SetManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(m, trigon_stabilize::profile("tar-gzip").unwrap().manifest());
    // 3. When.
    assert_eq!(p["run"]["id"], run.id);
    assert_eq!(p["run"]["startedOn"], "2026-09-27T00:00:00Z");
    assert_eq!(p["run"]["finishedOn"], "2026-09-27T00:03:00Z");
    // 3. Which Trigon built it, from the run, and which signed it, this one.
    assert_eq!(
        p["trigonVersion"]["builder"],
        "0.0.0+git.1111111111111111111111111111111111111111"
    );
    let attestor = p["trigonVersion"]["attestor"].as_str().unwrap();
    assert!(attestor.starts_with("0.0.0+git."), "{attestor}");
    let version = trigon(&d, &["--version"], &[]);
    assert!(
        String::from_utf8_lossy(&version.stdout).contains(attestor),
        "the version signed is the one the binary reports"
    );
    // 4. The egress tier, and `attestable`.
    assert_eq!(p["egressTier"], "mirror-only");
    assert_eq!(p["attestable"], true);
    // 5. The derivation method, as recorded.
    assert_eq!(p["derivation"]["method"], "heuristic");
    // 6. The falsifying command, structured, and rendering exactly as specified.
    let argv: Vec<String> = serde_json::from_value(p["falsifyingCommand"]["argv"].clone()).unwrap();
    assert_eq!(
        argv.join(" "),
        format!(
            "trigon verify-attestation --lookup sha256:{subject_sha256} --predicate {} --origin \
             {ORIGIN} --rerun-comparison --upstream <file>",
            trigon_attest::EQUIVALENCE_V2
        )
    );
    // 6. The dispute pointer, typed.
    assert_eq!(
        p["disputePointer"],
        serde_json::json!({ "kind": "url", "url": DISPUTES })
    );
    // 7. The evidence digests: the comparison report, the rebuilt artifact, the strategy, the
    // guard manifest, each the digest of a blob the store holds.
    assert_eq!(
        p["evidence"]["comparison"]["sha256"],
        blob_hex(run.comparison.unwrap())
    );
    assert_eq!(
        p["evidence"]["rebuiltArtifact"]["sha256"],
        blob_hex(run.rebuild.as_ref().unwrap().sha256)
    );
    assert_eq!(
        p["evidence"]["strategy"]["sha256"],
        blob_hex(run.strategy.unwrap())
    );
    assert_eq!(
        p["evidence"]["guardManifest"]["sha256"],
        run.environment.guard_manifest.clone().unwrap()
    );
    // 8. The canonical purl, and its canonicalisation version.
    assert_eq!(p["purl"], TARGET);
    assert_eq!(p["purlCanon"], 1);
    // 9. Not superseding anything.
    assert!(p.get("supersedes").is_none());

    // `rebuild` names the set now, and stays v1.
    let rebuild = the(&all, trigon_attest::REBUILD);
    assert_eq!(rebuild["predicate"]["stabilizerSet"]["id"], "tar-gzip");
    assert_eq!(
        rebuild["predicate"]["runDetails"]["builder"]["version"]["trigon"],
        attestor
    );
}

#[test]
fn without_an_origin_and_a_dispute_channel_neither_is_signed() {
    let d = dir("no-namespace");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 2));
    let run = rt().block_on(compared_run(&store, "1789000100-bbbbbbbb", &u, &r));
    ok(&attest(&d, &run.id, &[], &[]));
    let v = the(&statements(&store, &run.id), trigon_attest::EQUIVALENCE_V2);
    // Absent, not empty: a statement made for local use names no repository.
    assert!(v["predicate"].get("falsifyingCommand").is_none(), "{v}");
    assert!(v["predicate"].get("disputePointer").is_none(), "{v}");

    // One of the two set, and not the other: still neither, and the operator is told why.
    let path = d.join("home/.config/trigon/evidence.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, format!("[publish]\norigin = \"{ORIGIN}\"\n")).unwrap();
    let run = rt().block_on(compared_run(&store, "1789000200-cccccccc", &u, &r));
    let out = ok(&attest(&d, &run.id, &[], &[]));
    assert!(out.contains("together or not at all"), "{out}");
    let v = the(&statements(&store, &run.id), trigon_attest::EQUIVALENCE_V2);
    assert!(v["predicate"].get("falsifyingCommand").is_none(), "{v}");
}

#[test]
fn a_run_that_recorded_no_derivation_is_not_signed_as_heuristic() {
    let d = dir("no-derivation");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789000300-dddddddd", &u, &r));
    run.derivation = None;
    run.trigon_version = None;
    rt().block_on(store.put_run(&run)).unwrap();
    ok(&attest(&d, &run.id, &[], &[]));
    let all = statements(&store, &run.id);
    let v = the(&all, trigon_attest::EQUIVALENCE_V2);
    assert!(v["predicate"].get("derivation").is_none(), "{v}");
    assert!(
        v["predicate"]["trigonVersion"].get("builder").is_none(),
        "{v}"
    );
    let rebuild = the(&all, trigon_attest::REBUILD);
    assert!(
        rebuild["predicate"]["derivation"].get("method").is_none(),
        "{}",
        rebuild["predicate"]["derivation"]
    );
}

/// `rebuild/v1`'s `derivation.transcript` names the model exchange the run kept, and is `null`
/// where it kept none. It was `null` whatever the run held: 24 of 75 attested runs in one store had
/// a transcript digest no statement signed.
#[test]
fn the_model_exchange_a_run_kept_is_signed_and_one_it_did_not_keep_is_not() {
    let d = dir("transcript");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789001500-b1b1b1b1", &u, &r));
    let exchange = rt()
        .block_on(store.blobs().put(br#"{"turns":[]}"#.to_vec()))
        .unwrap();
    run.transcript = Some(exchange);
    run.derivation = Some("model_assisted".into());
    rt().block_on(store.put_run(&run)).unwrap();
    ok(&attest(&d, &run.id, &[], &[]));
    let rebuild = the(&statements(&store, &run.id), trigon_attest::REBUILD);
    assert_eq!(
        rebuild["predicate"]["derivation"]["transcript"],
        serde_json::json!({ "sha256": exchange.to_hex() })
    );

    let bare = rt().block_on(compared_run(&store, "1789001600-b2b2b2b2", &u, &r));
    assert_eq!(bare.transcript, None);
    ok(&attest(&d, &bare.id, &[], &[]));
    let rebuild = the(&statements(&store, &bare.id), trigon_attest::REBUILD);
    assert!(
        rebuild["predicate"]["derivation"]["transcript"].is_null(),
        "{}",
        rebuild["predicate"]["derivation"]
    );
}

/// The gate counts a second attempt as agreeing by the record's agreement digest, so a record whose
/// digest is not its comparison's is refused, as one whose outcome is not is.
#[test]
fn a_record_whose_agreement_digest_is_not_its_comparisons_is_not_signed() {
    let d = dir("agreement");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789001700-b3b3b3b3", &u, &r));
    run.agreement = Some(trigon_core::Digest::from_bytes([1u8; 32]));
    rt().block_on(store.put_run(&run)).unwrap();
    let out = attest(&d, &run.id, &[], &[]);
    assert!(!out.status.success());
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("agreement digest"), "{e}");
    assert!(statements(&store, &run.id).is_empty(), "nothing was signed");

    // The one the comparison gives is signed.
    let bytes = rt()
        .block_on(store.blobs().get(&run.comparison.unwrap()))
        .unwrap();
    let c: trigon_compare::Comparison = serde_json::from_slice(&bytes).unwrap();
    run.agreement = Some(c.agreement());
    rt().block_on(store.put_run(&run)).unwrap();
    ok(&attest(&d, &run.id, &[], &[]));
}

#[test]
fn a_divergence_is_signed_as_divergence_v2_and_re_derives() {
    let d = dir("divergence");
    configure_namespace(&d);
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (
        tgz(b"module.exports = 1\n", 1),
        tgz(b"module.exports = 2\n", 1),
    );
    let run = rt().block_on(compared_run(&store, "1789000400-eeeeeeee", &u, &r));
    ok(&attest(&d, &run.id, &[], &[]));
    let rec = rt().block_on(store.get_run(&run.id)).unwrap();
    let path = rec
        .attestations
        .iter()
        .find(|p| p.ends_with("/divergence.intoto.json"))
        .expect("filed as a divergence");
    let v = the(&statements(&store, &run.id), trigon_attest::DIVERGENCE_V2);
    assert_eq!(v["predicate"]["outcome"], "divergent");
    let argv = v["predicate"]["falsifyingCommand"]["argv"].to_string();
    assert!(argv.contains(trigon_attest::DIVERGENCE_V2), "{argv}");

    // The v2 statement re-derives through the same path a v1 did.
    let (uf, rf) = (d.join("up.tgz"), d.join("rb.tgz"));
    std::fs::write(&uf, &u).unwrap();
    std::fs::write(&rf, &r).unwrap();
    let bundle = d.join("store").join(path);
    let out = trigon(
        &d,
        &[
            "verify-attestation",
            bundle.to_str().unwrap(),
            "--rerun-comparison",
            "--upstream",
            uf.to_str().unwrap(),
            "--rebuild",
            rf.to_str().unwrap(),
        ],
        &[],
    );
    let text = ok(&out);
    assert!(text.contains("divergence/v2"), "{text}");
    assert!(text.contains("the claim holds"), "{text}");
}

// ---------------------------------------------------------------------------------------------
// Old statements
// ---------------------------------------------------------------------------------------------

#[test]
fn a_v1_bundle_signed_before_v2_existed_still_verifies_through_the_binary() {
    // The signature verifies and the claim reads as it always did. Re-deriving it needs the
    // `tar-gzip` set it was signed under, which this binary no longer carries since two of that
    // set's passes took new ids (`docs/16-findings.md` §3.106): the binary names the set and where
    // its manifest is published, and refutes nothing. `crates/trigon-attest/tests/verdicts.rs`
    // re-derives the same bundles through that set.
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-statements");
    let public = std::fs::read_to_string(fixtures.join("public.hex")).unwrap();
    let d = dir("v1");
    for (bundle, rebuilt, claims) in [
        (
            "equivalence-v1.intoto.json",
            "rebuilt-demo-1.0.0.tgz",
            "normalized",
        ),
        (
            "divergence-v1.intoto.json",
            "diverged-demo-1.0.0.tgz",
            "divergent",
        ),
    ] {
        let path = fixtures.join(bundle);
        let read = [
            "verify-attestation",
            path.to_str().unwrap(),
            "--public-key",
            public.trim(),
        ];
        let out = trigon(&d, &read, &[]);
        let text = ok(&out);
        assert!(text.contains("signature verified"), "{bundle}: {text}");
        assert!(
            text.contains(&format!("claims    {claims}")),
            "{bundle}: {text}"
        );

        let upstream = fixtures.join("demo-1.0.0.tgz");
        let rebuilt = fixtures.join(rebuilt);
        let mut rerun = read.to_vec();
        rerun.extend([
            "--rerun-comparison",
            "--upstream",
            upstream.to_str().unwrap(),
            "--rebuild",
            rebuilt.to_str().unwrap(),
        ]);
        let out = trigon(&d, &rerun, &[]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{bundle}: re-derived under another set"
        );
        assert!(
            err.contains("The set this claim was made under is `tar-gzip@4598411b636d`"),
            "{bundle}: {err}"
        );
        assert!(!err.contains("refuted"), "{bundle}: {err}");
    }
}

// ---------------------------------------------------------------------------------------------
// Void
// ---------------------------------------------------------------------------------------------

/// A run the guard stopped, recorded as `record_terminal` records one: no comparison, no outcome,
/// no bytes kept.
async fn guard_tripped_run(store: &Store, id: &str, bytes: &[u8]) -> RunRecord {
    let guard = store
        .blobs()
        .put(br#"{"artifact":"demo","members":["cd"]}"#.to_vec())
        .await
        .unwrap();
    let mut env = environment("mirror-only");
    env.guard_manifest = Some(guard.to_hex());
    env.guarded_members = Some(1);
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: ARTIFACT.into(),
            sha256: trigon_store::digest_of(bytes),
            bytes: bytes.len() as u64,
            stored: false,
        },
        env,
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.terminal = Some("void".into());
    r.guard_trips = vec!["the artifact under test arrived from registry.npmjs.org".into()];
    r.upstream_digests = Some(fetched(bytes));
    r.trigon_version = Some("0.0.0+git.1111111111111111111111111111111111111111".into());
    store.put_run(&r).await.unwrap();
    r
}

/// Nothing in a void says which way a comparison went.
fn assert_says_nothing_of_an_outcome(p: &serde_json::Value) {
    assert_eq!(p["outcome"], "void");
    for absent in [
        "artifacts",
        "stabilized",
        "applied",
        "members",
        "differences",
        "container",
        "containerBitIdentical",
        "provenanceCap",
        "falsifyingCommand",
        "disputePointer",
    ] {
        assert!(p.get(absent).is_none(), "a void carries `{absent}`: {p}");
    }
    for absent in ["comparison", "rebuiltArtifact", "strategy"] {
        assert!(p["evidence"].get(absent).is_none(), "{absent}: {p}");
    }
}

#[test]
fn a_guard_tripped_run_yields_void_v1_and_never_a_verdict() {
    let d = dir("guard");
    configure_namespace(&d);
    let store = Store::local(&d.join("store")).unwrap();
    let bytes = tgz(b"x\n", 1);
    let run = rt().block_on(guard_tripped_run(&store, "1789000500-ffffffff", &bytes));
    let out = attest(&d, &run.id, &[], &[]);
    let text = ok(&out);
    assert!(text.contains("guard_tripped"), "{text}");
    assert!(text.contains("no verdict"), "{text}");

    let all = statements(&store, &run.id);
    assert_eq!(
        predicate_types(&all),
        [trigon_attest::VOID],
        "only the void"
    );
    let v = &all[0];
    let p = &v["predicate"];
    assert_eq!(p["because"], "guard_tripped");
    assert_eq!(
        p["facts"]["artifactHashCheck"]["trips"][0],
        run.guard_trips[0]
    );
    assert_eq!(p["facts"]["artifactHashCheck"]["performed"], true);
    assert_eq!(p["facts"]["artifactHashCheck"]["guardedMembers"], 1);
    assert_eq!(
        p["evidence"]["guardManifest"]["sha256"],
        run.environment.guard_manifest.clone().unwrap()
    );
    assert_eq!(p["purl"], TARGET);
    assert_eq!(p["egressTier"], "mirror-only");
    assert!(p.get("stabilizerSet").is_none(), "it never compared");
    // Every digest a consumer holds, from what the fetch recorded, since the bytes are gone.
    let digests = &v["subject"][0]["digest"];
    assert_eq!(digests["sha512"], trigon_attest::sha512_of(&bytes).to_hex());
    assert_eq!(digests["sha1"], trigon_attest::sha1_of(&bytes).to_hex());
    assert_says_nothing_of_an_outcome(p);

    // A void read back says what it is, and is not something to re-derive.
    let rec = rt().block_on(store.get_run(&run.id)).unwrap();
    let path = d.join("store").join(&rec.attestations[0]);
    let text = ok(&trigon(
        &d,
        &["verify-attestation", path.to_str().unwrap()],
        &[],
    ));
    assert!(
        text.contains("claims    void, because guard_tripped"),
        "{text}"
    );
    let f = d.join("up.tgz");
    std::fs::write(&f, &bytes).unwrap();
    let out = trigon(
        &d,
        &[
            "verify-attestation",
            path.to_str().unwrap(),
            "--rerun-comparison",
            "--upstream",
            f.to_str().unwrap(),
            "--rebuild",
            f.to_str().unwrap(),
        ],
        &[],
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("makes no comparison claim"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_guard_tripped_run_with_a_comparison_is_still_void_and_only_void() {
    // A run recorded with both — the guard tripped after the build compared — gets the same.
    let d = dir("guard-compared");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 1));
    let mut run = rt().block_on(compared_run(&store, "1789000600-a0a0a0a0", &u, &r));
    run.guard_trips = vec!["package/index.js arrived inside another package".into()];
    rt().block_on(store.put_run(&run)).unwrap();
    ok(&attest(&d, &run.id, &[], &[]));
    let all = statements(&store, &run.id);
    assert_eq!(predicate_types(&all), [trigon_attest::VOID]);
    let p = &all[0]["predicate"];
    assert_eq!(p["because"], "guard_tripped");
    assert_eq!(p["stabilizerSet"]["id"], "tar-gzip");
    assert_says_nothing_of_an_outcome(p);
}

#[test]
fn an_open_egress_run_yields_void_too() {
    // This was signed as a verdict: the attestor refused a tripped guard and nothing else, so an
    // open-egress divergence became a signed `divergence/v1` that only the API's gate held back.
    let d = dir("open");
    configure_namespace(&d);
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (
        tgz(b"module.exports = 1\n", 1),
        tgz(b"module.exports = 2\n", 1),
    );
    let mut run = rt().block_on(compared_run(&store, "1789000700-b0b0b0b0", &u, &r));
    run.environment.egress = "open".into();
    run.environment.attestable = false;
    rt().block_on(store.put_run(&run)).unwrap();
    let text = ok(&attest(&d, &run.id, &[], &[]));
    assert!(text.contains("open_egress"), "{text}");
    assert!(
        !text.contains("rederived"),
        "nothing was re-derived to be signed: {text}"
    );

    let all = statements(&store, &run.id);
    assert_eq!(predicate_types(&all), [trigon_attest::VOID]);
    let p = &all[0]["predicate"];
    assert_eq!(p["because"], "open_egress");
    assert_eq!(p["egressTier"], "open");
    assert_eq!(p["attestable"], false);
    assert_says_nothing_of_an_outcome(p);
    // And not the word, anywhere in the signed bytes.
    assert!(!all[0].to_string().contains("divergen"), "{}", all[0]);
}

#[test]
fn a_void_that_its_own_evidence_does_not_support_is_not_signed() {
    // The record says a stabilizer somebody wrote applied; the comparison it names shows only
    // built-in passes. A void is harmless, and still not signed on a fact that is not true.
    let d = dir("non-builtin");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789000800-c0c0c0c0", &u, &r));
    run.non_builtin_stabilizer = Some(true);
    rt().block_on(store.put_run(&run)).unwrap();
    let out = attest(&d, &run.id, &[], &[]);
    assert!(!out.status.success(), "it signed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("built in"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(statements(&store, &run.id).is_empty());
}

/// Put a pass a person wrote among the comparison's applied passes, on both sides, and point the
/// run at the result: the comparison of a run whose normalization somebody hand-wrote. Returns
/// the built-in passes that were already there, so a test can say they are not the ones named.
async fn with_an_authored_pass(store: &Store, r: &mut RunRecord) -> Vec<String> {
    let bytes = store.blobs().get(&r.comparison.unwrap()).await.unwrap();
    let mut c: trigon_compare::Comparison = serde_json::from_slice(&bytes).unwrap();
    let builtin: Vec<String> = c
        .applied()
        .iter()
        .map(|a| a.id.as_str().to_string())
        .collect();
    let pass = trigon_stabilize::Applied {
        id: trigon_core::StabilizerId::new("strip-build-banner"),
        risk: trigon_core::RiskTier::Content,
        provenance: trigon_core::Provenance::Human {
            reviewer: "a-maintainer".into(),
        },
        entries_touched: 1,
        bytes_changed: 8,
    };
    c.upstream.applied.push(pass.clone());
    c.rebuild.applied.push(pass);
    let digest = store
        .blobs()
        .put(serde_json::to_vec(&c).unwrap())
        .await
        .unwrap();
    r.comparison = Some(digest);
    store.put_run(r).await.unwrap();
    builtin
}

#[test]
fn a_run_a_hand_written_stabilizer_applied_to_is_signed_as_void_and_only_void() {
    // The one void whose facts the attestor reads from the comparison: which passes a person or
    // a model wrote, each once, and none of the built-in ones beside them.
    let d = dir("authored-void");
    configure_namespace(&d);
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789000850-c1c1c1c1", &u, &r));
    let builtin = rt().block_on(with_an_authored_pass(&store, &mut run));
    assert!(
        !builtin.is_empty(),
        "a built-in pass applied too, so the test can tell them apart"
    );
    run.non_builtin_stabilizer = Some(true);
    rt().block_on(store.put_run(&run)).unwrap();

    let text = ok(&attest(&d, &run.id, &[], &[]));
    assert!(text.contains("non_builtin_stabilizer"), "{text}");
    assert!(!text.contains("rederived"), "{text}");
    let all = statements(&store, &run.id);
    assert_eq!(
        predicate_types(&all),
        [trigon_attest::VOID],
        "only the void"
    );
    let p = &all[0]["predicate"];
    assert_eq!(p["because"], "non_builtin_stabilizer");
    assert_eq!(
        p["facts"]["authoredStabilizers"],
        serde_json::json!([
            { "id": "strip-build-banner", "risk": "content", "provenance": "human" }
        ]),
        "exactly the pass a person wrote, once, though it applied on both sides"
    );
    assert_eq!(p["stabilizerSet"]["id"], "tar-gzip");
    assert_eq!(p["egressTier"], "mirror-only");
    assert_says_nothing_of_an_outcome(p);
    assert!(!all[0].to_string().contains(&run.outcome.clone().unwrap()));
}

#[test]
fn a_verdict_is_not_signed_for_a_record_that_hides_a_hand_written_stabilizer() {
    // The record says no hand-written pass applied, or nothing either way, and the comparison it
    // names shows one did. The gate reads the record, so a verdict signed here would be published
    // by it as one, about a run that is void.
    for (what, says) in [("says-no", Some(false)), ("says-nothing", None)] {
        let d = dir(&format!("authored-hidden-{what}"));
        configure_namespace(&d);
        let store = Store::local(&d.join("store")).unwrap();
        let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 1));
        let mut run = rt().block_on(compared_run(&store, "1789000870-c2c2c2c2", &u, &r));
        rt().block_on(with_an_authored_pass(&store, &mut run));
        run.non_builtin_stabilizer = says;
        rt().block_on(store.put_run(&run)).unwrap();

        let out = attest(&d, &run.id, &[], &[]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{what}: it signed");
        assert!(
            err.contains("`strip-build-banner` (human)"),
            "{what}: {err}"
        );
        assert!(
            err.contains("disagrees with its own evidence"),
            "{what}: {err}"
        );
        assert!(statements(&store, &run.id).is_empty(), "{what}");
    }
}

// ---------------------------------------------------------------------------------------------
// Supersession and withdrawal
// ---------------------------------------------------------------------------------------------

/// A record file holding the run's signed statements, as `publish` will write one.
fn record_file(d: &Path, store: &Store, id: &str) -> PathBuf {
    let r = rt().block_on(store.get_run(id)).unwrap();
    let envelopes: Vec<trigon_attest::Envelope> = r
        .attestations
        .iter()
        .map(|p| rt().block_on(store.get_attestation(p)).unwrap())
        .collect();
    let primary = statements(store, id)
        .into_iter()
        .find(|s| trigon_attest::is_primary(s["predicateType"].as_str().unwrap()))
        .unwrap();
    let record = serde_json::json!({
        "schema": trigon_attest::RECORD_SCHEMA,
        "subject": {
            "purl": primary["predicate"]["purl"],
            "digests": primary["subject"][0]["digest"],
        },
        "statements": envelopes,
        "evidence": {},
    });
    let path = d.join(format!("{id}.record.json"));
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    path
}

fn sha256_of(path: &Path) -> String {
    trigon_store::digest_of(&std::fs::read(path).unwrap()).to_hex()
}

#[test]
fn a_superseding_verdict_signs_what_it_supersedes_and_why() {
    let d = dir("supersede");
    configure_namespace(&d);
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (tgz(b"x\n", 1), tgz(b"x\n", 2));
    let first = rt().block_on(compared_run(&store, "1789000900-d0d0d0d0", &u, &r));
    ok(&attest(&d, &first.id, &[], &[]));
    let record = record_file(&d, &store, &first.id);

    let second = rt().block_on(compared_run(&store, "1789001000-d0d0d0d0", &u, &r));
    let text = ok(&attest(
        &d,
        &second.id,
        &[
            "--supersedes",
            record.to_str().unwrap(),
            "--reason",
            "set_changed",
        ],
        &[],
    ));
    assert!(text.contains(&sha256_of(&record)), "{text}");
    let v = the(
        &statements(&store, &second.id),
        trigon_attest::EQUIVALENCE_V2,
    );
    assert_eq!(
        v["predicate"]["supersedes"],
        format!("sha256:{}", sha256_of(&record))
    );
    assert_eq!(v["predicate"]["reason"], "set_changed");
}

#[test]
fn a_supersession_of_a_record_about_another_artifact_is_refused() {
    let d = dir("supersede-other");
    let store = Store::local(&d.join("store")).unwrap();
    let first = rt().block_on(compared_run(
        &store,
        "1789001100-e0e0e0e0",
        &tgz(b"one\n", 1),
        &tgz(b"one\n", 2),
    ));
    ok(&attest(&d, &first.id, &[], &[]));
    let record = record_file(&d, &store, &first.id);
    let other = rt().block_on(compared_run(
        &store,
        "1789001200-e0e0e0e0",
        &tgz(b"two\n", 1),
        &tgz(b"two\n", 2),
    ));
    let out = attest(
        &d,
        &other.id,
        &[
            "--supersedes",
            record.to_str().unwrap(),
            "--reason",
            "pipeline_bug",
        ],
        &[],
    );
    assert!(!out.status.success(), "it signed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("same artifact"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(statements(&store, &other.id).is_empty());
}

#[test]
fn a_withdrawal_names_the_record_and_the_reason_and_carries_no_verdict() {
    let d = dir("withdraw");
    let store = Store::local(&d.join("store")).unwrap();
    let key = d.join("signing.key");
    ok(&trigon(
        &d,
        &["keygen", "--out", key.to_str().unwrap()],
        &[],
    ));
    let run = rt().block_on(compared_run(
        &store,
        "1789001300-f0f0f0f0",
        &tgz(b"x\n", 1),
        &tgz(b"x\n", 2),
    ));
    ok(&attest(&d, &run.id, &[], &[]));
    let record = record_file(&d, &store, &run.id);
    let verdict = the(&statements(&store, &run.id), trigon_attest::EQUIVALENCE_V2);

    let store_dir = d.join("store");
    let text = ok(&trigon(
        &d,
        &[
            "attest",
            "--store",
            store_dir.to_str().unwrap(),
            "--withdraw",
            record.to_str().unwrap(),
            "--reason",
            "withdrawn",
            "--key",
            key.to_str().unwrap(),
        ],
        &[],
    ));
    let path = format!(
        "withdrawals/sha256/{}/withdrawal.intoto.json",
        sha256_of(&record)
    );
    assert!(text.contains(&path), "{text}");
    let env = rt().block_on(store.get_attestation(&path)).unwrap();
    assert!(env.is_signed());
    let st: serde_json::Value = serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap();
    assert_eq!(st["predicateType"], trigon_attest::WITHDRAWAL);
    // The superseded record's own subject and purl.
    assert_eq!(st["subject"], verdict["subject"]);
    let p = &st["predicate"];
    assert_eq!(p["purl"], TARGET);
    assert_eq!(p["purlCanon"], 1);
    assert_eq!(p["supersedes"], format!("sha256:{}", sha256_of(&record)));
    assert_eq!(p["reason"], "withdrawn");
    assert!(
        p.get("outcome").is_none(),
        "a withdrawal is no verdict: {p}"
    );

    // And it reads back as what it is.
    let text = ok(&trigon(
        &d,
        &[
            "verify-attestation",
            store_dir.join(&path).to_str().unwrap(),
        ],
        &[],
    ));
    assert!(
        text.contains(&format!(
            "withdraws sha256:{} (withdrawn)",
            sha256_of(&record)
        )),
        "{text}"
    );
}

#[test]
fn the_reason_is_one_of_the_closed_list_and_required() {
    let d = dir("reasons");
    let store_dir = d.join("store");
    let s = store_dir.to_str().unwrap();
    for (args, says) in [
        (
            vec!["attest", "--store", s, "--withdraw", "r.json"],
            "--reason",
        ),
        (
            vec![
                "attest",
                "--store",
                s,
                "--withdraw",
                "r.json",
                "--reason",
                "oops",
            ],
            "set_changed",
        ),
        (
            vec!["attest", "--store", s, "--reason", "withdrawn"],
            "--supersedes",
        ),
    ] {
        let out = trigon(&d, &args, &[]);
        assert!(!out.status.success(), "{args:?}");
        let e = String::from_utf8_lossy(&out.stderr);
        assert!(e.contains(says), "{args:?}: {e}");
    }
}

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

#[test]
fn a_configuration_that_cannot_be_read_stops_attest_with_exit_5_and_says_where() {
    let d = dir("bad-config");
    let store = Store::local(&d.join("store")).unwrap();
    let run = rt().block_on(compared_run(
        &store,
        "1789001400-a1a1a1a1",
        &tgz(b"x\n", 1),
        &tgz(b"x\n", 2),
    ));
    let path = d.join("home/.config/trigon/evidence.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "[publish]\norign = \"github.com/owner/r\"\n").unwrap();
    let out = attest(&d, &run.id, &[], &[]);
    assert_eq!(out.status.code(), Some(5));
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(
        e.contains("orign") && e.contains(&path.display().to_string()),
        "{e}"
    );
    assert!(statements(&store, &run.id).is_empty(), "nothing was signed");

    // `TRIGON_EVIDENCE_CONFIG` names the file instead, and a project's own is refused whole.
    let named = d.join("named.toml");
    std::fs::write(
        &named,
        format!("[publish]\norigin = \"{ORIGIN}\"\ndisputes = \"{DISPUTES}\"\n"),
    )
    .unwrap();
    let text = ok(&attest(
        &d,
        &run.id,
        &[],
        &[("TRIGON_EVIDENCE_CONFIG", named.to_str().unwrap())],
    ));
    assert!(text.contains(ORIGIN), "{text}");

    std::fs::remove_file(&path).unwrap();
    let project = d.join("project/.trigon/evidence.toml");
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(&project, "[publish]\norigin = \"evil.example/x\"\n").unwrap();
    let out = attest(&d, &run.id, &[], &[]);
    assert_eq!(out.status.code(), Some(5));
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("[publish]") && e.contains("refused"), "{e}");
}
