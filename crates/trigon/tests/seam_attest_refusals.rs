//! What `trigon attest` refuses to sign, and what it says about a store, through the binary.
//!
//! The attestor is a separate process because the one that ran the build could record any outcome
//! it liked (`docs/09-attestations.md` §6): it reads blobs by hash, re-derives the claim and only
//! then signs. So the tests that matter are the refusals — a record that disagrees with its own
//! evidence, a comparison the bytes do not give, bytes the store no longer holds, a set this
//! binary does not carry, digests that are not the bytes', a transcript that cannot be read, a
//! void its evidence does not show, and a supersession that would be signed and never applied —
//! each of which must leave nothing signed behind it.
//!
//! Each test gets a store, a home and a working directory of its own, and runs the binary with no
//! `TRIGON_*` variable from this process, so a developer's own `evidence.toml` changes nothing.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store, UpstreamDigests};

mod set_module;

const TARGET: &str = "pkg:npm/demo@1.0.0";
const ARTIFACT: &str = "demo-1.0.0.tgz";

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
    let d = std::env::temp_dir().join(format!(
        "trigon-attest-refusals-{}-{what}",
        std::process::id()
    ));
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

fn tgz(members: &[(&str, &[u8])], mtime: u64) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(mtime);
        h.set_cksum();
        b.append_data(&mut h, *name, *body).unwrap();
    }
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

/// One member, `package/index.js`, holding `body`, stamped `mtime`.
fn one(body: &[u8], mtime: u64) -> Vec<u8> {
    tgz(&[("package/index.js", body)], mtime)
}

fn environment() -> Environment {
    Environment {
        base_image: "docker.io/library/debian@sha256:aa".into(),
        derived_image: None,
        egress: "mirror-only".into(),
        isolation: "user_ns".into(),
        guard_manifest: None,
        guarded_members: None,
        attestable: true,
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

fn compare(upstream: &[u8], rebuilt: &[u8]) -> trigon_compare::Comparison {
    trigon_compare::compare_bytes(
        upstream.to_vec(),
        rebuilt.to_vec(),
        trigon_core::Format::TarGz,
        &trigon_stabilize::profile("tar-gzip").unwrap(),
        &trigon_archive::Limits::default(),
    )
    .unwrap()
}

/// A run as `record_run` writes one: both artifacts, the comparison, the strategy and the guard
/// manifest in the store, the Trigon that built it, how the strategy was derived, and when.
async fn compared_run(
    store: &Store,
    id: &str,
    target: &str,
    upstream: &[u8],
    rebuilt: &[u8],
) -> RunRecord {
    let up = store.blobs().put(upstream.to_vec()).await.unwrap();
    let rb = store.blobs().put(rebuilt.to_vec()).await.unwrap();
    let comparison = compare(upstream, rebuilt);
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

    let mut env = environment();
    env.guard_manifest = Some(guard.to_hex());
    env.guarded_members = Some(1);
    let mut r = RunRecord::new(
        id,
        target,
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
        name: format!("rebuilt-{ARTIFACT}"),
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

/// A run that reached no comparison and is not void: a build that failed at an enforced tier. Its
/// artifact is not kept, so its subject is the digests the fetch computed.
async fn failed_run(store: &Store, id: &str, upstream: &[u8]) -> RunRecord {
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: ARTIFACT.into(),
            sha256: trigon_store::digest_of(upstream),
            bytes: upstream.len() as u64,
            stored: false,
        },
        environment(),
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.terminal = Some("build-failed:build".into());
    r.upstream_digests = Some(fetched(upstream));
    r.trigon_version = Some("0.0.0+git.1111111111111111111111111111111111111111".into());
    store.put_run(&r).await.unwrap();
    r
}

/// Point `r` at `c` as its comparison, stored as the run path stores one.
async fn with_comparison(store: &Store, r: &mut RunRecord, c: &trigon_compare::Comparison) {
    let digest = store
        .blobs()
        .put(serde_json::to_vec(c).unwrap())
        .await
        .unwrap();
    r.comparison = Some(digest);
    store.put_run(r).await.unwrap();
}

/// `trigon <args>` in `d/project`, with `d/home` as HOME and nothing from this process's
/// `TRIGON_*`.
fn trigon(d: &Path, args: &[&str]) -> Output {
    let mut c = Command::new(bin());
    c.current_dir(d.join("project"))
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"))
        .env("XDG_STATE_HOME", d.join("home/.local/state"))
        .env("NO_COLOR", "1");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.args(args).output().unwrap()
}

fn attest(d: &Path, id: &str, extra: &[&str]) -> Output {
    let store = d.join("store");
    let mut args = vec!["attest", id, "--store", store.to_str().unwrap()];
    args.extend_from_slice(extra);
    trigon(d, &args)
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

/// The refusal: a failure, and what it said on stderr.
fn refused(out: &Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "it signed:\n{}{err}",
        String::from_utf8_lossy(&out.stdout)
    );
    err
}

/// Every statement the run's record names, decoded.
///
/// Not what a refusal is held to: the record names a statement only once `attest` has finished
/// signing, so after any refusal this is empty whatever was already written to disk. [`filed_for`]
/// looks at the disk.
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

/// Every file under the store's attestation tree: what a refusal must not have left behind,
/// whether or not a record names it.
fn filed(d: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![d.join("store")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.to_string_lossy().ends_with(".intoto.json") {
                out.push(p);
            }
        }
    }
    out
}

/// Every statement file under run `id`'s own directory. Statements are filed per run
/// (`attestations/…/<artifact>/<run-id>/`), so this is what a refusal of that run must not have
/// left behind, and a run attested earlier in the same store is not counted against it.
fn filed_for(d: &Path, id: &str) -> Vec<PathBuf> {
    filed(d)
        .into_iter()
        .filter(|p| p.components().any(|c| c.as_os_str() == id))
        .collect()
}

fn the(statements: &[serde_json::Value], predicate: &str) -> serde_json::Value {
    statements
        .iter()
        .find(|s| s["predicateType"] == predicate)
        .unwrap_or_else(|| panic!("no {predicate} among {statements:?}"))
        .clone()
}

/// A record file holding the run's signed statements, as `publish` writes one.
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

// ---------------------------------------------------------------------------------------------
// A record that disagrees with its evidence
// ---------------------------------------------------------------------------------------------

/// The record is a separate document from the comparison it points at, written by the process
/// that ran the build. A record claiming better than its comparison would otherwise have that
/// claim survive into `trigon runs` and everything that reads it.
#[test]
fn a_record_claiming_another_outcome_than_its_comparison_is_not_signed() {
    let d = dir("outcome");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789002000-a0a0a0a0", TARGET, &u, &r));
    assert_eq!(run.outcome.as_deref(), Some("normalized"));
    run.outcome = Some("exact".into());
    rt().block_on(store.put_run(&run)).unwrap();

    let err = refused(&attest(&d, &run.id, &[]));
    assert!(
        err.contains(
            "the run record says `exact` and the comparison it points at says `normalized`"
        ),
        "{err}"
    );
    assert!(err.contains("disagrees with its own evidence"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed(&d).is_empty(), "{:?}", filed(&d));
}

/// The stored comparison overstates what the bytes give, and the record agrees with it: the one
/// forgery re-deriving exists to catch. Nothing is signed, and the refusal names both outcomes.
#[test]
fn a_comparison_the_bytes_do_not_give_is_refused_before_anything_is_signed() {
    let d = dir("forged");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789002100-a1a1a1a1", TARGET, &u, &r));
    let mut forged = compare(&u, &r);
    assert_eq!(forged.outcome, trigon_core::Match::Normalized);
    forged.outcome = trigon_core::Match::Exact;
    run.outcome = Some("exact".into());
    rt().block_on(with_comparison(&store, &mut run, &forged));

    let err = refused(&attest(&d, &run.id, &[]));
    assert!(
        err.contains("refusing to sign: the run recorded `exact` and the bytes give `normalized`"),
        "{err}"
    );
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed(&d).is_empty(), "{:?}", filed(&d));
}

/// A run whose artifacts were pruned after it was attested cannot be signed again: the claim
/// cannot be re-derived from bytes the store no longer holds, and signing it anyway would be
/// signing what the record says.
#[test]
fn a_run_whose_artifacts_are_gone_is_not_signed_again() {
    let d = dir("pruned");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789002200-a2a2a2a2", TARGET, &u, &r));
    run.rebuild.as_mut().unwrap().stored = false;
    rt().block_on(store.put_run(&run)).unwrap();

    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains("no longer in the store"), "{err}");
    assert!(err.contains("cannot be re-derived"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// A comparison made under a set this binary does not carry cannot be re-derived here, so it is
/// not signed here: a different set would be answering a different question.
#[test]
fn a_comparison_made_under_a_set_this_binary_lacks_is_not_signed() {
    let d = dir("unknown-set");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789002300-a3a3a3a3", TARGET, &u, &r));
    let mut c = compare(&u, &r);
    c.upstream.set.0 = trigon_core::ProfileId::new("tar-gzip-retired");
    c.rebuild.set.0 = trigon_core::ProfileId::new("tar-gzip-retired");
    rt().block_on(with_comparison(&store, &mut run, &c));

    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains("`tar-gzip-retired`"), "{err}");
    assert!(
        err.contains("does not carry, so the claim cannot be re-derived to be signed"),
        "{err}"
    );
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// The record's fetch-time digests and the stored bytes describe different artifacts. A subject
/// is signed for neither: the sha512 a consumer looks a record up by would name some other file.
#[test]
fn published_bytes_that_are_not_what_the_fetch_hashed_are_not_given_a_subject() {
    let d = dir("subject");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789002400-a4a4a4a4", TARGET, &u, &r));
    run.upstream_digests = Some(fetched(b"some other artifact"));
    rt().block_on(store.put_run(&run)).unwrap();

    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains("the stored bytes do not hash to"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// An empty transcript is the claim that the build fetched nothing, so one that cannot be read
/// stops the attestation rather than being summarised as empty — and one the store does not hold
/// stops it too.
#[test]
fn a_network_transcript_that_cannot_be_read_stops_the_attestation() {
    let d = dir("transcript");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789002500-a5a5a5a5", TARGET, &u, &r));

    let garbage = rt()
        .block_on(store.blobs().put(b"this is not an exchange\n".to_vec()))
        .unwrap();
    run.network_transcript = Some(garbage);
    rt().block_on(store.put_run(&run)).unwrap();
    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains("cannot be read"), "{err}");
    assert!(statements(&store, &run.id).is_empty());

    run.network_transcript = Some(trigon_store::digest_of(b"bytes nobody stored"));
    rt().block_on(store.put_run(&run)).unwrap();
    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains("reading the network transcript"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed(&d).is_empty(), "{:?}", filed(&d));

    // And an empty one is read as exactly that: a complete account of a build that fetched
    // nothing, counted from the blob.
    let empty = rt().block_on(store.blobs().put(Vec::new())).unwrap();
    run.network_transcript = Some(empty);
    rt().block_on(store.put_run(&run)).unwrap();
    ok(&attest(&d, &run.id, &[]));
    let obs = the(
        &statements(&store, &run.id),
        trigon_attest::BUILD_OBSERVATION,
    );
    let t = &obs["predicate"]["networkTranscript"];
    assert_eq!(t["requests"], 0, "{t}");
    assert_eq!(t["bytes"], 0, "{t}");
}

/// A guard manifest the record names and the store does not hold — a run recorded before the
/// manifest was kept — is named as evidence by no statement, since a record cannot carry bytes
/// nobody kept; the build observation still names the digest the guard was armed with.
#[test]
fn a_guard_manifest_the_store_lost_is_not_named_as_evidence() {
    let d = dir("guard");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut run = rt().block_on(compared_run(&store, "1789002600-a6a6a6a6", TARGET, &u, &r));
    let lost = "ab".repeat(32);
    run.environment.guard_manifest = Some(lost.clone());
    rt().block_on(store.put_run(&run)).unwrap();

    let text = ok(&attest(&d, &run.id, &[]));
    assert!(text.contains("is not in the store"), "{text}");
    let all = statements(&store, &run.id);
    let verdict = the(&all, trigon_attest::EQUIVALENCE_V2);
    let evidence = &verdict["predicate"]["evidence"];
    assert!(evidence.get("guardManifest").is_none(), "{evidence}");
    assert!(evidence.get("comparison").is_some(), "{evidence}");
    let obs = the(&all, trigon_attest::BUILD_OBSERVATION);
    assert_eq!(
        obs["predicate"]["artifactHashCheck"]["guardManifest"]["sha256"], lost,
        "{}",
        obs["predicate"]
    );
}

// ---------------------------------------------------------------------------------------------
// Voids and supersessions
// ---------------------------------------------------------------------------------------------

/// A record that says a stabilizer somebody wrote applied, with no comparison to show one did, is
/// void by what it says and signed as nothing: a void resting on a fact its evidence does not
/// show is still a signed statement that is not known to be true.
#[test]
fn a_void_with_no_comparison_to_show_its_reason_is_not_signed() {
    let d = dir("void-unshown");
    let store = Store::local(&d.join("store")).unwrap();
    let u = one(b"x\n", 1);
    let mut run = rt().block_on(failed_run(&store, "1789002700-a7a7a7a7", &u));
    run.terminal = None;
    run.outcome = Some("normalized".into());
    run.non_builtin_stabilizer = Some(true);
    rt().block_on(store.put_run(&run)).unwrap();

    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains("it has no comparison to show which"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// A supersession rides on a run's result, and a run that compared nothing has none. Refused
/// before anything is filed, so no build observation is left beside a supersession that failed.
#[test]
fn a_run_with_no_comparison_supersedes_nothing() {
    let d = dir("supersede-nothing");
    let store = Store::local(&d.join("store")).unwrap();
    let u = one(b"x\n", 1);
    let first = rt().block_on(compared_run(
        &store,
        "1789002800-a8a8a8a8",
        TARGET,
        &u,
        &one(b"x\n", 2),
    ));
    ok(&attest(&d, &first.id, &[]));
    let record = record_file(&d, &store, &first.id);

    let failed = rt().block_on(failed_run(&store, "1789002900-a8a8a8a8", &u));
    let out = attest(
        &d,
        &failed.id,
        &[
            "--supersedes",
            record.to_str().unwrap(),
            "--reason",
            "set_changed",
        ],
    );
    let err = refused(&out);
    assert!(
        err.contains("reached no comparison, so there is no verdict to supersede"),
        "{err}"
    );
    assert!(statements(&store, &failed.id).is_empty());
    // The run attested first keeps what it filed; the refused one has nothing under it.
    assert!(!filed_for(&d, &first.id).is_empty(), "{:?}", filed(&d));
    assert!(filed_for(&d, &failed.id).is_empty(), "{:?}", filed(&d));

    // Without the supersession the same run is signed as what it is: a build observation and
    // no result.
    let text = ok(&attest(&d, &failed.id, &[]));
    assert!(text.contains("unsigned"), "{text}");
    let all = statements(&store, &failed.id);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0]["predicateType"], trigon_attest::BUILD_OBSERVATION);
}

/// A client drops a superseded record only for one about the same artifact and the same package
/// (`docs/19` §3). The same bytes under another purl would be signed, logged and ignored, so it
/// is refused where the mistake is made.
#[test]
fn a_supersession_about_the_same_bytes_under_another_package_is_refused() {
    let d = dir("supersede-purl");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let first = rt().block_on(compared_run(&store, "1789003000-b0b0b0b0", TARGET, &u, &r));
    ok(&attest(&d, &first.id, &[]));
    let record = record_file(&d, &store, &first.id);

    let other = rt().block_on(compared_run(
        &store,
        "1789003100-b0b0b0b0",
        "pkg:npm/other@1.0.0",
        &u,
        &r,
    ));
    let err = refused(&attest(
        &d,
        &other.id,
        &[
            "--supersedes",
            record.to_str().unwrap(),
            "--reason",
            "pipeline_bug",
        ],
    ));
    assert!(
        err.contains(
            "the record is about `pkg:npm/demo@1.0.0` and this run about `pkg:npm/other@1.0.0`"
        ),
        "{err}"
    );
    assert!(err.contains("names the same package"), "{err}");
    assert!(statements(&store, &other.id).is_empty());
    assert!(!filed_for(&d, &first.id).is_empty(), "{:?}", filed(&d));
    assert!(filed_for(&d, &other.id).is_empty(), "{:?}", filed(&d));
}

/// Every statement about a published artifact signs a canonical purl, so a run about something
/// that has none is not signed at all.
#[test]
fn a_run_about_something_with_no_canonical_purl_is_not_signed() {
    let d = dir("no-purl");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let run = rt().block_on(compared_run(
        &store,
        "1789003200-b1b1b1b1",
        "demo@1.0.0",
        &u,
        &r,
    ));
    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains("which has no canonical purl"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed(&d).is_empty(), "{:?}", filed(&d));
}

// ---------------------------------------------------------------------------------------------
// Which run, and what a store says it holds
// ---------------------------------------------------------------------------------------------

/// `trigon attest` without a run signs the most recent, and a store with none says so rather than
/// signing nothing and succeeding.
#[test]
fn attest_without_a_run_signs_the_most_recent_one() {
    let d = dir("most-recent");
    let store_dir = d.join("store");
    let s = store_dir.to_str().unwrap();
    let err = refused(&trigon(&d, &["attest", "--store", s]));
    assert!(err.contains("this store holds no runs"), "{err}");

    let store = Store::local(&store_dir).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let older = rt().block_on(compared_run(&store, "1789003300-b2b2b2b2", TARGET, &u, &r));
    let newer = rt().block_on(compared_run(&store, "1789003400-b2b2b2b2", TARGET, &u, &r));
    let text = ok(&trigon(&d, &["attest", "--store", s]));
    assert!(text.contains(&format!("run       {}", newer.id)), "{text}");
    assert!(!statements(&store, &newer.id).is_empty());
    assert!(statements(&store, &older.id).is_empty());
}

/// A run the store does not hold is a mistyped id: said as the command line's, never as a bug in
/// trigon to be reported, and nothing is signed.
#[test]
fn a_run_the_store_does_not_hold_is_the_command_lines_fault_and_not_trigons() {
    let d = dir("no-such-run");
    let err = refused(&attest(&d, "nope", &[]));
    assert!(err.contains("no run `nope` in this store"), "{err}");
    assert!(err.contains("the command line's: no such run"), "{err}");
    assert!(!err.contains("bug in trigon"), "{err}");
    assert!(filed(&d).is_empty(), "{:?}", filed(&d));
}

/// `trigon runs`: a store with nothing in it says so, and each run says what it concluded — a
/// verdict, `void` for a run whose guard tripped, `-` for one that reached neither — and whether
/// anything has been signed about it.
#[test]
fn runs_says_what_each_run_concluded_and_whether_it_was_signed() {
    let d = dir("runs");
    let store_dir = d.join("store");
    let s = store_dir.to_str().unwrap();
    let text = ok(&trigon(&d, &["runs", "--store", s]));
    assert_eq!(text.trim(), "no runs");

    let store = Store::local(&store_dir).unwrap();
    let u = one(b"x\n", 1);
    let compared = rt().block_on(compared_run(
        &store,
        "1789003500-b3b3b3b3",
        TARGET,
        &u,
        &one(b"x\n", 2),
    ));
    let failed = rt().block_on(failed_run(&store, "1789003600-b3b3b3b3", &u));
    let mut void = rt().block_on(failed_run(&store, "1789003700-b3b3b3b3", &u));
    void.terminal = Some("void".into());
    void.guard_trips = vec!["the artifact under test arrived from registry.npmjs.org".into()];
    rt().block_on(store.put_run(&void)).unwrap();
    ok(&attest(&d, &compared.id, &[]));

    let text = ok(&trigon(&d, &["runs", "--store", s]));
    let row = |id: &str| -> Vec<String> {
        text.lines()
            .find(|l| l.starts_with(id))
            .unwrap_or_else(|| panic!("no row for {id}:\n{text}"))
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        row(&compared.id),
        [compared.id.as_str(), TARGET, "normalized", "attested"]
    );
    assert_eq!(
        row(&failed.id),
        [failed.id.as_str(), TARGET, "-", "unattested"]
    );
    assert_eq!(
        row(&void.id),
        [void.id.as_str(), TARGET, "void", "unattested"]
    );
    // Most recent first, which is the order `attest` without a run reads them in.
    let order: Vec<&str> = text.lines().map(|l| &l[..19]).collect();
    assert_eq!(
        order,
        [void.id.as_str(), failed.id.as_str(), compared.id.as_str()]
    );
}

/// `attest --prune` drops the rebuilt artifact's bytes and keeps its digests — except for a
/// divergence, whose bytes a maintainer needs to answer it, and bytes another run still names.
#[test]
fn prune_after_signing_keeps_what_a_divergence_or_another_run_still_needs() {
    let d = dir("prune");
    let store = Store::local(&d.join("store")).unwrap();
    let u = one(b"x\n", 1);

    let matched = rt().block_on(compared_run(
        &store,
        "1789003800-b4b4b4b4",
        TARGET,
        &u,
        &one(b"x\n", 2),
    ));
    let text = ok(&attest(&d, &matched.id, &["--prune"]));
    assert!(
        text.contains("pruned the rebuilt artifact; its digests remain"),
        "{text}"
    );
    let after = rt().block_on(store.get_run(&matched.id)).unwrap();
    let rebuilt = after.rebuild.expect("the digests remain");
    assert!(!rebuilt.stored, "the record still says the bytes are kept");
    assert_eq!(rebuilt.sha256, matched.rebuild.unwrap().sha256);

    let diverged = rt().block_on(compared_run(
        &store,
        "1789003900-b4b4b4b4",
        TARGET,
        &u,
        &one(b"y\n", 1),
    ));
    assert_eq!(diverged.outcome.as_deref(), Some("divergent"));
    let text = ok(&attest(&d, &diverged.id, &["--prune"]));
    assert!(
        text.contains("kept the rebuilt artifact: a divergence needs its bytes"),
        "{text}"
    );
    let kept = rt().block_on(store.get_run(&diverged.id)).unwrap();
    assert!(kept.rebuild.unwrap().stored);

    // Two runs that rebuilt the same bytes, as a confirmation does: pruning one keeps the bytes
    // the other still names.
    let rb = one(b"x\n", 3);
    let first = rt().block_on(compared_run(&store, "1789004000-b4b4b4b4", TARGET, &u, &rb));
    let second = rt().block_on(compared_run(&store, "1789004100-b4b4b4b4", TARGET, &u, &rb));
    let text = ok(&attest(&d, &first.id, &["--prune"]));
    assert!(
        text.contains(&format!("run {} still names", second.id)),
        "{text}"
    );
    let digest = first.rebuild.unwrap().sha256;
    assert!(rt().block_on(store.blobs().get(&digest)).is_ok());
}

// ---------------------------------------------------------------------------------------------
// The stabilizer-set module a verdict names (docs/09 §7.1)
// ---------------------------------------------------------------------------------------------

/// `[publish] stabilizer_module` in `d`'s `evidence.toml`.
fn configure_module(d: &Path, module: &Path) {
    let path = d.join("home/.config/trigon/evidence.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        format!("[publish]\nstabilizer_module = \"{}\"\n", module.display()),
    )
    .unwrap();
}

/// The set digest this binary's `tar-gzip` has, as the bytes a module reports.
fn tar_gzip_digest() -> [u8; 32] {
    *trigon_stabilize::profile("tar-gzip")
        .unwrap()
        .digest()
        .as_bytes()
}

/// A verdict names the module only once the module has reproduced it, and names it by the sha256
/// of the bytes `attest` ran: those bytes are kept in the store, for `publish` to copy, and the
/// module is not named in the statements beside the verdict.
#[test]
fn a_verdict_names_the_module_that_reproduced_it_and_the_store_keeps_its_bytes() {
    let d = dir("module-named");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let run = rt().block_on(compared_run(&store, "1789003000-b0b0b0b0", TARGET, &u, &r));
    let module = set_module::built();
    let bytes = std::fs::read(&module).unwrap();
    let hex = set_module::sha256(&bytes);

    let said = ok(&attest(
        &d,
        &run.id,
        &["--stabilizer-module", module.to_str().unwrap()],
    ));
    assert!(said.contains(&format!("module    sha256:{hex}")), "{said}");
    assert!(
        said.contains("stabilizes both artifacts as the run did, so the verdict names it"),
        "{said}"
    );
    let all = statements(&store, &run.id);
    let verdict = the(&all, trigon_attest::EQUIVALENCE_V2);
    assert_eq!(
        verdict["predicate"]["evidence"]["stabilizerSetModule"]["sha256"],
        hex.as_str()
    );
    for other in [trigon_attest::REBUILD, trigon_attest::BUILD_OBSERVATION] {
        assert!(
            !the(&all, other).to_string().contains(&hex),
            "{other} names the module"
        );
    }
    let digest = trigon_core::Digest::from_hex(&hex).unwrap();
    let kept = rt().block_on(store.blobs().get(&digest)).unwrap();
    assert_eq!(&kept[..], &bytes[..]);
}

/// `--stabilizer-module` wins over `[publish] stabilizer_module`, which is read where the flag is
/// not given: a configured module that is not the run's set is refused, and the flag's is signed.
#[test]
fn the_flag_wins_over_the_configured_module() {
    let d = dir("module-flag");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let run = rt().block_on(compared_run(&store, "1789003100-b1b1b1b1", TARGET, &u, &r));
    let configured = d.join("configured.wasm");
    std::fs::write(&configured, set_module::fake([0x11; 32], b"x")).unwrap();
    configure_module(&d, &configured);

    let err = refused(&attest(&d, &run.id, &[]));
    assert!(err.contains(&configured.display().to_string()), "{err}");
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));

    let module = set_module::built();
    ok(&attest(
        &d,
        &run.id,
        &["--stabilizer-module", module.to_str().unwrap()],
    ));
    let verdict = the(&statements(&store, &run.id), trigon_attest::EQUIVALENCE_V2);
    assert_eq!(
        verdict["predicate"]["evidence"]["stabilizerSetModule"]["sha256"],
        set_module::sha256(&std::fs::read(&module).unwrap()).as_str()
    );
}

/// A module of another set is refused before anything is signed, and the refusal names both sets:
/// it would be named beside a claim it cannot have made.
#[test]
fn a_module_of_another_set_is_refused_and_nothing_is_signed() {
    let d = dir("module-other-set");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let run = rt().block_on(compared_run(&store, "1789003200-b2b2b2b2", TARGET, &u, &r));
    let module = d.join("other.wasm");
    std::fs::write(&module, set_module::fake([0x11; 32], b"x")).unwrap();

    let err = refused(&attest(
        &d,
        &run.id,
        &["--stabilizer-module", module.to_str().unwrap()],
    ));
    let native = trigon_stabilize::profile("tar-gzip")
        .unwrap()
        .digest()
        .to_hex();
    assert!(
        err.contains(&format!(
            "implements `tar-gzip@111111111111…`, and the run compared under `tar-gzip@{}…`",
            &native[..12]
        )),
        "{err}"
    );
    assert!(err.contains("Nothing was signed"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// The set digest is the module's own word. A module that gives the right one and stabilizes
/// differently would be named beside a claim it does not reproduce, so the stabilized digests are
/// what `attest` holds it to, and it is refused.
#[test]
fn a_module_with_the_right_set_digest_that_stabilizes_differently_is_refused() {
    let d = dir("module-liar");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let run = rt().block_on(compared_run(&store, "1789003300-b3b3b3b3", TARGET, &u, &r));
    let module = d.join("liar.wasm");
    std::fs::write(&module, set_module::fake(tar_gzip_digest(), b"stable")).unwrap();

    let err = refused(&attest(
        &d,
        &run.id,
        &["--stabilizer-module", module.to_str().unwrap()],
    ));
    let recorded = compare(&u, &r).upstream.stabilized.sha256.to_hex();
    assert!(
        err.contains(&format!(
            "reports the run's set digest, and stabilizes the published artifact to sha256:{}, \
             where the run recorded sha256:{recorded}",
            set_module::sha256(b"stable")
        )),
        "{err}"
    );
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// The published artifact stabilized natively, as `compare` stabilizes it.
fn stabilized(bytes: &[u8]) -> Vec<u8> {
    let set = trigon_stabilize::profile("tar-gzip").unwrap();
    let mut notes = Vec::new();
    let mut parsed = trigon_archive::parse(
        bytes.to_vec(),
        trigon_core::Format::TarGz,
        &trigon_archive::Limits::default(),
        &mut notes,
    )
    .unwrap();
    trigon_stabilize::apply(&set, &mut parsed.archive);
    trigon_archive::serialize(&parsed.archive, true).unwrap()
}

/// Both artifacts are held to what the run recorded, not the first alone. In a divergence the two
/// stabilized digests differ, and a module that stabilizes the published artifact as the run did
/// and the rebuilt one otherwise reproduces half the claim: it is refused on the rebuilt side.
#[test]
fn a_module_that_reproduces_the_published_side_alone_is_refused_on_the_rebuilt_one() {
    let d = dir("module-half");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"y\n", 1));
    let run = rt().block_on(compared_run(&store, "1789003350-b3b3b3b3", TARGET, &u, &r));
    assert_eq!(run.outcome.as_deref(), Some("divergent"));
    let c = compare(&u, &r);
    let published = stabilized(&u);
    assert_eq!(
        set_module::sha256(&published),
        c.upstream.stabilized.sha256.to_hex()
    );
    let module = d.join("half.wasm");
    std::fs::write(&module, set_module::fake(tar_gzip_digest(), &published)).unwrap();

    let err = refused(&attest(
        &d,
        &run.id,
        &["--stabilizer-module", module.to_str().unwrap()],
    ));
    assert!(
        err.contains(&format!(
            "reports the run's set digest, and stabilizes the rebuilt artifact to sha256:{}, \
             where the run recorded sha256:{}",
            set_module::sha256(&published),
            c.rebuild.stabilized.sha256.to_hex()
        )),
        "{err}"
    );
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// `attest` says which commit a module names beside the commit this Trigon was built from: where a
/// verifier who would rather rebuild the module than run it starts. The commit is the module's
/// word, said and never refused, since `attest` asks of a module only that it reproduce the claim;
/// but an answer that is not a commit is refused, as a module that cannot say what it is.
#[test]
fn attest_says_which_commit_the_module_names() {
    let d = dir("module-commit");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let stable = stabilized(&u);
    assert_eq!(stable, stabilized(&r), "both sides stabilize alike");
    let version = ok(&trigon(&d, &["--version"]));
    let ours = version.trim().split_once("+git.").unwrap().1.to_string();
    let other = "a".repeat(40);

    let mut cases = vec![
        (
            None,
            "commit    the module names no commit it was built from".to_string(),
        ),
        (
            Some(other.clone()),
            format!("commit    the module was built from {other}, and this Trigon from {ours}"),
        ),
        (
            Some(format!("{other}.dirty")),
            format!(
                "commit    the module was built from a tree with changes {other} does not have, \
                 so nobody can rebuild it from a commit"
            ),
        ),
    ];
    // A clean build of this Trigon has a commit a module can share; CI's is one.
    if ours.len() == 40 {
        cases.push((
            Some(ours.clone()),
            format!("commit    the module was built from {ours}, as this Trigon was"),
        ));
    }
    for (n, (commit, says)) in cases.into_iter().enumerate() {
        let id = format!("17890037{n:02}-c0c0c0c0");
        let run = rt().block_on(compared_run(&store, &id, TARGET, &u, &r));
        let module = d.join(format!("module-{n}.wasm"));
        let bytes = set_module::fake_naming(tar_gzip_digest(), &stable, commit.as_deref());
        std::fs::write(&module, &bytes).unwrap();
        let said = ok(&attest(
            &d,
            &run.id,
            &["--stabilizer-module", module.to_str().unwrap()],
        ));
        assert!(said.contains(&says), "{commit:?}: {said}");
        let verdict = the(&statements(&store, &run.id), trigon_attest::EQUIVALENCE_V2);
        assert_eq!(
            verdict["predicate"]["evidence"]["stabilizerSetModule"]["sha256"],
            set_module::sha256(&bytes).as_str()
        );
    }

    let run = rt().block_on(compared_run(&store, "1789003799-c0c0c0c0", TARGET, &u, &r));
    let module = d.join("not-a-commit.wasm");
    let bytes = set_module::fake_naming(tar_gzip_digest(), &stable, Some("v1.0"));
    std::fs::write(&module, bytes).unwrap();
    let err = refused(&attest(
        &d,
        &run.id,
        &["--stabilizer-module", module.to_str().unwrap()],
    ));
    assert!(
        err.contains("names the commit it was built from as something that is not a commit"),
        "{err}"
    );
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// A file that is no module, and a file that is not there, are refused as what they are, before
/// anything is signed.
#[test]
fn a_module_that_cannot_be_read_or_loaded_is_refused() {
    let d = dir("module-unloadable");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let run = rt().block_on(compared_run(&store, "1789003400-b4b4b4b4", TARGET, &u, &r));
    let notes = d.join("notes.wasm");
    std::fs::write(&notes, b"{\"not\": \"a module\"}").unwrap();
    let err = refused(&attest(
        &d,
        &run.id,
        &["--stabilizer-module", notes.to_str().unwrap()],
    ));
    assert!(err.contains("cannot be loaded"), "{err}");
    let err = refused(&attest(
        &d,
        &run.id,
        &[
            "--stabilizer-module",
            d.join("missing.wasm").to_str().unwrap(),
        ],
    ));
    assert!(err.contains("reading the stabilizer-set module"), "{err}");
    assert!(statements(&store, &run.id).is_empty());
    assert!(filed_for(&d, &run.id).is_empty(), "{:?}", filed(&d));
}

/// A void makes no claim to re-derive, so it names no module, and a configured one is not even
/// read; and without a module a verdict is signed as before, saying that `publish` will refuse it.
#[test]
fn a_void_names_no_module_and_a_verdict_without_one_says_what_it_lacks() {
    let d = dir("module-void");
    let store = Store::local(&d.join("store")).unwrap();
    let (u, r) = (one(b"x\n", 1), one(b"x\n", 2));
    let mut void = rt().block_on(compared_run(&store, "1789003500-b5b5b5b5", TARGET, &u, &r));
    void.environment.egress = "open".into();
    void.environment.attestable = false;
    rt().block_on(store.put_run(&void)).unwrap();
    configure_module(&d, &d.join("never-read.wasm"));
    let said = ok(&attest(&d, &void.id, &[]));
    assert!(!said.contains("module    "), "{said}");
    let st = the(&statements(&store, &void.id), trigon_attest::VOID);
    assert!(
        st["predicate"]["evidence"]
            .get("stabilizerSetModule")
            .is_none(),
        "{st}"
    );

    std::fs::remove_file(d.join("home/.config/trigon/evidence.toml")).unwrap();
    let plain = rt().block_on(compared_run(&store, "1789003600-b6b6b6b6", TARGET, &u, &r));
    let said = ok(&attest(&d, &plain.id, &[]));
    assert!(
        said.contains("module    none: the verdict names no stabilizer-set module"),
        "{said}"
    );
    assert!(said.contains("`trigon publish` refuses it"), "{said}");
    let verdict = the(
        &statements(&store, &plain.id),
        trigon_attest::EQUIVALENCE_V2,
    );
    assert!(
        verdict["predicate"]["evidence"]
            .get("stabilizerSetModule")
            .is_none(),
        "{verdict}"
    );
}
