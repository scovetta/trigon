//! `trigon rederive`: the explanation a stored comparison predates, filled in beside it and never
//! over it.
//!
//! Through the binary, against a store of the test's own holding runs compared for real, because
//! the command is the code that decides when a re-derivation may be written: only under the set
//! the run was judged with, only where it agrees with the original on everything a verdict rests
//! on, and never in place of the original.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trigon_compare::Comparison;
use trigon_core::Digest;
use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

const TARGET: &str = "pkg:npm/demo@1.0.0";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-rederive-{}-{what}", std::process::id()));
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

/// A gzipped tarball of one member stamped `mtime`. Two that differ only in the stamp agree once
/// `tar-time` has run, so their comparison is `normalized` and has something to explain.
fn tgz(mtime: u64) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let body = b"module.exports = 1\n";
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
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

/// The published artifact and the rebuilt one of every run here.
fn pair() -> (Vec<u8>, Vec<u8>) {
    (tgz(1_700_000_000), tgz(1_600_000_000))
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

/// The comparison of the pair under `tar-gzip`, as this binary makes one: with its progression.
fn compared(upstream: &[u8], rebuild: &[u8]) -> Comparison {
    let c = trigon_compare::compare_bytes(
        upstream.to_vec(),
        rebuild.to_vec(),
        trigon_core::Format::TarGz,
        &trigon_stabilize::profile("tar-gzip").unwrap(),
        &trigon_archive::Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, trigon_core::Match::Normalized, "the fixture");
    let diff = c
        .diff
        .as_ref()
        .expect("a normalized comparison carries a member report");
    assert!(
        diff.progression.is_some() && !diff.field_edits.is_empty(),
        "the fixture"
    );
    c
}

/// `c` as a binary written before per-field attribution and the progression existed wrote it.
fn predating(c: &Comparison) -> serde_json::Value {
    let mut v = serde_json::to_value(c).unwrap();
    let diff = v["diff"].as_object_mut().unwrap();
    diff.remove("progression");
    diff.remove("field_edits");
    v
}

fn artifact(name: &str, bytes: &[u8]) -> ArtifactRef {
    ArtifactRef {
        name: name.into(),
        sha256: trigon_store::digest_of(bytes),
        bytes: bytes.len() as u64,
        stored: true,
    }
}

/// A run recorded as `record_run` records one: both artifacts kept in the blob store, and `cmp`
/// as the comparison it was judged on.
async fn recorded(store: &Store, id: &str, cmp: &serde_json::Value) -> RunRecord {
    let (up, rb) = pair();
    store.blobs().put(up.clone()).await.unwrap();
    store.blobs().put(rb.clone()).await.unwrap();
    let digest = store
        .blobs()
        .put(serde_json::to_vec(cmp).unwrap())
        .await
        .unwrap();
    let mut r = RunRecord::new(
        id,
        TARGET,
        artifact("demo-1.0.0.tgz", &up),
        env(),
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = cmp["outcome"].as_str().map(str::to_string);
    r.comparison = Some(digest);
    r.rebuild = Some(artifact("demo-1.0.0.tgz", &rb));
    store.put_run(&r).await.unwrap();
    r
}

/// A store holding one run per `(id, comparison)`.
fn store_with(what: &str, runs: &[(&str, serde_json::Value)]) -> (PathBuf, Store, Vec<RunRecord>) {
    let root = dir(what).join("store");
    let store = Store::local(&root).unwrap();
    let records = rt().block_on(async {
        let mut out = Vec::new();
        for (id, cmp) in runs {
            out.push(recorded(&store, id, cmp).await);
        }
        out
    });
    (root, store, records)
}

fn rederive(store: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .env("NO_COLOR", "1")
        .arg("rederive")
        .arg("--store")
        .arg(store)
        .args(args)
        .output()
        .unwrap()
}

/// What a run in which no line failed printed: every run written or skipped, and it exits 0.
fn said(out: &Output) -> String {
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    text
}

/// What a run in which a line failed printed, and what it said on stderr. It exits 1, and only
/// after every line and the tally: one run that failed stops no other, and a backfill run from a
/// script does not pass over a comparison the same bytes no longer give.
fn refused(out: &Output) -> (String, String) {
    let (text, err) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert_eq!(out.status.code(), Some(1), "{text}{err}");
    assert!(text.contains(" failed, of "), "the tally was not printed: {text}");
    (text, err)
}

/// The runs stderr names after `what`, in id order.
fn named<'a>(err: &'a str, what: &str) -> Vec<&'a str> {
    let at = err.find(what).unwrap_or_else(|| panic!("no `{what}`: {err}"));
    let rest = err[at + what.len()..].lines().next().unwrap_or_default();
    let mut ids: Vec<&str> = rest.split(';').next().unwrap().split(", ").collect();
    ids.sort_unstable();
    ids
}

/// The line about run `id`.
fn line<'a>(text: &'a str, id: &str) -> &'a str {
    text.lines()
        .find(|l| l.starts_with(id))
        .unwrap_or_else(|| panic!("no line for {id}: {text}"))
}

fn derived(store: &Store, r: &RunRecord) -> Option<Comparison> {
    let recorded = r.comparison.unwrap();
    rt().block_on(store.get_derived_comparison(&recorded))
        .unwrap()
        .map(|b| serde_json::from_slice(&b).unwrap())
}

/// The file a run record is kept in, byte for byte.
fn record_bytes(root: &Path, id: &str) -> Vec<u8> {
    std::fs::read(root.join("runs").join(format!("{id}.json"))).unwrap()
}

/// Where the blob store keeps `d`.
fn blob_path(root: &Path, d: &Digest) -> PathBuf {
    let hex = d.to_hex();
    root.join("blobs/sha256").join(&hex[..2]).join(hex)
}

/// The step and edit counts a written line reports.
fn counts(line: &str) -> (usize, usize) {
    let words: Vec<&str> = line.split_whitespace().collect();
    let before = |w: &str| {
        let at = words.iter().position(|x| x.starts_with(w)).unwrap();
        words[at - 1].trim_end_matches(',').parse().unwrap()
    };
    (before("step(s)"), before("field"))
}

/// The case the command exists for: a comparison written before the explanation existed gets one,
/// beside it, agreeing with it on the verdict — and the record and the comparison it names are the
/// bytes they were.
#[test]
fn an_old_comparison_gains_its_explanation_beside_it_and_the_record_is_untouched() {
    let (up, rb) = pair();
    let fresh = compared(&up, &rb);
    let id = "1789000000-aaaaaaaa";
    let (root, store, runs) = store_with("old", &[(id, predating(&fresh))]);
    let recorded = runs[0].comparison.unwrap();
    let record_before = record_bytes(&root, id);
    let blob_before = std::fs::read(blob_path(&root, &recorded)).unwrap();

    let text = said(&rederive(&root, &[]));
    let written = line(&text, id);
    assert!(written.contains("  written  "), "{text}");
    assert!(
        text.contains("1 written, 0 skipped, 0 failed, of 1 run(s)"),
        "{text}"
    );

    let d = derived(&store, &runs[0]).expect("the re-derivation is kept beside the original");
    let diff = d.diff.as_ref().unwrap();
    let progression = diff
        .progression
        .as_ref()
        .expect("the progression is filled in");
    // What the line reports is what was written.
    assert_eq!(
        counts(written),
        (progression.steps.len(), diff.field_edits.len()),
        "{written}"
    );
    assert!(!diff.field_edits.is_empty(), "attribution is filled in too");
    // And it explains the verdict the run was judged on, not another.
    assert_eq!(d.outcome, fresh.outcome);
    assert_eq!(
        d.upstream.stabilized.sha256,
        fresh.upstream.stabilized.sha256
    );
    assert_eq!(d.rebuild.stabilized.sha256, fresh.rebuild.stabilized.sha256);

    // **The original is never touched.** The record still names the comparison it was judged on,
    // and that comparison is the bytes it was.
    assert_eq!(record_bytes(&root, id), record_before);
    assert_eq!(
        std::fs::read(blob_path(&root, &recorded)).unwrap(),
        blob_before
    );
    let still: Comparison = serde_json::from_slice(&blob_before).unwrap();
    assert!(still.diff.unwrap().progression.is_none());
}

/// A run already re-derived is skipped and says so; `--force` re-derives it anyway. Naming runs
/// re-derives only those.
#[test]
fn rederiving_again_skips_what_is_done_unless_forced_and_names_only_what_was_asked() {
    let (up, rb) = pair();
    let old = predating(&compared(&up, &rb));
    let (a, b) = ("1789000000-aaaaaaaa", "1789000100-bbbbbbbb");
    let (root, store, runs) = store_with("again", &[(a, old.clone()), (b, old)]);

    // Only the run named.
    let text = said(&rederive(&root, &[a]));
    assert!(line(&text, a).contains("  written  "), "{text}");
    assert!(!text.contains(b), "a run nobody named was touched: {text}");
    assert!(text.contains("of 1 run(s)"), "{text}");

    // Both runs name one comparison blob — the same bytes judged twice — so the derivation the
    // first wrote is the second's too, and neither is re-derived again.
    assert_eq!(runs[0].comparison, runs[1].comparison);
    let text = said(&rederive(&root, &[]));
    for id in [a, b] {
        assert!(
            line(&text, id).ends_with("skipped  already re-derived"),
            "{text}"
        );
    }
    assert!(
        text.contains("0 written, 2 skipped, 0 failed, of 2 run(s)"),
        "{text}"
    );

    let text = said(&rederive(&root, &["--force", b]));
    assert!(line(&text, b).contains("  written  "), "{text}");
    assert!(derived(&store, &runs[1]).is_some());
}

/// `--dry-run` says what it would write, counts it as such, and writes nothing.
#[test]
fn a_dry_run_says_what_it_would_write_and_writes_nothing() {
    let (up, rb) = pair();
    let id = "1789000000-aaaaaaaa";
    let (root, store, runs) = store_with("dry", &[(id, predating(&compared(&up, &rb)))]);

    let text = said(&rederive(&root, &["--dry-run"]));
    assert!(line(&text, id).contains("  would write  "), "{text}");
    assert!(
        text.contains("1 would be written, 0 skipped, 0 failed, of 1 run(s)"),
        "{text}"
    );
    assert!(derived(&store, &runs[0]).is_none(), "a dry run wrote");

    // And a dry run leaves nothing that makes the real one think it is done.
    let text = said(&rederive(&root, &[]));
    assert!(line(&text, id).contains("  written  "), "{text}");
}

/// A comparison judged with its own progression has nothing to fill in, and is left alone.
#[test]
fn a_comparison_that_recorded_its_own_progression_is_left_alone() {
    let (up, rb) = pair();
    let id = "1789000000-aaaaaaaa";
    let current = serde_json::to_value(compared(&up, &rb)).unwrap();
    let (root, store, runs) = store_with("current", &[(id, current)]);

    let text = said(&rederive(&root, &[]));
    assert!(
        line(&text, id).ends_with(
            "skipped  recorded its own progression when it was judged; nothing to fill in"
        ),
        "{text}"
    );
    assert!(derived(&store, &runs[0]).is_none());

    // `--force` is the one way past it.
    let text = said(&rederive(&root, &["--force"]));
    assert!(line(&text, id).contains("  written  "), "{text}");
}

/// A run with nothing to re-derive from is skipped, and the line says what it lacked: no
/// comparison, no rebuilt artifact, or one never kept. None is a failure: a second backfill meets
/// them all again, and nothing in the store is damaged.
#[test]
fn a_run_with_nothing_to_rederive_from_is_skipped_and_says_what_it_lacked() {
    let (up, rb) = pair();
    let old = predating(&compared(&up, &rb));
    let ids = [
        "1789000000-nocompare",
        "1789000001-norebuild",
        "1789000002-notkept",
    ];
    let runs: Vec<(&str, serde_json::Value)> = ids.iter().map(|id| (*id, old.clone())).collect();
    let root = dir("lacking").join("store");
    let store = Store::local(&root).unwrap();
    rt().block_on(async {
        for (id, cmp) in &runs {
            let mut r = recorded(&store, id, cmp).await;
            match *id {
                "1789000000-nocompare" => r.comparison = None,
                "1789000001-norebuild" => r.rebuild = None,
                "1789000002-notkept" => r.rebuild.as_mut().unwrap().stored = false,
                _ => {}
            }
            store.put_run(&r).await.unwrap();
        }
    });

    let text = said(&rederive(&root, &[]));
    assert!(
        line(&text, ids[0]).ends_with("skipped  reached no comparison"),
        "{text}"
    );
    assert!(
        line(&text, ids[1]).ends_with("skipped  has no rebuilt artifact"),
        "{text}"
    );
    assert!(
        line(&text, ids[2]).contains("skipped  one of the two artifacts was not kept in the store"),
        "{text}"
    );
    assert!(
        text.contains("0 written, 3 skipped, 0 failed, of 3 run(s)"),
        "{text}"
    );
    // Every run here names one comparison, so one lookup covers them all.
    let any = rt().block_on(store.get_run(ids[1])).unwrap();
    assert!(
        derived(&store, &any).is_none(),
        "a skipped run wrote a derivation"
    );
}

/// An artifact the record says is kept and the store has lost, and one whose bytes are not the
/// bytes the record names, are damage rather than a run with nothing to fill in: each line says
/// which, the command fails naming both, and the run after them is still re-derived.
#[test]
fn bytes_the_store_lost_or_cannot_give_back_fail_the_command_and_say_which() {
    let (up, rb) = pair();
    let old = predating(&compared(&up, &rb));
    // The store lists its newest run first, so the fine run is the oldest: it comes after the
    // damage, and writing its derivation first would make the others read as already done.
    let ids = [
        "1789000003-missing",
        "1789000004-corrupt",
        "1789000002-fine",
    ];
    let runs: Vec<(&str, serde_json::Value)> = ids.iter().map(|id| (*id, old.clone())).collect();
    let root = dir("damaged").join("store");
    let store = Store::local(&root).unwrap();
    rt().block_on(async {
        for (id, cmp) in &runs {
            let mut r = recorded(&store, id, cmp).await;
            // Its own bytes, so losing them loses no other run's.
            if *id == "1789000003-missing" {
                let lost = b"a rebuilt artifact the store lost".to_vec();
                r.rebuild = Some(artifact("lost.tgz", &lost));
            }
            store.put_run(&r).await.unwrap();
        }
    });
    // Bytes at the rebuilt artifact's address that are not the bytes it names. Every run here
    // shares that blob, so this one names its own.
    let impostor = b"the rebuilt artifact, as it was".to_vec();
    rt().block_on(async {
        let mut r = store.get_run(ids[1]).await.unwrap();
        let named = artifact("impostor.tgz", &impostor);
        std::fs::create_dir_all(blob_path(&root, &named.sha256).parent().unwrap()).unwrap();
        std::fs::write(blob_path(&root, &named.sha256), b"other bytes entirely").unwrap();
        r.rebuild = Some(named);
        store.put_run(&r).await.unwrap();
    });

    let (text, err) = refused(&rederive(&root, &[]));
    // Kept by the record's word and gone from the store: missing, and said so, never taken for a
    // run whose bytes were pruned on purpose.
    let missing = line(&text, ids[0]);
    assert!(missing.contains("failed   "), "{text}");
    assert!(missing.contains("rebuilt artifact"), "{missing}");
    assert!(missing.contains("the bytes are missing"), "{missing}");
    // Bytes that are not the ones the record names are not re-derived from.
    assert!(
        line(&text, ids[1])
            .contains("failed   one of the two artifacts could not be read from the store"),
        "{text}"
    );
    assert!(line(&text, ids[2]).contains("  written  "), "{text}");
    assert!(
        text.contains("1 written, 0 skipped, 2 failed, of 3 run(s)"),
        "{text}"
    );
    // The exit names both, as runs that could not be re-derived, and not the one written.
    assert_eq!(
        named(&err, "2 run(s) could not be re-derived: "),
        [ids[0], ids[1]],
        "{err}"
    );
    assert!(!err.contains(ids[2]), "{err}");
    assert!(!err.contains("other than the one recorded"), "{err}");
}

/// A run judged under a set this binary does not have, or under another version of a set it
/// does, is skipped: explaining a verdict with a different set would explain a different verdict.
#[test]
fn a_run_judged_under_another_set_is_not_explained_with_this_one() {
    let (up, rb) = pair();
    let old = predating(&compared(&up, &rb));
    let mut retired = old.clone();
    retired["upstream"]["set"][0] = "tar-gzip-retired".into();
    let mut earlier = old;
    earlier["upstream"]["set"][1] = "00".repeat(32).into();
    let (a, b) = ("1789000000-retired", "1789000001-earlier");
    let (root, store, runs) = store_with("sets", &[(a, retired), (b, earlier)]);

    let text = said(&rederive(&root, &[]));
    assert!(
        line(&text, a).ends_with(
            "skipped  was judged under profile `tar-gzip-retired`, which this binary does not have"
        ),
        "{text}"
    );
    let other = line(&text, b);
    assert!(
        other.contains(&format!("was judged under tar-gzip {}", "0".repeat(12))),
        "{other}"
    );
    assert!(
        other.contains("a different set would explain a different verdict"),
        "{other}"
    );
    for r in &runs {
        assert!(
            derived(&store, r).is_none(),
            "{} was explained anyway",
            r.id
        );
    }
}

/// A re-derivation that disagrees with the record on what the verdict rests on is refused loudly —
/// a failure, not a skip — and nothing is written: the same bytes under the same set should give
/// the same verdict, and when they do not, that is a finding about the comparator.
#[test]
fn a_rederivation_that_disagrees_with_the_record_is_refused_and_not_written() {
    let (up, rb) = pair();
    let old = predating(&compared(&up, &rb));
    let mut outcome = old.clone();
    outcome["outcome"] = "divergent".into();
    let mut digest = old;
    digest["rebuild"]["stabilized"]["sha256"] = "11".repeat(32).into();
    let (a, b) = ("1789000000-outcome", "1789000001-digest");
    let (root, store, runs) = store_with("disagrees", &[(a, outcome), (b, digest)]);

    let (text, err) = refused(&rederive(&root, &[]));
    assert!(
        line(&text, a).ends_with(
            "failed   re-derivation disagrees with the recorded comparison: outcome divergent vs \
             normalized"
        ),
        "{text}"
    );
    assert!(
        line(&text, b).ends_with(
            "failed   re-derivation disagrees with the recorded comparison: rebuild stabilized \
             digest"
        ),
        "{text}"
    );
    assert!(
        text.contains("0 written, 0 skipped, 2 failed, of 2 run(s)"),
        "{text}"
    );
    for r in &runs {
        assert!(derived(&store, r).is_none(), "{} was written anyway", r.id);
    }
    // And the exit says which, as a disagreement: not a run that could not be read.
    assert_eq!(
        named(&err, "2 run(s) re-derived to a comparison other than the one recorded: "),
        [a, b],
        "{err}"
    );
    assert!(!err.contains("could not be re-derived"), "{err}");
}

/// A run the store does not hold, a comparison blob it has lost, and one that is not a comparison
/// are failures, each said, and the runs after them are still re-derived.
#[test]
fn what_cannot_be_read_is_a_failure_and_the_rest_still_run() {
    let (up, rb) = pair();
    let old = predating(&compared(&up, &rb));
    let ids = ["1789000000-lostcmp", "1789000001-notcmp", "1789000002-fine"];
    let root = dir("unreadable").join("store");
    let store = Store::local(&root).unwrap();
    rt().block_on(async {
        for id in ids {
            let mut r = recorded(&store, id, &old).await;
            match id {
                "1789000000-lostcmp" => {
                    r.comparison = Some(trigon_store::digest_of(b"a comparison nobody stored"));
                }
                "1789000001-notcmp" => {
                    r.comparison = Some(store.blobs().put(b"{\"not\": 1}".to_vec()).await.unwrap());
                }
                _ => {}
            }
            store.put_run(&r).await.unwrap();
        }
    });

    let absent = "1789999999-ffffffff";
    let (text, err) = refused(&rederive(&root, &[ids[0], ids[1], absent, ids[2]]));
    assert!(
        line(&text, ids[0]).contains("failed   reading the recorded comparison"),
        "{text}"
    );
    assert!(
        line(&text, ids[1]).contains("failed   parsing the recorded comparison"),
        "{text}"
    );
    let unknown = line(&text, absent);
    assert!(
        unknown.starts_with(&format!("{absent}  failed   ")),
        "{text}"
    );
    assert!(line(&text, ids[2]).contains("  written  "), "{text}");
    assert!(
        text.contains("1 written, 0 skipped, 3 failed, of 4 run(s)"),
        "{text}"
    );
    // The exit names each run that failed, and none that was written.
    assert_eq!(
        named(&err, "3 run(s) could not be re-derived: "),
        [ids[0], ids[1], absent],
        "{err}"
    );
    assert!(!err.contains(ids[2]), "{err}");
    assert!(!err.contains("other than the one recorded"), "{err}");
}

/// A store path that names nothing is refused rather than created and read as an empty store, and
/// the refusal is the command line's mistake, never a bug in trigon to be reported.
#[test]
fn rederive_refuses_a_store_that_is_not_there() {
    let d = dir("nostore");
    let typo = d.join("trigon-stroe");
    let out = rederive(&typo, &[]);
    assert!(
        !out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("is not a directory"), "{err}");
    assert!(err.contains("the command line's: no such store"), "{err}");
    assert!(!err.contains("bug in trigon"), "{err}");
    assert!(!typo.exists(), "reading a store created one");
}
