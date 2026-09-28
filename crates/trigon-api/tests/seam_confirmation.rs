//! When two agreeing attempts are two: `docs/19` §10 phase 3's done-when, through the index.
//!
//! A run reaches `Published` only through a second attempt at the same cache key, begun at least
//! `[publish] confirmation_interval` after the first, on another machine — or, where
//! `same_host_confirmation` is set (D8), on the same machine with no build cache and its base image
//! pulled again by digest. Each way a pair falls short of that is withheld for its own reason, and
//! each has a test here.
//!
//! The records are shaped as the run path writes them: a key from `trigon_store::cache_key`, an
//! agreement digest from a real comparison, a host id from `trigon_store::host_id_from`, a cache
//! state, and the time each attempt began. They go through `put_run` → `Index::refresh`, because
//! the gate's answer about a *set* of records is what is asserted, and no podman is started: the
//! attempts are the records a build would have left.

use std::sync::Arc;
use std::time::Duration;

use trigon_api::{Confirmation, Index, Publication, Switches, Withheld};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, CacheState, Environment, RunRecord, RunState, Store};

const TARGET: &str = "pkg:npm/left-pad@1.3.0";
const ARTIFACT: &str = "left-pad-1.3.0.tgz";
const STRATEGY: &str = "5f1c0e4bd1f6d3a0a8c4c1b2e3f40516273849aabbccddeeff00112233445566";

/// Two machines, as `host_id` names them from their machine ids.
fn machine(n: u8) -> String {
    trigon_store::host_id_from(Some(&format!("{n:032x}")), None).unwrap()
}

/// A real comparison of the published artifact with a rebuild of it, under `tar-gzip`.
fn comparison(rebuilt_body: &[u8]) -> trigon_compare::Comparison {
    fn tgz(body: &[u8], mtime: u64) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
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
    trigon_compare::compare_bytes(
        tgz(b"module.exports = leftPad;\n", 1_700_000_000),
        // Another mtime every time: an honest rebuild is rarely byte-identical, and agreement is
        // about what the comparison found, not about the raw bytes.
        tgz(rebuilt_body, 1_800_000_000),
        trigon_core::Format::TarGz,
        &trigon_stabilize::profile("tar-gzip").unwrap(),
        &trigon_archive::Limits::default(),
    )
    .unwrap()
}

/// One attempt, as `record_run` writes it: at `started`, on `host`, with `cache`.
fn attempt(id: &str, started: &str, host: &str, cache: CacheState) -> RunRecord {
    let c = comparison(b"module.exports = leftPad;\n");
    let mut r = RunRecord::new(
        id,
        TARGET,
        ArtifactRef {
            name: ARTIFACT.into(),
            sha256: Digest::from_bytes([7u8; 32]),
            bytes: 1,
            stored: true,
        },
        Environment {
            base_image: "docker.io/library/node@sha256:aa".into(),
            derived_image: None,
            egress: "mirror-only".into(),
            isolation: "user_ns".into(),
            attestable: true,
            registry_moment: None,
            pin: None,
            guard_manifest: None,
            guarded_members: None,
        },
        started,
    );
    r.state = RunState::Done;
    r.outcome = Some(c.outcome.to_string());
    r.non_builtin_stabilizer = Some(false);
    r.strategy_digest = Some(STRATEGY.into());
    r.cache_key = trigon_store::cache_key(TARGET, ARTIFACT, STRATEGY, &c.upstream.set.1.to_hex());
    r.agreement = Some(c.agreement());
    r.host = Some(host.into());
    r.cache = Some(cache);
    r
}

/// A warm attempt: the layer cache and the source cache could have answered.
fn warm() -> CacheState {
    CacheState {
        warm: vec![CacheState::LAYERS.into(), CacheState::SOURCES.into()],
        image_repulled: false,
    }
}

/// What `rebuild --confirm` records: nothing could answer, and the image was pulled again.
fn cold() -> CacheState {
    CacheState {
        warm: Vec::new(),
        image_repulled: true,
    }
}

async fn index(records: &[RunRecord], switches: Switches) -> Index {
    let store = Arc::new(Store::in_memory());
    for r in records {
        store.put_run(r).await.expect("put_run");
    }
    let ix = Index::new();
    ix.refresh(&store, switches).await.expect("refresh");
    ix
}

/// What the gate decides about each run, with these settings.
async fn decided(records: &[RunRecord], switches: Switches) -> Vec<Publication> {
    let ix = index(records, switches).await;
    records
        .iter()
        .map(|r| ix.entry(&r.id).expect("indexed").publication)
        .collect()
}

fn withheld(because: Withheld) -> Publication {
    Publication::Withheld { because }
}

/// `same_host_confirmation = true`, at the default interval.
fn same_host_allowed() -> Switches {
    Switches {
        confirmation: Confirmation {
            same_host: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn one_attempt_is_not_a_confirmation() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    assert_eq!(
        decided(&[first], Switches::default()).await,
        [withheld(Withheld::AwaitingConfirmation)]
    );
}

#[tokio::test]
async fn a_second_attempt_on_another_machine_an_interval_later_publishes_both() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let second = attempt("1790503600-ab", "2026-09-27T11:00:00Z", &machine(2), warm());
    assert_ne!(
        comparison(b"module.exports = leftPad;\n")
            .rebuild
            .raw
            .sha256,
        comparison(b"module.exports = leftPad;\n")
            .upstream
            .raw
            .sha256,
        "the premise: the rebuild is not byte-identical, and the two agree all the same"
    );
    assert_eq!(
        decided(&[first, second], Switches::default()).await,
        [Publication::Published, Publication::Published]
    );
}

#[tokio::test]
async fn a_second_attempt_that_began_too_soon_is_withheld_as_too_close() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let second = attempt("1790500900-ab", "2026-09-27T10:15:00Z", &machine(2), warm());
    let records = [first, second];
    assert_eq!(
        decided(&records, Switches::default()).await,
        [
            withheld(Withheld::AttemptsTooClose),
            withheld(Withheld::AttemptsTooClose)
        ],
        "fifteen minutes is inside the hour a gate with no configuration asks for"
    );
    // The interval is the operator's to set.
    let ten_minutes = Switches {
        confirmation: Confirmation {
            interval: Duration::from_secs(600),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        decided(&records, ten_minutes).await,
        [Publication::Published, Publication::Published]
    );
}

#[tokio::test]
async fn two_attempts_on_one_machine_are_withheld_unless_the_operator_accepts_it() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let second = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(1), cold());
    assert_eq!(
        decided(&[first, second], Switches::default()).await,
        [withheld(Withheld::SameHost), withheld(Withheld::SameHost)],
        "D8 is off by default, and a cold second attempt does not change that"
    );
}

#[tokio::test]
async fn on_one_machine_a_warm_confirmation_is_withheld_as_not_cold() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), cold());
    let second = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(1), warm());
    assert_eq!(
        decided(&[first, second], same_host_allowed()).await,
        [
            withheld(Withheld::ConfirmationNotCold),
            withheld(Withheld::ConfirmationNotCold)
        ],
        "the confirming attempt is the later one, and it could have replayed the first"
    );
}

#[tokio::test]
async fn on_one_machine_a_cold_confirmation_whose_image_was_not_pulled_again_is_withheld() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let second = attempt(
        "1790507200-ab",
        "2026-09-27T12:00:00Z",
        &machine(1),
        CacheState {
            warm: Vec::new(),
            image_repulled: false,
        },
    );
    assert_eq!(
        decided(&[first, second], same_host_allowed()).await,
        [
            withheld(Withheld::ConfirmationNotCold),
            withheld(Withheld::ConfirmationNotCold)
        ]
    );
}

#[tokio::test]
async fn on_one_machine_a_cold_re_pulled_confirmation_an_interval_later_publishes() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let second = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(1), cold());
    assert_eq!(
        decided(&[first.clone(), second.clone()], same_host_allowed()).await,
        [Publication::Published, Publication::Published]
    );
    // And the interval still holds on one machine.
    let mut soon = second;
    soon.started = "2026-09-27T10:30:00Z".into();
    assert_eq!(
        decided(&[first, soon], same_host_allowed()).await,
        [
            withheld(Withheld::AttemptsTooClose),
            withheld(Withheld::AttemptsTooClose)
        ]
    );
}

#[tokio::test]
async fn an_attempt_under_another_strategy_or_set_is_another_question() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    for (what, key) in [
        (
            "strategy",
            trigon_store::cache_key(TARGET, ARTIFACT, &"ab".repeat(32), &"cd".repeat(32)),
        ),
        (
            "set",
            trigon_store::cache_key(TARGET, ARTIFACT, STRATEGY, &"ef".repeat(32)),
        ),
    ] {
        let mut second = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(2), cold());
        second.cache_key = key;
        assert_eq!(
            decided(&[first.clone(), second], Switches::default()).await,
            [
                withheld(Withheld::AwaitingConfirmation),
                withheld(Withheld::AwaitingConfirmation)
            ],
            "another {what} is a different question, and answers nothing about the first"
        );
    }
}

#[tokio::test]
async fn a_run_keyed_before_keys_were_built_from_what_it_ran_is_counted_with_nothing() {
    // A worker's run carried its job's key, which was the purl alone; a CLI run carried none.
    let mut old = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    old.cache_key = Some(TARGET.into());
    old.agreement = None;
    old.host = None;
    old.cache = None;
    let new = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(2), cold());
    assert_eq!(
        decided(&[old, new], Switches::default()).await,
        [
            withheld(Withheld::AwaitingConfirmation),
            withheld(Withheld::AwaitingConfirmation)
        ]
    );
}

#[tokio::test]
async fn attempts_that_found_different_things_disagree_whatever_the_outcome_says() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let mut second = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(2), cold());
    // Both divergent, and divergent in different ways: the outcome string agrees, and what the
    // comparisons found does not.
    let one = comparison(b"module.exports = one;\n");
    let two = comparison(b"module.exports = two;\n");
    assert_eq!(one.outcome, trigon_core::Match::Divergent);
    let mut first = first;
    for (r, c) in [(&mut first, &one), (&mut second, &two)] {
        r.outcome = Some(c.outcome.to_string());
        r.agreement = Some(c.agreement());
    }
    assert_eq!(
        decided(&[first, second], Switches::default()).await,
        [
            withheld(Withheld::AttemptsDisagree),
            withheld(Withheld::AttemptsDisagree)
        ]
    );
}

#[tokio::test]
async fn an_attempt_that_does_not_say_where_it_ran_confirms_nothing() {
    let first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let mut second = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(2), cold());
    second.host = None;
    assert_eq!(
        decided(&[first, second], same_host_allowed()).await,
        [
            withheld(Withheld::ConfirmationUnrecorded),
            withheld(Withheld::ConfirmationUnrecorded)
        ],
        "absent is not another machine"
    );
}

#[tokio::test]
async fn an_anonymous_reader_is_given_one_withheld_total_and_no_reason() {
    let records = [
        attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm()),
        attempt("1790500060-ab", "2026-09-27T10:01:00Z", &machine(1), warm()),
    ];
    let ix = index(&records, Switches::default()).await;
    let public = ix.stats(true);
    assert_eq!(
        public.by_withheld,
        std::collections::BTreeMap::from([("withheld".to_string(), 2)])
    );
    let operator = ix.stats(false);
    assert!(
        operator.by_withheld.is_empty(),
        "an operator is shown every row"
    );
}

/// `[publish] same_host_confirmation` and `confirmation_interval` are read from `evidence.toml`,
/// as `trigon serve` reads them, and change what is published.
#[tokio::test]
async fn the_settings_are_the_configurations() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("evidence.toml");
    std::fs::write(
        &file,
        "[publish]\nsame_host_confirmation = true\nconfirmation_interval = \"10m\"\n",
    )
    .unwrap();
    let config = trigon_attest::config::EvidenceConfig::load(&trigon_attest::config::Env {
        cwd: dir.path().to_path_buf(),
        evidence_config: Some(file),
        ..Default::default()
    })
    .unwrap();
    let configured = Switches {
        confirmation: Confirmation::from(config.publish()),
        ..Default::default()
    };
    assert_eq!(
        configured.confirmation,
        Confirmation {
            same_host: true,
            interval: Duration::from_secs(600),
        }
    );

    let records = [
        attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm()),
        attempt("1790500900-ab", "2026-09-27T10:15:00Z", &machine(1), cold()),
    ];
    assert_eq!(
        decided(&records, configured).await,
        [Publication::Published, Publication::Published]
    );
    assert_eq!(
        decided(&records, Switches::default()).await,
        [
            withheld(Withheld::AttemptsTooClose),
            withheld(Withheld::AttemptsTooClose)
        ],
        "and with no configuration, the defaults"
    );
}
