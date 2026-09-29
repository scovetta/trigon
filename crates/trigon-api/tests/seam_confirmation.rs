//! When two agreeing attempts are two: `docs/19` §10 phase 3's done-when, through the index.
//!
//! A run reaches `Published` only through a second attempt at the same cache key, begun at least
//! `[publish] confirmation_interval` after the first, on another machine — or, where
//! `same_host_confirmation` is set (D8), on the same machine with no build cache and its base image
//! pulled again by digest, or, where `same_host_local_images` is set as well, with no build cache
//! on a local base image pinned by its content id. Each way a pair falls short of that is withheld
//! for its own reason, and each has a test here.
//!
//! The records are shaped as the run path writes them: a key from `trigon_store::cache_key`, an
//! agreement digest from a real comparison, a host id from `trigon_store::host_id_from`, a cache
//! state, and the time each attempt began. They go through `put_run` → `Index::refresh`, because
//! the gate's answer about a *set* of records is what is asserted, and no podman is started: the
//! attempts are the records a build would have left.

use std::sync::Arc;
use std::time::Duration;

use trigon_api::{Confirmation, Index, NotCold, Publication, Switches, Withheld};
use trigon_core::Digest;
use trigon_store::{ArtifactRef, CacheState, Environment, ImagePin, RunRecord, RunState, Store};

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

/// A warm attempt: the layer cache and the source cache could have answered. A first attempt, so
/// nothing was asked of its image.
fn warm() -> CacheState {
    CacheState {
        warm: vec![CacheState::LAYERS.into(), CacheState::SOURCES.into()],
        image_repulled: false,
        image_pin: None,
    }
}

/// What `rebuild --confirm` records: nothing could answer, and the image was pulled again.
fn cold() -> CacheState {
    CacheState {
        warm: Vec::new(),
        image_repulled: true,
        image_pin: Some(ImagePin::RegistryDigest),
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
            withheld(Withheld::ConfirmationNotCold(NotCold::Warm)),
            withheld(Withheld::ConfirmationNotCold(NotCold::Warm))
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
            image_pin: Some(ImagePin::RegistryDigest),
        },
    );
    assert_eq!(
        decided(&[first, second], same_host_allowed()).await,
        [
            withheld(Withheld::ConfirmationNotCold(NotCold::NotRepulled)),
            withheld(Withheld::ConfirmationNotCold(NotCold::NotRepulled))
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
            local_images: false,
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

// ---------------------------------------------------------------------------------------------
// `[publish] same_host_local_images`: a confirmation on a base image built on this machine
// ---------------------------------------------------------------------------------------------

/// A base image `trigon base-image` built, as a run records it: its full content id.
fn local_image_id() -> String {
    "f21d52e1657f28329790932f70bce9d4ddc2617ddfff54af98b02cbcf3d97cf6".into()
}

/// A first attempt and its confirmation on one machine two hours later, both on the local image;
/// the confirmation's cache state is `confirming`.
fn on_a_local_image(confirming: CacheState) -> [RunRecord; 2] {
    let mut first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let mut second = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(1), confirming);
    for r in [&mut first, &mut second] {
        r.environment.base_image = local_image_id();
    }
    [first, second]
}

/// What `rebuild --confirm` records on a local image: nothing could answer, and there was nothing
/// to pull the image again by.
fn cold_on_a_local_image() -> CacheState {
    CacheState {
        warm: Vec::new(),
        image_repulled: false,
        image_pin: Some(ImagePin::LocalContentId),
    }
}

/// `same_host_confirmation` and `same_host_local_images` as given, at the default interval.
fn settings(same_host: bool, local_images: bool) -> Switches {
    Switches {
        confirmation: Confirmation {
            same_host,
            local_images,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn with_both_settings_a_cold_confirmation_on_a_local_image_publishes() {
    assert_eq!(
        decided(&on_a_local_image(cold_on_a_local_image()), settings(true, true)).await,
        [Publication::Published, Publication::Published]
    );
}

#[tokio::test]
async fn without_the_opt_in_a_local_image_is_withheld_as_not_cold_naming_the_setting() {
    let records = on_a_local_image(cold_on_a_local_image());
    let off = decided(&records, settings(true, false)).await;
    let because = Withheld::ConfirmationNotCold(NotCold::LocalImage);
    assert_eq!(off, [withheld(because), withheld(because)]);
    // The same reason on the wire as every confirmation that was not cold, and a sentence that
    // says the one thing between this pair and publishing is a setting, by name.
    assert_eq!(because.key(), "confirmation_not_cold");
    assert!(
        because.sentence().contains("same_host_local_images"),
        "{}",
        because.sentence()
    );
    // And the default configuration is that: off.
    assert_eq!(
        off,
        decided(&records, same_host_allowed()).await,
        "`same_host_local_images` is off unless it is set"
    );
}

#[tokio::test]
async fn the_opt_in_without_same_host_confirmation_is_withheld_as_same_host() {
    assert_eq!(
        decided(&on_a_local_image(cold_on_a_local_image()), settings(false, true)).await,
        [withheld(Withheld::SameHost), withheld(Withheld::SameHost)],
        "set alone it changes nothing: one machine does not confirm itself"
    );
}

#[tokio::test]
async fn the_opt_in_does_not_accept_a_registry_image_that_was_not_pulled_again() {
    // The pull failed, or the image would not leave the store: a registry could have served it
    // again, and did not. And a reference with no digest to pull by is no better.
    for pin in [ImagePin::RegistryDigest, ImagePin::Other] {
        let mut records = on_a_local_image(CacheState {
            warm: Vec::new(),
            image_repulled: false,
            image_pin: Some(pin),
        });
        for r in &mut records {
            r.environment.base_image = match pin {
                ImagePin::RegistryDigest => {
                    format!("docker.io/library/node@sha256:{}", "ab".repeat(32))
                }
                _ => "docker.io/library/node:22-bookworm".into(),
            };
        }
        assert_eq!(
            decided(&records, settings(true, true)).await,
            [
                withheld(Withheld::ConfirmationNotCold(NotCold::NotRepulled)),
                withheld(Withheld::ConfirmationNotCold(NotCold::NotRepulled))
            ],
            "{pin:?}"
        );
    }
}

#[tokio::test]
async fn the_opt_in_does_not_accept_a_warm_confirmation_on_a_local_image() {
    for cache in [
        CacheState::LAYERS,
        CacheState::FETCH,
        CacheState::SOURCES,
        CacheState::DERIVED_IMAGE,
    ] {
        let warm_local = CacheState {
            warm: vec![cache.into()],
            ..cold_on_a_local_image()
        };
        assert_eq!(
            decided(&on_a_local_image(warm_local), settings(true, true)).await,
            [
                withheld(Withheld::ConfirmationNotCold(NotCold::Warm)),
                withheld(Withheld::ConfirmationNotCold(NotCold::Warm))
            ],
            "{cache}"
        );
    }
    // Nor one too soon after the first, however cold.
    let [first, mut second] = on_a_local_image(cold_on_a_local_image());
    second.started = "2026-09-27T10:30:00Z".into();
    assert_eq!(
        decided(&[first, second], settings(true, true)).await,
        [
            withheld(Withheld::AttemptsTooClose),
            withheld(Withheld::AttemptsTooClose)
        ]
    );
}

/// Run files written before `image_pin` was recorded carry `cache` with `warm` and
/// `image_repulled` alone. They are read from disk, as `trigon serve` and `trigon publish` read
/// them, and the gate decides about them as it did: pulled again counts, not pulled again does
/// not, whatever `same_host_local_images` says.
///
/// The one not pulled again ran on a local image's content id, as the confirmations of findings
/// §3.105 did: cold, `image_repulled: false`, no pin. Those are the records a gate that guessed the
/// pin from `environment.base_image` would publish, and it must not: what the record does not
/// say, the run did not check.
#[tokio::test]
async fn a_run_file_from_before_the_pin_was_recorded_is_decided_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let runs = dir.path().join("runs");
    std::fs::create_dir_all(&runs).unwrap();
    let write = |r: &RunRecord| {
        let mut v = serde_json::to_value(r).unwrap();
        let cache = v["cache"].as_object_mut().expect("a cache state");
        cache.remove("image_pin");
        let mut keys: Vec<&str> = cache.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["image_repulled", "warm"],
            "the shape of a cache state before the pin"
        );
        std::fs::write(
            runs.join(format!("{}.json", r.id)),
            serde_json::to_vec_pretty(&v).unwrap(),
        )
        .unwrap();
    };
    let mut first = attempt("1790500000-aa", "2026-09-27T10:00:00Z", &machine(1), warm());
    let pulled = attempt("1790507200-ab", "2026-09-27T12:00:00Z", &machine(1), cold());
    let mut kept = attempt(
        "1790507300-ac",
        "2026-09-27T12:01:40Z",
        &machine(1),
        CacheState {
            warm: Vec::new(),
            image_repulled: false,
            image_pin: None,
        },
    );
    for r in [&mut first, &mut kept] {
        r.environment.base_image = local_image_id();
    }
    let store = Store::local(dir.path()).unwrap();
    for (confirming, same_host, expect) in [
        (&pulled, true, Publication::Published),
        (
            &kept,
            true,
            withheld(Withheld::ConfirmationNotCold(NotCold::NotRepulled)),
        ),
        (&pulled, false, withheld(Withheld::SameHost)),
    ] {
        for f in std::fs::read_dir(&runs).unwrap() {
            std::fs::remove_file(f.unwrap().path()).unwrap();
        }
        write(&first);
        write(confirming);
        let read = store.get_run(&confirming.id).await.expect("an old run file reads");
        assert_eq!(read.cache.as_ref().map(|c| c.image_pin), Some(None));
        for local_images in [false, true] {
            let ix = Index::new();
            ix.refresh(&store, settings(same_host, local_images))
                .await
                .expect("refresh");
            for id in [&first.id, &confirming.id] {
                assert_eq!(
                    ix.entry(id).expect("indexed").publication,
                    expect,
                    "{} with same_host={same_host}, local_images={local_images}",
                    confirming.id
                );
            }
        }
    }
}

/// `same_host_local_images` is read from `evidence.toml` into the `Confirmation` that `trigon
/// serve`, `trigon attest` and `trigon publish` each build the gate from, beside the two settings
/// they already read that way.
#[tokio::test]
async fn the_opt_in_is_the_configurations() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("evidence.toml");
    let load = |text: &str| {
        std::fs::write(&file, text).unwrap();
        trigon_attest::config::EvidenceConfig::load(&trigon_attest::config::Env {
            cwd: dir.path().to_path_buf(),
            evidence_config: Some(file.clone()),
            ..Default::default()
        })
        .unwrap()
    };
    let records = on_a_local_image(cold_on_a_local_image());

    let both = load("[publish]\nsame_host_confirmation = true\nsame_host_local_images = true\n");
    assert!(both.notes().is_empty(), "{:?}", both.notes());
    let configured = Switches {
        confirmation: Confirmation::from(both.publish()),
        ..Default::default()
    };
    assert_eq!(
        configured.confirmation,
        Confirmation {
            same_host: true,
            local_images: true,
            interval: Duration::from_secs(3600),
        }
    );
    assert_eq!(
        decided(&records, configured).await,
        [Publication::Published, Publication::Published]
    );

    // Alone, it is read, it changes nothing, and the configuration says so.
    let alone = load("[publish]\nsame_host_local_images = true\n");
    assert_eq!(alone.notes().len(), 1, "{:?}", alone.notes());
    let configured = Switches {
        confirmation: Confirmation::from(alone.publish()),
        ..Default::default()
    };
    assert!(configured.confirmation.local_images);
    assert_eq!(
        decided(&records, configured).await,
        [withheld(Withheld::SameHost), withheld(Withheld::SameHost)]
    );
}
