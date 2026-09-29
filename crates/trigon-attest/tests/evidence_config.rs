//! `evidence.toml` and the environment, resolved: `docs/19` §2.4, key by key and rule by rule.
//!
//! Each test states the environment it means as an `Env` value and writes its files under a
//! directory of its own, so nothing here reads or changes the process's environment or the
//! developer's own configuration.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use sha2::Digest as _;
use trigon_attest::LocalKey;
use trigon_attest::config::{
    AddedBy, ConfigError, Divergences, Env, EvidenceConfig, RebuiltArtifacts, parse_duration,
};
use trigon_attest::location::Transport;

const ORIGIN: &str = "github.com/owner/trigon-evidence";

/// A fresh directory with `home/` and `project/` under it.
fn root(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "trigon-evidence-config-{}-{what}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("home")).unwrap();
    std::fs::create_dir_all(d.join("project")).unwrap();
    d
}

fn env(root: &Path) -> Env {
    Env {
        cwd: root.join("project"),
        home: Some(root.join("home")),
        ..Default::default()
    }
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn user_file(root: &Path) -> PathBuf {
    root.join("home/.config/trigon/evidence.toml")
}

fn project_file(root: &Path) -> PathBuf {
    root.join("project/.trigon/evidence.toml")
}

fn key() -> LocalKey {
    LocalKey::from_bytes(&[9u8; 32]).unwrap()
}

/// A C2SP verifier key for `origin`, computed here from a key this test holds.
fn vkey(origin: &str) -> String {
    let pk = key().public_key();
    let mut raw = vec![0x01];
    raw.extend_from_slice(pk.as_bytes());
    let mut h = sha2::Sha256::new();
    h.update(origin.as_bytes());
    h.update(b"\n");
    h.update(&raw);
    let hash: String = h.finalize()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "{origin}+{hash}+{}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn load(env: &Env) -> Result<EvidenceConfig, String> {
    EvidenceConfig::load(env).map_err(|e| e.to_string())
}

fn loads(env: &Env) -> EvidenceConfig {
    EvidenceConfig::load(env).unwrap_or_else(|e| panic!("{e}"))
}

// ---------------------------------------------------------------------------------------------
// Nothing configured
// ---------------------------------------------------------------------------------------------

#[test]
fn with_nothing_configured_every_setting_has_its_default() {
    let r = root("defaults");
    let c = loads(&env(&r));
    let p = c.publish();
    assert_eq!(p.repo, None);
    assert_eq!(p.branch, "main");
    assert_eq!(p.origin, None);
    assert_eq!(p.disputes, None);
    assert_eq!(p.log_key, None);
    assert_eq!(
        p.divergences,
        Divergences::Refuse,
        "D7's conservative default"
    );
    assert_eq!(p.rebuilt_artifacts, RebuiltArtifacts::None, "D4's");
    assert!(!p.same_host_confirmation, "D8's");
    assert!(!p.same_host_local_images, "D8's, for an image built here");
    assert_eq!(p.confirmation_interval, Duration::from_secs(3600));
    assert_eq!(p.heartbeat, Duration::from_secs(7 * 86_400));
    assert_eq!(c.freshness().stale_after, Duration::from_secs(86_400));
    assert_eq!(c.freshness().frozen_after, Duration::from_secs(14 * 86_400));
    assert!(c.sources().is_empty());
    assert!(c.files_read().is_empty());
    assert!(c.notes().is_empty());
    assert_eq!(p.namespace(), None);
}

#[test]
fn a_command_that_needs_a_source_and_has_none_says_how_to_configure_one() {
    let r = root("no-source");
    let c = loads(&env(&r));
    let e = c.require_sources().unwrap_err();
    // `docs/19` §6: 5 is the tool failing, which having nothing to ask is.
    assert_eq!(e.exit_code(), 5);
    let m = e.to_string();
    assert!(m.contains("no evidence source is configured"), "{m}");
    assert!(m.contains("[[source]]"), "{m}");
    assert!(m.contains(&user_file(&r).display().to_string()), "{m}");
    assert!(m.contains("TRIGON_EVIDENCE_REPO"), "{m}");
    assert!(m.contains("TRIGON_EVIDENCE_LOG_KEY"), "{m}");
}

#[test]
fn the_directories_default_under_home_and_follow_xdg_and_the_environment() {
    let r = root("dirs");
    let mut e = env(&r);
    let c = loads(&e);
    assert_eq!(
        c.cache_dir().unwrap(),
        r.join("home/.cache/trigon/evidence")
    );
    assert_eq!(
        c.state_dir().unwrap(),
        r.join("home/.local/state/trigon/evidence")
    );

    e.xdg_cache_home = Some(r.join("xdg-cache"));
    e.xdg_state_home = Some(r.join("xdg-state"));
    let c = loads(&e);
    assert_eq!(c.cache_dir().unwrap(), r.join("xdg-cache/trigon/evidence"));
    assert_eq!(c.state_dir().unwrap(), r.join("xdg-state/trigon/evidence"));

    // A relative XDG value names no fixed place, and the XDG specification says to ignore it.
    e.xdg_cache_home = Some(PathBuf::from("relative/cache"));
    assert_eq!(
        loads(&e).cache_dir().unwrap(),
        r.join("home/.cache/trigon/evidence")
    );

    // The two variables replace both, and a relative one is taken from the working directory.
    e.evidence_cache = Some(PathBuf::from("clones"));
    e.evidence_state = Some(r.join("state"));
    let c = loads(&e);
    assert_eq!(c.cache_dir().unwrap(), r.join("project/clones"));
    assert_eq!(c.state_dir().unwrap(), r.join("state"));

    // No HOME and nothing set: said, rather than a clone written somewhere arbitrary.
    let bare = Env {
        cwd: r.join("project"),
        ..Default::default()
    };
    let c = loads(&bare);
    let m = c.cache_dir().unwrap_err().to_string();
    assert!(m.contains("TRIGON_EVIDENCE_CACHE"), "{m}");
    let m = c.state_dir().unwrap_err().to_string();
    assert!(m.contains("TRIGON_EVIDENCE_STATE"), "{m}");
}

// ---------------------------------------------------------------------------------------------
// The user's file
// ---------------------------------------------------------------------------------------------

#[test]
fn every_key_of_the_documented_example_is_read() {
    let r = root("example");
    let pem = r.join("home/.config/trigon/attestation.pub");
    write(&pem, &key().public_pem());
    write(
        &user_file(&r),
        &format!(
            r#"
[publish]
repo = "git@github.com:owner/trigon-evidence.git"
branch = "evidence"
origin = "{ORIGIN}"
disputes = "https://github.com/owner/trigon-evidence/issues"
log_key = "~/.config/trigon/log.key"
divergences = "feed"
rebuilt_artifacts = "github-release"
same_host_confirmation = true
same_host_local_images = true
confirmation_interval = "30m"
heartbeat = "3d"

[freshness]
stale_after = "2h"
frozen_after = "7d"

[[source]]
name = "trigon"
urls = ["https://github.com/owner/trigon-evidence.git",
        "https://codeberg.org/owner/trigon-evidence.git"]
log_key = "{vk}"
attestation_key = "{hex}"
checkpoint = "~/.config/trigon/trigon.checkpoint"
required = true

[[source]]
name = "private"
urls = ["./private-evidence"]
log_key = "{vk}"
attestation_key = "attestation.pub"
"#,
            vk = vkey(ORIGIN),
            hex = key().public_hex()
        ),
    );
    let c = loads(&env(&r));
    let p = c.publish();
    let repo = p.repo.as_ref().unwrap();
    assert_eq!(repo.transport(), Transport::Ssh);
    assert_eq!(
        repo.as_git_arg(),
        "git@github.com:owner/trigon-evidence.git"
    );
    assert_eq!(p.branch, "evidence");
    assert_eq!(p.origin.as_deref(), Some(ORIGIN));
    assert_eq!(
        p.disputes.as_deref(),
        Some("https://github.com/owner/trigon-evidence/issues")
    );
    assert_eq!(
        p.log_key.as_deref(),
        Some(r.join("home/.config/trigon/log.key").as_path())
    );
    assert_eq!(p.divergences, Divergences::Feed);
    assert_eq!(p.rebuilt_artifacts, RebuiltArtifacts::GithubRelease);
    assert!(p.same_host_confirmation);
    assert!(p.same_host_local_images);
    assert!(
        c.notes().is_empty(),
        "both set is what the second asks for: {:?}",
        c.notes()
    );
    assert_eq!(p.confirmation_interval, Duration::from_secs(30 * 60));
    assert_eq!(p.heartbeat, Duration::from_secs(3 * 86_400));
    assert_eq!(
        p.namespace(),
        Some((ORIGIN, "https://github.com/owner/trigon-evidence/issues"))
    );
    assert_eq!(c.freshness().stale_after, Duration::from_secs(2 * 3600));
    assert_eq!(c.freshness().frozen_after, Duration::from_secs(7 * 86_400));

    let s = c.source("trigon").unwrap();
    assert_eq!(s.urls.len(), 2, "one log, served from two places");
    assert!(s.urls.iter().all(|u| u.transport() == Transport::Https));
    assert_eq!(s.log_key.as_ref().unwrap().origin(), ORIGIN);
    assert_eq!(
        s.attestation_key.as_ref().unwrap().to_hex(),
        key().public_hex()
    );
    assert_eq!(
        s.checkpoint.as_deref(),
        Some(r.join("home/.config/trigon/trigon.checkpoint").as_path())
    );
    assert!(s.required);
    assert!(!s.trust_on_first_use);
    assert_eq!(s.added_by, AddedBy::UserFile(user_file(&r)));

    // Relative to the file that named them: the location and the PEM beside it.
    let s = c.source("private").unwrap();
    assert_eq!(s.urls[0].transport(), Transport::LocalPath);
    assert_eq!(
        s.urls[0].local_path(),
        Some(r.join("home/.config/trigon/private-evidence").as_path())
    );
    assert_eq!(
        s.attestation_key.as_ref().unwrap().to_hex(),
        key().public_hex(),
        "read from the PEM keygen --public-out writes"
    );
    assert!(!s.required, "`required` defaults to false");
    assert_eq!(c.files_read(), [user_file(&r)]);
    assert_eq!(c.require_sources().unwrap().len(), 2);
}

#[test]
fn an_unknown_key_is_an_error_in_every_table() {
    // A typo in a security setting that is silently ignored is a setting that is silently off.
    let r = root("unknown");
    let source = format!(
        "name = \"s\"\nurls = [\"https://example.org/r.git\"]\nlog_key = \"{}\"\n\
         attestation_key = \"{}\"\n",
        vkey(ORIGIN),
        key().public_hex()
    );
    for (text, key) in [
        ("[publish]\nrepos = \"x\"\n".to_string(), "repos"),
        (
            "[publish]\nsame_host_confirmations = true\n".into(),
            "same_host_confirmations",
        ),
        (
            "[publish]\nsame_host_local_image = true\n".into(),
            "same_host_local_image",
        ),
        ("[freshness]\nstale = \"1d\"\n".into(), "stale"),
        (format!("[[source]]\n{source}requried = true\n"), "requried"),
        ("[publsh]\norigin = \"x\"\n".into(), "publsh"),
        ("divergences = \"feed\"\n".into(), "divergences"),
    ] {
        write(&user_file(&r), &text);
        let e = EvidenceConfig::load(&env(&r)).unwrap_err();
        assert_eq!(e.exit_code(), 5);
        let m = e.to_string();
        assert!(m.contains(key), "{text}: {m}");
        assert!(m.contains("unknown field"), "{text}: {m}");
        assert!(
            m.contains(&user_file(&r).display().to_string()),
            "{text}: {m}"
        );
    }
}

/// `same_host_local_images` widens what a same-host confirmation may run on, so set without
/// `same_host_confirmation` it changes nothing. That is said, as a note naming the file and both
/// settings, and it is not an error: the file is well formed and the command goes on.
#[test]
fn same_host_local_images_alone_changes_nothing_and_the_loader_says_so() {
    let r = root("local-images-alone");
    for (text, noted) in [
        ("[publish]\nsame_host_local_images = true\n", true),
        (
            "[publish]\nsame_host_local_images = true\nsame_host_confirmation = false\n",
            true,
        ),
        (
            "[publish]\nsame_host_local_images = true\nsame_host_confirmation = true\n",
            false,
        ),
        ("[publish]\nsame_host_confirmation = true\n", false),
        ("[publish]\nsame_host_local_images = false\n", false),
    ] {
        write(&user_file(&r), text);
        let c = loads(&env(&r));
        assert_eq!(
            c.publish().same_host_local_images,
            text.contains("same_host_local_images = true"),
            "{text}"
        );
        match noted {
            true => {
                let [note] = c.notes() else {
                    panic!("{text}: one note, and there are {:?}", c.notes());
                };
                for says in [
                    "same_host_local_images",
                    "same_host_confirmation",
                    "changes nothing",
                    &*user_file(&r).display().to_string(),
                ] {
                    assert!(note.contains(says), "{text}: {note}");
                }
            }
            false => assert!(c.notes().is_empty(), "{text}: {:?}", c.notes()),
        }
    }
}

#[test]
fn a_value_of_the_wrong_kind_is_refused_with_the_key_and_the_file() {
    let r = root("values");
    for (text, says) in [
        ("[publish]\ndivergences = \"publish\"\n", "refuse"),
        (
            "[publish]\nrebuilt_artifacts = \"github\"\n",
            "github-release",
        ),
        (
            "[publish]\nsame_host_confirmation = \"yes\"\n",
            "same_host_confirmation",
        ),
        (
            "[publish]\nsame_host_local_images = 1\n",
            "same_host_local_images",
        ),
        (
            "[publish]\nconfirmation_interval = \"1 hour\"\n",
            "confirmation_interval",
        ),
        ("[publish]\nheartbeat = \"1w\"\n", "heartbeat"),
        ("[freshness]\nstale_after = \"1.5d\"\n", "stale_after"),
        ("[freshness]\nfrozen_after = \"-14d\"\n", "frozen_after"),
        (
            "[publish]\norigin = \"https://github.com/owner/r\"\n",
            "schema-less",
        ),
        ("[publish]\norigin = \"github.com/o+r\"\n", "`+`"),
        (
            "[publish]\ndisputes = \"http://github.com/o/r/issues\"\n",
            "https://",
        ),
        (
            "[publish]\ndisputes = \"github.com/o/r/issues\"\n",
            "https://",
        ),
        ("[publish]\nrepo = \"backup:evidence\"\n", "SSH"),
        (
            "[publish]\nrepo = \"https://u:p@github.com/o/r\"\n",
            "password",
        ),
        ("[publish]\nbranch = \"-f\"\n", "branch"),
        ("[publish]\nlog_key = \"~root/log.key\"\n", "only `~/`"),
        ("[publish\n", "TOML"),
    ] {
        write(&user_file(&r), text);
        let m = load(&env(&r)).unwrap_err();
        assert!(m.contains(says), "{text}: {m}");
        assert!(
            m.contains(&user_file(&r).display().to_string()),
            "{text}: {m}"
        );
    }
}

#[test]
fn a_source_is_checked_as_it_is_read() {
    let r = root("sources");
    let good = |name: &str| {
        format!(
            "[[source]]\nname = \"{name}\"\nurls = [\"https://example.org/r.git\"]\n\
             log_key = \"{}\"\nattestation_key = \"{}\"\n",
            vkey(ORIGIN),
            key().public_hex()
        )
    };
    // One hex digit of the key hash changed, so it names another key.
    let mut bad_vkey = vkey(ORIGIN);
    let at = bad_vkey.find('+').unwrap() + 1;
    let flipped = if &bad_vkey[at..at + 1] == "0" {
        "1"
    } else {
        "0"
    };
    bad_vkey.replace_range(at..at + 1, flipped);
    for (text, says) in [
        (format!("{}{}", good("a"), good("a")), "configured twice"),
        (good("env"), "TRIGON_EVIDENCE_REPO"),
        (good("../escape"), "not a source name"),
        (good(""), "not a source name"),
        (good("-x"), "not a source name"),
        (
            good("s").replace("urls = [\"https://example.org/r.git\"]", "urls = []"),
            "`urls` is empty",
        ),
        (
            good("s").replace(
                "urls = [\"https://example.org/r.git\"]",
                "urls = [\"https://example.org/r.git\", \"https://example.org/r.git\"]",
            ),
            "listed twice",
        ),
        (
            good("s").replace(&vkey(ORIGIN), &bad_vkey),
            "names a key other than",
        ),
        (good("s").replace(&vkey(ORIGIN), "not-a-vkey"), "C2SP"),
        (
            good("s").replace(&key().public_hex(), "missing.pem"),
            "neither 64 hex digits nor a PEM file",
        ),
        (
            good("s").replace(&format!("log_key = \"{}\"\n", vkey(ORIGIN)), ""),
            "does not pin a log key",
        ),
        (
            good("s").replace(
                &format!("attestation_key = \"{}\"\n", key().public_hex()),
                "",
            ),
            "an attestation key",
        ),
        (
            good("s").replace(
                "urls = [\"https://example.org/r.git\"]",
                "urls = \"https://example.org/r.git\"",
            ),
            "sequence",
        ),
    ] {
        write(&user_file(&r), &text);
        let m = load(&env(&r)).unwrap_err();
        assert!(m.contains(says), "{text}\n{m}");
    }
}

#[test]
fn a_file_source_without_both_keys_needs_trust_on_first_use_and_says_it_rests_on_it() {
    let r = root("tofu-file");
    write(
        &user_file(&r),
        "[[source]]\nname = \"s\"\nurls = [\"https://example.org/r.git\"]\n\
         trust_on_first_use = true\n",
    );
    let c = loads(&env(&r));
    let s = c.source("s").unwrap();
    assert!(s.trust_on_first_use);
    assert_eq!(s.log_key, None);
    assert_eq!(s.attestation_key, None);

    // Both keys pinned: trust on first use has nothing to trust, and the source does not say it
    // rests on keys it read.
    write(
        &user_file(&r),
        &format!(
            "[[source]]\nname = \"s\"\nurls = [\"https://example.org/r.git\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\ntrust_on_first_use = true\n",
            vkey(ORIGIN),
            key().public_hex()
        ),
    );
    assert!(!loads(&env(&r)).source("s").unwrap().trust_on_first_use);
}

#[test]
fn trigon_evidence_config_names_the_file_instead_and_turns_off_the_projects() {
    let r = root("named");
    write(&user_file(&r), "[publish]\nbranch = \"from-user-file\"\n");
    let named = r.join("elsewhere/evidence.toml");
    write(&named, "[publish]\nbranch = \"from-named-file\"\n");
    write(
        &project_file(&r),
        "[publish]\nbranch = \"a project may not set this, and is not read\"\n",
    );
    let mut e = env(&r);
    e.evidence_config = Some(named.clone());
    let c = loads(&e);
    assert_eq!(c.publish().branch, "from-named-file");
    assert_eq!(c.files_read(), [named]);

    // A name that names nothing is an error: the user asked for that file.
    e.evidence_config = Some(r.join("nowhere.toml"));
    let m = load(&e).unwrap_err();
    assert!(
        m.contains("TRIGON_EVIDENCE_CONFIG") && m.contains("nowhere.toml"),
        "{m}"
    );

    // Relative to the working directory.
    write(
        &r.join("project/cfg.toml"),
        "[publish]\nbranch = \"relative\"\n",
    );
    e.evidence_config = Some(PathBuf::from("cfg.toml"));
    assert_eq!(loads(&e).publish().branch, "relative");
}

#[test]
fn the_default_file_is_under_xdg_config_home_when_it_is_set() {
    let r = root("xdg-config");
    write(
        &r.join("xdg/trigon/evidence.toml"),
        "[publish]\nbranch = \"xdg\"\n",
    );
    let mut e = env(&r);
    e.xdg_config_home = Some(r.join("xdg"));
    assert_eq!(loads(&e).publish().branch, "xdg");
}

// ---------------------------------------------------------------------------------------------
// The environment
// ---------------------------------------------------------------------------------------------

#[test]
fn trigon_publish_repo_replaces_the_files_repo_for_one_run() {
    let r = root("publish-repo");
    write(
        &user_file(&r),
        "[publish]\nrepo = \"https://github.com/o/r.git\"\n",
    );
    let mut e = env(&r);
    e.publish_repo = Some("../bare.git".into());
    let c = loads(&e);
    let repo = c.publish().repo.as_ref().unwrap();
    assert_eq!(repo.transport(), Transport::LocalPath);
    // From the working directory, since the environment named it.
    assert_eq!(
        repo.as_git_arg(),
        r.join("project/../bare.git").to_str().unwrap()
    );

    e.publish_repo = Some("ftp://example.org/r".into());
    let m = load(&e).unwrap_err();
    assert!(m.contains("TRIGON_PUBLISH_REPO"), "{m}");
}

#[test]
fn trigon_evidence_repo_adds_a_required_source_named_env() {
    let r = root("env-source");
    write(&r.join("project/keys/attestation.pub"), &key().public_pem());
    let mut e = env(&r);
    e.evidence_repo = Some(
        "https://github.com/o/trigon-evidence.git  https://codeberg.org/o/trigon-evidence.git \
         ./mirror"
            .into(),
    );
    e.evidence_log_key = Some(vkey(ORIGIN));
    e.evidence_attestation_key = Some("keys/attestation.pub".into());
    e.evidence_checkpoint = Some("trigon.checkpoint".into());
    let c = loads(&e);
    let s = c.source("env").unwrap();
    assert!(s.required, "a source named in the environment is required");
    assert_eq!(s.added_by, AddedBy::Environment);
    assert_eq!(s.urls.len(), 3);
    assert_eq!(
        s.urls[2].local_path(),
        Some(r.join("project/mirror").as_path())
    );
    assert_eq!(s.log_key.as_ref().unwrap().origin(), ORIGIN);
    assert_eq!(
        s.attestation_key.as_ref().unwrap().to_hex(),
        key().public_hex()
    );
    assert_eq!(
        s.checkpoint.as_deref(),
        Some(r.join("project/trigon.checkpoint").as_path())
    );
    assert!(!s.trust_on_first_use);
}

#[test]
fn trigon_evidence_repo_without_both_keys_is_refused_unless_trust_on_first_use() {
    let r = root("env-tofu");
    let mut e = env(&r);
    e.evidence_repo = Some("https://github.com/o/r.git".into());
    let m = load(&e).unwrap_err();
    assert!(m.contains("TRIGON_EVIDENCE_REPO"), "{m}");
    assert!(m.contains("TRIGON_EVIDENCE_TOFU=1"), "{m}");

    e.evidence_log_key = Some(vkey(ORIGIN));
    let m = load(&e).unwrap_err();
    assert!(m.contains("without an attestation key"), "{m}");

    e.evidence_tofu = Some("1".into());
    let c = loads(&e);
    let s = c.source("env").unwrap();
    assert!(s.trust_on_first_use);
    assert!(
        s.log_key.is_some(),
        "the key that was given is still pinned"
    );
    assert_eq!(s.attestation_key, None);

    e.evidence_tofu = Some("yes".into());
    let m = load(&e).unwrap_err();
    assert!(m.contains("TRIGON_EVIDENCE_TOFU"), "{m}");

    e.evidence_tofu = Some("0".into());
    assert!(load(&e).is_err(), "0 is off");
}

#[test]
fn a_pin_with_nothing_to_pin_is_an_error_rather_than_ignored() {
    let r = root("env-orphan");
    for set in [
        |e: &mut Env| e.evidence_log_key = Some(vkey(ORIGIN)),
        |e: &mut Env| e.evidence_attestation_key = Some(key().public_hex()),
        |e: &mut Env| e.evidence_checkpoint = Some("cp".into()),
        |e: &mut Env| e.evidence_tofu = Some("1".into()),
    ] {
        let mut e = env(&r);
        set(&mut e);
        let m = load(&e).unwrap_err();
        assert!(m.contains("TRIGON_EVIDENCE_REPO is not"), "{m}");
    }
}

#[test]
fn a_bad_value_in_the_environment_names_the_variable() {
    let r = root("env-bad");
    let mut e = env(&r);
    e.evidence_repo = Some("https://github.com/o/r.git".into());
    e.evidence_log_key = Some("nope".into());
    e.evidence_attestation_key = Some(key().public_hex());
    let m = load(&e).unwrap_err();
    assert!(m.starts_with("TRIGON_EVIDENCE_LOG_KEY"), "{m}");

    e.evidence_log_key = Some(vkey(ORIGIN));
    e.evidence_repo = Some("backup:r".into());
    let m = load(&e).unwrap_err();
    assert!(m.starts_with("TRIGON_EVIDENCE_REPO"), "{m}");
}

// ---------------------------------------------------------------------------------------------
// A project's own file
// ---------------------------------------------------------------------------------------------

/// A project source that keeps every rule, with its checkpoint in the project.
fn project_source(r: &Path, name: &str) -> String {
    write(&r.join("project/.trigon/ours.checkpoint"), "checkpoint\n");
    format!(
        "[[source]]\nname = \"{name}\"\nurls = [\"https://example.org/theirs.git\"]\n\
         log_key = \"{}\"\nattestation_key = \"{}\"\ncheckpoint = \"ours.checkpoint\"\n",
        vkey("example.org/theirs"),
        key().public_hex()
    )
}

#[test]
fn a_project_file_that_keeps_the_rules_adds_its_sources_and_says_so() {
    let r = root("project-ok");
    write(
        &r.join("project/.trigon/attestation.pub"),
        &key().public_pem(),
    );
    let mut second = project_source(&r, "second");
    second = second.replace(&key().public_hex(), "attestation.pub");
    write(
        &project_file(&r),
        &format!("{}{second}", project_source(&r, "theirs")),
    );
    let c = loads(&env(&r));
    assert_eq!(c.sources().len(), 2);
    let s = c.source("theirs").unwrap();
    // Every answer from it names the file that added it.
    assert_eq!(s.added_by, AddedBy::ProjectFile(project_file(&r)));
    assert!(s.added_by.to_string().contains("the project's own"));
    assert!(!s.required);
    assert!(!s.trust_on_first_use);
    assert_eq!(
        s.checkpoint.as_deref(),
        Some(r.join("project/.trigon/ours.checkpoint").as_path())
    );
    assert_eq!(c.files_read(), [project_file(&r)]);
}

#[test]
fn a_project_file_that_breaks_a_rule_is_refused_whole_with_the_rule() {
    let r = root("project-rules");
    write(
        &user_file(&r),
        &format!(
            "[[source]]\nname = \"trigon\"\nurls = [\"https://github.com/o/r.git\"]\n\
             log_key = \"{}\"\nattestation_key = \"{}\"\n",
            vkey(ORIGIN),
            key().public_hex()
        ),
    );
    write(&r.join("outside.checkpoint"), "not the project's\n");
    let ok = project_source(&r, "theirs");
    let hex = key().public_hex();
    let checkpoint_line = "checkpoint = \"ours.checkpoint\"\n";
    for (bad, rule) in [
        (
            "[publish]\norigin = \"example.org/x\"\n".to_string(),
            "[publish]",
        ),
        (
            "[freshness]\nfrozen_after = \"3650d\"\n".into(),
            "[freshness]",
        ),
        (format!("{ok}required = true\n"), "`required`"),
        (format!("{ok}required = false\n"), "`required`"),
        (
            format!("{ok}trust_on_first_use = true\n"),
            "trust_on_first_use",
        ),
        (
            ok.replace(
                &format!("log_key = \"{}\"\n", vkey("example.org/theirs")),
                "",
            ),
            "both `log_key` and `attestation_key`",
        ),
        (
            ok.replace(&format!("attestation_key = \"{hex}\"\n"), ""),
            "both `log_key` and `attestation_key`",
        ),
        (ok.replace(checkpoint_line, ""), "`checkpoint`"),
        (
            ok.replace(
                "https://example.org/theirs.git",
                "git@example.org:theirs.git",
            ),
            "HTTPS only",
        ),
        (
            ok.replace(
                "https://example.org/theirs.git",
                "http://example.org/theirs.git",
            ),
            "HTTPS only",
        ),
        (
            ok.replace("https://example.org/theirs.git", "./theirs"),
            "HTTPS only",
        ),
        (ok.replace("\"theirs\"", "\"trigon\""), "already configured"),
        (format!("{ok}{ok}"), "already configured"),
        (
            ok.replace(
                checkpoint_line,
                "checkpoint = \"../../outside.checkpoint\"\n",
            ),
            "outside the project",
        ),
        (
            ok.replace(
                checkpoint_line,
                &format!(
                    "checkpoint = \"{}\"\n",
                    r.join("outside.checkpoint").display()
                ),
            ),
            "not a path inside the project",
        ),
        (
            ok.replace(checkpoint_line, "checkpoint = \"~/cp\"\n"),
            "not a path inside the project",
        ),
        (
            ok.replace(&hex, "../../outside.checkpoint"),
            "outside the project",
        ),
    ] {
        // One good source and one bad in the same file: the good one is not added either.
        let text = format!("{}{bad}", project_source(&r, "fine"));
        write(&project_file(&r), &text);
        let e = EvidenceConfig::load(&env(&r)).unwrap_err();
        assert_eq!(e.exit_code(), 5);
        let m = e.to_string();
        assert!(m.contains(rule), "{bad}\n{m}");
        assert!(
            m.contains(&project_file(&r).display().to_string()),
            "{bad}\nthe refusal names the file: {m}"
        );
        assert!(
            matches!(e, ConfigError::ProjectRule { .. }),
            "{bad}\nrefused as a project rule: {m}"
        );
    }
}

#[test]
fn a_project_cannot_reach_outside_itself_through_a_symlink() {
    // The project controls its symlinks too, so the check follows them.
    let r = root("project-symlink");
    write(&r.join("secret"), "the host's, not the project's\n");
    std::fs::create_dir_all(r.join("project/.trigon")).unwrap();
    std::os::unix::fs::symlink(r.join("secret"), r.join("project/.trigon/cp")).unwrap();
    let text = project_source(&r, "theirs").replace("ours.checkpoint", "cp");
    write(&project_file(&r), &text);
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("outside the project"), "{m}");
}

#[test]
fn a_project_cannot_reuse_the_environments_source_name() {
    let r = root("project-env");
    write(&project_file(&r), &project_source(&r, "env"));
    let mut e = env(&r);
    e.evidence_repo = Some("https://github.com/o/r.git".into());
    e.evidence_log_key = Some(vkey(ORIGIN));
    e.evidence_attestation_key = Some(key().public_hex());
    let m = load(&e).unwrap_err();
    assert!(m.contains("already configured"), "{m}");
}

#[test]
fn a_projects_refusal_prints_its_strings_escaped() {
    // Every place a refusal quotes something the project wrote: a name refused by a project rule,
    // a name refused as a name, a log key, the path of a PEM that is not one, a key toml does not
    // know, and a value toml cannot parse.
    let r = root("project-escape");
    let ok = project_source(&r, "x");
    let pem = "k\u{1b}[2J.pem";
    write(&r.join("project/.trigon").join(pem), "not a key\n");
    // Each with whether the refusal quotes the string, and so shows the character escaped.
    for (bad, quoted) in [
        (
            format!(
                "{}required = true\n",
                ok.replace("name = \"x\"", "name = \"x\\u001b[2J\"")
            ),
            true,
        ),
        (ok.replace("name = \"x\"", "name = \"x\\u001b[2J\""), true),
        (
            ok.replace(&vkey("example.org/theirs"), "a\\u001b[2J+033de0ae+AAAA"),
            true,
        ),
        (ok.replace(&key().public_hex(), "k\\u001b[2J.pem"), true),
        (
            format!("{ok}\"\\u001b]0;pwned\\u0007\\u001b[2J\" = 1\n"),
            true,
        ),
        // Raw, which toml refuses without quoting it.
        (format!("{ok}\u{1b}[2J = 1\n"), false),
        ("[[source]]\nname = \"\u{1b}[2J\"\n".into(), false),
    ] {
        write(&project_file(&r), &bad);
        let m = load(&env(&r)).unwrap_err();
        assert!(
            !m.contains('\u{1b}') && !m.contains('\u{7}'),
            "{bad}\n{m:?}"
        );
        if quoted {
            assert!(
                m.contains(r"\u{1b}"),
                "the character is shown escaped: {bad}\n{m}"
            );
        }
    }
}

#[test]
fn a_project_file_that_links_outside_the_project_is_not_read() {
    // A pull request writes its symlinks too. A `.trigon/evidence.toml` that is a link to a file of
    // the runner's was read, failed to parse, and had toml quote the line into the CI log.
    let r = root("project-file-link");
    let secret = "GITHUB_TOKEN=ghs_SUPERSECRETVALUE";
    write(
        &r.join("host/secrets"),
        &format!("{secret} PATH=/usr/bin\n"),
    );
    write(&r.join("host/evidence.toml"), &format!("{secret}\n"));
    std::fs::create_dir_all(r.join("project/.trigon")).unwrap();
    std::os::unix::fs::symlink(r.join("host/secrets"), project_file(&r)).unwrap();
    let e = EvidenceConfig::load(&env(&r)).unwrap_err();
    let m = e.to_string();
    assert!(matches!(e, ConfigError::ProjectRule { .. }), "{m}");
    assert!(m.contains("outside the project"), "{m}");
    assert!(
        !m.contains("ghs_"),
        "the host's file reached the message: {m}"
    );

    // So is one reached through a linked `.trigon`.
    std::fs::remove_dir_all(r.join("project/.trigon")).unwrap();
    std::os::unix::fs::symlink(r.join("host"), r.join("project/.trigon")).unwrap();
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("outside the project"), "{m}");
    assert!(!m.contains("ghs_"), "{m}");

    // And a device, the size of which is no limit on what reading it yields.
    std::fs::remove_file(r.join("project/.trigon")).unwrap();
    std::fs::create_dir_all(r.join("project/.trigon")).unwrap();
    std::os::unix::fs::symlink("/dev/zero", project_file(&r)).unwrap();
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("outside the project"), "{m}");

    // A link to nothing is a file that is there and cannot be read, not an absent one.
    std::fs::remove_file(project_file(&r)).unwrap();
    std::os::unix::fs::symlink(r.join("host/nothing"), project_file(&r)).unwrap();
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("cannot be resolved"), "{m}");
}

#[test]
fn a_project_file_that_links_inside_the_project_is_read() {
    let r = root("project-file-link-inside");
    write(
        &r.join("project/config/evidence.toml"),
        &project_source(&r, "theirs"),
    );
    std::os::unix::fs::symlink(r.join("project/config/evidence.toml"), project_file(&r)).unwrap();
    assert!(loads(&env(&r)).source("theirs").is_some());
}

#[test]
fn a_project_file_that_is_not_a_small_regular_file_is_refused() {
    let r = root("project-file-shape");
    std::fs::create_dir_all(project_file(&r)).unwrap();
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("not a regular file"), "{m}");

    std::fs::remove_dir(project_file(&r)).unwrap();
    let limit = trigon_attest::config::PROJECT_FILE_LIMIT as usize;
    let mut big = project_source(&r, "theirs");
    big.push_str(&"#".repeat(limit + 1 - big.len()));
    write(&project_file(&r), &big);
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("larger than"), "{m}");
    // One byte less is read.
    big.pop();
    write(&project_file(&r), &big);
    assert!(loads(&env(&r)).source("theirs").is_some());
}

#[test]
fn a_projects_parse_error_says_where_and_does_not_quote_the_file() {
    let r = root("project-parse");
    write(
        &project_file(&r),
        "[[source]]\nname = \"a\"\nGITHUB_TOKEN=ghs_SECRET PATH\n",
    );
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("line 3, column"), "{m}");
    assert!(!m.contains("ghs_SECRET"), "{m}");
}

#[test]
fn a_source_name_is_one_whatever_its_case() {
    // A name is the source's directory, and on a case-insensitive filesystem `Trigon` and `trigon`
    // are one: a project's `Trigon` would share the user's source's checkpoint and key history.
    let r = root("name-case");
    write(
        &user_file(&r),
        &format!(
            "[[source]]\nname = \"trigon\"\nurls = [\"https://github.com/o/r.git\"]\n\
             log_key = \"{}\"\nattestation_key = \"{}\"\n",
            vkey(ORIGIN),
            key().public_hex()
        ),
    );
    write(&project_file(&r), &project_source(&r, "Trigon"));
    let e = EvidenceConfig::load(&env(&r)).unwrap_err();
    assert!(matches!(e, ConfigError::ProjectRule { .. }), "{e}");
    assert!(e.to_string().contains("already configured"), "{e}");

    // Two in one project file, and two in the user's.
    write(
        &project_file(&r),
        &format!(
            "{}{}",
            project_source(&r, "theirs"),
            project_source(&r, "THEIRS")
        ),
    );
    assert!(load(&env(&r)).unwrap_err().contains("already configured"));
    std::fs::remove_file(project_file(&r)).unwrap();
    let user = std::fs::read_to_string(user_file(&r)).unwrap();
    write(
        &user_file(&r),
        &format!("{user}{}", user.replace("\"trigon\"", "\"TriGon\"")),
    );
    assert!(load(&env(&r)).unwrap_err().contains("configured twice"));

    // And the environment's name is reserved in every case.
    write(&user_file(&r), &user.replace("\"trigon\"", "\"ENV\""));
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("TRIGON_EVIDENCE_REPO"), "{m}");
}

#[test]
fn an_unknown_key_in_a_project_file_is_refused_too() {
    let r = root("project-unknown");
    write(
        &project_file(&r),
        &format!("{}mirror = true\n", project_source(&r, "theirs")),
    );
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("unknown field") && m.contains("mirror"), "{m}");
}

// ---------------------------------------------------------------------------------------------
// Durations
// ---------------------------------------------------------------------------------------------

#[test]
fn a_duration_is_a_whole_number_and_one_unit() {
    for (s, secs) in [
        ("30s", 30),
        ("15m", 900),
        ("1h", 3600),
        ("7d", 604_800),
        ("0s", 0),
        ("014d", 14 * 86_400),
    ] {
        assert_eq!(parse_duration(s), Ok(Duration::from_secs(secs)), "{s}");
    }
    for s in [
        "", "1", "h", "1.5h", "-1h", "+1h", "1w", "1 h", " 1h", "1H", "1hh", "1dd",
    ] {
        let e = parse_duration(s).unwrap_err();
        assert!(e.contains("`1h`"), "{s:?}: {e}");
    }
    assert!(
        parse_duration("99999999999999999999d").is_err(),
        "too large to count is refused, not wrapped"
    );
    assert!(
        parse_duration("213503982334602d")
            .unwrap_err()
            .contains("longer")
    );
}

// ---------------------------------------------------------------------------------------------
// `trigon evidence add` and `remove`, and what a source trusting on first use is pinned by
// ---------------------------------------------------------------------------------------------

#[test]
fn a_source_is_added_to_the_file_named_made_where_it_is_not_there_and_removed_again() {
    use trigon_attest::config::{NewSource, add_source, remove_source};
    let r = root("add-named");
    let named = r.join("elsewhere/evidence.toml");
    let e = Env {
        evidence_config: Some(named.clone()),
        ..env(&r)
    };
    let new = NewSource {
        name: "theirs".into(),
        urls: vec!["https://example.org/theirs.git".into(), "../mirror".into()],
        log_key: Some(vkey(ORIGIN)),
        attestation_key: Some(key().public_hex()),
        ..Default::default()
    };
    let (path, source) = add_source(&e, &new).unwrap();
    assert_eq!(path, named);
    assert_eq!(source.added_by, AddedBy::UserFile(named.clone()));
    // A relative path is from the working directory, and written absolute: `..` is left for
    // the filesystem to resolve, through whatever links are there, as every location's is.
    let text = std::fs::read_to_string(&named).unwrap();
    assert!(
        text.contains(&format!("\"{}\"", r.join("project/../mirror").display())),
        "{text}"
    );
    assert_eq!(loads(&e).source("theirs").unwrap().urls.len(), 2);
    // The name is taken, whatever its case.
    let again = NewSource {
        name: "THEIRS".into(),
        ..new.clone()
    };
    let m = add_source(&e, &again).unwrap_err().to_string();
    assert!(m.contains("is configured already"), "{m}");
    let (path, gone) = remove_source(&e, "Theirs").unwrap();
    assert_eq!((path, gone.name.as_str()), (named.clone(), "theirs"));
    assert!(loads(&e).sources().is_empty());
}

/// A user file kept as a link — a dotfiles manager keeps it in a directory of its own — is
/// written where the link leads, and the link is kept, so adding and removing a source changes the
/// file the user keeps. A link to a file not made yet makes it there.
#[test]
fn a_source_is_added_to_the_file_a_link_leads_to_and_the_link_is_kept() {
    use trigon_attest::config::{NewSource, add_source, remove_source};
    let r = root("add-link");
    let kept = r.join("dotfiles/trigon/evidence.toml");
    let original = "# mine\n[freshness]\nstale_after = \"12h\"\n";
    write(&kept, original);
    let link = user_file(&r);
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("../../../dotfiles/trigon/evidence.toml", &link).unwrap();
    let is_link = |p: &Path| {
        std::fs::symlink_metadata(p)
            .unwrap()
            .file_type()
            .is_symlink()
    };
    let e = env(&r);
    let new = NewSource {
        name: "theirs".into(),
        urls: vec!["https://example.org/theirs.git".into()],
        log_key: Some(vkey(ORIGIN)),
        attestation_key: Some(key().public_hex()),
        ..Default::default()
    };
    let (path, _) = add_source(&e, &new).unwrap();
    assert_eq!(path, link, "said as the file configured");
    assert!(is_link(&link), "the link is kept");
    let text = std::fs::read_to_string(&kept).unwrap();
    assert!(text.starts_with(original), "{text}");
    assert!(text.contains("name = \"theirs\""), "{text}");
    assert_eq!(loads(&e).source("theirs").unwrap().urls.len(), 1);
    remove_source(&e, "theirs").unwrap();
    assert!(is_link(&link));
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), original);

    std::fs::remove_file(&kept).unwrap();
    add_source(&e, &new).unwrap();
    assert!(is_link(&link));
    let text = std::fs::read_to_string(&kept).unwrap();
    assert!(text.contains("name = \"theirs\""), "{text}");
}

#[test]
fn a_source_trusting_on_first_use_is_pinned_by_the_keys_its_first_sync_recorded() {
    use trigon_attest::state::{FirstUse, KeysFile};
    let r = root("tofu-pins");
    write(
        &user_file(&r),
        "[[source]]\nname = \"s\"\nurls = [\"https://example.org/r.git\"]\n\
         trust_on_first_use = true\n",
    );
    let c = loads(&env(&r));
    // Nothing recorded yet: the verifier has nothing to hold a record to, and says where it
    // looked.
    let e = c.pins("s").unwrap_err();
    assert_eq!(e.exit_code(), 5);
    let m = e.to_string();
    assert!(m.contains("no `trigon evidence sync` has recorded"), "{m}");
    assert!(m.contains("keys"), "{m}");

    let log = trigon_attest::LogVkey::parse(&vkey(ORIGIN)).unwrap();
    let attestation = trigon_attest::AttestationKey::from(key().public_key());
    let first_use = FirstUse {
        read_from: "https://example.org/r.git".into(),
        at: 1_790_000_000,
    };
    let recorded = KeysFile {
        schema: "trigon.evidence-keys/v1".into(),
        log_key: log.to_string(),
        attestation_key: attestation.to_hex(),
        first_use: Some(first_use.clone()),
        logs: Vec::new(),
        attestation_keys: Vec::new(),
    };
    let state = c.source_state_dir("s").unwrap();
    recorded.write(&state).unwrap();
    // Recorded keys are a sync that got as far as writing its state, so a checkpoint that is not
    // there was lost, and is refused as `evidence sync` refuses it rather than read as never
    // accepted.
    let e = c.pins("s").unwrap_err();
    assert_eq!(e.exit_code(), 5);
    let m = e.to_string();
    assert!(m.contains("has synced before"), "{m}");
    assert!(m.contains("--accept-state-loss s"), "{m}");
    write(&state.join("checkpoint"), "a note\n");
    let p = c.pins("s").unwrap();
    assert_eq!(p.log_key, log);
    assert_eq!(p.attestation_key, attestation);
    assert_eq!(p.first_use, Some(first_use));
    // A pinned source says nothing of first use, whatever its state holds.
    write(
        &user_file(&r),
        &format!(
            "[[source]]\nname = \"s\"\nurls = [\"https://example.org/r.git\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\n",
            vkey(ORIGIN),
            key().public_hex()
        ),
    );
    assert_eq!(loads(&env(&r)).pins("s").unwrap().first_use, None);
}

#[test]
fn a_key_history_says_where_it_disagrees_with_the_log_and_not_where_the_log_went_on() {
    use trigon_attest::state::{ChainLog, Epoch, KeysFile, Place};
    let epoch = |k: &str, from: Option<u64>| Epoch {
        key_id: format!("id-{k}"),
        public_key: k.repeat(64),
        from: from.map(|index| Place {
            log: 0,
            origin: ORIGIN.into(),
            index,
        }),
        until: None,
    };
    let file = |keys: Vec<Epoch>, logs: Vec<&str>| KeysFile {
        schema: "trigon.evidence-keys/v1".into(),
        log_key: vkey(ORIGIN),
        attestation_key: "a".repeat(64),
        first_use: None,
        logs: logs
            .into_iter()
            .map(|o| ChainLog {
                origin: o.into(),
                log_key: format!("{o}+key"),
            })
            .collect(),
        attestation_keys: keys,
    };
    let was = file(vec![epoch("a", None)], vec![ORIGIN]);
    // The log went on: a key change and a succession since. Not a disagreement.
    let grown = file(
        vec![epoch("a", None), epoch("b", Some(4))],
        vec![ORIGIN, "example.com/trigon-evidence/1"],
    );
    assert!(was.differences(&grown).is_empty());
    // The log now lacks what was kept: a key change it once held.
    let d = grown.differences(&was);
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(d[0].contains("records the logs"), "{d:?}");
    assert!(d[1].contains("records the attestation keys"), "{d:?}");
    // Another key at the same place.
    let other = file(vec![epoch("a", None), epoch("c", Some(4))], vec![ORIGIN]);
    assert_eq!(grown.differences(&other).len(), 2);
}

// ---------------------------------------------------------------------------------------------
// What else is refused, and what a source trusting on first use is pinned by when it pins one key
// ---------------------------------------------------------------------------------------------

/// Every pin the environment gives that cannot be read is refused, naming its variable, and so is a
/// source variable that names no location at all.
#[test]
fn every_environment_pin_that_cannot_be_read_names_its_variable() {
    let r = root("env-bad-pins");
    let pinned = || Env {
        evidence_repo: Some("https://github.com/o/r.git".into()),
        evidence_log_key: Some(vkey(ORIGIN)),
        evidence_attestation_key: Some(key().public_hex()),
        ..env(&r)
    };
    assert_eq!(loads(&pinned()).sources().len(), 1);
    for (set, says) in [
        (
            (|e: &mut Env| e.evidence_attestation_key = Some("no-such.pem".into())) as fn(&mut Env),
            "TRIGON_EVIDENCE_ATTESTATION_KEY is refused: `no-such.pem` is neither 64 hex digits",
        ),
        (
            |e| e.evidence_checkpoint = Some("~other/checkpoint".into()),
            "TRIGON_EVIDENCE_CHECKPOINT is refused: `~other/checkpoint`: only `~/` is expanded",
        ),
        (
            |e| e.evidence_repo = Some(" \t ".into()),
            "TRIGON_EVIDENCE_REPO names no location",
        ),
    ] {
        let mut e = pinned();
        set(&mut e);
        let m = load(&e).unwrap_err();
        assert!(m.starts_with(says), "{m}");
    }
}

/// An origin names a log for good and is its key's name: one that is empty or holds whitespace is
/// refused, in the file and wherever a command is given one; and so is a path that is empty.
#[test]
fn an_origin_that_could_name_no_log_and_an_empty_path_are_refused() {
    use trigon_attest::config::check_origin;
    let r = root("origins");
    for (origin, says) in [
        ("", "is empty"),
        ("github.com/owner /r", "contains whitespace"),
        ("github.com/owner\t/r", "contains whitespace"),
        ("github.com/owner/r\u{7}", "contains whitespace"),
    ] {
        let e = check_origin(origin).unwrap_err();
        assert!(e.contains(says), "{origin:?}: {e}");
        write(
            &user_file(&r),
            &format!("[publish]\norigin = {}\n", toml_string(origin)),
        );
        let m = load(&env(&r)).unwrap_err();
        assert!(m.contains(says), "{origin:?}: {m}");
    }
    check_origin(ORIGIN).unwrap();

    write(&user_file(&r), "[publish]\nlog_key = \"\"\n");
    let m = load(&env(&r)).unwrap_err();
    assert!(m.contains("log_key: the path is empty"), "{m}");
}

/// `s` as a TOML basic string.
fn toml_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A file named that is not a file is an error reading it, never a file with nothing in it.
#[test]
fn a_configuration_file_that_cannot_be_read_is_an_error_not_an_empty_file() {
    use trigon_attest::config::{NewSource, add_source};
    let r = root("unreadable");
    let e = Env {
        evidence_config: Some(r.join("home")),
        ..env(&r)
    };
    let m = load(&e).unwrap_err();
    assert!(
        m.starts_with(&format!("reading {}", r.join("home").display())),
        "{m}"
    );
    let new = NewSource {
        name: "theirs".into(),
        urls: vec!["https://example.org/theirs.git".into()],
        log_key: Some(vkey(ORIGIN)),
        attestation_key: Some(key().public_hex()),
        ..Default::default()
    };
    let m = add_source(&e, &new).unwrap_err().to_string();
    assert!(
        m.starts_with(&format!("reading {}", r.join("home").display())),
        "{m}"
    );
}

/// `trigon evidence add` holds a source to every rule the file does before writing it: not under
/// `TRIGON_EVIDENCE_REPO`'s name, and with at least one location. A PEM attestation key and an
/// initial checkpoint, given from the working directory, are written absolute and load as given.
#[test]
fn a_source_added_keeps_the_files_rules_and_its_files_are_written_absolute() {
    use trigon_attest::config::{NewSource, add_source};
    let r = root("add-rules");
    let e = env(&r);
    let new = NewSource {
        name: "theirs".into(),
        urls: vec!["https://example.org/theirs.git".into()],
        log_key: Some(vkey(ORIGIN)),
        attestation_key: Some(key().public_hex()),
        ..Default::default()
    };
    for (changed, says) in [
        (
            NewSource {
                name: "ENV".into(),
                ..new.clone()
            },
            "that name is TRIGON_EVIDENCE_REPO's",
        ),
        (
            NewSource {
                urls: Vec::new(),
                ..new.clone()
            },
            "it needs at least one location",
        ),
        (
            NewSource {
                attestation_key: Some("keys/missing.pem".into()),
                ..new.clone()
            },
            "--attestation-key",
        ),
    ] {
        let m = add_source(&e, &changed).unwrap_err().to_string();
        assert!(m.contains(says), "{m}");
    }
    assert!(!user_file(&r).exists(), "nothing is written for a refusal");

    // A PEM key and a checkpoint the log key opens, both relative to the working directory.
    write(&r.join("project/keys/attestation.pub"), &key().public_pem());
    let signer = trigon_attest::log::LogSigner::from_seed(ORIGIN, [9; 32]).unwrap();
    let checkpoint = trigon_attest::log::SignedCheckpoint::sign(
        &trigon_attest::log::Checkpoint::empty(ORIGIN),
        &signer,
    )
    .unwrap();
    write(
        &r.join("project/keys/initial.checkpoint"),
        &checkpoint.to_string(),
    );
    let (path, source) = add_source(
        &e,
        &NewSource {
            attestation_key: Some("keys/attestation.pub".into()),
            checkpoint: Some("keys/initial.checkpoint".into()),
            required: true,
            ..new.clone()
        },
    )
    .unwrap();
    assert_eq!(path, user_file(&r));
    let text = std::fs::read_to_string(&path).unwrap();
    for file in ["attestation.pub", "initial.checkpoint"] {
        let absolute = r.join("project/keys").join(file);
        assert!(
            text.contains(&format!("\"{}\"", absolute.display())),
            "{text}"
        );
    }
    assert!(text.contains("required = true"), "{text}");
    assert_eq!(
        source.attestation_key,
        Some(trigon_attest::AttestationKey::from(key().public_key()))
    );
    assert_eq!(
        source.checkpoint,
        Some(r.join("project/keys/initial.checkpoint"))
    );
    assert!(source.required);
    let pins = loads(&e).pins("theirs").unwrap();
    assert_eq!(
        pins.accepted.map(|(_, note)| note),
        Some(checkpoint.to_string().into_bytes())
    );
}

/// A file whose sources are written other than as `[[source]]` tables is read like any other, and
/// is neither added to nor removed from by rewriting it: the user is told to do it by hand.
#[test]
fn sources_written_inline_are_read_and_left_to_the_user_to_change() {
    use trigon_attest::config::{NewSource, add_source, remove_source};
    let r = root("inline");
    let inline = format!(
        "source = [{{ name = \"mine\", urls = [\"https://example.org/mine.git\"], \
         log_key = \"{}\", attestation_key = \"{}\" }}]\n",
        vkey(ORIGIN),
        key().public_hex()
    );
    write(&user_file(&r), &inline);
    let e = env(&r);
    assert_eq!(loads(&e).sources().len(), 1);
    let new = NewSource {
        name: "theirs".into(),
        urls: vec!["https://example.org/theirs.git".into()],
        log_key: Some(vkey(ORIGIN)),
        attestation_key: Some(key().public_hex()),
        ..Default::default()
    };
    let m = add_source(&e, &new).unwrap_err().to_string();
    assert!(m.contains("add it by hand"), "{m}");
    let m = remove_source(&e, "mine").unwrap_err().to_string();
    assert!(m.contains("remove it by hand"), "{m}");
    assert_eq!(std::fs::read_to_string(user_file(&r)).unwrap(), inline);
}

/// A source trusting on first use that pins one key is pinned by that key, whatever its first sync
/// recorded, and by the recorded one only for the key it does not pin.
#[test]
fn a_key_a_source_pins_wins_over_the_one_its_first_sync_recorded() {
    use trigon_attest::state::{FirstUse, KeysFile};
    let r = root("tofu-one-key");
    let pinned_log = trigon_attest::LogVkey::parse(&vkey(ORIGIN)).unwrap();
    let pinned_attestation = trigon_attest::AttestationKey::from(key().public_key());
    let other = LocalKey::from_bytes(&[8u8; 32]).unwrap();
    let recorded_log = trigon_attest::log::LogSigner::from_seed(ORIGIN, [8; 32])
        .unwrap()
        .vkey();
    let recorded_attestation = trigon_attest::AttestationKey::from(other.public_key());
    let source = |pin: &str| {
        format!(
            "[[source]]\nname = \"s\"\nurls = [\"https://example.org/r.git\"]\n{pin}\n\
             trust_on_first_use = true\n"
        )
    };
    let record = |c: &EvidenceConfig| {
        let state = c.source_state_dir("s").unwrap();
        KeysFile {
            schema: "trigon.evidence-keys/v1".into(),
            log_key: recorded_log.to_string(),
            attestation_key: recorded_attestation.to_hex(),
            first_use: Some(FirstUse {
                read_from: "https://example.org/r.git".into(),
                at: 1_790_000_000,
            }),
            logs: Vec::new(),
            attestation_keys: Vec::new(),
        }
        .write(&state)
        .unwrap();
        write(&state.join("checkpoint"), "a note\n");
    };

    write(
        &user_file(&r),
        &source(&format!("log_key = \"{}\"", vkey(ORIGIN))),
    );
    let c = loads(&env(&r));
    record(&c);
    let p = c.pins("s").unwrap();
    assert_eq!(p.log_key, pinned_log);
    assert_eq!(p.attestation_key, recorded_attestation);
    assert!(p.first_use.is_some());

    write(
        &user_file(&r),
        &source(&format!("attestation_key = \"{}\"", key().public_hex())),
    );
    let c = loads(&env(&r));
    let p = c.pins("s").unwrap();
    assert_eq!(p.log_key, recorded_log);
    assert_eq!(p.attestation_key, pinned_attestation);

    // A recorded key that cannot be read is refused, saying which file, never passed over.
    let state = c.source_state_dir("s").unwrap();
    let mut keys = KeysFile::read(&state).unwrap().unwrap();
    keys.log_key = "not a key".into();
    keys.write(&state).unwrap();
    let m = c.pins("s").unwrap_err().to_string();
    assert!(
        m.starts_with(&state.join("keys").display().to_string()) && m.contains("its `logKey`"),
        "{m}"
    );
}

/// The checkpoint a log is held to is refused where it is there and cannot be read — the one last
/// accepted, or the initial one configured — rather than passed over: it is what a rollback is
/// caught against.
#[test]
fn a_checkpoint_that_cannot_be_read_is_refused_not_passed_over() {
    let r = root("pins-unreadable");
    write(
        &user_file(&r),
        &format!(
            "[[source]]\nname = \"s\"\nurls = [\"https://example.org/r.git\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\ncheckpoint = \"initial.checkpoint\"\n",
            vkey(ORIGIN),
            key().public_hex()
        ),
    );
    let c = loads(&env(&r));
    let initial = r.join("home/.config/trigon/initial.checkpoint");
    let m = c.pins("s").unwrap_err().to_string();
    assert!(
        m.starts_with(&initial.display().to_string())
            && m.contains("the checkpoint cannot be read"),
        "{m}"
    );
    write(&initial, "a note\n");
    assert_eq!(
        c.pins("s").unwrap().accepted,
        Some((initial.clone(), b"a note\n".to_vec()))
    );

    let last = c.source_state_dir("s").unwrap().join("checkpoint");
    std::fs::create_dir_all(&last).unwrap();
    let m = c.pins("s").unwrap_err().to_string();
    assert!(
        m.starts_with(&last.display().to_string())
            && m.contains("the checkpoint is not a regular file"),
        "{m}"
    );
}

/// A user file kept at the end of as many links as the system follows — forty, on Linux — is
/// written where they lead, as it was read from there.
#[cfg(target_os = "linux")]
#[test]
fn a_user_file_at_the_end_of_forty_links_is_written_where_they_lead() {
    use trigon_attest::config::{NewSource, add_source};
    // Canonical, so that the chain is the only links on the way: the system counts a link in the
    // temporary directory's own path again at every hop.
    let r = std::fs::canonicalize(root("forty-links")).unwrap();
    let kept = r.join("links/evidence.toml");
    let original = "# mine\n[freshness]\nstale_after = \"12h\"\n";
    write(&kept, original);
    let mut to = kept.clone();
    for n in 0..40 {
        let link = r.join(format!("links/{n}"));
        std::os::unix::fs::symlink(&to, &link).unwrap();
        to = link;
    }
    std::fs::read_to_string(&to).expect("the system follows forty links");
    let e = Env {
        evidence_config: Some(to.clone()),
        ..env(&r)
    };
    let new = NewSource {
        name: "theirs".into(),
        urls: vec!["https://example.org/theirs.git".into()],
        log_key: Some(vkey(ORIGIN)),
        attestation_key: Some(key().public_hex()),
        ..Default::default()
    };
    add_source(&e, &new).unwrap();
    let text = std::fs::read_to_string(&kept).unwrap();
    assert!(
        text.starts_with(original) && text.contains("name = \"theirs\""),
        "{text}"
    );
    assert!(
        std::fs::symlink_metadata(&to)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

/// The user's file is written whole or not at all: where the write cannot be made — here, the
/// temporary file it is written to first cannot be created — the change is refused as a write,
/// said with the file, and the file is as it was.
#[test]
fn a_change_that_cannot_be_written_leaves_the_users_file_as_it_was() {
    use trigon_attest::config::{NewSource, add_source, remove_source};
    let r = root("unwritable");
    let original = format!(
        "# mine\n[[source]]\nname = \"mine\"\nurls = [\"https://example.org/mine.git\"]\n\
         log_key = \"{}\"\nattestation_key = \"{}\"\n",
        vkey(ORIGIN),
        key().public_hex()
    );
    write(&user_file(&r), &original);
    // What the write goes through first, blocked by a directory of its name.
    let blocked =
        user_file(&r).with_file_name(format!(".evidence.toml.{}.tmp", std::process::id()));
    std::fs::create_dir_all(blocked.join("in-the-way")).unwrap();
    let e = env(&r);
    let new = NewSource {
        name: "theirs".into(),
        urls: vec!["https://example.org/theirs.git".into()],
        log_key: Some(vkey(ORIGIN)),
        attestation_key: Some(key().public_hex()),
        ..Default::default()
    };
    let refused = |what: &str, err: ConfigError| {
        let m = err.to_string();
        assert!(
            matches!(&err, ConfigError::Write { path, .. } if *path == user_file(&r)),
            "{what}: {err:?}"
        );
        assert!(
            m.starts_with(&format!("writing {}", user_file(&r).display())),
            "{what}: {m}"
        );
        assert!(!m.contains("reading"), "{what}: a write is not a read: {m}");
        assert_eq!(err.exit_code(), 5, "{what}");
        assert_eq!(
            std::fs::read_to_string(user_file(&r)).unwrap(),
            original,
            "{what}"
        );
    };
    refused("add", add_source(&e, &new).unwrap_err());
    refused("remove", remove_source(&e, "mine").unwrap_err());
    assert!(blocked.join("in-the-way").is_dir());
}

/// The process's own environment is read once, into an `Env`: an empty variable counts as unset,
/// as a shell's `FOO=` usually means, and one that is not Unicode is refused, naming it, as is a
/// working directory that cannot be read. Each case runs in a child process of this test binary
/// given the environment it means, so that this process's own environment and working directory
/// are neither read nor changed.
#[cfg(unix)]
#[test]
fn the_process_environment_is_read_with_empty_as_unset_and_not_unicode_refused() {
    use std::os::unix::ffi::OsStrExt as _;
    const CHILD: &str = "TRIGON_ATTEST_TEST_CHILD";
    const NAME: &str =
        "the_process_environment_is_read_with_empty_as_unset_and_not_unicode_refused";
    const READ: &[&str] = &[
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "TRIGON_EVIDENCE_CONFIG",
        "TRIGON_PUBLISH_REPO",
        "TRIGON_EVIDENCE_REPO",
        "TRIGON_EVIDENCE_LOG_KEY",
        "TRIGON_EVIDENCE_ATTESTATION_KEY",
        "TRIGON_EVIDENCE_CHECKPOINT",
        "TRIGON_EVIDENCE_TOFU",
        "TRIGON_EVIDENCE_CACHE",
        "TRIGON_EVIDENCE_STATE",
    ];
    if let Some(case) = std::env::var_os(CHILD) {
        match case.to_str() {
            Some("empty") => {
                let e = Env::from_process().unwrap();
                assert_eq!(e.publish_repo, None);
                assert_eq!(e.evidence_cache, None);
                assert_eq!(e.home, None);
                assert!(e.cwd.is_absolute());
            }
            Some("not-unicode") => {
                let m = Env::from_process().unwrap_err().to_string();
                assert_eq!(m, "TRIGON_PUBLISH_REPO is not valid Unicode");
            }
            Some("cwd-gone") => {
                // This child's own working directory, removed from under it.
                let gone = std::env::temp_dir().join(format!(
                    "trigon-evidence-config-{}-cwd-gone",
                    std::process::id()
                ));
                std::fs::create_dir_all(&gone).unwrap();
                std::env::set_current_dir(&gone).unwrap();
                std::fs::remove_dir(&gone).unwrap();
                let e = Env::from_process().unwrap_err();
                assert!(
                    matches!(
                        &e,
                        ConfigError::Env { var: "the working directory", message }
                            if message.starts_with("cannot be read (")
                    ),
                    "{e:?}"
                );
                assert_eq!(e.exit_code(), 5);
            }
            other => panic!("no such case: {other:?}"),
        }
        return;
    }
    for (case, value) in [
        ("empty", std::ffi::OsStr::new("")),
        ("not-unicode", std::ffi::OsStr::from_bytes(b"repo-\xff")),
        ("cwd-gone", std::ffi::OsStr::new("")),
    ] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child.args([NAME, "--exact", "--test-threads=1"]);
        for var in READ {
            child.env_remove(var);
        }
        let out = child
            .env(CHILD, case)
            .env("HOME", "")
            .env("TRIGON_EVIDENCE_CACHE", "")
            .env("TRIGON_PUBLISH_REPO", value)
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{case}: {said}");
        assert!(
            said.contains("1 passed"),
            "{case}: the child ran the case: {said}"
        );
    }
}
