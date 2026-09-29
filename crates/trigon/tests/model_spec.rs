//! `--model`, read before anything touches the network.
//!
//! Keys come from the environment and never from the command line, so a key stays out of shell
//! history and process listings. These run the binary with the environment each case needs, set on
//! the child alone, and every spec here fails before the run resolves the package: none reaches a
//! registry or a model.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-model-spec-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Every variable a provider reads, so the host's own keys and endpoints play no part.
const PROVIDER_ENV: &[&str] = &[
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "TRIGON_LLM_API_KEY",
    "OLLAMA_HOST",
];

/// `trigon rebuild` of a package with `--model <spec>`, in a home of its own, with `set` as the
/// only provider variables it sees.
fn rebuild_with(what: &str, spec: &str, set: &[(&str, &str)]) -> Output {
    let d = dir(what);
    let mut c = Command::new(bin());
    c.current_dir(&d)
        .env("HOME", &d)
        .env("XDG_CONFIG_HOME", d.join(".config"))
        .env("NO_COLOR", "1");
    for k in PROVIDER_ENV {
        c.env_remove(k);
    }
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    for (k, v) in set {
        c.env(k, v);
    }
    c.args([
        "rebuild",
        "pkg:npm/left-pad@1.3.0",
        "--image",
        "unused",
        "--work",
    ])
    .arg(d.join("work"))
    .args(["--model", spec]);
    c.output().unwrap()
}

fn refused(out: &Output) -> String {
    assert!(
        !out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A provider whose key is absent from the environment — or present and blank — is refused by the
/// name of the variable, before the run does anything else.
#[test]
fn a_provider_without_its_key_in_the_environment_is_refused_by_the_variables_name() {
    for (spec, var) in [
        ("openai:gpt-4o-2024-08-06", "OPENAI_API_KEY"),
        ("openrouter:qwen/qwen3-coder", "OPENROUTER_API_KEY"),
        ("anthropic:claude-haiku-4-5-20251001", "ANTHROPIC_API_KEY"),
    ] {
        for blank in [None, Some("   ")] {
            let set: Vec<(&str, &str)> = blank.map(|b| (var, b)).into_iter().collect();
            let err = refused(&rebuild_with("nokey", spec, &set));
            assert!(err.contains(&format!("${var} is not set")), "{spec}: {err}");
            assert!(
                err.contains("rather than passed on the command line"),
                "{spec}: {err}"
            );
        }
    }
}

/// A spec that names a provider and no model says a model is needed, and how to name one.
#[test]
fn a_provider_named_without_a_model_says_one_is_needed() {
    for (spec, var) in [
        ("openai:", "OPENAI_API_KEY"),
        ("openrouter:", "OPENROUTER_API_KEY"),
        ("anthropic:", "ANTHROPIC_API_KEY"),
    ] {
        let err = refused(&rebuild_with("nomodel", spec, &[(var, "k-not-a-real-key")]));
        let provider = spec.trim_end_matches(':');
        assert!(
            err.contains(&format!(
                "`--model {provider}:<model>` needs a model, such as `{provider}:<name>`"
            )),
            "{spec}: {err}"
        );
    }
}
