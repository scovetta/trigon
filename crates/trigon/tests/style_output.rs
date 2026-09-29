//! How the human-readable output is painted and folded, as a reader's environment asks.
//!
//! `src/style.rs`'s three rules: colour follows the terminal, `NO_COLOR` wins, and colour is an
//! accent and never the message. Each case runs the binary with the variables it needs set on the
//! child and every other one removed, so the host's own terminal settings play no part.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-style-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Every variable that decides colour or width.
const TERMINAL_ENV: &[&str] = &["NO_COLOR", "CLICOLOR_FORCE", "TERM", "COLUMNS"];

fn write_tgz(path: &Path, body: &[u8], mtime: u64) -> PathBuf {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
    h.set_cksum();
    b.append_data(&mut h, "package/index.js", body).unwrap();
    let mut gz = Vec::new();
    {
        use std::io::Write as _;
        let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        e.write_all(&b.into_inner().unwrap()).unwrap();
        e.finish().unwrap();
    }
    std::fs::write(path, gz).unwrap();
    path.to_path_buf()
}

/// Stdout of `trigon <args>` with exactly `env` for the terminal variables.
fn run(args: &[&std::ffi::OsStr], env: &[(&str, &str)]) -> String {
    let mut c = Command::new(bin());
    for k in TERMINAL_ENV {
        c.env_remove(k);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A normalized pair and a divergent pair to verify.
struct Pairs {
    same: (PathBuf, PathBuf),
    differs: (PathBuf, PathBuf),
}

fn pairs(d: &Path) -> Pairs {
    Pairs {
        same: (
            write_tgz(&d.join("a.tgz"), b"same\n", 1_700_000_000),
            write_tgz(&d.join("b.tgz"), b"same\n", 1_500_000_000),
        ),
        differs: (
            write_tgz(&d.join("c.tgz"), b"upstream\n", 1_700_000_000),
            write_tgz(&d.join("e.tgz"), b"rebuild\n", 1_700_000_000),
        ),
    }
}

fn verify(theme: &str, pair: &(PathBuf, PathBuf), env: &[(&str, &str)]) -> String {
    run(
        &[
            "--theme".as_ref(),
            theme.as_ref(),
            "verify".as_ref(),
            pair.0.as_os_str(),
            pair.1.as_os_str(),
        ],
        env,
    )
}

/// The first line: the verdict.
fn verdict_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

/// Each theme paints the verdict line its own way, and says the same thing in every one.
#[test]
fn each_theme_paints_the_verdict_its_own_way() {
    let d = dir("verdict");
    let p = pairs(&d);

    assert_eq!(
        verdict_line(&verify("textcolor", &p.same, &[])),
        "\x1b[1;32m✔ normalized\x1b[0m"
    );
    assert_eq!(
        verdict_line(&verify("textcolor", &p.differs, &[])),
        "\x1b[1;31m✖ divergent\x1b[0m"
    );
    // Neon: the bright set, one step up from the base.
    assert_eq!(
        verdict_line(&verify("neon", &p.same, &[])),
        "\x1b[1;92m✔ normalized\x1b[0m"
    );
    assert_eq!(
        verdict_line(&verify("neon", &p.differs, &[])),
        "\x1b[1;91m✖ divergent\x1b[0m"
    );
    // BBS: a reverse-video badge in the outcome's colour, the word in capitals.
    assert_eq!(
        verdict_line(&verify("bbs", &p.same, &[])),
        "\x1b[1;30;42m▐ ✔ NORMALIZED ▌\x1b[0m"
    );
    assert_eq!(
        verdict_line(&verify("bbs", &p.differs, &[])),
        "\x1b[1;30;41m▐ ✖ DIVERGENT ▌\x1b[0m"
    );
    // And with colour off, every theme still carries the mark and the word.
    for theme in ["textcolor", "neon"] {
        assert_eq!(
            verdict_line(&verify(theme, &p.same, &[("NO_COLOR", "1")])),
            "✔ normalized",
            "{theme}"
        );
    }
    assert_eq!(
        verdict_line(&verify("bbs", &p.differs, &[("NO_COLOR", "1")])),
        "▐ ✖ DIVERGENT ▌"
    );
}

/// BBS parts its sections with a shaded block before the title, as well as the weight.
#[test]
fn the_bbs_theme_marks_a_heading_with_a_block() {
    let d = dir("heading");
    let lock = d.join("package-lock.json");
    std::fs::write(
        &lock,
        r#"{"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(d.join("store")).unwrap();
    let check = |theme: &str| {
        run(
            &[
                "--theme".as_ref(),
                theme.as_ref(),
                "check".as_ref(),
                lock.as_os_str(),
                "--store".as_ref(),
                d.join("store").as_os_str(),
            ],
            &[],
        )
    };
    let path = lock.display().to_string();
    assert!(
        check("bbs").starts_with(&format!("\x1b[1;95m▓▒ {path}\x1b[0m")),
        "{}",
        check("bbs")
    );
    assert!(
        check("neon").starts_with(&format!("\x1b[1;95m{path}\x1b[0m")),
        "{}",
        check("neon")
    );
    assert!(
        check("textcolor").starts_with(&format!("\x1b[1;97m{path}\x1b[0m")),
        "{}",
        check("textcolor")
    );
}

/// `CLICOLOR_FORCE` turns colour on for a pipe, and only where nothing said otherwise: not when it
/// is `0` or empty, not over an explicit plain theme, and never over `NO_COLOR`. A terminal that
/// calls itself dumb is not something saying otherwise: `TERM` is set for every command a shell
/// runs, and the force is set for this one, so the force wins, as the `CLICOLOR` convention has it.
#[test]
fn clicolor_force_colours_a_pipe_unless_something_said_plain() {
    let d = dir("force");
    let p = pairs(&d);
    let coloured = |env: &[(&str, &str)], theme: &str| verify(theme, &p.same, env).contains('\x1b');

    assert!(!coloured(&[], "auto"), "a pipe is plain by default");
    assert!(coloured(&[("CLICOLOR_FORCE", "1")], "auto"));
    assert!(!coloured(&[("CLICOLOR_FORCE", "0")], "auto"));
    assert!(!coloured(&[("CLICOLOR_FORCE", "")], "auto"));
    assert!(
        !coloured(&[("CLICOLOR_FORCE", "1")], "textnocolor"),
        "the reader named a plain theme"
    );
    assert!(
        !coloured(&[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")], "auto"),
        "NO_COLOR lost to CLICOLOR_FORCE"
    );
    assert!(!coloured(&[("TERM", "dumb")], "auto"));
    assert!(
        coloured(&[("CLICOLOR_FORCE", "1"), ("TERM", "dumb")], "auto"),
        "a dumb TERM beat CLICOLOR_FORCE"
    );
    assert!(
        !coloured(
            &[("CLICOLOR_FORCE", "1"), ("TERM", "dumb"), ("NO_COLOR", "1")],
            "auto"
        ),
        "NO_COLOR lost to CLICOLOR_FORCE with a dumb TERM"
    );
    assert!(!coloured(&[("CLICOLOR_FORCE", "0"), ("TERM", "dumb")], "auto"));
    // `NO_COLOR=0` is still `NO_COLOR` set; only an empty value is not.
    assert!(!coloured(&[("NO_COLOR", "0")], "textcolor"));
    assert!(coloured(&[("NO_COLOR", "")], "textcolor"));
}

/// An explicit `COLUMNS` folds long prose to that width even in a pipe, each continuation hung
/// under its column; a width too narrow to mean anything, or not a number, is ignored, and a pipe
/// with none leaves the prose on one line.
#[test]
fn columns_folds_long_prose_under_its_column_even_in_a_pipe() {
    let d = dir("columns");
    let lock = d.join("package-lock.json");
    std::fs::write(
        &lock,
        r#"{"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(d.join("store")).unwrap();
    let check = |env: &[(&str, &str)]| {
        run(
            &[
                "check".as_ref(),
                lock.as_os_str(),
                "--store".as_ref(),
                d.join("store").as_os_str(),
            ],
            env,
        )
    };
    // The footer: one sentence of prose, placed two columns in.
    let footer = |text: &str| -> Vec<String> {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines
            .iter()
            .position(|l| l.contains("`never checked` is a count"))
            .unwrap_or_else(|| panic!("{text}"));
        lines[start..]
            .iter()
            .take_while(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect()
    };

    let unfolded = footer(&check(&[]));
    assert_eq!(unfolded.len(), 1, "{unfolded:#?}");
    for ignored in ["19", "wide", ""] {
        assert_eq!(
            footer(&check(&[("COLUMNS", ignored)])),
            unfolded,
            "COLUMNS={ignored}"
        );
    }

    let folded = footer(&check(&[("COLUMNS", "60")]));
    assert!(folded.len() > 1, "{folded:#?}");
    for l in &folded {
        assert!(l.chars().count() <= 60, "over the width: {l:?}");
        assert!(l.starts_with("  ") && !l[2..].starts_with(' '), "{l:?}");
    }
    // Nothing lost, nothing added: the same words in the same order.
    let words = |ls: &[String]| {
        ls.iter()
            .flat_map(|l| l.split_whitespace().map(str::to_string))
            .collect::<Vec<_>>()
    };
    assert_eq!(words(&folded), words(&unfolded));
}
