//! What `trigon verify` tells a person, and the small commands around it: the member list and its
//! cut, the lines that must reach a human whatever the verdict, the exit code a closed pipe gets,
//! a format or profile that does not exist, the themes, the public half of a key, and the
//! strategy listings.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "trigon-verify-report-{}-{what}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = ::tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, *name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn gzip(bytes: &[u8], level: flate2::Compression) -> Vec<u8> {
    use std::io::Write as _;
    let mut gz = Vec::new();
    let mut e = flate2::write::GzEncoder::new(&mut gz, level);
    e.write_all(bytes).unwrap();
    e.finish().unwrap();
    gz
}

fn write_tgz(path: &Path, members: &[(&str, &[u8])]) -> PathBuf {
    std::fs::write(path, gzip(&tar(members), flate2::Compression::default())).unwrap();
    path.to_path_buf()
}

/// `trigon <args>` with colour off, as a pipe reads it.
fn trigon(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(bin())
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn verify(a: &Path, b: &Path, extra: &[&str]) -> (Option<i32>, String) {
    let mut args: Vec<&std::ffi::OsStr> = vec!["verify".as_ref(), a.as_os_str(), b.as_os_str()];
    args.extend(extra.iter().map(std::ffi::OsStr::new));
    let out = trigon(&args);
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The member rows of a text report: the lines under the counts that name a member.
fn member_rows(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| {
            let t = l.trim_start();
            ["differs ", "onlyupstream ", "onlyrebuild "]
                .iter()
                .any(|s| t.starts_with(s))
        })
        .collect()
}

/// Twelve members that differ: the report names ten and says how many more there are and how to
/// see them; `--explain` names every one and says nothing is left out.
#[test]
fn a_long_divergence_names_ten_members_and_explain_names_them_all() {
    let d = dir("cut");
    let names: Vec<String> = (0..12).map(|i| format!("package/m{i:02}.js")).collect();
    let up: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"one"[..])).collect();
    let rb: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"two"[..])).collect();
    let a = write_tgz(&d.join("a.tgz"), &up);
    let b = write_tgz(&d.join("b.tgz"), &rb);

    let (code, text) = verify(&a, &b, &[]);
    assert_eq!(code, Some(1), "{text}");
    assert_eq!(member_rows(&text).len(), 10, "{text}");
    assert!(text.contains("… 2 more, pass --explain"), "{text}");

    let (code, text) = verify(&a, &b, &["--explain"]);
    assert_eq!(code, Some(1), "{text}");
    let rows = member_rows(&text);
    assert_eq!(rows.len(), 12, "{text}");
    for n in &names {
        assert!(rows.iter().any(|r| r.ends_with(n.as_str())), "{n}:\n{text}");
    }
    assert!(!text.contains("more, pass --explain"), "{text}");
}

/// A member on one side only is named as such, with the counts that say how many of each there
/// are.
#[test]
fn a_member_on_one_side_only_is_named_by_the_side_it_is_on() {
    let d = dir("sides");
    let a = write_tgz(
        &d.join("a.tgz"),
        &[("package/index.js", b"same"), ("package/lost.js", b"a")],
    );
    let b = write_tgz(
        &d.join("b.tgz"),
        &[("package/index.js", b"same"), ("package/new.js", b"b")],
    );
    let (code, text) = verify(&a, &b, &[]);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("1 identical, 0 differ, 1 upstream-only, 1 rebuild-only"),
        "{text}"
    );
    let rows = member_rows(&text);
    assert!(
        rows.iter()
            .any(|r| r.trim_start().starts_with("onlyupstream") && r.ends_with("package/lost.js")),
        "{text}"
    );
    assert!(
        rows.iter()
            .any(|r| r.trim_start().starts_with("onlyrebuild") && r.ends_with("package/new.js")),
        "{text}"
    );
}

/// An executable member that differs is never benign, and the report says so outright rather
/// than leaving it one row among the others.
#[test]
fn a_differing_executable_member_is_called_never_benign() {
    let d = dir("executable");
    let a = write_tgz(&d.join("a.tgz"), &[("package/native.so", b"\x7fELF one")]);
    let b = write_tgz(&d.join("b.tgz"), &[("package/native.so", b"\x7fELF two")]);
    let (code, text) = verify(&a, &b, &[]);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("1 executable member(s) differ, which is never benign"),
        "{text}"
    );

    // And a differing member that is not executable does not get the sentence.
    let a = write_tgz(&d.join("c.tgz"), &[("package/readme.md", b"one")]);
    let b = write_tgz(&d.join("e.tgz"), &[("package/readme.md", b"two")]);
    let (_, text) = verify(&a, &b, &[]);
    assert!(!text.contains("never benign"), "{text}");
}

/// The same tar compressed two ways: the container is bit-identical and only the gzip framing
/// differs, which is a different finding from containers that differ too, and the report says
/// which of the two it is.
#[test]
fn the_same_container_in_other_framing_is_told_apart_from_a_different_container() {
    let d = dir("framing");
    let inner = tar(&[("package/index.js", b"module.exports = 1;\n")]);
    let a = d.join("a.tgz");
    let b = d.join("b.tgz");
    std::fs::write(&a, gzip(&inner, flate2::Compression::best())).unwrap();
    std::fs::write(&b, gzip(&inner, flate2::Compression::none())).unwrap();
    assert_ne!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());

    let (code, text) = verify(&a, &b, &[]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("same container, different outer framing"),
        "{text}"
    );
    assert!(!text.contains("containers differ as well"), "{text}");

    // Another tar under other framing: the containers differ too, and the report says that and
    // not the other.
    let other = tar(&[("package/index.js", b"module.exports = 2;\n")]);
    let c = d.join("c.tgz");
    std::fs::write(&c, gzip(&other, flate2::Compression::none())).unwrap();
    let (code, text) = verify(&a, &c, &[]);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("containers differ as well as the framing"),
        "{text}"
    );
    assert!(!text.contains("same container"), "{text}");

    // Identical bytes are exact, and there is nothing about framing to say.
    let (code, text) = verify(&a, &a, &[]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("exact"), "{text}");
    assert!(!text.contains("framing"), "{text}");
}

/// A reader that goes away is not a failure of the comparison: the process exits as a shell
/// reports `yes | head` — 141, 128 + SIGPIPE — and never panics, which would be indistinguishable
/// from a real failure in a pipeline that reads the exit code.
#[test]
fn a_reader_that_goes_away_gets_the_exit_a_shell_expects_and_no_panic() {
    let d = dir("pipe");
    // Far more than any pipe buffer holds, so the writer is still writing when the reader closes.
    let names: Vec<String> = (0..6000)
        .map(|i| format!("package/{}{i:05}.js", "m".repeat(60)))
        .collect();
    let up: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"one"[..])).collect();
    let rb: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"two"[..])).collect();
    let a = write_tgz(&d.join("a.tgz"), &up);
    let b = write_tgz(&d.join("b.tgz"), &rb);

    let mut child = Command::new(bin())
        .env("NO_COLOR", "1")
        .args(["verify", "--explain"])
        .arg(&a)
        .arg(&b)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = [0u8; 16];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut first)
        .unwrap();
    drop(child.stdout.take());
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(status.code(), Some(141), "{err}");
}

/// A format named on the command line is parsed by the one parser, and one that does not exist is
/// refused naming what was typed, before anything is compared.
#[test]
fn a_named_format_that_does_not_exist_is_refused() {
    let d = dir("format");
    let a = write_tgz(&d.join("a.tgz"), &[("package/index.js", b"x")]);
    let (code, text) = verify(&a, &a, &["--format", "tarball-ish"]);
    assert_ne!(code, Some(0), "{text}");
    assert!(text.contains("tarball-ish"), "{text}");
    let (code, text) = verify(&a, &a, &["--format", "tgz"]);
    assert_eq!(code, Some(0), "an alias the parser knows: {text}");
}

/// However verbose, and in either log format, logs go to stderr: stdout is the result, and a
/// script piping `--output json` to `jq` reads the same bytes at every verbosity.
#[test]
fn stdout_is_the_result_at_every_verbosity() {
    let d = dir("verbosity");
    let a = write_tgz(&d.join("a.tgz"), &[("package/index.js", b"x")]);
    let run = |flags: &[&str]| -> Vec<u8> {
        let out = Command::new(bin())
            .env("NO_COLOR", "1")
            .env_remove("RUST_LOG")
            .args(flags)
            .arg("verify")
            .arg(&a)
            .arg(&a)
            .args(["--output", "json"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{flags:?}");
        out.stdout
    };
    let quiet = run(&[]);
    serde_json::from_slice::<serde_json::Value>(&quiet).expect("json");
    for flags in [
        &["-v"][..],
        &["-vv"],
        &["-vvv"],
        &["--log-json"],
        &["-vvv", "--log-json"],
    ] {
        assert_eq!(
            run(flags),
            quiet,
            "{flags:?} put something on stdout that is not the result"
        );
    }
}

#[test]
fn listing_a_profile_that_does_not_exist_names_the_ones_that_do() {
    let out = trigon(&[
        "stabilizers".as_ref(),
        "--profile".as_ref(),
        "tarr".as_ref(),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown profile `tarr`"), "{err}");
    assert!(err.contains("tar-gzip") && err.contains("wheel"), "{err}");
}

/// Each `--theme` is the palette it names, and `NO_COLOR` still overrides every one of them.
#[test]
fn each_theme_colours_or_not_as_it_says_and_no_color_wins() {
    let run = |theme: &str, no_color: bool| -> String {
        let mut c = Command::new(bin());
        c.args(["--theme", theme, "stabilizers", "--profile", "gem"])
            .env_remove("CLICOLOR_FORCE");
        if no_color {
            c.env("NO_COLOR", "1");
        } else {
            c.env_remove("NO_COLOR");
        }
        let out = c.output().unwrap();
        assert!(out.status.success(), "{theme}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    for theme in ["textcolor", "neon", "bbs"] {
        assert!(
            run(theme, false).contains('\x1b'),
            "{theme} is not coloured"
        );
        assert!(
            !run(theme, true).contains('\x1b'),
            "NO_COLOR lost to {theme}"
        );
    }
    assert!(!run("textnocolor", false).contains('\x1b'));
    // Piped, so `auto` does not colour.
    assert!(!run("auto", false).contains('\x1b'));
    // Every theme says the same thing; only the paint differs.
    let plain = run("textnocolor", false);
    assert_eq!(run("textcolor", true), plain);
}

/// `public-key` gives back the key `keygen` printed and wrote: the hex by default, the PEM with
/// `--pem`, byte for byte what `--public-out` holds.
#[test]
fn the_public_half_of_a_key_reads_back_as_keygen_gave_it() {
    let d = dir("public-key");
    // A directory that does not exist yet: keygen makes it rather than failing on it.
    let key = d.join("keys/nested/signing.key");
    let pem = d.join("public.pem");
    let out = trigon(&[
        "keygen".as_ref(),
        "--out".as_ref(),
        key.as_os_str(),
        "--public-out".as_ref(),
        pem.as_os_str(),
    ]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = text
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("public key "))
        .expect("keygen prints the public key")
        .trim()
        .to_string();

    let out = trigon(&["public-key".as_ref(), key.as_os_str()]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{printed}\n"));

    let out = trigon(&["public-key".as_ref(), key.as_os_str(), "--pem".as_ref()]);
    assert!(out.status.success());
    assert_eq!(out.stdout, std::fs::read(&pem).unwrap());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("-----BEGIN PUBLIC KEY-----"));

    // The same key as its 32 raw bytes, and as hex pasted out of a terminal with the whitespace
    // around it, reads back as the same key.
    let hex = std::fs::read_to_string(&key).unwrap();
    let seed: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(seed.len(), 32);
    let raw_key = d.join("raw.key");
    std::fs::write(&raw_key, &seed).unwrap();
    let pasted = d.join("pasted.key");
    std::fs::write(&pasted, format!("  \n{}\r\n\n", hex.trim())).unwrap();
    for k in [&raw_key, &pasted] {
        let out = trigon(&["public-key".as_ref(), k.as_os_str()]);
        assert!(
            out.status.success(),
            "{}: {}",
            k.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{printed}\n"),
            "{}",
            k.display()
        );
    }
}

/// `strategy tools` lists every registered tool with its parameters, the required ones marked, and
/// says how many there are.
#[test]
fn strategy_tools_lists_every_tool_and_marks_required_parameters() {
    let out = trigon(&["strategy".as_ref(), "tools".as_ref()]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let rows: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("  ") && !l.trim().is_empty())
        .filter(|l| !l.contains("tools, * marks"))
        .collect();
    let count = text
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_suffix(" tools, * marks a required parameter")
        })
        .unwrap_or_else(|| panic!("no count line:\n{text}"));
    assert_eq!(count.parse::<usize>().unwrap(), rows.len(), "{text}");
    assert!(
        rows.iter()
            .any(|r| r.trim_start().starts_with("git-checkout")),
        "{text}"
    );
    // `npm/build/pack` requires `npm_version` and not `registry_time`, and its row says which.
    let pack = rows
        .iter()
        .find(|r| r.trim_start().starts_with("npm/build/pack "))
        .unwrap_or_else(|| panic!("no npm/build/pack row:\n{text}"));
    let params: Vec<&str> = pack
        .trim_start()
        .strip_prefix("npm/build/pack")
        .unwrap()
        .split(',')
        .map(str::trim)
        .collect();
    assert!(params.contains(&"npm_version*"), "{pack}");
    assert!(params.contains(&"registry_time"), "{pack}");
}

/// `strategy render --output json` carries the digest, the instructions and the custom
/// stabilizers, and the digest is the one the text form prints: the script a build runs and the
/// one `render` shows are one rendering.
#[test]
fn strategy_render_as_json_is_the_same_rendering_as_the_text() {
    let d = dir("render-json");
    let file = d.join("strategy.yaml");
    std::fs::write(
        &file,
        "schema: 1\nkind: flow\nlocation:\n  repo: https://github.com/owner/demo\n  ref: \
         ff8e7ba8b4122829cf66125ca8445cac7f073bce\nsrc:\n- uses: git-checkout\nbuild:\n- runs: npm \
         pack\noutput_path: '*.tgz'\n",
    )
    .unwrap();
    let out = trigon(&[
        "strategy".as_ref(),
        "render".as_ref(),
        file.as_os_str(),
        "--output".as_ref(),
        "json".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let digest = doc["strategy_digest"].as_str().unwrap();
    assert_eq!(digest.len(), 64, "{doc}");
    assert_eq!(doc["custom_stabilizers"], serde_json::json!([]), "{doc}");
    assert_eq!(
        doc["instructions"]["location"]["repo"],
        "https://github.com/owner/demo"
    );
    assert!(
        doc["instructions"]["build"]
            .as_str()
            .is_some_and(|b| b.contains("npm pack")),
        "{doc}"
    );

    let out = trigon(&["strategy".as_ref(), "render".as_ref(), file.as_os_str()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.lines().next() == Some(&format!("strategy {}", &digest[..16])),
        "{text}"
    );
}
