//! The commands that put work on a queue and take it off: `grant`, `enqueue` and `worker`, against
//! a SQLite queue in a directory of the test's own, and `serve`, which with `worker` reads the
//! publication gate's settings before it touches anything.
//!
//! Nothing here builds: the worker is run `--once` against a queue with nothing on it, which is
//! the check its `--once` exists for, and every refusal happens before a queue is opened or a
//! socket is bound.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

/// A directory with `home/` under it.
fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-queue-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("home")).unwrap();
    d
}

fn url(d: &Path) -> String {
    format!("sqlite://{}?mode=rwc", d.join("q.db").display())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// `trigon <args>` with `d/home` as HOME and no `TRIGON_*` from this process, so the evidence
/// configuration is the one the test writes or none.
fn command(d: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(bin());
    c.current_dir(d)
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"))
        .env("XDG_STATE_HOME", d.join("home/.local/state"))
        .env("TMPDIR", d)
        .env("NO_COLOR", "1");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.args(args);
    c
}

fn trigon(d: &Path, args: &[&str]) -> Output {
    command(d, args).output().unwrap()
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

/// The value of a `label   value` line.
fn field<'a>(text: &'a str, label: &str) -> Vec<&'a str> {
    text.lines()
        .filter_map(|l| l.trim_start().strip_prefix(label))
        .filter(|rest| rest.starts_with(' '))
        .map(str::trim)
        .collect()
}

/// The bytes of the queue's database and its journal, where a stolen copy would be read from.
fn database_bytes(d: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for e in std::fs::read_dir(d).unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with("q.db") {
            all.extend(std::fs::read(e.path()).unwrap());
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn principal(url: &str, token: &str) -> Option<trigon_store::queue::Principal> {
    rt().block_on(async {
        let q = trigon_store::Queue::open(url).await.unwrap();
        q.principal_for(token).await.unwrap()
    })
}

// ---------------------------------------------------------------------------------------------
// grant
// ---------------------------------------------------------------------------------------------

/// The token is printed once and never stored: a stolen database yields its digest and no
/// credential, and the token it printed is the one that resolves to the principal granted.
#[test]
fn grant_prints_a_token_that_works_and_stores_only_its_digest() {
    let d = dir("grant");
    let text = ok(&trigon(
        &d,
        &[
            "grant",
            &url(&d),
            "alice",
            "--name",
            "Alice Example",
            "--scopes",
            "request, review",
            "--daily-quota",
            "5",
        ],
    ));
    let token = field(&text, "token")
        .first()
        .copied()
        .unwrap_or_else(|| panic!("no token:\n{text}"))
        .to_string();
    assert_eq!(token.len(), 64, "32 bytes of randomness, as hex: {token}");
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit()), "{token}");
    assert_eq!(
        field(&text, "principal"),
        ["alice (request, review)"],
        "{text}"
    );
    assert_eq!(field(&text, "quota"), ["5 rebuild(s) a day"], "{text}");
    assert!(text.contains("Shown once"), "{text}");

    let db = database_bytes(&d);
    assert!(
        !contains(&db, token.as_bytes()),
        "the token itself is in the database"
    );
    assert!(
        contains(&db, sha256_hex(&token).as_bytes()),
        "the token's digest is not what was stored"
    );

    let p = principal(&url(&d), &token).expect("the printed token resolves");
    assert_eq!(p.id, "alice");
    assert_eq!(p.name, "Alice Example");
    assert_eq!(p.scopes, ["request", "review"]);
    assert_eq!(p.daily_quota, 5);
    assert!(principal(&url(&d), &"0".repeat(64)).is_none());
}

/// Granting the same id again rotates its scopes and quota and adds a token, rather than
/// replacing one: revoking is a separate decision from issuing.
#[test]
fn granting_again_adds_a_token_and_keeps_the_first() {
    let d = dir("regrant");
    let first = ok(&trigon(&d, &["grant", &url(&d), "bob"]));
    let first = field(&first, "token")[0].to_string();
    let second = ok(&trigon(
        &d,
        &[
            "grant",
            &url(&d),
            "bob",
            "--scopes",
            "operate",
            "--daily-quota",
            "1",
        ],
    ));
    assert!(second.contains("bob (operate)"), "{second}");
    let second = field(&second, "token")[0].to_string();
    assert_ne!(first, second);
    for token in [&first, &second] {
        let p = principal(&url(&d), token).expect("both tokens resolve");
        assert_eq!(p.id, "bob");
        // The name defaults to the id, and the scopes and quota are the latest grant's.
        assert_eq!(p.name, "bob");
        assert_eq!(p.scopes, ["operate"]);
        assert_eq!(p.daily_quota, 1);
    }
}

/// A scope that does not exist is refused, naming the ones that do, and no credential is issued.
#[test]
fn grant_refuses_a_scope_that_does_not_exist() {
    let d = dir("scope");
    let out = trigon(
        &d,
        &["grant", &url(&d), "carol", "--scopes", "request,admin"],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unknown scope `admin`; known: request, review, operate"),
        "{err}"
    );
    assert!(field(&String::from_utf8_lossy(&out.stdout), "token").is_empty());
}

// ---------------------------------------------------------------------------------------------
// enqueue
// ---------------------------------------------------------------------------------------------

fn depth(url: &str) -> Vec<(String, i64)> {
    rt().block_on(async {
        let q = trigon_store::Queue::open(url).await.unwrap();
        q.depth().await.unwrap()
    })
}

fn job_for(url: &str, target: &str) -> Option<(i64, String)> {
    rt().block_on(async {
        let q = trigon_store::Queue::open(url).await.unwrap();
        q.job_for(target).await.unwrap()
    })
}

/// Each target is offered and each package queued once: running the same list again adds
/// nothing, and the count says targets offered rather than jobs created.
#[test]
fn enqueue_queues_each_package_once_however_often_it_is_offered() {
    let d = dir("enqueue");
    let text = ok(&trigon(
        &d,
        &[
            "enqueue",
            &url(&d),
            "pkg:npm/left-pad@1.3.0",
            "pkg:npm/once@1.4.0",
            "--migrate",
        ],
    ));
    assert!(
        text.contains("offered 2 target(s) to the bulk queue"),
        "{text}"
    );
    assert_eq!(depth(&url(&d)), [("ready".to_string(), 2)]);

    let text = ok(&trigon(
        &d,
        &[
            "enqueue",
            &url(&d),
            "pkg:npm/left-pad@1.3.0",
            "pkg:npm/once@1.4.0",
            "--tier",
            "interactive",
        ],
    ));
    assert!(
        text.contains("offered 2 target(s) to the interactive queue"),
        "{text}"
    );
    assert_eq!(
        depth(&url(&d)),
        [("ready".to_string(), 2)],
        "a package already queued was queued again"
    );
    assert_eq!(field(&text, "ready"), ["2"], "{text}");
}

/// `-` reads the targets from stdin, one per line, trimmed, with comments and blank lines
/// skipped, as a targets file is read.
#[test]
fn enqueue_reads_targets_from_stdin() {
    let d = dir("stdin");
    let mut child = command(
        &d,
        &[
            "enqueue",
            &url(&d),
            "-",
            "--migrate",
            "--tier",
            "regression",
        ],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"# the corpus\n\n  pkg:npm/left-pad@1.3.0  \npkg:npm/once@1.4.0\n#pkg:npm/no@1\n",
        )
        .unwrap();
    let text = ok(&child.wait_with_output().unwrap());
    assert!(
        text.contains("offered 2 target(s) to the regression queue"),
        "{text}"
    );
    assert!(job_for(&url(&d), "pkg:npm/left-pad@1.3.0").is_some());
    assert!(job_for(&url(&d), "pkg:npm/once@1.4.0").is_some());
    assert!(job_for(&url(&d), "pkg:npm/no@1").is_none());
}

#[test]
fn enqueue_refuses_a_tier_that_does_not_exist() {
    let d = dir("tier");
    let out = trigon(
        &d,
        &["enqueue", &url(&d), "pkg:npm/a@1", "--tier", "urgent"],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unknown tier `urgent`; known: interactive, regression, bulk"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------------------------
// worker and serve
// ---------------------------------------------------------------------------------------------

fn worker(d: &Path, extra: &[&str]) -> Command {
    let work = d.join("work");
    let store = d.join("store");
    let mut args = vec![
        "worker",
        "--image",
        "docker.io/library/debian@sha256:aa",
        "--work",
        work.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--migrate",
        "--once",
    ];
    args.extend_from_slice(extra);
    let url = url(d);
    let mut c = command(d, &args);
    c.arg(url);
    c
}

fn configure(d: &Path, text: &str) -> PathBuf {
    let path = d.join("home/.config/trigon/evidence.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    path
}

/// A worker names itself by host and process unless named, says at start whether and where it
/// confirms a verdict — which is what a fleet of one machine needs to be told — and `--once` on an
/// empty queue handles nothing and stops.
#[test]
fn a_worker_says_who_it_is_and_how_it_confirms_before_it_takes_anything() {
    let d = dir("worker");
    let out = worker(&d, &[])
        .env("HOSTNAME", "builder-7")
        .output()
        .unwrap();
    let text = ok(&out);
    assert!(text.contains("worker builder-7-"), "{text}");
    assert_eq!(
        field(&text, "building"),
        ["docker.io/library/debian@sha256:aa at egress mirror-only"]
    );
    assert_eq!(
        field(&text, "confirming"),
        ["each verdict, on a machine other than the one that reached it"],
        "{text}"
    );
    assert!(text.contains("handled 0 job(s)"), "{text}");

    // Named, it is that name; the gate's setting in evidence.toml decides where it confirms.
    configure(&d, "[publish]\nsame_host_confirmation = true\n");
    let text = ok(&worker(&d, &["--name", "night-shift"]).output().unwrap());
    assert!(text.contains("worker night-shift on sqlite://"), "{text}");
    assert_eq!(
        field(&text, "confirming"),
        ["each verdict, on any machine, cold (same_host_confirmation is on)"],
        "{text}"
    );

    let text = ok(&worker(&d, &["--no-confirm"]).output().unwrap());
    assert_eq!(
        field(&text, "confirming"),
        ["no second attempts (--no-confirm), so nothing this worker does can publish"],
        "{text}"
    );
}

/// The class is a capability: a worker asked to be one this build has no work for is refused, by
/// the name it was given, rather than quietly given rebuilds to run.
#[test]
fn a_worker_of_a_class_with_no_work_here_is_refused_by_name() {
    let d = dir("class");
    for class in ["infer", "judge"] {
        let out = worker(&d, &["--class", class]).output().unwrap();
        assert!(!out.status.success(), "{class}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains(&format!("a `{class}` worker asked to lease `rebuild` jobs")),
            "{class}: {err}"
        );
    }
    ok(&worker(&d, &["--class", "build"]).output().unwrap());
}

/// `worker` and `serve` read the gate's settings before anything else, and a configuration that
/// cannot be read stops them with exit 5 — the tool failing before it could answer — naming the
/// file, before a queue is opened or an address bound.
#[test]
fn worker_and_serve_refuse_a_configuration_they_cannot_read() {
    let d = dir("bad-config");
    let path = configure(&d, "[publish]\nsame_host_confirmations = true\n");

    let out = worker(&d, &[]).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("same_host_confirmations"), "{err}");
    assert!(err.contains(&path.display().to_string()), "{err}");
    assert!(!d.join("q.db").exists(), "the queue was opened");

    let store = d.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let out = trigon(
        &d,
        &["serve", store.to_str().unwrap(), "--bind", "127.0.0.1:0"],
    );
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("same_host_confirmations"), "{err}");
}

/// `same_host_local_images` set without `same_host_confirmation` changes nothing. A worker, which
/// reads the gate's settings to decide where it confirms, says so as a note on stderr naming the
/// file, and works all the same: a note is not a refusal.
#[test]
fn a_worker_notes_a_setting_that_changes_nothing_and_works_all_the_same() {
    let d = dir("local-images-note");
    let path = configure(&d, "[publish]\nsame_host_local_images = true\n");
    let out = worker(&d, &[]).output().unwrap();
    let text = ok(&out);
    assert!(text.contains("handled 0 job(s)"), "{text}");
    assert_eq!(
        field(&text, "confirming"),
        ["each verdict, on a machine other than the one that reached it"],
        "{text}"
    );
    // As printed, wrapped to the terminal; the words are what is asserted.
    let err = String::from_utf8_lossy(&out.stderr)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for says in [
        "note:",
        "`[publish] same_host_local_images` is set and `same_host_confirmation` is not",
        "changes nothing",
        &*path.display().to_string(),
    ] {
        assert!(err.contains(says), "{says}: {err}");
    }

    // Beside `same_host_confirmation` it is something, and there is nothing to note.
    configure(
        &d,
        "[publish]\nsame_host_confirmation = true\nsame_host_local_images = true\n",
    );
    let out = worker(&d, &[]).output().unwrap();
    ok(&out);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("note:"), "{err}");
}
