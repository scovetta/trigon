//! `trigon serve --public` is one flag and two controls (`docs/22-management-layer.md` §7): the
//! publication gate, so an anonymous reader sees only what it released, and the evidence class
//! table, so no build log leaves the process. Without the flag the same store is served to an
//! operator, whole.
//!
//! Each server binds `127.0.0.1:0`, serves a fixed snapshot of a store made for the test, is asked
//! over plain HTTP on loopback, and is stopped by the test that started it. The one asked to serve
//! off loopback is given an address that cannot be bound, so nothing listens.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

const LOG: &[u8] = b"npm notice the build log, with GITHUB_TOKEN=ghp_unredacted in it\n";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-serve-public-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("home")).unwrap();
    d
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A run that compared, with its build log in the store: withheld by the gate at `mirror-only`
/// as a single unconfirmed attempt, and published as a void at `open`.
async fn run(store: &Store, id: &str, egress: &str) {
    let log = store.blobs().put(LOG.to_vec()).await.unwrap();
    let mut r = RunRecord::new(
        id,
        "pkg:npm/demo@1.0.0",
        ArtifactRef {
            name: "demo-1.0.0.tgz".into(),
            sha256: trigon_core::Digest::from_bytes([7u8; 32]),
            bytes: 100,
            stored: false,
        },
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
        },
        "2026-09-27T00:00:00Z",
    );
    r.state = RunState::Done;
    r.outcome = Some("exact".into());
    r.non_builtin_stabilizer = Some(false);
    r.cache_key = Some(format!("key-{id}"));
    r.build_log = Some(log);
    store.put_run(&r).await.unwrap();
}

/// A server this test started, stopped when the test is done with it.
struct Server {
    child: Child,
    addr: String,
    banner: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(d: &Path, public: bool) -> Server {
    let mut c = Command::new(bin());
    c.current_dir(d)
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"))
        .env("XDG_STATE_HOME", d.join("home/.local/state"))
        .env("NO_COLOR", "1")
        .arg("serve")
        .arg(d.join("store"))
        .args(["--bind", "127.0.0.1:0", "--refresh-seconds", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if public {
        c.arg("--public");
    }
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    let mut child = c.spawn().unwrap();
    // The line it prints once it is listening names the port it bound.
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut banner = String::new();
    loop {
        let mut line = String::new();
        if lines.read_line(&mut line).unwrap() == 0 {
            let _ = child.kill();
            panic!("the server exited before it listened");
        }
        if line.starts_with("serving ") {
            banner = line;
            break;
        }
        banner.push_str(&line);
    }
    let addr = banner
        .split("http://")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in {banner:?}"))
        .to_string();
    Server {
        child,
        addr,
        banner,
    }
}

/// `GET path`, as status and body.
fn get(server: &Server, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(&server.addr).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        server.addr
    )
    .unwrap();
    let mut response = Vec::new();
    s.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP response: {text:?}"));
    (status, text)
}

/// A response's body, without the headers: two answers are the same answer when these are equal,
/// whatever their `date`.
fn body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map_or_else(|| panic!("no body in {response:?}"), |(_, b)| b)
}

#[test]
fn public_serves_only_what_the_gate_released_and_no_build_log() {
    let d = dir("gate");
    {
        let store = Store::local(&d.join("store")).unwrap();
        let rt = rt();
        rt.block_on(run(&store, "1789006000-11111111", "mirror-only"));
        rt.block_on(run(&store, "1789006100-22222222", "open"));
    }
    let (withheld, void) = ("1789006000-11111111", "1789006100-22222222");
    let log = String::from_utf8_lossy(LOG).trim().to_string();

    // An operator sees the store whole, build logs included.
    let operator = serve(&d, false);
    assert!(
        operator.banner.contains("serving 2 run(s)"),
        "{}",
        operator.banner
    );
    assert!(operator.banner.contains("operator:"), "{}", operator.banner);
    for id in [withheld, void] {
        let (status, body) = get(&operator, &format!("/v1/runs/{id}"));
        assert_eq!(status, 200, "{body}");
        let (status, body) = get(&operator, &format!("/v1/runs/{id}/log"));
        assert_eq!(status, 200, "{body}");
        assert!(body.contains(&log), "{body}");
    }
    drop(operator);

    // The public is shown what the gate released — the void, as a void — and never the unconfirmed
    // run; and a build log leaves the process for neither.
    let public = serve(&d, true);
    assert!(public.banner.contains("public:"), "{}", public.banner);

    // The withheld run is absent, and refused in the same bytes as a run that does not exist, by
    // its record's route and its log's: a 403, or any other difference, would tell a reader
    // holding the artifact that a run of it is being held back.
    let absent = "1789009999-00000000";
    for route in ["", "/log"] {
        let (status, none) = get(&public, &format!("/v1/runs/{absent}{route}"));
        assert_eq!(status, 404, "{none}");
        let (status, answer) = get(&public, &format!("/v1/runs/{withheld}{route}"));
        assert_eq!(status, 404, "{route}: {answer}");
        assert_eq!(body(&answer), body(&none), "{route}");
        assert!(!answer.contains(&log), "{answer}");
        assert!(!answer.contains("ghp_unredacted"), "{answer}");
    }

    // The void is shown, as a void: its row says why, and neither the row nor the record says what
    // its comparison found.
    let (status, answer) = get(&public, &format!("/v1/runs/{void}"));
    assert_eq!(status, 200, "{answer}");
    let shown: serde_json::Value = serde_json::from_str(body(&answer)).unwrap();
    assert_eq!(
        shown["entry"]["publication"],
        serde_json::json!({"state": "void", "because": "open_egress"}),
        "{shown}"
    );
    assert!(shown["entry"]["outcome"].is_null(), "{shown}");
    assert!(shown["record"]["outcome"].is_null(), "{shown}");
    assert!(!body(&answer).contains("exact"), "{shown}");

    // Its build log is refused by class, never served: the run is published, so the refusal may
    // name the class, and a log is still not the public's.
    let (status, answer) = get(&public, &format!("/v1/runs/{void}/log"));
    assert_eq!(status, 403, "{answer}");
    assert!(body(&answer).contains("\"class_gated\""), "{answer}");
    assert!(!answer.contains(&log), "{answer}");
    assert!(!answer.contains("ghp_unredacted"), "{answer}");

    let (status, answer) = get(&public, "/v1/runs");
    assert_eq!(status, 200, "{answer}");
    assert!(!answer.contains(withheld), "{answer}");
}

/// `trigon serve` on a store of its own at `bind`, run until it exits.
fn serve_until_exit(d: &Path, bind: &str, public: bool) -> Output {
    let mut c = Command::new(bin());
    c.current_dir(d)
        .env("HOME", d.join("home"))
        .env("XDG_CONFIG_HOME", d.join("home/.config"))
        .env("XDG_STATE_HOME", d.join("home/.local/state"))
        .env("NO_COLOR", "1")
        .arg("serve")
        .arg(d.join("store"))
        .args(["--bind", bind, "--refresh-seconds", "0"]);
    if public {
        c.arg("--public");
    }
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("TRIGON_") {
            c.env_remove(k);
        }
    }
    c.output().unwrap()
}

/// A store served to an operator anywhere but loopback serves its build logs, unredacted, to
/// whoever can reach it, and the command says so before it binds; with `--public` nothing
/// unredacted is served, and there is nothing to warn about.
#[test]
fn an_operator_server_off_loopback_is_warned_about_before_it_binds() {
    let d = dir("off-loopback");
    // Not an address at all, so the bind is refused without asking a resolver and nothing
    // listens: what is held is what was said before it.
    let out = serve_until_exit(&d, "nowhere", false);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(
        err.contains("warning: binding nowhere without --public"),
        "{err}"
    );
    assert!(
        err.contains("this serves them to anyone who can reach that address"),
        "{err}"
    );
    let warned = err.find("without --public").unwrap();
    let refused = err
        .find("binding nowhere:")
        .unwrap_or_else(|| panic!("the bind was not refused: {err}"));
    assert!(warned < refused, "{err}");

    let out = serve_until_exit(&d, "nowhere", true);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("binding nowhere:"), "{err}");
    assert!(!err.contains("without --public"), "{err}");
}
