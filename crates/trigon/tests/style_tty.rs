//! What the human-readable output does when stdout is a terminal.
//!
//! `src/style.rs` decides colour and width from whether stdout is a terminal and, when it is, how
//! wide the terminal says it is. A pipe can show neither, so each case here hands the binary a
//! pseudo-terminal of a size the test sets and reads back what was written to it. Every variable
//! that decides colour or width is removed from the child unless the case sets it, so the host's
//! own terminal plays no part.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-style-tty-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Every variable that decides colour or width.
const TERMINAL_ENV: &[&str] = &["NO_COLOR", "CLICOLOR_FORCE", "TERM", "COLUMNS"];

/// A pseudo-terminal that says it is `cols` wide: the side the test reads, and the side the child
/// writes to.
///
/// Both ends are opened by path, so both are close-on-exec from the moment they exist: a child
/// another test spawns meanwhile cannot inherit one and hold this terminal open.
fn pty(cols: u16) -> (File, File) {
    let open = |path: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(path)
    };
    let master = open(Path::new("/dev/ptmx")).expect("a pseudo-terminal");
    let fd = master.as_raw_fd();
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: `fd` is the open master, and `name` is a writable buffer of the length given.
    unsafe {
        assert_eq!(libc::grantpt(fd), 0);
        assert_eq!(libc::unlockpt(fd), 0);
        assert_eq!(libc::ptsname_r(fd, name.as_mut_ptr(), name.len()), 0);
    }
    // SAFETY: `ptsname_r` succeeded, so `name` holds a NUL-terminated path.
    let path = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .unwrap()
        .to_owned();
    let ws = libc::winsize {
        ws_row: 24,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `ws` is plain data the call reads, and `fd` is open.
    assert_eq!(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) }, 0);
    let slave = open(Path::new(&path)).unwrap();
    (master, slave)
}

/// A lockfile of one package and an empty store to check it against: enough for `trigon check` to
/// print its footer, one sentence of prose placed two columns in.
fn lock_and_store(d: &Path) -> (PathBuf, PathBuf) {
    let lock = d.join("package-lock.json");
    std::fs::write(
        &lock,
        r#"{"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}"#,
    )
    .unwrap();
    let store = d.join("store");
    std::fs::create_dir_all(&store).unwrap();
    (lock, store)
}

/// What `trigon <theme> check` wrote to a terminal `cols` wide, with exactly `env` for the terminal
/// variables — its line endings put back, since the terminal writes `\n` as `\r\n`.
fn on_terminal(what: &str, cols: u16, theme: &str, env: &[(&str, &str)]) -> String {
    let d = dir(what);
    let (lock, store) = lock_and_store(&d);
    let (mut master, slave) = pty(cols);
    let mut c = Command::new(bin());
    for k in TERMINAL_ENV {
        c.env_remove(k);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    let args: [&OsStr; 6] = [
        "--theme".as_ref(),
        theme.as_ref(),
        "check".as_ref(),
        lock.as_os_str(),
        "--store".as_ref(),
        store.as_os_str(),
    ];
    let mut child = c
        .args(args)
        .stdin(Stdio::null())
        .stdout(slave)
        .stderr(File::create(d.join("stderr")).unwrap())
        .spawn()
        .unwrap();
    // The child holds the terminal now. Ours has to go, or the reading below never ends.
    drop(c);
    let mut out = Vec::new();
    match master.read_to_end(&mut out) {
        Ok(_) => {}
        // Linux says every writer has gone with EIO, once what they wrote has been read.
        Err(e) if e.raw_os_error() == Some(libc::EIO) => {}
        Err(e) => panic!("reading the terminal: {e}"),
    }
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "{}",
        std::fs::read_to_string(d.join("stderr")).unwrap_or_default()
    );
    String::from_utf8(out).unwrap().replace("\r\n", "\n")
}

/// Remove every `ESC[…m` sequence, leaving what a reader actually sees.
fn visible(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// The footer's lines as a reader sees them.
fn footer(text: &str) -> Vec<String> {
    let text = visible(text);
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
}

/// That the footer is folded to exactly `cols`: more than one line, none wider, each hung two
/// columns in, and none that could have taken the next line's first word.
fn folded_at(lines: &[String], cols: usize) {
    assert!(lines.len() > 1, "not folded: {lines:#?}");
    for l in lines {
        assert!(l.chars().count() <= cols, "over {cols}: {l:?}");
        assert!(l.starts_with("  ") && !l[2..].starts_with(' '), "{l:?}");
    }
    for pair in lines.windows(2) {
        let next = pair[1].split_whitespace().next().unwrap();
        assert!(
            pair[0].chars().count() + 1 + next.chars().count() > cols,
            "folded short of {cols}: {:?} had room for {next:?}",
            pair[0]
        );
    }
}

/// A terminal is coloured, and prose is folded to the width the terminal says it has.
#[test]
fn a_terminal_is_coloured_and_folded_to_its_own_width() {
    let text = on_terminal("sixty", 60, "auto", &[]);
    assert!(text.contains('\x1b'), "a terminal was left plain: {text:?}");
    folded_at(&footer(&text), 60);
}

/// A terminal that gives no width is still folded, to a conventional hundred columns, rather
/// than not at all.
#[test]
fn a_terminal_that_gives_no_width_is_folded_to_a_hundred_columns() {
    folded_at(&footer(&on_terminal("unmeasured", 0, "auto", &[])), 100);
}

/// An exported `COLUMNS` is the reader stating a width, and wins over the terminal's own.
#[test]
fn columns_wins_over_the_width_the_terminal_gives() {
    let text = on_terminal("columns", 60, "auto", &[("COLUMNS", "80")]);
    folded_at(&footer(&text), 80);
}

/// On a terminal, as in a pipe, colour stays off where something said so: a terminal that says
/// it cannot do it, `NO_COLOR`, and the plain theme.
#[test]
fn a_terminal_is_plain_where_something_said_plain() {
    for (what, theme, env) in [
        ("dumb", "auto", &[("TERM", "dumb")][..]),
        ("no-color", "auto", &[("NO_COLOR", "1")][..]),
        ("no-color-theme", "textcolor", &[("NO_COLOR", "1")][..]),
        ("plain-theme", "textnocolor", &[][..]),
    ] {
        let text = on_terminal(what, 60, theme, env);
        assert!(!text.contains('\x1b'), "{what}: {text:?}");
        // And plain is not empty: the words are all there.
        assert!(
            text.contains("`never checked` is a count"),
            "{what}: {text:?}"
        );
    }
}
