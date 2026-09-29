//! Repository locations: every form `docs/19` §2.4 accepts, what each is classified as, what `git`
//! is given, and every form refused with what to write instead.
//!
//! The classification is what later phases ask — `sync` reports the transport, and a project's
//! own configuration may name HTTPS alone — so a location classified wrongly is a rule applied
//! wrongly, and these cases pin it.

use std::path::Path;

use trigon_attest::location::{Location, Transport};

const BASE: &str = "/home/u/.config/trigon";
const HOME: &str = "/home/u";

fn parse(s: &str) -> Result<Location, String> {
    Location::parse(s, Path::new(BASE), Some(Path::new(HOME))).map_err(|e| e.to_string())
}

fn ok(s: &str) -> Location {
    parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

/// A URL reaches git exactly as written.
#[test]
fn every_url_form_is_classified_and_passed_to_git_unchanged() {
    for (s, transport) in [
        (
            "https://github.com/owner/trigon-evidence.git",
            Transport::Https,
        ),
        (
            "https://codeberg.org/owner/trigon-evidence",
            Transport::Https,
        ),
        // A port, a path with a query: git's to interpret.
        ("https://git.example.org:8443/o/r.git", Transport::Https),
        (
            "ssh://git@example.org/owner/trigon-evidence.git",
            Transport::Ssh,
        ),
        ("ssh://git@example.org:2222/owner/r.git", Transport::Ssh),
        ("git+ssh://git@example.org/owner/r.git", Transport::Ssh),
        ("ssh+git://git@example.org/owner/r.git", Transport::Ssh),
        (
            "git://example.org/owner/trigon-evidence.git",
            Transport::Git,
        ),
        (
            "http://example.org/owner/trigon-evidence.git",
            Transport::Http,
        ),
        ("file:///srv/git/trigon-evidence.git", Transport::File),
        // The scheme is matched in any case, and still passed as written.
        ("HTTPS://github.com/owner/r.git", Transport::Https),
    ] {
        let l = ok(s);
        assert_eq!(l.transport(), transport, "{s}");
        assert_eq!(l.as_git_arg(), s, "{s} must reach git unchanged");
        assert_eq!(l.written(), s);
        assert_eq!(l.local_path(), None, "{s} is not a local path");
    }
}

#[test]
fn the_scp_form_is_ssh_when_the_part_before_the_colon_is_a_host() {
    for s in [
        "git@github.com:owner/trigon-evidence.git",
        "git@example.org:trigon-evidence.git",
        // A host with a dot needs no user.
        "github.com:owner/trigon-evidence.git",
        // A user makes an alias with no dot a host, as ssh reads it.
        "git@myalias:owner/r.git",
        "deploy@build-01.internal:repo",
        // Bracketed IPv6, with and without a user.
        "[::1]:repo.git",
        "git@[2001:db8::1]:owner/r.git",
    ] {
        let l = ok(s);
        assert_eq!(l.transport(), Transport::Ssh, "{s}");
        assert_eq!(l.as_git_arg(), s);
    }
}

#[test]
fn plain_text_transports_are_allowed_and_say_so() {
    // Integrity rests on the signatures and the log, not the transport; but a reader should know.
    assert!(ok("git://example.org/r.git").transport().is_plain_text());
    assert!(ok("http://example.org/r.git").transport().is_plain_text());
    assert!(!ok("https://example.org/r.git").transport().is_plain_text());
    assert!(!ok("git@example.org:r.git").transport().is_plain_text());
}

#[test]
fn a_local_path_is_made_absolute_against_the_file_that_named_it() {
    for (s, want) in [
        ("/srv/git/evidence.git", "/srv/git/evidence.git"),
        ("/srv/git/./evidence.git", "/srv/git/evidence.git"),
        ("/srv//git/evidence.git/", "/srv/git/evidence.git"),
        ("./evidence", "/home/u/.config/trigon/evidence"),
        ("evidence", "/home/u/.config/trigon/evidence"),
        (
            "repos/evidence.git",
            "/home/u/.config/trigon/repos/evidence.git",
        ),
        // `..` is kept: the filesystem resolves it through whatever symlinks are there, and
        // collapsing it here could name another directory.
        ("../evidence", "/home/u/.config/trigon/../evidence"),
        ("~/evidence", "/home/u/evidence"),
        ("~", "/home/u"),
        // A colon after the first slash is part of the path, as git reads it.
        ("repos/a:b", "/home/u/.config/trigon/repos/a:b"),
        ("./C:/evidence", "/home/u/.config/trigon/C:/evidence"),
        // Spaces are a path's own business.
        ("my evidence", "/home/u/.config/trigon/my evidence"),
    ] {
        let l = ok(s);
        assert_eq!(l.transport(), Transport::LocalPath, "{s}");
        assert_eq!(l.as_git_arg(), want, "{s}");
        assert_eq!(l.local_path(), Some(Path::new(want)), "{s}");
        assert_eq!(l.written(), s);
    }
}

#[test]
fn a_relative_path_from_the_environment_is_taken_from_the_working_directory() {
    // The caller passes the working directory as the base for the environment and the command
    // line; the rule is the same function with a different base.
    let l = Location::parse("./evidence", Path::new("/work/project"), None).unwrap();
    assert_eq!(l.as_git_arg(), "/work/project/evidence");
}

#[test]
fn a_colon_before_the_first_slash_that_is_not_a_host_is_refused_with_the_way_out() {
    for s in [
        // Windows-looking paths are out of scope, and fall under the colon rule.
        "C:\\evidence",
        "C:/evidence",
        "c:evidence",
        // A directory with a colon in its name, written bare.
        "evidence:2026/repo",
        "backup:repo",
        // An alias with no dot and no user: as likely a directory as a host.
        "myalias:owner/r.git",
    ] {
        let e = parse(s).expect_err(s);
        assert!(e.contains("SSH"), "{s}: {e}");
        assert!(e.contains("./"), "{s}: the advice for a path is `./`: {e}");
        assert!(e.contains("file://"), "{s}: or `file://`: {e}");
        assert!(
            e.contains("ssh://"),
            "{s}: and `ssh://` for a host alias: {e}"
        );
    }
}

#[test]
fn a_remote_helper_and_an_unknown_scheme_are_refused() {
    for (s, says) in [
        // `ext::` runs a command of the location's choosing.
        ("ext::sh -c touch% /tmp/pwned", "remote helper"),
        ("fd::17", "remote helper"),
        ("ftp://example.org/r.git", "ftp://"),
        ("svn://example.org/r", "svn://"),
    ] {
        let e = parse(s).expect_err(s);
        assert!(e.contains(says), "{s}: {e}");
    }
}

#[test]
fn a_password_in_a_url_is_refused_because_credentials_are_gits_own() {
    for s in [
        "https://user:ghp_secret@github.com/o/r.git",
        "https://:ghp_secret@github.com/o/r.git",
        "ssh://git:ghp_secret@example.org/o/r.git",
    ] {
        let e = parse(s).expect_err(s);
        assert!(e.contains("password"), "{s}: {e}");
        assert!(e.contains("credential helper"), "{s}: {e}");
        assert!(
            !e.contains("ghp_secret"),
            "the refusal prints the secret: {e}"
        );
    }
}

#[test]
fn a_user_name_in_an_http_url_is_refused_because_it_is_where_a_token_goes() {
    // GitHub takes a token as `https://<token>@github.com/…`, and nothing about the string says
    // whether it is a token or a name, so over HTTP it is refused either way.
    for s in [
        "https://ghp_secret@github.com/o/r.git",
        "HTTPS://ghp_secret@github.com/o/r.git",
        "http://ghp_secret@example.org/o/r.git",
        "git://ghp_secret@example.org/o/r.git",
        "https://ghp_secret@git.example.org:8443/o/r.git",
    ] {
        let e = parse(s).expect_err(s);
        assert!(e.contains("credential"), "{s}: {e}");
        assert!(
            e.contains("username"),
            "it says how to name the user instead: {e}"
        );
        assert!(
            !e.contains("ghp_secret"),
            "the refusal prints the token: {e}"
        );
        assert!(e.contains("://***@"), "{s}: {e}");
    }
    // Over SSH the user names the account, and stays, in either form.
    for s in [
        "ssh://git@example.org/o/r.git",
        "git+ssh://deploy@example.org/o/r.git",
        "git@github.com:o/r.git",
    ] {
        assert_eq!(ok(s).transport(), Transport::Ssh, "{s}");
    }
}

#[test]
fn a_url_refused_for_anything_else_still_does_not_print_its_credentials() {
    // Refused for whitespace, a missing host or its scheme before the user part is looked at, and
    // every refusal names the location.
    for s in [
        "https://ghp_secret@github.com/o/my repo",
        "https://user:ghp_secret@github.com/o/my repo",
        "ftp://ghp_secret@example.org/r.git",
        "https://ghp_secret@/o/r",
        "https://ghp_secret@github.com/o/r\u{1b}[2J",
    ] {
        let e = parse(s).expect_err(s);
        assert!(!e.contains("ghp_secret"), "{s}: {e}");
    }
    // A user name that is not a credential is shown, since it is the account being named.
    let e = parse("ssh://git@example.org/o/my repo").unwrap_err();
    assert!(e.contains("ssh://git@example.org"), "{e}");
}

#[test]
fn malformed_locations_are_refused_with_the_reason() {
    for (s, says) in [
        ("", "empty"),
        ("   ", "empty"),
        (" https://github.com/o/r", "whitespace"),
        ("https://github.com/o/r ", "whitespace"),
        ("-uhack", "option"),
        ("--upload-pack=touch /tmp/x", "option"),
        ("https://", "no host"),
        ("https:///o/r", "no host"),
        ("ssh://@/r", "no host"),
        ("https://github.com/o/my repo", "whitespace"),
        ("https://github.com/o/r\n", "whitespace"),
        ("https://github.com/o\u{1b}[31m/r", "control"),
        ("~other/evidence", "only `~/`"),
    ] {
        let e = parse(s).expect_err(s);
        assert!(e.contains(says), "{s:?}: {e}");
        assert!(e.contains("is not a repository location"), "{s:?}: {e}");
    }
}

#[test]
fn a_refusal_prints_a_control_character_escaped() {
    // A project's file is chosen by the thing under test, and its refusal lands in a terminal or
    // a CI log; an escape sequence in it would be written there as one.
    let e = parse("https://github.com/o\u{1b}[31m/r").unwrap_err();
    assert!(!e.contains('\u{1b}'), "{e:?}");
    assert!(e.contains("\\u{1b}"), "{e:?}");
}

#[test]
fn a_home_relative_path_with_no_home_is_refused() {
    let e = Location::parse("~/evidence", Path::new(BASE), None)
        .unwrap_err()
        .to_string();
    assert!(e.contains("HOME"), "{e}");
}

#[test]
fn every_transport_has_a_name_a_message_can_use() {
    for (t, name) in [
        (Transport::Https, "https"),
        (Transport::Ssh, "ssh"),
        (Transport::Git, "git"),
        (Transport::Http, "http"),
        (Transport::File, "file"),
        (Transport::LocalPath, "local path"),
    ] {
        assert_eq!(t.to_string(), name);
    }
}

/// Before the colon, an empty user, a user with a colon of its own, or nothing at all is no host;
/// and a bracket that neither begins the location nor follows a user is no IPv6 host. Each is
/// refused under the colon rule, never handed to git as SSH to a host nobody meant.
#[test]
fn what_is_not_a_host_before_the_colon_is_refused() {
    for s in [
        "@example.org:repo",
        "a:b@[::1]:repo",
        ":repo",
        "x[::1]:repo",
    ] {
        let e = parse(s).expect_err(s);
        assert!(e.contains("as SSH to the host"), "{s}: {e}");
    }
}

/// A relative path is taken from the directory it is relative to, and is refused where that
/// directory is not absolute: it would name a different place from every working directory.
#[test]
fn a_relative_path_against_a_relative_directory_is_refused() {
    let e = Location::parse("evidence", Path::new("relative/dir"), None)
        .unwrap_err()
        .to_string();
    assert!(e.contains("`relative/dir`, is not absolute"), "{e}");
}
