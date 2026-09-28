//! Where an evidence repository is: anything `git` can clone from or push to (`docs/19` §2.4).
//!
//! A location is classified once, here, so every later phase asks one value what transport it
//! names — `sync` says which transport it used, and a project's own configuration may name only
//! HTTPS. URLs reach `git` exactly as written, so whatever `git` accepts is accepted and nothing it
//! rejects is worked around. A local path is made absolute first: `~/` is expanded, and a relative
//! path is taken from the directory of the file that named it, or from the working directory when
//! the environment or the command line did.
//!
//! Refused, each with what to write instead:
//!
//! - **A path with a colon before its first slash.** `git` reads `name:path` as SSH to the host
//!   `name`, so `evidence:2026` and `C:\evidence` are SSH locations to `git` whatever they were
//!   meant to be. The SSH form is recognised when the part before the colon says it is a host —
//!   `user@host`, a name with a dot in it, or `[an:ipv6:address]` — and anything else is refused
//!   with the advice to write `./` or `file://` for a path, or `ssh://` for a host alias.
//! - **A remote helper** (`<transport>::<address>`) and any scheme but the five `docs/19` lists.
//!   `ext::` runs a command of the location's choosing, and a location is configuration, not code.
//! - **A password in a URL, and any user name in an `https://`, `http://` or `git://` URL.**
//!   Credentials are `git`'s own — SSH keys, a credential helper, `GIT_ASKPASS` — and Trigon never
//!   passes one, so a URL carrying one is refused rather than handed to `git` and printed in every
//!   message that names the location. Over HTTP the user name is where a token goes
//!   (`https://<token>@github.com/…` is how GitHub takes one), so there it is refused whatever it
//!   looks like; a credential helper is told the user name by `git config
//!   credential.<url>.username` instead. Over SSH the user name names an account, `git@`, and is
//!   kept. A refusal prints the location with its user part replaced by `***`, so it does not print
//!   the secret it refused.
//! - **A leading `-`**, which `git` would read as an option.

use std::path::{Component, Path, PathBuf};

/// How `git` will reach a location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Https,
    /// `ssh://`, `git+ssh://`, or the scp form `user@host:path`.
    Ssh,
    /// `git://`: plain text, unauthenticated.
    Git,
    /// `http://`: plain text.
    Http,
    /// A `file://` URL.
    File,
    /// A path on this machine, made absolute.
    LocalPath,
}

impl Transport {
    /// The name a message uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Https => "https",
            Transport::Ssh => "ssh",
            Transport::Git => "git",
            Transport::Http => "http",
            Transport::File => "file",
            Transport::LocalPath => "local path",
        }
    }

    /// Whether the transport carries the repository in plain text. Allowed, because integrity
    /// rests on the signatures and the log rather than on the transport, and said, because a
    /// reader should know which it was.
    pub fn is_plain_text(self) -> bool {
        matches!(self, Transport::Git | Transport::Http)
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A location, as written and as `git` will be given it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Location {
    written: String,
    resolved: String,
    transport: Transport,
}

impl Location {
    /// Classify `s`, resolving a local path against `base` and `~/` against `home`.
    ///
    /// `base` is the directory of the configuration file that named `s`, or the working directory
    /// for a value from the environment or the command line. It is used only for a relative path,
    /// and must itself be absolute.
    pub fn parse(s: &str, base: &Path, home: Option<&Path>) -> Result<Self, LocationError> {
        // Whatever the refusal is for, it names the location, and never with a credential in it.
        let refuse = |why: String| LocationError {
            location: printable(&without_credentials(s)),
            why,
        };
        if s.trim().is_empty() {
            return Err(refuse("it is empty".into()));
        }
        if s.trim() != s {
            return Err(refuse(
                "it starts or ends with whitespace, which git would take as part of the name"
                    .into(),
            ));
        }
        if s.chars().any(char::is_control) {
            return Err(refuse("it contains a control character".into()));
        }
        if s.starts_with('-') {
            return Err(refuse(
                "it starts with `-`, which git would read as an option. Write `./-…` for a path"
                    .into(),
            ));
        }

        if let Some((scheme, rest)) = url_scheme(s) {
            return Self::url(s, &scheme, rest).map_err(refuse);
        }
        // `<transport>::<address>`, a git remote helper. Checked before the scp form, which it
        // would otherwise look like, because git checks it first too.
        if let Some((helper, _)) = s.split_once("::")
            && is_scheme(helper)
        {
            return Err(refuse(format!(
                "it is a git remote helper (`{helper}::…`), and a location is https, ssh, git, \
                 http, file or a path. `ext::` in particular runs a command"
            )));
        }

        if s == "~" || s.starts_with("~/") {
            let home = home.ok_or_else(|| {
                refuse("it starts with `~/`, and HOME is not set to expand it".into())
            })?;
            return Ok(Self::local(
                s,
                &home.join(s.trim_start_matches('~').trim_start_matches('/')),
            ));
        }
        if s.starts_with('~') {
            return Err(refuse(
                "only `~/` is expanded, to your own home directory; write the path in full".into(),
            ));
        }
        if s.starts_with('/') {
            return Ok(Self::local(s, Path::new(s)));
        }

        // A colon before the first slash, or a colon and no slash at all: git reads this as the
        // scp-like SSH form, `[user@]host:path`, whatever it was meant to be.
        let first_slash = s.find('/').unwrap_or(s.len());
        if let Some(colon) = scp_ipv6(s).or_else(|| s[..first_slash].find(':')) {
            return match scp_host(s, colon) {
                Some(_) => Ok(Location {
                    written: s.to_string(),
                    resolved: s.to_string(),
                    transport: Transport::Ssh,
                }),
                None => Err(refuse(format!(
                    "git reads a colon before the first slash as SSH to the host `{}`. For a \
                     path, write `./{s}` or `file://…`; for an SSH host alias, `ssh://{}/…` or \
                     `user@{}:…`",
                    &s[..colon],
                    &s[..colon],
                    &s[..colon],
                ))),
            };
        }

        if !base.is_absolute() {
            return Err(refuse(format!(
                "it is a relative path and the directory it is relative to, `{}`, is not absolute",
                base.display()
            )));
        }
        Ok(Self::local(s, &base.join(s)))
    }

    fn url(s: &str, scheme: &str, rest: &str) -> Result<Self, String> {
        let transport = match scheme {
            "https" => Transport::Https,
            "http" => Transport::Http,
            "ssh" | "git+ssh" | "ssh+git" => Transport::Ssh,
            "git" => Transport::Git,
            "file" => Transport::File,
            other => {
                return Err(format!(
                    "`{other}://` is not a transport Trigon hands to git. A location is https://, \
                     ssh://, git://, http://, file://, `user@host:path`, or a path"
                ));
            }
        };
        if s.chars().any(char::is_whitespace) {
            return Err("a URL contains no whitespace; percent-encode it (`%20`)".into());
        }
        if transport != Transport::File {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            let (userinfo, host) = match authority.rsplit_once('@') {
                Some((u, h)) => (Some(u), h),
                None => (None, authority),
            };
            if host.is_empty() || host.starts_with(':') {
                return Err(format!("it names no host after `{scheme}://`"));
            }
            if userinfo.is_some_and(|u| u.contains(':')) {
                return Err(
                    "it carries a password. Credentials are git's own — an SSH key, a credential \
                     helper, GIT_ASKPASS — and Trigon never passes one; name the user alone, or \
                     no one"
                        .into(),
                );
            }
            // Over HTTP a user name is where a token goes, and GitHub takes one there, so it is
            // refused whatever it looks like. Over SSH it names the account and stays.
            if userinfo.is_some() && transport != Transport::Ssh {
                return Err(format!(
                    "it names a user before the host, which in a `{scheme}://` URL is where a \
                     token goes, and Trigon never passes a credential. Credentials are git's own; \
                     to tell a credential helper the user, run `git config \
                     credential.{scheme}://<host>.username <user>`, and write the URL without it"
                ));
            }
        }
        Ok(Location {
            written: s.to_string(),
            resolved: s.to_string(),
            transport,
        })
    }

    fn local(written: &str, path: &Path) -> Self {
        // `Path::components` drops interior `.` segments and repeated slashes. `..` stays: it is
        // resolved by the filesystem, through whatever symlinks are there, and collapsing it here
        // could name a different directory.
        let mut out = PathBuf::new();
        for c in path.components() {
            if c != Component::CurDir {
                out.push(c.as_os_str());
            }
        }
        Location {
            written: written.to_string(),
            resolved: out.to_string_lossy().into_owned(),
            transport: Transport::LocalPath,
        }
    }

    /// What the configuration or the environment said.
    pub fn written(&self) -> &str {
        &self.written
    }

    /// What `git` is given: the URL unchanged, or the path made absolute.
    pub fn as_git_arg(&self) -> &str {
        &self.resolved
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// The absolute path, for a local path; `None` for any URL, `file://` included.
    pub fn local_path(&self) -> Option<&Path> {
        (self.transport == Transport::LocalPath).then(|| Path::new(&self.resolved))
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.resolved)
    }
}

/// A location that is not one, and why.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("`{location}` is not a repository location: {why}")]
pub struct LocationError {
    /// As written, with any control character escaped: a project's file is input chosen by the
    /// thing under test, and its refusal is printed into somebody's terminal or CI log.
    pub location: String,
    pub why: String,
}

/// `s` with the user part of a URL's authority replaced by `***` wherever it could be a
/// credential: a password anywhere, and any user name but an SSH one. A refusal prints the
/// location it refuses, and printing the token it was refused for would put the token in the log
/// the refusal exists to keep it out of.
fn without_credentials(s: &str) -> String {
    let Some((scheme, rest)) = s.trim().split_once("://") else {
        return s.to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return s.to_string();
    };
    let ssh = matches!(
        scheme.to_ascii_lowercase().as_str(),
        "ssh" | "git+ssh" | "ssh+git"
    );
    if ssh && !userinfo.contains(':') {
        return s.to_string();
    }
    let at = s.find("://").map_or(0, |i| i + 3);
    format!("{}***{}", &s[..at], &s[at + userinfo.len()..])
}

pub(crate) fn printable(s: &str) -> String {
    s.chars()
        .map(|c| match c.is_control() {
            true => c.escape_default().to_string(),
            false => c.to_string(),
        })
        .collect()
}

/// The scheme of `s`, lowercased, and what follows `://`, where `s` is written as a URL.
fn url_scheme(s: &str) -> Option<(String, &str)> {
    let (scheme, rest) = s.split_once("://")?;
    is_scheme(scheme).then(|| (scheme.to_ascii_lowercase(), rest))
}

/// Whether `s` is spelled as a URL scheme, which is also how git spells a remote helper's name.
fn is_scheme(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The colon after a bracketed IPv6 host in the scp form, `[::1]:repo` or `git@[::1]:repo`,
/// which the first-colon search finds inside the brackets instead.
fn scp_ipv6(s: &str) -> Option<usize> {
    let open = s.find('[')?;
    if open != 0 && !s[..open].ends_with('@') {
        return None;
    }
    let close = open + s[open..].find("]:")?;
    let slash = s.find('/').unwrap_or(s.len());
    (close < slash).then_some(close + 1)
}

/// The host of an scp-like location whose colon is at `colon`, where the part before it reads as
/// one: `user@host`, a name with a dot in it, or a bracketed IPv6 address. `None` for anything
/// else, which is refused rather than handed to git as SSH to a host nobody meant.
fn scp_host(s: &str, colon: usize) -> Option<&str> {
    let before = &s[..colon];
    let (user, host) = match before.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, before),
    };
    if user.is_some_and(|u| u.is_empty() || u.contains(':')) || host.is_empty() {
        return None;
    }
    if host.starts_with('[') && host.ends_with(']') {
        return Some(host);
    }
    let hostname = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    // A name with no dot and no user is as likely a directory as a host — and one letter is a
    // Windows drive — so it is refused and the advice says how to write either.
    (hostname && (user.is_some() || host.contains('.'))).then_some(host)
}
