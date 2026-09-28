//! `git`, as `publish` and `log init` run it (`docs/19` §2.4).
//!
//! Shelled out to, as fetching sources is, and with the location handed over exactly as it was
//! configured: a URL unchanged, a local path made absolute, so anything `git` accepts is accepted
//! and nothing it rejects is worked around. **Credentials are `git`'s own** — SSH keys, a
//! credential helper, `GIT_ASKPASS` — so, unlike a fetch of a package's source, this keeps the
//! operator's git configuration: the credential helper that pushes lives there. Trigon never reads,
//! passes or logs a credential: a location carrying one is refused when it is parsed, nothing here
//! puts one on argv, and what `git` prints is scrubbed of anything in a URL's user part before it
//! is shown.
//!
//! **Nothing waits for a person.** `GIT_TERMINAL_PROMPT=0` stops `git`'s own prompt for an HTTP
//! credential, and ssh, which reads a key's passphrase or a host-key question from the terminal
//! whatever `git` is told, runs with `BatchMode=yes`: added to the `ssh` command when none is
//! configured, and to one that is when it runs `ssh`. A missing credential, or a host key nobody
//! has accepted, then fails rather than waits on a terminal nobody is watching. A program the
//! operator configures to answer instead — a credential helper, an askpass, an ssh wrapper that is
//! not `ssh` — is theirs, and runs as configured.
//!
//! **The operator's configuration never changes what is committed, or what is read.** A
//! publication's files are staged as blobs of exactly their bytes, never by `git add`, which
//! follows ignore rules and the attributes that name filters and line-end conversion
//! ([`commit`]). `core.autocrlf` and the operator's own attributes file are switched off for every
//! run, so a checkout writes each blob's bytes as they are; a tree that names attributes of its own
//! is refused ([`attributes`]); and a commit is never signed with the operator's key. And the
//! variables that point `git` at a repository other than the one named — `GIT_DIR` and its kin —
//! are removed, so that a `publish` run from inside a git hook, or under a caller's `GIT_DIR`,
//! still writes its own clone and no other.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{Context as _, Result, anyhow, bail};
use sha2::Digest as _;
use trigon_attest::location::Location;

/// The variables through which a caller's environment points `git` at another repository.
const REPOSITORY_VARIABLES: [&str; 9] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_QUARANTINE_PATH",
];

/// Configuration fixed for every run, whatever the operator's says, because it changes bytes
/// between a blob and the file checked out from it: `core.autocrlf` rewrites line ends with no
/// attribute asking, and `core.attributesFile` is the operator's own attributes, which can name a
/// filter or a conversion for any path. The system's attributes file is switched off by
/// `GIT_ATTR_NOSYSTEM`.
const PINNED: [&str; 2] = ["core.autocrlf=false", "core.attributesFile=/dev/null"];

/// Who commits a publication. Not the operator's own identity: who committed a file is never who
/// signed it (`docs/19` §8), and the operator's address would otherwise go into a public history
/// with every publication.
const COMMITTER: (&str, &str) = ("trigon publish", "publish@trigon.invalid");

/// How many paths one `git ls-tree` is asked about, so a reconcile of many index files stays well
/// inside the argument limit.
const PATHS_PER_CALL: usize = 256;

/// The command for `git` in `dir`, or in the working directory where there is none.
///
/// Where there is a `dir`, `git` looks for its repository there and no further up: a directory
/// that is not a repository of its own is refused, never taken for whichever repository encloses
/// it. A store kept inside a checkout — `./trigon-store` usually is — would otherwise have a
/// command meant for its clone rewrite that checkout. (A path with a colon in it cannot be one
/// entry of `GIT_CEILING_DIRECTORIES`, and is left to the check each caller makes of it.)
pub(crate) fn command(dir: Option<&Path>) -> Command {
    let mut c = Command::new("git");
    if let Some(d) = dir {
        c.arg("-C").arg(d);
        let parent = std::path::absolute(d)
            .ok()
            .and_then(|a| a.parent().map(Path::to_path_buf));
        if let Some(p) = parent.filter(|p| !p.as_os_str().as_encoded_bytes().contains(&b':')) {
            c.env("GIT_CEILING_DIRECTORIES", p);
        }
    }
    for p in PINNED {
        c.arg("-c").arg(p);
    }
    c.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .stdin(Stdio::null());
    for v in REPOSITORY_VARIABLES {
        c.env_remove(v);
    }
    c
}

/// The command for `git` in `dir` where it reaches a remote: [`command`], with ssh told never to
/// ask anything ([`batch_ssh`]).
fn network(dir: Option<&Path>) -> Command {
    let mut c = command(dir);
    if let Some(ssh) = batch_ssh(dir) {
        c.env("GIT_SSH_COMMAND", ssh);
    }
    c
}

/// The ssh command a network `git` is to run, where it must be set: the one configured —
/// `GIT_SSH_COMMAND`, `GIT_SSH` or `core.sshCommand`, in `git`'s order — with `-o BatchMode=yes`
/// added, or plain `ssh` with it where none is. `None` leaves the configured command as it is.
fn batch_ssh(dir: Option<&Path>) -> Option<String> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let configured = match (var("GIT_SSH_COMMAND"), var("GIT_SSH")) {
        (Some(c), _) => Some(c),
        // A program, which `git` runs with arguments rather than through a shell: it is written
        // as a command by quoting it, since `GIT_SSH_COMMAND` is the only way to add one.
        (None, Some(program)) => Some(format!("'{}'", program.replace('\'', r"'\''"))),
        (None, None) => configured_ssh(dir),
    };
    batch_mode(configured.as_deref())
}

/// `core.sshCommand`, as `git` in `dir` reads it; where there is no `dir` yet, as a clone reads it,
/// from the system's and the user's configuration and not from whatever repository the working
/// directory is in.
fn configured_ssh(dir: Option<&Path>) -> Option<String> {
    let out = command(Some(dir.unwrap_or(Path::new("/"))))
        .args(["config", "--get", "core.sshCommand"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let c = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !c.is_empty()).then_some(c)
}

/// `configured` with `BatchMode=yes` added where it runs `ssh`, as `git` itself decides whether a
/// command is OpenSSH's before it adds options of its own; plain `ssh` with it where nothing is
/// configured; and `None` for a command that runs something else, whose options are unknown. An
/// option given twice to ssh keeps its first value, so a command that sets `BatchMode` itself
/// keeps its own.
fn batch_mode(configured: Option<&str>) -> Option<String> {
    const BATCH: &str = "-o BatchMode=yes";
    let Some(c) = configured else {
        return Some(format!("ssh {BATCH}"));
    };
    let c = c.trim();
    // The first word, as a shell reads it: up to the closing quote where it is quoted.
    let first = match c.chars().next() {
        Some(q @ ('\'' | '"')) => c[1..].split(q).next(),
        _ => c.split_whitespace().next(),
    };
    let program = first.and_then(|w| Path::new(w).file_name());
    program
        .is_some_and(|p| p == "ssh")
        .then(|| format!("{c} {BATCH}"))
}

/// Run `git` with `args` in `dir`: its output, or an error naming the command and saying what
/// `git` said, scrubbed.
pub(crate) fn run<S: AsRef<OsStr>>(dir: Option<&Path>, args: &[S]) -> Result<Output> {
    finish(command(dir), args)
}

/// [`run`], for a command that reaches a remote.
pub(crate) fn run_network<S: AsRef<OsStr>>(dir: Option<&Path>, args: &[S]) -> Result<Output> {
    finish(network(dir), args)
}

fn finish<S: AsRef<OsStr>>(mut c: Command, args: &[S]) -> Result<Output> {
    let out = c
        .args(args)
        .output()
        .map_err(|e| anyhow!("running git: {e}. Is git installed and on PATH?"))?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            shown_args(args),
            scrub(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    Ok(out)
}

/// Run `git` and return what it printed, trimmed.
pub(crate) fn text<S: AsRef<OsStr>>(dir: Option<&Path>, args: &[S]) -> Result<String> {
    let out = run(dir, args)?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Whether `git` with `args` succeeds, for the questions that are answered by its exit.
pub(crate) fn succeeds<S: AsRef<OsStr>>(dir: Option<&Path>, args: &[S]) -> bool {
    command(dir)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run `git` with `input` on its standard input, written from a thread of its own so that neither
/// side waits on the other's full pipe.
fn run_with_input<S: AsRef<OsStr>>(dir: &Path, args: &[S], input: Vec<u8>) -> Result<Output> {
    feed(command(Some(dir)), args, input)
}

/// [`run_with_input`], for the command `c`.
fn feed<S: AsRef<OsStr>>(mut c: Command, args: &[S], input: Vec<u8>) -> Result<Output> {
    let mut child = c
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("running git: {e}. Is git installed and on PATH?"))?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output()?;
    let written = writer
        .join()
        .map_err(|_| anyhow!("writing to git panicked"))?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            shown_args(args),
            scrub(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    written.with_context(|| format!("writing to git {}", shown_args(args)))?;
    Ok(out)
}

/// The arguments of a command as a message shows them. A location is on argv only as it was
/// configured, and a configured location carries no credential; scrubbed all the same.
fn shown_args<S: AsRef<OsStr>>(args: &[S]) -> String {
    let joined: Vec<String> = args
        .iter()
        .map(|a| a.as_ref().to_string_lossy().into_owned())
        .collect();
    scrub(&joined.join(" "))
}

/// `git clone` of `location` into `dir`, with no tags and nothing checked out: the location as
/// `git` is to be given it, unchanged, after `--`, so that nothing in it is read as an option.
pub(crate) fn clone_args(location: &Location, dir: &Path) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> =
        ["clone", "--quiet", "--no-tags", "--no-checkout", "--"]
            .map(Into::into)
            .to_vec();
    args.push(location.as_git_arg().into());
    args.push(dir.into());
    args
}

/// Clone `location` into `dir`.
pub(crate) fn clone(location: &Location, dir: &Path) -> Result<()> {
    run_network(None, &clone_args(location, dir)).map(|_| ())
}

/// Whether `dir` is the top of a working tree of its own, with its git directory at `dir/.git`:
/// the check a directory kept as a clone is held to before anything is run in it, so that one
/// whose `.git` is gone, or leads elsewhere, is never taken for another repository.
pub(crate) fn is_clone_at(dir: &Path) -> bool {
    let (Ok(top), Ok(git_dir)) = (
        text(Some(dir), &["rev-parse", "--show-toplevel"]),
        text(Some(dir), &["rev-parse", "--absolute-git-dir"]),
    ) else {
        return false;
    };
    let real = |p: &Path| p.canonicalize().ok();
    match (real(dir), real(&dir.join(".git"))) {
        (Some(d), Some(g)) => {
            real(Path::new(&top)) == Some(d) && real(Path::new(&git_dir)) == Some(g)
        }
        _ => false,
    }
}

/// What one commit changes: every file it writes, by its path in the tree with the bytes written
/// there, and every path it removes.
#[derive(Default)]
pub(crate) struct Change<'a> {
    pub writes: Vec<(&'a str, &'a [u8])>,
    pub removes: Vec<&'a str>,
}

/// Commit exactly `change` in the working tree at `dir`, on top of `parent` (`None` for a branch's
/// first commit), as [`COMMITTER`], with `message`; and check that the commit holds it.
///
/// **Exactly, and nothing else.** Each file written is staged as a blob of its bytes as they are
/// on disk — `hash-object --no-filters`, never `git add`, which skips what the tree's `.gitignore`
/// or the operator's excludes name and runs whatever filter or line-end conversion an attribute
/// names — and each removed path is taken out of the index. The commit is then read back: its
/// parent must be `parent`, every path it changes must be one `change` names or lies under, every
/// file written must be in it as a blob of exactly the bytes given, and every path removed must be
/// gone. Anything else is refused before it can be pushed, and the caller discards it: what `trigon
/// log sign` checked on disk is what is committed, or nothing is.
///
/// `--no-verify`, so that no pre-commit hook of a working tree published into can stage something
/// else; `--no-gpg-sign`, so that the operator's `commit.gpgSign` neither signs a public commit
/// with their own key, which the fixed committer is there to keep out of the history, nor waits
/// on a passphrase.
pub(crate) fn commit(
    dir: &Path,
    parent: Option<&str>,
    change: &Change,
    message: &str,
) -> Result<String> {
    for path in change
        .writes
        .iter()
        .map(|(p, _)| *p)
        .chain(change.removes.iter().copied())
    {
        let plain = !path.is_empty()
            && !path.contains(['\n', '\0'])
            && Path::new(path)
                .components()
                .all(|c| matches!(c, Component::Normal(_)));
        if !plain {
            bail!("`{path}` is not a path inside the repository");
        }
    }
    let format = text(Some(dir), &["rev-parse", "--show-object-format"])?;
    if !change.removes.is_empty() {
        let mut input = Vec::new();
        for p in &change.removes {
            input.extend_from_slice(p.as_bytes());
            input.push(0);
        }
        run_with_input(
            dir,
            &[
                "--literal-pathspecs",
                "rm",
                "-r",
                "--cached",
                "--quiet",
                "--ignore-unmatch",
                "--pathspec-from-file=-",
                "--pathspec-file-nul",
            ],
            input,
        )?;
    }
    let mut want: BTreeMap<&str, String> = BTreeMap::new();
    if !change.writes.is_empty() {
        let mut paths = Vec::new();
        for (p, _) in &change.writes {
            paths.extend_from_slice(p.as_bytes());
            paths.push(b'\n');
        }
        let out = run_with_input(
            dir,
            &["hash-object", "-w", "--no-filters", "--stdin-paths"],
            paths,
        )?;
        let ids = String::from_utf8_lossy(&out.stdout).into_owned();
        let ids: Vec<&str> = ids.lines().collect();
        if ids.len() != change.writes.len() {
            bail!(
                "git hash-object gave {} ids for {} files",
                ids.len(),
                change.writes.len()
            );
        }
        let mut entries = Vec::new();
        for ((path, bytes), id) in change.writes.iter().zip(ids) {
            let expected = blob_id(&format, bytes)?;
            if id != expected {
                bail!(
                    "{} is not what was written there: its blob is {id}, and the bytes written \
                     make {expected}",
                    dir.join(path).display()
                );
            }
            entries.extend_from_slice(format!("100644 {id}\t{path}").as_bytes());
            entries.push(0);
            want.insert(path, expected);
        }
        run_with_input(
            dir,
            &["update-index", "--add", "--replace", "-z", "--index-info"],
            entries,
        )?;
    }
    let out = command(Some(dir))
        .args([
            "commit",
            "--quiet",
            "--no-verify",
            "--no-gpg-sign",
            "--message",
            message,
        ])
        .env("GIT_AUTHOR_NAME", COMMITTER.0)
        .env("GIT_AUTHOR_EMAIL", COMMITTER.1)
        .env("GIT_COMMITTER_NAME", COMMITTER.0)
        .env("GIT_COMMITTER_EMAIL", COMMITTER.1)
        .output()
        .map_err(|e| anyhow!("running git: {e}"))?;
    if !out.status.success() {
        bail!(
            "git commit failed: {}",
            scrub(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    let head = text(Some(dir), &["rev-parse", "--verify", "HEAD"])?;
    holds(dir, &head, parent, change, &want)
        .with_context(|| format!("the commit {head} is not the publication, and is not pushed"))?;
    Ok(head)
}

/// Read the commit `head` back, and check it is `parent` and exactly `change` (see [`commit`]).
fn holds(
    dir: &Path,
    head: &str,
    parent: Option<&str>,
    change: &Change,
    want: &BTreeMap<&str, String>,
) -> Result<()> {
    let listed = text(Some(dir), &["rev-list", "--parents", "-n", "1", head])?;
    let parents: Vec<&str> = listed.split_whitespace().skip(1).collect();
    if parents != parent.into_iter().collect::<Vec<_>>() {
        bail!(
            "its parents are {parents:?}, and it was to be made on {}",
            parent.unwrap_or("nothing")
        );
    }
    let out = run(
        Some(dir),
        &[
            "diff-tree",
            "-r",
            "-z",
            "--no-renames",
            "--no-commit-id",
            "--root",
            head,
        ],
    )?;
    // `:<old mode> <new mode> <old id> <new id> <status>` NUL `<path>` NUL, per path changed.
    let mut changed: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut fields = out.stdout.split(|b| *b == 0).filter(|f| !f.is_empty());
    while let (Some(meta), Some(path)) = (fields.next(), fields.next()) {
        let meta = String::from_utf8_lossy(meta);
        let m: Vec<&str> = meta.trim_start_matches(':').split(' ').collect();
        let (Some(mode), Some(id)) = (m.get(1), m.get(3)) else {
            bail!("git diff-tree printed `{meta}`, which is not a change");
        };
        changed.insert(
            String::from_utf8_lossy(path).into_owned(),
            (mode.to_string(), id.to_string()),
        );
    }
    let under =
        |p: &str, of: &str| p == of || p.strip_prefix(of).is_some_and(|r| r.starts_with('/'));
    let named = |p: &str| {
        change.writes.iter().any(|(w, _)| under(p, w)) || change.removes.iter().any(|r| under(p, r))
    };
    if let Some(p) = changed.keys().find(|p| !named(p)) {
        bail!("it changes `{p}`, which the publication does not write");
    }
    let mut unchanged = Vec::new();
    for (path, id) in want {
        match changed.get(*path) {
            Some((mode, got)) if mode == "100644" && got == id => {}
            Some((mode, got)) => bail!(
                "it holds `{path}` as {got} (mode {mode}), and the bytes written make the blob \
                 {id}"
            ),
            None => unchanged.push(*path),
        }
    }
    // What the commit did not change must already be in it as written, and nothing removed may be.
    let mut asked: Vec<&str> = unchanged.clone();
    asked.extend(change.removes.iter().copied());
    let mut found: BTreeMap<String, (String, String)> = BTreeMap::new();
    for chunk in asked.chunks(PATHS_PER_CALL) {
        let mut args = vec![
            "--literal-pathspecs",
            "ls-tree",
            "-z",
            "--full-tree",
            head,
            "--",
        ];
        args.extend_from_slice(chunk);
        let out = run(Some(dir), &args)?;
        for entry in out.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            let entry = String::from_utf8_lossy(entry);
            let Some((meta, path)) = entry.split_once('\t') else {
                bail!("git ls-tree printed `{entry}`, which is not an entry");
            };
            let m: Vec<&str> = meta.split(' ').collect();
            if let (Some(mode), Some(id)) = (m.first(), m.get(2)) {
                found.insert(path.to_string(), (mode.to_string(), id.to_string()));
            }
        }
    }
    for path in unchanged {
        match found.get(path) {
            Some((mode, id)) if mode == "100644" && Some(id) == want.get(path) => {}
            _ => bail!("it does not hold `{path}` as it was written"),
        }
    }
    if let Some(p) = change.removes.iter().find(|r| found.contains_key(**r)) {
        bail!("it still holds `{p}`, which the publication removes");
    }
    Ok(())
}

/// The id `git` gives a blob of `bytes` in a repository of object format `format`, computed here
/// rather than asked of `git`, so that a commit is checked against the bytes and not against
/// `git`'s word for them.
fn blob_id(format: &str, bytes: &[u8]) -> Result<String> {
    let header = format!("blob {}\0", bytes.len());
    let id: Vec<u8> = match format {
        "sha1" => trigon_attest::sha1_of(&[header.as_bytes(), bytes].concat())
            .0
            .to_vec(),
        "sha256" => sha2::Sha256::new()
            .chain_update(header.as_bytes())
            .chain_update(bytes)
            .finalize()
            .to_vec(),
        other => {
            bail!("the repository's object format is `{other}`, which this build cannot check")
        }
    };
    Ok(id.iter().map(|b| format!("{b:02x}")).collect())
}

/// How a push ended.
pub(crate) enum Pushed {
    Yes,
    /// Rejected, and the branch on the remote is no longer the commit this one was built on:
    /// another writer won.
    LostRace,
}

/// Push `branch` to `origin`, never forced: a compare-and-swap, so a second writer's push is
/// rejected rather than interleaved (`docs/19` §2.2). A failure is judged by asking the remote
/// where its branch is, never by `git`'s wording: at `pushed`, the commit just sent, it took the
/// push and the connection went before it said so; moved from `base`, the commit this one was
/// built on, another writer won; still at `base`, the failure is the error it is. `--no-signed`,
/// so that the operator's `push.gpgSign` neither signs a push nor waits on a passphrase.
pub(crate) fn push(dir: &Path, branch: &str, base: &str, pushed: &str) -> Result<Pushed> {
    let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
    let out = network(Some(dir))
        .args(["push", "--porcelain", "--no-signed", "origin", &refspec])
        .output()
        .map_err(|e| anyhow!("running git: {e}"))?;
    if out.status.success() {
        return Ok(Pushed::Yes);
    }
    let said = scrub(
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .trim(),
    );
    let remote =
        remote_head(dir, branch).map_err(|e| anyhow!("git push failed ({said}), and then {e}"))?;
    match remote.as_deref() {
        Some(r) if r == pushed => Ok(Pushed::Yes),
        Some(r) if r == base => bail!(
            "git push failed, and the remote's `{branch}` is still the commit this was built on, \
             so nobody else won: {said}"
        ),
        _ => Ok(Pushed::LostRace),
    }
}

/// Whether `origin` would take a push of a commit on top of `parent` to `branch` — `None` for a
/// branch it does not have — asked with `push --dry-run`, which connects and authenticates as a
/// push does and sends nothing. The commit is an empty one, made in the clone at `dir` only to be
/// named, and left there.
pub(crate) fn would_take_a_push(dir: &Path, branch: &str, parent: Option<&str>) -> Result<()> {
    let tree = text(Some(dir), &["mktree"])?;
    let mut args = vec![
        "commit-tree",
        tree.as_str(),
        "-m",
        "trigon: can this be pushed?",
    ];
    if let Some(p) = parent {
        args.extend(["-p", p]);
    }
    let out = command(Some(dir))
        .args(&args)
        .env("GIT_AUTHOR_NAME", COMMITTER.0)
        .env("GIT_AUTHOR_EMAIL", COMMITTER.1)
        .env("GIT_COMMITTER_NAME", COMMITTER.0)
        .env("GIT_COMMITTER_EMAIL", COMMITTER.1)
        .output()
        .map_err(|e| anyhow!("running git: {e}"))?;
    if !out.status.success() {
        bail!(
            "git commit-tree failed: {}",
            scrub(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    let probe = String::from_utf8_lossy(&out.stdout).trim().to_string();
    run_network(
        Some(dir),
        &[
            "push",
            "--dry-run",
            "--quiet",
            "--no-signed",
            "origin",
            &format!("{probe}:refs/heads/{branch}"),
        ],
    )
    .map(|_| ())
}

/// The commit `branch` is at on `origin`, asked of the remote itself; `None` where it has no such
/// branch. `ls-remote` matches a pattern against the end of every ref, so the one line whose ref
/// is exactly the branch is the answer: `refs/heads/a/refs/heads/main` is some other branch.
pub(crate) fn remote_head(dir: &Path, branch: &str) -> Result<Option<String>> {
    let want = format!("refs/heads/{branch}");
    let out = run_network(Some(dir), &["ls-remote", "--heads", "origin", &want])?;
    Ok(String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        let mut f = l.split_whitespace();
        let id = f.next()?;
        (f.next()? == want).then(|| id.to_string())
    }))
}

/// Whether `path` is a working tree's top directory (`Some(true)`), a bare repository
/// (`Some(false)`), or neither.
pub(crate) fn kind_of(path: &Path) -> Result<Option<bool>> {
    if !succeeds(Some(path), &["rev-parse", "--git-dir"]) {
        // Not a repository of its own. Asked again, looking further up, only to say which working
        // tree it is inside, if any.
        let mut c = command(Some(path));
        c.env_remove("GIT_CEILING_DIRECTORIES");
        let top = c
            .args(["rev-parse", "--show-toplevel"])
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|t| !t.is_empty());
        if let Some(top) = top {
            bail!(
                "{} is inside the working tree {top}, not its top; name the repository by its top \
                 directory",
                path.display()
            );
        }
        return Ok(None);
    }
    if text(Some(path), &["rev-parse", "--is-bare-repository"])? == "true" {
        return Ok(Some(false));
    }
    let top = PathBuf::from(text(Some(path), &["rev-parse", "--show-toplevel"])?);
    let same = match (top.canonicalize(), path.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        bail!(
            "{} is inside the working tree {}, not its top; name the repository by its top \
             directory",
            path.display(),
            top.display()
        );
    }
    Ok(Some(true))
}

/// Why a working tree cannot be published into, or `None` where it can: it must be on `branch`,
/// and clean, untracked files included; and under `paths`, where a publication reads and writes,
/// it must hold no file git ignores either, since one there would be read as the repository's and
/// never committed.
pub(crate) fn unfit_to_publish_into(
    tree: &Path,
    branch: &str,
    paths: &[&str],
) -> Result<Option<String>> {
    let on = text(Some(tree), &["symbolic-ref", "--quiet", "--short", "HEAD"]).unwrap_or_default();
    if on != branch {
        return Ok(Some(format!(
            "it is on `{}`, and [publish] branch is `{branch}`",
            if on.is_empty() { "no branch" } else { &on }
        )));
    }
    let status = text(
        Some(tree),
        &["status", "--porcelain", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        let n = status.lines().count();
        return Ok(Some(format!(
            "it has {n} uncommitted change(s), and what a publication reads must be what is \
             committed. Commit or remove them; if an interrupted `trigon publish` left them, `git \
             -C {} reset --hard && git -C {} clean -fd` discards them",
            tree.display(),
            tree.display()
        )));
    }
    let mut args = vec![
        "--literal-pathspecs",
        "status",
        "--porcelain",
        "--ignored",
        "--untracked-files=all",
        "--",
    ];
    args.extend_from_slice(paths);
    let ignored = text(Some(tree), &args)?;
    if !ignored.is_empty() {
        let n = ignored.lines().count();
        return Ok(Some(format!(
            "it has {n} file(s) git ignores under {}, where a publication reads and writes: one \
             there would be read as the repository's and never committed. Remove them; `git -C {} \
             clean -fdX -- {}` does",
            paths.join(", "),
            tree.display(),
            paths.join(" ")
        )));
    }
    Ok(None)
}

/// Why the tree `treeish` in the repository at `dir` cannot be published to, or `None`: it names
/// git attributes, in a `.gitattributes` file anywhere or in the git directory's
/// `info/attributes`. An attribute can name a filter or a line-end conversion, which `git` runs on
/// every checkout, so the files a publication reads would not be the blobs every client clones.
/// Asked before `treeish` is checked out, so that no such filter ever runs; `None` for `treeish`
/// is a branch with no commit yet.
pub(crate) fn attributes(dir: &Path, treeish: Option<&str>) -> Result<Option<String>> {
    let info = text(Some(dir), &["rev-parse", "--git-path", "info/attributes"])?;
    let info = dir.join(info);
    if std::fs::symlink_metadata(&info).is_ok() {
        return Ok(Some(format!(
            "{} is there, and git attributes can rewrite the bytes a publication reads and \
             writes. Remove it",
            info.display()
        )));
    }
    let Some(treeish) = treeish else {
        return Ok(None);
    };
    let mut child = command(Some(dir))
        .args(["ls-tree", "-r", "-z", "--name-only", treeish])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("running git: {e}. Is git installed and on PATH?"))?;
    let mut names = BufReader::new(child.stdout.take().expect("stdout is piped"));
    let mut name = Vec::new();
    let mut named = None;
    while names.read_until(0, &mut name)? > 0 {
        let path = name.strip_suffix(&[0]).unwrap_or(&name);
        if path.rsplit(|b| *b == b'/').next() == Some(b".gitattributes".as_slice()) {
            named = Some(String::from_utf8_lossy(path).into_owned());
            break;
        }
        name.clear();
    }
    if named.is_some() {
        let _ = child.kill();
    }
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    let status = child.wait()?;
    if let Some(path) = named {
        return Ok(Some(format!(
            "it has `{}`, and git attributes can name a filter or a line-end conversion that \
             rewrites the bytes of the files a publication reads, on every checkout. Remove it \
             from the branch",
            trigon_attest::location::printable(&path)
        )));
    }
    if !status.success() {
        bail!("git ls-tree -r {treeish} failed: {}", scrub(err.trim()));
    }
    Ok(None)
}

/// The blob at each of `revs`, each `<commit>:<path>`, or `None` where there is none: asked of one
/// `git cat-file --batch`.
pub(crate) fn blobs(dir: &Path, revs: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
    let out = run_with_input(dir, &["cat-file", "--batch"], lines_of(revs)?)?;
    read_batch(&out.stdout, revs)
}

/// [`blobs`], in a partial clone: a blob its objects do not hold is fetched from the remote it was
/// cloned from, which `git` does on its own when one is read, so this runs as a command that
/// reaches a remote ([`network`]) — and names each blob fetched to the host that serves it.
pub(crate) fn blobs_fetching(dir: &Path, revs: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
    let out = feed(network(Some(dir)), &["cat-file", "--batch"], lines_of(revs)?)?;
    read_batch(&out.stdout, revs)
}

/// Whether each of `revs` is an object the clone's objects hold already, asked with fetching
/// turned off: what says whether reading it will name it to the host. One `git cat-file -e` each,
/// whose exit answers; `--batch-check` stops at the first missing object of a partial clone
/// instead of saying it is missing, when fetching is off.
pub(crate) fn blobs_held(dir: &Path, revs: &[String]) -> Result<Vec<bool>> {
    revs.iter()
        .map(|r| {
            if r.starts_with('-') || r.contains('\n') {
                bail!("`{r}` is not a revision");
            }
            Ok(command(Some(dir))
                .env("GIT_NO_LAZY_FETCH", "1")
                .args(["cat-file", "-e", r])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success()))
        })
        .collect()
}

/// `revs`, one to a line, as `git cat-file --batch` reads them.
fn lines_of(revs: &[String]) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    for r in revs {
        if r.contains('\n') {
            bail!("`{r}` is not a revision");
        }
        input.extend_from_slice(r.as_bytes());
        input.push(b'\n');
    }
    Ok(input)
}

/// What `git cat-file --batch` printed for `revs`, blob by blob.
fn read_batch(stdout: &[u8], revs: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
    let mut rest = stdout;
    let mut found = Vec::with_capacity(revs.len());
    for _ in revs {
        let nl = rest
            .iter()
            .position(|b| *b == b'\n')
            .context("git cat-file --batch stopped early")?;
        let header = String::from_utf8_lossy(&rest[..nl]).into_owned();
        rest = &rest[nl + 1..];
        let f: Vec<&str> = header.split(' ').collect();
        match (f.get(1), f.get(2).and_then(|s| s.parse::<usize>().ok())) {
            (Some(kind), Some(size)) if rest.len() > size => {
                found.push((*kind == "blob").then(|| rest[..size].to_vec()));
                rest = &rest[size + 1..];
            }
            // `<rev> missing`, or `ambiguous`: nothing follows the line.
            _ if f.len() == 2 => found.push(None),
            _ => bail!("git cat-file --batch printed `{header}`"),
        }
    }
    Ok(found)
}

/// `s` with the user part of every URL in it replaced by `***`: what `git` prints may quote a
/// location, and a location reached through a credential helper is never shown with a secret in
/// it, however `git` came to print one.
pub(crate) fn scrub(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("://") {
        let (before, after) = rest.split_at(at + 3);
        out.push_str(before);
        let end = after
            .find(|c: char| c == '/' || c.is_whitespace() || c == '\'' || c == '"')
            .unwrap_or(after.len());
        let authority = &after[..end];
        match authority.rfind('@') {
            Some(i) => {
                out.push_str("***");
                out.push_str(&authority[i..]);
            }
            None => out.push_str(authority),
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTPS and SSH cannot be pushed to offline, so what they reach `git` as is asserted here:
    /// exactly as configured, after `--`, never rewritten, and nothing but the location and the
    /// directory beside the fixed flags.
    #[test]
    fn a_location_reaches_git_exactly_as_it_was_configured() {
        let dir = Path::new("/store/publish/x/clone");
        for written in [
            "https://github.com/owner/trigon-evidence.git",
            "ssh://git@example.org/owner/trigon-evidence.git",
            "git@github.com:owner/trigon-evidence.git",
            "git://example.org/trigon-evidence.git",
            "http://example.org/trigon-evidence.git",
            "file:///srv/trigon-evidence.git",
        ] {
            let l = Location::parse(written, Path::new("/cwd"), None).unwrap();
            let args = clone_args(&l, dir);
            let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
            assert_eq!(
                args,
                [
                    "clone",
                    "--quiet",
                    "--no-tags",
                    "--no-checkout",
                    "--",
                    written,
                    "/store/publish/x/clone"
                ],
                "{written}"
            );
        }
        // A local path, made absolute and nothing else.
        let l = Location::parse("./evidence", Path::new("/cwd"), None).unwrap();
        assert_eq!(clone_args(&l, dir)[5], "/cwd/evidence");
    }

    /// A missing credential fails rather than waits for a person, a caller's `GIT_DIR` cannot
    /// point `publish` at another repository, `git` looks for the repository in the directory it
    /// is given and no further up, and neither line ends nor the operator's attributes change a
    /// byte between a blob and its file.
    #[test]
    fn git_never_prompts_and_never_follows_a_callers_repository() {
        let c = command(Some(Path::new("/tmp/store/clone")));
        let envs: Vec<(String, Option<String>)> = c
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(envs.contains(&("GIT_TERMINAL_PROMPT".into(), Some("0".into()))));
        assert!(envs.contains(&("GIT_ATTR_NOSYSTEM".into(), Some("1".into()))));
        assert!(envs.contains(&("GIT_CEILING_DIRECTORIES".into(), Some("/tmp/store".into()))));
        for v in REPOSITORY_VARIABLES {
            assert!(envs.contains(&(v.into(), None)), "{v} is not removed");
        }
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for p in PINNED {
            assert!(
                args.windows(2).any(|w| w[0] == "-c" && w[1] == p),
                "{p}: {args:?}"
            );
        }
        // The operator's credentials are git's own, so nothing that reaches them is switched off.
        for kept in [
            "GIT_ASKPASS",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "HOME",
        ] {
            assert!(!envs.iter().any(|(k, _)| k == kept), "{kept} is touched");
        }
    }

    /// ssh asks for a passphrase or a host key on the terminal whatever `git` is told, so it runs
    /// with `BatchMode=yes`: plain `ssh` with it where nothing is configured, the operator's
    /// `ssh` command with it added, and a command that is not `ssh` left as it is.
    #[test]
    fn ssh_is_told_never_to_ask() {
        assert_eq!(batch_mode(None).as_deref(), Some("ssh -o BatchMode=yes"));
        assert_eq!(
            batch_mode(Some("ssh -i ~/.ssh/deploy")).as_deref(),
            Some("ssh -i ~/.ssh/deploy -o BatchMode=yes")
        );
        assert_eq!(
            batch_mode(Some("/usr/bin/ssh -F /etc/evidence")).as_deref(),
            Some("/usr/bin/ssh -F /etc/evidence -o BatchMode=yes")
        );
        assert_eq!(
            batch_mode(Some("'/opt/my ssh/ssh'")).as_deref(),
            Some("'/opt/my ssh/ssh' -o BatchMode=yes")
        );
        assert_eq!(batch_mode(Some("plink -batch")), None);
        assert_eq!(batch_mode(Some("/usr/local/bin/ssh-wrapper")), None);
    }

    #[test]
    fn what_git_prints_is_shown_with_no_user_part_in_any_url() {
        assert_eq!(
            scrub("fatal: could not read from 'https://x-token:ghp_secret@github.com/o/r.git/'"),
            "fatal: could not read from 'https://***@github.com/o/r.git/'"
        );
        assert_eq!(
            scrub("To https://ghp_secret@github.com/o/r.git\n ! [rejected]"),
            "To https://***@github.com/o/r.git\n ! [rejected]"
        );
        assert_eq!(
            scrub("ssh://git@example.org/o/r.git and https://github.com/o/r"),
            "ssh://***@example.org/o/r.git and https://github.com/o/r"
        );
        assert_eq!(scrub("no url here"), "no url here");
    }

    /// A scratch directory for a test that runs `git`, removed when dropped.
    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Dir {
            let d = std::env::temp_dir().join(format!("trigon-git-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Dir(d)
        }

        /// `git` in `dir` under this directory, with no configuration of the host's.
        fn git(&self, dir: &str, args: &[&str]) -> String {
            let out = Command::new("git")
                .arg("-C")
                .arg(self.0.join(dir))
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A branch whose name ends in `refs/heads/main` sorts before `main` in `ls-remote`, which
    /// matches patterns against the end of a ref; it is some other branch, and never the answer.
    #[test]
    fn the_remote_head_is_the_branch_named_and_no_other_ending_in_its_name() {
        let d = Dir::new("remote-head");
        d.git(".", &["init", "--quiet", "--bare", "-b", "main", "r.git"]);
        d.git(".", &["init", "--quiet", "-b", "main", "w"]);
        std::fs::write(d.0.join("w/a"), "a").unwrap();
        d.git("w", &["add", "a"]);
        d.git("w", &["commit", "--quiet", "-m", "a"]);
        let main = d.git("w", &["rev-parse", "HEAD"]);
        d.git("w", &["push", "--quiet", "../r.git", "main"]);
        d.git("w", &["checkout", "--quiet", "-b", "a/refs/heads/main"]);
        d.git("w", &["commit", "--quiet", "--allow-empty", "-m", "b"]);
        d.git("w", &["push", "--quiet", "../r.git", "a/refs/heads/main"]);
        d.git(".", &["clone", "--quiet", "r.git", "c"]);
        let listed = d.git("c", &["ls-remote", "--heads", "origin", "refs/heads/main"]);
        assert!(
            listed
                .lines()
                .next()
                .unwrap()
                .ends_with("refs/heads/a/refs/heads/main"),
            "{listed}"
        );
        assert_eq!(remote_head(&d.0.join("c"), "main").unwrap(), Some(main));
        assert_eq!(remote_head(&d.0.join("c"), "other").unwrap(), None);
    }

    /// A clone directory whose `.git` is gone is not a clone, whatever repository encloses it:
    /// `git` is never let look further up, where it would find the enclosing one.
    #[test]
    fn a_directory_without_a_repository_of_its_own_is_never_taken_for_the_one_around_it() {
        let d = Dir::new("enclosed");
        d.git(".", &["init", "--quiet", "-b", "main", "project"]);
        std::fs::create_dir_all(d.0.join("project/store/clone")).unwrap();
        let clone = d.0.join("project/store/clone");
        assert!(!succeeds(Some(&clone), &["rev-parse", "--git-dir"]));
        assert!(!is_clone_at(&clone));
        d.git("project/store", &["init", "--quiet", "-b", "main", "clone"]);
        assert!(is_clone_at(&clone));
        // A `.git` that leads to another repository is not this directory's own.
        std::fs::remove_dir_all(clone.join(".git")).unwrap();
        std::fs::write(
            clone.join(".git"),
            format!("gitdir: {}\n", d.0.join("project/.git").display()),
        )
        .unwrap();
        assert!(!is_clone_at(&clone));
        // And a subdirectory of a working tree is said to be one, not taken for its top.
        let e = kind_of(&d.0.join("project/store")).unwrap_err().to_string();
        assert!(e.contains("is inside the working tree"), "{e}");
    }

    /// A commit holds exactly the bytes written and the paths removed, whatever the tree's
    /// `.gitignore` and `.gitattributes` say: a line-end conversion never rewrites a file, an
    /// ignored path is committed, and a directory where a file is written goes with it.
    #[test]
    fn a_commit_holds_exactly_what_was_written_whatever_the_tree_ignores() {
        let d = Dir::new("commit");
        d.git(".", &["init", "--quiet", "-b", "main", "w"]);
        let w = d.0.join("w");
        std::fs::write(w.join(".gitignore"), "tile/\nrecords/\n").unwrap();
        std::fs::write(w.join(".gitattributes"), "* text\n").unwrap();
        std::fs::create_dir_all(w.join("d/x")).unwrap();
        std::fs::write(w.join("d/x/f"), "planted").unwrap();
        std::fs::write(w.join("gone"), "old").unwrap();
        d.git("w", &["add", "--all"]);
        d.git("w", &["commit", "--quiet", "-m", "base"]);
        let base = d.git("w", &["rev-parse", "HEAD"]);

        let crlf: &[u8] = b"\x01\x02\r\n\x03";
        std::fs::create_dir_all(w.join("log/tile/0/000.p")).unwrap();
        std::fs::write(w.join("log/tile/0/000.p/1"), crlf).unwrap();
        std::fs::create_dir_all(w.join("records")).unwrap();
        std::fs::write(w.join("records/a.json"), b"{}\n").unwrap();
        std::fs::remove_dir_all(w.join("d/x")).unwrap();
        std::fs::write(w.join("d/x"), b"file").unwrap();
        std::fs::remove_file(w.join("gone")).unwrap();
        let change = Change {
            writes: vec![
                ("log/tile/0/000.p/1", crlf),
                ("records/a.json", b"{}\n"),
                ("d/x", b"file"),
            ],
            removes: vec!["gone"],
        };
        let head = commit(&w, Some(&base), &change, "publish: test").unwrap();
        let shown = |path: &str| {
            Command::new("git")
                .arg("-C")
                .arg(&w)
                .args(["cat-file", "blob", &format!("{head}:{path}")])
                .output()
                .unwrap()
                .stdout
        };
        assert_eq!(shown("log/tile/0/000.p/1"), crlf);
        assert_eq!(shown("records/a.json"), b"{}\n");
        assert_eq!(shown("d/x"), b"file");
        let files = d.git("w", &["ls-tree", "-r", "--name-only", &head]);
        assert!(
            !files.contains("gone") && !files.contains("d/x/f"),
            "{files}"
        );
        assert_eq!(
            d.git("w", &["log", "-1", "--format=%an <%ae>|%s|%G?", &head]),
            "trigon publish <publish@trigon.invalid>|publish: test|N"
        );

        // Bytes on disk that are not the bytes given are refused before anything is committed.
        std::fs::write(w.join("records/b.json"), b"other").unwrap();
        let e = commit(
            &w,
            Some(&head),
            &Change {
                writes: vec![("records/b.json", b"meant")],
                removes: Vec::new(),
            },
            "publish: test",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("is not what was written there"), "{e}");
        assert_eq!(d.git("w", &["rev-parse", "HEAD"]), head);

        // A commit whose parent is not the one it was built on is not the publication.
        d.git("w", &["reset", "--quiet", "--hard", &head]);
        std::fs::write(w.join("records/c.json"), b"c").unwrap();
        let e = commit(
            &w,
            Some(&base),
            &Change {
                writes: vec![("records/c.json", b"c")],
                removes: Vec::new(),
            },
            "publish: test",
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("was to be made on"), "{e:#}");

        // Anything else already staged would go into the commit with the publication: refused.
        d.git("w", &["reset", "--quiet", "--hard", &head]);
        std::fs::write(w.join("extra"), b"staged before").unwrap();
        d.git("w", &["add", "extra"]);
        std::fs::write(w.join("records/d.json"), b"d").unwrap();
        let e = commit(
            &w,
            Some(&head),
            &Change {
                writes: vec![("records/d.json", b"d")],
                removes: Vec::new(),
            },
            "publish: test",
        )
        .unwrap_err();
        assert!(
            format!("{e:#}").contains("it changes `extra`, which the publication does not write"),
            "{e:#}"
        );
    }

    #[test]
    fn a_blob_id_is_gits_own() {
        let d = Dir::new("blob-id");
        d.git(".", &["init", "--quiet", "-b", "main", "w"]);
        std::fs::write(d.0.join("w/f"), b"\x00\r\nbytes").unwrap();
        let git = d.git("w", &["hash-object", "--no-filters", "f"]);
        assert_eq!(blob_id("sha1", b"\x00\r\nbytes").unwrap(), git);
        assert_eq!(
            blob_id("sha256", b"").unwrap(),
            "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
        );
        assert!(blob_id("sha3", b"").is_err());
    }
}
