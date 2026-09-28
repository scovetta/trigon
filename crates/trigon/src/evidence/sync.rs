//! A source's clones, verified, and its state updated only then (`docs/19` §6, §6.1).
//!
//! **One clone per location**, at `<cache>/<name>/<sha256 of the location>/`: every URL of a
//! source — one log and its mirrors — and every URL a log-end names for a successor in another
//! repository, which is part of the same source. A remote is cloned shallow, partial and sparse —
//! `git clone --depth 1 --filter=blob:none --sparse`, then `git sparse-checkout set keys log
//! records` — so `index/` and `evidence/` stay out; a local path is cloned in full, since `git`
//! ignores depth and filters there. A sync is `git fetch --depth 1 origin <branch>` and then `git
//! reset --hard FETCH_HEAD`, never a pull: a shallow clone has no merge base to fast-forward from.
//! `--full-history` keeps the whole history instead and says when a fetch is not a fast-forward.
//!
//! **Every clone reads exactly the blobs.** A repository's own `.gitattributes` could have a
//! checkout rewrite line ends in the files a client verifies, so each clone's
//! `.git/info/attributes`, which outranks every attributes file in the tree, unsets every attribute
//! that changes bytes. `git` itself runs as `publish` runs it ([`crate::publish::git`]): it never
//! prompts, ssh runs in batch mode, it looks for no repository above the clone, and a credential is
//! never on argv or in what is printed. Nothing the repository names reaches argv as a bare word:
//! its default branch, which a clone takes from it, is refused unless `git` would make a branch of
//! the name, and is fetched as `refs/heads/<branch>` after `--`, so that a branch named
//! `--upload-pack=<command>` is never an option.
//!
//! **A clone is kept only once a sync accepts it.** It is made beside where it goes, under a name
//! beginning with a dot, marked unaccepted, and only then moved into place; the mark comes off when
//! the sync is accepted. A sync stopped anywhere before that — a kill while `git clone` runs, a
//! timeout during verification — leaves nothing that counts as a sync that finished, and the next
//! sync makes the clone again rather than fetching into it.
//!
//! **A project's source goes on over HTTPS only.** Its log-end is signed by the key the project
//! pins, so a successor elsewhere it names at any other location is refused, as the project's file
//! itself would be: the thing under test never chooses where this client connects.
//!
//! **Verified before anything is accepted**, each clone by itself with the phase 4 code — the
//! checkpoint under the source's log key, the root recomputed from every leaf, times that never go
//! back, every key change and succession followed — then every location held to every other:
//! copies of one log that are not one log are an equivocation, with both signed notes. The largest
//! copy answers; a smaller one is lagging. The whole chain, across repositories, is then held to the
//! checkpoint last accepted, and its key history recomputed and compared with the one kept. Only
//! then is the state written, and a new clone kept. A sync that is refused keeps every clone as it
//! was and the state untouched.
//!
//! **The state is what a rollback is caught against**, so a source that has synced before and has
//! lost it is not silently given a new one: the sync is refused until `--accept-state-loss <name>`
//! says the loss is known. Only what was lost starts over then: keys first read that survive a lost
//! checkpoint still pin the source, and a checkpoint that survives lost keys must open under the
//! keys read again.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use sha2::Digest as _;
use trigon_attest::config::{AddedBy, EvidenceConfig, Source, read_checkpoint_file};
use trigon_attest::evidence::Repository;
use trigon_attest::location::{Location, Transport, printable};
use trigon_attest::log::{
    DirFiles, LogError, LogFiles as _, VerifiedLog, VerifiedSource, compare_chains,
    verify_continuation, verify_source,
};
use trigon_attest::state::{
    self, Failure, FirstUse, KeysFile, LogSeen, StateError, SyncRecord, UNACCEPTED, UrlSeen,
};
use trigon_attest::{AttestationKey, LogVkey};

use crate::publish::git;

/// What a clone's working tree holds (`docs/19` §6): `index/` and `evidence/` stay out, and are
/// read from git's objects when a command asks for them.
const SPARSE: [&str; 3] = ["keys", "log", "records"];

/// `.git/info/attributes` of every clone: every attribute that could make a checked-out file other
/// than its blob, unset for every path. It outranks the tree's own `.gitattributes`, which whoever
/// can push writes.
const NO_ATTRIBUTES: &str = "* -text -eol -filter -ident -working-tree-encoding\n";

/// The longest `keys/*` file read: a PEM key or a verifier key is under 200 bytes.
const KEY_FILE_LIMIT: u64 = 16 * 1024;

/// The longest chain of repositories followed: a succession into another repository is a rare
/// event, and a chain longer than this is a loop or an attack.
const MOST_REPOSITORIES: usize = 64;

/// How a sync runs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Options {
    pub full_history: bool,
    pub accept_state_loss: bool,
    pub verbose: bool,
    /// Now, in Unix seconds: what the sync record is stamped with.
    pub now: u64,
}

/// Where a source's clones and state are.
#[derive(Clone, Debug)]
pub(crate) struct Dirs {
    /// `<cache>/<name>`: one clone per location under it.
    pub cache: PathBuf,
    /// `<state>/<name>`: the checkpoint last accepted, the key history, the sync record.
    pub state: PathBuf,
}

impl Dirs {
    pub(crate) fn of(config: &EvidenceConfig, name: &str) -> anyhow::Result<Dirs> {
        Ok(Dirs {
            cache: config.cache_dir()?.join(name),
            state: config.source_state_dir(name)?,
        })
    }

    /// Where the clone of `location` is kept.
    fn clone_of(&self, location: &Location) -> PathBuf {
        let hash = sha2::Sha256::digest(location.as_git_arg().as_bytes());
        self.cache.join(hex(&hash))
    }

    /// Whether any clone of the source is kept that a sync accepted: evidence that it has synced
    /// before, whatever its state directory now says.
    pub(crate) fn has_clone(&self) -> bool {
        state::has_accepted_clone(&self.cache)
    }
}

/// The keys a source's chain is verified from: its pinned ones, or those trust on first use read,
/// with where and when.
#[derive(Clone, Debug)]
pub(crate) struct StartKeys {
    pub log: LogVkey,
    pub attestation: AttestationKey,
    pub first_use: Option<FirstUse>,
}

/// A source's chain, verified: what its answers come from.
pub(crate) struct Opened {
    pub repo: Repository,
    pub keys: StartKeys,
    /// The checkpoint of the chain's last log, the signed note as its clone holds it.
    pub checkpoint: Vec<u8>,
    /// Each location, and what was found there.
    pub urls: Vec<UrlSeen>,
    /// What a person is told: a mirror lagging, a succession followed, a first checkpoint
    /// accepted, a key history that disagreed with the log.
    pub notes: Vec<String>,
}

impl Opened {
    /// The last log of the chain, which answers are as of.
    pub(crate) fn last(&self) -> &VerifiedLog {
        &self
            .repo
            .source()
            .logs
            .last()
            .expect("a chain has a log")
            .log
    }

    /// The chain's logs, each with its size.
    fn logs_seen(&self) -> Vec<LogSeen> {
        self.repo
            .logs()
            .iter()
            .map(|l| LogSeen {
                origin: l.origin().to_string(),
                size: l.size(),
            })
            .collect()
    }
}

/// Why a source could not be synced or opened.
#[derive(Debug)]
pub(crate) struct Failed {
    /// Whether the source failed verification — it may be lying, and `docs/19` §6 gives that exit
    /// 4 — rather than could not be reached or read.
    pub refused: bool,
    pub error: anyhow::Error,
    /// What was found before it failed, for a person.
    pub urls: Vec<UrlSeen>,
}

impl Failed {
    fn refused(error: impl Into<anyhow::Error>) -> Failed {
        Failed {
            refused: true,
            error: error.into(),
            urls: Vec::new(),
        }
    }

    fn unreadable(error: impl Into<anyhow::Error>) -> Failed {
        Failed {
            refused: false,
            error: error.into(),
            urls: Vec::new(),
        }
    }

    /// A log that failed verification refuses the source; one that could not be read leaves it
    /// unreadable.
    fn of_log(e: LogError, context: String) -> Failed {
        let refused = e.fails_verification();
        Failed {
            refused,
            error: anyhow::Error::new(e).context(context),
            urls: Vec::new(),
        }
    }
}

/// What a sync, or an offline open, found at a location: the clone to verify, or why there is
/// none.
enum Reached {
    Copy { dir: PathBuf, note: Option<String> },
    Missing(String),
}

/// A clone a sync changed, so that a refusal can put it back.
enum Touched {
    /// Made by this sync: removed if it is refused, and marked accepted if it is not.
    New(PathBuf),
    /// Fetched and reset from `previous`, where it is put back if it is refused.
    Moved { dir: PathBuf, previous: String },
}

/// Clones for a sync: fetched where they are, made where they are not, each recorded so the sync
/// can be undone.
struct Fetcher<'a> {
    dirs: &'a Dirs,
    full_history: bool,
    verbose: bool,
    touched: Vec<Touched>,
}

impl Fetcher<'_> {
    fn reach(&mut self, location: &Location) -> Reached {
        let dir = self.dirs.clone_of(location);
        // A clone still marked unaccepted is what a sync stopped before it was accepted left
        // behind — a kill, a timeout — and is made again rather than fetched into: only a clone
        // this sync makes has its mark taken off when the sync is accepted.
        let kept = git::is_clone_at(&dir)
            && !dir.join(".git").join(UNACCEPTED).exists()
            && branch_of(&dir).is_ok();
        let fetched = match kept {
            true => self.fetch(location, &dir),
            false => self.make(location, &dir),
        };
        match fetched {
            Ok(note) => Reached::Copy { dir, note },
            Err(e) => Reached::Missing(printable(&format!("{e:#}"))),
        }
    }

    /// Bring an existing clone to what the location serves now.
    fn fetch(&mut self, location: &Location, dir: &Path) -> anyhow::Result<Option<String>> {
        let branch = branch_of(dir)?;
        let previous = git::text(Some(dir), &["rev-parse", "--verify", "HEAD"])?;
        let shallow = git::text(Some(dir), &["rev-parse", "--is-shallow-repository"])? == "true";
        git::run(
            Some(dir),
            &["remote", "set-url", "origin", location.as_git_arg()],
        )?;
        // Put back every time: whoever writes the cache could have removed it.
        write_attributes(dir)?;
        let mut args = vec!["fetch", "--quiet", "--no-tags"];
        match (shallow, self.full_history) {
            (true, true) => args.push("--unshallow"),
            (true, false) => args.extend(["--depth", "1"]),
            (false, _) => {}
        }
        // The branch as a whole ref, and after `--`: its name is the repository's to choose, and
        // one beginning with a dash would be read as an option — `--upload-pack=<command>` runs
        // the command — whatever `branch_of` has refused already.
        let refspec = format!("refs/heads/{branch}");
        args.extend(["--", "origin", refspec.as_str()]);
        git::run_network(Some(dir), &args)?;
        let mut note = None;
        // A clone with its history can say whether the branch moved on from what it held, or was
        // rewritten: the log decides what that means, and this says it happened.
        if !shallow || self.full_history {
            let forward = git::succeeds(
                Some(dir),
                &["merge-base", "--is-ancestor", &previous, "FETCH_HEAD"],
            );
            if !forward {
                note = Some(format!(
                    "the fetch is not a fast-forward from {previous}: the branch's history was \
                     rewritten, whatever its log says"
                ));
            }
        }
        git::run(Some(dir), &["reset", "--quiet", "--hard", "FETCH_HEAD"])?;
        // Nothing but the commit: a file left in the working tree, by a kill or by whoever can
        // write the cache, would be read as the repository's.
        git::run(Some(dir), &["clean", "-ffdxq"])?;
        self.touched.push(Touched::Moved {
            dir: dir.to_path_buf(),
            previous,
        });
        Ok(note)
    }

    /// Make a clone of `location` at `dir`, marked unaccepted until the sync is.
    fn make(&mut self, location: &Location, dir: &Path) -> anyhow::Result<Option<String>> {
        // Not a clone, or not one this can use — a `.git` gone, a clone no sync accepted — so
        // made again.
        remove_path(dir)?;
        let parent = parent_of(dir);
        std::fs::create_dir_all(&parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Cloned beside it under a name beginning with a dot, which is never taken for a clone,
        // and moved into place only once marked: a sync killed while `git clone` runs leaves
        // nothing that looks like a clone a sync accepted.
        let making = parent.join(format!(
            ".{}.making",
            dir.file_name().unwrap_or_default().to_string_lossy()
        ));
        remove_path(&making)?;
        let local = location.transport() == Transport::LocalPath;
        let mut args: Vec<std::ffi::OsString> = ["clone", "--quiet", "--no-tags", "--no-checkout"]
            .map(Into::into)
            .to_vec();
        if !local {
            if !self.full_history {
                args.extend(["--depth".into(), "1".into()]);
            }
            args.push("--filter=blob:none".into());
        }
        args.push("--sparse".into());
        args.push("--".into());
        args.push(location.as_git_arg().into());
        args.push(making.as_os_str().into());
        let made = (|| -> anyhow::Result<()> {
            git::run_network(None, &args)?;
            std::fs::write(making.join(".git").join(UNACCEPTED), b"")
                .with_context(|| format!("marking {}", making.display()))?;
            std::fs::rename(&making, dir).with_context(|| {
                format!("moving {} to {}", making.display(), dir.display())
            })?;
            branch_of(dir)?;
            write_attributes(dir)?;
            let mut set = vec!["sparse-checkout", "set"];
            set.extend(SPARSE);
            git::run(Some(dir), &set)?;
            if !git::succeeds(Some(dir), &["rev-parse", "--verify", "--quiet", "HEAD"]) {
                anyhow::bail!("it has no commits, so it holds no log");
            }
            git::run(Some(dir), &["reset", "--quiet", "--hard", "HEAD"])?;
            Ok(())
        })();
        if let Err(e) = made {
            let _ = remove_path(&making);
            let _ = remove_path(dir);
            return Err(e);
        }
        self.touched.push(Touched::New(dir.to_path_buf()));
        Ok((local && self.verbose).then(|| {
            "a local path, cloned in full: git ignores depth and filters for one".to_string()
        }))
    }

    /// The sync was refused: every clone as it was before it.
    fn put_back(self) {
        for t in self.touched.into_iter().rev() {
            match t {
                Touched::New(dir) => {
                    let _ = remove_path(&dir);
                }
                Touched::Moved { dir, previous } => {
                    let _ = git::run(Some(&dir), &["reset", "--quiet", "--hard", &previous])
                        .and_then(|_| git::run(Some(&dir), &["clean", "-ffdxq"]));
                }
            }
        }
    }

    /// The sync was accepted: every new clone is kept as the source's.
    fn keep(self) {
        for t in self.touched {
            if let Touched::New(dir) = t {
                let _ = std::fs::remove_file(dir.join(".git").join(UNACCEPTED));
            }
        }
    }
}

/// The branch a clone is on: the one the repository's `HEAD` named when it was cloned, and so the
/// repository's to choose. Refused unless `git` would make a branch of the name, which never
/// begins with a dash: one that does is an option wherever it reaches a command line.
fn branch_of(dir: &Path) -> anyhow::Result<String> {
    let branch = git::text(Some(dir), &["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    // `check-ref-format --branch` takes the argument after it as the name, whatever it begins
    // with.
    let valid = !branch.starts_with('-')
        && git::succeeds(Some(dir), &["check-ref-format", "--branch", &branch]);
    if !valid {
        anyhow::bail!(
            "its default branch is named `{}`, which is not a name git makes a branch of, so it is \
             not fetched",
            printable(&branch)
        );
    }
    Ok(branch)
}

fn parent_of(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn write_attributes(dir: &Path) -> anyhow::Result<()> {
    let info = dir.join(".git").join("info");
    std::fs::create_dir_all(&info).with_context(|| format!("creating {}", info.display()))?;
    std::fs::write(info.join("attributes"), NO_ATTRIBUTES)
        .with_context(|| format!("writing {}", info.join("attributes").display()))
}

/// Remove a directory, or a link or file where one is, never following a link.
fn remove_path(path: &Path) -> anyhow::Result<()> {
    let removed = match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(_) => Ok(()),
    };
    removed.with_context(|| format!("removing {}", path.display()))
}

/// A lock on one source, held while it is synced: two syncs of it — two jobs sharing a cache, a
/// lookup syncing a stale source while `evidence sync` runs — take turns rather than write one
/// clone and one state at once. Waited for, not refused: a sync that waits finds the other's work
/// done, and fetches again from there.
struct SourceLock {
    file: std::fs::File,
}

impl SourceLock {
    /// Held alone, by a sync, which changes the clones and the state.
    fn take(dirs: &Dirs) -> anyhow::Result<SourceLock> {
        std::fs::create_dir_all(&dirs.state)
            .with_context(|| format!("creating {}", dirs.state.display()))?;
        Self::lock(&dirs.state.join("lock"), libc::LOCK_EX)
    }

    /// Held beside other readers, by an open, which reads them: never while a sync is changing
    /// them. `None` for a source with no state directory, which no sync has written yet — and an
    /// open makes none, so that looking changes nothing on disk.
    fn shared(dirs: &Dirs) -> anyhow::Result<Option<SourceLock>> {
        if !dirs.state.is_dir() {
            return Ok(None);
        }
        Self::lock(&dirs.state.join("lock"), libc::LOCK_SH).map(Some)
    }

    fn lock(path: &Path, how: libc::c_int) -> anyhow::Result<SourceLock> {
        use std::os::fd::AsRawFd as _;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .with_context(|| format!("opening the lock {}", path.display()))?;
        // SAFETY: the descriptor is owned by `file` and outlives the call.
        if unsafe { libc::flock(file.as_raw_fd(), how) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("locking {}", path.display()));
        }
        Ok(SourceLock { file })
    }
}

impl Drop for SourceLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        // SAFETY: the descriptor is owned by `self.file`, which is still open here.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// What the state directory holds of a source before a sync or an open.
struct Held {
    accepted: Option<Vec<u8>>,
    keys: Option<KeysFile>,
    sync: Option<SyncRecord>,
}

impl Held {
    fn read(dirs: &Dirs) -> Result<Held, StateError> {
        Ok(Held {
            accepted: state::read_checkpoint(&dirs.state)?,
            keys: KeysFile::read(&dirs.state)?,
            sync: SyncRecord::read(&dirs.state)?,
        })
    }

    /// Whether the source has synced before: a clone a sync accepted is kept, a sync worked, or
    /// one recorded keys trusted on first use — as [`state::synced_before`] reads it for the
    /// verifier.
    fn synced_before(&self, dirs: &Dirs) -> bool {
        dirs.has_clone()
            || self.sync.as_ref().is_some_and(|s| s.last_success.is_some())
            || self.keys.as_ref().is_some_and(|k| k.first_use.is_some())
    }

    /// What of the state a source that has synced before should have and does not: the
    /// checkpoint, and for one trusting on first use, the keys it read.
    fn lost(&self, source: &Source, dirs: &Dirs) -> Option<Lost> {
        if !self.synced_before(dirs) {
            return None;
        }
        let first_use = self.keys.as_ref().and_then(|k| k.first_use.as_ref());
        let lost = Lost {
            checkpoint: self.accepted.is_none(),
            keys: source.trust_on_first_use && first_use.is_none(),
        };
        (lost.checkpoint || lost.keys).then_some(lost)
    }
}

/// What a source that has synced before has lost of its state. Only what is lost is started over
/// when the loss is accepted: what survives still holds the log, so that losing one file never
/// undoes what the other pins.
struct Lost {
    /// The checkpoint last accepted, which a rollback is caught against.
    checkpoint: bool,
    /// For a source trusting on first use, the keys its first sync read: its only pin.
    keys: bool,
}

impl Lost {
    /// What is gone, with the files.
    fn said(&self, dirs: &Dirs) -> String {
        let mut out = Vec::new();
        if self.checkpoint {
            out.push(format!(
                "{} is not there",
                dirs.state.join(state::CHECKPOINT).display()
            ));
        }
        if self.keys {
            out.push(format!(
                "{} holds no keys first read from the repository, which this source trusts on \
                 first use",
                dirs.state.join(state::KEYS).display()
            ));
        }
        out.join(", and ")
    }

    /// What accepting the loss does: what the log is held to afterwards, and what is kept.
    fn accepting(&self, source: &Source, held: &Held) -> String {
        let held_to = match &source.checkpoint {
            Some(p) => format!("its initial checkpoint, {}", p.display()),
            None => "itself, from the first checkpoint that verifies".into(),
        };
        let first_use = held.keys.as_ref().and_then(|k| k.first_use.as_ref());
        match (self.checkpoint, self.keys) {
            (true, false) => match first_use {
                Some(f) => format!(
                    "the log is then held only to {held_to}, and still under the keys first read \
                     from {} at {}, which are kept",
                    printable(&f.read_from),
                    crate::rfc3339_from_unix(f.at)
                ),
                None => format!("the log is then held only to {held_to}"),
            },
            (false, _) => "its keys are then read again from `keys/` of the first location \
                 reached, as a first contact reads them, and the checkpoint last accepted, which \
                 is kept, must open under them and be extended: a log under other keys is refused"
                .into(),
            (true, true) => format!(
                "its keys are then read again from `keys/` of the first location reached, as a \
                 first contact reads them, and the log is held only to {held_to}"
            ),
        }
    }
}

/// The initial checkpoint a source is configured with, read.
fn initial(source: &Source) -> anyhow::Result<Option<Vec<u8>>> {
    match &source.checkpoint {
        Some(p) => read_checkpoint_file(p)
            .map(Some)
            .map_err(|why| anyhow!("the initial checkpoint {} {why}", p.display())),
        None => Ok(None),
    }
}

/// Sync one source (see the module's documentation), under its lock.
pub(crate) fn sync(source: &Source, dirs: &Dirs, opt: Options) -> Result<Opened, Failed> {
    let _lock = SourceLock::take(dirs).map_err(Failed::unreadable)?;
    let held = Held::read(dirs).map_err(Failed::unreadable)?;
    let mut notes = Vec::new();
    let lost = held.lost(source, dirs);
    if let Some(l) = &lost {
        if !opt.accept_state_loss {
            let f = Failed::refused(anyhow!(
                "`{name}` has synced before — {clone} — and its state is gone: {what}. The state \
                 is what a rollback is caught against, so it is not silently made again. If it was \
                 lost, on a new machine or with a cleared directory, run `trigon evidence sync \
                 --accept-state-loss {name}`: {accepting}",
                name = source.name,
                clone = match dirs.has_clone() {
                    true => format!("its clones are in {}", dirs.cache.display()),
                    false => "a sync of it worked".into(),
                },
                what = l.said(dirs),
                accepting = l.accepting(source, &held),
            ));
            record_failure(dirs, held.sync.clone(), &f, opt.now);
            return Err(f);
        }
        notes.push(format!(
            "state loss accepted: {}; {}",
            l.said(dirs),
            l.accepting(source, &held)
        ));
    }
    // Whatever of a lost state survives is kept: keys first read still pin a source whose
    // checkpoint is gone, and a checkpoint still holds keys read again. Only what is gone starts
    // over.
    let keys_held = held.keys.clone();
    let accepted = match held.accepted.clone() {
        Some(a) => Some(a),
        None => initial(source).map_err(Failed::unreadable)?,
    };
    let attempt = |failed: &Failed| {
        record_failure(dirs, held.sync.clone(), failed, opt.now);
    };

    let mut fetcher = Fetcher {
        dirs,
        full_history: opt.full_history,
        verbose: opt.verbose,
        touched: Vec::new(),
    };
    let first: Vec<Reached> = source.urls.iter().map(|l| fetcher.reach(l)).collect();
    let keys = match start_keys(source, keys_held.as_ref(), &first, opt.now) {
        Ok((keys, said)) => {
            notes.extend(said);
            keys
        }
        Err(f) => {
            fetcher.put_back();
            attempt(&f);
            return Err(f);
        }
    };
    let opened = chain(
        source,
        &keys,
        first,
        &mut |l| fetcher.reach(l),
        accepted.as_deref(),
    );
    let mut opened = match opened {
        Ok(o) => o,
        Err(f) => {
            fetcher.put_back();
            attempt(&f);
            return Err(f);
        }
    };
    opened.notes.splice(0..0, notes);
    if accepted.is_none() {
        let last = opened.last();
        opened.notes.push(format!(
            "no checkpoint was accepted for `{}` before, and none is configured: the first that \
             verifies under its log key is accepted, {} leaves of `{}`",
            source.name,
            last.size(),
            last.origin()
        ));
    }
    let computed = KeysFile::of(
        &opened.keys.log,
        &opened.keys.attestation,
        opened.keys.first_use.clone(),
        &opened.repo.logs(),
        opened.repo.keys(),
    );
    match &keys_held {
        Some(was) => {
            let differs = was.differences(&computed);
            if !differs.is_empty() {
                opened.notes.push(format!(
                    "the key history in {} disagrees with the log, and the log wins: {}",
                    dirs.state.join(state::KEYS).display(),
                    differs.join("; ")
                ));
            }
        }
        None if held.accepted.is_some() && lost.is_none() => opened.notes.push(format!(
            "{} was not there, and is written again from the log",
            dirs.state.join(state::KEYS).display()
        )),
        None => {}
    }
    // The record of when it last synced is not what a rollback is caught against, so it is made
    // again; but said, as every state file found missing is.
    if held.sync.is_none() && held.accepted.is_some() && lost.is_none() {
        opened.notes.push(format!(
            "{} was not there, so when this source last synced was not known until now",
            dirs.state.join(state::SYNC).display()
        ));
    }

    // Only now, with everything verified: the key history, the checkpoint, and last the record
    // that says the sync worked, so that a sync stopped between them is stale sooner, never
    // fresher than what it accepted.
    let accepting = computed
        .write(&dirs.state)
        .and_then(|()| state::write_checkpoint(&dirs.state, &opened.checkpoint));
    if let Err(e) = accepting {
        fetcher.put_back();
        let f = Failed::unreadable(
            anyhow::Error::new(e).context(format!("writing the state in {}", dirs.state.display())),
        );
        attempt(&f);
        return Err(f);
    }
    // The checkpoint is accepted, so the clones it was read from are kept whatever follows: put
    // back behind it, they would be refused as a rollback of it.
    fetcher.keep();
    let recorded = SyncRecord {
        last_success: Some(opt.now),
        last_attempt: Some(opt.now),
        failure: None,
        newest_leaf: opened.repo.newest_time(),
        logs: opened.logs_seen(),
        urls: opened.urls.clone(),
        ..Default::default()
    }
    .write(&dirs.state);
    if let Err(e) = recorded {
        opened.notes.push(format!(
            "the checkpoint is accepted, and the record of this sync could not be written to {} \
             ({e}): the source is taken to have synced when it last recorded doing so, so it goes \
             stale sooner, never later",
            dirs.state.join(state::SYNC).display()
        ));
    }
    Ok(opened)
}

/// Record a sync that did not work: the attempt and why, leaving the last success, the checkpoint
/// and the key history as they were. Best effort: a state directory that cannot be written is said
/// by the sync's own failure.
fn record_failure(dirs: &Dirs, before: Option<SyncRecord>, failed: &Failed, now: u64) {
    let mut r = before.unwrap_or_default();
    r.last_attempt = Some(now);
    r.failure = Some(Failure {
        at: now,
        why: format!("{:#}", failed.error),
        refused: failed.refused,
    });
    if !failed.urls.is_empty() {
        r.urls = failed.urls.clone();
    }
    let _ = r.write(&dirs.state);
}

/// Open a source from its clones as they are, touching no network: the same verification a sync
/// makes, against the state as it is. What `--offline` answers from, and what every command
/// answers from after a sync.
pub(crate) fn open(source: &Source, dirs: &Dirs) -> Result<Opened, Failed> {
    let _lock = SourceLock::shared(dirs).map_err(Failed::unreadable)?;
    let held = Held::read(dirs).map_err(Failed::unreadable)?;
    if let Some(l) = held.lost(source, dirs) {
        return Err(Failed::refused(anyhow!(
            "`{}` has synced before and its state is gone: {}. Run `trigon evidence sync \
             --accept-state-loss {}` if it was lost",
            source.name,
            l.said(dirs),
            source.name
        )));
    }
    let accepted = match held.accepted.clone() {
        Some(a) => Some(a),
        None => initial(source).map_err(Failed::unreadable)?,
    };
    let find = |l: &Location| -> Reached {
        let dir = dirs.clone_of(l);
        match git::is_clone_at(&dir) && !dir.join(".git").join(UNACCEPTED).exists() {
            true => Reached::Copy { dir, note: None },
            false => Reached::Missing("no clone of it is kept: it has never been synced".into()),
        }
    };
    // Offline, a key trusted on first use is only ever the one a sync recorded: the clone's own
    // `keys/` is never read as one here.
    let recorded = held.keys.as_ref().is_some_and(|k| k.first_use.is_some());
    if source.trust_on_first_use && !recorded {
        return Err(Failed::unreadable(anyhow!(
            "`{}` trusts on first use, and no sync has recorded the keys it read",
            source.name
        )));
    }
    let first: Vec<Reached> = source.urls.iter().map(find).collect();
    let (keys, _) = start_keys(source, held.keys.as_ref(), &first, 0)?;
    chain(source, &keys, first, &mut |l| find(l), accepted.as_deref())
}

/// The keys the chain is verified from: those the source pins; for a key it does not, the one its
/// first sync read and recorded; and on a first sync of a source trusting on first use, the one in
/// `keys/` of the first location reached, with a line saying so.
fn start_keys(
    source: &Source,
    held: Option<&KeysFile>,
    first: &[Reached],
    now: u64,
) -> Result<(StartKeys, Vec<String>), Failed> {
    if let (Some(log), Some(attestation)) = (&source.log_key, &source.attestation_key) {
        return Ok((
            StartKeys {
                log: log.clone(),
                attestation: attestation.clone(),
                first_use: None,
            },
            Vec::new(),
        ));
    }
    let bad_state = |why: String| Failed::unreadable(anyhow!("{why}"));
    if let Some(k) = held.filter(|k| k.first_use.is_some()) {
        let log = match &source.log_key {
            Some(l) => l.clone(),
            None => k.log_vkey().map_err(bad_state)?,
        };
        let attestation = match &source.attestation_key {
            Some(a) => a.clone(),
            None => k.start_key().map_err(bad_state)?,
        };
        return Ok((
            StartKeys {
                log,
                attestation,
                first_use: k.first_use.clone(),
            },
            Vec::new(),
        ));
    }
    // First contact: the keys the repository publishes, from the first location that could be
    // reached, which every later sync is then pinned by.
    let reached = source.urls.iter().zip(first).find_map(|(l, r)| match r {
        Reached::Copy { dir, .. } => Some((l, dir)),
        Reached::Missing(_) => None,
    });
    let Some((location, dir)) = reached else {
        return Err(Failed::unreadable(anyhow!(
            "`{}` trusts on first use, and no location of it could be reached to read its keys \
             from",
            source.name
        )));
    };
    let files = DirFiles::new(dir);
    let read = |path: &str| -> Result<String, Failed> {
        let bytes = files
            .read(path, KEY_FILE_LIMIT)
            .map_err(|e| Failed::unreadable(anyhow!("{location}: {e}")))?
            .ok_or_else(|| {
                Failed::unreadable(anyhow!(
                    "{location} has no {path}, so there is no key to trust on first use"
                ))
            })?;
        String::from_utf8(bytes)
            .map_err(|_| Failed::unreadable(anyhow!("{location}'s {path} is not text")))
    };
    let log = match &source.log_key {
        Some(l) => l.clone(),
        None => LogVkey::parse(read("keys/log.vkey")?.trim())
            .map_err(|e| Failed::unreadable(anyhow!("{location}'s keys/log.vkey: {e}")))?,
    };
    let attestation = match &source.attestation_key {
        Some(a) => a.clone(),
        None => AttestationKey::from_pem(&read("keys/attestation.pub")?)
            .map_err(|e| Failed::unreadable(anyhow!("{location}'s keys/attestation.pub: {e}")))?,
    };
    let said = format!(
        "trusting on first use: the log key {log} and the attestation key {} were read from {}'s \
         keys/ and recorded, and every answer from `{}` rests on them",
        attestation.key_id(),
        location,
        source.name
    );
    Ok((
        StartKeys {
            log,
            attestation,
            first_use: Some(FirstUse {
                read_from: location.as_git_arg().to_string(),
                at: now,
            }),
        },
        vec![said],
    ))
}

/// The source's chain: its first repository from the copies of its own locations, and each
/// repository it goes on in from copies `reach` finds of the locations the log-end names; each
/// repository's copies held to one another, the largest answering; and the whole chain held to the
/// checkpoint last accepted.
fn chain(
    source: &Source,
    keys: &StartKeys,
    first: Vec<Reached>,
    reach: &mut dyn FnMut(&Location) -> Reached,
    accepted: Option<&[u8]>,
) -> Result<Opened, Failed> {
    let mut urls = Vec::new();
    let mut notes = Vec::new();
    let mut parts: Vec<(PathBuf, VerifiedSource)> = Vec::new();
    let start = pick(
        &source.urls,
        first,
        &|dir| verify_source(dir, &keys.log, None),
        &mut urls,
        &mut notes,
    )
    .map_err(|mut f| {
        f.urls = urls.clone();
        f
    })?;
    parts.push(start);
    loop {
        let (_, part) = parts.last().expect("the chain has its first repository");
        let Some(next) = part.continues_at.clone() else {
            break;
        };
        let prev = part
            .logs
            .last()
            .expect("a repository's part of a chain has a log")
            .log
            .clone();
        if parts.len() >= MOST_REPOSITORIES
            || parts
                .iter()
                .any(|(_, p)| p.logs.iter().any(|c| c.log.origin() == next.origin))
        {
            return Err(Failed::refused(anyhow!(
                "`{}`'s log-end names `{}`, which this chain has reached before, or the chain \
                 runs past {MOST_REPOSITORIES} repositories: a succession never returns to an \
                 earlier log",
                prev.origin(),
                printable(&next.origin)
            )));
        }
        let mut locations = Vec::new();
        for u in &next.urls {
            // A log-end names only locations anyone can clone, which its leaf was held to.
            let l = Location::parse(u, Path::new("/"), None).map_err(|e| {
                Failed::refused(anyhow!(
                    "`{}`'s log-end names its successor at {e}",
                    prev.origin()
                ))
            })?;
            // A project's source is fetched over HTTPS only (`docs/19` §2.4), and the log-end
            // naming where it goes on is signed by the key the project pins: without this, the
            // thing under test would choose where this client connects, over ssh with the user's
            // own identity or in plain text.
            if let AddedBy::ProjectFile(file) = &source.added_by
                && l.transport() != Transport::Https
            {
                return Err(Failed::refused(anyhow!(
                    "`{}`'s log-end names its successor at {l} ({}), and `{}`, which the \
                     project's own {} added, is fetched over HTTPS only: nothing is fetched from \
                     there, and nothing it served is accepted",
                    prev.origin(),
                    l.transport(),
                    source.name,
                    file.display()
                )));
            }
            locations.push(l);
        }
        let reached: Vec<Reached> = locations.iter().map(&mut *reach).collect();
        let (dir, verified) = pick(
            &locations,
            reached,
            &|dir| verify_continuation(&prev, dir),
            &mut urls,
            &mut notes,
        )
        .map_err(|mut f| {
            f.urls = urls.clone();
            f
        })?;
        notes.push(format!(
            "`{}` ended, and its successor `{}` is followed into another repository, {}",
            prev.origin(),
            printable(&next.origin),
            next.urls
                .iter()
                .map(|u| printable(u))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        parts.push((dir, verified));
    }
    let repo = Repository::chain(parts, &keys.attestation, accepted).map_err(|e| {
        let mut f = Failed::of_log(
            e,
            format!(
                "`{}`'s chain does not extend the checkpoint last accepted for it",
                source.name
            ),
        );
        f.urls = urls.clone();
        f
    })?;
    let last = repo.source().logs.last().expect("a chain has a log");
    let root = repo
        .roots()
        .last()
        .expect("a chain has a repository")
        .to_path_buf();
    let checkpoint = DirFiles::in_repository(&root, &last.dir)
        .read("checkpoint", 64 * 1024)
        .map_err(|e| Failed::unreadable(anyhow!(e)))?
        .ok_or_else(|| Failed::unreadable(anyhow!("the answering clone lost its checkpoint")))?;
    Ok(Opened {
        repo,
        keys: keys.clone(),
        checkpoint,
        urls,
        notes,
    })
}

/// Verify the copy at each location of one repository with `verify`, hold every copy that
/// verifies to every other (`docs/19` §6.1), and return the largest's clone and part of the chain.
/// A copy that fails verification refuses the source; one that could not be reached or read is
/// said, and the others answer.
fn pick(
    locations: &[Location],
    reached: Vec<Reached>,
    verify: &dyn Fn(&Path) -> Result<VerifiedSource, LogError>,
    urls: &mut Vec<UrlSeen>,
    notes: &mut Vec<String>,
) -> Result<(PathBuf, VerifiedSource), Failed> {
    let seen = |l: &Location, size: Option<u64>, state: &str, note: Option<String>| UrlSeen {
        url: l.as_git_arg().to_string(),
        transport: l.transport().to_string(),
        size,
        state: state.into(),
        note,
    };
    let mut ok: Vec<(usize, PathBuf, VerifiedSource)> = Vec::new();
    let mut missing = Vec::new();
    let mut said: Vec<Option<String>> = vec![None; locations.len()];
    for (i, (l, r)) in locations.iter().zip(reached).enumerate() {
        match r {
            Reached::Missing(why) => {
                missing.push(format!("{l}: {why}"));
                urls.push(seen(l, None, "unreachable", Some(why)));
            }
            Reached::Copy { dir, note } => match verify(&dir) {
                Ok(part) => {
                    said[i] = note;
                    ok.push((i, dir, part));
                }
                Err(e) if e.fails_verification() => {
                    return Err(Failed::of_log(
                        e,
                        format!("the evidence repository at {l} does not verify"),
                    ));
                }
                Err(e) => {
                    let why = printable(&format!("its log could not be read: {e}"));
                    missing.push(format!("{l}: {why}"));
                    urls.push(seen(l, None, "unreachable", Some(why)));
                }
            },
        }
    }
    if ok.is_empty() {
        return Err(Failed::unreadable(anyhow!(
            "no location could be reached and read: {}",
            missing.join("; ")
        )));
    }
    let largest = {
        let refs: Vec<Vec<&VerifiedLog>> = ok
            .iter()
            .map(|(_, _, p)| p.logs.iter().map(|c| &c.log).collect())
            .collect();
        // Every copy against every other, since two copies that each agree with a third can still
        // disagree with each other after where the third ends.
        for a in 0..refs.len() {
            for b in a + 1..refs.len() {
                if let Err(d) = compare_chains(&refs[a], &refs[b]) {
                    let (la, lb) = (&locations[ok[a].0], &locations[ok[b].0]);
                    return Err(Failed::refused(LogError::Equivocation {
                        why: format!(
                            "{la} and {lb} serve one source and are not one log: {}",
                            d.why
                        ),
                        first_dir: la.to_string(),
                        first: refs[a][d.first].checkpoint().to_string(),
                        second_dir: lb.to_string(),
                        second: refs[b][d.second].checkpoint().to_string(),
                    }));
                }
            }
        }
        // Every pair is one chain, so the order is total, and the largest is the one nothing
        // exceeds.
        let ahead = |a: &[&VerifiedLog], b: &[&VerifiedLog]| {
            compare_chains(a, b).is_ok_and(|o| o == std::cmp::Ordering::Greater)
        };
        let mut largest = 0;
        for k in 1..refs.len() {
            if ahead(&refs[k], &refs[largest]) {
                largest = k;
            }
        }
        let reach = |r: &[&VerifiedLog]| {
            r.last()
                .map_or((String::new(), 0), |l| (l.origin().to_string(), l.size()))
        };
        let (top_origin, top) = reach(&refs[largest]);
        for (k, (i, _, _)) in ok.iter().enumerate() {
            let l = &locations[*i];
            let behind = ahead(&refs[largest], &refs[k]);
            let (origin, size) = reach(&refs[k]);
            if behind {
                notes.push(format!(
                    "{l} is lagging: it serves `{origin}` at {size} leaves, and {} serves \
                     `{top_origin}` at {top}",
                    locations[ok[largest].0]
                ));
            }
            let state = match (k == largest, behind) {
                (true, _) => "answering",
                (false, true) => "lagging",
                (false, false) => "in agreement",
            };
            urls.push(seen(l, Some(size), state, said[*i].take()));
        }
        largest
    };
    let (_, dir, part) = ok.swap_remove(largest);
    Ok((dir, part))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
