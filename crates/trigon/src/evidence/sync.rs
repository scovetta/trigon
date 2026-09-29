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
//! **Verified before anything is accepted**, as every command that answers from the clones opens
//! them ([`crate::clones`]): each clone by itself with the phase 4 code — the checkpoint under the
//! source's log key, the root recomputed from every leaf, times that never go back, every key change
//! and succession followed — then every location held to every other: copies of one log that are
//! not one log are an equivocation, with both signed notes. The largest copy answers; a smaller one
//! is lagging. The whole chain, across repositories, is then held to the checkpoint last accepted,
//! and its key history recomputed and compared with the one kept. Only then is the state written,
//! and a new clone kept, and the clone of a location the source no longer names removed from the
//! cache. A sync that is refused keeps every clone as it was and the state untouched.
//!
//! **The state is what a rollback is caught against**, so a source that has synced before and has
//! lost it is not silently given a new one: the sync is refused until `--accept-state-loss <name>`
//! says the loss is known. Only what was lost starts over then: keys first read that survive a lost
//! checkpoint still pin the source, and a checkpoint that survives lost keys must open under the
//! keys read again.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use trigon_attest::config::Source;
use trigon_attest::location::{Location, Transport, printable};
use trigon_attest::state::{self, Failure, KeysFile, SyncRecord, UNACCEPTED};

pub(crate) use crate::clones::{Dirs, Failed, Opened, open};
use crate::clones::{Held, Reached, SourceLock, chain, initial, start_keys};
use crate::publish::git;

/// What a clone's working tree holds (`docs/19` §6): `index/` and `evidence/` stay out, and are
/// read from git's objects when a command asks for them.
const SPARSE: [&str; 3] = ["keys", "log", "records"];

/// `.git/info/attributes` of every clone: every attribute that could make a checked-out file other
/// than its blob, unset for every path. It outranks the tree's own `.gitattributes`, which whoever
/// can push writes.
const NO_ATTRIBUTES: &str = "* -text -eol -filter -ident -working-tree-encoding\n";

/// How a sync runs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Options {
    pub full_history: bool,
    pub accept_state_loss: bool,
    pub verbose: bool,
    /// Now, in Unix seconds: what the sync record is stamped with.
    pub now: u64,
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
    // And a clone of a location the source no longer names — a mirror taken out of its `urls`, a
    // successor's location a log-end no longer leads to — goes from the cache, which it would
    // otherwise hold for ever, unread. Its state is the source's, and stays.
    let reached: Vec<PathBuf> = source
        .urls
        .iter()
        .map(|l| dirs.clone_of(l))
        .chain(opened.urls.iter().map(|u| dirs.clone_of_arg(&u.url)))
        .collect();
    opened.notes.extend(forget_unconfigured(dirs, &reached));
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

/// Remove from the cache every clone of `dirs` that is not one of `keep`, saying which location each
/// was a clone of. Only the directories a clone is kept in are looked at — named by a sha256 in
/// hex — so a clone being made, which begins with a dot, is never taken for one.
fn forget_unconfigured(dirs: &Dirs, keep: &[PathBuf]) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(&dirs.cache) else {
        return Vec::new();
    };
    let mut said = Vec::new();
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        let clone = name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit());
        if !clone || keep.contains(&path) {
            continue;
        }
        let was = match git::is_clone_at(&path) {
            true => git::text(Some(&path), &["config", "--get", "remote.origin.url"])
                .map(|u| printable(&git::scrub(&u)))
                .unwrap_or_else(|_| "a location it no longer records".into()),
            false => "a location it no longer records".into(),
        };
        said.push(match remove_path(&path) {
            Ok(()) => format!(
                "removed the clone of {was}, a location this source no longer names, from the \
                 cache: {}",
                path.display()
            ),
            Err(e) => format!(
                "kept the clone of {was}, a location this source no longer names, since it could \
                 not be removed: {e:#}"
            ),
        });
    }
    said
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
