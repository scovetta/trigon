//! A source's clones, opened as every command that answers from them opens them (`docs/19` §6,
//! §6.1): the same verification a sync makes, touching no network. What `--offline` answers from,
//! what every command answers from after a sync, and what the network-free verifier's `--record
//! --source` reads when it is given no `--evidence` directory. In both builds, since reading a
//! directory opens no socket; making and fetching clones is `crate::evidence::sync`'s, in the
//! default build only.
//!
//! **One clone per location**, at `<cache>/<name>/<sha256 of the location>/`: every URL of a
//! source — one log and its mirrors — and every URL a log-end names for a successor in another
//! repository, which is part of the same source. A clone counts only once a sync accepted it: its
//! git directory is a directory of its own, and carries no mark saying a sync never finished with
//! it.
//!
//! **Verified before anything is answered**, each clone by itself with the phase 4 code — the
//! checkpoint under the source's log key, the root recomputed from every leaf, times that never go
//! back, every key change and succession followed — then every location held to every other:
//! copies of one log that are not one log are an equivocation, with both signed notes. The largest
//! copy answers; a smaller one is lagging. The whole chain, across repositories, is then held to the
//! checkpoint last accepted.
//!
//! **The state is what a rollback is caught against**, so a source that has synced before and has
//! lost it is refused, not silently given a new one, until `trigon evidence sync
//! --accept-state-loss <name>` says the loss is known.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use base64::Engine as _;
use sha2::Digest as _;
use trigon_attest::config::{AddedBy, EvidenceConfig, Source, read_checkpoint_file};
use trigon_attest::evidence::Repository;
use trigon_attest::location::{Location, Transport, printable};
use trigon_attest::log::{
    Checkpoint, DirFiles, LogError, LogFiles as _, VerifiedLog, VerifiedSource, compare_chains,
    holds_no_log, verify_continuation, verify_source,
};
use trigon_attest::state::{self, FirstUse, KeysFile, StateError, SyncRecord, UNACCEPTED, UrlSeen};
use trigon_attest::{AttestationKey, LogVkey};

/// The longest `keys/*` file read: a PEM key or a verifier key is under 200 bytes.
const KEY_FILE_LIMIT: u64 = 16 * 1024;

/// The longest chain of repositories followed: a succession into another repository is a rare
/// event, and a chain longer than this is a loop or an attack.
const MOST_REPOSITORIES: usize = 64;

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
    pub(crate) fn clone_of(&self, location: &Location) -> PathBuf {
        self.clone_of_arg(location.as_git_arg())
    }

    /// Where the clone of a location is kept, by the location as `git` is given it.
    pub(crate) fn clone_of_arg(&self, location: &str) -> PathBuf {
        let hash = sha2::Sha256::digest(location.as_bytes());
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
    #[cfg_attr(
        not(feature = "build"),
        expect(
            dead_code,
            reason = "a sync records it; the verifier only reads the clones"
        )
    )]
    pub checkpoint: Vec<u8>,
    /// Each location, and what was found there.
    #[cfg_attr(
        not(feature = "build"),
        expect(
            dead_code,
            reason = "a sync records it; the verifier only reads the clones"
        )
    )]
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
    #[cfg(feature = "build")]
    pub(crate) fn logs_seen(&self) -> Vec<trigon_attest::state::LogSeen> {
        self.repo
            .logs()
            .iter()
            .map(|l| trigon_attest::state::LogSeen {
                origin: l.origin().to_string(),
                size: l.size(),
            })
            .collect()
    }

    /// The checkpoint answers are given from: the last log's, which a sync accepts.
    #[cfg(feature = "build")]
    pub(crate) fn checkpoint_of(&self) -> &Checkpoint {
        self.last().checkpoint().checkpoint()
    }
}

/// What every report that answers from a source prints beside it (`docs/19` §6): the checkpoint
/// the answer was given from, as `checkpoint <origin> <size> <root>` — the three lines of its note
/// on one, the root spelled as the note spells it. A log has one tree at each size, so two people
/// whose lines for one origin at one size differ have been shown two logs, a split view: the line
/// is what they paste to each other to find out.
pub(crate) fn checkpoint_line(c: &Checkpoint) -> String {
    format!("checkpoint {} {} {}", c.origin, c.size, root_said(c))
}

/// [`checkpoint_line`], as `--output json` carries it.
pub(crate) fn checkpoint_json(c: &Checkpoint) -> serde_json::Value {
    serde_json::json!({ "origin": c.origin, "size": c.size, "root": root_said(c) })
}

/// A checkpoint's root as its note spells it: padded standard base64, the one spelling a
/// checkpoint's third line can have and be read at all (`trigon_attest::log::Checkpoint::parse`).
fn root_said(c: &Checkpoint) -> String {
    base64::engine::general_purpose::STANDARD.encode(c.root)
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
    pub(crate) fn refused(error: impl Into<anyhow::Error>) -> Failed {
        Failed {
            refused: true,
            error: error.into(),
            urls: Vec::new(),
        }
    }

    pub(crate) fn unreadable(error: impl Into<anyhow::Error>) -> Failed {
        Failed {
            refused: false,
            error: error.into(),
            urls: Vec::new(),
        }
    }

    /// A log that failed verification refuses the source; one that could not be read leaves it
    /// unreadable.
    pub(crate) fn of_log(e: LogError, context: String) -> Failed {
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
pub(crate) enum Reached {
    Copy { dir: PathBuf, note: Option<String> },
    Missing(String),
}

/// A lock on one source, held while it is synced: two syncs of it — two jobs sharing a cache, a
/// lookup syncing a stale source while `evidence sync` runs — take turns rather than write one
/// clone and one state at once. Waited for, not refused: a sync that waits finds the other's work
/// done, and fetches again from there.
pub(crate) struct SourceLock {
    file: std::fs::File,
}

impl SourceLock {
    /// Held alone, by a sync, which changes the clones and the state.
    #[cfg(feature = "build")]
    pub(crate) fn take(dirs: &Dirs) -> anyhow::Result<SourceLock> {
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
pub(crate) struct Held {
    pub accepted: Option<Vec<u8>>,
    pub keys: Option<KeysFile>,
    pub sync: Option<SyncRecord>,
}

impl Held {
    pub(crate) fn read(dirs: &Dirs) -> Result<Held, StateError> {
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
    pub(crate) fn lost(&self, source: &Source, dirs: &Dirs) -> Option<Lost> {
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
pub(crate) struct Lost {
    /// The checkpoint last accepted, which a rollback is caught against.
    pub checkpoint: bool,
    /// For a source trusting on first use, the keys its first sync read: its only pin.
    pub keys: bool,
}

impl Lost {
    /// What is gone, with the files.
    pub(crate) fn said(&self, dirs: &Dirs) -> String {
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
    #[cfg(feature = "build")]
    pub(crate) fn accepting(&self, source: &Source, held: &Held) -> String {
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
                 reached that holds a log, as a first contact reads them, and the checkpoint last \
                 accepted, which is kept, must open under them and be extended: a log under other \
                 keys is refused"
                .into(),
            (true, true) => format!(
                "its keys are then read again from `keys/` of the first location reached that \
                 holds a log, as a first contact reads them, and the log is held only to {held_to}"
            ),
        }
    }
}

/// The initial checkpoint a source is configured with, read.
pub(crate) fn initial(source: &Source) -> anyhow::Result<Option<Vec<u8>>> {
    match &source.checkpoint {
        Some(p) => read_checkpoint_file(p)
            .map(Some)
            .map_err(|why| anyhow!("the initial checkpoint {} {why}", p.display())),
        None => Ok(None),
    }
}

/// Whether `dir` is a clone a sync accepted: its git directory is a directory of its own — not a
/// link, nor a file pointing elsewhere — with no mark saying a sync never finished with it. Asked
/// without running `git`, so the verifier can ask it; nothing is run in the clone, only read, and
/// every file is read inside it ([`DirFiles`]).
pub(crate) fn accepted_clone(dir: &Path) -> bool {
    let git = dir.join(".git");
    std::fs::symlink_metadata(&git).is_ok_and(|m| m.is_dir()) && !git.join(UNACCEPTED).exists()
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
        match accepted_clone(&dir) {
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
/// `keys/` of the first location reached that holds a log, with a line saying so, and one for each
/// location passed over for serving no log at all.
pub(crate) fn start_keys(
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
    // reached and holds a log, which every later sync is then pinned by. One that serves no log at
    // all — a mistyped URL, a repository nothing has been published to — is passed over, as `pick`
    // sets it aside, rather than stopping the sync before a location that does hold one is read.
    let mut notes = Vec::new();
    let mut reached = None;
    for (l, r) in source.urls.iter().zip(first) {
        let Reached::Copy { dir, .. } = r else {
            continue;
        };
        if holds_no_log(dir) {
            notes.push(format!(
                "{l} serves no log at all, so no key is read from its keys/ to trust on first use"
            ));
            continue;
        }
        reached = Some((l, dir));
        break;
    }
    let Some((location, dir)) = reached else {
        return Err(Failed::unreadable(match notes.is_empty() {
            true => anyhow!(
                "`{}` trusts on first use, and no location of it could be reached to read its \
                 keys from",
                source.name
            ),
            false => anyhow!(
                "`{}` trusts on first use, and no location of it that could be reached holds a \
                 log to read its keys from: {}",
                source.name,
                notes.join("; ")
            ),
        }));
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
    // Only a key the source does not pin was read; one it pins is said to be pinned, never read.
    let read = match (&source.log_key, &source.attestation_key) {
        (None, None) => format!(
            "the log key {log} and the attestation key {} were",
            attestation.key_id()
        ),
        (None, Some(_)) => format!(
            "the log key {log}, beside the attestation key {} the source pins, was",
            attestation.key_id()
        ),
        (Some(_), _) => format!(
            "the attestation key {}, beside the log key {log} the source pins, was",
            attestation.key_id()
        ),
    };
    notes.push(format!(
        "trusting on first use: {read} read from {location}'s keys/ and recorded, and every \
         answer from `{}` rests on them",
        source.name
    ));
    Ok((
        StartKeys {
            log,
            attestation,
            first_use: Some(FirstUse {
                read_from: location.as_git_arg().to_string(),
                at: now,
            }),
        },
        notes,
    ))
}

/// The source's chain: its first repository from the copies of its own locations, and each
/// repository it goes on in from copies `reach` finds of the locations the log-end names; each
/// repository's copies held to one another, the largest answering; and the whole chain held to the
/// checkpoint last accepted.
pub(crate) fn chain(
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
/// said, and the others answer. A copy with no log at all is one that could not be read, said with
/// a note naming its URL; one with a checkpoint that does not open is one that fails.
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
                // No log at all, which is not a log that fails to verify: set aside, and said
                // loudly, since the likeliest cause is a URL that names the wrong repository.
                Err(e @ LogError::NoLog(_)) => {
                    let why = printable(&format!(
                        "its log could not be read: {e}. A mistyped URL, or a repository nothing \
                         has been published to yet, serves no log at all"
                    ));
                    notes.push(format!(
                        "{l} serves no log at all, and is set aside while the other locations \
                         answer: check the URL, since a mistyped one, or a repository nothing has \
                         been published to yet, looks like this"
                    ));
                    missing.push(format!("{l}: {why}"));
                    urls.push(seen(l, None, "unreachable", Some(why)));
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
