//! `trigon publish`: what the publication gate releases, written into the evidence repository as
//! one commit (`docs/19` §2.4, §3, §10 phase 5).
//!
//! **The only thing that writes an evidence repository**, and it builds only on a log it has
//! verified. Each attempt runs the steps of `docs/19` §10 phase 5 in order:
//!
//! 1. Fetch, and reset the working clone hard to the remote — discarding any commit a previous
//!    attempt made and did not push, and the checkpoint signed for it — refusing a branch that
//!    names git attributes before it is checked out. Verify the remote's log whole under its
//!    `keys/log.vkey`, whose origin must be `[publish] origin`, and against the newest checkpoint
//!    of the log this host has published or verified, kept by the log's origin under the host's
//!    state directory, so that every store and every spelling of the repository is held to it.
//!    Only the files the checkpoint's tree has are read, so anything planted in `log/` beyond it
//!    is ignored, and overwritten where a publication writes the same path.
//! 2. Ask the gate about each run, through a `trigon_api::Index` of the store with the kill-switch
//!    read from the repository — the same code `trigon serve` asks — and refuse, for every run at
//!    once and before anything is written: a run withheld; every divergence while `[publish]
//!    divergences` is `refuse`; a run already logged; the second of two agreeing attempts whose
//!    first is published; a verdict or void for an artifact with a current record it does not
//!    supersede; a verdict without its falsifying command naming `[publish] origin`, or without the
//!    dispute pointer `[publish] disputes` names; and any record every client would refuse, checked
//!    with the client's own `check_record` before it is written.
//! 3. (Rebuilt artifacts as release assets: `docs/19` D4, not built; `rebuilt_artifacts =
//!    "github-release"` is refused rather than published without them.)
//! 4. Write each record and its evidence, deduplicated; one leaf per record, in the order the runs
//!    were named, at a time never earlier than the leaf before it; the tiles and bundles the append
//!    writes, the partials it makes obsolete removed; and each index file of every key of every new
//!    record, derived from the log whole.
//! 5. Run `trigon log sign` as a child process, which holds the log key and checks the tree again
//!    from disk, against the same newest checkpoint; `publish` never opens the key.
//! 6. Commit exactly what steps 4 and 5 wrote, as one commit, checked to hold those bytes and
//!    nothing else, and push it, never forced. A rejected push whose remote has moved is a lost
//!    race: the commit and the checkpoint signed for it are discarded, and the attempt starts again
//!    from step 1.
//! 7. Record `RunRecord.published` for each run; a run whose record is logged and has none — a
//!    crash between the push and this — is completed here instead of logged again.
//!
//! A local path to a non-bare working tree is published into in place: it must be clean and on
//! `[publish] branch`, the commit is made there, and nothing is pushed.
//!
//! One `publish` runs at a time on a host, whatever store it runs from, under a lock in the host's
//! state directory, and one at a time in a store, under the store's.

mod git;
mod init;
mod lock;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use sha2::Digest as _;
use trigon_api::publication::{Confirmation, Publication, Switches};
use trigon_attest::config::{Divergences, Env, EvidenceConfig, RebuiltArtifacts};
use trigon_attest::evidence::{
    IndexKey, Key, Repository, check_record, evidence_path, index_files, index_files_after,
    record_leaf, record_path,
};
use trigon_attest::location::{Location, printable};
use trigon_attest::log::{
    Checkpoint, DirFiles, HeartbeatLeaf, Leaf, LeafPos, LogFiles as _, SignedCheckpoint, Staged,
    VerifiedLog,
};
use trigon_attest::{
    AttestationKey, BUILD_OBSERVATION, DIVERGENCE_V2, DisputePointer, EQUIVALENCE_V2, Envelope,
    FalsifyingCommand, LogVkey, REBUILD, Record, Statement, VOID, WITHDRAWAL, evidence_key,
};
use trigon_core::Digest;
use trigon_store::{Published, RunRecord, Store};

use crate::evidence_log::{NewestPublished, host_state};
use crate::style;

pub(crate) use init::{InitArgs, run as init};

/// How many times a publication is built again after losing a push to another writer. With one
/// publishing host and its lock the race cannot happen (`docs/19` D5); this bounds it where a
/// second host is a configuration mistake away.
const ATTEMPTS: u32 = 5;

/// Where in a repository a publication reads and writes. A working tree published into must hold
/// nothing git ignores under them, and a publication that fails is discarded there, ignored files
/// included.
const PUBLICATION_PATHS: [&str; 6] = ["keys", "log", "records", "evidence", "index", "kill-switch"];

/// The longest `keys/*` file read: a PEM key or a verifier key is under 200 bytes.
const KEY_FILE_LIMIT: u64 = 16 * 1024;

/// The longest envelope `--withdrawal` reads. A withdrawal is a few hundred bytes of statement.
const ENVELOPE_LIMIT: u64 = 1 << 20;

/// What `trigon publish` is given.
pub(crate) struct Args {
    pub runs: Vec<String>,
    pub store: PathBuf,
    pub repo: Option<String>,
    pub withdrawal: Option<PathBuf>,
    pub heartbeat: bool,
    pub dry_run: bool,
    pub reconcile: bool,
}

/// What one invocation publishes.
enum What {
    Runs(Vec<String>),
    Withdrawal(PathBuf),
    Heartbeat,
    Reconcile,
}

/// `[publish]`, and the repository this run publishes to, resolved.
struct Settings {
    location: Location,
    branch: String,
    origin: String,
    disputes: Option<String>,
    log_key: Option<PathBuf>,
    divergences: Divergences,
    heartbeat: Duration,
    confirmation: Confirmation,
}

/// Where the publication is made.
enum Place {
    /// A remote, and the working clone of it this publisher keeps under the store.
    Remote { clone: PathBuf },
    /// A local working tree, published into in place.
    InPlace { tree: PathBuf },
}

/// The repository as step 1 verified it.
struct Base {
    /// The tree read: the working clone, a working tree published into, or a dry run's clone.
    root: PathBuf,
    /// The commit the tree is at.
    head: String,
    repo: Repository,
    /// The directory of the log a publication appends to: the chain's last.
    dir: String,
    vkey: LogVkey,
    kill_switch: bool,
}

impl Base {
    fn log(&self) -> &VerifiedLog {
        &self
            .repo
            .source()
            .logs
            .last()
            .expect("a chain has a log")
            .log
    }

    /// Where the next leaf goes, as the log's chain counts.
    fn pos(&self, offset: u64) -> LeafPos {
        LeafPos {
            log: self.repo.source().logs.len() - 1,
            index: self.log().size() + offset,
        }
    }
}

/// One leaf to append, and the files it needs.
struct Entry {
    /// The run it is the record of, for step 7.
    run: Option<String>,
    leaf: Leaf,
    /// The record file, where the leaf is a record's: its digest and bytes.
    record: Option<(Digest, Vec<u8>)>,
    /// Every evidence file the record names that the repository carries.
    evidence: Vec<(Digest, Vec<u8>)>,
    /// What it is, for a person.
    said: String,
}

/// A run whose record the log already holds, and which has no `published`: a crash came between
/// the push and step 7.
struct Completion {
    run: String,
    record: Digest,
    pos: LeafPos,
}

/// Everything one attempt writes.
struct Plan {
    entries: Vec<Entry>,
    completions: Vec<Completion>,
    /// Files by path in the repository, only where they differ from what is there.
    writes: BTreeMap<String, Vec<u8>>,
    /// Directories and files to remove, by path in the repository.
    removes: Vec<String>,
    /// The new tree's checkpoint, unsigned; `None` where nothing is appended.
    checkpoint: Option<Checkpoint>,
    message: String,
    /// What is said where nothing is written.
    idle: String,
}

pub(crate) fn run(args: Args) -> Result<()> {
    let what = what(&args)?;
    let env = Env::from_process()?;
    let config = EvidenceConfig::load(&env)?;
    let settings = settings(&config, &args, &env, &what)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let store = Store::existing(&args.store)?;
    let state = args
        .store
        .join("publish")
        .join(hex(&sha2::Sha256::digest(settings.location.as_git_arg())));
    let newest = NewestPublished::of(&env, &settings.origin)?;
    let holder = format!(
        "pid {}, since {}, publishing to {} from {}",
        std::process::id(),
        crate::now_rfc3339(),
        settings.location,
        args.store.display()
    );
    // One per host, whatever store it runs from, and so whatever working clone: two would build on
    // the same log and race to push, and D26's window is open only while they do.
    let _host_lock = lock::Lock::take(&host_state(&env)?.join("lock"), &holder)?;
    let _lock = lock::Lock::take(&args.store.join("publish").join("lock"), &holder)?;
    let place = place(&settings.location, &state)?;
    // A working tree published into is somebody's: a second store must not write it meanwhile.
    let _tree_lock = match (&place, args.dry_run) {
        (Place::InPlace { tree }, false) => {
            let git_dir = git::text(Some(tree), &["rev-parse", "--absolute-git-dir"])?;
            Some(lock::Lock::take(
                &Path::new(&git_dir).join("trigon-publish.lock"),
                &format!(
                    "pid {}, publishing from {}",
                    std::process::id(),
                    state.display()
                ),
            )?)
        }
        _ => None,
    };

    println!("repository {} ({})", settings.location, settings.branch);
    for attempt in 1..=ATTEMPTS {
        let (base, _scratch) = prepare(&place, &settings, &state, &newest, args.dry_run)?;
        let plan = plan(&base, &what, &settings, &store, &rt)?;
        if args.dry_run {
            show(&base, &plan);
            return Ok(());
        }
        if plan.writes.is_empty() && plan.removes.is_empty() {
            complete(&base, &plan, &settings, (&store, &newest), &rt, None)?;
            return Ok(());
        }
        let root = base.root.clone();
        let mut unwind = Unwind {
            place: &place,
            root: &root,
            head: &base.head,
            armed: true,
        };
        write(&base.root, &plan)?;
        die_at("written");
        let signed = match &plan.checkpoint {
            Some(checkpoint) => Some(sign(&base, checkpoint, &settings)?),
            None => None,
        };
        die_at("signed");
        // Exactly what was written and signed, and nothing else the tree holds.
        let checkpoint_path = format!("{}/checkpoint", base.dir);
        let mut change = git::Change {
            writes: plan
                .writes
                .iter()
                .map(|(p, b)| (p.as_str(), b.as_slice()))
                .collect(),
            removes: plan.removes.iter().map(String::as_str).collect(),
        };
        if let Some(bytes) = &signed {
            change
                .writes
                .push((checkpoint_path.as_str(), bytes.as_slice()));
        }
        let commit = git::commit(&base.root, Some(&base.head), &change, &plan.message)?;
        die_at("committed");
        if let Place::Remote { .. } = place {
            match git::push(&base.root, &settings.branch, &base.head, &commit)? {
                git::Pushed::Yes => {}
                git::Pushed::LostRace => {
                    // `unwind` discards the commit and the checkpoint signed for it, which never
                    // left this host, and the next attempt starts from the remote as it is now.
                    println!(
                        "lost      the push to another writer (attempt {attempt} of {ATTEMPTS}); \
                         discarding this commit and its checkpoint, and building again"
                    );
                    continue;
                }
            }
        }
        unwind.armed = false;
        die_at("pushed");
        complete(
            &base,
            &plan,
            &settings,
            (&store, &newest),
            &rt,
            Some(&commit),
        )?;
        return Ok(());
    }
    bail!(
        "lost the push {ATTEMPTS} times running to another writer of {}. Publishing is meant to \
         happen from one host (docs/19 D5); find the other one",
        settings.location
    )
}

/// Discards a publication that did not reach the repository: the working tree is reset to the
/// commit it was built on, and everything written since removed, the signed checkpoint with it.
/// Armed until the publication is pushed, or committed in place. A kill runs no destructor, and
/// step 1 of the next run does the same for a working clone; a working tree published into is then
/// found unclean, and refused with how to discard it.
struct Unwind<'a> {
    place: &'a Place,
    root: &'a Path,
    head: &'a str,
    armed: bool,
}

impl Drop for Unwind<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut clean = vec!["clean", "-ffdxq"];
        // Somebody's tree, which held nothing untracked or ignored under the paths a publication
        // writes when this began: what is there now is what this wrote, and the rest is theirs.
        if let Place::InPlace { .. } = self.place {
            clean.push("--");
            clean.extend_from_slice(&PUBLICATION_PATHS);
        }
        let reset = git::run(Some(self.root), &["reset", "--quiet", "--hard", self.head])
            .and_then(|_| git::run(Some(self.root), &clean));
        if let Err(e) = reset {
            eprintln!(
                "could not discard the unpublished commit in {}: {e}. Nothing was pushed. The next \
                 `trigon publish` resets a working clone; a working tree published into is \
                 refused until it is clean",
                self.root.display()
            );
        }
    }
}

/// For the tests of a publisher killed between steps: exit here, as a kill would, with nothing
/// cleaned up, when `TRIGON_PUBLISH_DIE_AT` names this point. A kill can stop `publish` at any of
/// these anyway; the variable makes it stop at a chosen one rather than by timing.
fn die_at(point: &str) {
    if std::env::var_os("TRIGON_PUBLISH_DIE_AT").is_some_and(|v| v == point) {
        eprintln!("TRIGON_PUBLISH_DIE_AT={point}: stopping here as a kill would");
        std::process::exit(137);
    }
}

fn what(args: &Args) -> Result<What> {
    let named = [
        !args.runs.is_empty(),
        args.withdrawal.is_some(),
        args.heartbeat,
        args.reconcile,
    ];
    match named.iter().filter(|n| **n).count() {
        1 => {}
        0 => bail!(
            "name what to publish: runs by id, or --withdrawal <envelope>, --heartbeat or \
             --reconcile"
        ),
        _ => bail!(
            "publish one thing at a time: runs, --withdrawal, --heartbeat or --reconcile, each in \
             a commit of its own"
        ),
    }
    Ok(if let Some(w) = &args.withdrawal {
        What::Withdrawal(w.clone())
    } else if args.heartbeat {
        What::Heartbeat
    } else if args.reconcile {
        What::Reconcile
    } else {
        What::Runs(args.runs.clone())
    })
}

fn settings(config: &EvidenceConfig, args: &Args, env: &Env, what: &What) -> Result<Settings> {
    let p = config.publish();
    let location = match &args.repo {
        Some(r) => Location::parse(r, &env.cwd, env.home.as_deref())?,
        None => p.repo.clone().ok_or_else(|| {
            anyhow!(
                "no evidence repository is named: give --repo <location>, set \
                 TRIGON_PUBLISH_REPO, or set `[publish] repo` in evidence.toml (docs/19 §2.4)"
            )
        })?,
    };
    let origin = p.origin.clone().ok_or_else(|| {
        anyhow!(
            "`[publish] origin` is not set in evidence.toml. It is the log's name, and publish \
             checks the repository's keys/log.vkey and every verdict's falsifying command against \
             it (docs/19 §2.4)"
        )
    })?;
    if p.rebuilt_artifacts == RebuiltArtifacts::GithubRelease && matches!(what, What::Runs(_)) {
        bail!(
            "`[publish] rebuilt_artifacts = \"github-release\"`: uploading rebuilt artifacts as \
             release assets is not built yet (docs/19 §10 phase 5, D4), and a record that names \
             an asset nobody uploaded is one nobody can re-derive. Set it to \"none\" to publish \
             without them"
        );
    }
    let signs = !args.dry_run && !matches!(what, What::Reconcile);
    if signs && p.log_key.is_none() {
        bail!(
            "`[publish] log_key` is not set in evidence.toml. It names the log key `trigon log \
             sign` signs each new checkpoint with; publish itself never opens it"
        );
    }
    Ok(Settings {
        location,
        branch: p.branch.clone(),
        origin,
        disputes: p.disputes.clone(),
        log_key: p.log_key.clone(),
        divergences: p.divergences,
        heartbeat: p.heartbeat,
        confirmation: Confirmation::from(p),
    })
}

/// Where a location is published to: a local working tree in place, or anything else — a bare
/// repository's path included — as a remote.
fn place(location: &Location, state: &Path) -> Result<Place> {
    if let Some(path) = location.local_path() {
        if !path.exists() {
            bail!(
                "{} does not exist. Create the repository — `git init --bare` for a remote, or a \
                 working tree — and its log with `trigon log init`",
                path.display()
            );
        }
        match git::kind_of(path)? {
            Some(true) => {
                return Ok(Place::InPlace {
                    tree: path.to_path_buf(),
                });
            }
            Some(false) => {}
            None => bail!("{} is not a git repository", path.display()),
        }
    }
    Ok(Place::Remote {
        clone: state.join("clone"),
    })
}

/// A directory removed when dropped: a dry run's clone.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Step 1: the repository as it is now, verified. A dry run reads a fresh clone of its own, so
/// that the working clone is left exactly as it was, and records nothing.
fn prepare(
    place: &Place,
    s: &Settings,
    state: &Path,
    newest: &NewestPublished,
    dry_run: bool,
) -> Result<(Base, Option<Scratch>)> {
    let (root, head, scratch) = match place {
        Place::Remote { .. } if dry_run => {
            // Any other is a dry run a kill stopped: the lock says none is running now.
            for e in std::fs::read_dir(state).into_iter().flatten().flatten() {
                if e.file_name().to_string_lossy().starts_with("dry-run-") {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
            let scratch = state.join(format!("dry-run-{}", std::process::id()));
            std::fs::create_dir_all(state)?;
            git::clone(&s.location, &scratch)?;
            let head = checkout(&scratch, s)?;
            (scratch.clone(), head, Some(Scratch(scratch)))
        }
        Place::Remote { clone } => {
            let head = sync(clone, s)?;
            (clone.clone(), head, None)
        }
        Place::InPlace { tree } => {
            if let Some(why) = git::unfit_to_publish_into(tree, &s.branch, &PUBLICATION_PATHS)? {
                bail!("{} cannot be published into: {why}", tree.display());
            }
            let head = git::text(Some(tree), &["rev-parse", "--verify", "--quiet", "HEAD"])
                .map_err(|_| no_log(&s.location))?;
            if let Some(why) = git::attributes(tree, Some(&head))? {
                bail!("{} cannot be published into: {why}", tree.display());
            }
            (tree.clone(), head, None)
        }
    };
    let base = verify(&root, head, s, newest)?;
    if !dry_run {
        std::fs::create_dir_all(state)?;
        newest.advance(base.log().checkpoint(), &base.vkey)?;
        std::fs::write(state.join("location"), format!("{}\n", s.location))?;
    }
    Ok((base, scratch))
}

fn no_log(location: &Location) -> anyhow::Error {
    anyhow!(
        "{location} has no log on its branch: create it with `trigon log init --origin <origin> \
         --repo {location}`"
    )
}

/// Bring the working clone to the remote's branch, whatever was in it: a commit not pushed, a
/// checkpoint signed for it, files a killed attempt left. The clone is ours, under the store, and
/// holds nothing that is not the remote's or a discarded attempt's.
fn sync(clone: &Path, s: &Settings) -> Result<String> {
    // Only a repository of its own at exactly this directory is the clone: one whose `.git` is
    // gone would otherwise be taken for whichever repository encloses the store, and have its
    // remote, branch and working tree rewritten.
    if !git::is_clone_at(clone) {
        // Never made, a clone a kill interrupted, or one whose `.git` went: made again from
        // nothing.
        let removed = match std::fs::symlink_metadata(clone) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(clone),
            // A link is removed itself, never what it leads to.
            Ok(_) => std::fs::remove_file(clone),
            Err(_) => Ok(()),
        };
        removed.with_context(|| format!("removing the half-made clone {}", clone.display()))?;
        if let Some(parent) = clone.parent() {
            std::fs::create_dir_all(parent)?;
        }
        git::clone(&s.location, clone)?;
    } else {
        git::run(
            Some(clone),
            &["remote", "set-url", "origin", s.location.as_git_arg()],
        )?;
    }
    checkout(clone, s)
}

/// Fetch the branch and check it out exactly as the remote has it, unless it names git
/// attributes, which are refused before any checkout could apply them.
fn checkout(clone: &Path, s: &Settings) -> Result<String> {
    let b = &s.branch;
    let tracking = format!("refs/remotes/origin/{b}");
    let fetched = git::run_network(
        Some(clone),
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            "origin",
            &format!("+refs/heads/{b}:{tracking}"),
        ],
    );
    if let Err(e) = fetched {
        // Asked of the remote, so that "it has no such branch" and "it could not be reached" are
        // two messages.
        if matches!(git::remote_head(clone, b), Ok(None)) {
            return Err(no_log(&s.location));
        }
        return Err(e);
    }
    if let Some(why) = git::attributes(clone, Some(&tracking))? {
        bail!("{} cannot be published to: {why}", s.location);
    }
    git::run(
        Some(clone),
        &["checkout", "--quiet", "--force", "-B", b, &tracking],
    )?;
    git::run(Some(clone), &["clean", "-ffdxq"])?;
    git::text(Some(clone), &["rev-parse", "HEAD"])
}

/// Verify the repository at `root`: its keys name `[publish] origin`, its log verifies whole and
/// extends the newest checkpoint of the log this host has published or verified, and it has not
/// ended.
fn verify(root: &Path, head: String, s: &Settings, newest: &NewestPublished) -> Result<Base> {
    let files = DirFiles::new(root);
    let read = |path: &str| -> Result<String> {
        let bytes = files.read(path, KEY_FILE_LIMIT)?.ok_or_else(|| {
            anyhow!(
                "{} has no {path}, so it is not an evidence repository, or its log was never \
                 begun: create it with `trigon log init`",
                s.location
            )
        })?;
        String::from_utf8(bytes).map_err(|_| anyhow!("{path} in {} is not text", s.location))
    };
    let vkey = LogVkey::parse(read("keys/log.vkey")?.trim())
        .with_context(|| format!("reading keys/log.vkey in {}", s.location))?;
    if vkey.origin() != s.origin {
        bail!(
            "{}'s keys/log.vkey names the log `{}`, and `[publish] origin` is `{}`. Refusing to \
             publish into it: every verdict signed for `{}` would name another log than the one \
             it is logged in, and every client would refuse it",
            s.location,
            printable(vkey.origin()),
            s.origin,
            s.origin
        );
    }
    let attestation = AttestationKey::from_pem(&read("keys/attestation.pub")?)
        .with_context(|| format!("reading keys/attestation.pub in {}", s.location))?;
    let accepted = newest.bytes()?;
    let repo = Repository::open(root, &vkey, &attestation, accepted.as_deref()).with_context(|| {
        format!(
            "the log in {} does not verify, or does not extend the newest checkpoint of `{}` this \
             host has published or verified ({}), from any store and however the repository was \
             named; nothing is built on it",
            s.location,
            s.origin,
            newest.path().display()
        )
    })?;
    let source = repo.source();
    let last = source.logs.last().expect("a chain has a log");
    if source.continues_at.is_some() || last.log.log_end().is_some() {
        bail!(
            "the log `{}` in {} has ended, naming a successor; publishing to a successor is not \
             built yet (docs/19 §10 phase 5, `trigon log succeed`)",
            last.log.origin(),
            s.location
        );
    }
    if last.log.origin() != s.origin {
        bail!(
            "the log {} appends to is `{}`, and `[publish] origin` is `{}`",
            s.location,
            last.log.origin(),
            s.origin
        );
    }
    let kill_switch = std::fs::symlink_metadata(root.join("kill-switch")).is_ok();
    Ok(Base {
        root: root.to_path_buf(),
        head,
        dir: last.dir.clone(),
        repo,
        vkey,
        kill_switch,
    })
}

fn plan(
    base: &Base,
    what: &What,
    s: &Settings,
    store: &Store,
    rt: &tokio::runtime::Runtime,
) -> Result<Plan> {
    let (entries, completions) = match what {
        What::Runs(ids) => runs(base, ids, s, store, rt)?,
        What::Withdrawal(path) => (withdrawal(base, path, s)?, Vec::new()),
        What::Heartbeat => match heartbeat(base, s)? {
            Ok(entries) => (entries, Vec::new()),
            Err(why) => {
                return Ok(Plan {
                    idle: why,
                    ..assemble(base, Vec::new(), Vec::new())?
                });
            }
        },
        What::Reconcile => return reconcile(base),
    };
    assemble(base, entries, completions)
}

/// The time the next leaves are logged at: now, and never earlier than the newest leaf.
fn leaf_time(base: &Base) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.max(base.repo.newest_time().unwrap_or(0))
}

/// The run's statements, as it names them, each with its envelope: the last of each predicate
/// type is the one a record is made from, since a run attested again files beside what it signed
/// before and never over it.
async fn statements(
    store: &Store,
    r: &RunRecord,
) -> Result<BTreeMap<String, (Envelope, Statement)>> {
    let mut out = BTreeMap::new();
    for path in &r.attestations {
        let env = store
            .get_attestation(path)
            .await
            .with_context(|| format!("reading the statement {path} of run `{}`", r.id))?;
        let st: Statement = serde_json::from_slice(&env.decoded_payload()?)
            .with_context(|| format!("reading the statement {path} of run `{}`", r.id))?;
        out.insert(st.predicate_type.clone(), (env, st));
    }
    Ok(out)
}

/// Whether the log holds a record of run `id` among the records `found` for its artifact: the
/// record's digest, and where it is.
fn logged_run(found: &[trigon_attest::evidence::Found], id: &str) -> Option<(Digest, LeafPos)> {
    found.iter().find_map(|f| {
        let v = f.verified()?;
        let run = v.statement.predicate.pointer("/run/id")?.as_str()?;
        (run == id).then_some((f.leaf.record, f.pos))
    })
}

/// Step 2 for runs: a record for each, or every refusal at once.
fn runs(
    base: &Base,
    ids: &[String],
    s: &Settings,
    store: &Store,
    rt: &tokio::runtime::Runtime,
) -> Result<(Vec<Entry>, Vec<Completion>)> {
    let index = trigon_api::Index::new();
    rt.block_on(index.refresh(
        store,
        Switches {
            stop_divergences: base.kill_switch,
            confirmation: s.confirmation,
        },
    ))
    .map_err(|e| anyhow!("reading the store: {e}"))?;
    let time = leaf_time(base);
    let key = base.repo.keys().current().clone();
    let mut refused: Vec<String> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut completions: Vec<Completion> = Vec::new();
    // Artifacts this publication already has a record for, by sha256, and the run it is of.
    let mut subjects: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    // Staged as they are planned, so a later run's record is checked against evidence an earlier
    // one in this publication writes.
    let mut staged: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for id in ids {
        let refuse = |why: String| format!("run `{id}`: {why}");
        if !seen.insert(id) {
            refused.push(refuse("it is named twice".into()));
            continue;
        }
        let Some(r) = index.get(id) else {
            refused.push(refuse("the store holds no such run".into()));
            continue;
        };
        let publication = index
            .entry(id)
            .map(|e| e.publication)
            .unwrap_or(Publication::Withheld {
                because: trigon_api::Withheld::NoOutcome,
            });
        let void = match publication {
            Publication::Withheld { because } => {
                refused.push(refuse(format!(
                    "the publication gate withholds it ({}): {}",
                    because.key(),
                    because.sentence()
                )));
                continue;
            }
            Publication::Void { .. } => true,
            Publication::Published => false,
        };
        if !void && r.outcome.as_deref() == Some("divergent") {
            refused.push(refuse(match s.divergences {
                Divergences::Refuse => "it is a divergence, and `[publish] divergences` is \
                    \"refuse\": a divergence is a public accusation, and ADR-0010 safeguard 4, \
                    notifying the maintainer, has no channel until docs/19 D7 decides one"
                    .into(),
                Divergences::Feed => "it is a divergence, and `[publish] divergences = \
                    \"feed\"` publishes one with an entry in feed/divergences.atom, which is not \
                    built yet (docs/19 §10 phase 5); nothing is published without it"
                    .into(),
            }));
            continue;
        }
        // What the log already holds of this run, and of an attempt it agrees with, is asked by
        // the artifact the run is about and before its statements are read: a run published, or
        // the second of an agreeing pair, is refused whatever it was signed as.
        let sha256 = r.upstream.sha256.to_hex();
        let found = base
            .repo
            .lookup(&Key::Digest {
                algorithm: "sha256",
                hex: sha256.clone(),
            })
            .found;
        if let Some(p) = &r.published {
            refused.push(refuse(format!(
                "it is already published: the record sha256:{} at leaf {} of {}, in commit {}",
                p.record.to_hex(),
                p.leaf,
                p.repository,
                p.commit
            )));
            continue;
        }
        // Logged, and the run does not say so: a crash came after the push. Completed, never
        // logged again.
        if let Some((logged, pos)) = logged_run(&found, id) {
            completions.push(Completion {
                run: id.clone(),
                record: logged,
                pos,
            });
            continue;
        }
        // Of two agreeing attempts, one is published (`docs/19` §3).
        if let Some(other) = index.agreeing(id).into_iter().find(|o| {
            o.published.is_some()
                || logged_run(&found, &o.id).is_some()
                || entries
                    .iter()
                    .any(|e| e.run.as_deref() == Some(o.id.as_str()))
        }) {
            refused.push(refuse(format!(
                "it agrees with run `{}`, which is {}: of two agreeing attempts one is published, \
                 and the second would be the same finding again (docs/19 §3)",
                other.id,
                if other.published.is_some() || logged_run(&found, &other.id).is_some() {
                    "published"
                } else {
                    "named before it here"
                }
            )));
            continue;
        }
        let signed = match rt.block_on(statements(store, &r)) {
            Ok(s) => s,
            Err(e) => {
                refused.push(refuse(format!("{e:#}")));
                continue;
            }
        };
        // A void publishes only as `void/v1`, whatever else the run was once signed as; a verdict
        // as its verdict, with the `rebuild` and `buildobservation` signed beside it.
        let wanted: &[&str] = match (void, r.outcome.as_deref()) {
            (true, _) => &[VOID],
            (false, Some("divergent")) => &[DIVERGENCE_V2, REBUILD, BUILD_OBSERVATION],
            (false, _) => &[EQUIVALENCE_V2, REBUILD, BUILD_OBSERVATION],
        };
        let Some((primary, st)) = signed.get(wanted[0]) else {
            refused.push(refuse(format!(
                "it has no `{}` statement to publish{}. Sign one with `trigon attest {id} --key \
                 <key>`",
                wanted[0],
                if void {
                    ", and a void run publishes as nothing else"
                } else {
                    ""
                }
            )));
            continue;
        };
        if !primary.is_signed() {
            refused.push(refuse(format!(
                "its `{}` statement is unsigned; attest it again with --key",
                wanted[0]
            )));
            continue;
        }
        if !void && let Err(why) = recourse(st, s) {
            refused.push(refuse(why));
            continue;
        }
        let envelopes: Vec<Envelope> = wanted
            .iter()
            .filter_map(|p| signed.get(*p).map(|(e, _)| e.clone()))
            .collect();
        let made = Record::assemble(envelopes).and_then(|rec| {
            let bytes = rec.encode()?;
            Ok((rec, bytes))
        });
        let (record, bytes) = match made {
            Ok(m) => m,
            Err(e) => {
                refused.push(refuse(format!("its statements do not make a record: {e}")));
                continue;
            }
        };
        let digest = Record::digest_of(&bytes);
        // Logged, and not found above because its file is not one this could read: completed as
        // a crash after the push leaves it, never logged again.
        if let Some((pos, _)) = base.repo.record_leaves().find(|(_, l)| l.record == digest) {
            completions.push(Completion {
                run: id.clone(),
                record: digest,
                pos,
            });
            continue;
        }
        if let Some(earlier) = subjects.get(&sha256) {
            refused.push(refuse(format!(
                "it is about the same artifact, sha256:{sha256}, as run `{earlier}`, named before \
                 it. Publish one; the other can supersede it afterwards"
            )));
            continue;
        }
        if let Err(why) = supersedes_what_is_current(st, &found, base) {
            refused.push(refuse(why));
            continue;
        }

        let mut evidence = Vec::new();
        let mut missing = None;
        for (name, value) in &record.evidence {
            if name == evidence_key::REBUILT_ARTIFACT {
                continue;
            }
            let d = value
                .strip_prefix("sha256:")
                .and_then(|h| Digest::from_hex(h).ok())
                .expect("a record's evidence map is `sha256:<hex>`");
            match rt.block_on(store.blobs().get(&d)) {
                Ok(bytes) => evidence.push((d, bytes.to_vec())),
                Err(e) => {
                    missing = Some(format!(
                        "its `{name}` evidence, sha256:{}, is not in the store ({e}), and a record \
                         is published with the evidence it names",
                        d.to_hex()
                    ));
                    break;
                }
            }
        }
        if let Some(why) = missing {
            refused.push(refuse(why));
            continue;
        }
        let leaf = match record_leaf(&bytes, &key.key_id(), time) {
            Ok(l) => l,
            Err(e) => {
                refused.push(refuse(format!("{e}")));
                continue;
            }
        };
        let entry = Entry {
            run: Some(id.clone()),
            said: format!(
                "run {id}: {} {}, {}",
                predicate_name(&st.predicate_type),
                leaf.outcome.map(|o| o.as_str()).unwrap_or_default(),
                leaf.purl
            ),
            leaf: Leaf::Record(leaf),
            record: Some((digest, bytes)),
            evidence,
        };
        if let Err(why) = client_accepts(base, &entry, entries.len() as u64, &mut staged) {
            refused.push(refuse(why));
            continue;
        }
        subjects.insert(sha256, id.clone());
        entries.push(entry);
    }
    if !refused.is_empty() {
        bail!(
            "refusing to publish, and nothing was written:\n  - {}",
            refused.join("\n  - ")
        );
    }
    Ok((entries, completions))
}

/// `docs/19` §2.4 and §4.2 item 6: a verdict is published with the command that would falsify it,
/// naming `[publish] origin`, and the dispute pointer `[publish] disputes` names.
fn recourse(st: &Statement, s: &Settings) -> Result<(), String> {
    let again = "set `[publish] origin` and `disputes` and attest it again";
    let Some(command) = st.predicate.get("falsifyingCommand") else {
        return Err(format!(
            "its verdict signs no falsifying command, so no reader could check it: it was attested \
             with no `[publish] origin` and `disputes` set; {again}"
        ));
    };
    let origin = serde_json::from_value::<FalsifyingCommand>(command.clone())
        .ok()
        .and_then(|c| {
            let at = c.argv.iter().position(|a| a == "--origin")?;
            c.argv.get(at + 1).cloned()
        });
    if origin.as_deref() != Some(s.origin.as_str()) {
        return Err(format!(
            "its falsifying command names the log `{}`, and `[publish] origin` is `{}`: a reader \
             would look for it in another source; {again}",
            printable(origin.as_deref().unwrap_or("none")),
            s.origin
        ));
    }
    let Some(disputes) = &s.disputes else {
        return Err(
            "`[publish] disputes` is not set, and a verdict is published with where to dispute it"
                .into(),
        );
    };
    let pointer = st
        .predicate
        .get("disputePointer")
        .and_then(|p| serde_json::from_value::<DisputePointer>(p.clone()).ok());
    match pointer {
        Some(DisputePointer::Url { url }) if url == *disputes => Ok(()),
        Some(DisputePointer::Url { url }) => Err(format!(
            "its dispute pointer is `{}`, and `[publish] disputes` is `{disputes}`; {again}",
            printable(&url)
        )),
        None => Err(format!(
            "its verdict signs no dispute pointer, so a reader could not dispute it; {again}"
        )),
    }
}

/// `docs/19` §3: a verdict or a void for an artifact with a current record is published only as
/// its supersession, and a supersession names a logged record of the same artifact that nothing
/// supersedes yet. A record superseded by nothing — current, deleted or failed — is standing, and
/// a second standing record for one artifact is two answers a client can only show side by side.
fn supersedes_what_is_current(
    st: &Statement,
    found: &[trigon_attest::evidence::Found],
    base: &Base,
) -> Result<(), String> {
    let standing: Vec<&trigon_attest::evidence::Found> = found
        .iter()
        .filter(|f| f.superseded_by.is_empty())
        .collect();
    let named = st
        .predicate
        .get("supersedes")
        .and_then(|v| v.as_str())
        .and_then(|v| v.strip_prefix("sha256:"))
        .and_then(|h| Digest::from_hex(h).ok());
    let how = "sign its verdict as the supersession: `trigon attest <run> --supersedes <record \
               file> --reason <code>` (docs/19 §3)";
    if standing.len() > 1 {
        return Err(format!(
            "its artifact has {} records nothing supersedes, and one supersession can replace \
             only one of them",
            standing.len()
        ));
    }
    match (named, standing.first()) {
        (None, None) => Ok(()),
        (None, Some(one)) => Err(format!(
            "its artifact has a current record, sha256:{} at leaf {}; {how}",
            one.leaf.record.to_hex(),
            one.pos.index
        )),
        (Some(d), Some(one)) if one.leaf.record == d => Ok(()),
        (Some(d), current) => {
            let logged = base.repo.record_leaves().any(|(_, l)| l.record == d);
            Err(match (logged, current) {
                (false, _) => format!(
                    "it supersedes sha256:{}, which this repository's log does not hold, so no \
                     client would ever apply it",
                    d.to_hex()
                ),
                (true, Some(one)) => format!(
                    "it supersedes sha256:{}, and the record current for its artifact is \
                     sha256:{}; supersede that one",
                    d.to_hex(),
                    one.leaf.record.to_hex()
                ),
                (true, None) => format!(
                    "it supersedes sha256:{}, which is no record of its artifact nothing \
                     supersedes: it is about another artifact, or already superseded",
                    d.to_hex()
                ),
            })
        }
    }
}

/// Check a planned record with the client's own `check_record`, against the evidence already in
/// the repository and what this publication stages, at the leaf it will have: a record every
/// client would refuse is refused here, before anything is written.
fn client_accepts(
    base: &Base,
    entry: &Entry,
    offset: u64,
    staged: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let (Some((digest, bytes)), Leaf::Record(leaf)) = (&entry.record, &entry.leaf) else {
        return Ok(());
    };
    for (d, e) in &entry.evidence {
        staged.insert(evidence_path(d), e.clone());
    }
    staged.insert(record_path(digest), bytes.clone());
    let under = DirFiles::new(&base.root);
    let files = Staged::new(staged, &under);
    check_record(
        bytes,
        Some((base.pos(offset), leaf)),
        base.log().origin(),
        base.repo.keys(),
        &files,
        None,
    )
    .map(|_| ())
    .map_err(|e| format!("every client would refuse its record: {e}"))
}

/// Step 2 for `--withdrawal`: a record of the withdrawal a `trigon attest --withdraw` signed, of a
/// record the log holds and nothing supersedes.
fn withdrawal(base: &Base, path: &Path, s: &Settings) -> Result<Vec<Entry>> {
    let _ = s;
    let text = read_small(path, ENVELOPE_LIMIT)?
        .with_context(|| format!("{} is not there", path.display()))?;
    let env: Envelope = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a DSSE envelope", path.display()))?;
    let st: Statement = serde_json::from_slice(&env.decoded_payload()?)
        .with_context(|| format!("{} holds no in-toto statement", path.display()))?;
    if st.predicate_type != WITHDRAWAL {
        bail!(
            "{} is a `{}` statement, and --withdrawal publishes a `{WITHDRAWAL}`, as `trigon \
             attest --withdraw <record> --reason <code>` signs one",
            path.display(),
            printable(&st.predicate_type)
        );
    }
    if !env.is_signed() {
        bail!(
            "{} is unsigned; sign the withdrawal with `trigon attest --withdraw … --key <key>`",
            path.display()
        );
    }
    let of = st
        .predicate
        .get("supersedes")
        .and_then(|v| v.as_str())
        .and_then(|v| v.strip_prefix("sha256:"))
        .and_then(|h| Digest::from_hex(h).ok())
        .context("the withdrawal names no record it withdraws")?;
    let Some((pos, target)) = base.repo.record_leaves().find(|(_, l)| l.record == of) else {
        bail!(
            "the withdrawal is of sha256:{}, which this repository's log does not hold; a \
             withdrawal is published only of a logged record",
            of.to_hex()
        );
    };
    let record = Record::assemble(vec![env])?;
    let bytes = record.encode()?;
    let digest = Record::digest_of(&bytes);
    if let Some((at, _)) = base.repo.record_leaves().find(|(_, l)| l.record == digest) {
        bail!(
            "this withdrawal is already logged, at leaf {} of {}: nothing to publish",
            at.index,
            s.location
        );
    }
    let key = Key::Digest {
        algorithm: "sha256",
        hex: target.subject.get("sha256").cloned().unwrap_or_default(),
    };
    let found = base.repo.lookup(&key).found;
    if let Some(f) = found.iter().find(|f| f.leaf.record == of)
        && let Some(by) = f.superseded_by.first()
    {
        bail!(
            "sha256:{} is already superseded, by sha256:{} at leaf {} ({}); withdraw the record \
             that is current",
            of.to_hex(),
            by.record.to_hex(),
            by.pos.index,
            by.reason
        );
    }
    let leaf = record_leaf(
        &bytes,
        &base.repo.keys().current().key_id(),
        leaf_time(base),
    )?;
    if leaf.subject != target.subject || leaf.purl != target.purl {
        bail!(
            "the withdrawal is about {} ({}), and the record it withdraws, at leaf {}, is about \
             {} ({}); a client applies a withdrawal only to a record of the same artifact",
            leaf.subject.get("sha256").map_or("nothing", String::as_str),
            printable(&leaf.purl),
            pos.index,
            target
                .subject
                .get("sha256")
                .map_or("nothing", String::as_str),
            target.purl
        );
    }
    let entry = Entry {
        run: None,
        said: format!(
            "withdrawal of sha256:{} ({})",
            of.to_hex(),
            leaf.reason.map(|r| r.as_str()).unwrap_or_default()
        ),
        leaf: Leaf::Record(leaf),
        record: Some((digest, bytes)),
        evidence: Vec::new(),
    };
    client_accepts(base, &entry, 0, &mut BTreeMap::new()).map_err(anyhow::Error::msg)?;
    Ok(vec![entry])
}

/// Step 2 for `--heartbeat`: a heartbeat leaf where the newest leaf is older than `[publish]
/// heartbeat`; otherwise nothing, and why.
fn heartbeat(base: &Base, s: &Settings) -> Result<Result<Vec<Entry>, String>> {
    let time = leaf_time(base);
    if let Some(newest) = base.repo.newest_time() {
        let age = time.saturating_sub(newest);
        if age < s.heartbeat.as_secs() {
            return Ok(Err(format!(
                "heartbeat not due: the newest leaf was logged at {} ({} ago), within `[publish] \
                 heartbeat` of {}. Nothing is written",
                crate::rfc3339_from_unix(newest),
                human(Duration::from_secs(age)),
                human(s.heartbeat)
            )));
        }
    }
    Ok(Ok(vec![Entry {
        run: None,
        said: "heartbeat".into(),
        leaf: Leaf::Heartbeat(HeartbeatLeaf { time }),
        record: None,
        evidence: Vec::new(),
    }]))
}

/// `--reconcile`: `index/` rebuilt from the log whole — every file the log implies written as it
/// implies it, and every other file under `index/` removed.
fn reconcile(base: &Base) -> Result<Plan> {
    let mut writes = BTreeMap::new();
    let mut want = BTreeSet::new();
    for (path, file) in index_files(base.repo.source())? {
        let bytes = file.encode()?;
        if differs(&base.root, &path, &bytes) {
            writes.insert(path.clone(), bytes);
        }
        want.insert(path);
    }
    let mut removes = Vec::new();
    for path in files_under(&base.root, "index")? {
        if !want.contains(&path) {
            removes.push(path);
        }
    }
    Ok(Plan {
        entries: Vec::new(),
        completions: Vec::new(),
        message: format!(
            "publish: reconcile index/, tree {}",
            base.log().checkpoint().size()
        ),
        writes,
        removes,
        checkpoint: None,
        idle: "index/ is already what the log implies; nothing is committed".into(),
    })
}

/// Every regular file under `dir` of the tree at `root`, by path in the tree; a link is listed as
/// a file, never followed. `dir` itself is refused where it is a link or a file, before anything is
/// read through it: git stores links, and one planted as `index` would have the walk list a
/// directory of the host's.
fn files_under(root: &Path, dir: &str) -> Result<Vec<String>> {
    // Every directory on the way to a file under it, `dir` included, is the tree's own.
    inside(root, &format!("{dir}/-"))?;
    match std::fs::symlink_metadata(root.join(dir)) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {dir}")),
    }
    let mut out = Vec::new();
    let mut stack = vec![dir.to_string()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(root.join(&d)) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {d}")),
        };
        for e in entries {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let path = format!("{d}/{name}");
            if e.file_type()?.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Step 4, in memory: every file the entries need, the tiles and bundles of the append, the index
/// files of every key of every new record, and the commit message.
fn assemble(base: &Base, entries: Vec<Entry>, completions: Vec<Completion>) -> Result<Plan> {
    let old = base.log().size();
    if entries.is_empty() {
        return Ok(Plan {
            entries,
            completions,
            writes: BTreeMap::new(),
            removes: Vec::new(),
            checkpoint: None,
            message: String::new(),
            idle: "nothing to publish".into(),
        });
    }
    let leaves: Vec<Leaf> = entries.iter().map(|e| e.leaf.clone()).collect();
    let append = base.log().plan_append(&leaves)?;
    let mut writes = BTreeMap::new();
    let put = |writes: &mut BTreeMap<String, Vec<u8>>, path: String, bytes: Vec<u8>| {
        if differs(&base.root, &path, &bytes) {
            writes.insert(path, bytes);
        }
    };
    for e in &entries {
        if let Some((d, bytes)) = &e.record {
            put(&mut writes, record_path(d), bytes.clone());
        }
        for (d, bytes) in &e.evidence {
            put(&mut writes, evidence_path(d), bytes.clone());
        }
    }
    for (path, bytes) in &append.files {
        // Written whatever is there: anything at a path the append writes, beyond the checkpoint,
        // is not the log's and is overwritten.
        writes.insert(format!("{}/{path}", base.dir), bytes.clone());
    }
    let mut keys = BTreeSet::new();
    for leaf in &leaves {
        if let Leaf::Record(r) = leaf {
            keys.extend(IndexKey::of_leaf(r)?.into_iter().map(|k| k.path()));
        }
    }
    for (path, file) in index_files_after(base.repo.source(), &leaves)? {
        if keys.contains(&path) {
            put(&mut writes, path, file.encode()?);
        }
    }
    let removes = append
        .obsolete
        .iter()
        .map(|p| format!("{}/{p}", base.dir))
        .collect();
    let records = leaves
        .iter()
        .filter(|l| matches!(l, Leaf::Record(_)))
        .count();
    let what = match records {
        0 => "heartbeat".to_string(),
        1 => "1 record".to_string(),
        n => format!("{n} records"),
    };
    Ok(Plan {
        message: format!("publish: {what}, tree {old} → {}", append.size),
        checkpoint: Some(Checkpoint {
            origin: base.log().origin().to_string(),
            size: append.size,
            root: append.root,
        }),
        entries,
        completions,
        writes,
        removes,
        idle: String::new(),
    })
}

/// Whether the file at `path` in the tree is other than `bytes`, or not a plain file at all.
fn differs(root: &Path, path: &str, bytes: &[u8]) -> bool {
    let full = root.join(path);
    match std::fs::symlink_metadata(&full) {
        Ok(m) if m.is_file() => std::fs::read(&full).map_or(true, |b| b != bytes),
        _ => true,
    }
}

/// `path` in the tree at `root`, where every directory on the way is a directory of the tree and
/// not a link out of it: git stores links, and one planted where a publication writes would have
/// it write outside the repository.
fn inside(root: &Path, path: &str) -> Result<PathBuf> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut at = root.to_path_buf();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || *part == "." || *part == ".." {
            bail!("`{path}` is not a path inside the repository");
        }
        at.push(part);
        if i + 1 == parts.len() {
            break;
        }
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!(
                "`{}` in {} is a link or a file where a publication writes a directory, and \
                 publish writes only inside the repository. Remove it from the repository",
                parts[..=i].join("/"),
                root.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", at.display())),
        }
    }
    Ok(at)
}

/// Step 4, on disk.
fn write(root: &Path, plan: &Plan) -> Result<()> {
    for path in &plan.removes {
        let full = inside(root, path)?;
        match std::fs::symlink_metadata(&full) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(&full)?,
            Ok(_) => std::fs::remove_file(&full)?,
            Err(_) => {}
        }
    }
    for (path, bytes) in &plan.writes {
        let full = inside(root, path)?;
        // Whatever is there is replaced, never written through: a link at the path is removed,
        // not followed.
        match std::fs::symlink_metadata(&full) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(&full)?,
            Ok(_) => std::fs::remove_file(&full)?,
            Err(_) => {}
        }
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&full, bytes).with_context(|| format!("writing {}", full.display()))?;
    }
    Ok(())
}

/// Step 5: `trigon log sign`, a child process of this binary that holds the log key and checks the
/// tree again from disk. Its checkpoint is then held to the one planned, and returned as it is on
/// disk, for the commit to hold exactly those bytes.
fn sign(base: &Base, planned: &Checkpoint, s: &Settings) -> Result<Vec<u8>> {
    let key = s
        .log_key
        .as_ref()
        .expect("checked when the settings were read");
    let exe = std::env::current_exe().context("finding this binary to run `trigon log sign`")?;
    let out = std::process::Command::new(exe)
        .args(["log", "sign", "--tree"])
        .arg(&base.root)
        .args([
            "--log",
            &base.dir,
            "--size",
            &planned.size.to_string(),
            "--key",
        ])
        .arg(key)
        .stdin(std::process::Stdio::null())
        .output()
        .context("running `trigon log sign`")?;
    if !out.status.success() {
        bail!(
            "`trigon log sign` refused to sign the new checkpoint, and nothing is committed:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let bytes = DirFiles::in_repository(&base.root, &base.dir)
        .read("checkpoint", 64 * 1024)?
        .context("`trigon log sign` succeeded and wrote no checkpoint")?;
    let signed = SignedCheckpoint::open(&bytes, &base.vkey)?;
    if signed.checkpoint() != planned {
        bail!(
            "`trigon log sign` signed {} leaves with another root than the {} planned; nothing is \
             committed",
            signed.size(),
            planned.size
        );
    }
    Ok(bytes)
}

/// Step 7, and what a person is told: `RunRecord.published` for every run logged, those a crash
/// left without it included, and the checkpoint this host has now published.
fn complete(
    base: &Base,
    plan: &Plan,
    s: &Settings,
    (store, newest): (&Store, &NewestPublished),
    rt: &tokio::runtime::Runtime,
    commit: Option<&str>,
) -> Result<()> {
    let log = (base.dir != "log").then(|| base.dir.clone());
    for (i, e) in plan.entries.iter().enumerate() {
        let pos = base.pos(i as u64);
        println!("logged    leaf {}: {}", pos.index, e.said);
        if let (Some(run), Some((record, _)), Some(commit)) = (&e.run, &e.record, commit) {
            rt.block_on(store.record_published(
                run,
                &Published {
                    repository: s.location.to_string(),
                    commit: commit.to_string(),
                    record: *record,
                    leaf: pos.index,
                    log: log.clone(),
                },
            ))?;
        }
    }
    for c in &plan.completions {
        let commit = logged_in(base, c.pos.index)?;
        // The log holds the leaf, and every client reports a leaf whose record file is gone as
        // deleted, whatever its outcome: said here, since this run's record is the one missing.
        let path = record_path(&c.record);
        if std::fs::symlink_metadata(base.root.join(&path)).is_err() {
            eprintln!(
                "warning: the record of run {} is logged at leaf {}, and {} has no `{path}`: every \
                 client reports it as deleted until the file is restored",
                c.run, c.pos.index, s.location
            );
        }
        rt.block_on(store.record_published(
            &c.run,
            &Published {
                repository: s.location.to_string(),
                commit: commit.clone(),
                record: c.record,
                leaf: c.pos.index,
                log: log.clone(),
            },
        ))?;
        println!(
            "completed run {}: its record sha256:{} was logged at leaf {} in commit {} and the run \
             did not say so; it does now",
            c.run,
            c.record.to_hex(),
            c.pos.index,
            commit
        );
    }
    let Some(commit) = commit else {
        if plan.completions.is_empty() && plan.entries.is_empty() {
            println!("{}", plan.idle);
        }
        return Ok(());
    };
    let bytes = DirFiles::in_repository(&base.root, &base.dir)
        .read("checkpoint", 64 * 1024)?
        .context("the published tree has no checkpoint")?;
    let signed = SignedCheckpoint::open(&bytes, &base.vkey)?;
    // The newest checkpoint this host has published is now this one: it is what the push made the
    // remote hold, and what every later tree, from any store, must extend.
    newest.advance(&signed, &base.vkey)?;
    println!(
        "commit    {} {}",
        style::ident(commit),
        style::muted(&format!("({})", plan.message))
    );
    println!(
        "checkpoint {}",
        signed.checkpoint().body().trim_end().replace('\n', " ")
    );
    Ok(())
}

/// The commit that logged leaf `index`: the first on the branch whose checkpoint, opened under the
/// log's key, covers it. Asked of the log's own history rather than of when the record file was
/// added, which whoever can push may have removed, or never had.
fn logged_in(base: &Base, index: u64) -> Result<String> {
    let path = format!("{}/checkpoint", base.dir);
    let commits = git::text(
        Some(&base.root),
        &[
            "--literal-pathspecs",
            "log",
            "--format=%H",
            "--reverse",
            "--first-parent",
            "--",
            &path,
        ],
    )?;
    let commits: Vec<&str> = commits.lines().collect();
    let revs: Vec<String> = commits.iter().map(|c| format!("{c}:{path}")).collect();
    for (commit, bytes) in commits.iter().zip(git::blobs(&base.root, &revs)?) {
        let covers = bytes
            .and_then(|b| SignedCheckpoint::open(&b, &base.vkey).ok())
            .is_some_and(|c| c.size() > index);
        if covers {
            return Ok(commit.to_string());
        }
    }
    bail!(
        "no commit of {}'s `{}` has a checkpoint covering leaf {index}, and its log holds it: the \
         branch's history is not the log's",
        base.root.display(),
        path
    )
}

/// Every file and leaf a publication would write, and the checkpoint body it would sign, unsigned.
fn show(base: &Base, plan: &Plan) {
    println!(
        "dry run   nothing is written, and `trigon log sign` is not run; the working clone and the \
         repository are left as they are"
    );
    if plan.writes.is_empty() && plan.removes.is_empty() {
        for c in &plan.completions {
            println!(
                "complete  run {}: its record sha256:{} is logged at leaf {}",
                c.run,
                c.record.to_hex(),
                c.pos.index
            );
        }
        if plan.completions.is_empty() {
            println!("{}", plan.idle);
        }
        return;
    }
    for path in &plan.removes {
        println!("remove    {path}");
    }
    for (path, bytes) in &plan.writes {
        let there = std::fs::symlink_metadata(base.root.join(path)).is_ok();
        println!(
            "write     {path} ({} bytes{})",
            bytes.len(),
            if there {
                ", replacing what is there"
            } else {
                ""
            }
        );
    }
    for (i, e) in plan.entries.iter().enumerate() {
        let leaf = e.leaf.encode().unwrap_or_default();
        println!(
            "leaf {}    {}",
            base.log().size() + i as u64,
            String::from_utf8_lossy(&leaf)
        );
    }
    if let Some(c) = &plan.checkpoint {
        println!("checkpoint, unsigned:");
        for line in c.body().lines() {
            println!("  {line}");
        }
    }
    println!("commit    {}", plan.message);
}

/// A predicate type as a person reads it: `equivalence/v2`.
fn predicate_name(t: &str) -> String {
    t.rsplitn(3, '/')
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/")
}

/// A duration as `[publish] heartbeat` reads to a person: `7 days`, `36 hours`.
pub(crate) fn human(d: Duration) -> String {
    let s = d.as_secs();
    let (n, unit) = match s {
        _ if s % 86_400 == 0 && s > 0 => (s / 86_400, "day"),
        _ if s % 3600 == 0 && s > 0 => (s / 3600, "hour"),
        _ if s % 60 == 0 && s > 0 => (s / 60, "minute"),
        _ => (s, "second"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A small text file, or `None` where there is none; refused whole past `limit` bytes.
fn read_small(path: &Path, limit: u64) -> Result<Option<String>> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut text = String::new();
    file.take(limit + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    if text.len() as u64 > limit {
        bail!("{} is longer than {limit} bytes", path.display());
    }
    Ok(Some(text))
}
