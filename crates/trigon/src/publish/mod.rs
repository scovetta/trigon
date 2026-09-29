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
//!    dispute pointer `[publish] disputes` names; a record not signed by the attestation key the
//!    log has now; where rebuilt artifacts are published, a verdict whose rebuilt artifact is over
//!    GitHub's 2 GiB or is not the one it signs; and any record every client would refuse, checked
//!    with the client's own `check_record` before it is written.
//! 3. Where `[publish] rebuilt_artifacts = "github-release"`, find or upload each verdict's rebuilt
//!    artifact as the release asset `sha256-<hex>` ([`release`]), before anything that names one
//!    is written; an asset a failed attempt uploaded is reused, and one a publication never commits
//!    is harmless.
//! 4. Write each record and its evidence, deduplicated; one leaf per record, in the order the runs
//!    were named, at a time never earlier than the leaf before it; the tiles and bundles the append
//!    writes, the partials it makes obsolete removed; each index file of every key of every new
//!    record, derived from the log whole; and, with a divergence or a record superseding one, the
//!    divergence feed, derived from the log whole too ([`feed`]).
//! 5. Run `trigon log sign` as a child process, which holds the log key and checks the tree again
//!    from disk, against the same newest checkpoint; `publish` never opens the key.
//! 6. Commit exactly what steps 4 and 5 wrote, as one commit, checked to hold those bytes and
//!    nothing else, and push it, never forced. A rejected push whose remote has moved is a lost
//!    race: the commit and the checkpoint signed for it are discarded, and the attempt starts again
//!    from step 1.
//! 7. Record `RunRecord.published` for each run; a run whose record is logged and has none — a
//!    crash between the push and this — is completed here instead of logged again. Only then, with
//!    `--prune`, is each such run's rebuilt artifact pruned from the store.
//!
//! **Rotation goes through the same steps**, 1 and 4 to 6 (`docs/19` §8): `trigon log key-change`
//! logs a key-change leaf signed by the current attestation key and the new one, and `trigon log
//! succeed` a log-end naming a successor, whose final checkpoint `log sign` cosigns with the
//! successor's key, and the successor's log-continuation, in the same commit where the successor
//! is in this repository. A chain of logs is published into at its last log, whose origin must be
//! `[publish] origin`.
//!
//! A local path to a non-bare working tree is published into in place: it must be clean and on
//! `[publish] branch`, the commit is made there, and nothing is pushed.
//!
//! One `publish` runs at a time on a host, whatever store it runs from, under a lock in the host's
//! state directory, and one at a time in a store, under the store's.

mod feed;
pub(crate) mod git;
mod init;
mod lock;
pub(crate) mod release;
mod switch;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use sha2::Digest as _;
use trigon_api::publication::{Confirmation, Publication, Switches};
use trigon_attest::config::{Divergences, Env, EvidenceConfig, RebuiltArtifacts, check_origin};
use trigon_attest::evidence::{
    IndexKey, Key, RECORD_LIMIT, Repository, check_record, evidence_path, index_files,
    index_files_after, record_leaf, record_path,
};
use trigon_attest::location::{Location, Transport, printable};
use trigon_attest::log::{
    Checkpoint, DirFiles, HeartbeatLeaf, KeyChangeKey, KeyChangeLeaf, Leaf, LeafOutcome, LeafPos,
    LogContinuationLeaf, LogEndLeaf, LogFiles as _, RecordLeaf, SignedCheckpoint, SignedNote,
    Staged, Successor, Tree, VerifiedLog, plan_append,
};
use trigon_attest::{
    AttestationKey, BUILD_OBSERVATION, DIVERGENCE_V2, DisputePointer, EQUIVALENCE_V2, Envelope,
    FalsifyingCommand, LogVkey, REBUILD, Record, Statement, VOID, WITHDRAWAL, evidence_key,
};
use trigon_core::Digest;
use trigon_store::{Pruned, Published, RunRecord, Store};

use crate::evidence_log::{NewestPublished, host_state};
use crate::style;

pub(crate) use init::{InitArgs, run as init};
pub(crate) use switch::reader as repository_switch;

/// How many times a publication is built again after losing a push to another writer. With one
/// publishing host and its lock the race cannot happen (`docs/19` D5); this bounds it where a
/// second host is a configuration mistake away.
const ATTEMPTS: u32 = 5;

/// Where in a repository a publication reads and writes. A working tree published into must hold
/// nothing git ignores under them, and a publication that fails is discarded there, ignored files
/// included.
const PUBLICATION_PATHS: [&str; 8] = [
    "keys",
    "log",
    "records",
    "evidence",
    "index",
    "feed",
    "kill-switch",
    "README.md",
];

/// The longest `keys/*` file read: a PEM key or a verifier key is under 200 bytes.
const KEY_FILE_LIMIT: u64 = 16 * 1024;

/// The longest envelope `--withdrawal` reads. A withdrawal is a few hundred bytes of statement.
const ENVELOPE_LIMIT: u64 = 1 << 20;

/// The longest README read, to regenerate its account of rotations.
const README_LIMIT: u64 = 1 << 20;

/// The heading of the README's account of key changes and successors, which is regenerated from
/// the log whole with each rotation; everything above it is left as it is.
const ROTATIONS: &str = "## Key changes and successors";

/// What `trigon publish` is given.
pub(crate) struct Args {
    pub runs: Vec<String>,
    pub store: PathBuf,
    pub repo: Option<String>,
    pub withdrawal: Option<PathBuf>,
    pub heartbeat: bool,
    pub dry_run: bool,
    pub reconcile: bool,
    pub prune: bool,
}

/// What `trigon log key-change` is given.
pub(crate) struct KeyChangeArgs {
    pub key: PathBuf,
    pub new_key: PathBuf,
    pub store: PathBuf,
    pub repo: Option<String>,
    pub dry_run: bool,
}

/// What `trigon log succeed` is given.
pub(crate) struct SucceedArgs {
    pub origin: String,
    pub log_key: PathBuf,
    pub urls: Vec<String>,
    pub dir: Option<String>,
    pub store: PathBuf,
    pub repo: Option<String>,
    pub dry_run: bool,
}

/// Where and how any of them writes.
struct Common {
    store: PathBuf,
    repo: Option<String>,
    dry_run: bool,
    prune: bool,
}

/// What one invocation publishes.
enum What {
    Runs(Vec<String>),
    Withdrawal(PathBuf),
    Heartbeat,
    Reconcile,
    /// A key-change leaf: the current attestation key's file, and the new one's.
    KeyChange {
        key: PathBuf,
        new_key: PathBuf,
    },
    /// A log-end, and the successor it names begun.
    Succeed(Succession),
}

/// The successor `trigon log succeed` is asked for.
struct Succession {
    origin: String,
    log_key: PathBuf,
    urls: Vec<String>,
    dir: Option<String>,
}

/// `[publish]`, and the repository this run publishes to, resolved.
struct Settings {
    location: Location,
    branch: String,
    origin: String,
    disputes: Option<String>,
    log_key: Option<PathBuf>,
    divergences: Divergences,
    rebuilt_artifacts: RebuiltArtifacts,
    /// GitHub's API, for the releases rebuilt artifacts are assets of: where they are published
    /// and this run publishes runs. `None` otherwise, and in a dry run with no token.
    github: Option<release::GitHub>,
    heartbeat: Duration,
    confirmation: Confirmation,
    env: Env,
    /// The whole configuration, for the evidence sources step 2 reads a chain through when it
    /// goes on from another repository ([`whole_chain`]).
    config: EvidenceConfig,
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
    /// The log key `keys/log.vkey` names: the first log's, which the chain is verified from.
    pinned: LogVkey,
    /// The log key of the log a publication appends to.
    vkey: LogVkey,
    kill_switch: bool,
    /// The successor the chain's last log names in another repository, where it has ended.
    ended: Option<Successor>,
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
    /// The rebuilt artifact the record names, where it is published as a release asset.
    asset: Option<release::Asset>,
    /// What it is, for a person.
    said: String,
}

/// A succession, as planned: the successor the log-end names, and what begins it.
struct SuccessionPlan {
    successor: Successor,
    vkey: LogVkey,
    /// The successor's log key file, read only by the `trigon log sign` this runs.
    log_key: PathBuf,
    /// When the log-end is logged, which the log-continuation takes too.
    end_time: u64,
    /// Whether the log ended already, in a publication whose successor elsewhere was not begun.
    ended_already: bool,
    /// The newest checkpoint of the successor this host has published.
    newest: NewestPublished,
}

impl SuccessionPlan {
    /// Whether the successor is in this repository, and begun in the same commit.
    fn here(&self) -> bool {
        self.successor.in_this_repository()
    }
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
    /// The new tree's checkpoint, unsigned; `None` where nothing is appended, or where its root
    /// covers signatures a dry run does not make.
    checkpoint: Option<Checkpoint>,
    /// Files a dry run shows by path alone, since their bytes cover signatures only the
    /// publication makes: a key change's bundle and tiles, by path in the repository.
    unsigned: Vec<String>,
    message: String,
    /// What is said where nothing is written.
    idle: String,
    /// When the new leaves are logged: the month a rebuilt artifact's release is named by.
    time: u64,
    /// The succession, where the publication ends the log.
    succession: Option<SuccessionPlan>,
}

impl Plan {
    /// Every rebuilt artifact the new records name as a release asset, once each.
    fn assets(&self) -> Vec<release::Asset> {
        let mut seen = BTreeSet::new();
        self.entries
            .iter()
            .filter_map(|e| e.asset.clone())
            .filter(|a| seen.insert(a.digest))
            .collect()
    }
}

pub(crate) fn run(args: Args) -> Result<()> {
    let what = what(&args)?;
    publish(
        Common {
            store: args.store,
            repo: args.repo,
            dry_run: args.dry_run,
            prune: args.prune,
        },
        what,
    )
}

/// `trigon log key-change`: a key-change leaf, through publish's steps 1 and 4 to 6.
pub(crate) fn key_change(args: KeyChangeArgs) -> Result<()> {
    publish(
        Common {
            store: args.store,
            repo: args.repo,
            dry_run: args.dry_run,
            prune: false,
        },
        What::KeyChange {
            key: args.key,
            new_key: args.new_key,
        },
    )
}

/// `trigon log succeed`: a log-end and the successor it names, through publish's steps 1 and 4 to
/// 6.
pub(crate) fn succeed(args: SucceedArgs) -> Result<()> {
    publish(
        Common {
            store: args.store,
            repo: args.repo,
            dry_run: args.dry_run,
            prune: false,
        },
        What::Succeed(Succession {
            origin: args.origin,
            log_key: args.log_key,
            urls: args.urls,
            dir: args.dir,
        }),
    )
}

fn publish(common: Common, what: What) -> Result<()> {
    let env = Env::from_process()?;
    let config = EvidenceConfig::load(&env)?;
    crate::say_config_notes(&config);
    let settings = settings(&config, &common, &env, &what)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let store = Store::existing(&common.store)?;
    let state = common
        .store
        .join("publish")
        .join(hex(&sha2::Sha256::digest(settings.location.as_git_arg())));
    let newest = NewestPublished::of(&env, &settings.origin)?;
    // A successor is named by its log key, which a `trigon log public-key` child reads: the process
    // that pushes never opens a log key.
    let successor = match &what {
        What::Succeed(s) => Some(public_key_of(&s.log_key)?),
        _ => None,
    };
    let holder = format!(
        "pid {}, since {}, publishing to {} from {}",
        std::process::id(),
        crate::now_rfc3339(),
        settings.location,
        common.store.display()
    );
    // One per host, whatever store it runs from, and so whatever working clone: two would build on
    // the same log and race to push, and D26's window is open only while they do.
    let _host_lock = lock::Lock::take(&host_state(&env)?.join("lock"), &holder)?;
    let _lock = lock::Lock::take(&common.store.join("publish").join("lock"), &holder)?;
    let place = place(&settings.location, &state)?;
    // A working tree published into is somebody's: a second store must not write it meanwhile.
    let _tree_lock = match (&place, common.dry_run) {
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
        let (base, _scratch) = prepare(&place, &settings, &state, &newest, common.dry_run)?;
        let plan = plan(
            &base,
            &what,
            &settings,
            (&store, &rt),
            successor.as_ref(),
            common.dry_run,
        )?;
        if common.dry_run {
            show(&base, &plan, &settings);
            return Ok(());
        }
        if plan.writes.is_empty() && plan.removes.is_empty() {
            complete(
                &base,
                &plan,
                &settings,
                (&store, &newest),
                &rt,
                None,
                common.prune,
            )?;
            // A log that ended in a publication whose successor, in another repository, was never
            // begun: begun now, from the final checkpoint that publication pushed.
            if let Some(sp) = &plan.succession {
                let end = DirFiles::in_repository(&base.root, &base.dir)
                    .read("checkpoint", 64 * 1024)?
                    .context("the ended log has no checkpoint")?;
                begin_elsewhere(&base, sp, &settings, &end)?;
                advise(&base, &plan);
            }
            return Ok(());
        }
        // Step 3: every rebuilt artifact the new records name, as a release asset, before anything
        // that names one is written.
        let assets = plan.assets();
        if !assets.is_empty() {
            let gh = settings
                .github
                .as_ref()
                .expect("an asset is planned only where the API was set up with the settings");
            let placed = rt.block_on(gh.put(&assets, plan.time, &settings.branch, &store))?;
            for p in placed {
                println!(
                    "asset     {} in release {} of {}{}",
                    p.name,
                    p.release,
                    gh.repository(),
                    if p.reused { ", there already" } else { "" }
                );
            }
            die_at("uploaded");
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
            Some(checkpoint) => Some(sign(
                &base,
                checkpoint,
                &settings,
                plan.succession.as_ref(),
            )?),
            None => None,
        };
        // A successor in this repository is begun in the same commit: its log-continuation holds
        // the final checkpoint just signed by both log keys.
        let begun = match (&plan.succession, &signed) {
            (Some(sp), Some(end)) if sp.here() => begin_here(&base, sp, end)?,
            _ => Vec::new(),
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
        for (path, bytes) in &begun {
            change.writes.push((path.as_str(), bytes.as_slice()));
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
            common.prune,
        )?;
        // A successor in another repository is begun there once this log's end is pushed: never
        // before, since a successor continuing a final checkpoint nobody published would be one
        // a retry could sign a second time, with another root.
        if let (Some(sp), Some(end)) = (&plan.succession, &signed)
            && !sp.here()
        {
            die_at("ended");
            begin_elsewhere(&base, sp, &settings, end)?;
        }
        advise(&base, &plan);
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

fn settings(config: &EvidenceConfig, args: &Common, env: &Env, what: &What) -> Result<Settings> {
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
    // Before anything is read or written: a location with no releases, or no token to upload to
    // one, is refused here, once for every run named. A dry run uploads nothing, and says where it
    // would, token or not.
    let github = match (p.rebuilt_artifacts, what) {
        (RebuiltArtifacts::GithubRelease, What::Runs(_)) => {
            release::repository_of(&location)?;
            match args.dry_run && !release::token_is_set() {
                true => None,
                false => Some(release::GitHub::for_location(&location)?),
            }
        }
        _ => None,
    };
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
        rebuilt_artifacts: p.rebuilt_artifacts,
        github,
        heartbeat: p.heartbeat,
        confirmation: Confirmation::from(p),
        env: env.clone(),
        config: config.clone(),
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
    let began = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
    switch::record_fetch(clone, began, &tracking)?;
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

/// Verify the repository at `root`: its chain of logs, from the one `keys/log.vkey` names,
/// verifies whole and extends the newest checkpoint of the log this host has published or
/// verified, and its last log in this repository is `[publish] origin`'s. A last log that has
/// ended, naming a successor in another repository, is kept in [`Base::ended`]: only `trigon log
/// succeed` builds on it, to begin that successor.
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
    let ended = source.continues_at.clone();
    if last.log.origin() != s.origin {
        let chain = &source.logs;
        // `[publish] origin` is a log of the chain that has ended: the operator has not moved on
        // to its successor.
        if let Some(at) = chain.iter().position(|c| c.log.origin() == s.origin) {
            let next = &chain[at + 1];
            bail!(
                "the log `{}` in {} has ended, and its successor `{}` is at `{}` in the same \
                 repository: publishing continues there. Set `[publish] origin` to `{}` and \
                 `log_key` to the successor's log key, and attest again what is to be published, \
                 since every verdict signs the origin of the log it is published into (docs/19 \
                 §8)",
                s.origin,
                s.location,
                next.log.origin(),
                next.dir,
                next.log.origin()
            );
        }
        if let Some(e) = ended.as_ref().filter(|e| e.origin == s.origin) {
            bail!(
                "`{}` is the successor of the log `{}` in {}, in another repository, {}: publish \
                 there, with `[publish] repo` set to it",
                s.origin,
                last.log.origin(),
                s.location,
                e.urls.join(", ")
            );
        }
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
    let kill_switch = std::fs::symlink_metadata(root.join("kill-switch")).is_ok();
    Ok(Base {
        root: root.to_path_buf(),
        head,
        dir: last.dir.clone(),
        vkey: last.log.vkey().clone(),
        pinned: vkey,
        repo,
        kill_switch,
        ended,
    })
}

/// The chain step 2 asks what is already published (`docs/19` §3): this repository's own, or,
/// where it begins by continuing a log in another repository, the whole of it, which the earlier
/// repositories' logs come first in.
struct Chain<'a> {
    repo: &'a Repository,
    /// How many logs of it come before this repository's first.
    before: usize,
}

impl<'a> Chain<'a> {
    fn of(base: &'a Base, whole: Option<&'a Repository>) -> Chain<'a> {
        match whole {
            Some(w) => Chain {
                repo: w,
                before: w.logs().len() - base.repo.logs().len(),
            },
            None => Chain {
                repo: &base.repo,
                before: 0,
            },
        }
    }

    /// A leaf of the chain as this repository's own chain counts it, or `None` for one in an
    /// earlier repository.
    fn here(&self, pos: LeafPos) -> Option<LeafPos> {
        pos.log.checked_sub(self.before).map(|log| LeafPos {
            log,
            index: pos.index,
        })
    }

    /// Why a run whose record is logged in an earlier repository of the chain is not completed
    /// here: its publication is recorded against the commit that logged it, which only that
    /// repository's history holds.
    fn logged_elsewhere(&self, record: Digest, pos: LeafPos) -> String {
        format!(
            "it is already published: its record sha256:{} is logged at leaf {} of `{}`, in {}, \
             an earlier repository of this chain, and the run does not say so because a crash \
             came between that push and recording it. Nothing is logged again",
            record.to_hex(),
            pos.index,
            self.repo.origin(pos),
            self.repo.root_of(pos).display()
        )
    }
}

/// Where this repository's chain of logs begins by continuing a log in another repository — a
/// successor begun elsewhere by `trigon log succeed --url` — the whole chain, read the way `trigon
/// evidence sync` reads a source's (`docs/19` §6.1, §8): through a configured evidence source whose
/// chain reaches the log this one continues, synced first where it is stale, then this
/// repository's own logs, followed from that log's end. `None` where the chain begins here.
///
/// So a verdict for an artifact with a current record earlier in the chain is refused as a second
/// current record, as it would be in one repository, and a withdrawal may be of a record logged
/// there. Refused where no configured source reaches the log continued from the chain's first
/// log, since step 2 would otherwise judge by part of the chain: a source whose last sync was
/// refused is not read, and nor is one pinned partway through the succession, whose chain begins
/// by continuing a log it does not read. Where none serves, every source this has not just synced
/// is synced now, whatever its age, and looked at once more: its clone may be from before the log
/// it reaches ended, which is the usual order right after `log succeed --url`.
///
/// A dry run syncs nothing: every source is read from its clone as it is.
fn whole_chain(base: &Base, s: &Settings, dry_run: bool) -> Result<Option<Repository>> {
    use crate::evidence::{Mode, ready};
    let first = &base.repo.source().logs[0];
    let Some(Leaf::LogContinuation(c)) = first.log.leaf(0) else {
        return Ok(None);
    };
    let held = c.old_checkpoint()?;
    let config = &s.config;
    let all: Vec<String> = config
        .sources()
        .iter()
        .map(|src| src.name.clone())
        .collect();
    // The sources whose chain, as last synced, reaches the log continued, so that no other is
    // synced for its age; every one where none is known to, since a source never synced may. A
    // dry run syncs nothing, and reads them all.
    let reaches = |name: &str| -> bool {
        config
            .source_state_dir(name)
            .ok()
            .and_then(|d| trigon_attest::state::KeysFile::read(&d).ok().flatten())
            .is_some_and(|k| k.logs.iter().any(|l| l.origin == held.origin))
    };
    let mut asked: Vec<String> = all.iter().filter(|n| reaches(n)).cloned().collect();
    if asked.is_empty() || dry_run {
        asked = all.clone();
    }
    let now = crate::evidence::now();
    let mode = match dry_run {
        true => Mode::Offline,
        false => Mode::Sync,
    };
    let found = match asked.is_empty() {
        true => Vec::new(),
        false => ready(config, &asked, mode, now, false)?,
    };
    // Why each source that reaches the log continued was passed over, by its name.
    let mut passed_over: Vec<(String, String)> = Vec::new();
    if let Some(whole) = chain_through(base, s, &held, &found, &mut passed_over, dry_run)? {
        return Ok(Some(whole));
    }
    if !dry_run {
        let synced: Vec<&str> = found
            .iter()
            .filter(|r| r.synced)
            .map(|r| r.source.name.as_str())
            .collect();
        let behind: Vec<String> = all
            .iter()
            .filter(|n| !synced.contains(&n.as_str()))
            .cloned()
            .collect();
        if !behind.is_empty() {
            passed_over.retain(|(n, _)| !behind.contains(n));
            let again = ready(config, &behind, Mode::Refresh, now, false)?;
            if let Some(whole) =
                chain_through(base, s, &held, &again, &mut passed_over, dry_run)?
            {
                return Ok(Some(whole));
            }
        }
    }
    let why: Vec<&str> = passed_over.iter().map(|(_, w)| w.as_str()).collect();
    bail!(
        "`{}` in {} continues `{}`, which is in another repository, and no evidence source \
         configured here reaches it from the chain's first log{}{}. Publishing reads the whole \
         chain before it refuses a second current record for an artifact (docs/19 §3): add the \
         chain's first repository as a source, pinned to the chain's first log key — `trigon \
         evidence add <name> <its location> --log-key <the first log's key> --attestation-key \
         <key>` — and publish again",
        first.log.origin(),
        s.location,
        held.origin,
        match why.is_empty() {
            true => String::new(),
            false => format!(" that can be read ({})", why.join("; ")),
        },
        match dry_run {
            true => ". A dry run syncs nothing, so each source was read from its clone as it \
                 is: `trigon evidence sync` brings them up to date",
            false => "",
        }
    )
}

/// The whole chain through the first of `found` that reaches the log `held` is the checkpoint of
/// and names this repository's first log as its successor, from the chain's first log; `None`,
/// with why each source that reaches it was passed over, where none does.
fn chain_through(
    base: &Base,
    s: &Settings,
    held: &Checkpoint,
    found: &[crate::evidence::Ready],
    passed_over: &mut Vec<(String, String)>,
    dry_run: bool,
) -> Result<Option<Repository>> {
    let first = &base.repo.source().logs[0];
    for r in found {
        let name = &r.source.name;
        for n in &r.notes {
            println!("source    `{name}`: {n}");
        }
        let Some(o) = &r.opened else {
            continue;
        };
        let logs = o.repo.logs();
        let Some(k) = logs.iter().position(|l| l.origin() == held.origin) else {
            continue;
        };
        if let trigon_attest::evidence::Standing::Refused { why } = &r.standing {
            passed_over.push((
                name.clone(),
                format!(
                    "`{name}` reaches it, and its last sync was refused: {}",
                    printable(why)
                ),
            ));
            continue;
        }
        // A source pinned at a log that itself continues another — a successor's key, in place or
        // elsewhere — reads the chain from partway: a record current in a log before it would not
        // be seen, and a second current record for its artifact would be published.
        if let Some(Leaf::LogContinuation(_)) = logs[0].leaf(0) {
            passed_over.push((
                name.clone(),
                format!(
                    "`{name}` reaches it, and its chain begins at `{}`, which continues an earlier \
                     log that it does not read: it is pinned partway through the succession, and \
                     must be pinned to the chain's first log key",
                    logs[0].origin()
                ),
            ));
            continue;
        }
        let end = logs[k].log_end().map(|e| &e.successor);
        let named = end.is_some_and(|e| {
            e.origin == first.log.origin() && e.log_key == first.log.vkey().to_string()
        });
        if !named {
            passed_over.push((
                name.clone(),
                format!(
                    "`{name}` reaches `{}`, and {} `{}` under its log key{}",
                    held.origin,
                    match end {
                        Some(_) => "its log-end does not name",
                        None => "that log has not ended in its clone, naming",
                    },
                    first.log.origin(),
                    match dry_run && !r.synced {
                        true => ", as its clone holds it",
                        false => "",
                    }
                ),
            ));
            continue;
        }
        trigon_attest::log::follow(
            logs[k],
            &DirFiles::in_repository(&base.root, &first.dir),
            None,
        )
        .with_context(|| {
            format!(
                "`{}` in {} is not the successor `{}`'s log-end names",
                first.log.origin(),
                s.location,
                held.origin
            )
        })?;
        let mut parts = o.repo.parts_through(k);
        parts.push((base.root.clone(), base.repo.source().clone()));
        let whole = Repository::chain(parts, &o.keys.attestation, None).with_context(|| {
            format!(
                "the chain from the evidence source `{name}` through {} does not verify",
                s.location
            )
        })?;
        println!(
            "chain     `{}` continues `{}`, in another repository: the whole chain is read, from \
             the evidence source `{name}`{}",
            first.log.origin(),
            held.origin,
            match (dry_run, r.synced) {
                (true, _) => ", as its clone holds it: a dry run syncs nothing",
                _ => "",
            }
        );
        return Ok(Some(whole));
    }
    Ok(None)
}

fn plan(
    base: &Base,
    what: &What,
    s: &Settings,
    (store, rt): (&Store, &tokio::runtime::Runtime),
    successor: Option<&LogVkey>,
    dry_run: bool,
) -> Result<Plan> {
    if let Some(end) = &base.ended
        && !matches!(what, What::Succeed(_))
    {
        bail!(
            "the log `{}` in {} has ended, and its successor `{}` is in another repository, {}: \
             publish there, with `[publish] repo` set to it and `origin` and `log_key` to the \
             successor's (docs/19 §8). If `trigon log succeed` stopped before beginning it, run it \
             again",
            base.log().origin(),
            s.location,
            end.origin,
            end.urls.join(", ")
        );
    }
    let mut succession = None;
    let (entries, completions) = match what {
        What::Runs(ids) => runs(base, ids, s, store, rt, dry_run)?,
        What::Withdrawal(path) => (withdrawal(base, path, s, dry_run)?, Vec::new()),
        What::Heartbeat => match heartbeat(base, s)? {
            Ok(entries) => (entries, Vec::new()),
            Err(why) => {
                return Ok(Plan {
                    idle: why,
                    ..assemble(base, Vec::new(), Vec::new(), s)?
                });
            }
        },
        What::Reconcile => return reconcile(base, s),
        // A dry run signs nothing, so it shows the key change unsigned.
        What::KeyChange { key, new_key } if dry_run => {
            return key_change_preview(base, key, new_key);
        }
        What::KeyChange { key, new_key } => (key_change_leaf(base, key, new_key)?, Vec::new()),
        What::Succeed(asked) => {
            let vkey = successor.expect("a succession's key is read before it is planned");
            let (entries, sp) = succession_leaf(base, asked, vkey, s)?;
            succession = Some(sp);
            (entries, Vec::new())
        }
    };
    let mut plan = assemble(base, entries, completions, s)?;
    if let Some(sp) = &succession {
        plan.message = format!(
            "log succeed: `{}` ends, tree {} → {}; `{}` begins at {}",
            base.log().origin(),
            base.log().size(),
            base.log().size() + plan.entries.len() as u64,
            sp.successor.origin,
            where_is(&sp.successor)
        );
        if sp.ended_already {
            plan.idle = format!(
                "`{}` ended already, naming `{}`; beginning it",
                base.log().origin(),
                sp.successor.origin
            );
        }
    }
    plan.succession = succession;
    Ok(plan)
}

/// Where a successor is, for a person: `log/1 in this repository`, or its directory and URLs.
fn where_is(s: &Successor) -> String {
    match s.in_this_repository() {
        true => format!("{} in this repository", s.dir),
        false => format!("{} in {}", s.dir, s.urls.join(", ")),
    }
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
    dry_run: bool,
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
    // What is published is asked of the whole chain, which goes on from another repository where
    // this one begins by continuing a log elsewhere: a record current there is current here. Read
    // when the first run the gate releases asks what is published, and not for a publication the
    // gate refuses whole, which needs nothing of it.
    let mut whole: Option<Option<Repository>> = None;
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
        // Under "feed", a divergence is published with its entry in `feed/divergences.atom`, in
        // the same commit: ADR-0010 safeguard 4 as docs/19 D7 proposes it.
        if !void
            && r.outcome.as_deref() == Some("divergent")
            && s.divergences == Divergences::Refuse
        {
            refused.push(refuse(
                "it is a divergence, and `[publish] divergences` is \"refuse\": a divergence is a \
                 public accusation, and ADR-0010 safeguard 4, notifying the maintainer, has no \
                 channel until docs/19 D7 decides one. `divergences = \"feed\"` publishes one with \
                 an entry in feed/divergences.atom"
                    .into(),
            ));
            continue;
        }
        // What the log already holds of this run, and of an attempt it agrees with, is asked by
        // the artifact the run is about and before its statements are read: a run published, or
        // the second of an agreeing pair, is refused whatever it was signed as.
        if whole.is_none() {
            whole = Some(whole_chain(base, s, dry_run)?);
        }
        let chain = Chain::of(base, whole.as_ref().and_then(Option::as_ref));
        let sha256 = r.upstream.sha256.to_hex();
        let found = chain
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
            match chain.here(pos) {
                Some(pos) => completions.push(Completion {
                    run: id.clone(),
                    record: logged,
                    pos,
                }),
                None => refused.push(refuse(chain.logged_elsewhere(logged, pos))),
            }
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
        // Signed by the key the log has now: after a key change, a record signed by the old key
        // is one every client refuses (`docs/19` §8).
        if !primary
            .signatures
            .iter()
            .any(|g| !g.sig.is_empty() && g.keyid == key.key_id())
        {
            let by: Vec<&str> = primary
                .signatures
                .iter()
                .filter(|g| !g.sig.is_empty())
                .map(|g| g.keyid.as_str())
                .collect();
            refused.push(refuse(format!(
                "its `{}` statement is signed by {}, and the repository's attestation key is {}{}: \
                 attest it again with that key, `trigon attest {id} --key <key>`",
                wanted[0],
                printable(&by.join(", ")),
                key.key_id(),
                since_key_change(base)
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
        if let Some((pos, _)) = chain.repo.record_leaves().find(|(_, l)| l.record == digest) {
            match chain.here(pos) {
                Some(pos) => completions.push(Completion {
                    run: id.clone(),
                    record: digest,
                    pos,
                }),
                None => refused.push(refuse(chain.logged_elsewhere(digest, pos))),
            }
            continue;
        }
        if let Some(earlier) = subjects.get(&sha256) {
            refused.push(refuse(format!(
                "it is about the same artifact, sha256:{sha256}, as run `{earlier}`, named before \
                 it. Publish one; the other can supersede it afterwards"
            )));
            continue;
        }
        if let Err(why) = supersedes_what_is_current(st, &found, chain.repo) {
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
        // An exact rebuild is the published artifact itself, byte for byte, which is not ours to
        // redistribute and which every reader already holds (`docs/19` §4.1); a void has none.
        let asset = match (s.rebuilt_artifacts, void, r.outcome.as_deref()) {
            (RebuiltArtifacts::GithubRelease, false, Some(o)) if o != "exact" => {
                match rebuilt_asset(&r, &record) {
                    Ok(a) => Some(a),
                    Err(why) => {
                        refused.push(refuse(why));
                        continue;
                    }
                }
            }
            _ => None,
        };
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
            asset,
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

/// Where the attestation key the log has now became its key, for a message: after the key change
/// that made it current, or nothing where it is the key the chain starts at.
fn since_key_change(base: &Base) -> String {
    match base.repo.keys().epochs().last().and_then(|e| e.from) {
        Some(pos) => format!(
            " since the key change at leaf {} of `{}`",
            pos.index,
            base.repo.origin(pos)
        ),
        None => String::new(),
    }
}

/// The release asset of a verdict's rebuilt artifact: the one its signed statement names, which
/// must be the run's, and within GitHub's 2 GiB.
fn rebuilt_asset(r: &RunRecord, record: &Record) -> Result<release::Asset, String> {
    let signed = record
        .evidence
        .get(evidence_key::REBUILT_ARTIFACT)
        .and_then(|v| v.strip_prefix("sha256:"))
        .and_then(|h| Digest::from_hex(h).ok())
        .ok_or_else(|| {
            "its verdict signs no rebuilt artifact, and `rebuilt_artifacts = \"github-release\"` \
             publishes the one a verdict names"
                .to_string()
        })?;
    let Some(rebuilt) = &r.rebuild else {
        return Err("the run names no rebuilt artifact to publish".into());
    };
    if rebuilt.sha256 != signed {
        return Err(format!(
            "its rebuilt artifact is sha256:{} in the store, and its verdict signs sha256:{}; \
             attest it again",
            rebuilt.sha256.to_hex(),
            signed.to_hex()
        ));
    }
    if rebuilt.bytes >= release::ASSET_LIMIT {
        return Err(format!(
            "its rebuilt artifact is {} bytes, and GitHub takes a release asset only under 2 GiB \
             ({} bytes). Set `rebuilt_artifacts = \"none\"` to publish its record without it: \
             the record's falsifying command then takes the rebuild from whoever runs it",
            rebuilt.bytes,
            release::ASSET_LIMIT
        ));
    }
    Ok(release::Asset {
        digest: signed,
        size: rebuilt.bytes,
        run: r.id.clone(),
    })
}

/// `trigon log key-change`: a key-change leaf from the attestation key current now, whose private
/// half is `key`, to `new_key`'s, signed by both over the log it is logged in (`docs/19` §8).
///
/// Signed by `trigon log key-change-leaf`, a child process that opens no socket, as `publish` has
/// `log sign` hold the log key: this process, which fetches and pushes, never opens an attestation
/// key, and holds what the child prints to everything it asked for. Refused where `key` is not the
/// current key, since only it can hand over; where the new key is the current one; and where it is
/// one the log has retired, since whoever holds a retired key is who a change away from it was
/// for.
fn key_change_leaf(base: &Base, key: &Path, new_key: &Path) -> Result<Vec<Entry>> {
    let origin = base.log().origin();
    let time = leaf_time(base);
    let exe = std::env::current_exe().context("finding this binary to sign the key change")?;
    let out = std::process::Command::new(exe)
        .args(["log", "key-change-leaf", "--key"])
        .arg(key)
        .arg("--new-key")
        .arg(new_key)
        .args(["--origin", origin, "--time", &time.to_string()])
        .stdin(std::process::Stdio::null())
        .output()
        .context("running `trigon log key-change-leaf`")?;
    if !out.status.success() {
        bail!(
            "the key change could not be signed, and nothing was written:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let leaf = match Leaf::decode(String::from_utf8_lossy(&out.stdout).trim().as_bytes())? {
        Leaf::KeyChange(k) if k.time == time => k,
        _ => bail!("`trigon log key-change-leaf` printed something other than the leaf asked for"),
    };
    leaf.verify(origin)?;
    let (old_public, new_public) = (leaf.old_key()?, leaf.new_key()?);
    may_hand_over(base, &old_public, &new_public)?;
    Ok(vec![Entry {
        run: None,
        said: format!(
            "key change: the attestation key {} hands over to {}",
            old_public.key_id(),
            new_public.key_id()
        ),
        leaf: Leaf::KeyChange(leaf),
        record: None,
        evidence: Vec::new(),
        asset: None,
    }])
}

/// Whether the attestation key `old` may hand over to `new` in this repository's log: `old` is the
/// key current now, since only it can hand over, and `new` is another, and one the log has never
/// had, since whoever holds a retired key is who a change away from it was for.
fn may_hand_over(base: &Base, old: &AttestationKey, new: &AttestationKey) -> Result<()> {
    let keys = base.repo.keys();
    let current = keys.current();
    if old == new {
        bail!(
            "--key and --new-key are one key, {}: a key change hands over to another",
            old.key_id()
        );
    }
    if old != current {
        bail!(
            "--key is the key {}, and the repository's attestation key is {}{}: a key change is \
             signed by the key current now, and by the new one",
            old.key_id(),
            current.key_id(),
            since_key_change(base)
        );
    }
    if keys.epochs().iter().any(|e| e.key == *new) {
        bail!(
            "{} was this repository's attestation key before, and a key the log has retired is \
             never current again: whoever might hold it is who the change away from it was for. \
             Make a new one with `trigon keygen`",
            new.key_id()
        );
    }
    Ok(())
}

/// `trigon log key-change --dry-run`: the key change as it would be logged, but unsigned, and what
/// it would write. Nothing is signed. The two keys' public halves are read by `trigon public-key`,
/// a child that signs nothing, and held to what the real run holds them to; the leaf is shown with
/// its signatures empty, since a signed one printed by a preview, into a CI log say, would be a
/// hand-over anyone holding the log key could append. The leaf's bundle, the tiles and the
/// checkpoint's root cover both signatures, so they are shown by path, and the checkpoint by size.
fn key_change_preview(base: &Base, key: &Path, new_key: &Path) -> Result<Plan> {
    let old = attestation_key_of(key, "--key")?;
    let new = attestation_key_of(new_key, "--new-key")?;
    may_hand_over(base, &old, &new)?;
    let time = leaf_time(base);
    let side = |k: &AttestationKey| KeyChangeKey {
        key_id: k.key_id(),
        public_key: k.to_hex(),
        signature: String::new(),
    };
    let leaf = Leaf::KeyChange(KeyChangeLeaf {
        time,
        old: side(&old),
        new: side(&new),
    });
    // Which files an append of one leaf writes and removes depends on the tree's size alone: asked
    // of a heartbeat at the same time, whose bytes are not shown.
    let stand_in = base
        .log()
        .plan_append(&[Leaf::Heartbeat(HeartbeatLeaf { time })])?;
    let mut writes = BTreeMap::new();
    if let Some(readme) = readme_after(base, std::slice::from_ref(&leaf))?
        && differs(&base.root, "README.md", &readme)
    {
        writes.insert("README.md".to_string(), readme);
    }
    Ok(Plan {
        entries: vec![Entry {
            run: None,
            said: format!(
                "key change: the attestation key {} hands over to {}",
                old.key_id(),
                new.key_id()
            ),
            leaf,
            record: None,
            evidence: Vec::new(),
            asset: None,
        }],
        completions: Vec::new(),
        writes,
        removes: stand_in
            .obsolete
            .iter()
            .map(|p| format!("{}/{p}", base.dir))
            .collect(),
        checkpoint: None,
        unsigned: stand_in
            .files
            .iter()
            .map(|(p, _)| format!("{}/{p}", base.dir))
            .collect(),
        message: format!(
            "publish: key change, tree {} → {}",
            base.log().size(),
            stand_in.size
        ),
        idle: String::new(),
        time,
        succession: None,
    })
}

/// The public half of the attestation key in the file `key`, from `trigon public-key`, a child
/// process of this binary that reads it and signs nothing: the process that pushes opens no
/// attestation key. `flag` names the file for a person.
fn attestation_key_of(key: &Path, flag: &str) -> Result<AttestationKey> {
    let exe = std::env::current_exe().context("finding this binary to run `trigon public-key`")?;
    let out = std::process::Command::new(exe)
        .arg("public-key")
        .arg(key)
        .stdin(std::process::Stdio::null())
        .output()
        .context("running `trigon public-key`")?;
    if !out.status.success() {
        bail!(
            "the key {flag} names could not be read:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    AttestationKey::from_hex(String::from_utf8_lossy(&out.stdout).trim())
        .context("reading what `trigon public-key` printed")
}

/// `trigon log succeed`: the log-end naming the successor asked for, and the plan that begins it
/// (`docs/19` §8). `vkey` is the successor's log key, whose name must be its origin.
///
/// Where the chain's last log ended already, naming a successor in another repository that was
/// never begun, the same successor asked for again is begun, with no leaf appended; any other is
/// refused, since a log ends once.
fn succession_leaf(
    base: &Base,
    asked: &Succession,
    vkey: &LogVkey,
    s: &Settings,
) -> Result<(Vec<Entry>, SuccessionPlan)> {
    check_origin(&asked.origin).map_err(anyhow::Error::msg)?;
    if vkey.origin() != asked.origin {
        bail!(
            "the log key {} is for the log `{}`, and --origin is `{}`: a log key's name is its \
             log's origin. Make one for the successor with `trigon log keygen --origin {} --out \
             <file>`",
            asked.log_key.display(),
            printable(vkey.origin()),
            asked.origin,
            asked.origin
        );
    }
    if let Some(c) = base
        .repo
        .source()
        .logs
        .iter()
        .find(|c| c.log.origin() == asked.origin)
    {
        bail!(
            "`{}` is a log of this repository's chain already, at `{}`; a successor is a new log, \
             with an origin and a key of its own",
            asked.origin,
            c.dir
        );
    }
    for u in &asked.urls {
        let l = Location::parse(u, &s.env.cwd, s.env.home.as_deref())?;
        if matches!(l.transport(), Transport::LocalPath | Transport::File) {
            bail!(
                "--url `{u}` is a path on this machine, and a log-end names only locations anyone \
                 can clone the successor from"
            );
        }
    }
    let here = asked.urls.is_empty();
    let dir = match (&asked.dir, here) {
        (Some(d), _) => d.clone(),
        (None, true) => next_dir(&base.root)?,
        (None, false) => "log".to_string(),
    };
    let numbered = dir.strip_prefix("log/").is_some_and(|n| {
        !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit())
    });
    if !(numbered || (dir == "log" && !here)) {
        bail!(
            "--dir `{}` is not where a successor can be: `log/<n>` in this repository, and `log` \
             or `log/<n>` in another (docs/19 §2.3)",
            printable(&dir)
        );
    }
    let successor = Successor {
        origin: asked.origin.clone(),
        log_key: vkey.to_string(),
        urls: asked.urls.clone(),
        dir,
    };
    let newest = NewestPublished::of(&s.env, &asked.origin)?;
    if let Some(end) = &base.ended {
        let same = end.origin == successor.origin
            && end.log_key == successor.log_key
            && end.urls == successor.urls
            && asked.dir.as_ref().is_none_or(|d| *d == end.dir);
        if !same {
            bail!(
                "`{}` ended already, naming the successor `{}` at {}; a log ends once",
                base.log().origin(),
                printable(&end.origin),
                where_is(end)
            );
        }
        let end_time = base.log().log_end().map_or(0, |e| e.time);
        return Ok((
            Vec::new(),
            SuccessionPlan {
                successor: end.clone(),
                vkey: vkey.clone(),
                log_key: asked.log_key.clone(),
                end_time,
                ended_already: true,
                newest,
            },
        ));
    }
    if here && std::fs::symlink_metadata(base.root.join(&successor.dir)).is_ok() {
        bail!(
            "`{}` is in {} already, and a successor is begun in a directory of its own: name \
             another with --dir",
            successor.dir,
            s.location
        );
    }
    if let Some(p) = newest.open(vkey)?.filter(|p| p.size() > 0) {
        bail!(
            "this host has published `{}` at {} leaves ({}): it is begun already, and a log is \
             begun once. A successor takes an origin and a key of its own",
            p.origin(),
            p.size(),
            newest.path().display()
        );
    }
    if !here {
        successor_can_be_begun(&successor, s)?;
    }
    let end_time = leaf_time(base);
    let entry = Entry {
        run: None,
        said: format!(
            "log-end: `{}` is succeeded by `{}`, at {}",
            base.log().origin(),
            successor.origin,
            where_is(&successor)
        ),
        leaf: Leaf::LogEnd(LogEndLeaf {
            time: end_time,
            successor: successor.clone(),
        }),
        record: None,
        evidence: Vec::new(),
        asset: None,
    };
    Ok((
        vec![entry],
        SuccessionPlan {
            successor,
            vkey: vkey.clone(),
            log_key: asked.log_key.clone(),
            end_time,
            ended_already: false,
            newest,
        },
    ))
}

/// The next free `log/<n>` in the tree at `root`: one past the highest number any directory under
/// `log/` has, a planted one included, so that a successor is never begun over one.
fn next_dir(root: &Path) -> Result<String> {
    let mut n = 0u64;
    for e in dirs_under(root, "log")? {
        if let Some(k) = e.strip_prefix("log/").and_then(|k| k.parse::<u64>().ok()) {
            n = n.max(k);
        }
    }
    Ok(format!("log/{}", n + 1))
}

/// The directories directly under `dir` in the tree at `root`, as `dir/<name>`.
fn dirs_under(root: &Path, dir: &str) -> Result<Vec<String>> {
    inside(root, &format!("{dir}/-"))?;
    let entries = match std::fs::read_dir(root.join(dir)) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {dir}")),
    };
    let mut out = Vec::new();
    for e in entries {
        let e = e?;
        if e.file_type()?.is_dir() {
            out.push(format!("{dir}/{}", e.file_name().to_string_lossy()));
        }
    }
    Ok(out)
}

/// A log key's verifier key, from `trigon log public-key`, a child process of this binary: the
/// process that pushes never opens a log key.
fn public_key_of(key: &Path) -> Result<LogVkey> {
    let exe =
        std::env::current_exe().context("finding this binary to run `trigon log public-key`")?;
    let out = std::process::Command::new(exe)
        .args(["log", "public-key"])
        .arg(key)
        .stdin(std::process::Stdio::null())
        .output()
        .context("running `trigon log public-key`")?;
    if !out.status.success() {
        bail!(
            "the successor's log key could not be read:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    LogVkey::parse(text.trim()).context("reading what `trigon log public-key` printed")
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
    chain: &Repository,
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
            "its artifact has a current record, sha256:{} at leaf {} of `{}`; {how}",
            one.leaf.record.to_hex(),
            one.pos.index,
            chain.origin(one.pos)
        )),
        (Some(d), Some(one)) if one.leaf.record == d => Ok(()),
        (Some(d), current) => {
            let logged = chain.record_leaves().any(|(_, l)| l.record == d);
            Err(match (logged, current) {
                (false, _) => format!(
                    "it supersedes sha256:{}, which this repository's chain of logs does not \
                     hold, so no client would ever apply it",
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
fn withdrawal(base: &Base, path: &Path, s: &Settings, dry_run: bool) -> Result<Vec<Entry>> {
    let whole = whole_chain(base, s, dry_run)?;
    let chain = Chain::of(base, whole.as_ref());
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
    let Some((pos, target)) = chain.repo.record_leaves().find(|(_, l)| l.record == of) else {
        bail!(
            "the withdrawal is of sha256:{}, which this repository's chain of logs does not hold; \
             a withdrawal is published only of a logged record",
            of.to_hex()
        );
    };
    let record = Record::assemble(vec![env])?;
    let bytes = record.encode()?;
    let digest = Record::digest_of(&bytes);
    if let Some((at, _)) = chain.repo.record_leaves().find(|(_, l)| l.record == digest) {
        bail!(
            "this withdrawal is already logged, at leaf {} of `{}`: nothing to publish",
            at.index,
            chain.repo.origin(at)
        );
    }
    let key = Key::Digest {
        algorithm: "sha256",
        hex: target.subject.get("sha256").cloned().unwrap_or_default(),
    };
    let found = chain.repo.lookup(&key).found;
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
            "the withdrawal is about {} ({}), and the record it withdraws, at leaf {} of `{}`, is \
             about {} ({}); a client applies a withdrawal only to a record of the same artifact",
            leaf.subject.get("sha256").map_or("nothing", String::as_str),
            printable(&leaf.purl),
            pos.index,
            chain.repo.origin(pos),
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
        asset: None,
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
        asset: None,
    }]))
}

/// `--reconcile`: `index/` rebuilt from the log whole — every file the log implies written as it
/// implies it, and every other file under `index/` removed — and the divergence feed with it,
/// where the log holds a divergence, the feed is on, or a feed is there to be put right.
fn reconcile(base: &Base, s: &Settings) -> Result<Plan> {
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
    let feed_there = !files_under(&base.root, "feed")?.is_empty();
    let divergent = base
        .repo
        .record_leaves()
        .any(|(_, l)| l.outcome == Some(LeafOutcome::Divergent));
    let feed = feed_there || divergent || s.divergences == Divergences::Feed;
    if feed {
        let bytes = feed_after(base, &[], &BTreeMap::new(), s)?;
        if differs(&base.root, feed::PATH, &bytes) {
            writes.insert(feed::PATH.to_string(), bytes);
        }
        // Whatever else is under `feed/` is not the log's: whoever can push put it there.
        for path in files_under(&base.root, "feed")? {
            if path != feed::PATH {
                removes.push(path);
            }
        }
    }
    Ok(Plan {
        entries: Vec::new(),
        completions: Vec::new(),
        message: format!(
            "publish: reconcile index/{}, tree {}",
            if feed { " and the feed" } else { "" },
            base.log().checkpoint().size()
        ),
        writes,
        removes,
        checkpoint: None,
        idle: format!(
            "index/ is already what the log implies{}; nothing is committed",
            if feed { ", and so is the feed" } else { "" }
        ),
        time: leaf_time(base),
        succession: None,
        unsigned: Vec::new(),
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
/// files of every key of every new record, the feed where a divergence is among them or is
/// superseded by one, the README's account of rotations where a key change or a log-end is, and
/// the commit message.
fn assemble(
    base: &Base,
    entries: Vec<Entry>,
    completions: Vec<Completion>,
    s: &Settings,
) -> Result<Plan> {
    let old = base.log().size();
    let time = leaf_time(base);
    if entries.is_empty() {
        return Ok(Plan {
            entries,
            completions,
            writes: BTreeMap::new(),
            removes: Vec::new(),
            checkpoint: None,
            message: String::new(),
            idle: "nothing to publish".into(),
            time,
            succession: None,
            unsigned: Vec::new(),
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
    // The feed, in the same commit as a divergence, or as what supersedes one: derived from the
    // log whole, with this publication's records read from what it is about to write.
    if touches_feed(base, &leaves) {
        let feed = feed_after(base, &entries, &writes, s)?;
        put(&mut writes, feed::PATH.to_string(), feed);
    }
    if leaves
        .iter()
        .any(|l| matches!(l, Leaf::KeyChange(_) | Leaf::LogEnd(_)))
        && let Some(readme) = readme_after(base, &leaves)?
    {
        put(&mut writes, "README.md".to_string(), readme);
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
    let what = match (records, leaves.first()) {
        (0, Some(Leaf::KeyChange(_))) => "key change".to_string(),
        (0, Some(Leaf::LogEnd(_))) => "log-end".to_string(),
        (0, _) => "heartbeat".to_string(),
        (1, _) => "1 record".to_string(),
        (n, _) => format!("{n} records"),
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
        time,
        succession: None,
        unsigned: Vec::new(),
    })
}

/// Whether a publication of `new` leaves changes the feed: one is a divergence, or supersedes a
/// record logged as one.
fn touches_feed(base: &Base, new: &[Leaf]) -> bool {
    let divergent = |d: &Digest| {
        base.repo
            .record_leaves()
            .map(|(_, l)| l)
            .chain(new.iter().filter_map(|l| match l {
                Leaf::Record(r) => Some(r),
                _ => None,
            }))
            .any(|l| l.record == *d && l.outcome == Some(LeafOutcome::Divergent))
    };
    new.iter().any(|l| match l {
        Leaf::Record(r) => {
            r.outcome == Some(LeafOutcome::Divergent)
                || r.supersedes.as_ref().is_some_and(divergent)
        }
        _ => false,
    })
}

/// The divergence feed as the chain of logs implies it once `entries` are logged after its last
/// leaf ([`feed`]): every divergence of it, the most recent kept, each read with the client's own
/// `check_record` — a record this publication writes read from `staged` — and each marked with the
/// record that supersedes it, where one does.
fn feed_after(
    base: &Base,
    entries: &[Entry],
    staged: &BTreeMap<String, Vec<u8>>,
    s: &Settings,
) -> Result<Vec<u8>> {
    // Every record leaf of the chain, then this publication's, with where each is.
    let mut all: Vec<(LeafPos, RecordLeaf, String)> = base
        .repo
        .record_leaves()
        .map(|(pos, l)| (pos, l.clone(), base.repo.origin(pos).to_string()))
        .collect();
    for (i, e) in entries.iter().enumerate() {
        if let Leaf::Record(r) = &e.leaf {
            all.push((
                base.pos(i as u64),
                r.clone(),
                base.log().origin().to_string(),
            ));
        }
    }
    let mut superseding: BTreeMap<Digest, feed::Superseding> = BTreeMap::new();
    for (pos, l, origin) in &all {
        if let (Some(d), Some(reason)) = (l.supersedes, l.reason) {
            superseding.entry(d).or_insert(feed::Superseding {
                record: l.record,
                index: pos.index,
                origin: origin.clone(),
                reason,
                time: l.time,
            });
        }
    }
    let under = DirFiles::new(&base.root);
    let files = Staged::new(staged, &under);
    let divergent: Vec<&(LeafPos, RecordLeaf, String)> = all
        .iter()
        .filter(|(_, l, _)| l.outcome == Some(LeafOutcome::Divergent))
        .collect();
    let skip = divergent.len().saturating_sub(feed::ENTRIES);
    let mut items = Vec::new();
    for (pos, leaf, origin) in divergent.into_iter().skip(skip) {
        let read = match files.read(&record_path(&leaf.record), RECORD_LIMIT) {
            Ok(None) => feed::Read::Missing,
            Err(e) => feed::Read::Failed(e.to_string()),
            Ok(Some(bytes)) => {
                match check_record(
                    &bytes,
                    Some((*pos, leaf)),
                    origin,
                    base.repo.keys(),
                    &files,
                    None,
                ) {
                    Ok(v) => {
                        let p = &v.statement.predicate;
                        feed::Read::Verified {
                            dispute: p
                                .get("disputePointer")
                                .and_then(|d| {
                                    serde_json::from_value::<DisputePointer>(d.clone()).ok()
                                })
                                .map(|DisputePointer::Url { url }| url),
                            command: p
                                .get("falsifyingCommand")
                                .and_then(|c| {
                                    serde_json::from_value::<FalsifyingCommand>(c.clone()).ok()
                                })
                                .map(|c| c.render()),
                        }
                    }
                    Err(e) => feed::Read::Failed(format!("{e} ({})", e.kind())),
                }
            }
        };
        items.push(feed::Item {
            leaf: leaf.clone(),
            index: pos.index,
            origin: origin.clone(),
            read,
            superseded: superseding.get(&leaf.record).cloned(),
        });
    }
    let quiet = base
        .repo
        .newest_time()
        .into_iter()
        .chain(entries.iter().map(|e| e.leaf.time()))
        .max()
        .unwrap_or(0);
    Ok(feed::render(
        &items,
        &feed::Meta {
            first_origin: base.repo.source().logs[0].log.origin().to_string(),
            origin: base.log().origin().to_string(),
            base: release::on_github(&s.location)
                .map(|r| format!("https://github.com/{r}/blob/{}/feed/", s.branch)),
            quiet,
        },
    ))
}

/// The README with its account of key changes and successors regenerated from the chain of logs,
/// `new` leaves included, in place of the account it had or after everything it says; the rest
/// of it as it is. `None` where the log holds no rotation.
fn readme_after(base: &Base, new: &[Leaf]) -> Result<Option<Vec<u8>>> {
    let logs = &base.repo.source().logs;
    let mut lines = Vec::new();
    for (n, c) in logs.iter().enumerate() {
        let more = if n + 1 == logs.len() { new } else { &[] };
        let size = c.log.size();
        let leaves = c
            .log
            .leaves()
            .chain(more.iter().enumerate().map(|(i, l)| (size + i as u64, l)));
        for (index, leaf) in leaves {
            match leaf {
                Leaf::KeyChange(k) => lines.push(format!(
                    "- Leaf {index} of `{}` changed the attestation key from `{}` (key id `{}`) \
                     to `{}` (key id `{}`), signed by both. A record logged after it is signed by \
                     the new key, and one signed by the old key is refused.",
                    c.log.origin(),
                    k.old.public_key,
                    k.old.key_id,
                    k.new.public_key,
                    k.new.key_id
                )),
                Leaf::LogContinuation(cont) => {
                    let held = cont.old_checkpoint()?;
                    lines.push(continuation_line(c.log.origin(), &held.origin, held.size));
                }
                Leaf::LogEnd(e) => lines.push(format!(
                    "- Leaf {index} ended `{}`. Its successor is `{}`, whose log key is `{}`, at \
                     {}; its first leaf holds this log's final checkpoint, signed by both log \
                     keys.",
                    c.log.origin(),
                    e.successor.origin,
                    e.successor.log_key,
                    where_is(&e.successor)
                )),
                _ => {}
            }
        }
    }
    if lines.is_empty() {
        return Ok(None);
    }
    let old = DirFiles::new(&base.root)
        .read("README.md", README_LIMIT)?
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let kept = match old.find(&format!("\n{ROTATIONS}\n")) {
        Some(at) => &old[..at],
        None => old.as_str(),
    };
    let lines: Vec<String> = lines.iter().map(|l| wrapped(l, "  ")).collect();
    let text = format!(
        "{}\n\n{ROTATIONS}\n\n{}\n\n{}\n",
        kept.trim_end(),
        wrapped(ROTATIONS_INTRO, ""),
        lines.join("\n")
    );
    Ok(Some(text.trim_start().as_bytes().to_vec()))
}

/// `text` folded at the README's width, every line after the first indented by `indent`: a word
/// longer than the width, a key, is kept whole on a line of its own.
fn wrapped(text: &str, indent: &str) -> String {
    const WIDTH: usize = 88;
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > WIDTH {
            out.push_str(&line);
            out.push('\n');
            line = indent.to_string();
        } else if !line.is_empty() && line != indent {
            line.push(' ');
        }
        line.push_str(word);
    }
    out.push_str(&line);
    out
}

/// What the README's account of rotations says before it lists them.
const ROTATIONS_INTRO: &str = "From the log, which is the authority: a client follows each of \
    these itself, from the keys it pinned, and the copies in `keys/` stay the keys the chain \
    starts at.";

/// The README's line for a log that continues another.
fn continuation_line(origin: &str, of: &str, size: u64) -> String {
    wrapped(
        &format!(
            "- `{origin}` continues `{of}`: its first leaf holds that log's final checkpoint, \
             of {size} leaves, signed by both log keys."
        ),
        "  ",
    )
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
    write_files(
        root,
        &plan.removes,
        plan.writes.iter().map(|(p, b)| (p.as_str(), b.as_slice())),
    )
}

/// Remove `removes` and write `writes` in the tree at `root`, each inside it.
fn write_files<'a>(
    root: &Path,
    removes: &[String],
    writes: impl Iterator<Item = (&'a str, &'a [u8])>,
) -> Result<()> {
    for path in removes {
        let full = inside(root, path)?;
        match std::fs::symlink_metadata(&full) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(&full)?,
            Ok(_) => std::fs::remove_file(&full)?,
            Err(_) => {}
        }
    }
    for (path, bytes) in writes {
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
/// disk, for the commit to hold exactly those bytes. Where the publication ends the log, `log sign`
/// holds the successor's key too, and the final checkpoint it writes is cosigned by it.
fn sign(
    base: &Base,
    planned: &Checkpoint,
    s: &Settings,
    succession: Option<&SuccessionPlan>,
) -> Result<Vec<u8>> {
    let key = s
        .log_key
        .as_ref()
        .expect("checked when the settings were read");
    let size = planned.size.to_string();
    let mut args: Vec<std::ffi::OsString> = ["log", "sign", "--tree"].map(Into::into).to_vec();
    args.push(base.root.clone().into());
    args.extend(["--log", &base.dir, "--size", &size, "--key"].map(Into::into));
    args.push(key.into());
    if let Some(sp) = succession {
        args.push("--successor-key".into());
        args.push(sp.log_key.clone().into());
    }
    log_sign(&args, "sign the new checkpoint")?;
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

/// Run `trigon log sign` with `args` as a child process of this binary, to `what`.
fn log_sign(args: &[std::ffi::OsString], what: &str) -> Result<()> {
    let exe = std::env::current_exe().context("finding this binary to run `trigon log sign`")?;
    let out = std::process::Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .context("running `trigon log sign`")?;
    if !out.status.success() {
        bail!(
            "`trigon log sign` refused to {what}, and nothing is committed:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The first tree of a successor, at `dir` in the tree at `root`: its log-continuation, holding
/// `end` — the final checkpoint `log sign` signed with both keys — logged when the log-end was, and
/// the tiles and bundle of a tree of one; then its first checkpoint, signed by `trigon log sign
/// --continuing` under the successor's key, which holds the pair to what every client follows.
/// `from` is the tree whose chain holds the log it continues. Returns every file written, by path.
fn begin_successor(
    root: &Path,
    from: &Path,
    sp: &SuccessionPlan,
    end: &[u8],
) -> Result<Vec<(String, Vec<u8>)>> {
    SignedNote::parse(end)?.verify(&sp.vkey).context(
        "the final checkpoint `trigon log sign` wrote carries no signature by the successor's key",
    )?;
    let note = String::from_utf8(end.to_vec()).context("the final checkpoint is not text")?;
    let leaf = Leaf::LogContinuation(LogContinuationLeaf {
        time: sp.end_time,
        checkpoint: note,
    });
    let append = plan_append(&Tree::new(), &[] as &[Vec<u8>], &[leaf.encode()?])?;
    let dir = &sp.successor.dir;
    let mut files: Vec<(String, Vec<u8>)> = append
        .files
        .into_iter()
        .map(|(path, bytes)| (format!("{dir}/{path}"), bytes))
        .collect();
    write_files(
        root,
        &[],
        files.iter().map(|(p, b)| (p.as_str(), b.as_slice())),
    )?;
    let args: Vec<std::ffi::OsString> = vec![
        "log".into(),
        "sign".into(),
        "--tree".into(),
        root.into(),
        "--log".into(),
        dir.into(),
        "--size".into(),
        "1".into(),
        "--key".into(),
        sp.log_key.clone().into(),
        "--continuing".into(),
        from.into(),
    ];
    log_sign(&args, &format!("begin `{}`", sp.successor.origin))?;
    let bytes = DirFiles::in_repository(root, dir)
        .read("checkpoint", 64 * 1024)?
        .context("`trigon log sign --continuing` succeeded and wrote no checkpoint")?;
    let signed = SignedCheckpoint::open(&bytes, &sp.vkey)?;
    let planned = Checkpoint {
        origin: sp.successor.origin.clone(),
        size: 1,
        root: append.root,
    };
    if *signed.checkpoint() != planned {
        bail!(
            "`trigon log sign --continuing` signed another tree than the successor's first; \
             nothing is committed"
        );
    }
    files.push((format!("{dir}/checkpoint"), bytes));
    Ok(files)
}

/// A successor in this repository, begun in the commit that ends the log.
fn begin_here(base: &Base, sp: &SuccessionPlan, end: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    begin_successor(&base.root, &base.root, sp, end)
}

/// A successor in another repository, at the first of its URLs, begun once the log's end is
/// pushed: its first commit, as `trigon log init`'s is a log's — `keys/`, a README, and the tree of
/// its log-continuation, signed by `log sign --continuing` from the old repository's tree. Refused
/// where the repository has a log already, unless it is this successor's, begun before.
fn begin_elsewhere(base: &Base, sp: &SuccessionPlan, s: &Settings, end: &[u8]) -> Result<()> {
    let written = &sp.successor.urls[0];
    let location = Location::parse(written, &s.env.cwd, s.env.home.as_deref())?;
    let branch = &s.branch;
    let (clone, head) = successor_clone(&location, branch, &sp.successor.origin)?;
    let scratch = clone.0.clone();
    let dir = &sp.successor.dir;
    // Begun already, by an attempt that pushed and stopped before it was told: said, not redone.
    if let Ok(Some(there)) = DirFiles::new(&scratch).read("keys/log.vkey", KEY_FILE_LIMIT)
        && String::from_utf8_lossy(&there).trim() == sp.vkey.to_string()
        && let Ok(Some(bytes)) =
            DirFiles::in_repository(&scratch, dir).read("checkpoint", 64 * 1024)
    {
        let signed = SignedCheckpoint::open(&bytes, &sp.vkey)?;
        sp.newest.advance(&signed, &sp.vkey)?;
        println!(
            "begun     `{}` is begun already in {location}, at {} leaves",
            sp.successor.origin,
            signed.size()
        );
        return Ok(());
    }
    // Looked at before the log-end was written ([`successor_can_be_begun`]); written to since.
    if let Some(there) = log_there(&scratch, dir) {
        bail!(
            "{location} has {there} on `{branch}` already, so it holds a log, or the start of one, \
             and `{}` is begun only in a repository of its own. `{}` has ended naming it there, \
             which was looked at before the log-end was written: find out who has written to it \
             since, remove what they wrote, and run `trigon log succeed` again to begin it",
            sp.successor.origin,
            base.log().origin()
        );
    }
    if let Some(why) = git::attributes(&scratch, head.as_deref())? {
        bail!(
            "{location} cannot have `{}` begun in it: {why}",
            sp.successor.origin
        );
    }
    let attestation = base.repo.keys().current().to_pem();
    let vkey_text = format!("{}\n", sp.vkey);
    let readme = init::readme(
        &sp.successor.origin,
        &sp.vkey,
        base.repo.keys().current(),
        s.heartbeat,
        s.disputes
            .as_deref()
            .unwrap_or("(no dispute channel is configured)"),
    ) + &format!(
        "\n{ROTATIONS}\n\n{}\n\n{}\n",
        wrapped(ROTATIONS_INTRO, ""),
        continuation_line(
            &sp.successor.origin,
            base.log().origin(),
            sp_end_index(base, sp) + 1
        )
    );
    let mut writes: Vec<(String, Vec<u8>)> = vec![
        ("keys/log.vkey".into(), vkey_text.into_bytes()),
        ("keys/attestation.pub".into(), attestation.into_bytes()),
        ("README.md".into(), readme.into_bytes()),
    ];
    // Safeguard 5 is cleared by a person, never by a succession: a switch set where the log ended
    // is set where it goes on, from the successor's first commit.
    if base.kill_switch {
        writes.push(("kill-switch".into(), carried_switch(base)));
    }
    write_files(
        &scratch,
        &[],
        writes.iter().map(|(p, b)| (p.as_str(), b.as_slice())),
    )?;
    writes.extend(begin_successor(&scratch, &base.root, sp, end)?);
    let change = git::Change {
        writes: writes
            .iter()
            .map(|(p, b)| (p.as_str(), b.as_slice()))
            .collect(),
        removes: Vec::new(),
    };
    let message = format!(
        "log succeed: `{}` begins, continuing `{}`, tree 1",
        sp.successor.origin,
        base.log().origin()
    );
    let commit = git::commit(&scratch, head.as_deref(), &change, &message)?;
    let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
    git::run_network(
        Some(&scratch),
        &["push", "--quiet", "--no-signed", "origin", &refspec],
    )
    .map_err(|e| {
        anyhow!(
            "{e}\n`{}` was not begun in {location}: the push was refused, never forced. `{}` has \
             ended, naming it; run `trigon log succeed` again once the repository is as it should \
             be",
            sp.successor.origin,
            base.log().origin()
        )
    })?;
    let bytes = DirFiles::in_repository(&scratch, dir)
        .read("checkpoint", 64 * 1024)?
        .context("the successor's first tree has no checkpoint")?;
    let signed = SignedCheckpoint::open(&bytes, &sp.vkey)?;
    sp.newest.advance(&signed, &sp.vkey)?;
    println!(
        "begun     `{}` at {dir} in {location}, commit {}",
        sp.successor.origin,
        style::ident(&commit)
    );
    if base.kill_switch {
        println!(
            "kill-switch set in {}, and so set in {location} too, in the successor's first \
             commit: no divergence is published there until a person removes it",
            s.location
        );
    }
    Ok(())
}

/// The kill-switch a successor elsewhere begins with, where the repository its predecessor ended in
/// has one set: that file's words where it is a plain file of a readable size, and otherwise a line
/// saying where it was set.
fn carried_switch(base: &Base) -> Vec<u8> {
    let path = base.root.join("kill-switch");
    let words = match std::fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() && m.len() <= KEY_FILE_LIMIT => std::fs::read(&path).ok(),
        _ => None,
    };
    words.unwrap_or_else(|| {
        format!(
            "Set in the repository of `{}` when that log ended, and carried over by `trigon log \
             succeed`.\n",
            base.log().origin()
        )
        .into_bytes()
    })
}

/// A clone, in the temporary directory, of the repository at `location` that the successor
/// `origin` is begun in, on `branch`: checked out where the repository has the branch, an orphan
/// of that name where it has none, and refused where the branch names git attributes, before any
/// checkout could apply them. The clone, removed when dropped, and the commit it is at.
fn successor_clone(
    location: &Location,
    branch: &str,
    origin: &str,
) -> Result<(Scratch, Option<String>)> {
    let scratch = std::env::temp_dir().join(format!(
        "trigon-log-succeed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let guard = Scratch(scratch.clone());
    git::clone(location, &scratch)?;
    let tracking = format!("refs/remotes/origin/{branch}");
    let head = if git::succeeds(
        Some(&scratch),
        &["rev-parse", "--verify", "--quiet", &tracking],
    ) {
        if let Some(why) = git::attributes(&scratch, Some(&tracking))? {
            bail!("{location} cannot have `{origin}` begun in it: {why}");
        }
        git::run(
            Some(&scratch),
            &["checkout", "--quiet", "--force", "-B", branch, &tracking],
        )?;
        Some(git::text(Some(&scratch), &["rev-parse", "HEAD"])?)
    } else {
        git::run(Some(&scratch), &["switch", "--quiet", "--orphan", branch])?;
        None
    };
    Ok((guard, head))
}

/// What of a log, or the start of one, the tree at `root` holds, where a successor at `dir` would
/// be begun: `keys/`, `log/`, or `dir` itself.
fn log_there(root: &Path, dir: &str) -> Option<String> {
    ["keys", "log", dir]
        .into_iter()
        .find(|p| std::fs::symlink_metadata(root.join(p)).is_ok())
        .map(|p| format!("{p}/"))
}

/// Before a log-end naming a successor in another repository is written: whether the successor can
/// be begun where its first URL says. A log-end is for good, so one naming a place no successor
/// could be begun would leave the log ended with nowhere to go, and no `log succeed` could put it
/// right. Refused where the URL names this repository, where it cannot be cloned, where its branch
/// holds a log or the start of one, or names git attributes, and where git would not take a push
/// there, which `push --dry-run` asks, sending nothing. Nothing is written.
fn successor_can_be_begun(successor: &Successor, s: &Settings) -> Result<()> {
    let url = &successor.urls[0];
    let location = Location::parse(url, &s.env.cwd, s.env.home.as_deref())?;
    let origin = &successor.origin;
    let same_on_github = release::on_github(&location)
        .zip(release::on_github(&s.location))
        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(&b));
    if location.as_git_arg() == s.location.as_git_arg() || same_on_github {
        bail!(
            "--url `{}` is the evidence repository itself: a successor in this repository is \
             begun at `log/<n>`, in the commit that ends the log, by leaving --url out. Nothing \
             was written",
            printable(url)
        );
    }
    let not_here = |e: anyhow::Error| {
        anyhow!(
            "{e:#}\n`{origin}` could not be begun at {location}, so the log has not been ended, and \
             nothing was written. A log-end is for good: it names only a place its successor can \
             be begun"
        )
    };
    let (clone, head) = successor_clone(&location, &s.branch, origin).map_err(not_here)?;
    if let Some(there) = log_there(&clone.0, &successor.dir) {
        bail!(
            "{location} has {there} on `{}` already, so it holds a log, or the start of one, and \
             `{origin}` is begun only in a repository of its own. Nothing was written: name an \
             empty repository with --url",
            s.branch
        );
    }
    git::would_take_a_push(&clone.0, &s.branch, head.as_deref()).map_err(not_here)
}

/// The index of the log-end leaf a succession wrote or found: the old log's last.
fn sp_end_index(base: &Base, sp: &SuccessionPlan) -> u64 {
    match sp.ended_already {
        true => base.log().size().saturating_sub(1),
        false => base.log().size(),
    }
}

/// Step 7, and what a person is told: `RunRecord.published` for every run logged, those a crash
/// left without it included, and the checkpoint this host has now published — a successor begun
/// in the same commit's too. With `prune`, only then is each of those runs' rebuilt artifact
/// dropped from the store.
fn complete(
    base: &Base,
    plan: &Plan,
    s: &Settings,
    (store, newest): (&Store, &NewestPublished),
    rt: &tokio::runtime::Runtime,
    commit: Option<&str>,
    prune: bool,
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
        // The log of the chain that holds the leaf, which after a succession is not the one
        // appended to now: its directory, its key and its history are what the leaf is found in.
        let held = &base.repo.source().logs[c.pos.log];
        let commit = logged_in(&base.root, &held.dir, held.log.vkey(), c.pos.index)?;
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
                log: (held.dir != "log").then(|| held.dir.clone()),
            },
        ))?;
        println!(
            "completed run {}: its record sha256:{} was logged at leaf {} of `{}` in commit {} and \
             the run did not say so; it does now",
            c.run,
            c.record.to_hex(),
            c.pos.index,
            held.log.origin(),
            commit
        );
    }
    let published: Vec<&str> = plan
        .entries
        .iter()
        .filter_map(|e| e.run.as_deref())
        .chain(plan.completions.iter().map(|c| c.run.as_str()))
        .collect();
    let Some(commit) = commit else {
        if plan.completions.is_empty() && plan.entries.is_empty() {
            println!("{}", plan.idle);
        }
        return prune_published(store, rt, &published, prune);
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
    // A successor begun in the same commit is published with it, and every later tree of it is
    // held to that as the log it ended is.
    if let Some(sp) = plan.succession.as_ref().filter(|sp| sp.here()) {
        let bytes = DirFiles::in_repository(&base.root, &sp.successor.dir)
            .read("checkpoint", 64 * 1024)?
            .context("the published successor has no checkpoint")?;
        let begun = SignedCheckpoint::open(&bytes, &sp.vkey)?;
        sp.newest.advance(&begun, &sp.vkey)?;
        println!(
            "checkpoint {}",
            begun.checkpoint().body().trim_end().replace('\n', " ")
        );
    }
    prune_published(store, rt, &published, prune)
}

/// `publish --prune`: each run just published, or completed, loses its rebuilt artifact's bytes
/// from the store, by the store's own rule, which keeps a divergence's. Only once the publication
/// is pushed and recorded, since until then the artifact is what a release asset is uploaded from
/// and what a dispute is answered with.
fn prune_published(
    store: &Store,
    rt: &tokio::runtime::Runtime,
    runs: &[&str],
    prune: bool,
) -> Result<()> {
    if !prune {
        return Ok(());
    }
    for run in runs {
        match rt.block_on(store.prune_rebuild(run)) {
            Ok(Pruned::Deleted) => {
                println!("pruned    run {run}'s rebuilt artifact; its digests remain")
            }
            Ok(Pruned::Shared(others)) => println!(
                "pruned    run {run}'s rebuilt artifact, and kept its bytes, which {}; its \
                 digests remain",
                match others.is_empty() {
                    true => "are the published artifact too".to_string(),
                    false => format!("run {} still names", others.join(", ")),
                }
            ),
            Ok(Pruned::Kept) => println!(
                "kept      run {run}'s rebuilt artifact: a divergence keeps its bytes, and a run \
                 with none stored has none to drop"
            ),
            Err(e) => println!("kept      run {run}'s rebuilt artifact: {e}"),
        }
    }
    Ok(())
}

/// What the operator does next, after a rotation: said once it is published.
fn advise(base: &Base, plan: &Plan) {
    let rotated = plan
        .entries
        .iter()
        .find(|e| matches!(e.leaf, Leaf::KeyChange(_)));
    if let Some(Entry {
        leaf: Leaf::KeyChange(k),
        ..
    }) = rotated
    {
        println!();
        println!(
            "{}",
            style::wrap(
                &format!(
                    "From this leaf on, the repository's attestation key is {} and `trigon \
                     publish` publishes only records signed by it; every client refuses a record \
                     signed by {} whose leaf comes later. Sign with the new key from now on: \
                     `trigon attest <run> --key <new key file>`, and the same key for `trigon \
                     rebuild --attest --key`. A run attested with the old key is published only \
                     once it is attested again with the new one. Nothing in evidence.toml names \
                     the signing key: a `[[source]]` that pins this repository keeps pinning {}, \
                     the key its chain starts at, and follows the change from the log, and so \
                     does `keys/attestation.pub`. Keep the old key file out of use.",
                    k.new.key_id, k.old.key_id, k.old.key_id
                ),
                0
            )
        );
    }
    if let Some(sp) = &plan.succession {
        let repo = match sp.here() {
            true => String::new(),
            false => format!(
                "`repo = \"{}\"`, ",
                sp.successor.urls.first().map(String::as_str).unwrap_or("")
            ),
        };
        println!();
        println!(
            "{}",
            style::wrap(
                &format!(
                    "`{}` has ended, and `{}` continues it at {}. Publish into the successor from \
                     now on: set {repo}`origin = \"{}\"` and `log_key = \"{}\"` under \
                     `[publish]` in evidence.toml, and attest again whatever is to be published, \
                     since every verdict signs the origin of the log it is published into. Keep \
                     the old log key: nothing more is appended to `{}`, and its final checkpoint \
                     is what a client holding it checks the succession against. A client pinned \
                     to `{}` follows the succession itself.",
                    base.log().origin(),
                    sp.successor.origin,
                    where_is(&sp.successor),
                    sp.successor.origin,
                    sp.log_key.display(),
                    base.log().origin(),
                    base.pinned.origin()
                ),
                0
            )
        );
    }
}

/// The commit that logged leaf `index` of the log at `dir` in the tree at `root`: the first on the
/// branch whose checkpoint of that log, opened under its key `vkey`, covers it. Asked of the log's
/// own history rather than of when the record file was added, which whoever can push may have
/// removed, or never had.
fn logged_in(root: &Path, dir: &str, vkey: &LogVkey, index: u64) -> Result<String> {
    let path = format!("{dir}/checkpoint");
    let commits = git::text(
        Some(root),
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
    for (commit, bytes) in commits.iter().zip(git::blobs(root, &revs)?) {
        let covers = bytes
            .and_then(|b| SignedCheckpoint::open(&b, vkey).ok())
            .is_some_and(|c| c.size() > index);
        if covers {
            return Ok(commit.to_string());
        }
    }
    bail!(
        "no commit of {}'s `{}` has a checkpoint covering leaf {index}, and its log holds it: the \
         branch's history is not the log's",
        root.display(),
        path
    )
}

/// Every file and leaf a publication would write, and the checkpoint body it would sign, unsigned;
/// every rebuilt artifact it would find or upload; and, for a succession, what begins the
/// successor, which only `log sign` can write.
fn show(base: &Base, plan: &Plan, s: &Settings) {
    println!(
        "dry run   nothing is written, and `trigon log sign` is not run; the working clone and the \
         repository are left as they are"
    );
    let assets = plan.assets();
    if !assets.is_empty() {
        let repository = release::on_github(&s.location).unwrap_or_default();
        for a in &assets {
            println!(
                "asset     {} ({} bytes), the rebuilt artifact of run {}: a release asset of {}, in \
                 {} or the next of its series with room, unless one of that name is there",
                a.name(),
                a.size,
                a.run,
                repository,
                release::tag(&release::month_of(plan.time), 1)
            );
        }
        if s.github.is_none() {
            println!(
                "          neither GITHUB_TOKEN nor GH_TOKEN is set, and `trigon publish` itself \
                 would refuse to upload without one"
            );
        }
    }
    if let Some(sp) = plan.succession.as_ref().filter(|sp| sp.ended_already) {
        println!(
            "begin     `{}` at {}: `{}` ended already, naming it",
            sp.successor.origin,
            where_is(&sp.successor),
            base.log().origin()
        );
        return;
    }
    if plan.writes.is_empty() && plan.removes.is_empty() && plan.unsigned.is_empty() {
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
    for path in &plan.unsigned {
        println!("write     {path} (its bytes cover the signatures only the publication makes)");
    }
    for (i, e) in plan.entries.iter().enumerate() {
        let leaf = match &e.leaf {
            Leaf::KeyChange(k) if k.old.signature.is_empty() => unsigned_key_change(k),
            l => String::from_utf8_lossy(&l.encode().unwrap_or_default()).into_owned(),
        };
        println!("leaf {}    {leaf}", base.log().size() + i as u64);
    }
    if let Some(c) = &plan.checkpoint {
        println!("checkpoint, unsigned:");
        for line in c.body().lines() {
            println!("  {line}");
        }
    }
    if !plan.unsigned.is_empty() {
        println!(
            "checkpoint of `{}` at {} leaves, whose root covers the key change's two signatures, \
             which a dry run does not make: published, both attestation keys sign the leaf in a \
             child process, and `trigon log sign` the checkpoint",
            base.log().origin(),
            base.log().size() + plan.entries.len() as u64
        );
    }
    if let Some(sp) = &plan.succession {
        println!(
            "begin     `{}` at {}, with its log-continuation leaf: the final checkpoint above, \
             signed by both log keys, which only `trigon log sign` holding both can write, so it \
             is not shown here",
            sp.successor.origin,
            where_is(&sp.successor)
        );
    }
    println!("commit    {}", plan.message);
}

/// A key change a dry run planned, as it would be logged but with its two signatures empty: it is
/// no leaf until both keys sign it, so it is printed as its fields, not encoded as one.
fn unsigned_key_change(k: &KeyChangeLeaf) -> String {
    let mut v = serde_json::to_value(k).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("kind".into(), "key-change".into());
    }
    v.to_string()
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
