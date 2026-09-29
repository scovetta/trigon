//! `trigon verify-attestation --record <file> --evidence <dir>`: one published record checked
//! against the log of the evidence repository it is from (`docs/19` §6, the network-free
//! verifier).
//!
//! For one source, with its keys and the checkpoint its log must extend taken from `--source
//! <name>` — `evidence.toml` and the state directory — or given as `--log-vkey`,
//! `--attestation-key` and `--checkpoint`. The directory is a clone or any copy of one; nothing
//! here opens a socket, and cloning is the default build's job. **Without `--evidence`**, `--source
//! <name>` reads the source's own clones, as a sync left them, and follows its chain across every
//! repository it has gone on in, as the sync did ([`crate::clones::open`]), so a record logged in a
//! successor elsewhere is checked where it is logged and a withdrawal logged there is seen.
//! `verify-attestation --lookup` finds its record and then reports on it here too.
//!
//! What it checks, in order: the source's log, whole, from `<dir>` (`trigon_attest::evidence::
//! Repository::open`); the record against its leaf, the key its source had at that leaf, and the
//! evidence files beside it (`check_record`); what the source says of the record's artifact now,
//! every supersession applied (`lookup`); and, under `--rerun-comparison`, the claim re-derived
//! from the two artifacts and the published comparison report held to it. It shows the record as
//! `docs/19` §4.2 has every client show one: with its set, when and which Trigon, the egress tier,
//! the derivation, and for a verdict the command that would falsify it and where to dispute it.
//!
//! **Exit codes are `docs/19` §6's**, because this ends up in CI: 0 for a verdict at or above
//! `normalized_with_caveats`, 1 for a divergence, 2 for a withdrawn artifact, 3 for a void or a
//! lower verdict, 4 for a record, a log or a claim that failed verification — an equivocation
//! among them — or a source that cannot say what it says now, and 5 when it could not check at
//! all: bad arguments, `clap`'s included, an unreadable input, or no such source. Of several, the
//! first in the order 5, 4, 1, 3, 2 wins.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use serde_json::{Value, json};
use trigon_attest::config::{
    AddedBy, Env, EvidenceConfig, read_attestation_key, read_checkpoint_file,
};
use trigon_attest::evidence::{
    Answer, EvidenceState, Key, Lookup, RecordFailure, RecordKind, Repository, Standing,
    VerifiedRecord, read_evidence_from,
};
use trigon_attest::location::printable;
use trigon_attest::log::{Checkpoint, LogError, LogFiles, SignedNote};
use trigon_attest::state::SyncRecord;
use trigon_attest::{
    AttestationKey, DisputePointer, FalsifyingCommand, LogVkey, Record, Rederived, ReportCheck,
};
use trigon_core::Match;

use crate::{OutputFormat, Rerun};

/// `docs/19` §6: any record, log or claim that failed verification, an equivocation, or a source
/// that cannot answer.
const FAILED: i32 = 4;
/// `docs/19` §6: the tool itself failed — bad arguments, an unreadable input, no source.
pub(crate) const CANNOT: i32 = 5;
/// The outcome floor. `verify-attestation` takes no `--min`, and §6's default is this.
const FLOOR: Match = Match::NormalizedWithCaveats;

pub(crate) struct Args<'a> {
    pub record: &'a Path,
    pub evidence: Option<&'a Path>,
    pub source: Option<&'a str>,
    pub log_vkey: Option<&'a str>,
    pub attestation_key: Option<&'a str>,
    pub checkpoint: Option<&'a Path>,
    pub rerun: bool,
    pub files: Rerun<'a>,
    pub output: OutputFormat,
}

/// Refuse the command's arguments, with exit code 5, as `docs/19` §6 gives bad arguments.
pub(crate) fn usage(message: &str) -> ! {
    eprintln!("Error: {message}");
    std::process::exit(CANNOT)
}

/// Refuse the arguments of the record or the `--lookup` form as [`usage`] does, and under `--output
/// json` print the document every other stop prints, `cannot-check`: a JSON reader gets one
/// wherever `--output` was read, and only `clap`'s own refusals, before it is, print none.
pub(crate) fn refuse(message: &str, output: OutputFormat) -> ! {
    eprintln!("Error: {message}");
    if output == OutputFormat::Json {
        println!("{}", pretty(&stopped(CANNOT, &anyhow!("{message}"), None)));
    }
    std::process::exit(CANNOT)
}

/// Whether a command line is one of `docs/19` §6's forms — `verify-attestation` given `--record`
/// or `--lookup` — read from the raw arguments, so that `main` knows, when `clap` refuses them,
/// that they exit 5 and not 2.
pub(crate) fn named(args: impl IntoIterator<Item = OsString>) -> bool {
    let mut after = args
        .into_iter()
        .skip(1)
        .skip_while(|a| a != "verify-attestation");
    let flag = |a: &OsString, f: &str| {
        a == f || a.to_str().is_some_and(|s| s.starts_with(&format!("{f}=")))
    };
    after.next().is_some()
        && after
            .take_while(|a| a != "--")
            .any(|a| flag(&a, "--record") || flag(&a, "--lookup"))
}

/// Check the record, print the report, and exit with its code.
pub(crate) fn run(args: Args<'_>) -> anyhow::Result<()> {
    finish(check(&args), args.output)
}

/// Exit with a report's code, or say why the command stopped before it had a record to report on
/// and exit with that: the end of the record form and of `--lookup` alike.
pub(crate) fn finish(result: Result<i32, Stop>, output: OutputFormat) -> anyhow::Result<()> {
    let code = match result {
        Ok(code) => code,
        Err(Stop { code, error, cause }) => {
            // `--lookup` finding no current record, and answering with what the sources say of the
            // artifact instead, is no failure, and is said as the answer it is, not as an error.
            match code {
                FAILED | CANNOT => {
                    crate::report_fault(&error);
                    eprintln!("Error: {error:?}");
                }
                _ => eprintln!("{error:#}"),
            }
            // A JSON reader gets a document on every exit, and most of all on the ones §6 cares
            // about: an equivocation or a log that does not verify stops before any record is read.
            if output == OutputFormat::Json {
                println!("{}", pretty(&stopped(code, &error, cause)));
            }
            code
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Why the command stopped before it had a record to report on, and the exit code that says so.
pub(crate) struct Stop {
    pub code: i32,
    pub error: anyhow::Error,
    /// What stopped it, where that was a source or no current record: `None` where it was the
    /// tool, a log or a record, which the code and the error say.
    pub cause: Option<Cause>,
}

/// What stopped a check where it was neither the tool, a log nor a record, as `--output json` names
/// it, so that `failed-verification` is said of a record and of nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    /// No source configured here has the log of the origin `--lookup` names: exit 4.
    #[cfg_attr(
        not(feature = "build"),
        expect(
            dead_code,
            reason = "only `--lookup` resolves an origin, and it is the default build's"
        )
    )]
    NoSource,
    /// A source failed verification as a whole — its last sync was refused, or its clones do not
    /// verify — and no record was checked: exit 4.
    SourceRefused,
    /// A source cannot say what it says now — required and unknown, every one asked unknown, or its
    /// clones not there to be read — and no record was checked: exit 4.
    SourceUnknown,
    /// `--lookup` found no current verdict or void, and exits with what the sources say of the
    /// artifact instead — never checked, withdrawn, or a record of another predicate — which is no
    /// failure.
    #[cfg_attr(
        not(feature = "build"),
        expect(
            dead_code,
            reason = "only `--lookup` resolves a record, and it is the default build's"
        )
    )]
    NoCurrentRecord,
}

impl Cause {
    /// The name `--output json` gives it, as `stopped`.
    fn key(self) -> &'static str {
        match self {
            Cause::NoSource => "no-source",
            Cause::SourceRefused => "source-refused",
            Cause::SourceUnknown => "source-unknown",
            Cause::NoCurrentRecord => "no-current-record",
        }
    }
}

/// The tool could not check at all: exit 5.
pub(crate) fn cannot(error: impl Into<anyhow::Error>) -> Stop {
    Stop {
        code: CANNOT,
        error: error.into(),
        cause: None,
    }
}

/// A log, a record or a file a record names failed verification, or a log cannot be read: exit 4.
/// A source that stops the command is said to with [`Stop::because`].
pub(crate) fn failed(error: impl Into<anyhow::Error>) -> Stop {
    Stop {
        code: FAILED,
        error: error.into(),
        cause: None,
    }
}

impl Stop {
    /// Say that a source, or no current record, stopped it: called what `cause` names, and never a
    /// record that failed verification.
    pub(crate) fn because(self, cause: Cause) -> Stop {
        Stop {
            cause: Some(cause),
            ..self
        }
    }
}

/// The checkpoint a log is held to: the signed note, where it was read from, and what it says it
/// is.
struct Accepted {
    path: PathBuf,
    note: Vec<u8>,
    origin: String,
    size: u64,
}

/// Read a checkpoint given as the last accepted. One that is not a checkpoint is a bad argument or
/// a damaged state file, and the tool could not check at all (exit 5): the source has not been
/// asked anything yet, so it is never blamed for it. Its signature is the source's to answer for,
/// and is checked against the log.
fn accepted(path: PathBuf, note: Vec<u8>) -> Result<Accepted, Stop> {
    let c = SignedNote::parse(&note)
        .and_then(|n| Checkpoint::parse(n.text()))
        .map_err(|e| {
            cannot(anyhow!(
                "{} is not a checkpoint: {e}. The checkpoint a log is held to is a signed note, as \
                 a repository's `log/checkpoint` is",
                path.display()
            ))
        })?;
    Ok(Accepted {
        path,
        note,
        origin: c.origin,
        size: c.size,
    })
}

/// What the source's log is held to, and where each part came from.
struct Pinned {
    /// How to name the source in the report: its name and the file that added it, or the flags.
    said: String,
    log_key: LogVkey,
    attestation_key: AttestationKey,
    accepted: Option<Accepted>,
    /// Why there is no checkpoint to hold the log to, where there is none.
    unaccepted: String,
    /// Where a source's state holds no checkpoint and its initial one stands in: said, since a
    /// missing state file is reported rather than passed over (`docs/19` §6.1).
    fallback: Option<String>,
}

fn pins(a: &Args<'_>) -> Result<Pinned, Stop> {
    match (a.source, a.log_vkey, a.attestation_key, a.checkpoint) {
        (Some(name), None, None, None) => {
            let config = Env::from_process()
                .and_then(|env| EvidenceConfig::load(&env))
                .map_err(cannot)?;
            let p = config.pins(name).map_err(cannot)?;
            let mut said = match &p.added_by {
                AddedBy::ProjectFile(f) => format!(
                    "`{}`, added by the project's own {}",
                    printable(name),
                    f.display()
                ),
                other => format!("`{}`, from {other}", printable(name)),
            };
            // Every answer from a source that trusts on first use says what it rests on.
            if let Some(f) = &p.first_use {
                said.push_str(&format!(
                    ", resting on keys trusted on first use: read from {}'s keys/ at {} by its \
                     first sync, and pinned since",
                    printable(&f.read_from),
                    crate::rfc3339_from_unix(f.at)
                ));
            }
            let unaccepted = format!(
                "no checkpoint has been accepted for this source — {} is not there — and it \
                 configures no initial one, so its log is checked whole and not against anything \
                 this client has seen before",
                p.state.display()
            );
            let fallback = p
                .accepted
                .as_ref()
                .is_some_and(|(path, _)| *path != p.state)
                .then(|| {
                    format!(
                        "no checkpoint has been accepted for this source — {} is not there — so \
                         its log is held only to the initial checkpoint it is configured with: a \
                         rollback to any state since that one is not detected",
                        p.state.display()
                    )
                });
            Ok(Pinned {
                said,
                log_key: p.log_key,
                attestation_key: p.attestation_key,
                accepted: p
                    .accepted
                    .map(|(path, note)| accepted(path, note))
                    .transpose()?,
                unaccepted,
                fallback,
            })
        }
        (None, Some(vkey), Some(key), checkpoint) => {
            let log_key = LogVkey::parse(vkey).map_err(|e| cannot(anyhow!("--log-vkey: {e}")))?;
            let cwd = std::env::current_dir().map_err(cannot)?;
            let home = std::env::var_os("HOME").map(PathBuf::from);
            let attestation_key = read_attestation_key(key, &cwd, home.as_deref())
                .map_err(|m| cannot(anyhow!("--attestation-key: {m}")))?;
            let accepted = match checkpoint {
                Some(p) => {
                    let note = read_checkpoint_file(p)
                        .map_err(|m| cannot(anyhow!("--checkpoint {}: {m}", p.display())))?;
                    Some(accepted(p.to_path_buf(), note)?)
                }
                None => None,
            };
            Ok(Pinned {
                said: "the keys given on the command line".into(),
                log_key,
                attestation_key,
                accepted,
                unaccepted:
                    "no --checkpoint, so the log is checked whole and not against anything \
                             this client has seen before"
                        .into(),
                fallback: None,
            })
        }
        (Some(_), ..) => Err(cannot(anyhow!(
            "--source takes the source's keys and checkpoint from its configuration and state; \
             --log-vkey, --attestation-key and --checkpoint are for a source not configured, \
             and go without it"
        ))),
        _ => Err(cannot(anyhow!(
            "--record is checked against one source's keys: name the source with --source \
             <name>, or give its keys with --log-vkey and --attestation-key, and the checkpoint \
             last accepted with --checkpoint"
        ))),
    }
}

/// `--rerun-comparison`'s arguments, checked before anything is verified, so that a bad one exits
/// 5 whatever the record turns out to be (§6: 5 before 4): both artifacts named and readable, and
/// none of its files given without it.
fn rerun_arguments(a: &Args<'_>) -> Result<(), Stop> {
    rerun_files(a.rerun, a.files, true)
}

/// [`rerun_arguments`], for any form: `rebuild_needed` is false where the rebuilt artifact can be
/// had another way — `--lookup`, from the release asset a record names.
pub(crate) fn rerun_files(rerun: bool, f: crate::Rerun<'_>, rebuild_needed: bool) -> Result<(), Stop> {
    let given = [
        ("--upstream", f.upstream),
        ("--rebuild", f.rebuild),
        ("--stabilizers", f.stabilizers),
    ];
    if !rerun {
        return match given.iter().find(|(_, p)| p.is_some()) {
            Some((flag, _)) => Err(cannot(anyhow!(
                "{flag} is read by --rerun-comparison, and goes with it: without it the claim is \
                 read and not re-derived, and nothing would read {flag}"
            ))),
            None => Ok(()),
        };
    }
    if f.upstream.is_none() || (rebuild_needed && f.rebuild.is_none()) {
        return Err(cannot(anyhow!(
            "--rerun-comparison needs both --upstream <file>, the published artifact, and \
             --rebuild <file>, the rebuilt one"
        )));
    }
    for (flag, path) in given {
        let Some(path) = path else { continue };
        let file = std::fs::metadata(path)
            .map_err(|e| cannot(anyhow!("{flag} {}: {e}", path.display())))?;
        if !file.is_file() {
            return Err(cannot(anyhow!("{flag} {} is not a file", path.display())));
        }
    }
    Ok(())
}

/// Everything the report says, gathered before any of it is printed.
struct Report {
    pinned: String,
    notes: Vec<String>,
    logs: Vec<(String, u64)>,
    newest: Option<u64>,
    record: trigon_core::Digest,
    verified: Result<VerifiedRecord, RecordFailure>,
    origin: Option<String>,
    lookup: Option<Lookup>,
    /// Why what the source says of the artifact now is not known here, where it is not: the log
    /// continues in a repository this directory does not hold.
    unknown: Option<String>,
    rerun: Option<Rederivation>,
}

fn check(a: &Args<'_>) -> Result<i32, Stop> {
    let reading = match (a.evidence, a.source) {
        (Some(dir), _) => {
            if !dir.is_dir() {
                return Err(cannot(anyhow!("--evidence {} is not a directory", dir.display())));
            }
            rerun_arguments(a)?;
            from_directory(a, dir)?
        }
        (None, Some(name)) => {
            if a.log_vkey.is_some() || a.attestation_key.is_some() || a.checkpoint.is_some() {
                return Err(cannot(anyhow!(
                    "--source takes the source's keys and checkpoint from its configuration and \
                     state; --log-vkey, --attestation-key and --checkpoint are for a source not \
                     configured, and go without it"
                )));
            }
            rerun_arguments(a)?;
            from_clones(name)?
        }
        (None, None) => {
            return Err(cannot(anyhow!(
                "--record needs --evidence <dir>, the evidence repository the record is from — a \
                 clone or any directory with the layout of docs/19 §2.3 — or --source <name>, \
                 whose synced clones are read"
            )));
        }
    };
    let bytes = std::fs::read(a.record)
        .with_context(|| format!("reading {}", a.record.display()))
        .map_err(cannot)?;
    let rerun = a.rerun.then_some(a.files);
    let done = report(&reading.reading(), &bytes, None, rerun)?;
    print(&done, a.output);
    Ok(done.code)
}

/// A source's log, opened and verified whole, and what a report says of where it came from: what a
/// record is checked against.
pub(crate) struct Reading<'a> {
    /// How the source is named: its name and the file that added it, or the flags.
    pub pinned: String,
    pub repo: &'a Repository,
    pub notes: Vec<String>,
    /// Why what the source says of the artifact now is not known, where it is not: the log
    /// continues where this does not reach, or the source is stale or frozen.
    pub unknown: Option<String>,
}

/// A [`Reading`] that holds the repository it reads.
struct Opened {
    pinned: String,
    repo: Repository,
    notes: Vec<String>,
    unknown: Option<String>,
}

impl Opened {
    fn reading(&self) -> Reading<'_> {
        Reading {
            pinned: self.pinned.clone(),
            repo: &self.repo,
            notes: self.notes.clone(),
            unknown: self.unknown.clone(),
        }
    }
}

/// The repository in `--evidence <dir>`, verified under the keys `--source` or the flags give.
fn from_directory(a: &Args<'_>, evidence: &Path) -> Result<Opened, Stop> {
    let pinned = pins(a)?;
    // The source's log, whole, before anything is read from the repository. A log that does not
    // verify — a signature, a tree, a rollback, two trees under one key — is the source failing
    // verification, and one that cannot be read is a source that cannot answer: both 4.
    let held_to = pinned.accepted.as_ref().map(|c| c.note.as_slice());
    let repo = Repository::open(evidence, &pinned.log_key, &pinned.attestation_key, held_to)
        .map_err(|e| {
            failed(anyhow::Error::new(e).context(format!(
                "the evidence repository in {} does not verify under {}",
                evidence.display(),
                pinned.said
            )))
        })?;
    let source = repo.source();
    let mut notes = Vec::new();
    notes.extend(pinned.fallback.clone());
    match &pinned.accepted {
        // Said only once it has been checked: a checkpoint the log was never held to is not one
        // it is held to.
        Some(c) if source.accepted_checked => notes.push(format!(
            "the log is held to the checkpoint of {} leaves in {}",
            c.size,
            c.path.display()
        )),
        Some(c) => notes.push(unchecked_checkpoint(c, source.continues_at.as_ref())),
        None => notes.push(pinned.unaccepted.clone()),
    }
    // A log that continues in a repository this directory does not hold may hold, past what is
    // here, a withdrawal or a supersession of this very record: what the source says now is not
    // known here, and is never answered as though it were (§4.2 `unknown`, §6 exit 4).
    let unknown = source.continues_at.as_ref().map(|s| {
        format!(
            "the log continues as `{}` at {}, which this directory does not hold, so a record \
             logged there — a withdrawal or a supersession of this one among them — is not seen \
             here, and what the source says of the artifact now is not known",
            printable(&s.origin),
            s.urls
                .iter()
                .map(|u| printable(u))
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    Ok(Opened {
        pinned: pinned.said,
        repo,
        notes,
        unknown,
    })
}

/// The source `name`'s own clones, as its last sync left them, opened as every command that
/// answers from them opens them: every location held to every other, the chain followed into
/// every repository it has gone on in, and all of it held to the checkpoint last accepted. Nothing
/// is fetched; a source that is stale or frozen still has its record checked, and what it says of
/// the artifact now is unknown.
fn from_clones(name: &str) -> Result<Opened, Stop> {
    let config = Env::from_process()
        .and_then(|env| EvidenceConfig::load(&env))
        .map_err(cannot)?;
    let source = config
        .source(name)
        .ok_or_else(|| {
            cannot(trigon_attest::config::ConfigError::NoSuchSource {
                name: printable(name),
                known: config.sources().iter().map(|s| s.name.clone()).collect(),
            })
        })?
        .clone();
    let dirs = crate::clones::Dirs::of(&config, &source.name).map_err(cannot)?;
    // No record has been read: what stops it here is the source, refused or not there to be read,
    // and a log that failed is named as the log it is.
    let opened = crate::clones::open(&source, &dirs).map_err(|f| {
        failed(f.error.context(format!(
            "`{}`'s clones in {} {}",
            source.name,
            dirs.cache.display(),
            match f.refused {
                true => "do not verify",
                false => {
                    "cannot be read; run `trigon evidence sync --source <name>` in the default \
                     build, or give the repository with --evidence <dir>"
                }
            }
        )))
        .because(match f.refused {
            true => Cause::SourceRefused,
            false => Cause::SourceUnknown,
        })
    })?;
    let mut pinned = match &source.added_by {
        AddedBy::ProjectFile(f) => format!(
            "`{}`, added by the project's own {}",
            source.name,
            f.display()
        ),
        other => format!("`{}`, from {other}", source.name),
    };
    if let Some(f) = &opened.keys.first_use {
        pinned.push_str(&format!(
            ", resting on keys trusted on first use: read from {}'s keys/ at {} by its first \
             sync, and pinned since",
            printable(&f.read_from),
            crate::rfc3339_from_unix(f.at)
        ));
    }
    let last = opened.last();
    let mut notes = vec![format!(
        "read from its clones in {}, as its last sync left them, as of {} leaves of `{}`",
        dirs.cache.display(),
        last.size(),
        last.origin()
    )];
    notes.extend(opened.notes.iter().cloned());
    let state = dirs.state.join(trigon_attest::state::CHECKPOINT);
    notes.push(match (state.exists(), &source.checkpoint) {
        (true, _) => format!(
            "the chain is held to the checkpoint last accepted, in {}",
            state.display()
        ),
        (false, Some(initial)) => format!(
            "no checkpoint has been accepted for this source — {} is not there — so its log is \
             held only to the initial checkpoint it is configured with, {}",
            state.display(),
            initial.display()
        ),
        (false, None) => format!(
            "no checkpoint has been accepted for this source — {} is not there — and it \
             configures no initial one, so its log is checked whole and not against anything \
             this client has seen before",
            state.display()
        ),
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let record = SyncRecord::read(&dirs.state).ok().flatten();
    let standing = Standing::of(config.freshness(), record.as_ref(), opened.repo.newest_time(), now);
    let unknown = (!standing.answers()).then(|| {
        format!(
            "`{}` is {}: {}, so what it says of the artifact now is not known",
            source.name,
            standing.key(),
            match &standing {
                Standing::Frozen { newest: Some(t) } => format!(
                    "its newest leaf was logged {}, longer ago than `frozen_after`",
                    crate::rfc3339_from_unix(*t)
                ),
                Standing::Frozen { newest: None } => "its log has no leaf".into(),
                Standing::Unknown { why } | Standing::Refused { why } => printable(why),
                Standing::Fresh | Standing::Usable { .. } => String::new(),
            }
        )
    });
    Ok(Opened {
        pinned,
        repo: opened.repo,
        notes,
        unknown,
    })
}

/// A record checked, and its exit code: what [`print`] shows.
pub(crate) struct Done {
    pub code: i32,
    report: Report,
}

impl Done {
    /// Say one thing more of it, beside the notes it was checked with: what was done while it was
    /// checked.
    #[cfg(feature = "build")]
    pub(crate) fn note(&mut self, note: String) {
        self.report.notes.push(note);
    }
}

/// Check one record against a source's log: everything `docs/19` §4.2 has every client show of it,
/// with what the source says of its artifact now, gathered for [`print`] — the record form's
/// report, and `--lookup`'s.
///
/// `evidence` is where the evidence the record names is read, where that is not the directory of
/// the repository that holds its log: a partial clone's objects. `rerun` holds the two artifacts
/// `--rerun-comparison` re-derives the claim from.
pub(crate) fn report(
    reading: &Reading<'_>,
    bytes: &[u8],
    evidence: Option<&dyn LogFiles>,
    rerun: Option<crate::Rerun<'_>>,
) -> Result<Done, Stop> {
    let repo = reading.repo;
    let mut notes = reading.notes.clone();
    let source = repo.source();
    for r in &source.refused {
        notes.push(format!("`{}` set aside: {}", r.dir, printable(&r.why)));
    }
    for d in &source.unnamed {
        notes.push(format!(
            "`{d}` is named by no log-end, and was not read as a successor"
        ));
    }
    for (pos, why) in repo.skipped_key_changes() {
        notes.push(format!(
            "key change at {pos} changed nothing: {}",
            printable(why)
        ));
    }

    let verified = repo.verify_record_reading(bytes, evidence);
    let mut report = Report {
        pinned: reading.pinned.clone(),
        notes,
        logs: source
            .logs
            .iter()
            .map(|c| (c.log.origin().to_string(), c.log.size()))
            .collect(),
        newest: repo.newest_time(),
        record: Record::digest_of(bytes),
        origin: verified
            .as_ref()
            .ok()
            .map(|v| repo.origin(v.pos).to_string()),
        lookup: None,
        unknown: reading.unknown.clone(),
        rerun: None,
        verified,
    };

    if let Ok(v) = &report.verified {
        let subject = v.leaf.subject["sha256"].clone();
        report.lookup = Some(repo.lookup(&Key::Digest {
            algorithm: "sha256",
            hex: subject,
        }));
        if let Some(files) = rerun {
            report.rerun = Some(rederive(files, repo, evidence, v)?);
        }
    } else if rerun.is_some() {
        report.notes.push(
            "not re-derived: the record failed verification, so its claim is not read".into(),
        );
    }

    let code = exit_code(&report);
    Ok(Done { code, report })
}

/// Print a record's report, in text or as its JSON document.
pub(crate) fn print(done: &Done, output: OutputFormat) {
    match output {
        OutputFormat::Text => print_text(&done.report),
        OutputFormat::Json => println!("{}", pretty(&json(done))),
    }
}

/// A record's report as `--output json` carries it.
pub(crate) fn json(done: &Done) -> Value {
    json_of(&done.report, done.code)
}

/// A checkpoint given as last accepted that the log in this directory was not held to, which is
/// only one for a log this repository's chain continues into elsewhere, or one past it: said, and
/// never as a checkpoint the log is held to.
fn unchecked_checkpoint(c: &Accepted, next: Option<&trigon_attest::log::Successor>) -> String {
    let whose = match next {
        Some(s) if s.origin == c.origin => format!(
            "`{}`, the log this repository's chain continues into in another repository",
            printable(&c.origin)
        ),
        Some(s) => format!(
            "`{}`, which is no log this directory holds, and not `{}`, the one its chain \
             continues into — perhaps a log past that one",
            printable(&c.origin),
            printable(&s.origin)
        ),
        None => format!("`{}`", printable(&c.origin)),
    };
    format!(
        "the checkpoint in {} is of {whose}; it was not checked here, and the log here is held to \
         nothing this client has seen before",
        c.path.display()
    )
}

/// What `--rerun-comparison` found of a verified verdict.
struct Rederivation {
    /// The claim re-derived from the two artifacts, or why the bytes refute it outright: a
    /// stabilized digest or a subject digest that is not theirs.
    claim: Result<Rederived, String>,
    /// The published comparison report, held to the re-derivation where there is one to hold it
    /// to and the directory holds it.
    report: Published,
}

/// What the published comparison report was found to be.
enum Published {
    /// Held to the re-derivation: what it disagrees with, and what it was not held to.
    Checked(ReportCheck),
    /// Not held to anything, and why: absent, a release asset, an archived set's re-derivation.
    Unchecked(String),
    /// Not the bytes the verdict signs when read again to be judged, or not a comparison at all:
    /// the record's evidence failing verification.
    Failed(String),
}

impl Rederivation {
    /// Whether the claim, or the report the verdict signs beside it, was refuted.
    fn refuted(&self) -> bool {
        let report = match &self.report {
            Published::Checked(c) => !c.agrees(),
            Published::Failed(_) => true,
            Published::Unchecked(_) => false,
        };
        report || self.claim.as_ref().is_ok_and(|d| !d.holds()) || self.claim.is_err()
    }
}

/// `--rerun-comparison` on a verified verdict: the claim re-derived from the two artifacts, and the
/// published comparison report, where it can be read — from the repository's directory, or from
/// `evidence` where one is given — held to the re-derivation.
fn rederive(
    files: crate::Rerun<'_>,
    repo: &Repository,
    evidence: Option<&dyn LogFiles>,
    v: &VerifiedRecord,
) -> Result<Rederivation, Stop> {
    if !trigon_attest::is_verdict(&v.statement.predicate_type) {
        return Err(cannot(anyhow!(
            "--rerun-comparison re-derives a verdict, and this record is a `{}`, which makes no \
             comparison claim",
            v.statement.predicate_type
        )));
    }
    let claim = match crate::rederive_files(&v.statement, files) {
        Ok(d) => Ok(d),
        // A claim the bytes refute fails verification, and is reported in full with the rest of
        // the record; anything else — the wrong file, a set this build does not carry, an
        // artifact that will not parse — is a check not made.
        Err(e)
            if e.downcast_ref::<trigon_attest::AttestError>()
                .is_some_and(|e| e.fails_verification()) =>
        {
            crate::report_fault(&e);
            Err(printable(&format!("{e:#}")))
        }
        Err(e) => return Err(cannot(e)),
    };
    let comparison = v
        .evidence
        .iter()
        .find(|e| e.name == trigon_attest::evidence_key::COMPARISON);
    let report = match (comparison, &claim) {
        (_, Err(_)) => Published::Unchecked(
            "unchecked: the claim did not re-derive, so there is nothing to hold the report to"
                .into(),
        ),
        (Some(e), Ok(d)) if e.state == EvidenceState::Matches => {
            // Read again to be judged, and held to its digest again: the file checked when the
            // record was verified may be other bytes by now.
            let read = match evidence {
                Some(files) => read_evidence_from(files, e),
                None => repo.read_evidence_checked(v.pos, e),
            };
            match read {
                Err(failure) => Published::Failed(failure.to_string()),
                Ok((state, None)) => Published::Unchecked(format!(
                    "unchecked: sha256:{} was there when the record was verified, and is {} now",
                    e.digest.to_hex(),
                    state_said(&state)
                )),
                Ok((_, Some(bytes))) => match d.check_report(&bytes) {
                    Ok(Some(checked)) => Published::Checked(checked),
                    Ok(None) => Published::Unchecked(
                        "unchecked: an archived set re-derives no report".into(),
                    ),
                    Err(e) => Published::Failed(e.to_string()),
                },
            }
        }
        (Some(e), Ok(_)) => Published::Unchecked(format!(
            "unchecked: sha256:{} is {}",
            e.digest.to_hex(),
            state_said(&e.state)
        )),
        (None, Ok(_)) => Published::Unchecked("unchecked: the verdict names none".into()),
    };
    Ok(Rederivation { claim, report })
}

/// The record's own answer and, under `--rerun-comparison`, whether its claim held: the most
/// severe, as §6 orders them.
fn exit_code(r: &Report) -> i32 {
    let Ok(_) = &r.verified else {
        return FAILED;
    };
    if r.rerun.as_ref().is_some_and(Rederivation::refuted) || r.unknown.is_some() {
        return FAILED;
    }
    let answer = r
        .lookup
        .as_ref()
        .map_or(Answer::NeverChecked, |l| l.answer(FLOOR));
    i32::from(answer.exit_code(FLOOR))
}

pub(crate) fn state_said(s: &EvidenceState) -> String {
    match s {
        EvidenceState::Matches => "there, and matches its digest".into(),
        EvidenceState::Absent => "not in this directory: unchecked".into(),
        EvidenceState::ReleaseAsset => "a release asset, not in the repository: unchecked".into(),
        EvidenceState::Unreadable(why) => format!("unreadable, so unchecked: {}", printable(why)),
    }
}

pub(crate) fn state_name(s: &EvidenceState) -> &'static str {
    match s {
        EvidenceState::Matches => "matches",
        EvidenceState::Absent => "absent",
        EvidenceState::ReleaseAsset => "release-asset",
        EvidenceState::Unreadable(_) => "unreadable",
    }
}

pub(crate) fn kind_said(k: RecordKind) -> String {
    match k {
        RecordKind::Verdict(m) => m.to_string(),
        RecordKind::Void => "void".into(),
        RecordKind::Withdrawal => "a withdrawal".into(),
    }
}

/// The record's place among its subject's records: whether it is current, and what supersedes it.
fn superseded(r: &Report, v: &VerifiedRecord) -> Vec<(String, String)> {
    let Some(l) = &r.lookup else {
        return Vec::new();
    };
    l.found
        .iter()
        .filter(|f| f.pos == v.pos)
        .flat_map(|f| &f.superseded_by)
        .map(|s| {
            (
                format!("sha256:{}", s.record.to_hex()),
                format!("{} ({})", s.pos, s.reason),
            )
        })
        .collect()
}

/// The fields `docs/19` §4.2 has every client that shows a record render, as its statement signs
/// them: the set, when and which Trigon, the egress tier and `attestable`, and for a verdict the
/// derivation method, the command that would falsify it and where to dispute it. Each is escaped,
/// since a statement is its signer's bytes, and absent is shown as absent, never as a value.
pub(crate) fn signed_fields(v: &VerifiedRecord) -> Vec<(&'static str, String)> {
    let p = &v.statement.predicate;
    let text = |pointer: &str| p.pointer(pointer).and_then(Value::as_str).map(printable);
    let kind = v.kind();
    let attestor = text("/trigonVersion/attestor");
    if kind == RecordKind::Withdrawal {
        // No run is behind a withdrawal, so no set, time, environment or derivation.
        return vec![(
            "trigon",
            attestor.map_or_else(|| "none signed".into(), |a| format!("signed by {a}")),
        )];
    }
    let set = match (
        text("/stabilizerSet/id"),
        text("/stabilizerSet/digest/sha256"),
    ) {
        (Some(id), Some(d)) => format!("{id}, sha256:{d}"),
        _ if kind == RecordKind::Void => "none: the run reached no comparison".into(),
        _ => "none signed".into(),
    };
    let run = match (
        text("/run/id"),
        text("/run/startedOn"),
        text("/run/finishedOn"),
    ) {
        (Some(id), Some(from), Some(to)) => format!("{id}, {from} to {to}"),
        (Some(id), Some(from), None) => format!("{id}, from {from}; its finish was not recorded"),
        _ => "none signed".into(),
    };
    let trigon = match (text("/trigonVersion/builder"), attestor) {
        (Some(b), Some(a)) => format!("built by {b}, signed by {a}"),
        (None, Some(a)) => format!("built by a Trigon the run did not record, signed by {a}"),
        (Some(b), None) => format!("built by {b}; the signer is not named"),
        (None, None) => "none signed".into(),
    };
    let attestable = match p.get("attestable").and_then(Value::as_bool) {
        Some(true) => "attestable",
        Some(false) => "not attestable",
        None => "`attestable` not signed",
    };
    let egress = match text("/egressTier") {
        Some(t) => format!("{t}, {attestable}"),
        None => format!("no tier signed, {attestable}"),
    };
    let mut out = vec![
        ("set", set),
        ("run", run),
        ("trigon", trigon),
        ("egress", egress),
    ];
    if let RecordKind::Verdict(_) = kind {
        out.push((
            "derived",
            text("/derivation/method")
                .unwrap_or_else(|| "not recorded: the statement names no derivation method".into()),
        ));
        let falsify = p
            .get("falsifyingCommand")
            .map(|c| serde_json::from_value::<FalsifyingCommand>(c.clone()));
        out.push((
            "falsify",
            match falsify {
                Some(Ok(c)) => printable(&c.render()),
                Some(Err(_)) => format!(
                    "signed in a form this build does not read: {}",
                    printable(&p["falsifyingCommand"].to_string())
                ),
                None => "none signed: this verdict names no command that would falsify it".into(),
            },
        ));
        let dispute = p
            .get("disputePointer")
            .map(|d| serde_json::from_value::<DisputePointer>(d.clone()));
        out.push((
            "dispute",
            match dispute {
                Some(Ok(DisputePointer::Url { url })) => printable(&url),
                Some(Err(_)) => format!(
                    "signed in a form this build does not read: {}",
                    printable(&p["disputePointer"].to_string())
                ),
                None => "none signed: this verdict names nowhere to dispute it".into(),
            },
        ));
    }
    out
}

fn print_text(r: &Report) {
    println!("source    {}", r.pinned);
    let logs: Vec<String> = r
        .logs
        .iter()
        .map(|(origin, size)| format!("{origin}, {size} leaves"))
        .collect();
    println!("log       {} — verified whole", logs.join(", then "));
    if let Some(t) = r.newest {
        println!("newest    leaf logged {}", crate::rfc3339_from_unix(t));
    }
    for n in &r.notes {
        println!("note      {n}");
    }
    let v = match &r.verified {
        Ok(v) => v,
        Err(why) => {
            println!("record    sha256:{}", r.record.to_hex());
            println!("verified  NO — the record failed verification: {why}");
            return;
        }
    };
    println!(
        "record    sha256:{} at leaf {} of {}",
        v.digest.to_hex(),
        v.pos.index,
        r.origin.as_deref().unwrap_or("?")
    );
    let st = &v.statement;
    for s in &st.subject {
        println!(
            "subject   {} ({})",
            printable(&s.name),
            s.digest.get("sha256").map(String::as_str).unwrap_or("?")
        );
    }
    println!("purl      {}", v.leaf.purl);
    println!("predicate {}", st.predicate_type);
    println!(
        "signature verified under {}, the source's attestation key at its leaf",
        v.key.key_id()
    );
    let said = |key: &str| printable(st.predicate[key].as_str().unwrap_or("?"));
    match v.kind() {
        RecordKind::Withdrawal => println!("withdraws {} ({})", said("supersedes"), said("reason")),
        RecordKind::Void => println!("claims    void, because {}", said("because")),
        RecordKind::Verdict(m) => println!("claims    {m}"),
    }
    for (label, value) in signed_fields(v) {
        println!("{label:<10}{value}");
    }
    if v.kind() != RecordKind::Withdrawal
        && let Some((record, reason)) = v.supersedes()
    {
        println!("supersedes sha256:{} ({reason})", record.to_hex());
    }
    let mut first = true;
    for e in &v.evidence {
        println!(
            "{}{} sha256:{} {}",
            if first { "evidence  " } else { "          " },
            e.name,
            e.digest.to_hex(),
            state_said(&e.state)
        );
        first = false;
    }
    let by = superseded(r, v);
    match (&r.unknown, by.is_empty()) {
        (None, true) => println!("current   yes: nothing the log holds supersedes it"),
        (Some(_), true) => println!(
            "current   unknown: nothing the log here holds supersedes it, and the log goes on \
             where this directory does not reach"
        ),
        // A supersession the log holds is final, whatever is logged after it.
        (_, false) => {}
    }
    for (record, at) in &by {
        println!("current   no: superseded by {record} at {at}");
    }
    match (&r.unknown, &r.lookup) {
        (Some(why), _) => println!("answer    unknown — {why}"),
        (None, Some(l)) => {
            let answer = l.answer(FLOOR);
            println!(
                "answer    {answer} — what this source says of the artifact now, from {} \
                 record(s) the log holds for it",
                l.found.len()
            );
        }
        (None, None) => {}
    }
    let Some(d) = &r.rerun else {
        return;
    };
    match &d.claim {
        Ok(claim) => crate::print_rederived(Some(claim)),
        Err(why) => println!("rederived the claim does NOT hold: {why}"),
    }
    match &d.report {
        Published::Checked(c) if c.agrees() => println!(
            "report    the published comparison report agrees with the re-derivation on all it \
             was held to: its outcome, set, digests, differences, passes, member counts, every \
             member, and its field edits"
        ),
        Published::Checked(c) => {
            println!("report    the published comparison report does NOT agree:");
            for x in &c.disagreements {
                println!("          {x}");
            }
        }
        Published::Unchecked(why) => println!("report    {why}"),
        Published::Failed(why) => println!("report    FAILED verification: {why}"),
    }
    if let Published::Checked(c) = &d.report
        && !c.unchecked.is_empty()
    {
        println!(
            "          not held to it, so unchecked: {}",
            c.unchecked
                .iter()
                .map(|f| format!("`{f}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn json_of(r: &Report, code: i32) -> Value {
    let logs: Vec<Value> = r
        .logs
        .iter()
        .map(|(origin, size)| json!({ "origin": origin, "size": size }))
        .collect();
    let mut doc = json!({
        "source": r.pinned,
        "logs": logs,
        "newestLeaf": r.newest.map(crate::rfc3339_from_unix),
        "notes": r.notes,
        "record": format!("sha256:{}", r.record.to_hex()),
        "exit": code,
    });
    match &r.verified {
        Err(why) => {
            doc["verified"] = json!(false);
            doc["failure"] = json!({ "kind": why.kind(), "reason": why.to_string() });
        }
        Ok(v) => {
            doc["verified"] = json!(true);
            doc["leaf"] = json!({
                "origin": r.origin,
                "log": v.pos.log,
                "index": v.pos.index,
            });
            let p = &v.statement.predicate;
            doc["subject"] = json!(v.statement.subject);
            doc["purl"] = json!(v.leaf.purl);
            doc["predicateType"] = json!(v.statement.predicate_type);
            doc["claims"] = json!(kind_said(v.kind()));
            // §4.2's fields, as signed, and `null` where the statement does not sign one.
            for (key, value) in [
                ("because", p.get("because")),
                ("stabilizerSet", p.get("stabilizerSet")),
                ("run", p.get("run")),
                ("trigonVersion", p.get("trigonVersion")),
                ("egressTier", p.get("egressTier")),
                ("attestable", p.get("attestable")),
                ("derivation", p.pointer("/derivation/method")),
                ("falsifyingCommand", p.get("falsifyingCommand")),
                ("disputePointer", p.get("disputePointer")),
            ] {
                doc[key] = value.cloned().unwrap_or(Value::Null);
            }
            doc["key"] = json!(v.key.key_id());
            doc["supersedes"] = match v.supersedes() {
                Some((record, reason)) => json!({
                    "record": format!("sha256:{}", record.to_hex()),
                    "reason": reason.as_str(),
                }),
                None => Value::Null,
            };
            doc["supersededBy"] = json!(
                superseded(r, v)
                    .into_iter()
                    .map(|(record, at)| json!({ "record": record, "at": at }))
                    .collect::<Vec<_>>()
            );
            doc["evidence"] = json!(
                v.evidence
                    .iter()
                    .map(|e| json!({
                        "name": e.name,
                        "digest": format!("sha256:{}", e.digest.to_hex()),
                        "state": state_name(&e.state),
                    }))
                    .collect::<Vec<_>>()
            );
            doc["answer"] = match (&r.unknown, &r.lookup) {
                (Some(_), _) => json!("unknown"),
                (None, l) => json!(l.as_ref().map(|l| l.answer(FLOOR).to_string())),
            };
            doc["unknown"] = json!(r.unknown);
        }
    }
    let Some(d) = &r.rerun else {
        doc["rederived"] = Value::Null;
        doc["report"] = Value::Null;
        return doc;
    };
    doc["rederived"] = match &d.claim {
        Ok(claim) => crate::rederived_json(claim),
        Err(why) => json!({ "holds": false, "refuted": why }),
    };
    doc["report"] = match &d.report {
        Published::Checked(c) => json!({
            "agrees": c.agrees(),
            "disagreements": c.disagreements.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
            "unchecked": c.unchecked,
        }),
        Published::Unchecked(why) => json!({ "agrees": Value::Null, "unchecked": why }),
        Published::Failed(why) => json!({ "agrees": false, "failed": why }),
    };
    doc
}

/// The JSON document for a check that stopped before it had a record to report on: the exit code,
/// what stopped it, why, and, for a log that equivocates or does not extend the checkpoint it is
/// held to, both signed notes, which §8 has the client print. What stopped it is named for what it
/// was — the tool, a log, a source, or `--lookup` finding no current record to check, with what the
/// sources say of the artifact instead, which is no failure — and is `failed-verification` only
/// where a record, or a file it names, failed. `docs/using-trigon.md` lists every name.
fn stopped(code: i32, error: &anyhow::Error, cause: Option<Cause>) -> Value {
    let log = error.downcast_ref::<LogError>();
    let stopped = match (code, log, cause) {
        (CANNOT, ..) => "cannot-check",
        (_, Some(LogError::Equivocation { .. }), _) => "equivocation",
        (_, Some(LogError::Inconsistent { .. }), _) => "inconsistent",
        (_, Some(l), _) if l.fails_verification() => "log-failed-verification",
        (_, Some(_), _) => "log-unreadable",
        (_, None, Some(c)) => c.key(),
        (_, None, None) => "failed-verification",
    };
    let notes = match log {
        Some(LogError::Equivocation {
            first_dir,
            first,
            second_dir,
            second,
            ..
        }) => json!([
            { "dir": first_dir, "note": first },
            { "dir": second_dir, "note": second },
        ]),
        Some(LogError::Inconsistent {
            accepted, offered, ..
        }) => json!([
            { "accepted": accepted },
            { "offered": offered },
        ]),
        _ => Value::Null,
    };
    json!({
        "exit": code,
        "stopped": stopped,
        "error": format!("{error:#}"),
        "signedNotes": notes,
    })
}

pub(crate) fn pretty(doc: &Value) -> String {
    // A `Value` is always serializable; nothing here can fail but the allocator.
    serde_json::to_string_pretty(doc).unwrap_or_else(|_| doc.to_string())
}
