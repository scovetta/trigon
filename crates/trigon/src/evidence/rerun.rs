//! `trigon verify-attestation --lookup sha256:<subject> [--predicate <type>] [--origin <origin>]
//! [--rerun-comparison --upstream <file> [--rebuild <file>]]`: the form of every record's falsifying
//! command (`docs/19` §4.2 item 6, §6).
//!
//! **Resolved where the record is logged, and nowhere else.** The current record for the subject
//! is resolved in the synced clone of the source whose chain holds a log of `--origin` — that
//! source alone synced first where it is stale, as every command that answers from a clone does —
//! through the log and every supersession it records. A client with no source of that origin says
//! so and exits 4: the command was signed to be answered there, and an answer from elsewhere would
//! be another source's claim. An origin is only a name, so sources that give it to logs of
//! different keys are not all asked: a source a project's `.trigon/evidence.toml` added is set
//! aside, and said to be, where the user's own sources or the environment's hold the origin under
//! another key (`docs/19` §8: a project's source cannot change what another answers), and where
//! nothing tells them apart the command is refused as ambiguous. Without `--origin`, every source
//! is asked, and records in more than one are refused as ambiguous.
//!
//! **Every source asked is weighed.** Its exit code is the more severe of the record's report and
//! what every source asked says of the artifact, as `lookup` weighs them (`docs/19` §6): a source
//! that is refused, or required and unknown, or says withdrawn, is printed beside the record and
//! counted, never dropped because another source holds a current record.
//!
//! **Its evidence is fetched on demand.** A clone keeps `evidence/` out of its working tree, and
//! out of its objects where it is partial, so each file the record names is read from git's
//! objects, which fetches a blob the clone does not hold from the remote it was cloned from. That
//! names the record to the host, as nothing a clone does otherwise, and it is said when it happens
//! (`docs/19` §7).
//!
//! **The rebuilt artifact** is `--rebuild <file>` where given, and nothing is fetched for it.
//! Otherwise it is looked for by the record and its sources alone: the release asset
//! `sha256-<hex>` of the digest the verdict signs, in the `rebuilt-YYYY-MM` releases of the
//! GitHub repository that holds the record's leaf — the source's own, by any location of it on
//! github.com, or after a succession into another repository that one — for the month the record
//! was logged in and the months either side, where `publish` puts it; then in those of every other
//! source that holds the record, but never one a project's `.trigon/evidence.toml` added where the
//! record was resolved in a source of the user's. Downloaded without a token into a directory made
//! for it that only this user can enter, and held to that digest as it is written. What this host
//! publishes (`[publish] rebuilt_artifacts`) says nothing of what another operator's repository
//! holds, so it plays no part. An exact verdict's rebuilt artifact is the published one, byte for
//! byte, which no repository publishes again: it is the `--upstream` file, held to the digest the
//! verdict signs like any other, and nothing is asked of GitHub, so the signed command runs as
//! written. Where no repository that holds the record is on github.com, where none holds such an
//! asset, or where GitHub cannot be asked, the check is not made, exit 5, and the user is asked for
//! `--rebuild <file>`: another artifact is never guessed at. Then the record is checked and its
//! claim re-derived exactly as the record form does (`crate::verify_record::report`). A void makes
//! no claim to re-derive: it is reported, with its code, and said not to have been.

use std::cell::RefCell;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use serde::Deserialize;
use sha2::Digest as _;
use trigon_attest::config::{AddedBy, Env, EvidenceConfig};
use trigon_attest::evidence::{
    Answer, Key, RECORD_LIMIT, RecordKind, Said, exit_code, first_that_wins, record_path,
};
use trigon_attest::location::{Location, printable};
use trigon_attest::log::{DirFiles, LeafPos, LogError, LogFiles};
use trigon_attest::state::KeysFile;

use super::{Dirs, Mode, Ready, ready};
use crate::OutputFormat;
use crate::publish::git;
use crate::publish::release::on_github;
use crate::verify_record::{self, Cause, Done, Reading, Stop, cannot, failed};

/// The outcome floor `verify-attestation` holds an answer to: it takes no `--min`.
const FLOOR: trigon_core::Match = trigon_core::Match::NormalizedWithCaveats;

/// How many pages of releases, or of one release's assets, are read, as `publish` reads them.
const PAGES: u32 = 100;

/// What `verify-attestation --lookup` is given.
pub(crate) struct Args<'a> {
    pub subject: &'a str,
    pub predicate: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub rerun: bool,
    pub files: crate::Rerun<'a>,
    pub output: OutputFormat,
    pub verbose: bool,
}

/// Resolve, check, re-derive, report, and exit with the code.
pub(crate) fn run(args: Args<'_>) -> anyhow::Result<()> {
    verify_record::finish(check(&args), args.output)
}

fn check(a: &Args<'_>) -> Result<i32, Stop> {
    let key = match Key::parse(a.subject) {
        Ok(
            k @ Key::Digest {
                algorithm: "sha256",
                ..
            },
        ) => k,
        _ => {
            return Err(cannot(anyhow!(
                "--lookup takes the subject's sha256, `sha256:<64 hex digits>`, as a record's \
                 falsifying command names it; `{}` is not one",
                printable(a.subject)
            )));
        }
    };
    verify_record::rerun_files(a.rerun, a.files, false)?;
    let config = Env::from_process()
        .and_then(|env| EvidenceConfig::load(&env))
        .map_err(cannot)?;
    let now = super::now();
    // Only the sources that may hold the origin's log are synced: one of another origin plays no
    // part in the answer, and syncing it would cost a fetch for nothing.
    let asked = match a.origin {
        Some(o) => holding(&config, o),
        None => Vec::new(),
    };
    let all = ready(&config, &asked, Mode::Sync, now, a.verbose).map_err(cannot)?;
    // The sources the command is to be answered in: those whose chain reaches a log of the origin
    // it names, under one key — by the log key each pins, where it could not be opened — or every
    // one.
    let mut aside = Vec::new();
    let named: Vec<&Ready> = match a.origin {
        Some(o) => {
            let claiming: Vec<(&Ready, Vec<String>)> = all
                .iter()
                .filter_map(|r| {
                    let keys = keys_for(&config, r, o);
                    (!keys.is_empty()).then_some((r, keys))
                })
                .collect();
            one_log(claiming, o, &mut aside)?
        }
        None => all.iter().collect(),
    };
    if named.is_empty() {
        return Err(failed(anyhow!(
            "no evidence source configured here has the log `{}`, so the record this command \
             names cannot be resolved: it is resolved in the source that logged it and nowhere \
             else. Add that source — `trigon evidence add <name> <url> --log-key <vkey> \
             --attestation-key <key>` — and run it again{}",
            printable(a.origin.unwrap_or_default()),
            match aside.is_empty() {
                true => String::new(),
                false => format!(" ({})", aside.join("; ")),
            }
        ))
        .because(Cause::NoSource));
    }
    let mut found: Vec<(&Ready, trigon_attest::evidence::Found)> = Vec::new();
    let mut said = Vec::new();
    let mut unanswered = Vec::new();
    for r in &named {
        let answer = r.said(|repo| repo.lookup(&key).answer(FLOOR));
        if !matches!(answer, Said::Answered(_)) {
            unanswered.push(format!(
                "`{}` cannot answer: {}",
                r.source.name,
                super::standing_said(&r.standing)
            ));
        }
        said.push(answer);
        let Some(o) = &r.opened else { continue };
        for f in o.repo.lookup(&key).found {
            let kind = f.verified().map(|v| v.kind());
            let predicate = f.verified().map(|v| v.statement.predicate_type.clone());
            // A record found through two sources of one origin is one record of one log,
            // configured twice — mirrors named as sources of their own — and is checked once.
            if f.is_current()
                && matches!(kind, Some(RecordKind::Verdict(_) | RecordKind::Void))
                && a.predicate.is_none_or(|p| predicate.as_deref() == Some(p))
                && !found.iter().any(|(_, g)| g.leaf.record == f.leaf.record)
            {
                found.push((r, f));
            }
        }
    }
    let sources_with: Vec<&str> = {
        let mut n: Vec<&str> = found.iter().map(|(r, _)| r.source.name.as_str()).collect();
        n.dedup();
        n
    };
    if a.origin.is_none() && sources_with.len() > 1 {
        return Err(cannot(anyhow!(
            "{} each hold a current record for {key}; name the log it was published in with \
             --origin <origin>, as its falsifying command does",
            sources_with
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(" and ")
        )));
    }
    // What every source asked says of the artifact, weighed as `lookup` weighs it.
    let weighed = exit_code(&said, FLOOR, true);
    let answers: Vec<String> = named
        .iter()
        .zip(&said)
        .map(|(r, s)| format!("`{}` says {}", r.source.name, super::lookup::said_word(s)))
        .collect();
    if found.is_empty() {
        // Nothing current to check: what the source says instead, and its code. A 4 is a record
        // that was deleted or failed verification, where a source answers so, and otherwise a
        // source that was refused or cannot answer, which is never called a record that failed.
        let withdrawn = said.contains(&Said::Answered(Answer::Withdrawn));
        let record_failed = said
            .iter()
            .any(|s| matches!(s, Said::Answered(answer) if answer.exit_code(FLOOR) == 4));
        let why = match (a.predicate, withdrawn) {
            (_, true) => {
                "its only current record is a withdrawal, so there is no verdict to re-derive"
            }
            (Some(_), false) => "no current record of that predicate is logged for it",
            (None, false) => "no current verdict or void is logged for it",
        };
        return Err(Stop {
            code: i32::from(weighed),
            error: anyhow!(
                "{key}: {why}. {}",
                answers
                    .iter()
                    .chain(&unanswered)
                    .chain(&aside)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            cause: match (weighed, record_failed, said.contains(&Said::Refused)) {
                // `failed-verification`, which is a record's.
                (4, true, _) => None,
                (4, false, true) => Some(Cause::SourceRefused),
                (4, false, false) => Some(Cause::SourceUnknown),
                _ => Some(Cause::NoCurrentRecord),
            },
        });
    }

    let mut done: Vec<Done> = Vec::new();
    for (r, f) in &found {
        let opened = r.opened.as_ref().expect("a record was found in it");
        let root = opened.repo.root_of(f.pos).to_path_buf();
        let v = f.verified().expect("a current record is verified");
        let bytes = DirFiles::new(&root)
            .read(&record_path(&f.leaf.record), RECORD_LIMIT)
            .map_err(|e| failed(anyhow::Error::new(e)))?
            .ok_or_else(|| failed(anyhow!("the record verified a moment ago is gone")))?;
        let mut notes = vec![format!(
            "resolved as the current record of {key}{} in `{}`, through its log and every \
             supersession it records",
            a.predicate
                .map(|p| format!(" under `{p}`"))
                .unwrap_or_default(),
            r.source.name
        )];
        notes.extend(r.notes.iter().cloned());
        // Every other source asked, and what it says: one answer is never shown as the only one.
        if named.len() > 1 {
            notes.extend(answers.iter().cloned());
        }
        notes.extend(unanswered.iter().cloned());
        notes.extend(aside.iter().cloned());
        let void = v.kind() == RecordKind::Void;
        // The rebuilt artifact where none is given: an exact verdict's is the upstream file, and
        // any other's is its release asset, removed when this record's report is done.
        let mut rebuild = a.files.rebuild;
        let mut asset = None;
        if a.rerun && rebuild.is_none() && !void {
            let subject = f.leaf.subject.get("sha256").map(String::as_str);
            match wanted(v.kind(), &v.statement.predicate, subject)? {
                Wanted::Upstream(why) => {
                    rebuild = a.files.upstream;
                    notes.push(format!(
                        "the rebuilt artifact is the upstream file given: {why}, so it is the \
                         published artifact itself, byte for byte, which no evidence repository \
                         publishes again as a release asset (docs/19 §4.1). It is held to the \
                         rebuilt artifact's digest the verdict signs, as any rebuilt artifact is, \
                         and nothing was asked of GitHub"
                    ));
                }
                Wanted::Asset(digest) => asset = Some(rebuilt_asset(r, &named, f, &digest)?),
            }
        }
        let files = crate::Rerun {
            upstream: a.files.upstream,
            rebuild: asset.as_ref().map(|d| d.path.as_path()).or(rebuild),
            stabilizers: a.files.stabilizers,
        };
        notes.extend(asset.as_ref().map(|d| d.said.clone()));
        if a.rerun && void {
            notes.push(
                "not re-derived: a void makes no comparison claim, so there is nothing to re-derive, \
                 and it answers as the void it is"
                    .into(),
            );
        }
        let evidence = GitFiles::new(&root);
        let reading = Reading {
            pinned: r.label(),
            repo: &opened.repo,
            notes,
            unknown: (!r.standing.answers()).then(|| super::standing_said(&r.standing)),
        };
        let mut d = verify_record::report(
            &reading,
            &bytes,
            Some(&evidence),
            (a.rerun && !void).then_some(files),
        )?;
        if let Some(n) = evidence.said() {
            d.note(n);
        }
        done.push(d);
    }
    let code = first_that_wins(
        std::iter::once(weighed).chain(done.iter().map(|d| u8::try_from(d.code).unwrap_or(5))),
    );
    // One record's report carries the command's code, which every source asked may have made more
    // severe than the record's own.
    if let [d] = done.as_mut_slice()
        && i32::from(code) != d.code
    {
        d.note(format!(
            "exit {code}, not this record's {}: what every source asked says of the artifact is \
             weighed too ({})",
            d.code,
            answers
                .iter()
                .chain(&unanswered)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
        d.code = i32::from(code);
    }
    match (a.output, done.len()) {
        (OutputFormat::Json, 1) => verify_record::print(&done[0], a.output),
        (OutputFormat::Json, _) => println!(
            "{}",
            verify_record::pretty(&serde_json::json!(
                done.iter().map(verify_record::json).collect::<Vec<_>>()
            ))
        ),
        (OutputFormat::Text, n) => {
            for (i, d) in done.iter().enumerate() {
                if n > 1 {
                    if i > 0 {
                        println!();
                    }
                    println!(
                        "current   record {} of {n}: the source holds more than one current record \
                         for this artifact, so each is shown, and the more severe decides",
                        i + 1
                    );
                }
                verify_record::print(d, a.output);
            }
        }
    }
    Ok(i32::from(code))
}

/// The sources that may hold the log `origin` names, by name: those whose pinned log key has that
/// name, or whose chain as last synced reached a log of it. Empty where none is known to — a
/// source never synced, or one whose chain has gone on since — which asks every source.
fn holding(config: &EvidenceConfig, origin: &str) -> Vec<String> {
    config
        .sources()
        .iter()
        .filter(|s| {
            s.log_key.as_ref().is_some_and(|k| k.origin() == origin)
                || Dirs::of(config, &s.name)
                    .ok()
                    .and_then(|d| KeysFile::read(&d.state).ok().flatten())
                    .is_some_and(|k| k.logs.iter().any(|l| l.origin == origin))
        })
        .map(|s| s.name.clone())
        .collect()
}

/// Each log key under which `r` holds a log named `origin`: the key it pins, where that is the
/// name; each log of its chain of that name, where it could be opened; and where it could not, the
/// chain its last sync recorded.
fn keys_for(config: &EvidenceConfig, r: &Ready, origin: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    if let Some(k) = r.source.log_key.as_ref().filter(|k| k.origin() == origin) {
        keys.push(k.to_string());
    }
    match &r.opened {
        Some(o) => keys.extend(
            o.repo
                .logs()
                .iter()
                .filter(|l| l.origin() == origin)
                .map(|l| l.vkey().to_string()),
        ),
        None => keys.extend(
            Dirs::of(config, &r.source.name)
                .ok()
                .and_then(|d| KeysFile::read(&d.state).ok().flatten())
                .map_or_else(Vec::new, |k| k.logs)
                .into_iter()
                .filter(|l| l.origin == origin)
                .map(|l| l.log_key),
        ),
    }
    keys.sort();
    keys.dedup();
    keys
}

/// Of the sources that have a log named `origin`, those that hold the one log it names. An origin
/// is only the name in a log key, and any source can give its own key that name: where the sources
/// give it to one key, all of them; where they do not, those the user's own configuration or the
/// environment added, when they agree on one key, with every source a project's
/// `.trigon/evidence.toml` added under another set aside and said to be in `aside` — a project's
/// source adds a claim, and cannot change what another source answers (`docs/19` §8) — and
/// otherwise nothing tells which log the command was signed in, and it is refused as ambiguous.
fn one_log<'r>(
    claiming: Vec<(&'r Ready, Vec<String>)>,
    origin: &str,
    aside: &mut Vec<String>,
) -> Result<Vec<&'r Ready>, Stop> {
    let mut keys: Vec<&String> = claiming.iter().flat_map(|(_, k)| k).collect();
    keys.sort();
    keys.dedup();
    if keys.len() <= 1 {
        return Ok(claiming.into_iter().map(|(r, _)| r).collect());
    }
    let project = |r: &Ready| matches!(r.source.added_by, AddedBy::ProjectFile(_));
    let mut trusted: Vec<&String> = claiming
        .iter()
        .filter(|(r, _)| !project(r))
        .flat_map(|(_, k)| k)
        .collect();
    trusted.sort();
    trusted.dedup();
    if let [key] = trusted.as_slice() {
        let key = (*key).clone();
        let holders = claiming
            .iter()
            .filter(|(_, k)| k.contains(&key))
            .map(|(r, _)| format!("`{}`", r.source.name))
            .collect::<Vec<_>>()
            .join(" and ");
        let mut out = Vec::new();
        for (r, k) in claiming {
            match k.contains(&key) {
                true => out.push(r),
                false => aside.push(format!(
                    "`{}`, {}, has a log named `{origin}` under another key, {}, and is not \
                     asked: the log of that name is {holders}'s, under {key}, and a project's \
                     source cannot answer for another source's log (docs/19 §8)",
                    r.source.name,
                    super::added_by(&r.source.added_by),
                    k.join(", ")
                )),
            }
        }
        return Ok(out);
    }
    Err(cannot(anyhow!(
        "{} each have a log named `{origin}`, under different log keys: {}. An origin names one \
         log, and which of them this command was signed in cannot be told here; remove the \
         source you do not trust, and run it again",
        claiming
            .iter()
            .map(|(r, _)| format!("`{}`", r.source.name))
            .collect::<Vec<_>>()
            .join(" and "),
        claiming
            .iter()
            .map(|(r, k)| format!("`{}` under {}", r.source.name, k.join(", ")))
            .collect::<Vec<_>>()
            .join("; ")
    )))
}

/// A partial clone's files: the working tree where a file is checked out, and git's objects where
/// it is not — `evidence/`, which a clone keeps out of its working tree — fetching a blob the clone
/// does not hold from the remote it was cloned from.
struct GitFiles {
    root: PathBuf,
    tree: DirFiles,
    /// Each path read that had to be fetched.
    fetched: RefCell<Vec<String>>,
}

impl GitFiles {
    fn new(root: &Path) -> GitFiles {
        GitFiles {
            root: root.to_path_buf(),
            tree: DirFiles::new(root),
            fetched: RefCell::new(Vec::new()),
        }
    }

    /// What fetching named to the host, where anything was fetched.
    fn said(&self) -> Option<String> {
        let f = self.fetched.borrow();
        (!f.is_empty()).then(|| {
            let url = git::text(Some(&self.root), &["config", "--get", "remote.origin.url"])
                .map(|u| git::scrub(&u))
                .unwrap_or_else(|_| "its remote".into());
            format!(
                "fetched {} evidence file(s) the record names from {url}, which names the record \
                 to that host, as nothing a clone does otherwise (docs/19 §7): {}",
                f.len(),
                f.join(", ")
            )
        })
    }
}

impl LogFiles for GitFiles {
    fn read(&self, path: &str, limit: u64) -> Result<Option<Vec<u8>>, LogError> {
        if let Some(b) = self.tree.read(path, limit)? {
            return Ok(Some(b));
        }
        let io = |e: anyhow::Error| LogError::Io {
            path: path.to_string(),
            source: std::io::Error::other(format!("{e:#}")),
        };
        // Only a clone a sync accepted is run in: one whose `.git` leads elsewhere is not asked.
        if !git::is_clone_at(&self.root) {
            return Ok(None);
        }
        let rev = vec![format!("HEAD:{path}")];
        if !git::blobs_held(&self.root, &rev).map_err(io)?[0] {
            self.fetched.borrow_mut().push(path.to_string());
        }
        let blob = git::blobs_fetching(&self.root, &rev)
            .map_err(io)?
            .pop()
            .flatten();
        match blob {
            Some(b) if b.len() as u64 > limit => Err(LogError::Malformed(format!(
                "`{path}` is {} bytes, and no file at that path can be more than {limit}",
                b.len()
            ))),
            other => Ok(other),
        }
    }

    fn shown(&self, path: &str) -> String {
        format!("{}:HEAD:{path}", self.root.display())
    }
}

/// A rebuilt artifact downloaded from a release asset, in a directory of its own that only this
/// user can enter, removed with it when dropped.
struct Download {
    dir: PathBuf,
    path: PathBuf,
    said: String,
}

impl Drop for Download {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Download {
    /// A new directory for one download, made here and nowhere a path already was: made `0700`,
    /// by `mkdir`, which follows no link and fails where anything is in the way, so no other user
    /// of the machine can put a link where the asset is written, or change it between its digest
    /// being checked and its bytes being read. Its name is 128 random bits, so no other user can
    /// know it beforehand to take it first either.
    fn new(digest: &trigon_core::Digest) -> anyhow::Result<Download> {
        let tmp = std::env::temp_dir();
        for _ in 0..16u32 {
            let mut random = [0u8; 16];
            crate::getrandom(&mut random)?;
            let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let dir = tmp.join(format!("trigon-rebuilt-{name}"));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&dir) {
                Ok(()) => {
                    return Ok(Download {
                        path: dir.join(format!("sha256-{}", digest.to_hex())),
                        dir,
                        said: String::new(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(anyhow!(
                        "making a directory for the rebuilt artifact in {}: {e}",
                        tmp.display()
                    ));
                }
            }
        }
        Err(anyhow!(
            "no new directory could be made for the rebuilt artifact in {}",
            tmp.display()
        ))
    }
}

#[derive(Deserialize)]
struct Release {
    id: u64,
    tag_name: String,
    #[serde(default)]
    draft: bool,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    /// `uploaded` once its upload finished. One begun and never finished stays under its name
    /// until it is removed, and is nothing to download.
    #[serde(default)]
    state: String,
    browser_download_url: String,
}

/// A release asset found and downloaded: the release it is in, its size, and the sha256 of the
/// bytes written.
struct Fetched {
    release: String,
    size: u64,
    digest: trigon_core::Digest,
}

/// A GitHub repository the rebuilt artifact is looked for in, and the source that names it: `own`
/// where that is the source the record was resolved in.
struct Candidate {
    repository: String,
    source: String,
    own: bool,
}

/// What the user is asked for wherever the rebuilt artifact cannot be had from a release asset.
const GIVE_REBUILD: &str = "give it with --rebuild <file>, the output of re-running the build \
                            under the record's published strategy";

/// What asking for the asset by name told GitHub, which is said whatever came of it.
const NAMED_TO_GITHUB: &str = "the artifact, and so the record, to GitHub (docs/19 §7)";

/// The rebuilt artifact a verdict names, for `--rerun-comparison` without `--rebuild`: the release
/// asset `sha256-<hex>`, in a `rebuilt-YYYY-MM` release of a GitHub repository that holds the
/// record's leaf, held to the digest the verdict signs. `r` is the source the record `f` was
/// resolved in, and `named` every source asked. Found by the record and its sources alone, never
/// by this host's own `[publish] rebuilt_artifacts`, which says what this host publishes and
/// nothing of another operator's repository.
///
/// `r`'s own repository is asked first, and then that of every other source that holds the
/// record, so that a mirror with no releases hides nothing; [`candidates`] says which. `digest` is
/// the one the verdict signs, as [`wanted`] read it. A record no repository of which is on
/// github.com — asked nothing — and one that no repository asked holds such an asset for, or that
/// GitHub cannot be asked about, are a check not made, exit 5, and the user is asked for `--rebuild
/// <file>`: no other artifact is guessed at. An asset of the name that is other bytes is the
/// evidence failing, exit 4, since an asset is named by its digest, where it is in `r`'s own
/// repository; in another source's it is that repository's, not the record's, and the next is
/// asked.
fn rebuilt_asset(
    r: &Ready,
    named: &[&Ready],
    f: &trigon_attest::evidence::Found,
    digest: &trigon_core::Digest,
) -> Result<Download, Stop> {
    let digest = *digest;
    let (candidates, considered, aside) = candidates(r, named, &f.leaf.record);
    let aside = match aside.is_empty() {
        true => String::new(),
        false => format!(" ({})", aside.join("; ")),
    };
    if candidates.is_empty() {
        return Err(cannot(anyhow!(
            "--rerun-comparison needs the rebuilt artifact, and no repository that holds the \
             record, in {}, is on github.com, so none has releases to look for it in, and \
             nothing was asked of GitHub{aside}; {GIVE_REBUILD}",
            considered.join(" and ")
        )));
    }
    let name = format!("sha256-{}", digest.to_hex());
    let logged = crate::publish::release::month_of(f.leaf.time);
    let months = months_around(&logged);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(cannot)?;
    let mut download = Download::new(&digest).map_err(cannot)?;
    // Whether a download was asked for: that names the artifact to GitHub, which is said whether
    // or not it was had.
    let mut asked = false;
    let mut before: Vec<String> = Vec::new();
    let mut unreachable = false;
    for c in &candidates {
        // Hashed as it is written, so the digest held to is that of the bytes that were written,
        // and nothing reads the file between the two.
        let fetched = rt.block_on(fetch_asset(
            &c.repository,
            &name,
            &months,
            &download.path,
            &mut asked,
        ));
        let whose = match c.own {
            true => String::new(),
            false => format!(" (`{}`'s, which holds the record too)", c.source),
        };
        match fetched {
            Err(e) => {
                unreachable = true;
                before.push(format!("{}{whose} did not give it: {e:#}", c.repository));
            }
            Ok(None) => before.push(format!(
                "no `rebuilt-YYYY-MM` release of {}{whose} holds an asset named {name}",
                c.repository
            )),
            Ok(Some(got)) if got.digest == digest => {
                download.said = format!(
                    "the rebuilt artifact is the release asset {name} of {}{whose}, in release {}, \
                     {} bytes, downloaded without a token and held to the digest the verdict \
                     signs; asking GitHub for it names {NAMED_TO_GITHUB}{}",
                    c.repository,
                    printable(&got.release),
                    got.size,
                    match before.is_empty() {
                        true => String::new(),
                        false => format!(". Before it, {}", before.join("; ")),
                    }
                );
                return Ok(download);
            }
            Ok(Some(got)) if c.own => {
                return Err(failed(anyhow!(
                    "the release asset {name} of {}, in release {}, is not the rebuilt artifact \
                     the verdict signs: its sha256 is {}, and an asset is named by the digest of \
                     what it holds. Asking GitHub for it named {NAMED_TO_GITHUB}",
                    c.repository,
                    printable(&got.release),
                    got.digest.to_hex()
                )));
            }
            // Another source's repository, which the record was not resolved in: what it holds
            // under the name is its own, and says nothing of the record's evidence.
            Ok(Some(got)) => before.push(format!(
                "the release asset {name} of {}{whose}, in release {}, is other bytes, sha256 {}, \
                 which are that repository's and not the record's, resolved in `{}`",
                c.repository,
                printable(&got.release),
                got.digest.to_hex(),
                r.source.name
            )),
        }
    }
    Err(cannot(anyhow!(
        "--rerun-comparison needs the rebuilt artifact, and it could not be had: {}{aside}. It is \
         looked for in the series of {} to {}, where `publish` puts the rebuilt artifact of a \
         record logged in {logged}, and no other artifact is guessed at; {}{GIVE_REBUILD}{}",
        before.join("; "),
        months[1],
        months[2],
        match unreachable {
            true => "run it again later, or ",
            false => "",
        },
        match asked {
            true => format!(". Asking GitHub for it by name named {NAMED_TO_GITHUB}"),
            false => String::new(),
        }
    )))
}

/// Where the rebuilt artifact of a verdict is had from when `--rebuild` is not given.
#[derive(Debug, PartialEq)]
enum Wanted {
    /// The `--upstream` file, and why it is the rebuilt artifact.
    Upstream(&'static str),
    /// The release asset named by this digest, the one the verdict signs.
    Asset(trigon_core::Digest),
}

/// Where a verdict of `kind` has its rebuilt artifact from, by what `predicate` signs of it, when
/// `--rebuild` is not given. An exact verdict's rebuilt artifact is the published artifact itself,
/// byte for byte — the sha256 it signs for it is the subject's, `subject`, and a verdict that signs
/// the subject's is one too — which `publish` never uploads (`docs/19` §4.1): it is the
/// `--upstream` file, which re-deriving holds to the rebuilt artifact's digest the verdict signs as
/// it holds any rebuilt artifact, so the same signed command works either way (§4.2 item 6), and
/// nothing is asked of GitHub, which would spend the anonymous rate limit, and name the record, for
/// an asset that cannot be there. Any other verdict's is the release asset named by the digest it
/// signs; one that signs none has nothing to find an asset by, and is the check not made, exit 5,
/// with nothing asked of GitHub.
fn wanted(
    kind: RecordKind,
    predicate: &serde_json::Value,
    subject: Option<&str>,
) -> Result<Wanted, Stop> {
    if kind == RecordKind::Verdict(trigon_core::Match::Exact) {
        return Ok(Wanted::Upstream("this verdict is exact"));
    }
    let digest = predicate
        .pointer("/artifacts/rebuild/sha256")
        .and_then(|h| h.as_str())
        .and_then(|h| trigon_core::Digest::from_hex(h).ok())
        .ok_or_else(|| {
            cannot(anyhow!(
                "--rerun-comparison needs the rebuilt artifact, and the verdict signs no rebuilt \
                 artifact's sha256 to find a release asset by, so none is looked for, and nothing \
                 was asked of GitHub; {GIVE_REBUILD}"
            ))
        })?;
    if subject.is_some_and(|s| s == digest.to_hex()) {
        return Ok(Wanted::Upstream(
            "the sha256 this verdict signs for its rebuilt artifact is the subject's",
        ));
    }
    Ok(Wanted::Asset(digest))
}

/// The GitHub repositories the rebuilt artifact of `record` is looked for in, `r`'s own first and
/// then those of every other source in `named` that holds the record; each source whose
/// repositories were, by name; and what was set aside, and why.
///
/// A source a project's `.trigon/evidence.toml` added is set aside where `r` is a source of the
/// user's or the environment's: it is input chosen by the thing under test (`docs/19` §8), and
/// asked, it would choose the repository a genuine verdict's rebuilt artifact is fetched from, and
/// could hold it to other bytes, or have GitHub asked where the record's own repository is not on
/// github.com. Where `r` is itself a project's source, no source of the user's or the
/// environment's holds the record, which is the project's own claim, and each that holds it is
/// asked.
fn candidates(
    r: &Ready,
    named: &[&Ready],
    record: &trigon_core::Digest,
) -> (Vec<Candidate>, Vec<String>, Vec<String>) {
    let project = |s: &Ready| matches!(s.source.added_by, AddedBy::ProjectFile(_));
    let mut out: Vec<Candidate> = Vec::new();
    let mut considered = Vec::new();
    let mut aside = Vec::new();
    let others = named.iter().copied().filter(|n| !std::ptr::eq(*n, r));
    for n in std::iter::once(r).chain(others) {
        let Some(pos) = n.opened.as_ref().and_then(|o| {
            o.repo
                .record_leaves()
                .find(|(_, l)| l.record == *record)
                .map(|(pos, _)| pos)
        }) else {
            continue;
        };
        let own = std::ptr::eq(n, r);
        let repositories = github_repositories_of(n, pos);
        if !own && project(n) && !project(r) {
            if !repositories.is_empty() {
                aside.push(format!(
                    "`{}`, {}, holds the record too, and {} was not asked: a project's source \
                     cannot change what another source's record is held to (docs/19 §8)",
                    n.source.name,
                    super::added_by(&n.source.added_by),
                    repositories.join(" and ")
                ));
            }
            continue;
        }
        considered.push(format!("`{}`", n.source.name));
        for repository in repositories {
            if !out.iter().any(|c| c.repository == repository) {
                out.push(Candidate {
                    repository,
                    source: n.source.name.clone(),
                    own,
                });
            }
        }
    }
    (out, considered, aside)
}

/// Each `owner/repo` on GitHub of the repository that holds leaf `pos` of `r`'s chain: the
/// source's own locations on github.com for the repository its chain starts in, and for one its
/// chain went on in, those of the locations the log-end that led there names — which is where a
/// successor's publisher uploads its release assets. HTTPS and SSH alike, as `publish` takes them:
/// the API is asked over HTTPS whatever git reaches the repository by, and the location only names
/// it.
fn github_repositories_of(r: &Ready, pos: LeafPos) -> Vec<String> {
    let Some(o) = r.opened.as_ref() else {
        return Vec::new();
    };
    let logs = &o.repo.source().logs;
    let elsewhere = logs[..pos.log.min(logs.len())].iter().rev().find_map(|c| {
        c.log
            .log_end()
            .map(|e| &e.successor)
            .filter(|s| !s.in_this_repository())
    });
    let found: Vec<String> = match elsewhere {
        None => r.source.urls.iter().filter_map(on_github).collect(),
        Some(s) => s
            .urls
            .iter()
            .filter_map(|u| Location::parse(u, Path::new("/"), None).ok())
            .filter_map(|l| on_github(&l))
            .collect(),
    };
    let mut out: Vec<String> = Vec::new();
    for f in found {
        if !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

/// The months whose series `publish` may have put the rebuilt artifact of a record logged in
/// `month` in: that month, where it is uploaded; the month before, whose series `publish` reads
/// too and reuses an asset of the name from; and the month after, where the publication's time,
/// read after its leaves', had crossed into it. In the order they are asked.
fn months_around(month: &str) -> [String; 3] {
    use crate::publish::release::{next_month, previous_month};
    [month.to_string(), previous_month(month), next_month(month)]
}

/// Find the asset `name` in the `rebuilt-YYYY-MM` releases of `repository` for `months` — the
/// series `publish` uploads to, and no other release, whose assets are nothing a record names —
/// and download it to `to`. `None` where no release of them holds a finished asset of the name;
/// an error where GitHub could not be asked, or where every release that holds one failed to give
/// it. `asked` is set once a download is asked for, which names the asset to GitHub. Anonymous,
/// since the repository is public and nothing is written; the API is GitHub's, or the one
/// `TRIGON_GITHUB_API` names, and a download or a redirect is followed only to HTTPS, or where
/// that API is on this machine, to this machine.
///
/// Only those months' releases are listed, never the whole series: every request counts against
/// GitHub's sixty an hour for a client with no token, and a release holds up to ten pages of
/// assets, so a search through every release of a repository that has published for a while
/// would run out of them before it reached an older record's.
async fn fetch_asset(
    repository: &str,
    name: &str,
    months: &[String],
    to: &Path,
    asked: &mut bool,
) -> anyhow::Result<Option<Fetched>> {
    let api = crate::publish::release::api_base()?;
    let loopback = api.scheme() == "http";
    let client = reqwest::Client::builder()
        .user_agent(trigon_politeness::user_agent())
        .redirect(reqwest::redirect::Policy::custom(move |a| {
            if a.previous().len() > 5 {
                a.error("too many redirects")
            } else if a.url().scheme() == "https" || (loopback && on_loopback(a.url())) {
                a.follow()
            } else {
                a.stop()
            }
        }))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()?;
    let get = |url: String| {
        client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .timeout(std::time::Duration::from_secs(60))
            .send()
    };
    let base = api.as_str().trim_end_matches('/').to_string();
    // The releases of those months' series, by the order of `months` and then by number.
    let mut series: Vec<(usize, u32, Release)> = Vec::new();
    for page in 1..=PAGES {
        let url = format!("{base}/repos/{repository}/releases?per_page=100&page={page}");
        let resp = get(url.clone())
            .await
            .map_err(|e| anyhow!("{url}: {}", shown(e)))?;
        if !resp.status().is_success() {
            bail!(
                "listing the releases of {repository}: GitHub answered {}",
                resp.status()
            );
        }
        let releases: Vec<Release> = resp.json().await?;
        let last = releases.len() < 100;
        for rel in releases {
            if let Some((month, n)) = crate::publish::release::series_of(&rel.tag_name)
                && !rel.draft
                && let Some(i) = months.iter().position(|m| *m == month)
            {
                series.push((i, n, rel));
            }
        }
        if last {
            break;
        }
    }
    series.sort_by_key(|(i, n, _)| (*i, *n));
    let mut failures: Vec<String> = Vec::new();
    for (_, _, rel) in &series {
        for apage in 1..=PAGES {
            let url = format!(
                "{base}/repos/{repository}/releases/{}/assets?per_page=100&page={apage}",
                rel.id
            );
            let resp = get(url.clone())
                .await
                .map_err(|e| anyhow!("{url}: {}", shown(e)))?;
            if !resp.status().is_success() {
                bail!(
                    "listing the assets of release {}: GitHub answered {}",
                    printable(&rel.tag_name),
                    resp.status()
                );
            }
            let assets: Vec<Asset> = resp.json().await?;
            // A finished upload only: one left unfinished may sit under the name in one release
            // while another of the series holds the finished copy.
            if let Some(asset) = assets
                .iter()
                .find(|x| x.name == name && x.state == "uploaded")
            {
                match download(&client, asset, to, loopback, asked).await {
                    Ok((size, digest)) => {
                        return Ok(Some(Fetched {
                            release: rel.tag_name.clone(),
                            size,
                            digest,
                        }));
                    }
                    // Another release of the series may hold it too, and give it.
                    Err(e) => {
                        failures.push(format!(
                            "downloading it from release {}: {e:#}",
                            printable(&rel.tag_name)
                        ));
                        break;
                    }
                }
            }
            if assets.len() < 100 {
                break;
            }
        }
    }
    match failures.is_empty() {
        true => Ok(None),
        false => Err(anyhow!("{}", failures.join("; "))),
    }
}

/// Download `asset` to `to`, streaming, refusing more than GitHub's limit on one asset: its size,
/// and the sha256 of what was written, hashed as it was. `asked` is set as the request is sent.
/// Whatever an earlier attempt left at `to`, in the directory made for this download alone, is
/// removed first, and the file is then made where nothing is.
async fn download(
    client: &reqwest::Client,
    asset: &Asset,
    to: &Path,
    loopback: bool,
    asked: &mut bool,
) -> anyhow::Result<(u64, trigon_core::Digest)> {
    let url = reqwest::Url::parse(&asset.browser_download_url)
        .map_err(|e| anyhow!("its download URL is not one ({e})"))?;
    if url.scheme() != "https" && !(loopback && on_loopback(&url)) {
        bail!(
            "its download URL, {}, is not https://",
            printable(url.as_str())
        );
    }
    if asset.size >= crate::publish::release::ASSET_LIMIT {
        bail!(
            "it is {} bytes, past GitHub's limit on one asset",
            asset.size
        );
    }
    *asked = true;
    let mut resp = client
        .get(url.clone())
        .timeout(std::time::Duration::from_secs(3600))
        .send()
        .await
        .map_err(|e| anyhow!("{url}: {}", shown(e)))?;
    if !resp.status().is_success() {
        bail!("{url} answered {}", resp.status());
    }
    match std::fs::remove_file(to) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => bail!("removing {}, left by an earlier attempt: {e}", to.display()),
    }
    let mut file = new_file(to)?;
    let mut h = sha2::Sha256::new();
    let mut written: u64 = 0;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| anyhow!("{url}: {}", shown(e)))?
    {
        written += chunk.len() as u64;
        if written >= crate::publish::release::ASSET_LIMIT {
            bail!("it is longer than GitHub's limit on one asset");
        }
        h.update(&chunk);
        file.write_all(&chunk)?;
    }
    file.flush()?;
    Ok((
        written,
        trigon_core::Digest::from_bytes(h.finalize().into()),
    ))
}

/// Whether `url` is plain HTTP to this machine: followed only where `TRIGON_GITHUB_API` names a
/// server on this machine itself, as the tests' own is, and nowhere else over plain text.
fn on_loopback(url: &reqwest::Url) -> bool {
    url.scheme() == "http"
        && url.host_str().is_some_and(|h| {
            matches!(h, "localhost" | "[::1]")
                || h.parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
}

/// A file at `to` that nothing was at: made `0600`, and never opened through a link or over a
/// file already there.
fn new_file(to: &Path) -> anyhow::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(to)
        .with_context(|| format!("creating {}", to.display()))
}

fn shown(e: reqwest::Error) -> String {
    printable(&e.without_url().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rebuilt artifact is downloaded into a directory of its own, made for it, that only this
    /// user can enter, and into a file nothing was at: at a predictable path in the shared
    /// temporary directory, another user could put a link there to have it written through, or a
    /// file of theirs to change between its digest being checked and its bytes being read, or
    /// take the name first.
    #[test]
    fn a_download_is_made_where_no_other_user_can_reach_it() {
        let digest = trigon_core::Digest::from_bytes([7; 32]);
        let a = Download::new(&digest).unwrap();
        let b = Download::new(&digest).unwrap();
        assert_ne!(a.dir, b.dir, "each download has a directory of its own");
        assert_eq!(a.path.parent(), Some(a.dir.as_path()));
        assert_eq!(a.dir.parent(), Some(std::env::temp_dir().as_path()));
        // Named by 128 random bits, and nothing a process id or a clock would let another user
        // work out beforehand.
        for d in [&a.dir, &b.dir] {
            let name = d.file_name().unwrap().to_str().unwrap();
            let random = name.strip_prefix("trigon-rebuilt-").unwrap();
            assert_eq!(random.len(), 32, "{name}");
            assert!(random.bytes().all(|c| c.is_ascii_hexdigit()), "{name}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&a.dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        // Whatever is already where the file goes is never written through or over.
        let victim = b.dir.join("victim");
        std::fs::write(&victim, b"theirs").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&victim, &b.path).unwrap();
            assert!(new_file(&b.path).is_err());
            std::fs::remove_file(&b.path).unwrap();
        }
        std::fs::write(&b.path, b"theirs").unwrap();
        assert!(new_file(&b.path).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"theirs");
        let fresh = new_file(&a.path);
        assert!(fresh.is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&a.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Dropped, the directory goes with what was downloaded into it.
        let dir = a.dir.clone();
        drop(fresh);
        drop(a);
        assert!(!dir.exists());
    }

    /// An exact verdict's rebuilt artifact is the upstream file, by its outcome or by the digest it
    /// signs for its rebuilt artifact being the subject's, whatever else it signs: its falsifying
    /// command runs as signed, with `--upstream` alone, and nothing is asked of GitHub. Any other
    /// verdict names its asset by the digest it signs; where it signs none, nothing is asked of
    /// GitHub and the check is not made, exit 5, with the rebuilt artifact asked for — never exit
    /// 4, which would blame the evidence.
    #[test]
    fn an_exact_verdicts_rebuilt_artifact_is_the_upstream_file_and_any_others_its_signed_asset() {
        use trigon_core::Match;
        let rebuilt = "ab".repeat(32);
        let subject = "cd".repeat(32);
        let signing = serde_json::json!({"artifacts": {"rebuild": {"sha256": rebuilt}}});
        for kind in [Match::Normalized, Match::NormalizedWithCaveats, Match::Divergent] {
            let w = wanted(RecordKind::Verdict(kind), &signing, Some(&subject))
                .unwrap_or_else(|s| panic!("{kind:?}: {:#}", s.error));
            assert_eq!(
                w,
                Wanted::Asset(trigon_core::Digest::from_hex(&rebuilt).unwrap()),
                "{kind:?}"
            );
        }
        let upstream = [
            // Exact by its outcome, whatever it signs of the rebuilt artifact: re-deriving holds
            // the upstream file to that digest, as it holds any rebuilt artifact.
            (Match::Exact, signing.clone(), "this verdict is exact"),
            (Match::Exact, serde_json::json!({}), "this verdict is exact"),
            // Exact by its digest: the rebuilt artifact it signs is the subject's bytes.
            (
                Match::Normalized,
                serde_json::json!({"artifacts": {"rebuild": {"sha256": subject}}}),
                "is the subject's",
            ),
        ];
        for (kind, predicate, why) in upstream {
            match wanted(RecordKind::Verdict(kind), &predicate, Some(&subject)) {
                Ok(Wanted::Upstream(said)) => assert!(said.contains(why), "{kind:?}: {said}"),
                Ok(other) => panic!("{kind:?} {predicate}: {other:?}"),
                Err(s) => panic!("{kind:?} {predicate}: {:#}", s.error),
            }
        }
        // Without the subject's digest to compare, a signed digest is the asset's name.
        assert_eq!(
            wanted(RecordKind::Verdict(Match::Normalized), &signing, None).ok(),
            Some(Wanted::Asset(trigon_core::Digest::from_hex(&rebuilt).unwrap()))
        );
        let refused = [
            serde_json::json!({"artifacts": {"upstream": {"sha256": subject}}}),
            serde_json::json!({"artifacts": {"rebuild": {"sha256": "not hex"}}}),
            serde_json::json!({"artifacts": {"rebuild": {"sha256": 7}}}),
        ];
        for predicate in refused {
            let normalized = RecordKind::Verdict(Match::Normalized);
            let Err(stop) = wanted(normalized, &predicate, Some(&subject)) else {
                panic!("{predicate}: an asset was looked for");
            };
            let e = format!("{:#}", stop.error);
            assert_eq!(stop.code, 5, "{e}");
            assert!(e.contains("signs no rebuilt artifact's sha256"), "{e}");
            assert!(e.contains("nothing was asked of GitHub"), "{e}");
            assert!(e.contains(GIVE_REBUILD), "{e}");
        }
    }

    /// Plain HTTP is followed only to this machine, where the tests' own API is: never to a host
    /// that only begins like one, and never to anything else.
    #[test]
    fn plain_http_is_followed_to_this_machine_alone() {
        let url = |u: &str| reqwest::Url::parse(u).unwrap();
        for here in [
            "http://127.0.0.1:8123/download/x",
            "http://127.1.2.3/x",
            "http://localhost/x",
            "http://[::1]:9/x",
        ] {
            assert!(on_loopback(&url(here)), "{here}");
        }
        for elsewhere in [
            "https://127.0.0.1/x",
            "http://127.0.0.1.example.com/x",
            "http://localhost.example.com/x",
            "http://github.com/x",
            "http://10.0.0.1/x",
        ] {
            assert!(!on_loopback(&url(elsewhere)), "{elsewhere}");
        }
    }
}
