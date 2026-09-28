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
//! **The rebuilt artifact** is the release asset the verdict names by digest where the operator
//! publishes them (`[publish] rebuilt_artifacts = "github-release"`, D4) — found by name in the
//! releases of the GitHub repository that holds the record's leaf, which after a succession into
//! another repository is that one, downloaded without a token into a directory only this user can
//! enter, and held to the digest the verdict signs as it is written — and `--rebuild <file>`
//! otherwise, or where given. Then the record is checked and its claim re-derived exactly as the
//! record form does (`crate::verify_record::report`). A void makes no claim to re-derive: it is
//! reported, with its code, and said not to have been.

use std::cell::RefCell;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use serde::Deserialize;
use sha2::Digest as _;
use trigon_attest::config::{AddedBy, Env, EvidenceConfig, RebuiltArtifacts};
use trigon_attest::evidence::{
    Answer, Key, RECORD_LIMIT, RecordKind, Said, exit_code, first_that_wins, record_path,
};
use trigon_attest::location::{Location, Transport, printable};
use trigon_attest::log::{DirFiles, LeafPos, LogError, LogFiles};
use trigon_attest::state::KeysFile;

use super::{Dirs, Mode, Ready, ready};
use crate::OutputFormat;
use crate::publish::git;
use crate::publish::release::on_github;
use crate::verify_record::{self, Done, Reading, Stop, cannot, failed};

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
        )));
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
        // Nothing current to check: what the source says instead, and its code.
        let withdrawn = said.contains(&Said::Answered(Answer::Withdrawn));
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
        // The rebuilt artifact, from its release asset where one is published and none is given;
        // removed when this record's report is done.
        let asset = match a.rerun && a.files.rebuild.is_none() && !void {
            true => {
                // Released by the repository that holds the record's leaf, in whichever source
                // holding the record names one on GitHub.
                let holding: Vec<(&Ready, LeafPos)> = named
                    .iter()
                    .copied()
                    .filter_map(|n| {
                        let o = n.opened.as_ref()?;
                        o.repo
                            .record_leaves()
                            .find(|(_, l)| l.record == f.leaf.record)
                            .map(|(pos, _)| (n, pos))
                    })
                    .collect();
                Some(rebuilt_asset(&config, &holding, v)?)
            }
            false => None,
        };
        let files = crate::Rerun {
            upstream: a.files.upstream,
            rebuild: asset.as_ref().map(|d| d.path.as_path()).or(a.files.rebuild),
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
    /// being checked and its bytes being read.
    fn new(digest: &trigon_core::Digest) -> anyhow::Result<Download> {
        let tmp = std::env::temp_dir();
        for attempt in 0..16u32 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = tmp.join(format!(
                "trigon-rebuilt-{}-{nanos:08x}{attempt:x}",
                std::process::id()
            ));
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
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    browser_download_url: String,
}

/// The rebuilt artifact a verdict names, for `--rerun-comparison` without `--rebuild`: the release
/// asset `sha256-<hex>` of the GitHub repository that holds the record's leaf, where the operator
/// publishes rebuilt artifacts (`rebuilt_artifacts = "github-release"`), held to the digest the
/// verdict signs. `holding` is each source that holds the record, with where. Refused, as bad
/// arguments, where they are not published: `--rebuild <file>` is then how the rebuilt artifact
/// is given.
fn rebuilt_asset(
    config: &EvidenceConfig,
    holding: &[(&Ready, LeafPos)],
    v: &trigon_attest::evidence::VerifiedRecord,
) -> Result<Download, Stop> {
    if config.publish().rebuilt_artifacts != RebuiltArtifacts::GithubRelease {
        return Err(cannot(anyhow!(
            "--rerun-comparison needs the rebuilt artifact: rebuilt artifacts are not published \
             as release assets here (`[publish] rebuilt_artifacts` is \"none\"), so give it with \
             --rebuild <file>, the output of rebuilding under the record's published strategy"
        )));
    }
    let digest = v
        .statement
        .predicate
        .pointer("/artifacts/rebuild/sha256")
        .and_then(|h| h.as_str())
        .and_then(|h| trigon_core::Digest::from_hex(h).ok())
        .ok_or_else(|| {
            failed(anyhow!(
                "the verdict signs no rebuilt artifact's sha256, so no release asset can be found \
                 for it; give it with --rebuild <file>"
            ))
        })?;
    let repository = holding
        .iter()
        .find_map(|(r, pos)| github_repository_of(r, *pos))
        .ok_or_else(|| {
            cannot(anyhow!(
                "the repository that holds the record in {} has no https://github.com/<owner>/<repo> \
                 URL, so no releases are known to hold the rebuilt artifact; give it with \
                 --rebuild <file>",
                holding
                    .iter()
                    .map(|(r, _)| format!("`{}`", r.source.name))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ))
        })?;
    let name = format!("sha256-{}", digest.to_hex());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(cannot)?;
    let mut download = Download::new(&digest).map_err(cannot)?;
    // Hashed as it is written, so the digest held to is that of the bytes that were written, and
    // nothing reads the file between the two.
    let (size, got) = rt
        .block_on(fetch_asset(&repository, &name, &download.path))
        .map_err(|e| failed(e.context(format!("the rebuilt artifact {name} of {repository}"))))?;
    if got != digest {
        return Err(failed(anyhow!(
            "the release asset {name} of {repository} is not the rebuilt artifact the verdict \
             signs: its sha256 is {}, and an asset is named by the digest of what it holds",
            got.to_hex()
        )));
    }
    download.said = format!(
        "the rebuilt artifact is the release asset {name} of {repository}, {size} bytes, \
         downloaded and held to the digest the verdict signs; asking for it names the record to \
         GitHub"
    );
    Ok(download)
}

/// The `owner/repo` on GitHub of the repository that holds leaf `pos` of `r`'s chain, where it
/// has one: the source's own locations for the repository its chain starts in, and for one its
/// chain went on in, the locations the log-end that led there names — which is where a successor's
/// publisher uploads its release assets.
fn github_repository_of(r: &Ready, pos: LeafPos) -> Option<String> {
    let o = r.opened.as_ref()?;
    let logs = &o.repo.source().logs;
    let elsewhere = logs[..pos.log.min(logs.len())].iter().rev().find_map(|c| {
        c.log
            .log_end()
            .map(|e| &e.successor)
            .filter(|s| !s.in_this_repository())
    });
    match elsewhere {
        None => super::remote::github_repository(&r.source),
        Some(s) => s.urls.iter().find_map(|u| {
            let l = Location::parse(u, Path::new("/"), None).ok()?;
            (l.transport() == Transport::Https)
                .then(|| on_github(&l))
                .flatten()
        }),
    }
}

/// Find the asset `name` in any release of `repository`, and download it to `to`: its size, and
/// the sha256 of the bytes written. Anonymous, since the repository is public and nothing is
/// written; the API is GitHub's, or the one `TRIGON_GITHUB_API` names, and a download is followed
/// only to HTTPS, or to that API's own host where it is on this machine.
async fn fetch_asset(
    repository: &str,
    name: &str,
    to: &Path,
) -> anyhow::Result<(u64, trigon_core::Digest)> {
    let api = crate::publish::release::api_base()?;
    let loopback = api.scheme() == "http";
    let client = reqwest::Client::builder()
        .user_agent(trigon_politeness::user_agent())
        .redirect(reqwest::redirect::Policy::custom(move |a| {
            if a.previous().len() > 5 {
                a.error("too many redirects")
            } else if a.url().scheme() == "https" || loopback {
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
        for rel in &releases {
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
                        rel.tag_name,
                        resp.status()
                    );
                }
                let assets: Vec<Asset> = resp.json().await?;
                if let Some(asset) = assets.iter().find(|x| x.name == name) {
                    return download(&client, asset, to, loopback).await;
                }
                if assets.len() < 100 {
                    break;
                }
            }
        }
        if releases.len() < 100 {
            break;
        }
    }
    bail!(
        "no release of {repository} holds an asset named {name}: the operator publishes rebuilt \
         artifacts, and this one is not there. Give it with --rebuild <file>"
    )
}

/// Download `asset` to `to`, a file that must not exist yet, streaming, refusing more than
/// GitHub's limit on one asset: its size, and the sha256 of what was written, hashed as it was.
async fn download(
    client: &reqwest::Client,
    asset: &Asset,
    to: &Path,
    loopback: bool,
) -> anyhow::Result<(u64, trigon_core::Digest)> {
    let url = reqwest::Url::parse(&asset.browser_download_url)
        .map_err(|e| anyhow!("its download URL is not one ({e})"))?;
    let plain_to_loopback = url.scheme() == "http"
        && loopback
        && url
            .host_str()
            .is_some_and(|h| matches!(h, "127.0.0.1" | "localhost" | "[::1]"));
    if url.scheme() != "https" && !plain_to_loopback {
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
    let mut resp = client
        .get(url.clone())
        .timeout(std::time::Duration::from_secs(3600))
        .send()
        .await
        .map_err(|e| anyhow!("{url}: {}", shown(e)))?;
    if !resp.status().is_success() {
        bail!("downloading it: {url} answered {}", resp.status());
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
    /// file of theirs to change between its digest being checked and its bytes being read.
    #[test]
    fn a_download_is_made_where_no_other_user_can_reach_it() {
        let digest = trigon_core::Digest::from_bytes([7; 32]);
        let a = Download::new(&digest).unwrap();
        let b = Download::new(&digest).unwrap();
        assert_ne!(a.dir, b.dir, "each download has a directory of its own");
        assert_eq!(a.path.parent(), Some(a.dir.as_path()));
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
        // Dropped, the directory goes with what was downloaded into it.
        let dir = a.dir.clone();
        drop(fresh);
        drop(a);
        assert!(!dir.exists());
    }
}
