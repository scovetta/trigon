//! `trigon evidence add`, `list`, `remove` and `sync`: the evidence sources a consumer trusts, and
//! the clones every answer is read from (`docs/19` §2.4, §6, §6.1).
//!
//! **A source is one log**, named in `evidence.toml`, by `TRIGON_EVIDENCE_REPO`, or by a project's
//! `.trigon/evidence.toml`, whose rules the configuration enforces. `add` writes one into the
//! user's file, keeping its comments and order; `remove` takes one out of it, and refuses one the
//! project's file or the environment added, saying why; `list` shows each with what its state says
//! of it; `sync` brings every one up to date, in parallel, each verified whole before anything is
//! accepted from it ([`sync`]).
//!
//! **What phase 6b's commands answer from** is [`ready`]: every source a command asks, a stale one
//! synced first unless `--offline`, each opened from its clones with the same verification and
//! classified by the two clocks of `docs/19` §6 ([`trigon_attest::evidence::Standing`]), with the
//! file that added it and whether its keys rest on first use, so that every answer can say both.

pub(crate) mod check;
pub(crate) mod lookup;
pub(crate) mod remote;
pub(crate) mod rerun;
pub(crate) mod sync;

use anyhow::{Result, anyhow};
use serde_json::json;
use trigon_attest::config::{
    AddedBy, ConfigError, EvidenceConfig, NewSource, Source, add_source, remove_source,
};
use trigon_attest::evidence::{Said, Standing, ago};
use trigon_attest::location::printable;
use trigon_attest::state::{FirstUse, KeysFile, SyncRecord};

use crate::OutputFormat;
pub(crate) use crate::clones::{Dirs, Failed, Opened, checkpoint_json, checkpoint_line};

/// `docs/19` §6: a source that failed verification, or one that could not answer.
const FAILED: i32 = 4;

/// Now, in Unix seconds.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `trigon evidence add`.
pub(crate) fn add(new: NewSource) -> Result<()> {
    let env = crate::evidence_env()?;
    let (path, source) = add_source(&env, &new)?;
    println!("added     `{}` to {}", source.name, path.display());
    match &source.log_key {
        Some(k) => println!("origin    {}, the log key's name", k.origin()),
        None => println!(
            "origin    not known until the first sync, which reads the log key from the \
             repository's keys/ and records it: every answer from it will say it rests on that"
        ),
    }
    for l in &source.urls {
        println!("url       {} ({})", l, l.transport());
    }
    if let Some(c) = &source.checkpoint {
        println!("pinned    the initial checkpoint {}", c.display());
    }
    println!(
        "required  {}",
        match source.required {
            true => "yes: while it cannot answer, a check fails",
            false => "no",
        }
    );
    println!("next      trigon evidence sync --source {}", source.name);
    Ok(())
}

/// `trigon evidence remove`: the source out of the user's file, and its clones and state with it,
/// since a source added again under the name is a new source and starts over.
pub(crate) fn remove(name: &str) -> Result<()> {
    let env = crate::evidence_env()?;
    // The directories are asked of the configuration as it is before the source goes.
    let config = EvidenceConfig::load(&env)?;
    let (path, source) = remove_source(&env, name)?;
    println!("removed   `{}` from {}", source.name, path.display());
    let dirs = Dirs::of(&config, &source.name)?;
    for (what, dir) in [("its clones", &dirs.cache), ("its state", &dirs.state)] {
        if std::fs::symlink_metadata(dir).is_err() {
            continue;
        }
        let removed = match std::fs::symlink_metadata(dir) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(dir),
            _ => std::fs::remove_file(dir),
        };
        match removed {
            Ok(()) => println!("removed   {what}, {}", dir.display()),
            Err(e) => println!(
                "kept      {what}, {}: it could not be removed ({e})",
                dir.display()
            ),
        }
    }
    Ok(())
}

/// What `trigon evidence sync` is given.
pub(crate) struct SyncArgs {
    pub sources: Vec<String>,
    pub full_history: bool,
    pub accept_state_loss: Vec<String>,
    pub verbose: bool,
}

/// `trigon evidence sync`: every source asked for, in parallel, each reported whole in the order
/// it is configured. Exits 0 when every one synced, and 4 when any did not — refused because it
/// failed verification or lost its state, or not reached — each saying what it answers from now.
pub(crate) fn sync_command(args: SyncArgs) -> Result<()> {
    let env = crate::evidence_env()?;
    let config = EvidenceConfig::load(&env)?;
    let chosen = chosen(&config, &args.sources)?;
    for n in &args.accept_state_loss {
        if !chosen.iter().any(|s| s.name.eq_ignore_ascii_case(n)) {
            // A bad argument, which `docs/19` §6 gives exit 5 like a configuration that cannot be
            // read.
            crate::verify_record::usage(&format!(
                "--accept-state-loss {}: no source being synced is named that{}",
                printable(n),
                match args.sources.is_empty() {
                    true => "",
                    false => "; name it with --source too",
                }
            ));
        }
    }
    let now = now();
    let outcomes: Vec<(Source, Result<Dirs>, std::result::Result<Opened, Failed>)> =
        std::thread::scope(|scope| {
            let handles: Vec<_> = chosen
                .iter()
                .map(|source| {
                    let config = &config;
                    let opt = sync::Options {
                        full_history: args.full_history,
                        accept_state_loss: args
                            .accept_state_loss
                            .iter()
                            .any(|n| n.eq_ignore_ascii_case(&source.name)),
                        verbose: args.verbose,
                        now,
                    };
                    scope.spawn(move || {
                        let dirs = Dirs::of(config, &source.name);
                        let result = match &dirs {
                            Ok(d) => sync::sync(source, d, opt),
                            Err(e) => Err(Failed {
                                refused: false,
                                error: anyhow!("{e:#}"),
                                urls: Vec::new(),
                            }),
                        };
                        (source.clone(), dirs, result)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("a sync does not panic"))
                .collect()
        });
    let mut failed = false;
    for (source, dirs, result) in &outcomes {
        println!(
            "source    `{}`, {}",
            source.name,
            added_by(&source.added_by)
        );
        match (result, dirs) {
            (Ok(opened), _) => report_synced(opened),
            (Err(f), dirs) => {
                failed = true;
                report_failed(&config, source, dirs.as_ref().ok(), f, now);
            }
        }
    }
    if failed {
        std::process::exit(FAILED);
    }
    Ok(())
}

/// The sources a command asks, by `--source`, or every one configured; none configured, or a
/// name none has, is the tool failing before it could answer (exit 5).
fn chosen(config: &EvidenceConfig, names: &[String]) -> Result<Vec<Source>> {
    let all = config.require_sources()?;
    if names.is_empty() {
        return Ok(all.to_vec());
    }
    let mut out: Vec<Source> = Vec::new();
    for n in names {
        let s = all
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(n))
            .ok_or_else(|| ConfigError::NoSuchSource {
                name: printable(n),
                known: all.iter().map(|s| s.name.clone()).collect(),
            })?;
        if !out.iter().any(|o| o.name == s.name) {
            out.push(s.clone());
        }
    }
    Ok(out)
}

fn added_by(a: &AddedBy) -> String {
    match a {
        AddedBy::ProjectFile(p) => format!("added by the project's own {}", p.display()),
        AddedBy::UserFile(p) => format!("from {}", p.display()),
        AddedBy::Environment => "from TRIGON_EVIDENCE_REPO".into(),
    }
}

fn report_synced(opened: &Opened) {
    let last = opened.last();
    let newest = match opened.repo.newest_time() {
        Some(t) => format!("newest leaf {}", crate::rfc3339_from_unix(t)),
        None => "no leaf yet".into(),
    };
    println!(
        "synced    `{}`: {} leaves, {newest}{}",
        last.origin(),
        last.size(),
        match opened.repo.logs().len() {
            1 => String::new(),
            n => format!(", the last of the {n} logs of its chain"),
        }
    );
    println!("{}", checkpoint_line(opened.checkpoint_of()));
    if let Some(f) = &opened.keys.first_use {
        println!("{}", first_use_line(f));
    }
    for u in &opened.urls {
        println!("{}", url_line(u));
    }
    for n in &opened.notes {
        println!("note      {}", crate::style::wrap(n, 10));
    }
}

fn report_failed(
    config: &EvidenceConfig,
    source: &Source,
    dirs: Option<&Dirs>,
    f: &Failed,
    now: u64,
) {
    let said = match f.refused {
        true => "REFUSED   nothing it served is accepted, for this reason:",
        false => "failed    it could not be synced, for this reason:",
    };
    println!("{said}");
    for u in &f.urls {
        println!("{}", url_line(u));
    }
    // Printed whole, with its causes: a refusal of a log that does not extend the one accepted, or
    // of an equivocation, carries both signed notes, which `docs/19` §8 has the client print.
    for line in format!("{:#}", f.error).lines() {
        println!("          {line}");
    }
    let record = dirs.and_then(|d| SyncRecord::read(&d.state).ok().flatten());
    let standing = Standing::of(
        config.freshness(),
        record.as_ref(),
        record.as_ref().and_then(|r| r.newest_leaf),
        now,
    );
    println!(
        "kept      its clones and its state as they were; {}",
        match (&standing, f.refused) {
            (_, true) => format!(
                "every command asking `{}` exits 4 until a sync of it works",
                source.name
            ),
            (Standing::Usable { stale_at, .. }, false) => format!(
                "it answers from its clone until it is stale, at {}",
                crate::rfc3339_from_unix(*stale_at)
            ),
            (s, false) => format!("it answers unknown: {}", standing_said(s)),
        }
    );
}

fn url_line(u: &trigon_attest::state::UrlSeen) -> String {
    let size = u.size.map_or(String::new(), |s| format!("{s} leaves, "));
    let note = u
        .note
        .as_ref()
        .map_or(String::new(), |n| format!(": {}", printable(n)));
    format!(
        "url       {} ({}): {size}{}{note}",
        u.url, u.transport, u.state
    )
}

fn first_use_line(f: &FirstUse) -> String {
    format!(
        "trust     on first use: its keys were read from {}'s keys/ at {}, and every answer from it \
         rests on them",
        f.read_from,
        crate::rfc3339_from_unix(f.at)
    )
}

fn standing_said(s: &Standing) -> String {
    match s {
        Standing::Fresh => "fresh".into(),
        Standing::Usable { failure, stale_at } => format!(
            "its last sync failed ({}), and it answers from its clone until {}",
            printable(failure),
            crate::rfc3339_from_unix(*stale_at)
        ),
        Standing::Frozen { newest: Some(t) } => format!(
            "frozen: its newest leaf was logged {}, longer ago than `frozen_after`",
            crate::rfc3339_from_unix(*t)
        ),
        Standing::Frozen { newest: None } => {
            "frozen: its log has no leaf, which says nothing about how recent it is".into()
        }
        Standing::Unknown { why } => printable(why),
        Standing::Refused { why } => format!("refused: {}", printable(why)),
    }
}

/// `trigon evidence list`: every source, with what its state says of it and how it stands now —
/// its clones verified as a command asking it would, touching no network ([`Mode::Offline`]).
pub(crate) fn list(output: OutputFormat, verbose: bool) -> Result<()> {
    let env = crate::evidence_env()?;
    let config = EvidenceConfig::load(&env)?;
    if config.sources().is_empty() {
        match output {
            OutputFormat::Json => println!("[]"),
            OutputFormat::Text => println!(
                "no evidence source is configured. Add one with `trigon evidence add <name> <url> \
                 --log-key <vkey> --attestation-key <key>`, or set TRIGON_EVIDENCE_REPO"
            ),
        }
        return Ok(());
    }
    let now = now();
    let mut rows = Vec::new();
    for r in ready(&config, &[], Mode::Offline, now, verbose)? {
        let dirs = Dirs::of(&config, &r.source.name)?;
        // A state file that cannot be read is shown on its source's row, which answers unknown
        // for it, and every other row is shown as it is.
        let (record, keys, unreadable) =
            match (SyncRecord::read(&dirs.state), KeysFile::read(&dirs.state)) {
                (Ok(r), Ok(k)) => (r, k, None),
                (r, k) => {
                    let why = [r.err(), k.err()]
                        .into_iter()
                        .flatten()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");
                    (None, None, Some(why))
                }
            };
        rows.push((r, record, keys, unreadable));
    }
    // What the clone holds where it could be verified, and what the last sync recorded where not.
    let size = |r: &Ready, record: &Option<SyncRecord>| match &r.opened {
        Some(o) => Some((o.last().origin().to_string(), o.last().size())),
        None => record
            .as_ref()
            .and_then(|x| x.logs.last().map(|l| (l.origin.clone(), l.size))),
    };
    let newest = |r: &Ready, record: &Option<SyncRecord>| match &r.opened {
        Some(o) => o.repo.newest_time(),
        None => record.as_ref().and_then(|x| x.newest_leaf),
    };
    if output == OutputFormat::Json {
        let doc: Vec<serde_json::Value> = rows
            .iter()
            .map(|(r, record, keys, unreadable)| {
                let s = &r.source;
                let first_use = keys.as_ref().and_then(|k| k.first_use.clone());
                json!({
                    "name": s.name,
                    "origin": origin_of(s, keys.as_ref()),
                    "urls": s.urls.iter().map(|l| json!({
                        "url": l.as_git_arg(),
                        "transport": l.transport().as_str(),
                    })).collect::<Vec<_>>(),
                    "required": s.required,
                    "addedBy": s.added_by.to_string(),
                    "projectFile": matches!(s.added_by, AddedBy::ProjectFile(_)),
                    "trust": match (s.trust_on_first_use, &first_use) {
                        (false, _) => json!("pinned"),
                        (true, Some(f)) => json!({"firstUse": f}),
                        (true, None) => json!("first-use-pending"),
                    },
                    "lastSync": record.as_ref().and_then(|x| x.last_success),
                    "lastAttempt": record.as_ref().and_then(|x| x.last_attempt),
                    "failure": record.as_ref().and_then(|x| x.failure.clone()),
                    "size": size(r, record).map(|(_, n)| n),
                    "checkpoint": r.opened.as_ref().map(|o| checkpoint_json(o.checkpoint_of())),
                    "newestLeaf": newest(r, record),
                    "standing": r.standing.key(),
                    "why": standing_said(&r.standing),
                    "label": r.label(),
                    "stateUnreadable": unreadable,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    for (i, (r, record, keys, unreadable)) in rows.iter().enumerate() {
        let s = &r.source;
        if i > 0 {
            println!();
        }
        println!("source    `{}`", s.name);
        println!("origin    {}", origin_of(s, keys.as_ref()));
        for l in &s.urls {
            println!("url       {} ({})", l, l.transport());
        }
        println!("required  {}", if s.required { "yes" } else { "no" });
        println!("added by  {}", s.added_by);
        if let Some(why) = unreadable {
            println!(
                "state     cannot be read: {}",
                crate::style::wrap(&printable(why), 10)
            );
        }
        match (
            s.trust_on_first_use,
            keys.as_ref().and_then(|k| k.first_use.as_ref()),
        ) {
            (false, _) => println!("trust     its keys are pinned"),
            (true, Some(f)) => println!("{}", first_use_line(f)),
            (true, None) => println!(
                "trust     on first use: its keys will be read from the repository on its first \
                 sync"
            ),
        }
        match record.as_ref().and_then(|x| x.last_success) {
            Some(t) => println!(
                "synced    {} ({} ago)",
                crate::rfc3339_from_unix(t),
                ago(now.saturating_sub(t))
            ),
            None => println!("synced    never"),
        }
        if let Some(f) = record.as_ref().and_then(|x| x.failure.as_ref()) {
            println!(
                "failed    {}: {}",
                crate::rfc3339_from_unix(f.at),
                crate::style::wrap(&printable(&f.why), 10)
            );
        }
        match (&r.opened, size(r, record)) {
            (Some(o), _) => println!("{}", checkpoint_line(o.checkpoint_of())),
            (None, Some((origin, n))) => println!(
                "recorded  {n} leaves of `{origin}`, by its last sync: nothing answers from its \
                 clones now"
            ),
            (None, None) => {}
        }
        if let Some(t) = newest(r, record) {
            println!("newest    leaf logged {}", crate::rfc3339_from_unix(t));
        }
        println!("now       {}", standing_said(&r.standing));
    }
    Ok(())
}

/// A source's origin: its log key's name, or the one trust on first use read.
fn origin_of(s: &Source, keys: Option<&KeysFile>) -> String {
    match (&s.log_key, keys.and_then(|k| k.log_vkey().ok())) {
        (Some(k), _) => k.origin().to_string(),
        (None, Some(k)) => format!("{} (read on first use)", k.origin()),
        (None, None) => "not known until its first sync".into(),
    }
}

/// Whether a command that needs sources may sync one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// A stale source is synced first, and the command says so.
    Sync,
    /// Every source is synced first, stale or not, and the command says so: for a command that
    /// knows a source's clone is behind what it needs, as `publish` does when the log it continues
    /// has ended since the source was synced.
    Refresh,
    /// Nothing touches the network (`--offline`): a stale source answers unknown, as a failed
    /// sync would.
    Offline,
}

/// One source as a command that needs it finds it (`docs/19` §6, §6.1): whether it can answer,
/// what from, and what every answer from it has to say.
pub(crate) struct Ready {
    pub source: Source,
    pub standing: Standing,
    /// The chain it answers from, verified, where it could be opened.
    pub opened: Option<Opened>,
    /// Where its keys were read, where they rest on first use.
    pub first_use: Option<FirstUse>,
    /// What was done and found: a stale source synced first, a sync that failed.
    pub notes: Vec<String>,
    /// Whether this call synced it, or tried to: a source it did not is answered from its clone
    /// as it was.
    pub synced: bool,
}

impl Ready {
    /// What every answer from this source carries: the source, the file that added it, the keys
    /// it rests on, and the checkpoint the answer came from.
    pub(crate) fn label(&self) -> String {
        let mut parts = vec![format!(
            "`{}`, {}",
            self.source.name,
            added_by(&self.source.added_by)
        )];
        if let Some(f) = &self.first_use {
            parts.push(format!(
                "resting on keys trusted on first use, read from {} at {}",
                f.read_from,
                crate::rfc3339_from_unix(f.at)
            ));
        }
        if let Some(o) = &self.opened {
            let last = o.last();
            parts.push(format!(
                "as of {} leaves of `{}`",
                last.size(),
                last.origin()
            ));
        }
        parts.join("; ")
    }

    /// What this source says of one package, as `docs/19` §6 weighs it: `answer` asked of its
    /// chain where it can answer; unknown where it cannot, which counts only if it is required;
    /// refused where its last sync failed verification.
    pub(crate) fn said(
        &self,
        answer: impl FnOnce(&trigon_attest::evidence::Repository) -> trigon_attest::evidence::Answer,
    ) -> Said {
        match (&self.standing, &self.opened) {
            (Standing::Refused { .. }, _) => Said::Refused,
            (s, Some(o)) if s.answers() => Said::Answered(answer(&o.repo)),
            _ => Said::Unknown {
                required: self.source.required,
            },
        }
    }
}

/// Every source a command asks — `names`, or all — each synced first where it is stale and `mode`
/// allows, then opened from its clones and classified by the two clocks of `docs/19` §6, in
/// parallel and returned in the order configured. None configured is exit 5
/// ([`EvidenceConfig::require_sources`]).
///
/// Sync and failure are per source (§6.1): a source whose state cannot be read, or that cannot be
/// synced or opened, answers unknown or refused, saying why, and the others answer as they are.
pub(crate) fn ready(
    config: &EvidenceConfig,
    names: &[String],
    mode: Mode,
    now: u64,
    verbose: bool,
) -> Result<Vec<Ready>> {
    let chosen = chosen(config, names)?;
    let freshness = *config.freshness();
    std::thread::scope(|scope| {
        let handles: Vec<_> = chosen
            .into_iter()
            .map(|source| {
                scope.spawn(move || -> Result<Ready> {
                    let dirs = Dirs::of(config, &source.name)?;
                    let mut notes = Vec::new();
                    // A record that cannot be read is this source's failure, which opening it
                    // says, and no other's.
                    let last_success = SyncRecord::read(&dirs.state)
                        .ok()
                        .flatten()
                        .and_then(|r| r.last_success);
                    let stale = last_success
                        .is_none_or(|t| now.saturating_sub(t) > freshness.stale_after.as_secs());
                    // A source none of whose locations has a clone — its URL changed since its
                    // last sync, in `evidence.toml` or `TRIGON_EVIDENCE_REPO`, or its clones were
                    // removed — cannot be opened however recent that sync was, so it is synced
                    // first too, as a source never synced is. One mirror of several without a
                    // clone is not, or every command would fetch while it is down.
                    let unopenable = !source
                        .urls
                        .iter()
                        .any(|l| crate::clones::accepted_clone(&dirs.clone_of(l)));
                    let synced = match mode {
                        Mode::Sync => stale || unopenable,
                        Mode::Refresh => true,
                        Mode::Offline => false,
                    };
                    if synced {
                        let said = match (last_success, stale) {
                            (_, false) if unopenable && mode == Mode::Sync => {
                                "synced first: no location it names has a clone — its URLs \
                                 changed since its last sync, or its clones were removed"
                                    .to_string()
                            }
                            (_, false) => "synced first: this command needs what it serves now, \
                                 and its clone may be from before that"
                                .to_string(),
                            (Some(t), true) => format!(
                                "synced first: its last sync was {} ago, longer than \
                                 `stale_after`",
                                ago(now.saturating_sub(t))
                            ),
                            (None, true) => "synced first: it had never been synced".into(),
                        };
                        notes.push(said);
                        let opt = sync::Options {
                            full_history: false,
                            accept_state_loss: false,
                            verbose,
                            now,
                        };
                        if let Err(f) = sync::sync(&source, &dirs, opt) {
                            notes.push(format!("the sync failed: {:#}", f.error));
                        }
                    }
                    let record = SyncRecord::read(&dirs.state).ok().flatten();
                    let (opened, standing) = match sync::open(&source, &dirs) {
                        Ok(o) => {
                            let s = Standing::of(
                                &freshness,
                                record.as_ref(),
                                o.repo.newest_time(),
                                now,
                            );
                            (Some(o), s)
                        }
                        Err(f) if f.refused => (
                            None,
                            Standing::Refused {
                                why: format!("{:#}", f.error),
                            },
                        ),
                        Err(f) => {
                            let s = match Standing::of(&freshness, record.as_ref(), None, now) {
                                r @ Standing::Refused { .. } => r,
                                _ => Standing::Unknown {
                                    why: format!("{:#}", f.error),
                                },
                            };
                            (None, s)
                        }
                    };
                    let first_use = opened.as_ref().and_then(|o| o.keys.first_use.clone());
                    Ok(Ready {
                        source,
                        standing,
                        opened,
                        first_use,
                        notes,
                        synced,
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().map_err(|_| anyhow!("opening a source panicked"))?)
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use trigon_attest::LocalKey;
    use trigon_attest::config::Env;
    use trigon_attest::evidence::{Answer, Key};
    use trigon_attest::log::{
        Checkpoint, HeartbeatLeaf, Leaf, LogSigner, SignedCheckpoint, Tree, plan_append,
    };
    use trigon_core::Match;

    use super::*;

    const ORIGIN: &str = "example.com/ready";
    const DAY: u64 = 86_400;

    /// A scratch directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let d = std::env::temp_dir().join(format!(
                "trigon-evidence-ready-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Scratch(d)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
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
    }

    /// A bare repository whose log is heartbeats logged at `times`, with its keys, as a
    /// publisher's commits would leave it.
    fn repository(root: &Path, signer: &LogSigner, key: &LocalKey, times: &[u64]) -> PathBuf {
        git(
            root,
            &["init", "--quiet", "--bare", "-b", "main", "remote.git"],
        );
        git(root, &["init", "--quiet", "-b", "main", "w"]);
        let w = root.join("w");
        std::fs::create_dir_all(w.join("keys")).unwrap();
        std::fs::write(w.join("keys/log.vkey"), format!("{}\n", signer.vkey())).unwrap();
        std::fs::write(w.join("keys/attestation.pub"), key.public_pem()).unwrap();
        log_heartbeats(root, signer, times)
    }

    /// The repository's log written again, in its working tree, as heartbeats logged at `times`,
    /// committed and pushed: a log that extends the one before where `times` does.
    fn log_heartbeats(root: &Path, signer: &LogSigner, times: &[u64]) -> PathBuf {
        let w = root.join("w");
        let _ = std::fs::remove_dir_all(w.join("log"));
        let leaves: Vec<Vec<u8>> = times
            .iter()
            .map(|t| {
                Leaf::Heartbeat(HeartbeatLeaf { time: *t })
                    .encode()
                    .unwrap()
            })
            .collect();
        let append = plan_append(&Tree::new(), &[] as &[Vec<u8>], &leaves).unwrap();
        for (path, bytes) in &append.files {
            let p = w.join("log").join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        let checkpoint = Checkpoint {
            origin: ORIGIN.into(),
            size: append.size,
            root: append.root,
        };
        std::fs::create_dir_all(w.join("log")).unwrap();
        std::fs::write(
            w.join("log/checkpoint"),
            SignedCheckpoint::sign(&checkpoint, signer)
                .unwrap()
                .to_string(),
        )
        .unwrap();
        git(&w, &["add", "--all"]);
        git(&w, &["commit", "--quiet", "-m", "log"]);
        let bare = root.join("remote.git");
        git(&w, &["push", "--quiet", bare.to_str().unwrap(), "main"]);
        bare
    }

    /// A configuration with one source, `main`, at `bare`, and its cache and state under `root`.
    fn config(root: &Path, bare: &Path, signer: &LogSigner, key: &LocalKey) -> EvidenceConfig {
        let file = root.join("evidence.toml");
        std::fs::write(
            &file,
            format!(
                "[[source]]\nname = \"main\"\nurls = [\"{}\"]\nlog_key = \"{}\"\n\
                 attestation_key = \"{}\"\n",
                bare.display(),
                signer.vkey(),
                key.public_hex()
            ),
        )
        .unwrap();
        let env = Env {
            cwd: root.to_path_buf(),
            home: Some(root.join("home")),
            evidence_config: Some(file),
            evidence_cache: Some(root.join("cache")),
            evidence_state: Some(root.join("state")),
            ..Default::default()
        };
        EvidenceConfig::load(&env).unwrap()
    }

    fn one(config: &EvidenceConfig, mode: Mode, now: u64) -> Ready {
        let mut all = ready(config, &[], mode, now, false).unwrap();
        assert_eq!(all.len(), 1);
        all.remove(0)
    }

    /// What a command asks of a source, with the lookup it would make.
    fn said(r: &Ready) -> Said {
        let key = Key::parse(&format!("sha256:{}", "0".repeat(64))).unwrap();
        r.said(|repo| repo.lookup(&key).answer(Match::NormalizedWithCaveats))
    }

    /// A command that needs a source syncs a stale one first and says so; offline, a stale source
    /// answers unknown and nothing is fetched; a frozen one answers unknown whatever the sync did;
    /// and one that cannot be reached answers from its clone until the clone is stale. Every time
    /// is an argument here, and nothing waits.
    #[test]
    fn a_command_that_needs_a_source_syncs_a_stale_one_first_and_says_so() {
        let dir = Scratch::new("stale");
        let root = &dir.0;
        let signer = LogSigner::from_seed(ORIGIN, [5; 32]).unwrap();
        let key = LocalKey::from_bytes(&[6; 32]).unwrap();
        let now = now();
        let bare = repository(root, &signer, &key, &[now - DAY]);
        let config = config(root, &bare, &signer, &key);

        let r = one(&config, Mode::Sync, now);
        assert_eq!(r.notes, ["synced first: it had never been synced"]);
        assert_eq!(r.standing, Standing::Fresh);
        assert!(
            r.label().contains("as of 1 leaves of `example.com/ready`"),
            "{}",
            r.label()
        );
        assert_eq!(said(&r), Said::Answered(Answer::NeverChecked));

        // A day and an hour on, offline: stale, so unknown, and nothing was fetched.
        let later = now + DAY + 3600;
        let r = one(&config, Mode::Offline, later);
        assert!(r.notes.is_empty(), "{:?}", r.notes);
        assert!(
            matches!(&r.standing, Standing::Unknown { why } if why.contains("stale")),
            "{:?}",
            r.standing
        );
        assert_eq!(said(&r), Said::Unknown { required: false });

        // Allowed to, it syncs first, and says how old its last sync was.
        let r = one(&config, Mode::Sync, later);
        assert_eq!(
            r.notes,
            ["synced first: its last sync was 1d 1h ago, longer than `stale_after`"]
        );
        assert_eq!(r.standing, Standing::Fresh);

        // Unreachable, and not yet stale: it answers from its clone, and says its sync failed.
        std::fs::rename(&bare, root.join("gone.git")).unwrap();
        let dirs = Dirs::of(&config, "main").unwrap();
        let opt = sync::Options {
            full_history: false,
            accept_state_loss: false,
            verbose: false,
            now: later + 60,
        };
        let failed = match sync::sync(&config.sources()[0], &dirs, opt) {
            Err(f) => f,
            Ok(_) => panic!("a source that cannot be reached was synced"),
        };
        assert!(!failed.refused, "{:#}", failed.error);
        let r = one(&config, Mode::Offline, later + 120);
        assert!(
            matches!(r.standing, Standing::Usable { stale_at, .. } if stale_at == later + DAY),
            "{:?}",
            r.standing
        );
        assert_eq!(said(&r), Said::Answered(Answer::NeverChecked));
        // Stale, and still unreachable: unknown, and the failed sync is said.
        let r = one(&config, Mode::Sync, later + 2 * DAY);
        assert!(
            r.notes.iter().any(|n| n.starts_with("the sync failed")),
            "{:?}",
            r.notes
        );
        assert!(
            matches!(r.standing, Standing::Unknown { .. }),
            "{:?}",
            r.standing
        );

        // Frozen whatever the sync did: reachable again, synced, and its newest leaf is fifteen
        // days old.
        std::fs::rename(root.join("gone.git"), &bare).unwrap();
        let r = one(&config, Mode::Sync, now + 14 * DAY + 60);
        assert!(r.notes[0].starts_with("synced first"), "{:?}", r.notes);
        assert_eq!(
            r.standing,
            Standing::Frozen {
                newest: Some(now - DAY)
            }
        );
        assert_eq!(said(&r), Said::Unknown { required: false });
    }

    /// A sync whose checkpoint is written and whose record of the sync then cannot be keeps the
    /// clones the checkpoint was read from: put back behind it, they would be refused as a rollback
    /// of the sync's own checkpoint. It answers from them, and says the record was not written.
    #[test]
    fn a_sync_whose_record_cannot_be_written_keeps_the_clones_it_accepted() {
        let dir = Scratch::new("record-unwritten");
        let root = &dir.0;
        let signer = LogSigner::from_seed(ORIGIN, [5; 32]).unwrap();
        let key = LocalKey::from_bytes(&[6; 32]).unwrap();
        let now = now();
        let bare = repository(root, &signer, &key, &[now - 60]);
        let config = config(root, &bare, &signer, &key);
        let source = &config.sources()[0];
        let dirs = Dirs::of(&config, "main").unwrap();
        let opt = sync::Options {
            full_history: false,
            accept_state_loss: false,
            verbose: false,
            now,
        };
        if let Err(f) = sync::sync(source, &dirs, opt) {
            panic!("{:#}", f.error);
        }

        log_heartbeats(root, &signer, &[now - 60, now]);
        // The record's temporary file cannot be made: a directory is where it would go.
        let blocked = dirs.state.join(format!(".sync.{}.tmp", std::process::id()));
        std::fs::create_dir_all(blocked.join("in-the-way")).unwrap();
        let opened = match sync::sync(source, &dirs, opt) {
            Ok(o) => o,
            Err(f) => panic!("{:#}", f.error),
        };
        assert_eq!(opened.last().size(), 2);
        assert!(
            opened
                .notes
                .iter()
                .any(|n| n.contains("the record of this sync could not be written")),
            "{:?}",
            opened.notes
        );
        std::fs::remove_dir_all(&blocked).unwrap();
        // The checkpoint of two leaves is accepted, and the clone it was read from is kept.
        let reopened = match sync::open(source, &dirs) {
            Ok(o) => o,
            Err(f) => panic!("{:#}", f.error),
        };
        assert_eq!(reopened.last().size(), 2);
    }

    /// A source refused on its last sync answers nothing, whatever its clone holds, and is weighed
    /// as such; an unknown one counts only where it is required.
    #[test]
    fn what_a_source_says_is_weighed_by_how_it_stands() {
        let dir = Scratch::new("weighed");
        let root = &dir.0;
        let signer = LogSigner::from_seed(ORIGIN, [5; 32]).unwrap();
        let key = LocalKey::from_bytes(&[6; 32]).unwrap();
        let bare = repository(root, &signer, &key, &[now()]);
        let config = config(root, &bare, &signer, &key);
        let mut r = one(&config, Mode::Sync, now());
        assert!(r.opened.is_some());
        r.standing = Standing::Refused {
            why: "an equivocation".into(),
        };
        assert_eq!(said(&r), Said::Refused);
        r.standing = Standing::Unknown {
            why: "stale".into(),
        };
        r.source.required = true;
        assert_eq!(said(&r), Said::Unknown { required: true });
        r.standing = Standing::Fresh;
        r.opened = None;
        assert_eq!(said(&r), Said::Unknown { required: true });
    }
}
