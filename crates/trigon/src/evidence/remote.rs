//! `--remote` on `lookup` and `check` (`docs/19` §6): one question answered with plain HTTPS GETs
//! from `raw.githubusercontent.com`, for a place a clone is unwelcome — and labelled as the
//! exception it is.
//!
//! **What it reads, and what it proves.** The checkpoint of the source's log, opened under the
//! pinned log key and held to the checkpoint last accepted in the state directory by a consistency
//! proof from the hash tiles (`log::verify_extension_from_tiles`); the log's last leaf, proven
//! included, which says how recent the log is and whether it goes on in a successor, which is then
//! read the same way; the index file for the key; each record it lists; and the entry bundle and
//! the hash tiles that prove each record's leaf included in the tree its checkpoint signs
//! (`log::prove_inclusion_from_tiles`). A record whose leaf cannot be proven fails verification. A
//! record is checked against its leaf and the source's attestation keys as a clone's is
//! (`evidence::check_record`); its evidence files are not fetched, so each is reported unchecked.
//! A successor is followed only where its first leaf, proven, is the log-continuation its
//! predecessor's log-end requires (`log::check_continuation`), as a sync follows one.
//!
//! **What cannot be read is unknown, and what does not prove fails.** A file that is not served, a
//! request refused, cut short or rate-limited, and an index entry past the checkpoint read — which
//! is what a publish landing between two requests looks like, since each file is read at whatever
//! commit the host serves then — leave the source unable to answer that question: unknown, as
//! `docs/19` §4.2 has a failed `--remote` lookup. A proof that does not lead to the signed root, a
//! leaf that is not the record listed, and a record that does not verify fail verification, exit 4.
//!
//! **The state is held as a sync holds it.** A source whose last sync was refused answers nothing
//! here either; a key history recorded under another pin than the configuration's now is not used;
//! and the checkpoint last accepted is held to.
//!
//! **What it costs, said whenever it is used** ([`CAVEATS`]): it tells GitHub which package was
//! asked about; it is rate-limited for an unauthenticated client; and it sees a supersession or a
//! withdrawal only where the index file for the key lists it, since it reads the index and not the
//! log. A clone has none of the three.
//!
//! Only for a source with a `https://github.com/<owner>/<repo>` URL, which names the raw files'
//! place. `TRIGON_EVIDENCE_RAW_BASE` replaces `https://raw.githubusercontent.com` — HTTPS, or plain
//! HTTP to this machine alone — so that the tests read a published repository's files from a
//! server of their own on `127.0.0.1:0`.

use std::cell::RefCell;
use std::collections::BTreeMap;

use anyhow::{Context as _, Result, anyhow, bail};
use trigon_attest::LogVkey;
use trigon_attest::config::{EvidenceConfig, Freshness, Source};
use trigon_attest::evidence::{
    Found, IndexFile, Key, Lookup, RECORD_LIMIT, RecordState, check_record, record_path,
};
use trigon_attest::location::{Location, Transport, printable};
use trigon_attest::log::{
    Bundle, Checkpoint, KeyHistory, Leaf, LeafPos, LogEndLeaf, LogError, LogFiles,
    SignedCheckpoint, SignedNote, Tile, check_continuation, prove_inclusion_from_tiles,
    successor_vkey, verify_extension_from_tiles,
};
use trigon_attest::state::{KeysFile, SyncRecord};

use crate::clones::Dirs;
use crate::publish::release::on_github;

/// What `--remote` costs, which `docs/19` §6 has it say whenever it is used.
pub(crate) const CAVEATS: [&str; 3] = [
    "--remote tells GitHub which package was asked about: each file it reads is named by the key, \
     as nothing a clone does is",
    "--remote is rate-limited: GitHub serves an unauthenticated client only so many requests, and \
     every key costs several",
    "--remote sees a supersession or a withdrawal only where the index file for the key lists it: \
     it reads the index, which is derived data whoever can push can alter, and not the log a \
     clone holds whole",
];

/// Where the raw files are served when `TRIGON_EVIDENCE_RAW_BASE` names nowhere else.
const DEFAULT_RAW: &str = "https://raw.githubusercontent.com";

/// The longest checkpoint note read, as a clone reads one.
const CHECKPOINT_LIMIT: u64 = 64 * 1024;

/// The longest index file read. One lists a record digest and a leaf per record filed under its
/// key, some eighty bytes each; a package with every version checked is a few thousand.
const INDEX_LIMIT: u64 = 4 << 20;

/// The longest chain of repositories followed, as a sync follows one.
const MOST_LOGS: usize = 64;

/// The base URL every raw file is read under: `TRIGON_EVIDENCE_RAW_BASE`, or GitHub's own. HTTPS,
/// or plain HTTP to loopback only: what is read is verified whatever carries it, and what it
/// names — the package asked about — should cross nothing but an encrypted connection.
fn raw_base() -> Result<reqwest::Url> {
    let given = std::env::var("TRIGON_EVIDENCE_RAW_BASE")
        .ok()
        .filter(|v| !v.is_empty());
    raw_base_from(given.as_deref())
}

fn raw_base_from(given: Option<&str>) -> Result<reqwest::Url> {
    let text = given.unwrap_or(DEFAULT_RAW);
    let url = reqwest::Url::parse(text.trim_end_matches('/')).map_err(|e| {
        anyhow!(
            "TRIGON_EVIDENCE_RAW_BASE is `{}`, which is not a URL ({e})",
            printable(text)
        )
    })?;
    let loopback = url.host_str().is_some_and(|h| {
        matches!(h, "localhost" | "[::1]")
            || h.parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => bail!(
            "TRIGON_EVIDENCE_RAW_BASE is `{}`: what --remote reads names the package asked about, \
             so it is an https:// URL, or http:// to this machine alone",
            printable(text)
        ),
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("TRIGON_EVIDENCE_RAW_BASE carries a user or a password, and --remote sends neither");
    }
    Ok(url)
}

/// `owner/repo` of the first `https://github.com/<owner>/<repo>` URL of a source, or `None` where
/// it has none: what `--remote` reads a source through.
pub(crate) fn github_repository(source: &Source) -> Option<String> {
    source
        .urls
        .iter()
        .filter(|l| l.transport() == Transport::Https)
        .find_map(on_github)
}

/// The refusal of a source `--remote` cannot read: the tool failing before it could answer, exit
/// 5, naming how to leave the source out.
pub(crate) fn unreadable_source(source: &Source) -> anyhow::Error {
    anyhow!(
        "--remote reads a source's files from raw.githubusercontent.com, and `{}` has no \
         https://github.com/<owner>/<repo> URL ({}), so it cannot be asked this way. Leave it out \
         with --source <name> for each source that can be, or drop --remote and ask its clone",
        source.name,
        source
            .urls
            .iter()
            .map(Location::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// One HTTP client, and the runtime its requests run on: `LogFiles::read` is called from code
/// that is not async, and every file is read in turn.
pub(crate) struct Http {
    client: reqwest::Client,
    rt: tokio::runtime::Runtime,
    /// Every URL asked for, in order, for `-v`.
    asked: RefCell<Vec<String>>,
}

impl Http {
    pub(crate) fn new() -> Result<Http> {
        let client = reqwest::Client::builder()
            .user_agent(trigon_politeness::user_agent())
            // A redirect is followed only to HTTPS, as the base itself must be.
            .redirect(reqwest::redirect::Policy::custom(|a| {
                if a.previous().len() > 5 {
                    a.error("too many redirects")
                } else if a.url().scheme() == "https" {
                    a.follow()
                } else {
                    a.stop()
                }
            }))
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("building the HTTP client for --remote")?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("starting the runtime for --remote")?;
        Ok(Http {
            client,
            rt,
            asked: RefCell::new(Vec::new()),
        })
    }

    /// The URLs asked for so far.
    pub(crate) fn asked(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }

    /// GET `url`: its body, `None` for a 404, and an error for anything else, or for a body longer
    /// than `limit`.
    fn get(&self, url: &str, limit: u64) -> std::result::Result<Option<Vec<u8>>, String> {
        self.asked.borrow_mut().push(url.to_string());
        self.rt.block_on(async {
            let resp = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|e| format!("it could not be reached: {}", shown(e)))?;
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(format!("it answered {status}"));
            }
            if resp.content_length().is_some_and(|n| n > limit) {
                return Err(format!("it is longer than the {limit} bytes read of one"));
            }
            let mut resp = resp;
            let mut body = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| format!("reading it: {}", shown(e)))?
            {
                body.extend_from_slice(&chunk);
                if body.len() as u64 > limit {
                    return Err(format!("it is longer than the {limit} bytes read of one"));
                }
            }
            Ok(Some(body))
        })
    }
}

/// A transport error as a message shows it: without its URL, which the message around it names.
fn shown(e: reqwest::Error) -> String {
    printable(&e.without_url().to_string())
}

/// One repository's raw files, by their paths in it, read over HTTP and kept once read.
struct RawRepo<'h> {
    http: &'h Http,
    /// `<base>/<owner>/<repo>/HEAD`, with no trailing slash.
    base: String,
    read: RefCell<BTreeMap<String, Option<Vec<u8>>>>,
}

impl<'h> RawRepo<'h> {
    fn new(http: &'h Http, base: &reqwest::Url, repository: &str) -> RawRepo<'h> {
        RawRepo {
            http,
            base: format!("{}/{repository}/HEAD", base.as_str().trim_end_matches('/')),
            read: RefCell::new(BTreeMap::new()),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.base)
    }

    fn file(&self, path: &str, limit: u64) -> std::result::Result<Option<Vec<u8>>, LogError> {
        if let Some(b) = self.read.borrow().get(path) {
            return Ok(b.clone());
        }
        let got = self
            .http
            .get(&self.url(path), limit)
            .map_err(|why| LogError::Io {
                path: self.url(path),
                source: std::io::Error::other(why),
            })?;
        self.read.borrow_mut().insert(path.to_string(), got.clone());
        Ok(got)
    }
}

/// The files of one log's directory in a raw repository, as `LogFiles`.
struct LogDir<'a, 'h> {
    repo: &'a RawRepo<'h>,
    /// `log`, or `log/<n>`.
    dir: String,
}

impl LogFiles for LogDir<'_, '_> {
    fn read(&self, path: &str, limit: u64) -> std::result::Result<Option<Vec<u8>>, LogError> {
        self.repo.file(&format!("{}/{path}", self.dir), limit)
    }

    fn shown(&self, path: &str) -> String {
        self.repo.url(&format!("{}/{path}", self.dir))
    }
}

/// No files at all: the evidence a record names, which `--remote` does not fetch, so each piece is
/// reported unchecked rather than read.
struct NoFiles;

impl LogFiles for NoFiles {
    fn read(&self, _: &str, _: u64) -> std::result::Result<Option<Vec<u8>>, LogError> {
        Ok(None)
    }
}

/// One log of the chain as `--remote` reached it: where it is, and its checkpoint, verified.
struct RemoteLog {
    /// Which repository of the chain it is in.
    repo: usize,
    dir: String,
    /// The key it was opened under: the pinned one, or the one the log-end before it names.
    vkey: LogVkey,
    checkpoint: SignedCheckpoint,
}

/// A source read over HTTPS: its chain of logs, each checkpoint verified, and what a record is
/// checked against.
pub(crate) struct Remote<'h> {
    repos: Vec<RawRepo<'h>>,
    /// The `owner/repo` of each repository, for a person.
    names: Vec<String>,
    logs: Vec<RemoteLog>,
    keys: KeyHistory,
    /// When the chain's newest leaf was logged.
    pub newest: Option<u64>,
    /// What every answer from it says beyond the caveats.
    pub notes: Vec<String>,
}

/// Why a source could not be read over HTTPS.
pub(crate) struct Unread {
    /// Whether it failed verification — a checkpoint that does not open, or does not extend the
    /// one accepted — rather than could not be reached or read.
    pub refused: bool,
    pub why: String,
}

impl Unread {
    fn of(e: LogError, context: String) -> Unread {
        Unread {
            refused: e.fails_verification(),
            why: format!("{context}: {e}"),
        }
    }

    fn unreadable(why: String) -> Unread {
        Unread {
            refused: false,
            why,
        }
    }
}

/// Why an entry an index file lists was not answered from.
enum Unproven {
    /// What proves it could not be read — not served, refused, cut short, rate-limited, or past
    /// the checkpoint read — so the source cannot answer the question now: unknown, as a failed
    /// `--remote` lookup is (`docs/19` §4.2), and never taken for an attack.
    Unread(String),
    /// A proof that does not prove, or a leaf that is not the record listed: failed verification,
    /// because it may be an attack.
    Failed(String),
}

impl Unproven {
    /// A log error, by what it is: one that fails verification fails, and one that is only a file
    /// not read is unread.
    fn of(e: LogError, why: String) -> Unproven {
        match e.fails_verification() {
            true => Unproven::Failed(format!("{why}: {e}")),
            false => Unproven::Unread(format!("{why}: {e}")),
        }
    }
}

impl<'h> Remote<'h> {
    /// Read `source`'s chain over HTTPS: its log key and the checkpoint last accepted from its
    /// configuration and state, as the network-free verifier reads them; each log's checkpoint,
    /// opened under its key; its last leaf, proven included, for how recent it is and where it
    /// goes on; and the checkpoint last accepted held to the log it is of.
    pub(crate) fn open(
        http: &'h Http,
        config: &EvidenceConfig,
        source: &Source,
    ) -> std::result::Result<Remote<'h>, Unread> {
        let base = raw_base().map_err(|e| Unread::unreadable(format!("{e:#}")))?;
        let Some(first) = github_repository(source) else {
            return Err(Unread::unreadable(format!(
                "{:#}",
                unreadable_source(source)
            )));
        };
        // A source that has synced before and lost its checkpoint is refused, as a sync and every
        // read of its clones refuse it: that checkpoint is what a rollback is caught against.
        let pins = config.pins(&source.name).map_err(|e| Unread {
            refused: matches!(e, trigon_attest::config::ConfigError::StateLost { .. }),
            why: e.to_string(),
        })?;
        let mut notes = Vec::new();
        let dirs =
            Dirs::of(config, &source.name).map_err(|e| Unread::unreadable(format!("{e:#}")))?;
        // A source whose last sync was refused answers nothing until a sync of it works, however
        // it is asked: what refused it — mirrors serving two logs, a rollback — is not undone by
        // reading one of them over HTTPS (`docs/19` §6: 4, whatever else is said).
        match SyncRecord::read(&dirs.state) {
            Ok(Some(r)) => {
                if let Some(f) = r.refusal() {
                    return Err(Unread {
                        refused: true,
                        why: format!(
                            "its last sync was refused, and a refused source answers nothing, over \
                             HTTPS too, until a sync of it works: {}",
                            printable(&f.why)
                        ),
                    });
                }
            }
            Ok(None) => {}
            Err(e) => return Err(Unread::unreadable(e.to_string())),
        }
        let mut repinned = false;
        let recorded = match KeysFile::read(&dirs.state) {
            // A history recorded from another pin than the configuration's now is not this
            // source's: a key re-pinned away from would still be trusted through it.
            Ok(Some(k))
                if k.log_key != pins.log_key.to_string()
                    || k.attestation_key != pins.attestation_key.to_hex() =>
            {
                notes.push(format!(
                    "the key history the last sync recorded starts at the attestation key {} under \
                     the log key {}, and the source pins {} under {} now: the pin changed since, \
                     so every record is held to the pinned attestation key alone, and a sync \
                     follows the log's key changes from it",
                    printable(&k.attestation_key),
                    printable(&k.log_key),
                    pins.attestation_key.key_id(),
                    pins.log_key
                ));
                repinned = true;
                Ok(None)
            }
            other => other,
        };
        let keys = match recorded {
            Ok(Some(k)) => {
                let history = k.history().map_err(|why| {
                    Unread::unreadable(format!(
                        "{} is not a key history this can use: {why}",
                        dirs.state.join(trigon_attest::state::KEYS).display()
                    ))
                })?;
                if history
                    .epochs()
                    .first()
                    .is_none_or(|e| e.key.to_hex() != pins.attestation_key.to_hex())
                {
                    return Err(Unread::unreadable(format!(
                        "{} starts its key history at another key than the one it says it starts \
                         at; sync the source to write it again",
                        dirs.state.join(trigon_attest::state::KEYS).display()
                    )));
                }
                history
            }
            Ok(None) => {
                if !repinned {
                    notes.push(
                        "no sync has recorded this source's key history, so every record is held \
                         to its pinned attestation key alone: one signed by a key its log has \
                         changed to since fails verification here, and a sync follows the change"
                            .into(),
                    );
                }
                KeyHistory::new(pins.attestation_key.clone())
            }
            Err(e) => return Err(Unread::unreadable(e.to_string())),
        };
        let mut remote = Remote {
            repos: vec![RawRepo::new(http, &base, &first)],
            names: vec![first],
            logs: Vec::new(),
            keys,
            newest: None,
            notes,
        };
        let mut vkey = pins.log_key.clone();
        let mut at = (0usize, "log".to_string());
        // The log-end that named the log being opened, with the log it ended: that log's first
        // leaf is held to it.
        let mut ended: Option<(LogVkey, SignedCheckpoint, LogEndLeaf)> = None;
        loop {
            if remote.logs.len() >= MOST_LOGS {
                return Err(Unread {
                    refused: true,
                    why: format!(
                        "`{}`'s chain runs past {MOST_LOGS} logs, which no succession does",
                        source.name
                    ),
                });
            }
            let files = LogDir {
                repo: &remote.repos[at.0],
                dir: at.1.clone(),
            };
            let note = files
                .read("checkpoint", CHECKPOINT_LIMIT)
                .map_err(|e| Unread::of(e, format!("reading {}", files.shown("checkpoint"))))?
                .ok_or_else(|| {
                    Unread::unreadable(format!(
                        "{} is not there: nothing is served where the log should be",
                        files.shown("checkpoint")
                    ))
                })?;
            let checkpoint = SignedCheckpoint::open(&note, &vkey)
                .map_err(|e| Unread::of(e, files.shown("checkpoint")))?;
            let size = checkpoint.size();
            // A successor is followed only where its first leaf, proven, is the log-continuation
            // its predecessor's log-end requires, as a sync follows one (`docs/19` §8): a log the
            // log-end's key opens is not enough, since nothing else binds it to the log it goes on
            // from.
            if let Some((prev_vkey, prev_final, end)) = ended.take() {
                let first = match size {
                    0 => None,
                    _ => Some(proven_leaf(&files, &checkpoint, 0).map_err(|e| {
                        Unread::of(e, format!("the first leaf of `{}`", vkey.origin()))
                    })?),
                };
                check_continuation(&prev_vkey, &prev_final, &end, &vkey, first.as_ref()).map_err(
                    |e| {
                        Unread::of(
                            e,
                            format!(
                                "`{}` is not followed into `{}`",
                                prev_vkey.origin(),
                                vkey.origin()
                            ),
                        )
                    },
                )?;
            }
            // The last leaf, proven: how recent the log is, and whether it has ended.
            let last =
                match size {
                    0 => None,
                    n => Some(proven_leaf(&files, &checkpoint, n - 1).map_err(|e| {
                        Unread::of(e, format!("the last leaf of `{}`", vkey.origin()))
                    })?),
                };
            remote.newest = last.as_ref().map(Leaf::time).or(remote.newest);
            remote.logs.push(RemoteLog {
                repo: at.0,
                dir: at.1.clone(),
                vkey: vkey.clone(),
                checkpoint: checkpoint.clone(),
            });
            let Some(Leaf::LogEnd(end)) = last else {
                break;
            };
            let next = end.successor.clone();
            let named = successor_vkey(vkey.origin(), &end)
                .map_err(|e| Unread::of(e, "its log-end".into()))?;
            if remote
                .logs
                .iter()
                .any(|l| l.checkpoint.origin() == named.origin())
            {
                return Err(Unread {
                    refused: true,
                    why: format!(
                        "`{}`'s log-end names `{}`, which this chain has reached before: a \
                         succession never returns to an earlier log",
                        vkey.origin(),
                        named.origin()
                    ),
                });
            }
            ended = Some((vkey, checkpoint, end));
            vkey = named;
            if next.in_this_repository() {
                at = (at.0, next.dir.clone());
                continue;
            }
            let found = next.urls.iter().find_map(|u| {
                let l = Location::parse(u, std::path::Path::new("/"), None).ok()?;
                (l.transport() == Transport::Https)
                    .then(|| on_github(&l))
                    .flatten()
            });
            let Some(repository) = found else {
                return Err(Unread::unreadable(format!(
                    "`{}` ended, and its successor `{}` is at {}, none of which is a github.com \
                     repository --remote can read: sync the source to follow it",
                    remote.logs.last().map_or("", |l| l.checkpoint.origin()),
                    printable(&next.origin),
                    next.urls
                        .iter()
                        .map(|u| printable(u))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            };
            remote.notes.push(format!(
                "`{}` ended, and its successor `{}` is read from {repository}",
                remote.logs.last().map_or("", |l| l.checkpoint.origin()),
                printable(&next.origin)
            ));
            remote.repos.push(RawRepo::new(http, &base, &repository));
            remote.names.push(repository);
            at = (remote.repos.len() - 1, next.dir.clone());
        }
        if let Some((path, accepted)) = &pins.accepted {
            remote.hold_to(accepted).map_err(|e| {
                Unread::of(
                    e,
                    format!(
                        "what {} serves does not extend the checkpoint in {}",
                        remote.names[0],
                        path.display()
                    ),
                )
            })?;
        }
        Ok(remote)
    }

    /// Hold the chain to the checkpoint last accepted: the log of its origin must extend it, by a
    /// consistency proof from that log's tiles; a chain that does not reach its origin is behind
    /// it, a rollback.
    fn hold_to(&self, accepted: &[u8]) -> std::result::Result<(), LogError> {
        let origin =
            trigon_attest::log::Checkpoint::parse(SignedNote::parse(accepted)?.text())?.origin;
        let Some(log) = self.logs.iter().find(|l| l.checkpoint.origin() == origin) else {
            return Err(LogError::Inconsistent {
                why: format!(
                    "the checkpoint last accepted is for `{}`, and no log this source's chain \
                     reaches over HTTPS has that origin: what is served is behind what was \
                     accepted",
                    printable(&origin)
                ),
                accepted: String::from_utf8_lossy(accepted).into_owned(),
                offered: self
                    .logs
                    .last()
                    .map(|l| l.checkpoint.to_string())
                    .unwrap_or_default(),
            });
        };
        let a = SignedCheckpoint::open(accepted, &log.vkey)?;
        let files = LogDir {
            repo: &self.repos[log.repo],
            dir: log.dir.clone(),
        };
        verify_extension_from_tiles(&files, &log.vkey, &a).map(|_| ())
    }

    /// The chain as a person reads it: each log's origin and size, and where it was read.
    pub(crate) fn label(&self) -> String {
        let last = self.logs.last().expect("a chain has a log");
        format!(
            "as of {} leaves of `{}`, read over HTTPS from {}",
            last.checkpoint.size(),
            last.checkpoint.origin(),
            self.names.join(", then ")
        )
    }

    /// The checkpoint its answers are given from: the chain's last log's, as fetched and verified.
    pub(crate) fn checkpoint(&self) -> &Checkpoint {
        self.logs
            .last()
            .expect("a chain has a log")
            .checkpoint
            .checkpoint()
    }

    /// The origin of each log of the chain, by position.
    pub(crate) fn origins(&self) -> Vec<String> {
        self.logs
            .iter()
            .map(|l| l.checkpoint.origin().to_string())
            .collect()
    }

    /// Whether the chain is frozen under `freshness` at `now`: its newest leaf is older than
    /// `frozen_after`, or it has none.
    pub(crate) fn frozen(&self, freshness: &Freshness, now: u64) -> bool {
        self.newest
            .is_none_or(|t| now.saturating_sub(t) > freshness.frozen_after.as_secs())
    }

    /// Every record the index files for `key` list, each leaf proven included and each record
    /// checked against it, and the supersessions among them applied; with every entry whose leaf
    /// does not prove, which fails verification whatever record it names. An error where anything
    /// that answers could not be read: the source cannot answer the question, unknown.
    pub(crate) fn lookup(&self, key: &Key) -> Result<(Lookup, Vec<String>), String> {
        let mut found: Vec<Found> = Vec::new();
        let mut unproven = Vec::new();
        for (r, repo) in self.repos.iter().enumerate() {
            for index_key in key.index_keys() {
                let path = index_key.path();
                let bytes = repo
                    .file(&path, INDEX_LIMIT)
                    .map_err(|e| format!("reading {}: {e}", repo.url(&path)))?;
                let Some(bytes) = bytes else { continue };
                let file = match IndexFile::parse(&bytes) {
                    Ok(f) if f.key == index_key.name() => f,
                    Ok(f) => {
                        unproven.push(format!(
                            "{} is the index file of `{}`, and is served for `{}`: nothing it \
                             lists is taken for this key",
                            repo.url(&path),
                            printable(&f.key),
                            index_key.name()
                        ));
                        continue;
                    }
                    Err(e) => {
                        unproven.push(format!("{}: {e}", repo.url(&path)));
                        continue;
                    }
                };
                for entry in &file.records {
                    let dir = entry.log.clone().unwrap_or_else(|| "log".into());
                    let Some(log) = self.logs.iter().position(|l| l.repo == r && l.dir == dir)
                    else {
                        unproven.push(format!(
                            "{} lists sha256:{} at leaf {} of `{dir}`, a log this source's chain \
                             does not reach, so its leaf cannot be proven",
                            repo.url(&path),
                            entry.record.to_hex(),
                            entry.leaf
                        ));
                        continue;
                    };
                    let pos = LeafPos {
                        log,
                        index: entry.leaf,
                    };
                    if found.iter().any(|f| f.pos == pos) {
                        continue;
                    }
                    match self.record(key, pos, &entry.record) {
                        Ok(Some(f)) => found.push(f),
                        Ok(None) => {}
                        Err(Unproven::Failed(why)) => unproven.push(why),
                        Err(Unproven::Unread(why)) => return Err(why),
                    }
                }
            }
        }
        found.sort_by_key(|f| f.pos);
        Ok((Lookup::resolve(key.clone(), found), unproven))
    }

    /// The record an index entry names at `pos`: its leaf proven, and the record checked against
    /// it. `None` where the proven leaf is not filed under `key` — the index was altered, and the
    /// record is not one for this key.
    fn record(
        &self,
        key: &Key,
        pos: LeafPos,
        record: &trigon_core::Digest,
    ) -> std::result::Result<Option<Found>, Unproven> {
        let log = &self.logs[pos.log];
        let repo = &self.repos[log.repo];
        let files = LogDir {
            repo,
            dir: log.dir.clone(),
        };
        let origin = log.checkpoint.origin();
        let size = log.checkpoint.size();
        let listed = format!(
            "sha256:{} at leaf {} of `{origin}`",
            record.to_hex(),
            pos.index
        );
        // Past the checkpoint read of the log still being written: logged after it, and listed by
        // an index read a moment later — every file is read at whatever commit the host serves
        // then — or an index altered. Either way nothing read here proves or disproves it. Past
        // an ended log's final checkpoint, it can only be a lie.
        if pos.index >= size {
            let why = format!(
                "{listed} is listed past the {size} leaves of the checkpoint read, so its leaf \
                 cannot be proven"
            );
            return Err(match pos.log + 1 == self.logs.len() {
                true => Unproven::Unread(format!(
                    "{why}: a publish that landed while the files were read, or an index altered. \
                     Ask again, or sync the source and ask its clone"
                )),
                false => Unproven::Failed(format!(
                    "{why}, and that log has ended: the record fails verification"
                )),
            });
        }
        let leaf = proven_leaf(&files, &log.checkpoint, pos.index).map_err(|e| {
            let proves = e.fails_verification();
            Unproven::of(
                e,
                match proves {
                    true => format!(
                        "{listed}: its leaf could not be proven included in the tree the \
                         checkpoint signs, so the record fails verification"
                    ),
                    false => format!("{listed}: what proves its leaf could not be read"),
                },
            )
        })?;
        let Leaf::Record(leaf) = leaf else {
            return Err(Unproven::Failed(format!(
                "sha256:{} is listed at leaf {} of `{origin}`, which is a `{}` leaf and names no \
                 record",
                record.to_hex(),
                pos.index,
                leaf.kind()
            )));
        };
        if leaf.record != *record {
            return Err(Unproven::Failed(format!(
                "sha256:{} is listed at leaf {} of `{origin}`, and that leaf logs sha256:{}",
                record.to_hex(),
                pos.index,
                leaf.record.to_hex()
            )));
        }
        if !key.matches(&leaf) {
            return Ok(None);
        }
        let file = repo.file(&record_path(record), RECORD_LIMIT).map_err(|e| {
            Unproven::of(e, format!("reading the record sha256:{}", record.to_hex()))
        })?;
        let state = match file {
            None => RecordState::Deleted,
            Some(bytes) => {
                match check_record(
                    &bytes,
                    Some((pos, &leaf)),
                    origin,
                    &self.keys,
                    &NoFiles,
                    Some(key),
                ) {
                    Ok(v) => RecordState::Verified(Box::new(v)),
                    Err(why) => RecordState::Failed(why),
                }
            }
        };
        Ok(Some(Found {
            pos,
            leaf,
            state,
            superseded_by: Vec::new(),
        }))
    }
}

/// Leaf `index` of the tree `checkpoint` signs: read from its entry bundle, and proven included
/// from the tiles, so a bundle that lies is caught by the root it would have to hash to.
fn proven_leaf(
    files: &dyn LogFiles,
    checkpoint: &SignedCheckpoint,
    index: u64,
) -> std::result::Result<Leaf, LogError> {
    let size = checkpoint.size();
    let n = index / 256;
    let tile = Tile::at(0, n, size).ok_or_else(|| {
        LogError::Mismatch(format!(
            "leaf {index} is past the {size} leaves of `{}`",
            checkpoint.origin()
        ))
    })?;
    let bundle = Bundle {
        index: n,
        width: tile.width,
    };
    let path = bundle.path();
    let bytes = files
        .read(&path, u64::from(bundle.width) * (2 + 65_535))?
        .ok_or_else(|| LogError::Missing {
            path: files.shown(&path),
        })?;
    let entries = trigon_attest::log::tiles::decode_bundle(&bytes, &bundle)?;
    let entry = entries
        .get((index % 256) as usize)
        .ok_or_else(|| LogError::Mismatch(format!("`{path}` does not hold leaf {index}")))?;
    prove_inclusion_from_tiles(files, checkpoint, index, entry)?;
    Leaf::decode(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The base is HTTPS, or loopback over plain HTTP, and carries no user: what is read names the
    /// package asked about.
    #[test]
    fn the_raw_base_is_https_or_loopback_and_names_no_user() {
        assert_eq!(
            raw_base_from(None).unwrap().as_str(),
            "https://raw.githubusercontent.com/"
        );
        for ok in [
            "https://mirror.example/raw",
            "http://127.0.0.1:9",
            "http://localhost:9",
        ] {
            assert!(raw_base_from(Some(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "http://example.org/raw",
            "ftp://127.0.0.1/",
            "https://user:pw@example.org/",
            "not a url",
        ] {
            assert!(raw_base_from(Some(bad)).is_err(), "{bad}");
        }
    }
}
