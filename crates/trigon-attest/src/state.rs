//! What a client keeps of each evidence source it syncs, outside the source's clones (`docs/19`
//! §2.4, §6.1): `<state>/<name>/`, where `<state>` is `TRIGON_EVIDENCE_STATE` or
//! `$XDG_STATE_HOME/trigon/evidence`.
//!
//! - [`CHECKPOINT`]: the last checkpoint accepted for the source, the signed note exactly as it
//!   was accepted. Every later one must extend it, and a clone older than it is a rollback.
//! - [`KEYS`]: the source's key history — the log key and attestation key its chain starts at,
//!   every log key of the chain after a succession, and every attestation key after a key change —
//!   and, for a source that trusts on first use, where and when its keys were first read.
//! - [`SYNC`]: when the source was last synced, whether that worked, and what it found: the
//!   freshness clock `stale_after` is read against, and what `trigon evidence list` shows.
//!
//! **Outside the clone, and never trusted over the log.** The checkpoint is what the log is held
//! to, and it is a signed note that is opened again under the source's key whenever it is read.
//! The key history is derived from the log, and kept so that a change to it is seen: whenever the
//! log is verified again the history is recomputed, the log wins, and a disagreement is reported.
//! Only the keys a source trusting on first use read on first contact are not derivable, and are
//! what every later sync of it is pinned by.
//!
//! Each file is written whole to a temporary name beside it and renamed over the old, so a reader
//! sees the old file or the new and never half of one. Here, in `trigon-attest`, because both
//! builds read them: the network-free verifier holds a record to a source's accepted checkpoint and
//! recorded keys, and opens no socket to do it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::log::{KeyEpoch, KeyHistory, LeafPos, VerifiedLog};
use crate::{AttestationKey, LogVkey};

/// The last accepted checkpoint, as `config` names it too.
pub const CHECKPOINT: &str = crate::config::ACCEPTED_CHECKPOINT;

/// The key history.
pub const KEYS: &str = "keys";

/// When the source was synced, and what was found.
pub const SYNC: &str = "sync";

/// In the git directory of a clone a sync made and has not yet accepted: a clone with it is no
/// evidence that the source synced before, and a sync makes it again rather than fetching into it.
pub const UNACCEPTED: &str = "trigon-unaccepted";

const KEYS_SCHEMA: &str = "trigon.evidence-keys/v1";
const SYNC_SCHEMA: &str = "trigon.evidence-sync/v1";

/// The longest state file read. A key history of a thousand rotations is still under this.
const STATE_FILE_LIMIT: u64 = 1 << 20;

/// A state file that is there and cannot be read as one: said with the file, since it is the
/// user's own disk and not the source that is at fault.
#[derive(Debug, thiserror::Error)]
#[error("{}: {why}", path.display())]
pub struct StateError {
    pub path: PathBuf,
    pub why: String,
}

/// Where a key a source trusts on first use was read, and when (`docs/19` §2.4): every answer from
/// such a source says it rests on these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirstUse {
    /// The location whose `keys/` was read, as `git` was given it.
    pub read_from: String,
    /// When, in Unix seconds.
    pub at: u64,
}

/// One log of a source's chain, and the key it is signed with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainLog {
    pub origin: String,
    /// Its C2SP verifier key.
    pub log_key: String,
}

/// A leaf's place in a source's chain, as [`LeafPos`] counts it, with the log's origin for a
/// person reading the file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Place {
    pub log: usize,
    pub origin: String,
    pub index: u64,
}

/// One attestation key's time as the source's key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Epoch {
    pub key_id: String,
    /// 64 hex digits.
    pub public_key: String,
    /// The key-change leaf that made it current; `None` for the key the chain starts at.
    pub from: Option<Place>,
    /// The key-change leaf that retired it; `None` for the current key.
    pub until: Option<Place>,
}

/// `<state>/<name>/keys`: the keys a source's chain starts at, and every key it has had since.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeysFile {
    pub schema: String,
    /// The log key the chain starts at: the pinned one, or the one trust on first use read.
    pub log_key: String,
    /// The attestation key the chain starts at, 64 hex digits.
    pub attestation_key: String,
    /// Where the keys were first read, for a source that trusts on first use; `None` for one
    /// whose keys are pinned in its configuration.
    pub first_use: Option<FirstUse>,
    /// Every log of the chain, from the one the chain starts at, each with its key.
    pub logs: Vec<ChainLog>,
    /// Every attestation key the chain has had, in order.
    pub attestation_keys: Vec<Epoch>,
}

impl KeysFile {
    /// The history of a chain just verified: `log_key` and `attestation_key` are the keys it was
    /// verified from, `chain` its logs, and `history` the attestation keys followed through them.
    pub fn of(
        log_key: &LogVkey,
        attestation_key: &AttestationKey,
        first_use: Option<FirstUse>,
        chain: &[&VerifiedLog],
        history: &KeyHistory,
    ) -> KeysFile {
        let place = |p: LeafPos| Place {
            log: p.log,
            origin: chain
                .get(p.log)
                .map_or_else(String::new, |l| l.origin().to_string()),
            index: p.index,
        };
        KeysFile {
            schema: KEYS_SCHEMA.into(),
            log_key: log_key.to_string(),
            attestation_key: attestation_key.to_hex(),
            first_use,
            logs: chain
                .iter()
                .map(|l| ChainLog {
                    origin: l.origin().to_string(),
                    log_key: l.vkey().to_string(),
                })
                .collect(),
            attestation_keys: history
                .epochs()
                .iter()
                .map(|e| Epoch {
                    key_id: e.key.key_id(),
                    public_key: e.key.to_hex(),
                    from: e.from.map(place),
                    until: e.until.map(place),
                })
                .collect(),
        }
    }

    /// The log key the chain starts at.
    pub fn log_vkey(&self) -> Result<LogVkey, String> {
        LogVkey::parse(&self.log_key).map_err(|e| format!("its `logKey`: {e}"))
    }

    /// The attestation keys the chain has had, as the sync that wrote this followed them: what a
    /// reader holding only some leaves checks a record's key against (`--remote`).
    pub fn history(&self) -> Result<KeyHistory, String> {
        let pos = |p: &Place| LeafPos {
            log: p.log,
            index: p.index,
        };
        let mut epochs = Vec::with_capacity(self.attestation_keys.len());
        for e in &self.attestation_keys {
            epochs.push(KeyEpoch {
                key: AttestationKey::from_hex(&e.public_key)
                    .map_err(|x| format!("its key {}: {x}", e.key_id))?,
                from: e.from.as_ref().map(pos),
                until: e.until.as_ref().map(pos),
            });
        }
        KeyHistory::from_epochs(epochs).map_err(|e| e.to_string())
    }

    /// The attestation key the chain starts at.
    pub fn start_key(&self) -> Result<AttestationKey, String> {
        AttestationKey::from_hex(&self.attestation_key)
            .map_err(|e| format!("its `attestationKey`: {e}"))
    }

    /// What this history says that `now`, the one the log gives, does not: each difference in
    /// words. Empty where they agree. The log wins either way; this is what is reported.
    pub fn differences(&self, now: &KeysFile) -> Vec<String> {
        let mut out = Vec::new();
        if self.log_key != now.log_key {
            out.push(format!(
                "it starts at the log key {}, and the chain is verified from {}",
                self.log_key, now.log_key
            ));
        }
        if self.attestation_key != now.attestation_key {
            out.push(format!(
                "it starts at the attestation key {}, and the chain is verified from {}",
                self.attestation_key, now.attestation_key
            ));
        }
        let logs = |f: &KeysFile| -> Vec<String> {
            f.logs
                .iter()
                .map(|l| format!("{} ({})", l.origin, l.log_key))
                .collect()
        };
        let (was, is) = (logs(self), logs(now));
        // A chain that has grown by a succession is the history going on, not disagreeing with it.
        if !is.starts_with(&was) {
            out.push(format!(
                "it records the logs {}, and the log's chain is {}",
                was.join(" → "),
                is.join(" → ")
            ));
        }
        let keys = |f: &KeysFile| -> Vec<(String, Option<Place>)> {
            f.attestation_keys
                .iter()
                .map(|e| (e.public_key.clone(), e.from.clone()))
                .collect()
        };
        let (was, is) = (keys(self), keys(now));
        if !is.starts_with(&was) {
            let said = |k: &[(String, Option<Place>)]| {
                k.iter()
                    .map(|(key, from)| match from {
                        Some(p) => format!("{key} from leaf {} of `{}`", p.index, p.origin),
                        None => key.clone(),
                    })
                    .collect::<Vec<_>>()
                    .join(", then ")
            };
            out.push(format!(
                "it records the attestation keys {}, and the log's key changes give {}",
                said(&was),
                said(&is)
            ));
        }
        out
    }

    /// `<dir>/keys`, or `None` where there is none.
    pub fn read(dir: &Path) -> Result<Option<KeysFile>, StateError> {
        let path = dir.join(KEYS);
        let Some(bytes) = read_file(&path)? else {
            return Ok(None);
        };
        let file: KeysFile = serde_json::from_slice(&bytes).map_err(|e| StateError {
            path: path.clone(),
            why: format!("it is not a key history this build reads ({e})"),
        })?;
        if file.schema != KEYS_SCHEMA {
            return Err(StateError {
                path,
                why: format!(
                    "its schema is `{}`, and this build reads `{KEYS_SCHEMA}`",
                    file.schema
                ),
            });
        }
        Ok(Some(file))
    }

    /// Write it to `<dir>/keys`, whole or not at all.
    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        write_json(&dir.join(KEYS), self)
    }
}

/// A sync that did not work, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Failure {
    pub at: u64,
    pub why: String,
    /// Whether the source failed verification — an equivocation, a checkpoint that does not extend
    /// the accepted one, a rollback, mirrors that disagree, a missing state file — rather than
    /// could not be reached or read: a source that may be lying, which `docs/19` §6 gives exit 4
    /// whatever else it says.
    pub refused: bool,
}

/// One location of a source, as the last sync found it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UrlSeen {
    /// As `git` was given it.
    pub url: String,
    pub transport: String,
    /// The leaves its copy of the chain's last log has, where it was verified.
    pub size: Option<u64>,
    /// `answering`, `lagging` or `unreachable`.
    pub state: String,
    pub note: Option<String>,
}

/// One log of the chain as the last sync that worked accepted it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogSeen {
    pub origin: String,
    pub size: u64,
}

/// `<state>/<name>/sync`: the source's freshness, and what its last sync found.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncRecord {
    pub schema: String,
    /// When a sync last worked, in Unix seconds: what `stale_after` is measured from.
    pub last_success: Option<u64>,
    /// When a sync was last tried.
    pub last_attempt: Option<u64>,
    /// The last sync's failure, where it failed; cleared by one that works.
    pub failure: Option<Failure>,
    /// When the newest leaf of the chain was logged, as of the last sync that worked: what
    /// `frozen_after` is measured from, until the clone is verified again.
    pub newest_leaf: Option<u64>,
    /// The chain as last accepted.
    pub logs: Vec<LogSeen>,
    /// Each location, as last seen.
    pub urls: Vec<UrlSeen>,
}

impl SyncRecord {
    /// `<dir>/sync`, or `None` where there is none.
    pub fn read(dir: &Path) -> Result<Option<SyncRecord>, StateError> {
        let path = dir.join(SYNC);
        let Some(bytes) = read_file(&path)? else {
            return Ok(None);
        };
        let r: SyncRecord = serde_json::from_slice(&bytes).map_err(|e| StateError {
            path: path.clone(),
            why: format!("it is not a sync record this build reads ({e})"),
        })?;
        if r.schema != SYNC_SCHEMA {
            return Err(StateError {
                path,
                why: format!(
                    "its schema is `{}`, and this build reads `{SYNC_SCHEMA}`",
                    r.schema
                ),
            });
        }
        Ok(Some(r))
    }

    /// Write it to `<dir>/sync`, whole or not at all.
    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        let mut r = self.clone();
        r.schema = SYNC_SCHEMA.into();
        write_json(&dir.join(SYNC), &r)
    }

    /// The failure, where the last sync was refused rather than merely not reached: one newer
    /// than the last sync that worked.
    pub fn refusal(&self) -> Option<&Failure> {
        self.failure
            .as_ref()
            .filter(|f| f.refused && self.last_success.is_none_or(|s| f.at >= s))
    }
}

/// Whether `cache`, a source's `<cache>/<name>`, keeps a clone a sync accepted: evidence that the
/// source has synced before, whatever its state directory now says. A clone still marked
/// [`UNACCEPTED`] is not one, and nor is a directory whose name begins with a dot, which is where a
/// clone is made before it is marked.
pub fn has_accepted_clone(cache: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(cache) else {
        return false;
    };
    entries.flatten().any(|e| {
        let git = e.path().join(".git");
        !e.file_name().to_string_lossy().starts_with('.')
            && git.is_dir()
            && !git.join(UNACCEPTED).exists()
    })
}

/// Whether a source has synced before, by what its state directory `dir` and its clones under
/// `cache` hold: a sync of it worked, it recorded keys trusted on first use, or a clone it accepted
/// is kept. What a missing checkpoint is then judged by: lost, rather than never accepted.
pub fn synced_before(dir: &Path, cache: Option<&Path>) -> Result<bool, StateError> {
    let worked = SyncRecord::read(dir)?.is_some_and(|s| s.last_success.is_some());
    let recorded = KeysFile::read(dir)?.is_some_and(|k| k.first_use.is_some());
    Ok(worked || recorded || cache.is_some_and(has_accepted_clone))
}

/// `<dir>/checkpoint`, the last accepted checkpoint as it was accepted, or `None` where there is
/// none.
pub fn read_checkpoint(dir: &Path) -> Result<Option<Vec<u8>>, StateError> {
    read_file(&dir.join(CHECKPOINT))
}

/// Write the accepted checkpoint, whole or not at all.
pub fn write_checkpoint(dir: &Path, note: &[u8]) -> std::io::Result<()> {
    write_atomic(&dir.join(CHECKPOINT), note)
}

/// A state file: `None` where it is not there, and refused where it is not a small regular file.
fn read_file(path: &Path) -> Result<Option<Vec<u8>>, StateError> {
    use std::io::Read as _;
    let refuse = |why: String| StateError {
        path: path.to_path_buf(),
        why,
    };
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(refuse(format!("it cannot be read ({e})"))),
    };
    let meta = file
        .metadata()
        .map_err(|e| refuse(format!("it cannot be read ({e})")))?;
    if !meta.is_file() {
        return Err(refuse("it is not a regular file".into()));
    }
    let mut bytes = Vec::new();
    file.take(STATE_FILE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refuse(format!("it cannot be read ({e})")))?;
    if bytes.len() as u64 > STATE_FILE_LIMIT {
        return Err(refuse(format!(
            "it is larger than {STATE_FILE_LIMIT} bytes"
        )));
    }
    Ok(Some(bytes))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

/// Write `bytes` to `path` whole or not at all: to a temporary file beside it, flushed to disk,
/// then renamed over it, which a reader sees as the old file or the new.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let written = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalKey;
    use crate::log::{KeyChangeLeaf, KeyHistory, LeafPos};

    /// The key history a sync records is the one `--remote` reads back: the same keys, each over
    /// the leaves the key changes gave it, and a record's key asked of it answered as the log's
    /// own history answers it. A history whose keys do not follow one another is refused.
    #[test]
    fn a_recorded_key_history_reads_back_as_the_one_the_log_gave() {
        let (old, new) = (
            LocalKey::from_bytes(&[1; 32]).unwrap(),
            LocalKey::from_bytes(&[2; 32]).unwrap(),
        );
        let pinned = AttestationKey::from(old.public_key());
        let mut history = KeyHistory::new(pinned.clone());
        let at = LeafPos { log: 0, index: 4 };
        let change = KeyChangeLeaf::sign("example.com/log", 10, &old, &new).unwrap();
        history.follow(at, "example.com/log", &change).unwrap();
        let file = KeysFile {
            schema: KEYS_SCHEMA.into(),
            log_key: String::new(),
            attestation_key: pinned.to_hex(),
            first_use: None,
            logs: Vec::new(),
            attestation_keys: KeysFile::of(
                &crate::log::LogSigner::from_seed("example.com/log", [3; 32])
                    .unwrap()
                    .vkey(),
                &pinned,
                None,
                &[],
                &history,
            )
            .attestation_keys,
        };
        let read = file.history().unwrap();
        assert_eq!(read, history);
        let new_id = AttestationKey::from(new.public_key()).key_id();
        let before = LeafPos { log: 0, index: 2 };
        let after = LeafPos { log: 0, index: 9 };
        assert!(read.key_for(&pinned.key_id(), before).is_ok());
        assert!(read.key_for(&pinned.key_id(), after).is_err());
        assert!(read.key_for(&new_id, after).is_ok());

        // A second key that no change made current is not a history.
        let mut broken = file.clone();
        broken.attestation_keys[1].from = None;
        assert!(broken.history().is_err());
        let mut broken = file;
        broken.attestation_keys[0].until = None;
        assert!(broken.history().is_err());
    }

    fn keys_file() -> KeysFile {
        KeysFile {
            schema: KEYS_SCHEMA.into(),
            log_key: "example.com/log+00000000+AQ".into(),
            attestation_key: "a".repeat(64),
            first_use: None,
            logs: Vec::new(),
            attestation_keys: Vec::new(),
        }
    }

    /// A key history that starts at another key than the chain is verified from says so, whichever
    /// key it is: the log wins, and the difference is what is reported.
    #[test]
    fn a_history_that_starts_at_other_keys_says_which() {
        let was = keys_file();
        let mut now = keys_file();
        now.log_key = "example.com/log+11111111+AQ".into();
        now.attestation_key = "b".repeat(64);
        let d = was.differences(&now);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(
            d[0].contains("starts at the log key example.com/log+00000000+AQ")
                && d[0].contains("verified from example.com/log+11111111+AQ"),
            "{d:?}"
        );
        assert!(d[1].contains("starts at the attestation key aaaa"), "{d:?}");
        assert!(was.differences(&keys_file()).is_empty());
    }

    /// A state file that is there and is not one this build reads is refused with the file, never
    /// read as absent: it is what a rollback is caught against, and what a source is pinned by.
    #[test]
    fn a_state_file_this_build_does_not_read_is_refused_with_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        assert!(KeysFile::read(dir).unwrap().is_none());
        assert!(SyncRecord::read(dir).unwrap().is_none());
        assert!(read_checkpoint(dir).unwrap().is_none());

        std::fs::write(dir.join(KEYS), b"not json").unwrap();
        let e = KeysFile::read(dir).unwrap_err();
        assert_eq!(e.path, dir.join(KEYS));
        assert!(e.why.contains("not a key history this build reads"), "{e}");

        let mut later = keys_file();
        later.schema = "trigon.evidence-keys/v2".into();
        later.write(dir).unwrap();
        let e = KeysFile::read(dir).unwrap_err();
        assert!(
            e.why
                .contains("its schema is `trigon.evidence-keys/v2`, and this build reads"),
            "{e}"
        );
        keys_file().write(dir).unwrap();
        assert_eq!(KeysFile::read(dir).unwrap(), Some(keys_file()));

        let r = serde_json::json!({ "schema": "trigon.evidence-sync/v0", "logs": [], "urls": [] });
        std::fs::write(dir.join(SYNC), r.to_string()).unwrap();
        let e = SyncRecord::read(dir).unwrap_err();
        assert_eq!(e.path, dir.join(SYNC));
        assert!(
            e.why.contains("its schema is `trigon.evidence-sync/v0`"),
            "{e}"
        );
        SyncRecord::default().write(dir).unwrap();
        assert!(SyncRecord::read(dir).unwrap().is_some());
    }

    /// A state file is a small regular file: a directory in its place, one past the limit, or a
    /// state directory that is itself a file is refused, never read as no file at all.
    #[test]
    fn a_state_file_that_is_not_a_small_regular_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dir.join(CHECKPOINT)).unwrap();
        let e = read_checkpoint(dir).unwrap_err();
        assert!(e.why.contains("not a regular file"), "{e}");
        std::fs::remove_dir(dir.join(CHECKPOINT)).unwrap();

        write_checkpoint(dir, &vec![b'x'; STATE_FILE_LIMIT as usize + 1]).unwrap();
        let e = read_checkpoint(dir).unwrap_err();
        assert!(e.why.contains("larger than"), "{e}");
        write_checkpoint(dir, &vec![b'x'; STATE_FILE_LIMIT as usize]).unwrap();
        assert_eq!(
            read_checkpoint(dir).unwrap().map(|b| b.len()),
            Some(STATE_FILE_LIMIT as usize)
        );

        let file = dir.join("a-file");
        std::fs::write(&file, b"").unwrap();
        let e = read_checkpoint(&file).unwrap_err();
        assert_eq!(e.path, file.join(CHECKPOINT));
        assert!(e.why.contains("cannot be read"), "{e}");
    }
}
