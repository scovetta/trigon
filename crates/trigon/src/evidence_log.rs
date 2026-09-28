//! `trigon log keygen` and `trigon log sign`: the evidence log's key, and the one step that holds
//! it (`docs/19` §2.3, §8, §10 phase 5).
//!
//! **The log key is used by `log sign` and nothing else.** `publish` writes a new tree to disk and
//! runs `trigon log sign` as a child process; it never opens the key file itself, so the process
//! that talks to the network and the one that holds the key are never the same process. `log sign`
//! opens no socket — both builds carry it, as they carry `keygen`, so a key held on a machine that
//! has never had a socket open is a reasonable thing to want (docs/19 D5) — and it trusts nothing
//! `publish` hands it: it reads the tree from disk and signs only what
//! `trigon_attest::evidence::check_to_sign` accepts, a tree extending a checkpoint it verifies
//! under its own key, whose every new leaf names a record every client would accept.
//!
//! **And a tree extending the newest checkpoint of the log this host has published**
//! ([`NewestPublished`]), kept under the host's state directory by the log's origin, whatever store
//! or spelling of the repository `publish` ran with. The checkpoint a tree holds is not enough: a
//! repository rolled back holds an older one the key opens as well as the newest, and a tree built
//! on it would be a second root, under the same key, for a size already published. What is kept is
//! what was published, never merely signed: a checkpoint signed for a push that lost, or for one a
//! kill stopped, never left the host, and holding the key to it would stop the log for good.
//!
//! **A succession takes both log keys, twice** (`docs/19` §8). `trigon log succeed` writes the
//! log-end, and `log sign --successor-key` signs the final checkpoint with the log's key and
//! cosigns it with the successor's, which only a holder of both can do; the final checkpoint is
//! written with both signatures, and the successor's log-continuation holds that note. Then `log
//! sign --continuing` begins the successor under its own key, only as the log the predecessor's
//! log-end names, and only where every client would follow the pair.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use sha2::Digest as _;
use trigon_attest::config::{Env, check_origin, read_attestation_key};
use trigon_attest::evidence::{check_to_begin, check_to_sign};
use trigon_attest::location::printable;
use trigon_attest::log::{
    Checkpoint, DirFiles, KeyChangeLeaf, KeyHistory, Leaf, LogFiles as _, LogSigner,
    SignedCheckpoint, find_predecessor, verify_source,
};
use trigon_attest::{AttestationKey, LogVkey};

use crate::{field, style};

/// The longest `keys/attestation.pub` read: a PEM key is under 200 bytes.
const KEY_FILE_LIMIT: u64 = 16 * 1024;

/// `trigon log keygen --origin <o> --out <file>`: a new log key, in Go's private-key format,
/// written `0600` and never over a file already there, with its verifier key printed.
pub(crate) fn keygen(origin: &str, out: &Path) -> Result<()> {
    check_origin(origin).map_err(anyhow::Error::msg)?;
    // Refused rather than overwritten, as `keygen` refuses: a log whose key is lost can never sign
    // another checkpoint, and every client pinned to it is stranded with it.
    if out.exists() {
        bail!(
            "{} already exists. Refusing to overwrite a log key — a log whose key is gone can \
             never be extended, and every client pinned to it is stranded. Move it aside if that \
             is really what you want.",
            out.display()
        );
    }
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let signer = LogSigner::generate(origin)?;
    crate::create_private(out, &format!("{}\n", signer.to_skey()))?;

    field(
        "wrote",
        format!(
            "{} {}",
            style::ident(&out.display().to_string()),
            style::muted("(0600)")
        ),
    );
    println!();
    // Whole, never shortened: it is what a client pins, so it has to be copyable whole.
    field("log key", style::ident(&signer.vkey().to_string()));
    println!();
    println!(
        "{}",
        style::muted(&style::wrap(
            &format!(
                "Set `[publish] log_key` to this file in evidence.toml; only `trigon log sign` \
                 ever reads it. Clients pin the log key above as a source's `log_key`, and \
                 `trigon log init --origin {origin} --repo <location>` begins the log. Keep the \
                 file: a log whose key is lost can only be succeeded, never extended."
            ),
            0,
        ))
    );
    Ok(())
}

/// `trigon log public-key <file>`: the verifier key of a log key, as `keygen` printed it.
///
/// What a client pins, and what `trigon log succeed` names a successor by: it runs this as a child
/// process, so that the process that pushes never opens a log key.
pub(crate) fn public_key(key: &Path) -> Result<()> {
    println!("{}", LogSigner::from_file(key)?.vkey());
    Ok(())
}

/// `trigon log key-change-leaf`: the key-change leaf from the attestation key in `key` to the one
/// in `new_key`, logged at `time` in the log `origin`, signed by both and printed as the log holds
/// it (`docs/19` §8).
///
/// `trigon log key-change` runs this as a child process, as `publish` runs `log sign`: the
/// attestation key is opened by a process that opens no socket, as `trigon attest` is, and never by
/// the one that fetches and pushes, which checks what this prints before it logs it.
pub(crate) fn key_change_leaf(key: &Path, new_key: &Path, origin: &str, time: u64) -> Result<()> {
    check_origin(origin).map_err(anyhow::Error::msg)?;
    let old = crate::load_key(key).context("--key")?;
    let new = crate::load_key(new_key).context("--new-key")?;
    if old.public_hex() == new.public_hex() {
        bail!(
            "--key and --new-key are one key, {}: a key change hands over to another",
            AttestationKey::from(old.public_key()).key_id()
        );
    }
    // Said as what it is, the operator's mistake, and never as a log that could not be read.
    let leaf = KeyChangeLeaf::sign(origin, time, &old, &new)
        .map_err(|e| anyhow::anyhow!("the key change could not be signed: {e}"))?;
    println!("{}", String::from_utf8(Leaf::KeyChange(leaf).encode()?)?);
    Ok(())
}

/// What `trigon log sign` is given.
pub(crate) struct SignArgs {
    pub tree: PathBuf,
    pub key: PathBuf,
    /// The size of the tree to sign; `None` only with `init`.
    pub size: Option<u64>,
    /// The log's directory in the tree: `log`, or `log/<n>` for a successor.
    pub log: String,
    pub attestation_key: Option<String>,
    pub init: bool,
    /// The successor's log key, where the tree ends the log with a log-end naming it.
    pub successor_key: Option<PathBuf>,
    /// The tree holding the log this one continues: begin this log as its successor.
    pub continuing: Option<PathBuf>,
}

/// `trigon log sign`: check the tree and sign its checkpoint; with `--init`, begin a log; with
/// `--continuing`, begin a successor.
pub(crate) fn sign(args: SignArgs) -> Result<()> {
    let numbered = args.log.strip_prefix("log/").is_some_and(|n| {
        !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit())
    });
    if args.log != "log" && !numbered {
        bail!(
            "`{}` is not a log's directory: it is `log`, or `log/<n>` for a successor (docs/19 \
             §2.3)",
            printable(&args.log)
        );
    }
    let signer = LogSigner::from_file(&args.key)?;
    let env = Env::from_process()?;
    let newest = NewestPublished::of(&env, signer.name())?;
    let published = newest.open(&signer.vkey()).context("refusing to sign")?;
    if args.init {
        return begin(&args.tree, &args.log, &signer, &newest, published.as_ref());
    }
    let Some(size) = args.size else {
        bail!("--size says how many leaves the tree to sign has; it is needed unless --init");
    };
    if let Some(from) = &args.continuing {
        return continue_log(&args.tree, &args.log, size, &signer, from, &env);
    }
    let successor = match &args.successor_key {
        Some(p) => Some(LogSigner::from_file(p).context("--successor-key")?),
        None => None,
    };
    let current = match &args.attestation_key {
        Some(k) => read_attestation_key(k, &env.cwd, env.home.as_deref())
            .map_err(|e| anyhow::anyhow!("--attestation-key: {e}"))?,
        None if args.log == "log" => tree_attestation_key(&args.tree)?,
        None => chain_attestation_key(&args.tree, &args.log)?,
    };
    let ext = check_to_sign(
        &args.tree,
        &args.log,
        &signer.vkey(),
        size,
        &current,
        published.as_ref(),
        successor.as_ref().map(LogSigner::vkey).as_ref(),
    )
    .with_context(|| {
        format!(
            "refusing to sign (the newest checkpoint of `{}` published from this host is {})",
            signer.name(),
            newest.path().display()
        )
    })?;
    let signed = ext.sign(&signer)?;
    // A final checkpoint is cosigned by the successor's key, which `check_to_sign` held to the one
    // the log-end names: the note the successor's log-continuation holds, written here too, where
    // a reader of the old log sees the successor vouch for its end. A reader of this log ignores
    // the second line, as it ignores a witness's.
    let note = match &successor {
        Some(s) => signed.note().cosign(s)?.to_string(),
        None => signed.to_string(),
    };
    // The checkpoint the tree extends is the repository's as `publish` verified it, and this one
    // extends it; kept, so that a tree built later on anything older is refused. The new one is
    // not: it is published only once `publish` has pushed it.
    newest.advance(ext.base(), &signer.vkey())?;
    replace(
        &args.tree.join(&args.log).join("checkpoint"),
        note.as_bytes(),
    )?;
    println!(
        "signed    {} at {} leaves, extending {}{}",
        signed.origin(),
        signed.size(),
        ext.base().size(),
        match &successor {
            Some(s) => format!(", its final checkpoint, cosigned by {}", s.name()),
            None => String::new(),
        }
    );
    Ok(())
}

/// Begin the log at `dir` in `tree` as the successor of a log of the chain in `from` — the same
/// tree, or the old repository's for a successor elsewhere — whose log-end names `signer`'s key:
/// its first checkpoint, over its log-continuation leaf alone, signed only where
/// [`check_to_begin`] finds every rule a client follows a succession by holds.
///
/// The predecessor is found from `from`'s `keys/log.vkey`, and anchored by the continuation it
/// must hold: its final checkpoint signed by both log keys, which only `log sign
/// --successor-key` makes, and only for a log-end it checked. It must extend the newest checkpoint
/// of it this host has published; and a log this host has published is never begun again.
fn continue_log(
    tree: &Path,
    dir: &str,
    size: u64,
    signer: &LogSigner,
    from: &Path,
    env: &Env,
) -> Result<()> {
    let newest = NewestPublished::of(env, signer.name())?;
    if let Some(p) = newest.open(&signer.vkey())?.filter(|p| p.size() > 0) {
        bail!(
            "this host has published `{}` at {} leaves ({}), and it is begun once: a successor \
             begun again would sign a second root for every size up to that",
            p.origin(),
            p.size(),
            newest.path().display()
        );
    }
    let files = DirFiles::new(from);
    let pinned = files
        .read("keys/log.vkey", KEY_FILE_LIMIT)?
        .with_context(|| {
            format!(
                "{} is not there, so the chain the successor continues cannot be read",
                files.shown("keys/log.vkey")
            )
        })?;
    let pinned = String::from_utf8(pinned)
        .map_err(|_| anyhow::anyhow!("{} is not text", files.shown("keys/log.vkey")))?;
    let pinned = LogVkey::parse(pinned.trim())
        .with_context(|| format!("reading {}", files.shown("keys/log.vkey")))?;
    let refusing = || format!("refusing to begin `{}`", signer.name());
    let pred = find_predecessor(from, &pinned, &signer.vkey()).with_context(refusing)?;
    let published = NewestPublished::of(env, pred.origin())?.open(pred.vkey())?;
    let begun = check_to_begin(tree, dir, &signer.vkey(), size, &pred, published.as_ref())
        .with_context(refusing)?;
    let signed = begun
        .sign(signer, &DirFiles::in_repository(tree, dir))
        .with_context(refusing)?;
    replace(
        &tree.join(dir).join("checkpoint"),
        signed.to_string().as_bytes(),
    )?;
    println!(
        "signed    {} at {} leaves, beginning it as the successor of {} at {} leaves",
        signed.origin(),
        signed.size(),
        pred.origin(),
        pred.size()
    );
    Ok(())
}

/// The attestation key current at the end of the chain of logs a tree holds, for a successor's
/// tree at `dir`: the tree's `keys/attestation.pub`, the key the chain starts at, followed through
/// every key change of every log before it and of its own signed leaves. `check_to_sign` follows
/// the successor's again, and finds them applied.
fn chain_attestation_key(tree: &Path, dir: &str) -> Result<AttestationKey> {
    let pinned = tree_attestation_key(tree)?;
    let files = DirFiles::new(tree);
    let vkey = files
        .read("keys/log.vkey", KEY_FILE_LIMIT)?
        .with_context(|| {
            format!(
                "{} is not there, so the chain `{dir}` is in cannot be read",
                files.shown("keys/log.vkey")
            )
        })?;
    let vkey = LogVkey::parse(String::from_utf8_lossy(&vkey).trim())
        .with_context(|| format!("reading {}", files.shown("keys/log.vkey")))?;
    let source = verify_source(tree, &vkey, None)
        .with_context(|| format!("verifying the chain of logs `{dir}` is in"))?;
    if source.logs.last().map(|c| c.dir.as_str()) != Some(dir) {
        bail!(
            "`{}` is not the last log of the chain keys/log.vkey begins, and only the last log of a \
             chain is extended",
            printable(dir)
        );
    }
    let (history, _) = KeyHistory::from_source(pinned, &source)?;
    Ok(history.current().clone())
}

/// The attestation key the tree names as current: its `keys/attestation.pub`, read inside the
/// tree as every file of it is, since whoever can push wrote it.
pub(crate) fn tree_attestation_key(tree: &Path) -> Result<AttestationKey> {
    const PATH: &str = "keys/attestation.pub";
    let files = DirFiles::new(tree);
    let pem = files.read(PATH, KEY_FILE_LIMIT)?.with_context(|| {
        format!(
            "{} is not there, so the tree names no attestation key to check its records under",
            files.shown(PATH)
        )
    })?;
    let pem = String::from_utf8(pem)
        .map_err(|_| anyhow::anyhow!("{} is not a PEM file: it is not text", files.shown(PATH)))?;
    AttestationKey::from_pem(&pem).with_context(|| format!("reading {}", files.shown(PATH)))
}

/// Begin a log: `keys/log.vkey` and a checkpoint of size 0, whose root is SHA-256 of nothing, in a
/// tree that has neither (`docs/19` §10 phase 5, `log init`).
///
/// Refused where the tree has any of the log's files: a checkpoint of size 0 is where a log starts,
/// and one written over a log would begin it again, a second tree under the same key. Refused too
/// where this host has published the log: a log begun again under its key, in another repository,
/// would be a second root for every size the first was published at.
fn begin(
    tree: &Path,
    dir: &str,
    signer: &LogSigner,
    newest: &NewestPublished,
    published: Option<&SignedCheckpoint>,
) -> Result<()> {
    let log = tree.join(dir);
    let vkey = tree.join("keys/log.vkey");
    for there in [&log, &vkey] {
        if std::fs::symlink_metadata(there).is_ok() {
            bail!(
                "{} is already there, and a log is begun only in a tree that has none: a \
                 checkpoint of size 0 written over a log would begin it again under the same key",
                there.display()
            );
        }
    }
    if let Some(p) = published.filter(|p| p.size() > 0) {
        bail!(
            "this host has published `{}` at {} leaves ({}), and a log begun again under its key \
             would sign a second root for every size up to that. A new log takes a new origin and \
             a new key: `trigon log keygen --origin <origin> --out <file>`",
            p.origin(),
            p.size(),
            newest.path().display()
        );
    }
    // Where the tree has a `keys` already, it is a directory of the tree's own, never a link out of
    // it that the verifier key would be written through.
    match std::fs::symlink_metadata(tree.join("keys")) {
        Ok(m) if !m.is_dir() => bail!(
            "{} is a link or a file, and `keys/log.vkey` is written only into a directory of the \
             tree's own",
            tree.join("keys").display()
        ),
        _ => {}
    }
    let signed = SignedCheckpoint::sign(&Checkpoint::empty(signer.name()), signer)?;
    std::fs::create_dir_all(&log).with_context(|| format!("creating {}", log.display()))?;
    std::fs::create_dir_all(tree.join("keys"))
        .with_context(|| format!("creating {}", tree.join("keys").display()))?;
    replace(&vkey, format!("{}\n", signer.vkey()).as_bytes())?;
    replace(&log.join("checkpoint"), signed.to_string().as_bytes())?;
    println!("signed    {} at 0 leaves, a new log", signed.origin());
    Ok(())
}

/// Write `bytes` to `path` by renaming a file written beside it, so that a reader, or a crash, sees
/// the old file or the new one and never half of one. The rename replaces a link at `path` rather
/// than writing through it.
///
/// **The file beside it is made new, never opened.** `create_new` refuses anything already at its
/// name, a link included, where a plain write would follow a link and write wherever it leads; and
/// a working clone holds whatever whoever can push committed, links named like this one among them.
/// Something already there is removed — the link itself, never what it leads to — and another name
/// tried.
pub(crate) fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let dir = path
        .parent()
        .context("a file to replace is in a directory")?;
    let name = path
        .file_name()
        .context("a file to replace has a name")?
        .to_string_lossy();
    for attempt in 0..8 {
        let tmp = dir.join(format!(".{name}.{}.{attempt}.tmp", std::process::id()));
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&tmp);
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("creating {}", tmp.display())),
        };
        let written = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("writing {}", tmp.display()));
        }
        return std::fs::rename(&tmp, path).with_context(|| {
            let _ = std::fs::remove_file(&tmp);
            format!("replacing {}", path.display())
        });
    }
    bail!(
        "could not make a file of its own beside {} to replace it with: every name tried was \
         taken, and could not be removed",
        path.display()
    )
}

/// The directory a host keeps its publishing state in, whatever store a `publish` runs from:
/// `$XDG_STATE_HOME/trigon/publish`, or `~/.local/state/trigon/publish`.
pub(crate) fn host_state(env: &Env) -> Result<PathBuf> {
    env.state_home()
        .map(|d| d.join("trigon").join("publish"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "neither XDG_STATE_HOME nor HOME is set, and a host keeps the newest checkpoint \
                 of each log it has published under one of them, which `trigon log sign` holds \
                 every tree to. Set XDG_STATE_HOME"
            )
        })
}

/// The longest checkpoint file read: three lines and a signature, or a few kilobytes with
/// cosignatures.
const CHECKPOINT_FILE_LIMIT: u64 = 64 * 1024;

/// The newest checkpoint of one log this host has published, or verified on the repository it
/// publishes to: `<host state>/<sha256 of the origin>.checkpoint`, the signed note as it was.
///
/// Kept by the log, not by the store or by how the repository was named, so that every `publish`
/// on the host is held to it — one from a fresh store, or to the same repository spelled another
/// way — and so is `trigon log sign`, which refuses a tree that does not extend it. Only ever
/// moved forward, to a checkpoint that extends it.
pub(crate) struct NewestPublished {
    path: PathBuf,
}

impl NewestPublished {
    pub(crate) fn of(env: &Env, origin: &str) -> Result<NewestPublished> {
        let hash: String = sha2::Sha256::digest(origin.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(NewestPublished {
            path: host_state(env)?.join(format!("{hash}.checkpoint")),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The signed note as it is kept, or `None` where this host has published nothing of the log.
    pub(crate) fn bytes(&self) -> Result<Option<Vec<u8>>> {
        use std::io::Read as _;
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };
        let mut bytes = Vec::new();
        file.take(CHECKPOINT_FILE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", self.path.display()))?;
        if bytes.len() as u64 > CHECKPOINT_FILE_LIMIT {
            bail!(
                "{} is longer than {CHECKPOINT_FILE_LIMIT} bytes, and no checkpoint is",
                self.path.display()
            );
        }
        Ok(Some(bytes))
    }

    /// The checkpoint kept, opened under the log's key: a checkpoint of this log published from
    /// this host that the key does not open is a second key under one origin, and refused.
    pub(crate) fn open(&self, vkey: &LogVkey) -> Result<Option<SignedCheckpoint>> {
        let Some(bytes) = self.bytes()? else {
            return Ok(None);
        };
        let why = || {
            format!(
                "{}, the newest checkpoint of `{}` this host has published, is not one the log \
                 key {} opens: a log is signed by one key, and a new key takes a new origin",
                self.path.display(),
                vkey.origin(),
                vkey
            )
        };
        SignedCheckpoint::open(&bytes, vkey)
            .map(Some)
            .with_context(why)
    }

    /// Keep `checkpoint`, which the caller has verified extends the one kept, unless the one kept
    /// is already as large: this only ever moves forward.
    pub(crate) fn advance(&self, checkpoint: &SignedCheckpoint, vkey: &LogVkey) -> Result<()> {
        if let Some(kept) = self.open(vkey)?
            && kept.size() >= checkpoint.size()
        {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        replace(&self.path, checkpoint.to_string().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link planted at the name of the file `replace` writes beside its target is never written
    /// through: the file it leads to keeps its bytes, and the target is a file of its own.
    #[test]
    fn a_file_is_replaced_and_never_written_through_a_link() {
        let dir = std::env::temp_dir().join(format!("trigon-replace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("log")).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "precious").unwrap();
        let pid = std::process::id();
        for n in 0..3 {
            std::os::unix::fs::symlink(&victim, dir.join(format!("log/.checkpoint.{pid}.{n}.tmp")))
                .unwrap();
        }
        // And a link at the target itself, which the rename replaces.
        std::os::unix::fs::symlink(&victim, dir.join("log/checkpoint")).unwrap();
        replace(&dir.join("log/checkpoint"), b"signed").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        let m = std::fs::symlink_metadata(dir.join("log/checkpoint")).unwrap();
        assert!(m.is_file(), "the checkpoint is a file of its own");
        assert_eq!(
            std::fs::read(dir.join("log/checkpoint")).unwrap(),
            b"signed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
