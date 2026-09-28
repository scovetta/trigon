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

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use sha2::Digest as _;
use trigon_attest::config::{Env, check_origin, read_attestation_key};
use trigon_attest::evidence::check_to_sign;
use trigon_attest::location::printable;
use trigon_attest::log::{Checkpoint, DirFiles, LogFiles as _, LogSigner, SignedCheckpoint};
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
}

/// `trigon log sign`: check the tree and sign its checkpoint, or, with `--init`, begin a log.
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
    let current = match &args.attestation_key {
        Some(k) => read_attestation_key(k, &env.cwd, env.home.as_deref())
            .map_err(|e| anyhow::anyhow!("--attestation-key: {e}"))?,
        None => tree_attestation_key(&args.tree)?,
    };
    let ext = check_to_sign(
        &args.tree,
        &args.log,
        &signer.vkey(),
        size,
        &current,
        published.as_ref(),
    )
    .with_context(|| {
        format!(
            "refusing to sign (the newest checkpoint of `{}` published from this host is {})",
            signer.name(),
            newest.path().display()
        )
    })?;
    let signed = ext.sign(&signer)?;
    // The checkpoint the tree extends is the repository's as `publish` verified it, and this one
    // extends it; kept, so that a tree built later on anything older is refused. The new one is
    // not: it is published only once `publish` has pushed it.
    newest.advance(ext.base(), &signer.vkey())?;
    replace(
        &args.tree.join(&args.log).join("checkpoint"),
        signed.to_string().as_bytes(),
    )?;
    println!(
        "signed    {} at {} leaves, extending {}",
        signed.origin(),
        signed.size(),
        ext.base().size()
    );
    Ok(())
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
