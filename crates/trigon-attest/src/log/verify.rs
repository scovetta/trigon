//! Verifying a log from its files (`docs/19` §6, §8), and a source's chain of logs.
//!
//! [`verify_log`] is what every client does on every sync, which makes each one a full monitor
//! rather than a sampler: the checkpoint's signature and origin under the pinned key; every leaf
//! of every entry bundle the checkpoint's tree has, decoded strictly, hashed, and the root
//! recomputed and compared; leaf times that never go backwards; every tile the tree has, checked
//! against the recomputed hashes, since a reader proving inclusion from the tiles relies on them;
//! and, given the checkpoint last accepted, that the new one extends it. Nothing beyond the
//! checkpoint's size is read as part of the log: a planted bundle or tile is simply not opened.
//!
//! [`verify_extension_from_tiles`] and [`prove_inclusion_from_tiles`] are the same questions asked
//! of a log whose leaves are not at hand — only its checkpoint and tiles — which is what a reader
//! over HTTPS has (`docs/19` §6 `--remote`).
//!
//! [`verify_source`] walks a repository's chain of logs: `log/`, then each successor a `log-end`
//! leaf names, followed only as [`follow`] allows.

use std::path::Path;

use super::LogError;
use super::checkpoint::{Checkpoint, SignedCheckpoint};
use super::files::{DirFiles, LogFiles};
use super::leaf::{Leaf, LogEndLeaf, Successor};
use super::merkle::{
    Hash, Tree, consistency_proof, inclusion_proof, leaf_hash, root_of, verify_consistency,
    verify_inclusion,
};
use super::note::{LogSigner, SignedNote};
use super::tiles::{
    Append, Bundle, TILE_WIDTH, Tile, TileHashes, bundle_limit, decode_bundle, decode_tile,
    plan_append, tile_limit,
};
use crate::LogVkey;
use crate::location::printable;

/// The checkpoint's path in a log's directory.
pub const CHECKPOINT: &str = "checkpoint";

/// The longest checkpoint note read. Ours is three lines and a signature; a hundred witness
/// cosignatures would still be a few kilobytes.
const CHECKPOINT_LIMIT: u64 = 64 * 1024;

/// A log whose every leaf was read, decoded and hashed to the root its checkpoint signs.
///
/// The leaves are kept decoded and not also as bytes: a leaf is read only in canonical form, so
/// writing it again gives back exactly the bytes it was read from, and a log of a million leaves
/// is not held twice.
#[derive(Clone, Debug)]
pub struct VerifiedLog {
    checkpoint: SignedCheckpoint,
    vkey: LogVkey,
    tree: Tree,
    leaves: Vec<Leaf>,
}

impl VerifiedLog {
    pub fn checkpoint(&self) -> &SignedCheckpoint {
        &self.checkpoint
    }

    /// The key the log was verified under.
    pub fn vkey(&self) -> &LogVkey {
        &self.vkey
    }

    pub fn origin(&self) -> &str {
        self.checkpoint.origin()
    }

    pub fn size(&self) -> u64 {
        self.checkpoint.size()
    }

    /// The tree over every leaf, for proofs.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Every leaf with its index, in order.
    pub fn leaves(&self) -> impl Iterator<Item = (u64, &Leaf)> {
        self.leaves.iter().enumerate().map(|(i, l)| (i as u64, l))
    }

    pub fn leaf(&self, index: u64) -> Option<&Leaf> {
        self.leaves.get(usize::try_from(index).ok()?)
    }

    /// A leaf's bytes, as its bundle holds them: what its hash is of.
    pub fn entry(&self, index: u64) -> Option<Vec<u8>> {
        let leaf = self.leaf(index)?;
        Some(
            leaf.encode()
                .expect("a leaf read from a verified log writes back"),
        )
    }

    /// When the newest leaf was logged: what a client's frozen clock reads (§6).
    pub fn newest_time(&self) -> Option<u64> {
        self.leaves.last().map(Leaf::time)
    }

    /// The log-end leaf, which is always the last, where the log has ended.
    pub fn log_end(&self) -> Option<&LogEndLeaf> {
        match self.leaves.last() {
            Some(Leaf::LogEnd(end)) => Some(end),
            _ => None,
        }
    }

    /// Plan appending `new` leaves, as `publish` will (`docs/19` §10 phase 5): the tiles and
    /// bundles to write and the partials to remove. Refused if a new leaf is earlier than the one
    /// before it, if the log has ended, if a log-end or log-continuation leaf is out of place, or
    /// if a leaf is one a reader would refuse ([`Self::check_for_readers`]).
    pub fn plan_append(&self, new: &[Leaf]) -> Result<Append, LogError> {
        if self.log_end().is_some() {
            return Err(LogError::Rule(format!(
                "`{}` ended with a log-end leaf, and nothing is appended to a log after it",
                self.origin()
            )));
        }
        let mut previous = self.newest_time();
        let mut encoded = Vec::with_capacity(new.len());
        for (i, leaf) in new.iter().enumerate() {
            let index = self.size() + i as u64;
            check_place(leaf, index, index + 1 == self.size() + new.len() as u64)?;
            check_time(leaf, index, previous)?;
            let bytes = leaf.encode()?;
            self.check_for_readers(leaf, index)?;
            previous = Some(leaf.time());
            encoded.push(bytes);
        }
        // The leaves of the last bundle, when it is partial: the new one begins with them.
        let tail_start = self.size() - self.size() % u64::from(TILE_WIDTH);
        let tail: Vec<Vec<u8>> = (tail_start..self.size())
            .filter_map(|i| self.entry(i))
            .collect();
        plan_append(&self.tree, &tail, &encoded)
    }

    /// What a reader holds a leaf of this log to beyond its fields, its place and its time, as far
    /// as this log can know it: the writer is held to the same, because the log is append-only
    /// and a leaf every reader refuses breaks the source for good.
    ///
    /// A key change must be signed by both keys over this log's origin, as [`KeyHistory`]
    /// requires, which a change signed for the repository's first log and appended to a successor
    /// is not. A log-end must name a successor with another origin, as [`follow`] requires. A
    /// log-continuation must be signed by this log's key, and hold another log's checkpoint; that
    /// it is the old log's final one, signed by the old key, is for the caller holding that log.
    ///
    /// [`KeyHistory`]: super::KeyHistory
    fn check_for_readers(&self, leaf: &Leaf, index: u64) -> Result<(), LogError> {
        check_for_readers(leaf, index, self.origin(), self.vkey())
    }
}

/// [`VerifiedLog::check_for_readers`], for a leaf at `index` of the log `origin` whose key is
/// `vkey`.
fn check_for_readers(
    leaf: &Leaf,
    index: u64,
    origin: &str,
    vkey: &LogVkey,
) -> Result<(), LogError> {
    let refuse = |why: String| {
        LogError::Rotation(format!(
            "leaf {index} of `{origin}` would be refused by every reader, and a leaf once logged \
             is there for good: {why}"
        ))
    };
    match leaf {
        Leaf::KeyChange(c) => c.verify(origin).map_err(|e| refuse(e.to_string())),
        Leaf::LogEnd(end) if end.successor.origin == origin => Err(refuse(
            "it is a log-end naming a successor with this log's own origin, and a successor is a \
             new log, with an origin of its own"
                .into(),
        )),
        Leaf::LogContinuation(c) => {
            if c.old_checkpoint()?.origin == origin {
                return Err(refuse(
                    "it is a log-continuation holding a checkpoint of this log, and one holds the \
                     final checkpoint of the log this one succeeds"
                        .into(),
                ));
            }
            c.note()?.verify(vkey).map_err(|e| {
                refuse(format!(
                    "it is a log-continuation not signed by this log's key, {vkey}: {e}"
                ))
            })
        }
        _ => Ok(()),
    }
}

/// Read and verify a log's checkpoint: its note, its signature by `vkey`, and its origin.
pub fn open_checkpoint(files: &dyn LogFiles, vkey: &LogVkey) -> Result<SignedCheckpoint, LogError> {
    let bytes = files
        .read(CHECKPOINT, CHECKPOINT_LIMIT)?
        .ok_or_else(|| LogError::Missing {
            path: files.shown(CHECKPOINT),
        })?;
    SignedCheckpoint::open(&bytes, vkey)
}

/// Verify a whole log from its files: see the module's documentation for every check.
///
/// `accepted` is the checkpoint last accepted for this log, if there is one. It is checked again
/// under `vkey`, since it comes from a state file on disk, and the log's checkpoint must extend it:
/// no smaller, and its first `accepted.size()` leaves hashing to the accepted root.
pub fn verify_log(
    files: &dyn LogFiles,
    vkey: &LogVkey,
    accepted: Option<&SignedCheckpoint>,
) -> Result<VerifiedLog, LogError> {
    let checkpoint = open_checkpoint(files, vkey)?;
    if let Some(a) = accepted {
        check_accepted_before(a, &checkpoint, vkey)?;
    }
    let size = checkpoint.size();

    let Read {
        tree,
        leaves,
        refused,
    } = read_leaves(files, size)?;
    let root = tree.root();
    if root != *checkpoint.root() {
        return Err(LogError::Mismatch(format!(
            "the {size} leaves of `{}` hash to the root {}, and its checkpoint signs {}: the entry \
             bundles are not the leaves the checkpoint was signed over",
            checkpoint.origin(),
            b64(&root),
            b64(checkpoint.root())
        )));
    }
    // Signed: the log key vouched for this leaf, and the log is refused for it.
    if let Some(e) = refused {
        return Err(e);
    }
    check_tiles(files, &tree, checkpoint.origin())?;

    if let Some(a) = accepted {
        let prefix = tree.root_at(a.size())?;
        if prefix != *a.root() {
            return Err(inconsistent(
                format!(
                    "the first {} leaves of `{}` hash to {}, and the checkpoint last accepted \
                     signs {} for them",
                    a.size(),
                    checkpoint.origin(),
                    b64(&prefix),
                    b64(a.root())
                ),
                a,
                &checkpoint,
            ));
        }
    }

    Ok(VerifiedLog {
        checkpoint,
        vkey: vkey.clone(),
        tree,
        leaves,
    })
}

/// The leaves of a tree of `size` leaves, as its entry bundles hold them, and the tree over them.
struct Read {
    tree: Tree,
    /// Every leaf up to the first refused one.
    leaves: Vec<Leaf>,
    /// The first leaf refused, held until the root is checked. A leaf that does not decode, or
    /// that breaks a rule of the log, is the log key's doing only if a checkpoint signs it; until
    /// a root says so it is as likely a bundle altered after signing, by whoever can push
    /// (`docs/19` §8), and reporting that as the log breaking its own rules would accuse the
    /// wrong party.
    refused: Option<LogError>,
}

/// Read every entry bundle a tree of `size` leaves has, and nothing beyond it: hash each leaf,
/// decode it strictly, and hold it to its place and its time.
fn read_leaves(files: &dyn LogFiles, size: u64) -> Result<Read, LogError> {
    let mut tree = Tree::new();
    let mut leaves: Vec<Leaf> = Vec::new();
    let mut refused: Option<LogError> = None;
    for bundle in Bundle::for_size(size) {
        let path = bundle.path();
        let bytes = files
            .read(&path, bundle_limit(&bundle))?
            .ok_or_else(|| LogError::Missing {
                path: files.shown(&path),
            })?;
        for entry in decode_bundle(&bytes, &bundle)? {
            let index = tree.size();
            tree.push(leaf_hash(&entry));
            if refused.is_some() {
                continue;
            }
            let leaf = Leaf::decode(&entry)
                .map_err(|e| {
                    LogError::Malformed(format!("leaf {index}, in `{path}`, is refused: {e}"))
                })
                .and_then(|leaf| {
                    check_place(&leaf, index, index + 1 == size)?;
                    check_time(&leaf, index, leaves.last().map(Leaf::time))?;
                    Ok(leaf)
                });
            match leaf {
                Ok(leaf) => leaves.push(leaf),
                Err(e) => refused = Some(e),
            }
        }
    }
    Ok(Read {
        tree,
        leaves,
        refused,
    })
}

/// Hold every tile a tree has to the hashes of its leaves: a reader proving inclusion from the
/// tiles relies on them.
fn check_tiles(files: &dyn LogFiles, tree: &Tree, origin: &str) -> Result<(), LogError> {
    for tile in Tile::for_size(tree.size()) {
        let path = tile.path();
        let bytes = files
            .read(&path, tile_limit(&tile))?
            .ok_or_else(|| LogError::Missing {
                path: files.shown(&path),
            })?;
        let want = tree
            .tile_hashes(tile.level, tile.index, tile.width)
            .expect("a tree held whole has every tile of its size");
        if decode_tile(&bytes, &tile)? != want {
            return Err(LogError::Mismatch(format!(
                "`{path}` does not hold the hashes of the leaves of `{origin}`, so a reader \
                 proving inclusion from the tiles would be misled; the tile was altered or written \
                 wrong"
            )));
        }
    }
    Ok(())
}

/// A log's files at a size beyond its signed checkpoint, verified as far as they can be before a
/// checkpoint for them is signed: what `trigon log sign` holds a tree to (`docs/19` §8, §10 phase
/// 5 step 5).
///
/// The checkpoint in the files is the one the new tree extends, and it was opened under the log's
/// own key — a checkpoint the signer has itself verified. The first [`Self::base`]'s size of the
/// new tree's leaves hash to its root, so the extension rewrites nothing that was signed; every
/// leaf decodes, sits where a leaf of its kind may and is no earlier than the one before it; and
/// every tile of the new tree holds its leaves' hashes. What a new leaf names — a record file and
/// its evidence — is the caller's to check, with the records beside the log.
#[derive(Clone, Debug)]
pub struct Extension {
    base: SignedCheckpoint,
    vkey: LogVkey,
    tree: Tree,
    leaves: Vec<Leaf>,
}

impl Extension {
    /// The signed checkpoint the tree extends.
    pub fn base(&self) -> &SignedCheckpoint {
        &self.base
    }

    pub fn origin(&self) -> &str {
        self.base.origin()
    }

    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    /// Every leaf of the new tree with its index, the base's among them.
    pub fn leaves(&self) -> impl Iterator<Item = (u64, &Leaf)> {
        self.leaves.iter().enumerate().map(|(i, l)| (i as u64, l))
    }

    /// The leaves the base's checkpoint does not sign, with their indices.
    pub fn new_leaves(&self) -> impl Iterator<Item = (u64, &Leaf)> {
        self.leaves().skip(self.base.size() as usize)
    }

    /// The checkpoint of the new tree, unsigned: what `trigon log sign` signs, and what `publish
    /// --dry-run` prints.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            origin: self.base.origin().to_string(),
            size: self.tree.size(),
            root: self.tree.root(),
        }
    }

    /// Check that the new tree extends `published`, a checkpoint of this log published before: it
    /// has at least as many leaves, and its first ones hash to that checkpoint's root.
    ///
    /// The base alone is not enough to sign over. It is whatever checkpoint the tree holds, and a
    /// repository rolled back holds an older one the key opens just as well; a tree extending that
    /// would be a second root, under the same key, for a size already published.
    pub fn check_extends(&self, published: &SignedCheckpoint) -> Result<(), LogError> {
        if published.origin() != self.origin() {
            return Err(LogError::Malformed(format!(
                "the checkpoint given as published is for `{}`, and this log is `{}`",
                printable(published.origin()),
                self.origin()
            )));
        }
        published.note().verify(&self.vkey)?;
        let offered = || self.checkpoint().body();
        if published.size() > self.tree.size() {
            return Err(inconsistent_notes(
                format!(
                    "the tree offered has {} leaves, fewer than the {} of `{}`'s checkpoint \
                     published before",
                    self.tree.size(),
                    published.size(),
                    self.origin()
                ),
                published.to_string(),
                offered(),
            ));
        }
        let prefix = self.tree.root_at(published.size())?;
        if prefix != *published.root() {
            return Err(inconsistent_notes(
                format!(
                    "the first {} leaves of the tree offered hash to {}, and `{}`'s checkpoint \
                     published before signs {} for them",
                    published.size(),
                    b64(&prefix),
                    self.origin(),
                    b64(published.root())
                ),
                published.to_string(),
                offered(),
            ));
        }
        Ok(())
    }

    /// Sign the new tree's checkpoint with the log key the base was opened under, and no other.
    pub fn sign(&self, signer: &LogSigner) -> Result<SignedCheckpoint, LogError> {
        if signer.vkey() != self.vkey {
            return Err(LogError::Unverified(format!(
                "the tree extends a checkpoint of {}, and the key given to sign it is {}: a log's \
                 checkpoints are signed by its own key",
                self.vkey,
                signer.vkey()
            )));
        }
        SignedCheckpoint::sign(&self.checkpoint(), signer)
    }
}

/// Verify the files of the log `vkey` names as a tree of `size` leaves extending the checkpoint
/// they hold (see [`Extension`]). Nothing beyond `size` is read, so a bundle or a tile planted
/// past it is never part of what is signed.
///
/// A size smaller than the checkpoint's is refused, as is one that adds a leaf after a log-end.
/// Every new leaf is held to what a reader holds a leaf of this log to ([`check_for_readers`]),
/// since a leaf once signed is there for good.
pub fn verify_extension(
    files: &dyn LogFiles,
    vkey: &LogVkey,
    size: u64,
) -> Result<Extension, LogError> {
    let base = open_checkpoint(files, vkey)?;
    if size < base.size() {
        return Err(LogError::Rule(format!(
            "a tree of {size} leaves was offered as extending `{}`'s checkpoint of {}; a log only \
             grows",
            base.origin(),
            base.size()
        )));
    }
    let Read {
        tree,
        leaves,
        refused,
    } = read_leaves(files, size)?;
    // Before anything else is said about the leaves: if the first ones are not the signed tree,
    // the files were changed under the checkpoint, and nothing new is signed over them.
    let prefix = tree.root_at(base.size())?;
    if prefix != *base.root() {
        return Err(LogError::Mismatch(format!(
            "the first {} leaves of the tree offered hash to {}, and `{}`'s checkpoint signs {} \
             for them: the tree rewrites what was signed, and is not an extension of it",
            base.size(),
            b64(&prefix),
            base.origin(),
            b64(base.root())
        )));
    }
    if let Some(e) = refused {
        return Err(e);
    }
    check_tiles(files, &tree, base.origin())?;
    for (index, leaf) in leaves.iter().enumerate().skip(base.size() as usize) {
        check_for_readers(leaf, index as u64, base.origin(), vkey)?;
    }
    Ok(Extension {
        base,
        vkey: vkey.clone(),
        tree,
        leaves,
    })
}

/// Verify a log's checkpoint, and that it extends the one last accepted, from its tiles alone: a
/// consistency proof built from the tiles the new checkpoint's tree has, verified against both
/// signed roots.
///
/// For a reader without the leaves. The tiles are not trusted, so a proof that fails is not yet
/// an equivocation: it is one only when the tiles are the tree the new checkpoint signs. A proof
/// whose hashes lead to the new root authenticates them, and then the first tree they show is the
/// signed one, and a first tree other than the accepted one is two trees under one key
/// ([`LogError::Inconsistent`]). A proof that does not lead to the new root is tiles that are not
/// the signed tree — damage, or a file planted by whoever can push — and shows nothing about the
/// log key, so it is a [`LogError::Mismatch`]; either way the checkpoint is refused.
pub fn verify_extension_from_tiles(
    files: &dyn LogFiles,
    vkey: &LogVkey,
    accepted: &SignedCheckpoint,
) -> Result<SignedCheckpoint, LogError> {
    let checkpoint = open_checkpoint(files, vkey)?;
    check_accepted_before(accepted, &checkpoint, vkey)?;
    let (m, n) = (accepted.size(), checkpoint.size());
    let hashes = TileHashes::new(files, n);
    let proof = consistency_proof(&hashes, m, n)?;
    if verify_consistency(m, n, accepted.root(), checkpoint.root(), &proof).is_ok() {
        return Ok(checkpoint);
    }
    // Two checkpoints of one size with two roots need no tiles to disagree.
    let why = if m == n {
        format!(
            "`{}`'s checkpoint signs {} for {n} leaves, and the checkpoint last accepted signs {} \
             for as many",
            checkpoint.origin(),
            b64(checkpoint.root()),
            b64(accepted.root())
        )
    } else {
        let prefix = root_of(&hashes, m)?;
        verify_consistency(m, n, &prefix, checkpoint.root(), &proof).map_err(|e| {
            LogError::Mismatch(format!(
                "the tiles of `{}` are not the tree its checkpoint signs: a consistency proof \
                 built from them does not lead to its root ({e}). A tile was altered or written \
                 wrong, and the tiles show nothing about whether the log extends the checkpoint \
                 last accepted",
                checkpoint.origin()
            ))
        })?;
        format!(
            "the first {m} leaves of `{}` hash to {}, as its tiles prove against the root its \
             checkpoint signs, and the checkpoint last accepted signs {} for them",
            checkpoint.origin(),
            b64(&prefix),
            b64(accepted.root())
        )
    };
    Err(inconsistent(why, accepted, &checkpoint))
}

/// Prove that `entry` is leaf `index` of the tree `checkpoint` signs, from that tree's tiles.
///
/// Signed, and not a bare [`Checkpoint`]: the proof is only as good as the root it ends at, and a
/// root nobody signed proves nothing. The size is the checkpoint's too, since a proof binds the
/// size only by its shape (`docs/09` §2.10).
pub fn prove_inclusion_from_tiles(
    files: &dyn LogFiles,
    checkpoint: &SignedCheckpoint,
    index: u64,
    entry: &[u8],
) -> Result<(), LogError> {
    let size = checkpoint.size();
    let hashes = TileHashes::new(files, size);
    let proof = inclusion_proof(&hashes, index, size)?;
    verify_inclusion(index, size, &leaf_hash(entry), &proof, checkpoint.root())
}

/// Follow a log's successor (`docs/19` §8): verify `files` as the log `prev`'s log-end leaf names,
/// and require its first leaf to be a log-continuation that holds `prev`'s final checkpoint, signed
/// by `prev`'s key and the successor's.
///
/// A successor is only ever reached this way, so one that `prev` does not name — `prev` has no
/// log-end, or the files are signed by another key or for another origin — is refused.
pub fn follow(
    prev: &VerifiedLog,
    files: &dyn LogFiles,
    accepted: Option<&SignedCheckpoint>,
) -> Result<VerifiedLog, LogError> {
    let end = prev.log_end().ok_or_else(|| {
        LogError::Rotation(format!(
            "`{}` has no log-end leaf, so it names no successor, and a log it does not name is \
             refused as one",
            prev.origin()
        ))
    })?;
    let named = &end.successor;
    let vkey = named.vkey()?;
    if vkey.origin() == prev.origin() {
        return Err(LogError::Rotation(format!(
            "`{}`'s log-end names a successor with its own origin; a successor is a new log, \
             with an origin of its own",
            prev.origin()
        )));
    }
    let log = verify_log(files, &vkey, accepted).map_err(|e| match e {
        LogError::Unverified(why) => LogError::Rotation(format!(
            "the log in `{}` is not the successor `{}`'s log-end names: {why}",
            files.shown(""),
            prev.origin()
        )),
        other => other,
    })?;
    let Some(Leaf::LogContinuation(c)) = log.leaf(0) else {
        return Err(LogError::Rotation(format!(
            "`{}` does not begin with a log-continuation leaf, so nothing in it holds the final \
             checkpoint of `{}`, and it is not followed",
            log.origin(),
            prev.origin()
        )));
    };
    let held = c.old_checkpoint()?;
    if held != *prev.checkpoint().checkpoint() {
        return Err(LogError::Rotation(format!(
            "`{}`'s log-continuation holds a checkpoint of `{}` at size {} with root {}, and that \
             log's final checkpoint is size {} with root {}",
            log.origin(),
            printable(&held.origin),
            held.size,
            b64(&held.root),
            prev.size(),
            b64(prev.checkpoint().root())
        )));
    }
    let note = c.note()?;
    for (key, whose) in [(prev.vkey(), "old"), (&vkey, "new")] {
        note.verify(key).map_err(|e| {
            LogError::Rotation(format!(
                "`{}`'s log-continuation is not signed by the {whose} log key, {}: {e}",
                log.origin(),
                key
            ))
        })?;
    }
    if c.time < end.time {
        return Err(LogError::Rule(format!(
            "`{}`'s log-continuation was logged at {}, before `{}`'s log-end at {}; a leaf's time \
             never goes backwards, across a succession too",
            log.origin(),
            c.time,
            prev.origin(),
            end.time
        )));
    }
    Ok(log)
}

/// One log of a source's chain, and where in the repository it is.
#[derive(Clone, Debug)]
pub struct ChainedLog {
    /// `log`, or `log/<n>` for a successor.
    pub dir: String,
    pub log: VerifiedLog,
}

/// A repository's chain of logs, verified.
#[derive(Clone, Debug)]
pub struct VerifiedSource {
    /// The log the pinned key opens, then each successor its predecessor names, in order.
    pub logs: Vec<ChainedLog>,
    /// A successor the last log names in another repository. The caller clones it and verifies it
    /// with [`follow`]; this crate opens no socket.
    pub continues_at: Option<Successor>,
    /// Directories `log/<n>` that no log-end leaf names, numbered after the log the chain starts
    /// at: refused as successors, and never read.
    pub unnamed: Vec<String>,
    /// Directories set aside in choosing where the chain starts, each with why: a checkpoint that
    /// could not be read; one that names the pinned log and does not open under its key; a copy of
    /// the checkpoint the chain starts at, whose files did not verify or were not needed; or an
    /// older checkpoint of that log, which the newest extends. Whoever can push can plant every
    /// one of these, so each is reported and none stops the source (`docs/19` §8). A second tree
    /// under the log's key is not among them: nobody without the key can plant one, and it is
    /// refused as an equivocation ([`LogError::Equivocation`]).
    pub refused: Vec<RefusedLog>,
    /// Whether the checkpoint last accepted was checked. False only when it is for a log beyond
    /// this repository, in [`Self::continues_at`], which the caller checks it against when it
    /// follows there.
    pub accepted_checked: bool,
}

/// A directory the chain does not start at, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedLog {
    /// `log`, or `log/<n>`.
    pub dir: String,
    pub why: String,
}

/// Verify an evidence repository's logs (`docs/19` §2.3): the log whose origin is the pinned key's
/// — `log/`, or the `log/<n>` a client pinned after a succession starts at — and each successor
/// a log-end leaf names in the same repository, each by [`verify_log`] and [`follow`].
///
/// The chain starts at the newest checkpoint the pinned key opens, in whichever directory holds
/// it, and at the first such directory whose files verify whole; see [`VerifiedSource::refused`]
/// for the others. Two checkpoints the pinned key opens whose trees are not one tree — the same
/// size with two roots, or an older one the newest does not extend — refuse the source as an
/// equivocation, with both signed notes (`docs/19` §6.1, §8).
///
/// `accepted` is the signed note of the checkpoint last accepted for this source, for whichever
/// log of the chain it belongs to; that log must extend it, and a chain that never reaches its
/// origin is refused as a rollback.
pub fn verify_source(
    repo: &Path,
    pinned: &LogVkey,
    accepted: Option<&[u8]>,
) -> Result<VerifiedSource, LogError> {
    let numbered = numbered_logs(&repo.join("log"))?;
    let accepted_origin = match accepted {
        Some(note) => Some(Checkpoint::parse(SignedNote::parse(note)?.text())?.origin),
        None => None,
    };
    // The checkpoint last accepted, opened under `vkey` where it is for that key's log.
    let accepted_under = |vkey: &LogVkey| -> Result<Option<SignedCheckpoint>, LogError> {
        match (accepted, &accepted_origin) {
            (Some(note), Some(origin)) if origin == vkey.origin() => {
                Ok(Some(SignedCheckpoint::open(note, vkey)?))
            }
            _ => Ok(None),
        }
    };
    let mut accepted_checked = accepted.is_none();

    let Start {
        newest,
        older,
        mut refused,
    } = start_of(repo, pinned, &numbered)?;
    let acc = accepted_under(pinned)?;
    accepted_checked |= acc.is_some();
    let (start_n, first) = first_log(repo, pinned, newest, acc.as_ref(), &mut refused)?;
    for (dir, cp) in older {
        if first.log.tree().root_at(cp.size()).ok() != Some(*cp.root()) {
            return Err(LogError::Equivocation {
                why: format!(
                    "`{dir}` holds a checkpoint of `{}` of {} leaves, signed by its key, that the \
                     tree in `{}` does not extend",
                    pinned.origin(),
                    cp.size(),
                    first.dir
                ),
                first_dir: first.dir.clone(),
                first: first.log.checkpoint().to_string(),
                second_dir: dir,
                second: cp.to_string(),
            });
        }
        refused.push(RefusedLog {
            why: format!(
                "it holds an older checkpoint of `{}`, of {} leaves, which the one in `{}` \
                 extends; a log is read from its newest checkpoint",
                pinned.origin(),
                cp.size(),
                first.dir
            ),
            dir,
        });
    }

    let mut logs: Vec<ChainedLog> = vec![first];
    let mut continues_at = None;
    loop {
        let prev = &logs.last().expect("the chain has its first log").log;
        let Some(s) = prev.log_end().map(|e| e.successor.clone()) else {
            break;
        };
        if !s.in_this_repository() {
            continues_at = Some(s);
            break;
        }
        if logs.iter().any(|c| c.dir == s.dir) {
            return Err(LogError::Rotation(format!(
                "a log-end names `{}` as its successor's directory, which holds an earlier log of \
                 the chain",
                s.dir
            )));
        }
        let acc = accepted_under(&s.vkey()?)?;
        accepted_checked |= acc.is_some();
        let log = follow(prev, &DirFiles::in_repository(repo, &s.dir), acc.as_ref())?;
        if logs.iter().any(|c| c.log.origin() == log.origin()) {
            return Err(LogError::Rotation(format!(
                "`{}` appears twice in this repository's chain of logs; a succession never \
                 returns to an earlier log",
                log.origin()
            )));
        }
        logs.push(ChainedLog { dir: s.dir, log });
    }

    if !accepted_checked && continues_at.is_none() {
        let last = &logs.last().expect("the chain has its first log").log;
        return Err(inconsistent_notes(
            format!(
                "the checkpoint last accepted is for `{}`, and no log this repository's chain \
                 reaches has that origin: the repository is behind what was accepted",
                printable(accepted_origin.as_deref().unwrap_or_default())
            ),
            String::from_utf8_lossy(accepted.unwrap_or_default()).into_owned(),
            last.checkpoint().to_string(),
        ));
    }
    let unnamed = numbered
        .into_iter()
        .filter(|(n, d)| {
            *n > start_n
                && !logs.iter().any(|c| &c.dir == d)
                && !refused.iter().any(|r| &r.dir == d)
        })
        .map(|(_, d)| d)
        .collect();
    Ok(VerifiedSource {
        logs,
        continues_at,
        unnamed,
        refused,
        accepted_checked,
    })
}

/// The directories `log/<n>` in a repository, by number.
fn numbered_logs(log: &Path) -> Result<Vec<(u64, String)>, LogError> {
    let io = |e: std::io::Error| LogError::Io {
        path: log.display().to_string(),
        source: e,
    };
    let entries = match std::fs::read_dir(log) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(e)),
    };
    let mut out = Vec::new();
    for e in entries {
        let e = e.map_err(io)?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let numeric = !name.starts_with('0') && name.bytes().all(|b| b.is_ascii_digit());
        if let Some(n) = numeric.then(|| name.parse::<u64>().ok()).flatten() {
            out.push((n, format!("log/{name}")));
        }
    }
    out.sort();
    Ok(out)
}

/// Where a chain may start: every directory's checkpoint, sorted by what the pinned key makes of
/// it.
struct Start {
    /// The directories holding the newest checkpoint the pinned key opens, `log` first and then by
    /// number, with their number (`log` is 0) and the checkpoint.
    newest: Vec<(u64, String, SignedCheckpoint)>,
    /// The directories holding an older one.
    older: Vec<(String, SignedCheckpoint)>,
    /// Those whose checkpoint could not be read, or names the pinned log and does not open.
    refused: Vec<RefusedLog>,
}

/// Read the checkpoint of `log` and of every `log/<n>`, and sort them for [`first_log`].
///
/// A directory is chosen by what the pinned key opens, never by what a checkpoint's text merely
/// says: whoever can push can write any origin line, and a directory chosen on its word alone
/// would stop the source by failing (`docs/16` §3.98). Where nothing opens, the first directory
/// that failed to is refused as the log, as it would have been were it the only one.
fn start_of(repo: &Path, pinned: &LogVkey, numbered: &[(u64, String)]) -> Result<Start, LogError> {
    let candidates = std::iter::once((0, "log".to_string())).chain(numbered.iter().cloned());
    let mut opened: Vec<(u64, String, SignedCheckpoint)> = Vec::new();
    let mut refused = Vec::new();
    let mut first_error = None;
    let mut seen = Vec::new();
    for (n, dir) in candidates {
        let files = DirFiles::in_repository(repo, &dir);
        let bytes = match files.read(CHECKPOINT, CHECKPOINT_LIMIT) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(e) => {
                refused.push(RefusedLog {
                    dir,
                    why: e.to_string(),
                });
                first_error.get_or_insert(e);
                continue;
            }
        };
        let origin = SignedNote::parse(&bytes)
            .and_then(|note| Checkpoint::parse(note.text()))
            .map(|c| c.origin);
        match origin {
            Ok(o) if o == pinned.origin() => match SignedCheckpoint::open(&bytes, pinned) {
                Ok(checkpoint) => opened.push((n, dir, checkpoint)),
                Err(e) => {
                    refused.push(RefusedLog {
                        why: format!(
                            "its checkpoint names `{}` and does not open under that log's pinned \
                             key: {e}",
                            pinned.origin()
                        ),
                        dir,
                    });
                    first_error.get_or_insert(e);
                }
            },
            Ok(o) => seen.push(format!("`{dir}` is `{}`", printable(&o))),
            Err(_) => seen.push(format!("`{dir}` has no readable checkpoint")),
        }
    }
    let Some(max) = opened.iter().map(|(_, _, c)| c.size()).max() else {
        return Err(first_error.unwrap_or_else(|| {
            LogError::Unverified(format!(
                "no log in {} has the origin `{}` its pinned key names ({}). Check that the key \
                 configured for this source is this repository's",
                repo.display(),
                pinned.origin(),
                if seen.is_empty() {
                    "it has no `log/checkpoint`".to_string()
                } else {
                    seen.join("; ")
                }
            ))
        }));
    };
    let (newest, older): (Vec<_>, Vec<_>) =
        opened.into_iter().partition(|(_, _, c)| c.size() == max);
    Ok(Start {
        newest,
        older: older.into_iter().map(|(_, dir, c)| (dir, c)).collect(),
        refused,
    })
}

/// The log a chain starts at: the first directory holding the newest checkpoint the pinned key
/// opens whose files verify whole, with its number.
///
/// Every such directory holds one signed tree, so whichever of them verifies is the log, and one
/// that does not — a copy planted with the checkpoint and nothing else, or damaged files — is set
/// aside for the next. Where none verifies, the first one's failure is the source's. Two of them
/// whose checkpoints sign different roots for as many leaves are two trees under the log's key,
/// and refuse the source as an equivocation before any is read.
fn first_log(
    repo: &Path,
    pinned: &LogVkey,
    newest: Vec<(u64, String, SignedCheckpoint)>,
    accepted: Option<&SignedCheckpoint>,
    refused: &mut Vec<RefusedLog>,
) -> Result<(u64, ChainedLog), LogError> {
    let (_, first_dir, first) = newest.first().expect("a start has a newest checkpoint");
    if let Some((_, dir, other)) = newest.iter().find(|(_, _, c)| c.root() != first.root()) {
        return Err(LogError::Equivocation {
            why: format!(
                "`{first_dir}` and `{dir}` each hold a checkpoint of `{}` of {} leaves, signed by \
                 its key, and they sign the roots {} and {}",
                pinned.origin(),
                first.size(),
                b64(first.root()),
                b64(other.root())
            ),
            first_dir: first_dir.clone(),
            first: first.to_string(),
            second_dir: dir.clone(),
            second: other.to_string(),
        });
    }
    let mut chosen: Option<(u64, ChainedLog)> = None;
    let mut first_error = None;
    for (n, dir, _) in newest {
        if let Some((_, start)) = &chosen {
            refused.push(RefusedLog {
                why: format!(
                    "it holds a copy of the checkpoint in `{}`, where the chain starts",
                    start.dir
                ),
                dir,
            });
            continue;
        }
        match verify_log(&DirFiles::in_repository(repo, &dir), pinned, accepted) {
            Ok(log) => chosen = Some((n, ChainedLog { dir, log })),
            Err(e) => {
                refused.push(RefusedLog {
                    dir,
                    why: e.to_string(),
                });
                first_error.get_or_insert(e);
            }
        }
    }
    chosen.ok_or_else(|| first_error.expect("the first directory was verified, and failed"))
}

/// Where a leaf may be: a log-continuation only first, a log-end only last.
fn check_place(leaf: &Leaf, index: u64, last: bool) -> Result<(), LogError> {
    match leaf {
        Leaf::LogContinuation(_) if index != 0 => Err(LogError::Rule(format!(
            "leaf {index} is a log-continuation, and one is only ever a log's first leaf"
        ))),
        Leaf::LogEnd(_) if !last => Err(LogError::Rule(format!(
            "leaf {index} is a log-end and is not the log's last leaf; nothing is logged after a \
             log ends"
        ))),
        _ => Ok(()),
    }
}

fn check_time(leaf: &Leaf, index: u64, previous: Option<u64>) -> Result<(), LogError> {
    match previous {
        Some(p) if leaf.time() < p => Err(LogError::Rule(format!(
            "leaf {index} was logged at {}, before leaf {}'s {p}; a leaf's time is never earlier \
             than the one before it (docs/19 §2.3)",
            leaf.time(),
            index - 1
        ))),
        _ => Ok(()),
    }
}

/// What can be checked of the accepted checkpoint before the tree is read.
fn check_accepted_before(
    accepted: &SignedCheckpoint,
    offered: &SignedCheckpoint,
    vkey: &LogVkey,
) -> Result<(), LogError> {
    if accepted.origin() != offered.origin() {
        return Err(LogError::Malformed(format!(
            "the checkpoint given as last accepted is for `{}`, and this log is `{}`",
            printable(accepted.origin()),
            offered.origin()
        )));
    }
    accepted.note().verify(vkey)?;
    if accepted.size() > offered.size() {
        return Err(inconsistent(
            format!(
                "`{}`'s checkpoint has {} leaves, fewer than the {} of the checkpoint last \
                 accepted",
                offered.origin(),
                offered.size(),
                accepted.size()
            ),
            accepted,
            offered,
        ));
    }
    Ok(())
}

fn inconsistent(why: String, accepted: &SignedCheckpoint, offered: &SignedCheckpoint) -> LogError {
    inconsistent_notes(why, accepted.to_string(), offered.to_string())
}

fn inconsistent_notes(why: String, accepted: String, offered: String) -> LogError {
    LogError::Inconsistent {
        why,
        accepted,
        offered,
    }
}

fn b64(h: &Hash) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(h)
}
