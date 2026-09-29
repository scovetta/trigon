//! Following an attestation-key rotation through the log (`docs/19` §8, ADR-0014 Decision 8).
//!
//! Until a root exists, a source's records are signed by one pinned key, and rotating it is a
//! `key-change` leaf signed by the current key and the new one. A client that verifies such a leaf
//! under the key it holds records the new key, and from that leaf on refuses a record signed by
//! the old key whose leaf comes later: whoever might hold the old key after the change can no
//! longer publish under it. The pinned key stays the start of the chain.
//!
//! These are pure functions over leaves already verified — by [`super::verify_log`], and across a
//! succession by [`super::follow`] — so a leaf's place is a [`LeafPos`]: which log of the source's
//! chain, and which leaf of it.

use super::LogError;
use super::leaf::{KeyChangeLeaf, Leaf};
use super::verify::VerifiedSource;
use crate::AttestationKey;

/// A leaf's place in a source: the log of its chain, counted from the one the chain starts at, and
/// the leaf's index in that log. Ordered as the source logged them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafPos {
    pub log: usize,
    pub index: u64,
}

impl std::fmt::Display for LeafPos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "leaf {} of log {}", self.index, self.log)
    }
}

/// One key's time as the source's attestation key: after the leaf that made it current, if one
/// did, and before the leaf that retired it, if one has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEpoch {
    pub key: AttestationKey,
    /// The key-change leaf that made this key current; `None` for the pinned key.
    pub from: Option<LeafPos>,
    /// The key-change leaf that retired it; `None` for the current key.
    pub until: Option<LeafPos>,
}

impl KeyEpoch {
    /// Whether a record whose leaf is at `pos` may be signed by this key: strictly after the change
    /// that made it current, and strictly before the one that retired it.
    fn covers(&self, pos: LeafPos) -> bool {
        self.from.is_none_or(|f| pos > f) && self.until.is_none_or(|u| pos < u)
    }
}

/// What following one key-change leaf did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyChange {
    /// It changed the current key to `to`.
    Followed { to: AttestationKey },
    /// It names an old key that is not the current one, so it changes nothing. A client pinned
    /// after a rotation sees the change that led to its pin this way; a change from a key already
    /// retired is also this, and is worth showing, since it was logged by someone holding that
    /// key and the log key.
    NotCurrent { why: String },
}

/// The attestation keys a source has had, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyHistory {
    epochs: Vec<KeyEpoch>,
}

impl KeyHistory {
    /// A history that begins at the pinned key.
    pub fn new(pinned: AttestationKey) -> Self {
        KeyHistory {
            epochs: vec![KeyEpoch {
                key: pinned,
                from: None,
                until: None,
            }],
        }
    }

    /// A history as a sync recorded it (`crate::state::KeysFile`): for a reader that cannot follow
    /// the key changes itself because it does not hold every leaf — `--remote`, which reads only
    /// the leaves it proves. Held to the shape [`Self::follow`] leaves: the first key from no
    /// change, each later one from a change after the last, each retired by the change that made
    /// the next and the last never.
    pub fn from_epochs(epochs: Vec<KeyEpoch>) -> Result<KeyHistory, LogError> {
        let bad = |why: &str| LogError::Malformed(format!("this key history is refused: {why}"));
        let Some(first) = epochs.first() else {
            return Err(bad("it has no key"));
        };
        if first.from.is_some() {
            return Err(bad("its first key was made current by a key change"));
        }
        for pair in epochs.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            match (a.until, b.from) {
                (Some(u), Some(f)) if u == f && a.from.is_none_or(|af| af < f) => {}
                _ => return Err(bad("its keys do not follow one another, change by change")),
            }
        }
        if epochs.last().is_some_and(|e| e.until.is_some()) {
            return Err(bad("its last key is retired, and nothing took its place"));
        }
        Ok(KeyHistory { epochs })
    }

    /// Follow every key-change leaf of a verified source, in order, from the pinned key. Returns
    /// the history and the changes that did not apply, with where each was.
    pub fn from_source(
        pinned: AttestationKey,
        source: &VerifiedSource,
    ) -> Result<(KeyHistory, Vec<(LeafPos, String)>), LogError> {
        let mut history = KeyHistory::new(pinned);
        let mut skipped = Vec::new();
        for (log, chained) in source.logs.iter().enumerate() {
            for (index, leaf) in chained.log.leaves() {
                if let Leaf::KeyChange(change) = leaf {
                    let pos = LeafPos { log, index };
                    if let KeyChange::NotCurrent { why } =
                        history.follow(pos, chained.log.origin(), change)?
                    {
                        skipped.push((pos, why));
                    }
                }
            }
        }
        Ok((history, skipped))
    }

    /// The key records are signed with now.
    pub fn current(&self) -> &AttestationKey {
        &self
            .epochs
            .last()
            .expect("a history has its pinned key")
            .key
    }

    pub fn epochs(&self) -> &[KeyEpoch] {
        &self.epochs
    }

    /// Follow one key-change leaf at `pos`, in the log `origin`.
    ///
    /// A change whose old key is the current one must be signed by both keys over this log's
    /// origin, and is refused otherwise: a leaf the log vouches for that claims a rotation the
    /// current key did not sign is what a stolen log key would write. A change from any other key
    /// changes nothing ([`KeyChange::NotCurrent`]).
    pub fn follow(
        &mut self,
        pos: LeafPos,
        origin: &str,
        change: &KeyChangeLeaf,
    ) -> Result<KeyChange, LogError> {
        let last = self.epochs.last().and_then(|e| e.from);
        if let Some(last) = last.filter(|&last| pos <= last) {
            return Err(LogError::Rotation(format!(
                "the key change at {pos} was followed after the one at {last}; key changes are \
                 followed in the order the log holds them"
            )));
        }
        let current = self.current().clone();
        if change.old.public_key != current.to_hex() {
            return Ok(KeyChange::NotCurrent {
                why: format!(
                    "the key change at {pos} is from {}, and the current key is {}",
                    change.old.key_id,
                    current.key_id()
                ),
            });
        }
        change.verify(origin)?;
        let to = change.new_key()?;
        self.epochs
            .last_mut()
            .expect("a history has its pinned key")
            .until = Some(pos);
        self.epochs.push(KeyEpoch {
            key: to.clone(),
            from: Some(pos),
            until: None,
        });
        Ok(KeyChange::Followed { to })
    }

    /// The key a record whose leaf is at `pos` and names `key_id` must verify under: refused if no
    /// key of the history has that id, or if the key's time does not cover the leaf — a record
    /// signed by a retired key whose leaf comes after the change that retired it.
    pub fn key_for(&self, key_id: &str, pos: LeafPos) -> Result<&AttestationKey, LogError> {
        let mut retired_at = None;
        for e in self.epochs.iter().filter(|e| e.key.key_id() == key_id) {
            if e.covers(pos) {
                return Ok(&e.key);
            }
            retired_at = retired_at.or(e.until.filter(|u| pos > *u)).or(e.from);
        }
        match retired_at {
            Some(at) => Err(LogError::Rotation(format!(
                "the record at {pos} is signed by {key_id}, and at {pos} that key was not the \
                 source's attestation key: the key change at {at} settles it. From a key change \
                 on, a record signed by the old key is refused (docs/19 §8)"
            ))),
            None => Err(LogError::Unverified(format!(
                "the record at {pos} is signed by {key_id}, which is neither this source's pinned \
                 attestation key nor one its log has changed to"
            ))),
        }
    }
}
