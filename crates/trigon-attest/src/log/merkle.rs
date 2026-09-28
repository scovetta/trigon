//! The RFC 6962 Merkle tree over the log's leaves, and its inclusion and consistency proofs.
//!
//! A leaf's hash is SHA-256(0x00 ‖ leaf) and a node's is SHA-256(0x01 ‖ left ‖ right); the root of
//! no leaves is SHA-256 of nothing. Proofs are generated as RFC 6962 §2.1.1 and §2.1.2 define them
//! and verified by the algorithms of RFC 9162 §2.1.3.2 and §2.1.4.2, which are the ones a verifier
//! in any other language will also have implemented.
//!
//! Generation needs the hash of a complete subtree — 2^h leaves starting at a multiple of 2^h —
//! and nothing else, because every left branch RFC 6962's recursion takes is one. So it is written
//! once, over [`Subtrees`], and serves both the tree held in memory ([`Tree`]) and a tree read
//! from tiles (`TileHashes`), which hold exactly such hashes at every eighth level.

use sha2::{Digest as _, Sha256};

use super::LogError;
use super::tiles::TILE_HEIGHT;

/// A SHA-256 hash in the tree.
pub type Hash = [u8; 32];

/// The longest proof a tree of up to 2^64 leaves has, and so the longest one read.
const MAX_PROOF: usize = 65;

/// SHA-256(0x00 ‖ leaf).
pub fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

/// SHA-256(0x01 ‖ left ‖ right).
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The root of the tree of no leaves: SHA-256 of the empty string, which is what a checkpoint of
/// size 0 signs.
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// The root of a list of leaf hashes, by RFC 6962's definition.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n as u64) as usize;
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// The hash of a complete subtree, from its 2^h bottom hashes.
fn complete(hashes: &[Hash]) -> Hash {
    debug_assert!(hashes.len().is_power_of_two());
    if hashes.len() == 1 {
        return hashes[0];
    }
    let (l, r) = hashes.split_at(hashes.len() / 2);
    node_hash(&complete(l), &complete(r))
}

/// The largest power of two less than `n`, for `n` ≥ 2: where RFC 6962 splits a tree of `n`.
fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1 << (63 - (n - 1).leading_zeros())
}

/// Hashes of complete subtrees: whatever holds a tree.
pub trait Subtrees {
    /// The hash of the complete subtree of height `height` whose first leaf is `index << height`.
    fn subtree(&self, height: u32, index: u64) -> Result<Hash, LogError>;
}

/// MTH(D[start:end]) by RFC 6962's recursion, which only ever reaches ranges whose left part is a
/// complete subtree.
fn range_hash(t: &dyn Subtrees, start: u64, end: u64) -> Result<Hash, LogError> {
    let n = end - start;
    if n == 0 {
        return Ok(empty_root());
    }
    if n.is_power_of_two() {
        let height = n.trailing_zeros();
        if start % n != 0 {
            return Err(LogError::Mismatch(format!(
                "leaves {start} to {end} are not a subtree of any tree; this is a bug in the \
                 proof code"
            )));
        }
        return t.subtree(height, start >> height);
    }
    let k = split(n);
    Ok(node_hash(
        &range_hash(t, start, start + k)?,
        &range_hash(t, start + k, end)?,
    ))
}

/// The root of the first `size` leaves.
pub fn root_of(t: &dyn Subtrees, size: u64) -> Result<Hash, LogError> {
    range_hash(t, 0, size)
}

/// RFC 6962 §2.1.1's audit path for leaf `index` in the tree of the first `size` leaves.
pub fn inclusion_proof(t: &dyn Subtrees, index: u64, size: u64) -> Result<Vec<Hash>, LogError> {
    if index >= size {
        return Err(LogError::Mismatch(format!(
            "leaf {index} is not in a tree of {size} leaves, so it has no inclusion proof"
        )));
    }
    fn path(
        t: &dyn Subtrees,
        m: u64,
        start: u64,
        end: u64,
        out: &mut Vec<Hash>,
    ) -> Result<(), LogError> {
        if end - start <= 1 {
            return Ok(());
        }
        let k = split(end - start);
        if m < start + k {
            path(t, m, start, start + k, out)?;
            out.push(range_hash(t, start + k, end)?);
        } else {
            path(t, m, start + k, end, out)?;
            out.push(range_hash(t, start, start + k)?);
        }
        Ok(())
    }
    let mut out = Vec::new();
    path(t, index, 0, size, &mut out)?;
    Ok(out)
}

/// RFC 6962 §2.1.2's proof that the tree of `old` leaves is a prefix of the tree of `new`.
///
/// Empty where `old` is 0 or equals `new`: every tree extends the empty one, and a tree extends
/// itself, and RFC 9162 defines no proof for either.
pub fn consistency_proof(t: &dyn Subtrees, old: u64, new: u64) -> Result<Vec<Hash>, LogError> {
    if old > new {
        return Err(LogError::Mismatch(format!(
            "a tree of {new} leaves cannot extend one of {old}"
        )));
    }
    if old == 0 || old == new {
        return Ok(Vec::new());
    }
    fn sub(
        t: &dyn Subtrees,
        m: u64,
        start: u64,
        end: u64,
        whole: bool,
        out: &mut Vec<Hash>,
    ) -> Result<(), LogError> {
        if m == end {
            if !whole {
                out.push(range_hash(t, start, end)?);
            }
            return Ok(());
        }
        let k = split(end - start);
        if m <= start + k {
            sub(t, m, start, start + k, whole, out)?;
            out.push(range_hash(t, start + k, end)?);
        } else {
            sub(t, m, start + k, end, false, out)?;
            out.push(range_hash(t, start, start + k)?);
        }
        Ok(())
    }
    let mut out = Vec::new();
    sub(t, old, 0, new, true, &mut out)?;
    Ok(out)
}

/// RFC 9162 §2.1.3.2: whether `proof` proves the leaf with hash `leaf` at `index` in the tree of
/// `size` leaves whose root is `root`.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf: &Hash,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), LogError> {
    let fail = |why: &str| {
        LogError::Mismatch(format!(
            "the inclusion proof for leaf {index} in the tree of {size} leaves does not verify: \
             {why}"
        ))
    };
    if index >= size {
        return Err(fail("the leaf is not in the tree"));
    }
    if proof.len() > MAX_PROOF {
        return Err(fail("it is longer than any tree's"));
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return Err(fail("it has more hashes than the tree has levels"));
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(fail("it has fewer hashes than the tree has levels"));
    }
    if r != *root {
        return Err(fail("it leads to another root"));
    }
    Ok(())
}

/// RFC 9162 §2.1.4.2: whether `proof` proves that the tree of `old` leaves with root `old_root`
/// is a prefix of the tree of `new` leaves with root `new_root`.
///
/// Where `old` is 0 the proof must be empty and `old_root` the empty tree's; where the sizes are
/// equal it must be empty and the roots equal.
pub fn verify_consistency(
    old: u64,
    new: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<(), LogError> {
    let fail = |why: &str| {
        LogError::Mismatch(format!(
            "the consistency proof from the tree of {old} leaves to the tree of {new} does not \
             verify: {why}"
        ))
    };
    if old > new {
        return Err(fail("the second tree is smaller than the first"));
    }
    if old == 0 {
        if !proof.is_empty() {
            return Err(fail("a proof from the empty tree is empty"));
        }
        if *old_root != empty_root() {
            return Err(fail("the empty tree's root is SHA-256 of nothing"));
        }
        return Ok(());
    }
    if old == new {
        if !proof.is_empty() {
            return Err(fail("a proof between trees of one size is empty"));
        }
        if old_root != new_root {
            return Err(fail("two trees of one size have different roots"));
        }
        return Ok(());
    }
    if proof.is_empty() {
        return Err(fail("it is empty"));
    }
    if proof.len() > MAX_PROOF {
        return Err(fail("it is longer than any tree's"));
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if old.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let (mut f, mut s) = (old - 1, new - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if s == 0 {
            return Err(fail("it has more hashes than the tree has levels"));
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(fail("it has fewer hashes than the tree has levels"));
    }
    if fr != *old_root {
        return Err(fail("it does not lead to the first tree's root"));
    }
    if sr != *new_root {
        return Err(fail("it does not lead to the second tree's root"));
    }
    Ok(())
}

/// A tree held in memory: every leaf hash, and above them the rows a tile holds.
///
/// Row 0 is the leaf hashes; row `L` holds the hash of every complete subtree of 256^L leaves, the
/// nodes at height 8L, which are the hashes a level-`L` tile lists. Kept as they grow, so a root,
/// a proof or a tile costs at most 128 hashes per subtree it needs rather than a pass over every
/// leaf.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    rows: Vec<Vec<Hash>>,
}

const WIDTH: usize = 1 << TILE_HEIGHT;

impl Tree {
    pub fn new() -> Tree {
        Tree::default()
    }

    /// A tree over these leaf hashes, in order.
    pub fn from_leaf_hashes(hashes: impl IntoIterator<Item = Hash>) -> Tree {
        let mut t = Tree::new();
        for h in hashes {
            t.push(h);
        }
        t
    }

    /// Append one leaf, by its hash.
    pub fn push(&mut self, leaf: Hash) {
        let mut hash = leaf;
        let mut level = 0;
        loop {
            if self.rows.len() == level {
                self.rows.push(Vec::new());
            }
            let row = &mut self.rows[level];
            row.push(hash);
            if row.len() % WIDTH != 0 {
                return;
            }
            // A group of 256 completed: it is one hash in the row above.
            hash = complete(&row[row.len() - WIDTH..]);
            level += 1;
        }
    }

    /// How many leaves.
    pub fn size(&self) -> u64 {
        self.rows.first().map_or(0, |r| r.len() as u64)
    }

    pub fn leaf_hash(&self, index: u64) -> Option<Hash> {
        self.rows
            .first()?
            .get(usize::try_from(index).ok()?)
            .copied()
    }

    /// The root of every leaf.
    pub fn root(&self) -> Hash {
        self.root_at(self.size())
            .expect("every prefix of a tree held whole is in it")
    }

    /// The root of the first `size` leaves: the root a checkpoint of that size signed.
    pub fn root_at(&self, size: u64) -> Result<Hash, LogError> {
        self.check_size(size)?;
        root_of(self, size)
    }

    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Hash>, LogError> {
        self.check_size(size)?;
        inclusion_proof(self, index, size)
    }

    pub fn consistency_proof(&self, old: u64, new: u64) -> Result<Vec<Hash>, LogError> {
        self.check_size(new)?;
        consistency_proof(self, old, new)
    }

    /// The hashes a tile lists: `width` hashes of row `level`, from tile `index`'s first.
    pub fn tile_hashes(&self, level: u8, index: u64, width: u16) -> Option<&[Hash]> {
        let row = self.rows.get(usize::from(level))?;
        let start = usize::try_from(index).ok()?.checked_mul(WIDTH)?;
        row.get(start..start.checked_add(usize::from(width))?)
    }

    fn check_size(&self, size: u64) -> Result<(), LogError> {
        if size > self.size() {
            return Err(LogError::Mismatch(format!(
                "a tree of {size} leaves was asked of one that has {}",
                self.size()
            )));
        }
        Ok(())
    }
}

impl Subtrees for Tree {
    fn subtree(&self, height: u32, index: u64) -> Result<Hash, LogError> {
        let level = (height / TILE_HEIGHT) as usize;
        let within = height % TILE_HEIGHT;
        let found = self.rows.get(level).and_then(|row| {
            let start = usize::try_from(index.checked_mul(1 << within)?).ok()?;
            row.get(start..start.checked_add(1 << within)?)
        });
        found.map(complete).ok_or_else(|| {
            LogError::Mismatch(format!(
                "the subtree of height {height} at {index} is not complete in a tree of {} leaves",
                self.size()
            ))
        })
    }
}

/// The subtree hash of 2^h bottom hashes, for a reader of tiles.
pub(crate) fn complete_hash(hashes: &[Hash]) -> Hash {
    complete(hashes)
}
