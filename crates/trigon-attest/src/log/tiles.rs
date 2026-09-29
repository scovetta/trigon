//! C2SP tlog-tiles (<https://c2sp.org/tlog-tiles>): where a log keeps its hashes and its leaves.
//!
//! A tile lists 256 consecutive hashes of one level of the tree — tiles of height 8, so a level-`L`
//! tile holds nodes at height 8L, and level 0 holds the leaf hashes — and an entry bundle lists the
//! 256 leaves whose hashes a level-0 tile holds, each framed by its length as a big-endian uint16.
//! The tile at a tree's right edge may be partial, of width 1 to 255. Paths are fixed by the
//! specification:
//!
//! ```text
//! tile/<L>/<N>[.p/<W>]          hashes: level L, tile N, and W for a partial
//! tile/entries/<N>[.p/<W>]      leaves
//! ```
//!
//! where N is written in groups of three digits, every group but the last prefixed `x`, so tile
//! 1234067 is `x001/x234/067` and no directory holds more than a thousand of each kind.
//!
//! **What a tree has, and nothing else.** A tree of N leaves has exactly the tiles
//! [`Tile::for_size`] lists: at each level, the full tiles, and the partial whose width that size
//! gives. A reader bound to a checkpoint ([`TileHashes`]) opens those files and only those — the
//! full tile where the tree fills it, the partial of the width the tree needs where it does not —
//! so a full tile or a wider partial written beside them, by a later publication or planted by
//! whoever holds the push credential (`docs/19` §8), is never read as part of the log. Every node
//! of an older tree is a node of a newer one, so this is also every hash a proof from any earlier
//! checkpoint needs.
//!
//! **Immutability** (`docs/19` §2.3): a full tile or bundle is never rewritten, a partial is never
//! rewritten either — a wider one is a new file beside it — and every partial of a tile is removed
//! in the commit that writes the full one. [`plan_append`] says which.

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::LogError;
use super::files::LogFiles;
use super::merkle::{Hash, Subtrees, Tree, complete_hash, leaf_hash};

/// Levels of the tree per tile: 256 hashes in a full tile.
pub const TILE_HEIGHT: u32 = 8;

/// Hashes in a full tile, and leaves in a full entry bundle.
pub const TILE_WIDTH: u16 = 1 << TILE_HEIGHT;

/// The longest leaf an entry bundle can frame, since its length is a uint16. Ours are under a
/// kilobyte (`docs/19` §2.3).
pub const MAX_LEAF: usize = u16::MAX as usize;

/// The highest tile level the specification allows.
const MAX_LEVEL: u8 = 63;

const HASH: usize = 32;

/// A tile of hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tile {
    pub level: u8,
    pub index: u64,
    /// 1 to 256; 256 is a full tile.
    pub width: u16,
}

/// An entry bundle: the leaves of the level-0 tile with the same index and width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bundle {
    pub index: u64,
    /// 1 to 256; 256 is a full bundle.
    pub width: u16,
}

impl Tile {
    pub fn is_full(&self) -> bool {
        self.width == TILE_WIDTH
    }

    /// `tile/<L>/<N>[.p/<W>]`.
    pub fn path(&self) -> String {
        format!(
            "tile/{}/{}",
            self.level,
            index_and_width(self.index, self.width)
        )
    }

    /// The directory the tile's partials are kept in, `tile/<L>/<N>.p`: removed whole when the
    /// full tile is written.
    pub fn partials(&self) -> String {
        format!("tile/{}/{}.p", self.level, index_path(self.index))
    }

    /// Read a tile's path, strictly: a path that is not the one [`Self::path`] writes is refused,
    /// so one tile has one path.
    pub fn parse(path: &str) -> Result<Tile, LogError> {
        let bad = || LogError::Malformed(format!("`{path}` is not a tile path"));
        let rest = path.strip_prefix("tile/").ok_or_else(bad)?;
        let (level, rest) = rest.split_once('/').ok_or_else(bad)?;
        let level: u8 = canonical_decimal(level)
            .and_then(|l| u8::try_from(l).ok())
            .filter(|&l| l <= MAX_LEVEL)
            .ok_or_else(bad)?;
        let (index, width) = parse_index_and_width(rest).ok_or_else(bad)?;
        let tile = Tile {
            level,
            index,
            width,
        };
        (tile.path() == path).then_some(tile).ok_or_else(bad)
    }

    /// Every tile a tree of `size` leaves has: at each level, its full tiles and then its partial,
    /// if it has one. A tree of no leaves has none.
    pub fn for_size(size: u64) -> impl Iterator<Item = Tile> {
        (0..=MAX_LEVEL)
            .map_while(move |level| {
                let count = size
                    .checked_shr(u32::from(level) * TILE_HEIGHT)
                    .filter(|&c| c > 0)?;
                Some((level, count))
            })
            .flat_map(|(level, count)| {
                row(count).map(move |(index, width)| Tile {
                    level,
                    index,
                    width,
                })
            })
    }

    /// Tile `index` of level `level` as the tree of `size` leaves has it, or `None` where that tree
    /// has no such tile.
    pub fn at(level: u8, index: u64, size: u64) -> Option<Tile> {
        let count = size.checked_shr(u32::from(level) * TILE_HEIGHT)?;
        let width = width_at(index, count)?;
        Some(Tile {
            level,
            index,
            width,
        })
    }
}

impl Bundle {
    pub fn is_full(&self) -> bool {
        self.width == TILE_WIDTH
    }

    /// `tile/entries/<N>[.p/<W>]`.
    pub fn path(&self) -> String {
        format!("tile/entries/{}", index_and_width(self.index, self.width))
    }

    /// `tile/entries/<N>.p`.
    pub fn partials(&self) -> String {
        format!("tile/entries/{}.p", index_path(self.index))
    }

    /// Read a bundle's path, strictly, as [`Tile::parse`] reads a tile's.
    pub fn parse(path: &str) -> Result<Bundle, LogError> {
        let bad = || LogError::Malformed(format!("`{path}` is not an entry bundle path"));
        let rest = path.strip_prefix("tile/entries/").ok_or_else(bad)?;
        let (index, width) = parse_index_and_width(rest).ok_or_else(bad)?;
        let bundle = Bundle { index, width };
        (bundle.path() == path).then_some(bundle).ok_or_else(bad)
    }

    /// Every entry bundle a tree of `size` leaves has.
    pub fn for_size(size: u64) -> impl Iterator<Item = Bundle> {
        row(size).map(|(index, width)| Bundle { index, width })
    }

    /// The index of this bundle's first leaf.
    pub fn first_leaf(&self) -> u64 {
        self.index * u64::from(TILE_WIDTH)
    }
}

/// The tiles of one row of `count` hashes: `(index, width)`.
fn row(count: u64) -> impl Iterator<Item = (u64, u16)> {
    let full = count / u64::from(TILE_WIDTH);
    let rest = (count % u64::from(TILE_WIDTH)) as u16;
    (0..full)
        .map(|i| (i, TILE_WIDTH))
        .chain((rest > 0).then_some((full, rest)))
}

/// How wide tile `index` of a row of `count` hashes is, if the row reaches it.
fn width_at(index: u64, count: u64) -> Option<u16> {
    let start = index.checked_mul(u64::from(TILE_WIDTH))?;
    let width = count.checked_sub(start).filter(|&w| w > 0)?;
    Some(width.min(u64::from(TILE_WIDTH)) as u16)
}

/// A tile index in groups of three digits, all but the last prefixed `x`: 1234067 is
/// `x001/x234/067`.
pub fn index_path(index: u64) -> String {
    let mut groups = vec![format!("{:03}", index % 1000)];
    let mut n = index / 1000;
    while n > 0 {
        groups.push(format!("x{:03}", n % 1000));
        n /= 1000;
    }
    groups.reverse();
    groups.join("/")
}

fn index_and_width(index: u64, width: u16) -> String {
    if width == TILE_WIDTH {
        index_path(index)
    } else {
        format!("{}.p/{width}", index_path(index))
    }
}

/// `<N>[.p/<W>]`, where the path has already been checked to be written canonically by the caller
/// writing it back.
fn parse_index_and_width(s: &str) -> Option<(u64, u16)> {
    let (index, width) = match s.split_once(".p/") {
        Some((index, width)) => {
            let w = canonical_decimal(width)?;
            (
                index,
                u16::try_from(w).ok().filter(|&w| w > 0 && w < TILE_WIDTH)?,
            )
        }
        None => (s, TILE_WIDTH),
    };
    let groups: Vec<&str> = index.split('/').collect();
    let mut n: u64 = 0;
    for (i, g) in groups.iter().enumerate() {
        let digits = if i + 1 < groups.len() {
            g.strip_prefix('x')?
        } else {
            g
        };
        if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        n = n.checked_mul(1000)?.checked_add(digits.parse().ok()?)?;
    }
    Some((n, width))
}

fn canonical_decimal(s: &str) -> Option<u64> {
    let canonical = s == "0" || (!s.is_empty() && !s.starts_with('0'));
    (canonical && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// A tile's bytes: its hashes, one after another.
pub fn encode_tile(hashes: &[Hash]) -> Vec<u8> {
    hashes.concat()
}

/// Read a tile's bytes: exactly `tile.width` hashes, and nothing after them.
pub fn decode_tile(bytes: &[u8], tile: &Tile) -> Result<Vec<Hash>, LogError> {
    let want = usize::from(tile.width) * HASH;
    if bytes.len() != want {
        return Err(LogError::Malformed(format!(
            "`{}` is {} bytes, and a tile of {} hashes is {want}",
            tile.path(),
            bytes.len(),
            tile.width
        )));
    }
    Ok(bytes
        .chunks_exact(HASH)
        .map(|c| c.try_into().expect("chunks of 32"))
        .collect())
}

/// An entry bundle's bytes: each leaf after its length as a big-endian uint16. A leaf longer than
/// 65,535 bytes cannot be framed, and is refused.
pub fn encode_bundle<E: AsRef<[u8]>>(entries: &[E]) -> Result<Vec<u8>, LogError> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let e = e.as_ref();
        let len = u16::try_from(e.len()).map_err(|_| too_long(i, e.len()))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(e);
    }
    Ok(out)
}

fn too_long(i: usize, len: usize) -> LogError {
    LogError::Malformed(format!(
        "leaf {i} of this append is {len} bytes, and an entry bundle frames a leaf of at most \
         {MAX_LEAF}"
    ))
}

/// Read an entry bundle's bytes: exactly `bundle.width` framed leaves, and nothing after them.
pub fn decode_bundle(bytes: &[u8], bundle: &Bundle) -> Result<Vec<Vec<u8>>, LogError> {
    let bad = |why: String| {
        LogError::Malformed(format!("`{}` is not an entry bundle: {why}", bundle.path()))
    };
    let mut out = Vec::with_capacity(usize::from(bundle.width));
    let mut rest = bytes;
    while !rest.is_empty() {
        if out.len() == usize::from(bundle.width) {
            return Err(bad(format!(
                "it holds more than the {} leaves its name says it does",
                bundle.width
            )));
        }
        let [a, b, tail @ ..] = rest else {
            return Err(bad("it ends inside a leaf's length".into()));
        };
        let len = usize::from(u16::from_be_bytes([*a, *b]));
        if tail.len() < len {
            return Err(bad(format!(
                "leaf {} says it is {len} bytes, and {} are left",
                out.len(),
                tail.len()
            )));
        }
        out.push(tail[..len].to_vec());
        rest = &tail[len..];
    }
    if out.len() != usize::from(bundle.width) {
        return Err(bad(format!(
            "it holds {} leaves, and its name says {}",
            out.len(),
            bundle.width
        )));
    }
    Ok(out)
}

/// The most bytes a tile file can hold.
pub(crate) fn tile_limit(tile: &Tile) -> u64 {
    u64::from(tile.width) * HASH as u64
}

/// The most bytes an entry bundle can hold.
pub(crate) fn bundle_limit(bundle: &Bundle) -> u64 {
    u64::from(bundle.width) * (2 + MAX_LEAF as u64)
}

/// The hashes of the tree a checkpoint signs, read from that tree's tiles.
///
/// Bound to the checkpoint's size, and it opens only the tiles that size has (see the module's
/// documentation). Nothing read is trusted: a proof built from these hashes is verified against
/// signed roots, and a tile that lies makes the proof fail.
pub struct TileHashes<'a> {
    files: &'a dyn LogFiles,
    size: u64,
    read: RefCell<BTreeMap<(u8, u64), Vec<Hash>>>,
}

impl<'a> TileHashes<'a> {
    pub fn new(files: &'a dyn LogFiles, size: u64) -> Self {
        TileHashes {
            files,
            size,
            read: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// A tile's hashes, as the tree of [`Self::size`] has the tile.
    pub fn tile(&self, level: u8, index: u64) -> Result<Vec<Hash>, LogError> {
        if let Some(h) = self.read.borrow().get(&(level, index)) {
            return Ok(h.clone());
        }
        let tile = Tile::at(level, index, self.size).ok_or_else(|| {
            LogError::Mismatch(format!(
                "a tree of {} leaves has no tile {index} at level {level}",
                self.size
            ))
        })?;
        let path = tile.path();
        let bytes =
            self.files
                .read(&path, tile_limit(&tile))?
                .ok_or_else(|| LogError::Missing {
                    path: self.files.shown(&path),
                })?;
        let hashes = decode_tile(&bytes, &tile)?;
        self.read
            .borrow_mut()
            .insert((level, index), hashes.clone());
        Ok(hashes)
    }
}

impl Subtrees for TileHashes<'_> {
    fn subtree(&self, height: u32, index: u64) -> Result<Hash, LogError> {
        let level = u8::try_from(height / TILE_HEIGHT).unwrap_or(u8::MAX);
        let count: u64 = 1 << (height % TILE_HEIGHT);
        let not_in = || {
            LogError::Mismatch(format!(
                "the subtree of height {height} at {index} is not complete in a tree of {} leaves",
                self.size
            ))
        };
        let first = index.checked_mul(count).ok_or_else(not_in)?;
        let tile_index = first / u64::from(TILE_WIDTH);
        let offset = (first % u64::from(TILE_WIDTH)) as usize;
        let tile = Tile::at(level, tile_index, self.size).ok_or_else(not_in)?;
        if offset + count as usize > usize::from(tile.width) {
            return Err(not_in());
        }
        let hashes = self.tile(level, tile_index)?;
        Ok(complete_hash(&hashes[offset..offset + count as usize]))
    }
}

/// What appending leaves to a log writes (`docs/19` §2.3, §10 phase 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Append {
    pub old_size: u64,
    pub size: u64,
    /// The new tree's root, for the checkpoint `trigon log sign` signs.
    pub root: Hash,
    /// Every file to write, by its path in the log's directory, in path order: each tile and entry
    /// bundle the new tree has and the old one did not, partials included.
    pub files: Vec<(String, Vec<u8>)>,
    /// The directories of partials to remove, `tile/<L>/<N>.p` and `tile/entries/<N>.p`, for
    /// every tile this append fills that the old tree held as a partial: the commit that writes a
    /// full tile removes every partial of it.
    pub obsolete: Vec<String>,
}

/// Plan an append of `new` leaves to `tree`, without changing it.
///
/// `tail` is the leaves of the old tree's last entry bundle when it is partial — the old size
/// modulo 256 of them, in order — which the new bundle begins with; the tree holds hashes, not
/// leaves. Each must hash to the tree's leaf in its place: a full bundle is never rewritten, so
/// one planned with other leaves than the tree's would break the log for good. A leaf too long to
/// frame is refused before anything is planned.
pub fn plan_append<T: AsRef<[u8]>, N: AsRef<[u8]>>(
    tree: &Tree,
    tail: &[T],
    new: &[N],
) -> Result<Append, LogError> {
    let old = tree.size();
    let width = u64::from(TILE_WIDTH);
    if tail.len() as u64 != old % width {
        return Err(LogError::Malformed(format!(
            "an append to a tree of {old} leaves begins with the {} leaves of its last bundle, and \
             {} were given",
            old % width,
            tail.len()
        )));
    }
    let tail_start = old - old % width;
    for (i, e) in tail.iter().enumerate() {
        let index = tail_start + i as u64;
        if tree.leaf_hash(index) != Some(leaf_hash(e.as_ref())) {
            return Err(LogError::Mismatch(format!(
                "leaf {index}, given as part of the last bundle of a tree of {old} leaves, is not \
                 the leaf the tree holds there; the bundle it begins would not be the tree's"
            )));
        }
    }
    for (i, e) in new.iter().enumerate() {
        if e.as_ref().len() > MAX_LEAF {
            return Err(too_long(i, e.as_ref().len()));
        }
    }
    let mut grown = tree.clone();
    for e in new {
        grown.push(leaf_hash(e.as_ref()));
    }
    let size = grown.size();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut obsolete: Vec<String> = Vec::new();

    for level in 0..=MAX_LEVEL {
        let shift = u32::from(level) * TILE_HEIGHT;
        let Some(new_count) = size.checked_shr(shift).filter(|&c| c > 0) else {
            break;
        };
        let old_count = old.checked_shr(shift).unwrap_or(0);
        if old_count == new_count {
            continue;
        }
        for index in old_count / width..new_count.div_ceil(width) {
            let tile = Tile::at(level, index, size).expect("the new tree reaches this tile");
            let hashes = grown
                .tile_hashes(level, index, tile.width)
                .expect("a tree held whole has every tile of its size");
            files.push((tile.path(), encode_tile(hashes)));
            if tile.is_full() && width_at(index, old_count).is_some_and(|w| w < TILE_WIDTH) {
                obsolete.push(tile.partials());
            }
        }
    }

    let first = old / width;
    let leaf = |i: u64| -> &[u8] {
        if i < old {
            tail[(i - tail_start) as usize].as_ref()
        } else {
            new[(i - old) as usize].as_ref()
        }
    };
    if size > old {
        for index in first..size.div_ceil(width) {
            let bundle = Bundle {
                index,
                width: width_at(index, size).expect("the new tree reaches this bundle"),
            };
            let entries: Vec<&[u8]> = (bundle.first_leaf()
                ..bundle.first_leaf() + u64::from(bundle.width))
                .map(leaf)
                .collect();
            files.push((bundle.path(), encode_bundle(&entries)?));
            if bundle.is_full() && width_at(index, old).is_some_and(|w| w < TILE_WIDTH) {
                obsolete.push(bundle.partials());
            }
        }
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    obsolete.sort();
    Ok(Append {
        old_size: old,
        size,
        root: grown.root(),
        files,
        obsolete,
    })
}
