//! C2SP tlog-tiles: paths, what a tree of each size has, entry-bundle framing, appends and the
//! partials they make obsolete, and reading a proof's hashes from tiles.

use std::cell::RefCell;
use std::collections::BTreeMap;

use proptest::prelude::*;
use trigon_attest::log::merkle::{
    consistency_proof, inclusion_proof, leaf_hash, root_of, verify_consistency, verify_inclusion,
};
use trigon_attest::log::tiles::{
    MAX_LEAF, decode_bundle, decode_tile, encode_bundle, encode_tile, index_path,
};
use trigon_attest::log::{
    Bundle, LogError, LogFiles, Tile, TileHashes, Tree, merkle::Subtrees, plan_append,
};

use crate::common::err;

/// Log files held in memory, as the tests of this module lay them out.
#[derive(Default)]
struct Mem {
    files: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl LogFiles for Mem {
    fn read(&self, path: &str, limit: u64) -> Result<Option<Vec<u8>>, LogError> {
        let got = self.files.borrow().get(path).cloned();
        if got.as_ref().is_some_and(|b| b.len() as u64 > limit) {
            return Err(LogError::Malformed(format!("{path} is too long")));
        }
        Ok(got)
    }
}

impl Mem {
    fn apply(&self, a: &trigon_attest::log::Append) {
        let mut files = self.files.borrow_mut();
        for (p, b) in &a.files {
            files.insert(p.clone(), b.clone());
        }
        for dir in &a.obsolete {
            let prefix = format!("{dir}/");
            files.retain(|p, _| !p.starts_with(&prefix));
        }
    }

    fn paths(&self) -> Vec<String> {
        self.files.borrow().keys().cloned().collect()
    }
}

fn entry(i: u64) -> Vec<u8> {
    format!("{{\"leaf\":{i}}}").into_bytes()
}

fn tile(level: u8, index: u64, width: u16) -> Tile {
    Tile {
        level,
        index,
        width,
    }
}

#[test]
fn tile_paths_are_the_specifications() {
    for (t, path) in [
        (tile(0, 0, 256), "tile/0/000"),
        (tile(0, 4, 180), "tile/0/004.p/180"),
        (tile(1, 0, 4), "tile/1/000.p/4"),
        (tile(0, 999, 256), "tile/0/999"),
        (tile(0, 1000, 256), "tile/0/x001/000"),
        (tile(0, 1_234_067, 256), "tile/0/x001/x234/067"),
        (tile(3, 1_234_067, 1), "tile/3/x001/x234/067.p/1"),
        (tile(63, 0, 255), "tile/63/000.p/255"),
        (
            tile(0, u64::MAX, 256),
            "tile/0/x018/x446/x744/x073/x709/x551/615",
        ),
    ] {
        assert_eq!(t.path(), path);
        assert_eq!(Tile::parse(path).unwrap(), t, "{path}");
    }
    for (b, path) in [
        (
            Bundle {
                index: 0,
                width: 256,
            },
            "tile/entries/000",
        ),
        (
            Bundle {
                index: 4,
                width: 180,
            },
            "tile/entries/004.p/180",
        ),
        (
            Bundle {
                index: 1_234_067,
                width: 8,
            },
            "tile/entries/x001/x234/067.p/8",
        ),
    ] {
        assert_eq!(b.path(), path);
        assert_eq!(Bundle::parse(path).unwrap(), b, "{path}");
    }
    assert_eq!(index_path(1_234_067), "x001/x234/067");
    assert_eq!(tile(0, 4, 180).partials(), "tile/0/004.p");
    assert_eq!(
        Bundle {
            index: 4,
            width: 180
        }
        .partials(),
        "tile/entries/004.p"
    );
}

#[test]
fn a_path_not_written_as_the_specification_writes_it_is_refused() {
    for path in [
        "tile/0/1",
        "tile/0/0000",
        "tile/0/001/000",
        "tile/0/x000/001",
        "tile/0/x1/000",
        "tile/0/000.p/256",
        "tile/0/000.p/0",
        "tile/0/000.p/01",
        "tile/0/000.p/",
        "tile/00/000",
        "tile/64/000",
        "tile/-1/000",
        "tile/data/000",
        "tile/0/000/",
        "tile/0",
        "tiles/0/000",
        "tile/0/x018/x446/x744/x073/x709/x551/616",
        "tile/entries/000",
    ] {
        assert!(Tile::parse(path).is_err(), "{path}");
    }
    for path in [
        "tile/entries/1",
        "tile/entries/000.p/300",
        "tile/entries/000.p/256",
        "tile/0/000",
    ] {
        assert!(Bundle::parse(path).is_err(), "{path}");
    }
}

fn paths(size: u64) -> Vec<String> {
    Tile::for_size(size).map(|t| t.path()).collect()
}

#[test]
fn a_tree_has_the_tiles_of_its_size_and_no_others() {
    assert!(paths(0).is_empty());
    assert_eq!(paths(1), ["tile/0/000.p/1"]);
    assert_eq!(paths(255), ["tile/0/000.p/255"]);
    assert_eq!(paths(256), ["tile/0/000", "tile/1/000.p/1"]);
    assert_eq!(
        paths(257),
        ["tile/0/000", "tile/0/001.p/1", "tile/1/000.p/1"]
    );
    // `docs/19` §2.3's example, at 1204 leaves.
    assert_eq!(
        paths(1204),
        [
            "tile/0/000",
            "tile/0/001",
            "tile/0/002",
            "tile/0/003",
            "tile/0/004.p/180",
            "tile/1/000.p/4"
        ]
    );
    let big = paths(65_536);
    assert_eq!(big.len(), 256 + 1 + 1);
    assert_eq!(&big[255..], ["tile/0/255", "tile/1/000", "tile/2/000.p/1"]);
    let bundles: Vec<String> = Bundle::for_size(1204).map(|b| b.path()).collect();
    assert_eq!(
        bundles,
        [
            "tile/entries/000",
            "tile/entries/001",
            "tile/entries/002",
            "tile/entries/003",
            "tile/entries/004.p/180"
        ]
    );
    assert_eq!(Tile::at(0, 4, 1204), Some(tile(0, 4, 180)));
    assert_eq!(Tile::at(1, 0, 1204), Some(tile(1, 0, 4)));
    assert_eq!(Tile::at(0, 5, 1204), None);
    assert_eq!(Tile::at(2, 0, 1204), None);
    // The largest tree there is has levels 0 to 7, and asking past them is no tile rather than an
    // overflow.
    assert_eq!(Tile::at(7, 0, u64::MAX), Some(tile(7, 0, 255)));
    assert_eq!(Tile::at(8, 0, u64::MAX), None);
    assert_eq!(Tile::at(0, u64::MAX, u64::MAX), None);
    // Listed lazily, so a checkpoint claiming a vast tree costs nothing until a file is read.
    assert_eq!(Tile::for_size(u64::MAX).next(), Some(tile(0, 0, 256)));
}

#[test]
fn an_entry_bundle_frames_each_leaf_with_its_length() {
    let bytes = encode_bundle(&[b"a".as_slice(), b"", b"bc"]).unwrap();
    assert_eq!(bytes, [0, 1, b'a', 0, 0, 0, 2, b'b', b'c']);
    let b = Bundle { index: 0, width: 3 };
    assert_eq!(
        decode_bundle(&bytes, &b).unwrap(),
        [b"a".to_vec(), vec![], b"bc".to_vec()]
    );

    // The longest leaf a uint16 frames, and one byte more.
    let longest = vec![b'x'; MAX_LEAF];
    let framed = encode_bundle(&[&longest]).unwrap();
    assert_eq!(&framed[..2], [0xff, 0xff]);
    assert_eq!(
        decode_bundle(&framed, &Bundle { index: 0, width: 1 }).unwrap(),
        [longest]
    );
    let e = err(encode_bundle(&[vec![0u8; MAX_LEAF + 1]]));
    assert!(e.contains("65536 bytes") && e.contains("65535"), "{e}");

    for (bytes, width, says) in [
        (vec![0], 1, "inside a leaf's length"),
        (vec![0, 2, b'a'], 1, "2 bytes, and 1 are left"),
        (vec![0, 1, b'a'], 2, "holds 1 leaves, and its name says 2"),
        (vec![0, 1, b'a', 0, 1, b'b'], 1, "more than the 1"),
        (vec![0, 1, b'a', 0], 1, "more than the 1"),
        (vec![], 1, "holds 0 leaves"),
    ] {
        let e = err(decode_bundle(&bytes, &Bundle { index: 7, width }));
        assert!(
            e.contains(says) && e.contains("tile/entries/007"),
            "{bytes:?}: {e}"
        );
    }
}

#[test]
fn a_tile_holds_exactly_its_width_in_hashes() {
    let hashes = [[1u8; 32], [2; 32]];
    let bytes = encode_tile(&hashes);
    assert_eq!(bytes.len(), 64);
    assert_eq!(decode_tile(&bytes, &tile(0, 0, 2)).unwrap(), hashes);
    assert!(err(decode_tile(&bytes, &tile(0, 0, 3))).contains("64 bytes"));
    assert!(err(decode_tile(&bytes[..63], &tile(0, 0, 2))).contains("63 bytes"));
}

fn tree(n: u64) -> Tree {
    Tree::from_leaf_hashes((0..n).map(|i| leaf_hash(&entry(i))))
}

fn entries(range: std::ops::Range<u64>) -> Vec<Vec<u8>> {
    range.map(entry).collect()
}

#[test]
fn an_append_that_fills_a_tile_writes_it_and_names_its_partials_obsolete() {
    let a = plan_append(&tree(250), &entries(0..250), &entries(250..260)).unwrap();
    let written: Vec<&str> = a.files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        written,
        [
            "tile/0/000",
            "tile/0/001.p/4",
            "tile/1/000.p/1",
            "tile/entries/000",
            "tile/entries/001.p/4"
        ]
    );
    assert_eq!(a.obsolete, ["tile/0/000.p", "tile/entries/000.p"]);
    assert_eq!((a.old_size, a.size), (250, 260));
    let whole = tree(260);
    assert_eq!(a.root, whole.root());
    for (path, bytes) in &a.files {
        if let Ok(t) = Tile::parse(path) {
            let want = whole.tile_hashes(t.level, t.index, t.width).unwrap();
            assert_eq!(decode_tile(bytes, &t).unwrap(), want, "{path}");
        } else {
            let b = Bundle::parse(path).unwrap();
            let want = entries(b.first_leaf()..b.first_leaf() + u64::from(b.width));
            assert_eq!(decode_bundle(bytes, &b).unwrap(), want, "{path}");
        }
    }
}

#[test]
fn an_append_inside_a_tile_writes_a_wider_partial_beside_the_old_one() {
    let a = plan_append(&tree(177), &entries(0..177), &entries(177..180)).unwrap();
    let written: Vec<&str> = a.files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(written, ["tile/0/000.p/180", "tile/entries/000.p/180"]);
    assert!(a.obsolete.is_empty());
}

#[test]
fn an_append_from_nothing_and_an_append_of_nothing() {
    let a = plan_append(&Tree::new(), &[] as &[Vec<u8>], &entries(0..3)).unwrap();
    let written: Vec<&str> = a.files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(written, ["tile/0/000.p/3", "tile/entries/000.p/3"]);
    let none = plan_append(&tree(3), &entries(0..3), &[] as &[Vec<u8>]).unwrap();
    assert!(none.files.is_empty() && none.obsolete.is_empty());
    assert_eq!(none.root, tree(3).root());
}

/// Every level at once: 65,535 leaves and two more fill the last level-0 tile, the first level-1
/// tile, and start level 2.
#[test]
fn an_append_that_fills_tiles_at_several_levels_obsoletes_each_ones_partials() {
    let a = plan_append(
        &tree(65_535),
        &entries(65_280..65_535),
        &entries(65_535..65_537),
    )
    .unwrap();
    let written: Vec<&str> = a.files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        written,
        [
            "tile/0/255",
            "tile/0/256.p/1",
            "tile/1/000",
            "tile/2/000.p/1",
            "tile/entries/255",
            "tile/entries/256.p/1",
        ]
    );
    assert_eq!(
        a.obsolete,
        ["tile/0/255.p", "tile/1/000.p", "tile/entries/255.p"]
    );
}

#[test]
fn an_append_is_refused_before_anything_is_planned_when_its_inputs_are_wrong() {
    let e = err(plan_append(&tree(10), &entries(0..9), &entries(10..11)));
    assert!(
        e.contains("10 leaves of its last bundle, and 9 were given"),
        "{e}"
    );
    let e = err(plan_append(
        &tree(0),
        &[] as &[Vec<u8>],
        &[vec![0u8; MAX_LEAF + 1]],
    ));
    assert!(e.contains("65535"), "{e}");
}

/// The tail begins the next bundle, which is written in full and never rewritten, so it must be
/// the tree's own leaves: a bundle of other leaves beside tiles and a root of these would break the
/// log for good.
#[test]
fn an_append_whose_tail_is_not_the_trees_leaves_is_refused() {
    let mut wrong = entries(0..250);
    wrong[249] = b"{\"leaf\":\"not 249\"}".to_vec();
    let e = plan_append(&tree(250), &wrong, &entries(250..260)).unwrap_err();
    assert!(matches!(e, LogError::Mismatch(_)), "{e}");
    assert!(e.to_string().contains("leaf 249"), "{e}");
    // Out of order is as wrong.
    let mut swapped = entries(0..250);
    swapped.swap(0, 1);
    assert!(plan_append(&tree(250), &swapped, &entries(250..260)).is_err());
    // A tail past a full bundle starts at that bundle's first leaf.
    plan_append(&tree(300), &entries(256..300), &entries(300..301)).unwrap();
    let e = err(plan_append(&tree(300), &entries(0..44), &entries(300..301)));
    assert!(e.contains("leaf 256"), "{e}");
}

#[test]
fn hashes_read_from_tiles_are_the_trees() {
    let mem = Mem::default();
    let mut t = Tree::new();
    for step in [1u64, 100, 155, 1, 300, 3000, 7] {
        let old = t.size();
        let new = entries(old..old + step);
        let tail_start = old - old % 256;
        let a = plan_append(&t, &entries(tail_start..old), &new).unwrap();
        mem.apply(&a);
        for e in &new {
            t.push(leaf_hash(e));
        }
    }
    let n = t.size();
    let tiles = TileHashes::new(&mem, n);
    assert_eq!(root_of(&tiles, n).unwrap(), t.root());
    for m in [0, 1, 255, 256, 257, 1000, n - 1, n] {
        assert_eq!(root_of(&tiles, m).unwrap(), t.root_at(m).unwrap(), "{m}");
        assert_eq!(
            consistency_proof(&tiles, m, n).unwrap(),
            t.consistency_proof(m, n).unwrap()
        );
    }
    for i in [0, 1, 255, 256, 2000, n - 1] {
        assert_eq!(
            inclusion_proof(&tiles, i, n).unwrap(),
            t.inclusion_proof(i, n).unwrap()
        );
    }
    // A subtree the tree does not complete is not there.
    assert!(tiles.subtree(12, 1).is_err());
}

/// Past 65,536 leaves a proof reads level-2 tiles, which no smaller tree has: grown in steps that
/// fill a level-2 tile's first hash and go on, the tiles still give the tree's own proofs.
#[test]
fn hashes_read_from_tiles_are_the_trees_past_level_two() {
    let mem = Mem::default();
    let mut t = Tree::new();
    for step in [40_000u64, 25_536, 1, 299] {
        let old = t.size();
        let new = entries(old..old + step);
        let tail_start = old - old % 256;
        mem.apply(&plan_append(&t, &entries(tail_start..old), &new).unwrap());
        for e in &new {
            t.push(leaf_hash(e));
        }
    }
    let n = t.size();
    assert_eq!(n, 65_836);
    assert!(mem.paths().contains(&"tile/2/000.p/1".to_string()));
    let tiles = TileHashes::new(&mem, n);
    assert_eq!(root_of(&tiles, n).unwrap(), t.root());
    for m in [1, 255, 256, 40_000, 65_535, 65_536, 65_537, n - 1, n] {
        assert_eq!(root_of(&tiles, m).unwrap(), t.root_at(m).unwrap(), "{m}");
        assert_eq!(
            consistency_proof(&tiles, m, n).unwrap(),
            t.consistency_proof(m, n).unwrap(),
            "{m}"
        );
    }
    for i in [0, 255, 40_000, 65_535, 65_536, n - 1] {
        let proof = inclusion_proof(&tiles, i, n).unwrap();
        assert_eq!(proof, t.inclusion_proof(i, n).unwrap(), "{i}");
        verify_inclusion(i, n, &t.leaf_hash(i).unwrap(), &proof, &t.root()).unwrap();
    }
    // The subtree of all 65,536 first leaves is one hash of the level-2 tile.
    assert_eq!(tiles.subtree(16, 0).unwrap(), t.root_at(65_536).unwrap());
}

/// What a checkpoint's tree does not cover is never read: a full tile beside the partial the tree
/// has, a wider partial, a tile past the end. Each is planted with garbage, and the proofs still
/// verify from the files the tree names.
#[test]
fn tiles_beyond_the_checkpoints_size_are_not_read() {
    let mem = Mem::default();
    let t = tree(180);
    mem.apply(&plan_append(&Tree::new(), &[] as &[Vec<u8>], &entries(0..180)).unwrap());
    for planted in [
        "tile/0/000",
        "tile/0/000.p/200",
        "tile/0/001.p/3",
        "tile/1/000.p/1",
    ] {
        mem.files
            .borrow_mut()
            .insert(planted.into(), vec![0xee; 256 * 32]);
    }
    let tiles = TileHashes::new(&mem, 180);
    let proof = inclusion_proof(&tiles, 17, 180).unwrap();
    verify_inclusion(17, 180, &t.leaf_hash(17).unwrap(), &proof, &t.root()).unwrap();
    let proof = consistency_proof(&tiles, 100, 180).unwrap();
    verify_consistency(100, 180, &t.root_at(100).unwrap(), &t.root(), &proof).unwrap();

    // And a tile the tree does name, missing, is reported as missing (to a reader that has not
    // already read it: a reader keeps what it read).
    mem.files.borrow_mut().remove("tile/0/000.p/180");
    let e = inclusion_proof(&TileHashes::new(&mem, 180), 17, 180).unwrap_err();
    assert!(
        matches!(e, LogError::Missing { ref path } if path == "tile/0/000.p/180"),
        "{e}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// However a log grows — any number of appends of any size — what is on disk afterwards is the
    /// tiles and bundles of its final size, each holding what it should, plus the older partials
    /// of the tiles still partial, and never a partial of a tile that is full.
    #[test]
    fn appends_in_any_steps_leave_the_tiles_of_the_final_size(
        steps in prop::collection::vec(0u64..600, 1..8),
    ) {
        let mem = Mem::default();
        let mut t = Tree::new();
        let mut sizes = vec![0];
        for step in steps {
            let old = t.size();
            let tail = entries(old - old % 256..old);
            let a = plan_append(&t, &tail, &entries(old..old + step)).unwrap();
            mem.apply(&a);
            for e in entries(old..old + step) {
                t.push(leaf_hash(&e));
            }
            prop_assert_eq!(a.root, t.root());
            sizes.push(t.size());
        }
        let n = t.size();
        let mut want: Vec<String> = Tile::for_size(n).map(|t| t.path()).collect();
        want.extend(Bundle::for_size(n).map(|b| b.path()));
        for s in &sizes {
            // A partial written at an earlier size survives while its tile is still partial now.
            for tl in Tile::for_size(*s).filter(|tl| !tl.is_full()) {
                if Tile::at(tl.level, tl.index, n).is_some_and(|now| !now.is_full()) {
                    want.push(tl.path());
                }
            }
            for b in Bundle::for_size(*s).filter(|b| !b.is_full()) {
                if Bundle::for_size(n).any(|now| now.index == b.index && !now.is_full()) {
                    want.push(b.path());
                }
            }
        }
        want.sort();
        want.dedup();
        prop_assert_eq!(mem.paths(), want);
        for path in mem.paths() {
            let bytes = mem.files.borrow()[&path].clone();
            if let Ok(tl) = Tile::parse(&path) {
                let full = t.tile_hashes(tl.level, tl.index, tl.width).unwrap();
                prop_assert_eq!(decode_tile(&bytes, &tl).unwrap(), full);
            } else {
                let b = Bundle::parse(&path).unwrap();
                let first = b.first_leaf();
                prop_assert_eq!(
                    decode_bundle(&bytes, &b).unwrap(),
                    entries(first..first + u64::from(b.width))
                );
            }
        }
    }

    /// Proofs built from tiles are the proofs built from the whole tree, at any size.
    #[test]
    fn proofs_from_tiles_are_proofs_from_the_tree(n in 1u64..2000, m_frac in 0.0f64..=1.0) {
        let mem = Mem::default();
        let t = tree(n);
        mem.apply(&plan_append(&Tree::new(), &[] as &[Vec<u8>], &entries(0..n)).unwrap());
        let tiles = TileHashes::new(&mem, n);
        let m = ((n as f64) * m_frac) as u64;
        prop_assert_eq!(
            consistency_proof(&tiles, m, n).unwrap(),
            t.consistency_proof(m, n).unwrap()
        );
        let i = m.min(n - 1);
        prop_assert_eq!(
            inclusion_proof(&tiles, i, n).unwrap(),
            t.inclusion_proof(i, n).unwrap()
        );
    }
}

/// A tile the checkpoint's tree does not have is refused without a file being opened, and a tile it
/// has is read once: a reader keeps what it read.
#[test]
fn a_tile_the_checkpoints_tree_does_not_have_is_refused_unread() {
    let mem = Mem::default();
    mem.apply(&plan_append(&Tree::new(), &[] as &[Vec<u8>], &entries(0..180)).unwrap());
    mem.files
        .borrow_mut()
        .insert("tile/1/000.p/1".into(), vec![0xee; 32]);
    let tiles = TileHashes::new(&mem, 180);
    assert_eq!(tiles.size(), 180);
    for (level, index) in [(0, 1), (1, 0)] {
        let e = tiles.tile(level, index).unwrap_err();
        assert!(matches!(e, LogError::Mismatch(_)), "{e}");
        assert!(e.to_string().contains("has no tile"), "{e}");
    }
    let first = tiles.tile(0, 0).unwrap();
    assert_eq!(first.len(), 180);
    mem.files.borrow_mut().clear();
    assert_eq!(tiles.tile(0, 0).unwrap(), first);
}
