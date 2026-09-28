//! RFC 6962 hashing and RFC 9162 proofs: held to the certificate-transparency vectors, and to
//! RFC 6962's own definition over trees of every size a property test reaches.

use proptest::prelude::*;
use serde_json::Value;
use trigon_attest::log::merkle::{
    Hash, empty_root, leaf_hash, node_hash, root, verify_consistency, verify_inclusion,
};
use trigon_attest::log::{LogError, Tree};

const VECTORS: &str = include_str!("../../testdata/log/merkle-rfc6962.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hash(s: &str) -> Hash {
    unhex(s).try_into().unwrap()
}

fn hashes(v: &Value) -> Vec<Hash> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|h| hash(h.as_str().unwrap()))
        .collect()
}

fn vectors() -> (Value, Tree) {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let tree = Tree::from_leaf_hashes(
        v["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| leaf_hash(&unhex(l.as_str().unwrap()))),
    );
    (v, tree)
}

#[test]
fn the_roots_are_the_certificate_transparency_roots() {
    let (v, tree) = vectors();
    for (n, want) in v["roots"].as_array().unwrap().iter().enumerate() {
        let want = hash(want.as_str().unwrap());
        assert_eq!(tree.root_at(n as u64).unwrap(), want, "root of {n}");
        // And the recursive definition, over the leaf hashes directly.
        let leaves: Vec<Hash> = (0..n as u64).map(|i| tree.leaf_hash(i).unwrap()).collect();
        assert_eq!(root(&leaves), want, "RFC 6962's root of {n}");
    }
    assert_eq!(tree.root_at(0).unwrap(), empty_root());
}

#[test]
fn every_audit_path_is_the_vectors_and_verifies() {
    let (v, tree) = vectors();
    for case in v["inclusion"].as_array().unwrap() {
        let (i, n) = (
            case["index"].as_u64().unwrap(),
            case["size"].as_u64().unwrap(),
        );
        let want = hashes(&case["path"]);
        assert_eq!(tree.inclusion_proof(i, n).unwrap(), want, "leaf {i} of {n}");
        let root = tree.root_at(n).unwrap();
        verify_inclusion(i, n, &tree.leaf_hash(i).unwrap(), &want, &root).unwrap();
    }
}

#[test]
fn every_consistency_proof_is_the_vectors_and_verifies() {
    let (v, tree) = vectors();
    for case in v["consistency"].as_array().unwrap() {
        let (m, n) = (case["old"].as_u64().unwrap(), case["new"].as_u64().unwrap());
        let want = hashes(&case["proof"]);
        assert_eq!(tree.consistency_proof(m, n).unwrap(), want, "{m} to {n}");
        let (a, b) = (tree.root_at(m).unwrap(), tree.root_at(n).unwrap());
        verify_consistency(m, n, &a, &b, &want).unwrap();
    }
}

#[test]
fn a_leaf_and_a_node_hash_are_domain_separated() {
    // A node's two children, read as one leaf, do not hash to the node: the 0x00 and 0x01 prefixes
    // are what stop a leaf being passed off as a subtree.
    let (l, r) = (leaf_hash(b"a"), leaf_hash(b"b"));
    assert_ne!(node_hash(&l, &r), leaf_hash(&[l, r].concat()));
}

fn mismatch(r: Result<(), LogError>) -> String {
    match r {
        Err(e @ LogError::Mismatch(_)) => e.to_string(),
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

#[test]
fn an_inclusion_proof_wrong_in_any_way_is_refused() {
    let tree = Tree::from_leaf_hashes((0..7u8).map(|i| leaf_hash(&[i])));
    let (n, i) = (7, 3);
    let proof = tree.inclusion_proof(i, n).unwrap();
    let r = tree.root();
    let leaf = tree.leaf_hash(i).unwrap();
    verify_inclusion(i, n, &leaf, &proof, &r).unwrap();

    let other = tree.leaf_hash(4).unwrap();
    assert!(mismatch(verify_inclusion(i, n, &other, &proof, &r)).contains("another root"));
    assert!(mismatch(verify_inclusion(i + 1, n, &leaf, &proof, &r)).contains("does not verify"));
    // A proof binds the size only by its shape: leaf 3's path has the same shape in trees of 5 to 8
    // leaves, so the same proof passes for any of them against this root. That is why the size a
    // client checks against is the signed checkpoint's, never one the proof comes with.
    verify_inclusion(i, 8, &leaf, &proof, &r).unwrap();
    assert!(mismatch(verify_inclusion(i, 4, &leaf, &proof, &r)).contains("more hashes"));
    assert!(mismatch(verify_inclusion(n, n, &leaf, &proof, &r)).contains("not in the tree"));
    assert!(mismatch(verify_inclusion(i, n, &leaf, &proof, &[0; 32])).contains("another root"));
    let longer = [proof.clone(), vec![[0; 32]]].concat();
    assert!(mismatch(verify_inclusion(i, n, &leaf, &longer, &r)).contains("more hashes"));
    let shorter = &proof[..proof.len() - 1];
    assert!(mismatch(verify_inclusion(i, n, &leaf, shorter, &r)).contains("fewer hashes"));
    let mut flipped = proof.clone();
    flipped[1][0] ^= 1;
    assert!(mismatch(verify_inclusion(i, n, &leaf, &flipped, &r)).contains("another root"));
    assert!(tree.inclusion_proof(7, 7).is_err());
    assert!(
        tree.inclusion_proof(0, 8).is_err(),
        "a tree larger than the one held"
    );
}

#[test]
fn a_consistency_proof_wrong_in_any_way_is_refused() {
    let tree = Tree::from_leaf_hashes((0..7u8).map(|i| leaf_hash(&[i])));
    let (m, n) = (3, 7);
    let proof = tree.consistency_proof(m, n).unwrap();
    let (a, b) = (tree.root_at(m).unwrap(), tree.root_at(n).unwrap());
    verify_consistency(m, n, &a, &b, &proof).unwrap();

    assert!(mismatch(verify_consistency(m, n, &b, &a, &proof)).contains("does not"));
    assert!(mismatch(verify_consistency(m, n, &a, &[0; 32], &proof)).contains("second tree"));
    assert!(mismatch(verify_consistency(m, n, &[0; 32], &b, &proof)).contains("first tree"));
    assert!(mismatch(verify_consistency(m + 1, n, &a, &b, &proof)).contains("does not"));
    assert!(mismatch(verify_consistency(m, n, &a, &b, &[])).contains("empty"));
    assert!(mismatch(verify_consistency(n, m, &b, &a, &proof)).contains("smaller"));
    let mut flipped = proof.clone();
    flipped[0][31] ^= 0x80;
    assert!(mismatch(verify_consistency(m, n, &a, &b, &flipped)).contains("does not"));
    let longer = [proof.clone(), vec![[0; 32]]].concat();
    assert!(mismatch(verify_consistency(m, n, &a, &b, &longer)).contains("more hashes"));
}

/// The two cases RFC 9162 defines no proof for: from the empty tree, and between equal sizes.
#[test]
fn consistency_from_nothing_and_with_itself_needs_no_proof() {
    let tree = Tree::from_leaf_hashes((0..5u8).map(|i| leaf_hash(&[i])));
    let r = tree.root();
    assert!(tree.consistency_proof(0, 5).unwrap().is_empty());
    assert!(tree.consistency_proof(5, 5).unwrap().is_empty());
    verify_consistency(0, 5, &empty_root(), &r, &[]).unwrap();
    verify_consistency(5, 5, &r, &r, &[]).unwrap();
    verify_consistency(0, 0, &empty_root(), &empty_root(), &[]).unwrap();

    assert!(mismatch(verify_consistency(0, 5, &r, &r, &[])).contains("SHA-256 of nothing"));
    assert!(mismatch(verify_consistency(0, 5, &empty_root(), &r, &[r])).contains("empty"));
    assert!(mismatch(verify_consistency(5, 5, &r, &[0; 32], &[])).contains("different roots"));
    assert!(mismatch(verify_consistency(5, 5, &r, &r, &[r])).contains("empty"));
}

fn tree_of(n: u64) -> Tree {
    Tree::from_leaf_hashes((0..n).map(|i| leaf_hash(&i.to_be_bytes())))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// The tree's root, built from rows as it grows, is RFC 6962's recursive definition at every
    /// size, and every prefix's too.
    #[test]
    fn the_trees_root_is_rfc_6962s(n in 0u64..1300, m_frac in 0.0f64..=1.0) {
        let tree = tree_of(n);
        let leaves: Vec<Hash> = (0..n).map(|i| tree.leaf_hash(i).unwrap()).collect();
        prop_assert_eq!(tree.root(), root(&leaves));
        let m = (n as f64 * m_frac) as u64;
        prop_assert_eq!(tree.root_at(m).unwrap(), root(&leaves[..m as usize]));
    }

    /// Every leaf's proof verifies, and no other leaf's hash or index passes with it.
    #[test]
    fn every_inclusion_proof_verifies_for_its_leaf_alone(n in 1u64..600, i_frac in 0.0f64..1.0) {
        let tree = tree_of(n);
        let i = ((n as f64) * i_frac) as u64;
        let proof = tree.inclusion_proof(i, n).unwrap();
        let r = tree.root();
        verify_inclusion(i, n, &tree.leaf_hash(i).unwrap(), &proof, &r).unwrap();
        for j in [i.wrapping_sub(1), i + 1] {
            if j < n {
                let other = tree.leaf_hash(j).unwrap();
                prop_assert!(verify_inclusion(i, n, &other, &proof, &r).is_err());
                let leaf = tree.leaf_hash(i).unwrap();
                prop_assert!(verify_inclusion(j, n, &leaf, &proof, &r).is_err());
            }
        }
    }

    /// Every consistency proof verifies between its two roots and fails between any others.
    #[test]
    fn every_consistency_proof_verifies_between_its_roots_alone(
        n in 1u64..600,
        m_frac in 0.0f64..=1.0,
    ) {
        let tree = tree_of(n);
        let m = ((n as f64) * m_frac) as u64;
        let proof = tree.consistency_proof(m, n).unwrap();
        let (a, b) = (tree.root_at(m).unwrap(), tree.root());
        verify_consistency(m, n, &a, &b, &proof).unwrap();
        if m > 0 && m < n {
            let wrong = tree.root_at(m - 1).unwrap();
            prop_assert!(verify_consistency(m, n, &wrong, &b, &proof).is_err());
            prop_assert!(verify_consistency(m, n, &a, &wrong, &proof).is_err());
            // A different tree of the same size, sharing no leaf.
            let other =
                Tree::from_leaf_hashes((0..n).map(|i| leaf_hash(&(i + 1_000_000).to_be_bytes())));
            prop_assert!(verify_consistency(m, n, &a, &other.root(), &proof).is_err());
        }
    }

    /// A single flipped bit anywhere in a proof is caught.
    #[test]
    fn a_proof_with_one_bit_flipped_never_verifies(
        n in 2u64..400,
        at_frac in 0.0f64..1.0,
        pick in any::<prop::sample::Index>(),
        bit in 0usize..256,
    ) {
        let tree = tree_of(n);
        let i = ((n as f64) * at_frac) as u64;
        let mut proof = tree.inclusion_proof(i, n).unwrap();
        let k = pick.index(proof.len());
        proof[k][bit / 8] ^= 1 << (bit % 8);
        let leaf = tree.leaf_hash(i).unwrap();
        prop_assert!(verify_inclusion(i, n, &leaf, &proof, &tree.root()).is_err());

        let m = i.max(1);
        let mut proof = tree.consistency_proof(m, n).unwrap();
        if !proof.is_empty() {
            let k = pick.index(proof.len());
            proof[k][bit / 8] ^= 1 << (bit % 8);
            let a = tree.root_at(m).unwrap();
            prop_assert!(verify_consistency(m, n, &a, &tree.root(), &proof).is_err());
        }
    }
}
