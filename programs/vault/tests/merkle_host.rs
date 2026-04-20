//! Host-side unit tests for the incremental Merkle tree implementation.
//!
//! We only exercise the pure-Rust `poseidon2` and `append_leaf` logic — not any
//! on-chain syscalls. These tests verify the tree math matches the expected
//! shape of the VALID_SPEND circom circuit (depth 20, Poseidon2 at each level).

use vault::merkle::{append_leaf, compute_zero_subtree_roots, empty_root, poseidon2};
use vault::state::{VaultConfig, MERKLE_DEPTH, ROOT_HISTORY_SIZE};

fn fresh_config() -> VaultConfig {
    let zeros = compute_zero_subtree_roots().unwrap();
    VaultConfig {
        admin: Default::default(),
        tee_pubkey: Default::default(),
        root_key: Default::default(),
        leaf_count: 0,
        current_root: empty_root(&zeros).unwrap(),
        roots: [[0u8; 32]; ROOT_HISTORY_SIZE],
        roots_head: 0,
        zero_subtree_roots: zeros,
        right_path: [[0u8; 32]; MERKLE_DEPTH as usize],
        bump: 0,
        protocol_owner_commitment: [0u8; 32],
        fee_rate_bps: 0,
        _padding: [0u8; 4],
    }
}

#[test]
fn poseidon2_zero_inputs_not_zero() {
    let z = [0u8; 32];
    let h = poseidon2(&z, &z).unwrap();
    assert_ne!(h, z, "Poseidon(0, 0) must not be zero");
}

#[test]
fn zero_subtree_roots_monotone() {
    let z = compute_zero_subtree_roots().unwrap();
    // Each level's zero root must differ from its neighbours (they're distinct Poseidon outputs).
    for i in 1..z.len() {
        assert_ne!(z[i], z[i - 1], "zero roots collision at level {i}");
    }
}

#[test]
fn append_leaf_increments_count_and_root() {
    let mut cfg = fresh_config();
    let initial_root = cfg.current_root;

    let leaf1 = {
        let mut b = [0u8; 32];
        b[31] = 0xaa;
        b
    };
    let new_root = append_leaf(&mut cfg, leaf1).unwrap();
    assert_eq!(cfg.leaf_count, 1);
    assert_ne!(new_root, initial_root);
    assert_eq!(cfg.current_root, new_root);
}

#[test]
fn append_two_leaves_root_changes_each_time() {
    let mut cfg = fresh_config();
    let leaf1 = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    let leaf2 = {
        let mut b = [0u8; 32];
        b[31] = 2;
        b
    };
    let r1 = append_leaf(&mut cfg, leaf1).unwrap();
    let r2 = append_leaf(&mut cfg, leaf2).unwrap();
    assert_eq!(cfg.leaf_count, 2);
    assert_ne!(r1, r2);
}

#[test]
fn root_history_ring_buffer_contains_roots() {
    let mut cfg = fresh_config();
    let empty = cfg.current_root;

    let leaf = {
        let mut b = [0u8; 32];
        b[31] = 7;
        b
    };
    let r1 = append_leaf(&mut cfg, leaf).unwrap();

    assert!(cfg.contains_root(&r1), "current root should be present");
    assert!(cfg.contains_root(&empty), "prior root should be in history");
}

#[test]
fn deterministic_tree_root_across_two_runs() {
    let leaves: Vec<[u8; 32]> = (0..5)
        .map(|i| {
            let mut b = [0u8; 32];
            b[31] = i as u8;
            b
        })
        .collect();

    let mut cfg1 = fresh_config();
    let mut cfg2 = fresh_config();
    let mut root1 = [0u8; 32];
    let mut root2 = [0u8; 32];
    for leaf in &leaves {
        root1 = append_leaf(&mut cfg1, *leaf).unwrap();
        root2 = append_leaf(&mut cfg2, *leaf).unwrap();
    }
    assert_eq!(root1, root2);
    assert_eq!(cfg1.current_root, cfg2.current_root);
}
