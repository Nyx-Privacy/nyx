//! Shared helpers for matching_engine integration tests.

use std::path::PathBuf;

pub fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

pub fn vault_so_path() -> PathBuf {
    repo_root().join("target/deploy/vault.so")
}

pub fn matching_engine_so_path() -> PathBuf {
    repo_root().join("target/deploy/matching_engine.so")
}

pub fn anchor_disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"global:");
    h.update(name.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 8];
    d.copy_from_slice(&out[..8]);
    d
}
