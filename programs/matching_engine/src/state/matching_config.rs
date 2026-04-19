//! Per-market matching config. Lives on L1, snapshot-readable from the PER.
//!
//! Stores the market's permissioned root key (copied from VaultConfig at
//! `init_market` time for cheap read access inside PER) plus per-market
//! parameters that Phase 4's batch auction will consume.

use anchor_lang::prelude::*;

#[account(zero_copy)]
#[repr(C)]
pub struct MatchingConfig {
    pub market: Pubkey,
    /// Copy of the vault's Permission Group root key at `init_market` time.
    /// Kept in sync via `sync_root_key` (not implemented in Phase 3 — root key
    /// rotation in vault requires a separate sync ix to propagate here).
    pub root_key: Pubkey,
    pub batch_interval_slots: u64,
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl MatchingConfig {
    pub const SEED: &'static [u8] = b"matching_config";
}
