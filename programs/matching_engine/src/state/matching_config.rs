//! Per-market matching config. Lives on L1, snapshot-readable from the PER.
//!
//! Phase 3 stored only { market, root_key, batch_interval_slots }.
//! Phase 4 adds batch-auction parameters: the mints that define the pair,
//! the Pyth oracle price account for circuit-breaker checks, the circuit
//! breaker deviation threshold in basis points, the tick size, and the
//! minimum order size. All of these are set once at `init_market` time and
//! may be rotated later by a root-key-gated ix (not part of Phase 4).

use anchor_lang::prelude::*;

#[account(zero_copy)]
#[repr(C)]
pub struct MatchingConfig {
    pub market: Pubkey,
    /// Copy of the vault's Permission Group root key at `init_market` time.
    pub root_key: Pubkey,

    /// Base-asset mint (what the ASK side is selling / the BID side is buying).
    pub base_mint: Pubkey,
    /// Quote-asset mint (what the BID side is paying with).
    pub quote_mint: Pubkey,
    /// Pyth price account holding the TWAP for this pair. Read at batch time
    /// for the circuit breaker check. For tests, a mock oracle account with
    /// the `MockPriceAccount` layout is accepted via a feature flag.
    pub pyth_account: Pubkey,

    pub batch_interval_slots: u64,
    /// Maximum |P* - pyth_twap| / pyth_twap, in basis points, before the
    /// circuit breaker halts matching for this pair in this batch.
    /// Spec §20.6 step 73 = 300 bps.
    pub circuit_breaker_bps: u64,
    /// Tick size in base units (the smallest price increment). 0 = unchecked.
    pub tick_size: u64,
    /// Minimum order size in base units. Orders smaller than this are
    /// rejected at `submit_order` time.
    pub min_order_size: u64,

    pub bump: u8,
    pub _padding: [u8; 7],
}

impl MatchingConfig {
    pub const SEED: &'static [u8] = b"matching_config";
}
