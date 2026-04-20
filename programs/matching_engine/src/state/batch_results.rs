//! `BatchResults` — per-market ring of MatchResults + last-batch stats.
//!
//! Lives on L1 (NOT delegated to the ER validator). `run_batch` runs in the
//! PER with DarkCLOB delegated; when the ER state commitment lands on L1,
//! the settlement program (Phase 5) will pick up the match results via CPI
//! into this PDA.
//!
//! The ring is small (16 slots) — each `run_batch` invocation produces
//! typically 1-4 matches; older matches are expected to be drained by
//! Phase-5 settlement before the ring wraps. A production deployment bumps
//! this to a much larger value (or uses a multi-PDA paginated scheme).

use anchor_lang::prelude::*;

use crate::state::fee_accumulator::FeeAccumulator;
use crate::state::match_result::MatchResult;

pub const BATCH_RESULTS_CAPACITY: usize = 16;

#[account(zero_copy)]
#[repr(C)]
pub struct BatchResults {
    pub market: Pubkey,
    /// Root of the Merkle tree over all `order_inclusion_commitment`s in
    /// the last batch. Zero before the first run_batch.
    pub last_inclusion_root: [u8; 32],
    /// Slot in which the last `run_batch` executed.
    pub last_batch_slot: u64,
    /// Number of crossings (matches) in the last batch.
    pub last_match_count: u64,
    /// Uniform clearing price from the last batch. 0 if circuit breaker tripped.
    pub last_clearing_price: u64,
    /// Pyth TWAP snapshot used for the last batch's circuit-breaker check.
    pub last_pyth_twap: u64,
    /// 1 if the last batch was aborted by the circuit breaker, 0 otherwise.
    pub last_circuit_breaker_tripped: u8,
    pub _padding_a: [u8; 7],

    /// Next write index into `results`. Wraps modulo BATCH_RESULTS_CAPACITY.
    pub write_cursor: u64,
    /// Monotonic per-market match id counter.
    pub next_match_id: u64,

    pub results: [MatchResult; BATCH_RESULTS_CAPACITY],

    /// Fee accumulators for this market. Slot 0 tracks the base mint, slot
    /// 1 the quote mint. Seeded from `MatchingConfig.{base,quote}_mint` at
    /// the start of each batch. The fee-note flush after `run_batch`
    /// consumes and zero-initialises these.
    pub fee_accumulators: [FeeAccumulator; 2],

    pub bump: u8,
    pub _padding_b: [u8; 7],
}

impl BatchResults {
    pub const SEED: &'static [u8] = b"batch_results";
}
