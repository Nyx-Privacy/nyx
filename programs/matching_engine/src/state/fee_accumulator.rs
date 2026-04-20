//! Per-batch fee accumulator. Inside the PER validator (our TEE analogue)
//! we run one `generate_matches` pass per batch; each filled crossing adds
//! its `buyer_fee_amt` and `seller_fee_amt` into the accumulator for the
//! corresponding mint. At batch close we flush the two accumulated totals
//! into a single Poseidon-committed fee note per mint and hand the
//! commitment off to the settlement CPI.
//!
//! We store the accumulator inline on `BatchResults` (one per market) so
//! there is no extra PDA and so the ER → L1 commit stages only have to
//! move one account. The struct itself is exposed here so tests and the
//! SDK can reason about its bytes without pulling in the full
//! `BatchResults` type.

use anchor_lang::prelude::*;

/// Flush the accumulator into a fee note when `accumulated > 0`; otherwise
/// emit `note_fee_commitment = None` and advance to the next batch.
#[zero_copy]
#[derive(Default, Debug)]
#[repr(C)]
pub struct FeeAccumulator {
    /// SPL token mint whose fees this slot tracks. Zero-pubkey = slot unused.
    pub token_mint: Pubkey,
    /// Cumulative fee for this mint across the current batch. Reset to 0
    /// by `run_batch` after the fee note commitment is handed to settlement.
    pub accumulated_fees: u64,
    /// Batch slot the accumulator is currently tracking. Stale values
    /// (older than BatchResults.last_batch_slot) are treated as 0.
    pub batch_slot: u64,
    /// Poseidon commitment of the flushed fee note for this batch.
    /// Populated by `run_batch` at batch close iff `accumulated_fees > 0`.
    /// The first `tee_forced_settle` call of the batch consumes this
    /// value — it inserts it into the Merkle tree and zero-writes this
    /// field to prevent the TEE from double-claiming the same fee note.
    /// All-zero means "nothing to flush".
    pub flushed_commitment: [u8; 32],
}
