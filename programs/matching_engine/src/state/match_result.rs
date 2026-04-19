//! MatchResult — the output of a single bid × ask crossing inside
//! `run_batch`. Stored in the per-market `BatchResults` ring so Phase 5
//! settlement can consume it via L1 CPI after the ER state commitment lands.
//!
//! Fields mirror spec §20.6 step 74:
//!   { note_buyer, note_seller, owner_buyer, owner_seller, base_amt,
//!     quote_amt, price, pyth_at_match, batch_slot }
//!
//! `owner_buyer` / `owner_seller` are the Trading Key pubkeys of the two
//! counterparties (not the underlying Shielded Spending Key — that stays
//! off-TEE). `note_buyer` / `note_seller` are the note commitments being
//! consumed by this match.

use anchor_lang::prelude::*;

#[zero_copy]
#[derive(Default, Debug)]
#[repr(C)]
pub struct MatchResult {
    /// Note commitment consumed by the buyer (locked USDC → becomes nullified).
    pub note_buyer: [u8; 32],
    /// Note commitment consumed by the seller (locked SOL → becomes nullified).
    pub note_seller: [u8; 32],
    /// Trading Key of the buyer (order-side = BID).
    pub owner_buyer: Pubkey,
    /// Trading Key of the seller (order-side = ASK).
    pub owner_seller: Pubkey,

    pub base_amt: u64,
    pub quote_amt: u64,
    /// Uniform clearing price for this batch.
    pub price: u64,
    /// Pyth TWAP snapshot at match time, for Phase-5 VALID_PRICE circuit.
    pub pyth_at_match: u64,
    /// Slot in which this match was generated.
    pub batch_slot: u64,

    /// Monotonic per-market id. Used as the nullifier's `match_id` seed.
    pub match_id: u64,

    /// 0 = empty slot, 1 = filled.
    pub status: u8,
    pub _padding: [u8; 7],
}

pub const MATCH_RESULT_STATUS_EMPTY: u8 = 0;
pub const MATCH_RESULT_STATUS_FILLED: u8 = 1;
