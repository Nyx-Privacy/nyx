//! MatchResult — the output of a single bid × ask crossing inside
//! `run_batch`. Stored in the per-market `BatchResults` ring so Phase 5
//! settlement can consume it via L1 CPI after the ER state commitment lands.
//!
//! Phase-5 shape (spec-change `change_note_implementation.md`):
//!   - Carries the full *input* note values so the vault's conservation
//!     law can verify `note.amount == trade_leg + change_leg` at settle time.
//!   - Carries optional `note_e_commitment` / `note_f_commitment` for the
//!     change notes (zero-bytes when `change_amt == 0`). The TEE computes
//!     these via Poseidon inside the enclave during run_batch.
//!
//! `owner_buyer` / `owner_seller` are the Trading Key pubkeys of the two
//! counterparties (not the underlying Shielded Spending Key — that stays
//! off-TEE). `note_buyer` / `note_seller` are the note commitments being
//! consumed by this match.

use anchor_lang::prelude::*;

/// Sentinel used in place of `Option::None` for `*_relock_order_id` in the
/// zero-copy [`MatchResult`]. An all-zero 16-byte order id is reserved —
/// `submit_order` rejects zero ids at intake so this cannot collide with
/// a legitimate active order.
pub const RELOCK_ORDER_ID_NONE: [u8; 16] = [0u8; 16];

#[zero_copy]
#[derive(Default, Debug)]
#[repr(C)]
pub struct MatchResult {
    /// Note commitment consumed by the buyer (locked quote/USDC → nullified).
    pub note_buyer: [u8; 32],
    /// Note commitment consumed by the seller (locked base/SOL → nullified).
    pub note_seller: [u8; 32],
    /// Change note commitment returned to the buyer (quote-asset change).
    /// All-zero when `buyer_change_amt == 0` (exact fill).
    pub note_e_commitment: [u8; 32],
    /// Change note commitment returned to the seller (base-asset change).
    /// All-zero when `seller_change_amt == 0` (exact fill).
    pub note_f_commitment: [u8; 32],
    /// Trading Key of the buyer (order-side = BID).
    pub owner_buyer: Pubkey,
    /// Trading Key of the seller (order-side = ASK).
    pub owner_seller: Pubkey,
    /// Buyer's user_commitment. Required by settlement because the change
    /// note `note_e_commitment = Poseidon(..., user_commitment_buyer, ...)`
    /// is the field the owner proves in VALID_SPEND.
    pub user_commitment_buyer: [u8; 32],
    /// Seller's user_commitment (symmetric to above for `note_f_commitment`).
    pub user_commitment_seller: [u8; 32],

    /// Full value of the buyer's input note (quote units).
    pub buyer_note_value: u64,
    /// Full value of the seller's input note (base units).
    pub seller_note_value: u64,

    /// Base-asset qty transferred from seller → buyer.
    pub base_amt: u64,
    /// Quote-asset qty transferred from buyer → seller.
    /// `= base_amt * price` (scaled appropriately).
    pub quote_amt: u64,
    /// Quote-asset change returned to the buyer (0 if exact fill).
    /// Conservation (with fees): `buyer_note_value == quote_amt +
    /// buyer_change_amt + buyer_fee_amt`.
    pub buyer_change_amt: u64,
    /// Base-asset change returned to the seller (0 if exact fill).
    /// Conservation (with fees): `seller_note_value == base_amt +
    /// seller_change_amt + seller_fee_amt`.
    pub seller_change_amt: u64,

    /// Protocol fee deducted from the buyer's input note (quote units).
    /// Accumulated into the per-batch `FeeAccumulator` for the quote mint
    /// and flushed as a single fee note at batch end.
    pub buyer_fee_amt: u64,
    /// Protocol fee deducted from the seller's input note (base units).
    pub seller_fee_amt: u64,

    /// If non-zero, the TEE is asking the vault to atomically re-lock the
    /// buyer's change note (`note_e`) against this order-id so the
    /// residual of a partially-filled order can continue trading in the
    /// next batch. `RELOCK_ORDER_ID_NONE` = no re-lock (exact-fill or
    /// order fully consumed).
    pub buyer_relock_order_id: [u8; 16],
    /// Absolute slot at which the re-locked change note's lock expires.
    /// Meaningful only when `buyer_relock_order_id != RELOCK_ORDER_ID_NONE`.
    pub buyer_relock_expiry: u64,
    /// Symmetric to `buyer_relock_order_id` for the seller's change note
    /// (`note_f`).
    pub seller_relock_order_id: [u8; 16],
    /// Symmetric to `buyer_relock_expiry` for the seller.
    pub seller_relock_expiry: u64,

    /// Uniform clearing price for this batch.
    pub price: u64,
    /// Pyth TWAP snapshot at match time, for Phase-6 VALID_PRICE circuit.
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
