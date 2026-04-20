//! On-PER OrderRecord. Written during `submit_order`, consumed by
//! `run_batch` in Phase 4.
//!
//! Layout is zero-copy POD — no enums, no Option<_>, only fixed-width ints
//! and byte arrays. Any new field MUST preserve the `#[repr(C)]` invariant
//! and MUST keep total size a multiple of 8.

use anchor_lang::prelude::*;

#[zero_copy]
#[derive(Default, Debug)]
#[repr(C)]
pub struct OrderRecord {
    /// Monotonic per-market counter. Precedence tie-breaker at equal
    /// price_limit. Assigned by TEE at `submit_order` arrival time.
    pub seq_no: u64,
    /// Slot number when the TEE accepted the order.
    pub arrival_slot: u64,
    /// Slot at which the lock auto-expires (see Phase 4 drain logic).
    pub expiry_slot: u64,
    /// Price limit in the market's native tick (base units per quote unit).
    pub price_limit: u64,
    /// Remaining order size (base units). Decremented on each partial fill.
    /// Equivalent to `total_quantity - filled_quantity`; kept denormalised
    /// so the matching loop doesn't need a subtraction per pairing.
    pub amount: u64,
    /// Minimum fill qty (base units). 0 = any fill allowed.
    /// Phase 4 rejects partial matches smaller than this.
    pub min_fill_qty: u64,
    /// Full value of the note currently acting as collateral (bid side:
    /// quote units, ask side: base units). Updates to the change note's
    /// value on each partial-fill re-lock.
    pub note_amount: u64,
    /// Original full order size. Frozen at submit_order time and never
    /// mutated — used by clients to render "filled X / Y" progress and by
    /// the TEE to check whether a partial fill still has remainder.
    pub total_quantity: u64,
    /// Cumulative amount filled across all partial fills. Monotonically
    /// non-decreasing. Relation: `filled_quantity + amount == total_quantity`.
    pub filled_quantity: u64,

    pub trading_key: Pubkey,
    /// Note commitment of the note CURRENTLY locked as collateral for this
    /// order. Starts as the original submit-order note; after a partial
    /// fill + re-lock it is rewritten to the change-note commitment
    /// (note_e for buyer orders, note_f for seller orders). The
    /// matching-engine loop and settlement CPI both read this field, so
    /// keeping it accurate is what prevents orphan orders.
    pub collateral_note: [u8; 32],
    /// User (wallet) commitment = Poseidon(spending_key, r_owner). Used by
    /// Phase-5 run_batch as the `owner_commitment` field when constructing
    /// change-note commitments so the owner can later VALID_SPEND them.
    pub user_commitment: [u8; 32],
    /// `SHA-256(seq_no || collateral_note_at_submit || trading_key)` —
    /// surfaced back to the user for censorship audits and the batch
    /// Merkle inclusion root. Anchored at submit time and NOT rotated
    /// across re-locks (the inclusion proof is about the original submission).
    pub order_inclusion_commitment: [u8; 32],
    /// Caller-supplied 16-byte id. Used for `cancel_order` lookups and
    /// vault NoteLock derivation.
    pub order_id: [u8; 16],

    /// 0 = bid (buy), 1 = ask (sell).
    pub side: u8,
    /// 0 = empty, 1 = active, 2 = filled, 3 = expired, 4 = cancelled.
    pub status: u8,
    /// 0 = LIMIT (rest in book), 1 = IOC (cancel unfilled remainder
    /// immediately), 2 = FOK (fill-or-kill — reject if full size not
    /// matchable this batch).
    pub order_type: u8,
    pub _padding: [u8; 5],
}

pub const ORDER_STATUS_EMPTY: u8 = 0;
pub const ORDER_STATUS_ACTIVE: u8 = 1;
pub const ORDER_STATUS_FILLED: u8 = 2;
pub const ORDER_STATUS_EXPIRED: u8 = 3;
pub const ORDER_STATUS_CANCELLED: u8 = 4;

pub const ORDER_SIDE_BID: u8 = 0;
pub const ORDER_SIDE_ASK: u8 = 1;

pub const ORDER_TYPE_LIMIT: u8 = 0;
pub const ORDER_TYPE_IOC: u8 = 1;
pub const ORDER_TYPE_FOK: u8 = 2;

impl OrderRecord {
    /// Is this slot currently matchable?
    pub fn is_matchable(&self, now_slot: u64) -> bool {
        self.status == ORDER_STATUS_ACTIVE && now_slot < self.expiry_slot
    }
}
