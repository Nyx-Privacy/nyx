//! Per-user delegated order slot.
//!
//! One PDA per (market, trading_key, slot_index). Created empty on L1 via
//! `init_pending_order_slot`, delegated to the ER validator via
//! `delegate_pending_order`, then written by `submit_order` (which runs
//! **inside the ER** — so the order intent never touches L1).
//!
//! Lifecycle:
//!   Empty   →  Pending  (submit_order inside ER)
//!   Pending →  Empty    (fully matched or expired inside run_batch)
//!   Pending →  Pending  (partially matched; amount/note fields updated in place)
//!
//! The slot stays delegated across batches. Unmatched Pending slots persist
//! into the next batch with their remaining amount — they appear on L1 only
//! as the post-commit snapshot of the (now-empty or still-pending) account,
//! never as the original order intent.

use anchor_lang::prelude::*;
use core::mem::size_of;

pub const PENDING_ORDER_SEED: &[u8] = b"pending_order";
/// Maximum concurrent open orders per user per market.
pub const MAX_PENDING_SLOTS: u8 = 8;

pub const PENDING_STATUS_EMPTY: u8 = 0;
pub const PENDING_STATUS_PENDING: u8 = 1;

/// Compile-time size check sentinel.
pub const PENDING_ORDER_SIZE: usize = size_of::<PendingOrder>();

/// A single pre-allocated order slot, owned by the matching_engine program.
///
/// All fields except `trading_key`, `market`, `slot_index`, and `bump` are
/// zero-initialised at `init_pending_order_slot` time and written by
/// `submit_order` running inside the ER TEE.
#[account(zero_copy)]
#[repr(C)]
pub struct PendingOrder {
    /// Owner's trading key — the only key permitted to write this slot.
    pub trading_key: Pubkey,        // 32
    /// Market this slot belongs to (validated in submit_order).
    pub market: Pubkey,             // 32
    /// Poseidon commitment of the collateral note. Written at submit time;
    /// updated to the change-note commitment on each partial-fill re-lock.
    pub note_commitment: [u8; 32],  // 32
    /// Owner commitment (= Poseidon(spending_key, r_owner)) — used by
    /// run_batch to derive change-note commitments so the owner can
    /// VALID_SPEND them later.
    pub user_commitment: [u8; 32],  // 32
    /// Limit price in the market's native tick.
    pub price_limit: u64,           // 8
    /// Remaining base-unit quantity. Decremented on each partial fill.
    pub amount: u64,                // 8
    /// Full value of the note currently acting as collateral.
    pub note_amount: u64,           // 8
    /// Minimum fill qty (base units). 0 = any fill accepted.
    pub min_fill_qty: u64,          // 8
    /// Slot at which the lock auto-expires on L1.
    pub expiry_slot: u64,           // 8
    /// Slot at which the TEE accepted this order (tie-breaker inside price level).
    pub arrival_slot: u64,          // 8
    /// Caller-supplied idempotency key. Required non-zero; used for cancel lookups
    /// and inclusion-commitment derivation.
    pub order_id: [u8; 16],         // 16
    /// 0 = BID (buy), 1 = ASK (sell).
    pub side: u8,                   // 1
    /// 0 = LIMIT, 1 = IOC, 2 = FOK.
    pub order_type: u8,             // 1
    /// PENDING_STATUS_* constant above.
    pub status: u8,                 // 1
    /// 0..MAX_PENDING_SLOTS - 1 — stamped at init time.
    pub slot_index: u8,             // 1
    pub bump: u8,                   // 1
    pub _padding: [u8; 3],          // 3
    // Total: 32*4 + 8*6 + 16 + 5 + 3 = 128+48+16+8 = 200 bytes (✓ 200%8==0)
}

impl PendingOrder {
    /// Reset every mutable field to zero, preserving the slot identity
    /// (trading_key, market, slot_index, bump). Called after a full fill or
    /// expiry so the slot is immediately reusable for the next order.
    pub fn reset(&mut self) {
        self.note_commitment = [0u8; 32];
        self.user_commitment = [0u8; 32];
        self.price_limit = 0;
        self.amount = 0;
        self.note_amount = 0;
        self.min_fill_qty = 0;
        self.expiry_slot = 0;
        self.arrival_slot = 0;
        self.order_id = [0u8; 16];
        self.side = 0;
        self.order_type = 0;
        self.status = PENDING_STATUS_EMPTY;
    }
}
