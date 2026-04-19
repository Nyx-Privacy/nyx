//! On-PER OrderRecord. Written during `submit_order`, sorted by the batch
//! auction in Phase 4.
//!
//! Precedence anchor: `seq_no` is assigned monotonically inside the TEE at the
//! moment `submit_order` is handled, not at L1 PDA init time. Two orders at
//! the same price_limit tie-break on `seq_no` (oldest-first). `arrival_slot`
//! is recorded separately for expiry math and censorship audits.

use anchor_lang::prelude::*;

#[zero_copy]
#[derive(Default, Debug)]
#[repr(C)]
pub struct OrderRecord {
    pub seq_no: u64,
    pub trading_key: Pubkey,
    pub note_commitment: [u8; 32],
    /// Identifier chosen by TEE — returned to user so they can audit inclusion
    /// against the batch `order_inclusion_root` published per Section 20.5.
    pub order_inclusion_commitment: [u8; 32],
    /// Price limit (base units per quote unit, in the market's native tick).
    pub price_limit: u64,
    pub amount: u64,
    /// Slot number when the TEE accepted the order.
    pub arrival_slot: u64,
    /// Side of the order: 0 = bid (buy), 1 = ask (sell).
    pub side: u8,
    /// 0 = empty slot, 1 = active, 2 = filled, 3 = expired.
    pub status: u8,
    pub _padding: [u8; 6],
}

pub const ORDER_STATUS_EMPTY: u8 = 0;
pub const ORDER_STATUS_ACTIVE: u8 = 1;
pub const ORDER_STATUS_FILLED: u8 = 2;
pub const ORDER_STATUS_EXPIRED: u8 = 3;

pub const ORDER_SIDE_BID: u8 = 0;
pub const ORDER_SIDE_ASK: u8 = 1;
