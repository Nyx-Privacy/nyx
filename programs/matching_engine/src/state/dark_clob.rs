//! On-PER DarkCLOB. Single PDA per market, delegated once at `init_market`
//! and never undelegated in normal operation.
//!
//! **Phase 3 stub:** this is a fixed-capacity ring of OrderRecords. The real
//! BTreeMap<price, VecDeque<OrderRecord>> zero-copy heap lands in Phase 4
//! alongside `run_batch`. Phase 3 only needs:
//!   - a PDA exists on-chain,
//!   - the PDA is delegated to the ER validator,
//!   - `next_seq` counter advances monotonically per `submit_order`,
//!   - inserted orders are retrievable (for tests asserting state).
//!
//! `DARK_CLOB_CAPACITY` is deliberately small (128) — enough to exercise
//! every Phase 3 test path but not so large that the account rent is painful.

use anchor_lang::prelude::*;

use crate::state::order_record::OrderRecord;

/// Phase 3 capacity. Kept small because Anchor's `init` constraint does a
/// realloc CPI whose limit is 10240 bytes on the inner-ix path. Phase 4's
/// real BTreeMap-heap DarkCLOB uses a proper multi-page allocation strategy.
pub const DARK_CLOB_CAPACITY: usize = 64;

#[account(zero_copy)]
#[repr(C)]
pub struct DarkCLOB {
    pub market: Pubkey,
    /// Monotonically increasing counter assigned to each accepted order.
    /// Used as the precedence tie-breaker — Phase 4 sorts by (price, seq_no).
    pub next_seq: u64,
    /// Number of non-empty slots in `orders`. Kept in sync with status != EMPTY.
    pub order_count: u64,
    /// Fixed-capacity order ring. Real price-indexed heap replaces this in Phase 4.
    pub orders: [OrderRecord; DARK_CLOB_CAPACITY],
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl DarkCLOB {
    pub const SEED: &'static [u8] = b"dark_clob";

    /// Find the first empty slot index. Returns `None` if the book is full.
    pub fn find_empty_slot(&self) -> Option<usize> {
        self.orders.iter().position(|o| o.status == 0)
    }
}
