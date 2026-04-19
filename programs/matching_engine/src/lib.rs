//! Nyx dark pool — matching engine program (Phase 3).
//!
//! Responsibilities (Phase 3 scope):
//!   - DarkCLOB + MatchingConfig PDAs, one per market.
//!   - Permission Group configuration (root-key-only `configure_access`).
//!   - Delegation of the DarkCLOB to the MagicBlock ER validator.
//!   - `submit_order` — TEE-side order ingestion, CPIs `vault::lock_note`.
//!
//! Out of scope (Phase 4+):
//!   - `run_batch` batch auction + uniform clearing price.
//!   - MatchResult state + TEE hardware signing.
//!   - Real BTreeMap-indexed CLOB heap (current fixed-array ring is a stub).
//!
//! Reference: Section 23.3 of darkpool_protocol_spec_v3_changed.md.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::ephemeral;

pub mod errors;
pub mod instructions;
pub mod state;

pub use instructions::configure_access;
pub use instructions::delegate_dark_clob;
pub use instructions::init_market;
pub use instructions::submit_order;

use instructions::*;

declare_id!("G8MHBmzhfvRnhejot7XfeSFm3NC96uqm7VNduutM1J2K");

#[ephemeral]
#[program]
pub mod matching_engine {
    use super::*;

    pub fn init_market(
        ctx: Context<InitMarket>,
        market: Pubkey,
        batch_interval_slots: u64,
    ) -> Result<()> {
        init_market::init_market_handler(ctx, market, batch_interval_slots)
    }

    pub fn configure_access(
        ctx: Context<ConfigureAccess>,
        market: Pubkey,
        members: Vec<configure_access::MemberArg>,
        is_update: bool,
    ) -> Result<()> {
        configure_access::configure_access_handler(ctx, market, members, is_update)
    }

    pub fn delegate_dark_clob(ctx: Context<DelegateDarkClob>, market: Pubkey) -> Result<()> {
        delegate_dark_clob::delegate_dark_clob_handler(ctx, market)
    }

    pub fn submit_order(
        ctx: Context<SubmitOrder>,
        args: submit_order::SubmitOrderArgs,
    ) -> Result<()> {
        submit_order::submit_order_handler(ctx, args)
    }
}
