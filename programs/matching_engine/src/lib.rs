//! Nyx dark pool — matching engine program.
//!
//! Phase 3 scope (shipped):
//!   - DarkCLOB + MatchingConfig + BatchResults PDAs per market.
//!   - Permission Group configuration (root-key-only `configure_access`).
//!   - Delegation of the DarkCLOB to the MagicBlock ER validator.
//!   - `submit_order` — TEE-side order ingestion + `vault::lock_note` CPI.
//!
//! Phase 4 scope (this file):
//!   - `run_batch` — periodic uniform-clearing-price batch auction with
//!     Pyth-based circuit breaker.
//!   - `cancel_order` — user removes their own OrderRecord from the book.
//!   - BatchResults ring holds MatchResults for Phase 5 settlement pickup.
//!   - Inclusion-root publishing (spec §20.5 step 75).
//!
//! Phase 5+ (future):
//!   - L1 tee_forced_settle for each MatchResult.
//!   - VALID_PRICE ZK circuit enforcing clearing price vs oracle bounds.
//!
//! Reference: Section 23.3 + 23.4 of darkpool_protocol_spec_v3_changed.md.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::ephemeral;

pub mod errors;
pub mod instructions;
pub mod state;

pub use instructions::cancel_order;
pub use instructions::commit_market_state;
pub use instructions::configure_access;
pub use instructions::delegate_batch_results;
pub use instructions::delegate_dark_clob;
pub use instructions::delegate_matching_config;
pub use instructions::delegate_pending_order;
pub use instructions::init_market;
pub use instructions::init_mock_oracle;
pub use instructions::init_pending_order_slot;
pub use instructions::run_batch;
pub use instructions::submit_order;
pub use instructions::undelegate_market;

use instructions::*;

declare_id!("DvYcaiBuaHgJFVjVd57JLM7ZMavzXvBezJwsvA46FJbH");

#[ephemeral]
#[program]
pub mod matching_engine {
    use super::*;

    pub fn init_market(
        ctx: Context<InitMarket>,
        args: init_market::InitMarketArgs,
    ) -> Result<()> {
        init_market::init_market_handler(ctx, args)
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

    pub fn init_pending_order_slot(
        ctx: Context<InitPendingOrderSlot>,
        market: Pubkey,
        slot_index: u8,
    ) -> Result<()> {
        init_pending_order_slot::init_pending_order_slot_handler(ctx, market, slot_index)
    }

    pub fn delegate_pending_order(
        ctx: Context<DelegatePendingOrder>,
        market: Pubkey,
        slot_index: u8,
        trading_key_pubkey: Pubkey,
    ) -> Result<()> {
        delegate_pending_order::delegate_pending_order_handler(
            ctx,
            market,
            slot_index,
            trading_key_pubkey,
        )
    }

    pub fn submit_order(
        ctx: Context<SubmitOrder>,
        args: submit_order::SubmitOrderArgs,
    ) -> Result<()> {
        submit_order::submit_order_handler(ctx, args)
    }

    pub fn cancel_order(
        ctx: Context<CancelOrder>,
        market: Pubkey,
        slot_index: u8,
    ) -> Result<()> {
        cancel_order::cancel_order_handler(ctx, market, slot_index)
    }

    pub fn run_batch(ctx: Context<RunBatch>, market: Pubkey) -> Result<()> {
        run_batch::run_batch_handler(ctx, market)
    }

    pub fn init_mock_oracle(ctx: Context<InitMockOracle>, twap: u64) -> Result<()> {
        init_mock_oracle::init_mock_oracle_handler(ctx, twap)
    }

    pub fn delegate_matching_config(
        ctx: Context<DelegateMatchingConfig>,
        market: Pubkey,
    ) -> Result<()> {
        delegate_matching_config::delegate_matching_config_handler(ctx, market)
    }

    pub fn delegate_batch_results(
        ctx: Context<DelegateBatchResults>,
        market: Pubkey,
    ) -> Result<()> {
        delegate_batch_results::delegate_batch_results_handler(ctx, market)
    }

    pub fn commit_market_state(ctx: Context<CommitMarketState>) -> Result<()> {
        commit_market_state::commit_market_state_handler(ctx)
    }

    pub fn undelegate_market(ctx: Context<UndelegateMarket>) -> Result<()> {
        undelegate_market::undelegate_market_handler(ctx)
    }
}
