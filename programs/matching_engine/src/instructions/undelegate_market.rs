//! `undelegate_market` — from within the ER session, commit state for
//! (DarkCLOB, MatchingConfig, BatchResults) and release delegation so the
//! accounts return to L1 ownership.
//!
//! Two use cases:
//!   1. Normal teardown — the TEE decides the session is over (market
//!      halted, validator rotation, end-of-trading-day). Commit + hand
//!      the accounts back.
//!   2. Emergency pressure valve — if the TEE or validator is degraded
//!      and L1 needs direct access to the DarkCLOB (e.g. to cancel orders
//!      via `cancel_order` on L1), an admin triggers this path.
//!
//! Companion instruction `force_undelegate_on_l1` lives on L1 and lets
//! the vault admin kick the delegation if this ER path can't be reached;
//! future work.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::commit;
use ephemeral_rollups_sdk::ephem::commit_and_undelegate_accounts;

#[commit]
#[derive(Accounts)]
pub struct UndelegateMarket<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: DarkCLOB PDA.
    #[account(mut)]
    pub dark_clob: AccountInfo<'info>,

    /// CHECK: MatchingConfig PDA.
    #[account(mut)]
    pub matching_config: AccountInfo<'info>,

    /// CHECK: BatchResults PDA.
    #[account(mut)]
    pub batch_results: AccountInfo<'info>,
}

pub fn undelegate_market_handler(ctx: Context<UndelegateMarket>) -> Result<()> {
    commit_and_undelegate_accounts(
        &ctx.accounts.payer,
        vec![
            &ctx.accounts.dark_clob,
            &ctx.accounts.matching_config,
            &ctx.accounts.batch_results,
        ],
        &ctx.accounts.magic_context,
        &ctx.accounts.magic_program,
    )?;
    Ok(())
}
