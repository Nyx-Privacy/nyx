//! `commit_market_state` — from within the ER session, schedule a commit
//! back to L1 for (DarkCLOB, MatchingConfig, BatchResults). Keeps the
//! accounts delegated (no undelegation) so the ER can continue processing
//! further batches after the commit lands.
//!
//! Pattern: TEE loop calls this after every `run_batch` so L1 settlement
//! can pick up the new MatchResult ring without waiting for a periodic
//! auto-commit. The settlement watcher polls L1 `batch_results` by pubkey
//! and fires `tee_forced_settle` when it sees a new `match_id`.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::commit;
use ephemeral_rollups_sdk::ephem::commit_accounts;

#[commit]
#[derive(Accounts)]
pub struct CommitMarketState<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: DarkCLOB PDA, delegated to this ER session.
    #[account(mut)]
    pub dark_clob: AccountInfo<'info>,

    /// CHECK: MatchingConfig PDA, delegated (read-only in run_batch but
    /// still part of the delegation set so it's live in the session).
    #[account(mut)]
    pub matching_config: AccountInfo<'info>,

    /// CHECK: BatchResults PDA, delegated. Carries the MatchResult ring +
    /// FeeAccumulator state that L1 settlement needs to read.
    #[account(mut)]
    pub batch_results: AccountInfo<'info>,
}

pub fn commit_market_state_handler(ctx: Context<CommitMarketState>) -> Result<()> {
    commit_accounts(
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
