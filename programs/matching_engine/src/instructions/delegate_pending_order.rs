//! `delegate_pending_order` — hand a PendingOrder PDA to the ER validator.
//!
//! Once delegated, the slot is writable only inside the ER session. The
//! `submit_order` instruction (sent to the ER RPC with a JWT) writes the
//! order intent into the slot. The intent is never replayed on L1 — only
//! the post-batch snapshot appears there, and only if BatchResults commits.
//!
//! Pattern mirrors `delegate_dark_clob` / `delegate_matching_config`.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::delegate;
use ephemeral_rollups_sdk::cpi::DelegateConfig;

use crate::state::PENDING_ORDER_SEED;

/// `trading_key_pubkey` is passed as an instruction arg (not a Signer here)
/// so the payer can delegate slots on behalf of a user whose trading key is
/// known but may not be the tx fee-payer.
#[delegate]
#[derive(Accounts)]
#[instruction(market: Pubkey, slot_index: u8, trading_key_pubkey: Pubkey)]
pub struct DelegatePendingOrder<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: The PendingOrder PDA being delegated to the ER validator.
    #[account(mut, del)]
    pub pda: AccountInfo<'info>,
}

pub fn delegate_pending_order_handler(
    ctx: Context<DelegatePendingOrder>,
    market: Pubkey,
    slot_index: u8,
    trading_key_pubkey: Pubkey,
) -> Result<()> {
    let seed_refs: &[&[u8]] = &[
        PENDING_ORDER_SEED,
        market.as_ref(),
        trading_key_pubkey.as_ref(),
        &[slot_index],
    ];
    ctx.accounts.delegate_pda(
        &ctx.accounts.payer,
        seed_refs,
        DelegateConfig::default(),
    )?;
    Ok(())
}
