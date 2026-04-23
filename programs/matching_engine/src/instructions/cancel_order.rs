//! `cancel_order` — reset a user's PendingOrder slot back to Empty.
//!
//! Runs inside the ER (same as submit_order) — the slot is already delegated.
//! The trading key must sign, and Anchor's seed constraint ensures only the
//! slot owner can cancel (seeds embed trading_key, so an intruder's PDA
//! derivation yields a different — non-existent — account).
//!
//! Cancelling immediately frees the slot for reuse. The collateral lock on L1
//! is handled separately: either the natural expiry releases it via
//! `vault::release_lock`, or `tee_forced_settle` closes it if the TEE
//! processes a cancel MatchResult (Phase 5+).

use anchor_lang::prelude::*;

use crate::errors::MatchingError;
use crate::state::{
    PendingOrder, PENDING_ORDER_SEED, PENDING_STATUS_PENDING,
};

#[derive(Accounts)]
#[instruction(market: Pubkey, slot_index: u8)]
pub struct CancelOrder<'info> {
    #[account(mut)]
    pub trading_key: Signer<'info>,

    #[account(
        mut,
        seeds = [
            PENDING_ORDER_SEED,
            market.as_ref(),
            trading_key.key().as_ref(),
            &[slot_index],
        ],
        bump = pending_order.load()?.bump,
    )]
    pub pending_order: AccountLoader<'info, PendingOrder>,
}

pub fn cancel_order_handler(
    ctx: Context<CancelOrder>,
    market: Pubkey,
    slot_index: u8,
) -> Result<()> {
    let order_id;
    {
        let po = ctx.accounts.pending_order.load()?;
        require!(po.market == market, MatchingError::MarketMismatch);
        require!(po.status == PENDING_STATUS_PENDING, MatchingError::OrderNotFound);
        order_id = po.order_id;
    }
    {
        let mut po = ctx.accounts.pending_order.load_mut()?;
        po.reset();
    }

    emit!(OrderCancelled {
        market,
        trading_key: ctx.accounts.trading_key.key(),
        order_id,
        slot_index,
    });
    Ok(())
}

#[event]
pub struct OrderCancelled {
    pub market: Pubkey,
    pub trading_key: Pubkey,
    pub order_id: [u8; 16],
    pub slot_index: u8,
}
