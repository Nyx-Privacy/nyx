//! `cancel_order` — user removes their own OrderRecord from the CLOB.
//!
//! Signer = Trading Key (the same key that signed `submit_order`). We look
//! up the OrderRecord by `(trading_key, order_id)` and flip its status to
//! CANCELLED. The L1 NoteLock stays in place until the natural
//! `expiry_slot` — `vault::release_lock` can only release after expiry by
//! design (see vault/src/instructions/release_lock.rs). That's deliberate:
//! allowing pre-expiry release from inside the PER would require a TEE
//! signature on the release path, which is Phase-5 territory.
//!
//! Phase 4 scope:
//!   - Flip status to CANCELLED in the CLOB.
//!   - Decrement order_count.
//!   - Emit OrderCancelled event so off-chain watchers can update their view.

use anchor_lang::prelude::*;

use crate::errors::MatchingError;
use crate::state::{DarkCLOB, ORDER_STATUS_ACTIVE, ORDER_STATUS_CANCELLED};

#[derive(Accounts)]
#[instruction(market: Pubkey, order_id: [u8; 16])]
pub struct CancelOrder<'info> {
    #[account(mut)]
    pub trading_key: Signer<'info>,

    #[account(
        mut,
        seeds = [DarkCLOB::SEED, market.as_ref()],
        bump = dark_clob.load()?.bump,
    )]
    pub dark_clob: AccountLoader<'info, DarkCLOB>,
}

pub fn cancel_order_handler(
    ctx: Context<CancelOrder>,
    market: Pubkey,
    order_id: [u8; 16],
) -> Result<()> {
    {
        let clob = ctx.accounts.dark_clob.load()?;
        require!(clob.market == market, MatchingError::MarketMismatch);
    }

    let mut clob = ctx.accounts.dark_clob.load_mut()?;
    let slot = clob
        .find_by_order_id(&ctx.accounts.trading_key.key(), &order_id)
        .ok_or(MatchingError::OrderNotFound)?;

    let seq_no;
    {
        let o = &mut clob.orders[slot];
        require!(
            o.status == ORDER_STATUS_ACTIVE,
            MatchingError::OrderNotFound
        );
        o.status = ORDER_STATUS_CANCELLED;
        seq_no = o.seq_no;
    }
    clob.order_count = clob.order_count.saturating_sub(1);

    emit!(OrderCancelled {
        market,
        trading_key: ctx.accounts.trading_key.key(),
        order_id,
        seq_no,
    });
    Ok(())
}

#[event]
pub struct OrderCancelled {
    pub market: Pubkey,
    pub trading_key: Pubkey,
    pub order_id: [u8; 16],
    pub seq_no: u64,
}
