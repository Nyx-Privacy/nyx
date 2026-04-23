//! `init_pending_order_slot` — allocate one empty PendingOrder PDA on L1.
//!
//! Called once per (market, trading_key, slot_index) before the trading
//! session opens. The account is zero-initialised (status = EMPTY) and
//! ready to be delegated to the ER via `delegate_pending_order`.
//!
//! This is the exact analogue of `create_game` / `join_game` in the
//! MagicBlock rock-paper-scissors example — it creates the PDA on L1 so
//! it can be delegated. The actual order intent is written later by
//! `submit_order` running inside the ER (never visible on L1).

use anchor_lang::prelude::*;
use core::mem::size_of;

use crate::state::{PendingOrder, PENDING_ORDER_SEED, PENDING_STATUS_EMPTY};

#[derive(Accounts)]
#[instruction(market: Pubkey, slot_index: u8)]
pub struct InitPendingOrderSlot<'info> {
    /// Fee-payer for the PDA rent.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Trading key that will own this slot. Must sign so no one else can
    /// pre-empt a user's slot index.
    pub trading_key: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = 8 + size_of::<PendingOrder>(),
        seeds = [
            PENDING_ORDER_SEED,
            market.as_ref(),
            trading_key.key().as_ref(),
            &[slot_index],
        ],
        bump,
    )]
    pub pending_order: AccountLoader<'info, PendingOrder>,

    pub system_program: Program<'info, System>,
}

pub fn init_pending_order_slot_handler(
    ctx: Context<InitPendingOrderSlot>,
    market: Pubkey,
    slot_index: u8,
) -> Result<()> {
    let mut po = ctx.accounts.pending_order.load_init()?;
    po.trading_key = ctx.accounts.trading_key.key();
    po.market = market;
    po.slot_index = slot_index;
    po.bump = ctx.bumps.pending_order;
    po.status = PENDING_STATUS_EMPTY;
    // All other fields zero-initialised by load_init.
    Ok(())
}
