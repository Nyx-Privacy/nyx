//! `submit_order` — write an order intent into a delegated PendingOrder slot.
//!
//! **Runs inside the ER (sent to PER RPC with a JWT). Never visible on L1.**
//!
//! This is the exact analogue of `make_choice` in the MagicBlock
//! rock-paper-scissors example: it writes private state into an
//! already-delegated PDA. The transaction data (side, amount, price_limit,
//! note_commitment) is processed by the ER validator's TEE and never
//! replayed to L1. Only the aggregated BatchResults commit later.
//!
//! Key differences vs the old L1 submit_order:
//!   • No vault CPI — `vault::lock_note` is called later by `tee_forced_settle`
//!     after matching, eliminating any L1 trace of the order intent.
//!   • No TEE authority account — the JWT + Permission Group check is done
//!     at the ER ingress layer. The `trading_key` Signer constraint is
//!     sufficient for the on-chain program.
//!   • No consumed-note probe — the vault will reject a double-spend at
//!     `tee_forced_settle` time if the note was already consumed.
//!
//! Validation performed here (stateless checks only):
//!   1. Slot is Empty — prevents overwriting a live order.
//!   2. trading_key matches the slot owner (Anchor seeds constraint enforces this).
//!   3. Order params well-formed (side, order_type, amount, price, expiry, id).
//!   4. Notional ≤ note_amount (collateral-sufficiency gate).
//!   5. min_fill_qty ≤ amount.

use anchor_lang::prelude::*;

use crate::errors::MatchingError;
use crate::state::{
    PendingOrder, PENDING_ORDER_SEED, PENDING_STATUS_EMPTY, PENDING_STATUS_PENDING,
    ORDER_SIDE_BID, ORDER_SIDE_ASK,
    ORDER_TYPE_LIMIT, ORDER_TYPE_IOC, ORDER_TYPE_FOK,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct SubmitOrderArgs {
    pub market: Pubkey,
    pub note_commitment: [u8; 32],
    pub amount: u64,
    pub price_limit: u64,
    pub side: u8,
    pub note_amount: u64,
    pub expiry_slot: u64,
    pub order_id: [u8; 16],
    /// 0 = LIMIT, 1 = IOC, 2 = FOK.
    pub order_type: u8,
    /// 0 = any fill allowed.
    pub min_fill_qty: u64,
    /// Owner commitment tied to the trading key (used for change-note derivation).
    pub user_commitment: [u8; 32],
    /// Slot index identifying which PendingOrder PDA to write.
    pub slot_index: u8,
}

#[derive(Accounts)]
#[instruction(args: SubmitOrderArgs)]
pub struct SubmitOrder<'info> {
    /// Trading key — slot owner and tx signer. Anchor's Signer<'info>
    /// enforces that the caller signed the tx. The PER JWT auth layer
    /// enforces Permission Group membership before the ix ever reaches
    /// the on-chain program.
    pub trading_key: Signer<'info>,

    /// The pre-allocated, already-delegated PendingOrder slot.
    /// Anchor validates the seeds so a wrong slot_index, market, or
    /// trading_key causes a ConstraintSeeds error before the handler runs.
    #[account(
        mut,
        seeds = [
            PENDING_ORDER_SEED,
            args.market.as_ref(),
            trading_key.key().as_ref(),
            &[args.slot_index],
        ],
        bump = pending_order.load()?.bump,
    )]
    pub pending_order: AccountLoader<'info, PendingOrder>,
}

pub fn submit_order_handler(ctx: Context<SubmitOrder>, args: SubmitOrderArgs) -> Result<()> {
    // --- Parameter validation ---
    require!(
        args.side == ORDER_SIDE_BID || args.side == ORDER_SIDE_ASK,
        MatchingError::InvalidSide
    );
    require!(
        args.order_type == ORDER_TYPE_LIMIT
            || args.order_type == ORDER_TYPE_IOC
            || args.order_type == ORDER_TYPE_FOK,
        MatchingError::InvalidOrderType
    );
    require!(args.amount > 0, MatchingError::ZeroAmount);
    require!(args.price_limit > 0, MatchingError::ZeroPrice);
    // Reserve the all-zero order_id as the `RELOCK_ORDER_ID_NONE` sentinel
    // in MatchResult. Client code MUST pick a random 16-byte id anyway.
    require!(
        args.order_id != [0u8; 16],
        MatchingError::InvalidOrderId
    );

    // min_fill_qty must not exceed amount (silly orders rejected at ingress).
    require!(
        args.min_fill_qty <= args.amount,
        MatchingError::AmountBelowMinOrderSize
    );

    // Expiry must be in the future.
    {
        let now = Clock::get()?.slot;
        require!(args.expiry_slot > now, MatchingError::ExpiryInPast);
    }

    // Notional / collateral sufficiency check:
    //   - BUY:  note is QUOTE-denominated; required = amount * price_limit.
    //   - SELL: note is BASE-denominated;  required = amount.
    // `run_batch` applies the same-unit conservation law
    // (`note.amount == trade_leg + change_leg + fee_leg`) where the legs
    // are all in the note's native currency — so matching this check to
    // the same semantic is the principled choice.
    let required = if args.side == ORDER_SIDE_BID {
        (args.amount as u128)
            .checked_mul(args.price_limit as u128)
            .ok_or(MatchingError::NotionalOverflow)?
    } else {
        args.amount as u128
    };
    require!(
        required <= args.note_amount as u128,
        MatchingError::NotionalExceedsNoteValue
    );

    // --- Slot availability check ---
    {
        let po = ctx.accounts.pending_order.load()?;
        require!(
            po.status == PENDING_STATUS_EMPTY,
            MatchingError::NoteAlreadyLocked // slot occupied — closest existing error
        );
    }

    // --- Write order intent into the delegated PendingOrder slot ---
    // This is the only mutation. It happens entirely inside the ER TEE.
    // No vault CPI. No NoteLock PDA. No L1 transaction.
    let arrival_slot = Clock::get()?.slot;
    {
        let mut po = ctx.accounts.pending_order.load_mut()?;
        po.note_commitment = args.note_commitment;
        po.user_commitment = args.user_commitment;
        po.market = args.market;
        po.price_limit = args.price_limit;
        po.amount = args.amount;
        po.note_amount = args.note_amount;
        po.min_fill_qty = args.min_fill_qty;
        po.expiry_slot = args.expiry_slot;
        po.arrival_slot = arrival_slot;
        po.order_id = args.order_id;
        po.side = args.side;
        po.order_type = args.order_type;
        po.status = PENDING_STATUS_PENDING;
    }

    emit!(OrderSubmitted {
        market: args.market,
        trading_key: ctx.accounts.trading_key.key(),
        slot_index: args.slot_index,
        arrival_slot,
    });
    Ok(())
}

/// Compute the order inclusion commitment.
/// SHA-256(order_id || note_commitment || trading_key) — globally unique
/// because order_id is client-chosen and required non-zero per user.
pub fn compute_inclusion_commitment(
    order_id: &[u8; 16],
    note_commitment: &[u8; 32],
    trading_key: &Pubkey,
) -> [u8; 32] {
    solana_program::hash::hashv(&[
        order_id.as_ref(),
        note_commitment.as_ref(),
        trading_key.as_ref(),
    ])
    .to_bytes()
}

#[event]
pub struct OrderSubmitted {
    pub market: Pubkey,
    pub trading_key: Pubkey,
    pub slot_index: u8,
    pub arrival_slot: u64,
}
