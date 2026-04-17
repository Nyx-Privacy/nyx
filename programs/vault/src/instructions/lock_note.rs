use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

#[derive(Accounts)]
#[instruction(note_commitment: [u8; 32], order_id: [u8; 16], expiry_slot: u64)]
pub struct LockNote<'info> {
    /// The TEE-operated relayer. We enforce that `tee_authority.key()` ==
    /// `vault_config.tee_pubkey` so only the registered TEE can lock notes.
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    #[account(
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<NoteLock>(),
        seeds = [NoteLock::SEED, note_commitment.as_ref()],
        bump,
    )]
    pub note_lock: AccountLoader<'info, NoteLock>,

    pub system_program: Program<'info, System>,
}

pub fn lock_note_handler(
    ctx: Context<LockNote>,
    note_commitment: [u8; 32],
    order_id: [u8; 16],
    expiry_slot: u64,
) -> Result<()> {
    let cfg = ctx.accounts.vault_config.load()?;
    require!(
        ctx.accounts.tee_authority.key() == cfg.tee_pubkey,
        VaultError::Unauthorized
    );

    let clock = Clock::get()?;
    require!(expiry_slot > clock.slot, VaultError::InvalidExpirySlot);

    let lock = &mut ctx.accounts.note_lock.load_init()?;
    lock.note_commitment = note_commitment;
    lock.order_id = order_id;
    lock.expiry_slot = expiry_slot;
    lock.locked_by = ctx.accounts.tee_authority.key();
    lock.bump = ctx.bumps.note_lock;
    lock._padding = [0u8; 7];

    emit!(NoteLocked {
        note_commitment,
        order_id,
        expiry_slot,
    });
    Ok(())
}

#[event]
pub struct NoteLocked {
    pub note_commitment: [u8; 32],
    pub order_id: [u8; 16],
    pub expiry_slot: u64,
}
