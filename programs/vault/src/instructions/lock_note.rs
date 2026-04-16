use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(note_commitment: [u8; 32], order_id: [u8; 16], expiry_slot: u64)]
pub struct LockNote<'info> {
    /// The TEE-operated relayer. We enforce that `tee_authority.key()` ==
    /// `vault_config.tee_pubkey` so only the registered TEE can lock notes.
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
        constraint = tee_authority.key() == vault_config.tee_pubkey @ VaultError::Unauthorized,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + NoteLock::INIT_SPACE,
        seeds = [NoteLock::SEED, note_commitment.as_ref()],
        bump,
    )]
    pub note_lock: Account<'info, NoteLock>,

    pub system_program: Program<'info, System>,
}

pub fn lock_note_handler(
    ctx: Context<LockNote>,
    note_commitment: [u8; 32],
    order_id: [u8; 16],
    expiry_slot: u64,
) -> Result<()> {
    let clock = Clock::get()?;
    require!(expiry_slot > clock.slot, VaultError::InvalidExpirySlot);

    let lock = &mut ctx.accounts.note_lock;
    lock.note_commitment = note_commitment;
    lock.order_id = order_id;
    lock.expiry_slot = expiry_slot;
    lock.locked_by = ctx.accounts.tee_authority.key();
    lock.bump = ctx.bumps.note_lock;

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
