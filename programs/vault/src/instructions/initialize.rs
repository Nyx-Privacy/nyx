use crate::errors::VaultError;
use crate::merkle::{compute_zero_subtree_roots, empty_root};
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

#[derive(Accounts)]
#[instruction(tee_pubkey: Pubkey, root_key: Pubkey)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + size_of::<VaultConfig>(),
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    pub system_program: Program<'info, System>,
}

pub fn initialize_handler(
    ctx: Context<Initialize>,
    tee_pubkey: Pubkey,
    root_key: Pubkey,
) -> Result<()> {
    let cfg = &mut ctx.accounts.vault_config.load_init()?;

    cfg.admin = ctx.accounts.admin.key();
    cfg.tee_pubkey = tee_pubkey;
    cfg.root_key = root_key;
    cfg.leaf_count = 0;
    cfg.zero_subtree_roots = compute_zero_subtree_roots()?;
    cfg.right_path = [[0u8; 32]; MERKLE_DEPTH as usize];
    cfg.current_root = empty_root(&cfg.zero_subtree_roots)?;
    cfg.roots = [[0u8; 32]; ROOT_HISTORY_SIZE];
    cfg.roots_head = 0;
    cfg.bump = ctx.bumps.vault_config;
    cfg.protocol_owner_commitment = [0u8; 32];
    cfg.fee_rate_bps = 0;
    cfg._padding = [0u8; 4];
    let _ = VaultError::ZeroAmount; // keep errors linked in
    Ok(())
}
