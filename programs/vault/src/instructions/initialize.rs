use crate::errors::VaultError;
use crate::merkle::{compute_zero_subtree_roots, empty_root};
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(tee_pubkey: Pubkey)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + VaultConfig::INIT_SPACE,
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    pub system_program: Program<'info, System>,
}

pub fn initialize_handler(ctx: Context<Initialize>, tee_pubkey: Pubkey) -> Result<()> {
    let cfg = &mut ctx.accounts.vault_config;

    cfg.admin = ctx.accounts.admin.key();
    cfg.tee_pubkey = tee_pubkey;
    cfg.leaf_count = 0;
    cfg.zero_subtree_roots = compute_zero_subtree_roots()?;
    cfg.right_path = [[0u8; 32]; MERKLE_DEPTH as usize];
    cfg.current_root = empty_root(&cfg.zero_subtree_roots)?;
    cfg.roots = [[0u8; 32]; ROOT_HISTORY_SIZE];
    cfg.roots_head = 0;
    cfg.bump = ctx.bumps.vault_config;
    let _ = VaultError::ZeroAmount; // keep errors linked in
    Ok(())
}
