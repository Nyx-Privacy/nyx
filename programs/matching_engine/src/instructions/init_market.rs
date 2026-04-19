//! `init_market` — one-time per-market setup.
//!
//! Creates the DarkCLOB + MatchingConfig PDAs on L1. Permission Group setup
//! and delegation to the PER validator are separate ixs (`configure_access` +
//! `delegate_dark_clob`) so that the caller can bundle them into one tx
//! (mirroring the reference darkpool/ pattern) or split them for tests.

use anchor_lang::prelude::*;
use core::mem::size_of;
use vault::state::VaultConfig;

use crate::errors::MatchingError;
use crate::state::{DarkCLOB, MatchingConfig};

#[derive(Accounts)]
#[instruction(market: Pubkey, batch_interval_slots: u64)]
pub struct InitMarket<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Snapshot-read to copy the current root_key into MatchingConfig.
    /// We intentionally do NOT require root_key signature here — anyone can
    /// create a market; only `configure_access` is root-key-gated.
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
        seeds::program = vault::ID,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    #[account(
        init,
        payer = payer,
        space = 8 + size_of::<DarkCLOB>(),
        seeds = [DarkCLOB::SEED, market.as_ref()],
        bump,
    )]
    pub dark_clob: AccountLoader<'info, DarkCLOB>,

    #[account(
        init,
        payer = payer,
        space = 8 + size_of::<MatchingConfig>(),
        seeds = [MatchingConfig::SEED, market.as_ref()],
        bump,
    )]
    pub matching_config: AccountLoader<'info, MatchingConfig>,

    pub system_program: Program<'info, System>,
}

pub fn init_market_handler(
    ctx: Context<InitMarket>,
    market: Pubkey,
    batch_interval_slots: u64,
) -> Result<()> {
    require!(batch_interval_slots > 0, MatchingError::ZeroAmount);

    let vault_cfg = ctx.accounts.vault_config.load()?;

    let mut clob = ctx.accounts.dark_clob.load_init()?;
    clob.market = market;
    clob.next_seq = 0;
    clob.order_count = 0;
    clob.bump = ctx.bumps.dark_clob;
    clob._padding = [0u8; 7];

    let mut cfg = ctx.accounts.matching_config.load_init()?;
    cfg.market = market;
    cfg.root_key = vault_cfg.root_key;
    cfg.batch_interval_slots = batch_interval_slots;
    cfg.bump = ctx.bumps.matching_config;
    cfg._padding = [0u8; 7];

    emit!(MarketInitialized {
        market,
        root_key: vault_cfg.root_key,
    });
    Ok(())
}

#[event]
pub struct MarketInitialized {
    pub market: Pubkey,
    pub root_key: Pubkey,
}
