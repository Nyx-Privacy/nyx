//! `init_market` — one-time per-market setup.
//!
//! Phase 3: created DarkCLOB + MatchingConfig.
//! Phase 4: also creates BatchResults and records the full MatchingConfig
//! parameter bundle (mints, Pyth account, circuit-breaker bps, tick, min
//! order size).

use anchor_lang::prelude::*;
use core::mem::size_of;
use vault::state::VaultConfig;

use crate::errors::MatchingError;
use crate::state::{BatchResults, DarkCLOB, MatchingConfig};

/// All parameters for a new market packed into one struct so the Anchor
/// ix stays a single argument. Fields are in declaration order for Borsh.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct InitMarketArgs {
    pub market: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pyth_account: Pubkey,
    pub batch_interval_slots: u64,
    pub circuit_breaker_bps: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
}

#[derive(Accounts)]
#[instruction(args: InitMarketArgs)]
pub struct InitMarket<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

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
        seeds = [DarkCLOB::SEED, args.market.as_ref()],
        bump,
    )]
    pub dark_clob: AccountLoader<'info, DarkCLOB>,

    #[account(
        init,
        payer = payer,
        space = 8 + size_of::<MatchingConfig>(),
        seeds = [MatchingConfig::SEED, args.market.as_ref()],
        bump,
    )]
    pub matching_config: AccountLoader<'info, MatchingConfig>,

    #[account(
        init,
        payer = payer,
        space = 8 + size_of::<BatchResults>(),
        seeds = [BatchResults::SEED, args.market.as_ref()],
        bump,
    )]
    pub batch_results: AccountLoader<'info, BatchResults>,

    pub system_program: Program<'info, System>,
}

pub fn init_market_handler(ctx: Context<InitMarket>, args: InitMarketArgs) -> Result<()> {
    require!(args.batch_interval_slots > 0, MatchingError::ZeroAmount);
    require!(args.circuit_breaker_bps > 0, MatchingError::ZeroAmount);

    let vault_cfg = ctx.accounts.vault_config.load()?;

    {
        let mut clob = ctx.accounts.dark_clob.load_init()?;
        clob.market = args.market;
        clob.next_seq = 0;
        clob.order_count = 0;
        clob.bump = ctx.bumps.dark_clob;
        clob._padding = [0u8; 7];
    }

    {
        let mut cfg = ctx.accounts.matching_config.load_init()?;
        cfg.market = args.market;
        cfg.root_key = vault_cfg.root_key;
        cfg.base_mint = args.base_mint;
        cfg.quote_mint = args.quote_mint;
        cfg.pyth_account = args.pyth_account;
        cfg.batch_interval_slots = args.batch_interval_slots;
        cfg.circuit_breaker_bps = args.circuit_breaker_bps;
        cfg.tick_size = args.tick_size;
        cfg.min_order_size = args.min_order_size;
        cfg.bump = ctx.bumps.matching_config;
        cfg._padding = [0u8; 7];
    }

    {
        let mut br = ctx.accounts.batch_results.load_init()?;
        br.market = args.market;
        br.last_inclusion_root = [0u8; 32];
        br.last_batch_slot = 0;
        br.last_match_count = 0;
        br.last_clearing_price = 0;
        br.last_pyth_twap = 0;
        br.last_circuit_breaker_tripped = 0;
        br._padding_a = [0u8; 7];
        br.write_cursor = 0;
        br.next_match_id = 0;
        br.bump = ctx.bumps.batch_results;
        br._padding_b = [0u8; 7];
    }

    emit!(MarketInitialized {
        market: args.market,
        root_key: vault_cfg.root_key,
        base_mint: args.base_mint,
        quote_mint: args.quote_mint,
        pyth_account: args.pyth_account,
    });
    Ok(())
}

#[event]
pub struct MarketInitialized {
    pub market: Pubkey,
    pub root_key: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pyth_account: Pubkey,
}
