//! `configure_access` — root-key-authorised Permission Group setup.
//!
//! Wraps MagicBlock's `CreatePermissionCpiBuilder` (first call) or
//! `UpdatePermissionCpiBuilder` (subsequent calls). The permissioned account
//! is the DarkCLOB PDA (matching_engine owns it, so we can PDA-sign via
//! `invoke_signed`). The root-key gate enforces spec §23.3.3
//! `test_permission_group_setup_root_key_only`.
//!
//! Accepted `MemberArg.flags` mirror MagicBlock's `Member` flags (see
//! ephemeral_rollups_sdk::access_control::structs::member).

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::access_control::instructions::{
    CreatePermissionCpiBuilder, UpdatePermissionCpiBuilder,
};
use ephemeral_rollups_sdk::access_control::structs::{Member, MembersArgs};
use ephemeral_rollups_sdk::consts::PERMISSION_PROGRAM_ID;

use crate::errors::MatchingError;
use crate::state::{DarkCLOB, MatchingConfig};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct MemberArg {
    pub flags: u8,
    pub pubkey: Pubkey,
}

#[derive(Accounts)]
#[instruction(market: Pubkey, members: Vec<MemberArg>, is_update: bool)]
pub struct ConfigureAccess<'info> {
    /// Must equal `matching_config.root_key`. Verified in handler.
    #[account(mut)]
    pub root_key: Signer<'info>,

    #[account(
        mut,
        seeds = [DarkCLOB::SEED, market.as_ref()],
        bump = dark_clob.load()?.bump,
    )]
    pub dark_clob: AccountLoader<'info, DarkCLOB>,

    #[account(
        seeds = [MatchingConfig::SEED, market.as_ref()],
        bump = matching_config.load()?.bump,
    )]
    pub matching_config: AccountLoader<'info, MatchingConfig>,

    /// Permission PDA (derived by MagicBlock permission program from the
    /// permissioned account). We pass this as an unchecked AccountInfo because
    /// the SDK's `Permission::find_pda` uses MagicBlock-specific seeds.
    /// CHECK: Validated by the MagicBlock permission program during CPI.
    #[account(mut)]
    pub permission: UncheckedAccount<'info>,

    /// CHECK: Must match PERMISSION_PROGRAM_ID — enforced by address check.
    #[account(address = PERMISSION_PROGRAM_ID)]
    pub permission_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn configure_access_handler(
    ctx: Context<ConfigureAccess>,
    market: Pubkey,
    members: Vec<MemberArg>,
    is_update: bool,
) -> Result<()> {
    // Root-key gate.
    {
        let cfg = ctx.accounts.matching_config.load()?;
        require!(cfg.market == market, MatchingError::MarketMismatch);
        require!(
            ctx.accounts.root_key.key() == cfg.root_key,
            MatchingError::NotRootKey
        );
    }

    let sdk_members: Vec<Member> = members
        .iter()
        .map(|m| Member {
            flags: m.flags,
            pubkey: m.pubkey,
        })
        .collect();

    // DarkCLOB PDA seeds for invoke_signed.
    let bump = ctx.accounts.dark_clob.load()?.bump;
    let seeds: &[&[u8]] = &[
        DarkCLOB::SEED,
        market.as_ref(),
        core::slice::from_ref(&bump),
    ];

    if is_update {
        UpdatePermissionCpiBuilder::new(&ctx.accounts.permission_program.to_account_info())
            .permissioned_account(&ctx.accounts.dark_clob.to_account_info(), true)
            .authority(&ctx.accounts.dark_clob.to_account_info(), false)
            .permission(&ctx.accounts.permission.to_account_info())
            .args(MembersArgs {
                members: Some(sdk_members),
            })
            .invoke_signed(&[seeds])
            .map_err(|_| MatchingError::PermissionCpiFailed)?;
    } else {
        CreatePermissionCpiBuilder::new(&ctx.accounts.permission_program.to_account_info())
            .permissioned_account(&ctx.accounts.dark_clob.to_account_info())
            .permission(&ctx.accounts.permission.to_account_info())
            .payer(&ctx.accounts.root_key.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .args(MembersArgs {
                members: Some(sdk_members),
            })
            .invoke_signed(&[seeds])
            .map_err(|_| MatchingError::PermissionCpiFailed)?;
    }

    emit!(PermissionGroupConfigured {
        market,
        is_update,
        member_count: members.len() as u32,
    });
    Ok(())
}

#[event]
pub struct PermissionGroupConfigured {
    pub market: Pubkey,
    pub is_update: bool,
    pub member_count: u32,
}
