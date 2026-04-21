//! Test/dev-net helper: create a mock-Pyth oracle account with the
//! `NYXMKPTH` magic + a u64 TWAP at offset 8.
//!
//! Purpose: on real devnet we can't `svm.set_account(...)` to inject an
//! arbitrary-owner 16-byte oracle stub the way the Rust harness does under
//! LiteSVM. This ix is the devnet equivalent — it CPIs System Program to
//! create a 16-byte account owned by this program, then writes the mock
//! payload in-place.
//!
//! The account's presence is entirely benign on any cluster: run_batch
//! reads an oracle account whose pubkey is frozen into `matching_config`
//! at init_market time, so unless someone deliberately passes a mock
//! account pubkey to `init_market`, this ix has no side-effect on real
//! production markets. Guarded only by: caller must sign both the payer
//! and the new mock-oracle keypair.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{create_account, CreateAccount};

use crate::state::pyth::MOCK_PYTH_MAGIC;

#[derive(Accounts)]
pub struct InitMockOracle<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// New oracle account to create. Must be a keypair-backed signer so
    /// System Program can allocate its storage. Ends up owned by this
    /// program with exactly 16 bytes of data.
    /// CHECK: Validated by the System Program during the CPI below.
    #[account(mut)]
    pub mock_oracle: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn init_mock_oracle_handler(ctx: Context<InitMockOracle>, twap: u64) -> Result<()> {
    let rent = Rent::get()?;
    let space: u64 = 16;
    let lamports = rent.minimum_balance(space as usize);

    create_account(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            CreateAccount {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.mock_oracle.to_account_info(),
            },
        ),
        lamports,
        space,
        &crate::ID,
    )?;

    let mut data = ctx.accounts.mock_oracle.try_borrow_mut_data()?;
    data[0..8].copy_from_slice(&MOCK_PYTH_MAGIC);
    data[8..16].copy_from_slice(&twap.to_le_bytes());
    Ok(())
}
