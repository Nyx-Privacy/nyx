use crate::errors::VaultError;
use crate::state::*;
use crate::zk::{
    verifier::make_vk, verify_groth16_proof, vk_valid_wallet_create::*, Groth16Proof,
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], proof: Groth16Proof)]
pub struct CreateWallet<'info> {
    /// Root Key signer.
    #[account(mut)]
    pub owner: Signer<'info>,

    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        init,
        payer = owner,
        space = 8 + WalletEntry::INIT_SPACE,
        seeds = [WalletEntry::SEED, commitment.as_ref()],
        bump,
    )]
    pub wallet_entry: Account<'info, WalletEntry>,

    pub system_program: Program<'info, System>,
}

pub fn create_wallet_handler(
    ctx: Context<CreateWallet>,
    commitment: [u8; 32],
    proof: Groth16Proof,
) -> Result<()> {
    // VALID_WALLET_CREATE has exactly 1 public input: the commitment itself.
    let public_inputs: [[u8; 32]; 1] = [commitment];

    let vk = make_vk(
        &VALID_WALLET_CREATE_ALPHA_G1,
        &VALID_WALLET_CREATE_BETA_G2,
        &VALID_WALLET_CREATE_GAMMA_G2,
        &VALID_WALLET_CREATE_DELTA_G2,
        &VALID_WALLET_CREATE_IC,
    );

    verify_groth16_proof::<1>(&vk, &proof, &public_inputs)?;

    let w = &mut ctx.accounts.wallet_entry;
    w.commitment = commitment;
    w.owner = ctx.accounts.owner.key();
    w.created_slot = Clock::get()?.slot;
    w.bump = ctx.bumps.wallet_entry;

    emit!(WalletCreated {
        commitment,
        owner: ctx.accounts.owner.key(),
        slot: w.created_slot,
    });

    // Silence unused warnings when running cargo check without full program.
    let _ = &ctx.accounts.vault_config;
    let _ = VaultError::Unauthorized;
    Ok(())
}

#[event]
pub struct WalletCreated {
    pub commitment: [u8; 32],
    pub owner: Pubkey,
    pub slot: u64,
}
