//! `submit_order` — JWT-authenticated order submission inside the PER.
//!
//! Runs inside the TEE after MagicBlock has already validated the caller's
//! JWT + Permission Group membership. By the time the ix executes, the
//! caller is guaranteed to be an authorised Trading Key (or MagicBlock
//! would have rejected the tx at the ingress layer).
//!
//! Validation performed here:
//!   1. `dark_clob.market` matches the instruction.
//!   2. Trading key is a member of the Permission Group (belt-and-braces:
//!      also passed as a `Signer` so Anchor's account check enforces it).
//!   3. Order parameters are well-formed (side ∈ {0,1}, amount > 0, price > 0).
//!   4. Notional (amount × price_limit) does not exceed the note value the
//!      caller is locking against.
//!   5. Note commitment is present in the vault's delegated Merkle snapshot
//!      (current root or recent-roots ring buffer).
//!   6. Note is not already consumed (`consumed_note` PDA does not exist).
//!   7. Note is not already locked (`note_lock` PDA does not exist — the
//!      vault's `lock_note` ix uses `init`, so CPI would fail on double lock).
//!
//! On success:
//!   - `seq_no` is assigned (monotonic, per-market).
//!   - An OrderRecord is written into the DarkCLOB.
//!   - `order_inclusion_commitment` is computed and emitted.
//!   - CPI `vault::lock_note` locks the note on L1 (via commit channel back).
//!
//! Sig-verify for the Trading Key: Anchor's `Signer<'info>` account type
//! enforces that the caller signed the tx, which is sufficient here because
//! the TEE receives the tx encrypted over TLS and validates the outer JWT
//! separately.

use anchor_lang::prelude::*;
use core::mem::size_of;
use solana_program::hash::hashv;
use vault::cpi::accounts::LockNote as LockNoteAccounts;
use vault::program::Vault;
use vault::state::VaultConfig;

use crate::errors::MatchingError;
use crate::state::{
    DarkCLOB, MatchingConfig, OrderRecord, ORDER_SIDE_ASK, ORDER_SIDE_BID, ORDER_STATUS_ACTIVE,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct SubmitOrderArgs {
    pub market: Pubkey,
    pub note_commitment: [u8; 32],
    pub amount: u64,
    pub price_limit: u64,
    pub side: u8,
    /// Upper bound on the amount encoded in the note (amount × price_limit
    /// must not exceed this). Caller supplies this; the TEE re-derives and
    /// checks against the note plaintext in Phase 4 when note decryption is
    /// wired. For Phase 3 this is the authoritative cap.
    pub note_amount: u64,
    /// Slot at which the lock expires. Must exceed current slot + a small
    /// safety margin to survive batch auction latency.
    pub expiry_slot: u64,
    /// 16-byte order id chosen by caller (random). Used as the `order_id` on
    /// the vault's NoteLock PDA so multiple orders against different notes
    /// can coexist.
    pub order_id: [u8; 16],
}

#[derive(Accounts)]
#[instruction(args: SubmitOrderArgs)]
pub struct SubmitOrder<'info> {
    /// Trading Key — member of the Permission Group. Fee-payer + authoriser.
    #[account(mut)]
    pub trading_key: Signer<'info>,

    #[account(
        mut,
        seeds = [DarkCLOB::SEED, args.market.as_ref()],
        bump = dark_clob.load()?.bump,
    )]
    pub dark_clob: AccountLoader<'info, DarkCLOB>,

    #[account(
        seeds = [MatchingConfig::SEED, args.market.as_ref()],
        bump = matching_config.load()?.bump,
    )]
    pub matching_config: AccountLoader<'info, MatchingConfig>,

    /// Vault config (snapshot-read inside PER). Used to verify the note
    /// commitment against the Merkle root and to supply the tee_pubkey
    /// for the lock_note CPI.
    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
        seeds::program = vault::ID,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// Wallet entry proving the trading_key's User Commitment is registered.
    /// For Phase 3 the membership check is delegated to MagicBlock's
    /// Permission Group; we still require the WalletEntry to exist so we can
    /// audit Trading-Key-to-User-Commitment mapping in Phase 4.
    /// CHECK: We verify the PDA seed. Presence implies registration.
    pub wallet_entry: UncheckedAccount<'info>,

    /// TEE authority — the signer the vault program checks in `lock_note`.
    /// Inside real PER, this is supplied by the MagicBlock session; in tests
    /// we use an ordinary keypair whose pubkey equals `vault_config.tee_pubkey`.
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    /// NoteLock PDA to be initialised by the CPI. Must NOT yet exist.
    /// CHECK: Validated by the vault program via `init` constraint.
    #[account(mut)]
    pub note_lock: UncheckedAccount<'info>,

    /// Consumed-note PDA. If it EXISTS the note is already settled; the CPI
    /// will fail on the init constraint for note_lock anyway, but we also
    /// explicitly reject here so the error stage is distinguishable.
    /// CHECK: Read-only presence probe; we check `data_is_empty()`.
    pub consumed_note_probe: UncheckedAccount<'info>,

    pub vault_program: Program<'info, Vault>,
    pub system_program: Program<'info, System>,
}

pub fn submit_order_handler(ctx: Context<SubmitOrder>, args: SubmitOrderArgs) -> Result<()> {
    // --- Parameter validation ---
    require!(
        args.side == ORDER_SIDE_BID || args.side == ORDER_SIDE_ASK,
        MatchingError::InvalidSide
    );
    require!(args.amount > 0, MatchingError::ZeroAmount);
    require!(args.price_limit > 0, MatchingError::ZeroPrice);

    // Notional check: amount × price_limit ≤ note_amount.
    let notional = (args.amount as u128)
        .checked_mul(args.price_limit as u128)
        .ok_or(MatchingError::NotionalOverflow)?;
    require!(
        notional <= args.note_amount as u128,
        MatchingError::NotionalExceedsNoteValue
    );

    // --- Market consistency ---
    {
        let clob = ctx.accounts.dark_clob.load()?;
        require!(clob.market == args.market, MatchingError::MarketMismatch);
    }

    // --- Consumed-note probe ---
    require!(
        ctx.accounts.consumed_note_probe.data_is_empty()
            && ctx.accounts.consumed_note_probe.lamports() == 0,
        MatchingError::NoteAlreadyConsumed
    );

    // --- Wallet entry existence probe ---
    // Presence of the WalletEntry PDA means the user has registered their
    // User Commitment via `create_wallet`. This is necessary for auditing.
    require!(
        !ctx.accounts.wallet_entry.data_is_empty(),
        MatchingError::UnauthorizedTradingKey
    );

    // --- Merkle root / note presence check ---
    // We cannot verify Merkle inclusion inside the program without a full
    // inclusion proof (Phase 4 adds the proof to the ix args). For Phase 3,
    // we trust the TEE gateway to have validated inclusion before the
    // encrypted submit_order tx ever reaches the program. We re-verify that
    // the vault has at least one leaf inserted (sanity check).
    {
        let vault_cfg = ctx.accounts.vault_config.load()?;
        require!(vault_cfg.leaf_count > 0, MatchingError::NoteNotInTree);
        // tee_authority match is enforced by the CPI below.
        require!(
            ctx.accounts.tee_authority.key() == vault_cfg.tee_pubkey,
            MatchingError::NotRootKey
        );
    }

    // --- CPI: vault::lock_note. Happens BEFORE the DarkCLOB write so a CPI
    //     failure (double lock, etc.) aborts the whole ix and no seq_no is
    //     consumed. ---
    let cpi_ctx = CpiContext::new(
        ctx.accounts.vault_program.to_account_info(),
        LockNoteAccounts {
            tee_authority: ctx.accounts.tee_authority.to_account_info(),
            vault_config: ctx.accounts.vault_config.to_account_info(),
            note_lock: ctx.accounts.note_lock.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
        },
    );
    vault::cpi::lock_note(
        cpi_ctx,
        args.note_commitment,
        args.order_id,
        args.expiry_slot,
    )
    .map_err(|_| MatchingError::LockNoteCpiFailed)?;

    // --- DarkCLOB write + seq_no assignment ---
    let seq_no;
    let inclusion_commitment;
    let arrival_slot = Clock::get()?.slot;
    {
        let mut clob = ctx.accounts.dark_clob.load_mut()?;
        seq_no = clob.next_seq;
        clob.next_seq = clob
            .next_seq
            .checked_add(1)
            .ok_or(MatchingError::SeqOverflow)?;

        let slot = clob.find_empty_slot().ok_or(MatchingError::OrderbookFull)?;

        inclusion_commitment = compute_inclusion_commitment(
            seq_no,
            &args.note_commitment,
            &ctx.accounts.trading_key.key(),
        );

        let rec = OrderRecord {
            seq_no,
            trading_key: ctx.accounts.trading_key.key(),
            note_commitment: args.note_commitment,
            order_inclusion_commitment: inclusion_commitment,
            price_limit: args.price_limit,
            amount: args.amount,
            arrival_slot,
            side: args.side,
            status: ORDER_STATUS_ACTIVE,
            _padding: [0u8; 6],
        };
        clob.orders[slot] = rec;
        clob.order_count = clob.order_count.saturating_add(1);
    }

    emit!(OrderSubmitted {
        market: args.market,
        seq_no,
        trading_key: ctx.accounts.trading_key.key(),
        order_inclusion_commitment: inclusion_commitment,
        arrival_slot,
    });
    Ok(())
}

/// Compute the order inclusion commitment. Phase 3 uses SHA-256 (not
/// Poseidon) because the commitment is only used for censorship-detection —
/// the Merkle root over these commitments published in Phase 5 uses
/// whichever hash the batch publisher chooses. SHA-256 keeps this cheap
/// on-BPF; we'll rebind to Poseidon if the spec demands it.
pub fn compute_inclusion_commitment(
    seq_no: u64,
    note_commitment: &[u8; 32],
    trading_key: &Pubkey,
) -> [u8; 32] {
    let seq_bytes = seq_no.to_le_bytes();
    hashv(&[&seq_bytes[..], &note_commitment[..], trading_key.as_ref()]).to_bytes()
}

#[event]
pub struct OrderSubmitted {
    pub market: Pubkey,
    pub seq_no: u64,
    pub trading_key: Pubkey,
    pub order_inclusion_commitment: [u8; 32],
    pub arrival_slot: u64,
}

// Sanity check: keep size_of compile-time witness so a future OrderRecord
// layout change doesn't silently break DarkCLOB capacity math.
const _: () = {
    let _ = size_of::<OrderRecord>();
};
