//! `run_batch` — periodic batch auction (spec §20.6 + §23.4).
//!
//! Signer-gated to the TEE authority. Runs on the PER — DarkCLOB,
//! MatchingConfig, BatchResults, and all PendingOrder PDAs are delegated.
//!
//! **Privacy model (post-privacy-fix):**
//! Orders are no longer stored in the DarkCLOB. Instead, each PendingOrder
//! PDA (pre-allocated on L1, delegated to ER, written by `submit_order`
//! inside the ER) is passed as a remaining_account. This is the exact
//! analogue of `reveal_winner` in the MagicBlock RPS example — run_batch
//! reads all delegated PendingOrder PDAs inside the ER, matches them, and
//! commits only BatchResults back to L1. Individual order intents never
//! surface as L1 transactions; unmatched orders leave zero L1 trace.
//!
//! Algorithm (matches spec §20.6 step 71-75):
//!   1. Iterate remaining_accounts — deserialise PendingOrder PDAs.
//!   2. Drain expired / too-close-to-expiry slots (reset to Empty).
//!   3. Read Pyth TWAP from the oracle account.
//!   4. Partition active Pending slots into bids / asks.
//!   5. Sort bids descending (price, arrival_slot); asks ascending.
//!   6. Compute uniform clearing price P* = argmax_P{min(demand(P),supply(P))}.
//!   7. Circuit breaker: abort if |P* − TWAP| / TWAP > circuit_breaker_bps.
//!   8. Generate MatchResults; update PendingOrder amounts/collateral for
//!      partial fills; reset fully-filled/IOC slots to Empty.
//!   9. Compute inclusion_root over all Pending orders' commitments.
//!  10. Flush fee notes; publish stats in BatchResults.

use anchor_lang::prelude::*;

use crate::errors::MatchingError;
use crate::instructions::submit_order::compute_inclusion_commitment;
use crate::state::batch_results::BATCH_RESULTS_CAPACITY;
use crate::state::pyth::read_oracle_price;
use crate::state::{
    change_note, BatchResults, MatchingConfig, MatchResult,
    ORDER_SIDE_ASK, ORDER_SIDE_BID,
    ORDER_TYPE_FOK, ORDER_TYPE_IOC,
    MATCH_RESULT_STATUS_FILLED, RELOCK_ORDER_ID_NONE,
    PENDING_ORDER_SIZE, PENDING_STATUS_PENDING,
    PendingOrder,
};
use darkpool_crypto::note::commitment_from_fields;
use vault::state::VaultConfig;

/// Orders expiring within this many slots of now are drained before matching
/// to ensure the follow-up `tee_forced_settle` has time to land on L1.
pub const SETTLEMENT_BUFFER_SLOTS: u64 = 20;

// ---------------------------------------------------------------------------
// Accounts struct
// ---------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(market: Pubkey)]
pub struct RunBatch<'info> {
    /// TEE authority signer.
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    #[account(
        seeds = [MatchingConfig::SEED, market.as_ref()],
        bump = matching_config.load()?.bump,
    )]
    pub matching_config: AccountLoader<'info, MatchingConfig>,

    #[account(
        mut,
        seeds = [BatchResults::SEED, market.as_ref()],
        bump = batch_results.load()?.bump,
    )]
    pub batch_results: AccountLoader<'info, BatchResults>,

    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
        seeds::program = vault::ID,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// Must equal `matching_config.pyth_account`.
    /// CHECK: validated by pubkey comparison in handler.
    pub oracle_account: UncheckedAccount<'info>,
    // remaining_accounts: all delegated PendingOrder PDAs for this market.
}

// ---------------------------------------------------------------------------
// Internal entry from a remaining_account
// ---------------------------------------------------------------------------

/// Snapshot of a Pending slot's matching-relevant fields plus the index into
/// ctx.remaining_accounts so we can write back after matching.
#[derive(Clone)]
struct PendingEntry {
    ra_idx: usize,
    price_limit: u64,
    amount: u64,
    min_fill_qty: u64,
    order_type: u8,
    note_commitment: [u8; 32],
    note_amount: u64,
    user_commitment: [u8; 32],
    trading_key: Pubkey,
    order_id: [u8; 16],
    expiry_slot: u64,
    arrival_slot: u64,
}

// ---------------------------------------------------------------------------
// Sorting helpers
// ---------------------------------------------------------------------------

fn sort_bids(entries: &mut [PendingEntry]) {
    entries.sort_by(|a, b| {
        b.price_limit
            .cmp(&a.price_limit)
            .then(a.arrival_slot.cmp(&b.arrival_slot))
    });
}

fn sort_asks(entries: &mut [PendingEntry]) {
    entries.sort_by(|a, b| {
        a.price_limit
            .cmp(&b.price_limit)
            .then(a.arrival_slot.cmp(&b.arrival_slot))
    });
}

// ---------------------------------------------------------------------------
// Clearing-price computation (unchanged logic)
// ---------------------------------------------------------------------------

fn compute_clearing_price(bids: &[PendingEntry], asks: &[PendingEntry]) -> Option<(u64, u64)> {
    if bids.is_empty() || asks.is_empty() {
        return None;
    }
    let mut candidates: Vec<u64> = Vec::with_capacity(bids.len() + asks.len());
    for e in bids.iter() { candidates.push(e.price_limit); }
    for e in asks.iter() { candidates.push(e.price_limit); }
    candidates.sort();
    candidates.dedup();

    let mut best_p: Option<u64> = None;
    let mut best_matched: u64 = 0;

    for &p in candidates.iter() {
        let mut demand: u64 = 0;
        for e in bids.iter() {
            if e.price_limit >= p { demand = demand.saturating_add(e.amount); }
        }
        let mut supply: u64 = 0;
        for e in asks.iter() {
            if e.price_limit <= p { supply = supply.saturating_add(e.amount); }
        }
        let matched = demand.min(supply);
        if matched > best_matched {
            best_matched = matched;
            best_p = Some(p);
        }
    }
    best_p.map(|p| (p, best_matched))
}

// ---------------------------------------------------------------------------
// SHA-256 Merkle root (unchanged)
// ---------------------------------------------------------------------------

fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    use solana_program::hash::hashv;
    if leaves.is_empty() { return [0u8; 32]; }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut target = 1usize;
    while target < level.len() { target *= 2; }
    while level.len() < target {
        let last = *level.last().unwrap();
        level.push(last);
    }
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hashv(&[&pair[0], &pair[1]]).to_bytes());
        }
        level = next;
    }
    level[0]
}

fn deviates_by_more_than_bps(p: u64, reference: u64, bps: u64) -> bool {
    if reference == 0 { return true; }
    let diff = p.abs_diff(reference);
    (diff as u128).saturating_mul(10_000) > (reference as u128).saturating_mul(bps as u128)
}

// ---------------------------------------------------------------------------
// Discriminator helper for PendingOrder account verification
// ---------------------------------------------------------------------------

fn pending_order_disc() -> [u8; 8] {
    let h = solana_program::hash::hashv(&[b"account:PendingOrder"]);
    let mut d = [0u8; 8];
    d.copy_from_slice(&h.to_bytes()[..8]);
    d
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub fn run_batch_handler(ctx: Context<RunBatch>, market: Pubkey) -> Result<()> {
    let (base_mint, quote_mint) = {
        let cfg = ctx.accounts.matching_config.load()?;
        require!(cfg.market == market, MatchingError::MarketMismatch);
        require!(
            ctx.accounts.oracle_account.key() == cfg.pyth_account,
            MatchingError::OracleAccountMismatch
        );
        (cfg.base_mint, cfg.quote_mint)
    };

    let (fee_rate_bps, protocol_owner_commitment) = {
        let vc = ctx.accounts.vault_config.load()?;
        (vc.fee_rate_bps as u64, vc.protocol_owner_commitment)
    };

    let now_slot = Clock::get()?.slot;
    let pyth_twap = read_oracle_price(&ctx.accounts.oracle_account.to_account_info())?;
    require!(pyth_twap > 0, MatchingError::OracleZeroPrice);

    let circuit_bps = ctx.accounts.matching_config.load()?.circuit_breaker_bps;

    // --- Reset per-batch FeeAccumulators ---
    {
        let mut br = ctx.accounts.batch_results.load_mut()?;
        br.fee_accumulators[0].token_mint = base_mint;
        br.fee_accumulators[0].accumulated_fees = 0;
        br.fee_accumulators[0].batch_slot = now_slot;
        br.fee_accumulators[0].flushed_commitment = [0u8; 32];
        br.fee_accumulators[1].token_mint = quote_mint;
        br.fee_accumulators[1].accumulated_fees = 0;
        br.fee_accumulators[1].batch_slot = now_slot;
        br.fee_accumulators[1].flushed_commitment = [0u8; 32];
    }

    // --- Pass 1: collect PendingOrder PDAs from remaining_accounts ---
    let disc = pending_order_disc();
    let expected_data_len = 8 + PENDING_ORDER_SIZE;

    let mut bid_entries: Vec<PendingEntry> = Vec::new();
    let mut ask_entries: Vec<PendingEntry> = Vec::new();
    let mut inclusion_leaves: Vec<[u8; 32]> = Vec::new();

    for (idx, ai) in ctx.remaining_accounts.iter().enumerate() {
        // Verify ownership + discriminator.
        if ai.owner != &crate::ID { continue; }
        let data = ai.data.borrow();
        if data.len() < expected_data_len { continue; }
        if data[0..8] != disc { continue; }

        let po: &PendingOrder = bytemuck::from_bytes(&data[8..8 + PENDING_ORDER_SIZE]);

        if po.market != market { continue; }
        if po.status != PENDING_STATUS_PENDING { continue; }

        // Drain orders too close to expiry.
        if po.expiry_slot <= now_slot.saturating_add(SETTLEMENT_BUFFER_SLOTS) {
            drop(data);
            let mut wdata = ai.data.borrow_mut();
            let po_mut: &mut PendingOrder =
                bytemuck::from_bytes_mut(&mut wdata[8..8 + PENDING_ORDER_SIZE]);
            po_mut.reset();
            continue;
        }

        inclusion_leaves.push(compute_inclusion_commitment(
            &po.order_id,
            &po.note_commitment,
            &po.trading_key,
        ));

        let side = po.side;
        let entry = PendingEntry {
            ra_idx: idx,
            price_limit: po.price_limit,
            amount: po.amount,
            min_fill_qty: po.min_fill_qty,
            order_type: po.order_type,
            note_commitment: po.note_commitment,
            note_amount: po.note_amount,
            user_commitment: po.user_commitment,
            trading_key: po.trading_key,
            order_id: po.order_id,
            expiry_slot: po.expiry_slot,
            arrival_slot: po.arrival_slot,
        };

        match side {
            ORDER_SIDE_BID => bid_entries.push(entry),
            ORDER_SIDE_ASK => ask_entries.push(entry),
            _ => {}
        }
    }

    // --- Sort ---
    sort_bids(&mut bid_entries);
    sort_asks(&mut ask_entries);

    // --- Clearing price + matching ---
    let clearing_opt = compute_clearing_price(&bid_entries, &ask_entries);
    let mut cb_tripped: u8 = 0;
    let mut match_count: u64 = 0;
    let clearing_price: u64;

    if let Some((p_star, _)) = clearing_opt {
        if deviates_by_more_than_bps(p_star, pyth_twap, circuit_bps) {
            cb_tripped = 1;
            clearing_price = 0;
        } else {
            clearing_price = p_star;
            let produced = generate_matches(
                &ctx,
                p_star,
                pyth_twap,
                now_slot,
                &bid_entries,
                &ask_entries,
                &base_mint,
                &quote_mint,
                fee_rate_bps,
            )?;
            match_count = produced as u64;
        }
    } else {
        clearing_price = 0;
    }

    // --- Cancel unfilled IOC orders ---
    for ai in ctx.remaining_accounts.iter() {
        if ai.owner != &crate::ID { continue; }
        let check = {
            let data = ai.data.borrow();
            if data.len() < expected_data_len { continue; }
            if data[0..8] != disc { continue; }
            let po: &PendingOrder = bytemuck::from_bytes(&data[8..8 + PENDING_ORDER_SIZE]);
            po.market == market
                && po.status == PENDING_STATUS_PENDING
                && po.order_type == ORDER_TYPE_IOC
        };
        if check {
            let mut wdata = ai.data.borrow_mut();
            let po_mut: &mut PendingOrder =
                bytemuck::from_bytes_mut(&mut wdata[8..8 + PENDING_ORDER_SIZE]);
            po_mut.reset();
        }
    }

    // --- Inclusion root ---
    let inclusion_root = merkle_root_sha256(&inclusion_leaves);

    // --- Flush fee notes ---
    if protocol_owner_commitment != [0u8; 32] && cb_tripped == 0 {
        const FEE_ROLE_BASE: u8 = 0xFB;
        const FEE_ROLE_QUOTE: u8 = 0xFC;

        let mut br = ctx.accounts.batch_results.load_mut()?;

        let base_fees = br.fee_accumulators[0].accumulated_fees;
        if base_fees > 0 {
            let nonce = change_note::derive_nonce(now_slot, FEE_ROLE_BASE);
            let r = change_note::derive_blinding(now_slot, FEE_ROLE_BASE);
            let c = commitment_from_fields(
                &base_mint.to_bytes(),
                base_fees,
                &protocol_owner_commitment,
                &nonce,
                &r,
            )
            .map_err(|_| error!(MatchingError::PoseidonFailed))?;
            br.fee_accumulators[0].flushed_commitment = c;
        }
        let quote_fees = br.fee_accumulators[1].accumulated_fees;
        if quote_fees > 0 {
            let nonce = change_note::derive_nonce(now_slot, FEE_ROLE_QUOTE);
            let r = change_note::derive_blinding(now_slot, FEE_ROLE_QUOTE);
            let c = commitment_from_fields(
                &quote_mint.to_bytes(),
                quote_fees,
                &protocol_owner_commitment,
                &nonce,
                &r,
            )
            .map_err(|_| error!(MatchingError::PoseidonFailed))?;
            br.fee_accumulators[1].flushed_commitment = c;
        }
    }

    // --- Publish stats ---
    {
        let mut br = ctx.accounts.batch_results.load_mut()?;
        br.last_inclusion_root = inclusion_root;
        br.last_batch_slot = now_slot;
        br.last_match_count = match_count;
        br.last_clearing_price = clearing_price;
        br.last_pyth_twap = pyth_twap;
        br.last_circuit_breaker_tripped = cb_tripped;
    }

    emit!(BatchExecuted {
        market,
        batch_slot: now_slot,
        match_count,
        clearing_price,
        pyth_twap,
        circuit_breaker_tripped: cb_tripped == 1,
        inclusion_root,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// generate_matches — produces MatchResults for each (bid, ask) crossing.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn generate_matches(
    ctx: &Context<RunBatch>,
    p_star: u64,
    pyth_twap: u64,
    now_slot: u64,
    bid_entries: &[PendingEntry],
    ask_entries: &[PendingEntry],
    base_mint: &Pubkey,
    quote_mint: &Pubkey,
    fee_rate_bps: u64,
) -> Result<usize> {
    let disc = pending_order_disc();
    let expected_data_len = 8 + PENDING_ORDER_SIZE;
    let mut produced: usize = 0;
    let mut bi = 0usize;
    let mut ai = 0usize;

    // Working copies of amounts (not written back until match confirmed).
    let mut b_amounts: Vec<u64> = bid_entries.iter().map(|e| e.amount).collect();
    let mut a_amounts: Vec<u64> = ask_entries.iter().map(|e| e.amount).collect();

    while bi < bid_entries.len() && ai < ask_entries.len() {
        let b = &bid_entries[bi];
        let a = &ask_entries[ai];

        if b.price_limit < p_star { bi += 1; continue; }
        if a.price_limit > p_star { ai += 1; continue; }

        let b_amt = b_amounts[bi];
        let a_amt = a_amounts[ai];
        let crossable = b_amt.min(a_amt);

        // FOK: reject if full size can't fill.
        if b.order_type == ORDER_TYPE_FOK && crossable < b.amount {
            reset_slot(ctx, b.ra_idx, &disc, expected_data_len);
            bi += 1;
            continue;
        }
        if a.order_type == ORDER_TYPE_FOK && crossable < a.amount {
            reset_slot(ctx, a.ra_idx, &disc, expected_data_len);
            ai += 1;
            continue;
        }

        // min_fill_qty gate.
        if crossable < b.min_fill_qty || crossable < a.min_fill_qty {
            if b_amt <= a_amt { bi += 1; } else { ai += 1; }
            continue;
        }

        // --- Trade legs ---
        let quote_amt_u128 = (crossable as u128)
            .checked_mul(p_star as u128)
            .ok_or(MatchingError::NotionalOverflow)?;
        if quote_amt_u128 > u64::MAX as u128 {
            return err!(MatchingError::NotionalOverflow);
        }
        let quote_amt = quote_amt_u128 as u64;

        let buyer_fee_amt = ((quote_amt as u128) * fee_rate_bps as u128 / 10_000u128) as u64;
        let seller_fee_amt = ((crossable as u128) * fee_rate_bps as u128 / 10_000u128) as u64;

        let buyer_charge = quote_amt
            .checked_add(buyer_fee_amt)
            .ok_or(MatchingError::FeeOverflow)?;
        let seller_charge = crossable
            .checked_add(seller_fee_amt)
            .ok_or(MatchingError::FeeOverflow)?;
        let buyer_change_amt = b.note_amount
            .checked_sub(buyer_charge)
            .ok_or(MatchingError::ConservationViolation)?;
        let seller_change_amt = a.note_amount
            .checked_sub(seller_charge)
            .ok_or(MatchingError::ConservationViolation)?;

        let match_id = {
            let br = ctx.accounts.batch_results.load()?;
            br.next_match_id
        };

        // Change-note commitments.
        let note_e_commitment = if buyer_change_amt > 0 {
            let nonce = change_note::derive_nonce(match_id, change_note::CHANGE_ROLE_BUYER);
            let r = change_note::derive_blinding(match_id, change_note::CHANGE_ROLE_BUYER);
            commitment_from_fields(&quote_mint.to_bytes(), buyer_change_amt, &b.user_commitment, &nonce, &r)
                .map_err(|_| error!(MatchingError::PoseidonFailed))?
        } else {
            [0u8; 32]
        };
        let note_f_commitment = if seller_change_amt > 0 {
            let nonce = change_note::derive_nonce(match_id, change_note::CHANGE_ROLE_SELLER);
            let r = change_note::derive_blinding(match_id, change_note::CHANGE_ROLE_SELLER);
            commitment_from_fields(&base_mint.to_bytes(), seller_change_amt, &a.user_commitment, &nonce, &r)
                .map_err(|_| error!(MatchingError::PoseidonFailed))?
        } else {
            [0u8; 32]
        };

        let b_remaining = b_amt.saturating_sub(crossable);
        let a_remaining = a_amt.saturating_sub(crossable);
        let buyer_relock = b_remaining > 0 && b.order_type == 0 && buyer_change_amt > 0;
        let seller_relock = a_remaining > 0 && a.order_type == 0 && seller_change_amt > 0;

        let (buyer_relock_order_id, buyer_relock_expiry) = if buyer_relock {
            (b.order_id, b.expiry_slot)
        } else {
            (RELOCK_ORDER_ID_NONE, 0)
        };
        let (seller_relock_order_id, seller_relock_expiry) = if seller_relock {
            (a.order_id, a.expiry_slot)
        } else {
            (RELOCK_ORDER_ID_NONE, 0)
        };

        // Write MatchResult.
        {
            let mut br = ctx.accounts.batch_results.load_mut()?;
            let slot = (br.write_cursor as usize) % BATCH_RESULTS_CAPACITY;
            br.results[slot] = MatchResult {
                note_buyer: b.note_commitment,
                note_seller: a.note_commitment,
                note_e_commitment,
                note_f_commitment,
                owner_buyer: b.trading_key,
                owner_seller: a.trading_key,
                user_commitment_buyer: b.user_commitment,
                user_commitment_seller: a.user_commitment,
                buyer_note_value: b.note_amount,
                seller_note_value: a.note_amount,
                base_amt: crossable,
                quote_amt,
                buyer_change_amt,
                seller_change_amt,
                buyer_fee_amt,
                seller_fee_amt,
                buyer_relock_order_id,
                buyer_relock_expiry,
                seller_relock_order_id,
                seller_relock_expiry,
                price: p_star,
                pyth_at_match: pyth_twap,
                batch_slot: now_slot,
                match_id,
                status: MATCH_RESULT_STATUS_FILLED,
                _padding: [0u8; 7],
            };
            br.write_cursor = br.write_cursor.saturating_add(1);
            br.next_match_id = br.next_match_id.saturating_add(1);
            br.fee_accumulators[0].accumulated_fees = br.fee_accumulators[0]
                .accumulated_fees
                .saturating_add(seller_fee_amt);
            br.fee_accumulators[1].accumulated_fees = br.fee_accumulators[1]
                .accumulated_fees
                .saturating_add(buyer_fee_amt);
        }

        // --- Update PendingOrder PDAs ---
        let b_new_amt = b_amt - crossable;
        {
            let bai = &ctx.remaining_accounts[b.ra_idx];
            let mut wdata = bai.data.borrow_mut();
            if wdata.len() >= expected_data_len && wdata[0..8] == disc {
                let po: &mut PendingOrder =
                    bytemuck::from_bytes_mut(&mut wdata[8..8 + PENDING_ORDER_SIZE]);
                if b_new_amt == 0 {
                    po.reset();
                } else {
                    po.amount = b_new_amt;
                    if buyer_relock {
                        po.note_commitment = note_e_commitment;
                        po.note_amount = buyer_change_amt;
                    }
                }
            }
        }
        let a_new_amt = a_amt - crossable;
        {
            let aai = &ctx.remaining_accounts[a.ra_idx];
            let mut wdata = aai.data.borrow_mut();
            if wdata.len() >= expected_data_len && wdata[0..8] == disc {
                let po: &mut PendingOrder =
                    bytemuck::from_bytes_mut(&mut wdata[8..8 + PENDING_ORDER_SIZE]);
                if a_new_amt == 0 {
                    po.reset();
                } else {
                    po.amount = a_new_amt;
                    if seller_relock {
                        po.note_commitment = note_f_commitment;
                        po.note_amount = seller_change_amt;
                    }
                }
            }
        }

        b_amounts[bi] = b_new_amt;
        a_amounts[ai] = a_new_amt;
        produced += 1;

        if b_new_amt == 0 { bi += 1; }
        if a_new_amt == 0 { ai += 1; }
    }

    Ok(produced)
}

// Reset a single PendingOrder slot identified by its index in remaining_accounts.
fn reset_slot(ctx: &Context<RunBatch>, ra_idx: usize, disc: &[u8; 8], expected_len: usize) {
    if let Some(ai) = ctx.remaining_accounts.get(ra_idx) {
        if ai.owner != &crate::ID { return; }
        let mut wdata = match ai.data.try_borrow_mut() {
            Ok(d) => d,
            Err(_) => return,
        };
        if wdata.len() < expected_len || wdata[0..8] != *disc { return; }
        let po: &mut PendingOrder =
            bytemuck::from_bytes_mut(&mut wdata[8..8 + PENDING_ORDER_SIZE]);
        po.reset();
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct BatchExecuted {
    pub market: Pubkey,
    pub batch_slot: u64,
    pub match_count: u64,
    pub clearing_price: u64,
    pub pyth_twap: u64,
    pub circuit_breaker_tripped: bool,
    pub inclusion_root: [u8; 32],
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic, no SBF / LiteSVM)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deviation_check_within_bounds_is_false() {
        assert!(!deviates_by_more_than_bps(1005, 1000, 50));
    }

    #[test]
    fn deviation_check_outside_bounds_is_true() {
        assert!(deviates_by_more_than_bps(1100, 1000, 50));
    }

    #[test]
    fn deviation_check_exact_300bps_boundary() {
        assert!(!deviates_by_more_than_bps(1030, 1000, 300));
        assert!(deviates_by_more_than_bps(1031, 1000, 300));
    }

    #[test]
    fn merkle_root_empty_is_zero() {
        assert_eq!(merkle_root_sha256(&[]), [0u8; 32]);
    }

    #[test]
    fn merkle_root_single_leaf_is_itself() {
        let leaf = [42u8; 32];
        assert_eq!(merkle_root_sha256(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_three_leaves_pads_last() {
        use solana_program::hash::hashv;
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let l2 = [3u8; 32];
        let h01 = hashv(&[&l0, &l1]).to_bytes();
        let h23 = hashv(&[&l2, &l2]).to_bytes();
        let expected = hashv(&[&h01, &h23]).to_bytes();
        assert_eq!(merkle_root_sha256(&[l0, l1, l2]), expected);
    }
}
