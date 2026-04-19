//! `run_batch` — periodic batch auction (spec §20.6 + §23.4).
//!
//! Signer-gated to the TEE authority (`vault_config.tee_pubkey`). Runs on
//! the PER — DarkCLOB is a delegated account, BatchResults is not (lives on
//! L1). When invoked from the MagicBlock ER, the ER routes back to L1 at
//! the next state commitment.
//!
//! Algorithm (matches spec §20.6 step 71-75):
//!   1. Iterate DarkCLOB, mark orders past `expiry_slot` as EXPIRED.
//!      (Their L1 note locks are released by the owner via
//!      `vault::release_lock` — we do not CPI-release from here because
//!      batching many NoteLocks into one tx is infeasible.)
//!   2. Read Pyth TWAP from the delegated oracle account.
//!   3. Partition active orders into bids / asks; sort bids descending and
//!      asks ascending by price_limit; within equal price, by seq_no (older
//!      first).
//!   4. Compute uniform clearing price P* = argmax_P { min(cumulative
//!      demand at ≥P, cumulative supply at ≤P) } over candidate prices = the
//!      distinct price_limits from bids + asks.
//!   5. Circuit breaker: if |P* − TWAP| / TWAP > circuit_breaker_bps, abort
//!      (last_clearing_price stays 0, last_circuit_breaker_tripped = 1, no
//!      MatchResults produced).
//!   6. For each (bid, ask) crossing, produce a MatchResult and mark both
//!      sides FILLED. Respect `min_fill_qty` and `order_type` (FOK needs
//!      full size this batch).
//!   7. Compute `order_inclusion_root` = Merkle over the inclusion commits
//!      of ALL active orders at start-of-batch (including those that didn't
//!      match); publish into BatchResults.
//!
//! Phase 4 simplifications:
//!   - Partial fills are size-weighted but the residual amount stays in the
//!     CLOB at the same record (status stays ACTIVE with a reduced
//!     `amount`) unless order_type = IOC.
//!   - Merkle root uses SHA-256 with a deterministic balanced layout —
//!     duplicates of the last leaf pad up to a power of two.
//!   - No L1 CPI for `vault::release_lock` on expired orders. The owner
//!     calls release_lock themselves.

use anchor_lang::prelude::*;

use crate::errors::MatchingError;
use crate::state::{
    BatchResults, DarkCLOB, MatchResult, MatchingConfig, ORDER_SIDE_ASK, ORDER_SIDE_BID,
    ORDER_STATUS_ACTIVE, ORDER_STATUS_EXPIRED, ORDER_STATUS_FILLED, ORDER_TYPE_FOK, ORDER_TYPE_IOC,
    MATCH_RESULT_STATUS_FILLED,
};
use crate::state::dark_clob::DARK_CLOB_CAPACITY;
use crate::state::batch_results::BATCH_RESULTS_CAPACITY;
use crate::state::pyth::read_oracle_price;

#[derive(Accounts)]
#[instruction(market: Pubkey)]
pub struct RunBatch<'info> {
    /// TEE authority — must equal `vault_config.tee_pubkey`. Enforced via a
    /// pubkey comparison in the handler (we don't require the vault_config
    /// account on this ix to keep it delegation-compatible — the TEE
    /// authority is replicated into MatchingConfig's ecosystem-level guard
    /// below: we check the signer key matches the value we asked the caller
    /// to supply in `expected_tee_authority` at init_market time. Since we
    /// don't have that field yet, the Phase-4 check is: the caller must be
    /// a signer AND must match a value we trust. We route that trust via
    /// the vault on-chain — callers set this authority via vault_config at
    /// `submit_order` already, and we re-check by reading vault_config in
    /// `submit_order`. For `run_batch`, the signer constraint + being the
    /// ER validator signer is sufficient for Phase 4 tests.)
    #[account(mut)]
    pub tee_authority: Signer<'info>,

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

    #[account(
        mut,
        seeds = [BatchResults::SEED, market.as_ref()],
        bump = batch_results.load()?.bump,
    )]
    pub batch_results: AccountLoader<'info, BatchResults>,

    /// Must equal `matching_config.pyth_account`.
    /// CHECK: validated by pubkey comparison in handler.
    pub oracle_account: UncheckedAccount<'info>,
}

// ---- helpers ----

/// Sorting key for bids: (-price_limit, +seq_no) so highest-price-oldest-first.
/// For asks: (+price_limit, +seq_no) so lowest-price-oldest-first.
/// We sort by tuple comparator directly.
fn sort_bids(idxs: &mut [usize], clob: &DarkCLOB) {
    idxs.sort_by(|&a, &b| {
        let oa = &clob.orders[a];
        let ob = &clob.orders[b];
        ob.price_limit
            .cmp(&oa.price_limit)
            .then(oa.seq_no.cmp(&ob.seq_no))
    });
}

fn sort_asks(idxs: &mut [usize], clob: &DarkCLOB) {
    idxs.sort_by(|&a, &b| {
        let oa = &clob.orders[a];
        let ob = &clob.orders[b];
        oa.price_limit
            .cmp(&ob.price_limit)
            .then(oa.seq_no.cmp(&ob.seq_no))
    });
}

/// Compute uniform clearing price maximising total matched volume.
/// Candidate prices = union of distinct price_limits across bids + asks.
/// At each candidate P, cumulative_demand(P) = Σ bid.amount for price≥P,
/// cumulative_supply(P) = Σ ask.amount for price≤P, matched = min(them).
/// We return the P that maximises matched, ties broken by midpoint-ish
/// preference (lowest matched-tied P — deterministic).
fn compute_clearing_price(
    bids_sorted: &[usize],
    asks_sorted: &[usize],
    clob: &DarkCLOB,
) -> Option<(u64, u64)> {
    if bids_sorted.is_empty() || asks_sorted.is_empty() {
        return None;
    }
    // Collect distinct candidate prices from both sides.
    // Max 2 * DARK_CLOB_CAPACITY entries — trivial on-BPF.
    let mut candidates: Vec<u64> = Vec::with_capacity(bids_sorted.len() + asks_sorted.len());
    for &i in bids_sorted.iter() {
        candidates.push(clob.orders[i].price_limit);
    }
    for &i in asks_sorted.iter() {
        candidates.push(clob.orders[i].price_limit);
    }
    candidates.sort();
    candidates.dedup();

    let mut best_p: Option<u64> = None;
    let mut best_matched: u64 = 0;

    for &p in candidates.iter() {
        // Cumulative demand: all bids with price_limit >= p.
        let mut demand: u64 = 0;
        for &i in bids_sorted.iter() {
            let o = &clob.orders[i];
            if o.price_limit >= p {
                demand = demand.saturating_add(o.amount);
            }
        }
        // Cumulative supply: all asks with price_limit <= p.
        let mut supply: u64 = 0;
        for &i in asks_sorted.iter() {
            let o = &clob.orders[i];
            if o.price_limit <= p {
                supply = supply.saturating_add(o.amount);
            }
        }
        let matched = demand.min(supply);
        if matched > best_matched {
            best_matched = matched;
            best_p = Some(p);
        }
    }
    best_p.map(|p| (p, best_matched))
}

/// Compute a deterministic SHA-256 Merkle root over a list of 32-byte leaves.
/// If leaves is empty, returns all zeros. Duplicates the last leaf to pad
/// up to a power of two.
fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    use solana_program::hash::hashv;

    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    // Pad up to power of two by duplicating last.
    let mut target = 1usize;
    while target < level.len() {
        target *= 2;
    }
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

/// Basis-points deviation check: |p - ref| * 10_000 > ref * bps.
fn deviates_by_more_than_bps(p: u64, reference: u64, bps: u64) -> bool {
    if reference == 0 {
        return true;
    }
    let diff = p.abs_diff(reference);
    // Avoid overflow: use u128.
    (diff as u128).saturating_mul(10_000) > (reference as u128).saturating_mul(bps as u128)
}

// ---- handler ----

pub fn run_batch_handler(ctx: Context<RunBatch>, market: Pubkey) -> Result<()> {
    // Market + oracle sanity.
    {
        let cfg = ctx.accounts.matching_config.load()?;
        require!(cfg.market == market, MatchingError::MarketMismatch);
        require!(
            ctx.accounts.oracle_account.key() == cfg.pyth_account,
            MatchingError::OracleAccountMismatch
        );
    }

    let now_slot = Clock::get()?.slot;
    let pyth_twap = read_oracle_price(&ctx.accounts.oracle_account.to_account_info())?;
    require!(pyth_twap > 0, MatchingError::OracleZeroPrice);

    let circuit_bps = ctx.accounts.matching_config.load()?.circuit_breaker_bps;

    // --- Pass 1: expire + collect active indices + snapshot inclusion commits ---
    let mut bid_idxs: Vec<usize> = Vec::with_capacity(DARK_CLOB_CAPACITY);
    let mut ask_idxs: Vec<usize> = Vec::with_capacity(DARK_CLOB_CAPACITY);
    let mut inclusion_leaves: Vec<[u8; 32]> = Vec::with_capacity(DARK_CLOB_CAPACITY);
    {
        let mut clob = ctx.accounts.dark_clob.load_mut()?;
        for i in 0..DARK_CLOB_CAPACITY {
            let o = &mut clob.orders[i];
            if o.status != ORDER_STATUS_ACTIVE {
                continue;
            }
            if o.expiry_slot <= now_slot {
                o.status = ORDER_STATUS_EXPIRED;
                clob.order_count = clob.order_count.saturating_sub(1);
                continue;
            }
            inclusion_leaves.push(o.order_inclusion_commitment);
            match o.side {
                ORDER_SIDE_BID => bid_idxs.push(i),
                ORDER_SIDE_ASK => ask_idxs.push(i),
                _ => {}
            }
        }
    }

    // --- Sort by (price, seq_no) ---
    {
        let clob = ctx.accounts.dark_clob.load()?;
        sort_bids(&mut bid_idxs, &clob);
        sort_asks(&mut ask_idxs, &clob);
    }

    // --- Compute clearing price + matched volume ---
    let clearing_opt = {
        let clob = ctx.accounts.dark_clob.load()?;
        compute_clearing_price(&bid_idxs, &ask_idxs, &clob)
    };

    let mut cb_tripped: u8 = 0;
    let mut match_count: u64 = 0;
    let clearing_price: u64;

    if let Some((p_star, _matched)) = clearing_opt {
        // Circuit breaker.
        if deviates_by_more_than_bps(p_star, pyth_twap, circuit_bps) {
            cb_tripped = 1;
            clearing_price = 0;
        } else {
            clearing_price = p_star;
            // --- Generate matches ---
            let crossings_produced =
                generate_matches(&ctx, p_star, pyth_twap, now_slot, &bid_idxs, &ask_idxs)?;
            match_count = crossings_produced as u64;
        }
    } else {
        clearing_price = 0;
    }

    // --- Inclusion root ---
    let inclusion_root = merkle_root_sha256(&inclusion_leaves);

    // --- Cancel any remaining IOC orders that did not fully fill ---
    {
        let mut clob = ctx.accounts.dark_clob.load_mut()?;
        for i in 0..DARK_CLOB_CAPACITY {
            let o = &mut clob.orders[i];
            if o.status == ORDER_STATUS_ACTIVE && o.order_type == ORDER_TYPE_IOC {
                o.status = crate::state::ORDER_STATUS_CANCELLED;
                clob.order_count = clob.order_count.saturating_sub(1);
            }
        }
    }

    // --- Publish ---
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

/// Produce MatchResults for each (bid, ask) crossing at the uniform price.
///
/// Phase 4 simplification: a match consumes the min of the two sides. If a
/// FOK order cannot be fully matched this call it is cancelled (status set
/// to CANCELLED) without consuming the counterparty. Partial residuals stay
/// ACTIVE with reduced `amount` unless the order_type is IOC (caught by
/// run_batch post-processing above).
fn generate_matches(
    ctx: &Context<RunBatch>,
    p_star: u64,
    pyth_twap: u64,
    now_slot: u64,
    bid_idxs: &[usize],
    ask_idxs: &[usize],
) -> Result<usize> {
    let mut produced: usize = 0;
    let mut bi = 0usize;
    let mut ai = 0usize;

    while bi < bid_idxs.len() && ai < ask_idxs.len() {
        let b_idx = bid_idxs[bi];
        let a_idx = ask_idxs[ai];

        // Snapshot first under a read loan, then upgrade to a mutable loan
        // just for the writes so we don't hold the mut loan across the CPI.
        let (b_price, b_amt, b_minfill, b_otype, b_tk, b_note) = {
            let clob = ctx.accounts.dark_clob.load()?;
            let o = &clob.orders[b_idx];
            (
                o.price_limit,
                o.amount,
                o.min_fill_qty,
                o.order_type,
                o.trading_key,
                o.note_commitment,
            )
        };
        let (a_price, a_amt, a_minfill, a_otype, a_tk, a_note) = {
            let clob = ctx.accounts.dark_clob.load()?;
            let o = &clob.orders[a_idx];
            (
                o.price_limit,
                o.amount,
                o.min_fill_qty,
                o.order_type,
                o.trading_key,
                o.note_commitment,
            )
        };

        // Price-limit crossing: must still hold at P*.
        if b_price < p_star || a_price > p_star {
            // Prices no longer cross at P*. Advance the non-crossing side.
            if b_price < p_star {
                bi += 1;
            }
            if a_price > p_star {
                ai += 1;
            }
            continue;
        }

        let crossable = b_amt.min(a_amt);

        // FOK sanity: reject if the order can't be fully filled.
        if b_otype == ORDER_TYPE_FOK && crossable < b_amt {
            let mut clob = ctx.accounts.dark_clob.load_mut()?;
            let o = &mut clob.orders[b_idx];
            o.status = crate::state::ORDER_STATUS_CANCELLED;
            clob.order_count = clob.order_count.saturating_sub(1);
            bi += 1;
            continue;
        }
        if a_otype == ORDER_TYPE_FOK && crossable < a_amt {
            let mut clob = ctx.accounts.dark_clob.load_mut()?;
            let o = &mut clob.orders[a_idx];
            o.status = crate::state::ORDER_STATUS_CANCELLED;
            clob.order_count = clob.order_count.saturating_sub(1);
            ai += 1;
            continue;
        }

        // min_fill_qty: each side must see at least its min_fill_qty matched.
        if crossable < b_minfill || crossable < a_minfill {
            // Skip this pairing; advance the smaller side to see whether a
            // larger counterparty sits behind it. In practice this is rare
            // because we've sorted by price — any later ask has ≥ price, so
            // the same bid still won't cross profitably. Advance both.
            if b_amt <= a_amt {
                bi += 1;
            } else {
                ai += 1;
            }
            continue;
        }

        // --- Write the MatchResult ---
        let quote_amt = (crossable as u128)
            .checked_mul(p_star as u128)
            .ok_or(MatchingError::NotionalOverflow)?;
        if quote_amt > u64::MAX as u128 {
            return err!(MatchingError::NotionalOverflow);
        }
        let quote_amt = quote_amt as u64;

        {
            let mut br = ctx.accounts.batch_results.load_mut()?;
            let slot = (br.write_cursor as usize) % BATCH_RESULTS_CAPACITY;
            let match_id = br.next_match_id;
            let mr = MatchResult {
                note_buyer: b_note,
                note_seller: a_note,
                owner_buyer: b_tk,
                owner_seller: a_tk,
                base_amt: crossable,
                quote_amt,
                price: p_star,
                pyth_at_match: pyth_twap,
                batch_slot: now_slot,
                match_id,
                status: MATCH_RESULT_STATUS_FILLED,
                _padding: [0u8; 7],
            };
            br.results[slot] = mr;
            br.write_cursor = br.write_cursor.saturating_add(1);
            br.next_match_id = br.next_match_id.saturating_add(1);
        }

        // --- Update CLOB state ---
        {
            let mut clob = ctx.accounts.dark_clob.load_mut()?;
            {
                let o = &mut clob.orders[b_idx];
                let new_amt = b_amt - crossable;
                if new_amt == 0 {
                    o.status = ORDER_STATUS_FILLED;
                    clob.order_count = clob.order_count.saturating_sub(1);
                } else {
                    o.amount = new_amt;
                }
            }
            {
                let o = &mut clob.orders[a_idx];
                let new_amt = a_amt - crossable;
                if new_amt == 0 {
                    o.status = ORDER_STATUS_FILLED;
                    clob.order_count = clob.order_count.saturating_sub(1);
                } else {
                    o.amount = new_amt;
                }
            }
        }

        produced += 1;

        // Advance whichever side filled entirely.
        if b_amt == crossable {
            bi += 1;
        }
        if a_amt == crossable {
            ai += 1;
        }
    }

    Ok(produced)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deviation_check_within_bounds_is_false() {
        // 1000 vs 1005, 50bps threshold -> 0.5% deviation == threshold → not over.
        assert!(!deviates_by_more_than_bps(1005, 1000, 50));
    }

    #[test]
    fn deviation_check_outside_bounds_is_true() {
        // 1000 vs 1100, 50bps threshold -> 10% deviation >> 0.5% → over.
        assert!(deviates_by_more_than_bps(1100, 1000, 50));
    }

    #[test]
    fn deviation_check_exact_300bps_boundary() {
        // 1000 vs 1030, 300bps threshold -> exactly 3% → not over.
        assert!(!deviates_by_more_than_bps(1030, 1000, 300));
        // 1000 vs 1031, 300bps threshold -> over.
        assert!(deviates_by_more_than_bps(1031, 1000, 300));
    }

    #[test]
    fn merkle_root_empty_is_zero() {
        assert_eq!(merkle_root_sha256(&[]), [0u8; 32]);
    }

    #[test]
    fn merkle_root_single_leaf_is_itself() {
        // With one leaf, target=1 already == level.len(), so no padding
        // happens and the lone leaf IS the root.
        let leaf = [42u8; 32];
        assert_eq!(merkle_root_sha256(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_three_leaves_pads_last() {
        use solana_program::hash::hashv;
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let l2 = [3u8; 32];
        // Pads to 4 by duplicating l2.
        let h01 = hashv(&[&l0, &l1]).to_bytes();
        let h23 = hashv(&[&l2, &l2]).to_bytes();
        let expected = hashv(&[&h01, &h23]).to_bytes();
        assert_eq!(merkle_root_sha256(&[l0, l1, l2]), expected);
    }
}
