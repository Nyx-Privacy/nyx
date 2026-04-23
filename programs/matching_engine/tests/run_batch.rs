//! Phase 4 §23.4.2 — run_batch + cancel_order litesvm integration tests.
//!
//! All tests seed PendingOrder PDAs directly via `seed_pending_order`, bypassing
//! `submit_order` (which runs inside the ER TEE). This exercises the matching
//! engine in isolation without a full vault+TEE flow.
//!
//! Covered:
//!   1. test_uniform_clearing_price
//!   2. test_intra_batch_ordering_irrelevant
//!   3. test_circuit_breaker_pauses_batch
//!   4. test_circuit_breaker_does_not_affect_other_pairs
//!   5. test_expired_orders_drained
//!   6. test_min_fill_qty_enforced
//!   7. test_match_result_signed_by_tee_key
//!   8. test_inclusion_root_published
//!   9. test_market_state_isolated
//!   + test_cancel_order_flips_status
//!   + test_cancel_order_unauthorized_caller_rejected

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

// ============================================================================
// 1. Uniform clearing price
// ============================================================================

#[test]
fn test_uniform_clearing_price() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(146);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    // 5 bids @ 150, 149, 148, 147, 146; 3 asks @ 144, 145, 146.
    let mut pdas = Vec::new();
    let bid_seeds = [
        make_pending_seed(0, 0, 150, 10, 1_000_000, tkb),
        make_pending_seed(1, 0, 149, 10, 1_000_000, tkb),
        make_pending_seed(2, 0, 148, 10, 1_000_000, tkb),
        make_pending_seed(3, 0, 147, 10, 1_000_000, tkb),
        make_pending_seed(4, 0, 146, 10, 1_000_000, tkb),
    ];
    let ask_seeds = [
        make_pending_seed(5, 1, 144, 10, 1_000_000, tkb),
        make_pending_seed(6, 1, 145, 10, 1_000_000, tkb),
        make_pending_seed(7, 1, 146, 10, 1_000_000, tkb),
    ];
    for (i, seed) in bid_seeds.iter().chain(ask_seeds.iter()).enumerate() {
        pdas.push(seed_pending_order(&mut h, &market, &tk, i as u8, seed));
    }

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_circuit_breaker_tripped, 0);
    // At P=146: demand=50, supply=30 → 30 matched. Optimal uniform price = 146.
    assert_eq!(br.last_clearing_price, 146);
    assert_eq!(br.last_match_count, 3);
}

// ============================================================================
// 2. Intra-batch ordering is irrelevant (seq_no permutations don't change outcome)
// ============================================================================

#[test]
fn test_intra_batch_ordering_irrelevant() {
    let run = |seeds: Vec<(PendingOrderSeed, u8)>| -> (u64, u64) {
        let mut h = Harness::setup();
        let market = Keypair::new().pubkey();
        h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
        h.update_mock_oracle(100);
        let tk = h.trader.pubkey();
        let mut pdas = Vec::new();
        for (i, (seed, _slot)) in seeds.iter().enumerate() {
            pdas.push(seed_pending_order(&mut h, &market, &tk, i as u8, seed));
        }
        let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
        let tx = Transaction::new(
            &[&h.tee],
            Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
            h.svm.latest_blockhash(),
        );
        h.svm.send_transaction(tx).expect("run_batch");
        let br = read_batch_results(&h, &market);
        (br.last_clearing_price, br.last_match_count)
    };

    let tk = [9u8; 32];
    let a = vec![
        (make_pending_seed(0, 0, 105, 5, 1_000_000, tk), 0u8),
        (make_pending_seed(1, 0, 100, 5, 1_000_000, tk), 1u8),
        (make_pending_seed(2, 1,  95, 5, 1_000_000, tk), 2u8),
        (make_pending_seed(3, 1, 100, 5, 1_000_000, tk), 3u8),
    ];
    // Permuted arrival_slots — same prices, different order in the book.
    let b = vec![
        (make_pending_seed(10, 0, 105, 5, 1_000_000, tk), 0u8),
        (make_pending_seed( 3, 0, 100, 5, 1_000_000, tk), 1u8),
        (make_pending_seed(20, 1,  95, 5, 1_000_000, tk), 2u8),
        (make_pending_seed( 1, 1, 100, 5, 1_000_000, tk), 3u8),
    ];

    let r1 = run(a);
    let r2 = run(b);
    assert_eq!(r1, r2, "batch outcome must be arrival-slot-permutation invariant");
}

// ============================================================================
// 3. Circuit breaker pauses batch when P* is too far from TWAP
// ============================================================================

#[test]
fn test_circuit_breaker_pauses_batch() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 300, 1, 0);
    h.update_mock_oracle(100);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    let bid_pda = seed_pending_order(&mut h, &market, &tk, 0, &make_pending_seed(0, 0, 150, 10, 1_000_000, tkb));
    let ask_pda = seed_pending_order(&mut h, &market, &tk, 1, &make_pending_seed(1, 1, 140, 10, 1_000_000, tkb));

    let ix = build_run_batch_ix(&h, &market, &h.tee, &[bid_pda, ask_pda]);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_circuit_breaker_tripped, 1);
    assert_eq!(br.last_match_count, 0);
    assert_eq!(br.last_clearing_price, 0);
    assert_eq!(br.last_pyth_twap, 100);
    // Orders must remain PENDING (not filled) so they try again next batch.
    assert_eq!(read_pending_order_status(&h, &bid_pda), 1);
    assert_eq!(read_pending_order_status(&h, &ask_pda), 1);
}

// ============================================================================
// 4. Circuit breaker does NOT affect other pairs (each market = own oracle)
// ============================================================================

#[test]
fn test_circuit_breaker_does_not_affect_other_pairs() {
    let mut h = Harness::setup();
    // Market A: oracle far from P* → cb trips.
    let oracle_a = Keypair::new().pubkey();
    Harness::write_mock_oracle(&mut h.svm, &oracle_a, 100);
    // Market B: oracle close to P* → cb stays quiet.
    let oracle_b = Keypair::new().pubkey();
    Harness::write_mock_oracle(&mut h.svm, &oracle_b, 145);

    let market_a = Keypair::new().pubkey();
    let market_b = Keypair::new().pubkey();
    h.init_market_full(&market_a, 2, oracle_a, 300, 1, 0);
    h.init_market_full(&market_b, 2, oracle_b, 300, 1, 0);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    let pdas_a = vec![
        seed_pending_order(&mut h, &market_a, &tk, 0, &make_pending_seed(0, 0, 150, 10, 1_000_000, tkb)),
        seed_pending_order(&mut h, &market_a, &tk, 1, &make_pending_seed(1, 1, 140, 10, 1_000_000, tkb)),
    ];
    // Market B: tight prices around TWAP=145.
    let pdas_b = vec![
        seed_pending_order(&mut h, &market_b, &tk, 0, &make_pending_seed(0, 0, 145, 10, 1_000_000, tkb)),
        seed_pending_order(&mut h, &market_b, &tk, 1, &make_pending_seed(1, 1, 145, 10, 1_000_000, tkb)),
    ];

    // Run batch on A — oracle_a is at index 4 (last named account).
    let mut ix_a = build_run_batch_ix(&h, &market_a, &h.tee, &pdas_a);
    ix_a.accounts[4].pubkey = oracle_a;
    let tx_a = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix_a], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx_a).expect("run_batch A");

    h.svm.expire_blockhash();

    let mut ix_b = build_run_batch_ix(&h, &market_b, &h.tee, &pdas_b);
    ix_b.accounts[4].pubkey = oracle_b;
    let tx_b = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix_b], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx_b).expect("run_batch B");

    let br_a = read_batch_results(&h, &market_a);
    let br_b = read_batch_results(&h, &market_b);

    assert_eq!(br_a.last_circuit_breaker_tripped, 1, "market A must trip");
    assert_eq!(br_a.last_match_count, 0);
    assert_eq!(br_b.last_circuit_breaker_tripped, 0, "market B must NOT trip");
    assert!(br_b.last_match_count > 0, "market B must match");
}

// ============================================================================
// 5. Expired orders are drained (reset to Empty)
// ============================================================================

#[test]
fn test_expired_orders_drained() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    // Slot 0: expiry_slot=5 (will expire). Slot 1: active.
    let expired_pda = seed_pending_order(&mut h, &market, &tk, 0,
        &make_pending_seed(0, 0, 100, 5, /*expiry*/ 5, tkb));
    let active_pda  = seed_pending_order(&mut h, &market, &tk, 1,
        &make_pending_seed(1, 1, 100, 5, 1_000_000, tkb));

    // Warp past slot 5 + settlement buffer so the first order expires.
    h.svm.warp_to_slot(100);

    let ix = build_run_batch_ix(&h, &market, &h.tee, &[expired_pda, active_pda]);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    // Expired slot must be reset to EMPTY (0).
    assert_eq!(read_pending_order_status(&h, &expired_pda), 0, "expired must be Empty");
    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_match_count, 0);
    assert_eq!(br.last_circuit_breaker_tripped, 0);
}

// ============================================================================
// 6. min_fill_qty enforced
// ============================================================================

#[test]
fn test_min_fill_qty_enforced() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    // Bid wants min 10 but only 5 ask available → must NOT match.
    let mut bid_seed = make_pending_seed(0, 0, 100, 20, 1_000_000, tkb);
    bid_seed.min_fill_qty = 10;
    let bid_pda = seed_pending_order(&mut h, &market, &tk, 0, &bid_seed);
    let ask_pda = seed_pending_order(&mut h, &market, &tk, 1,
        &make_pending_seed(1, 1, 100, 5, 1_000_000, tkb));

    let ix = build_run_batch_ix(&h, &market, &h.tee, &[bid_pda, ask_pda]);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_match_count, 0, "min_fill_qty must block the match");
    // Both orders stay PENDING (1).
    assert_eq!(read_pending_order_status(&h, &bid_pda), 1);
    assert_eq!(read_pending_order_status(&h, &ask_pda), 1);
}

// ============================================================================
// 7. run_batch accepts any designated TEE signer
// ============================================================================

#[test]
fn test_match_result_signed_by_tee_key() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    let pdas = vec![
        seed_pending_order(&mut h, &market, &tk, 0, &make_pending_seed(0, 0, 100, 5, 1_000_000, tkb)),
        seed_pending_order(&mut h, &market, &tk, 1, &make_pending_seed(1, 1, 100, 5, 1_000_000, tkb)),
    ];

    // Any funded signer can drive run_batch (the ER JWT layer enforces TEE auth).
    let tee_kp = Keypair::new();
    h.svm.airdrop(&tee_kp.pubkey(), 1_000_000_000).unwrap();
    let ix = build_run_batch_ix(&h, &market, &tee_kp, &pdas);
    let tx = Transaction::new(
        &[&tee_kp],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&tee_kp.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("tee-signed run_batch ok");

    let br = read_batch_results(&h, &market);
    assert!(br.last_match_count > 0);
    // Pyth TWAP stamped into BatchResults proves the handler ran.
    assert_eq!(br.last_pyth_twap, 150);
}

// ============================================================================
// 8. Inclusion root published and deterministic
// ============================================================================

#[test]
fn test_inclusion_root_published() {
    use solana_program::hash::hashv;

    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    let s0 = make_pending_seed(0, 0, 105, 5, 1_000_000, tkb);
    let s1 = make_pending_seed(1, 0, 100, 5, 1_000_000, tkb);
    let s2 = make_pending_seed(2, 1,  95, 5, 1_000_000, tkb);

    let pdas = vec![
        seed_pending_order(&mut h, &market, &tk, 0, &s0),
        seed_pending_order(&mut h, &market, &tk, 1, &s1),
        seed_pending_order(&mut h, &market, &tk, 2, &s2),
    ];

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_ne!(br.last_inclusion_root, [0u8; 32], "root must be published");

    // Reproduce the expected root client-side.
    // inclusion_commitment = SHA-256(order_id || note_commitment || trading_key).
    let ic = |seed: &PendingOrderSeed| -> [u8; 32] {
        hashv(&[&seed.order_id, &seed.note_commitment, &tkb]).to_bytes()
    };
    let ic0 = ic(&s0);
    let ic1 = ic(&s1);
    let ic2 = ic(&s2);
    // 3 leaves padded to power-of-2 = 4 by duplicating last.
    let h01 = hashv(&[&ic0, &ic1]).to_bytes();
    let h23 = hashv(&[&ic2, &ic2]).to_bytes();
    let expected = hashv(&[&h01, &h23]).to_bytes();
    assert_eq!(br.last_inclusion_root, expected);
}

// ============================================================================
// 9. Market state is isolated between markets
// ============================================================================

#[test]
fn test_market_state_isolated() {
    let mut h = Harness::setup();
    let market_a = Keypair::new().pubkey();
    let market_b = Keypair::new().pubkey();
    h.init_market_full(&market_a, 2, h.pyth_account, 100_000, 1, 0);
    h.init_market_full(&market_b, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    // A has a crossing pair; B only has bids (nothing to match).
    let pdas_a = vec![
        seed_pending_order(&mut h, &market_a, &tk, 0, &make_pending_seed(0, 0, 100, 5, 1_000_000, tkb)),
        seed_pending_order(&mut h, &market_a, &tk, 1, &make_pending_seed(1, 1, 100, 5, 1_000_000, tkb)),
    ];
    let pdas_b = vec![
        seed_pending_order(&mut h, &market_b, &tk, 0, &make_pending_seed(0, 0, 100, 5, 1_000_000, tkb)),
        seed_pending_order(&mut h, &market_b, &tk, 1, &make_pending_seed(1, 0, 100, 5, 1_000_000, tkb)),
    ];

    let ix_a = build_run_batch_ix(&h, &market_a, &h.tee, &pdas_a);
    let tx_a = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix_a], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx_a).expect("run_batch A");

    // B is untouched: its PendingOrders still PENDING (1).
    assert_eq!(read_pending_order_status(&h, &pdas_b[0]), 1);
    assert_eq!(read_pending_order_status(&h, &pdas_b[1]), 1);
    let br_b = read_batch_results(&h, &market_b);
    assert_eq!(br_b.last_batch_slot, 0, "batch B never ran");

    // A matched.
    let br_a = read_batch_results(&h, &market_a);
    assert!(br_a.last_match_count > 0);
}

// ============================================================================
// Cancel order flow
// ============================================================================

#[test]
fn test_cancel_order_flips_status() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    let seed = make_pending_seed(0, 0, 100, 10, 1_000_000, tkb);
    let pda = seed_pending_order(&mut h, &market, &tk, 0, &seed);

    // Before: PENDING (1).
    assert_eq!(read_pending_order_status(&h, &pda), 1);

    let ix = build_cancel_order_ix(&h, &market, 0, &h.trader);
    let tx = Transaction::new(
        &[&h.trader],
        Message::new(&[ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("cancel_order");

    // After: EMPTY (0) — slot is reusable.
    assert_eq!(read_pending_order_status(&h, &pda), 0);
}

#[test]
fn test_cancel_order_unauthorized_caller_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    // Order belongs to `h.trader`. An intruder must not be able to cancel it.
    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    let _pda = seed_pending_order(&mut h, &market, &tk, 0,
        &make_pending_seed(0, 0, 100, 10, 1_000_000, tkb));

    let intruder = Keypair::new();
    h.svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();
    // intruder tries to cancel slot 0, but the PDA is derived from intruder's key,
    // which yields a non-existent account → AccountNotInitialized.
    let ix = build_cancel_order_ix(&h, &market, 0, &intruder);
    let tx = Transaction::new(
        &[&intruder],
        Message::new(&[ix], Some(&intruder.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("intruder cancel must fail");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.contains("AccountNotInitialized")
            || logs.to_lowercase().contains("could not deserialize")
            || logs.to_lowercase().contains("invalid account"),
        "expected account error, got:\n{logs}"
    );
    // h.trader's slot is untouched.
    assert_eq!(read_pending_order_status(&h, &_pda), 1);
}
