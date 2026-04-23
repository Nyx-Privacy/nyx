//! submit_order litesvm integration tests (updated for Phase-6 privacy model).
//!
//! In the new model submit_order runs inside the ER (via PER RPC + JWT) and
//! writes into a delegated PendingOrder PDA. Tests exercise the on-chain
//! validation path only — no vault CPI is involved.
//!
//! Covered:
//!   1. test_notional_exceeds_note_value_rejected
//!   2. test_slot_already_occupied_rejected
//!   3. test_unauthorized_slot_owner_rejected (wrong trading_key seed)
//!   4. test_permission_group_setup_root_key_only_host_invariants

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

// ---------------------------------------------------------------------------
// Helper: seed an EMPTY PendingOrder PDA for a given trading key + slot_index.
// (We write status=0 instead of the PENDING=1 that seed_pending_order uses.)
// ---------------------------------------------------------------------------
fn seed_empty_slot(h: &mut Harness, market: &Pubkey, trading_key: &Pubkey, slot_index: u8) -> Pubkey {
    use solana_account::Account as SolAccount;
    let (pda, bump) = pending_order_pda(&h.me_id, market, trading_key, slot_index);
    let mut data = vec![0u8; 8 + PENDING_ORDER_STRUCT_SIZE];
    data[0..8].copy_from_slice(&anchor_acct_disc("PendingOrder"));
    // trading_key at offset 8
    data[8..40].copy_from_slice(&trading_key.to_bytes());
    // market at offset 40
    data[40..72].copy_from_slice(&market.to_bytes());
    // status byte at offset 8+32+32+32+32+8+8+8+8+8+8+16+1+1 = 194 → stays 0 (EMPTY)
    // slot_index at offset 195
    data[8 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 8 + 16 + 1 + 1 + 1] = slot_index;
    // bump at offset 196
    data[8 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 8 + 16 + 1 + 1 + 1 + 1] = bump;
    let acct = SolAccount {
        lamports: h.svm.minimum_balance_for_rent_exemption(data.len()),
        data,
        owner: h.me_id,
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(pda, acct).unwrap();
    pda
}

// ============================================================================
// 1. Notional exceeds note value → rejected
// ============================================================================

#[test]
fn test_notional_exceeds_note_value_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    let tk = &h.trader;
    let tkp = tk.pubkey();
    seed_empty_slot(&mut h, &market, &tkp, 0);

    let args = SubmitOrderArgs {
        market: market.to_bytes(),
        note_commitment: [9u8; 32],
        amount: 100,
        price_limit: 200,
        side: 0,
        note_amount: 19_999, // notional = 20_000 > 19_999
        expiry_slot: 1_000_000,
        order_id: [1u8; 16],
        order_type: 0,
        min_fill_qty: 0,
        user_commitment: [7u8; 32],
        slot_index: 0,
    };
    // Clone the keypair for `build_submit_order_ix` (takes &Keypair).
    let tk_clone = Keypair::from_bytes(&tk.to_bytes()).unwrap();
    let ix = h.build_submit_order_ix(args, &tk_clone);
    let tx = Transaction::new(
        &[&h.trader],
        Message::new(&[ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("submit_order must reject over-notional order");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("notional")
            || logs.to_lowercase().contains("exceeds note amount"),
        "expected notional error in logs, got:\n{logs}"
    );
}

// ============================================================================
// 2. Slot already occupied → rejected
// ============================================================================

#[test]
fn test_slot_already_occupied_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    // Seed the slot as PENDING (already has an active order).
    let seed = make_pending_seed(0, 0, 100, 10, 1_000_000, tkb);
    seed_pending_order(&mut h, &market, &tk, 0, &seed);

    let args = SubmitOrderArgs {
        market: market.to_bytes(),
        note_commitment: [9u8; 32],
        amount: 5,
        price_limit: 100,
        side: 0,
        note_amount: 500,
        expiry_slot: 1_000_000,
        order_id: [2u8; 16],
        order_type: 0,
        min_fill_qty: 0,
        user_commitment: [7u8; 32],
        slot_index: 0,
    };
    let tk_kp = Keypair::from_bytes(&h.trader.to_bytes()).unwrap();
    let ix = h.build_submit_order_ix(args, &tk_kp);
    let tx = Transaction::new(
        &[&h.trader],
        Message::new(&[ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("submit_order must reject occupied slot");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("notealreadylocked")
            || logs.to_lowercase().contains("slot occupied")
            || logs.to_lowercase().contains("already"),
        "expected slot-occupied error, got:\n{logs}"
    );
}

// ============================================================================
// 3. Wrong trading key → Anchor seed constraint rejects
// ============================================================================

#[test]
fn test_unauthorized_slot_owner_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    // Slot belongs to h.trader; intruder tries to write to it by providing
    // their own key as the signer — but the PDA derived from intruder is
    // different from the one derived from h.trader → AccountNotInitialized.
    let tk = h.trader.pubkey();
    let tkb = tk.to_bytes();
    seed_empty_slot(&mut h, &market, &tk, 0);

    let intruder = Keypair::new();
    h.svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();

    let args = SubmitOrderArgs {
        market: market.to_bytes(),
        note_commitment: [9u8; 32],
        amount: 5,
        price_limit: 100,
        side: 0,
        note_amount: 500,
        expiry_slot: 1_000_000,
        order_id: [1u8; 16],
        order_type: 0,
        min_fill_qty: 0,
        user_commitment: [0u8; 32],
        slot_index: 0,
    };
    // intruder signs → PDA derived from intruder key → doesn't exist.
    let ix = h.build_submit_order_ix(args, &intruder);
    let tx = Transaction::new(
        &[&intruder],
        Message::new(&[ix], Some(&intruder.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("intruder must not write to another user's slot");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.contains("AccountNotInitialized")
            || logs.to_lowercase().contains("seeds constraint")
            || logs.to_lowercase().contains("could not deserialize")
            || logs.to_lowercase().contains("invalid account"),
        "expected account/seed error, got:\n{logs}"
    );
    // h.trader's slot remains Empty.
    let _ = tkb; // suppress unused warning
}

// ============================================================================
// 4. MatchingConfig stores root_key from vault init
// ============================================================================

#[test]
fn test_permission_group_setup_root_key_only_host_invariants() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    // MatchingConfig layout: 8 disc + 32 market + 32 root_key + <rest>
    let (match_pda, _) = matching_config_pda(&h.me_id, &market);
    let acct = h
        .svm
        .get_account(&match_pda)
        .expect("matching_config must exist after init_market");
    assert!(acct.data.len() >= 8 + 32 + 32);
    let stored_root_key = &acct.data[8 + 32..8 + 32 + 32];
    assert_eq!(
        stored_root_key,
        h.root.pubkey().to_bytes().as_ref(),
        "matching_config.root_key must mirror vault_config.root_key"
    );
    assert_ne!(h.admin.pubkey().to_bytes(), h.root.pubkey().to_bytes());
}
