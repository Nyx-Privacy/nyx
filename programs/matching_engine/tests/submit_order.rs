//! Phase 3 submit_order litesvm integration tests (updated for Phase-4
//! OrderRecord / InitMarketArgs layout).
//!
//! Covered (Phase 3 §23.3.3):
//!   3.  test_unauthorized_trading_key_rejected
//!   6.  test_permission_group_setup_root_key_only_host_invariants
//!   10. test_note_not_in_tree_rejected
//!   11. test_notional_exceeds_note_value_rejected

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

#[test]
fn test_notional_exceeds_note_value_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    let user_commitment = [7u8; 32];
    h.create_wallet_stub(&user_commitment, &h.trader.pubkey());

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
    };
    let ix = h.build_submit_order_ix(args, &user_commitment);
    let tx = Transaction::new(
        &[&h.trader, &h.tee],
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

#[test]
fn test_note_not_in_tree_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    let user_commitment = [7u8; 32];
    h.create_wallet_stub(&user_commitment, &h.trader.pubkey());

    let args = SubmitOrderArgs {
        market: market.to_bytes(),
        note_commitment: [9u8; 32],
        amount: 10,
        price_limit: 100,
        side: 0,
        note_amount: 100_000,
        expiry_slot: 1_000_000,
        order_id: [1u8; 16],
        order_type: 0,
        min_fill_qty: 0,
    };
    let ix = h.build_submit_order_ix(args, &user_commitment);
    let tx = Transaction::new(
        &[&h.trader, &h.tee],
        Message::new(&[ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("submit_order must reject when leaf_count == 0");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("notnotintree")
            || logs.to_lowercase().contains("not present")
            || logs.to_lowercase().contains("merkle"),
        "expected note-not-in-tree error in logs, got:\n{logs}"
    );
}

#[test]
fn test_unauthorized_trading_key_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    let user_commitment = [42u8; 32]; // not registered

    let args = SubmitOrderArgs {
        market: market.to_bytes(),
        note_commitment: [9u8; 32],
        amount: 10,
        price_limit: 100,
        side: 0,
        note_amount: 100_000,
        expiry_slot: 1_000_000,
        order_id: [1u8; 16],
        order_type: 0,
        min_fill_qty: 0,
    };
    let ix = h.build_submit_order_ix(args, &user_commitment);
    let tx = Transaction::new(
        &[&h.trader, &h.tee],
        Message::new(&[ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("submit_order must reject unregistered trading key");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("unauthorizedtradingkey")
            || logs.to_lowercase().contains("not a member")
            || logs.to_lowercase().contains("walletentry")
            || logs.contains("AccountNotInitialized"),
        "expected unauthorized-trading-key error in logs, got:\n{logs}"
    );
}

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
