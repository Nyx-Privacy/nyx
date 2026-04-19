//! Shared helpers for matching_engine integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

use borsh::BorshSerialize;
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

pub type Pubkey = Address;
pub const SYSTEM_PROGRAM_ID: Pubkey = solana_system_interface::program::ID;

pub const VAULT_PROGRAM_ID: &str = "AB8ZJYgG6jNzfzQAgHHC9DNuQF6tB48UYqCWuseZ59XW";
pub const ME_PROGRAM_ID: &str = "G8MHBmzhfvRnhejot7XfeSFm3NC96uqm7VNduutM1J2K";

pub fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

pub fn vault_so_path() -> PathBuf {
    repo_root().join("target/deploy/vault.so")
}

pub fn matching_engine_so_path() -> PathBuf {
    repo_root().join("target/deploy/matching_engine.so")
}

pub fn anchor_disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"global:");
    h.update(name.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 8];
    d.copy_from_slice(&out[..8]);
    d
}

// ============================================================================
// Ix arg structs
// ============================================================================

#[derive(BorshSerialize)]
pub struct InitializeArgs {
    pub tee_pubkey: [u8; 32],
    pub root_key: [u8; 32],
}

#[derive(BorshSerialize)]
pub struct InitMarketArgs {
    pub market: [u8; 32],
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub pyth_account: [u8; 32],
    pub batch_interval_slots: u64,
    pub circuit_breaker_bps: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
}

#[derive(BorshSerialize, Clone, Copy)]
pub struct SubmitOrderArgs {
    pub market: [u8; 32],
    pub note_commitment: [u8; 32],
    pub amount: u64,
    pub price_limit: u64,
    pub side: u8,
    pub note_amount: u64,
    pub expiry_slot: u64,
    pub order_id: [u8; 16],
    pub order_type: u8,
    pub min_fill_qty: u64,
}

// ============================================================================
// PDA helpers
// ============================================================================

pub fn vault_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_config"], program_id)
}

pub fn dark_clob_pda(program_id: &Pubkey, market: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dark_clob", market.as_ref()], program_id)
}

pub fn matching_config_pda(program_id: &Pubkey, market: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"matching_config", market.as_ref()], program_id)
}

pub fn batch_results_pda(program_id: &Pubkey, market: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"batch_results", market.as_ref()], program_id)
}

pub fn wallet_entry_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"wallet", commitment.as_ref()], program_id)
}

pub fn note_lock_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"note_lock", commitment.as_ref()], program_id)
}

pub fn consumed_note_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"consumed_note", commitment.as_ref()], program_id)
}

// ============================================================================
// Harness
// ============================================================================

/// Bundle of programs + funded keys + initialised vault.
pub struct Harness {
    pub svm: LiteSVM,
    pub vault_id: Pubkey,
    pub me_id: Pubkey,
    pub admin: Keypair,
    pub tee: Keypair,
    pub root: Keypair,
    pub trader: Keypair,
    pub pyth_account: Pubkey,
}

impl Harness {
    pub fn setup() -> Self {
        let vault_so = vault_so_path();
        let me_so = matching_engine_so_path();
        if !vault_so.exists() {
            panic!(
                "vault binary missing — run `cargo build-sbf --manifest-path programs/vault/Cargo.toml`. Expected: {:?}",
                vault_so
            );
        }
        if !me_so.exists() {
            panic!(
                "matching_engine binary missing — run `cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml`. Expected: {:?}",
                me_so
            );
        }

        let mut svm = LiteSVM::new();
        let vault_id: Pubkey = VAULT_PROGRAM_ID.parse().unwrap();
        let me_id: Pubkey = ME_PROGRAM_ID.parse().unwrap();
        svm.add_program_from_file(vault_id, &vault_so).unwrap();
        svm.add_program_from_file(me_id, &me_so).unwrap();

        let admin = Keypair::new();
        let tee = Keypair::new();
        let root = Keypair::new();
        let trader = Keypair::new();
        for kp in [&admin, &tee, &root, &trader] {
            svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
        }

        // Initialize vault.
        let (vault_pda, _) = vault_config_pda(&vault_id);
        let mut init_data = anchor_disc("initialize").to_vec();
        InitializeArgs {
            tee_pubkey: tee.pubkey().to_bytes(),
            root_key: root.pubkey().to_bytes(),
        }
        .serialize(&mut init_data)
        .unwrap();
        let init_ix = Instruction {
            program_id: vault_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(vault_pda, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: init_data,
        };
        let tx = Transaction::new(
            &[&admin],
            Message::new(&[init_ix], Some(&admin.pubkey())),
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx).expect("vault initialize failed");

        // Create a mock Pyth oracle account holding a TWAP of 150 (arbitrary).
        let pyth_account = Keypair::new().pubkey();
        Self::write_mock_oracle(&mut svm, &pyth_account, 150);

        Self {
            svm,
            vault_id,
            me_id,
            admin,
            tee,
            root,
            trader,
            pyth_account,
        }
    }

    /// Write a mock oracle account with the `NYXMKPTH` magic + u64 twap at offset 8.
    pub fn write_mock_oracle(svm: &mut LiteSVM, addr: &Pubkey, twap: u64) {
        use solana_account::Account as SolAccount;

        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(b"NYXMKPTH");
        data[8..16].copy_from_slice(&twap.to_le_bytes());
        let acct = SolAccount {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: Pubkey::new_from_array([0u8; 32]),
            executable: false,
            rent_epoch: 0,
        };
        svm.set_account(*addr, acct).unwrap();
    }

    pub fn update_mock_oracle(&mut self, twap: u64) {
        Self::write_mock_oracle(&mut self.svm, &self.pyth_account.clone(), twap);
    }

    pub fn init_market(&mut self, market: &Pubkey, batch_interval_slots: u64) {
        self.init_market_full(market, batch_interval_slots, self.pyth_account, 300, 1, 0);
    }

    pub fn init_market_full(
        &mut self,
        market: &Pubkey,
        batch_interval_slots: u64,
        pyth: Pubkey,
        circuit_breaker_bps: u64,
        tick_size: u64,
        min_order_size: u64,
    ) {
        let (clob_pda, _) = dark_clob_pda(&self.me_id, market);
        let (match_pda, _) = matching_config_pda(&self.me_id, market);
        let (batch_pda, _) = batch_results_pda(&self.me_id, market);
        let (vault_pda, _) = vault_config_pda(&self.vault_id);

        let base_mint = Keypair::new().pubkey();
        let quote_mint = Keypair::new().pubkey();

        let mut data = anchor_disc("init_market").to_vec();
        InitMarketArgs {
            market: market.to_bytes(),
            base_mint: base_mint.to_bytes(),
            quote_mint: quote_mint.to_bytes(),
            pyth_account: pyth.to_bytes(),
            batch_interval_slots,
            circuit_breaker_bps,
            tick_size,
            min_order_size,
        }
        .serialize(&mut data)
        .unwrap();

        let ix = Instruction {
            program_id: self.me_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new_readonly(vault_pda, false),
                AccountMeta::new(clob_pda, false),
                AccountMeta::new(match_pda, false),
                AccountMeta::new(batch_pda, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        };
        let tx = Transaction::new(
            &[&self.admin],
            Message::new(&[ix], Some(&self.admin.pubkey())),
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_market failed");
    }

    /// Create a WalletEntry PDA for a user_commitment.
    pub fn create_wallet_stub(&mut self, user_commitment: &[u8; 32], owner: &Pubkey) {
        use solana_account::Account as SolAccount;
        let (pda, bump) = wallet_entry_pda(&self.vault_id, user_commitment);
        let mut data = vec![0u8; 88];
        data[0..8].copy_from_slice(&anchor_disc("WalletEntry"));
        data[8..40].copy_from_slice(user_commitment);
        data[40..72].copy_from_slice(&owner.to_bytes());
        data[72..80].copy_from_slice(&0u64.to_le_bytes());
        data[80] = bump;
        let acct = SolAccount {
            lamports: self.svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: self.vault_id,
            executable: false,
            rent_epoch: 0,
        };
        self.svm.set_account(pda, acct).unwrap();
    }

    pub fn build_submit_order_ix(
        &self,
        args: SubmitOrderArgs,
        user_commitment: &[u8; 32],
    ) -> Instruction {
        let market = Address::new_from_array(args.market);
        let (clob_pda, _) = dark_clob_pda(&self.me_id, &market);
        let (match_pda, _) = matching_config_pda(&self.me_id, &market);
        let (vault_pda, _) = vault_config_pda(&self.vault_id);
        let (wallet_pda, _) = wallet_entry_pda(&self.vault_id, user_commitment);
        let (lock_pda, _) = note_lock_pda(&self.vault_id, &args.note_commitment);
        let (consumed_probe, _) = consumed_note_pda(&self.vault_id, &args.note_commitment);

        let mut data = anchor_disc("submit_order").to_vec();
        args.serialize(&mut data).unwrap();

        Instruction {
            program_id: self.me_id,
            accounts: vec![
                AccountMeta::new(self.trader.pubkey(), true),
                AccountMeta::new(clob_pda, false),
                AccountMeta::new_readonly(match_pda, false),
                AccountMeta::new(vault_pda, false),
                AccountMeta::new_readonly(wallet_pda, false),
                AccountMeta::new(self.tee.pubkey(), true),
                AccountMeta::new(lock_pda, false),
                AccountMeta::new_readonly(consumed_probe, false),
                AccountMeta::new_readonly(self.vault_id, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        }
    }
}

// ============================================================================
// DarkCLOB direct-write helpers for Phase 4 run_batch tests.
//
// These bypass `submit_order` (which needs vault.leaf_count > 0 + CPI lock)
// and stuff well-formed OrderRecords straight into the DarkCLOB data. This
// is exactly what the on-chain program sees from its zero-copy loader.
// ============================================================================

/// Layout must match `OrderRecord` in
/// programs/matching_engine/src/state/order_record.rs — keep in sync.
pub const ORDER_RECORD_SIZE: usize = 8    // seq_no
    + 8   // arrival_slot
    + 8   // expiry_slot
    + 8   // price_limit
    + 8   // amount
    + 8   // min_fill_qty
    + 32  // trading_key
    + 32  // note_commitment
    + 32  // order_inclusion_commitment
    + 16  // order_id
    + 1   // side
    + 1   // status
    + 1   // order_type
    + 5;  // padding

pub const DARK_CLOB_CAPACITY: usize = 48;

/// Full DarkCLOB data size (no Anchor disc).
/// Layout: 32 market + 8 next_seq + 8 order_count + orders + 1 bump + 7 pad
pub const DARK_CLOB_DATA_SIZE: usize =
    32 + 8 + 8 + ORDER_RECORD_SIZE * DARK_CLOB_CAPACITY + 1 + 7;

/// Encode a single OrderRecord as its zero-copy bytes (side-safe).
#[derive(Clone, Copy, Debug)]
pub struct OrderSeed {
    pub seq_no: u64,
    pub arrival_slot: u64,
    pub expiry_slot: u64,
    pub price_limit: u64,
    pub amount: u64,
    pub min_fill_qty: u64,
    pub trading_key: [u8; 32],
    pub note_commitment: [u8; 32],
    pub order_inclusion_commitment: [u8; 32],
    pub order_id: [u8; 16],
    pub side: u8,
    pub status: u8,
    pub order_type: u8,
}

impl OrderSeed {
    pub fn write_into(&self, out: &mut [u8]) {
        assert_eq!(out.len(), ORDER_RECORD_SIZE);
        let mut off = 0;
        let mut put_u64 = |off: &mut usize, v: u64| {
            out[*off..*off + 8].copy_from_slice(&v.to_le_bytes());
            *off += 8;
        };
        put_u64(&mut off, self.seq_no);
        put_u64(&mut off, self.arrival_slot);
        put_u64(&mut off, self.expiry_slot);
        put_u64(&mut off, self.price_limit);
        put_u64(&mut off, self.amount);
        put_u64(&mut off, self.min_fill_qty);
        out[off..off + 32].copy_from_slice(&self.trading_key);
        off += 32;
        out[off..off + 32].copy_from_slice(&self.note_commitment);
        off += 32;
        out[off..off + 32].copy_from_slice(&self.order_inclusion_commitment);
        off += 32;
        out[off..off + 16].copy_from_slice(&self.order_id);
        off += 16;
        out[off] = self.side;
        off += 1;
        out[off] = self.status;
        off += 1;
        out[off] = self.order_type;
        off += 1;
        // 5 bytes padding — leave zero.
        off += 5;
        assert_eq!(off, ORDER_RECORD_SIZE);
    }
}

/// Stuff the given OrderSeeds into the DarkCLOB PDA starting at slot 0.
/// Clobbers next_seq to max(existing, highest seed seq_no + 1) so later
/// submit_order calls don't collide (not needed for Phase-4 tests yet).
pub fn seed_dark_clob(h: &mut Harness, market: &Pubkey, seeds: &[OrderSeed]) {
    let (pda, _) = dark_clob_pda(&h.me_id, market);
    let mut acct = h
        .svm
        .get_account(&pda)
        .expect("dark_clob PDA must exist — call init_market first");
    assert!(acct.data.len() == 8 + DARK_CLOB_DATA_SIZE);

    // Layout within account: 8 (disc) + 32 market + 8 next_seq + 8 order_count + orders...
    let orders_start = 8 + 32 + 8 + 8;
    let mut active_count: u64 = 0;
    let mut max_seq: u64 = 0;

    for (i, seed) in seeds.iter().enumerate() {
        assert!(i < DARK_CLOB_CAPACITY, "CLOB capacity exceeded");
        let start = orders_start + i * ORDER_RECORD_SIZE;
        let end = start + ORDER_RECORD_SIZE;
        seed.write_into(&mut acct.data[start..end]);
        if seed.status != 0 {
            active_count += 1;
        }
        if seed.seq_no >= max_seq {
            max_seq = seed.seq_no + 1;
        }
    }
    // Write order_count.
    acct.data[8 + 32 + 8..8 + 32 + 8 + 8].copy_from_slice(&active_count.to_le_bytes());
    // Bump next_seq forward.
    let existing_next =
        u64::from_le_bytes(acct.data[8 + 32..8 + 32 + 8].try_into().unwrap());
    let next_seq = existing_next.max(max_seq);
    acct.data[8 + 32..8 + 32 + 8].copy_from_slice(&next_seq.to_le_bytes());

    h.svm.set_account(pda, acct).unwrap();
}

/// Build a `run_batch` ix (no CPI, no vault account needed).
pub fn build_run_batch_ix(h: &Harness, market: &Pubkey, tee: &Keypair) -> Instruction {
    let (clob_pda, _) = dark_clob_pda(&h.me_id, market);
    let (match_pda, _) = matching_config_pda(&h.me_id, market);
    let (batch_pda, _) = batch_results_pda(&h.me_id, market);

    let mut data = anchor_disc("run_batch").to_vec();
    data.extend_from_slice(&market.to_bytes());

    Instruction {
        program_id: h.me_id,
        accounts: vec![
            AccountMeta::new(tee.pubkey(), true),
            AccountMeta::new(clob_pda, false),
            AccountMeta::new_readonly(match_pda, false),
            AccountMeta::new(batch_pda, false),
            AccountMeta::new_readonly(h.pyth_account, false),
        ],
        data,
    }
}

/// Build a `cancel_order` ix.
pub fn build_cancel_order_ix(
    h: &Harness,
    market: &Pubkey,
    order_id: &[u8; 16],
    signer: &Keypair,
) -> Instruction {
    let (clob_pda, _) = dark_clob_pda(&h.me_id, market);

    let mut data = anchor_disc("cancel_order").to_vec();
    data.extend_from_slice(&market.to_bytes());
    data.extend_from_slice(order_id);

    Instruction {
        program_id: h.me_id,
        accounts: vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(clob_pda, false),
        ],
        data,
    }
}

/// Decode BatchResults header fields (last_inclusion_root + stats).
pub struct BatchResultsView {
    pub last_inclusion_root: [u8; 32],
    pub last_batch_slot: u64,
    pub last_match_count: u64,
    pub last_clearing_price: u64,
    pub last_pyth_twap: u64,
    pub last_circuit_breaker_tripped: u8,
}

pub fn read_batch_results(h: &Harness, market: &Pubkey) -> BatchResultsView {
    let (pda, _) = batch_results_pda(&h.me_id, market);
    let acct = h
        .svm
        .get_account(&pda)
        .expect("batch_results must exist");
    // Layout: 8 disc + 32 market + 32 last_inclusion_root + 8 last_batch_slot
    //       + 8 last_match_count + 8 last_clearing_price + 8 last_pyth_twap
    //       + 1 cb_tripped + 7 pad + ...
    let d = &acct.data;
    let mut off = 8 + 32;
    let mut last_inclusion_root = [0u8; 32];
    last_inclusion_root.copy_from_slice(&d[off..off + 32]);
    off += 32;
    let last_batch_slot = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_match_count = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_clearing_price = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_pyth_twap = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_circuit_breaker_tripped = d[off];
    BatchResultsView {
        last_inclusion_root,
        last_batch_slot,
        last_match_count,
        last_clearing_price,
        last_pyth_twap,
        last_circuit_breaker_tripped,
    }
}

/// Read the `status` byte of the OrderRecord at `slot` of the CLOB.
pub fn read_order_status(h: &Harness, market: &Pubkey, slot: usize) -> u8 {
    let (pda, _) = dark_clob_pda(&h.me_id, market);
    let acct = h.svm.get_account(&pda).expect("dark_clob");
    // inside data: 8 disc + 32 market + 8 next_seq + 8 order_count + orders*
    // status byte within an OrderRecord:
    //   8 seq_no + 8 arr + 8 exp + 8 price + 8 amt + 8 minfill + 32 tk + 32 nc
    //   + 32 oic + 16 oid + 1 side + 1 status ...
    let off = 8 + 32 + 8 + 8 + slot * ORDER_RECORD_SIZE
        + 8 + 8 + 8 + 8 + 8 + 8 + 32 + 32 + 32 + 16 + 1;
    acct.data[off]
}

/// Build a default OrderSeed with deterministic note_commitment = [side,seq,0,...].
pub fn make_seed(
    seq_no: u64,
    side: u8,
    price_limit: u64,
    amount: u64,
    expiry_slot: u64,
    trading_key: [u8; 32],
) -> OrderSeed {
    let mut note_commitment = [0u8; 32];
    note_commitment[0] = side;
    note_commitment[1..9].copy_from_slice(&seq_no.to_le_bytes());
    let mut order_id = [0u8; 16];
    order_id[0..8].copy_from_slice(&seq_no.to_le_bytes());
    let mut oic = [0u8; 32];
    oic[0..8].copy_from_slice(&seq_no.to_le_bytes());
    oic[8] = side;
    OrderSeed {
        seq_no,
        arrival_slot: 1,
        expiry_slot,
        price_limit,
        amount,
        min_fill_qty: 0,
        trading_key,
        note_commitment,
        order_inclusion_commitment: oic,
        order_id,
        side,
        status: 1, // ACTIVE
        order_type: 0, // LIMIT
    }
}
