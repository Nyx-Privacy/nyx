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

pub const VAULT_PROGRAM_ID: &str = "ELt4FH2gH8RaZkYbvbbDjGkX8dPhGFdWnspM4w1fdjoY";
pub const ME_PROGRAM_ID: &str = "DvYcaiBuaHgJFVjVd57JLM7ZMavzXvBezJwsvA46FJbH";

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

/// Anchor account discriminator = first 8 bytes of sha256("account:<TypeName>").
pub fn anchor_acct_disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"account:");
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
    pub user_commitment: [u8; 32],
    /// PendingOrder slot index for this trading key.
    pub slot_index: u8,
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

pub fn nullifier_pda(program_id: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", nullifier.as_ref()], program_id)
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

    /// Build a `submit_order` ix for the new ER-based privacy model.
    /// Accounts: [trading_key (signer), pending_order PDA (mut)].
    /// No vault CPI — order intent lives only inside the ER.
    pub fn build_submit_order_ix(
        &self,
        args: SubmitOrderArgs,
        trading_key: &Keypair,
    ) -> Instruction {
        let market = Address::new_from_array(args.market);
        let (pending_pda, _) = pending_order_pda(
            &self.me_id,
            &market,
            &trading_key.pubkey(),
            args.slot_index,
        );

        let mut data = anchor_disc("submit_order").to_vec();
        args.serialize(&mut data).unwrap();

        Instruction {
            program_id: self.me_id,
            accounts: vec![
                AccountMeta::new(trading_key.pubkey(), true),
                AccountMeta::new(pending_pda, false),
            ],
            data,
        }
    }
}

// ============================================================================
// PendingOrder helpers (Phase 6 — privacy-fix run_batch tests).
//
// These create PendingOrder PDAs directly via `svm.set_account`, bypassing
// `submit_order` (which runs inside the ER). Tests exercise the matching
// engine in isolation.
// ============================================================================

pub const PENDING_ORDER_SEED: &[u8] = b"pending_order";

/// Data size of the PendingOrder struct (no Anchor disc).
/// Layout: 4×32 + 6×8 + 16 + 5 + 3 = 200 bytes — must stay in sync with
/// programs/matching_engine/src/state/pending_order.rs.
pub const PENDING_ORDER_STRUCT_SIZE: usize = 200;

pub fn pending_order_pda(
    program_id: &Pubkey,
    market: &Pubkey,
    trading_key: &Pubkey,
    slot_index: u8,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[PENDING_ORDER_SEED, market.as_ref(), trading_key.as_ref(), &[slot_index]],
        program_id,
    )
}

/// Minimal seed needed to create a Pending slot in tests.
#[derive(Clone, Copy, Debug)]
pub struct PendingOrderSeed {
    pub price_limit: u64,
    pub amount: u64,
    pub note_amount: u64,
    pub min_fill_qty: u64,
    pub expiry_slot: u64,
    pub arrival_slot: u64,
    pub order_id: [u8; 16],
    pub note_commitment: [u8; 32],
    pub user_commitment: [u8; 32],
    pub side: u8,  // 0 = BID, 1 = ASK
    pub order_type: u8,
}

/// Write a PendingOrder PDA account directly into the SVM for a given
/// (market, trading_key, slot_index). Status = PENDING (1).
pub fn seed_pending_order(
    h: &mut Harness,
    market: &Pubkey,
    trading_key: &Pubkey,
    slot_index: u8,
    seed: &PendingOrderSeed,
) -> Pubkey {
    use solana_account::Account as SolAccount;
    let (pda, bump) = pending_order_pda(&h.me_id, market, trading_key, slot_index);
    // total = 8 (disc) + 200 (struct)
    let mut data = vec![0u8; 8 + PENDING_ORDER_STRUCT_SIZE];
    data[0..8].copy_from_slice(&anchor_acct_disc("PendingOrder"));

    let mut off = 8usize;
    // trading_key
    data[off..off + 32].copy_from_slice(&trading_key.to_bytes()); off += 32;
    // market
    data[off..off + 32].copy_from_slice(&market.to_bytes()); off += 32;
    // note_commitment
    data[off..off + 32].copy_from_slice(&seed.note_commitment); off += 32;
    // user_commitment
    data[off..off + 32].copy_from_slice(&seed.user_commitment); off += 32;
    // price_limit
    data[off..off + 8].copy_from_slice(&seed.price_limit.to_le_bytes()); off += 8;
    // amount
    data[off..off + 8].copy_from_slice(&seed.amount.to_le_bytes()); off += 8;
    // note_amount
    data[off..off + 8].copy_from_slice(&seed.note_amount.to_le_bytes()); off += 8;
    // min_fill_qty
    data[off..off + 8].copy_from_slice(&seed.min_fill_qty.to_le_bytes()); off += 8;
    // expiry_slot
    data[off..off + 8].copy_from_slice(&seed.expiry_slot.to_le_bytes()); off += 8;
    // arrival_slot
    data[off..off + 8].copy_from_slice(&seed.arrival_slot.to_le_bytes()); off += 8;
    // order_id
    data[off..off + 16].copy_from_slice(&seed.order_id); off += 16;
    // side
    data[off] = seed.side; off += 1;
    // order_type
    data[off] = seed.order_type; off += 1;
    // status = PENDING (1)
    data[off] = 1u8; off += 1;
    // slot_index
    data[off] = slot_index; off += 1;
    // bump
    data[off] = bump; off += 1;
    // _padding[3]
    off += 3;
    debug_assert_eq!(off, 8 + PENDING_ORDER_STRUCT_SIZE);

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

/// Read the `status` byte of a PendingOrder PDA.
pub fn read_pending_order_status(h: &Harness, pda: &Pubkey) -> u8 {
    let acct = h.svm.get_account(pda).expect("pending_order PDA must exist");
    // disc(8) + trading_key(32) + market(32) + note_commitment(32)
    // + user_commitment(32) + price_limit(8) + amount(8) + note_amount(8)
    // + min_fill_qty(8) + expiry_slot(8) + arrival_slot(8) + order_id(16)
    // + side(1) + order_type(1) + STATUS(1)
    let status_off = 8 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 8 + 16 + 1 + 1;
    acct.data[status_off]
}

/// Make a PendingOrderSeed with deterministic fields similar to `make_seed`.
/// `seq` is repurposed as an arrival_slot tie-breaker. Zero the top byte of
/// user_commitment to keep BN254 inputs inside the field.
pub fn make_pending_seed(
    seq: u64,
    side: u8,
    price_limit: u64,
    amount: u64,
    expiry_slot: u64,
    trading_key_bytes: [u8; 32],
) -> PendingOrderSeed {
    let mut note_commitment = [0u8; 32];
    note_commitment[0] = side;
    note_commitment[1..9].copy_from_slice(&seq.to_le_bytes());
    let mut order_id = [0u8; 16];
    order_id[0..8].copy_from_slice(&seq.to_le_bytes());
    order_id[15] = side.wrapping_add(1); // ensure non-zero sentinel
    let mut user_commitment = trading_key_bytes;
    user_commitment[0] = 0; // keep inside BN254 Fr
    PendingOrderSeed {
        price_limit,
        amount,
        note_amount: if side == 0 {
            amount.saturating_mul(price_limit).max(1)
        } else {
            amount.max(1)
        },
        min_fill_qty: 0,
        expiry_slot,
        arrival_slot: seq + 1,
        order_id,
        note_commitment,
        user_commitment,
        side,
        order_type: 0,
    }
}

// ============================================================================
// DarkCLOB direct-write helpers — kept for backward compat but no longer
// used by run_batch tests (which now use PendingOrder PDAs).
// ============================================================================

/// Layout must match `OrderRecord` in
/// programs/matching_engine/src/state/order_record.rs — keep in sync.
/// Phase 5: +note_amount, +total_quantity, +filled_quantity, +user_commitment;
/// renamed note_commitment → collateral_note.
pub const ORDER_RECORD_SIZE: usize = 8    // seq_no
    + 8   // arrival_slot
    + 8   // expiry_slot
    + 8   // price_limit
    + 8   // amount
    + 8   // min_fill_qty
    + 8   // note_amount
    + 8   // total_quantity
    + 8   // filled_quantity
    + 32  // trading_key
    + 32  // collateral_note
    + 32  // user_commitment
    + 32  // order_inclusion_commitment
    + 16  // order_id
    + 1   // side
    + 1   // status
    + 1   // order_type
    + 5;  // padding

pub const DARK_CLOB_CAPACITY: usize = 45;

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
    pub note_amount: u64,
    pub total_quantity: u64,
    pub filled_quantity: u64,
    pub trading_key: [u8; 32],
    pub collateral_note: [u8; 32],
    pub user_commitment: [u8; 32],
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
        put_u64(&mut off, self.note_amount);
        put_u64(&mut off, self.total_quantity);
        put_u64(&mut off, self.filled_quantity);
        out[off..off + 32].copy_from_slice(&self.trading_key);
        off += 32;
        out[off..off + 32].copy_from_slice(&self.collateral_note);
        off += 32;
        out[off..off + 32].copy_from_slice(&self.user_commitment);
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
/// `ComputeBudget::SetComputeUnitLimit(cu)` ix. Phase-5's Poseidon calls
/// are expensive (~17k CU each) so run_batch can exceed the 200k default
/// when multiple matches produce change notes; tests should prepend this.
pub fn compute_budget_ix(cu: u32) -> Instruction {
    // ComputeBudget program id (hardcoded Solana builtin).
    let program_id = Pubkey::from([
        3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229,
        187, 197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
    ]);
    // Discriminator 0x02 = SetComputeUnitLimit.
    let mut data = vec![0x02u8];
    data.extend_from_slice(&cu.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

/// Build a `run_batch` ix.
/// `pending_order_pdas` are appended as writable remaining_accounts so the
/// handler can read and reset matched/expired PendingOrder slots.
pub fn build_run_batch_ix(
    h: &Harness,
    market: &Pubkey,
    tee: &Keypair,
    pending_order_pdas: &[Pubkey],
) -> Instruction {
    let (match_pda, _) = matching_config_pda(&h.me_id, market);
    let (batch_pda, _) = batch_results_pda(&h.me_id, market);
    let (vault_pda, _) = vault_config_pda(&h.vault_id);

    let mut data = anchor_disc("run_batch").to_vec();
    data.extend_from_slice(&market.to_bytes());

    let mut accounts = vec![
        AccountMeta::new(tee.pubkey(), true),
        AccountMeta::new_readonly(match_pda, false),
        AccountMeta::new(batch_pda, false),
        AccountMeta::new_readonly(vault_pda, false),
        AccountMeta::new_readonly(h.pyth_account, false),
    ];
    for pda in pending_order_pdas {
        accounts.push(AccountMeta::new(*pda, false));
    }

    Instruction {
        program_id: h.me_id,
        accounts,
        data,
    }
}

/// Build a `cancel_order` ix.
/// Cancels the PendingOrder at `slot_index` owned by `signer`.
pub fn build_cancel_order_ix(
    h: &Harness,
    market: &Pubkey,
    slot_index: u8,
    signer: &Keypair,
) -> Instruction {
    let (pending_pda, _) = pending_order_pda(&h.me_id, market, &signer.pubkey(), slot_index);

    let mut data = anchor_disc("cancel_order").to_vec();
    data.extend_from_slice(&market.to_bytes());
    data.push(slot_index);

    Instruction {
        program_id: h.me_id,
        accounts: vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(pending_pda, false),
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
    // status byte within an OrderRecord (Phase 5): 9 u64s + 4×32B + 16B + side+status.
    //   9×8 (u64s: seq/arr/exp/price/amt/minfill/note_amount/total_qty/filled_qty)
    //   + 32 tk + 32 collateral + 32 user_commit + 32 oic + 16 oid + 1 side + 1 status
    let off = 8 + 32 + 8 + 8 + slot * ORDER_RECORD_SIZE
        + 8 * 9 + 32 * 4 + 16 + 1;
    acct.data[off]
}

/// Build a default OrderSeed with deterministic collateral_note = [side,seq,0,...].
pub fn make_seed(
    seq_no: u64,
    side: u8,
    price_limit: u64,
    amount: u64,
    expiry_slot: u64,
    trading_key: [u8; 32],
) -> OrderSeed {
    let mut collateral_note = [0u8; 32];
    collateral_note[0] = side;
    collateral_note[1..9].copy_from_slice(&seq_no.to_le_bytes());
    let mut order_id = [0u8; 16];
    // Reserve byte 15 for uniqueness so the all-zero sentinel isn't hit.
    order_id[0..8].copy_from_slice(&seq_no.to_le_bytes());
    order_id[15] = side.wrapping_add(1);
    let mut oic = [0u8; 32];
    oic[0..8].copy_from_slice(&seq_no.to_le_bytes());
    oic[8] = side;
    // Phase 5: Poseidon (BN254) needs inputs < Fr modulus. Zero the top
    // byte so arbitrary 32-byte harness fixtures stay inside the field.
    let mut user_commitment = trading_key;
    user_commitment[0] = 0;
    OrderSeed {
        seq_no,
        arrival_slot: 1,
        expiry_slot,
        price_limit,
        amount,
        min_fill_qty: 0,
        note_amount: amount.saturating_mul(price_limit).max(1),
        total_quantity: amount,
        filled_quantity: 0,
        trading_key,
        collateral_note,
        user_commitment,
        order_inclusion_commitment: oic,
        order_id,
        side,
        status: 1, // ACTIVE
        order_type: 0, // LIMIT
    }
}

// ============================================================================
// Phase-5 settlement helpers (tee_forced_settle)
// ============================================================================

/// Byte-for-byte mirror of the on-chain `MatchResultPayload` Borsh shape.
/// When this diverges the settle test panics early rather than at the
/// program's deserializer.
#[derive(BorshSerialize, Clone)]
pub struct MatchResultPayload {
    pub match_id: [u8; 16],
    pub note_a_commitment: [u8; 32],
    pub note_b_commitment: [u8; 32],
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub nullifier_a: [u8; 32],
    pub nullifier_b: [u8; 32],
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    pub base_amount: u64,
    pub quote_amount: u64,
    pub buyer_change_amt: u64,
    pub seller_change_amt: u64,
    pub buyer_fee_amt: u64,
    pub seller_fee_amt: u64,
    pub note_fee_commitment: [u8; 32],
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    pub clearing_price: u64,
    pub batch_slot: u64,
}

/// Sentinel used by on-chain code.
pub const RELOCK_ORDER_ID_NONE: [u8; 16] = [0u8; 16];

/// Build a 32-byte "commitment" whose integer value fits inside the BN254
/// scalar field (top byte zero). Use for note_c/d/e/f/fee when Poseidon
/// will process them during Merkle append — arbitrary 0xFFs would cause
/// `InvalidProof` inside light-poseidon.
pub fn fr_safe(seed: u8, salt: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1] = seed; // byte 0 stays zero → value < 2^248 < Fr modulus
    out[31] = salt;
    out
}

impl MatchResultPayload {
    /// A sane zero-ish default that tests mutate selectively.
    #[allow(clippy::too_many_arguments)]
    pub fn exact_fill(
        match_id: [u8; 16],
        note_a: [u8; 32],
        note_b: [u8; 32],
        note_c: [u8; 32],
        note_d: [u8; 32],
        nullifier_a: [u8; 32],
        nullifier_b: [u8; 32],
        order_id_a: [u8; 16],
        order_id_b: [u8; 16],
        base_amount: u64,
        quote_amount: u64,
    ) -> Self {
        Self {
            match_id,
            note_a_commitment: note_a,
            note_b_commitment: note_b,
            note_c_commitment: note_c,
            note_d_commitment: note_d,
            note_e_commitment: [0u8; 32],
            note_f_commitment: [0u8; 32],
            nullifier_a,
            nullifier_b,
            order_id_a,
            order_id_b,
            base_amount,
            quote_amount,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_commitment: [0u8; 32],
            buyer_relock_order_id: RELOCK_ORDER_ID_NONE,
            buyer_relock_expiry: 0,
            seller_relock_order_id: RELOCK_ORDER_ID_NONE,
            seller_relock_expiry: 0,
            clearing_price: 0,
            batch_slot: 0,
        }
    }
}

/// Mirror of `tee_forced_settle::canonical_payload_hash`. Byte-identical
/// output or signature verification fails.
pub fn canonical_payload_hash(p: &MatchResultPayload) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nyx-match-v5");
    h.update(p.match_id);
    h.update(p.note_a_commitment);
    h.update(p.note_b_commitment);
    h.update(p.note_c_commitment);
    h.update(p.note_d_commitment);
    h.update(p.note_e_commitment);
    h.update(p.note_f_commitment);
    h.update(p.note_fee_commitment);
    h.update(p.nullifier_a);
    h.update(p.nullifier_b);
    h.update(p.order_id_a);
    h.update(p.order_id_b);
    h.update(p.base_amount.to_le_bytes());
    h.update(p.quote_amount.to_le_bytes());
    h.update(p.buyer_change_amt.to_le_bytes());
    h.update(p.seller_change_amt.to_le_bytes());
    h.update(p.buyer_fee_amt.to_le_bytes());
    h.update(p.seller_fee_amt.to_le_bytes());
    h.update(p.buyer_relock_order_id);
    h.update(p.buyer_relock_expiry.to_le_bytes());
    h.update(p.seller_relock_order_id);
    h.update(p.seller_relock_expiry.to_le_bytes());
    h.update(p.clearing_price.to_le_bytes());
    h.update(p.batch_slot.to_le_bytes());
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Solana Ed25519Program ID as a raw pubkey. Uses the canonical Solana
/// constant — do NOT hardcode bytes; LiteSVM enforces the real program.
pub fn ed25519_program_id() -> Pubkey {
    // base58 decode of "Ed25519SigVerify111111111111111111111111111".
    Pubkey::from([
        3, 125, 70, 214, 124, 147, 251, 190, 18, 249, 66, 143, 131, 141, 64, 255, 5, 112, 116,
        73, 39, 244, 138, 100, 252, 202, 112, 68, 128, 0, 0, 0,
    ])
}

/// Build an Ed25519Program precompile ix with inlined pubkey + msg + sig.
/// Layout per Solana SDK:
///   1  num_signatures = 1
///   1  padding = 0
///   2  signature_offset
///   2  signature_instruction_index = 0xFFFF (same ix)
///   2  public_key_offset
///   2  public_key_instruction_index = 0xFFFF
///   2  message_data_offset
///   2  message_data_size
///   2  message_instruction_index = 0xFFFF
/// Then inline: pubkey (32) || signature (64) || message (N).
pub fn build_ed25519_verify_ix(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Instruction {
    let header_len: u16 = 16;
    let pk_off: u16 = header_len;
    let sig_off: u16 = pk_off + 32;
    let msg_off: u16 = sig_off + 64;
    let msg_len: u16 = message.len() as u16;

    let mut data = Vec::with_capacity(header_len as usize + 32 + 64 + message.len());
    data.push(1u8); // num_signatures
    data.push(0u8); // padding
    data.extend_from_slice(&sig_off.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // signature_instruction_index
    data.extend_from_slice(&pk_off.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // public_key_instruction_index
    data.extend_from_slice(&msg_off.to_le_bytes());
    data.extend_from_slice(&msg_len.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // message_instruction_index
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: ed25519_program_id(),
        accounts: vec![],
        data,
    }
}

/// Directly seed a NoteLock PDA (bypasses the `lock_note` ix — the Phase-5
/// settle tests focus on *settlement* not lock mechanics). The PDA is
/// writable and owned by the vault program so the real handler can close
/// it via `close = tee_authority`.
pub fn seed_note_lock(
    h: &mut Harness,
    note_commitment: &[u8; 32],
    order_id: &[u8; 16],
    expiry_slot: u64,
    amount: u64,
) {
    use solana_account::Account as SolAccount;
    let (pda, bump) = note_lock_pda(&h.vault_id, note_commitment);
    // Layout: 8 disc + 32 commit + 16 order_id + 8 expiry + 32 locked_by
    //       + 8 amount + 1 bump + 7 pad = 112 bytes.
    let mut data = vec![0u8; 112];
    data[0..8].copy_from_slice(&anchor_acct_disc("NoteLock"));
    data[8..40].copy_from_slice(note_commitment);
    data[40..56].copy_from_slice(order_id);
    data[56..64].copy_from_slice(&expiry_slot.to_le_bytes());
    data[64..96].copy_from_slice(&h.tee.pubkey().to_bytes());
    data[96..104].copy_from_slice(&amount.to_le_bytes());
    data[104] = bump;
    let acct = SolAccount {
        lamports: h.svm.minimum_balance_for_rent_exemption(data.len()),
        data,
        owner: h.vault_id,
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(pda, acct).unwrap();
}

/// Read the current leaf_count out of VaultConfig.
pub fn vault_leaf_count(h: &Harness) -> u64 {
    let (pda, _) = vault_config_pda(&h.vault_id);
    let acct = h.svm.get_account(&pda).expect("vault_config");
    // Layout: 8 disc + 32 admin + 32 tee_pubkey + 32 root_key + 8 leaf_count
    let off = 8 + 32 + 32 + 32;
    u64::from_le_bytes(acct.data[off..off + 8].try_into().unwrap())
}

/// Read protocol_owner_commitment out of VaultConfig.
pub fn vault_protocol_owner(h: &Harness) -> [u8; 32] {
    use vault_layout::PROTOCOL_OWNER_OFFSET;
    let (pda, _) = vault_config_pda(&h.vault_id);
    let acct = h.svm.get_account(&pda).expect("vault_config");
    let mut out = [0u8; 32];
    out.copy_from_slice(&acct.data[PROTOCOL_OWNER_OFFSET..PROTOCOL_OWNER_OFFSET + 32]);
    out
}

/// Offsets inside VaultConfig.
/// Layout (matches programs/vault/src/state.rs::VaultConfig — keep in sync):
///   8  disc
///   32 admin + 32 tee_pubkey + 32 root_key
///   8  leaf_count
///   32 current_root
///   32 * 32  roots
///   32 * 20  zero_subtree_roots
///   32 * 20  right_path
///   1  roots_head (u8)
///   1  bump
///   32 protocol_owner_commitment
///   2  fee_rate_bps (u16)
///   4  _padding
pub mod vault_layout {
    pub const ROOT_HISTORY_SIZE: usize = 32;
    pub const MERKLE_DEPTH: usize = 20;
    pub const PROTOCOL_OWNER_OFFSET: usize = 8
        + 32 * 3   // admin + tee + root
        + 8        // leaf_count
        + 32       // current_root
        + 32 * ROOT_HISTORY_SIZE
        + 32 * MERKLE_DEPTH   // zero subtree roots
        + 32 * MERKLE_DEPTH   // right path
        + 1        // roots_head (u8)
        + 1;       // bump (u8)
}

/// Overwrite `protocol_owner_commitment` + `fee_rate_bps` directly in the
/// VaultConfig account. The on-chain program exposes no setter yet —
/// tests use this to simulate governance having set the fee rate.
pub fn set_vault_fee_config(h: &mut Harness, owner_commitment: [u8; 32], fee_rate_bps: u16) {
    use vault_layout::PROTOCOL_OWNER_OFFSET;
    let (pda, _) = vault_config_pda(&h.vault_id);
    let mut acct = h.svm.get_account(&pda).expect("vault_config");
    acct.data[PROTOCOL_OWNER_OFFSET..PROTOCOL_OWNER_OFFSET + 32].copy_from_slice(&owner_commitment);
    acct.data[PROTOCOL_OWNER_OFFSET + 32..PROTOCOL_OWNER_OFFSET + 34]
        .copy_from_slice(&fee_rate_bps.to_le_bytes());
    h.svm.set_account(pda, acct).unwrap();
}

/// True if the `consumed_note` PDA for `note_commitment` has been initialised.
pub fn consumed_note_exists(h: &Harness, note_commitment: &[u8; 32]) -> bool {
    let (pda, _) = consumed_note_pda(&h.vault_id, note_commitment);
    h.svm
        .get_account(&pda)
        .map(|a| !a.data.is_empty() && a.lamports > 0)
        .unwrap_or(false)
}

/// True if the `nullifier` PDA exists.
pub fn nullifier_exists(h: &Harness, nullifier: &[u8; 32]) -> bool {
    let (pda, _) = nullifier_pda(&h.vault_id, nullifier);
    h.svm
        .get_account(&pda)
        .map(|a| !a.data.is_empty() && a.lamports > 0)
        .unwrap_or(false)
}

/// True if a `note_lock` PDA exists for the commitment (unclosed lock).
pub fn note_lock_exists(h: &Harness, note_commitment: &[u8; 32]) -> bool {
    let (pda, _) = note_lock_pda(&h.vault_id, note_commitment);
    h.svm
        .get_account(&pda)
        .map(|a| !a.data.is_empty() && a.lamports > 0)
        .unwrap_or(false)
}

/// Build the accounts list + data for tee_forced_settle.
/// Requires: vault initialised, note_lock_a/b seeded for the input notes.
pub fn build_settle_ix(h: &Harness, payload: &MatchResultPayload) -> Instruction {
    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (lock_a, _) = note_lock_pda(&h.vault_id, &payload.note_a_commitment);
    let (lock_b, _) = note_lock_pda(&h.vault_id, &payload.note_b_commitment);
    let (consumed_a, _) = consumed_note_pda(&h.vault_id, &payload.note_a_commitment);
    let (consumed_b, _) = consumed_note_pda(&h.vault_id, &payload.note_b_commitment);
    let (null_a, _) = nullifier_pda(&h.vault_id, &payload.nullifier_a);
    let (null_b, _) = nullifier_pda(&h.vault_id, &payload.nullifier_b);

    // Re-lock PDAs: always supply a writable account at the expected seed
    // (zero commitment → use a dummy derivation so the handler still sees
    // a writable account it ignores).
    let (lock_e, _) = note_lock_pda(&h.vault_id, &payload.note_e_commitment);
    let (lock_f, _) = note_lock_pda(&h.vault_id, &payload.note_f_commitment);

    let instructions_sysvar: Pubkey = Pubkey::from([
        // Sysvar1nstructions1111111111111111111111111
        6, 167, 213, 23, 24, 123, 209, 102, 53, 218, 212, 4, 85, 253, 194, 192, 193, 36, 198, 143,
        33, 86, 117, 165, 219, 186, 203, 95, 8, 0, 0, 0,
    ]);

    let mut data = anchor_disc("tee_forced_settle").to_vec();
    payload.serialize(&mut data).unwrap();

    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(h.tee.pubkey(), true),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new(lock_a, false),
            AccountMeta::new(lock_b, false),
            AccountMeta::new(consumed_a, false),
            AccountMeta::new(consumed_b, false),
            AccountMeta::new(null_a, false),
            AccountMeta::new(null_b, false),
            AccountMeta::new(lock_e, false),
            AccountMeta::new(lock_f, false),
            AccountMeta::new_readonly(instructions_sysvar, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// One-shot: sign payload with TEE, build (ed25519_verify + tee_forced_settle)
/// message, wrap in a Transaction.
pub fn build_settle_tx(
    h: &Harness,
    payload: &MatchResultPayload,
) -> Transaction {
    let msg_hash = canonical_payload_hash(payload);
    let sig = h.tee.sign_message(&msg_hash);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig.as_ref());
    let tee_pk = h.tee.pubkey().to_bytes();
    let ed_ix = build_ed25519_verify_ix(&tee_pk, &sig_bytes, &msg_hash);
    let settle_ix = build_settle_ix(h, payload);
    Transaction::new(
        &[&h.tee],
        Message::new(
            &[compute_budget_ix(1_400_000), ed_ix, settle_ix],
            Some(&h.tee.pubkey()),
        ),
        h.svm.latest_blockhash(),
    )
}

