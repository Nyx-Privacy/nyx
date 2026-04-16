use anchor_lang::prelude::*;

/// Fixed Merkle tree depth. 2^20 = 1,048,576 notes. Matches circom circuit.
pub const MERKLE_DEPTH: u8 = 20;

/// Number of historical Merkle roots the vault tracks. A withdrawal's proof
/// may reference any of the last N roots so that a legitimate user isn't
/// DoS'd by a racing deposit.
pub const ROOT_HISTORY_SIZE: usize = 32;

/// Global vault configuration + append-only Merkle tree header + root history.
#[account]
#[derive(InitSpace)]
pub struct VaultConfig {
    /// Admin authority (usually a multisig). Can rotate `tee_pubkey`.
    pub admin: Pubkey,
    /// Attested TEE Ed25519 signing pubkey. Verified for `tee_forced_settle`.
    pub tee_pubkey: Pubkey,
    /// Number of leaves currently inserted into the Merkle tree. Monotonically
    /// increasing; used as the `note_counter` for blinding factor derivation.
    pub leaf_count: u64,
    /// Current Merkle root.
    pub current_root: [u8; 32],
    /// Ring buffer of the last `ROOT_HISTORY_SIZE` roots, newest first.
    pub roots: [[u8; 32]; ROOT_HISTORY_SIZE],
    pub roots_head: u8,
    /// Precomputed empty-subtree roots at each level (0 = leaf, depth-1 = root's children).
    /// Needed to verify append insertions without holding the entire tree on-chain.
    pub zero_subtree_roots: [[u8; 32]; MERKLE_DEPTH as usize],
    /// Right-path nodes: the rightmost filled node at each level. Lets us
    /// append a new leaf by recomputing only MERKLE_DEPTH hashes. This is
    /// exactly the "incremental Merkle tree" pattern from Tornado/Semaphore.
    pub right_path: [[u8; 32]; MERKLE_DEPTH as usize],
    pub bump: u8,
}

impl VaultConfig {
    pub const SEED: &'static [u8] = b"vault_config";
}

/// PDA marking a registered user commitment (wallet identity).
#[account]
#[derive(InitSpace)]
pub struct WalletEntry {
    pub commitment: [u8; 32],
    pub owner: Pubkey, // the Root Key that signed `create_wallet`
    pub created_slot: u64,
    pub bump: u8,
}

impl WalletEntry {
    pub const SEED: &'static [u8] = b"wallet";
}

/// PDA marking a spent nullifier. Existence of the PDA => nullifier consumed.
#[account]
#[derive(InitSpace)]
pub struct NullifierEntry {
    pub nullifier: [u8; 32],
    pub spent_slot: u64,
    pub bump: u8,
}

impl NullifierEntry {
    pub const SEED: &'static [u8] = b"nullifier";
}

/// PDA marking a note commitment consumed by TEE-forced settlement.
#[account]
#[derive(InitSpace)]
pub struct ConsumedNoteEntry {
    pub note_commitment: [u8; 32],
    pub match_id: [u8; 16],
    pub consumed_slot: u64,
    pub bump: u8,
}

impl ConsumedNoteEntry {
    pub const SEED: &'static [u8] = b"consumed_note";
}

/// PDA locking a note to a specific order. Automatically expires at `expiry_slot`.
#[account]
#[derive(InitSpace)]
pub struct NoteLock {
    pub note_commitment: [u8; 32],
    pub order_id: [u8; 16],
    pub expiry_slot: u64,
    pub locked_by: Pubkey, // the TEE key that locked
    pub bump: u8,
}

impl NoteLock {
    pub const SEED: &'static [u8] = b"note_lock";
}

impl VaultConfig {
    /// Check whether a Merkle root appears in the recent-roots ring buffer.
    pub fn contains_root(&self, root: &[u8; 32]) -> bool {
        if &self.current_root == root {
            return true;
        }
        self.roots.iter().any(|r| r == root)
    }

    /// Push a new root into the ring buffer, replacing the oldest entry.
    pub fn push_root(&mut self, root: [u8; 32]) {
        let idx = self.roots_head as usize;
        self.roots[idx] = self.current_root;
        self.roots_head = ((idx + 1) % ROOT_HISTORY_SIZE) as u8;
        self.current_root = root;
    }
}
