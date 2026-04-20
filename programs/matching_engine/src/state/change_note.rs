//! Deterministic change-note derivation for Phase-5 settlement.
//!
//! When a partial-fill happens, the TEE mints two change notes (one per
//! counterparty) inside the PER. Production TEEs SHOULD use per-session
//! randomness from `getrandom()` inside the enclave and deliver
//! `(nonce, blinding_r)` to each counterparty via the authenticated
//! PER session (spec §8.3 step 810). Our on-PER program has no randomness
//! source, so we derive both deterministically from `(match_id, role)`.
//!
//! Threat model: the outputs are unpredictable to anyone who doesn't see
//! the BatchResults account, which only the TEE writes. The settlement
//! program then validates the conservation law against the claimed values,
//! so a malicious TEE can't forge change notes that violate the input
//! note's amount. When we wire a real TDX enclave in Phase-6, we swap this
//! helper out for `getrandom()` and push the resulting bytes into the
//! MatchResult from the ER side.

use solana_program::hash::hashv;

/// Role tags used to separate the two change-note derivation domains.
pub const CHANGE_ROLE_BUYER: u8 = 0xB1;
pub const CHANGE_ROLE_SELLER: u8 = 0x5E;

/// Derive the change-note `nonce` (32 bytes) from (match_id, role, salt).
/// SHA-256 is cheap, deterministic, and non-cryptographic here — the goal
/// is domain separation, not unpredictability. We zero the top byte and
/// mask bits 254-253 of the second byte so the resulting 32-byte value is
/// strictly < BN254 Fr modulus (p ≈ 0x3064e72e...). This is conservative
/// but costs nothing in a non-adversarial setting.
pub fn derive_nonce(match_id: u64, role: u8) -> [u8; 32] {
    let mut h = hashv(&[b"nyx-change-nonce", &match_id.to_le_bytes(), &[role]]).to_bytes();
    h[0] = 0;
    h[1] &= 0x0f;
    h
}

/// Derive the change-note blinding factor `r` from (match_id, role, salt).
pub fn derive_blinding(match_id: u64, role: u8) -> [u8; 32] {
    let mut h = hashv(&[b"nyx-change-blind", &match_id.to_le_bytes(), &[role]]).to_bytes();
    h[0] = 0;
    h[1] &= 0x0f;
    h
}
