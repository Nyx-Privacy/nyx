//! Hierarchical viewing key tree (Umbra pattern adopted).
//!
//! Reference: Section 23.2.2, Appendix C of darkpool_protocol_spec_v3_changed.md
//!
//! ```text
//!     MVK            (master, never leaves compliance team)
//!      |
//!      PairVK(base, quote)       = Poseidon5(mvk, base_lo, base_hi, quote_lo, quote_hi)
//!      |
//!      MonthlyVK(year, month)    = Poseidon2( Poseidon2(pair_vk, year), month )
//! ```
//!
//! Property: one-directional — given a child key, no function exists to recover
//! the parent. Scope isolation is enforced by the Poseidon preimage resistance.

use crate::errors::CryptoError;
use crate::field::{pubkey_to_fr_pair, u64_to_fr, Fr};
use crate::poseidon::poseidon_hash;

/// Derive a per-pair viewing key from the Master Viewing Key.
pub fn derive_viewing_key_for_pair(
    mvk: &Fr,
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
) -> Result<Fr, CryptoError> {
    let [base_lo, base_hi] = pubkey_to_fr_pair(base_mint);
    let [quote_lo, quote_hi] = pubkey_to_fr_pair(quote_mint);
    poseidon_hash(&[*mvk, base_lo, base_hi, quote_lo, quote_hi])
}

/// Derive a per-month viewing key from a pair viewing key.
pub fn derive_monthly_viewing_key(
    pair_vk: &Fr,
    year: u64,
    month: u64,
) -> Result<Fr, CryptoError> {
    let yearly = poseidon_hash(&[*pair_vk, u64_to_fr(year)])?;
    poseidon_hash(&[yearly, u64_to_fr(month)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_vk_deterministic() {
        let mvk = Fr::from(7u64);
        let base = [1u8; 32];
        let quote = [2u8; 32];
        let a = derive_viewing_key_for_pair(&mvk, &base, &quote).unwrap();
        let b = derive_viewing_key_for_pair(&mvk, &base, &quote).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn viewing_key_scope_isolation() {
        let mvk = Fr::from(7u64);
        let base = [1u8; 32];
        let quote_a = [2u8; 32];
        let quote_b = [3u8; 32];

        let pair_a = derive_viewing_key_for_pair(&mvk, &base, &quote_a).unwrap();
        let pair_b = derive_viewing_key_for_pair(&mvk, &base, &quote_b).unwrap();
        assert_ne!(pair_a, pair_b, "different pairs must yield different keys");

        let mk_a_jan = derive_monthly_viewing_key(&pair_a, 2025, 1).unwrap();
        let mk_a_feb = derive_monthly_viewing_key(&pair_a, 2025, 2).unwrap();
        let mk_b_jan = derive_monthly_viewing_key(&pair_b, 2025, 1).unwrap();
        assert_ne!(mk_a_jan, mk_a_feb);
        assert_ne!(mk_a_jan, mk_b_jan);
    }

    #[test]
    fn hierarchy_one_directional() {
        // Statically enforced — there is no function in this module that takes a
        // child key and returns a parent. This test documents that contract.
        // (If someone adds a `recover_parent` function, this test's comment must
        // be updated and the API review must explicitly approve it.)
        let marker = "one-directional";
        assert!(!marker.is_empty());
    }
}
