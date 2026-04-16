//! BN254 scalar field helpers.
//!
//! All Poseidon hashes used by the protocol operate on BN254 scalar field elements
//! (Fr). To move bytes in/out of the field we use big-endian 32-byte encoding — this
//! matches circomlib / snarkjs / solana-poseidon exactly.
//!
//! Pubkey handling: a Solana `Pubkey` is 32 bytes, but a single BN254 field element
//! can hold only ~254 bits. We therefore split the pubkey into two 128-bit halves
//! (`[lo_u128, hi_u128]`), each cast into an Fr. This matches Umbra's mint-address
//! handling and is the convention used in the VALID_SPEND circuit.

use crate::errors::CryptoError;
use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, PrimeField};

pub type Fr = ArkFr;

/// Big-endian byte length of a BN254 scalar field element.
pub const FR_BYTES: usize = 32;

/// Parse a 32-byte big-endian slice into a BN254 `Fr`. Returns `NotInField` if
/// the value is >= the field modulus.
pub fn fr_from_be_bytes(bytes: &[u8]) -> Result<Fr, CryptoError> {
    if bytes.len() != FR_BYTES {
        return Err(CryptoError::InvalidByteLength {
            expected: FR_BYTES,
            got: bytes.len(),
        });
    }
    // ark-ff from_be_bytes_mod_order never fails — it silently reduces.
    // We want strict "in-field" semantics for cross-env parity, so check first.
    let fr = Fr::from_be_bytes_mod_order(bytes);
    // Verify round-trip equals input (i.e., no reduction happened).
    let round = fr.into_bigint().to_bytes_be();
    // `round` may have leading zeros trimmed depending on impl; normalize to 32.
    let mut padded = [0u8; FR_BYTES];
    padded[FR_BYTES - round.len()..].copy_from_slice(&round);
    if padded.as_slice() != bytes {
        return Err(CryptoError::NotInField);
    }
    Ok(fr)
}

/// Serialize a `Fr` to 32 big-endian bytes (left-padded with zeros if needed).
pub fn fr_to_be_bytes(fr: &Fr) -> [u8; FR_BYTES] {
    let bi = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; FR_BYTES];
    out[FR_BYTES - bi.len()..].copy_from_slice(&bi);
    out
}

/// Reduce an arbitrary byte buffer into an `Fr` by interpreting as big-endian
/// integer and reducing mod BN254_r. Used for KDF outputs (blinding factors,
/// spending keys) where we want a uniform distribution over the field.
pub fn fr_from_uniform_bytes(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Split a 32-byte Solana pubkey into `[lo_u128_fr, hi_u128_fr]`.
/// `lo` = least-significant 16 bytes, `hi` = most-significant 16 bytes.
/// Each half is left-padded to 32 bytes when converted to Fr.
pub fn pubkey_to_fr_pair(pubkey_bytes: &[u8; 32]) -> [Fr; 2] {
    let hi = &pubkey_bytes[0..16];
    let lo = &pubkey_bytes[16..32];
    let mut hi_padded = [0u8; FR_BYTES];
    hi_padded[FR_BYTES - 16..].copy_from_slice(hi);
    let mut lo_padded = [0u8; FR_BYTES];
    lo_padded[FR_BYTES - 16..].copy_from_slice(lo);
    [
        Fr::from_be_bytes_mod_order(&lo_padded),
        Fr::from_be_bytes_mod_order(&hi_padded),
    ]
}

/// Convert a u64 amount to an Fr. u64 always fits safely in BN254_r.
pub fn u64_to_fr(x: u64) -> Fr {
    Fr::from(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_fr_bytes() {
        let fr = Fr::from(123_456_789u64);
        let bytes = fr_to_be_bytes(&fr);
        let parsed = fr_from_be_bytes(&bytes).unwrap();
        assert_eq!(fr, parsed);
    }

    #[test]
    fn pubkey_split_is_deterministic() {
        let pk = [7u8; 32];
        let [lo, hi] = pubkey_to_fr_pair(&pk);
        let [lo2, hi2] = pubkey_to_fr_pair(&pk);
        assert_eq!(lo, lo2);
        assert_eq!(hi, hi2);
        // lo and hi halves are not the same value given a uniform byte pattern but
        // for [7u8; 32] both halves equal the same 16-byte integer 0x0707..07, so
        // they will actually be equal. Use a distinguishing input for robustness:
        let mut pk2 = [0u8; 32];
        pk2[0] = 0xaa;
        pk2[31] = 0x55;
        let [lo3, hi3] = pubkey_to_fr_pair(&pk2);
        assert_ne!(lo3, hi3);
    }

    #[test]
    fn reject_out_of_field_bytes() {
        // Modulus is ~2^254, so 0xff..ff (2^256 - 1) is always out of field.
        let all_ones = [0xffu8; 32];
        assert!(fr_from_be_bytes(&all_ones).is_err());
    }
}
