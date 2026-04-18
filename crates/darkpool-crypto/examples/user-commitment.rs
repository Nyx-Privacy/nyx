//! Helper CLI used by the TS parity test to emit a User Commitment as hex.
//!
//! Usage:
//!   user-commitment <root_pubkey_hex_64> <spending_fr_dec> <viewing_fr_dec> \
//!                   <r0_dec> <r1_dec> <r2_dec>

use ark_bn254::Fr;
use ark_ff::PrimeField;
use darkpool_crypto::field::fr_to_be_bytes;
use darkpool_crypto::user_commitment::{user_commitment_from_keys, UserCommitmentInputs};

fn dec_to_fr(s: &str) -> Fr {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut be = Vec::new();
    while !digits.is_empty() {
        let mut rem: u32 = 0;
        let mut new_digits = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + *d as u32;
            let q = cur / 256;
            rem = cur % 256;
            if !(new_digits.is_empty() && q == 0) {
                new_digits.push(q as u8);
            }
        }
        be.insert(0, rem as u8);
        digits = new_digits;
    }
    if be.is_empty() {
        be.push(0);
    }
    Fr::from_be_bytes_mod_order(&be)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "usage: user-commitment <root_pub_hex64> <sk_dec> <vk_dec> <r0_dec> <r1_dec> <r2_dec>"
        );
        std::process::exit(2);
    }
    let root_bytes = hex::decode(&args[1]).expect("hex root pubkey");
    assert_eq!(root_bytes.len(), 32);
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_bytes);

    let inputs = UserCommitmentInputs {
        root_key_pubkey: root,
        spending_key: dec_to_fr(&args[2]),
        viewing_key: dec_to_fr(&args[3]),
        r0: dec_to_fr(&args[4]),
        r1: dec_to_fr(&args[5]),
        r2: dec_to_fr(&args[6]),
    };
    let fr = user_commitment_from_keys(&inputs).unwrap();
    println!("{}", hex::encode(fr_to_be_bytes(&fr)));
}
