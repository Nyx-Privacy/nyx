//! Shared helpers for integration tests.
#![allow(dead_code)]
// Individual integration-test binaries pull in a subset of these helpers
// (e.g. set_protocol_config.rs only needs `repo_root` + `anchor_disc`).
// Cargo compiles each test crate independently and warns about the others;
// the allow keeps `-D warnings` happy without sprinkling per-item allows.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

pub fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

pub fn fr_to_dec(fr: &Fr) -> String {
    let bi = fr.into_bigint();
    let bytes = bi.to_bytes_be();
    let mut s = num_bigint_decstring(&bytes);
    if s.is_empty() {
        s = "0".to_string();
    }
    s
}

fn num_bigint_decstring(bytes: &[u8]) -> String {
    let mut n: Vec<u32> = Vec::new();
    for &b in bytes {
        let mut carry = b as u64;
        for limb in n.iter_mut() {
            let v = (*limb as u64) * 256 + carry;
            *limb = (v % 1_000_000_000) as u32;
            carry = v / 1_000_000_000;
        }
        while carry > 0 {
            n.push((carry % 1_000_000_000) as u32);
            carry /= 1_000_000_000;
        }
    }
    if n.is_empty() {
        return "0".into();
    }
    let mut out = String::new();
    for (i, limb) in n.iter().rev().enumerate() {
        if i == 0 {
            out.push_str(&limb.to_string());
        } else {
            out.push_str(&format!("{:09}", limb));
        }
    }
    out
}

pub fn dec_to_be32(s: &str) -> [u8; 32] {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut out = [0u8; 32];
    let mut byte_idx = 32;
    while !digits.is_empty() && byte_idx > 0 {
        let mut rem: u32 = 0;
        let mut new_digits: Vec<u8> = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + *d as u32;
            let q = cur / 256;
            rem = cur % 256;
            if !(new_digits.is_empty() && q == 0) {
                new_digits.push(q as u8);
            }
        }
        byte_idx -= 1;
        out[byte_idx] = rem as u8;
        digits = new_digits;
    }
    out
}

pub fn groth16_g1_bytes(v: &serde_json::Value) -> [u8; 64] {
    let x = dec_to_be32(v[0].as_str().unwrap());
    let y = dec_to_be32(v[1].as_str().unwrap());
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&x);
    out[32..64].copy_from_slice(&y);
    out
}

pub fn groth16_g2_bytes(v: &serde_json::Value) -> [u8; 128] {
    let x0 = dec_to_be32(v[0][0].as_str().unwrap());
    let x1 = dec_to_be32(v[0][1].as_str().unwrap());
    let y0 = dec_to_be32(v[1][0].as_str().unwrap());
    let y1 = dec_to_be32(v[1][1].as_str().unwrap());
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&x1);
    out[32..64].copy_from_slice(&x0);
    out[64..96].copy_from_slice(&y1);
    out[96..128].copy_from_slice(&y0);
    out
}

pub fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    const P_BYTES: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&point[0..32]);
    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..64]);
    let y_neg = sub_be(&P_BYTES, &y);
    out[32..64].copy_from_slice(&y_neg);
    out
}

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

pub struct ProofBytes {
    pub pi_a: [u8; 64],
    pub pi_b: [u8; 128],
    pub pi_c: [u8; 64],
}

/// Build input.json in `tmp`, run snarkjs fullprove, return parsed (proof, public[]).
pub fn snarkjs_fullprove(
    input_json: &str,
    circuit_build_dir: &std::path::Path,
    tmp_dir: &std::path::Path,
) -> (ProofBytes, Vec<[u8; 32]>) {
    fs::create_dir_all(tmp_dir).unwrap();
    let input_path = tmp_dir.join("input.json");
    let proof_path = tmp_dir.join("proof.json");
    let public_path = tmp_dir.join("public.json");
    fs::write(&input_path, input_json).unwrap();

    let wasm = circuit_build_dir.join("circuit_js/circuit.wasm");
    let zkey = circuit_build_dir.join("circuit_final.zkey");
    let root = repo_root();
    let snarkjs = root.join("node_modules/.bin/snarkjs");
    assert!(snarkjs.exists(), "snarkjs missing — run `npm install`");

    let status = Command::new(&snarkjs)
        .arg("groth16")
        .arg("fullprove")
        .arg(&input_path)
        .arg(&wasm)
        .arg(&zkey)
        .arg(&proof_path)
        .arg(&public_path)
        .status()
        .expect("failed to spawn snarkjs");
    assert!(status.success(), "snarkjs fullprove failed");

    let proof_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();
    let public_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&public_path).unwrap()).unwrap();

    let pi_a = groth16_g1_bytes(&proof_json["pi_a"]);
    let pi_b = groth16_g2_bytes(&proof_json["pi_b"]);
    let pi_c = groth16_g1_bytes(&proof_json["pi_c"]);
    let pi_a_negated = negate_g1(&pi_a);

    let public_inputs: Vec<[u8; 32]> = public_json
        .as_array()
        .unwrap()
        .iter()
        .map(|v| dec_to_be32(v.as_str().unwrap()))
        .collect();

    (
        ProofBytes {
            pi_a: pi_a_negated,
            pi_b,
            pi_c,
        },
        public_inputs,
    )
}

/// Anchor global instruction discriminator = first 8 bytes of sha256("global:<name>").
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
