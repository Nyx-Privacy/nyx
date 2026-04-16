/**
 * UTXO note construction + commitment.
 *
 * Must produce byte-identical Poseidon output to:
 *   - crates/darkpool-crypto (Rust, via light-poseidon)
 *   - circuits/valid_spend/circuit.circom (circom, via circomlib's poseidon)
 *
 * We use circomlibjs — the JavaScript counterpart of circomlib — which the
 * snarkjs/circom stack uses internally. It is byte-compatible with light-poseidon
 * when both are run with BN254 + CIRCOM parameters.
 */

import { buildPoseidon } from "circomlibjs";
import { bn254ToBE32 } from "../keys/key-generators.js";

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & {
  F: { toObject: (x: Uint8Array) => bigint };
};

let cached: PoseidonFn | null = null;
async function getPoseidon(): Promise<PoseidonFn> {
  if (cached) return cached;
  const p = await buildPoseidon();
  const fn = ((inputs: bigint[]) => p(inputs.map((i) => p.F.e(i)))) as PoseidonFn;
  fn.F = p.F;
  cached = fn;
  return fn;
}

/** Hash an array of field elements (each in [0, BN254_r)) -> 32-byte BE result. */
export async function poseidonHashBytesBE(inputs: bigint[]): Promise<Uint8Array> {
  const p = await getPoseidon();
  const packed = p(inputs);
  // circomlibjs returns a Montgomery-form Uint8Array. Convert to canonical bigint.
  const out = p.F.toObject(packed);
  return bn254ToBE32(out);
}

/** Split a 32-byte Solana pubkey into [lo_u128, hi_u128] bigints. */
export function pubkeyToFrPair(pk: Uint8Array): [bigint, bigint] {
  if (pk.length !== 32) throw new Error("pubkey must be 32 bytes");
  let hi = 0n;
  for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(pk[i]);
  let lo = 0n;
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(pk[i]);
  return [lo, hi];
}

export interface Note {
  tokenMint: Uint8Array;        // 32 bytes
  amount: bigint;
  ownerCommitment: bigint;
  nonce: bigint;
  blindingR: bigint;
}

/** Compute the 32-byte BE note commitment. */
export async function noteCommitment(note: Note): Promise<Uint8Array> {
  const [lo, hi] = pubkeyToFrPair(note.tokenMint);
  return poseidonHashBytesBE([lo, hi, note.amount, note.ownerCommitment, note.nonce, note.blindingR]);
}

export async function ownerCommitment(spendingKey: bigint, blinding: bigint): Promise<bigint> {
  const p = await getPoseidon();
  const packed = p([spendingKey, blinding]);
  return p.F.toObject(packed);
}

export async function nullifier(spendingKey: bigint, commitmentBE: Uint8Array): Promise<Uint8Array> {
  if (commitmentBE.length !== 32) throw new Error("commitment must be 32 bytes");
  let cBig = 0n;
  for (const b of commitmentBE) cBig = (cBig << 8n) | BigInt(b);
  const p = await getPoseidon();
  const packed = p([spendingKey, cBig]);
  return bn254ToBE32(p.F.toObject(packed));
}
