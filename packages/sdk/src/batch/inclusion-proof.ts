/**
 * Client-side helpers for the per-market Phase-4 BatchResults PDA:
 *   - decode the fixed-layout account data.
 *   - compute & verify the SHA-256 Merkle inclusion root over the set of
 *     `order_inclusion_commitment`s active at start-of-batch.
 *
 * The on-chain reference implementation lives in
 * `programs/matching_engine/src/instructions/run_batch.rs::merkle_root_sha256`.
 * The layout must be kept in lock-step with
 * `programs/matching_engine/src/state/batch_results.rs`.
 */

import { createHash } from "node:crypto";

// ---------- SHA-256 Merkle (mirrors on-chain run_batch.rs) ----------

/** sha256(a || b) — returns raw 32 bytes. */
export function sha256Hash(a: Uint8Array, b: Uint8Array): Uint8Array {
  const h = createHash("sha256");
  h.update(a);
  h.update(b);
  return new Uint8Array(h.digest());
}

/** Build the batch inclusion Merkle root exactly the way `run_batch` does:
 *   - empty → all-zero 32 bytes.
 *   - pad level to next power of two by duplicating the last leaf.
 *   - parent = sha256(left || right).
 */
export function computeInclusionRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return new Uint8Array(32);
  let level: Uint8Array[] = leaves.map((l) => copyBytes(l));
  let target = 1;
  while (target < level.length) target *= 2;
  while (level.length < target) {
    level.push(copyBytes(level[level.length - 1]));
  }
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256Hash(level[i], level[i + 1]));
    }
    level = next;
  }
  return level[0];
}

/** Produce the authentication path for `index` inside `leaves`, assuming the
 *  same pad-last-to-power-of-two layout used to build the root.
 *  Returns siblings bottom-up. */
export function computeInclusionPath(
  leaves: Uint8Array[],
  index: number,
): { siblings: Uint8Array[]; pathIndices: number[] } {
  if (leaves.length === 0 || index < 0 || index >= leaves.length) {
    throw new Error("index out of range for inclusion path");
  }
  let level: Uint8Array[] = leaves.map((l) => copyBytes(l));
  let target = 1;
  while (target < level.length) target *= 2;
  while (level.length < target) {
    level.push(copyBytes(level[level.length - 1]));
  }

  const siblings: Uint8Array[] = [];
  const pathIndices: number[] = [];
  let idx = index;
  while (level.length > 1) {
    const sib = idx % 2 === 0 ? level[idx + 1] : level[idx - 1];
    siblings.push(sib);
    pathIndices.push(idx % 2);
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256Hash(level[i], level[i + 1]));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return { siblings, pathIndices };
}

/** Verify that `leaf` at `index` hashes up to `root` via `siblings`. */
export function verifyInclusionPath(
  leaf: Uint8Array,
  index: number,
  siblings: Uint8Array[],
  root: Uint8Array,
): boolean {
  let cur = copyBytes(leaf);
  let idx = index;
  for (const sib of siblings) {
    cur = idx % 2 === 0 ? sha256Hash(cur, sib) : sha256Hash(sib, cur);
    idx = Math.floor(idx / 2);
  }
  return equalBytes(cur, root);
}

// ---------- BatchResults account decoder ----------

/** Matches `BATCH_RESULTS_CAPACITY` in batch_results.rs. */
export const BATCH_RESULTS_CAPACITY = 16;

/** Number of `FeeAccumulator` slots on `BatchResults` (base + quote). */
export const FEE_ACCUMULATOR_COUNT = 2;

/** Size (bytes) of a single `FeeAccumulator`. Keep in sync with
 *  `fee_accumulator.rs`: 32 mint + 8 accumulated + 8 batch_slot + 32 flushed = 80. */
export const FEE_ACCUMULATOR_SIZE = 80;

/** Size (bytes) of a single MatchResult in the results ring. Keep in sync
 *  with match_result.rs (Phase 5):
 *    32 note_buyer + 32 note_seller + 32 note_e + 32 note_f
 *    + 32 owner_buyer + 32 owner_seller
 *    + 32 user_commitment_buyer + 32 user_commitment_seller
 *    + 8 buyer_note_value + 8 seller_note_value
 *    + 8 base_amt + 8 quote_amt
 *    + 8 buyer_change_amt + 8 seller_change_amt
 *    + 8 buyer_fee_amt + 8 seller_fee_amt
 *    + 16 buyer_relock_oid + 8 buyer_relock_expiry
 *    + 16 seller_relock_oid + 8 seller_relock_expiry
 *    + 8 price + 8 pyth_at_match + 8 batch_slot
 *    + 8 match_id + 1 status + 7 padding
 *    = 408. */
export const MATCH_RESULT_SIZE = 408;

/** All-zero 16-byte sentinel: `submit_order` rejects zero order-ids so this
 *  cannot collide with a legitimate active order. */
export const RELOCK_ORDER_ID_NONE = new Uint8Array(16);

export interface MatchResultRecord {
  noteBuyer: Uint8Array;
  noteSeller: Uint8Array;
  /** Buyer change-note commitment (Poseidon). All-zero = exact fill. */
  noteEcommitment: Uint8Array;
  /** Seller change-note commitment. All-zero = exact fill. */
  noteFcommitment: Uint8Array;
  ownerBuyer: Uint8Array;
  ownerSeller: Uint8Array;
  userCommitmentBuyer: Uint8Array;
  userCommitmentSeller: Uint8Array;
  buyerNoteValue: bigint;
  sellerNoteValue: bigint;
  baseAmt: bigint;
  quoteAmt: bigint;
  buyerChangeAmt: bigint;
  sellerChangeAmt: bigint;
  buyerFeeAmt: bigint;
  sellerFeeAmt: bigint;
  buyerRelockOrderId: Uint8Array;
  buyerRelockExpiry: bigint;
  sellerRelockOrderId: Uint8Array;
  sellerRelockExpiry: bigint;
  price: bigint;
  pythAtMatch: bigint;
  batchSlot: bigint;
  matchId: bigint;
  status: number;
}

export interface FeeAccumulatorRecord {
  tokenMint: Uint8Array;
  accumulatedFees: bigint;
  batchSlot: bigint;
  flushedCommitment: Uint8Array;
}

export interface BatchResultsView {
  market: Uint8Array;
  lastInclusionRoot: Uint8Array;
  lastBatchSlot: bigint;
  lastMatchCount: bigint;
  lastClearingPrice: bigint;
  lastPythTwap: bigint;
  lastCircuitBreakerTripped: boolean;
  writeCursor: bigint;
  nextMatchId: bigint;
  results: MatchResultRecord[];
  feeAccumulators: FeeAccumulatorRecord[];
  bump: number;
}

function readU64(buf: Uint8Array, off: number): bigint {
  return new DataView(buf.buffer, buf.byteOffset + off, 8).getBigUint64(0, true);
}

function readBytes(buf: Uint8Array, off: number, len: number): Uint8Array {
  return copyBytes(buf.subarray(off, off + len));
}

/** Copy a Uint8Array into a fresh ArrayBuffer-backed Uint8Array.
 *  Avoids TS strict ArrayBufferLike vs ArrayBuffer friction and produces
 *  a stable, detached copy the caller owns. */
function copyBytes(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

function decodeMatchResult(buf: Uint8Array, off: number): MatchResultRecord {
  const noteBuyer = readBytes(buf, off, 32); off += 32;
  const noteSeller = readBytes(buf, off, 32); off += 32;
  const noteEcommitment = readBytes(buf, off, 32); off += 32;
  const noteFcommitment = readBytes(buf, off, 32); off += 32;
  const ownerBuyer = readBytes(buf, off, 32); off += 32;
  const ownerSeller = readBytes(buf, off, 32); off += 32;
  const userCommitmentBuyer = readBytes(buf, off, 32); off += 32;
  const userCommitmentSeller = readBytes(buf, off, 32); off += 32;
  const buyerNoteValue = readU64(buf, off); off += 8;
  const sellerNoteValue = readU64(buf, off); off += 8;
  const baseAmt = readU64(buf, off); off += 8;
  const quoteAmt = readU64(buf, off); off += 8;
  const buyerChangeAmt = readU64(buf, off); off += 8;
  const sellerChangeAmt = readU64(buf, off); off += 8;
  const buyerFeeAmt = readU64(buf, off); off += 8;
  const sellerFeeAmt = readU64(buf, off); off += 8;
  const buyerRelockOrderId = readBytes(buf, off, 16); off += 16;
  const buyerRelockExpiry = readU64(buf, off); off += 8;
  const sellerRelockOrderId = readBytes(buf, off, 16); off += 16;
  const sellerRelockExpiry = readU64(buf, off); off += 8;
  const price = readU64(buf, off); off += 8;
  const pythAtMatch = readU64(buf, off); off += 8;
  const batchSlot = readU64(buf, off); off += 8;
  const matchId = readU64(buf, off); off += 8;
  const status = buf[off];
  return {
    noteBuyer,
    noteSeller,
    noteEcommitment,
    noteFcommitment,
    ownerBuyer,
    ownerSeller,
    userCommitmentBuyer,
    userCommitmentSeller,
    buyerNoteValue,
    sellerNoteValue,
    baseAmt,
    quoteAmt,
    buyerChangeAmt,
    sellerChangeAmt,
    buyerFeeAmt,
    sellerFeeAmt,
    buyerRelockOrderId,
    buyerRelockExpiry,
    sellerRelockOrderId,
    sellerRelockExpiry,
    price,
    pythAtMatch,
    batchSlot,
    matchId,
    status,
  };
}

function decodeFeeAccumulator(buf: Uint8Array, off: number): FeeAccumulatorRecord {
  const tokenMint = readBytes(buf, off, 32); off += 32;
  const accumulatedFees = readU64(buf, off); off += 8;
  const batchSlot = readU64(buf, off); off += 8;
  const flushedCommitment = readBytes(buf, off, 32);
  return { tokenMint, accumulatedFees, batchSlot, flushedCommitment };
}

/** Decode the raw account.data (including 8-byte anchor discriminator) into
 *  a BatchResultsView. Throws if data length is wrong. */
export function decodeBatchResults(accountData: Uint8Array): BatchResultsView {
  // 8 (disc) + 32 market + 32 inclusion_root + 8 last_batch_slot
  //         + 8 last_match_count + 8 last_clearing_price
  //         + 8 last_pyth_twap + 1 cb + 7 pad
  //         + 8 write_cursor + 8 next_match_id
  //         + results[] + 1 bump + 7 pad
  const expected =
    8 +   // disc
    32 +  // market
    32 +  // inclusion_root
    8 +   // last_batch_slot
    8 +   // last_match_count
    8 +   // last_clearing_price
    8 +   // last_pyth_twap
    1 +   // cb
    7 +   // padding_a
    8 +   // write_cursor
    8 +   // next_match_id
    MATCH_RESULT_SIZE * BATCH_RESULTS_CAPACITY +
    FEE_ACCUMULATOR_SIZE * FEE_ACCUMULATOR_COUNT +
    1 +   // bump
    7;    // padding_b
  if (accountData.length !== expected) {
    throw new Error(
      `batch_results length mismatch: got ${accountData.length}, expected ${expected}`,
    );
  }
  let off = 8; // skip anchor discriminator
  const market = readBytes(accountData, off, 32);
  off += 32;
  const lastInclusionRoot = readBytes(accountData, off, 32);
  off += 32;
  const lastBatchSlot = readU64(accountData, off);
  off += 8;
  const lastMatchCount = readU64(accountData, off);
  off += 8;
  const lastClearingPrice = readU64(accountData, off);
  off += 8;
  const lastPythTwap = readU64(accountData, off);
  off += 8;
  const lastCircuitBreakerTripped = accountData[off] === 1;
  off += 1 + 7; // skip pad
  const writeCursor = readU64(accountData, off);
  off += 8;
  const nextMatchId = readU64(accountData, off);
  off += 8;
  const results: MatchResultRecord[] = [];
  for (let i = 0; i < BATCH_RESULTS_CAPACITY; i++) {
    results.push(decodeMatchResult(accountData, off));
    off += MATCH_RESULT_SIZE;
  }
  const feeAccumulators: FeeAccumulatorRecord[] = [];
  for (let i = 0; i < FEE_ACCUMULATOR_COUNT; i++) {
    feeAccumulators.push(decodeFeeAccumulator(accountData, off));
    off += FEE_ACCUMULATOR_SIZE;
  }
  const bump = accountData[off];
  return {
    market,
    lastInclusionRoot,
    lastBatchSlot,
    lastMatchCount,
    lastClearingPrice,
    lastPythTwap,
    lastCircuitBreakerTripped,
    writeCursor,
    nextMatchId,
    results,
    feeAccumulators,
    bump,
  };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export { equalBytes as bytesEq };
