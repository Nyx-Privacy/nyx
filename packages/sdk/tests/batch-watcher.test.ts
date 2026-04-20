/**
 * Phase 4 TS glue — BatchResults account decoder.
 *
 * Mirrors `programs/matching_engine/src/state/batch_results.rs` layout.
 * We construct a synthetic account buffer that matches the Rust struct
 * byte-for-byte, then assert the decoder extracts the right fields.
 *
 * This lets a client (block explorer, UI, tests) watch the per-market
 * BatchResults PDA and decode the latest batch stats + the MatchResult
 * ring without pulling in an IDL / anchor.
 */

import { describe, expect, it } from "vitest";

import {
  BATCH_RESULTS_CAPACITY,
  FEE_ACCUMULATOR_COUNT,
  FEE_ACCUMULATOR_SIZE,
  MATCH_RESULT_SIZE,
  decodeBatchResults,
  type MatchResultRecord,
} from "../src/batch/inclusion-proof.js";

function u8(n: number): number {
  return n & 0xff;
}

function writeU64LE(buf: Uint8Array, off: number, v: bigint): void {
  new DataView(buf.buffer, buf.byteOffset + off, 8).setBigUint64(0, v, true);
}

function writeBytes(buf: Uint8Array, off: number, src: Uint8Array): void {
  buf.set(src, off);
}

function filled32(n: number): Uint8Array {
  const b = new Uint8Array(32);
  b.fill(u8(n));
  return b;
}

/** Build a synthetic BatchResults account buffer. */
function synthesizeAccount(opts: {
  market: Uint8Array;
  lastInclusionRoot: Uint8Array;
  lastBatchSlot: bigint;
  lastMatchCount: bigint;
  lastClearingPrice: bigint;
  lastPythTwap: bigint;
  lastCircuitBreakerTripped: boolean;
  writeCursor: bigint;
  nextMatchId: bigint;
  matches: MatchResultRecord[];
  bump: number;
}): Uint8Array {
  const fullLen =
    8 + // disc
    32 + // market
    32 + // inclusion root
    8 + // batch slot
    8 + // match count
    8 + // clearing price
    8 + // pyth twap
    1 + // cb flag
    7 + // padding_a
    8 + // write cursor
    8 + // next match id
    MATCH_RESULT_SIZE * BATCH_RESULTS_CAPACITY +
    FEE_ACCUMULATOR_SIZE * FEE_ACCUMULATOR_COUNT +
    1 + // bump
    7; // padding_b
  const buf = new Uint8Array(fullLen);
  // Anchor disc — exact bytes don't matter for the decoder (it skips them).
  buf.set(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), 0);
  let off = 8;
  writeBytes(buf, off, opts.market);
  off += 32;
  writeBytes(buf, off, opts.lastInclusionRoot);
  off += 32;
  writeU64LE(buf, off, opts.lastBatchSlot);
  off += 8;
  writeU64LE(buf, off, opts.lastMatchCount);
  off += 8;
  writeU64LE(buf, off, opts.lastClearingPrice);
  off += 8;
  writeU64LE(buf, off, opts.lastPythTwap);
  off += 8;
  buf[off] = opts.lastCircuitBreakerTripped ? 1 : 0;
  off += 1 + 7;
  writeU64LE(buf, off, opts.writeCursor);
  off += 8;
  writeU64LE(buf, off, opts.nextMatchId);
  off += 8;
  for (let i = 0; i < BATCH_RESULTS_CAPACITY; i++) {
    const m = opts.matches[i];
    if (m) {
      let mo = off;
      writeBytes(buf, mo, m.noteBuyer); mo += 32;
      writeBytes(buf, mo, m.noteSeller); mo += 32;
      writeBytes(buf, mo, m.noteEcommitment); mo += 32;
      writeBytes(buf, mo, m.noteFcommitment); mo += 32;
      writeBytes(buf, mo, m.ownerBuyer); mo += 32;
      writeBytes(buf, mo, m.ownerSeller); mo += 32;
      writeBytes(buf, mo, m.userCommitmentBuyer); mo += 32;
      writeBytes(buf, mo, m.userCommitmentSeller); mo += 32;
      writeU64LE(buf, mo, m.buyerNoteValue); mo += 8;
      writeU64LE(buf, mo, m.sellerNoteValue); mo += 8;
      writeU64LE(buf, mo, m.baseAmt); mo += 8;
      writeU64LE(buf, mo, m.quoteAmt); mo += 8;
      writeU64LE(buf, mo, m.buyerChangeAmt); mo += 8;
      writeU64LE(buf, mo, m.sellerChangeAmt); mo += 8;
      writeU64LE(buf, mo, m.buyerFeeAmt); mo += 8;
      writeU64LE(buf, mo, m.sellerFeeAmt); mo += 8;
      writeBytes(buf, mo, m.buyerRelockOrderId); mo += 16;
      writeU64LE(buf, mo, m.buyerRelockExpiry); mo += 8;
      writeBytes(buf, mo, m.sellerRelockOrderId); mo += 16;
      writeU64LE(buf, mo, m.sellerRelockExpiry); mo += 8;
      writeU64LE(buf, mo, m.price); mo += 8;
      writeU64LE(buf, mo, m.pythAtMatch); mo += 8;
      writeU64LE(buf, mo, m.batchSlot); mo += 8;
      writeU64LE(buf, mo, m.matchId); mo += 8;
      buf[mo] = m.status;
    }
    off += MATCH_RESULT_SIZE;
  }
  // Zero fee_accumulators — they live inline after results. The decoder
  // reads them; tests that want non-zero accumulators can write them directly.
  off += FEE_ACCUMULATOR_SIZE * FEE_ACCUMULATOR_COUNT;
  buf[off] = opts.bump;
  return buf;
}

describe("Phase 4 — BatchResults decoder", () => {
  it("[decode_headers] extracts market + stats + cursor fields", () => {
    const market = filled32(9);
    const root = filled32(42);
    const raw = synthesizeAccount({
      market,
      lastInclusionRoot: root,
      lastBatchSlot: 1_234n,
      lastMatchCount: 2n,
      lastClearingPrice: 146n,
      lastPythTwap: 150n,
      lastCircuitBreakerTripped: false,
      writeCursor: 5n,
      nextMatchId: 7n,
      matches: [],
      bump: 251,
    });
    const view = decodeBatchResults(raw);
    expect(view.market).toEqual(market);
    expect(view.lastInclusionRoot).toEqual(root);
    expect(view.lastBatchSlot).toBe(1_234n);
    expect(view.lastMatchCount).toBe(2n);
    expect(view.lastClearingPrice).toBe(146n);
    expect(view.lastPythTwap).toBe(150n);
    expect(view.lastCircuitBreakerTripped).toBe(false);
    expect(view.writeCursor).toBe(5n);
    expect(view.nextMatchId).toBe(7n);
    expect(view.bump).toBe(251);
    expect(view.results.length).toBe(BATCH_RESULTS_CAPACITY);
  });

  it("[decode_results_ring] extracts filled MatchResult entries", () => {
    const fakeMatch: MatchResultRecord = {
      noteBuyer: filled32(1),
      noteSeller: filled32(2),
      noteEcommitment: filled32(0),
      noteFcommitment: filled32(0),
      ownerBuyer: filled32(3),
      ownerSeller: filled32(4),
      userCommitmentBuyer: filled32(5),
      userCommitmentSeller: filled32(6),
      buyerNoteValue: 14_600n,
      sellerNoteValue: 100n,
      baseAmt: 100n,
      quoteAmt: 14_600n,
      buyerChangeAmt: 0n,
      sellerChangeAmt: 0n,
      buyerFeeAmt: 0n,
      sellerFeeAmt: 0n,
      buyerRelockOrderId: new Uint8Array(16),
      buyerRelockExpiry: 0n,
      sellerRelockOrderId: new Uint8Array(16),
      sellerRelockExpiry: 0n,
      price: 146n,
      pythAtMatch: 150n,
      batchSlot: 99n,
      matchId: 17n,
      status: 1,
    };
    const raw = synthesizeAccount({
      market: filled32(0),
      lastInclusionRoot: filled32(0),
      lastBatchSlot: 0n,
      lastMatchCount: 1n,
      lastClearingPrice: 146n,
      lastPythTwap: 150n,
      lastCircuitBreakerTripped: false,
      writeCursor: 1n,
      nextMatchId: 18n,
      matches: [fakeMatch],
      bump: 254,
    });
    const view = decodeBatchResults(raw);
    const m = view.results[0];
    expect(m.noteBuyer).toEqual(fakeMatch.noteBuyer);
    expect(m.noteSeller).toEqual(fakeMatch.noteSeller);
    expect(m.ownerBuyer).toEqual(fakeMatch.ownerBuyer);
    expect(m.ownerSeller).toEqual(fakeMatch.ownerSeller);
    expect(m.baseAmt).toBe(100n);
    expect(m.quoteAmt).toBe(14_600n);
    expect(m.price).toBe(146n);
    expect(m.pythAtMatch).toBe(150n);
    expect(m.batchSlot).toBe(99n);
    expect(m.matchId).toBe(17n);
    expect(m.status).toBe(1);
    expect(m.buyerNoteValue).toBe(14_600n);
    expect(m.sellerNoteValue).toBe(100n);
    expect(m.buyerChangeAmt).toBe(0n);
    expect(m.sellerChangeAmt).toBe(0n);
    expect(m.buyerFeeAmt).toBe(0n);
    expect(m.sellerFeeAmt).toBe(0n);
    expect(m.noteEcommitment).toEqual(filled32(0));
    expect(m.noteFcommitment).toEqual(filled32(0));
    // Slot 1 is empty (status=0).
    expect(view.results[1].status).toBe(0);
    // Fee accumulators default to zero.
    expect(view.feeAccumulators.length).toBe(FEE_ACCUMULATOR_COUNT);
    expect(view.feeAccumulators[0].accumulatedFees).toBe(0n);
    expect(view.feeAccumulators[0].flushedCommitment).toEqual(filled32(0));
  });

  it("[decode_match_result_phase5_partial_fill_with_fees] carries change + fee + relock fields", () => {
    const fakeMatch: MatchResultRecord = {
      noteBuyer: filled32(0xA1),
      noteSeller: filled32(0xB1),
      noteEcommitment: filled32(0xE1),
      noteFcommitment: filled32(0),
      ownerBuyer: filled32(0x11),
      ownerSeller: filled32(0x22),
      userCommitmentBuyer: filled32(0x33),
      userCommitmentSeller: filled32(0x44),
      buyerNoteValue: 10_000n,
      sellerNoteValue: 100n,
      baseAmt: 50n,
      quoteAmt: 5_000n,
      buyerChangeAmt: 4_970n,
      sellerChangeAmt: 0n,
      buyerFeeAmt: 30n,
      sellerFeeAmt: 0n,
      buyerRelockOrderId: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
      buyerRelockExpiry: 9_999n,
      sellerRelockOrderId: new Uint8Array(16),
      sellerRelockExpiry: 0n,
      price: 100n,
      pythAtMatch: 101n,
      batchSlot: 123n,
      matchId: 7n,
      status: 1,
    };
    const raw = synthesizeAccount({
      market: filled32(0),
      lastInclusionRoot: filled32(0),
      lastBatchSlot: 0n,
      lastMatchCount: 1n,
      lastClearingPrice: 100n,
      lastPythTwap: 101n,
      lastCircuitBreakerTripped: false,
      writeCursor: 1n,
      nextMatchId: 8n,
      matches: [fakeMatch],
      bump: 253,
    });
    const view = decodeBatchResults(raw);
    const m = view.results[0];
    expect(m.buyerChangeAmt).toBe(4_970n);
    expect(m.buyerFeeAmt).toBe(30n);
    expect(m.noteEcommitment).toEqual(filled32(0xE1));
    expect(m.noteFcommitment).toEqual(filled32(0));
    expect(m.buyerRelockExpiry).toBe(9_999n);
    expect(m.buyerRelockOrderId[0]).toBe(1);
    expect(m.buyerRelockOrderId[15]).toBe(16);
  });

  it("[decode_cb_tripped_batch] circuit-breaker flag decodes true", () => {
    const raw = synthesizeAccount({
      market: filled32(0),
      lastInclusionRoot: filled32(0),
      lastBatchSlot: 42n,
      lastMatchCount: 0n,
      lastClearingPrice: 0n,
      lastPythTwap: 100n,
      lastCircuitBreakerTripped: true,
      writeCursor: 0n,
      nextMatchId: 0n,
      matches: [],
      bump: 255,
    });
    const view = decodeBatchResults(raw);
    expect(view.lastCircuitBreakerTripped).toBe(true);
    expect(view.lastMatchCount).toBe(0n);
    expect(view.lastClearingPrice).toBe(0n);
  });

  it("[decode_length_mismatch_throws] wrong-length buffer is rejected", () => {
    expect(() => decodeBatchResults(new Uint8Array(100))).toThrow(
      /batch_results length mismatch/,
    );
  });
});
