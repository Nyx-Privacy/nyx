/**
 * Offset-based Trading Key rotation (Umbra pattern).
 *
 * Rotating the Trading Key:
 *   1. Increment `tradingOffset`.
 *   2. Derive the new Ed25519 key: `deriveTradingKeyAtOffset(seed, newOffset)`.
 *   3. Root Key calls `configure_access` with the new pubkey, optionally removing the old.
 *
 * The Root Key, Spending Key, and Viewing Key are NOT affected by this rotation.
 */

import { deriveTradingKeyAtOffset } from "./key-generators.js";

export function rotateTradingKey(seed: Uint8Array, currentOffset: bigint) {
  const nextOffset = currentOffset + 1n;
  const next = deriveTradingKeyAtOffset(seed, nextOffset);
  return { offset: nextOffset, keypair: next };
}
