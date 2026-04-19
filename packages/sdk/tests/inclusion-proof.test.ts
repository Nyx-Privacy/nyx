/**
 * Phase 4 TS glue — inclusion proof helpers.
 *
 * On-chain reference: `programs/matching_engine/src/instructions/run_batch.rs`
 * `merkle_root_sha256` (and integration test `test_inclusion_root_published`).
 * These TS tests re-implement the same SHA-256 Merkle logic and check that:
 *   1. The recomputed root matches the known on-chain fixture.
 *   2. The path generator produces siblings that verify for every leaf index.
 *   3. A tampered leaf fails verification.
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  computeInclusionPath,
  computeInclusionRoot,
  sha256Hash,
  verifyInclusionPath,
} from "../src/batch/inclusion-proof.js";

function sha(a: Uint8Array, b: Uint8Array): Uint8Array {
  const h = createHash("sha256");
  h.update(a);
  h.update(b);
  return new Uint8Array(h.digest());
}

function leaf(n: number): Uint8Array {
  const b = new Uint8Array(32);
  b.fill(n);
  return b;
}

describe("Phase 4 — inclusion root + path", () => {
  it("[root_empty_is_zero] empty leaves produce an all-zero root", () => {
    expect(computeInclusionRoot([])).toEqual(new Uint8Array(32));
  });

  it("[root_single_leaf_is_itself] one leaf is its own root (matches on-chain semantics)", () => {
    const l = leaf(42);
    expect(computeInclusionRoot([l])).toEqual(l);
  });

  it("[root_two_leaves_is_sha256_concat] root of 2 leaves is sha256(l0 || l1)", () => {
    const l0 = leaf(1);
    const l1 = leaf(2);
    expect(computeInclusionRoot([l0, l1])).toEqual(sha(l0, l1));
  });

  it("[root_three_leaves_pads_last] root of 3 leaves pads to 4 by duplicating the last", () => {
    // This mirrors the on-chain integration test exactly.
    const l0 = leaf(1);
    const l1 = leaf(2);
    const l2 = leaf(3);
    const h01 = sha(l0, l1);
    const h23 = sha(l2, l2);
    const expected = sha(h01, h23);
    expect(computeInclusionRoot([l0, l1, l2])).toEqual(expected);
  });

  it("[sha256Hash_deterministic] sha256Hash matches the raw sha256 of concatenated inputs", () => {
    const a = leaf(7);
    const b = leaf(11);
    const expected = new Uint8Array(
      createHash("sha256").update(a).update(b).digest(),
    );
    expect(sha256Hash(a, b)).toEqual(expected);
  });

  it("[inclusion_path_verifies_for_all_indices] generated paths verify for every leaf", () => {
    const leaves = [leaf(1), leaf(2), leaf(3), leaf(4), leaf(5)];
    const root = computeInclusionRoot(leaves);
    for (let i = 0; i < leaves.length; i++) {
      const { siblings } = computeInclusionPath(leaves, i);
      expect(verifyInclusionPath(leaves[i], i, siblings, root)).toBe(true);
    }
  });

  it("[inclusion_path_rejects_tampered_leaf] verification fails when the leaf is altered", () => {
    const leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];
    const root = computeInclusionRoot(leaves);
    const { siblings } = computeInclusionPath(leaves, 0);
    const tampered = leaf(99);
    expect(verifyInclusionPath(tampered, 0, siblings, root)).toBe(false);
  });

  it("[inclusion_path_rejects_wrong_index] verifying path for index X against index Y fails", () => {
    const leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];
    const root = computeInclusionRoot(leaves);
    const { siblings } = computeInclusionPath(leaves, 2);
    // Use siblings that fit index 2 but verify at index 1 — must fail.
    expect(verifyInclusionPath(leaves[2], 1, siblings, root)).toBe(false);
  });
});
