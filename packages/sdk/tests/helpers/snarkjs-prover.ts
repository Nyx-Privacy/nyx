/**
 * Phase-5 devnet E2E helper — thin shell-out wrapper around
 * `node_modules/.bin/snarkjs groth16 fullprove`.
 *
 *   TODO(Phase-6): replace this with a real `WebProverSuite` implementation
 *   in `packages/sdk/src/zk/` that either (a) imports the `snarkjs` npm
 *   library in-process or (b) targets the browser via WebAssembly. This
 *   helper lives under `tests/helpers/` specifically so the SDK itself
 *   stays dependency-free on a CLI binary.
 *
 * What this does, mirroring `programs/vault/tests/common/mod.rs::snarkjs_fullprove`:
 *
 *   1. Writes `input.json` (all fields as decimal strings) into a tmp dir.
 *   2. Invokes `snarkjs groth16 fullprove <input> <wasm> <zkey> <proof> <public>`.
 *   3. Parses `proof.json` into the on-chain verifier byte layout:
 *        - pi_a: [x||y] BE 64 bytes, with y NEGATED (groth16-solana convention).
 *        - pi_b: [x1||x0||y1||y0] BE 128 bytes (coord-pair swap).
 *        - pi_c: [x||y] BE 64 bytes.
 *   4. Parses `public.json` into a list of 32-byte BE field-element arrays.
 *
 * Output shape matches `Groth16OnChainProof` in `packages/sdk/src/idl/vault-client.ts`,
 * so the result can be passed straight into `buildCreateWalletInstruction` or
 * `buildWithdrawInstruction`.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import type { Groth16OnChainProof } from "../../src/idl/vault-client.js";

// BN254 base field modulus, big-endian. Used to compute -y mod P for pi_a.
// Mirrors the constant in programs/vault/tests/common/mod.rs::negate_g1.
const BN254_P = new Uint8Array([
  0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81,
  0x81, 0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20,
  0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
]);

export interface SnarkjsProofResult {
  proof: Groth16OnChainProof;
  publicInputsBE: Uint8Array[]; // each 32 bytes, big-endian
}

export interface SnarkjsFullProveOpts {
  /** Absolute path to the compiled `.wasm` (e.g. `circuits/build/<name>/circuit_js/circuit.wasm`). */
  circuitWasmPath: string;
  /** Absolute path to the compiled `.zkey` (e.g. `circuits/build/<name>/circuit_final.zkey`). */
  circuitZkeyPath: string;
  /** Repo root — used to find `node_modules/.bin/snarkjs`. */
  repoRoot: string;
  /** Optional tmp dir; defaults to `<os.tmpdir>/nyx-snarkjs-<random>`. */
  tmpDir?: string;
}

/**
 * Shell out to snarkjs and return (proof, publicInputs) in the exact byte
 * layout the on-chain groth16-solana verifier expects.
 *
 * `inputs` is the circuit-witness object: every field MUST be a decimal
 * string (or an array of decimal strings). This mirrors the `format!`
 * blocks in the Rust tests — keep the keys in lock-step with the circuit's
 * `signal input` declarations.
 */
export function snarkjsFullProve(
  inputs: Record<string, string | string[]>,
  opts: SnarkjsFullProveOpts,
): SnarkjsProofResult {
  const tmp =
    opts.tmpDir ?? join(tmpdir(), `nyx-snarkjs-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  mkdirSync(tmp, { recursive: true });
  const inputPath = join(tmp, "input.json");
  const proofPath = join(tmp, "proof.json");
  const publicPath = join(tmp, "public.json");

  writeFileSync(inputPath, JSON.stringify(inputs));

  const snarkjsBin = resolve(opts.repoRoot, "node_modules/.bin/snarkjs");
  execFileSync(
    snarkjsBin,
    [
      "groth16",
      "fullprove",
      inputPath,
      opts.circuitWasmPath,
      opts.circuitZkeyPath,
      proofPath,
      publicPath,
    ],
    { stdio: "pipe" },
  );

  const proofJson = JSON.parse(readFileSync(proofPath, "utf8"));
  const publicJson = JSON.parse(readFileSync(publicPath, "utf8"));

  const piA = groth16G1Bytes(proofJson.pi_a);
  const piB = groth16G2Bytes(proofJson.pi_b);
  const piC = groth16G1Bytes(proofJson.pi_c);

  const piANeg = negateG1(piA);

  const publicInputsBE: Uint8Array[] = publicJson.map((s: string) =>
    decToBe32(s),
  );

  try {
    rmSync(tmp, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }

  return {
    proof: { piA: piANeg, piB, piC },
    publicInputsBE,
  };
}

// ─── Encoding helpers — byte-for-byte mirror of programs/vault/tests/common/mod.rs ───

function decToBe32(s: string): Uint8Array {
  // Pure long-division from decimal digits → 256 base.
  if (!/^\d+$/.test(s)) throw new Error(`non-decimal: ${s}`);
  let digits = Array.from(s, (c) => c.charCodeAt(0) - 48);
  const out = new Uint8Array(32);
  let byteIdx = 32;
  while (digits.length > 0 && byteIdx > 0) {
    let rem = 0;
    const next: number[] = [];
    for (const d of digits) {
      const cur = rem * 10 + d;
      const q = Math.floor(cur / 256);
      rem = cur % 256;
      if (!(next.length === 0 && q === 0)) next.push(q);
    }
    byteIdx -= 1;
    out[byteIdx] = rem;
    digits = next;
  }
  return out;
}

function groth16G1Bytes(v: string[]): Uint8Array {
  const out = new Uint8Array(64);
  out.set(decToBe32(v[0]), 0);
  out.set(decToBe32(v[1]), 32);
  return out;
}

function groth16G2Bytes(v: string[][]): Uint8Array {
  // G2 is Fq2: coefficient pairs come out of snarkjs as (c0, c1) but the
  // on-chain verifier (groth16-solana) expects the BE serialisation
  // (c1 || c0) — swap both x and y.
  const x0 = decToBe32(v[0][0]);
  const x1 = decToBe32(v[0][1]);
  const y0 = decToBe32(v[1][0]);
  const y1 = decToBe32(v[1][1]);
  const out = new Uint8Array(128);
  out.set(x1, 0);
  out.set(x0, 32);
  out.set(y1, 64);
  out.set(y0, 96);
  return out;
}

function negateG1(point: Uint8Array): Uint8Array {
  if (point.length !== 64) throw new Error("G1 point must be 64 bytes");
  const out = new Uint8Array(64);
  out.set(point.subarray(0, 32), 0);
  const yNeg = subBe(BN254_P, point.subarray(32, 64));
  out.set(yNeg, 32);
  return out;
}

function subBe(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== 32 || b.length !== 32) throw new Error("32B operands only");
  const out = new Uint8Array(32);
  let borrow = 0;
  for (let i = 31; i >= 0; i--) {
    const diff = a[i] - b[i] - borrow;
    if (diff < 0) {
      out[i] = diff + 256;
      borrow = 1;
    } else {
      out[i] = diff;
      borrow = 0;
    }
  }
  return out;
}
