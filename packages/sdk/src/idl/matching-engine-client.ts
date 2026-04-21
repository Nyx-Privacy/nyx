/**
 * Pure-TS instruction builder for the matching_engine program.
 *
 * Mirrors the style of `vault-client.ts`: Anchor discriminator (sha256
 * "global:<ix>")[0..8] ++ Borsh-encoded args. Fixed-size byte arrays are
 * emitted inline; Vec<T> carries a 4-byte length prefix.
 */

import { PublicKey, TransactionInstruction, SystemProgram } from "@solana/web3.js";
import { createHash } from "node:crypto";

import {
  BATCH_RESULTS_SEED,
  DARK_CLOB_SEED,
  MATCHING_CONFIG_SEED,
} from "./seeds.js";
import { vaultConfigPda, walletEntryPda, noteLockPda, consumedNotePda } from "./vault-client.js";

/** MagicBlock permission program id (see ephemeral-rollups-sdk consts). */
export const PERMISSION_PROGRAM_ID = new PublicKey(
  "ACLseoPoyC3cBqoUtkbjZ4aDrkurZW86v19pXz2XQnp1",
);

function anchorDiscriminator(name: string): Uint8Array {
  const h = createHash("sha256");
  h.update(`global:${name}`);
  return new Uint8Array(h.digest()).slice(0, 8);
}

function cat(...bs: Uint8Array[]): Uint8Array {
  const n = bs.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(n);
  let off = 0;
  for (const b of bs) {
    out.set(b, off);
    off += b.length;
  }
  return out;
}

function u64LE(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

function u32LE(v: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, v, true);
  return out;
}

function fixed32(x: Uint8Array): Uint8Array {
  if (x.length !== 32) throw new Error(`expected 32 bytes, got ${x.length}`);
  return x;
}

function fixed16(x: Uint8Array): Uint8Array {
  if (x.length !== 16) throw new Error(`expected 16 bytes, got ${x.length}`);
  return x;
}

export function darkClobPda(
  programId: PublicKey,
  market: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DARK_CLOB_SEED, market.toBuffer()],
    programId,
  );
}

export function matchingConfigPda(
  programId: PublicKey,
  market: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [MATCHING_CONFIG_SEED, market.toBuffer()],
    programId,
  );
}

export function batchResultsPda(
  programId: PublicKey,
  market: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [BATCH_RESULTS_SEED, market.toBuffer()],
    programId,
  );
}

/** Order type enum mirroring `ORDER_TYPE_*` in the program. */
export enum OrderType {
  Limit = 0,
  IOC = 1,
  FOK = 2,
}

export interface BuildInitMarketParams {
  programId: PublicKey;
  vaultProgramId: PublicKey;
  payer: PublicKey;
  market: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  pythAccount: PublicKey;
  batchIntervalSlots: bigint;
  circuitBreakerBps: bigint;
  tickSize: bigint;
  minOrderSize: bigint;
}

export function buildInitMarketInstruction(
  p: BuildInitMarketParams,
): TransactionInstruction {
  const [vaultCfg] = vaultConfigPda(p.vaultProgramId);
  const [clobPda] = darkClobPda(p.programId, p.market);
  const [matchPda] = matchingConfigPda(p.programId, p.market);
  const [batchPda] = batchResultsPda(p.programId, p.market);
  const data = cat(
    anchorDiscriminator("init_market"),
    p.market.toBytes(),
    p.baseMint.toBytes(),
    p.quoteMint.toBytes(),
    p.pythAccount.toBytes(),
    u64LE(p.batchIntervalSlots),
    u64LE(p.circuitBreakerBps),
    u64LE(p.tickSize),
    u64LE(p.minOrderSize),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: vaultCfg, isSigner: false, isWritable: false },
      { pubkey: clobPda, isSigner: false, isWritable: true },
      { pubkey: matchPda, isSigner: false, isWritable: true },
      { pubkey: batchPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

export interface MemberArgJson {
  flags: number;
  pubkey: PublicKey;
}

export interface BuildConfigureAccessParams {
  programId: PublicKey;
  rootKey: PublicKey;
  market: PublicKey;
  members: MemberArgJson[];
  isUpdate: boolean;
  /** Permission PDA (derived by MagicBlock from the DarkCLOB PDA). */
  permissionPda: PublicKey;
}

export function buildConfigureAccessInstruction(
  p: BuildConfigureAccessParams,
): TransactionInstruction {
  const [clobPda] = darkClobPda(p.programId, p.market);
  const [matchPda] = matchingConfigPda(p.programId, p.market);
  // Members vec serialisation: u32 length LE, then (u8 flags + 32 bytes pubkey) × N.
  const memberBytes: Uint8Array[] = [];
  for (const m of p.members) {
    memberBytes.push(new Uint8Array([m.flags]));
    memberBytes.push(m.pubkey.toBytes());
  }
  const data = cat(
    anchorDiscriminator("configure_access"),
    p.market.toBytes(),
    u32LE(p.members.length),
    ...memberBytes,
    new Uint8Array([p.isUpdate ? 1 : 0]),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.rootKey, isSigner: true, isWritable: true },
      { pubkey: clobPda, isSigner: false, isWritable: true },
      { pubkey: matchPda, isSigner: false, isWritable: false },
      { pubkey: p.permissionPda, isSigner: false, isWritable: true },
      { pubkey: PERMISSION_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

export interface BuildSubmitOrderParams {
  programId: PublicKey;
  vaultProgramId: PublicKey;
  tradingKey: PublicKey;
  teeAuthority: PublicKey;
  market: PublicKey;
  userCommitment: Uint8Array; // for walletEntry PDA
  noteCommitment: Uint8Array;
  amount: bigint;
  priceLimit: bigint;
  side: number; // 0 | 1
  noteAmount: bigint;
  expirySlot: bigint;
  orderId: Uint8Array; // 16 bytes
  /** 0 = LIMIT, 1 = IOC, 2 = FOK. Defaults to LIMIT. */
  orderType?: OrderType;
  /** Minimum base-unit fill qty. 0 = any fill allowed. Defaults to 0. */
  minFillQty?: bigint;
}

export interface SubmitOrderIxAndKeys {
  ix: TransactionInstruction;
  darkClobPda: PublicKey;
  noteLockPda: PublicKey;
  /** order_inclusion_commitment = SHA-256(seq_no || note_commitment || trading_key).
   *  Cannot be predicted before the ix runs (seq_no is TEE-assigned), so the SDK
   *  receives it from the TEE response. We return the raw ingredients here. */
  commitmentIngredients: {
    noteCommitment: Uint8Array;
    tradingKey: Uint8Array;
  };
}

export function buildSubmitOrderInstruction(
  p: BuildSubmitOrderParams,
): SubmitOrderIxAndKeys {
  const [clobPda] = darkClobPda(p.programId, p.market);
  const [matchPda] = matchingConfigPda(p.programId, p.market);
  const [vaultCfg] = vaultConfigPda(p.vaultProgramId);
  const [walletEntry] = walletEntryPda(p.vaultProgramId, p.userCommitment);
  const [noteLock] = noteLockPda(p.vaultProgramId, p.noteCommitment);
  const [consumedProbe] = consumedNotePda(p.vaultProgramId, p.noteCommitment);

  // Args struct (Borsh, fixed-size fields in declaration order). Must match
  // `SubmitOrderArgs` in programs/matching_engine/src/instructions/submit_order.rs.
  const argsBytes = cat(
    p.market.toBytes(),
    fixed32(p.noteCommitment),
    u64LE(p.amount),
    u64LE(p.priceLimit),
    new Uint8Array([p.side]),
    u64LE(p.noteAmount),
    u64LE(p.expirySlot),
    fixed16(p.orderId),
    new Uint8Array([p.orderType ?? OrderType.Limit]),
    u64LE(p.minFillQty ?? 0n),
    fixed32(p.userCommitment), // Phase 5: owner-commitment tied to the trading key
  );

  const data = cat(anchorDiscriminator("submit_order"), argsBytes);

  const ix = new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.tradingKey, isSigner: true, isWritable: true },
      { pubkey: clobPda, isSigner: false, isWritable: true },
      { pubkey: matchPda, isSigner: false, isWritable: false },
      { pubkey: vaultCfg, isSigner: false, isWritable: true },
      { pubkey: walletEntry, isSigner: false, isWritable: false },
      { pubkey: p.teeAuthority, isSigner: true, isWritable: true },
      { pubkey: noteLock, isSigner: false, isWritable: true },
      { pubkey: consumedProbe, isSigner: false, isWritable: false },
      { pubkey: p.vaultProgramId, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });

  return {
    ix,
    darkClobPda: clobPda,
    noteLockPda: noteLock,
    commitmentIngredients: {
      noteCommitment: p.noteCommitment,
      tradingKey: p.tradingKey.toBytes(),
    },
  };
}

// ---------------------------------------------------------------------------
// cancel_order (Phase 4)
// ---------------------------------------------------------------------------

export interface BuildCancelOrderParams {
  programId: PublicKey;
  tradingKey: PublicKey;
  market: PublicKey;
  orderId: Uint8Array; // 16 bytes
}

export function buildCancelOrderInstruction(
  p: BuildCancelOrderParams,
): TransactionInstruction {
  const [clobPda] = darkClobPda(p.programId, p.market);
  const data = cat(
    anchorDiscriminator("cancel_order"),
    p.market.toBytes(),
    fixed16(p.orderId),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.tradingKey, isSigner: true, isWritable: true },
      { pubkey: clobPda, isSigner: false, isWritable: true },
    ],
    data: Buffer.from(data),
  });
}

// ---------------------------------------------------------------------------
// run_batch (Phase 4)
// ---------------------------------------------------------------------------

export interface BuildRunBatchParams {
  programId: PublicKey;
  /** Vault program id — needed to derive the cross-program vault_config PDA. */
  vaultProgramId: PublicKey;
  teeAuthority: PublicKey;
  market: PublicKey;
  pythAccount: PublicKey;
}

export function buildRunBatchInstruction(
  p: BuildRunBatchParams,
): TransactionInstruction {
  const [clobPda] = darkClobPda(p.programId, p.market);
  const [matchPda] = matchingConfigPda(p.programId, p.market);
  const [batchPda] = batchResultsPda(p.programId, p.market);
  // Phase 5: `vault_config` is a read-only snapshot; PDA is derived under the
  // vault program id via `seeds::program = vault::ID` in the on-chain struct.
  const [vaultCfg] = vaultConfigPda(p.vaultProgramId);
  const data = cat(anchorDiscriminator("run_batch"), p.market.toBytes());
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.teeAuthority, isSigner: true, isWritable: true },
      { pubkey: clobPda, isSigner: false, isWritable: true },
      { pubkey: matchPda, isSigner: false, isWritable: false },
      { pubkey: batchPda, isSigner: false, isWritable: true },
      { pubkey: vaultCfg, isSigner: false, isWritable: false },
      { pubkey: p.pythAccount, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

// ---------------------------------------------------------------------------
// init_mock_oracle (dev-net / test-only helper)
// ---------------------------------------------------------------------------

export interface BuildInitMockOracleParams {
  programId: PublicKey;
  payer: PublicKey;
  mockOracle: PublicKey;
  /** u64 TWAP written to bytes [8..16] of the mock oracle account. */
  twap: bigint;
}

/**
 * Create + initialise a 16-byte mock Pyth oracle account on devnet. The
 * returned ix MUST be preceded (same tx, different signer set) by a fresh
 * keypair signer for `mockOracle`. Total tx signers: [payer, mockOracle].
 *
 * Account layout written by the handler:
 *   [0..8]   b"NYXMKPTH" (MOCK_PYTH_MAGIC)
 *   [8..16]  u64 LE TWAP
 */
export function buildInitMockOracleInstruction(
  p: BuildInitMockOracleParams,
): TransactionInstruction {
  const data = cat(
    anchorDiscriminator("init_mock_oracle"),
    u64LE(p.twap),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: p.mockOracle, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}
