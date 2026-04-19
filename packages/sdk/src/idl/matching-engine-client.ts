/**
 * Pure-TS instruction builder for the matching_engine program.
 *
 * Mirrors the style of `vault-client.ts`: Anchor discriminator (sha256
 * "global:<ix>")[0..8] ++ Borsh-encoded args. Fixed-size byte arrays are
 * emitted inline; Vec<T> carries a 4-byte length prefix.
 */

import { PublicKey, TransactionInstruction, SystemProgram } from "@solana/web3.js";
import { createHash } from "node:crypto";

import { DARK_CLOB_SEED, MATCHING_CONFIG_SEED } from "./seeds.js";
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

export interface BuildInitMarketParams {
  programId: PublicKey;
  vaultProgramId: PublicKey;
  payer: PublicKey;
  market: PublicKey;
  batchIntervalSlots: bigint;
}

export function buildInitMarketInstruction(
  p: BuildInitMarketParams,
): TransactionInstruction {
  const [vaultCfg] = vaultConfigPda(p.vaultProgramId);
  const [clobPda] = darkClobPda(p.programId, p.market);
  const [matchPda] = matchingConfigPda(p.programId, p.market);
  const data = cat(
    anchorDiscriminator("init_market"),
    p.market.toBytes(),
    u64LE(p.batchIntervalSlots),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: vaultCfg, isSigner: false, isWritable: false },
      { pubkey: clobPda, isSigner: false, isWritable: true },
      { pubkey: matchPda, isSigner: false, isWritable: true },
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

  // Args struct (Borsh, fixed-size fields in declaration order).
  const argsBytes = cat(
    p.market.toBytes(),
    fixed32(p.noteCommitment),
    u64LE(p.amount),
    u64LE(p.priceLimit),
    new Uint8Array([p.side]),
    u64LE(p.noteAmount),
    u64LE(p.expirySlot),
    fixed16(p.orderId),
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
