/**
 * Pure-TS instruction builder for the vault program.
 *
 * We do NOT pull the Anchor IDL JSON in at runtime (to keep the SDK thin and
 * avoid shipping the IDL to the browser). Instead, we compute the Anchor
 * discriminator directly (`sha256("global:<ix_name>")[0..8]`) and serialise
 * arguments with Borsh-compatible primitive writes.
 *
 * This matches the Umbra-style pattern: the SDK is responsible for producing
 * `TransactionInstruction`s that the wallet layer signs and sends.
 *
 * Layout for every instruction:
 *   data = [disc (8 bytes)] || borsh(args)
 *
 * For instruction arguments, Borsh emits:
 *   - `u64`              -> 8 bytes LE
 *   - `[u8; N]`          -> N bytes (no length prefix)
 *   - `struct`           -> concatenation of fields in declaration order
 *   - `Pubkey`           -> 32 bytes (same as `[u8; 32]`)
 *
 * Fixed-size byte arrays are emitted inline (no length prefix) — this is the
 * critical difference from `Vec<u8>`, which does carry a 4-byte length.
 */

import { PublicKey, TransactionInstruction, SystemProgram } from "@solana/web3.js";
import { createHash } from "node:crypto";

import { VAULT_CONFIG_SEED, WALLET_SEED, NULLIFIER_SEED, NOTE_LOCK_SEED, CONSUMED_NOTE_SEED, VAULT_TOKEN_SEED } from "./seeds.js";

/** On-chain portion of a Groth16 proof — the three curve points. */
export interface Groth16OnChainProof {
  piA: Uint8Array; // 64 bytes
  piB: Uint8Array; // 128 bytes
  piC: Uint8Array; // 64 bytes
}

/** Compute Anchor global instruction discriminator. */
export function anchorDiscriminator(name: string): Uint8Array {
  const h = createHash("sha256");
  h.update(`global:${name}`);
  return new Uint8Array(h.digest()).slice(0, 8);
}

/** Helper: append bytes into a growing buffer. */
function cat(...buffers: Uint8Array[]): Uint8Array {
  const total = buffers.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of buffers) {
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

function fixed32(x: Uint8Array): Uint8Array {
  if (x.length !== 32) throw new Error(`expected 32 bytes, got ${x.length}`);
  return x;
}

function fixed64(x: Uint8Array): Uint8Array {
  if (x.length !== 64) throw new Error(`expected 64 bytes, got ${x.length}`);
  return x;
}

function fixed128(x: Uint8Array): Uint8Array {
  if (x.length !== 128) throw new Error(`expected 128 bytes, got ${x.length}`);
  return x;
}

function serializeProof(p: Groth16OnChainProof): Uint8Array {
  return cat(fixed64(p.piA), fixed128(p.piB), fixed64(p.piC));
}

// ============================================================================
// PDA derivations (must match `state.rs` SEED constants)
// ============================================================================

export function vaultConfigPda(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([VAULT_CONFIG_SEED], programId);
}

export function walletEntryPda(
  programId: PublicKey,
  commitment: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([WALLET_SEED, fixed32(commitment)], programId);
}

export function nullifierEntryPda(
  programId: PublicKey,
  nullifier: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([NULLIFIER_SEED, fixed32(nullifier)], programId);
}

export function noteLockPda(
  programId: PublicKey,
  noteCommitment: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([NOTE_LOCK_SEED, fixed32(noteCommitment)], programId);
}

export function consumedNotePda(
  programId: PublicKey,
  noteCommitment: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [CONSUMED_NOTE_SEED, fixed32(noteCommitment)],
    programId,
  );
}

export function vaultTokenAccountPda(
  programId: PublicKey,
  mint: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [VAULT_TOKEN_SEED, mint.toBuffer()],
    programId,
  );
}

// ============================================================================
// Instruction builders
// ============================================================================

export interface BuildInitializeParams {
  programId: PublicKey;
  admin: PublicKey;
  teePubkey: PublicKey;
  rootKey: PublicKey;
}

export function buildInitializeInstruction(
  p: BuildInitializeParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const data = cat(
    anchorDiscriminator("initialize"),
    p.teePubkey.toBytes(),
    p.rootKey.toBytes(),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.admin, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

export interface BuildRotateRootKeyParams {
  programId: PublicKey;
  currentRootKey: PublicKey;
  newRootKey: PublicKey;
}

export function buildRotateRootKeyInstruction(
  p: BuildRotateRootKeyParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const data = cat(
    anchorDiscriminator("rotate_root_key"),
    p.newRootKey.toBytes(),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.currentRootKey, isSigner: true, isWritable: false },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
    ],
    data: Buffer.from(data),
  });
}

export interface BuildCreateWalletParams {
  programId: PublicKey;
  owner: PublicKey;
  commitment: Uint8Array;
  proof: Groth16OnChainProof;
}

export function buildCreateWalletInstruction(
  p: BuildCreateWalletParams,
): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [walletPda] = walletEntryPda(p.programId, p.commitment);
  const data = cat(
    anchorDiscriminator("create_wallet"),
    fixed32(p.commitment),
    serializeProof(p.proof),
  );
  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.owner, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: false },
      { pubkey: walletPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

export interface BuildDepositParams {
  programId: PublicKey;
  depositor: PublicKey;
  tokenMint: PublicKey;
  depositorTokenAccount: PublicKey;
  tokenProgramId: PublicKey;
  amount: bigint;
  ownerCommitment: Uint8Array;
  nonce: Uint8Array;
  blindingR: Uint8Array;
}

export function buildDepositInstruction(p: BuildDepositParams): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [vaultTokenAcct] = vaultTokenAccountPda(p.programId, p.tokenMint);

  const data = cat(
    anchorDiscriminator("deposit"),
    u64LE(p.amount),
    fixed32(p.ownerCommitment),
    fixed32(p.nonce),
    fixed32(p.blindingR),
  );

  // Sysvar rent pubkey = SysvarRent111111111111111111111111111111111
  const rentSysvar = new PublicKey("SysvarRent111111111111111111111111111111111");

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.depositor, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: p.tokenMint, isSigner: false, isWritable: false },
      { pubkey: p.depositorTokenAccount, isSigner: false, isWritable: true },
      { pubkey: vaultTokenAcct, isSigner: false, isWritable: true },
      { pubkey: p.tokenProgramId, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: rentSysvar, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

export interface BuildWithdrawParams {
  programId: PublicKey;
  payer: PublicKey;
  tokenMint: PublicKey;
  destinationTokenAccount: PublicKey;
  tokenProgramId: PublicKey;
  noteCommitment: Uint8Array;
  nullifier: Uint8Array;
  merkleRoot: Uint8Array;
  amount: bigint;
  proof: Groth16OnChainProof;
}

export function buildWithdrawInstruction(p: BuildWithdrawParams): TransactionInstruction {
  const [vaultPda] = vaultConfigPda(p.programId);
  const [vaultTokenAcct] = vaultTokenAccountPda(p.programId, p.tokenMint);
  const [consumedNote] = consumedNotePda(p.programId, p.noteCommitment);
  const [noteLock] = noteLockPda(p.programId, p.noteCommitment);
  const [nullifierEntry] = nullifierEntryPda(p.programId, p.nullifier);

  const data = cat(
    anchorDiscriminator("withdraw"),
    fixed32(p.noteCommitment),
    fixed32(p.nullifier),
    fixed32(p.merkleRoot),
    u64LE(p.amount),
    serializeProof(p.proof),
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.payer, isSigner: true, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: p.tokenMint, isSigner: false, isWritable: false },
      { pubkey: vaultTokenAcct, isSigner: false, isWritable: true },
      { pubkey: p.destinationTokenAccount, isSigner: false, isWritable: true },
      { pubkey: consumedNote, isSigner: false, isWritable: false },
      { pubkey: noteLock, isSigner: false, isWritable: false },
      { pubkey: nullifierEntry, isSigner: false, isWritable: true },
      { pubkey: p.tokenProgramId, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}
