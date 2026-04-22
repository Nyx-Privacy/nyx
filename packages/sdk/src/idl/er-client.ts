/**
 * MagicBlock Ephemeral Rollup (ER) client helpers.
 *
 * Two responsibilities:
 *   1. Constants + PDA derivations the delegation program needs.
 *   2. Instruction builders for the matching_engine's ER-facing ixs:
 *        - delegate_dark_clob       (L1)
 *        - delegate_matching_config (L1)
 *        - delegate_batch_results   (L1)
 *        - run_batch                (ER — reuse existing builder, just change route)
 *        - commit_market_state      (ER, CPIs ScheduleCommit back to L1)
 *        - undelegate_market        (ER, CPIs ScheduleCommitAndUndelegate)
 *
 * The ER RPC URL is supplied by the caller (via env / param). The TEE
 * signs ixs exactly the same way; only the Connection changes.
 *
 * References:
 *   - ephemeral-rollups-sdk-0.8.8 src/consts.rs
 *   - magicblock-delegation-program-1.1.3 src/pda.rs
 */

import {
  Connection,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  Commitment,
} from "@solana/web3.js";
import { createHash } from "node:crypto";

import {
  batchResultsPda,
  darkClobPda,
  matchingConfigPda,
} from "./matching-engine-client.js";

// ---------------------------------------------------------------------------
// Program IDs + well-known pubkeys
// ---------------------------------------------------------------------------

export const DELEGATION_PROGRAM_ID = new PublicKey(
  "DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh",
);
export const MAGIC_PROGRAM_ID = new PublicKey(
  "Magic11111111111111111111111111111111111111",
);
export const MAGIC_CONTEXT_ID = new PublicKey(
  "MagicContext1111111111111111111111111111111",
);

/** MagicBlock delegation-program PDA seed tags (from `magicblock-delegation-program/src/pda.rs`). */
export const DELEGATE_BUFFER_TAG = Buffer.from("buffer");
export const DELEGATION_RECORD_TAG = Buffer.from("delegation");
export const DELEGATION_METADATA_TAG = Buffer.from("delegation-metadata");

// ---------------------------------------------------------------------------
// Delegation-PDAs for the #[delegate] Accounts struct
// ---------------------------------------------------------------------------

/**
 * PDAs the `#[delegate]` macro expects as sibling accounts for a delegated
 * account. Buffer is owned by the OWNER program (matching_engine here).
 * Record + metadata are owned by the delegation program.
 */
export function delegationPdas(
  ownerProgramId: PublicKey,
  delegatedPda: PublicKey,
): {
  buffer: PublicKey;
  record: PublicKey;
  metadata: PublicKey;
} {
  const [buffer] = PublicKey.findProgramAddressSync(
    [DELEGATE_BUFFER_TAG, delegatedPda.toBuffer()],
    ownerProgramId,
  );
  const [record] = PublicKey.findProgramAddressSync(
    [DELEGATION_RECORD_TAG, delegatedPda.toBuffer()],
    DELEGATION_PROGRAM_ID,
  );
  const [metadata] = PublicKey.findProgramAddressSync(
    [DELEGATION_METADATA_TAG, delegatedPda.toBuffer()],
    DELEGATION_PROGRAM_ID,
  );
  return { buffer, record, metadata };
}

// ---------------------------------------------------------------------------
// Anchor discriminator helper (duplicated here so we don't import from the
// matching-engine-client module's private helpers).
// ---------------------------------------------------------------------------

function anchorDiscriminator(name: string): Buffer {
  const h = createHash("sha256");
  h.update(`global:${name}`);
  return h.digest().subarray(0, 8);
}

function encodePubkeyArg(market: PublicKey): Buffer {
  return Buffer.from(market.toBytes());
}

// ---------------------------------------------------------------------------
// Generic delegate builder — parameterised over seed tag + ix name.
// ---------------------------------------------------------------------------

interface DelegateMarketPdaParams {
  programId: PublicKey;
  payer: PublicKey;
  market: PublicKey;
}

function buildDelegatePdaIx(
  params: DelegateMarketPdaParams,
  ixName: string,
  pda: PublicKey,
): TransactionInstruction {
  const { programId, payer, market } = params;
  const { buffer, record, metadata } = delegationPdas(programId, pda);

  // Wire order mirrors the `#[delegate]` macro's field-injection pattern
  // EXACTLY. The macro walks the original struct top-to-bottom; for each
  // field carrying `del`, it PREPENDS three sibling fields (buffer,
  // delegation_record, delegation_metadata) BEFORE re-emitting the field
  // itself (with `del` stripped). Trailing fields (owner_program,
  // delegation_program, system_program) are appended at the end.
  //
  // For our single-del struct (`DelegateDarkClob { payer, pda: del }`):
  //   1. payer
  //   2. buffer_pda           <— injected
  //   3. delegation_record    <— injected
  //   4. delegation_metadata  <— injected
  //   5. pda (the delegated account)
  //   6. owner_program (= this program's id)
  //   7. delegation_program (= DELEGATION_PROGRAM_ID)
  //   8. system_program
  //
  // Getting this order wrong produces `ConstraintSeeds` at whichever
  // slot anchors the seed check — because Anchor recomputes per-field
  // against the account meta at the expected index.
  const keys = [
    { pubkey: payer, isSigner: true, isWritable: true },
    { pubkey: buffer, isSigner: false, isWritable: true },
    { pubkey: record, isSigner: false, isWritable: true },
    { pubkey: metadata, isSigner: false, isWritable: true },
    { pubkey: pda, isSigner: false, isWritable: true },
    { pubkey: programId, isSigner: false, isWritable: false },             // owner_program
    { pubkey: DELEGATION_PROGRAM_ID, isSigner: false, isWritable: false }, // delegation_program
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];

  // Ix data: discriminator ++ Borsh(market: Pubkey).
  const data = Buffer.concat([
    anchorDiscriminator(ixName),
    encodePubkeyArg(market),
  ]);

  return new TransactionInstruction({ programId, keys, data });
}

export function buildDelegateDarkClobInstruction(
  p: DelegateMarketPdaParams,
): TransactionInstruction {
  const [pda] = darkClobPda(p.programId, p.market);
  return buildDelegatePdaIx(p, "delegate_dark_clob", pda);
}

export function buildDelegateMatchingConfigInstruction(
  p: DelegateMarketPdaParams,
): TransactionInstruction {
  const [pda] = matchingConfigPda(p.programId, p.market);
  return buildDelegatePdaIx(p, "delegate_matching_config", pda);
}

export function buildDelegateBatchResultsInstruction(
  p: DelegateMarketPdaParams,
): TransactionInstruction {
  const [pda] = batchResultsPda(p.programId, p.market);
  return buildDelegatePdaIx(p, "delegate_batch_results", pda);
}

// ---------------------------------------------------------------------------
// commit_market_state / undelegate_market
// ---------------------------------------------------------------------------

export interface BuildCommitMarketStateParams {
  programId: PublicKey;
  payer: PublicKey;
  market: PublicKey;
}

function commitMarketStateAccounts(p: BuildCommitMarketStateParams) {
  const [clob] = darkClobPda(p.programId, p.market);
  const [mcfg] = matchingConfigPda(p.programId, p.market);
  const [breq] = batchResultsPda(p.programId, p.market);
  // Wire order mirrors the `#[commit]` macro (magic_program + magic_context
  // are appended after the explicit fields).
  return [
    { pubkey: p.payer, isSigner: true, isWritable: true },
    { pubkey: clob, isSigner: false, isWritable: true },
    { pubkey: mcfg, isSigner: false, isWritable: true },
    { pubkey: breq, isSigner: false, isWritable: true },
    { pubkey: MAGIC_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: MAGIC_CONTEXT_ID, isSigner: false, isWritable: true },
  ];
}

/**
 * Build a `commit_market_state` ix. Must be sent to the ER RPC — the CPI
 * inside invokes `MagicBlockInstruction::ScheduleCommit` which only works
 * inside the ER runtime.
 */
export function buildCommitMarketStateInstruction(
  p: BuildCommitMarketStateParams,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId,
    keys: commitMarketStateAccounts(p),
    data: anchorDiscriminator("commit_market_state"),
  });
}

/**
 * Build an `undelegate_market` ix. Must be sent to the ER RPC — CPIs
 * `ScheduleCommitAndUndelegate`, returning the 3 PDAs to L1 ownership.
 */
export function buildUndelegateMarketInstruction(
  p: BuildCommitMarketStateParams,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: p.programId,
    keys: commitMarketStateAccounts(p),
    data: anchorDiscriminator("undelegate_market"),
  });
}

// ---------------------------------------------------------------------------
// Dual-connection helper
// ---------------------------------------------------------------------------

export interface DualConnections {
  l1: Connection;
  er: Connection;
}

/**
 * Open a pair of RPC connections. The L1 connection is used for deposits,
 * wallet creation, submit_order (pre-delegation), settle, and withdraw.
 * The ER connection is used for run_batch + commit_market_state +
 * undelegate_market. Both use the same commitment level.
 */
export function openDualConnections(
  l1RpcUrl: string,
  erRpcUrl: string,
  commitment: Commitment = "confirmed",
): DualConnections {
  return {
    l1: new Connection(l1RpcUrl, commitment),
    er: new Connection(erRpcUrl, commitment),
  };
}

/**
 * Poll L1 until the given account's data hash changes. Useful after
 * calling `commit_market_state` in the ER — we need to know when the
 * state-commit transaction lands on L1 before reading `batch_results`.
 *
 * Returns the final L1 account data buffer when the hash changes, or
 * throws on timeout.
 */
export async function waitForL1AccountChange(
  l1: Connection,
  pubkey: PublicKey,
  initialDataHex: string | null,
  options: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<Buffer> {
  const timeoutMs = options.timeoutMs ?? 45_000;
  const intervalMs = options.intervalMs ?? 750;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const acct = await l1.getAccountInfo(pubkey, "confirmed");
    if (acct) {
      const hex = Buffer.from(acct.data).toString("hex");
      if (hex !== initialDataHex) return acct.data;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(
    `waitForL1AccountChange: ${pubkey.toBase58()} did not change within ${timeoutMs}ms`,
  );
}
