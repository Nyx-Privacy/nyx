/**
 * getOrderSubmitFunction — factory pattern per spec §23.3.2.
 *
 * Staged pipeline (each stage throws a DarkPoolError with its own `stage` tag):
 *   1. "attestation-verify"  — non-retryable. If TEE quote fails, abort.
 *   2. "auth-token-fetch"    — fetch/refresh JWT via PER session manager.
 *   3. "note-lock-check"     — note must not be locked/consumed.
 *   4. "instruction-build"   — pure local; caller-supplied params validated.
 *   5. "transaction-send"    — POST signed tx over PER RPC. On 401 → refresh
 *                              once and retry (via session manager).
 */

import type { PublicKey, TransactionSignature } from "@solana/web3.js";

import type { DarkPoolClient } from "../client.js";
import { DarkPoolError } from "../errors.js";
import type { IPerSessionManager } from "../per/session-manager.js";
import {
  buildSubmitOrderInstruction,
  OrderType,
  type SubmitOrderIxAndKeys,
} from "../idl/matching-engine-client.js";

export type OrderSide = "bid" | "ask";

/** Literal aliases for OrderType — lets SDK callers write "limit" | "ioc" | "fok". */
export type OrderTypeName = "limit" | "ioc" | "fok";

export interface OrderParams {
  /** The Trading Key that signs the submit_order tx. */
  tradingKey: PublicKey;
  /** The market this order belongs to. */
  market: PublicKey;
  /** TEE authority pubkey (must equal `vault_config.tee_pubkey`). */
  teeAuthority: PublicKey;
  /** User commitment this trading key is tied to (for walletEntry PDA). */
  userCommitment: Uint8Array;
  /** 32-byte commitment of the note being locked as collateral. */
  noteCommitment: Uint8Array;
  /** Amount (base units) of the token the user wants to trade. */
  amount: bigint;
  /** Max price (bid) / min price (ask) the user accepts. */
  priceLimit: bigint;
  side: OrderSide;
  /** Value encoded in the note. Caller-supplied ceiling for notional check. */
  noteAmount: bigint;
  /** Slot at which the lock auto-expires. */
  expirySlot: bigint;
  /** 16-byte random order id. */
  orderId: Uint8Array;
  /** LIMIT (rest in book), IOC (cancel unfilled remainder immediately),
   *  FOK (fill-or-kill). Defaults to LIMIT. */
  orderType?: OrderTypeName;
  /** Minimum fill qty in base units. 0 allows any partial fill. Defaults to 0. */
  minFillQty?: bigint;
}

const ORDER_TYPE_BY_NAME: Record<OrderTypeName, OrderType> = {
  limit: OrderType.Limit,
  ioc: OrderType.IOC,
  fok: OrderType.FOK,
};

export interface OrderReceipt {
  signature: TransactionSignature;
  orderInclusionCommitment: Uint8Array;
  darkClobPda: PublicKey;
  noteLockPda: PublicKey;
}

export interface OrderSubmitDeps {
  perSessionManager: IPerSessionManager;
}

export type OrderSubmitFn = (params: OrderParams) => Promise<OrderReceipt>;

export function getOrderSubmitFunction(
  { client }: { client: DarkPoolClient },
  deps: OrderSubmitDeps,
): OrderSubmitFn {
  if (!client.matchingEngineProgramId) {
    throw new DarkPoolError(
      "parameter",
      "DarkPoolClient.matchingEngineProgramId must be set for order submission",
    );
  }
  const meProgramId = client.matchingEngineProgramId;

  return async (params): Promise<OrderReceipt> => {
    // ----- Parameter validation (synchronous / no IO) -----
    if (params.noteCommitment.length !== 32) {
      throw new DarkPoolError("parameter", "noteCommitment must be 32 bytes");
    }
    if (params.userCommitment.length !== 32) {
      throw new DarkPoolError("parameter", "userCommitment must be 32 bytes");
    }
    if (params.orderId.length !== 16) {
      throw new DarkPoolError("parameter", "orderId must be 16 bytes");
    }
    if (params.amount <= 0n) {
      throw new DarkPoolError("parameter", "amount must be > 0");
    }
    if (params.priceLimit <= 0n) {
      throw new DarkPoolError("parameter", "priceLimit must be > 0");
    }
    const notional = params.amount * params.priceLimit;
    if (notional > params.noteAmount) {
      throw new DarkPoolError(
        "parameter",
        "notional (amount * priceLimit) exceeds noteAmount",
      );
    }
    const minFillQty = params.minFillQty ?? 0n;
    if (minFillQty < 0n) {
      throw new DarkPoolError("parameter", "minFillQty must be >= 0");
    }
    if (minFillQty > params.amount) {
      throw new DarkPoolError("parameter", "minFillQty must be <= amount");
    }

    // ----- Stage 1: attestation-verify -----
    const attestOk = await deps.perSessionManager.verifyAttestation();
    if (!attestOk) {
      throw new DarkPoolError(
        "attestation-verify",
        "TEE attestation failed — no order data sent",
      );
    }

    // ----- Stage 2: auth-token-fetch -----
    let jwt: string;
    try {
      jwt = await deps.perSessionManager.getToken();
    } catch (err) {
      if (err instanceof DarkPoolError) throw err;
      throw new DarkPoolError(
        "auth-token-fetch",
        `getToken failed: ${String(err)}`,
      );
    }

    // ----- Stage 3: note-lock-check -----
    const noteInfo = await client.getNoteStatus(params.noteCommitment);
    if (noteInfo.status === "locked") {
      throw new DarkPoolError(
        "note-lock-check",
        "note is already locked by another active order",
      );
    }
    if (noteInfo.status === "consumed") {
      throw new DarkPoolError(
        "note-lock-check",
        "note has been consumed by a prior settlement",
      );
    }
    if (noteInfo.status === "unknown") {
      throw new DarkPoolError("note-lock-check", "note status unknown");
    }

    // ----- Stage 4: instruction-build -----
    let built: SubmitOrderIxAndKeys;
    try {
      built = buildSubmitOrderInstruction({
        programId: meProgramId,
        vaultProgramId: client.programId,
        tradingKey: params.tradingKey,
        teeAuthority: params.teeAuthority,
        market: params.market,
        userCommitment: params.userCommitment,
        noteCommitment: params.noteCommitment,
        amount: params.amount,
        priceLimit: params.priceLimit,
        side: params.side === "bid" ? 0 : 1,
        noteAmount: params.noteAmount,
        expirySlot: params.expirySlot,
        orderId: params.orderId,
        orderType: ORDER_TYPE_BY_NAME[params.orderType ?? "limit"],
        minFillQty,
      });
    } catch (err) {
      throw new DarkPoolError(
        "instruction-build",
        `instruction build failed: ${String(err)}`,
      );
    }

    // ----- Stage 5: transaction-send (with one 401 refresh retry) -----
    const ctx = { traderPubkey: params.tradingKey.toBytes() };
    let signature: TransactionSignature;
    try {
      signature = await deps.perSessionManager.sendInstruction(
        built.ix,
        jwt,
        ctx,
      );
    } catch (err) {
      if (err instanceof DarkPoolError && err.stage === "auth-token-fetch") {
        // JWT expired mid-flight. Refresh once and retry.
        const jwt2 = await deps.perSessionManager.getToken();
        signature = await deps.perSessionManager.sendInstruction(
          built.ix,
          jwt2,
          ctx,
        );
      } else if (err instanceof DarkPoolError) {
        throw err;
      } else {
        throw new DarkPoolError(
          "transaction-send",
          `PER send failed: ${String(err)}`,
        );
      }
    }

    // The TEE returns the `order_inclusion_commitment` via the tx's emit!ed
    // event. For Phase 3 the SDK does not parse the response stream; callers
    // can subscribe to logs to pick up the commitment. We compute a *local*
    // placeholder here and leave the authoritative value to the event.
    const orderInclusionCommitment = hashInclusionCommitmentPlaceholder(
      params.noteCommitment,
      params.tradingKey.toBytes(),
    );

    return {
      signature,
      orderInclusionCommitment,
      darkClobPda: built.darkClobPda,
      noteLockPda: built.noteLockPda,
    };
  };
}

// Placeholder inclusion-commitment hash: we don't know seq_no locally, so we
// return H(note_commitment || trading_key). The authoritative commitment that
// matches on-chain uses seq_no and is returned by the TEE in the event log.
function hashInclusionCommitmentPlaceholder(
  noteCommitment: Uint8Array,
  tradingKey: Uint8Array,
): Uint8Array {
  const buf = new Uint8Array(32 + 32);
  buf.set(noteCommitment, 0);
  buf.set(tradingKey, 32);
  // Use a web-crypto compatible synchronous hash via SubtleCrypto is async;
  // for a sync placeholder we xor-fold into 32 bytes. This is only a
  // placeholder — tests check the on-chain event for the real commitment.
  const out = new Uint8Array(32);
  for (let i = 0; i < buf.length; i++) {
    out[i % 32] ^= buf[i];
  }
  return out;
}
