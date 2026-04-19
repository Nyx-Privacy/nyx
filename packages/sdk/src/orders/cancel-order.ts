/**
 * getOrderCancelFunction — Phase 4, spec §23.4.
 *
 * Cancel an existing order by flipping its OrderRecord status to CANCELLED.
 * Signer must equal the `trading_key` that submitted the order; otherwise
 * the on-chain `find_by_order_id` lookup returns None and the program
 * responds with `OrderNotFound`.
 *
 * IMPORTANT: this does NOT release the on-L1 NoteLock. The lock sits until
 * its natural `expiry_slot` (see `vault::release_lock`). Pre-expiry release
 * would require a TEE-signed vault ix and is Phase-5 territory.
 *
 * Stages (each throws DarkPoolError with a `stage` tag):
 *   1. "parameter"           — synchronous arg validation.
 *   2. "attestation-verify"  — non-retryable PER attestation check.
 *   3. "auth-token-fetch"    — fetch/refresh JWT.
 *   4. "instruction-build"   — pure local.
 *   5. "transaction-send"    — one 401-refresh retry (matches submit-order).
 */

import type { PublicKey, TransactionSignature } from "@solana/web3.js";

import type { DarkPoolClient } from "../client.js";
import { DarkPoolError } from "../errors.js";
import type { IPerSessionManager } from "../per/session-manager.js";
import { buildCancelOrderInstruction } from "../idl/matching-engine-client.js";

export interface CancelOrderParams {
  /** Trading Key that originally submitted the order. Must sign this tx. */
  tradingKey: PublicKey;
  /** Market the order lives in. */
  market: PublicKey;
  /** 16-byte id used at submit time. */
  orderId: Uint8Array;
}

export interface CancelOrderReceipt {
  signature: TransactionSignature;
}

export interface CancelOrderDeps {
  perSessionManager: IPerSessionManager;
}

export type OrderCancelFn = (
  params: CancelOrderParams,
) => Promise<CancelOrderReceipt>;

export function getOrderCancelFunction(
  { client }: { client: DarkPoolClient },
  deps: CancelOrderDeps,
): OrderCancelFn {
  if (!client.matchingEngineProgramId) {
    throw new DarkPoolError(
      "parameter",
      "DarkPoolClient.matchingEngineProgramId must be set for cancel_order",
    );
  }
  const meProgramId = client.matchingEngineProgramId;

  return async (params): Promise<CancelOrderReceipt> => {
    if (params.orderId.length !== 16) {
      throw new DarkPoolError("parameter", "orderId must be 16 bytes");
    }

    const attestOk = await deps.perSessionManager.verifyAttestation();
    if (!attestOk) {
      throw new DarkPoolError(
        "attestation-verify",
        "TEE attestation failed — no cancel sent",
      );
    }

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

    const ix = buildCancelOrderInstruction({
      programId: meProgramId,
      tradingKey: params.tradingKey,
      market: params.market,
      orderId: params.orderId,
    });

    const ctx = { traderPubkey: params.tradingKey.toBytes() };
    let signature: TransactionSignature;
    try {
      signature = await deps.perSessionManager.sendInstruction(ix, jwt, ctx);
    } catch (err) {
      if (err instanceof DarkPoolError && err.stage === "auth-token-fetch") {
        const jwt2 = await deps.perSessionManager.getToken();
        signature = await deps.perSessionManager.sendInstruction(ix, jwt2, ctx);
      } else if (err instanceof DarkPoolError) {
        throw err;
      } else {
        throw new DarkPoolError(
          "transaction-send",
          `PER send failed: ${String(err)}`,
        );
      }
    }

    return { signature };
  };
}
