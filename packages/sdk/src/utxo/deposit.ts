/**
 * getDepositFunction — factory-function pattern (Appendix C.3).
 *
 * Usage:
 *   const deposit = getDepositFunction({ client });
 *   const receipt = await deposit({ tokenMint, amount });
 */

import type { DarkPoolClient } from "../client.js";
import type { TransactionCallbacks } from "../providers.js";
import { DarkPoolError } from "../errors.js";
import { noteCommitment, ownerCommitment } from "./note.js";
import { deriveBlindingFactor } from "../keys/key-generators.js";

export interface DepositParams {
  tokenMint: Uint8Array;
  amount: bigint;
  /** Deterministic nonce (usually a per-user monotonically increasing counter). */
  nonce: bigint;
  callbacks?: TransactionCallbacks;
}

export interface DepositReceipt {
  signature: string;
  leafIndex: bigint;
  noteCommitment: Uint8Array; // 32 bytes BE
  notePlaintext: {
    tokenMint: Uint8Array;
    amount: bigint;
    ownerCommitment: bigint;
    nonce: bigint;
    blindingR: bigint;
  };
}

export function getDepositFunction(
  { client }: { client: DarkPoolClient },
): (params: DepositParams) => Promise<DepositReceipt> {
  return async (params) => {
    const { masterSeed, spendingKey, ownerBlinding } = await client.getResolvedKeys();

    // Step: fetch current leaf count to derive blinding factor deterministically.
    const leafIndex = await client.providers.accountInfoProvider
      .getAccountInfo(client.vaultConfigPda())
      .then((info) => {
        if (!info)
          throw new DarkPoolError("instruction-build", "vault_config not initialised");
        // Parse leaf_count from the account data — the first 8 bytes after the
        // 8-byte discriminator + 32 (admin) + 32 (tee_pubkey) = offset 72.
        const data = info.data;
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        return view.getBigUint64(8 + 32 + 32, true);
      });

    const blindingR = deriveBlindingFactor(masterSeed, leafIndex);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);

    const commitment = await noteCommitment({
      tokenMint: params.tokenMint,
      amount: params.amount,
      ownerCommitment: owner,
      nonce: params.nonce,
      blindingR,
    });

    await params.callbacks?.pre?.("deposit-send");

    // NB: Full Anchor instruction construction is intentionally left as a
    // follow-up — Phase 1 tests exercise the program via cargo, not via this
    // SDK. This stub documents the surface area and wiring.
    // TODO(phase-1.1): port Anchor `deposit()` ix here using @coral-xyz/anchor.
    throw new DarkPoolError(
      "instruction-build",
      "deposit() SDK path is scaffolded — on-chain tests cover Phase 1. " +
        "Full SDK transport will land with packages/web-zk-prover integration.",
    );

    // Unreachable but kept for shape:
    // eslint-disable-next-line no-unreachable
    return {
      signature: "",
      leafIndex,
      noteCommitment: commitment,
      notePlaintext: {
        tokenMint: params.tokenMint,
        amount: params.amount,
        ownerCommitment: owner,
        nonce: params.nonce,
        blindingR,
      },
    };
  };
}
