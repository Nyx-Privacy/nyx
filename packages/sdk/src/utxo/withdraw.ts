/**
 * getWithdrawFunction — factory-function pattern.
 *
 * Phase 1 SDK surface. The full transport implementation lands when
 * `packages/web-zk-prover` exposes a browser-side Groth16 prover.
 */

import type { DarkPoolClient } from "../client.js";
import type { TransactionCallbacks } from "../providers.js";
import { DarkPoolError } from "../errors.js";

export interface WithdrawParams {
  tokenMint: Uint8Array;
  amount: bigint;
  destination: Uint8Array;         // Solana pubkey
  notePlaintext: {
    tokenMint: Uint8Array;
    amount: bigint;
    ownerCommitment: bigint;
    nonce: bigint;
    blindingR: bigint;
  };
  leafIndex: bigint;
  callbacks?: TransactionCallbacks;
}

export interface WithdrawReceipt {
  signature: string;
  nullifier: Uint8Array;           // 32 bytes BE
}

export function getWithdrawFunction(
  { client }: { client: DarkPoolClient },
): (params: WithdrawParams) => Promise<WithdrawReceipt> {
  return async (params) => {
    await params.callbacks?.pre?.("merkle-proof-fetch");
    const _proof = await client.providers.merkleProofProvider.getInclusionProof(
      params.leafIndex,
    );

    await params.callbacks?.pre?.("proof-generation");
    // TODO(phase-1.1): call client.zkProver.spend.prove(spendInputs).
    // For now, tests prove via snarkjs directly in Rust.

    throw new DarkPoolError(
      "instruction-build",
      "withdraw() SDK path is scaffolded — on-chain tests cover Phase 1. " +
        "Full SDK transport will land with packages/web-zk-prover integration.",
    );
  };
}
