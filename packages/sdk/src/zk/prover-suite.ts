/**
 * IDarkPoolZkProverSuite — one interface per circuit. Swappable between
 * browser (snarkjs WASM) and relayer (ark-groth16 native).
 *
 * Only Phase 1 circuits are declared. Phase 4-5 circuits (VALID_CREATE,
 * VALID_PRICE, VALID_SOLVENCY) will extend this interface.
 */

export interface Groth16ProofBytes {
  piA: Uint8Array; // 64 bytes, NOT yet negated — on-chain wrapper negates.
  piB: Uint8Array; // 128 bytes
  piC: Uint8Array; // 64 bytes
  publicInputs: Uint8Array[]; // each 32 BE bytes
}

export interface WalletCreateInputs {
  userCommitment: bigint;
  rootKey: [bigint, bigint]; // [lo, hi]
  spendingKey: bigint;
  viewingKey: bigint;
  r0: bigint;
  r1: bigint;
  r2: bigint;
}

export interface SpendInputs {
  merkleRoot: bigint;
  nullifier: bigint;
  tokenMint: [bigint, bigint];
  amount: bigint;
  spendingKey: bigint;
  ownerCommitmentBlinding: bigint;
  nonce: bigint;
  blindingR: bigint;
  merklePath: bigint[]; // length 20
  merkleIndices: number[]; // length 20, 0 or 1
}

export interface IDarkPoolZkProverSuite {
  walletCreate: {
    prove(inputs: WalletCreateInputs): Promise<Groth16ProofBytes>;
  };
  spend: {
    prove(inputs: SpendInputs): Promise<Groth16ProofBytes>;
  };
}
