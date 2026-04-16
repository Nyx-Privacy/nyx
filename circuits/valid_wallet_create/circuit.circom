pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// VALID_WALLET_CREATE
//
// Proves the prover correctly computed a User Commitment from knowledge of the
// three keys plus their individual blinding factors. The on-chain program then
// registers `userCommitment` in the wallet registry.
//
// User Commitment Merkle definition (3 leaves, padded to next power of 2):
//   leafRoot     = Poseidon2(rootHash, spendingHash)
//   userCommit   = Poseidon2(leafRoot, viewingHash)
//
// Where each leaf is:
//   rootHash     = Poseidon2(rootKeyLow, rootKeyHigh, r0)  (Ed25519 pubkey split 128/128 + blinding)
//   spendingHash = Poseidon2(spendingKey, r1)
//   viewingHash  = Poseidon2(viewingKey, r2)
//
// (Keeping the Merkle shape very simple for Phase 1 — a flat Poseidon chain
// with explicit blinding factors per leaf. Matches Section 20.2 of the spec.)
//
// Public inputs:  userCommitment
// Private inputs: rootKey[2] (lo|hi 128-bit halves of Ed25519 pubkey),
//                 spendingKey, viewingKey, r0, r1, r2
template ValidWalletCreate() {
    // ----- Public -----
    signal input userCommitment;

    // ----- Private -----
    signal input rootKey[2];   // Ed25519 pubkey split [lo_u128, hi_u128]
    signal input spendingKey;
    signal input viewingKey;
    signal input r0;
    signal input r1;
    signal input r2;

    // Range checks: all field elements must be < BN254_r. This is automatic
    // in circom since all signals live in Fr. We don't need explicit bit
    // decomposition here — the field-arithmetic constraints enforce it.

    // rootHash = Poseidon3(rootKey[0], rootKey[1], r0)
    component rootHasher = Poseidon(3);
    rootHasher.inputs[0] <== rootKey[0];
    rootHasher.inputs[1] <== rootKey[1];
    rootHasher.inputs[2] <== r0;

    // spendingHash = Poseidon2(spendingKey, r1)
    component spendHasher = Poseidon(2);
    spendHasher.inputs[0] <== spendingKey;
    spendHasher.inputs[1] <== r1;

    // viewingHash = Poseidon2(viewingKey, r2)
    component viewHasher = Poseidon(2);
    viewHasher.inputs[0] <== viewingKey;
    viewHasher.inputs[1] <== r2;

    // leafRoot = Poseidon2(rootHash, spendingHash)
    component leafPair = Poseidon(2);
    leafPair.inputs[0] <== rootHasher.out;
    leafPair.inputs[1] <== spendHasher.out;

    // userCommit = Poseidon2(leafRoot, viewingHash)
    component topHasher = Poseidon(2);
    topHasher.inputs[0] <== leafPair.out;
    topHasher.inputs[1] <== viewHasher.out;

    userCommitment === topHasher.out;
}

component main { public [userCommitment] } = ValidWalletCreate();
