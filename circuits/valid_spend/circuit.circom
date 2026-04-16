pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// Merkle tree membership proof using Poseidon(arity=2) at each level.
// Matches the on-chain light-concurrent-merkle-tree node hashing convention:
// parent = Poseidon(left, right).
template MerkleTreeChecker(depth) {
    signal input leaf;
    signal input root;
    signal input pathElements[depth];
    // pathIndices[i] = 0 if the sibling is on the right (current node is left child).
    // pathIndices[i] = 1 if the sibling is on the left  (current node is right child).
    signal input pathIndices[depth];

    component hashers[depth];
    component switchers[depth];

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Ensure pathIndices[i] is boolean.
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== levelHashes[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root === levelHashes[depth];
}

// VALID_SPEND
//
// Proves:
//   1. Prover knows a note plaintext whose commitment is in the on-chain Merkle tree.
//   2. Prover knows the spending key that owns the note.
//   3. Nullifier is correctly derived.
//   4. Amount matches the note amount (declared publicly for the withdraw instruction).
//
// Public inputs: merkleRoot, nullifier, tokenMint[2] (lo|hi 128-bit halves), amount
// Private witnesses: spendingKey, ownerCommitmentBlinding, nonce, blindingR,
//                    merklePath[depth], merkleIndices[depth]
template ValidSpend(merkleDepth) {
    // ----- Public inputs -----
    signal input merkleRoot;
    signal input nullifier;
    signal input tokenMint[2];   // [lo_u128, hi_u128]
    signal input amount;

    // ----- Private witnesses -----
    signal input spendingKey;
    signal input ownerCommitmentBlinding;  // r_owner used in owner_commitment
    signal input nonce;
    signal input blindingR;
    signal input merklePath[merkleDepth];
    signal input merkleIndices[merkleDepth];

    // Constraint: owner_commitment = Poseidon2(spendingKey, ownerCommitmentBlinding)
    component ownerHash = Poseidon(2);
    ownerHash.inputs[0] <== spendingKey;
    ownerHash.inputs[1] <== ownerCommitmentBlinding;
    signal ownerCommitment;
    ownerCommitment <== ownerHash.out;

    // Constraint: note commitment correctly formed
    // C(note) = Poseidon6(tokenMint[0], tokenMint[1], amount, ownerCommitment, nonce, blindingR)
    component noteHash = Poseidon(6);
    noteHash.inputs[0] <== tokenMint[0];
    noteHash.inputs[1] <== tokenMint[1];
    noteHash.inputs[2] <== amount;
    noteHash.inputs[3] <== ownerCommitment;
    noteHash.inputs[4] <== nonce;
    noteHash.inputs[5] <== blindingR;
    signal noteCommitment;
    noteCommitment <== noteHash.out;

    // Constraint: note is in the Merkle tree at merkleRoot
    component merkle = MerkleTreeChecker(merkleDepth);
    merkle.leaf <== noteCommitment;
    merkle.root <== merkleRoot;
    for (var i = 0; i < merkleDepth; i++) {
        merkle.pathElements[i] <== merklePath[i];
        merkle.pathIndices[i]  <== merkleIndices[i];
    }

    // Constraint: nullifier = Poseidon2(spendingKey, noteCommitment)
    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== spendingKey;
    nullifierHash.inputs[1] <== noteCommitment;
    nullifier === nullifierHash.out;
}

// Tree depth 20 -> 2^20 = ~1M notes. Sufficient for Phase 1 devnet / mainnet soft launch.
component main { public [merkleRoot, nullifier, tokenMint, amount] } = ValidSpend(20);
