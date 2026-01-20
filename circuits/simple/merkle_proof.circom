pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Merkle Proof Circuit
 *
 * Proves: A leaf is part of a Merkle tree with a known root
 *         without revealing which leaf or its position.
 *
 * Use cases:
 * - Set membership (prove you're in a whitelist)
 * - Asset ownership (prove you own an asset in a collection)
 * - Voting eligibility (prove you're an eligible voter)
 */

template MerkleProof(depth) {
    // Private inputs
    signal input leaf;                    // The leaf value to prove membership
    signal input pathElements[depth];     // Sibling nodes along the path
    signal input pathIndices[depth];      // 0 = left, 1 = right at each level

    // Public input/output
    signal input root;                    // The Merkle root to verify against
    signal output verified;               // 1 if proof is valid

    // Hash function for internal nodes
    component hashers[depth];
    component mux[depth];

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Path index must be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        hashers[i] = Poseidon(2);
        mux[i] = MultiMux1(2);

        // Select order based on path index
        // If pathIndices[i] == 0: hash(current, sibling)
        // If pathIndices[i] == 1: hash(sibling, current)
        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== hashers[i].out;
    }

    // Verify computed root matches expected root
    verified <== hashes[depth] - root == 0 ? 1 : 0;

    // Actually this needs to be a proper equality constraint
    hashes[depth] === root;
}

// Depth 20 tree can hold 2^20 = ~1 million leaves
component main {public [root, verified]} = MerkleProof(20);
