pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsamimc.circom";
include "circomlib/circuits/mux1.circom";

/*
 * Ownership Proof Circuit
 *
 * Proves: User owns an asset registered in a Merkle tree
 *         without revealing which asset or their identity.
 *
 * Use cases:
 * - NFT ownership verification
 * - Token balance proofs
 * - Asset authentication
 */

template OwnershipProof(treeDepth) {
    // Private inputs
    signal input assetId;                        // The asset identifier
    signal input ownerSecret;                    // Owner's secret key
    signal input ownerPublicKey[2];              // Owner's EdDSA public key (x, y)
    signal input pathElements[treeDepth];        // Merkle proof siblings
    signal input pathIndices[treeDepth];         // Merkle proof indices

    // Public inputs
    signal input assetTreeRoot;                  // Root of asset ownership tree
    signal input challenge;                      // Random challenge for freshness

    // Public outputs
    signal output ownershipProof;                // Proof identifier

    // 1. Compute asset leaf = hash(assetId, ownerPublicKeyHash)
    component ownerKeyHash = Poseidon(2);
    ownerKeyHash.inputs[0] <== ownerPublicKey[0];
    ownerKeyHash.inputs[1] <== ownerPublicKey[1];

    component assetLeafHash = Poseidon(2);
    assetLeafHash.inputs[0] <== assetId;
    assetLeafHash.inputs[1] <== ownerKeyHash.out;
    signal assetLeaf;
    assetLeaf <== assetLeafHash.out;

    // 2. Verify Merkle proof
    component merkleHashers[treeDepth];
    component mux[treeDepth];
    signal hashes[treeDepth + 1];
    hashes[0] <== assetLeaf;

    for (var i = 0; i < treeDepth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        merkleHashers[i] = Poseidon(2);
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== pathIndices[i];

        merkleHashers[i].inputs[0] <== mux[i].out[0];
        merkleHashers[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== merkleHashers[i].out;
    }

    // Root must match
    hashes[treeDepth] === assetTreeRoot;

    // 3. Generate ownership proof using challenge
    // This proves knowledge of ownerSecret without revealing it
    component proofHash = Poseidon(3);
    proofHash.inputs[0] <== ownerSecret;
    proofHash.inputs[1] <== assetId;
    proofHash.inputs[2] <== challenge;
    ownershipProof <== proofHash.out;
}

// Tree depth 20 supports ~1 million assets
component main {public [assetTreeRoot, challenge, ownershipProof]} = OwnershipProof(20);
