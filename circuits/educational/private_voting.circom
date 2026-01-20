pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Private Voting Circuit
 *
 * Proves:
 * 1. Voter is in the set of eligible voters (via Merkle proof)
 * 2. This is their only vote (via nullifier)
 * 3. Vote is valid (0 or 1 for yes/no)
 *
 * Properties:
 * - Voter anonymity: Vote cannot be linked to voter
 * - Uniqueness: Each voter can only vote once
 * - Verifiability: Anyone can verify the proof is valid
 */

template PrivateVoting(voterTreeDepth) {
    // Private inputs
    signal input voterId;                              // Voter's secret identifier
    signal input voterSecret;                          // Voter's secret key
    signal input voterPathElements[voterTreeDepth];    // Merkle proof path
    signal input voterPathIndices[voterTreeDepth];     // Merkle proof indices
    signal input vote;                                 // 0 or 1

    // Public inputs
    signal input voterTreeRoot;    // Root of eligible voters Merkle tree
    signal input pollId;           // Unique poll identifier

    // Public outputs
    signal output nullifier;       // Prevents double voting
    signal output voteCommitment;  // Encrypted/committed vote

    // 1. Verify vote is binary (0 or 1)
    vote * (1 - vote) === 0;

    // 2. Compute voter leaf = hash(voterId, voterSecret)
    component voterLeafHash = Poseidon(2);
    voterLeafHash.inputs[0] <== voterId;
    voterLeafHash.inputs[1] <== voterSecret;
    signal voterLeaf;
    voterLeaf <== voterLeafHash.out;

    // 3. Verify Merkle proof
    component merkleHashers[voterTreeDepth];
    component mux[voterTreeDepth];
    signal hashes[voterTreeDepth + 1];
    hashes[0] <== voterLeaf;

    for (var i = 0; i < voterTreeDepth; i++) {
        voterPathIndices[i] * (1 - voterPathIndices[i]) === 0;

        merkleHashers[i] = Poseidon(2);
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== voterPathElements[i];
        mux[i].c[1][0] <== voterPathElements[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== voterPathIndices[i];

        merkleHashers[i].inputs[0] <== mux[i].out[0];
        merkleHashers[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== merkleHashers[i].out;
    }

    // Verify root matches
    hashes[voterTreeDepth] === voterTreeRoot;

    // 4. Compute nullifier = hash(voterSecret, pollId)
    // This is unique per voter per poll
    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== voterSecret;
    nullifierHash.inputs[1] <== pollId;
    nullifier <== nullifierHash.out;

    // 5. Compute vote commitment = hash(vote, voterSecret, pollId)
    component voteHash = Poseidon(3);
    voteHash.inputs[0] <== vote;
    voteHash.inputs[1] <== voterSecret;
    voteHash.inputs[2] <== pollId;
    voteCommitment <== voteHash.out;
}

// Support up to 2^15 = 32,768 voters
component main {public [voterTreeRoot, pollId, nullifier, voteCommitment]} = PrivateVoting(15);
