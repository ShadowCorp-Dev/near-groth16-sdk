pragma circom 2.1.0;

// ============================================================================
// Shielded Wallet Utilities
// ============================================================================
// Core building blocks for the shielded wallet:
// - Commitment scheme (Poseidon-based)
// - Nullifier derivation
// - Merkle tree verification
// ============================================================================

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/switcher.circom";

// ============================================================================
// COMMITMENT SCHEME
// ============================================================================
// Commitment = Poseidon(Poseidon(nullifier, secret), Poseidon(amount, assetId))
// This tree-style hash matches the contract's Poseidon implementation
// which only supports t=3 (2-input) Poseidon hash
// ============================================================================

template Commitment() {
    signal input nullifier;
    signal input secret;
    signal input amount;
    signal input assetId;

    signal output commitment;

    // Tree-style hash: hash(hash(a,b), hash(c,d))
    component hash1 = Poseidon(2);
    hash1.inputs[0] <== nullifier;
    hash1.inputs[1] <== secret;

    component hash2 = Poseidon(2);
    hash2.inputs[0] <== amount;
    hash2.inputs[1] <== assetId;

    component hashFinal = Poseidon(2);
    hashFinal.inputs[0] <== hash1.out;
    hashFinal.inputs[1] <== hash2.out;

    commitment <== hashFinal.out;
}

// Simplified commitment for fixed asset (e.g., native NEAR)
template CommitmentSimple() {
    signal input nullifier;
    signal input secret;
    signal input amount;
    
    signal output commitment;
    
    component hasher = Poseidon(3);
    hasher.inputs[0] <== nullifier;
    hasher.inputs[1] <== secret;
    hasher.inputs[2] <== amount;
    
    commitment <== hasher.out;
}

// ============================================================================
// NULLIFIER DERIVATION
// ============================================================================
// NullifierHash = Poseidon(nullifier, pathIndex)
// pathIndex ensures unique nullifier per leaf position
// ============================================================================

template NullifierDerivation() {
    signal input nullifier;
    signal input leafIndex;
    
    signal output nullifierHash;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== nullifier;
    hasher.inputs[1] <== leafIndex;
    
    nullifierHash <== hasher.out;
}

// Alternative: Simple nullifier (just hash the nullifier)
template NullifierSimple() {
    signal input nullifier;
    
    signal output nullifierHash;
    
    component hasher = Poseidon(1);
    hasher.inputs[0] <== nullifier;
    
    nullifierHash <== hasher.out;
}

// ============================================================================
// MERKLE TREE
// ============================================================================
// Binary Merkle tree with Poseidon hash
// Supports up to 2^levels leaves
// ============================================================================

// Hash two children to get parent
template MerkleHash() {
    signal input left;
    signal input right;
    
    signal output hash;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    
    hash <== hasher.out;
}

// Single level of Merkle proof verification
template MerkleLevel() {
    signal input current;      // Current hash
    signal input sibling;      // Sibling hash from proof
    signal input pathBit;      // 0 = current is left, 1 = current is right
    
    signal output parent;
    
    // Switcher: if pathBit=0, (current, sibling), else (sibling, current)
    component switcher = Switcher();
    switcher.sel <== pathBit;
    switcher.L <== current;
    switcher.R <== sibling;
    
    component hasher = MerkleHash();
    hasher.left <== switcher.outL;
    hasher.right <== switcher.outR;
    
    parent <== hasher.hash;
}

// Full Merkle proof verification
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];  // Binary path (0/1 per level)
    
    signal output root;
    signal output leafIndex;  // Computed leaf index from path
    
    // Verify each level
    component levels_[levels];
    signal hashes[levels + 1];
    hashes[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        levels_[i] = MerkleLevel();
        levels_[i].current <== hashes[i];
        levels_[i].sibling <== pathElements[i];
        levels_[i].pathBit <== pathIndices[i];
        hashes[i + 1] <== levels_[i].parent;
    }
    
    root <== hashes[levels];
    
    // Compute leaf index from path indices (binary to decimal)
    component bits2num = Bits2Num(levels);
    for (var i = 0; i < levels; i++) {
        bits2num.in[i] <== pathIndices[i];
    }
    leafIndex <== bits2num.out;
}

// ============================================================================
// RANGE CHECKS
// ============================================================================
// Ensure values are within valid ranges
// ============================================================================

// Check that value < 2^n
template RangeCheck(n) {
    signal input value;
    
    component bits = Num2Bits(n);
    bits.in <== value;
    // If value >= 2^n, Num2Bits will fail
}

// Check that value is non-zero
template NonZero() {
    signal input value;
    signal output out;

    signal inv;
    inv <-- 1 / value;  // Hint: compute inverse

    // Constrain that inv is actually the inverse of value
    inv * value === 1;

    // Output is always 1 if constraint passes
    out <== 1;
}

// ============================================================================
// ASSET ID HANDLING
// ============================================================================
// Asset ID 0 = native NEAR
// Other IDs = fungible tokens
// ============================================================================

template AssetCheck() {
    signal input assetId;
    signal input expectedAssetId;
    
    assetId === expectedAssetId;
}

// ============================================================================
// NOTE STRUCTURE
// ============================================================================
// A "note" represents a shielded UTXO
// Note = (nullifier, secret, amount, assetId)
// Commitment = Hash(Note)
// ============================================================================

template Note() {
    // Private inputs (known only to owner)
    signal input nullifier;
    signal input secret;
    signal input amount;
    signal input assetId;
    
    // Outputs
    signal output commitment;
    signal output nullifierHash;
    
    // Compute commitment
    component commitmentHasher = Commitment();
    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.secret <== secret;
    commitmentHasher.amount <== amount;
    commitmentHasher.assetId <== assetId;
    commitment <== commitmentHasher.commitment;
    
    // Compute nullifier hash (for spending)
    component nullifierHasher = NullifierSimple();
    nullifierHasher.nullifier <== nullifier;
    nullifierHash <== nullifierHasher.nullifierHash;
}
