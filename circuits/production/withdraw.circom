pragma circom 2.1.0;

// ============================================================================
// WITHDRAW CIRCUIT
// ============================================================================
// Proves: "I own a note in the Merkle tree and I'm spending it correctly"
//
// Public inputs:
//   - nullifierHash: Unique identifier to prevent double-spending
//   - root: Merkle tree root (verified on-chain)
//   - recipient: Address receiving the funds
//   - amount: Amount being withdrawn
//   - assetId: Asset type
//   - fee: Relayer fee (if using relayer)
//   - relayer: Relayer address (or 0 if self-relay)
//
// Private inputs:
//   - nullifier: The note's nullifier
//   - secret: The note's secret
//   - pathElements[]: Merkle proof siblings
//   - pathIndices[]: Merkle proof path (0/1 per level)
//
// Security properties:
//   1. Prover knows the note preimage (nullifier, secret, amount)
//   2. Note exists in the Merkle tree (valid proof to root)
//   3. NullifierHash is correctly derived (prevents double-spend)
//   4. Amount/recipient are bound to the proof (prevents front-running)
// ============================================================================

include "utils.circom";

template Withdraw(levels) {
    // ========== PUBLIC INPUTS ==========
    signal input nullifierHash;     // Prevents double-spending
    signal input root;              // Merkle tree root
    signal input recipient;         // Recipient address (as field element)
    signal input amount;            // Withdrawal amount
    signal input assetId;           // Asset type
    signal input fee;               // Relayer fee
    signal input relayer;           // Relayer address (0 if self-relay)
    
    // ========== PRIVATE INPUTS ==========
    signal input nullifier;         // Note nullifier (secret)
    signal input secret;            // Note secret
    signal input pathElements[levels];  // Merkle proof
    signal input pathIndices[levels];   // Merkle path
    
    // ========== STEP 1: Compute commitment ==========
    component commitmentHasher = Commitment();
    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.secret <== secret;
    commitmentHasher.amount <== amount;
    commitmentHasher.assetId <== assetId;
    
    signal commitment;
    commitment <== commitmentHasher.commitment;
    
    // ========== STEP 2: Verify Merkle proof ==========
    component merkleProof = MerkleProof(levels);
    merkleProof.leaf <== commitment;
    for (var i = 0; i < levels; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }
    
    // Root must match
    root === merkleProof.root;
    
    // ========== STEP 3: Verify nullifier hash ==========
    component nullifierDerivation = NullifierDerivation();
    nullifierDerivation.nullifier <== nullifier;
    nullifierDerivation.leafIndex <== merkleProof.leafIndex;
    
    nullifierHash === nullifierDerivation.nullifierHash;
    
    // ========== STEP 4: Validate amounts ==========
    // Amount must be within valid range (128 bits for yoctoNEAR)
    component amountRange = RangeCheck(128);
    amountRange.value <== amount;

    // Fee must be within valid range
    component feeRange = RangeCheck(128);
    feeRange.value <== fee;

    // Fee must be <= amount
    component feeCheck = LessEqThan(128);
    feeCheck.in[0] <== fee;
    feeCheck.in[1] <== amount;
    feeCheck.out === 1;

    // ========== STEP 5: Bind recipient to proof ==========
    // This is done implicitly by including recipient as public input
    // The proof is only valid for this specific recipient
    // (No additional constraints needed - Groth16 binds public inputs)
}

// Simplified withdraw for fixed asset (native NEAR only)
template WithdrawSimple(levels) {
    // ========== PUBLIC INPUTS ==========
    signal input nullifierHash;
    signal input root;
    signal input recipient;
    signal input amount;
    signal input fee;
    signal input relayer;
    
    // ========== PRIVATE INPUTS ==========
    signal input nullifier;
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Compute commitment (simplified - no assetId)
    component commitmentHasher = CommitmentSimple();
    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.secret <== secret;
    commitmentHasher.amount <== amount;
    
    signal commitment;
    commitment <== commitmentHasher.commitment;
    
    // Verify Merkle proof
    component merkleProof = MerkleProof(levels);
    merkleProof.leaf <== commitment;
    for (var i = 0; i < levels; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }
    root === merkleProof.root;
    
    // Verify nullifier
    component nullifierHasher = NullifierSimple();
    nullifierHasher.nullifier <== nullifier;
    nullifierHash === nullifierHasher.nullifierHash;

    // Validate amounts
    component amountRange = RangeCheck(128);
    amountRange.value <== amount;

    component feeRange = RangeCheck(128);
    feeRange.value <== fee;

    // Fee check
    component feeCheck = LessEqThan(128);
    feeCheck.in[0] <== fee;
    feeCheck.in[1] <== amount;
    feeCheck.out === 1;
}

// 20 levels = 2^20 = ~1 million notes capacity
component main {public [nullifierHash, root, recipient, amount, assetId, fee, relayer]} = Withdraw(20);

// For simple version:
// component main {public [nullifierHash, root, recipient, amount, fee, relayer]} = WithdrawSimple(20);
