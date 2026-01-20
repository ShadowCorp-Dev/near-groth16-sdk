pragma circom 2.1.0;

// ============================================================================
// DEPOSIT CIRCUIT
// ============================================================================
// Proves: "I know the preimage of this commitment"
// 
// Public inputs:
//   - commitment: The note commitment to be added to the Merkle tree
//   - amount: The deposit amount (public for contract to verify payment)
//   - assetId: The asset being deposited
//
// Private inputs:
//   - nullifier: Random value for future spending
//   - secret: Random value for hiding
//
// This circuit is simple because deposits don't require privacy -
// we just need to prove the commitment is correctly formed.
// ============================================================================

include "utils.circom";

template Deposit() {
    // ========== PUBLIC INPUTS ==========
    signal input commitment;    // The commitment to add to tree
    signal input amount;        // Amount being deposited
    signal input assetId;       // Asset type (0 = NEAR)
    
    // ========== PRIVATE INPUTS ==========
    signal input nullifier;     // Random nullifier for spending
    signal input secret;        // Random secret for hiding
    
    // ========== CONSTRAINTS ==========
    
    // 1. Verify commitment is correctly computed
    component commitmentCheck = Commitment();
    commitmentCheck.nullifier <== nullifier;
    commitmentCheck.secret <== secret;
    commitmentCheck.amount <== amount;
    commitmentCheck.assetId <== assetId;
    
    // Commitment must match
    commitment === commitmentCheck.commitment;
    
    // 2. Amount must be positive (within 128-bit range for NEAR amounts)
    component amountRange = RangeCheck(128);
    amountRange.value <== amount;
    
    // 3. Nullifier must be non-zero (prevents trivial nullifiers)
    component nullifierNonZero = NonZero();
    nullifierNonZero.value <== nullifier;
}

// For deposits with only native token (simplified)
template DepositSimple() {
    // ========== PUBLIC INPUTS ==========
    signal input commitment;
    signal input amount;
    
    // ========== PRIVATE INPUTS ==========
    signal input nullifier;
    signal input secret;
    
    // Verify commitment
    component commitmentCheck = CommitmentSimple();
    commitmentCheck.nullifier <== nullifier;
    commitmentCheck.secret <== secret;
    commitmentCheck.amount <== amount;
    
    commitment === commitmentCheck.commitment;
    
    // Range check
    component amountRange = RangeCheck(128);
    amountRange.value <== amount;
}

// Main component - choose which version to use
component main {public [commitment, amount, assetId]} = Deposit();

// For simple version:
// component main {public [commitment, amount]} = DepositSimple();
