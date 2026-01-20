pragma circom 2.1.0;

// ============================================================================
// TRANSFER CIRCUIT (GAS OPTIMIZED)
// ============================================================================
// Proves: "I'm spending input notes and creating output notes with value conservation"
//
// This is a 2-in-2-out transfer (like Zcash Sapling):
//   - 2 input notes (can be dummy if only using 1)
//   - 2 output notes (can be dummy if only creating 1)
//
// Public inputs (6 total - optimized from 8 to reduce gas):
//   - nullifierHash1, nullifierHash2: Input note nullifiers
//   - outputCommitment1, outputCommitment2: New note commitments
//   - root: Merkle tree root
//   - publicDataHash: Hash of (publicAmount, assetId, extDataHash)
//
// The contract computes publicDataHash on-chain and provides it for verification.
// This reduces the number of public inputs from 8 to 6, saving ~25 Tgas.
//
// Value conservation:
//   input1.amount + input2.amount + publicAmount = output1.amount + output2.amount
//
// ============================================================================

include "utils.circom";

template Transfer(levels) {
    // ========== PUBLIC INPUTS (6 total) ==========
    signal input nullifierHash1;       // First input nullifier
    signal input nullifierHash2;       // Second input nullifier
    signal input outputCommitment1;    // First output commitment
    signal input outputCommitment2;    // Second output commitment
    signal input root;                 // Merkle root
    signal input publicDataHash;       // Hash of (publicAmount, assetId, extDataHash)

    // ========== PRIVATE INPUTS - Public data components ==========
    signal input publicAmount;         // Public in/out amount (can be 0)
    signal input assetId;              // Asset being transferred
    signal input extDataHash;          // Hash of external data

    // ========== PRIVATE INPUTS - Input Note 1 ==========
    signal input inNullifier1;
    signal input inSecret1;
    signal input inAmount1;
    signal input inPathElements1[levels];
    signal input inPathIndices1[levels];

    // ========== PRIVATE INPUTS - Input Note 2 ==========
    signal input inNullifier2;
    signal input inSecret2;
    signal input inAmount2;
    signal input inPathElements2[levels];
    signal input inPathIndices2[levels];

    // ========== PRIVATE INPUTS - Output Note 1 ==========
    signal input outNullifier1;
    signal input outSecret1;
    signal input outAmount1;

    // ========== PRIVATE INPUTS - Output Note 2 ==========
    signal input outNullifier2;
    signal input outSecret2;
    signal input outAmount2;

    // ========== VERIFY PUBLIC DATA HASH ==========
    // publicDataHash = Poseidon(Poseidon(publicAmount, assetId), extDataHash)
    // Tree-style to match 2-input Poseidon on contract side
    component publicDataHash1 = Poseidon(2);
    publicDataHash1.inputs[0] <== publicAmount;
    publicDataHash1.inputs[1] <== assetId;

    component publicDataHashFinal = Poseidon(2);
    publicDataHashFinal.inputs[0] <== publicDataHash1.out;
    publicDataHashFinal.inputs[1] <== extDataHash;

    publicDataHash === publicDataHashFinal.out;

    // ========== VERIFY INPUT NOTE 1 ==========
    component inCommitment1 = Commitment();
    inCommitment1.nullifier <== inNullifier1;
    inCommitment1.secret <== inSecret1;
    inCommitment1.amount <== inAmount1;
    inCommitment1.assetId <== assetId;

    component inMerkle1 = MerkleProof(levels);
    inMerkle1.leaf <== inCommitment1.commitment;
    for (var i = 0; i < levels; i++) {
        inMerkle1.pathElements[i] <== inPathElements1[i];
        inMerkle1.pathIndices[i] <== inPathIndices1[i];
    }

    component inNullifierHash1 = NullifierDerivation();
    inNullifierHash1.nullifier <== inNullifier1;
    inNullifierHash1.leafIndex <== inMerkle1.leafIndex;

    // Check: either valid note OR dummy note (amount = 0)
    component isInput1Dummy = IsZero();
    isInput1Dummy.in <== inAmount1;

    // If not dummy, root must match
    signal rootCheck1;
    rootCheck1 <== (1 - isInput1Dummy.out) * (root - inMerkle1.root);
    rootCheck1 === 0;

    // Nullifier hash must match (even for dummy - we use nullifier 0)
    nullifierHash1 === inNullifierHash1.nullifierHash;

    // ========== VERIFY INPUT NOTE 2 ==========
    component inCommitment2 = Commitment();
    inCommitment2.nullifier <== inNullifier2;
    inCommitment2.secret <== inSecret2;
    inCommitment2.amount <== inAmount2;
    inCommitment2.assetId <== assetId;

    component inMerkle2 = MerkleProof(levels);
    inMerkle2.leaf <== inCommitment2.commitment;
    for (var i = 0; i < levels; i++) {
        inMerkle2.pathElements[i] <== inPathElements2[i];
        inMerkle2.pathIndices[i] <== inPathIndices2[i];
    }

    component inNullifierHash2 = NullifierDerivation();
    inNullifierHash2.nullifier <== inNullifier2;
    inNullifierHash2.leafIndex <== inMerkle2.leafIndex;

    component isInput2Dummy = IsZero();
    isInput2Dummy.in <== inAmount2;

    signal rootCheck2;
    rootCheck2 <== (1 - isInput2Dummy.out) * (root - inMerkle2.root);
    rootCheck2 === 0;

    nullifierHash2 === inNullifierHash2.nullifierHash;

    // ========== VERIFY OUTPUT NOTE 1 ==========
    component outCommitmentCalc1 = Commitment();
    outCommitmentCalc1.nullifier <== outNullifier1;
    outCommitmentCalc1.secret <== outSecret1;
    outCommitmentCalc1.amount <== outAmount1;
    outCommitmentCalc1.assetId <== assetId;

    outputCommitment1 === outCommitmentCalc1.commitment;

    // Amount range check (128 bits for yoctoNEAR amounts)
    component outRange1 = RangeCheck(128);
    outRange1.value <== outAmount1;

    // ========== VERIFY OUTPUT NOTE 2 ==========
    component outCommitmentCalc2 = Commitment();
    outCommitmentCalc2.nullifier <== outNullifier2;
    outCommitmentCalc2.secret <== outSecret2;
    outCommitmentCalc2.amount <== outAmount2;
    outCommitmentCalc2.assetId <== assetId;

    outputCommitment2 === outCommitmentCalc2.commitment;

    // Amount range check (128 bits for yoctoNEAR amounts)
    component outRange2 = RangeCheck(128);
    outRange2.value <== outAmount2;

    // ========== VALUE CONSERVATION ==========
    // inAmount1 + inAmount2 + publicAmount = outAmount1 + outAmount2
    //
    // publicAmount range check (must be within 128 bits)
    // Note: For deposits, publicAmount > 0. For pure transfers, publicAmount = 0.
    // For withdrawals, use the withdraw circuit instead.
    component publicAmountRange = RangeCheck(128);
    publicAmountRange.value <== publicAmount;

    signal totalIn;
    totalIn <== inAmount1 + inAmount2 + publicAmount;

    signal totalOut;
    totalOut <== outAmount1 + outAmount2;

    totalIn === totalOut;

    // ========== PREVENT DOUBLE-SPEND WITHIN TX ==========
    // Nullifiers must be different (unless both are dummy)
    component nullifiersDifferent = IsZero();
    nullifiersDifferent.in <== nullifierHash1 - nullifierHash2;

    // Either nullifiers are different, or both are dummy (amounts = 0)
    signal bothDummy;
    bothDummy <== isInput1Dummy.out * isInput2Dummy.out;

    // (nullifiers different) OR (both dummy)
    signal validNullifiers;
    validNullifiers <== (1 - nullifiersDifferent.out) + bothDummy;

    component validCheck = GreaterThan(2);
    validCheck.in[0] <== validNullifiers;
    validCheck.in[1] <== 0;
    validCheck.out === 1;
}

// 20 levels for ~1M note capacity
// 6 public inputs: nullifierHash1, nullifierHash2, outputCommitment1, outputCommitment2, root, publicDataHash
component main {public [
    nullifierHash1,
    nullifierHash2,
    outputCommitment1,
    outputCommitment2,
    root,
    publicDataHash
]} = Transfer(20);
