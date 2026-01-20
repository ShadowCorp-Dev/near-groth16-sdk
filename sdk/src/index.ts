/**
 * NEAR Groth16 SDK
 *
 * Complete TypeScript SDK for building privacy-preserving applications on NEAR Protocol.
 *
 * ## Quick Start
 *
 * ```typescript
 * import {
 *     verifyProof,
 *     generateProof,
 *     IncrementalMerkleTree,
 *     saveNote,
 *     getNotes
 * } from '@near-zk/groth16-sdk';
 * import { NearConnector } from '@hot-labs/near-connect';
 * import { poseidon } from 'circomlibjs';
 *
 * // 1. Connect wallet
 * const connector = new NearConnector({ network: 'mainnet' });
 * await connector.signIn();
 *
 * // 2. Build Merkle tree
 * const tree = new IncrementalMerkleTree(20, poseidon);
 * tree.insert(commitment);
 *
 * // 3. Generate proof
 * const { proof, publicSignals } = await generateProof(
 *     witnessInput,
 *     '/circuits/circuit.wasm',
 *     '/circuits/circuit.zkey'
 * );
 *
 * // 4. Submit to contract
 * await verifyProof(connector, 'verifier.near', proof, publicSignals);
 * ```
 *
 * ## Modules
 *
 * - **wallet**: Wallet connection and transaction formatting
 * - **prover**: Proof generation with snarkjs
 * - **merkle**: Client-side Merkle tree implementation
 * - **notes**: Note management and UTXO tracking
 *
 * ## Architecture
 *
 * ```
 * ┌─────────────┐
 * │   Browser   │
 * └──────┬──────┘
 *        │
 *        ├─ Wallet Integration (wallet.ts)
 *        │  └─ HOT Wallet compatible
 *        │  └─ Proper action format
 *        │  └─ signerId handling
 *        │
 *        ├─ Proof Generation (prover.ts)
 *        │  └─ snarkjs WASM
 *        │  └─ Progress tracking
 *        │  └─ Local verification
 *        │
 *        ├─ Merkle Trees (merkle.ts)
 *        │  └─ Incremental insertion
 *        │  └─ Proof generation
 *        │  └─ Tree synchronization
 *        │
 *        └─ Note Management (notes.ts)
 *           └─ UTXO tracking
 *           └─ Balance calculation
 *           └─ Note selection
 * ```
 *
 * ## Production Patterns
 *
 * ### 1. Deposit Flow
 * ```typescript
 * // User deposits NEAR into shielded pool
 * const note = createNote(amount, assetId);
 * const commitment = await note.commitment();
 *
 * // Save note BEFORE sending transaction
 * saveNote(userPublicKey, note);
 *
 * // Send deposit transaction
 * await deposit(connector, contractId, amount, commitment);
 * ```
 *
 * ### 2. Transfer Flow
 * ```typescript
 * // Select notes to spend
 * const inputNotes = getSpendableNotes(userPublicKey, assetId, amount);
 *
 * // Build Merkle proofs
 * const tree = await syncTreeWithContract(contractId);
 * const proof1 = tree.getProof(inputNotes[0].leafIndex);
 * const proof2 = tree.getProof(inputNotes[1].leafIndex);
 *
 * // Generate ZK proof
 * const witnessInput = buildTransferWitness(inputNotes, outputNotes, proofs);
 * const { proof, publicSignals } = await generateProof(witnessInput, wasm, zkey);
 *
 * // Submit transaction
 * await verifyAndRegister(connector, contractId, proof, publicSignals);
 *
 * // Mark input notes as spent
 * markSpent(userPublicKey, inputNotes[0].commitment);
 * markSpent(userPublicKey, inputNotes[1].commitment);
 * ```
 *
 * ### 3. Withdraw Flow
 * ```typescript
 * // Similar to transfer, but publicAmount is negative
 * const publicAmount = "-1000000000000000000000000"; // -1 NEAR
 * const witnessInput = buildWithdrawWitness(inputNote, recipient, publicAmount);
 *
 * // Generate and submit proof
 * const { proof, publicSignals } = await generateProof(witnessInput, wasm, zkey);
 * await verifyAndRegister(connector, contractId, proof, publicSignals);
 * ```
 *
 * ## Gas Optimization
 *
 * - Use public input compression (hash packing) to reduce gas
 * - Verify proofs locally before submitting to contract
 * - Batch multiple operations when possible
 * - Pre-compute witness inputs to reduce client-side latency
 *
 * ## Security Considerations
 *
 * - Notes stored in localStorage are visible to browser extensions
 * - Production apps should encrypt notes client-side
 * - Never expose nullifiers until ready to spend
 * - Always verify proofs locally before contract submission
 * - Use secure random number generation for secrets
 *
 * @packageDocumentation
 */

// Wallet integration
export {
    verifyProof,
    verifyAndRegister,
    initializeVerifier,
    isNullifierUsed,
    utils as walletUtils,
    type ProofJson
} from './wallet';

// Proof generation
export {
    generateProof,
    generateProofWithProgress,
    verifyProofLocally,
    exportVerificationKey,
    type WitnessInput,
    type ProofResult
} from './prover';

// Merkle trees
export {
    IncrementalMerkleTree,
    verifyMerkleProof,
    type MerkleProof
} from './merkle';

// Note management
export {
    saveNote,
    getNotes,
    markSpent,
    getSpendableNotes,
    getTotalBalance,
    createDummyNote,
    exportNotes,
    importNotes,
    type Note
} from './notes';
