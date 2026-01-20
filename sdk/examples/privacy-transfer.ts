/**
 * Complete Example: Privacy-Preserving Token Transfer on NEAR
 *
 * This example demonstrates a full end-to-end privacy transfer using:
 * - @near-zk/groth16-sdk for ZK proof generation
 * - @hot-labs/near-connect for wallet integration
 * - circomlibjs for Poseidon hashing
 *
 * SCENARIO:
 * Alice wants to send 1 NEAR to Bob privately, without revealing:
 * - That Alice is the sender
 * - That Bob is the recipient
 * - The amount being transferred
 *
 * PREREQUISITES:
 * 1. Deploy privacy contract with verification key
 * 2. Compile transfer circuit (transfer.circom)
 * 3. Alice has deposited NEAR into the shielded pool
 * 4. Bob has shared his shielded public key with Alice
 */

import { NearConnector } from '@hot-labs/near-connect';
import { poseidon } from 'circomlibjs';
import {
    generateProof,
    verifyProofLocally,
    IncrementalMerkleTree,
    getNotes,
    saveNote,
    markSpent,
    getSpendableNotes,
    verifyAndRegister,
    type Note
} from '@near-zk/groth16-sdk';

// Contract addresses
const PRIVACY_CONTRACT = 'privacy.near';
const WASM_PATH = '/circuits/transfer.wasm';
const ZKEY_PATH = '/circuits/transfer_final.zkey';
const VK_PATH = '/circuits/verification_key.json';

// Alice's shielded key (would come from secure storage)
const ALICE_SHIELDED_KEY = '0xalice...';

// Bob's shielded public key (received out-of-band)
const BOB_PUBLIC_KEY = '0xbob...';

/**
 * Step 1: Connect wallet
 */
async function connectWallet(): Promise<NearConnector> {
    console.log('Connecting wallet...');

    const connector = new NearConnector({ network: 'mainnet' });
    await connector.signIn();

    const wallet = await connector.wallet();
    const accounts = await wallet.getAccounts();

    console.log('✓ Connected as:', accounts[0].accountId);

    return connector;
}

/**
 * Step 2: Sync Merkle tree with contract
 *
 * We need the latest Merkle tree to generate valid inclusion proofs.
 */
async function syncMerkleTree(): Promise<IncrementalMerkleTree> {
    console.log('Syncing Merkle tree...');

    // In production, fetch commitments from contract:
    // const commitments = await contract.get_commitments_range({ from: 0, limit: 1000 });

    // For this example, assume we have cached commitments
    const commitments: string[] = [
        // Array of commitment hashes from previous deposits
    ];

    // Build tree
    const tree = IncrementalMerkleTree.fromCommitments(
        commitments.map(c => BigInt(c)),
        20,  // Tree depth (supports 1M leaves)
        poseidon
    );

    console.log('✓ Tree synced with', tree.getLeafCount(), 'leaves');
    console.log('✓ Current root:', tree.getRoot().toString());

    return tree;
}

/**
 * Step 3: Select input notes to spend
 *
 * Alice needs to select notes that cover the transfer amount + fee.
 */
function selectInputNotes(transferAmount: bigint): [Note, Note] {
    console.log('Selecting input notes...');

    // Get Alice's unspent notes
    const spendableNotes = getSpendableNotes(
        ALICE_SHIELDED_KEY,
        '0',  // assetId: 0 = NEAR
        transferAmount.toString()
    );

    if (spendableNotes.length === 0) {
        throw new Error('No unspent notes available');
    }

    // For 2-in-2-out circuit, we need exactly 2 input notes
    const note1 = spendableNotes[0];

    // If we only have 1 note, use a dummy note for the second input
    const note2 = spendableNotes.length > 1
        ? spendableNotes[1]
        : {
            nullifier: '0',
            secret: '0',
            amount: '0',  // Dummy note with zero amount
            assetId: '0',
            commitment: '0',
            leafIndex: 0,
            spent: false,
            createdAt: Date.now(),
            sourceType: 'deposit' as const
        };

    const totalInput = BigInt(note1.amount) + BigInt(note2.amount);
    console.log('✓ Selected notes with total:', totalInput.toString(), 'yoctoNEAR');

    return [note1, note2];
}

/**
 * Step 4: Create output notes
 *
 * - Output 1: For Bob (the transfer amount)
 * - Output 2: For Alice (change)
 */
function createOutputNotes(
    inputTotal: bigint,
    transferAmount: bigint
): [Partial<Note>, Partial<Note>] {
    console.log('Creating output notes...');

    // Output 1: For Bob
    const bobNote = {
        nullifier: generateRandomField(),  // New random nullifier
        secret: generateRandomField(),      // New random secret
        amount: transferAmount.toString(),
        assetId: '0',
        // Commitment would be computed: poseidon([nullifier, secret, amount, assetId])
    };

    // Output 2: Change for Alice
    const changeAmount = inputTotal - transferAmount;
    const aliceChangeNote = {
        nullifier: generateRandomField(),
        secret: generateRandomField(),
        amount: changeAmount.toString(),
        assetId: '0',
    };

    console.log('✓ Output 1 (Bob):', transferAmount.toString());
    console.log('✓ Output 2 (Alice change):', changeAmount.toString());

    return [bobNote, aliceChangeNote];
}

/**
 * Step 5: Build witness input for circuit
 *
 * This is the most complex part - we need to format all circuit inputs correctly.
 */
async function buildWitnessInput(
    inputNotes: [Note, Note],
    outputNotes: [Partial<Note>, Partial<Note>],
    tree: IncrementalMerkleTree
): Promise<Record<string, any>> {
    console.log('Building witness input...');

    // Get Merkle proofs for input notes
    const proof1 = tree.getProof(inputNotes[0].leafIndex);
    const proof2 = inputNotes[1].amount !== '0'
        ? tree.getProof(inputNotes[1].leafIndex)
        : { pathElements: [], pathIndices: [] };  // Dummy proof

    // Compute nullifier hashes
    const nullifierHash1 = poseidon([
        BigInt(inputNotes[0].nullifier),
        BigInt(inputNotes[0].leafIndex)
    ]);
    const nullifierHash2 = poseidon([
        BigInt(inputNotes[1].nullifier),
        BigInt(inputNotes[1].leafIndex)
    ]);

    // Compute output commitments
    const outputCommitment1 = poseidon([
        BigInt(outputNotes[0].nullifier!),
        BigInt(outputNotes[0].secret!),
        BigInt(outputNotes[0].amount!),
        BigInt(outputNotes[0].assetId!)
    ]);
    const outputCommitment2 = poseidon([
        BigInt(outputNotes[1].nullifier!),
        BigInt(outputNotes[1].secret!),
        BigInt(outputNotes[1].amount!),
        BigInt(outputNotes[1].assetId!)
    ]);

    // Compute publicDataHash (gas optimization)
    const publicAmount = 0n;  // Private transfer (no public in/out)
    const assetId = 0n;
    const extDataHash = 0n;

    const publicDataHash1 = poseidon([publicAmount, assetId]);
    const publicDataHash = poseidon([publicDataHash1, extDataHash]);

    const witness = {
        // Public inputs (6 total)
        nullifierHash1: nullifierHash1.toString(),
        nullifierHash2: nullifierHash2.toString(),
        outputCommitment1: outputCommitment1.toString(),
        outputCommitment2: outputCommitment2.toString(),
        root: tree.getRoot().toString(),
        publicDataHash: publicDataHash.toString(),

        // Private inputs - public data components
        publicAmount: publicAmount.toString(),
        assetId: assetId.toString(),
        extDataHash: extDataHash.toString(),

        // Private inputs - Input note 1
        inNullifier1: inputNotes[0].nullifier,
        inSecret1: inputNotes[0].secret,
        inAmount1: inputNotes[0].amount,
        inPathElements1: proof1.pathElements.map(e => e.toString()),
        inPathIndices1: proof1.pathIndices,

        // Private inputs - Input note 2
        inNullifier2: inputNotes[1].nullifier,
        inSecret2: inputNotes[1].secret,
        inAmount2: inputNotes[1].amount,
        inPathElements2: proof2.pathElements?.map(e => e.toString()) || [],
        inPathIndices2: proof2.pathIndices || [],

        // Private inputs - Output note 1 (Bob)
        outNullifier1: outputNotes[0].nullifier,
        outSecret1: outputNotes[0].secret,
        outAmount1: outputNotes[0].amount,

        // Private inputs - Output note 2 (Alice change)
        outNullifier2: outputNotes[1].nullifier,
        outSecret2: outputNotes[1].secret,
        outAmount2: outputNotes[1].amount,
    };

    console.log('✓ Witness input built with', Object.keys(witness).length, 'fields');

    return witness;
}

/**
 * Step 6: Generate ZK proof
 */
async function generateTransferProof(
    witnessInput: Record<string, any>
): Promise<{ proof: any; publicSignals: string[] }> {
    console.log('Generating ZK proof...');
    console.log('This may take 10-30 seconds...');

    const startTime = Date.now();

    const { proof, publicSignals } = await generateProof(
        witnessInput,
        WASM_PATH,
        ZKEY_PATH
    );

    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log('✓ Proof generated in', duration, 'seconds');

    // Verify locally before sending to contract
    const isValid = await verifyProofLocally(proof, publicSignals, VK_PATH);

    if (!isValid) {
        throw new Error('Proof verification failed locally!');
    }

    console.log('✓ Proof verified locally');

    return { proof, publicSignals };
}

/**
 * Step 7: Submit transaction to contract
 */
async function submitTransaction(
    connector: NearConnector,
    proof: any,
    publicSignals: string[]
): Promise<void> {
    console.log('Submitting transaction...');

    const result = await verifyAndRegister(
        connector,
        PRIVACY_CONTRACT,
        proof,
        publicSignals,
        '0',                      // No deposit
        '150000000000000'         // 150 TGas
    );

    console.log('✓ Transaction submitted:', result.transaction?.hash);
}

/**
 * Step 8: Update local note state
 */
function updateNoteState(
    inputNotes: [Note, Note],
    outputNotes: [Partial<Note>, Partial<Note>]
): void {
    console.log('Updating local note state...');

    // Mark input notes as spent
    markSpent(ALICE_SHIELDED_KEY, inputNotes[0].commitment);
    if (inputNotes[1].amount !== '0') {
        markSpent(ALICE_SHIELDED_KEY, inputNotes[1].commitment);
    }

    // Save change note for Alice
    const changeNote: Note = {
        ...outputNotes[1] as any,
        leafIndex: -1,  // Will be updated when contract emits event
        spent: false,
        createdAt: Date.now(),
        sourceType: 'change'
    };
    saveNote(ALICE_SHIELDED_KEY, changeNote);

    // Send encrypted output note to Bob (out-of-band)
    // In production, encrypt with Bob's public key and transmit via:
    // - IPFS
    // - Contract event logs
    // - Direct P2P communication

    console.log('✓ Local state updated');
}

/**
 * Main transfer flow
 */
async function main() {
    console.log('=== Privacy Transfer Demo ===\n');

    try {
        // 1. Connect wallet
        const connector = await connectWallet();

        // 2. Sync Merkle tree
        const tree = await syncMerkleTree();

        // 3. Select input notes
        const transferAmount = BigInt('1000000000000000000000000'); // 1 NEAR
        const inputNotes = selectInputNotes(transferAmount);
        const inputTotal = BigInt(inputNotes[0].amount) + BigInt(inputNotes[1].amount);

        // 4. Create output notes
        const outputNotes = createOutputNotes(inputTotal, transferAmount);

        // 5. Build witness
        const witnessInput = await buildWitnessInput(inputNotes, outputNotes, tree);

        // 6. Generate proof
        const { proof, publicSignals } = await generateTransferProof(witnessInput);

        // 7. Submit transaction
        await submitTransaction(connector, proof, publicSignals);

        // 8. Update local state
        updateNoteState(inputNotes, outputNotes);

        console.log('\n✓ Transfer completed successfully!');
        console.log('Alice sent', transferAmount.toString(), 'yoctoNEAR to Bob privately');

    } catch (error) {
        console.error('\n✗ Transfer failed:', error);
        throw error;
    }
}

/**
 * Helper: Generate random field element
 */
function generateRandomField(): string {
    // In production, use cryptographically secure random
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Run example
if (require.main === module) {
    main().catch(console.error);
}
