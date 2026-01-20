# End-to-End Integration Guide

This guide walks through building a complete ZK application on NEAR using the TypeScript SDK.

## Overview

Building a production ZK application involves:

1. **Circuit Design** - Define what you want to prove
2. **Circuit Compilation** - Compile circom to WASM
3. **Trusted Setup** - Generate proving and verification keys
4. **Contract Deployment** - Deploy verifier to NEAR
5. **Client Integration** - Build proof generation pipeline with TypeScript SDK
6. **Wallet Integration** - Connect to user wallets using production patterns

## Example: Privacy Transfer System

We'll build a privacy transfer system where users can:
- Deposit NEAR into a pool
- Transfer ownership privately (without revealing sender/recipient)
- Withdraw NEAR to any account

### Step 1: Circuit Design

```circom
// circuits/privacy_transfer.circom
pragma circom 2.1.0;

include "circomlibjs/circuits/poseidon.circom";
include "circomlibjs/circuits/comparators.circom";

// Merkle tree proof verification
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);

        // Select order based on pathIndices[i]
        // If pathIndices[i] == 0: hash(current, sibling)
        // If pathIndices[i] == 1: hash(sibling, current)
        hashers[i].inputs[0] <== hashes[i] * (1 - pathIndices[i]) + pathElements[i] * pathIndices[i];
        hashers[i].inputs[1] <== pathElements[i] * (1 - pathIndices[i]) + hashes[i] * pathIndices[i];

        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[levels];
}

template PrivacyTransfer() {
    // Private inputs: what the user knows
    signal input nullifier;      // Unique identifier to prevent double-spending
    signal input secret;          // Secret for the note
    signal input amount;          // Amount being transferred
    signal input assetId;         // 0 for NEAR
    signal input pathElements[20];
    signal input pathIndices[20];

    // Public inputs: what the contract needs to verify
    signal input publicHash;      // Hash of all public values (gas optimization)
    signal input recipient;       // Recipient's account (optional, for direct transfers)

    // 1. Verify commitment is valid
    component commitmentHasher = Poseidon(4);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== secret;
    commitmentHasher.inputs[2] <== amount;
    commitmentHasher.inputs[3] <== assetId;
    signal commitment;
    commitment <== commitmentHasher.out;

    // 2. Verify commitment is in the Merkle tree
    component merkleProof = MerkleProof(20);
    merkleProof.leaf <== commitment;
    for (var i = 0; i < 20; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }
    signal merkleRoot;
    merkleRoot <== merkleProof.root;

    // 3. Compute nullifier hash (prevents double-spending)
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    signal nullifierHash;
    nullifierHash <== nullifierHasher.out;

    // 4. Verify public hash (gas optimization)
    // publicHash = poseidon(nullifierHash, merkleRoot, amount)
    component publicHasher = Poseidon(3);
    publicHasher.inputs[0] <== nullifierHash;
    publicHasher.inputs[1] <== merkleRoot;
    publicHasher.inputs[2] <== amount;

    publicHash === publicHasher.out;
}

// Single public input for gas efficiency
component main {public [publicHash]} = PrivacyTransfer();
```

### Step 2: Compile Circuit

```bash
# Install dependencies
npm install -g circom snarkjs
npm install circomlibjs

# Compile circuit
circom circuits/privacy_transfer.circom \
    --r1cs --wasm --sym \
    -l node_modules \
    -o build

# Check constraint count
snarkjs r1cs info build/privacy_transfer.r1cs
# Constraints: ~4,000 (depends on Merkle tree depth)
```

### Step 3: Trusted Setup

```bash
# For testing: use powers of tau ceremony
# For production: use existing ceremony or conduct your own

# Download powers of tau (or create new one)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau

# Circuit-specific setup
snarkjs groth16 setup \
    build/privacy_transfer.r1cs \
    powersOfTau28_hez_final_15.ptau \
    build/privacy_transfer_0000.zkey

# Contribute to ceremony (add randomness)
snarkjs zkey contribute \
    build/privacy_transfer_0000.zkey \
    build/privacy_transfer_final.zkey \
    --name="First contribution"

# Export verification key
snarkjs zkey export verificationkey \
    build/privacy_transfer_final.zkey \
    build/verification_key.json
```

### Step 4: Deploy Contract

Use one of the production templates:

```bash
# Build the privacy-near-only contract
cd templates/privacy-near-only
cargo build --target wasm32-unknown-unknown --release

# Deploy to testnet
near deploy --accountId privacy-pool.testnet \
    --wasmFile target/wasm32-unknown-unknown/release/privacy_pool_near.wasm

# Initialize with verification key
near call privacy-pool.testnet new \
    "{\"vk\": $(cat ../../build/verification_key.json)}" \
    --accountId deployer.testnet \
    --gas 300000000000000
```

### Step 5: Install TypeScript SDK

See the [main README](../README.md#quick-start-3-minutes-to-zk-app) for SDK installation.

```bash
cd your-project
npm install @hot-labs/near-connect
npm install snarkjs circomlibjs
```

### Step 6: Client-Side Integration

**Complete example available at:** [`sdk/examples/privacy-transfer.ts`](../sdk/examples/privacy-transfer.ts)

**Key patterns from production:**

1. **Wallet Connection** - See [sdk/src/wallet.ts](../sdk/src/wallet.ts)
2. **Note Management** - See [sdk/src/notes.ts](../sdk/src/notes.ts)
3. **Merkle Trees** - See [sdk/src/merkle.ts](../sdk/src/merkle.ts)
4. **Proof Generation** - See [sdk/src/prover.ts](../sdk/src/prover.ts)

**Quick integration example:**

```typescript
import { NearConnector } from '@hot-labs/near-connect';
import { verifyProof, generateProof, IncrementalMerkleTree, saveNote } from '@near-zk/groth16-sdk';

// 1. Connect wallet
const connector = new NearConnector({ network: 'testnet' });
await connector.signIn();

// 2. Deposit (example)
const note = createNote(amount, assetId);
saveNote(userPublicKey, note);  // SAVE FIRST!

await connector.wallet().signAndSendTransaction({
    signerId: (await connector.wallet().getAccounts())[0].accountId,
    receiverId: 'privacy-pool.testnet',
    actions: [{
        type: "FunctionCall",
        params: {
            methodName: "deposit",
            args: { commitment: note.commitment },
            gas: "30000000000000",
            deposit: amount
        }
    }]
});

// 3. Withdraw (generate proof + submit)
const { proof, publicSignals } = await generateProof(
    witnessInput,
    '/circuits/circuit.wasm',
    '/circuits/circuit.zkey'
);

await verifyProof(connector, 'privacy-pool.testnet', proof, publicSignals);
```

## Production Integration Patterns

### 1. Wallet Action Format (CRITICAL)

Different wallets expect different formats. Use this pattern for HOT Wallet compatibility:

```typescript
// ✅ CORRECT - Works with HOT Wallet and MyNearWallet
const wallet = await connector.wallet();
const accounts = await wallet.getAccounts();
const signerId = accounts[0]?.accountId;

await wallet.signAndSendTransaction({
    signerId,  // MUST include for HOT Wallet!
    receiverId: contractId,
    actions: [{
        type: "FunctionCall",
        params: {
            methodName: "verify_proof",
            args: { proof, public_inputs },  // Plain object
            gas: "100000000000000",          // String, not BigInt
            deposit: "0"
        }
    }]
});

// ❌ WRONG - Breaks with HOT Wallet
await wallet.signAndSendTransaction({
    // Missing signerId
    receiverId: contractId,
    actions: [{
        functionCall: {  // Wrong structure
            methodName: "verify_proof",
            args: Buffer.from(JSON.stringify({...})),  // Serialized
            gas: BigInt(100000000000000),              // BigInt
            deposit: BigInt(0)
        }
    }]
});
```

### 2. Note Management (Data Loss Prevention)

Always save notes BEFORE transactions:

```typescript
// ✅ CORRECT - Note saved first
const note = createNote(amount, assetId);
saveNote(userPublicKey, note);  // Save to localStorage FIRST

// Then send transaction
await deposit(connector, contractId, amount, note.commitment);

// If user closes tab mid-transaction, note is still saved!

// ❌ WRONG - If user closes tab mid-transaction, note is lost!
await deposit(...);  // Transaction sent first
saveNote(...);       // May never execute if tab closed or error occurs
```

### 3. Merkle Tree Synchronization

Keep local tree in sync with contract:

```typescript
// Fetch commitments from contract
const commitments = await contract.get_commitments_range({
    from: 0,
    limit: 1000
});

// Rebuild tree
const tree = IncrementalMerkleTree.fromCommitments(
    commitments.map(c => BigInt(c)),
    20,
    poseidon
);

// Verify sync
const localRoot = tree.getRoot();
const contractRoot = await contract.get_merkle_root();

if (localRoot !== contractRoot) {
    throw new Error("Tree out of sync!");
}
```

### 4. Error Handling

```typescript
try {
    const { proof, publicSignals } = await generateProof(...);
    await verifyProof(connector, contractId, proof, publicSignals);
} catch (error) {
    if (error.message.includes('Nullifier already used')) {
        alert('This note has already been spent');
    } else if (error.message.includes('Invalid proof')) {
        alert('Proof verification failed. Please try again.');
    } else if (error.message.includes('Tree out of sync')) {
        alert('Please refresh the page to sync with the latest state');
    } else {
        console.error('Unexpected error:', error);
        alert('Transaction failed. Please contact support.');
    }
}
```

## Common Integration Issues

### "HOT Wallet signAndSendTransaction fails"

**Cause:** Missing `signerId` or incorrect action format.

**Solution:** See wallet action format pattern above. Always include explicit `signerId`.

### "Note lost after transaction failure"

**Cause:** Saving note after transaction instead of before.

**Solution:** Always save notes BEFORE sending transactions (see note management pattern above).

### "Merkle proof verification fails"

**Cause:** Local tree out of sync with contract.

**Solution:** Always fetch latest commitments before generating proofs (see tree synchronization pattern above).

### "Proof generation takes too long"

**Expected behavior:** Complex circuits can take 30-60 seconds for proof generation in browser.

**Solutions:**
1. Show progress indicator to user
2. Use web workers to avoid blocking UI
3. Warn users not to close tab during proof generation

## Testing

### Local Testing

```bash
# Test circuit locally
echo '{"nullifier": "123", "secret": "456", ...}' > input.json

# Generate witness
node build/privacy_transfer_js/generate_witness.js \
    build/privacy_transfer_js/privacy_transfer.wasm \
    input.json \
    witness.wtns

# Generate proof
snarkjs groth16 prove \
    build/privacy_transfer_final.zkey \
    witness.wtns \
    proof.json \
    public.json

# Verify locally
snarkjs groth16 verify \
    build/verification_key.json \
    public.json \
    proof.json
```

### Testnet Testing

```bash
# Create test accounts
near create-account test-user.testnet --masterAccount your.testnet

# Run verification
near call privacy-pool.testnet verify_proof '{
    "proof": '"$(cat proof.json)"',
    "public_inputs": '"$(cat public.json)"'
}' --accountId test-user.testnet --gas 150000000000000
```

## Production Checklist

### Circuit
- [ ] Professional circuit audit
- [ ] Edge case testing (zero amounts, max tree depth)
- [ ] Multi-party trusted setup ceremony
- [ ] Public input ordering documented

### Contract
- [ ] Professional security audit
- [ ] Gas optimization testing
- [ ] Access control review
- [ ] Event logging for indexing
- [ ] Storage cost analysis

### Client/SDK
- [ ] Secure random number generation (`crypto.getRandomValues`)
- [ ] Comprehensive error handling
- [ ] Loading states for proof generation
- [ ] Browser compatibility testing (Chrome, Firefox, Safari)
- [ ] Mobile wallet support testing
- [ ] Note backup/export functionality

### Deployment
- [ ] Mainnet account setup
- [ ] Initial contract configuration
- [ ] Monitoring setup (Sentry, etc.)
- [ ] User documentation
- [ ] Support channel

## Resources

- [Complete Privacy Transfer Example](../sdk/examples/privacy-transfer.ts)
- [Production Contract Templates](../templates/)
- [Gas Optimization Guide](./GAS_OPTIMIZATION.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)
- [circom Documentation](https://docs.circom.io/)
- [snarkjs GitHub](https://github.com/iden3/snarkjs)
- [@hot-labs/near-connect](https://github.com/hot-dao/near-connect)
