# Gas Cost & Optimization Guide

This guide covers gas costs for Groth16 verification on NEAR and techniques to minimize them.

## Understanding Gas Costs

### Base Verification Cost

Groth16 verification on NEAR uses three precompiles:

| Precompile | Operation | Base Cost |
|------------|-----------|-----------|
| `alt_bn128_g1_multiexp` | Compute vk_x from public inputs | ~15-20 TGas |
| `alt_bn128_g1_sum` | Add points | ~5 TGas |
| `alt_bn128_pairing_check` | 4-pair pairing check | ~40-50 TGas |

**Total base cost: ~60-75 TGas**

### Cost Per Public Input

Each additional public input requires:
- One scalar multiplication in multiexp
- Additional storage/parsing overhead

**Per-input cost: ~5-10 TGas**

### Approximate Total Costs

| Public Inputs | Estimated Gas | Notes |
|---------------|---------------|-------|
| 1 | 50-80 TGas | Minimal circuit |
| 2-3 | 60-90 TGas | Typical simple circuit |
| 5 | 80-110 TGas | Medium complexity |
| 10 | 100-150 TGas | Complex circuit |
| 20+ | 150-200+ TGas | Consider optimization |

## Optimization Techniques

### 1. Public Input Compression (Hash Packing)

**The Problem:** Each public input costs gas. A circuit with nullifier, commitment, and Merkle root has 3 public inputs.

**The Solution:** Hash multiple values into a single public input.

```circom
pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

template OptimizedCircuit() {
    // Private inputs (what we're proving)
    signal input nullifier;
    signal input commitment;
    signal input merkleRoot;
    signal input secret;
    // ... other private inputs

    // Single public input - hash of all public values
    signal input publicHash;

    // Verify the public hash is correctly computed
    component hasher = Poseidon(3);
    hasher.inputs[0] <== nullifier;
    hasher.inputs[1] <== commitment;
    hasher.inputs[2] <== merkleRoot;

    // Constraint: publicHash must equal hash of all values
    publicHash === hasher.out;

    // Rest of circuit logic uses nullifier, commitment, merkleRoot
    // as private inputs (already constrained via publicHash)
}

// Only ONE public input instead of THREE
component main {public [publicHash]} = OptimizedCircuit();
```

**Gas Savings:**
- Before: 3 public inputs = ~90 TGas
- After: 1 public input = ~70 TGas
- **Savings: ~20 TGas (~22%)**

**Client-Side Implementation:**

```javascript
const { buildPoseidon } = require("circomlibjs");

async function computePublicHash(nullifier, commitment, merkleRoot) {
    const poseidon = await buildPoseidon();
    const hash = poseidon([
        BigInt(nullifier),
        BigInt(commitment),
        BigInt(merkleRoot)
    ]);
    return poseidon.F.toString(hash);
}

// Generate proof with compressed input
async function generateProof(inputs) {
    const publicHash = await computePublicHash(
        inputs.nullifier,
        inputs.commitment,
        inputs.merkleRoot
    );

    const witness = {
        nullifier: inputs.nullifier,
        commitment: inputs.commitment,
        merkleRoot: inputs.merkleRoot,
        secret: inputs.secret,
        publicHash: publicHash,  // Single public input
    };

    return snarkjs.groth16.fullProve(witness, wasmPath, zkeyPath);
}
```

**Contract-Side Verification:**

```rust
use near_groth16_verifier::U256;

pub fn verify_with_packed_hash(
    &self,
    proof: ProofJson,
    nullifier: String,
    commitment: String,
    merkle_root: String,
) -> bool {
    // Compute expected public hash on-chain
    // (Or accept pre-computed hash from client and verify)
    let public_inputs = vec![
        compute_poseidon_hash(&[&nullifier, &commitment, &merkle_root])
    ];

    self.verifier.verify_json(&proof, &public_inputs)
}
```

### 2. Minimize Constraint Count

Fewer constraints = smaller circuit = faster proof generation (though on-chain cost is mainly about public inputs).

```circom
// BAD: Unnecessary intermediate signals
signal a_squared;
signal b_squared;
signal sum;
a_squared <== a * a;
b_squared <== b * b;
sum <== a_squared + b_squared;
c <== sum;

// GOOD: Combine where possible
c <== a * a + b * b;
```

### 3. Use Efficient Hash Functions

| Hash | Constraints | On-chain Cost |
|------|-------------|---------------|
| Poseidon(2) | ~250 | Cheapest |
| Poseidon(3) | ~300 | Very cheap |
| MiMC | ~300 | Cheap |
| SHA256 | ~25,000 | Expensive |

**Always use Poseidon or MiMC for ZK circuits.**

### 4. Batch Nullifier Checks

Instead of checking nullifier on every call, batch them:

```rust
pub fn verify_batch(
    &mut self,
    proofs: Vec<(ProofJson, Vec<String>)>,
) -> Vec<bool> {
    // Single storage read for nullifier set
    let results: Vec<bool> = proofs.iter().map(|(proof, inputs)| {
        let nullifier = U256::from_dec_str(&inputs[0]).unwrap();
        let nullifier_bytes = nullifier.to_be_bytes();

        if self.nullifiers.contains(&nullifier_bytes) {
            return false;
        }

        if self.verifier.verify_json(proof, inputs) {
            self.nullifiers.insert(&nullifier_bytes);
            true
        } else {
            false
        }
    }).collect();

    results
}
```

### 5. View Methods for Testing

View calls are free - use them for testing before state-changing calls:

```rust
// Free - use for testing
pub fn check_proof(&self, proof: ProofJson, inputs: Vec<String>) -> bool {
    self.verifier.verify_json(&proof, &inputs)
}

// Costs gas - use only when needed
pub fn verify_and_register(&mut self, proof: ProofJson, inputs: Vec<String>) -> bool {
    // ... verification + state changes
}
```

### 6. Lazy Nullifier Storage

Use `LookupSet` instead of `UnorderedSet` for nullifiers:

```rust
// GOOD: O(1) lookup, minimal storage overhead
nullifiers: LookupSet<[u8; 32]>,

// BAD: Stores enumeration data, more expensive
nullifiers: UnorderedSet<[u8; 32]>,
```

### 7. Fixed-Size Types

Use fixed-size arrays instead of vectors when possible:

```rust
// GOOD: Fixed 32-byte nullifier
nullifiers: LookupSet<[u8; 32]>,

// BAD: Variable-length, more storage overhead
nullifiers: LookupSet<Vec<u8>>,
```

## Real-World Example: Privacy Transaction

### Before Optimization (3 public inputs)

```circom
template PrivacyTransfer() {
    signal input nullifier;      // Public
    signal input newCommitment;  // Public
    signal input merkleRoot;     // Public
    signal input secret;         // Private
    // ...
}

component main {public [nullifier, newCommitment, merkleRoot]} = PrivacyTransfer();
```

**Cost: ~90-100 TGas**

### After Optimization (1 public input)

```circom
template PrivacyTransferOptimized() {
    signal input nullifier;      // Now private (constrained via hash)
    signal input newCommitment;  // Now private (constrained via hash)
    signal input merkleRoot;     // Now private (constrained via hash)
    signal input publicHash;     // Single public input
    signal input secret;         // Private

    // Constrain all "public" values via hash
    component hasher = Poseidon(3);
    hasher.inputs[0] <== nullifier;
    hasher.inputs[1] <== newCommitment;
    hasher.inputs[2] <== merkleRoot;
    publicHash === hasher.out;

    // Rest of logic unchanged
}

component main {public [publicHash]} = PrivacyTransferOptimized();
```

**Cost: ~70-80 TGas**

**Savings: 20-30 TGas per transaction**

### Contract Changes for Packed Hash

```rust
use near_sdk::env;

impl PrivacyContract {
    /// Verify with packed public hash
    ///
    /// Client computes: publicHash = poseidon(nullifier, commitment, root)
    /// Contract receives: proof + publicHash + individual values for state updates
    pub fn transfer(
        &mut self,
        proof: ProofJson,
        public_hash: String,
        nullifier: String,
        new_commitment: String,
        merkle_root: String,
    ) -> bool {
        // Verify merkle root is current
        require!(merkle_root == self.current_root, "Stale merkle root");

        // Check nullifier not used
        let nullifier_bytes = parse_to_bytes(&nullifier);
        require!(!self.nullifiers.contains(&nullifier_bytes), "Nullifier used");

        // Verify proof with single public input
        let public_inputs = vec![public_hash];
        require!(
            self.verifier.verify_json(&proof, &public_inputs),
            "Invalid proof"
        );

        // Update state
        self.nullifiers.insert(&nullifier_bytes);
        self.add_commitment(&new_commitment);

        true
    }
}
```

## Gas Estimation Tool

Use the CLI to estimate gas:

```bash
near-zk info -i verification_key.json

# Output:
# === Verification Key Info ===
#
# Protocol:       groth16
# Curve:          bn128
# Public inputs:  3
# IC points:      4
#
# Estimated Verification Cost:
#   ~65-95 TGas
#   ~0.0650 NEAR (at 100 Tgas/mNEAR)
```

## Cost Comparison Table

| Optimization | Public Inputs | Gas Cost | Savings |
|--------------|---------------|----------|---------|
| None | 5 | ~110 TGas | - |
| Hash packing (3→1) | 3 | ~80 TGas | ~30 TGas |
| Hash packing (5→1) | 1 | ~70 TGas | ~40 TGas |
| + View method testing | 1 | 0 (view) | 100% for tests |
| + LookupSet | 1 | ~70 TGas | Storage savings |

## When NOT to Optimize

1. **Development/testing** - Use clear, unoptimized circuits first
2. **Low-volume applications** - Optimization complexity may not be worth it
3. **Audit requirements** - Simpler circuits are easier to audit
4. **Client-side hash computation** - Adds complexity, ensure it's worth it

## Summary

1. **Pack multiple public inputs into a single hash** - Biggest impact
2. **Use Poseidon for hashing** - ZK-efficient
3. **Use LookupSet for nullifiers** - Storage efficient
4. **Test with view methods** - Free verification
5. **Batch operations when possible** - Amortize fixed costs

The public hash packing technique alone can save 20-40 TGas per verification, which adds up significantly at scale.
