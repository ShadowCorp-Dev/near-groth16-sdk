# Smart Contract Guide

This guide covers building and deploying Groth16 verifier smart contracts on NEAR Protocol.

## Getting Started

### 1. Add the Crate to Your Project

```toml
# Cargo.toml
[package]
name = "my_zk_contract"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
near-sdk = "5.7"
near_groth16_verifier = { path = "../crate" }

[profile.release]
codegen-units = 1
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true
```

### 2. Basic Contract Structure

```rust
use near_sdk::{near, env, PanicOnDefault};
use near_groth16_verifier::{Verifier, ProofJson, VerificationKeyJson};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MyContract {
    verifier: Verifier,
}

#[near]
impl MyContract {
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        let verifier = Verifier::from_json(&vk)
            .expect("Invalid verification key");
        Self { verifier }
    }

    pub fn verify(&self, proof: ProofJson, inputs: Vec<String>) -> bool {
        self.verifier.verify_json(&proof, &inputs)
    }
}
```

## API Reference

### Types

#### `U256`

256-bit unsigned integer for field elements.

```rust
use near_groth16_verifier::U256;

// From decimal string (snarkjs format)
let x = U256::from_dec_str("12345").unwrap();

// To bytes
let bytes: [u8; 32] = x.to_be_bytes();

// From bytes
let y = U256::from_be_bytes(&bytes);

// Check if zero
if x.is_zero() { /* ... */ }
```

#### `G1Point`

Point on BN254 G1 curve.

```rust
use near_groth16_verifier::{G1Point, U256};

// Create from coordinates
let point = G1Point {
    x: U256::from_dec_str("1234").unwrap(),
    y: U256::from_dec_str("5678").unwrap(),
};

// Serialize (64 bytes)
let bytes: [u8; 64] = point.to_bytes();

// Deserialize
let point2 = G1Point::from_bytes(&bytes);

// From snarkjs format
let point3 = G1Point::from_json_array(&["1234".into(), "5678".into(), "1".into()]).unwrap();
```

#### `G2Point`

Point on BN254 G2 curve (Fq2 extension field).

```rust
use near_groth16_verifier::{G2Point, U256};

let point = G2Point {
    x: [U256::from(1), U256::from(2)],
    y: [U256::from(3), U256::from(4)],
};

// Serialize (128 bytes)
let bytes: [u8; 128] = point.to_bytes();
```

#### `Proof`

Groth16 proof structure.

```rust
use near_groth16_verifier::Proof;

// From snarkjs JSON format
let proof = Proof::from_json(
    &pi_a_strings,  // ["x", "y", "1"]
    &pi_b_strings,  // [["x0", "x1"], ["y0", "y1"], ["1", "0"]]
    &pi_c_strings,  // ["x", "y", "1"]
).unwrap();
```

#### `VerificationKey`

Contains the verification parameters.

```rust
use near_groth16_verifier::{VerificationKey, VerificationKeyJson};

// From JSON (most common)
let vk_json: VerificationKeyJson = serde_json::from_str(json_str)?;
let vk = vk_json.to_vk()?;

// Number of expected public inputs
let n = vk.num_inputs();
```

#### `Verifier`

Main verifier struct.

```rust
use near_groth16_verifier::Verifier;

// Create from JSON
let verifier = Verifier::from_json(&vk_json)?;

// Verify with native types
let is_valid = verifier.verify(inputs_vec, proof);

// Verify with JSON strings (snarkjs format)
let is_valid = verifier.verify_json(&proof_json, &input_strings);
```

## Production Contract Templates

For production use, start with one of the extensively-commented templates:

### privacy-near-only/
Simple NEAR-only privacy pool with detailed inline comments. Best for:
- Learning ZK contract patterns
- NEAR-only privacy applications
- Anonymous donations or payments

**Features:**
- Private NEAR transfers
- Nullifier-based double-spend protection
- Commitment tracking for Merkle tree
- ~100-140 TGas per transaction

**See:** [templates/privacy-near-only/src/lib.rs](../templates/privacy-near-only/src/lib.rs)

### privacy-multi-asset/
Advanced privacy pool supporting NEAR + any NEP-141 fungible token. Best for:
- Multi-token privacy applications
- Privacy-preserving stablecoin payments
- Anonymous DEX swaps

**Features:**
- Multi-asset support (NEAR, USDC, USDT, etc.)
- Asset ID hashing for token identification
- FT receiver interface (NEP-141)
- Per-asset balance tracking

**See:** [templates/privacy-multi-asset/src/lib.rs](../templates/privacy-multi-asset/src/lib.rs)

---

## Contract Patterns

### Basic Verifier

The simplest pattern - just verify proofs:

```rust
#[near(contract_state)]
pub struct BasicVerifier {
    verifier: Verifier,
}

#[near]
impl BasicVerifier {
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        Self {
            verifier: Verifier::from_json(&vk).expect("Invalid VK")
        }
    }

    pub fn verify(&self, proof: ProofJson, inputs: Vec<String>) -> bool {
        self.verifier.verify_json(&proof, &inputs)
    }
}
```

### With Nullifier Tracking

Prevent double-use of proofs:

```rust
use near_sdk::collections::LookupSet;

#[near(contract_state)]
pub struct NullifierContract {
    verifier: Verifier,
    nullifiers: LookupSet<[u8; 32]>,
}

#[near]
impl NullifierContract {
    pub fn verify_and_register(
        &mut self,
        proof: ProofJson,
        inputs: Vec<String>,
    ) -> bool {
        // First input is nullifier
        let nullifier = U256::from_dec_str(&inputs[0]).unwrap();
        let nullifier_bytes = nullifier.to_be_bytes();

        // Check not used
        require!(!self.nullifiers.contains(&nullifier_bytes), "Already used");

        // Verify
        require!(self.verifier.verify_json(&proof, &inputs), "Invalid proof");

        // Register
        self.nullifiers.insert(&nullifier_bytes);

        true
    }
}
```

### With Commitment Tracking

Track valid commitments for set membership:

```rust
use near_sdk::collections::LookupSet;

#[near(contract_state)]
pub struct CommitmentContract {
    verifier: Verifier,
    commitments: LookupSet<[u8; 32]>,
}

#[near]
impl CommitmentContract {
    pub fn add_commitment(&mut self, commitment: String) {
        let c = U256::from_dec_str(&commitment).unwrap();
        self.commitments.insert(&c.to_be_bytes());
    }

    pub fn verify_membership(
        &self,
        proof: ProofJson,
        inputs: Vec<String>,
    ) -> bool {
        // Verify commitment is in our set
        let commitment = U256::from_dec_str(&inputs[1]).unwrap();
        require!(
            self.commitments.contains(&commitment.to_be_bytes()),
            "Unknown commitment"
        );

        self.verifier.verify_json(&proof, &inputs)
    }
}
```

### With Events

Emit events for off-chain indexing:

```rust
#[near(event_json(standard = "nep297"))]
pub enum ContractEvent {
    #[event_version("1.0.0")]
    ProofVerified {
        nullifier: String,
        timestamp: u64,
    },
}

#[near]
impl MyContract {
    pub fn verify(&mut self, proof: ProofJson, inputs: Vec<String>) -> bool {
        let valid = self.verifier.verify_json(&proof, &inputs);

        if valid {
            ContractEvent::ProofVerified {
                nullifier: inputs[0].clone(),
                timestamp: env::block_timestamp(),
            }.emit();
        }

        valid
    }
}
```

### Multiple Circuits

Support different verification keys for different circuits:

```rust
use near_sdk::collections::LookupMap;

#[near(contract_state)]
pub struct MultiCircuitVerifier {
    verifiers: LookupMap<String, Verifier>,
    owner: AccountId,
}

#[near]
impl MultiCircuitVerifier {
    pub fn add_circuit(&mut self, name: String, vk: VerificationKeyJson) {
        require!(env::predecessor_account_id() == self.owner);
        let verifier = Verifier::from_json(&vk).expect("Invalid VK");
        self.verifiers.insert(&name, &verifier);
    }

    pub fn verify(
        &self,
        circuit: String,
        proof: ProofJson,
        inputs: Vec<String>,
    ) -> bool {
        let verifier = self.verifiers.get(&circuit).expect("Unknown circuit");
        verifier.verify_json(&proof, &inputs)
    }
}
```

## Building and Deploying

### Build

```bash
# Set up build environment
export RUSTFLAGS='-C link-arg=-s'

# Build for WASM
cargo build --target wasm32-unknown-unknown --release

# Output: target/wasm32-unknown-unknown/release/my_contract.wasm
```

### Deploy

```bash
# Create account for contract
near create-account verifier.testnet --masterAccount deployer.testnet

# Deploy
near deploy --accountId verifier.testnet \
  --wasmFile target/wasm32-unknown-unknown/release/my_contract.wasm

# Initialize
near call verifier.testnet new "$(cat verification_key.json)" \
  --accountId deployer.testnet \
  --gas 300000000000000
```

### Interact

```bash
# Verify a proof
near call verifier.testnet verify '{
  "proof": {
    "pi_a": ["123...", "456...", "1"],
    "pi_b": [["12...", "34..."], ["56...", "78..."], ["1", "0"]],
    "pi_c": ["987...", "654...", "1"]
  },
  "inputs": ["111", "222"]
}' --accountId user.testnet

# View methods (no gas)
near view verifier.testnet num_public_inputs
```

## Gas Optimization

### Minimize Storage

```rust
// Use LookupSet instead of UnorderedSet for large sets
nullifiers: LookupSet<[u8; 32]>,

// Use fixed-size arrays when possible
nullifiers: LookupSet<[u8; 32]>,  // Good
nullifiers: LookupSet<Vec<u8>>,   // Less efficient
```

### Batch Operations

```rust
// Verify multiple proofs in one call
pub fn verify_batch(
    &self,
    proofs: Vec<(ProofJson, Vec<String>)>,
) -> Vec<bool> {
    proofs.iter()
        .map(|(proof, inputs)| self.verifier.verify_json(proof, inputs))
        .collect()
}
```

### View Methods for Testing

```rust
// Free verification (view call)
pub fn check_proof(&self, proof: ProofJson, inputs: Vec<String>) -> bool {
    self.verifier.verify_json(&proof, &inputs)
}

// State-changing verification (costs gas)
pub fn verify_and_record(&mut self, proof: ProofJson, inputs: Vec<String>) -> bool {
    // ... verification + state changes
}
```

## Error Handling

```rust
use near_sdk::require;

pub fn verify(&self, proof: ProofJson, inputs: Vec<String>) -> bool {
    // Input validation
    require!(
        inputs.len() == self.verifier.vk.num_inputs(),
        format!("Expected {} inputs, got {}", self.verifier.vk.num_inputs(), inputs.len())
    );

    // Proof verification
    let is_valid = self.verifier.verify_json(&proof, &inputs);

    if !is_valid {
        env::panic_str("Proof verification failed");
    }

    true
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn get_context() -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .predecessor_account_id("alice.testnet".parse().unwrap())
            .block_timestamp(1_000_000);
        builder
    }

    #[test]
    fn test_initialization() {
        testing_env!(get_context().build());

        let vk_json = r#"{"protocol":"groth16"...}"#;
        let vk: VerificationKeyJson = serde_json::from_str(vk_json).unwrap();

        let contract = MyContract::new(vk);
        assert_eq!(contract.verifier.vk.num_inputs(), 2);
    }
}
```

### Integration Tests

```bash
# Deploy to testnet sandbox
near-workspaces test

# Or use NEAR CLI
near call verifier.testnet verify '...' --accountId test.testnet
```

## Upgradeability

### Owner-Only VK Updates

```rust
pub fn update_verification_key(&mut self, vk: VerificationKeyJson) {
    require!(
        env::predecessor_account_id() == self.owner,
        "Only owner"
    );
    self.verifier = Verifier::from_json(&vk).expect("Invalid VK");
    env::log_str("Verification key updated");
}
```

### Migration Pattern

```rust
#[private]
#[init(ignore_state)]
pub fn migrate() -> Self {
    // Read old state
    let old: OldContract = env::state_read().unwrap();

    // Transform to new state
    Self {
        verifier: old.verifier,
        nullifiers: old.nullifiers,
        // ... new fields with defaults
    }
}
```

## Security Checklist

- [ ] Validate all inputs are in the scalar field
- [ ] Check nullifiers before accepting proofs
- [ ] Use `require!` for input validation
- [ ] Emit events for audit trail
- [ ] Test edge cases (zero values, max values)
- [ ] Consider front-running protection if needed
- [ ] Implement access control for admin functions
