//! Example NEAR smart contract using near_groth16_verifier
//!
//! This contract demonstrates how to integrate Groth16 verification
//! into a NEAR Protocol smart contract using SDK 5.x.
//!
//! ## Build
//! ```bash
//! cargo build --target wasm32-unknown-unknown --release
//! ```
//!
//! ## Deploy
//! ```bash
//! near deploy --accountId your-contract.testnet \
//!   --wasmFile target/wasm32-unknown-unknown/release/your_contract.wasm
//! ```

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupSet;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, require, AccountId, PanicOnDefault};

// Import the Groth16 verifier types
use near_groth16_verifier::{
    G1Point, G2Point, Proof, ProofJson, U256, Verifier, VerificationKeyJson,
};

/// Event emitted when a proof is verified
#[near(event_json(standard = "nep297"))]
pub enum ContractEvent {
    #[event_version("1.0.0")]
    ProofVerified {
        nullifier: String,
        verified_by: AccountId,
    },
    #[event_version("1.0.0")]
    VerificationFailed { reason: String },
}

/// Storage keys for collections
#[derive(BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    Nullifiers,
}

/// Example ZK-proof contract for privacy-preserving transactions
///
/// This contract:
/// 1. Stores a Groth16 verification key
/// 2. Verifies proofs submitted by users
/// 3. Tracks nullifiers to prevent double-spending
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct ZkContract {
    /// The Groth16 verifier with loaded verification key
    verifier: Verifier,
    /// Set of used nullifiers (to prevent double-spending)
    nullifiers: LookupSet<[u8; 32]>,
    /// Contract owner
    owner: AccountId,
}

#[near]
impl ZkContract {
    /// Initialize the contract with a verification key
    ///
    /// # Arguments
    /// * `vk` - The verification key in snarkjs JSON format
    ///
    /// # Example
    /// ```bash
    /// near call contract.testnet new '{"vk": {...}}' --accountId owner.testnet
    /// ```
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        let verifier = Verifier::from_json(&vk).expect("Invalid verification key");

        Self {
            verifier,
            nullifiers: LookupSet::new(StorageKey::Nullifiers),
            owner: env::predecessor_account_id(),
        }
    }

    /// Verify a proof and register the nullifier
    ///
    /// This is the main entry point for privacy-preserving transactions.
    /// The nullifier prevents the same proof from being used twice.
    ///
    /// # Arguments
    /// * `proof` - The Groth16 proof in snarkjs JSON format
    /// * `public_inputs` - Public inputs as decimal strings
    ///
    /// # Returns
    /// `true` if verification succeeded, panics otherwise
    ///
    /// # Example
    /// ```bash
    /// near call contract.testnet verify_and_register '{
    ///   "proof": {"pi_a": [...], "pi_b": [...], "pi_c": [...]},
    ///   "public_inputs": ["123", "456"]
    /// }' --accountId user.testnet
    /// ```
    pub fn verify_and_register(
        &mut self,
        proof: ProofJson,
        public_inputs: Vec<String>,
    ) -> bool {
        // First public input is typically the nullifier
        require!(
            !public_inputs.is_empty(),
            "At least one public input (nullifier) required"
        );

        // Parse the nullifier from first public input
        let nullifier_u256 = U256::from_dec_str(&public_inputs[0])
            .expect("Invalid nullifier format");
        let nullifier_bytes = nullifier_u256.to_be_bytes();

        // Check nullifier hasn't been used
        require!(
            !self.nullifiers.contains(&nullifier_bytes),
            "Nullifier already used"
        );

        // Verify the proof
        let is_valid = self.verifier.verify_json(&proof, &public_inputs);

        if is_valid {
            // Register nullifier to prevent replay
            self.nullifiers.insert(&nullifier_bytes);

            // Emit success event
            ContractEvent::ProofVerified {
                nullifier: public_inputs[0].clone(),
                verified_by: env::predecessor_account_id(),
            }
            .emit();

            true
        } else {
            // Emit failure event
            ContractEvent::VerificationFailed {
                reason: "Proof verification failed".to_string(),
            }
            .emit();

            env::panic_str("Proof verification failed");
        }
    }

    /// Verify a proof without registering nullifier (view method)
    ///
    /// Use this for testing or when you don't need nullifier protection.
    pub fn verify_only(&self, proof: ProofJson, public_inputs: Vec<String>) -> bool {
        self.verifier.verify_json(&proof, &public_inputs)
    }

    /// Check if a nullifier has been used
    pub fn is_nullifier_used(&self, nullifier: String) -> bool {
        let nullifier_u256 = U256::from_dec_str(&nullifier)
            .expect("Invalid nullifier format");
        let nullifier_bytes = nullifier_u256.to_be_bytes();
        self.nullifiers.contains(&nullifier_bytes)
    }

    /// Get the number of public inputs expected by the verification key
    pub fn num_public_inputs(&self) -> usize {
        self.verifier.vk.num_inputs()
    }

    /// Update the verification key (owner only)
    ///
    /// This allows upgrading the circuit without redeploying the contract.
    pub fn update_verification_key(&mut self, vk: VerificationKeyJson) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can update verification key"
        );
        self.verifier = Verifier::from_json(&vk).expect("Invalid verification key");
    }

    /// Get the contract owner
    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }
}

/// Alternative constructor for manual verification key input
#[near]
impl ZkContract {
    /// Initialize with raw verification key components
    ///
    /// Use this if you want to pass the VK components directly
    /// rather than as a JSON object.
    #[init]
    #[private]
    pub fn new_with_raw_vk(
        alpha: G1Point,
        beta: G2Point,
        gamma: G2Point,
        delta: G2Point,
        ic: Vec<G1Point>,
    ) -> Self {
        use near_groth16_verifier::types::VerificationKey;

        let vk = VerificationKey {
            alpha,
            beta,
            gamma,
            delta,
            ic,
        };

        Self {
            verifier: Verifier::new(vk),
            nullifiers: LookupSet::new(StorageKey::Nullifiers),
            owner: env::predecessor_account_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require the near-sdk unit-testing feature
    // and mock verification key/proof data

    #[test]
    fn test_module_compiles() {
        // Basic compilation test
        assert!(true);
    }
}
