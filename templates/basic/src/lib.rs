//! # Basic Groth16 Verifier
//!
//! Minimal ZK proof verifier contract - your starting point for zero-knowledge apps on NEAR.
//!
//! ## What is Groth16?
//!
//! **Groth16** is a ZK-SNARK proof system that lets you prove "I know a secret that satisfies
//! some condition" without revealing the secret itself. Think of it as proving you're over 21
//! without showing your ID.
//!
//! **How it works**:
//! 1. Write circuit in circom (define what you're proving)
//! 2. Compile circuit to get proving key + verification key
//! 3. Client generates proof (expensive, ~1-10 seconds)
//! 4. Contract verifies proof (cheap, ~100 TGas on NEAR)
//!
//! ## What You Can Build
//!
//! - **Anonymous voting**: Prove you're eligible without revealing identity
//! - **Privacy pools**: Hide transaction sources/destinations
//! - **Private credentials**: Prove you have a credential without showing it
//! - **ZK rollups**: Batch transactions with validity proofs
//! - **Age verification**: Prove you're over 18 without revealing birth date
//!
//! ## Quick Start
//!
//! ```bash
//! # 1. Compile your circom circuit
//! circom circuit.circom --r1cs --wasm --sym
//! snarkjs groth16 setup circuit.r1cs powersOfTau28.ptau circuit_0000.zkey
//! snarkjs zkey export verificationkey circuit_0000.zkey verification_key.json
//!
//! # 2. Deploy this contract with the verification key
//! near deploy --wasm basic.wasm --initFunction new --initArgs '{"vk": '$(cat verification_key.json)'}'
//!
//! # 3. Generate and verify proofs
//! snarkjs groth16 fullprove input.json circuit.wasm circuit_0000.zkey proof.json public.json
//! near call verifier.near verify '{"proof": '$(cat proof.json)', "public_inputs": '$(cat public.json)'}' --accountId user.near
//! ```
//!
//! ## Gas Costs
//!
//! **Verification**: ~100-120 TGas (~0.01 NEAR) depending on circuit complexity
//! **View call** (check_proof): FREE (no state changes)
//!
//! ## Circuit Compatibility
//!
//! Works with any circom circuit + snarkjs verification key. The contract doesn't care
//! what you're proving - it just verifies the math. Circuit semantics are enforced
//! off-chain by your application logic.

use near_sdk::{near, env, PanicOnDefault};
use near_groth16_verifier::{Verifier, ProofJson, VerificationKeyJson};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct BasicVerifier {
    /// The Groth16 verifier with loaded verification key
    verifier: Verifier,
}

#[near]
impl BasicVerifier {
    /// Initialize the contract with a verification key
    ///
    /// # Arguments
    /// * `vk` - Verification key in snarkjs JSON format
    ///
    /// # Example
    /// ```bash
    /// near call verifier.testnet new "$(cat verification_key.json)" --accountId deployer.testnet
    /// ```
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        let verifier = Verifier::from_json(&vk).expect("Invalid verification key format");
        env::log_str(&format!("Verifier initialized with {} public inputs", verifier.vk.num_inputs()));
        Self { verifier }
    }

    /// Verify a Groth16 proof
    ///
    /// # Arguments
    /// * `proof` - The proof in snarkjs JSON format
    /// * `public_inputs` - Public inputs as decimal strings
    ///
    /// # Returns
    /// `true` if proof is valid, panics otherwise
    ///
    /// # Example
    /// ```bash
    /// near call verifier.testnet verify '{
    ///   "proof": '"$(cat proof.json)"',
    ///   "public_inputs": '"$(cat public.json)"'
    /// }' --accountId user.testnet
    /// ```
    pub fn verify(&self, proof: ProofJson, public_inputs: Vec<String>) -> bool {
        let is_valid = self.verifier.verify_json(&proof, &public_inputs);

        if is_valid {
            env::log_str("Proof verified successfully");
            true
        } else {
            env::panic_str("Proof verification failed")
        }
    }

    /// Check proof without state changes (view method)
    ///
    /// Use this for testing - no gas cost for view calls.
    pub fn check_proof(&self, proof: ProofJson, public_inputs: Vec<String>) -> bool {
        self.verifier.verify_json(&proof, &public_inputs)
    }

    /// Get the number of expected public inputs
    pub fn num_public_inputs(&self) -> usize {
        self.verifier.vk.num_inputs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiles() {
        // Basic compilation test
        assert!(true);
    }
}
