//! Groth16 verifier using NEAR's alt_bn128 precompiles
//!
//! This module provides efficient on-chain Groth16 verification by leveraging
//! NEAR Protocol's native alt_bn128 cryptographic precompiles.
//!
//! ## Verification Equation
//!
//! The Groth16 verification equation is:
//! ```text
//! e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ)
//! ```
//!
//! Where `vk_x = IC[0] + Σ(input[i] * IC[i+1])`
//!
//! This is transformed into a pairing product check:
//! ```text
//! e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1
//! ```

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::env;

use crate::types::{G1Point, G2Point, Proof, U256, VerificationKey, negate_g1};

/// Groth16 Verifier
///
/// Stores the verification key and provides verification methods.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Verifier {
    /// The verification key
    pub vk: VerificationKey,
}

impl Verifier {
    /// Create a new verifier with the given verification key
    pub fn new(vk: VerificationKey) -> Self {
        Self { vk }
    }

    /// Create verifier from JSON-formatted verification key
    pub fn from_json(vk_json: &crate::types::VerificationKeyJson) -> Result<Self, &'static str> {
        Ok(Self::new(vk_json.to_vk()?))
    }

    /// Verify a Groth16 proof
    ///
    /// # Arguments
    /// * `inputs` - Public inputs as U256 values
    /// * `proof` - The Groth16 proof
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, inputs: Vec<U256>, proof: Proof) -> bool {
        // Check input count matches verification key
        if inputs.len() != self.vk.num_inputs() {
            return false;
        }

        // Compute vk_x = IC[0] + Σ(input[i] * IC[i+1])
        // Using alt_bn128_g1_multiexp for efficient scalar multiplication
        let vk_x = match self.compute_vk_x(&inputs) {
            Some(p) => p,
            None => return false,
        };

        // Perform pairing check:
        // e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1
        self.pairing_check(&proof, &vk_x)
    }

    /// Verify a proof with inputs as decimal strings (snarkjs format)
    pub fn verify_json(
        &self,
        proof_json: &crate::types::ProofJson,
        inputs: &[String],
    ) -> bool {
        // Parse proof
        let proof = match proof_json.to_proof() {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Parse inputs
        let inputs: Result<Vec<U256>, _> = inputs
            .iter()
            .map(|s| U256::from_dec_str(s))
            .collect();
        
        let inputs = match inputs {
            Ok(i) => i,
            Err(_) => return false,
        };

        self.verify(inputs, proof)
    }

    /// Compute vk_x = IC[0] + Σ(input[i] * IC[i+1])
    ///
    /// Uses alt_bn128_g1_multiexp for efficient multi-scalar multiplication
    fn compute_vk_x(&self, inputs: &[U256]) -> Option<G1Point> {
        if self.vk.ic.is_empty() {
            return None;
        }

        // Start with IC[0]
        let mut result = self.vk.ic[0].clone();

        if inputs.is_empty() {
            return Some(result);
        }

        // Build multiexp input: [(scalar, point), ...]
        // Format: scalar (32 bytes LE) + point (64 bytes)
        let mut multiexp_input = Vec::with_capacity(inputs.len() * 96);

        for (i, input) in inputs.iter().enumerate() {
            if i + 1 >= self.vk.ic.len() {
                return None; // Not enough IC points
            }

            // Skip zero inputs (optimization)
            if input.is_zero() {
                continue;
            }

            // Scalar in little-endian format for NEAR precompile
            let mut scalar_le = [0u8; 32];
            input.to_little_endian(&mut scalar_le);
            multiexp_input.extend_from_slice(&scalar_le);

            // Point in big-endian format
            multiexp_input.extend_from_slice(&self.vk.ic[i + 1].to_bytes());
        }

        // If all inputs were zero, just return IC[0]
        if multiexp_input.is_empty() {
            return Some(result);
        }

        // Perform multi-scalar multiplication
        let multiexp_result = env::alt_bn128_g1_multiexp(&multiexp_input);
        
        if multiexp_result.len() != 64 {
            return None;
        }

        let sum_point = G1Point::from_bytes(&multiexp_result.try_into().ok()?);

        // Add IC[0] + multiexp result using alt_bn128_g1_sum
        let sum_result = self.add_g1_points(&result, &sum_point)?;
        
        Some(sum_result)
    }

    /// Add two G1 points using NEAR's alt_bn128_g1_sum precompile
    fn add_g1_points(&self, p1: &G1Point, p2: &G1Point) -> Option<G1Point> {
        // Format: num_points (1 byte) + point1 (64 bytes) + point2 (64 bytes)
        // Actually NEAR expects: point1 || point2 without length prefix
        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&p1.to_bytes());
        input.extend_from_slice(&p2.to_bytes());

        let result = env::alt_bn128_g1_sum(&input);
        
        if result.len() != 64 {
            return None;
        }

        Some(G1Point::from_bytes(&result.try_into().ok()?))
    }

    /// Perform the pairing check using NEAR's alt_bn128_pairing_check precompile
    ///
    /// Checks: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1
    fn pairing_check(&self, proof: &Proof, vk_x: &G1Point) -> bool {
        // Build pairing input: [(G1_1, G2_1), (G1_2, G2_2), ...]
        // Format: G1 (64 bytes) + G2 (128 bytes) per pair
        let mut pairing_input = Vec::with_capacity(4 * 192); // 4 pairs × 192 bytes

        // Pair 1: (-A, B) - negate A for the equation transformation
        let neg_a = negate_g1(&proof.a);
        pairing_input.extend_from_slice(&neg_a.to_bytes());
        pairing_input.extend_from_slice(&proof.b.to_bytes());

        // Pair 2: (α, β)
        pairing_input.extend_from_slice(&self.vk.alpha.to_bytes());
        pairing_input.extend_from_slice(&self.vk.beta.to_bytes());

        // Pair 3: (vk_x, γ)
        pairing_input.extend_from_slice(&vk_x.to_bytes());
        pairing_input.extend_from_slice(&self.vk.gamma.to_bytes());

        // Pair 4: (C, δ)
        pairing_input.extend_from_slice(&proof.c.to_bytes());
        pairing_input.extend_from_slice(&self.vk.delta.to_bytes());

        // The pairing check returns true if the product of pairings equals 1
        env::alt_bn128_pairing_check(&pairing_input)
    }
}

/// Standalone verification function (for use without Verifier struct)
pub fn verify_proof(
    vk: &VerificationKey,
    inputs: &[U256],
    proof: &Proof,
) -> bool {
    let verifier = Verifier::new(vk.clone());
    verifier.verify(inputs.to_vec(), proof.clone())
}

#[cfg(all(test, feature = "standalone"))]
mod standalone_tests {
    use super::*;

    // These tests require a mock environment and are only run
    // with the standalone feature enabled
    
    #[test]
    fn test_verifier_creation() {
        let vk = VerificationKey {
            alpha: G1Point::zero(),
            beta: G2Point::zero(),
            gamma: G2Point::zero(),
            delta: G2Point::zero(),
            ic: vec![G1Point::zero(), G1Point::zero()],
        };
        let verifier = Verifier::new(vk);
        assert_eq!(verifier.vk.num_inputs(), 1);
    }
}
