//! # near_groth16_verifier
//!
//! A Groth16 zero-knowledge proof verifier for NEAR Protocol smart contracts.
//! Compatible with snarkjs/circom generated proofs.
//!
//! ## Features
//! - Uses NEAR's native `alt_bn128` precompiles for efficient on-chain verification
//! - Compatible with snarkjs JSON proof format
//! - NEAR SDK 5.x compatible
//!
//! ## Usage
//!
//! ```rust,ignore
//! use near_sdk::{near, PanicOnDefault};
//! use near_groth16_verifier::{Verifier, Proof, G1Point, G2Point, U256};
//!
//! #[near(contract_state)]
//! #[derive(PanicOnDefault)]
//! pub struct Contract {
//!     pub verifier: Verifier,
//! }
//!
//! #[near]
//! impl Contract {
//!     #[init]
//!     pub fn new(verifier: Verifier) -> Self {
//!         Self { verifier }
//!     }
//!
//!     pub fn verify(&self, input: Vec<U256>, proof: Proof) -> bool {
//!         self.verifier.verify(input, proof)
//!     }
//! }
//! ```

pub mod types;
pub mod verifier;
pub mod transcript;
pub mod poseidon;
pub mod poseidon_precomputed;

// Re-export main types
pub use types::{G1Point, G2Point, Proof, ProofJson, U256, VerificationKeyJson};
pub use verifier::Verifier;
pub use transcript::FiatShamirTranscript;
pub use poseidon::{Fr, poseidon_hash2, poseidon_hash4, compute_commitment, compute_nullifier_hash};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::types::{G1Point, G2Point, Proof, ProofJson, U256, VerificationKeyJson};
    pub use crate::verifier::Verifier;
    pub use crate::transcript::FiatShamirTranscript;
    pub use crate::poseidon::{Fr, poseidon_hash2, poseidon_hash4, compute_commitment, compute_nullifier_hash};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_from_decimal() {
        let val = U256::from_dec_str("21888242871839275222246405745257275088696311157297823662689037894645226208583").unwrap();
        assert!(!val.is_zero());
    }

    #[test]
    fn test_g1_point_serialization() {
        let p = G1Point {
            x: U256::from(1u64),
            y: U256::from(2u64),
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), 64);
    }
}

#[cfg(test)]
mod poseidon_tests;

#[cfg(test)]
mod groth16_tests;
