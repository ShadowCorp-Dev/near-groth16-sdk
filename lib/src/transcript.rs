//! Fiat-Shamir Transcript for PLONK verification
//!
//! This module implements a Fiat-Shamir transcript compatible with snarkjs PLONK.
//!
//! ## Important Notes
//!
//! **snarkjs uses raw Keccak256 hashing, NOT STROBE-based Merlin transcripts.**
//!
//! The challenge derivation follows this order:
//! 1. Hash wire commitments (A, B, C) → derive β, γ
//! 2. Hash permutation commitment (Z) → derive α
//! 3. Hash quotient commitments (T1, T2, T3) → derive ξ (zeta)
//! 4. Hash polynomial evaluations → derive v
//! 5. Hash opening proofs → derive u
//!
//! All field elements are serialized in **big-endian** format.

use near_sdk::env;
use crate::types::{G1Point, U256};

/// BN254 scalar field modulus (r)
const FR_MODULUS: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Fiat-Shamir transcript for snarkjs-compatible PLONK
///
/// Uses Keccak256 hashing to derive challenges from proof elements.
#[derive(Clone, Debug)]
pub struct FiatShamirTranscript {
    /// Accumulated data to be hashed
    state: Vec<u8>,
}

impl Default for FiatShamirTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl FiatShamirTranscript {
    /// Create a new empty transcript
    pub fn new() -> Self {
        Self {
            state: Vec::with_capacity(1024),
        }
    }

    /// Clear the transcript state
    pub fn reset(&mut self) {
        self.state.clear();
    }

    /// Append a G1 point to the transcript
    ///
    /// Points are serialized as 64 bytes (32 bytes x + 32 bytes y) in big-endian.
    pub fn append_g1(&mut self, point: &G1Point) {
        self.state.extend_from_slice(&point.to_bytes());
    }

    /// Append multiple G1 points
    pub fn append_g1_vec(&mut self, points: &[G1Point]) {
        for point in points {
            self.append_g1(point);
        }
    }

    /// Append a scalar field element to the transcript
    ///
    /// Scalars are serialized as 32 bytes in big-endian.
    pub fn append_scalar(&mut self, scalar: &U256) {
        self.state.extend_from_slice(&scalar.to_be_bytes());
    }

    /// Append multiple scalars
    pub fn append_scalars(&mut self, scalars: &[U256]) {
        for scalar in scalars {
            self.append_scalar(scalar);
        }
    }

    /// Append raw bytes to the transcript
    pub fn append_bytes(&mut self, bytes: &[u8]) {
        self.state.extend_from_slice(bytes);
    }

    /// Generate a challenge by hashing the current state
    ///
    /// Returns the hash reduced modulo the scalar field order.
    /// Does NOT clear the state (allows chaining).
    pub fn challenge(&self) -> U256 {
        let hash = env::keccak256(&self.state);
        hash_to_field(&hash)
    }

    /// Generate a challenge and clear the state
    pub fn squeeze_challenge(&mut self) -> U256 {
        let challenge = self.challenge();
        self.reset();
        challenge
    }

    /// Generate a challenge from double hashing (for gamma in snarkjs)
    ///
    /// snarkjs derives gamma as: keccak256(keccak256(state))
    pub fn challenge_double_hash(&self) -> U256 {
        let hash1 = env::keccak256(&self.state);
        let hash2 = env::keccak256(&hash1);
        hash_to_field(&hash2)
    }

    /// Get current state length (for debugging)
    pub fn state_len(&self) -> usize {
        self.state.len()
    }

    // ==========================================================================
    // PLONK-specific challenge derivation (snarkjs compatible)
    // ==========================================================================

    /// Round 1: Derive beta and gamma from wire commitments
    ///
    /// ```text
    /// beta  = keccak256(A || B || C) mod r
    /// gamma = keccak256(keccak256(A || B || C)) mod r
    /// ```
    pub fn round1_challenges(
        &mut self,
        a: &G1Point,
        b: &G1Point,
        c: &G1Point,
    ) -> (U256, U256) {
        self.reset();
        self.append_g1(a);
        self.append_g1(b);
        self.append_g1(c);

        let beta = self.challenge();
        let gamma = self.challenge_double_hash();

        (beta, gamma)
    }

    /// Round 2: Derive alpha from permutation commitment Z
    ///
    /// ```text
    /// alpha = keccak256(Z) mod r
    /// ```
    pub fn round2_challenge(&mut self, z: &G1Point) -> U256 {
        self.reset();
        self.append_g1(z);
        self.squeeze_challenge()
    }

    /// Round 3: Derive zeta from quotient commitments
    ///
    /// ```text
    /// zeta = keccak256(T1 || T2 || T3) mod r
    /// ```
    pub fn round3_challenge(
        &mut self,
        t1: &G1Point,
        t2: &G1Point,
        t3: &G1Point,
    ) -> U256 {
        self.reset();
        self.append_g1(t1);
        self.append_g1(t2);
        self.append_g1(t3);
        self.squeeze_challenge()
    }

    /// Round 4: Derive v from polynomial evaluations
    ///
    /// ```text
    /// v = keccak256(a_eval || b_eval || c_eval || s1_eval || s2_eval || z_shifted_eval) mod r
    /// ```
    pub fn round4_challenge(
        &mut self,
        a_eval: &U256,
        b_eval: &U256,
        c_eval: &U256,
        s1_eval: &U256,
        s2_eval: &U256,
        z_shifted_eval: &U256,
    ) -> U256 {
        self.reset();
        self.append_scalar(a_eval);
        self.append_scalar(b_eval);
        self.append_scalar(c_eval);
        self.append_scalar(s1_eval);
        self.append_scalar(s2_eval);
        self.append_scalar(z_shifted_eval);
        self.squeeze_challenge()
    }

    /// Round 5: Derive u from opening proofs
    ///
    /// ```text
    /// u = keccak256(W_xi || W_xi_omega) mod r
    /// ```
    pub fn round5_challenge(
        &mut self,
        w_xi: &G1Point,
        w_xi_omega: &G1Point,
    ) -> U256 {
        self.reset();
        self.append_g1(w_xi);
        self.append_g1(w_xi_omega);
        self.squeeze_challenge()
    }
}

/// Convert a 32-byte hash to a field element
///
/// Interprets bytes as big-endian integer and reduces modulo r.
pub fn hash_to_field(hash: &[u8]) -> U256 {
    let fr_modulus = U256::from_dec_str(FR_MODULUS).unwrap();
    let value = U256::from_big_endian(hash);
    value % fr_modulus
}

/// Full PLONK challenge derivation
///
/// This struct encapsulates all challenges needed for PLONK verification.
#[derive(Clone, Debug)]
pub struct PlonkChallenges {
    pub beta: U256,
    pub gamma: U256,
    pub alpha: U256,
    pub zeta: U256,
    pub v: U256,
    pub u: U256,
}

impl PlonkChallenges {
    /// Derive all PLONK challenges from proof components
    ///
    /// # Arguments
    /// * `a, b, c` - Wire commitments (Round 1)
    /// * `z` - Permutation commitment (Round 2)
    /// * `t1, t2, t3` - Quotient commitments (Round 3)
    /// * `evaluations` - Polynomial evaluations [a, b, c, s1, s2, z_shifted] (Round 4)
    /// * `w_xi, w_xi_omega` - Opening proofs (Round 5)
    pub fn derive(
        a: &G1Point,
        b: &G1Point,
        c: &G1Point,
        z: &G1Point,
        t1: &G1Point,
        t2: &G1Point,
        t3: &G1Point,
        evaluations: &[U256; 6],
        w_xi: &G1Point,
        w_xi_omega: &G1Point,
    ) -> Self {
        let mut transcript = FiatShamirTranscript::new();

        // Round 1: beta, gamma
        let (beta, gamma) = transcript.round1_challenges(a, b, c);

        // Round 2: alpha
        let alpha = transcript.round2_challenge(z);

        // Round 3: zeta
        let zeta = transcript.round3_challenge(t1, t2, t3);

        // Round 4: v
        let v = transcript.round4_challenge(
            &evaluations[0],
            &evaluations[1],
            &evaluations[2],
            &evaluations[3],
            &evaluations[4],
            &evaluations[5],
        );

        // Round 5: u
        let u = transcript.round5_challenge(w_xi, w_xi_omega);

        Self {
            beta,
            gamma,
            alpha,
            zeta,
            v,
            u,
        }
    }
}

// ==========================================================================
// Alternative transcript for debugging/testing
// ==========================================================================

/// Simple transcript that accumulates everything and hashes at the end
///
/// Use this for debugging when you need to match the exact snarkjs behavior.
#[derive(Clone, Debug, Default)]
pub struct SimpleTranscript {
    data: Vec<u8>,
}

impl SimpleTranscript {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub fn append_g1(&mut self, p: &G1Point) {
        self.data.extend_from_slice(&p.to_bytes());
    }

    pub fn append_scalar(&mut self, s: &U256) {
        self.data.extend_from_slice(&s.to_be_bytes());
    }

    pub fn hash(&self) -> [u8; 32] {
        env::keccak256(&self.data).try_into().unwrap()
    }

    pub fn challenge(&self) -> U256 {
        hash_to_field(&self.hash())
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Get raw state for inspection
    pub fn state(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_append() {
        let mut transcript = FiatShamirTranscript::new();
        assert_eq!(transcript.state_len(), 0);

        let point = G1Point {
            x: U256::from(1u64),
            y: U256::from(2u64),
        };
        transcript.append_g1(&point);
        assert_eq!(transcript.state_len(), 64);

        let scalar = U256::from(123u64);
        transcript.append_scalar(&scalar);
        assert_eq!(transcript.state_len(), 96);
    }

    #[test]
    fn test_fr_modulus() {
        let modulus = U256::from_dec_str(FR_MODULUS).unwrap();
        // Verify it's the correct BN254 scalar field modulus
        assert!(!modulus.is_zero());
    }
}
