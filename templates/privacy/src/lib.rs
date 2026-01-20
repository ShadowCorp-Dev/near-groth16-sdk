//! # Generic Privacy Contract Template
//!
//! Building block for privacy-preserving apps using Groth16 proofs + nullifiers.
//!
//! ## Core Concepts
//!
//! **Nullifier**: Unique "spending key" that can only be used once. Prevents double-spending
//! in privacy pools or double-voting in elections. Derived from a secret, so only you know it.
//!
//! **Commitment**: Cryptographic hash that hides information but can be proven later. Like a
//! sealed envelope - you can prove "I have something" without revealing what it is.
//!
//! **Public inputs**: Values everyone can see on-chain (nullifier hash, merkle root, etc)
//! **Private inputs**: Secret values only known to the prover (amount, secret key, etc)
//!
//! ## How This Template Works
//!
//! 1. **verify_and_register()**: Verifies proof, extracts nullifier from public_inputs[0],
//!    marks it as "used", optionally registers a new commitment from public_inputs[1].
//!
//! 2. **Nullifier check**: If nullifier already used → reject (prevents double-spend)
//!
//! 3. **Proof verification**: BN254 pairing check on the proof
//!
//! 4. **State update**: Record nullifier, optionally add commitment, increment counter
//!
//! ## What You Can Build
//!
//! **Privacy pool**: Nullifier = spent note, Commitment = new deposit
//! **Voting system**: Nullifier = voter ID, no commitment needed
//! **Credentials**: Nullifier = credential use, Commitment = revocation list entry
//! **ZK rollup**: Nullifier = old state root, Commitment = new state root
//!
//! ## Security Model
//!
//! **Protected**: Secrets hidden in proofs (private inputs never revealed)
//! **Exposed**: Public inputs, nullifiers, commitments, transaction metadata
//!
//! **Warning**: This is a TEMPLATE. Production apps need:
//! - Merkle tree tracking (see privacy-near-only)
//! - Asset/balance management (see privacy-multi-asset)
//! - Access control beyond owner-only
//! - Commitment uniqueness checks

use near_sdk::borsh::BorshSerialize;
use near_sdk::store::LookupSet;
use near_sdk::{near, env, require, AccountId, PanicOnDefault};
use near_groth16_verifier::{Verifier, ProofJson, VerificationKeyJson, U256};

/// Events for off-chain indexing
#[near(event_json(standard = "nep297"))]
pub enum PrivacyEvent {
    #[event_version("1.0.0")]
    ProofVerified {
        nullifier: String,
        commitment: String,
        caller: AccountId,
    },
    #[event_version("1.0.0")]
    CommitmentAdded {
        commitment: String,
    },
}

// SDK 5.x compatibility: Storage keys are now byte literals

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PrivacyContract {
    /// Groth16 verifier
    verifier: Verifier,
    /// Used nullifiers (prevent double-spending)
    nullifiers: LookupSet<[u8; 32]>,
    /// Valid commitments (for set membership proofs)
    commitments: LookupSet<[u8; 32]>,
    /// Contract owner
    owner: AccountId,
    /// Total number of verified proofs
    proof_count: u64,
}

#[near]
impl PrivacyContract {
    /// Initialize the contract
    ///
    /// # Arguments
    /// * `vk` - Verification key in snarkjs JSON format
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        let verifier = Verifier::from_json(&vk).expect("Invalid verification key");

        Self {
            verifier,
            nullifiers: LookupSet::new(b"n"),
            commitments: LookupSet::new(b"c"),
            owner: env::predecessor_account_id(),
            proof_count: 0,
        }
    }

    /// Verify proof and register nullifier
    ///
    /// The first public input is treated as the nullifier.
    /// The second public input (if present) is treated as a new commitment.
    ///
    /// # Arguments
    /// * `proof` - Groth16 proof
    /// * `public_inputs` - [nullifier, commitment?, ...]
    ///
    /// # Panics
    /// - If nullifier already used
    /// - If proof verification fails
    #[payable]
    pub fn verify_and_register(
        &mut self,
        proof: ProofJson,
        public_inputs: Vec<String>,
    ) -> bool {
        require!(
            !public_inputs.is_empty(),
            "At least one public input (nullifier) required"
        );

        // Parse nullifier (first input)
        let nullifier_u256 = U256::from_dec_str(&public_inputs[0])
            .expect("Invalid nullifier format");
        let nullifier_bytes = nullifier_u256.to_be_bytes();

        // Check nullifier hasn't been used
        require!(
            !self.nullifiers.contains(&nullifier_bytes),
            "Nullifier already used - possible double-spend attempt"
        );

        // Verify the proof
        let is_valid = self.verifier.verify_json(&proof, &public_inputs);
        require!(is_valid, "Proof verification failed");

        // Register nullifier
        self.nullifiers.insert(nullifier_bytes);
        self.proof_count += 1;

        // If there's a second input, register it as a commitment
        let commitment_str = if public_inputs.len() > 1 {
            let commitment_u256 = U256::from_dec_str(&public_inputs[1])
                .expect("Invalid commitment format");
            let commitment_bytes = commitment_u256.to_be_bytes();
            self.commitments.insert(commitment_bytes);

            PrivacyEvent::CommitmentAdded {
                commitment: public_inputs[1].clone(),
            }.emit();

            public_inputs[1].clone()
        } else {
            String::new()
        };

        // Emit verification event
        PrivacyEvent::ProofVerified {
            nullifier: public_inputs[0].clone(),
            commitment: commitment_str,
            caller: env::predecessor_account_id(),
        }.emit();

        true
    }

    /// Check if a nullifier has been used
    pub fn is_nullifier_used(&self, nullifier: String) -> bool {
        let nullifier_u256 = U256::from_dec_str(&nullifier)
            .expect("Invalid nullifier format");
        self.nullifiers.contains(&nullifier_u256.to_be_bytes())
    }

    /// Check if a commitment exists
    pub fn commitment_exists(&self, commitment: String) -> bool {
        let commitment_u256 = U256::from_dec_str(&commitment)
            .expect("Invalid commitment format");
        self.commitments.contains(&commitment_u256.to_be_bytes())
    }

    /// Add a commitment (owner only)
    ///
    /// Used for initial state setup or authorized deposits
    pub fn add_commitment(&mut self, commitment: String) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can add commitments directly"
        );

        let commitment_u256 = U256::from_dec_str(&commitment)
            .expect("Invalid commitment format");
        self.commitments.insert(commitment_u256.to_be_bytes());

        PrivacyEvent::CommitmentAdded { commitment }.emit();
    }

    /// Verify without registering (view method for testing)
    pub fn verify_only(&self, proof: ProofJson, public_inputs: Vec<String>) -> bool {
        self.verifier.verify_json(&proof, &public_inputs)
    }

    /// Get contract statistics
    pub fn get_stats(&self) -> (u64, usize, AccountId) {
        (
            self.proof_count,
            self.verifier.vk.num_inputs(),
            self.owner.clone(),
        )
    }

    /// Update verification key (owner only)
    pub fn update_verification_key(&mut self, vk: VerificationKeyJson) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can update verification key"
        );
        self.verifier = Verifier::from_json(&vk).expect("Invalid verification key");
        env::log_str("Verification key updated");
    }

    /// Transfer ownership
    pub fn transfer_ownership(&mut self, new_owner: AccountId) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can transfer ownership"
        );
        self.owner = new_owner;
    }
}
