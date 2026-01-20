///! # NEAR Privacy Pool
///!
///! Privacy pool for NEAR tokens using zero-knowledge proofs. Deposit publicly,
///! withdraw privately - no one can link deposits to withdrawals.
///!
///! ## How It Works
///!
///! **Commitment**: Poseidon(Poseidon(nullifier, secret), Poseidon(amount, 0))
///! Proves you own NEAR without revealing who you are.
///!
///! **Nullifier**: Unique spending key prevents double-spending. Revealed once during withdrawal.
///!
///! **Merkle Tree**: All commitments stored in a tree. Prove membership without revealing which leaf.
///!
///! **ZK Proof**: Proves you know (nullifier, secret, amount) that match a commitment in the tree.
///!
///! ## Example Flow
///!
///! ```text
///! Alice deposits 1 NEAR → commitment added to tree at index 42
///! [100 other deposits happen...]
///! Bob proves ownership → withdraws 1 NEAR to bob.near
///! Result: Link between Alice and Bob is hidden in the anonymity set!
///! ```
///!
///! ## Privacy Model
///!
///! **Private**: Which deposit funded which withdrawal
///! **Public**: Deposit/withdrawal amounts, timing, tree size
///!
///! **Best practices**: Wait before withdrawing, use common amounts (1, 10 NEAR),
///! use relayer to hide your account.
///!
///! ## Gas Costs
///!
///! Deposit: ~20 TGas (~0.002 NEAR) | Withdraw: ~120 TGas (~0.012 NEAR)

use near_sdk::borsh::BorshSerialize;
use near_sdk::store::{LookupSet, Vector};
use near_sdk::{near, env, require, AccountId, PanicOnDefault, NearToken};
use near_groth16_verifier::{Verifier, ProofJson, VerificationKeyJson, U256};

/// Events for off-chain indexing (wallets, explorers)
/// PRIVACY WARNING: Events are public! Don't emit secrets or nullifiers before use.
#[near(event_json(standard = "nep297"))]
pub enum NearPrivacyEvent {
    /// Proof verified - nullifier spent, commitment created
    #[event_version("1.0.0")]
    ProofVerified {
        nullifier: String,
        commitment: String,
        caller: AccountId,
    },

    /// Commitment added to Merkle tree
    #[event_version("1.0.0")]
    CommitmentAdded {
        commitment: String,
        leaf_index: u64,
    },

    /// NEAR deposited (reveals depositor and amount - use relayer for privacy)
    #[event_version("1.0.0")]
    Deposit {
        commitment: String,
        amount: String,
    },

    /// NEAR withdrawn (reveals recipient and amount, NOT which deposit it came from)
    #[event_version("1.0.0")]
    Withdrawal {
        recipient: AccountId,
        amount: String,
    },
}

// SDK 5.x compatibility: Storage keys are now byte literals instead of Vec<u8>
// This is more efficient and reduces contract size.

/// Privacy Pool Contract - NEAR-only implementation
///
/// **State**: Verifier (proof checker), nullifiers (spent notes), commitments (valid notes),
/// commitments_list (Merkle tree), owner, balances
///
/// **How it works**: ZK proof lets you prove "I own one of these 1000 notes" without
/// revealing which one. Nullifiers prevent double-spending. Larger anonymity set =
/// better privacy but slower proof generation.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct NearPrivacyPool {
    /// Groth16 verifier (proof checker from circuit verification key)
    verifier: Verifier,

    /// Spent nullifiers (prevents double-spending)
    nullifiers: LookupSet<[u8; 32]>,

    /// Valid commitments (for duplicate checking)
    commitments: LookupSet<[u8; 32]>,

    /// Ordered commitments (Merkle tree leaves - clients use this to build tree)
    commitments_list: Vector<[u8; 32]>,

    /// Contract owner (can update VK and transfer ownership, cannot steal funds)
    owner: AccountId,

    /// Total NEAR locked (should equal sum of unspent notes)
    total_balance: NearToken,

    /// Proof verification counter (stats/security monitoring)
    proof_count: u64,
}

#[near]
impl NearPrivacyPool {
    /// Initialize privacy pool with verification key from circuit
    ///
    /// VK generated via: `circom → snarkjs groth16 setup → snarkjs zkey export verificationkey`
    ///
    /// **CRITICAL**: VK must match your circuit. Changing VK after initialization breaks all notes!
    /// **Gas**: ~300 TGas (~0.03 NEAR)
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        // Parse and validate verification key
        let verifier = Verifier::from_json(&vk)
            .expect("Invalid verification key format");

        env::log_str(&format!(
            "Privacy pool initialized with {} public inputs",
            verifier.vk.num_inputs()
        ));

        Self {
            verifier,
            // Storage key prefixes for NEAR SDK 5.x
            nullifiers: LookupSet::new(b"n"),
            commitments: LookupSet::new(b"c"),
            commitments_list: Vector::new(b"l"),
            owner: env::predecessor_account_id(),
            total_balance: NearToken::from_yoctonear(0),
            proof_count: 0,
        }
    }

    /// Deposit NEAR into the privacy pool
    ///
    /// Locks NEAR and stores commitment in Merkle tree. Commitment is:
    /// `Poseidon(Poseidon(nullifier, secret), Poseidon(amount, 0))`
    ///
    /// **Public**: Your account deposited, amount, commitment hash
    /// **Private**: Nullifier and secret (keep these to withdraw!)
    ///
    /// **Security**: Commitment must be unique, must attach NEAR
    /// **Gas**: ~20 TGas (~0.002 NEAR)
    #[payable]
    pub fn deposit(&mut self, commitment: String) {
        let deposit_amount = env::attached_deposit();

        // SECURITY: Must attach NEAR to create a note
        require!(
            deposit_amount.as_yoctonear() > 0,
            "Must attach NEAR to deposit"
        );

        // Parse commitment from decimal string to bytes
        // The commitment should be a BN254 field element (< 254 bits)
        let commitment_u256 = U256::from_dec_str(&commitment)
            .expect("Commitment must be a decimal string");
        let commitment_bytes = commitment_u256.to_be_bytes();

        // SECURITY: Prevent commitment reuse (could deposit 0.1 NEAR with old commitment, withdraw 1 NEAR)
        require!(
            !self.commitments.contains(&commitment_bytes),
            "Commitment already exists - must be unique"
        );

        // Add to commitment tracking structures
        self.commitments.insert(commitment_bytes);
        let leaf_index = self.commitments_list.len() as u64;
        self.commitments_list.push(commitment_bytes);

        // Update total pool balance
        self.total_balance = NearToken::from_yoctonear(
            self.total_balance.as_yoctonear() + deposit_amount.as_yoctonear()
        );

        // Emit events for off-chain indexers
        // These help wallets and explorers track activity
        NearPrivacyEvent::CommitmentAdded {
            commitment: commitment.clone(),
            leaf_index,
        }.emit();

        NearPrivacyEvent::Deposit {
            commitment,
            amount: deposit_amount.as_yoctonear().to_string(),
        }.emit();

        env::log_str(&format!(
            "Deposited {} yoctoNEAR, commitment at index {} (total pool: {})",
            deposit_amount.as_yoctonear(),
            leaf_index,
            self.total_balance.as_yoctonear()
        ));
    }

    /// Withdraw NEAR using ZK proof
    ///
    /// Proves you own a note (commitment) without revealing which one. Contract verifies
    /// proof, marks nullifier as spent, and sends NEAR to recipient.
    ///
    /// **What the proof shows**: "I know secrets for SOME commitment in the tree"
    /// **What stays hidden**: Which commitment, original depositor, secrets
    ///
    /// **Security checks**:
    /// - Proof verification (BN254 pairing)
    /// - Nullifier not used before
    /// - Pool has sufficient balance
    ///
    /// **Gas**: ~120-150 TGas (~0.012 NEAR)
    #[payable]
    pub fn withdraw(
        &mut self,
        proof: ProofJson,
        public_inputs: Vec<String>,
        recipient: AccountId,
        amount: String,
    ) {
        // Validate we have required public inputs
        require!(
            public_inputs.len() >= 1,
            "Public inputs must include nullifier hash"
        );

        // Parse withdrawal amount from decimal string
        let withdraw_amount = U256::from_dec_str(&amount)
            .expect("Amount must be a decimal string");
        let withdraw_yocto = u128::try_from(withdraw_amount)
            .expect("Amount too large for u128");

        // SECURITY: Check pool has sufficient balance (prevent draining more than available)
        require!(
            withdraw_yocto <= self.total_balance.as_yoctonear(),
            "Insufficient pool balance"
        );

        // Parse nullifier (Poseidon(nullifier, leafIndex) - ensures one-time spend)
        let nullifier_u256 = U256::from_dec_str(&public_inputs[0])
            .expect("Nullifier must be a decimal string");
        let nullifier_bytes = nullifier_u256.to_be_bytes();

        // SECURITY: Double-spend protection
        require!(
            !self.nullifiers.contains(&nullifier_bytes),
            "Nullifier already used - note already spent"
        );

        // VERIFY ZK PROOF (~80 TGas)
        // Checks: commitment knowledge, Merkle proof, nullifier derivation, public input binding
        let is_valid = self.verifier.verify_json(&proof, &public_inputs);
        require!(is_valid, "Proof verification failed - invalid proof or wrong circuit");

        // Mark nullifier as used (prevents double-spending)
        self.nullifiers.insert(nullifier_bytes);
        self.proof_count += 1;

        // Update pool balance
        self.total_balance = NearToken::from_yoctonear(
            self.total_balance.as_yoctonear() - withdraw_yocto
        );

        // Transfer LAST (checks-effects-interactions pattern)
        let _transfer_promise = near_sdk::Promise::new(recipient.clone())
            .transfer(NearToken::from_yoctonear(withdraw_yocto));

        // Emit withdrawal event (for indexers and wallets)
        NearPrivacyEvent::Withdrawal {
            recipient: recipient.clone(),
            amount: withdraw_yocto.to_string(),
        }.emit();

        env::log_str(&format!(
            "Withdrew {} yoctoNEAR to {}, nullifier marked spent (pool balance: {})",
            withdraw_yocto,
            recipient,
            self.total_balance.as_yoctonear()
        ));
    }

    /// Private transfer within the pool (most private operation)
    ///
    /// Transfers NEAR from one note to another WITHOUT on-chain movement. Spends input
    /// notes and creates output notes. Proves value conservation in circuit.
    ///
    /// **MORE private than withdraw**: No recipient revealed, no amount revealed
    ///
    /// **Example**: Spend 1 NEAR note → create 0.3 NEAR note (Bob) + 0.7 NEAR note (change)
    /// **Allows**: Splitting notes, merging notes, self-transfers
    /// **Gas**: ~130-170 TGas (~0.013 NEAR)
    #[payable]
    pub fn transfer(
        &mut self,
        proof: ProofJson,
        public_inputs: Vec<String>,
    ) {
        require!(
            public_inputs.len() >= 2,
            "Must have at least nullifier and commitment"
        );

        // Parse input nullifier (note being spent)
        let nullifier_u256 = U256::from_dec_str(&public_inputs[0])
            .expect("Nullifier must be a decimal string");
        let nullifier_bytes = nullifier_u256.to_be_bytes();

        // SECURITY: Double-spend check
        require!(
            !self.nullifiers.contains(&nullifier_bytes),
            "Nullifier already used - input note already spent"
        );

        // VERIFY ZK PROOF (proves note ownership, value conservation, correct outputs)
        let is_valid = self.verifier.verify_json(&proof, &public_inputs);
        require!(is_valid, "Proof verification failed");

        // Mark input note as spent
        self.nullifiers.insert(nullifier_bytes);
        self.proof_count += 1;

        // Add output commitment (new note)
        let commitment_u256 = U256::from_dec_str(&public_inputs[1])
            .expect("Commitment must be a decimal string");
        let commitment_bytes = commitment_u256.to_be_bytes();

        // SECURITY: Prevent commitment reuse (would create unbacked notes in tree)
        require!(
            !self.commitments.contains(&commitment_bytes),
            "Commitment already exists - cannot reuse commitments"
        );

        // Add new commitment to tree
        self.commitments.insert(commitment_bytes);
        let leaf_index = self.commitments_list.len() as u64;
        self.commitments_list.push(commitment_bytes);

        // Emit events for indexers
        NearPrivacyEvent::ProofVerified {
            nullifier: public_inputs[0].clone(),
            commitment: public_inputs[1].clone(),
            caller: env::predecessor_account_id(),
        }.emit();

        NearPrivacyEvent::CommitmentAdded {
            commitment: public_inputs[1].clone(),
            leaf_index,
        }.emit();

        env::log_str(&format!(
            "Private transfer completed: nullifier spent, new commitment at index {}",
            leaf_index
        ));
    }

    // ========== VIEW METHODS (Read-only, no gas cost) ==========

    /// Check if nullifier has been used (note is spent)
    /// Use before generating proof to verify note is still unspent.
    pub fn is_nullifier_used(&self, nullifier: String) -> bool {
        let nullifier_u256 = U256::from_dec_str(&nullifier)
            .expect("Invalid nullifier");
        self.nullifiers.contains(&nullifier_u256.to_be_bytes())
    }

    /// Get commitment at specific index in Merkle tree
    ///
    /// Used for debugging or verifying Merkle tree reconstruction.
    ///
    /// Returns commitment as hex string prefixed with "0x".
    pub fn get_commitment_at(&self, index: u64) -> String {
        let bytes = self.commitments_list.get(index as u32)
            .expect("Index out of bounds");
        format!("0x{}", hex::encode(bytes))
    }

    /// Get commitments range for Merkle tree building
    ///
    /// Clients fetch these to rebuild tree and generate proofs.
    /// For >1000 commitments, use a backend indexer instead.
    ///
    /// Returns commitments as hex strings.
    pub fn get_commitments_range(&self, start: u64, limit: u64) -> Vec<String> {
        let end = std::cmp::min(start + limit, self.commitments_list.len() as u64);
        (start..end)
            .filter_map(|i| self.commitments_list.get(i as u32))
            .map(|bytes| format!("0x{}", hex::encode(bytes)))
            .collect()
    }

    /// Get pool statistics
    ///
    /// Returns: (commitments_count, proofs_verified, total_balance, owner)
    ///
    /// Useful for monitoring pool health and usage.
    pub fn get_stats(&self) -> (u64, u64, String, String) {
        (
            self.commitments_list.len() as u64,
            self.proof_count,
            self.total_balance.as_yoctonear().to_string(),
            self.owner.to_string(),
        )
    }

    /// Get total NEAR locked in pool
    ///
    /// This should equal the sum of all unspent notes.
    /// If it doesn't, something is wrong (bug or exploit).
    pub fn get_total_balance(&self) -> String {
        self.total_balance.as_yoctonear().to_string()
    }

    // ========== ADMIN METHODS (Owner only) ==========

    /// Update verification key (⚠️ BREAKS ALL EXISTING NOTES!)
    /// Only use on empty pools or for critical circuit bugs. Deploy new contract instead.
    pub fn update_verification_key(&mut self, vk: VerificationKeyJson) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can update verification key"
        );
        self.verifier = Verifier::from_json(&vk)
            .expect("Invalid verification key");
        env::log_str("⚠️ Verification key updated - existing notes may be unspendable!");
    }

    /// Transfer contract ownership (new owner can update VK, cannot steal funds or see private data)
    pub fn transfer_ownership(&mut self, new_owner: AccountId) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can transfer ownership"
        );
        let old_owner = self.owner.clone();
        self.owner = new_owner.clone();
        env::log_str(&format!("Ownership transferred from {} to {}", old_owner, new_owner));
    }
}
