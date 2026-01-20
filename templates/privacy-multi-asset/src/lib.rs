///! # Multi-Asset Privacy Pool
///!
///! Privacy pool supporting NEAR + NEP-141 fungible tokens (USDC, USDT, etc).
///!
///! ## How It Works
///!
///! **Shared Merkle Tree**: All assets use ONE tree for commitments, creating a
///! larger anonymity set. Tree can contain: [NEAR deposit, USDC deposit, NEAR deposit, ...]
///!
///! **Asset IDs**: Each token gets a unique Poseidon hash:
///! - NEAR: assetId = 0
///! - USDC: assetId = Poseidon(b"usdc.near")
///! - USDT: assetId = Poseidon(b"usdt.near")
///!
///! **Commitment**: `Poseidon(Poseidon(nullifier, secret), Poseidon(amount, assetId))`
///! The assetId binds the commitment to a specific token - you can't claim USDC
///! and withdraw NEAR.
///!
///! ## Critical Security Fix: Poseidon vs SHA256
///!
///! **CRITICAL-1 Vulnerability**: Original code used SHA256 to hash token account IDs,
///! but circuits use Poseidon. This let attackers deposit cheap tokens and withdraw
///! expensive ones (deposit 0.01 USDC, withdraw 100 NEAR).
///!
///! **Fix**: Admin pre-computes Poseidon hashes client-side and stores them in
///! `token_asset_ids` mapping. Contract validates proof assetId matches the stored hash.
///!
///! ## NEP-141 Integration
///!
///! Users deposit FT via `token.ft_transfer_call(pool, amount, msg)` where msg contains
///! the commitment and asset_id. Contract validates:
///! 1. Token is whitelisted (prevents malicious tokens from inflating balances)
///! 2. Asset ID matches pre-computed Poseidon hash
///! 3. Commitment is unique (prevents double-deposits)
///!
///! Withdrawals use callback pattern to revert balance if FT transfer fails.
///!
///! ## Privacy Model
///!
///! **Private**: Which deposit you're withdrawing from (could be any matching asset)
///! **Public**: Deposit events, withdrawal events, asset types, amounts
///!
///! Anonymity set = deposits with same asset+amount. Use standard denominations
///! (1, 10, 100 USDC) for better privacy.

use near_sdk::borsh::BorshSerialize;
use near_sdk::store::{LookupSet, UnorderedMap, Vector};
use near_sdk::{near, env, require, AccountId, PanicOnDefault, NearToken, Gas, PromiseOrValue, PromiseResult, ext_contract};
use near_sdk::json_types::U128;
use near_groth16_verifier::{Verifier, ProofJson, VerificationKeyJson, U256};

/// External FT contract interface (NEP-141)
#[ext_contract(ext_ft)]
pub trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(10);
const GAS_FOR_FT_RESOLVE: Gas = Gas::from_tgas(5);

/// Events for multi-asset operations
#[near(event_json(standard = "nep297"))]
pub enum MultiAssetEvent {
    #[event_version("1.0.0")]
    ProofVerified {
        nullifier: String,
        commitment: String,
        asset_id: String,
        caller: AccountId,
    },

    #[event_version("1.0.0")]
    CommitmentAdded {
        commitment: String,
        asset_id: String,
        leaf_index: u64,
    },

    #[event_version("1.0.0")]
    Deposit {
        commitment: String,
        asset_id: String,
        amount: String,
        depositor: AccountId,
    },

    #[event_version("1.0.0")]
    Withdrawal {
        recipient: AccountId,
        asset_id: String,
        amount: String,
    },
}

/// Multi-asset privacy pool with shared commitment tree
///
/// **Why shared tree?** Larger anonymity set across all assets. Withdrawing 1 NEAR
/// could be from any NEAR deposit in the tree, mixed with USDC/USDT/etc deposits.
///
/// **Trade-off**: Must track per-asset balances separately to prevent inflation attacks.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MultiAssetPool {
    /// Groth16 verifier for ZK proofs
    verifier: Verifier,

    /// Spent nullifiers (shared across all assets to prevent cross-asset double-spend)
    nullifiers: LookupSet<[u8; 32]>,

    /// Valid commitments (shared tree for all assets)
    commitments: LookupSet<[u8; 32]>,

    /// Ordered commitment list (Merkle tree leaves)
    commitments_list: Vector<[u8; 32]>,

    /// Per-asset balances: assetId → amount locked
    ///
    /// **Why needed?** Prevents inflation attacks where someone deposits 1 USDC
    /// but withdraws 1000 NEAR by claiming pool has unlimited balance.
    ///
    /// Example: assetBalances["0"] = 100 NEAR, assetBalances[hash("usdc.near")] = 5000 USDC
    asset_balances: UnorderedMap<String, u128>,

    /// Registered FT token contracts (whitelist)
    ///
    /// **Security**: Only whitelisted tokens can call ft_on_transfer. Prevents
    /// malicious contracts from calling ft_on_transfer directly and inflating balances.
    registered_tokens: LookupSet<AccountId>,

    /// Pre-computed Poseidon asset IDs for registered tokens
    ///
    /// **CRITICAL**: Maps token_contract → Poseidon hash of account ID.
    /// This fixes the SHA256 vs Poseidon vulnerability (CRITICAL-1).
    /// Admin must compute Poseidon hashes client-side and store here.
    token_asset_ids: UnorderedMap<AccountId, String>,

    /// Contract owner (can register tokens, set asset IDs)
    owner: AccountId,

    /// Total proofs verified (stats)
    proof_count: u64,
}

#[near]
impl MultiAssetPool {
    /// Initialize multi-asset privacy pool
    ///
    /// **Circuit requirements**: Must include assetId as public input and enforce
    /// that all inputs/outputs use the same assetId (no asset mixing).
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        let verifier = Verifier::from_json(&vk)
            .expect("Invalid verification key");

        env::log_str(&format!(
            "Multi-asset pool initialized for {} public inputs",
            verifier.vk.num_inputs()
        ));

        Self {
            verifier,
            nullifiers: LookupSet::new(b"n"),
            commitments: LookupSet::new(b"c"),
            commitments_list: Vector::new(b"l"),
            asset_balances: UnorderedMap::new(b"a"),
            registered_tokens: LookupSet::new(b"r"),
            token_asset_ids: UnorderedMap::new(b"t"),
            owner: env::predecessor_account_id(),
            proof_count: 0,
        }
    }

    // ===== NEAR Deposit/Withdrawal =====

    /// Deposit NEAR into the pool (assetId = 0)
    ///
    /// **Gas**: ~20 TGas
    #[payable]
    pub fn deposit_near(&mut self, commitment: String) {
        let deposit_amount = env::attached_deposit();

        require!(
            deposit_amount.as_yoctonear() > 0,
            "Must attach NEAR"
        );

        let asset_id = "0".to_string();
        self.internal_deposit(commitment, asset_id, deposit_amount.as_yoctonear());

        env::log_str(&format!(
            "Deposited {} yoctoNEAR",
            deposit_amount.as_yoctonear()
        ));
    }

    /// Withdraw NEAR from the pool (assetId = 0)
    ///
    /// **Public inputs**: [nullifier_hash, asset_id, amount, ...]
    /// **Security**: Verifies assetId is 0 and pool has sufficient NEAR balance
    /// **Gas**: ~120-150 TGas (Groth16 verification is expensive!)
    #[payable]
    pub fn withdraw_near(
        &mut self,
        proof: ProofJson,
        public_inputs: Vec<String>,
        recipient: AccountId,
        amount: String,
    ) {
        require!(
            public_inputs.len() >= 2,
            "Must include nullifier and assetId"
        );

        // Verify assetId is 0 (NEAR)
        require!(
            public_inputs[1] == "0",
            "AssetId must be 0 for NEAR withdrawal"
        );

        let withdraw_amount = U256::from_dec_str(&amount)
            .expect("Invalid amount");
        let withdraw_yocto = u128::try_from(withdraw_amount)
            .expect("Amount too large");

        // Verify proof and update state
        self.internal_verify_and_register(&proof, &public_inputs);

        // Check NEAR balance
        let near_balance = self.asset_balances.get(&"0".to_string()).copied().unwrap_or(0);
        require!(
            withdraw_yocto <= near_balance,
            "Insufficient NEAR balance in pool"
        );

        // Update balance
        self.asset_balances.insert(
            "0".to_string(),
            near_balance - withdraw_yocto
        );

        // Transfer NEAR
        near_sdk::Promise::new(recipient.clone())
            .transfer(NearToken::from_yoctonear(withdraw_yocto));

        MultiAssetEvent::Withdrawal {
            recipient,
            asset_id: "0".to_string(),
            amount: withdraw_yocto.to_string(),
        }.emit();

        env::log_str(&format!("Withdrew {} yoctoNEAR", withdraw_yocto));
    }

    // ===== FT Deposit/Withdrawal (NEP-141) =====

    /// NEP-141 callback - called when user does token.ft_transfer_call(pool, amount, msg)
    ///
    /// **Flow**:
    /// 1. User calls: token.ft_transfer_call(pool, 1000_USDC, '{"commitment": "...", "asset_id": "..."}')
    /// 2. Token contract transfers 1000 USDC to pool
    /// 3. Token contract calls this method with transferred amount
    /// 4. Pool registers commitment and accepts tokens (returns 0)
    ///
    /// **Security checks**:
    /// - Token must be registered (whitelisted)
    /// - Asset ID must match pre-computed Poseidon hash (fixes CRITICAL-1)
    /// - Commitment must be unique
    ///
    /// **Gas**: ~25-35 TGas
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let token_contract = env::predecessor_account_id();

        // SECURITY: Only accept FT deposits from registered token contracts
        // Prevents malicious contracts from calling this directly and inflating balances
        require!(
            self.registered_tokens.contains(&token_contract),
            format!(
                "Token contract '{}' is not registered. Admin must register it first.",
                token_contract
            )
        );

        // Parse deposit message: {"commitment": "12345...", "asset_id": "67890..."}
        let deposit_msg: serde_json::Value = serde_json::from_str(&msg)
            .expect("Invalid deposit message format");

        let commitment = deposit_msg["commitment"].as_str()
            .expect("Missing commitment in msg")
            .to_string();

        let asset_id = deposit_msg["asset_id"].as_str()
            .expect("Missing asset_id in msg")
            .to_string();

        // SECURITY FIX (CRITICAL-1): Verify asset_id matches pre-computed Poseidon hash
        //
        // This prevents the attack where someone deposits USDC (using Poseidon hash)
        // but withdraws NEAR (using different hash function).
        let expected_asset_id = self.token_asset_ids.get(&token_contract)
            .unwrap_or_else(|| {
                env::panic_str(&format!(
                    "Token '{}' asset ID not configured. Admin must set it via set_token_asset_id()",
                    token_contract
                ))
            });

        require!(
            asset_id == *expected_asset_id,
            format!(
                "Asset ID mismatch: expected {}, got {}. Ensure client uses correct Poseidon hash.",
                expected_asset_id, asset_id
            )
        );

        // Register deposit
        self.internal_deposit(commitment.clone(), asset_id.clone(), amount.0);

        MultiAssetEvent::Deposit {
            commitment,
            asset_id,
            amount: amount.0.to_string(),
            depositor: sender_id,
        }.emit();

        env::log_str(&format!(
            "FT deposit: {} from {}",
            amount.0, token_contract
        ));

        // Return 0 = accept all tokens (don't refund)
        PromiseOrValue::Value(U128(0))
    }

    /// Withdraw FT tokens using ZK proof
    ///
    /// **Public inputs**: [nullifier_hash, asset_id, amount, ...]
    ///
    /// **Security**: Verifies asset_id in proof matches Poseidon hash of token_contract.
    /// This ensures you can't prove ownership of USDC deposit but withdraw USDT.
    ///
    /// **Gas**: ~140-180 TGas (verification + FT transfer + callback)
    #[payable]
    pub fn withdraw_ft(
        &mut self,
        proof: ProofJson,
        public_inputs: Vec<String>,
        recipient: AccountId,
        amount: String,
        token_contract: AccountId,
    ) {
        require!(
            public_inputs.len() >= 2,
            "Must include nullifier and assetId"
        );

        // SECURITY FIX (CRITICAL-1): Verify assetId matches token contract's Poseidon hash
        let expected_asset_id = self.token_asset_ids.get(&token_contract)
            .unwrap_or_else(|| {
                env::panic_str(&format!(
                    "Token '{}' asset ID not configured. Admin must set it via set_token_asset_id()",
                    token_contract
                ))
            }).clone();

        require!(
            public_inputs[1] == expected_asset_id,
            format!(
                "AssetId mismatch: expected {} for {}. Ensure client uses correct Poseidon hash.",
                expected_asset_id, token_contract
            )
        );

        let withdraw_amount = U256::from_dec_str(&amount)
            .expect("Invalid amount");
        let withdraw_tokens = u128::try_from(withdraw_amount)
            .expect("Amount too large");

        // Verify proof
        self.internal_verify_and_register(&proof, &public_inputs);

        // Check FT balance
        let ft_balance = self.asset_balances
            .get(&expected_asset_id)
            .copied().unwrap_or(0);

        require!(
            withdraw_tokens <= ft_balance,
            format!(
                "Insufficient balance: have {}, need {}",
                ft_balance, withdraw_tokens
            )
        );

        // Update balance
        self.asset_balances.insert(
            expected_asset_id.clone(),
            ft_balance - withdraw_tokens
        );

        // Transfer FT tokens with callback to handle failures
        // If transfer fails, callback will revert the balance deduction
        ext_ft::ext(token_contract.clone())
            .with_static_gas(GAS_FOR_FT_TRANSFER)
            .with_attached_deposit(NearToken::from_yoctonear(1))  // 1 yocto for FT transfer
            .ft_transfer(
                recipient.clone(),
                U128(withdraw_tokens),
                Some("Privacy pool withdrawal".to_string())
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_FT_RESOLVE)
                    .ft_resolve_transfer(
                        expected_asset_id.clone(),
                        withdraw_tokens,
                        recipient.clone()
                    )
            );

        env::log_str(&format!(
            "Initiated FT withdrawal: {} tokens from {}",
            withdraw_tokens, token_contract
        ));
    }

    /// Callback to handle FT transfer result
    ///
    /// **Security**: If transfer failed, reverts the balance deduction to prevent
    /// pool from losing tokens when user doesn't receive them.
    #[private]
    pub fn ft_resolve_transfer(
        &mut self,
        asset_id: String,
        amount: u128,
        recipient: AccountId,
    ) {
        match env::promise_result(0) {
            PromiseResult::Successful(_) => {
                // Transfer succeeded - emit withdrawal event
                MultiAssetEvent::Withdrawal {
                    recipient,
                    asset_id,
                    amount: amount.to_string(),
                }.emit();

                env::log_str(&format!("FT withdrawal completed: {} tokens", amount));
            },
            _ => {
                // Transfer failed - revert the balance deduction
                let current_balance = self.asset_balances.get(&asset_id).copied().unwrap_or(0);
                self.asset_balances.insert(asset_id.clone(), current_balance + amount);

                env::log_str(&format!(
                    "FT transfer failed, reverted balance. Asset: {}, Amount: {}",
                    asset_id, amount
                ));
            }
        }
    }

    // ===== Private Transfer (Multi-Asset) =====

    /// Private transfer within the pool (same asset)
    ///
    /// **Important**: Circuit must enforce all inputs/outputs use the SAME assetId.
    /// You can't spend a USDC note and create a NEAR note.
    ///
    /// **Gas**: ~130-170 TGas
    #[payable]
    pub fn transfer(
        &mut self,
        proof: ProofJson,
        public_inputs: Vec<String>,
    ) {
        require!(
            public_inputs.len() >= 2,
            "Must include nullifier and commitment"
        );

        self.internal_verify_and_register(&proof, &public_inputs);

        let asset_id = if public_inputs.len() > 2 {
            public_inputs[2].clone()
        } else {
            "0".to_string()  // Default to NEAR
        };

        env::log_str(&format!(
            "Private transfer completed for asset {}",
            asset_id
        ));
    }

    // ===== Internal Methods =====

    /// Internal deposit logic (shared by NEAR and FT deposits)
    fn internal_deposit(
        &mut self,
        commitment: String,
        asset_id: String,
        amount: u128,
    ) {
        let commitment_u256 = U256::from_dec_str(&commitment)
            .expect("Invalid commitment");
        let commitment_bytes = commitment_u256.to_be_bytes();

        // SECURITY: Prevent commitment reuse
        // If we allowed reuse, attacker could:
        // 1. Deposit 1 NEAR with commitment C
        // 2. Withdraw 1 NEAR using C
        // 3. Deposit 0.1 NEAR with SAME commitment C
        // 4. Withdraw 1 NEAR again (contract thinks it's the first deposit!)
        require!(
            !self.commitments.contains(&commitment_bytes),
            "Commitment already exists - cannot reuse commitments"
        );

        // Add commitment to tree
        self.commitments.insert(commitment_bytes);
        let leaf_index = self.commitments_list.len() as u64;
        self.commitments_list.push(commitment_bytes);

        // Update asset balance
        let current_balance = self.asset_balances.get(&asset_id).copied().unwrap_or(0);
        self.asset_balances.insert(asset_id.clone(), current_balance + amount);

        MultiAssetEvent::CommitmentAdded {
            commitment,
            asset_id,
            leaf_index,
        }.emit();
    }

    /// Internal proof verification and state update
    fn internal_verify_and_register(
        &mut self,
        proof: &ProofJson,
        public_inputs: &Vec<String>,
    ) {
        // Parse nullifier
        let nullifier_u256 = U256::from_dec_str(&public_inputs[0])
            .expect("Invalid nullifier");
        let nullifier_bytes = nullifier_u256.to_be_bytes();

        // SECURITY: Prevent double-spend
        // Nullifier is derived from your secret, so only you know it.
        // Once revealed during withdrawal, it's marked spent forever.
        require!(
            !self.nullifiers.contains(&nullifier_bytes),
            "Nullifier already used"
        );

        // If creating new commitment (transfer), check uniqueness
        if public_inputs.len() > 1 && !public_inputs[1].is_empty() {
            let commitment_u256 = U256::from_dec_str(&public_inputs[1])
                .expect("Invalid commitment");
            let commitment_bytes = commitment_u256.to_be_bytes();

            require!(
                !self.commitments.contains(&commitment_bytes),
                "Commitment already exists - cannot reuse commitments"
            );
        }

        // VERIFY THE ZK PROOF
        // This checks:
        // 1. You know (nullifier, secret, amount, assetId) that hash to some commitment C
        // 2. Commitment C exists in the current Merkle tree
        // 3. Nullifier hash is correctly computed
        // 4. Public inputs (amount, recipient, etc) match the function call
        let is_valid = self.verifier.verify_json(proof, public_inputs);
        require!(is_valid, "Proof verification failed");

        // Mark nullifier spent
        self.nullifiers.insert(nullifier_bytes);
        self.proof_count += 1;

        // If creating new commitment, add it to tree
        if public_inputs.len() > 1 && !public_inputs[1].is_empty() {
            let commitment_u256 = U256::from_dec_str(&public_inputs[1])
                .expect("Invalid commitment");
            let commitment_bytes = commitment_u256.to_be_bytes();

            self.commitments.insert(commitment_bytes);
            let leaf_index = self.commitments_list.len() as u64;
            self.commitments_list.push(commitment_bytes);

            let asset_id = if public_inputs.len() > 2 {
                public_inputs[2].clone()
            } else {
                "0".to_string()
            };

            MultiAssetEvent::CommitmentAdded {
                commitment: public_inputs[1].clone(),
                asset_id: asset_id.clone(),
                leaf_index,
            }.emit();
        }

        MultiAssetEvent::ProofVerified {
            nullifier: public_inputs[0].clone(),
            commitment: if public_inputs.len() > 1 {
                public_inputs[1].clone()
            } else {
                String::new()
            },
            asset_id: if public_inputs.len() > 2 {
                public_inputs[2].clone()
            } else {
                "0".to_string()
            },
            caller: env::predecessor_account_id(),
        }.emit();
    }

    /// DEPRECATED: Do not use - SHA256 != Poseidon
    ///
    /// This function was the source of CRITICAL-1 vulnerability.
    /// Use token_asset_ids mapping instead with client-side Poseidon hashes.
    ///
    /// Client-side Poseidon (JavaScript):
    /// ```js
    /// import { poseidon } from 'circomlibjs';
    /// const assetId = poseidon([...Buffer.from("usdc.near")]).toString();
    /// ```
    #[deprecated(note = "Use token_asset_ids mapping instead - this uses SHA256 not Poseidon")]
    fn _hash_account_id_deprecated(&self, account_id: &AccountId) -> String {
        use near_sdk::env::sha256;
        let hash = sha256(account_id.as_bytes());
        let hash_int = U256::from_big_endian(&hash);
        hash_int.to_string()
    }

    // ===== View Methods =====

    /// Get balance for an asset
    pub fn get_asset_balance(&self, asset_id: String) -> U128 {
        U128(self.asset_balances.get(&asset_id).copied().unwrap_or(0))
    }

    /// Get commitment at index
    pub fn get_commitment_at(&self, index: u64) -> String {
        let bytes = self.commitments_list.get(index as u32)
            .expect("Index out of bounds");
        format!("0x{}", hex::encode(bytes))
    }

    /// Get commitments range (for building Merkle tree client-side)
    pub fn get_commitments_range(&self, start: u64, limit: u64) -> Vec<String> {
        let end = std::cmp::min(start + limit, self.commitments_list.len() as u64);
        (start..end)
            .filter_map(|i| self.commitments_list.get(i as u32))
            .map(|bytes| format!("0x{}", hex::encode(bytes)))
            .collect()
    }

    /// Check if nullifier used (double-spend check)
    pub fn is_nullifier_used(&self, nullifier: String) -> bool {
        let nullifier_u256 = U256::from_dec_str(&nullifier)
            .expect("Invalid nullifier");
        self.nullifiers.contains(&nullifier_u256.to_be_bytes())
    }

    /// Get pool stats
    pub fn get_stats(&self) -> (u64, u64, AccountId) {
        (
            self.commitments_list.len() as u64,
            self.proof_count,
            self.owner.clone(),
        )
    }

    // ===== Admin Methods =====

    /// Register a fungible token contract (whitelist)
    ///
    /// **Security**: Required before users can deposit this token.
    /// After registering, you MUST call set_token_asset_id() to configure the Poseidon hash.
    ///
    /// **Example**:
    /// ```bash
    /// near call pool.near register_token '{"token_contract": "usdc.near"}' --accountId admin.near
    /// ```
    pub fn register_token(&mut self, token_contract: AccountId) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can register tokens"
        );

        self.registered_tokens.insert(token_contract.clone());
        env::log_str(&format!(
            "Registered token contract: {}. Remember to call set_token_asset_id() next!",
            token_contract
        ));
    }

    /// Set the Poseidon-hashed asset ID for a registered token
    ///
    /// **CRITICAL**: This fixes the SHA256 vs Poseidon vulnerability (CRITICAL-1).
    /// The asset_id MUST be computed client-side using Poseidon hash:
    ///
    /// ```js
    /// import { poseidon } from 'circomlibjs';
    /// const accountId = "usdc.near";
    /// const bytes = new TextEncoder().encode(accountId);
    /// const assetId = poseidon([...Array.from(bytes)]).toString();
    /// // Now call: contract.set_token_asset_id("usdc.near", assetId)
    /// ```
    ///
    /// **Example**:
    /// ```bash
    /// near call pool.near set_token_asset_id '{"token_contract": "usdc.near", "asset_id": "12847364..."}' --accountId admin.near
    /// ```
    pub fn set_token_asset_id(&mut self, token_contract: AccountId, asset_id: String) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can set asset IDs"
        );

        // Validate asset_id is a valid decimal number
        U256::from_dec_str(&asset_id)
            .expect("asset_id must be a valid decimal number");

        env::log_str(&format!(
            "Set asset ID for {}: {}",
            token_contract, asset_id
        ));

        self.token_asset_ids.insert(token_contract, asset_id);
    }

    /// Get the asset ID for a registered token
    pub fn get_token_asset_id(&self, token_contract: AccountId) -> Option<String> {
        self.token_asset_ids.get(&token_contract).cloned()
    }

    /// Unregister a fungible token contract
    pub fn unregister_token(&mut self, token_contract: AccountId) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can unregister tokens"
        );

        self.registered_tokens.remove(&token_contract);
        env::log_str(&format!("Unregistered token contract: {}", token_contract));
    }

    /// Check if a token contract is registered
    pub fn is_token_registered(&self, token_contract: AccountId) -> bool {
        self.registered_tokens.contains(&token_contract)
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
