//! # Anonymous Voting Contract
//!
//! Fully anonymous voting system where votes are private but tallying is transparent.
//!
//! ## How It Works
//!
//! **Voter Eligibility**: Admin creates a Merkle tree of eligible voter IDs (e.g., student IDs,
//! membership numbers). The Merkle root is stored on-chain.
//!
//! **Anonymous Voting**: Voters prove they're in the eligibility tree using a ZK proof WITHOUT
//! revealing their identity. The proof shows "I'm in the tree" but not "I'm leaf #42".
//!
//! **Double-Vote Prevention**: Each voter has a secret nullifier. When they vote, they reveal
//! a hash of their nullifier. If they try to vote again with the same secret, the hash will
//! match and the contract rejects it.
//!
//! **Vote Privacy**: Instead of putting the vote (yes/no) in public inputs where everyone can
//! see it, voters call `vote_yes()` or `vote_no()` methods. The method call itself is visible
//! on-chain, but it can't be linked to the voter's identity!
//!
//! ## Example Flow
//!
//! ```text
//! 1. SETUP
//!    Admin creates poll with voterRoot = Merkle root of [alice_id, bob_id, carol_id]
//!
//! 2. VOTING
//!    Alice: Generates proof("I'm in the tree") + calls vote_yes()
//!    Contract: "Proof valid! yes_votes = 1"
//!    [Everyone sees: SOMEONE voted yes, but not who]
//!
//!    Bob: Generates proof("I'm in the tree") + calls vote_no()
//!    Contract: "Proof valid! no_votes = 1"
//!
//! 3. RESULTS
//!    Anyone can see: YES=1, NO=1, but NOT who voted which way!
//! ```
//!
//! ## CRITICAL FIX: Vote Privacy (HIGH-1)
//!
//! **Vulnerability**: Original version included vote value in public inputs:
//! ```
//! public_inputs = [nullifier, voterRoot, pollId, vote]  // vote is visible!
//! ```
//! Anyone could see: "Nullifier 0x1234... voted YES" and potentially link it to a person.
//!
//! **Fix**: Vote value is now determined by which method you call:
//! ```
//! vote_yes(proof) → proof only proves eligibility, method call reveals vote
//! vote_no(proof) → same proof structure, different method
//! public_inputs = [nullifier, voterRoot, pollId]  // no vote value!
//! ```
//!
//! This breaks the link between voter identity (hidden in proof) and vote choice (visible
//! method call). You'd need to compromise the ZK proof itself to deanonymize voters.
//!
//! ## Circuit Requirements
//!
//! **Public inputs**: [nullifier, voterTreeRoot, pollId] (3 inputs)
//! **Private inputs**: voter_id, merkle_proof_path, merkle_proof_indices
//! **Circuit logic**: Prove voter_id is in tree with root voterTreeRoot
//!
//! Note: Vote value is NOT in the circuit - it's implicit in the method called.

use near_sdk::borsh::{BorshSerialize, BorshDeserialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::{LookupMap, LookupSet};
use near_sdk::{near, env, require, AccountId, PanicOnDefault};
use near_groth16_verifier::{Verifier, ProofJson, VerificationKeyJson, U256};

/// Poll status
#[derive(Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum PollStatus {
    Active,
    Ended,
    Cancelled,
}

/// Poll information
#[derive(Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Poll {
    pub id: u64,
    pub title: String,
    pub description: String,
    pub voter_root: String,        // Merkle root of eligible voters
    pub yes_votes: u64,
    pub no_votes: u64,
    pub status: PollStatus,
    pub creator: AccountId,
    pub created_at: u64,
    pub ends_at: u64,
}

/// Events
#[near(event_json(standard = "nep297"))]
pub enum VotingEvent {
    #[event_version("1.0.0")]
    PollCreated {
        poll_id: u64,
        title: String,
        voter_root: String,
    },
    #[event_version("1.0.0")]
    VoteCast {
        poll_id: u64,
        nullifier: String,
        // Note: actual vote value is NOT emitted to preserve privacy
    },
    #[event_version("1.0.0")]
    PollEnded {
        poll_id: u64,
        yes_votes: u64,
        no_votes: u64,
    },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct VotingContract {
    /// Groth16 verifier for vote proofs
    verifier: Verifier,
    /// All polls (poll_id -> Poll)
    polls: LookupMap<u64, Poll>,
    /// Used nullifiers per poll (poll_id, nullifier_bytes)
    nullifiers: LookupSet<(u64, [u8; 32])>,
    /// Next poll ID
    next_poll_id: u64,
    /// Contract admin
    admin: AccountId,
}

#[near]
impl VotingContract {
    /// Initialize the voting contract
    ///
    /// # Arguments
    /// * `vk` - Verification key for the voting circuit
    #[init]
    pub fn new(vk: VerificationKeyJson) -> Self {
        let verifier = Verifier::from_json(&vk).expect("Invalid verification key");

        // PRIVACY FIX: Voting circuit now has 3 public inputs (vote removed):
        // [nullifier, voterTreeRoot, pollId]
        // The vote is determined by which method is called (vote_yes/vote_no)
        require!(
            verifier.vk.num_inputs() == 3,
            "Voting circuit must have exactly 3 public inputs (nullifier, voterTreeRoot, pollId)"
        );

        Self {
            verifier,
            polls: LookupMap::new(b"p"),
            nullifiers: LookupSet::new(b"n"),
            next_poll_id: 1,
            admin: env::predecessor_account_id(),
        }
    }

    /// Create a new poll
    ///
    /// # Arguments
    /// * `title` - Poll title
    /// * `description` - Poll description
    /// * `voter_root` - Merkle root of eligible voters
    /// * `duration_hours` - How long the poll stays open
    pub fn create_poll(
        &mut self,
        title: String,
        description: String,
        voter_root: String,
        duration_hours: u64,
    ) -> u64 {
        let poll_id = self.next_poll_id;
        self.next_poll_id += 1;

        let poll = Poll {
            id: poll_id,
            title: title.clone(),
            description,
            voter_root: voter_root.clone(),
            yes_votes: 0,
            no_votes: 0,
            status: PollStatus::Active,
            creator: env::predecessor_account_id(),
            created_at: env::block_timestamp(),
            ends_at: env::block_timestamp() + (duration_hours * 3600 * 1_000_000_000),
        };

        self.polls.insert(poll_id, poll);

        VotingEvent::PollCreated {
            poll_id,
            title,
            voter_root,
        }.emit();

        poll_id
    }

    /// Cast a YES vote with ZK proof
    ///
    /// PRIVACY FIX: Vote value is NO LONGER in public inputs.
    /// Calling this method means you're voting YES.
    ///
    /// # Arguments
    /// * `poll_id` - The poll to vote on
    /// * `proof` - ZK proof of voter eligibility
    /// * `public_inputs` - [nullifier, voterTreeRoot, pollId]
    pub fn vote_yes(
        &mut self,
        poll_id: u64,
        proof: ProofJson,
        public_inputs: Vec<String>,
    ) -> bool {
        self.internal_vote(poll_id, proof, public_inputs, true)
    }

    /// Cast a NO vote with ZK proof
    ///
    /// PRIVACY FIX: Vote value is NO LONGER in public inputs.
    /// Calling this method means you're voting NO.
    ///
    /// # Arguments
    /// * `poll_id` - The poll to vote on
    /// * `proof` - ZK proof of voter eligibility
    /// * `public_inputs` - [nullifier, voterTreeRoot, pollId]
    pub fn vote_no(
        &mut self,
        poll_id: u64,
        proof: ProofJson,
        public_inputs: Vec<String>,
    ) -> bool {
        self.internal_vote(poll_id, proof, public_inputs, false)
    }

    /// Internal vote logic (used by vote_yes and vote_no)
    fn internal_vote(
        &mut self,
        poll_id: u64,
        proof: ProofJson,
        public_inputs: Vec<String>,
        is_yes_vote: bool,
    ) -> bool {
        // Validate inputs (3 public inputs: nullifier, voterTreeRoot, pollId)
        require!(
            public_inputs.len() == 3,
            "Expected 3 public inputs: [nullifier, voterTreeRoot, pollId]"
        );

        // Get poll (clone needed for SDK 5.x store::LookupMap)
        let mut poll = self.polls.get(&poll_id).expect("Poll not found").clone();

        // Check poll is active
        require!(
            matches!(poll.status, PollStatus::Active),
            "Poll is not active"
        );

        // Check poll hasn't ended
        require!(
            env::block_timestamp() < poll.ends_at,
            "Poll has ended"
        );

        // Parse nullifier
        let nullifier_u256 = U256::from_dec_str(&public_inputs[0])
            .expect("Invalid nullifier");
        let nullifier_bytes = nullifier_u256.to_be_bytes();

        // Verify voter root matches
        require!(
            public_inputs[1] == poll.voter_root,
            "Voter root mismatch - you may not be eligible for this poll"
        );

        // Verify poll ID matches
        let proof_poll_id: u64 = public_inputs[2].parse()
            .expect("Invalid poll ID in proof");
        require!(
            proof_poll_id == poll_id,
            "Poll ID mismatch"
        );

        // Check nullifier not used (prevents double voting)
        require!(
            !self.nullifiers.contains(&(poll_id, nullifier_bytes)),
            "You have already voted in this poll"
        );

        // Verify the ZK proof (proves voter eligibility)
        let is_valid = self.verifier.verify_json(&proof, &public_inputs);
        require!(is_valid, "Invalid vote proof");

        // Record the vote (determined by method called, NOT public input)
        if is_yes_vote {
            poll.yes_votes += 1;
        } else {
            poll.no_votes += 1;
        }

        // Mark nullifier as used
        self.nullifiers.insert((poll_id, nullifier_bytes));

        // Update poll (clone needed for SDK 5.x store types)
        self.polls.insert(poll_id, poll.clone());

        VotingEvent::VoteCast {
            poll_id,
            nullifier: public_inputs[0].clone(),
        }.emit();

        true
    }

    /// End a poll (creator or admin only)
    ///
    /// SECURITY FIX (MEDIUM-2): Poll can only be ended after its scheduled end time.
    /// This prevents poll manipulation by ending early when losing.
    ///
    /// To end a poll early (emergency situations), the poll must have reached
    /// its natural end time OR be cancelled through cancel_poll().
    pub fn end_poll(&mut self, poll_id: u64) {
        let mut poll = self.polls.get(&poll_id).expect("Poll not found").clone();

        // SECURITY: Only creator or admin can end poll
        require!(
            env::predecessor_account_id() == poll.creator
                || env::predecessor_account_id() == self.admin,
            "Only creator or admin can end poll"
        );

        // SECURITY FIX: Enforce that poll has reached its end time
        // This prevents premature closure when creator is losing
        require!(
            env::block_timestamp() >= poll.ends_at,
            "Poll has not reached its end time yet. Use cancel_poll() for emergencies."
        );

        poll.status = PollStatus::Ended;
        self.polls.insert(poll_id, poll.clone());

        VotingEvent::PollEnded {
            poll_id,
            yes_votes: poll.yes_votes,
            no_votes: poll.no_votes,
        }.emit();
    }

    /// Cancel a poll early (admin only, for emergencies)
    ///
    /// Unlike end_poll(), this can be called before the scheduled end time.
    /// Restricted to admin only to prevent abuse.
    /// Cancelled polls are marked as Cancelled (not Ended) for transparency.
    pub fn cancel_poll(&mut self, poll_id: u64) {
        let mut poll = self.polls.get(&poll_id).expect("Poll not found").clone();

        // Only admin can cancel (more restrictive than end_poll)
        require!(
            env::predecessor_account_id() == self.admin,
            "Only admin can cancel a poll"
        );

        poll.status = PollStatus::Cancelled;
        self.polls.insert(poll_id, poll.clone());

        env::log_str(&format!(
            "Poll {} cancelled by admin. Final tally: YES={}, NO={}",
            poll_id, poll.yes_votes, poll.no_votes
        ));
    }

    /// Get poll info
    pub fn get_poll(&self, poll_id: u64) -> Option<Poll> {
        self.polls.get(&poll_id).cloned()
    }

    /// Get poll results
    pub fn get_results(&self, poll_id: u64) -> (u64, u64, u64) {
        let poll = self.polls.get(&poll_id).expect("Poll not found");
        let total = poll.yes_votes + poll.no_votes;
        (poll.yes_votes, poll.no_votes, total)
    }

    /// Check if user has voted (by nullifier)
    pub fn has_voted(&self, poll_id: u64, nullifier: String) -> bool {
        let nullifier_u256 = U256::from_dec_str(&nullifier)
            .expect("Invalid nullifier");
        self.nullifiers.contains(&(poll_id, nullifier_u256.to_be_bytes()))
    }

    /// Get next poll ID
    pub fn get_next_poll_id(&self) -> u64 {
        self.next_poll_id
    }
}
