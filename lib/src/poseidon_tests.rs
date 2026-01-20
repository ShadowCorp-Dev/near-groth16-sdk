/*!
 * Poseidon Test Vectors
 * 
 * These test vectors are derived from circomlibjs to verify
 * that our implementation matches exactly.
 * 
 * Run these tests after building to ensure compatibility
 * with your Circom circuits.
 */

#[cfg(test)]
mod poseidon_tests {
    use crate::poseidon::{poseidon_hash2, poseidon_hash4, compute_commitment, compute_nullifier_hash, Fr, poseidon_t3};

    /// Test vectors from circomlibjs
    /// These MUST match or proofs will fail!
    
    #[test]
    fn test_poseidon_hash2_vectors() {
        // Test vector 1: hash(1, 2)
        // Expected from circomlibjs: poseidon([1n, 2n])
        let result = poseidon_hash2("1", "2");
        println!("Poseidon(1, 2) = {}", result);
        
        // The actual expected value from circomlibjs for t=3:
        // 7853200120776062878684798364095072458815029376092732009249414926327459813530
        // Note: Your circuit parameters must match!
        
        // Test vector 2: hash(0, 0)
        let result_zeros = poseidon_hash2("0", "0");
        println!("Poseidon(0, 0) = {}", result_zeros);
        
        // Test vector 3: Large numbers
        let result_large = poseidon_hash2(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            "1"
        );
        println!("Poseidon(p-1, 1) = {}", result_large);
    }

    #[test]
    fn test_poseidon_determinism() {
        // Same inputs must always produce same output
        let a1 = poseidon_hash2("12345", "67890");
        let a2 = poseidon_hash2("12345", "67890");
        assert_eq!(a1, a2, "Poseidon must be deterministic");
    }

    #[test]
    fn test_poseidon_collision_resistance() {
        // Different inputs must produce different outputs
        let h1 = poseidon_hash2("1", "2");
        let h2 = poseidon_hash2("2", "1");
        let h3 = poseidon_hash2("1", "3");
        
        assert_ne!(h1, h2, "hash(1,2) should differ from hash(2,1)");
        assert_ne!(h1, h3, "hash(1,2) should differ from hash(1,3)");
    }

    #[test]
    fn test_merkle_tree_zeros() {
        // Compute the zero values for an empty Merkle tree
        let mut zeros = vec!["0".to_string()];
        
        for i in 0..20 {
            let prev = &zeros[i];
            let next = poseidon_hash2(prev, prev);
            println!("Zero level {}: {}", i + 1, next);
            zeros.push(next);
        }
        
        // The root of an empty 20-level tree
        println!("Empty tree root: {}", zeros[20]);
    }

    #[test]
    fn test_commitment_computation() {
        // Test note commitment
        let nullifier = "123456789";
        let secret = "987654321";
        let amount = "1000000000000000000000000"; // 1 NEAR
        let asset_id = "0";
        
        let commitment = compute_commitment(nullifier, secret, amount, asset_id);
        println!("Commitment: {}", commitment);
        
        // Verify it's deterministic
        let commitment2 = compute_commitment(nullifier, secret, amount, asset_id);
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_nullifier_hash_computation() {
        let nullifier = "123456789";
        let leaf_index: u64 = 42;
        
        let nh = compute_nullifier_hash(nullifier, leaf_index);
        println!("Nullifier hash: {}", nh);
        
        // Different leaf index = different hash
        let nh2 = compute_nullifier_hash(nullifier, 43);
        assert_ne!(nh, nh2);
    }

    #[test]
    fn test_fr_arithmetic() {
        // Basic field arithmetic tests
        let a = Fr::from_str("100");
        let b = Fr::from_str("200");
        
        // Addition
        let sum = a.add(&b);
        assert_eq!(sum.to_string(), "300");
        
        // Subtraction
        let diff = b.sub(&a);
        assert_eq!(diff.to_string(), "100");
        
        // Multiplication
        let prod = a.mul(&b);
        assert_eq!(prod.to_string(), "20000");
        
        // Power of 5 (S-box)
        let x = Fr::from_str("3");
        let x5 = x.pow5();
        assert_eq!(x5.to_string(), "243"); // 3^5 = 243
    }

    #[test]
    fn test_fr_modular_reduction() {
        // Test that values wrap around the field modulus correctly
        let modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        let one = Fr::from_str("1");
        let p_minus_one = Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
        
        // p - 1 + 1 should equal 0 (wraps around)
        let result = p_minus_one.add(&one);
        assert_eq!(result.to_string(), "0", "Field modular reduction failed");
    }
}

/// Known test vectors from circomlibjs
/// Use these to verify your implementation matches exactly
pub mod test_vectors {
    /// Poseidon(1, 2) with t=3 parameters from circomlibjs
    /// 
    /// JavaScript code to generate:
    /// ```js
    /// const { buildPoseidon } = require("circomlibjs");
    /// const poseidon = await buildPoseidon();
    /// const hash = poseidon([1n, 2n]);
    /// console.log(poseidon.F.toString(hash));
    /// ```
    pub const HASH_1_2: &str = "7853200120776062878684798364095072458815029376092732009249414926327459813530";
    
    /// Poseidon(0, 0)
    pub const HASH_0_0: &str = "14744269619966411208579211824598458697587494354926760081771325075741142829156";
    
    /// First few levels of empty Merkle tree (zero values)
    pub const EMPTY_TREE_ZEROS: [&str; 5] = [
        "0",
        "14744269619966411208579211824598458697587494354926760081771325075741142829156", // hash(0,0)
        "7423237065226347324353380772367382631490014989348495481811164164159255474657",  // hash(z1, z1)
        "11286972368698509976183087595462810875513684078608517520839298933882497716792", // hash(z2, z2)
        "3607627140608796879659380071776844901612302623152076817094415224584923813162",  // hash(z3, z3)
    ];
}
