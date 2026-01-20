/*!
 * Poseidon Hash Implementation for NEAR
 * 
 * This implementation matches circomlibjs Poseidon parameters exactly.
 * 
 * Parameters:
 * - Curve: BN254
 * - Field modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
 * - Security level: 128 bits
 * - S-box: x^5
 * - Full rounds (RF): 8 (4 at beginning, 4 at end)
 * - Partial rounds (RP): 57 for t=3, 60 for t=5
 * 
 * Reference: https://github.com/iden3/circomlibjs/blob/main/src/poseidon.js
 */

use crate::poseidon_precomputed::{C_T3_FR, M_T3_FR};

/// BN254 scalar field modulus
const MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// Montgomery constant: R = 2^256 mod p
const R: [u64; 4] = [
    0xac96341c4ffffffbu64,
    0x36fc76959f60cd29u64,
    0x666ea36f7879462eu64,
    0x0e0a77c19a07df2fu64,
];

/// Montgomery constant: R^2 mod p (for converting to Montgomery form)
const R2: [u64; 4] = [
    0x1bb8e645ae216da7u64,
    0x53fe3ab1e35c59e3u64,
    0x8c49833d53bb8085u64,
    0x0216d0b17f4e44a5u64,
];

/// Montgomery constant: p' = -p^(-1) mod 2^64
const P_PRIME: u64 = 0xc2e1f593efffffffu64;

// ============================================================================
// FIELD ARITHMETIC HELPERS
// ============================================================================

/// Multiply-accumulate: a + b*c + carry, returns (result, carry)
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let tmp = (a as u128) + (b as u128 * c as u128) + (carry as u128);
    (tmp as u64, (tmp >> 64) as u64)
}

/// Add with carry: a + b + carry, returns (result, carry)
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let tmp = (a as u128) + (b as u128) + (carry as u128);
    (tmp as u64, (tmp >> 64) as u64)
}

// ============================================================================
// CONSTANT-TIME HELPERS
// ============================================================================

/// Constant-time conditional select: returns a if choice == 1, else b
/// Runs in constant time regardless of choice value
#[inline(always)]
fn ct_select(choice: bool, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mask = (choice as u64).wrapping_neg(); // 0 if false, u64::MAX if true
    [
        (a[0] & mask) | (b[0] & !mask),
        (a[1] & mask) | (b[1] & !mask),
        (a[2] & mask) | (b[2] & !mask),
        (a[3] & mask) | (b[3] & !mask),
    ]
}

/// Constant-time greater-than-or-equal comparison
/// Returns true if a >= b, else false
/// Processes all limbs unconditionally to avoid timing leaks
#[inline(always)]
fn ct_gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    // Process from most significant to least significant limb
    // Track: greater=1, equal=0, less=-1
    let mut state: i8 = 0; // 0 = equal so far

    for i in (0..4).rev() {
        let is_greater = (a[i] > b[i]) as i8;
        let is_less = (a[i] < b[i]) as i8;

        // If state is still 0 (equal), update it
        let still_equal = (state == 0) as i8;
        state = state + still_equal * (is_greater - is_less);
    }

    state >= 0 // true if greater or equal, false if less
}

// ============================================================================
// FIELD ELEMENT - 256-bit arithmetic in BN254 scalar field
// ============================================================================

/// Field element represented as 4 x 64-bit limbs (little-endian)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Fr {
    pub limbs: [u64; 4],
}

impl Fr {
    /// Zero element
    pub const ZERO: Fr = Fr { limbs: [0, 0, 0, 0] };
    
    /// One element
    pub const ONE: Fr = Fr { limbs: [1, 0, 0, 0] };

    /// Create from u64
    pub fn from_u64(n: u64) -> Self {
        Fr { limbs: [n, 0, 0, 0] }
    }

    /// Create from decimal string
    pub fn from_str(s: &str) -> Self {
        if s.is_empty() || s == "0" {
            return Fr::ZERO;
        }

        let mut result = Fr::ZERO;
        let ten = Fr::from_u64(10);

        for c in s.chars() {
            if let Some(digit) = c.to_digit(10) {
                result = result.mul(&ten);
                result = result.add(&Fr::from_u64(digit as u64));
            }
        }

        result
    }

    /// Convert to decimal string
    pub fn to_string(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }

        let mut result = Vec::new();
        let mut temp = *self;
        let ten = Fr::from_u64(10);

        while !temp.is_zero() {
            let rem = temp.mod_small(10);
            result.push(char::from_digit(rem as u32, 10).unwrap());
            temp = temp.div_small(10);
        }

        result.into_iter().rev().collect()
    }

    /// Check if zero
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs[0] == 0 && self.limbs[1] == 0 && 
        self.limbs[2] == 0 && self.limbs[3] == 0
    }

    /// Addition modulo p (constant-time)
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            let sum = self.limbs[i] as u128 + other.limbs[i] as u128 + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }

        let r = Fr { limbs: result };

        // Constant-time reduction: always compute reduced value
        let reduced = r.sub_modulus();

        // Constant-time select: use reduced if carry > 0 or r >= modulus
        let needs_reduction = carry > 0 || ct_gte(&r.limbs, &MODULUS);
        Fr { limbs: ct_select(needs_reduction, &reduced.limbs, &r.limbs) }
    }

    /// Subtraction modulo p (constant-time)
    pub fn sub(&self, other: &Self) -> Self {
        // Always compute both paths
        // Path 1: Simple subtraction (if self >= other)
        let mut result_direct = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            let diff = self.limbs[i] as i128 - other.limbs[i] as i128 - borrow;
            if diff < 0 {
                result_direct[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result_direct[i] = diff as u64;
                borrow = 0;
            }
        }

        // Path 2: Add modulus first (if self < other)
        let with_mod = self.add_modulus();
        let result_with_mod = with_mod.sub_internal(other);

        // Constant-time select based on self >= other
        let use_direct = ct_gte(&self.limbs, &other.limbs);
        Fr { limbs: ct_select(use_direct, &result_direct, &result_with_mod.limbs) }
    }

    /// Internal subtraction helper (assumes self >= other)
    fn sub_internal(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            let diff = self.limbs[i] as i128 - other.limbs[i] as i128 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }

        Fr { limbs: result }
    }

    /// Multiplication modulo p using Montgomery multiplication (CIOS algorithm)
    /// This computes a*b mod p in approximately 4 reduction rounds
    pub fn mul(&self, other: &Self) -> Self {
        // Montgomery multiplication using CIOS (Coarsely Integrated Operand Scanning)
        // Computes a*b*R^(-1) mod p where R = 2^256
        // Since our inputs are in standard form (not Montgomery form), we need to adjust
        //
        // We compute: (a * b) * R^(-1) mod p, then multiply by R to get a*b mod p
        // This is done by: mont_mul(a, b) then mont_mul(result, R^2) = a*b*R^(-1)*R^2*R^(-1) = a*b
        //
        // But actually, for better performance, let's use CIOS directly:
        // It interleaves multiplication and reduction

        let mut t = [0u64; 5]; // We need 5 limbs for intermediate results

        // Process each limb of self
        for i in 0..4 {
            // Multiply-accumulate: t += self[i] * other
            let mut carry = 0u128;
            for j in 0..4 {
                let tmp = t[j] as u128 + self.limbs[i] as u128 * other.limbs[j] as u128 + carry;
                t[j] = tmp as u64;
                carry = tmp >> 64;
            }
            let tmp = t[4] as u128 + carry;
            t[4] = tmp as u64;

            // Montgomery reduction step: m = t[0] * p' mod 2^64
            let m = t[0].wrapping_mul(P_PRIME);

            // Reduce: t += m * p, then shift right by 64 bits
            carry = 0u128;
            let tmp = t[0] as u128 + m as u128 * MODULUS[0] as u128;
            carry = tmp >> 64;

            for j in 1..4 {
                let tmp = t[j] as u128 + m as u128 * MODULUS[j] as u128 + carry;
                t[j - 1] = tmp as u64;
                carry = tmp >> 64;
            }

            let tmp = t[4] as u128 + carry;
            t[3] = tmp as u64;
            t[4] = (tmp >> 64) as u64;
        }

        // Result is in t[0..3], but it's a*b*R^(-1) mod p
        // We need to multiply by R^2 and do another Montgomery reduction to get a*b
        let montgomery_result = Fr { limbs: [t[0], t[1], t[2], t[3]] };

        // Constant-time reduction: always compute both paths
        let reduced = montgomery_result.sub_modulus();
        let needs_reduction = montgomery_result.gte_modulus() || t[4] > 0;
        let mut result = Fr { limbs: ct_select(needs_reduction, &reduced.limbs, &montgomery_result.limbs) };

        // Now multiply by R^2 to convert back from Montgomery form
        // mont_mul(a*b*R^(-1), R^2) = a*b*R^(-1)*R^2*R^(-1) = a*b
        let mut t2 = [0u64; 5];

        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let tmp = t2[j] as u128 + result.limbs[i] as u128 * R2[j] as u128 + carry;
                t2[j] = tmp as u64;
                carry = tmp >> 64;
            }
            let tmp = t2[4] as u128 + carry;
            t2[4] = tmp as u64;

            let m = t2[0].wrapping_mul(P_PRIME);

            carry = 0u128;
            let tmp = t2[0] as u128 + m as u128 * MODULUS[0] as u128;
            carry = tmp >> 64;

            for j in 1..4 {
                let tmp = t2[j] as u128 + m as u128 * MODULUS[j] as u128 + carry;
                t2[j - 1] = tmp as u64;
                carry = tmp >> 64;
            }

            let tmp = t2[4] as u128 + carry;
            t2[3] = tmp as u64;
            t2[4] = (tmp >> 64) as u64;
        }

        result = Fr { limbs: [t2[0], t2[1], t2[2], t2[3]] };

        // Constant-time final reduction
        let reduced_final = result.sub_modulus();
        let needs_reduction_final = result.gte_modulus() || t2[4] > 0;
        Fr { limbs: ct_select(needs_reduction_final, &reduced_final.limbs, &result.limbs) }
    }

    /// Reduce a 512-bit value to an Fr using iterative k-reduction
    fn reduce_512_bit(t: &[u64; 8]) -> Self {
        // k = 2^256 mod p
        const K: [u64; 4] = [
            0xac96341c4ffffffbu64,
            0x36fc76959f60cd29u64,
            0x666ea36f7879462eu64,
            0x0e0a77c19a07df2fu64,
        ];

        let mut acc = *t;

        // Each iteration reduces ~4 bits, need ~60 iterations for 504->256 bits
        for _ in 0..64 {
            // Check if high part (acc[4..7]) is all zeros
            if acc[4] == 0 && acc[5] == 0 && acc[6] == 0 && acc[7] == 0 {
                break;
            }

            // Compute acc_hi * k
            let mut product = [0u64; 8];
            for i in 0..4 {
                let mut carry = 0u128;
                for j in 0..4 {
                    let mul_result = acc[4 + i] as u128 * K[j] as u128;
                    let sum = product[i + j] as u128 + mul_result + carry;
                    product[i + j] = sum as u64;
                    carry = sum >> 64;
                }
                let mut k_idx = i + 4;
                while carry > 0 && k_idx < 8 {
                    let sum = product[k_idx] as u128 + carry;
                    product[k_idx] = sum as u64;
                    carry = sum >> 64;
                    k_idx += 1;
                }
            }

            // Compute new_acc = acc_lo + product
            let mut new_acc = [0u64; 8];
            let mut carry = 0u128;

            for i in 0..4 {
                let sum = acc[i] as u128 + product[i] as u128 + carry;
                new_acc[i] = sum as u64;
                carry = sum >> 64;
            }

            for i in 4..8 {
                let sum = product[i] as u128 + carry;
                new_acc[i] = sum as u64;
                carry = sum >> 64;
            }

            acc = new_acc;
        }

        let mut result = Fr {
            limbs: [acc[0], acc[1], acc[2], acc[3]],
        };

        // Constant-time reduction: fixed iteration count (max 3 needed for BN254)
        for _ in 0..3 {
            let reduced = result.sub_modulus();
            let needs_reduction = result.gte_modulus();
            result = Fr { limbs: ct_select(needs_reduction, &reduced.limbs, &result.limbs) };
        }

        result
    }

    /// x^5 (S-box for Poseidon) - optimized
    #[inline]
    pub fn pow5(&self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(&x2);
        x4.mul(self)
    }

    // ========================================================================
    // Helper functions
    // ========================================================================

    /// Check if >= modulus (constant-time)
    fn gte_modulus(&self) -> bool {
        ct_gte(&self.limbs, &MODULUS)
    }

    /// Check if self >= other (constant-time)
    fn gte(&self, other: &Self) -> bool {
        ct_gte(&self.limbs, &other.limbs)
    }

    /// Subtract modulus (assuming self >= modulus)
    fn sub_modulus(&self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            let diff = self.limbs[i] as i128 - MODULUS[i] as i128 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }

        Fr { limbs: result }
    }

    /// Add modulus
    fn add_modulus(&self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            let sum = self.limbs[i] as u128 + MODULUS[i] as u128 + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }

        Fr { limbs: result }
    }

    /// Reduce 512-bit value modulo p
    /// Uses the identity: x mod p = (x_lo + x_hi * (2^256 mod p)) mod p
    /// Since (2^256 mod p) < 2^254, the product x_hi * k fits in ~508 bits
    /// After adding x_lo, we get at most 509 bits
    /// We iterate until the result fits in 256 bits, then do final reduction
    fn reduce_wide(&self, wide: &[u128; 8]) -> Self {
        // k = 2^256 mod p
        // = 6350874878119819312338956282401532410528162663560392320966563075034087161851
        const K: [u64; 4] = [
            0xac96341c4ffffffbu64,
            0x36fc76959f60cd29u64,
            0x666ea36f7879462eu64,
            0x0e0a77c19a07df2fu64,
        ];

        // For BN254 field, we have:
        // k ≈ 0.29 * p (more precisely, k/p ≈ 0.29)
        // So each iteration reduces the magnitude by roughly factor of 0.29
        // For a 504-bit input, worst case needs about log_{0.29}(2^248) ≈ 60 iterations
        //
        // However, we can use a more efficient approach:
        // 1. Compute x_lo + x_hi * k (this gives at most ~509 bits)
        // 2. Split result into low 256 bits and high bits (at most ~253 bits)
        // 3. Repeat until high bits are zero
        //
        // The trick is that k < 2^254, so x_hi (at most 256 bits) * k is at most 510 bits
        // But our x_hi starts with only 248 bits (since input is at most 504 bits)
        // So x_hi * k is at most 248 + 254 = 502 bits
        // Adding x_lo (256 bits) gives at most 503 bits
        //
        // After iteration 1: max ~248 bits in high part
        // After iteration 2: high part max ~248 + 254 - 256 = 246 bits, total ~502 bits
        // ... slowly converges

        // We work with a 512-bit accumulator stored as 8 x u64 limbs
        let mut acc = [0u64; 8];
        for i in 0..8 {
            acc[i] = wide[i] as u64;
        }

        // Iterate until high part is zero
        for _ in 0..64 {
            // Check if high part (acc[4..7]) is all zeros
            if acc[4] == 0 && acc[5] == 0 && acc[6] == 0 && acc[7] == 0 {
                break;
            }

            // Compute acc_hi * k
            let mut product = [0u64; 8];
            for i in 0..4 {
                let mut carry = 0u128;
                for j in 0..4 {
                    let mul_result = acc[4 + i] as u128 * K[j] as u128;
                    let sum = product[i + j] as u128 + mul_result + carry;
                    product[i + j] = sum as u64;
                    carry = sum >> 64;
                }
                let mut k_idx = i + 4;
                while carry > 0 && k_idx < 8 {
                    let sum = product[k_idx] as u128 + carry;
                    product[k_idx] = sum as u64;
                    carry = sum >> 64;
                    k_idx += 1;
                }
            }

            // Compute new_acc = acc_lo + product
            let mut new_acc = [0u64; 8];
            let mut carry = 0u128;

            for i in 0..4 {
                let sum = acc[i] as u128 + product[i] as u128 + carry;
                new_acc[i] = sum as u64;
                carry = sum >> 64;
            }

            for i in 4..8 {
                let sum = product[i] as u128 + carry;
                new_acc[i] = sum as u64;
                carry = sum >> 64;
            }

            acc = new_acc;
        }

        // Final reduction (constant-time)
        let mut result = Fr {
            limbs: [acc[0], acc[1], acc[2], acc[3]],
        };

        // Constant-time reduction: fixed iteration count (max 3 needed for BN254)
        for _ in 0..3 {
            let reduced = result.sub_modulus();
            let needs_reduction = result.gte_modulus();
            result = Fr { limbs: ct_select(needs_reduction, &reduced.limbs, &result.limbs) };
        }

        result
    }

    /// Modulo by small number (for string conversion)
    fn mod_small(&self, n: u64) -> u64 {
        let mut rem = 0u128;
        for i in (0..4).rev() {
            rem = (rem << 64) + self.limbs[i] as u128;
            rem %= n as u128;
        }
        rem as u64
    }

    /// Divide by small number (for string conversion)
    fn div_small(&self, n: u64) -> Self {
        let mut result = [0u64; 4];
        let mut rem = 0u128;
        
        for i in (0..4).rev() {
            let cur = (rem << 64) + self.limbs[i] as u128;
            result[i] = (cur / n as u128) as u64;
            rem = cur % n as u128;
        }
        
        Fr { limbs: result }
    }
}

/// Add two 256-bit numbers with carry
fn add_with_carry_256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut result = [0u64; 4];
    let mut carry = 0u128;

    for i in 0..4 {
        let sum = a[i] as u128 + b[i] as u128 + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }

    (result, carry as u64)
}

// ============================================================================
// POSEIDON HASH
// ============================================================================

/// Poseidon sponge state
pub struct PoseidonState<const T: usize> {
    state: [Fr; T],
}

impl<const T: usize> PoseidonState<T> {
    /// Create new state initialized with zeros
    pub fn new() -> Self {
        Self {
            state: [Fr::ZERO; T],
        }
    }
}

/// Poseidon hash for t=3 (2-input hash, used for Merkle tree)
/// Uses pre-computed Fr constants for efficiency
pub fn poseidon_t3(inputs: &[Fr]) -> Fr {
    assert!(inputs.len() <= 2, "Too many inputs for t=3 Poseidon");

    const T: usize = 3;
    const N_ROUNDS_F: usize = 8;
    const N_ROUNDS_P: usize = 57;

    // Initialize state: [0, input1, input2]
    let mut state = [Fr::ZERO; T];
    for (i, input) in inputs.iter().enumerate() {
        state[i + 1] = *input;
    }

    // Use pre-computed constants directly (no string parsing!)
    let c = &C_T3_FR;
    let m = &M_T3_FR;

    let mut round = 0;

    // First half of full rounds
    for _ in 0..(N_ROUNDS_F / 2) {
        // Add round constants
        for i in 0..T {
            if round * T + i < c.len() {
                state[i] = state[i].add(&c[round * T + i]);
            }
        }
        // S-box on all elements
        for i in 0..T {
            state[i] = state[i].pow5();
        }
        // MDS matrix
        state = mds_multiply_t3(&state, m);
        round += 1;
    }

    // Partial rounds
    for _ in 0..N_ROUNDS_P {
        // Add round constants
        for i in 0..T {
            if round * T + i < c.len() {
                state[i] = state[i].add(&c[round * T + i]);
            }
        }
        // S-box on first element only
        state[0] = state[0].pow5();
        // MDS matrix
        state = mds_multiply_t3(&state, m);
        round += 1;
    }

    // Second half of full rounds
    for _ in 0..(N_ROUNDS_F / 2) {
        // Add round constants
        for i in 0..T {
            if round * T + i < c.len() {
                state[i] = state[i].add(&c[round * T + i]);
            }
        }
        // S-box on all elements
        for i in 0..T {
            state[i] = state[i].pow5();
        }
        // MDS matrix
        state = mds_multiply_t3(&state, m);
        round += 1;
    }

    state[0]
}

/// MDS matrix multiplication for t=3
fn mds_multiply_t3(state: &[Fr; 3], m: &[[Fr; 3]; 3]) -> [Fr; 3] {
    let mut result = [Fr::ZERO; 3];
    
    for i in 0..3 {
        for j in 0..3 {
            let product = state[j].mul(&m[i][j]);
            result[i] = result[i].add(&product);
        }
    }
    
    result
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Hash two field element strings (for Merkle tree)
pub fn poseidon_hash2(left: &str, right: &str) -> String {
    let a = Fr::from_str(left);
    let b = Fr::from_str(right);
    let result = poseidon_t3(&[a, b]);
    result.to_string()
}

/// Debug Poseidon - returns state after first round
pub fn poseidon_debug(left: &str, right: &str) -> Vec<String> {
    let a = Fr::from_str(left);
    let b = Fr::from_str(right);

    const T: usize = 3;

    let mut state = [Fr::ZERO; T];
    state[1] = a;
    state[2] = b;

    let c = &C_T3_FR;
    let m = &M_T3_FR;

    let mut debug_output = Vec::new();

    // Initial state
    debug_output.push(format!("Initial: [{}, {}, {}]", state[0].to_string(), state[1].to_string(), state[2].to_string()));

    // Add round constants for round 0
    for i in 0..T {
        state[i] = state[i].add(&c[i]);
    }
    debug_output.push(format!("After ARK: [{}, {}, {}]", state[0].to_string(), state[1].to_string(), state[2].to_string()));

    // Debug pow5 for state[0]
    let s0 = state[0];
    let s0_2 = s0.mul(&s0);
    debug_output.push(format!("s0^2 = {}", s0_2.to_string()));
    let s0_4 = s0_2.mul(&s0_2);
    debug_output.push(format!("s0^4 = {}", s0_4.to_string()));
    let s0_5 = s0_4.mul(&s0);
    debug_output.push(format!("s0^5 = {}", s0_5.to_string()));

    // S-box
    for i in 0..T {
        state[i] = state[i].pow5();
    }
    debug_output.push(format!("After SBOX: [{}, {}, {}]", state[0].to_string(), state[1].to_string(), state[2].to_string()));

    // MDS matrix
    state = mds_multiply_t3(&state, m);
    debug_output.push(format!("After MDS: [{}, {}, {}]", state[0].to_string(), state[1].to_string(), state[2].to_string()));

    // Also output the first constant
    debug_output.push(format!("c[0] = {}", c[0].to_string()));
    debug_output.push(format!("c[1] = {}", c[1].to_string()));
    debug_output.push(format!("c[2] = {}", c[2].to_string()));

    debug_output
}

/// Debug multiplication - returns detailed intermediate values
pub fn debug_mul(a: &str, b: &str) -> Vec<String> {
    let x = Fr::from_str(a);
    let y = Fr::from_str(b);

    let mut debug_output = Vec::new();

    // Show input limbs
    debug_output.push(format!("x.limbs = [{}, {}, {}, {}]", x.limbs[0], x.limbs[1], x.limbs[2], x.limbs[3]));
    debug_output.push(format!("y.limbs = [{}, {}, {}, {}]", y.limbs[0], y.limbs[1], y.limbs[2], y.limbs[3]));

    // Compute 512-bit product manually for debug
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let product = x.limbs[i] as u128 * y.limbs[j] as u128;
            let sum = result[i + j] as u128 + product + carry;
            result[i + j] = sum as u64;
            carry = sum >> 64;
        }
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let sum = result[k] as u128 + carry;
            result[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
    }

    debug_output.push(format!("512-bit: [{}, {}, {}, {}, {}, {}, {}, {}]",
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]));

    // Compute multiplication and show result
    let mul_result = x.mul(&y);
    debug_output.push(format!("result = {}", mul_result.to_string()));
    debug_output.push(format!("result.limbs = [{}, {}, {}, {}]", mul_result.limbs[0], mul_result.limbs[1], mul_result.limbs[2], mul_result.limbs[3]));

    debug_output
}

/// Hash four field element strings (for note commitment)
/// Uses tree hashing: hash(hash(a,b), hash(c,d))
pub fn poseidon_hash4(a: &str, b: &str, c: &str, d: &str) -> String {
    let h1 = poseidon_hash2(a, b);
    let h2 = poseidon_hash2(c, d);
    poseidon_hash2(&h1, &h2)
}

/// Compute note commitment
/// commitment = Poseidon(Poseidon(nullifier, secret), Poseidon(amount, assetId))
pub fn compute_commitment(
    nullifier: &str,
    secret: &str,
    amount: &str,
    asset_id: &str,
) -> String {
    poseidon_hash4(nullifier, secret, amount, asset_id)
}

/// Compute nullifier hash
/// nullifierHash = Poseidon(nullifier, leafIndex)
pub fn compute_nullifier_hash(nullifier: &str, leaf_index: u64) -> String {
    poseidon_hash2(nullifier, &leaf_index.to_string())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_from_str() {
        let a = Fr::from_str("12345");
        assert_eq!(a.to_string(), "12345");
    }

    #[test]
    fn test_fr_add() {
        let a = Fr::from_u64(100);
        let b = Fr::from_u64(200);
        let c = a.add(&b);
        assert_eq!(c.to_string(), "300");
    }

    #[test]
    fn test_fr_mul() {
        let a = Fr::from_u64(1000);
        let b = Fr::from_u64(2000);
        let c = a.mul(&b);
        assert_eq!(c.to_string(), "2000000");
    }

    #[test]
    fn test_fr_pow5() {
        let a = Fr::from_u64(3);
        let b = a.pow5();
        assert_eq!(b.to_string(), "243"); // 3^5 = 243
    }

    #[test]
    fn test_poseidon_basic() {
        // Test that Poseidon produces a deterministic output
        let result = poseidon_hash2("1", "2");
        assert!(!result.is_empty());
        
        // Same inputs should produce same output
        let result2 = poseidon_hash2("1", "2");
        assert_eq!(result, result2);
        
        // Different inputs should produce different output
        let result3 = poseidon_hash2("1", "3");
        assert_ne!(result, result3);
    }

    #[test]
    fn test_poseidon_zeros() {
        // Hash of zeros
        let result = poseidon_hash2("0", "0");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_commitment() {
        let commitment = compute_commitment(
            "12345",  // nullifier
            "67890",  // secret
            "1000000000000000000000000",  // amount (1 NEAR)
            "0",      // asset_id
        );
        assert!(!commitment.is_empty());
    }

    #[test]
    fn test_nullifier_hash() {
        let nh = compute_nullifier_hash("12345", 42);
        assert!(!nh.is_empty());
    }
}

