//! Types for Groth16 verification on NEAR Protocol
//!
//! These types are designed to be compatible with snarkjs/circom output format.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
pub use uint::construct_uint;

// Define U256 type for field elements
construct_uint! {
    /// 256-bit unsigned integer for field elements
    #[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    pub struct U256(4);
}

impl U256 {
    /// Convert to big-endian 32-byte array
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }

    /// Create from big-endian bytes
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        U256::from_big_endian(bytes)
    }
}

/// G1 point on BN254 curve (affine coordinates)
/// Format: 64 bytes = 32 bytes x + 32 bytes y (big-endian)
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct G1Point {
    pub x: U256,
    pub y: U256,
}

impl G1Point {
    /// Point at infinity (identity element)
    pub fn zero() -> Self {
        Self {
            x: U256::zero(),
            y: U256::zero(),
        }
    }

    /// Check if point is at infinity
    pub fn is_zero(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }

    /// Serialize to 64 bytes (big-endian format for NEAR precompiles)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.x.to_be_bytes());
        result[32..].copy_from_slice(&self.y.to_be_bytes());
        result
    }

    /// Deserialize from 64 bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            x: U256::from_be_bytes(&bytes[..32]),
            y: U256::from_be_bytes(&bytes[32..]),
        }
    }

    /// Create from snarkjs JSON array format ["x", "y", "1"]
    /// The third element is always "1" for affine coordinates
    pub fn from_json_array(arr: &[String]) -> Result<Self, &'static str> {
        if arr.len() < 2 {
            return Err("G1 point requires at least 2 coordinates");
        }
        Ok(Self {
            x: U256::from_dec_str(&arr[0]).map_err(|_| "Invalid decimal string for x")?,
            y: U256::from_dec_str(&arr[1]).map_err(|_| "Invalid decimal string for y")?,
        })
    }
}

/// G2 point on BN254 curve (affine coordinates over Fq2)
/// Each coordinate is an element of Fq2 = Fq[u]/(u² + 1)
/// Format: 128 bytes = (32 bytes x0 + 32 bytes x1) + (32 bytes y0 + 32 bytes y1)
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct G2Point {
    /// x coordinate: x[0] + x[1] * u
    pub x: [U256; 2],
    /// y coordinate: y[0] + y[1] * u
    pub y: [U256; 2],
}

impl G2Point {
    /// Point at infinity
    pub fn zero() -> Self {
        Self {
            x: [U256::zero(), U256::zero()],
            y: [U256::zero(), U256::zero()],
        }
    }

    /// Check if point is at infinity
    pub fn is_zero(&self) -> bool {
        self.x[0].is_zero() && self.x[1].is_zero() && 
        self.y[0].is_zero() && self.y[1].is_zero()
    }

    /// Serialize to 128 bytes (big-endian format for NEAR precompiles)
    /// Note: NEAR uses (x1, x0, y1, y0) ordering for G2 points
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut result = [0u8; 128];
        // x coordinate (Fq2): high part first, then low part
        result[0..32].copy_from_slice(&self.x[1].to_be_bytes());   // x1
        result[32..64].copy_from_slice(&self.x[0].to_be_bytes());  // x0
        // y coordinate (Fq2): high part first, then low part  
        result[64..96].copy_from_slice(&self.y[1].to_be_bytes());  // y1
        result[96..128].copy_from_slice(&self.y[0].to_be_bytes()); // y0
        result
    }

    /// Deserialize from 128 bytes
    pub fn from_bytes(bytes: &[u8; 128]) -> Self {
        Self {
            x: [
                U256::from_be_bytes(&bytes[32..64]),  // x0
                U256::from_be_bytes(&bytes[0..32]),   // x1
            ],
            y: [
                U256::from_be_bytes(&bytes[96..128]), // y0
                U256::from_be_bytes(&bytes[64..96]),  // y1
            ],
        }
    }

    /// Create from snarkjs JSON array format [["x0", "x1"], ["y0", "y1"], ["1", "0"]]
    pub fn from_json_array(arr: &[Vec<String>]) -> Result<Self, &'static str> {
        if arr.len() < 2 {
            return Err("G2 point requires at least 2 coordinate pairs");
        }
        if arr[0].len() < 2 || arr[1].len() < 2 {
            return Err("Each G2 coordinate requires 2 elements");
        }
        Ok(Self {
            x: [
                U256::from_dec_str(&arr[0][0]).map_err(|_| "Invalid decimal string for x0")?,
                U256::from_dec_str(&arr[0][1]).map_err(|_| "Invalid decimal string for x1")?,
            ],
            y: [
                U256::from_dec_str(&arr[1][0]).map_err(|_| "Invalid decimal string for y0")?,
                U256::from_dec_str(&arr[1][1]).map_err(|_| "Invalid decimal string for y1")?,
            ],
        })
    }
}

/// Groth16 proof structure
/// Compatible with snarkjs output format
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Proof {
    /// A point (G1)
    pub a: G1Point,
    /// B point (G2)
    pub b: G2Point,
    /// C point (G1)
    pub c: G1Point,
}

impl Proof {
    /// Create proof from snarkjs JSON format
    pub fn from_json(
        pi_a: &[String],
        pi_b: &[Vec<String>],
        pi_c: &[String],
    ) -> Result<Self, &'static str> {
        Ok(Self {
            a: G1Point::from_json_array(pi_a)?,
            b: G2Point::from_json_array(pi_b)?,
            c: G1Point::from_json_array(pi_c)?,
        })
    }

    /// Serialize proof for pairing check
    /// Returns (A_neg, B, C) where A is negated for the pairing equation
    pub fn to_pairing_bytes(&self, negate_a: bool) -> ([u8; 64], [u8; 128], [u8; 64]) {
        let a_bytes = if negate_a {
            negate_g1(&self.a).to_bytes()
        } else {
            self.a.to_bytes()
        };
        (a_bytes, self.b.to_bytes(), self.c.to_bytes())
    }
}

/// Negate a G1 point (for pairing equation transformation)
/// -P = (x, -y) where -y = p - y (mod p)
pub fn negate_g1(p: &G1Point) -> G1Point {
    if p.is_zero() {
        return p.clone();
    }
    
    // BN254 base field modulus
    let field_modulus = U256::from_dec_str(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583"
    ).unwrap();
    
    // -y = p - y (mod p)
    let neg_y = field_modulus - p.y;
    
    G1Point {
        x: p.x,
        y: neg_y,
    }
}

/// Verification key for Groth16
/// Compatible with snarkjs verification_key.json
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationKey {
    /// α point in G1 (alpha)
    pub alpha: G1Point,
    /// β point in G2 (beta)
    pub beta: G2Point,
    /// γ point in G2 (gamma)
    pub gamma: G2Point,
    /// δ point in G2 (delta)
    pub delta: G2Point,
    /// IC (input constraints) - array of G1 points
    /// IC[0] is the base, IC[1..n+1] are multiplied by public inputs
    pub ic: Vec<G1Point>,
}

impl VerificationKey {
    /// Create from snarkjs verification_key.json format
    pub fn from_json(
        vk_alpha_1: &[String],
        vk_beta_2: &[Vec<String>],
        vk_gamma_2: &[Vec<String>],
        vk_delta_2: &[Vec<String>],
        ic: &[Vec<String>],
    ) -> Result<Self, &'static str> {
        let ic_points: Result<Vec<G1Point>, _> = ic
            .iter()
            .map(|p| G1Point::from_json_array(p))
            .collect();
        
        Ok(Self {
            alpha: G1Point::from_json_array(vk_alpha_1)?,
            beta: G2Point::from_json_array(vk_beta_2)?,
            gamma: G2Point::from_json_array(vk_gamma_2)?,
            delta: G2Point::from_json_array(vk_delta_2)?,
            ic: ic_points?,
        })
    }

    /// Number of public inputs this verification key expects
    pub fn num_inputs(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }
}

/// JSON format for snarkjs proof files
#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct ProofJson {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: Option<String>,
    pub curve: Option<String>,
}

impl ProofJson {
    /// Convert to Proof struct
    pub fn to_proof(&self) -> Result<Proof, &'static str> {
        Proof::from_json(&self.pi_a, &self.pi_b, &self.pi_c)
    }
}

/// JSON format for snarkjs verification_key.json
#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationKeyJson {
    pub protocol: Option<String>,
    pub curve: Option<String>,
    #[serde(rename = "nPublic")]
    pub n_public: Option<u32>,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

impl VerificationKeyJson {
    /// Convert to VerificationKey struct
    pub fn to_vk(&self) -> Result<VerificationKey, &'static str> {
        VerificationKey::from_json(
            &self.vk_alpha_1,
            &self.vk_beta_2,
            &self.vk_gamma_2,
            &self.vk_delta_2,
            &self.ic,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_serialization_roundtrip() {
        let p = G1Point {
            x: U256::from(123456u64),
            y: U256::from(789012u64),
        };
        let bytes = p.to_bytes();
        let p2 = G1Point::from_bytes(&bytes);
        assert_eq!(p.x, p2.x);
        assert_eq!(p.y, p2.y);
    }

    #[test]
    fn test_g2_serialization_roundtrip() {
        let p = G2Point {
            x: [U256::from(1u64), U256::from(2u64)],
            y: [U256::from(3u64), U256::from(4u64)],
        };
        let bytes = p.to_bytes();
        let p2 = G2Point::from_bytes(&bytes);
        assert_eq!(p.x[0], p2.x[0]);
        assert_eq!(p.x[1], p2.x[1]);
        assert_eq!(p.y[0], p2.y[0]);
        assert_eq!(p.y[1], p2.y[1]);
    }
}
