# Troubleshooting Guide

This guide documents common issues encountered when working with Groth16 proofs on NEAR Protocol and their solutions.

## Endianness Issues

### The Problem

NEAR's `alt_bn128` precompiles expect **big-endian** byte encoding for points, while snarkjs and many other tools use **little-endian** for certain operations.

### Key Encoding Rules

| Component | NEAR Expectation | Format |
|-----------|------------------|--------|
| G1 Point X | Big-endian | 32 bytes |
| G1 Point Y | Big-endian | 32 bytes |
| G2 Point X | (x1, x0) big-endian | 64 bytes |
| G2 Point Y | (y1, y0) big-endian | 64 bytes |
| Scalar (multiexp) | **Little-endian** | 32 bytes |

### G2 Point Ordering

**Critical:** G2 points have a specific coordinate ordering for NEAR:

```rust
// G2 serialization for NEAR precompiles
// Note: x1/y1 come BEFORE x0/y0 (high part first)
pub fn to_bytes(&self) -> [u8; 128] {
    let mut result = [0u8; 128];
    result[0..32].copy_from_slice(&self.x[1].to_be_bytes());   // x1 (high)
    result[32..64].copy_from_slice(&self.x[0].to_be_bytes());  // x0 (low)
    result[64..96].copy_from_slice(&self.y[1].to_be_bytes());  // y1 (high)
    result[96..128].copy_from_slice(&self.y[0].to_be_bytes()); // y0 (low)
    result
}
```

### Multiexp Scalar Encoding

For `alt_bn128_g1_multiexp`, scalars must be **little-endian**:

```rust
// Correct: little-endian for multiexp
let mut scalar_le = [0u8; 32];
scalar.to_little_endian(&mut scalar_le);
multiexp_input.extend_from_slice(&scalar_le);
multiexp_input.extend_from_slice(&point.to_bytes()); // Point is big-endian
```

## Proof Verification Failures

### "Proof verification failed" with correct inputs

**Cause 1: G2 coordinate swap**

Some implementations swap pi_b coordinates. NEAR's precompile does NOT require swapping.

```rust
// WRONG: Don't swap coordinates
fn to_bytes_swapped(&self) -> [u8; 128] {
    // ... swapping x[0]/x[1] and y[0]/y[1] ...
}

// CORRECT: Use natural order (high, low)
fn to_bytes(&self) -> [u8; 128] {
    // x1, x0, y1, y0 (high parts first)
}
```

**Cause 2: Negating the wrong point**

The pairing equation requires negating A (pi_a), NOT any other point:

```rust
// Correct pairing check:
// e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1

fn pairing_check(&self, proof: &Proof, vk_x: &G1Point) -> bool {
    let neg_a = negate_g1(&proof.a);  // Negate A only!

    // Pair 1: (-A, B)
    pairing_input.extend_from_slice(&neg_a.to_bytes());
    pairing_input.extend_from_slice(&proof.b.to_bytes());

    // ... rest of pairs unchanged ...
}
```

**Cause 3: Wrong public input ordering**

Public inputs must match the order in the circuit's `main` component:

```circom
// Circuit defines order
component main {public [nullifier, commitment, root]} = MyCircuit();
```

```javascript
// Must match this order in public.json
["nullifier_value", "commitment_value", "root_value"]
```

### "Wrong number of public inputs"

The verification key's IC array determines expected inputs:

```
Number of public inputs = IC.length - 1
```

Check your verification key:
```bash
cat verification_key.json | jq '.IC | length'
# Subtract 1 for actual public input count
```

## Circuit Compilation Issues

### "Non-quadratic constraint"

Circom only allows quadratic constraints (degree 2). This fails:

```circom
// WRONG: cubic constraint
c <== a * b * d;

// CORRECT: break into quadratics
signal ab;
ab <== a * b;
c <== ab * d;
```

### "Unknown component"

Include paths must be correct:

```bash
# Compile with include path
circom circuit.circom -l node_modules -o build/
```

### "Constraint not satisfied"

The witness doesn't satisfy constraints. Debug:

```bash
# Generate witness with debug output
node circuit_js/generate_witness.js circuit.wasm input.json witness.wtns

# If it fails, check your input values
# Common issues:
# - Values exceeding field modulus
# - Division by zero
# - Negative numbers (use field arithmetic instead)
```

## Witness Generation Issues

### "Scalar is too big"

Field elements must be less than the scalar field modulus:

```
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

Solution: Ensure all inputs are within this range.

### "Assert failed"

The circuit has an `assert` or `===` constraint that fails:

```circom
// This will fail if condition is false
condition === 1;
```

Debug by checking input values and intermediate computations.

## On-Chain Verification Issues

### Gas Limit Exceeded

**Solutions:**

1. Reduce public inputs:
```circom
// Instead of multiple public inputs
signal input a;  // public
signal input b;  // public
signal input c;  // public

// Use a single commitment
signal input commitment;  // hash(a, b, c)
```

2. Use view methods for testing:
```rust
// Free (no gas)
pub fn check_proof(&self, proof: ProofJson, inputs: Vec<String>) -> bool {
    self.verifier.verify_json(&proof, &inputs)
}
```

3. Approximate gas costs:
```
Base verification: ~50 TGas
Per public input: ~5-10 TGas additional
Complex circuits: ~100-150 TGas
```

### Serialization Errors

**"Invalid proof format"**

Ensure proof JSON matches expected structure:

```json
{
    "pi_a": ["x", "y", "1"],
    "pi_b": [["x0", "x1"], ["y0", "y1"], ["1", "0"]],
    "pi_c": ["x", "y", "1"]
}
```

**"Invalid verification key"**

Check VK structure:

```json
{
    "protocol": "groth16",
    "curve": "bn128",
    "vk_alpha_1": ["x", "y", "1"],
    "vk_beta_2": [["x0", "x1"], ["y0", "y1"], ["1", "0"]],
    "vk_gamma_2": [...],
    "vk_delta_2": [...],
    "IC": [["x", "y", "1"], ...]
}
```

## BN254/alt_bn128 Specifics

### Field Modulus

Base field (Fq):
```
q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
```

Scalar field (Fr):
```
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

### Point Negation

To negate a G1 point for the pairing equation:

```rust
pub fn negate_g1(p: &G1Point) -> G1Point {
    if p.is_zero() {
        return p.clone();
    }

    let field_modulus = U256::from_dec_str(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583"
    ).unwrap();

    G1Point {
        x: p.x,
        y: field_modulus - p.y,  // -y = q - y
    }
}
```

### Point at Infinity

```rust
// Check for point at infinity
if point.x.is_zero() && point.y.is_zero() {
    // Handle identity element
}
```

## snarkjs Compatibility

### Decimal String Format

snarkjs outputs numbers as decimal strings, not hex:

```javascript
// snarkjs output
{
    "pi_a": ["12345678901234567890...", "98765432109876543210...", "1"]
}

// NOT hex
{
    "pi_a": ["0x1234...", "0xabcd...", "0x1"]
}
```

Parse with:
```rust
let value = U256::from_dec_str(&string_value)?;
```

### Proof Format Differences

Some tools output proofs differently. Ensure you're using snarkjs format:

```bash
# Generate with snarkjs
snarkjs groth16 prove circuit.zkey witness.wtns proof.json public.json

# Verify format
cat proof.json | jq 'keys'
# Should show: ["curve", "pi_a", "pi_b", "pi_c", "protocol"]
```

## Debugging Workflow

### 1. Verify Locally First

```bash
# Always test proof locally before on-chain
snarkjs groth16 verify verification_key.json public.json proof.json
```

### 2. Log Intermediate Values

```rust
// Add logging to debug
pub fn verify(&self, proof: ProofJson, inputs: Vec<String>) -> bool {
    env::log_str(&format!("Input count: {}", inputs.len()));
    env::log_str(&format!("Expected: {}", self.verifier.vk.num_inputs()));

    let result = self.verifier.verify_json(&proof, &inputs);
    env::log_str(&format!("Result: {}", result));

    result
}
```

### 3. Check Raw Bytes

```rust
// Debug point encoding
fn debug_g1(name: &str, p: &G1Point) {
    let bytes = p.to_bytes();
    env::log_str(&format!("{}: {:?}", name, hex::encode(&bytes[..16])));
}
```

### 4. Compare with Known-Good Values

Generate a test proof and verify the exact byte representation matches what you expect at each step.

## Common Error Messages

| Error | Likely Cause | Solution |
|-------|--------------|----------|
| "Proof verification failed" | Encoding/format issue | Check endianness and coordinate order |
| "Invalid verification key" | Wrong JSON format | Verify VK structure |
| "Wrong number of public inputs" | Input count mismatch | Check IC.length - 1 |
| "Nullifier already used" | Double-spend attempt | Expected behavior |
| "Gas limit exceeded" | Too many inputs | Reduce inputs or increase gas |
| "Constraint not satisfied" | Invalid witness | Check input values |

## Getting Help

1. Check this guide first
2. Verify locally with snarkjs
3. Add logging to isolate the issue
4. Check the example contracts for reference
5. Open an issue with:
   - Circuit code (or description)
   - Verification key
   - Sample proof and inputs
   - Error message
