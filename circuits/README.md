# Example Circuits

This directory contains example circom circuits for common ZK use cases.

## Directory Structure

```
circuits/
├── simple/                 # Basic educational circuits
│   ├── multiplier.circom   # Basic multiplication proof
│   ├── hash_preimage.circom # Hash commitment verification
│   ├── range_proof.circom  # Prove value in range
│   └── merkle_proof.circom # Set membership proof
│
└── educational/            # More complex production patterns
    ├── age_verification.circom   # Prove age >= threshold
    ├── private_voting.circom     # Anonymous voting
    ├── ownership_proof.circom    # Asset ownership
    └── arithmetic_proof.circom   # Mathematical proofs
```

## Simple Circuits

### multiplier.circom

The "hello world" of ZK - proves you know `a` and `b` such that `a * b = c`.

**Private inputs:** `a`, `b`
**Public outputs:** `c`

```bash
# Test
echo '{"a": 3, "b": 7}' | circom multiplier.circom --wasm --r1cs -o build/
```

### hash_preimage.circom

Proves knowledge of a value that hashes to a public commitment.

**Private inputs:** `preimage`
**Public outputs:** `commitment`

**Requires:** `circomlib` for Poseidon hash

### range_proof.circom

Proves a secret value falls within a public range [min, max].

**Private inputs:** `value`
**Public inputs:** `minValue`, `maxValue`
**Public outputs:** `valid` (always 1 if proof succeeds)

### merkle_proof.circom

Proves a leaf is part of a Merkle tree with a known root.

**Private inputs:** `leaf`, `pathElements[]`, `pathIndices[]`
**Public inputs:** `root`
**Public outputs:** `verified`

**Tree depth:** 20 (configurable, supports ~1M leaves)

## Educational Circuits

### age_verification.circom

Proves user is above a minimum age without revealing exact birth date.

**Private inputs:** `birthYear`, `birthYearSalt`
**Public inputs:** `currentYear`, `minimumAge`, `birthYearCommitment`
**Public outputs:** `isEligible`

### private_voting.circom

Anonymous voting with Merkle-based eligibility and nullifier protection.

**Private inputs:** `voterId`, `voterSecret`, `voterPathElements[]`, `voterPathIndices[]`, `vote`
**Public inputs:** `voterTreeRoot`, `pollId`
**Public outputs:** `nullifier`, `voteCommitment`

### ownership_proof.circom

Proves ownership of an asset in a Merkle tree without revealing identity.

**Private inputs:** `assetId`, `ownerSecret`, `ownerPublicKey[]`, `pathElements[]`, `pathIndices[]`
**Public inputs:** `assetTreeRoot`, `challenge`
**Public outputs:** `ownershipProof`

### arithmetic_proof.circom

Mathematical proofs (Pythagorean theorem, factorization).

**Template: PythagoreanProof**
- **Private inputs:** `a`, `b`
- **Public outputs:** `c` (where a² + b² = c)

## Compilation

All circuits require circom 2.1.0+ and circomlib:

```bash
npm install circomlib

# Compile any circuit
circom circuit.circom --r1cs --wasm --sym -l node_modules -o build/
```

## Testing

```bash
# Generate test input
echo '{"a": 3, "b": 4}' > input.json

# Generate witness
node build/circuit_js/generate_witness.js build/circuit_js/circuit.wasm input.json witness.wtns

# Create proof (requires setup first)
snarkjs groth16 prove circuit.zkey witness.wtns proof.json public.json

# Verify locally
snarkjs groth16 verify verification_key.json public.json proof.json
```

## Customization

These circuits are templates. For production use:

1. Adjust tree depths based on your use case
2. Add additional constraints as needed
3. Optimize for your specific requirements
4. Conduct thorough testing and auditing
