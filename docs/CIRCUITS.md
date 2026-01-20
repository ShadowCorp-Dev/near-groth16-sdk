# Circuit Development Guide

This guide covers developing circom circuits for use with the NEAR Groth16 verifier.

## Prerequisites

```bash
npm install -g circom snarkjs
```

## Circuit Basics

### Structure of a Circom Circuit

```circom
pragma circom 2.1.0;

// Import standard library components
include "circomlib/circuits/poseidon.circom";

// Define your template
template MyCircuit() {
    // Signals are variables in the circuit
    signal input privateInput;    // Private by default
    signal input publicInput;     // Will be made public
    signal output result;         // Outputs are public

    // Constraints define the computation
    result <== privateInput * publicInput;
}

// Main component - specify which signals are public
component main {public [publicInput, result]} = MyCircuit();
```

### Signal Types

- **Private inputs**: Known only to the prover
- **Public inputs**: Known to everyone, verified on-chain
- **Outputs**: Always public
- **Intermediate signals**: Internal computation values

### Constraint Types

```circom
// Quadratic constraint (most common)
c <== a * b;

// Linear constraint
c <== a + b;

// Assignment without constraint (use carefully!)
c <-- a * b;  // Just assigns, doesn't constrain

// Equality constraint
a === b;
```

## Circuit Patterns

### Hash Commitment

```circom
include "circomlib/circuits/poseidon.circom";

template Commitment() {
    signal input secret;
    signal input salt;
    signal output commitment;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== secret;
    hasher.inputs[1] <== salt;
    commitment <== hasher.out;
}
```

### Merkle Proof

```circom
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";

template MerkleLevel() {
    signal input current;
    signal input sibling;
    signal input isRight;  // 0 = current is left, 1 = current is right
    signal output parent;

    component hasher = Poseidon(2);
    component mux = MultiMux1(2);

    // Select order based on position
    mux.c[0][0] <== current;
    mux.c[0][1] <== sibling;
    mux.c[1][0] <== sibling;
    mux.c[1][1] <== current;
    mux.s <== isRight;

    hasher.inputs[0] <== mux.out[0];
    hasher.inputs[1] <== mux.out[1];
    parent <== hasher.out;
}
```

### Range Check

```circom
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template RangeCheck(n) {
    signal input value;
    signal input max;

    // Decompose to bits ensures value < 2^n
    component bits = Num2Bits(n);
    bits.in <== value;

    // Check value <= max
    component lte = LessEqThan(n);
    lte.in[0] <== value;
    lte.in[1] <== max;
    lte.out === 1;
}
```

## Compilation Workflow

### 1. Compile the Circuit

```bash
circom circuit.circom --r1cs --wasm --sym -o build/

# Outputs:
# - build/circuit.r1cs      (constraint system)
# - build/circuit_js/       (witness generator)
# - build/circuit.sym       (symbol file for debugging)
```

### 2. Powers of Tau Setup

For testing, create a new ceremony:

```bash
# Create new powers of tau (size 12 = 2^12 constraints max)
snarkjs powersoftau new bn128 12 pot12_0000.ptau

# Contribute randomness
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau \
  --name="First contribution"

# Finalize
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau
```

For production, use existing ceremonies:
- Hermez: https://hermez.io/
- Zcash: https://github.com/zcash/zcash/tree/master/zcutil/sapling-keygen

### 3. Circuit-Specific Setup

```bash
# Generate proving key
snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit_0000.zkey

# Contribute to ceremony
snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey \
  --name="Circuit contribution"

# Export verification key
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
```

### 4. Generate Proofs

```bash
# Create input file
echo '{"a": 3, "b": 7}' > input.json

# Generate witness
node circuit_js/generate_witness.js circuit_js/circuit.wasm input.json witness.wtns

# Generate proof
snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json

# Verify locally
snarkjs groth16 verify verification_key.json public.json proof.json
```

## Circuit Libraries

### circomlib

Standard library with essential components:

```circom
// Hashing
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mimcsponge.circom";
include "circomlib/circuits/sha256.circom";  // Very expensive!

// Comparisons
include "circomlib/circuits/comparators.circom";
// LessThan, GreaterThan, LessEqThan, GreaterEqThan, IsEqual, IsZero

// Bit operations
include "circomlib/circuits/bitify.circom";
// Num2Bits, Bits2Num

// Multiplexing
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/mux2.circom";

// Elliptic curves
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulfix.circom";

// Signatures
include "circomlib/circuits/eddsamimc.circom";
include "circomlib/circuits/eddsamimcsponge.circom";
```

Install: `npm install circomlib`

## Optimization Tips

### 1. Minimize Constraints

Each constraint costs gas. Optimize by:

```circom
// BAD: Multiple constraints
signal x;
x <== a + b;
signal y;
y <== x * c;

// BETTER: Combine into one
signal y;
y <== (a + b) * c;
```

### 2. Use Efficient Hash Functions

| Hash Function | ~Constraints | Notes |
|---------------|--------------|-------|
| Poseidon      | ~250         | ZK-friendly, recommended |
| MiMC          | ~300         | Alternative ZK-friendly |
| SHA256        | ~25,000      | Avoid if possible |

### 3. Batch Operations

```circom
// Instead of multiple single hashes
for (var i = 0; i < n; i++) {
    hashers[i] = Poseidon(1);
    hashers[i].inputs[0] <== values[i];
}

// Consider multi-input hash when possible
component batchHash = Poseidon(n);
for (var i = 0; i < n; i++) {
    batchHash.inputs[i] <== values[i];
}
```

### 4. Minimize Public Inputs

Each public input adds verification cost. Bundle related data into commitments.

## Testing

### Unit Testing with Circom-tester

```javascript
const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Multiplier", () => {
    let circuit;

    before(async () => {
        circuit = await wasm_tester(path.join(__dirname, "multiplier.circom"));
    });

    it("should multiply correctly", async () => {
        const witness = await circuit.calculateWitness({
            a: 3,
            b: 7
        });

        await circuit.assertOut(witness, {
            c: 21
        });
    });

    it("should fail for wrong output", async () => {
        // This would fail constraint checking
        try {
            const witness = await circuit.calculateWitness({
                a: 3,
                b: 7,
                c: 20  // Wrong!
            });
            assert.fail("Should have thrown");
        } catch (e) {
            // Expected
        }
    });
});
```

### Integration Testing

```bash
#!/bin/bash
# Full workflow test

# Compile
circom circuit.circom --r1cs --wasm -o build/

# Setup
snarkjs groth16 setup build/circuit.r1cs pot12_final.ptau build/circuit.zkey

# Export VK
snarkjs zkey export verificationkey build/circuit.zkey build/vk.json

# Test inputs
echo '{"a": 3, "b": 7}' > test_input.json

# Generate and verify proof
node build/circuit_js/generate_witness.js \
    build/circuit_js/circuit.wasm \
    test_input.json \
    build/witness.wtns

snarkjs groth16 prove \
    build/circuit.zkey \
    build/witness.wtns \
    build/proof.json \
    build/public.json

snarkjs groth16 verify \
    build/vk.json \
    build/public.json \
    build/proof.json

echo "Test passed!"
```

## Common Pitfalls

### 1. Non-Deterministic Witness

```circom
// BAD: Division is non-deterministic
signal x;
x <-- a / b;  // Could fail during witness generation

// GOOD: Prove with constraints
signal x;
signal inv;
inv <-- 1 / b;  // Hint
inv * b === 1;  // Constraint: proves inv is inverse
x <== a * inv;
```

### 2. Over-Constraining

```circom
// BAD: Unnecessary constraints
signal bit;
bit * bit === bit;  // Constraint 1
bit * (1 - bit) === 0;  // Constraint 2 (redundant!)

// GOOD: One constraint is enough
signal bit;
bit * (1 - bit) === 0;  // Proves bit is 0 or 1
```

### 3. Underconstraining

```circom
// BAD: Value is assigned but not constrained
signal secret;
signal hash;
hash <-- poseidon(secret);  // Just assignment!

// GOOD: Use component with constraints
component hasher = Poseidon(1);
hasher.inputs[0] <== secret;
signal hash;
hash <== hasher.out;
```

## Debug Tools

### 1. Symbol File

Use `--sym` flag to generate debugging info:

```bash
circom circuit.circom --r1cs --wasm --sym
```

### 2. Witness Inspector

```javascript
const { wtns } = require("snarkjs");

async function inspectWitness(wtnsPath) {
    const witness = await wtns.read(wtnsPath);
    console.log("Witness values:", witness);
}
```

### 3. Constraint Analysis

```bash
# View R1CS info
snarkjs r1cs info circuit.r1cs

# Print constraints
snarkjs r1cs print circuit.r1cs circuit.sym
```

## Next Steps

1. Start with `circuits/simple/` examples
2. Test locally with snarkjs
3. Deploy to NEAR testnet
4. Graduate to `circuits/educational/` for production patterns
