# NEAR Groth16 ZK Toolkit

A complete toolkit for building zero-knowledge applications on NEAR Protocol using Groth16 proofs.

## Deliverables

### 1. near_groth16_verifier Crate (`/crate`)
- NEAR SDK 5.7 compatible
- circom 2.x / snarkjs compatible
- Uses native `alt_bn128` precompiles
- Includes Fiat-Shamir transcript for PLONK support

### 2. Example Circuits Library (`/circuits`)

**Simple (4 circuits):**
- `multiplier.circom` - Basic multiplication proof
- `hash_preimage.circom` - Hash commitment
- `range_proof.circom` - Value in range
- `merkle_proof.circom` - Set membership

**Educational (4 circuits):**
- `age_verification.circom` - Age check without revealing DOB
- `private_voting.circom` - Anonymous voting with nullifiers
- `ownership_proof.circom` - Asset ownership in Merkle tree
- `arithmetic_proof.circom` - Pythagorean/factorization proofs

### 3. TypeScript SDK (`/sdk`)

Production-ready browser SDK for building ZK applications:
- Wallet integration (@hot-labs/near-connect, HOT Wallet, MyNearWallet)
- Proof generation with snarkjs wrapper
- Client-side Merkle tree implementation
- UTXO note management (save-before-transaction pattern)
- Local proof verification
- Full browser support

**Key Features:**
- Correct wallet action format for HOT Wallet compatibility
- Explicit signerId handling
- Note management patterns that prevent data loss
- Merkle tree synchronization utilities

### 4. Smart Contract Templates (`/templates`)
- `basic/` - Minimal verifier
- `privacy/` - With nullifier + commitment tracking
- `privacy-near-only/` - Simple NEAR-only privacy pool with extensive inline comments
- `privacy-multi-asset/` - Multi-asset support (NEAR + FTs) with NEP-141 integration
- `voting/` - Full anonymous voting system with polls

### 5. CLI Deployment Tool (`/cli`)
- `convert-vk` - Validate/convert verification keys
- `format-proof` - Format proofs for contract calls
- `deploy-script` - Generate deployment scripts
- `validate` - Check VK format
- `call-args` - Generate NEAR CLI commands
- `info` - Show circuit info and gas estimates

### 6. Comprehensive Documentation (`/docs`)
- `README.md` - Overview and quick start
- `CIRCUITS.md` - Circuit development guide
- `CONTRACTS.md` - Smart contract patterns
- `INTEGRATION.md` - End-to-end workflow with TypeScript SDK
- `TROUBLESHOOTING.md` - Common issues (endianness, G2 ordering, etc.)
- `GAS_OPTIMIZATION.md` - Gas costs and public hash packing technique

---

## Overview

This toolkit provides everything needed to deploy and use Groth16 zero-knowledge proofs on NEAR Protocol.

## Quick Start

### Prerequisites

- Rust toolchain with `wasm32-unknown-unknown` target
- Node.js 16+ for circom/snarkjs
- NEAR CLI (`near-cli-rs`)

```bash
# Install Rust WASM target
rustup target add wasm32-unknown-unknown

# Install circom
npm install -g circom snarkjs

# Install NEAR CLI
cargo install near-cli-rs
```

### 1. Create Your Circuit

```circom
pragma circom 2.1.0;

template SecretMultiplier() {
    signal input a;      // Private
    signal input b;      // Private
    signal output c;     // Public

    c <== a * b;
}

component main {public [c]} = SecretMultiplier();
```

### 2. Compile and Generate Keys

```bash
# Compile
circom circuit.circom --r1cs --wasm --sym

# Setup (use existing powers of tau for production)
snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit.zkey

# Export verification key
snarkjs zkey export verificationkey circuit.zkey verification_key.json
```

### 3. Build and Deploy Contract

```bash
cd templates/basic
cargo build --target wasm32-unknown-unknown --release

# Deploy
near deploy --accountId verifier.testnet \
  --wasmFile target/wasm32-unknown-unknown/release/zk_verifier_basic.wasm

# Initialize with verification key
near call verifier.testnet new "$(cat verification_key.json)" \
  --accountId deployer.testnet
```

### 4. Generate and Verify Proofs

```bash
# Generate proof
echo '{"a": 3, "b": 7}' > input.json
snarkjs groth16 fullprove input.json circuit_js/circuit.wasm circuit.zkey \
  proof.json public.json

# Verify on-chain
near call verifier.testnet verify '{
  "proof": '"$(cat proof.json)"',
  "public_inputs": '"$(cat public.json)"'
}' --accountId user.testnet
```

## Why Groth16 on NEAR?

NEAR Protocol includes native `alt_bn128` cryptographic precompiles:
- `alt_bn128_g1_multiexp` - Multi-scalar multiplication on G1
- `alt_bn128_g1_sum` - Point addition on G1
- `alt_bn128_pairing_check` - Bilinear pairing verification

This enables efficient Groth16 verification:

| Verification Type | Approximate Gas Cost |
|-------------------|---------------------|
| Simple (1 input)  | ~50-80 TGas        |
| Medium (5 inputs) | ~70-100 TGas       |
| Complex (10+ inputs) | ~100-150 TGas   |

Compare to pure WASM implementations that would require 300+ TGas.

## Repository Structure

```
.
├── crate/                    # The Rust verification crate
│   ├── src/
│   │   ├── lib.rs           # Main exports
│   │   ├── types.rs         # G1, G2, Proof, VK types
│   │   ├── verifier.rs      # Core verification logic
│   │   └── transcript.rs    # Fiat-Shamir for PLONK
│   └── examples/
│       └── contract.rs      # Full example contract
│
├── sdk/                     # TypeScript SDK for browser/Node.js
│   ├── src/
│   │   ├── wallet.ts        # Wallet integration
│   │   ├── prover.ts        # Proof generation
│   │   ├── merkle.ts        # Merkle tree utilities
│   │   ├── notes.ts         # UTXO note management
│   │   └── index.ts         # Main exports
│   └── examples/
│       └── privacy-transfer.ts  # Complete end-to-end example
│
├── circuits/                 # Example circom circuits
│   ├── simple/              # Basic educational circuits
│   │   ├── multiplier.circom
│   │   ├── hash_preimage.circom
│   │   ├── range_proof.circom
│   │   └── merkle_proof.circom
│   └── educational/         # More complex examples
│       ├── age_verification.circom
│       ├── private_voting.circom
│       ├── ownership_proof.circom
│       └── arithmetic_proof.circom
│
├── templates/               # Production contract templates
│   ├── basic/              # Minimal verifier
│   ├── privacy/            # With nullifier tracking
│   ├── privacy-near-only/  # NEAR-only privacy pool
│   ├── privacy-multi-asset/ # Multi-asset privacy pool
│   └── voting/             # Anonymous voting system
│
├── cli/                    # Command-line tools
│   └── src/main.rs        # Conversion & deployment
│
└── docs/                   # Documentation
    ├── README.md          # This file
    ├── CIRCUITS.md        # Circuit development guide
    ├── CONTRACTS.md       # Smart contract guide
    └── INTEGRATION.md     # End-to-end integration
```

## Documentation

- [Circuit Development Guide](./CIRCUITS.md) - Writing and testing circom circuits
- [Smart Contract Guide](./CONTRACTS.md) - Building verifier contracts
- [Integration Guide](./INTEGRATION.md) - Full workflow from circuit to deployment
- [Gas Optimization Guide](./GAS_OPTIMIZATION.md) - Reduce verification costs (public hash packing)
- [Troubleshooting Guide](./TROUBLESHOOTING.md) - Common issues and solutions

## Security Considerations

### Trusted Setup

Groth16 requires a trusted setup ceremony. Options:
1. Use existing public ceremonies (Hermez, Zcash) for compatible circuits
2. Conduct your own multi-party computation ceremony
3. Use circuit-specific setup with multiple contributors

### Circuit Security

- Audit your circuits - ZK proofs only prove computation correctness
- Test edge cases thoroughly
- Validate all inputs are in the scalar field

### Nullifier Management

For privacy applications:
- Always check nullifiers before accepting proofs
- Use deterministic nullifier derivation
- Consider nullifier collision resistance

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please open issues or PRs on GitHub.
