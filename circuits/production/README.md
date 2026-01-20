# Production Privacy Circuits

Production-grade circom circuits for shielded pools with commitment schemes and Merkle trees.

Ported from the [Obscura Wallet](https://github.com/obscura-protocol/obscurav2) project - battle-tested privacy patterns for NEAR Protocol.

## Overview

These circuits implement a complete privacy pool system using:
- **Poseidon Hash** - ZK-friendly hashing (200 constraints vs 25,000 for SHA-256)
- **Merkle Trees** - Note commitment storage (20 levels = ~1M capacity)
- **Nullifier System** - Double-spend prevention
- **UTXO Model** - 2-in-2-out transfers like Zcash Sapling

## Core Components (utils.circom)

### Commitment Scheme

**`template Commitment()`**

Computes note commitment using tree-style Poseidon hash:

```circom
commitment = Poseidon(
    Poseidon(nullifier, secret),
    Poseidon(amount, assetId)
)
```

**Why tree-style?** Matches NEAR contract's t=3 Poseidon (2-input only).

**Inputs:**
- `nullifier` - Random value for spending
- `secret` - Random value for hiding
- `amount` - Token amount
- `assetId` - Asset identifier (0 = NEAR)

**Output:**
- `commitment` - Unique commitment to add to Merkle tree

---

**`template CommitmentSimple()`**

Simplified 3-input commitment for single-asset pools:

```circom
commitment = Poseidon(nullifier, secret, amount)
```

### Nullifier Derivation

**`template NullifierDerivation()`**

Derives unique nullifier hash to prevent double-spending:

```circom
nullifierHash = Poseidon(nullifier, leafIndex)
```

**Why include leafIndex?** Ensures same nullifier can't be reused at different tree positions.

**Inputs:**
- `nullifier` - Note's secret nullifier
- `leafIndex` - Position in Merkle tree

**Output:**
- `nullifierHash` - Public nullifier for spending

---

**`template NullifierSimple()`**

Simplified version without leaf index:

```circom
nullifierHash = Poseidon(nullifier)
```

### Merkle Tree Verification

**`template MerkleProof(levels)`**

Verifies note exists in Merkle tree:

**Inputs:**
- `leaf` - Commitment to verify
- `pathElements[levels]` - Sibling hashes (proof)
- `pathIndices[levels]` - Path bits (0=left, 1=right)

**Outputs:**
- `root` - Computed Merkle root
- `leafIndex` - Leaf position (from path bits)

**Example:**
```circom
component merkle = MerkleProof(20); // 2^20 = ~1M notes
merkle.leaf <== commitment;
merkle.pathElements[i] <== proof.siblings[i];
merkle.pathIndices[i] <== proof.path[i];
```

---

**`template MerkleLevel()`**

Single level of Merkle proof (used internally by MerkleProof).

### Range Checks

**`template RangeCheck(n)`**

Ensures value < 2^n (prevents overflow attacks):

```circom
component check = RangeCheck(128); // 128-bit amounts
check.value <== amount;
```

---

**`template NonZero()`**

Ensures value is non-zero:

```circom
component check = NonZero();
check.value <== nullifier;
```

## Privacy Operations

### 1. Deposit Circuit (deposit.circom)

Proves: "I know the preimage of this commitment"

**Public Inputs (3):**
- `commitment` - The commitment to add to tree
- `amount` - Deposit amount (public for contract)
- `assetId` - Asset type (0 = NEAR)

**Private Inputs:**
- `nullifier` - Random nullifier for future spending
- `secret` - Random secret for hiding

**Constraints:**
1. Commitment is correctly computed
2. Amount is within valid range (128-bit)
3. Nullifier is non-zero

**Usage:**
```bash
circom deposit.circom --r1cs --wasm --sym
```

### 2. Withdraw Circuit (withdraw.circom)

Proves: "I own a note in the tree and I'm spending it correctly"

**Public Inputs (7):**
- `nullifierHash` - Prevents double-spending
- `root` - Merkle tree root
- `recipient` - Withdrawal address
- `amount` - Withdrawal amount
- `assetId` - Asset type
- `fee` - Relayer fee
- `relayer` - Relayer address (0 if self-relay)

**Private Inputs:**
- `nullifier` - Note's secret nullifier
- `secret` - Note's secret
- `pathElements[20]` - Merkle proof siblings
- `pathIndices[20]` - Merkle proof path

**Security Properties:**
1. Prover knows note preimage (nullifier, secret, amount)
2. Note exists in Merkle tree (valid proof to root)
3. NullifierHash correctly derived (prevents double-spend)
4. Amount/recipient bound to proof (prevents front-running)
5. Fee ≤ amount (prevents invalid fees)

**Usage:**
```bash
circom withdraw.circom --r1cs --wasm --sym
```

### 3. Transfer Circuit (transfer.circom)

Proves: "I'm spending input notes and creating output notes with value conservation"

**Gas-Optimized Design:** 2-in-2-out transfer (like Zcash Sapling)

**Public Inputs (6):**
- `nullifierHash1`, `nullifierHash2` - Input note nullifiers
- `outputCommitment1`, `outputCommitment2` - New note commitments
- `root` - Merkle tree root
- `publicDataHash` - Hash of (publicAmount, assetId, extDataHash)

**Private Inputs:**
- Input Note 1: nullifier, secret, amount, pathElements[20], pathIndices[20]
- Input Note 2: nullifier, secret, amount, pathElements[20], pathIndices[20]
- Output Note 1: nullifier, secret, amount
- Output Note 2: nullifier, secret, amount
- Public data: publicAmount, assetId, extDataHash

**Value Conservation:**
```
input1.amount + input2.amount + publicAmount = output1.amount + output2.amount
```

**Dummy Notes:** If only using 1 input, set the other to amount=0 (dummy note).

**Security Properties:**
1. Both input notes exist in tree
2. Nullifiers correctly derived
3. Value conservation enforced
4. Output commitments correctly formed
5. No double-spend within transaction (nullifiers different)

**Usage:**
```bash
circom transfer.circom --r1cs --wasm --sym
```

## Circuit → Contract Alignment

These circuits match the security fixes in near-groth16-sdk templates:

| Security Fix | Circuit Enforcement |
|--------------|-------------------|
| **CRITICAL-4**: Commitment uniqueness | Each deposit creates unique commitment |
| **CRITICAL-3**: FT deposit validation | Asset ID bound to commitment |
| **CRITICAL-1**: Asset ID hash | Poseidon hash of asset ID in commitment |
| **HIGH-1**: Vote privacy | Vote value NOT in public inputs (separate methods) |
| **MEDIUM-2**: Poll timestamp | Timestamp validation on-chain (not circuit) |

## Testing

**Verify Poseidon matches circomlibjs:**

```bash
cd /path/to/near-groth16-sdk
cargo test poseidon_tests -- --nocapture
```

**Expected output:**
```
hash(1, 2) = 7853200120776062878684798364095072458815029376092732009249414926327459813530
hash(0, 0) = 14744269619966411208579211824598458697587494354926760081771325075741142829156
```

**Compile circuits:**

```bash
# Install circom
curl -L https://github.com/iden3/circom/releases/download/v2.1.6/circom-linux-amd64 -o /usr/local/bin/circom
chmod +x /usr/local/bin/circom

# Compile
circom utils.circom --r1cs --wasm --sym
circom deposit.circom --r1cs --wasm --sym
circom withdraw.circom --r1cs --wasm --sym
circom transfer.circom --r1cs --wasm --sym
```

**Expected constraint counts:**
- `deposit`: ~200 constraints (Poseidon hash + range check)
- `withdraw`: ~5,000 constraints (Merkle proof 20 levels + checks)
- `transfer`: ~10,000 constraints (2 inputs + 2 outputs + value check)

## References

- **Obscura Wallet**: https://github.com/obscura-protocol/obscurav2
- **circomlibjs**: https://github.com/iden3/circomlibjs
- **Poseidon Paper**: https://eprint.iacr.org/2019/458.pdf
- **Zcash Sapling**: https://z.cash/upgrade/sapling/

## License

MIT OR Apache-2.0
