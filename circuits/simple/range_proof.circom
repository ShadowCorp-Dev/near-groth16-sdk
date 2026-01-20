pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Range Proof Circuit
 *
 * Proves: A secret value is within a range [min, max]
 *         without revealing the actual value.
 *
 * Use cases:
 * - Age verification (prove age >= 18 without revealing exact age)
 * - Credit score verification (prove score > threshold)
 * - Balance checks (prove balance >= amount)
 */

template RangeProof(n) {
    // Private input - the secret value
    signal input value;

    // Public inputs - the range bounds
    signal input minValue;
    signal input maxValue;

    // Public output - always 1 if proof is valid
    signal output valid;

    // Decompose value to bits to ensure it's within n-bit range
    component valueBits = Num2Bits(n);
    valueBits.in <== value;

    // Check: value >= minValue
    component gte = GreaterEqThan(n);
    gte.in[0] <== value;
    gte.in[1] <== minValue;

    // Check: value <= maxValue
    component lte = LessEqThan(n);
    lte.in[0] <== value;
    lte.in[1] <== maxValue;

    // Both conditions must be true
    valid <== gte.out * lte.out;

    // Enforce valid == 1 (constraint will fail if not in range)
    valid === 1;
}

// 64-bit range proof (handles values up to 2^64 - 1)
component main {public [minValue, maxValue, valid]} = RangeProof(64);
