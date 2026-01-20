pragma circom 2.1.0;

/*
 * Simple Multiplier Circuit
 *
 * Proves: a * b = c where c is public
 *
 * This is the "hello world" of ZK circuits - demonstrates basic
 * constraint satisfaction without revealing the private inputs.
 *
 * Use case: Proving you know two factors of a number without revealing them.
 */

template Multiplier() {
    // Private inputs
    signal input a;
    signal input b;

    // Public output
    signal output c;

    // The constraint: multiplication
    c <== a * b;
}

// Main component with public output
component main {public [c]} = Multiplier();
