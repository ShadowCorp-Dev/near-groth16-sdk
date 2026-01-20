pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

/*
 * Hash Preimage Circuit
 *
 * Proves: I know a secret value that hashes to a public commitment
 *
 * This demonstrates the fundamental ZK pattern:
 * - Public: the hash output (commitment)
 * - Private: the preimage (secret)
 *
 * Use cases:
 * - Password verification without transmitting passwords
 * - Commitment schemes
 * - Identity proofs
 */

template HashPreimage() {
    // Private input - the secret preimage
    signal input preimage;

    // Public output - the hash/commitment
    signal output commitment;

    // Poseidon hash is ZK-friendly (fewer constraints than SHA256)
    component hasher = Poseidon(1);
    hasher.inputs[0] <== preimage;

    commitment <== hasher.out;
}

component main {public [commitment]} = HashPreimage();
