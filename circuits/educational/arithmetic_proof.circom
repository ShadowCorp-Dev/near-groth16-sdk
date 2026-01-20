pragma circom 2.1.0;

/*
 * Arithmetic Proof Circuit
 *
 * Proves: Knowledge of values that satisfy a polynomial equation
 *         a^2 + b^2 = c (Pythagorean theorem)
 *
 * This demonstrates:
 * - Quadratic constraints
 * - Multiple private inputs
 * - Mathematical proofs in ZK
 *
 * Use cases:
 * - Proving computation results without revealing inputs
 * - Verifiable computation
 */

template PythagoreanProof() {
    // Private inputs - the secret sides
    signal input a;
    signal input b;

    // Public output - the result we're proving
    signal output c;

    // Intermediate signals for squares
    signal a_squared;
    signal b_squared;

    // Compute squares
    a_squared <== a * a;
    b_squared <== b * b;

    // Sum of squares
    c <== a_squared + b_squared;
}

// Alternative: prove we know factors
template FactorizationProof() {
    // Private inputs
    signal input p;  // First prime factor
    signal input q;  // Second prime factor

    // Public output
    signal output n;  // The product

    // Simple multiplication constraint
    n <== p * q;

    // Optional: enforce p > 1 and q > 1 (they're not trivial)
    signal p_minus_1;
    signal q_minus_1;
    p_minus_1 <== p - 1;
    q_minus_1 <== q - 1;

    // Both must be positive (non-zero constraint)
    // This is a simplified check - full primality would need more
    signal p_check;
    signal q_check;
    p_check <-- 1 / p_minus_1;  // Will fail if p = 1
    q_check <-- 1 / q_minus_1;  // Will fail if q = 1
    p_check * p_minus_1 === 1;
    q_check * q_minus_1 === 1;
}

// Quadratic equation solver proof
// Prove we know x such that ax^2 + bx + c = 0
template QuadraticSolution() {
    // Private input - the solution
    signal input x;

    // Public inputs - coefficients
    signal input a;
    signal input b;
    signal input c;

    // Compute ax^2 + bx + c
    signal x_squared;
    signal ax_squared;
    signal bx;
    signal result;

    x_squared <== x * x;
    ax_squared <== a * x_squared;
    bx <== b * x;
    result <== ax_squared + bx + c;

    // Prove result is zero
    result === 0;
}

// Main: export Pythagorean proof
component main {public [c]} = PythagoreanProof();
