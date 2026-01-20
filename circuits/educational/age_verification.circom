pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * Age Verification Circuit
 *
 * Proves: User is above a minimum age without revealing exact age or birth date.
 *
 * Pattern:
 * 1. User commits to their birth year (hashed)
 * 2. Proves: currentYear - birthYear >= minimumAge
 *
 * Use cases:
 * - Age-restricted content access
 * - Regulatory compliance (e.g., gambling, alcohol)
 * - KYC without full identity disclosure
 */

template AgeVerification() {
    // Private inputs
    signal input birthYear;          // User's birth year (e.g., 1990)
    signal input birthYearSalt;      // Salt for commitment

    // Public inputs
    signal input currentYear;        // Current year (e.g., 2024)
    signal input minimumAge;         // Required age (e.g., 18)
    signal input birthYearCommitment; // Hash(birthYear, salt)

    // Public output
    signal output isEligible;

    // Verify commitment to birth year
    component commitmentHash = Poseidon(2);
    commitmentHash.inputs[0] <== birthYear;
    commitmentHash.inputs[1] <== birthYearSalt;
    birthYearCommitment === commitmentHash.out;

    // Calculate age
    signal age;
    age <== currentYear - birthYear;

    // Check age >= minimumAge
    component ageCheck = GreaterEqThan(8); // 8 bits enough for age
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== minimumAge;

    isEligible <== ageCheck.out;

    // Enforce eligibility
    isEligible === 1;
}

component main {public [currentYear, minimumAge, birthYearCommitment, isEligible]} = AgeVerification();
