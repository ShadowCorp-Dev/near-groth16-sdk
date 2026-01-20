/**
 * Incremental Merkle Tree for Groth16 Privacy Applications
 *
 * WHY CLIENT-SIDE MERKLE TREES:
 * - Contract stores commitments, but building full tree on-chain is expensive
 * - Client builds tree locally, generates proofs for ZK circuits
 * - Only the root is submitted to contract for verification
 *
 * TREE STRUCTURE:
 * - Binary tree with depth N supports 2^N leaves
 * - Depth 20 = 1,048,576 leaves (good for most apps)
 * - Depth 32 = 4 billion leaves (if you need more)
 * - Each level uses Poseidon hash for efficiency in circuits
 *
 * CRITICAL: Tree must be built with SAME hash function as circuit uses!
 */

/**
 * Poseidon hash implementation for Merkle tree
 *
 * IMPORTANT: This must match the Poseidon implementation in your circom circuit.
 * Default uses circomlib's Poseidon with 2 inputs.
 *
 * For production, import from a library like:
 * - circomlibjs (JavaScript implementation)
 * - @zk-kit/incremental-merkle-tree (optimized)
 */
type PoseidonHashFunction = (inputs: bigint[]) => bigint;

// Placeholder - in production, use actual Poseidon implementation
const defaultPoseidon: PoseidonHashFunction = (inputs: bigint[]): bigint => {
    // This is a placeholder. In production, use circomlibjs:
    // import { poseidon } from "circomlibjs";
    // return poseidon(inputs);

    throw new Error(
        'Poseidon hash not implemented. Import from circomlibjs:\n' +
        'npm install circomlibjs\n' +
        'import { poseidon } from "circomlibjs";\n' +
        'const tree = new IncrementalMerkleTree(20, poseidon);'
    );
};

/**
 * Merkle proof for a leaf
 *
 * Used in ZK circuits to prove a commitment exists in the tree.
 */
export interface MerkleProof {
    /** Leaf value (commitment) */
    leaf: bigint;
    /** Leaf position in tree (0 to 2^depth - 1) */
    leafIndex: number;
    /** Sibling hashes from leaf to root */
    pathElements: bigint[];
    /** Path directions (0 = left, 1 = right) */
    pathIndices: number[];
    /** Current Merkle root */
    root: bigint;
}

/**
 * Incremental Merkle Tree
 *
 * INCREMENTAL PATTERN:
 * - Leaves added left-to-right, no gaps
 * - Tree maintains all intermediate hashes for efficient proof generation
 * - Can reconstruct tree from commitment list (for sync with contract)
 *
 * EXAMPLE USAGE:
 * ```typescript
 * import { poseidon } from "circomlibjs";
 *
 * // Create tree (depth 20 = 1M leaves)
 * const tree = new IncrementalMerkleTree(20, poseidon);
 *
 * // Add commitments
 * const commitment1 = poseidon([nullifier, secret, amount, assetId]);
 * const leafIndex = tree.insert(commitment1);
 *
 * // Get root for contract submission
 * const root = tree.getRoot();
 *
 * // Generate proof for ZK circuit
 * const proof = tree.getProof(leafIndex);
 * ```
 */
export class IncrementalMerkleTree {
    /** Tree depth (max leaves = 2^depth) */
    private depth: number;

    /** Hash function (must match circuit) */
    private hasher: PoseidonHashFunction;

    /** All tree levels: levels[0] = leaves, levels[depth] = root */
    private levels: Map<number, bigint[]>;

    /** Current number of leaves inserted */
    private leafCount: number;

    /** Zero values for empty nodes at each level */
    private zeros: bigint[];

    /**
     * Create a new Merkle tree
     *
     * @param depth - Tree depth (20 for ~1M leaves, 32 for ~4B leaves)
     * @param hasher - Poseidon hash function (must match circuit)
     * @param zeroLeaf - Value for empty leaves (default: 0)
     *
     * ZERO VALUE PATTERN:
     * - Empty leaves use zero value
     * - Each level's zero = hash(leftZero, rightZero)
     * - Pre-computed for efficiency
     */
    constructor(
        depth: number,
        hasher?: PoseidonHashFunction,
        zeroLeaf: bigint = 0n
    ) {
        if (depth < 1 || depth > 32) {
            throw new Error('Tree depth must be between 1 and 32');
        }

        this.depth = depth;
        this.hasher = hasher || defaultPoseidon;
        this.levels = new Map();
        this.leafCount = 0;

        // Pre-compute zero values for each level
        this.zeros = [zeroLeaf];
        for (let i = 0; i < depth; i++) {
            const prevZero = this.zeros[i];
            this.zeros.push(this.hasher([prevZero, prevZero]));
        }

        // Initialize empty tree
        this.levels.set(0, []); // Leaves
    }

    /**
     * Insert a new leaf
     *
     * @param leaf - Commitment to insert
     * @returns Leaf index (position in tree)
     *
     * INCREMENTAL PROPERTY:
     * - Leaves added sequentially, no gaps
     * - Only recomputes path from new leaf to root
     * - O(depth) time complexity
     */
    insert(leaf: bigint): number {
        const leafIndex = this.leafCount;

        if (leafIndex >= Math.pow(2, this.depth)) {
            throw new Error(`Tree is full (max ${Math.pow(2, this.depth)} leaves)`);
        }

        // Add leaf
        const leaves = this.levels.get(0) || [];
        leaves.push(leaf);
        this.levels.set(0, leaves);

        // Update path to root
        let currentIndex = leafIndex;
        let currentValue = leaf;

        for (let level = 0; level < this.depth; level++) {
            const levelNodes = this.levels.get(level + 1) || [];
            const isRightNode = currentIndex % 2 === 1;

            if (isRightNode) {
                // Right node - sibling is to the left
                const leftSibling = leaves[currentIndex - 1];
                currentValue = this.hasher([leftSibling, currentValue]);
            } else {
                // Left node - sibling is zero or existing right node
                const rightSibling = (currentIndex + 1 < leaves.length)
                    ? leaves[currentIndex + 1]
                    : this.zeros[level];
                currentValue = this.hasher([currentValue, rightSibling]);
            }

            // Update parent node
            const parentIndex = Math.floor(currentIndex / 2);
            levelNodes[parentIndex] = currentValue;
            this.levels.set(level + 1, levelNodes);

            currentIndex = parentIndex;
        }

        this.leafCount++;
        return leafIndex;
    }

    /**
     * Get current Merkle root
     *
     * @returns Root hash
     *
     * USAGE:
     * - Submit to contract for verification
     * - Contract checks: root exists in valid roots set
     * - Prevents front-running (root must be recent)
     */
    getRoot(): bigint {
        if (this.leafCount === 0) {
            // Empty tree root = hash of all zeros
            return this.zeros[this.depth];
        }

        const rootLevel = this.levels.get(this.depth);
        if (!rootLevel || rootLevel.length === 0) {
            throw new Error('Tree root not computed');
        }

        return rootLevel[0];
    }

    /**
     * Get Merkle proof for a leaf
     *
     * @param leafIndex - Leaf position
     * @returns Merkle proof (for ZK circuit)
     *
     * PROOF STRUCTURE:
     * - pathElements: sibling hashes from leaf to root
     * - pathIndices: path directions (0 = left, 1 = right)
     *
     * CIRCUIT USAGE:
     * ```circom
     * component merkle = MerkleProof(20);
     * merkle.leaf <== commitment;
     * for (var i = 0; i < 20; i++) {
     *     merkle.pathElements[i] <== proof.pathElements[i];
     *     merkle.pathIndices[i] <== proof.pathIndices[i];
     * }
     * root === merkle.root;
     * ```
     */
    getProof(leafIndex: number): MerkleProof {
        if (leafIndex < 0 || leafIndex >= this.leafCount) {
            throw new Error(`Invalid leaf index: ${leafIndex}`);
        }

        const leaves = this.levels.get(0);
        if (!leaves) {
            throw new Error('Tree has no leaves');
        }

        const leaf = leaves[leafIndex];
        const pathElements: bigint[] = [];
        const pathIndices: number[] = [];

        let currentIndex = leafIndex;

        for (let level = 0; level < this.depth; level++) {
            const levelNodes = this.levels.get(level) || [];
            const isRightNode = currentIndex % 2 === 1;

            if (isRightNode) {
                // Sibling is to the left
                const sibling = levelNodes[currentIndex - 1];
                pathElements.push(sibling);
                pathIndices.push(1);
            } else {
                // Sibling is to the right (or zero)
                const sibling = (currentIndex + 1 < levelNodes.length)
                    ? levelNodes[currentIndex + 1]
                    : this.zeros[level];
                pathElements.push(sibling);
                pathIndices.push(0);
            }

            currentIndex = Math.floor(currentIndex / 2);
        }

        return {
            leaf,
            leafIndex,
            pathElements,
            pathIndices,
            root: this.getRoot()
        };
    }

    /**
     * Rebuild tree from commitment list
     *
     * @param commitments - Array of commitments (from contract)
     *
     * SYNC PATTERN:
     * 1. Query contract: get_commitments_range(0, total_count)
     * 2. Build local tree from commitments
     * 3. Verify local root matches contract root
     * 4. Tree is now synced, ready to generate proofs
     *
     * EXAMPLE:
     * ```typescript
     * // Fetch commitments from contract
     * const commitments = await contract.get_commitments_range({ from: 0, limit: 1000 });
     *
     * // Rebuild tree
     * const tree = IncrementalMerkleTree.fromCommitments(commitments, 20, poseidon);
     *
     * // Verify sync
     * const localRoot = tree.getRoot();
     * const contractRoot = await contract.get_tree_state().merkle_root;
     * assert(localRoot === contractRoot, "Tree out of sync!");
     * ```
     */
    static fromCommitments(
        commitments: bigint[],
        depth: number,
        hasher: PoseidonHashFunction
    ): IncrementalMerkleTree {
        const tree = new IncrementalMerkleTree(depth, hasher);

        for (const commitment of commitments) {
            tree.insert(commitment);
        }

        return tree;
    }

    /**
     * Get number of leaves in tree
     */
    getLeafCount(): number {
        return this.leafCount;
    }

    /**
     * Get all leaves
     */
    getLeaves(): bigint[] {
        return this.levels.get(0) || [];
    }

    /**
     * Export tree state (for persistence)
     *
     * BACKUP PATTERN:
     * - Save tree state to localStorage
     * - On app reload, restore from saved state
     * - Avoids rebuilding from contract on every page load
     */
    exportState(): {
        depth: number;
        leafCount: number;
        leaves: string[];  // Hex strings
    } {
        const leaves = this.getLeaves();

        return {
            depth: this.depth,
            leafCount: this.leafCount,
            leaves: leaves.map(l => '0x' + l.toString(16))
        };
    }

    /**
     * Import tree state (from persistence)
     */
    static importState(
        state: { depth: number; leafCount: number; leaves: string[] },
        hasher: PoseidonHashFunction
    ): IncrementalMerkleTree {
        const leaves = state.leaves.map(l => BigInt(l));
        return IncrementalMerkleTree.fromCommitments(leaves, state.depth, hasher);
    }
}

/**
 * Verify a Merkle proof locally (before submitting to contract)
 *
 * @param proof - Merkle proof
 * @param hasher - Poseidon hash function
 * @returns true if proof is valid
 *
 * TESTING PATTERN:
 * - Generate proof locally
 * - Verify locally (instant, free)
 * - If invalid, debug before submitting to contract
 * - Saves gas on invalid proofs
 */
export function verifyMerkleProof(
    proof: MerkleProof,
    hasher: PoseidonHashFunction
): boolean {
    let currentHash = proof.leaf;

    for (let i = 0; i < proof.pathElements.length; i++) {
        const sibling = proof.pathElements[i];
        const isRightNode = proof.pathIndices[i] === 1;

        if (isRightNode) {
            currentHash = hasher([sibling, currentHash]);
        } else {
            currentHash = hasher([currentHash, sibling]);
        }
    }

    return currentHash === proof.root;
}
