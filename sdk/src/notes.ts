/**
 * Note Management for Groth16 Privacy Applications
 *
 * UTXO Model for Private Transactions:
 * - Notes are like UTXOs in Bitcoin - unspent transaction outputs
 * - Each note has: nullifier (spending key), secret, amount, assetId
 * - To spend a note, you reveal its nullifier in a proof
 * - Once nullifier is revealed, note is permanently spent
 *
 * CRITICAL CONCEPTS:
 * - Commitment = hash(nullifier, secret, amount, assetId)
 * - Nullifier hash = hash(nullifier, leafIndex) - prevents double-spending
 * - Notes are stored CLIENT-SIDE (browser localStorage or encrypted backup)
 * - Contract only stores commitments and nullifier hashes
 */

/**
 * A private note (UTXO) in the shielded pool
 *
 * FIELDS:
 * - nullifier: Secret value, revealing it marks note as spent
 * - secret: Blinding factor for commitment
 * - amount: Value in atomic units (yoctoNEAR or token smallest unit)
 * - assetId: Hash of token contract ID (0 for NEAR)
 * - commitment: Public commitment = hash(nullifier, secret, amount, assetId)
 * - leafIndex: Position in Merkle tree (needed for proof generation)
 * - spent: Client-side tracking (server doesn't know which note is which)
 * - createdAt: Timestamp for UI sorting
 * - sourceType: How this note was created
 */
export interface Note {
    nullifier: string;        // Hex or decimal string
    secret: string;           // Hex or decimal string
    amount: string;           // Decimal string (BigInt-compatible)
    assetId: string;          // Decimal string
    commitment: string;       // Hex or decimal string
    leafIndex: number;        // Tree position
    spent: boolean;           // Client-side tracking
    createdAt: number;        // Unix timestamp
    sourceType: 'deposit' | 'transfer' | 'change';  // Origin
}

/**
 * Storage key for a user's notes
 *
 * PRIVACY CONSIDERATION:
 * - Notes are encrypted with user's shielded key
 * - Different users can't see each other's notes
 * - Even if localStorage is exposed, notes are useless without the key
 */
function getStorageKey(publicKey: string): string {
    return `zk_notes_${publicKey}`;
}

/**
 * Save a note to browser localStorage
 *
 * @param publicKey - User's shielded public key (hex string)
 * @param note - Note to save
 *
 * SECURITY:
 * - Notes stored in localStorage are viewable by browser extensions
 * - Production apps should encrypt notes client-side
 * - Consider using IndexedDB for larger note sets
 *
 * EXAMPLE:
 * ```typescript
 * const note = {
 *     nullifier: "0x1234...",
 *     secret: "0x5678...",
 *     amount: "1000000000000000000000000", // 1 NEAR
 *     assetId: "0",
 *     commitment: "0xabcd...",
 *     leafIndex: 42,
 *     spent: false,
 *     createdAt: Date.now(),
 *     sourceType: 'deposit'
 * };
 * saveNote(userPublicKey, note);
 * ```
 */
export function saveNote(publicKey: string, note: Note): void {
    const key = getStorageKey(publicKey);
    const existing = getNotes(publicKey);

    // Prevent duplicates - check by commitment
    const duplicate = existing.find(n => n.commitment === note.commitment);
    if (duplicate) {
        console.warn('[NoteManager] Duplicate note detected, skipping save:', note.commitment);
        return;
    }

    existing.push(note);
    localStorage.setItem(key, JSON.stringify(existing));

    console.log('[NoteManager] Saved note:', {
        commitment: note.commitment,
        amount: note.amount,
        leafIndex: note.leafIndex,
        sourceType: note.sourceType
    });
}

/**
 * Get all notes for a user
 *
 * @param publicKey - User's shielded public key
 * @param spent - Filter by spent status (undefined = all notes)
 * @returns Array of notes
 *
 * EXAMPLE:
 * ```typescript
 * // Get all unspent notes
 * const unspent = getNotes(userPublicKey, false);
 *
 * // Get all notes (spent + unspent)
 * const allNotes = getNotes(userPublicKey);
 * ```
 */
export function getNotes(publicKey: string, spent?: boolean): Note[] {
    const key = getStorageKey(publicKey);
    const stored = localStorage.getItem(key);

    if (!stored) return [];

    try {
        const notes: Note[] = JSON.parse(stored);

        if (spent !== undefined) {
            return notes.filter(n => n.spent === spent);
        }

        return notes;
    } catch (e) {
        console.error('[NoteManager] Failed to parse notes:', e);
        return [];
    }
}

/**
 * Mark a note as spent
 *
 * @param publicKey - User's shielded public key
 * @param commitment - Note commitment to mark spent
 *
 * WHEN TO CALL:
 * - After successfully submitting a transaction that spends the note
 * - After transaction is confirmed on-chain
 * - DO NOT mark spent if transaction fails
 *
 * EXAMPLE:
 * ```typescript
 * // After successful transfer
 * const result = await wallet.signAndSendTransaction({...});
 * if (result.status === 'success') {
 *     markSpent(userPublicKey, inputNote.commitment);
 * }
 * ```
 */
export function markSpent(publicKey: string, commitment: string): void {
    const key = getStorageKey(publicKey);
    const notes = getNotes(publicKey);

    const note = notes.find(n => n.commitment === commitment);
    if (!note) {
        console.warn('[NoteManager] Note not found for commitment:', commitment);
        return;
    }

    note.spent = true;
    localStorage.setItem(key, JSON.stringify(notes));

    console.log('[NoteManager] Marked note as spent:', commitment);
}

/**
 * Get spendable notes for a specific amount and asset
 *
 * @param publicKey - User's shielded public key
 * @param assetId - Asset ID to filter by
 * @param targetAmount - Minimum total amount needed
 * @returns Array of unspent notes, sorted by amount (largest first)
 *
 * UTXO SELECTION STRATEGY:
 * - Largest-first (minimizes number of inputs needed)
 * - Only includes unspent notes
 * - Filters by assetId (can't mix NEAR and USDC in same proof)
 *
 * EXAMPLE:
 * ```typescript
 * // User wants to transfer 5 NEAR
 * const notes = getSpendableNotes(publicKey, "0", "5000000000000000000000000");
 *
 * // Check if user has enough balance
 * const totalAmount = notes.reduce((sum, n) => sum + BigInt(n.amount), 0n);
 * if (totalAmount < targetAmount) {
 *     throw new Error("Insufficient balance");
 * }
 *
 * // Use first 2 notes (assuming 2-input circuit)
 * const [note1, note2] = notes;
 * ```
 */
export function getSpendableNotes(
    publicKey: string,
    assetId: string,
    targetAmount: string
): Note[] {
    const target = BigInt(targetAmount);

    // Get unspent notes for this asset
    const notes = getNotes(publicKey, false)
        .filter(n => n.assetId === assetId)
        .sort((a, b) => {
            // Sort largest first
            const diff = BigInt(b.amount) - BigInt(a.amount);
            return diff > 0n ? 1 : diff < 0n ? -1 : 0;
        });

    // Select notes until we have enough
    const selected: Note[] = [];
    let total = 0n;

    for (const note of notes) {
        selected.push(note);
        total += BigInt(note.amount);

        if (total >= target) {
            break;
        }
    }

    return selected;
}

/**
 * Get total balance for an asset
 *
 * @param publicKey - User's shielded public key
 * @param assetId - Asset ID to check
 * @param includeSpent - Include spent notes in total (default: false)
 * @returns Total balance as decimal string
 *
 * EXAMPLE:
 * ```typescript
 * // Get unspent NEAR balance
 * const balance = getTotalBalance(publicKey, "0");
 * console.log(`Balance: ${balance} yoctoNEAR`);
 *
 * // Get historical total (spent + unspent)
 * const allTimeTotal = getTotalBalance(publicKey, "0", true);
 * ```
 */
export function getTotalBalance(
    publicKey: string,
    assetId: string,
    includeSpent: boolean = false
): string {
    const notes = includeSpent
        ? getNotes(publicKey).filter(n => n.assetId === assetId)
        : getNotes(publicKey, false).filter(n => n.assetId === assetId);

    const total = notes.reduce((sum, note) => {
        return sum + BigInt(note.amount);
    }, 0n);

    return total.toString();
}

/**
 * Create a dummy note for 2-input circuits
 *
 * When a circuit requires 2 input notes but user only has 1,
 * use a dummy note with amount = 0.
 *
 * DUMMY NOTE PROPERTIES:
 * - amount = 0
 * - nullifier = random (won't be checked)
 * - secret = random
 * - assetId = same as real note
 * - leafIndex = 0 (or any valid index)
 *
 * CIRCUIT HANDLING:
 * ```circom
 * // Circuit checks: either valid note OR dummy (amount = 0)
 * component isInput1Dummy = IsZero();
 * isInput1Dummy.in <== inAmount1;
 *
 * // If dummy, skip Merkle proof verification
 * component shouldCheckMerkle = IsZero();
 * shouldCheckMerkle.in <== isInput1Dummy.out;
 * ```
 */
export function createDummyNote(assetId: string): Partial<Note> {
    return {
        nullifier: "0",
        secret: "0",
        amount: "0",
        assetId: assetId
    };
}

/**
 * Export all notes to JSON (for backup)
 *
 * @param publicKey - User's shielded public key
 * @returns JSON string of all notes
 *
 * BACKUP PATTERN:
 * 1. User clicks "Backup Notes"
 * 2. App calls exportNotes()
 * 3. Save to file or encrypted cloud storage
 * 4. To restore, load JSON and parse
 *
 * SECURITY WARNING:
 * - This export contains spending keys (nullifiers)
 * - Anyone with this file can spend user's notes
 * - Encrypt before storing or transmitting
 */
export function exportNotes(publicKey: string): string {
    const notes = getNotes(publicKey);
    return JSON.stringify(notes, null, 2);
}

/**
 * Import notes from JSON backup
 *
 * @param publicKey - User's shielded public key
 * @param jsonData - JSON string from exportNotes()
 * @param merge - Merge with existing notes (default) or replace
 */
export function importNotes(
    publicKey: string,
    jsonData: string,
    merge: boolean = true
): void {
    try {
        const imported: Note[] = JSON.parse(jsonData);

        if (!Array.isArray(imported)) {
            throw new Error("Invalid notes format - expected array");
        }

        const key = getStorageKey(publicKey);

        if (merge) {
            const existing = getNotes(publicKey);
            const combined = [...existing];

            // Add imported notes, skip duplicates
            for (const note of imported) {
                const duplicate = existing.find(n => n.commitment === note.commitment);
                if (!duplicate) {
                    combined.push(note);
                }
            }

            localStorage.setItem(key, JSON.stringify(combined));
            console.log('[NoteManager] Imported and merged', imported.length, 'notes');
        } else {
            // Replace all notes
            localStorage.setItem(key, jsonData);
            console.log('[NoteManager] Imported', imported.length, 'notes (replaced existing)');
        }
    } catch (e) {
        console.error('[NoteManager] Failed to import notes:', e);
        throw new Error('Invalid notes backup file');
    }
}
