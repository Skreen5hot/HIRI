/**
 * Statement Index Construction — Milestone 13
 *
 * Builds and verifies salted statement indices for selective disclosure (§8.4).
 *
 * Key constraints:
 * - Concatenation is byte-level: concat(rawSaltBytes, UTF-8(statement))
 * - Each statementHash is a raw 32-byte SHA-256 digest (NOT "sha256:..." prefixed)
 * - indexRoot = "sha256:" + hex(SHA-256(concat(allRawDigests)))
 * - Verifiers MUST NOT re-canonicalize disclosed statements (§8.8)
 *
 * This module is Layer 2 (Privacy).
 */

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

export interface StatementIndexResult {
  statementHashes: Uint8Array[]; // Raw 32-byte digests per statement
  indexRoot: string; // "sha256:<hex>"
  indexSalt: Uint8Array; // Raw 32 bytes
  statements: string[]; // Individual N-Quad strings
}

// ---------------------------------------------------------------------------
// Statement Index Construction (§8.4.2)
// ---------------------------------------------------------------------------

/**
 * Build a salted statement index from canonical N-Quads.
 *
 * @param canonicalNQuads - URDNA2015 canonical N-Quads (newline-separated)
 * @param indexSalt - Optional 32-byte salt (generated if not provided)
 */
export async function buildStatementIndex(
  canonicalNQuads: string,
  indexSalt?: Uint8Array,
): Promise<StatementIndexResult> {
  // Step 1: Generate or use provided salt
  const salt = indexSalt ?? globalThis.crypto.getRandomValues(new Uint8Array(32));
  if (salt.length !== 32) {
    throw new Error(`indexSalt must be 32 bytes, got ${salt.length}`);
  }

  // Step 2: Split into individual statements
  const statements = canonicalNQuads.split("\n").filter((s) => s.length > 0);

  // Step 3: Compute salted hash per statement
  const statementHashes: Uint8Array[] = [];
  for (const stmt of statements) {
    const hash = await computeSaltedHash(salt, stmt);
    statementHashes.push(hash);
  }

  // Step 4: Compute index root = SHA-256(concat(allRawDigests))
  const totalBytes = statementHashes.length * 32;
  const rawDigests = new Uint8Array(totalBytes);
  for (let i = 0; i < statementHashes.length; i++) {
    rawDigests.set(statementHashes[i], i * 32);
  }
  const rootDigest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", rawDigests),
  );
  const indexRoot = "sha256:" + bytesToHex(rootDigest);

  return { statementHashes, indexRoot, indexSalt: salt, statements };
}

// ---------------------------------------------------------------------------
// Statement Verification (§8.8)
// ---------------------------------------------------------------------------

/**
 * Verify a single statement against its expected hash in the index.
 *
 * MUST NOT re-canonicalize the statement (§8.8 blank node rule).
 * Hashes the N-Quad string as-is.
 *
 * @param statement - The N-Quad string to verify
 * @param expectedHash - The expected raw 32-byte salted hash
 * @param indexSalt - Raw 32-byte salt
 */
export async function verifyStatementInIndex(
  statement: string,
  expectedHash: Uint8Array,
  indexSalt: Uint8Array,
): Promise<boolean> {
  const computed = await computeSaltedHash(indexSalt, statement);
  return constantTimeEqual(computed, expectedHash);
}

/**
 * Verify the index root against the published statement hashes.
 *
 * @param statementHashes - All raw 32-byte statement hashes
 * @param expectedRoot - Expected index root ("sha256:<hex>")
 */
export async function verifyIndexRoot(
  statementHashes: Uint8Array[],
  expectedRoot: string,
): Promise<boolean> {
  const totalBytes = statementHashes.length * 32;
  const rawDigests = new Uint8Array(totalBytes);
  for (let i = 0; i < statementHashes.length; i++) {
    rawDigests.set(statementHashes[i], i * 32);
  }
  const rootDigest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", rawDigests),
  );
  const computedRoot = "sha256:" + bytesToHex(rootDigest);
  return computedRoot === expectedRoot;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256(concat(rawSaltBytes, UTF-8(statement))).
 * Byte-level concatenation per §8.4.2.
 */
async function computeSaltedHash(
  salt: Uint8Array,
  statement: string,
): Promise<Uint8Array> {
  const stmtBytes = new TextEncoder().encode(statement);
  const input = new Uint8Array(salt.length + stmtBytes.length);
  input.set(salt, 0);
  input.set(stmtBytes, salt.length);
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
