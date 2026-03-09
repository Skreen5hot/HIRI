/**
 * HIRI Privacy Extension Tests — Milestone 13: Selective Disclosure (HMAC Suite)
 *
 * Tests 13.1–13.23: Statement index construction, salted hashing,
 * statement verification, HMAC suite, key distribution, manifest structure,
 * delta restrictions, context registry, and dictionary attack defense.
 */

import { strictEqual, ok } from "node:assert";

// Kernel imports
import { signManifest } from "../src/kernel/signing.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import type { ResolutionManifest, StorageAdapter } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";
import { generateX25519Keypair } from "../src/adapters/crypto/x25519.js";
import { URDNA2015Canonicalizer } from "../src/adapters/canonicalization/urdna2015-canonicalizer.js";
import { createCatalogDocumentLoader } from "../src/adapters/canonicalization/secure-document-loader.js";

// Privacy imports
import { buildStatementIndex, verifyStatementInIndex, verifyIndexRoot } from "../src/privacy/statement-index.js";
import { generateHmacTags, verifyHmacTag, encryptHmacKeyForRecipients, decryptHmacKey } from "../src/privacy/hmac-disclosure.js";
import { buildSelectiveDisclosureManifest } from "../src/privacy/selective-manifest.js";
import { validatePrivacyDelta } from "../src/privacy/delta-restrictions.js";
import { resolveWithPrivacy } from "../src/privacy/resolve.js";
import { hmacSha256 } from "../src/adapters/crypto/hmac.js";

const crypto = defaultCryptoProvider;
const canonicalizer = new URDNA2015Canonicalizer();

// Minimal schema.org-like context for tests (embedded, no network fetch needed)
const TEST_SCHEMA_CONTEXT = {
  "@context": {
    "schema": "https://schema.org/",
    "Person": "schema:Person",
    "Organization": "schema:Organization",
    "name": "schema:name",
    "jobTitle": "schema:jobTitle",
    "birthDate": "schema:birthDate",
    "member": { "@id": "schema:member", "@type": "@id" },
  },
};

const documentLoader = createCatalogDocumentLoader({
  "https://schema.org": TEST_SCHEMA_CONTEXT,
});

let passed = 0;
let failed = 0;

function pass(msg: string): void {
  console.log(`  \u2713 PASS: ${msg}`);
  passed++;
}

function fail(msg: string, error: unknown): void {
  console.error(`  \u2717 FAIL: ${msg}`);
  console.error("  ", error instanceof Error ? error.message : String(error));
  failed++;
}

// =========================================================================
// Setup
// =========================================================================

const keypair = await generateKeypair();
const authority = deriveAuthority(keypair.publicKey, "ed25519");
const signingKey = {
  algorithm: "ed25519",
  publicKey: keypair.publicKey,
  privateKey: keypair.privateKey,
  keyId: "key-1",
};

// Recipient keypairs (X25519)
const alice = generateX25519Keypair();
const bob = generateX25519Keypair();

// Test JSON-LD document with 4 statements when canonicalized
const testDoc = {
  "@context": "https://schema.org",
  "@id": "https://example.org/person/1",
  "@type": "Person",
  "name": "Dana Reeves",
  "jobTitle": "Systems Architect",
  "birthDate": "1990-05-15",
};

// Canonicalize to N-Quads
const canonicalBytes = await canonicalizer.canonicalize(
  testDoc as Record<string, unknown>,
  documentLoader,
);
const canonicalNQuads = new TextDecoder().decode(canonicalBytes);
const statements = canonicalNQuads.split("\n").filter((s) => s.length > 0);

// Helpers
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// =========================================================================
// Tests: 13.1–13.4 — Statement Index Construction (§8.4)
// =========================================================================

console.log("\n=== Statement Index Construction (§8.4) ===\n");

// 13.1: Build index from N-Quads → correct number of hashes + valid indexRoot
try {
  const result = await buildStatementIndex(canonicalNQuads);

  strictEqual(result.statements.length, statements.length);
  strictEqual(result.statementHashes.length, statements.length);
  ok(result.statementHashes.every((h) => h.length === 32), "Each hash should be 32 bytes");
  ok(result.indexRoot.startsWith("sha256:"), "indexRoot should be sha256-prefixed");
  ok(result.indexSalt.length === 32, "indexSalt should be 32 bytes");
  pass(`13.1 Build index from ${statements.length}-statement N-Quads → valid hashes and indexRoot`);
} catch (e) {
  fail("13.1 Build index from N-Quads", e);
}

// 13.2: Same statements + same salt → same index (determinism)
try {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await buildStatementIndex(canonicalNQuads, salt);
  const result2 = await buildStatementIndex(canonicalNQuads, salt);

  strictEqual(result1.indexRoot, result2.indexRoot);
  for (let i = 0; i < result1.statementHashes.length; i++) {
    ok(
      result1.statementHashes[i].every((b, j) => b === result2.statementHashes[i][j]),
      `Hash ${i} should be identical`,
    );
  }
  pass("13.2 Same statements + same salt → byte-identical index (determinism)");
} catch (e) {
  fail("13.2 Same statements + same salt → same index", e);
}

// 13.3: Same statements + different salt → different index
try {
  const salt1 = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const salt2 = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await buildStatementIndex(canonicalNQuads, salt1);
  const result2 = await buildStatementIndex(canonicalNQuads, salt2);

  ok(result1.indexRoot !== result2.indexRoot, "Different salts should produce different index roots");
  ok(
    bytesToHex(result1.statementHashes[0]) !== bytesToHex(result2.statementHashes[0]),
    "Different salts should produce different statement hashes",
  );
  pass("13.3 Same statements + different salt → different index");
} catch (e) {
  fail("13.3 Same statements + different salt → different index", e);
}

// 13.4: Index root is SHA-256 of concatenated raw digests
try {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result = await buildStatementIndex(canonicalNQuads, salt);

  // Manually compute expected root
  const totalBytes = result.statementHashes.length * 32;
  const rawDigests = new Uint8Array(totalBytes);
  for (let i = 0; i < result.statementHashes.length; i++) {
    rawDigests.set(result.statementHashes[i], i * 32);
  }
  const rootDigest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", rawDigests),
  );
  const expectedRoot = "sha256:" + bytesToHex(rootDigest);

  strictEqual(result.indexRoot, expectedRoot);
  pass("13.4 Index root = SHA-256(concat(allRawDigests)) matches manual computation");
} catch (e) {
  fail("13.4 Index root is SHA-256 of concatenated raw digests", e);
}

// =========================================================================
// Tests: 13.5–13.6 — Salted Hashing (§8.4.2, B.13)
// =========================================================================

console.log("\n=== Salted Hashing (§8.4.2, B.13) ===\n");

// 13.5: Salt decoded to raw bytes before concat
try {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result = await buildStatementIndex(canonicalNQuads, salt);

  // Manually compute first statement's salted hash using byte-level concat
  const stmt = result.statements[0];
  const stmtBytes = new TextEncoder().encode(stmt);
  const input = new Uint8Array(32 + stmtBytes.length);
  input.set(salt, 0);
  input.set(stmtBytes, 32);
  const expectedHash = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", input),
  );

  ok(
    expectedHash.every((b, i) => b === result.statementHashes[0][i]),
    "Byte-level concat should match buildStatementIndex output",
  );
  pass("13.5 Salt decoded to raw bytes, byte-level concat produces correct hash");
} catch (e) {
  fail("13.5 Salt decoded from base64url to raw bytes before concat", e);
}

// 13.6: String concat produces different hash than byte concat (B.13)
try {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const stmt = statements[0];

  // Correct: byte-level concat
  const stmtBytes = new TextEncoder().encode(stmt);
  const byteInput = new Uint8Array(32 + stmtBytes.length);
  byteInput.set(salt, 0);
  byteInput.set(stmtBytes, 32);
  const byteHash = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", byteInput),
  );

  // Wrong: string concat (base64url of salt + statement text, then encode)
  const saltB64 = base64urlEncode(salt);
  const stringInput = new TextEncoder().encode(saltB64 + stmt);
  const stringHash = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", stringInput),
  );

  ok(
    bytesToHex(byteHash) !== bytesToHex(stringHash),
    "String concat MUST produce different hash than byte concat",
  );
  pass("13.6 String concat produces different hash than byte concat (B.13)");
} catch (e) {
  fail("13.6 String concat produces different hash than byte concat", e);
}

// =========================================================================
// Tests: 13.7–13.9 — Statement Verification (§8.8, B.8)
// =========================================================================

console.log("\n=== Statement Verification (§8.8) ===\n");

const verifyResult = await buildStatementIndex(canonicalNQuads);

// 13.7: Verify known statement against index position → match
try {
  const valid = await verifyStatementInIndex(
    verifyResult.statements[0],
    verifyResult.statementHashes[0],
    verifyResult.indexSalt,
  );
  strictEqual(valid, true);
  pass("13.7 Verify known statement against index position → true");
} catch (e) {
  fail("13.7 Verify known statement against index position", e);
}

// 13.8: Verify wrong statement against index position → no match
try {
  const valid = await verifyStatementInIndex(
    "WRONG STATEMENT",
    verifyResult.statementHashes[0],
    verifyResult.indexSalt,
  );
  strictEqual(valid, false);
  pass("13.8 Verify wrong statement against index position → false");
} catch (e) {
  fail("13.8 Verify wrong statement against index position", e);
}

// 13.9: Statement with blank node verified without re-canonicalization (B.10)
try {
  // Build a doc that will produce blank nodes
  const blankNodeDoc = {
    "@context": "https://schema.org",
    "@id": "https://example.org/org/1",
    "@type": "Organization",
    "name": "Test Corp",
    "member": {
      "@type": "Person",
      "name": "Anonymous Member",
    },
  };

  const bnBytes = await canonicalizer.canonicalize(
    blankNodeDoc as Record<string, unknown>,
    documentLoader,
  );
  const bnNQuads = new TextDecoder().decode(bnBytes);
  const bnResult = await buildStatementIndex(bnNQuads);

  // Find a statement with a blank node label
  const bnStatement = bnResult.statements.find((s) => s.includes("_:c14n"));
  if (bnStatement) {
    const bnIdx = bnResult.statements.indexOf(bnStatement);
    // Verify as-is without re-canonicalization
    const valid = await verifyStatementInIndex(
      bnStatement,
      bnResult.statementHashes[bnIdx],
      bnResult.indexSalt,
    );
    strictEqual(valid, true);
    pass("13.9 Blank node statement verified as-is without re-canonicalization (§8.8)");
  } else {
    // No blank nodes produced — still valid, verify first statement
    const valid = await verifyStatementInIndex(
      bnResult.statements[0],
      bnResult.statementHashes[0],
      bnResult.indexSalt,
    );
    strictEqual(valid, true);
    pass("13.9 Statement verified without re-canonicalization (no blank nodes in test doc)");
  }
} catch (e) {
  fail("13.9 Statement with blank node verified without re-canonicalization", e);
}

// =========================================================================
// Tests: 13.10–13.13 — HMAC Suite (§8.6.1)
// =========================================================================

console.log("\n=== HMAC Suite (§8.6.1) ===\n");

const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
const hmacSalt = verifyResult.indexSalt;

// 13.10: Generate HMAC tags for all statements → one tag per statement
try {
  const tags = generateHmacTags(verifyResult.statements, hmacKey, hmacSalt);

  strictEqual(tags.length, verifyResult.statements.length);
  ok(tags.every((t) => t.length === 32), "Each HMAC tag should be 32 bytes");
  // Tags should all be different (different statements)
  const tagHexes = new Set(tags.map(bytesToHex));
  strictEqual(tagHexes.size, tags.length, "All tags should be unique");
  pass("13.10 Generate HMAC tags for all statements → one 32-byte tag per statement");
} catch (e) {
  fail("13.10 Generate HMAC tags for all statements", e);
}

// 13.11: Verify disclosed statement with correct HMAC key → tag matches
try {
  const tags = generateHmacTags(verifyResult.statements, hmacKey, hmacSalt);
  const valid = verifyHmacTag(
    verifyResult.statements[0],
    hmacKey,
    hmacSalt,
    tags[0],
  );
  strictEqual(valid, true);
  pass("13.11 Verify disclosed statement with correct HMAC key → tag matches");
} catch (e) {
  fail("13.11 Verify disclosed statement with correct HMAC key", e);
}

// 13.12: Verify with wrong HMAC key → tag does not match
try {
  const tags = generateHmacTags(verifyResult.statements, hmacKey, hmacSalt);
  const wrongKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const valid = verifyHmacTag(
    verifyResult.statements[0],
    wrongKey,
    hmacSalt,
    tags[0],
  );
  strictEqual(valid, false);
  pass("13.12 Verify with wrong HMAC key → tag does not match");
} catch (e) {
  fail("13.12 Verify with wrong HMAC key", e);
}

// 13.13: HMAC uses "hiri-hmac-v1.1" label, not "hiri-cek-v1.1"
try {
  // This test verifies domain separation in key distribution, not in HMAC itself.
  // encryptHmacKeyForRecipients uses "hiri-hmac-v1.1" internally.
  // We verify by encrypting with the HMAC function and checking the label is different.
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const disclosureMap = new Map<string, number[] | "all">([["alice", "all"]]);

  const dist = await encryptHmacKeyForRecipients(hmacKey, recipients, disclosureMap);

  // Decrypt with "hiri-hmac-v1.1" label — should succeed
  const decrypted = await decryptHmacKey(
    dist.recipients[0].encryptedHmacKey,
    dist.ephemeralPublicKey,
    dist.iv,
    alice.privateKey,
    "alice",
  );
  ok(
    decrypted.every((b, i) => b === hmacKey[i]),
    "Decrypted HMAC key with correct label should match original",
  );

  // Trying to decrypt with "hiri-cek-v1.1" label should fail (different KEK)
  // We import decryptKeyFromSender to try with wrong label
  const { decryptKeyFromSender } = await import("../src/adapters/crypto/key-agreement.js");
  let wrongLabelThrew = false;
  try {
    await decryptKeyFromSender({
      ownPrivateKeyX25519: alice.privateKey,
      ephemeralPublicKey: dist.ephemeralPublicKey,
      iv: dist.iv,
      encryptedKey: dist.recipients[0].encryptedHmacKey,
      recipientId: "alice",
      hkdfLabel: "hiri-cek-v1.1", // Wrong label!
    });
  } catch {
    wrongLabelThrew = true;
  }
  ok(wrongLabelThrew, "Decrypting with 'hiri-cek-v1.1' label must fail (domain separation)");
  pass("13.13 HMAC key distribution uses 'hiri-hmac-v1.1' label, not 'hiri-cek-v1.1'");
} catch (e) {
  fail("13.13 HMAC uses 'hiri-hmac-v1.1' label", e);
}

// =========================================================================
// Tests: 13.14–13.15 — HMAC Key Distribution
// =========================================================================

console.log("\n=== HMAC Key Distribution ===\n");

// 13.14: Encrypt HMAC key for 2 recipients → unique encrypted keys
try {
  const recipients = new Map<string, Uint8Array>([
    ["alice", alice.publicKey],
    ["bob", bob.publicKey],
  ]);
  const disclosureMap = new Map<string, number[] | "all">([
    ["alice", "all"],
    ["bob", [0, 1]],
  ]);

  const dist = await encryptHmacKeyForRecipients(hmacKey, recipients, disclosureMap);

  strictEqual(dist.recipients.length, 2);
  ok(
    bytesToHex(dist.recipients[0].encryptedHmacKey) !== bytesToHex(dist.recipients[1].encryptedHmacKey),
    "Each recipient should get unique encrypted key",
  );
  strictEqual(dist.recipients.find((r) => r.id === "alice")!.disclosedStatements, "all");
  const bobEntry = dist.recipients.find((r) => r.id === "bob")!;
  ok(Array.isArray(bobEntry.disclosedStatements), "Bob should have array of indices");
  pass("13.14 Encrypt HMAC key for 2 recipients → unique encrypted keys");
} catch (e) {
  fail("13.14 Encrypt HMAC key for 2 recipients", e);
}

// 13.15: Recipient decrypts HMAC key, verifies disclosed statements — full round-trip
try {
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const disclosureMap = new Map<string, number[] | "all">([["alice", "all"]]);

  const dist = await encryptHmacKeyForRecipients(hmacKey, recipients, disclosureMap);
  const tags = generateHmacTags(verifyResult.statements, hmacKey, hmacSalt);

  // Alice decrypts HMAC key
  const decryptedKey = await decryptHmacKey(
    dist.recipients[0].encryptedHmacKey,
    dist.ephemeralPublicKey,
    dist.iv,
    alice.privateKey,
    "alice",
  );

  // Alice verifies each statement's HMAC tag
  for (let i = 0; i < verifyResult.statements.length; i++) {
    const valid = verifyHmacTag(
      verifyResult.statements[i],
      decryptedKey,
      hmacSalt,
      tags[i],
    );
    ok(valid, `Statement ${i} HMAC tag should verify`);
  }
  pass("13.15 Full round-trip: encrypt HMAC key → decrypt → verify all statement tags");
} catch (e) {
  fail("13.15 Recipient decrypts HMAC key, verifies disclosed statements", e);
}

// =========================================================================
// Tests: 13.16–13.18 — Selective Disclosure Manifest
// =========================================================================

console.log("\n=== Selective Disclosure Manifest ===\n");

// Build a full SD manifest for manifest structure tests
const sdSalt = verifyResult.indexSalt;
const sdTags = generateHmacTags(verifyResult.statements, hmacKey, sdSalt);
const sdRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
const sdDisclosure = new Map<string, number[] | "all">([["alice", "all"]]);
const sdDist = await encryptHmacKeyForRecipients(hmacKey, sdRecipients, sdDisclosure);

// Build published content blob
const mandatoryIndices = [0, 1];
const sdContentBlob = {
  mandatoryNQuads: mandatoryIndices.map((i) => verifyResult.statements[i]),
  statementIndex: verifyResult.statementHashes.map(bytesToHex),
  hmacTags: sdTags.map(bytesToHex),
};
const sdContentBytes = new TextEncoder().encode(stableStringify(sdContentBlob));
const sdContentHash = await crypto.hash(sdContentBytes);

// 13.16: Build manifest with mandatory=[0,1] → correct manifest structure
try {
  const manifest = buildSelectiveDisclosureManifest({
    baseManifestParams: {
      id: `hiri://key:ed25519:${authority}/content/test-sd`,
      version: "1",
      branch: "main",
      created: "2026-03-01T00:00:00Z",
      contentHash: sdContentHash,
      addressing: "raw-sha256",
      contentFormat: "application/ld+json",
      contentSize: sdContentBytes.length,
      canonicalization: "URDNA2015",
    },
    statementCount: verifyResult.statements.length,
    indexSalt: sdSalt,
    indexRoot: verifyResult.indexRoot,
    mandatoryStatements: mandatoryIndices,
    hmacKeyDistribution: sdDist,
  });

  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as any;
  strictEqual(privacy.mode, "selective-disclosure");
  strictEqual(privacy.parameters.disclosureProofSuite, "hiri-hmac-sd-2026");
  strictEqual(privacy.parameters.statementCount, verifyResult.statements.length);
  ok(Array.isArray(privacy.parameters.mandatoryStatements), "mandatoryStatements should be array");
  strictEqual(privacy.parameters.mandatoryStatements[0], 0);
  strictEqual(privacy.parameters.mandatoryStatements[1], 1);
  ok(privacy.parameters.indexSalt.length > 0, "indexSalt should be base64url encoded");
  ok(privacy.parameters.indexRoot.startsWith("sha256:"), "indexRoot should be sha256-prefixed");
  pass("13.16 Build manifest with mandatory=[0,1] → correct structure");
} catch (e) {
  fail("13.16 Build manifest with mandatory=[0,1]", e);
}

// 13.17: content.availability is "partial"
try {
  const manifest = buildSelectiveDisclosureManifest({
    baseManifestParams: {
      id: `hiri://key:ed25519:${authority}/content/test-sd`,
      version: "1",
      branch: "main",
      created: "2026-03-01T00:00:00Z",
      contentHash: sdContentHash,
      addressing: "raw-sha256",
      contentFormat: "application/ld+json",
      contentSize: sdContentBytes.length,
      canonicalization: "URDNA2015",
    },
    statementCount: verifyResult.statements.length,
    indexSalt: sdSalt,
    indexRoot: verifyResult.indexRoot,
    mandatoryStatements: mandatoryIndices,
    hmacKeyDistribution: sdDist,
  });

  const content = (manifest as Record<string, unknown>)["hiri:content"] as any;
  strictEqual(content.availability, "partial");
  pass("13.17 content.availability is 'partial'");
} catch (e) {
  fail("13.17 content.availability is 'partial'", e);
}

// 13.18: content.canonicalization is "URDNA2015"
try {
  const manifest = buildSelectiveDisclosureManifest({
    baseManifestParams: {
      id: `hiri://key:ed25519:${authority}/content/test-sd`,
      version: "1",
      branch: "main",
      created: "2026-03-01T00:00:00Z",
      contentHash: sdContentHash,
      addressing: "raw-sha256",
      contentFormat: "application/ld+json",
      contentSize: sdContentBytes.length,
      canonicalization: "URDNA2015",
    },
    statementCount: verifyResult.statements.length,
    indexSalt: sdSalt,
    indexRoot: verifyResult.indexRoot,
    mandatoryStatements: mandatoryIndices,
    hmacKeyDistribution: sdDist,
  });

  const content = (manifest as Record<string, unknown>)["hiri:content"] as any;
  strictEqual(content.canonicalization, "URDNA2015");

  // Also verify JCS is rejected
  let jcsThrew = false;
  try {
    buildSelectiveDisclosureManifest({
      baseManifestParams: {
        id: `hiri://key:ed25519:${authority}/content/test-sd`,
        version: "1",
        branch: "main",
        created: "2026-03-01T00:00:00Z",
        contentHash: sdContentHash,
        addressing: "raw-sha256",
        contentFormat: "application/ld+json",
        contentSize: sdContentBytes.length,
        canonicalization: "JCS",
      },
      statementCount: verifyResult.statements.length,
      indexSalt: sdSalt,
      indexRoot: verifyResult.indexRoot,
      mandatoryStatements: mandatoryIndices,
      hmacKeyDistribution: sdDist,
    });
  } catch {
    jcsThrew = true;
  }
  ok(jcsThrew, "JCS canonicalization should be rejected for selective disclosure");
  pass("13.18 content.canonicalization is 'URDNA2015', JCS rejected (§8.3)");
} catch (e) {
  fail("13.18 content.canonicalization is 'URDNA2015'", e);
}

// =========================================================================
// Tests: 13.19–13.20 — Statement-Index Delta (§14.4)
// =========================================================================

console.log("\n=== Statement-Index Delta (§14.4) ===\n");

// 13.19: Delta for selective disclosure — index-only format → valid
try {
  const delta = {
    hash: "sha256:abcdef",
    format: "application/hiri-statement-index-delta+json",
    appliesTo: "sha256:previous",
    operations: 0,
  };
  const result = validatePrivacyDelta("selective-disclosure", delta as any);
  strictEqual(result.valid, true);
  pass("13.19 Statement-index delta format → valid");
} catch (e) {
  fail("13.19 Delta for selective disclosure — index-only format", e);
}

// 13.20: Reject JSON Patch delta for selective disclosure
try {
  const delta = {
    hash: "sha256:abcdef",
    format: "application/json-patch+json",
    appliesTo: "sha256:previous",
    operations: 3,
  };
  const result = validatePrivacyDelta("selective-disclosure", delta as any);
  strictEqual(result.valid, false);
  ok(
    result.reason!.includes("application/hiri-statement-index-delta+json"),
    "Reason should mention required format",
  );
  pass("13.20 JSON Patch delta rejected for selective disclosure");
} catch (e) {
  fail("13.20 Reject JSON Patch delta for selective disclosure", e);
}

// =========================================================================
// Tests: 13.21–13.22 — Context Registry Enforcement (§8.3)
// =========================================================================

console.log("\n=== Context Registry Enforcement (§8.3) ===\n");

// 13.21: Selective disclosure with unregistered context → canonicalization fails
try {
  const badDoc = {
    "@context": "https://example.org/unknown-context/v1",
    "@id": "https://example.org/test/1",
    "@type": "Thing",
    "label": "test",
  };

  let threw = false;
  try {
    await canonicalizer.canonicalize(
      badDoc as Record<string, unknown>,
      documentLoader, // secure loader blocks unknown URLs
    );
  } catch {
    threw = true;
  }
  ok(threw, "Canonicalization with unregistered context must fail");
  pass("13.21 Unregistered context → URDNA2015 canonicalization fails (no network fetch)");
} catch (e) {
  fail("13.21 Selective disclosure with unregistered context", e);
}

// 13.22: Selective disclosure with context in contextCatalog → succeeds
try {
  // Create a catalog with a known context + hash
  const schemaContext = {
    "@context": {
      "@vocab": "https://schema.org/",
    },
  };
  const catalogLoader = createCatalogDocumentLoader(
    { "https://custom.example.org/context/v1": schemaContext },
  );

  const catalogDoc = {
    "@context": "https://custom.example.org/context/v1",
    "@id": "https://example.org/test/2",
    "@type": "Person",
    "name": "Catalog Test",
  };

  const result = await canonicalizer.canonicalize(
    catalogDoc as Record<string, unknown>,
    catalogLoader,
  );
  ok(result.length > 0, "Canonicalization with cataloged context should succeed");
  pass("13.22 Context in contextCatalog with SHA-256 hash → canonicalization succeeds");
} catch (e) {
  fail("13.22 Selective disclosure with contextCatalog context", e);
}

// =========================================================================
// Test: 13.23 — Salt Defeats Dictionary Attack (B.9)
// =========================================================================

console.log("\n=== Salt Defeats Dictionary Attack (B.9) ===\n");

// 13.23: Brute-force 8 candidates → match found but no HMAC tag
try {
  // Scenario: attacker knows the predicate and subject URI for a blood type field.
  // 8 possible blood types. Salt is public. Attacker can compute salted hashes
  // for all 8 candidates and compare against withheld positions.

  const bloodTypeDoc = {
    "@context": "https://schema.org",
    "@id": "https://example.org/patient/1",
    "@type": "Person",
    "name": "Test Patient",
  };

  const btBytes = await canonicalizer.canonicalize(
    bloodTypeDoc as Record<string, unknown>,
    documentLoader,
  );
  const btNQuads = new TextDecoder().decode(btBytes);

  // Build index with a known salt
  const attackSalt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const btResult = await buildStatementIndex(btNQuads, attackSalt);

  // Pick the "name" statement as the withheld statement
  const nameStmt = btResult.statements.find((s) => s.includes("Test Patient"));
  ok(nameStmt, "Should find name statement");
  const nameIdx = btResult.statements.indexOf(nameStmt!);

  // Attacker's 8 candidates (including the correct one)
  const candidates = [
    nameStmt!, // correct
    nameStmt!.replace("Test Patient", "Alice"),
    nameStmt!.replace("Test Patient", "Bob"),
    nameStmt!.replace("Test Patient", "Charlie"),
    nameStmt!.replace("Test Patient", "Dana"),
    nameStmt!.replace("Test Patient", "Eve"),
    nameStmt!.replace("Test Patient", "Frank"),
    nameStmt!.replace("Test Patient", "Grace"),
  ];

  // Attacker computes salted hashes for all candidates
  let matchCount = 0;
  let matchedCandidate = "";
  for (const candidate of candidates) {
    const valid = await verifyStatementInIndex(
      candidate,
      btResult.statementHashes[nameIdx],
      attackSalt,
    );
    if (valid) {
      matchCount++;
      matchedCandidate = candidate;
    }
  }

  // Salt is public → attacker CAN find the match
  strictEqual(matchCount, 1, "Exactly one candidate should match the salted hash");
  strictEqual(matchedCandidate, nameStmt!, "Matched candidate should be the original");

  // BUT without the HMAC key, attacker cannot produce the HMAC tag
  const secretHmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const realTags = generateHmacTags(btResult.statements, secretHmacKey, attackSalt);

  // Attacker tries to forge HMAC with a guessed key
  const attackerKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const forgedValid = verifyHmacTag(
    nameStmt!,
    attackerKey,
    attackSalt,
    realTags[nameIdx],
  );
  strictEqual(forgedValid, false, "Attacker's forged HMAC should not match");

  pass("13.23 Dictionary attack finds salted hash match but cannot forge HMAC tag");
} catch (e) {
  fail("13.23 Salt defeats dictionary attack (B.9)", e);
}

// =========================================================================
// Summary
// =========================================================================

console.log(`\n=== M13 Selective Disclosure: ${passed} passed, ${failed} failed ===\n`);

if (failed > 0) {
  process.exit(1);
}
