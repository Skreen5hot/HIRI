/**
 * HIRI Privacy Extension Tests — Milestone 12: Privacy Level 2
 *
 * Tests 12.1–12.23: Encryption pipeline, decryption pipeline,
 * dual content hashes, manifest structure, encrypted resolution,
 * opaque delta validation, key agreement identifiers, and recipient management.
 */

import { strictEqual, ok } from "node:assert";

// Kernel imports
import { buildUnsignedManifest } from "../src/kernel/manifest.js";
import { signManifest } from "../src/kernel/signing.js";
import { hashManifest } from "../src/kernel/chain.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import type { ResolutionManifest, StorageAdapter } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";
import { generateX25519Keypair } from "../src/adapters/crypto/x25519.js";
import { ed25519PrivateToX25519 } from "../src/adapters/crypto/key-conversion.js";
import { aesGcmEncrypt } from "../src/adapters/crypto/aes-gcm.js";
import { encryptKeyForRecipient } from "../src/adapters/crypto/key-agreement.js";

// Privacy imports
import { encryptContent } from "../src/privacy/encryption.js";
import type { EncryptionResult } from "../src/privacy/encryption.js";
import { decryptContent } from "../src/privacy/decryption.js";
import { buildEncryptedManifest } from "../src/privacy/encrypted-manifest.js";
import { validatePrivacyDelta, decryptAndParseOpaqueDelta } from "../src/privacy/delta-restrictions.js";
import { resolveWithPrivacy } from "../src/privacy/resolve.js";
import { getLogicalPlaintextHash } from "../src/privacy/plaintext-hash.js";
import type { EncryptedPrivacyParams } from "../src/privacy/types.js";

const crypto = defaultCryptoProvider;

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
const baseUri = `hiri://key:ed25519:${authority}/content/test-encrypted`;

// Recipient keypairs (X25519)
const alice = generateX25519Keypair();
const bob = generateX25519Keypair();
const charlie = generateX25519Keypair();

// Test content
const plaintext = new TextEncoder().encode('{"@context":"https://schema.org","@type":"Article","name":"Secret Report"}');

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

/** Build an encrypted manifest with signing. */
async function buildSignedEncryptedManifest(
  encResult: EncryptionResult,
  version = "1",
  chain?: { previous: string; genesisHash: string; depth: number },
  delta?: Record<string, unknown>,
): Promise<ResolutionManifest> {
  const unsigned = buildEncryptedManifest({
    baseManifestParams: {
      id: baseUri,
      version,
      branch: "main",
      created: "2026-03-01T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
      ...(chain ? { chain: { ...chain, previousBranch: "main" } } : {}),
      ...(delta ? { delta: delta as any } : {}),
    },
    encryptionResult: encResult,
    plaintextFormat: "application/ld+json",
    plaintextSize: plaintext.length,
  });

  const ts = "2026-03-01T00:00:00Z";
  return signManifest(unsigned, signingKey, ts, "JCS", crypto);
}

/** Create in-memory storage. */
function createMemoryStorage(
  entries: Array<{ manifest: ResolutionManifest; content: Uint8Array }>,
): StorageAdapter {
  const store = new Map<string, Uint8Array>();
  const pending: Promise<void>[] = [];
  for (const entry of entries) {
    pending.push(
      (async () => {
        const manifestBytes = new TextEncoder().encode(stableStringify(entry.manifest));
        const manifestHash = await crypto.hash(manifestBytes);
        store.set(manifestHash, manifestBytes);
        const contentHash = entry.manifest["hiri:content"].hash;
        store.set(contentHash, entry.content);
      })(),
    );
  }
  return {
    get: async (hash: string) => {
      await Promise.all(pending);
      return store.get(hash) ?? null;
    },
    has: async (hash: string) => {
      await Promise.all(pending);
      return store.has(hash);
    },
  };
}

async function getManifestHash(manifest: ResolutionManifest): Promise<string> {
  const bytes = new TextEncoder().encode(stableStringify(manifest));
  return crypto.hash(bytes);
}

// =========================================================================
// Tests: 12.1–12.3 — Encryption Pipeline (§7.4)
// =========================================================================

console.log("\n=== Encryption Pipeline (§7.4) ===\n");

// 12.1: Encrypt known plaintext → ciphertext differs from plaintext
try {
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const result = await encryptContent(plaintext, recipients, crypto);

  ok(result.ciphertext.length > 0, "Ciphertext should be non-empty");
  // Ciphertext should differ from plaintext (includes GCM tag, so length differs too)
  ok(result.ciphertext.length !== plaintext.length || !plaintext.every((b, i) => b === result.ciphertext[i]),
    "Ciphertext must differ from plaintext");
  ok(result.iv.length === 12, "IV should be 12 bytes");
  ok(result.plaintextHash.startsWith("sha256:"), "plaintextHash should be sha256 prefixed");
  ok(result.ciphertextHash.startsWith("sha256:"), "ciphertextHash should be sha256 prefixed");
  ok(result.ephemeralPublicKey.length === 32, "Ephemeral public key should be 32 bytes");
  strictEqual(result.recipients.length, 1);
  strictEqual(result.recipients[0].id, "alice");
  pass("12.1 Encrypt known plaintext → ciphertext differs from plaintext");
} catch (e) {
  fail("12.1 Encrypt known plaintext → ciphertext differs from plaintext", e);
}

// 12.2: Same plaintext, different CEK → different ciphertext
try {
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const result1 = await encryptContent(plaintext, recipients, crypto);
  const result2 = await encryptContent(plaintext, recipients, crypto);

  // CEKs are random → ciphertexts should differ
  const ct1Hex = bytesToHex(result1.ciphertext);
  const ct2Hex = bytesToHex(result2.ciphertext);
  ok(ct1Hex !== ct2Hex, "Two encryptions of same plaintext should produce different ciphertext");

  // But plaintext hashes should match (same input)
  strictEqual(result1.plaintextHash, result2.plaintextHash);
  pass("12.2 Same plaintext, different CEK → different ciphertext (non-deterministic)");
} catch (e) {
  fail("12.2 Same plaintext, different CEK → different ciphertext", e);
}

// 12.3: Encrypt for 3 recipients → 3 encrypted key shares
try {
  const recipients = new Map<string, Uint8Array>([
    ["alice", alice.publicKey],
    ["bob", bob.publicKey],
    ["charlie", charlie.publicKey],
  ]);
  const result = await encryptContent(plaintext, recipients, crypto);

  strictEqual(result.recipients.length, 3);
  const ids = result.recipients.map((r) => r.id).sort();
  strictEqual(ids.join(","), "alice,bob,charlie");

  // Each encrypted key should be different (different ECDH shared secrets)
  const shares = result.recipients.map((r) => bytesToHex(r.encryptedKey));
  ok(shares[0] !== shares[1], "Alice and Bob shares should differ");
  ok(shares[1] !== shares[2], "Bob and Charlie shares should differ");
  ok(shares[0] !== shares[2], "Alice and Charlie shares should differ");
  pass("12.3 Encrypt for 3 recipients → 3 distinct encrypted key shares");
} catch (e) {
  fail("12.3 Encrypt for 3 recipients → 3 distinct encrypted key shares", e);
}

// =========================================================================
// Tests: 12.4–12.7 — Decryption Pipeline (§7.5)
// =========================================================================

console.log("\n=== Decryption Pipeline (§7.5) ===\n");

// Shared encryption result for decryption tests
const decryptRecipients = new Map<string, Uint8Array>([
  ["alice", alice.publicKey],
  ["bob", bob.publicKey],
]);
const encResult = await encryptContent(plaintext, decryptRecipients, crypto);

// Build EncryptedPrivacyParams from encryption result
const encParams: EncryptedPrivacyParams = {
  algorithm: "AES-256-GCM",
  keyAgreement: "X25519-HKDF-SHA256",
  iv: bytesToHex(encResult.iv),
  tagLength: 128,
  plaintextHash: encResult.plaintextHash,
  plaintextFormat: "application/ld+json",
  plaintextSize: plaintext.length,
  ephemeralPublicKey: bytesToHex(encResult.ephemeralPublicKey),
  recipients: encResult.recipients.map((r) => ({
    id: r.id,
    encryptedKey: bytesToHex(r.encryptedKey),
  })),
};

// 12.4: Authorized recipient decrypts successfully
try {
  const result = await decryptContent(
    encResult.ciphertext,
    encParams,
    alice.privateKey,
    "alice",
    crypto,
  );

  // Verify plaintext matches original
  strictEqual(result.plaintext.length, plaintext.length);
  ok(plaintext.every((b, i) => b === result.plaintext[i]), "Decrypted plaintext must match original");
  pass("12.4 Authorized recipient (alice) decrypts successfully → plaintext matches");
} catch (e) {
  fail("12.4 Authorized recipient decrypts successfully", e);
}

// 12.5: Plaintext hash verified after decryption
try {
  const result = await decryptContent(
    encResult.ciphertext,
    encParams,
    alice.privateKey,
    "alice",
    crypto,
  );

  strictEqual(result.plaintextHashValid, true);
  pass("12.5 Plaintext hash verified after decryption → plaintextHashValid: true");
} catch (e) {
  fail("12.5 Plaintext hash verified after decryption", e);
}

// 12.6: Wrong private key → decryption fails (GCM auth failure)
try {
  const wrongKey = generateX25519Keypair();
  let threw = false;
  try {
    await decryptContent(
      encResult.ciphertext,
      encParams,
      wrongKey.privateKey,
      "alice",
      crypto,
    );
  } catch {
    threw = true;
  }
  ok(threw, "Decryption with wrong private key must throw");
  pass("12.6 Wrong private key → GCM authentication failure");
} catch (e) {
  fail("12.6 Wrong private key → GCM authentication failure", e);
}

// 12.7: Wrong recipient ID → decryption fails (wrong KEK)
try {
  // alice's private key but claiming to be "bob" → HKDF derives wrong KEK
  let threw = false;
  try {
    await decryptContent(
      encResult.ciphertext,
      encParams,
      alice.privateKey,
      "bob",
      crypto,
    );
  } catch {
    threw = true;
  }
  ok(threw, "Decryption with wrong recipient ID must throw (wrong KEK from HKDF)");
  pass("12.7 Wrong recipient ID → wrong KEK → GCM authentication failure");
} catch (e) {
  fail("12.7 Wrong recipient ID → wrong KEK → GCM authentication failure", e);
}

// =========================================================================
// Tests: 12.8–12.10 — Dual Content Hashes (§7.6)
// =========================================================================

console.log("\n=== Dual Content Hashes (§7.6) ===\n");

const dualHashRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
const dualHashResult = await encryptContent(plaintext, dualHashRecipients, crypto);

// 12.8: Manifest contains both ciphertext hash and plaintext hash
try {
  const manifest = await buildSignedEncryptedManifest(dualHashResult);

  // Content hash in manifest is ciphertext hash
  strictEqual(manifest["hiri:content"].hash, dualHashResult.ciphertextHash);

  // Privacy block contains plaintext hash
  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as any;
  strictEqual(privacy.parameters.plaintextHash, dualHashResult.plaintextHash);

  // They should differ (ciphertext ≠ plaintext)
  ok(
    manifest["hiri:content"].hash !== privacy.parameters.plaintextHash,
    "Ciphertext hash and plaintext hash must differ",
  );
  pass("12.8 Manifest contains both ciphertext hash and plaintext hash in correct fields");
} catch (e) {
  fail("12.8 Manifest contains both ciphertext hash and plaintext hash", e);
}

// 12.9: Ciphertext hash verifiable without decryption key
try {
  const computedCiphertextHash = await crypto.hash(dualHashResult.ciphertext);
  strictEqual(computedCiphertextHash, dualHashResult.ciphertextHash);
  pass("12.9 Ciphertext hash verifiable without decryption key (public verification)");
} catch (e) {
  fail("12.9 Ciphertext hash verifiable without decryption key", e);
}

// 12.10: Plaintext hash verifiable after decryption
try {
  const dualParams: EncryptedPrivacyParams = {
    algorithm: "AES-256-GCM",
    keyAgreement: "X25519-HKDF-SHA256",
    iv: bytesToHex(dualHashResult.iv),
    tagLength: 128,
    plaintextHash: dualHashResult.plaintextHash,
    plaintextFormat: "application/ld+json",
    plaintextSize: plaintext.length,
    ephemeralPublicKey: bytesToHex(dualHashResult.ephemeralPublicKey),
    recipients: dualHashResult.recipients.map((r) => ({
      id: r.id,
      encryptedKey: bytesToHex(r.encryptedKey),
    })),
  };
  const decResult = await decryptContent(
    dualHashResult.ciphertext,
    dualParams,
    alice.privateKey,
    "alice",
    crypto,
  );
  strictEqual(decResult.plaintextHashValid, true);
  const computedPlaintextHash = await crypto.hash(decResult.plaintext);
  strictEqual(computedPlaintextHash, dualHashResult.plaintextHash);
  pass("12.10 Plaintext hash verifiable after decryption (private verification)");
} catch (e) {
  fail("12.10 Plaintext hash verifiable after decryption", e);
}

// =========================================================================
// Tests: 12.11–12.12 — Manifest Structure (§7.3)
// =========================================================================

console.log("\n=== Manifest Structure (§7.3) ===\n");

// 12.11: Encrypted manifest has format: "application/octet-stream"
try {
  const structRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const structResult = await encryptContent(plaintext, structRecipients, crypto);
  const manifest = await buildSignedEncryptedManifest(structResult);

  strictEqual(manifest["hiri:content"].format, "application/octet-stream");
  pass("12.11 Encrypted manifest has format: 'application/octet-stream'");
} catch (e) {
  fail("12.11 Encrypted manifest has format: 'application/octet-stream'", e);
}

// 12.12: Privacy block has correct parameters
try {
  const structRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const structResult = await encryptContent(plaintext, structRecipients, crypto);
  const manifest = await buildSignedEncryptedManifest(structResult);

  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as any;
  strictEqual(privacy.mode, "encrypted");
  strictEqual(privacy.parameters.algorithm, "AES-256-GCM");
  strictEqual(privacy.parameters.keyAgreement, "X25519-HKDF-SHA256");
  strictEqual(privacy.parameters.tagLength, 128);
  ok(typeof privacy.parameters.iv === "string" && privacy.parameters.iv.length === 24, "IV hex should be 24 chars (12 bytes)");
  ok(typeof privacy.parameters.ephemeralPublicKey === "string" && privacy.parameters.ephemeralPublicKey.length === 64, "Ephemeral key hex should be 64 chars (32 bytes)");
  ok(privacy.parameters.plaintextHash.startsWith("sha256:"), "plaintextHash should be sha256 prefixed");
  strictEqual(privacy.parameters.plaintextFormat, "application/ld+json");
  strictEqual(privacy.parameters.plaintextSize, plaintext.length);
  strictEqual(privacy.parameters.recipients.length, 1);
  strictEqual(privacy.parameters.recipients[0].id, "alice");
  ok(typeof privacy.parameters.recipients[0].encryptedKey === "string", "encryptedKey should be hex string");
  pass("12.12 Privacy block has correct parameters (algorithm, iv, tagLength, recipients, etc.)");
} catch (e) {
  fail("12.12 Privacy block has correct parameters", e);
}

// =========================================================================
// Tests: 12.13–12.15 — Resolution (§12)
// =========================================================================

console.log("\n=== Encrypted Resolution (§12) ===\n");

// 12.13: Resolve encrypted manifest without key → ciphertext-verified
try {
  const resRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const resResult = await encryptContent(plaintext, resRecipients, crypto);
  const manifest = await buildSignedEncryptedManifest(resResult);
  const storage = createMemoryStorage([{ manifest, content: resResult.ciphertext }]);
  const manifestHash = await getManifestHash(manifest);

  const resolution = await resolveWithPrivacy(baseUri, storage, {
    manifestHash,
    publicKey: keypair.publicKey,
    crypto,
  });

  strictEqual(resolution.verified, true);
  strictEqual(resolution.privacyMode, "encrypted");
  strictEqual(resolution.contentStatus, "ciphertext-verified");
  ok(!resolution.decryptedContent, "No decrypted content without key");
  pass("12.13 Resolve encrypted manifest without key → ciphertext-verified");
} catch (e) {
  fail("12.13 Resolve encrypted manifest without key → ciphertext-verified", e);
}

// 12.14: Resolve encrypted manifest with valid key → decrypted-verified
try {
  const resRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const resResult = await encryptContent(plaintext, resRecipients, crypto);
  const manifest = await buildSignedEncryptedManifest(resResult);
  const storage = createMemoryStorage([{ manifest, content: resResult.ciphertext }]);
  const manifestHash = await getManifestHash(manifest);

  const resolution = await resolveWithPrivacy(baseUri, storage, {
    manifestHash,
    publicKey: keypair.publicKey,
    crypto,
    decryptionKey: alice.privateKey,
    recipientId: "alice",
  });

  strictEqual(resolution.verified, true);
  strictEqual(resolution.privacyMode, "encrypted");
  strictEqual(resolution.contentStatus, "decrypted-verified");
  ok(resolution.decryptedContent, "Should have decrypted content");
  ok(
    plaintext.every((b, i) => b === resolution.decryptedContent![i]),
    "Decrypted content must match original plaintext",
  );
  pass("12.14 Resolve encrypted manifest with valid key → decrypted-verified");
} catch (e) {
  fail("12.14 Resolve encrypted manifest with valid key → decrypted-verified", e);
}

// 12.15: Resolve encrypted manifest with wrong key → decryption-failed, verified: true
try {
  const resRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const resResult = await encryptContent(plaintext, resRecipients, crypto);
  const manifest = await buildSignedEncryptedManifest(resResult);
  const storage = createMemoryStorage([{ manifest, content: resResult.ciphertext }]);
  const manifestHash = await getManifestHash(manifest);

  const wrongKey = generateX25519Keypair();
  const resolution = await resolveWithPrivacy(baseUri, storage, {
    manifestHash,
    publicKey: keypair.publicKey,
    crypto,
    decryptionKey: wrongKey.privateKey,
    recipientId: "alice",
  });

  // Manifest is verified (sig + chain passed), only decryption failed
  strictEqual(resolution.verified, true);
  strictEqual(resolution.privacyMode, "encrypted");
  strictEqual(resolution.contentStatus, "decryption-failed");
  ok(!resolution.decryptedContent, "No decrypted content on failure");
  ok(resolution.warnings.some((w) => w.includes("Decryption failed")), "Should have decryption failure warning");
  pass("12.15 Resolve with wrong key → verified: true, contentStatus: 'decryption-failed'");
} catch (e) {
  fail("12.15 Resolve with wrong key → verified: true, contentStatus: 'decryption-failed'", e);
}

// =========================================================================
// Tests: 12.16–12.19 — Opaque Delta (§14.3)
// =========================================================================

console.log("\n=== Opaque Delta (§14.3) ===\n");

// 12.16: Encrypted manifest with opaque delta — valid
try {
  const opaqueDelta = {
    hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    format: "application/octet-stream",
    operations: -1,
  };
  const result = validatePrivacyDelta("encrypted", opaqueDelta as any);
  strictEqual(result.valid, true);
  pass("12.16 Encrypted manifest with opaque delta → valid");
} catch (e) {
  fail("12.16 Encrypted manifest with opaque delta → valid", e);
}

// 12.17: Encrypted manifest with JSON Patch delta → rejected
try {
  const jsonPatchDelta = {
    hash: "sha256:abcdef",
    format: "application/json-patch+json",
    appliesTo: "sha256:previous",
    operations: 3,
  };
  const result = validatePrivacyDelta("encrypted", jsonPatchDelta as any);
  strictEqual(result.valid, false);
  ok(result.reason!.includes("application/octet-stream"), "Reason should mention required format");
  pass("12.17 Encrypted manifest with JSON Patch delta → rejected (wrong format)");
} catch (e) {
  fail("12.17 Encrypted manifest with JSON Patch delta → rejected", e);
}

// 12.18: Opaque delta with appliesTo in manifest-level metadata → rejected
try {
  const badDelta = {
    hash: "sha256:abcdef",
    format: "application/octet-stream",
    appliesTo: "sha256:previous-content-hash",
    operations: -1,
  };
  const result = validatePrivacyDelta("encrypted", badDelta as any);
  strictEqual(result.valid, false);
  ok(result.reason!.includes("appliesTo"), "Reason should mention appliesTo restriction");
  pass("12.18 Opaque delta with manifest-level appliesTo → rejected (§14.3)");
} catch (e) {
  fail("12.18 Opaque delta with manifest-level appliesTo → rejected", e);
}

// 12.19: Decrypt opaque delta blob, verify inner appliesTo matches previous plaintext hash
try {
  // Build v1 encrypted manifest
  const v1Recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const v1Enc = await encryptContent(plaintext, v1Recipients, crypto);
  const v1Manifest = await buildSignedEncryptedManifest(v1Enc, "1");
  const v1ManifestHash = await hashManifest(v1Manifest, crypto);

  // Get v1's logical plaintext hash
  const v1PlaintextHashResult = getLogicalPlaintextHash(v1Manifest);
  const v1PlaintextHash = v1PlaintextHashResult.hash;

  // Build inner delta blob with appliesTo referencing v1's plaintext hash
  const innerDelta = {
    appliesTo: v1PlaintextHash,
    operations: [{ op: "replace", path: "/name", value: "Updated Secret Report" }],
  };
  const innerDeltaBytes = new TextEncoder().encode(JSON.stringify(innerDelta));

  // Encrypt the delta blob using same ephemeral key pattern
  // We reuse the v2 encryption for the delta blob
  const v2Plaintext = new TextEncoder().encode('{"@context":"https://schema.org","@type":"Article","name":"Updated Secret Report"}');
  const v2Enc = await encryptContent(v2Plaintext, v1Recipients, crypto);

  // Encrypt the delta blob separately with v2's key agreement
  const deltaCek = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const deltaIv = v2Enc.iv; // Reuse IV for simplicity in test (in production, generate fresh)
  const deltaEphemeral = generateX25519Keypair();
  const encryptedDeltaBlob = await aesGcmEncrypt(deltaCek, deltaIv, innerDeltaBytes);

  // Encrypt delta CEK for alice
  const deltaEncryptedKey = await encryptKeyForRecipient({
    ephemeralPrivateKey: deltaEphemeral.privateKey,
    recipientPublicKeyX25519: alice.publicKey,
    iv: deltaIv,
    secretKey: deltaCek,
    recipientId: "alice",
    hkdfLabel: "hiri-cek-v1.1",
  });

  // Build delta params
  const deltaParams: EncryptedPrivacyParams = {
    algorithm: "AES-256-GCM",
    keyAgreement: "X25519-HKDF-SHA256",
    iv: bytesToHex(deltaIv),
    tagLength: 128,
    plaintextHash: await crypto.hash(innerDeltaBytes),
    plaintextFormat: "application/octet-stream",
    plaintextSize: innerDeltaBytes.length,
    ephemeralPublicKey: bytesToHex(deltaEphemeral.publicKey),
    recipients: [{ id: "alice", encryptedKey: bytesToHex(deltaEncryptedKey) }],
  };

  // Decrypt and parse the opaque delta
  const decryptedDelta = await decryptAndParseOpaqueDelta(
    encryptedDeltaBlob,
    deltaParams,
    alice.privateKey,
    "alice",
    crypto,
  );

  // Verify inner appliesTo matches v1's logical plaintext hash
  strictEqual(decryptedDelta.appliesTo, v1PlaintextHash);
  ok(Array.isArray(decryptedDelta.operations), "Inner operations should be an array");
  pass("12.19 Decrypt opaque delta blob → inner appliesTo matches previous logical plaintext hash");
} catch (e) {
  fail("12.19 Decrypt opaque delta blob → inner appliesTo matches previous logical plaintext hash", e);
}

// =========================================================================
// Tests: 12.20–12.21 — Key Agreement Identifiers (§13.2)
// =========================================================================

console.log("\n=== Key Agreement Identifiers (§13.2) ===\n");

// 12.20: Manifest with keyAgreement: "X25519-HKDF-SHA256" — accepted
try {
  const kaRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const kaResult = await encryptContent(plaintext, kaRecipients, crypto);
  const manifest = await buildSignedEncryptedManifest(kaResult);

  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as any;
  strictEqual(privacy.parameters.keyAgreement, "X25519-HKDF-SHA256");

  // Verify decryption works with this identifier
  const kaParams: EncryptedPrivacyParams = {
    ...privacy.parameters,
    recipients: privacy.parameters.recipients,
  };
  const decResult = await decryptContent(kaResult.ciphertext, kaParams, alice.privateKey, "alice", crypto);
  ok(decResult.plaintextHashValid, "Decryption with X25519-HKDF-SHA256 should work");
  pass("12.20 keyAgreement: 'X25519-HKDF-SHA256' → accepted, decryption succeeds");
} catch (e) {
  fail("12.20 keyAgreement: 'X25519-HKDF-SHA256' → accepted", e);
}

// 12.21: Manifest with keyAgreement: "HPKE-Base-X25519-SHA256-AES256GCM" — accepted
try {
  const hpkeRecipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const hpkeResult = await encryptContent(plaintext, hpkeRecipients, crypto);

  // Build manifest with HPKE identifier
  const manifest = buildEncryptedManifest({
    baseManifestParams: {
      id: baseUri,
      version: "1",
      branch: "main",
      created: "2026-03-01T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
    },
    encryptionResult: hpkeResult,
    plaintextFormat: "application/ld+json",
    plaintextSize: plaintext.length,
    keyAgreement: "HPKE-Base-X25519-SHA256-AES256GCM",
  });

  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as any;
  strictEqual(privacy.parameters.keyAgreement, "HPKE-Base-X25519-SHA256-AES256GCM");

  // Same HKDF derivation → decryption still works
  const hpkeParams: EncryptedPrivacyParams = {
    ...privacy.parameters,
    recipients: privacy.parameters.recipients,
  };
  const decResult = await decryptContent(hpkeResult.ciphertext, hpkeParams, alice.privateKey, "alice", crypto);
  ok(decResult.plaintextHashValid, "Decryption with HPKE identifier should work (same derivation)");
  pass("12.21 keyAgreement: 'HPKE-Base-X25519-SHA256-AES256GCM' → accepted (same derivation)");
} catch (e) {
  fail("12.21 keyAgreement: 'HPKE-Base-X25519-SHA256-AES256GCM' → accepted", e);
}

// =========================================================================
// Tests: 12.22–12.23 — Recipient Management (§7.8)
// =========================================================================

console.log("\n=== Recipient Management (§7.8) ===\n");

// 12.22: Add recipient → new version with new CEK
try {
  // v1: alice only
  const v1Recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const v1Result = await encryptContent(plaintext, v1Recipients, crypto);

  // v2: alice + bob (re-encrypt with new CEK)
  const v2Recipients = new Map<string, Uint8Array>([
    ["alice", alice.publicKey],
    ["bob", bob.publicKey],
  ]);
  const v2Result = await encryptContent(plaintext, v2Recipients, crypto);

  // New CEK → different ciphertext
  ok(
    bytesToHex(v1Result.ciphertext) !== bytesToHex(v2Result.ciphertext),
    "Adding recipient should produce new ciphertext (new CEK)",
  );

  // Both alice and bob can decrypt v2
  const v2Params: EncryptedPrivacyParams = {
    algorithm: "AES-256-GCM",
    keyAgreement: "X25519-HKDF-SHA256",
    iv: bytesToHex(v2Result.iv),
    tagLength: 128,
    plaintextHash: v2Result.plaintextHash,
    plaintextFormat: "application/ld+json",
    plaintextSize: plaintext.length,
    ephemeralPublicKey: bytesToHex(v2Result.ephemeralPublicKey),
    recipients: v2Result.recipients.map((r) => ({
      id: r.id,
      encryptedKey: bytesToHex(r.encryptedKey),
    })),
  };

  const aliceDec = await decryptContent(v2Result.ciphertext, v2Params, alice.privateKey, "alice", crypto);
  const bobDec = await decryptContent(v2Result.ciphertext, v2Params, bob.privateKey, "bob", crypto);
  ok(aliceDec.plaintextHashValid, "Alice can decrypt v2");
  ok(bobDec.plaintextHashValid, "Bob can decrypt v2");
  pass("12.22 Add recipient → new CEK, new ciphertext, both recipients can decrypt");
} catch (e) {
  fail("12.22 Add recipient → new version with new CEK", e);
}

// 12.23: Remove recipient → new version without that entry
try {
  // v1: alice + bob
  const v1Recipients = new Map<string, Uint8Array>([
    ["alice", alice.publicKey],
    ["bob", bob.publicKey],
  ]);
  const v1Result = await encryptContent(plaintext, v1Recipients, crypto);

  // v2: alice only (bob removed, re-encrypted with new CEK)
  const v2Recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const v2Result = await encryptContent(plaintext, v2Recipients, crypto);

  const v2Params: EncryptedPrivacyParams = {
    algorithm: "AES-256-GCM",
    keyAgreement: "X25519-HKDF-SHA256",
    iv: bytesToHex(v2Result.iv),
    tagLength: 128,
    plaintextHash: v2Result.plaintextHash,
    plaintextFormat: "application/ld+json",
    plaintextSize: plaintext.length,
    ephemeralPublicKey: bytesToHex(v2Result.ephemeralPublicKey),
    recipients: v2Result.recipients.map((r) => ({
      id: r.id,
      encryptedKey: bytesToHex(r.encryptedKey),
    })),
  };

  // Alice can decrypt v2
  const aliceDec = await decryptContent(v2Result.ciphertext, v2Params, alice.privateKey, "alice", crypto);
  ok(aliceDec.plaintextHashValid, "Alice can decrypt v2");

  // Bob cannot decrypt v2 — not in recipient list
  let bobThrew = false;
  try {
    await decryptContent(v2Result.ciphertext, v2Params, bob.privateKey, "bob", crypto);
  } catch (err) {
    bobThrew = true;
    ok(
      (err as Error).message.includes("Not an authorized recipient"),
      "Should throw 'not authorized' for removed recipient",
    );
  }
  ok(bobThrew, "Bob must be rejected from v2 (removed recipient)");
  pass("12.23 Remove recipient → removed recipient cannot decrypt new version");
} catch (e) {
  fail("12.23 Remove recipient → removed recipient cannot decrypt new version", e);
}

// =========================================================================
// Summary
// =========================================================================

console.log(`\n=== M12 Privacy Level 2: ${passed} passed, ${failed} failed ===\n`);

if (failed > 0) {
  process.exit(1);
}
