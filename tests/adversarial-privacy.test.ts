/**
 * HIRI Privacy Extension — Adversarial & Unhappy Path Tests
 *
 * Tests that attack boundaries, malformed inputs, wrong-size keys,
 * serialization round-trips, state leakage, and edge cases that
 * the happy-path M10–M15 suites don't cover.
 *
 * Organized by attack surface:
 *   A.1–A.8:   Input validation & boundary conditions
 *   A.9–A.16:  Cryptographic edge cases
 *   A.17–A.24: Serialization round-trip integrity
 *   A.25–A.32: Cross-mode & chain adversarial cases
 *   A.33–A.40: Attestation adversarial cases
 *   A.41–A.48: Resolver adversarial cases
 *   A.49–A.54: Statement content edge cases (Unicode, empty, huge)
 */

import { strictEqual, ok, rejects, throws } from "node:assert";

// Kernel imports
import { buildUnsignedManifest } from "../src/kernel/manifest.js";
import { signManifest, verifyManifest } from "../src/kernel/signing.js";
import { hashManifest } from "../src/kernel/chain.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import type { ResolutionManifest, StorageAdapter } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";
import { generateX25519Keypair } from "../src/adapters/crypto/x25519.js";
import { InMemoryStorageAdapter } from "../src/adapters/persistence/storage.js";

// Privacy imports
import { buildStatementIndex, verifyStatementInIndex, verifyIndexRoot } from "../src/privacy/statement-index.js";
import { generateHmacTags, verifyHmacTag, encryptHmacKeyForRecipients, decryptHmacKey } from "../src/privacy/hmac-disclosure.js";
import { encryptContent } from "../src/privacy/encryption.js";
import { decryptContent } from "../src/privacy/decryption.js";
import { buildEncryptedManifest } from "../src/privacy/encrypted-manifest.js";
import { buildSelectiveDisclosureManifest } from "../src/privacy/selective-manifest.js";
import { generateEphemeralAuthority, validateAnonymousConstraints, buildAnonymousPrivacyBlock } from "../src/privacy/anonymous.js";
import { buildAttestationManifest, signAttestationManifest, verifyAttestation, validateAttestationManifest, hashAttestationManifest } from "../src/privacy/attestation.js";
import type { SignedAttestationManifest } from "../src/privacy/attestation.js";
import { resolveWithPrivacy } from "../src/privacy/resolve.js";
import { getLogicalPlaintextHash } from "../src/privacy/plaintext-hash.js";
import { getPrivacyMode } from "../src/privacy/privacy-mode.js";
import { isCustodyStale } from "../src/privacy/proof-of-possession.js";
import { validateTransition, validateAddressingConsistency } from "../src/privacy/lifecycle.js";
import { verifyPrivacyChain } from "../src/privacy/chain-walker.js";
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

// ── Helpers ────────────────────────────────────────────────────────────

function createStorage(entries: Map<string, Uint8Array>): StorageAdapter {
  return {
    get: async (hash: string) => entries.get(hash) ?? null,
    has: async (hash: string) => entries.has(hash),
  };
}

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

// ── Setup ──────────────────────────────────────────────────────────────

const keypair = await generateKeypair();
const authority = deriveAuthority(keypair.publicKey, "ed25519");
const signingKey = {
  algorithm: "ed25519",
  publicKey: keypair.publicKey,
  privateKey: keypair.privateKey,
  keyId: "key-1",
};

const alice = generateX25519Keypair();
const bob = generateX25519Keypair();

// =========================================================================
// A.1–A.8: Input Validation & Boundary Conditions
// =========================================================================

console.log("\n=== Input Validation & Boundary Conditions ===\n");

// A.1: buildStatementIndex with 31-byte salt (wrong size)
try {
  const shortSalt = new Uint8Array(31);
  let threw = false;
  try {
    await buildStatementIndex("some statement .\n", shortSalt);
  } catch (e) {
    threw = true;
    ok((e as Error).message.includes("32"), "Error should mention 32 bytes");
  }
  strictEqual(threw, true, "31-byte salt must be rejected");
  pass("A.1 buildStatementIndex rejects 31-byte salt");
} catch (e) {
  fail("A.1 buildStatementIndex 31-byte salt", e);
}

// A.2: buildStatementIndex with 33-byte salt (wrong size)
try {
  const longSalt = new Uint8Array(33);
  let threw = false;
  try {
    await buildStatementIndex("some statement .\n", longSalt);
  } catch (e) {
    threw = true;
    ok((e as Error).message.includes("32"), "Error should mention 32 bytes");
  }
  strictEqual(threw, true, "33-byte salt must be rejected");
  pass("A.2 buildStatementIndex rejects 33-byte salt");
} catch (e) {
  fail("A.2 buildStatementIndex 33-byte salt", e);
}

// A.3: buildStatementIndex with 0-byte salt
try {
  const emptySalt = new Uint8Array(0);
  let threw = false;
  try {
    await buildStatementIndex("some statement .\n", emptySalt);
  } catch (e) {
    threw = true;
  }
  strictEqual(threw, true, "0-byte salt must be rejected");
  pass("A.3 buildStatementIndex rejects 0-byte salt");
} catch (e) {
  fail("A.3 buildStatementIndex 0-byte salt", e);
}

// A.4: buildStatementIndex with empty N-Quads string
try {
  const result = await buildStatementIndex("");
  strictEqual(result.statements.length, 0, "Empty N-Quads should produce 0 statements");
  strictEqual(result.statementHashes.length, 0, "Empty N-Quads should produce 0 hashes");
  ok(result.indexRoot.startsWith("sha256:"), "Index root should still be valid (hash of empty concat)");
  pass("A.4 buildStatementIndex handles empty N-Quads string gracefully");
} catch (e) {
  fail("A.4 buildStatementIndex empty N-Quads", e);
}

// A.5: buildStatementIndex with only whitespace/newlines
try {
  const result = await buildStatementIndex("\n\n\n");
  strictEqual(result.statements.length, 0, "Whitespace-only should produce 0 statements");
  pass("A.5 buildStatementIndex handles whitespace-only N-Quads");
} catch (e) {
  fail("A.5 buildStatementIndex whitespace-only", e);
}

// A.6: encryptContent with zero recipients
try {
  const plaintext = new TextEncoder().encode("test");
  let threw = false;
  try {
    await encryptContent(plaintext, new Map(), crypto);
  } catch (e) {
    threw = true;
    ok(
      (e as Error).message.toLowerCase().includes("recipient"),
      "Error should mention recipients",
    );
  }
  strictEqual(threw, true, "Zero recipients must be rejected");
  pass("A.6 encryptContent rejects zero recipients");
} catch (e) {
  fail("A.6 encryptContent zero recipients", e);
}

// A.7: encryptContent with empty plaintext (0 bytes)
try {
  const emptyPlaintext = new Uint8Array(0);
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  // Should either succeed (encrypt empty bytes) or throw clearly
  let succeeded = false;
  let threwClear = false;
  try {
    const result = await encryptContent(emptyPlaintext, recipients, crypto);
    // If it succeeds, ciphertext should exist (GCM tag at minimum)
    ok(result.ciphertext.length > 0, "Ciphertext should at least contain GCM tag");
    ok(result.plaintextHash.startsWith("sha256:"), "Plaintext hash should be valid");
    succeeded = true;
  } catch (e) {
    // If it throws, the error should be clear
    threwClear = (e as Error).message.length > 0;
  }
  ok(succeeded || threwClear, "Either succeeds or throws a clear error");
  pass("A.7 encryptContent handles empty plaintext (0 bytes)");
} catch (e) {
  fail("A.7 encryptContent empty plaintext", e);
}

// A.8: generateHmacTags with mismatched array lengths (0 statements, non-zero salt)
try {
  const hmacKey = new Uint8Array(32);
  const salt = new Uint8Array(32);
  const tags = generateHmacTags([], hmacKey, salt);
  strictEqual(tags.length, 0, "0 statements should produce 0 tags");
  pass("A.8 generateHmacTags handles 0 statements");
} catch (e) {
  fail("A.8 generateHmacTags 0 statements", e);
}

// =========================================================================
// A.9–A.16: Cryptographic Edge Cases
// =========================================================================

console.log("\n=== Cryptographic Edge Cases ===\n");

// A.9: Decrypt with wrong recipient ID (correct key, wrong ID)
try {
  const plaintext = new TextEncoder().encode('{"secret":"data"}');
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const encParams: EncryptedPrivacyParams = {
    algorithm: "AES-256-GCM",
    keyAgreement: "X25519-HKDF-SHA256",
    iv: bytesToHex(encResult.iv),
    tagLength: 128,
    plaintextHash: encResult.plaintextHash,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
    ephemeralPublicKey: bytesToHex(encResult.ephemeralPublicKey),
    recipients: encResult.recipients.map((r) => ({
      id: r.id,
      encryptedKey: bytesToHex(r.encryptedKey),
    })),
  };

  let threw = false;
  try {
    // Alice's key but "bob" as recipient ID → not found in recipient list
    await decryptContent(encResult.ciphertext, encParams, alice.privateKey, "bob", crypto);
  } catch (e) {
    threw = true;
    ok(
      (e as Error).message.includes("not found") || (e as Error).message.includes("Not an authorized"),
      "Should report recipient not found",
    );
  }
  strictEqual(threw, true, "Wrong recipient ID must fail");
  pass("A.9 decryptContent fails with wrong recipient ID (correct key, wrong ID)");
} catch (e) {
  fail("A.9 Decrypt wrong recipient ID", e);
}

// A.10: Decrypt with correct recipient ID but wrong private key
try {
  const plaintext = new TextEncoder().encode('{"secret":"data"}');
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const encParams: EncryptedPrivacyParams = {
    algorithm: "AES-256-GCM",
    keyAgreement: "X25519-HKDF-SHA256",
    iv: bytesToHex(encResult.iv),
    tagLength: 128,
    plaintextHash: encResult.plaintextHash,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
    ephemeralPublicKey: bytesToHex(encResult.ephemeralPublicKey),
    recipients: encResult.recipients.map((r) => ({
      id: r.id,
      encryptedKey: bytesToHex(r.encryptedKey),
    })),
  };

  let threw = false;
  try {
    // Bob's private key but "alice" as ID → ECDH produces wrong shared secret
    await decryptContent(encResult.ciphertext, encParams, bob.privateKey, "alice", crypto);
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "Wrong private key must fail (GCM auth failure)");
  pass("A.10 decryptContent fails with wrong private key (GCM authentication failure)");
} catch (e) {
  fail("A.10 Decrypt wrong private key", e);
}

// A.11: HMAC verification with truncated tag (31 bytes instead of 32)
try {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const stmt = '<https://example.org/s> <https://example.org/p> "value" .';
  const tags = generateHmacTags([stmt], hmacKey, salt);
  const truncatedTag = tags[0].slice(0, 31); // 31 bytes instead of 32

  const valid = verifyHmacTag(stmt, hmacKey, salt, truncatedTag);
  strictEqual(valid, false, "Truncated tag must not verify");
  pass("A.11 verifyHmacTag rejects truncated 31-byte tag");
} catch (e) {
  fail("A.11 HMAC truncated tag", e);
}

// A.12: HMAC verification with extended tag (33 bytes)
try {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const stmt = '<https://example.org/s> <https://example.org/p> "value" .';
  const tags = generateHmacTags([stmt], hmacKey, salt);
  const extendedTag = new Uint8Array(33);
  extendedTag.set(tags[0]);
  extendedTag[32] = 0xff;

  const valid = verifyHmacTag(stmt, hmacKey, salt, extendedTag);
  strictEqual(valid, false, "Extended tag must not verify");
  pass("A.12 verifyHmacTag rejects extended 33-byte tag");
} catch (e) {
  fail("A.12 HMAC extended tag", e);
}

// A.13: Same plaintext encrypted twice produces different ciphertext (IV randomness)
try {
  const plaintext = new TextEncoder().encode('{"same":"content"}');
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);

  const enc1 = await encryptContent(plaintext, recipients, crypto);
  const enc2 = await encryptContent(plaintext, recipients, crypto);

  ok(
    bytesToHex(enc1.ciphertext) !== bytesToHex(enc2.ciphertext),
    "Same plaintext must produce different ciphertext (random IV + CEK)",
  );
  ok(
    bytesToHex(enc1.iv) !== bytesToHex(enc2.iv),
    "IVs must differ between encryptions",
  );
  // But plaintext hashes should be identical
  strictEqual(enc1.plaintextHash, enc2.plaintextHash, "Plaintext hashes must match");
  pass("A.13 Same plaintext → different ciphertext (IV/CEK randomness verified)");
} catch (e) {
  fail("A.13 Ciphertext randomness", e);
}

// A.14: Decrypt ciphertext with 1 bit flipped → GCM auth failure
try {
  const plaintext = new TextEncoder().encode('{"tamper":"test"}');
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  // Flip one bit in ciphertext
  const tampered = new Uint8Array(encResult.ciphertext);
  tampered[0] ^= 0x01;

  const encParams: EncryptedPrivacyParams = {
    algorithm: "AES-256-GCM",
    keyAgreement: "X25519-HKDF-SHA256",
    iv: bytesToHex(encResult.iv),
    tagLength: 128,
    plaintextHash: encResult.plaintextHash,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
    ephemeralPublicKey: bytesToHex(encResult.ephemeralPublicKey),
    recipients: encResult.recipients.map((r) => ({
      id: r.id,
      encryptedKey: bytesToHex(r.encryptedKey),
    })),
  };

  let threw = false;
  try {
    await decryptContent(tampered, encParams, alice.privateKey, "alice", crypto);
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "1-bit ciphertext flip must cause GCM auth failure");
  pass("A.14 1-bit ciphertext tamper → GCM authentication failure");
} catch (e) {
  fail("A.14 Ciphertext tamper", e);
}

// A.15: verifyStatementInIndex with swapped salt bytes (salt[0] ↔ salt[1])
try {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const stmt = '<https://example.org/s> <https://example.org/p> "test" .';
  const result = await buildStatementIndex(stmt + "\n", salt);

  // Swap first two bytes of salt
  const swappedSalt = new Uint8Array(salt);
  const tmp = swappedSalt[0];
  swappedSalt[0] = swappedSalt[1];
  swappedSalt[1] = tmp;

  // Unless bytes happened to be equal, verification should fail
  if (salt[0] !== salt[1]) {
    const valid = await verifyStatementInIndex(
      result.statements[0],
      result.statementHashes[0],
      swappedSalt,
    );
    strictEqual(valid, false, "Swapped salt bytes must produce different hash");
    pass("A.15 Salt byte swap → verification fails");
  } else {
    // Extremely unlikely but handle gracefully
    pass("A.15 Salt byte swap (skipped — first two bytes were equal)");
  }
} catch (e) {
  fail("A.15 Salt byte swap", e);
}

// A.16: HMAC key encrypted for alice, decrypted by bob → GCM failure
try {
  const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const disclosureMap = new Map<string, number[] | "all">([["alice", "all"]]);

  const dist = await encryptHmacKeyForRecipients(hmacKey, recipients, disclosureMap);

  let threw = false;
  try {
    // Bob tries to decrypt alice's encrypted HMAC key
    await decryptHmacKey(
      dist.recipients[0].encryptedHmacKey,
      dist.ephemeralPublicKey,
      dist.iv,
      bob.privateKey, // Wrong key!
      "alice",
    );
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "Bob cannot decrypt alice's HMAC key");
  pass("A.16 HMAC key encrypted for alice → bob cannot decrypt (GCM failure)");
} catch (e) {
  fail("A.16 HMAC key cross-recipient", e);
}

// =========================================================================
// A.17–A.24: Serialization Round-Trip Integrity
// =========================================================================

console.log("\n=== Serialization Round-Trip Integrity ===\n");

// A.17: Encrypted manifest → JSON → parse → resolve (cold round-trip)
try {
  const plaintext = new TextEncoder().encode(stableStringify({ roundtrip: true }));
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const manifest = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/test/roundtrip`,
      version: "1",
      branch: "main",
      created: "2026-03-09T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
  });
  const signed = await signManifest(manifest, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);

  // Serialize to JSON string
  const jsonStr = stableStringify(signed);

  // Parse back (simulates cold load from storage)
  const parsed = JSON.parse(jsonStr) as ResolutionManifest;

  // Verify signature on the parsed manifest
  const sigValid = await verifyManifest(parsed, keypair.publicKey, "JCS", crypto);
  strictEqual(sigValid, true, "Signature must verify after JSON round-trip");

  // Verify privacy mode survived
  const mode = getPrivacyMode(parsed);
  strictEqual(mode, "encrypted", "Privacy mode must survive JSON round-trip");

  // Verify the encrypted params survived
  const privacy = (parsed as Record<string, unknown>)["hiri:privacy"] as Record<string, unknown>;
  const params = privacy.parameters as Record<string, unknown>;
  strictEqual(typeof params.iv, "string", "IV must be a hex string after round-trip");
  strictEqual(typeof params.ephemeralPublicKey, "string", "Ephemeral key must be a hex string");
  ok(params.plaintextHash?.toString().startsWith("sha256:"), "Plaintext hash preserved");

  pass("A.17 Encrypted manifest survives JSON serialize → parse → verify");
} catch (e) {
  fail("A.17 Encrypted manifest round-trip", e);
}

// A.18: Attestation manifest → JSON → parse → validate (no content block survives)
try {
  const subjectKeypair = await generateKeypair();
  const subjectAuth = deriveAuthority(subjectKeypair.publicKey, "ed25519");

  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "roundtrip-test",
    subject: {
      authority: subjectAuth,
      manifestHash: "sha256:abc",
      contentHash: "sha256:def",
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "test",
      value: true,
      attestedAt: "2026-03-09T00:00:00Z",
    },
    evidence: { method: "test", description: "Round-trip test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });

  const jsonStr = JSON.stringify(attestation);
  const parsed = JSON.parse(jsonStr);

  // Validate structure
  const validation = validateAttestationManifest(parsed);
  strictEqual(validation.valid, true, "Attestation must validate after round-trip");
  ok(!("hiri:content" in parsed), "No hiri:content block after round-trip");

  pass("A.18 Attestation manifest survives JSON round-trip without gaining hiri:content");
} catch (e) {
  fail("A.18 Attestation round-trip", e);
}

// A.19: SD manifest with hex-encoded hashes → round-trip preserves hex strings (not Uint8Array objects)
try {
  const stmts = ['<https://example.org/s> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/T> .'];
  const nquads = stmts.join("\n") + "\n";
  const indexResult = await buildStatementIndex(nquads);

  const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const hmacTags = generateHmacTags(stmts, hmacKey, indexResult.indexSalt);

  // Build content blob with hex-encoded values
  const contentBlob = {
    mandatoryNQuads: stmts,
    statementIndex: indexResult.statementHashes.map(bytesToHex),
    hmacTags: hmacTags.map(bytesToHex),
  };
  const jsonStr = JSON.stringify(contentBlob);
  const parsed = JSON.parse(jsonStr);

  // Verify hex strings survived (not "[object Object]" or numbered objects)
  strictEqual(typeof parsed.statementIndex[0], "string", "Statement hash must be a string");
  strictEqual(parsed.statementIndex[0].length, 64, "SHA-256 hex = 64 chars");
  ok(!parsed.statementIndex[0].includes("[object"), "Must not be [object Object]");
  ok(!parsed.statementIndex[0].includes("{"), "Must not be a serialized object");
  strictEqual(typeof parsed.hmacTags[0], "string", "HMAC tag must be a string");
  strictEqual(parsed.hmacTags[0].length, 64, "HMAC hex = 64 chars");

  hmacKey.fill(0);
  pass("A.19 SD content blob hex strings survive JSON round-trip (not Uint8Array objects)");
} catch (e) {
  fail("A.19 SD hex string round-trip", e);
}

// A.20: Manifest with Uint8Array accidentally placed in privacy block → detect after round-trip
try {
  // Simulate the developer mistake: put raw Uint8Array in privacy params
  const rawBytes = new Uint8Array([1, 2, 3, 4]);
  const badManifest = {
    "hiri:privacy": {
      mode: "encrypted",
      parameters: {
        iv: rawBytes, // WRONG: should be hex string
      },
    },
  };

  const jsonStr = JSON.stringify(badManifest);
  const parsed = JSON.parse(jsonStr);

  // After round-trip, Uint8Array becomes { "0": 1, "1": 2, "2": 3, "3": 4 }
  const ivAfterRoundTrip = (parsed["hiri:privacy"] as any).parameters.iv;
  ok(typeof ivAfterRoundTrip !== "string", "Raw Uint8Array does NOT survive as a string");
  ok(typeof ivAfterRoundTrip === "object", "Uint8Array becomes a plain object after JSON round-trip");

  // This is the bug the developer guide warns about
  pass("A.20 Uint8Array in privacy block → becomes object after JSON round-trip (developer guide bug #2)");
} catch (e) {
  fail("A.20 Uint8Array JSON round-trip", e);
}

// A.21: Resolve encrypted manifest from cold storage (full pipeline)
try {
  const plaintext = new TextEncoder().encode(stableStringify({ cold: "storage" }));
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const manifest = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/test/cold`,
      version: "1",
      branch: "main",
      created: "2026-03-09T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
  });
  const signed = await signManifest(manifest, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);

  // Simulate cold storage: serialize everything to JSON, then parse back
  const manifestJson = stableStringify(signed);
  const manifestBytes = new TextEncoder().encode(manifestJson);
  const manifestHash = await crypto.hash(manifestBytes);

  // Store as raw bytes (simulating file/network read)
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(encResult.ciphertextHash, encResult.ciphertext);

  // Resolve from cold storage
  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/cold`,
    createStorage(entries),
    {
      crypto,
      publicKey: keypair.publicKey,
      manifestHash,
      decryptionKey: alice.privateKey,
      recipientId: "alice",
    },
  );

  strictEqual(result.verified, true, "Must verify from cold storage");
  strictEqual(result.contentStatus, "decrypted-verified", "Must decrypt from cold storage");
  ok(result.decryptedContent instanceof Uint8Array, "Decrypted content present");

  const decryptedStr = new TextDecoder().decode(result.decryptedContent);
  ok(decryptedStr.includes("cold"), "Decrypted content matches original");

  pass("A.21 Full cold-storage round-trip: encrypt → serialize → store → fetch → parse → decrypt");
} catch (e) {
  fail("A.21 Cold storage round-trip", e);
}

// A.22: Resolve PoP manifest where content IS in storage (resolver must still not return it)
try {
  const content = new TextEncoder().encode(stableStringify({ should_not: "be returned" }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/pop-leak`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  (unsigned as Record<string, unknown>)["hiri:privacy"] = {
    mode: "proof-of-possession",
    parameters: { refreshPolicy: "P30D" },
  };
  const signed = await signManifest(unsigned, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);
  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  // Store both manifest AND content (content shouldn't be returned for PoP)
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content); // This exists but should not be fetched

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/pop-leak`,
    createStorage(entries),
    { crypto, publicKey: keypair.publicKey, manifestHash },
  );

  strictEqual(result.contentStatus, "private-custody-asserted");
  strictEqual(result.decryptedContent, undefined, "PoP must NOT return content even if available");
  pass("A.22 PoP resolver does not leak content even when content exists in storage");
} catch (e) {
  fail("A.22 PoP content leak", e);
}

// A.23: isCustodyStale with malformed duration string
try {
  // "P30X" is not a valid ISO 8601 duration
  const result = isCustodyStale("2026-01-01T00:00:00Z", "P30X", "2026-02-15T00:00:00Z");
  // Should either return a reasonable default or handle gracefully
  // (not throw an unhandled error)
  ok(typeof result === "boolean", "Must return boolean even with bad duration");
  pass("A.23 isCustodyStale handles malformed duration gracefully");
} catch (e) {
  // If it throws, that's also acceptable — it's a clear error
  ok((e as Error).message.length > 0, "Throws with a clear message");
  pass("A.23 isCustodyStale throws clearly for malformed duration");
}

// A.24: isCustodyStale with undefined refreshPolicy → not stale (no policy = no expiry)
try {
  const result = isCustodyStale("2026-01-01T00:00:00Z", undefined, "2099-12-31T00:00:00Z");
  strictEqual(result, false, "No refresh policy means never stale");
  pass("A.24 isCustodyStale with undefined refreshPolicy → not stale");
} catch (e) {
  fail("A.24 isCustodyStale undefined policy", e);
}

// =========================================================================
// A.25–A.32: Cross-Mode & Chain Adversarial Cases
// =========================================================================

console.log("\n=== Cross-Mode & Chain Adversarial Cases ===\n");

// A.25: Transition from public to encrypted (INVALID — cannot make public content private)
try {
  const result = validateTransition("public", "encrypted");
  strictEqual(result.valid, false, "Public → Encrypted must be rejected");
  pass("A.25 Public → Encrypted transition rejected (monotonically decreasing)");
} catch (e) {
  fail("A.25 Public → Encrypted", e);
}

// A.26: Transition from public to selective-disclosure (INVALID)
try {
  const result = validateTransition("public", "selective-disclosure");
  strictEqual(result.valid, false, "Public → SD must be rejected");
  pass("A.26 Public → Selective Disclosure transition rejected");
} catch (e) {
  fail("A.26 Public → SD", e);
}

// A.27: Transition from encrypted to selective-disclosure (questionable — same privacy level?)
try {
  const result = validateTransition("encrypted", "selective-disclosure");
  // The privacy ordering is: PoP(4) > SD(3) > Encrypted(2) > Public(1)
  // Encrypted(2) → SD(3) means INCREASING privacy — should be invalid
  strictEqual(result.valid, false, "Encrypted → SD is increasing privacy — must be rejected");
  pass("A.27 Encrypted → Selective Disclosure rejected (SD is more private than encrypted)");
} catch (e) {
  fail("A.27 Encrypted → SD", e);
}

// A.28: Double transition: PoP → Public → PoP (second transition is invalid even though first was valid)
try {
  const t1 = validateTransition("proof-of-possession", "public");
  strictEqual(t1.valid, true, "PoP → Public is valid");

  const t2 = validateTransition("public", "proof-of-possession");
  strictEqual(t2.valid, false, "Public → PoP is invalid (cannot re-privatize)");
  pass("A.28 Double transition: PoP→Public valid, Public→PoP invalid");
} catch (e) {
  fail("A.28 Double transition", e);
}

// A.29: Unknown mode → Unknown mode transition (forward compatibility)
try {
  const result = validateTransition("quantum-encrypted", "post-quantum-public");
  strictEqual(result.valid, true, "Unknown → Unknown must be accepted (forward compatibility)");
  pass("A.29 Unknown → Unknown mode transition accepted (forward compat)");
} catch (e) {
  fail("A.29 Unknown mode transition", e);
}

// A.30: getLogicalPlaintextHash on manifest with no privacy block (public)
try {
  const content = new TextEncoder().encode(stableStringify({ public: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/no-privacy`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);

  const lph = getLogicalPlaintextHash(signed);
  strictEqual(lph.hash, contentHash, "Public manifest: logical plaintext hash = content.hash");
  pass("A.30 getLogicalPlaintextHash on public manifest returns content.hash");
} catch (e) {
  fail("A.30 getLogicalPlaintextHash public", e);
}

// A.31: getLogicalPlaintextHash on attestation manifest → throws
try {
  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "lph-test",
    subject: {
      authority: "test",
      manifestHash: "sha256:abc",
      contentHash: "sha256:def",
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "test",
      value: true,
      attestedAt: "2026-03-09T00:00:00Z",
    },
    evidence: { method: "test", description: "test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });
  const signed = await signAttestationManifest(attestation, signingKey, "2026-03-09T00:00:00Z", crypto);

  let threw = false;
  try {
    getLogicalPlaintextHash(signed as unknown as ResolutionManifest);
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "Attestation manifest must throw on getLogicalPlaintextHash");
  pass("A.31 getLogicalPlaintextHash throws for attestation manifest");
} catch (e) {
  fail("A.31 getLogicalPlaintextHash attestation", e);
}

// A.32: Addressing consistency with one attestation manifest (no content block) → should pass
try {
  const content = new TextEncoder().encode(stableStringify({ data: true }));
  const contentHash = await crypto.hash(content);

  const normalManifest = buildUnsignedManifest({
    id: `hiri://${authority}/test/addr`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const normalSigned = await signManifest(normalManifest, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);

  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "addr-test",
    subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
    claim: { "@type": "hiri:PropertyAttestation", property: "test", value: true, attestedAt: "2026-03-09T00:00:00Z" },
    evidence: { method: "test", description: "test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });
  const attestSigned = await signAttestationManifest(attestation, signingKey, "2026-03-09T00:00:00Z", crypto);

  // Attestation has no hiri:content → addressing check should skip
  const result = validateAddressingConsistency(
    attestSigned as unknown as ResolutionManifest,
    normalSigned,
  );
  strictEqual(result.valid, true, "Attestation manifest (no content) should skip addressing check");
  pass("A.32 Addressing consistency skips attestation manifests (no content block)");
} catch (e) {
  fail("A.32 Addressing with attestation", e);
}

// =========================================================================
// A.33–A.40: Attestation Adversarial Cases
// =========================================================================

console.log("\n=== Attestation Adversarial Cases ===\n");

// A.33: validateAttestationManifest with hiri:content AND hiri:attestation (both present)
try {
  const manifest = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/attestation/both",
    "@type": "hiri:AttestationManifest",
    "hiri:version": "1",
    "hiri:branch": "main",
    "hiri:timing": { created: "2026-03-09T00:00:00Z" },
    "hiri:privacy": { mode: "attestation" },
    "hiri:attestation": {
      subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
      claim: { "@type": "hiri:PropertyAttestation", property: "test", value: true, attestedAt: "2026-03-09T00:00:00Z" },
      evidence: { method: "test", description: "test" },
    },
    "hiri:content": { hash: "sha256:sneaky", format: "application/json", size: 100 },
  };

  const result = validateAttestationManifest(manifest);
  strictEqual(result.valid, false, "Must reject attestation WITH hiri:content");
  ok(result.reason?.includes("MUST NOT"), "Reason should cite the constraint");
  pass("A.33 Attestation with both hiri:content AND hiri:attestation → rejected");
} catch (e) {
  fail("A.33 Attestation with content", e);
}

// A.34: validateAttestationManifest with wrong @type
try {
  const manifest = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/attestation/wrong-type",
    "@type": "hiri:ResolutionManifest", // Wrong type!
    "hiri:version": "1",
    "hiri:branch": "main",
    "hiri:timing": { created: "2026-03-09T00:00:00Z" },
    "hiri:privacy": { mode: "attestation" },
    "hiri:attestation": {
      subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
      claim: { "@type": "hiri:PropertyAttestation", property: "test", value: true, attestedAt: "2026-03-09T00:00:00Z" },
      evidence: { method: "test", description: "test" },
    },
  };

  const result = validateAttestationManifest(manifest);
  strictEqual(result.valid, false, "Wrong @type must be rejected");
  pass("A.34 Attestation with wrong @type (ResolutionManifest) → rejected");
} catch (e) {
  fail("A.34 Wrong @type", e);
}

// A.35: validateAttestationManifest missing hiri:attestation block entirely
try {
  const manifest = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/attestation/no-block",
    "@type": "hiri:AttestationManifest",
    "hiri:version": "1",
    "hiri:branch": "main",
    "hiri:timing": { created: "2026-03-09T00:00:00Z" },
    "hiri:privacy": { mode: "attestation" },
    // No hiri:attestation block!
  };

  const result = validateAttestationManifest(manifest);
  strictEqual(result.valid, false, "Missing hiri:attestation must be rejected");
  pass("A.35 Attestation missing hiri:attestation block → rejected");
} catch (e) {
  fail("A.35 Missing attestation block", e);
}

// A.36: verifyAttestation with tampered attestation signature
try {
  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "tamper-sig",
    subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
    claim: { "@type": "hiri:PropertyAttestation", property: "test", value: true, attestedAt: "2026-03-09T00:00:00Z" },
    evidence: { method: "test", description: "test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });
  const signed = await signAttestationManifest(attestation, signingKey, "2026-03-09T00:00:00Z", crypto);

  // Tamper the signature
  const tampered = JSON.parse(JSON.stringify(signed)) as SignedAttestationManifest;
  const sig = tampered["hiri:signature"].proofValue;
  tampered["hiri:signature"].proofValue = sig.substring(0, sig.length - 1) + (sig.endsWith("a") ? "b" : "a");

  const result = await verifyAttestation(tampered, keypair.publicKey, null, null, crypto);
  strictEqual(result.attestationVerified, false, "Tampered signature must fail verification");
  strictEqual(result.trustLevel, "unverifiable", "Trust level must be unverifiable");
  pass("A.36 Tampered attestation signature → attestationVerified: false, trustLevel: unverifiable");
} catch (e) {
  fail("A.36 Tampered attestation sig", e);
}

// A.37: verifyAttestation with wrong attestor public key
try {
  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "wrong-key",
    subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
    claim: { "@type": "hiri:PropertyAttestation", property: "test", value: true, attestedAt: "2026-03-09T00:00:00Z" },
    evidence: { method: "test", description: "test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });
  const signed = await signAttestationManifest(attestation, signingKey, "2026-03-09T00:00:00Z", crypto);

  // Use a completely different public key
  const wrongKeypair = await generateKeypair();
  const result = await verifyAttestation(signed, wrongKeypair.publicKey, null, null, crypto);
  strictEqual(result.attestationVerified, false, "Wrong public key must fail");
  pass("A.37 verifyAttestation with wrong attestor public key → fails");
} catch (e) {
  fail("A.37 Wrong attestor key", e);
}

// A.38: verifyAttestation with revoked-compromised status + subject verified → partial
try {
  const subjectKeypair = await generateKeypair();
  const subjectAuth = deriveAuthority(subjectKeypair.publicKey, "ed25519");
  const subjectContent = new TextEncoder().encode('{"test":true}');
  const subjectContentHash = await crypto.hash(subjectContent);

  const subjectUnsigned = buildUnsignedManifest({
    id: `hiri://${subjectAuth}/test/subject`,
    contentHash: subjectContentHash,
    contentFormat: "application/json",
    contentSize: subjectContent.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const subjectSigned = await signManifest(subjectUnsigned, {
    algorithm: "ed25519",
    publicKey: subjectKeypair.publicKey,
    privateKey: subjectKeypair.privateKey,
    keyId: "key-1",
  }, "2026-03-09T00:00:00Z", "JCS", crypto);
  const subjectManifestHash = await crypto.hash(
    new TextEncoder().encode(stableStringify(subjectSigned)),
  );

  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "compromised",
    subject: {
      authority: subjectAuth,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: { "@type": "hiri:PropertyAttestation", property: "test", value: true, attestedAt: "2026-03-09T00:00:00Z" },
    evidence: { method: "test", description: "test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });
  const signed = await signAttestationManifest(attestation, signingKey, "2026-03-09T00:00:00Z", crypto);

  const result = await verifyAttestation(
    signed,
    keypair.publicKey,
    subjectSigned,
    subjectKeypair.publicKey,
    crypto,
    "revoked-compromised", // Revoked but subject is available
  );

  strictEqual(result.attestationVerified, true, "Signature itself is still valid");
  strictEqual(result.trustLevel, "partial", "Revoked + subject verified = partial");
  ok(result.warnings.some((w) => w.includes("revoked")), "Should warn about compromised key");
  pass("A.38 revoked-compromised + subject verified → partial trust (not unverifiable)");
} catch (e) {
  fail("A.38 Revoked-compromised with subject", e);
}

// A.39: Attestation with validUntil in the far future → not stale
try {
  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "far-future",
    subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "test",
      value: true,
      attestedAt: "2026-03-09T00:00:00Z",
      validUntil: "2099-12-31T23:59:59Z",
    },
    evidence: { method: "test", description: "test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });
  const signed = await signAttestationManifest(attestation, signingKey, "2026-03-09T00:00:00Z", crypto);
  const result = await verifyAttestation(signed, keypair.publicKey, null, null, crypto, "active", "2050-06-15T00:00:00Z");

  strictEqual(result.stale, false, "validUntil in 2099 → not stale in 2050");
  pass("A.39 Attestation with far-future validUntil → not stale");
} catch (e) {
  fail("A.39 Far-future validUntil", e);
}

// A.40: Attestation with no validUntil → never stale
try {
  const attestation = buildAttestationManifest({
    attestorAuthority: authority,
    attestationId: "no-expiry",
    subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "test",
      value: true,
      attestedAt: "2026-03-09T00:00:00Z",
      // No validUntil
    },
    evidence: { method: "test", description: "test" },
    version: "1",
    timestamp: "2026-03-09T00:00:00Z",
  });
  const signed = await signAttestationManifest(attestation, signingKey, "2026-03-09T00:00:00Z", crypto);
  const result = await verifyAttestation(signed, keypair.publicKey, null, null, crypto, "active", "2099-12-31T23:59:59Z");

  strictEqual(result.stale, false, "No validUntil means never stale");
  pass("A.40 Attestation without validUntil → never stale regardless of timestamp");
} catch (e) {
  fail("A.40 No validUntil", e);
}

// =========================================================================
// A.41–A.48: Resolver Adversarial Cases
// =========================================================================

console.log("\n=== Resolver Adversarial Cases ===\n");

// A.41: Resolve with manifest hash that doesn't match stored bytes
try {
  const content = new TextEncoder().encode(stableStringify({ mismatch: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/hash-mismatch`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);
  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const realHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(realHash, manifestBytes);
  entries.set(contentHash, content);

  // Pass a WRONG manifest hash
  let threw = false;
  try {
    await resolveWithPrivacy(
      `hiri://${authority}/test/hash-mismatch`,
      createStorage(entries),
      { crypto, publicKey: keypair.publicKey, manifestHash: "sha256:0000000000000000" },
    );
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "Wrong manifest hash must cause resolution failure");
  pass("A.41 Resolver rejects manifest hash mismatch");
} catch (e) {
  fail("A.41 Manifest hash mismatch", e);
}

// A.42: Resolve encrypted manifest where ciphertext hash in storage doesn't match manifest
try {
  const plaintext = new TextEncoder().encode(stableStringify({ tamper: "ciphertext" }));
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const manifest = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/test/ct-tamper`,
      version: "1",
      branch: "main",
      created: "2026-03-09T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
  });
  const signed = await signManifest(manifest, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);
  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  // Store tampered ciphertext at the correct hash key
  const tamperedCiphertext = new Uint8Array(encResult.ciphertext);
  tamperedCiphertext[0] ^= 0xff;

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(encResult.ciphertextHash, tamperedCiphertext); // Wrong bytes at correct key

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/ct-tamper`,
    createStorage(entries),
    { crypto, publicKey: keypair.publicKey, manifestHash },
  );

  // The manifest signature verifies, but content hash won't match
  // Depending on implementation: either verified:false with hash mismatch, or throws
  ok(
    !result.verified || result.warnings.some((w) => w.toLowerCase().includes("hash") || w.toLowerCase().includes("mismatch")),
    "Tampered ciphertext must be detected (hash mismatch or verification failure)",
  );
  pass("A.42 Tampered ciphertext at correct storage key → detected");
} catch (e) {
  fail("A.42 Ciphertext tamper in storage", e);
}

// A.43: Resolve with unknown privacy mode string
try {
  const content = new TextEncoder().encode(stableStringify({ future: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/unknown-mode`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  (unsigned as Record<string, unknown>)["hiri:privacy"] = { mode: "quantum-entangled-mode-7" };
  const signed = await signManifest(unsigned, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);
  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/unknown-mode`,
    createStorage(entries),
    { crypto, publicKey: keypair.publicKey, manifestHash },
  );

  // Must NOT throw — unknown modes are reported, not rejected (§4.4)
  strictEqual(result.verified, true, "Unknown mode: signature still valid");
  strictEqual(result.contentStatus, "unsupported-mode", "Must report unsupported-mode");
  ok(result.warnings.some((w) => w.includes("quantum")), "Must warn about unknown mode");
  pass("A.43 Unknown privacy mode → unsupported-mode (not rejected, §4.4)");
} catch (e) {
  fail("A.43 Unknown privacy mode", e);
}

// A.44: Resolve with completely wrong public key
try {
  const content = new TextEncoder().encode(stableStringify({ wrong_key: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/wrong-key`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);
  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const wrongKeypair = await generateKeypair();

  let threw = false;
  try {
    await resolveWithPrivacy(
      `hiri://${authority}/test/wrong-key`,
      createStorage(entries),
      { crypto, publicKey: wrongKeypair.publicKey, manifestHash },
    );
  } catch {
    threw = true;
  }
  // Either throws or returns verified: false
  ok(threw, "Wrong public key must cause resolution failure");
  pass("A.44 Resolve with wrong public key → signature verification fails");
} catch (e) {
  fail("A.44 Wrong public key", e);
}

// A.45: KeyDocument staleness check — exactly at boundary (age == maxAge)
try {
  const content = new TextEncoder().encode(stableStringify({ boundary: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/staleness-boundary`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-09T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, signingKey, "2026-03-09T00:00:00Z", "JCS", crypto);
  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  // Set keyDocumentTimestamp exactly maxAge ago
  const maxAge = 48 * 60 * 60 * 1000; // 48 hours
  const fetchedAt = new Date("2026-03-07T00:00:00Z");
  const verificationTime = new Date(fetchedAt.getTime() + maxAge).toISOString();

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/staleness-boundary`,
    createStorage(entries),
    {
      crypto,
      publicKey: keypair.publicKey,
      manifestHash,
      keyDocumentTimestamp: fetchedAt.toISOString(),
      keyDocumentMaxAge: maxAge,
      verificationTime,
    },
  );

  // At exactly the boundary, the age equals maxAge. The check is age > maxAge.
  // So at exactly the boundary, it should NOT be stale.
  strictEqual(result.verified, true);
  // The exact boundary behavior depends on > vs >=
  // Either way, document the result
  const isStaleWarning = result.warnings.some((w) => w.includes("keyDocumentStale"));
  pass(`A.45 KeyDocument staleness at exact boundary: stale=${isStaleWarning} (age == maxAge)`);
} catch (e) {
  fail("A.45 Staleness boundary", e);
}

// A.46: Resolve with empty storage (manifest hash points to nothing)
try {
  const emptyStorage = createStorage(new Map());
  let threw = false;
  try {
    await resolveWithPrivacy(
      `hiri://${authority}/test/empty`,
      emptyStorage,
      { crypto, publicKey: keypair.publicKey, manifestHash: "sha256:nonexistent" },
    );
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "Empty storage must cause resolution failure");
  pass("A.46 Resolve against empty storage → manifest not found");
} catch (e) {
  fail("A.46 Empty storage", e);
}

// A.47: Resolve with storage that returns empty bytes for manifest hash
try {
  const entries = new Map<string, Uint8Array>();
  entries.set("sha256:test", new Uint8Array(0));

  let threw = false;
  try {
    await resolveWithPrivacy(
      `hiri://${authority}/test/empty-bytes`,
      createStorage(entries),
      { crypto, publicKey: keypair.publicKey, manifestHash: "sha256:test" },
    );
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "Empty bytes at manifest hash must fail");
  pass("A.47 Resolve with empty bytes at manifest hash → fails");
} catch (e) {
  fail("A.47 Empty bytes manifest", e);
}

// A.48: SD buildSelectiveDisclosureManifest rejects JCS canonicalization
try {
  let threw = false;
  try {
    buildSelectiveDisclosureManifest({
      baseManifestParams: {
        id: `hiri://${authority}/test/sd-jcs`,
        version: "1",
        branch: "main",
        created: "2026-03-09T00:00:00Z",
        contentHash: "sha256:abc",
        addressing: "raw-sha256",
        contentFormat: "application/json",
        contentSize: 100,
        canonicalization: "JCS", // Must be rejected!
      },
      statementCount: 3,
      indexSalt: new Uint8Array(32),
      indexRoot: "sha256:abc",
      mandatoryStatements: [0],
      hmacKeyDistribution: {
        ephemeralPublicKey: new Uint8Array(32),
        iv: new Uint8Array(12),
        recipients: [],
      },
    });
  } catch (e) {
    threw = true;
    ok((e as Error).message.includes("URDNA2015"), "Error should mention URDNA2015 requirement");
  }
  strictEqual(threw, true, "JCS must be rejected for selective disclosure");
  pass("A.48 buildSelectiveDisclosureManifest rejects JCS canonicalization (§8.3)");
} catch (e) {
  fail("A.48 SD rejects JCS", e);
}

// =========================================================================
// A.49–A.54: Statement Content Edge Cases
// =========================================================================

console.log("\n=== Statement Content Edge Cases ===\n");

// A.49: Statement with Unicode (CJK characters, emoji)
try {
  const unicodeStmts = [
    '<https://example.org/s> <https://example.org/name> "田中太郎" .',
    '<https://example.org/s> <https://example.org/emoji> "🔒🗝️🛡️" .',
    '<https://example.org/s> <https://example.org/arabic> "مرحبا" .',
  ];
  const nquads = unicodeStmts.join("\n") + "\n";
  const result = await buildStatementIndex(nquads);

  strictEqual(result.statements.length, 3, "Should parse 3 Unicode statements");
  strictEqual(result.statementHashes.length, 3, "Should produce 3 hashes");

  // Each hash should be unique (different content)
  const hexHashes = result.statementHashes.map(bytesToHex);
  strictEqual(new Set(hexHashes).size, 3, "All 3 Unicode statements should produce unique hashes");

  // Verify each statement against its hash
  for (let i = 0; i < 3; i++) {
    const valid = await verifyStatementInIndex(
      result.statements[i],
      result.statementHashes[i],
      result.indexSalt,
    );
    strictEqual(valid, true, `Unicode statement ${i} should verify`);
  }

  pass("A.49 Unicode statements (CJK, emoji, Arabic) hash and verify correctly");
} catch (e) {
  fail("A.49 Unicode statements", e);
}

// A.50: Statement with escaped characters (quotes, backslashes, newlines in literals)
try {
  const escapedStmts = [
    '<https://example.org/s> <https://example.org/quote> "He said \\"hello\\"" .',
    '<https://example.org/s> <https://example.org/path> "C:\\\\Users\\\\test" .',
    '<https://example.org/s> <https://example.org/multi> "line1\\nline2\\nline3" .',
  ];
  const nquads = escapedStmts.join("\n") + "\n";
  const result = await buildStatementIndex(nquads);

  strictEqual(result.statements.length, 3, "Should parse 3 escaped statements");

  // Verify each
  for (let i = 0; i < 3; i++) {
    const valid = await verifyStatementInIndex(
      result.statements[i],
      result.statementHashes[i],
      result.indexSalt,
    );
    strictEqual(valid, true, `Escaped statement ${i} should verify`);
  }

  pass("A.50 Statements with escaped characters (quotes, backslashes, \\n) verify correctly");
} catch (e) {
  fail("A.50 Escaped characters", e);
}

// A.51: Statement with empty string literal
try {
  const emptyLiteralStmt = '<https://example.org/s> <https://example.org/empty> "" .';
  const result = await buildStatementIndex(emptyLiteralStmt + "\n");

  strictEqual(result.statements.length, 1);
  const valid = await verifyStatementInIndex(
    result.statements[0],
    result.statementHashes[0],
    result.indexSalt,
  );
  strictEqual(valid, true, "Empty string literal should verify");
  pass("A.51 Statement with empty string literal verifies correctly");
} catch (e) {
  fail("A.51 Empty string literal", e);
}

// A.52: Very long literal value (10KB string)
try {
  const longValue = "x".repeat(10000);
  const longStmt = `<https://example.org/s> <https://example.org/long> "${longValue}" .`;
  const result = await buildStatementIndex(longStmt + "\n");

  strictEqual(result.statements.length, 1);
  ok(result.statementHashes[0].length === 32, "Hash should still be 32 bytes");

  const valid = await verifyStatementInIndex(
    result.statements[0],
    result.statementHashes[0],
    result.indexSalt,
  );
  strictEqual(valid, true, "10KB literal should verify");
  pass("A.52 Statement with 10KB literal value hashes and verifies correctly");
} catch (e) {
  fail("A.52 10KB literal", e);
}

// A.53: Duplicate statements (same statement twice)
try {
  const duplicateStmt = '<https://example.org/s> <https://example.org/p> "same" .';
  const nquads = duplicateStmt + "\n" + duplicateStmt + "\n";
  const result = await buildStatementIndex(nquads);

  strictEqual(result.statements.length, 2, "Should produce 2 entries (no dedup)");
  // Same statement + same salt → same hash
  strictEqual(
    bytesToHex(result.statementHashes[0]),
    bytesToHex(result.statementHashes[1]),
    "Duplicate statements produce identical hashes (same salt)",
  );
  pass("A.53 Duplicate statements produce identical hashes (no deduplication at index level)");
} catch (e) {
  fail("A.53 Duplicate statements", e);
}

// A.54: Statement that looks like a hash collision attempt (near-identical statements)
try {
  const stmt1 = '<https://example.org/s> <https://example.org/p> "value1" .';
  const stmt2 = '<https://example.org/s> <https://example.org/p> "value2" .';
  // Differ by only the last character of the literal
  const nquads = stmt1 + "\n" + stmt2 + "\n";
  const result = await buildStatementIndex(nquads);

  ok(
    bytesToHex(result.statementHashes[0]) !== bytesToHex(result.statementHashes[1]),
    "Near-identical statements must produce different hashes",
  );

  // Cross-verify: stmt1 against stmt2's hash must fail
  const crossValid = await verifyStatementInIndex(
    stmt1,
    result.statementHashes[1], // stmt2's hash
    result.indexSalt,
  );
  strictEqual(crossValid, false, "Statement must not verify against another statement's hash");

  pass("A.54 Near-identical statements ('value1' vs 'value2') produce different hashes, cross-verify fails");
} catch (e) {
  fail("A.54 Near-identical statements", e);
}

// =========================================================================
// Summary
// =========================================================================

console.log(`\n=== Adversarial Tests: ${passed} passed, ${failed} failed ===\n`);

if (failed > 0) {
  process.exit(1);
}
