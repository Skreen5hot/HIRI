/**
 * HIRI Privacy Extension Tests — Milestone 11: Cryptographic Primitives
 *
 * Tests 11.1–11.18: Ed25519↔X25519 conversion, X25519 ECDH,
 * HKDF-SHA256, AES-256-GCM, HMAC-SHA256, and the full key agreement pipeline.
 */

import { strictEqual, deepStrictEqual, ok } from "node:assert";

// Adapter imports — existing
import { generateKeypair } from "../src/adapters/crypto/ed25519.js";

// New M11 adapter imports
import { ed25519PublicToX25519, ed25519PrivateToX25519 } from "../src/adapters/crypto/key-conversion.js";
import { generateX25519Keypair, x25519SharedSecret } from "../src/adapters/crypto/x25519.js";
import { buildHKDFInfo, hkdfDerive } from "../src/adapters/crypto/hkdf.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "../src/adapters/crypto/aes-gcm.js";
import { hmacSha256 } from "../src/adapters/crypto/hmac.js";
import { encryptKeyForRecipient, decryptKeyFromSender } from "../src/adapters/crypto/key-agreement.js";

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

/** Helper: compare two Uint8Arrays for equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// =========================================================================
// Tests: 11.1–11.3 — Ed25519↔X25519 Conversion (§13.3)
// =========================================================================

console.log("\n=== Ed25519↔X25519 Conversion (§13.3) ===\n");

// 11.1: Convert Ed25519 public key to X25519
try {
  const kp = await generateKeypair();
  const x25519Pub = ed25519PublicToX25519(kp.publicKey);
  strictEqual(x25519Pub.length, 32);
  // Verify it's not all zeros (degenerate case)
  ok(x25519Pub.some(b => b !== 0), "X25519 public key should not be all zeros");
  pass("11.1 Ed25519 pub → X25519 pub: 32 bytes");
} catch (e) {
  fail("11.1 Ed25519 pub → X25519 pub: 32 bytes", e);
}

// 11.2: Ed25519 private → X25519 private, derived public matches converted public
try {
  const kp = await generateKeypair();
  const x25519Pub = ed25519PublicToX25519(kp.publicKey);
  const x25519Priv = ed25519PrivateToX25519(kp.privateKey);
  strictEqual(x25519Priv.length, 32);

  // Derive X25519 public from converted private using the x25519 module
  const { x25519 } = await import("@noble/curves/ed25519.js");
  const derivedPub = x25519.getPublicKey(x25519Priv);
  ok(bytesEqual(derivedPub, x25519Pub), "Derived X25519 pub must match converted pub");
  pass("11.2 Ed25519 priv → X25519 priv, derived pub matches converted pub");
} catch (e) {
  fail("11.2 Ed25519 priv → X25519 priv, derived pub matches converted pub", e);
}

// 11.3: Wrong length input rejected
try {
  let threw = false;
  try {
    ed25519PublicToX25519(new Uint8Array(31));
  } catch {
    threw = true;
  }
  ok(threw, "31-byte input should throw");

  threw = false;
  try {
    ed25519PrivateToX25519(new Uint8Array(33));
  } catch {
    threw = true;
  }
  ok(threw, "33-byte input should throw");
  pass("11.3 Wrong-length keys rejected");
} catch (e) {
  fail("11.3 Wrong-length keys rejected", e);
}

// =========================================================================
// Tests: 11.4–11.5 — X25519 Key Agreement
// =========================================================================

console.log("\n=== X25519 Key Agreement ===\n");

// 11.4: Generate X25519 keypair
try {
  const kp = generateX25519Keypair();
  strictEqual(kp.publicKey.length, 32);
  strictEqual(kp.privateKey.length, 32);
  ok(kp.publicKey.some(b => b !== 0), "Public key should not be all zeros");
  pass("11.4 X25519 keypair: 32-byte pub + priv");
} catch (e) {
  fail("11.4 X25519 keypair: 32-byte pub + priv", e);
}

// 11.5: ECDH commutativity
try {
  const a = generateX25519Keypair();
  const b = generateX25519Keypair();
  const ssAB = x25519SharedSecret(a.privateKey, b.publicKey);
  const ssBA = x25519SharedSecret(b.privateKey, a.publicKey);
  ok(bytesEqual(ssAB, ssBA), "X25519(aPriv, bPub) must equal X25519(bPriv, aPub)");
  strictEqual(ssAB.length, 32);
  pass("11.5 ECDH commutativity: shared secrets match");
} catch (e) {
  fail("11.5 ECDH commutativity: shared secrets match", e);
}

// =========================================================================
// Tests: 11.6–11.10 — HKDF-SHA256 (§13.2)
// =========================================================================

console.log("\n=== HKDF-SHA256 (§13.2) ===\n");

// 11.6: buildHKDFInfo("hiri-cek-v1.1", "alice") → 18 bytes matching B.14
try {
  const info = buildHKDFInfo("hiri-cek-v1.1", "alice");
  strictEqual(info.length, 18);
  const expected = new Uint8Array([
    0x68, 0x69, 0x72, 0x69, 0x2d, 0x63, 0x65, 0x6b, 0x2d, 0x76, 0x31, 0x2e, 0x31,
    0x61, 0x6c, 0x69, 0x63, 0x65,
  ]);
  ok(bytesEqual(info, expected), "Info bytes must match B.14 exactly");
  pass("11.6 buildHKDFInfo('hiri-cek-v1.1', 'alice') → 18 bytes matching B.14");
} catch (e) {
  fail("11.6 buildHKDFInfo('hiri-cek-v1.1', 'alice') → 18 bytes matching B.14", e);
}

// 11.7: buildHKDFInfo("hiri-hmac-v1.1", "alice") → 19 bytes, ≠ CEK info
try {
  const hmacInfo = buildHKDFInfo("hiri-hmac-v1.1", "alice");
  strictEqual(hmacInfo.length, 19); // "hiri-hmac-v1.1" = 14 bytes + "alice" = 5 bytes
  const cekInfo = buildHKDFInfo("hiri-cek-v1.1", "alice");
  ok(!bytesEqual(hmacInfo, cekInfo), "HMAC info must differ from CEK info");
  pass("11.7 buildHKDFInfo('hiri-hmac-v1.1', 'alice') → 19 bytes, ≠ CEK info");
} catch (e) {
  fail("11.7 buildHKDFInfo('hiri-hmac-v1.1', 'alice') → 19 bytes, ≠ CEK info", e);
}

// 11.8: HKDF derivation produces 32-byte output
try {
  const ikm = new Uint8Array(32);
  globalThis.crypto.getRandomValues(ikm);
  const salt = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  const info = buildHKDFInfo("hiri-cek-v1.1", "test");
  const key = hkdfDerive({ ikm, salt, info, length: 32 });
  strictEqual(key.length, 32);
  pass("11.8 HKDF derivation → 32-byte output");
} catch (e) {
  fail("11.8 HKDF derivation → 32-byte output", e);
}

// 11.9: Same inputs → same KEK (determinism)
try {
  const ikm = new Uint8Array(32);
  globalThis.crypto.getRandomValues(ikm);
  const salt = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  const info = buildHKDFInfo("hiri-cek-v1.1", "alice");
  const key1 = hkdfDerive({ ikm, salt, info, length: 32 });
  const key2 = hkdfDerive({ ikm, salt, info, length: 32 });
  ok(bytesEqual(key1, key2), "Same inputs must produce identical KEK");
  pass("11.9 Same inputs → same KEK (determinism)");
} catch (e) {
  fail("11.9 Same inputs → same KEK (determinism)", e);
}

// 11.10: Different recipientId → different KEK (domain separation per B.14)
try {
  const ikm = new Uint8Array(32);
  globalThis.crypto.getRandomValues(ikm);
  const salt = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  const infoAlice = buildHKDFInfo("hiri-cek-v1.1", "alice");
  const infoBob = buildHKDFInfo("hiri-cek-v1.1", "bob");
  const kekAlice = hkdfDerive({ ikm, salt, info: infoAlice, length: 32 });
  const kekBob = hkdfDerive({ ikm, salt, info: infoBob, length: 32 });
  ok(!bytesEqual(kekAlice, kekBob), "Different recipientId must produce different KEK");
  pass("11.10 Different recipientId → different KEK (domain separation)");
} catch (e) {
  fail("11.10 Different recipientId → different KEK (domain separation)", e);
}

// =========================================================================
// Tests: 11.11–11.13 — AES-256-GCM
// =========================================================================

console.log("\n=== AES-256-GCM ===\n");

// 11.11: Encrypt then decrypt round-trip
try {
  const key = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode("Hello, HIRI Privacy Extension!");

  const ciphertext = await aesGcmEncrypt(key, iv, plaintext);
  ok(ciphertext.length > plaintext.length, "Ciphertext should be longer (includes GCM tag)");
  // GCM tag is 16 bytes
  strictEqual(ciphertext.length, plaintext.length + 16);

  const recovered = await aesGcmDecrypt(key, iv, ciphertext);
  ok(bytesEqual(recovered, plaintext), "Recovered plaintext must match original");
  pass("11.11 AES-GCM encrypt→decrypt round-trip");
} catch (e) {
  fail("11.11 AES-GCM encrypt→decrypt round-trip", e);
}

// 11.12: Tampered ciphertext → decryption fails
try {
  const key = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode("Tamper test");

  const ciphertext = await aesGcmEncrypt(key, iv, plaintext);
  // Flip a byte
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff;

  let threw = false;
  try {
    await aesGcmDecrypt(key, iv, tampered);
  } catch {
    threw = true;
  }
  ok(threw, "Tampered ciphertext must cause GCM auth failure");
  pass("11.12 Tampered ciphertext → decrypt throws");
} catch (e) {
  fail("11.12 Tampered ciphertext → decrypt throws", e);
}

// 11.13: Wrong key → decryption fails
try {
  const key1 = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key1);
  const key2 = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key2);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode("Wrong key test");

  const ciphertext = await aesGcmEncrypt(key1, iv, plaintext);

  let threw = false;
  try {
    await aesGcmDecrypt(key2, iv, ciphertext);
  } catch {
    threw = true;
  }
  ok(threw, "Wrong key must cause GCM auth failure");
  pass("11.13 Wrong key → decrypt throws");
} catch (e) {
  fail("11.13 Wrong key → decrypt throws", e);
}

// =========================================================================
// Tests: 11.14–11.15 — HMAC-SHA256
// =========================================================================

console.log("\n=== HMAC-SHA256 ===\n");

// 11.14: HMAC with known key and data → 32-byte tag
try {
  const key = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key);
  const data = new TextEncoder().encode("HMAC test data");
  const tag = hmacSha256(key, data);
  strictEqual(tag.length, 32);
  ok(tag.some(b => b !== 0), "HMAC tag should not be all zeros");
  pass("11.14 HMAC-SHA256 → 32-byte tag");
} catch (e) {
  fail("11.14 HMAC-SHA256 → 32-byte tag", e);
}

// 11.15: Different key → different tag
try {
  const key1 = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key1);
  const key2 = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key2);
  const data = new TextEncoder().encode("Same data, different keys");
  const tag1 = hmacSha256(key1, data);
  const tag2 = hmacSha256(key2, data);
  ok(!bytesEqual(tag1, tag2), "Different keys must produce different HMAC tags");
  pass("11.15 Different key → different HMAC tag");
} catch (e) {
  fail("11.15 Different key → different HMAC tag", e);
}

// =========================================================================
// Tests: 11.16–11.18 — Key Agreement Pipeline
// =========================================================================

console.log("\n=== Key Agreement Pipeline ===\n");

// 11.16: Full encrypt→decrypt round-trip for CEK
try {
  // Simulate: publisher generates ephemeral key, recipient has Ed25519 identity
  const recipientEd = await generateKeypair();
  const recipientX25519Pub = ed25519PublicToX25519(recipientEd.publicKey);
  const recipientX25519Priv = ed25519PrivateToX25519(recipientEd.privateKey);

  const ephemeral = generateX25519Keypair();
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  // The CEK to distribute
  const cek = new Uint8Array(32);
  globalThis.crypto.getRandomValues(cek);

  // Publisher encrypts CEK for recipient
  const encryptedKey = await encryptKeyForRecipient({
    ephemeralPrivateKey: ephemeral.privateKey,
    recipientPublicKeyX25519: recipientX25519Pub,
    iv,
    secretKey: cek,
    recipientId: "alice",
    hkdfLabel: "hiri-cek-v1.1",
  });

  // Recipient decrypts CEK
  const recoveredCek = await decryptKeyFromSender({
    ownPrivateKeyX25519: recipientX25519Priv,
    ephemeralPublicKey: ephemeral.publicKey,
    iv,
    encryptedKey,
    recipientId: "alice",
    hkdfLabel: "hiri-cek-v1.1",
  });

  ok(bytesEqual(recoveredCek, cek), "Recovered CEK must match original");
  pass("11.16 Full pipeline encrypt→decrypt with CEK label");
} catch (e) {
  fail("11.16 Full pipeline encrypt→decrypt with CEK label", e);
}

// 11.17: Full encrypt→decrypt with HMAC label
try {
  const recipientEd = await generateKeypair();
  const recipientX25519Pub = ed25519PublicToX25519(recipientEd.publicKey);
  const recipientX25519Priv = ed25519PrivateToX25519(recipientEd.privateKey);

  const ephemeral = generateX25519Keypair();
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const hmacKey = new Uint8Array(32);
  globalThis.crypto.getRandomValues(hmacKey);

  const encryptedKey = await encryptKeyForRecipient({
    ephemeralPrivateKey: ephemeral.privateKey,
    recipientPublicKeyX25519: recipientX25519Pub,
    iv,
    secretKey: hmacKey,
    recipientId: "bob",
    hkdfLabel: "hiri-hmac-v1.1",
  });

  const recoveredKey = await decryptKeyFromSender({
    ownPrivateKeyX25519: recipientX25519Priv,
    ephemeralPublicKey: ephemeral.publicKey,
    iv,
    encryptedKey,
    recipientId: "bob",
    hkdfLabel: "hiri-hmac-v1.1",
  });

  ok(bytesEqual(recoveredKey, hmacKey), "Recovered HMAC key must match original");
  pass("11.17 Full pipeline encrypt→decrypt with HMAC label");
} catch (e) {
  fail("11.17 Full pipeline encrypt→decrypt with HMAC label", e);
}

// 11.18: Wrong recipientId → pipeline decrypt fails
try {
  const recipientEd = await generateKeypair();
  const recipientX25519Pub = ed25519PublicToX25519(recipientEd.publicKey);
  const recipientX25519Priv = ed25519PrivateToX25519(recipientEd.privateKey);

  const ephemeral = generateX25519Keypair();
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const cek = new Uint8Array(32);
  globalThis.crypto.getRandomValues(cek);

  // Encrypt for "alice"
  const encryptedKey = await encryptKeyForRecipient({
    ephemeralPrivateKey: ephemeral.privateKey,
    recipientPublicKeyX25519: recipientX25519Pub,
    iv,
    secretKey: cek,
    recipientId: "alice",
    hkdfLabel: "hiri-cek-v1.1",
  });

  // Decrypt with wrong recipientId "eve"
  let threw = false;
  try {
    await decryptKeyFromSender({
      ownPrivateKeyX25519: recipientX25519Priv,
      ephemeralPublicKey: ephemeral.publicKey,
      iv,
      encryptedKey,
      recipientId: "eve",
      hkdfLabel: "hiri-cek-v1.1",
    });
  } catch {
    threw = true;
  }
  ok(threw, "Wrong recipientId must cause GCM auth failure (domain separation)");
  pass("11.18 Wrong recipientId → pipeline decrypt fails");
} catch (e) {
  fail("11.18 Wrong recipientId → pipeline decrypt fails", e);
}

// =========================================================================
// Summary
// =========================================================================

console.log(`\n=== M11 Crypto Primitives: ${passed} passed, ${failed} failed ===\n`);

if (failed > 0) {
  process.exit(1);
}
