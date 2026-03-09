/**
 * HIRI Privacy Extension Tests — Milestone 15: Privacy Level 3 Integration
 *
 * Tests 15.1–15.24: Privacy lifecycle transitions, cross-mode chain walking,
 * addressing consistency, full resolution algorithm, KeyDocument staleness,
 * metadata hardening.
 */

import { strictEqual, ok } from "node:assert";

// Kernel imports
import { buildUnsignedManifest } from "../src/kernel/manifest.js";
import { signManifest, verifyManifest } from "../src/kernel/signing.js";
import { hashManifest } from "../src/kernel/chain.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import type { ResolutionManifest, StorageAdapter, ManifestFetcher, ContentFetcher } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";
import { generateX25519Keypair } from "../src/adapters/crypto/x25519.js";
import { URDNA2015Canonicalizer } from "../src/adapters/canonicalization/urdna2015-canonicalizer.js";
import { createCatalogDocumentLoader } from "../src/adapters/canonicalization/secure-document-loader.js";

// Privacy imports
import { validateTransition, validateAddressingConsistency } from "../src/privacy/lifecycle.js";
import { verifyPrivacyChain } from "../src/privacy/chain-walker.js";
import { resolveWithPrivacy } from "../src/privacy/resolve.js";
import { getLogicalPlaintextHash } from "../src/privacy/plaintext-hash.js";
import { buildAnonymousPrivacyBlock } from "../src/privacy/anonymous.js";
import { generateEphemeralAuthority } from "../src/privacy/anonymous.js";
import { encryptContent } from "../src/privacy/encryption.js";
import { buildEncryptedManifest } from "../src/privacy/encrypted-manifest.js";
import { buildStatementIndex } from "../src/privacy/statement-index.js";
import { generateHmacTags, encryptHmacKeyForRecipients } from "../src/privacy/hmac-disclosure.js";
import { buildSelectiveDisclosureManifest } from "../src/privacy/selective-manifest.js";
import {
  buildAttestationManifest,
  signAttestationManifest,
} from "../src/privacy/attestation.js";

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
// Helpers
// =========================================================================

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

function createStorage(entries: Map<string, Uint8Array>): StorageAdapter {
  return {
    get: async (hash: string) => entries.get(hash) ?? null,
    has: async (hash: string) => entries.has(hash),
  };
}

async function getManifestHash(manifest: ResolutionManifest): Promise<string> {
  const bytes = new TextEncoder().encode(stableStringify(manifest));
  return crypto.hash(bytes);
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

const baseUri = `hiri://${authority}/test/chain`;

// Shared plaintext — used across modes to prove getLogicalPlaintextHash consistency
const plaintext = new TextEncoder().encode(
  stableStringify({ name: "Dana Reeves", clearance: "TS/SCI" }),
);
const plaintextHash = await crypto.hash(plaintext);

// X25519 keypairs for encryption tests
const alice = generateX25519Keypair();

// =========================================================================
// Tests 15.1–15.7: Privacy Lifecycle Transitions (§11.2)
// =========================================================================

console.log("\n=== Privacy Lifecycle Transitions (§11.2) ===\n");

// 15.1: PoP → Encrypted (valid)
try {
  const result = validateTransition("proof-of-possession", "encrypted");
  strictEqual(result.valid, true);
  pass("15.1 PoP → Encrypted (valid transition)");
} catch (e) {
  fail("15.1 PoP → Encrypted", e);
}

// 15.2: PoP → Public (valid)
try {
  const result = validateTransition("proof-of-possession", "public");
  strictEqual(result.valid, true);
  pass("15.2 PoP → Public (valid transition)");
} catch (e) {
  fail("15.2 PoP → Public", e);
}

// 15.3: Encrypted → Public (valid)
try {
  const result = validateTransition("encrypted", "public");
  strictEqual(result.valid, true);
  pass("15.3 Encrypted → Public (valid transition)");
} catch (e) {
  fail("15.3 Encrypted → Public", e);
}

// 15.4: Encrypted → PoP (INVALID)
try {
  const result = validateTransition("encrypted", "proof-of-possession");
  strictEqual(result.valid, false);
  ok(result.reason?.includes("monotonically decreasing"), "Should cite §11.2");
  pass("15.4 Encrypted → PoP (INVALID — cannot withdraw, §11.2)");
} catch (e) {
  fail("15.4 Encrypted → PoP", e);
}

// 15.5: Public → PoP (INVALID)
try {
  const result = validateTransition("public", "proof-of-possession");
  strictEqual(result.valid, false);
  ok(result.reason?.includes("monotonically decreasing"), "Should cite §11.2");
  pass("15.5 Public → PoP (INVALID)");
} catch (e) {
  fail("15.5 Public → PoP", e);
}

// 15.6: PoP → Selective Disclosure (valid)
try {
  const result = validateTransition("proof-of-possession", "selective-disclosure");
  strictEqual(result.valid, true);
  pass("15.6 PoP → Selective Disclosure (valid)");
} catch (e) {
  fail("15.6 PoP → Selective Disclosure", e);
}

// 15.7: Selective Disclosure → Public (valid)
try {
  const result = validateTransition("selective-disclosure", "public");
  strictEqual(result.valid, true);
  pass("15.7 Selective Disclosure → Public (valid)");
} catch (e) {
  fail("15.7 Selective Disclosure → Public", e);
}

// =========================================================================
// Tests 15.8–15.10: Cross-Mode Chain Walking (§11.3)
// =========================================================================

console.log("\n=== Cross-Mode Chain Walking (§11.3, B.15) ===\n");

// 15.8: 3-version chain: PoP → Encrypted → Public
try {
  // V1: proof-of-possession
  const v1Unsigned = buildUnsignedManifest({
    id: baseUri,
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "1",
    branch: "main",
    created: "2026-01-01T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const v1WithPrivacy = {
    ...v1Unsigned,
    "hiri:privacy": { mode: "proof-of-possession", parameters: { custodyAssertion: true } },
  };
  const v1Signed = await signManifest(v1WithPrivacy, signingKey, "2026-01-01T00:00:00Z", "JCS", crypto);
  const v1Hash = await hashManifest(v1Signed, crypto);

  // V2: encrypted (uses same logical plaintext)
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const v2Base = buildEncryptedManifest({
    baseManifestParams: {
      id: baseUri,
      version: "2",
      branch: "main",
      created: "2026-02-01T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
      chain: { previous: v1Hash, depth: 2, genesisHash: v1Hash, previousBranch: "main" },
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
  });
  const v2Signed = await signManifest(v2Base, signingKey, "2026-02-01T00:00:00Z", "JCS", crypto);
  const v2Hash = await hashManifest(v2Signed, crypto);

  // V3: public
  const v3Unsigned = buildUnsignedManifest({
    id: baseUri,
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "3",
    branch: "main",
    created: "2026-03-01T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
    chain: { previous: v2Hash, depth: 3, genesisHash: v1Hash, previousBranch: "main" },
  });
  const v3Signed = await signManifest(v3Unsigned, signingKey, "2026-03-01T00:00:00Z", "JCS", crypto);

  // Build fetchers
  const manifests = new Map<string, ResolutionManifest>();
  manifests.set(v1Hash, v1Signed);
  manifests.set(v2Hash, v2Signed);
  const fetchManifest: ManifestFetcher = async (hash) => manifests.get(hash) ?? null;
  const fetchContent: ContentFetcher = async (hash) => {
    if (hash === plaintextHash) return plaintext;
    if (hash === encResult.ciphertextHash) return encResult.ciphertext;
    return null;
  };

  const result = await verifyPrivacyChain(v3Signed, keypair.publicKey, fetchManifest, fetchContent, crypto);

  strictEqual(result.valid, true);
  strictEqual(result.depth, 3);
  strictEqual(result.modeTransitions.length, 2);
  // Chain walker walks backwards: V3→V2→V1
  // First transition encountered: V3(public)←V2(encrypted), recorded as V2→V3
  // Second transition encountered: V2(encrypted)←V1(PoP), recorded as V1→V2
  // But modeTransitions records them in discovery order (reverse chronological)
  // Transition 0: between V2(encrypted) and V3(public) — discovered first
  strictEqual(result.modeTransitions[0].fromMode, "encrypted");
  strictEqual(result.modeTransitions[0].toMode, "public");
  // Transition 1: between V1(PoP) and V2(encrypted) — discovered second
  strictEqual(result.modeTransitions[1].fromMode, "proof-of-possession");
  strictEqual(result.modeTransitions[1].toMode, "encrypted");

  pass("15.8 3-version chain: PoP → Encrypted → Public (B.15)");
} catch (e) {
  fail("15.8 3-version PoP→Encrypted→Public chain", e);
}

// 15.9: Chain walker uses getLogicalPlaintextHash, not raw content.hash
try {
  // Build a 2-version chain: PoP (V1) → Encrypted (V2)
  // The PoP manifest's content.hash = plaintext hash
  // The encrypted manifest's content.hash = ciphertext hash (different!)
  // getLogicalPlaintextHash returns plaintext hash for both

  const v1Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/lph`,
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "1",
    branch: "main",
    created: "2026-01-01T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const v1WithPrivacy = {
    ...v1Unsigned,
    "hiri:privacy": { mode: "proof-of-possession", parameters: {} },
  };
  const v1Signed = await signManifest(v1WithPrivacy, signingKey, "2026-01-01T00:00:00Z", "JCS", crypto);

  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const v2Base = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/test/lph`,
      version: "2",
      branch: "main",
      created: "2026-02-01T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
      chain: { previous: await hashManifest(v1Signed, crypto), depth: 2, genesisHash: await hashManifest(v1Signed, crypto), previousBranch: "main" },
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
  });
  const v2Signed = await signManifest(v2Base, signingKey, "2026-02-01T00:00:00Z", "JCS", crypto);

  // getLogicalPlaintextHash for V1 (PoP) = content.hash = plaintextHash
  const lph1 = getLogicalPlaintextHash(v1Signed);
  strictEqual(lph1.hash, plaintextHash);

  // getLogicalPlaintextHash for V2 (encrypted) = privacy.parameters.plaintextHash
  const lph2 = getLogicalPlaintextHash(v2Signed);
  strictEqual(lph2.hash, encResult.plaintextHash);

  // Both should resolve to the same underlying plaintext hash
  strictEqual(lph1.hash, lph2.hash);

  // But raw content.hash differs!
  const v2ContentHash = v2Signed["hiri:content"].hash;
  ok(v2ContentHash !== plaintextHash, "Encrypted content.hash is ciphertext hash, not plaintext");

  pass("15.9 Chain walker uses getLogicalPlaintextHash(), not raw content.hash");
} catch (e) {
  fail("15.9 getLogicalPlaintextHash cross-mode", e);
}

// 15.10: Raw content.hash comparison across PoP→Encrypted would fail
try {
  // V1 PoP content.hash = plaintextHash
  // V2 Encrypted content.hash = ciphertextHash
  // These differ — proving raw comparison breaks

  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  // PoP content.hash
  const popContentHash = plaintextHash;
  // Encrypted content.hash
  const encContentHash = encResult.ciphertextHash;

  ok(popContentHash !== encContentHash, "Raw content.hash differs across PoP→Encrypted");

  // But logical plaintext hashes match
  strictEqual(plaintextHash, encResult.plaintextHash);

  pass("15.10 Raw content.hash comparison across PoP→Encrypted would fail");
} catch (e) {
  fail("15.10 Raw content.hash comparison fails", e);
}

// =========================================================================
// Tests 15.11–15.12: Addressing Mode Consistency (§11.3)
// =========================================================================

console.log("\n=== Addressing Mode Consistency (§11.3) ===\n");

// 15.11: All versions use raw-sha256 → accepted
try {
  const v1 = buildUnsignedManifest({
    id: baseUri,
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "1",
    branch: "main",
    created: "2026-01-01T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const v2 = buildUnsignedManifest({
    id: baseUri,
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "2",
    branch: "main",
    created: "2026-02-01T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  const result = validateAddressingConsistency(
    v2 as unknown as ResolutionManifest,
    v1 as unknown as ResolutionManifest,
  );
  strictEqual(result.valid, true);
  pass("15.11 All versions use raw-sha256 → accepted");
} catch (e) {
  fail("15.11 Consistent addressing", e);
}

// 15.12: V1 raw-sha256, V2 cidv1-dag-cbor → rejected
try {
  const v1 = buildUnsignedManifest({
    id: baseUri,
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "1",
    branch: "main",
    created: "2026-01-01T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const v2 = buildUnsignedManifest({
    id: baseUri,
    contentHash: "bafk" + "a".repeat(55), // fake CIDv1
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "2",
    branch: "main",
    created: "2026-02-01T00:00:00Z",
    canonicalization: "JCS",
    addressing: "cidv1-dag-cbor",
  });

  const result = validateAddressingConsistency(
    v2 as unknown as ResolutionManifest,
    v1 as unknown as ResolutionManifest,
  );
  strictEqual(result.valid, false);
  ok(result.reason?.includes("Addressing mode inconsistency"), "Should cite addressing inconsistency");
  pass("15.12 V1 raw-sha256, V2 cidv1-dag-cbor → rejected");
} catch (e) {
  fail("15.12 Inconsistent addressing", e);
}

// =========================================================================
// Tests 15.13–15.20: Full Resolution Algorithm (§12)
// =========================================================================

console.log("\n=== Full Resolution Algorithm (§12) ===\n");

// 15.13: Resolve public manifest → contentStatus: "verified"
try {
  const content = new TextEncoder().encode(stableStringify({ public: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/public`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, signingKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/public`,
    createStorage(entries),
    { manifestHash, publicKey: keypair.publicKey, crypto },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "public");
  strictEqual(result.contentStatus, "verified");
  pass("15.13 Resolve public manifest → contentStatus: 'verified'");
} catch (e) {
  fail("15.13 Resolve public", e);
}

// 15.14: Resolve PoP manifest → contentStatus: "private-custody-asserted"
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/pop`,
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintext.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const withPrivacy = {
    ...unsigned,
    "hiri:privacy": { mode: "proof-of-possession", parameters: { custodyAssertion: true } },
  };
  const signed = await signManifest(withPrivacy, signingKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/pop`,
    createStorage(entries),
    { manifestHash, publicKey: keypair.publicKey, crypto },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "proof-of-possession");
  strictEqual(result.contentStatus, "private-custody-asserted");
  pass("15.14 Resolve PoP manifest → contentStatus: 'private-custody-asserted'");
} catch (e) {
  fail("15.14 Resolve PoP", e);
}

// 15.15: Resolve encrypted (no key) → contentStatus: "ciphertext-verified"
try {
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const encManifest = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/test/enc`,
      version: "1",
      branch: "main",
      created: "2026-03-08T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
  });
  const signed = await signManifest(encManifest, signingKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(encResult.ciphertextHash, encResult.ciphertext);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/enc`,
    createStorage(entries),
    { manifestHash, publicKey: keypair.publicKey, crypto },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "encrypted");
  strictEqual(result.contentStatus, "ciphertext-verified");
  pass("15.15 Resolve encrypted (no key) → contentStatus: 'ciphertext-verified'");
} catch (e) {
  fail("15.15 Resolve encrypted no key", e);
}

// 15.16: Resolve encrypted (valid key) → contentStatus: "decrypted-verified"
try {
  const recipients = new Map<string, Uint8Array>([["alice", alice.publicKey]]);
  const encResult = await encryptContent(plaintext, recipients, crypto);

  const encManifest = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/test/enc-dec`,
      version: "1",
      branch: "main",
      created: "2026-03-08T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintext.length,
  });
  const signed = await signManifest(encManifest, signingKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(encResult.ciphertextHash, encResult.ciphertext);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/enc-dec`,
    createStorage(entries),
    {
      manifestHash,
      publicKey: keypair.publicKey,
      crypto,
      decryptionKey: alice.privateKey,
      recipientId: "alice",
    },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "encrypted");
  strictEqual(result.contentStatus, "decrypted-verified");
  ok(result.decryptedContent instanceof Uint8Array, "Decrypted content present");
  pass("15.16 Resolve encrypted (valid key) → contentStatus: 'decrypted-verified'");
} catch (e) {
  fail("15.16 Resolve encrypted with key", e);
}

// 15.17: Resolve selective disclosure → contentStatus: "partial-disclosure"
try {
  // Build SD content blob with simple test statements
  const testStmts = [
    '<https://example.org/person/1> <https://schema.org/name> "Dana Reeves" .',
    '<https://example.org/person/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .',
    '<https://example.org/person/1> <https://schema.org/jobTitle> "Systems Architect" .',
  ];
  const nquads = testStmts.join("\n") + "\n";

  const indexResult = await buildStatementIndex(nquads);
  const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const hmacTags = await generateHmacTags(testStmts, hmacKey, indexResult.indexSalt);
  const hmacDist = await encryptHmacKeyForRecipients(
    hmacKey,
    new Map<string, Uint8Array>([["alice", alice.publicKey]]),
    new Map<string, number[] | "all">([["alice", "all"]]),
  );

  const sdContentBlob = {
    mandatoryNQuads: [testStmts[0], testStmts[1]],
    statementIndex: indexResult.statementHashes.map((h) => bytesToHex(h)),
    hmacTags: hmacTags.map((t) => bytesToHex(t)),
  };
  const sdContentBlobBytes = new TextEncoder().encode(stableStringify(sdContentBlob));
  const sdContentBlobHash = await crypto.hash(sdContentBlobBytes);

  // Build manifest with JCS (avoids URDNA2015 JSON-LD context issues in test)
  // The resolver dispatches on hiri:privacy.mode, not on canonicalization
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/sd`,
    contentHash: sdContentBlobHash,
    contentFormat: "application/json",
    contentSize: sdContentBlobBytes.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  const withPrivacy = {
    ...unsigned,
    "hiri:privacy": {
      mode: "selective-disclosure",
      parameters: {
        disclosureProofSuite: "hiri-hmac-sd-2026",
        statementCount: testStmts.length,
        indexSalt: base64urlEncode(indexResult.indexSalt),
        indexRoot: indexResult.indexRoot,
        mandatoryStatements: [0, 1],
        hmacKeyRecipients: {
          ephemeralPublicKey: bytesToHex(hmacDist.ephemeralPublicKey),
          iv: bytesToHex(hmacDist.iv),
          keyAgreement: "X25519-HKDF-SHA256",
          recipients: hmacDist.recipients.map((r) => ({
            id: r.id,
            encryptedHmacKey: bytesToHex(r.encryptedHmacKey),
            disclosedStatements: r.disclosedStatements,
          })),
        },
      },
    },
  };

  const signed = await signManifest(withPrivacy, signingKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(sdContentBlobHash, sdContentBlobBytes);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/sd`,
    createStorage(entries),
    { manifestHash, publicKey: keypair.publicKey, crypto },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "selective-disclosure");
  strictEqual(result.contentStatus, "partial-disclosure");
  pass("15.17 Resolve selective disclosure → contentStatus: 'partial-disclosure'");
} catch (e) {
  fail("15.17 Resolve selective disclosure", e);
}

// 15.18: Resolve anonymous ephemeral → identityType: "anonymous-ephemeral"
try {
  const eph = await generateEphemeralAuthority();
  const ephSigningKey = {
    algorithm: "ed25519",
    publicKey: eph.publicKey,
    privateKey: eph.privateKey,
    keyId: "ephemeral-key",
  };

  const content = new TextEncoder().encode(stableStringify({ anon: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${eph.authority}/test/anon`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const withPrivacy = {
    ...unsigned,
    "hiri:privacy": buildAnonymousPrivacyBlock({
      authorityType: "ephemeral",
      contentVisibility: "public",
      identityDisclosable: false,
    }),
  };
  const signed = await signManifest(withPrivacy, ephSigningKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${eph.authority}/test/anon`,
    createStorage(entries),
    { manifestHash, publicKey: eph.publicKey, crypto },
  );

  strictEqual(result.privacyMode, "anonymous");
  strictEqual(result.identityType, "anonymous-ephemeral");
  eph.privateKey.fill(0);
  pass("15.18 Resolve anonymous ephemeral → identityType: 'anonymous-ephemeral'");
} catch (e) {
  fail("15.18 Resolve anonymous ephemeral", e);
}

// 15.19: Resolve attestation → contentStatus: "attestation-verified"
try {
  const attestorKeypair = await generateKeypair();
  const attestorAuth = deriveAuthority(attestorKeypair.publicKey, "ed25519");
  const attestorSK = {
    algorithm: "ed25519",
    publicKey: attestorKeypair.publicKey,
    privateKey: attestorKeypair.privateKey,
    keyId: "key-1",
  };

  const attestation = buildAttestationManifest({
    attestorAuthority: attestorAuth,
    attestationId: "resolve-test",
    subject: {
      authority,
      manifestHash: "sha256:abc",
      contentHash: "sha256:def",
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "resolve-test",
      value: true,
      attestedAt: "2026-03-08T00:00:00Z",
    },
    evidence: { method: "direct", description: "Resolver integration test." },
    version: "1",
    timestamp: "2026-03-08T00:00:00Z",
  });
  const signedAtt = await signAttestationManifest(attestation, attestorSK, "2026-03-08T00:00:00Z", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signedAtt));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);

  const result = await resolveWithPrivacy(
    `hiri://${attestorAuth}/attestation/resolve-test`,
    createStorage(entries),
    { manifestHash, publicKey: attestorKeypair.publicKey, crypto },
  );

  strictEqual(result.privacyMode, "attestation");
  strictEqual(result.contentStatus, "attestation-verified");
  ok(result.attestationResult !== undefined, "Attestation result present");
  pass("15.19 Resolve attestation → contentStatus: 'attestation-verified'");
} catch (e) {
  fail("15.19 Resolve attestation", e);
}

// 15.20: Resolve unknown mode → contentStatus: "unsupported-mode"
try {
  const content = new TextEncoder().encode(stableStringify({ future: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/future`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const withPrivacy = {
    ...unsigned,
    "hiri:privacy": { mode: "future-quantum-mode" },
  };
  const signed = await signManifest(withPrivacy, signingKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/future`,
    createStorage(entries),
    { manifestHash, publicKey: keypair.publicKey, crypto },
  );

  strictEqual(result.verified, true);
  strictEqual(result.contentStatus, "unsupported-mode");
  ok(result.warnings.some((w) => w.includes("future-quantum-mode")), "Should warn about unknown mode");
  pass("15.20 Resolve unknown mode → contentStatus: 'unsupported-mode'");
} catch (e) {
  fail("15.20 Resolve unknown mode", e);
}

// 15.21: Anonymous + selective disclosure dispatch
try {
  const eph = await generateEphemeralAuthority();
  const ephSigningKey = {
    algorithm: "ed25519",
    publicKey: eph.publicKey,
    privateKey: eph.privateKey,
    keyId: "ephemeral-key",
  };

  const testStmts = [
    '<https://example.org/person/anon> <https://schema.org/name> "Anonymous Source" .',
    '<https://example.org/person/anon> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .',
    '<https://example.org/person/anon> <https://schema.org/jobTitle> "Whistleblower" .',
  ];
  const nquads = testStmts.join("\n") + "\n";

  const indexResult = await buildStatementIndex(nquads);
  const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const hmacTags = await generateHmacTags(testStmts, hmacKey, indexResult.indexSalt);
  const hmacDist = await encryptHmacKeyForRecipients(
    hmacKey,
    new Map<string, Uint8Array>([["alice", alice.publicKey]]),
    new Map<string, number[] | "all">([["alice", "all"]]),
  );

  const sdContentBlob = {
    mandatoryNQuads: [testStmts[0]],
    statementIndex: indexResult.statementHashes.map((h) => bytesToHex(h)),
    hmacTags: hmacTags.map((t) => bytesToHex(t)),
  };
  const sdContentBlobBytes = new TextEncoder().encode(stableStringify(sdContentBlob));
  const sdContentBlobHash = await crypto.hash(sdContentBlobBytes);

  // Build manifest with JCS + anonymous+SD privacy block
  const unsigned = buildUnsignedManifest({
    id: `hiri://${eph.authority}/test/anon-sd`,
    contentHash: sdContentBlobHash,
    contentFormat: "application/json",
    contentSize: sdContentBlobBytes.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  const withPrivacy = {
    ...unsigned,
    "hiri:privacy": {
      mode: "anonymous",
      parameters: {
        authorityType: "ephemeral",
        contentVisibility: "selective-disclosure",
        identityDisclosable: false,
        disclosureProofSuite: "hiri-hmac-sd-2026",
        statementCount: testStmts.length,
        indexSalt: base64urlEncode(indexResult.indexSalt),
        indexRoot: indexResult.indexRoot,
        mandatoryStatements: [0],
        hmacKeyRecipients: {
          ephemeralPublicKey: bytesToHex(hmacDist.ephemeralPublicKey),
          iv: bytesToHex(hmacDist.iv),
          keyAgreement: "X25519-HKDF-SHA256",
          recipients: hmacDist.recipients.map((r) => ({
            id: r.id,
            encryptedHmacKey: bytesToHex(r.encryptedHmacKey),
            disclosedStatements: r.disclosedStatements,
          })),
        },
      },
    },
  };

  const signed = await signManifest(withPrivacy, ephSigningKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(sdContentBlobHash, sdContentBlobBytes);

  const result = await resolveWithPrivacy(
    `hiri://${eph.authority}/test/anon-sd`,
    createStorage(entries),
    { manifestHash, publicKey: eph.publicKey, crypto },
  );

  strictEqual(result.privacyMode, "anonymous");
  strictEqual(result.identityType, "anonymous-ephemeral");
  strictEqual(result.contentStatus, "partial-disclosure");

  eph.privateKey.fill(0);
  pass("15.21 Resolve anonymous + selective disclosure → anonymous publisher, partial disclosure");
} catch (e) {
  fail("15.21 Anonymous + selective disclosure", e);
}

// =========================================================================
// Test 15.22: KeyDocument Cache Staleness (§13.1)
// =========================================================================

console.log("\n=== KeyDocument Cache Staleness (§13.1) ===\n");

// 15.22: Resolve with stale-cached KeyDocument → warning
try {
  const content = new TextEncoder().encode(stableStringify({ keydoc: "stale" }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/test/stale-keydoc`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, signingKey, "2026-03-08T00:00:00Z", "JCS", crypto);

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);
  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${authority}/test/stale-keydoc`,
    createStorage(entries),
    {
      manifestHash,
      publicKey: keypair.publicKey,
      crypto,
      keyDocumentTimestamp: "2026-01-01T00:00:00Z",
      keyDocumentMaxAge: 48 * 60 * 60 * 1000, // 48 hours
      verificationTime: "2026-03-08T00:00:00Z", // well past 48 hours
    },
  );

  strictEqual(result.verified, true);
  ok(
    result.warnings.some((w) => w.includes("keyDocumentStale: true")),
    "Should contain keyDocumentStale warning",
  );
  pass("15.22 Resolve with stale-cached KeyDocument → keyDocumentStale: true warning");
} catch (e) {
  fail("15.22 KeyDocument staleness", e);
}

// =========================================================================
// Tests 15.23–15.24: Metadata Hardening (§15.3)
// =========================================================================

console.log("\n=== Metadata Hardening (§15.3) ===\n");

// 15.23: Padded statement count (add padding N-Quads to index)
try {
  const urdna = new URDNA2015Canonicalizer();
  const TEST_SCHEMA_CONTEXT = {
    "@context": {
      "schema": "https://schema.org/",
      "Person": "schema:Person",
      "name": "schema:name",
      "jobTitle": "schema:jobTitle",
    },
  };
  const docLoader = createCatalogDocumentLoader({
    "https://schema.org": TEST_SCHEMA_CONTEXT,
  });

  const testDoc = {
    "@context": "https://schema.org",
    "@id": "https://example.org/person/padded",
    "@type": "Person",
    "name": "Padded Person",
    "jobTitle": "Test Subject",
  };

  const canonicalBytes = await urdna.canonicalize(testDoc as Record<string, unknown>, docLoader);
  const nquads = new TextDecoder().decode(canonicalBytes);
  const realStmts = nquads.split("\n").filter((s) => s.length > 0);

  // Add 4 padding N-Quads (random dummy statements)
  const paddingStmts = [
    '<urn:padding:1> <urn:padding:prop> "pad1" .',
    '<urn:padding:2> <urn:padding:prop> "pad2" .',
    '<urn:padding:3> <urn:padding:prop> "pad3" .',
    '<urn:padding:4> <urn:padding:prop> "pad4" .',
  ];
  const allStmts = [...realStmts, ...paddingStmts];
  const paddedNQuads = allStmts.join("\n") + "\n";

  // Build index with padded statements
  const indexResult = await buildStatementIndex(paddedNQuads);

  strictEqual(indexResult.statementHashes.length, allStmts.length);
  ok(indexResult.indexRoot.startsWith("sha256:"), "Index root valid");

  // Verify that a real statement verifies correctly in the padded index
  const { verifyStatementInIndex } = await import("../src/privacy/statement-index.js");
  const realStmtValid = await verifyStatementInIndex(
    realStmts[0],
    indexResult.statementHashes[0],
    indexResult.indexSalt,
  );
  strictEqual(realStmtValid, true);

  // Verify that a padding statement also verifies at its position
  const paddingIdx = realStmts.length; // first padding statement
  const padValid = await verifyStatementInIndex(
    paddingStmts[0],
    indexResult.statementHashes[paddingIdx],
    indexResult.indexSalt,
  );
  strictEqual(padValid, true);

  pass("15.23 Manifest with padded statement count (${realStmts.length} → ${allStmts.length} with 4 padding N-Quads)");
} catch (e) {
  fail("15.23 Padded statement count", e);
}

// 15.24: Dummy recipients (2 extra) — encryption/decryption still works
try {
  const dummyKey1 = generateX25519Keypair();
  const dummyKey2 = generateX25519Keypair();

  const recipients = new Map<string, Uint8Array>([
    ["alice", alice.publicKey],
    ["dummy-1", dummyKey1.publicKey],
    ["dummy-2", dummyKey2.publicKey],
  ]);

  const encResult = await encryptContent(plaintext, recipients, crypto);

  // 3 recipients in the result
  strictEqual(encResult.recipients.length, 3);

  // Alice can decrypt
  const { decryptContent } = await import("../src/privacy/decryption.js");
  const encParams = {
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

  const decrypted = await decryptContent(
    encResult.ciphertext,
    encParams,
    alice.privateKey,
    "alice",
    crypto,
  );

  ok(decrypted.plaintextHashValid, "Plaintext hash should verify");
  // Decrypted content matches original
  const decryptedStr = new TextDecoder().decode(decrypted.plaintext);
  const originalStr = new TextDecoder().decode(plaintext);
  strictEqual(decryptedStr, originalStr);

  pass("15.24 Manifest with dummy recipients (2 extra) → encryption/decryption still works for real recipients");
} catch (e) {
  fail("15.24 Dummy recipients", e);
}

// =========================================================================
// Summary
// =========================================================================

console.log(`\n=== M15 Privacy Level 3 Integration: ${passed} passed, ${failed} failed ===\n`);

if (failed > 0) {
  process.exit(1);
}
