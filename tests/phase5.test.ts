/**
 * HIRI Protocol Tests — Phase 5: The Sovereign Authority
 *
 * Milestone 5 test cases 5.1–5.13.
 * Proves that key lifecycle (rotation, revocation, grace periods)
 * is correctly enforced across the verification pipeline.
 *
 * Uses the existing test harness pattern (counter-based, checkmark markers).
 */

import { strictEqual, ok } from "node:assert";
import { dirname, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";

// Kernel imports
import { resolveSigningKey, verifyManifestWithKeyLifecycle, verifyRotationProof } from "../src/kernel/key-lifecycle.js";
import { verifyChainWithKeyLifecycle } from "../src/kernel/chain.js";
import { hashManifest } from "../src/kernel/chain.js";
import { resolve } from "../src/kernel/resolve.js";
import type { VerifiedContent } from "../src/kernel/resolve.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import { deriveAuthorityAsync } from "../src/kernel/authority.js";
import { buildUnsignedManifest, buildKeyDocument, prepareContent } from "../src/kernel/manifest.js";
import { signManifest, signKeyDocument } from "../src/kernel/signing.js";
import { encode as base58Encode } from "../src/kernel/base58.js";
import type {
  KeyDocument,
  ResolutionManifest,
  RotatedKey,
  RotationClaim,
  ManifestFetcher,
  ContentFetcher,
} from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";
import { InMemoryStorageAdapter } from "../src/adapters/persistence/storage.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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
// Shared Setup
// =========================================================================

const crypto = defaultCryptoProvider;

// Generate 3 keypairs
const keyA = await generateKeypair("key-1");
const keyB = await generateKeypair("key-2");
const keyC = await generateKeypair("key-3");

// Authority derived from Key A (genesis key) — persists through all rotations
const authority = await deriveAuthorityAsync(keyA.publicKey, "ed25519", crypto);

// Multibase-encode public keys (z prefix + base58)
const keyAMultibase = "z" + base58Encode(keyA.publicKey);
const keyBMultibase = "z" + base58Encode(keyB.publicKey);
const keyCMultibase = "z" + base58Encode(keyC.publicKey);

const keyDocUri = `hiri://${authority}/key/main`;

// =========================================================================
// Build Full-Lifecycle KeyDocument
// =========================================================================

const unsignedKeyDoc = buildKeyDocument({
  authority,
  authorityType: "key",
  version: 3,
  activeKeys: [
    {
      "@id": `${keyDocUri}#key-3`,
      "@type": "Ed25519VerificationKey2020",
      controller: keyDocUri,
      publicKeyMultibase: keyCMultibase,
      purposes: ["assertionMethod"],
      validFrom: "2025-07-01T00:00:00Z",
    },
  ],
  rotatedKeys: [
    {
      "@id": `${keyDocUri}#key-2`,
      rotatedAt: "2025-07-01T00:00:00Z",
      rotatedTo: `${keyDocUri}#key-3`,
      reason: "scheduled-rotation",
      verifyUntil: "2025-12-31T00:00:00Z",
      publicKeyMultibase: keyBMultibase,
      // rotationProof added below after signing
    },
  ],
  revokedKeys: [
    {
      "@id": `${keyDocUri}#key-1`,
      revokedAt: "2025-03-01T00:00:00Z",
      reason: "compromise-suspected",
      manifestsInvalidAfter: "2025-02-15T00:00:00Z",
      publicKeyMultibase: keyAMultibase,
    },
  ],
  policies: {
    // Grace expiry = rotatedAt(2025-07-01) + P183D = 2025-12-31T00:00:00Z. Matches verifyUntil.
    gracePeriodAfterRotation: "P183D",
    minimumKeyValidity: "P365D",
  },
});

// Sign KeyDocument with current active key (Key C)
const keyDoc: KeyDocument = await signKeyDocument(unsignedKeyDoc, keyC, "2025-07-01T00:00:00Z", crypto);

// =========================================================================
// Build Rotation Proof for Test 5.11
// =========================================================================

const rotationClaim: RotationClaim = {
  oldKeyId: `${keyDocUri}#key-2`,
  newKeyId: `${keyDocUri}#key-3`,
  rotatedAt: "2025-07-01T00:00:00Z",
  reason: "scheduled-rotation",
};

const claimBytes = new TextEncoder().encode(stableStringify(rotationClaim, false));
const oldKeySig = await crypto.sign(claimBytes, keyB.privateKey);
const newKeySig = await crypto.sign(claimBytes, keyC.privateKey);

// Build KeyDocument WITH rotation proof for test 5.11
const unsignedKeyDocWithProof = buildKeyDocument({
  authority,
  authorityType: "key",
  version: 3,
  activeKeys: unsignedKeyDoc["hiri:activeKeys"],
  rotatedKeys: [
    {
      "@id": `${keyDocUri}#key-2`,
      rotatedAt: "2025-07-01T00:00:00Z",
      rotatedTo: `${keyDocUri}#key-3`,
      reason: "scheduled-rotation",
      verifyUntil: "2025-12-31T00:00:00Z",
      publicKeyMultibase: keyBMultibase,
      rotationProof: [
        {
          purpose: "old-key-authorizes-rotation",
          verificationMethod: `${keyDocUri}#key-2`,
          proofValue: "z" + base58Encode(oldKeySig),
        },
        {
          purpose: "new-key-confirms-rotation",
          verificationMethod: `${keyDocUri}#key-3`,
          proofValue: "z" + base58Encode(newKeySig),
        },
      ],
    },
  ],
  revokedKeys: unsignedKeyDoc["hiri:revokedKeys"],
  policies: unsignedKeyDoc["hiri:policies"],
});
const keyDocWithProof: KeyDocument = await signKeyDocument(unsignedKeyDocWithProof, keyC, "2025-07-01T00:00:00Z", crypto);

// =========================================================================
// Build Timeline Manifests (M-V1 through M-V5)
// =========================================================================

const resourceId = "lifecycle-test";
const resourceUri = `hiri://${authority}/data/${resourceId}`;

// Shared content (same for all versions in standalone tests)
const contentObj = { "@id": resourceUri, "name": "Lifecycle Test" };
const contentStr = stableStringify(contentObj, false);
const contentBytes = new TextEncoder().encode(contentStr);
const contentHash = await crypto.hash(contentBytes);

/**
 * Build and sign a standalone manifest (no chain) at a given version.
 */
async function buildManifest(
  version: number,
  signingKey: typeof keyA,
  timestamp: string,
): Promise<ResolutionManifest> {
  const unsigned = buildUnsignedManifest({
    id: resourceUri,
    version,
    branch: "main",
    created: timestamp,
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
  });
  return signManifest(unsigned, signingKey, timestamp, crypto);
}

// M-V1: Signed by Key A at 2025-01-15 (before invalidation point 2025-02-15)
const mV1 = await buildManifest(1, keyA, "2025-01-15T00:00:00Z");

// M-V2: Signed by Key A at 2025-02-20 (after invalidation point, before revocation)
const mV2 = await buildManifest(2, keyA, "2025-02-20T00:00:00Z");

// M-V3: Signed by Key B at 2025-05-01 (Key B active)
const mV3 = await buildManifest(3, keyB, "2025-05-01T00:00:00Z");

// M-V4: Signed by Key B at 2025-08-01 (Key B rotated, within grace)
const mV4 = await buildManifest(4, keyB, "2025-08-01T00:00:00Z");

// M-V5: Signed by Key C at 2025-08-01 (Key C active)
const mV5 = await buildManifest(5, keyC, "2025-08-01T00:00:00Z");

// Test 5.4 needs a manifest signed by Key A AFTER revocation
const mV4Revoked = await buildManifest(4, keyA, "2025-04-01T00:00:00Z");

// =========================================================================
// Build Chained Manifests for Tests 5.9, 5.10, 5.13
// =========================================================================

// Chain for 5.9: V3 (Key B) → V5 (Key C) — 2-manifest chain
const mV3Genesis = await buildManifest(1, keyB, "2025-05-01T00:00:00Z");
const mV3GenesisHash = await hashManifest(mV3Genesis, crypto);

const mV5ChainedUnsigned = buildUnsignedManifest({
  id: resourceUri,
  version: 2,
  branch: "main",
  created: "2025-08-01T00:00:00Z",
  contentHash,
  contentFormat: "application/ld+json",
  contentSize: contentBytes.length,
  canonicalization: "JCS",
  chain: {
    previous: mV3GenesisHash,
    previousBranch: "main",
    genesisHash: mV3GenesisHash,
    depth: 2,
  },
});
const mV5Chained = await signManifest(mV5ChainedUnsigned, keyC, "2025-08-01T00:00:00Z", crypto);

// Chain for 5.10: V1 (Key A) → V2 (Key A) → V3 (Key B) — 3-manifest chain
const mChainV1 = await buildManifest(1, keyA, "2025-01-15T00:00:00Z");
const mChainV1Hash = await hashManifest(mChainV1, crypto);

const mChainV2Unsigned = buildUnsignedManifest({
  id: resourceUri,
  version: 2,
  branch: "main",
  created: "2025-02-20T00:00:00Z",
  contentHash,
  contentFormat: "application/ld+json",
  contentSize: contentBytes.length,
  canonicalization: "JCS",
  chain: {
    previous: mChainV1Hash,
    previousBranch: "main",
    genesisHash: mChainV1Hash,
    depth: 2,
  },
});
const mChainV2 = await signManifest(mChainV2Unsigned, keyA, "2025-02-20T00:00:00Z", crypto);
const mChainV2Hash = await hashManifest(mChainV2, crypto);

const mChainV3Unsigned = buildUnsignedManifest({
  id: resourceUri,
  version: 3,
  branch: "main",
  created: "2025-05-01T00:00:00Z",
  contentHash,
  contentFormat: "application/ld+json",
  contentSize: contentBytes.length,
  canonicalization: "JCS",
  chain: {
    previous: mChainV2Hash,
    previousBranch: "main",
    genesisHash: mChainV1Hash,
    depth: 3,
  },
});
const mChainV3 = await signManifest(mChainV3Unsigned, keyB, "2025-05-01T00:00:00Z", crypto);

// =========================================================================
// Milestone 5 Tests
// =========================================================================

console.log("--- Milestone 5 Tests ---");

// 5.1: Active key signs — valid
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV5, keyDoc, "2025-09-01T00:00:00Z", crypto,
  );
  strictEqual(result.valid, true);
  strictEqual(result.keyStatus, "active");
  strictEqual(result.keyId, "key-3");
  strictEqual(result.warning, undefined);

  pass("5.1: Active key (Key C) signs manifest — valid, status='active'");
} catch (e) { fail("5.1: Active key (Key C) signs manifest — valid, status='active'", e); }

// 5.2: Rotated key within grace — valid with warning
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV4, keyDoc, "2025-08-15T00:00:00Z", crypto,
  );
  strictEqual(result.valid, true);
  strictEqual(result.keyStatus, "rotated-grace");
  strictEqual(result.keyId, "key-2");
  ok(result.warning?.includes("rotated key"), "Should include grace period warning");

  pass("5.2: Rotated key within grace period — valid with warning");
} catch (e) { fail("5.2: Rotated key within grace period — valid with warning", e); }

// 5.3: Rotated key after grace — rejected
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV4, keyDoc, "2026-02-01T00:00:00Z", crypto,
  );
  strictEqual(result.valid, false);
  strictEqual(result.keyStatus, "rotated-expired");
  strictEqual(result.keyId, "key-2");

  pass("5.3: Rotated key after grace period — rejected, status='rotated-expired'");
} catch (e) { fail("5.3: Rotated key after grace period — rejected, status='rotated-expired'", e); }

// 5.4: Revoked key — manifest signed after revocation — rejected
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV4Revoked, keyDoc, "2025-09-01T00:00:00Z", crypto,
  );
  strictEqual(result.valid, false);
  strictEqual(result.keyStatus, "revoked");
  strictEqual(result.keyId, "key-1");

  pass("5.4: Revoked key, signed after invalidation point — rejected");
} catch (e) { fail("5.4: Revoked key, signed after invalidation point — rejected", e); }

// 5.5: Revoked key — past signature before invalidation — valid with warning
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV1, keyDoc, "2025-09-01T00:00:00Z", crypto,
  );
  strictEqual(result.valid, true);
  strictEqual(result.keyStatus, "revoked");
  strictEqual(result.keyId, "key-1");
  ok(result.warning?.includes("predates invalidation"), "Should mention predates invalidation");

  pass("5.5: Revoked key, signature before invalidation — valid with warning");
} catch (e) { fail("5.5: Revoked key, signature before invalidation — valid with warning", e); }

// 5.6: CRITICAL GATE — Retroactive revocation
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV2, keyDoc, "2025-09-01T00:00:00Z", crypto,
  );
  strictEqual(result.valid, false, "Retroactive revocation must reject");
  strictEqual(result.keyStatus, "revoked");
  strictEqual(result.keyId, "key-1");

  pass("5.6: Retroactive revocation — signature after invalidation point rejected");
} catch (e) { fail("5.6: Retroactive revocation — signature after invalidation point rejected", e); }

// 5.7: Grace period boundary (−1 second) — valid
// Grace expiry = rotatedAt(2025-07-01) + P183D = 2025-12-31T00:00:00Z. Probe at -1s.
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV4, keyDoc, "2025-12-30T23:59:59Z", crypto,
  );
  strictEqual(result.valid, true);
  strictEqual(result.keyStatus, "rotated-grace");

  pass("5.7: Grace period boundary −1s — valid (rotated-grace)");
} catch (e) { fail("5.7: Grace period boundary −1s — valid (rotated-grace)", e); }

// 5.8: Grace period boundary (+1 second) — rejected
// Grace expiry = 2025-12-31T00:00:00Z. Probe at +1s.
try {
  const result = await verifyManifestWithKeyLifecycle(
    mV4, keyDoc, "2025-12-31T00:00:01Z", crypto,
  );
  strictEqual(result.valid, false);
  strictEqual(result.keyStatus, "rotated-expired");

  pass("5.8: Grace period boundary +1s — rejected (rotated-expired)");
} catch (e) { fail("5.8: Grace period boundary +1s — rejected (rotated-expired)", e); }

// 5.9: Chain with rotation (V3→V5, Key B→Key C) — both valid
try {
  const manifests = new Map<string, ResolutionManifest>();
  manifests.set(mV3GenesisHash, mV3Genesis);

  const fetchManifest: ManifestFetcher = async (hash) => manifests.get(hash) ?? null;
  const fetchContent: ContentFetcher = async () => null; // No deltas

  const result = await verifyChainWithKeyLifecycle(
    mV5Chained, keyDoc, "2025-09-01T00:00:00Z",
    fetchManifest, fetchContent, crypto,
  );

  strictEqual(result.valid, true, "Both signatures should be valid");
  strictEqual(result.depth, 2);
  // V3 (genesis) signed by Key B (active at 2025-05-01) should produce a grace warning
  // since Key B is now rotated, verification at 2025-09-01 is within grace
  ok(result.warnings.length > 0, "Should have grace period warning for Key B");

  pass("5.9: Chain with rotation (Key B→Key C) — both signatures valid, depth=2");
} catch (e) { fail("5.9: Chain with rotation (Key B→Key C) — both signatures valid, depth=2", e); }

// 5.10: CRITICAL GATE — Chain with retroactive revocation
// V1 (Key A, before invalidation) → V2 (Key A, after invalidation) → V3 (Key B)
// Expected: V3 valid, V2 invalid (retroactive revocation), V1 valid
try {
  const manifests = new Map<string, ResolutionManifest>();
  manifests.set(mChainV1Hash, mChainV1);
  manifests.set(mChainV2Hash, mChainV2);

  const fetchManifest: ManifestFetcher = async (hash) => manifests.get(hash) ?? null;
  const fetchContent: ContentFetcher = async () => null;

  const result = await verifyChainWithKeyLifecycle(
    mChainV3, keyDoc, "2025-09-01T00:00:00Z",
    fetchManifest, fetchContent, crypto,
  );

  strictEqual(result.valid, false, "Chain should be invalid due to V2");
  strictEqual(result.depth, 3, "Should walk all 3 manifests");
  ok(result.failures !== undefined, "Should have failures array");
  ok(result.failures!.length >= 1, "Should have at least 1 failure");

  // V2 should be the failure point
  const v2Failure = result.failures!.find(f => f.version === 2);
  ok(v2Failure !== undefined, "V2 should be the failure point");
  strictEqual(v2Failure!.keyStatus, "revoked");
  strictEqual(v2Failure!.keyId, "key-1");

  pass("5.10: Chain with retroactive revocation — V2 is failure point, V1 and V3 valid");
} catch (e) { fail("5.10: Chain with retroactive revocation — V2 is failure point, V1 and V3 valid", e); }

// 5.11: Dual-signature rotation proof
try {
  const rotatedEntry = keyDocWithProof["hiri:rotatedKeys"][0];
  const result = await verifyRotationProof(rotatedEntry, keyDocWithProof, crypto);
  strictEqual(result, true, "Both rotation signatures should verify");

  pass("5.11: Dual-signature rotation proof — both old and new key signatures verify");
} catch (e) { fail("5.11: Dual-signature rotation proof — both old and new key signatures verify", e); }

// 5.12: Unknown key — #key-99 not in any list
try {
  // Create a manifest that claims to be signed by key-99
  const fakeUnsigned = buildUnsignedManifest({
    id: resourceUri,
    version: 99,
    branch: "main",
    created: "2025-09-01T00:00:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
  });
  // Sign with Key A but manually set keyId to "key-99"
  const fakeKey = { ...keyA, keyId: "key-99" };
  const fakeManifest = await signManifest(fakeUnsigned, fakeKey, "2025-09-01T00:00:00Z", crypto);

  const result = resolveSigningKey(fakeManifest, keyDoc, "2025-09-01T00:00:00Z");
  strictEqual(result.valid, false);
  strictEqual(result.keyStatus, "unknown");
  strictEqual(result.keyId, "key-99");

  pass("5.12: Unknown key (#key-99) — rejected, status='unknown'");
} catch (e) { fail("5.12: Unknown key (#key-99) — rejected, status='unknown'", e); }

// 5.13: Resolver integration — V3→V5 chain via resolve() with keyDocument
try {
  const adapter = new InMemoryStorageAdapter();

  // Store manifests
  const mV5ChainedCanonical = stableStringify(mV5Chained, false);
  const mV5ChainedBytes = new TextEncoder().encode(mV5ChainedCanonical);
  const mV5ChainedHash = await crypto.hash(mV5ChainedBytes);
  await adapter.put(mV5ChainedHash, mV5ChainedBytes);

  const mV3GenesisCanonical = stableStringify(mV3Genesis, false);
  const mV3GenesisBytes = new TextEncoder().encode(mV3GenesisCanonical);
  await adapter.put(mV3GenesisHash, mV3GenesisBytes);

  // Store content
  await adapter.put(contentHash, contentBytes);

  const resolved: VerifiedContent = await resolve(resourceUri, adapter, {
    crypto,
    publicKey: keyA.publicKey, // Genesis key for authority derivation
    manifestHash: mV5ChainedHash,
    keyDocument: keyDoc,
    verificationTime: "2025-09-01T00:00:00Z",
  });

  ok(resolved.content.length > 0, "Should return content");
  ok(resolved.warnings !== undefined, "Should have warnings array");
  ok(resolved.warnings!.length > 0, "Should have at least one grace-period warning");

  pass("5.13: Resolver integration — VerifiedContent with key lifecycle warnings");
} catch (e) { fail("5.13: Resolver integration — VerifiedContent with key lifecycle warnings", e); }

// =========================================================================
// Summary
// =========================================================================

console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
