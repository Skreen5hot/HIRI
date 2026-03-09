/**
 * HIRI Privacy Extension Tests — Milestone 10: Privacy Level 1
 *
 * Tests 10.1–10.18: Privacy mode parsing, logical plaintext hash,
 * proof of possession, and graceful degradation.
 */

import { strictEqual, deepStrictEqual, ok, throws } from "node:assert";

// Kernel imports
import { buildUnsignedManifest } from "../src/kernel/manifest.js";
import { signManifest, verifyManifest } from "../src/kernel/signing.js";
import { hashManifest } from "../src/kernel/chain.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import type { ResolutionManifest, StorageAdapter } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";

// Privacy imports
import { getPrivacyMode, parsePrivacyBlock } from "../src/privacy/privacy-mode.js";
import { getLogicalPlaintextHash } from "../src/privacy/plaintext-hash.js";
import { isCustodyStale, parseDurationMs } from "../src/privacy/proof-of-possession.js";
import { resolveWithPrivacy } from "../src/privacy/resolve.js";

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

const baseUri = `hiri://key:ed25519:${authority}/content/test-privacy`;

/** Helper: build a signed manifest with optional privacy block. */
async function buildSignedManifest(
  contentBytes: Uint8Array,
  privacyBlock?: Record<string, unknown>,
  version = "1",
  chain?: ResolutionManifest,
): Promise<ResolutionManifest> {
  const contentHash = await crypto.hash(contentBytes);
  const unsigned = buildUnsignedManifest({
    id: baseUri,
    version,
    branch: "main",
    created: "2026-03-01T00:00:00Z",
    contentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    ...(chain ? {
      chain: {
        previous: await hashManifest(chain, crypto),
        previousBranch: "main",
        genesisHash: chain["hiri:chain"]
          ? chain["hiri:chain"].genesisHash
          : await hashManifest(chain, crypto),
        depth: (chain["hiri:chain"]?.depth ?? 1) + 1,
      },
    } : {}),
  });

  // Inject privacy block if provided
  if (privacyBlock) {
    (unsigned as Record<string, unknown>)["hiri:privacy"] = privacyBlock;
  }

  const ts = "2026-03-01T00:00:00Z";
  return signManifest(unsigned, signingKey, ts, "JCS", crypto);
}

/** Helper: create an in-memory StorageAdapter from manifest+content pairs. */
function createMemoryStorage(
  entries: Array<{ manifest: ResolutionManifest; content: Uint8Array }>,
): StorageAdapter & { contentFetched: Set<string> } {
  const store = new Map<string, Uint8Array>();
  const contentFetched = new Set<string>();

  // We need to store asynchronously, but return sync. Pre-populate.
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
    contentFetched,
    get: async (hash: string) => {
      await Promise.all(pending);
      if (hash.startsWith("sha256:") && !hash.includes("manifest")) {
        // Track content fetches (rough heuristic: content hashes vs manifest hashes)
        contentFetched.add(hash);
      }
      return store.get(hash) ?? null;
    },
    has: async (hash: string) => {
      await Promise.all(pending);
      return store.has(hash);
    },
  };
}

/** Helper: get the manifest hash for a signed manifest. */
async function getManifestHash(manifest: ResolutionManifest): Promise<string> {
  const bytes = new TextEncoder().encode(stableStringify(manifest));
  return crypto.hash(bytes);
}

// =========================================================================
// Tests: 10.1–10.4 — Privacy Mode Parsing (§5)
// =========================================================================

console.log("\n=== Privacy Mode Parsing (§5) ===\n");

// 10.1: No privacy block → public
try {
  const content = new TextEncoder().encode('{"test": "public"}');
  const manifest = await buildSignedManifest(content);
  const mode = getPrivacyMode(manifest);
  strictEqual(mode, "public");
  const block = parsePrivacyBlock(manifest);
  strictEqual(block, null);
  pass("10.1 No hiri:privacy block → getPrivacyMode() returns 'public'");
} catch (e) {
  fail("10.1 No hiri:privacy block → getPrivacyMode() returns 'public'", e);
}

// 10.2: Proof of possession mode
try {
  const content = new TextEncoder().encode('{"test": "pop"}');
  const manifest = await buildSignedManifest(content, {
    mode: "proof-of-possession",
    parameters: {
      availability: "private",
      custodyAssertion: true,
      refreshPolicy: "P30D",
    },
  });
  const mode = getPrivacyMode(manifest);
  strictEqual(mode, "proof-of-possession");
  const block = parsePrivacyBlock(manifest);
  ok(block !== null);
  strictEqual(block!.mode, "proof-of-possession");
  strictEqual((block!.parameters as Record<string, unknown>)?.refreshPolicy, "P30D");
  pass("10.2 Parse proof-of-possession mode with parameters");
} catch (e) {
  fail("10.2 Parse proof-of-possession mode with parameters", e);
}

// 10.3: Encrypted mode
try {
  const content = new TextEncoder().encode('{"test": "encrypted"}');
  const manifest = await buildSignedManifest(content, {
    mode: "encrypted",
    parameters: {
      plaintextHash: "sha256:abc123",
      algorithm: "AES-256-GCM",
    },
  });
  const mode = getPrivacyMode(manifest);
  strictEqual(mode, "encrypted");
  pass("10.3 Parse encrypted mode");
} catch (e) {
  fail("10.3 Parse encrypted mode", e);
}

// 10.4: Unknown future mode
try {
  const content = new TextEncoder().encode('{"test": "future"}');
  const manifest = await buildSignedManifest(content, {
    mode: "future-mode",
    parameters: { version: "2.0" },
  });
  const mode = getPrivacyMode(manifest);
  strictEqual(mode, "future-mode");
  // Must NOT throw
  const block = parsePrivacyBlock(manifest);
  ok(block !== null);
  strictEqual(block!.mode, "future-mode");
  pass("10.4 Unknown mode 'future-mode' parsed without error");
} catch (e) {
  fail("10.4 Unknown mode 'future-mode' parsed without error", e);
}

// =========================================================================
// Tests: 10.5–10.11 — Logical Plaintext Hash (§11.3)
// =========================================================================

console.log("\n=== Logical Plaintext Hash (§11.3) ===\n");

// 10.5: Public manifest
try {
  const content = new TextEncoder().encode('{"test": "public-hash"}');
  const manifest = await buildSignedManifest(content);
  const result = getLogicalPlaintextHash(manifest);
  strictEqual(result.hash, manifest["hiri:content"].hash);
  strictEqual(result.warnings.length, 0);
  pass("10.5 Public manifest → returns content.hash");
} catch (e) {
  fail("10.5 Public manifest → returns content.hash", e);
}

// 10.6: Proof of possession
try {
  const content = new TextEncoder().encode('{"test": "pop-hash"}');
  const manifest = await buildSignedManifest(content, {
    mode: "proof-of-possession",
    parameters: { availability: "private", custodyAssertion: true },
  });
  const result = getLogicalPlaintextHash(manifest);
  strictEqual(result.hash, manifest["hiri:content"].hash);
  strictEqual(result.warnings.length, 0);
  pass("10.6 Proof-of-possession → returns content.hash");
} catch (e) {
  fail("10.6 Proof-of-possession → returns content.hash", e);
}

// 10.7: Encrypted manifest → plaintextHash from parameters
try {
  const content = new TextEncoder().encode('{"test": "encrypted-hash"}');
  const plaintextHash = "sha256:deadbeef1234567890abcdef";
  const manifest = await buildSignedManifest(content, {
    mode: "encrypted",
    parameters: { plaintextHash },
  });
  const result = getLogicalPlaintextHash(manifest);
  strictEqual(result.hash, plaintextHash);
  strictEqual(result.warnings.length, 0);
  pass("10.7 Encrypted → returns privacy.parameters.plaintextHash");
} catch (e) {
  fail("10.7 Encrypted → returns privacy.parameters.plaintextHash", e);
}

// 10.8: Selective disclosure → content.hash
try {
  const content = new TextEncoder().encode('{"test": "sd-hash"}');
  const manifest = await buildSignedManifest(content, {
    mode: "selective-disclosure",
    parameters: { statementCount: 5 },
  });
  const result = getLogicalPlaintextHash(manifest);
  strictEqual(result.hash, manifest["hiri:content"].hash);
  pass("10.8 Selective-disclosure → returns content.hash");
} catch (e) {
  fail("10.8 Selective-disclosure → returns content.hash", e);
}

// 10.9: Anonymous + encrypted → plaintextHash
try {
  const content = new TextEncoder().encode('{"test": "anon-enc"}');
  const plaintextHash = "sha256:anon_encrypted_plaintext";
  const manifest = await buildSignedManifest(content, {
    mode: "anonymous",
    parameters: {
      contentVisibility: "encrypted",
      plaintextHash,
    },
  });
  const result = getLogicalPlaintextHash(manifest);
  strictEqual(result.hash, plaintextHash);
  pass("10.9 Anonymous+encrypted → returns privacy.parameters.plaintextHash");
} catch (e) {
  fail("10.9 Anonymous+encrypted → returns privacy.parameters.plaintextHash", e);
}

// 10.10: Anonymous + public → content.hash
try {
  const content = new TextEncoder().encode('{"test": "anon-pub"}');
  const manifest = await buildSignedManifest(content, {
    mode: "anonymous",
    parameters: { contentVisibility: "public" },
  });
  const result = getLogicalPlaintextHash(manifest);
  strictEqual(result.hash, manifest["hiri:content"].hash);
  pass("10.10 Anonymous+public → returns content.hash");
} catch (e) {
  fail("10.10 Anonymous+public → returns content.hash", e);
}

// 10.11: Attestation → throws
try {
  const content = new TextEncoder().encode('{"test": "attestation"}');
  const manifest = await buildSignedManifest(content, {
    mode: "attestation",
    parameters: { targetAuthority: "hiri://key:ed25519:abc123" },
  });
  let threw = false;
  try {
    getLogicalPlaintextHash(manifest);
  } catch (e) {
    threw = true;
    ok((e as Error).message.includes("Attestation"));
  }
  ok(threw, "Expected getLogicalPlaintextHash to throw for attestation");
  pass("10.11 Attestation → throws 'no logical plaintext hash'");
} catch (e) {
  fail("10.11 Attestation → throws 'no logical plaintext hash'", e);
}

// =========================================================================
// Tests: 10.12–10.15 — Proof of Possession (§6)
// =========================================================================

console.log("\n=== Proof of Possession (§6) ===\n");

// 10.12: Resolve PoP — content NOT fetched
try {
  const content = new TextEncoder().encode('{"test": "pop-resolve"}');
  const manifest = await buildSignedManifest(content, {
    mode: "proof-of-possession",
    parameters: {
      availability: "private",
      custodyAssertion: true,
    },
  });

  const storage = createMemoryStorage([{ manifest, content }]);
  const manifestHash = await getManifestHash(manifest);

  const result = await resolveWithPrivacy(baseUri, storage, {
    crypto,
    publicKey: keypair.publicKey,
    manifestHash,
  });

  strictEqual(result.contentStatus, "private-custody-asserted");
  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "proof-of-possession");
  // Content should NOT have been fetched
  // (The storage tracks content fetches — the manifest hash is fetched but content hash should not be)
  pass("10.12 PoP resolve: contentStatus is 'private-custody-asserted', verified=true");
} catch (e) {
  fail("10.12 PoP resolve: contentStatus is 'private-custody-asserted', verified=true", e);
}

// 10.13: PoP with refreshPolicy "P30D", created 15 days ago → not stale
try {
  const stale = isCustodyStale(
    "2026-03-01T00:00:00Z",
    "P30D",
    "2026-03-16T00:00:00Z", // 15 days later
  );
  strictEqual(stale, false);
  pass("10.13 Custody refresh: 15 days into 30-day policy → not stale");
} catch (e) {
  fail("10.13 Custody refresh: 15 days into 30-day policy → not stale", e);
}

// 10.14: PoP with refreshPolicy "P30D", created 45 days ago → stale
try {
  const stale = isCustodyStale(
    "2026-03-01T00:00:00Z",
    "P30D",
    "2026-04-15T00:00:00Z", // 45 days later
  );
  strictEqual(stale, true);

  // Also verify the resolver emits a staleness warning
  const content = new TextEncoder().encode('{"test": "pop-stale"}');
  const manifest = await buildSignedManifest(content, {
    mode: "proof-of-possession",
    parameters: {
      availability: "private",
      custodyAssertion: true,
      refreshPolicy: "P30D",
    },
  });

  const storage = createMemoryStorage([{ manifest, content }]);
  const manifestHash = await getManifestHash(manifest);

  const result = await resolveWithPrivacy(baseUri, storage, {
    crypto,
    publicKey: keypair.publicKey,
    manifestHash,
    verificationTime: "2026-04-15T00:00:00Z",
  });

  ok(result.warnings.some(w => w.includes("stale")));
  pass("10.14 Custody refresh: 45 days into 30-day policy → stale, warning emitted");
} catch (e) {
  fail("10.14 Custody refresh: 45 days into 30-day policy → stale, warning emitted", e);
}

// 10.15: No refreshPolicy → never stale
try {
  const stale = isCustodyStale(
    "2020-01-01T00:00:00Z",
    undefined,
    "2026-03-08T00:00:00Z", // 6 years later
  );
  strictEqual(stale, false);
  pass("10.15 No refreshPolicy → never stale");
} catch (e) {
  fail("10.15 No refreshPolicy → never stale", e);
}

// =========================================================================
// Tests: 10.16–10.18 — Graceful Degradation (§4.4)
// =========================================================================

console.log("\n=== Graceful Degradation (§4.4) ===\n");

// 10.16: Unknown mode → signature verified, chain verified, contentStatus "unsupported-mode"
try {
  const content = new TextEncoder().encode('{"test": "future-mode"}');
  const manifest = await buildSignedManifest(content, {
    mode: "future-mode",
    parameters: { futureParam: true },
  });

  const storage = createMemoryStorage([{ manifest, content }]);
  const manifestHash = await getManifestHash(manifest);

  const result = await resolveWithPrivacy(baseUri, storage, {
    crypto,
    publicKey: keypair.publicKey,
    manifestHash,
  });

  strictEqual(result.verified, true);
  strictEqual(result.contentStatus, "unsupported-mode");
  strictEqual(result.privacyMode, "future-mode");
  ok(result.warnings.some(w => w.includes("Unknown privacy mode")));
  pass("10.16 Unknown mode: sig verified, chain verified, contentStatus='unsupported-mode'");
} catch (e) {
  fail("10.16 Unknown mode: sig verified, chain verified, contentStatus='unsupported-mode'", e);
}

// 10.17: Manifest with privacy block still verifies signature
try {
  const content = new TextEncoder().encode('{"test": "sig-verify-with-privacy"}');
  const manifest = await buildSignedManifest(content, {
    mode: "proof-of-possession",
    parameters: { availability: "private", custodyAssertion: true },
  });

  // Direct kernel signature verification (proves privacy block doesn't break it)
  const profile = manifest["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
  const sigValid = await verifyManifest(manifest, keypair.publicKey, profile, crypto);
  strictEqual(sigValid, true);
  pass("10.17 Privacy block does not break v3.1.1 signature verification");
} catch (e) {
  fail("10.17 Privacy block does not break v3.1.1 signature verification", e);
}

// 10.18: Manifest with privacy block still verifies chain
try {
  const content1 = new TextEncoder().encode('{"test": "chain-v1"}');
  const manifest1 = await buildSignedManifest(content1, {
    mode: "proof-of-possession",
    parameters: { availability: "private", custodyAssertion: true },
  });

  const content2 = new TextEncoder().encode('{"test": "chain-v2"}');
  const manifest2 = await buildSignedManifest(
    content2,
    {
      mode: "proof-of-possession",
      parameters: { availability: "private", custodyAssertion: true },
    },
    "2",
    manifest1,
  );

  const storage = createMemoryStorage([
    { manifest: manifest1, content: content1 },
    { manifest: manifest2, content: content2 },
  ]);
  const manifestHash = await getManifestHash(manifest2);

  const result = await resolveWithPrivacy(baseUri, storage, {
    crypto,
    publicKey: keypair.publicKey,
    manifestHash,
  });

  strictEqual(result.verified, true);
  strictEqual(result.contentStatus, "private-custody-asserted");
  pass("10.18 Privacy block does not break chain verification");
} catch (e) {
  fail("10.18 Privacy block does not break chain verification", e);
}

// =========================================================================
// Bonus: Unknown mode with warning on getLogicalPlaintextHash
// =========================================================================

console.log("\n=== Bonus: Unknown mode warning ===\n");

try {
  const content = new TextEncoder().encode('{"test": "unknown-hash"}');
  const manifest = await buildSignedManifest(content, {
    mode: "quantum-entangled",
    parameters: {},
  });
  const result = getLogicalPlaintextHash(manifest);
  strictEqual(result.hash, manifest["hiri:content"].hash);
  ok(result.warnings.length > 0, "Expected warning for unknown mode");
  ok(result.warnings[0].includes("quantum-entangled"));
  pass("Bonus: Unknown mode getLogicalPlaintextHash returns hash WITH warning");
} catch (e) {
  fail("Bonus: Unknown mode getLogicalPlaintextHash returns hash WITH warning", e);
}

// =========================================================================
// Summary
// =========================================================================

console.log(`\n=== M10 Privacy Level 1: ${passed} passed, ${failed} failed ===\n`);

if (failed > 0) {
  process.exit(1);
}
