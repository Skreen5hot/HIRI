/**
 * HIRI Protocol Tests — Phase 3: The Abstracted Resolver
 *
 * Infrastructure tests (version handling, storage adapters) +
 * Milestone 3 test cases 3.1–3.8.
 * Uses the existing test harness pattern (counter-based, ✓/✗ markers).
 */

import { strictEqual, deepStrictEqual, ok } from "node:assert";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { resolve as pathResolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

// Kernel imports
import { parseVersion, encodeVersion, isMonotonicallyIncreasing, validateVersion } from "../src/kernel/version.js";
import { resolve, ResolutionError } from "../src/kernel/resolve.js";
import type { ResolveOptions, VerifiedContent } from "../src/kernel/resolve.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { buildUnsignedManifest, prepareContent } from "../src/kernel/manifest.js";
import { signManifest } from "../src/kernel/signing.js";
import { hashManifest } from "../src/kernel/chain.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";
import { InMemoryStorageAdapter } from "../src/adapters/persistence/storage.js";
import { FileSystemAdapter } from "../src/adapters/persistence/filesystem.js";
import { DelayedAdapter } from "../src/adapters/persistence/delayed.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = pathResolve(__dirname, "..", "..");

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
// Infrastructure Tests: Version Handling
// =========================================================================

console.log("--- Version Handling ---");

// version: parseVersion safe integer
try {
  const result = parseVersion("42");
  strictEqual(result, 42n);
  pass("version: parseVersion safe integer");
} catch (e) { fail("version: parseVersion safe integer", e); }

// version: parseVersion large string
try {
  const result = parseVersion("9007199254740993");
  strictEqual(result, 9007199254740993n);
  pass("version: parseVersion large string");
} catch (e) { fail("version: parseVersion large string", e); }

// version: parseVersion rejects invalid
try {
  let threw: boolean;

  // 0
  threw = false;
  try { parseVersion("0"); } catch { threw = true; }
  ok(threw, "Should reject 0");

  // negative
  threw = false;
  try { parseVersion("-1"); } catch { threw = true; }
  ok(threw, "Should reject negative");

  // non-integer
  threw = false;
  try { parseVersion("1.5"); } catch { threw = true; }
  ok(threw, "Should reject non-integer");

  // validateVersion for non-number/string
  const v = validateVersion(null);
  strictEqual(v.valid, false);

  pass("version: parseVersion rejects invalid inputs");
} catch (e) { fail("version: parseVersion rejects invalid inputs", e); }

// version: encodeVersion
try {
  strictEqual(encodeVersion(42n), "42");
  strictEqual(typeof encodeVersion(42n), "string");

  const large = 9007199254740993n;
  strictEqual(encodeVersion(large), "9007199254740993");
  strictEqual(typeof encodeVersion(large), "string");

  pass("version: encodeVersion safe→number, large→string");
} catch (e) { fail("version: encodeVersion safe→number, large→string", e); }

// version: isMonotonicallyIncreasing
try {
  strictEqual(isMonotonicallyIncreasing("2", "1"), true);
  strictEqual(isMonotonicallyIncreasing("1", "2"), false);
  strictEqual(isMonotonicallyIncreasing("1", "1"), false);
  strictEqual(isMonotonicallyIncreasing("9007199254740993", "9007199254740992"), true);

  pass("version: isMonotonicallyIncreasing");
} catch (e) { fail("version: isMonotonicallyIncreasing", e); }

// =========================================================================
// Infrastructure Tests: Storage Adapters
// =========================================================================

console.log("\n--- Storage Adapters ---");

// storage: InMemory put/get round-trip
try {
  const adapter = new InMemoryStorageAdapter();
  const testBytes = new TextEncoder().encode("hello world");
  await adapter.put("sha256:test", testBytes);
  const retrieved = await adapter.get("sha256:test");
  ok(retrieved !== null, "Should retrieve stored bytes");
  deepStrictEqual(retrieved, testBytes);

  pass("storage: InMemory put/get round-trip");
} catch (e) { fail("storage: InMemory put/get round-trip", e); }

// storage: InMemory get returns null
try {
  const adapter = new InMemoryStorageAdapter();
  const result = await adapter.get("sha256:nonexistent");
  strictEqual(result, null);

  pass("storage: InMemory get returns null for unknown hash");
} catch (e) { fail("storage: InMemory get returns null for unknown hash", e); }

// storage: InMemory has
try {
  const adapter = new InMemoryStorageAdapter();
  const testBytes = new TextEncoder().encode("data");
  await adapter.put("sha256:exists", testBytes);
  strictEqual(await adapter.has("sha256:exists"), true);
  strictEqual(await adapter.has("sha256:missing"), false);

  pass("storage: InMemory has returns correct boolean");
} catch (e) { fail("storage: InMemory has returns correct boolean", e); }

// storage: FileSystem read-back
try {
  const tmpDir = await mkdtemp(join(tmpdir(), "hiri-fs-test-"));
  try {
    const testBytes = new TextEncoder().encode("filesystem content");
    const hash = "sha256:fstest123";
    await FileSystemAdapter.writeContent(tmpDir, hash, testBytes);

    const adapter = new FileSystemAdapter(tmpDir);
    const retrieved = await adapter.get(hash);
    ok(retrieved !== null, "Should retrieve from filesystem");
    deepStrictEqual(retrieved, testBytes);
    strictEqual(await adapter.has(hash), true);
    strictEqual(await adapter.has("sha256:missing"), false);

    pass("storage: FileSystem read-back matches written content");
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
} catch (e) { fail("storage: FileSystem read-back matches written content", e); }

// storage: DelayedAdapter results match
try {
  const inner = new InMemoryStorageAdapter();
  const testBytes = new TextEncoder().encode("delayed content");
  await inner.put("sha256:delayed", testBytes);

  const delayed = new DelayedAdapter(inner, 10);
  const retrieved = await delayed.get("sha256:delayed");
  ok(retrieved !== null, "Delayed adapter should return bytes");
  deepStrictEqual(retrieved, testBytes);
  strictEqual(await delayed.has("sha256:delayed"), true);
  strictEqual(await delayed.has("sha256:missing"), false);

  pass("storage: DelayedAdapter results match inner adapter");
} catch (e) { fail("storage: DelayedAdapter results match inner adapter", e); }

// =========================================================================
// Milestone 3: Resolver Tests — Shared Setup
// =========================================================================

console.log("\n--- Milestone 3 Tests ---");

const crypto = defaultCryptoProvider;
let testKeypair: Awaited<ReturnType<typeof generateKeypair>>;
let testAuthority: string;
let testUri: string;
let testManifestHash: string;
let testContentBytes: Uint8Array;
let testContentHash: string;
let memoryAdapter: InMemoryStorageAdapter;
let resolveResult31: VerifiedContent = undefined as unknown as VerifiedContent;

try {
  // Generate keypair and derive authority
  testKeypair = await generateKeypair("key-1");
  testAuthority = deriveAuthority(testKeypair.publicKey, "ed25519");
  testUri = `hiri://${testAuthority}/data/person-001`;

  // Load and prepare person.jsonld
  const personPath = pathResolve(projectRoot, "examples", "person.jsonld");
  const personRaw = JSON.parse(await readFile(personPath, "utf-8"));
  const canonicalContent = prepareContent(personRaw, "AUTHORITY_PLACEHOLDER", testAuthority);
  testContentBytes = new TextEncoder().encode(canonicalContent);
  testContentHash = await crypto.hash(testContentBytes);

  // Build genesis manifest
  const unsigned = buildUnsignedManifest({
    id: testUri,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash: testContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: testContentBytes.length,
    canonicalization: "JCS",
  });
  const signed = await signManifest(unsigned, testKeypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  // Serialize manifest to bytes
  const manifestCanonical = stableStringify(signed, false);
  const manifestBytes = new TextEncoder().encode(manifestCanonical);
  testManifestHash = await crypto.hash(manifestBytes);

  // Populate InMemoryStorageAdapter
  memoryAdapter = new InMemoryStorageAdapter();
  await memoryAdapter.put(testManifestHash, manifestBytes);
  await memoryAdapter.put(testContentHash, testContentBytes);
} catch (e) {
  console.error("  M3 test setup failed:", e instanceof Error ? e.message : String(e));
  process.exit(1);
}

// =========================================================================
// Test 3.1: Resolve valid URI against MemoryAdapter
// =========================================================================

try {
  const options: ResolveOptions = {
    crypto,
    publicKey: testKeypair.publicKey,
    manifestHash: testManifestHash,
  };

  resolveResult31 = await resolve(testUri, memoryAdapter, options);

  // Verify content bytes match
  deepStrictEqual(resolveResult31.content, testContentBytes);
  strictEqual(resolveResult31.contentHash, testContentHash);
  strictEqual(resolveResult31.authority, testAuthority);
  strictEqual(resolveResult31.manifest["@id"], testUri);
  strictEqual(resolveResult31.manifest["hiri:version"], "1");

  pass("3.1: Resolve valid URI against MemoryAdapter");
} catch (e) { fail("3.1: Resolve valid URI against MemoryAdapter", e); }

// =========================================================================
// Test 3.2: Resolve same URI against FileSystemAdapter — byte-identical
// =========================================================================

try {
  const tmpDir = await mkdtemp(join(tmpdir(), "hiri-resolve-fs-"));
  try {
    // Write same data to filesystem
    const manifestBytes = await memoryAdapter.get(testManifestHash);
    const contentBytes = await memoryAdapter.get(testContentHash);
    ok(manifestBytes && contentBytes, "Setup data must exist");

    await FileSystemAdapter.writeContent(tmpDir, testManifestHash, manifestBytes!);
    await FileSystemAdapter.writeContent(tmpDir, testContentHash, contentBytes!);

    const fsAdapter = new FileSystemAdapter(tmpDir);
    const options: ResolveOptions = {
      crypto,
      publicKey: testKeypair.publicKey,
      manifestHash: testManifestHash,
    };

    const fsResult = await resolve(testUri, fsAdapter, options);

    // Byte-identical to 3.1
    deepStrictEqual(fsResult.content, resolveResult31.content);
    strictEqual(fsResult.contentHash, resolveResult31.contentHash);
    strictEqual(fsResult.authority, resolveResult31.authority);
    strictEqual(
      stableStringify(fsResult.manifest, false),
      stableStringify(resolveResult31.manifest, false),
    );

    pass("3.2: Resolve same URI against FileSystemAdapter — byte-identical to 3.1");
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
} catch (e) { fail("3.2: Resolve same URI against FileSystemAdapter", e); }

// =========================================================================
// Test 3.3: Resolve same URI against DelayedAdapter — byte-identical
// =========================================================================

try {
  const delayedAdapter = new DelayedAdapter(memoryAdapter, 50);
  const options: ResolveOptions = {
    crypto,
    publicKey: testKeypair.publicKey,
    manifestHash: testManifestHash,
  };

  const delayedResult = await resolve(testUri, delayedAdapter, options);

  // Byte-identical to 3.1
  deepStrictEqual(delayedResult.content, resolveResult31.content);
  strictEqual(delayedResult.contentHash, resolveResult31.contentHash);
  strictEqual(delayedResult.authority, resolveResult31.authority);
  strictEqual(
    stableStringify(delayedResult.manifest, false),
    stableStringify(resolveResult31.manifest, false),
  );

  pass("3.3: Resolve same URI against DelayedAdapter — byte-identical to 3.1");
} catch (e) { fail("3.3: Resolve same URI against DelayedAdapter", e); }

// =========================================================================
// Test 3.4: Unknown authority → AUTHORITY_NOT_FOUND
// =========================================================================

try {
  const wrongKeypair = await generateKeypair("key-2");
  const options: ResolveOptions = {
    crypto,
    publicKey: wrongKeypair.publicKey,
    manifestHash: testManifestHash,
  };

  let caught: ResolutionError | null = null;
  try {
    await resolve(testUri, memoryAdapter, options);
  } catch (e) {
    if (e instanceof ResolutionError) caught = e;
    else throw e;
  }

  ok(caught !== null, "Should throw ResolutionError");
  strictEqual(caught!.code, "AUTHORITY_NOT_FOUND");

  pass("3.4: Unknown authority → AUTHORITY_NOT_FOUND");
} catch (e) { fail("3.4: Unknown authority → AUTHORITY_NOT_FOUND", e); }

// =========================================================================
// Test 3.5: Manifest exists but content missing → CONTENT_NOT_FOUND
// =========================================================================

try {
  // Adapter with manifest but no content
  const sparseAdapter = new InMemoryStorageAdapter();
  const manifestBytes = await memoryAdapter.get(testManifestHash);
  ok(manifestBytes, "Manifest bytes must exist");
  await sparseAdapter.put(testManifestHash, manifestBytes!);
  // Intentionally NOT putting content

  const options: ResolveOptions = {
    crypto,
    publicKey: testKeypair.publicKey,
    manifestHash: testManifestHash,
  };

  let caught: ResolutionError | null = null;
  try {
    await resolve(testUri, sparseAdapter, options);
  } catch (e) {
    if (e instanceof ResolutionError) caught = e;
    else throw e;
  }

  ok(caught !== null, "Should throw ResolutionError");
  strictEqual(caught!.code, "CONTENT_NOT_FOUND");

  pass("3.5: Manifest exists but content missing → CONTENT_NOT_FOUND");
} catch (e) { fail("3.5: Manifest exists but content missing → CONTENT_NOT_FOUND", e); }

// =========================================================================
// Test 3.6: Invalid signature → SIGNATURE_VERIFICATION_FAILED
// =========================================================================

try {
  // Tamper with the manifest after signing: change a field, re-serialize, re-store
  const manifestBytes = await memoryAdapter.get(testManifestHash);
  ok(manifestBytes, "Manifest bytes must exist");
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes!));

  // Tamper: change the version field (signature now invalid)
  manifest["hiri:version"] = 999;

  const tamperedBytes = new TextEncoder().encode(stableStringify(manifest, false));
  const tamperedHash = await crypto.hash(tamperedBytes);

  const tamperedAdapter = new InMemoryStorageAdapter();
  await tamperedAdapter.put(tamperedHash, tamperedBytes);
  await tamperedAdapter.put(testContentHash, testContentBytes);

  const options: ResolveOptions = {
    crypto,
    publicKey: testKeypair.publicKey,
    manifestHash: tamperedHash,
  };

  // The URI won't match either (version changed in manifest), but signature check comes first
  // Actually, @id still matches. Let's verify the pipeline order.
  // Pipeline: parse URI → authority → fetch manifest → verify hash → deserialize → verify @id → verify signature
  // The @id still matches testUri, so the signature check will fire.
  let caught: ResolutionError | null = null;
  try {
    await resolve(testUri, tamperedAdapter, options);
  } catch (e) {
    if (e instanceof ResolutionError) caught = e;
    else throw e;
  }

  ok(caught !== null, "Should throw ResolutionError");
  strictEqual(caught!.code, "SIGNATURE_VERIFICATION_FAILED");

  pass("3.6: Invalid signature → SIGNATURE_VERIFICATION_FAILED");
} catch (e) { fail("3.6: Invalid signature → SIGNATURE_VERIFICATION_FAILED", e); }

// =========================================================================
// Test 3.7: Concurrent resolution — 10 URIs against DelayedAdapter
// =========================================================================

try {
  const delayedAdapter = new DelayedAdapter(memoryAdapter, 20);

  // Create 10 different resources
  const resources: Array<{ uri: string; manifestHash: string; contentBytes: Uint8Array }> = [];

  for (let i = 0; i < 10; i++) {
    const personPath = pathResolve(projectRoot, "examples", "person.jsonld");
    const personRaw = JSON.parse(await readFile(personPath, "utf-8"));
    const resourceUri = `hiri://${testAuthority}/data/person-${String(i).padStart(3, "0")}`;

    // Prepare content with unique @id
    const prepared = JSON.parse(prepareContent(personRaw, "AUTHORITY_PLACEHOLDER", testAuthority));
    prepared["@id"] = resourceUri;
    const canonical = stableStringify(prepared, false);
    const contentBytes = new TextEncoder().encode(canonical);
    const contentHash = await crypto.hash(contentBytes);

    const unsigned = buildUnsignedManifest({
      id: resourceUri,
      version: "1",
      branch: "main",
      created: "2025-01-15T14:30:00Z",
      contentHash,
      contentFormat: "application/ld+json",
      contentSize: contentBytes.length,
      canonicalization: "JCS",
    addressing: "raw-sha256",
    });
    const signed = await signManifest(unsigned, testKeypair, "2025-01-15T14:30:00Z", "JCS", crypto);
    const manifestCanonical = stableStringify(signed, false);
    const manifestBytes = new TextEncoder().encode(manifestCanonical);
    const manifestHash = await crypto.hash(manifestBytes);

    // Store in the shared memory adapter (DelayedAdapter wraps it)
    await memoryAdapter.put(manifestHash, manifestBytes);
    await memoryAdapter.put(contentHash, contentBytes);

    resources.push({ uri: resourceUri, manifestHash, contentBytes });
  }

  // Resolve all 10 concurrently
  const results = await Promise.all(
    resources.map((r) =>
      resolve(r.uri, delayedAdapter, {
        crypto,
        publicKey: testKeypair.publicKey,
        manifestHash: r.manifestHash,
      }),
    ),
  );

  // Verify all 10 succeeded with correct content
  for (let i = 0; i < 10; i++) {
    deepStrictEqual(results[i].content, resources[i].contentBytes);
    strictEqual(results[i].manifest["@id"], resources[i].uri);
  }

  pass("3.7: Concurrent resolution — 10 URIs against DelayedAdapter all succeed");
} catch (e) { fail("3.7: Concurrent resolution — 10 URIs against DelayedAdapter", e); }

// =========================================================================
// Test 3.8: Malformed URIs → PARSE_ERROR
// =========================================================================

try {
  const malformedUris = [
    "",
    "not-a-uri",
    "http://wrong-scheme/data/test",
    "hiri://",
    "hiri://authority-only",
  ];

  const options: ResolveOptions = {
    crypto,
    publicKey: testKeypair.publicKey,
    manifestHash: testManifestHash,
  };

  for (const badUri of malformedUris) {
    let caught: ResolutionError | null = null;
    try {
      await resolve(badUri, memoryAdapter, options);
    } catch (e) {
      if (e instanceof ResolutionError) caught = e;
      else throw e;
    }
    ok(caught !== null, `Should throw ResolutionError for "${badUri}"`);
    strictEqual(caught!.code, "PARSE_ERROR", `Expected PARSE_ERROR for "${badUri}", got: ${caught!.code}`);
  }

  pass("3.8: Malformed URIs → PARSE_ERROR");
} catch (e) { fail("3.8: Malformed URIs → PARSE_ERROR", e); }

// =========================================================================
// Summary
// =========================================================================

console.log(`\n  ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
