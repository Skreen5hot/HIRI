/**
 * HIRI Protocol Tests — Milestones 1 & 2
 *
 * Infrastructure tests (base58, JCS, JSON Patch) +
 * Milestone 1 test cases 1.1–1.9 +
 * Milestone 2 test cases 2.1–2.13.
 * Uses the existing test harness pattern (counter-based, ✓/✗ markers).
 */

import { strictEqual, deepStrictEqual, ok } from "node:assert";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Kernel imports
import { encode as base58Encode, decode as base58Decode } from "../src/kernel/base58.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import { HiriURI } from "../src/kernel/hiri-uri.js";
import { HashRegistry } from "../src/kernel/hash-registry.js";
import { deriveAuthority, extractPublicKey } from "../src/kernel/authority.js";
import { buildUnsignedManifest, buildKeyDocument, prepareContent } from "../src/kernel/manifest.js";
import { signManifest, verifyManifest, signKeyDocument } from "../src/kernel/signing.js";
import { validateGenesis } from "../src/kernel/genesis.js";
import { hashManifest, validateChainLink, verifyChain } from "../src/kernel/chain.js";
import { applyPatch } from "../src/kernel/json-patch.js";
import { buildDelta, verifyDelta } from "../src/kernel/delta.js";
import type { ResolutionManifest, JsonPatchOperation } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, SHA256Algorithm, generateKeypair } from "../src/adapters/crypto/provider.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// Two levels up: dist-tests/tests/ → dist-tests/ → project root
const projectRoot = resolve(__dirname, "..", "..");

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
// Infrastructure Tests: Base58
// =========================================================================

console.log("--- Base58 ---");

// base58: empty input
try {
  const encoded = base58Encode(new Uint8Array([]));
  strictEqual(encoded, "");
  const decoded = base58Decode("");
  strictEqual(decoded.length, 0);
  pass("base58: empty input round-trip");
} catch (e) { fail("base58: empty input round-trip", e); }

// base58: single zero byte
try {
  const encoded = base58Encode(new Uint8Array([0]));
  strictEqual(encoded, "1");
  const decoded = base58Decode("1");
  strictEqual(decoded.length, 1);
  strictEqual(decoded[0], 0);
  pass("base58: single zero byte encodes to '1'");
} catch (e) { fail("base58: single zero byte encodes to '1'", e); }

// base58: leading zeros preserved
try {
  const input = new Uint8Array([0, 0, 0, 1, 2, 3]);
  const encoded = base58Encode(input);
  ok(encoded.startsWith("111"), `Expected 3 leading '1's, got: ${encoded}`);
  const decoded = base58Decode(encoded);
  deepStrictEqual(decoded, input);
  pass("base58: leading zeros preserved in round-trip");
} catch (e) { fail("base58: leading zeros preserved in round-trip", e); }

// base58: 32-byte round-trip
try {
  const input = new Uint8Array(32);
  for (let i = 0; i < 32; i++) input[i] = (i * 7 + 13) & 0xff;
  const encoded = base58Encode(input);
  ok(encoded.length > 0, "Encoded string should be non-empty");
  const decoded = base58Decode(encoded);
  deepStrictEqual(decoded, input);
  pass("base58: 32-byte round-trip");
} catch (e) { fail("base58: 32-byte round-trip", e); }

// =========================================================================
// Infrastructure Tests: JCS Edge Cases
// =========================================================================

console.log("\n--- JCS Edge Cases ---");

try {
  // Object with numeric values, nested objects, and arrays
  const obj = {
    z: 42,
    a: 3.14,
    m: "hello \u{1F600}",  // emoji (above U+FFFF)
    nested: { b: 2, a: 1 },
  };
  const result = stableStringify(obj, false);
  // Keys should be sorted: a, m, nested, z
  // Nested keys sorted: a, b
  const parsed = JSON.parse(result);
  const keys = Object.keys(parsed);
  deepStrictEqual(keys, ["a", "m", "nested", "z"]);
  const nestedKeys = Object.keys(parsed.nested);
  deepStrictEqual(nestedKeys, ["a", "b"]);
  // Verify determinism
  const result2 = stableStringify(obj, false);
  strictEqual(result, result2);
  pass("JCS: key sorting, numeric values, and Unicode above U+FFFF");
} catch (e) { fail("JCS: key sorting, numeric values, and Unicode above U+FFFF", e); }

// =========================================================================
// Milestone Test 1.8: Hash Registry Resolution
// =========================================================================

console.log("\n--- Milestone Tests ---");

try {
  const registry = new HashRegistry();
  const sha256 = new SHA256Algorithm();
  registry.register(sha256);

  const algo = registry.resolve("sha256:abc123");
  strictEqual(algo.prefix, "sha256");

  // Test the verify convenience method
  const testContent = new TextEncoder().encode("hello world");
  const hash = await registry.hash(testContent);
  ok(hash.startsWith("sha256:"), `Hash should start with sha256:, got: ${hash}`);
  const verified = await registry.verify(testContent, hash);
  strictEqual(verified, true);

  pass("1.8: HashRegistry resolves sha256 and verify convenience method works");
} catch (e) { fail("1.8: HashRegistry resolves sha256 and verify convenience method works", e); }

// =========================================================================
// Milestone Test 1.9: Unsupported Algorithm Throws
// =========================================================================

try {
  const registry = new HashRegistry();
  const sha256 = new SHA256Algorithm();
  registry.register(sha256);

  let threw = false;
  try {
    registry.resolve("blake3:abc123");
  } catch {
    threw = true;
  }
  strictEqual(threw, true, "Expected resolve to throw for unregistered algorithm");
  pass("1.9: HashRegistry throws for unregistered algorithm");
} catch (e) { fail("1.9: HashRegistry throws for unregistered algorithm", e); }

// =========================================================================
// Milestone Test 1.1: Keypair Generation and Authority Derivation
// =========================================================================

let testKeypair: Awaited<ReturnType<typeof generateKeypair>>;
let testAuthority: string;

try {
  testKeypair = await generateKeypair("key-1");

  // Verify keypair structure
  strictEqual(testKeypair.algorithm, "ed25519");
  strictEqual(testKeypair.keyId, "key-1");
  ok(testKeypair.publicKey instanceof Uint8Array, "publicKey should be Uint8Array");
  ok(testKeypair.privateKey instanceof Uint8Array, "privateKey should be Uint8Array");
  ok(testKeypair.publicKey.length === 32, `publicKey should be 32 bytes, got ${testKeypair.publicKey.length}`);

  // Derive authority
  testAuthority = deriveAuthority(testKeypair.publicKey, "ed25519");

  // Verify format: key:ed25519:<20-base58-chars>
  const pattern = /^key:ed25519:z[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
  ok(pattern.test(testAuthority), `Authority should match pattern, got: ${testAuthority}`);

  // Verify round-trip: extractPublicKey(deriveAuthority(pk)) === pk
  const recovered = extractPublicKey(testAuthority);
  deepStrictEqual(recovered.publicKey, testKeypair.publicKey, "Round-trip must recover original key");

  pass("1.1: Keypair generation and authority derivation matches key:ed25519:z<full-key>");
} catch (e) { fail("1.1: Keypair generation and authority derivation", e); }

// =========================================================================
// Milestone Test 1.2: Sign person.jsonld, Produce Manifest
// =========================================================================

let signedManifest: Awaited<ReturnType<typeof signManifest>> | undefined;

try {
  // Load person.jsonld
  const personPath = resolve(projectRoot, "examples", "person.jsonld");
  const personRaw = JSON.parse(await readFile(personPath, "utf-8"));

  // Prepare content: replace placeholder, canonicalize
  const canonicalContent = prepareContent(personRaw, "AUTHORITY_PLACEHOLDER", testAuthority!);
  const contentBytes = new TextEncoder().encode(canonicalContent);

  // Hash content
  const contentHash = await defaultCryptoProvider.hash(contentBytes);

  // Build the manifest
  const manifestId = `hiri://${testAuthority!}/data/person-001`;
  const timestamp = "2025-01-15T14:30:00Z";

  const unsigned = buildUnsignedManifest({
    id: manifestId,
    version: "1",
    branch: "main",
    created: timestamp,
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  // Sign it
  signedManifest = await signManifest(unsigned, testKeypair!, timestamp, "JCS", defaultCryptoProvider);

  // Assert all required fields
  ok(Array.isArray(signedManifest["@context"]), "@context should be array");
  strictEqual(signedManifest["@id"], manifestId);
  strictEqual(signedManifest["@type"], "hiri:ResolutionManifest");
  strictEqual(signedManifest["hiri:version"], "1");
  strictEqual(signedManifest["hiri:branch"], "main");
  ok(signedManifest["hiri:timing"].created, "timing.created should exist");
  ok(signedManifest["hiri:content"].hash.startsWith("sha256:"), "content.hash should have sha256 prefix");
  strictEqual(signedManifest["hiri:content"].format, "application/ld+json");
  ok(signedManifest["hiri:content"].size > 0, "content.size should be positive");
  strictEqual(signedManifest["hiri:content"].canonicalization, "JCS");
  strictEqual(signedManifest["hiri:content"].addressing, "raw-sha256");
  strictEqual(signedManifest["hiri:signature"].canonicalization, "JCS");
  strictEqual(signedManifest["hiri:signature"].type, "Ed25519Signature2020");
  ok(signedManifest["hiri:signature"].proofValue.startsWith("z"), "proofValue should have z multibase prefix");
  ok(signedManifest["hiri:signature"].verificationMethod.includes("#key-1"), "verificationMethod should reference key-1");

  pass("1.2: Signed manifest has all required fields per §5.2");
} catch (e) { fail("1.2: Sign person.jsonld and produce manifest", e); }

// =========================================================================
// Milestone Test 1.3: Verify Manifest Against Public Key
// =========================================================================

try {
  ok(signedManifest, "Signed manifest required from test 1.2");
  const result = await verifyManifest(signedManifest!, testKeypair!.publicKey, "JCS", defaultCryptoProvider);
  strictEqual(result, true);
  pass("1.3: Manifest signature verified against public key");
} catch (e) { fail("1.3: Verify manifest against public key", e); }

// =========================================================================
// Milestone Test 1.4a: Content Tampering (content integrity)
// =========================================================================

try {
  ok(signedManifest, "Signed manifest required from test 1.2");

  // Load person.jsonld again, tamper with one byte of content
  const personPath = resolve(projectRoot, "examples", "person.jsonld");
  const personRaw = JSON.parse(await readFile(personPath, "utf-8"));
  const canonicalContent = prepareContent(personRaw, "AUTHORITY_PLACEHOLDER", testAuthority!);

  // Tamper: change one character
  const tampered = canonicalContent.substring(0, 10) + "X" + canonicalContent.substring(11);
  const tamperedBytes = new TextEncoder().encode(tampered);
  const tamperedHash = await defaultCryptoProvider.hash(tamperedBytes);

  // The tampered hash should NOT match the manifest's content hash
  ok(
    tamperedHash !== signedManifest!["hiri:content"].hash,
    "Tampered content hash should differ from manifest content hash",
  );

  pass("1.4a: Content tampering detected — hash mismatch");
} catch (e) { fail("1.4a: Content tampering detected", e); }

// =========================================================================
// Milestone Test 1.4b: Manifest Tampering (signature integrity)
// =========================================================================

try {
  ok(signedManifest, "Signed manifest required from test 1.2");

  // Clone manifest and modify the content hash field
  const tampered = structuredClone(signedManifest!);
  const originalHash = tampered["hiri:content"].hash;
  const lastChar = originalHash[originalHash.length - 1];
  tampered["hiri:content"].hash = originalHash.substring(0, originalHash.length - 1) + (lastChar === "0" ? "1" : "0");

  // Signature should now be invalid
  const result = await verifyManifest(tampered, testKeypair!.publicKey, "JCS", defaultCryptoProvider);
  strictEqual(result, false);

  pass("1.4b: Manifest tampering detected — signature verification fails");
} catch (e) { fail("1.4b: Manifest tampering detected", e); }

// =========================================================================
// Milestone Test 1.5: Signature Tampering
// =========================================================================

try {
  ok(signedManifest, "Signed manifest required from test 1.2");

  // Clone manifest and modify one character of the proofValue
  const tampered = structuredClone(signedManifest!);
  const pv = tampered["hiri:signature"].proofValue;
  // Flip a character in the middle of the proof value
  const mid = Math.floor(pv.length / 2);
  const flipped = pv[mid] === "A" ? "B" : "A";
  tampered["hiri:signature"].proofValue = pv.substring(0, mid) + flipped + pv.substring(mid + 1);

  const result = await verifyManifest(tampered, testKeypair!.publicKey, "JCS", defaultCryptoProvider);
  strictEqual(result, false);

  pass("1.5: Signature tampering detected — verification fails");
} catch (e) { fail("1.5: Signature tampering detected", e); }

// =========================================================================
// Milestone Test 1.6: Genesis Manifest (version 1, no chain)
// =========================================================================

try {
  ok(signedManifest, "Signed manifest required from test 1.2");

  const result = validateGenesis(signedManifest!);
  strictEqual(result.valid, true);
  strictEqual(result.reason, undefined);

  pass("1.6: Genesis manifest (version=1, no chain) is valid");
} catch (e) { fail("1.6: Genesis manifest validation", e); }

// =========================================================================
// Milestone Test 1.7: Non-genesis Without Chain (invalid)
// =========================================================================

try {
  // Build a manifest with version 2 but no chain
  const unsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "2",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: 100,
    canonicalization: "JCS",
  });

  const result = validateGenesis(unsigned);
  strictEqual(result.valid, false);
  ok(result.reason!.includes("version > 1"), `Reason should mention version > 1, got: ${result.reason}`);

  pass("1.7: Non-genesis manifest (version=2, no chain) is invalid");
} catch (e) { fail("1.7: Non-genesis without chain validation", e); }

// =========================================================================
// Infrastructure Tests: JSON Patch
// =========================================================================

console.log("\n--- JSON Patch ---");

// json-patch: replace
try {
  const doc = { a: 1, b: 2 };
  const result = applyPatch(doc, [{ op: "replace", path: "/a", value: 99 }]) as Record<string, unknown>;
  strictEqual(result.a, 99);
  strictEqual(result.b, 2);
  // Verify immutability
  strictEqual(doc.a, 1);
  pass("json-patch: replace on simple object");
} catch (e) { fail("json-patch: replace on simple object", e); }

// json-patch: add
try {
  const doc = { a: 1 };
  const result = applyPatch(doc, [{ op: "add", path: "/b", value: "new" }]) as Record<string, unknown>;
  strictEqual(result.b, "new");
  strictEqual(result.a, 1);
  pass("json-patch: add new field");
} catch (e) { fail("json-patch: add new field", e); }

// json-patch: remove
try {
  const doc = { a: 1, b: 2, c: 3 };
  const result = applyPatch(doc, [{ op: "remove", path: "/b" }]) as Record<string, unknown>;
  strictEqual("b" in result, false);
  strictEqual(result.a, 1);
  strictEqual(result.c, 3);
  pass("json-patch: remove existing field");
} catch (e) { fail("json-patch: remove existing field", e); }

// json-patch: nested path
try {
  const doc = { a: { b: { c: "old" } } };
  const result = applyPatch(doc, [
    { op: "replace", path: "/a/b/c", value: "new" },
  ]) as { a: { b: { c: string } } };
  strictEqual(result.a.b.c, "new");
  pass("json-patch: nested path traversal");
} catch (e) { fail("json-patch: nested path traversal", e); }

// json-patch: person v1 → v2 transformation
try {
  const personV1Path = resolve(projectRoot, "examples", "person.jsonld");
  const personV2Path = resolve(projectRoot, "examples", "person-v2.jsonld");
  const v1Raw = JSON.parse(await readFile(personV1Path, "utf-8"));
  const v2Raw = JSON.parse(await readFile(personV2Path, "utf-8"));

  // Replace placeholder with a test authority for comparison
  const testAuth = testAuthority!;
  const v1Prepared = JSON.parse(prepareContent(v1Raw, "AUTHORITY_PLACEHOLDER", testAuth));
  const v2Prepared = JSON.parse(prepareContent(v2Raw, "AUTHORITY_PLACEHOLDER", testAuth));

  // Apply the 4 patch operations that transform v1 → v2
  const patchOps: JsonPatchOperation[] = [
    { op: "replace", path: "/schema:address/schema:addressLocality", value: "Seattle" },
    { op: "replace", path: "/schema:address/schema:addressRegion", value: "WA" },
    { op: "replace", path: "/schema:jobTitle", value: "Principal Systems Architect" },
    { op: "add", path: "/schema:email", value: "d.reeves@cascadeinfra.example" },
  ];

  const patched = applyPatch(v1Prepared, patchOps);
  const patchedCanonical = stableStringify(patched, false);
  const v2Canonical = stableStringify(v2Prepared, false);
  strictEqual(patchedCanonical, v2Canonical);

  pass("json-patch: person v1 → v2 transformation matches fixture");
} catch (e) { fail("json-patch: person v1 → v2 transformation", e); }

// =========================================================================
// Milestone 2: Chain & Versioning — Test Setup
// =========================================================================

console.log("\n--- Milestone 2 Tests ---");

// Shared state for M2 tests
let v1Manifest: ResolutionManifest;
let v1ContentBytes: Uint8Array;
let v1ContentHash: string;
let v1ManifestHash: string;
let v2Manifest: ResolutionManifest;
let v2ContentBytes: Uint8Array;
let v2ContentHash: string;
let v2ManifestHash: string;
let deltaOps: JsonPatchOperation[];
let deltaSerializedBytes: Uint8Array;

// Build the full M2 test scenario
const manifestStore = new Map<string, ResolutionManifest>();
const contentStore = new Map<string, Uint8Array>();

try {
  // --- V1 Genesis ---
  const personV1Path = resolve(projectRoot, "examples", "person.jsonld");
  const personV1Raw = JSON.parse(await readFile(personV1Path, "utf-8"));
  const v1Canonical = prepareContent(personV1Raw, "AUTHORITY_PLACEHOLDER", testAuthority!);
  v1ContentBytes = new TextEncoder().encode(v1Canonical);
  v1ContentHash = await defaultCryptoProvider.hash(v1ContentBytes);

  const v1Unsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash: v1ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v1ContentBytes.length,
    canonicalization: "JCS",
  });
  v1Manifest = await signManifest(v1Unsigned, testKeypair!, "2025-01-15T14:30:00Z", "JCS", defaultCryptoProvider);
  v1ManifestHash = await hashManifest(v1Manifest, defaultCryptoProvider);

  // --- V2 with chain + delta ---
  const personV2Path = resolve(projectRoot, "examples", "person-v2.jsonld");
  const personV2Raw = JSON.parse(await readFile(personV2Path, "utf-8"));
  const v2Canonical = prepareContent(personV2Raw, "AUTHORITY_PLACEHOLDER", testAuthority!);
  v2ContentBytes = new TextEncoder().encode(v2Canonical);
  v2ContentHash = await defaultCryptoProvider.hash(v2ContentBytes);

  deltaOps = [
    { op: "replace", path: "/schema:address/schema:addressLocality", value: "Seattle" },
    { op: "replace", path: "/schema:address/schema:addressRegion", value: "WA" },
    { op: "replace", path: "/schema:jobTitle", value: "Principal Systems Architect" },
    { op: "add", path: "/schema:email", value: "d.reeves@cascadeinfra.example" },
  ];

  const { delta, serialized } = await buildDelta(deltaOps, v1ContentHash, defaultCryptoProvider);
  deltaSerializedBytes = new TextEncoder().encode(serialized);

  const v2Unsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "2",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: v1ManifestHash,
      previousBranch: "main",
      genesisHash: v1ManifestHash,
      depth: 2,
    },
    delta,
  });
  v2Manifest = await signManifest(v2Unsigned, testKeypair!, "2025-02-15T14:30:00Z", "JCS", defaultCryptoProvider);
  v2ManifestHash = await hashManifest(v2Manifest, defaultCryptoProvider);

  // Populate stores
  manifestStore.set(v1ManifestHash, v1Manifest);
  manifestStore.set(v2ManifestHash, v2Manifest);
  contentStore.set(v1ContentHash, v1ContentBytes);
  contentStore.set(v2ContentHash, v2ContentBytes);
  contentStore.set(delta.hash, deltaSerializedBytes);
} catch (e) {
  console.error("  M2 test setup failed:", e instanceof Error ? e.message : String(e));
  process.exit(1);
}

// Fetcher functions backed by Maps
const fetchManifest = async (hash: string) => manifestStore.get(hash) ?? null;
const fetchContent = async (hash: string) => contentStore.get(hash) ?? null;

// =========================================================================
// Test 2.1: Create V2 with chain linking to V1
// =========================================================================

try {
  const chain = v2Manifest["hiri:chain"]!;
  strictEqual(chain.previous, v1ManifestHash, "chain.previous should be hash of v1");
  strictEqual(chain.genesisHash, v1ManifestHash, "chain.genesisHash should be hash of v1 (genesis)");
  strictEqual(chain.depth, 2, "chain.depth should be 2");
  strictEqual(chain.previousBranch, "main", "chain.previousBranch should be 'main'");

  pass("2.1: V2 chain.previous = hash of V1, depth=2, genesisHash correct");
} catch (e) { fail("2.1: Create V2 with chain linking to V1", e); }

// =========================================================================
// Test 2.2: Chain walk V2→V1 valid
// =========================================================================

try {
  const result = await verifyChain(v2Manifest, testKeypair!.publicKey, fetchManifest, fetchContent, defaultCryptoProvider);
  strictEqual(result.valid, true, `Expected valid chain, got: ${result.reason}`);
  strictEqual(result.depth, 2, `Expected depth 2, got: ${result.depth}`);
  deepStrictEqual(result.warnings, [], `Expected no warnings, got: ${JSON.stringify(result.warnings)}`);

  pass("2.2: Chain walk V2→V1 reports { valid: true, depth: 2 }");
} catch (e) { fail("2.2: Chain walk V2→V1", e); }

// =========================================================================
// Test 2.3: Tamper V1 content in storage
// =========================================================================

try {
  // Create a tampered manifest store where v1 is modified
  const tamperedV1 = structuredClone(v1Manifest);
  tamperedV1["hiri:version"] = "99"; // tamper
  const tamperedStore = new Map(manifestStore);
  tamperedStore.set(v1ManifestHash, tamperedV1); // store tampered under original hash

  const tamperedFetch = async (hash: string) => tamperedStore.get(hash) ?? null;
  const result = await verifyChain(v2Manifest, testKeypair!.publicKey, tamperedFetch, fetchContent, defaultCryptoProvider);
  strictEqual(result.valid, false, "Should detect storage tampering");

  pass("2.3: Storage tampering detected — hash of fetched V1 doesn't match");
} catch (e) { fail("2.3: Tamper V1 content in storage", e); }

// =========================================================================
// Test 2.4: Delta application: apply patch to V1 → produces V2 content
// =========================================================================

try {
  const result = await verifyDelta(
    v2Manifest["hiri:delta"]!,
    deltaOps,
    v1ContentBytes,
    v2ContentHash,
    "JCS",
    defaultCryptoProvider,
  );
  strictEqual(result.valid, true, `Expected valid delta, got: ${result.reason}`);

  pass("2.4: Delta verification: apply patch to V1 produces V2 content hash");
} catch (e) { fail("2.4: Delta application V1→V2", e); }

// =========================================================================
// Test 2.5: Delta corruption, fallback + warning
// =========================================================================

try {
  // Create a corrupted delta ops store
  const corruptedDeltaOps: JsonPatchOperation[] = [
    ...deltaOps.slice(0, -1),
    { op: "replace", path: "/schema:email", value: "CORRUPTED@example.com" },
  ];
  const corruptedSerialized = stableStringify(corruptedDeltaOps, false);
  const corruptedBytes = new TextEncoder().encode(corruptedSerialized);
  const corruptedHash = await defaultCryptoProvider.hash(corruptedBytes);

  // Build a v2 with corrupted delta
  const corruptedDelta = {
    hash: corruptedHash,
    format: "application/json-patch+json",
    appliesTo: v1ContentHash,
    operations: corruptedDeltaOps.length,
  };

  const corruptedV2Unsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "2",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: v1ManifestHash,
      previousBranch: "main",
      genesisHash: v1ManifestHash,
      depth: 2,
    },
    delta: corruptedDelta,
  });
  const corruptedV2 = await signManifest(corruptedV2Unsigned, testKeypair!, "2025-02-15T14:30:00Z", "JCS", defaultCryptoProvider);
  const corruptedV2Hash = await hashManifest(corruptedV2, defaultCryptoProvider);

  // Set up stores with corrupted v2
  const corruptedManifestStore = new Map(manifestStore);
  corruptedManifestStore.set(corruptedV2Hash, corruptedV2);

  const corruptedContentStore = new Map(contentStore);
  corruptedContentStore.set(corruptedHash, corruptedBytes);

  const corruptedFetchManifest = async (hash: string) => corruptedManifestStore.get(hash) ?? null;
  const corruptedFetchContent = async (hash: string) => corruptedContentStore.get(hash) ?? null;

  const result = await verifyChain(corruptedV2, testKeypair!.publicKey, corruptedFetchManifest, corruptedFetchContent, defaultCryptoProvider);
  strictEqual(result.valid, true, `Expected valid (fallback), got: ${result.reason}`);
  ok(result.warnings.length > 0, "Expected warnings about delta failure");
  ok(result.warnings[0].includes("Delta verification failed"), `Warning should mention delta failure, got: ${result.warnings[0]}`);

  pass("2.5: Delta corruption detected, fallback to full content + warning");
} catch (e) { fail("2.5: Delta corruption with fallback", e); }

// =========================================================================
// Test 2.6: Delta appliesTo mismatch
// =========================================================================

try {
  const wrongAppliesTo = {
    ...v2Manifest["hiri:delta"]!,
    appliesTo: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  };

  const result = await verifyDelta(
    wrongAppliesTo,
    deltaOps,
    v1ContentBytes,
    v2ContentHash,
    "JCS",
    defaultCryptoProvider,
  );
  strictEqual(result.valid, false, "Should detect appliesTo mismatch");
  ok(result.reason!.includes("appliesTo"), `Reason should mention appliesTo, got: ${result.reason}`);

  pass("2.6: Delta appliesTo mismatch detected");
} catch (e) { fail("2.6: Delta appliesTo mismatch", e); }

// =========================================================================
// Test 2.7: Genesis at chain root — walker verifies V1 as standalone
// =========================================================================

try {
  const result = await verifyChain(v1Manifest, testKeypair!.publicKey, fetchManifest, fetchContent, defaultCryptoProvider);
  strictEqual(result.valid, true, `Expected valid genesis, got: ${result.reason}`);
  strictEqual(result.depth, 1, `Expected depth 1, got: ${result.depth}`);
  deepStrictEqual(result.warnings, [], `Expected no warnings, got: ${JSON.stringify(result.warnings)}`);

  pass("2.7: Genesis at chain root: walker confirms V1, depth=1");
} catch (e) { fail("2.7: Genesis at chain root", e); }

// =========================================================================
// Test 2.8: Three-deep chain V3→V2→V1
// =========================================================================

try {
  // Build v3 manifest (same content as v2 for simplicity, but version 3)
  const v3Unsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "3",
    branch: "main",
    created: "2025-03-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: v2ManifestHash,
      previousBranch: "main",
      genesisHash: v1ManifestHash,
      depth: 3,
    },
  });
  const v3Manifest = await signManifest(v3Unsigned, testKeypair!, "2025-03-15T14:30:00Z", "JCS", defaultCryptoProvider);

  // Add to stores
  const threeDeepManifestStore = new Map(manifestStore);
  const v3Hash = await hashManifest(v3Manifest, defaultCryptoProvider);
  threeDeepManifestStore.set(v3Hash, v3Manifest);

  const threeDeepFetch = async (hash: string) => threeDeepManifestStore.get(hash) ?? null;
  const result = await verifyChain(v3Manifest, testKeypair!.publicKey, threeDeepFetch, fetchContent, defaultCryptoProvider);
  strictEqual(result.valid, true, `Expected valid 3-deep chain, got: ${result.reason}`);
  strictEqual(result.depth, 3, `Expected depth 3, got: ${result.depth}`);

  pass("2.8: Three-deep chain V3→V2→V1, depth=3");
} catch (e) { fail("2.8: Three-deep chain", e); }

// =========================================================================
// Test 2.9: Version monotonicity — V2.version <= V1.version fails
// =========================================================================

try {
  // Build a v2 with version=1 (same as v1)
  const badV2Unsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "1",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: v1ManifestHash,
      previousBranch: "main",
      genesisHash: v1ManifestHash,
      depth: 2,
    },
  });
  const badV2 = await signManifest(badV2Unsigned, testKeypair!, "2025-02-15T14:30:00Z", "JCS", defaultCryptoProvider);

  const result = await validateChainLink(badV2, v1Manifest, defaultCryptoProvider);
  strictEqual(result.valid, false, "Should reject non-monotonic version");
  ok(result.reason!.includes("monoton"), `Reason should mention monotonicity, got: ${result.reason}`);

  pass("2.9: Version monotonicity violation detected");
} catch (e) { fail("2.9: Version monotonicity", e); }

// =========================================================================
// Test 2.10 (Bonus): Depth integrity — wrong depth
// =========================================================================

try {
  const badDepthUnsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "2",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: v1ManifestHash,
      previousBranch: "main",
      genesisHash: v1ManifestHash,
      depth: 5, // Wrong: should be 2
    },
  });
  const badDepthV2 = await signManifest(badDepthUnsigned, testKeypair!, "2025-02-15T14:30:00Z", "JCS", defaultCryptoProvider);

  const result = await validateChainLink(badDepthV2, v1Manifest, defaultCryptoProvider);
  strictEqual(result.valid, false, "Should reject wrong depth");
  ok(result.reason!.includes("Depth"), `Reason should mention depth, got: ${result.reason}`);

  pass("2.10: Depth integrity violation detected (depth=5, expected=2)");
} catch (e) { fail("2.10: Depth integrity", e); }

// =========================================================================
// Test 2.11 (Bonus): Genesis hash immutability
// =========================================================================

try {
  const badGenesisUnsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "2",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: v1ManifestHash,
      previousBranch: "main",
      genesisHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000", // Wrong genesis hash
      depth: 2,
    },
  });
  const badGenesisV2 = await signManifest(badGenesisUnsigned, testKeypair!, "2025-02-15T14:30:00Z", "JCS", defaultCryptoProvider);

  const result = await validateChainLink(badGenesisV2, v1Manifest, defaultCryptoProvider);
  strictEqual(result.valid, false, "Should reject wrong genesis hash");
  ok(result.reason!.includes("Genesis hash"), `Reason should mention genesis hash, got: ${result.reason}`);

  pass("2.11: Genesis hash immutability violation detected");
} catch (e) { fail("2.11: Genesis hash immutability", e); }

// =========================================================================
// Test 2.12 (Bonus): Branch consistency
// =========================================================================

try {
  const badBranchUnsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "2",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: v1ManifestHash,
      previousBranch: "staging", // Wrong: v1 is on "main"
      genesisHash: v1ManifestHash,
      depth: 2,
    },
  });
  const badBranchV2 = await signManifest(badBranchUnsigned, testKeypair!, "2025-02-15T14:30:00Z", "JCS", defaultCryptoProvider);

  const result = await validateChainLink(badBranchV2, v1Manifest, defaultCryptoProvider);
  strictEqual(result.valid, false, "Should reject branch mismatch");
  ok(result.reason!.includes("Branch"), `Reason should mention branch, got: ${result.reason}`);

  pass("2.12: Branch consistency violation detected");
} catch (e) { fail("2.12: Branch consistency", e); }

// =========================================================================
// Test 2.13 (Bonus): chain.previous tampering (re-signed)
// =========================================================================

try {
  // Build a v2 with the wrong chain.previous (pointing to some random hash)
  const tamperedPreviousUnsigned = buildUnsignedManifest({
    id: `hiri://${testAuthority!}/data/person-001`,
    version: "2",
    branch: "main",
    created: "2025-02-15T14:30:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2ContentBytes.length,
    canonicalization: "JCS",
    chain: {
      previous: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      previousBranch: "main",
      genesisHash: v1ManifestHash,
      depth: 2,
    },
  });
  // Re-sign with valid key — the signature is valid but chain.previous is wrong
  const tamperedPreviousV2 = await signManifest(tamperedPreviousUnsigned, testKeypair!, "2025-02-15T14:30:00Z", "JCS", defaultCryptoProvider);

  const result = await validateChainLink(tamperedPreviousV2, v1Manifest, defaultCryptoProvider);
  strictEqual(result.valid, false, "Should reject tampered chain.previous");
  ok(result.reason!.includes("previous hash"), `Reason should mention previous hash, got: ${result.reason}`);

  pass("2.13: chain.previous tampering detected (re-signed manifest)");
} catch (e) { fail("2.13: chain.previous tampering", e); }

// =========================================================================
// Summary
// =========================================================================

console.log(`\n  ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
