/**
 * HIRI Protocol Tests — Milestone 6: v3.1.1 Core Migration
 *
 * Tests 6.1–6.20: Verify all v3.1.1-specific behaviors including
 * full-key authority, string-only versions, profile symmetry,
 * addressing field, delta-canonicalization coupling, and
 * verification status reporting.
 */

import { strictEqual, deepStrictEqual, ok } from "node:assert";

// Kernel imports
import { deriveAuthority, extractPublicKey } from "../src/kernel/authority.js";
import { parseVersion, encodeVersion, validateVersion, isMonotonicallyIncreasing } from "../src/kernel/version.js";
import { buildUnsignedManifest } from "../src/kernel/manifest.js";
import { signManifest, verifyManifest } from "../src/kernel/signing.js";
import { buildDelta, validateDeltaCoupling } from "../src/kernel/delta.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import { resolveSigningKey } from "../src/kernel/key-lifecycle.js";
import { encode as base58Encode } from "../src/kernel/base58.js";
import type { ManifestDelta, KeyDocument, ResolutionManifest } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";

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

const contentBytes = new TextEncoder().encode(stableStringify({ "@id": "test", "name": "v3.1.1" }, false));
const contentHash = await crypto.hash(contentBytes);

console.log("--- Milestone 6: v3.1.1 Migration Tests ---");

// =========================================================================
// 6.1: Authority format is key:ed25519:z<full-base58>
// =========================================================================
try {
  ok(authority.startsWith("key:ed25519:z"), "Authority must start with key:ed25519:z");
  ok(authority.length > 50, `Authority should be >50 chars (full key), got ${authority.length}`);
  const encoded = authority.split(":")[2];
  ok(encoded.length > 20, "Authority encoded part must not be truncated to 20 chars");

  pass("6.1: Authority format is key:ed25519:z<full-base58>");
} catch (e) { fail("6.1: Authority format is key:ed25519:z<full-base58>", e); }

// =========================================================================
// 6.2: Authority round-trip (deriveAuthority -> extractPublicKey)
// =========================================================================
try {
  const extracted = extractPublicKey(authority);
  strictEqual(extracted.algorithm, "ed25519");
  deepStrictEqual(extracted.publicKey, keypair.publicKey);

  pass("6.2: Authority round-trip (deriveAuthority -> extractPublicKey)");
} catch (e) { fail("6.2: Authority round-trip (deriveAuthority -> extractPublicKey)", e); }

// =========================================================================
// 6.3: extractPublicKey rejects invalid format
// =========================================================================
try {
  let threw = false;
  try { extractPublicKey("invalid-authority"); } catch { threw = true; }
  ok(threw, "Should reject malformed authority");

  threw = false;
  try { extractPublicKey("key:ed25519:noZprefix"); } catch { threw = true; }
  ok(threw, "Should reject authority without z prefix");

  pass("6.3: extractPublicKey rejects invalid format");
} catch (e) { fail("6.3: extractPublicKey rejects invalid format", e); }

// =========================================================================
// 6.4: Version is always string (parseVersion rejects numbers)
// =========================================================================
try {
  strictEqual(parseVersion("1"), 1n);
  strictEqual(parseVersion("999"), 999n);

  let threw = false;
  try { parseVersion(42 as unknown as string); } catch { threw = true; }
  ok(threw, "parseVersion must reject number input");

  pass("6.4: Version is always string (parseVersion rejects numbers)");
} catch (e) { fail("6.4: Version is always string (parseVersion rejects numbers)", e); }

// =========================================================================
// 6.5: encodeVersion always returns string
// =========================================================================
try {
  const v = encodeVersion(42n);
  strictEqual(v, "42");
  strictEqual(typeof v, "string");

  const large = encodeVersion(9007199254740993n);
  strictEqual(large, "9007199254740993");
  strictEqual(typeof large, "string");

  pass("6.5: encodeVersion always returns string");
} catch (e) { fail("6.5: encodeVersion always returns string", e); }

// =========================================================================
// 6.6: validateVersion rejects non-string
// =========================================================================
try {
  strictEqual(validateVersion(42).valid, false);
  strictEqual(validateVersion(null).valid, false);
  strictEqual(validateVersion(undefined).valid, false);
  strictEqual(validateVersion("1").valid, true);

  pass("6.6: validateVersion rejects non-string");
} catch (e) { fail("6.6: validateVersion rejects non-string", e); }

// =========================================================================
// 6.7: Manifest includes addressing field
// =========================================================================
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  strictEqual(unsigned["hiri:content"].addressing, "raw-sha256");

  pass("6.7: Manifest includes addressing field");
} catch (e) { fail("6.7: Manifest includes addressing field", e); }

// =========================================================================
// 6.8: Signed manifest includes canonicalization in signature block
// =========================================================================
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  strictEqual(signed["hiri:signature"].canonicalization, "JCS");

  pass("6.8: Signed manifest includes canonicalization in signature block");
} catch (e) { fail("6.8: Signed manifest includes canonicalization in signature block", e); }

// =========================================================================
// 6.9: Profile Symmetry Rule — signing rejects mismatched canonicalization
// =========================================================================
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  // Tamper: change content canonicalization to mismatch
  (unsigned["hiri:content"] as { canonicalization: string }).canonicalization = "URDNA2015";

  let threw = false;
  try {
    await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);
  } catch (e) {
    threw = true;
    ok((e as Error).message.includes("symmetry"), "Should mention symmetry violation");
  }
  ok(threw, "signManifest must throw on profile symmetry violation");

  pass("6.9: Profile Symmetry Rule — signing rejects mismatched content.canonicalization");
} catch (e) { fail("6.9: Profile Symmetry Rule — signing rejects mismatched content.canonicalization", e); }

// =========================================================================
// 6.10: Profile Symmetry Rule — verification rejects mismatch
// =========================================================================
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  // Tamper: change content canonicalization after signing
  const tampered = structuredClone(signed);
  (tampered["hiri:content"] as { canonicalization: string }).canonicalization = "URDNA2015";

  const result = await verifyManifest(tampered, keypair.publicKey, "JCS", crypto);
  strictEqual(result, false, "Verification must fail on canonicalization mismatch");

  pass("6.10: Profile Symmetry Rule — verification rejects mismatch");
} catch (e) { fail("6.10: Profile Symmetry Rule — verification rejects mismatch", e); }

// =========================================================================
// 6.11: Manifest version is string in JSON output
// =========================================================================
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  strictEqual(typeof signed["hiri:version"], "string");
  strictEqual(signed["hiri:version"], "1");

  // Also verify in serialized form
  const json = JSON.stringify(signed);
  ok(json.includes('"hiri:version":"1"'), "Serialized version must be quoted string");

  pass("6.11: Manifest version is string in JSON output");
} catch (e) { fail("6.11: Manifest version is string in JSON output", e); }

// =========================================================================
// 6.12: Delta format uses MIME type
// =========================================================================
try {
  const ops = [{ op: "replace" as const, path: "/name", value: "updated" }];
  const { delta } = await buildDelta(ops, contentHash, crypto);

  strictEqual(delta.format, "application/json-patch+json");

  pass("6.12: Delta format uses MIME type (application/json-patch+json)");
} catch (e) { fail("6.12: Delta format uses MIME type (application/json-patch+json)", e); }

// =========================================================================
// 6.13: Delta-canonicalization coupling — JCS requires JSON Patch
// =========================================================================
try {
  const validDelta: ManifestDelta = {
    hash: "abc",
    format: "application/json-patch+json",
    appliesTo: "def",
    operations: 1,
  };
  const result = validateDeltaCoupling("JCS", validDelta);
  strictEqual(result.valid, true);

  const wrongDelta: ManifestDelta = {
    hash: "abc",
    format: "application/rdf-patch",
    appliesTo: "def",
    operations: 1,
  };
  const result2 = validateDeltaCoupling("JCS", wrongDelta);
  strictEqual(result2.valid, false);
  ok(result2.reason!.includes("JSON Patch"), "Should mention JSON Patch");

  pass("6.13: Delta-canonicalization coupling — JCS requires JSON Patch");
} catch (e) { fail("6.13: Delta-canonicalization coupling — JCS requires JSON Patch", e); }

// =========================================================================
// 6.14: Delta-canonicalization coupling — URDNA2015 requires RDF Patch
// =========================================================================
try {
  const rdfDelta: ManifestDelta = {
    hash: "abc",
    format: "application/rdf-patch",
    appliesTo: "def",
    operations: 1,
  };
  const result = validateDeltaCoupling("URDNA2015", rdfDelta);
  strictEqual(result.valid, true);

  const wrongDelta: ManifestDelta = {
    hash: "abc",
    format: "application/json-patch+json",
    appliesTo: "def",
    operations: 1,
  };
  const result2 = validateDeltaCoupling("URDNA2015", wrongDelta);
  strictEqual(result2.valid, false);
  ok(result2.reason!.includes("RDF Patch"), "Should mention RDF Patch");

  pass("6.14: Delta-canonicalization coupling — URDNA2015 requires RDF Patch");
} catch (e) { fail("6.14: Delta-canonicalization coupling — URDNA2015 requires RDF Patch", e); }

// =========================================================================
// 6.15: Context URL is v3.1
// =========================================================================
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  ok(unsigned["@context"].includes("https://hiri-protocol.org/spec/v3.1"), "Context must include v3.1 URL");

  pass("6.15: Context URL is v3.1");
} catch (e) { fail("6.15: Context URL is v3.1", e); }

// =========================================================================
// 6.16: Verification status fields on active key
// =========================================================================
try {
  const keyDoc: KeyDocument = {
    "@context": ["https://hiri-protocol.org/spec/v3.1", "https://w3id.org/security/v2"],
    "@id": `hiri://${authority}/key/main`,
    "@type": "hiri:KeyDocument",
    "hiri:version": "1",
    "hiri:authority": authority,
    "hiri:authorityType": "ed25519",
    "hiri:activeKeys": [{
      "@id": `hiri://${authority}/key/main#key-1`,
      "@type": "Ed25519VerificationKey2020",
      controller: `hiri://${authority}/key/main`,
      publicKeyMultibase: "z" + base58Encode(keypair.publicKey),
      purposes: ["assertionMethod"],
      validFrom: "2025-01-01T00:00:00Z",
    }],
    "hiri:rotatedKeys": [],
    "hiri:revokedKeys": [],
    "hiri:policies": {
      gracePeriodAfterRotation: "P30D",
      minimumKeyValidity: "P365D",
    },
    "hiri:signature": {
      type: "Ed25519Signature2020",
      canonicalization: "JCS",
      created: "2025-01-15T00:00:00Z",
      verificationMethod: `hiri://${authority}/key/main#key-1`,
      proofPurpose: "assertionMethod",
      proofValue: "zDUMMY",
    },
  };

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  const result = resolveSigningKey(signed, keyDoc, "2025-01-15T14:30:00Z");
  strictEqual(result.valid, true);
  strictEqual(result.keyStatus, "active");
  strictEqual(result.revocationStatus, "confirmed-valid");
  strictEqual(result.timestampVerification, "advisory-only");

  pass("6.16: Verification status fields on active key");
} catch (e) { fail("6.16: Verification status fields on active key", e); }

// =========================================================================
// 6.17: deriveAuthority is synchronous (no crypto.hash needed)
// =========================================================================
try {
  const kp = await generateKeypair();
  const auth = deriveAuthority(kp.publicKey, "ed25519");
  ok(auth.startsWith("key:ed25519:z"), "Should produce valid authority synchronously");

  pass("6.17: deriveAuthority is synchronous (no crypto.hash needed)");
} catch (e) { fail("6.17: deriveAuthority is synchronous (no crypto.hash needed)", e); }

// =========================================================================
// 6.18: Signature verification discovers profile from manifest
// =========================================================================
try {
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/test`,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  // Discover profile from manifest, then verify
  const discoveredProfile = signed["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
  strictEqual(discoveredProfile, "JCS");
  const valid = await verifyManifest(signed, keypair.publicKey, discoveredProfile, crypto);
  strictEqual(valid, true);

  // Wrong profile should fail
  const wrongResult = await verifyManifest(signed, keypair.publicKey, "URDNA2015", crypto);
  strictEqual(wrongResult, false);

  pass("6.18: Signature verification discovers profile from manifest");
} catch (e) { fail("6.18: Signature verification discovers profile from manifest", e); }

// =========================================================================
// 6.19: isMonotonicallyIncreasing works with string versions
// =========================================================================
try {
  strictEqual(isMonotonicallyIncreasing("2", "1"), true);
  strictEqual(isMonotonicallyIncreasing("1", "2"), false);
  strictEqual(isMonotonicallyIncreasing("1", "1"), false);
  strictEqual(isMonotonicallyIncreasing("100", "99"), true);
  strictEqual(isMonotonicallyIncreasing("9007199254740993", "9007199254740992"), true);

  pass("6.19: isMonotonicallyIncreasing works with string versions");
} catch (e) { fail("6.19: isMonotonicallyIncreasing works with string versions", e); }

// =========================================================================
// 6.20: Full manifest round-trip with all v3.1.1 fields
// =========================================================================
try {
  const uri = `hiri://${authority}/data/round-trip`;
  const unsigned = buildUnsignedManifest({
    id: uri,
    version: "1",
    branch: "main",
    created: "2025-01-15T14:30:00Z",
    contentHash,
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  // Verify all v3.1.1 fields present
  strictEqual(signed["@id"], uri);
  strictEqual(typeof signed["hiri:version"], "string");
  strictEqual(signed["hiri:version"], "1");
  strictEqual(signed["hiri:content"].addressing, "raw-sha256");
  strictEqual(signed["hiri:content"].canonicalization, "JCS");
  strictEqual(signed["hiri:signature"].canonicalization, "JCS");
  ok(signed["@context"].includes("https://hiri-protocol.org/spec/v3.1"));

  // Verify signature
  const verified = await verifyManifest(signed, keypair.publicKey, "JCS", crypto);
  strictEqual(verified, true);

  // Serialize -> deserialize -> verify still works
  const serialized = stableStringify(signed, false);
  const deserialized = JSON.parse(serialized) as ResolutionManifest;
  const verified2 = await verifyManifest(deserialized, keypair.publicKey, "JCS", crypto);
  strictEqual(verified2, true);

  pass("6.20: Full manifest round-trip with all v3.1.1 fields");
} catch (e) { fail("6.20: Full manifest round-trip with all v3.1.1 fields", e); }

// =========================================================================
// Summary
// =========================================================================

console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
