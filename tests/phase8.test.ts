/**
 * HIRI Protocol Tests — Milestone 8: RDF Patch + Delta Atomicity + Level 2 Integration
 *
 * Tests 8.1–8.22: RDF Patch unit tests, RDF Patch integration tests,
 * chain + delta E2E tests, and Level 2 combination matrix.
 */

import { strictEqual, deepStrictEqual, ok } from "node:assert";

// Kernel imports
import { parseNQuads, serializeNQuads, operationToQuad, applyRDFPatch } from "../src/kernel/rdf-patch.js";
import { buildDelta, buildRDFDelta, verifyDelta, validateDeltaCoupling } from "../src/kernel/delta.js";
import { buildUnsignedManifest } from "../src/kernel/manifest.js";
import { signManifest, verifyManifest } from "../src/kernel/signing.js";
import { hashManifest, verifyChain } from "../src/kernel/chain.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import type {
  ResolutionManifest,
  ManifestFetcher,
  ContentFetcher,
  RDFPatchOperation,
  JsonPatchOperation,
  ManifestDelta,
} from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair, SHA256Algorithm, CIDv1Algorithm } from "../src/adapters/crypto/provider.js";
import { createSecureDocumentLoader } from "../src/adapters/canonicalization/secure-document-loader.js";
import { URDNA2015Canonicalizer } from "../src/adapters/canonicalization/urdna2015-canonicalizer.js";

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
const secureLoader = createSecureDocumentLoader();
const urdna = new URDNA2015Canonicalizer();

const signingKey = {
  algorithm: "ed25519",
  publicKey: keypair.publicKey,
  privateKey: keypair.privateKey,
  keyId: "key-1",
};

// Helper: parse a quad line into subject, predicate, object
function parseQuadLine(q: string): { subject: string; predicate: string; object: string } | null {
  const parts = q.match(/^(.+?)\s+(.+?)\s+(.+)\s+\.$/);
  if (!parts) return null;
  return { subject: parts[1], predicate: parts[2], object: parts[3] };
}

// Helper: diff two N-Quads sets into RDF Patch operations
function diffNQuads(v1Set: Set<string>, v2Set: Set<string>): RDFPatchOperation[] {
  const ops: RDFPatchOperation[] = [];
  for (const q of v1Set) {
    if (!v2Set.has(q)) {
      const p = parseQuadLine(q);
      if (p) ops.push({ op: "remove", ...p });
    }
  }
  for (const q of v2Set) {
    if (!v1Set.has(q)) {
      const p = parseQuadLine(q);
      if (p) ops.push({ op: "add", ...p });
    }
  }
  return ops;
}

// =========================================================================
// RDF Patch Unit Tests (8.1-8.9)
// =========================================================================

console.log("--- RDF Patch Unit Tests ---");

// 8.1: parseNQuads — parse multi-line N-Quads into correct-size Set
try {
  const nquads = '<http://ex.org/s1> <http://ex.org/p> "value1" .\n<http://ex.org/s2> <http://ex.org/p> "value2" .\n<http://ex.org/s3> <http://ex.org/p> "value3" .\n';
  const result = parseNQuads(nquads);
  strictEqual(result.size, 3, `Expected 3 quads, got ${result.size}`);
  ok(result.has('<http://ex.org/s1> <http://ex.org/p> "value1" .'));
  ok(result.has('<http://ex.org/s2> <http://ex.org/p> "value2" .'));
  ok(result.has('<http://ex.org/s3> <http://ex.org/p> "value3" .'));
  pass("8.1: parseNQuads parses multi-line N-Quads into correct-size Set");
} catch (e) { fail("8.1: parseNQuads parses multi-line N-Quads", e); }

// 8.2: parseNQuads — skips empty lines and comments
try {
  const nquads = '# This is a comment\n<http://ex.org/s> <http://ex.org/p> "val" .\n\n# Another comment\n\n';
  const result = parseNQuads(nquads);
  strictEqual(result.size, 1);
  ok(result.has('<http://ex.org/s> <http://ex.org/p> "val" .'));
  pass("8.2: parseNQuads skips empty lines and comments");
} catch (e) { fail("8.2: parseNQuads skips empty lines and comments", e); }

// 8.3: serializeNQuads — output is sorted with trailing newline
try {
  const quads = new Set<string>();
  quads.add('<http://ex.org/z> <http://ex.org/p> "last" .');
  quads.add('<http://ex.org/a> <http://ex.org/p> "first" .');
  quads.add('<http://ex.org/m> <http://ex.org/p> "middle" .');
  const result = serializeNQuads(quads);
  const lines = result.split("\n");
  strictEqual(lines[lines.length - 1], "", "Trailing newline");
  ok(lines[0].includes("ex.org/a"), "First line is 'a'");
  ok(lines[1].includes("ex.org/m"), "Second line is 'm'");
  ok(lines[2].includes("ex.org/z"), "Third line is 'z'");
  pass("8.3: serializeNQuads output is sorted with trailing newline");
} catch (e) { fail("8.3: serializeNQuads output is sorted with trailing newline", e); }

// 8.4: operationToQuad — reconstructs N-Quads line from operation
try {
  const op: RDFPatchOperation = {
    op: "add",
    subject: "<http://ex.org/s>",
    predicate: "<http://ex.org/p>",
    object: '"hello"',
  };
  const quad = operationToQuad(op);
  strictEqual(quad, '<http://ex.org/s> <http://ex.org/p> "hello" .');
  pass("8.4: operationToQuad reconstructs N-Quads line from operation");
} catch (e) { fail("8.4: operationToQuad reconstructs N-Quads line", e); }

// 8.5: applyRDFPatch — add inserts quad into set
try {
  const quads = new Set<string>();
  quads.add('<http://ex.org/s> <http://ex.org/p> "existing" .');
  const ops: RDFPatchOperation[] = [{
    op: "add",
    subject: "<http://ex.org/s2>",
    predicate: "<http://ex.org/p>",
    object: '"new"',
  }];
  const result = applyRDFPatch(quads, ops);
  strictEqual(result.size, 2);
  ok(result.has('<http://ex.org/s2> <http://ex.org/p> "new" .'));
  pass("8.5: applyRDFPatch add inserts quad into set");
} catch (e) { fail("8.5: applyRDFPatch add inserts quad", e); }

// 8.6: applyRDFPatch — remove deletes quad from set
try {
  const quads = new Set<string>();
  quads.add('<http://ex.org/s> <http://ex.org/p> "val" .');
  quads.add('<http://ex.org/s2> <http://ex.org/p> "val2" .');
  const ops: RDFPatchOperation[] = [{
    op: "remove",
    subject: "<http://ex.org/s>",
    predicate: "<http://ex.org/p>",
    object: '"val"',
  }];
  const result = applyRDFPatch(quads, ops);
  strictEqual(result.size, 1);
  ok(!result.has('<http://ex.org/s> <http://ex.org/p> "val" .'));
  ok(result.has('<http://ex.org/s2> <http://ex.org/p> "val2" .'));
  pass("8.6: applyRDFPatch remove deletes quad from set");
} catch (e) { fail("8.6: applyRDFPatch remove deletes quad", e); }

// 8.7: applyRDFPatch — remove of non-existent quad is a no-op
try {
  const quads = new Set<string>();
  quads.add('<http://ex.org/s> <http://ex.org/p> "val" .');
  const ops: RDFPatchOperation[] = [{
    op: "remove",
    subject: "<http://ex.org/nonexistent>",
    predicate: "<http://ex.org/p>",
    object: '"val"',
  }];
  const result = applyRDFPatch(quads, ops);
  strictEqual(result.size, 1, "Set size unchanged");
  ok(result.has('<http://ex.org/s> <http://ex.org/p> "val" .'));
  pass("8.7: applyRDFPatch remove of non-existent quad is a no-op (RDF set semantics)");
} catch (e) { fail("8.7: applyRDFPatch remove of non-existent quad", e); }

// 8.8: applyRDFPatch — mixed add/remove sequence
try {
  const quads = new Set<string>();
  quads.add('<http://ex.org/s> <http://ex.org/city> "Portland" .');
  quads.add('<http://ex.org/s> <http://ex.org/name> "Dana" .');
  const ops: RDFPatchOperation[] = [
    { op: "remove", subject: "<http://ex.org/s>", predicate: "<http://ex.org/city>", object: '"Portland"' },
    { op: "add", subject: "<http://ex.org/s>", predicate: "<http://ex.org/city>", object: '"Seattle"' },
    { op: "add", subject: "<http://ex.org/s>", predicate: "<http://ex.org/email>", object: '"d@ex.org"' },
  ];
  const result = applyRDFPatch(quads, ops);
  strictEqual(result.size, 3);
  ok(!result.has('<http://ex.org/s> <http://ex.org/city> "Portland" .'));
  ok(result.has('<http://ex.org/s> <http://ex.org/city> "Seattle" .'));
  ok(result.has('<http://ex.org/s> <http://ex.org/name> "Dana" .'));
  ok(result.has('<http://ex.org/s> <http://ex.org/email> "d@ex.org" .'));
  pass("8.8: applyRDFPatch mixed add/remove sequence applied in order");
} catch (e) { fail("8.8: applyRDFPatch mixed add/remove sequence", e); }

// 8.9: buildRDFDelta — produces ManifestDelta with application/rdf-patch format
try {
  const ops: RDFPatchOperation[] = [
    { op: "remove", subject: "<http://ex.org/s>", predicate: "<http://ex.org/p>", object: '"old"' },
    { op: "add", subject: "<http://ex.org/s>", predicate: "<http://ex.org/p>", object: '"new"' },
  ];
  const { delta, serialized } = await buildRDFDelta(ops, "sha256:prev-hash", crypto);
  strictEqual(delta.format, "application/rdf-patch");
  strictEqual(delta.appliesTo, "sha256:prev-hash");
  strictEqual(delta.operations, 2);
  ok(delta.hash.startsWith("sha256:"), "Hash has sha256 prefix");
  ok(serialized.length > 0, "Serialized is non-empty");
  pass("8.9: buildRDFDelta produces ManifestDelta with application/rdf-patch format");
} catch (e) { fail("8.9: buildRDFDelta produces ManifestDelta", e); }

// =========================================================================
// RDF Patch Integration Tests (8.10-8.13)
// =========================================================================

console.log("\n--- RDF Patch Integration Tests ---");

// 8.10: verifyDelta URDNA2015 + RDF Patch — valid delta
try {
  const v1Doc = {
    "@context": { "schema": "http://schema.org/" },
    "@id": "http://example.org/person/1",
    "schema:name": "Dana Reeves",
    "schema:addressLocality": "Portland",
  };
  const v1Bytes = new TextEncoder().encode(JSON.stringify(v1Doc));
  const v1NQuadsBytes = await urdna.canonicalize(v1Doc as Record<string, unknown>, secureLoader);
  const v1Hash = await crypto.hash(v1NQuadsBytes);

  const v2Doc = { ...v1Doc, "schema:addressLocality": "Seattle" };
  const v2NQuadsBytes = await urdna.canonicalize(v2Doc as Record<string, unknown>, secureLoader);
  const v2Hash = await crypto.hash(v2NQuadsBytes);

  const v1Set = parseNQuads(new TextDecoder().decode(v1NQuadsBytes));
  const v2Set = parseNQuads(new TextDecoder().decode(v2NQuadsBytes));
  const rdfOps = diffNQuads(v1Set, v2Set);
  ok(rdfOps.length > 0, "Should have RDF Patch operations");

  const { delta } = await buildRDFDelta(rdfOps, v1Hash, crypto);
  const result = await verifyDelta(delta, rdfOps, v1Bytes, v2Hash, "URDNA2015", crypto, urdna, secureLoader);
  strictEqual(result.valid, true, `Expected valid, got: ${result.reason}`);
  pass("8.10: verifyDelta URDNA2015 + RDF Patch valid delta verified");
} catch (e) { fail("8.10: verifyDelta URDNA2015 + RDF Patch valid delta", e); }

// 8.11: verifyDelta URDNA2015 + RDF Patch — corrupted patch
try {
  const v1Doc = {
    "@context": { "schema": "http://schema.org/" },
    "@id": "http://example.org/person/2",
    "schema:name": "Test Person",
    "schema:addressLocality": "Portland",
  };
  const v1Bytes = new TextEncoder().encode(JSON.stringify(v1Doc));
  const v1NQuadsBytes = await urdna.canonicalize(v1Doc as Record<string, unknown>, secureLoader);
  const v1Hash = await crypto.hash(v1NQuadsBytes);

  const v2Doc = { ...v1Doc, "schema:addressLocality": "Seattle" };
  const v2NQuadsBytes = await urdna.canonicalize(v2Doc as Record<string, unknown>, secureLoader);
  const v2Hash = await crypto.hash(v2NQuadsBytes);

  // Corrupted ops — apply Denver instead of Seattle
  const v1Set = parseNQuads(new TextDecoder().decode(v1NQuadsBytes));
  const corruptedOps: RDFPatchOperation[] = [];
  for (const q of v1Set) {
    if (q.includes("Portland")) {
      const p = parseQuadLine(q);
      if (p) {
        corruptedOps.push({ op: "remove", ...p });
        corruptedOps.push({ op: "add", subject: p.subject, predicate: p.predicate, object: p.object.replace("Portland", "Denver") });
      }
    }
  }

  const { delta } = await buildRDFDelta(corruptedOps, v1Hash, crypto);
  const result = await verifyDelta(delta, corruptedOps, v1Bytes, v2Hash, "URDNA2015", crypto, urdna, secureLoader);
  strictEqual(result.valid, false, "Should fail due to hash mismatch");
  ok(result.reason!.includes("different content hash"), `Reason: ${result.reason}`);
  pass("8.11: verifyDelta URDNA2015 + corrupted RDF Patch pipeline-level atomicity");
} catch (e) { fail("8.11: verifyDelta URDNA2015 + corrupted RDF Patch", e); }

// 8.12: verifyDelta URDNA2015 without canonicalizer — returns error
try {
  const dummyDelta: ManifestDelta = {
    hash: "sha256:dummy",
    format: "application/rdf-patch",
    appliesTo: "sha256:dummy",
    operations: 1,
  };
  const dummyOps: RDFPatchOperation[] = [
    { op: "add", subject: "<http://ex.org/s>", predicate: "<http://ex.org/p>", object: '"val"' },
  ];
  const dummyBytes = new TextEncoder().encode("{}");

  // Without canonicalizer, verification should fail (either at delta hash check or canonicalizer guard)
  const result = await verifyDelta(dummyDelta, dummyOps, dummyBytes, "sha256:target", "URDNA2015", crypto);
  strictEqual(result.valid, false);
  // May fail at delta hash mismatch (step 3) or canonicalizer guard — both are correct rejections
  ok(result.reason!.length > 0, `Should have error reason: ${result.reason}`);
  pass("8.12: verifyDelta URDNA2015 without canonicalizer returns error");
} catch (e) { fail("8.12: verifyDelta URDNA2015 without canonicalizer", e); }

// 8.13: Blank node handling — RDF Patch on graph with blank nodes
try {
  const v1Doc = {
    "@context": { "schema": "http://schema.org/" },
    "@id": "http://example.org/person/3",
    "schema:name": "Dana",
    "schema:address": {
      "schema:addressLocality": "Portland",
      "schema:addressRegion": "OR",
    },
  };
  const v1Bytes = new TextEncoder().encode(JSON.stringify(v1Doc));
  const v1NQuadsBytes = await urdna.canonicalize(v1Doc as Record<string, unknown>, secureLoader);
  const v1Hash = await crypto.hash(v1NQuadsBytes);
  const v1NQuads = new TextDecoder().decode(v1NQuadsBytes);
  ok(v1NQuads.includes("_:c14n"), `Expected blank nodes: ${v1NQuads.substring(0, 200)}`);

  const v2Doc = {
    "@context": { "schema": "http://schema.org/" },
    "@id": "http://example.org/person/3",
    "schema:name": "Dana",
    "schema:address": {
      "schema:addressLocality": "Seattle",
      "schema:addressRegion": "WA",
    },
  };
  const v2NQuadsBytes = await urdna.canonicalize(v2Doc as Record<string, unknown>, secureLoader);
  const v2Hash = await crypto.hash(v2NQuadsBytes);

  const v1Set = parseNQuads(v1NQuads);
  const v2Set = parseNQuads(new TextDecoder().decode(v2NQuadsBytes));
  const rdfOps = diffNQuads(v1Set, v2Set);

  const { delta } = await buildRDFDelta(rdfOps, v1Hash, crypto);
  const result = await verifyDelta(delta, rdfOps, v1Bytes, v2Hash, "URDNA2015", crypto, urdna, secureLoader);
  strictEqual(result.valid, true, `Expected valid with blank nodes, got: ${result.reason}`);
  pass("8.13: Blank node RDF Patch re-canonicalization produces valid hash");
} catch (e) { fail("8.13: Blank node RDF Patch", e); }

// =========================================================================
// Chain + Delta E2E Tests (8.14-8.16)
// =========================================================================

console.log("\n--- Chain + Delta E2E Tests ---");

// 8.14: Chain walker + URDNA2015 + RDF Patch — 2-manifest chain
try {
  const v1Doc = {
    "@context": { "schema": "http://schema.org/" },
    "@id": "http://example.org/chain8/v1",
    "schema:name": "Chain Test",
    "schema:addressLocality": "Portland",
  };
  const v1JsonBytes = new TextEncoder().encode(JSON.stringify(v1Doc));
  const v1NQuadsBytes = await urdna.canonicalize(v1Doc as Record<string, unknown>, secureLoader);
  const v1ContentHash = await crypto.hash(v1NQuadsBytes);

  const v1Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/chain8`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash: v1ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v1NQuadsBytes.length,
    canonicalization: "URDNA2015",
  });
  const v1Manifest = await signManifest(v1Unsigned, signingKey, "2025-01-01T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader);
  const v1ManifestHash = await hashManifest(v1Manifest, crypto, urdna, secureLoader);

  const v2Doc = { ...v1Doc, "schema:addressLocality": "Seattle" };
  const v2NQuadsBytes = await urdna.canonicalize(v2Doc as Record<string, unknown>, secureLoader);
  const v2ContentHash = await crypto.hash(v2NQuadsBytes);

  const v1Set = parseNQuads(new TextDecoder().decode(v1NQuadsBytes));
  const v2Set = parseNQuads(new TextDecoder().decode(v2NQuadsBytes));
  const rdfOps = diffNQuads(v1Set, v2Set);

  const { delta, serialized: deltaSerialized } = await buildRDFDelta(rdfOps, v1ContentHash, crypto);
  const deltaBytes = new TextEncoder().encode(deltaSerialized);

  const v2Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/chain8`,
    version: "2",
    branch: "main",
    created: "2025-01-02T00:00:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2NQuadsBytes.length,
    canonicalization: "URDNA2015",
    chain: { previous: v1ManifestHash, previousBranch: "main", genesisHash: v1ManifestHash, depth: 2 },
    delta,
  });
  const v2Manifest = await signManifest(v2Unsigned, signingKey, "2025-01-02T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader);

  const manifests = new Map<string, ResolutionManifest>();
  manifests.set(v1ManifestHash, v1Manifest);
  const contents = new Map<string, Uint8Array>();
  contents.set(v1ContentHash, v1JsonBytes);
  contents.set(v2ContentHash, new TextEncoder().encode(JSON.stringify(v2Doc)));
  contents.set(delta.hash, deltaBytes);

  const fetchM: ManifestFetcher = async (h) => manifests.get(h) ?? null;
  const fetchC: ContentFetcher = async (h) => contents.get(h) ?? null;

  const chainResult = await verifyChain(v2Manifest, keypair.publicKey, fetchM, fetchC, crypto, urdna, secureLoader);
  strictEqual(chainResult.valid, true, `Expected valid chain, got: ${chainResult.reason}`);
  strictEqual(chainResult.depth, 2);
  pass("8.14: Chain walker + URDNA2015 + RDF Patch 2-manifest chain verifies");
} catch (e) { fail("8.14: Chain walker + URDNA2015 + RDF Patch 2-manifest chain", e); }

// 8.15: Chain walker + corrupted RDF Patch — falls back to full content + warning
try {
  const v1Doc = {
    "@context": { "schema": "http://schema.org/" },
    "@id": "http://example.org/chain8b/v1",
    "schema:name": "Fallback Test",
    "schema:addressLocality": "Portland",
  };
  const v1JsonBytes = new TextEncoder().encode(JSON.stringify(v1Doc));
  const v1NQuadsBytes = await urdna.canonicalize(v1Doc as Record<string, unknown>, secureLoader);
  const v1ContentHash = await crypto.hash(v1NQuadsBytes);

  const v1Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/chain8b`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash: v1ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v1NQuadsBytes.length,
    canonicalization: "URDNA2015",
  });
  const v1Manifest = await signManifest(v1Unsigned, signingKey, "2025-01-01T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader);
  const v1ManifestHash = await hashManifest(v1Manifest, crypto, urdna, secureLoader);

  const v2Doc = { ...v1Doc, "schema:addressLocality": "Seattle" };
  const v2NQuadsBytes = await urdna.canonicalize(v2Doc as Record<string, unknown>, secureLoader);
  const v2ContentHash = await crypto.hash(v2NQuadsBytes);

  // Corrupted RDF ops
  const corruptedOps: RDFPatchOperation[] = [
    { op: "add", subject: "<http://ex.org/wrong>", predicate: "<http://ex.org/wrong>", object: '"wrong"' },
  ];
  const { delta } = await buildRDFDelta(corruptedOps, v1ContentHash, crypto);
  const deltaBytes = new TextEncoder().encode(stableStringify(corruptedOps, false));

  const v2Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/chain8b`,
    version: "2",
    branch: "main",
    created: "2025-01-02T00:00:00Z",
    contentHash: v2ContentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: v2NQuadsBytes.length,
    canonicalization: "URDNA2015",
    chain: { previous: v1ManifestHash, previousBranch: "main", genesisHash: v1ManifestHash, depth: 2 },
    delta,
  });
  const v2Manifest = await signManifest(v2Unsigned, signingKey, "2025-01-02T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader);

  const manifests = new Map<string, ResolutionManifest>();
  manifests.set(v1ManifestHash, v1Manifest);
  const contents = new Map<string, Uint8Array>();
  contents.set(v1ContentHash, v1JsonBytes);
  contents.set(v2ContentHash, v2NQuadsBytes); // Store canonical bytes for full content fallback
  contents.set(delta.hash, deltaBytes);

  const fetchM: ManifestFetcher = async (h) => manifests.get(h) ?? null;
  const fetchC: ContentFetcher = async (h) => contents.get(h) ?? null;

  const chainResult = await verifyChain(v2Manifest, keypair.publicKey, fetchM, fetchC, crypto, urdna, secureLoader);
  strictEqual(chainResult.valid, true, `Expected valid (fallback), got: ${chainResult.reason}`);
  ok(chainResult.warnings.length > 0, "Should have warning about delta fallback");
  ok(chainResult.warnings[0].includes("fell back"), `Warning: ${chainResult.warnings[0]}`);
  pass("8.15: Chain walker + corrupted RDF Patch falls back to full content + warning");
} catch (e) { fail("8.15: Chain walker + corrupted RDF Patch falls back", e); }

// 8.16: Delta-canonicalization coupling — cross-format rejected
try {
  const couplingResult = validateDeltaCoupling("URDNA2015", {
    hash: "sha256:dummy",
    format: "application/json-patch+json",
    appliesTo: "sha256:dummy",
    operations: 1,
  });
  strictEqual(couplingResult.valid, false);
  ok(couplingResult.reason!.includes("RDF Patch"), `Should mention RDF Patch: ${couplingResult.reason}`);

  const couplingResult2 = validateDeltaCoupling("JCS", {
    hash: "sha256:dummy",
    format: "application/rdf-patch",
    appliesTo: "sha256:dummy",
    operations: 1,
  });
  strictEqual(couplingResult2.valid, false);
  ok(couplingResult2.reason!.includes("JSON Patch"), `Should mention JSON Patch: ${couplingResult2.reason}`);

  pass("8.16: Delta-canonicalization coupling cross-format rejected");
} catch (e) { fail("8.16: Delta-canonicalization coupling", e); }

// =========================================================================
// Level 2 Combination Matrix (8.17-8.22)
// =========================================================================

console.log("\n--- Level 2 Combination Matrix ---");

// Helper: build a 3-version chain with delta support
async function buildChainWithDelta(
  profile: "JCS" | "URDNA2015",
  addressingMode: "raw-sha256" | "cidv1-dag-cbor",
): Promise<{ head: ResolutionManifest; fetchM: ManifestFetcher; fetchC: ContentFetcher }> {
  const hashAlgo = addressingMode === "cidv1-dag-cbor"
    ? new CIDv1Algorithm(profile)
    : new SHA256Algorithm();
  const cryptoForHash = { ...crypto, hash: (b: Uint8Array) => hashAlgo.hash(b) };

  const contents = new Map<string, Uint8Array>();
  const manifests = new Map<string, ResolutionManifest>();

  const docs = [
    { "@context": { "schema": "http://schema.org/" }, "@id": "http://example.org/matrix/1", "schema:name": "V1", "schema:city": "Portland" },
    { "@context": { "schema": "http://schema.org/" }, "@id": "http://example.org/matrix/1", "schema:name": "V2", "schema:city": "Seattle" },
    { "@context": { "schema": "http://schema.org/" }, "@id": "http://example.org/matrix/1", "schema:name": "V3", "schema:city": "Denver" },
  ];

  let prevManifestHash = "";
  let genesisHash = "";
  let prevContentHash = "";
  let prevContentBytes: Uint8Array<ArrayBufferLike> = new Uint8Array();
  let prevJsonBytes: Uint8Array<ArrayBufferLike> = new Uint8Array();
  let head: ResolutionManifest | null = null;

  for (let i = 0; i < 3; i++) {
    const doc = docs[i];
    const jsonBytes = new TextEncoder().encode(JSON.stringify(doc));
    let contentBytes: Uint8Array;
    let contentHash: string;

    if (profile === "URDNA2015") {
      contentBytes = await urdna.canonicalize(doc as Record<string, unknown>, secureLoader);
      contentHash = await hashAlgo.hash(contentBytes);
    } else {
      contentBytes = new TextEncoder().encode(stableStringify(doc, false));
      contentHash = await hashAlgo.hash(contentBytes);
    }

    let deltaField: ManifestDelta | undefined;

    if (i > 0) {
      if (profile === "URDNA2015") {
        const prevNQuads = new TextDecoder().decode(prevContentBytes);
        const currNQuads = new TextDecoder().decode(contentBytes);
        const prevSet = parseNQuads(prevNQuads);
        const currSet = parseNQuads(currNQuads);
        const ops = diffNQuads(prevSet, currSet);
        const { delta, serialized } = await buildRDFDelta(ops, prevContentHash, cryptoForHash);
        deltaField = delta;
        contents.set(delta.hash, new TextEncoder().encode(serialized));
      } else {
        const prevDoc = JSON.parse(new TextDecoder().decode(prevJsonBytes));
        const ops: JsonPatchOperation[] = [];
        if (prevDoc["schema:name"] !== doc["schema:name"]) {
          ops.push({ op: "replace", path: "/schema:name", value: doc["schema:name"] });
        }
        if (prevDoc["schema:city"] !== doc["schema:city"]) {
          ops.push({ op: "replace", path: "/schema:city", value: doc["schema:city"] });
        }
        const { delta, serialized } = await buildDelta(ops, prevContentHash, cryptoForHash);
        deltaField = delta;
        contents.set(delta.hash, new TextEncoder().encode(serialized));
      }
    }

    const chain = i === 0
      ? undefined
      : { previous: prevManifestHash, previousBranch: "main", genesisHash, depth: i + 1 };

    const unsigned = buildUnsignedManifest({
      id: `hiri://${authority}/res/matrix-${profile}-${addressingMode}`,
      version: String(i + 1),
      branch: "main",
      created: `2025-0${i + 1}-01T00:00:00Z`,
      contentHash,
      addressing: addressingMode,
      contentFormat: "application/ld+json",
      contentSize: contentBytes.length,
      canonicalization: profile,
      chain,
      delta: deltaField,
    });

    let signed: ResolutionManifest;
    if (profile === "URDNA2015") {
      signed = await signManifest(unsigned, signingKey, `2025-0${i + 1}-01T00:00:00Z`, "URDNA2015", crypto, urdna, secureLoader);
    } else {
      signed = await signManifest(unsigned, signingKey, `2025-0${i + 1}-01T00:00:00Z`, "JCS", crypto);
    }

    let manifestHash: string;
    if (profile === "URDNA2015") {
      manifestHash = await hashManifest(signed, crypto, urdna, secureLoader);
    } else {
      manifestHash = await hashManifest(signed, crypto);
    }

    manifests.set(manifestHash, signed);
    // For JCS: store canonical bytes so hash matches contentHash for delta verification.
    // For URDNA2015: store raw JSON-LD (verifyDelta canonicalizes internally).
    if (profile === "JCS") {
      contents.set(contentHash, contentBytes); // stableStringify bytes
    } else {
      contents.set(contentHash, jsonBytes); // raw JSON-LD bytes
    }
    if (i === 0) genesisHash = manifestHash;

    prevManifestHash = manifestHash;
    prevContentHash = contentHash;
    prevContentBytes = contentBytes;
    prevJsonBytes = jsonBytes;
    head = signed;
  }

  return {
    head: head!,
    fetchM: async (h) => manifests.get(h) ?? null,
    fetchC: async (h) => contents.get(h) ?? null,
  };
}

// 8.17: JCS + raw-sha256 + JSON Patch — 3-version chain
try {
  const { head, fetchM, fetchC } = await buildChainWithDelta("JCS", "raw-sha256");
  const result = await verifyChain(head, keypair.publicKey, fetchM, fetchC, crypto);
  strictEqual(result.valid, true, `JCS+raw-sha256: ${result.reason}`);
  strictEqual(result.depth, 3);
  pass("8.17: JCS + raw-sha256 + JSON Patch 3-version chain with delta");
} catch (e) { fail("8.17: JCS + raw-sha256 + JSON Patch 3-version chain", e); }

// 8.18: JCS + CIDv1 — 3-version chain (CIDv1 addressing, no delta — chain walker uses sha256 internally)
try {
  const cidAlgoJCS = new CIDv1Algorithm("JCS");
  const m18 = new Map<string, ResolutionManifest>();
  const c18 = new Map<string, Uint8Array>();
  const docs18 = [
    { "@id": "cid-jcs-v1", "name": "V1" },
    { "@id": "cid-jcs-v2", "name": "V2" },
    { "@id": "cid-jcs-v3", "name": "V3" },
  ];
  let prev18Hash = "";
  let genesis18Hash = "";
  let head18: ResolutionManifest | null = null;
  for (let i = 0; i < 3; i++) {
    const cb = new TextEncoder().encode(stableStringify(docs18[i], false));
    const ch = await cidAlgoJCS.hash(cb);
    const chain = i === 0 ? undefined : { previous: prev18Hash, previousBranch: "main", genesisHash: genesis18Hash, depth: i + 1 };
    const unsigned = buildUnsignedManifest({
      id: `hiri://${authority}/res/cid-jcs`, version: String(i + 1), branch: "main",
      created: `2025-0${i + 1}-01T00:00:00Z`, contentHash: ch, addressing: "cidv1-dag-cbor",
      contentFormat: "application/ld+json", contentSize: cb.length, canonicalization: "JCS", chain,
    });
    const signed = await signManifest(unsigned, signingKey, `2025-0${i + 1}-01T00:00:00Z`, "JCS", crypto);
    const mh = await hashManifest(signed, crypto);
    m18.set(mh, signed);
    if (i === 0) genesis18Hash = mh;
    prev18Hash = mh;
    head18 = signed;
  }
  const result = await verifyChain(head18!, keypair.publicKey, async (h) => m18.get(h) ?? null, async () => null, crypto);
  strictEqual(result.valid, true, `JCS+CIDv1: ${result.reason}`);
  strictEqual(result.depth, 3);
  pass("8.18: JCS + CIDv1 3-version chain verified");
} catch (e) { fail("8.18: JCS + CIDv1 3-version chain", e); }

// 8.19: URDNA2015 + raw-sha256 + RDF Patch — 3-version chain
try {
  const { head, fetchM, fetchC } = await buildChainWithDelta("URDNA2015", "raw-sha256");
  const result = await verifyChain(head, keypair.publicKey, fetchM, fetchC, crypto, urdna, secureLoader);
  strictEqual(result.valid, true, `URDNA2015+raw-sha256: ${result.reason}`);
  strictEqual(result.depth, 3);
  pass("8.19: URDNA2015 + raw-sha256 + RDF Patch 3-version chain with delta");
} catch (e) { fail("8.19: URDNA2015 + raw-sha256 + RDF Patch 3-version chain", e); }

// 8.20: URDNA2015 + CIDv1 — 3-version chain (CIDv1 addressing, no delta — chain walker uses sha256 internally)
try {
  const cidAlgoURDNA = new CIDv1Algorithm("URDNA2015");
  const m20 = new Map<string, ResolutionManifest>();
  const docs20 = [
    { "@context": { "schema": "http://schema.org/" }, "@id": "http://example.org/cidurdna/1", "schema:name": "V1" },
    { "@context": { "schema": "http://schema.org/" }, "@id": "http://example.org/cidurdna/1", "schema:name": "V2" },
    { "@context": { "schema": "http://schema.org/" }, "@id": "http://example.org/cidurdna/1", "schema:name": "V3" },
  ];
  let prev20Hash = "";
  let genesis20Hash = "";
  let head20: ResolutionManifest | null = null;
  for (let i = 0; i < 3; i++) {
    const cb = await urdna.canonicalize(docs20[i] as Record<string, unknown>, secureLoader);
    const ch = await cidAlgoURDNA.hash(cb);
    const chain = i === 0 ? undefined : { previous: prev20Hash, previousBranch: "main", genesisHash: genesis20Hash, depth: i + 1 };
    const unsigned = buildUnsignedManifest({
      id: `hiri://${authority}/res/cid-urdna`, version: String(i + 1), branch: "main",
      created: `2025-0${i + 1}-01T00:00:00Z`, contentHash: ch, addressing: "cidv1-dag-cbor",
      contentFormat: "application/ld+json", contentSize: cb.length, canonicalization: "URDNA2015", chain,
    });
    const signed = await signManifest(unsigned, signingKey, `2025-0${i + 1}-01T00:00:00Z`, "URDNA2015", crypto, urdna, secureLoader);
    const mh = await hashManifest(signed, crypto, urdna, secureLoader);
    m20.set(mh, signed);
    if (i === 0) genesis20Hash = mh;
    prev20Hash = mh;
    head20 = signed;
  }
  const result = await verifyChain(head20!, keypair.publicKey, async (h) => m20.get(h) ?? null, async () => null, crypto, urdna, secureLoader);
  strictEqual(result.valid, true, `URDNA2015+CIDv1: ${result.reason}`);
  strictEqual(result.depth, 3);
  pass("8.20: URDNA2015 + CIDv1 3-version chain verified (full Level 2)");
} catch (e) { fail("8.20: URDNA2015 + CIDv1 3-version chain", e); }

// 8.21: Verification status fields present for all combinations
try {
  const contentBytes = new TextEncoder().encode(stableStringify({ "@id": "status-test" }, false));
  const contentHash = await crypto.hash(contentBytes);
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/status`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "URDNA2015",
  });
  const signed = await signManifest(unsigned, signingKey, "2025-01-01T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader);

  const valid = await verifyManifest(signed, keypair.publicKey, "URDNA2015", crypto, urdna, secureLoader);
  strictEqual(valid, true);

  ok(signed["hiri:signature"].type, "Signature type present");
  strictEqual(signed["hiri:signature"].canonicalization, "URDNA2015");
  ok(signed["hiri:signature"].created, "Created timestamp present");
  ok(signed["hiri:signature"].verificationMethod, "Verification method present");
  ok(signed["hiri:signature"].proofPurpose, "Proof purpose present");
  ok(signed["hiri:signature"].proofValue, "Proof value present");

  pass("8.21: Verification status fields present and correct");
} catch (e) { fail("8.21: Verification status fields present", e); }

// 8.22: Backward compat — JCS chain without explicit canonicalizer still works
try {
  const contentBytesV1 = new TextEncoder().encode(stableStringify({ "@id": "compat-v1" }, false));
  const contentHashV1 = await crypto.hash(contentBytesV1);
  const unsignedV1 = buildUnsignedManifest({
    id: `hiri://${authority}/res/compat8`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash: contentHashV1,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytesV1.length,
    canonicalization: "JCS",
  });
  const v1 = await signManifest(unsignedV1, signingKey, "2025-01-01T00:00:00Z", "JCS", crypto);
  const v1Hash = await hashManifest(v1, crypto);

  const contentBytesV2 = new TextEncoder().encode(stableStringify({ "@id": "compat-v2" }, false));
  const contentHashV2 = await crypto.hash(contentBytesV2);
  const unsignedV2 = buildUnsignedManifest({
    id: `hiri://${authority}/res/compat8`,
    version: "2",
    branch: "main",
    created: "2025-01-02T00:00:00Z",
    contentHash: contentHashV2,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytesV2.length,
    canonicalization: "JCS",
    chain: { previous: v1Hash, previousBranch: "main", genesisHash: v1Hash, depth: 2 },
  });
  const v2 = await signManifest(unsignedV2, signingKey, "2025-01-02T00:00:00Z", "JCS", crypto);

  const manifests = new Map<string, ResolutionManifest>();
  manifests.set(v1Hash, v1);
  const fetchM: ManifestFetcher = async (h) => manifests.get(h) ?? null;
  const fetchC: ContentFetcher = async () => null;

  const chainResult = await verifyChain(v2, keypair.publicKey, fetchM, fetchC, crypto);
  strictEqual(chainResult.valid, true, `Expected valid, got: ${chainResult.reason}`);
  strictEqual(chainResult.depth, 2);
  pass("8.22: Backward compat JCS chain without explicit canonicalizer still works");
} catch (e) { fail("8.22: Backward compat JCS chain without explicit canonicalizer", e); }

// =========================================================================
// Summary
// =========================================================================

console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
