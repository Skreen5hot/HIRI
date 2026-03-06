/**
 * HIRI Protocol Tests — Phase 4: The Storeless Oracle
 *
 * Milestone 4 test cases 4.1–4.11.
 * Proves that verified content can be loaded into an in-memory RDF index
 * and queried with SPARQL, with entailment mode respected.
 *
 * Uses the existing test harness pattern (counter-based, checkmark markers).
 */

import { strictEqual, deepStrictEqual, ok } from "node:assert";
import { readFile } from "node:fs/promises";
import { resolve as pathResolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Kernel imports
import { buildGraph, resolveEntailmentMode } from "../src/kernel/graph-builder.js";
import { executeQuery } from "../src/kernel/query-executor.js";
import { resolve } from "../src/kernel/resolve.js";
import type { VerifiedContent } from "../src/kernel/resolve.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import { deriveAuthority } from "../src/kernel/authority.js";
import { buildUnsignedManifest, prepareContent } from "../src/kernel/manifest.js";
import { signManifest } from "../src/kernel/signing.js";
import { hashManifest } from "../src/kernel/chain.js";
import type { ManifestSemantics, QueryResult } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair } from "../src/adapters/crypto/provider.js";
import { InMemoryStorageAdapter } from "../src/adapters/persistence/storage.js";
import { OxigraphRDFStore } from "../src/adapters/rdf/oxigraph-store.js";

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
// Shared Setup
// =========================================================================

const crypto = defaultCryptoProvider;
const semanticsNone: ManifestSemantics = {
  entailmentMode: "none",
  baseRegime: null,
  vocabularies: [],
};

// Generate keypair and derive authority
const keypair = await generateKeypair("key-1");
const authority = deriveAuthority(keypair.publicKey, "ed25519");

/**
 * Helper: prepare a JSON-LD fixture, build a signed genesis manifest,
 * store in adapter, and return the content bytes + manifest hash.
 */
async function prepareFixture(
  fixturePath: string,
  resourceId: string,
  adapter: InMemoryStorageAdapter,
  opts?: { includeSemantics?: boolean },
): Promise<{ contentBytes: Uint8Array; manifestHash: string; contentHash: string }> {
  const raw = JSON.parse(await readFile(fixturePath, "utf-8"));
  const canonicalContent = prepareContent(raw, "AUTHORITY_PLACEHOLDER", authority);
  const contentBytes = new TextEncoder().encode(canonicalContent);
  const contentHash = await crypto.hash(contentBytes);

  const uri = `hiri://${authority}/data/${resourceId}`;
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
    ...(opts?.includeSemantics !== false ? { semantics: semanticsNone } : {}),
  });
  const signed = await signManifest(unsigned, keypair, "2025-01-15T14:30:00Z", "JCS", crypto);

  const manifestCanonical = stableStringify(signed, false);
  const manifestBytes = new TextEncoder().encode(manifestCanonical);
  const manifestHash = await crypto.hash(manifestBytes);

  await adapter.put(manifestHash, manifestBytes);
  await adapter.put(contentHash, contentBytes);

  return { contentBytes, manifestHash, contentHash };
}

// =========================================================================
// Prepare person.jsonld fixture
// =========================================================================

const personAdapter = new InMemoryStorageAdapter();
const personFixturePath = pathResolve(projectRoot, "examples", "person.jsonld");
const personData = await prepareFixture(personFixturePath, "person-001", personAdapter);

// Build the index for person.jsonld (reused by tests 4.1, 4.2, 4.3, 4.7)
const personStore = new OxigraphRDFStore();
await personStore.load(personData.contentBytes, "application/ld+json", "");

// =========================================================================
// Milestone 4 Tests
// =========================================================================

console.log("--- Milestone 4 Tests ---");

// 4.1: Load person.jsonld → query name (type-filtered to avoid org name)
try {
  const result = await executeQuery(
    `SELECT ?name WHERE { ?s a <http://schema.org/Person> . ?s <http://schema.org/name> ?name }`,
    personStore,
    personStore,
  );
  strictEqual(result.bindings.length, 1, "Should have exactly 1 binding");
  strictEqual(result.bindings[0].name.type, "literal");
  strictEqual(result.bindings[0].name.value, "Dana Reeves");
  strictEqual(result.truncated, false);

  pass("4.1: Load person.jsonld, query name returns 'Dana Reeves'");
} catch (e) { fail("4.1: Load person.jsonld, query name returns 'Dana Reeves'", e); }

// 4.2: Query job title
try {
  const result = await executeQuery(
    `SELECT ?title WHERE { ?s <http://schema.org/jobTitle> ?title }`,
    personStore,
    personStore,
  );
  strictEqual(result.bindings.length, 1);
  strictEqual(result.bindings[0].title.type, "literal");
  strictEqual(result.bindings[0].title.value, "Systems Architect");

  pass("4.2: Query jobTitle returns 'Systems Architect'");
} catch (e) { fail("4.2: Query jobTitle returns 'Systems Architect'", e); }

// 4.3: Typed literal (birthDate as xsd:date)
try {
  const result = await executeQuery(
    `SELECT ?date WHERE { ?s <http://schema.org/birthDate> ?date }`,
    personStore,
    personStore,
  );
  strictEqual(result.bindings.length, 1);
  const dateTerm = result.bindings[0].date;
  strictEqual(dateTerm.type, "literal");
  strictEqual(dateTerm.value, "1988-03-14");
  strictEqual(dateTerm.datatype, "http://www.w3.org/2001/XMLSchema#date");

  pass("4.3: Typed literal query returns birthDate with xsd:date datatype");
} catch (e) { fail("4.3: Typed literal query returns birthDate with xsd:date datatype", e); }

// 4.4: CRITICAL GATE — Entailment boundary
// Load entailment-trap.jsonld with mode="none", query for schema:Person
// ex:testSubject is typed as ex:SoftwareArchitect (subclass of Person)
// Under mode="none", it must NOT be inferred as schema:Person
try {
  const trapPath = pathResolve(projectRoot, "examples", "entailment-trap.jsonld");
  const trapRaw = await readFile(trapPath, "utf-8");
  const trapBytes = new TextEncoder().encode(trapRaw);

  const trapStore = new OxigraphRDFStore();
  const index = await buildGraph(
    trapBytes,
    "application/ld+json",
    "",
    { entailmentMode: "none" },
    () => trapStore,
  );

  const result = await executeQuery(
    `SELECT ?x WHERE { ?x a <http://schema.org/Person> }`,
    index,
    trapStore,
  );

  strictEqual(result.bindings.length, 0, "No RDFS inference — empty result set");

  pass("4.4: Entailment boundary — no RDFS inference leaks under mode='none'");
} catch (e) { fail("4.4: Entailment boundary — no RDFS inference leaks under mode='none'", e); }

// 4.5: Query all types from entailment-trap
// Should return exactly the explicitly asserted types, no inferred ones
try {
  const trapPath = pathResolve(projectRoot, "examples", "entailment-trap.jsonld");
  const trapRaw = await readFile(trapPath, "utf-8");
  const trapBytes = new TextEncoder().encode(trapRaw);

  const trapStore = new OxigraphRDFStore();
  await trapStore.load(trapBytes, "application/ld+json", "");

  const result = await executeQuery(
    `SELECT ?x ?type WHERE { ?x a ?type }`,
    trapStore,
    trapStore,
  );

  // Should have exactly 2 explicit type assertions:
  // ex:SoftwareArchitect a rdfs:Class
  // ex:testSubject a ex:SoftwareArchitect
  strictEqual(result.bindings.length, 2, "Exactly 2 explicit type assertions");

  const types = result.bindings.map(b => ({
    subject: b.x.value,
    type: b.type.value,
  })).sort((a, b) => a.subject.localeCompare(b.subject));

  // ex:SoftwareArchitect a rdfs:Class
  strictEqual(types[0].subject, "http://example.org/test/SoftwareArchitect");
  strictEqual(types[0].type, "http://www.w3.org/2000/01/rdf-schema#Class");

  // ex:testSubject a ex:SoftwareArchitect
  strictEqual(types[1].subject, "http://example.org/test/testSubject");
  strictEqual(types[1].type, "http://example.org/test/SoftwareArchitect");

  pass("4.5: Query all types — exactly 2 explicit assertions, no inferred types");
} catch (e) { fail("4.5: Query all types — exactly 2 explicit assertions, no inferred types", e); }

// 4.6: Multi-row results with team.jsonld
try {
  const teamPath = pathResolve(projectRoot, "examples", "team.jsonld");
  const teamRaw = JSON.parse(await readFile(teamPath, "utf-8"));
  const teamCanonical = prepareContent(teamRaw, "AUTHORITY_PLACEHOLDER", authority);
  const teamBytes = new TextEncoder().encode(teamCanonical);

  const teamStore = new OxigraphRDFStore();
  await teamStore.load(teamBytes, "application/ld+json", "");

  const result = await executeQuery(
    `SELECT ?name ?title WHERE { ?s <http://schema.org/name> ?name . ?s <http://schema.org/jobTitle> ?title } ORDER BY ?name`,
    teamStore,
    teamStore,
  );

  strictEqual(result.bindings.length, 3, "Should have 3 team members");

  // Alphabetical order: Ava, Dana, Morgan
  strictEqual(result.bindings[0].name.value, "Ava Okonkwo");
  strictEqual(result.bindings[0].title.value, "Cryptography Lead");
  strictEqual(result.bindings[1].name.value, "Dana Reeves");
  strictEqual(result.bindings[1].title.value, "Systems Architect");
  strictEqual(result.bindings[2].name.value, "Morgan Chen");
  strictEqual(result.bindings[2].title.value, "Protocol Engineer");

  pass("4.6: Multi-row query returns 3 team members in alphabetical order");
} catch (e) { fail("4.6: Multi-row query returns 3 team members in alphabetical order", e); }

// 4.7: Empty result set (query non-existent property)
try {
  const result = await executeQuery(
    `SELECT ?x WHERE { ?x <http://schema.org/email> ?email }`,
    personStore,
    personStore,
  );
  strictEqual(result.bindings.length, 0, "No schema:email in person.jsonld");
  ok(Array.isArray(result.bindings), "bindings should be an array");
  strictEqual(result.truncated, false);

  pass("4.7: Empty result set for non-existent property — not an error");
} catch (e) { fail("4.7: Empty result set for non-existent property — not an error", e); }

// 4.8: Full pipeline integration (URI → resolve → buildGraph → executeQuery)
try {
  const personUri = `hiri://${authority}/data/person-001`;

  // Resolve through M3 resolver
  const resolved: VerifiedContent = await resolve(personUri, personAdapter, {
    crypto,
    publicKey: keypair.publicKey,
    manifestHash: personData.manifestHash,
  });

  // Determine entailment mode from manifest semantics
  const mode = resolveEntailmentMode(
    resolved.manifest["hiri:semantics"] as ManifestSemantics | undefined,
  );

  // Build graph through kernel function
  const pipelineStore = new OxigraphRDFStore();
  const index = await buildGraph(
    resolved.content,
    "application/ld+json",
    "",
    { entailmentMode: mode },
    () => pipelineStore,
  );

  // Query through kernel function
  const result = await executeQuery(
    `SELECT ?name WHERE { ?s a <http://schema.org/Person> . ?s <http://schema.org/name> ?name }`,
    index,
    pipelineStore,
  );

  strictEqual(result.bindings.length, 1);
  strictEqual(result.bindings[0].name.value, "Dana Reeves");

  pass("4.8: Full pipeline URI → resolve → buildGraph → executeQuery returns 'Dana Reeves'");
} catch (e) { fail("4.8: Full pipeline URI → resolve → buildGraph → executeQuery returns 'Dana Reeves'", e); }

// 4.9: Missing semantics field (backward compatibility)
// Build a manifest WITHOUT hiri:semantics — should default to mode="none"
try {
  const noSemAdapter = new InMemoryStorageAdapter();
  const noSemData = await prepareFixture(
    personFixturePath,
    "person-nosem",
    noSemAdapter,
    { includeSemantics: false },
  );

  // Resolve — manifest has no hiri:semantics field
  const noSemUri = `hiri://${authority}/data/person-nosem`;
  const resolved = await resolve(noSemUri, noSemAdapter, {
    crypto,
    publicKey: keypair.publicKey,
    manifestHash: noSemData.manifestHash,
  });

  // resolveEntailmentMode should return "none" for missing semantics
  const mode = resolveEntailmentMode(
    resolved.manifest["hiri:semantics"] as ManifestSemantics | undefined,
  );
  strictEqual(mode, "none", "Missing semantics defaults to 'none'");

  // Should still load and query successfully
  const noSemStore = new OxigraphRDFStore();
  const index = await buildGraph(
    resolved.content,
    "application/ld+json",
    "",
    { entailmentMode: mode },
    () => noSemStore,
  );

  ok(index.tripleCount() > 0, "Graph should contain triples");

  pass("4.9: Missing semantics field defaults to mode='none', loads successfully");
} catch (e) { fail("4.9: Missing semantics field defaults to mode='none', loads successfully", e); }

// 4.10: SPARQL syntax error
try {
  const store = new OxigraphRDFStore();
  let threw = false;
  try {
    await store.query("SELCT ?x WERE { ?x a ?y }", store);
  } catch {
    threw = true;
  }
  ok(threw, "SPARQL syntax error should throw");

  pass("4.10: SPARQL syntax error throws, not empty result");
} catch (e) { fail("4.10: SPARQL syntax error throws, not empty result", e); }

// 4.11: No network activity
// The jsonld documentLoader in OxigraphRDFStore explicitly blocks remote fetches.
// If any fixture used a remote @context, it would throw "Remote context fetch blocked".
// All fixtures use inline @context objects, so no remote fetch is attempted.
// This test verifies the pipeline completes without network-related errors.
try {
  // Re-run the pipeline from scratch with a fresh store
  const netStore = new OxigraphRDFStore();
  await netStore.load(personData.contentBytes, "application/ld+json", "");

  const result = await executeQuery(
    `SELECT ?name WHERE { ?s a <http://schema.org/Person> . ?s <http://schema.org/name> ?name }`,
    netStore,
    netStore,
  );

  strictEqual(result.bindings.length, 1);
  strictEqual(result.bindings[0].name.value, "Dana Reeves");

  // Also verify entailment-trap loads without network
  const trapPath = pathResolve(projectRoot, "examples", "entailment-trap.jsonld");
  const trapRaw = await readFile(trapPath, "utf-8");
  const trapBytes = new TextEncoder().encode(trapRaw);

  const trapStore = new OxigraphRDFStore();
  await trapStore.load(trapBytes, "application/ld+json", "");
  ok(trapStore.tripleCount() > 0, "Entailment trap loaded locally");

  // Also verify team.jsonld loads without network
  const teamPath = pathResolve(projectRoot, "examples", "team.jsonld");
  const teamRaw = JSON.parse(await readFile(teamPath, "utf-8"));
  const teamCanonical = prepareContent(teamRaw, "AUTHORITY_PLACEHOLDER", authority);
  const teamBytes = new TextEncoder().encode(teamCanonical);

  const teamStore = new OxigraphRDFStore();
  await teamStore.load(teamBytes, "application/ld+json", "");
  ok(teamStore.tripleCount() > 0, "Team fixture loaded locally");

  pass("4.11: No network activity — all computation local");
} catch (e) { fail("4.11: No network activity — all computation local", e); }

// =========================================================================
// Summary
// =========================================================================

console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
