/**
 * Preset Scenarios
 *
 * Three preset scenarios from the v1.4 spec, pre-generating all data on load.
 *
 * | Preset          | Pre-generates                                        | Tabs populated     |
 * |-----------------|------------------------------------------------------|--------------------|
 * | Simple Verify   | 1 keypair, 1 genesis manifest, person data           | B, C, D            |
 * | Chain w/ Delta  | 1 keypair, 3-version chain, V3 has corrupted delta   | B, C, D            |
 * | Key Rotation    | 3 keypairs, B→C rotation, chain spanning rotation    | A, B, D            |
 */

import { generateKeypair } from "../adapters/crypto/ed25519.js";
import { deriveAuthority } from "../kernel/authority.js";
import { buildKeyDocument, buildUnsignedManifest, prepareContent } from "../kernel/manifest.js";
import { signKeyDocument, signManifest } from "../kernel/signing.js";
import { hashManifest } from "../kernel/chain.js";
import { buildDelta } from "../kernel/delta.js";
import { stableStringify } from "../kernel/canonicalize.js";
import { encode as base58Encode } from "../kernel/base58.js";
import { addDuration } from "../kernel/temporal.js";
import { defaultCryptoProvider } from "../adapters/crypto/provider.js";
import { demoState, type ManifestEntry } from "./state.js";
import { URDNA2015Canonicalizer } from "../adapters/canonicalization/urdna2015-canonicalizer.js";
import { CIDv1Algorithm } from "../adapters/content-addressing/cidv1-algorithm.js";
import { createCatalogDocumentLoader } from "../adapters/canonicalization/secure-document-loader.js";
import { buildRDFDelta } from "../kernel/delta.js";
import { parseNQuads } from "../kernel/rdf-patch.js";
import type {
  ResolutionManifest,
  KeyDocument,
  VerificationKey,
  RotatedKey,
  RotationClaim,
  ManifestChain,
  JsonPatchOperation,
  RDFPatchOperation,
} from "../kernel/types.js";

const crypto = defaultCryptoProvider;

// ── Person data fixtures ──────────────────────────────────────────────

function personV1(authority: string): object {
  return {
    "@context": { "schema": "http://schema.org/" },
    "@id": `hiri://${authority}/data/person`,
    "@type": "schema:Person",
    "schema:name": "Dana Reeves",
    "schema:jobTitle": "Protocol Architect",
    "schema:address": {
      "@type": "schema:PostalAddress",
      "schema:addressLocality": "Portland",
      "schema:addressRegion": "Oregon",
    },
  };
}

function personV2(authority: string): object {
  return {
    "@context": { "schema": "http://schema.org/" },
    "@id": `hiri://${authority}/data/person`,
    "@type": "schema:Person",
    "schema:name": "Dana Reeves",
    "schema:jobTitle": "Protocol Architect",
    "schema:address": {
      "@type": "schema:PostalAddress",
      "schema:addressLocality": "Seattle",
      "schema:addressRegion": "Washington",
    },
  };
}

function personV3(authority: string): object {
  return {
    "@context": { "schema": "http://schema.org/" },
    "@id": `hiri://${authority}/data/person`,
    "@type": "schema:Person",
    "schema:name": "Dana Reeves",
    "schema:jobTitle": "Chief Architect",
    "schema:address": {
      "@type": "schema:PostalAddress",
      "schema:addressLocality": "Seattle",
      "schema:addressRegion": "Washington",
    },
    "schema:email": "dana@example.org",
  };
}

// ── Helpers ────────────────────────────────────────────────────────────

async function signAndStore(
  unsigned: ReturnType<typeof buildUnsignedManifest>,
  keypair: Awaited<ReturnType<typeof generateKeypair>>,
  timestamp: string,
  contentBytes: Uint8Array,
  contentHash: string,
  version: string,
): Promise<ManifestEntry> {
  const signed = await signManifest(unsigned, keypair, timestamp, "JCS", crypto);
  const manifestHash = await hashManifest(signed, crypto);

  await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
  await demoState.storage.put(contentHash, contentBytes);

  const entry: ManifestEntry = { manifest: signed, manifestHash, contentBytes, contentHash, version: String(version) };
  demoState.manifests.push(entry);
  return entry;
}

async function prepContent(jsonLd: object): Promise<{ canonical: string; bytes: Uint8Array; hash: string }> {
  const canonical = stableStringify(jsonLd);
  const bytes = new TextEncoder().encode(canonical);
  const hash = await crypto.hash(bytes);
  return { canonical, bytes, hash };
}

// ── Preset: Simple Verify ─────────────────────────────────────────────

async function loadSimpleVerify(): Promise<void> {
  demoState.clear();

  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  // Content
  const content = personV1(authority);
  const { bytes, hash } = await prepContent(content);

  // Manifest
  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/person`,
    version: "1",
    branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash: hash,
    contentFormat: "application/ld+json",
    contentSize: bytes.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
  });

  await signAndStore(unsigned, key1, "2025-01-15T00:00:00Z", bytes, hash, "1");
}

// ── Preset: Chain with Delta ──────────────────────────────────────────

async function loadChainWithDelta(): Promise<void> {
  demoState.clear();

  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  const resourceUri = `hiri://${authority}/data/person`;

  // ── V1 (genesis) ──
  const v1Content = personV1(authority);
  const v1 = await prepContent(v1Content);
  const v1Unsigned = buildUnsignedManifest({
    id: resourceUri, version: "1", branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash: v1.hash, contentFormat: "application/ld+json",
    contentSize: v1.bytes.length, addressing: "raw-sha256", canonicalization: "JCS",
  });
  const v1Entry = await signAndStore(v1Unsigned, key1, "2025-01-15T00:00:00Z", v1.bytes, v1.hash, "1");

  // ── V2 (valid delta: Portland→Seattle) ──
  const v2Content = personV2(authority);
  const v2 = await prepContent(v2Content);
  const v2DeltaOps: JsonPatchOperation[] = [
    { op: "replace", path: "/schema:address/schema:addressLocality", value: "Seattle" },
    { op: "replace", path: "/schema:address/schema:addressRegion", value: "Washington" },
  ];
  const v2DeltaCanonical = stableStringify(v2DeltaOps);
  const v2DeltaBytes = new TextEncoder().encode(v2DeltaCanonical);
  const v2DeltaHash = await crypto.hash(v2DeltaBytes);
  await demoState.storage.put(v2DeltaHash, v2DeltaBytes);

  const v2Unsigned = buildUnsignedManifest({
    id: resourceUri, version: "2", branch: "main",
    created: "2025-03-01T00:00:00Z",
    contentHash: v2.hash, contentFormat: "application/ld+json",
    contentSize: v2.bytes.length, addressing: "raw-sha256", canonicalization: "JCS",
    chain: {
      previous: v1Entry.manifestHash, previousBranch: "main",
      genesisHash: v1Entry.manifestHash, depth: 2,
    },
    delta: {
      hash: v2DeltaHash, format: "application/json-patch+json",
      appliesTo: v1.hash, operations: v2DeltaOps.length,
    },
  });
  const v2Entry = await signAndStore(v2Unsigned, key1, "2025-03-01T00:00:00Z", v2.bytes, v2.hash, "2");

  // ── V3 (semantically corrupted delta) ──
  // Semantic delta corruption: delta applies cleanly but produces wrong content hash.
  // Chain walker detects mismatch and falls back to full content.
  const v3Content = personV3(authority);
  const v3 = await prepContent(v3Content);

  // Build a WRONG delta — operations that produce different content than v3
  const wrongDeltaOps: JsonPatchOperation[] = [
    { op: "replace", path: "/schema:jobTitle", value: "WRONG TITLE" },
    { op: "add", path: "/schema:email", value: "wrong@example.org" },
  ];
  const wrongDeltaCanonical = stableStringify(wrongDeltaOps);
  const wrongDeltaBytes = new TextEncoder().encode(wrongDeltaCanonical);
  const wrongDeltaHash = await crypto.hash(wrongDeltaBytes);
  await demoState.storage.put(wrongDeltaHash, wrongDeltaBytes);

  const v3Unsigned = buildUnsignedManifest({
    id: resourceUri, version: "3", branch: "main",
    created: "2025-05-01T00:00:00Z",
    contentHash: v3.hash, // Correct content hash
    contentFormat: "application/ld+json",
    contentSize: v3.bytes.length, addressing: "raw-sha256", canonicalization: "JCS",
    chain: {
      previous: v2Entry.manifestHash, previousBranch: "main",
      genesisHash: v1Entry.manifestHash, depth: 3,
    },
    delta: {
      hash: wrongDeltaHash, // WRONG delta hash
      format: "application/json-patch+json",
      appliesTo: v2.hash,
      operations: wrongDeltaOps.length,
    },
  });
  await signAndStore(v3Unsigned, key1, "2025-05-01T00:00:00Z", v3.bytes, v3.hash, "3");
}

// ── Preset: Key Rotation ──────────────────────────────────────────────

async function loadKeyRotation(): Promise<void> {
  demoState.clear();

  const keyA = await generateKeypair("key-1");
  const keyB = await generateKeypair("key-2");
  const keyC = await generateKeypair("key-3");
  const authority = deriveAuthority(keyA.publicKey, keyA.algorithm);

  demoState.keypairs.push(
    { keypair: keyA, keyId: keyA.keyId, authority },
    { keypair: keyB, keyId: keyB.keyId },
    { keypair: keyC, keyId: keyC.keyId },
  );
  demoState.authority = authority;
  demoState.initialized = true;

  const keyDocUri = `hiri://${authority}/key/main`;
  const resourceUri = `hiri://${authority}/data/person`;
  const GRACE = "P183D";

  // Multibase-encode public keys
  const keyAMultibase = "z" + base58Encode(keyA.publicKey);
  const keyBMultibase = "z" + base58Encode(keyB.publicKey);
  const keyCMultibase = "z" + base58Encode(keyC.publicKey);

  // Build rotation proof (B→C)
  const rotationClaim: RotationClaim = {
    oldKeyId: `${keyDocUri}#key-2`,
    newKeyId: `${keyDocUri}#key-3`,
    rotatedAt: "2025-07-01T00:00:00Z",
    reason: "scheduled-rotation",
  };
  const claimBytes = new TextEncoder().encode(stableStringify(rotationClaim));
  const oldKeySig = await crypto.sign(claimBytes, keyB.privateKey);
  const newKeySig = await crypto.sign(claimBytes, keyC.privateKey);

  // Build Key Document (Key C active, Key B rotated, Key A not included)
  const unsignedKeyDoc = buildKeyDocument({
    authority,
    authorityType: "key",
    version: "3",
    activeKeys: [{
      "@id": `${keyDocUri}#key-3`,
      "@type": "Ed25519VerificationKey2020",
      controller: keyDocUri,
      publicKeyMultibase: keyCMultibase,
      purposes: ["assertionMethod"],
      validFrom: "2025-07-01T00:00:00Z",
    }],
    rotatedKeys: [{
      "@id": `${keyDocUri}#key-2`,
      rotatedAt: "2025-07-01T00:00:00Z",
      rotatedTo: `${keyDocUri}#key-3`,
      reason: "scheduled-rotation",
      verifyUntil: addDuration("2025-07-01T00:00:00Z", GRACE),
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
    }],
    policies: {
      gracePeriodAfterRotation: GRACE,
      minimumKeyValidity: "P365D",
    },
  });

  demoState.keyDocument = await signKeyDocument(unsignedKeyDoc, keyC, "2025-07-01T00:00:00Z", "JCS", crypto);

  // Build chained manifests spanning the key rotation
  // V1: signed by Key B at 2025-04-01 (Key B active)
  const v1Content = personV1(authority);
  const v1 = await prepContent(v1Content);
  const v1Unsigned = buildUnsignedManifest({
    id: resourceUri, version: "1", branch: "main",
    created: "2025-04-01T00:00:00Z",
    contentHash: v1.hash, contentFormat: "application/ld+json",
    contentSize: v1.bytes.length, addressing: "raw-sha256", canonicalization: "JCS",
  });
  const v1Entry = await signAndStore(v1Unsigned, keyB, "2025-04-01T00:00:00Z", v1.bytes, v1.hash, "1");

  // V2: signed by Key C at 2025-08-01 (Key C active, after rotation)
  const v2Content = personV2(authority);
  const v2 = await prepContent(v2Content);
  const v2Unsigned = buildUnsignedManifest({
    id: resourceUri, version: "2", branch: "main",
    created: "2025-08-01T00:00:00Z",
    contentHash: v2.hash, contentFormat: "application/ld+json",
    contentSize: v2.bytes.length, addressing: "raw-sha256", canonicalization: "JCS",
    chain: {
      previous: v1Entry.manifestHash, previousBranch: "main",
      genesisHash: v1Entry.manifestHash, depth: 2,
    },
  });
  await signAndStore(v2Unsigned, keyC, "2025-08-01T00:00:00Z", v2.bytes, v2.hash, "2");
}


// -- Preset: Level 2 (URDNA2015 + CIDv1 + RDF Patch) --------------------

// Minimal schema.org context for the document loader (no network fetch)
const SCHEMA_ORG_CONTEXT = {
  "@context": {
    "schema": "http://schema.org/",
    "schema:Person": { "@id": "http://schema.org/Person" },
    "schema:name": { "@id": "http://schema.org/name" },
    "schema:jobTitle": { "@id": "http://schema.org/jobTitle" },
    "schema:affiliation": { "@id": "http://schema.org/affiliation" },
    "schema:email": { "@id": "http://schema.org/email" },
    "schema:address": { "@id": "http://schema.org/address" },
    "schema:PostalAddress": { "@id": "http://schema.org/PostalAddress" },
    "schema:addressLocality": { "@id": "http://schema.org/addressLocality" },
    "schema:addressRegion": { "@id": "http://schema.org/addressRegion" },
  },
};

function researcherV1(authority: string): Record<string, unknown> {
  return {
    "@context": { "schema": "http://schema.org/" },
    "@id": `hiri://${authority}/data/researcher`,
    "@type": "schema:Person",
    "schema:name": "Dr. Ada Chen",
    "schema:jobTitle": "Cryptography Researcher",
    "schema:affiliation": "Signal Foundation",
  };
}

function researcherV2(authority: string): Record<string, unknown> {
  return {
    "@context": { "schema": "http://schema.org/" },
    "@id": `hiri://${authority}/data/researcher`,
    "@type": "schema:Person",
    "schema:name": "Dr. Ada Chen",
    "schema:jobTitle": "Principal Cryptographer",
    "schema:affiliation": "IETF Working Group",
    "schema:email": "ada@example.org",
  };
}

async function loadLevel2Demo(): Promise<void> {
  demoState.clear();

  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  const resourceUri = `hiri://${authority}/data/researcher`;
  const canonicalizer = new URDNA2015Canonicalizer();
  const cidAlgorithm = new CIDv1Algorithm("URDNA2015");
  const documentLoader = createCatalogDocumentLoader({
    "http://schema.org/": SCHEMA_ORG_CONTEXT,
  });

  // -- V1 (genesis, URDNA2015 + CIDv1) --
  const v1Content = researcherV1(authority);
  const v1Bytes = await canonicalizer.canonicalize(
    v1Content as Record<string, unknown>, documentLoader,
  );
  const v1Hash = await cidAlgorithm.hash(v1Bytes);

  const v1Unsigned = buildUnsignedManifest({
    id: resourceUri, version: "1", branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash: v1Hash, contentFormat: "application/ld+json",
    contentSize: v1Bytes.length, addressing: "cidv1-dag-cbor",
    canonicalization: "URDNA2015",
  });

  const v1Signed = await signManifest(
    v1Unsigned, key1, "2025-01-15T00:00:00Z", "URDNA2015", crypto,
    canonicalizer, documentLoader,
  );
  const v1ManifestHash = await hashManifest(v1Signed, crypto);

  await demoState.storage.put(v1ManifestHash, new TextEncoder().encode(stableStringify(v1Signed)));
  await demoState.storage.put(v1Hash, v1Bytes);

  const v1Entry: ManifestEntry = {
    manifest: v1Signed, manifestHash: v1ManifestHash,
    contentBytes: v1Bytes, contentHash: v1Hash, version: "1",
  };
  demoState.manifests.push(v1Entry);

  // -- V2 (chained, URDNA2015 + CIDv1 + RDF Patch delta) --
  const v2Content = researcherV2(authority);
  const v2Bytes = await canonicalizer.canonicalize(
    v2Content as Record<string, unknown>, documentLoader,
  );
  const v2Hash = await cidAlgorithm.hash(v2Bytes);

  // Compute RDF Patch by diffing N-Quads
  const v1Nquads = new TextDecoder().decode(v1Bytes);
  const v2Nquads = new TextDecoder().decode(v2Bytes);
  const v1Quads = parseNQuads(v1Nquads);
  const v2Quads = parseNQuads(v2Nquads);

  const rdfOps: RDFPatchOperation[] = [];
  for (const quad of v1Quads) {
    if (!v2Quads.has(quad)) {
      const parts = parseQuadLine(quad);
      if (parts) rdfOps.push({ op: "remove", ...parts });
    }
  }
  for (const quad of v2Quads) {
    if (!v1Quads.has(quad)) {
      const parts = parseQuadLine(quad);
      if (parts) rdfOps.push({ op: "add", ...parts });
    }
  }

  const { delta: rdfDelta, serialized: rdfSerialized } = await buildRDFDelta(rdfOps, v1Hash, crypto);
  const rdfDeltaBytes = new TextEncoder().encode(rdfSerialized);
  await demoState.storage.put(rdfDelta.hash, rdfDeltaBytes);

  const v2Unsigned = buildUnsignedManifest({
    id: resourceUri, version: "2", branch: "main",
    created: "2025-06-01T00:00:00Z",
    contentHash: v2Hash, contentFormat: "application/ld+json",
    contentSize: v2Bytes.length, addressing: "cidv1-dag-cbor",
    canonicalization: "URDNA2015",
    chain: {
      previous: v1ManifestHash, previousBranch: "main",
      genesisHash: v1ManifestHash, depth: 2,
    },
    delta: rdfDelta,
  });

  const v2Signed = await signManifest(
    v2Unsigned, key1, "2025-06-01T00:00:00Z", "URDNA2015", crypto,
    canonicalizer, documentLoader,
  );
  const v2ManifestHash = await hashManifest(v2Signed, crypto);

  await demoState.storage.put(v2ManifestHash, new TextEncoder().encode(stableStringify(v2Signed)));
  await demoState.storage.put(v2Hash, v2Bytes);

  demoState.manifests.push({
    manifest: v2Signed, manifestHash: v2ManifestHash,
    contentBytes: v2Bytes, contentHash: v2Hash, version: "2",
  });
}

/** Parse an N-Quads line into subject, predicate, object components. */
function parseQuadLine(line: string): { subject: string; predicate: string; object: string } | null {
  const trimmed = line.trim().replace(/\s*\.\s*$/, "");
  if (!trimmed) return null;
  const firstSpace = trimmed.indexOf(" ");
  if (firstSpace < 0) return null;
  const secondSpace = trimmed.indexOf(" ", firstSpace + 1);
  if (secondSpace < 0) return null;
  return {
    subject: trimmed.substring(0, firstSpace),
    predicate: trimmed.substring(firstSpace + 1, secondSpace),
    object: trimmed.substring(secondSpace + 1),
  };
}

// ── Public API ─────────────────────────────────────────────────────────

export async function loadPreset(name: string): Promise<void> {
  switch (name) {
    case "simple-verify":
      await loadSimpleVerify();
      break;
    case "chain-delta":
      await loadChainWithDelta();
      break;
    case "key-rotation":
      await loadKeyRotation();
      break;
    case "level-2":
      await loadLevel2Demo();
      break;
    default:
      console.warn("Unknown preset:", name);
  }
}
