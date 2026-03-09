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
import { generateX25519Keypair } from "../adapters/crypto/x25519.js";
import { ed25519PublicToX25519 } from "../adapters/crypto/key-conversion.js";
import { encryptContent } from "../privacy/encryption.js";
import { buildEncryptedManifest } from "../privacy/encrypted-manifest.js";
import { buildStatementIndex } from "../privacy/statement-index.js";
import { generateHmacTags, encryptHmacKeyForRecipients } from "../privacy/hmac-disclosure.js";
import { generateEphemeralAuthority, buildAnonymousPrivacyBlock } from "../privacy/anonymous.js";
import { buildAttestationManifest, signAttestationManifest } from "../privacy/attestation.js";
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

// ── Privacy Helpers ────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Preset: Proof of Possession ────────────────────────────────────────

async function loadPrivacyPoP(): Promise<void> {
  demoState.clear();

  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  const contentStr = '{"@type":"Person","name":"Dana Reeves","clearance":"TS/SCI"}';
  const contentBytes = new TextEncoder().encode(contentStr);
  const contentHash = await crypto.hash(contentBytes);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/person`,
    version: "1",
    branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash,
    contentFormat: "application/json",
    contentSize: contentBytes.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
  });

  (unsigned as Record<string, unknown>)["hiri:privacy"] = {
    mode: "proof-of-possession",
    parameters: { refreshPolicy: "P30D" },
  };

  const signed = await signManifest(unsigned, key1, "2025-01-15T00:00:00Z", "JCS", crypto);
  const manifestHash = await hashManifest(signed, crypto);
  await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
  // Content NOT stored (§6.4)

  demoState.manifests.push({
    manifest: signed,
    manifestHash,
    contentBytes,
    contentHash,
    version: "1",
  });
}

// ── Preset: Encrypted for Two Recipients ───────────────────────────────

async function loadPrivacyEncrypted(): Promise<void> {
  demoState.clear();

  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  // Recipients
  const alice = { id: "alice", ...generateX25519Keypair() };
  const bob = { id: "bob", ...generateX25519Keypair() };
  demoState.privacyRecipients = [
    { id: alice.id, x25519Public: alice.x25519Public, x25519Private: alice.x25519Private },
    { id: bob.id, x25519Public: bob.x25519Public, x25519Private: bob.x25519Private },
  ];

  const plaintextStr = '{"name":"Dana Reeves","clearance":"TS/SCI","compartment":"GAMMA"}';
  const plaintextBytes = new TextEncoder().encode(plaintextStr);

  const recipientKeys = new Map<string, Uint8Array>();
  recipientKeys.set("alice", alice.x25519Public);
  recipientKeys.set("bob", bob.x25519Public);

  const encResult = await encryptContent(plaintextBytes, recipientKeys, crypto);

  const unsigned = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/data/encrypted-person`,
      version: "1",
      branch: "main",
      created: "2025-01-15T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintextBytes.length,
  });

  const signed = await signManifest(unsigned, key1, "2025-01-15T00:00:00Z", "JCS", crypto);
  const manifestHash = await hashManifest(signed, crypto);
  await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
  await demoState.storage.put(signed["hiri:content"].hash, encResult.ciphertext);

  demoState.manifests.push({
    manifest: signed,
    manifestHash,
    contentBytes: encResult.ciphertext,
    contentHash: signed["hiri:content"].hash,
    version: "1",
  });
}

// ── Preset: Selective Disclosure ────────────────────────────────────────

async function loadPrivacySD(): Promise<void> {
  demoState.clear();

  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  // Recipients
  const alice = { id: "alice", ...generateX25519Keypair() };
  const bob = { id: "bob", ...generateX25519Keypair() };
  demoState.privacyRecipients = [
    { id: alice.id, x25519Public: alice.x25519Public, x25519Private: alice.x25519Private },
    { id: bob.id, x25519Public: bob.x25519Public, x25519Private: bob.x25519Private },
  ];

  const statements = [
    '<https://example.org/person/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .',
    '<https://example.org/person/1> <http://schema.org/name> "Dana Reeves" .',
    '<https://example.org/person/1> <http://schema.org/jobTitle> "Protocol Architect" .',
    '<https://example.org/person/1> <http://schema.org/email> "dana@example.org" .',
    '<https://example.org/person/1> <http://schema.org/birthDate> "1990-05-15" .',
  ];
  const mandatoryIndices = [0, 1];

  // Build statement index
  const indexResult = await buildStatementIndex(statements);

  // Generate HMAC tags
  const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const hmacTags = generateHmacTags(statements, hmacKey, indexResult.salt);

  // Encrypt HMAC key for recipients
  const disclosureMap = new Map<string, number[] | "all">();
  disclosureMap.set("alice", [0, 1, 2, 3]);
  disclosureMap.set("bob", mandatoryIndices);
  const recipientKeys = new Map<string, Uint8Array>();
  recipientKeys.set("alice", alice.x25519Public);
  recipientKeys.set("bob", bob.x25519Public);
  const publisherX25519 = ed25519PublicToX25519(key1.publicKey);
  const hmacDistribution = await encryptHmacKeyForRecipients(hmacKey, recipientKeys, disclosureMap, publisherX25519);
  hmacKey.fill(0);

  // Build SD content blob
  const mandatoryNQuads = mandatoryIndices.map(i => statements[i]);
  const sdContentBlob = stableStringify({
    mandatoryNQuads,
    statementIndex: indexResult.statementHashes.map(h => bytesToHex(h)),
    hmacTags: hmacTags.map(t => bytesToHex(t)),
  });
  const sdContentBytes = new TextEncoder().encode(sdContentBlob);
  const sdContentHash = await crypto.hash(sdContentBytes);

  // Index root
  const indexRootBytes = new Uint8Array(await globalThis.crypto.subtle.digest(
    "SHA-256",
    indexResult.statementHashes.reduce((acc, h) => {
      const merged = new Uint8Array(acc.length + h.length);
      merged.set(acc); merged.set(h, acc.length);
      return merged;
    }, new Uint8Array(0)),
  ));
  const indexRoot = "sha256:" + bytesToHex(indexRootBytes);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/sd-person`,
    version: "1",
    branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash: sdContentHash,
    contentFormat: "application/json",
    contentSize: sdContentBytes.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
  });

  (unsigned as Record<string, unknown>)["hiri:privacy"] = {
    mode: "selective-disclosure",
    parameters: {
      disclosureProofSuite: "hiri-hmac-sd-2026",
      statementCount: statements.length,
      indexSalt: bytesToBase64url(indexResult.salt),
      indexRoot,
      mandatoryStatements: mandatoryIndices,
      hmacKeyRecipients: hmacDistribution,
    },
  };

  const signed = await signManifest(unsigned, key1, "2025-01-15T00:00:00Z", "JCS", crypto);
  const manifestHash = await hashManifest(signed, crypto);
  await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
  await demoState.storage.put(sdContentHash, sdContentBytes);

  demoState.manifests.push({
    manifest: signed,
    manifestHash,
    contentBytes: sdContentBytes,
    contentHash: sdContentHash,
    version: "1",
  });
}

// ── Preset: Anonymous Whistleblower ────────────────────────────────────

async function loadPrivacyAnonWhistleblower(): Promise<void> {
  demoState.clear();

  // Generate an ephemeral authority (anonymous)
  const ephemeral = await generateEphemeralAuthority();
  const keypair = { publicKey: ephemeral.publicKey, privateKey: ephemeral.privateKey, keyId: ephemeral.keyId, algorithm: "ed25519" as const };
  const authority = ephemeral.authority;
  demoState.keypairs.push({ keypair, keyId: ephemeral.keyId, authority });
  demoState.authority = authority;
  demoState.ephemeralKeypairs.push({
    publicKey: ephemeral.publicKey,
    privateKey: ephemeral.privateKey,
    authority,
  });
  demoState.initialized = true;

  const contentStr = '{"whistleblower_report":true,"finding":"Unauthorized data sharing","severity":"critical"}';
  const contentBytes = new TextEncoder().encode(contentStr);
  const contentHash = await crypto.hash(contentBytes);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/report`,
    version: "1",
    branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash,
    contentFormat: "application/json",
    contentSize: contentBytes.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
  });

  const anonBlock = buildAnonymousPrivacyBlock({
    authorityType: "ephemeral",
    contentVisibility: "public",
    identityDisclosable: false,
  });
  (unsigned as Record<string, unknown>)["hiri:privacy"] = anonBlock;

  const signed = await signManifest(unsigned, keypair, "2025-01-15T00:00:00Z", "JCS", crypto);
  // Destroy private key
  keypair.privateKey.fill(0);

  const manifestHash = await hashManifest(signed, crypto);
  await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
  await demoState.storage.put(contentHash, contentBytes);

  demoState.manifests.push({
    manifest: signed,
    manifestHash,
    contentBytes,
    contentHash,
    version: "1",
  });
}

// ── Preset: Security Clearance Attestation ─────────────────────────────

async function loadPrivacyAttestation(): Promise<void> {
  demoState.clear();

  // Attestor keypair
  const attestorKey = await generateKeypair("attestor-1");
  const attestorAuthority = deriveAuthority(attestorKey.publicKey, attestorKey.algorithm);
  demoState.keypairs.push({ keypair: attestorKey, keyId: attestorKey.keyId, authority: attestorAuthority });
  demoState.authority = attestorAuthority;
  demoState.initialized = true;

  // Subject keypair
  const subjectKey = await generateKeypair("subject-1");
  const subjectAuthority = deriveAuthority(subjectKey.publicKey, subjectKey.algorithm);
  demoState.keypairs.push({ keypair: subjectKey, keyId: subjectKey.keyId, authority: subjectAuthority });

  // Build subject manifest
  const subjectContent = new TextEncoder().encode('{"name":"Dana Reeves","clearance":"TS/SCI"}');
  const subjectContentHash = await crypto.hash(subjectContent);
  const subjectUnsigned = buildUnsignedManifest({
    id: `hiri://${subjectAuthority}/data/person`,
    version: "1",
    branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash: subjectContentHash,
    contentFormat: "application/json",
    contentSize: subjectContent.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
  });
  const subjectSigned = await signManifest(subjectUnsigned, subjectKey, "2025-01-15T00:00:00Z", "JCS", crypto);
  const subjectManifestHash = await hashManifest(subjectSigned, crypto);
  await demoState.storage.put(subjectManifestHash, new TextEncoder().encode(stableStringify(subjectSigned)));
  await demoState.storage.put(subjectContentHash, subjectContent);

  // Build attestation manifest
  const attestationUnsigned = buildAttestationManifest({
    attestorAuthority,
    attestationId: "clearance-check-1",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "security-clearance-valid",
      value: true,
      scope: "TS/SCI",
      attestedAt: "2025-02-01T00:00:00Z",
      validUntil: "2027-03-07T00:00:00Z",
    },
    evidence: {
      method: "direct-examination",
      description: "Examined personnel security record and verified clearance status",
    },
    version: "1",
    timestamp: "2025-02-01T00:00:00Z",
  });
  const attestSigned = await signAttestationManifest(attestationUnsigned, attestorKey, "2025-02-01T00:00:00Z", crypto);
  const attestManifestHash = await hashManifest(attestSigned as unknown as ResolutionManifest, crypto);
  await demoState.storage.put(attestManifestHash, new TextEncoder().encode(stableStringify(attestSigned as unknown as Record<string, unknown>)));

  demoState.manifests.push({
    manifest: subjectSigned,
    manifestHash: subjectManifestHash,
    contentBytes: subjectContent,
    contentHash: subjectContentHash,
    version: "1",
  });
}

// ── Preset: Privacy Lifecycle (PoP → Encrypted → Public) ──────────────

async function loadPrivacyLifecycle(): Promise<void> {
  demoState.clear();

  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  // Alice recipient for V2 (encrypted)
  const alice = { id: "alice", ...generateX25519Keypair() };
  demoState.privacyRecipients = [
    { id: alice.id, x25519Public: alice.x25519Public, x25519Private: alice.x25519Private },
  ];

  // Shared plaintext across all versions
  const plaintextStr = '{"name":"Dana Reeves","clearance":"TS/SCI"}';
  const plaintextBytes = new TextEncoder().encode(plaintextStr);
  const plaintextHash = await crypto.hash(plaintextBytes);

  // V1: Proof of Possession (content hash = plaintext hash, content NOT stored)
  const v1Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/person`,
    version: "1",
    branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintextBytes.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
  });
  (v1Unsigned as Record<string, unknown>)["hiri:privacy"] = {
    mode: "proof-of-possession",
    parameters: { refreshPolicy: "P30D" },
  };
  const v1Signed = await signManifest(v1Unsigned, key1, "2025-01-15T00:00:00Z", "JCS", crypto);
  const v1Hash = await hashManifest(v1Signed, crypto);
  await demoState.storage.put(v1Hash, new TextEncoder().encode(stableStringify(v1Signed)));

  demoState.manifests.push({
    manifest: v1Signed,
    manifestHash: v1Hash,
    contentBytes: plaintextBytes,
    contentHash: plaintextHash,
    version: "1",
  });

  // V2: Encrypted (content hash = ciphertext hash, plaintext hash in privacy block)
  const recipientKeys = new Map<string, Uint8Array>();
  recipientKeys.set("alice", alice.x25519Public);
  const encResult = await encryptContent(plaintextBytes, recipientKeys, crypto);

  const v2Unsigned = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/data/person`,
      version: "2",
      branch: "main",
      created: "2025-04-15T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
      chain: { previous: v1Hash, depth: 2, genesisHash: v1Hash },
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: plaintextBytes.length,
  });

  const v2Signed = await signManifest(v2Unsigned, key1, "2025-04-15T00:00:00Z", "JCS", crypto);
  const v2Hash = await hashManifest(v2Signed, crypto);
  await demoState.storage.put(v2Hash, new TextEncoder().encode(stableStringify(v2Signed)));
  await demoState.storage.put(v2Signed["hiri:content"].hash, encResult.ciphertext);

  demoState.manifests.push({
    manifest: v2Signed,
    manifestHash: v2Hash,
    contentBytes: encResult.ciphertext,
    contentHash: v2Signed["hiri:content"].hash,
    version: "2",
  });

  // V3: Public (content hash = plaintext hash again, content stored)
  const v3Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/person`,
    version: "3",
    branch: "main",
    created: "2025-07-15T00:00:00Z",
    contentHash: plaintextHash,
    contentFormat: "application/json",
    contentSize: plaintextBytes.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
    chain: { previous: v2Hash, depth: 3, genesisHash: v1Hash },
  });

  const v3Signed = await signManifest(v3Unsigned, key1, "2025-07-15T00:00:00Z", "JCS", crypto);
  const v3Hash = await hashManifest(v3Signed, crypto);
  await demoState.storage.put(v3Hash, new TextEncoder().encode(stableStringify(v3Signed)));
  await demoState.storage.put(plaintextHash, plaintextBytes);

  demoState.manifests.push({
    manifest: v3Signed,
    manifestHash: v3Hash,
    contentBytes: plaintextBytes,
    contentHash: plaintextHash,
    version: "3",
  });
}

// ── Preset: Key Rotation + Encrypted ───────────────────────────────────

async function loadPrivacyKeyRotationEnc(): Promise<void> {
  demoState.clear();

  // Key 1
  const key1 = await generateKeypair("key-1");
  const authority = deriveAuthority(key1.publicKey, key1.algorithm);
  demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
  demoState.authority = authority;
  demoState.initialized = true;

  // Key 2
  const key2 = await generateKeypair("key-2");
  demoState.keypairs.push({ keypair: key2, keyId: key2.keyId, authority });

  // Key Document with rotation
  const keyDoc = buildKeyDocument({
    authority,
    authorityType: "ed25519",
    version: "2",
    activeKeys: [{
      id: key2.keyId,
      type: "Ed25519VerificationKey2020",
      publicKeyMultibase: `z${base58Encode(key2.publicKey)}`,
    }],
    rotatedKeys: [{
      id: key1.keyId,
      type: "Ed25519VerificationKey2020",
      publicKeyMultibase: `z${base58Encode(key1.publicKey)}`,
      rotatedAt: "2025-06-01T00:00:00Z",
      gracePeriod: "P180D",
    }],
    revokedKeys: [],
    policies: { maxGracePeriod: "P365D" },
  });
  const signedKeyDoc = await signKeyDocument(keyDoc, key2, "2025-06-01T00:00:00Z", "JCS", crypto);
  demoState.keyDocument = signedKeyDoc;

  // Recipient
  const alice = { id: "alice", ...generateX25519Keypair() };
  demoState.privacyRecipients = [
    { id: alice.id, x25519Public: alice.x25519Public, x25519Private: alice.x25519Private },
  ];

  // V1: Public, signed by key1
  const contentStr = '{"name":"Dana Reeves","clearance":"TS/SCI"}';
  const contentBytes = new TextEncoder().encode(contentStr);
  const contentHash = await crypto.hash(contentBytes);

  const v1Unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/data/person`,
    version: "1",
    branch: "main",
    created: "2025-01-15T00:00:00Z",
    contentHash,
    contentFormat: "application/json",
    contentSize: contentBytes.length,
    addressing: "raw-sha256",
    canonicalization: "JCS",
  });
  const v1Signed = await signManifest(v1Unsigned, key1, "2025-01-15T00:00:00Z", "JCS", crypto);
  const v1Hash = await hashManifest(v1Signed, crypto);
  await demoState.storage.put(v1Hash, new TextEncoder().encode(stableStringify(v1Signed)));
  await demoState.storage.put(contentHash, contentBytes);

  demoState.manifests.push({
    manifest: v1Signed,
    manifestHash: v1Hash,
    contentBytes,
    contentHash,
    version: "1",
  });

  // V2: Encrypted, signed by key2 (after rotation)
  const recipientKeys = new Map<string, Uint8Array>();
  recipientKeys.set("alice", alice.x25519Public);
  const encResult = await encryptContent(contentBytes, recipientKeys, crypto);

  const v2Unsigned = buildEncryptedManifest({
    baseManifestParams: {
      id: `hiri://${authority}/data/person`,
      version: "2",
      branch: "main",
      created: "2025-07-01T00:00:00Z",
      addressing: "raw-sha256",
      canonicalization: "JCS",
      chain: { previous: v1Hash, depth: 2, genesisHash: v1Hash },
    },
    encryptionResult: encResult,
    plaintextFormat: "application/json",
    plaintextSize: contentBytes.length,
  });
  const v2Signed = await signManifest(v2Unsigned, key2, "2025-07-01T00:00:00Z", "JCS", crypto);
  const v2Hash = await hashManifest(v2Signed, crypto);
  await demoState.storage.put(v2Hash, new TextEncoder().encode(stableStringify(v2Signed)));
  await demoState.storage.put(v2Signed["hiri:content"].hash, encResult.ciphertext);

  demoState.manifests.push({
    manifest: v2Signed,
    manifestHash: v2Hash,
    contentBytes: encResult.ciphertext,
    contentHash: v2Signed["hiri:content"].hash,
    version: "2",
  });
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
    case "privacy-pop":
      await loadPrivacyPoP();
      break;
    case "privacy-encrypted":
      await loadPrivacyEncrypted();
      break;
    case "privacy-sd":
      await loadPrivacySD();
      break;
    case "privacy-anon-whistleblower":
      await loadPrivacyAnonWhistleblower();
      break;
    case "privacy-attestation":
      await loadPrivacyAttestation();
      break;
    case "privacy-lifecycle":
      await loadPrivacyLifecycle();
      break;
    case "privacy-key-rotation-enc":
      await loadPrivacyKeyRotationEnc();
      break;
    default:
      console.warn("Unknown preset:", name);
  }
}
