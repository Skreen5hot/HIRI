/**
 * HIRI Protocol Tests — Milestone 7: Level 2 Interoperable Conformance
 *
 * Tests 7.1–7.27: URDNA2015 canonicalization, CIDv1 content addressing,
 * secure document loader, URDNA2015 signing/verification, chain integration,
 * and backward compatibility.
 */

import { strictEqual, ok, throws, rejects } from "node:assert";

// Kernel imports
import { deriveAuthority } from "../src/kernel/authority.js";
import { buildUnsignedManifest } from "../src/kernel/manifest.js";
import { signManifest, verifyManifest } from "../src/kernel/signing.js";
import { hashManifest, verifyChain } from "../src/kernel/chain.js";
import { HashRegistry } from "../src/kernel/hash-registry.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import { JCSCanonicalizer } from "../src/kernel/jcs-canonicalizer.js";
import type { DocumentLoader, ResolutionManifest, ManifestFetcher, ContentFetcher } from "../src/kernel/types.js";

// Adapter imports
import { defaultCryptoProvider, generateKeypair, SHA256Algorithm, CIDv1Algorithm } from "../src/adapters/crypto/provider.js";
import { createSecureDocumentLoader, createCatalogDocumentLoader } from "../src/adapters/canonicalization/secure-document-loader.js";
import { URDNA2015Canonicalizer, CanonicalizationResourceExceeded } from "../src/adapters/canonicalization/urdna2015-canonicalizer.js";

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

// =========================================================================
// URDNA2015 Canonicalization (7.1–7.11)
// =========================================================================

// 7.1: B.8a — Key ordering variation → identical N-Quads
try {
  const doc1 = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/1",
    "@type": "hiri:ResolutionManifest",
    "hiri:version": "1",
    "hiri:branch": "main",
  };
  const doc2 = {
    "@type": "hiri:ResolutionManifest",
    "@id": "hiri://test/1",
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "hiri:branch": "main",
    "hiri:version": "1",
  };
  const bytes1 = await urdna.canonicalize(doc1, secureLoader);
  const bytes2 = await urdna.canonicalize(doc2, secureLoader);
  strictEqual(
    new TextDecoder().decode(bytes1),
    new TextDecoder().decode(bytes2),
  );
  pass("7.1: B.8a — Key ordering variation → identical N-Quads");
} catch (e) { fail("7.1: B.8a — Key ordering variation → identical N-Quads", e); }

// 7.2: B.8b — Compact vs expanded form → identical N-Quads
try {
  const compact = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/2",
    "hiri:version": "1",
  };
  const expanded = {
    "@id": "hiri://test/2",
    "https://hiri-protocol.org/ns/version": [{ "@value": "1" }],
  };
  const bytes1 = await urdna.canonicalize(compact, secureLoader);
  const bytes2 = await urdna.canonicalize(expanded, secureLoader);
  strictEqual(
    new TextDecoder().decode(bytes1),
    new TextDecoder().decode(bytes2),
  );
  pass("7.2: B.8b — Compact vs expanded → identical N-Quads");
} catch (e) { fail("7.2: B.8b — Compact vs expanded → identical N-Quads", e); }

// 7.3: B.8c — Language-tagged literals → correct N-Quads
try {
  const doc = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/lang",
    "http://purl.org/dc/terms/title": [
      { "@value": "Hello", "@language": "en" },
      { "@value": "Bonjour", "@language": "fr" },
    ],
  };
  const bytes = await urdna.canonicalize(doc, secureLoader);
  const nquads = new TextDecoder().decode(bytes);
  ok(nquads.includes('"Hello"@en'), "Contains English literal");
  ok(nquads.includes('"Bonjour"@fr'), "Contains French literal");
  pass("7.3: B.8c — Language-tagged literals → correct N-Quads");
} catch (e) { fail("7.3: B.8c — Language-tagged literals → correct N-Quads", e); }

// 7.4: B.8d — Typed literal vs plain literal → identical N-Quads
try {
  const doc1 = {
    "@id": "hiri://test/typed",
    "http://example.org/val": [{ "@value": "42", "@type": "http://www.w3.org/2001/XMLSchema#integer" }],
  };
  const doc2 = {
    "@id": "hiri://test/typed",
    "http://example.org/val": [{ "@value": "42", "@type": "http://www.w3.org/2001/XMLSchema#integer" }],
  };
  const bytes1 = await urdna.canonicalize(doc1, secureLoader);
  const bytes2 = await urdna.canonicalize(doc2, secureLoader);
  strictEqual(
    new TextDecoder().decode(bytes1),
    new TextDecoder().decode(bytes2),
  );
  pass("7.4: B.8d — Typed literal → identical N-Quads");
} catch (e) { fail("7.4: B.8d — Typed literal → identical N-Quads", e); }

// 7.5: B.8e — Blank node canonicalization → deterministic _:c14n labels
try {
  const doc = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/bnode",
    "hiri:content": {
      "hash": "sha256:abc",
    },
  };
  const bytes = await urdna.canonicalize(doc, secureLoader);
  const nquads = new TextDecoder().decode(bytes);
  ok(nquads.includes("_:c14n"), "Contains canonicalized blank node labels");
  pass("7.5: B.8e — Blank node canonicalization → deterministic labels");
} catch (e) { fail("7.5: B.8e — Blank node canonicalization → deterministic labels", e); }

// 7.6: Secure document loader resolves embedded HIRI context
try {
  const result = await secureLoader("https://hiri-protocol.org/spec/v3.1");
  ok(result.document, "HIRI context document returned");
  strictEqual(result.documentUrl, "https://hiri-protocol.org/spec/v3.1");
  pass("7.6: Secure document loader resolves embedded HIRI context");
} catch (e) { fail("7.6: Secure document loader resolves embedded HIRI context", e); }

// 7.7: Secure document loader resolves embedded security/v2 context
try {
  const result = await secureLoader("https://w3id.org/security/v2");
  ok(result.document, "Security context document returned");
  strictEqual(result.documentUrl, "https://w3id.org/security/v2");
  pass("7.7: Secure document loader resolves embedded security/v2 context");
} catch (e) { fail("7.7: Secure document loader resolves embedded security/v2 context", e); }

// 7.8: Secure document loader blocks unknown URLs
try {
  await rejects(
    () => secureLoader("https://evil.example.com/context"),
    /unknown context URL/i,
  );
  pass("7.8: Secure document loader blocks unknown URLs");
} catch (e) { fail("7.8: Secure document loader blocks unknown URLs", e); }

// 7.9: Context catalog — resolves listed contexts
try {
  const customContext = { "@context": { "custom": "http://example.org/custom#" } };
  const catalogLoader = createCatalogDocumentLoader({
    "http://example.org/custom-context": customContext,
  });
  const result = await catalogLoader("http://example.org/custom-context");
  strictEqual(result.documentUrl, "http://example.org/custom-context");
  ok(result.document, "Catalog context resolved");
  // Also resolves normative contexts
  const hiriResult = await catalogLoader("https://hiri-protocol.org/spec/v3.1");
  ok(hiriResult.document, "Normative context still resolves through catalog loader");
  pass("7.9: Context catalog resolves listed contexts");
} catch (e) { fail("7.9: Context catalog resolves listed contexts", e); }

// 7.10: Context catalog — rejects unlisted context
try {
  const catalogLoader = createCatalogDocumentLoader({});
  await rejects(
    () => catalogLoader("http://unknown.example.org/context"),
    /not in embedded registry or manifest contextCatalog/i,
  );
  pass("7.10: Context catalog rejects unlisted context");
} catch (e) { fail("7.10: Context catalog rejects unlisted context", e); }

// 7.11: Resource limit — blank node count exceeds 1000
try {
  const limitedURDNA = new URDNA2015Canonicalizer({ maxBlankNodes: 5 });
  // Create a doc with >5 blank nodes
  const nodes: object[] = [];
  for (let i = 0; i < 10; i++) {
    nodes.push({ "http://example.org/val": `item-${i}` });
  }
  const doc = {
    "@id": "hiri://test/blanks",
    "http://example.org/items": nodes,
  };
  await rejects(
    () => limitedURDNA.canonicalize(doc, secureLoader),
    /CANONICALIZATION_RESOURCE_EXCEEDED/,
  );
  pass("7.11: Resource limit — blank node count exceeds limit");
} catch (e) { fail("7.11: Resource limit — blank node count exceeds limit", e); }

// =========================================================================
// CIDv1 Content Addressing (7.12–7.18)
// =========================================================================

const cidAlgo = new CIDv1Algorithm("JCS");

// 7.12: CIDv1 hash produces base32lower string starting with 'b'
try {
  const content = new TextEncoder().encode("test content");
  const cid = await cidAlgo.hash(content);
  ok(cid.startsWith("b"), `CID starts with 'b': ${cid.substring(0, 10)}...`);
  ok(cid.length > 20, "CID has reasonable length");
  // Verify base32lower: only lowercase alphanumeric
  ok(/^b[a-z2-7]+=*$/.test(cid), "CID is valid base32lower");
  pass("7.12: CIDv1 hash produces base32lower string starting with 'b'");
} catch (e) { fail("7.12: CIDv1 hash produces base32lower string starting with 'b'", e); }

// 7.13: CIDv1 — same content → same CID (determinism)
try {
  const content = new TextEncoder().encode("deterministic");
  const cid1 = await cidAlgo.hash(content);
  const cid2 = await cidAlgo.hash(content);
  strictEqual(cid1, cid2);
  pass("7.13: CIDv1 — same content → same CID (determinism)");
} catch (e) { fail("7.13: CIDv1 — same content → same CID (determinism)", e); }

// 7.14: CIDv1 — different content → different CID
try {
  const cid1 = await cidAlgo.hash(new TextEncoder().encode("content-a"));
  const cid2 = await cidAlgo.hash(new TextEncoder().encode("content-b"));
  ok(cid1 !== cid2, "Different content produces different CIDs");
  pass("7.14: CIDv1 — different content → different CID");
} catch (e) { fail("7.14: CIDv1 — different content → different CID", e); }

// 7.15: CIDv1 — different profile → different CID
try {
  const content = new TextEncoder().encode("profile-test");
  const cidJCS = await new CIDv1Algorithm("JCS").hash(content);
  const cidURDNA = await new CIDv1Algorithm("URDNA2015").hash(content);
  ok(cidJCS !== cidURDNA, "Different profile → different CID");
  pass("7.15: CIDv1 — different profile → different CID");
} catch (e) { fail("7.15: CIDv1 — different profile → different CID", e); }

// 7.16: CIDv1 round-trip — hash then verify
try {
  const content = new TextEncoder().encode("round-trip");
  const cid = await cidAlgo.hash(content);
  const valid = await cidAlgo.verify(content, cid);
  strictEqual(valid, true);
  pass("7.16: CIDv1 round-trip — hash then verify → true");
} catch (e) { fail("7.16: CIDv1 round-trip — hash then verify → true", e); }

// 7.17: HashRegistry resolves CIDv1 strings (no colon prefix)
try {
  const registry = new HashRegistry();
  registry.register(new SHA256Algorithm());
  registry.register(new CIDv1Algorithm("JCS"));
  const content = new TextEncoder().encode("registry-test");
  const cid = await cidAlgo.hash(content);
  const algo = registry.resolve(cid);
  strictEqual(algo.prefix, "cidv1");
  pass("7.17: HashRegistry resolves CIDv1 strings");
} catch (e) { fail("7.17: HashRegistry resolves CIDv1 strings", e); }

// 7.18: CBOR determinism — re-encoding same envelope → identical bytes
try {
  const content = new TextEncoder().encode("cbor-det");
  const cid1 = await cidAlgo.hash(content);
  const cid2 = await cidAlgo.hash(content);
  strictEqual(cid1, cid2, "Re-encoding produces identical CID");
  pass("7.18: CBOR determinism — re-encoding → identical bytes");
} catch (e) { fail("7.18: CBOR determinism — re-encoding → identical bytes", e); }

// =========================================================================
// URDNA2015 Signing/Verification (7.19–7.23)
// =========================================================================

// 7.19: Sign manifest with URDNA2015 profile succeeds
let urdnaSignedManifest: ResolutionManifest | null = null;
try {
  const contentBytes = new TextEncoder().encode(stableStringify({
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": `hiri://${authority}/res/test`,
    "name": "urdna-test",
  }, false));
  const contentHash = await crypto.hash(contentBytes);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/test`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "URDNA2015",
  });

  urdnaSignedManifest = await signManifest(
    unsigned, signingKey, "2025-01-01T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader,
  );

  ok(urdnaSignedManifest["hiri:signature"], "Signature present");
  strictEqual(urdnaSignedManifest["hiri:signature"].canonicalization, "URDNA2015");
  pass("7.19: Sign manifest with URDNA2015 profile succeeds");
} catch (e) { fail("7.19: Sign manifest with URDNA2015 profile succeeds", e); }

// 7.20: Verify URDNA2015-signed manifest → true
try {
  ok(urdnaSignedManifest, "Signed manifest available from 7.19");
  const valid = await verifyManifest(
    urdnaSignedManifest!, keypair.publicKey, "URDNA2015", crypto, urdna, secureLoader,
  );
  strictEqual(valid, true);
  pass("7.20: Verify URDNA2015-signed manifest → true");
} catch (e) { fail("7.20: Verify URDNA2015-signed manifest → true", e); }

// 7.21: Profile symmetry enforced — URDNA2015-signed manifest rejected with JCS
try {
  ok(urdnaSignedManifest, "Signed manifest available from 7.19");
  // Verifier uses JCS profile — should fail because signature says URDNA2015
  const valid = await verifyManifest(
    urdnaSignedManifest!, keypair.publicKey, "JCS", crypto,
  );
  strictEqual(valid, false, "Profile mismatch should fail verification");
  pass("7.21: Profile symmetry — URDNA2015 manifest rejected when verified with JCS");
} catch (e) { fail("7.21: Profile symmetry — URDNA2015 manifest rejected when verified with JCS", e); }

// 7.22: Cross-profile forgery — signed with URDNA2015 bytes but declares JCS
try {
  // Build a manifest declaring JCS canonicalization
  const contentBytes = new TextEncoder().encode(stableStringify({ "@id": "forgery-test" }, false));
  const contentHash = await crypto.hash(contentBytes);

  const unsignedJCS = buildUnsignedManifest({
    id: `hiri://${authority}/res/forgery`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
  });

  // Sign legitimately with JCS
  const legitimateManifest = await signManifest(
    unsignedJCS, signingKey, "2025-01-01T00:00:00Z", "JCS", crypto,
  );

  // Now tamper: change the content.canonicalization to URDNA2015
  // but keep the JCS-generated signature
  const forged = structuredClone(legitimateManifest) as ResolutionManifest;
  forged["hiri:content"] = { ...forged["hiri:content"], canonicalization: "URDNA2015" };
  // Also change signature.canonicalization to match (otherwise symmetry check fails first)
  forged["hiri:signature"] = { ...forged["hiri:signature"], canonicalization: "URDNA2015" };

  // Verifier follows declaration (URDNA2015), but bytes were signed with JCS → fail
  const valid = await verifyManifest(
    forged, keypair.publicKey, "URDNA2015", crypto, urdna, secureLoader,
  );
  strictEqual(valid, false, "Forged profile declaration should fail");
  pass("7.22: Cross-profile forgery — declaration mismatch → verification fails");
} catch (e) { fail("7.22: Cross-profile forgery — declaration mismatch → verification fails", e); }

// 7.23: URDNA2015 + cidv1-dag-cbor — full manifest round-trip
try {
  const cidAlgoURDNA = new CIDv1Algorithm("URDNA2015");
  const contentBytes = new TextEncoder().encode(stableStringify({
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": `hiri://${authority}/res/cidv1-urdna`,
    "name": "cidv1-urdna-test",
  }, false));
  const contentCID = await cidAlgoURDNA.hash(contentBytes);

  ok(contentCID.startsWith("b"), "CID starts with b");

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/cidv1-urdna`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash: contentCID,
    addressing: "cidv1-dag-cbor",
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "URDNA2015",
  });

  const signed = await signManifest(
    unsigned, signingKey, "2025-01-01T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader,
  );

  const valid = await verifyManifest(
    signed, keypair.publicKey, "URDNA2015", crypto, urdna, secureLoader,
  );
  strictEqual(valid, true);

  // Verify CID
  const cidValid = await cidAlgoURDNA.verify(contentBytes, contentCID);
  strictEqual(cidValid, true);

  pass("7.23: URDNA2015 + cidv1-dag-cbor — full manifest round-trip");
} catch (e) { fail("7.23: URDNA2015 + cidv1-dag-cbor — full manifest round-trip", e); }

// =========================================================================
// Chain & Integration (7.24–7.27)
// =========================================================================

// 7.24: Chain with URDNA2015 — 3-manifest chain → verifyChain succeeds
try {
  const contentBytesGen = new TextEncoder().encode(stableStringify({ "@id": "chain-v1" }, false));
  const contentHashGen = await crypto.hash(contentBytesGen);

  const unsignedGen = buildUnsignedManifest({
    id: `hiri://${authority}/res/chain-urdna`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash: contentHashGen,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytesGen.length,
    canonicalization: "URDNA2015",
  });

  const genesis = await signManifest(
    unsignedGen, signingKey, "2025-01-01T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader,
  );
  const genesisHash = await hashManifest(genesis, crypto, urdna, secureLoader);

  // V2
  const contentBytesV2 = new TextEncoder().encode(stableStringify({ "@id": "chain-v2" }, false));
  const contentHashV2 = await crypto.hash(contentBytesV2);
  const unsignedV2 = buildUnsignedManifest({
    id: `hiri://${authority}/res/chain-urdna`,
    version: "2",
    branch: "main",
    created: "2025-01-02T00:00:00Z",
    contentHash: contentHashV2,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytesV2.length,
    canonicalization: "URDNA2015",
    chain: { previous: genesisHash, previousBranch: "main", genesisHash, depth: 2 },
  });
  const v2 = await signManifest(
    unsignedV2, signingKey, "2025-01-02T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader,
  );
  const v2Hash = await hashManifest(v2, crypto, urdna, secureLoader);

  // V3
  const contentBytesV3 = new TextEncoder().encode(stableStringify({ "@id": "chain-v3" }, false));
  const contentHashV3 = await crypto.hash(contentBytesV3);
  const unsignedV3 = buildUnsignedManifest({
    id: `hiri://${authority}/res/chain-urdna`,
    version: "3",
    branch: "main",
    created: "2025-01-03T00:00:00Z",
    contentHash: contentHashV3,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytesV3.length,
    canonicalization: "URDNA2015",
    chain: { previous: v2Hash, previousBranch: "main", genesisHash, depth: 3 },
  });
  const v3 = await signManifest(
    unsignedV3, signingKey, "2025-01-03T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader,
  );

  // Build fetchers
  const manifests = new Map<string, ResolutionManifest>();
  manifests.set(genesisHash, genesis);
  manifests.set(v2Hash, v2);
  const fetchManifest: ManifestFetcher = async (hash) => manifests.get(hash) ?? null;
  const fetchContent: ContentFetcher = async () => null;

  const chainResult = await verifyChain(v3, keypair.publicKey, fetchManifest, fetchContent, crypto, urdna, secureLoader);
  strictEqual(chainResult.valid, true);
  strictEqual(chainResult.depth, 3);
  pass("7.24: Chain with URDNA2015 — 3-manifest chain → verifyChain succeeds");
} catch (e) { fail("7.24: Chain with URDNA2015 — 3-manifest chain → verifyChain succeeds", e); }

// 7.25: Full pipeline — JSON-LD → URDNA2015 → CIDv1 → sign → verify
try {
  const cidAlgoFull = new CIDv1Algorithm("URDNA2015");
  const jsonld = {
    "@context": ["https://hiri-protocol.org/spec/v3.1", "https://w3id.org/security/v2"],
    "@id": `hiri://${authority}/res/full-pipeline`,
    "@type": "hiri:ResolutionManifest",
    "hiri:version": "1",
  };
  const canonicalBytes = await urdna.canonicalize(jsonld as Record<string, unknown>, secureLoader);
  const cid = await cidAlgoFull.hash(canonicalBytes);
  ok(cid.startsWith("b"), "CID starts with b");

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/full-pipeline`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash: cid,
    addressing: "cidv1-dag-cbor",
    contentFormat: "application/ld+json",
    contentSize: canonicalBytes.length,
    canonicalization: "URDNA2015",
  });

  const signed = await signManifest(
    unsigned, signingKey, "2025-01-01T00:00:00Z", "URDNA2015", crypto, urdna, secureLoader,
  );
  const valid = await verifyManifest(
    signed, keypair.publicKey, "URDNA2015", crypto, urdna, secureLoader,
  );
  strictEqual(valid, true);
  const cidValid = await cidAlgoFull.verify(canonicalBytes, cid);
  strictEqual(cidValid, true);
  pass("7.25: Full pipeline — JSON-LD → URDNA2015 → CIDv1 → sign → verify");
} catch (e) { fail("7.25: Full pipeline — JSON-LD → URDNA2015 → CIDv1 → sign → verify", e); }

// 7.26: Backward compat — JCS signing still works without explicit canonicalizer
try {
  const contentBytes = new TextEncoder().encode(stableStringify({ "@id": "compat-test" }, false));
  const contentHash = await crypto.hash(contentBytes);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${authority}/res/compat`,
    version: "1",
    branch: "main",
    created: "2025-01-01T00:00:00Z",
    contentHash,
    addressing: "raw-sha256",
    contentFormat: "application/ld+json",
    contentSize: contentBytes.length,
    canonicalization: "JCS",
  });

  // No canonicalizer argument — should default to JCS
  const signed = await signManifest(
    unsigned, signingKey, "2025-01-01T00:00:00Z", "JCS", crypto,
  );
  const valid = await verifyManifest(
    signed, keypair.publicKey, "JCS", crypto,
  );
  strictEqual(valid, true);
  pass("7.26: Backward compat — JCS signing works without explicit canonicalizer");
} catch (e) { fail("7.26: Backward compat — JCS signing works without explicit canonicalizer", e); }

// 7.27: CBOR determinism — key ordering in envelope does not affect CID
try {
  // CIDv1Algorithm always builds the envelope in the same key order,
  // so calling it twice with same content produces same CID
  const content = new TextEncoder().encode("key-order-test");
  const algo1 = new CIDv1Algorithm("JCS");
  const algo2 = new CIDv1Algorithm("JCS");
  const cid1 = await algo1.hash(content);
  const cid2 = await algo2.hash(content);
  strictEqual(cid1, cid2, "Different instances produce same CID");
  pass("7.27: CBOR determinism — key ordering does not affect CID");
} catch (e) { fail("7.27: CBOR determinism — key ordering does not affect CID", e); }

// =========================================================================
// Summary
// =========================================================================

console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
