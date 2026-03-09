/**
 * HIRI Privacy Extension Tests — Milestone 14: Anonymous Publication & Attestation
 *
 * Tests 14.1–14.18: Ephemeral/pseudonymous authorities, anonymous resolution
 * with contentVisibility dispatch, attestation manifest structure, dual-signature
 * verification, trust levels, staleness, attestation chains.
 */

import { strictEqual, ok } from "node:assert";

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
import {
  generateEphemeralAuthority,
  validateAnonymousConstraints,
  buildAnonymousPrivacyBlock,
} from "../src/privacy/anonymous.js";
import {
  buildAttestationManifest,
  signAttestationManifest,
  verifyAttestation,
  validateAttestationManifest,
  hashAttestationManifest,
} from "../src/privacy/attestation.js";
import type { SignedAttestationManifest } from "../src/privacy/attestation.js";
import { resolveWithPrivacy } from "../src/privacy/resolve.js";
import { getLogicalPlaintextHash } from "../src/privacy/plaintext-hash.js";
import type { AnonymousParams, AttestationSubject, AttestationClaim, AttestationEvidence } from "../src/privacy/types.js";

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

// Attestor keypair
const attestorKeypair = await generateKeypair();
const attestorAuthority = deriveAuthority(attestorKeypair.publicKey, "ed25519");
const attestorSigningKey = {
  algorithm: "ed25519",
  publicKey: attestorKeypair.publicKey,
  privateKey: attestorKeypair.privateKey,
  keyId: "key-1",
};

// Subject keypair (different authority)
const subjectKeypair = await generateKeypair();
const subjectAuthority = deriveAuthority(subjectKeypair.publicKey, "ed25519");
const subjectSigningKey = {
  algorithm: "ed25519",
  publicKey: subjectKeypair.publicKey,
  privateKey: subjectKeypair.privateKey,
  keyId: "key-1",
};

// Build a subject manifest for attestation tests
const subjectContent = new TextEncoder().encode(
  stableStringify({ name: "Dana Reeves", clearance: "TS/SCI" }),
);
const subjectContentHash = await crypto.hash(subjectContent);

const subjectUnsigned = buildUnsignedManifest({
  id: `hiri://${subjectAuthority}/data/clearance`,
  contentHash: subjectContentHash,
  contentFormat: "application/json",
  contentSize: subjectContent.length,
  version: "1",
  branch: "main",
  created: "2026-03-01T00:00:00Z",
  canonicalization: "JCS",
  addressing: "raw-sha256",
});
const subjectManifest = await signManifest(
  subjectUnsigned,
  subjectSigningKey,
  "2026-03-01T00:00:00Z",
  "JCS",
  crypto,
);
const subjectManifestBytes = new TextEncoder().encode(stableStringify(subjectManifest));
const subjectManifestHash = await crypto.hash(subjectManifestBytes);

// In-memory storage helper
function createStorage(entries: Map<string, Uint8Array>): StorageAdapter {
  return {
    get: async (hash: string) => entries.get(hash) ?? null,

    has: async (hash: string) => entries.has(hash),
  };
}

// =========================================================================
// Tests: 14.1–14.5 — Anonymous Publication (§9)
// =========================================================================

console.log("\n=== Anonymous Publication (§9) ===\n");

// 14.1: Generate ephemeral authority → valid authority string, fresh keypair
try {
  const eph = await generateEphemeralAuthority();
  ok(eph.publicKey.length === 32, "Public key should be 32 bytes");
  ok(eph.privateKey.length === 32 || eph.privateKey.length === 64, "Private key should be 32 or 64 bytes");
  ok(eph.authority.startsWith("key:ed25519:z"), "Authority should start with key:ed25519:z");
  ok(eph.authority.length > 20, "Authority should be a full-length key identifier");
  pass("14.1 Generate ephemeral authority → valid authority string, fresh keypair");
} catch (e) {
  fail("14.1 Generate ephemeral authority", e);
}

// 14.2: Sign manifest with ephemeral key → signature verifies
try {
  const eph = await generateEphemeralAuthority();
  const ephSigningKey = {
    algorithm: "ed25519",
    publicKey: eph.publicKey,
    privateKey: eph.privateKey,
    keyId: "ephemeral-key",
  };

  const content = new TextEncoder().encode(stableStringify({ anonymous: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${eph.authority}/test/anon`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const signed = await signManifest(
    unsigned,
    ephSigningKey,
    "2026-03-08T00:00:00Z",
    "JCS",
    crypto,
  );

  const sigValid = await verifyManifest(signed, eph.publicKey, "JCS", crypto);
  strictEqual(sigValid, true);

  // Destroy private key
  eph.privateKey.fill(0);

  pass("14.2 Sign manifest with ephemeral key → signature verifies");
} catch (e) {
  fail("14.2 Sign manifest with ephemeral key", e);
}

// 14.3: Ephemeral authority → resolver reports identityType: "anonymous-ephemeral"
try {
  const eph = await generateEphemeralAuthority();
  const ephSigningKey = {
    algorithm: "ed25519",
    publicKey: eph.publicKey,
    privateKey: eph.privateKey,
    keyId: "ephemeral-key",
  };

  const content = new TextEncoder().encode(stableStringify({ data: "ephemeral-test" }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${eph.authority}/test/anon`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  // Add anonymous privacy block
  const manifestWithPrivacy = {
    ...unsigned,
    "hiri:privacy": buildAnonymousPrivacyBlock({
      authorityType: "ephemeral",
      contentVisibility: "public",
      identityDisclosable: false,
    }),
  };

  const signed = await signManifest(
    manifestWithPrivacy,
    ephSigningKey,
    "2026-03-08T00:00:00Z",
    "JCS",
    crypto,
  );

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${eph.authority}/test/anon`,
    createStorage(entries),
    {
      manifestHash,
      publicKey: eph.publicKey,
      crypto,
    },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "anonymous");
  strictEqual(result.identityType, "anonymous-ephemeral");
  strictEqual(result.contentStatus, "verified");

  eph.privateKey.fill(0);

  pass("14.3 Ephemeral authority → resolver reports identityType: 'anonymous-ephemeral'");
} catch (e) {
  fail("14.3 Ephemeral authority resolver identity", e);
}

// 14.4: Pseudonymous authority — two manifests linkable (same authority)
try {
  const pseudoKeypair = await generateKeypair();
  const pseudoAuthority = deriveAuthority(pseudoKeypair.publicKey, "ed25519");
  const pseudoSigningKey = {
    algorithm: "ed25519",
    publicKey: pseudoKeypair.publicKey,
    privateKey: pseudoKeypair.privateKey,
    keyId: "key-1",
  };

  const content1 = new TextEncoder().encode(stableStringify({ doc: 1 }));
  const content2 = new TextEncoder().encode(stableStringify({ doc: 2 }));
  const hash1 = await crypto.hash(content1);
  const hash2 = await crypto.hash(content2);

  const unsigned1 = buildUnsignedManifest({
    id: `hiri://${pseudoAuthority}/test/pseudo`,
    contentHash: hash1,
    contentFormat: "application/json",
    contentSize: content1.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });
  const unsigned2 = buildUnsignedManifest({
    id: `hiri://${pseudoAuthority}/test/pseudo`,
    contentHash: hash2,
    contentFormat: "application/json",
    contentSize: content2.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T01:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  const signed1 = await signManifest(unsigned1, pseudoSigningKey, "2026-03-08T00:00:00Z", "JCS", crypto);
  const signed2 = await signManifest(unsigned2, pseudoSigningKey, "2026-03-08T01:00:00Z", "JCS", crypto);

  // Same authority in both
  strictEqual(
    (signed1 as Record<string, unknown>)["@id"]?.toString().includes(pseudoAuthority),
    true,
  );
  strictEqual(
    (signed2 as Record<string, unknown>)["@id"]?.toString().includes(pseudoAuthority),
    true,
  );

  pass("14.4 Pseudonymous authority — two manifests linkable (same authority)");
} catch (e) {
  fail("14.4 Pseudonymous linkability", e);
}

// 14.5: Two ephemeral authorities — computationally unlinkable
try {
  const eph1 = await generateEphemeralAuthority();
  const eph2 = await generateEphemeralAuthority();

  // Different keys
  ok(
    !constantTimeEqual(eph1.publicKey, eph2.publicKey),
    "Ephemeral public keys must differ",
  );
  // Different authorities
  ok(eph1.authority !== eph2.authority, "Ephemeral authorities must differ");

  eph1.privateKey.fill(0);
  eph2.privateKey.fill(0);

  pass("14.5 Two ephemeral authorities — computationally unlinkable");
} catch (e) {
  fail("14.5 Ephemeral unlinkability", e);
}

// =========================================================================
// Tests: 14.6–14.8 — Anonymous + Content Visibility
// =========================================================================

console.log("\n=== Anonymous + Content Visibility ===\n");

// 14.6: Anonymous + encrypted content visibility
try {
  const eph = await generateEphemeralAuthority();
  const ephSigningKey = {
    algorithm: "ed25519",
    publicKey: eph.publicKey,
    privateKey: eph.privateKey,
    keyId: "ephemeral-key",
  };

  // Build a manifest with anonymous mode + encrypted visibility
  // For this test, we just verify the resolver dispatches to encrypted path
  const content = new TextEncoder().encode(stableStringify({ secret: "data" }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${eph.authority}/test/anon`,
    contentHash,
    contentFormat: "application/octet-stream",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  const manifestWithPrivacy = {
    ...unsigned,
    "hiri:privacy": buildAnonymousPrivacyBlock({
      authorityType: "ephemeral",
      contentVisibility: "encrypted",
      identityDisclosable: false,
    }),
  };

  const signed = await signManifest(
    manifestWithPrivacy,
    ephSigningKey,
    "2026-03-08T00:00:00Z",
    "JCS",
    crypto,
  );

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${eph.authority}/test/anon`,
    createStorage(entries),
    {
      manifestHash,
      publicKey: eph.publicKey,
      crypto,
    },
  );

  strictEqual(result.privacyMode, "anonymous");
  strictEqual(result.identityType, "anonymous-ephemeral");
  // Encrypted path without decryption key → ciphertext-verified
  strictEqual(result.contentStatus, "ciphertext-verified");

  eph.privateKey.fill(0);

  pass("14.6 Anonymous + encrypted content visibility → ciphertext-verified");
} catch (e) {
  fail("14.6 Anonymous + encrypted visibility", e);
}

// 14.7: Anonymous + public content visibility
try {
  const eph = await generateEphemeralAuthority();
  const ephSigningKey = {
    algorithm: "ed25519",
    publicKey: eph.publicKey,
    privateKey: eph.privateKey,
    keyId: "ephemeral-key",
  };

  const content = new TextEncoder().encode(stableStringify({ public: true }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${eph.authority}/test/anon`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  const manifestWithPrivacy = {
    ...unsigned,
    "hiri:privacy": buildAnonymousPrivacyBlock({
      authorityType: "ephemeral",
      contentVisibility: "public",
      identityDisclosable: false,
    }),
  };

  const signed = await signManifest(
    manifestWithPrivacy,
    ephSigningKey,
    "2026-03-08T00:00:00Z",
    "JCS",
    crypto,
  );

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${eph.authority}/test/anon`,
    createStorage(entries),
    {
      manifestHash,
      publicKey: eph.publicKey,
      crypto,
    },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "anonymous");
  strictEqual(result.identityType, "anonymous-ephemeral");
  strictEqual(result.contentStatus, "verified");

  eph.privateKey.fill(0);

  pass("14.7 Anonymous + public content visibility → content readable, publisher anonymous");
} catch (e) {
  fail("14.7 Anonymous + public visibility", e);
}

// 14.8: Resolve anonymous ephemeral manifest — full resolver output
try {
  const eph = await generateEphemeralAuthority();
  const ephSigningKey = {
    algorithm: "ed25519",
    publicKey: eph.publicKey,
    privateKey: eph.privateKey,
    keyId: "ephemeral-key",
  };

  const content = new TextEncoder().encode(stableStringify({ resolve: "test" }));
  const contentHash = await crypto.hash(content);

  const unsigned = buildUnsignedManifest({
    id: `hiri://${eph.authority}/test/anon`,
    contentHash,
    contentFormat: "application/json",
    contentSize: content.length,
    version: "1",
    branch: "main",
    created: "2026-03-08T00:00:00Z",
    canonicalization: "JCS",
    addressing: "raw-sha256",
  });

  const manifestWithPrivacy = {
    ...unsigned,
    "hiri:privacy": buildAnonymousPrivacyBlock({
      authorityType: "pseudonymous",
      contentVisibility: "public",
      identityDisclosable: true,
      disclosureConditions: "Upon court order",
    }),
  };

  const signed = await signManifest(
    manifestWithPrivacy,
    ephSigningKey,
    "2026-03-08T00:00:00Z",
    "JCS",
    crypto,
  );

  const manifestBytes = new TextEncoder().encode(stableStringify(signed));
  const manifestHash = await crypto.hash(manifestBytes);

  const entries = new Map<string, Uint8Array>();
  entries.set(manifestHash, manifestBytes);
  entries.set(contentHash, content);

  const result = await resolveWithPrivacy(
    `hiri://${eph.authority}/test/anon`,
    createStorage(entries),
    {
      manifestHash,
      publicKey: eph.publicKey,
      crypto,
    },
  );

  strictEqual(result.verified, true);
  strictEqual(result.privacyMode, "anonymous");
  strictEqual(result.identityType, "pseudonymous");
  strictEqual(result.contentStatus, "verified");
  ok(result.authority.startsWith("key:ed25519:z"), "Authority present in result");

  eph.privateKey.fill(0);

  pass("14.8 Resolve anonymous pseudonymous manifest → identityType: 'pseudonymous'");
} catch (e) {
  fail("14.8 Resolve anonymous pseudonymous", e);
}

// =========================================================================
// Tests: 14.9–14.11 — Attestation Manifest Structure (§10)
// =========================================================================

console.log("\n=== Attestation Manifest Structure (§10) ===\n");

// 14.9: Build attestation manifest — no hiri:content block
try {
  const claim: AttestationClaim = {
    "@type": "hiri:PropertyAttestation",
    property: "security-clearance-valid",
    value: true,
    scope: "TS/SCI",
    attestedAt: "2026-03-07T12:00:00Z",
    validUntil: "2027-03-07T12:00:00Z",
  };

  const evidence: AttestationEvidence = {
    method: "direct-examination",
    description: "Attestor examined the personnel record and confirmed the clearance field.",
  };

  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "clearance-check-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim,
    evidence,
    version: "1",
    timestamp: "2026-03-07T12:00:00Z",
  });

  // MUST NOT have hiri:content
  ok(!("hiri:content" in attestation), "Attestation manifest must not have hiri:content");
  strictEqual(attestation["@type"], "hiri:AttestationManifest");
  strictEqual(attestation["hiri:privacy"].mode, "attestation");

  pass("14.9 Build attestation manifest — no hiri:content block (§10.4)");
} catch (e) {
  fail("14.9 Build attestation — no content", e);
}

// 14.10: Attestation has required minimum fields (§10.4)
try {
  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "field-check-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "test-property",
      value: "test-value",
      attestedAt: "2026-03-07T12:00:00Z",
    },
    evidence: {
      method: "automated-verification",
      description: "Automated check.",
    },
    version: "1",
    timestamp: "2026-03-07T12:00:00Z",
  });

  // Check all required fields per §10.4
  ok("@context" in attestation, "@context required");
  ok("@id" in attestation, "@id required");
  ok("@type" in attestation, "@type required");
  ok("hiri:version" in attestation, "hiri:version required");
  ok("hiri:branch" in attestation, "hiri:branch required");
  ok("hiri:timing" in attestation, "hiri:timing required");
  ok("hiri:privacy" in attestation, "hiri:privacy required");
  ok("hiri:attestation" in attestation, "hiri:attestation required");
  ok("subject" in attestation["hiri:attestation"], "subject required");
  ok("claim" in attestation["hiri:attestation"], "claim required");
  ok("evidence" in attestation["hiri:attestation"], "evidence required");

  // Validate via validateAttestationManifest
  const validation = validateAttestationManifest(
    attestation as unknown as Record<string, unknown>,
  );
  strictEqual(validation.valid, true);

  pass("14.10 Attestation has required minimum fields (§10.4)");
} catch (e) {
  fail("14.10 Attestation required fields", e);
}

// 14.11: Verify attestation signature → attestationVerified: true
try {
  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "sig-check-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "sig-test",
      value: true,
      attestedAt: "2026-03-07T12:00:00Z",
    },
    evidence: {
      method: "direct-examination",
      description: "Signature verification test.",
    },
    version: "1",
    timestamp: "2026-03-07T12:00:00Z",
  });

  const signed = await signAttestationManifest(
    attestation,
    attestorSigningKey,
    "2026-03-07T12:00:00Z",
    crypto,
  );

  const result = await verifyAttestation(
    signed,
    attestorKeypair.publicKey,
    null, // no subject manifest
    null,
    crypto,
  );

  strictEqual(result.attestationVerified, true);
  strictEqual(result.claim.property, "sig-test");

  pass("14.11 Verify attestation signature → attestationVerified: true");
} catch (e) {
  fail("14.11 Verify attestation signature", e);
}

// =========================================================================
// Tests: 14.12–14.15 — Attestation Verification & Trust Levels (§10.5)
// =========================================================================

console.log("\n=== Attestation Verification & Trust Levels (§10.5) ===\n");

// 14.12: Verify attestation + subject manifest (dual sig) → trustLevel: "full"
try {
  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "dual-sig-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "clearance-valid",
      value: true,
      scope: "TS/SCI",
      attestedAt: "2026-03-07T12:00:00Z",
      validUntil: "2027-03-07T12:00:00Z",
    },
    evidence: {
      method: "direct-examination",
      description: "Full dual-sig verification test.",
    },
    version: "1",
    timestamp: "2026-03-07T12:00:00Z",
  });

  const signed = await signAttestationManifest(
    attestation,
    attestorSigningKey,
    "2026-03-07T12:00:00Z",
    crypto,
  );

  const result = await verifyAttestation(
    signed,
    attestorKeypair.publicKey,
    subjectManifest,
    subjectKeypair.publicKey,
    crypto,
    "active",
    "2026-06-01T00:00:00Z", // before validUntil
  );

  strictEqual(result.attestationVerified, true);
  strictEqual(result.subjectManifestVerified, true);
  strictEqual(result.trustLevel, "full");
  strictEqual(result.stale, false);
  strictEqual(result.claim.scope, "TS/SCI");

  pass("14.12 Dual-signature verification → trustLevel: 'full'");
} catch (e) {
  fail("14.12 Dual-sig full verification", e);
}

// 14.13: Subject manifest unavailable → trustLevel: "partial"
try {
  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "partial-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "partial-test",
      value: "yes",
      attestedAt: "2026-03-07T12:00:00Z",
    },
    evidence: {
      method: "direct-examination",
      description: "Subject unavailable test.",
    },
    version: "1",
    timestamp: "2026-03-07T12:00:00Z",
  });

  const signed = await signAttestationManifest(
    attestation,
    attestorSigningKey,
    "2026-03-07T12:00:00Z",
    crypto,
  );

  const result = await verifyAttestation(
    signed,
    attestorKeypair.publicKey,
    null, // subject manifest unavailable
    null,
    crypto,
  );

  strictEqual(result.attestationVerified, true);
  strictEqual(result.subjectManifestVerified, false);
  strictEqual(result.trustLevel, "partial");
  ok(
    result.warnings.some((w) => w.includes("Subject manifest unavailable")),
    "Should warn about unavailable subject",
  );

  pass("14.13 Subject manifest unavailable → trustLevel: 'partial'");
} catch (e) {
  fail("14.13 Subject unavailable", e);
}

// 14.14: AttestationManifest WITH hiri:content → rejected
try {
  const badManifest = {
    "@context": ["https://hiri-protocol.org/spec/v3.1"],
    "@id": "hiri://test/attestation/bad",
    "@type": "hiri:AttestationManifest",
    "hiri:version": "1",
    "hiri:branch": "main",
    "hiri:timing": { created: "2026-03-07T12:00:00Z" },
    "hiri:privacy": { mode: "attestation" },
    "hiri:attestation": {
      subject: { authority: "test", manifestHash: "sha256:abc", contentHash: "sha256:def", manifestVersion: "1" },
      claim: { "@type": "hiri:PropertyAttestation", property: "test", value: true, attestedAt: "2026-03-07T12:00:00Z" },
      evidence: { method: "test", description: "test" },
    },
    "hiri:content": { hash: "sha256:bad", format: "application/json", size: 100 },
  };

  const validation = validateAttestationManifest(badManifest);
  strictEqual(validation.valid, false);
  ok(
    validation.reason?.includes("MUST NOT have hiri:content"),
    "Should reject with content block reason",
  );

  pass("14.14 AttestationManifest WITH hiri:content → rejected (§10.4)");
} catch (e) {
  fail("14.14 Reject content block", e);
}

// 14.15: Stale attestation (validUntil passed) → stale: true, warning
try {
  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "stale-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "stale-test",
      value: true,
      attestedAt: "2025-01-01T00:00:00Z",
      validUntil: "2025-06-01T00:00:00Z", // Already expired
    },
    evidence: {
      method: "direct-examination",
      description: "Staleness test.",
    },
    version: "1",
    timestamp: "2025-01-01T00:00:00Z",
  });

  const signed = await signAttestationManifest(
    attestation,
    attestorSigningKey,
    "2025-01-01T00:00:00Z",
    crypto,
  );

  const result = await verifyAttestation(
    signed,
    attestorKeypair.publicKey,
    null,
    null,
    crypto,
    "active",
    "2026-03-08T00:00:00Z", // After validUntil
  );

  strictEqual(result.attestationVerified, true);
  strictEqual(result.stale, true);
  ok(
    result.warnings.some((w) => w.includes("expired") || w.includes("validUntil")),
    "Should warn about staleness",
  );

  pass("14.15 Stale attestation (validUntil passed) → stale: true, warning");
} catch (e) {
  fail("14.15 Stale attestation", e);
}

// =========================================================================
// Test: 14.16 — Attestation Chain (§10.6)
// =========================================================================

console.log("\n=== Attestation Chain (§10.6) ===\n");

// 14.16: 3-version attestation chain → chain verifies
try {
  // V1: Clearance valid
  const v1 = buildAttestationManifest({
    attestorAuthority,
    attestationId: "clearance-chain",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "clearance-status",
      value: "valid",
      scope: "TS/SCI",
      attestedAt: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
    },
    evidence: { method: "direct-examination", description: "Initial clearance check." },
    version: "1",
    timestamp: "2026-01-01T00:00:00Z",
  });
  const signedV1 = await signAttestationManifest(v1, attestorSigningKey, "2026-01-01T00:00:00Z", crypto);
  const v1Hash = await hashAttestationManifest(signedV1, crypto);

  // V2: Clearance upgraded
  const v2 = buildAttestationManifest({
    attestorAuthority,
    attestationId: "clearance-chain",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "clearance-status",
      value: "upgraded",
      scope: "TS/SCI/SAP",
      attestedAt: "2026-06-01T00:00:00Z",
      validUntil: "2028-01-01T00:00:00Z",
    },
    evidence: { method: "direct-examination", description: "Upgrade verified." },
    version: "2",
    timestamp: "2026-06-01T00:00:00Z",
    chain: { previous: v1Hash, depth: 2, genesisHash: v1Hash },
  });
  const signedV2 = await signAttestationManifest(v2, attestorSigningKey, "2026-06-01T00:00:00Z", crypto);
  const v2Hash = await hashAttestationManifest(signedV2, crypto);

  // V3: Clearance revoked
  const v3 = buildAttestationManifest({
    attestorAuthority,
    attestationId: "clearance-chain",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "clearance-status",
      value: "revoked",
      attestedAt: "2027-01-01T00:00:00Z",
    },
    evidence: { method: "direct-examination", description: "Clearance revoked." },
    version: "3",
    timestamp: "2027-01-01T00:00:00Z",
    chain: { previous: v2Hash, depth: 3, genesisHash: v1Hash },
  });
  const signedV3 = await signAttestationManifest(v3, attestorSigningKey, "2027-01-01T00:00:00Z", crypto);

  // Verify all three attestation signatures
  const r1 = await verifyAttestation(signedV1, attestorKeypair.publicKey, null, null, crypto);
  const r2 = await verifyAttestation(signedV2, attestorKeypair.publicKey, null, null, crypto);
  const r3 = await verifyAttestation(signedV3, attestorKeypair.publicKey, null, null, crypto);

  strictEqual(r1.attestationVerified, true);
  strictEqual(r2.attestationVerified, true);
  strictEqual(r3.attestationVerified, true);

  // Verify chain linking
  strictEqual(signedV2["hiri:chain"]?.previous, v1Hash);
  strictEqual(signedV3["hiri:chain"]?.previous, v2Hash);
  strictEqual(signedV3["hiri:chain"]?.genesisHash, v1Hash);
  strictEqual(signedV3["hiri:chain"]?.depth, 3);

  // Verify claim evolution
  strictEqual(r1.claim.value, "valid");
  strictEqual(r2.claim.value, "upgraded");
  strictEqual(r3.claim.value, "revoked");

  pass("14.16 Attestation chain: 3 versions (clearance updates, §10.6) → chain verifies");
} catch (e) {
  fail("14.16 Attestation chain", e);
}

// =========================================================================
// Tests: 14.17–14.18 — Edge Cases
// =========================================================================

console.log("\n=== Edge Cases ===\n");

// 14.17: Attestor key revoked + subject unavailable → trustLevel: "unverifiable"
try {
  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "revoked-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "revoke-test",
      value: true,
      attestedAt: "2026-03-07T12:00:00Z",
    },
    evidence: { method: "direct-examination", description: "Key revocation test." },
    version: "1",
    timestamp: "2026-03-07T12:00:00Z",
  });

  const signed = await signAttestationManifest(
    attestation,
    attestorSigningKey,
    "2026-03-07T12:00:00Z",
    crypto,
  );

  const result = await verifyAttestation(
    signed,
    attestorKeypair.publicKey,
    null, // subject unavailable
    null,
    crypto,
    "revoked", // attestor key is revoked
  );

  strictEqual(result.attestationVerified, true); // signature itself is valid
  strictEqual(result.trustLevel, "unverifiable");
  ok(
    result.warnings.some((w) => w.includes("revoked")),
    "Should warn about revoked key",
  );

  pass("14.17 Attestor key revoked + subject unavailable → trustLevel: 'unverifiable'");
} catch (e) {
  fail("14.17 Attestor key revoked", e);
}

// 14.18: getLogicalPlaintextHash() for attestation → throws (§11.3)
try {
  const attestation = buildAttestationManifest({
    attestorAuthority,
    attestationId: "hash-test-001",
    subject: {
      authority: subjectAuthority,
      manifestHash: subjectManifestHash,
      contentHash: subjectContentHash,
      manifestVersion: "1",
    },
    claim: {
      "@type": "hiri:PropertyAttestation",
      property: "hash-test",
      value: true,
      attestedAt: "2026-03-07T12:00:00Z",
    },
    evidence: { method: "test", description: "Hash exception test." },
    version: "1",
    timestamp: "2026-03-07T12:00:00Z",
  });

  const signed = await signAttestationManifest(
    attestation,
    attestorSigningKey,
    "2026-03-07T12:00:00Z",
    crypto,
  );

  let threw = false;
  try {
    getLogicalPlaintextHash(signed as unknown as ResolutionManifest);
  } catch (err) {
    threw = true;
    ok(
      (err as Error).message.includes("no logical plaintext hash") ||
      (err as Error).message.includes("Attestation"),
      "Error should mention attestation or no logical plaintext hash",
    );
  }
  strictEqual(threw, true, "getLogicalPlaintextHash must throw for attestation");

  pass("14.18 getLogicalPlaintextHash() for attestation → throws (§11.3)");
} catch (e) {
  fail("14.18 getLogicalPlaintextHash attestation exception", e);
}

// =========================================================================
// Summary
// =========================================================================

console.log(`\n=== M14 Anonymous Publication & Attestation: ${passed} passed, ${failed} failed ===\n`);

if (failed > 0) {
  process.exit(1);
}

// =========================================================================
// Helpers
// =========================================================================

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
