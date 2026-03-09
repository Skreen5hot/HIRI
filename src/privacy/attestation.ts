/**
 * Third-Party Attestation — Milestone 14
 *
 * Implements Mode 5: Third-Party Attestation (§10).
 *
 * An attestor examines content held by one authority and publishes a signed
 * attestation about a property of that content — without publishing the
 * content itself. The attestation IS the manifest; there is no separate
 * content block (§10.4).
 *
 * Verification requires dual-signature checking (§10.5):
 * 1. Attestor's signature on the attestation manifest
 * 2. Subject authority's signature on the referenced manifest
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel) and Layer 1 (Adapters).
 */

import type {
  CryptoProvider,
  SigningKey,
  ResolutionManifest,
  HiriSignature,
  DocumentLoader,
} from "../kernel/types.js";
import type {
  AttestationSubject,
  AttestationClaim,
  AttestationEvidence,
  AttestationVerificationResult,
} from "./types.js";
import { JCSCanonicalizer } from "../kernel/jcs-canonicalizer.js";
import { encode as base58Encode, decode as base58Decode } from "../kernel/base58.js";
import { verifyManifest } from "../kernel/signing.js";

/** No-op document loader for JCS (JCS ignores it but the interface requires it). */
const jcsDocumentLoader: DocumentLoader = async (url: string) => {
  throw new Error(`JCS canonicalization does not fetch documents: ${url}`);
};

// ---------------------------------------------------------------------------
// Attestation Manifest Type
// ---------------------------------------------------------------------------

/** Unsigned attestation manifest (before signing). */
export interface UnsignedAttestationManifest {
  "@context": string[];
  "@id": string;
  "@type": "hiri:AttestationManifest";
  "hiri:version": string;
  "hiri:branch": string;
  "hiri:timing": { created: string };
  "hiri:privacy": { mode: "attestation" };
  "hiri:attestation": {
    subject: AttestationSubject;
    claim: AttestationClaim;
    evidence: AttestationEvidence;
  };
  "hiri:chain"?: {
    previous: string;
    depth: number;
    genesisHash: string;
  };
}

/** Signed attestation manifest. */
export interface SignedAttestationManifest extends UnsignedAttestationManifest {
  "hiri:signature": HiriSignature;
}

// ---------------------------------------------------------------------------
// Build Attestation Manifest (§10.2)
// ---------------------------------------------------------------------------

export interface BuildAttestationParams {
  attestorAuthority: string;
  attestationId: string;
  subject: AttestationSubject;
  claim: AttestationClaim;
  evidence: AttestationEvidence;
  version: string;
  branch?: string;
  timestamp: string;
  chain?: {
    previous: string;
    depth: number;
    genesisHash: string;
  };
}

/**
 * Build an unsigned attestation manifest (§10.2).
 *
 * MUST NOT include hiri:content (§10.4).
 */
export function buildAttestationManifest(
  params: BuildAttestationParams,
): UnsignedAttestationManifest {
  const manifest: UnsignedAttestationManifest = {
    "@context": [
      "https://hiri-protocol.org/spec/v3.1",
      "https://hiri-protocol.org/privacy/v1",
      "https://w3id.org/security/v2",
    ],
    "@id": `hiri://${params.attestorAuthority}/attestation/${params.attestationId}`,
    "@type": "hiri:AttestationManifest",
    "hiri:version": params.version,
    "hiri:branch": params.branch ?? "main",
    "hiri:timing": { created: params.timestamp },
    "hiri:privacy": { mode: "attestation" },
    "hiri:attestation": {
      subject: params.subject,
      claim: params.claim,
      evidence: params.evidence,
    },
  };

  if (params.chain) {
    manifest["hiri:chain"] = params.chain;
  }

  return manifest;
}

// ---------------------------------------------------------------------------
// Sign Attestation Manifest
// ---------------------------------------------------------------------------

/**
 * Sign an attestation manifest.
 *
 * Uses JCS canonicalization (attestation manifests have no hiri:content
 * to declare a profile, so JCS is the default).
 */
export async function signAttestationManifest(
  unsigned: UnsignedAttestationManifest,
  key: SigningKey,
  timestamp: string,
  crypto: CryptoProvider,
): Promise<SignedAttestationManifest> {
  const canonicalizer = new JCSCanonicalizer();
  const bytes = await canonicalizer.canonicalize(
    unsigned as unknown as Record<string, unknown>,
    jcsDocumentLoader,
  );
  const signature = await crypto.sign(bytes, key.privateKey);

  // Extract attestor authority from @id (hiri://<authority>/attestation/<id>)
  const attestorAuth = unsigned["@id"].split("//")[1]?.split("/attestation")[0] ?? "unknown";

  const signed: SignedAttestationManifest = {
    ...unsigned,
    "hiri:signature": {
      type: "Ed25519Signature2020",
      canonicalization: "JCS",
      created: timestamp,
      verificationMethod: `hiri://${attestorAuth}/key/main#${key.keyId}`,
      proofPurpose: "assertionMethod",
      proofValue: "z" + base58Encode(signature),
    },
  };

  return signed;
}

// ---------------------------------------------------------------------------
// Validate Attestation Manifest Structure (§10.4)
// ---------------------------------------------------------------------------

export interface AttestationValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validate attestation manifest structure per §10.4.
 *
 * Rejects if hiri:content is present. Validates all required fields.
 */
export function validateAttestationManifest(
  manifest: Record<string, unknown>,
): AttestationValidationResult {
  // §10.4: hiri:content MUST NOT be present
  if ("hiri:content" in manifest) {
    return {
      valid: false,
      reason: "AttestationManifest MUST NOT have hiri:content block (§10.4)",
    };
  }

  // @type must be hiri:AttestationManifest
  if (manifest["@type"] !== "hiri:AttestationManifest") {
    return {
      valid: false,
      reason: `@type must be "hiri:AttestationManifest", got "${manifest["@type"]}"`,
    };
  }

  // Required fields
  const requiredFields = [
    "@context",
    "@id",
    "@type",
    "hiri:version",
    "hiri:branch",
    "hiri:timing",
    "hiri:privacy",
    "hiri:attestation",
  ];

  for (const field of requiredFields) {
    if (!(field in manifest)) {
      return {
        valid: false,
        reason: `Missing required field "${field}" (§10.4)`,
      };
    }
  }

  // hiri:privacy must have mode: "attestation"
  const privacy = manifest["hiri:privacy"] as Record<string, unknown> | undefined;
  if (!privacy || privacy.mode !== "attestation") {
    return {
      valid: false,
      reason: `hiri:privacy.mode must be "attestation"`,
    };
  }

  // hiri:attestation must have subject, claim, evidence
  const attestation = manifest["hiri:attestation"] as Record<string, unknown> | undefined;
  if (!attestation) {
    return { valid: false, reason: "Missing hiri:attestation block" };
  }
  for (const sub of ["subject", "claim", "evidence"]) {
    if (!(sub in attestation)) {
      return {
        valid: false,
        reason: `Missing hiri:attestation.${sub} (§10.3)`,
      };
    }
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Verify Attestation — Dual Signature (§10.5)
// ---------------------------------------------------------------------------

/**
 * Verify an attestation with dual-signature checking (§10.5).
 *
 * 1. Verify attestor's signature on the attestation manifest
 * 2. If subject manifest provided, verify subject authority's signature
 *
 * Trust levels:
 * - "full": both signatures verified
 * - "partial": attestor verified, subject unavailable or subject verified but attestor key revoked
 * - "unverifiable": attestor signature fails, or attestor key revoked + subject unavailable
 *
 * @param attestation - The signed attestation manifest
 * @param attestorPublicKey - Attestor's Ed25519 public key
 * @param subjectManifest - The referenced subject manifest (null if unavailable)
 * @param subjectPublicKey - Subject authority's public key (null if unavailable)
 * @param crypto - CryptoProvider for signature verification
 * @param attestorKeyStatus - Key status from KeyDocument resolution (default "active")
 * @param currentTimestamp - Current time for staleness check (ISO 8601)
 */
export async function verifyAttestation(
  attestation: SignedAttestationManifest,
  attestorPublicKey: Uint8Array,
  subjectManifest: ResolutionManifest | null,
  subjectPublicKey: Uint8Array | null,
  crypto: CryptoProvider,
  attestorKeyStatus: string = "active",
  currentTimestamp?: string,
): Promise<AttestationVerificationResult> {
  const warnings: string[] = [];
  const attestationBlock = attestation["hiri:attestation"];
  const claim = attestationBlock.claim;

  // Extract claim info for result
  const claimResult = {
    property: claim.property,
    value: claim.value,
    scope: claim.scope,
  };

  // Step 1: Verify attestor's signature
  const canonicalizer = new JCSCanonicalizer();
  const unsigned = structuredClone(attestation) as unknown as Record<string, unknown>;
  delete unsigned["hiri:signature"];
  const bytes = await canonicalizer.canonicalize(unsigned, jcsDocumentLoader);
  const sig = attestation["hiri:signature"];
  const proofValue = sig.proofValue;
  const sigBytes = base58Decode(
    proofValue.startsWith("z") ? proofValue.substring(1) : proofValue,
  );
  const attestorSigValid = await crypto.verify(bytes, sigBytes, attestorPublicKey);

  if (!attestorSigValid) {
    return {
      attestationVerified: false,
      attestorAuthority: attestation["@id"].split("//")[1]?.split("/attestation")[0] ?? "",
      attestorKeyStatus,
      subjectManifestVerified: false,
      claim: claimResult,
      stale: false,
      trustLevel: "unverifiable",
      warnings: ["Attestor signature verification failed"],
    };
  }

  // Step 2: Check staleness
  let stale = false;
  if (claim.validUntil) {
    const now = currentTimestamp ?? new Date().toISOString();
    if (now > claim.validUntil) {
      stale = true;
      warnings.push(
        `Attestation expired: validUntil ${claim.validUntil} has passed`,
      );
    }
  }

  // Step 3: Check attestor key status
  const keyRevoked =
    attestorKeyStatus === "revoked" || attestorKeyStatus === "revoked-compromised";

  if (keyRevoked) {
    warnings.push(`Attestor key status: ${attestorKeyStatus}`);
  }

  // Step 4: Verify subject manifest if available
  let subjectManifestVerified = false;
  if (subjectManifest && subjectPublicKey) {
    // Discover profile from subject manifest's signature
    const subjectSig = subjectManifest["hiri:signature"];
    const subjectProfile =
      (subjectSig?.canonicalization as "JCS" | "URDNA2015") ?? "JCS";

    try {
      subjectManifestVerified = await verifyManifest(
        subjectManifest,
        subjectPublicKey,
        subjectProfile,
        crypto,
      );
    } catch {
      subjectManifestVerified = false;
    }

    if (subjectManifestVerified) {
      // Verify manifest hash matches
      const manifestBytes = await canonicalizer.canonicalize(
        subjectManifest as unknown as Record<string, unknown>,
        jcsDocumentLoader,
      );
      const manifestHash = await crypto.hash(manifestBytes);
      if (manifestHash !== attestationBlock.subject.manifestHash) {
        subjectManifestVerified = false;
        warnings.push("Subject manifestHash does not match computed hash");
      }
    }

    if (!subjectManifestVerified) {
      warnings.push("Subject manifest signature verification failed");
    }
  } else if (!subjectManifest) {
    warnings.push("Subject manifest unavailable — trust based on attestor signature alone");
  }

  // Step 5: Determine trust level
  let trustLevel: "full" | "partial" | "unverifiable";
  if (keyRevoked && !subjectManifestVerified) {
    trustLevel = "unverifiable";
  } else if (subjectManifestVerified && !keyRevoked) {
    trustLevel = "full";
  } else {
    trustLevel = "partial";
  }

  // Extract attestor authority from @id
  const attestorAuthority =
    attestation["@id"].split("//")[1]?.split("/attestation")[0] ?? "";

  return {
    attestationVerified: true,
    attestorAuthority,
    attestorKeyStatus,
    subjectManifestVerified,
    claim: claimResult,
    stale,
    trustLevel,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Hash Attestation Manifest (for chain linking)
// ---------------------------------------------------------------------------

/**
 * Compute the hash of a signed attestation manifest for chain linking.
 */
export async function hashAttestationManifest(
  attestation: SignedAttestationManifest,
  crypto: CryptoProvider,
): Promise<string> {
  const canonicalizer = new JCSCanonicalizer();
  const bytes = await canonicalizer.canonicalize(
    attestation as unknown as Record<string, unknown>,
    jcsDocumentLoader,
  );
  return crypto.hash(bytes);
}
