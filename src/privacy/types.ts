/**
 * Privacy Extension Type Definitions — Milestones 10, 12, 13, 14, 15
 *
 * Result types for privacy-aware resolution. These compose with
 * the kernel's VerifiedContent type, adding privacy mode information
 * and mode-specific result fields.
 *
 * This module is Layer 2 (Privacy) and MAY import from Layer 0 (Kernel).
 */

import type { ResolutionManifest } from "../kernel/types.js";

// ---------------------------------------------------------------------------
// Privacy Mode Type
// ---------------------------------------------------------------------------

export type PrivacyMode =
  | "public"
  | "proof-of-possession"
  | "encrypted"
  | "selective-disclosure"
  | "anonymous"
  | "attestation";

// ---------------------------------------------------------------------------
// Privacy Block (parsed from manifest)
// ---------------------------------------------------------------------------

export interface PrivacyBlock {
  mode: PrivacyMode | string; // string for unknown future modes
  parameters?: Record<string, unknown>;
  transitionFrom?: string;
  transitionReason?: string;
}

// ---------------------------------------------------------------------------
// Privacy-Aware Verification Result
// ---------------------------------------------------------------------------

export interface PrivacyAwareVerificationResult {
  verified: boolean;
  manifest: ResolutionManifest;
  authority: string;
  warnings: string[];

  // Privacy extension fields
  privacyMode: PrivacyMode | string;
  contentStatus:
    | "verified"
    | "ciphertext-verified"
    | "decrypted-verified"
    | "decryption-failed"
    | "partial-disclosure"
    | "private-custody-asserted"
    | "attestation-verified"
    | "unsupported-mode";

  // Mode-specific (populated by later milestones)
  decryptedContent?: Uint8Array;
  disclosedNQuads?: string[];
  disclosedStatementIndices?: number[];
  attestationResult?: AttestationVerificationResult;
  identityType?: "identified" | "anonymous-ephemeral" | "pseudonymous";
}

// ---------------------------------------------------------------------------
// Encrypted Privacy Parameters (§7, Milestone 12)
// ---------------------------------------------------------------------------

/** Recipient entry within encrypted privacy parameters. */
export interface EncryptedRecipientEntry {
  id: string;
  encryptedKey: string; // Hex-encoded encrypted CEK
}

/** Parsed privacy parameters for Mode 2 (encrypted). */
export interface EncryptedPrivacyParams {
  algorithm: string; // "AES-256-GCM"
  keyAgreement: string; // "X25519-HKDF-SHA256" or "HPKE-Base-X25519-SHA256-AES256GCM"
  iv: string; // Hex-encoded 12-byte IV
  tagLength: number; // 128 (bits)
  plaintextHash: string; // "sha256:<hex>"
  plaintextFormat: string; // Original content format before encryption
  plaintextSize: number; // Original content size in bytes
  ephemeralPublicKey: string; // Hex-encoded X25519 ephemeral public key
  recipients: EncryptedRecipientEntry[];
}

// ---------------------------------------------------------------------------
// Selective Disclosure Parameters (§8, Milestone 13)
// ---------------------------------------------------------------------------

/** Recipient entry for HMAC key distribution. */
export interface HmacKeyRecipientEntry {
  id: string;
  encryptedHmacKey: string; // Hex-encoded encrypted HMAC key
  disclosedStatements: number[] | "all";
}

/** HMAC key recipients block in manifest. */
export interface HmacKeyRecipients {
  ephemeralPublicKey: string; // Hex-encoded X25519 ephemeral public key
  iv: string; // Hex-encoded 12-byte IV
  keyAgreement: string; // "X25519-HKDF-SHA256"
  recipients: HmacKeyRecipientEntry[];
}

/** Parsed privacy parameters for Mode 3 (selective-disclosure). */
export interface SelectiveDisclosureParams {
  disclosureProofSuite: string; // "hiri-hmac-sd-2026"
  statementCount: number;
  indexSalt: string; // Base64url-encoded (no padding) 32-byte salt
  indexRoot: string; // "sha256:<hex>"
  mandatoryStatements: number[]; // Indices of mandatory (always-disclosed) statements
  hmacKeyRecipients: HmacKeyRecipients;
}

/**
 * Published content blob for selective disclosure.
 * Stored at content.hash. Serialized as JCS JSON.
 */
export interface SelectiveDisclosureContent {
  mandatoryNQuads: string[]; // Plaintext N-Quad strings at mandatory indices
  statementIndex: string[]; // Hex-encoded salted statement hashes (all positions)
  hmacTags: string[]; // Hex-encoded HMAC tags (all positions)
}

// ---------------------------------------------------------------------------
// Anonymous Publication Parameters (§9, Milestone 14)
// ---------------------------------------------------------------------------

/** Parameters for Mode 4 (anonymous) privacy block. */
export interface AnonymousParams {
  authorityType: "ephemeral" | "pseudonymous";
  contentVisibility: "public" | "encrypted" | "private" | "selective-disclosure";
  identityDisclosable: boolean;
  disclosureConditions?: string;
}

// ---------------------------------------------------------------------------
// Attestation Types (§10, Milestone 14)
// ---------------------------------------------------------------------------

/** Identifies the data being attested to (§10.3). */
export interface AttestationSubject {
  authority: string;
  manifestHash: string;
  contentHash: string;
  manifestVersion: string;
}

/** The property being attested (§10.3). */
export interface AttestationClaim {
  "@type": "hiri:PropertyAttestation";
  property: string;
  value: unknown;
  scope?: string;
  attestedAt: string;
  validUntil?: string;
}

/** How the attestation was produced (§10.3). */
export interface AttestationEvidence {
  method: string;
  description: string;
}

/** Result of dual-signature attestation verification (§10.5). */
export interface AttestationVerificationResult {
  attestationVerified: boolean;
  attestorAuthority: string;
  attestorKeyStatus: string;
  subjectManifestVerified: boolean;
  claim: {
    property: string;
    value: unknown;
    scope?: string;
  };
  stale: boolean;
  trustLevel: "full" | "partial" | "unverifiable";
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Privacy Chain Walking (§11, Milestone 15)
// ---------------------------------------------------------------------------

import type { Canonicalizer, DocumentLoader } from "../kernel/types.js";
import type { HashRegistry } from "../kernel/hash-registry.js";

/** Options for the privacy-aware chain walker. */
export interface PrivacyChainOptions {
  canonicalizer?: Canonicalizer;
  documentLoader?: DocumentLoader;
  hashRegistry?: HashRegistry;
  decryptionKey?: Uint8Array;
  recipientId?: string;
}

/** Result of privacy-aware chain walking. */
export interface PrivacyChainWalkResult {
  valid: boolean;
  depth: number;
  warnings: string[];
  modeTransitions: Array<{
    fromVersion: string;
    toVersion: string;
    fromMode: PrivacyMode | string;
    toMode: PrivacyMode | string;
  }>;
  reason?: string;
}
