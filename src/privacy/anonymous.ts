/**
 * Anonymous Publication — Milestone 14
 *
 * Implements Mode 4: Anonymous Publication (§9).
 *
 * Ephemeral authorities: one-time keypair, destroyed after signing,
 * computationally unlinkable across publications.
 *
 * Pseudonymous authorities: persistent keypair not linked to identity,
 * linkable across publications from the same authority.
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel) and Layer 1 (Adapters).
 */

import type { ResolutionManifest } from "../kernel/types.js";
import { deriveAuthority } from "../kernel/authority.js";
import { generateKeypair } from "../adapters/crypto/ed25519.js";
import type { AnonymousParams } from "./types.js";

// ---------------------------------------------------------------------------
// Ephemeral Authority Generation (§9.6)
// ---------------------------------------------------------------------------

export interface EphemeralAuthorityResult {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  authority: string;
  keyId: string;
}

/**
 * Generate an ephemeral signing keypair for anonymous publication.
 *
 * The caller MUST destroy the private key after signing (zero the buffer).
 * Two calls produce computationally unlinkable authorities.
 *
 * @returns Fresh Ed25519 keypair with derived authority string
 */
export async function generateEphemeralAuthority(): Promise<EphemeralAuthorityResult> {
  const signingKey = await generateKeypair("ephemeral-key");
  const authority = deriveAuthority(signingKey.publicKey, "ed25519");
  return {
    publicKey: signingKey.publicKey,
    privateKey: signingKey.privateKey,
    authority,
    keyId: signingKey.keyId,
  };
}

// ---------------------------------------------------------------------------
// Anonymous Constraint Validation (§9.5)
// ---------------------------------------------------------------------------

export interface AnonymousValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validate anonymous manifest constraints per §9.5.
 *
 * Ephemeral authorities:
 * - MUST NOT have a KeyDocument reference in the manifest
 * - MUST NOT have key rotation or revocation fields
 *
 * Pseudonymous authorities:
 * - MAY have a KeyDocument (no additional constraints enforced here)
 */
export function validateAnonymousConstraints(
  manifest: ResolutionManifest,
  params: AnonymousParams,
): AnonymousValidationResult {
  if (params.authorityType === "ephemeral") {
    // Check for KeyDocument reference in signature block
    const sig = manifest["hiri:signature"] as unknown as Record<string, unknown> | undefined;
    if (sig) {
      const verificationMethod = sig.verificationMethod as string | undefined;
      if (verificationMethod && verificationMethod.includes("/key/")) {
        // Ephemeral authorities MUST NOT reference a KeyDocument
        return {
          valid: false,
          reason: "Ephemeral authority MUST NOT reference a KeyDocument (§9.5)",
        };
      }
    }
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Anonymous Privacy Block Builder
// ---------------------------------------------------------------------------

/**
 * Build the hiri:privacy block for an anonymous manifest.
 */
export function buildAnonymousPrivacyBlock(
  params: AnonymousParams,
): Record<string, unknown> {
  const block: Record<string, unknown> = {
    mode: "anonymous",
    parameters: {
      authorityType: params.authorityType,
      contentVisibility: params.contentVisibility,
      identityDisclosable: params.identityDisclosable,
    },
  };

  if (params.identityDisclosable && params.disclosureConditions) {
    (block.parameters as Record<string, unknown>).disclosureConditions =
      params.disclosureConditions;
  }

  return block;
}
