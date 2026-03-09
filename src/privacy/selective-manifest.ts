/**
 * Selective Disclosure Manifest Builder — Milestone 13
 *
 * Builds an unsigned manifest with selective disclosure (§8.5).
 * Sets canonicalization to URDNA2015 (§8.3 requirement),
 * availability to "partial", and populates the hiri:privacy block.
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel).
 */

import type { ManifestParams, UnsignedManifest } from "../kernel/types.js";
import { buildUnsignedManifest } from "../kernel/manifest.js";
import type { HmacKeyDistributionResult } from "./hmac-disclosure.js";

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

export interface SelectiveDisclosureManifestParams {
  /** Base manifest parameters. contentHash should be hash of the SD content blob. */
  baseManifestParams: ManifestParams;
  /** Total number of statements in the canonical N-Quads. */
  statementCount: number;
  /** Raw 32-byte index salt. */
  indexSalt: Uint8Array;
  /** Index root hash ("sha256:<hex>"). */
  indexRoot: string;
  /** Indices of mandatory (always-disclosed) statements. */
  mandatoryStatements: number[];
  /** HMAC key distribution result from encryptHmacKeyForRecipients(). */
  hmacKeyDistribution: HmacKeyDistributionResult;
  /** Key agreement identifier. Defaults to "X25519-HKDF-SHA256". */
  keyAgreement?: string;
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/**
 * Build an unsigned manifest for selective disclosure content.
 *
 * Enforces:
 * - canonicalization = "URDNA2015" (§8.3)
 * - availability = "partial"
 * - mode = "selective-disclosure"
 */
export function buildSelectiveDisclosureManifest(
  params: SelectiveDisclosureManifestParams,
): UnsignedManifest {
  // Enforce URDNA2015 requirement
  if (params.baseManifestParams.canonicalization !== "URDNA2015") {
    throw new Error(
      `Selective disclosure requires URDNA2015 canonicalization (§8.3), got "${params.baseManifestParams.canonicalization}"`,
    );
  }

  const unsigned = buildUnsignedManifest(params.baseManifestParams);

  // Set availability to "partial"
  (unsigned["hiri:content"] as unknown as Record<string, unknown>).availability = "partial";

  // Attach privacy block
  const manifest = unsigned as UnsignedManifest & { "hiri:privacy": Record<string, unknown> };
  manifest["hiri:privacy"] = {
    mode: "selective-disclosure",
    parameters: {
      disclosureProofSuite: "hiri-hmac-sd-2026",
      statementCount: params.statementCount,
      indexSalt: base64urlEncode(params.indexSalt),
      indexRoot: params.indexRoot,
      mandatoryStatements: params.mandatoryStatements,
      hmacKeyRecipients: {
        ephemeralPublicKey: bytesToHex(params.hmacKeyDistribution.ephemeralPublicKey),
        iv: bytesToHex(params.hmacKeyDistribution.iv),
        keyAgreement: params.keyAgreement ?? "X25519-HKDF-SHA256",
        recipients: params.hmacKeyDistribution.recipients.map((r) => ({
          id: r.id,
          encryptedHmacKey: bytesToHex(r.encryptedHmacKey),
          disclosedStatements: r.disclosedStatements,
        })),
      },
    },
  };

  return manifest;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Encode bytes as base64url without padding (RFC 4648 §5).
 */
function base64urlEncode(bytes: Uint8Array): string {
  // Convert to regular base64 first
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  // Convert to base64url: replace + with -, / with _, remove = padding
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
