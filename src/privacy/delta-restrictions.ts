/**
 * Delta Restrictions for Privacy Modes — Milestones 12, 13
 *
 * Validates delta metadata against privacy mode constraints (§14).
 * Also provides opaque delta blob decryption and inner structure parsing (§14.3).
 *
 * For encrypted mode (§14.3):
 * - format MUST be "application/octet-stream"
 * - operations MUST be -1
 * - appliesTo MUST NOT be present in manifest-level delta metadata
 *
 * For selective-disclosure mode (§14.4):
 * - format MUST be "application/hiri-statement-index-delta+json"
 * - Contains only indexRoot changes, no operation-level detail
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel) and Layer 1 (Adapters).
 */

import type { ManifestDelta, CryptoProvider } from "../kernel/types.js";
import type { PrivacyMode, EncryptedPrivacyParams } from "./types.js";
import { decryptKeyFromSender } from "../adapters/crypto/key-agreement.js";
import { aesGcmDecrypt } from "../adapters/crypto/aes-gcm.js";

// ---------------------------------------------------------------------------
// Delta Validation
// ---------------------------------------------------------------------------

export interface DeltaValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validate delta restrictions per privacy mode.
 *
 * @param mode - Privacy mode of the manifest
 * @param delta - Delta metadata from the manifest
 * @returns Validation result with optional reason on failure
 */
export function validatePrivacyDelta(
  mode: PrivacyMode | string,
  delta: ManifestDelta,
): DeltaValidationResult {
  switch (mode) {
    case "public":
    case "proof-of-possession":
      // No restrictions on delta format for public/PoP modes
      return { valid: true };

    case "encrypted":
      return validateEncryptedDelta(delta);

    case "selective-disclosure":
      return validateSelectiveDisclosureDelta(delta);

    default:
      // Future modes: no validation yet
      return { valid: true };
  }
}

function validateEncryptedDelta(delta: ManifestDelta): DeltaValidationResult {
  // §14.3: format MUST be "application/octet-stream"
  if (delta.format !== "application/octet-stream") {
    return {
      valid: false,
      reason: `Encrypted mode requires delta format "application/octet-stream", got "${delta.format}"`,
    };
  }

  // §14.3: operations MUST be -1 (opaque)
  if (delta.operations !== -1) {
    return {
      valid: false,
      reason: `Encrypted mode requires delta operations -1 (opaque), got ${delta.operations}`,
    };
  }

  // §14.3: appliesTo MUST NOT be present in manifest-level delta
  if (delta.appliesTo !== undefined && delta.appliesTo !== "") {
    return {
      valid: false,
      reason: `Encrypted mode: appliesTo must not be in manifest-level delta metadata (§14.3: appliesTo lives inside encrypted blob)`,
    };
  }

  return { valid: true };
}

function validateSelectiveDisclosureDelta(delta: ManifestDelta): DeltaValidationResult {
  // §14.4: format MUST be "application/hiri-statement-index-delta+json"
  if (delta.format !== "application/hiri-statement-index-delta+json") {
    return {
      valid: false,
      reason: `Selective disclosure mode requires delta format "application/hiri-statement-index-delta+json", got "${delta.format}"`,
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Opaque Delta Blob — Decryption and Inner Parsing (§14.3)
// ---------------------------------------------------------------------------

/** Inner structure of a decrypted opaque delta blob. */
export interface DecryptedDeltaInner {
  appliesTo: string; // Previous logical plaintext hash
  operations: unknown; // The actual delta operations (format-specific)
}

/**
 * Decrypt an opaque delta blob and parse the inner structure.
 *
 * The encrypted delta blob, when decrypted, contains JSON with:
 * - appliesTo: reference to previous version's logical plaintext hash
 * - operations: the actual delta operations
 *
 * @param encryptedDeltaBlob - The encrypted delta content
 * @param params - Encrypted privacy parameters (from manifest)
 * @param ownPrivateKey - Recipient's X25519 private key
 * @param ownRecipientId - Recipient's identifier
 * @param crypto - CryptoProvider (unused currently but kept for API consistency)
 * @param hkdfLabel - HKDF info label (defaults to "hiri-cek-v1.1")
 */
export async function decryptAndParseOpaqueDelta(
  encryptedDeltaBlob: Uint8Array,
  params: EncryptedPrivacyParams,
  ownPrivateKey: Uint8Array,
  ownRecipientId: string,
  _crypto: CryptoProvider,
  hkdfLabel: string = "hiri-cek-v1.1",
): Promise<DecryptedDeltaInner> {
  // Find recipient entry
  const recipientEntry = params.recipients.find((r) => r.id === ownRecipientId);
  if (!recipientEntry) {
    throw new Error(
      `Not an authorized recipient: "${ownRecipientId}" not found in recipient list`,
    );
  }

  // Parse hex-encoded values
  const iv = hexToBytes(params.iv);
  const ephemeralPublicKey = hexToBytes(params.ephemeralPublicKey);
  const encryptedKey = hexToBytes(recipientEntry.encryptedKey);

  // Decrypt CEK
  const cek = await decryptKeyFromSender({
    ownPrivateKeyX25519: ownPrivateKey,
    ephemeralPublicKey,
    iv,
    encryptedKey,
    recipientId: ownRecipientId,
    hkdfLabel,
  });

  // Decrypt the delta blob
  const plainDeltaBytes = await aesGcmDecrypt(cek, iv, encryptedDeltaBlob);
  cek.fill(0);

  // Parse inner JSON
  const innerJson = JSON.parse(new TextDecoder().decode(plainDeltaBytes));

  if (!innerJson.appliesTo || typeof innerJson.appliesTo !== "string") {
    throw new Error("Decrypted delta blob missing required 'appliesTo' field");
  }

  return {
    appliesTo: innerJson.appliesTo,
    operations: innerJson.operations,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
