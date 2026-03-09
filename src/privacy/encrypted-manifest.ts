/**
 * Encrypted Manifest Builder — Milestone 12
 *
 * Builds an unsigned manifest with encrypted content (§7.3).
 * Sets content format to "application/octet-stream" and populates
 * the hiri:privacy block with encryption parameters.
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel).
 */

import type { ManifestParams, UnsignedManifest } from "../kernel/types.js";
import { buildUnsignedManifest } from "../kernel/manifest.js";
import type { EncryptionResult } from "./encryption.js";

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

export interface EncryptedManifestParams {
  /** Base manifest parameters (id, version, branch, created, addressing, canonicalization). */
  baseManifestParams: Omit<ManifestParams, "contentHash" | "contentFormat" | "contentSize">;
  /** Result from encryptContent(). */
  encryptionResult: EncryptionResult;
  /** Original plaintext format (e.g., "application/ld+json"). */
  plaintextFormat: string;
  /** Original plaintext size in bytes. */
  plaintextSize: number;
  /** Key agreement identifier. Defaults to "X25519-HKDF-SHA256". */
  keyAgreement?: string;
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/**
 * Build an unsigned manifest for encrypted content.
 *
 * - Sets `hiri:content.hash` to ciphertextHash
 * - Sets `hiri:content.format` to `"application/octet-stream"`
 * - Populates `hiri:privacy` block with Mode 2 parameters
 */
export function buildEncryptedManifest(params: EncryptedManifestParams): UnsignedManifest {
  const { encryptionResult, plaintextFormat, plaintextSize, keyAgreement } = params;

  // Build base manifest with ciphertext hash as content hash
  const manifestParams: ManifestParams = {
    ...params.baseManifestParams,
    contentHash: encryptionResult.ciphertextHash,
    contentFormat: "application/octet-stream",
    contentSize: encryptionResult.ciphertext.length,
  };

  const unsigned = buildUnsignedManifest(manifestParams);

  // Attach privacy block
  const manifest = unsigned as UnsignedManifest & { "hiri:privacy": Record<string, unknown> };
  manifest["hiri:privacy"] = {
    mode: "encrypted",
    parameters: {
      algorithm: "AES-256-GCM",
      keyAgreement: keyAgreement ?? "X25519-HKDF-SHA256",
      iv: bytesToHex(encryptionResult.iv),
      tagLength: 128,
      plaintextHash: encryptionResult.plaintextHash,
      plaintextFormat,
      plaintextSize,
      ephemeralPublicKey: bytesToHex(encryptionResult.ephemeralPublicKey),
      recipients: encryptionResult.recipients.map((r) => ({
        id: r.id,
        encryptedKey: bytesToHex(r.encryptedKey),
      })),
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
