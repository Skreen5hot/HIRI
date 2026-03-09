/**
 * HKDF-SHA256 Key Derivation — Milestone 11
 *
 * Implements the normative HKDF info construction from §13.2 and
 * wraps @noble/hashes HKDF for key derivation.
 *
 * This module is Layer 1 (Adapters).
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Build HKDF info parameter per §13.2 normative pseudocode.
 * Byte-level concatenation of ASCII label + UTF-8 recipient ID.
 * No separator. No framing.
 *
 * @param label - Protocol label, e.g., "hiri-cek-v1.1" or "hiri-hmac-v1.1"
 * @param recipientId - Recipient identifier string
 * @returns Concatenated info bytes
 */
export function buildHKDFInfo(label: string, recipientId: string): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  const idBytes = new TextEncoder().encode(recipientId);
  const info = new Uint8Array(labelBytes.length + idBytes.length);
  info.set(labelBytes, 0);
  info.set(idBytes, labelBytes.length);
  return info;
}

/**
 * Derive a key via HKDF-SHA256.
 *
 * @param params.ikm - Input keying material (e.g., X25519 shared secret)
 * @param params.salt - Salt (e.g., the AES-GCM IV)
 * @param params.info - Info parameter (from buildHKDFInfo)
 * @param params.length - Output key length in bytes
 * @returns Derived key
 */
export function hkdfDerive(params: {
  ikm: Uint8Array;
  salt: Uint8Array;
  info: Uint8Array;
  length: number;
}): Uint8Array {
  return hkdf(sha256, params.ikm, params.salt, params.info, params.length);
}
