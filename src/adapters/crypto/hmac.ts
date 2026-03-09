/**
 * HMAC-SHA256 — Milestone 11
 *
 * Computes HMAC-SHA256 tags for selective disclosure (Mode 3).
 *
 * This module is Layer 1 (Adapters).
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Compute HMAC-SHA256 tag.
 * @param key - HMAC key (arbitrary length, but typically 32 bytes)
 * @param data - Data to authenticate
 * @returns 32-byte HMAC-SHA256 tag
 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}
