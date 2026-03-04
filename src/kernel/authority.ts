/**
 * Authority Derivation
 *
 * Derives the HIRI authority string from a public key.
 * The authority is self-certifying: it IS the (truncated, encoded) key identity.
 *
 * Pipeline: raw SHA-256 digest bytes → base58 encode → truncate to 20 chars
 *
 * CRITICAL: The input to base58 must be the raw digest bytes (32 bytes),
 * NOT the hex-encoded string (64 chars). These produce completely different
 * base58 output.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { encode as base58Encode } from "./base58.js";
import type { CryptoProvider } from "./types.js";

/** Authority truncation length in base58 characters (~119 bits). */
const AUTHORITY_LENGTH = 20;

/**
 * Derive an authority string from raw SHA-256 digest bytes.
 * Pure and synchronous.
 *
 * @param digestBytes - Raw SHA-256 digest of the public key (32 bytes)
 * @param algorithm - Key algorithm name, e.g., "ed25519"
 * @returns Authority string, e.g., "key:ed25519:7Hf9sK3mAbC..."
 */
export function deriveAuthority(
  digestBytes: Uint8Array,
  algorithm: string,
): string {
  const b58 = base58Encode(digestBytes);
  const truncated = b58.substring(0, AUTHORITY_LENGTH);
  return `key:${algorithm}:${truncated}`;
}

/**
 * Async convenience: derive authority from a raw public key.
 * Hashes the public key via the injected CryptoProvider, then
 * delegates to the synchronous deriveAuthority.
 *
 * @param publicKey - Raw public key bytes
 * @param algorithm - Key algorithm name, e.g., "ed25519"
 * @param crypto - Injected crypto provider for hashing
 * @returns Authority string
 */
export async function deriveAuthorityAsync(
  publicKey: Uint8Array,
  algorithm: string,
  crypto: CryptoProvider,
): Promise<string> {
  const prefixedHash = await crypto.hash(publicKey); // "sha256:<hex>"
  const hex = prefixedHash.substring(prefixedHash.indexOf(":") + 1);
  const digestBytes = hexToBytes(hex);
  return deriveAuthority(digestBytes, algorithm);
}

/**
 * Convert a hex string to a Uint8Array.
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
