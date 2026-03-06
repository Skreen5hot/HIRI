/**
 * Authority Derivation (v3.1.1)
 *
 * Derives the HIRI authority string from a public key.
 * The authority is self-certifying: it IS the full encoded public key.
 *
 * v3.1.1 pipeline: raw public key bytes -> "z" + base58btc(publicKey)
 * No hashing, no truncation. The authority contains the complete key material.
 *
 * Invariant (Appendix B.1):
 *   extractPublicKey(deriveAuthority(pk, "ed25519")).publicKey === pk
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { encode as base58Encode, decode as base58Decode } from "./base58.js";

/**
 * Derive an authority string from a raw public key.
 * Pure and synchronous. No hashing required (v3.1.1).
 *
 * @param publicKey - Raw public key bytes (32 bytes for Ed25519)
 * @param algorithm - Key algorithm name, e.g., "ed25519"
 * @returns Authority string, e.g., "key:ed25519:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
 */
export function deriveAuthority(
  publicKey: Uint8Array,
  algorithm: string,
): string {
  if (publicKey.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes, got ${publicKey.length}`);
  }
  if (algorithm !== "ed25519") {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
  const encoded = "z" + base58Encode(publicKey);
  return `key:${algorithm}:${encoded}`;
}

/**
 * Extract the public key bytes and algorithm from an authority string.
 *
 * @param authority - Authority string, e.g., "key:ed25519:z6Mk..."
 * @returns The algorithm name and raw public key bytes
 * @throws If the authority format is invalid or missing z prefix
 */
export function extractPublicKey(authority: string): {
  algorithm: string;
  publicKey: Uint8Array;
} {
  const match = authority.match(/^key:([a-z0-9]+):(z[A-Za-z0-9]+)$/);
  if (!match) {
    throw new Error(`Invalid authority format: ${authority}`);
  }
  const [, algorithm, encoded] = match;
  const publicKey = base58Decode(encoded.slice(1)); // Strip z prefix
  return { algorithm, publicKey };
}
