/**
 * X25519 Key Agreement — Milestone 11
 *
 * Native X25519 keypair generation and ECDH shared secret computation.
 * Ephemeral keys MUST be generated natively as X25519, NOT converted
 * from Ed25519 (§13.3 normative requirement).
 *
 * This module is Layer 1 (Adapters).
 */

import { x25519 } from "@noble/curves/ed25519.js";

/**
 * Generate an X25519 keypair for ephemeral ECDH.
 * Generated natively as X25519 per §13.3.
 */
export function generateX25519Keypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Compute X25519 shared secret.
 * @param privateKey - 32-byte X25519 private key
 * @param publicKey - 32-byte X25519 public key
 * @returns 32-byte shared secret
 */
export function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}
