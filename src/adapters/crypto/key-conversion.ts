/**
 * Ed25519 ↔ X25519 Key Conversion — Milestone 11
 *
 * Converts Ed25519 signing keys to X25519 encryption keys.
 * Used to derive encryption keys from HIRI authority identities (§13.3).
 *
 * Recipient keys are converted; ephemeral keys are generated natively as X25519.
 *
 * This module is Layer 1 (Adapters).
 */

import { ed25519 } from "@noble/curves/ed25519.js";

/**
 * Convert an Ed25519 public key to X25519 for ECDH key agreement.
 * @param edPublic - 32-byte Ed25519 public key
 * @returns 32-byte X25519 public key
 */
export function ed25519PublicToX25519(edPublic: Uint8Array): Uint8Array {
  if (edPublic.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${edPublic.length}`);
  }
  return ed25519.utils.toMontgomery(edPublic);
}

/**
 * Convert an Ed25519 private key to X25519.
 * @param edPrivate - 32-byte Ed25519 private key (seed)
 * @returns 32-byte X25519 private key
 */
export function ed25519PrivateToX25519(edPrivate: Uint8Array): Uint8Array {
  if (edPrivate.length !== 32) {
    throw new Error(`Ed25519 private key must be 32 bytes, got ${edPrivate.length}`);
  }
  return ed25519.utils.toMontgomerySecret(edPrivate);
}
