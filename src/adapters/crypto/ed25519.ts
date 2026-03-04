/**
 * Ed25519 Adapter
 *
 * Wraps @noble/ed25519 for keypair generation, signing, and verification.
 * Key generation uses randomness and MUST live in this adapter, not the kernel.
 *
 * This is an adapter (Layer 2) and MAY import from the kernel and external packages.
 */

import * as ed from "@noble/ed25519";
import type { SigningKey } from "../../kernel/types.js";

/**
 * Generate an Ed25519 keypair.
 * Uses crypto.getRandomValues() internally — this is the ONLY place
 * where non-deterministic operations occur in the signing pipeline.
 *
 * @returns A SigningKey with algorithm, publicKey, privateKey, and keyId
 */
export async function generateKeypair(keyId: string = "key-1"): Promise<SigningKey> {
  const privateKey = ed.utils.randomSecretKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    algorithm: "ed25519",
    publicKey,
    privateKey,
    keyId,
  };
}

/**
 * Sign a message with an Ed25519 private key.
 * Ed25519 signing is deterministic: same key + same message = same signature (RFC 8032).
 */
export async function sign(
  message: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  return ed.signAsync(message, privateKey);
}

/**
 * Verify an Ed25519 signature.
 */
export async function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}
