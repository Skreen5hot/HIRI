/**
 * Default Crypto Provider
 *
 * Wires SHA256Algorithm and Ed25519 adapter into the CryptoProvider
 * interface expected by kernel functions.
 *
 * This is an adapter (Layer 2) and MAY import from the kernel and external packages.
 */

import type { CryptoProvider } from "../../kernel/types.js";
import { SHA256Algorithm } from "./sha256.js";
import * as ed25519 from "./ed25519.js";

const sha256 = new SHA256Algorithm();

/**
 * Default CryptoProvider implementation using SHA-256 + Ed25519.
 */
export const defaultCryptoProvider: CryptoProvider = {
  async hash(content: Uint8Array): Promise<string> {
    return sha256.hash(content);
  },

  async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(message, privateKey);
  },

  async verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<boolean> {
    return ed25519.verify(message, signature, publicKey);
  },
};

/** Re-export for convenience. */
export { SHA256Algorithm } from "./sha256.js";
export { generateKeypair } from "./ed25519.js";
