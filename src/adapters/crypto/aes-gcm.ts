/**
 * AES-256-GCM Authenticated Encryption — Milestone 11
 *
 * Uses Web Crypto API for AES-256-GCM encryption and decryption.
 * The GCM authentication tag (16 bytes) is appended to the ciphertext.
 *
 * This module is Layer 1 (Adapters).
 */

// Web Crypto is available globally in Node 19+ and all modern browsers.
// In Node, it's at globalThis.crypto.subtle.
const subtle = globalThis.crypto.subtle;

/**
 * Encrypt with AES-256-GCM.
 * @param key - 32-byte AES key
 * @param iv - 12-byte initialization vector (nonce)
 * @param plaintext - Data to encrypt
 * @returns Ciphertext with appended 16-byte GCM authentication tag
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error(`AES-256 key must be 32 bytes, got ${key.length}`);
  }
  if (iv.length !== 12) {
    throw new Error(`AES-GCM IV must be 12 bytes, got ${iv.length}`);
  }

  const cryptoKey = await subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  const result = await subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    plaintext,
  );

  return new Uint8Array(result);
}

/**
 * Decrypt with AES-256-GCM.
 * GCM tag failure throws an error.
 * @param key - 32-byte AES key
 * @param iv - 12-byte initialization vector (nonce)
 * @param ciphertext - Data to decrypt (includes appended 16-byte GCM tag)
 * @returns Recovered plaintext
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error(`AES-256 key must be 32 bytes, got ${key.length}`);
  }
  if (iv.length !== 12) {
    throw new Error(`AES-GCM IV must be 12 bytes, got ${iv.length}`);
  }

  const cryptoKey = await subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const result = await subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    ciphertext,
  );

  return new Uint8Array(result);
}
