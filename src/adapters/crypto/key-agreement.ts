/**
 * Key Agreement Pipeline — Milestone 11
 *
 * Full key agreement pipeline: ECDH → HKDF → AES-GCM encrypt/decrypt.
 * Combines x25519, hkdf, and aes-gcm into a single high-level operation
 * matching §13.2 steps.
 *
 * This module is Layer 1 (Adapters).
 */

import { x25519SharedSecret } from "./x25519.js";
import { buildHKDFInfo, hkdfDerive } from "./hkdf.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "./aes-gcm.js";

/**
 * Encrypt a secret key for a specific recipient.
 *
 * Pipeline (§13.2):
 * 1. SS = X25519(ephemeralPrivateKey, recipientPublicKeyX25519)
 * 2. info = buildHKDFInfo(hkdfLabel, recipientId)
 * 3. KEK = HKDF-SHA256(ikm=SS, salt=iv, info=info, length=32)
 * 4. encryptedKey = AES-256-GCM(key=KEK, nonce=iv, plaintext=secretKey)
 */
export async function encryptKeyForRecipient(params: {
  ephemeralPrivateKey: Uint8Array;
  recipientPublicKeyX25519: Uint8Array;
  iv: Uint8Array;
  secretKey: Uint8Array;
  recipientId: string;
  hkdfLabel: string;
}): Promise<Uint8Array> {
  const ss = x25519SharedSecret(params.ephemeralPrivateKey, params.recipientPublicKeyX25519);
  const info = buildHKDFInfo(params.hkdfLabel, params.recipientId);
  const kek = hkdfDerive({ ikm: ss, salt: params.iv, info, length: 32 });
  return aesGcmEncrypt(kek, params.iv, params.secretKey);
}

/**
 * Decrypt a secret key from a sender's ephemeral public key.
 *
 * Pipeline (§13.2, recipient side):
 * 1. SS = X25519(ownPrivateKeyX25519, ephemeralPublicKey)
 * 2. info = buildHKDFInfo(hkdfLabel, recipientId)
 * 3. KEK = HKDF-SHA256(ikm=SS, salt=iv, info=info, length=32)
 * 4. secretKey = AES-256-GCM-Decrypt(key=KEK, nonce=iv, ciphertext=encryptedKey)
 */
export async function decryptKeyFromSender(params: {
  ownPrivateKeyX25519: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  iv: Uint8Array;
  encryptedKey: Uint8Array;
  recipientId: string;
  hkdfLabel: string;
}): Promise<Uint8Array> {
  const ss = x25519SharedSecret(params.ownPrivateKeyX25519, params.ephemeralPublicKey);
  const info = buildHKDFInfo(params.hkdfLabel, params.recipientId);
  const kek = hkdfDerive({ ikm: ss, salt: params.iv, info, length: 32 });
  return aesGcmDecrypt(kek, params.iv, params.encryptedKey);
}
