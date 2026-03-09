/**
 * Decryption Pipeline — Milestone 12
 *
 * Decrypts content as an authorized recipient per §7.5:
 * 1. Locate own recipient entry
 * 2. ECDH → HKDF → AES-GCM decrypt CEK
 * 3. AES-GCM decrypt content with CEK
 * 4. Verify plaintext hash
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel) and Layer 1 (Adapters).
 */

import type { CryptoProvider } from "../kernel/types.js";
import type { EncryptedPrivacyParams } from "./types.js";
import { decryptKeyFromSender } from "../adapters/crypto/key-agreement.js";
import { aesGcmDecrypt } from "../adapters/crypto/aes-gcm.js";

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

export interface DecryptionResult {
  plaintext: Uint8Array;
  plaintextHashValid: boolean;
}

// ---------------------------------------------------------------------------
// Decryption Pipeline (§7.5)
// ---------------------------------------------------------------------------

/**
 * Decrypt content as an authorized recipient.
 *
 * @param ciphertext - Encrypted content (ciphertext + GCM tag)
 * @param params - Parsed encrypted privacy parameters from manifest
 * @param ownPrivateKey - Recipient's X25519 private key
 * @param ownRecipientId - Recipient's identifier (must match an entry in params.recipients)
 * @param crypto - CryptoProvider for hashing
 * @param hkdfLabel - HKDF info label (defaults to "hiri-cek-v1.1")
 */
export async function decryptContent(
  ciphertext: Uint8Array,
  params: EncryptedPrivacyParams,
  ownPrivateKey: Uint8Array,
  ownRecipientId: string,
  crypto: CryptoProvider,
  hkdfLabel: string = "hiri-cek-v1.1",
): Promise<DecryptionResult> {
  // Step 1: Locate own recipient entry
  const recipientEntry = params.recipients.find((r) => r.id === ownRecipientId);
  if (!recipientEntry) {
    throw new Error(
      `Not an authorized recipient: "${ownRecipientId}" not found in recipient list`,
    );
  }

  // Parse hex-encoded values from params
  const iv = hexToBytes(params.iv);
  const ephemeralPublicKey = hexToBytes(params.ephemeralPublicKey);
  const encryptedKey = hexToBytes(recipientEntry.encryptedKey);

  // Step 2: Decrypt CEK via ECDH + HKDF + AES-GCM
  const cek = await decryptKeyFromSender({
    ownPrivateKeyX25519: ownPrivateKey,
    ephemeralPublicKey,
    iv,
    encryptedKey,
    recipientId: ownRecipientId,
    hkdfLabel,
  });

  // Step 3: Decrypt content with CEK
  const plaintext = await aesGcmDecrypt(cek, iv, ciphertext);

  // Step 4: Zero out CEK
  cek.fill(0);

  // Step 5: Verify plaintext hash
  const computedHash = await crypto.hash(plaintext);
  const plaintextHashValid = computedHash === params.plaintextHash;

  return { plaintext, plaintextHashValid };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
