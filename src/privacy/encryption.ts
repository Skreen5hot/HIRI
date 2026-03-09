/**
 * Encryption Pipeline — Milestone 12
 *
 * Encrypts content for multiple recipients per §7.4:
 * 1. Generate CEK + IV
 * 2. Hash plaintext (before encryption)
 * 3. Encrypt with AES-256-GCM
 * 4. Hash ciphertext
 * 5. Generate ephemeral X25519 keypair
 * 6. Per recipient: ECDH → HKDF → AES-GCM(KEK, IV, CEK)
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel) and Layer 1 (Adapters).
 */

import type { CryptoProvider } from "../kernel/types.js";
import { generateX25519Keypair } from "../adapters/crypto/x25519.js";
import { encryptKeyForRecipient } from "../adapters/crypto/key-agreement.js";
import { aesGcmEncrypt } from "../adapters/crypto/aes-gcm.js";

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

export interface EncryptionRecipient {
  id: string;
  encryptedKey: Uint8Array;
}

export interface EncryptionResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  plaintextHash: string;
  ciphertextHash: string;
  ephemeralPublicKey: Uint8Array;
  recipients: EncryptionRecipient[];
}

// ---------------------------------------------------------------------------
// Encryption Pipeline (§7.4)
// ---------------------------------------------------------------------------

/**
 * Encrypt content for multiple recipients.
 *
 * @param canonicalBytes - Canonicalized plaintext content
 * @param recipientPublicKeys - Map of recipientId → X25519 public key
 * @param crypto - CryptoProvider for hashing
 * @param hkdfLabel - HKDF info label (defaults to "hiri-cek-v1.1")
 */
export async function encryptContent(
  canonicalBytes: Uint8Array,
  recipientPublicKeys: Map<string, Uint8Array>,
  crypto: CryptoProvider,
  hkdfLabel: string = "hiri-cek-v1.1",
): Promise<EncryptionResult> {
  if (recipientPublicKeys.size === 0) {
    throw new Error("At least one recipient is required for encryption");
  }

  // Step 1: Generate CEK (32 bytes) and IV (12 bytes)
  const cek = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

  // Step 2: Hash plaintext before encryption
  const plaintextHash = await crypto.hash(canonicalBytes);

  // Step 3: Encrypt content with AES-256-GCM
  const ciphertext = await aesGcmEncrypt(cek, iv, canonicalBytes);

  // Step 4: Hash ciphertext
  const ciphertextHash = await crypto.hash(ciphertext);

  // Step 5: Generate ephemeral X25519 keypair (native, not Ed25519-converted per §13.3)
  const ephemeral = generateX25519Keypair();

  // Step 6: Per recipient — encrypt CEK
  const recipients: EncryptionRecipient[] = [];
  for (const [recipientId, recipientPubKey] of recipientPublicKeys) {
    const encryptedKey = await encryptKeyForRecipient({
      ephemeralPrivateKey: ephemeral.privateKey,
      recipientPublicKeyX25519: recipientPubKey,
      iv,
      secretKey: cek,
      recipientId,
      hkdfLabel,
    });
    recipients.push({ id: recipientId, encryptedKey });
  }

  // Step 7: Zero out sensitive material
  cek.fill(0);
  ephemeral.privateKey.fill(0);

  return {
    ciphertext,
    iv,
    plaintextHash,
    ciphertextHash,
    ephemeralPublicKey: ephemeral.publicKey,
    recipients,
  };
}
