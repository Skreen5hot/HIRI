/**
 * HMAC Disclosure Proofs — Milestone 13
 *
 * Implements the hiri-hmac-sd-2026 disclosure proof suite (§8.6.1).
 *
 * Publisher side: generate HMAC tags for all statements.
 * Recipient side: verify HMAC tags for disclosed statements.
 * Key distribution: encrypt HMAC key for recipients using "hiri-hmac-v1.1" label.
 *
 * This module is Layer 2 (Privacy). Imports from Layer 1 (Adapters).
 */

import { hmacSha256 } from "../adapters/crypto/hmac.js";
import { generateX25519Keypair } from "../adapters/crypto/x25519.js";
import { encryptKeyForRecipient, decryptKeyFromSender } from "../adapters/crypto/key-agreement.js";
import type { HmacKeyRecipientEntry } from "./types.js";

// ---------------------------------------------------------------------------
// HMAC Tag Generation (§8.6.1 — Publisher Side)
// ---------------------------------------------------------------------------

/**
 * Generate HMAC-SHA256 tags for all statements.
 *
 * Input per tag: HMAC-SHA256(hmacKey, concat(rawIndexSaltBytes, UTF-8(statement)))
 *
 * @param statements - Individual N-Quad strings (from URDNA2015 canonicalization)
 * @param hmacKey - 32-byte HMAC key
 * @param indexSalt - Raw 32-byte salt
 * @returns Array of 32-byte HMAC tags, one per statement
 */
export function generateHmacTags(
  statements: string[],
  hmacKey: Uint8Array,
  indexSalt: Uint8Array,
): Uint8Array[] {
  const tags: Uint8Array[] = [];
  for (const stmt of statements) {
    const stmtBytes = new TextEncoder().encode(stmt);
    const input = new Uint8Array(indexSalt.length + stmtBytes.length);
    input.set(indexSalt, 0);
    input.set(stmtBytes, indexSalt.length);
    tags.push(hmacSha256(hmacKey, input));
  }
  return tags;
}

// ---------------------------------------------------------------------------
// HMAC Tag Verification (§8.6.1 — Recipient Side)
// ---------------------------------------------------------------------------

/**
 * Verify a single disclosed statement's HMAC tag.
 *
 * @param statement - The N-Quad string to verify
 * @param hmacKey - 32-byte HMAC key (decrypted by recipient)
 * @param indexSalt - Raw 32-byte salt
 * @param expectedTag - Expected 32-byte HMAC tag
 * @returns true if tag matches
 */
export function verifyHmacTag(
  statement: string,
  hmacKey: Uint8Array,
  indexSalt: Uint8Array,
  expectedTag: Uint8Array,
): boolean {
  const stmtBytes = new TextEncoder().encode(statement);
  const input = new Uint8Array(indexSalt.length + stmtBytes.length);
  input.set(indexSalt, 0);
  input.set(stmtBytes, indexSalt.length);
  const computed = hmacSha256(hmacKey, input);
  return constantTimeEqual(computed, expectedTag);
}

// ---------------------------------------------------------------------------
// HMAC Key Distribution (§8.6.1 Step 7)
// ---------------------------------------------------------------------------

export interface HmacKeyDistributionResult {
  ephemeralPublicKey: Uint8Array;
  iv: Uint8Array;
  recipients: Array<{
    id: string;
    encryptedHmacKey: Uint8Array;
    disclosedStatements: number[] | "all";
  }>;
}

/**
 * Encrypt the HMAC key for multiple recipients.
 *
 * Uses "hiri-hmac-v1.1" HKDF label for domain separation from Mode 2 CEK.
 *
 * @param hmacKey - 32-byte HMAC key to distribute
 * @param recipientPublicKeys - Map of recipientId → X25519 public key
 * @param disclosureMap - Map of recipientId → disclosed statement indices (or "all")
 * @param iv - Optional 12-byte IV (generated if not provided)
 */
export async function encryptHmacKeyForRecipients(
  hmacKey: Uint8Array,
  recipientPublicKeys: Map<string, Uint8Array>,
  disclosureMap: Map<string, number[] | "all">,
  iv?: Uint8Array,
): Promise<HmacKeyDistributionResult> {
  const actualIv = iv ?? globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ephemeral = generateX25519Keypair();

  const recipients: HmacKeyDistributionResult["recipients"] = [];
  for (const [recipientId, recipientPubKey] of recipientPublicKeys) {
    const encryptedHmacKey = await encryptKeyForRecipient({
      ephemeralPrivateKey: ephemeral.privateKey,
      recipientPublicKeyX25519: recipientPubKey,
      iv: actualIv,
      secretKey: hmacKey,
      recipientId,
      hkdfLabel: "hiri-hmac-v1.1",
    });
    recipients.push({
      id: recipientId,
      encryptedHmacKey,
      disclosedStatements: disclosureMap.get(recipientId) ?? "all",
    });
  }

  ephemeral.privateKey.fill(0);

  return {
    ephemeralPublicKey: ephemeral.publicKey,
    iv: actualIv,
    recipients,
  };
}

/**
 * Decrypt the HMAC key as a recipient.
 *
 * Uses "hiri-hmac-v1.1" HKDF label for domain separation.
 *
 * @param encryptedHmacKey - Encrypted HMAC key bytes
 * @param ephemeralPublicKey - Publisher's ephemeral X25519 public key
 * @param iv - 12-byte IV
 * @param ownPrivateKey - Recipient's X25519 private key
 * @param ownRecipientId - Recipient's identifier
 */
export async function decryptHmacKey(
  encryptedHmacKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  iv: Uint8Array,
  ownPrivateKey: Uint8Array,
  ownRecipientId: string,
): Promise<Uint8Array> {
  return decryptKeyFromSender({
    ownPrivateKeyX25519: ownPrivateKey,
    ephemeralPublicKey,
    iv,
    encryptedKey: encryptedHmacKey,
    recipientId: ownRecipientId,
    hkdfLabel: "hiri-hmac-v1.1",
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
