/**
 * Key Lifecycle Verification — Milestone 5
 *
 * Implements key lifecycle awareness for manifest signature verification.
 * These are NEW functions that wrap the existing bare-key verifyManifest()
 * from signing.ts (ADR-007: wrap, don't modify).
 *
 * Core algorithm (v1.4 spec, Key Resolution Algorithm):
 * 1. Extract keyId from manifest signature verificationMethod
 * 2. Search activeKeys → "active"
 * 3. Search rotatedKeys → check grace period
 * 4. Search revokedKeys → check retroactive invalidation
 * 5. Not found → "unknown"
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { stableStringify } from "./canonicalize.js";
import { decode as base58Decode } from "./base58.js";
import { verifyManifest } from "./signing.js";
import { addDuration, compareTimestamps } from "./temporal.js";
import type {
  CryptoProvider,
  KeyDocument,
  ResolutionManifest,
  KeyStatus,
  KeyVerificationResult,
  VerificationKey,
  RotatedKey,
  RevokedKey,
  RotationClaim,
} from "./types.js";

/**
 * Determine the key status for a manifest's signing key.
 *
 * Implements the 5-step key resolution algorithm from the v1.4 spec.
 * Does NOT verify the cryptographic signature — only determines whether
 * the key was authorized to sign at the relevant timestamps.
 *
 * @param manifest - The signed manifest to check
 * @param keyDocument - The full-lifecycle KeyDocument
 * @param verificationTime - Injected clock (ISO 8601) for grace period checks
 * @returns Key verification result (valid/invalid + status + warning)
 */
export function resolveSigningKey(
  manifest: ResolutionManifest,
  keyDocument: KeyDocument,
  verificationTime: string,
): KeyVerificationResult {
  // Step 1: Extract keyId from verificationMethod
  const sig = manifest["hiri:signature"];
  if (!sig) {
    return { valid: false, keyStatus: "unknown", keyId: "" };
  }
  const keyId = extractKeyId(sig.verificationMethod);

  // Step 2: Search activeKeys
  const activeKey = findKeyById(keyDocument["hiri:activeKeys"], keyId);
  if (activeKey) {
    return { valid: true, keyStatus: "active", keyId };
  }

  // Step 3: Search rotatedKeys — check grace period
  const rotatedKey = findRotatedKeyById(keyDocument["hiri:rotatedKeys"], keyId);
  if (rotatedKey) {
    const gracePeriod = keyDocument["hiri:policies"].gracePeriodAfterRotation;
    const computedGraceExpiry = addDuration(rotatedKey.rotatedAt, gracePeriod);

    // Use the stricter (earlier) of verifyUntil and computed grace expiry
    const effectiveExpiry =
      compareTimestamps(rotatedKey.verifyUntil, computedGraceExpiry) <= 0
        ? rotatedKey.verifyUntil
        : computedGraceExpiry;

    if (compareTimestamps(verificationTime, effectiveExpiry) <= 0) {
      return {
        valid: true,
        keyStatus: "rotated-grace",
        keyId,
        warning: "Signed by rotated key within grace period",
      };
    }

    return { valid: false, keyStatus: "rotated-expired", keyId };
  }

  // Step 4: Search revokedKeys — check retroactive invalidation
  const revokedKey = findRevokedKeyById(keyDocument["hiri:revokedKeys"], keyId);
  if (revokedKey) {
    const manifestCreated = manifest["hiri:timing"].created;

    // If manifest was signed BEFORE the invalidation point, it's still valid
    if (compareTimestamps(manifestCreated, revokedKey.manifestsInvalidAfter) < 0) {
      return {
        valid: true,
        keyStatus: "revoked",
        keyId,
        warning: "Key subsequently revoked but signature predates invalidation point",
      };
    }

    // Signed after invalidation point — retroactively invalid
    return { valid: false, keyStatus: "revoked", keyId };
  }

  // Step 5: Key not found in any list
  return { valid: false, keyStatus: "unknown", keyId };
}

/**
 * Verify a manifest's signature with full key lifecycle awareness.
 *
 * Wraps M1's verifyManifest() with temporal key status checks.
 * First determines key authorization (resolveSigningKey), then
 * if authorized, performs the cryptographic signature check.
 *
 * @param manifest - The signed manifest to verify
 * @param keyDocument - The full-lifecycle KeyDocument
 * @param verificationTime - Injected clock for grace period checks
 * @param crypto - Injected crypto provider
 * @returns Key verification result with full status details
 */
export async function verifyManifestWithKeyLifecycle(
  manifest: ResolutionManifest,
  keyDocument: KeyDocument,
  verificationTime: string,
  crypto: CryptoProvider,
): Promise<KeyVerificationResult> {
  // Step 1: Resolve key status
  const keyResult = resolveSigningKey(manifest, keyDocument, verificationTime);

  // If key is not authorized, return immediately (no crypto needed)
  if (!keyResult.valid) {
    return keyResult;
  }

  // Step 2: Extract public key material from the appropriate list
  const publicKeyBytes = extractPublicKeyBytes(keyResult.keyId, keyDocument);
  if (!publicKeyBytes) {
    return {
      valid: false,
      keyStatus: keyResult.keyStatus,
      keyId: keyResult.keyId,
      warning: `Public key material not found for ${keyResult.keyId}`,
    };
  }

  // Step 3: Cryptographic signature verification
  const sigValid = await verifyManifest(manifest, publicKeyBytes, crypto);
  if (!sigValid) {
    return {
      valid: false,
      keyStatus: keyResult.keyStatus,
      keyId: keyResult.keyId,
      warning: "Signature cryptographically invalid",
    };
  }

  // Both key authorization and signature are valid
  return keyResult;
}

/**
 * Verify a dual-signature rotation proof.
 *
 * Rotation entries must be authorized by both the old key and the new key.
 * The signing target is a RotationClaim (canonical JSON), which breaks
 * the circularity (signatures are not in the signed payload).
 *
 * @param rotatedKey - The rotated key entry with rotationProof
 * @param keyDocument - The KeyDocument containing both old and new keys
 * @param crypto - Injected crypto provider
 * @returns true if both signatures verify
 */
export async function verifyRotationProof(
  rotatedKey: RotatedKey,
  keyDocument: KeyDocument,
  crypto: CryptoProvider,
): Promise<boolean> {
  const proof = rotatedKey.rotationProof;
  if (!proof || proof.length !== 2) {
    return false;
  }

  // Find the two expected purposes
  const oldKeyProof = proof.find(p => p.purpose === "old-key-authorizes-rotation");
  const newKeyProof = proof.find(p => p.purpose === "new-key-confirms-rotation");
  if (!oldKeyProof || !newKeyProof) {
    return false;
  }

  // Reconstruct the RotationClaim — the canonical fact being attested
  const claim: RotationClaim = {
    oldKeyId: rotatedKey["@id"],
    newKeyId: rotatedKey.rotatedTo,
    rotatedAt: rotatedKey.rotatedAt,
    reason: rotatedKey.reason,
  };

  const claimBytes = new TextEncoder().encode(stableStringify(claim, false));

  // Verify old key signature
  const oldKeyBytes = decodeMultibase(rotatedKey.publicKeyMultibase);
  const oldSigBytes = decodeMultibase(oldKeyProof.proofValue);
  const oldValid = await crypto.verify(claimBytes, oldSigBytes, oldKeyBytes);
  if (!oldValid) return false;

  // Verify new key signature — find the new key in activeKeys
  const newKeyId = extractKeyId(rotatedKey.rotatedTo);
  const newKey = findKeyById(keyDocument["hiri:activeKeys"], newKeyId);
  if (!newKey) return false;

  const newKeyBytes = decodeMultibase(newKey.publicKeyMultibase);
  const newSigBytes = decodeMultibase(newKeyProof.proofValue);
  return crypto.verify(claimBytes, newSigBytes, newKeyBytes);
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Extract key fragment ID from a verification method URI.
 * e.g., "hiri://key:ed25519:abc/key/main#key-2" → "key-2"
 */
function extractKeyId(verificationMethod: string): string {
  const hashIdx = verificationMethod.lastIndexOf("#");
  if (hashIdx === -1) return verificationMethod;
  return verificationMethod.substring(hashIdx + 1);
}

/**
 * Find a verification key by its fragment ID in an array.
 */
function findKeyById(
  keys: VerificationKey[],
  keyId: string,
): VerificationKey | undefined {
  return keys.find(k => k["@id"].endsWith(`#${keyId}`));
}

/**
 * Find a rotated key by its fragment ID.
 */
function findRotatedKeyById(
  keys: RotatedKey[],
  keyId: string,
): RotatedKey | undefined {
  return keys.find(k => k["@id"].endsWith(`#${keyId}`));
}

/**
 * Find a revoked key by its fragment ID.
 */
function findRevokedKeyById(
  keys: RevokedKey[],
  keyId: string,
): RevokedKey | undefined {
  return keys.find(k => k["@id"].endsWith(`#${keyId}`));
}

/**
 * Extract the raw public key bytes from a KeyDocument for a given key ID.
 * Searches activeKeys, rotatedKeys, and revokedKeys.
 */
function extractPublicKeyBytes(
  keyId: string,
  keyDocument: KeyDocument,
): Uint8Array | null {
  // Check activeKeys
  const activeKey = findKeyById(keyDocument["hiri:activeKeys"], keyId);
  if (activeKey) {
    return decodeMultibase(activeKey.publicKeyMultibase);
  }

  // Check rotatedKeys
  const rotatedKey = findRotatedKeyById(keyDocument["hiri:rotatedKeys"], keyId);
  if (rotatedKey) {
    return decodeMultibase(rotatedKey.publicKeyMultibase);
  }

  // Check revokedKeys
  const revokedKey = findRevokedKeyById(keyDocument["hiri:revokedKeys"], keyId);
  if (revokedKey) {
    return decodeMultibase(revokedKey.publicKeyMultibase);
  }

  return null;
}

/**
 * Decode a multibase-encoded value (z prefix + base58).
 */
function decodeMultibase(multibase: string): Uint8Array {
  const raw = multibase.startsWith("z") ? multibase.substring(1) : multibase;
  return base58Decode(raw);
}
