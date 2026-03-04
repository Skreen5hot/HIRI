/**
 * Manifest Signing and Verification
 *
 * Signs and verifies ResolutionManifests and KeyDocuments using
 * injected CryptoProvider. The signing target is the manifest
 * WITHOUT the hiri:signature field, serialized via JCS (stableStringify).
 *
 * Sign:   manifest_bytes = canonicalize(manifest - signature) → sign(bytes, key) → signature
 * Verify: manifest_bytes = canonicalize(manifest - signature) → verify(bytes, sig, pubKey) → boolean
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { stableStringify } from "./canonicalize.js";
import { encode as base58Encode, decode as base58Decode } from "./base58.js";
import type {
  CryptoProvider,
  SigningKey,
  HiriSignature,
  UnsignedManifest,
  ResolutionManifest,
  UnsignedKeyDocument,
  KeyDocument,
} from "./types.js";

/**
 * Sign a ResolutionManifest.
 *
 * @param unsigned - The manifest without a signature
 * @param key - The signing key
 * @param timestamp - ISO 8601 timestamp (per ADR-003: caller provides)
 * @param crypto - Injected crypto provider
 * @returns The manifest with hiri:signature attached
 */
export async function signManifest(
  unsigned: UnsignedManifest,
  key: SigningKey,
  timestamp: string,
  crypto: CryptoProvider,
): Promise<ResolutionManifest> {
  const signature = await createSignature(unsigned, key, timestamp, "assertionMethod", crypto);
  return {
    ...unsigned,
    "hiri:signature": signature,
  };
}

/**
 * Sign a KeyDocument.
 *
 * @param unsigned - The KeyDocument without a signature
 * @param key - The signing key
 * @param timestamp - ISO 8601 timestamp (per ADR-003: caller provides)
 * @param crypto - Injected crypto provider
 * @returns The KeyDocument with hiri:signature attached
 */
export async function signKeyDocument(
  unsigned: UnsignedKeyDocument,
  key: SigningKey,
  timestamp: string,
  crypto: CryptoProvider,
): Promise<KeyDocument> {
  const signature = await createSignature(unsigned, key, timestamp, "assertionMethod", crypto);
  return {
    ...unsigned,
    "hiri:signature": signature,
  };
}

/**
 * Verify a signed manifest's signature against a public key.
 *
 * @param manifest - The signed manifest
 * @param publicKey - The public key bytes
 * @param crypto - Injected crypto provider
 * @returns true if the signature is valid
 */
export async function verifyManifest(
  manifest: ResolutionManifest,
  publicKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<boolean> {
  const signature = manifest["hiri:signature"];
  if (!signature) return false;

  // Reconstruct the unsigned manifest (remove hiri:signature)
  const unsigned = stripSignature(manifest);

  // Canonicalize and encode to bytes
  const canonical = stableStringify(unsigned, false);
  const bytes = new TextEncoder().encode(canonical);

  // Decode the base58 signature (strip 'z' multibase prefix)
  const proofValue = signature.proofValue;
  const sigBytes = base58Decode(proofValue.startsWith("z") ? proofValue.substring(1) : proofValue);

  return crypto.verify(bytes, sigBytes, publicKey);
}

/**
 * Verify a signed KeyDocument's signature against a public key.
 */
export async function verifyKeyDocument(
  doc: KeyDocument,
  publicKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<boolean> {
  const signature = doc["hiri:signature"];
  if (!signature) return false;

  const unsigned = stripSignature(doc);
  const canonical = stableStringify(unsigned, false);
  const bytes = new TextEncoder().encode(canonical);
  const sigBytes = base58Decode(
    signature.proofValue.startsWith("z")
      ? signature.proofValue.substring(1)
      : signature.proofValue,
  );

  return crypto.verify(bytes, sigBytes, publicKey);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Create a HiriSignature for a document.
 */
async function createSignature(
  document: Record<string, unknown>,
  key: SigningKey,
  timestamp: string,
  proofPurpose: string,
  crypto: CryptoProvider,
): Promise<HiriSignature> {
  // Serialize the document (without signature) to canonical bytes
  const canonical = stableStringify(document, false);
  const bytes = new TextEncoder().encode(canonical);

  // Sign
  const sigBytes = await crypto.sign(bytes, key.privateKey);

  // Encode: 'z' multibase prefix + base58
  const proofValue = "z" + base58Encode(sigBytes);

  // Build the verification method URI
  // Pattern: hiri://<authority>/key/main#<keyId>
  // The authority is embedded in the document's @id
  const docId = document["@id"] as string;
  const authority = extractAuthority(docId);
  const verificationMethod = `hiri://${authority}/key/main#${key.keyId}`;

  return {
    type: "Ed25519Signature2020",
    created: timestamp,
    verificationMethod,
    proofPurpose,
    proofValue,
  };
}

/**
 * Extract the authority from a HIRI URI string.
 * e.g., "hiri://key:ed25519:abc123/data/person-001" → "key:ed25519:abc123"
 */
function extractAuthority(uri: string): string {
  const withoutScheme = uri.replace("hiri://", "");
  const firstSlash = withoutScheme.indexOf("/");
  return firstSlash === -1 ? withoutScheme : withoutScheme.substring(0, firstSlash);
}

/**
 * Strip the hiri:signature field from a document, returning a clean copy.
 */
function stripSignature(doc: Record<string, unknown>): Record<string, unknown> {
  const copy = structuredClone(doc) as Record<string, unknown>;
  delete copy["hiri:signature"];
  return copy;
}
