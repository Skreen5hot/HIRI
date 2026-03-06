/**
 * Manifest Signing and Verification (v3.1.1)
 *
 * Signs and verifies ResolutionManifests and KeyDocuments using
 * injected CryptoProvider. The signing target is the manifest
 * WITHOUT the hiri:signature field, serialized via the declared profile.
 *
 * v3.1.1 changes:
 * - profile parameter ("JCS" | "URDNA2015") added to sign functions
 * - Profile Symmetry Rule: signature.canonicalization must match content.canonicalization
 * - canonicalization field added to HiriSignature
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { encode as base58Encode, decode as base58Decode } from "./base58.js";
import { JCSCanonicalizer } from "./jcs-canonicalizer.js";
import type {
  Canonicalizer,
  DocumentLoader,
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
 * Enforces Profile Symmetry Rule: the declared profile must match
 * the content canonicalization field.
 */
export async function signManifest(
  unsigned: UnsignedManifest,
  key: SigningKey,
  timestamp: string,
  profile: "JCS" | "URDNA2015",
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<ResolutionManifest> {
  // Profile Symmetry Rule: content.canonicalization must match signing profile
  if (unsigned["hiri:content"].canonicalization !== profile) {
    throw new Error(
      `Profile symmetry violation: content declares "${unsigned["hiri:content"].canonicalization}" but signing with "${profile}"`
    );
  }
  const canon = resolveCanonicalizer(profile, canonicalizer);
  const loader = documentLoader ?? defaultDocumentLoader;
  const signature = await createSignature(unsigned, key, timestamp, "assertionMethod", profile, crypto, canon, loader);
  return {
    ...unsigned,
    "hiri:signature": signature,
  };
}

/**
 * Sign a KeyDocument.
 */
export async function signKeyDocument(
  unsigned: UnsignedKeyDocument,
  key: SigningKey,
  timestamp: string,
  profile: "JCS" | "URDNA2015",
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<KeyDocument> {
  const canon = resolveCanonicalizer(profile, canonicalizer);
  const loader = documentLoader ?? defaultDocumentLoader;
  const signature = await createSignature(unsigned, key, timestamp, "assertionMethod", profile, crypto, canon, loader);
  return {
    ...unsigned,
    "hiri:signature": signature,
  };
}

/**
 * Verify a signed manifest's signature against a public key.
 *
 * Checks Profile Symmetry Rule before cryptographic verification:
 * signature.canonicalization must match content.canonicalization.
 *
 * The profile parameter is discovered from the manifest itself by the caller
 * (typically manifest["hiri:signature"].canonicalization).
 */
export async function verifyManifest(
  manifest: ResolutionManifest,
  publicKey: Uint8Array,
  profile: "JCS" | "URDNA2015",
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<boolean> {
  const signature = manifest["hiri:signature"];
  if (!signature) return false;

  // Profile Symmetry check
  if (signature.canonicalization !== manifest["hiri:content"].canonicalization) {
    return false;
  }
  if (signature.canonicalization !== profile) {
    return false;
  }

  const canon = resolveCanonicalizer(profile, canonicalizer);

  // Reconstruct the unsigned manifest (remove hiri:signature)
  const unsigned = stripSignature(manifest);

  // Canonicalize to bytes
  const loader = documentLoader ?? defaultDocumentLoader;
  const bytes = await canon.canonicalize(unsigned, loader);

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
  profile: "JCS" | "URDNA2015",
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<boolean> {
  const signature = doc["hiri:signature"];
  if (!signature) return false;

  if (signature.canonicalization !== profile) {
    return false;
  }

  const canon = resolveCanonicalizer(profile, canonicalizer);
  const unsigned = stripSignature(doc);
  const loader = documentLoader ?? defaultDocumentLoader;
  const bytes = await canon.canonicalize(unsigned, loader);
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
  profile: "JCS" | "URDNA2015",
  crypto: CryptoProvider,
  canonicalizer: Canonicalizer,
  documentLoader: DocumentLoader,
): Promise<HiriSignature> {
  // Canonicalize document to bytes using the injected canonicalizer
  const bytes = await canonicalizer.canonicalize(document, documentLoader);

  // Sign
  const sigBytes = await crypto.sign(bytes, key.privateKey);

  // Encode: 'z' multibase prefix + base58
  const proofValue = "z" + base58Encode(sigBytes);

  // Build the verification method URI
  const docId = document["@id"] as string;
  const authority = extractAuthority(docId);
  const verificationMethod = `hiri://${authority}/key/main#${key.keyId}`;

  return {
    type: "Ed25519Signature2020",
    canonicalization: profile,
    created: timestamp,
    verificationMethod,
    proofPurpose,
    proofValue,
  };
}

/**
 * Extract the authority from a HIRI URI string.
 */
function extractAuthority(uri: string): string {
  const withoutScheme = uri.replace("hiri://", "");
  const firstSlash = withoutScheme.indexOf("/");
  return firstSlash === -1 ? withoutScheme : withoutScheme.substring(0, firstSlash);
}

/** Default document loader (throws — JCS ignores it, URDNA2015 must provide its own). */
const defaultDocumentLoader: DocumentLoader = async (url) => {
  throw new Error("No document loader configured. URDNA2015 requires an explicit documentLoader. URL: " + url);
};

/**
 * Resolve canonicalizer: use provided, default to JCS, or throw if URDNA2015 without one.
 */
function resolveCanonicalizer(
  profile: "JCS" | "URDNA2015",
  canonicalizer?: Canonicalizer,
): Canonicalizer {
  if (canonicalizer) return canonicalizer;
  if (profile === "URDNA2015") {
    throw new Error("URDNA2015 profile requires an explicit Canonicalizer instance");
  }
  return new JCSCanonicalizer();
}

/**
 * Strip the hiri:signature field from a document, returning a clean copy.
 */
function stripSignature(doc: Record<string, unknown>): Record<string, unknown> {
  const copy = structuredClone(doc) as Record<string, unknown>;
  delete copy["hiri:signature"];
  return copy;
}
