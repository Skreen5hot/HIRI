/**
 * The Abstracted Resolver — Milestone 3 Deliverable
 *
 * resolve(uri, storage, options) → VerifiedContent
 *
 * Proves that the storage mechanism is irrelevant to the protocol:
 * produces byte-identical output against any StorageAdapter implementation.
 *
 * Resolution pipeline:
 * 1. Parse URI → { authority, type, identifier }
 * 2. Verify authority matches public key
 * 3. Fetch and verify manifest bytes from storage
 * 4. Deserialize manifest
 * 5. Verify manifest @id matches URI
 * 6. Verify manifest signature
 * 7. If chained: walk chain from head to genesis
 * 8. Fetch and verify content bytes
 * 9. Return verified content
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs. All I/O is via injected StorageAdapter.
 */

import { HiriURI } from "./hiri-uri.js";
import { deriveAuthority } from "./authority.js";
import { verifyManifest } from "./signing.js";
import { verifyChain, verifyChainWithKeyLifecycle } from "./chain.js";
import { verifyManifestWithKeyLifecycle } from "./key-lifecycle.js";
import type {
  Canonicalizer,
  DocumentLoader,
  CryptoProvider,
  StorageAdapter,
  ResolutionManifest,
  KeyDocument,
  KeyVerificationResult,
  ManifestFetcher,
  ContentFetcher,
} from "./types.js";

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface ResolveOptions {
  crypto: CryptoProvider;
  publicKey: Uint8Array;
  manifestHash: string;
  keyDocument?: KeyDocument;     // Enables lifecycle-aware verification (M5)
  verificationTime?: string;     // Injected mock clock for grace period checks (M5)
  canonicalizer?: Canonicalizer; // Injected canonicalizer for URDNA2015 (M7)
  documentLoader?: DocumentLoader; // Injected document loader for URDNA2015 (M7)
}

export interface VerifiedContent {
  content: Uint8Array;
  manifest: ResolutionManifest;
  authority: string;
  contentHash: string;
  warnings?: string[];                    // Key lifecycle warnings (M5)
  keyVerification?: KeyVerificationResult; // Detailed key status (M5)
}

export type ResolutionErrorCode =
  | "PARSE_ERROR"
  | "AUTHORITY_NOT_FOUND"
  | "MANIFEST_NOT_FOUND"
  | "CONTENT_NOT_FOUND"
  | "SIGNATURE_VERIFICATION_FAILED"
  | "CHAIN_VERIFICATION_FAILED"
  | "STORAGE_CORRUPTION"
  | "IDENTITY_MISMATCH"
  | "KEY_REVOKED"
  | "KEY_EXPIRED"
  | "KEY_UNKNOWN";

export class ResolutionError extends Error {
  constructor(
    public readonly code: ResolutionErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ResolutionError";
  }
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

export async function resolve(
  uri: string,
  storage: StorageAdapter,
  options: ResolveOptions,
): Promise<VerifiedContent> {
  const { crypto, publicKey, manifestHash } = options;

  // Step 1: Parse URI
  let parsed: HiriURI;
  try {
    parsed = HiriURI.parse(uri);
  } catch {
    throw new ResolutionError("PARSE_ERROR", `Malformed URI: ${uri}`);
  }

  // Step 2: Verify authority matches public key (v3.1.1: sync, no hashing)
  const derivedAuthority = deriveAuthority(publicKey, "ed25519");
  if (derivedAuthority !== parsed.authority) {
    throw new ResolutionError(
      "AUTHORITY_NOT_FOUND",
      `Authority mismatch: URI has "${parsed.authority}", public key derives "${derivedAuthority}"`,
    );
  }

  // Step 3: Fetch manifest bytes from storage
  const manifestBytes = await storage.get(manifestHash);
  if (!manifestBytes) {
    throw new ResolutionError(
      "MANIFEST_NOT_FOUND",
      `Manifest not found in storage: ${manifestHash}`,
    );
  }

  // Step 4: Verify manifest hash integrity
  const computedManifestHash = await crypto.hash(manifestBytes);
  if (computedManifestHash !== manifestHash) {
    throw new ResolutionError(
      "STORAGE_CORRUPTION",
      `Manifest hash mismatch: expected "${manifestHash}", computed "${computedManifestHash}"`,
    );
  }

  // Step 5: Deserialize manifest
  const manifest = JSON.parse(
    new TextDecoder().decode(manifestBytes),
  ) as ResolutionManifest;

  // Step 6: Verify manifest @id matches URI
  if (manifest["@id"] !== uri) {
    throw new ResolutionError(
      "IDENTITY_MISMATCH",
      `Manifest @id "${manifest["@id"]}" does not match requested URI "${uri}"`,
    );
  }

  // Step 7: Verify manifest signature
  // Fork: lifecycle-aware verification when keyDocument is provided (M5)
  const { keyDocument, verificationTime } = options;
  let lifecycleWarnings: string[] | undefined;
  let keyVerification: KeyVerificationResult | undefined;

  if (keyDocument && verificationTime) {
    const keyResult = await verifyManifestWithKeyLifecycle(
      manifest,
      keyDocument,
      verificationTime,
      crypto,
    );

    keyVerification = keyResult;

    if (!keyResult.valid) {
      const errorCode: ResolutionErrorCode =
        keyResult.keyStatus === "revoked" ? "KEY_REVOKED" :
        keyResult.keyStatus === "rotated-expired" ? "KEY_EXPIRED" :
        keyResult.keyStatus === "unknown" ? "KEY_UNKNOWN" :
        "SIGNATURE_VERIFICATION_FAILED";

      throw new ResolutionError(
        errorCode,
        `Key lifecycle verification failed: ${keyResult.keyStatus} (key: ${keyResult.keyId})`,
      );
    }

    if (keyResult.warning) {
      lifecycleWarnings = [keyResult.warning];
    }
  } else {
    // M1–M4 path: bare public key verification
    const profile = manifest["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
    const sigValid = await verifyManifest(manifest, publicKey, profile, crypto, options.canonicalizer, options.documentLoader);
    if (!sigValid) {
      throw new ResolutionError(
        "SIGNATURE_VERIFICATION_FAILED",
        `Manifest signature verification failed`,
      );
    }
  }

  // Step 8: If chained, walk chain from head to genesis
  if (manifest["hiri:chain"]) {
    const fetchManifestFn = manifestFetcherFromStorage(storage, crypto);
    const fetchContentFn = contentFetcherFromStorage(storage);

    if (keyDocument && verificationTime) {
      // M5 path: lifecycle-aware chain walk (no short-circuit)
      const chainResult = await verifyChainWithKeyLifecycle(
        manifest,
        keyDocument,
        verificationTime,
        fetchManifestFn,
        fetchContentFn,
        crypto,
        options.canonicalizer,
        options.documentLoader,
      );

      if (chainResult.warnings.length > 0) {
        lifecycleWarnings = [...(lifecycleWarnings ?? []), ...chainResult.warnings];
      }

      if (!chainResult.valid) {
        throw new ResolutionError(
          "CHAIN_VERIFICATION_FAILED",
          `Chain verification failed: ${chainResult.reason}`,
        );
      }
    } else {
      // M1–M4 path: bare-key chain walk
      const chainResult = await verifyChain(
        manifest,
        publicKey,
        fetchManifestFn,
        fetchContentFn,
        crypto,
        options.canonicalizer,
        options.documentLoader,
      );

      if (!chainResult.valid) {
        throw new ResolutionError(
          "CHAIN_VERIFICATION_FAILED",
          `Chain verification failed: ${chainResult.reason}`,
        );
      }
    }
  }

  // Step 9: Fetch content bytes
  const contentHash = manifest["hiri:content"].hash;
  const contentBytes = await storage.get(contentHash);
  if (!contentBytes) {
    throw new ResolutionError(
      "CONTENT_NOT_FOUND",
      `Content not found in storage: ${contentHash}`,
    );
  }

  // Step 10: Verify content hash
  const computedContentHash = await crypto.hash(contentBytes);
  if (computedContentHash !== contentHash) {
    throw new ResolutionError(
      "STORAGE_CORRUPTION",
      `Content hash mismatch: expected "${contentHash}", computed "${computedContentHash}"`,
    );
  }

  return {
    content: contentBytes,
    manifest,
    authority: derivedAuthority,
    contentHash,
    ...(lifecycleWarnings && lifecycleWarnings.length > 0 ? { warnings: lifecycleWarnings } : {}),
    ...(keyVerification ? { keyVerification } : {}),
  };
}

// ---------------------------------------------------------------------------
// Bridge Functions (internal)
// ---------------------------------------------------------------------------

/**
 * Build a ManifestFetcher from a StorageAdapter.
 *
 * This is NOT a trivial wrapper. It handles:
 * 1. Fetching raw bytes from storage
 * 2. Verifying hash integrity (trust nothing)
 * 3. Deserializing JSON → ResolutionManifest
 */
function manifestFetcherFromStorage(
  storage: StorageAdapter,
  crypto: CryptoProvider,
): ManifestFetcher {
  return async (hash: string): Promise<ResolutionManifest | null> => {
    const bytes = await storage.get(hash);
    if (!bytes) return null;

    // Verify hash integrity
    const computedHash = await crypto.hash(bytes);
    if (computedHash !== hash) return null;

    // Deserialize
    return JSON.parse(
      new TextDecoder().decode(bytes),
    ) as ResolutionManifest;
  };
}

/**
 * Build a ContentFetcher from a StorageAdapter.
 *
 * Passthrough: StorageAdapter.get() returns Uint8Array,
 * ContentFetcher expects Uint8Array. Callers already verify hashes.
 */
function contentFetcherFromStorage(storage: StorageAdapter): ContentFetcher {
  return (hash: string) => storage.get(hash);
}
