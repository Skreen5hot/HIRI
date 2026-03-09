/**
 * Privacy-Aware Resolution Dispatcher — Milestones 10, 12, 13, 14, 15
 *
 * Wraps the kernel resolver with privacy mode awareness.
 * Dispatches to mode-specific handlers:
 * - public → delegates to kernel resolve() (full content verification)
 * - proof-of-possession → signature + chain, skip content fetch
 * - encrypted → fetch ciphertext, verify hash, optionally decrypt (M12)
 * - selective-disclosure → verify index, optionally verify HMAC tags (M13)
 * - anonymous → identity wrapper, dispatches on contentVisibility (M14)
 * - attestation → dual-signature verification (M14)
 *
 * This module is Layer 2 (Privacy) and MAY import from Layer 0 and Layer 1.
 */

import { resolve as kernelResolve } from "../kernel/resolve.js";
import type { ResolveOptions } from "../kernel/resolve.js";
import type { StorageAdapter, ResolutionManifest } from "../kernel/types.js";
import { verifyManifest } from "../kernel/signing.js";
import { deriveAuthority } from "../kernel/authority.js";
import { verifyChain } from "../kernel/chain.js";
import { getPrivacyMode } from "./privacy-mode.js";
import { isKnownPrivacyMode } from "./privacy-mode.js";
import { isCustodyStale } from "./proof-of-possession.js";
import type {
  PrivacyAwareVerificationResult,
  EncryptedPrivacyParams,
  SelectiveDisclosureParams,
  SelectiveDisclosureContent,
  AnonymousParams,
} from "./types.js";
import { decryptContent } from "./decryption.js";
import { verifyStatementInIndex, verifyIndexRoot } from "./statement-index.js";
import { verifyHmacTag, decryptHmacKey } from "./hmac-disclosure.js";
import { verifyAttestation, validateAttestationManifest } from "./attestation.js";
import type { SignedAttestationManifest } from "./attestation.js";

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

export interface PrivacyResolveOptions extends ResolveOptions {
  /** Injected clock for staleness checks. Defaults to manifest created time. */
  verificationTime?: string;
  /** X25519 private key for decryption (Mode 2). If absent, ciphertext-only verification. */
  decryptionKey?: Uint8Array;
  /** Recipient identifier for decryption key lookup. Required if decryptionKey is provided. */
  recipientId?: string;
  /** Subject authority's public key for attestation dual-signature verification (Mode 5). */
  subjectPublicKey?: Uint8Array;
  /** Attestor key status from KeyDocument resolution (Mode 5). Defaults to "active". */
  attestorKeyStatus?: string;
  /** Timestamp when the KeyDocument was last fetched (ISO 8601). For staleness detection. */
  keyDocumentTimestamp?: string;
  /** Maximum age of cached KeyDocument in milliseconds. If exceeded, emit staleness warning. */
  keyDocumentMaxAge?: number;
}

/**
 * Privacy-aware resolution.
 *
 * Parses the manifest's privacy mode and dispatches accordingly.
 * For public manifests, delegates entirely to the kernel resolver.
 */
export async function resolveWithPrivacy(
  uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
): Promise<PrivacyAwareVerificationResult> {
  // First, we need to fetch and parse the manifest to determine privacy mode.
  // We do a lightweight fetch here, then dispatch.
  const manifest = await fetchAndParseManifest(uri, storage, options);
  const mode = getPrivacyMode(manifest);

  // KeyDocument staleness check (§13.1)
  const keyDocWarnings = checkKeyDocumentStaleness(options);

  const result = await dispatchMode(uri, storage, options, manifest, mode);

  // Append KeyDocument staleness warning if applicable
  if (keyDocWarnings.length > 0) {
    result.warnings.push(...keyDocWarnings);
  }

  return result;
}

/** @internal Dispatch on privacy mode. */
async function dispatchMode(
  uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  manifest: ResolutionManifest,
  mode: string,
): Promise<PrivacyAwareVerificationResult> {
  switch (mode) {
    case "public":
      return resolvePublic(uri, storage, options, manifest);

    case "proof-of-possession":
      return resolveProofOfPossession(uri, storage, options, manifest);

    case "encrypted":
      return resolveEncrypted(uri, storage, options, manifest);

    case "selective-disclosure":
      return resolveSelectiveDisclosure(uri, storage, options, manifest);

    case "anonymous":
      return resolveAnonymous(uri, storage, options, manifest);

    case "attestation":
      return resolveAttestation(uri, storage, options, manifest);

    default:
      // Unknown future mode: verify signature + chain, return unsupported-mode with warning
      return resolveUnsupportedMode(uri, storage, options, manifest, mode);
  }
}

// ---------------------------------------------------------------------------
// Internal: Manifest Fetch (lightweight, no content fetch)
// ---------------------------------------------------------------------------

async function fetchAndParseManifest(
  uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
): Promise<ResolutionManifest> {
  const manifestBytes = await storage.get(options.manifestHash);
  if (!manifestBytes) {
    throw new Error(`Manifest not found in storage: ${options.manifestHash}`);
  }

  // Verify manifest hash integrity
  const computedHash = await options.crypto.hash(manifestBytes);
  if (computedHash !== options.manifestHash) {
    throw new Error(
      `Manifest hash mismatch: expected "${options.manifestHash}", computed "${computedHash}"`,
    );
  }

  return JSON.parse(
    new TextDecoder().decode(manifestBytes),
  ) as ResolutionManifest;
}

// ---------------------------------------------------------------------------
// Mode: Public — full kernel delegation
// ---------------------------------------------------------------------------

async function resolvePublic(
  uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  _manifest: ResolutionManifest,
): Promise<PrivacyAwareVerificationResult> {
  const result = await kernelResolve(uri, storage, options);

  return {
    verified: true,
    manifest: result.manifest,
    authority: result.authority,
    warnings: result.warnings ?? [],
    privacyMode: "public",
    contentStatus: "verified",
  };
}

// ---------------------------------------------------------------------------
// Mode: Proof of Possession — signature + chain, skip content
// ---------------------------------------------------------------------------

async function resolveProofOfPossession(
  uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  manifest: ResolutionManifest,
): Promise<PrivacyAwareVerificationResult> {
  const warnings: string[] = [];

  // Step 1: Verify signature via kernel (reuse the kernel's signature verification)
  const profile = manifest["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
  const sigValid = await verifyManifest(
    manifest,
    options.publicKey,
    profile,
    options.crypto,
    options.canonicalizer,
    options.documentLoader,
  );
  if (!sigValid) {
    return {
      verified: false,
      manifest,
      authority: "",
      warnings: ["Signature verification failed"],
      privacyMode: "proof-of-possession",
      contentStatus: "private-custody-asserted",
    };
  }

  // Step 2: Verify authority
  const authority = deriveAuthority(options.publicKey, "ed25519");

  // Step 3: Verify chain if present
  if (manifest["hiri:chain"]) {
    const chainResult = await verifyChain(
      manifest,
      options.publicKey,
      async (hash: string) => {
        const bytes = await storage.get(hash);
        if (!bytes) return null;
        const computed = await options.crypto.hash(bytes);
        if (computed !== hash) return null;
        return JSON.parse(new TextDecoder().decode(bytes)) as ResolutionManifest;
      },
      (hash: string) => storage.get(hash),
      options.crypto,
      options.canonicalizer,
      options.documentLoader,
      options.hashRegistry,
    );
    if (!chainResult.valid) {
      return {
        verified: false,
        manifest,
        authority,
        warnings: [`Chain verification failed: ${chainResult.reason}`],
        privacyMode: "proof-of-possession",
        contentStatus: "private-custody-asserted",
      };
    }
    if (chainResult.warnings.length > 0) {
      warnings.push(...chainResult.warnings);
    }
  }

  // Step 4: Extract PoP parameters and check staleness
  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
    | { parameters?: Record<string, unknown> }
    | undefined;
  const params = privacy?.parameters;
  const refreshPolicy = params?.refreshPolicy as string | undefined;
  const created = manifest["hiri:timing"].created;
  const verificationTime = options.verificationTime ?? created;

  const stale = isCustodyStale(created, refreshPolicy, verificationTime);
  if (stale) {
    warnings.push(
      `Custody assertion is stale: created ${created}, refreshPolicy ${refreshPolicy}, checked at ${verificationTime}`,
    );
  }

  // Step 5: DO NOT fetch content (§6.4)
  return {
    verified: true,
    manifest,
    authority,
    warnings,
    privacyMode: "proof-of-possession",
    contentStatus: "private-custody-asserted",
  };
}

// ---------------------------------------------------------------------------
// Mode: Encrypted — ciphertext verification, optional decryption (M12)
// ---------------------------------------------------------------------------

async function resolveEncrypted(
  _uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  manifest: ResolutionManifest,
): Promise<PrivacyAwareVerificationResult> {
  const warnings: string[] = [];

  // Step 1: Verify signature
  const profile = manifest["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
  const sigValid = await verifyManifest(
    manifest,
    options.publicKey,
    profile,
    options.crypto,
    options.canonicalizer,
    options.documentLoader,
  );
  if (!sigValid) {
    return {
      verified: false,
      manifest,
      authority: "",
      warnings: ["Signature verification failed"],
      privacyMode: "encrypted",
      contentStatus: "ciphertext-verified",
    };
  }

  // Step 2: Derive authority
  const authority = deriveAuthority(options.publicKey, "ed25519");

  // Step 3: Verify chain if present
  if (manifest["hiri:chain"]) {
    const chainResult = await verifyChain(
      manifest,
      options.publicKey,
      async (hash: string) => {
        const bytes = await storage.get(hash);
        if (!bytes) return null;
        const computed = await options.crypto.hash(bytes);
        if (computed !== hash) return null;
        return JSON.parse(new TextDecoder().decode(bytes)) as ResolutionManifest;
      },
      (hash: string) => storage.get(hash),
      options.crypto,
      options.canonicalizer,
      options.documentLoader,
      options.hashRegistry,
    );
    if (!chainResult.valid) {
      return {
        verified: false,
        manifest,
        authority,
        warnings: [`Chain verification failed: ${chainResult.reason}`],
        privacyMode: "encrypted",
        contentStatus: "ciphertext-verified",
      };
    }
    if (chainResult.warnings.length > 0) {
      warnings.push(...chainResult.warnings);
    }
  }

  // Step 4: Fetch ciphertext and verify ciphertext hash
  const contentHash = manifest["hiri:content"].hash;
  const ciphertextBytes = await storage.get(contentHash);
  if (!ciphertextBytes) {
    return {
      verified: false,
      manifest,
      authority,
      warnings: ["Encrypted content not found in storage"],
      privacyMode: "encrypted",
      contentStatus: "ciphertext-verified",
    };
  }

  const computedContentHash = await options.crypto.hash(ciphertextBytes);
  if (computedContentHash !== contentHash) {
    return {
      verified: false,
      manifest,
      authority,
      warnings: [`Ciphertext hash mismatch: expected "${contentHash}", computed "${computedContentHash}"`],
      privacyMode: "encrypted",
      contentStatus: "ciphertext-verified",
    };
  }

  // Step 5: If no decryption key provided, ciphertext-only verification
  if (!options.decryptionKey || !options.recipientId) {
    return {
      verified: true,
      manifest,
      authority,
      warnings,
      privacyMode: "encrypted",
      contentStatus: "ciphertext-verified",
    };
  }

  // Step 6: Attempt decryption
  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
    | { parameters?: Record<string, unknown> }
    | undefined;
  if (!privacy?.parameters) {
    return {
      verified: true,
      manifest,
      authority,
      warnings: [...warnings, "Missing privacy parameters for decryption"],
      privacyMode: "encrypted",
      contentStatus: "ciphertext-verified",
    };
  }

  const encParams = privacy.parameters as unknown as EncryptedPrivacyParams;

  try {
    const result = await decryptContent(
      ciphertextBytes,
      encParams,
      options.decryptionKey,
      options.recipientId,
      options.crypto,
    );

    if (!result.plaintextHashValid) {
      warnings.push("Plaintext hash mismatch after decryption");
    }

    return {
      verified: true,
      manifest,
      authority,
      warnings,
      privacyMode: "encrypted",
      contentStatus: "decrypted-verified",
      decryptedContent: result.plaintext,
    };
  } catch (err) {
    // Decryption failed (wrong key, wrong recipient, GCM auth failure)
    // Manifest itself is still verified — only content decryption failed
    return {
      verified: true,
      manifest,
      authority,
      warnings: [
        ...warnings,
        `Decryption failed: ${err instanceof Error ? err.message : String(err)}`,
      ],
      privacyMode: "encrypted",
      contentStatus: "decryption-failed",
    };
  }
}

// ---------------------------------------------------------------------------
// Mode: Selective Disclosure — index verification, optional HMAC (M13)
// ---------------------------------------------------------------------------

async function resolveSelectiveDisclosure(
  _uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  manifest: ResolutionManifest,
): Promise<PrivacyAwareVerificationResult> {
  const warnings: string[] = [];

  // Step 1: Verify signature
  const profile = manifest["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
  const sigValid = await verifyManifest(
    manifest,
    options.publicKey,
    profile,
    options.crypto,
    options.canonicalizer,
    options.documentLoader,
  );
  if (!sigValid) {
    return {
      verified: false,
      manifest,
      authority: "",
      warnings: ["Signature verification failed"],
      privacyMode: "selective-disclosure",
      contentStatus: "partial-disclosure",
    };
  }

  // Step 2: Derive authority
  const authority = deriveAuthority(options.publicKey, "ed25519");

  // Step 3: Verify chain if present
  if (manifest["hiri:chain"]) {
    const chainResult = await verifyChain(
      manifest,
      options.publicKey,
      async (hash: string) => {
        const bytes = await storage.get(hash);
        if (!bytes) return null;
        const computed = await options.crypto.hash(bytes);
        if (computed !== hash) return null;
        return JSON.parse(new TextDecoder().decode(bytes)) as ResolutionManifest;
      },
      (hash: string) => storage.get(hash),
      options.crypto,
      options.canonicalizer,
      options.documentLoader,
      options.hashRegistry,
    );
    if (!chainResult.valid) {
      return {
        verified: false,
        manifest,
        authority,
        warnings: [`Chain verification failed: ${chainResult.reason}`],
        privacyMode: "selective-disclosure",
        contentStatus: "partial-disclosure",
      };
    }
    if (chainResult.warnings.length > 0) {
      warnings.push(...chainResult.warnings);
    }
  }

  // Step 4: Fetch published SD content blob and verify hash
  const contentHash = manifest["hiri:content"].hash;
  const contentBytes = await storage.get(contentHash);
  if (!contentBytes) {
    return {
      verified: false,
      manifest,
      authority,
      warnings: ["Selective disclosure content not found in storage"],
      privacyMode: "selective-disclosure",
      contentStatus: "partial-disclosure",
    };
  }

  const computedContentHash = await options.crypto.hash(contentBytes);
  if (computedContentHash !== contentHash) {
    return {
      verified: false,
      manifest,
      authority,
      warnings: [`Content hash mismatch: expected "${contentHash}", computed "${computedContentHash}"`],
      privacyMode: "selective-disclosure",
      contentStatus: "partial-disclosure",
    };
  }

  // Step 5: Parse SD content blob
  const sdContent: SelectiveDisclosureContent = JSON.parse(
    new TextDecoder().decode(contentBytes),
  );

  // Step 6: Extract privacy parameters
  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
    | { parameters?: Record<string, unknown> }
    | undefined;
  if (!privacy?.parameters) {
    return {
      verified: true,
      manifest,
      authority,
      warnings: [...warnings, "Missing privacy parameters"],
      privacyMode: "selective-disclosure",
      contentStatus: "partial-disclosure",
    };
  }
  const sdParams = privacy.parameters as unknown as SelectiveDisclosureParams;

  // Step 7: Decode indexSalt and verify mandatory statements against index
  const indexSalt = base64urlDecode(sdParams.indexSalt);
  const statementHashes = sdContent.statementIndex.map((hex) => hexToBytes(hex));

  for (let mi = 0; mi < sdParams.mandatoryStatements.length; mi++) {
    const idx = sdParams.mandatoryStatements[mi];
    const stmt = sdContent.mandatoryNQuads[mi];
    if (!stmt) {
      warnings.push(`Mandatory statement at index ${idx} missing from content blob`);
      continue;
    }
    const valid = await verifyStatementInIndex(stmt, statementHashes[idx], indexSalt);
    if (!valid) {
      warnings.push(`Mandatory statement at index ${idx} failed salted hash verification`);
    }
  }

  // Step 8: Verify index root
  const rootValid = await verifyIndexRoot(statementHashes, sdParams.indexRoot);
  if (!rootValid) {
    warnings.push("Index root mismatch: published hashes do not match declared indexRoot");
  }

  // Step 9: If decryption key + recipientId provided, decrypt HMAC key and verify tags
  const disclosedNQuads: string[] = [...sdContent.mandatoryNQuads];
  const disclosedIndices: number[] = [...sdParams.mandatoryStatements];

  if (options.decryptionKey && options.recipientId) {
    const hmacRecipients = sdParams.hmacKeyRecipients;
    const recipientEntry = hmacRecipients.recipients.find(
      (r) => r.id === options.recipientId,
    );

    if (recipientEntry) {
      try {
        const hmacKey = await decryptHmacKey(
          hexToBytes(recipientEntry.encryptedHmacKey),
          hexToBytes(hmacRecipients.ephemeralPublicKey),
          hexToBytes(hmacRecipients.iv),
          options.decryptionKey,
          options.recipientId,
        );

        // Verify HMAC tags for disclosed statements
        const hmacTags = sdContent.hmacTags.map((hex) => hexToBytes(hex));
        const disclosed = recipientEntry.disclosedStatements === "all"
          ? Array.from({ length: sdParams.statementCount }, (_, i) => i)
          : recipientEntry.disclosedStatements;

        for (const idx of disclosed) {
          if (disclosedIndices.includes(idx)) continue; // Already verified as mandatory
          const tagValid = verifyHmacTag(
            sdContent.mandatoryNQuads[sdParams.mandatoryStatements.indexOf(idx)] ?? "",
            hmacKey,
            indexSalt,
            hmacTags[idx],
          );
          if (!tagValid) {
            warnings.push(`HMAC tag verification failed for statement index ${idx}`);
          }
        }

        hmacKey.fill(0);
      } catch (err) {
        warnings.push(
          `HMAC key decryption failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  }

  return {
    verified: true,
    manifest,
    authority,
    warnings,
    privacyMode: "selective-disclosure",
    contentStatus: "partial-disclosure",
    disclosedNQuads,
    disclosedStatementIndices: disclosedIndices,
  };
}

// ---------------------------------------------------------------------------
// Mode: Anonymous — identity wrapper, dispatches on contentVisibility (M14)
// ---------------------------------------------------------------------------

async function resolveAnonymous(
  uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  manifest: ResolutionManifest,
): Promise<PrivacyAwareVerificationResult> {
  // Extract anonymous parameters
  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
    | { parameters?: Record<string, unknown> }
    | undefined;
  const params = privacy?.parameters as AnonymousParams | undefined;
  const authorityType = params?.authorityType ?? "ephemeral";
  const contentVisibility = params?.contentVisibility ?? "public";

  // Determine identity type
  const identityType: "anonymous-ephemeral" | "pseudonymous" =
    authorityType === "ephemeral" ? "anonymous-ephemeral" : "pseudonymous";

  // Dispatch on contentVisibility to the appropriate content handler
  let baseResult: PrivacyAwareVerificationResult;

  switch (contentVisibility) {
    case "encrypted":
      baseResult = await resolveEncrypted(uri, storage, options, manifest);
      break;
    case "selective-disclosure":
      baseResult = await resolveSelectiveDisclosure(uri, storage, options, manifest);
      break;
    case "private":
      baseResult = await resolveProofOfPossession(uri, storage, options, manifest);
      break;
    case "public":
    default:
      baseResult = await resolvePublic(uri, storage, options, manifest);
      break;
  }

  // Override privacy mode and identity type on the result
  return {
    ...baseResult,
    privacyMode: "anonymous",
    identityType,
  };
}

// ---------------------------------------------------------------------------
// Mode: Attestation — dual-signature verification (M14)
// ---------------------------------------------------------------------------

async function resolveAttestation(
  _uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  manifest: ResolutionManifest,
): Promise<PrivacyAwareVerificationResult> {
  const warnings: string[] = [];

  // Step 1: Validate attestation manifest structure
  const validation = validateAttestationManifest(
    manifest as unknown as Record<string, unknown>,
  );
  if (!validation.valid) {
    return {
      verified: false,
      manifest,
      authority: "",
      warnings: [validation.reason ?? "Invalid attestation manifest"],
      privacyMode: "attestation",
      contentStatus: "attestation-verified",
    };
  }

  // Step 2: Derive attestor authority
  const authority = deriveAuthority(options.publicKey, "ed25519");

  // Step 3: Fetch subject manifest if referenced
  const attestation = manifest as unknown as SignedAttestationManifest;
  const subjectRef = attestation["hiri:attestation"].subject;
  let subjectManifest: ResolutionManifest | null = null;
  let subjectPublicKey: Uint8Array | null = null;

  if (subjectRef.manifestHash) {
    const subjectBytes = await storage.get(subjectRef.manifestHash);
    if (subjectBytes) {
      const computed = await options.crypto.hash(subjectBytes);
      if (computed === subjectRef.manifestHash) {
        subjectManifest = JSON.parse(
          new TextDecoder().decode(subjectBytes),
        ) as ResolutionManifest;
        subjectPublicKey = options.subjectPublicKey ?? null;
      }
    }
  }

  // Step 4: Determine attestor key status
  const attestorKeyStatus = options.attestorKeyStatus ?? "active";

  // Step 5: Verify attestation (dual-signature)
  const result = await verifyAttestation(
    attestation,
    options.publicKey,
    subjectManifest,
    subjectPublicKey,
    options.crypto,
    attestorKeyStatus,
    options.verificationTime,
  );

  warnings.push(...result.warnings);

  return {
    verified: result.attestationVerified,
    manifest,
    authority,
    warnings,
    privacyMode: "attestation",
    contentStatus: "attestation-verified",
    attestationResult: result,
  };
}

// ---------------------------------------------------------------------------
// Stub: Unsupported/Future Modes — verify sig + chain, report unsupported
// ---------------------------------------------------------------------------

async function resolveUnsupportedMode(
  uri: string,
  storage: StorageAdapter,
  options: PrivacyResolveOptions,
  manifest: ResolutionManifest,
  mode: string,
): Promise<PrivacyAwareVerificationResult> {
  const warnings: string[] = [];

  // §4.4: MUST verify signature
  const profile = manifest["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
  const sigValid = await verifyManifest(
    manifest,
    options.publicKey,
    profile,
    options.crypto,
    options.canonicalizer,
    options.documentLoader,
  );
  if (!sigValid) {
    return {
      verified: false,
      manifest,
      authority: "",
      warnings: ["Signature verification failed"],
      privacyMode: mode,
      contentStatus: "unsupported-mode",
    };
  }

  // §4.4: MUST verify chain integrity
  const authority = deriveAuthority(options.publicKey, "ed25519");

  if (manifest["hiri:chain"]) {
    const chainResult = await verifyChain(
      manifest,
      options.publicKey,
      async (hash: string) => {
        const bytes = await storage.get(hash);
        if (!bytes) return null;
        const computed = await options.crypto.hash(bytes);
        if (computed !== hash) return null;
        return JSON.parse(new TextDecoder().decode(bytes)) as ResolutionManifest;
      },
      (hash: string) => storage.get(hash),
      options.crypto,
      options.canonicalizer,
      options.documentLoader,
      options.hashRegistry,
    );
    if (!chainResult.valid) {
      return {
        verified: false,
        manifest,
        authority,
        warnings: [`Chain verification failed: ${chainResult.reason}`],
        privacyMode: mode,
        contentStatus: "unsupported-mode",
      };
    }
    if (chainResult.warnings.length > 0) {
      warnings.push(...chainResult.warnings);
    }
  }

  // Report unsupported mode (§4.4: MUST NOT reject, MUST report)
  if (!isKnownPrivacyMode(mode)) {
    warnings.push(`Unknown privacy mode "${mode}": content cannot be verified`);
  } else {
    warnings.push(`Privacy mode "${mode}" is not yet implemented: content cannot be verified`);
  }

  return {
    verified: true,
    manifest,
    authority,
    warnings,
    privacyMode: mode,
    contentStatus: "unsupported-mode",
  };
}

// ---------------------------------------------------------------------------
// KeyDocument Staleness Check (§13.1)
// ---------------------------------------------------------------------------

function checkKeyDocumentStaleness(options: PrivacyResolveOptions): string[] {
  if (!options.keyDocumentTimestamp || !options.keyDocumentMaxAge) {
    return [];
  }

  const fetchedAt = new Date(options.keyDocumentTimestamp).getTime();
  const now = options.verificationTime
    ? new Date(options.verificationTime).getTime()
    : Date.now();
  const age = now - fetchedAt;

  if (age > options.keyDocumentMaxAge) {
    return [
      `keyDocumentStale: true — KeyDocument fetched at ${options.keyDocumentTimestamp} exceeds max age of ${options.keyDocumentMaxAge}ms`,
    ];
  }

  return [];
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

function base64urlDecode(str: string): Uint8Array {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
