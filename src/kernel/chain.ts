/**
 * Chain Validation and Walking
 *
 * Provides manifest hashing, chain link validation, and the chain walker
 * that recurses from head manifest to genesis, verifying integrity at
 * each step.
 *
 * The chain walker is the core Milestone 2 deliverable. It accepts
 * injected ManifestFetcher and ContentFetcher functions for I/O
 * (in-memory Maps in tests, StorageAdapter in M3).
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { stableStringify } from "./canonicalize.js";
import { JCSCanonicalizer } from "./jcs-canonicalizer.js";
import { parseVersion } from "./version.js";
import { verifyManifest } from "./signing.js";
import { verifyDelta } from "./delta.js";
import { verifyManifestWithKeyLifecycle } from "./key-lifecycle.js";
import type {
  Canonicalizer,
  DocumentLoader,
  CryptoProvider,
  ResolutionManifest,
  KeyDocument,
  JsonPatchOperation,
  ChainValidation,
  ChainWalkResult,
  ChainFailure,
  ManifestFetcher,
  ContentFetcher,
} from "./types.js";

/**
 * Hash a complete signed manifest.
 *
 * Canonicalizes the full manifest (including hiri:signature) via JCS,
 * encodes to UTF-8 bytes, and hashes via the injected CryptoProvider.
 *
 * The signature is intentionally included in the hash payload. This means
 * a re-signed manifest with a different key produces a different hash,
 * making the chain tamper-evident at the signature level, not just the
 * content level.
 */
export async function hashManifest(
  manifest: ResolutionManifest,
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<string> {
  const canon = canonicalizer ?? new JCSCanonicalizer();
  const loader: DocumentLoader = documentLoader ?? (async (url: string) => { throw new Error("No document loader: " + url); });
  const bytes = await canon.canonicalize(manifest as unknown as Record<string, unknown>, loader);
  return crypto.hash(bytes);
}

/**
 * Validate a single chain link between two manifests.
 *
 * This is a building block for the chain walker. It checks 6 rules:
 * 1. ID consistency
 * 2. Version monotonicity
 * 3. Previous hash correctness
 * 4. Genesis hash immutability
 * 5. Depth increment
 * 6. Branch consistency
 */
export async function validateChainLink(
  current: ResolutionManifest,
  previous: ResolutionManifest,
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<ChainValidation> {
  const chain = current["hiri:chain"];
  if (!chain) {
    return { valid: false, reason: "Current manifest has no chain field" };
  }

  // Rule 1: ID consistency
  if (current["@id"] !== previous["@id"]) {
    return {
      valid: false,
      reason: `ID mismatch: current="${current["@id"]}", previous="${previous["@id"]}"`,
    };
  }

  // Rule 2: Version monotonicity
  if (parseVersion(current["hiri:version"]) <= parseVersion(previous["hiri:version"])) {
    return {
      valid: false,
      reason: `Version not monotonically increasing: current=${current["hiri:version"]}, previous=${previous["hiri:version"]}`,
    };
  }

  // Rule 3: Previous hash
  const previousHash = await hashManifest(previous, crypto, canonicalizer, documentLoader);
  if (chain.previous !== previousHash) {
    return {
      valid: false,
      reason: `chain.previous hash mismatch: expected="${previousHash}", got="${chain.previous}"`,
    };
  }

  // Rule 4: Genesis hash immutability
  const previousChain = previous["hiri:chain"];
  if (previousChain) {
    // Previous is not genesis — genesis hash must be inherited
    if (chain.genesisHash !== previousChain.genesisHash) {
      return {
        valid: false,
        reason: `Genesis hash mismatch: current="${chain.genesisHash}", previous="${previousChain.genesisHash}"`,
      };
    }
  } else {
    // Previous IS genesis — genesis hash should be hash of the previous manifest
    if (chain.genesisHash !== previousHash) {
      return {
        valid: false,
        reason: `Genesis hash should equal hash of genesis manifest: expected="${previousHash}", got="${chain.genesisHash}"`,
      };
    }
  }

  // Rule 5: Depth increment
  const previousDepth = previousChain ? previousChain.depth : 1;
  if (chain.depth !== previousDepth + 1) {
    return {
      valid: false,
      reason: `Depth mismatch: expected=${previousDepth + 1}, got=${chain.depth}`,
    };
  }

  // Rule 6: Branch consistency
  if (chain.previousBranch !== previous["hiri:branch"]) {
    return {
      valid: false,
      reason: `Branch mismatch: chain.previousBranch="${chain.previousBranch}", previous branch="${previous["hiri:branch"]}"`,
    };
  }

  return { valid: true };
}

/**
 * Walk a chain from head manifest to genesis, verifying every link.
 *
 * This is the core Milestone 2 deliverable. It accepts injected fetcher
 * functions for I/O abstraction:
 * - ManifestFetcher: retrieves manifests by hash (Map in tests, StorageAdapter in M3)
 * - ContentFetcher: retrieves raw content bytes by hash (for delta fallback)
 *
 * The walker verifies signatures, chain link rules, and optionally delta
 * integrity at each step. When a delta fails verification, the walker
 * falls back to full content fetch and records a warning.
 *
 * @param head - The head manifest to walk from
 * @param publicKey - Public key for signature verification
 * @param fetchManifest - Injected function to fetch manifests by hash
 * @param fetchContent - Injected function to fetch content bytes by hash
 * @param crypto - Injected crypto provider
 * @returns Chain walk result with validity, depth, and any warnings
 */
export async function verifyChain(
  head: ResolutionManifest,
  publicKey: Uint8Array,
  fetchManifest: ManifestFetcher,
  fetchContent: ContentFetcher,
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<ChainWalkResult> {
  const warnings: string[] = [];
  let current = head;
  let depth = 0;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    depth++;

    // Verify signature of current manifest
    const profile = current["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
    const sigValid = await verifyManifest(current, publicKey, profile, crypto, canonicalizer, documentLoader);
    if (!sigValid) {
      return {
        valid: false,
        depth,
        reason: `Signature verification failed at version ${current["hiri:version"]}`,
        warnings,
      };
    }

    const chain = current["hiri:chain"];

    // No chain → genesis terminus
    if (!chain) {
      return { valid: true, depth, warnings };
    }

    // Fetch previous manifest
    const previous = await fetchManifest(chain.previous);
    if (!previous) {
      return {
        valid: false,
        depth,
        reason: `Previous manifest not found: ${chain.previous}`,
        warnings,
      };
    }

    // Storage tampering check: hash of fetched manifest must match
    const computedHash = await hashManifest(previous, crypto, canonicalizer, documentLoader);
    if (computedHash !== chain.previous) {
      return {
        valid: false,
        depth,
        reason: `Storage tampering detected: hash of fetched manifest (${computedHash}) does not match chain.previous (${chain.previous})`,
        warnings,
      };
    }

    // Validate chain link rules
    const linkResult = await validateChainLink(current, previous, crypto, canonicalizer, documentLoader);
    if (!linkResult.valid) {
      return {
        valid: false,
        depth,
        reason: linkResult.reason,
        warnings,
      };
    }

    // Delta verification (if present): try delta, fall back to full content
    const delta = current["hiri:delta"];
    if (delta) {
      // Fetch previous content to attempt delta verification
      const prevContentBytes = await fetchContent(previous["hiri:content"].hash);
      if (prevContentBytes) {
        // Reconstruct delta operations from fetchContent (stored alongside manifest)
        // The delta operations are fetched by delta hash
        const deltaOpsBytes = await fetchContent(delta.hash);
        if (deltaOpsBytes) {
          const deltaOps = JSON.parse(
            new TextDecoder().decode(deltaOpsBytes),
          );

          const profile2 = current["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
          const deltaResult = await verifyDelta(
            delta,
            deltaOps,
            prevContentBytes,
            current["hiri:content"].hash,
            profile2,
            crypto,
            canonicalizer,
            documentLoader,
          );

          if (!deltaResult.valid) {
            // Delta failed — fall back to full content verification
            const contentBytes = await fetchContent(current["hiri:content"].hash);
            if (contentBytes) {
              const contentHash = await crypto.hash(contentBytes);
              if (contentHash !== current["hiri:content"].hash) {
                return {
                  valid: false,
                  depth,
                  reason: `Content hash mismatch at version ${current["hiri:version"]}`,
                  warnings,
                };
              }
              // Content hash matches — record warning about delta failure
              warnings.push(
                `Delta verification failed at version ${current["hiri:version"]}: ${deltaResult.reason}; fell back to full content verification`,
              );
            }
          }
        }
      }
    }

    // Recurse: move to previous manifest
    current = previous;
  }
}

/**
 * Walk a chain with full key lifecycle awareness (Milestone 5).
 *
 * Unlike verifyChain(), this function does NOT short-circuit on first failure.
 * It walks the entire chain and collects per-manifest results, enabling
 * partial chain validity reporting (e.g., test 5.10: V3 valid, V2 invalid, V1 valid).
 *
 * Uses verifyManifestWithKeyLifecycle() instead of bare-key verifyManifest().
 *
 * @param head - The head manifest to walk from
 * @param keyDocument - The full-lifecycle KeyDocument
 * @param verificationTime - Injected clock for grace period checks
 * @param fetchManifest - Injected function to fetch manifests by hash
 * @param fetchContent - Injected function to fetch content bytes by hash
 * @param crypto - Injected crypto provider
 * @returns Chain walk result with validity, depth, warnings, and failures
 */
export async function verifyChainWithKeyLifecycle(
  head: ResolutionManifest,
  keyDocument: KeyDocument,
  verificationTime: string,
  fetchManifest: ManifestFetcher,
  fetchContent: ContentFetcher,
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
): Promise<ChainWalkResult> {
  const warnings: string[] = [];
  const failures: ChainFailure[] = [];
  let current = head;
  let depth = 0;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    depth++;

    // Verify signature with key lifecycle awareness (no short-circuit)
    const keyResult = await verifyManifestWithKeyLifecycle(
      current,
      keyDocument,
      verificationTime,
      crypto,
    );

    if (!keyResult.valid) {
      failures.push({
        version: current["hiri:version"],
        keyId: keyResult.keyId,
        keyStatus: keyResult.keyStatus,
        reason: keyResult.warning ?? `Key verification failed: ${keyResult.keyStatus}`,
      });
    } else if (keyResult.warning) {
      warnings.push(
        `Version ${current["hiri:version"]}: ${keyResult.warning}`,
      );
    }

    const chain = current["hiri:chain"];

    // No chain → genesis terminus
    if (!chain) {
      return {
        valid: failures.length === 0,
        depth,
        warnings,
        failures: failures.length > 0 ? failures : undefined,
        ...(failures.length > 0 ? { reason: `Chain has ${failures.length} key lifecycle failure(s)` } : {}),
      };
    }

    // Fetch previous manifest
    const previous = await fetchManifest(chain.previous);
    if (!previous) {
      return {
        valid: false,
        depth,
        reason: `Previous manifest not found: ${chain.previous}`,
        warnings,
        failures: failures.length > 0 ? failures : undefined,
      };
    }

    // Storage tampering check
    const computedHash = await hashManifest(previous, crypto, canonicalizer, documentLoader);
    if (computedHash !== chain.previous) {
      return {
        valid: false,
        depth,
        reason: `Storage tampering detected at version ${current["hiri:version"]}`,
        warnings,
        failures: failures.length > 0 ? failures : undefined,
      };
    }

    // Validate structural chain link rules (unchanged from M2)
    const linkResult = await validateChainLink(current, previous, crypto, canonicalizer, documentLoader);
    if (!linkResult.valid) {
      return {
        valid: false,
        depth,
        reason: linkResult.reason,
        warnings,
        failures: failures.length > 0 ? failures : undefined,
      };
    }

    // Delta verification (if present): try delta, fall back to full content
    const delta = current["hiri:delta"];
    if (delta) {
      const prevContentBytes = await fetchContent(previous["hiri:content"].hash);
      if (prevContentBytes) {
        const deltaOpsBytes = await fetchContent(delta.hash);
        if (deltaOpsBytes) {
          const deltaOps = JSON.parse(
            new TextDecoder().decode(deltaOpsBytes),
          );

          const profile2 = current["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
          const deltaResult = await verifyDelta(
            delta,
            deltaOps,
            prevContentBytes,
            current["hiri:content"].hash,
            profile2,
            crypto,
            canonicalizer,
            documentLoader,
          );

          if (!deltaResult.valid) {
            // Delta failed — fall back to full content verification
            const contentBytes = await fetchContent(current["hiri:content"].hash);
            if (contentBytes) {
              const contentHash = await crypto.hash(contentBytes);
              if (contentHash !== current["hiri:content"].hash) {
                return {
                  valid: false,
                  depth,
                  reason: `Content hash mismatch at version ${current["hiri:version"]}`,
                  warnings,
                  failures: failures.length > 0 ? failures : undefined,
                };
              }
              warnings.push(
                `Delta verification failed at version ${current["hiri:version"]}: ${deltaResult.reason}; fell back to full content verification`,
              );
            }
          }
        }
      }
    }

    // Move to previous manifest (continue walking, don't short-circuit)
    current = previous;
  }
}
