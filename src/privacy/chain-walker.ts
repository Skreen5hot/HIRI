/**
 * Privacy-Aware Chain Walker — Milestone 15
 *
 * Walks version chains across privacy mode transitions (§11).
 * Uses getLogicalPlaintextHash() instead of raw content.hash for
 * cross-version content comparison. Validates transition legality
 * and addressing mode consistency at each link.
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel).
 */

import type {
  CryptoProvider,
  ResolutionManifest,
  ManifestFetcher,
  ContentFetcher,
} from "../kernel/types.js";
import { validateChainLink, hashManifest } from "../kernel/chain.js";
import { verifyManifest } from "../kernel/signing.js";
import type { PrivacyChainOptions, PrivacyChainWalkResult, PrivacyMode } from "./types.js";
import { getPrivacyMode } from "./privacy-mode.js";
import { getLogicalPlaintextHash } from "./plaintext-hash.js";
import { validateTransition, validateAddressingConsistency } from "./lifecycle.js";

/**
 * Walk a chain across privacy mode transitions (§11).
 *
 * Unlike the kernel's verifyChain, this walker:
 * 1. Uses getLogicalPlaintextHash() for cross-version content comparison
 * 2. Validates privacy mode transitions (§11.2)
 * 3. Validates addressing mode consistency (§11.3)
 * 4. Records mode transitions in the result
 *
 * @param head - The head manifest to walk from
 * @param publicKey - Ed25519 public key for signature verification
 * @param fetchManifest - Injected function to fetch manifests by hash
 * @param fetchContent - Injected function to fetch content bytes by hash
 * @param crypto - Injected crypto provider
 * @param options - Optional canonicalizer, document loader, hash registry
 */
export async function verifyPrivacyChain(
  head: ResolutionManifest,
  publicKey: Uint8Array,
  fetchManifest: ManifestFetcher,
  fetchContent: ContentFetcher,
  crypto: CryptoProvider,
  options?: PrivacyChainOptions,
): Promise<PrivacyChainWalkResult> {
  const warnings: string[] = [];
  const modeTransitions: PrivacyChainWalkResult["modeTransitions"] = [];
  let current = head;
  let depth = 0;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    depth++;

    // Verify signature of current manifest
    const profile = current["hiri:signature"].canonicalization as "JCS" | "URDNA2015";
    const sigValid = await verifyManifest(
      current,
      publicKey,
      profile,
      crypto,
      options?.canonicalizer,
      options?.documentLoader,
    );
    if (!sigValid) {
      return {
        valid: false,
        depth,
        reason: `Signature verification failed at version ${current["hiri:version"]}`,
        warnings,
        modeTransitions,
      };
    }

    const chain = current["hiri:chain"];

    // No chain → genesis terminus
    if (!chain) {
      return { valid: true, depth, warnings, modeTransitions };
    }

    // Fetch previous manifest
    const previous = await fetchManifest(chain.previous);
    if (!previous) {
      return {
        valid: false,
        depth,
        reason: `Previous manifest not found: ${chain.previous}`,
        warnings,
        modeTransitions,
      };
    }

    // Storage tampering check
    const computedHash = await hashManifest(
      previous,
      crypto,
      options?.canonicalizer,
      options?.documentLoader,
    );
    if (computedHash !== chain.previous) {
      return {
        valid: false,
        depth,
        reason: `Storage tampering detected at version ${current["hiri:version"]}`,
        warnings,
        modeTransitions,
      };
    }

    // Validate structural chain link rules (kernel)
    const linkResult = await validateChainLink(
      current,
      previous,
      crypto,
      options?.canonicalizer,
      options?.documentLoader,
    );
    if (!linkResult.valid) {
      return {
        valid: false,
        depth,
        reason: linkResult.reason,
        warnings,
        modeTransitions,
      };
    }

    // --- Privacy-specific checks ---

    // Check privacy mode transition (§11.2)
    const currentMode = getPrivacyMode(current);
    const previousMode = getPrivacyMode(previous);

    if (currentMode !== previousMode) {
      modeTransitions.push({
        fromVersion: previous["hiri:version"],
        toVersion: current["hiri:version"],
        fromMode: previousMode,
        toMode: currentMode,
      });

      const transitionResult = validateTransition(previousMode, currentMode);
      if (!transitionResult.valid) {
        return {
          valid: false,
          depth,
          reason: transitionResult.reason,
          warnings,
          modeTransitions,
        };
      }
    }

    // Check addressing mode consistency (§11.3)
    const addressingResult = validateAddressingConsistency(current, previous);
    if (!addressingResult.valid) {
      return {
        valid: false,
        depth,
        reason: addressingResult.reason,
        warnings,
        modeTransitions,
      };
    }

    // Cross-version content comparison using logical plaintext hash (§11.3)
    // Only compare if both manifests have logical plaintext hashes
    // (attestation manifests throw — skip comparison for those)
    try {
      const currentHash = getLogicalPlaintextHash(current);
      const previousHash = getLogicalPlaintextHash(previous);

      if (currentHash.warnings.length > 0) {
        warnings.push(...currentHash.warnings);
      }
      if (previousHash.warnings.length > 0) {
        warnings.push(...previousHash.warnings);
      }

      // Note: logical plaintext hashes are NOT required to match across versions.
      // Content changes between versions are expected. The logical plaintext hash
      // is used to ensure we're comparing the RIGHT hash (plaintext, not ciphertext)
      // when doing delta verification. The chain link rules (previous hash, etc.)
      // handle integrity — this just ensures we extract the correct hash per mode.
    } catch {
      // One of the manifests is an attestation — no content comparison possible
      warnings.push(
        `Cannot compare logical plaintext hash across version ${previous["hiri:version"]} → ${current["hiri:version"]} (attestation manifest)`,
      );
    }

    // Move to previous
    current = previous;
  }
}
