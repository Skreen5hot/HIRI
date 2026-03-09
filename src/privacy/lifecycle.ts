/**
 * Privacy Lifecycle Transitions — Milestone 15
 *
 * Implements §11.2 (transition validation) and §11.3 (addressing consistency).
 *
 * Privacy transitions are monotonically decreasing: once content is published
 * publicly, it cannot be made private again. Encrypted content can become
 * public but not proof-of-possession.
 *
 * This module is Layer 2 (Privacy). Imports from Layer 0 (Kernel).
 */

import type { ResolutionManifest } from "../kernel/types.js";
import type { PrivacyMode } from "./types.js";

// ---------------------------------------------------------------------------
// Transition Validation (§11.2)
// ---------------------------------------------------------------------------

/**
 * Privacy level ordering (higher = more private).
 *
 * Transitions must be monotonically decreasing (from more private to less
 * private). Same-mode transitions are always valid (identity).
 */
const PRIVACY_LEVEL: Record<string, number> = {
  "proof-of-possession": 4,
  "selective-disclosure": 3,
  "encrypted": 2,
  "public": 1,
};

export interface TransitionValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validate a privacy mode transition (§11.2).
 *
 * Valid transitions move from higher privacy to lower privacy (monotonically
 * decreasing). Same-mode transitions are valid. Anonymous and attestation
 * modes do not participate in transition ordering — they are orthogonal.
 */
export function validateTransition(
  fromMode: PrivacyMode | string,
  toMode: PrivacyMode | string,
): TransitionValidationResult {
  // Same mode → always valid
  if (fromMode === toMode) {
    return { valid: true };
  }

  // Anonymous and attestation are orthogonal — not in the transition lattice
  if (
    fromMode === "anonymous" || toMode === "anonymous" ||
    fromMode === "attestation" || toMode === "attestation"
  ) {
    return { valid: true };
  }

  const fromLevel = PRIVACY_LEVEL[fromMode];
  const toLevel = PRIVACY_LEVEL[toMode];

  // Unknown modes: accept but warn (forward compatibility)
  if (fromLevel === undefined || toLevel === undefined) {
    return { valid: true };
  }

  // Must be monotonically decreasing (fromLevel >= toLevel)
  if (fromLevel < toLevel) {
    return {
      valid: false,
      reason: `Invalid privacy transition: "${fromMode}" → "${toMode}" violates monotonically decreasing privacy (§11.2)`,
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Addressing Mode Consistency (§11.3)
// ---------------------------------------------------------------------------

/**
 * Validate addressing mode consistency across a chain link (§11.3).
 *
 * The addressing mode used for content hashing MUST be constant across
 * all versions in a chain. Mixing raw-sha256 and cidv1-dag-cbor within
 * the same chain is not allowed.
 *
 * Attestation manifests (no hiri:content) are skipped.
 */
export function validateAddressingConsistency(
  currentManifest: ResolutionManifest,
  previousManifest: ResolutionManifest,
): TransitionValidationResult {
  const currentContent = currentManifest["hiri:content"];
  const previousContent = previousManifest["hiri:content"];

  // Attestation manifests have no content block — skip
  if (!currentContent || !previousContent) {
    return { valid: true };
  }

  const currentAddressing = currentContent.addressing;
  const previousAddressing = previousContent.addressing;

  if (currentAddressing && previousAddressing && currentAddressing !== previousAddressing) {
    return {
      valid: false,
      reason: `Addressing mode inconsistency: version ${currentManifest["hiri:version"]} uses "${currentAddressing}" but version ${previousManifest["hiri:version"]} uses "${previousAddressing}" (§11.3)`,
    };
  }

  return { valid: true };
}
