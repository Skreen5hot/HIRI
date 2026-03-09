/**
 * Privacy Mode Parser — Milestone 10
 *
 * Extracts and validates the hiri:privacy block from manifests.
 * Returns "public" when the block is absent (backward compatibility).
 *
 * This module is Layer 2 (Privacy) and MAY import from Layer 0 (Kernel).
 */

import type { ResolutionManifest } from "../kernel/types.js";
import type { PrivacyMode, PrivacyBlock } from "./types.js";

const KNOWN_MODES: ReadonlySet<string> = new Set([
  "public",
  "proof-of-possession",
  "encrypted",
  "selective-disclosure",
  "anonymous",
  "attestation",
]);

/**
 * Extract privacy mode from a manifest.
 * Returns "public" when hiri:privacy is absent (backward compatibility per §5.2).
 */
export function getPrivacyMode(manifest: ResolutionManifest): PrivacyMode | string {
  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
    | { mode?: string }
    | undefined;

  if (!privacy || !privacy.mode) {
    return "public";
  }

  return privacy.mode;
}

/**
 * Parse and validate the hiri:privacy block.
 * Returns null for public manifests (no privacy block).
 */
export function parsePrivacyBlock(manifest: ResolutionManifest): PrivacyBlock | null {
  const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
    | Record<string, unknown>
    | undefined;

  if (!privacy) {
    return null;
  }

  const mode = (privacy.mode as string) ?? "public";

  return {
    mode: KNOWN_MODES.has(mode) ? (mode as PrivacyMode) : mode,
    parameters: privacy.parameters as Record<string, unknown> | undefined,
    transitionFrom: privacy.transitionFrom as string | undefined,
    transitionReason: privacy.transitionReason as string | undefined,
  };
}

/**
 * Check whether a mode string is a known privacy mode.
 */
export function isKnownPrivacyMode(mode: string): mode is PrivacyMode {
  return KNOWN_MODES.has(mode);
}
