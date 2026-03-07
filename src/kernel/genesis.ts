/**
 * Genesis Manifest Validation
 *
 * Validates whether a manifest is a valid genesis (first in chain)
 * or a valid non-genesis (must have chain reference).
 *
 * Rules:
 *   version=1, no chain   → valid genesis
 *   version=1, with chain → valid (optional chain on v1)
 *   version>1, no chain   → INVALID (non-genesis must chain)
 *   version>1, with chain → valid structure (chain content verified in Milestone 2)
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { parseVersion } from "./version.js";
import type { UnsignedManifest, ResolutionManifest, GenesisValidation } from "./types.js";

/**
 * Validate genesis rules for a manifest.
 *
 * @param manifest - A signed or unsigned manifest
 * @returns Validation result with reason if invalid
 */
export function validateGenesis(
  manifest: UnsignedManifest | ResolutionManifest,
): GenesisValidation {
  const version = manifest["hiri:version"];
  const hasChain = "hiri:chain" in manifest && manifest["hiri:chain"] != null;

  if (parseVersion(version) === 1n) {
    // Genesis: version 1, chain is optional
    return { valid: true };
  }

  if (parseVersion(version) > 1n && !hasChain) {
    return {
      valid: false,
      reason: "Non-genesis manifest (version > 1) must include hiri:chain",
    };
  }

  // version > 1 with chain: structurally valid
  // (chain content verification deferred to Milestone 2)
  return { valid: true };
}
