/**
 * Logical Plaintext Hash — Milestone 10
 *
 * Implements §11.3 of the Privacy Extension v1.4.1.
 * Resolves the correct plaintext hash from a manifest regardless
 * of privacy mode. Chain walkers use this for cross-version comparison
 * when privacy modes differ between versions.
 *
 * This module is Layer 2 (Privacy) and MAY import from Layer 0 (Kernel).
 */

import type { ResolutionManifest } from "../kernel/types.js";
import { getPrivacyMode } from "./privacy-mode.js";

export interface PlaintextHashResult {
  hash: string;
  warnings: string[];
}

/**
 * Resolve the logical plaintext hash from a manifest,
 * regardless of privacy mode (§11.3).
 *
 * For unknown modes: returns content.hash WITH a warning
 * (not silently — the caller must know the hash may be unreliable).
 *
 * For attestation: throws (attestation manifests have no content).
 */
export function getLogicalPlaintextHash(manifest: ResolutionManifest): PlaintextHashResult {
  const mode = getPrivacyMode(manifest);
  const warnings: string[] = [];

  switch (mode) {
    case "public":
      return { hash: manifest["hiri:content"].hash, warnings };

    case "proof-of-possession":
      return { hash: manifest["hiri:content"].hash, warnings };

    case "encrypted": {
      const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
        { parameters?: { plaintextHash?: string } };
      const plaintextHash = privacy?.parameters?.plaintextHash;
      if (!plaintextHash) {
        throw new Error(
          "Encrypted manifest missing hiri:privacy.parameters.plaintextHash",
        );
      }
      return { hash: plaintextHash, warnings };
    }

    case "selective-disclosure":
      return { hash: manifest["hiri:content"].hash, warnings };

    case "attestation":
      throw new Error("Attestation manifests have no logical plaintext hash");

    case "anonymous": {
      const privacy = (manifest as Record<string, unknown>)["hiri:privacy"] as
        { parameters?: { contentVisibility?: string; plaintextHash?: string } };
      const visibility = privacy?.parameters?.contentVisibility;
      if (visibility === "encrypted") {
        const plaintextHash = privacy?.parameters?.plaintextHash;
        if (!plaintextHash) {
          throw new Error(
            "Anonymous+encrypted manifest missing hiri:privacy.parameters.plaintextHash",
          );
        }
        return { hash: plaintextHash, warnings };
      }
      return { hash: manifest["hiri:content"].hash, warnings };
    }

    default:
      // Unknown mode: return content.hash WITH a warning (user-approved fix)
      warnings.push(
        `Unknown privacy mode "${mode}": returning content.hash as best-effort logical plaintext hash`,
      );
      return { hash: manifest["hiri:content"].hash, warnings };
  }
}
