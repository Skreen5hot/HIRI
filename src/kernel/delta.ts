/**
 * Delta Construction and Verification (v3.1.1)
 *
 * Provides functions for building delta metadata (for manifest embedding)
 * and verifying deltas against previous and current content.
 *
 * v3.1.1 changes:
 * - Format uses MIME types: "application/json-patch+json" | "application/rdf-patch"
 * - Delta-canonicalization coupling validation added
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { stableStringify } from "./canonicalize.js";
import { applyPatch } from "./json-patch.js";
import type {
  CryptoProvider,
  JsonPatchOperation,
  ManifestDelta,
  ChainValidation,
} from "./types.js";

/**
 * Build delta metadata for embedding in a manifest.
 *
 * Serializes the operations array via JCS (canonical form for hashing),
 * hashes the result, and returns the ManifestDelta structure plus the
 * serialized string.
 */
export async function buildDelta(
  operations: JsonPatchOperation[],
  appliesTo: string,
  crypto: CryptoProvider,
): Promise<{ delta: ManifestDelta; serialized: string }> {
  const serialized = stableStringify(operations, false);
  const bytes = new TextEncoder().encode(serialized);
  const hash = await crypto.hash(bytes);

  return {
    delta: {
      hash,
      format: "application/json-patch+json",
      appliesTo,
      operations: operations.length,
    },
    serialized,
  };
}

/**
 * Validate delta-canonicalization coupling.
 *
 * JCS profile requires JSON Patch format.
 * URDNA2015 profile requires RDF Patch format.
 */
export function validateDeltaCoupling(
  profile: "JCS" | "URDNA2015",
  delta: ManifestDelta,
): ChainValidation {
  if (profile === "JCS" && delta.format !== "application/json-patch+json") {
    return { valid: false, reason: "JCS profile requires JSON Patch format (application/json-patch+json)" };
  }
  if (profile === "URDNA2015" && delta.format !== "application/rdf-patch") {
    return { valid: false, reason: "URDNA2015 profile requires RDF Patch format (application/rdf-patch)" };
  }
  return { valid: true };
}

/**
 * Verify a delta against previous and current content.
 *
 * Full pipeline (accepts Uint8Array for previous content):
 * 1. Validate delta-canonicalization coupling
 * 2. Verify delta.appliesTo matches hash of previousContentBytes
 * 3. Verify delta.hash matches hash of serialized deltaContent
 * 4. Decode previousContentBytes -> parse JSON
 * 5. Apply patch operations
 * 6. Canonicalize result -> encode -> hash
 * 7. Compare to currentContentHash
 */
export async function verifyDelta(
  delta: ManifestDelta,
  deltaContent: JsonPatchOperation[],
  previousContentBytes: Uint8Array,
  currentContentHash: string,
  profile: "JCS" | "URDNA2015",
  crypto: CryptoProvider,
): Promise<ChainValidation> {
  // Step 1: Validate delta-canonicalization coupling
  const couplingResult = validateDeltaCoupling(profile, delta);
  if (!couplingResult.valid) {
    return couplingResult;
  }

  // Step 2: Verify delta.appliesTo matches previous content hash
  const previousHash = await crypto.hash(previousContentBytes);
  if (previousHash !== delta.appliesTo) {
    return {
      valid: false,
      reason: `delta.appliesTo does not match previous content hash: expected="${previousHash}", got="${delta.appliesTo}"`,
    };
  }

  // Step 3: Verify delta hash matches serialized operations
  const serialized = stableStringify(deltaContent, false);
  const serializedBytes = new TextEncoder().encode(serialized);
  const deltaHash = await crypto.hash(serializedBytes);
  if (deltaHash !== delta.hash) {
    return {
      valid: false,
      reason: `Delta content hash mismatch: expected="${deltaHash}", got="${delta.hash}"`,
    };
  }

  // Step 4: Decode previous content
  let previousDoc: unknown;
  try {
    const previousStr = new TextDecoder().decode(previousContentBytes);
    previousDoc = JSON.parse(previousStr);
  } catch (e) {
    return {
      valid: false,
      reason: `Failed to decode/parse previous content: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  // Step 5: Apply patch (catches throws from applyPatch)
  let patchedDoc: unknown;
  try {
    patchedDoc = applyPatch(previousDoc, deltaContent);
  } catch (e) {
    return {
      valid: false,
      reason: `Failed to apply patch: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  // Step 6: Canonicalize, encode, and hash
  const patchedStr = stableStringify(patchedDoc, false);
  const patchedBytes = new TextEncoder().encode(patchedStr);
  const patchedHash = await crypto.hash(patchedBytes);

  // Step 7: Compare to current content hash
  if (patchedHash !== currentContentHash) {
    return {
      valid: false,
      reason: `Delta application produces different content hash: expected="${currentContentHash}", got="${patchedHash}"`,
    };
  }

  return { valid: true };
}
