/**
 * Delta Construction and Verification
 *
 * Provides functions for building delta metadata (for manifest embedding)
 * and verifying deltas against previous and current content.
 *
 * verifyDelta accepts Uint8Array for previous content, owning the full
 * pipeline: hash verify → decode → parse → apply patch → canonicalize →
 * encode → hash → compare. This prevents hash-verification-on-different-bytes bugs.
 *
 * Error handling contract:
 * - applyPatch (in json-patch.ts) throws on programming errors
 * - verifyDelta catches throws and returns { valid: false, reason }
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
 *
 * @param operations - The JSON Patch operations
 * @param appliesTo - Hash of the previous content this delta applies to
 * @param crypto - Injected crypto provider
 * @returns Delta metadata and serialized operations string
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
      format: "json-patch",
      appliesTo,
      operations: operations.length,
    },
    serialized,
  };
}

/**
 * Verify a delta against previous and current content.
 *
 * Full pipeline (accepts Uint8Array for previous content):
 * 1. Verify delta.appliesTo matches hash of previousContentBytes
 * 2. Verify delta.hash matches hash of serialized deltaContent
 * 3. Decode previousContentBytes → parse JSON
 * 4. Apply patch operations
 * 5. Canonicalize result → encode → hash
 * 6. Compare to currentContentHash
 *
 * @param delta - The delta metadata from the manifest
 * @param deltaContent - The actual patch operations
 * @param previousContentBytes - Raw bytes of the previous content
 * @param currentContentHash - Expected hash of the current content
 * @param crypto - Injected crypto provider
 * @returns Validation result
 */
export async function verifyDelta(
  delta: ManifestDelta,
  deltaContent: JsonPatchOperation[],
  previousContentBytes: Uint8Array,
  currentContentHash: string,
  crypto: CryptoProvider,
): Promise<ChainValidation> {
  // Step 1: Verify delta.appliesTo matches previous content hash
  const previousHash = await crypto.hash(previousContentBytes);
  if (previousHash !== delta.appliesTo) {
    return {
      valid: false,
      reason: `delta.appliesTo does not match previous content hash: expected="${previousHash}", got="${delta.appliesTo}"`,
    };
  }

  // Step 2: Verify delta hash matches serialized operations
  const serialized = stableStringify(deltaContent, false);
  const serializedBytes = new TextEncoder().encode(serialized);
  const deltaHash = await crypto.hash(serializedBytes);
  if (deltaHash !== delta.hash) {
    return {
      valid: false,
      reason: `Delta content hash mismatch: expected="${deltaHash}", got="${delta.hash}"`,
    };
  }

  // Step 3: Decode previous content
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

  // Step 4: Apply patch (catches throws from applyPatch)
  let patchedDoc: unknown;
  try {
    patchedDoc = applyPatch(previousDoc, deltaContent);
  } catch (e) {
    return {
      valid: false,
      reason: `Failed to apply patch: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  // Step 5: Canonicalize, encode, and hash
  const patchedStr = stableStringify(patchedDoc, false);
  const patchedBytes = new TextEncoder().encode(patchedStr);
  const patchedHash = await crypto.hash(patchedBytes);

  // Step 6: Compare to current content hash
  if (patchedHash !== currentContentHash) {
    return {
      valid: false,
      reason: `Delta application produces different content hash: expected="${currentContentHash}", got="${patchedHash}"`,
    };
  }

  return { valid: true };
}
