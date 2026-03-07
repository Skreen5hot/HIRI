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
import { parseNQuads, serializeNQuads, applyRDFPatch } from "./rdf-patch.js";
import type { HashRegistry } from "./hash-registry.js";
import type {
  CryptoProvider,
  JsonPatchOperation,
  RDFPatchOperation,
  ManifestDelta,
  ChainValidation,
  Canonicalizer,
  DocumentLoader,
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
 * Build RDF Patch delta metadata for embedding in a manifest.
 * Same pattern as buildDelta() but sets format to "application/rdf-patch".
 */
export async function buildRDFDelta(
  operations: RDFPatchOperation[],
  appliesTo: string,
  crypto: CryptoProvider,
): Promise<{ delta: ManifestDelta; serialized: string }> {
  const serialized = stableStringify(operations, false);
  const bytes = new TextEncoder().encode(serialized);
  const hash = await crypto.hash(bytes);

  return {
    delta: {
      hash,
      format: "application/rdf-patch",
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
  deltaContent: JsonPatchOperation[] | RDFPatchOperation[],
  previousContentBytes: Uint8Array,
  currentContentHash: string,
  profile: "JCS" | "URDNA2015",
  crypto: CryptoProvider,
  canonicalizer?: Canonicalizer,
  documentLoader?: DocumentLoader,
  hashRegistry?: HashRegistry,
): Promise<ChainValidation> {
  // Step 1: Validate delta-canonicalization coupling
  const couplingResult = validateDeltaCoupling(profile, delta);
  if (!couplingResult.valid) {
    return couplingResult;
  }

  // Step 2: Verify delta.appliesTo matches previous content hash
  // For JCS: hash of raw bytes. For URDNA2015: hash of canonical N-Quads.
  // Check is deferred to format-specific branches because URDNA2015
  // must canonicalize before hashing (raw JSON-LD != canonical N-Quads).
  if (delta.format === "application/json-patch+json") {
    const appliesToMatch = hashRegistry
      ? await hashRegistry.verify(previousContentBytes, delta.appliesTo)
      : (await crypto.hash(previousContentBytes)) === delta.appliesTo;
    if (!appliesToMatch) {
      return {
        valid: false,
        reason: `delta.appliesTo does not match previous content hash (expected="${delta.appliesTo}")`,
      };
    }
  }
  // URDNA2015 appliesTo check happens after canonicalization (see below)

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

  // Format-dispatched delta application
  if (delta.format === "application/json-patch+json") {
    // JCS path: JSON Patch on JSON syntax tree
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

    let patchedDoc: unknown;
    try {
      patchedDoc = applyPatch(previousDoc, deltaContent as JsonPatchOperation[]);
    } catch (e) {
      return {
        valid: false,
        reason: `Failed to apply patch: ${e instanceof Error ? e.message : String(e)}`,
      };
    }

    const patchedStr = stableStringify(patchedDoc, false);
    const patchedBytes = new TextEncoder().encode(patchedStr);
    const patchedMatch = hashRegistry
      ? await hashRegistry.verify(patchedBytes, currentContentHash)
      : (await crypto.hash(patchedBytes)) === currentContentHash;

    if (!patchedMatch) {
      return {
        valid: false,
        reason: `Delta application produces different content hash (expected="${currentContentHash}")`,
      };
    }

    return { valid: true };
  } else if (delta.format === "application/rdf-patch") {
    // URDNA2015 path (§11.4.5): RDF Patch on N-Quads quad set
    if (!canonicalizer?.canonicalizeNQuads) {
      return {
        valid: false,
        reason: "RDF Patch verification requires a canonicalizer with canonicalizeNQuads support",
      };
    }
    if (!documentLoader) {
      return {
        valid: false,
        reason: "RDF Patch verification requires a documentLoader",
      };
    }

    // Parse previous content as JSON-LD
    let previousDoc: Record<string, unknown>;
    try {
      const previousStr = new TextDecoder().decode(previousContentBytes);
      previousDoc = JSON.parse(previousStr) as Record<string, unknown>;
    } catch (e) {
      return {
        valid: false,
        reason: `Failed to decode/parse previous content as JSON-LD: ${e instanceof Error ? e.message : String(e)}`,
      };
    }

    // Canonicalize previous content via URDNA2015 to N-Quads
    let prevNQuads: string;
    let nquadsBytes: Uint8Array;
    try {
      nquadsBytes = await canonicalizer.canonicalize(previousDoc, documentLoader);
      prevNQuads = new TextDecoder().decode(nquadsBytes);
    } catch (e) {
      return {
        valid: false,
        reason: `Failed to canonicalize previous content: ${e instanceof Error ? e.message : String(e)}`,
      };
    }

    // Verify delta.appliesTo matches hash of canonical N-Quads
    const appliesToMatch2 = hashRegistry
      ? await hashRegistry.verify(nquadsBytes, delta.appliesTo)
      : (await crypto.hash(nquadsBytes)) === delta.appliesTo;
    if (!appliesToMatch2) {
      return {
        valid: false,
        reason: `delta.appliesTo does not match previous content hash (expected="${delta.appliesTo}")`,
      };
    }

    // Parse N-Quads into quad set and apply RDF Patch
    const quadSet = parseNQuads(prevNQuads);
    const patchedQuads = applyRDFPatch(quadSet, deltaContent as RDFPatchOperation[]);

    // Serialize modified quad set
    const modifiedNQuads = serializeNQuads(patchedQuads);

    // Re-canonicalize via URDNA2015 (§11.4.3: post-patch re-canonicalization)
    let canonicalBytes: Uint8Array;
    try {
      canonicalBytes = await canonicalizer.canonicalizeNQuads(modifiedNQuads, documentLoader);
    } catch (e) {
      return {
        valid: false,
        reason: `Failed to re-canonicalize patched N-Quads: ${e instanceof Error ? e.message : String(e)}`,
      };
    }

    // Hash and compare
    const patchedMatch2 = hashRegistry
      ? await hashRegistry.verify(canonicalBytes, currentContentHash)
      : (await crypto.hash(canonicalBytes)) === currentContentHash;
    if (!patchedMatch2) {
      return {
        valid: false,
        reason: `Delta application produces different content hash (expected="${currentContentHash}")`,
      };
    }

    return { valid: true };
  }

  return {
    valid: false,
    reason: `Unknown delta format: "${delta.format}"`,
  };
}
