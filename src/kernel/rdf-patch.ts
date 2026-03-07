/**
 * RDF Patch Operations
 *
 * Pure kernel module for N-Quads set manipulation and RDF Patch application.
 * No external dependencies -- all operations are string-based.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import type { RDFPatchOperation } from "./types.js";

/**
 * Parse N-Quads text into a Set of quad lines.
 * Each line is trimmed. Empty lines and comment lines (#) are skipped.
 */
export function parseNQuads(nquadsText: string): Set<string> {
  const quads = new Set<string>();
  for (const line of nquadsText.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    quads.add(trimmed);
  }
  return quads;
}

/**
 * Serialize a Set of quad lines to sorted canonical N-Quads.
 * Lines are sorted lexicographically and joined with newline.
 * Trailing newline appended (N-Quads convention).
 */
export function serializeNQuads(quads: Set<string>): string {
  const sorted = [...quads].sort();
  return sorted.length > 0 ? sorted.join("\n") + "\n" : "";
}

/**
 * Reconstruct a quad line from an RDF Patch operation.
 * Subject, predicate, and object are already in N-Quads notation.
 */
export function operationToQuad(op: RDFPatchOperation): string {
  return `${op.subject} ${op.predicate} ${op.object} .`;
}

/**
 * Apply RDF Patch operations to a quad set.
 *
 * RDF set semantics:
 * - "add" inserts a quad (idempotent -- sets ignore duplicates)
 * - "remove" deletes a quad if present, no-op if absent
 *
 * All operations always complete. No per-operation errors.
 * Atomicity is enforced at the pipeline level: the caller hashes
 * the result and compares to hiri:content.hash. If mismatch,
 * entire delta discarded.
 */
export function applyRDFPatch(
  quads: Set<string>,
  operations: RDFPatchOperation[],
): Set<string> {
  const result = new Set(quads);
  for (const op of operations) {
    const quad = operationToQuad(op);
    if (op.op === "add") {
      result.add(quad);
    } else {
      result.delete(quad);
    }
  }
  return result;
}
