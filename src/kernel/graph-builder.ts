/**
 * Graph Builder — Milestone 4 Kernel Module
 *
 * Orchestrates loading verified content into an RDF index
 * with entailment mode routing.
 *
 * Pure kernel function. Only imports from ./types.js. No I/O.
 */

import type {
  RDFIndex,
  EntailmentMode,
  GraphBuilderConfig,
  ManifestSemantics,
} from "./types.js";

/**
 * Resolve the entailment mode from manifest semantics.
 * Manifests without hiri:semantics default to "none" (safe default).
 */
export function resolveEntailmentMode(
  semantics: ManifestSemantics | undefined,
): EntailmentMode {
  if (!semantics) return "none";
  return semantics.entailmentMode;
}

/**
 * Build an RDF index from verified content bytes.
 *
 * Routes on entailmentMode:
 * - "none": load triples as-is, no inference
 * - "materialized": not yet implemented (throws)
 * - "runtime": not yet implemented (throws)
 *
 * The indexFactory parameter allows the kernel to remain
 * independent of any specific RDF library.
 */
export async function buildGraph(
  content: Uint8Array,
  format: string,
  baseURI: string,
  config: GraphBuilderConfig,
  indexFactory: () => RDFIndex,
): Promise<RDFIndex> {
  if (config.entailmentMode === "none") {
    const index = indexFactory();
    await index.load(content, format, baseURI);
    return index;
  } else if (config.entailmentMode === "materialized") {
    throw new Error("Materialized entailment not yet implemented");
  } else if (config.entailmentMode === "runtime") {
    throw new Error("Runtime entailment not yet implemented");
  }

  throw new Error(
    `Unknown entailment mode: ${config.entailmentMode as string}`,
  );
}
