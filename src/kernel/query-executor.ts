/**
 * Query Executor — Milestone 4 Kernel Module
 *
 * Orchestrates SPARQL query execution against an RDF index.
 * Establishes the kernel contract boundary: tests verify this
 * function is the entry point for all queries.
 *
 * Pure kernel function. Only imports from ./types.js. No I/O.
 */

import type { RDFIndex, SPARQLEngine, QueryResult } from "./types.js";

/**
 * Execute a SPARQL query against an RDF index using the provided engine.
 */
export async function executeQuery(
  sparql: string,
  index: RDFIndex,
  engine: SPARQLEngine,
): Promise<QueryResult> {
  return engine.query(sparql, index);
}
