/**
 * URDNA2015 Canonicalizer (§7.2)
 *
 * Adapter-layer Canonicalizer implementation using jsonld.canonize().
 * Passes the caller-provided documentLoader through to jsonld.
 * Enforces resource limits (§7.7).
 */

import jsonld from "jsonld";
// RemoteDocument type not needed — using  cast for documentLoader
import type { Canonicalizer, DocumentLoader, CanonicalizationLimits } from "../../kernel/types.js";

const DEFAULT_LIMITS: Required<CanonicalizationLimits> = {
  maxBlankNodes: 1000,
  maxWallClockMs: 5000,
  maxOutputBytes: 10_485_760, // 10 MB
};

export class URDNA2015Canonicalizer implements Canonicalizer {
  private limits: Required<CanonicalizationLimits>;

  constructor(limits?: CanonicalizationLimits) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
  }

  async canonicalize(
    doc: Record<string, unknown>,
    documentLoader: DocumentLoader,
  ): Promise<Uint8Array> {
    // Pre-check: count blank nodes in input
    const blankNodeCount = countBlankNodes(doc);
    if (blankNodeCount > this.limits.maxBlankNodes) {
      throw new CanonicalizationResourceExceeded(
        `Blank node count (${blankNodeCount}) exceeds limit (${this.limits.maxBlankNodes})`
      );
    }

    // Wrap our DocumentLoader to match jsonld's expected signature
    const wrappedLoader = async (url: string): Promise<any> => {
      return await documentLoader(url) as any;
    };

    // Canonicalize with timeout
    const nquads = await withTimeout(
      jsonld.canonize(doc, {
        algorithm: "URDNA2015",
        format: "application/n-quads",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        documentLoader: wrappedLoader as any,
      }),
      this.limits.maxWallClockMs,
    );

    const bytes = new TextEncoder().encode(nquads as string);

    // Post-check: output size
    if (bytes.byteLength > this.limits.maxOutputBytes) {
      throw new CanonicalizationResourceExceeded(
        `Output size (${bytes.byteLength} bytes) exceeds limit (${this.limits.maxOutputBytes})`
      );
    }

    return bytes;
  }
}

/**
 * Error thrown when canonicalization resource limits are exceeded (§7.7).
 */
export class CanonicalizationResourceExceeded extends Error {
  constructor(message: string) {
    super(`CANONICALIZATION_RESOURCE_EXCEEDED: ${message}`);
    this.name = "CanonicalizationResourceExceeded";
  }
}

/**
 * Count blank nodes in a JSON-LD document (heuristic: objects without @id).
 */
function countBlankNodes(value: unknown, count = 0): number {
  if (value === null || typeof value !== "object") return count;
  if (Array.isArray(value)) {
    for (const item of value) {
      count = countBlankNodes(item, count);
    }
    return count;
  }
  const obj = value as Record<string, unknown>;
  // An object without @id is a blank node in JSON-LD
  if (!("@id" in obj) && Object.keys(obj).length > 0) {
    count++;
  }
  for (const val of Object.values(obj)) {
    count = countBlankNodes(val, count);
  }
  return count;
}

/**
 * Wrap a promise with a timeout.
 */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new CanonicalizationResourceExceeded(`Wall-clock time exceeded ${ms}ms`)),
      ms,
    );
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}
