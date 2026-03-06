/**
 * JCS Canonicalizer
 *
 * Kernel-safe Canonicalizer implementation using JCS (stableStringify).
 * Ignores the documentLoader parameter — JCS does not resolve JSON-LD contexts.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { stableStringify } from "./canonicalize.js";
import type { Canonicalizer, DocumentLoader } from "./types.js";

export class JCSCanonicalizer implements Canonicalizer {
  async canonicalize(
    doc: Record<string, unknown>,
    _documentLoader: DocumentLoader,
  ): Promise<Uint8Array> {
    const canonical = stableStringify(doc, false);
    return new TextEncoder().encode(canonical);
  }
}
