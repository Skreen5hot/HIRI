/**
 * Kernel Transform Function
 *
 * Pure function: JSON-LD → JSON-LD
 * MUST be deterministic. MUST NOT perform I/O.
 * MUST NOT reference Date, Math.random, fetch, or any non-deterministic API.
 *
 * This is the identity transform — the template's starting point.
 * Consumers replace the transformation logic with their domain-specific rules.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A valid JSON-LD document. MUST include @context. */
export interface JsonLdDocument {
  "@context": string | Record<string, unknown> | Array<string | Record<string, unknown>>;
  [key: string]: unknown;
}

/** Deterministic provenance metadata. No timestamps. */
export interface Provenance {
  "@type": "Provenance";
  kernelVersion: string;
  rulesApplied: string[];
}

/** Uncertainty annotation for unresolved values. */
export interface UncertaintyAnnotation {
  "@type": "Uncertainty";
  status: "deferred" | "assumed" | "unknown";
  reason: string;
  references: string[];
}

/** Successful transform output. */
export interface TransformOutput extends JsonLdDocument {
  provenance: Provenance;
}

/** Error output returned for invalid input. */
export interface TransformError {
  "@context": "https://schema.org";
  "@type": "Error";
  errorCode: string;
  error: string;
  provenance: Provenance;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Static kernel version. Update when making breaking changes. */
const KERNEL_VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Transform
// ---------------------------------------------------------------------------

/**
 * Pure deterministic transformation.
 *
 * Given a JSON-LD input document, produces a JSON-LD output document.
 * This is the identity transform — the template's starting point.
 * Consumers replace the body with their domain-specific transformation logic.
 *
 * The function never throws for any input. Invalid input produces a
 * well-formed JSON-LD error object with a stable error code.
 *
 * @param input - A value expected to be a valid JSON-LD document
 * @returns A new JSON-LD document (never mutates input)
 */
export function transform(input: unknown): TransformOutput | TransformError {
  // -----------------------------------------------------------------------
  // Input validation — return error objects, never throw
  // -----------------------------------------------------------------------

  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return makeError("INVALID_INPUT", "Input must be a non-null, non-array object");
  }

  const doc = input as Record<string, unknown>;

  if (!("@context" in doc)) {
    return makeError("INVALID_CONTEXT", "Input must include an @context property");
  }

  // -----------------------------------------------------------------------
  // Identity transform
  //
  // Deep-clone the input to guarantee immutability, then attach provenance.
  // Replace this section with domain-specific transformation rules.
  // Each rule should be named in rulesApplied for traceability.
  // -----------------------------------------------------------------------

  const output = structuredClone(doc) as JsonLdDocument;

  return {
    ...output,
    provenance: {
      "@type": "Provenance",
      kernelVersion: KERNEL_VERSION,
      rulesApplied: ["identity"],
    },
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function makeError(errorCode: string, message: string): TransformError {
  return {
    "@context": "https://schema.org",
    "@type": "Error",
    errorCode,
    error: message,
    provenance: {
      "@type": "Provenance",
      kernelVersion: KERNEL_VERSION,
      rulesApplied: [],
    },
  };
}
