/**
 * Deterministic Canonicalization
 *
 * Provides stable serialization of JSON values by recursively sorting
 * object keys and optionally sorting unordered arrays. This ensures
 * that identical data structures produce identical string representations
 * regardless of property insertion order.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

/**
 * Recursively canonicalize a value by sorting object keys.
 * Arrays are preserved in their original order (caller is responsible
 * for ensuring semantic ordering if needed).
 *
 * @param value - Any JSON-serializable value
 * @returns A new value with all object keys sorted recursively
 */
function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  // Plain object: sort keys lexicographically
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const sorted: Record<string, unknown> = {};
  for (const key of keys) {
    sorted[key] = canonicalize(obj[key]);
  }
  return sorted;
}

/**
 * Produce a deterministic JSON string from any JSON-serializable value.
 *
 * Object keys are sorted recursively. Arrays preserve element order.
 * The output is suitable for deterministic comparison and hashing.
 *
 * @param value - Any JSON-serializable value
 * @param pretty - If true, output is indented with 2 spaces (default: false)
 * @returns A deterministic JSON string
 */
export function stableStringify(value: unknown, pretty: boolean = false): string {
  const canonical = canonicalize(value);
  return pretty
    ? JSON.stringify(canonical, null, 2)
    : JSON.stringify(canonical);
}
