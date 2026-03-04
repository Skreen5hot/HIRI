/**
 * Version Parsing and Encoding
 *
 * Pure functions for handling HIRI version numbers with BigInt support.
 * Versions are always positive integers (>= 1).
 *
 * The hiri:version field in manifests is typed as `number` for now.
 * These functions provide a migration path for versions > MAX_SAFE_INTEGER
 * via string encoding.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

/**
 * Parse a version value (number or string) into a BigInt.
 *
 * @param version - A positive integer as number or string
 * @returns The version as a BigInt
 * @throws If the version is < 1, non-integer, or exceeds MAX_SAFE_INTEGER for number type
 */
export function parseVersion(version: number | string): bigint {
  if (typeof version === "number") {
    if (!Number.isInteger(version)) {
      throw new Error(`Version must be an integer, got: ${version}`);
    }
    if (version > Number.MAX_SAFE_INTEGER) {
      throw new Error(
        `Version exceeds MAX_SAFE_INTEGER (${Number.MAX_SAFE_INTEGER}), use string encoding`,
      );
    }
    if (version < 1) {
      throw new Error(`Version must be >= 1, got: ${version}`);
    }
    return BigInt(version);
  }

  // String input
  let parsed: bigint;
  try {
    parsed = BigInt(version);
  } catch {
    throw new Error(`Invalid version string: "${version}"`);
  }

  if (parsed < 1n) {
    throw new Error(`Version must be >= 1, got: ${version}`);
  }

  return parsed;
}

/**
 * Encode a BigInt version back to number or string.
 *
 * Returns a number if the value fits safely in a JavaScript number,
 * otherwise returns a string.
 *
 * @param version - The version as a BigInt
 * @returns number if safe, string if large
 */
export function encodeVersion(version: bigint): number | string {
  if (version <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(version);
  }
  return version.toString();
}

/**
 * Validate a version value without throwing.
 *
 * @param version - The value to validate
 * @returns Validation result with optional reason
 */
export function validateVersion(
  version: unknown,
): { valid: boolean; reason?: string } {
  if (typeof version === "number") {
    if (!Number.isInteger(version)) {
      return { valid: false, reason: `Version must be an integer, got: ${version}` };
    }
    if (version > Number.MAX_SAFE_INTEGER) {
      return {
        valid: false,
        reason: `Version exceeds MAX_SAFE_INTEGER, use string encoding`,
      };
    }
    if (version < 1) {
      return { valid: false, reason: `Version must be >= 1, got: ${version}` };
    }
    return { valid: true };
  }

  if (typeof version === "string") {
    try {
      const parsed = BigInt(version);
      if (parsed < 1n) {
        return { valid: false, reason: `Version must be >= 1, got: ${version}` };
      }
      return { valid: true };
    } catch {
      return { valid: false, reason: `Invalid version string: "${version}"` };
    }
  }

  return { valid: false, reason: `Version must be a number or string, got: ${typeof version}` };
}

/**
 * Check if current version is monotonically increasing from previous.
 *
 * @param current - The current version (number or string)
 * @param previous - The previous version (number or string)
 * @returns true if current > previous
 */
export function isMonotonicallyIncreasing(
  current: number | string,
  previous: number | string,
): boolean {
  return parseVersion(current) > parseVersion(previous);
}
