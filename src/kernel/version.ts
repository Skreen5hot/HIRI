/**
 * Version Parsing and Encoding (v3.1.1)
 *
 * Pure functions for handling HIRI version strings with BigInt support.
 * Versions are always positive integers (>= 1), encoded as strings.
 *
 * v3.1.1: hiri:version is ALWAYS a JSON string. Number input is rejected.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

/**
 * Parse a version string into a BigInt.
 *
 * @param version - A positive integer as string (e.g., "1", "42")
 * @returns The version as a BigInt
 * @throws If input is not a string, < 1, or not a valid integer
 */
export function parseVersion(version: string): bigint {
  if (typeof version !== "string") {
    throw new Error("Version must be a string");
  }

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
 * Encode a BigInt version to a string.
 *
 * @param version - The version as a BigInt
 * @returns The version as a string (always)
 */
export function encodeVersion(version: bigint): string {
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
  if (typeof version !== "string") {
    return { valid: false, reason: `Version must be a string, got: ${typeof version}` };
  }

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

/**
 * Check if current version is monotonically increasing from previous.
 *
 * @param current - The current version (string)
 * @param previous - The previous version (string)
 * @returns true if current > previous
 */
export function isMonotonicallyIncreasing(
  current: string,
  previous: string,
): boolean {
  return parseVersion(current) > parseVersion(previous);
}
