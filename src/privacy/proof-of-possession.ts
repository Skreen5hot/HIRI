/**
 * Proof of Possession (Mode 1) — Milestone 10
 *
 * Implements §6 of the Privacy Extension v1.4.1.
 * PoP manifests prove the publisher holds content without revealing it.
 * Content is NOT fetched during resolution.
 *
 * This module is Layer 2 (Privacy) and MAY import from Layer 0 (Kernel).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProofOfPossessionParams {
  availability: "private";
  custodyAssertion: boolean;
  refreshPolicy?: string; // ISO 8601 duration, e.g., "P30D"
}

export interface ProofOfPossessionResult {
  verified: true;
  contentStatus: "private-custody-asserted";
  contentHash: string;
  custodyAssertedAt: string;
  refreshPolicy?: string;
  stale: boolean;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// ISO 8601 Duration Parsing (subset: PnYnMnDTnHnMnS)
// ---------------------------------------------------------------------------

/**
 * Parse an ISO 8601 duration string to milliseconds.
 * Supports: P[n]Y[n]M[n]D[T[n]H[n]M[n]S]
 *
 * Approximations: 1Y = 365d, 1M = 30d (per common convention).
 */
export function parseDurationMs(duration: string): number {
  const match = duration.match(
    /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/,
  );
  if (!match) {
    throw new Error(`Invalid ISO 8601 duration: ${duration}`);
  }

  const years = parseInt(match[1] || "0", 10);
  const months = parseInt(match[2] || "0", 10);
  const days = parseInt(match[3] || "0", 10);
  const hours = parseInt(match[4] || "0", 10);
  const minutes = parseInt(match[5] || "0", 10);
  const seconds = parseInt(match[6] || "0", 10);

  const MS_PER_SECOND = 1000;
  const MS_PER_MINUTE = 60 * MS_PER_SECOND;
  const MS_PER_HOUR = 60 * MS_PER_MINUTE;
  const MS_PER_DAY = 24 * MS_PER_HOUR;

  return (
    years * 365 * MS_PER_DAY +
    months * 30 * MS_PER_DAY +
    days * MS_PER_DAY +
    hours * MS_PER_HOUR +
    minutes * MS_PER_MINUTE +
    seconds * MS_PER_SECOND
  );
}

// ---------------------------------------------------------------------------
// Custody Staleness Check
// ---------------------------------------------------------------------------

/**
 * Check if a custody assertion is stale based on refreshPolicy and created timestamp.
 *
 * Rules:
 * - No refreshPolicy → never stale (returns false)
 * - refreshPolicy present → stale if verificationTime > created + duration
 */
export function isCustodyStale(
  created: string,
  refreshPolicy: string | undefined,
  verificationTime: string,
): boolean {
  if (!refreshPolicy) {
    return false;
  }

  const createdMs = new Date(created).getTime();
  const verificationMs = new Date(verificationTime).getTime();
  const durationMs = parseDurationMs(refreshPolicy);

  return verificationMs > createdMs + durationMs;
}
