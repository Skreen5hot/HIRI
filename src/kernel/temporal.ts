/**
 * Temporal Utilities — Milestone 5
 *
 * Pure functions for ISO 8601 duration parsing, timestamp arithmetic,
 * and timestamp comparison. No Date constructor, no I/O.
 *
 * MVP scope: day-precision durations (PnD) only. Month/year durations
 * throw explicitly — they introduce calendar complexity not needed by M5.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

/**
 * Parse an ISO 8601 duration string to a day count.
 * Only supports PnD format (e.g., "P184D", "P365D").
 * Throws on month/year/time durations.
 */
export function parseDuration(iso8601: string): { days: number } {
  const match = /^P(\d+)D$/.exec(iso8601);
  if (!match) {
    throw new Error(
      `Unsupported ISO 8601 duration format: "${iso8601}". Only PnD (day) durations are supported.`,
    );
  }
  return { days: parseInt(match[1], 10) };
}

/**
 * Add a day-precision ISO 8601 duration to a timestamp.
 * Returns a new ISO 8601 timestamp.
 *
 * Uses manual date arithmetic (no Date constructor).
 * Handles month/year overflow correctly.
 *
 * @param timestamp - ISO 8601 UTC timestamp (e.g., "2025-07-01T00:00:00Z")
 * @param duration - ISO 8601 duration (e.g., "P184D")
 * @returns ISO 8601 UTC timestamp
 */
export function addDuration(timestamp: string, duration: string): string {
  const { days } = parseDuration(duration);
  const p = parseTimestamp(timestamp);

  // Add days with month/year overflow
  let { year, month, day } = addDaysToDate(p.year, p.month, p.day, days);

  return formatTimestamp(year, month, day, p.hour, p.minute, p.second, p.millis);
}

/**
 * Compare two ISO 8601 UTC timestamps.
 * Returns -1 if a < b, 0 if a === b, 1 if a > b.
 *
 * Parses to epoch milliseconds via manual string dissection.
 * Handles fractional seconds of varying lengths correctly.
 */
export function compareTimestamps(a: string, b: string): number {
  const ma = toEpochMillis(a);
  const mb = toEpochMillis(b);
  if (ma < mb) return -1;
  if (ma > mb) return 1;
  return 0;
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

interface ParsedTimestamp {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  millis: number;
}

function isLeapYear(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || (y % 400 === 0);
}

const DAYS_IN_MONTH = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function daysInMonth(y: number, m: number): number {
  if (m === 2 && isLeapYear(y)) return 29;
  return DAYS_IN_MONTH[m];
}

/**
 * Add a number of days to a date, handling month/year overflow.
 */
function addDaysToDate(
  year: number,
  month: number,
  day: number,
  numDays: number,
): { year: number; month: number; day: number } {
  day += numDays;
  while (day > daysInMonth(year, month)) {
    day -= daysInMonth(year, month);
    month++;
    if (month > 12) {
      month = 1;
      year++;
    }
  }
  return { year, month, day };
}

/**
 * Parse an ISO 8601 UTC timestamp string into components.
 * Requires Z suffix (UTC only).
 */
function parseTimestamp(ts: string): ParsedTimestamp {
  if (!ts.endsWith("Z")) {
    throw new Error(`Non-UTC timestamp not supported: "${ts}". Must end with Z.`);
  }

  const body = ts.slice(0, -1);
  const tIdx = body.indexOf("T");
  if (tIdx === -1) {
    throw new Error(`Invalid timestamp format: "${ts}". Missing T separator.`);
  }
  const datePart = body.slice(0, tIdx);
  const timePart = body.slice(tIdx + 1);

  // Parse date: YYYY-MM-DD
  const dateParts = datePart.split("-");
  if (dateParts.length !== 3) {
    throw new Error(`Invalid date format in timestamp: "${ts}".`);
  }
  const year = parseInt(dateParts[0], 10);
  const month = parseInt(dateParts[1], 10);
  const day = parseInt(dateParts[2], 10);

  // Parse time: HH:MM:SS or HH:MM:SS.fff
  const dotIdx = timePart.indexOf(".");
  let hms: string;
  let millis = 0;
  if (dotIdx !== -1) {
    hms = timePart.slice(0, dotIdx);
    const fracStr = timePart.slice(dotIdx + 1);
    // Normalize to 3 digits (milliseconds)
    const padded = (fracStr + "000").slice(0, 3);
    millis = parseInt(padded, 10);
  } else {
    hms = timePart;
  }

  const timeParts = hms.split(":");
  if (timeParts.length !== 3) {
    throw new Error(`Invalid time format in timestamp: "${ts}".`);
  }
  const hour = parseInt(timeParts[0], 10);
  const minute = parseInt(timeParts[1], 10);
  const second = parseInt(timeParts[2], 10);

  return { year, month, day, hour, minute, second, millis };
}

/**
 * Convert a parsed timestamp to epoch milliseconds.
 * Counts days from 1970-01-01 using cumulative day counting.
 */
function toEpochMillis(ts: string): number {
  const p = parseTimestamp(ts);

  // Count days from 1970-01-01 to the given date
  let totalDays = 0;

  // Full years from 1970 to (year - 1)
  for (let y = 1970; y < p.year; y++) {
    totalDays += isLeapYear(y) ? 366 : 365;
  }

  // Full months in the target year
  for (let m = 1; m < p.month; m++) {
    totalDays += daysInMonth(p.year, m);
  }

  // Days in the target month (1-indexed, so subtract 1)
  totalDays += p.day - 1;

  return (
    totalDays * 86400000 +
    p.hour * 3600000 +
    p.minute * 60000 +
    p.second * 1000 +
    p.millis
  );
}

/**
 * Format timestamp components back to ISO 8601 UTC string.
 */
function formatTimestamp(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  millis: number,
): string {
  const yStr = String(year).padStart(4, "0");
  const mStr = String(month).padStart(2, "0");
  const dStr = String(day).padStart(2, "0");
  const hStr = String(hour).padStart(2, "0");
  const minStr = String(minute).padStart(2, "0");
  const sStr = String(second).padStart(2, "0");

  if (millis > 0) {
    const msStr = String(millis).padStart(3, "0");
    return `${yStr}-${mStr}-${dStr}T${hStr}:${minStr}:${sStr}.${msStr}Z`;
  }
  return `${yStr}-${mStr}-${dStr}T${hStr}:${minStr}:${sStr}Z`;
}
