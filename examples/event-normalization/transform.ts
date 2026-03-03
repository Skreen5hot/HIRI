/**
 * Event Normalization Transform — Reference Example
 *
 * Demonstrates a real-world transform for Schema.org Event documents.
 * This is NOT part of the kernel — it is a standalone example showing
 * how consumers implement domain-specific transformation logic.
 *
 * Rules applied:
 *   1. normalize-event-name       — Title-case the event name
 *   2. trim-description           — Strip leading/trailing whitespace
 *   3. infer-location-type        — Add @type "Place" if missing
 *   4. infer-address-type         — Add @type "PostalAddress" if missing
 *   5. normalize-organizer-name   — Title-case organizer name
 *   6. normalize-event-status     — Map to Schema.org EventStatusType URI
 *   7. annotate-missing-end-date  — Flag missing endDate
 *   8. annotate-missing-duration  — Flag uncomputable duration
 *
 * Operates on the literal input graph. Does NOT expand or resolve contexts.
 */

import type {
  JsonLdDocument,
  Provenance,
  UncertaintyAnnotation,
  TransformOutput,
  TransformError,
} from "../../src/kernel/transform.js";

const KERNEL_VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Pure helper functions
// ---------------------------------------------------------------------------

/** Title-case an ASCII string: "quarterly PLANNING meeting" → "Quarterly Planning Meeting" */
function titleCase(str: string): string {
  return str
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 0)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Map common status strings to Schema.org EventStatusType URIs. */
const STATUS_MAP: Record<string, string> = {
  scheduled: "https://schema.org/EventScheduled",
  cancelled: "https://schema.org/EventCancelled",
  postponed: "https://schema.org/EventPostponed",
  rescheduled: "https://schema.org/EventRescheduled",
  movedOnline: "https://schema.org/EventMovedOnline",
};

function normalizeStatus(raw: unknown): string | unknown {
  if (typeof raw !== "string") return raw;
  return STATUS_MAP[raw.toLowerCase()] ?? raw;
}

function makeUncertainty(
  status: UncertaintyAnnotation["status"],
  reason: string,
  references: string[] = [],
): { uncertainty: UncertaintyAnnotation } {
  return {
    uncertainty: {
      "@type": "Uncertainty",
      status,
      reason,
      references,
    },
  };
}

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

// ---------------------------------------------------------------------------
// Main transform
// ---------------------------------------------------------------------------

export function transformEvent(input: unknown): TransformOutput | TransformError {
  // --- Input validation (same pattern as kernel) ---
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return makeError("INVALID_INPUT", "Input must be a non-null, non-array object");
  }

  const doc = input as Record<string, unknown>;

  if (!("@context" in doc)) {
    return makeError("INVALID_CONTEXT", "Input must include an @context property");
  }

  // --- Deep clone to guarantee immutability ---
  const out = structuredClone(doc) as Record<string, unknown>;
  const rules: string[] = [];

  // Rule 1: normalize-event-name
  if (typeof out.name === "string") {
    out.name = titleCase(out.name);
    rules.push("normalize-event-name");
  }

  // Rule 2: trim-description
  if (typeof out.description === "string") {
    out.description = out.description.trim();
    rules.push("trim-description");
  }

  // Rule 3 & 4: infer location and address types
  if (out.location && typeof out.location === "object" && !Array.isArray(out.location)) {
    const loc = out.location as Record<string, unknown>;
    if (!("@type" in loc)) {
      loc["@type"] = "Place";
      rules.push("infer-location-type");
    }
    if (loc.address && typeof loc.address === "object" && !Array.isArray(loc.address)) {
      const addr = loc.address as Record<string, unknown>;
      if (!("@type" in addr)) {
        addr["@type"] = "PostalAddress";
        rules.push("infer-address-type");
      }
    }
  }

  // Rule 5: normalize-organizer-name
  if (out.organizer && typeof out.organizer === "object" && !Array.isArray(out.organizer)) {
    const org = out.organizer as Record<string, unknown>;
    if (typeof org.name === "string") {
      org.name = titleCase(org.name);
      rules.push("normalize-organizer-name");
    }
  }

  // Rule 6: normalize-event-status
  if ("eventStatus" in out) {
    const normalized = normalizeStatus(out.eventStatus);
    if (normalized !== out.eventStatus) {
      out.eventStatus = normalized;
      rules.push("normalize-event-status");
    }
  }

  // Rule 7: annotate-missing-end-date
  if (!("endDate" in out) || out.endDate === undefined) {
    out.endDate = null;
    rules.push("annotate-missing-end-date");
  }

  // Rule 8: annotate-missing-duration
  if (!("duration" in out) || out.duration === undefined) {
    if (out.endDate === null) {
      out.duration = makeUncertainty(
        "unknown",
        "Cannot compute duration without endDate",
        ["endDate"],
      );
      rules.push("annotate-missing-duration");
    }
  }

  // --- Attach provenance ---
  const provenance: Provenance = {
    "@type": "Provenance",
    kernelVersion: KERNEL_VERSION,
    rulesApplied: rules,
  };

  return {
    ...(out as JsonLdDocument),
    provenance,
  };
}
