/**
 * Manifest and KeyDocument Construction
 *
 * Pure functions that build unsigned ResolutionManifest and KeyDocument
 * structures from parameters. No crypto operations — just structure assembly.
 *
 * Also includes content preparation (authority placeholder replacement
 * and canonicalization) for the signing pipeline.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import { stableStringify } from "./canonicalize.js";
import type {
  ManifestParams,
  KeyDocumentParams,
  UnsignedManifest,
  UnsignedKeyDocument,
} from "./types.js";

const HIRI_CONTEXT = "https://hiri-protocol.org/spec/v2.1";
const SECURITY_CONTEXT = "https://w3id.org/security/v2";

/**
 * Build an unsigned ResolutionManifest.
 * Pure and synchronous.
 */
export function buildUnsignedManifest(params: ManifestParams): UnsignedManifest {
  const manifest: UnsignedManifest = {
    "@context": [HIRI_CONTEXT, SECURITY_CONTEXT],
    "@id": params.id,
    "@type": "hiri:ResolutionManifest",
    "hiri:version": params.version,
    "hiri:branch": params.branch,
    "hiri:timing": {
      created: params.created,
    },
    "hiri:content": {
      hash: params.contentHash,
      format: params.contentFormat,
      size: params.contentSize,
      canonicalization: params.canonicalization,
    },
  };

  if (params.chain) {
    manifest["hiri:chain"] = params.chain;
  }

  if (params.delta) {
    manifest["hiri:delta"] = params.delta;
  }

  if (params.semantics) {
    manifest["hiri:semantics"] = params.semantics;
  }

  return manifest;
}

/**
 * Build an unsigned KeyDocument.
 * Pure and synchronous.
 */
export function buildKeyDocument(params: KeyDocumentParams): UnsignedKeyDocument {
  return {
    "@context": [HIRI_CONTEXT, SECURITY_CONTEXT],
    "@id": `hiri://${params.authority}/key/main`,
    "@type": "hiri:KeyDocument",
    "hiri:version": params.version,
    "hiri:authority": params.authority,
    "hiri:authorityType": params.authorityType,
    "hiri:activeKeys": params.activeKeys,
    "hiri:rotatedKeys": params.rotatedKeys ?? [],
    "hiri:revokedKeys": params.revokedKeys ?? [],
    "hiri:policies": params.policies,
  };
}

/**
 * Prepare content for hashing and manifest construction.
 *
 * Replaces the authority placeholder in all string values of the JSON-LD
 * document, then canonicalizes via JCS (stableStringify, compact form).
 *
 * Ordering: generate key → derive authority → prepareContent → hash → build manifest → sign
 *
 * @param jsonLd - The raw JSON-LD object
 * @param placeholder - The placeholder string to replace (e.g., "AUTHORITY_PLACEHOLDER")
 * @param authority - The actual derived authority string
 * @returns The canonical JSON string ready for hashing
 */
export function prepareContent(
  jsonLd: object,
  placeholder: string,
  authority: string,
): string {
  const replaced = replaceInObject(jsonLd, placeholder, authority);
  return stableStringify(replaced, false);
}

/**
 * Deep-replace a substring in all string values of an object.
 * Returns a new object (does not mutate input).
 */
function replaceInObject(
  value: unknown,
  search: string,
  replacement: string,
): unknown {
  if (typeof value === "string") {
    return value.split(search).join(replacement);
  }
  if (Array.isArray(value)) {
    return value.map((item) => replaceInObject(item, search, replacement));
  }
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      result[key] = replaceInObject(val, search, replacement);
    }
    return result;
  }
  return value;
}
