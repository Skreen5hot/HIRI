/**
 * Secure Document Loader (§7.5)
 *
 * Provides a JSON-LD document loader that resolves contexts from an
 * embedded registry. MUST NOT fetch remote URLs.
 *
 * Normative contexts (§7.6):
 * - https://hiri-protocol.org/spec/v3.1
 * - https://w3id.org/security/v2
 *
 * Non-standard contexts are supported via hiri:contextCatalog (§7.6).
 */

import type { DocumentLoader } from "../../kernel/types.js";

// ---------------------------------------------------------------------------
// Embedded Context: https://hiri-protocol.org/spec/v3.1
// ---------------------------------------------------------------------------

const HIRI_CONTEXT = {
  "@context": {
    "hiri": "https://hiri-protocol.org/ns/",
    "hiri:ResolutionManifest": { "@id": "hiri:ResolutionManifest" },
    "hiri:KeyDocument": { "@id": "hiri:KeyDocument" },
    "hiri:CanonicalContent": { "@id": "hiri:CanonicalContent" },
    "hiri:version": { "@id": "hiri:version" },
    "hiri:branch": { "@id": "hiri:branch" },
    "hiri:timing": { "@id": "hiri:timing" },
    "hiri:content": { "@id": "hiri:content" },
    "hiri:chain": { "@id": "hiri:chain" },
    "hiri:delta": { "@id": "hiri:delta" },
    "hiri:semantics": { "@id": "hiri:semantics" },
    "hiri:signature": { "@id": "hiri:signature" },
    "hiri:authority": { "@id": "hiri:authority" },
    "hiri:authorityType": { "@id": "hiri:authorityType" },
    "hiri:activeKeys": { "@id": "hiri:activeKeys", "@container": "@set" },
    "hiri:rotatedKeys": { "@id": "hiri:rotatedKeys", "@container": "@set" },
    "hiri:revokedKeys": { "@id": "hiri:revokedKeys", "@container": "@set" },
    "hiri:policies": { "@id": "hiri:policies" },
    "hiri:canonicalization": { "@id": "hiri:canonicalization" },
    "hiri:contextCatalog": { "@id": "hiri:contextCatalog" },
    "hash": { "@id": "hiri:hash" },
    "addressing": { "@id": "hiri:addressing" },
    "format": { "@id": "hiri:format" },
    "size": { "@id": "hiri:size" },
    "canonicalization": { "@id": "hiri:canonicalization" },
    "created": { "@id": "hiri:created" },
    "expires": { "@id": "hiri:expires" },
    "previous": { "@id": "hiri:previous" },
    "previousBranch": { "@id": "hiri:previousBranch" },
    "genesisHash": { "@id": "hiri:genesisHash" },
    "depth": { "@id": "hiri:depth" },
    "type": { "@id": "hiri:signatureType" },
    "verificationMethod": { "@id": "hiri:verificationMethod" },
    "proofPurpose": { "@id": "hiri:proofPurpose" },
    "proofValue": { "@id": "hiri:proofValue" },
    "controller": { "@id": "hiri:controller" },
    "publicKeyMultibase": { "@id": "hiri:publicKeyMultibase" },
    "purposes": { "@id": "hiri:purposes", "@container": "@set" },
    "validFrom": { "@id": "hiri:validFrom" },
    "validUntil": { "@id": "hiri:validUntil" },
    "rotatedAt": { "@id": "hiri:rotatedAt" },
    "rotatedTo": { "@id": "hiri:rotatedTo" },
    "reason": { "@id": "hiri:reason" },
    "verifyUntil": { "@id": "hiri:verifyUntil" },
    "revokedAt": { "@id": "hiri:revokedAt" },
    "manifestsInvalidAfter": { "@id": "hiri:manifestsInvalidAfter" },
    "gracePeriodAfterRotation": { "@id": "hiri:gracePeriodAfterRotation" },
    "minimumKeyValidity": { "@id": "hiri:minimumKeyValidity" },
    "entailmentMode": { "@id": "hiri:entailmentMode" },
    "baseRegime": { "@id": "hiri:baseRegime" },
    "vocabularies": { "@id": "hiri:vocabularies", "@container": "@set" },
    "appliesTo": { "@id": "hiri:appliesTo" },
    "operations": { "@id": "hiri:operations" },
  },
};

// ---------------------------------------------------------------------------
// Embedded Context: https://w3id.org/security/v2
// ---------------------------------------------------------------------------

const SECURITY_V2_CONTEXT = {
  "@context": {
    "id": "@id",
    "type": "@type",
    "dc": "http://purl.org/dc/terms/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "Ed25519VerificationKey2020": "sec:Ed25519VerificationKey2020",
    "Ed25519Signature2020": "sec:Ed25519Signature2020",
    "assertionMethod": { "@id": "sec:assertionMethod", "@type": "@id", "@container": "@set" },
    "authentication": { "@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set" },
    "controller": { "@id": "sec:controller", "@type": "@id" },
    "created": { "@id": "dc:created", "@type": "xsd:dateTime" },
    "domain": "sec:domain",
    "expires": { "@id": "sec:expiration", "@type": "xsd:dateTime" },
    "nonce": "sec:nonce",
    "proof": { "@id": "sec:proof", "@type": "@id" },
    "proofPurpose": { "@id": "sec:proofPurpose", "@type": "@vocab" },
    "proofValue": "sec:proofValue",
    "publicKeyMultibase": "sec:publicKeyMultibase",
    "verificationMethod": { "@id": "sec:verificationMethod", "@type": "@id" },
  },
};

// ---------------------------------------------------------------------------
// Context Registry
// ---------------------------------------------------------------------------

const EMBEDDED_CONTEXTS: Record<string, object> = {
  "https://hiri-protocol.org/spec/v3.1": HIRI_CONTEXT,
  "https://w3id.org/security/v2": SECURITY_V2_CONTEXT,
};

/**
 * Create a secure document loader with only the embedded normative contexts.
 * Throws on any URL not in the registry.
 */
export function createSecureDocumentLoader(): DocumentLoader {
  return async (url: string) => {
    const doc = EMBEDDED_CONTEXTS[url];
    if (doc) {
      return { document: doc, documentUrl: url };
    }
    throw new Error(`Secure document loader: unknown context URL "${url}". Remote fetch blocked.`);
  };
}

/**
 * Create a document loader that also resolves contexts from a manifest's
 * hiri:contextCatalog (§7.6). The catalog maps context URLs to their content.
 *
 * Falls back to the embedded registry for normative contexts.
 *
 * @param catalog - Map of context URL to context document
 */
export function createCatalogDocumentLoader(
  catalog: Record<string, object>,
): DocumentLoader {
  return async (url: string) => {
    // Check embedded contexts first
    const embedded = EMBEDDED_CONTEXTS[url];
    if (embedded) {
      return { document: embedded, documentUrl: url };
    }
    // Check catalog
    const catalogDoc = catalog[url];
    if (catalogDoc) {
      return { document: catalogDoc, documentUrl: url };
    }
    throw new Error(
      `Secure document loader: unknown context URL "${url}". ` +
      `Not in embedded registry or manifest contextCatalog. Remote fetch blocked.`
    );
  };
}
