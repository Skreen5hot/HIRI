# HIRI MVP Milestones v1.3
## Edge-Canonical Implementation Roadmap

**Version:** 1.3  
**Previous:** 1.2 (accepted as governing roadmap)  
**Last Updated:** February 2026  
**Governing Spec:** HIRI Protocol Specification v2.1.0

---

## v1.3 Revision Summary

v1.2 is accepted as the governing roadmap. v1.3 adds execution detail for Milestone 1, specifically:

| Addition | Purpose |
|----------|---------|
| **Canonical Harness** | TypeScript interfaces that enforce Edge-Canonical compliance before any signing logic exists |
| **Test Fixture: `person.jsonld`** | The raw input data for all Milestone 1 test cases |
| **Execution Sequence** | Step-by-step implementation order within Milestone 1, resolving dependency ordering |
| **KeyDocument fixture** | Minimal Key Document structure required for Milestone 1 verification |
| **Manifest output specification** | Exact expected structure of Milestone 1's primary output |

All v1.2 content (Milestones 2–5, Integration, Dependency Graph, Deferred Capabilities, Success Criteria) remains unchanged and is not reproduced here. This document is an addendum to v1.2, not a replacement.

---

## Milestone 1: The Verifiable Atom — Execution Detail

### Step 1: The Harness

These interfaces are defined before any implementation code. They are the constraints that force Edge-Canonical compliance. No library imports yet—just the shapes that all code must fit.

#### 1.1 Hash Algorithm Interface & Registry

```typescript
// Ensures no hardcoded hashing exists in the codebase.

export interface HashAlgorithm {
  readonly prefix: string; // e.g., "sha256"
  hash(content: Uint8Array): Promise<string>; // Returns "sha256:Qm..."
  verify(content: Uint8Array, hash: string): Promise<boolean>;
}

export class HashRegistry {
  private algos = new Map<string, HashAlgorithm>();

  register(algo: HashAlgorithm) {
    this.algos.set(algo.prefix, algo);
  }

  resolve(prefixedHash: string): HashAlgorithm {
    const [prefix] = prefixedHash.split(":");
    const algo = this.algos.get(prefix);
    if (!algo) throw new Error(`Unsupported Hash Algorithm: ${prefix}`);
    return algo;
  }

  // Convenience method for the default system algo
  async hash(content: Uint8Array, prefix: string = "sha256"): Promise<string> {
    const algo = this.algos.get(prefix);
    if (!algo) throw new Error(`Algorithm ${prefix} not registered`);
    return algo.hash(content);
  }
}
```

#### 1.2 HIRI URI Scheme

```typescript
// Ensures all logic operates on strict URIs, not string manipulation.

export class HiriURI {
  // Pattern: hiri://<authority>/<type>/<identifier>
  private static pattern = /^hiri:\/\/([^\/]+)\/([^\/]+)\/(.+)$/;

  constructor(
    public readonly authority: string,
    public readonly type: string,
    public readonly identifier: string
  ) {}

  static parse(uri: string): HiriURI {
    const match = uri.match(HiriURI.pattern);
    if (!match) throw new Error(`Invalid HIRI URI: ${uri}`);
    return new HiriURI(match[1], match[2], match[3]);
  }

  toString(): string {
    return `hiri://${this.authority}/${this.type}/${this.identifier}`;
  }
}
```

#### 1.3 Signature Interface

```typescript
// The shape of a spec-compliant signature block (§5.2).
// Implementation comes in Step 3.

export interface HiriSignature {
  type: string;                    // e.g., "Ed25519Signature2020"
  created: string;                 // ISO 8601
  verificationMethod: string;      // HIRI URI to key, e.g., "hiri://key:ed25519:.../key/main#key-1"
  proofPurpose: string;            // e.g., "assertionMethod"
  proofValue: string;              // Base58 or multibase-encoded signature
}

export interface SigningKey {
  algorithm: string;               // e.g., "ed25519"
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  keyId: string;                   // Fragment identifier, e.g., "key-1"
}

export interface Signer {
  sign(content: Uint8Array, key: SigningKey, timestamp: string): Promise<HiriSignature>;
  verify(content: Uint8Array, signature: HiriSignature, publicKey: Uint8Array): Promise<boolean>;
}
```

#### 1.4 Authority Derivation

```typescript
// Deterministic derivation of HIRI authority from public key.
// The authority string IS the key identity — self-certifying.

export interface AuthorityDerivation {
  /**
   * Derives the canonical authority string from a public key.
   * e.g., "key:ed25519:7Hf9sK3m..."
   * 
   * The hash is truncated to a specified length for usability.
   * The full public key is always available in the Key Document.
   */
  derive(publicKey: Uint8Array, algorithm: string): Promise<string>;

  /**
   * Builds the full HIRI URI for a resource under this authority.
   */
  buildURI(authority: string, type: string, identifier: string): HiriURI;
}
```

---

### Step 2: The Inputs

#### 2.1 Test Fixture: `person.jsonld`

This is the atomic unit of content that Milestone 1 wraps, signs, and verifies. It is deliberately small, uses standard Schema.org vocabulary, and contains enough structure to be meaningful for Milestone 4's SPARQL queries without being complex enough to distract from cryptographic concerns.

```json
{
  "@context": {
    "schema": "http://schema.org/",
    "hiri": "https://hiri-protocol.org/ns/",
    "xsd": "http://www.w3.org/2001/XMLSchema#"
  },
  "@id": "hiri://key:ed25519:AUTHORITY_PLACEHOLDER/data/person-001",
  "@type": "schema:Person",
  "schema:name": "Dana Reeves",
  "schema:birthDate": {
    "@type": "xsd:date",
    "@value": "1988-03-14"
  },
  "schema:address": {
    "@type": "schema:PostalAddress",
    "schema:addressLocality": "Portland",
    "schema:addressRegion": "OR",
    "schema:addressCountry": "US"
  },
  "schema:jobTitle": "Systems Architect",
  "schema:worksFor": {
    "@type": "schema:Organization",
    "schema:name": "Cascade Infrastructure Labs"
  }
}
```

**Design Notes:**

- `AUTHORITY_PLACEHOLDER` is replaced at signing time with the derived authority string from the generated keypair. This is intentional: the content's `@id` and the manifest's `@id` must share the same authority, and that authority is not known until the key exists.
- The `schema:birthDate` with explicit `xsd:date` typing is included specifically because it will be relevant for Milestone 4 (typed literal queries) and future ZK proof scenarios (age verification).
- `schema:address` is a nested object to test that hashing is stable across nested JSON-LD structures.
- No RDFS subclass relationships are present. This is deliberate: Milestone 4's entailment test (4.4) will introduce those separately to verify that the query engine does NOT infer them.

#### 2.2 Test Fixture: `person-v2.jsonld` (for Milestone 2, documented here for completeness)

```json
{
  "@context": {
    "schema": "http://schema.org/",
    "hiri": "https://hiri-protocol.org/ns/",
    "xsd": "http://www.w3.org/2001/XMLSchema#"
  },
  "@id": "hiri://key:ed25519:AUTHORITY_PLACEHOLDER/data/person-001",
  "@type": "schema:Person",
  "schema:name": "Dana Reeves",
  "schema:birthDate": {
    "@type": "xsd:date",
    "@value": "1988-03-14"
  },
  "schema:address": {
    "@type": "schema:PostalAddress",
    "schema:addressLocality": "Seattle",
    "schema:addressRegion": "WA",
    "schema:addressCountry": "US"
  },
  "schema:jobTitle": "Principal Systems Architect",
  "schema:worksFor": {
    "@type": "schema:Organization",
    "schema:name": "Cascade Infrastructure Labs"
  },
  "schema:email": "d.reeves@cascadeinfra.example"
}
```

**Delta from V1 → V2:** Three changes — address city/state updated (Portland OR → Seattle WA), job title promoted, email added. This produces a non-trivial JSON Patch for Milestone 2's delta verification.

---

### Step 3: Execution Sequence

The implementation order within Milestone 1 is dependency-driven. Each sub-step produces a testable artifact.

```
Step 3a: SHA256Algorithm
    │     Implement HashAlgorithm interface using Web Crypto API
    │     Test: hash known content, verify against known digest
    │
Step 3b: HashRegistry wiring
    │     Register SHA256Algorithm, test resolve/dispatch
    │     Test cases: 1.8, 1.9
    │
Step 3c: Ed25519 keypair generation
    │     Generate keypair, derive authority string
    │     Test case: 1.1
    │
Step 3d: Content preparation
    │     Load person.jsonld, replace AUTHORITY_PLACEHOLDER,
    │     canonicalize to deterministic byte sequence,
    │     hash via HashRegistry
    │
Step 3e: Manifest construction
    │     Build ResolutionManifest with all required fields
    │     (no signature yet — structure only)
    │
Step 3f: Signing
    │     Sign manifest using Ed25519, produce spec-compliant
    │     HiriSignature block
    │     Test case: 1.2
    │
Step 3g: Verification
    │     Verify manifest signature against public key
    │     Test cases: 1.3, 1.4, 1.5
    │
Step 3h: Genesis handling
    │     Verify genesis manifest accepted without chain,
    │     non-genesis rejected without chain
    │     Test cases: 1.6, 1.7
    │
Step 3i: KeyDocument construction
          Build minimal KeyDocument establishing authority
```

#### 3a–3b: Hashing

The SHA-256 implementation uses the Web Crypto API (`crypto.subtle.digest`), which is available in both Node.js and browsers. The hash output is hex-encoded with the `sha256:` prefix.

**Canonicalization requirement:** JSON-LD content must be serialized to a deterministic byte sequence before hashing. For MVP, we use JSON Canonicalization Scheme (JCS, RFC 8785) — deterministic key ordering, no whitespace, normalized Unicode. This ensures the same logical content always produces the same hash regardless of serialization order.

```typescript
// Canonical serialization before hashing
function canonicalize(jsonld: object): Uint8Array {
  // RFC 8785: JSON Canonicalization Scheme
  // - Sort keys lexicographically at all nesting levels
  // - No insignificant whitespace
  // - Normalize number representations
  // - Normalize Unicode to NFC
  const canonical = JSON.stringify(jsonld, Object.keys(jsonld).sort());
  return new TextEncoder().encode(canonical);
}
```

**Note:** Full JSON-LD canonicalization (URDNA2015 / RDF Dataset Canonicalization) is a heavier algorithm that normalizes at the RDF graph level. For MVP, JCS is sufficient because all content originates from a single authority and we control serialization. If cross-authority graph merging becomes necessary, URDNA2015 should replace JCS. This is a documented technical debt item, not an oversight.

#### 3c: Keypair and Authority Derivation

```
Input:  Ed25519 keypair generation (32-byte seed → 32-byte public key + 64-byte secret key)
Output: authority string = "key:ed25519:" + base58(sha256(publicKey))[0:20]
```

The authority is a truncated hash of the public key, not the raw key. This provides a stable, human-readable-ish identifier while the full key lives in the Key Document. The truncation length (20 characters of base58 ≈ 119 bits) provides collision resistance sufficient for identifier uniqueness without being unwieldy.

#### 3d–3e: Manifest Construction

After content hashing and authority derivation, the manifest is assembled. The expected output structure:

```json
{
  "@context": [
    "https://hiri-protocol.org/spec/v2.1",
    "https://w3id.org/security/v2"
  ],
  "@id": "hiri://key:ed25519:<derived-authority>/data/person-001",
  "@type": "hiri:ResolutionManifest",

  "hiri:version": 1,
  "hiri:branch": "main",

  "hiri:timing": {
    "created": "<ISO-8601-timestamp>"
  },

  "hiri:content": {
    "hash": "sha256:<content-digest>",
    "format": "application/ld+json",
    "size": "<byte-count>",
    "canonicalization": "JCS"
  },

  "hiri:signature": {
    "type": "Ed25519Signature2020",
    "created": "<ISO-8601-timestamp>",
    "verificationMethod": "hiri://key:ed25519:<derived-authority>/key/main#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base58-encoded-signature>"
  }
}
```

**Fields absent by design (genesis manifest):**
- `hiri:chain` — absent because this is genesis (version 1). Test 1.6 verifies acceptance; test 1.7 verifies rejection when version > 1 and chain is absent.
- `hiri:delta` — absent because there is no previous version.
- `hiri:contentLayers` — deferred (single-layer content only in MVP).
- `hiri:semantics` — will be added in Milestone 4 when entailment mode becomes relevant.

#### 3f–3g: Signing and Verification

The signing target is the manifest *without* the `hiri:signature` field. That is: construct the manifest, remove or omit the signature block, canonicalize that structure (JCS), sign the resulting bytes, then attach the signature block.

The verification algorithm reverses this: extract the signature block, reconstruct the unsigned manifest, canonicalize, and verify.

```
Sign:   manifest_bytes = canonicalize(manifest - signature) → sign(manifest_bytes, privateKey) → signature
Verify: manifest_bytes = canonicalize(manifest - signature) → verify(manifest_bytes, signature, publicKey) → boolean
```

#### 3h: Genesis Handling

The verifier must distinguish genesis from non-genesis:

```typescript
function isGenesisValid(manifest: ResolutionManifest): boolean {
  if (manifest.version === 1 && !manifest.chain) return true;   // Valid genesis
  if (manifest.version === 1 && manifest.chain) return true;     // Also valid: V1 can optionally chain
  if (manifest.version > 1 && !manifest.chain) return false;     // Invalid: non-genesis must chain
  return true;                                                    // V > 1 with chain: check chain in M2
}
```

#### 3i: Minimal KeyDocument

Milestone 1 requires a minimal Key Document. The full lifecycle (rotation, revocation, recovery) is Milestone 5. This structure establishes the authority and its active key.

```json
{
  "@context": [
    "https://hiri-protocol.org/spec/v2.1",
    "https://w3id.org/security/v2"
  ],
  "@id": "hiri://key:ed25519:<derived-authority>/key/main",
  "@type": "hiri:KeyDocument",

  "hiri:version": 1,

  "hiri:authority": "key:ed25519:<derived-authority>",
  "hiri:authorityType": "key",

  "hiri:activeKeys": [
    {
      "@id": "hiri://key:ed25519:<derived-authority>/key/main#key-1",
      "@type": "Ed25519VerificationKey2020",
      "controller": "hiri://key:ed25519:<derived-authority>/key/main",
      "publicKeyMultibase": "z6Mk<base58-encoded-public-key>",
      "purposes": ["assertionMethod"],
      "validFrom": "<ISO-8601-timestamp>"
    }
  ],

  "hiri:rotatedKeys": [],
  "hiri:revokedKeys": [],

  "hiri:policies": {
    "gracePeriodAfterRotation": "P180D",
    "minimumKeyValidity": "P365D"
  },

  "hiri:signature": {
    "type": "Ed25519Signature2020",
    "created": "<ISO-8601-timestamp>",
    "verificationMethod": "hiri://key:ed25519:<derived-authority>/key/main#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base58-encoded-signature>"
  }
}
```

**Note:** The Key Document is self-signed by the key it establishes. This is the self-certifying property: the authority *is* the key, and the Key Document's validity is verified against that same key. No external trust anchor.

---

### Step 4: Test Execution

All tests from v1.2 Milestone 1 test matrix (1.1–1.9), executed against the artifacts produced in Step 3. Reproduced here with implementation notes:

| # | Test Case | Artifact Under Test | Pass Condition |
|---|-----------|---------------------|----------------|
| 1.1 | Generate keypair, derive HIRI authority URI | `AuthorityDerivation.derive()` | URI matches `hiri://key:ed25519:<20-char-base58>/...` pattern |
| 1.2 | Sign `person.jsonld`, produce manifest | `Signer.sign()` + manifest builder | Manifest contains valid `@id`, `hiri:content.hash`, `hiri:signature` per §5.2 |
| 1.3 | Verify manifest against public key | `Signer.verify()` | Returns `true` |
| 1.4 | Modify one byte of content, re-verify | `Signer.verify()` with tampered content | Returns `false` |
| 1.5 | Modify signature, re-verify against original content | `Signer.verify()` with tampered signature | Returns `false` |
| 1.6 | Genesis manifest (version 1, no chain) | `isGenesisValid()` | Returns `true` |
| 1.7 | Non-genesis manifest (version 2, no chain) | `isGenesisValid()` | Returns `false` |
| 1.8 | Hash string `sha256:Qm...` resolved via registry | `HashRegistry.resolve()` | Returns `SHA256Algorithm` instance |
| 1.9 | Hash string `blake3:Qm...` with no registered algorithm | `HashRegistry.resolve()` | Throws `UnsupportedHashAlgorithm` |

---

### Documented Technical Debt

Items that are conscious simplifications in Milestone 1, with their resolution milestone:

| Item | Simplification | Resolution |
|------|----------------|------------|
| **Canonicalization** | JCS (RFC 8785) instead of URDNA2015 | Replace if cross-authority graph merging is needed (post-MVP) |
| **Authority truncation** | 20 chars base58 (~119 bits) | Evaluate collision risk at scale; may need to extend |
| **Key encoding** | `publicKeyMultibase` using `z` prefix (base58btc) | Spec-compliant but may need multicodec prefix for multi-algorithm support |
| **Timestamp source** | `Date.now()` / system clock | Milestone 5 introduces mock clock; TSA integration is post-MVP |
| **Manifest canonicalization** | JCS for signing target | Same as content canonicalization note above |
| **KeyDocument self-signing** | Bootstrap circularity is accepted for key-based authority | Consortium authorities (post-MVP) require different trust model |

---

## Execution Order

```
1. Create project structure and TypeScript config
2. Implement harness interfaces (Step 1: copy verbatim, no modifications)
3. Implement SHA256Algorithm + HashRegistry (Step 3a–3b)
4. Run tests 1.8, 1.9
5. Implement Ed25519 keypair generation + authority derivation (Step 3c)
6. Run test 1.1
7. Implement content preparation + canonicalization (Step 3d)
8. Implement manifest construction (Step 3e)
9. Implement signing (Step 3f)
10. Run test 1.2
11. Implement verification (Step 3g)
12. Run tests 1.3, 1.4, 1.5
13. Implement genesis validation (Step 3h)
14. Run tests 1.6, 1.7
15. Construct KeyDocument (Step 3i)
16. All 9 tests green → Milestone 1 complete
```

---

*v1.2 remains the governing document for Milestones 2–5 and Integration. This addendum provides execution detail for Milestone 1 only.*
