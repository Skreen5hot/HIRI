# HIRI MVP Milestones v3
## v3.1.1 Upgrade: Milestones 6–9

**Version:** 3.0
**Previous:** v1.4 (Milestones 1–5 execution detail)
**Last Updated:** March 2026
**Governing Spec:** HIRI Protocol Specification v3.1.1
**Target Conformance:** Level 2 — Interoperable (§18.2)

---

## Preamble

Milestones 1–5 delivered a complete, tested v2.1.0 implementation: 75 tests across 4 suites, a browser demo, CI/CD, and a public site. The implementation proved the core thesis — edge-canonical, verifiable semantic knowledge with no network dependency.

v3.1.1 is a breaking upgrade. It changes authority derivation, adds canonicalization profiles, introduces content addressing modes, unifies version encoding, and couples delta formats to canonicalization. These are not incremental features — they require coordinated changes across the type system, signing pipeline, chain walker, and resolution logic.

**Strategy: Clean Break.** All v2.1.0 fixtures and test assertions are rewritten for v3.1.1. No backward compatibility layer. No migration code. The implementation jumps from v2.1.0 to v3.1.1 in a single coordinated pass. This is justified because:

1. The codebase has a single consumer (our own tests and demo)
2. No third-party integrations exist yet
3. Migration code adds complexity that would never be exercised after the upgrade
4. A clean break lets us validate v3.1.1 semantics without v2.1.0 interference

**Scope:** Kernel (`src/kernel/`) and tests (`tests/`) only. Adapters and demo are updated in a separate follow-up. Each milestone proves its invariants through tests — no milestone ships without green CI.

**TSA Policy:** Timestamp Authority fields (`timestampVerification`, `timestampProof`) are present in all verification reports but report-only. `timestampVerification` returns `"advisory-only"` when no TSA proof exists, or `"tsa-present-unverified"` when a proof blob is present but cannot be verified (no TSA verification infrastructure in scope). Actual TSA verification is deferred.

---

## Current Implementation State

| Phase | Milestone | Status | Tests |
|-------|-----------|--------|-------|
| Phase 1 | M1: Verifiable Atom | **Complete** | 21/21 |
| Phase 2 | M2: Deterministic Chain | **Complete** | 18/18 |
| Phase 2.5 | Persistence Infrastructure | **Complete** | 9/9 |
| Phase 3 | M3: Abstracted Resolver | **Complete** | 8/8 |
| Phase 4 | M4: Storeless Oracle | **Complete** | 11/11 |
| Phase 5 | M5: Sovereign Authority | **Complete** | 8/8 |
| — | M6: v3.1.1 Core Migration | **Not started** | 0 |
| — | M7: URDNA2015 Profile | **Not started** | 0 |
| — | M8: CIDv1 Content Addressing | **Not started** | 0 |
| — | M9: Level 2 Integration | **Not started** | 0 |

**Total existing tests:** 75 (4 files)
**Post-M6 expected tests:** ~95 (existing rewritten + new rejection tests)
**Post-M9 expected tests:** ~141 (full Level 2 coverage)

---

## Dependency Graph

```
M6: v3.1.1 Core Migration
 ├── M7: URDNA2015 Profile (depends on M6 type system + profile-aware signing)
 ├── M8: CIDv1 Content Addressing (depends on M6 addressing field + HashRegistry)
 │
 └── M9: Level 2 Integration (depends on M7 + M8)
         ├── RDF Patch (depends on M7 URDNA2015)
         ├── Cross-profile integration tests
         └── Level 2 conformance declaration
```

M7 and M8 are independent of each other. Both depend on M6. M9 depends on both.

---

## Milestone 6: v3.1.1 Core Migration (The Clean Break)

### Objective

Apply all v3.1.1 breaking changes to the existing JCS + raw-sha256 path. After M6, every existing capability works identically but uses v3.1.1 data formats. All 75 existing tests pass with v3.1.1-compliant fixtures. New tests cover v3.1.1 rejection semantics.

### What This Milestone Proves

That the v2.1.0 → v3.1.1 type system migration is complete and sound. The full-key authority is self-certifying. Profile symmetry is enforced. Delta–canonicalization coupling is validated. Version encoding is string-only. Verification reports include revocation and timestamp status. The JCS + raw-sha256 path is fully v3.1.1 compliant.

### Breaking Changes Applied

| Change | Spec Section | Files Modified |
|--------|-------------|----------------|
| Full-key authority (no truncation, `z` prefix) | §5.1 | `authority.ts`, `types.ts` |
| `hiri:version` string-only | §9.2, §11.3 | `version.ts`, `types.ts`, `manifest.ts` |
| `hiri:content.addressing` field | §8.3 | `types.ts`, `manifest.ts` |
| `hiri:signature.canonicalization` field | §10.1 | `types.ts`, `signing.ts`, `manifest.ts` |
| Profile Symmetry Rule | §7.3 | `signing.ts` |
| Delta format MIME types | §11.4.2 | `delta.ts`, `types.ts` |
| Delta–canonicalization coupling | §11.4.1 | `delta.ts` |
| Verification status reporting | §13.6 | `key-lifecycle.ts`, `types.ts` |
| Context URL v2.1 → v3.1 | §7.6 | `manifest.ts` |

### 6.A — Type System Updates (`types.ts`)

```typescript
// Authority: no change to string type, but derivation changes (see 6.B)

// Version: number → string
export interface UnsignedManifest {
  "hiri:version": string;  // Was: number | string
  // ...
}

// Content: add addressing field
export interface ManifestContent {
  hash: string;
  addressing: string;         // NEW: "raw-sha256" | "cidv1-dag-cbor"
  canonicalization: string;   // "JCS" | "URDNA2015"
  format: string;
  size: number;
}

// Signature: add canonicalization field
export interface HiriSignature {
  type: string;
  canonicalization: string;   // NEW: "JCS" | "URDNA2015"
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
}

// Delta: MIME-typed format
export interface ManifestDelta {
  hash: string;
  format: string;    // "application/json-patch+json" | "application/rdf-patch"
  appliesTo: string;
  operations: number;
}

// Verification: extended status reporting
export interface VerificationStatus {
  signatureValid: boolean;
  keyStatus: KeyStatus;
  revocationStatus: "confirmed-valid" | "confirmed-revoked" | "unknown";
  timestampVerification: "tsa-verified" | "tsa-present-unverified" | "advisory-only" | "absent";
}
```

**Constraint:** All interfaces that reference `hiri:version` must accept `string` only. The `number` type is removed entirely.

### 6.B — Authority Derivation (`authority.ts`)

**Current:** `base58(sha256(publicKey)).substring(0, 20)` → `key:ed25519:<truncated>`

**v3.1.1:** `"z" + base58btc(publicKey)` → `key:ed25519:z<full-key>`

```typescript
export function deriveAuthority(publicKey: Uint8Array, algorithm: string): string {
  if (publicKey.length !== 32) throw new Error("Invalid key length");
  if (algorithm !== "ed25519") throw new Error("Unsupported algorithm");
  const encoded = "z" + base58Encode(publicKey);
  return `key:${algorithm}:${encoded}`;
}

export function extractPublicKey(authority: string): {
  algorithm: string;
  publicKey: Uint8Array;
} {
  const match = authority.match(/^key:([a-z0-9]+):(z[A-Za-z0-9]+)$/);
  if (!match) throw new Error("Invalid authority format");
  const [, algorithm, encoded] = match;
  const publicKey = base58Decode(encoded.slice(1));  // Strip 'z' for decode
  return { algorithm, publicKey };
}
```

**Invariant (Appendix B.1):**
```
extractPublicKey(deriveAuthority(pk, "ed25519")).publicKey === pk
```

**Impact:** `deriveAuthorityAsync` is removed — authority derivation no longer requires hashing, so it is synchronous. Every function that called `deriveAuthorityAsync` switches to `deriveAuthority`.

### 6.C — Version Encoding (`version.ts`)

```typescript
export function parseVersion(version: string): bigint   // Rejects number input
export function encodeVersion(version: bigint): string   // Always returns string
export function validateVersion(version: unknown): { valid: boolean; reason?: string }
export function isMonotonicallyIncreasing(current: string, previous: string): boolean
```

All functions accept and return `string` only. `typeof version !== "string"` → throw.

### 6.D — Manifest Builder (`manifest.ts`)

Updated `ManifestParams`:

```typescript
export interface ManifestParams {
  id: string;
  version: string;              // Was: number
  branch: string;
  contentHash: string;
  addressing: string;           // NEW: "raw-sha256"
  canonicalization: string;     // "JCS"
  contentFormat: string;
  contentSize: number;
  chain?: ChainParams;
  delta?: DeltaParams;
  entailmentMode?: string;
}
```

Context URL: `"https://hiri-protocol.org/spec/v3.1"` (was v2.1).

### 6.E — Signing Pipeline (`signing.ts`)

```typescript
export async function signManifest(
  unsigned: UnsignedManifest,
  key: SigningKey,
  timestamp: string,
  profile: "JCS" | "URDNA2015",  // NEW parameter
  crypto: CryptoProvider,
): Promise<ResolutionManifest>
```

Steps:
1. Enforce Profile Symmetry: `unsigned["hiri:content"].canonicalization === profile` or reject
2. Attach signature metadata with `canonicalization: profile`
3. Canonicalize per declared profile (M6: only JCS implemented)
4. Sign and attach `proofValue`

Verification adds symmetry check:
```typescript
if (signature.canonicalization !== manifest["hiri:content"].canonicalization) {
  return false;  // Profile symmetry violation
}
```

For M6, passing `"URDNA2015"` as profile throws `"URDNA2015 not yet implemented"`. M7 enables it.

### 6.F — Delta Pipeline (`delta.ts`)

Format string changes:
- `"json-patch"` → `"application/json-patch+json"`

Delta–canonicalization coupling validation added:
```typescript
if (profile === "JCS" && delta.format !== "application/json-patch+json") {
  return { valid: false, reason: "JCS profile requires JSON Patch format" };
}
if (profile === "URDNA2015" && delta.format !== "application/rdf-patch") {
  return { valid: false, reason: "URDNA2015 profile requires RDF Patch format" };
}
```

### 6.G — Verification Status Reporting (`key-lifecycle.ts`)

Extend `KeyVerificationResult` to include:

```typescript
export interface KeyVerificationResult {
  valid: boolean;
  keyStatus: KeyStatus;
  keyId: string;
  warning?: string;
  // NEW v3.1.1 fields:
  revocationStatus: "confirmed-valid" | "confirmed-revoked" | "unknown";
  timestampVerification: "tsa-verified" | "tsa-present-unverified" | "advisory-only" | "absent";
}
```

Logic:
- `revocationStatus`: `"confirmed-valid"` when KeyDocument available and key not revoked, `"confirmed-revoked"` when key found in `revokedKeys`, `"unknown"` when no KeyDocument
- `timestampVerification`: `"advisory-only"` when no `timestampProof`, `"tsa-present-unverified"` when proof exists but cannot be verified (no TSA infrastructure)

### Test Fixtures

All test fixtures rebuilt from scratch using v3.1.1 format:
- Authority: full-key with `z` prefix (~44 chars, not 20)
- Version: `"1"`, `"2"`, `"3"` (strings, not numbers)
- Content addressing: `"raw-sha256"`
- Signature includes `canonicalization: "JCS"`
- Delta format: `"application/json-patch+json"`
- Verification reports include `revocationStatus` and `timestampVerification`

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Authority (§5.1)** | | |
| 6.1 | `deriveAuthority(knownPubKey, "ed25519")` | Matches Appendix B.1 vector: `key:ed25519:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK` |
| 6.2 | `extractPublicKey(deriveAuthority(pk))` round-trip | Recovered key === original key (byte-identical) |
| 6.3 | `deriveAuthority(31-byte-key)` | Throws: invalid key length |
| 6.4 | `extractPublicKey("key:ed25519:noZprefix")` | Throws: invalid authority format |
| **Version (§11.3)** | | |
| 6.5 | `parseVersion("42")` | Returns `42n` |
| 6.6 | `parseVersion("9007199254740993")` | Returns `9007199254740993n` (beyond Number.MAX_SAFE_INTEGER) |
| 6.7 | `parseVersion(42)` (number input) | Throws: version must be a string |
| 6.8 | `parseVersion("0")` | Throws: version must be ≥ 1 |
| 6.9 | `parseVersion("abc")` | Throws: not a valid integer |
| 6.10 | `encodeVersion(42n)` | Returns `"42"` (string) |
| **Profile Symmetry (§7.3)** | | |
| 6.11 | Sign manifest with `content.canonicalization: "JCS"`, profile `"JCS"` | Succeeds |
| 6.12 | Sign manifest with `content.canonicalization: "URDNA2015"`, profile `"JCS"` | Rejects: profile symmetry violation |
| 6.13 | Verify manifest where `signature.canonicalization ≠ content.canonicalization` | Returns `false` (Appendix B.6) |
| **Manifest Structure (§9)** | | |
| 6.14 | Build genesis manifest with v3.1.1 fields | Contains `addressing`, `signature.canonicalization`, string version, v3.1 context |
| 6.15 | Build chained manifest (V2) with delta | Delta format is `"application/json-patch+json"` |
| **Delta Coupling (§11.4)** | | |
| 6.16 | Verify delta with JCS manifest + `application/json-patch+json` | Succeeds (valid coupling) |
| 6.17 | Verify delta with JCS manifest + `application/rdf-patch` | Rejects delta, falls back to full content (Appendix B.7) |
| **Verification Status (§13.6)** | | |
| 6.18 | Verify manifest with active key, KeyDocument available | `signatureValid: true, keyStatus: "active", revocationStatus: "confirmed-valid", timestampVerification: "advisory-only"` |
| 6.19 | Verify manifest with rotated key in grace period | `keyStatus: "rotated-grace", revocationStatus: "confirmed-valid"` |
| 6.20 | Verify manifest without KeyDocument (signature-only) | `revocationStatus: "unknown", timestampVerification: "advisory-only"` |
| **Existing M1–M5 Rewrite** | | |
| 6.21–6.95 | All existing 75 tests rewritten with v3.1.1 fixtures | All pass with new authority format, string versions, addressing field, signature canonicalization |

**Total M6 tests:** ~95 (75 rewritten + 20 new)

### Execution Sequence

```
1.  Update types.ts — all interface changes (6.A)
2.  Update authority.ts — full-key derivation + extraction (6.B)
3.  Update version.ts — string-only (6.C)
4.  Update manifest.ts — new fields, v3.1 context (6.D)
5.  Update signing.ts — profile parameter, symmetry enforcement (6.E)
6.  Update delta.ts — MIME format, coupling validation (6.F)
7.  Update key-lifecycle.ts — status reporting (6.G)
8.  Update chain.ts — pass profile through chain walker
9.  Update resolve.ts — pass profile, use new authority extraction
10. Rewrite hiri.test.ts fixtures — M1/M2 tests with v3.1.1 format
11. Rewrite phase3.test.ts fixtures — M3 tests with v3.1.1 format
12. Rewrite phase4.test.ts fixtures — M4 tests with v3.1.1 format
13. Rewrite phase5.test.ts fixtures — M5 tests with v3.1.1 format
14. Add new test file: tests/v3-migration.test.ts — tests 6.1–6.20
15. npm run build — zero TypeScript errors
16. npm test — all tests pass
17. npm run test:purity — kernel purity verified
18. All green → M6 complete
```

### Files Modified

| File | Nature | Lines (est.) |
|------|--------|-------------|
| `src/kernel/types.ts` | Interface changes | ~40 |
| `src/kernel/authority.ts` | Rewrite derivation | ~60 |
| `src/kernel/version.ts` | String-only | ~30 |
| `src/kernel/manifest.ts` | New fields, context | ~30 |
| `src/kernel/signing.ts` | Profile parameter, symmetry | ~50 |
| `src/kernel/delta.ts` | MIME format, coupling | ~30 |
| `src/kernel/key-lifecycle.ts` | Status fields | ~40 |
| `src/kernel/chain.ts` | Pass profile | ~20 |
| `src/kernel/resolve.ts` | New authority, profile | ~30 |
| `tests/hiri.test.ts` | Fixture rewrite | ~100 |
| `tests/phase3.test.ts` | Fixture rewrite | ~50 |
| `tests/phase4.test.ts` | Fixture rewrite | ~50 |
| `tests/phase5.test.ts` | Fixture rewrite | ~50 |
| `tests/v3-migration.test.ts` | NEW — rejection tests | ~200 |

---

## Milestone 7: URDNA2015 Canonicalization (The Interoperability Profile)

### Objective

Implement the URDNA2015 canonicalization profile (§7.2), enabling graph-level deterministic hashing and signing. After M7, manifests can be created and verified with either JCS or URDNA2015 canonicalization.

### What This Milestone Proves

That two structurally different JSON-LD documents representing the same RDF graph produce identical canonical forms, identical content hashes, and identical verification results. This is the interoperability proof: serialization format is irrelevant to protocol correctness.

### Core Logic

#### 7.A — Secure Document Loader (`src/kernel/context-registry.ts`)

The document loader is a kernel concern — it determines what contexts are trusted. The actual JSON-LD processing is injected.

```typescript
export interface ContextRegistry {
  resolve(url: string): { document: object; documentUrl: string } | null;
  has(url: string): boolean;
  register(url: string, document: object, expectedHash?: string): void;
}

export function createContextRegistry(): ContextRegistry;

// Built-in contexts (required by §7.6):
//   "https://hiri-protocol.org/spec/v3.1"
//   "https://w3id.org/security/v2"
```

The registry is initialized with the two normative contexts. Additional contexts can be registered if a manifest includes `hiri:contextCatalog`.

```typescript
export function createSecureDocumentLoader(
  registry: ContextRegistry
): (url: string) => Promise<{ document: object; documentUrl: string }> {
  return async (url: string) => {
    const entry = registry.resolve(url);
    if (!entry) throw new Error(`Unknown context: ${url}`);
    return entry;
  };
}
```

**Kernel purity:** The registry holds static data (context JSON objects). It does not fetch from the network. The document loader is a pure function over the registry.

#### 7.B — Canonicalization Adapter Interface

The kernel defines the interface; the adapter provides the implementation.

```typescript
// Kernel type (in types.ts)
export interface Canonicalizer {
  canonicalize(
    doc: Record<string, unknown>,
    documentLoader: (url: string) => Promise<{ document: object; documentUrl: string }>
  ): Promise<Uint8Array>;
}
```

The JCS canonicalizer wraps existing `stableStringify()`. The URDNA2015 canonicalizer wraps `jsonld.canonize()` — this lives in `src/adapters/` since it depends on the `jsonld` library.

```typescript
// src/adapters/rdf/urdna2015-canonicalizer.ts
export function createURDNA2015Canonicalizer(): Canonicalizer {
  return {
    async canonicalize(doc, documentLoader) {
      const nquads = await jsonld.canonize(doc, {
        algorithm: "URDNA2015",
        format: "application/n-quads",
        documentLoader,
      });
      return new TextEncoder().encode(nquads);
    }
  };
}
```

#### 7.C — Resource Limits (§7.7)

```typescript
export interface CanonicalizationLimits {
  maxBlankNodes: number;       // Default: 1000
  maxWallClockMs: number;      // Default: 5000
  maxOutputBytes: number;      // Default: 10_485_760 (10 MB)
}
```

Enforcement: before URDNA2015 canonicalization, count blank nodes in the expanded JSON-LD. If above limit, reject with `CANONICALIZATION_RESOURCE_EXCEEDED`. Wall-clock timeout wraps the canonicalization call with `Promise.race` against a timer. Output size is checked after canonicalization completes.

#### 7.D — Profile-Aware Signing and Verification

M6 added the `profile` parameter to signing/verification but only implemented JCS. M7 enables URDNA2015:

```typescript
// In signing.ts — the profile dispatch
const canonicalBytes = profile === "JCS"
  ? new TextEncoder().encode(stableStringify(manifestWithoutProof, false))
  : await canonicalizer.canonicalize(manifestWithoutProof, documentLoader);
```

The `Canonicalizer` and `documentLoader` are new parameters injected into signing/verification functions.

### Dependencies

- `jsonld` (already in `package.json` — used by RDF adapter)
- No new runtime dependencies required

### Test Fixtures

Two sets of fixture content for each test — one in compact JSON-LD form, one in expanded form — that produce identical RDF graphs.

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Context Registry (§7.5, §7.6)** | | |
| 7.1 | Resolve known HIRI context URL | Returns embedded context document |
| 7.2 | Resolve unknown context URL | Throws: unknown context |
| 7.3 | Register custom context, then resolve | Returns custom context |
| 7.4 | Secure document loader rejects all remote URLs | Throws for any URL not in registry |
| **Context Catalog (§7.6)** | | |
| 7.4b | Manifest references context URL not in registry AND not in `hiri:contextCatalog` | Verifier rejects |
| 7.4c | Manifest includes `hiri:contextCatalog` with custom context + SHA-256 hash | Canonicalization succeeds using cataloged context |
| **URDNA2015 Canonicalization (§7.2)** | | |
| 7.5 | Canonicalize simple JSON-LD with key reordering (B.8a) | Identical N-Quads for both key orderings |
| 7.6 | Canonicalize compact vs expanded JSON-LD (B.8b) | Identical N-Quads |
| 7.7 | Canonicalize with language-tagged literals (B.8c) | Correct N-Quads with language tags |
| 7.8 | Canonicalize with typed vs plain literals (B.8d) | Identical N-Quads |
| 7.9 | Canonicalize with blank nodes (B.8e) | Deterministic `_:c14n0` labels |
| **Resource Limits (§7.7)** | | |
| 7.10 | Document with 1001 blank nodes | Rejects: `CANONICALIZATION_RESOURCE_EXCEEDED` |
| 7.11 | Document within limits | Succeeds |
| **Signing with URDNA2015 (§10)** | | |
| 7.12 | Sign genesis manifest with URDNA2015 profile | Signature verifies; `canonicalization: "URDNA2015"` in signature block |
| 7.13 | Sign and verify round-trip with URDNA2015 | `verifyManifest` returns `true` |
| 7.14 | Verify URDNA2015-signed manifest with tampered content | Returns `false` |
| **Chain with URDNA2015 (§11)** | | |
| 7.15 | Build 3-deep chain with URDNA2015 profile (no deltas) | Chain walker verifies all links |
| **Cross-Profile Forgery Detection** | | |
| 7.16 | Manifest signed over URDNA2015 bytes but `signature.canonicalization` claims `"JCS"` | Verifier uses JCS path, produces different canonical bytes, signature fails |

**Total M7 tests:** ~18

### Execution Sequence

```
1.  Create src/kernel/context-registry.ts — registry + secure loader
2.  Define Canonicalizer interface in types.ts
3.  Create JCS canonicalizer wrapper in kernel
4.  Create URDNA2015 canonicalizer in src/adapters/rdf/
5.  Add resource limits types and enforcement
6.  Update signing.ts — accept Canonicalizer + documentLoader
7.  Update verification path to use injected canonicalizer
8.  Update chain walker to pass canonicalizer through
9.  Embed normative context JSON for HIRI v3.1 and security/v2
10. Write tests/phase7.test.ts with B.8 vectors
11. npm run build && npm test && npm run test:purity
12. All green → M7 complete
```

### Files Modified/Created

| File | Nature |
|------|--------|
| `src/kernel/context-registry.ts` | NEW — context registry + secure loader |
| `src/kernel/types.ts` | Add `Canonicalizer`, `CanonicalizationLimits` |
| `src/kernel/signing.ts` | Accept canonicalizer injection |
| `src/kernel/chain.ts` | Pass canonicalizer through |
| `src/kernel/resolve.ts` | Thread canonicalizer to signing |
| `src/adapters/rdf/urdna2015-canonicalizer.ts` | NEW — URDNA2015 adapter |
| `tests/phase7.test.ts` | NEW — URDNA2015 tests |

---

## Milestone 8: CIDv1 Content Addressing (IPFS-Ready Hashing)

### Objective

Implement the `cidv1-dag-cbor` content addressing mode (§8.2), enabling content hashes that are directly usable as IPFS CIDs. After M8, manifests can declare either `raw-sha256` or `cidv1-dag-cbor` addressing and the hash registry dispatches verification accordingly.

### What This Milestone Proves

That the same logical content, canonicalized identically, produces a valid CIDv1 when wrapped in the dag-cbor envelope. The CID is deterministic and verifiable without IPFS infrastructure — it is computed locally from the canonical bytes.

### Core Logic

#### 8.A — dag-cbor Envelope (§8.2, Appendix C.3)

```typescript
// Adapter: src/adapters/crypto/cidv1.ts
import { encode as dagCborEncode } from "@ipld/dag-cbor";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";

export async function computeCIDv1(
  canonicalBytes: Uint8Array,
  profile: string
): Promise<string> {
  const envelope = {
    "@type": "hiri:CanonicalContent",
    "hiri:canonicalization": profile,
    "hiri:content": canonicalBytes,
  };
  const cborBytes = dagCborEncode(envelope);
  const hash = await sha256.digest(cborBytes);
  const cid = CID.createV1(0x71, hash);  // codec: dag-cbor
  return cid.toString();                   // base32lower multibase
}
```

#### 8.B — CIDv1Algorithm for HashRegistry

The `HashAlgorithm` interface (`hash(content): Promise<string>`) doesn't carry profile information, but the dag-cbor envelope embeds `hiri:canonicalization` as metadata. CIDv1 computed with profile `"JCS"` differs from CIDv1 computed with `"URDNA2015"` for the same canonical bytes. This means `CIDv1Algorithm` needs the profile at construction time, not call time.

```typescript
export function createCIDv1Algorithm(profile: "JCS" | "URDNA2015"): HashAlgorithm {
  return {
    prefix: "b",  // CIDv1 base32lower starts with 'b'
    async hash(content: Uint8Array): Promise<string> {
      return computeCIDv1(content, profile);
    },
    async verify(content: Uint8Array, hash: string): Promise<boolean> {
      const computed = await this.hash(content);
      return computed === hash;
    }
  };
}
```

**Generation:** The manifest builder creates the right algorithm instance based on the manifest's declared canonicalization profile.

**Verification:** The `HashRegistry`'s `verify(content, hash)` convenience method doesn't carry enough context for CIDv1 (it does for `raw-sha256`, which has no metadata in the hash). The resolver reads the manifest's `hiri:content.canonicalization` field, constructs a profile-bound `CIDv1Algorithm`, and calls `verify` directly instead of going through the registry. The registry is still useful for prefix-based routing (`b` → CIDv1), but the resolver owns the CIDv1 context-aware dispatch. This is one special case, not a pattern — it doesn't warrant complicating the registry interface.

The `HashRegistry` registers a default `CIDv1Algorithm` (profile `"JCS"`) for prefix resolution. Profile-aware callers construct their own instance.

#### 8.C — Manifest Addressing Mode

The `addressing` field (added in M6) now has two valid values:

| Value | Content Hash Format | Registered Algorithm |
|-------|--------------------|--------------------|
| `raw-sha256` | `sha256:<hex>` | `SHA256Algorithm` |
| `cidv1-dag-cbor` | `b<base32lower-cid>` | `CIDv1Algorithm` |

The resolver and verifier dispatch based on `manifest["hiri:content"].addressing`.

### Dependencies

**New runtime dependencies (require Orchestrator approval):**

| Package | Purpose | Size |
|---------|---------|------|
| `multiformats` | CID construction, multibase, multihash | ~25 KB |
| `@ipld/dag-cbor` | Deterministic CBOR encoding | ~15 KB |

Both are maintained by Protocol Labs, widely used in the IPFS ecosystem, and work in browsers. They have no native/WASM dependencies.

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **CIDv1 Construction (§8.2)** | | |
| 8.1 | Compute CIDv1 for known canonical bytes | Matches expected CID string |
| 8.2 | Same content → same CID (determinism) | Two calls produce identical CID |
| 8.3 | Different content → different CID | CIDs differ |
| **HashRegistry Dispatch** | | |
| 8.4 | Register CIDv1Algorithm, resolve `b`-prefixed hash | Dispatches to CIDv1Algorithm |
| 8.5 | Verify content against correct CIDv1 | Returns `true` |
| 8.6 | Verify content against incorrect CIDv1 | Returns `false` |
| **Manifest Addressing** | | |
| 8.7 | Build manifest with `addressing: "cidv1-dag-cbor"` | Hash field is a valid CIDv1 string |
| 8.8 | Sign and verify manifest with CIDv1 content hash | Full round-trip succeeds |
| 8.9 | Resolve URI for CIDv1-addressed manifest | Verification passes, content returned |
| **Profile-Binding (§8.2)** | | |
| 8.10 | CIDv1 with profile `"JCS"` vs CIDv1 with profile `"URDNA2015"` for same bytes | CIDs differ (envelope metadata differs) |
| **CBOR Determinism (Appendix B.9)** | | |
| 8.11 | Encode → decode → re-encode produces identical bytes | Byte-identical |
| 8.12 | Non-deterministic CBOR input rejected | Error: `NON_DETERMINISTIC_CBOR` |
| **CBOR Round-Trip Utility (Level 3 readiness)** | | |
| 8.13 | `verifyCborDeterminism(encode(manifest))` round-trip | Decoded manifest matches original |

**Total M8 tests:** ~13

### Execution Sequence

```
1.  npm install multiformats @ipld/dag-cbor (with Orchestrator approval)
2.  Create src/adapters/crypto/cidv1.ts — CIDv1 computation + createCIDv1Algorithm factory
3.  Create CBOR round-trip utility in src/adapters/crypto/cbor-determinism.ts (Level 3 building block)
4.  Register default CIDv1Algorithm in adapter setup
5.  Update manifest builder to support cidv1-dag-cbor addressing
6.  Update resolver to dispatch on addressing mode (profile-aware CIDv1 instance for verification)
7.  Write tests/phase8.test.ts
8.  npm run build && npm test && npm run test:purity
9.  All green → M8 complete
```

### Files Modified/Created

| File | Nature |
|------|--------|
| `src/adapters/crypto/cidv1.ts` | NEW — CIDv1 computation + profile-bound factory |
| `src/adapters/crypto/cbor-determinism.ts` | NEW — CBOR round-trip utility (Level 3 building block) |
| `src/kernel/hash-registry.ts` | Register CIDv1 prefix dispatch |
| `src/kernel/manifest.ts` | Support cidv1-dag-cbor addressing |
| `src/kernel/resolve.ts` | Dispatch on addressing mode |
| `tests/phase8.test.ts` | NEW — CIDv1 tests |
| `package.json` | Add `multiformats`, `@ipld/dag-cbor` |

---

## Milestone 9: RDF Patch & Level 2 Integration

### Objective

Implement RDF Patch delta format (§11.4.3), complete the delta–canonicalization coupling matrix, and run full integration tests combining both profiles with both addressing modes. After M9, the implementation declares Level 2 (Interoperable) conformance.

### What This Milestone Proves

That the complete Level 2 feature matrix works end-to-end:

| Combination | Profile | Addressing | Delta Format |
|-------------|---------|------------|--------------|
| JCS + raw-sha256 + JSON Patch | ✓ M6 | ✓ M6 | ✓ M6 |
| JCS + CIDv1 + JSON Patch | ✓ M6 | ✓ M8 | ✓ M6 |
| URDNA2015 + raw-sha256 + RDF Patch | ✓ M7 | ✓ M6 | **M9** |
| URDNA2015 + CIDv1 + RDF Patch | ✓ M7 | ✓ M8 | **M9** |

M9 fills the last column and validates all combinations.

### Core Logic

#### 9.A — RDF Patch Parser (`src/kernel/rdf-patch.ts`)

```typescript
export interface RDFPatchOperation {
  op: "add" | "remove";
  subject: string;    // N-Quads notation
  predicate: string;  // N-Quads notation
  object: string;     // N-Quads notation, includes datatype/language
  graph?: string;     // Optional named graph
}

export function parseRDFPatch(operations: RDFPatchOperation[]): RDFPatchOperation[] {
  // Validate each operation has required fields
  // Return validated operations
}
```

#### 9.B — RDF Patch Application

```typescript
export function applyRDFPatch(
  nquads: string,            // Canonical N-Quads from URDNA2015
  operations: RDFPatchOperation[]
): string {
  // Parse N-Quads into quad set
  // Apply operations in array order (NOT reordered — §11.4.3: "applied in order")
  // Serialize back to sorted N-Quads
  // Return canonical N-Quads string
}
```

**Operation order is array order.** Per §11.4.3: "The operations are applied in order." This means the array sequence, not a reordering into remove-first/add-then. A patch that adds then removes a triple produces a different result than remove-then-add. Test 9.3 validates this explicitly.

**Kernel purity:** RDF Patch application operates on N-Quads strings (plain text). It does not require the `jsonld` library. The patched N-Quads are then hashed directly.

#### 9.C — Delta Verification Pipeline (URDNA2015, §11.4.5)

```
1. Fetch previous content bytes
2. Verify previous content hash matches delta.appliesTo
3. Canonicalize previous content via URDNA2015 → N-Quads
4. Apply RDF Patch operations to N-Quads
5. Hash result
6. Compare to current hiri:content.hash
```

On failure at any step → fall back to full content verification with warning.

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **RDF Patch (§11.4.3)** | | |
| 9.1 | Apply `add` operation to N-Quads | Triple added |
| 9.2 | Apply `remove` operation to N-Quads | Triple removed |
| 9.3 | Apply mixed add/remove sequence | Correct final quad set |
| 9.4 | Remove non-existent triple | No-op (no error) |
| **Delta Verification (URDNA2015 path)** | | |
| 9.5 | Build 2-version chain with URDNA2015 + RDF Patch delta | Chain verifies, delta verifies |
| 9.6 | Tamper with RDF Patch operations | Delta fails, falls back to full content, chain still valid |
| 9.6b | RDF Patch with 3 ops where op 2 fails — verify op 1 NOT applied to final graph | Atomic rollback: no partial application (§11.4.1) |
| 9.7 | URDNA2015 manifest with JSON Patch delta | Delta rejected (B.7), falls back to full content |
| 9.8 | JCS manifest with RDF Patch delta | Delta rejected (B.7), falls back to full content |
| **Level 2 Integration** | | |
| 9.9 | Full chain: JCS + raw-sha256 + JSON Patch (3 versions) | Verify chain, verify deltas, resolve URI |
| 9.10 | Full chain: JCS + CIDv1 + JSON Patch (3 versions) | Verify chain, verify deltas, resolve URI |
| 9.11 | Full chain: URDNA2015 + raw-sha256 + RDF Patch (3 versions) | Verify chain, verify deltas, resolve URI |
| 9.12 | Full chain: URDNA2015 + CIDv1 + RDF Patch (3 versions) | Verify chain, verify deltas, resolve URI |
| 9.13 | Verification status for all four combinations | Correct `signatureValid`, `keyStatus`, `revocationStatus`, `timestampVerification` |
| **Blank Node Identity (§11.4.3 note)** | | |
| 9.14 | RDF Patch that modifies a blank node subgraph | Post-patch re-canonicalization produces valid hash |

**Total M9 tests:** ~15

### Execution Sequence

```
1.  Create src/kernel/rdf-patch.ts — parser + applier
2.  Update delta.ts — URDNA2015 verification pipeline
3.  Update chain walker — thread URDNA2015 delta verification
4.  Write tests/phase9.test.ts — RDF Patch + integration matrix
5.  npm run build && npm test && npm run test:purity
6.  All green → M9 complete, Level 2 conformance achieved
```

### Files Modified/Created

| File | Nature |
|------|--------|
| `src/kernel/rdf-patch.ts` | NEW — RDF Patch parser + applier |
| `src/kernel/delta.ts` | URDNA2015 delta verification pipeline |
| `src/kernel/chain.ts` | Thread URDNA2015 delta path |
| `tests/phase9.test.ts` | NEW — RDF Patch + Level 2 integration |

---

## Verification Checklist (All Milestones)

After each milestone:

1. `npm run build` — zero TypeScript errors
2. `npm test` — all tests pass
3. `npm run test:purity` — kernel purity verified (no I/O, no non-deterministic APIs)
4. New kernel files import nothing from `src/adapters/` or `src/demo/`
5. No new runtime dependencies added without Orchestrator approval

After M9:

6. All four profile × addressing combinations verified end-to-end
7. All Appendix B test vectors pass (B.1–B.10, excluding B.9 CBOR for Level 2)
8. Verification reports include all four §13.6 status fields
9. Level 2 conformance per §18.2 declared

---

## Summary

| Milestone | Deliverable | New Tests | Cumulative |
|-----------|-------------|-----------|------------|
| M6 | v3.1.1 breaking changes, JCS + raw-sha256 | ~95 | ~95 |
| M7 | URDNA2015 canonicalization + context catalog | ~18 | ~113 |
| M8 | CIDv1 content addressing + CBOR determinism | ~13 | ~126 |
| M9 | RDF Patch, delta atomicity, Level 2 integration | ~15 | ~141 |

**Total new kernel files:** 3 (`context-registry.ts`, `rdf-patch.ts`, one adapter)
**Total new adapter files:** 2 (`cidv1.ts`, `cbor-determinism.ts`)
**Total new test files:** 4 (`v3-migration.test.ts`, `phase7.test.ts`, `phase8.test.ts`, `phase9.test.ts`)
**New runtime dependencies:** 2 (`multiformats`, `@ipld/dag-cbor`) — M8 only
**Kernel files modified:** 9 (all existing kernel modules except `base58.ts`)
**Kernel files unmodified:** `base58.ts`, `json-patch.ts`, `graph-builder.ts`, `query-executor.ts`
