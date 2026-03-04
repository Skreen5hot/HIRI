# Roadmap

<!--
  This is your project's north star. Structure work into phases with
  explicit scope boundaries. AI agents read this at session start to
  understand what to work on and — critically — what NOT to touch.
-->

## Phase 1: The Verifiable Atom (Milestone 1)

**Goal:** Implement HIRI protocol core: Ed25519 keypair generation, authority derivation, content hashing, manifest construction, signing, verification, and genesis validation.

**Status:** COMPLETE

**Governing Spec:** HIRI Protocol Specification v2.1.0, HIRI Milestones v1.3

### 1.1 Kernel Interfaces and Types

**Status:** Complete

Defined all HIRI protocol interfaces in `src/kernel/types.ts`: `HashAlgorithm`, `CryptoProvider`, `SigningKey`, `HiriSignature`, `ResolutionManifest`, `UnsignedManifest`, `KeyDocument`, and supporting types.

**Key Design Decision (ADR-002, ADR-003):**
- `@noble/ed25519` approved as first runtime dependency
- Timestamps passed as input parameters (no clock in kernel)
- Crypto operations injected via `CryptoProvider` interface (purity checker blocks direct imports)

### 1.2 Pure Kernel Functions

**Status:** Complete

Implemented 8 kernel modules with zero external imports:

| Module | Purpose |
|--------|---------|
| `src/kernel/types.ts` | All HIRI interfaces |
| `src/kernel/base58.ts` | Base58 encode/decode (BigInt arithmetic) |
| `src/kernel/hiri-uri.ts` | HIRI URI parser/builder |
| `src/kernel/hash-registry.ts` | Hash algorithm dispatch with `verify` convenience method |
| `src/kernel/authority.ts` | Authority derivation from raw digest bytes |
| `src/kernel/manifest.ts` | Manifest + KeyDocument construction, content preparation |
| `src/kernel/signing.ts` | Sign/verify manifests and KeyDocuments |
| `src/kernel/genesis.ts` | Genesis validation rules |

### 1.3 Crypto Adapters

**Status:** Complete

Implemented `@noble/ed25519` and Web Crypto adapters in `src/adapters/crypto/`:

| Module | Purpose |
|--------|---------|
| `sha256.ts` | SHA-256 via `crypto.subtle.digest` |
| `ed25519.ts` | Ed25519 keypair generation, signing, verification |
| `provider.ts` | `DefaultCryptoProvider` wiring SHA256 + Ed25519 |

### 1.4 Domain Tests

**Status:** Complete — 15/15 pass

| Test | Result |
|------|--------|
| base58: empty, zero byte, leading zeros, 32-byte round-trip | 4 pass |
| JCS: key sorting, numerics, Unicode above U+FFFF | 1 pass |
| 1.1: Keypair generation + authority derivation | pass |
| 1.2: Sign person.jsonld, manifest has all §5.2 fields | pass |
| 1.3: Verify manifest against public key | pass |
| 1.4a: Content tampering — hash mismatch | pass |
| 1.4b: Manifest tampering — signature verification fails | pass |
| 1.5: Signature tampering — verification fails | pass |
| 1.6: Genesis manifest (v1, no chain) valid | pass |
| 1.7: Non-genesis (v2, no chain) invalid | pass |
| 1.8: HashRegistry resolves sha256 + verify convenience | pass |
| 1.9: HashRegistry throws for unregistered algorithm | pass |

### Technical Debt

| Item | Status | Notes |
|------|--------|-------|
| JCS compliance | Verified for MVP | `stableStringify` handles key sorting and numerics; full RFC 8785 edge cases (number normalization) not formally certified |
| Authority truncation | Deferred to M3 | 20 chars base58 (~119 bits). Evaluate collision risk at scale |
| URDNA2015 | Deferred post-MVP | JCS sufficient for single-authority. Cross-authority graph merging needs full RDF normalization |
| `person-v2.jsonld` | Resolved in M2 | Now covered by json-patch v1→v2 test and delta verification tests |

---

## Phase 2: Chain & Versioning (Milestone 2)

**Goal:** Chain integrity (linking manifests into verifiable history), chain walker (recursive verification from head to genesis), and delta support (JSON Patch application and verification between versions).

**Status:** COMPLETE

**Governing Spec:** HIRI Protocol Specification v2.1.0, HIRI Milestones v1.3

### 2.1 Type Extensions

**Status:** Complete

Extended `src/kernel/types.ts` with Milestone 2 types:
- `JsonPatchOperation` — RFC 6902 patch operation (add, remove, replace)
- `ManifestDelta` — Delta metadata embedded in manifests (hash, format, appliesTo, operations count)
- `ChainValidation` — Result of chain link validation
- `ChainWalkResult` — Richer result for chain walker (valid, depth, reason, warnings)
- `ManifestFetcher` / `ContentFetcher` — Injected I/O types for chain walking
- Added `"hiri:delta"?` to `UnsignedManifest` and `delta?` to `ManifestParams`

### 2.2 New Kernel Modules

**Status:** Complete — 3 new modules, zero external imports

| Module | Purpose |
|--------|---------|
| `src/kernel/chain.ts` | `hashManifest`, `validateChainLink` (6 rules), `verifyChain` (chain walker) |
| `src/kernel/json-patch.ts` | RFC 6902 `applyPatch` (add, remove, replace) with RFC 6901 JSON Pointer |
| `src/kernel/delta.ts` | `buildDelta` (construct delta metadata), `verifyDelta` (full pipeline: Uint8Array → hash → decode → patch → canonicalize → compare) |

**Key Design Decisions:**
- `hashManifest` includes signature in hash payload — chain is tamper-evident at the signature level
- `verifyDelta` accepts `Uint8Array` and owns the full verification pipeline (prevents hash-on-different-bytes bugs)
- `applyPatch` throws on errors; `verifyDelta` catches and returns structured `ChainValidation`
- Chain walker uses injected `ManifestFetcher`/`ContentFetcher` functions (in-memory Map in tests, StorageAdapter in M3)
- Delta fallback: when delta verification fails, walker falls back to full content fetch and records a warning

### 2.3 Domain Tests

**Status:** Complete — 18/18 pass (33/33 total with M1)

**JSON Patch Infrastructure:**

| Test | Result |
|------|--------|
| json-patch: replace on simple object | pass |
| json-patch: add new field | pass |
| json-patch: remove existing field | pass |
| json-patch: nested path traversal | pass |
| json-patch: person v1 → v2 transformation matches fixture | pass |

**v1.2 Milestone Test Cases:**

| Test | Description | Result |
|------|-------------|--------|
| 2.1 | V2 chain.previous = hash of V1, depth=2, genesisHash correct | pass |
| 2.2 | Chain walk V2→V1 reports { valid: true, depth: 2 } | pass |
| 2.3 | Storage tampering detected — hash of fetched V1 doesn't match | pass |
| 2.4 | Delta verification: apply patch to V1 produces V2 content hash | pass |
| 2.5 | Delta corruption detected, fallback to full content + warning | pass |
| 2.6 | Delta appliesTo mismatch detected | pass |
| 2.7 | Genesis at chain root: walker confirms V1, depth=1 | pass |
| 2.8 | Three-deep chain V3→V2→V1, depth=3 | pass |
| 2.9 | Version monotonicity violation detected | pass |

**Bonus Tests:**

| Test | Description | Result |
|------|-------------|--------|
| 2.10 | Depth integrity violation (depth=5, expected=2) | pass |
| 2.11 | Genesis hash immutability violation | pass |
| 2.12 | Branch consistency violation | pass |
| 2.13 | chain.previous tampering (re-signed manifest) | pass |

### Technical Debt

| Item | Status | Notes |
|------|--------|-------|
| Replay protection | Deferred to M3 | Requires local-only storage adapter; security concern per IPFS Spec §9.3 |
| BigInt versions | Deferred | `number` sufficient for MVP; string encoding for versions > 2^53 not yet needed |
| JSON Patch move/copy/test | Deferred | Only add/remove/replace implemented |
| Multi-branch versioning | Deferred to M3 | All current tests use "main" branch only |
| Compaction references | Deferred to M3+ | SNARK-based chain compaction |
| Full StorageAdapter | Deferred to M3 | M2 uses `ManifestFetcher`/`ContentFetcher` function injection |

---

## Phase 3: The Abstracted Resolver (Milestone 3)

**Goal:** Prove that the storage mechanism is irrelevant to the protocol by implementing a `resolve()` function that produces byte-identical output against different storage backends (InMemoryStorageAdapter, FileSystemAdapter, DelayedAdapter).

**Status:** COMPLETE

**Governing Spec:** HIRI Protocol Specification v2.1.0, HIRI Milestones v1.3

### 3.1 Kernel Types — StorageAdapter Interface

**Status:** Complete

Added minimal `StorageAdapter` interface to `src/kernel/types.ts`: two methods (`get`, `has`). Content-addressed retrieval only — no indexing, no publishing. Callers MUST verify returned bytes hash to the expected value.

### 3.2 BigInt Version Handling

**Status:** Complete

New kernel module `src/kernel/version.ts` with zero imports:

| Function | Purpose |
|----------|---------|
| `parseVersion` | number/string → bigint, rejects invalid |
| `encodeVersion` | bigint → number (if safe) or string |
| `validateVersion` | Non-throwing validation wrapper |
| `isMonotonicallyIncreasing` | Parses both, returns current > previous |

### 3.3 Storage Adapters

**Status:** Complete — 3 adapters

| Module | Purpose |
|--------|---------|
| `src/adapters/persistence/storage.ts` | `InMemoryStorageAdapter` — Map-backed, with `put()` for population |
| `src/adapters/persistence/filesystem.ts` | `FileSystemAdapter` — reads hash-named files from a directory |
| `src/adapters/persistence/delayed.ts` | `DelayedAdapter` — wraps any adapter with configurable async delay |

### 3.4 Resolver Function

**Status:** Complete

`src/kernel/resolve.ts` — the Milestone 3 deliverable:

| Export | Purpose |
|--------|---------|
| `resolve(uri, storage, options)` | 10-step resolution pipeline → `VerifiedContent` |
| `ResolveOptions` | Typed options: crypto, publicKey, manifestHash |
| `VerifiedContent` | Result: content, manifest, authority, contentHash |
| `ResolutionError` | Error class with discriminated `code` field |

Error codes: `PARSE_ERROR`, `AUTHORITY_NOT_FOUND`, `MANIFEST_NOT_FOUND`, `CONTENT_NOT_FOUND`, `SIGNATURE_VERIFICATION_FAILED`, `CHAIN_VERIFICATION_FAILED`, `STORAGE_CORRUPTION`, `IDENTITY_MISMATCH`.

Internal bridge functions: `manifestFetcherFromStorage` (deserialization + hash verification) and `contentFetcherFromStorage` (passthrough).

**Key Design Decision (ADR-004):**
- Minimal `StorageAdapter { get, has }` per v1.2 — no indexing, no publishing
- Resolver in kernel (pure function of inputs), not in adapters
- Bridge function is deserialization + verification, not trivial passthrough

### 3.5 Domain Tests

**Status:** Complete — 18/18 pass (57/57 total with M1+M2)

**Infrastructure Tests:**

| Test | Result |
|------|--------|
| version: parseVersion safe integer | pass |
| version: parseVersion large string | pass |
| version: parseVersion rejects invalid | pass |
| version: encodeVersion safe→number, large→string | pass |
| version: isMonotonicallyIncreasing | pass |
| storage: InMemory put/get round-trip | pass |
| storage: InMemory get returns null | pass |
| storage: InMemory has | pass |
| storage: FileSystem read-back | pass |
| storage: DelayedAdapter results match | pass |

**v1.2 Milestone 3 Test Cases:**

| Test | Description | Result |
|------|-------------|--------|
| 3.1 | Resolve valid URI against MemoryAdapter | pass |
| 3.2 | Resolve same URI against FileSystemAdapter — byte-identical to 3.1 | pass |
| 3.3 | Resolve same URI against DelayedAdapter — byte-identical to 3.1 | pass |
| 3.4 | Unknown authority → AUTHORITY_NOT_FOUND | pass |
| 3.5 | Manifest exists but content missing → CONTENT_NOT_FOUND | pass |
| 3.6 | Invalid signature → SIGNATURE_VERIFICATION_FAILED | pass |
| 3.7 | Concurrent resolution: 10 URIs against DelayedAdapter | pass |
| 3.8 | Malformed URIs → PARSE_ERROR | pass |

### Technical Debt

| Item | Status | Notes |
|------|--------|-------|
| `hiri:version` typed as `number` | Deferred | `parseVersion`/`encodeVersion` ready for migration |
| ManifestIndex interface | Deferred | Needed for publishing/management UI, not resolution |
| ManifestTracker (replay protection) | Deferred | Operational security, not protocol verification |
| KeyPinStore (TOFU) | Deferred to M5 | Full key lifecycle management |
| Multi-branch support | Deferred per v1.2 | "MVP assumes main branch" |
| Discovery profiles | Deferred to P4 | Resolver requires caller-provided publicKey + manifestHash |
| JSON Patch move/copy/test | Unchanged from M2 | Only add/remove/replace |

---

## Phase 4: The Storeless Oracle (Milestone 4)

**Goal:** Prove that verified content (from `resolve()`) can be loaded into a local RDF index and queried with SPARQL — without a graph database server. Establish the entailment contract that future milestones must satisfy.

**Status:** COMPLETE

**Governing Spec:** HIRI Protocol Specification v2.1.0, HIRI Milestones v1.4

### 4.1 Kernel Types — RDF Index & Query Interfaces

**Status:** Complete

Extended `src/kernel/types.ts` with Milestone 4 types:
- `EntailmentMode` — `"none" | "materialized" | "runtime"`
- `ManifestSemantics` — `{ entailmentMode, baseRegime, vocabularies }`
- `RDFIndex` — `{ load, tripleCount }`
- `SPARQLEngine` — `{ query }`
- `QueryResult` — `{ bindings, truncated }`
- `RDFTerm` — `{ type, value, datatype?, language? }`
- `GraphBuilderConfig` — `{ entailmentMode }`
- Added `"hiri:semantics"?` to `UnsignedManifest` and `semantics?` to `ManifestParams`

### 4.2 New Kernel Modules

**Status:** Complete — 2 new modules, zero external imports

| Module | Purpose |
|--------|---------|
| `src/kernel/graph-builder.ts` | `buildGraph` (load content into index with entailment routing), `resolveEntailmentMode` (backward compat default) |
| `src/kernel/query-executor.ts` | `executeQuery` (orchestrate SPARQL query via injected engine) |

**Key Design Decisions (ADR-005, ADR-006):**
- Oxigraph WASM for in-memory RDF store + SPARQL 1.1
- `jsonld` library for JSON-LD → N-Quads conversion (Oxigraph WASM does not parse JSON-LD)
- Remote context fetches explicitly blocked via custom `documentLoader`
- Oxigraph loaded with `lenient: true` for HIRI URI scheme compatibility
- Unimplemented entailment modes throw explicitly (no silent fallback)

### 4.3 Adapter — OxigraphRDFStore

**Status:** Complete

`src/adapters/rdf/oxigraph-store.ts` — single class implementing both `RDFIndex` and `SPARQLEngine`:

| Method | Interface | Purpose |
|--------|-----------|---------|
| `load(content, format, baseURI)` | `RDFIndex` | JSON-LD → N-Quads (via jsonld) → Oxigraph store |
| `tripleCount()` | `RDFIndex` | Count triples in store |
| `query(sparql, index)` | `SPARQLEngine` | Execute SPARQL, map Oxigraph terms → `RDFTerm` |

### 4.4 Manifest Builder Update

**Status:** Complete

`src/kernel/manifest.ts` — added `hiri:semantics` wiring in `buildUnsignedManifest()`, following existing pattern for `chain` and `delta`.

### 4.5 Test Fixtures

**Status:** Complete — 2 new fixtures

| Fixture | Purpose |
|---------|---------|
| `examples/entailment-trap.jsonld` | RDFS subclass trap: `ex:SoftwareArchitect rdfs:subClassOf schema:Person` with typed individual. Tests that inference does NOT leak. |
| `examples/team.jsonld` | 3 `schema:Person` entities for multi-row query testing |

### 4.6 Domain Tests

**Status:** Complete — 11/11 pass (68/68 total with M1+M2+M3)

| Test | Description | Result |
|------|-------------|--------|
| 4.1 | Load person.jsonld, query name (type-filtered) | pass |
| 4.2 | Query jobTitle returns "Systems Architect" | pass |
| 4.3 | Typed literal: birthDate with xsd:date datatype | pass |
| 4.4 | **Critical gate:** Entailment boundary — no RDFS inference under mode="none" | pass |
| 4.5 | Query all types — exactly 2 explicit assertions, no inferred types | pass |
| 4.6 | Multi-row: 3 team members in alphabetical order | pass |
| 4.7 | Empty result set for non-existent property | pass |
| 4.8 | Full pipeline: URI → resolve → buildGraph → executeQuery | pass |
| 4.9 | Missing semantics field defaults to mode="none" | pass |
| 4.10 | SPARQL syntax error throws | pass |
| 4.11 | No network activity — all computation local | pass |

### Technical Debt

| Item | Status | Notes |
|------|--------|-------|
| `entailmentMode: "materialized"` | Deferred | Throws explicitly; future milestone |
| `entailmentMode: "runtime"` | Deferred | Throws explicitly; future milestone |
| Multi-manifest graph merging | Deferred | Single-document loading only in MVP |
| Named graph isolation | Deferred | All triples in default graph |
| Query result pagination/limits | Deferred | `truncated: false` for all results |
| Oxigraph `lenient: true` | Noted | See detailed analysis below |
| HIRI URI scheme vs IRI spec | Protocol debt | `hiri://key:ed25519:...` authority component contains colons that violate RFC 3987 generic IRI syntax. Will resurface with any standards-compliant RDF tooling. Preferred fix: declare HIRI as scheme-specific per RFC 3986 §3.2 (authority syntax defined by scheme registration) — preserves human-readable self-certifying property. Percent-encoding (`key%3Aed25519%3A...`) is technically correct but destroys readability. Do not default to percent-encoding without considering this tradeoff. |
| `hiri:version` typed as `number` | Unchanged | `parseVersion`/`encodeVersion` ready for migration |
| ManifestTracker, KeyPinStore | Deferred to M5 | Operational security, not protocol verification |

#### Oxigraph `lenient: true` — Impact Analysis

Oxigraph's `lenient: true` flag relaxes IRI validation on `store.load()`. Empirical testing shows it affects three categories:

| Category | Strict mode | Lenient mode | Risk to HIRI |
|----------|-------------|--------------|--------------|
| HIRI URIs (`hiri://key:ed25519:...`) | Rejects (colons in authority) | Accepts | **This is why we need lenient** |
| Relative IRIs (`<relative/path>`) | Rejects | Accepts silently | Low — `jsonld.toRDF()` always produces absolute IRIs |
| Empty datatypes (`^^<>`) | Rejects | Accepts silently | Low — `jsonld.toRDF()` never produces empty datatypes |
| Malformed literals (`"not-a-date"^^xsd:date`) | Accepts | Accepts | No difference |
| Query results on valid data | N results | N results (identical) | No difference |

**Conclusion:** For MVP, the risk is acceptable because:
1. All N-Quads fed to Oxigraph come from `jsonld.toRDF()`, not from arbitrary user input
2. `jsonld.toRDF()` produces fully resolved absolute IRIs with proper datatypes — verified empirically against all 3 fixtures
3. The only non-standard IRIs are HIRI URIs, which are structurally controlled by the protocol
4. Query results are byte-identical between strict and lenient modes for well-formed data

**Future mitigation:** When the protocol spec addresses the HIRI URI / IRI compatibility issue, the `lenient: true` flag can be removed. If an IRI-safe authority encoding is adopted (e.g., percent-encoding colons), strict mode will work and the broader permissiveness is eliminated.

---

## Phase 5: The Sovereign Authority (Milestone 5)

**Goal:** Retroactive hardening of M1–M3: key rotation changes the semantics of signature verification. The resolver, chain walker, and manifest verifier now consult the Key Document's temporal key states. Implements 5-step key resolution algorithm, grace period arithmetic, retroactive revocation, dual-signature rotation proofs, and full-chain walk without short-circuit.

**Status:** COMPLETE

**Governing Spec:** HIRI Protocol Specification v2.1.0, HIRI Milestones v1.4

### 5.1 Kernel Types — Key Lifecycle Extensions

**Status:** Complete

Extended `src/kernel/types.ts` with Milestone 5 types:
- `KeyStatus` — `"active" | "rotated-grace" | "rotated-expired" | "revoked" | "unknown"`
- `KeyVerificationResult` — `{ valid, keyStatus, keyId, warning? }`
- `RotationSignature` — `{ purpose, verificationMethod, proofValue }`
- `RotationClaim` — `{ oldKeyId, newKeyId, rotatedAt, reason }`
- `ChainFailure` — `{ version, keyId, keyStatus, reason }`
- Extended `RotatedKey` with `publicKeyMultibase` and `rotationProof?`
- Extended `RevokedKey` with `publicKeyMultibase`
- Extended `ChainWalkResult` with `failures?: ChainFailure[]`

### 5.2 New Kernel Modules

**Status:** Complete — 2 new modules, zero external imports

| Module | Purpose |
|--------|---------|
| `src/kernel/temporal.ts` | `parseDuration` (PnD only), `addDuration`, `compareTimestamps` (epoch-millis via manual parsing) |
| `src/kernel/key-lifecycle.ts` | `resolveSigningKey` (5-step algorithm), `verifyManifestWithKeyLifecycle`, `verifyRotationProof` (dual-signature) |

**Key Design Decisions (ADR-007):**
- Wrap, don't modify: existing `verifyManifest()` and `verifyChain()` unchanged; new lifecycle-aware functions alongside
- `temporal.ts` uses no `Date` constructor — pure string manipulation and arithmetic
- `resolveSigningKey` uses two temporal inputs: `verificationTime` (grace period) and `manifest.timing.created` (retroactive revocation)
- `verifyRotationProof` reconstructs a `RotationClaim` as the deterministic signing target, breaking signature circularity

### 5.3 Extended Kernel Modules

**Status:** Complete

| Module | Change |
|--------|--------|
| `src/kernel/chain.ts` | Added `verifyChainWithKeyLifecycle()` — full-chain walk without short-circuit, collects per-manifest failures |
| `src/kernel/resolve.ts` | Extended `ResolveOptions` (`keyDocument?`, `verificationTime?`), `VerifiedContent` (`warnings?`, `keyVerification?`), new error codes (`KEY_REVOKED`, `KEY_EXPIRED`, `KEY_UNKNOWN`), forked Steps 7/8 for lifecycle-aware path |

### 5.4 Domain Tests

**Status:** Complete — 13/13 pass (81/81 total with M1+M2+M3+M4)

| Test | Description | Result |
|------|-------------|--------|
| 5.1 | Active key (Key C) signs manifest — valid, status='active' | pass |
| 5.2 | Rotated key within grace period — valid with warning | pass |
| 5.3 | Rotated key after grace period — rejected, status='rotated-expired' | pass |
| 5.4 | Revoked key, signed after invalidation point — rejected | pass |
| 5.5 | Revoked key, signature before invalidation — valid with warning | pass |
| 5.6 | **Critical gate:** Retroactive revocation — signature after invalidation rejected | pass |
| 5.7 | Grace period boundary −1s — valid (rotated-grace) | pass |
| 5.8 | Grace period boundary +1s — rejected (rotated-expired) | pass |
| 5.9 | Chain with rotation (Key B→Key C) — both valid, depth=2 | pass |
| 5.10 | **Critical gate:** Chain with retroactive revocation — V2 failure, V1/V3 valid | pass |
| 5.11 | Dual-signature rotation proof — both old+new key signatures verify | pass |
| 5.12 | Unknown key (#key-99) — rejected, status='unknown' | pass |
| 5.13 | Resolver integration — VerifiedContent with key lifecycle warnings | pass |

### Technical Debt

| Item | Status | Notes |
|------|--------|-------|
| TOFU (Trust-On-First-Use) | Deferred | Not in v1.4 M5 scope |
| ManifestTracker / KeyPinStore | Deferred | Operational security, not protocol verification |
| Consortium key management (§10.3) | Deferred post-MVP | Multi-party key governance |
| Month/year duration parsing | Deferred | Only `PnD` format needed; `parseDuration` throws on month/year |
| KeyDocument versioning/evolution | Deferred | Single KeyDocument per authority in MVP |
| `hiri:version` typed as `number` | Unchanged | `parseVersion`/`encodeVersion` ready for migration |
