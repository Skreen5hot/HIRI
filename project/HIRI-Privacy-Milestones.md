# HIRI Privacy Extension Milestones
## Milestones 10–15: Privacy & Confidentiality

**Version:** 1.0
**Last Updated:** March 2026
**Governing Spec:** HIRI Privacy & Confidentiality Extension v1.4.1
**Base Protocol:** HIRI Protocol Specification v3.1.1
**Prerequisite:** Level 2 — Interoperable (144/144 tests, M1–M8 complete)
**Target Conformance:** Privacy Level 3 — Full (§16.3)

---

## Preamble

Milestones 1–8 delivered a Level 2: Interoperable implementation of the HIRI Protocol — 144 tests across 7 suites, covering both canonicalization profiles (JCS, URDNA2015), both content addressing modes (raw-sha256, cidv1-dag-cbor), and both delta formats (JSON Patch, RDF Patch). The kernel is pure, the layer boundaries are enforced, and the demo site proves end-to-end operation.

The Privacy Extension adds a new layer above the kernel: Layer 2 (Privacy). Privacy operations transform content *before* it reaches Layer 0 for signing. The kernel signs whatever the privacy layer produces — ciphertext, disclosure-proof bundles, or plaintext. The kernel does not know or care which privacy mode is active.

**Strategy: Incremental Conformance.** Unlike the v3.1.1 migration (which required a clean break), the Privacy Extension composes with the existing protocol. No kernel changes are needed. Each milestone delivers a conformance level that is independently useful:

1. **Privacy Level 1 (M10):** Proof of Possession — manifest-only publication, no content retrieval
2. **Privacy Level 2 (M11–M12):** Encrypted Distribution — AES-256-GCM, X25519 key agreement, dual hashes
3. **Privacy Level 3 (M13–M15):** Selective Disclosure + Anonymous + Attestation + Lifecycle

**Layer Assignment:** All privacy code lives in `src/privacy/` (new directory, Layer 2). Cryptographic primitives (X25519, HKDF, AES-GCM) live in `src/adapters/crypto/` (Layer 1). The kernel is untouched.

**New Runtime Dependencies (require Orchestrator approval):**

| Package | Purpose | Milestone |
|---------|---------|-----------|
| `@noble/curves` | Ed25519↔X25519 conversion, X25519 ECDH | M11 |
| `@noble/hashes` | HKDF-SHA256, HMAC-SHA256 | M11 |

Both are audited, zero-dependency packages by Paul Miller. Browser and Node compatible. No WASM.

---

## Current Implementation State

| Phase | Milestone | Status | Tests |
|-------|-----------|--------|-------|
| Phase 1–5 | M1–M5: Core Protocol | **Complete** | 75/75 |
| Phase 6–8 | M6–M8: v3.1.1 Migration | **Complete** | 144/144 |
| — | M10: Privacy Level 1 | **Not started** | 0 |
| — | M11: Crypto Primitives | **Not started** | 0 |
| — | M12: Privacy Level 2 | **Not started** | 0 |
| — | M13: Selective Disclosure | **Not started** | 0 |
| — | M14: Anonymous + Attestation | **Not started** | 0 |
| — | M15: Privacy Level 3 Integration | **Not started** | 0 |

**Existing tests:** 144 (7 files)
**Post-M15 expected tests:** ~268 (144 existing + ~124 privacy)

---

## Dependency Graph

```
M10: Privacy Level 1 (Infrastructure + Proof of Possession)
 │
 ├── M11: Crypto Primitives (X25519, HKDF, AES-GCM adapters)
 │    │
 │    ├── M12: Privacy Level 2 (Encrypted Distribution)
 │    │
 │    └── M13: Selective Disclosure (HMAC suite, depends on M10 + M11 + existing URDNA2015)
 │         │   (M11 needed for HMAC key distribution via X25519+HKDF+AES-GCM)
 │
 ├── M14: Anonymous + Attestation (depends on M10)
 │
 └── M15: Privacy Level 3 Integration (depends on M12 + M13 + M14)
          ├── Privacy lifecycle transitions
          ├── Cross-mode chain walking
          ├── Extended resolution algorithm
          └── Level 3 conformance declaration
```

M12 and M13 are independent of each other but both depend on M11. M14 depends only on M10. M15 depends on all prior milestones.

---

## Milestone 10: Privacy Level 1 — Infrastructure & Proof of Possession

### Objective

Build the privacy mode declaration system, implement Mode 1 (Proof of Possession), and establish the `getLogicalPlaintextHash()` function. After M10, the implementation can parse privacy blocks, resolve PoP manifests without fetching content, and gracefully degrade for unrecognized modes.

### What This Milestone Proves

That privacy metadata composes cleanly with existing v3.1.1 manifests. A manifest with `hiri:privacy` is still a valid v3.1.1 manifest — signature verification, chain integrity, and key lifecycle all work unchanged. The resolver correctly skips content retrieval for proof-of-possession manifests and reports custody assertions.

### Core Logic

#### 10.A — Privacy Mode Parser (`src/privacy/privacy-mode.ts`)

```typescript
export type PrivacyMode =
  | "public"
  | "proof-of-possession"
  | "encrypted"
  | "selective-disclosure"
  | "anonymous"
  | "attestation";

export interface PrivacyBlock {
  mode: PrivacyMode;
  parameters?: Record<string, unknown>;
  transitionFrom?: string;
  transitionReason?: string;
}

/**
 * Extract privacy mode from a manifest.
 * Returns "public" when hiri:privacy is absent (backward compatibility).
 */
export function getPrivacyMode(manifest: ResolutionManifest): PrivacyMode;

/**
 * Parse and validate the hiri:privacy block.
 * Returns null for public manifests (no privacy block).
 */
export function parsePrivacyBlock(manifest: ResolutionManifest): PrivacyBlock | null;
```

#### 10.B — Logical Plaintext Hash (`src/privacy/plaintext-hash.ts`)

```typescript
/**
 * Resolve the logical plaintext hash from a manifest,
 * regardless of privacy mode (§11.3).
 */
export function getLogicalPlaintextHash(manifest: ResolutionManifest): string;
```

Implements the normative function from §11.3. Dispatches on privacy mode:
- `public`, `proof-of-possession`, `selective-disclosure` → `content.hash`
- `encrypted` → `privacy.parameters.plaintextHash`
- `anonymous` → recurse on `contentVisibility` sub-mode
- `attestation` → throws (no content)

#### 10.C — Proof of Possession Types (`src/privacy/proof-of-possession.ts`)

```typescript
export interface ProofOfPossessionParams {
  availability: "private";
  custodyAssertion: boolean;
  refreshPolicy?: string;  // ISO 8601 duration
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

/**
 * Check if a custody assertion is stale based on refreshPolicy and created timestamp.
 */
export function isCustodyStale(
  created: string,
  refreshPolicy: string | undefined,
  verificationTime: string,
): boolean;
```

#### 10.D — Privacy-Aware Resolution Types (`src/privacy/types.ts`)

```typescript
export interface PrivacyAwareVerificationResult {
  verified: boolean;
  manifest: ResolutionManifest;
  authority: string;
  warnings: string[];

  // Privacy extension fields
  privacyMode: PrivacyMode;
  contentStatus:
    | "verified"
    | "ciphertext-verified"
    | "decrypted-verified"
    | "partial-disclosure"
    | "private-custody-asserted"
    | "attestation-verified"
    | "unsupported-mode";

  // Mode-specific (populated by later milestones)
  decryptedContent?: Uint8Array;
  disclosedNQuads?: string[];
  disclosedStatementIndices?: number[];
  attestationResult?: unknown;
  identityType?: "identified" | "anonymous-ephemeral" | "pseudonymous";
}
```

#### 10.E — Graceful Degradation

When the resolver encounters an unrecognized privacy mode:
1. Verify signature (always possible)
2. Verify chain integrity (always possible)
3. Report `contentStatus: "unsupported-mode"`
4. Do NOT reject the manifest

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Privacy Mode Parsing (§5)** | | |
| 10.1 | Parse manifest with no `hiri:privacy` block | `getPrivacyMode()` returns `"public"` |
| 10.2 | Parse manifest with `mode: "proof-of-possession"` | Returns correct mode and parameters |
| 10.3 | Parse manifest with `mode: "encrypted"` | Returns correct mode |
| 10.4 | Parse manifest with unknown mode `"future-mode"` | Returns mode string, no error |
| **Logical Plaintext Hash (§11.3)** | | |
| 10.5 | `getLogicalPlaintextHash()` for public manifest | Returns `content.hash` |
| 10.6 | `getLogicalPlaintextHash()` for proof-of-possession | Returns `content.hash` |
| 10.7 | `getLogicalPlaintextHash()` for encrypted manifest | Returns `privacy.parameters.plaintextHash` |
| 10.8 | `getLogicalPlaintextHash()` for selective-disclosure | Returns `content.hash` |
| 10.9 | `getLogicalPlaintextHash()` for anonymous+encrypted | Returns `privacy.parameters.plaintextHash` |
| 10.10 | `getLogicalPlaintextHash()` for anonymous+public | Returns `content.hash` |
| 10.11 | `getLogicalPlaintextHash()` for attestation | Throws: no logical plaintext hash |
| **Proof of Possession (§6)** | | |
| 10.12 | Resolve PoP manifest — content NOT fetched | `contentStatus: "private-custody-asserted"`, no content retrieval attempted |
| 10.13 | PoP manifest with `refreshPolicy: "P30D"`, created 15 days ago | `stale: false` |
| 10.14 | PoP manifest with `refreshPolicy: "P30D"`, created 45 days ago | `stale: true`, warning emitted |
| 10.15 | PoP manifest with no refreshPolicy | `stale: false` (never stale without policy) |
| **Graceful Degradation (§4.4)** | | |
| 10.16 | Resolve manifest with `mode: "future-mode"` | Signature verified, chain verified, `contentStatus: "unsupported-mode"` |
| 10.17 | Manifest with privacy block still verifies signature | Standard v3.1.1 signature verification succeeds |
| 10.18 | Manifest with privacy block still verifies chain | Chain walker succeeds |

**Total M10 tests:** ~18

### Execution Sequence

```
1.  Create src/privacy/ directory
2.  Create src/privacy/types.ts — PrivacyAwareVerificationResult, PrivacyMode
3.  Create src/privacy/privacy-mode.ts — mode parser, privacy block extraction
4.  Create src/privacy/plaintext-hash.ts — getLogicalPlaintextHash()
5.  Create src/privacy/proof-of-possession.ts — PoP types, staleness check
6.  Create src/privacy/resolve.ts — privacy-aware resolution dispatcher (initial)
7.  Write tests/privacy-level1.test.ts
8.  npm run build && npm test && npm run test:purity
9.  All green → M10 complete, Privacy Level 1 achieved
```

### Files Created

| File | Nature | Layer |
|------|--------|-------|
| `src/privacy/types.ts` | Privacy result types | 2 |
| `src/privacy/privacy-mode.ts` | Mode parser | 2 |
| `src/privacy/plaintext-hash.ts` | Logical plaintext hash | 2 |
| `src/privacy/proof-of-possession.ts` | PoP verification | 2 |
| `src/privacy/resolve.ts` | Privacy-aware resolution | 2 |
| `tests/privacy-level1.test.ts` | Level 1 tests | — |

### Files Modified

None. No kernel changes. No adapter changes.

---

## Milestone 11: Cryptographic Primitives

### Objective

Implement the cryptographic adapter layer needed for encrypted distribution and selective disclosure: X25519 ECDH key agreement, Ed25519↔X25519 key conversion, HKDF-SHA256 key derivation, and AES-256-GCM authenticated encryption. After M11, all crypto building blocks are available as tested, injectable adapters.

### What This Milestone Proves

That the cryptographic primitives are correct and interoperable. HKDF info construction matches the normative byte-level pseudocode (§13.2). Ed25519↔X25519 conversion round-trips correctly. AES-256-GCM encryption/decryption is deterministic and authenticated.

### Core Logic

#### 11.A — Ed25519 ↔ X25519 Conversion (`src/adapters/crypto/key-conversion.ts`)

```typescript
/**
 * Convert an Ed25519 public key to X25519 for ECDH key agreement.
 * Used to derive encryption keys from HIRI authority identities.
 */
export function ed25519PublicToX25519(edPublic: Uint8Array): Uint8Array;

/**
 * Convert an Ed25519 private key to X25519.
 */
export function ed25519PrivateToX25519(edPrivate: Uint8Array): Uint8Array;
```

Uses `@noble/curves/ed25519` for the conversion.

#### 11.B — X25519 Key Agreement (`src/adapters/crypto/x25519.ts`)

```typescript
/**
 * Generate an X25519 keypair for ephemeral ECDH.
 * Note: ephemeral keys are generated natively as X25519, NOT converted from Ed25519 (§13.3).
 */
export function generateX25519Keypair(): { publicKey: Uint8Array; privateKey: Uint8Array };

/**
 * Compute X25519 shared secret.
 */
export function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
```

#### 11.C — HKDF-SHA256 (`src/adapters/crypto/hkdf.ts`)

```typescript
/**
 * Build HKDF info parameter per §13.2 normative pseudocode.
 * Byte-level concatenation of ASCII label + UTF-8 recipient ID.
 * No separator. No framing.
 */
export function buildHKDFInfo(label: string, recipientId: string): Uint8Array;

/**
 * Derive a key via HKDF-SHA256.
 */
export function hkdfDerive(params: {
  ikm: Uint8Array;
  salt: Uint8Array;
  info: Uint8Array;
  length: number;
}): Uint8Array;
```

#### 11.D — AES-256-GCM (`src/adapters/crypto/aes-gcm.ts`)

```typescript
/**
 * Encrypt with AES-256-GCM. Returns ciphertext with appended authentication tag.
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array>;

/**
 * Decrypt with AES-256-GCM. GCM tag failure throws.
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array>;
```

Uses Web Crypto API (`crypto.subtle.encrypt/decrypt`).

#### 11.E — HMAC-SHA256 (`src/adapters/crypto/hmac.ts`)

```typescript
/**
 * Compute HMAC-SHA256 tag.
 */
export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
```

#### 11.F — Key Agreement Pipeline (`src/adapters/crypto/key-agreement.ts`)

```typescript
/**
 * Full key agreement pipeline: ECDH → HKDF → KEK → encrypt/decrypt secret key.
 * Combines 11.B, 11.C, 11.D into a single high-level operation.
 */
export async function encryptKeyForRecipient(params: {
  ephemeralPrivateKey: Uint8Array;
  recipientPublicKeyX25519: Uint8Array;
  iv: Uint8Array;
  secretKey: Uint8Array;
  recipientId: string;
  hkdfLabel: string;  // "hiri-cek-v1.1" or "hiri-hmac-v1.1"
}): Promise<Uint8Array>;

export async function decryptKeyFromSender(params: {
  ownPrivateKeyX25519: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  iv: Uint8Array;
  encryptedKey: Uint8Array;
  recipientId: string;
  hkdfLabel: string;
}): Promise<Uint8Array>;
```

### Dependencies

**New runtime dependencies (require Orchestrator approval):**

| Package | Purpose | Size |
|---------|---------|------|
| `@noble/curves` | Ed25519↔X25519, X25519 ECDH | ~45 KB |
| `@noble/hashes` | HKDF-SHA256, HMAC-SHA256 | ~25 KB |

Both are audited, widely used, zero-dependency.

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Ed25519↔X25519 Conversion (§13.3)** | | |
| 11.1 | Convert known Ed25519 public key to X25519 | Matches expected X25519 key |
| 11.2 | Convert Ed25519 private key to X25519, compute public | Matches converted public |
| 11.3 | 32-byte key accepted, 31-byte rejected | Throws on wrong length |
| **X25519 Key Agreement** | | |
| 11.4 | Generate X25519 keypair | 32-byte public, 32-byte private |
| 11.5 | ECDH: `X25519(aPriv, bPub) === X25519(bPriv, aPub)` | Shared secrets match |
| **HKDF-SHA256 (§13.2)** | | |
| 11.6 | `buildHKDFInfo("hiri-cek-v1.1", "alice")` | Matches B.14 byte sequence (18 bytes) |
| 11.7 | `buildHKDFInfo("hiri-hmac-v1.1", "alice")` | 19 bytes, different from CEK label |
| 11.8 | HKDF derivation produces 32-byte output | Correct length |
| 11.9 | Same inputs → same KEK (determinism) | Byte-identical |
| 11.10 | Different recipientId → different KEK (domain separation) | B.14: `KEK_alice ≠ KEK_bob` |
| **AES-256-GCM** | | |
| 11.11 | Encrypt then decrypt round-trip | Recovered plaintext matches original |
| 11.12 | Tampered ciphertext → decryption fails | Throws: GCM authentication failure |
| 11.13 | Wrong key → decryption fails | Throws |
| **HMAC-SHA256** | | |
| 11.14 | HMAC with known key and data | Matches expected tag |
| 11.15 | Different key → different tag | Tags differ |
| **Key Agreement Pipeline** | | |
| 11.16 | Full encrypt→decrypt round-trip for CEK | Recovered CEK matches original |
| 11.17 | Full encrypt→decrypt with HMAC label | Recovered HMAC key matches original |
| 11.18 | Wrong recipient ID → decryption fails | GCM auth failure (wrong KEK) |

**Total M11 tests:** ~18

### Execution Sequence

```
1.  npm install @noble/curves @noble/hashes (with Orchestrator approval)
2.  Create src/adapters/crypto/key-conversion.ts — Ed25519↔X25519
3.  Create src/adapters/crypto/x25519.ts — keypair generation, ECDH
4.  Create src/adapters/crypto/hkdf.ts — HKDF-SHA256, info builder
5.  Create src/adapters/crypto/aes-gcm.ts — AES-256-GCM encrypt/decrypt
6.  Create src/adapters/crypto/hmac.ts — HMAC-SHA256
7.  Create src/adapters/crypto/key-agreement.ts — high-level pipeline
8.  Write tests/crypto-primitives.test.ts
9.  npm run build && npm test && npm run test:purity
10. All green → M11 complete
```

### Files Created

| File | Nature | Layer |
|------|--------|-------|
| `src/adapters/crypto/key-conversion.ts` | Ed25519↔X25519 | 1 |
| `src/adapters/crypto/x25519.ts` | X25519 ECDH | 1 |
| `src/adapters/crypto/hkdf.ts` | HKDF-SHA256 | 1 |
| `src/adapters/crypto/aes-gcm.ts` | AES-256-GCM | 1 |
| `src/adapters/crypto/hmac.ts` | HMAC-SHA256 | 1 |
| `src/adapters/crypto/key-agreement.ts` | Key agreement pipeline | 1 |
| `tests/crypto-primitives.test.ts` | Crypto tests | — |

### Files Modified

| File | Change |
|------|--------|
| `package.json` | Add `@noble/curves`, `@noble/hashes` |

---

## Milestone 12: Privacy Level 2 — Encrypted Distribution

### Objective

Implement Mode 2 (§7): content encryption with AES-256-GCM, multi-recipient key distribution via X25519+HKDF, dual content hash verification, and opaque delta restrictions. After M12, manifests can be created with encrypted content and resolved by authorized recipients.

### What This Milestone Proves

That encrypted content is indistinguishable from random to unauthorized parties while fully verifiable by authorized recipients. The dual hash model (ciphertext hash for public verification, plaintext hash for private verification) provides integrity at both layers. Opaque deltas reveal nothing about content changes.

### Core Logic

#### 12.A — Encryption Pipeline (`src/privacy/encryption.ts`)

```typescript
export interface EncryptionResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  plaintextHash: string;
  ciphertextHash: string;
  ephemeralPublicKey: Uint8Array;
  recipients: Array<{
    id: string;
    encryptedKey: Uint8Array;
  }>;
}

/**
 * Encrypt content for multiple recipients (§7.4).
 * 1. Generate CEK + IV
 * 2. Canonicalize plaintext, compute plaintextHash
 * 3. Encrypt with AES-256-GCM
 * 4. Compute ciphertextHash
 * 5. Generate ephemeral X25519 keypair
 * 6. Per recipient: ECDH → HKDF → AES-GCM(KEK, IV, CEK)
 * 7. Destroy CEK, ePriv, shared secrets
 */
export async function encryptContent(
  canonicalBytes: Uint8Array,
  recipientPublicKeys: Map<string, Uint8Array>,  // recipientId → X25519 public key
  crypto: CryptoProvider,
  hkdfLabel?: string,      // Defaults to "hiri-cek-v1.1" for Mode 2
  hashRegistry?: HashRegistry,
): Promise<EncryptionResult>;
```

#### 12.B — Decryption Pipeline (`src/privacy/decryption.ts`)

```typescript
export interface DecryptionResult {
  plaintext: Uint8Array;
  plaintextHashValid: boolean;
}

/**
 * Decrypt content as an authorized recipient (§7.5).
 */
export async function decryptContent(
  ciphertext: Uint8Array,
  params: EncryptedPrivacyParams,
  ownPrivateKey: Uint8Array,
  ownRecipientId: string,
  crypto: CryptoProvider,
): Promise<DecryptionResult>;
```

#### 12.C — Encrypted Manifest Builder (`src/privacy/encrypted-manifest.ts`)

```typescript
/**
 * Build an unsigned manifest with encrypted content.
 * Sets format to "application/octet-stream", populates hiri:privacy block.
 */
export function buildEncryptedManifest(params: {
  baseManifestParams: ManifestParams;
  encryptionResult: EncryptionResult;
  plaintextFormat: string;
  plaintextSize: number;
}): UnsignedManifest;
```

#### 12.D — Opaque Delta Validation (`src/privacy/delta-restrictions.ts`)

```typescript
/**
 * Validate delta restrictions per privacy mode (§14).
 */
export function validatePrivacyDelta(
  mode: PrivacyMode,
  delta: ManifestDelta,
): { valid: boolean; reason?: string };
```

For encrypted mode:
- `format` MUST be `"application/octet-stream"`
- `encrypted` MUST be `true`
- `operations` MUST be `-1`
- `appliesTo` MUST NOT be present in manifest-level delta metadata (§14.3, v1.4.1: `appliesTo` lives inside the encrypted delta blob, referencing the previous logical plaintext hash)

#### 12.E — Encrypted Resolution (`src/privacy/resolve.ts` update)

Extend the privacy-aware resolver from M10:
- Fetch ciphertext, verify ciphertext hash
- If decryption key provided: decrypt, verify plaintextHash
- If no key: report `contentStatus: "ciphertext-verified"`
- Decryption failure does NOT cause overall verification to fail

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Encryption Pipeline (§7.4)** | | |
| 12.1 | Encrypt known plaintext → ciphertext differs from plaintext | Ciphertext is not plaintext |
| 12.2 | Same plaintext, different CEK → different ciphertext | Non-deterministic (fresh CEK) |
| 12.3 | Encrypt for 3 recipients → 3 encrypted key shares | Each share differs |
| **Decryption Pipeline (§7.5)** | | |
| 12.4 | Authorized recipient decrypts successfully | Plaintext matches original |
| 12.5 | Plaintext hash verified after decryption | `plaintextHashValid: true` |
| 12.6 | Wrong private key → decryption fails | GCM authentication failure |
| 12.7 | Wrong recipient ID → decryption fails | Wrong KEK derived |
| **Dual Content Hashes (§7.6)** | | |
| 12.8 | Manifest contains both ciphertext hash and plaintext hash | Both present in correct fields |
| 12.9 | Ciphertext hash verifiable without decryption key | Public verification succeeds |
| 12.10 | Plaintext hash verifiable after decryption | Private verification succeeds |
| **Manifest Structure (§7.3)** | | |
| 12.11 | Encrypted manifest has `format: "application/octet-stream"` | Correct format |
| 12.12 | Privacy block has correct parameters | algorithm, iv, tagLength, recipients, etc. |
| **Resolution (§12)** | | |
| 12.13 | Resolve encrypted manifest without key (B.2) | `contentStatus: "ciphertext-verified"` |
| 12.14 | Resolve encrypted manifest with valid key (B.3) | `contentStatus: "decrypted-verified"` |
| 12.15 | Resolve encrypted manifest with wrong key (B.4) | `contentStatus: "decryption-failed"`, `verified: true` |
| **Opaque Delta (§14.3)** | | |
| 12.16 | Encrypted manifest with opaque delta | `format: "application/octet-stream"`, `operations: -1`, `appliesTo` absent from manifest delta |
| 12.17 | Encrypted manifest with JSON Patch delta | Rejected: wrong format for encrypted mode (B.12) |
| 12.18 | Opaque delta with `appliesTo` in manifest-level metadata | Rejected: `appliesTo` must be inside encrypted blob (§14.3) |
| 12.19 | Authorized recipient decrypts delta blob, finds `appliesTo` referencing previous logical plaintext hash | Correct inner `appliesTo` value |
| **Key Agreement Identifiers (§13.2)** | | |
| 12.20 | Manifest with `keyAgreement: "X25519-HKDF-SHA256"` | Accepted, standard path |
| 12.21 | Manifest with `keyAgreement: "HPKE-Base-X25519-SHA256-AES256GCM"` | Accepted (same HKDF derivation, different identifier) |
| **Recipient Management (§7.8)** | | |
| 12.22 | Add recipient → new version with new CEK | New ciphertext, new key shares |
| 12.23 | Remove recipient → new version without that entry | Removed recipient cannot decrypt new version |

**Total M12 tests:** ~23

### Execution Sequence

```
1.  Create src/privacy/encryption.ts — encryption pipeline
2.  Create src/privacy/decryption.ts — decryption pipeline
3.  Create src/privacy/encrypted-manifest.ts — manifest builder
4.  Create src/privacy/delta-restrictions.ts — delta validation
5.  Update src/privacy/resolve.ts — encrypted mode resolution
6.  Write tests/privacy-level2.test.ts
7.  npm run build && npm test && npm run test:purity
8.  All green → M12 complete, Privacy Level 2 achieved
```

### Files Created

| File | Nature | Layer |
|------|--------|-------|
| `src/privacy/encryption.ts` | Encryption pipeline | 2 |
| `src/privacy/decryption.ts` | Decryption pipeline | 2 |
| `src/privacy/encrypted-manifest.ts` | Manifest builder | 2 |
| `src/privacy/delta-restrictions.ts` | Delta validation | 2 |
| `tests/privacy-level2.test.ts` | Level 2 tests | — |

### Files Modified

| File | Change |
|------|--------|
| `src/privacy/resolve.ts` | Add encrypted mode dispatch |
| `src/privacy/types.ts` | Add encrypted-specific result types |

---

## Milestone 13: Selective Disclosure (HMAC Suite)

### Objective

Implement Mode 3 (§8) with the mandatory HMAC disclosure proof suite: URDNA2015 statement index construction, salted statement hashing, HMAC tag generation/verification, and statement-index delta restrictions. After M13, publishers can create manifests that disclose specific RDF statements to specific recipients while provably withholding the rest.

### What This Milestone Proves

That individual RDF statements can be independently verified as belonging to a signed dataset without revealing the remaining statements. The salted statement index prevents dictionary attacks. The HMAC tags provide authentication beyond the public hash-based index. The blank node verification rule (§8.8) prevents false failures.

### Prerequisites

- URDNA2015 canonicalization is already implemented (M7). This milestone operates on URDNA2015 canonical N-Quads output.
- M11 crypto primitives are required for HMAC key distribution (X25519 + HKDF + AES-GCM).

### Core Logic

#### 13.A — Statement Index (`src/privacy/statement-index.ts`)

```typescript
/**
 * Build a salted statement index from canonical N-Quads (§8.4).
 *
 * Steps:
 * 1. Generate random 256-bit indexSalt
 * 2. Split N-Quads into individual statements
 * 3. For each statement: SHA-256(concat(rawSaltBytes, UTF-8(statement)))
 * 4. Compute indexRoot = SHA-256(concat(allRawDigests))
 */
export async function buildStatementIndex(
  canonicalNQuads: string,
  indexSalt?: Uint8Array,  // Optional: generate if not provided
): Promise<{
  statementHashes: Uint8Array[];  // Raw 32-byte digests
  indexRoot: string;              // "sha256:<hex>"
  indexSalt: Uint8Array;          // Raw 32 bytes
  statements: string[];           // Individual N-Quad strings
}>;

/**
 * Verify a single statement against the index (§8.8).
 * Hashes the N-Quad string as-is — MUST NOT re-canonicalize.
 */
export async function verifyStatementInIndex(
  statement: string,
  statementIndex: number,
  expectedHash: Uint8Array,
  indexSalt: Uint8Array,
): Promise<boolean>;
```

#### 13.B — HMAC Disclosure Proofs (`src/privacy/hmac-disclosure.ts`)

```typescript
/**
 * Generate HMAC tags for all statements (§8.6.1 — publisher side).
 */
export async function generateHmacTags(
  statements: string[],
  hmacKey: Uint8Array,
  indexSalt: Uint8Array,
): Promise<Uint8Array[]>;

/**
 * Verify a disclosed statement's HMAC tag (§8.6.1 — recipient side).
 */
export async function verifyHmacTag(
  statement: string,
  hmacKey: Uint8Array,
  indexSalt: Uint8Array,
  expectedTag: Uint8Array,
): Promise<boolean>;

/**
 * Encrypt HMAC key for recipients using Mode 2 key agreement
 * with HMAC-specific HKDF label "hiri-hmac-v1.1" (§8.6.1 step 7).
 */
export async function encryptHmacKeyForRecipients(
  hmacKey: Uint8Array,
  recipientPublicKeys: Map<string, Uint8Array>,
  iv: Uint8Array,
): Promise<{
  ephemeralPublicKey: Uint8Array;
  recipients: Array<{
    id: string;
    encryptedHmacKey: Uint8Array;
    disclosedStatements: number[] | "all";
  }>;
}>;
```

#### 13.C — Selective Disclosure Manifest Builder (`src/privacy/selective-manifest.ts`)

```typescript
/**
 * Build an unsigned manifest with selective disclosure (§8.5).
 */
export function buildSelectiveDisclosureManifest(params: {
  baseManifestParams: ManifestParams;
  statementCount: number;
  indexSalt: Uint8Array;
  indexRoot: string;
  mandatoryStatements: number[];
  hmacKeyRecipients: HmacKeyRecipients;
}): UnsignedManifest;
```

#### 13.D — Statement-Index Delta (`src/privacy/delta-restrictions.ts` update)

For selective-disclosure mode (§14.4):
- Delta format: `"application/hiri-statement-index-delta+json"`
- Contains only: `previousIndexRoot`, `currentIndexRoot`, `previousStatementCount`, `currentStatementCount`
- No operation-level detail published

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Statement Index Construction (§8.4)** | | |
| 13.1 | Build index from 4-statement N-Quads (Appendix D) | 4 hashes, valid indexRoot |
| 13.2 | Same statements + same salt → same index (determinism) | Byte-identical hashes |
| 13.3 | Same statements + different salt → different index | Hashes differ |
| 13.4 | Index root is SHA-256 of concatenated raw digests | Matches expected root |
| **Salted Hashing (§8.4.2, B.13)** | | |
| 13.5 | Salt decoded from base64url to raw bytes before concat | Correct byte-level concat |
| 13.6 | String concat produces different hash than byte concat | Different results (B.13) |
| **Statement Verification (§8.8, B.8)** | | |
| 13.7 | Verify known statement against index position | Match: true |
| 13.8 | Verify wrong statement against index position | Match: false |
| 13.9 | Statement with blank node verified without re-canonicalization (B.10) | Match: true |
| **HMAC Suite (§8.6.1, B.8)** | | |
| 13.10 | Generate HMAC tags for all statements | One tag per statement |
| 13.11 | Verify disclosed statement with correct HMAC key | Tag matches |
| 13.12 | Verify with wrong HMAC key | Tag does not match |
| 13.13 | HMAC uses `hiri-hmac-v1.1` label, not `hiri-cek-v1.1` | Different KEK from Mode 2 |
| **HMAC Key Distribution** | | |
| 13.14 | Encrypt HMAC key for 2 recipients | Each gets unique encrypted key |
| 13.15 | Recipient decrypts HMAC key, verifies disclosed statements | Full round-trip |
| **Selective Disclosure Manifest** | | |
| 13.16 | Build manifest with mandatory=[0,1,2,5] | Correct manifest structure |
| 13.17 | `content.availability` is `"partial"` | Correct field |
| 13.18 | `content.canonicalization` is `"URDNA2015"` | Required by §8.3 |
| **Statement-Index Delta (§14.4)** | | |
| 13.19 | Delta for selective disclosure — index-only format | Correct format, no operations |
| 13.20 | Reject JSON Patch delta for selective disclosure | Validation fails |
| **Context Registry Enforcement (§8.3)** | | |
| 13.21 | Selective disclosure with unregistered, un-cataloged JSON-LD context | Canonicalization fails: unknown context |
| 13.22 | Selective disclosure with context declared in `hiri:contextCatalog` + SHA-256 hash | Canonicalization succeeds |
| **Salt Defeats Dictionary Attack (B.9)** | | |
| 13.23 | Brute-force 8 candidates against salted index | Match found but no HMAC tag |

**Total M13 tests:** ~23

### Execution Sequence

```
1.  Create src/privacy/statement-index.ts — index construction + verification
2.  Create src/privacy/hmac-disclosure.ts — HMAC tag generation/verification
3.  Create src/privacy/selective-manifest.ts — manifest builder
4.  Update src/privacy/delta-restrictions.ts — statement-index delta
5.  Update src/privacy/resolve.ts — selective disclosure resolution
6.  Write tests/selective-disclosure.test.ts
7.  npm run build && npm test && npm run test:purity
8.  All green → M13 complete
```

### Files Created

| File | Nature | Layer |
|------|--------|-------|
| `src/privacy/statement-index.ts` | Statement index construction | 2 |
| `src/privacy/hmac-disclosure.ts` | HMAC disclosure proofs | 2 |
| `src/privacy/selective-manifest.ts` | SD manifest builder | 2 |
| `tests/selective-disclosure.test.ts` | SD tests | — |

### Files Modified

| File | Change |
|------|--------|
| `src/privacy/delta-restrictions.ts` | Add statement-index delta validation |
| `src/privacy/resolve.ts` | Add selective disclosure dispatch |
| `src/privacy/types.ts` | Add SelectiveDisclosureResult |

---

## Milestone 14: Anonymous Publication & Third-Party Attestation

### Objective

Implement Mode 4 (§9) and Mode 5 (§10): anonymous publication with ephemeral/pseudonymous authorities, and third-party attestation with cross-authority verification. After M14, publishers can publish without identity disclosure, and attestors can vouch for properties of another authority's content.

### What This Milestone Proves

That cryptographic anonymity is achievable within the HIRI framework without breaking verification. Ephemeral authorities are computationally unlinkable. Attestations bind cryptographically to specific manifest versions and require dual-signature verification.

### Core Logic

#### 14.A — Anonymous Publication (`src/privacy/anonymous.ts`)

```typescript
export interface AnonymousParams {
  authorityType: "ephemeral" | "pseudonymous";
  contentVisibility: "public" | "encrypted" | "private";
  identityDisclosable: boolean;
  disclosureConditions?: string;
}

/**
 * Generate an ephemeral signing keypair (§9.6).
 * Private key MUST be destroyed after signing.
 */
export function generateEphemeralAuthority(
  crypto: CryptoProvider,
): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  authority: string;
}>;

/**
 * Validate anonymous manifest constraints (§9.5).
 * Ephemeral: no KeyDocument, no rotation, no revocation.
 */
export function validateAnonymousConstraints(
  manifest: ResolutionManifest,
  params: AnonymousParams,
): { valid: boolean; reason?: string };
```

#### 14.B — Attestation Manifest (`src/privacy/attestation.ts`)

```typescript
export interface AttestationSubject {
  authority: string;
  manifestHash: string;
  contentHash: string;
  manifestVersion: string;
}

export interface AttestationClaim {
  "@type": "hiri:PropertyAttestation";
  property: string;
  value: unknown;
  scope?: string;
  attestedAt: string;
  validUntil?: string;
}

export interface AttestationEvidence {
  method: string;
  description: string;
}

export interface AttestationManifest {
  // Standard fields (minus hiri:content)
  "@context": string[];
  "@id": string;
  "@type": "hiri:AttestationManifest";
  "hiri:version": string;
  "hiri:branch": string;
  "hiri:timing": { created: string };
  "hiri:privacy": { mode: "attestation" };
  "hiri:attestation": {
    subject: AttestationSubject;
    claim: AttestationClaim;
    evidence: AttestationEvidence;
  };
  "hiri:signature"?: HiriSignature;
  "hiri:chain"?: ChainBlock;
}

/**
 * Build an unsigned attestation manifest (§10.2).
 */
export function buildAttestationManifest(params: {
  attestorAuthority: string;
  attestationId: string;
  subject: AttestationSubject;
  claim: AttestationClaim;
  evidence: AttestationEvidence;
  version: string;
  chain?: ChainParams;
}): AttestationManifest;

/**
 * Verify an attestation: dual-signature verification (§10.5).
 */
export async function verifyAttestation(
  attestation: AttestationManifest,
  attestorPublicKey: Uint8Array,
  subjectManifest: ResolutionManifest | null,
  subjectPublicKey: Uint8Array | null,
  crypto: CryptoProvider,
): Promise<AttestationVerificationResult>;
```

#### 14.C — Attestation Verification Result

```typescript
export interface AttestationVerificationResult {
  attestationVerified: boolean;
  attestorAuthority: string;
  attestorKeyStatus: string;
  subjectManifestVerified: boolean;
  claim: {
    property: string;
    value: unknown;
    scope?: string;
  };
  stale: boolean;
  trustLevel: "full" | "partial" | "unverifiable";
  warnings: string[];
}
```

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Anonymous Publication (§9)** | | |
| 14.1 | Generate ephemeral authority | Valid authority string, fresh keypair |
| 14.2 | Sign manifest with ephemeral key | Signature verifies |
| 14.3 | Ephemeral authority has no KeyDocument (§9.5) | Resolver reports `identity: "anonymous-ephemeral"` |
| 14.4 | Pseudonymous authority — two manifests linkable | Same public key in both |
| 14.5 | Two ephemeral authorities — computationally unlinkable | Different keys, different authorities |
| 14.6 | Anonymous + encrypted content visibility | Content encrypted, publisher anonymous |
| 14.7 | Anonymous + public content visibility | Content readable, publisher anonymous |
| 14.8 | Resolve anonymous ephemeral manifest (B.5) | `identityType: "anonymous-ephemeral"`, `keyDocumentResolved: false` |
| **Attestation (§10)** | | |
| 14.9 | Build attestation manifest — no `hiri:content` block (§10.4) | Content block absent |
| 14.10 | Attestation has required minimum fields (§10.4) | All required fields present |
| 14.11 | Verify attestation signature | `attestationVerified: true` |
| 14.12 | Verify attestation + subject manifest (dual sig) | `trustLevel: "full"` |
| 14.13 | Attestation — subject manifest unavailable (B.6) | `trustLevel: "partial"`, `subjectManifestVerified: false` |
| 14.14 | AttestationManifest WITH a `hiri:content` block (§10.4) | Rejected: content block MUST NOT be present |
| 14.15 | Stale attestation (validUntil passed) | `stale: true`, warning emitted |
| 14.16 | Attestation chain: 3 versions (clearance updates, §10.6) | Chain verifies |
| 14.17 | Attestation — attestor key revoked, subject unavailable | `trustLevel: "unverifiable"` |
| 14.18 | `getLogicalPlaintextHash()` for attestation | Throws (§11.3) |

**Total M14 tests:** ~18

### Execution Sequence

```
1.  Create src/privacy/anonymous.ts — ephemeral/pseudonymous authorities
2.  Create src/privacy/attestation.ts — attestation manifest + verification
3.  Update src/privacy/resolve.ts — anonymous + attestation dispatch
4.  Write tests/anonymous-attestation.test.ts
5.  npm run build && npm test && npm run test:purity
6.  All green → M14 complete
```

### Files Created

| File | Nature | Layer |
|------|--------|-------|
| `src/privacy/anonymous.ts` | Anonymous publication | 2 |
| `src/privacy/attestation.ts` | Attestation manifest + verification | 2 |
| `tests/anonymous-attestation.test.ts` | Anonymous + attestation tests | — |

### Files Modified

| File | Change |
|------|--------|
| `src/privacy/resolve.ts` | Add anonymous + attestation dispatch |
| `src/privacy/types.ts` | Add AttestationVerificationResult |

---

## Milestone 15: Privacy Level 3 Integration — Lifecycle & Full Resolution

### Objective

Implement privacy lifecycle transitions (§11), cross-mode chain walking with `getLogicalPlaintextHash()`, and the full extended resolution algorithm (§12). After M15, the implementation declares Privacy Level 3 (Full) conformance. All five modes work end-to-end, chains can span multiple privacy modes, and the resolver correctly dispatches on any mode.

### What This Milestone Proves

That privacy modes compose with version chains. A document can transition from proof-of-possession to encrypted to public, and the chain walker verifies integrity at every step using `getLogicalPlaintextHash()`. The extended resolution algorithm handles every mode combination. The addressing mode consistency rule (§11.3) is enforced.

### Core Logic

#### 15.A — Privacy-Aware Chain Walker (`src/privacy/chain-walker.ts`)

```typescript
/**
 * Walk a chain across privacy mode transitions.
 *
 * Uses getLogicalPlaintextHash() instead of raw content.hash for
 * cross-version comparison (§11.3). Validates addressing mode consistency.
 */
export async function verifyPrivacyChain(
  head: ResolutionManifest,
  publicKey: Uint8Array,
  fetchManifest: ManifestFetcher,
  fetchContent: ContentFetcher,
  crypto: CryptoProvider,
  options?: PrivacyChainOptions,
): Promise<PrivacyChainWalkResult>;

export interface PrivacyChainOptions {
  canonicalizer?: Canonicalizer;
  documentLoader?: DocumentLoader;
  hashRegistry?: HashRegistry;
  decryptionKey?: Uint8Array;
  recipientId?: string;
}

export interface PrivacyChainWalkResult {
  valid: boolean;
  depth: number;
  warnings: string[];
  modeTransitions: Array<{
    fromVersion: string;
    toVersion: string;
    fromMode: PrivacyMode;
    toMode: PrivacyMode;
  }>;
  reason?: string;
}
```

#### 15.B — Transition Validation (`src/privacy/lifecycle.ts`)

```typescript
/**
 * Validate a privacy mode transition (§11.2).
 * Transitions are monotonically decreasing in privacy.
 */
export function validateTransition(
  fromMode: PrivacyMode,
  toMode: PrivacyMode,
): { valid: boolean; reason?: string };

/**
 * Validate addressing mode consistency across a chain (§11.3).
 * The addressing mode used for logical plaintext hash MUST be constant.
 */
export function validateAddressingConsistency(
  currentManifest: ResolutionManifest,
  previousManifest: ResolutionManifest,
): { valid: boolean; reason?: string };
```

#### 15.C — Full Extended Resolution (`src/privacy/resolve.ts` final)

Complete the resolution dispatcher (§12) with all mode paths:
- `public` → standard v3.1.1
- `proof-of-possession` → skip content, custody assertion
- `encrypted` → ciphertext verify, optional decrypt
- `selective-disclosure` → index root verify, HMAC verify
- `anonymous` → identity type reporting, content sub-mode dispatch
- `attestation` → dual signature verification
- Unknown → signature + chain only, unsupported-mode status

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| **Privacy Lifecycle Transitions (§11)** | | |
| 15.1 | PoP → Encrypted (valid transition) | Accepted |
| 15.2 | PoP → Public (valid transition) | Accepted |
| 15.3 | Encrypted → Public (valid transition) | Accepted |
| 15.4 | Encrypted → PoP (INVALID — cannot withdraw, §11.2) | Rejected |
| 15.5 | Public → PoP (INVALID) | Rejected |
| 15.6 | PoP → Selective Disclosure (valid) | Accepted |
| 15.7 | Selective Disclosure → Public (valid) | Accepted |
| **Cross-Mode Chain Walking (§11.3, B.7, B.15)** | | |
| 15.8 | 3-version chain: PoP → Encrypted → Public (B.15) | Chain valid, logical plaintext hash consistent |
| 15.9 | Chain walker uses `getLogicalPlaintextHash()`, not raw content.hash | Correct cross-mode comparison |
| 15.10 | Raw content.hash comparison across PoP→Encrypted would fail | Demonstrates why `getLogicalPlaintextHash()` is needed |
| **Addressing Mode Consistency (§11.3)** | | |
| 15.11 | All versions use `raw-sha256` | Accepted |
| 15.12 | V1 `raw-sha256`, V2 `cidv1-dag-cbor` | Rejected: inconsistent addressing |
| **Full Resolution Algorithm (§12)** | | |
| 15.13 | Resolve public manifest | `contentStatus: "verified"` |
| 15.14 | Resolve PoP manifest | `contentStatus: "private-custody-asserted"` |
| 15.15 | Resolve encrypted (no key) | `contentStatus: "ciphertext-verified"` |
| 15.16 | Resolve encrypted (valid key) | `contentStatus: "decrypted-verified"` |
| 15.17 | Resolve selective disclosure | `contentStatus: "partial-disclosure"` |
| 15.18 | Resolve anonymous ephemeral | `identityType: "anonymous-ephemeral"` |
| 15.19 | Resolve attestation | `contentStatus: "attestation-verified"` |
| 15.20 | Resolve unknown mode | `contentStatus: "unsupported-mode"` |
| 15.21 | Resolve anonymous + selective disclosure | Anonymous publisher, partial disclosure, correct dispatch |
| **KeyDocument Cache Staleness (§13.1)** | | |
| 15.22 | Resolve encrypted manifest with stale-cached KeyDocument | Verification succeeds with `keyDocumentStale: true` warning |
| **Metadata Hardening (§15.3)** | | |
| 15.23 | Manifest with padded statement count (12 → 16 with 4 padding N-Quads) | Statement index verifies, index root correct |
| 15.24 | Manifest with dummy recipients (2 extra) | Encryption/decryption still works for real recipients |

**Total M15 tests:** ~24

### Execution Sequence

```
1.  Create src/privacy/lifecycle.ts — transition validation, addressing consistency
2.  Create src/privacy/chain-walker.ts — privacy-aware chain walker
3.  Finalize src/privacy/resolve.ts — all mode paths
4.  Write tests/privacy-level3.test.ts
5.  npm run build && npm test && npm run test:purity
6.  All green → M15 complete, Privacy Level 3 achieved
```

### Files Created

| File | Nature | Layer |
|------|--------|-------|
| `src/privacy/lifecycle.ts` | Transition validation | 2 |
| `src/privacy/chain-walker.ts` | Privacy-aware chain walker | 2 |
| `tests/privacy-level3.test.ts` | Level 3 integration tests | — |

### Files Modified

| File | Change |
|------|--------|
| `src/privacy/resolve.ts` | Complete all mode paths |
| `src/privacy/types.ts` | Final result types |

---

## Verification Checklist (All Milestones)

After each milestone:

1. `npm run build` — zero TypeScript errors
2. `npm test` — all tests pass (existing 144 + new privacy tests)
3. `npm run test:purity` — kernel purity verified (privacy code is NOT kernel)
4. No kernel files modified
5. No new runtime dependencies without Orchestrator approval
6. `src/privacy/` imports only from `src/kernel/` (types) and `src/adapters/` (crypto)

After M10:

7. Privacy Level 1 conformance per §16.1

After M12:

8. Privacy Level 2 conformance per §16.2
9. Dual hash model verified end-to-end
10. Opaque delta restrictions enforced

After M15:

11. Privacy Level 3 conformance per §16.3
12. All five modes verified end-to-end
13. Cross-mode chain walking verified (B.15)
14. All Appendix B test vectors pass (B.1–B.15)
15. Extended resolution algorithm handles all modes

---

## Summary

| Milestone | Deliverable | Conformance | New Tests | Cumulative |
|-----------|-------------|-------------|-----------|------------|
| M10 | Privacy infrastructure + Proof of Possession | Privacy Level 1 | ~18 | 162 |
| M11 | X25519, HKDF, AES-GCM, HMAC adapters | — (building blocks) | ~18 | 180 |
| M12 | Encrypted Distribution + opaque deltas | Privacy Level 2 | ~23 | 203 |
| M13 | Selective Disclosure (HMAC suite) | — (Level 3 partial) | ~23 | 226 |
| M14 | Anonymous Publication + Attestation | — (Level 3 partial) | ~18 | 244 |
| M15 | Lifecycle transitions + full resolution | Privacy Level 3 | ~24 | 268 |

**Total new privacy files:** ~15 (`src/privacy/` + `src/adapters/crypto/`)
**Total new test files:** 6
**New runtime dependencies:** 2 (`@noble/curves`, `@noble/hashes`) — M11 only
**Kernel files modified:** 0
**Estimated total tests post-M15:** ~268 (144 existing + ~124 privacy)

---

## Risk Notes

- **OneDrive EEXIST errors:** Edit/Write tools may fail. Python script workaround available.
- **BBS+ deferred:** BBS+ suite (`hiri-bbs-sd-2026`) is RECOMMENDED but not REQUIRED for Level 3. It requires a BBS+ library (pairing-friendly curves) which adds significant complexity. It is deferred to a future milestone if the Orchestrator approves.
- **Commitment model deferred:** §17 (Pedersen commitments) is explicitly marked future/non-normative. Not in scope.
- **No kernel changes:** All privacy code is Layer 2. If a kernel change is ever discovered to be necessary, STOP and request Architectural Review.
- **Web Crypto API dependency:** AES-256-GCM uses `crypto.subtle`. This is available in Node.js ≥15 and all modern browsers. Same as existing SHA-256 adapter.
- **HPKE alternative:** §13.2 allows either explicit HKDF construction OR RFC 9180 HPKE. This implementation uses the explicit HKDF construction internally but accepts manifests declaring either `"X25519-HKDF-SHA256"` or `"HPKE-Base-X25519-SHA256-AES256GCM"` as `keyAgreement` identifiers (both produce identical KEKs). Full HPKE library integration is a future enhancement.
