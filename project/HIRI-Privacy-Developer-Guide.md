# HIRI Privacy Extension — Developer Guide

**Companion to:** HIRI Privacy & Confidentiality Extension v1.4.1
**Prerequisite:** HIRI Protocol Developer Guide (M1–M8)
**Implementation Reference:** M10–M15 (269 tests, Privacy Level 3)

---

## How to Read This Guide

This guide is organized by conformance level. If you're building a public-only HIRI implementation, you don't need this guide at all — your resolver already handles public manifests. Start reading when your use case requires one of the five privacy modes.

The guide follows the same progression as the spec's conformance levels:

- **Level 1** (§16.1): Recognize privacy modes, pass through what you don't understand
- **Level 2** (§16.2): Implement encrypted distribution and selective disclosure
- **Level 3** (§16.3): Support cross-mode chains, lifecycle transitions, and metadata hardening

Each section includes runnable code using the HIRI public API, spec section references (§), and test vector references (B.) from Appendix B.

---

## 1. The Single Entry Point: `resolveWithPrivacy()`

Every privacy-aware resolution goes through one function. If you remember nothing else from this guide, remember this: do not call the kernel's `resolve()` directly for manifests that might have a `hiri:privacy` block. Use `resolveWithPrivacy()` instead.

```typescript
import { resolveWithPrivacy } from "hiri/privacy/resolve.js";

const result = await resolveWithPrivacy(uri, storage, {
  crypto,
  publicKey,
  manifestHash,
  // Optional, mode-dependent:
  decryptionKey,      // X25519 private key (Mode 2, Mode 3)
  recipientId,        // Your recipient identifier (Mode 2, Mode 3)
  subjectPublicKey,   // Subject authority's key (Mode 5)
  attestorKeyStatus,  // "active" | "revoked" (Mode 5)
  verificationTime,   // ISO 8601 timestamp for staleness checks
  keyDocumentTimestamp, // When the KeyDocument was last fetched
  keyDocumentMaxAge,   // Max staleness in milliseconds
});
```

The result always contains:

```typescript
interface PrivacyAwareVerificationResult {
  verified: boolean;            // Signature + chain integrity
  privacyMode: string;          // "public" | "proof-of-possession" | "encrypted" | ...
  contentStatus: string;        // Mode-specific content verification outcome
  identityType?: string;        // For anonymous: "anonymous-ephemeral" | "pseudonymous"
  warnings: string[];           // Staleness, key status, verification notes
  manifest: ResolutionManifest; // The verified manifest
  authority: string;            // Publisher's authority string
  // Mode-specific fields:
  decryptedContent?: Uint8Array;          // Mode 2 with valid key
  disclosedNQuads?: string[];             // Mode 3 mandatory statements
  disclosedStatementIndices?: number[];   // Mode 3 indices
  attestationResult?: AttestationVerificationResult; // Mode 5
}
```

The resolver dispatches internally based on the manifest's `hiri:privacy.mode` field. You never need to write mode-detection logic yourself.

---

## 2. When to Use Each Mode — Decision Tree

```
Does the content need to exist publicly?
├── Yes → Mode: public (no privacy block needed)
└── No
    ├── Does the publisher need to prove they HAVE the data
    │   without revealing it?
    │   └── Yes → Mode 1: Proof of Possession (§6)
    │
    ├── Should specific recipients be able to read the full content?
    │   └── Yes → Mode 2: Encrypted Distribution (§7)
    │
    ├── Should recipients see SOME statements but not others?
    │   └── Yes → Mode 3: Selective Disclosure (§8)
    │
    ├── Should the publisher's identity be hidden?
    │   └── Yes → Mode 4: Anonymous Publication (§9)
    │       └── Combined with any content visibility:
    │           public, encrypted, selective-disclosure, or private
    │
    └── Does a third party need to vouch for a property
        of someone else's content?
        └── Yes → Mode 5: Third-Party Attestation (§10)
```

Modes 1–3 are about content visibility. Mode 4 is about identity visibility. Mode 5 is about cross-authority trust. Modes can compose: an anonymous publisher (Mode 4) can use selective disclosure (Mode 3) for content — this is the "anonymous whistleblower" use case (§4.6).

---

## 3. Level 1: Recognizing Privacy Modes

Level 1 conformance means your resolver can encounter a privacy manifest and not crash. You verify the signature and chain, report the mode, and return `contentStatus: "unsupported-mode"` for modes you don't implement.

### 3.1 Detecting the Privacy Block

```typescript
import { getPrivacyMode, isKnownPrivacyMode } from "hiri/privacy/privacy-mode.js";

const mode = getPrivacyMode(manifest);
// Returns: "public" | "proof-of-possession" | "encrypted" | 
//          "selective-disclosure" | "anonymous" | "attestation" | string

if (!isKnownPrivacyMode(mode)) {
  // Future mode — verify signature + chain, return "unsupported-mode"
  // Do NOT reject the manifest (§4.4)
}
```

The critical rule: unknown privacy modes are NOT errors. A Level 1 resolver MUST verify the signature and chain integrity, MUST report the mode in its result, and MUST NOT reject the manifest. It returns `contentStatus: "unsupported-mode"` with a warning. The manifest is `verified: true` (the cryptography is valid) even though the content is inaccessible.

### 3.2 Proof of Possession (Mode 1)

PoP is the simplest privacy mode. The publisher signs a manifest whose `content.hash` references data they hold, but the data is never stored in the content-addressable network. The resolver verifies the signature and chain, but does not fetch content.

```typescript
import { isCustodyStale } from "hiri/privacy/proof-of-possession.js";

// Check if the custody assertion is stale
const stale = isCustodyStale(
  manifest["hiri:timing"].created,  // When the assertion was made
  refreshPolicy,                     // "P30D", "P90D", etc. (ISO 8601 duration)
  verificationTime,                  // When the verifier is checking
);

// Result:
// contentStatus: "private-custody-asserted"
// The content hash is in the manifest, but the content bytes are NOT fetchable
```

PoP manifests use the same signing and chain infrastructure as public manifests. The only difference is that the content is never stored, and the resolver knows not to attempt a content fetch.

### 3.3 The `getLogicalPlaintextHash()` Function

This function exists for one reason: cross-mode chain walking. Different modes store the content hash differently:

- **Public:** `content.hash` IS the plaintext hash
- **PoP:** `content.hash` IS the plaintext hash (content just isn't stored)
- **Encrypted:** `content.hash` is the CIPHERTEXT hash; the plaintext hash is in `privacy.parameters.plaintextHash`
- **Selective Disclosure:** `content.hash` is the hash of the SD content blob; no single "plaintext hash" exists

```typescript
import { getLogicalPlaintextHash } from "hiri/privacy/plaintext-hash.js";

const { hash, warnings } = getLogicalPlaintextHash(manifest);
// Returns the plaintext-equivalent hash regardless of mode
// Throws for attestation manifests (no content block)
```

You need this when walking a chain where versions use different privacy modes. Raw `content.hash` comparison across a PoP → Encrypted transition FAILS because V1's `content.hash` is the plaintext hash and V2's `content.hash` is the ciphertext hash. `getLogicalPlaintextHash()` returns the plaintext hash for both.

This is test vector B.15 in the spec. If you skip this function, your chain walker will reject valid cross-mode chains.

---

## 4. Level 2: Encrypted Distribution

### 4.1 The Dual Hash Model

Encrypted manifests have two hashes:

```
manifest["hiri:content"].hash           → ciphertext hash (public)
manifest["hiri:privacy"].parameters.plaintextHash → plaintext hash (in privacy block)
```

The ciphertext hash is what storage adapters use for content-addressed lookup. The plaintext hash is what `getLogicalPlaintextHash()` returns for chain walking. Both are SHA-256. The ciphertext hash is computed AFTER encryption; the plaintext hash is computed BEFORE encryption.

This means a storage adapter can verify it received the correct ciphertext without being able to decrypt it. The ciphertext hash serves the same integrity role as `content.hash` does for public manifests.

### 4.2 Encrypting Content

```typescript
import { encryptContent } from "hiri/privacy/encryption.js";
import { buildEncryptedManifest } from "hiri/privacy/encrypted-manifest.js";
import { generateX25519Keypair } from "hiri/adapters/crypto/x25519.js";

// Generate recipient keys (or use existing ones)
const alice = generateX25519Keypair();
const bob = generateX25519Keypair();

// Encrypt
const encResult = await encryptContent(
  plaintextBytes,
  new Map([["alice", alice.publicKey], ["bob", bob.publicKey]]),
  crypto,
);
// encResult contains: ciphertext, iv, plaintextHash, ciphertextHash,
//                     ephemeralPublicKey, recipients[]

// Build the manifest
const manifest = buildEncryptedManifest({
  baseManifestParams: { id, version, branch, created, addressing, canonicalization },
  encryptionResult: encResult,
  plaintextFormat: "application/ld+json",
  plaintextSize: plaintextBytes.length,
});

// Sign normally
const signed = await signManifest(manifest, signingKey, created, "JCS", crypto);
```

The encryption pipeline: generate a random 256-bit CEK and 96-bit IV → hash the plaintext → AES-256-GCM encrypt the content → hash the ciphertext → generate an ephemeral X25519 keypair → for each recipient: ECDH(ephemeral, recipient) → HKDF(shared, "hiri-cek-v1.1", recipientId) → AES-GCM(KEK, IV, CEK). The CEK and ephemeral private key are zeroed after use.

### 4.3 Decrypting Content

```typescript
import { decryptContent } from "hiri/privacy/decryption.js";

const result = await decryptContent(
  ciphertextBytes,
  encryptedPrivacyParams, // Parsed from manifest's hiri:privacy.parameters
  alicePrivateKey,        // Alice's X25519 private key
  "alice",                // Must match the recipient ID used during encryption
  crypto,
);
// result.plaintext: Uint8Array
// result.plaintextHashValid: boolean (compare against privacy.parameters.plaintextHash)
```

Three possible outcomes when resolving an encrypted manifest:

| Scenario | `contentStatus` | `verified` |
|----------|-----------------|------------|
| No decryption key provided | `"ciphertext-verified"` | `true` |
| Valid recipient key | `"decrypted-verified"` | `true` |
| Wrong key / not a recipient | `"decryption-failed"` | `true` |

Note: `verified` is `true` in ALL cases. Signature and chain verification are orthogonal to content decryption. A manifest with a valid signature but a failed decryption is still a verified manifest — you just can't read the content.

### 4.4 HKDF Label: Domain Separation

The HKDF label `"hiri-cek-v1.1"` is used for Mode 2 (encrypted) CEK distribution. Mode 3 (selective disclosure) uses `"hiri-hmac-v1.1"` for HMAC key distribution. These labels MUST be different — they produce different key encryption keys from the same ECDH shared secret. If you accidentally use the wrong label, AES-GCM decryption will fail with an authentication error.

```
Mode 2 (Encrypted):            HKDF(shared, "hiri-cek-v1.1",  recipientId) → KEK for CEK
Mode 3 (Selective Disclosure):  HKDF(shared, "hiri-hmac-v1.1", recipientId) → KEK for HMAC key
```

The HKDF info parameter is constructed as: `concat(UTF-8(label), UTF-8(recipientId))` — no separator between label and ID. This means `buildHKDFInfo("hiri-cek-v1.1", "alice")` produces 18 bytes and `buildHKDFInfo("hiri-hmac-v1.1", "alice")` produces 19 bytes.

---

## 5. Level 2: Selective Disclosure

### 5.1 Concepts

Selective disclosure lets a publisher canonicalize a JSON-LD document into individual RDF statements (N-Quads), then disclose some statements publicly while withholding others. Each statement gets:

- A salted SHA-256 hash (in the statement index)
- An HMAC-SHA-256 tag (for authorized verification)

The publisher decides which statements are mandatory (always visible) and which are withheld. Recipients get the HMAC key encrypted for them, along with a list of which statement indices they're authorized to see.

### 5.2 Building a Statement Index

```typescript
import { buildStatementIndex } from "hiri/privacy/statement-index.js";
import { generateHmacTags, encryptHmacKeyForRecipients } from "hiri/privacy/hmac-disclosure.js";

// Start with canonical N-Quads (from URDNA2015 canonicalization)
const indexResult = await buildStatementIndex(canonicalNQuads);
// indexResult.statements: string[]        — individual N-Quad strings
// indexResult.statementHashes: Uint8Array[] — raw 32-byte salted SHA-256 digests
// indexResult.indexRoot: string            — "sha256:<hex>" of concatenated digests
// indexResult.indexSalt: Uint8Array        — raw 32 bytes

// Generate HMAC tags
const hmacKey = crypto.getRandomValues(new Uint8Array(32));
const tags = generateHmacTags(statements, hmacKey, indexResult.indexSalt);

// Encrypt HMAC key for recipients with per-recipient disclosure scope
const distribution = await encryptHmacKeyForRecipients(
  hmacKey,
  recipientPublicKeys,  // Map<string, Uint8Array>
  disclosureMap,        // Map<string, number[] | "all">
);

// Zero the HMAC key
hmacKey.fill(0);
```

### 5.3 The Byte-Level Concatenation Rule (CRITICAL)

This is the most common implementation bug. The spec (§8.4.2) requires:

```
statementHash[i] = SHA-256(concat(rawSaltBytes, UTF-8(statement)))
```

This is BYTE-LEVEL concatenation of two `Uint8Array` values. NOT string concatenation.

```typescript
// CORRECT: byte-level concat
const stmtBytes = new TextEncoder().encode(statement);
const input = new Uint8Array(salt.length + stmtBytes.length);
input.set(salt, 0);
input.set(stmtBytes, salt.length);
const hash = await crypto.subtle.digest("SHA-256", input);

// WRONG: string concat (produces different hash!)
const saltB64 = base64urlEncode(salt);
const input = new TextEncoder().encode(saltB64 + statement);
const hash = await crypto.subtle.digest("SHA-256", input);
```

The wrong approach encodes the salt as a base64url string, concatenates it with the statement string, then encodes the combined string to bytes. This produces a completely different hash because the base64url encoding of the salt has different bytes than the raw salt.

Test vector B.13 in the spec proves these two approaches produce different hashes. If your implementation uses string concatenation, every hash will be wrong and no cross-implementation verification will succeed.

The same rule applies to the index root (§8.4.2 step 6):

```
indexRoot = SHA-256(concat(rawDigest[0], rawDigest[1], ..., rawDigest[N-1]))
```

Concatenate raw 32-byte digest arrays, NOT hex-encoded strings. A hex string of a 32-byte hash is 64 bytes — concatenating hex strings would produce an input twice as large as intended.

### 5.4 The No-Re-Canonicalization Rule

When verifying a disclosed statement against its hash in the index, verifiers MUST NOT re-canonicalize the statement (§8.8). Hash the N-Quad string as-is, including any blank node labels (`_:c14n0`).

Why? URDNA2015 assigns deterministic blank node labels based on the entire graph. If you re-canonicalize a single statement in isolation, the blank node labels may change, producing a different hash. The publisher canonicalized the complete document once; verifiers hash each statement string as it was produced by that single canonicalization pass.

```typescript
import { verifyStatementInIndex } from "hiri/privacy/statement-index.js";

// Correct: hash the statement string as-is
const valid = await verifyStatementInIndex(
  statement,      // The N-Quad string exactly as published
  expectedHash,   // The raw 32-byte hash from the statement index
  indexSalt,      // Raw 32-byte salt
);
// Do NOT call canonicalizer.canonicalize() on the statement first!
```

### 5.5 Dictionary Attack Defense

The statement index uses a per-manifest random salt. This prevents rainbow table attacks — an attacker cannot precompute hashes for all possible statement values.

However, for low-entropy fields (like blood type with 8 possible values, or birth dates within a 100-year range), an attacker who knows the predicate and subject can enumerate all candidates, compute their salted hashes, and compare against withheld positions. The salt is in the manifest (it must be, so recipients can verify), so this enumeration is always possible in theory.

The HMAC key is the second line of defense. Even if an attacker finds a salted hash match, they cannot produce the HMAC tag without the secret HMAC key. The HMAC key is encrypted for authorized recipients only.

This is a defense-in-depth model:

- **Salt** defeats rainbow tables (pre-computation across manifests)
- **HMAC key** defeats per-manifest enumeration (targeted attack on one manifest)

For high-entropy fields (free-text names, UUIDs, long strings), the salt alone provides strong protection. For low-entropy fields, the HMAC key is essential.

Test 13.23 demonstrates this: 8 candidate values, attacker finds the salted hash match, but cannot forge the HMAC tag. See also §B.9 in the spec.

### 5.6 Context Registry and URDNA2015

Selective disclosure requires URDNA2015 canonicalization (§8.3), which requires JSON-LD context resolution. The spec mandates a context registry — a pre-approved set of JSON-LD contexts with pinned SHA-256 hashes. The canonicalizer MUST NOT fetch contexts from the network at runtime.

```typescript
import { URDNA2015Canonicalizer } from "hiri/adapters/canonicalization/urdna2015-canonicalizer.js";
import { createCatalogDocumentLoader } from "hiri/adapters/canonicalization/secure-document-loader.js";

const documentLoader = createCatalogDocumentLoader({
  "https://schema.org": SCHEMA_ORG_CONTEXT,  // Embedded, not fetched
  "https://custom.example.org/v1": CUSTOM_CONTEXT,
});

const canonicalizer = new URDNA2015Canonicalizer();
const nquads = await canonicalizer.canonicalize(document, documentLoader);
```

If a document references a context URL not in the registry, canonicalization MUST fail. This prevents context manipulation attacks where an attacker modifies a remote context to change how terms resolve, altering the canonical N-Quads without changing the source document.

### 5.7 HMAC Verification Boundary

HMAC tag verification requires the statement text. The published SD content blob only contains mandatory N-Quad strings — withheld statement text is not stored publicly. This creates a verification boundary:

- **Mandatory statements:** Verifiable by anyone. The statement text is in the published blob, so the salted hash and HMAC tag can both be checked.
- **Non-mandatory disclosed statements:** Authorized but not verifiable from the published blob alone. The recipient has the HMAC key (proving authorization), but the statement text must be delivered via a separate channel (e.g., direct sharing, encrypted side-channel). HMAC tag verification is only possible once the recipient has the actual N-Quad string.

A resolver that attempts HMAC verification for non-mandatory statements using the published blob will fail — the mandatory N-Quads array does not contain withheld statements, and looking up an index that returns `-1` produces an empty string, which hashes to the wrong value.

```typescript
// WRONG: verify all disclosed statements against mandatoryNQuads
for (const idx of disclosedIndices) {
  const mandatoryPos = mandatoryStatements.indexOf(idx);
  // mandatoryPos is -1 for non-mandatory statements!
  const stmt = mandatoryNQuads[mandatoryPos] ?? ""; // empty string → wrong HMAC
  verifyHmacTag(stmt, hmacKey, salt, tags[idx]); // FAILS
}

// CORRECT: only verify statements whose text is available
for (const idx of disclosedIndices) {
  const mandatoryPos = mandatoryStatements.indexOf(idx);
  if (mandatoryPos !== -1) {
    // Text available in published blob — verify HMAC tag
    verifyHmacTag(mandatoryNQuads[mandatoryPos], hmacKey, salt, tags[idx]);
  }
  // Non-mandatory: HMAC key decryption success proves authorization.
  // Tag verification requires out-of-band statement delivery.
}
```

This is an inherent property of the SD storage model, not a bug. The published blob is minimal by design — it contains only what public verifiers need.

---

## 6. Anonymous Publication

### 6.1 Ephemeral vs. Pseudonymous

Anonymous publication (Mode 4) separates identity from content. Two authority types:

**Ephemeral:** One-time keypair. The private key is destroyed after signing. Two ephemeral publications are computationally unlinkable — different keys, different authorities, no way to prove they came from the same publisher.

```typescript
import { generateEphemeralAuthority } from "hiri/privacy/anonymous.js";

const eph = await generateEphemeralAuthority();
// eph.publicKey, eph.privateKey, eph.authority

// Sign the manifest...
const signed = await signManifest(manifest, ephSigningKey, created, "JCS", crypto);

// MUST destroy the private key after signing
eph.privateKey.fill(0);
```

**Pseudonymous:** Persistent keypair not linked to a real-world identity. Multiple publications from the same pseudonym are linkable (same authority string), but the authority doesn't resolve to a known identity.

Ephemeral authorities MUST NOT have a KeyDocument reference (§9.5). The resolver skips KeyDocument resolution for ephemeral authorities and reports `identityType: "anonymous-ephemeral"`.

### 6.2 Content Visibility

Anonymous publication combines with any content visibility mode. The `contentVisibility` parameter in the privacy block tells the resolver which content handler to use:

| `contentVisibility` | Content Handler | `contentStatus` |
|---------------------|-----------------|-----------------|
| `"public"` | Standard content fetch + hash verify | `"verified"` |
| `"encrypted"` | Encrypted distribution pipeline | `"ciphertext-verified"` or `"decrypted-verified"` |
| `"selective-disclosure"` | Statement index + HMAC verification | `"partial-disclosure"` |
| `"private"` | Proof of Possession (no content fetch) | `"private-custody-asserted"` |

The anonymous whistleblower use case (§4.6) combines ephemeral authority with selective disclosure: the publisher's identity is unlinkable, and only authorized recipients can verify the disclosed statements.

---

## 7. Third-Party Attestation

### 7.1 The Attestation Model

Attestation (Mode 5) lets an examiner (attestor) vouch for a property of content held by another authority (subject). The attestation IS the manifest — there is no separate content block.

```typescript
import { buildAttestationManifest } from "hiri/privacy/attestation.js";

const attestation = buildAttestationManifest({
  attestorAuthority,
  attestationId: "clearance-check-001",
  subject: {
    authority: subjectAuthority,
    manifestHash: subjectManifestHash,
    contentHash: subjectContentHash,
    manifestVersion: "1",
  },
  claim: {
    "@type": "hiri:PropertyAttestation",
    property: "security-clearance-valid",
    value: true,
    scope: "TS/SCI",
    attestedAt: "2026-03-07T12:00:00Z",
    validUntil: "2027-03-07T12:00:00Z",
  },
  evidence: {
    method: "direct-examination",
    description: "Examined the personnel security record.",
  },
  version: "1",
  timestamp: "2026-03-07T12:00:00Z",
});

// attestation has NO hiri:content block (§10.4)
// Calling getLogicalPlaintextHash() on an attestation manifest throws
```

### 7.2 Dual-Signature Verification

Attestation verification checks two signatures:

1. **Attestor's signature** on the attestation manifest
2. **Subject authority's signature** on the referenced manifest

```typescript
import { verifyAttestation } from "hiri/privacy/attestation.js";

const result = await verifyAttestation(
  signedAttestation,
  attestorPublicKey,
  subjectManifest,     // null if unavailable
  subjectPublicKey,    // null if unavailable
  crypto,
  attestorKeyStatus,   // "active" | "revoked" | "revoked-compromised"
  currentTimestamp,     // For staleness check against validUntil
);
```

### 7.3 Trust Levels

The verification result includes a `trustLevel` that reflects what could be verified:

| Scenario | `trustLevel` | Meaning |
|----------|-------------|---------|
| Both signatures verified, attestor key active | `"full"` | Maximum assurance |
| Attestor verified, subject unavailable | `"partial"` | Trust the attestor's word |
| Attestor verified, attestor key revoked, subject verified | `"partial"` | Key was valid when attestation was made |
| Attestor signature fails | `"unverifiable"` | Cannot trust anything |
| Attestor key revoked AND subject unavailable | `"unverifiable"` | No independent verification possible |

Trust level is informational — the resolver reports it, the application decides what to do with it. A `"partial"` attestation from a highly trusted attestor may be more valuable than a `"full"` attestation from an unknown one. The HIRI protocol provides the cryptographic facts; trust policy is the application's responsibility.

### 7.4 Staleness

Attestations can have a `validUntil` timestamp. After that time, the attestation is `stale: true`. Stale attestations are not invalid — the claim was true at the time it was made — but the application should treat them as potentially outdated.

### 7.5 Attestation Chains

Attestation manifests support `hiri:chain` for versioned attestation sequences. A clearance attestation might have three versions:

```
V1: clearance = valid (2026-01)
V2: clearance = upgraded/SAP (2026-06)
V3: clearance = revoked (2027-01)
```

Each version links to the previous via the standard chain mechanism. The chain records the evolution of the attested property over time.

---

## 8. Level 3: Cross-Mode Chains and Lifecycle

### 8.1 Privacy Mode Transitions (§11.2)

Content can transition between privacy modes across versions. Transitions MUST be monotonically decreasing in privacy — once content is published publicly, it cannot be made private again.

Valid transitions (from → to):

```
proof-of-possession → encrypted         ✓ (sharing with recipients)
proof-of-possession → selective-disclosure ✓ (partial sharing)
proof-of-possession → public            ✓ (full publication)
encrypted → public                      ✓ (declassification)
selective-disclosure → public           ✓ (full disclosure)
encrypted → proof-of-possession         ✗ (cannot withdraw access)
public → anything private               ✗ (cannot unpublish)
same-mode → same-mode                   ✓ (content update within mode)
```

Anonymous and attestation modes are orthogonal — they don't participate in the transition ordering.

```typescript
import { validateTransition } from "hiri/privacy/lifecycle.js";

const result = validateTransition("encrypted", "public");
// result.valid: true

const invalid = validateTransition("public", "proof-of-possession");
// invalid.valid: false
// invalid.reason: "violates monotonically decreasing privacy (§11.2)"
```

### 8.2 Addressing Mode Consistency (§11.3)

The content addressing mode (`hiri:content.addressing`) MUST be constant across all versions in a chain. You cannot mix `raw-sha256` and `cidv1-dag-cbor` within the same chain.

```typescript
import { validateAddressingConsistency } from "hiri/privacy/lifecycle.js";

const result = validateAddressingConsistency(currentManifest, previousManifest);
// result.valid: true if both use the same addressing mode
```

### 8.3 The Privacy-Aware Chain Walker

The kernel's `verifyChain()` doesn't understand privacy modes. For chains that contain privacy transitions, use the privacy-aware chain walker:

```typescript
import { verifyPrivacyChain } from "hiri/privacy/chain-walker.js";

const result = await verifyPrivacyChain(
  headManifest,
  publicKey,
  fetchManifest,   // (hash: string) => Promise<ResolutionManifest | null>
  fetchContent,    // (hash: string) => Promise<Uint8Array | null>
  crypto,
);

// result.valid: boolean
// result.depth: number
// result.modeTransitions: Array<{fromVersion, toVersion, fromMode, toMode}>
// result.warnings: string[]
```

The privacy chain walker does everything the kernel chain walker does, plus:

1. Uses `getLogicalPlaintextHash()` instead of raw `content.hash` for cross-version content comparison
2. Validates privacy mode transitions (§11.2)
3. Validates addressing mode consistency (§11.3)
4. Records mode transitions in the result

### 8.4 Example: The Three-Version Chain

This is the most important test scenario for Level 3 conformance. Build a chain where each version uses a different privacy mode:

```
V1: Proof of Possession
    content.hash = sha256:aaa   (plaintext hash)
    getLogicalPlaintextHash() → sha256:aaa

V2: Encrypted Distribution
    content.hash = sha256:bbb   (ciphertext hash)
    privacy.parameters.plaintextHash = sha256:aaa
    getLogicalPlaintextHash() → sha256:aaa

V3: Public
    content.hash = sha256:aaa   (plaintext hash)
    getLogicalPlaintextHash() → sha256:aaa
```

Raw `content.hash` comparison between V1 and V2 FAILS (aaa ≠ bbb). The privacy chain walker uses `getLogicalPlaintextHash()`, which returns `sha256:aaa` for all three versions. The logical plaintext hash is consistent across the chain even though the storage format changes.

The mode transitions are valid: PoP → Encrypted (sharing with recipients), Encrypted → Public (declassification). Both are monotonically decreasing in privacy.

---

## 9. Common Mistakes

### 9.1 String Concatenation Instead of Byte Concatenation

**Symptom:** Every salted hash and index root is wrong. Cross-implementation verification fails.

**Cause:** Using `base64url(salt) + statement` as a string instead of `concat(rawSaltBytes, UTF-8(statement))` as byte arrays.

**Fix:** See §5.3 of this guide. Test with vector B.13.

### 9.2 Hex-Encoded Index Root

**Symptom:** Index root doesn't match across implementations.

**Cause:** Concatenating hex-encoded hash strings (64 bytes each) instead of raw 32-byte digests before computing the root hash.

**Fix:** `indexRoot = SHA-256(concat(rawDigest[0]...rawDigest[N-1]))` — raw bytes, not hex strings.

### 9.3 Re-Canonicalizing Disclosed Statements

**Symptom:** Blank node statements fail verification even though the hash was computed correctly.

**Cause:** Running URDNA2015 on a single disclosed statement before hashing. Blank node labels change when canonicalizing a single statement vs. the complete graph.

**Fix:** Hash the N-Quad string exactly as published, including `_:c14n` labels. See §5.4.

### 9.4 Wrong HKDF Label

**Symptom:** AES-GCM authentication failure when decrypting a CEK or HMAC key.

**Cause:** Using `"hiri-cek-v1.1"` for HMAC key distribution (Mode 3) or `"hiri-hmac-v1.1"` for CEK distribution (Mode 2).

**Fix:** Mode 2 uses `"hiri-cek-v1.1"`. Mode 3 uses `"hiri-hmac-v1.1"`. The labels are different for domain separation — same shared secret, different derived keys.

### 9.5 Comparing Raw `content.hash` Across Modes

**Symptom:** Chain verification fails at a PoP → Encrypted transition even though the same plaintext was used.

**Cause:** Comparing `content.hash` directly. In PoP mode, `content.hash` is the plaintext hash. In encrypted mode, `content.hash` is the ciphertext hash.

**Fix:** Use `getLogicalPlaintextHash()` for all cross-version content comparisons. See §8.4.

### 9.6 Expecting Content from Attestation Manifests

**Symptom:** `getLogicalPlaintextHash()` throws. Content fetch returns null.

**Cause:** Attestation manifests have no `hiri:content` block (§10.4). The attestation IS the manifest.

**Fix:** Check `privacyMode === "attestation"` before attempting content operations. The resolver handles this automatically if you use `resolveWithPrivacy()`.

### 9.7 Treating `verified: true` + `decryption-failed` as an Error

**Symptom:** Application rejects a valid manifest because content couldn't be decrypted.

**Cause:** Conflating signature verification with content access. They are orthogonal.

**Fix:** `verified: true` means the manifest's signature and chain are cryptographically valid. `contentStatus: "decryption-failed"` means you don't have the right key. The manifest is authentic — you just can't read it.

### 9.8 Uint8Array Fields in JSON-Serialized Manifests

**Symptom:** `"uCoordinate" expected Uint8Array of length 32, got length=0` when decrypting HMAC keys or CEKs. Or `hexToBytes()` receives `[object Object]` instead of a hex string.

**Cause:** Placing `Uint8Array` values (from `encryptHmacKeyForRecipients()` or `encryptContent()`) directly into the manifest's `hiri:privacy.parameters` block. The manifest is JSON-serialized for storage (`JSON.stringify` / `stableStringify`), and `Uint8Array` serializes as `{"0":1,"1":2,...}` — a plain object, not a hex string. After `JSON.parse`, the resolver's `hexToBytes()` receives an object instead of a string, producing a zero-length or garbage `Uint8Array`.

**Fix:** Convert all `Uint8Array` fields to hex strings before embedding in the privacy block. The `HmacKeyRecipients` and `EncryptedPrivacyParams` interfaces define these fields as `string` (hex-encoded) — match the interface, not the raw function output.

```typescript
// WRONG: raw Uint8Array from function result
parameters.hmacKeyRecipients = hmacDistribution; // Uint8Array fields won't survive JSON

// CORRECT: convert to hex strings matching HmacKeyRecipients interface
parameters.hmacKeyRecipients = {
  ephemeralPublicKey: bytesToHex(hmacDistribution.ephemeralPublicKey),
  iv: bytesToHex(hmacDistribution.iv),
  keyAgreement: "X25519-HKDF-SHA256",
  recipients: hmacDistribution.recipients.map(r => ({
    id: r.id,
    encryptedHmacKey: bytesToHex(r.encryptedHmacKey),
    disclosedStatements: r.disclosedStatements,
  })),
};
```

This affects both Mode 2 (`encryptContent()` results) and Mode 3 (`encryptHmacKeyForRecipients()` results). Any function that returns `Uint8Array` cryptographic material destined for a JSON-serialized manifest must have its output hex-encoded at the integration boundary.

### 9.9 Passing Publisher Keys as IV to `encryptHmacKeyForRecipients()`

**Symptom:** `AES-GCM IV must be 12 bytes, got 32` when building a selective disclosure manifest.

**Cause:** Passing a 32-byte X25519 public key as the optional `iv` parameter of `encryptHmacKeyForRecipients()`. The function signature is `(hmacKey, recipientPublicKeys, disclosureMap, iv?)` — the 4th argument is an optional 12-byte IV, not a publisher key.

**Fix:** Omit the 4th argument. The function generates its own ephemeral X25519 keypair internally (for ECDH key agreement) and generates a random 12-byte IV if none is provided. There is no publisher key parameter — the ephemeral keypair is per-operation and its public key is included in the result for recipients to use during decryption.

```typescript
// WRONG: passing publisher's X25519 key as IV
const publisherX25519 = ed25519PublicToX25519(signingKey.publicKey);
const distribution = await encryptHmacKeyForRecipients(
  hmacKey, recipientKeys, disclosureMap, publisherX25519, // 32 bytes ≠ 12 bytes
);

// CORRECT: let the function generate its own ephemeral key and IV
const distribution = await encryptHmacKeyForRecipients(
  hmacKey, recipientKeys, disclosureMap,
);
```

### 9.10 HMAC Verification of Non-Mandatory Disclosed Statements

**Symptom:** HMAC tag verification fails for statement indices that are disclosed to a recipient but not in the mandatory set. Warnings like `"HMAC tag verification failed for statement index 2"` appear even though the HMAC key was decrypted successfully.

**Cause:** The verification loop looks up statement text in `mandatoryNQuads` using `mandatoryStatements.indexOf(idx)`. For non-mandatory indices, `indexOf` returns `-1`, so `mandatoryNQuads[-1]` is `undefined`, falling back to `""`. HMAC of an empty string does not match the HMAC of the actual statement.

**Fix:** Only verify HMAC tags for mandatory statements (where the text is available in the published blob). Non-mandatory disclosed statements are authorized by HMAC key decryption success — the tag cannot be verified without the statement text, which must be delivered out-of-band. See §5.7 of this guide.

---

## 10. Metadata Hardening (Level 3)

Level 3 conformance recommends two metadata hardening techniques:

### 10.1 Statement Padding

An attacker who knows the number of statements in a document can infer information about its structure. Padding adds dummy N-Quad statements to obscure the true statement count.

```typescript
// Add padding statements before building the index
const paddingStatements = [
  '<urn:padding:1> <urn:padding:prop> "pad1" .',
  '<urn:padding:2> <urn:padding:prop> "pad2" .',
];
const allStatements = [...realStatements, ...paddingStatements];
const paddedNQuads = allStatements.join("\n") + "\n";

// Build index with padded statements
const indexResult = await buildStatementIndex(paddedNQuads);
// statementCount in the manifest = padded count
```

Padding statements verify correctly in the index — they're real entries with valid salted hashes and HMAC tags. The `mandatoryStatements` array still references only the real mandatory indices.

### 10.2 Dummy Recipients

An attacker who sees the recipient list can infer the audience size. Adding dummy recipients (with real X25519 public keys) obscures the true recipient count.

```typescript
const dummyKey1 = generateX25519Keypair();
const dummyKey2 = generateX25519Keypair();

const recipients = new Map([
  ["alice", alice.publicKey],    // Real
  ["dummy-1", dummyKey1.publicKey], // Padding
  ["dummy-2", dummyKey2.publicKey], // Padding
]);

const encResult = await encryptContent(plaintext, recipients, crypto);
// 3 recipients in the manifest; only alice can actually use the content
```

Real recipients decrypt normally — the dummy entries just add noise to the recipient list.

---

## 11. KeyDocument Cache Staleness

The resolver supports an optional staleness check on cached KeyDocuments:

```typescript
const result = await resolveWithPrivacy(uri, storage, {
  crypto,
  publicKey,
  manifestHash,
  keyDocumentTimestamp: "2026-01-01T00:00:00Z",  // When you last fetched it
  keyDocumentMaxAge: 48 * 60 * 60 * 1000,        // 48 hours in milliseconds
  verificationTime: "2026-03-08T00:00:00Z",       // Current time
});

// If now - keyDocumentTimestamp > keyDocumentMaxAge:
// result.warnings includes "keyDocumentStale: true — ..."
```

This is a caller-side concern — the resolver doesn't fetch KeyDocuments itself. You provide the staleness parameters, and the resolver includes a warning if the cached KeyDocument is too old. The resolution still succeeds; the warning is informational.

---

## 12. Publisher Neutrality (§4.6)

The privacy extension makes no distinction about who deserves privacy. The same modes that protect a human publisher's medical records also serve a non-human agent's internal reasoning traces. This is the Publisher Neutrality principle: privacy modes serve non-human agents (synthetic moral persons) with equal rigor.

The closing line of the spec captures this: "Privacy is not the absence of information. It is the presence of control. This specification treats confidentiality as a layer, not a lock — and makes no distinction about who deserves it."

---

## Appendix A: API Quick Reference

### Privacy Resolution
| Function | Purpose |
|----------|---------|
| `resolveWithPrivacy()` | Single entry point for all privacy-aware resolution |
| `getPrivacyMode()` | Extract privacy mode from manifest |
| `getLogicalPlaintextHash()` | Get plaintext-equivalent hash regardless of mode |

### Mode 1: Proof of Possession
| Function | Purpose |
|----------|---------|
| `isCustodyStale()` | Check if custody assertion exceeds refresh policy |

### Mode 2: Encrypted Distribution
| Function | Purpose |
|----------|---------|
| `encryptContent()` | Encrypt content for multiple recipients |
| `decryptContent()` | Decrypt content as an authorized recipient |
| `buildEncryptedManifest()` | Build manifest with encrypted privacy block |

### Mode 3: Selective Disclosure
| Function | Purpose |
|----------|---------|
| `buildStatementIndex()` | Build salted statement index from N-Quads |
| `verifyStatementInIndex()` | Verify a statement against its index hash |
| `verifyIndexRoot()` | Verify index root against published hashes |
| `generateHmacTags()` | Generate HMAC tags for all statements |
| `verifyHmacTag()` | Verify a single statement's HMAC tag |
| `encryptHmacKeyForRecipients()` | Encrypt HMAC key for authorized recipients |
| `decryptHmacKey()` | Decrypt HMAC key as a recipient |
| `buildSelectiveDisclosureManifest()` | Build manifest with SD privacy block |

### Mode 4: Anonymous Publication
| Function | Purpose |
|----------|---------|
| `generateEphemeralAuthority()` | Generate a one-time signing identity |
| `buildAnonymousPrivacyBlock()` | Build the anonymous privacy block |

### Mode 5: Third-Party Attestation
| Function | Purpose |
|----------|---------|
| `buildAttestationManifest()` | Build attestation manifest (no content block) |
| `verifyAttestation()` | Dual-signature verification with trust levels |
| `validateAttestationManifest()` | Validate attestation structure (reject if content present) |

### Chain Walking (Level 3)
| Function | Purpose |
|----------|---------|
| `verifyPrivacyChain()` | Walk chain with privacy mode awareness |
| `validateTransition()` | Check if a mode transition is valid |
| `validateAddressingConsistency()` | Check addressing mode consistency |

---

## Appendix B: Conformance Checklist

### Level 1 (Minimum)
- [ ] Detect `hiri:privacy` block on manifests
- [ ] Report privacy mode in resolution result
- [ ] Return `"unsupported-mode"` for unimplemented modes (do NOT reject)
- [ ] Verify signature and chain for all modes, including unknown ones
- [ ] Implement `getLogicalPlaintextHash()` for PoP and public modes

### Level 2 (Interoperable)
- [ ] Encrypt content for multiple recipients (Mode 2)
- [ ] Decrypt content as an authorized recipient (Mode 2)
- [ ] Report three `contentStatus` values: `ciphertext-verified`, `decrypted-verified`, `decryption-failed`
- [ ] Build statement indices with byte-level concatenation (Mode 3)
- [ ] Verify statements against index without re-canonicalization (Mode 3)
- [ ] Generate and verify HMAC tags (Mode 3)
- [ ] Encrypt/decrypt HMAC keys with correct domain separation label (Mode 3)
- [ ] Hex-encode all Uint8Array fields before embedding in JSON-serialized privacy blocks (Mode 2, Mode 3)
- [ ] Use secure document loader for URDNA2015 (no network context fetch)

### Level 3 (Full)
- [ ] Validate privacy mode transitions (monotonically decreasing)
- [ ] Validate addressing mode consistency across chains
- [ ] Walk chains using `getLogicalPlaintextHash()` (not raw `content.hash`)
- [ ] Support ephemeral and pseudonymous anonymous publication (Mode 4)
- [ ] Support attestation with dual-signature verification (Mode 5)
- [ ] Support trust levels: full, partial, unverifiable (Mode 5)
- [ ] Support attestation staleness checking (Mode 5)
- [ ] Support statement padding (metadata hardening)
- [ ] Support dummy recipients (metadata hardening)
- [ ] Support KeyDocument cache staleness warnings
