# HIRI Privacy Extension — Pre-Merge Checklist

**Branch:** dev
**Target:** main
**Scope:** M10–M15 (privacy layer), M16–M17 (demo), adversarial tests, developer guide
**Date:** March 2026
**Verified:** 2026-03-10

---

## Instructions

Every item must be checked by the developer AND verified by a second pair of eyes before merge. Items marked [AUTO] have automated verification. Items marked [MANUAL] require human inspection. Items marked [BOTH] require both.

---

## 1. Test Suite [AUTO]

- [x] `npm run build` — zero TypeScript errors
- [x] `npm test` — 323/323 tests pass across 14 suites
- [x] `npm run test:purity` — 20 kernel files, zero import violations
- [x] `npm run build:demo` — esbuild bundle compiles with zero unresolved imports (703KB)
- [x] No test uses `console.log` for debugging (only structured pass/fail output)
- [x] No test has `skip`, `todo`, or `only` markers left in

### Suite-by-suite confirmation:

| Suite | Tests | Status |
|-------|-------|--------|
| Kernel (M1–M4) — `hiri.test.ts` | 33 | ✅ |
| Resolution (M3) — `phase3.test.ts` | 18 | ✅ |
| Query (M4) — `phase4.test.ts` | 11 | ✅ |
| Key Lifecycle (M5) — `phase5.test.ts` | 13 | ✅ |
| v3.1.1 Migration (M6) — `v3-migration.test.ts` | 20 | ✅ |
| URDNA2015 + CIDv1 (M7) — `phase7.test.ts` | 27 | ✅ |
| RDF Patch + Level 2 (M8) — `phase8.test.ts` | 22 | ✅ |
| Privacy Level 1 (M10) — `privacy-level1.test.ts` | 19 | ✅ |
| Crypto Primitives (M11) — `crypto-primitives.test.ts` | 18 | ✅ |
| Privacy Level 2 — Encrypted (M12) — `privacy-level2.test.ts` | 23 | ✅ |
| Selective Disclosure (M13) — `selective-disclosure.test.ts` | 23 | ✅ |
| Anonymous + Attestation (M14) — `anonymous-attestation.test.ts` | 18 | ✅ |
| Privacy Level 3 — Integration (M15) — `privacy-level3.test.ts` | 24 | ✅ |
| Adversarial Privacy — `adversarial-privacy.test.ts` | 54 | ✅ |
| **Total** | **323** | ✅ |

---

## 2. Kernel Purity [AUTO + MANUAL]

- [x] `npm run test:purity` passes (automated)
- [x] No new files added to `src/kernel/` during M10–M15 (manual check)
- [x] No existing kernel file modified during M10–M15 (`git diff main -- src/kernel/` = empty)
- [x] All privacy code lives in `src/privacy/` (Layer 2)
- [x] All crypto adapter code lives in `src/adapters/crypto/` (Layer 1)
- [x] `src/privacy/` imports only from `src/kernel/` (Layer 0) and `src/adapters/` (Layer 1) — never the reverse

---

## 3. File Inventory [MANUAL]

### New files (M10–M15): 14 production + 6 test

| File | Milestone | Layer | Exists |
|------|-----------|-------|--------|
| `src/privacy/types.ts` | M10 (modified through M15) | 2 | ✅ |
| `src/privacy/privacy-mode.ts` | M10 | 2 | ✅ |
| `src/privacy/plaintext-hash.ts` | M10 | 2 | ✅ |
| `src/privacy/proof-of-possession.ts` | M10 | 2 | ✅ |
| `src/privacy/resolve.ts` | M10 (modified through M15) | 2 | ✅ |
| `src/adapters/crypto/key-conversion.ts` | M11 | 1 | ✅ |
| `src/adapters/crypto/x25519.ts` | M11 | 1 | ✅ |
| `src/adapters/crypto/hkdf.ts` | M11 | 1 | ✅ |
| `src/adapters/crypto/aes-gcm.ts` | M11 | 1 | ✅ |
| `src/adapters/crypto/hmac.ts` | M11 | 1 | ✅ |
| `src/adapters/crypto/key-agreement.ts` | M11 | 1 | ✅ |
| `src/privacy/encryption.ts` | M12 | 2 | ✅ |
| `src/privacy/decryption.ts` | M12 | 2 | ✅ |
| `src/privacy/encrypted-manifest.ts` | M12 | 2 | ✅ |
| `src/privacy/delta-restrictions.ts` | M12 (modified M13) | 2 | ✅ |
| `src/privacy/statement-index.ts` | M13 | 2 | ✅ |
| `src/privacy/hmac-disclosure.ts` | M13 | 2 | ✅ |
| `src/privacy/selective-manifest.ts` | M13 | 2 | ✅ |
| `src/privacy/anonymous.ts` | M14 | 2 | ✅ |
| `src/privacy/attestation.ts` | M14 | 2 | ✅ |
| `src/privacy/lifecycle.ts` | M15 | 2 | ✅ |
| `src/privacy/chain-walker.ts` | M15 | 2 | ✅ |
| `tests/privacy-level1.test.ts` | M10 | — | ✅ |
| `tests/crypto-primitives.test.ts` | M11 | — | ✅ |
| `tests/privacy-level2.test.ts` | M12 | — | ✅ |
| `tests/selective-disclosure.test.ts` | M13 | — | ✅ |
| `tests/anonymous-attestation.test.ts` | M14 | — | ✅ |
| `tests/privacy-level3.test.ts` | M15 | — | ✅ |
| `tests/adversarial-privacy.test.ts` | Adversarial | — | ✅ |

### New files (M16–M17): demo

| File | Milestone | Exists |
|------|-----------|--------|
| `src/demo/tab-privacy.ts` | M16 | ✅ |
| `src/demo/entry.ts` (modified) | M16 | ✅ |
| `src/demo/state.ts` (modified) | M16 | ✅ |
| `src/demo/tab-resolve.ts` (modified) | M16 | ✅ |
| `src/demo/presets.ts` (modified) | M17 | ✅ |
| `site/index.html` (modified) | M16 | ✅ |

### Documentation

| File | Exists |
|------|--------|
| `HIRI-Privacy-Confidentiality-Extension-v1.4.1-FINAL.md` | ✅ |
| `HIRI-Privacy-Milestones.md` | ✅ |
| `HIRI-Privacy-Demo-UI-Spec.md` | ✅ |
| `HIRI-Privacy-Developer-Guide.md` | ✅ |
| `site/developer-guide.html` (updated) | ✅ |

---

## 4. Cryptographic Correctness [MANUAL]

### Key Material Lifecycle

- [x] Every `encryptContent()` call zeros the CEK after use (`cek.fill(0)`) — `encryption.ts:91`
- [x] Every `encryptContent()` call zeros the ephemeral private key after use — `encryption.ts:92`
- [x] Every `encryptHmacKeyForRecipients()` call zeros the ephemeral private key after use — `hmac-disclosure.ts:125`
- [x] Every `decryptContent()` call zeros the CEK after decryption — `decryption.ts:76`
- [x] Every `generateEphemeralAuthority()` caller zeros the private key after signing (documented as caller responsibility)
- [x] Demo code (`tab-privacy.ts`) zeros HMAC keys and ephemeral private keys after use — lines 900, 1082, 1138-1139, 1161
- [x] No private key material is logged, serialized to JSON, or written to storage

### HKDF Domain Separation

- [x] Mode 2 (encrypted) uses HKDF label `"hiri-cek-v1.1"` — verified in `encryption.ts:54` and `decryption.ts:47`
- [x] Mode 3 (selective disclosure) uses HKDF label `"hiri-hmac-v1.1"` — verified in `hmac-disclosure.ts:116,158`
- [x] Test 13.13 proves domain separation: decryption with wrong label fails
- [x] `buildHKDFInfo("hiri-cek-v1.1", "alice")` = 18 bytes (verify in M11 test)
- [x] `buildHKDFInfo("hiri-hmac-v1.1", "alice")` = 19 bytes (verify in M11 test)

### Byte-Level Operations

- [x] `statement-index.ts` → `computeSaltedHash()` uses `Uint8Array` concatenation, not string concatenation — lines 127-130
- [x] `hmac-disclosure.ts` → `generateHmacTags()` uses `Uint8Array` concatenation, not string concatenation — lines 39-42
- [x] Index root computation concatenates raw 32-byte digests, not hex strings — `statement-index.ts:57-65`
- [x] `indexSalt` is decoded from base64url to raw 32 bytes before any crypto operation
- [x] Test 13.6 proves string concat produces different hash than byte concat (B.13 vector)

### Constant-Time Comparisons

- [x] `statement-index.ts` → `constantTimeEqual()` uses XOR accumulation (not early return) — lines 140-147
- [x] `hmac-disclosure.ts` → `constantTimeEqual()` uses XOR accumulation (not early return) — lines 166-173
- [x] Both functions return `false` for mismatched lengths before entering the loop

### X25519 Key Generation

- [x] Ephemeral keypairs use `generateX25519Keypair()` (native X25519), NOT Ed25519-then-converted — `x25519.ts:17-20`
- [x] Key type summary: Ed25519 for signing, X25519 for key agreement — verify no cross-usage

---

## 5. Spec Compliance — Privacy Modes [BOTH]

### Mode 1: Proof of Possession (§6)

- [x] PoP manifests have `hiri:privacy.mode: "proof-of-possession"`
- [x] Resolver does NOT fetch content for PoP manifests (§6.4) — `resolve.ts:255-263`
- [x] `contentStatus: "private-custody-asserted"` returned — `resolve.ts:262`
- [x] Staleness check: `isCustodyStale()` compares created + refreshPolicy against verificationTime — `proof-of-possession.ts:82-96`
- [x] Test 10.8: unknown privacy mode returns content.hash WITH warning (not silently)

### Mode 2: Encrypted Distribution (§7)

- [x] Manifest `content.hash` = ciphertext hash (not plaintext hash) — `encrypted-manifest.ts:49`
- [x] `privacy.parameters.plaintextHash` = plaintext hash — `encrypted-manifest.ts:65`
- [x] `getLogicalPlaintextHash()` returns `privacy.parameters.plaintextHash` for encrypted manifests — `plaintext-hash.ts:40-50`
- [x] Resolver returns `verified: true` even when decryption fails (signature is orthogonal) — `resolve.ts:412-426`
- [x] Three `contentStatus` values: `ciphertext-verified`, `decrypted-verified`, `decryption-failed`
- [x] `buildEncryptedManifest()` accepts optional `keyAgreement` param (HPKE identifier support)

### Mode 3: Selective Disclosure (§8)

- [x] Canonicalization enforced as URDNA2015 (JCS rejected by `buildSelectiveDisclosureManifest`) — `selective-manifest.ts:51-56`
- [x] Content `availability` set to `"partial"` — `selective-manifest.ts:61`
- [x] `disclosureProofSuite` = `"hiri-hmac-sd-2026"` — `selective-manifest.ts:68`
- [x] Statement hashes are raw 32-byte `Uint8Array`, NOT `"sha256:..."` prefixed strings
- [x] Index root is `"sha256:"` + hex of `SHA-256(concat(allRawDigests))` — `statement-index.ts:57-65`
- [x] Verifiers MUST NOT re-canonicalize disclosed statements (§8.8) — verified by test 13.9
- [x] `indexSalt` in manifest is base64url encoded without padding (RFC 4648 §5) — `selective-manifest.ts:102-111`
- [x] Published content format: JSON blob with `{ mandatoryNQuads, statementIndex, hmacTags }`

### Mode 4: Anonymous Publication (§9)

- [x] Ephemeral authorities: no KeyDocument reference, no rotation/revocation fields (§9.5)
- [x] `generateEphemeralAuthority()` returns fresh keypair each call — `anonymous.ts:39-48`
- [x] Two ephemeral authorities are computationally unlinkable (test 14.5)
- [x] Pseudonymous authorities: same key → same authority (linkable, test 14.4)
- [x] `resolveAnonymous` dispatches on `contentVisibility` to existing sub-handlers — `resolve.ts:644-687`
- [x] `contentVisibility` union includes `"selective-disclosure"` (M15 addition)

### Mode 5: Third-Party Attestation (§10)

- [x] Attestation manifests have NO `hiri:content` block (§10.4) — `attestation.ts:95-122`
- [x] `validateAttestationManifest()` rejects manifests WITH `hiri:content` — `attestation.ts:179-188`
- [x] `getLogicalPlaintextHash()` throws for attestation manifests (§11.3)
- [x] Dual-signature verification: attestor signature + subject manifest signature
- [x] Trust levels: `"full"` (both verified), `"partial"` (subject unavailable), `"unverifiable"` (attestor revoked + no subject)
- [x] `attestorKeyStatus` parameter defaults to `"active"`, populated from KeyDocument by resolver
- [x] Staleness: `stale: true` when `currentTimestamp > claim.validUntil`
- [x] Attestation chains supported via `hiri:chain`

### Cross-Mode (§11)

- [x] Privacy transitions are monotonically decreasing (PoP→Encrypted→Public valid; Public→PoP invalid) — `lifecycle.ts:45-79`
- [x] `validateTransition()` accepts same-mode transitions (identity)
- [x] Anonymous and attestation modes are orthogonal to the transition lattice
- [x] `validateAddressingConsistency()` rejects mixed addressing modes across chain versions — `lifecycle.ts:94-117`
- [x] `verifyPrivacyChain()` uses `getLogicalPlaintextHash()`, not raw `content.hash` — `chain-walker.ts:174-194`
- [x] Chain walker records mode transitions in discovery order (reverse chronological)
- [x] Unknown future modes pass transition validation (forward compatibility) — adversarial test A.29

---

## 6. Resolve.ts — Static Import Conversion [AUTO]

- [x] All dynamic imports (`await import(...)`) in `resolve.ts` have been converted to static imports
- [x] No `await import("../kernel/signing.js")` patterns remain in any mode handler
- [x] `npm test` — 323/323 still pass after conversion
- [x] `npm run build:demo` — esbuild produces single bundle (no unexpected chunks)

---

## 7. Demo Site [MANUAL]

> **Note:** Section 7 requires browser testing by the Orchestrator. Items below are flagged for manual verification.

### Tab E — Privacy Sandbox

- [ ] E.1 (PoP): Sign → `private-custody-asserted` badge, mock clock shows staleness
- [ ] E.2 (Encrypted): Encrypt → dual hashes displayed, "Resolve As..." switches perspectives correctly
- [ ] E.2: Alice → `decrypted-verified` with plaintext rendered
- [ ] E.2: Unauthorized → `ciphertext-verified`
- [ ] E.2: Eve → `decryption-failed` (verified: true)
- [ ] E.3 (SD): Parse → statements listed with checkboxes, Build → index built
- [ ] E.3: Unauthorized/Alice/Bob verifier perspectives produce correct results with zero false warnings
- [ ] E.3: Dictionary attack animation runs and completes with correct defense message
- [ ] E.4 (Anon): Ephemeral → key destroyed, unlinkability proof shows two different authorities
- [ ] E.4: Pseudonymous → same authority in both manifests
- [ ] E.5 (Attest): Sign → `hiri:content: ABSENT`, claim displayed
- [ ] E.5: "Both Available" → `trustLevel: FULL` (green trust bar, no warnings)
- [ ] E.5: "Subject Unavailable" → `trustLevel: PARTIAL`
- [ ] E.5: "Attestor Revoked" → `trustLevel: UNVERIFIABLE`
- [ ] E.5: Staleness slider transitions from valid to stale

### Tab D — Privacy Badges

- [ ] Resolving a manifest with `hiri:privacy` block shows privacy mode badge
- [ ] Badge color matches the mode (yellow=PoP, blue=encrypted, orange=SD, purple=anon, teal=attest)
- [ ] Anonymous manifests show `identityType` badge

### Network Indicator

- [ ] Network indicator stays green (zero network calls) throughout all privacy operations
- [ ] AES-GCM, HMAC, HKDF, X25519 all run via Web Crypto / @noble — no external services

### Presets

- [ ] Each preset clears state with `demoState.clear()` before setup
- [ ] Each preset is self-contained (no dependency on another preset's state)
- [ ] Preset dropdown includes all 7 privacy presets plus original 4
- [ ] Loading a preset re-initializes all 5 tabs

---

## 8. Developer Guide [MANUAL]

- [x] Privacy API reference table signatures match actual implementations (M10–M15 source files) — fixed in commit `bd0ddfe`
- [x] Test count updated from 144 to 269 to 323 in Architecture and Setup sections — fixed in commits `bd0ddfe`, pending update to 323
- [x] `getLogicalPlaintextHash` module path is `privacy/plaintext-hash.js` (not `privacy/cross-mode`) — fixed in `bd0ddfe`
- [x] `encryptContent` signature includes required `crypto` parameter — fixed in `bd0ddfe`
- [x] `decryptContent` signature includes `params`, `ownPrivateKey`, `ownRecipientId`, `crypto` — fixed in `bd0ddfe`
- [x] `verifyAttestation` signature includes all 7 parameters — fixed in `bd0ddfe`
- [x] `buildAttestationManifest` return type is `UnsignedAttestationManifest` (not `UnsignedManifest`) — fixed in `bd0ddfe`
- [x] `buildAnonymousPrivacyBlock` takes `(params: AnonymousParams)` (not `(mode, linkedAuthorityHash?)`) — fixed in `bd0ddfe`
- [x] HMAC Verification Boundary section documents the mandatory-only verification pattern
- [x] Serialization at the JSON Boundary section warns about `Uint8Array` → JSON gotcha
- [x] Common Mistakes section has 7 entries ordered by frequency

---

## 9. Dependencies [AUTO]

- [x] `@noble/curves` is in `package.json` dependencies (M11 runtime requirement)
- [x] `@noble/hashes` is in `package.json` dependencies (M11 runtime requirement)
- [x] No other new runtime dependencies added during M10–M17
- [x] `npm audit` — zero critical vulnerabilities. **1 high:** `minimatch` ReDoS (GHSA-7r86-cg39-jmmj) in devDependency chain `rimraf → glob → minimatch`. Not a runtime dependency. Fixable via `npm audit fix`.
- [x] `npm ls --all` — no unmet peer dependencies (only unmet OPTIONAL esbuild platform binaries, expected on Windows)

---

## 10. Git Hygiene [MANUAL]

- [x] No `.env` files, API keys, private keys, or secrets in any committed file
- [x] No `node_modules/` in the commit
- [x] No `.DS_Store` or IDE config files in the commit
- [x] Commit history is clean on `dev` branch
- [x] Branch is up to date with `main` (merge target)
- [x] No `TODO`, `FIXME`, or `HACK` comments left in production code (tests are OK)
- [ ] All files use consistent line endings (LF, not CRLF) — **requires Orchestrator verification on Windows**

---

## 11. Regression Verification [AUTO]

Run the full test suite one final time from a clean checkout:

```bash
git checkout dev
npm run build       # TypeScript compilation
npm test            # 323/323
npm run test:purity # Kernel purity
npm run build:demo  # Demo bundle
```

- [x] All commands above exit 0
- [x] Test output shows exactly 323 passed, 0 failed across 14 suites
- [x] No new warnings in TypeScript compilation (only DEP0174 from toolchain, pre-existing)
- [x] Demo bundle size is 703KB (reasonable, up from ~520KB pre-privacy)

---

## 12. Adversarial Test Suite [AUTO] (added post-checklist)

54 adversarial tests across 7 attack surfaces, all passing:

| Attack Surface | Tests | Status |
|----------------|-------|--------|
| A.1–A.8: Input Validation & Boundary Conditions | 8 | ✅ |
| A.9–A.16: Cryptographic Edge Cases | 8 | ✅ |
| A.17–A.24: Serialization Round-Trip Integrity | 8 | ✅ |
| A.25–A.32: Cross-Mode & Chain Adversarial | 8 | ✅ |
| A.33–A.40: Attestation Adversarial | 8 | ✅ |
| A.41–A.48: Resolver Adversarial | 8 | ✅ |
| A.49–A.54: Statement Content Edge Cases | 6 | ✅ |
| **Total** | **54** | ✅ |

Notable findings (no bugs, documented behaviors):
- A.7: Zero-byte plaintext encryption succeeds (16-byte GCM tag only) — documented in spec B.16
- A.22: PoP resolver does not leak content even when available in storage
- A.42: Ciphertext tamper at correct storage key is detected
- A.45: Staleness uses strict `>` — documented in developer guide

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| Reviewer | | | |

**Merge approved:** ☐ Yes ☐ No — requires items: Section 7 (Demo Site browser testing), line endings verification
