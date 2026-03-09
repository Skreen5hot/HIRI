# HIRI Privacy Extension — Demo Site UI Specification

**Version:** 1.0
**Date:** March 2026
**Governing Spec:** HIRI Privacy & Confidentiality Extension v1.4.1
**Base Demo:** HIRI Protocol Demo (4-tab architecture, Oxigraph WASM)
**Implementation:** M10–M15 (269/269 tests, Privacy Level 3)

---

## Design Principles

1. **Extend, don't replace.** The existing four-tab demo (Keys → Build → Query → Resolve) remains intact. Privacy features are added as a fifth tab and as mode-aware extensions to existing tabs.

2. **Layer visibility.** The privacy layer sits above the kernel. The UI must make this visible — every privacy operation should show what it hands to the kernel for signing, and what the kernel hands back. The "Under the Hood" panels already do this; the privacy extension extends the pattern.

3. **Progressive disclosure.** The demo starts with the simplest privacy mode (Proof of Possession) and builds toward the most complex (Selective Disclosure + Anonymous + Attestation chains). Presets guide the progression.

4. **Zero Network preserved.** All privacy operations (encryption, HMAC, key agreement, statement indexing) run locally. The network indicator must remain green throughout. AES-GCM and HMAC use Web Crypto / @noble/hashes — no external services.

5. **Spec traceability.** Every UI element that implements a spec feature includes a `§` reference in its "Under the Hood" panel. Reviewers can trace from the UI back to the spec section.

---

## Architecture: Tab Structure

```
Existing:                          New:
┌─────┬───────┬───────┬─────────┬──────────┐
│ A   │ B     │ C     │ D       │ E        │
│Keys │Build  │Query  │Resolve  │Privacy   │
└─────┴───────┴───────┴─────────┴──────────┘
        │                │           │
        │ Mode selector  │ Mode-     │ Five sub-panels:
        │ added to       │ aware     │ PoP, Encrypt,
        │ build form     │ results   │ Disclose, Anon,
        │                │           │ Attest
```

### Tab E: Privacy Sandbox (NEW)

This is the primary new tab. It contains five sub-panels, one per privacy mode, arranged as a vertical accordion or horizontal sub-tabs within the tab. Only one sub-panel is expanded at a time.

### Tab B: Build (MODIFIED)

A "Privacy Mode" dropdown is added above the content form. When a privacy mode is selected, the build pipeline changes:
- **Public (default):** Existing behavior, unchanged.
- **Proof of Possession:** Signs manifest but does not store content. Badge shows "Private — Custody Only."
- **Encrypted:** Encrypts content before signing. Shows dual hashes. Recipient selector appears.
- **Selective Disclosure:** Canonicalizes via URDNA2015, builds statement index, shows mandatory/withheld split. Recipient selector appears.
- **Anonymous:** Generates ephemeral authority. Existing identity panel dims. Content visibility sub-selector appears.
- **Attestation:** Switches form to attestation fields (subject, claim, evidence). No content block.

### Tab D: Resolve (MODIFIED)

The resolution result panel gains privacy-aware fields:
- `privacyMode` badge (color-coded by mode)
- `contentStatus` badge (verified / ciphertext-verified / decrypted-verified / partial-disclosure / private-custody-asserted / attestation-verified / unsupported-mode)
- `identityType` badge for anonymous manifests
- Decryption key input (optional) for encrypted manifests
- HMAC key decryption for selective disclosure
- Trust level indicator for attestations

---

## Tab E: Privacy Sandbox — Detailed Layout

### E.1 Sub-Panel: Proof of Possession (Mode 1)

**Purpose:** Demonstrate that a publisher can prove data ownership without revealing the data.

**Layout:**

```
┌─────────────────────────────────────────────────┐
│ PROOF OF POSSESSION                        §6   │
├─────────────────────────────────────────────────┤
│                                                 │
│ Content (never leaves this panel):              │
│ ┌─────────────────────────────────────────────┐ │
│ │ { "@type": "Person",                        │ │
│ │   "name": "Dana Reeves",                    │ │
│ │   "clearance": "TS/SCI" }                   │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ Content Hash: sha256:abc123...                  │
│ Refresh Policy: [P30D ▼]                        │
│                                                 │
│ [Sign Custody Assertion]                        │
│                                                 │
│ ┌─ Result ──────────────────────────────────┐   │
│ │ ✓ Manifest signed (content NOT stored)    │   │
│ │ ✓ contentStatus: private-custody-asserted │   │
│ │ ✓ Staleness: not stale (15d / 30d)        │   │
│ └───────────────────────────────────────────┘   │
│                                                 │
│ ── Mock Clock ──────────────────────────────    │
│ [|──────────●─────────] 2026-04-15             │
│  Created    ▲      Policy expires              │
│             │                                   │
│  staleness: TRUE (45d > 30d policy)             │
│  ⚠ Warning: Custody assertion is stale          │
│                                                 │
│ ▶ Under the Hood                                │
│   { function: "resolveWithPrivacy()",           │
│     mode: "proof-of-possession",                │
│     contentFetched: false,                      │
│     signatureVerified: true,                    │
│     staleness: { ... } }                        │
└─────────────────────────────────────────────────┘
```

**Interactive elements:**
- Content textarea (editable, computes hash in real-time)
- Refresh policy dropdown (P7D, P30D, P90D, P365D, none)
- "Sign Custody Assertion" button
- Mock clock slider (reuses pattern from Tab A's key lifecycle slider)
- Staleness indicator that updates as slider moves

**Key demo point:** The content hash appears in the manifest, but the content bytes are never stored. The resolver returns `contentStatus: "private-custody-asserted"` without ever fetching content.

---

### E.2 Sub-Panel: Encrypted Distribution (Mode 2)

**Purpose:** Demonstrate multi-recipient encryption with dual content hashes.

**Layout:**

```
┌─────────────────────────────────────────────────┐
│ ENCRYPTED DISTRIBUTION                   §7     │
├─────────────────────────────────────────────────┤
│                                                 │
│ Plaintext:                                      │
│ ┌─────────────────────────────────────────────┐ │
│ │ { "name": "Dana Reeves",                    │ │
│ │   "clearance": "TS/SCI" }                   │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ Recipients:                                     │
│  ☑ Alice (X25519: z7Kp...nBw)    [Remove]      │
│  ☑ Bob   (X25519: z9Qr...xYz)    [Remove]      │
│  [+ Add Recipient]                              │
│                                                 │
│ [Encrypt & Sign]                                │
│                                                 │
│ ┌─ Dual Hashes ─────────────────────────────┐   │
│ │ Plaintext hash:  sha256:aaa111...          │   │
│ │ Ciphertext hash: sha256:bbb222...          │   │
│ │ (manifest stores ciphertext hash)          │   │
│ │ (privacy block stores plaintext hash)      │   │
│ └───────────────────────────────────────────┘   │
│                                                 │
│ ┌─ Resolve As... ───────────────────────────┐   │
│ │ ○ Unauthorized (no key)                    │   │
│ │   → ciphertext-verified ✓                  │   │
│ │ ○ Alice (has key)                          │   │
│ │   → decrypted-verified ✓                   │   │
│ │   → plaintext: { "name": "Dana..." }       │   │
│ │ ○ Eve (wrong key)                          │   │
│ │   → decryption-failed (verified: true) ⚠   │   │
│ └───────────────────────────────────────────┘   │
│                                                 │
│ ── Recipient Management ────────────────────    │
│ [Add Charlie → Re-encrypt] [Remove Bob → Re-encrypt] │
│                                                 │
│ ▶ Under the Hood                                │
│   { pipeline: "ECDH → HKDF → AES-GCM",        │
│     hkdfLabel: "hiri-cek-v1.1",                 │
│     ephemeralKey: "z...",                        │
│     perRecipientKEKs: 2,                         │
│     ivReuse: "safe (unique KEK per recipient)" } │
└─────────────────────────────────────────────────┘
```

**Interactive elements:**
- Plaintext textarea
- Recipient list with add/remove buttons (generates X25519 keypairs on add)
- "Encrypt & Sign" button
- "Resolve As..." radio selector (switches between unauthorized, each recipient, wrong-key)
- Recipient management buttons (demonstrate re-encryption)

**Key demo points:**
- Dual hash model: ciphertext hash is public, plaintext hash is private
- Three resolver perspectives in one panel
- Re-encryption on recipient change (new CEK, new ciphertext)
- `verified: true` even when decryption fails (signature and chain are orthogonal to content access)

---

### E.3 Sub-Panel: Selective Disclosure (Mode 3)

**Purpose:** Demonstrate statement-level RDF disclosure with HMAC proofs.

**Layout:**

```
┌─────────────────────────────────────────────────┐
│ SELECTIVE DISCLOSURE (HMAC Suite)         §8     │
├─────────────────────────────────────────────────┤
│                                                 │
│ Source Document (JSON-LD):                      │
│ ┌─────────────────────────────────────────────┐ │
│ │ { "@context": "https://schema.org",          │ │
│ │   "@type": "Person",                         │ │
│ │   "name": "Dana Reeves",                     │ │
│ │   "jobTitle": "Protocol Architect",           │ │
│ │   "email": "dana@example.org",                │ │
│ │   "birthDate": "1990-05-15" }                 │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ [Canonicalize (URDNA2015)]                      │
│                                                 │
│ ── Canonical N-Quads (6 statements) ──────────  │
│                                                 │
│  Mandatory (public):                            │
│  ☑ [0] <.../person> rdf:type schema:Person .    │
│  ☑ [1] <.../person> schema:name "Dana Reeves" . │
│                                                 │
│  Withheld (private):                            │
│  ☐ [2] <.../person> schema:jobTitle "..." .     │
│  ☐ [3] <.../person> schema:email "..." .        │
│  ☐ [4] <.../person> schema:birthDate "..." .    │
│  ☐ [5] _:c14n0 schema:addressLocality "..." .   │
│                                                 │
│ Recipients:                                     │
│  Alice: statements [0,1,2,3] (name + job + email)│
│  Bob:   statements [0,1] (name only)            │
│                                                 │
│ [Build Statement Index & Sign]                  │
│                                                 │
│ ┌─ Index ────────────────────────────────────┐  │
│ │ Salt: p_O5wg... (base64url)                │  │
│ │ Root: sha256:f4a3...                        │  │
│ │ Hashes: [sha256:7a2f, sha256:3b8e, ...]    │  │
│ │ HMAC tags: [32 bytes × 6]                   │  │
│ └────────────────────────────────────────────┘  │
│                                                 │
│ ── Verifier Perspectives ────────────────────   │
│                                                 │
│ [Unauthorized]  Sees: statements 0,1 only       │
│   → Can verify index root ✓                     │
│   → Can verify mandatory hashes ✓               │
│   → Cannot verify withheld statements ✗         │
│   → Cannot forge HMAC tags ✗                    │
│                                                 │
│ [Alice]  Sees: statements 0,1,2,3               │
│   → Decrypts HMAC key ✓                         │
│   → Verifies all 4 statement HMAC tags ✓        │
│   → Cannot see statements 4,5 ✗                 │
│                                                 │
│ [Bob]  Sees: statements 0,1                     │
│   → Decrypts HMAC key ✓                         │
│   → Verifies 2 statement HMAC tags ✓            │
│                                                 │
│ ── Dictionary Attack Simulator ──────────────   │
│ Withheld statement [4] is birthDate.             │
│ Attacker knows predicate (schema:birthDate).     │
│ Trying year-month combos: [████████░░] 80%       │
│                                                 │
│ ⚠ Salted hash match found for "1990-05-15"       │
│ ✗ But HMAC tag cannot be forged without key      │
│ → Defense-in-depth: salt defeats rainbow tables, │
│   HMAC key defeats per-manifest enumeration.     │
│                                                 │
│ ▶ Under the Hood                                │
│   { §8.4: "byte-level concat",                  │
│     §8.6.1: "hiri-hmac-v1.1 label",             │
│     §8.8: "no re-canonicalization",              │
│     B.13: "string vs byte concat differ" }       │
└─────────────────────────────────────────────────┘
```

**Interactive elements:**
- JSON-LD source document textarea
- "Canonicalize" button (runs URDNA2015 via existing M7 canonicalizer)
- Statement checklist (mandatory/withheld toggle per statement)
- Per-recipient disclosure scope selector
- "Build Statement Index & Sign" button
- Verifier perspective switcher (Unauthorized / Alice / Bob)
- Dictionary attack simulator (animated progress bar, shows salt+HMAC defense)
- Blank node demonstration (if document produces `_:c14n` labels)

**Key demo points:**
- The published N-Quads are a valid RDF subgraph (loadable in SPARQL)
- Per-recipient disclosure scope is enforced by plaintext distribution, not cryptography (HMAC limitation)
- The dictionary attack simulator is the spec's B.9 test vector made visual
- Blank node statements verify without re-canonicalization (§8.8)

---

### E.4 Sub-Panel: Anonymous Publication (Mode 4)

**Purpose:** Demonstrate ephemeral and pseudonymous authorities.

**Layout:**

```
┌─────────────────────────────────────────────────┐
│ ANONYMOUS PUBLICATION                    §9     │
├─────────────────────────────────────────────────┤
│                                                 │
│ Authority Type: ○ Ephemeral  ○ Pseudonymous     │
│ Content Visibility: [Public ▼]                  │
│ Identity Disclosable: ☐                         │
│                                                 │
│ [Generate Anonymous Identity]                   │
│                                                 │
│ ┌─ Ephemeral Authority ─────────────────────┐   │
│ │ Authority: key:ed25519:z8Qm... (one-time) │   │
│ │ Private key: [destroyed after signing]      │   │
│ │ KeyDocument: NONE (§9.5)                    │   │
│ └───────────────────────────────────────────┘   │
│                                                 │
│ Content:                                        │
│ ┌─────────────────────────────────────────────┐ │
│ │ { "whistleblower_report": true,              │ │
│ │   "finding": "Unauthorized data sharing" }   │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ [Sign & Publish Anonymously]                    │
│                                                 │
│ ┌─ Resolution Result ───────────────────────┐   │
│ │ verified: true ✓                           │   │
│ │ privacyMode: anonymous                     │   │
│ │ identityType: anonymous-ephemeral          │   │
│ │ contentStatus: verified                     │   │
│ │ keyDocumentResolved: false                  │   │
│ └───────────────────────────────────────────┘   │
│                                                 │
│ ── Unlinkability Proof ──────────────────────   │
│ [Generate Second Ephemeral]                     │
│ Authority 1: key:ed25519:z8Qm...                │
│ Authority 2: key:ed25519:z6Nk...                │
│ Keys differ: ✓  Authorities differ: ✓           │
│ → Computationally unlinkable                     │
│                                                 │
│ ── Pseudonymous Comparison ──────────────────   │
│ [Sign Two Manifests with Same Pseudonym]        │
│ Authority 1: key:ed25519:z4Rj... ← same         │
│ Authority 2: key:ed25519:z4Rj... ← same         │
│ → Linkable (same persistent identity)            │
│                                                 │
│ ▶ Under the Hood                                │
│   { authorityType: "ephemeral",                  │
│     keyDocumentExpected: false,                   │
│     contentVisibility: "public",                  │
│     privateKeyDestroyed: true }                   │
└─────────────────────────────────────────────────┘
```

**Interactive elements:**
- Authority type radio (ephemeral / pseudonymous)
- Content visibility dropdown (public / encrypted / selective-disclosure / private)
- "Generate Anonymous Identity" button
- "Sign & Publish Anonymously" button
- Unlinkability proof (generates two ephemeral authorities, proves they differ)
- Pseudonymous comparison (signs two manifests with same key, proves linkability)

**Key demo points:**
- Ephemeral authorities have no KeyDocument
- Private key destruction after signing (shown explicitly)
- Two ephemeral authorities are computationally unlinkable
- Pseudonymous authorities are intentionally linkable
- Content visibility dispatches to the appropriate sub-handler (encrypted, SD, public, PoP)

---

### E.5 Sub-Panel: Third-Party Attestation (Mode 5)

**Purpose:** Demonstrate cross-authority attestation with dual-signature verification.

**Layout:**

```
┌─────────────────────────────────────────────────┐
│ THIRD-PARTY ATTESTATION                  §10    │
├─────────────────────────────────────────────────┤
│                                                 │
│ ── Subject (data owner) ─────────────────────   │
│ Authority: key:ed25519:z6Mk... (auto-generated) │
│ Manifest: sha256:abc123...                       │
│ Content: { "name": "Dana", "clearance": "TS" }  │
│ [View Subject Manifest]                          │
│                                                 │
│ ── Attestor (examiner) ──────────────────────   │
│ Authority: key:ed25519:z9Qr... (separate key)   │
│                                                 │
│ Claim:                                          │
│  Property: [security-clearance-valid]           │
│  Value: [true]                                  │
│  Scope: [TS/SCI]                                │
│  Valid Until: [2027-03-07]                       │
│                                                 │
│ Evidence:                                       │
│  Method: [direct-examination]                   │
│  Description: [Examined personnel record...]     │
│                                                 │
│ [Sign Attestation]                              │
│                                                 │
│ ┌─ Attestation Manifest ────────────────────┐   │
│ │ @type: hiri:AttestationManifest            │   │
│ │ hiri:content: ABSENT (§10.4)               │   │
│ │ hiri:attestation:                          │   │
│ │   subject: { authority, manifestHash }      │   │
│ │   claim: { property, value, scope }         │   │
│ │   evidence: { method, description }         │   │
│ └───────────────────────────────────────────┘   │
│                                                 │
│ ── Verification ─────────────────────────────   │
│                                                 │
│ [Verify: Both Available]                        │
│  Attestor signature: ✓                          │
│  Subject signature: ✓                            │
│  Trust level: FULL ████████████                  │
│                                                 │
│ [Verify: Subject Unavailable]                   │
│  Attestor signature: ✓                          │
│  Subject manifest: unavailable                   │
│  Trust level: PARTIAL ████████░░░░               │
│  ⚠ Trust based on attestor signature alone       │
│                                                 │
│ [Verify: Attestor Key Revoked]                  │
│  Attestor key status: revoked                    │
│  Subject manifest: unavailable                   │
│  Trust level: UNVERIFIABLE ░░░░░░░░░░░           │
│                                                 │
│ ── Staleness ────────────────────────────────   │
│ [|──────────●─────────] 2027-06-01             │
│  Attested    ▲      validUntil                  │
│              │                                   │
│  stale: TRUE ⚠                                   │
│                                                 │
│ ── Attestation Chain ────────────────────────   │
│ V1: clearance=valid (2026-01)                    │
│ V2: clearance=upgraded/SAP (2026-06)             │
│ V3: clearance=revoked (2027-01)                  │
│ [Build 3-Version Chain]                          │
│ Chain valid: ✓  Depth: 3                         │
│                                                 │
│ ▶ Under the Hood                                │
│   { dualSignature: true,                         │
│     attestorSig: "verified",                     │
│     subjectSig: "verified",                      │
│     trustLevel: "full",                           │
│     §10.4: "no hiri:content block" }             │
└─────────────────────────────────────────────────┘
```

**Interactive elements:**
- Subject manifest viewer (auto-generated or loaded from Tab B)
- Attestation claim form (property, value, scope, validUntil)
- Evidence form (method, description)
- "Sign Attestation" button
- Three verification buttons (both available, subject unavailable, attestor revoked)
- Trust level visual indicator (progress bar: full/partial/unverifiable)
- Staleness slider (same pattern as PoP and Tab A clock)
- "Build 3-Version Chain" button (clearance lifecycle demo)

**Key demo points:**
- Attestation manifests have NO `hiri:content` block
- Trust is a three-level spectrum, not binary
- Stale attestations are not invalid — they're informational
- Attestation chains track evolving claims

---

## Tab B Modifications: Privacy Mode Selector

Add a dropdown above the existing content form:

```
┌─ Privacy Mode ──────────────────────────────┐
│ [Public ▼]                                   │
│                                              │
│  Public (default)                            │
│  Proof of Possession                         │
│  Encrypted Distribution                      │
│  Selective Disclosure                        │
│  Anonymous Publication                       │
│  Third-Party Attestation                     │
└──────────────────────────────────────────────┘
```

When a non-public mode is selected:
- The JSON-LD preview updates to show the `hiri:privacy` block
- The manifest preview shows the mode-specific fields
- The "Sign" button label changes (e.g., "Sign Custody Assertion", "Encrypt & Sign")
- Mode-specific controls appear below the content form (recipient selector, statement checkboxes, etc.)
- The "Chain" panel shows `transitionFrom` when chaining across modes

---

## Tab D Modifications: Privacy-Aware Resolution

The resolution result panel gains new fields:

```
┌─ Resolution Result ──────────────────────────┐
│                                               │
│ Resolution succeeded in 14.2ms                │
│                                               │
│ Signature: ✓ valid                            │
│ Key: active                                   │
│ Privacy Mode: [encrypted]  ← NEW badge        │
│ Content Status: [ciphertext-verified] ← NEW   │
│ Identity Type: [identified] ← NEW (for anon)  │
│                                               │
│ ── Decryption (optional) ──────────────────   │
│ Recipient ID: [alice]                         │
│ Private Key: [paste or select] [Decrypt]      │
│ → Status: decrypted-verified ✓                │
│ → Plaintext: { "name": "Dana Reeves" }        │
│                                               │
│ ── Attestation Result (if Mode 5) ─────────   │
│ Trust Level: FULL                             │
│ Claim: security-clearance-valid = true         │
│ Stale: false                                   │
│                                               │
└───────────────────────────────────────────────┘
```

The fault injection panel gains privacy-specific faults:
- **Corrupt Ciphertext** — flip a byte in encrypted content → GCM auth failure
- **Swap Recipient Key** — replace alice's encrypted key share with random bytes
- **Tamper Statement Index** — modify a salted hash → index root mismatch

---

## Presets (New)

Add to the existing preset dropdown:

| Preset | Modes Exercised | What It Demonstrates |
|--------|----------------|---------------------|
| Proof of Possession | Mode 1 | Custody assertion without content revelation |
| Encrypted for Two Recipients | Mode 2 | Multi-recipient encryption, dual hashes, three resolver perspectives |
| Selective Disclosure | Mode 3 | Statement-level RDF disclosure, HMAC proofs, dictionary attack defense |
| Anonymous Whistleblower | Mode 4 + Mode 3 | Ephemeral authority + selective disclosure (the §4.6 use case) |
| Security Clearance Attestation | Mode 5 | Dual-signature verification, trust levels, attestation chain |
| Privacy Lifecycle: PoP → Encrypted → Public | Modes 1,2,public | Cross-mode chain walking with `getLogicalPlaintextHash()` |
| Key Rotation + Encrypted | Mode 2 + M5 | Encrypted content signed with rotated key — key lifecycle meets privacy |

### Preset: Privacy Lifecycle (most important)

This preset builds a 3-version chain:

```
V1: Proof of Possession (content private)
    content.hash = sha256:aaa111  (plaintext hash)

V2: Encrypted Distribution (content shared with alice)
    content.hash = sha256:bbb222  (ciphertext hash)
    privacy.parameters.plaintextHash = sha256:aaa111

V3: Public (content published openly)
    content.hash = sha256:aaa111  (plaintext hash)
```

The demo walks the chain and shows:
- Raw `content.hash` comparison: V1→V2 FAILS (aaa≠bbb)
- `getLogicalPlaintextHash()` comparison: V1→V2 SUCCEEDS (aaa=aaa)
- Mode transitions recorded: PoP→Encrypted, Encrypted→Public
- Addressing mode consistent: all `raw-sha256`

This is test vector B.15 from the spec, made interactive.

---

## Visual Design

### Color Coding by Privacy Mode

| Mode | Badge Color | Rationale |
|------|------------|-----------|
| Public | Green (`--green`) | Open, verified |
| Proof of Possession | Yellow (`--yellow`) | Claimed but unverifiable |
| Encrypted | Blue (`--accent`) | Confidential, key-dependent |
| Selective Disclosure | Orange (`--orange`) | Partial visibility |
| Anonymous | Purple (`#a371f7`) | Identity hidden |
| Attestation | Teal (`#56d4dd`) | Third-party trust |

These colors appear as:
- Tab E sub-panel accent bars
- Privacy mode badges in Tab D resolution results
- Chain visualization node colors in Tab B
- Preset selector category indicators

### Badge Patterns

```css
.badge-pop    { background: rgba(210, 153, 34, 0.15); color: var(--yellow); }
.badge-enc    { background: rgba(88, 166, 255, 0.15); color: var(--accent); }
.badge-sd     { background: rgba(219, 109, 40, 0.15); color: var(--orange); }
.badge-anon   { background: rgba(163, 113, 247, 0.15); color: #a371f7; }
.badge-attest { background: rgba(86, 212, 221, 0.15); color: #56d4dd; }
```

### Trust Level Indicator

```
FULL:          ████████████  (green)
PARTIAL:       ████████░░░░  (yellow)
UNVERIFIABLE:  ░░░░░░░░░░░░  (red)
```

---

## Implementation Strategy

### Phase 1: Tab E Infrastructure + PoP + Encrypted

- Create Tab E with accordion/sub-tab structure
- Implement E.1 (Proof of Possession) — simplest mode, reuses M10 code
- Implement E.2 (Encrypted Distribution) — reuses M11/M12 code
- Add privacy mode badges to Tab D resolution results
- Add "Encrypted for Two Recipients" preset

### Phase 2: Selective Disclosure

- Implement E.3 (Selective Disclosure) — the most complex panel
- Requires URDNA2015 canonicalizer (already in demo.js from M7)
- Statement index visualization
- Dictionary attack simulator animation
- Add "Selective Disclosure" preset

### Phase 3: Anonymous + Attestation

- Implement E.4 (Anonymous Publication)
- Implement E.5 (Third-Party Attestation)
- Add "Anonymous Whistleblower" preset
- Add "Security Clearance Attestation" preset

### Phase 4: Cross-Mode Integration

- Add privacy mode selector to Tab B
- Add privacy lifecycle preset (PoP → Encrypted → Public chain)
- Add privacy-aware fault injection to Tab D
- Wire all presets

### Bundle Integration

All privacy code is already in `demo.js` (the M10–M15 implementation compiles into the existing bundle). Tab E's JavaScript calls the same functions the tests call:
- `encryptContent()`, `decryptContent()` from `src/privacy/encryption.ts` / `decryption.ts`
- `buildStatementIndex()`, `generateHmacTags()` from `src/privacy/statement-index.ts` / `hmac-disclosure.ts`
- `generateEphemeralAuthority()` from `src/privacy/anonymous.ts`
- `buildAttestationManifest()`, `verifyAttestation()` from `src/privacy/attestation.ts`
- `resolveWithPrivacy()` from `src/privacy/resolve.ts`

No new dependencies. No new WASM. The existing Oxigraph engine handles the SPARQL queries over disclosed RDF subgraphs.

---

## Accessibility

- All interactive elements keyboard-navigable
- Color badges supplemented with text labels (not color-only)
- Trust level indicator has text fallback ("FULL", "PARTIAL", "UNVERIFIABLE")
- Statement checkboxes have aria-labels describing the N-Quad content
- Dictionary attack simulator has a text-only result summary below the animation

---

## Demo Script Integration

The existing HIRI-Demo-Script.docx (4-act structure) extends to a 6-act version:

- **Act 1:** Create identity and sign V1 (existing)
- **Act 2:** Verify and resolve (existing)
- **Act 3:** Tamper detection (existing)
- **Act 4:** Key rotation and revocation (existing)
- **Act 5 (NEW):** Privacy modes — walk through PoP, Encrypted, Selective Disclosure
- **Act 6 (NEW):** Privacy lifecycle — build a 3-version cross-mode chain, demonstrate `getLogicalPlaintextHash()` consistency, show the dictionary attack defense

Total demo time: ~20–25 minutes (up from ~12–15 minutes).
