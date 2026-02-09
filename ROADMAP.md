# HIRI Protocol - Roadmap

**Version:** 0.1.0
**Last Updated:** February 2026

---

## Vision

**HIRI (Hash-IRI) Protocol** is a protocol for decentralized, verifiable knowledge and claims that operates local-first, offline-capable, and without dependence on centralized servers, blockchains, or protocol-specific trust anchors.

**What HIRI IS:**
- A TypeScript library implementing protocol primitives for verifiable, content-addressed knowledge
- A local-first system where all verification happens on the client
- A JSON-LD-native protocol with self-describing, linkable data

**What HIRI is NOT:**
- Not a database, not a blockchain, not a server application
- Not a product — it is a protocol and reference implementation
- Not dependent on any specific network, storage, or trust infrastructure

---

## Edge-Canonical Commitment

All core protocol logic runs in a browser or via `node index.js`. Cloud deployments, databases, and service meshes are derivative optimizations — never the baseline.

**The Spec Test:** Before any module is accepted into `src/core/`, it must pass this question:

> Could a developer evaluate, reason about, and execute this system using only a browser, a local Node.js runtime, and JSON-LD files?

---

## Architecture

### Four-Layer Separation

| Layer | Location | Edge-Canonical? | Description |
|-------|----------|-----------------|-------------|
| **Computation** | `src/core/` | **Yes (required)** | Hashing, signing, verification, URI parsing |
| **State** | `src/state/` | Pluggable | In-memory, localStorage, IndexedDB |
| **Orchestration** | Application-level | Pluggable | Direct call, event loop |
| **Integration** | `src/adapters/` | Adapter only | HTTP fetch, IPFS, file system |

### Key Technical Decisions

- **Language:** TypeScript (strict mode)
- **Module system:** ESM-only
- **Cryptography:** Web Crypto API (Node.js 20+ and browsers)
- **Canonicalization:** JCS (RFC 8785) for MVP
- **Data format:** JSON-LD as canonical representation
- **Runtime dependencies:** Zero

---

## Phase 0: Development Infrastructure

**Status:** Complete
**Tests:** 3 (smoke tests)

### Deliverables

| File | Description |
|------|-------------|
| `package.json` | ESM-only, zero runtime deps, 4 dev deps |
| `tsconfig.json` | ES2022, strict, NodeNext module resolution |
| `vitest.config.ts` | Node.js test environment |
| `vitest.browser.config.ts` | Browser test environment (Playwright/Chromium) |
| `src/core/index.ts` | Core module barrel (empty) |
| `src/index.ts` | Top-level entry point |
| `tests/unit/smoke.test.ts` | Infrastructure verification |
| `tests/fixtures/person.jsonld` | Milestone 1 test fixture |
| `tests/fixtures/person-v2.jsonld` | Milestone 2 test fixture |
| `schemas/hiri.context.jsonld` | HIRI JSON-LD context (v0.1) |
| `scripts/check-edge-canonical.js` | Automated edge-canonical enforcement |
| `scripts/clean.js` | Build artifact cleanup |
| `CLAUDE.md` | Agent instructions |
| `.claude/settings.json` | Agent permissions |
| `.github/workflows/ci.yml` | CI pipeline (Node 20+22, browser, security) |
| `.github/dependabot.yml` | Automated dependency updates |
| `ROADMAP.md` | This file |
| `README.md` | Project overview and quick start |

---

## Phase 1 / Milestone 1: The Verifiable Atom (NEXT)

**Status:** Not started
**Priority:** Critical
**Depends On:** Phase 0
**Edge-Canonical:** Yes — all code in `src/core/`
**Governing Detail:** `HIRI_Milestones.md` v1.3

### Goal

Produce a single signed, verifiable manifest for a JSON-LD document. This is the atomic unit of the HIRI protocol — every subsequent milestone builds on this foundation.

### Harness Interfaces (implement first)

| Interface | File | Purpose |
|-----------|------|---------|
| `HashAlgorithm` | `src/core/hash-algorithm.ts` | Pluggable hash algorithm interface |
| `HashRegistry` | `src/core/hash-registry.ts` | Algorithm registration and dispatch |
| `HiriURI` | `src/core/hiri-uri.ts` | HIRI URI parsing and construction |
| `HiriSignature` | `src/core/signature.ts` | Signature block structure |
| `SigningKey` | `src/core/signature.ts` | Key material wrapper |
| `Signer` | `src/core/signature.ts` | Sign/verify interface |
| `AuthorityDerivation` | `src/core/authority.ts` | Public key to authority derivation |

### Implementation Sequence

```
3a: SHA256Algorithm (Web Crypto API)        → Tests 1.8, 1.9
3b: HashRegistry wiring
3c: Ed25519 keypair + authority derivation  → Test 1.1
3d: Content preparation + canonicalization (JCS, RFC 8785)
3e: Manifest construction
3f: Signing (Ed25519)                       → Test 1.2
3g: Verification                            → Tests 1.3, 1.4, 1.5
3h: Genesis handling                        → Tests 1.6, 1.7
3i: Minimal KeyDocument construction
```

### Test Cases (9 total)

| # | Test Case | Pass Condition |
|---|-----------|----------------|
| 1.1 | Generate keypair, derive authority URI | URI matches `hiri://key:ed25519:<20-char-base58>/...` |
| 1.2 | Sign person.jsonld, produce manifest | Manifest has valid `@id`, `hiri:content.hash`, `hiri:signature` |
| 1.3 | Verify manifest against public key | Returns `true` |
| 1.4 | Modify content byte, re-verify | Returns `false` |
| 1.5 | Modify signature, re-verify | Returns `false` |
| 1.6 | Genesis manifest (v1, no chain) | Accepted |
| 1.7 | Non-genesis manifest (v2, no chain) | Rejected |
| 1.8 | Resolve `sha256:Qm...` via registry | Returns SHA256Algorithm |
| 1.9 | Resolve `blake3:Qm...` (unregistered) | Throws UnsupportedHashAlgorithm |

### Custom Implementations (no external deps)

- **Base58 encoding** — ~50 lines, custom in `src/core/`
- **JCS canonicalization** (RFC 8785) — ~100 lines, custom in `src/core/`

### Success Criteria

- All 9 tests passing in both Node.js and browser
- Zero runtime dependencies
- Edge-canonical check passes
- Manifest output matches structure in HIRI Protocol Spec §5.2

---

## Phase 2 / Milestone 2: Chain and Delta

**Status:** Not started
**Depends On:** Phase 1
**Edge-Canonical:** Yes

Chain linking between manifest versions, delta format (JSON Patch / RDF-aware delta), and chain verification.

---

## Phase 3 / Milestone 3: Storeless Index

**Status:** Not started
**Depends On:** Phase 2
**Edge-Canonical:** Yes

Client-side RDF index with private/public separation. No triple store server required.

---

## Phase 4 / Milestone 4: Query

**Status:** Not started
**Depends On:** Phase 3
**Edge-Canonical:** Yes

Client-side SPARQL query execution against local index. Entailment modes (none, runtime, materialized).

---

## Phase 5 / Milestone 5: Key Lifecycle

**Status:** Not started
**Depends On:** Phase 1
**Edge-Canonical:** Yes

Full key lifecycle management: rotation, revocation, recovery keys, grace periods.

---

## v1/v2 Scope Contract

### v1 IN SCOPE (locked)

**Architectural constraint:** All v1 code must pass the edge-canonical spec test.

- Milestone 1: Hash-IRI identifiers, manifests, signing, verification
- Milestone 2: Chain linking, delta format, version history
- Milestone 3: Storeless index, local RDF indexing
- Milestone 4: SPARQL query, entailment modes
- Milestone 5: Key lifecycle, rotation, revocation
- All custom implementations (Base58, JCS, etc.)

### v2 EXPLICITLY DEFERRED

- **ZK proof generation/verification** — requires proof system infrastructure (§9)
- **Chain compaction** — requires recursive SNARK implementation (§12)
- **Privacy accumulators** — requires Privacy Authority infrastructure (§9.5)
- **Timestamp authority integration** — requires external TSA service
- **Consortium key management** — requires multi-party coordination
- **IPFS/IPNS adapters** — infrastructure integration, not core logic
- **DNS-based discovery** — convenience layer, not security baseline

---

## Bundle/Performance Budget

| Metric | Target |
|--------|--------|
| Runtime dependencies | 0 |
| Core bundle size (minified) | < 50KB |
| Manifest verification time | < 10ms |
| SPARQL query (10K triples) | < 100ms |

---

## Version History

| Date | Phase | Description |
|------|-------|-------------|
| 2026-02-08 | Phase 0 | Development infrastructure scaffold |
