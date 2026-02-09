# HIRI Protocol - Agent Instructions

## Project Identity

**HIRI (Hash-IRI) Protocol** is a protocol-agnostic, local-first, verifiable knowledge and claim foundation. This is a TypeScript library, not an application. It produces edge-canonical modules that run in both Node.js and browsers.

- **Governing specification:** `HIRI-Protocol-Spec.md` v2.1.0
- **Implementation roadmap:** `HIRI_Milestones.md` v1.3
- **Development philosophy:** `Agentic_Startup_Guide.md`
- **Current status:** See `ROADMAP.md`

## The Primary Rule: Edge-Canonical Constraint

**ALL code in `src/core/` MUST run in a browser or via `node index.js`. No exceptions.**

- No Node.js built-ins (`fs`, `path`, `http`, `net`, `os`, `child_process`) in `src/core/`
- No npm runtime dependencies. All protocol logic is self-contained.
- Network unavailability is not an error state.
- The edge-canonical check (`npm run check:edge-canonical`) must pass at all times.
- If a component cannot function under this constraint, it belongs in `src/adapters/`, not `src/core/`.

## Architecture

```
src/
  core/       Sacred. Edge-canonical only. Pure computation.
  adapters/   Pluggable integrations. May use Node.js APIs.
  state/      Pluggable state backends.
  data/       Static data, JSON-LD schemas.
```

### Four-Layer Separation

| Layer | Location | Edge-Canonical? |
|-------|----------|-----------------|
| **Computation** | `src/core/` | **Yes (required)** |
| **State** | `src/state/` | Pluggable |
| **Orchestration** | Application-level | Pluggable |
| **Integration** | `src/adapters/` | Adapter only |

## JSON-LD Contract

- All inputs and outputs use JSON-LD as the canonical format.
- Context files live in `schemas/`.
- Test fixtures are JSON-LD files in `tests/fixtures/`.
- Manifest structures follow the HIRI Protocol Spec v2.1.0.

## Naming Conventions

- **Files:** kebab-case (`hash-algorithm.ts`, `hiri-uri.ts`)
- **Classes/Interfaces:** PascalCase (`HashAlgorithm`, `HiriURI`)
- **Functions:** camelCase (`deriveAuthority`, `canonicalize`)
- **Constants:** UPPER_SNAKE_CASE (`FORBIDDEN_MODULES`)
- **Test files:** `*.test.ts` matching source file name

## Test Requirements

- Every new module in `src/core/` must have a corresponding test file in `tests/unit/`.
- Tests use explicit imports: `import { describe, it, expect } from 'vitest'` (no globals).
- All unit tests must pass in both Node.js and browser environments.
- Test fixtures are JSON-LD files in `tests/fixtures/`.

## Build and Test Commands

```bash
npm run build              # TypeScript compilation
npm test                   # Run all tests (Node.js)
npm run test:browser       # Run tests in Chromium (edge-canonical verification)
npm run test:watch         # Run tests in watch mode
npm run test:coverage      # Run tests with coverage report
npm run check              # Type checking without emit
npm run check:edge-canonical  # Verify no Node.js imports in core
npm run clean              # Remove build artifacts
```

## Scope Boundaries

### v1 IN SCOPE (Milestones 1-5)

- Milestone 1: Hash-IRI identifiers, manifests, signing, verification
- Milestone 2: Chain linking, delta format, version history
- Milestone 3: Storeless index, local RDF indexing
- Milestone 4: SPARQL query, entailment modes
- Milestone 5: Key lifecycle, rotation, revocation

### v2 DEFERRED

- ZK proof generation and verification
- Chain compaction (recursive SNARKs)
- Privacy accumulators and budget enforcement
- Timestamp authority integration
- Consortium key management
- IPFS/IPNS adapters

## Don't-Do List

- **DO NOT** add runtime npm dependencies without explicit approval.
- **DO NOT** import Node.js built-ins in `src/core/`.
- **DO NOT** assume network availability in core logic.
- **DO NOT** use databases, message brokers, or external services in core.
- **DO NOT** implement features beyond the current milestone scope.
- **DO NOT** modify the protocol specification files (`HIRI-Protocol-Spec.md`).
- **DO NOT** use CommonJS (`require`/`module.exports`). This is an ESM-only project.
- **DO NOT** skip the edge-canonical check before committing.
- **DO NOT** add infrastructure dependencies to solve problems that can be solved with pure computation.

## Key Technical Decisions

- **Module system:** ESM-only (`"type": "module"` in package.json)
- **TypeScript target:** ES2022 with strict mode
- **Cryptography:** Web Crypto API (available in both Node.js 20+ and browsers)
- **Canonicalization:** JCS (RFC 8785) for MVP; URDNA2015 deferred to post-MVP
- **Import paths:** Use `.js` extensions in imports (required by NodeNext module resolution)
