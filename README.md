# HIRI (Hash-IRI) Protocol

Trust without centralization: verifiable claim identifiers.

## What is HIRI?

HIRI is a protocol for decentralized, verifiable knowledge and claims that operates **local-first**, **offline-capable**, and without dependence on centralized servers, blockchains, or protocol-specific trust anchors. It enables offline verification of data integrity and authorship, client-side querying without graph servers, and privacy-preserving public verification using zero-knowledge proofs.

For the full protocol specification, see [HIRI-Protocol-Spec.md](HIRI-Protocol-Spec.md).

## Core Design Principles

- **Local-first verification** — All trust decisions are made on the client using cryptographic primitives
- **Content-addressed truth** — Hashes, not servers, define integrity
- **Edge-canonical** — All core logic runs in a browser or via `node index.js`
- **JSON-LD native** — All inputs and outputs use JSON-LD as the canonical format
- **Zero runtime dependencies** — All protocol logic is self-contained

## Quick Start

```bash
git clone https://github.com/Skreen5hot/HIRI.git
cd HIRI
npm install
npm run build
npm test
```

**Requirements:** Node.js >= 20.0.0

## Project Structure

```
src/
  core/           Core computation (edge-canonical, no infrastructure deps)
  adapters/       Pluggable integration adapters
  state/          Pluggable state backends
  data/           Static data and JSON-LD schemas
tests/
  unit/           Per-component unit tests
  integration/    Full-system corpus validation
  browser/        Browser-specific tests
  fixtures/       JSON-LD test data
schemas/          JSON-LD context files and vocabularies
scripts/          Build, test, and utility scripts
docs/             User and developer documentation
planning/         Sprint-level planning documents
deliverables/     Milestone summaries
```

## Development

```bash
npm run build              # TypeScript compilation
npm test                   # Run tests (Node.js)
npm run test:browser       # Run tests in browser (edge-canonical verification)
npm run check              # Type checking
npm run check:edge-canonical  # Verify no Node.js imports in core
npm run clean              # Remove build artifacts
```

## Architecture

HIRI separates concerns into four layers. Only the first is core — the rest are pluggable:

| Layer | Description | Edge-Canonical? |
|-------|-------------|-----------------|
| **Computation** | Hashing, signing, verification, parsing | Yes (required) |
| **State** | Storage of intermediate results | Pluggable |
| **Orchestration** | Invocation and scheduling | Pluggable |
| **Integration** | External system access | Adapter only |

See [ROADMAP.md](ROADMAP.md) for implementation status and [Agentic_Startup_Guide.md](Agentic_Startup_Guide.md) for the development philosophy.

## Implementation Roadmap

| Phase | Milestone | Status |
|-------|-----------|--------|
| 0 | Development Infrastructure | Complete |
| 1 | The Verifiable Atom (signing, verification) | Next |
| 2 | Chain and Delta (version history) | Planned |
| 3 | Storeless Index (local RDF) | Planned |
| 4 | Query (client-side SPARQL) | Planned |
| 5 | Key Lifecycle (rotation, revocation) | Planned |

See [HIRI_Milestones.md](HIRI_Milestones.md) for detailed milestone specifications.

## Contributing

Contributions are welcome. Before contributing:

1. Read [ROADMAP.md](ROADMAP.md) for current scope and status
2. Read [CLAUDE.md](CLAUDE.md) for architectural constraints
3. All core code must pass the edge-canonical constraint — no Node.js built-ins in `src/core/`
4. All modules must have corresponding tests
5. All tests must pass in both Node.js and browser environments

## License

MIT - see [LICENSE](LICENSE)
