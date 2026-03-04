# HIRI Protocol

HIRI (Hash-IRI) is a decentralized, edge-first, verifiable knowledge protocol. Knowledge is represented as signed JSON-LD artifacts linked into hash-verified chains — publishable, shareable, and queryable without centralized infrastructure.

**[Try the live demo](https://skreen5hot.github.io/HIRI/)** — runs entirely in your browser with zero network requests.

## Quick Start

```bash
npm install
npm run build
npm test              # 81 spec tests across 4 test suites
npm run test:purity   # verify kernel has no I/O or infrastructure imports
npm run build:demo    # bundle the browser demo
```

## Project Structure

```
src/kernel/           Pure computation — signing, hashing, chains, resolution, queries
src/adapters/         Infrastructure — Ed25519, SHA-256, storage backends, Oxigraph RDF
src/demo/             Browser demo — 4 interactive tabs, presets, network monitor
site/                 Static site — demo shell, FAQ, Developer Guide
tests/                Spec tests — M1 through M5
project/              Specs and planning — protocol spec, milestones, decisions
```

### Layer Boundaries

| Layer | Directory | Rule |
|-------|-----------|------|
| 0 — Kernel | `src/kernel/` | Pure computation. No I/O. No imports from other layers. |
| 1 — Adapters | `src/adapters/` | Infrastructure. May import from kernel. |
| 2 — Demo | `src/demo/` | Browser UI. May import from kernel and adapters. |

Enforced by `npm run test:purity`.

## Documentation

- [Protocol Specification](project/HIRI-Protocol-Spec.md) — the governing spec (v2.1)
- [Milestone Definitions](project/HIRI-MVP-Milestones-v1.4.md) — test matrices, interface contracts, execution sequences
- [Architecture Decisions](project/DECISIONS.md) — ADR log
- [Developer Guide](https://skreen5hot.github.io/HIRI/developer-guide.html) — protocol walkthrough with API reference
- [FAQ](https://skreen5hot.github.io/HIRI/faq.html) — common technical and business questions

## License

[MIT](LICENSE)
