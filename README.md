# JSON-LD Deterministic Service Template

A minimal template for building deterministic services that transform JSON-LD documents. The kernel is a pure function: JSON-LD in, JSON-LD out.

## What This Is

A starting point for services that need:

- **Deterministic, reproducible transformations** — same input always produces same output
- **JSON-LD as the canonical data format** — semantic interoperability built in
- **Offline-first, edge-compatible execution** — no server required
- **No infrastructure dependencies at the core** — the kernel is pure computation

This template intentionally contains: **1 kernel, 3 spec tests, 0 runtime dependencies.**

## What This Is Not

- A framework (no runtime, no lifecycle management)
- An API server (adapters handle that)
- A database (adapters handle that)
- An opinionated application scaffold

## Quick Start

**Prerequisites:** Node.js >= 22

```bash
npm install
npm run build
node dist/kernel/index.js examples/input.jsonld
```

This runs the kernel transform on the example input and prints canonicalized JSON-LD to stdout.

### Event Normalization Example

See `examples/event-normalization/` for a real-world transform that normalizes Schema.org Event documents — title-casing, type inference, status mapping, and Uncertainty annotations for missing data.

## Conformance Checklist

Three spec tests and a purity check verify architectural compliance:

| Test | What it verifies | Command |
|------|-----------------|---------|
| Determinism | Same input produces identical output across invocations | `npm test` |
| No-Network | Kernel executes without any network API calls | `npm test` |
| Snapshot | Example input produces expected output exactly | `npm test` |
| Kernel Purity | No imports from outside `src/kernel/` in kernel code | `npm run test:purity` |

Run everything:

```bash
npm test
npm run test:purity
```

## Project Structure

```
src/kernel/
  canonicalize.ts    # Deterministic JSON serialization
  transform.ts       # Pure transformation function (edit this)
  index.ts           # CLI entry point
src/composition/
  concepts/          # Domain Concepts (Layer 1, optional)
  synchronizations/  # Event-driven orchestration (Layer 1, optional)
src/adapters/
  integration/       # HTTP, file, queue adapters (Layer 2, optional)
  persistence/       # Storage adapters (Layer 2, optional)
  orchestration/     # Scheduling, retries, deployment (Layer 2, optional)
tests/
  determinism.test.ts
  no-network.test.ts
  snapshot.test.ts
  run-tests.ts       # Test runner with JSON reporting
scripts/
  ensure-kernel-purity.ts  # Static import analysis
examples/
  input.jsonld              # Example input document
  expected-output.jsonld    # Expected output (update when transform changes)
  event-normalization/      # Real-world Schema.org Event example
docs/
  ARCHITECTURE.md           # Core design contract (6 principles)
  COMPUTATION_MODEL.md      # Kernel specification
  COMPOSITION_GUIDE.md      # Building on the kernel (optional)
  ADAPTER_BOUNDARIES.md     # Integration rules
  CONTRIBUTING.md           # How to contribute
  TEMPLATE_INTENT.md        # Why this template is minimal
  TESTING_GUIDE.md          # How to write domain-specific tests
  COOKBOOK.md                # Practical recipes for common tasks
project/
  ROADMAP.md                # Your implementation roadmap (edit this)
  SPEC.md                   # Your domain-specific technical spec (edit this)
  DECISIONS.md              # Architecture decision log
CLAUDE.md                   # AI agent governance (Barcode System directives)
```

## How to Use This Template

1. Clone or use as a GitHub template
2. Define your roadmap in `project/ROADMAP.md` and your domain spec in `project/SPEC.md`
3. Edit `src/kernel/transform.ts` — replace the identity transform with your domain logic
4. Update `examples/expected-output.jsonld` to match your new output
5. Run `npm test` to verify conformance
6. Build adapters outside `src/kernel/` for persistence, networking, etc.

## Documentation

- [Architecture Principles](docs/ARCHITECTURE.md) — the normative design contract
- [Computation Model](docs/COMPUTATION_MODEL.md) — kernel specification and contracts
- [Composition Guide](docs/COMPOSITION_GUIDE.md) — optional patterns for building on the kernel
- [Adapter Boundaries](docs/ADAPTER_BOUNDARIES.md) — rules for infrastructure integration
- [Contributing](docs/CONTRIBUTING.md) — how to contribute and the spec test checklist
- [Template Intent](docs/TEMPLATE_INTENT.md) — why this template is intentionally minimal
- [Testing Guide](docs/TESTING_GUIDE.md) — how to write domain-specific tests
- [Cookbook](docs/COOKBOOK.md) — recipes for HTTP APIs, databases, context resolution, and more
- [CLAUDE.md](CLAUDE.md) — AI agent governance directives (Barcode System)
- [Project Space](project/) — your roadmap, technical spec, and decision log

## License

[MIT](LICENSE)
