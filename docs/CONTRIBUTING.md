# Contributing

## Spec Test Checklist

Before merging any change, verify all of the following:

- [ ] `npm run build` succeeds with no TypeScript errors
- [ ] `npm test` passes all three spec tests (determinism, no-network, snapshot)
- [ ] `npm run test:purity` passes the static kernel isolation check
- [ ] Kernel code (`src/kernel/`) contains no I/O operations (`fetch`, `fs`, `Date.now`, `Math.random`)
- [ ] All kernel input and output uses JSON-LD format (`@context` required)
- [ ] Determinism is preserved — same input produces identical canonicalized output
- [ ] No new runtime dependencies added (devDependencies are acceptable)
- [ ] `examples/expected-output.jsonld` is updated if transform output changes

## Development Workflow

1. Clone the repository
2. `npm install`
3. Edit the transformation logic in `src/kernel/transform.ts`
4. Update `examples/expected-output.jsonld` if the output structure changes
5. Run `npm run build` to compile
6. Run `npm test` to verify all spec tests pass
7. Run `npm run test:purity` to verify kernel isolation
8. Submit a pull request

## Domain-Specific Tests

When implementing transformation logic beyond the identity transform, write domain-specific tests following the patterns in the [Testing Guide](./TESTING_GUIDE.md). Domain tests are auto-discovered by the test runner — place them in `tests/` with the `*.test.ts` naming convention.

## Architecture Compliance

All changes MUST conform to the principles defined in [ARCHITECTURE.md](./ARCHITECTURE.md).

The kernel (`src/kernel/transform.ts`) MUST remain a pure function:
- No file system access
- No network calls
- No environment variable reads
- No non-deterministic operations
- No imports from outside `src/kernel/`

## AI-Assisted Development

When working with AI agents (Claude, Copilot, etc.), the [CLAUDE.md](../CLAUDE.md) file at the repo root defines governance directives, persona triggers, and operational boundaries.

Key points:
- `project/ROADMAP.md` is the source of truth for current work — read it at session start
- `project/DECISIONS.md` logs architectural decisions across sessions
- The Barcode flow (Product Owner → Lead Developer → Cynical Auditor → Terminal Check) structures AI-assisted implementation
- AI agents MUST NOT modify spec tests or add runtime dependencies without Orchestrator approval

## Commit Guidelines

- Use descriptive commit messages that explain *why*, not just *what*
- One logical change per commit
- Run the full spec test suite before pushing

## Optional: Linting

This template does not ship with a linter to keep dependencies minimal. If you add ESLint, configure it to flag non-deterministic API usage in `src/kernel/`. A recommended starting point:

```json
{
  "rules": {
    "no-restricted-globals": ["error", "Date", "fetch", "XMLHttpRequest"],
    "no-restricted-properties": ["error",
      { "object": "Math", "property": "random" },
      { "object": "process", "property": "env" }
    ]
  }
}
```
