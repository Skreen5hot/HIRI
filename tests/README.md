# HIRI Protocol - Test Suite

## Directory Structure

```
tests/
├── unit/           # Per-component unit tests
├── integration/    # Full-system corpus validation
├── browser/        # Browser-specific tests
├── fixtures/       # JSON-LD test data
│   ├── person.jsonld       # Milestone 1 primary fixture
│   └── person-v2.jsonld    # Milestone 2 delta fixture
└── README.md       # This file
```

## Running Tests

```bash
# Run all tests (Node.js environment)
npm test

# Run tests in watch mode
npm run test:watch

# Run tests in browser (edge-canonical verification)
npm run test:browser

# Run tests with coverage
npm run test:coverage
```

## Edge-Canonical Verification

All tests in `tests/unit/` are designed to pass in **both** Node.js and browser environments. This is the primary mechanism for verifying edge-canonical compliance.

- `npm test` runs tests in Node.js (fast, default)
- `npm run test:browser` runs the same tests in Chromium via Playwright

If a unit test passes in Node.js but fails in the browser, that indicates an edge-canonical violation in the code under test.

## Conventions

- Test files use the `.test.ts` suffix
- Test files mirror source file names: `src/core/hash-algorithm.ts` -> `tests/unit/hash-algorithm.test.ts`
- Tests use explicit imports: `import { describe, it, expect } from 'vitest'`
- Fixtures are JSON-LD files in `tests/fixtures/`

## Milestone 1 Test Cases

| # | Test Case | Module Under Test |
|---|-----------|-------------------|
| 1.1 | Generate keypair, derive HIRI authority URI | AuthorityDerivation |
| 1.2 | Sign person.jsonld, produce manifest | Signer + ManifestBuilder |
| 1.3 | Verify manifest against public key | Signer.verify() |
| 1.4 | Modify content, re-verify (expect false) | Signer.verify() |
| 1.5 | Modify signature, re-verify (expect false) | Signer.verify() |
| 1.6 | Genesis manifest accepted (v1, no chain) | isGenesisValid() |
| 1.7 | Non-genesis rejected (v2, no chain) | isGenesisValid() |
| 1.8 | Hash resolved via registry (sha256) | HashRegistry.resolve() |
| 1.9 | Unsupported hash algorithm throws | HashRegistry.resolve() |
