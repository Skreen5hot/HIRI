# Testing Guide

How to write domain-specific tests beyond the spec test suite.

## Spec Tests vs. Domain Tests

The template ships with three spec tests and a purity check:

| Test | Purpose |
|------|---------|
| `determinism.test.ts` | Same input → identical output |
| `no-network.test.ts` | No network API calls |
| `snapshot.test.ts` | Example input matches expected output |
| `ensure-kernel-purity.ts` | No imports from outside `src/kernel/` |

**Do not modify spec tests.** They validate architectural invariants — determinism, isolation, and purity. Domain tests validate *your* logic. They serve different purposes and must remain separate.

## Where to Put Domain Tests

Place domain test files in `tests/` with the naming convention `<domain>.test.ts`:

```
tests/
  determinism.test.ts          # spec test (do not modify)
  no-network.test.ts           # spec test (do not modify)
  snapshot.test.ts             # spec test (do not modify)
  run-tests.ts                 # test runner
  event-normalization.test.ts  # YOUR domain test
```

The test runner (`run-tests.ts`) auto-discovers all `*.test.js` files in the `tests/` directory. No registration needed.

## Test File Pattern

Each test file is a standalone Node.js script. Use `node:assert` for assertions and the `✓ PASS:` / `✗ FAIL:` markers for test runner detection.

```ts
import { strictEqual, deepStrictEqual } from "node:assert";
import { transformEvent } from "../examples/event-normalization/transform.js";

console.log("Event normalization tests\n");

let passed = 0;
let failed = 0;

// --- Test: individual rule ---
try {
  const result = transformEvent({
    "@context": "https://schema.org",
    "@type": "Event",
    "name": "quarterly PLANNING meeting",
    "startDate": "2025-03-15T09:00:00",
  });
  if ("errorCode" in result) throw new Error("Expected success, got error");
  strictEqual(result.name, "Quarterly Planning Meeting");
  console.log("  ✓ PASS: event name is title-cased");
  passed++;
} catch (error) {
  console.error("  ✗ FAIL: event name title-casing");
  console.error("   ", error instanceof Error ? error.message : String(error));
  failed++;
}

// Summary
console.log(`\n  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
```

## Testing Patterns

### Testing Error Cases

```ts
try {
  const result = transformEvent({ name: "No Context" });
  strictEqual("errorCode" in result, true);
  strictEqual((result as any).errorCode, "INVALID_CONTEXT");
  console.log("  ✓ PASS: missing @context returns INVALID_CONTEXT");
  passed++;
} catch (error) {
  console.error("  ✗ FAIL: missing @context error handling");
  console.error("   ", error instanceof Error ? error.message : String(error));
  failed++;
}
```

### Testing Uncertainty Annotations

```ts
try {
  const result = transformEvent({
    "@context": "https://schema.org",
    "@type": "Event",
    "name": "Test",
    "startDate": "2025-03-15T09:00:00",
    // no endDate
  });
  const duration = (result as any).duration;
  strictEqual(duration.uncertainty["@type"], "Uncertainty");
  strictEqual(duration.uncertainty.status, "unknown");
  console.log("  ✓ PASS: missing endDate annotated with Uncertainty");
  passed++;
} catch (error) {
  console.error("  ✗ FAIL: Uncertainty annotation for missing endDate");
  console.error("   ", error instanceof Error ? error.message : String(error));
  failed++;
}
```

### Testing Provenance Tracking

```ts
try {
  const result = transformEvent(fullInput);
  const rules = (result as any).provenance.rulesApplied;
  strictEqual(rules.includes("normalize-event-name"), true);
  strictEqual(rules.includes("annotate-missing-end-date"), true);
  console.log("  ✓ PASS: provenance tracks applied rules");
  passed++;
} catch (error) {
  console.error("  ✗ FAIL: provenance rule tracking");
  console.error("   ", error instanceof Error ? error.message : String(error));
  failed++;
}
```

## How Test Discovery Works

The test runner (`tests/run-tests.ts`) calls `readdir` on its own directory, finds all `*.test.js` files, and runs each in a separate `node` child process. It counts `✓ PASS:` and `✗ FAIL:` markers in stdout/stderr.

Key points:

- Each test file MUST be self-contained (no shared setup)
- Each test file MUST exit with code 0 on success, non-zero on failure
- Use `✓ PASS:` prefix for passing assertions (Unicode U+2713)
- Use `✗ FAIL:` prefix for failing assertions (Unicode U+2717)
- Print a summary line at the end: `N passed, M failed`

## Running Tests

Domain tests run automatically with the spec tests:

```bash
npm test
```

The test runner discovers all `*.test.js` files — your domain tests are included without configuration.
