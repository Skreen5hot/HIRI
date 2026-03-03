/**
 * Determinism Test
 *
 * Verifies that the kernel transform produces identical output
 * when invoked multiple times with the same input.
 *
 * This is Spec Test #1 from ARCHITECTURE.md.
 */

import { deepStrictEqual, strictEqual } from "node:assert";
import { transform } from "../src/kernel/transform.js";
import { stableStringify } from "../src/kernel/canonicalize.js";
import type { JsonLdDocument } from "../src/kernel/transform.js";

const input: JsonLdDocument = {
  "@context": "https://schema.org",
  "@type": "Thing",
  "name": "Determinism Test",
  "description": "Input for verifying deterministic behavior",
};

let passed = 0;
let failed = 0;

// Test 1: Structural equality across invocations
try {
  const output1 = transform(input);
  const output2 = transform(input);
  deepStrictEqual(output1, output2);
  console.log("  \u2713 PASS: transform produces structurally identical output on repeated invocation");
  passed++;
} catch (error) {
  console.error("  \u2717 FAIL: transform produced structurally different output on repeated invocation");
  console.error(" ", error instanceof Error ? error.message : String(error));
  failed++;
}

// Test 2: Canonicalized string equality (catches key ordering differences)
try {
  const output1 = transform(input);
  const output2 = transform(input);
  const str1 = stableStringify(output1);
  const str2 = stableStringify(output2);
  strictEqual(str1, str2);
  console.log("  \u2713 PASS: canonicalized output strings are identical");
  passed++;
} catch (error) {
  console.error("  \u2717 FAIL: canonicalized output strings differ");
  console.error(" ", error instanceof Error ? error.message : String(error));
  failed++;
}

// Test 3: Input immutability
try {
  const freshInput: JsonLdDocument = {
    "@context": "https://schema.org",
    "@type": "Thing",
    "name": "Determinism Test",
    "description": "Input for verifying deterministic behavior",
  };
  transform(input);
  deepStrictEqual(input, freshInput);
  console.log("  \u2713 PASS: transform does not mutate input");
  passed++;
} catch (error) {
  console.error("  \u2717 FAIL: transform mutated the input object");
  console.error(" ", error instanceof Error ? error.message : String(error));
  failed++;
}

// Summary
console.log(`\n  ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
