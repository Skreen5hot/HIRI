/**
 * Snapshot Test
 *
 * Verifies that transform(examples/input.jsonld) produces output
 * that matches examples/expected-output.jsonld when compared using
 * canonicalized serialization.
 *
 * This is Spec Test #3 from ARCHITECTURE.md.
 */

import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { strictEqual } from "node:assert";
import { transform } from "../src/kernel/transform.js";
import { stableStringify } from "../src/kernel/canonicalize.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Resolve paths relative to project root (tests/ is one level down from dist-tests/tests/)
const projectRoot = resolve(__dirname, "..", "..");
const inputPath = resolve(projectRoot, "examples", "input.jsonld");
const expectedPath = resolve(projectRoot, "examples", "expected-output.jsonld");

let passed = 0;
let failed = 0;

async function main(): Promise<void> {
  const inputRaw = await readFile(inputPath, "utf-8");
  const expectedRaw = await readFile(expectedPath, "utf-8");

  const input = JSON.parse(inputRaw);
  const expected = JSON.parse(expectedRaw);
  const actual = transform(input);

  // Compare using canonicalized serialization
  const actualStr = stableStringify(actual, true);
  const expectedStr = stableStringify(expected, true);

  try {
    strictEqual(actualStr, expectedStr);
    console.log("  \u2713 PASS: transform output matches expected-output.jsonld (canonicalized comparison)");
    passed++;
  } catch (error) {
    console.error("  \u2717 FAIL: transform output does not match expected-output.jsonld");
    console.error("\n  Expected:\n" + expectedStr);
    console.error("\n  Actual:\n" + actualStr);
    failed++;
  }
}

await main();

// Summary
console.log(`\n  ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
