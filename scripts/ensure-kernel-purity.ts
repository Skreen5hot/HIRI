/**
 * Kernel Purity Check
 *
 * Static analysis script that scans compiled kernel files to ensure
 * they do not import from outside the kernel directory.
 *
 * This prevents accidental adapter, composition, or infrastructure
 * imports from leaking into the pure kernel layer.
 *
 * Run via: npm run test:purity
 */

import { readFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Compiled kernel files live at dist/kernel/ (from dist-tests perspective: ../dist/kernel/)
// But since we compile with tsconfig.test.json, kernel files are at dist-tests/src/kernel/
const kernelDir = join(__dirname, "..", "src", "kernel");

const FORBIDDEN_PATTERNS = [
  /from\s+["']\.\.\/(?!kernel)/,       // relative imports leaving kernel dir (but not ./kernel)
  /from\s+["']\.\.\/\.\.\//,           // imports going two levels up
  /from\s+["'].*\/adapters\//,          // explicit adapter imports
  /require\s*\(\s*["'](?!node:)/,       // CommonJS require (except node: builtins)
  /import\s+.*from\s+["'](?!\.\/|node:)/, // absolute imports (except relative and node: builtins)
];

let violations = 0;

async function checkFile(filePath: string): Promise<void> {
  const content = await readFile(filePath, "utf-8");
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of FORBIDDEN_PATTERNS) {
      if (pattern.test(line)) {
        console.error(`  \u2717 VIOLATION: ${filePath}:${i + 1}`);
        console.error(`    ${line.trim()}`);
        console.error(`    Pattern: ${pattern}`);
        violations++;
      }
    }
  }
}

async function main(): Promise<void> {
  console.log("Checking kernel purity...\n");

  let files: string[];
  try {
    const entries = await readdir(kernelDir);
    files = entries
      .filter((f) => f.endsWith(".js"))
      .map((f) => join(kernelDir, f));
  } catch {
    console.error(`  \u2717 FAIL: Could not read kernel directory: ${kernelDir}`);
    process.exit(1);
  }

  if (files.length === 0) {
    console.error("  \u2717 FAIL: No compiled kernel files found");
    process.exit(1);
  }

  for (const file of files) {
    await checkFile(file);
  }

  if (violations > 0) {
    console.error(`\n  \u2717 FAIL: ${violations} import violation(s) found in kernel`);
    process.exit(1);
  }

  console.log(`  \u2713 PASS: ${files.length} kernel file(s) checked, no import violations`);
}

await main();
