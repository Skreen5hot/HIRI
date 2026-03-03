/**
 * Test Runner
 *
 * Discovers and runs all *.test.js files in the tests directory.
 * Each test file runs in its own process for isolation.
 * Produces JSON reports for CI integration.
 *
 * Usage: node dist-tests/tests/run-tests.js [--write-json] [--json]
 */

import { spawn } from "node:child_process";
import { readdir, writeFile } from "node:fs/promises";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface TestResult {
  file: string;
  passed: boolean;
  duration: number;
  testsPassed: number;
  testsFailed: number;
}

async function findTestFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (
      entry.isFile() &&
      entry.name.endsWith(".test.js") &&
      entry.name !== "run-tests.js"
    ) {
      files.push(join(dir, entry.name));
    }
  }
  return files.sort();
}

function runTest(file: string): Promise<TestResult> {
  return new Promise((res) => {
    const startTime = Date.now();
    const child = spawn("node", [file], { stdio: "pipe" });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data: Buffer) => {
      const text = data.toString();
      stdout += text;
      process.stdout.write(text);
    });

    child.stderr.on("data", (data: Buffer) => {
      const text = data.toString();
      stderr += text;
      process.stderr.write(text);
    });

    child.on("close", (code) => {
      const duration = Date.now() - startTime;
      const passMatches = stdout.match(/\u2713 PASS:/g);
      const failMatches = (stdout + stderr).match(/\u2717 FAIL:/g);

      res({
        file: file.replace(__dirname, "").replace(/\\/g, "/"),
        passed: code === 0,
        duration,
        testsPassed: passMatches ? passMatches.length : 0,
        testsFailed: failMatches ? failMatches.length : 0,
      });
    });
  });
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const writeJson = args.includes("--write-json") || args.includes("--json");

  console.log("\n=== JSON-LD Deterministic Service Template - Spec Tests ===\n");

  const testFiles = await findTestFiles(__dirname);

  if (testFiles.length === 0) {
    console.error("No test files found.");
    process.exit(1);
  }

  const results: TestResult[] = [];

  // Run sequentially for deterministic output ordering
  for (const file of testFiles) {
    const shortName = file.replace(__dirname, "").replace(/\\/g, "/");
    console.log(`--- ${shortName} ---`);
    const result = await runTest(file);
    results.push(result);
    console.log("");
  }

  // Summary
  const totalPassed = results.filter((r) => r.passed).length;
  const totalFailed = results.filter((r) => !r.passed).length;
  const totalTests = results.reduce((sum, r) => sum + r.testsPassed + r.testsFailed, 0);
  const totalTestsPassed = results.reduce((sum, r) => sum + r.testsPassed, 0);

  console.log("=== Summary ===");
  for (const r of results) {
    const status = r.passed ? "PASSED" : "FAILED";
    console.log(`  ${status}: ${r.file} (${r.duration}ms)`);
  }
  console.log(`\n  Files: ${totalPassed}/${results.length} passed`);
  console.log(`  Tests: ${totalTestsPassed}/${totalTests} passed`);

  if (writeJson) {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        totalFiles: results.length,
        filesPassed: totalPassed,
        filesFailed: totalFailed,
        totalTests,
        testsPassed: totalTestsPassed,
      },
      results,
    };
    const reportPath = resolve(__dirname, "..", "..", "unit-test-results.json");
    await writeFile(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n  JSON report written to: unit-test-results.json`);
  }

  if (totalFailed > 0) {
    process.exit(1);
  }
}

main();
