/**
 * CLI Entry Point
 *
 * Reads a JSON-LD file from the command line, invokes the kernel transform,
 * and writes the canonicalized result to stdout.
 *
 * Usage: node dist/kernel/index.js <input-file.jsonld>
 *
 * This file is the ONLY place where I/O occurs. The transform function
 * itself is pure and deterministic.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { transform } from "./transform.js";
import { stableStringify } from "./canonicalize.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    process.stderr.write(
      "Usage: node dist/kernel/index.js <input-file.jsonld>\n"
    );
    process.exit(1);
  }

  const inputPath = resolve(args[0]);

  try {
    const raw = await readFile(inputPath, "utf-8");
    const input: unknown = JSON.parse(raw);
    const output = transform(input);
    process.stdout.write(stableStringify(output, true) + "\n");
  } catch (error) {
    if (error instanceof SyntaxError) {
      process.stderr.write(`Invalid JSON in input file: ${error.message}\n`);
    } else if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      process.stderr.write(`File not found: ${inputPath}\n`);
    } else {
      process.stderr.write(
        `Error: ${error instanceof Error ? error.message : String(error)}\n`
      );
    }
    process.exit(1);
  }
}

main();
