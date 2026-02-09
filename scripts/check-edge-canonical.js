// Edge-Canonical Compliance Checker
// Ensures src/core/ contains no Node.js-specific imports.
// Runs as: node scripts/check-edge-canonical.js

import { readdir, readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';

const FORBIDDEN_MODULES = [
  'node:fs', 'node:path', 'node:http', 'node:https', 'node:net',
  'node:child_process', 'node:os', 'node:stream', 'node:worker_threads',
  'node:cluster', 'node:dgram', 'node:dns', 'node:readline', 'node:tls',
  "'fs'", "'path'", "'http'", "'https'", "'net'",
  "'child_process'", "'os'", "'stream'",
  '"fs"', '"path"', '"http"', '"https"', '"net"',
  '"child_process"', '"os"', '"stream"',
];

const CORE_DIR = join(process.cwd(), 'src', 'core');

async function* walkDir(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkDir(fullPath);
    } else if (extname(entry.name) === '.ts' || extname(entry.name) === '.js') {
      yield fullPath;
    }
  }
}

let violations = 0;

try {
  for await (const filePath of walkDir(CORE_DIR)) {
    const content = await readFile(filePath, 'utf-8');
    for (const forbidden of FORBIDDEN_MODULES) {
      if (content.includes(forbidden)) {
        console.error(`VIOLATION: ${filePath} imports forbidden module: ${forbidden}`);
        violations++;
      }
    }
  }
} catch (err) {
  if (err.code === 'ENOENT') {
    console.log('src/core/ does not exist yet. Edge-canonical check skipped.');
    process.exit(0);
  }
  throw err;
}

if (violations > 0) {
  console.error(`\nEdge-canonical check FAILED: ${violations} violation(s) found.`);
  console.error('Core modules must not import Node.js built-in modules.');
  console.error('Move infrastructure code to src/adapters/.');
  process.exit(1);
} else {
  console.log('Edge-canonical check PASSED.');
}
