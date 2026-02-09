// Clean build artifacts
// Runs as: node scripts/clean.js

import { rm } from 'node:fs/promises';
import { join } from 'node:path';

const dirs = ['dist', 'coverage', 'test-results', 'playwright-report'];

for (const dir of dirs) {
  await rm(join(process.cwd(), dir), { recursive: true, force: true });
}

console.log('Clean complete.');
