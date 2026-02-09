// Site Validation Script
// Verifies index.html exists and has expected structure.
// Runs as: node scripts/test-site.js

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const INDEX_PATH = join(process.cwd(), 'index.html');

let failures = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    failures++;
  } else {
    console.log(`PASS: ${message}`);
  }
}

const html = await readFile(INDEX_PATH, 'utf-8');

// Structure checks
assert(html.includes('<!DOCTYPE html>'), 'Has DOCTYPE declaration');
assert(html.includes('<html lang="en">'), 'Has html element with lang attribute');
assert(html.includes('<meta charset="UTF-8">'), 'Has charset meta tag');
assert(html.includes('<meta name="viewport"'), 'Has viewport meta tag');
assert(html.includes('<title>'), 'Has title element');

// Content checks
assert(html.includes('HIRI'), 'Contains HIRI reference');
assert(html.includes('class="qa"'), 'Contains Q&A sections');
assert(html.includes('class="question"'), 'Contains question elements');
assert(html.includes('class="answer"'), 'Contains answer elements');

// Section checks
const sections = [
  'General Overview',
  'Architecture',
  'Privacy, Security, and Trust',
  'Knowledge',
  'Advanced Topics',
  'Business Value',
];
for (const section of sections) {
  assert(html.includes(section), `Contains "${section}" section`);
}

// Count Q&A pairs
const questionCount = (html.match(/class="question"/g) || []).length;
const answerCount = (html.match(/class="answer"/g) || []).length;
assert(questionCount === answerCount, `Questions (${questionCount}) match answers (${answerCount})`);
assert(questionCount >= 14, `Has at least 14 Q&A pairs (found ${questionCount})`);

// Accessibility basics
assert(html.includes('<header>'), 'Has semantic header element');
assert(html.includes('<main>'), 'Has semantic main element');
assert(html.includes('<footer>'), 'Has semantic footer element');

if (failures > 0) {
  console.error(`\nSite validation FAILED: ${failures} check(s) failed.`);
  process.exit(1);
} else {
  console.log(`\nSite validation PASSED: All checks passed.`);
}
