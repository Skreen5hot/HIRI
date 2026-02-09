import { describe, it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

describe('Site - index.html', () => {
  let html: string;

  // Load once before all tests
  it('should exist and be readable', async () => {
    html = await readFile(join(process.cwd(), 'index.html'), 'utf-8');
    expect(html).toBeDefined();
    expect(html.length).toBeGreaterThan(0);
  });

  it('should have valid HTML5 document structure', async () => {
    html ??= await readFile(join(process.cwd(), 'index.html'), 'utf-8');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('<meta charset="UTF-8">');
    expect(html).toContain('<meta name="viewport"');
    expect(html).toContain('<title>');
    expect(html).toContain('</html>');
  });

  it('should have semantic landmark elements', async () => {
    html ??= await readFile(join(process.cwd(), 'index.html'), 'utf-8');
    expect(html).toContain('<header>');
    expect(html).toContain('<main>');
    expect(html).toContain('<footer>');
  });

  it('should contain all Q&A sections', async () => {
    html ??= await readFile(join(process.cwd(), 'index.html'), 'utf-8');
    const sections = [
      'General Overview',
      'Architecture',
      'Privacy, Security, and Trust',
      'Knowledge',
      'Advanced Topics',
      'Business Value',
    ];
    for (const section of sections) {
      expect(html).toContain(section);
    }
  });

  it('should have matching question/answer pairs', async () => {
    html ??= await readFile(join(process.cwd(), 'index.html'), 'utf-8');
    const questions = (html.match(/class="question"/g) || []).length;
    const answers = (html.match(/class="answer"/g) || []).length;
    expect(questions).toBe(answers);
    expect(questions).toBeGreaterThanOrEqual(14);
  });

  it('should have responsive viewport meta tag', async () => {
    html ??= await readFile(join(process.cwd(), 'index.html'), 'utf-8');
    expect(html).toContain('width=device-width');
  });
});
