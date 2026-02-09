import { describe, it, expect } from 'vitest';

describe('HIRI Protocol - Smoke Test', () => {
  it('should verify test infrastructure is working', () => {
    expect(1 + 1).toBe(2);
  });

  it('should confirm ESM module support', async () => {
    const module = await import('../../src/core/index.js');
    expect(module).toBeDefined();
  });

  it('should confirm Web Crypto API is available', () => {
    expect(globalThis.crypto).toBeDefined();
    expect(globalThis.crypto.subtle).toBeDefined();
    expect(typeof globalThis.crypto.subtle.digest).toBe('function');
  });
});
