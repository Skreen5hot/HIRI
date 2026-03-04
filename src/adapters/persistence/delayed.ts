/**
 * Delayed Storage Adapter
 *
 * Wraps any StorageAdapter with a configurable async delay.
 * Proves that the resolver produces identical results regardless of timing.
 */

import type { StorageAdapter } from "../../kernel/types.js";

export class DelayedAdapter implements StorageAdapter {
  constructor(
    private inner: StorageAdapter,
    private delayMs: number,
  ) {}

  async get(hash: string): Promise<Uint8Array | null> {
    await this.delay();
    return this.inner.get(hash);
  }

  async has(hash: string): Promise<boolean> {
    await this.delay();
    return this.inner.has(hash);
  }

  private delay(): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, this.delayMs));
  }
}
