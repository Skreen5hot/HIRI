/**
 * In-Memory Storage Adapter
 *
 * Content-addressed storage backed by a Map<string, Uint8Array>.
 * Implements the StorageAdapter interface for testing and lightweight usage.
 *
 * The `put` method is NOT on the StorageAdapter interface — publishing
 * is a separate concern from resolution.
 */

import type { StorageAdapter } from "../../kernel/types.js";

export class InMemoryStorageAdapter implements StorageAdapter {
  private store = new Map<string, Uint8Array>();

  async get(hash: string): Promise<Uint8Array | null> {
    return this.store.get(hash) ?? null;
  }

  async has(hash: string): Promise<boolean> {
    return this.store.has(hash);
  }

  /** Store bytes by hash. NOT on the StorageAdapter interface. */
  async put(hash: string, bytes: Uint8Array): Promise<void> {
    this.store.set(hash, bytes);
  }

  /** Clear all stored data. For testing. */
  clear(): void {
    this.store.clear();
  }
}
