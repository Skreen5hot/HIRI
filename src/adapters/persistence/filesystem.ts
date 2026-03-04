/**
 * File System Storage Adapter
 *
 * Content-addressed storage backed by a directory of hash-named files.
 * Implements the StorageAdapter interface.
 *
 * File naming: colons in hashes are replaced with dashes.
 * e.g., "sha256:abc123" → "sha256-abc123"
 */

import { readFile, access, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import type { StorageAdapter } from "../../kernel/types.js";

export class FileSystemAdapter implements StorageAdapter {
  constructor(private basePath: string) {}

  async get(hash: string): Promise<Uint8Array | null> {
    const filePath = this.hashToPath(hash);
    try {
      const buffer = await readFile(filePath);
      // Convert Node.js Buffer to plain Uint8Array for cross-environment consistency
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } catch (e: unknown) {
      if (isNodeError(e) && e.code === "ENOENT") {
        return null;
      }
      throw e;
    }
  }

  async has(hash: string): Promise<boolean> {
    const filePath = this.hashToPath(hash);
    try {
      await access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  private hashToPath(hash: string): string {
    const filename = hash.replace(/:/g, "-");
    return join(this.basePath, filename);
  }

  /**
   * Write content to a hash-named file. For test setup.
   * NOT on the StorageAdapter interface.
   */
  static async writeContent(
    basePath: string,
    hash: string,
    bytes: Uint8Array,
  ): Promise<void> {
    const filename = hash.replace(/:/g, "-");
    const filePath = join(basePath, filename);
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, bytes);
  }
}

function isNodeError(e: unknown): e is NodeJS.ErrnoException {
  return e instanceof Error && "code" in e;
}
