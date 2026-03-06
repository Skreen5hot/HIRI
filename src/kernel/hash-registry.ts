/**
 * Hash Algorithm Registry
 *
 * Dispatches hashing and verification to registered HashAlgorithm
 * implementations based on the prefix in a prefixed hash string
 * (e.g., "sha256:<hex-digest>").
 *
 * The registry itself is pure — it holds injected implementations
 * and dispatches to them. No crypto logic lives here.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import type { HashAlgorithm } from "./types.js";

export class HashRegistry {
  private algos = new Map<string, HashAlgorithm>();

  /**
   * Register a hash algorithm implementation.
   */
  register(algo: HashAlgorithm): void {
    this.algos.set(algo.prefix, algo);
  }

  /**
   * Resolve a hash algorithm from a prefixed hash string.
   *
   * @param prefixedHash - A string in the format "<prefix>:<digest>"
   * @returns The registered HashAlgorithm for the prefix
   * @throws Error if no algorithm is registered for the prefix
   */
  resolve(prefixedHash: string): HashAlgorithm {
    // CIDv1 base32lower strings start with 'b' and have no colon
    const colonIndex = prefixedHash.indexOf(":");
    if (colonIndex === -1 && prefixedHash.startsWith("b")) {
      const algo = this.algos.get("cidv1");
      if (algo) return algo;
    }
    const prefix = colonIndex === -1 ? prefixedHash : prefixedHash.substring(0, colonIndex);
    const algo = this.algos.get(prefix);
    if (!algo) {
      throw new Error(`Unsupported hash algorithm: ${prefix}`);
    }
    return algo;
  }

  /**
   * Hash content using a registered algorithm.
   *
   * @param content - The bytes to hash
   * @param prefix - Algorithm prefix (default: "sha256")
   * @returns Prefixed hash string, e.g., "sha256:<hex-digest>"
   * @throws Error if the algorithm is not registered
   */
  async hash(content: Uint8Array, prefix: string = "sha256"): Promise<string> {
    const algo = this.algos.get(prefix);
    if (!algo) {
      throw new Error(`Algorithm ${prefix} not registered`);
    }
    return algo.hash(content);
  }

  /**
   * Verify content against a prefixed hash string.
   * Parses the prefix, dispatches to the correct algorithm's verify.
   *
   * @param content - The bytes to verify
   * @param prefixedHash - The expected hash, e.g., "sha256:<hex-digest>"
   * @returns true if the content matches the hash
   * @throws Error if the algorithm is not registered
   */
  async verify(content: Uint8Array, prefixedHash: string): Promise<boolean> {
    const algo = this.resolve(prefixedHash);
    return algo.verify(content, prefixedHash);
  }
}
