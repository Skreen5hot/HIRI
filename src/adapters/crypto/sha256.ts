/**
 * SHA-256 Hash Algorithm Adapter
 *
 * Implements the HashAlgorithm interface using the Web Crypto API
 * (crypto.subtle.digest). Available in both Node.js (≥15) and browsers.
 *
 * This is an adapter (Layer 2) and MAY import from the kernel.
 */

import type { HashAlgorithm } from "../../kernel/types.js";

export class SHA256Algorithm implements HashAlgorithm {
  readonly prefix = "sha256";

  async hash(content: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", content);
    const hex = bytesToHex(new Uint8Array(digest));
    return `${this.prefix}:${hex}`;
  }

  async verify(content: Uint8Array, hash: string): Promise<boolean> {
    const actual = await this.hash(content);
    return actual === hash;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}
