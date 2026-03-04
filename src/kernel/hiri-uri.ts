/**
 * HIRI URI Parser and Builder
 *
 * Strict URI handling for the HIRI protocol.
 * Pattern: hiri://<authority>/<type>/<identifier>
 *
 * Authority may contain colons (e.g., "key:ed25519:abc123"),
 * so parsing uses the first slash after the scheme to delimit components.
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

const SCHEME = "hiri://";

// Matches: hiri://<authority>/<type>/<identifier>
// Authority is greedy up to the first slash that starts the type segment.
// We split on '/' after stripping the scheme, taking the last two segments
// as type and identifier, and everything before as authority.
const HIRI_PATTERN = /^hiri:\/\/([^/]+)\/([^/]+)\/(.+)$/;

export class HiriURI {
  constructor(
    public readonly authority: string,
    public readonly type: string,
    public readonly identifier: string,
  ) {}

  /**
   * Parse a HIRI URI string into its components.
   *
   * @param uri - A string in the format hiri://<authority>/<type>/<identifier>
   * @returns A HiriURI instance
   * @throws Error if the URI does not match the expected pattern
   */
  static parse(uri: string): HiriURI {
    const match = uri.match(HIRI_PATTERN);
    if (!match) {
      throw new Error(`Invalid HIRI URI: ${uri}`);
    }
    return new HiriURI(match[1], match[2], match[3]);
  }

  /**
   * Build a HIRI URI from components.
   */
  static build(authority: string, type: string, identifier: string): HiriURI {
    return new HiriURI(authority, type, identifier);
  }

  /**
   * Serialize to the canonical URI string.
   */
  toString(): string {
    return `${SCHEME}${this.authority}/${this.type}/${this.identifier}`;
  }
}
