/**
 * CIDv1 Content Addressing Algorithm (§8.2)
 *
 * Wraps content in a dag-cbor envelope, hashes with SHA-256,
 * and produces a CIDv1 as a base32lower multibase string.
 *
 * The algorithm is profile-bound: the CBOR envelope includes
 * the canonicalization profile name, so different profiles
 * produce different CIDs for the same content bytes.
 */

import * as dagCbor from "@ipld/dag-cbor";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { base32 } from "multiformats/bases/base32";
import type { HashAlgorithm } from "../../kernel/types.js";

/** dag-cbor codec code */
const DAG_CBOR_CODEC = 0x71;

export class CIDv1Algorithm implements HashAlgorithm {
  readonly prefix = "cidv1";
  private profile: string;

  /**
   * @param profile - Canonicalization profile (e.g., "URDNA2015", "JCS")
   *                  included in the CBOR envelope to make the CID profile-bound.
   */
  constructor(profile: string) {
    this.profile = profile;
  }

  /**
   * Hash content bytes to a CIDv1 base32lower string.
   *
   * Steps (§8.2):
   * 1. Construct CBOR envelope with profile metadata
   * 2. Encode as deterministic dag-cbor bytes
   * 3. SHA-256 multihash
   * 4. Construct CIDv1 (version=1, codec=dag-cbor 0x71, hash=sha2-256)
   * 5. Return base32lower string (prefix 'b')
   */
  async hash(content: Uint8Array): Promise<string> {
    const cborBytes = this.buildEnvelope(content);
    const multihash = await sha256.digest(cborBytes);
    const cid = CID.createV1(DAG_CBOR_CODEC, multihash);
    return cid.toString(base32);
  }

  /**
   * Verify content bytes against a CID string.
   * Re-hashes and compares.
   */
  async verify(content: Uint8Array, cidString: string): Promise<boolean> {
    const computed = await this.hash(content);
    return computed === cidString;
  }

  /**
   * Build the dag-cbor envelope and encode to bytes.
   */
  private buildEnvelope(content: Uint8Array): Uint8Array {
    const envelope = {
      "@type": "hiri:CanonicalContent",
      "hiri:canonicalization": this.profile,
      "hiri:content": content,
    };
    return dagCbor.encode(envelope);
  }
}
