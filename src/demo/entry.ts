/**
 * Browser Demo Entry Point
 *
 * Explicit, minimal re-exports of kernel + adapter functions
 * needed by the demo UI. Tree-shakeable by esbuild.
 * Does NOT re-export Node.js-only modules (filesystem adapter, CLI entry).
 */

// Identity
export { generateKeypair } from "../adapters/crypto/ed25519.js";
export { deriveAuthority, extractPublicKey } from "../kernel/authority.js";
export {
  buildKeyDocument,
  buildUnsignedManifest,
  prepareContent,
} from "../kernel/manifest.js";
export {
  signManifest,
  signKeyDocument,
  verifyManifest,
  verifyKeyDocument,
} from "../kernel/signing.js";

// Chain & Delta
export {
  hashManifest,
  validateChainLink,
  verifyChain,
  verifyChainWithKeyLifecycle,
} from "../kernel/chain.js";
export { buildDelta, buildRDFDelta, verifyDelta } from "../kernel/delta.js";
export { applyPatch } from "../kernel/json-patch.js";
export { parseNQuads, serializeNQuads, applyRDFPatch } from "../kernel/rdf-patch.js";
export { validateGenesis } from "../kernel/genesis.js";

// Resolution
export { resolve, ResolutionError } from "../kernel/resolve.js";
export { InMemoryStorageAdapter } from "../adapters/persistence/storage.js";
export { DelayedAdapter } from "../adapters/persistence/delayed.js";

// Query
export {
  buildGraph,
  resolveEntailmentMode,
} from "../kernel/graph-builder.js";
export { executeQuery } from "../kernel/query-executor.js";
export { OxigraphRDFStore } from "../adapters/rdf/oxigraph-store.js";

// Key Lifecycle
export {
  resolveSigningKey,
  verifyManifestWithKeyLifecycle,
  verifyRotationProof,
} from "../kernel/key-lifecycle.js";
export {
  parseDuration,
  addDuration,
  compareTimestamps,
} from "../kernel/temporal.js";

// Utilities
export { stableStringify } from "../kernel/canonicalize.js";
export { JCSCanonicalizer } from "../kernel/jcs-canonicalizer.js";
export { URDNA2015Canonicalizer } from "../adapters/canonicalization/urdna2015-canonicalizer.js";
export { CIDv1Algorithm } from "../adapters/content-addressing/cidv1-algorithm.js";
export {
  createSecureDocumentLoader,
  createCatalogDocumentLoader,
} from "../adapters/canonicalization/secure-document-loader.js";
export { HiriURI } from "../kernel/hiri-uri.js";
export { HashRegistry } from "../kernel/hash-registry.js";
export { defaultCryptoProvider } from "../adapters/crypto/provider.js";
export {
  encode as base58Encode,
  decode as base58Decode,
} from "../kernel/base58.js";

// Re-export key types for TypeScript consumers
export type {
  SigningKey,
  CryptoProvider,
  ResolutionManifest,
  UnsignedManifest,
  KeyDocument,
  UnsignedKeyDocument,
  KeyDocumentParams,
  ManifestParams,
  StorageAdapter,
  ChainWalkResult,
  KeyStatus,
  KeyVerificationResult,
  QueryResult,
  RDFTerm,
  VerificationKey,
  RotatedKey,
  RevokedKey,
  KeyPolicies,
  JsonPatchOperation,
  RDFPatchOperation,
  EntailmentMode,
  Canonicalizer,
  DocumentLoader,
  ManifestDelta,
} from "../kernel/types.js";

export type {
  ResolveOptions,
  VerifiedContent,
  ResolutionErrorCode,
} from "../kernel/resolve.js";

// Privacy — Resolution
export { resolveWithPrivacy } from "../privacy/resolve.js";
export type { PrivacyResolveOptions } from "../privacy/resolve.js";
export { getPrivacyMode, isKnownPrivacyMode } from "../privacy/privacy-mode.js";

// Privacy — Proof of Possession (Mode 1)
export { isCustodyStale } from "../privacy/proof-of-possession.js";

// Privacy — Encrypted Distribution (Mode 2)
export { encryptContent } from "../privacy/encryption.js";
export { decryptContent } from "../privacy/decryption.js";
export { buildEncryptedManifest } from "../privacy/encrypted-manifest.js";

// Privacy — Selective Disclosure (Mode 3)
export { buildSelectiveDisclosureManifest } from "../privacy/selective-manifest.js";
export {
  buildStatementIndex,
  verifyStatementInIndex,
  verifyIndexRoot,
} from "../privacy/statement-index.js";
export {
  generateHmacTags,
  verifyHmacTag,
  decryptHmacKey,
  encryptHmacKeyForRecipients,
} from "../privacy/hmac-disclosure.js";

// Privacy — Anonymous Publication (Mode 4)
export {
  generateEphemeralAuthority,
  buildAnonymousPrivacyBlock,
} from "../privacy/anonymous.js";

// Privacy — Attestation (Mode 5)
export {
  buildAttestationManifest,
  verifyAttestation,
  validateAttestationManifest,
} from "../privacy/attestation.js";

// Privacy — Chain Walking (§11)
export { verifyPrivacyChain } from "../privacy/chain-walker.js";

// Privacy types
export type {
  PrivacyMode,
  PrivacyBlock,
  PrivacyAwareVerificationResult,
  EncryptedPrivacyParams,
  SelectiveDisclosureParams,
  SelectiveDisclosureContent,
  AnonymousParams,
  AttestationSubject,
  AttestationClaim,
  AttestationEvidence,
  AttestationVerificationResult,
} from "../privacy/types.js";

// Crypto adapters — X25519 key agreement
export { generateX25519Keypair } from "../adapters/crypto/x25519.js";
export {
  ed25519PublicToX25519,
  ed25519PrivateToX25519,
} from "../adapters/crypto/key-conversion.js";

// Demo tab modules
export { initKeysTab } from "./tab-keys.js";
export { initBuildTab } from "./tab-build.js";
export { initQueryTab } from "./tab-query.js";
export { initResolveTab } from "./tab-resolve.js";
export { initPrivacyTab } from "./tab-privacy.js";
export { demoState } from "./state.js";
export { loadPreset } from "./presets.js";
