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

// Demo tab modules
export { initKeysTab } from "./tab-keys.js";
export { initBuildTab } from "./tab-build.js";
export { initQueryTab } from "./tab-query.js";
export { initResolveTab } from "./tab-resolve.js";
export { demoState } from "./state.js";
export { loadPreset } from "./presets.js";
