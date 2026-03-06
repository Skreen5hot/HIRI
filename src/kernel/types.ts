/**
 * HIRI Protocol Type Definitions
 *
 * All interfaces and types for the HIRI protocol kernel.
 * These define the contracts that adapter implementations must satisfy.
 *
 * This module is part of the kernel and MUST NOT import from
 * adapters, composition, or external packages.
 */

// ---------------------------------------------------------------------------
// Crypto Interfaces (implemented by adapters, injected into kernel functions)
// ---------------------------------------------------------------------------

/** A pluggable hash algorithm registered by prefix. */
export interface HashAlgorithm {
  readonly prefix: string; // e.g., "sha256"
  hash(content: Uint8Array): Promise<string>; // Returns "sha256:<hex-digest>"
  verify(content: Uint8Array, hash: string): Promise<boolean>;
}

/**
 * Provides all cryptographic operations needed by the kernel.
 * Implementations live in src/adapters/crypto/. The kernel never
 * imports crypto libraries directly.
 */
export interface CryptoProvider {
  hash(content: Uint8Array): Promise<string>;
  sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
  verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Key Types
// ---------------------------------------------------------------------------

/** An Ed25519 signing key with metadata. */
export interface SigningKey {
  algorithm: string; // e.g., "ed25519"
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  keyId: string; // Fragment identifier, e.g., "key-1"
}

// ---------------------------------------------------------------------------
// Signature Types
// ---------------------------------------------------------------------------

/** A spec-compliant signature block (HIRI Protocol §5.2). */
export interface HiriSignature {
  type: string; // e.g., "Ed25519Signature2020"
  canonicalization: string; // "JCS" | "URDNA2015"
  created: string; // ISO 8601
  verificationMethod: string; // HIRI URI to key, e.g., "hiri://key:ed25519:.../key/main#key-1"
  proofPurpose: string; // e.g., "assertionMethod"
  proofValue: string; // Multibase-encoded signature (z prefix + base58)
}

// ---------------------------------------------------------------------------
// Manifest Types
// ---------------------------------------------------------------------------

/** Timing metadata for a manifest. */
export interface ManifestTiming {
  created: string; // ISO 8601
  expires?: string; // ISO 8601, optional
}

/** Content reference within a manifest. */
export interface ManifestContent {
  hash: string; // e.g., "sha256:<hex-digest>"
  addressing: string; // "raw-sha256" | "cidv1-dag-cbor"
  format: string; // MIME type, e.g., "application/ld+json"
  size: number; // Byte count
  canonicalization: string; // "JCS" | "URDNA2015"
}

/** Chain link to previous manifest (absent for genesis). */
export interface ManifestChain {
  previous: string; // Hash of previous manifest
  previousBranch: string; // Branch of previous
  genesisHash: string; // Hash of first manifest in chain
  depth: number; // Distance from genesis
}

/** A resolution manifest without signature (pre-signing). */
export interface UnsignedManifest {
  "@context": Array<string>;
  "@id": string;
  "@type": string;
  "hiri:version": string;
  "hiri:branch": string;
  "hiri:timing": ManifestTiming;
  "hiri:content": ManifestContent;
  "hiri:chain"?: ManifestChain;
  "hiri:delta"?: ManifestDelta;
  "hiri:semantics"?: ManifestSemantics;
  [key: string]: unknown;
}

/** Semantic metadata for RDF indexing (Milestone 4). */
export interface ManifestSemantics {
  entailmentMode: EntailmentMode;
  baseRegime: string | null;
  vocabularies: string[];
}

/** A signed resolution manifest. */
export interface ResolutionManifest extends UnsignedManifest {
  "hiri:signature": HiriSignature;
}

// ---------------------------------------------------------------------------
// KeyDocument Types
// ---------------------------------------------------------------------------

/** A verification key entry in a KeyDocument. */
export interface VerificationKey {
  "@id": string;
  "@type": string; // "Ed25519VerificationKey2020"
  controller: string;
  publicKeyMultibase: string; // z prefix + base58-encoded public key
  purposes: string[];
  validFrom: string; // ISO 8601
  validUntil?: string; // ISO 8601, optional
}

/** A rotated key entry. */
export interface RotatedKey {
  "@id": string;
  rotatedAt: string;
  rotatedTo: string;
  reason: string;
  verifyUntil: string;
  publicKeyMultibase: string; // Key material for grace-period signature verification (M5)
  rotationProof?: RotationSignature[]; // Dual signatures for rotation authorization (M5)
}

/** A revoked key entry. */
export interface RevokedKey {
  "@id": string;
  revokedAt: string;
  reason: string;
  manifestsInvalidAfter: string;
  publicKeyMultibase: string; // Key material for pre-invalidation signature verification (M5)
}

/** Key lifecycle policies. */
export interface KeyPolicies {
  gracePeriodAfterRotation: string; // ISO 8601 duration, e.g., "P180D"
  minimumKeyValidity: string; // ISO 8601 duration, e.g., "P365D"
}

/** An unsigned KeyDocument (pre-signing). */
export interface UnsignedKeyDocument {
  "@context": Array<string>;
  "@id": string;
  "@type": string;
  "hiri:version": string;
  "hiri:authority": string;
  "hiri:authorityType": string;
  "hiri:activeKeys": VerificationKey[];
  "hiri:rotatedKeys": RotatedKey[];
  "hiri:revokedKeys": RevokedKey[];
  "hiri:policies": KeyPolicies;
  [key: string]: unknown;
}

/** A signed KeyDocument. */
export interface KeyDocument extends UnsignedKeyDocument {
  "hiri:signature": HiriSignature;
}

// ---------------------------------------------------------------------------
// Manifest Builder Params
// ---------------------------------------------------------------------------

/** Parameters for building an unsigned manifest. */
export interface ManifestParams {
  id: string;
  version: string;
  branch: string;
  created: string; // ISO 8601 timestamp (per ADR-003: caller provides)
  contentHash: string;
  addressing: string; // "raw-sha256" | "cidv1-dag-cbor"
  contentFormat: string;
  contentSize: number;
  canonicalization: string;
  chain?: ManifestChain;
  delta?: ManifestDelta;
  semantics?: ManifestSemantics;
}

/** Parameters for building an unsigned KeyDocument. */
export interface KeyDocumentParams {
  authority: string;
  authorityType: string;
  version: string;
  activeKeys: VerificationKey[];
  rotatedKeys?: RotatedKey[];
  revokedKeys?: RevokedKey[];
  policies: KeyPolicies;
}

// ---------------------------------------------------------------------------
// Delta Types (Milestone 2)
// ---------------------------------------------------------------------------

/** A single RFC 6902 JSON Patch operation. */
export interface JsonPatchOperation {
  op: "add" | "remove" | "replace";
  path: string;
  value?: unknown;
  from?: string;
}

/** Delta metadata embedded in a manifest. */
export interface ManifestDelta {
  hash: string; // Hash of the canonicalized delta operations
  format: string; // "application/json-patch+json" | "application/rdf-patch"
  appliesTo: string; // Hash of the previous content this delta applies to
  operations: number; // Count of patch operations
}

// ---------------------------------------------------------------------------
// Validation Types
// ---------------------------------------------------------------------------

/** Result of genesis validation. */
export interface GenesisValidation {
  valid: boolean;
  reason?: string;
}

/** Result of chain link validation. */
export interface ChainValidation {
  valid: boolean;
  reason?: string;
}

/** Result of a full chain walk from head to genesis. */
export interface ChainWalkResult {
  valid: boolean;
  depth: number;
  reason?: string;
  warnings: string[];
  failures?: Array<ChainFailure>; // Per-manifest failure details (M5)
}

/** A single failure point in a chain walk (Milestone 5). */
export interface ChainFailure {
  version: string;
  keyId: string;
  keyStatus: KeyStatus;
  reason: string;
}

// ---------------------------------------------------------------------------
// Chain Walker I/O Types (injected, not imported)
// ---------------------------------------------------------------------------

/** Fetches a manifest by its hash. Implemented by adapters, injected into kernel. */
export type ManifestFetcher = (hash: string) => Promise<ResolutionManifest | null>;

/** Fetches raw content bytes by hash. Implemented by adapters, injected into kernel. */
export type ContentFetcher = (hash: string) => Promise<Uint8Array | null>;

// ---------------------------------------------------------------------------
// Storage Interface (Milestone 3)
// ---------------------------------------------------------------------------

/**
 * Content-addressed storage adapter.
 *
 * Minimal interface for the resolver: get bytes by hash, check existence.
 * No indexing, no queries — those belong in a separate ManifestIndex interface.
 *
 * Contract: get(hash) makes NO hash verification guarantee.
 * Callers MUST verify that the returned bytes actually hash to the expected value.
 */
export interface StorageAdapter {
  get(hash: string): Promise<Uint8Array | null>;
  has(hash: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// RDF Index & Query Interfaces (Milestone 4)
// ---------------------------------------------------------------------------

/** Entailment mode declared in manifest semantics. */
export type EntailmentMode = "none" | "materialized" | "runtime";

/**
 * An in-memory RDF index built from verified content.
 * Implementations live in src/adapters/rdf/. The kernel never
 * imports RDF libraries directly.
 */
export interface RDFIndex {
  load(content: Uint8Array, format: string, baseURI: string): Promise<void>;
  tripleCount(): number;
}

/**
 * Executes SPARQL queries against an RDFIndex.
 * Implementations live in src/adapters/rdf/.
 */
export interface SPARQLEngine {
  query(sparql: string, index: RDFIndex): Promise<QueryResult>;
}

/** Result of a SPARQL SELECT query. */
export interface QueryResult {
  bindings: Array<Record<string, RDFTerm>>;
  truncated: boolean;
}

/** A single RDF term in a query result binding. */
export interface RDFTerm {
  type: "uri" | "literal" | "bnode";
  value: string;
  datatype?: string;
  language?: string;
}

/** Configuration for the graph builder. */
export interface GraphBuilderConfig {
  entailmentMode: EntailmentMode;
}

// ---------------------------------------------------------------------------
// Key Lifecycle Types (Milestone 5)
// ---------------------------------------------------------------------------

/** Key status in the lifecycle (active → rotated → expired / revoked). */
export type KeyStatus = "active" | "rotated-grace" | "rotated-expired" | "revoked" | "unknown";

/** Result of key lifecycle verification for a single manifest. */
export interface KeyVerificationResult {
  valid: boolean;
  keyStatus: KeyStatus;
  keyId: string;
  warning?: string;
  revocationStatus: "confirmed-valid" | "confirmed-revoked" | "unknown";
  timestampVerification: "tsa-verified" | "tsa-present-unverified" | "advisory-only" | "absent";
}

export interface VerificationStatus {
  signatureValid: boolean;
  keyStatus: KeyStatus;
  revocationStatus: "confirmed-valid" | "confirmed-revoked" | "unknown";
  timestampVerification: "tsa-verified" | "tsa-present-unverified" | "advisory-only" | "absent";
}

/** A signature within a rotation proof (dual-signature authorization). */
export interface RotationSignature {
  purpose: string; // "old-key-authorizes-rotation" | "new-key-confirms-rotation"
  verificationMethod: string; // HIRI URI to key
  proofValue: string; // Multibase-encoded signature
}

/** The canonical fact attested by rotation proof signatures. */
export interface RotationClaim {
  oldKeyId: string;
  newKeyId: string;
  rotatedAt: string;
  reason: string;
}
