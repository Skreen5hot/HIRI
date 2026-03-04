# HIRI MVP Milestones v1.4
## Milestones 3–5 and Integration: Execution Detail

**Version:** 1.4  
**Previous:** 1.3 (M1 execution detail), 1.2 (governing roadmap — not previously committed to repo)  
**Last Updated:** March 2026  
**Governing Spec:** HIRI Protocol Specification v2.1.0

---

## Preamble: Why This Document Exists

v1.2 was accepted as the governing roadmap but was never committed to the repository. v1.3 provided execution detail for Milestone 1 and stated: "All v1.2 content (Milestones 2–5, Integration, Dependency Graph, Deferred Capabilities, Success Criteria) remains unchanged and is not reproduced here." This left the developers working from an addendum that points to a document they don't have.

v1.4 resolves this. It contains the complete, authoritative specification for Milestones 3, 4, 5, and Integration — including test matrices, execution sequences, fixture definitions, and interface contracts. It also reconciles the actual implementation state (persistence infrastructure already built as "Phase 3") with the governing milestone definitions.

After this document, the developers have everything needed to complete the MVP. No more ghost references.

---

## Current Implementation State

Before specifying what remains, here is what exists:

| Phase | Milestone | Status | Tests | Key Artifacts |
|-------|-----------|--------|-------|---------------|
| Phase 1 | M1: Verifiable Atom | **Complete** | 21/21 | Keypair, authority, manifest, signing, verification, genesis |
| Phase 2 | M2: Deterministic Chain | **Complete** | 18/18 | Chain walker, delta verification, JSON Patch |
| Phase 2.5 | Persistence Infrastructure | **Complete** | 27/27 | StorageAdapter, ManifestTracker, KeyPinStore, BigInt versions |
| — | M3: Abstracted Resolver | **Not started** | 0 | No resolver function, no FileSystemAdapter, no DelayedAdapter |
| — | M4: Storeless Oracle | **Not started** | 0 | No RDF index, no SPARQL engine, no entailment enforcement |
| — | M5: Sovereign Authority | **Not started** | 0 | No key rotation, no temporal verification, no retroactive revocation |
| — | Integration: Browser Reader | **Not started** | 0 | — |

**Total existing tests:** 66 (39 milestone + 27 infrastructure)

The Phase 2.5 persistence work built `InMemoryStorageAdapter`, `ManifestTracker`, `InMemoryKeyPinStore`, and BigInt version handling. These are consumed by later milestones but are not themselves a governing milestone. The `StorageAdapter` interface the developers built has seven methods (including indexing); M3 requires only the two-method content-addressed core. This distinction is addressed in M3 below.

---

## Addressing the Layer Question

The developers correctly note that the HIRI Protocol Spec defines **Layer 3: Storeless Index** (§7) and **Layer 4: Query & Verification** (§8) as separate architectural layers. The question is whether these should be separate milestones.

**Answer: No.** The layer separation is an architectural concern (how the system is structured), not a milestone concern (what we need to prove works). The Storeless Index exists to be queried. You cannot test the index without querying it, and you cannot test the query engine without an index. A milestone that builds an index with no query tests would prove nothing beyond "JSON-LD was parsed" — the real validation is always "does the SPARQL query return correct results from verified content."

Milestone 4 therefore covers both layers as a single deliverable: **load verified content into a local RDF index and query it with SPARQL, respecting the manifest's declared entailment mode.** This is the "Storeless Oracle" — a client-side query capability with no graph server.

The Layer 3 / Layer 4 boundary is respected *internally* — the index-building code and the query-execution code should be separate modules. But they are tested together because neither is meaningful in isolation.

---

## Milestone 3: The Abstracted Resolver

### Objective

Implement the HIRI-URI resolution logic (Protocol Spec §6.2), proving that the storage mechanism is irrelevant to the protocol. Force async-correct design by requiring equivalence across three storage backends.

### What This Milestone Proves

That the same `Resolve` function, given the same HIRI URI and the same logical content, returns byte-identical verified results regardless of whether the underlying storage is an in-memory map, a filesystem, or a delayed async backend. This is the "Edge-Canonical" proof: the verification logic is decoupled from I/O.

### Core Logic

```typescript
interface ResolverConfig {
  storage: StorageAdapter;
  crypto: CryptoProvider;
  keyPinning?: {
    enabled: boolean;
    store: KeyPinStore;
  };
}

interface VerifiedContent {
  data: Uint8Array;
  manifest: ResolutionManifest;
  verification: {
    canonicalAuthority: string;
    chainVerified: boolean;
    chainDepth: number;
    warnings: string[];
  };
}

async function resolve(
  uri: string,
  config: ResolverConfig
): Promise<VerifiedContent>
```

### Required: StorageAdapter (Minimal Interface)

The Phase 2.5 `StorageAdapter` has seven methods. The resolver needs only two. Define a minimal interface that the resolver depends on, keeping the indexing methods as an extension:

```typescript
// What the resolver needs (kernel type)
interface ContentStore {
  get(hash: string): Promise<Uint8Array | null>;
  has(hash: string): Promise<boolean>;
}
```

The existing `InMemoryStorageAdapter` already satisfies this (it has `get` and could trivially implement `has`). The two new adapters only need to implement `ContentStore`, not the full seven-method interface.

**Alternatively**, if the developers prefer not to introduce a new interface, the resolver can accept the existing `StorageAdapter` and simply not call the indexing methods. Either approach works; the key constraint is that `FileSystemAdapter` and `DelayedAdapter` must not be forced to implement `getLatest`, `listVersions`, or `listBranches`.

### Required: Three Storage Adapters

**3.A — InMemoryStorageAdapter** (already exists from Phase 2.5)
The existing adapter satisfies the resolver's needs. Expose a `has()` method if not already present.

**3.B — FileSystemAdapter** (new)

```typescript
class FileSystemAdapter implements ContentStore {
  constructor(private basePath: string) {}

  async get(hash: string): Promise<Uint8Array | null> {
    // hash "sha256:abc123..." → file path "<basePath>/sha256--abc123..."
    const filename = hash.replace(":", "--");
    const filepath = path.join(this.basePath, filename);
    try {
      return await fs.readFile(filepath);
    } catch {
      return null;
    }
  }

  async has(hash: string): Promise<boolean> {
    const filename = hash.replace(":", "--");
    const filepath = path.join(this.basePath, filename);
    try {
      await fs.access(filepath);
      return true;
    } catch {
      return false;
    }
  }
}
```

Content-addressed filenames: the hash prefix colon is replaced with `--` to produce filesystem-safe names. The test setup populates a temp directory with files named by their content hash.

**3.C — DelayedAdapter** (new)

```typescript
class DelayedAdapter implements ContentStore {
  constructor(
    private inner: ContentStore,
    private minDelayMs: number = 50,
    private maxDelayMs: number = 500
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
    const ms = this.minDelayMs + Math.random() * (this.maxDelayMs - this.minDelayMs);
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

The random delay forces the resolver to be properly async. Any code that accidentally awaits in the wrong order or holds stale references across async boundaries will produce intermittent failures.

### Resolution Steps (mapping to Protocol Spec §6.2)

The `resolve` function performs these steps in order:

```
1. Parse HIRI URI → authority, type, identifier
2. Derive Key Document hash from authority (deterministic for key-based authorities)
3. Fetch Key Document from storage by hash
4. Verify Key Document is self-signed (key-based authority bootstrap)
5. Extract canonical key authority from Key Document
6. (Optional) Check key pinning: first-use → pin; match → continue; mismatch → error
7. Derive manifest location hash from authority + type + identifier
8. Fetch manifest from storage by location hash
9. Verify manifest signature against Key Document's active key
10. Verify chain integrity (using M2's verifyChain with storage-backed fetchers)
11. Fetch content by manifest's content hash
12. Verify content hash matches manifest declaration
13. Return VerifiedContent with verification metadata
```

**Step 7 note — manifest location:** For MVP, the manifest's location in storage is its own hash (the manifest is stored content-addressed like everything else). The resolver needs a way to find the manifest hash for a given URI. For MVP, this is solved by a `manifestIndex: Map<string, string>` that maps URI strings to manifest hashes, passed as part of the resolver config or as a fourth parameter. This index is the "discovery" step — in production it would be HIRI-KEY, HIRI-DNS, etc. In MVP it's a lookup table.

```typescript
interface ResolverConfig {
  storage: ContentStore;
  crypto: CryptoProvider;
  manifestIndex: Map<string, string>;  // URI → manifest hash
  keyPinning?: { enabled: boolean; store: KeyPinStore };
}
```

### Test Fixtures

All fixtures are built programmatically in test setup using the M1/M2 infrastructure:

1. Generate keypair, derive authority
2. Build and sign `person.jsonld` as genesis manifest (M1)
3. Build and sign `person-v2.jsonld` as V2 with chain + delta (M2)
4. Store all artifacts (Key Document, manifests, content) in each adapter
5. Build manifest index mapping URI → head manifest hash

For `FileSystemAdapter`: write all artifacts to a temp directory as content-addressed files.
For `DelayedAdapter`: wrap the `InMemoryStorageAdapter`.

### Test Matrix

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| 3.1 | Resolve valid URI against `InMemoryStorageAdapter` | Returns `VerifiedContent` with correct JSON-LD, `chainVerified: true`, `chainDepth: 2` |
| 3.2 | Resolve same URI against `FileSystemAdapter` | Returns byte-identical `data` field to 3.1 |
| 3.3 | Resolve same URI against `DelayedAdapter` | Returns byte-identical `data` field to 3.1 |
| 3.4 | Resolve URI with unknown authority (no Key Document in storage) | Throws/returns `AuthorityNotFound` error |
| 3.5 | Resolve URI where manifest exists but content hash is not in storage | Throws/returns `ContentNotFound` error |
| 3.6 | Resolve URI where manifest exists but signature doesn't verify against Key Document | Throws/returns `SignatureVerificationFailed` error |
| 3.7 | Resolve 10 different URIs concurrently against `DelayedAdapter` using `Promise.all` | All 10 return correct results; no cross-contamination between concurrent resolutions |
| 3.8 | Parse malformed URIs: `"not-a-uri"`, `"hiri://"`, `"hiri://auth/type"` (missing identifier), `"hiri://auth/type/id/extra"` (too many segments) | Each returns appropriate parse error |

**Test 3.1–3.3 equivalence proof:** Tests 3.1, 3.2, and 3.3 must compare the `data` field byte-for-byte. The verification metadata may differ (e.g., timing), but the verified content must be identical. This is the core proof: storage mechanism is irrelevant to protocol correctness.

**Test 3.7 concurrency proof:** The 10 URIs should include a mix of valid URIs (different person identifiers) and at least one invalid URI (unknown authority). The test verifies that the invalid resolution's failure doesn't corrupt the valid resolutions. This surfaces shared-state bugs that only appear under concurrency.

### Execution Sequence

```
1. Define ContentStore interface (or confirm existing StorageAdapter suffices)
2. Implement FileSystemAdapter
3. Implement DelayedAdapter
4. Implement resolve() function (steps 1–13 above)
5. Build test fixtures programmatically using M1/M2 infrastructure
6. Run tests 3.8 (URI parsing — no storage needed)
7. Run tests 3.1 (in-memory resolution)
8. Run tests 3.4, 3.5, 3.6 (error cases)
9. Populate temp directory, run test 3.2 (filesystem equivalence)
10. Run test 3.3 (delayed equivalence)
11. Run test 3.7 (concurrency)
12. All 8 tests green → Milestone 3 complete
```

### Infrastructure

- Node.js `fs/promises` for `FileSystemAdapter` (adapter layer, not kernel)
- `os.tmpdir()` for test fixture directory
- `setTimeout` for `DelayedAdapter` (adapter layer)
- No new npm dependencies

### Exit Criteria

- All 8 tests pass
- The `resolve` function accepts any `ContentStore` implementation
- Tests 3.1–3.3 produce byte-identical `data` output
- Test 3.7 passes consistently (no intermittent failures from race conditions)
- Zero direct storage access in the resolver — all I/O goes through `ContentStore`

---

## Milestone 4: The Storeless Oracle

### Objective

Prove that a client can load verified content into a local RDF index and query it with SPARQL — without a graph database server. Establish the entailment contract that future milestones (materialized entailment, runtime entailment) must satisfy.

### What This Milestone Proves

That the output of `resolve()` (Milestone 3) can be loaded into an in-memory RDF graph and queried with standard SPARQL, with the query engine respecting the manifest's declared `entailmentMode`. This completes the verification-to-knowledge pipeline: URI → verified content → queryable knowledge.

### Scope: Layers 3 and 4 Combined

Protocol Spec Layer 3 (Storeless Index, §7) defines how clients build local RDF indices from verified content. Layer 4 (Query & Verification, §8) defines how clients query those indices.

For the MVP, these are tested together as a single pipeline. The index is built from verified content (Layer 3), then queried (Layer 4). The two are separate modules but a single milestone, because neither is testable in isolation:
- An index with no query capability proves nothing beyond "JSON-LD was parsed"
- A query engine with no index has nothing to query

### Core Logic

```typescript
/** Layer 3: Build index from verified content */
interface RDFIndex {
  load(content: Uint8Array, format: string, baseURI: string): Promise<void>;
  tripleCount(): number;
}

/** Layer 4: Query the index */
interface SPARQLEngine {
  query(sparql: string, index: RDFIndex): Promise<QueryResult>;
}

/** Combined pipeline */
interface QueryResult {
  bindings: Array<Record<string, RDFTerm>>;
  truncated: boolean;
}

interface RDFTerm {
  type: "uri" | "literal" | "bnode";
  value: string;
  datatype?: string;   // for typed literals
  language?: string;    // for language-tagged literals
}

/** Entailment mode from manifest semantics */
type EntailmentMode = "none" | "materialized" | "runtime";
```

### WASM Dependency: Oxigraph

Oxigraph (WASM build) is the SPARQL engine for MVP. It provides:
- In-memory RDF graph store
- Full SPARQL 1.1 query support
- Optional RDFS inference (which we must explicitly disable for `entailmentMode: "none"`)
- ~2–3MB WASM bundle, acceptable for MVP

**ADR Required:** The developers should log an ADR for Oxigraph as a runtime dependency, following the pattern of ADR-002 (`@noble/ed25519`). The WASM module loads in the adapter layer, not the kernel. The kernel defines the `RDFIndex` and `SPARQLEngine` interfaces; the adapter wraps Oxigraph.

**Alternative if Oxigraph proves problematic:** `n3.js` (N3 library) for parsing + a minimal SPARQL evaluator. This is lighter but less complete. Oxigraph is preferred.

### Architecture

```
┌─────────────────────────────────────────────┐
│  Kernel (pure)                              │
│  ├── types.ts: RDFIndex, SPARQLEngine,      │
│  │             QueryResult, EntailmentMode  │
│  ├── graph-builder.ts: buildGraph()         │
│  │   (orchestrates load + entailment check) │
│  └── query-executor.ts: executeQuery()      │
│       (orchestrates query + result limits)  │
├─────────────────────────────────────────────┤
│  Adapters                                   │
│  ├── rdf/oxigraph-index.ts: OxigraphIndex   │
│  │   implements RDFIndex                    │
│  └── rdf/oxigraph-engine.ts: OxigraphEngine │
│      implements SPARQLEngine                │
└─────────────────────────────────────────────┘
```

### The `hiri:semantics` Field

Milestone 4 introduces the `hiri:semantics` field on manifests. Milestones 1–3 omitted this field (it was listed as "will be added in Milestone 4" in v1.3). The field structure:

```json
{
  "hiri:semantics": {
    "entailmentMode": "none",
    "baseRegime": null,
    "vocabularies": []
  }
}
```

For MVP, only `entailmentMode: "none"` is implemented. The field must be present on manifests that will be loaded into the graph. The graph builder reads this field and configures the index accordingly.

**Backward compatibility:** Manifests from M1–M3 that lack `hiri:semantics` are treated as `entailmentMode: "none"` by default. This is the safe default — no inference applied.

### Pipeline: resolve → build graph → query

```
1. resolve(uri, config) → VerifiedContent          [Milestone 3]
2. Parse VerifiedContent.data as JSON-LD
3. Read entailment mode from manifest (or default to "none")
4. Load parsed triples into RDFIndex
5. Configure index for declared entailment mode
6. Execute SPARQL query against index
7. Return QueryResult
```

### Test Fixtures

**4.A — Primary fixture: `person.jsonld` (existing)**
The existing `person.jsonld` from M1 provides the base graph for most tests. After resolution through M3, it contains triples like:

```turtle
<hiri://key:ed25519:.../data/person-001> a schema:Person ;
    schema:name "Dana Reeves" ;
    schema:birthDate "1988-03-14"^^xsd:date ;
    schema:jobTitle "Systems Architect" ;
    schema:address [ a schema:PostalAddress ;
        schema:addressLocality "Portland" ;
        schema:addressRegion "OR" ;
        schema:addressCountry "US" ] ;
    schema:worksFor [ a schema:Organization ;
        schema:name "Cascade Infrastructure Labs" ] .
```

**4.B — Entailment test fixture: `entailment-trap.jsonld` (new)**

This fixture is designed specifically to test that inference does NOT leak through when `entailmentMode: "none"`. It introduces an RDFS subclass relationship and a typed individual, then queries for the superclass type.

```json
{
  "@context": {
    "schema": "http://schema.org/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "ex": "http://example.org/test/"
  },
  "@graph": [
    {
      "@id": "ex:SoftwareArchitect",
      "@type": "rdfs:Class",
      "rdfs:subClassOf": { "@id": "schema:Person" }
    },
    {
      "@id": "ex:testSubject",
      "@type": "ex:SoftwareArchitect",
      "schema:name": "Test Subject"
    }
  ]
}
```

Under RDFS inference, `ex:testSubject` would be inferred as `a schema:Person` (via the subclass axiom). Under `entailmentMode: "none"`, it must NOT be. This is the critical gate test.

**4.C — Multi-entity fixture: `team.jsonld` (new)**

For multi-row query testing:

```json
{
  "@context": {
    "schema": "http://schema.org/",
    "xsd": "http://www.w3.org/2001/XMLSchema#"
  },
  "@graph": [
    {
      "@id": "hiri://key:ed25519:AUTHORITY_PLACEHOLDER/data/person-001",
      "@type": "schema:Person",
      "schema:name": "Dana Reeves",
      "schema:jobTitle": "Systems Architect"
    },
    {
      "@id": "hiri://key:ed25519:AUTHORITY_PLACEHOLDER/data/person-002",
      "@type": "schema:Person",
      "schema:name": "Morgan Chen",
      "schema:jobTitle": "Protocol Engineer"
    },
    {
      "@id": "hiri://key:ed25519:AUTHORITY_PLACEHOLDER/data/person-003",
      "@type": "schema:Person",
      "schema:name": "Ava Okonkwo",
      "schema:jobTitle": "Cryptography Lead"
    }
  ]
}
```

### Test Matrix

| # | Test Case | Fixture | Expected Result |
|---|-----------|---------|-----------------|
| 4.1 | Load verified `person.jsonld` into index, execute `SELECT ?name WHERE { ?s schema:name ?name }` | 4.A | Returns single binding: `{ name: { type: "literal", value: "Dana Reeves" } }` |
| 4.2 | Execute `SELECT ?title WHERE { ?s schema:jobTitle ?title }` | 4.A | Returns `"Systems Architect"` |
| 4.3 | Execute typed literal query: `SELECT ?date WHERE { ?s schema:birthDate ?date }` | 4.A | Returns `{ type: "literal", value: "1988-03-14", datatype: "xsd:date" }` |
| 4.4 | **Entailment boundary (critical gate):** Load `entailment-trap.jsonld` with `entailmentMode: "none"`. Execute `SELECT ?x WHERE { ?x a schema:Person }` | 4.B | Returns **empty result set**. `ex:testSubject` is typed as `ex:SoftwareArchitect`, NOT as `schema:Person`. No RDFS subclass inference applied. |
| 4.5 | **Entailment mode respected:** Confirm that the index was configured without RDFS reasoning. Query `SELECT ?x ?type WHERE { ?x a ?type }` on fixture 4.B | 4.B | Returns exactly 2 bindings: `ex:SoftwareArchitect a rdfs:Class` and `ex:testSubject a ex:SoftwareArchitect`. No inferred types present. |
| 4.6 | **Multi-row results:** Load `team.jsonld`, execute `SELECT ?name ?title WHERE { ?s schema:name ?name . ?s schema:jobTitle ?title } ORDER BY ?name` | 4.C | Returns 3 bindings in alphabetical order: Ava, Dana, Morgan |
| 4.7 | **Empty result set:** Execute `SELECT ?x WHERE { ?x schema:email ?email }` against `person.jsonld` (no email in V1) | 4.A | Returns empty result set (not an error) |
| 4.8 | **Full pipeline integration:** Starting from a HIRI URI string, resolve → build graph → query, as a single composed operation | 4.A + M3 resolver | Returns correct name from verified, resolved content |
| 4.9 | **Missing semantics field (backward compat):** Load a manifest from M1 (no `hiri:semantics` field) into the graph builder | M1 manifest | Defaults to `entailmentMode: "none"`, loads successfully |
| 4.10 | **SPARQL syntax error:** Execute `SELCT ?x WERE { ?x a ?y }` (misspelled keywords) | any | Returns/throws a query parse error, not an empty result |
| 4.11 | **No network activity (constraint check):** Run tests 4.1–4.3 and confirm no external HTTP requests were made during any operation | 4.A | All computation is local — no network calls from the RDF engine or WASM loader |

### Entailment Mode Interface

Even though only `"none"` is implemented, the graph builder must accept the mode as a parameter and route accordingly. This establishes the contract for future modes:

```typescript
interface GraphBuilderConfig {
  entailmentMode: EntailmentMode;
  // Future: vocabularies, materializationProof, etc.
}

async function buildGraph(
  content: Uint8Array,
  format: string,
  config: GraphBuilderConfig,
  indexFactory: () => RDFIndex
): Promise<RDFIndex> {
  const index = indexFactory();

  if (config.entailmentMode === "none") {
    // Load triples as-is, no inference
    await index.load(content, format, "");
  } else if (config.entailmentMode === "materialized") {
    // Future: load pre-expanded graph, optionally verify materialization
    throw new Error("Materialized entailment not yet implemented");
  } else if (config.entailmentMode === "runtime") {
    // Future: load triples then apply reasoner
    throw new Error("Runtime entailment not yet implemented");
  }

  return index;
}
```

The `throw` for unimplemented modes is intentional — it's a loud failure that prevents silent fallback to wrong behavior. When materialized entailment is implemented, the throw is replaced with the real logic.

### Execution Sequence

```
1. Log ADR for Oxigraph WASM dependency
2. Define RDFIndex, SPARQLEngine, QueryResult, EntailmentMode in kernel types
3. Implement OxigraphIndex adapter (load JSON-LD, expose triple count)
4. Implement OxigraphEngine adapter (execute SPARQL, return bindings)
5. Implement buildGraph() kernel function with entailment mode routing
6. Implement executeQuery() kernel function with timeout/limit guards
7. Create entailment-trap.jsonld and team.jsonld fixtures
8. Run test 4.1 (basic name query)
9. Run tests 4.2, 4.3 (job title, typed literal)
10. Run tests 4.4, 4.5 (entailment boundary — critical gate)
11. Run tests 4.6, 4.7 (multi-row, empty result)
12. Run test 4.8 (full pipeline integration with M3 resolver)
13. Run tests 4.9, 4.10 (backward compat, syntax error)
14. Run test 4.11 (no network activity)
15. All 11 tests green → Milestone 4 complete
```

### Exit Criteria

- All 11 tests pass
- Test 4.4 is the critical gate: if RDFS inference leaks through, the milestone fails regardless of other tests
- Test 4.8 demonstrates M1→M2→M3→M4 working as a composed pipeline
- The query function accepts an `EntailmentMode` parameter
- Unimplemented entailment modes throw explicitly (no silent fallback)
- No network requests during any test execution

---

## Milestone 5: The Sovereign Authority

### Objective

Prove that identity persists when keys change, using self-certifying logic. This milestone is a **retroactive hardening pass** on Milestones 1–3 — key rotation changes the semantics of signature verification, which means the resolver's verification step and the chain walker's per-manifest verification must now consult the Key Document's temporal key states.

### What This Milestone Proves

That a manifest signed by a rotated key during the grace period is accepted (with warning). That a manifest signed after the grace period is rejected. That a retroactive revocation invalidates past signatures after the declared invalidation point. That the chain walker correctly handles chains spanning key rotation events.

### The Retroactive Coupling

This is the most important architectural point. Key rotation does not exist in isolation — it reaches back and modifies the verification functions from M1 and the chain walker from M2.

Specifically:
- M1's `verifyManifest` currently accepts a bare public key. After M5, it must accept a `KeyDocument` and a timestamp, then determine which key was valid at the manifest's signing time.
- M2's `verifyChain` currently verifies each manifest's signature against a single key. After M5, it must consult the Key Document for *each* manifest in the chain, checking temporal validity per signature.
- M3's `resolve` calls both of these. Its verification metadata must now include key status information.

The milestone is not complete until the chain walker correctly handles all temporal key states across a full chain.

### Core Logic

```typescript
type KeyStatus =
  | "active"
  | "rotated-grace"
  | "rotated-expired"
  | "revoked";

interface KeyVerificationResult {
  valid: boolean;
  keyStatus: KeyStatus;
  keyId: string;
  warning?: string;
}

/**
 * Determine which key should verify a manifest, given the Key Document
 * and the manifest's signing timestamp.
 */
function resolveSigningKey(
  manifest: ResolutionManifest,
  keyDocument: KeyDocument,
  verificationTime: string        // ISO 8601 — current time for status check
): KeyVerificationResult;

/**
 * Verify a manifest's signature with full key lifecycle awareness.
 * Replaces M1's simple verify for production use.
 */
async function verifyManifestWithKeyLifecycle(
  manifest: ResolutionManifest,
  keyDocument: KeyDocument,
  verificationTime: string,
  crypto: CryptoProvider
): Promise<KeyVerificationResult>;
```

### KeyDocument Structure (Full Lifecycle)

The M1 KeyDocument had only `activeKeys` with empty `rotatedKeys` and `revokedKeys`. M5 populates all three:

```json
{
  "@type": "hiri:KeyDocument",
  "hiri:version": 3,
  "hiri:authority": "key:ed25519:<derived-authority>",
  "hiri:authorityType": "key",

  "hiri:activeKeys": [
    {
      "@id": "...#key-3",
      "@type": "Ed25519VerificationKey2020",
      "publicKeyMultibase": "z6MkNewKey...",
      "purposes": ["assertionMethod"],
      "validFrom": "2025-07-01T00:00:00Z"
    }
  ],

  "hiri:rotatedKeys": [
    {
      "@id": "...#key-2",
      "rotatedAt": "2025-07-01T00:00:00Z",
      "rotatedTo": "...#key-3",
      "reason": "scheduled-rotation",
      "verifyUntil": "2025-12-31T00:00:00Z"
    }
  ],

  "hiri:revokedKeys": [
    {
      "@id": "...#key-1",
      "revokedAt": "2025-03-01T00:00:00Z",
      "reason": "compromise-suspected",
      "manifestsInvalidAfter": "2025-02-15T00:00:00Z"
    }
  ],

  "hiri:policies": {
    "gracePeriodAfterRotation": "P180D",
    "minimumKeyValidity": "P365D"
  }
}
```

### Mock Clock

All M5 tests use a mock clock. No `Date.now()` in any code path. The `verificationTime` parameter is the injected clock, consistent with ADR-003.

```typescript
// Test helper
function mockTime(iso: string): string { return iso; }

// Usage in tests
const result = resolveSigningKey(manifest, keyDoc, mockTime("2025-08-15T00:00:00Z"));
```

### ISO 8601 Duration Parsing

The `gracePeriodAfterRotation` field uses ISO 8601 duration format (`P180D`). M5 requires a pure kernel function to parse this:

```typescript
function parseDuration(iso8601: string): { days: number };  // MVP: days only
function addDuration(timestamp: string, duration: string): string;  // Returns ISO timestamp
```

For MVP, only day-precision durations (`PnD`) need to be supported. Month/year durations introduce calendar complexity that is not needed for the test cases.

### Key Resolution Algorithm

```
Given: manifest with signature.verificationMethod = "...#key-2"
       keyDocument with activeKeys, rotatedKeys, revokedKeys
       verificationTime = "2025-08-15T00:00:00Z"

1. Extract keyId from verificationMethod ("key-2")
2. Search activeKeys for matching @id
   → If found: return { valid: true, keyStatus: "active" }
3. Search rotatedKeys for matching @id
   → If found:
     a. Compute grace expiry = rotatedAt + gracePeriodAfterRotation
     b. If verificationTime ≤ verifyUntil AND verificationTime ≤ grace expiry:
        return { valid: true, keyStatus: "rotated-grace",
                 warning: "Signed by rotated key within grace period" }
     c. Else:
        return { valid: false, keyStatus: "rotated-expired" }
4. Search revokedKeys for matching @id
   → If found:
     a. If manifest.timing.created < manifestsInvalidAfter:
        return { valid: true, keyStatus: "revoked",
                 warning: "Key subsequently revoked but signature predates invalidation point" }
     b. Else:
        return { valid: false, keyStatus: "revoked" }
5. Key not found in any list:
   return { valid: false, keyStatus: "unknown" }
```

### Test Fixtures

M5 requires three keypairs and a KeyDocument that spans the full lifecycle:

**Setup:**
```
KeyPair A (key-1): Generated first. Will be revoked with retrospective invalidation.
KeyPair B (key-2): Generated second. Will be rotated to Key C.
KeyPair C (key-3): Generated third. Currently active.

Timeline:
  2025-01-01  Key A active (genesis)
  2025-02-15  Key A's manifestsInvalidAfter (retrospective)
  2025-03-01  Key A revoked (compromise suspected)
  2025-04-01  Key B becomes active
  2025-07-01  Key B rotated to Key C
  2025-12-31  Key B's verifyUntil (grace period ends)
  2026-01-01  Key C active (current)
```

**Manifests across the timeline:**
```
M-V1: Signed by Key A at 2025-01-15 (before invalidation point)
M-V2: Signed by Key A at 2025-02-20 (after invalidation point, before revocation)
M-V3: Signed by Key B at 2025-05-01 (Key B active)
M-V4: Signed by Key B at 2025-08-01 (Key B rotated, within grace)
M-V5: Signed by Key C at 2025-08-01 (Key C active)
```

### Test Matrix

| # | Test Case | Manifest | Verification Time | Expected Result |
|---|-----------|----------|-------------------|-----------------|
| 5.1 | **Active key signs** | M-V5 (Key C) | 2025-09-01 | `{ valid: true, keyStatus: "active" }` |
| 5.2 | **Rotated key within grace** | M-V4 (Key B) | 2025-08-15 | `{ valid: true, keyStatus: "rotated-grace", warning: "Signed by rotated key within grace period" }` |
| 5.3 | **Rotated key after grace** | M-V4 (Key B) | 2026-02-01 | `{ valid: false, keyStatus: "rotated-expired" }` |
| 5.4 | **Revoked key** — manifest signed after revocation | Signed by Key A at 2025-04-01 | 2025-09-01 | `{ valid: false, keyStatus: "revoked" }` |
| 5.5 | **Revoked key — past signature before invalidation** | M-V1 (Key A, signed 2025-01-15) | 2025-09-01 | `{ valid: true, keyStatus: "revoked", warning: "Key subsequently revoked but signature predates invalidation point" }` |
| 5.6 | **Revoked key — past signature after invalidation (retroactive)** | M-V2 (Key A, signed 2025-02-20) | 2025-09-01 | `{ valid: false, keyStatus: "revoked" }` |
| 5.7 | **Grace period boundary (−1 second)** | M-V4 (Key B) | 2025-12-30T23:59:59Z | `{ valid: true, keyStatus: "rotated-grace" }` |
| 5.8 | **Grace period boundary (+1 second)** | M-V4 (Key B) | 2025-12-31T00:00:01Z | `{ valid: false, keyStatus: "rotated-expired" }` |
| 5.9 | **Chain with rotation:** V3 signed by Key B, V5 signed by Key C. Verify full chain. | M-V3 + M-V5 | 2025-09-01 | `{ valid: true, depth: 2 }` — both signatures valid in temporal context |
| 5.10 | **Chain with retroactive revocation:** M-V1 (Key A, before invalidation) → M-V2 (Key A, after invalidation) → M-V3 (Key B). Verify chain from V3. | M-V1→V2→V3 | 2025-09-01 | Chain walker: V3 valid, V2 invalid (retroactive revocation), V1 valid. Reports partial chain validity with specific failure point. |
| 5.11 | **Dual signature rotation:** Verify that the Key Document's rotation entry for Key B → Key C contains both old-key-authorizes and new-key-confirms signatures (Protocol Spec §10.2.1) | KeyDocument | any | Rotation accepted only if both signatures verify |
| 5.12 | **Unknown key:** Manifest claims `verificationMethod: ...#key-99` which doesn't exist in any key list | Fabricated | 2025-09-01 | `{ valid: false, keyStatus: "unknown" }` |
| 5.13 | **Updated resolver:** Run M3's `resolve()` against a chain spanning Key B → Key C rotation | M-V3→V5 via resolver | 2025-09-01 | `VerifiedContent` returned with `warnings` array containing grace-period note for V3's Key B signature |

### Chain Walker Update

M2's `verifyChain` must be extended (or wrapped) to accept a KeyDocument and verification time:

```typescript
async function verifyChainWithKeyLifecycle(
  head: ResolutionManifest,
  keyDocument: KeyDocument,
  verificationTime: string,
  fetchManifest: ManifestFetcher,
  fetchContent: ContentFetcher,
  crypto: CryptoProvider
): Promise<ChainWalkResult> {
  // For each manifest in the chain:
  //   1. Determine which key signed it (from verificationMethod)
  //   2. Resolve key status at verificationTime
  //   3. If active or rotated-grace: verify signature, continue
  //   4. If rotated-expired or revoked: record failure point
  //   5. Special: revoked with manifestsInvalidAfter — check manifest's signing time
}

interface ChainWalkResult {
  valid: boolean;        // true only if ALL links valid
  depth: number;
  warnings: string[];    // grace period notices, etc.
  failures: Array<{
    version: number;
    keyId: string;
    keyStatus: KeyStatus;
    reason: string;
  }>;
}
```

**Test 5.10 specifically validates this:** The chain V1→V2→V3 has V2 signed by a retroactively-revoked key. The walker must report V2 as the failure point while noting V1 is valid (signed before the invalidation point) and V3 is valid (signed by a different, non-revoked key). This is partial chain validity — the most complex verification case in the MVP.

### Execution Sequence

```
1. Implement parseDuration() and addDuration() in kernel
2. Implement resolveSigningKey() in kernel
3. Implement verifyManifestWithKeyLifecycle() in kernel
4. Generate three keypairs (A, B, C) in test setup
5. Build full-lifecycle KeyDocument fixture
6. Build timeline manifests (M-V1 through M-V5)
7. Run tests 5.1–5.6 (individual key status cases)
8. Run tests 5.7–5.8 (boundary conditions)
9. Implement verifyChainWithKeyLifecycle() — extends M2 chain walker
10. Run tests 5.9–5.10 (chain verification with rotation/revocation)
11. Run test 5.11 (dual-signature rotation)
12. Run test 5.12 (unknown key)
13. Update M3 resolver to use key-lifecycle-aware verification
14. Run test 5.13 (resolver integration)
15. All 13 tests green → Milestone 5 complete
```

### Exit Criteria

- All 13 tests pass
- Tests 5.6 (retroactive revocation) and 5.7–5.8 (boundary conditions) are the critical gates
- M1's verification function is updated or wrapped to accept KeyDocument + timestamp
- M2's chain walker is updated or wrapped to verify per-manifest key status
- M3's resolver returns key status information in verification metadata
- All temporal tests use mock clock — no `Date.now()` in any code path
- Existing M1–M4 tests still pass (backward compatibility)

---

## Integration: The MVP Browser Reader

### Objective

Validate the complete pipeline as a single artifact. This is the final proof that Milestones 1–5 compose correctly.

### Architecture

A single `index.html` file containing:

**1. Mock Network Panel** — A JSON text area where the user provides (or loads from a preset) a complete "world state": a JSON object mapping content hashes to their base64-encoded content. This includes manifests, Key Documents, and data payloads. This acts as the `ContentStore` for the resolver.

**2. URI Input** — A text field accepting a `hiri://key:ed25519:.../data/...` URI.

**3. Resolve Button** — Triggers the full pipeline:
- Parse URI (M1 abstractions)
- Discover Key Document from authority (M3 resolver)
- Fetch and verify manifest with key lifecycle awareness (M1 + M5)
- Verify chain integrity with temporal key status (M2 + M5)
- Verify delta application if applicable (M2)
- Build local RDF graph index (M4)

**4. Verification Report** — Displays:
- Chain depth and validity
- Key status for each signature in the chain (active / rotated-grace / revoked)
- Delta verification results
- Any warnings (rotated keys in grace period, retroactive revocation, etc.)

**5. Data Viewer** — Renders the verified JSON-LD content in a readable format.

**6. SPARQL Console** — A text area for SPARQL queries against the verified graph, with a result table below. The entailment mode is displayed and respected.

### Why Not Paste-and-Verify

The v1.0 integration accepted a pasted manifest, which only validated M1 and M4. The full integration accepts a HIRI URI and a mock world state, then runs M1→M2→M3→M4→M5 as a composed pipeline. Every milestone's code is exercised.

### Preset Scenarios

| Preset | What It Exercises | Content |
|--------|-------------------|---------|
| **Simple Verify** | M1, M3, M4 | Genesis manifest, single key, `person.jsonld`. Resolve, verify, query for name. |
| **Chain with Delta** | M1, M2, M3, M4 | Three-version chain. V2 has a valid delta (Portland→Seattle). V3 has a corrupted delta (falls back to full content with warning). Resolve head, verify chain, query for current address. |
| **Key Rotation** | M1–M5 | Chain spanning Key B → Key C rotation. V3 signed by Key B (rotated, in grace period). V5 signed by Key C (active). Resolve, verify chain with temporal key status, query. Verification report shows grace-period warning. |

### Test Matrix

| # | Test | Expected |
|---|------|----------|
| I.1 | Load "Simple Verify" preset, enter URI, click Resolve | Verification report: valid genesis, `chainDepth: 1`. Data viewer shows Dana Reeves. SPARQL `SELECT ?name` returns "Dana Reeves". |
| I.2 | Load "Chain with Delta" preset, resolve URI | Report: 3-deep chain, delta corruption warning on V3, all content verified. SPARQL `SELECT ?city WHERE { ?s schema:addressLocality ?city }` returns current city. |
| I.3 | Load "Key Rotation" preset, resolve URI | Report: chain valid, Key B status = rotated-grace with warning, Key C status = active. Data viewer shows verified content. |
| I.4 | Load any preset, modify one byte in the mock network's content payload, resolve | Verification fails with content hash mismatch displayed in report. |
| I.5 | Load "Simple Verify" preset, resolve, then run `SELECT ?name WHERE { ?s schema:name ?name }` | SPARQL result table shows "Dana Reeves". |
| I.6 | Open browser devtools network tab before any operation. Run all three presets. | Zero HTTP requests recorded. All computation is client-side. |

### Infrastructure

- Single `index.html` file
- Oxigraph WASM loaded inline or from a relative path (no CDN fetch during verification — the WASM can be loaded at page init but no network during resolve/verify/query)
- All M1–M5 kernel code bundled (via esbuild or similar)
- No other runtime dependencies

---

## Dependency Graph

```
M1: The Verifiable Atom
├── HashRegistry, URI scheme, signatures, genesis
│
▼
M2: The Deterministic Chain
├── Chain walker, delta verification, JSON Patch
│
▼
Phase 2.5: Persistence Infrastructure (already complete)
├── StorageAdapter, ManifestTracker, KeyPinStore, BigInt versions
│
▼
M3: The Abstracted Resolver
├── resolve() function
├── FileSystemAdapter, DelayedAdapter
├── Storage-mechanism equivalence proof
│
▼
M4: The Storeless Oracle
├── Oxigraph WASM integration
├── RDFIndex, SPARQLEngine interfaces
├── Entailment mode enforcement (none)
├── Full pipeline: URI → resolve → graph → query
│
▼
M5: The Sovereign Authority ────────────────────┐
├── Key rotation, temporal verification          │
├── Grace period boundaries                      │  retroactive
├── Retroactive revocation                       │  hardening
├── Updated verifyManifest (M1) ◀────────────────┤
├── Updated verifyChain (M2) ◀───────────────────┤
├── Updated resolve (M3) ◀──────────────────────┘
│
▼
Integration: MVP Browser Reader
├── Full pipeline: URI → resolve → verify → graph → query
├── Three preset scenarios exercising M1–M5
└── Zero network dependency during operation
```

---

## What Is Explicitly Deferred

| Capability | Spec Section | Why Deferred |
|------------|-------------|--------------|
| Chain compaction (recursive SNARKs) | §12 | Requires ZK infrastructure; MVP proves chain verification works without compaction |
| Zero-knowledge proofs | §9 | Proof generation/verification is a separate workstream; MVP proves the data layer |
| Privacy accumulators | §9.5 | Depends on ZK layer and Privacy Authority infrastructure |
| Materialized entailment | §8.1.2 | MVP enforces `entailmentMode: "none"`; materialized mode requires reasoner integration |
| Runtime entailment | §8.1.1 | Same; the entailment interface is established but only `"none"` is implemented |
| DNS/IPNS/Registry discovery | §6.1.2–6.1.4 | MVP uses HIRI-KEY (self-certifying) only; convenience layers add no security value at MVP |
| Content layers (authorization) | §5.2 `contentLayers` | MVP resolves single-layer content; multi-layer auth is an access control problem |
| Consortium authorities | §5.1 | MVP uses key-based authority only |
| Branching | §5.2 `hiri:branch` | MVP assumes `"main"` branch; branching adds complexity without validating core primitives |
| Timestamp Authority integration | §5.4 | MVP uses advisory timestamps; verified timestamps require TSA infrastructure |
| Persistent storage backends | §13.1 | MVP uses in-memory + filesystem adapters; IndexedDB/S3/PostgreSQL are deployment concerns |

---

## Success Criteria for MVP Completion

The MVP is complete when:

1. All milestone tests pass: M1 (9) + M2 (9) + M3 (8) + M4 (11) + M5 (13) = **50 governing tests** (plus Phase 2.5 infrastructure tests and any additional developer-added tests)
2. The integration Browser Reader exercises all three presets without errors
3. Zero network activity occurs during any verification or query operation
4. The entire system runs in a browser with no server dependencies
5. Every function that touches I/O does so through the `ContentStore` / `StorageAdapter` interface
6. Every function that computes a hash does so through the `HashRegistry`
7. Every function that checks time does so through an injected timestamp parameter
8. The codebase contains no hardcoded hash algorithm, no hardcoded storage path, no hardcoded authority, and no `Date.now()` call
9. A developer unfamiliar with the project can load `index.html`, pick a preset, and understand what HIRI does within 60 seconds

---

*This document supersedes v1.2 for Milestones 3–5 and Integration. v1.3's Milestone 1 execution detail is considered fully implemented and the v1.3 addendum is retired. v1.2's Milestone 2 test matrix (tests 2.1–2.9) remains authoritative for Milestone 2.*
