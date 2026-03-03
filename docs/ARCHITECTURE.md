# Architecture Principles

> **Quick Spec Test:** A conforming implementation MUST pass `npm test` (determinism, no-network, snapshot) and `npm run test:purity` (kernel isolation) with zero failures.

## Why This Exists

This template provides an architectural contract for services that transform JSON-LD documents deterministically. It exists because most service architectures conflate computation with infrastructure, making transformations non-reproducible, non-portable, and difficult to verify. This template separates them by design.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## 1. Edge-Canonical Execution

Computation MUST be able to run at the edge — on the client, in the browser, or on any device with a standard JavaScript runtime. The kernel MUST NOT require a centralized server to function.

Services built from this template SHOULD treat the edge as the primary execution environment. Server-side execution MAY occur but MUST NOT be required. The kernel MUST produce identical results regardless of where it executes.

This principle ensures that consumers retain control over their data and computation. No phone-home requirement, no licensing server, no mandatory cloud dependency.

## 2. No Required Infrastructure

The kernel MUST NOT depend on databases, message queues, cloud services, key-value stores, or any infrastructure beyond a JavaScript runtime. The kernel MUST function with nothing more than `node dist/kernel/index.js input.jsonld`.

Adapters MAY provide infrastructure integration for persistence, networking, or orchestration. However, these adapters MUST exist outside the kernel and MUST be replaceable without affecting kernel behavior. The kernel MUST remain testable without any adapter present.

## 3. Determinism Over Deployment

Given identical input, the kernel MUST produce identical output — regardless of when, where, or how many times it executes. This is the central invariant of the architecture.

The kernel MUST NOT reference or depend on: current time (`Date.now()`, `new Date()`), random values (`Math.random()`, `crypto.getRandomValues()`), environment variables (`process.env`), file system state beyond the input document, network resources, or any other source of non-determinism.

Determinism is verified automatically by the spec test suite. Any change that breaks determinism MUST be treated as a breaking change.

## 4. Separation of Concerns

The architecture defines three layers:

- **Layer 0 — Kernel:** Pure transformation logic. JSON-LD in, JSON-LD out. No side effects. No I/O. This is the only required layer.
- **Layer 1 — Composition:** Optional orchestration of kernel invocations using Concepts, Synchronizations, and Sessions. This layer MAY coordinate multiple transformations but MUST NOT contain business logic.
- **Layer 2 — Adapters:** Optional infrastructure integration. Adapters handle persistence, networking, scheduling, and deployment. Adapters MUST NOT modify kernel semantics and MUST be replaceable.

Code in Layer 0 MUST NOT import from Layer 1 or Layer 2. Code in Layer 1 MUST NOT import from Layer 2. Violations are detected by the static kernel purity check.

## 5. JSON-LD as Canonical Representation

All kernel input and output MUST be valid JSON-LD. The kernel operates exclusively on JSON-LD documents. Every input MUST include an `@context` property. Every output MUST include an `@context` property.

JSON-LD is chosen because it provides semantic interoperability through linked data, is natively valid JSON (and therefore serializable, parseable, and storable with standard tools), and supports extensibility through context definitions without breaking existing consumers.

The kernel SHOULD produce canonicalized output — objects with recursively sorted keys — to support deterministic comparison and hashing.

## 6. Offline Is First-Class

The kernel MUST function without network access. Any operation that requires a network connection is, by definition, an adapter concern and MUST NOT exist in the kernel.

Offline operation is not a fallback mode — it is the primary mode. The spec test suite verifies this by stubbing network APIs and failing if the kernel attempts to use them. Services that require online connectivity for their core transformation logic do not conform to this architecture.

---

## Spec Test

A conforming implementation MUST pass all of the following automated checks:

1. **Determinism Test:** `transform(input)` MUST produce output that is deeply equal to a second invocation of `transform(input)` with the same input. Both structural equality (`deepStrictEqual`) and canonicalized string equality MUST hold.

2. **No-Network Test:** The kernel MUST execute without invoking `fetch`, `XMLHttpRequest`, or any other network API. The test stubs these APIs and fails if they are called during kernel execution.

3. **Snapshot Test:** `transform(examples/input.jsonld)` MUST produce output that matches `examples/expected-output.jsonld` when compared using canonicalized serialization.

4. **Kernel Purity Check:** Source files in `src/kernel/` MUST NOT import from any path outside `src/kernel/`. This is verified by static analysis of compiled output.
