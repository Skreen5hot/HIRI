# Computation Model

This document defines the formal computation model for the kernel. It is a specification, not a tutorial.

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" are to be interpreted as described in RFC 2119.

---

## 1. Kernel Definition

The kernel is defined as a pure function:

    transform : JSON-LD Document → JSON-LD Document

The kernel accepts a single JSON-LD document as input and produces a single JSON-LD document as output. No other inputs or outputs are permitted during kernel execution.

---

## 2. Input Contract

- Input MUST be a valid JSON object.
- Input MUST include an `@context` property (JSON-LD requirement).
- Input MAY include any additional JSON-LD properties.
- The kernel MUST NOT modify the input object. The input MUST be treated as immutable.
- If input is `null`, not an object, or missing `@context`, the kernel MUST return a well-formed error output (see Section 7) rather than throwing an exception.

---

## 3. Output Contract

- Output MUST be a valid JSON object.
- Output MUST include an `@context` property.
- Output MUST be fully serializable to JSON (no functions, symbols, undefined values, or circular references).
- Output MUST include a `provenance` object (see Section 5).
- Output SHOULD be canonicalized — object keys recursively sorted — to support deterministic comparison.

---

## 4. Determinism Requirements

Given identical input, the kernel MUST produce bit-identical output when serialized through the canonical serializer (`stableStringify`).

The kernel MUST NOT reference or depend on:

- Current time: `Date.now()`, `new Date()`, `performance.now()`
- Random values: `Math.random()`, `crypto.getRandomValues()`
- Environment variables: `process.env`
- File system state (beyond the input document itself)
- Network resources: `fetch`, `XMLHttpRequest`, WebSocket
- Global mutable state not provided as input
- Platform-specific behavior that varies across runtimes

---

## 5. Provenance & Trace

Every kernel output MUST include a `provenance` object with the following structure:

```json
{
  "@type": "Provenance",
  "kernelVersion": "0.1.0",
  "rulesApplied": ["identity"]
}
```

### Required Fields

- `@type`: MUST be `"Provenance"`.
- `kernelVersion`: MUST be a semantic version string matching the template version. MUST be a static string literal in the kernel source — not read from `package.json` or any external source at runtime.
- `rulesApplied`: MUST be an ordered array of string identifiers naming the transformation rules that were applied, in the order they were applied. For the identity transform, this is `["identity"]`.

### Optional Fields

- `inputDigest`: A deterministic hash of the canonicalized input. If included, it MUST be computed from `stableStringify(input)` using a deterministic hashing algorithm. This field is optional in v0.1.0.

### Constraints

- Provenance MUST be deterministic. It MUST NOT contain timestamps, random identifiers, or any non-deterministic value.
- Provenance MUST be reproducible: given the same input and the same kernel version, provenance MUST be identical.

---

## 6. Uncertainty & Partial Resolution

If the kernel cannot fully resolve a transformation, it MUST still produce valid JSON-LD output. The kernel MUST NOT throw exceptions for valid JSON-LD input.

Unresolved elements SHOULD be annotated with an uncertainty marker using the following vocabulary:

```json
{
  "uncertainty": {
    "@type": "Uncertainty",
    "status": "deferred",
    "reason": "Dependent value not resolvable in this context",
    "references": []
  }
}
```

### Status Values

- `"deferred"`: The resolution is postponed to a later stage or a different adapter.
- `"assumed"`: A default or heuristic value was used; the result may change with better input.
- `"unknown"`: The kernel cannot determine a value and makes no assumption.

### Constraints

- `status` MUST be one of: `"deferred"`, `"assumed"`, `"unknown"`.
- `reason` MUST be a human-readable string explaining why resolution failed.
- `references` MAY contain an array of node identifiers (strings) related to the uncertainty.

---

## 7. Error Handling

When the kernel receives invalid input (not an object, missing `@context`, malformed JSON-LD), it MUST return a well-formed JSON-LD error object rather than throwing an exception.

### Error Output Structure

```json
{
  "@context": "https://schema.org",
  "@type": "Error",
  "errorCode": "INVALID_CONTEXT",
  "error": "Input must include @context property",
  "provenance": {
    "@type": "Provenance",
    "kernelVersion": "0.1.0",
    "rulesApplied": []
  }
}
```

### Error Code Taxonomy

| Code | Condition |
|------|-----------|
| `INVALID_INPUT` | Input is null or not an object |
| `INVALID_CONTEXT` | Input is missing the `@context` property |
| `MALFORMED_JSONLD` | Input has structural issues preventing transformation |
| `MISSING_MANDATORY_NODE` | A required node for the specific transform is absent |

Error codes MUST be stable across versions — tests MAY assert on specific error codes.

---

## 8. Canonicalization

The kernel SHOULD produce canonicalized output to ensure deterministic serialization.

### Canonicalization Rules

1. **Object keys** MUST be sorted lexicographically (Unicode code point order), recursively for nested objects.
2. **Ordered arrays** (where element order is semantically meaningful) MUST preserve their original order.
3. **Unordered arrays** (where element order is not semantically meaningful) SHOULD be sorted by the stable serialized form of each element.
4. **Numbers** MUST use standard JSON number representation (no trailing zeros in decimals, no leading zeros in integers).
5. **Booleans** MUST be `true` or `false` (lowercase, as required by JSON).
6. **Null** MUST be represented as `null`.

The `stableStringify` function in `src/kernel/canonicalize.ts` implements these rules. The CLI entry point uses this function for output serialization.
