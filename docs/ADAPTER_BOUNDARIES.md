# Adapter Boundaries

Adapters connect the kernel and composition layer to external infrastructure. This document defines the rules governing adapter integration.

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" are to be interpreted as described in RFC 2119.

---

## 1. Integration Boundary

The integration boundary is where external data enters the system.

Adapters at this boundary translate external formats into JSON-LD for the kernel, and translate kernel output back into formats required by external consumers.

### Examples

- HTTP request handler: receives a POST body, wraps it in JSON-LD, invokes the kernel, returns the response.
- File watcher: detects file changes, reads the file, invokes the kernel with the content.
- Message queue consumer: dequeues a message, transforms it to JSON-LD, invokes the kernel.

### Rules

- Integration adapters MUST NOT modify kernel semantics. They translate formats, not logic.
- Integration adapters MUST validate external input before passing it to the kernel.
- Integration adapters SHOULD handle serialization/deserialization at the boundary.

---

## 2. Persistence Boundary

The persistence boundary is where transformed data is stored.

Adapters at this boundary receive JSON-LD output from the kernel and persist it to a storage system.

### Examples

- IndexedDB adapter: stores JSON-LD documents in the browser's IndexedDB.
- File system adapter: writes JSON-LD output to `.jsonld` files.
- S3 adapter: uploads JSON-LD documents to an object store.
- PostgreSQL adapter: stores JSON-LD in a JSONB column.

### Rules

- Persistence adapters MUST be replaceable without affecting kernel behavior.
- Persistence adapters MUST NOT require kernel changes when switching storage backends.
- Persistence adapters MUST handle their own connection management, retries, and error recovery.
- Persistence adapters MUST NOT inject state into the kernel.

---

## 3. Orchestration Boundary

The orchestration boundary is where scheduling, retries, distribution, and lifecycle management occur.

Adapters at this boundary invoke the kernel on schedule or in response to external triggers, managing the operational concerns that surround kernel execution.

### Examples

- Cron job: invokes the kernel on a schedule with stored input documents.
- Queue worker: processes a backlog of transformation requests.
- Serverless function handler: wraps the kernel in an AWS Lambda or Cloudflare Worker.
- CI/CD pipeline step: runs the kernel as a build step to validate or transform data.

### Rules

- Orchestration adapters MUST NOT affect kernel determinism. The kernel MUST produce the same output regardless of how it was invoked.
- Orchestration adapters MUST handle retries, timeouts, and error recovery outside the kernel.
- Orchestration adapters SHOULD log invocation metadata (timing, source) separately from kernel output.

---

## Summary of Adapter Rules

1. Adapters MUST NOT modify kernel semantics.
2. Adapters MUST be replaceable without kernel changes.
3. The kernel MUST remain testable without any adapters present.
4. Adapters MUST handle their own error recovery.
5. Adapters MUST NOT inject state into the kernel.
6. Adapter code MUST NOT reside in `src/kernel/`. The kernel purity check enforces this.
