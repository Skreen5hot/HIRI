# Persistence Adapters

Persistence adapters receive JSON-LD output from the kernel and store it in a storage system. **The kernel never reads from or writes to storage — persistence is entirely a shell concern.**

Examples: IndexedDB, file system, S3, PostgreSQL JSONB.

**Boundary rule:** Code in this directory MUST NOT be imported by `src/kernel/*`.

```
Layer 0: src/kernel/          <- Core (pure, no dependencies)
Layer 1: src/composition/     <- Optional
Layer 2: src/adapters/        <- Optional (you are here)
```

See [Adapter Boundaries](../../../docs/ADAPTER_BOUNDARIES.md) for rules and constraints.
