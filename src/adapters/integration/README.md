# Integration Adapters

Integration adapters translate external formats into JSON-LD for the kernel and translate kernel output back for external consumers.

Examples: HTTP request handlers, file watchers, message queue consumers.

**Boundary rule:** Code in this directory MUST NOT be imported by `src/kernel/*`.

```
Layer 0: src/kernel/          <- Core (pure, no dependencies)
Layer 1: src/composition/     <- Optional
Layer 2: src/adapters/        <- Optional (you are here)
```

See [Adapter Boundaries](../../../docs/ADAPTER_BOUNDARIES.md) for rules and constraints.
