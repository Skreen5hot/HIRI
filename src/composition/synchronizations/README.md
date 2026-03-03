# Synchronizations

A Synchronization coordinates multiple Concepts in response to events. Synchronizations MUST be event-driven, MUST NOT contain business logic, and MUST NOT hold persistent state. They are thin orchestration glue between Concepts.

**Boundary rule:** Code in this directory MUST NOT be imported by `src/kernel/*`.

```
Layer 0: src/kernel/          <- Core (pure, no dependencies)
Layer 1: src/composition/     <- Optional (you are here)
Layer 2: src/adapters/        <- Optional
```

See [Composition Guide](../../../docs/COMPOSITION_GUIDE.md) for trigger semantics and boundary rules.
