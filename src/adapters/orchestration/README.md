# Orchestration Adapters

Orchestration adapters handle scheduling, retries, distribution, and lifecycle management around kernel execution. They trigger kernel invocations but MUST NOT affect kernel determinism.

Examples: cron jobs, queue workers, serverless function handlers, CI steps.

**Boundary rule:** Code in this directory MUST NOT be imported by `src/kernel/*`.

```
Layer 0: src/kernel/          <- Core (pure, no dependencies)
Layer 1: src/composition/     <- Optional
Layer 2: src/adapters/        <- Optional (you are here)
```

See [Adapter Boundaries](../../../docs/ADAPTER_BOUNDARIES.md) for rules and constraints.
