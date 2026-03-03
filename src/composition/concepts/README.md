# Concepts

A Concept is an independent module representing a single domain entity or capability. Concepts encapsulate state, expose actions, and communicate through events. They MAY invoke the kernel `transform()` function but MUST NOT contain infrastructure logic.

**Boundary rule:** Code in this directory MUST NOT be imported by `src/kernel/*`.

```
Layer 0: src/kernel/          <- Core (pure, no dependencies)
Layer 1: src/composition/     <- Optional (you are here)
Layer 2: src/adapters/        <- Optional
```

See [Composition Guide](../../../docs/COMPOSITION_GUIDE.md) for the full specification, interface definition, and examples.
