# Composition Guide

> **This layer is OPTIONAL.** The kernel functions without it. Everything described here exists at Layer 1 — above the kernel, below the adapters.

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" are to be interpreted as described in RFC 2119.

---

## 1. Concepts

A Concept is an independent module representing a single domain entity or capability. Concepts encapsulate state, expose actions, and communicate through events.

### Definition

```ts
interface Concept<TState> {
  state: TState;
  actions: Record<string, (...args: unknown[]) => unknown>;
  subscribe(callback: (event: string, payload: unknown) => void): void;
  notify(event: string, payload: unknown): void;
}
```

### Constraints

- Each Concept MUST be a singleton — one instance per domain entity.
- Concepts MUST manage their own state. No shared mutable state between Concepts.
- Concepts MUST NOT call other Concepts directly. Use events or Synchronizations instead.
- Concepts MAY invoke the kernel `transform()` function to perform transformations.

### Example: Invoking the Kernel from a Concept

```ts
// Run this with: node concept-example.js

import { transform } from "./dist/kernel/transform.js";

const documentConcept = {
  state: { current: null },

  actions: {
    process(input) {
      const result = transform(input);
      documentConcept.state.current = result;
      documentConcept.notify("processed", result);
      return result;
    },
  },

  _subscribers: [],
  subscribe(fn) { this._subscribers.push(fn); },
  notify(event, payload) {
    for (const fn of this._subscribers) fn(event, payload);
  },
};
```

This demonstrates how Layer 1 invokes Layer 0: the Concept calls `transform()` and stores the result. The kernel remains pure — all side effects (state mutation, event emission) happen in the Concept.

---

## 2. Synchronizations

A Synchronization coordinates multiple Concepts in response to events. It is the composition glue.

### Definition

A Synchronization subscribes to events from one or more Concepts and invokes actions on other Concepts in response.

### Trigger Semantics

- Synchronizations MUST be event-driven, not polling-based.
- Synchronizations MUST NOT contain business logic. Logic belongs in Concepts or the kernel.
- Synchronizations SHOULD be thin — a few lines of orchestration, not computation.

### Boundary Rules

- Synchronizations MUST NOT call the kernel directly. They orchestrate Concepts, which call the kernel.
- Synchronizations MUST NOT hold persistent state. If state is needed, delegate to a Concept.

### Example

```ts
// Synchronization: when a document is processed, log the result
documentConcept.subscribe((event, payload) => {
  if (event === "processed") {
    logConcept.actions.append(payload);
  }
});
```

---

## 3. Sessions

A Session captures the state of a composition at a point in time. Sessions enable undo, replay, and serialization.

### State Snapshot Pattern

- A Session MUST be serializable to JSON (and optionally to JSON-LD for kernel compatibility).
- Sessions exist at the composition layer, not the kernel. The kernel is stateless.
- To create a Session snapshot, collect the `state` property from each active Concept.
- To restore a Session, assign the snapshot back to each Concept's `state`.

### Constraints

- Session snapshots MUST NOT include functions, event subscribers, or non-serializable values.
- Session restore MUST NOT bypass Concept action interfaces for side effects.

---

## 4. Adapter Boundaries

Composition patterns MUST NOT depend on specific adapters. A Concept that works with IndexedDB today MUST work with a file system adapter tomorrow without changing its interface.

For detailed adapter rules, see [ADAPTER_BOUNDARIES.md](./ADAPTER_BOUNDARIES.md).
