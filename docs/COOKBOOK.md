# Cookbook

Practical recipes for building on this template.

---

## How do I expose this as an HTTP API?

Create an integration adapter in `src/adapters/integration/`. The adapter handles HTTP concerns; the kernel stays pure.

```ts
// src/adapters/integration/http-server.ts
import { createServer, IncomingMessage } from "node:http";
import { transform } from "../../kernel/transform.js";
import { stableStringify } from "../../kernel/canonicalize.js";

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf-8");
}

const server = createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/transform") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
    return;
  }

  let input: unknown;
  try {
    input = JSON.parse(await readBody(req));
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid JSON" }));
    return;
  }

  const result = transform(input);
  const status = "errorCode" in result ? 422 : 200;
  res.writeHead(status, { "Content-Type": "application/ld+json" });
  res.end(stableStringify(result, true));
});

server.listen(3000, () => {
  console.log("Transform API listening on http://localhost:3000/transform");
});
```

This uses only `node:http` — no runtime dependencies. For Express or Fastify, the pattern is the same: wrap the `transform()` call in a route handler. The adapter handles request parsing, error mapping, and response serialization. The kernel never sees HTTP.

---

## How do I add a database?

Create a persistence adapter in `src/adapters/persistence/`.

**Persistence is a shell concern. The kernel never reads from or writes to storage.**

```ts
// src/adapters/persistence/file-store.ts
import { writeFile, readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { stableStringify } from "../../kernel/canonicalize.js";
import type { TransformOutput } from "../../kernel/transform.js";

export class FileStore {
  constructor(private dir: string) {}

  async save(id: string, doc: TransformOutput): Promise<void> {
    await mkdir(this.dir, { recursive: true });
    const path = join(this.dir, `${id}.jsonld`);
    await writeFile(path, stableStringify(doc, true), "utf-8");
  }

  async load(id: string): Promise<TransformOutput> {
    const path = join(this.dir, `${id}.jsonld`);
    const raw = await readFile(path, "utf-8");
    return JSON.parse(raw) as TransformOutput;
  }
}
```

For a real database (PostgreSQL, SQLite, etc.), the interface is the same: `save(id, doc)` and `load(id)`. Swap the implementation without touching the kernel.

---

## How do I handle JSON-LD context expansion?

### Why the kernel does not expand contexts

The kernel MUST NOT perform network I/O (Architecture Principle 6). JSON-LD context expansion requires fetching remote `@context` URLs, which violates this constraint.

**Kernel MUST assume all contexts are already locally resolvable.** Context expansion is an adapter concern.

### Strategy 1: Embedded contexts (recommended)

Include the full context inline instead of referencing a URL:

```json
{
  "@context": {
    "@vocab": "https://schema.org/",
    "name": "https://schema.org/name",
    "startDate": "https://schema.org/startDate"
  },
  "@type": "Event",
  "name": "Example"
}
```

The kernel processes this directly — no expansion needed.

### Strategy 2: Pre-resolved contexts at the adapter boundary

Resolve remote contexts in an integration adapter BEFORE passing input to the kernel:

```ts
// src/adapters/integration/context-resolver.ts
import { transform } from "../../kernel/transform.js";

const CONTEXT_CACHE: Record<string, Record<string, unknown>> = {
  "https://schema.org": {
    "@vocab": "https://schema.org/",
  },
};

export function transformWithResolvedContext(input: unknown): unknown {
  const doc = input as Record<string, unknown>;
  const ctx = doc["@context"];

  if (typeof ctx === "string" && CONTEXT_CACHE[ctx]) {
    return transform({ ...doc, "@context": CONTEXT_CACHE[ctx] });
  }

  return transform(input);
}
```

### Strategy 3: Static context maps for controlled vocabularies

For services operating on a known set of vocabularies, maintain a static map shipped with the adapter:

```
src/adapters/integration/
  contexts/
    schema-org.json      # Pre-resolved Schema.org context
    activity-streams.json  # Pre-resolved ActivityStreams context
```

Load at adapter startup, inject inline before calling the kernel.

### Which strategy to choose

| Scenario | Strategy |
|----------|----------|
| You control the input documents | Embedded contexts |
| You consume external documents with remote `@context` | Pre-resolved at adapter boundary |
| You operate on a fixed set of vocabularies | Static context maps |
| You need full JSON-LD processing (compaction, framing) | Use `jsonld` library in an adapter |

In all cases, the kernel receives a document with a locally resolvable `@context` — it never fetches anything.

---

## How do I handle multiple transform pipelines?

Use the composition layer. Create a Concept for each pipeline stage:

```ts
// src/composition/concepts/validator.ts
import { transform } from "../../kernel/transform.js";

export const validatorConcept = {
  state: { lastResult: null as unknown },
  actions: {
    validate(input: unknown) {
      const result = transform(input);
      validatorConcept.state.lastResult = result;
      validatorConcept.notify("validated", result);
      return result;
    },
  },
  _subscribers: [] as Array<(event: string, payload: unknown) => void>,
  subscribe(fn: (event: string, payload: unknown) => void) {
    this._subscribers.push(fn);
  },
  notify(event: string, payload: unknown) {
    for (const fn of this._subscribers) fn(event, payload);
  },
};
```

Wire stages together with a Synchronization:

```ts
// src/composition/synchronizations/pipeline.ts
import { validatorConcept } from "../concepts/validator.js";
import { enricherConcept } from "../concepts/enricher.js";

validatorConcept.subscribe((event, payload) => {
  if (event === "validated" && !("errorCode" in (payload as any))) {
    enricherConcept.actions.enrich(payload);
  }
});
```

Each stage calls `transform()` through its Concept. Synchronizations coordinate them via events — no lifecycle engine, no framework. See [Composition Guide](./COMPOSITION_GUIDE.md) for the full specification.

---

## How do I test my domain logic?

See [Testing Guide](./TESTING_GUIDE.md) for patterns covering:

- Testing individual transformation rules
- Testing error handling
- Testing Uncertainty annotations
- Testing provenance tracking
