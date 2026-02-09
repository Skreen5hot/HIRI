# Edge-Canonical Agentic Development Startup Guide

**How to set up a high-quality, AI-assisted software project that runs anywhere, assumes nothing, and stays honest about what it knows.**

This guide codifies a development philosophy and practice for building software through human-AI pair programming under a strict set of architectural constraints. The goal is simple: every system you build should be runnable in a browser or via `node index.js`, with no hidden infrastructure, no false precision, and no accidental complexity. Cloud deployments, databases, and service meshes are derivative optimizations — never the baseline.

---

## Table of Contents

1. [Foundational Principles](#1-foundational-principles)
2. [The Edge-Canonical Constraint](#2-the-edge-canonical-constraint)
3. [Repository Structure](#3-repository-structure)
4. [The Agent Instructions File](#4-the-agent-instructions-file)
5. [Specification-Driven Development](#5-specification-driven-development)
6. [Test-Driven Development](#6-test-driven-development)
7. [The Planning-First Workflow](#7-the-planning-first-workflow)
8. [Scope Control: The v1/v2 Contract](#8-scope-control-the-v1v2-contract)
9. [Phased Delivery](#9-phased-delivery)
10. [JSON-LD as Canonical Representation](#10-json-ld-as-canonical-representation)
11. [Offline-First and Graceful Degradation](#11-offline-first-and-graceful-degradation)
12. [Separation of Concerns](#12-separation-of-concerns)
13. [Documentation as Architecture](#13-documentation-as-architecture)
14. [Security from Day One](#14-security-from-day-one)
15. [CI/CD and Automation](#15-cicd-and-automation)
16. [Dependency Philosophy](#16-dependency-philosophy)
17. [Working with the AI Agent](#17-working-with-the-ai-agent)
18. [Metrics and Quality Gates](#18-metrics-and-quality-gates)
19. [Anti-Patterns to Avoid](#19-anti-patterns-to-avoid)
20. [Starter Checklist](#20-starter-checklist)

---

## 1. Foundational Principles

Adopt these beliefs before writing a single line of code. They are not aspirational — they are constraints that make everything else possible.

### 1.1 Determinism Over Cleverness

Given the same inputs, the system must produce the same outputs. Hidden state, ambient services, and environment-coupled behavior are violations of the model unless explicitly isolated behind a declared adapter boundary. When you don't know something, say so explicitly in your data structures — don't guess. This makes your system auditable, testable, and trustworthy.

### 1.2 Correctness Before Coverage

It is better to handle 20 cases perfectly than 100 cases poorly. Resist the urge to add features before the core is rock-solid. An AI agent will happily generate code for edge cases all day — your job is to stop it and ask "is the foundation right first?"

### 1.3 Semantic Honesty

Don't force your system to produce answers it can't justify. If a piece of data is ambiguous, preserve the ambiguity and let the consumer decide. Structured uncertainty is always preferable to false precision. Systems that admit what they don't know are more trustworthy than systems that fabricate confidence.

### 1.4 Minimalism

Every dependency is a liability. Every abstraction is a maintenance cost. Every feature that isn't needed today is a distraction. The right amount of complexity is the minimum needed for the current task.

---

## 2. The Edge-Canonical Constraint

This is the architectural law that governs everything in this guide. It is intentionally restrictive — and intentionally liberating.

### The Rule

All systems specified under this guide must be able to run, unmodified, in a browser or via `node index.js`. This is the canonical execution model. Any cloud, server, or enterprise deployment is a derivative optimization, not the baseline assumption.

If a component cannot function under this constraint, it is **infrastructure**, not **core logic**, and must be treated as optional, pluggable, or out-of-scope for the core specification.

### No Required Infrastructure

Specifications must not assume the existence of:

- Databases
- Message brokers
- Service registries
- Background workers
- Addressable servers
- Deployment topologies

These may appear only as non-normative examples or adapter implementations, never as architectural requirements.

### The Spec Test

Before submitting any draft specification or architectural proposal, the author should be able to answer "yes" to the following question:

> Could a developer evaluate, reason about, and execute this system using only a browser, a local Node.js runtime, and JSON-LD files?

If the answer is "no," the spec needs to be revised.

### Why This Matters

This constraint forces clarity between essential computation and accidental infrastructure. It ensures that:

- Your core logic is portable across any environment
- New contributors can run the system immediately, with no provisioning
- Tests are deterministic and fast
- The system degrades gracefully rather than failing catastrophically
- You can reason about the system's behavior from its source code alone

---

## 3. Repository Structure

Set up your repository with clear separation of concerns from the start.

```
project/
├── src/                    # Source code, organized by subsystem
│   ├── core/               # Core computation (must run edge-canonical)
│   ├── adapters/           # Integration adapters (pluggable, optional)
│   ├── state/              # State management (pluggable backends)
│   └── data/               # Static data, registries, JSON-LD schemas
│
├── tests/                  # All tests
│   ├── unit/               # Unit tests per component
│   ├── integration/        # Full-system corpus validation
│   ├── browser/            # Browser-specific tests
│   └── README.md           # Test documentation
│
├── docs/                   # User and developer documentation
│   ├── architecture/       # Design decisions and rationale
│   ├── development/        # Development guides
│   ├── guides/             # User-facing guides
│   └── research/           # Research notes and references
│
├── planning/               # Sprint/phase planning documents
│   ├── phase1/
│   ├── phase2/
│   └── ...
│
├── deliverables/           # Milestone summaries and reports
│
├── schemas/                # JSON-LD context files and vocabularies
│
├── scripts/                # Build, test, and utility scripts
│
├── config/                 # Domain/environment configuration
│
├── dist/                   # Built artifacts
│
├── .claude/                # AI agent settings and permissions
│   └── settings.json
│
├── .github/
│   ├── workflows/          # CI/CD pipelines
│   └── dependabot.yml      # Dependency update automation
│
├── ROADMAP.md              # Living roadmap (the most important doc)
├── CLAUDE.md               # Agent instructions and project identity
├── README.md               # Quick start and overview
└── package.json            # Project metadata
```

### Key Principles

- **`src/core/` is sacred.** Everything in this directory must pass the edge-canonical spec test. No network calls, no database imports, no environment assumptions.
- **`src/adapters/` is the boundary.** All integration with external systems lives here. Adapters are pluggable and optional.
- **`schemas/` holds your contracts.** JSON-LD context files define the canonical representation for all inputs, outputs, and inter-component communication.
- **`planning/` is separate from `docs/`.** Planning documents are working documents for the development process. Docs are for users and future developers.
- **`deliverables/` captures milestones.** After each phase, write a summary of what was accomplished.
- **`ROADMAP.md` is the single source of truth.** This is the document the AI agent and the human both refer to constantly.

---

## 4. The Agent Instructions File

If your AI tool supports a project-level instructions file (Claude Code uses `CLAUDE.md` and `.claude/settings.json`), invest serious time in it. This is the "brain" that tells the AI agent what it can and cannot do.

### Permission Whitelisting

Start restrictive. Only allow what's needed:

```json
{
  "permissions": {
    "allow": [
      "Bash(node scripts/build.js:*)",
      "Bash(node tests/*:*)",
      "Bash(git add:*)",
      "Bash(git commit:*)",
      "Bash(git fetch:*)"
    ]
  }
}
```

### What to Include in Agent Instructions

1. **Project identity** — What the project is, what it is NOT
2. **Edge-canonical constraint** — Remind the agent that all core logic must run in a browser or via `node index.js`
3. **Architecture overview** — The key patterns the agent must follow, including the separation between core, adapters, and state
4. **JSON-LD contract** — All inputs and outputs use JSON-LD as the canonical format
5. **Naming conventions** — How files, classes, and variables are named
6. **Test requirements** — "Every new module must have a corresponding test file"
7. **Scope boundaries** — What is v1, what is deferred
8. **Build/test commands** — Exact commands to run
9. **Don't-do list** — "Don't add infrastructure dependencies to core," "Don't assume network availability," "Don't use external services in core computation"

The more context you give the agent upfront, the less you need to correct it mid-task.

---

## 5. Specification-Driven Development

This is the single most important practice for agentic development.

### Write the Spec Before the Code

For every significant feature, write a specification document BEFORE asking the AI to implement it. The spec should include:

1. **Problem statement** — What problem does this solve?
2. **API design** — What will the public interface look like? (code examples)
3. **Internal architecture** — How will it work internally?
4. **Edge-canonical verification** — Can this run in a browser? What adapters are needed?
5. **JSON-LD schema** — What do the inputs and outputs look like as JSON-LD?
6. **Test strategy** — What tests will prove it works? (specific test cases)
7. **Offline behavior** — What happens when external resources are unavailable?
8. **Success criteria** — How do we know when it's done?
9. **Scope boundaries** — What is explicitly NOT included?
10. **Bundle/performance budget** — Size and speed constraints

### Why This Matters for Agentic Development

An AI agent without a spec will over-engineer solutions, add features you didn't ask for, make architectural decisions that conflict with your vision, and introduce infrastructure dependencies that violate the edge-canonical constraint.

An AI agent WITH a spec will implement exactly what's described, follow the architectural patterns you've defined, keep core logic free of infrastructure assumptions, and stay within scope.

### Spec Template

```markdown
## Phase X.Y: Feature Name

**Goal:** One sentence describing the objective
**Status:** Not started / In progress / Complete
**Priority:** Critical / High / Medium / Low
**Effort:** Low / Medium / High
**Tests:** Expected test count
**Bundle Size Budget:** +NKB max
**Depends On:** Phase X.Z
**Edge-Canonical:** Yes / Requires adapter for [specific integration]

### Problem Statement
What problem does this solve? Why now?

### API Design
```javascript
// Show exact usage examples
const result = myModule.doThing(input, options);
```

### JSON-LD Contract
```json
{
  "@context": "https://yourproject.org/context/v1",
  "@type": "FeatureOutput",
  "result": "...",
  "confidence": 0.85,
  "uncertainties": []
}
```

### Separation of Concerns
| Layer | Responsibility | Edge-Canonical? |
|-------|---------------|-----------------|
| Computation | What is derived or reasoned | Yes (required) |
| State | How intermediate results are stored | Pluggable |
| Orchestration | How/when computation is invoked | Pluggable |
| Integration | How external world is contacted | Adapter only |

### Offline Behavior
What happens when external resources are unavailable?

### Deliverables
| File | Description |
|------|-------------|
| `src/core/MyModule.js` | Main implementation (edge-canonical) |
| `src/adapters/MyAdapter.js` | Optional integration adapter |
| `tests/unit/my-module.test.js` | Test suite |

### Test Coverage: N tests across M categories
| Category | Count | Description |
|----------|-------|-------------|
| Basic | 10 | Core functionality |
| Edge cases | 5 | Error handling |
| Offline | 3 | Degraded mode behavior |

### Success Criteria
- Criterion 1
- Criterion 2
- Runs in browser without modification
- Zero regression on existing tests
```

---

## 6. Test-Driven Development

### The Test Pyramid

```
                  /\
                 /  \
                /E2E \              Browser/acceptance tests
               /______\
              /        \
             /  Unit    \           Per-component isolation tests
            /  Tests     \         (the bulk of your tests)
           /______________\
          /                \
         /  Integration     \       Full-system corpus validation
        /   Tests            \     (golden test data)
       /______________________\
      /                        \
     /  Edge-Canonical          \   Browser execution verification
    /  Verification Tests        \ (prove it runs without infra)
   /______________________________\
```

### Golden Test Corpus

The single best testing investment is creating a golden test corpus — a set of real-world input/output pairs that define correct behavior.

1. **Collect real examples** of the inputs your system will process
2. **Define expected outputs** for each example as JSON-LD
3. **Run the corpus as your primary test** (`npm test` should run this)
4. **Track accuracy metrics** — coverage, precision, F1 scores
5. **Save metrics to a file** for historical tracking (e.g., `METRICS.json`)

### Edge-Canonical Verification Tests

Every core module should include a test that proves it runs in a browser-compatible environment:

```javascript
// Verify no Node.js-only APIs are required
test('runs without Node.js built-ins', () => {
  // Module should not require 'fs', 'path', 'http', etc.
  const result = myModule.process(input);
  expect(result).toBeDefined();
});

// Verify JSON-LD round-trip
test('input and output are valid JSON-LD', () => {
  const input = loadJsonLd('test-input.jsonld');
  const output = myModule.process(input);
  expect(output['@context']).toBeDefined();
  expect(JSON.parse(JSON.stringify(output))).toEqual(output);
});
```

### Test-First Workflow with an AI Agent

1. **You write the test spec** (what should be tested, expected results, JSON-LD schemas)
2. **Agent writes the test file** (from your spec)
3. **Agent runs the tests** (all should fail — nothing implemented yet)
4. **Agent implements the feature** (making tests pass one by one)
5. **Agent runs the full test suite** (no regressions)
6. **You review** the implementation against the spec and the edge-canonical constraint

### Performance Budgets as Tests

Set explicit performance targets and test them:

```javascript
const start = Date.now();
const result = processor.run(input);
const elapsed = Date.now() - start;
assert(elapsed < 50, `Processing took ${elapsed}ms, expected <50ms`);
```

---

## 7. The Planning-First Workflow

Every sprint or phase follows this cycle:

```
Plan → Spec → Edge-Canonical Check → Test Design → Implement → Validate → Document → Deliver
```

### Planning Documents

Before each phase, create a planning document:

```
planning/
├── phase1/
│   ├── INVENTORY.md          # What exists, what's needed
│   └── INTERFACES.md         # API and JSON-LD schema design
├── phase2/
│   └── IMPLEMENTATION_PLAN.md
```

These documents serve three purposes: alignment between human and AI agent on what to build; constraints that keep the agent within architectural boundaries; and history so future developers and future AI sessions can understand why decisions were made.

### Weekly Sprint Structure

| Day | Activity |
|-----|----------|
| Start | Review ROADMAP, write/update planning doc for the phase |
| Early | Design tests, write test specs, define JSON-LD schemas |
| Middle | Implement features (agent does the coding) |
| Late | Run full test suite, verify edge-canonical compliance |
| End | Write deliverable summary, update ROADMAP |

---

## 8. Scope Control: The v1/v2 Contract

This is one of the most important practices for working with an AI agent.

### The Problem

AI agents are enthusiastic. They will happily implement features you mentioned in passing, refactor code that's working fine, add abstractions "for future flexibility," and introduce infrastructure dependencies to solve problems you haven't encountered yet. Without scope control, you end up with a sprawling codebase that does many things poorly and can no longer run edge-canonical.

### The Solution: Explicit Scope Contract

Create a section in your ROADMAP that explicitly classifies every feature:

```markdown
## v1/v2 Scope Contract

### v1: [Mission Statement]
**Architectural constraint:** All v1 code must pass the edge-canonical spec test.

**v1 IN SCOPE (locked):**
- Feature A (bounded: only handles X, Y, Z)
- Feature B (edge-canonical, no adapters needed)
- All existing passing capabilities frozen

**v1 EXPLICITLY DEFERRED to v2:**
- Feature C (requires server-side orchestration — infrastructure, not core)
- Feature D (needs persistent state beyond in-memory — adapter work)
- Feature E (needs external API integration — adapter layer)
```

### Key Principles

1. **"Locked" means locked.** Once the scope contract is written, don't add to v1. New ideas go to v2.
2. **Bound every feature.** Don't just say "add modal detection." Say "add modal detection for shall, must, should — no conditional/subjunctive mood."
3. **Explain WHY things are deferred.** "Deferred to v2 because it requires a persistence adapter, which is infrastructure." This prevents the agent from trying to sneak it in.
4. **Use scope tags in your backlog.** Tag every enhancement as `[v1]` or `[v2]`.
5. **Flag infrastructure creep.** If a v1 feature starts requiring infrastructure, re-classify it or split it into a core piece (v1) and an infrastructure piece (v2).

### Enhancement Tracking

Maintain a backlog file (e.g., `enhancements_from_tests.md`) with enhancement ID, source, scope tag, priority and complexity, edge-canonical impact assessment, and a proposed fix specific enough for the agent to implement.

---

## 9. Phased Delivery

Break your project into numbered phases with clear deliverables and dependencies.

### Phase Structure

```markdown
### Phase 2.1: Feature Name

**Status:** Complete
**Tests:** 55 passing
**Depends On:** Phase 2.0
**Enables:** Phase 2.2
**Edge-Canonical:** Yes — all core logic runs in browser

**Deliverables:**
- `src/core/FeatureName.js`
- `schemas/feature-name.context.jsonld`
- `tests/unit/phase2/feature-name.test.js`
```

### Dependency Chain

Map your phases as a dependency graph:

```
Phase 1.0 → 1.1 → 1.2 → 1.3
                              ↘
                    Phase 2.0 → 2.1 → 2.2 → 2.3
                                                 ↘
                                       Phase 3.0 → 3.1 → 3.2
```

This prevents the agent from trying to implement Phase 2.2 before 2.1 is done.

### Backwards Compatibility via Opt-In Flags

When adding new capabilities, use opt-in flags to preserve backwards compatibility:

```javascript
// Old API (still works)
const result = processor.run(input);

// New API (opt-in)
const result = processor.run(input, { preserveAmbiguity: true });
```

---

## 10. JSON-LD as Canonical Representation

JSON-LD is the authoritative format for inputs, outputs, configuration, knowledge structures, and inter-component contracts.

### Why JSON-LD

- It is valid JSON, so it works everywhere JSON works
- It carries its own semantic context via `@context`
- It enables interoperability without requiring a shared database or service registry
- It runs natively in browsers
- It makes your data self-describing and linkable

### Canonical Contract Pattern

Every component should define its JSON-LD contract:

```json
{
  "@context": {
    "@vocab": "https://yourproject.org/vocab/",
    "schema": "https://schema.org/",
    "result": "schema:result",
    "confidence": "schema:confidenceLevel",
    "uncertainty": "schema:uncertainty"
  },
  "@type": "ProcessingResult",
  "result": "...",
  "confidence": 0.85,
  "uncertainties": [
    {
      "@type": "AmbiguityRecord",
      "source": "lexical",
      "alternatives": ["reading-a", "reading-b"]
    }
  ]
}
```

### Rules

- All inputs and outputs use JSON-LD as the canonical format
- Alternative internal representations are permitted only as optimizations
- Internal representations must be losslessly derivable from the JSON-LD form
- Configuration files use JSON-LD
- Test fixtures use JSON-LD
- Schema files live in `schemas/` and are versioned

---

## 11. Offline-First and Graceful Degradation

Inability to reach external systems is not an error state. This is a first-class design constraint, not an edge case.

### Required Offline Behaviors

Every specification must define valid behavior for:

- **Partial information** — What happens when some data is missing? The system should produce partial results with explicit uncertainty markers, not fail.
- **Deferred resolution** — When a lookup can't be performed now, the system should produce a deferred-resolution token that can be resolved later.
- **Degraded execution** — When optional enrichment services are unavailable, the system should produce a baseline result and document what was skipped.
- **Explicit uncertainty** — When the system can't determine something, it should say so in the output schema, not guess.

### Pattern: Deferred Resolution Token

```json
{
  "@type": "DeferredResolution",
  "requestedResource": "https://example.org/ontology/v2",
  "fallbackUsed": "local-cache-v1",
  "resolvedAt": null,
  "degradedFields": ["enrichedLabel", "externalClassification"]
}
```

### Pattern: Uncertainty Envelope

```json
{
  "@type": "UncertainResult",
  "bestGuess": "reading-a",
  "alternatives": ["reading-b", "reading-c"],
  "confidenceDistribution": {
    "reading-a": 0.6,
    "reading-b": 0.3,
    "reading-c": 0.1
  },
  "reason": "lexical-ambiguity"
}
```

---

## 12. Separation of Concerns

Every specification must clearly distinguish between four layers. Only the first is core. The rest must be pluggable.

### The Four Layers

| Layer | Responsibility | Edge-Canonical? | Examples |
|-------|---------------|-----------------|----------|
| **Computation** | What is being derived or reasoned | **Yes — required** | Parsing, classification, scoring, transformation |
| **State** | How intermediate results are stored or resumed | Pluggable | In-memory map, localStorage, IndexedDB, Redis adapter |
| **Orchestration** | How and when computation is invoked | Pluggable | Direct call, event loop, message queue adapter |
| **Integration** | How the external world is contacted | Adapter only | HTTP fetch, file system, API clients |

### Implementation Pattern

```javascript
// Core computation — edge-canonical, no dependencies
export function classify(input, ontology) {
  // Pure function: input → output
  // No network calls, no database, no file system
  return { classification, confidence, uncertainties };
}

// State adapter — pluggable
export const memoryStateAdapter = {
  save(key, value) { this.store.set(key, value); },
  load(key) { return this.store.get(key); }
};

// Integration adapter — pluggable, optional
export const httpOntologyAdapter = {
  async fetchOntology(uri) {
    try {
      const response = await fetch(uri);
      return await response.json();
    } catch {
      return { deferred: true, uri };
    }
  }
};
```

### The Rule

If you find yourself writing `import http` or `import fs` in a file under `src/core/`, stop. That code belongs in `src/adapters/`.

---

## 13. Documentation as Architecture

Documentation isn't an afterthought — it's a design tool.

### Documentation Hierarchy

| Document | Audience | Purpose |
|----------|----------|---------|
| `README.md` | New users | Quick start, features, installation |
| `ROADMAP.md` | Developers + AI agent | Vision, architecture, phase plan, scope |
| `CLAUDE.md` | AI agent | Project identity, constraints, don't-do list |
| `docs/architecture/` | Senior developers | Design decisions and rationale |
| `docs/guides/` | Users | How-to guides for specific features |
| `schemas/` | All consumers | JSON-LD contracts and vocabularies |
| `planning/` | Development team | Sprint-level implementation plans |
| `deliverables/` | Stakeholders | What was accomplished each phase |

### The ROADMAP.md

This is the most important file in the repository. It should contain:

1. **Vision statement** — What the project IS and IS NOT
2. **Edge-canonical commitment** — Explicit statement of the architectural constraint
3. **Architecture philosophy** — Key design decisions
4. **JSON-LD schema overview** — Canonical representations
5. **Completed phases** — What's been built, with test counts
6. **Current phase** — Detailed spec of what's being built now
7. **Future phases** — Specs for upcoming work
8. **v1/v2 scope contract** — What's in and out
9. **Bundle/performance budgets** — Size and speed constraints
10. **Version history** — When each phase was completed

Keep this file updated after every phase. It is the primary context document for new AI sessions.

### Lessons Learned Sections

After each phase, add a "Lessons Learned" section:

```markdown
### Phase N Lessons Learned

**What Worked Well:**
- Keeping computation pure enabled instant browser testing
- JSON-LD contracts caught integration mismatches early

**What Could Be Improved:**
- Adapter interface was underspecified, causing inconsistency
- Need clearer boundary between state and orchestration

**Edge-Canonical Notes:**
- Module X initially required fs — refactored to accept data as parameter
- Offline behavior for Y was undertested
```

---

## 14. Security from Day One

Don't bolt on security later. Build it in from the start.

### Security Module Structure

```
src/
├── core/
│   └── security/
│       ├── input-validator.js       # Input size limits, pattern checks
│       ├── semantic-validators.js   # Domain-specific attack detection
│       └── output-sanitizer.js      # XSS/injection prevention
└── adapters/
    └── security/
        ├── audit-logger.js          # Security event logging (pluggable)
        └── integrity-checker.js     # File integrity verification
```

Note that input validation and output sanitization are **core computation** — they must be edge-canonical. Audit logging and integrity checking may require adapters.

### Trust Boundaries

| Input Source | Trust Level | Validation |
|-------------|-------------|------------|
| User-provided data | Untrusted | Size limits, pattern checks, sanitization |
| JSON-LD configuration | Conditionally trusted | Schema validation |
| External ontologies | Conditionally trusted | Integrity checks, deferred resolution |
| Your own code | Trusted | Code review, CI/CD |

### Security Testing

Maintain a dedicated security test suite that includes input validation tests (malformed input, oversized input, injection attempts), output sanitization tests, a red team corpus (adversarial inputs designed to break the system), and JSON-LD schema validation tests.

---

## 15. CI/CD and Automation

### GitHub Actions Setup

At minimum, set up these workflows:

**1. Build and Test Pipeline:**
- Triggers on push to main
- Runs `npm install` and `npm run build`
- Runs `npm test` (including edge-canonical verification tests)
- Runs browser-environment tests
- Deploys artifacts

**2. Security Pipeline:**
- Triggers on push, pull request, and weekly schedule
- Runs `npm audit`
- Runs security-specific tests
- Verifies JSON-LD schema integrity

### Edge-Canonical CI Check

Add a CI step that verifies no core module imports infrastructure:

```bash
# Fail if any core file imports Node.js built-ins
grep -r "require('fs')\|require('http')\|require('path')\|require('net')" src/core/ && exit 1
echo "Edge-canonical check passed"
```

### Dependabot

Enable automated dependency updates with weekly scanning and conservative pull request limits.

---

## 16. Dependency Philosophy

### The Minimalist Rule

Before adding a dependency, ask:

1. **Can we write it ourselves in under 200 lines?** If yes, write it yourself.
2. **Is this a core competency of the project?** If yes, own it.
3. **Does it work in both browser and Node.js?** If not, it cannot be a core dependency.
4. **What's the bundle size impact?** Set a budget and enforce it.
5. **What's the supply chain risk?** Every dependency is a potential CVE.
6. **Does it introduce infrastructure assumptions?** If it requires a database, a server, or a specific runtime, it's an adapter concern.

### Custom Over External

The AI agent can write high-quality implementations of focused modules faster than you can evaluate and integrate a third-party library. Custom modules give you zero new dependencies, full control over behavior, smaller bundle size, and guaranteed edge-canonical compliance.

### Dependency Classification

| Category | Rule |
|----------|------|
| Core dependencies | Must work in browser AND Node.js. As few as possible. |
| Adapter dependencies | Allowed in `src/adapters/` only. Must not leak into core. |
| Dev dependencies | Keep minimal. Prefer built-in tooling. |

---

## 17. Working with the AI Agent

### Session Management

Each AI session starts fresh or with limited context. To make sessions productive:

1. **Point the agent to ROADMAP.md first.** This gives it the full project context.
2. **Remind it of the edge-canonical constraint.** "All core logic must run in a browser."
3. **Reference the specific phase spec.** "Implement Phase 2.1 as described in ROADMAP.md."
4. **Give it the test file first.** "Here are the tests. Make them pass."
5. **Set explicit scope.** "Only modify files in src/core/. Don't touch src/adapters/."

### Effective Prompting Patterns

**Good:** "Implement Phase 2.1 as specified in ROADMAP.md. This is a core computation module — it must have zero infrastructure dependencies and work in a browser. Create the file at src/core/FeatureName.js, the JSON-LD schema at schemas/feature-name.context.jsonld, and tests at tests/unit/phase2/feature-name.test.js. Run the tests when done."

**Bad:** "Add a feature name module to the project." (Too vague — agent will invent its own design and likely introduce infrastructure.)

### The Human's Role

When working with an AI agent, the human's job shifts from writing code to:

1. **Architecting** — Design the system, write specs, define JSON-LD contracts, enforce the edge-canonical constraint
2. **Reviewing** — Check the agent's output against the spec, verify no infrastructure crept into core
3. **Scoping** — Decide what's v1 vs v2, what to build now vs later
4. **Testing judgment** — Decide if the tests are meaningful, not just passing
5. **Course-correcting** — When the agent drifts toward infrastructure or scope creep, pull it back

### What the AI Agent Does Well

- Implementing well-specified modules from a clear spec
- Writing large test suites with many cases
- Generating JSON-LD schemas from examples
- Refactoring code to match a pattern you've defined
- Finding and fixing bugs when given a failing test
- Generating documentation from existing code
- Building CI/CD pipelines from a description

### What Requires Human Judgment

- Architectural decisions (what is core vs adapter)
- Scope control (what to build now vs later)
- Edge-canonical enforcement (did infrastructure sneak in?)
- Quality assessment (are these tests actually testing the right thing?)
- Dependency decisions (add a library vs build it yourself)
- Security threat modeling (what are the attack vectors?)

---

## 18. Metrics and Quality Gates

### Track These Metrics

| Metric | How to Measure | Target |
|--------|---------------|--------|
| Test count | Count of test cases | Growing every phase |
| Test pass rate | Passing / Total | 100% |
| Accuracy | Correct outputs / Total corpus items | Domain-specific target |
| Bundle size | File size of built artifact | Under budget ceiling |
| Processing time | Milliseconds per operation | <50ms (or your target) |
| Dependency count | `npm ls --depth=0` | As few as possible |
| CVE count | `npm audit` | 0 high/critical |
| Edge-canonical compliance | Core modules with zero infra imports | 100% |
| JSON-LD validity | Schemas that pass validation | 100% |
| Offline test pass rate | Tests that run without network | 100% of core tests |

### Quality Gates

Before merging any phase:

- All tests passing (`npm test`)
- Security tests passing
- Bundle builds successfully
- Bundle size within budget
- Performance within target
- No regressions in existing functionality
- Edge-canonical spec test passes (runs in browser, no infra)
- JSON-LD schemas valid
- Offline behavior tested
- ROADMAP.md updated with completion status
- Deliverable summary written

---

## 19. Anti-Patterns to Avoid

### 1. "Just Build It" Without a Spec

Starting implementation before writing a specification leads to code that doesn't fit the architecture, tests that test implementation details instead of behavior, scope creep, and infrastructure dependencies that violate the edge-canonical constraint.

### 2. Infrastructure Creep into Core

The most insidious anti-pattern. It starts with "just this one database call in core" and ends with a system that can't run without provisioning three services. Enforce the boundary ruthlessly. If it touches the network or the file system, it's an adapter.

### 3. Trusting the Agent Without Reviewing

AI agents write confident, well-structured code that is sometimes subtly wrong. Always read the code the agent produced, verify it matches the spec, verify no infrastructure leaked into core, run the tests yourself, and check for security implications.

### 4. Skipping the v1/v2 Classification

Every enhancement request should be immediately classified. If you don't do this, the agent will try to address everything at once and the edge-canonical constraint will erode.

### 5. Giant Monolithic Phases

Phases should be small enough to complete in 1–3 sessions. Small phases mean frequent wins and easier debugging.

### 6. No Performance Budget

If you don't set bundle size and performance budgets, the codebase will bloat. Track bundle size at every phase with explicit budgets.

### 7. Ignoring Test Failures

A failing test is a spec violation. Fix it immediately or update the spec. Never leave failing tests in the codebase.

### 8. Documentation Drift

If ROADMAP.md says one thing and the code does another, the next AI session will be confused and produce inconsistent work.

### 9. "We'll Add Offline Support Later"

Offline behavior is not a feature — it's a design constraint. If you don't design for it from the start, retrofitting it requires architectural changes that touch everything.

### 10. Treating JSON-LD as Optional

If components communicate via ad-hoc JSON shapes, you lose semantic interoperability, self-describing data, and the ability to validate contracts. JSON-LD is the canonical format. Use it from day one.

---

## 20. Starter Checklist

### Day 1: Foundation
- [ ] Create repository with the directory structure from Section 3
- [ ] Write `README.md` with project identity and quick start
- [ ] Write `ROADMAP.md` with vision statement, edge-canonical commitment, and Phase 1 spec
- [ ] Write `CLAUDE.md` with agent instructions including edge-canonical constraint
- [ ] Set up `.claude/settings.json` with restrictive permissions
- [ ] Create initial JSON-LD context file in `schemas/`
- [ ] Initialize `package.json`
- [ ] Create `.github/workflows/` with build, test, and security pipelines
- [ ] Add edge-canonical CI check
- [ ] Enable Dependabot

### Day 2: Test Infrastructure
- [ ] Create `tests/` directory with unit/, integration/, browser/, and README.md
- [ ] Collect or create golden test corpus with JSON-LD fixtures
- [ ] Write first integration test (runs corpus, reports accuracy)
- [ ] Write edge-canonical verification tests
- [ ] Write offline behavior tests
- [ ] Set up `npm test` to run all tests
- [ ] Establish performance and bundle size budgets

### Day 3: Phase 1
- [ ] Write Phase 1 specification in ROADMAP.md (follow the template in Section 5)
- [ ] Verify spec passes the edge-canonical spec test
- [ ] Define JSON-LD schemas for Phase 1 inputs and outputs
- [ ] Write test files for Phase 1 (tests should fail — nothing implemented yet)
- [ ] Implement Phase 1 (agent writes code to make tests pass)
- [ ] Verify all core code is in `src/core/` with no infrastructure imports
- [ ] Run full test suite, verify no regressions
- [ ] Update ROADMAP.md with completion status and lessons learned
- [ ] Write deliverable summary in `deliverables/phase1/`

### Ongoing
- [ ] Classify every new idea as v1 or v2 immediately
- [ ] Write spec before implementation for every phase
- [ ] Enforce edge-canonical constraint at every review
- [ ] Track metrics after every test run
- [ ] Update ROADMAP.md after every phase completion
- [ ] Review agent output against the spec AND the architectural constraints
- [ ] Periodically run the spec test: "Can this run with only a browser, Node.js, and JSON-LD files?"

---

## Summary

The edge-canonical agentic development process can be summarized as:

**Write the spec. Verify it runs at the edge. Write the tests. Let the agent implement. Verify against the spec and the constraint.**

Everything else — the phased delivery, the scope contract, the JSON-LD contracts, the offline-first design, the separation of concerns — exists to support that core loop.

The human provides judgment, architecture, and quality control. The AI agent provides implementation speed and thoroughness. The edge-canonical constraint provides discipline. Together, they produce systems that are portable, auditable, testable, and honest about what they know — systems that run anywhere, assume nothing, and degrade gracefully when the world is less than perfect.

These constraints exist to force clarity between essential computation and accidental infrastructure. They are intentionally restrictive — and intentionally liberating.

---

*This guide is based on practices developed through human-AI collaborative software engineering (2025–2026), refined across multiple projects built under edge-canonical architectural constraints. The methodology produced production-ready systems with comprehensive test coverage — built in weeks rather than months — that run identically in browsers and on servers with zero infrastructure dependencies.*
