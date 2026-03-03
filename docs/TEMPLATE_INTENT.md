# Template Intent

This template is intentionally minimal.

The kernel (`src/kernel/transform.ts`) is the only required runtime piece. It defines a pure function that transforms JSON-LD documents deterministically, with no infrastructure dependencies, no framework overhead, and no runtime assumptions beyond a standard JavaScript environment.

Everything else in this repository exists to support, document, or verify that kernel:

- **`docs/`** defines the architectural contract and composition patterns
- **`tests/`** enforces conformance through automated spec tests
- **`examples/`** demonstrates the kernel's input/output contract
- **`scripts/`** provides static analysis guardrails

If you find yourself adding code that the kernel depends on at runtime, stop and reconsider. The kernel MUST remain self-contained. Infrastructure, persistence, networking, and orchestration belong in the adapter layer, which consumers build outside this template.

Complexity is not a goal. Correctness and determinism are.
