# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Real-world Event normalization example (`examples/event-normalization/`)
- Layer 1 scaffolding: `src/composition/concepts/`, `src/composition/synchronizations/`
- Layer 2 scaffolding: `src/adapters/integration/`, `src/adapters/persistence/`, `src/adapters/orchestration/`
- Domain-specific testing guide (`docs/TESTING_GUIDE.md`)
- Cookbook with practical recipes (`docs/COOKBOOK.md`)
- JSON-LD context resolution strategies (in Cookbook)
- Implementation space: `project/` directory with ROADMAP, SPEC, and DECISIONS templates
- Governance layer: `CLAUDE.md` with Barcode System directives, persona triggers, and session workflow
- Adversarial review section in pull request template

## [0.1.0] - 2026-02-19

### Added

- Kernel with pure JSON-LD identity transform (`src/kernel/transform.ts`)
- Deterministic canonicalization (`src/kernel/canonicalize.ts`)
- CLI entry point (`src/kernel/index.ts`)
- Spec tests: determinism, no-network, snapshot
- Static kernel purity checker
- Architecture documentation (6 core principles)
- Computation model specification
- Composition guide and adapter boundary documentation
- Contributing guidelines with spec test checklist
- Example input/output JSON-LD documents
- CI/CD pipeline with GitHub Actions
- MIT License
