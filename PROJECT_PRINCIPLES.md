# Scoplen protocol principles

This repository is a component of Scoplen, a Plystra project. The project-level adoption record is
[`scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md).

## Review record

- Philosophy version reviewed: Plystra Craft 1.0.1
- Source commit reviewed: `plystra/craft@dd617b370203d5dce1d30b8b81284d16d96a432c`
- Review date and maintainer: 2026-10-06, immoses (Moses Qiu)
- Maturity: Exploration
- Maintenance: Active
- Components: Rust libraries and shared known-answer test vectors
- Public data surface: none; the crates do not collect user data
- Review status: Open gaps remain while contract implementations are built

## Applicable standards

The repository applies `plystra-craft` and `plystra-craft-code` from `.agents/skills/`. The source
license is Apache-2.0. Security-sensitive protocol and cryptographic behavior is implemented only
after its contract is specified in `scoplen-docs` and covered by vectors and failure-path tests.

## Open gaps

- The S1 baseline is the current implementation boundary; S2–S7 behavior is not yet present.
- Independent security review and interoperability evidence are required before a Stable release.
